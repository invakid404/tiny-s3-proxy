//! Strict-mode SigV4 presigned URL query-auth parser and verifier.
//!
//! Public entry points: [`has_presigned_signature_query`] (cheap precheck),
//! [`parse_presigned_authorization`] (field parser), and
//! [`verify_presigned_request`] (canonical-request rebuild and HMAC-SHA256
//! comparison against the supplied `X-Amz-Signature`). The verifier returns
//! the same [`VerifiedRequest`] shape the header-auth path produces, so
//! downstream handler code consumes it identically.
//!
//! Detection vs. parsing have intentionally different strictness:
//!
//! - `has_presigned_signature_query` does a percent-decoded, case-insensitive
//!   byte-level scan for `X-Amz-Signature` so request shapes like
//!   `X%2DAmz%2DSignature=…` or `x-amz-signature=…` can't bypass strict-mode
//!   dispatch and fall through to the "no auth at all" branch.
//! - `parse_presigned_authorization` matches the *exact* decoded field names
//!   (`X-Amz-Algorithm`, `X-Amz-Credential`, etc.). A detected-but-misnamed
//!   signature key therefore makes the parser surface
//!   `AuthorizationHeaderMalformed`, rather than silently ignoring the
//!   request's signing intent.
//!
//! STS-issued temporary credentials are supported: the parser percent-
//! decodes `X-Amz-Security-Token` and the verifier forwards it to the
//! resolver. The canonical query already includes `X-Amz-Security-Token`
//! because the only excluded auth parameter is `X-Amz-Signature` (the
//! signature itself).

use crate::auth::credentials::InboundCredentialResolver;
use crate::auth::sigv4::canonical::{
    CanonicalQueryMode, build_canonical_request_from_signed_headers, percent_decode_for_query,
};
use crate::auth::sigv4::parser::{
    CredentialScope, ensure_scope_date_matches, parse_amz_date, parse_credential,
    parse_signature_hex, parse_signed_headers,
};
use crate::auth::sigv4::payload::PayloadHashForSigning;
use crate::auth::sigv4::{
    VerifiedRequest, build_string_to_sign, derive_signing_key, parse_hex32,
    resolve_credential_for_sigv4,
};
use crate::auth::verified::{VerifiedCredentialScope, VerifiedSigningContext};
use crate::s3::errors::S3Error;
use chrono::{DateTime, Utc};
use http::HeaderName;
use std::time::Duration;
use subtle::ConstantTimeEq;

/// AWS S3 caps presigned URL validity at 7 days (604 800 seconds).
pub const MAX_PRESIGNED_EXPIRES_SECS: u64 = 604_800;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const ECDSA_ALGORITHM_PREFIX: &str = "AWS4-ECDSA-";

/// Canonical (AWS-documented) casing for every `X-Amz-*` query parameter
/// the parser cares about. The parser does case-insensitive matching to
/// decide whether a key is "an auth param" but then enforces the *exact*
/// casing — a mis-cased auth key cannot be silently accepted as an
/// ordinary signed query param, which is what the detection layer is
/// meant to prevent.
const PRESIGNED_AUTH_NAMES: &[&str] = &[
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
    "X-Amz-Security-Token",
    "X-Amz-Content-Sha256",
];

/// If `decoded_key` ASCII-case-insensitively matches one of the
/// recognised presigned-auth parameter names, return that canonical
/// (correctly-cased) name. Used by the parser to fail closed on
/// `x-amz-signature` and friends.
fn classify_presigned_auth_key(decoded_key: &str) -> Option<&'static str> {
    PRESIGNED_AUTH_NAMES
        .iter()
        .find(|name| name.eq_ignore_ascii_case(decoded_key))
        .copied()
}

/// Output of a successful presigned-URL auth parse. Shape matches what the
/// header path produces in `SigV4Authorization`, plus the request time and
/// validity window from `X-Amz-Date` / `X-Amz-Expires`.
#[derive(Debug, Clone)]
pub struct PresignedAuthorization {
    pub access_key_id: String,
    pub scope: CredentialScope,
    pub signed_headers: Vec<HeaderName>,
    pub signature: [u8; 32],
    pub signature_hex: String,
    pub amz_date: String,
    pub request_time: DateTime<Utc>,
    pub expires: Duration,
    /// Percent-decoded `X-Amz-Security-Token` value, when the URL was
    /// generated from STS-issued temporary credentials. `None` for
    /// long-lived presigned URLs.
    pub session_token: Option<String>,
}

/// Cheap precheck for "is this a presigned URL request?". Compares decoded
/// query-key bytes case-insensitively so that the percent-encoded form
/// (`X%2DAmz%2DSignature=…`) and casing variants (`x-amz-signature=…`)
/// still route through the presigned verifier rather than slipping past as
/// an unsigned request.
pub fn has_presigned_signature_query(raw_query: &str) -> bool {
    for chunk in raw_query.split('&') {
        if chunk.is_empty() {
            continue;
        }
        let raw_k = chunk.split_once('=').map(|(k, _)| k).unwrap_or(chunk);
        if eq_ignore_ascii_case_bytes(raw_k.as_bytes(), b"X-Amz-Signature") {
            return true;
        }
        let decoded = percent_decode_for_query(raw_k);
        if eq_ignore_ascii_case_bytes(&decoded, b"X-Amz-Signature") {
            return true;
        }
    }
    false
}

/// Parse the `X-Amz-*` query auth parameters carried by a presigned URL.
///
/// Each required field is matched on its exact percent-decoded name. STS
/// (`X-Amz-Security-Token`) credentials are accepted and verified — the
/// token is percent-decoded and stored on the returned
/// [`PresignedAuthorization`]. SigV4A (`AWS4-ECDSA-*`) presigned URLs stay
/// fail-closed with `UnsupportedSignature` (PR 5 of #63).
pub fn parse_presigned_authorization(
    raw_query: &str,
    request_id: &str,
) -> Result<PresignedAuthorization, S3Error> {
    let mut algorithm: Option<String> = None;
    let mut credential: Option<String> = None;
    let mut amz_date: Option<String> = None;
    let mut expires_raw: Option<String> = None;
    let mut signed_headers_raw: Option<String> = None;
    let mut signature_raw: Option<String> = None;
    let mut security_token: Option<String> = None;

    for chunk in raw_query.split('&') {
        if chunk.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match chunk.split_once('=') {
            Some((k, v)) => (k, v),
            None => (chunk, ""),
        };

        let decoded_key = percent_decode_for_query(raw_k);
        // Required-auth field names are ASCII; anything that isn't valid
        // UTF-8 can't match any recognised name and is therefore just a
        // non-auth query param.
        let key_str = match std::str::from_utf8(&decoded_key) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Case-insensitive recognition; an exact-case mismatch fails
        // closed so that e.g. `?X-Amz-Signature=A&x-amz-signature=B`
        // can't be smuggled past the parser by treating the lowercase
        // form as an ordinary signed query param.
        let canonical_name = match classify_presigned_auth_key(key_str) {
            Some(name) => name,
            None => continue,
        };
        if key_str != canonical_name {
            return Err(S3Error::authorization_header_malformed(
                &format!(
                    "presigned auth parameter {canonical_name} must be sent with the AWS canonical \
                     casing"
                ),
                request_id,
            ));
        }

        // `X-Amz-Content-Sha256` is a payload marker, not an auth field;
        // `check_presigned_payload_marker` reads it from the raw query
        // after parsing. The parser only enforces its canonical casing.
        if canonical_name == "X-Amz-Content-Sha256" {
            continue;
        }

        // STS session token gets the same shape rules as the other auth
        // params (single occurrence, non-empty, UTF-8 ASCII string) but
        // is stored on its own slot since it's optional. "Opaque token"
        // means no case-folding / trimming / form-decoding — base64-ish
        // bytes like `+`, `/`, `=` MUST round-trip — but it doesn't mean
        // accepting arbitrary Unicode. AWS STS tokens are ASCII, and the
        // header-auth path already rejects non-ASCII via `HeaderValue::to_str`;
        // matching that here keeps the two auth paths symmetric.
        if canonical_name == "X-Amz-Security-Token" {
            if security_token.is_some() {
                return Err(S3Error::authorization_header_malformed(
                    "presigned auth has duplicate X-Amz-Security-Token",
                    request_id,
                ));
            }
            let decoded_value = percent_decode_for_query(raw_v);
            let value_str = std::str::from_utf8(&decoded_value).map_err(|_| {
                S3Error::authorization_header_malformed(
                    "presigned auth field X-Amz-Security-Token is not valid UTF-8",
                    request_id,
                )
            })?;
            if value_str.is_empty() {
                return Err(S3Error::authorization_header_malformed(
                    "presigned auth field X-Amz-Security-Token is empty",
                    request_id,
                ));
            }
            if value_str.bytes().any(|b| b >= 0x80) {
                return Err(S3Error::authorization_header_malformed(
                    "presigned auth field X-Amz-Security-Token is not valid ASCII",
                    request_id,
                ));
            }
            security_token = Some(value_str.to_string());
            continue;
        }

        let slot = match canonical_name {
            "X-Amz-Algorithm" => &mut algorithm,
            "X-Amz-Credential" => &mut credential,
            "X-Amz-Date" => &mut amz_date,
            "X-Amz-Expires" => &mut expires_raw,
            "X-Amz-SignedHeaders" => &mut signed_headers_raw,
            "X-Amz-Signature" => &mut signature_raw,
            other => unreachable!("classify_presigned_auth_key emitted {other}"),
        };

        let decoded_value = percent_decode_for_query(raw_v);
        let value_str = std::str::from_utf8(&decoded_value).map_err(|_| {
            S3Error::authorization_header_malformed(
                &format!("presigned auth field {canonical_name} is not valid UTF-8"),
                request_id,
            )
        })?;
        // The SigV4 grammar is ASCII-only for each of these fields.
        // Reject any byte >= 0x80 before storing the value — otherwise a
        // non-ASCII credential / signed-headers / algorithm value would
        // flow into `parse_credential` / `parse_signed_headers` and then
        // into HMAC computation. Only the canonical six required auth
        // values get this ASCII enforcement; ordinary signed query params
        // are unaffected.
        if value_str.bytes().any(|b| b >= 0x80) {
            return Err(S3Error::authorization_header_malformed(
                &format!("presigned auth field {canonical_name} contains non-ASCII bytes"),
                request_id,
            ));
        }

        if slot.is_some() {
            return Err(S3Error::authorization_header_malformed(
                &format!("presigned auth has duplicate {canonical_name}"),
                request_id,
            ));
        }
        *slot = Some(value_str.to_string());
    }

    // SigV4A presigned URLs use `AWS4-ECDSA-*`. The signing keys are ECDSA,
    // not HMAC, so neither the proxy nor the upstream re-signer can verify
    // them — fail closed before structural required-field checks.
    if let Some(algo) = algorithm.as_deref()
        && (algo.starts_with(ECDSA_ALGORITHM_PREFIX)
            || algo.eq_ignore_ascii_case("AWS4-ECDSA-P256-SHA256"))
    {
        return Err(S3Error::unsupported_signature(
            "SigV4A (AWS4-ECDSA-P256-SHA256) presigned URLs are not supported in strict mode; \
             tracked in PR 5 of issue #63",
            request_id,
        ));
    }

    let algorithm = algorithm.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "presigned auth missing X-Amz-Algorithm",
            request_id,
        )
    })?;
    if algorithm != ALGORITHM {
        return Err(S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Algorithm must be AWS4-HMAC-SHA256",
            request_id,
        ));
    }

    let credential_v = credential.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "presigned auth missing X-Amz-Credential",
            request_id,
        )
    })?;
    let amz_date_v = amz_date.ok_or_else(|| {
        S3Error::authorization_header_malformed("presigned auth missing X-Amz-Date", request_id)
    })?;
    let expires_v = expires_raw.ok_or_else(|| {
        S3Error::authorization_header_malformed("presigned auth missing X-Amz-Expires", request_id)
    })?;
    let signed_headers_v = signed_headers_raw.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "presigned auth missing X-Amz-SignedHeaders",
            request_id,
        )
    })?;
    let signature_v = signature_raw.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "presigned auth missing X-Amz-Signature",
            request_id,
        )
    })?;

    let (access_key_id, scope) = parse_credential(&credential_v, request_id)?;
    let signed_headers = parse_signed_headers(&signed_headers_v, request_id)?;
    let (signature, signature_hex) = parse_signature_hex(&signature_v, request_id)?;

    let request_time = parse_amz_date(&amz_date_v).ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Date is not in YYYYMMDDTHHMMSSZ format",
            request_id,
        )
    })?;

    // X-Amz-Expires: decimal integer in 1..=604800. AWS S3 caps validity at
    // seven days; zero or out-of-range values mean the URL was never valid.
    if expires_v.is_empty() || !expires_v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Expires must be a decimal integer",
            request_id,
        ));
    }
    let expires_secs: u64 = expires_v.parse().map_err(|_| {
        S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Expires is out of range",
            request_id,
        )
    })?;
    if expires_secs == 0 || expires_secs > MAX_PRESIGNED_EXPIRES_SECS {
        return Err(S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Expires must be in 1..=604800",
            request_id,
        ));
    }

    Ok(PresignedAuthorization {
        access_key_id,
        scope,
        signed_headers,
        signature,
        signature_hex,
        amz_date: amz_date_v,
        request_time,
        expires: Duration::from_secs(expires_secs),
        session_token: security_token,
    })
}

fn eq_ignore_ascii_case_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// End-to-end strict verification of a presigned URL request.
///
/// Performs (in order): aws-chunked compatibility rejection, query-auth
/// parse, validity-window check against `now`, payload-marker sanity check
/// (`UNSIGNED-PAYLOAD` only — STREAMING-* and signed-payload-hash presigned
/// URLs are deferred), credential resolution, canonical-request rebuild
/// with `X-Amz-Signature` excluded from the query, HMAC-SHA256 over the
/// string-to-sign, and constant-time comparison against the supplied
/// signature.
///
/// Returns the same [`VerifiedRequest`] shape the header-auth path produces
/// so the handler's request-scoped logic stays unaware of which auth
/// mechanism the client used. `payload` is always
/// `PayloadHashForSigning::UnsignedPayload`, which means downstream body
/// buffering for hash verification is skipped.
pub fn verify_presigned_request(
    parts: &http::request::Parts,
    resolver: &dyn InboundCredentialResolver,
    request_id: &str,
    now: DateTime<Utc>,
) -> Result<VerifiedRequest, S3Error> {
    // Reject the presigned/aws-chunked intersection before anything else.
    // PR 2's chunk verifier can't be seeded from a query signature without
    // a deliberate seeding step we haven't designed, and "presigned + signed
    // streaming" is not part of the documented S3 presigned auth flow.
    reject_presigned_aws_chunked(parts, request_id)?;

    let raw_query = parts.uri.query().unwrap_or("");
    let pres = parse_presigned_authorization(raw_query, request_id)?;

    // The credential scope date must match the UTC date in X-Amz-Date —
    // otherwise the canonical request the client signed is dated against
    // one day and our signing-key derivation against another. Header auth
    // enforces the same invariant via `ensure_scope_date_matches`.
    ensure_scope_date_matches(&pres.scope, pres.request_time, request_id)?;

    enforce_presigned_validity(&pres, now, request_id)?;
    check_presigned_payload_marker(parts, request_id)?;

    // Resolve the access key. Tuple miss → InvalidAccessKeyId, expired →
    // ExpiredToken, resolver-classified malformed token → InvalidToken,
    // store error → InternalError. The session token (if any) is part of
    // the canonical query and is now also part of the lookup key.
    let credential = resolve_credential_for_sigv4(
        resolver,
        &pres.access_key_id,
        pres.session_token.as_deref(),
        now,
        request_id,
    )?;

    let payload = PayloadHashForSigning::UnsignedPayload;
    let canonical = build_canonical_request_from_signed_headers(
        parts,
        &pres.signed_headers,
        &payload,
        CanonicalQueryMode::ExcludePresignedSignature,
        request_id,
    )?;

    let signing_key = derive_signing_key(
        credential.secret_access_key.expose(),
        &pres.scope.date_yyyymmdd,
        &pres.scope.region,
        &pres.scope.service,
    );

    let string_to_sign =
        build_string_to_sign(&pres.scope, &pres.amz_date, &canonical.canonical_request);
    let expected_hex =
        aws_sigv4::sign::v4::calculate_signature(signing_key.as_bytes(), string_to_sign.as_bytes());
    let expected_bytes = parse_hex32(&expected_hex).ok_or_else(|| {
        S3Error::internal_error("internal error computing expected signature", request_id)
    })?;

    if expected_bytes.ct_eq(&pres.signature).unwrap_u8() != 1 {
        return Err(S3Error::signature_does_not_match(
            "computed request signature does not match the supplied X-Amz-Signature",
            request_id,
        ));
    }

    Ok(VerifiedRequest {
        access_key_id: credential.access_key_id.clone(),
        credential_scope: VerifiedCredentialScope::SigV4(pres.scope),
        signed_headers: pres.signed_headers,
        request_signature_hex: pres.signature_hex,
        signing_context: VerifiedSigningContext::HmacSha256(signing_key),
        amz_date: pres.amz_date,
        payload,
    })
}

/// Reject the request before signature work if it looks like a presigned
/// aws-chunked streaming upload — that shape is fail-closed in PR 3.
fn reject_presigned_aws_chunked(
    parts: &http::request::Parts,
    request_id: &str,
) -> Result<(), S3Error> {
    let mismatch = || {
        S3Error::unsupported_signature(
            "presigned aws-chunked streaming uploads are not supported in strict mode; \
             tracked in PR 5 of issue #63",
            request_id,
        )
    };

    if parts.headers.contains_key("x-amz-decoded-content-length")
        || parts.headers.contains_key("x-amz-trailer")
    {
        return Err(mismatch());
    }
    if let Some(v) = parts.headers.get("content-encoding")
        && let Ok(s) = v.to_str()
        && s.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("aws-chunked"))
    {
        return Err(mismatch());
    }
    if let Some(v) = parts.headers.get("x-amz-content-sha256")
        && let Ok(s) = v.to_str()
        && s.starts_with("STREAMING-")
    {
        return Err(mismatch());
    }
    let raw_query = parts.uri.query().unwrap_or("");
    for chunk in raw_query.split('&') {
        if chunk.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match chunk.split_once('=') {
            Some((k, v)) => (k, v),
            None => (chunk, ""),
        };
        let decoded_k = percent_decode_for_query(raw_k);
        if decoded_k.as_slice() == b"X-Amz-Content-Sha256" {
            let decoded_v = percent_decode_for_query(raw_v);
            if decoded_v.starts_with(b"STREAMING-") {
                return Err(mismatch());
            }
        }
    }
    Ok(())
}

fn enforce_presigned_validity(
    pres: &PresignedAuthorization,
    now: DateTime<Utc>,
    request_id: &str,
) -> Result<(), S3Error> {
    // `pres.expires` is bounded to `MAX_PRESIGNED_EXPIRES_SECS` by the parser,
    // so the chrono conversion can never overflow in production.
    let expires = chrono::Duration::from_std(pres.expires).map_err(|_| {
        S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Expires is out of range",
            request_id,
        )
    })?;
    let expires_at = pres.request_time + expires;
    if now < pres.request_time || now > expires_at {
        return Err(S3Error::request_time_too_skewed(
            "presigned URL is outside its validity window",
            request_id,
        ));
    }
    Ok(())
}

/// Verify the request's `x-amz-content-sha256` markers (header *and*
/// query — every occurrence on both sides) are either absent or all
/// `UNSIGNED-PAYLOAD`. A presigned URL can legally sign more than one
/// `X-Amz-Content-Sha256` query parameter, so the canonical query — and
/// therefore the HMAC — stays valid even when those occurrences disagree;
/// classifying only the first occurrence let a trailing concrete 64-hex
/// digest slip past the unsigned marker that came before it. Signed-
/// payload-hash and streaming presigned URLs are deferred to follow-up
/// PRs of issue #63 — the standard S3 presigned canonical request uses
/// `UNSIGNED-PAYLOAD`.
fn check_presigned_payload_marker(
    parts: &http::request::Parts,
    request_id: &str,
) -> Result<(), S3Error> {
    let mut markers: Vec<Vec<u8>> = Vec::new();

    // Every `x-amz-content-sha256` header value (`get_all` so the rare
    // multiple-header-line case fails closed instead of being silently
    // truncated to the first value).
    for v in parts.headers.get_all("x-amz-content-sha256").iter() {
        markers.push(v.as_bytes().to_vec());
    }

    // Every exact-case `X-Amz-Content-Sha256` query occurrence (mis-cased
    // forms are already rejected by the auth-key parser before we get
    // here). All occurrences feed into the same dangerous-pattern /
    // disagreement scan below.
    let raw_query = parts.uri.query().unwrap_or("");
    for chunk in raw_query.split('&') {
        if chunk.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match chunk.split_once('=') {
            Some((k, v)) => (k, v),
            None => (chunk, ""),
        };
        let decoded_k = percent_decode_for_query(raw_k);
        if decoded_k.as_slice() == b"X-Amz-Content-Sha256" {
            markers.push(percent_decode_for_query(raw_v));
        }
    }

    if markers.is_empty() {
        return Ok(());
    }

    // Per-marker scan for the dangerous patterns first, so a single
    // 64-hex / STREAMING marker among a list of `UNSIGNED-PAYLOAD`s
    // surfaces the specific spec-mandated error code instead of the
    // generic disagreement one. STREAMING-* normally never reaches us
    // because `reject_presigned_aws_chunked` runs earlier and iterates
    // every header / query occurrence; this branch is kept for
    // defence-in-depth so a future refactor that drops that gate can't
    // silently downgrade STREAMING to `AuthorizationHeaderMalformed`.
    for bytes in &markers {
        if let Ok(s) = std::str::from_utf8(bytes) {
            if s.starts_with("STREAMING-") {
                return Err(S3Error::unsupported_signature(
                    "presigned aws-chunked streaming uploads are not supported in strict mode; \
                     tracked in PR 5 of issue #63",
                    request_id,
                ));
            }
            if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(S3Error::invalid_request(
                    "presigned URLs with signed payload hashes are not supported",
                    request_id,
                ));
            }
        }
    }

    // Disagreement among the (already-collected-from-everywhere) markers.
    // Even if every individual occurrence is itself "safe-looking", a
    // mismatch between them means the client signed two conflicting
    // payload-hash intents; fail closed before classifying.
    if markers.iter().any(|m| m != &markers[0]) {
        return Err(S3Error::invalid_request(
            "presigned URL x-amz-content-sha256 header / query markers disagree",
            request_id,
        ));
    }

    // All markers identical at this point; classify the unified value.
    classify_presigned_payload_marker(&markers[0], request_id)
}

/// Classify a unified `x-amz-content-sha256` marker value (from header or
/// query). Pulled out so the disagreement check above can call it on the
/// single agreed-on byte sequence without duplicating the rules.
fn classify_presigned_payload_marker(bytes: &[u8], request_id: &str) -> Result<(), S3Error> {
    let s = std::str::from_utf8(bytes).map_err(|_| {
        S3Error::authorization_header_malformed(
            "x-amz-content-sha256 is not valid UTF-8",
            request_id,
        )
    })?;
    if s == "UNSIGNED-PAYLOAD" {
        return Ok(());
    }
    if s.starts_with("STREAMING-") {
        return Err(S3Error::unsupported_signature(
            "presigned aws-chunked streaming uploads are not supported in strict mode; \
             tracked in PR 5 of issue #63",
            request_id,
        ));
    }
    // 64 hex characters (case-insensitive) → a concrete signed-payload
    // digest. AWS's documented presigned canonical request is
    // `UNSIGNED-PAYLOAD`; supporting signed-payload presigned URLs would
    // require buffering bodies on a path that currently avoids it.
    // Deferred. Accept both lowercase and uppercase / mixed-case hex so
    // the error code stays `InvalidRequest` regardless of casing.
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(S3Error::invalid_request(
            "presigned URLs with signed payload hashes are not supported",
            request_id,
        ));
    }
    Err(S3Error::authorization_header_malformed(
        "presigned URL x-amz-content-sha256 must be UNSIGNED-PAYLOAD",
        request_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> &'static str {
        "req-test"
    }

    /// The AWS S3 presigned GET reference URL from the docs:
    /// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
    /// `aeeed9bb…` is the documented signature for these inputs and is
    /// pinned by the canonical-request crypto test in a follow-up commit.
    fn aws_doc_presigned_query() -> String {
        concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
            "&X-Amz-Date=20130524T000000Z",
            "&X-Amz-Expires=86400",
            "&X-Amz-SignedHeaders=host",
            "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
        )
        .to_string()
    }

    // ── Detection ───────────────────────────────────────────────────────

    #[test]
    fn test_detect_canonical_signature_key() {
        assert!(has_presigned_signature_query(&aws_doc_presigned_query()));
    }

    #[test]
    fn test_detect_lowercase_signature_key() {
        // Lowercase variant must still trigger detection so it dispatches
        // to the presigned parser and fails as malformed; otherwise it
        // would slip past and be treated as an unsigned request.
        assert!(has_presigned_signature_query("x-amz-signature=abc"));
    }

    #[test]
    fn test_detect_percent_encoded_signature_key() {
        // `X%2DAmz%2DSignature` decodes (byte-level) to `X-Amz-Signature`.
        assert!(has_presigned_signature_query(
            "X%2DAmz%2DSignature=abc&foo=1"
        ));
    }

    #[test]
    fn test_detect_returns_false_for_header_auth() {
        // No `X-Amz-Signature` key present at all → not a presigned URL.
        assert!(!has_presigned_signature_query("foo=1&bar=2"));
        assert!(!has_presigned_signature_query(""));
    }

    // ── Parse: happy path ───────────────────────────────────────────────

    #[test]
    fn test_parse_aws_doc_presigned_query_round_trip() {
        let pres = parse_presigned_authorization(&aws_doc_presigned_query(), rid())
            .expect("AWS doc query parses");
        assert_eq!(pres.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(pres.scope.date_yyyymmdd, "20130524");
        assert_eq!(pres.scope.region, "us-east-1");
        assert_eq!(pres.scope.service, "s3");
        assert_eq!(pres.signed_headers.len(), 1);
        assert_eq!(pres.signed_headers[0].as_str(), "host");
        assert_eq!(pres.amz_date, "20130524T000000Z");
        assert_eq!(pres.expires, Duration::from_secs(86400));
        assert_eq!(
            pres.signature_hex,
            "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    #[test]
    fn test_parse_ignores_non_auth_query_params() {
        // Application/S3 query params like `partNumber` and `versionId`
        // sit alongside the auth params; the parser must not flag them.
        let q = concat!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "&partNumber=2",
            "&X-Amz-Credential=AKID%2F20260101%2Fus-east-1%2Fs3%2Faws4_request",
            "&versionId=abc",
            "&X-Amz-Date=20260101T120000Z",
            "&X-Amz-Expires=60",
            "&X-Amz-SignedHeaders=host",
            "&X-Amz-Signature=",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let pres = parse_presigned_authorization(q, rid()).expect("parses");
        assert_eq!(pres.access_key_id, "AKID");
    }

    // ── Parse: required-field presence ──────────────────────────────────

    #[test]
    fn test_parse_missing_algorithm() {
        let q = aws_doc_presigned_query().replace("X-Amz-Algorithm=AWS4-HMAC-SHA256&", "");
        let err = parse_presigned_authorization(&q, rid()).expect_err("missing algorithm");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_missing_credential() {
        let q = aws_doc_presigned_query().replace(
            "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
            "",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("missing credential");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_missing_date() {
        let q = aws_doc_presigned_query().replace("&X-Amz-Date=20130524T000000Z", "");
        let err = parse_presigned_authorization(&q, rid()).expect_err("missing date");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_missing_expires() {
        let q = aws_doc_presigned_query().replace("&X-Amz-Expires=86400", "");
        let err = parse_presigned_authorization(&q, rid()).expect_err("missing expires");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_missing_signed_headers() {
        let q = aws_doc_presigned_query().replace("&X-Amz-SignedHeaders=host", "");
        let err = parse_presigned_authorization(&q, rid()).expect_err("missing signed headers");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_missing_signature() {
        // Drop the canonical `X-Amz-Signature` key. The detector would not
        // route a missing-signature request to the parser in production,
        // but we still want a well-defined error if the parser is called.
        let q = aws_doc_presigned_query().replace(
            "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
            "",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("missing signature");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_lowercase_signature_alongside_canonical_rejected_as_duplicate() {
        // Both a canonical `X-Amz-Signature` (with a syntactically valid
        // hex blob) and a lowercase `x-amz-signature=<other>` are present.
        // Previously the parser would silently treat the lowercase key as
        // an ordinary signed query param, letting the request through with
        // the canonical signature. After the case-insensitive recognition
        // fix it now fails closed with `AuthorizationHeaderMalformed`.
        // Deleting the `classify_presigned_auth_key` casing check flips
        // this back to Ok.
        let q = format!("{}&x-amz-signature=other-value", aws_doc_presigned_query());
        let err = parse_presigned_authorization(&q, rid()).expect_err("mis-cased duplicate");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_non_ascii_credential_rejected() {
        // `%C3%89` decodes to U+00C9 (É) — valid UTF-8, but not ASCII.
        // The SigV4 grammar is ASCII for the credential field; deleting
        // the `b >= 0x80` enforcement would let this value flow into
        // `parse_credential` / signing-key derivation and surface as a
        // signature mismatch instead of the documented malformed error.
        let q = aws_doc_presigned_query().replace(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
            "X-Amz-Credential=AKIA%C3%89%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("non-ASCII credential");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_lowercase_signature_key_is_malformed() {
        // Detection routes this to the parser; the parser only accepts the
        // exact decoded `X-Amz-Signature` name, so it surfaces
        // AuthorizationHeaderMalformed rather than silently dropping the
        // signing intent.
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKID%2F20260101%2Fus-east-1%2Fs3%2Faws4_request\
                 &X-Amz-Date=20260101T120000Z\
                 &X-Amz-Expires=60\
                 &X-Amz-SignedHeaders=host\
                 &x-amz-signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_presigned_authorization(q, rid()).expect_err("lowercase sig key");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    // ── Parse: duplicates ───────────────────────────────────────────────

    #[test]
    fn test_parse_duplicate_signature_rejected() {
        let q = format!("{}&X-Amz-Signature=abc", aws_doc_presigned_query());
        let err = parse_presigned_authorization(&q, rid()).expect_err("duplicate signature");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_duplicate_credential_rejected() {
        let q = format!(
            "{}&X-Amz-Credential=AKID%2F20260101%2Fus-east-1%2Fs3%2Faws4_request",
            aws_doc_presigned_query()
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("duplicate credential");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    // ── Parse: percent-decoding ─────────────────────────────────────────

    #[test]
    fn test_parse_credential_percent_decoded() {
        // `%2F` decodes to `/` so the credential field separators land at
        // the right places. The AWS doc URL relies on this.
        let pres = parse_presigned_authorization(&aws_doc_presigned_query(), rid())
            .expect("parses with encoded credential");
        assert_eq!(pres.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(pres.scope.date_yyyymmdd, "20130524");
    }

    #[test]
    fn test_parse_signed_headers_percent_decoded() {
        // `host%3Bx-amz-date` decodes to `host;x-amz-date`.
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=AKID%2F20260101%2Fus-east-1%2Fs3%2Faws4_request\
                 &X-Amz-Date=20260101T120000Z\
                 &X-Amz-Expires=60\
                 &X-Amz-SignedHeaders=host%3Bx-amz-date\
                 &X-Amz-Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pres = parse_presigned_authorization(q, rid()).expect("parses encoded headers");
        assert_eq!(pres.signed_headers.len(), 2);
        assert_eq!(pres.signed_headers[0].as_str(), "host");
        assert_eq!(pres.signed_headers[1].as_str(), "x-amz-date");
    }

    // ── Parse: STS / SigV4A deferrals ───────────────────────────────────

    #[test]
    fn test_parse_security_token_now_parsed_and_percent_decoded() {
        // Reverts PR 3's `InvalidToken` parser-level reject. A presigned
        // URL with `X-Amz-Security-Token` now parses and the percent-
        // decoded value lands on `PresignedAuthorization::session_token`.
        // Re-adding the `InvalidToken` short-circuit in the parser flips
        // this back to an error.
        //
        // The token value here covers two things at once: percent-decoded
        // `%2F` becomes `/`, and the bare `+` stays a literal plus (no
        // form decoding). Real STS tokens use base64-ish alphabets so
        // both bytes appear in the wild.
        let q = format!(
            "{}&X-Amz-Security-Token=FQoG%2FAAa+EXAMPLE",
            aws_doc_presigned_query()
        );
        let pres = parse_presigned_authorization(&q, rid()).expect("STS token now parses");
        assert_eq!(
            pres.session_token.as_deref(),
            Some("FQoG/AAa+EXAMPLE"),
            "session_token must be percent-decoded; `+` stays literal"
        );
    }

    #[test]
    fn test_parse_security_token_duplicate_rejected() {
        // Duplicate `X-Amz-Security-Token` query params are malformed —
        // we never join token values for resolver lookup (STS tokens are
        // not a comma-mergeable list), so accepting the duplicate would
        // make resolver behavior position-dependent.
        let q = format!(
            "{}&X-Amz-Security-Token=tok1&X-Amz-Security-Token=tok2",
            aws_doc_presigned_query()
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("duplicate STS token");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_security_token_empty_rejected() {
        let q = format!("{}&X-Amz-Security-Token=", aws_doc_presigned_query());
        let err = parse_presigned_authorization(&q, rid()).expect_err("empty STS token");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_security_token_non_ascii_rejected() {
        // `%C3%A9` decodes to U+00E9 (é): valid UTF-8 but not ASCII. AWS
        // STS tokens are ASCII bearer strings, and the header-auth path
        // already rejects non-ASCII via `HeaderValue::to_str`. The other
        // six presigned required auth fields enforce this same
        // `b >= 0x80` check; deleting the matching enforcement here would
        // let non-ASCII token bytes flow into the resolver's
        // `subtle::ConstantTimeEq` compare and create an unnecessary
        // asymmetry between the two auth paths. `+`, `/`, `=` are still
        // accepted (covered by the round-trip / decoding tests above) —
        // this only rejects bytes outside the ASCII range.
        let q = format!(
            "{}&X-Amz-Security-Token=tok%C3%A9",
            aws_doc_presigned_query()
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("non-ASCII STS token");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_security_token_mis_cased_query_key_still_rejected() {
        // The canonical-casing rule for presigned auth params is enforced
        // for every recognised name, including `X-Amz-Security-Token`.
        // Lowercase variants get classified by the case-insensitive
        // matcher but then fail the exact-case check; without that check
        // a client could smuggle in an STS token under `x-amz-security-token`
        // (an ordinary signed query param shape) and bypass the dedicated
        // token slot.
        let q = format!("{}&x-amz-security-token=tok", aws_doc_presigned_query());
        let err = parse_presigned_authorization(&q, rid()).expect_err("mis-cased STS token");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_sigv4a_algorithm_rejected_as_unsupported() {
        let q = aws_doc_presigned_query().replace(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("SigV4A");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    #[test]
    fn test_parse_unknown_algorithm_malformed() {
        let q = aws_doc_presigned_query().replace(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Algorithm=AWS4-HMAC-SHA1",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("bad algo");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    // ── Parse: expiry bounds ────────────────────────────────────────────

    #[test]
    fn test_parse_expires_zero_rejected() {
        let q = aws_doc_presigned_query().replace("&X-Amz-Expires=86400", "&X-Amz-Expires=0");
        let err = parse_presigned_authorization(&q, rid()).expect_err("expires=0");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_expires_non_digit_rejected() {
        let q = aws_doc_presigned_query()
            .replace("&X-Amz-Expires=86400", "&X-Amz-Expires=not-a-number");
        let err = parse_presigned_authorization(&q, rid()).expect_err("non-digit expires");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_expires_over_max_rejected() {
        let q = aws_doc_presigned_query().replace("&X-Amz-Expires=86400", "&X-Amz-Expires=604801");
        let err = parse_presigned_authorization(&q, rid()).expect_err("expires>604800");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_expires_max_accepted() {
        let q = aws_doc_presigned_query().replace("&X-Amz-Expires=86400", "&X-Amz-Expires=604800");
        let pres = parse_presigned_authorization(&q, rid()).expect("expires=604800 OK");
        assert_eq!(
            pres.expires,
            Duration::from_secs(MAX_PRESIGNED_EXPIRES_SECS)
        );
    }

    // ── Parse: structural delegation to header-auth helpers ─────────────

    #[test]
    fn test_parse_signed_headers_must_include_host() {
        let q = aws_doc_presigned_query().replace(
            "&X-Amz-SignedHeaders=host",
            "&X-Amz-SignedHeaders=x-amz-date",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("no host");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_signed_headers_security_token_now_accepted_at_parser_level() {
        // The shared `parse_signed_headers` used to reject
        // `x-amz-security-token` outright (PR 1 behavior). PR 4 lifts that
        // because the canonical request includes the token header (and the
        // canonical query includes the `X-Amz-Security-Token` parameter)
        // when the client presents STS credentials. Re-adding the
        // parser-level reject in `parse_signed_headers` flips this back
        // to an `InvalidToken` error.
        let q = aws_doc_presigned_query().replace(
            "&X-Amz-SignedHeaders=host",
            "&X-Amz-SignedHeaders=host%3Bx-amz-security-token",
        );
        let pres =
            parse_presigned_authorization(&q, rid()).expect("STS in signed headers now parses");
        assert!(
            pres.signed_headers
                .iter()
                .any(|n| n.as_str() == "x-amz-security-token")
        );
    }

    #[test]
    fn test_parse_signature_must_be_64_hex() {
        let q = aws_doc_presigned_query().replace(
            "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
            "tooshort",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("bad hex");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_parse_credential_service_must_be_s3() {
        let q = aws_doc_presigned_query().replace("%2Fs3%2Faws4_request", "%2Fec2%2Faws4_request");
        let err = parse_presigned_authorization(&q, rid()).expect_err("non-s3 service");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use crate::auth::credentials::{
        CredentialResolveError, InboundCredential, InboundCredentialResolver, InboundSecret,
        SessionToken,
    };
    use chrono::{TimeZone, Utc};
    use http::Request;
    use std::sync::Arc;

    fn rid() -> &'static str {
        "rid"
    }

    /// Test resolver shared with the header-auth tests. Configurable with
    /// an optional no-token credential AND an optional token-bearing
    /// credential under the same access-key id so each test pins its own
    /// namespace shape.
    struct FixedResolver {
        akid: Arc<str>,
        no_token_secret: Option<InboundSecret>,
        token: Option<(SessionToken, InboundSecret, Option<DateTime<Utc>>)>,
    }

    impl FixedResolver {
        fn new(akid: &str, secret: &str) -> Self {
            Self {
                akid: Arc::from(akid),
                no_token_secret: Some(InboundSecret::new(secret.to_string())),
                token: None,
            }
        }

        fn with_token(
            akid: &str,
            token: &str,
            secret: &str,
            expires_at: Option<DateTime<Utc>>,
        ) -> Self {
            Self {
                akid: Arc::from(akid),
                no_token_secret: None,
                token: Some((
                    SessionToken::new(token.to_string()),
                    InboundSecret::new(secret.to_string()),
                    expires_at,
                )),
            }
        }
    }

    impl InboundCredentialResolver for FixedResolver {
        fn resolve(
            &self,
            access_key_id: &str,
            session_token: Option<&str>,
            now: DateTime<Utc>,
        ) -> Result<Option<Arc<InboundCredential>>, CredentialResolveError> {
            if access_key_id != self.akid.as_ref() {
                return Ok(None);
            }
            match session_token {
                None => Ok(self.no_token_secret.as_ref().map(|secret| {
                    Arc::new(InboundCredential {
                        access_key_id: self.akid.clone(),
                        secret_access_key: secret.clone(),
                        session_token: None,
                        expires_at: None,
                    })
                })),
                Some(t) => {
                    let Some((stored, secret, expires_at)) = self.token.as_ref() else {
                        return Ok(None);
                    };
                    if stored.expose() != t {
                        return Ok(None);
                    }
                    if let Some(exp) = expires_at
                        && now >= *exp
                    {
                        return Err(CredentialResolveError::Expired { expires_at: *exp });
                    }
                    Ok(Some(Arc::new(InboundCredential {
                        access_key_id: self.akid.clone(),
                        secret_access_key: secret.clone(),
                        session_token: Some(stored.clone()),
                        expires_at: *expires_at,
                    })))
                }
            }
        }
    }

    // ── AWS-published reference vector ──────────────────────────────────
    //
    // The presigned GET URL example from AWS S3 docs (the one that lists
    // `aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404` as
    // the signature). Pinning this round trip means our canonical query
    // construction, header normalization, signing-key derivation, and
    // string-to-sign all match the documented AWS output bit-for-bit.

    const AWS_DOC_AKID: &str = "AKIAIOSFODNN7EXAMPLE";
    const AWS_DOC_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const AWS_DOC_HOST: &str = "examplebucket.s3.amazonaws.com";
    const AWS_DOC_SIGNATURE: &str =
        "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";

    fn aws_doc_query() -> String {
        format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z\
             &X-Amz-Expires=86400\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature={AWS_DOC_SIGNATURE}",
        )
    }

    fn aws_doc_parts(query: &str) -> http::request::Parts {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{query}"))
            .header("host", AWS_DOC_HOST)
            .body(())
            .unwrap();
        req.into_parts().0
    }

    fn aws_doc_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2013, 5, 24, 1, 0, 0).unwrap()
    }

    fn aws_doc_resolver() -> FixedResolver {
        FixedResolver::new(AWS_DOC_AKID, AWS_DOC_SECRET)
    }

    #[test]
    fn test_aws_published_presigned_get_vector_round_trip() {
        // The whole `aeeed9bb…` signature is documented by AWS — if any
        // step in the verifier diverges (query sort, header trim, key
        // derivation, string-to-sign layout) we get SignatureDoesNotMatch
        // instead of a 200. Replacing `ExcludePresignedSignature` with
        // `IncludeAll` flips this from Ok to SignatureDoesNotMatch.
        let parts = aws_doc_parts(&aws_doc_query());
        let resolver = aws_doc_resolver();
        let verified =
            verify_presigned_request(&parts, &resolver, rid(), aws_doc_now()).expect("verifies");
        assert_eq!(&*verified.access_key_id, AWS_DOC_AKID);
        assert_eq!(verified.request_signature_hex, AWS_DOC_SIGNATURE);
        assert_eq!(verified.payload, PayloadHashForSigning::UnsignedPayload);
    }

    #[test]
    fn test_aws_published_vector_tampered_query_value_fails() {
        // Bump `X-Amz-Expires` from 86400 to 86500 — still keeps `aws_doc_now`
        // inside the validity window, but flips one byte of the canonical
        // query so our recomputed signature diverges from the AWS-published
        // `aeeed9bb…` value.
        let q = aws_doc_query().replace("&X-Amz-Expires=86400", "&X-Amz-Expires=86500");
        let parts = aws_doc_parts(&q);
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("tampered expires");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    #[test]
    fn test_aws_published_vector_tampered_host_fails() {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{}", aws_doc_query()))
            .header("host", "evil.example.com")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("tampered host");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    #[test]
    fn test_aws_published_vector_tampered_signature_fails() {
        let q = aws_doc_query().replace(AWS_DOC_SIGNATURE, &"0".repeat(64));
        let parts = aws_doc_parts(&q);
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("tampered signature");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    #[test]
    fn test_unknown_access_key_rejected() {
        let parts = aws_doc_parts(&aws_doc_query());
        let other = FixedResolver::new("OTHER", AWS_DOC_SECRET);
        let err = verify_presigned_request(&parts, &other, rid(), aws_doc_now())
            .expect_err("unknown akid");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_credential_scope_date_mismatch_with_amz_date_rejected() {
        // X-Amz-Credential scope says 20130525, X-Amz-Date says 20130524.
        // Without the `ensure_scope_date_matches` call the verifier would
        // continue all the way to the HMAC compare and surface
        // SignatureDoesNotMatch — but the AWS spec wants a structural
        // AuthorizationHeaderMalformed first, mirroring the header-auth
        // `ensure_scope_date_matches` invariant. Deleting that call flips
        // this assertion to `SignatureDoesNotMatch`.
        let q = aws_doc_query().replace(
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request",
            "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130525%2Fus-east-1%2Fs3%2Faws4_request",
        );
        let parts = aws_doc_parts(&q);
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("scope-date mismatch");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    // ── Validity-window edges ───────────────────────────────────────────
    //
    // X-Amz-Date is the inclusive lower bound; `X-Amz-Date + X-Amz-Expires`
    // is the inclusive upper bound.

    #[test]
    fn test_validity_window_at_start_accepted() {
        let parts = aws_doc_parts(&aws_doc_query());
        let now = Utc.with_ymd_and_hms(2013, 5, 24, 0, 0, 0).unwrap();
        verify_presigned_request(&parts, &aws_doc_resolver(), rid(), now)
            .expect("exact start accepted");
    }

    #[test]
    fn test_validity_window_at_expiry_accepted() {
        let parts = aws_doc_parts(&aws_doc_query());
        // 20130524T000000Z + 86400 seconds = 20130525T000000Z.
        let now = Utc.with_ymd_and_hms(2013, 5, 25, 0, 0, 0).unwrap();
        verify_presigned_request(&parts, &aws_doc_resolver(), rid(), now)
            .expect("exact expiry accepted");
    }

    #[test]
    fn test_validity_window_after_expiry_rejected() {
        let parts = aws_doc_parts(&aws_doc_query());
        let now = Utc.with_ymd_and_hms(2013, 5, 25, 0, 0, 1).unwrap();
        let err =
            verify_presigned_request(&parts, &aws_doc_resolver(), rid(), now).expect_err("expired");
        assert_eq!(err.code, "RequestTimeTooSkewed");
    }

    #[test]
    fn test_validity_window_before_start_rejected() {
        let parts = aws_doc_parts(&aws_doc_query());
        let now = Utc.with_ymd_and_hms(2013, 5, 23, 23, 59, 59).unwrap();
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), now)
            .expect_err("not yet valid");
        assert_eq!(err.code, "RequestTimeTooSkewed");
    }

    // ── Payload-marker rules ────────────────────────────────────────────

    fn parts_with_extra_header(name: &str, value: &str) -> http::request::Parts {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{}", aws_doc_query()))
            .header("host", AWS_DOC_HOST)
            .header(name, value)
            .body(())
            .unwrap();
        req.into_parts().0
    }

    #[test]
    fn test_unsigned_payload_header_accepted() {
        // Setting `x-amz-content-sha256: UNSIGNED-PAYLOAD` doesn't enter the
        // canonical request (the URL didn't sign that header), so the
        // signature still matches the AWS-published vector.
        let parts = parts_with_extra_header("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect("unsigned-payload header accepted");
    }

    #[test]
    fn test_signed_payload_hash_header_rejected() {
        // 64 lowercase hex chars — looks like a signed body digest. PR 3
        // doesn't support presigned URLs that sign over a concrete body
        // hash, so this is InvalidRequest before signature work.
        let parts = parts_with_extra_header(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("signed-payload hash");
        assert_eq!(err.code, "InvalidRequest");
    }

    #[test]
    fn test_uppercase_signed_payload_hash_header_rejected_as_invalid_request() {
        // Same 64-hex digest but in uppercase. Before the case-insensitive
        // hex check this would fall through to `AuthorizationHeaderMalformed`
        // instead of `InvalidRequest`; replacing `is_ascii_hexdigit` with
        // the prior lowercase-only check flips this assertion.
        let parts = parts_with_extra_header(
            "x-amz-content-sha256",
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        );
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("uppercase signed-payload hash");
        assert_eq!(err.code, "InvalidRequest");
    }

    #[test]
    fn test_signed_payload_hash_query_marker_rejected_even_when_header_unsigned() {
        // Header carries the well-behaved `UNSIGNED-PAYLOAD` value, but
        // the signed query string smuggles in a concrete 64-hex digest.
        // The prior "header takes precedence" logic let this slip past;
        // scanning *both* sources catches it as `InvalidRequest`.
        let q = format!(
            "{}&X-Amz-Content-Sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            aws_doc_query()
        );
        let req = Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{q}"))
            .header("host", AWS_DOC_HOST)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("query-side signed-payload hash");
        assert_eq!(err.code, "InvalidRequest");
    }

    #[test]
    fn test_multiple_signed_payload_hash_query_markers_with_concrete_hex_rejected() {
        // Two `X-Amz-Content-Sha256` query occurrences: an unsigned
        // marker followed by a concrete 64-hex digest. Replacing the
        // all-occurrences scan in `check_presigned_payload_marker` with
        // a first-wins `break` flips this from `InvalidRequest` back to
        // acceptance via the leading `UNSIGNED-PAYLOAD` marker. Both
        // orderings are exercised so the rejection isn't accidentally
        // position-dependent.
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        for q in [
            format!(
                "{}&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Content-Sha256={hex}",
                aws_doc_query()
            ),
            format!(
                "{}&X-Amz-Content-Sha256={hex}&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD",
                aws_doc_query()
            ),
        ] {
            let parts = aws_doc_parts(&q);
            let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
                .expect_err("trailing concrete-hex marker must fail closed");
            assert_eq!(err.code, "InvalidRequest");
        }
    }

    #[test]
    fn test_multiple_signed_payload_hash_query_markers_with_disagreement_rejected() {
        // Two `X-Amz-Content-Sha256` query occurrences with distinct
        // non-streaming, non-hex values. The dangerous-pattern scan
        // passes; the disagreement check has to catch this.
        let q = format!(
            "{}&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Content-Sha256=UNSIGNED-OTHER",
            aws_doc_query()
        );
        let parts = aws_doc_parts(&q);
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("multi-marker disagreement");
        assert_eq!(err.code, "InvalidRequest");
    }

    #[test]
    fn test_identical_duplicate_unsigned_payload_query_markers_accepted() {
        // Pin the accept case: two identical `UNSIGNED-PAYLOAD` query
        // markers must not be widened into a rejection. The HMAC will
        // not match (the canonical query now contains an unsigned extra
        // param) but the payload-marker stage itself must pass — calling
        // the classifier directly isolates the property we care about
        // without coupling it to the signature compare.
        let q = format!(
            "{}&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD",
            aws_doc_query()
        );
        let parts = aws_doc_parts(&q);
        check_presigned_payload_marker(&parts, rid())
            .expect("identical duplicate markers accepted at the payload-marker stage");
    }

    #[test]
    fn test_signed_payload_hash_header_and_query_must_agree() {
        // Header says `UNSIGNED-PAYLOAD`, query says something else
        // entirely (deliberately non-`STREAMING-*` and non-64-hex so the
        // disagreement check — not the aws-chunked gate or the hex
        // check — is the rule under test). Without the agreement check,
        // the header would "win" silently and the request would proceed.
        let q = format!(
            "{}&X-Amz-Content-Sha256=UNSIGNED-DIFFERENT",
            aws_doc_query()
        );
        let req = Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{q}"))
            .header("host", AWS_DOC_HOST)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("header/query disagreement");
        assert_eq!(err.code, "InvalidRequest");
    }

    #[test]
    fn test_streaming_payload_marker_header_rejected() {
        let parts =
            parts_with_extra_header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("streaming marker");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    // ── aws-chunked rejection (request-shape gate) ──────────────────────

    #[test]
    fn test_presigned_aws_chunked_content_encoding_rejected() {
        let parts = parts_with_extra_header("content-encoding", "aws-chunked");
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("aws-chunked CE");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    #[test]
    fn test_presigned_x_amz_decoded_content_length_rejected() {
        let parts = parts_with_extra_header("x-amz-decoded-content-length", "100");
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("x-amz-decoded-content-length");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    #[test]
    fn test_presigned_x_amz_trailer_rejected() {
        let parts = parts_with_extra_header("x-amz-trailer", "x-amz-checksum-sha256");
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("x-amz-trailer");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    #[test]
    fn test_presigned_x_amz_content_sha256_streaming_query_rejected() {
        // STREAMING-* via the X-Amz-Content-Sha256 query param. Some
        // S3-compatible presigners put the marker on the URL instead of as
        // a header; either form must fail closed.
        let q = format!(
            "{}&X-Amz-Content-Sha256=STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            aws_doc_query()
        );
        let parts = aws_doc_parts(&q);
        let err = verify_presigned_request(&parts, &aws_doc_resolver(), rid(), aws_doc_now())
            .expect_err("streaming via query");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    // ── Presigned + STS (PR 4 of #63) ───────────────────────────────────

    /// Build a fresh presigned-URL query that signs `host` and includes a
    /// `X-Amz-Security-Token` query parameter. Returns the query string —
    /// the verifier rebuilds the canonical request from `parts` and the
    /// signed headers, so the same self-contained signing we already trust
    /// for the no-token reference vector applies here.
    fn build_sts_presigned_query(
        akid: &str,
        secret: &str,
        host: &str,
        amz_date: &str,
        token: &str,
    ) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::{Digest, Sha256};
        type HmacSha256 = Hmac<Sha256>;

        let date_yyyymmdd = &amz_date[..8];
        // AWS uri-encode the token for the query: `+`, `/`, `=` go to
        // their %-escapes, everything else (alnum, `-_.~`) stays. The
        // proxy decodes the same way on input.
        let encoded_token: String = token
            .bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect();
        let encoded_credential =
            format!("{akid}%2F{date_yyyymmdd}%2Fus-east-1%2Fs3%2Faws4_request");

        // Canonical query: sort by encoded key. The request URL we'll
        // send keeps fields in any order — the verifier sorts them — so
        // we only need to compute the canonical form for the signature.
        let mut params: Vec<(String, String)> = vec![
            (
                "X-Amz-Algorithm".to_string(),
                "AWS4-HMAC-SHA256".to_string(),
            ),
            ("X-Amz-Credential".to_string(), encoded_credential.clone()),
            ("X-Amz-Date".to_string(), amz_date.to_string()),
            ("X-Amz-Expires".to_string(), "60".to_string()),
            ("X-Amz-Security-Token".to_string(), encoded_token.clone()),
            ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
        ];
        params.sort();
        let canonical_query = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");

        let canonical_request =
            format!("GET\n/test.txt\n{canonical_query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");
        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        let creq_hex = hex::encode(hasher.finalize());

        let scope = format!("{date_yyyymmdd}/us-east-1/s3/aws4_request");
        let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{creq_hex}");

        fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), date_yyyymmdd.as_bytes());
        let k_region = hmac(&k_date, b"us-east-1");
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, sts.as_bytes()));

        // Emit the URL in the same order params were sorted; sticking
        // with the canonical order keeps the test query mirror the
        // canonical query for easy diffing.
        format!("{canonical_query}&X-Amz-Signature={signature}")
    }

    fn sts_parts(query: &str) -> http::request::Parts {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{query}"))
            .header("host", AWS_DOC_HOST)
            .body(())
            .unwrap();
        req.into_parts().0
    }

    fn sts_now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    #[test]
    fn test_presigned_sts_round_trip_verifies() {
        // Reverts PR 3's `InvalidToken` rejection for presigned URLs that
        // carry `X-Amz-Security-Token`. The canonical query includes the
        // token because only `X-Amz-Signature` is excluded; the resolver
        // accepts the `(akid, token)` tuple. Removing the
        // `pres.session_token.as_deref()` argument to the resolver in
        // `verify_presigned_request` would flip this to `InvalidAccessKeyId`
        // because the resolver would look up the no-token namespace.
        let q = build_sts_presigned_query(
            AWS_DOC_AKID,
            AWS_DOC_SECRET,
            AWS_DOC_HOST,
            "20260101T120000Z",
            "tok-abc",
        );
        let parts = sts_parts(&q);
        let resolver = FixedResolver::with_token(
            AWS_DOC_AKID,
            "tok-abc",
            AWS_DOC_SECRET,
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        );
        let verified =
            verify_presigned_request(&parts, &resolver, rid(), sts_now()).expect("verifies");
        assert_eq!(&*verified.access_key_id, AWS_DOC_AKID);
    }

    #[test]
    fn test_presigned_sts_token_with_special_bytes_round_trip() {
        // Real STS tokens contain `+`, `/`, `=`. The token must round-trip
        // through percent-decoding (the resolver sees the same bytes the
        // signer used) and the canonical query must encode them back to
        // their byte-canonical forms. Pinning a token with all three
        // characters catches any drift to form-decoding (`+` → space).
        let q = build_sts_presigned_query(
            AWS_DOC_AKID,
            AWS_DOC_SECRET,
            AWS_DOC_HOST,
            "20260101T120000Z",
            "abc+def/ghi==",
        );
        let parts = sts_parts(&q);
        let resolver = FixedResolver::with_token(
            AWS_DOC_AKID,
            "abc+def/ghi==",
            AWS_DOC_SECRET,
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        );
        verify_presigned_request(&parts, &resolver, rid(), sts_now())
            .expect("special-byte token round-trips");
    }

    #[test]
    fn test_presigned_sts_wrong_token_returns_invalid_access_key_id() {
        // Resolver has token "right-token"; the URL was signed with the
        // wrong token. The signature itself would have matched if the
        // resolver picked any credential — but with no `(akid, token)`
        // match we surface `InvalidAccessKeyId` before reaching HMAC.
        let q = build_sts_presigned_query(
            AWS_DOC_AKID,
            AWS_DOC_SECRET,
            AWS_DOC_HOST,
            "20260101T120000Z",
            "wrong-token",
        );
        let parts = sts_parts(&q);
        let resolver = FixedResolver::with_token(
            AWS_DOC_AKID,
            "right-token",
            AWS_DOC_SECRET,
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        );
        let err =
            verify_presigned_request(&parts, &resolver, rid(), sts_now()).expect_err("wrong token");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_presigned_sts_expired_token_returns_expired_token() {
        let q = build_sts_presigned_query(
            AWS_DOC_AKID,
            AWS_DOC_SECRET,
            AWS_DOC_HOST,
            "20260101T120000Z",
            "tok-abc",
        );
        let parts = sts_parts(&q);
        // `expires_at` is in the past relative to `sts_now()`.
        let resolver = FixedResolver::with_token(
            AWS_DOC_AKID,
            "tok-abc",
            AWS_DOC_SECRET,
            Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
        );
        let err = verify_presigned_request(&parts, &resolver, rid(), sts_now())
            .expect_err("expired token");
        assert_eq!(err.code, "ExpiredToken");
    }

    #[test]
    fn test_presigned_sts_token_when_only_no_token_credential_configured() {
        // URL carries (akid, token) but the resolver only knows a
        // long-lived credential under the same akid. Token namespace
        // miss → `InvalidAccessKeyId`.
        let q = build_sts_presigned_query(
            AWS_DOC_AKID,
            AWS_DOC_SECRET,
            AWS_DOC_HOST,
            "20260101T120000Z",
            "tok-abc",
        );
        let parts = sts_parts(&q);
        let resolver = FixedResolver::new(AWS_DOC_AKID, AWS_DOC_SECRET);
        let err = verify_presigned_request(&parts, &resolver, rid(), sts_now())
            .expect_err("namespace miss");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_presigned_no_token_when_only_token_credential_configured() {
        // Inverse: the URL has no `X-Amz-Security-Token`, but the
        // resolver only knows a token-bearing credential under that akid.
        // No-token namespace miss → `InvalidAccessKeyId`.
        let parts = aws_doc_parts(&aws_doc_query());
        let resolver = FixedResolver::with_token(
            AWS_DOC_AKID,
            "tok-abc",
            AWS_DOC_SECRET,
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        );
        let err = verify_presigned_request(&parts, &resolver, rid(), aws_doc_now())
            .expect_err("no-token namespace miss");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_presigned_sts_with_aws_chunked_still_rejected() {
        // Presigned + aws-chunked stays fail-closed regardless of STS —
        // the rejection runs before the parser, so adding a session
        // token can't open a path that was deliberately closed.
        let q = build_sts_presigned_query(
            AWS_DOC_AKID,
            AWS_DOC_SECRET,
            AWS_DOC_HOST,
            "20260101T120000Z",
            "tok-abc",
        );
        let req = Request::builder()
            .method("GET")
            .uri(format!("/test.txt?{q}"))
            .header("host", AWS_DOC_HOST)
            .header("x-amz-decoded-content-length", "100")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let resolver = FixedResolver::with_token(
            AWS_DOC_AKID,
            "tok-abc",
            AWS_DOC_SECRET,
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        );
        let err = verify_presigned_request(&parts, &resolver, rid(), sts_now())
            .expect_err("aws-chunked + STS");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    #[test]
    fn test_presigned_sts_with_sigv4a_still_rejected() {
        // SigV4A rejection happens before STS handling too.
        let amz_date = "20260101T120000Z";
        let date_yyyymmdd = &amz_date[..8];
        let q = format!(
            "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256\
             &X-Amz-Credential={AWS_DOC_AKID}%2F{date_yyyymmdd}%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date={amz_date}\
             &X-Amz-Expires=60\
             &X-Amz-Security-Token=tok-abc\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=0000000000000000000000000000000000000000000000000000000000000000"
        );
        let parts = sts_parts(&q);
        let resolver = FixedResolver::with_token(
            AWS_DOC_AKID,
            "tok-abc",
            AWS_DOC_SECRET,
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        );
        let err = verify_presigned_request(&parts, &resolver, rid(), sts_now())
            .expect_err("SigV4A + STS");
        assert_eq!(err.code, "UnsupportedSignature");
    }
}
