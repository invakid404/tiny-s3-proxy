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

use crate::auth::credentials::InboundCredentialResolver;
use crate::auth::sigv4::canonical::{
    CanonicalQueryMode, build_canonical_request_from_signed_headers, percent_decode_for_query,
};
use crate::auth::sigv4::parser::{
    CredentialScope, ensure_scope_date_matches, parse_amz_date, parse_credential,
    parse_signature_hex, parse_signed_headers,
};
use crate::auth::sigv4::payload::PayloadHashForSigning;
use crate::auth::sigv4::{VerifiedRequest, build_string_to_sign, derive_signing_key, parse_hex32};
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
/// (`X-Amz-Security-Token`) and SigV4A (`AWS4-ECDSA-*`) presigned URLs are
/// scoped to follow-up PRs of issue #63, so they get their own fail-closed
/// error codes (`InvalidToken` / `UnsupportedSignature`) before any
/// credential lookup or HMAC math.
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
    let mut security_token_seen = false;

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
        if canonical_name == "X-Amz-Security-Token" {
            security_token_seen = true;
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

    // STS session tokens go on a separate compatibility path; fail closed
    // before any credential lookup. Mirrors the parser-level rejection for
    // STS tokens carried in the Authorization header's SignedHeaders.
    if security_token_seen {
        return Err(S3Error::invalid_token(
            "temporary credentials (X-Amz-Security-Token) are not supported in strict mode; \
             tracked in PR 4 of issue #63",
            request_id,
        ));
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

    // Resolve the access key. A miss → InvalidAccessKeyId; a store error →
    // InternalError. PR 3 always passes `None` for the session token —
    // STS-issued temporary credentials are rejected earlier by the parser.
    let credential = resolver
        .resolve(&pres.access_key_id, None)
        .map_err(|e| {
            tracing::error!(error = %e, "credential resolver failed");
            S3Error::internal_error("credential resolver failed", request_id)
        })?
        .ok_or_else(|| {
            S3Error::invalid_access_key_id("access-key id is not configured", request_id)
        })?;

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
        scope: pres.scope,
        signed_headers: pres.signed_headers,
        request_signature_hex: pres.signature_hex,
        signing_key,
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

/// Verify the request's `x-amz-content-sha256` marker (header or query) is
/// either absent or set to `UNSIGNED-PAYLOAD`. Signed-payload-hash and
/// streaming presigned URLs are deferred — the standard S3 presigned canonical
/// request uses `UNSIGNED-PAYLOAD`.
fn check_presigned_payload_marker(
    parts: &http::request::Parts,
    request_id: &str,
) -> Result<(), S3Error> {
    // Header form takes precedence — if both are present and signed, the
    // header is the one that goes into `canonical_headers`. The query form
    // is still scanned so a header-absent / query-present URL is validated.
    let mut marker_bytes: Option<Vec<u8>> = None;

    if let Some(v) = parts.headers.get("x-amz-content-sha256") {
        marker_bytes = Some(v.as_bytes().to_vec());
    } else {
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
                marker_bytes = Some(percent_decode_for_query(raw_v));
                break;
            }
        }
    }

    let Some(bytes) = marker_bytes else {
        return Ok(());
    };
    let s = std::str::from_utf8(&bytes).map_err(|_| {
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
    // 64 lowercase hex characters → a concrete signed-payload digest. AWS's
    // documented presigned canonical request is `UNSIGNED-PAYLOAD`; supporting
    // signed-payload presigned URLs would require buffering bodies on a path
    // that currently avoids it. Deferred.
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
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
    fn test_parse_security_token_rejected_as_invalid_token() {
        let q = format!("{}&X-Amz-Security-Token=FQoG…", aws_doc_presigned_query());
        let err = parse_presigned_authorization(&q, rid()).expect_err("STS token");
        assert_eq!(err.code, "InvalidToken");
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
    fn test_parse_signed_headers_security_token_rejected() {
        // STS via SignedHeaders should be rejected the same way the
        // header-path parser does it; routed through `parse_signed_headers`.
        let q = aws_doc_presigned_query().replace(
            "&X-Amz-SignedHeaders=host",
            "&X-Amz-SignedHeaders=host%3Bx-amz-security-token",
        );
        let err = parse_presigned_authorization(&q, rid()).expect_err("STS in signed headers");
        assert_eq!(err.code, "InvalidToken");
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
    };
    use chrono::{TimeZone, Utc};
    use http::Request;
    use std::sync::Arc;

    fn rid() -> &'static str {
        "rid"
    }

    struct FixedResolver {
        akid: Arc<str>,
        secret: InboundSecret,
    }

    impl FixedResolver {
        fn new(akid: &str, secret: &str) -> Self {
            Self {
                akid: Arc::from(akid),
                secret: InboundSecret::new(secret.to_string()),
            }
        }
    }

    impl InboundCredentialResolver for FixedResolver {
        fn resolve(
            &self,
            access_key_id: &str,
            _session_token: Option<&str>,
        ) -> Result<Option<Arc<InboundCredential>>, CredentialResolveError> {
            if access_key_id == self.akid.as_ref() {
                Ok(Some(Arc::new(InboundCredential {
                    access_key_id: self.akid.clone(),
                    secret_access_key: self.secret.clone(),
                    session_token: None,
                    expires_at: None,
                })))
            } else {
                Ok(None)
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
}
