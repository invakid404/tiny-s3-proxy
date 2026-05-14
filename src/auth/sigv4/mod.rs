//! Strict-mode inbound SigV4 verification.
//!
//! Public entry point: [`SigV4Verifier::verify`] dispatches between the
//! `Authorization` header path and the presigned-URL `X-Amz-*` query path
//! (or rejects requests that mix both / carry neither). The header path
//! does scope / date / canonical-request / signature; the presigned path
//! does query-param parse / validity-window / canonical-request /
//! signature. Both return the same [`VerifiedRequest`] shape so downstream
//! handler code stays agnostic of which mechanism the client used.
//! [`SigV4Verifier::verify_payload_hash`] confirms the body SHA-256 matches
//! a signed `x-amz-content-sha256` (header path only — presigned URLs use
//! `UNSIGNED-PAYLOAD` and skip body buffering).
//!
//! The verifier deliberately does not pull bytes off the wire. The caller
//! decides whether the operation has a body and whether to buffer it
//! (using `VerifiedRequest::payload.requires_body_bytes()`); we just consume
//! the buffer once it exists. This matches our current request-dispatch
//! shape — small request bodies are already routed through `to_bytes`, and
//! the strict path doesn't change that.

pub mod canonical;
pub mod parser;
pub mod payload;
pub mod presigned;
pub mod streaming;

use crate::auth::credentials::{
    CredentialResolveError, InboundCredential, InboundCredentialResolver,
};
use crate::auth::verified::{VerifiedCredentialScope, VerifiedSigningContext};
use crate::s3::errors::S3Error;
use chrono::{DateTime, Utc};
use http::HeaderName;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use crate::auth::verified::VerifiedRequest;

use self::canonical::build_canonical_request;
use self::parser::{
    AuthorizationAlgorithm, CredentialScope, classify_authorization_algorithm, enforce_skew,
    ensure_scope_date_matches, parse_authorization, resolve_request_time,
};
use self::payload::{PayloadHashForSigning, classify_payload_header, verify_payload_matches_hash};

/// SigV4 signing key (HMAC-SHA256 output, 32 bytes), zeroized on drop.
///
/// Reused for chunk-by-chunk verification of aws-chunked uploads (see
/// [`streaming::StreamingSigV4Context`]); keeping it in `Zeroizing` from
/// the start avoids leaving HMAC keys lingering in memory after a request
/// finishes.
pub struct SigningKey(Zeroizing<[u8; 32]>);

impl SigningKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Clone the underlying 32-byte HMAC key into a fresh `Zeroizing`
    /// buffer. Used by the streaming verifier to carry a private copy of
    /// the signing key across chunk boundaries without exposing it
    /// through the public API.
    pub(crate) fn clone_bytes(&self) -> Zeroizing<[u8; 32]> {
        self.0.clone()
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(<32 bytes>)")
    }
}

/// Top-level verifier. One instance is shared via `Arc` across all requests.
pub struct SigV4Verifier {
    resolver: Arc<dyn InboundCredentialResolver>,
    max_skew: Duration,
}

impl std::fmt::Debug for SigV4Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigV4Verifier")
            .field("max_skew", &self.max_skew)
            .finish_non_exhaustive()
    }
}

impl SigV4Verifier {
    pub fn new(resolver: Arc<dyn InboundCredentialResolver>, max_skew: Duration) -> Self {
        Self { resolver, max_skew }
    }

    /// Verify the request line, headers, and signature. The body is **not**
    /// touched here; pass it to `verify_payload_hash` if
    /// `result.payload.requires_body_bytes()` is true.
    pub fn verify(
        &self,
        parts: &http::request::Parts,
        request_id: &str,
    ) -> Result<VerifiedRequest, S3Error> {
        self.verify_at(parts, request_id, Utc::now())
    }

    /// Testing seam: same as `verify` but with a caller-supplied `now`.
    /// Dispatches between the `Authorization` header path and the
    /// `X-Amz-*` presigned-URL query path; rejects requests that mix both
    /// or carry neither up front.
    pub fn verify_at(
        &self,
        parts: &http::request::Parts,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedRequest, S3Error> {
        let has_query_auth =
            presigned::has_presigned_signature_query(parts.uri.query().unwrap_or(""));
        let has_header_auth = parts.headers.contains_key(http::header::AUTHORIZATION);

        match (has_header_auth, has_query_auth) {
            (true, true) => Err(S3Error::invalid_request(
                "Only one auth mechanism is allowed; use either the Authorization header \
                 or X-Amz-* query authentication, not both",
                request_id,
            )),
            (false, true) => {
                // Cheap algorithm sniff so SigV4A presigned URLs route
                // to their own verifier. Missing / unrecognised
                // algorithms fall through to the HMAC parser, which
                // surfaces `AuthorizationHeaderMalformed`.
                let raw_query = parts.uri.query().unwrap_or("");
                match presigned::classify_presigned_algorithm(raw_query) {
                    Some(presigned::PresignedAlgorithm::SigV4aEcdsaP256Sha256) => {
                        crate::auth::sigv4a::presigned::verify_sigv4a_presigned_request(
                            parts,
                            self.resolver.as_ref(),
                            request_id,
                            now,
                        )
                    }
                    _ => presigned::verify_presigned_request(
                        parts,
                        self.resolver.as_ref(),
                        request_id,
                        now,
                    ),
                }
            }
            (true, false) => {
                // Cheap algorithm sniff so SigV4A (`AWS4-ECDSA-P256-SHA256`)
                // requests are routed to their own parser/verifier; HMAC
                // requests stay on the existing path. Unknown algorithms
                // fall through to the HMAC parser, which surfaces a
                // structured `AuthorizationHeaderMalformed` for them.
                let raw = parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                match classify_authorization_algorithm(raw) {
                    AuthorizationAlgorithm::SigV4aEcdsaP256Sha256 => {
                        crate::auth::sigv4a::verify_authorization_header_at(
                            parts,
                            self.resolver.as_ref(),
                            self.max_skew,
                            request_id,
                            now,
                        )
                    }
                    AuthorizationAlgorithm::SigV4HmacSha256 | AuthorizationAlgorithm::Other => {
                        self.verify_authorization_header_at(parts, request_id, now)
                    }
                }
            }
            (false, false) => Err(S3Error::missing_authentication_token(
                "request is missing the Authorization header or X-Amz-Signature query parameter",
                request_id,
            )),
        }
    }

    /// Header-auth path: parse the `Authorization` header, classify the
    /// payload, build and verify the canonical request. Extracted from the
    /// PR 1 `verify_at` body so the new dispatch can route header vs.
    /// presigned-URL flows separately.
    fn verify_authorization_header_at(
        &self,
        parts: &http::request::Parts,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedRequest, S3Error> {
        let auth_header = parts.headers.get("authorization").ok_or_else(|| {
            S3Error::missing_authentication_token(
                "request is missing the Authorization header",
                request_id,
            )
        })?;
        let auth_str = auth_header.to_str().map_err(|_| {
            S3Error::authorization_header_malformed(
                "Authorization header is not valid ASCII",
                request_id,
            )
        })?;
        let auth = parse_authorization(auth_str, request_id)?;

        // Resolve the request timestamp first; the credential scope date
        // must match the request date, and we want a clear skew/date error
        // before we burn an HMAC.
        let (amz_date, request_time) = resolve_request_time(&parts.headers, request_id)?;
        enforce_skew(
            request_time,
            now,
            chrono::Duration::from_std(self.max_skew).unwrap_or(chrono::Duration::seconds(900)),
            request_id,
        )?;
        ensure_scope_date_matches(&auth.scope, request_time, request_id)?;

        // Classify the payload header up front (cheap; rejects fail-closed
        // streaming sentinels before we resolve credentials).
        let payload_header = parts
            .headers
            .get("x-amz-content-sha256")
            .ok_or_else(|| {
                S3Error::authorization_header_malformed(
                    "request is missing x-amz-content-sha256",
                    request_id,
                )
            })?
            .to_str()
            .map_err(|_| {
                S3Error::authorization_header_malformed(
                    "x-amz-content-sha256 is not valid ASCII",
                    request_id,
                )
            })?;
        let payload = classify_payload_header(payload_header, request_id)?;

        // Extract `x-amz-security-token` if present and require the
        // SignedHeaders list to cover it. An unsigned token header would
        // let the client influence resolver namespace without binding the
        // token to their signature.
        let session_token = extract_header_session_token(parts, &auth.signed_headers, request_id)?;

        // Resolve credential. Tuple miss → InvalidAccessKeyId, expired →
        // ExpiredToken, resolver-classified malformed → InvalidToken,
        // store error → InternalError.
        let credential = resolve_credential_for_sigv4(
            self.resolver.as_ref(),
            &auth.access_key_id,
            session_token.as_deref(),
            now,
            request_id,
        )?;

        // Build canonical request, hash it, derive signing key, calculate
        // expected signature, constant-time compare.
        let canonical = build_canonical_request(parts, &auth, &payload, request_id)?;
        let signing_key = derive_signing_key(
            credential.secret_access_key.expose(),
            &auth.scope.date_yyyymmdd,
            &auth.scope.region,
            &auth.scope.service,
        );

        let string_to_sign =
            build_string_to_sign(&auth.scope, &amz_date, &canonical.canonical_request);
        let expected_hex = aws_sigv4::sign::v4::calculate_signature(
            signing_key.as_bytes(),
            string_to_sign.as_bytes(),
        );
        let expected_bytes = parse_hex32(&expected_hex).ok_or_else(|| {
            S3Error::internal_error("internal error computing expected signature", request_id)
        })?;

        if expected_bytes.ct_eq(&auth.signature).unwrap_u8() != 1 {
            return Err(S3Error::signature_does_not_match(
                "computed request signature does not match the supplied signature",
                request_id,
            ));
        }

        Ok(VerifiedRequest {
            access_key_id: credential.access_key_id.clone(),
            credential_scope: VerifiedCredentialScope::SigV4(auth.scope),
            signed_headers: auth.signed_headers,
            request_signature_hex: auth.signature_hex,
            signing_context: VerifiedSigningContext::HmacSha256(signing_key),
            amz_date,
            payload,
        })
    }

    /// Confirm the buffered request body hashes to the signed payload hash.
    /// Only call when `verified.payload.requires_body_bytes()` is true.
    pub fn verify_payload_hash(
        &self,
        verified: &VerifiedRequest,
        body_bytes: &[u8],
        request_id: &str,
    ) -> Result<(), S3Error> {
        match &verified.payload {
            PayloadHashForSigning::SignedSha256 { hex, .. } => {
                verify_payload_matches_hash(body_bytes, hex, request_id)
            }
            // Calling verify_payload_hash on a payload whose body isn't a
            // single buffered SHA-256 is a caller bug, but we treat it as
            // a no-op rather than panicking so a future refactor can't
            // accidentally break a request. The HMAC streaming variants
            // are verified by the aws-chunked decoder, not here.
            PayloadHashForSigning::UnsignedPayload
            | PayloadHashForSigning::StreamingUnsignedPayloadTrailer
            | PayloadHashForSigning::StreamingAws4HmacSha256Payload
            | PayloadHashForSigning::StreamingAws4HmacSha256PayloadTrailer => Ok(()),
        }
    }
}

pub(crate) fn derive_signing_key(
    secret: &str,
    date_yyyymmdd: &str,
    region: &str,
    service: &str,
) -> SigningKey {
    // We could use aws_sigv4::sign::v4::generate_signing_key, but its
    // return type is `impl AsRef<[u8]>` (and it owns a different internal
    // buffer type), which is awkward to keep in our zeroized container.
    // Recomputing the four-step HMAC ourselves is trivial.
    //
    // Each intermediate HMAC output (kDate, kRegion, kService) is wrapped in
    // `Zeroizing` so the stack-stored 32-byte buffer is wiped when the
    // wrapper drops. Without this, the intermediates would linger in the
    // stack frame after the function returns, defeating the point of
    // zeroizing only the final kSigning.
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    fn hmac(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(data);
        let result = mac.finalize().into_bytes();

        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Zeroizing::new(out)
    }

    let mut prefix = Zeroizing::new(String::with_capacity(4 + secret.len()));
    prefix.push_str("AWS4");
    prefix.push_str(secret);

    let k_date = hmac(prefix.as_bytes(), date_yyyymmdd.as_bytes());
    let k_region = hmac(&k_date[..], region.as_bytes());
    let k_service = hmac(&k_region[..], service.as_bytes());
    let k_signing = hmac(&k_service[..], b"aws4_request");

    SigningKey(k_signing)
}

pub(crate) fn build_string_to_sign(
    scope: &CredentialScope,
    amz_date: &str,
    canonical_request: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(canonical_request.as_bytes());
    let hashed = hasher.finalize();
    let mut hex = String::with_capacity(64);
    const HEX: &[u8] = b"0123456789abcdef";
    for b in hashed.iter() {
        hex.push(HEX[(b >> 4) as usize] as char);
        hex.push(HEX[(b & 0x0f) as usize] as char);
    }

    let scope_str = format!(
        "{}/{}/{}/aws4_request",
        scope.date_yyyymmdd, scope.region, scope.service
    );
    format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", amz_date, scope_str, hex)
}

pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Header-auth helper: pull an `x-amz-security-token` value out of the
/// request and confirm the client signed it. Returns `None` when the header
/// is absent (a non-STS request).
///
/// Header rules:
/// - Missing header + token in `SignedHeaders` is already caught by the
///   canonical-headers builder (it can't reconstruct a missing signed
///   header), so we don't double-check here.
/// - Header present but not signed → `AuthorizationHeaderMalformed`.
/// - Duplicate header lines → `AuthorizationHeaderMalformed` (we don't
///   join token values for resolver lookup; STS tokens are not a
///   `,`-mergeable list).
/// - Empty value after SigV4 whitespace normalization →
///   `AuthorizationHeaderMalformed`.
pub(crate) fn extract_header_session_token(
    parts: &http::request::Parts,
    signed_headers: &[HeaderName],
    request_id: &str,
) -> Result<Option<String>, S3Error> {
    let mut iter = parts.headers.get_all("x-amz-security-token").iter();
    let Some(first) = iter.next() else {
        return Ok(None);
    };
    if iter.next().is_some() {
        return Err(S3Error::authorization_header_malformed(
            "request has multiple x-amz-security-token header values",
            request_id,
        ));
    }

    if !signed_headers
        .iter()
        .any(|n| n.as_str() == "x-amz-security-token")
    {
        return Err(S3Error::authorization_header_malformed(
            "x-amz-security-token header must be listed in SignedHeaders",
            request_id,
        ));
    }

    let raw = first.to_str().map_err(|_| {
        S3Error::authorization_header_malformed(
            "x-amz-security-token header value is not valid ASCII",
            request_id,
        )
    })?;
    // SigV4 header whitespace normalization matches the canonicalizer:
    // trim ASCII spaces, then collapse internal runs of spaces.
    let normalized = normalize_sigv4_header_value(raw);
    if normalized.is_empty() {
        return Err(S3Error::authorization_header_malformed(
            "x-amz-security-token header value is empty",
            request_id,
        ));
    }
    Ok(Some(normalized))
}

/// SigV4 header normalization: trim leading/trailing ASCII spaces and
/// collapse internal runs of spaces. Kept private to this module — the
/// canonicalizer has its own copy because it operates on already-string-
/// converted bytes inside the canonical request layout.
fn normalize_sigv4_header_value(s: &str) -> String {
    let trimmed = s.trim_matches(' ');
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_space = false;
    for ch in trimmed.chars() {
        if ch == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

/// Resolve a credential and translate resolver errors into the wire-format
/// `S3Error` variants the strict verifier expects. Shared between the
/// header-auth and presigned paths so the error mapping stays in one place:
///
/// - tuple miss (`Ok(None)`) → `InvalidAccessKeyId`
/// - `Expired` → `ExpiredToken`
/// - `InvalidToken` → `InvalidToken`
/// - `Internal` → `InternalError`
pub(crate) fn resolve_credential_for_sigv4(
    resolver: &dyn InboundCredentialResolver,
    access_key_id: &str,
    session_token: Option<&str>,
    now: DateTime<Utc>,
    request_id: &str,
) -> Result<Arc<InboundCredential>, S3Error> {
    match resolver.resolve(access_key_id, session_token, now) {
        Ok(Some(cred)) => Ok(cred),
        Ok(None) => Err(S3Error::invalid_access_key_id(
            "access-key id is not configured",
            request_id,
        )),
        Err(CredentialResolveError::Expired { .. }) => Err(S3Error::expired_token(
            "The provided token has expired.",
            request_id,
        )),
        Err(CredentialResolveError::InvalidToken) => Err(S3Error::invalid_token(
            "The provided session token is malformed or otherwise invalid.",
            request_id,
        )),
        Err(e @ CredentialResolveError::Internal(_)) => {
            tracing::error!(error = %e, "credential resolver failed");
            Err(S3Error::internal_error(
                "credential resolver failed",
                request_id,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::credentials::{
        CredentialResolveError, InboundCredential, InboundCredentialResolver, InboundSecret,
        SessionToken,
    };
    use crate::auth::sigv4::parser::SigV4Authorization;
    use chrono::TimeZone;
    use http::Request;

    /// Test resolver shared across the header-auth and (test-only) STS
    /// scenarios. Supports a single no-token credential and an optional
    /// token-bearing credential under the same access-key id. Both are
    /// configured explicitly so each test pins its own resolver shape.
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

    /// Sign a request with the given key material and produce
    /// (Authorization header, x-amz-date value). The signing logic here is
    /// kept self-contained so the test asserts independently of the
    /// verifier — i.e. matches AWS, not just "matches our own canonical
    /// builder".
    #[allow(clippy::too_many_arguments)]
    fn sign_request_for_test(
        method: &str,
        uri: &str,
        host: &str,
        amz_date: &str,
        payload_hash: &str,
        akid: &str,
        secret: &str,
        region: &str,
    ) -> (String, http::HeaderMap) {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::{Digest, Sha256};
        type HmacSha256 = Hmac<Sha256>;

        let date_yyyymmdd = &amz_date[..8];
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_hash)
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();

        let signed_headers = ["host", "x-amz-content-sha256", "x-amz-date"];
        let signed_headers_str = signed_headers.join(";");

        let payload_for_signing = match payload_hash {
            "UNSIGNED-PAYLOAD" => PayloadHashForSigning::UnsignedPayload,
            other if other.len() == 64 => {
                let bytes = parse_hex32(other).unwrap();
                PayloadHashForSigning::SignedSha256 {
                    hex: other.to_string(),
                    bytes,
                }
            }
            other => panic!("unsupported payload hash for test: {other}"),
        };
        let signed = SigV4Authorization {
            access_key_id: akid.to_string(),
            scope: CredentialScope {
                date: chrono::NaiveDate::parse_from_str(date_yyyymmdd, "%Y%m%d").unwrap(),
                date_yyyymmdd: date_yyyymmdd.to_string(),
                region: region.to_string(),
                service: "s3".to_string(),
            },
            signed_headers: signed_headers
                .iter()
                .map(|n| http::HeaderName::from_static(n))
                .collect(),
            signature: [0u8; 32],
            signature_hex: "0".repeat(64),
        };

        let canonical =
            build_canonical_request(&parts, &signed, &payload_for_signing, "rid").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(canonical.canonical_request.as_bytes());
        let creq_hex = hex::encode(hasher.finalize());

        let scope_str = format!("{date_yyyymmdd}/{region}/s3/aws4_request");
        let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope_str}\n{creq_hex}");

        fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), date_yyyymmdd.as_bytes());
        let k_region = hmac(&k_date, region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, sts.as_bytes()));

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={akid}/{date_yyyymmdd}/{region}/s3/aws4_request, \
             SignedHeaders={signed_headers_str}, Signature={signature}"
        );
        (auth_header, parts.headers)
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    fn build_verifier(akid: &str, secret: &str) -> SigV4Verifier {
        let resolver: Arc<dyn InboundCredentialResolver> =
            Arc::new(FixedResolver::new(akid, secret));
        SigV4Verifier::new(resolver, Duration::from_secs(900))
    }

    fn parts_for(
        method: &str,
        uri: &str,
        headers: http::HeaderMap,
        auth: &str,
    ) -> http::request::Parts {
        let mut req = Request::builder().method(method).uri(uri);
        for (k, v) in headers.iter() {
            req = req.header(k.clone(), v.clone());
        }
        req = req.header("authorization", auth);
        let req = req.body(()).unwrap();
        let (parts, _) = req.into_parts();
        parts
    }

    /// Like `sign_request_for_test`, but signs over the host /
    /// content-sha256 / date headers PLUS one additional caller-supplied
    /// header. Used by the STS tests to sign `x-amz-security-token`.
    /// `extra` must be lowercase (the parser rejects mixed case in
    /// SignedHeaders) and sort lexicographically into the right position
    /// relative to `host`, `x-amz-content-sha256`, `x-amz-date`.
    #[allow(clippy::too_many_arguments)]
    fn sign_request_with_extra_header(
        method: &str,
        uri: &str,
        host: &str,
        amz_date: &str,
        payload_hash: &str,
        akid: &str,
        secret: &str,
        region: &str,
        extra: (&str, &str),
    ) -> (String, http::HeaderMap) {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::{Digest, Sha256};
        type HmacSha256 = Hmac<Sha256>;

        let date_yyyymmdd = &amz_date[..8];
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_hash)
            .header(extra.0, extra.1)
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();

        let mut signed_names: Vec<&str> =
            vec!["host", "x-amz-content-sha256", "x-amz-date", extra.0];
        signed_names.sort();
        let signed_headers_str = signed_names.join(";");

        let payload_for_signing = match payload_hash {
            "UNSIGNED-PAYLOAD" => PayloadHashForSigning::UnsignedPayload,
            other if other.len() == 64 => {
                let bytes = parse_hex32(other).unwrap();
                PayloadHashForSigning::SignedSha256 {
                    hex: other.to_string(),
                    bytes,
                }
            }
            other => panic!("unsupported payload hash for test: {other}"),
        };
        let signed = SigV4Authorization {
            access_key_id: akid.to_string(),
            scope: CredentialScope {
                date: chrono::NaiveDate::parse_from_str(date_yyyymmdd, "%Y%m%d").unwrap(),
                date_yyyymmdd: date_yyyymmdd.to_string(),
                region: region.to_string(),
                service: "s3".to_string(),
            },
            signed_headers: signed_names
                .iter()
                .map(|n| HeaderName::from_bytes(n.as_bytes()).unwrap())
                .collect(),
            signature: [0u8; 32],
            signature_hex: "0".repeat(64),
        };

        let canonical =
            build_canonical_request(&parts, &signed, &payload_for_signing, "rid").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(canonical.canonical_request.as_bytes());
        let creq_hex = hex::encode(hasher.finalize());

        let scope_str = format!("{date_yyyymmdd}/{region}/s3/aws4_request");
        let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope_str}\n{creq_hex}");

        fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
            let mut mac = HmacSha256::new_from_slice(key).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), date_yyyymmdd.as_bytes());
        let k_region = hmac(&k_date, region.as_bytes());
        let k_service = hmac(&k_region, b"s3");
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, sts.as_bytes()));

        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={akid}/{date_yyyymmdd}/{region}/s3/aws4_request, \
             SignedHeaders={signed_headers_str}, Signature={signature}"
        );
        (auth_header, parts.headers)
    }

    #[test]
    fn test_signed_request_round_trip_get() {
        let (auth, headers) = sign_request_for_test(
            "GET",
            "/bucket/key?foo=bar",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        let parts = parts_for("GET", "/bucket/key?foo=bar", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let verified = v.verify_at(&parts, "rid", now()).expect("verifies");
        assert_eq!(&*verified.access_key_id, "AKID");
        assert_eq!(verified.payload, PayloadHashForSigning::UnsignedPayload);
        assert!(!verified.payload.requires_body_bytes());
    }

    #[test]
    fn test_signed_request_round_trip_put_signed_payload() {
        // SHA-256 of "hello".
        let hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let (auth, headers) = sign_request_for_test(
            "PUT",
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            hex,
            "AKID",
            "SECRET",
            "us-east-1",
        );
        let parts = parts_for("PUT", "/bucket/key", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let verified = v.verify_at(&parts, "rid", now()).expect("verifies");
        assert!(verified.payload.requires_body_bytes());
        v.verify_payload_hash(&verified, b"hello", "rid")
            .expect("body matches");
        let err = v
            .verify_payload_hash(&verified, b"goodbye", "rid")
            .expect_err("tampered body");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    #[test]
    fn test_tampered_signed_header_fails() {
        let (auth, mut headers) = sign_request_for_test(
            "GET",
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        // Change a signed header after signing.
        headers.insert("host", "evil.example".parse().unwrap());
        let parts = parts_for("GET", "/bucket/key", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("must fail");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    #[test]
    fn test_unknown_access_key_rejected() {
        let (auth, headers) = sign_request_for_test(
            "GET",
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "OTHER",
            "SECRET",
            "us-east-1",
        );
        let parts = parts_for("GET", "/bucket/key", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("unknown akid");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_missing_authorization_header() {
        let req = Request::builder()
            .method("GET")
            .uri("/b/k")
            .header("host", "example.com")
            .header("x-amz-date", "20260101T120000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("no auth");
        assert_eq!(err.code, "MissingAuthenticationToken");
    }

    #[test]
    fn test_dispatch_rejects_no_auth_at_all() {
        // Neither Authorization header nor X-Amz-Signature query →
        // MissingAuthenticationToken (the catch-all "where's the auth"
        // response for strict mode).
        let req = Request::builder()
            .method("GET")
            .uri("/b/k")
            .header("host", "example.com")
            .header("x-amz-date", "20260101T120000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("no auth");
        assert_eq!(err.code, "MissingAuthenticationToken");
    }

    #[test]
    fn test_dispatch_rejects_dual_auth_as_invalid_request() {
        // Authorization header AND X-Amz-Signature query both present →
        // InvalidRequest. Deleting the (true, true) arm in `verify_at`
        // would let one of the two paths win silently — both clients would
        // then be relying on whichever path the proxy happens to choose.
        let (auth, headers) = sign_request_for_test(
            "GET",
            "/b/k?X-Amz-Signature=deadbeef",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        let parts = parts_for("GET", "/b/k?X-Amz-Signature=deadbeef", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("dual auth");
        assert_eq!(err.code, "InvalidRequest");
    }

    // ── STS / x-amz-security-token (PR 4 of #63) ────────────────────────

    fn build_verifier_with(resolver: FixedResolver) -> SigV4Verifier {
        let resolver: Arc<dyn InboundCredentialResolver> = Arc::new(resolver);
        SigV4Verifier::new(resolver, Duration::from_secs(900))
    }

    #[test]
    fn test_header_auth_sts_token_round_trip_verifies() {
        // Reverts PR 1's `InvalidToken` rejection of `x-amz-security-token`
        // in SignedHeaders. The canonical request now includes the token
        // header, the resolver picks the token-bearing credential by the
        // `(akid, token)` tuple, and the signature lines up. Adding back
        // the parser-level reject in `parse_signed_headers` flips this to
        // `InvalidToken`.
        let (auth, headers) = sign_request_with_extra_header(
            "GET",
            "/b/k",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
            ("x-amz-security-token", "tok-abc"),
        );
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier_with(FixedResolver::with_token(
            "AKID",
            "tok-abc",
            "SECRET",
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        ));
        let verified = v.verify_at(&parts, "rid", now()).expect("verifies");
        assert_eq!(&*verified.access_key_id, "AKID");
        // VerifiedRequest deliberately does not carry the session token —
        // the token's lifetime ends at credential resolution.
        assert!(
            verified
                .signed_headers
                .iter()
                .any(|n| n.as_str() == "x-amz-security-token"),
        );
    }

    #[test]
    fn test_header_auth_token_present_but_unsigned_rejected() {
        // Sign the request without `x-amz-security-token` in SignedHeaders,
        // then bolt the header on after the fact. The verifier must
        // reject this as `AuthorizationHeaderMalformed` — accepting an
        // unsigned token would let the client influence resolver namespace
        // (a credential miss vs. hit) without binding the token to the
        // signature.
        let (auth, mut headers) = sign_request_for_test(
            "GET",
            "/b/k",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        headers.insert("x-amz-security-token", "tok-abc".parse().unwrap());
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("must reject");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_header_auth_signed_token_header_missing_rejected() {
        // SignedHeaders lists `x-amz-security-token` but the request does
        // not carry it. The canonical-headers reconstruction already
        // catches this (it can't synthesize a missing signed header) and
        // surfaces `AuthorizationHeaderMalformed`. Pinning the behavior
        // because the dispatch wraps the same error code we want clients
        // to see.
        let mut signed_names: Vec<&str> = vec![
            "host",
            "x-amz-content-sha256",
            "x-amz-date",
            "x-amz-security-token",
        ];
        signed_names.sort();
        let signed_headers_str = signed_names.join(";");
        let auth = format!(
            "AWS4-HMAC-SHA256 \
             Credential=AKID/20260101/us-east-1/s3/aws4_request, \
             SignedHeaders={signed_headers_str}, \
             Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );

        let mut headers = http::HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        headers.insert("x-amz-date", "20260101T120000Z".parse().unwrap());
        headers.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("must reject");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_header_auth_empty_token_value_rejected() {
        // Empty header value after SigV4 whitespace normalization is
        // malformed. AWS S3 docs treat absent vs empty as distinct, and
        // we shouldn't run resolver compare against an empty bytestring.
        let (auth, mut headers) = sign_request_with_extra_header(
            "GET",
            "/b/k",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
            ("x-amz-security-token", "tok-abc"),
        );
        // Overwrite to a value that normalizes to empty.
        headers.insert("x-amz-security-token", "   ".parse().unwrap());
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier_with(FixedResolver::with_token(
            "AKID",
            "tok-abc",
            "SECRET",
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        ));
        let err = v.verify_at(&parts, "rid", now()).expect_err("empty token");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_header_auth_wrong_token_returns_invalid_access_key_id() {
        // Tuple miss: the token bytes don't match any configured entry.
        // We surface `InvalidAccessKeyId` rather than `InvalidToken` —
        // confirming the access key exists in another token namespace
        // would leak more about the credential store than the client
        // needs to recover.
        let (auth, headers) = sign_request_with_extra_header(
            "GET",
            "/b/k",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
            ("x-amz-security-token", "wrong-token"),
        );
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier_with(FixedResolver::with_token(
            "AKID",
            "right-token",
            "SECRET",
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        ));
        let err = v.verify_at(&parts, "rid", now()).expect_err("wrong tok");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_header_auth_expired_token_returns_expired_token() {
        // Matched (akid, token) but the credential's `expires_at` is past
        // `now`. AWS S3 documents this as `ExpiredToken` (400). Replacing
        // the `CredentialResolveError::Expired` arm with the
        // `InvalidAccessKeyId` mapping would surface a misleading
        // 403/InvalidAccessKeyId that wouldn't tell the client to refresh
        // their STS credential.
        let (auth, headers) = sign_request_with_extra_header(
            "GET",
            "/b/k",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
            ("x-amz-security-token", "tok-abc"),
        );
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier_with(FixedResolver::with_token(
            "AKID",
            "tok-abc",
            "SECRET",
            Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
        ));
        let err = v.verify_at(&parts, "rid", now()).expect_err("expired");
        assert_eq!(err.code, "ExpiredToken");
    }

    #[test]
    fn test_header_auth_missing_token_when_only_token_credential_configured() {
        // Resolver only knows a token-bearing credential under "AKID";
        // the request signs without `x-amz-security-token`. From the
        // resolver's perspective the no-token tuple doesn't exist, so
        // verifier returns `InvalidAccessKeyId`.
        let (auth, headers) = sign_request_for_test(
            "GET",
            "/b/k",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier_with(FixedResolver::with_token(
            "AKID",
            "tok-abc",
            "SECRET",
            Some(Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap()),
        ));
        let err = v.verify_at(&parts, "rid", now()).expect_err("missing tok");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_header_auth_token_present_when_only_no_token_credential_configured() {
        // Inverse: resolver has only a long-lived credential, request
        // includes a (signed) token. Token namespace lookup misses →
        // `InvalidAccessKeyId`.
        let (auth, headers) = sign_request_with_extra_header(
            "GET",
            "/b/k",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
            ("x-amz-security-token", "tok-abc"),
        );
        let parts = parts_for("GET", "/b/k", headers, &auth);
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("only no-tok");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    #[test]
    fn test_aws_get_vanilla_reference_vector() {
        // AWS SigV4 reference vector "get-vanilla" from the published test
        // suite (shipped with aws-sigv4 1.4.3 under
        // aws-signing-test-suite/v4/get-vanilla/). We feed the documented
        // canonical request into our derive_signing_key + string-to-sign +
        // calculate_signature chain and check the bit-for-bit signature.
        let canonical = concat!(
            "GET\n",
            "/\n",
            "\n",
            "host:example.amazonaws.com\n",
            "x-amz-date:20150830T123600Z\n",
            "\n",
            "host;x-amz-date\n",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let scope = CredentialScope {
            date: chrono::NaiveDate::from_ymd_opt(2015, 8, 30).unwrap(),
            date_yyyymmdd: "20150830".to_string(),
            region: "us-east-1".to_string(),
            service: "service".to_string(),
        };
        let sts = build_string_to_sign(&scope, "20150830T123600Z", canonical);
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "service",
        );
        let sig = aws_sigv4::sign::v4::calculate_signature(key.as_bytes(), sts.as_bytes());
        assert_eq!(
            sig,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn test_aws_get_vanilla_query_order_vector() {
        // AWS reference vector "get-vanilla-query-order-key-case": the
        // request URI is `?Param2=value2&Param1=value1`, but the canonical
        // form sorts the query string into `Param1=value1&Param2=value2`.
        let canonical = concat!(
            "GET\n",
            "/\n",
            "Param1=value1&Param2=value2\n",
            "host:example.amazonaws.com\n",
            "x-amz-date:20150830T123600Z\n",
            "\n",
            "host;x-amz-date\n",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let scope = CredentialScope {
            date: chrono::NaiveDate::from_ymd_opt(2015, 8, 30).unwrap(),
            date_yyyymmdd: "20150830".to_string(),
            region: "us-east-1".to_string(),
            service: "service".to_string(),
        };
        let sts = build_string_to_sign(&scope, "20150830T123600Z", canonical);
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "service",
        );
        let sig = aws_sigv4::sign::v4::calculate_signature(key.as_bytes(), sts.as_bytes());
        assert_eq!(
            sig,
            "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    #[test]
    fn test_aws_iam_signature_calculation_vector() {
        // Reproduces the test from aws-sigv4 1.4.3 src/sign/v4.rs (the
        // SDK's own test_signature_calculation), targeting the iam service.
        // Confirms our derive_signing_key matches the SDK's even with
        // service != "service".
        let creq = "AWS4-HMAC-SHA256
20150830T123600Z
20150830/us-east-1/iam/aws4_request
f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
        let key = derive_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        let sig = aws_sigv4::sign::v4::calculate_signature(key.as_bytes(), creq.as_bytes());
        assert_eq!(
            sig,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }
}
