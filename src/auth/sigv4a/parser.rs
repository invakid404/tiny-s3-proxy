//! Parser for the inbound SigV4A (`AWS4-ECDSA-P256-SHA256`)
//! `Authorization` header.
//!
//! Sibling of [`crate::auth::sigv4::parser`] but with the SigV4A-specific
//! shape: regionless credential scope, ECDSA DER-hex signature (variable
//! length, max 144 hex chars), and the requirement that the request signs
//! its `x-amz-region-set` header.
//!
//! Every malformed input here maps to
//! `S3Error::authorization_header_malformed` (HTTP 400, AWS code
//! `AuthorizationHeaderMalformed`), matching the HMAC parser's contract.

use crate::auth::sigv4::parser::parse_signed_headers;
use crate::auth::sigv4a::SIGV4A_ALGORITHM;
use crate::auth::sigv4a::SigV4aCredentialScope;
use crate::auth::sigv4a::crypto::{MAX_SIGV4A_DER_SIGNATURE_HEX_LEN, parse_der_signature_hex};
use crate::s3::errors::S3Error;
use chrono::NaiveDate;
use http::HeaderName;

#[derive(Debug, Clone)]
pub struct SigV4aAuthorization {
    pub access_key_id: String,
    pub scope: SigV4aCredentialScope,
    pub signed_headers: Vec<HeaderName>,
    pub signature_der: Vec<u8>,
    pub signature_hex: String,
}

/// Parse a SigV4A `Authorization` header value.
///
/// Grammar accepted (mirroring AWS docs):
///
/// ```text
/// AWS4-ECDSA-P256-SHA256 Credential=<akid>/<yyyymmdd>/s3/aws4_request,
///     SignedHeaders=<h1>;<h2>;...,
///     Signature=<lowercase hex of DER ECDSA, even length, <= 144 chars>
/// ```
///
/// Whitespace around `,` / `=` is tolerated to match real-world clients.
/// The HMAC parser already does the same; reusing the conventions keeps
/// the two parsers symmetric.
pub fn parse_sigv4a_authorization(
    header_value: &str,
    request_id: &str,
) -> Result<SigV4aAuthorization, S3Error> {
    let (algorithm, params) = header_value
        .split_once(char::is_whitespace)
        .ok_or_else(|| {
            S3Error::authorization_header_malformed(
                "Authorization header missing algorithm/params separator",
                request_id,
            )
        })?;
    let algorithm = algorithm.trim();
    let params = params.trim();

    if algorithm != SIGV4A_ALGORITHM {
        return Err(S3Error::authorization_header_malformed(
            "Authorization header algorithm is not AWS4-ECDSA-P256-SHA256",
            request_id,
        ));
    }

    let mut credential: Option<&str> = None;
    let mut signed_headers_raw: Option<&str> = None;
    let mut signature_raw: Option<&str> = None;

    for raw in params.split(',') {
        let part = raw.trim();
        if part.is_empty() {
            return Err(S3Error::authorization_header_malformed(
                "Authorization header contains an empty parameter",
                request_id,
            ));
        }
        let (k, v) = part.split_once('=').ok_or_else(|| {
            S3Error::authorization_header_malformed(
                "Authorization parameter missing '='",
                request_id,
            )
        })?;
        let k = k.trim();
        let v = v.trim();
        match k {
            "Credential" => {
                if credential.is_some() {
                    return Err(S3Error::authorization_header_malformed(
                        "Authorization header has duplicate Credential",
                        request_id,
                    ));
                }
                credential = Some(v);
            }
            "SignedHeaders" => {
                if signed_headers_raw.is_some() {
                    return Err(S3Error::authorization_header_malformed(
                        "Authorization header has duplicate SignedHeaders",
                        request_id,
                    ));
                }
                signed_headers_raw = Some(v);
            }
            "Signature" => {
                if signature_raw.is_some() {
                    return Err(S3Error::authorization_header_malformed(
                        "Authorization header has duplicate Signature",
                        request_id,
                    ));
                }
                signature_raw = Some(v);
            }
            other => {
                return Err(S3Error::authorization_header_malformed(
                    &format!("Authorization header has unknown parameter '{other}'"),
                    request_id,
                ));
            }
        }
    }

    let credential = credential.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "Authorization header missing Credential",
            request_id,
        )
    })?;
    let signed_headers_raw = signed_headers_raw.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "Authorization header missing SignedHeaders",
            request_id,
        )
    })?;
    let signature_raw = signature_raw.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "Authorization header missing Signature",
            request_id,
        )
    })?;

    let (access_key_id, scope) = parse_sigv4a_credential(credential, request_id)?;
    let signed_headers = parse_signed_headers(signed_headers_raw, request_id)?;
    // `parse_der_signature_hex` does both hex-shape validation
    // (lowercase, even length, <=144) AND DER-structure validation, so
    // raw `r||s` and arbitrary non-DER hex are rejected here as
    // `AuthorizationHeaderMalformed` rather than collapsing into
    // `SignatureDoesNotMatch` at verify time.
    let signature_der = parse_der_signature_hex(signature_raw).map_err(|_| {
        S3Error::authorization_header_malformed(
            &format!(
                "Signature must be lowercase hex of a DER-encoded ECDSA P-256/SHA-256 \
                 signature (even length, <= {MAX_SIGV4A_DER_SIGNATURE_HEX_LEN} chars)"
            ),
            request_id,
        )
    })?;

    Ok(SigV4aAuthorization {
        access_key_id,
        scope,
        signed_headers,
        signature_der,
        signature_hex: signature_raw.to_string(),
    })
}

/// Parse the SigV4A credential field: `<akid>/<yyyymmdd>/s3/aws4_request`.
///
/// Note the absence of a region component compared to the HMAC parser —
/// SigV4A credential scope is regionless.
pub(crate) fn parse_sigv4a_credential(
    value: &str,
    request_id: &str,
) -> Result<(String, SigV4aCredentialScope), S3Error> {
    let mut parts = value.split('/');
    let akid = parts.next().ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "Credential field missing access-key id",
            request_id,
        )
    })?;
    let date = parts.next().ok_or_else(|| {
        S3Error::authorization_header_malformed("Credential field missing date", request_id)
    })?;
    let service = parts.next().ok_or_else(|| {
        S3Error::authorization_header_malformed("Credential field missing service", request_id)
    })?;
    let suffix = parts.next().ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "Credential field missing aws4_request suffix",
            request_id,
        )
    })?;
    if parts.next().is_some() {
        // A five-component SigV4A credential is almost certainly the
        // HMAC shape `<akid>/<date>/<region>/<service>/aws4_request`
        // misclassified by the dispatch layer. We surface a specific
        // error so clients can distinguish "wrong algorithm for the
        // credential shape" from generic malformedness.
        return Err(S3Error::authorization_header_malformed(
            "SigV4A Credential field has extra components after aws4_request \
             (expected <akid>/<yyyymmdd>/s3/aws4_request — no region)",
            request_id,
        ));
    }

    if akid.is_empty() {
        return Err(S3Error::authorization_header_malformed(
            "Credential field has empty access-key id",
            request_id,
        ));
    }
    if service != "s3" {
        return Err(S3Error::authorization_header_malformed(
            "SigV4A Credential field service must be 's3'",
            request_id,
        ));
    }
    if suffix != "aws4_request" {
        return Err(S3Error::authorization_header_malformed(
            "Credential field must end with /aws4_request",
            request_id,
        ));
    }

    let parsed_date = NaiveDate::parse_from_str(date, "%Y%m%d").map_err(|_| {
        S3Error::authorization_header_malformed(
            "Credential field date is not a valid YYYYMMDD value",
            request_id,
        )
    })?;

    Ok((
        akid.to_string(),
        SigV4aCredentialScope {
            date: parsed_date,
            date_yyyymmdd: date.to_string(),
            service: service.to_string(),
        },
    ))
}

/// Confirm `x-amz-region-set` is present (with a non-empty ASCII
/// value) in the request and listed in `SignedHeaders`. SigV4A
/// requires the region set to be signed — otherwise an attacker could
/// re-target an inbound request at a different region without breaking
/// the signature.
///
/// Value-level checks reject:
/// - absent header
/// - non-ASCII / `to_str()` failure (the canonicalizer requires ASCII)
/// - empty value after `trim()` (covers both `""` and whitespace-only)
///
/// All failures surface as `AuthorizationHeaderMalformed` so the
/// client can correct the shape. Without the trim-and-reject, a
/// request that signs an empty `x-amz-region-set` would canonicalize
/// to `x-amz-region-set:\n` and the signed canonical request would
/// match against an empty region intent — exactly what SigV4A's
/// signed region set exists to prevent.
pub(crate) fn ensure_sigv4a_region_set_signed(
    headers: &http::HeaderMap,
    signed_headers: &[HeaderName],
    request_id: &str,
) -> Result<(), S3Error> {
    let value = headers.get("x-amz-region-set").ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "SigV4A requests must include the x-amz-region-set header",
            request_id,
        )
    })?;
    let raw = value.to_str().map_err(|_| {
        S3Error::authorization_header_malformed(
            "SigV4A x-amz-region-set header is not valid ASCII",
            request_id,
        )
    })?;
    if raw.trim().is_empty() {
        return Err(S3Error::authorization_header_malformed(
            "SigV4A x-amz-region-set header is empty",
            request_id,
        ));
    }
    if !signed_headers
        .iter()
        .any(|n| n.as_str() == "x-amz-region-set")
    {
        return Err(S3Error::authorization_header_malformed(
            "SigV4A SignedHeaders must include x-amz-region-set",
            request_id,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> &'static str {
        "req-test"
    }

    /// Lowercase hex of a real ECDSA P-256 DER signature produced via
    /// the same `aws_sigv4` + `p256` primitives the production verifier
    /// expects. We can't hard-code a placeholder anymore because PR 5
    /// (commit 9) DER-validates at parse time; `from_der` rejects
    /// bytes that decode as ASN.1 but aren't a valid ECDSA P-256
    /// signature (out-of-range scalars, non-canonical integer
    /// encodings, etc.). Curve membership / canonical-form rules are
    /// enforced by `ecdsa-core` 0.14's `from_der`.
    fn real_der_hex() -> String {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};
        let scalar = aws_sigv4::sign::v4a::generate_signing_key("AKID", "SECRET");
        let signing_key = SigningKey::from_bytes(scalar.as_ref()).unwrap();
        let sig: Signature = signing_key.sign(b"parser-test-string-to-sign");
        hex::encode(sig.to_der().as_ref())
    }

    /// A baseline header that the parser must accept. Uses a real DER
    /// signature for the load-bearing happy-path test; tests that fail
    /// before the DER check (credential parsing, lowercase check, etc.)
    /// continue to use literal placeholder hex.
    fn valid_header() -> String {
        format!(
            "AWS4-ECDSA-P256-SHA256 Credential=AKID/20260101/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
             Signature={}",
            real_der_hex(),
        )
    }

    #[test]
    fn test_parse_valid_regionless_scope() {
        let auth = parse_sigv4a_authorization(&valid_header(), rid()).expect("parses");
        assert_eq!(auth.access_key_id, "AKID");
        assert_eq!(auth.scope.service, "s3");
        assert_eq!(auth.scope.date_yyyymmdd, "20260101");
        assert!(auth.signed_headers.iter().any(|n| n.as_str() == "host"));
        assert!(
            auth.signed_headers
                .iter()
                .any(|n| n.as_str() == "x-amz-region-set")
        );
        // Signature was lowercase DER hex, even length, <=144.
        assert!(auth.signature_der.len() >= 8);
    }

    #[test]
    fn test_rejects_hmac_algorithm() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, \
                 SignedHeaders=host, \
                 Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_sigv4a_authorization(h, rid()).expect_err("HMAC algorithm");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    /// SigV4A credential is regionless — a five-component
    /// `<akid>/<date>/<region>/s3/aws4_request` shape is the HMAC form
    /// and must be rejected.
    #[test]
    fn test_rejects_regionful_credential() {
        let h = "AWS4-ECDSA-P256-SHA256 \
                 Credential=AKID/20260101/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-region-set, \
                 Signature=30450220111111111111111111111111111111111111111111111111111111111111\
                 111102210099999999999999999999999999999999999999999999999999999999999999";
        let err = parse_sigv4a_authorization(h, rid()).expect_err("regionful");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
        assert!(
            err.message.contains("no region"),
            "error should explain SigV4A is regionless, got: {}",
            err.message,
        );
    }

    #[test]
    fn test_rejects_non_s3_service() {
        let h = "AWS4-ECDSA-P256-SHA256 \
                 Credential=AKID/20260101/iam/aws4_request, \
                 SignedHeaders=host, \
                 Signature=304402201111111111111111111111111111111111111111111111111111111111111111\
                 0220222222222222222222222222222222222222222222222222222222222222222222";
        let err = parse_sigv4a_authorization(h, rid()).expect_err("non-s3");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_rejects_uppercase_signature_hex() {
        let h = "AWS4-ECDSA-P256-SHA256 \
                 Credential=AKID/20260101/s3/aws4_request, \
                 SignedHeaders=host, \
                 Signature=304402201111111111111111111111111111111111111111111111111111111111111111\
                 0220AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = parse_sigv4a_authorization(h, rid()).expect_err("uppercase");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_rejects_over_144_signature_hex() {
        let sig = "a".repeat(146);
        let h = format!(
            "AWS4-ECDSA-P256-SHA256 \
             Credential=AKID/20260101/s3/aws4_request, \
             SignedHeaders=host, Signature={sig}"
        );
        let err = parse_sigv4a_authorization(&h, rid()).expect_err("over-144");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    /// Raw 64-byte `r||s` (128 hex chars) is well-formed lowercase hex
    /// of the right length but is NOT DER. The parser must reject it
    /// as `AuthorizationHeaderMalformed` at the DER-validation step
    /// inside `parse_der_signature_hex`. Without this layering, raw
    /// `r||s` slips through and only fails inside
    /// `verify_sigv4a_der_signature`, surfacing as
    /// `SignatureDoesNotMatch` — wrong wire-format error.
    ///
    /// Bug-revert reasoning: dropping the `Signature::from_der` call
    /// inside `parse_der_signature_hex` flips this assertion from
    /// `AuthorizationHeaderMalformed` to `SignatureDoesNotMatch`.
    #[test]
    fn test_rejects_raw_r_s_signature_at_parse_layer() {
        let raw_rs = "0".repeat(128);
        let h = format!(
            "AWS4-ECDSA-P256-SHA256 \
             Credential=AKID/20260101/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
             Signature={raw_rs}"
        );
        let err = parse_sigv4a_authorization(&h, rid()).expect_err("raw r||s");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    /// Arbitrary non-DER lowercase hex (right hex shape, wrong ASN.1
    /// structure) must reject as `AuthorizationHeaderMalformed`, not
    /// `SignatureDoesNotMatch`. Same layering check as
    /// `test_rejects_raw_r_s_signature_at_parse_layer`, but with input
    /// that doesn't even start with a valid `30 ..` DER sequence
    /// header.
    #[test]
    fn test_rejects_arbitrary_non_der_hex_at_parse_layer() {
        let h = "AWS4-ECDSA-P256-SHA256 \
                 Credential=AKID/20260101/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
                 Signature=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let err = parse_sigv4a_authorization(h, rid()).expect_err("non-DER hex");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_ensure_region_set_signed_happy_path() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-region-set", "us-east-1".parse().unwrap());
        let signed = vec![
            HeaderName::from_static("host"),
            HeaderName::from_static("x-amz-region-set"),
        ];
        ensure_sigv4a_region_set_signed(&headers, &signed, rid()).expect("ok");
    }

    #[test]
    fn test_ensure_region_set_signed_rejects_missing_header() {
        let headers = http::HeaderMap::new();
        let signed = vec![
            HeaderName::from_static("host"),
            HeaderName::from_static("x-amz-region-set"),
        ];
        let err =
            ensure_sigv4a_region_set_signed(&headers, &signed, rid()).expect_err("missing header");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_ensure_region_set_signed_rejects_unsigned() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-region-set", "us-east-1".parse().unwrap());
        let signed = vec![HeaderName::from_static("host")];
        let err = ensure_sigv4a_region_set_signed(&headers, &signed, rid())
            .expect_err("unsigned region set");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    /// SigV4A requires a non-empty signed region set. An empty header
    /// value (`""`) would canonicalize to `x-amz-region-set:\n` and the
    /// request would carry an "intentionally empty" region intent —
    /// defeating the point of signing the region set. The helper now
    /// rejects this at the parse boundary so the verifier doesn't
    /// canonicalize against an empty signed field.
    ///
    /// Bug-revert reasoning: dropping the `raw.trim().is_empty()`
    /// check in `ensure_sigv4a_region_set_signed` flips this assertion
    /// from `AuthorizationHeaderMalformed` to `Ok(())`.
    #[test]
    fn test_sigv4a_region_set_empty_value_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-region-set", "".parse().unwrap());
        let signed = vec![
            HeaderName::from_static("host"),
            HeaderName::from_static("x-amz-region-set"),
        ];
        let err = ensure_sigv4a_region_set_signed(&headers, &signed, rid())
            .expect_err("empty region set");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
        assert!(
            err.message.contains("empty"),
            "error should mention emptiness, got: {}",
            err.message,
        );
    }

    /// Whitespace-only region-set value normalizes to empty after
    /// `trim()` and is rejected on the same path as the literal
    /// `""` case. Pinned separately so a future refactor that
    /// switches to `is_empty()` (no trim) regresses with a clear
    /// failure rather than silently accepting `"   "`.
    #[test]
    fn test_sigv4a_region_set_whitespace_only_rejected() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-region-set", "   ".parse().unwrap());
        let signed = vec![
            HeaderName::from_static("host"),
            HeaderName::from_static("x-amz-region-set"),
        ];
        let err = ensure_sigv4a_region_set_signed(&headers, &signed, rid())
            .expect_err("whitespace region set");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    /// Non-ASCII bytes in the region-set value can't survive
    /// `to_str()` and the canonicalizer requires ASCII anyway. Reject
    /// up front rather than letting an invalid byte sequence flow
    /// into the canonical request builder.
    #[test]
    fn test_sigv4a_region_set_invalid_utf8_rejected() {
        let mut headers = http::HeaderMap::new();
        // `0xC3 0x28` is an invalid UTF-8 sequence (continuation byte
        // missing the high bit). `HeaderValue::from_bytes` accepts any
        // visible bytes; `HeaderValue::to_str` then refuses it.
        headers.insert(
            "x-amz-region-set",
            http::HeaderValue::from_bytes(&[0xc3, 0x28]).unwrap(),
        );
        let signed = vec![
            HeaderName::from_static("host"),
            HeaderName::from_static("x-amz-region-set"),
        ];
        let err = ensure_sigv4a_region_set_signed(&headers, &signed, rid())
            .expect_err("non-ASCII region set");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }
}
