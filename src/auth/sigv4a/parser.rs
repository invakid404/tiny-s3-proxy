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
    let signature_der = parse_der_signature_hex(signature_raw).map_err(|_| {
        S3Error::authorization_header_malformed(
            &format!(
                "Signature must be lowercase hex of a DER ECDSA P-256/SHA-256 signature \
                 (even length, <= {MAX_SIGV4A_DER_SIGNATURE_HEX_LEN} chars)"
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

/// Confirm `x-amz-region-set` is present in the request and listed in
/// `SignedHeaders`. SigV4A requires the region set to be signed —
/// otherwise an attacker could re-target an inbound request at a
/// different region without breaking the signature.
pub(crate) fn ensure_sigv4a_region_set_signed(
    headers: &http::HeaderMap,
    signed_headers: &[HeaderName],
    request_id: &str,
) -> Result<(), S3Error> {
    if !headers.contains_key("x-amz-region-set") {
        return Err(S3Error::authorization_header_malformed(
            "SigV4A requests must include the x-amz-region-set header",
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

    /// A baseline header that the parser must accept. The 4-byte DER
    /// blob `3001020100` is the shortest valid ASN.1 signature shape;
    /// parsing only checks structural validity, not curve membership.
    fn valid_header() -> &'static str {
        "AWS4-ECDSA-P256-SHA256 Credential=AKID/20260101/s3/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-region-set, \
         Signature=304402201111111111111111111111111111111111111111111111111111111111111111\
         0220222222222222222222222222222222222222222222222222222222222222222222"
    }

    #[test]
    fn test_parse_valid_regionless_scope() {
        let auth = parse_sigv4a_authorization(valid_header(), rid()).expect("parses");
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
}
