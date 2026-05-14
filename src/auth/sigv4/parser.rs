//! Parser for the inbound SigV4 `Authorization` header, credential scope,
//! and request date. Pure functions; no I/O.
//!
//! Every malformed input here maps to `S3Error::authorization_header_malformed`
//! (HTTP 400, AWS code `AuthorizationHeaderMalformed`) unless explicitly noted
//! otherwise: ECDSA → `UnsupportedSignature`. STS-issued temporary
//! credentials (`x-amz-security-token` in `SignedHeaders`) are now accepted
//! and verified by the resolver — see the header-auth path in
//! [`super::SigV4Verifier`].
//!
//! The grammar we accept follows the AWS SigV4 documentation:
//!
//! ```text
//! AWS4-HMAC-SHA256 Credential=<akid>/<yyyymmdd>/<region>/<service>/aws4_request,
//!     SignedHeaders=<h1>;<h2>;...,
//!     Signature=<64 lowercase hex chars>
//! ```
//!
//! - The algorithm token MUST be exactly `AWS4-HMAC-SHA256` (we reject the
//!   ECDSA variant `AWS4-ECDSA-P256-SHA256` with `UnsupportedSignature`).
//! - Service MUST be `s3` in this PR.
//! - Signed headers must be lowercase, sorted, deduplicated, and include
//!   `host`. They must include `x-amz-date` when the request carries one.
//! - We accept optional spaces around `,` and `=` (clients in the wild emit
//!   them; the AWS reference parser tolerates this).

use crate::s3::errors::S3Error;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use http::HeaderMap;
use http::HeaderName;
use std::str::FromStr;
use std::time::SystemTime;

/// Maximum allowed clock skew is provided by the caller (config); the date
/// parser only enforces it when given a value to compare against `now`.
#[derive(Debug, Clone)]
pub struct CredentialScope {
    pub date: NaiveDate,
    pub date_yyyymmdd: String,
    pub region: String,
    pub service: String,
}

#[derive(Debug, Clone)]
pub struct SigV4Authorization {
    pub access_key_id: String,
    pub scope: CredentialScope,
    pub signed_headers: Vec<HeaderName>,
    pub signature: [u8; 32],
    pub signature_hex: String,
}

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const ECDSA_ALGORITHM: &str = "AWS4-ECDSA-P256-SHA256";

pub fn parse_authorization(
    header_value: &str,
    request_id: &str,
) -> Result<SigV4Authorization, S3Error> {
    // Split on the first whitespace to separate algorithm from params.
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

    if algorithm == ECDSA_ALGORITHM
        || algorithm.eq_ignore_ascii_case(ECDSA_ALGORITHM)
        || algorithm.starts_with("AWS4-ECDSA-")
    {
        return Err(S3Error::unsupported_signature(
            "SigV4A (AWS4-ECDSA-P256-SHA256) is not supported in strict mode; \
             tracked in PR 5 of issue #63",
            request_id,
        ));
    }
    if algorithm != ALGORITHM {
        return Err(S3Error::authorization_header_malformed(
            "unsupported signing algorithm; expected AWS4-HMAC-SHA256",
            request_id,
        ));
    }

    // Params is "Credential=...,SignedHeaders=...,Signature=..." (comma-separated,
    // optional spaces around the commas).
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

    let (access_key_id, scope) = parse_credential(credential, request_id)?;
    let signed_headers = parse_signed_headers(signed_headers_raw, request_id)?;
    let (signature, signature_hex) = parse_signature_hex(signature_raw, request_id)?;

    Ok(SigV4Authorization {
        access_key_id,
        scope,
        signed_headers,
        signature,
        signature_hex,
    })
}

pub(crate) fn parse_credential(
    value: &str,
    request_id: &str,
) -> Result<(String, CredentialScope), S3Error> {
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
    let region = parts.next().ok_or_else(|| {
        S3Error::authorization_header_malformed("Credential field missing region", request_id)
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
        return Err(S3Error::authorization_header_malformed(
            "Credential field has extra components after aws4_request",
            request_id,
        ));
    }

    if akid.is_empty() {
        return Err(S3Error::authorization_header_malformed(
            "Credential field has empty access-key id",
            request_id,
        ));
    }
    if region.is_empty() {
        return Err(S3Error::authorization_header_malformed(
            "Credential field has empty region",
            request_id,
        ));
    }
    if service != "s3" {
        return Err(S3Error::authorization_header_malformed(
            "Credential field service must be 's3'",
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
        CredentialScope {
            date: parsed_date,
            date_yyyymmdd: date.to_string(),
            region: region.to_string(),
            service: service.to_string(),
        },
    ))
}

pub(crate) fn parse_signed_headers(
    value: &str,
    request_id: &str,
) -> Result<Vec<HeaderName>, S3Error> {
    if value.is_empty() {
        return Err(S3Error::authorization_header_malformed(
            "SignedHeaders is empty",
            request_id,
        ));
    }
    let raw: Vec<&str> = value.split(';').collect();
    let mut names: Vec<HeaderName> = Vec::with_capacity(raw.len());

    for part in &raw {
        if part.is_empty() {
            return Err(S3Error::authorization_header_malformed(
                "SignedHeaders contains an empty element",
                request_id,
            ));
        }
        // Reject any uppercase character — AWS requires the canonical
        // SignedHeaders list to be lowercase.
        if part.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(S3Error::authorization_header_malformed(
                "SignedHeaders entries must be lowercase",
                request_id,
            ));
        }
        let name = HeaderName::from_str(part).map_err(|_| {
            S3Error::authorization_header_malformed(
                "SignedHeaders contains an invalid header name",
                request_id,
            )
        })?;
        names.push(name);
    }

    // Detect duplicates / unsorted ordering. AWS canonical SignedHeaders MUST
    // be sorted ascending and unique; otherwise the canonical request the
    // client signed is ambiguous.
    for w in names.windows(2) {
        match w[0].as_str().cmp(w[1].as_str()) {
            std::cmp::Ordering::Greater => {
                return Err(S3Error::authorization_header_malformed(
                    "SignedHeaders must be sorted in ascending order",
                    request_id,
                ));
            }
            std::cmp::Ordering::Equal => {
                return Err(S3Error::authorization_header_malformed(
                    "SignedHeaders contains a duplicate header name",
                    request_id,
                ));
            }
            std::cmp::Ordering::Less => {}
        }
    }

    // `host` is required by AWS.
    if !names.iter().any(|n| n.as_str() == "host") {
        return Err(S3Error::authorization_header_malformed(
            "SignedHeaders must include 'host'",
            request_id,
        ));
    }

    Ok(names)
}

pub(crate) fn parse_signature_hex(
    value: &str,
    request_id: &str,
) -> Result<([u8; 32], String), S3Error> {
    if value.len() != 64 {
        return Err(S3Error::authorization_header_malformed(
            "Signature must be 64 hex characters",
            request_id,
        ));
    }
    // Lowercase only — the canonical form is lowercase. A mixed-case
    // signature would never match because we compare bytes, but we reject it
    // up front for a clearer error message.
    if value.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(S3Error::authorization_header_malformed(
            "Signature hex must be lowercase",
            request_id,
        ));
    }

    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let hi = hex_nibble(value.as_bytes()[2 * i]).ok_or_else(|| {
            S3Error::authorization_header_malformed(
                "Signature contains non-hex characters",
                request_id,
            )
        })?;
        let lo = hex_nibble(value.as_bytes()[2 * i + 1]).ok_or_else(|| {
            S3Error::authorization_header_malformed(
                "Signature contains non-hex characters",
                request_id,
            )
        })?;
        *byte = (hi << 4) | lo;
    }
    Ok((bytes, value.to_string()))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// ── Date / skew validation ─────────────────────────────────────────────

/// Resolve the canonical `x-amz-date` string to use in the string-to-sign.
/// Prefers the `x-amz-date` header, falls back to RFC 2822 `Date` reformatted
/// to ISO 8601 basic. The returned tuple also includes the parsed time for
/// downstream signing-key derivation and skew enforcement.
pub fn resolve_request_time(
    headers: &HeaderMap,
    request_id: &str,
) -> Result<(String, DateTime<Utc>), S3Error> {
    if let Some(v) = headers.get("x-amz-date") {
        let s = v.to_str().map_err(|_| {
            S3Error::authorization_header_malformed(
                "x-amz-date header value is not valid ASCII",
                request_id,
            )
        })?;
        let dt = parse_amz_date(s).ok_or_else(|| {
            S3Error::authorization_header_malformed(
                "x-amz-date header is not in YYYYMMDDTHHMMSSZ format",
                request_id,
            )
        })?;
        return Ok((s.to_string(), dt));
    }
    if let Some(v) = headers.get("date") {
        let s = v.to_str().map_err(|_| {
            S3Error::authorization_header_malformed(
                "Date header value is not valid ASCII",
                request_id,
            )
        })?;
        let st: SystemTime = httpdate::parse_http_date(s).map_err(|_| {
            S3Error::authorization_header_malformed(
                "Date header is not a valid HTTP date",
                request_id,
            )
        })?;
        let dt: DateTime<Utc> = DateTime::<Utc>::from(st);
        // The string-to-sign needs the ISO 8601 basic format regardless of
        // which header it came from.
        return Ok((dt.format("%Y%m%dT%H%M%SZ").to_string(), dt));
    }
    Err(S3Error::authorization_header_malformed(
        "request is missing x-amz-date and Date headers",
        request_id,
    ))
}

/// Parse the AWS basic ISO 8601 format (`YYYYMMDDTHHMMSSZ`) used by SigV4.
pub fn parse_amz_date(s: &str) -> Option<DateTime<Utc>> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|nd| DateTime::<Utc>::from_naive_utc_and_offset(nd, Utc))
}

/// Enforce request freshness. Returns `RequestTimeTooSkewed` if the request
/// timestamp is outside `max_skew` of `now` in either direction.
pub fn enforce_skew(
    request_time: DateTime<Utc>,
    now: DateTime<Utc>,
    max_skew: Duration,
    request_id: &str,
) -> Result<(), S3Error> {
    let delta = now.signed_duration_since(request_time);
    let abs = if delta < Duration::zero() {
        -delta
    } else {
        delta
    };
    if abs > max_skew {
        return Err(S3Error::request_time_too_skewed(
            "request date is outside the configured clock-skew window",
            request_id,
        ));
    }
    Ok(())
}

/// Cross-check the date in the credential scope against the request time.
/// AWS requires them to refer to the same calendar day (UTC). A mismatch
/// makes the canonical request unverifiable, so we surface it as
/// `AuthorizationHeaderMalformed`.
pub fn ensure_scope_date_matches(
    scope: &CredentialScope,
    request_time: DateTime<Utc>,
    request_id: &str,
) -> Result<(), S3Error> {
    let scope_date = scope.date;
    let req_date = request_time.date_naive();
    if scope_date != req_date {
        return Err(S3Error::authorization_header_malformed(
            "Credential scope date does not match the request timestamp",
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

    fn valid_header() -> String {
        "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, \
         SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
         Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_string()
    }

    #[test]
    fn test_parse_valid() {
        let auth = parse_authorization(&valid_header(), rid()).expect("parses");
        assert_eq!(auth.access_key_id, "AKID");
        assert_eq!(auth.scope.region, "us-east-1");
        assert_eq!(auth.scope.service, "s3");
        assert_eq!(auth.scope.date_yyyymmdd, "20260101");
        assert_eq!(auth.signed_headers.len(), 3);
        assert_eq!(auth.signed_headers[0].as_str(), "host");
        assert_eq!(auth.signature_hex.len(), 64);
    }

    #[test]
    fn test_missing_credential_field() {
        let h = "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=00000000000000000000000000000000000000000000000000000000aabbccdd";
        let err = parse_authorization(h, rid()).expect_err("missing Credential");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_missing_signed_headers_field() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, Signature=00000000000000000000000000000000000000000000000000000000aabbccdd";
        let err = parse_authorization(h, rid()).expect_err("missing SignedHeaders");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_missing_signature_field() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host";
        let err = parse_authorization(h, rid()).expect_err("missing Signature");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_duplicate_field_rejected() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("duplicate Credential");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_whitespace_tolerance() {
        // The wire format is widely seen with both no-space and with-space
        // commas. We tolerate either.
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request,SignedHeaders=host,Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let auth = parse_authorization(h, rid()).expect("no-space parses");
        assert_eq!(auth.scope.region, "us-east-1");

        let h2 = "AWS4-HMAC-SHA256    Credential = AKID/20260101/us-east-1/s3/aws4_request ,  SignedHeaders = host , Signature = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let auth2 = parse_authorization(h2, rid()).expect("padded parses");
        assert_eq!(auth2.scope.region, "us-east-1");
    }

    #[test]
    fn test_unknown_algorithm_rejected() {
        let h = "AWS4-HMAC-SHA1 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("bad algorithm");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_ecdsa_rejected_as_unsupported_signature() {
        let h = "AWS4-ECDSA-P256-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("ECDSA");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    #[test]
    fn test_signature_must_be_lowercase_hex() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("uppercase hex");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_signed_headers_must_be_lowercase() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=Host;x-amz-date, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("uppercase signed header");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_signed_headers_duplicate_rejected() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=host;host, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("duplicate signed header");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_signed_headers_must_be_sorted() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=x-amz-date;host, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("unsorted signed headers");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_signed_headers_must_include_host() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, SignedHeaders=x-amz-date, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("missing host");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_sts_session_token_signed_header_accepted() {
        // Reverts PR 1's parser-level `InvalidToken` rejection. A request
        // with `x-amz-security-token` in `SignedHeaders` is now a
        // structurally valid SigV4 header; expiry and credential lookup
        // happen later in the verifier. Re-adding the `*part ==
        // "x-amz-security-token"` reject in `parse_signed_headers` flips
        // this test back to an `InvalidToken` error.
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_request, \
                 SignedHeaders=host;x-amz-security-token, \
                 Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let auth = parse_authorization(h, rid()).expect("STS token now parses");
        assert!(
            auth.signed_headers
                .iter()
                .any(|n| n.as_str() == "x-amz-security-token")
        );
    }

    #[test]
    fn test_credential_service_must_be_s3() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3-something/aws4_request, SignedHeaders=host, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("non-s3 service");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_credential_must_end_with_aws4_request() {
        let h = "AWS4-HMAC-SHA256 Credential=AKID/20260101/us-east-1/s3/aws4_garbage, SignedHeaders=host, Signature=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let err = parse_authorization(h, rid()).expect_err("bad scope suffix");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    // ── Date / skew tests ─────────────────────────────────────────

    fn dt(s: &str) -> DateTime<Utc> {
        parse_amz_date(s).expect("amz date parses")
    }

    #[test]
    fn test_amz_date_basic_iso8601() {
        let parsed = dt("20260114T123000Z");
        assert_eq!(
            parsed.format("%Y%m%dT%H%M%SZ").to_string(),
            "20260114T123000Z"
        );
    }

    #[test]
    fn test_amz_date_rejects_wrong_format() {
        assert!(parse_amz_date("2026-01-14T12:30:00Z").is_none());
        assert!(parse_amz_date("20260114T123000").is_none());
        assert!(parse_amz_date("20260114T123000+0000").is_none());
    }

    #[test]
    fn test_resolve_request_time_prefers_x_amz_date() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-date", "20260101T120000Z".parse().unwrap());
        // Even if Date header is present, x-amz-date wins.
        headers.insert("date", "Thu, 01 Jan 2026 12:00:00 GMT".parse().unwrap());
        let (s, _) = resolve_request_time(&headers, rid()).expect("resolves");
        assert_eq!(s, "20260101T120000Z");
    }

    #[test]
    fn test_resolve_request_time_falls_back_to_date_header() {
        let mut headers = HeaderMap::new();
        headers.insert("date", "Thu, 01 Jan 2026 12:00:00 GMT".parse().unwrap());
        let (s, t) = resolve_request_time(&headers, rid()).expect("resolves via Date");
        assert_eq!(s, "20260101T120000Z");
        assert_eq!(t.format("%Y%m%d").to_string(), "20260101");
    }

    #[test]
    fn test_resolve_request_time_missing_both_errors() {
        let headers = HeaderMap::new();
        let err = resolve_request_time(&headers, rid()).expect_err("no date headers");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_enforce_skew_in_window() {
        let now = dt("20260101T120000Z");
        let req = dt("20260101T120500Z"); // 5 minutes ahead
        enforce_skew(req, now, Duration::seconds(900), rid()).expect("within 15min");
    }

    #[test]
    fn test_enforce_skew_too_old_rejected() {
        let now = dt("20260101T120000Z");
        let req = dt("20260101T100000Z"); // 2 hours ago
        let err =
            enforce_skew(req, now, Duration::seconds(900), rid()).expect_err("stale should reject");
        assert_eq!(err.code, "RequestTimeTooSkewed");
    }

    #[test]
    fn test_enforce_skew_too_far_future_rejected() {
        let now = dt("20260101T120000Z");
        let req = dt("20260101T140000Z");
        let err = enforce_skew(req, now, Duration::seconds(900), rid())
            .expect_err("future should reject");
        assert_eq!(err.code, "RequestTimeTooSkewed");
    }

    #[test]
    fn test_ensure_scope_date_matches() {
        let req = dt("20260101T120000Z");
        let mut scope = CredentialScope {
            date: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            date_yyyymmdd: "20260101".to_string(),
            region: "us-east-1".to_string(),
            service: "s3".to_string(),
        };
        ensure_scope_date_matches(&scope, req, rid()).expect("matches");
        scope.date = NaiveDate::from_ymd_opt(2026, 1, 2).unwrap();
        let err = ensure_scope_date_matches(&scope, req, rid()).expect_err("mismatched date");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }
}
