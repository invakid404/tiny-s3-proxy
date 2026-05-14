//! Strict-mode parser for SigV4 presigned URL query auth (`X-Amz-*` query
//! parameters). The canonical-request rebuild and signature comparison live in
//! a follow-up step; this module only parses the auth fields the URL carries.
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

use crate::auth::sigv4::canonical::percent_decode_for_query;
use crate::auth::sigv4::parser::{
    CredentialScope, parse_amz_date, parse_credential, parse_signature_hex, parse_signed_headers,
};
use crate::s3::errors::S3Error;
use chrono::{DateTime, Utc};
use http::HeaderName;
use std::time::Duration;

/// AWS S3 caps presigned URL validity at 7 days (604 800 seconds).
pub const MAX_PRESIGNED_EXPIRES_SECS: u64 = 604_800;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const ECDSA_ALGORITHM_PREFIX: &str = "AWS4-ECDSA-";

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
        // UTF-8 can't match any required name and is therefore just a
        // non-auth query param.
        let key_str = match std::str::from_utf8(&decoded_key) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let slot = match key_str {
            "X-Amz-Algorithm" => &mut algorithm,
            "X-Amz-Credential" => &mut credential,
            "X-Amz-Date" => &mut amz_date,
            "X-Amz-Expires" => &mut expires_raw,
            "X-Amz-SignedHeaders" => &mut signed_headers_raw,
            "X-Amz-Signature" => &mut signature_raw,
            "X-Amz-Security-Token" => {
                security_token_seen = true;
                continue;
            }
            _ => continue,
        };

        let decoded_value = percent_decode_for_query(raw_v);
        let value_str = std::str::from_utf8(&decoded_value).map_err(|_| {
            S3Error::authorization_header_malformed(
                &format!("presigned auth field '{key_str}' is not valid UTF-8"),
                request_id,
            )
        })?;

        if slot.is_some() {
            return Err(S3Error::authorization_header_malformed(
                &format!("presigned auth has duplicate {key_str}"),
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
