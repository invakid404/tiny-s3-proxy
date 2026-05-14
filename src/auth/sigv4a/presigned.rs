//! Strict-mode SigV4A (`AWS4-ECDSA-P256-SHA256`) presigned URL parser
//! and verifier.
//!
//! Sibling of [`crate::auth::sigv4::presigned`], with the same overall
//! shape: parse query-auth fields, enforce the validity window, build
//! the canonical request with `X-Amz-Signature` excluded, verify the
//! signature, return a [`VerifiedRequest`] indistinguishable to
//! downstream handler code from the HMAC presigned output.
//!
//! Two SigV4A-specific differences from the HMAC parser:
//!
//! - Credential scope is regionless
//!   (`<akid>/<yyyymmdd>/s3/aws4_request`); five-component HMAC-shaped
//!   credentials are rejected with a specific "no region" message.
//! - `X-Amz-Region-Set` is required as a canonical query parameter and
//!   participates in the signed canonical request.

use crate::auth::credentials::InboundCredentialResolver;
use crate::auth::sigv4::canonical::{
    CanonicalQueryMode, build_canonical_request_from_signed_headers, percent_decode_for_query,
};
use crate::auth::sigv4::parser::{parse_amz_date, parse_signed_headers};
use crate::auth::sigv4::payload::PayloadHashForSigning;
use crate::auth::sigv4::presigned::{
    MAX_PRESIGNED_EXPIRES_SECS, check_presigned_payload_marker, enforce_presigned_window,
    reject_presigned_aws_chunked,
};
use crate::auth::sigv4::resolve_credential_for_sigv4;
use crate::auth::sigv4a::SIGV4A_ALGORITHM;
use crate::auth::sigv4a::SigV4aCredentialScope;
use crate::auth::sigv4a::build_sigv4a_string_to_sign;
use crate::auth::sigv4a::crypto::{
    MAX_SIGV4A_DER_SIGNATURE_HEX_LEN, derive_sigv4a_verifying_key, parse_der_signature_hex,
    verify_sigv4a_der_signature,
};
use crate::auth::sigv4a::parser::parse_sigv4a_credential;
use crate::auth::verified::{VerifiedCredentialScope, VerifiedRequest, VerifiedSigningContext};
use crate::s3::errors::S3Error;
use chrono::{DateTime, Utc};
use http::HeaderName;
use std::time::Duration;

const PRESIGNED_AUTH_NAMES: &[&str] = &[
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
    "X-Amz-Security-Token",
    "X-Amz-Region-Set",
    "X-Amz-Content-Sha256",
];

fn classify_presigned_auth_key(decoded_key: &str) -> Option<&'static str> {
    PRESIGNED_AUTH_NAMES
        .iter()
        .find(|name| name.eq_ignore_ascii_case(decoded_key))
        .copied()
}

#[derive(Debug, Clone)]
pub struct SigV4aPresignedAuthorization {
    pub access_key_id: String,
    pub scope: SigV4aCredentialScope,
    pub signed_headers: Vec<HeaderName>,
    pub signature_der: Vec<u8>,
    pub signature_hex: String,
    pub amz_date: String,
    pub request_time: DateTime<Utc>,
    pub expires: Duration,
    pub session_token: Option<String>,
    pub region_set: String,
}

pub fn parse_sigv4a_presigned_authorization(
    raw_query: &str,
    request_id: &str,
) -> Result<SigV4aPresignedAuthorization, S3Error> {
    let mut algorithm: Option<String> = None;
    let mut credential: Option<String> = None;
    let mut amz_date: Option<String> = None;
    let mut expires_raw: Option<String> = None;
    let mut signed_headers_raw: Option<String> = None;
    let mut signature_raw: Option<String> = None;
    let mut security_token: Option<String> = None;
    let mut region_set: Option<String> = None;

    for chunk in raw_query.split('&') {
        if chunk.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match chunk.split_once('=') {
            Some((k, v)) => (k, v),
            None => (chunk, ""),
        };

        let decoded_key = percent_decode_for_query(raw_k);
        let key_str = match std::str::from_utf8(&decoded_key) {
            Ok(s) => s,
            Err(_) => continue,
        };

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

        if canonical_name == "X-Amz-Content-Sha256" {
            // Marker is read separately by `check_presigned_payload_marker`.
            continue;
        }

        let decoded_value = percent_decode_for_query(raw_v);
        let value_str = std::str::from_utf8(&decoded_value).map_err(|_| {
            S3Error::authorization_header_malformed(
                &format!("presigned auth field {canonical_name} is not valid UTF-8"),
                request_id,
            )
        })?;
        if value_str.is_empty() && canonical_name != "X-Amz-Region-Set" {
            // X-Amz-Region-Set is independently required and rejected
            // below; for the other auth fields, an empty decoded value
            // is malformed up front.
            return Err(S3Error::authorization_header_malformed(
                &format!("presigned auth field {canonical_name} is empty"),
                request_id,
            ));
        }
        if value_str.bytes().any(|b| b >= 0x80) {
            return Err(S3Error::authorization_header_malformed(
                &format!("presigned auth field {canonical_name} contains non-ASCII bytes"),
                request_id,
            ));
        }

        let slot = match canonical_name {
            "X-Amz-Algorithm" => &mut algorithm,
            "X-Amz-Credential" => &mut credential,
            "X-Amz-Date" => &mut amz_date,
            "X-Amz-Expires" => &mut expires_raw,
            "X-Amz-SignedHeaders" => &mut signed_headers_raw,
            "X-Amz-Signature" => &mut signature_raw,
            "X-Amz-Security-Token" => &mut security_token,
            "X-Amz-Region-Set" => &mut region_set,
            other => unreachable!("classify_presigned_auth_key emitted {other}"),
        };
        if slot.is_some() {
            return Err(S3Error::authorization_header_malformed(
                &format!("presigned auth has duplicate {canonical_name}"),
                request_id,
            ));
        }
        *slot = Some(value_str.to_string());
    }

    let algorithm = algorithm.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "presigned auth missing X-Amz-Algorithm",
            request_id,
        )
    })?;
    if algorithm != SIGV4A_ALGORITHM {
        return Err(S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Algorithm must be AWS4-ECDSA-P256-SHA256",
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
    let region_set_v = region_set.ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "SigV4A presigned auth missing X-Amz-Region-Set",
            request_id,
        )
    })?;
    if region_set_v.is_empty() {
        return Err(S3Error::authorization_header_malformed(
            "SigV4A presigned auth X-Amz-Region-Set is empty",
            request_id,
        ));
    }

    let (access_key_id, scope) = parse_sigv4a_credential(&credential_v, request_id)?;
    let signed_headers = parse_signed_headers(&signed_headers_v, request_id)?;
    // `parse_der_signature_hex` does both hex-shape and DER-structure
    // validation, so raw `r||s` and arbitrary non-DER hex are rejected
    // here as `AuthorizationHeaderMalformed` rather than collapsing
    // into `SignatureDoesNotMatch` at verify time.
    let signature_der = parse_der_signature_hex(&signature_v).map_err(|_| {
        S3Error::authorization_header_malformed(
            &format!(
                "X-Amz-Signature must be lowercase hex of a DER-encoded ECDSA P-256/SHA-256 \
                 signature (even length, <= {MAX_SIGV4A_DER_SIGNATURE_HEX_LEN} chars)"
            ),
            request_id,
        )
    })?;

    let request_time = parse_amz_date(&amz_date_v).ok_or_else(|| {
        S3Error::authorization_header_malformed(
            "presigned auth X-Amz-Date is not in YYYYMMDDTHHMMSSZ format",
            request_id,
        )
    })?;

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

    Ok(SigV4aPresignedAuthorization {
        access_key_id,
        scope,
        signed_headers,
        signature_der,
        signature_hex: signature_v,
        amz_date: amz_date_v,
        request_time,
        expires: Duration::from_secs(expires_secs),
        session_token: security_token,
        region_set: region_set_v,
    })
}

pub fn verify_sigv4a_presigned_request(
    parts: &http::request::Parts,
    resolver: &dyn InboundCredentialResolver,
    request_id: &str,
    now: DateTime<Utc>,
) -> Result<VerifiedRequest, S3Error> {
    // Streaming + presigned is still fail-closed in this PR — chunk
    // signatures from a presigned URL aren't a documented S3 shape.
    reject_presigned_aws_chunked(parts, request_id)?;

    let raw_query = parts.uri.query().unwrap_or("");
    let pres = parse_sigv4a_presigned_authorization(raw_query, request_id)?;

    if pres.scope.date != pres.request_time.date_naive() {
        return Err(S3Error::authorization_header_malformed(
            "Credential scope date does not match the request timestamp",
            request_id,
        ));
    }

    enforce_presigned_window(pres.request_time, pres.expires, now, request_id)?;
    check_presigned_payload_marker(parts, request_id)?;

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

    let verifying_key =
        derive_sigv4a_verifying_key(&pres.access_key_id, credential.secret_access_key.expose())
            .map_err(|e| {
                tracing::error!(error = %e, "SigV4A KDF failed for resolved credential");
                S3Error::internal_error("internal error deriving SigV4A verifying key", request_id)
            })?;

    let string_to_sign =
        build_sigv4a_string_to_sign(&pres.scope, &pres.amz_date, &canonical.canonical_request);

    verify_sigv4a_der_signature(
        &verifying_key,
        string_to_sign.as_bytes(),
        &pres.signature_der,
    )
    .map_err(|_| {
        S3Error::signature_does_not_match(
            "computed SigV4A signature does not match the supplied X-Amz-Signature",
            request_id,
        )
    })?;

    Ok(VerifiedRequest {
        access_key_id: credential.access_key_id.clone(),
        credential_scope: VerifiedCredentialScope::SigV4a(pres.scope),
        signed_headers: pres.signed_headers,
        request_signature_hex: pres.signature_hex,
        signing_context: VerifiedSigningContext::EcdsaP256(verifying_key),
        amz_date: pres.amz_date,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::credentials::{
        CredentialResolveError, InboundCredential, InboundCredentialResolver, InboundSecret,
    };
    use chrono::TimeZone;
    use http::Request;
    use std::sync::Arc;

    struct FixedResolver {
        akid: Arc<str>,
        secret: InboundSecret,
    }
    impl InboundCredentialResolver for FixedResolver {
        fn resolve(
            &self,
            access_key_id: &str,
            _session_token: Option<&str>,
            _now: DateTime<Utc>,
        ) -> Result<Option<Arc<InboundCredential>>, CredentialResolveError> {
            if access_key_id != self.akid.as_ref() {
                return Ok(None);
            }
            Ok(Some(Arc::new(InboundCredential {
                access_key_id: self.akid.clone(),
                secret_access_key: self.secret.clone(),
                session_token: None,
                expires_at: None,
            })))
        }
    }

    fn rid() -> &'static str {
        "req-test"
    }
    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    /// AWS canonical query encoding: same NON_ALPHANUMERIC + unreserved
    /// set the canonical builder uses. Tests build query strings directly
    /// so they don't need the full builder.
    fn enc(s: &str) -> String {
        const HEX: &[u8] = b"0123456789ABCDEF";
        let mut out = String::with_capacity(s.len());
        for &b in s.as_bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                out.push(b as char);
            } else {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
        out
    }

    /// Sign a SigV4A presigned URL the same way AWS SDKs do.
    #[allow(clippy::too_many_arguments)]
    fn sign_sigv4a_presigned_query(
        path: &str,
        host: &str,
        amz_date: &str,
        expires: u64,
        akid: &str,
        secret: &str,
        region_set: &str,
        extra_signed: &[(&str, &str)],
    ) -> String {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};

        let date_yyyymmdd = &amz_date[..8];
        let credential_raw = format!("{akid}/{date_yyyymmdd}/s3/aws4_request");
        let credential_enc = enc(&credential_raw);
        let region_set_enc = enc(region_set);
        let signed_names_str = "host";
        let signed_headers_enc = enc(signed_names_str);

        // Build the unsigned URL with auth params except X-Amz-Signature.
        let unsigned_query = format!(
            "X-Amz-Algorithm={SIGV4A_ALGORITHM}\
             &X-Amz-Credential={credential_enc}\
             &X-Amz-Date={amz_date}\
             &X-Amz-Expires={expires}\
             &X-Amz-Region-Set={region_set_enc}\
             &X-Amz-SignedHeaders={signed_headers_enc}",
        );
        let mut full_query = unsigned_query.clone();
        for (k, v) in extra_signed {
            full_query.push('&');
            full_query.push_str(&enc(k));
            full_query.push('=');
            full_query.push_str(&enc(v));
        }

        // Build a Parts to feed the canonical builder.
        let uri = format!("{path}?{full_query}");
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header("host", host)
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();

        let signed_headers = vec![HeaderName::from_static("host")];
        let canonical = build_canonical_request_from_signed_headers(
            &parts,
            &signed_headers,
            &PayloadHashForSigning::UnsignedPayload,
            CanonicalQueryMode::ExcludePresignedSignature,
            "rid",
        )
        .unwrap();
        let scope = SigV4aCredentialScope {
            date: chrono::NaiveDate::parse_from_str(date_yyyymmdd, "%Y%m%d").unwrap(),
            date_yyyymmdd: date_yyyymmdd.to_string(),
            service: "s3".to_string(),
        };
        let sts = build_sigv4a_string_to_sign(&scope, amz_date, &canonical.canonical_request);

        let signing_scalar = aws_sigv4::sign::v4a::generate_signing_key(akid, secret);
        let signing_key = SigningKey::from_bytes(signing_scalar.as_ref()).unwrap();
        let sig: Signature = signing_key.sign(sts.as_bytes());
        let der_hex = hex::encode(sig.to_der().as_ref());

        format!("{full_query}&X-Amz-Signature={der_hex}")
    }

    fn parts_for(method: &str, path: &str, query: &str, host: &str) -> http::request::Parts {
        let req = Request::builder()
            .method(method)
            .uri(format!("{path}?{query}"))
            .header("host", host)
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        parts
    }

    fn build_resolver(akid: &str, secret: &str) -> FixedResolver {
        FixedResolver {
            akid: Arc::from(akid),
            secret: InboundSecret::new(secret.to_string()),
        }
    }

    /// Happy-path SigV4A presigned URL: sign with AWS-SDK-equivalent
    /// machinery, verify with our presigned verifier.
    #[test]
    fn test_sigv4a_presigned_round_trip_verifies() {
        let q = sign_sigv4a_presigned_query(
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            3600,
            "AKID",
            "SECRET",
            "us-east-1",
            &[],
        );
        let parts = parts_for("GET", "/bucket/key", &q, "example.com");
        let resolver = build_resolver("AKID", "SECRET");
        let verified =
            verify_sigv4a_presigned_request(&parts, &resolver, rid(), now()).expect("verifies");
        assert_eq!(&*verified.access_key_id, "AKID");
        assert!(matches!(
            verified.credential_scope,
            VerifiedCredentialScope::SigV4a(_)
        ));
    }

    /// Missing `X-Amz-Region-Set` is rejected up front. Without this
    /// the SigV4A canonical request is ill-defined.
    #[test]
    fn test_sigv4a_presigned_missing_region_set_rejected() {
        let amz_date = "20260101T120000Z";
        let credential_enc = enc("AKID/20260101/s3/aws4_request");
        let q = format!(
            "X-Amz-Algorithm={SIGV4A_ALGORITHM}\
             &X-Amz-Credential={credential_enc}\
             &X-Amz-Date={amz_date}\
             &X-Amz-Expires=3600\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=304402201111111111111111111111111111111111111111111111111111111111111111\
             0220222222222222222222222222222222222222222222222222222222222222222222",
        );
        let parts = parts_for("GET", "/bucket/key", &q, "example.com");
        let resolver = build_resolver("AKID", "SECRET");
        let err = verify_sigv4a_presigned_request(&parts, &resolver, rid(), now())
            .expect_err("missing region set");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    /// Expired presigned URL: `now` is past `X-Amz-Date + X-Amz-Expires`.
    /// Surfaces as `RequestTimeTooSkewed`, matching the HMAC verifier.
    #[test]
    fn test_sigv4a_presigned_expired_window_rejected() {
        let q = sign_sigv4a_presigned_query(
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            60,
            "AKID",
            "SECRET",
            "us-east-1",
            &[],
        );
        let parts = parts_for("GET", "/bucket/key", &q, "example.com");
        let resolver = build_resolver("AKID", "SECRET");
        let past_expiry = Utc.with_ymd_and_hms(2026, 1, 1, 13, 0, 0).unwrap();
        let err = verify_sigv4a_presigned_request(&parts, &resolver, rid(), past_expiry)
            .expect_err("expired");
        assert_eq!(err.code, "RequestTimeTooSkewed");
    }

    /// Tampering a signed query param (here, the path → forces a
    /// different canonical request) flips the signature.
    #[test]
    fn test_sigv4a_presigned_tampered_path_rejected() {
        let q = sign_sigv4a_presigned_query(
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            3600,
            "AKID",
            "SECRET",
            "us-east-1",
            &[],
        );
        // Sign for `/bucket/key`, verify against a different path.
        let parts = parts_for("GET", "/bucket/other", &q, "example.com");
        let resolver = build_resolver("AKID", "SECRET");
        let err = verify_sigv4a_presigned_request(&parts, &resolver, rid(), now())
            .expect_err("tampered path");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    /// SigV4A credential is regionless; the HMAC-shaped credential
    /// `<akid>/<date>/<region>/s3/aws4_request` is rejected by the
    /// SigV4A parser as malformed (the "no region" branch). Without
    /// this, the dispatcher could route an HMAC-shaped credential to
    /// the wrong parser via the algorithm field alone.
    #[test]
    fn test_sigv4a_presigned_regionful_credential_rejected() {
        let amz_date = "20260101T120000Z";
        let credential_enc = enc("AKID/20260101/us-east-1/s3/aws4_request");
        let q = format!(
            "X-Amz-Algorithm={SIGV4A_ALGORITHM}\
             &X-Amz-Credential={credential_enc}\
             &X-Amz-Date={amz_date}\
             &X-Amz-Expires=3600\
             &X-Amz-Region-Set=us-east-1\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=304402201111111111111111111111111111111111111111111111111111111111111111\
             0220222222222222222222222222222222222222222222222222222222222222222222"
        );
        let err = parse_sigv4a_presigned_authorization(&q, rid()).expect_err("regionful");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
        assert!(
            err.message.contains("no region"),
            "error should explain SigV4A is regionless, got: {}",
            err.message,
        );
    }

    /// Raw 64-byte `r||s` (128 hex chars) as `X-Amz-Signature` must
    /// reject as `AuthorizationHeaderMalformed` at parse time, not
    /// `SignatureDoesNotMatch` at verify time. Mirrors the header-auth
    /// layering test in `auth::sigv4a::parser`.
    ///
    /// Bug-revert reasoning: dropping the `Signature::from_der` call
    /// inside `parse_der_signature_hex` flips this from
    /// `AuthorizationHeaderMalformed` to `SignatureDoesNotMatch`.
    #[test]
    fn test_sigv4a_presigned_raw_r_s_signature_rejected_at_parse_layer() {
        let amz_date = "20260101T120000Z";
        let credential_enc = enc("AKID/20260101/s3/aws4_request");
        let raw_rs = "0".repeat(128);
        let q = format!(
            "X-Amz-Algorithm={SIGV4A_ALGORITHM}\
             &X-Amz-Credential={credential_enc}\
             &X-Amz-Date={amz_date}\
             &X-Amz-Expires=3600\
             &X-Amz-Region-Set=us-east-1\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature={raw_rs}"
        );
        let err = parse_sigv4a_presigned_authorization(&q, rid()).expect_err("raw r||s");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    /// Arbitrary non-DER lowercase hex — well-formed hex of an
    /// acceptable length, but no DER structure — must also reject as
    /// `AuthorizationHeaderMalformed`.
    #[test]
    fn test_sigv4a_presigned_arbitrary_non_der_hex_rejected_at_parse_layer() {
        let amz_date = "20260101T120000Z";
        let credential_enc = enc("AKID/20260101/s3/aws4_request");
        let q = format!(
            "X-Amz-Algorithm={SIGV4A_ALGORITHM}\
             &X-Amz-Credential={credential_enc}\
             &X-Amz-Date={amz_date}\
             &X-Amz-Expires=3600\
             &X-Amz-Region-Set=us-east-1\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        );
        let err = parse_sigv4a_presigned_authorization(&q, rid()).expect_err("non-DER hex");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }
}
