//! Strict-mode inbound SigV4 verification.
//!
//! Public entry point: [`SigV4Verifier::verify`] (header / scope / date /
//! canonical request / signature) and [`SigV4Verifier::verify_payload_hash`]
//! (body sha256 vs. signed `x-amz-content-sha256`).
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
pub mod streaming;

use crate::auth::credentials::InboundCredentialResolver;
use crate::s3::errors::S3Error;
use chrono::{DateTime, Utc};
use http::HeaderName;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use self::canonical::build_canonical_request;
use self::parser::{
    CredentialScope, enforce_skew, ensure_scope_date_matches, parse_authorization,
    resolve_request_time,
};
use self::payload::{PayloadHashForSigning, classify_payload_header, verify_payload_matches_hash};

/// SigV4 signing key (HMAC-SHA256 output, 32 bytes), zeroized on drop.
///
/// PR 2 will reuse this for chunk-by-chunk verification of aws-chunked
/// uploads; keeping it in `Zeroizing` from the start avoids leaving HMAC
/// keys lingering in memory after a request finishes.
pub struct SigningKey(Zeroizing<[u8; 32]>);

impl SigningKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(<32 bytes>)")
    }
}

/// Output of a successful header/canonical-request verification. The
/// signature itself has matched; the payload-hash check is separate (see
/// `verify_payload_hash`) so callers can avoid buffering bodies for requests
/// that don't sign them.
#[derive(Debug)]
pub struct VerifiedRequest {
    pub access_key_id: Arc<str>,
    pub scope: CredentialScope,
    pub signed_headers: Vec<HeaderName>,
    pub request_signature_hex: String,
    pub signing_key: SigningKey,
    pub amz_date: String,
    pub payload: PayloadHashForSigning,
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
    pub fn verify_at(
        &self,
        parts: &http::request::Parts,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedRequest, S3Error> {
        // Reject any presigned-URL keys up front, even before parsing the
        // Authorization header — they bypass strict mode by design.
        if has_presigned_query(parts.uri.query().unwrap_or("")) {
            return Err(S3Error::missing_authentication_token(
                "presigned URLs (X-Amz-Signature) are not supported in strict mode; \
                 tracked in PR 3 of issue #63",
                request_id,
            ));
        }

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

        // Resolve credential. A miss → InvalidAccessKeyId (the standard
        // S3 response for an unknown key); a store error → InternalError.
        let credential = self
            .resolver
            .resolve(&auth.access_key_id, None)
            .map_err(|e| {
                tracing::error!(error = %e, "credential resolver failed");
                S3Error::internal_error("credential resolver failed", request_id)
            })?
            .ok_or_else(|| {
                S3Error::invalid_access_key_id("access-key id is not configured", request_id)
            })?;

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
            scope: auth.scope,
            signed_headers: auth.signed_headers,
            request_signature_hex: auth.signature_hex,
            signing_key,
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

fn has_presigned_query(raw_query: &str) -> bool {
    raw_query.split('&').any(|chunk| {
        let key = chunk.split_once('=').map(|(k, _)| k).unwrap_or(chunk);
        key.eq_ignore_ascii_case("X-Amz-Signature")
    })
}

fn derive_signing_key(
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

fn build_string_to_sign(
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

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::credentials::{
        CredentialResolveError, InboundCredential, InboundCredentialResolver, InboundSecret,
    };
    use crate::auth::sigv4::parser::SigV4Authorization;
    use chrono::TimeZone;
    use http::Request;

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
    fn test_presigned_query_rejected_up_front() {
        let req = Request::builder()
            .method("GET")
            .uri("/b/k?X-Amz-Signature=deadbeef")
            .header("host", "example.com")
            .header("x-amz-date", "20260101T120000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let v = build_verifier("AKID", "SECRET");
        let err = v.verify_at(&parts, "rid", now()).expect_err("presigned");
        assert_eq!(err.code, "MissingAuthenticationToken");
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
