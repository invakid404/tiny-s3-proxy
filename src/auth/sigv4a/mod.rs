//! Strict-mode inbound SigV4A (`AWS4-ECDSA-P256-SHA256`) verification.
//!
//! Sibling of [`crate::auth::sigv4`]. SigV4A shares canonical-request
//! construction, header/skew validation, and credential resolution with
//! plain SigV4 HMAC; it differs in (1) the per-credential signing key,
//! which is an ECDSA P-256 scalar derived from the access key id and
//! secret access key via an SP 800-108 counter-mode KDF, (2) the
//! regionless credential scope (`<yyyymmdd>/s3/aws4_request`), (3) the
//! signed region-set parameter, and (4) the signature wire format
//! (lowercase hex of DER-encoded ECDSA-P256/SHA-256, variable length up
//! to 144 hex chars).
//!
//! Public entry point: [`verify_authorization_header_at`] for the
//! `Authorization: AWS4-ECDSA-P256-SHA256 ...` header path. Presigned
//! URL and aws-chunked streaming verifiers land in subsequent commits.

pub mod crypto;
pub mod parser;
pub mod presigned;

use crate::auth::credentials::InboundCredentialResolver;
use crate::auth::sigv4::canonical::{
    CanonicalQueryMode, build_canonical_request_from_signed_headers,
};
use crate::auth::sigv4::parser::{enforce_skew, resolve_request_time};
use crate::auth::sigv4::payload::classify_payload_header;
use crate::auth::sigv4::{extract_header_session_token, resolve_credential_for_sigv4};
use crate::auth::verified::{VerifiedCredentialScope, VerifiedSigningContext};
use crate::s3::errors::S3Error;
use chrono::{DateTime, NaiveDate, Utc};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub use crate::auth::verified::VerifiedRequest;

use self::crypto::{derive_sigv4a_verifying_key, verify_sigv4a_der_signature};
use self::parser::{
    SigV4aAuthorization, ensure_sigv4a_region_set_signed, parse_sigv4a_authorization,
};

pub const SIGV4A_ALGORITHM: &str = "AWS4-ECDSA-P256-SHA256";

/// Credential scope for SigV4A header / presigned auth.
///
/// Differs from [`crate::auth::sigv4::parser::CredentialScope`] in the
/// absence of a region component — SigV4A scopes are regionless, and the
/// signed region set lives in `x-amz-region-set` (header) or
/// `X-Amz-Region-Set` (query) instead.
#[derive(Debug, Clone)]
pub struct SigV4aCredentialScope {
    pub date: NaiveDate,
    pub date_yyyymmdd: String,
    pub service: String,
}

/// Build the SigV4A string-to-sign. Four lines like HMAC, but with the
/// SigV4A algorithm literal and a regionless scope:
///
/// ```text
/// AWS4-ECDSA-P256-SHA256
/// <amz-date>
/// <yyyymmdd>/s3/aws4_request
/// <lowercase hex SHA-256 of canonical request>
/// ```
pub(crate) fn build_sigv4a_string_to_sign(
    scope: &SigV4aCredentialScope,
    amz_date: &str,
    canonical_request: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_request.as_bytes());
    let digest = hasher.finalize();
    let creq_hex = hex_lower(&digest);
    let scope_str = format!("{}/{}/aws4_request", scope.date_yyyymmdd, scope.service);
    format!("{SIGV4A_ALGORITHM}\n{amz_date}\n{scope_str}\n{creq_hex}")
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// SigV4A header-auth verifier entry point.
///
/// Mirrors [`crate::auth::sigv4::SigV4Verifier::verify_authorization_header_at`]
/// at the structural level (parse Authorization header, resolve request
/// time, enforce skew, classify payload, resolve credential, build
/// canonical request, verify signature) but uses ECDSA instead of HMAC
/// for the signature step and requires `x-amz-region-set` to be signed.
pub(crate) fn verify_authorization_header_at(
    parts: &http::request::Parts,
    resolver: &dyn InboundCredentialResolver,
    max_skew: Duration,
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
    let auth: SigV4aAuthorization = parse_sigv4a_authorization(auth_str, request_id)?;

    // Resolve the request timestamp first; the credential scope date must
    // match the request date, and we want a clear skew/date error before
    // we burn an ECDSA verify.
    let (amz_date, request_time) = resolve_request_time(&parts.headers, request_id)?;
    enforce_skew(
        request_time,
        now,
        chrono::Duration::from_std(max_skew).unwrap_or(chrono::Duration::seconds(900)),
        request_id,
    )?;
    if auth.scope.date != request_time.date_naive() {
        return Err(S3Error::authorization_header_malformed(
            "Credential scope date does not match the request timestamp",
            request_id,
        ));
    }

    // SigV4A-specific: x-amz-region-set must be present and signed.
    ensure_sigv4a_region_set_signed(&parts.headers, &auth.signed_headers, request_id)?;

    // Classify the payload header. Shape rules are identical to HMAC —
    // SigV4A streaming sentinels are accepted here once commit 5 adds
    // their variants; today they still surface as UnsupportedSignature.
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

    // STS token handling is identical to HMAC: when present, the header
    // must be in SignedHeaders, and the resolver selects the credential
    // by (access_key_id, session_token).
    let session_token = extract_header_session_token(parts, &auth.signed_headers, request_id)?;

    let credential = resolve_credential_for_sigv4(
        resolver,
        &auth.access_key_id,
        session_token.as_deref(),
        now,
        request_id,
    )?;

    // The signed canonical request is the same six-line layout as HMAC.
    // x-amz-region-set already lives in the request headers and was
    // required in SignedHeaders above, so the canonical builder picks
    // it up automatically.
    let canonical = build_canonical_request_from_signed_headers(
        parts,
        &auth.signed_headers,
        &payload,
        CanonicalQueryMode::IncludeAll,
        request_id,
    )?;

    let verifying_key =
        derive_sigv4a_verifying_key(&auth.access_key_id, credential.secret_access_key.expose())
            .map_err(|e| {
                tracing::error!(error = %e, "SigV4A KDF failed for resolved credential");
                S3Error::internal_error("internal error deriving SigV4A verifying key", request_id)
            })?;
    let string_to_sign =
        build_sigv4a_string_to_sign(&auth.scope, &amz_date, &canonical.canonical_request);

    verify_sigv4a_der_signature(
        &verifying_key,
        string_to_sign.as_bytes(),
        &auth.signature_der,
    )
    .map_err(|_| {
        S3Error::signature_does_not_match(
            "computed SigV4A signature does not match the supplied signature",
            request_id,
        )
    })?;

    Ok(VerifiedRequest {
        access_key_id: credential.access_key_id.clone(),
        credential_scope: VerifiedCredentialScope::SigV4a(auth.scope),
        signed_headers: auth.signed_headers,
        request_signature_hex: auth.signature_hex,
        signing_context: VerifiedSigningContext::EcdsaP256(verifying_key),
        amz_date,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::credentials::{
        CredentialResolveError, InboundCredential, InboundCredentialResolver, InboundSecret,
    };
    use crate::auth::sigv4::payload::PayloadHashForSigning;
    use chrono::TimeZone;
    use http::{HeaderName, Request};
    use std::sync::Arc;

    /// Resolver that returns a single configured `(akid, secret)` pair
    /// (no STS in this commit). Used by the SigV4A round-trip tests.
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

    /// Sign a SigV4A request the same way AWS SDKs do: build the
    /// canonical request, hash it into the SigV4A string-to-sign, sign
    /// with `aws_sigv4::sign::v4a::generate_signing_key + p256 sign`,
    /// hex-encode the DER signature, return the `Authorization` header.
    #[allow(clippy::too_many_arguments)]
    fn sign_sigv4a_request(
        method: &str,
        uri: &str,
        host: &str,
        amz_date: &str,
        payload_hash: &str,
        akid: &str,
        secret: &str,
        region_set: &str,
    ) -> (String, http::HeaderMap) {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};

        let date_yyyymmdd = &amz_date[..8];
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", host)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-region-set", region_set)
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();

        let signed_headers = vec![
            HeaderName::from_static("host"),
            HeaderName::from_static("x-amz-content-sha256"),
            HeaderName::from_static("x-amz-date"),
            HeaderName::from_static("x-amz-region-set"),
        ];
        let signed_headers_str = "host;x-amz-content-sha256;x-amz-date;x-amz-region-set";

        let payload = match payload_hash {
            "UNSIGNED-PAYLOAD" => PayloadHashForSigning::UnsignedPayload,
            _ => panic!("unsupported payload hash for test: {payload_hash}"),
        };

        let canonical = build_canonical_request_from_signed_headers(
            &parts,
            &signed_headers,
            &payload,
            CanonicalQueryMode::IncludeAll,
            "rid",
        )
        .unwrap();
        let scope = SigV4aCredentialScope {
            date: NaiveDate::parse_from_str(date_yyyymmdd, "%Y%m%d").unwrap(),
            date_yyyymmdd: date_yyyymmdd.to_string(),
            service: "s3".to_string(),
        };
        let sts = build_sigv4a_string_to_sign(&scope, amz_date, &canonical.canonical_request);

        let signing_scalar = aws_sigv4::sign::v4a::generate_signing_key(akid, secret);
        let signing_key = SigningKey::from_bytes(signing_scalar.as_ref()).unwrap();
        let sig: Signature = signing_key.sign(sts.as_bytes());
        let der_hex = hex::encode(sig.to_der().as_ref());

        let auth_header = format!(
            "AWS4-ECDSA-P256-SHA256 Credential={akid}/{date_yyyymmdd}/s3/aws4_request, \
             SignedHeaders={signed_headers_str}, Signature={der_hex}"
        );
        (auth_header, parts.headers)
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

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    fn build_resolver(akid: &str, secret: &str) -> FixedResolver {
        FixedResolver {
            akid: Arc::from(akid),
            secret: InboundSecret::new(secret.to_string()),
        }
    }

    /// Happy path: AWS SDKs sign with the same KDF + canonical-request
    /// pipeline we verify with, so a fresh signature round-trips. ECDSA
    /// signatures are non-deterministic (the underlying RustCrypto
    /// `Signer` uses RFC 6979, but real SDK signers can use random
    /// nonces); the test asserts acceptance, not a fixed signature.
    #[test]
    fn test_sigv4a_header_round_trip_verifies() {
        let resolver = build_resolver("AKID", "SECRET");
        let (auth, headers) = sign_sigv4a_request(
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
        let verified = verify_authorization_header_at(
            &parts,
            &resolver,
            Duration::from_secs(900),
            "rid",
            now(),
        )
        .expect("verifies");
        assert_eq!(&*verified.access_key_id, "AKID");
        assert!(matches!(
            verified.credential_scope,
            VerifiedCredentialScope::SigV4a(_)
        ));
        assert!(matches!(
            verified.signing_context,
            VerifiedSigningContext::EcdsaP256(_)
        ));
    }

    /// Tampering a signed header after signing must surface as
    /// `SignatureDoesNotMatch`. Bug-revert reasoning: dropping the
    /// `verify_sigv4a_der_signature` call (i.e. only structurally
    /// parsing the auth header without actually checking the signature)
    /// would flip this from `SignatureDoesNotMatch` to `Ok(_)`.
    #[test]
    fn test_sigv4a_header_tampered_signed_header_fails() {
        let resolver = build_resolver("AKID", "SECRET");
        let (auth, mut headers) = sign_sigv4a_request(
            "GET",
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        headers.insert("host", "evil.example".parse().unwrap());
        let parts = parts_for("GET", "/bucket/key", headers, &auth);
        let err = verify_authorization_header_at(
            &parts,
            &resolver,
            Duration::from_secs(900),
            "rid",
            now(),
        )
        .expect_err("tampered host");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    /// Tampering the region set must fail — it's a signed header and is
    /// part of the canonical request. Pinning this prevents a future
    /// `ensure_sigv4a_region_set_signed` regression where the header is
    /// declared present but the canonical builder silently omits it.
    #[test]
    fn test_sigv4a_header_tampered_region_set_fails() {
        let resolver = build_resolver("AKID", "SECRET");
        let (auth, mut headers) = sign_sigv4a_request(
            "GET",
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        headers.insert("x-amz-region-set", "us-west-2".parse().unwrap());
        let parts = parts_for("GET", "/bucket/key", headers, &auth);
        let err = verify_authorization_header_at(
            &parts,
            &resolver,
            Duration::from_secs(900),
            "rid",
            now(),
        )
        .expect_err("tampered region set");
        assert_eq!(err.code, "SignatureDoesNotMatch");
    }

    /// Wrong access key — resolver tuple miss — must surface as
    /// `InvalidAccessKeyId`, not `SignatureDoesNotMatch`. This pins the
    /// error mapping in `resolve_credential_for_sigv4` for the SigV4A
    /// path (same code as HMAC; this test guards the cross-module call).
    #[test]
    fn test_sigv4a_header_unknown_access_key_rejected() {
        let resolver = build_resolver("AKID", "SECRET");
        let (auth, headers) = sign_sigv4a_request(
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
        let err = verify_authorization_header_at(
            &parts,
            &resolver,
            Duration::from_secs(900),
            "rid",
            now(),
        )
        .expect_err("unknown akid");
        assert_eq!(err.code, "InvalidAccessKeyId");
    }

    /// Without `x-amz-region-set` in the request, SigV4A must reject up
    /// front (before doing the signature verify), because the canonical
    /// request the client signed includes `x-amz-region-set`. The test
    /// uses a body that *would* sign correctly with the header present,
    /// then strips the header — exercise the explicit pre-check rather
    /// than relying on the implicit signature mismatch downstream.
    #[test]
    fn test_sigv4a_header_missing_region_set_rejected() {
        let resolver = build_resolver("AKID", "SECRET");
        let (auth, mut headers) = sign_sigv4a_request(
            "GET",
            "/bucket/key",
            "example.com",
            "20260101T120000Z",
            "UNSIGNED-PAYLOAD",
            "AKID",
            "SECRET",
            "us-east-1",
        );
        headers.remove("x-amz-region-set");
        let parts = parts_for("GET", "/bucket/key", headers, &auth);
        let err = verify_authorization_header_at(
            &parts,
            &resolver,
            Duration::from_secs(900),
            "rid",
            now(),
        )
        .expect_err("missing region set");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }
}
