//! Shared output shape for strict-mode inbound auth: header / presigned
//! / streaming verifiers all return a [`VerifiedRequest`] so downstream
//! handler code stays unaware of which mechanism (HMAC SigV4 vs ECDSA
//! SigV4A) and which transport (Authorization header vs `X-Amz-*` query)
//! the client used.
//!
//! Per-algorithm material — HMAC `kSigning` for SigV4 vs P-256
//! `VerifyingKey` for SigV4A — lives in the [`VerifiedSigningContext`]
//! enum. The credential scope likewise has two shapes: SigV4 has a
//! region component, SigV4A does not (region set is signed separately
//! via `x-amz-region-set` / `X-Amz-Region-Set`). Both shapes live in
//! [`VerifiedCredentialScope`]; helpers on it expose the bits that are
//! identical across both variants (yyyymmdd date, service name,
//! canonical scope-string format).

use crate::auth::sigv4::SigningKey;
use crate::auth::sigv4::parser::CredentialScope;
use crate::auth::sigv4::payload::PayloadHashForSigning;
use crate::auth::sigv4a::SigV4aCredentialScope;
use crate::auth::sigv4a::crypto::SigV4aVerifyingKey;
use http::HeaderName;
use std::sync::Arc;

/// Result of a successful strict-mode request verification.
///
/// The signature itself has matched; the payload-hash check is separate
/// (see [`crate::auth::sigv4::SigV4Verifier::verify_payload_hash`]) so
/// callers can avoid buffering bodies for requests that don't sign them.
#[derive(Debug)]
pub struct VerifiedRequest {
    pub access_key_id: Arc<str>,
    pub credential_scope: VerifiedCredentialScope,
    pub signed_headers: Vec<HeaderName>,
    pub request_signature_hex: String,
    pub signing_context: VerifiedSigningContext,
    pub amz_date: String,
    pub payload: PayloadHashForSigning,
}

/// SigV4 credential scope (region-bearing) vs SigV4A credential scope
/// (regionless). Kept as an enum so handler code can switch on it where
/// the difference matters and use helpers where it doesn't.
#[derive(Debug, Clone)]
pub enum VerifiedCredentialScope {
    SigV4(CredentialScope),
    SigV4a(SigV4aCredentialScope),
}

impl VerifiedCredentialScope {
    pub fn date_yyyymmdd(&self) -> &str {
        match self {
            VerifiedCredentialScope::SigV4(s) => &s.date_yyyymmdd,
            VerifiedCredentialScope::SigV4a(s) => &s.date_yyyymmdd,
        }
    }

    pub fn service(&self) -> &str {
        match self {
            VerifiedCredentialScope::SigV4(s) => &s.service,
            VerifiedCredentialScope::SigV4a(s) => &s.service,
        }
    }

    /// Canonical credential-scope string that appears on line 3 of the
    /// SigV4(A) string-to-sign and on line 3 of streaming chunk /
    /// trailer string-to-signs:
    ///
    /// - SigV4: `<yyyymmdd>/<region>/<service>/aws4_request`
    /// - SigV4A: `<yyyymmdd>/<service>/aws4_request`  (no region)
    pub fn credential_scope_string(&self) -> String {
        match self {
            VerifiedCredentialScope::SigV4(s) => {
                format!(
                    "{}/{}/{}/aws4_request",
                    s.date_yyyymmdd, s.region, s.service
                )
            }
            VerifiedCredentialScope::SigV4a(s) => {
                format!("{}/{}/aws4_request", s.date_yyyymmdd, s.service)
            }
        }
    }

    /// Borrow the SigV4-shaped scope when present; returns `None` for
    /// SigV4A requests. Used by HMAC-only code paths (e.g. the streaming
    /// HMAC seeding) that need the legacy region-bearing fields.
    pub fn as_sigv4(&self) -> Option<&CredentialScope> {
        match self {
            VerifiedCredentialScope::SigV4(s) => Some(s),
            VerifiedCredentialScope::SigV4a(_) => None,
        }
    }
}

/// Per-algorithm material the request-level verifier carries forward.
///
/// HMAC keeps the derived signing key so per-chunk streaming can extend
/// the same key schedule without re-derivation. ECDSA keeps only the
/// public verifying key — the private scalar is built, used, then
/// dropped inside the KDF helper.
#[derive(Debug)]
pub enum VerifiedSigningContext {
    HmacSha256(SigningKey),
    EcdsaP256(SigV4aVerifyingKey),
}

impl VerifiedRequest {
    /// HMAC signing key, when the request was verified under plain SigV4.
    /// Returns `None` for SigV4A requests.
    pub fn hmac_signing_key(&self) -> Option<&SigningKey> {
        match &self.signing_context {
            VerifiedSigningContext::HmacSha256(k) => Some(k),
            VerifiedSigningContext::EcdsaP256(_) => None,
        }
    }

    /// SigV4A verifying key, when the request was verified under SigV4A.
    /// Returns `None` for plain SigV4 requests.
    pub fn sigv4a_verifying_key(&self) -> Option<&SigV4aVerifyingKey> {
        match &self.signing_context {
            VerifiedSigningContext::EcdsaP256(k) => Some(k),
            VerifiedSigningContext::HmacSha256(_) => None,
        }
    }

    /// Convenience: the canonical credential-scope string, delegated to
    /// [`VerifiedCredentialScope::credential_scope_string`].
    pub fn credential_scope_string(&self) -> String {
        self.credential_scope.credential_scope_string()
    }
}
