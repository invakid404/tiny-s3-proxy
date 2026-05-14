//! Inbound credential resolution for strict SigV4 verification.
//!
//! The strict verifier (see `crate::auth::sigv4`) needs a way to look up the
//! shared secret for an inbound `Authorization`'s access-key id. This module
//! defines the lookup trait and ships a static-JSON-file implementation; STS
//! / dynamic stores are deferred to a follow-up PR of issue #63.
//!
//! Two invariants drive the type shapes here:
//!
//! 1. Secrets are **zeroized on drop**. We cannot use `Arc<str>` directly
//!    because `Arc<T>` does not (and cannot) zero its inner allocation when
//!    the last reference goes away. Wrapping a `String` in `Zeroizing` and
//!    putting *that* behind an `Arc` is the only shape that gives us both
//!    cheap clones AND zeroization on the final drop.
//! 2. The raw file bytes are zeroized too. Parsers can leave secret
//!    substrings lingering in non-zeroized memory if you feed them a
//!    `String` directly, so the resolver reads the file into `Zeroizing<String>`,
//!    deserializes once, and lets the raw buffer zero out as it falls out of
//!    scope.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// Wrapper that owns a secret string and zeroes it on the final drop.
///
/// `Arc<str>` cannot be zeroized — its allocation is shared and immutable.
/// `Zeroizing<String>` zeroes but isn't cheaply cloneable. Combining the two
/// (`Arc<Zeroizing<String>>`) gives both cheap clones across requests AND a
/// guaranteed zero when the last reference is dropped.
#[derive(Clone)]
pub struct InboundSecret(Arc<Zeroizing<String>>);

impl InboundSecret {
    /// Construct from a plain `String`. The string is moved into a
    /// `Zeroizing<String>` so its backing buffer is wiped on drop.
    pub fn new(secret: String) -> Self {
        Self(Arc::new(Zeroizing::new(secret)))
    }

    /// Expose the underlying secret for HMAC/signing. Callers must not
    /// store the returned slice past the lifetime of the `InboundSecret`,
    /// and should not write it to logs / error messages.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for InboundSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never include the secret in Debug output. A length hint helps
        // diagnose "no creds loaded" vs "creds loaded but mismatch".
        write!(f, "InboundSecret(<{} bytes>)", self.0.len())
    }
}

/// A resolved inbound credential. `session_token` and `expires_at` are kept
/// in the shape they will take in later PRs (STS support); they are always
/// `None` in this PR.
#[derive(Debug, Clone)]
pub struct InboundCredential {
    pub access_key_id: Arc<str>,
    pub secret_access_key: InboundSecret,
    pub session_token: Option<Arc<str>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Resolver errors. Misses (no credential for the given access-key id) are
/// represented as `Ok(None)` instead — only true I/O / parsing failures use
/// this error.
#[derive(Debug, Error)]
pub enum CredentialResolveError {
    #[error("internal credential store error: {0}")]
    Internal(String),
}

/// Inbound credential lookup.
///
/// Implementations look up a credential by access-key id (and, in future PRs,
/// optional session token). Returning `Ok(None)` means "no such credential",
/// which the verifier will map to `InvalidAccessKeyId`. Returning `Err`
/// means the store itself failed (I/O, corruption) and should map to a 500.
pub trait InboundCredentialResolver: Send + Sync {
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
    ) -> Result<Option<Arc<InboundCredential>>, CredentialResolveError>;
}

// ── Static JSON-file resolver ──────────────────────────────────────────

/// Errors that can occur while loading a static credentials file.
#[derive(Debug, Error)]
pub enum StaticCredentialsLoadError {
    #[error("failed to read credentials file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse credentials file {path}: {reason}")]
    Parse { path: PathBuf, reason: String },
    #[error("credentials file {path} failed validation: {reason}")]
    Validation { path: PathBuf, reason: String },
}

/// The on-disk JSON shape. `deny_unknown_fields` catches typos at startup
/// rather than silently ignoring them at runtime.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialsFile {
    version: u32,
    credentials: Vec<CredentialEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEntry {
    access_key_id: String,
    secret_access_key: String,
}

/// Static credentials store backed by a single JSON file. The file is read
/// once at startup; reloads require restarting the proxy.
pub struct StaticInboundCredentials {
    by_access_key_id: HashMap<Arc<str>, Arc<InboundCredential>>,
}

impl std::fmt::Debug for StaticInboundCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only the count, never any key material.
        write!(
            f,
            "StaticInboundCredentials({} credentials)",
            self.by_access_key_id.len()
        )
    }
}

impl StaticInboundCredentials {
    /// Load credentials from a JSON file at `path`.
    ///
    /// The raw file contents are placed in `Zeroizing<String>` immediately
    /// so the secret bytes are wiped from memory after parsing. Each parsed
    /// secret is then re-wrapped in a per-credential `InboundSecret`.
    pub fn load_from_file(path: &Path) -> Result<Self, StaticCredentialsLoadError> {
        let raw = fs::read_to_string(path).map_err(|source| StaticCredentialsLoadError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        // Move into a Zeroizing<String> *before* parsing so the raw secret
        // bytes are wiped when we drop the buffer at the end of this fn.
        let raw = Zeroizing::new(raw);

        let parsed: CredentialsFile =
            serde_json::from_str(raw.as_str()).map_err(|e| StaticCredentialsLoadError::Parse {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;

        if parsed.version != 1 {
            return Err(StaticCredentialsLoadError::Validation {
                path: path.to_path_buf(),
                reason: format!(
                    "unsupported credentials file version {} (expected 1)",
                    parsed.version
                ),
            });
        }

        if parsed.credentials.is_empty() {
            return Err(StaticCredentialsLoadError::Validation {
                path: path.to_path_buf(),
                reason: "credentials array is empty; at least one entry is required".to_string(),
            });
        }

        let mut by_access_key_id: HashMap<Arc<str>, Arc<InboundCredential>> =
            HashMap::with_capacity(parsed.credentials.len());

        for entry in parsed.credentials {
            let access_key_id = entry.access_key_id;
            let secret_access_key = entry.secret_access_key;

            if access_key_id.is_empty() {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: "empty access_key_id".to_string(),
                });
            }
            if access_key_id.trim() != access_key_id {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "access_key_id has leading/trailing whitespace: {access_key_id:?}"
                    ),
                });
            }
            if secret_access_key.is_empty() {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: format!("empty secret_access_key for {access_key_id}"),
                });
            }
            if secret_access_key.trim() != secret_access_key {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "secret_access_key for {access_key_id} has leading/trailing whitespace"
                    ),
                });
            }

            let akid_arc: Arc<str> = Arc::from(access_key_id.as_str());
            if by_access_key_id.contains_key(&akid_arc) {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: format!("duplicate access_key_id: {access_key_id}"),
                });
            }

            let cred = InboundCredential {
                access_key_id: akid_arc.clone(),
                secret_access_key: InboundSecret::new(secret_access_key),
                session_token: None,
                expires_at: None,
            };
            by_access_key_id.insert(akid_arc, Arc::new(cred));
        }

        Ok(Self { by_access_key_id })
    }

    /// Number of credentials loaded. Useful for startup logging.
    pub fn len(&self) -> usize {
        self.by_access_key_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_access_key_id.is_empty()
    }
}

impl InboundCredentialResolver for StaticInboundCredentials {
    fn resolve(
        &self,
        access_key_id: &str,
        _session_token: Option<&str>,
    ) -> Result<Option<Arc<InboundCredential>>, CredentialResolveError> {
        // PR 1: session tokens are rejected before reaching the resolver
        // (the parser raises InvalidToken for `x-amz-security-token` in
        // signed headers), so we ignore the argument here.
        Ok(self.by_access_key_id.get(access_key_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_file(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_loads_valid_file() {
        let f = write_file(
            r#"{
              "version": 1,
              "credentials": [
                { "access_key_id": "client-a", "secret_access_key": "secret-a" },
                { "access_key_id": "client-b", "secret_access_key": "secret-b" }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        assert_eq!(store.len(), 2);

        let a = store.resolve("client-a", None).unwrap().expect("client-a");
        assert_eq!(&*a.access_key_id, "client-a");
        assert_eq!(a.secret_access_key.expose(), "secret-a");
        assert!(a.session_token.is_none());
        assert!(a.expires_at.is_none());

        let b = store.resolve("client-b", None).unwrap().expect("client-b");
        assert_eq!(b.secret_access_key.expose(), "secret-b");

        assert!(store.resolve("client-c", None).unwrap().is_none());
    }

    #[test]
    fn test_missing_file_errors_clearly() {
        let err = StaticInboundCredentials::load_from_file(Path::new(
            "/nonexistent/path/should/not/exist.json",
        ))
        .expect_err("missing file must error");
        match err {
            StaticCredentialsLoadError::Io { .. } => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn test_malformed_json_errors_clearly() {
        let f = write_file("{ not valid json");
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("malformed JSON must error");
        match err {
            StaticCredentialsLoadError::Parse { .. } => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn test_rejects_unknown_version() {
        let f = write_file(
            r#"{ "version": 2, "credentials": [{ "access_key_id": "a", "secret_access_key": "b" }] }"#,
        );
        let err =
            StaticInboundCredentials::load_from_file(f.path()).expect_err("version!=1 must error");
        match err {
            StaticCredentialsLoadError::Validation { reason, .. } => {
                assert!(reason.contains("version"), "got: {reason}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_rejects_empty_credentials_array() {
        let f = write_file(r#"{ "version": 1, "credentials": [] }"#);
        let err =
            StaticInboundCredentials::load_from_file(f.path()).expect_err("empty array must error");
        match err {
            StaticCredentialsLoadError::Validation { reason, .. } => {
                assert!(reason.contains("empty"), "got: {reason}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_rejects_empty_access_key_id() {
        let f = write_file(
            r#"{ "version": 1, "credentials": [{ "access_key_id": "", "secret_access_key": "s" }] }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("empty access_key_id must error");
        assert!(matches!(err, StaticCredentialsLoadError::Validation { .. }));
    }

    #[test]
    fn test_rejects_empty_secret() {
        let f = write_file(
            r#"{ "version": 1, "credentials": [{ "access_key_id": "a", "secret_access_key": "" }] }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("empty secret must error");
        assert!(matches!(err, StaticCredentialsLoadError::Validation { .. }));
    }

    #[test]
    fn test_rejects_whitespace_padded_values() {
        let f = write_file(
            r#"{ "version": 1, "credentials": [{ "access_key_id": " a ", "secret_access_key": "s" }] }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("padded access_key_id must error");
        assert!(matches!(err, StaticCredentialsLoadError::Validation { .. }));

        let f = write_file(
            r#"{ "version": 1, "credentials": [{ "access_key_id": "a", "secret_access_key": " s" }] }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("padded secret must error");
        assert!(matches!(err, StaticCredentialsLoadError::Validation { .. }));
    }

    #[test]
    fn test_rejects_duplicate_access_key_id() {
        let f = write_file(
            r#"{
              "version": 1,
              "credentials": [
                { "access_key_id": "dup", "secret_access_key": "s1" },
                { "access_key_id": "dup", "secret_access_key": "s2" }
              ]
            }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("duplicate akid must error");
        match err {
            StaticCredentialsLoadError::Validation { reason, .. } => {
                assert!(reason.contains("duplicate"), "got: {reason}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_rejects_unknown_fields() {
        // serde's `deny_unknown_fields` should reject typos in the file.
        let f = write_file(
            r#"{
              "version": 1,
              "credentials": [
                { "access_key_id": "a", "secret_access_key": "s", "extra": "field" }
              ]
            }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("unknown field must error");
        assert!(matches!(err, StaticCredentialsLoadError::Parse { .. }));

        let f = write_file(
            r#"{
              "version": 1,
              "credentials": [{ "access_key_id": "a", "secret_access_key": "s" }],
              "wat": true
            }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("unknown top-level field must error");
        assert!(matches!(err, StaticCredentialsLoadError::Parse { .. }));
    }

    #[test]
    fn test_inbound_secret_debug_does_not_leak_value() {
        let s = InboundSecret::new("super-secret-key".to_string());
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("super-secret-key"),
            "InboundSecret Debug leaked plaintext: {dbg}"
        );
        assert!(dbg.contains("bytes"), "Debug should hint at length: {dbg}");
    }
}
