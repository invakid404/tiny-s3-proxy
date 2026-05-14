//! Inbound credential resolution for strict SigV4 verification.
//!
//! The strict verifier (see `crate::auth::sigv4`) needs a way to look up the
//! shared secret for an inbound `Authorization`'s access-key id (and, when
//! the client uses STS-issued temporary credentials, its session token).
//! This module defines the lookup trait and ships a static-JSON-file
//! implementation.
//!
//! The static file accepts two schema versions:
//!
//! - **v1** — long-lived credentials only. Entries are `(access_key_id,
//!   secret_access_key)`. This is the original PR 1 schema and still loads.
//! - **v2** — superset of v1 that additionally allows optional
//!   `session_token` and `expires_at` (RFC 3339) on each entry. STS temporary
//!   credentials are a `(access_key_id, session_token)` tuple and the
//!   logical lookup key reflects that: a request without a token never
//!   matches a token-bearing entry, and vice-versa.
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
use subtle::ConstantTimeEq;
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

/// Session token, kept opaque and zeroized on the final drop. STS tokens are
/// not as sensitive as the secret access key, but they are still bearer
/// credentials — clients present them verbatim and any party that learns one
/// can impersonate the associated temporary identity until it expires.
#[derive(Clone)]
pub struct SessionToken(Arc<Zeroizing<String>>);

impl SessionToken {
    pub fn new(token: String) -> Self {
        Self(Arc::new(Zeroizing::new(token)))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionToken(<{} bytes>)", self.0.len())
    }
}

/// A resolved inbound credential. `session_token` is `Some` for v2
/// token-bearing entries and `None` for v1 / v2 long-lived entries; the
/// resolver's lookup logic keeps the two namespaces disjoint so a request
/// can't be "upgraded" between them.
#[derive(Debug, Clone)]
pub struct InboundCredential {
    pub access_key_id: Arc<str>,
    pub secret_access_key: InboundSecret,
    pub session_token: Option<SessionToken>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Resolver errors. Misses (no credential for the given access-key id /
/// session-token tuple) are represented as `Ok(None)` instead — only
/// expiry, true I/O / parsing failures, or implementation-specific
/// malformed-token classifications use this error.
#[derive(Debug, Error)]
pub enum CredentialResolveError {
    /// The credential tuple matched a configured entry but the entry's
    /// `expires_at` is in the past. Verifier maps this to `ExpiredToken`.
    #[error("credential has expired at {expires_at}")]
    Expired { expires_at: DateTime<Utc> },

    /// Resolver-specific "the supplied session token is malformed". The
    /// static resolver does not invent token grammar beyond load-time
    /// empty-value validation, so it never raises this — it's reserved for
    /// future dynamic stores that can classify token shapes.
    #[error("session token is malformed or otherwise invalid")]
    InvalidToken,

    /// Resolver store failure (I/O, corruption). Verifier maps this to
    /// `InternalError`.
    #[error("internal credential store error: {0}")]
    Internal(String),
}

/// Inbound credential lookup.
///
/// Implementations look up a credential by `(access_key_id, session_token)`:
///
/// - `session_token: None` matches only no-token entries.
/// - `session_token: Some(t)` matches only entries whose `session_token` is
///   equal to `t` (byte-for-byte; the static resolver uses
///   `subtle::ConstantTimeEq`).
///
/// Returning `Ok(None)` means "no such credential" — the verifier surfaces
/// this as `InvalidAccessKeyId` so the response never leaks whether the key
/// exists in another token namespace.
///
/// `now` is supplied by the caller (not read from `Utc::now()` inside the
/// resolver) so expiry checks are deterministic in verifier tests.
pub trait InboundCredentialResolver: Send + Sync {
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: DateTime<Utc>,
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
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

/// Static credentials store backed by a single JSON file. The file is read
/// once at startup; reloads require restarting the proxy.
///
/// The physical map is keyed only by `access_key_id` — the bucket holds
/// every credential sharing that key (typically one no-token + zero or
/// more token-bearing entries). Lookup narrows on the access key, then
/// constant-time compares the candidate `session_token`s, so the token
/// itself is never used as a `HashMap` key (which would defeat the
/// constant-time compare).
pub struct StaticInboundCredentials {
    by_access_key_id: HashMap<Arc<str>, Vec<Arc<InboundCredential>>>,
    len: usize,
}

impl std::fmt::Debug for StaticInboundCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show only the count, never any key material.
        write!(f, "StaticInboundCredentials({} credentials)", self.len)
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

        if parsed.version != 1 && parsed.version != 2 {
            return Err(StaticCredentialsLoadError::Validation {
                path: path.to_path_buf(),
                reason: format!(
                    "unsupported credentials file version {} (expected 1 or 2)",
                    parsed.version
                ),
            });
        }
        let version = parsed.version;

        if parsed.credentials.is_empty() {
            return Err(StaticCredentialsLoadError::Validation {
                path: path.to_path_buf(),
                reason: "credentials array is empty; at least one entry is required".to_string(),
            });
        }

        let mut by_access_key_id: HashMap<Arc<str>, Vec<Arc<InboundCredential>>> = HashMap::new();
        let mut total = 0usize;

        for entry in parsed.credentials {
            let access_key_id = entry.access_key_id;
            let secret_access_key = entry.secret_access_key;
            let session_token = entry.session_token;
            let expires_at = entry.expires_at;

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

            // v1 must not carry STS-only fields.
            if version == 1 && (session_token.is_some() || expires_at.is_some()) {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: format!(
                        "credentials file version 1 does not support session_token / expires_at \
                         (offending entry: {access_key_id}); use version 2"
                    ),
                });
            }

            // STS credentials always expire. Accepting `session_token`
            // without `expires_at` would silently turn temporary credentials
            // into long-lived ones.
            if session_token.is_some() && expires_at.is_none() {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: format!("session_token requires expires_at on entry {access_key_id}"),
                });
            }

            if let Some(ref token) = session_token
                && token.is_empty()
            {
                return Err(StaticCredentialsLoadError::Validation {
                    path: path.to_path_buf(),
                    reason: format!("empty session_token for {access_key_id}"),
                });
            }

            let akid_arc: Arc<str> = Arc::from(access_key_id.as_str());
            let bucket = by_access_key_id.entry(akid_arc.clone()).or_default();

            // Reject duplicate `(access_key_id, session_token)` tuples. We
            // compare with `ConstantTimeEq` even at load time so we don't
            // leak token content via side-channels in the (rare) misconfig
            // case where a future tool emits two entries with the same
            // token; and so the duplicate-detection path stays consistent
            // with the lookup path.
            for existing in bucket.iter() {
                match (existing.session_token.as_ref(), session_token.as_ref()) {
                    (None, None) => {
                        return Err(StaticCredentialsLoadError::Validation {
                            path: path.to_path_buf(),
                            reason: format!("duplicate access_key_id: {access_key_id}"),
                        });
                    }
                    (Some(a), Some(b))
                        if a.expose().as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1 =>
                    {
                        return Err(StaticCredentialsLoadError::Validation {
                            path: path.to_path_buf(),
                            reason: format!(
                                "duplicate (access_key_id, session_token) for {access_key_id}"
                            ),
                        });
                    }
                    _ => {}
                }
            }

            let cred = InboundCredential {
                access_key_id: akid_arc.clone(),
                secret_access_key: InboundSecret::new(secret_access_key),
                session_token: session_token.map(SessionToken::new),
                expires_at,
            };
            bucket.push(Arc::new(cred));
            total += 1;
        }

        Ok(Self {
            by_access_key_id,
            len: total,
        })
    }

    /// Total number of credentials loaded (not the number of distinct
    /// access-key ids). Useful for startup logging.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl InboundCredentialResolver for StaticInboundCredentials {
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<Arc<InboundCredential>>, CredentialResolveError> {
        let Some(bucket) = self.by_access_key_id.get(access_key_id) else {
            return Ok(None);
        };

        let matched = match session_token {
            None => bucket.iter().find(|c| c.session_token.is_none()),
            Some(t) => bucket.iter().find(|c| match c.session_token.as_ref() {
                Some(stored) => stored.expose().as_bytes().ct_eq(t.as_bytes()).unwrap_u8() == 1,
                None => false,
            }),
        };

        let Some(cred) = matched else {
            return Ok(None);
        };

        if let Some(expires_at) = cred.expires_at
            && now >= expires_at
        {
            return Err(CredentialResolveError::Expired { expires_at });
        }

        Ok(Some(cred.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_file(contents: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap()
    }

    #[test]
    fn test_loads_valid_v1_file() {
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

        let a = store
            .resolve("client-a", None, now())
            .unwrap()
            .expect("client-a");
        assert_eq!(&*a.access_key_id, "client-a");
        assert_eq!(a.secret_access_key.expose(), "secret-a");
        assert!(a.session_token.is_none());
        assert!(a.expires_at.is_none());

        let b = store
            .resolve("client-b", None, now())
            .unwrap()
            .expect("client-b");
        assert_eq!(b.secret_access_key.expose(), "secret-b");

        assert!(store.resolve("client-c", None, now()).unwrap().is_none());
    }

    #[test]
    fn test_v1_rejects_session_token_field() {
        // v1 must not silently accept STS-only fields — otherwise an
        // operator who upgrades a v1 deployment to add token-bearing
        // entries without bumping `version` would get long-lived
        // credentials that the resolver would never enforce expiry on.
        let f = write_file(
            r#"{
              "version": 1,
              "credentials": [
                {
                  "access_key_id": "a",
                  "secret_access_key": "s",
                  "session_token": "t",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("v1 + session_token must error");
        assert!(matches!(err, StaticCredentialsLoadError::Validation { .. }));
    }

    #[test]
    fn test_loads_valid_v2_file_with_mixed_entries() {
        // Both shapes must coexist: a v1-style long-lived entry alongside
        // a v2 token-bearing one. Lookups land in disjoint namespaces.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                { "access_key_id": "long", "secret_access_key": "long-secret" },
                {
                  "access_key_id": "temp",
                  "secret_access_key": "temp-secret",
                  "session_token": "tok-xyz",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        assert_eq!(store.len(), 2);

        let long = store
            .resolve("long", None, now())
            .unwrap()
            .expect("long resolves");
        assert!(long.session_token.is_none());

        let temp = store
            .resolve("temp", Some("tok-xyz"), now())
            .unwrap()
            .expect("temp resolves");
        assert_eq!(temp.secret_access_key.expose(), "temp-secret");
        assert_eq!(temp.session_token.as_ref().unwrap().expose(), "tok-xyz");
    }

    #[test]
    fn test_v2_session_token_requires_expires_at() {
        // STS credentials always expire — accepting `session_token` without
        // `expires_at` would silently turn temporary credentials into
        // long-lived ones, defeating the entire point of STS.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "a",
                  "secret_access_key": "s",
                  "session_token": "t"
                }
              ]
            }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("session_token without expires_at must error");
        match err {
            StaticCredentialsLoadError::Validation { reason, .. } => {
                assert!(reason.contains("expires_at"), "got: {reason}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_v2_no_token_namespace_separation() {
        // Removing the `c.session_token.is_none()` predicate in `resolve`
        // for the `None` branch would let a no-token lookup match a
        // token-bearing entry, silently elevating an unauthenticated
        // request to STS authority. This test pins that separation.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "shared",
                  "secret_access_key": "stem-secret",
                  "session_token": "tok",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        // Bare-key lookup must not match the token-bearing entry.
        assert!(store.resolve("shared", None, now()).unwrap().is_none());
        // And with the right token it does match.
        assert!(
            store
                .resolve("shared", Some("tok"), now())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_v2_token_lookup_does_not_match_no_token_entry() {
        // Mirror of the previous test in the other direction: a request
        // that carries a session token must not be served by a long-lived
        // (no-token) credential.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                { "access_key_id": "shared", "secret_access_key": "stem-secret" }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        assert!(
            store
                .resolve("shared", Some("any-token"), now())
                .unwrap()
                .is_none()
        );
        // Bare-key still resolves.
        assert!(store.resolve("shared", None, now()).unwrap().is_some());
    }

    #[test]
    fn test_v2_same_access_key_with_both_namespaces_accepted() {
        // A long-lived credential and an STS-issued credential sharing the
        // same access-key id occupy disjoint namespaces and must both
        // load. The bucket holds both, and lookup picks the matching one.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                { "access_key_id": "shared", "secret_access_key": "long" },
                {
                  "access_key_id": "shared",
                  "secret_access_key": "temp",
                  "session_token": "tok",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        assert_eq!(store.len(), 2);
        let long = store.resolve("shared", None, now()).unwrap().unwrap();
        assert_eq!(long.secret_access_key.expose(), "long");
        let temp = store
            .resolve("shared", Some("tok"), now())
            .unwrap()
            .unwrap();
        assert_eq!(temp.secret_access_key.expose(), "temp");
    }

    #[test]
    fn test_v2_duplicate_no_token_tuple_rejected() {
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                { "access_key_id": "dup", "secret_access_key": "s1" },
                { "access_key_id": "dup", "secret_access_key": "s2" }
              ]
            }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("duplicate no-token must error");
        match err {
            StaticCredentialsLoadError::Validation { reason, .. } => {
                assert!(reason.contains("duplicate"), "got: {reason}");
            }
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    fn test_v2_duplicate_token_tuple_rejected_without_logging_token() {
        // Whatever the load error says, it MUST NOT echo the session
        // token. Tokens are bearer credentials — if a config error path
        // logs them, they'll land in process logs and be readable by
        // anyone with log access.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "shared",
                  "secret_access_key": "s",
                  "session_token": "super-secret-token-do-not-log",
                  "expires_at": "2026-05-14T18:30:00Z"
                },
                {
                  "access_key_id": "shared",
                  "secret_access_key": "s",
                  "session_token": "super-secret-token-do-not-log",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("duplicate token tuple must error");
        let reason = match err {
            StaticCredentialsLoadError::Validation { reason, .. } => reason,
            other => panic!("expected Validation, got {other:?}"),
        };
        assert!(
            !reason.contains("super-secret-token-do-not-log"),
            "validation message leaked token: {reason}"
        );
    }

    #[test]
    fn test_v2_expired_token_credential_returns_expired() {
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "temp",
                  "secret_access_key": "s",
                  "session_token": "tok",
                  "expires_at": "2025-01-01T00:00:00Z"
                }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        let err = store
            .resolve("temp", Some("tok"), now())
            .expect_err("expired must surface as Err");
        assert!(matches!(err, CredentialResolveError::Expired { .. }));
    }

    #[test]
    fn test_v2_expires_at_on_no_token_credential_is_enforced() {
        // Optional `expires_at` on a no-token entry must still be honoured
        // — useful for planned key retirement. Without that branch the
        // long-lived credential would survive past its retirement date.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "retiring",
                  "secret_access_key": "s",
                  "expires_at": "2025-01-01T00:00:00Z"
                }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        let err = store
            .resolve("retiring", None, now())
            .expect_err("expired no-token entry must surface as Err");
        assert!(matches!(err, CredentialResolveError::Expired { .. }));
    }

    #[test]
    fn test_v2_empty_session_token_rejected_at_load() {
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "a",
                  "secret_access_key": "s",
                  "session_token": "",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let err =
            StaticInboundCredentials::load_from_file(f.path()).expect_err("empty token must error");
        assert!(matches!(err, StaticCredentialsLoadError::Validation { .. }));
    }

    #[test]
    fn test_v2_tokens_with_special_bytes_resolve_byte_identically() {
        // Real STS tokens contain `+`, `/`, `=` (they're base64-flavored).
        // The resolver must treat them as opaque byte strings — no form
        // decoding, no trimming, no case folding. Replacing the
        // `ct_eq(...)` byte compare with `eq_ignore_ascii_case` would
        // make `tok+/==` accept `TOK+/==` and break this test.
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "a",
                  "secret_access_key": "s",
                  "session_token": "abc+def/ghi==",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        assert!(
            store
                .resolve("a", Some("abc+def/ghi=="), now())
                .unwrap()
                .is_some()
        );
        // Anything else is a miss, not a loose match.
        assert!(
            store
                .resolve("a", Some("abc+def/ghi="), now())
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .resolve("a", Some("ABC+DEF/GHI=="), now())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_v2_mismatched_token_returns_none() {
        let f = write_file(
            r#"{
              "version": 2,
              "credentials": [
                {
                  "access_key_id": "a",
                  "secret_access_key": "s",
                  "session_token": "right",
                  "expires_at": "2026-05-14T18:30:00Z"
                }
              ]
            }"#,
        );
        let store = StaticInboundCredentials::load_from_file(f.path()).expect("loads");
        assert!(store.resolve("a", Some("wrong"), now()).unwrap().is_none());
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
            r#"{ "version": 3, "credentials": [{ "access_key_id": "a", "secret_access_key": "b" }] }"#,
        );
        let err = StaticInboundCredentials::load_from_file(f.path())
            .expect_err("version!=1,2 must error");
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
    fn test_v1_rejects_duplicate_access_key_id() {
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

    #[test]
    fn test_session_token_debug_does_not_leak_value() {
        let t = SessionToken::new("super-secret-token".to_string());
        let dbg = format!("{t:?}");
        assert!(
            !dbg.contains("super-secret-token"),
            "SessionToken Debug leaked plaintext: {dbg}"
        );
        assert!(dbg.contains("bytes"), "Debug should hint at length: {dbg}");
    }
}
