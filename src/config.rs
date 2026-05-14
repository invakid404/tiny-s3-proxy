use std::env;
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur when loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable {name} is not set")]
    MissingRequired { name: String },

    #[error("failed to parse environment variable {name}: {reason}")]
    ParseError { name: String, reason: String },

    #[error("configuration validation error: {reason}")]
    ValidationError { reason: String },
}

/// Authentication mode for inbound S3 requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMode {
    /// Trust all requests (for internal/VPC deployments).
    TrustedInternal,
    /// Validate the access key ID against an allowlist.
    AccessKeyAllowlist,
}

/// Top-level configuration parsed from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    // Frontend
    pub s3_listen_addr: String,
    pub admin_listen_addr: String,
    pub frontend_bucket: String,
    pub auth_mode: AuthMode,
    pub allowed_frontend_keys: Vec<String>,

    // Backend
    pub backend_endpoint: String,
    pub backend_region: String,
    pub backend_bucket: String,
    pub backend_access_key_id: String,
    pub backend_secret_access_key: String,
    pub backend_use_path_style: bool,
    pub backend_allow_http: bool,

    // Cache
    pub cache_dir: PathBuf,
    pub cache_max_bytes: u64,
    pub cache_max_object_bytes: u64,
    pub cacheable_prefixes: Vec<String>,
    pub cache_serve_stale_on_error: bool,
    pub cache_eviction_interval_secs: u64,

    // Retry
    pub get_max_attempts: u32,
    pub head_max_attempts: u32,
    pub list_max_attempts: u32,
    pub put_max_attempts: u32,
    pub delete_max_attempts: u32,
    pub retry_base_backoff_ms: u64,
    pub upstream_connect_timeout_ms: u64,
    pub upstream_request_timeout_ms: u64,
    pub max_request_body_bytes: u64,
    pub passthrough_unsigned_payload: bool,

    // Inbound SigV4 verification (strict mode). When `inbound_auth_verify_signatures`
    // is true, normal requests are required to carry a valid SigV4
    // `Authorization` header or a presigned-URL `X-Amz-*` query signature
    // backed by one of the credentials in `inbound_credentials_path`. STS,
    // SigV4A, and presigned-aws-chunked flows remain fail-closed in this
    // mode (rejected up front; tracked in follow-up PRs of issue #63).
    pub inbound_auth_verify_signatures: bool,
    pub inbound_credentials_path: Option<PathBuf>,
    pub inbound_auth_max_skew_secs: u64,
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let config = Self {
            // Frontend
            s3_listen_addr: get_env_or_default("S3_LISTEN_ADDR", "0.0.0.0:8080"),
            admin_listen_addr: get_env_or_default("ADMIN_LISTEN_ADDR", "0.0.0.0:9090"),
            frontend_bucket: get_env_required("FRONTEND_BUCKET")?,
            auth_mode: parse_auth_mode(&get_env_or_default("AUTH_MODE", "trusted_internal"))?,
            allowed_frontend_keys: get_env_comma_separated("ALLOWED_FRONTEND_KEYS"),

            // Backend
            backend_endpoint: get_env_required("BACKEND_ENDPOINT")?,
            backend_region: get_env_or_default("BACKEND_REGION", "auto"),
            backend_bucket: get_env_required("BACKEND_BUCKET")?,
            backend_access_key_id: get_env_required("BACKEND_ACCESS_KEY_ID")?,
            backend_secret_access_key: get_env_required("BACKEND_SECRET_ACCESS_KEY")?,
            backend_use_path_style: parse_bool_env("BACKEND_USE_PATH_STYLE", true)?,
            backend_allow_http: parse_bool_env("BACKEND_ALLOW_HTTP", false)?,

            // Cache
            cache_dir: PathBuf::from(get_env_or_default("CACHE_DIR", "/cache")),
            cache_max_bytes: parse_u64_env("CACHE_MAX_BYTES", 10_737_418_240)?,
            cache_max_object_bytes: parse_u64_env("CACHE_MAX_OBJECT_BYTES", 536_870_912)?,
            cacheable_prefixes: {
                let raw = get_env_or_default("CACHEABLE_PREFIXES", "");
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            },
            cache_serve_stale_on_error: parse_bool_env("CACHE_SERVE_STALE_ON_ERROR", true)?,
            cache_eviction_interval_secs: parse_u64_env("CACHE_EVICTION_INTERVAL_SECS", 300)?
                .max(10),

            // Retry
            get_max_attempts: parse_u32_env("GET_MAX_ATTEMPTS", 3)?,
            head_max_attempts: parse_u32_env("HEAD_MAX_ATTEMPTS", 3)?,
            list_max_attempts: parse_u32_env("LIST_MAX_ATTEMPTS", 3)?,
            put_max_attempts: parse_u32_env("PUT_MAX_ATTEMPTS", 1)?,
            delete_max_attempts: parse_u32_env("DELETE_MAX_ATTEMPTS", 2)?,
            retry_base_backoff_ms: parse_u64_env("RETRY_BASE_BACKOFF_MS", 100)?,
            upstream_connect_timeout_ms: parse_u64_env("UPSTREAM_CONNECT_TIMEOUT_MS", 5000)?,
            upstream_request_timeout_ms: parse_u64_env("UPSTREAM_REQUEST_TIMEOUT_MS", 30000)?,
            max_request_body_bytes: parse_u64_env("MAX_REQUEST_BODY_BYTES", 268_435_456)?, // 256 MiB default
            passthrough_unsigned_payload: parse_bool_env("PASSTHROUGH_UNSIGNED_PAYLOAD", false)?,

            inbound_auth_verify_signatures: parse_bool_env(
                "INBOUND_AUTH_VERIFY_SIGNATURES",
                false,
            )?,
            inbound_credentials_path: env::var("INBOUND_CREDENTIALS_PATH")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            inbound_auth_max_skew_secs: parse_u64_env("INBOUND_AUTH_MAX_SKEW_SECS", 900)?,
        };

        // The AccessKeyAllowlist mode requires a non-empty key list — without
        // one every request would be rejected. Strict SigV4 verification
        // replaces that gate entirely (the resolver IS the allowlist), so the
        // empty-keys check is skipped when strict mode is on.
        if config.auth_mode == AuthMode::AccessKeyAllowlist
            && config.allowed_frontend_keys.is_empty()
            && !config.inbound_auth_verify_signatures
        {
            return Err(ConfigError::ValidationError {
                reason: "AUTH_MODE is access_key_allowlist but ALLOWED_FRONTEND_KEYS is empty or not set; all requests would be rejected".to_string(),
            });
        }

        // Strict mode REQUIRES a credentials file; without it the resolver has
        // no keys to validate against, so every request would be rejected.
        if config.inbound_auth_verify_signatures && config.inbound_credentials_path.is_none() {
            return Err(ConfigError::ValidationError {
                reason: "INBOUND_AUTH_VERIFY_SIGNATURES=true requires INBOUND_CREDENTIALS_PATH \
                         to point at a credentials JSON file"
                    .to_string(),
            });
        }

        // If strict mode is on and a credentials path is set, the file must
        // exist at startup. We deliberately catch this here rather than at
        // first request: a missing file would otherwise fail every request
        // long after deployment instead of failing the rollout.
        if let Some(ref path) = config.inbound_credentials_path
            && config.inbound_auth_verify_signatures
            && !path.exists()
        {
            return Err(ConfigError::ValidationError {
                reason: format!(
                    "INBOUND_CREDENTIALS_PATH does not exist: {}",
                    path.display()
                ),
            });
        }

        // Reject URL-embedded credentials in BACKEND_ENDPOINT at config load.
        // Credentials belong in BACKEND_ACCESS_KEY_ID / BACKEND_SECRET_ACCESS_KEY;
        // if userinfo reaches the SDK, request errors can format the endpoint
        // into log strings and leak `user:pass@host` at runtime. Source-side
        // rejection closes that class of leak at the boundary. The error
        // intentionally does not echo the endpoint, host, or userinfo.
        if endpoint_has_userinfo(&config.backend_endpoint) {
            return Err(ConfigError::ValidationError {
                reason: "BACKEND_ENDPOINT must not include URL userinfo; configure \
                         backend credentials with BACKEND_ACCESS_KEY_ID and \
                         BACKEND_SECRET_ACCESS_KEY instead"
                    .to_string(),
            });
        }

        // UNSIGNED-PAYLOAD relies entirely on transport security (TLS) for
        // body integrity. With an HTTP backend, request bodies would be sent
        // both unsigned and unencrypted, so a network attacker could tamper
        // with them without detection. Reject this combination at startup
        // rather than allow a silent-downgrade misconfiguration. Note that
        // we inspect the actual scheme of BACKEND_ENDPOINT, not BACKEND_ALLOW_HTTP
        // (which only grants permission to use HTTP, regardless of whether
        // the configured endpoint actually does).
        if config.passthrough_unsigned_payload
            && endpoint_scheme(&config.backend_endpoint).eq_ignore_ascii_case("http")
        {
            return Err(ConfigError::ValidationError {
                reason: format!(
                    "PASSTHROUGH_UNSIGNED_PAYLOAD=true requires BACKEND_ENDPOINT to use https \
                     for body integrity; got scheme \"{}\". UNSIGNED-PAYLOAD relies on transport \
                     security to protect request bodies — over plaintext, an attacker on the \
                     network path could tamper with bodies undetected.",
                    endpoint_scheme(&config.backend_endpoint),
                ),
            });
        }

        Ok(config)
    }
}

fn get_env_required(name: &str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::MissingRequired {
        name: name.to_string(),
    })
}

fn get_env_or_default(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn get_env_comma_separated(name: &str) -> Vec<String> {
    env::var(name)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_auth_mode(value: &str) -> Result<AuthMode, ConfigError> {
    match value {
        "trusted_internal" => Ok(AuthMode::TrustedInternal),
        "access_key_allowlist" => Ok(AuthMode::AccessKeyAllowlist),
        other => Err(ConfigError::ParseError {
            name: "AUTH_MODE".to_string(),
            reason: format!(
                "unknown auth mode '{}', expected 'trusted_internal' or 'access_key_allowlist'",
                other
            ),
        }),
    }
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool, ConfigError> {
    match env::var(name) {
        Ok(val) => match val.to_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            other => Err(ConfigError::ParseError {
                name: name.to_string(),
                reason: format!("'{}' is not a valid boolean", other),
            }),
        },
        Err(_) => Ok(default),
    }
}

fn parse_u64_env(name: &str, default: u64) -> Result<u64, ConfigError> {
    match env::var(name) {
        Ok(val) => val.parse::<u64>().map_err(|e| ConfigError::ParseError {
            name: name.to_string(),
            reason: e.to_string(),
        }),
        Err(_) => Ok(default),
    }
}

fn parse_u32_env(name: &str, default: u32) -> Result<u32, ConfigError> {
    match env::var(name) {
        Ok(val) => val.parse::<u32>().map_err(|e| ConfigError::ParseError {
            name: name.to_string(),
            reason: e.to_string(),
        }),
        Err(_) => Ok(default),
    }
}

/// Extract the URL scheme from an endpoint string (the part before "://"),
/// or an empty string if no scheme is present. Used by both config validation
/// and backend client construction so they agree on what counts as HTTP.
pub fn endpoint_scheme(endpoint: &str) -> &str {
    endpoint.split_once("://").map(|(s, _)| s).unwrap_or("")
}

/// Detect whether a URL-shaped endpoint carries non-empty userinfo
/// (`user`, `user:pass`, etc. before an `@` in the authority). Mirrors the
/// authority-scanning shape of `redact_url_userinfo` so the two stay aligned
/// on what they consider userinfo. Empty userinfo (`http://@host`) is
/// degenerate and not flagged.
fn endpoint_has_userinfo(endpoint: &str) -> bool {
    let Some((_, rest)) = endpoint.split_once("://") else {
        return false;
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rsplit_once('@') {
        Some((userinfo, _)) => !userinfo.is_empty(),
        None => false,
    }
}

/// Best-effort strip of the `userinfo` (`user:pass@`) portion from a URL-shaped
/// endpoint string before it is logged. Returns the input unchanged if no
/// scheme/authority structure is detected, so callers can pass arbitrary
/// strings without losing them. The original endpoint must still be used for
/// SDK / request construction — only log output should consume the redacted
/// form.
pub fn redact_url_userinfo(endpoint: &str) -> String {
    let Some((scheme, rest)) = endpoint.split_once("://") else {
        return endpoint.to_string();
    };

    if scheme.is_empty() {
        return endpoint.to_string();
    }

    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_end);

    let Some((_, host_and_port)) = authority.rsplit_once('@') else {
        return endpoint.to_string();
    };

    format!("{scheme}://{host_and_port}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env var tests must run serially since they modify process-global state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// All environment variable names that Config::from_env() reads.
    const ALL_CONFIG_VARS: &[&str] = &[
        "S3_LISTEN_ADDR",
        "ADMIN_LISTEN_ADDR",
        "FRONTEND_BUCKET",
        "AUTH_MODE",
        "ALLOWED_FRONTEND_KEYS",
        "BACKEND_ENDPOINT",
        "BACKEND_REGION",
        "BACKEND_BUCKET",
        "BACKEND_ACCESS_KEY_ID",
        "BACKEND_SECRET_ACCESS_KEY",
        "BACKEND_USE_PATH_STYLE",
        "BACKEND_ALLOW_HTTP",
        "CACHE_DIR",
        "CACHE_MAX_BYTES",
        "CACHE_MAX_OBJECT_BYTES",
        "CACHEABLE_PREFIXES",
        "CACHE_SERVE_STALE_ON_ERROR",
        "CACHE_EVICTION_INTERVAL_SECS",
        "GET_MAX_ATTEMPTS",
        "HEAD_MAX_ATTEMPTS",
        "LIST_MAX_ATTEMPTS",
        "PUT_MAX_ATTEMPTS",
        "DELETE_MAX_ATTEMPTS",
        "RETRY_BASE_BACKOFF_MS",
        "UPSTREAM_CONNECT_TIMEOUT_MS",
        "UPSTREAM_REQUEST_TIMEOUT_MS",
        "MAX_REQUEST_BODY_BYTES",
        "PASSTHROUGH_UNSIGNED_PAYLOAD",
        "INBOUND_AUTH_VERIFY_SIGNATURES",
        "INBOUND_CREDENTIALS_PATH",
        "INBOUND_AUTH_MAX_SKEW_SECS",
    ];

    fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();

        // Snapshot ALL config vars (not just the ones being set), then clear
        // the full surface so tests don't depend on the outer process env.
        let originals: Vec<_> = ALL_CONFIG_VARS
            .iter()
            .map(|k| (*k, env::var(k).ok()))
            .collect();

        // SAFETY: Tests run serially under ENV_LOCK, so no other thread
        // is reading env vars concurrently.
        unsafe {
            for k in ALL_CONFIG_VARS {
                env::remove_var(k);
            }
            for (k, v) in vars {
                env::set_var(k, v);
            }
        }

        f();

        // Restore ALL originals.
        // SAFETY: Same serialization guarantee via ENV_LOCK.
        unsafe {
            for (k, original) in &originals {
                match original {
                    Some(v) => env::set_var(k, v),
                    None => env::remove_var(k),
                }
            }
        }
    }

    fn required_env_vars() -> Vec<(&'static str, &'static str)> {
        vec![
            ("FRONTEND_BUCKET", "my-frontend"),
            (
                "BACKEND_ENDPOINT",
                "https://example.r2.cloudflarestorage.com",
            ),
            ("BACKEND_BUCKET", "my-backend"),
            ("BACKEND_ACCESS_KEY_ID", "AKID123"),
            ("BACKEND_SECRET_ACCESS_KEY", "secret456"),
        ]
    }

    #[test]
    fn test_defaults_with_required_vars() {
        with_env_vars(&required_env_vars(), || {
            let config = Config::from_env().expect("should parse");

            assert_eq!(config.s3_listen_addr, "0.0.0.0:8080");
            assert_eq!(config.admin_listen_addr, "0.0.0.0:9090");
            assert_eq!(config.auth_mode, AuthMode::TrustedInternal);
            assert!(config.allowed_frontend_keys.is_empty());

            assert_eq!(config.backend_region, "auto");
            assert!(config.backend_use_path_style);
            assert!(!config.backend_allow_http);

            assert_eq!(config.cache_dir, PathBuf::from("/cache"));
            assert_eq!(config.cache_max_bytes, 10_737_418_240);
            assert_eq!(config.cache_max_object_bytes, 536_870_912);
            assert!(config.cacheable_prefixes.is_empty());
            assert!(config.cache_serve_stale_on_error);
            assert_eq!(config.cache_eviction_interval_secs, 300);

            assert_eq!(config.get_max_attempts, 3);
            assert_eq!(config.head_max_attempts, 3);
            assert_eq!(config.list_max_attempts, 3);
            assert_eq!(config.put_max_attempts, 1);
            assert_eq!(config.delete_max_attempts, 2);
            assert_eq!(config.retry_base_backoff_ms, 100);
            assert_eq!(config.upstream_connect_timeout_ms, 5000);
            assert_eq!(config.upstream_request_timeout_ms, 30000);
            assert!(!config.passthrough_unsigned_payload);
        });
    }

    #[test]
    fn test_missing_frontend_bucket() {
        with_env_vars(&[], || {
            // Clear required vars to ensure they're missing.
            let _guard = (); // ENV_LOCK already held by with_env_vars
            let result = Config::from_env();
            assert!(result.is_err());
            let err = result.unwrap_err();
            match err {
                ConfigError::MissingRequired { name } => {
                    assert_eq!(name, "FRONTEND_BUCKET");
                }
                other => panic!("expected MissingRequired, got: {:?}", other),
            }
        });
    }

    #[test]
    fn test_missing_backend_endpoint() {
        with_env_vars(&[("FRONTEND_BUCKET", "b")], || {
            let result = Config::from_env();
            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::MissingRequired { name } => {
                    assert_eq!(name, "BACKEND_ENDPOINT");
                }
                other => panic!("expected MissingRequired, got: {:?}", other),
            }
        });
    }

    #[test]
    fn test_invalid_auth_mode() {
        let mut vars = required_env_vars();
        vars.push(("AUTH_MODE", "bogus"));
        with_env_vars(&vars, || {
            let result = Config::from_env();
            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::ParseError { name, .. } => {
                    assert_eq!(name, "AUTH_MODE");
                }
                other => panic!("expected ParseError, got: {:?}", other),
            }
        });
    }

    #[test]
    fn test_access_key_allowlist_mode() {
        let mut vars = required_env_vars();
        vars.push(("AUTH_MODE", "access_key_allowlist"));
        vars.push(("ALLOWED_FRONTEND_KEYS", "key1,key2, key3"));
        with_env_vars(&vars, || {
            let config = Config::from_env().expect("should parse");
            assert_eq!(config.auth_mode, AuthMode::AccessKeyAllowlist);
            assert_eq!(config.allowed_frontend_keys, vec!["key1", "key2", "key3"]);
        });
    }

    #[test]
    fn test_custom_cache_values() {
        let mut vars = required_env_vars();
        vars.push(("CACHE_MAX_BYTES", "1024"));
        vars.push(("CACHE_MAX_OBJECT_BYTES", "256"));
        vars.push(("CACHEABLE_PREFIXES", "foo/,bar/"));
        with_env_vars(&vars, || {
            let config = Config::from_env().expect("should parse");
            assert_eq!(config.cache_max_bytes, 1024);
            assert_eq!(config.cache_max_object_bytes, 256);
            assert_eq!(config.cacheable_prefixes, vec!["foo/", "bar/"]);
        });
    }

    #[test]
    fn test_invalid_u64_value() {
        let mut vars = required_env_vars();
        vars.push(("CACHE_MAX_BYTES", "not_a_number"));
        with_env_vars(&vars, || {
            let result = Config::from_env();
            assert!(result.is_err());
            match result.unwrap_err() {
                ConfigError::ParseError { name, .. } => {
                    assert_eq!(name, "CACHE_MAX_BYTES");
                }
                other => panic!("expected ParseError, got: {:?}", other),
            }
        });
    }

    #[test]
    fn test_bool_parsing() {
        let mut vars = required_env_vars();
        vars.push(("BACKEND_USE_PATH_STYLE", "false"));
        vars.push(("BACKEND_ALLOW_HTTP", "true"));
        with_env_vars(&vars, || {
            let config = Config::from_env().expect("should parse");
            assert!(!config.backend_use_path_style);
            assert!(config.backend_allow_http);
        });
    }

    #[test]
    fn test_unsigned_payload_with_http_backend_rejected() {
        let mut vars = required_env_vars();
        // Override the default https endpoint with a plain http one. The
        // validation message must NOT echo the raw endpoint or its host —
        // Config::from_env errors are surfaced via .expect() in main.rs,
        // so anything in the message lands in process logs.
        vars.retain(|(k, _)| *k != "BACKEND_ENDPOINT");
        vars.push(("BACKEND_ENDPOINT", "http://insecure.example"));
        vars.push(("BACKEND_ALLOW_HTTP", "true"));
        vars.push(("PASSTHROUGH_UNSIGNED_PAYLOAD", "true"));
        with_env_vars(&vars, || {
            let result = Config::from_env();
            match result {
                Err(ConfigError::ValidationError { reason }) => {
                    assert!(
                        reason.contains("PASSTHROUGH_UNSIGNED_PAYLOAD"),
                        "reason should cite the env var: {reason}"
                    );
                    assert!(
                        reason.contains("BACKEND_ENDPOINT"),
                        "reason should cite BACKEND_ENDPOINT: {reason}"
                    );
                    assert!(
                        !reason.contains("http://insecure.example"),
                        "reason must not echo the raw endpoint: {reason}"
                    );
                    assert!(
                        !reason.contains("insecure.example"),
                        "reason must not echo the host portion of the endpoint: {reason}"
                    );
                }
                other => panic!("expected ValidationError, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_backend_endpoint_with_userinfo_rejected() {
        let mut vars = required_env_vars();
        vars.retain(|(k, _)| *k != "BACKEND_ENDPOINT");
        vars.push((
            "BACKEND_ENDPOINT",
            "https://alice:supersecret@s3.example.com:9443/root",
        ));
        with_env_vars(&vars, || {
            let err =
                Config::from_env().expect_err("expected ValidationError for endpoint userinfo");
            let reason = match err {
                ConfigError::ValidationError { reason } => reason,
                other => panic!("expected ValidationError, got {other:?}"),
            };

            // Positive: error message references the relevant env vars.
            assert!(reason.contains("BACKEND_ENDPOINT"));
            assert!(reason.contains("BACKEND_ACCESS_KEY_ID"));
            assert!(reason.contains("BACKEND_SECRET_ACCESS_KEY"));

            // Negative: error does NOT leak userinfo or the raw URL.
            assert!(!reason.contains("alice"));
            assert!(!reason.contains("supersecret"));
            assert!(!reason.contains("https://alice"));
            // Also catches partial redaction that strips userinfo but leaks host.
            assert!(!reason.contains("s3.example.com"));
        });
    }

    #[test]
    fn test_unsigned_payload_with_https_backend_accepted() {
        let mut vars = required_env_vars();
        // required_env_vars already uses https; just opt into unsigned payload.
        vars.push(("PASSTHROUGH_UNSIGNED_PAYLOAD", "true"));
        with_env_vars(&vars, || {
            let config = Config::from_env().expect("https + unsigned should parse");
            assert!(config.passthrough_unsigned_payload);
        });
    }

    // ── redact_url_userinfo tests ───────────────────────────────────
    //
    // The helper is deliberately best-effort: it does not parse the URL,
    // it just lops off everything between the scheme separator and the last
    // `@` in the authority. These cases pin the behaviors we rely on for
    // log redaction.

    #[test]
    fn test_redact_url_userinfo_strips_credentials() {
        assert_eq!(
            redact_url_userinfo("https://user:pass@example.com:9000/root"),
            "https://example.com:9000/root"
        );
    }

    #[test]
    fn test_redact_url_userinfo_handles_ipv6_authority() {
        assert_eq!(
            redact_url_userinfo("http://user:pass@[::1]:443/root"),
            "http://[::1]:443/root"
        );
    }

    #[test]
    fn test_redact_url_userinfo_handles_empty_userinfo() {
        assert_eq!(redact_url_userinfo("http://@host/root"), "http://host/root");
    }

    #[test]
    fn test_redact_url_userinfo_ignores_at_in_query() {
        assert_eq!(
            redact_url_userinfo("https://host/root?x=a@b"),
            "https://host/root?x=a@b"
        );
    }

    #[test]
    fn test_redact_url_userinfo_ignores_when_no_scheme() {
        assert_eq!(redact_url_userinfo("host/root@x"), "host/root@x");
    }

    #[test]
    fn test_redact_url_userinfo_passthrough_when_no_userinfo() {
        assert_eq!(
            redact_url_userinfo("https://host/root"),
            "https://host/root"
        );
    }

    #[test]
    fn test_redact_url_userinfo_handles_multiple_at_in_authority() {
        // rsplit_once redacts through the LAST `@` in the authority, so
        // even a userinfo segment that itself contains a literal `@` is
        // fully removed.
        assert_eq!(
            redact_url_userinfo("https://a@b:c@example.com/root"),
            "https://example.com/root"
        );
    }

    #[test]
    fn test_strict_inbound_defaults_off() {
        with_env_vars(&required_env_vars(), || {
            let config = Config::from_env().expect("should parse");
            assert!(!config.inbound_auth_verify_signatures);
            assert!(config.inbound_credentials_path.is_none());
            assert_eq!(config.inbound_auth_max_skew_secs, 900);
        });
    }

    #[test]
    fn test_strict_inbound_requires_credentials_path() {
        let mut vars = required_env_vars();
        vars.push(("INBOUND_AUTH_VERIFY_SIGNATURES", "true"));
        with_env_vars(&vars, || {
            let err = Config::from_env()
                .expect_err("strict mode without credentials path must fail validation");
            match err {
                ConfigError::ValidationError { reason } => {
                    assert!(reason.contains("INBOUND_AUTH_VERIFY_SIGNATURES"));
                    assert!(reason.contains("INBOUND_CREDENTIALS_PATH"));
                }
                other => panic!("expected ValidationError, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_strict_inbound_requires_existing_credentials_file() {
        let mut vars = required_env_vars();
        vars.push(("INBOUND_AUTH_VERIFY_SIGNATURES", "true"));
        vars.push((
            "INBOUND_CREDENTIALS_PATH",
            "/nonexistent/path/to/creds.json",
        ));
        with_env_vars(&vars, || {
            let err = Config::from_env()
                .expect_err("strict mode with missing creds file must fail validation");
            match err {
                ConfigError::ValidationError { reason } => {
                    assert!(reason.contains("INBOUND_CREDENTIALS_PATH"));
                    assert!(reason.contains("does not exist"));
                }
                other => panic!("expected ValidationError, got: {other:?}"),
            }
        });
    }

    #[test]
    fn test_strict_inbound_relaxes_allowlist_empty_check() {
        // Without strict mode, AccessKeyAllowlist + empty keys is fatal.
        // With strict mode, the resolver replaces the allowlist, so the
        // empty-keys validation is intentionally skipped.
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(
            &mut tmp,
            br#"{"version":1,"credentials":[{"access_key_id":"AKID","secret_access_key":"s"}]}"#,
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let mut vars = required_env_vars();
        vars.push(("AUTH_MODE", "access_key_allowlist"));
        vars.push(("INBOUND_AUTH_VERIFY_SIGNATURES", "true"));
        vars.push(("INBOUND_CREDENTIALS_PATH", &path));
        with_env_vars(&vars, || {
            let config =
                Config::from_env().expect("strict mode should bypass empty-allowlist check");
            assert!(config.inbound_auth_verify_signatures);
            assert_eq!(config.auth_mode, AuthMode::AccessKeyAllowlist);
            assert!(config.allowed_frontend_keys.is_empty());
        });
    }

    #[test]
    fn test_strict_inbound_custom_skew() {
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        std::io::Write::write_all(
            &mut tmp,
            br#"{"version":1,"credentials":[{"access_key_id":"AKID","secret_access_key":"s"}]}"#,
        )
        .unwrap();
        let path = tmp.path().to_str().unwrap().to_string();

        let mut vars = required_env_vars();
        vars.push(("INBOUND_AUTH_VERIFY_SIGNATURES", "true"));
        vars.push(("INBOUND_CREDENTIALS_PATH", &path));
        vars.push(("INBOUND_AUTH_MAX_SKEW_SECS", "60"));
        with_env_vars(&vars, || {
            let config = Config::from_env().expect("should parse");
            assert_eq!(config.inbound_auth_max_skew_secs, 60);
        });
    }

    #[test]
    fn test_unsigned_payload_off_with_http_backend_accepted() {
        // Plain HTTP is allowed when not using UNSIGNED-PAYLOAD; the validation
        // is specifically the unsigned-over-plaintext combo.
        let mut vars = required_env_vars();
        vars.retain(|(k, _)| *k != "BACKEND_ENDPOINT");
        vars.push(("BACKEND_ENDPOINT", "http://insecure.example"));
        vars.push(("BACKEND_ALLOW_HTTP", "true"));
        with_env_vars(&vars, || {
            let config = Config::from_env().expect("http + signed should parse");
            assert!(!config.passthrough_unsigned_payload);
        });
    }
}
