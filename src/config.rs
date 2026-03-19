use std::env;
use thiserror::Error;

/// Errors that can occur when loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("required environment variable {name} is not set")]
    MissingRequired { name: String },

    #[error("failed to parse environment variable {name}: {reason}")]
    ParseError { name: String, reason: String },
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
    pub cache_dir: String,
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
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
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
            cache_dir: get_env_or_default("CACHE_DIR", "/cache"),
            cache_max_bytes: parse_u64_env("CACHE_MAX_BYTES", 10_737_418_240)?,
            cache_max_object_bytes: parse_u64_env("CACHE_MAX_OBJECT_BYTES", 536_870_912)?,
            cacheable_prefixes: {
                let raw =
                    get_env_or_default("CACHEABLE_PREFIXES", "script_bundle/,bun_bundle/,tar/");
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            },
            cache_serve_stale_on_error: parse_bool_env("CACHE_SERVE_STALE_ON_ERROR", true)?,
            cache_eviction_interval_secs: parse_u64_env("CACHE_EVICTION_INTERVAL_SECS", 300)?,

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
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env var tests must run serially since they modify process-global state.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// All environment variable names that Config::from_env() reads.
    const ALL_CONFIG_VARS: &[&str] = &[
        "S3_LISTEN_ADDR", "ADMIN_LISTEN_ADDR", "FRONTEND_BUCKET",
        "AUTH_MODE", "ALLOWED_FRONTEND_KEYS",
        "BACKEND_ENDPOINT", "BACKEND_REGION", "BACKEND_BUCKET",
        "BACKEND_ACCESS_KEY_ID", "BACKEND_SECRET_ACCESS_KEY",
        "BACKEND_USE_PATH_STYLE", "BACKEND_ALLOW_HTTP",
        "CACHE_DIR", "CACHE_MAX_BYTES", "CACHE_MAX_OBJECT_BYTES",
        "CACHEABLE_PREFIXES", "CACHE_SERVE_STALE_ON_ERROR",
        "CACHE_EVICTION_INTERVAL_SECS",
        "GET_MAX_ATTEMPTS", "HEAD_MAX_ATTEMPTS", "LIST_MAX_ATTEMPTS",
        "PUT_MAX_ATTEMPTS", "DELETE_MAX_ATTEMPTS", "RETRY_BASE_BACKOFF_MS",
        "UPSTREAM_CONNECT_TIMEOUT_MS", "UPSTREAM_REQUEST_TIMEOUT_MS",
        "MAX_REQUEST_BODY_BYTES",
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

            assert_eq!(config.cache_dir, "/cache");
            assert_eq!(config.cache_max_bytes, 10_737_418_240);
            assert_eq!(config.cache_max_object_bytes, 536_870_912);
            assert_eq!(
                config.cacheable_prefixes,
                vec!["script_bundle/", "bun_bundle/", "tar/"]
            );
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
}
