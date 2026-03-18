pub mod allowlist;
pub mod trusted_internal;

use crate::config::{AuthMode, Config};
use crate::error::ProxyError;
use crate::s3::ops::ParsedRequest;

/// Trait for authenticating inbound S3 requests.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, req: &ParsedRequest) -> Result<(), ProxyError>;
}

/// Create the appropriate authenticator based on configuration.
pub fn create_authenticator(config: &Config) -> Box<dyn Authenticator> {
    match config.auth_mode {
        AuthMode::TrustedInternal => Box::new(trusted_internal::TrustedInternalAuth::new()),
        AuthMode::AccessKeyAllowlist => Box::new(allowlist::AccessKeyAllowlistAuth::new(
            config.allowed_frontend_keys.clone(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};

    fn make_request() -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::GetObject {
                bucket: "b".to_string(),
                key: "k".to_string(),
            },
            request_id: "r".to_string(),
            content_type: None,
            content_length: None,
            content_md5: None,
            authorization: Some(
                "AWS4-HMAC-SHA256 Credential=TESTKEY/20240101/us-east-1/s3/aws4_request, \
                 SignedHeaders=host, Signature=abc"
                    .to_string(),
            ),
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
        }
    }

    fn test_config(auth_mode: AuthMode, keys: Vec<String>) -> Config {
        Config {
            s3_listen_addr: "0.0.0.0:8080".to_string(),
            admin_listen_addr: "0.0.0.0:9090".to_string(),
            frontend_bucket: "fb".to_string(),
            auth_mode,
            allowed_frontend_keys: keys,
            backend_endpoint: "https://example.com".to_string(),
            backend_region: "auto".to_string(),
            backend_bucket: "bb".to_string(),
            backend_access_key_id: "AKID".to_string(),
            backend_secret_access_key: "secret".to_string(),
            backend_use_path_style: true,
            backend_allow_http: false,
            cache_dir: "/cache".to_string(),
            cache_max_bytes: 1024,
            cache_max_object_bytes: 512,
            cacheable_prefixes: vec![],
            cache_serve_stale_on_error: true,
            cache_eviction_interval_secs: 300,
            get_max_attempts: 3,
            head_max_attempts: 3,
            list_max_attempts: 3,
            put_max_attempts: 1,
            delete_max_attempts: 2,
            retry_base_backoff_ms: 100,
            upstream_connect_timeout_ms: 5000,
            upstream_request_timeout_ms: 30000,
            max_request_body_bytes: 5_368_709_120,
        }
    }

    #[test]
    fn test_create_authenticator_trusted_internal() {
        let config = test_config(AuthMode::TrustedInternal, vec![]);
        let authenticator = create_authenticator(&config);
        // TrustedInternal accepts everything
        let req = make_request();
        assert!(authenticator.authenticate(&req).is_ok());
    }

    #[test]
    fn test_create_authenticator_allowlist_accepts_known_key() {
        let config = test_config(AuthMode::AccessKeyAllowlist, vec!["TESTKEY".to_string()]);
        let authenticator = create_authenticator(&config);
        let req = make_request();
        assert!(authenticator.authenticate(&req).is_ok());
    }

    #[test]
    fn test_create_authenticator_allowlist_rejects_unknown_key() {
        let config = test_config(AuthMode::AccessKeyAllowlist, vec!["OTHERKEY".to_string()]);
        let authenticator = create_authenticator(&config);
        let req = make_request();
        assert!(authenticator.authenticate(&req).is_err());
    }
}
