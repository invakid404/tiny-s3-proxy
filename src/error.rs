use http::StatusCode;
use thiserror::Error;

/// Central error type for the proxy.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("backend error during {operation}: {source}")]
    Backend {
        source: Box<dyn std::error::Error + Send + Sync>,
        operation: String,
    },

    #[error("cache error during {operation}: {source}")]
    Cache {
        source: Box<dyn std::error::Error + Send + Sync>,
        operation: String,
    },

    #[error("auth error: {message}")]
    Auth { message: String },

    #[error("invalid request: {message}")]
    InvalidRequest { message: String },

    #[error("unsupported operation: {operation}")]
    UnsupportedOperation { operation: String },

    #[error("timeout during {operation}")]
    Timeout { operation: String },

    #[error("upstream S3 error (HTTP {status_code}) during {operation}: [{s3_code}] {message}")]
    UpstreamS3 {
        status_code: u16,
        s3_code: String,
        message: String,
        operation: String,
    },

    #[error("internal error: {source}")]
    Internal {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl ProxyError {
    /// Map this error to an HTTP status code.
    pub fn status_code(&self) -> StatusCode {
        match self {
            ProxyError::Backend { .. } => StatusCode::BAD_GATEWAY,
            ProxyError::Cache { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::Auth { .. } => StatusCode::FORBIDDEN,
            ProxyError::InvalidRequest { .. } => StatusCode::BAD_REQUEST,
            ProxyError::UnsupportedOperation { .. } => StatusCode::NOT_IMPLEMENTED,
            ProxyError::Timeout { .. } => StatusCode::GATEWAY_TIMEOUT,
            ProxyError::UpstreamS3 { status_code, .. } => {
                StatusCode::from_u16(*status_code).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            ProxyError::Internal { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Whether this error is transient (worth retrying or serving stale for).
    /// Returns false for semantic errors like 404/403 where stale data would
    /// hide a real state change from the client.
    pub fn is_transient(&self) -> bool {
        match self {
            ProxyError::Backend { .. } | ProxyError::Timeout { .. } => true,
            ProxyError::UpstreamS3 { status_code, .. } => *status_code >= 500,
            _ => false,
        }
    }

    /// Map this error to an S3-compatible error code string.
    pub fn s3_error_code(&self) -> &str {
        match self {
            ProxyError::Backend { .. } => "InternalError",
            ProxyError::Cache { .. } => "InternalError",
            ProxyError::Auth { .. } => "AccessDenied",
            ProxyError::InvalidRequest { .. } => "InvalidRequest",
            ProxyError::UnsupportedOperation { .. } => "NotImplemented",
            ProxyError::Timeout { .. } => "RequestTimeout",
            ProxyError::UpstreamS3 { s3_code, .. } => s3_code.as_str(),
            ProxyError::Internal { .. } => "InternalError",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────

    fn backend_err() -> ProxyError {
        ProxyError::Backend {
            source: "test".into(),
            operation: "get_object".into(),
        }
    }

    fn cache_err() -> ProxyError {
        ProxyError::Cache {
            source: "disk full".into(),
            operation: "write".into(),
        }
    }

    fn auth_err() -> ProxyError {
        ProxyError::Auth {
            message: "denied".into(),
        }
    }

    fn invalid_request_err() -> ProxyError {
        ProxyError::InvalidRequest {
            message: "bad".into(),
        }
    }

    fn unsupported_err() -> ProxyError {
        ProxyError::UnsupportedOperation {
            operation: "COPY".into(),
        }
    }

    fn timeout_err() -> ProxyError {
        ProxyError::Timeout {
            operation: "get_object".into(),
        }
    }

    fn upstream_err(status_code: u16, s3_code: &str) -> ProxyError {
        ProxyError::UpstreamS3 {
            status_code,
            s3_code: s3_code.into(),
            message: "upstream error".into(),
            operation: "get_object".into(),
        }
    }

    fn internal_err() -> ProxyError {
        ProxyError::Internal {
            source: "bug".into(),
        }
    }

    // ── status_code tests ───────────────────────────────────────────

    #[test]
    fn test_status_code_backend() {
        assert_eq!(backend_err().status_code(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_status_code_cache() {
        assert_eq!(cache_err().status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_status_code_auth() {
        assert_eq!(auth_err().status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_status_code_invalid_request() {
        assert_eq!(invalid_request_err().status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_status_code_unsupported() {
        assert_eq!(unsupported_err().status_code(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn test_status_code_timeout() {
        assert_eq!(timeout_err().status_code(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn test_status_code_upstream_s3_404() {
        assert_eq!(
            upstream_err(404, "NoSuchKey").status_code(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn test_status_code_upstream_s3_invalid() {
        // 0 is not a valid HTTP status code; should fall back to 502 BAD_GATEWAY.
        assert_eq!(
            upstream_err(0, "Unknown").status_code(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn test_status_code_internal() {
        assert_eq!(
            internal_err().status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // ── is_transient tests ──────────────────────────────────────────

    #[test]
    fn test_is_transient_backend() {
        assert!(backend_err().is_transient());
    }

    #[test]
    fn test_is_transient_timeout() {
        assert!(timeout_err().is_transient());
    }

    #[test]
    fn test_is_transient_upstream_500() {
        assert!(upstream_err(500, "InternalError").is_transient());
    }

    #[test]
    fn test_is_transient_upstream_503() {
        assert!(upstream_err(503, "SlowDown").is_transient());
    }

    #[test]
    fn test_is_transient_upstream_404() {
        assert!(!upstream_err(404, "NoSuchKey").is_transient());
    }

    #[test]
    fn test_is_transient_upstream_403() {
        assert!(!upstream_err(403, "AccessDenied").is_transient());
    }

    #[test]
    fn test_is_transient_auth() {
        assert!(!auth_err().is_transient());
    }

    #[test]
    fn test_is_transient_invalid_request() {
        assert!(!invalid_request_err().is_transient());
    }

    #[test]
    fn test_is_transient_cache() {
        assert!(!cache_err().is_transient());
    }

    // ── s3_error_code tests ─────────────────────────────────────────

    #[test]
    fn test_s3_error_code_backend() {
        assert_eq!(backend_err().s3_error_code(), "InternalError");
    }

    #[test]
    fn test_s3_error_code_auth() {
        assert_eq!(auth_err().s3_error_code(), "AccessDenied");
    }

    #[test]
    fn test_s3_error_code_invalid_request() {
        assert_eq!(invalid_request_err().s3_error_code(), "InvalidRequest");
    }

    #[test]
    fn test_s3_error_code_unsupported() {
        assert_eq!(unsupported_err().s3_error_code(), "NotImplemented");
    }

    #[test]
    fn test_s3_error_code_timeout() {
        assert_eq!(timeout_err().s3_error_code(), "RequestTimeout");
    }

    #[test]
    fn test_s3_error_code_upstream() {
        assert_eq!(upstream_err(404, "NoSuchKey").s3_error_code(), "NoSuchKey");
    }
}
