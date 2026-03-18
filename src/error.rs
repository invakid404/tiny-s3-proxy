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
