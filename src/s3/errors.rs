use crate::error::ProxyError;
use http::StatusCode;

/// An S3-compatible error response.
#[derive(Debug)]
pub struct S3Error {
    pub http_status: StatusCode,
    pub code: String,
    pub message: String,
    pub resource: Option<String>,
    pub request_id: String,
}

impl S3Error {
    /// Create from a ProxyError.
    ///
    /// Uses stable, client-facing messages instead of raw internal error strings.
    /// Detailed error context is available in server-side logs.
    pub fn from_proxy_error(err: &ProxyError, request_id: &str, resource: Option<&str>) -> Self {
        let message = match err {
            ProxyError::Backend { .. } => "A backend error occurred. Please retry the request.".to_string(),
            ProxyError::Timeout { .. } => "The request to the backend timed out. Please retry.".to_string(),
            ProxyError::UpstreamS3 { s3_code, .. } => {
                // Use a stable message; the specific S3 code is in <Code>.
                format!("The backend returned an error: {s3_code}")
            }
            ProxyError::Auth { .. } => "Access Denied".to_string(),
            ProxyError::Cache { .. } => "An internal cache error occurred.".to_string(),
            ProxyError::Internal { .. } => "An internal error occurred.".to_string(),
            // For InvalidRequest and UnsupportedOperation, the message is already user-facing.
            _ => err.to_string(),
        };

        S3Error {
            http_status: err.status_code(),
            code: err.s3_error_code().to_string(),
            message,
            resource: resource.map(|s| s.to_string()),
            request_id: request_id.to_string(),
        }
    }

    /// Render to S3 XML error format.
    pub fn to_xml(&self) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error>");
        xml.push_str(&format!(
            "<Code>{}</Code>",
            quick_xml::escape::escape(&self.code)
        ));
        xml.push_str(&format!(
            "<Message>{}</Message>",
            quick_xml::escape::escape(&self.message)
        ));
        if let Some(ref resource) = self.resource {
            xml.push_str(&format!(
                "<Resource>{}</Resource>",
                quick_xml::escape::escape(resource)
            ));
        }
        xml.push_str(&format!(
            "<RequestId>{}</RequestId>",
            quick_xml::escape::escape(&self.request_id)
        ));
        xml.push_str("</Error>");
        xml
    }

    /// Convert to an axum HTTP Response.
    pub fn to_response(&self) -> http::Response<axum::body::Body> {
        let body = self.to_xml();
        http::Response::builder()
            .status(self.http_status)
            .header("content-type", "application/xml")
            .header("x-amz-request-id", &self.request_id)
            .body(axum::body::Body::from(body))
            .expect("failed to build error response")
    }

    /// Create a NoSuchKey error.
    pub fn no_such_key(key: &str, request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::NOT_FOUND,
            code: "NoSuchKey".to_string(),
            message: "The specified key does not exist.".to_string(),
            resource: Some(key.to_string()),
            request_id: request_id.to_string(),
        }
    }

    /// Create a NoSuchBucket error.
    pub fn no_such_bucket(bucket: &str, request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::NOT_FOUND,
            code: "NoSuchBucket".to_string(),
            message: "The specified bucket does not exist.".to_string(),
            resource: Some(bucket.to_string()),
            request_id: request_id.to_string(),
        }
    }

    /// Create an AccessDenied error.
    pub fn access_denied(request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::FORBIDDEN,
            code: "AccessDenied".to_string(),
            message: "Access Denied".to_string(),
            resource: None,
            request_id: request_id.to_string(),
        }
    }

    /// Create an InternalError.
    pub fn internal_error(message: &str, request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "InternalError".to_string(),
            message: message.to_string(),
            resource: None,
            request_id: request_id.to_string(),
        }
    }

    /// Create an EntityTooLarge error (HTTP 400).
    pub fn entity_too_large(message: &str, request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::BAD_REQUEST,
            code: "EntityTooLarge".to_string(),
            message: message.to_string(),
            resource: None,
            request_id: request_id.to_string(),
        }
    }

    /// Create an error from a body-read failure. Returns EntityTooLarge for
    /// limit violations, IncompleteBody for stream/transport errors.
    pub fn from_body_error(e: &axum::Error, request_id: &str) -> Self {
        // Walk the error source chain looking for the typed LengthLimitError.
        let mut source: Option<&dyn std::error::Error> = Some(e);
        while let Some(err) = source {
            if err.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
                return Self::entity_too_large(
                    "request body exceeded the configured size limit",
                    request_id,
                );
            }
            source = err.source();
        }
        S3Error {
            http_status: StatusCode::BAD_REQUEST,
            code: "IncompleteBody".to_string(),
            message: format!("failed to read request body: {e}"),
            resource: None,
            request_id: request_id.to_string(),
        }
    }

    /// Create a MalformedXML error (HTTP 400).
    pub fn malformed_xml(message: &str, request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::BAD_REQUEST,
            code: "MalformedXML".to_string(),
            message: message.to_string(),
            resource: None,
            request_id: request_id.to_string(),
        }
    }

    /// Create an InvalidArgument error (HTTP 400).
    pub fn invalid_argument(message: &str, request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::BAD_REQUEST,
            code: "InvalidArgument".to_string(),
            message: message.to_string(),
            resource: None,
            request_id: request_id.to_string(),
        }
    }

    /// Create a NotImplemented error.
    pub fn not_implemented(operation: &str, request_id: &str) -> Self {
        S3Error {
            http_status: StatusCode::NOT_IMPLEMENTED,
            code: "NotImplemented".to_string(),
            message: format!("The operation '{}' is not implemented.", operation),
            resource: None,
            request_id: request_id.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_such_key_xml() {
        let err = S3Error::no_such_key("/mybucket/mykey", "req-123");
        let xml = err.to_xml();
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<Code>NoSuchKey</Code>"));
        assert!(xml.contains("<Message>The specified key does not exist.</Message>"));
        assert!(xml.contains("<Resource>/mybucket/mykey</Resource>"));
        assert!(xml.contains("<RequestId>req-123</RequestId>"));
        assert!(xml.ends_with("</Error>"));
    }

    #[test]
    fn test_no_such_key_status() {
        let err = S3Error::no_such_key("/b/k", "r");
        assert_eq!(err.http_status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_no_such_bucket_xml() {
        let err = S3Error::no_such_bucket("mybucket", "req-456");
        let xml = err.to_xml();
        assert!(xml.contains("<Code>NoSuchBucket</Code>"));
        assert!(xml.contains("<Resource>mybucket</Resource>"));
    }

    #[test]
    fn test_no_such_bucket_status() {
        let err = S3Error::no_such_bucket("b", "r");
        assert_eq!(err.http_status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_access_denied_xml() {
        let err = S3Error::access_denied("req-789");
        let xml = err.to_xml();
        assert!(xml.contains("<Code>AccessDenied</Code>"));
        assert!(xml.contains("<Message>Access Denied</Message>"));
        // No Resource element expected
        assert!(!xml.contains("<Resource>"));
    }

    #[test]
    fn test_access_denied_status() {
        let err = S3Error::access_denied("r");
        assert_eq!(err.http_status, StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_internal_error_xml() {
        let err = S3Error::internal_error("something broke", "req-000");
        let xml = err.to_xml();
        assert!(xml.contains("<Code>InternalError</Code>"));
        assert!(xml.contains("<Message>something broke</Message>"));
    }

    #[test]
    fn test_internal_error_status() {
        let err = S3Error::internal_error("msg", "r");
        assert_eq!(err.http_status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_not_implemented_xml() {
        let err = S3Error::not_implemented("PutBucketAcl", "req-111");
        let xml = err.to_xml();
        assert!(xml.contains("<Code>NotImplemented</Code>"));
        assert!(xml.contains("PutBucketAcl"));
    }

    #[test]
    fn test_not_implemented_status() {
        let err = S3Error::not_implemented("op", "r");
        assert_eq!(err.http_status, StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn test_from_proxy_error() {
        let proxy_err = ProxyError::Auth {
            message: "bad token".to_string(),
        };
        let s3err = S3Error::from_proxy_error(&proxy_err, "req-x", Some("/bucket/key"));
        assert_eq!(s3err.http_status, StatusCode::FORBIDDEN);
        assert_eq!(s3err.code, "AccessDenied");
        assert_eq!(s3err.resource.as_deref(), Some("/bucket/key"));
    }

    #[test]
    fn test_to_response_status_and_headers() {
        let err = S3Error::no_such_key("/b/k", "req-resp");
        let resp = err.to_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/xml"
        );
        assert_eq!(resp.headers().get("x-amz-request-id").unwrap(), "req-resp");
    }

    #[test]
    fn test_from_proxy_error_upstream_s3() {
        let proxy_err = ProxyError::UpstreamS3 {
            status_code: 404,
            s3_code: "NoSuchKey".to_string(),
            message: "The specified key does not exist.".to_string(),
            operation: "get_object".to_string(),
        };
        let s3err = S3Error::from_proxy_error(&proxy_err, "req-x", Some("/bucket/key"));
        assert_eq!(s3err.http_status, StatusCode::NOT_FOUND);
        assert_eq!(s3err.code, "NoSuchKey");
    }

    #[test]
    fn test_xml_escapes_special_characters() {
        let err = S3Error::internal_error("value with <xml> & \"quotes\"", "r&id");
        let xml = err.to_xml();
        assert!(xml.contains("&lt;xml&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;quotes&quot;"));
        assert!(xml.contains("r&amp;id"));
    }
}
