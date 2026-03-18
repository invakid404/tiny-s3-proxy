use crate::auth::Authenticator;
use crate::error::ProxyError;
use crate::s3::ops::ParsedRequest;

/// Authenticator that accepts all requests without validation.
/// Suitable for deployment behind private networking where only
/// trusted services can reach the proxy.
pub struct TrustedInternalAuth;

impl TrustedInternalAuth {
    pub fn new() -> Self {
        Self
    }
}

impl Authenticator for TrustedInternalAuth {
    fn authenticate(&self, _req: &ParsedRequest) -> Result<(), ProxyError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};

    fn make_request(authorization: Option<&str>) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::GetObject {
                bucket: "test-bucket".to_string(),
                key: "test-key".to_string(),
            },
            request_id: "test-request-id".to_string(),
            content_type: None,
            content_length: None,
            content_md5: None,
            authorization: authorization.map(|s| s.to_string()),
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_accepts_request_without_authorization() {
        let auth = TrustedInternalAuth::new();
        let req = make_request(None);
        assert!(auth.authenticate(&req).is_ok());
    }

    #[test]
    fn test_accepts_request_with_authorization() {
        let auth = TrustedInternalAuth::new();
        let req = make_request(Some(
            "AWS4-HMAC-SHA256 Credential=AKID1234567890AB/20240101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abcdef",
        ));
        assert!(auth.authenticate(&req).is_ok());
    }

    #[test]
    fn test_accepts_request_with_garbage_authorization() {
        let auth = TrustedInternalAuth::new();
        let req = make_request(Some("garbage-value"));
        assert!(auth.authenticate(&req).is_ok());
    }
}
