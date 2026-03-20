use sha2::{Digest, Sha256};

use crate::auth::RequestGate;
use crate::error::ProxyError;
use crate::s3::ops::ParsedRequest;

/// Access-control gate that extracts the access key ID from the SigV4
/// Authorization header and checks it against an allowlist.
///
/// # Security Model
/// This is NOT cryptographic authentication — it does NOT verify SigV4
/// signatures. It only checks that the claimed access key ID is in the
/// allowlist, which provides coarse-grained access control suitable for
/// trusted internal networks (e.g. VPC-only deployments).
///
/// The proxy re-signs all backend requests with its own credentials
/// regardless of the inbound signature, so the original signature is
/// never validated. If you need actual signature verification with
/// per-client secrets, implement a full SigV4 validator or place the
/// proxy behind an authenticating reverse proxy.
///
/// This mode exists as a lightweight gate for multi-tenant internal
/// environments where network isolation provides the primary security
/// boundary and the allowlist adds defence-in-depth.
pub struct AccessKeyAllowlistAuth {
    /// SHA-256 digests of each allowed access key, precomputed at startup.
    /// Comparisons are always on fixed-size 32-byte digests, eliminating any
    /// timing side-channel based on key length or content.
    allowed_digests: Vec<[u8; 32]>,
}

impl AccessKeyAllowlistAuth {
    pub fn new(allowed_keys: Vec<String>) -> Self {
        let allowed_digests = allowed_keys
            .iter()
            .map(|k| {
                let mut h = Sha256::new();
                h.update(k.as_bytes());
                h.finalize().into()
            })
            .collect();
        Self { allowed_digests }
    }
}

impl RequestGate for AccessKeyAllowlistAuth {
    fn check_access(&self, req: &ParsedRequest) -> Result<(), ProxyError> {
        let authorization = req
            .authorization
            .as_deref()
            .ok_or_else(|| ProxyError::Auth {
                message: "missing Authorization header".to_string(),
            })?;

        let access_key_id =
            extract_access_key_id(authorization).ok_or_else(|| ProxyError::Auth {
                message: "malformed SigV4 Authorization header".to_string(),
            })?;

        // Hash the incoming access key to a fixed-size SHA-256 digest so
        // all comparisons are on 32-byte slices, eliminating any timing
        // side-channel based on key length or content.
        let mut h = Sha256::new();
        h.update(access_key_id.as_bytes());
        let input_digest: [u8; 32] = h.finalize().into();

        // Always iterate the entire list so timing does not reveal which
        // position (if any) matched.
        let mut found = false;
        for allowed_digest in &self.allowed_digests {
            found |= constant_time_eq_bytes(&input_digest, allowed_digest);
        }

        if found {
            Ok(())
        } else {
            Err(ProxyError::Auth {
                message: "access key ID not in allowlist".to_string(),
            })
        }
    }
}

/// Extract the access key ID from a SigV4 Authorization header.
/// Format: `AWS4-HMAC-SHA256 Credential=AKID/date/region/s3/aws4_request, ...`
/// Validates the scheme prefix to reject garbage Authorization headers.
fn extract_access_key_id(authorization: &str) -> Option<&str> {
    // SigV4 format: "AWS4-HMAC-SHA256 Credential=AKID/date/region/service/aws4_request, ..."
    // The Credential= field must immediately follow the scheme + space.
    let after_scheme = authorization.strip_prefix("AWS4-HMAC-SHA256 ")?;
    let after_cred = after_scheme.strip_prefix("Credential=")?;
    let slash_pos = after_cred.find('/')?;
    let key = &after_cred[..slash_pos];
    if key.is_empty() {
        return None;
    }
    Some(key)
}

/// Constant-time comparison of two equal-length byte slices.
///
/// Both slices must be the same length (guaranteed by callers that
/// compare SHA-256 digests). Every byte is XOR'd into the accumulator
/// with no branches or early exits.
fn constant_time_eq_bytes(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result: u8 = 0;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
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
            content_headers: std::collections::HashMap::new(),
        }
    }

    fn sigv4_header(access_key: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential={}/20240101/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=abcdef1234567890",
            access_key
        )
    }

    #[test]
    fn test_valid_access_key_accepted() {
        let auth = AccessKeyAllowlistAuth::new(vec!["AKID1234567890AB".to_string()]);
        let req = make_request(Some(&sigv4_header("AKID1234567890AB")));
        assert!(auth.check_access(&req).is_ok());
    }

    #[test]
    fn test_unknown_access_key_rejected() {
        let auth = AccessKeyAllowlistAuth::new(vec!["AKID1234567890AB".to_string()]);
        let req = make_request(Some(&sigv4_header("UNKNOWN_KEY")));
        let err = auth.check_access(&req).unwrap_err();
        match err {
            ProxyError::Auth { message } => {
                assert!(message.contains("not in allowlist"), "got: {}", message);
            }
            other => panic!("expected ProxyError::Auth, got: {:?}", other),
        }
    }

    #[test]
    fn test_missing_authorization_rejected() {
        let auth = AccessKeyAllowlistAuth::new(vec!["AKID1234567890AB".to_string()]);
        let req = make_request(None);
        let err = auth.check_access(&req).unwrap_err();
        match err {
            ProxyError::Auth { message } => {
                assert!(
                    message.contains("missing Authorization"),
                    "got: {}",
                    message
                );
            }
            other => panic!("expected ProxyError::Auth, got: {:?}", other),
        }
    }

    #[test]
    fn test_malformed_authorization_rejected() {
        let auth = AccessKeyAllowlistAuth::new(vec!["AKID1234567890AB".to_string()]);
        let req = make_request(Some("Bearer some-token"));
        let err = auth.check_access(&req).unwrap_err();
        match err {
            ProxyError::Auth { message } => {
                assert!(message.contains("malformed"), "got: {}", message);
            }
            other => panic!("expected ProxyError::Auth, got: {:?}", other),
        }
    }

    #[test]
    fn test_empty_allowlist_rejects_everything() {
        let auth = AccessKeyAllowlistAuth::new(vec![]);
        let req = make_request(Some(&sigv4_header("AKID1234567890AB")));
        let err = auth.check_access(&req).unwrap_err();
        match err {
            ProxyError::Auth { message } => {
                assert!(message.contains("not in allowlist"), "got: {}", message);
            }
            other => panic!("expected ProxyError::Auth, got: {:?}", other),
        }
    }

    #[test]
    fn test_multiple_allowed_keys_first() {
        let auth = AccessKeyAllowlistAuth::new(vec![
            "KEY1".to_string(),
            "KEY2".to_string(),
            "KEY3".to_string(),
        ]);
        let req = make_request(Some(&sigv4_header("KEY1")));
        assert!(auth.check_access(&req).is_ok());
    }

    #[test]
    fn test_multiple_allowed_keys_middle() {
        let auth = AccessKeyAllowlistAuth::new(vec![
            "KEY1".to_string(),
            "KEY2".to_string(),
            "KEY3".to_string(),
        ]);
        let req = make_request(Some(&sigv4_header("KEY2")));
        assert!(auth.check_access(&req).is_ok());
    }

    #[test]
    fn test_multiple_allowed_keys_last() {
        let auth = AccessKeyAllowlistAuth::new(vec![
            "KEY1".to_string(),
            "KEY2".to_string(),
            "KEY3".to_string(),
        ]);
        let req = make_request(Some(&sigv4_header("KEY3")));
        assert!(auth.check_access(&req).is_ok());
    }

    #[test]
    fn test_full_sigv4_format_parsing() {
        let auth = AccessKeyAllowlistAuth::new(vec!["AKID1234567890AB".to_string()]);
        let header =
            "AWS4-HMAC-SHA256 Credential=AKID1234567890AB/20240101/us-east-1/s3/aws4_request, \
                       SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                       Signature=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let req = make_request(Some(header));
        assert!(auth.check_access(&req).is_ok());
    }

    // --- Tests for extract_access_key_id ---

    #[test]
    fn test_extract_access_key_id_standard() {
        let header = "AWS4-HMAC-SHA256 Credential=AKID12345/20240101/us-east-1/s3/aws4_request";
        assert_eq!(extract_access_key_id(header), Some("AKID12345"));
    }

    #[test]
    fn test_extract_access_key_id_no_credential() {
        assert_eq!(extract_access_key_id("Bearer token"), None);
    }

    #[test]
    fn test_extract_access_key_id_no_slash() {
        assert_eq!(extract_access_key_id("Credential=AKID12345"), None);
    }

    #[test]
    fn test_extract_access_key_id_empty_key() {
        assert_eq!(
            extract_access_key_id("Credential=/20240101/us-east-1/s3/aws4_request"),
            None
        );
    }

    #[test]
    fn test_extract_access_key_id_credential_in_middle() {
        let header =
            "AWS4-HMAC-SHA256 Credential=MYKEY99/20240101/auto/s3/aws4_request, SignedHeaders=host";
        assert_eq!(extract_access_key_id(header), Some("MYKEY99"));
    }

    #[test]
    fn test_extract_access_key_id_rejects_wrong_scheme() {
        assert_eq!(
            extract_access_key_id("junk Credential=AKID/20240101/us-east-1/s3/aws4_request"),
            None
        );
    }

    #[test]
    fn test_extract_access_key_id_rejects_junk_between_scheme_and_credential() {
        // Scheme is correct but Credential= is not the first field
        assert_eq!(
            extract_access_key_id(
                "AWS4-HMAC-SHA256 junk Credential=AKID/20240101/us-east-1/s3/aws4_request"
            ),
            None
        );
    }

    // --- Tests for constant_time_eq_bytes ---

    fn sha256(input: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(input.as_bytes());
        h.finalize().into()
    }

    #[test]
    fn test_constant_time_eq_bytes_equal() {
        let a = sha256("hello");
        let b = sha256("hello");
        assert!(constant_time_eq_bytes(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_bytes_different() {
        let a = sha256("hello");
        let b = sha256("world");
        assert!(!constant_time_eq_bytes(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_bytes_single_bit_difference() {
        let mut a = sha256("hello");
        let b = a;
        a[0] ^= 1;
        assert!(!constant_time_eq_bytes(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_bytes_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(constant_time_eq_bytes(&a, &b));
    }

    #[test]
    fn test_digest_comparison_different_length_keys_rejected() {
        // Keys of different lengths produce different digests and are rejected.
        let auth = AccessKeyAllowlistAuth::new(vec!["AKID12345".to_string()]);
        let req = make_request(Some(&sigv4_header("AKID1234567890AB")));
        assert!(auth.check_access(&req).is_err());
    }
}
