/// Represents a classified S3 operation parsed from an inbound HTTP request.
#[derive(Debug, Clone)]
pub enum S3Operation {
    GetObject {
        bucket: String,
        key: String,
    },
    HeadObject {
        bucket: String,
        key: String,
    },
    PutObject {
        bucket: String,
        key: String,
    },
    DeleteObject {
        bucket: String,
        key: String,
    },
    ListObjectsV1 {
        bucket: String,
        params: ListParams,
    },
    ListObjectsV2 {
        bucket: String,
        params: ListParams,
    },
    CreateMultipartUpload {
        bucket: String,
        key: String,
    },
    UploadPart {
        bucket: String,
        key: String,
        part_number: i32,
        upload_id: String,
    },
    CompleteMultipartUpload {
        bucket: String,
        key: String,
        upload_id: String,
    },
    AbortMultipartUpload {
        bucket: String,
        key: String,
        upload_id: String,
    },
    Unsupported {
        method: String,
        path: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct ListParams {
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<i32>,
    pub continuation_token: Option<String>, // v2
    pub marker: Option<String>,             // v1
    pub start_after: Option<String>,        // v2
    pub encoding_type: Option<String>,
}

/// Metadata extracted from the inbound HTTP request alongside the classified operation.
#[derive(Debug)]
pub struct ParsedRequest {
    pub operation: S3Operation,
    pub request_id: String,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub content_md5: Option<String>,
    pub authorization: Option<String>,
    pub amz_date: Option<String>,
    pub amz_content_sha256: Option<String>,
    pub range: Option<String>,
    /// `x-amz-meta-*` user metadata headers from the inbound request.
    pub user_metadata: std::collections::HashMap<String, String>,
    /// Other `x-amz-*` headers that should be forwarded (e.g. `x-amz-storage-class`).
    pub extra_amz_headers: std::collections::HashMap<String, String>,
    /// Standard content headers to forward on write paths (content-encoding,
    /// content-disposition, content-language, cache-control, expires).
    pub content_headers: std::collections::HashMap<String, String>,
}

impl ParsedRequest {
    pub fn read_options(&self) -> crate::backend::models::ReadOptions {
        crate::backend::models::ReadOptions {
            checksum_mode: self
                .extra_amz_headers
                .get("x-amz-checksum-mode")
                .and_then(|value| crate::backend::models::ChecksumMode::from_header_value(value)),
        }
    }
}

impl S3Operation {
    /// Returns a short, human-readable name for this operation (for metrics labels).
    pub fn name(&self) -> &'static str {
        match self {
            Self::GetObject { .. } => "GetObject",
            Self::HeadObject { .. } => "HeadObject",
            Self::PutObject { .. } => "PutObject",
            Self::DeleteObject { .. } => "DeleteObject",
            Self::ListObjectsV1 { .. } => "ListObjectsV1",
            Self::ListObjectsV2 { .. } => "ListObjectsV2",
            Self::CreateMultipartUpload { .. } => "CreateMultipartUpload",
            Self::UploadPart { .. } => "UploadPart",
            Self::CompleteMultipartUpload { .. } => "CompleteMultipartUpload",
            Self::AbortMultipartUpload { .. } => "AbortMultipartUpload",
            Self::Unsupported { .. } => "Unsupported",
        }
    }

    /// Returns the bucket name for this operation.
    pub fn bucket(&self) -> &str {
        match self {
            S3Operation::GetObject { bucket, .. }
            | S3Operation::HeadObject { bucket, .. }
            | S3Operation::PutObject { bucket, .. }
            | S3Operation::DeleteObject { bucket, .. }
            | S3Operation::ListObjectsV1 { bucket, .. }
            | S3Operation::ListObjectsV2 { bucket, .. }
            | S3Operation::CreateMultipartUpload { bucket, .. }
            | S3Operation::UploadPart { bucket, .. }
            | S3Operation::CompleteMultipartUpload { bucket, .. }
            | S3Operation::AbortMultipartUpload { bucket, .. } => bucket,
            S3Operation::Unsupported { path, .. } => path,
        }
    }

    /// Returns the object key if this operation targets a specific object.
    pub fn key(&self) -> Option<&str> {
        match self {
            S3Operation::GetObject { key, .. }
            | S3Operation::HeadObject { key, .. }
            | S3Operation::PutObject { key, .. }
            | S3Operation::DeleteObject { key, .. }
            | S3Operation::CreateMultipartUpload { key, .. }
            | S3Operation::UploadPart { key, .. }
            | S3Operation::CompleteMultipartUpload { key, .. }
            | S3Operation::AbortMultipartUpload { key, .. } => Some(key),
            S3Operation::ListObjectsV1 { .. }
            | S3Operation::ListObjectsV2 { .. }
            | S3Operation::Unsupported { .. } => None,
        }
    }

    /// Returns true if this is a cacheable read operation (GetObject only).
    pub fn is_cacheable_read(&self) -> bool {
        matches!(self, S3Operation::GetObject { .. })
    }

    /// Returns true if this is a write operation that mutates objects.
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            S3Operation::PutObject { .. }
                | S3Operation::DeleteObject { .. }
                | S3Operation::CompleteMultipartUpload { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_returns_correct_value() {
        let op = S3Operation::GetObject {
            bucket: "my-bucket".to_string(),
            key: "my-key".to_string(),
        };
        assert_eq!(op.bucket(), "my-bucket");

        let op = S3Operation::ListObjectsV2 {
            bucket: "list-bucket".to_string(),
            params: ListParams::default(),
        };
        assert_eq!(op.bucket(), "list-bucket");
    }

    #[test]
    fn test_key_returns_some_for_object_ops() {
        let op = S3Operation::PutObject {
            bucket: "b".to_string(),
            key: "path/to/obj".to_string(),
        };
        assert_eq!(op.key(), Some("path/to/obj"));
    }

    #[test]
    fn test_key_returns_none_for_list_ops() {
        let op = S3Operation::ListObjectsV1 {
            bucket: "b".to_string(),
            params: ListParams::default(),
        };
        assert_eq!(op.key(), None);
    }

    #[test]
    fn test_key_returns_none_for_unsupported() {
        let op = S3Operation::Unsupported {
            method: "PATCH".to_string(),
            path: "/weird".to_string(),
        };
        assert_eq!(op.key(), None);
    }

    #[test]
    fn test_is_cacheable_read() {
        let get = S3Operation::GetObject {
            bucket: "b".to_string(),
            key: "k".to_string(),
        };
        assert!(get.is_cacheable_read());

        let head = S3Operation::HeadObject {
            bucket: "b".to_string(),
            key: "k".to_string(),
        };
        assert!(!head.is_cacheable_read());

        let list = S3Operation::ListObjectsV2 {
            bucket: "b".to_string(),
            params: ListParams::default(),
        };
        assert!(!list.is_cacheable_read());
    }

    #[test]
    fn test_is_write() {
        let put = S3Operation::PutObject {
            bucket: "b".to_string(),
            key: "k".to_string(),
        };
        assert!(put.is_write());

        let delete = S3Operation::DeleteObject {
            bucket: "b".to_string(),
            key: "k".to_string(),
        };
        assert!(delete.is_write());

        let complete = S3Operation::CompleteMultipartUpload {
            bucket: "b".to_string(),
            key: "k".to_string(),
            upload_id: "uid".to_string(),
        };
        assert!(complete.is_write());

        let get = S3Operation::GetObject {
            bucket: "b".to_string(),
            key: "k".to_string(),
        };
        assert!(!get.is_write());

        let create = S3Operation::CreateMultipartUpload {
            bucket: "b".to_string(),
            key: "k".to_string(),
        };
        assert!(!create.is_write());
    }

    #[test]
    fn test_parsed_request_read_options_extract_checksum_mode() {
        let mut extra_amz_headers = std::collections::HashMap::new();
        extra_amz_headers.insert("x-amz-checksum-mode".to_string(), "ENABLED".to_string());

        let parsed = ParsedRequest {
            operation: S3Operation::GetObject {
                bucket: "bucket".to_string(),
                key: "key".to_string(),
            },
            request_id: "req".to_string(),
            content_type: None,
            content_length: None,
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers,
            content_headers: std::collections::HashMap::new(),
        };

        assert!(parsed.read_options().wants_checksum_headers());
    }

    #[test]
    fn test_parsed_request_read_options_rejects_invalid_or_missing_checksum_mode() {
        let parsed_missing = ParsedRequest {
            operation: S3Operation::GetObject {
                bucket: "bucket".to_string(),
                key: "key".to_string(),
            },
            request_id: "req".to_string(),
            content_type: None,
            content_length: None,
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
            content_headers: std::collections::HashMap::new(),
        };
        assert!(!parsed_missing.read_options().wants_checksum_headers());

        let mut invalid_headers = std::collections::HashMap::new();
        invalid_headers.insert("x-amz-checksum-mode".to_string(), "disabled".to_string());
        let parsed_invalid = ParsedRequest {
            extra_amz_headers: invalid_headers,
            ..parsed_missing
        };
        assert!(!parsed_invalid.read_options().wants_checksum_headers());
    }
}
