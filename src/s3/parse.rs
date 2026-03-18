use http::Request;
use percent_encoding::percent_decode_str;
use std::collections::HashMap;

use crate::request_id;
use crate::s3::ops::{ListParams, ParsedRequest, S3Operation};

/// S3 subresource query parameters that change the meaning of an operation.
/// When present, the request is NOT a simple object GET/PUT/DELETE and must
/// be routed as Unsupported (passthrough) to avoid misclassifying it.
const S3_SUBRESOURCE_PARAMS: &[&str] = &[
    "acl", "cors", "delete", "encryption", "intelligent-tiering",
    "inventory", "legal-hold", "lifecycle", "location", "logging",
    "metrics", "notification", "object-lock", "policy", "replication",
    "requestPayment", "restore", "retention", "select", "tagging",
    "torrent", "versioning", "versions", "website", "accelerate",
    "analytics",
];

/// Parse query string into key-value pairs.
fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if query.is_empty() {
        return map;
    }
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let decoded_key = percent_decode_str(key).decode_utf8_lossy().to_string();
            let decoded_value = percent_decode_str(value).decode_utf8_lossy().to_string();
            map.insert(decoded_key, decoded_value);
        } else {
            let decoded_key = percent_decode_str(pair).decode_utf8_lossy().to_string();
            map.insert(decoded_key, String::new());
        }
    }
    map
}

/// Extract a header value as a String.
fn header_str<B>(req: &Request<B>, name: &str) -> Option<String> {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Parse an inbound HTTP request into a classified S3 operation.
pub fn parse_request<B>(req: &Request<B>) -> ParsedRequest {
    let method = req.method().as_str();
    let path = req.uri().path();
    let query_str = req.uri().query().unwrap_or("");
    let query = parse_query(query_str);

    // Parse path: strip leading '/' then split into bucket and key
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let (bucket, raw_key) = if trimmed.is_empty() {
        ("", "")
    } else if let Some((b, k)) = trimmed.split_once('/') {
        (b, k)
    } else {
        (trimmed, "")
    };

    // URL-decode the key
    let key = percent_decode_str(raw_key).decode_utf8_lossy().to_string();

    let has_key = !key.is_empty();

    let operation = if bucket.is_empty() {
        // No bucket in path
        S3Operation::Unsupported {
            method: method.to_string(),
            path: path.to_string(),
        }
    } else if has_key {
        // Check for S3 subresource query parameters. When present, the request
        // is a subresource operation (e.g. GET ?acl, PUT ?tagging) that we don't
        // handle natively. Route it as Unsupported so it goes through passthrough.
        let is_subresource = S3_SUBRESOURCE_PARAMS.iter().any(|p| query.contains_key(*p));
        if is_subresource {
            S3Operation::Unsupported {
                method: method.to_string(),
                path: path.to_string(),
            }
        } else {
        // Operations on objects
        match method {
            "GET" => S3Operation::GetObject {
                bucket: bucket.to_string(),
                key,
            },
            "HEAD" => S3Operation::HeadObject {
                bucket: bucket.to_string(),
                key,
            },
            "PUT" => {
                if query.contains_key("partNumber") && query.contains_key("uploadId") {
                    let part_number = query
                        .get("partNumber")
                        .and_then(|v| v.parse::<i32>().ok())
                        .unwrap_or(0);
                    let upload_id = query.get("uploadId").cloned().unwrap_or_default();
                    S3Operation::UploadPart {
                        bucket: bucket.to_string(),
                        key,
                        part_number,
                        upload_id,
                    }
                } else {
                    S3Operation::PutObject {
                        bucket: bucket.to_string(),
                        key,
                    }
                }
            }
            "POST" => {
                if query.contains_key("uploads") {
                    S3Operation::CreateMultipartUpload {
                        bucket: bucket.to_string(),
                        key,
                    }
                } else if let Some(upload_id) = query.get("uploadId") {
                    S3Operation::CompleteMultipartUpload {
                        bucket: bucket.to_string(),
                        key,
                        upload_id: upload_id.clone(),
                    }
                } else {
                    S3Operation::Unsupported {
                        method: method.to_string(),
                        path: path.to_string(),
                    }
                }
            }
            "DELETE" => {
                if let Some(upload_id) = query.get("uploadId") {
                    S3Operation::AbortMultipartUpload {
                        bucket: bucket.to_string(),
                        key,
                        upload_id: upload_id.clone(),
                    }
                } else {
                    S3Operation::DeleteObject {
                        bucket: bucket.to_string(),
                        key,
                    }
                }
            }
            _ => S3Operation::Unsupported {
                method: method.to_string(),
                path: path.to_string(),
            },
        }
        }
    } else {
        // Bucket-level operations (no key)
        match method {
            "GET" => {
                // Check for bucket-level subresource queries
                let is_subresource = S3_SUBRESOURCE_PARAMS.iter().any(|p| query.contains_key(*p));
                if is_subresource {
                    S3Operation::Unsupported {
                        method: method.to_string(),
                        path: path.to_string(),
                    }
                } else {
                    let params = ListParams {
                        prefix: query.get("prefix").cloned(),
                        delimiter: query.get("delimiter").cloned(),
                        max_keys: query.get("max-keys").and_then(|v| v.parse().ok()),
                        continuation_token: query.get("continuation-token").cloned(),
                        marker: query.get("marker").cloned(),
                        start_after: query.get("start-after").cloned(),
                        encoding_type: query.get("encoding-type").cloned(),
                    };

                    if query.get("list-type").map(|v| v.as_str()) == Some("2") {
                        S3Operation::ListObjectsV2 {
                            bucket: bucket.to_string(),
                            params,
                        }
                    } else {
                        S3Operation::ListObjectsV1 {
                            bucket: bucket.to_string(),
                            params,
                        }
                    }
                }
            }
            _ => S3Operation::Unsupported {
                method: method.to_string(),
                path: path.to_string(),
            },
        }
    };

    let content_length = header_str(req, "content-length").and_then(|v| v.parse::<u64>().ok());

    // Scan for x-amz-meta-* user metadata and other x-amz-* headers to forward.
    let mut user_metadata = HashMap::new();
    let mut extra_amz_headers = HashMap::new();
    for (name, value) in req.headers() {
        let name_lower = name.as_str();
        if let Ok(v) = value.to_str() {
            if let Some(bare_key) = name_lower.strip_prefix("x-amz-meta-") {
                // Store bare key (without "x-amz-meta-" prefix) for internal use.
                // The prefix is added back when building response headers, and the
                // AWS SDK expects bare keys in its metadata() builder method.
                user_metadata.insert(bare_key.to_string(), v.to_string());
            } else if name_lower.starts_with("x-amz-")
                && name_lower != "x-amz-date"
                && name_lower != "x-amz-content-sha256"
            {
                extra_amz_headers.insert(name_lower.to_string(), v.to_string());
            }
        }
    }

    ParsedRequest {
        operation,
        request_id: request_id::generate(),
        content_type: header_str(req, "content-type"),
        content_length,
        content_md5: header_str(req, "content-md5"),
        authorization: header_str(req, "authorization"),
        amz_date: header_str(req, "x-amz-date"),
        amz_content_sha256: header_str(req, "x-amz-content-sha256"),
        range: header_str(req, "range"),
        user_metadata,
        extra_amz_headers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn build_request(method: &str, uri: &str) -> Request<()> {
        Request::builder().method(method).uri(uri).body(()).unwrap()
    }

    #[test]
    fn test_get_object() {
        let req = build_request("GET", "/mybucket/mykey");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::GetObject { bucket, key } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(key, "mykey");
            }
            other => panic!("Expected GetObject, got {:?}", other),
        }
    }

    #[test]
    fn test_head_object() {
        let req = build_request("HEAD", "/mybucket/mykey");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::HeadObject { .. }));
    }

    #[test]
    fn test_put_object() {
        let req = build_request("PUT", "/mybucket/mykey");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::PutObject { .. }));
    }

    #[test]
    fn test_delete_object() {
        let req = build_request("DELETE", "/mybucket/mykey");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::DeleteObject { .. }));
    }

    #[test]
    fn test_list_objects_v2() {
        let req = build_request("GET", "/mybucket?list-type=2&prefix=scripts/");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::ListObjectsV2 { bucket, params } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(params.prefix.as_deref(), Some("scripts/"));
            }
            other => panic!("Expected ListObjectsV2, got {:?}", other),
        }
    }

    #[test]
    fn test_list_objects_v1_with_params() {
        let req = build_request("GET", "/mybucket?prefix=logs/&delimiter=/");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::ListObjectsV1 { bucket, params } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(params.prefix.as_deref(), Some("logs/"));
                assert_eq!(params.delimiter.as_deref(), Some("/"));
            }
            other => panic!("Expected ListObjectsV1, got {:?}", other),
        }
    }

    #[test]
    fn test_list_objects_v1_no_params() {
        let req = build_request("GET", "/mybucket");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::ListObjectsV1 { bucket, params } => {
                assert_eq!(bucket, "mybucket");
                assert!(params.prefix.is_none());
                assert!(params.delimiter.is_none());
            }
            other => panic!("Expected ListObjectsV1, got {:?}", other),
        }
    }

    #[test]
    fn test_create_multipart_upload() {
        let req = build_request("POST", "/mybucket/mykey?uploads");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::CreateMultipartUpload { bucket, key } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(key, "mykey");
            }
            other => panic!("Expected CreateMultipartUpload, got {:?}", other),
        }
    }

    #[test]
    fn test_upload_part() {
        let req = build_request("PUT", "/mybucket/mykey?partNumber=3&uploadId=abc123");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::UploadPart {
                bucket,
                key,
                part_number,
                upload_id,
            } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(key, "mykey");
                assert_eq!(*part_number, 3);
                assert_eq!(upload_id, "abc123");
            }
            other => panic!("Expected UploadPart, got {:?}", other),
        }
    }

    #[test]
    fn test_complete_multipart_upload() {
        let req = build_request("POST", "/mybucket/mykey?uploadId=abc123");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::CompleteMultipartUpload {
                bucket,
                key,
                upload_id,
            } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(key, "mykey");
                assert_eq!(upload_id, "abc123");
            }
            other => panic!("Expected CompleteMultipartUpload, got {:?}", other),
        }
    }

    #[test]
    fn test_abort_multipart_upload() {
        let req = build_request("DELETE", "/mybucket/mykey?uploadId=abc123");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::AbortMultipartUpload {
                bucket,
                key,
                upload_id,
            } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(key, "mykey");
                assert_eq!(upload_id, "abc123");
            }
            other => panic!("Expected AbortMultipartUpload, got {:?}", other),
        }
    }

    #[test]
    fn test_deep_key_path() {
        let req = build_request("GET", "/mybucket/path/to/deep/key.js");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::GetObject { bucket, key } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(key, "path/to/deep/key.js");
            }
            other => panic!("Expected GetObject, got {:?}", other),
        }
    }

    #[test]
    fn test_url_decoded_key() {
        let req = build_request("GET", "/mybucket/path%20with%20spaces/key");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::GetObject { bucket, key } => {
                assert_eq!(bucket, "mybucket");
                assert_eq!(key, "path with spaces/key");
            }
            other => panic!("Expected GetObject, got {:?}", other),
        }
    }

    #[test]
    fn test_put_on_bucket_root_is_unsupported() {
        let req = build_request("PUT", "/mybucket");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::Unsupported { .. }));
    }

    #[test]
    fn test_no_path_segments_is_unsupported() {
        let req = build_request("GET", "/");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::Unsupported { .. }));
    }

    #[test]
    fn test_patch_is_unsupported() {
        let req = build_request("PATCH", "/mybucket/key");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::Unsupported { .. }));
    }

    #[test]
    fn test_request_id_is_generated() {
        let req = build_request("GET", "/mybucket/mykey");
        let parsed = parse_request(&req);
        assert!(!parsed.request_id.is_empty());
    }

    #[test]
    fn test_headers_extracted() {
        let req = Request::builder()
            .method("PUT")
            .uri("/mybucket/mykey")
            .header("content-type", "application/octet-stream")
            .header("content-length", "1024")
            .header("content-md5", "abc123==")
            .header("authorization", "AWS4-HMAC-SHA256 ...")
            .header("x-amz-date", "20240101T000000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("range", "bytes=0-99")
            .body(())
            .unwrap();
        let parsed = parse_request(&req);
        assert_eq!(
            parsed.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(parsed.content_length, Some(1024));
        assert_eq!(parsed.content_md5.as_deref(), Some("abc123=="));
        assert_eq!(
            parsed.authorization.as_deref(),
            Some("AWS4-HMAC-SHA256 ...")
        );
        assert_eq!(parsed.amz_date.as_deref(), Some("20240101T000000Z"));
        assert_eq!(
            parsed.amz_content_sha256.as_deref(),
            Some("UNSIGNED-PAYLOAD")
        );
        assert_eq!(parsed.range.as_deref(), Some("bytes=0-99"));
    }

    #[test]
    fn test_user_metadata_headers_extracted() {
        let req = Request::builder()
            .method("PUT")
            .uri("/mybucket/mykey")
            .header("x-amz-meta-author", "alice")
            .header("x-amz-meta-version", "42")
            .body(())
            .unwrap();
        let parsed = parse_request(&req);
        assert_eq!(parsed.user_metadata.len(), 2);
        assert_eq!(parsed.user_metadata.get("author").unwrap(), "alice");
        assert_eq!(parsed.user_metadata.get("version").unwrap(), "42");
    }

    #[test]
    fn test_extra_amz_headers_extracted() {
        let req = Request::builder()
            .method("PUT")
            .uri("/mybucket/mykey")
            .header("x-amz-storage-class", "REDUCED_REDUNDANCY")
            .header("x-amz-date", "20240101T000000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(())
            .unwrap();
        let parsed = parse_request(&req);
        // x-amz-date and x-amz-content-sha256 should NOT appear in extra_amz_headers
        assert_eq!(parsed.extra_amz_headers.len(), 1);
        assert_eq!(
            parsed.extra_amz_headers.get("x-amz-storage-class").unwrap(),
            "REDUCED_REDUNDANCY"
        );
        assert!(!parsed.extra_amz_headers.contains_key("x-amz-date"));
        assert!(!parsed
            .extra_amz_headers
            .contains_key("x-amz-content-sha256"));
    }

    #[test]
    fn test_user_metadata_not_in_extra_amz() {
        let req = Request::builder()
            .method("PUT")
            .uri("/mybucket/mykey")
            .header("x-amz-meta-custom", "value")
            .body(())
            .unwrap();
        let parsed = parse_request(&req);
        // x-amz-meta-* should be in user_metadata, NOT in extra_amz_headers
        assert_eq!(parsed.user_metadata.len(), 1);
        assert!(parsed.extra_amz_headers.is_empty());
    }

    #[test]
    fn test_get_object_with_acl_subresource_is_unsupported() {
        let req = build_request("GET", "/mybucket/mykey?acl");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::Unsupported { .. }));
    }

    #[test]
    fn test_put_object_with_tagging_subresource_is_unsupported() {
        let req = build_request("PUT", "/mybucket/mykey?tagging");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::Unsupported { .. }));
    }

    #[test]
    fn test_get_bucket_location_is_unsupported() {
        let req = build_request("GET", "/mybucket?location");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::Unsupported { .. }));
    }

    #[test]
    fn test_multipart_params_not_treated_as_subresource() {
        // partNumber+uploadId should still be UploadPart, not Unsupported
        let req = build_request("PUT", "/mybucket/mykey?partNumber=1&uploadId=abc");
        let parsed = parse_request(&req);
        assert!(matches!(parsed.operation, S3Operation::UploadPart { .. }));
    }

    #[test]
    fn test_query_params_are_percent_decoded() {
        let req = build_request("GET", "/mybucket?prefix=%2Fdir%2F&delimiter=%2F");
        let parsed = parse_request(&req);
        match &parsed.operation {
            S3Operation::ListObjectsV1 { params, .. } => {
                assert_eq!(params.prefix.as_deref(), Some("/dir/"));
                assert_eq!(params.delimiter.as_deref(), Some("/"));
            }
            other => panic!("Expected ListObjectsV1, got {:?}", other),
        }
    }
}
