use std::collections::HashMap;

use http::header::{HeaderName, HeaderValue};
use http::HeaderMap;

use crate::backend::models::{GetObjectMeta, HeadObjectOutput};

/// Format a DateTime to RFC 7231 (HTTP-date) format.
fn format_last_modified(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Build response headers for `x-amz-meta-*` user metadata.
///
/// Metadata is stored internally with bare keys (e.g. "author", "version").
/// This function adds the `x-amz-meta-` prefix for the HTTP response.
pub fn metadata_headers(metadata: &HashMap<String, String>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (k, v) in metadata {
        let header_name = format!("x-amz-meta-{}", k);
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(header_name.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }
    headers
}

/// Build response headers for a successful GetObject response.
pub fn get_object_headers(meta: &GetObjectMeta) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Some(ref ct) = meta.content_type
        && let Ok(val) = HeaderValue::from_str(ct)
    {
        headers.insert("content-type", val);
    }

    if let Some(cl) = meta.content_length {
        headers.insert("content-length", HeaderValue::from(cl));
    }

    if let Some(ref etag) = meta.etag
        && let Ok(val) = HeaderValue::from_str(etag)
    {
        headers.insert("etag", val);
    }

    if let Some(ref dt) = meta.last_modified
        && let Ok(val) = HeaderValue::from_str(&format_last_modified(dt))
    {
        headers.insert("last-modified", val);
    }

    // Include x-amz-meta-* user metadata
    headers.extend(metadata_headers(&meta.metadata));

    headers
}

/// Build response headers for a successful HeadObject response.
pub fn head_object_headers(output: &HeadObjectOutput) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Some(ref ct) = output.content_type
        && let Ok(val) = HeaderValue::from_str(ct)
    {
        headers.insert("content-type", val);
    }

    if let Some(cl) = output.content_length {
        headers.insert("content-length", HeaderValue::from(cl));
    }

    if let Some(ref etag) = output.etag
        && let Ok(val) = HeaderValue::from_str(etag)
    {
        headers.insert("etag", val);
    }

    if let Some(ref dt) = output.last_modified
        && let Ok(val) = HeaderValue::from_str(&format_last_modified(dt))
    {
        headers.insert("last-modified", val);
    }

    // Include x-amz-meta-* user metadata
    headers.extend(metadata_headers(&output.metadata));

    headers
}

/// Build common S3 response headers.
pub fn common_headers(request_id: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Ok(val) = HeaderValue::from_str(request_id) {
        headers.insert("x-amz-request-id", val);
    }

    headers.insert("x-amz-id-2", HeaderValue::from_static("tiny-s3-proxy-id-2"));
    headers.insert("server", HeaderValue::from_static("tiny-s3-proxy"));

    headers
}

/// Build headers for a PutObject success response.
pub fn put_object_headers(etag: Option<&str>, request_id: &str) -> HeaderMap {
    let mut headers = common_headers(request_id);

    if let Some(etag) = etag
        && let Ok(val) = HeaderValue::from_str(etag)
    {
        headers.insert("etag", val);
    }

    headers
}

/// Add a cache diagnostic header.
pub fn with_cache_status(headers: &mut HeaderMap, status: &str) {
    if let Ok(val) = HeaderValue::from_str(status) {
        headers.insert("x-cache", val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_get_object_headers_includes_all() {
        let meta = GetObjectMeta {
            content_type: Some("application/json".to_string()),
            content_length: Some(256),
            etag: Some("\"abc123\"".to_string()),
            last_modified: Some(chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            metadata: HashMap::new(),
        };
        let headers = get_object_headers(&meta);
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
        assert_eq!(headers.get("content-length").unwrap(), "256");
        assert_eq!(headers.get("etag").unwrap(), "\"abc123\"");
        assert_eq!(
            headers.get("last-modified").unwrap(),
            "Mon, 01 Jan 2024 00:00:00 GMT"
        );
    }

    #[test]
    fn test_head_object_headers_includes_etag_and_content_length() {
        let output = HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(512),
            etag: Some("\"def456\"".to_string()),
            last_modified: None,
            metadata: HashMap::new(),
        };
        let headers = head_object_headers(&output);
        assert_eq!(headers.get("etag").unwrap(), "\"def456\"");
        assert_eq!(headers.get("content-length").unwrap(), "512");
    }

    #[test]
    fn test_common_headers_includes_request_id() {
        let headers = common_headers("req-12345");
        assert_eq!(headers.get("x-amz-request-id").unwrap(), "req-12345");
        assert!(headers.get("x-amz-id-2").is_some());
        assert_eq!(headers.get("server").unwrap(), "tiny-s3-proxy");
    }

    #[test]
    fn test_put_object_headers_with_etag() {
        let headers = put_object_headers(Some("\"put-etag\""), "req-put");
        assert_eq!(headers.get("etag").unwrap(), "\"put-etag\"");
        assert_eq!(headers.get("x-amz-request-id").unwrap(), "req-put");
    }

    #[test]
    fn test_put_object_headers_without_etag() {
        let headers = put_object_headers(None, "req-put2");
        assert!(headers.get("etag").is_none());
        assert_eq!(headers.get("x-amz-request-id").unwrap(), "req-put2");
    }

    #[test]
    fn test_with_cache_status() {
        let mut headers = HeaderMap::new();
        with_cache_status(&mut headers, "HIT");
        assert_eq!(headers.get("x-cache").unwrap(), "HIT");
    }

    #[test]
    fn test_with_cache_status_miss() {
        let mut headers = HeaderMap::new();
        with_cache_status(&mut headers, "MISS");
        assert_eq!(headers.get("x-cache").unwrap(), "MISS");
    }

    #[test]
    fn test_last_modified_format_rfc7231() {
        let dt = chrono::Utc
            .with_ymd_and_hms(2024, 7, 15, 14, 30, 45)
            .unwrap();
        let formatted = format_last_modified(&dt);
        assert_eq!(formatted, "Mon, 15 Jul 2024 14:30:45 GMT");
    }

    #[test]
    fn test_get_object_headers_missing_optional_fields() {
        let meta = GetObjectMeta {
            content_type: None,
            content_length: None,
            etag: None,
            last_modified: None,
            metadata: HashMap::new(),
        };
        let headers = get_object_headers(&meta);
        assert!(headers.get("content-type").is_none());
        assert!(headers.get("content-length").is_none());
        assert!(headers.get("etag").is_none());
        assert!(headers.get("last-modified").is_none());
    }

    #[test]
    fn test_metadata_headers_produces_correct_headermap() {
        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "alice".to_string());
        metadata.insert("version".to_string(), "42".to_string());

        let headers = metadata_headers(&metadata);
        assert_eq!(headers.get("x-amz-meta-author").unwrap(), "alice");
        assert_eq!(headers.get("x-amz-meta-version").unwrap(), "42");
    }

    #[test]
    fn test_metadata_headers_empty() {
        let metadata = HashMap::new();
        let headers = metadata_headers(&metadata);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_get_object_headers_includes_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("custom".to_string(), "value".to_string());
        let meta = GetObjectMeta {
            content_type: Some("text/plain".to_string()),
            content_length: Some(100),
            etag: None,
            last_modified: None,
            metadata,
        };
        let headers = get_object_headers(&meta);
        assert_eq!(headers.get("x-amz-meta-custom").unwrap(), "value");
        assert_eq!(headers.get("content-type").unwrap(), "text/plain");
    }

    #[test]
    fn test_head_object_headers_includes_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("tag".to_string(), "test".to_string());
        let output = HeadObjectOutput {
            content_type: None,
            content_length: Some(200),
            etag: None,
            last_modified: None,
            metadata,
        };
        let headers = head_object_headers(&output);
        assert_eq!(headers.get("x-amz-meta-tag").unwrap(), "test");
        assert_eq!(headers.get("content-length").unwrap(), "200");
    }
}
