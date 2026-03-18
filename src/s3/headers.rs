use http::header::HeaderValue;
use http::HeaderMap;

use crate::backend::models::{GetObjectOutput, HeadObjectOutput};

/// Format a DateTime to RFC 7231 (HTTP-date) format.
fn format_last_modified(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Build response headers for a successful GetObject response.
pub fn get_object_headers(output: &GetObjectOutput) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Some(ref ct) = output.content_type {
        if let Ok(val) = HeaderValue::from_str(ct) {
            headers.insert("content-type", val);
        }
    }

    if let Some(cl) = output.content_length {
        headers.insert("content-length", HeaderValue::from(cl));
    }

    if let Some(ref etag) = output.etag {
        if let Ok(val) = HeaderValue::from_str(etag) {
            headers.insert("etag", val);
        }
    }

    if let Some(ref dt) = output.last_modified {
        let formatted = format_last_modified(dt);
        if let Ok(val) = HeaderValue::from_str(&formatted) {
            headers.insert("last-modified", val);
        }
    }

    headers
}

/// Build response headers for a successful HeadObject response.
pub fn head_object_headers(output: &HeadObjectOutput) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Some(ref ct) = output.content_type {
        if let Ok(val) = HeaderValue::from_str(ct) {
            headers.insert("content-type", val);
        }
    }

    if let Some(cl) = output.content_length {
        headers.insert("content-length", HeaderValue::from(cl));
    }

    if let Some(ref etag) = output.etag {
        if let Ok(val) = HeaderValue::from_str(etag) {
            headers.insert("etag", val);
        }
    }

    if let Some(ref dt) = output.last_modified {
        let formatted = format_last_modified(dt);
        if let Ok(val) = HeaderValue::from_str(&formatted) {
            headers.insert("last-modified", val);
        }
    }

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

    if let Some(etag) = etag {
        if let Ok(val) = HeaderValue::from_str(etag) {
            headers.insert("etag", val);
        }
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
    use std::collections::HashMap;

    #[test]
    fn test_get_object_headers_includes_all() {
        let output = GetObjectOutput {
            body: vec![],
            content_type: Some("application/json".to_string()),
            content_length: Some(256),
            etag: Some("\"abc123\"".to_string()),
            last_modified: Some(chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            metadata: HashMap::new(),
        };
        let headers = get_object_headers(&output);
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
        let output = GetObjectOutput {
            body: vec![],
            content_type: None,
            content_length: None,
            etag: None,
            last_modified: None,
            metadata: HashMap::new(),
        };
        let headers = get_object_headers(&output);
        assert!(headers.get("content-type").is_none());
        assert!(headers.get("content-length").is_none());
        assert!(headers.get("etag").is_none());
        assert!(headers.get("last-modified").is_none());
    }
}
