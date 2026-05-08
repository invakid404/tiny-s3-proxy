use std::collections::HashMap;

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

use crate::backend::models::{GetObjectMeta, HeadObjectOutput};

pub(crate) fn is_checksum_response_header(name: &str) -> bool {
    const PREFIX: &str = "x-amz-checksum-";
    name.len() >= PREFIX.len() && name[..PREFIX.len()].eq_ignore_ascii_case(PREFIX)
}

/// Format a DateTime to RFC 7231 (HTTP-date) format.
/// Pre-allocates the exact 29-byte capacity to avoid reallocation.
fn format_last_modified(dt: &chrono::DateTime<chrono::Utc>) -> String {
    use std::fmt::Write;
    // RFC 7231 date: "Mon, 01 Jan 2024 00:00:00 GMT" — always 29 bytes
    let mut buf = String::with_capacity(29);
    write!(buf, "{}", dt.format("%a, %d %b %Y %H:%M:%S GMT")).unwrap();
    buf
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

/// Shared helper: populate standard S3 response headers from common fields.
fn build_object_headers_common(
    content_type: Option<&str>,
    content_length: Option<i64>,
    etag: Option<&str>,
    last_modified: Option<&chrono::DateTime<chrono::Utc>>,
    metadata: &HashMap<String, String>,
    extra_headers: &HashMap<String, String>,
    include_checksum_headers: bool,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    if let Some(ct) = content_type
        && let Ok(val) = HeaderValue::from_str(ct)
    {
        headers.insert("content-type", val);
    }

    if let Some(cl) = content_length {
        headers.insert("content-length", HeaderValue::from(cl));
    }

    if let Some(etag) = etag
        && let Ok(val) = HeaderValue::from_str(etag)
    {
        headers.insert("etag", val);
    }

    if let Some(dt) = last_modified
        && let Ok(val) = HeaderValue::from_str(&format_last_modified(dt))
    {
        headers.insert("last-modified", val);
    }

    headers.extend(metadata_headers(metadata));

    let filtered = extra_headers
        .iter()
        .filter(|(k, _)| include_checksum_headers || !is_checksum_response_header(k.as_str()));
    for (name, val) in parse_valid_extra_headers(filtered) {
        headers.insert(name, val);
    }

    headers
}

/// Build response headers for a successful GetObject response.
pub fn get_object_headers(meta: &GetObjectMeta, include_checksum_headers: bool) -> HeaderMap {
    build_object_headers_common(
        meta.content_type.as_deref(),
        meta.content_length,
        meta.etag.as_deref(),
        meta.last_modified.as_ref(),
        &meta.metadata,
        &meta.extra_headers,
        include_checksum_headers,
    )
}

/// Build response headers for a successful HeadObject response.
pub fn head_object_headers(output: &HeadObjectOutput, include_checksum_headers: bool) -> HeaderMap {
    build_object_headers_common(
        output.content_type.as_deref(),
        output.content_length,
        output.etag.as_deref(),
        output.last_modified.as_ref(),
        &output.metadata,
        &output.extra_headers,
        include_checksum_headers,
    )
}

/// Build common S3 response headers.
/// Pre-allocates capacity for 3 headers and uses `from_static` for constant values.
pub fn common_headers(request_id: &str) -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(3);

    headers.insert("server", HeaderValue::from_static("tiny-s3-proxy"));
    headers.insert("x-amz-id-2", HeaderValue::from_static("tiny-s3-proxy-id-2"));
    if let Ok(val) = HeaderValue::from_str(request_id) {
        headers.insert("x-amz-request-id", val);
    }

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

/// Parse a `(String, String)` extra-headers iterable into validated
/// `(HeaderName, HeaderValue)` pairs, silently dropping entries with invalid
/// names or values. Used by callers that need to forward backend-supplied
/// extra headers onto a response.
pub fn parse_valid_extra_headers<'a, I>(
    extra: I,
) -> impl Iterator<Item = (HeaderName, HeaderValue)> + 'a
where
    I: IntoIterator<Item = (&'a String, &'a String)> + 'a,
{
    extra.into_iter().filter_map(|(k, v)| {
        match (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            (Ok(name), Ok(val)) => Some((name, val)),
            _ => None,
        }
    })
}

/// Append extra headers from a HashMap to a response builder, silently
/// skipping entries with invalid header names or values.
pub fn append_extra_headers(
    mut builder: http::response::Builder,
    headers: &HashMap<String, String>,
) -> http::response::Builder {
    for (name, val) in parse_valid_extra_headers(headers) {
        builder = builder.header(name, val);
    }
    builder
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
            extra_headers: HashMap::new(),
        };
        let headers = get_object_headers(&meta, false);
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
            extra_headers: HashMap::new(),
        };
        let headers = head_object_headers(&output, false);
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
            extra_headers: HashMap::new(),
        };
        let headers = get_object_headers(&meta, false);
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
            extra_headers: HashMap::new(),
        };
        let headers = get_object_headers(&meta, false);
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
            extra_headers: HashMap::new(),
        };
        let headers = head_object_headers(&output, false);
        assert_eq!(headers.get("x-amz-meta-tag").unwrap(), "test");
        assert_eq!(headers.get("content-length").unwrap(), "200");
    }

    #[test]
    fn test_get_object_headers_filters_checksum_headers() {
        let mut extra_headers = HashMap::new();
        extra_headers.insert("x-amz-checksum-sha256".to_string(), "abc".to_string());
        extra_headers.insert("cache-control".to_string(), "max-age=60".to_string());

        let meta = GetObjectMeta {
            content_type: None,
            content_length: None,
            etag: None,
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        };

        let headers = get_object_headers(&meta, false);
        assert!(headers.get("x-amz-checksum-sha256").is_none());
        assert_eq!(headers.get("cache-control").unwrap(), "max-age=60");

        let headers = get_object_headers(&meta, true);
        assert_eq!(headers.get("x-amz-checksum-sha256").unwrap(), "abc");
    }

    #[test]
    fn test_is_checksum_response_header_case_insensitive() {
        assert!(is_checksum_response_header("x-amz-checksum-sha256"));
        assert!(is_checksum_response_header("X-Amz-Checksum-SHA256"));
        assert!(is_checksum_response_header("X-AMZ-CHECKSUM-CRC32"));
        assert!(is_checksum_response_header("x-AmZ-cHeCkSuM-crc32c"));
        assert!(!is_checksum_response_header("x-amz-meta-checksum"));
        assert!(!is_checksum_response_header("x-amz-checksum"));
        assert!(!is_checksum_response_header(""));
    }

    #[test]
    fn test_get_object_headers_filters_mixed_case_checksum_headers() {
        let mut extra_headers = HashMap::new();
        extra_headers.insert("X-Amz-Checksum-CRC32".to_string(), "abc".to_string());
        extra_headers.insert("Cache-Control".to_string(), "max-age=60".to_string());

        let meta = GetObjectMeta {
            content_type: None,
            content_length: None,
            etag: None,
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        };

        let headers = get_object_headers(&meta, false);
        assert!(headers.get("x-amz-checksum-crc32").is_none());
        assert_eq!(headers.get("cache-control").unwrap(), "max-age=60");
    }

    #[test]
    fn test_head_object_headers_filters_checksum_headers() {
        let mut extra_headers = HashMap::new();
        extra_headers.insert("x-amz-checksum-crc32".to_string(), "xyz".to_string());
        extra_headers.insert("cache-control".to_string(), "no-store".to_string());

        let output = HeadObjectOutput {
            content_type: None,
            content_length: Some(1),
            etag: None,
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        };

        let headers = head_object_headers(&output, false);
        assert!(headers.get("x-amz-checksum-crc32").is_none());
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");

        let headers = head_object_headers(&output, true);
        assert_eq!(headers.get("x-amz-checksum-crc32").unwrap(), "xyz");
        assert_eq!(headers.get("cache-control").unwrap(), "no-store");
    }
}
