use std::sync::Arc;

use axum::body::Body;
use http::Response;

use crate::backend::Backend;
use crate::backend::models::PutObjectInput;
use crate::cache::CacheStore;
use crate::cache::key::CacheKey;
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::put_object_headers;
use crate::s3::ops::ParsedRequest;

/// Handle a PutObject request. On success, purges the cache for this key.
pub async fn handle_put<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    body: Body,
) -> Response<Body> {
    // NOTE: Bodies are fully buffered in memory. The retry logic uses
    // Bytes::clone() which is O(1) (reference-counted, no data copy), so
    // retries do not multiply memory usage. The configurable
    // max_request_body_bytes (default 256 MiB) caps per-request memory; set
    // it based on expected concurrent uploads and available RAM. For objects
    // larger than the limit, clients should use multipart upload.

    // Read body bytes
    let body_bytes =
        match axum::body::to_bytes(body, state.config.max_request_body_bytes as usize).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    request_id = %parsed.request_id,
                    error = %e,
                    operation = "PutObject",
                    key = key,
                    "failed to read request body"
                );
                let s3err = S3Error::from_body_error(&e, &parsed.request_id);
                return s3err.to_response();
            }
        };

    let input = PutObjectInput {
        bucket: state.backend_bucket.to_string(),
        key: key.to_string(),
        body: body_bytes.clone(),
        content_type: parsed.content_type.clone(),
        content_md5: parsed.content_md5.clone(),
        metadata: parsed.user_metadata.clone(),
        extra_amz_headers: parsed.extra_amz_headers.clone(),
        content_headers: parsed.content_headers.clone(),
    };

    // Retry handled by the backend client
    let result = state.backend.put_object(input).await;

    match result {
        Ok(output) => {
            // Purge cache for this key (best-effort with one retry)
            let cache_key = CacheKey::new(&*state.backend_bucket, key);
            super::invalidate_cache_key(
                &state.cache,
                &state.singleflight,
                &cache_key,
                "PutObject",
                key,
                &parsed.request_id,
            )
            .await;

            tracing::info!(
                request_id = %parsed.request_id,
                operation = "PutObject",
                key = key,
                "put object success"
            );

            let headers = put_object_headers(output.etag.as_deref(), &parsed.request_id);

            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            if let Some(ref vid) = output.version_id {
                response = response.header("x-amz-version-id", vid);
            }
            for (k, v) in &output.extra_headers {
                if let (Ok(name), Ok(val)) = (
                    http::header::HeaderName::from_bytes(k.as_bytes()),
                    http::header::HeaderValue::from_str(v),
                ) {
                    response = response.header(name, val);
                }
            }
            response.body(Body::empty()).unwrap()
        }
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "PutObject",
                key = key,
                "backend error"
            );
            let s3err = S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.frontend_bucket, key)),
            );
            s3err.to_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::key::CacheKey;
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};
    use std::collections::HashMap;

    fn make_parsed(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::PutObject {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
            },
            request_id: "test-req-id".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            content_length: Some(5),
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: HashMap::new(),
            extra_amz_headers: HashMap::new(),
            content_headers: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_successful_put_purges_cache() {
        let key = "script_bundle/test.js";
        let cache_key = CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, b"old content");

        let backend = MockBackend::new().with_put(Ok(crate::backend::models::PutObjectOutput {
            etag: Some("\"new-etag\"".to_string()),
            version_id: None,
            extra_headers: std::collections::HashMap::new(),
        }));

        let cache = MockCache::new().with_entry(&cache_key, b"old content", meta);

        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let body = Body::from(b"hello".to_vec());
        let resp = handle_put(&state, &parsed, key, body).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("etag").unwrap().to_str().unwrap(),
            "\"new-etag\""
        );

        // Verify cache was purged (entry should be gone)
        let cached = state.cache.lookup(&cache_key).await.unwrap();
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_put_backend_error_returns_s3_error() {
        let key = "some/key.txt";

        let backend = MockBackend::new().with_put(Err(crate::error::ProxyError::Backend {
            source: "write failed".into(),
            operation: "put_object".into(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let body = Body::from(b"data".to_vec());
        let resp = handle_put(&state, &parsed, key, body).await;

        assert_eq!(resp.status(), 502);
    }

    #[tokio::test]
    async fn test_put_success_calls_poison_on_purge_failure() {
        let key = "script_bundle/test.js";

        let backend = MockBackend::new().with_put(Ok(crate::backend::models::PutObjectOutput {
            etag: Some("\"new-etag\"".to_string()),
            version_id: None,
            extra_headers: std::collections::HashMap::new(),
        }));

        let cache = MockCache::new().with_purge_failing();
        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let body = Body::from(b"hello".to_vec());
        let resp = handle_put(&state, &parsed, key, body).await;

        // Put should succeed even though purge failed
        assert_eq!(resp.status(), 200);

        // Poison should have been called
        let poison_calls = state.cache.poison_calls.lock().unwrap();
        assert_eq!(poison_calls.len(), 1);
        let expected_key = CacheKey::new("test-backend", key);
        assert_eq!(poison_calls[0], expected_key);
    }

    #[tokio::test]
    async fn test_put_forwards_user_metadata_to_backend() {
        use crate::s3::parse::parse_request;

        let key = "some/key.txt";

        let backend = MockBackend::new().with_put(Ok(crate::backend::models::PutObjectOutput {
            etag: Some("\"etag\"".to_string()),
            version_id: None,
            extra_headers: std::collections::HashMap::new(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());

        // Build the request with actual x-amz-meta-* headers and run it
        // through parse_request to exercise the full parser contract
        // (the parser strips the "x-amz-meta-" prefix and stores bare keys).
        let req = http::Request::builder()
            .method("PUT")
            .uri("/test-frontend/some/key.txt")
            .header("x-amz-meta-author", "alice")
            .header("x-amz-meta-version", "3")
            .header("content-length", "5")
            .body(())
            .unwrap();
        let parsed = parse_request(&req);

        let body = Body::from(b"hello".to_vec());
        let resp = handle_put(&state, &parsed, key, body).await;

        assert_eq!(resp.status(), 200);

        // Verify the metadata was forwarded to the backend.
        // The parser stores bare keys (without the "x-amz-meta-" prefix),
        // and the handler forwards them as-is to the backend.
        let calls = state.backend.put_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let put_input = &calls[0];
        assert_eq!(put_input.metadata.get("author").unwrap(), "alice");
        assert_eq!(put_input.metadata.get("version").unwrap(), "3");
    }
}
