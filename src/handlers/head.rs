use std::sync::Arc;

use axum::body::Body;
use http::Response;

use crate::backend::retry::{with_retry, RetryPolicy};
use crate::backend::Backend;
use crate::cache::key::CacheKey;
use crate::cache::CacheStore;
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::{common_headers, head_object_headers, with_cache_status};
use crate::s3::ops::ParsedRequest;

/// Handle a HeadObject request.
///
/// If the key is cacheable and we have a cached entry, serve metadata from cache.
/// Otherwise, passthrough to the backend.
pub async fn handle_head<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
) -> Response<Body> {
    // Try cache first if key is cacheable
    if state.policy.is_cacheable(key) {
        let cache_key = CacheKey::new(&state.backend_bucket, key);
        match state.cache.lookup(&cache_key).await {
            Ok(Some(entry)) => {
                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "HeadObject",
                    key = key,
                    cache_status = "HIT",
                    "serving HEAD from cache"
                );

                let head_output = crate::backend::models::HeadObjectOutput {
                    content_type: entry.meta.content_type.clone(),
                    content_length: Some(entry.meta.content_length),
                    etag: entry.meta.etag.clone(),
                    last_modified: entry.meta.last_modified,
                    metadata: std::collections::HashMap::new(),
                };

                let mut headers = head_object_headers(&head_output);
                let common = common_headers(&parsed.request_id);
                headers.extend(common);
                with_cache_status(&mut headers, "HIT");

                let mut response = Response::builder().status(200);
                for (k, v) in headers.iter() {
                    response = response.header(k, v);
                }
                return response.body(Body::empty()).unwrap();
            }
            Ok(None) => {
                // Cache miss, fall through to backend
            }
            Err(e) => {
                tracing::warn!(
                    request_id = %parsed.request_id,
                    error = %e,
                    operation = "HeadObject",
                    key = key,
                    "cache lookup error, falling through to backend"
                );
            }
        }
    }

    // Passthrough to backend
    let backend = state.backend.clone();
    let bucket = state.backend_bucket.clone();
    let key_owned = key.to_string();
    let policy = RetryPolicy::for_reads(
        state.config.head_max_attempts,
        state.config.retry_base_backoff_ms,
    );

    let result = with_retry(&policy, "head_object", |_attempt| {
        let backend = backend.clone();
        let bucket = bucket.clone();
        let key_owned = key_owned.clone();
        async move { backend.head_object(&bucket, &key_owned).await }
    })
    .await;

    match result {
        Ok(output) => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "HeadObject",
                key = key,
                "served from backend"
            );

            let mut headers = head_object_headers(&output);
            let common = common_headers(&parsed.request_id);
            headers.extend(common);

            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            response.body(Body::empty()).unwrap()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                operation = "HeadObject",
                key = key,
                "backend error"
            );
            let s3err = S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.backend_bucket, key)),
            );
            s3err.to_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};
    use std::collections::HashMap;

    fn make_parsed(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::HeadObject {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
            },
            request_id: "test-req-id".to_string(),
            content_type: None,
            content_length: None,
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_head_from_backend() {
        let key = "logs/file.txt";

        let backend =
            MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
                content_type: Some("text/plain".to_string()),
                content_length: Some(1024),
                etag: Some("\"head-etag\"".to_string()),
                last_modified: None,
                metadata: HashMap::new(),
            }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_head(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-length")
                .unwrap()
                .to_str()
                .unwrap(),
            "1024"
        );
        assert_eq!(
            resp.headers().get("etag").unwrap().to_str().unwrap(),
            "\"head-etag\""
        );
        // Body should be empty for HEAD
        let body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_head_from_cache() {
        let key = "script_bundle/cached.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, b"cached body");

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);

        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_head(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "HIT"
        );
        // Body should be empty for HEAD
        let body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_head_backend_error() {
        let key = "logs/missing.txt";

        let backend = MockBackend::new().with_head(Err(crate::error::ProxyError::Backend {
            source: "not found".into(),
            operation: "head_object".into(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_head(&state, &parsed, key).await;

        assert_eq!(resp.status(), 502);
    }
}
