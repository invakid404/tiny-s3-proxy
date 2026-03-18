use std::sync::Arc;

use axum::body::Body;
use http::Response;

use crate::backend::Backend;
use crate::cache::key::CacheKey;
use crate::cache::CacheStore;
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::common_headers;
use crate::s3::ops::ParsedRequest;

/// Handle a DeleteObject request. On success, purges the cache for this key.
pub async fn handle_delete<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
) -> Response<Body> {
    // Retry handled by the backend client
    let result = state.backend.delete_object(&state.backend_bucket, key).await;

    match result {
        Ok(()) => {
            // Purge cache for this key (best-effort)
            let cache_key = CacheKey::new(&*state.backend_bucket, key);
            if let Err(e) = state.cache.purge(&cache_key).await {
                tracing::warn!(
                    error = %e,
                    operation = "DeleteObject",
                    key = key,
                    "failed to purge cache"
                );
            }
            state.singleflight.cancel(&cache_key).await;

            tracing::info!(
                request_id = %parsed.request_id,
                operation = "DeleteObject",
                key = key,
                "delete object success"
            );

            let headers = common_headers(&parsed.request_id);
            let mut response = Response::builder().status(204);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            response.body(Body::empty()).unwrap()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                operation = "DeleteObject",
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
    use crate::cache::key::CacheKey;
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};

    fn make_parsed(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::DeleteObject {
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
    async fn test_successful_delete_purges_cache() {
        let key = "script_bundle/test.js";
        let cache_key = CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, b"cached data");

        let backend = MockBackend::new().with_delete(Ok(()));
        let cache = MockCache::new().with_entry(&cache_key, b"cached data", meta);

        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_delete(&state, &parsed, key).await;

        assert_eq!(resp.status(), 204);

        // Verify cache was purged (entry should be gone)
        let cached = state.cache.lookup(&cache_key).await.unwrap();
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_delete_backend_error() {
        let key = "some/key.txt";

        let backend =
            MockBackend::new().with_delete(Err(crate::error::ProxyError::Backend {
                source: "delete failed".into(),
                operation: "delete_object".into(),
            }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_delete(&state, &parsed, key).await;

        assert_eq!(resp.status(), 502);
    }
}
