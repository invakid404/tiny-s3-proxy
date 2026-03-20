use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use bytes::Bytes;
use http::Response;
use tokio_util::io::ReaderStream;

use crate::backend::models::GetObjectMeta;
use crate::backend::{Backend, BoxByteStream};
use crate::cache::entry::CacheEntry;
use crate::cache::key::CacheKey;
use crate::cache::metadata::CacheMeta;
use crate::cache::{CacheStore, FlightResult};
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::{common_headers, get_object_headers, with_cache_status};
use crate::s3::ops::ParsedRequest;

/// Build an HTTP response from metadata + a streaming body.
fn build_streaming_response(
    meta: &GetObjectMeta,
    body_stream: BoxByteStream,
    request_id: &str,
    cache_status: &str,
) -> Response<Body> {
    let mut headers = get_object_headers(meta);
    let common = common_headers(request_id);
    headers.extend(common);
    with_cache_status(&mut headers, cache_status);

    let mut response = Response::builder().status(200);
    for (k, v) in headers.iter() {
        response = response.header(k, v);
    }
    response.body(Body::from_stream(body_stream)).unwrap()
}

/// Build an HTTP response from metadata + an already-constructed Body.
fn build_meta_response(
    meta: &GetObjectMeta,
    body: Body,
    request_id: &str,
    cache_status: &str,
) -> Response<Body> {
    let mut headers = get_object_headers(meta);
    let common = common_headers(request_id);
    headers.extend(common);
    with_cache_status(&mut headers, cache_status);

    let mut response = Response::builder().status(200);
    for (k, v) in headers.iter() {
        response = response.header(k, v);
    }
    response.body(body).unwrap()
}

/// Open a cached body file and return a boxed stream of chunks.
async fn open_file_stream(
    path: &std::path::Path,
) -> Result<BoxByteStream, std::io::Error> {
    let file = tokio::fs::File::open(path).await?;
    Ok(Box::pin(ReaderStream::with_capacity(file, 65536))) // 64KB chunks
}

/// Build response from a CacheEntry (streams from disk, no buffering).
/// Try to build a response from a cached entry. Returns `None` if the body
/// file has disappeared (e.g. eviction/purge race), signaling the caller
/// should fall back to the backend rather than returning a 500.
async fn build_cache_response(
    entry: &CacheEntry,
    request_id: &str,
    cache_status: &str,
) -> Option<Response<Body>> {
    let meta = GetObjectMeta {
        content_type: entry.meta.content_type.clone(),
        content_length: Some(entry.meta.content_length),
        etag: entry.meta.etag.clone(),
        last_modified: entry.meta.last_modified,
        metadata: entry.meta.metadata.clone(),
        extra_headers: entry.meta.extra_headers.clone(),
    };

    let body_path = entry.body_path.clone();
    match open_file_stream(&body_path).await {
        Ok(stream) => {
            let mut headers = get_object_headers(&meta);
            let common = common_headers(request_id);
            headers.extend(common);
            with_cache_status(&mut headers, cache_status);

            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            Some(response.body(Body::from_stream(stream)).unwrap())
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %body_path.display(),
                "cache body file disappeared after lookup; treating as miss"
            );
            None
        }
    }
}

/// Handle a GetObject request with caching, singleflight, and stale-on-error.
pub async fn handle_get<B: Backend + 'static, C: CacheStore + 'static>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
) -> Response<Body> {
    // Range requests are routed through raw passthrough at the dispatch layer
    // (handlers/mod.rs) to preserve the Range header. This is a defensive
    // fallback for any edge case where a ranged request reaches this handler.
    if parsed.range.is_some() {
        tracing::info!(
            request_id = %parsed.request_id,
            operation = "GetObject",
            key = key,
            cache_status = "BYPASS",
            "range request, bypassing cache"
        );
        return handle_passthrough(state, parsed, key, "BYPASS").await;
    }

    // Check if key is cacheable
    if !state.policy.is_cacheable(key) {
        tracing::info!(
            request_id = %parsed.request_id,
            operation = "GetObject",
            key = key,
            cache_status = "BYPASS",
            "key not cacheable"
        );
        return handle_passthrough(state, parsed, key, "BYPASS").await;
    }

    // Try cache lookup
    let cache_key = CacheKey::new(&*state.backend_bucket, key);
    match state.cache.lookup(&cache_key).await {
        Ok(Some(entry)) => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                cache_status = "HIT",
                "serving from cache"
            );
            if let Some(resp) = build_cache_response(&entry, &parsed.request_id, "HIT").await {
                return resp;
            }
            // Body file disappeared — fall through to backend
        }
        Ok(None) => {
            // Cache miss, proceed to singleflight
        }
        Err(e) => {
            tracing::warn!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "GetObject",
                key = key,
                "cache lookup error, falling through to backend"
            );
        }
    }

    // Cache miss -> singleflight
    let flight_result = state.singleflight.try_acquire(&cache_key).await;

    match flight_result {
        FlightResult::Leader { waiter } => {
            handle_leader(state, parsed, key, &cache_key, waiter).await
        }
        FlightResult::Follower { mut receiver } => {
            handle_follower(state, parsed, key, &cache_key, &mut receiver).await
        }
    }
}

/// Handle passthrough: fetch from backend, stream directly, no caching.
async fn handle_passthrough<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    cache_status: &str,
) -> Response<Body> {
    match state
        .backend
        .get_object(&state.backend_bucket, key)
        .await
    {
        Ok((meta, body_stream)) => {
            build_streaming_response(&meta, body_stream, &parsed.request_id, cache_status)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                operation = "GetObject",
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

/// Leader path: fetch from backend, tee stream to cache + client.
async fn handle_leader<B: Backend + 'static, C: CacheStore + 'static>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    cache_key: &CacheKey,
    waiter: crate::cache::FlightWaiter,
) -> Response<Body> {
    // Register fill BEFORE the backend fetch so that any purge() during
    // the round-trip bumps the generation counter, causing commit_fill to
    // reject the stale response. Without this, a purge during the GET
    // would find no active fill entry to invalidate.
    let fill_guard = state.cache.begin_fill(cache_key).await.ok();

    let result = state
        .backend
        .get_object(&state.backend_bucket, key)
        .await;

    match result {
        Ok((meta, body_stream)) => {
            // Only cache when content_length is known; unknown-length responses
            // could be arbitrarily large and bypass cache_max_object_bytes.
            let is_size_cacheable = meta
                .content_length
                .map(|len| state.policy.is_size_cacheable(len as u64))
                .unwrap_or(false);

            if is_size_cacheable {
                // Tee: stream to client AND write to cache
                let (tx, rx) =
                    tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);

                let temp_body_path = PathBuf::from(&state.config.cache_dir)
                    .join("tmp")
                    .join(format!("{}-{}.body", std::process::id(), crate::request_id::generate()));

                let cache = state.cache.clone();

                let cache_meta = CacheMeta {
                    bucket: state.backend_bucket.to_string(),
                    key: key.to_string(),
                    etag: meta.etag.clone(),
                    last_modified: meta.last_modified,
                    content_type: meta.content_type.clone(),
                    content_length: meta.content_length.unwrap_or(0),
                    cache_written_at: chrono::Utc::now(),
                    last_accessed_at: chrono::Utc::now(),
                    hit_count: 0,
                    source_status: 200,
                    metadata: meta.metadata.clone(),
                    extra_headers: meta.extra_headers.clone(),
                };
                let temp_path_clone = temp_body_path.clone();

                // Spawn tee task
                tokio::spawn(async move {
                    use futures_util::StreamExt;
                    use tokio::io::AsyncWriteExt;

                    let mut file = match tokio::fs::File::create(&temp_path_clone).await {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::warn!("cache fill: failed to create temp file: {}", e);
                            if let Some(guard) = fill_guard {
                                cache.abort_fill(guard).await;
                            }
                            // Drain stream to client without caching
                            let mut stream = body_stream;
                            while let Some(chunk) = stream.next().await {
                                let _ = tx.send(chunk).await;
                            }
                            waiter.complete().await;
                            return;
                        }
                    };

                    let mut stream = body_stream;
                    let mut cache_ok = true;

                    while let Some(chunk_result) = stream.next().await {
                        match chunk_result {
                            Ok(chunk) => {
                                if cache_ok
                                    && let Err(e) = file.write_all(&chunk).await
                                {
                                    tracing::warn!("cache fill: write error: {}", e);
                                    cache_ok = false;
                                }
                                // Send to client; if client disconnected, still
                                // continue writing to disk so cache fills for followers.
                                let _ = tx.send(Ok(chunk)).await;
                            }
                            Err(e) => {
                                let _ = tx
                                    .send(Err(std::io::Error::other(e.to_string())))
                                    .await;
                                cache_ok = false;
                                break;
                            }
                        }
                    }

                    // Drop sender so the client body ends
                    drop(tx);

                    if cache_ok {
                        if let Err(e) = file.sync_all().await {
                            tracing::warn!("cache fill: fsync error: {}", e);
                            if let Some(guard) = fill_guard {
                                cache.abort_fill(guard).await;
                            }
                            let _ = tokio::fs::remove_file(&temp_path_clone).await;
                            waiter.complete().await;
                            return;
                        }
                        drop(file);

                        if let Some(guard) = fill_guard {
                            // commit_fill always cleans up active_fills internally
                            // (on success, rejection, and error).
                            if let Err(e) = cache
                                .commit_fill(guard, temp_path_clone.clone(), cache_meta)
                                .await
                            {
                                tracing::warn!("cache fill: commit error: {}", e);
                                let _ = tokio::fs::remove_file(&temp_path_clone).await;
                            }
                        } else {
                            tracing::warn!("cache fill: no fill guard, skipping cache commit");
                            let _ = tokio::fs::remove_file(&temp_path_clone).await;
                        }
                    } else {
                        if let Some(guard) = fill_guard {
                            cache.abort_fill(guard).await;
                        }
                        let _ = tokio::fs::remove_file(&temp_path_clone).await;
                    }

                    waiter.complete().await;
                });

                // Build response from channel receiver
                let body = Body::from_stream(
                    tokio_stream::wrappers::ReceiverStream::new(rx),
                );

                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    cache_status = "MISS",
                    cached = true,
                    "serving from backend (tee to cache)"
                );

                build_meta_response(&meta, body, &parsed.request_id, "MISS")
            } else {
                // Too large to cache — abort the pre-registered fill.
                if let Some(guard) = fill_guard {
                    state.cache.abort_fill(guard).await;
                }
                waiter.complete().await;

                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    cache_status = "MISS",
                    cached = false,
                    "served from backend (too large to cache)"
                );

                build_streaming_response(
                    &meta,
                    body_stream,
                    &parsed.request_id,
                    "MISS",
                )
            }
        }
        Err(e) => {
            // Backend failed — abort the pre-registered fill.
            if let Some(guard) = fill_guard {
                state.cache.abort_fill(guard).await;
            }
            // Try serving stale from cache if configured.
            if state.config.cache_serve_stale_on_error
                && e.is_transient()
                && let Ok(Some(stale_entry)) = state.cache.lookup(cache_key).await
            {
                tracing::warn!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    cache_status = "STALE",
                    error = %e,
                    "serving stale cache entry on backend error"
                );
                if let Some(resp) = build_cache_response(
                    &stale_entry,
                    &parsed.request_id,
                    "STALE",
                )
                .await {
                    waiter.complete().await;
                    return resp;
                }
                // Stale body disappeared — fall through to error
            }

            // No stale entry available (or stale body disappeared)
            waiter.complete().await;
            tracing::error!(
                error = %e,
                operation = "GetObject",
                key = key,
                "backend error, no stale cache entry"
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

/// Follower path: wait for leader, then re-read from cache or fetch directly.
async fn handle_follower<B: Backend + 'static, C: CacheStore + 'static>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    cache_key: &CacheKey,
    receiver: &mut tokio::sync::broadcast::Receiver<()>,
) -> Response<Body> {
    // Wait for leader to complete (or drop)
    let _ = receiver.recv().await;

    // Re-read from cache
    match state.cache.lookup(cache_key).await {
        Ok(Some(entry)) => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                cache_status = "HIT",
                "follower served from cache after leader"
            );
            if let Some(resp) = build_cache_response(&entry, &parsed.request_id, "HIT").await {
                return resp;
            }
            // Body file disappeared — fall through to direct backend fetch
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                "follower cache body disappeared, fetching from backend"
            );
            return handle_passthrough(state, parsed, key, "MISS").await;
        }
        _ => {
            // Leader may have failed or object was too large to cache.
            // Fetch directly from backend (no singleflight to avoid recursion).
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                "follower cache miss, fetching from backend directly"
            );
            handle_passthrough(state, parsed, key, "MISS").await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::cache::key::CacheKey;
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};

    fn make_parsed(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::GetObject {
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
            user_metadata: HashMap::new(),
            extra_amz_headers: HashMap::new(),
            content_headers: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let key = "script_bundle/test.js";
        let body = b"console.log('hello')".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, &body);

        let cache = MockCache::new().with_entry(&cache_key, &body, meta);

        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_get(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "HIT"
        );
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(resp_body.as_ref(), body.as_slice());
    }

    #[tokio::test]
    async fn test_cache_miss_fills_cache() {
        let key = "script_bundle/test.js";
        let body = b"console.log('miss')".to_vec();

        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: body.clone(),
            content_type: Some("application/javascript".to_string()),
            etag: Some("\"etag-miss\"".to_string()),
        }));
        let cache = MockCache::new();

        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_get(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "MISS"
        );
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(resp_body.as_ref(), body.as_slice());

        // Verify cache was filled: wait a moment for the tee task to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let cache_key = CacheKey::new("test-backend", key);
        let cached = state.cache.lookup(&cache_key).await.unwrap();
        assert!(cached.is_some());
        let entry = cached.unwrap();
        let cached_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(cached_body, body);
    }

    #[tokio::test]
    async fn test_bypass_for_non_cacheable_prefix() {
        let key = "logs/output.log";
        let body = b"log data".to_vec();

        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: body.clone(),
            content_type: Some("text/plain".to_string()),
            etag: None,
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_get(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "BYPASS"
        );
    }

    #[tokio::test]
    async fn test_backend_error_no_cache_returns_s3_error() {
        let key = "script_bundle/missing.js";

        let backend = MockBackend::new().with_get(Err(crate::error::ProxyError::Backend {
            source: "not found".into(),
            operation: "get_object".into(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_get(&state, &parsed, key).await;

        assert_eq!(resp.status(), 502);
        let body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("InternalError"));
    }

    #[tokio::test]
    async fn test_stale_on_error() {
        let key = "script_bundle/stale.js";
        let stale_body = b"stale content".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, &stale_body);

        // Backend will fail
        let backend = MockBackend::new().with_get(Err(crate::error::ProxyError::Backend {
            source: "backend down".into(),
            operation: "get_object".into(),
        }));

        // Cache has a stale entry
        let cache = MockCache::new().with_entry(&cache_key, &stale_body, meta);

        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        // Note: with the current MockCache, the initial lookup returns the entry
        // (HIT path) since the entry is always present. This test verifies the
        // HIT path works with the cached entry present.
        let resp = handle_get(&state, &parsed, key).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "HIT"
        );
    }

    // ---- StaleMockCache: returns None on first lookup, Some on subsequent ----
    //
    // This is needed to exercise the TRUE stale-on-error code path, where:
    //   1. Initial cache.lookup() returns None (miss) → enters singleflight
    //   2. Backend returns a transient error
    //   3. Stale fallback calls cache.lookup() again → returns the entry
    //   4. Handler serves the cached entry with x-cache: STALE

    use std::sync::atomic::{AtomicU32, Ordering};

    struct StaleMockCache {
        /// The entry to serve on the stale (second) lookup.
        entry: Option<CacheEntry>,
        lookup_count: AtomicU32,
        temp_dir: tempfile::TempDir,
    }

    impl StaleMockCache {
        #[allow(dead_code)]
        fn new(entry: Option<CacheEntry>) -> Self {
            Self {
                entry,
                lookup_count: AtomicU32::new(0),
                temp_dir: tempfile::TempDir::new().expect("create stale mock temp dir"),
            }
        }
    }

    impl CacheStore for StaleMockCache {
        async fn lookup(
            &self,
            _key: &CacheKey,
        ) -> Result<Option<CacheEntry>, crate::error::ProxyError> {
            let count = self.lookup_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // First lookup: simulate cache miss
                Ok(None)
            } else {
                // Subsequent lookups: return the stale entry (if any)
                Ok(self.entry.as_ref().map(|e| CacheEntry {
                    meta: e.meta.clone(),
                    body_path: e.body_path.clone(),
                }))
            }
        }

        async fn begin_fill(
            &self,
            key: &CacheKey,
        ) -> Result<crate::cache::FillGuard, crate::error::ProxyError> {
            Ok(crate::cache::FillGuard {
                key: key.clone(),
                temp_dir: self.temp_dir.path().to_path_buf(),
                generation: 0,
            })
        }

        async fn abort_fill(&self, _guard: crate::cache::FillGuard) {}

        async fn commit_fill(
            &self,
            _guard: crate::cache::FillGuard,
            _temp_body_path: std::path::PathBuf,
            _meta: crate::cache::metadata::CacheMeta,
        ) -> Result<(), crate::error::ProxyError> {
            Ok(())
        }

        async fn purge(
            &self,
            _key: &CacheKey,
        ) -> Result<bool, crate::error::ProxyError> {
            Ok(false)
        }

        async fn poison(
            &self,
            _key: &CacheKey,
        ) -> Result<(), crate::error::ProxyError> {
            Ok(())
        }

        async fn stats(&self) -> crate::cache::CacheStatsSnapshot {
            crate::cache::CacheStatsSnapshot::default()
        }
    }

    /// Build an AppState using StaleMockCache instead of MockCache.
    fn build_stale_app_state(
        backend: MockBackend,
        cache: StaleMockCache,
        auth: MockAuth,
        stale_on_error: bool,
    ) -> Arc<AppState<MockBackend, StaleMockCache>> {
        let mut config = test_config();
        config.cache_dir = cache.temp_dir.path().to_str().unwrap().to_string();
        config.cache_serve_stale_on_error = stale_on_error;
        let tmp_dir = cache.temp_dir.path().join("tmp");
        let _ = std::fs::create_dir_all(&tmp_dir);

        Arc::new(AppState {
            backend: Arc::new(backend),
            cache: Arc::new(cache),
            singleflight: Arc::new(crate::cache::SingleFlight::new()),
            auth: Arc::new(auth),
            policy: crate::cache::policy::CachePolicy::new(
                config.cacheable_prefixes.clone(),
                config.cache_max_object_bytes,
            ),
            frontend_bucket: Arc::from(config.frontend_bucket.as_str()),
            backend_bucket: Arc::from(config.backend_bucket.as_str()),
            http_client: reqwest::Client::new(),
            config: Arc::new(config),
        })
    }

    /// Create a CacheEntry with a real body file in the given temp dir.
    fn make_stale_entry(
        temp_dir: &std::path::Path,
        bucket: &str,
        key: &str,
        body: &[u8],
    ) -> CacheEntry {
        let body_path = temp_dir.join("stale-test.body");
        std::fs::write(&body_path, body).expect("write stale body file");
        CacheEntry {
            meta: test_cache_meta(bucket, key, body),
            body_path,
        }
    }

    #[tokio::test]
    async fn test_true_stale_on_error_serves_cached_entry() {
        let key = "script_bundle/stale-test.js";
        let stale_body = b"stale javascript content".to_vec();

        // Build the StaleMockCache: first lookup → None, second → Some
        let temp_dir = tempfile::TempDir::new().unwrap();
        let entry = make_stale_entry(temp_dir.path(), "test-backend", key, &stale_body);
        let cache = StaleMockCache {
            entry: Some(entry),
            lookup_count: AtomicU32::new(0),
            temp_dir,
        };

        // Backend returns a transient error
        let backend = MockBackend::new().with_get(Err(crate::error::ProxyError::Backend {
            source: "connection refused".into(),
            operation: "get_object".into(),
        }));

        let state = build_stale_app_state(backend, cache, MockAuth::allow_all(), true);
        let parsed = make_parsed(key);

        let resp = handle_get(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "STALE",
        );
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(resp_body.as_ref(), stale_body.as_slice());

        // Verify two lookups occurred (initial miss + stale fallback)
        assert_eq!(state.cache.lookup_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_stale_disabled_returns_error() {
        let key = "script_bundle/stale-disabled.js";
        let stale_body = b"should not be served".to_vec();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let entry = make_stale_entry(temp_dir.path(), "test-backend", key, &stale_body);
        let cache = StaleMockCache {
            entry: Some(entry),
            lookup_count: AtomicU32::new(0),
            temp_dir,
        };

        let backend = MockBackend::new().with_get(Err(crate::error::ProxyError::Backend {
            source: "backend down".into(),
            operation: "get_object".into(),
        }));

        // stale_on_error = false
        let state = build_stale_app_state(backend, cache, MockAuth::allow_all(), false);
        let parsed = make_parsed(key);

        let resp = handle_get(&state, &parsed, key).await;

        assert_eq!(resp.status(), 502);
        // The stale fallback lookup should NOT have been attempted
        assert_eq!(state.cache.lookup_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_stale_non_transient_error_not_served() {
        let key = "script_bundle/gone.js";
        let stale_body = b"should not be served for 404".to_vec();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let entry = make_stale_entry(temp_dir.path(), "test-backend", key, &stale_body);
        let cache = StaleMockCache {
            entry: Some(entry),
            lookup_count: AtomicU32::new(0),
            temp_dir,
        };

        // 404 is NOT transient — stale should not be served
        let backend = MockBackend::new().with_get(Err(crate::error::ProxyError::UpstreamS3 {
            status_code: 404,
            s3_code: "NoSuchKey".into(),
            message: "The specified key does not exist.".into(),
            operation: "get_object".into(),
        }));

        let state = build_stale_app_state(backend, cache, MockAuth::allow_all(), true);
        let parsed = make_parsed(key);

        let resp = handle_get(&state, &parsed, key).await;

        assert_eq!(resp.status(), 404);
        // Only the initial lookup, no stale fallback for non-transient errors
        assert_eq!(state.cache.lookup_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_follower_gets_cache_after_leader_fills() {
        let key = "script_bundle/follower-test.js";
        let body = b"leader-filled content".to_vec();
        let cache_key = CacheKey::new("test-backend", key);

        // Backend returns a successful response (leader will fill cache)
        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: body.clone(),
            content_type: Some("application/javascript".to_string()),
            etag: Some("\"etag-follower\"".to_string()),
        }));
        let cache = MockCache::new();
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        // Pre-acquire singleflight to become leader for this key
        let flight_result = state.singleflight.try_acquire(&cache_key).await;
        let waiter = match flight_result {
            crate::cache::FlightResult::Leader { waiter } => waiter,
            _ => panic!("expected to be leader"),
        };

        // Spawn a follower task — it will block waiting for the leader
        let state_clone = Arc::clone(&state);
        let parsed = make_parsed(key);
        let key_owned = key.to_string();
        let follower = tokio::spawn(async move {
            handle_get(&state_clone, &parsed, &key_owned).await
        });

        // Give the follower time to enter the waiting state
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Simulate leader completing: write entry to cache, then signal
        let meta = test_cache_meta("test-backend", key, &body);
        let body_path = state.cache.temp_dir.path().join("follower-test.body");
        tokio::fs::write(&body_path, &body).await.unwrap();
        let entry = CacheEntry {
            meta,
            body_path,
        };
        state
            .cache
            .entries
            .lock()
            .unwrap()
            .insert(cache_key.hash_hex(), entry);

        // Signal followers
        waiter.complete().await;

        // Follower should return 200 with HIT from cache
        let resp = follower.await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "HIT",
        );
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(resp_body.as_ref(), body.as_slice());
    }
}
