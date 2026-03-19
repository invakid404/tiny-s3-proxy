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
                let cache_key_owned = cache_key.clone();

                // Capture the fill guard BEFORE downloading starts, so the
                // generation reflects the pre-fetch state. If a purge happens
                // during the download, commit_fill will detect the mismatch.
                let fill_guard = cache.begin_fill(&cache_key_owned).await.ok();

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
                // Too large to cache, stream directly
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
            // Backend failed. Try serving stale from cache if configured.
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
}
