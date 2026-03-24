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
use crate::cache::{CacheStore, FlightResult, FlightWaiter};
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::{
    common_headers, get_object_headers, is_checksum_response_header, metadata_headers,
    with_cache_status,
};
use crate::s3::ops::ParsedRequest;

use super::purge_then_poison_if_unchanged;

/// Build an HTTP response from metadata + a streaming body.
fn build_streaming_response(
    meta: &GetObjectMeta,
    body_stream: BoxByteStream,
    request_id: &str,
    cache_status: &str,
    include_checksum_headers: bool,
) -> Response<Body> {
    let mut headers = get_object_headers(meta, include_checksum_headers);
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
    include_checksum_headers: bool,
) -> Response<Body> {
    let mut headers = get_object_headers(meta, include_checksum_headers);
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
    file: Option<tokio::fs::File>,
    path: &std::path::Path,
) -> Result<BoxByteStream, std::io::Error> {
    let file = match file {
        Some(file) => file,
        None => tokio::fs::File::open(path).await?,
    };
    Ok(Box::pin(ReaderStream::with_capacity(file, 65536))) // 64KB chunks
}

/// Build response from a CacheEntry (streams from disk, no buffering).
/// Try to build a response from a cached entry. Returns `None` if the body
/// file has disappeared (e.g. eviction/purge race), signaling the caller
/// should fall back to the backend rather than returning a 500.
///
/// Builds headers directly from `CacheMeta` references, avoiding the
/// HashMap clones that constructing an intermediate `GetObjectMeta` would
/// require.
async fn build_cache_response(
    entry: CacheEntry,
    request_id: &str,
    cache_status: &str,
    include_checksum_headers: bool,
) -> Option<Response<Body>> {
    let body_path = entry.body_path.clone();
    match open_file_stream(entry.body_file, &body_path).await {
        Ok(stream) => {
            let m = &entry.meta;
            let mut headers = http::HeaderMap::new();

            if let Some(ref ct) = m.content_type {
                if let Ok(val) = http::header::HeaderValue::from_str(ct) {
                    headers.insert("content-type", val);
                }
            }
            headers.insert(
                "content-length",
                http::header::HeaderValue::from(m.content_length),
            );
            if let Some(ref etag) = m.etag {
                if let Ok(val) = http::header::HeaderValue::from_str(etag) {
                    headers.insert("etag", val);
                }
            }
            if let Some(ref dt) = m.last_modified {
                let formatted = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
                if let Ok(val) = http::header::HeaderValue::from_str(&formatted) {
                    headers.insert("last-modified", val);
                }
            }
            headers.extend(metadata_headers(&m.metadata));
            for (k, v) in &m.extra_headers {
                if !include_checksum_headers && is_checksum_response_header(k.as_str()) {
                    continue;
                }
                if let (Ok(name), Ok(val)) = (
                    http::header::HeaderName::from_bytes(k.as_bytes()),
                    http::header::HeaderValue::from_str(v),
                ) {
                    headers.insert(name, val);
                }
            }

            headers.extend(common_headers(request_id));
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

fn cache_entry_satisfies_read_options(
    entry: &CacheEntry,
    options: crate::backend::models::ReadOptions,
) -> bool {
    !options.wants_checksum_headers() || entry.meta.checksum_mode_checked
}

/// Attempt a HEAD-based metadata refresh for a checksum-mode GET on a
/// plain-warmed cache entry. This is called when `checksum_mode_checked` is
/// false, meaning the entry was filled by a plain GET that didn't request
/// checksum headers.
///
/// Design tradeoff: the first checksum-mode GET after a plain fill always
/// pays HEAD + GET because HEAD cannot set `checksum_mode_checked` (HEAD
/// and GET can return different checksum surfaces on some backends). The
/// HEAD probes for ETag validity and enriches HEAD-specific metadata, but
/// the GET must still follow to populate the GET-shared checksum surface.
/// This is a one-time warm-up cost per cache entry.
async fn try_refresh_cached_get_metadata<B: Backend + 'static, C: CacheStore + 'static>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    cache_key: &CacheKey,
    entry: &CacheEntry,
) -> Option<Response<Body>> {
    let read_options = parsed.read_options();
    if !read_options.wants_checksum_headers() || entry.meta.checksum_mode_checked {
        return None;
    }

    let head_output = match state
        .backend
        .head_object(&state.backend_bucket, key, read_options)
        .await
    {
        Ok(output) => output,
        Err(e) => {
            if matches!(
                &e,
                crate::error::ProxyError::UpstreamS3 {
                    status_code: 404,
                    ..
                }
            ) {
                let invalidated = purge_then_poison_if_unchanged(
                    &state.cache,
                    cache_key,
                    entry.meta.fill_id,
                    &parsed.request_id,
                    "GetObject",
                    key,
                    "purged stale cache entry after HEAD returned not found during GET refresh",
                    "HEAD returned not found during GET refresh, but cache entry changed before invalidation",
                    "failed to purge stale cache entry after HEAD returned not found during GET refresh",
                    "poisoned stale cache entry after purge failure during GET refresh",
                    "failed to poison stale cache entry after purge failure during GET refresh",
                )
                .await;

                if invalidated {
                    // The 404 is authoritative for the generation we observed.
                    let _ = state.cache.note_miss().await;
                    let s3err = S3Error::from_proxy_error(
                        &e,
                        &parsed.request_id,
                        Some(&format!("/{}/{}", state.frontend_bucket, key)),
                    );
                    return Some(s3err.to_response());
                }
                // purge_if_unchanged returned false — a concurrent refill
                // replaced the entry. The 404 is stale; fall through to let
                // the caller re-probe and serve the newer entry or continue
                // upstream. (Same pattern as the transient-error re-probe in
                // handle_head stale fallback at src/handlers/head.rs.)
                return None;
            }
            tracing::warn!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                error = %e,
                "failed to refresh cached GET metadata via HEAD"
            );
            return None;
        }
    };

    match crate::handlers::head::refreshed_cache_meta(
        &entry.meta,
        &head_output,
        read_options.wants_checksum_headers(),
    ) {
        crate::handlers::head::CacheRefreshOutcome::Updated(updated_meta) => {
            match state
                .cache
                .update_metadata_if_unchanged(cache_key, entry.meta.fill_id, updated_meta)
                .await
            {
                Ok(true) => {
                    // Metadata persisted but checksum_mode_checked is still
                    // false (HEAD can't flip it), so the entry won't satisfy
                    // a checksum GET — skip the re-probe and fall through to
                    // the backend GET path.
                    return None;
                }
                Ok(false) => {
                    tracing::info!(
                        request_id = %parsed.request_id,
                        operation = "GetObject",
                        key = key,
                        "metadata refresh lost race, entry was replaced"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        request_id = %parsed.request_id,
                        operation = "GetObject",
                        key = key,
                        error = %e,
                        "failed to persist refreshed GET metadata from HEAD"
                    );
                    return None;
                }
            }
        }
        crate::handlers::head::CacheRefreshOutcome::EtagMismatch => {
            let _ = purge_then_poison_if_unchanged(
                &state.cache,
                cache_key,
                entry.meta.fill_id,
                &parsed.request_id,
                "GetObject",
                key,
                "purged stale cache entry after HEAD etag mismatch during GET refresh",
                "HEAD etag mismatch observed during GET refresh, but cache entry changed before invalidation",
                "failed to purge stale cache entry after HEAD etag mismatch during GET refresh",
                "poisoned stale cache entry after purge failure during GET refresh",
                "failed to poison stale cache entry after purge failure during GET refresh",
            )
            .await;
            return None;
        }
        crate::handlers::head::CacheRefreshOutcome::NoStrongMatch => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                "cached body did not strongly match HEAD refresh, falling back to GET"
            );
            return None;
        }
    }

    match state.cache.peek_body(cache_key).await {
        Ok(Some(refreshed_entry))
            if cache_entry_satisfies_read_options(&refreshed_entry, read_options) =>
        {
            let meta_for_hit = refreshed_entry.meta.clone();
            let resp = build_cache_response(
                refreshed_entry,
                &parsed.request_id,
                "MISS",
                read_options.wants_checksum_headers(),
            )
            .await;
            if resp.is_some() {
                // Record both: miss (backend HEAD was needed) and hit (body
                // served from cache) so stats reflect both the backend
                // round-trip and the LRU touch.
                let _ = state.cache.note_miss().await;
                if let Err(e) = state.cache.note_hit(cache_key, &meta_for_hit).await {
                    tracing::warn!(
                        request_id = %parsed.request_id,
                        error = %e,
                        operation = "GetObject",
                        key = key,
                        "failed to record cache hit after HEAD refresh"
                    );
                }
                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    cache_status = "MISS",
                    "served cached body after HEAD metadata refresh"
                );
            }
            resp
        }
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                error = %e,
                "cache lookup failed after HEAD metadata refresh"
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
    handle_get_with_refresh(state, parsed, key, true).await
}

async fn handle_get_with_refresh<B: Backend + 'static, C: CacheStore + 'static>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    allow_post_flight_refresh: bool,
) -> Response<Body> {
    let read_options = parsed.read_options();

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

    // Probe cache without accounting first so checksum refresh checks do not
    // inflate hit stats for entries that still need backend work. Use a
    // body-pinning probe so a usable GET hit can stream the same entry.
    let cache_key = CacheKey::new(&*state.backend_bucket, key);
    match state.cache.peek_body(&cache_key).await {
        Ok(Some(entry)) => {
            if !cache_entry_satisfies_read_options(&entry, read_options) {
                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    cache_status = "MISS",
                    "cache entry missing requested checksum metadata, refreshing from backend"
                );
            } else {
                let meta_for_hit = entry.meta.clone();
                if let Some(resp) = build_cache_response(
                    entry,
                    &parsed.request_id,
                    "HIT",
                    read_options.wants_checksum_headers(),
                )
                .await
                {
                    if let Err(e) = state.cache.note_hit(&cache_key, &meta_for_hit).await {
                        tracing::warn!(
                            request_id = %parsed.request_id,
                            error = %e,
                            operation = "GetObject",
                            key = key,
                            "failed to record cache hit"
                        );
                    }
                    tracing::info!(
                        request_id = %parsed.request_id,
                        operation = "GetObject",
                        key = key,
                        cache_status = "HIT",
                        "serving from cache"
                    );
                    return resp;
                }
                // Body file disappeared — fall through to singleflight.
            }
        }
        Ok(None) => {
            // Cache miss — proceed to singleflight. Miss accounting is
            // deferred to the actual MISS response path to avoid inflation
            // when followers later serve from cache as HIT.
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
            handle_follower(
                state,
                parsed,
                key,
                &cache_key,
                &mut receiver,
                allow_post_flight_refresh,
            )
            .await
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
    let read_options = parsed.read_options();
    match state
        .backend
        .get_object(&state.backend_bucket, key, read_options)
        .await
    {
        Ok((meta, body_stream)) => {
            if cache_status == "MISS" {
                let _ = state.cache.note_miss().await;
            }
            build_streaming_response(
                &meta,
                body_stream,
            &parsed.request_id,
            cache_status,
            read_options.wants_checksum_headers(),
        )
        },
        Err(e) => {
            if cache_status == "MISS" {
                let _ = state.cache.note_miss().await;
            }
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

/// Spawn a background task that tees the backend body stream to both
/// the client (via an mpsc channel) and the disk cache.
///
/// Returns the client-facing response Body backed by the channel receiver.
///
/// # Why this isn't behind CacheStore
///
/// The tee operation bridges two concerns that cannot be cleanly separated:
/// streaming the response to the client AND filling the cache simultaneously.
/// Pushing this behind CacheStore would require the trait to understand
/// HTTP response bodies and mpsc channels, leaking transport details into
/// the cache abstraction.
fn spawn_cache_tee<C: CacheStore + 'static>(
    cache: Arc<C>,
    body_stream: BoxByteStream,
    cache_meta: CacheMeta,
    fill_guard: Option<crate::cache::FillGuard>,
    waiter: FlightWaiter,
    temp_body_path: PathBuf,
    request_id: String,
    key: String,
) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(32);
    let temp_path_clone = temp_body_path.clone();
    let req_id_for_tee = request_id;
    let key_for_tee = key;

    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        use tokio_stream::StreamExt;

        let mut file = match tokio::fs::File::create(&temp_path_clone).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    request_id = %req_id_for_tee,
                    key = %key_for_tee,
                    error = %e,
                    "cache fill: failed to create temp file"
                );
                if let Some(guard) = fill_guard {
                    cache.abort_fill(guard).await;
                }
                // Release followers immediately — they should not wait for
                // the client drain since no cache fill will complete.
                waiter.complete().await;
                // Drain remaining stream to the leader's client only.
                let drain_send_timeout = std::time::Duration::from_secs(30);
                let mut stream = body_stream;
                while let Some(chunk) = stream.next().await {
                    match tokio::time::timeout(drain_send_timeout, tx.send(chunk)).await {
                        Ok(Ok(())) => {} // sent successfully
                        Ok(Err(_)) => break, // receiver dropped
                        Err(_) => {
                            tracing::warn!(
                                request_id = %req_id_for_tee,
                                key = %key_for_tee,
                                "cache fill drain: client send timed out, aborting drain"
                            );
                            break;
                        }
                    }
                }
                return;
            }
        };

        let mut stream = body_stream;

        let mut waiter = Some(waiter);
        let cache_ok = {
            let chunk_timeout = std::time::Duration::from_secs(300);
            let send_timeout = std::time::Duration::from_secs(30);
            let mut ok = true;
            let mut client_alive = true;
            loop {
                match tokio::time::timeout(chunk_timeout, stream.next()).await {
                    Ok(Some(Ok(chunk))) => {
                        if ok && let Err(e) = file.write_all(&chunk).await {
                            tracing::warn!(
                                request_id = %req_id_for_tee,
                                key = %key_for_tee,
                                error = %e,
                                "cache fill: write error"
                            );
                            ok = false;
                            // Release followers immediately — the cache fill
                            // won't publish, so they should not wait for the
                            // remaining stream to drain.
                            if let Some(w) = waiter.take() {
                                w.complete().await;
                            }
                        }
                        // Send to client with a timeout so a slow/stalled
                        // client doesn't block the cache fill indefinitely.
                        if client_alive {
                            match tokio::time::timeout(send_timeout, tx.send(Ok(chunk))).await {
                                Ok(Ok(())) => {} // sent successfully
                                Ok(Err(_)) => {
                                    // Receiver dropped — client disconnected.
                                    client_alive = false;
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        request_id = %req_id_for_tee,
                                        key = %key_for_tee,
                                        "cache fill: client send timed out, continuing disk fill only"
                                    );
                                    client_alive = false;
                                }
                            }
                        }
                        // No reason to keep draining the backend if both the
                        // cache fill failed and the client is gone.
                        if !ok && !client_alive {
                            break;
                        }
                    }
                    Ok(Some(Err(e))) => {
                        if client_alive {
                            let _ = tokio::time::timeout(
                                send_timeout,
                                tx.send(Err(std::io::Error::other(e.to_string()))),
                            )
                            .await;
                        }
                        ok = false;
                        break;
                    }
                    Ok(None) => break, // stream finished
                    Err(_) => {
                        tracing::error!(
                            request_id = %req_id_for_tee,
                            key = %key_for_tee,
                            "cache fill: chunk read timed out after 300s"
                        );
                        if client_alive {
                            let _ = tokio::time::timeout(
                                send_timeout,
                                tx.send(Err(std::io::Error::other("chunk read timeout"))),
                            )
                            .await;
                        }
                        ok = false;
                        break;
                    }
                }
            }
            ok
        };

        // Drop sender so the client body ends
        drop(tx);

        if cache_ok {
            if let Err(e) = file.sync_all().await {
                tracing::warn!(
                    request_id = %req_id_for_tee,
                    key = %key_for_tee,
                    error = %e,
                    "cache fill: fsync error"
                );
                if let Some(guard) = fill_guard {
                    cache.abort_fill(guard).await;
                }
                let _ = tokio::fs::remove_file(&temp_path_clone).await;
                if let Some(w) = waiter.take() {
                    w.complete().await;
                }
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
                    tracing::warn!(
                        request_id = %req_id_for_tee,
                        key = %key_for_tee,
                        error = %e,
                        "cache fill: commit error"
                    );
                    let _ = tokio::fs::remove_file(&temp_path_clone).await;
                }
            } else {
                tracing::warn!(
                    request_id = %req_id_for_tee,
                    key = %key_for_tee,
                    "cache fill: no fill guard, skipping cache commit"
                );
                let _ = tokio::fs::remove_file(&temp_path_clone).await;
            }
        } else {
            if let Some(guard) = fill_guard {
                cache.abort_fill(guard).await;
            }
            let _ = tokio::fs::remove_file(&temp_path_clone).await;
        }

        if let Some(w) = waiter.take() {
            w.complete().await;
        }
    });

    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
}

/// Leader path: fetch from backend, tee stream to cache + client.
async fn handle_leader<B: Backend + 'static, C: CacheStore + 'static>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    cache_key: &CacheKey,
    waiter: FlightWaiter,
) -> Response<Body> {
    let read_options = parsed.read_options();

    // Re-probe cache after acquiring leadership. Use metadata-only peek first
    // to avoid pinning a body file handle unnecessarily. Only open the body
    // (peek_body) when we're about to serve a HIT.
    match state.cache.peek(cache_key).await {
        Ok(Some(entry)) if cache_entry_satisfies_read_options(&entry, read_options) => {
            // Entry satisfies — pin the body and serve.
            if let Ok(Some(pinned)) = state.cache.peek_body(cache_key).await {
                if cache_entry_satisfies_read_options(&pinned, read_options) {
                    let meta_for_hit = pinned.meta.clone();
                    if let Some(resp) = build_cache_response(
                        pinned,
                        &parsed.request_id,
                        "HIT",
                        read_options.wants_checksum_headers(),
                    )
                    .await
                    {
                        if let Err(e) = state.cache.note_hit(cache_key, &meta_for_hit).await {
                            tracing::warn!(
                                request_id = %parsed.request_id,
                                error = %e,
                                operation = "GetObject",
                                key = key,
                                "failed to record cache hit"
                            );
                        }
                        waiter.complete().await;
                        return resp;
                    }
                }
            }
        }
        Ok(Some(entry)) if read_options.wants_checksum_headers() => {
            // Entry doesn't satisfy checksum requirements — try HEAD refresh.
            if let Some(resp) =
                try_refresh_cached_get_metadata(state, parsed, key, cache_key, &entry).await
            {
                waiter.complete().await;
                return resp;
            }
            // try_refresh returned None — either HEAD failed or the 404
            // invalidation found the entry was replaced by a concurrent
            // refill. Re-probe: if a newer entry now satisfies, serve it
            // instead of paying a redundant backend GET.
            if let Ok(Some(refreshed)) = state.cache.peek(cache_key).await {
                if cache_entry_satisfies_read_options(&refreshed, read_options) {
                    if let Ok(Some(pinned)) = state.cache.peek_body(cache_key).await {
                        if cache_entry_satisfies_read_options(&pinned, read_options) {
                            let meta_for_hit = pinned.meta.clone();
                            if let Some(resp) = build_cache_response(
                                pinned,
                                &parsed.request_id,
                                "HIT",
                                read_options.wants_checksum_headers(),
                            )
                            .await
                            {
                                if let Err(e) =
                                    state.cache.note_hit(cache_key, &meta_for_hit).await
                                {
                                    tracing::warn!(
                                        request_id = %parsed.request_id,
                                        error = %e,
                                        operation = "GetObject",
                                        key = key,
                                        "failed to record cache hit after 404 re-probe"
                                    );
                                }
                                waiter.complete().await;
                                return resp;
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "GetObject",
                key = key,
                "leader cache probe failed"
            );
        }
        _ => {} // Cache miss or non-checksum unsatisfied — proceed to backend
    }

    // Register fill BEFORE the backend fetch so that any purge() during
    // the round-trip bumps the generation counter, causing commit_fill to
    // reject the stale response. Without this, a purge during the GET
    // would find no active fill entry to invalidate.
    let fill_guard = state.cache.begin_fill(cache_key).await.ok();

    let result = state
        .backend
        .get_object(&state.backend_bucket, key, read_options)
        .await;

    match result {
        Ok((meta, body_stream)) => {
            // Only cache when content_length is known; unknown-length responses
            // could be arbitrarily large and bypass cache_max_object_bytes.
            let is_size_cacheable = meta
                .content_length
                .map(|len| state.policy.is_size_cacheable(len as u64))
                .unwrap_or(false);

            if is_size_cacheable && fill_guard.is_some() {
                let temp_body_path =
                    PathBuf::from(&state.config.cache_dir)
                        .join("tmp")
                        .join(format!(
                            "{}-{}.body",
                            std::process::id(),
                            crate::request_id::generate()
                        ));

                let cache_meta = CacheMeta {
                    bucket: state.backend_bucket.to_string(),
                    key: key.to_string(),
                    etag: meta.etag.clone(),
                    last_modified: meta.last_modified,
                    content_type: meta.content_type.clone(),
                    content_length: meta.content_length.unwrap_or(0),
                    cache_written_at: chrono::Utc::now(),
                    fill_id: 0, // stamped by commit_fill()
                    metadata_version: 0,
                    last_accessed_at: chrono::Utc::now(),
                    hit_count: 0,
                    source_status: 200,
                    metadata: meta.metadata.clone(),
                    extra_headers: meta.extra_headers.clone(),
                    head_extra_headers: std::collections::HashMap::new(),
                    head_checksum_headers: std::collections::HashMap::new(),
                    checksum_mode_checked: read_options.wants_checksum_headers()
                        || meta.extra_headers.keys().any(|k| {
                            crate::s3::headers::is_checksum_response_header(k)
                        }),
                    head_metadata_checked: false,
                    head_checksum_checked: false,
                };

                let body = spawn_cache_tee(
                    state.cache.clone(),
                    body_stream,
                    cache_meta,
                    fill_guard,
                    waiter,
                    temp_body_path,
                    parsed.request_id.clone(),
                    key.to_string(),
                );

                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    cache_status = "MISS",
                    cached = true,
                    "serving from backend (tee to cache)"
                );
                let _ = state.cache.note_miss().await;

                build_meta_response(
                    &meta,
                    body,
                    &parsed.request_id,
                    "MISS",
                    read_options.wants_checksum_headers(),
                )
            } else if is_size_cacheable {
                // Size is cacheable but fill_guard is None (begin_fill failed).
                // Stream directly without tee — don't block followers on a
                // fill that can never commit.
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
                    "serving from backend (fill registration failed)"
                );
                let _ = state.cache.note_miss().await;

                build_streaming_response(
                    &meta,
                    body_stream,
                    &parsed.request_id,
                    "MISS",
                    read_options.wants_checksum_headers(),
                )
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
                let _ = state.cache.note_miss().await;

                build_streaming_response(
                    &meta,
                    body_stream,
                    &parsed.request_id,
                    "MISS",
                    read_options.wants_checksum_headers(),
                )
            }
        }
        Err(e) => {
            // Backend failed — abort the pre-registered fill.
            if let Some(guard) = fill_guard {
                state.cache.abort_fill(guard).await;
            }
            // Try serving stale from cache if configured.
            if state.config.cache_serve_stale_on_error && e.is_transient() {
                match state.cache.peek_body(cache_key).await {
                    Err(probe_err) => {
                        tracing::warn!(
                            request_id = %parsed.request_id,
                            error = %probe_err,
                            operation = "GetObject",
                            key = key,
                            "stale cache probe failed"
                        );
                    }
                    Ok(None) => {} // No cached entry available.
                    Ok(Some(stale_entry))
                        if !cache_entry_satisfies_read_options(&stale_entry, read_options) => {}
                    Ok(Some(stale_entry)) => {
                let stale_meta = stale_entry.meta.clone();
                if let Some(resp) = build_cache_response(
                    stale_entry,
                    &parsed.request_id,
                    "STALE",
                    read_options.wants_checksum_headers(),
                )
                .await
                {
                    // Record miss (backend GET was attempted) + hit (body
                    // served from stale cache) for accurate stats.
                    let _ = state.cache.note_miss().await;
                    tracing::warn!(
                        request_id = %parsed.request_id,
                        operation = "GetObject",
                        key = key,
                        cache_status = "STALE",
                        error = %e,
                        "serving stale cache entry on backend error"
                    );
                    if let Err(hit_err) =
                        state.cache.note_hit(cache_key, &stale_meta).await
                    {
                        tracing::warn!(
                            request_id = %parsed.request_id,
                            error = %hit_err,
                            "failed to record stale cache hit"
                        );
                    }
                    waiter.complete().await;
                    return resp;
                }
                    // Stale body disappeared — fall through to error
                    }
                }
            }

            // No stale entry available (or stale body disappeared)
            waiter.complete().await;
            let _ = state.cache.note_miss().await;
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
    allow_post_flight_refresh: bool,
) -> Response<Body> {
    // Wait for leader to complete (or drop)
    let _ = receiver.recv().await;

    // Re-read from cache
    match state.cache.peek_body(cache_key).await {
        Ok(Some(entry)) => {
            let read_options = parsed.read_options();
            if !cache_entry_satisfies_read_options(&entry, read_options) {
                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    allow_post_flight_refresh,
                    "follower cache entry missing requested checksum metadata"
                );
                if allow_post_flight_refresh {
                    return Box::pin(handle_get_with_refresh(state, parsed, key, false)).await;
                }
                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    "follower already attempted post-flight refresh, falling back to direct backend read"
                );
                return handle_passthrough(state, parsed, key, "MISS").await;
            }
            let meta_for_hit = entry.meta.clone();
            if let Some(resp) = build_cache_response(
                entry,
                &parsed.request_id,
                "HIT",
                read_options.wants_checksum_headers(),
            )
            .await
            {
                if let Err(e) = state.cache.note_hit(cache_key, &meta_for_hit).await {
                    tracing::warn!(
                        request_id = %parsed.request_id,
                        error = %e,
                        operation = "GetObject",
                        key = key,
                        "failed to record follower cache hit"
                    );
                }
                tracing::info!(
                    request_id = %parsed.request_id,
                    operation = "GetObject",
                    key = key,
                    cache_status = "HIT",
                    "follower served from cache after leader"
                );
                return resp;
            }
            // Body file disappeared — fall through
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                "follower cache body disappeared, fetching from backend"
            );
            return handle_passthrough(state, parsed, key, "MISS").await;
        }
        Ok(None) => {
            // Known tradeoff: if the leader returned a HEAD 404 and purged
            // the entry, followers see Ok(None) and fall back to a backend
            // GET. Propagating the negative outcome through singleflight
            // would require a result channel, which is not worth the
            // complexity for this rare edge case (deleted key under load).
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "GetObject",
                key = key,
                "follower cache miss, fetching from backend directly"
            );
            handle_passthrough(state, parsed, key, "MISS").await
        }
        Err(e) => {
            tracing::warn!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "GetObject",
                key = key,
                "follower cache probe failed, fetching from backend directly"
            );
            handle_passthrough(state, parsed, key, "MISS").await
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

    fn make_parsed_with_checksum(key: &str) -> ParsedRequest {
        let mut parsed = make_parsed(key);
        parsed
            .extra_amz_headers
            .insert("x-amz-checksum-mode".to_string(), "ENABLED".to_string());
        parsed
    }

    async fn wait_for_cached_entry<F>(
        state: &Arc<AppState<MockBackend, MockCache>>,
        cache_key: &CacheKey,
        predicate: F,
    ) -> CacheEntry
    where
        F: Fn(&CacheEntry) -> bool,
    {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(entry) = state.cache.peek(cache_key).await.unwrap()
                    && predicate(&entry)
                {
                    return entry;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed out waiting for cached entry")
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
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(resp_body.as_ref(), body.as_slice());
        assert_eq!(
            state
                .cache
                .peek_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            state
                .cache
                .peek_body_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            state
                .cache
                .lookup_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            state
                .cache
                .note_hit_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_cache_hit_filters_checksum_headers_when_not_requested() {
        let key = "script_bundle/checksum-filter.js";
        let body = b"cached checksum body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, &body);
        meta.extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "abc123".to_string());
        meta.checksum_mode_checked = true;

        let cache = MockCache::new().with_entry(&cache_key, &body, meta);
        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());

        let resp = handle_get(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert!(resp.headers().get("x-amz-checksum-sha256").is_none());
    }

    #[tokio::test]
    async fn test_checksum_mode_cache_hit_preserves_checksum_headers() {
        let key = "script_bundle/checksum-hit.js";
        let body = b"cached checksum body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, &body);
        meta.extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "abc123".to_string());
        meta.checksum_mode_checked = true;

        let cache = MockCache::new().with_entry(&cache_key, &body, meta);
        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());

        let resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "abc123"
        );
        assert!(state.backend.get_read_calls.lock().unwrap().is_empty());
    }

    /// A plain GET fill whose backend response includes checksum headers
    /// should infer checksum_mode_checked = true. A subsequent checksum GET
    /// must be a cache HIT without needing a backend round-trip.
    #[tokio::test]
    async fn test_plain_get_with_checksum_headers_satisfies_checksum_get() {
        let key = "script_bundle/plain-get-checksums.js";
        let body = b"body with checksums".to_vec();
        let cache_key = CacheKey::new("test-backend", key);

        let mut get_extra = HashMap::new();
        get_extra.insert("x-amz-checksum-sha256".to_string(), "abc123".to_string());

        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: body.clone(),
            content_type: Some("text/plain".to_string()),
            etag: Some("\"etag-1\"".to_string()),
            extra_headers: get_extra,
        }));
        let cache = MockCache::new();
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        // Plain GET fill — backend returns checksum headers.
        let resp = handle_get(&state, &make_parsed(key), key).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");

        // Verify the fill inferred checksum_mode_checked from extra_headers.
        let cached = wait_for_cached_entry(&state, &cache_key, |e| e.meta.checksum_mode_checked)
            .await;
        assert!(cached.meta.checksum_mode_checked);
        assert_eq!(
            cached.meta.extra_headers.get("x-amz-checksum-sha256").unwrap(),
            "abc123"
        );

        // Subsequent checksum GET should be a HIT — no backend call.
        let checksum_resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(checksum_resp.status(), 200);
        assert_eq!(checksum_resp.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            checksum_resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "abc123"
        );
        // Only the original fill GET was called — no additional backend calls.
        assert_eq!(state.backend.get_read_calls.lock().unwrap().len(), 1);
    }

    /// HEAD refresh enriches HEAD-specific state but cannot make checksum
    /// GET a cache hit. The checksum GET falls back to a real backend GET
    /// which populates extra_headers with GET-derived checksums.
    #[tokio::test]
    async fn test_checksum_mode_falls_through_to_get_after_head_refresh() {
        let key = "script_bundle/checksum-refresh.js";
        let cached_body = b"cached body".to_vec();
        let fresh_body = b"fresh body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, &cached_body);

        let mut head_extra = HashMap::new();
        head_extra.insert("x-amz-checksum-sha256".to_string(), "headsum".to_string());
        head_extra.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );
        let mut get_extra = HashMap::new();
        get_extra.insert("x-amz-checksum-sha256".to_string(), "getsum".to_string());

        let backend = MockBackend::new()
            .with_head(Ok(crate::backend::models::HeadObjectOutput {
                content_type: Some("application/javascript".to_string()),
                content_length: Some(cached_body.len() as i64),
                etag: stale_meta.etag.clone(),
                last_modified: None,
                metadata: HashMap::new(),
                extra_headers: head_extra,
            }))
            .with_get(Ok(MockGetResponse {
                body: fresh_body.clone(),
                content_type: Some("application/javascript".to_string()),
                etag: stale_meta.etag.clone(),
                extra_headers: get_extra,
            }));
        let cache = MockCache::new().with_entry(&cache_key, &cached_body, stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");
        // Response has GET-derived checksum, not HEAD-derived.
        assert_eq!(
            resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "getsum"
        );

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), fresh_body.as_slice());

        // Both HEAD and GET were called.
        assert_eq!(state.backend.head_read_calls.lock().unwrap().len(), 1);
        assert_eq!(state.backend.get_read_calls.lock().unwrap().len(), 1);
    }

    /// HEAD refresh must NOT overwrite GET-derived checksum headers in
    /// extra_headers. Trigger a plain HEAD refresh on an entry that has
    /// GET-derived checksums, then verify a subsequent checksum GET still
    /// returns the original GET-derived values.
    #[tokio::test]
    async fn test_head_refresh_does_not_overwrite_get_checksum_headers() {
        let key = "script_bundle/head-no-overwrite-get-checksum.js";
        let cached_body = b"cached body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, &cached_body);
        meta.extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "getsum".to_string());
        meta.checksum_mode_checked = true;
        // head_metadata_checked = false triggers a HEAD refresh on plain HEAD.

        let mut head_extra = HashMap::new();
        head_extra.insert("x-amz-checksum-sha256".to_string(), "headsum".to_string());
        head_extra.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );
        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(cached_body.len() as i64),
            etag: meta.etag.clone(),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: head_extra,
        }));
        let cache = MockCache::new().with_entry(&cache_key, &cached_body, meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        // Plain HEAD triggers refresh (head_metadata_checked = false).
        let head_resp = crate::handlers::head::handle_head(
            &state,
            &make_parsed(key),
            key,
        )
        .await;
        assert_eq!(head_resp.status(), 200);

        // Now a checksum GET should serve from cache with original GET checksum.
        let get_resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(get_resp.status(), 200);
        assert_eq!(get_resp.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            get_resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "getsum",
            "HEAD refresh must not overwrite GET-derived checksum"
        );

        // Verify metadata: GET checksums preserved, HEAD checksums separate.
        let cached = state.cache.peek(&cache_key).await.unwrap().unwrap();
        assert_eq!(
            cached.meta.extra_headers.get("x-amz-checksum-sha256").unwrap(),
            "getsum"
        );
    }

    #[tokio::test]
    async fn test_checksum_mode_falls_back_to_get_when_head_refresh_mismatches_body() {
        let key = "script_bundle/checksum-refresh-fallback.js";
        let stale_body = b"stale body".to_vec();
        let fresh_body = b"fresh body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, &stale_body);

        let mut head_headers = HashMap::new();
        head_headers.insert("x-amz-checksum-sha256".to_string(), "freshsum".to_string());
        let mut get_headers = HashMap::new();
        get_headers.insert("x-amz-checksum-sha256".to_string(), "freshsum".to_string());

        let backend = MockBackend::new()
            .with_head(Ok(crate::backend::models::HeadObjectOutput {
                content_type: Some("application/javascript".to_string()),
                content_length: Some(fresh_body.len() as i64),
                etag: Some("\"etag-refresh\"".to_string()),
                last_modified: None,
                metadata: HashMap::new(),
                extra_headers: head_headers,
            }))
            .with_get(Ok(MockGetResponse {
                body: fresh_body.clone(),
                content_type: Some("application/javascript".to_string()),
                etag: Some("\"etag-refresh\"".to_string()),
                extra_headers: get_headers,
            }));
        let cache = MockCache::new().with_entry(&cache_key, &stale_body, stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), fresh_body.as_slice());

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        let get_calls = state.backend.get_read_calls.lock().unwrap();
        assert_eq!(get_calls.len(), 1);
        assert!(get_calls[0].wants_checksum_headers());
    }

    /// When a checksum HEAD returns no checksum headers, checksum_mode_checked
    /// must NOT be flipped — the empty HEAD is not authoritative for the GET
    /// checksum surface. The request falls back to a backend GET.
    #[tokio::test]
    async fn test_checksum_mode_falls_back_to_get_when_head_has_no_checksums() {
        let key = "script_bundle/checksum-refresh-no-head-checksums.js";
        let cached_body = b"cached body".to_vec();
        let fresh_body = b"fresh body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, &cached_body);

        let mut head_headers = HashMap::new();
        head_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        let backend = MockBackend::new()
            .with_head(Ok(crate::backend::models::HeadObjectOutput {
                content_type: Some("application/javascript".to_string()),
                content_length: Some(cached_body.len() as i64),
                etag: stale_meta.etag.clone(),
                last_modified: None,
                metadata: HashMap::new(),
                extra_headers: head_headers,
            }))
            .with_get(Ok(MockGetResponse {
                body: fresh_body.clone(),
                content_type: Some("application/javascript".to_string()),
                etag: stale_meta.etag.clone(),
                extra_headers: HashMap::new(),
            }));
        let cache = MockCache::new().with_entry(&cache_key, &cached_body, stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), fresh_body.as_slice());

        // Empty-checksum HEAD does NOT satisfy checksum GET — falls back to GET.
        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        let get_calls = state.backend.get_read_calls.lock().unwrap();
        assert_eq!(get_calls.len(), 1);
        // The fallback GET must preserve checksum mode.
        assert!(get_calls[0].wants_checksum_headers());
    }

    /// Regression: a GET refill (triggered by checksum GET fallback after HEAD
    /// etag mismatch) must clear HEAD-specific state so stale HEAD-only
    /// metadata is not carried forward.
    #[tokio::test]
    async fn test_get_refill_clears_head_state() {
        let key = "script_bundle/get-refill-clears-head.js";
        let cache_key = CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"old body");
        meta.head_extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );
        meta.head_metadata_checked = true;
        meta.head_checksum_checked = true;
        meta.head_checksum_headers
            .insert("x-amz-checksum-sha256".to_string(), "oldsum".to_string());
        // checksum_mode_checked = false forces a HEAD refresh on checksum GET.

        let fresh_body = b"new body".to_vec();
        let new_etag = "\"new-etag\"".to_string();
        // HEAD returns a different ETag — triggers refill via GET fallback.
        let backend = MockBackend::new()
            .with_head(Ok(crate::backend::models::HeadObjectOutput {
                content_type: Some("text/plain".to_string()),
                content_length: Some(fresh_body.len() as i64),
                etag: Some(new_etag.clone()),
                last_modified: None,
                metadata: HashMap::new(),
                extra_headers: HashMap::new(),
            }))
            .with_get(Ok(MockGetResponse {
                body: fresh_body.clone(),
                content_type: Some("text/plain".to_string()),
                etag: Some(new_etag.clone()),
                extra_headers: HashMap::new(),
            }));
        let cache = MockCache::new().with_entry(&cache_key, b"old body", meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");

        let cached = wait_for_cached_entry(&state, &cache_key, |e| e.meta.etag.as_deref() == Some(&new_etag)).await;
        assert!(!cached.meta.head_metadata_checked);
        assert!(!cached.meta.head_checksum_checked);
        assert!(cached.meta.head_extra_headers.is_empty());
        assert!(cached.meta.head_checksum_headers.is_empty());
    }

    #[tokio::test]
    async fn test_checksum_refresh_head_not_found_purges_cache_entry() {
        let key = "script_bundle/checksum-refresh-not-found.js";
        let stale_body = b"stale body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, &stale_body);

        let backend = MockBackend::new()
            .with_head(Err(crate::error::ProxyError::UpstreamS3 {
                status_code: 404,
                s3_code: "NoSuchKey".into(),
                message: "deleted upstream".into(),
                operation: "head_object".into(),
            }));
        let cache = MockCache::new().with_entry(&cache_key, &stale_body, stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_get(&state, &make_parsed_with_checksum(key), key).await;

        // HEAD 404 returns 404 directly — no redundant GET issued.
        assert_eq!(resp.status(), 404);
        assert!(state.cache.lookup(&cache_key).await.unwrap().is_none());
        assert_eq!(state.cache.purge_calls.lock().unwrap().len(), 1);
        assert!(state.cache.poison_calls.lock().unwrap().is_empty());
        assert!(state.backend.get_read_calls.lock().unwrap().is_empty());
        assert_eq!(
            state.cache.note_miss_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "HEAD 404 invalidation path must record a cache miss"
        );

        // A subsequent plain GET (cache now empty) should also 404 via backend.
        *state.backend.get_response.lock().unwrap() =
            Some(Err(crate::error::ProxyError::UpstreamS3 {
                status_code: 404,
                s3_code: "NoSuchKey".into(),
                message: "deleted upstream".into(),
                operation: "get_object".into(),
            }));

        let plain_resp = handle_get(&state, &make_parsed(key), key).await;
        assert_eq!(plain_resp.status(), 404);
    }

    /// Verify the purge helper's return-value contract that the 404 re-probe
    /// logic depends on. A true end-to-end test of the concurrent-refill race
    /// requires modifying the entry between peek and purge within
    /// try_refresh_cached_get_metadata, which can't be done with MockCache's
    /// synchronous backend. The code paths are verified structurally:
    /// - purge_if_unchanged returns false for mismatched fill_id
    /// - purge_then_poison_if_unchanged propagates that false
    /// - try_refresh_cached_get_metadata returns None on false (tested above)
    /// - handle_leader re-probes and serves HIT on None (code at line 784)
    #[tokio::test]
    async fn test_purge_returns_false_for_replaced_entry() {
        let key = "script_bundle/purge-false.js";
        let cache_key = CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, b"body");
        let cache = MockCache::new().with_entry(&cache_key, b"body", meta);

        let original_fill_id = {
            let entries = cache.entries.lock().unwrap();
            entries.get(cache_key.hash_hex()).unwrap().meta.fill_id
        };

        // Mismatched fill_id → purge returns false.
        let result = cache
            .purge_if_unchanged(&cache_key, original_fill_id.wrapping_add(1000))
            .await
            .unwrap();
        assert!(!result);
        assert!(cache.peek(&cache_key).await.unwrap().is_some());

        let cache_arc = std::sync::Arc::new(cache);
        let invalidated = super::purge_then_poison_if_unchanged(
            &cache_arc,
            &cache_key,
            original_fill_id.wrapping_add(1000),
            "test", "GetObject", key,
            "ok", "changed", "fail", "poison ok", "poison fail",
        )
        .await;
        assert!(!invalidated);
    }

    #[tokio::test]
    async fn test_cache_miss_fills_cache() {
        let key = "script_bundle/test.js";
        let body = b"console.log('miss')".to_vec();

        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: body.clone(),
            content_type: Some("application/javascript".to_string()),
            etag: Some("\"etag-miss\"".to_string()),
            extra_headers: HashMap::new(),
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
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(resp_body.as_ref(), body.as_slice());

        let cache_key = CacheKey::new("test-backend", key);
        let entry = wait_for_cached_entry(&state, &cache_key, |_| true).await;
        let cached_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(cached_body, body);
        assert_eq!(
            state
                .cache
                .note_miss_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_bypass_for_non_cacheable_prefix() {
        let key = "logs/output.log";
        let body = b"log data".to_vec();

        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: body.clone(),
            content_type: Some("text/plain".to_string()),
            etag: None,
            extra_headers: HashMap::new(),
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
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
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

    // ---- StaleMockCache: returns None on first body probe, Some on subsequent ----
    //
    // This is needed to exercise the TRUE stale-on-error code path, where:
    //   1. Initial cache.peek_body() returns None (miss) → enters singleflight
    //   2. Backend returns a transient error
    //   3. Stale fallback re-probes the cache via peek_body() and returns the entry
    //   4. Handler serves the cached entry with x-cache: STALE

    use std::sync::atomic::{AtomicU32, Ordering};

    struct StaleMockCache {
        /// The entry to serve on the stale (second) lookup.
        entry: Option<CacheEntry>,
        peek_count: AtomicU32,
        peek_body_count: AtomicU32,
        lookup_count: AtomicU32,
        note_hit_count: AtomicU32,
        note_miss_count: AtomicU32,
        temp_dir: tempfile::TempDir,
    }

    impl StaleMockCache {
        #[allow(dead_code)]
        fn new(entry: Option<CacheEntry>) -> Self {
            Self {
                entry,
                peek_count: AtomicU32::new(0),
                peek_body_count: AtomicU32::new(0),
                lookup_count: AtomicU32::new(0),
                note_hit_count: AtomicU32::new(0),
                note_miss_count: AtomicU32::new(0),
                temp_dir: tempfile::TempDir::new().expect("create stale mock temp dir"),
            }
        }
    }

    impl CacheStore for StaleMockCache {
        async fn lookup(
            &self,
            _key: &CacheKey,
        ) -> Result<Option<CacheEntry>, crate::error::ProxyError> {
            self.lookup_count.fetch_add(1, Ordering::SeqCst);
            match self.entry.as_ref() {
                Some(e) => {
                    let body_file = tokio::fs::File::open(&e.body_path).await.ok();
                    Ok(Some(CacheEntry {
                        meta: e.meta.clone(),
                        body_path: e.body_path.clone(),
                        body_file,
                    }))
                }
                None => Ok(None),
            }
        }

        async fn peek(
            &self,
            _key: &CacheKey,
        ) -> Result<Option<CacheEntry>, crate::error::ProxyError> {
            let count = self.peek_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                Ok(None)
            } else {
                Ok(self.entry.as_ref().map(|e| CacheEntry {
                    meta: e.meta.clone(),
                    body_path: e.body_path.clone(),
                    body_file: None,
                }))
            }
        }

        async fn peek_body(
            &self,
            _key: &CacheKey,
        ) -> Result<Option<CacheEntry>, crate::error::ProxyError> {
            let count = self.peek_body_count.fetch_add(1, Ordering::SeqCst);
            // Return None for the first call (initial probe). The leader
            // re-probe now uses peek (metadata-only), not peek_body.
            if count < 1 {
                Ok(None)
            } else {
                match self.entry.as_ref() {
                    Some(e) => {
                        let body_file = tokio::fs::File::open(&e.body_path).await.ok();
                        Ok(Some(CacheEntry {
                            meta: e.meta.clone(),
                            body_path: e.body_path.clone(),
                            body_file,
                        }))
                    }
                    None => Ok(None),
                }
            }
        }

        async fn note_hit(
            &self,
            _key: &CacheKey,
            _meta: &crate::cache::metadata::CacheMeta,
        ) -> Result<(), crate::error::ProxyError> {
            self.note_hit_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn note_miss(&self) -> Result<(), crate::error::ProxyError> {
            self.note_miss_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
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

        async fn purge(&self, _key: &CacheKey) -> Result<bool, crate::error::ProxyError> {
            Ok(false)
        }

        async fn poison(&self, _key: &CacheKey) -> Result<(), crate::error::ProxyError> {
            Ok(())
        }

        async fn purge_if_unchanged(
            &self,
            _key: &CacheKey,
            _expected_fill_id: u64,
        ) -> Result<bool, crate::error::ProxyError> {
            Ok(false)
        }

        async fn poison_if_unchanged(
            &self,
            _key: &CacheKey,
            _expected_fill_id: u64,
        ) -> Result<bool, crate::error::ProxyError> {
            Ok(false)
        }

        async fn update_metadata_if_unchanged(
            &self,
            _key: &CacheKey,
            _expected_fill_id: u64,
            _meta: crate::cache::metadata::CacheMeta,
        ) -> Result<bool, crate::error::ProxyError> {
            Ok(false)
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
            body_file: None,
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
            peek_count: AtomicU32::new(0),
            peek_body_count: AtomicU32::new(0),
            lookup_count: AtomicU32::new(0),
            note_hit_count: AtomicU32::new(0),
            note_miss_count: AtomicU32::new(0),
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
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(resp_body.as_ref(), stale_body.as_slice());

        // peek: 1 leader re-probe (metadata-only)
        assert_eq!(state.cache.peek_count.load(Ordering::SeqCst), 1);
        // peek_body: 1 initial miss, 1 stale probe
        assert_eq!(state.cache.peek_body_count.load(Ordering::SeqCst), 2);
        assert_eq!(state.cache.lookup_count.load(Ordering::SeqCst), 0);
        // Stale replay records both a miss (backend GET attempted) and a hit
        // (body served from stale cache).
        assert_eq!(state.cache.note_miss_count.load(Ordering::SeqCst), 1);
        assert_eq!(state.cache.note_hit_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_stale_disabled_returns_error() {
        let key = "script_bundle/stale-disabled.js";
        let stale_body = b"should not be served".to_vec();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let entry = make_stale_entry(temp_dir.path(), "test-backend", key, &stale_body);
        let cache = StaleMockCache {
            entry: Some(entry),
            peek_count: AtomicU32::new(0),
            peek_body_count: AtomicU32::new(0),
            lookup_count: AtomicU32::new(0),
            note_hit_count: AtomicU32::new(0),
            note_miss_count: AtomicU32::new(0),
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
        // peek: 1 leader re-probe (metadata-only)
        assert_eq!(state.cache.peek_count.load(Ordering::SeqCst), 1);
        // peek_body: 1 initial miss
        assert_eq!(state.cache.peek_body_count.load(Ordering::SeqCst), 1);
        assert_eq!(state.cache.lookup_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_stale_non_transient_error_not_served() {
        let key = "script_bundle/gone.js";
        let stale_body = b"should not be served for 404".to_vec();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let entry = make_stale_entry(temp_dir.path(), "test-backend", key, &stale_body);
        let cache = StaleMockCache {
            entry: Some(entry),
            peek_count: AtomicU32::new(0),
            peek_body_count: AtomicU32::new(0),
            lookup_count: AtomicU32::new(0),
            note_hit_count: AtomicU32::new(0),
            note_miss_count: AtomicU32::new(0),
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
        // peek: 1 leader re-probe (metadata-only)
        assert_eq!(state.cache.peek_count.load(Ordering::SeqCst), 1);
        // peek_body: 1 initial miss
        assert_eq!(state.cache.peek_body_count.load(Ordering::SeqCst), 1);
        assert_eq!(state.cache.lookup_count.load(Ordering::SeqCst), 0);
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
            extra_headers: HashMap::new(),
        }));
        let cache = MockCache::new();
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        // Pre-acquire singleflight to become leader for this key
        let flight_result = state.singleflight.try_acquire(&cache_key).await;
        let waiter = match flight_result {
            crate::cache::FlightResult::Leader { waiter } => waiter,
            _ => panic!("expected to be leader"),
        };

        let mut receiver = match state.singleflight.try_acquire(&cache_key).await {
            crate::cache::FlightResult::Follower { receiver } => receiver,
            _ => panic!("expected follower receiver"),
        };
        let state_clone = Arc::clone(&state);
        let parsed = make_parsed(key);
        let key_owned = key.to_string();
        let cache_key_clone = cache_key.clone();
        let follower = tokio::spawn(async move {
            handle_follower(
                &state_clone,
                &parsed,
                &key_owned,
                &cache_key_clone,
                &mut receiver,
                true,
            )
            .await
        });

        // Simulate leader completing: write entry to cache, then signal
        let meta = test_cache_meta("test-backend", key, &body);
        let body_path = state.cache.temp_dir.path().join("follower-test.body");
        tokio::fs::write(&body_path, &body).await.unwrap();
        let entry = CacheEntry {
            meta,
            body_path,
            body_file: None,
        };
        state
            .cache
            .entries
            .lock()
            .unwrap()
            .insert(cache_key.hash_hex().to_string(), entry);

        // Signal followers
        waiter.complete().await;

        // Follower should return 200 with HIT from cache
        let resp = follower.await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "HIT",
        );
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(resp_body.as_ref(), body.as_slice());
    }

    #[tokio::test]
    async fn test_checksum_followers_coalesce_after_plain_fill() {
        let key = "script_bundle/checksum-followers.js";
        let plain_body = b"plain cached content".to_vec();
        let refreshed_body = b"checksum refreshed content".to_vec();
        let cache_key = CacheKey::new("test-backend", key);

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "checksum-123".to_string(),
        );
        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: refreshed_body.clone(),
            content_type: Some("application/javascript".to_string()),
            etag: Some("\"etag-checksum-refresh\"".to_string()),
            extra_headers,
        }));
        let cache = MockCache::new();
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let flight_result = state.singleflight.try_acquire(&cache_key).await;
        let waiter = match flight_result {
            crate::cache::FlightResult::Leader { waiter } => waiter,
            _ => panic!("expected to be leader"),
        };

        let mut receiver_one = match state.singleflight.try_acquire(&cache_key).await {
            crate::cache::FlightResult::Follower { receiver } => receiver,
            _ => panic!("expected first follower receiver"),
        };
        let mut receiver_two = match state.singleflight.try_acquire(&cache_key).await {
            crate::cache::FlightResult::Follower { receiver } => receiver,
            _ => panic!("expected second follower receiver"),
        };
        let state_clone = Arc::clone(&state);
        let key_owned = key.to_string();
        let cache_key_clone = cache_key.clone();
        let follower_one = tokio::spawn(async move {
            let parsed = make_parsed_with_checksum(&key_owned);
            handle_follower(
                &state_clone,
                &parsed,
                &key_owned,
                &cache_key_clone,
                &mut receiver_one,
                true,
            )
            .await
        });

        let state_clone = Arc::clone(&state);
        let key_owned = key.to_string();
        let cache_key_clone = cache_key.clone();
        let follower_two = tokio::spawn(async move {
            let parsed = make_parsed_with_checksum(&key_owned);
            handle_follower(
                &state_clone,
                &parsed,
                &key_owned,
                &cache_key_clone,
                &mut receiver_two,
                true,
            )
            .await
        });

        let mut meta = test_cache_meta("test-backend", key, &plain_body);
        meta.checksum_mode_checked = false;
        let body_path = state.cache.temp_dir.path().join("plain-fill.body");
        tokio::fs::write(&body_path, &plain_body).await.unwrap();
        let entry = CacheEntry {
            meta,
            body_path,
            body_file: None,
        };
        state
            .cache
            .entries
            .lock()
            .unwrap()
            .insert(cache_key.hash_hex().to_string(), entry);

        waiter.complete().await;

        let resp_one = follower_one.await.unwrap();
        let resp_two = follower_two.await.unwrap();

        let x_cache_values = [
            resp_one.headers().get("x-cache"),
            resp_two.headers().get("x-cache"),
        ]
        .into_iter()
        .map(|value| value.unwrap().to_str().unwrap().to_string())
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            x_cache_values,
            std::collections::BTreeSet::from(["HIT".to_string(), "MISS".to_string()])
        );

        for resp in [resp_one, resp_two] {
            assert_eq!(resp.status(), 200);
            assert_eq!(
                resp.headers().get("x-amz-checksum-sha256").unwrap(),
                "checksum-123"
            );
            let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
            assert_eq!(body.as_ref(), refreshed_body.as_slice());
        }

        let cached =
            wait_for_cached_entry(&state, &cache_key, |entry| entry.meta.checksum_mode_checked)
                .await;
        assert!(cached.meta.checksum_mode_checked);
        assert_eq!(
            cached
                .meta
                .extra_headers
                .get("x-amz-checksum-sha256")
                .unwrap(),
            "checksum-123"
        );

        let get_calls = state.backend.get_read_calls.lock().unwrap();
        assert_eq!(get_calls.len(), 1);
        assert!(get_calls[0].wants_checksum_headers());
    }

    #[tokio::test]
    async fn test_follower_post_flight_refresh_falls_back_without_recursing() {
        let key = "script_bundle/checksum-follower-bounded.js";
        let stale_body = b"stale body".to_vec();
        let fresh_body = b"fresh body".to_vec();
        let cache_key = CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, &stale_body);

        let mut extra_headers = HashMap::new();
        extra_headers.insert("x-amz-checksum-sha256".to_string(), "freshsum".to_string());
        let backend = MockBackend::new().with_get(Ok(MockGetResponse {
            body: fresh_body.clone(),
            content_type: Some("application/javascript".to_string()),
            etag: Some("\"etag-bounded\"".to_string()),
            extra_headers,
        }));
        let cache = MockCache::new().with_entry(&cache_key, &stale_body, stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let (tx, mut receiver) = tokio::sync::broadcast::channel(1);
        let _ = tx.send(());

        let resp = handle_follower(
            &state,
            &make_parsed_with_checksum(key),
            key,
            &cache_key,
            &mut receiver,
            false,
        )
        .await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");
        assert_eq!(
            resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "freshsum"
        );

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), fresh_body.as_slice());

        let get_calls = state.backend.get_read_calls.lock().unwrap();
        assert_eq!(get_calls.len(), 1);
        assert!(get_calls[0].wants_checksum_headers());
    }
}
