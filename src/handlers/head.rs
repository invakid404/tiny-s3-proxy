use std::sync::Arc;

use axum::body::Body;
use http::Response;

use crate::backend::Backend;
use crate::backend::models::HeadObjectInput;
use crate::cache::CacheStore;
use crate::cache::key::CacheKey;
use crate::cache::metadata::CacheMeta;
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::{common_headers, head_object_headers, with_cache_status};
use crate::s3::ops::ParsedRequest;

use super::{InvalidationMessages, purge_then_poison_if_unchanged};

// Keep this list in sync with HEAD-only extraction in backend/client.rs.
// Today only `x-amz-archive-status` is added exclusively on the typed HEAD
// path, so it must stay out of shared GET cache metadata while still being
// preserved for cached HEAD responses.
fn is_head_only_response_header(name: &str) -> bool {
    matches!(name, "x-amz-archive-status")
}

fn split_head_refresh_headers(
    headers: &std::collections::HashMap<String, String>,
) -> (
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
) {
    let (head_only_vec, shared_vec): (Vec<_>, Vec<_>) = headers
        .iter()
        .partition(|(name, _)| is_head_only_response_header(name));
    (
        shared_vec
            .into_iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
        head_only_vec
            .into_iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    )
}

fn extract_checksum_headers(
    headers: &std::collections::HashMap<String, String>,
) -> std::collections::HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| crate::s3::headers::is_checksum_response_header(name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

pub(crate) enum CacheRefreshOutcome {
    Updated(Box<CacheMeta>),
    EtagMismatch,
    NoStrongMatch,
}

pub(crate) fn refreshed_cache_meta(
    cached: &CacheMeta,
    output: &crate::backend::models::HeadObjectOutput,
    requested_checksum_headers: bool,
) -> CacheRefreshOutcome {
    let (Some(cached_etag), Some(output_etag)) = (&cached.etag, &output.etag) else {
        return CacheRefreshOutcome::NoStrongMatch;
    };
    if cached_etag != output_etag {
        return CacheRefreshOutcome::EtagMismatch;
    }

    let (mut extra_headers, head_extra_headers) = split_head_refresh_headers(&output.extra_headers);
    let observed_checksum_headers = extract_checksum_headers(&extra_headers);
    // HEAD-derived checksum headers go ONLY into head_checksum_headers, never
    // into extra_headers (the GET-shared bucket). Strip any that leaked in
    // from the HEAD response, then always carry forward the cached GET-side
    // checksum headers so GET hits continue to return GET-derived values.
    extra_headers.retain(|name, _| !crate::s3::headers::is_checksum_response_header(name));
    for (name, value) in &cached.extra_headers {
        if crate::s3::headers::is_checksum_response_header(name) {
            extra_headers.insert(name.clone(), value.clone());
        }
    }

    CacheRefreshOutcome::Updated(Box::new(CacheMeta {
        bucket: cached.bucket.clone(),
        key: cached.key.clone(),
        etag: Some(output_etag.clone()),
        last_modified: output.last_modified.or(cached.last_modified),
        content_type: output
            .content_type
            .clone()
            .or_else(|| cached.content_type.clone()),
        content_length: output.content_length.unwrap_or(cached.content_length),
        cache_written_at: cached.cache_written_at,
        fill_id: cached.fill_id,
        metadata_version: cached.metadata_version,
        last_accessed_at: cached.last_accessed_at,
        hit_count: cached.hit_count,
        source_status: cached.source_status,
        metadata: output.metadata.clone(),
        extra_headers,
        head_extra_headers,
        head_checksum_headers: if requested_checksum_headers {
            observed_checksum_headers
        } else {
            cached.head_checksum_headers.clone()
        },
        // HEAD refreshes must NEVER flip checksum_mode_checked — that flag
        // gates checksum GET cache eligibility and must only be set when
        // extra_headers actually contains GET-derived checksum headers.
        // A HEAD refresh puts checksums into head_checksum_headers only.
        checksum_mode_checked: cached.checksum_mode_checked,
        // Note: HEAD-only metadata (e.g. x-amz-archive-status) is cached
        // and replayed until eviction or a new body fill. If the backend
        // changes archive/storage state without changing the ETag, clients
        // will see stale values until the cache entry is replaced. This is
        // a known limitation of the current caching model.
        head_metadata_checked: true,
        head_checksum_checked: cached.head_checksum_checked || requested_checksum_headers,
    }))
}

fn cache_entry_satisfies_head_request(
    meta: &CacheMeta,
    options: crate::backend::models::ReadOptions,
) -> bool {
    if options.wants_checksum_headers() {
        // Cached checksum HEADs require the HEAD-specific checksum surface, not
        // just the shared checksum headers that may already be sufficient for
        // cached checksum GETs on the same object version.
        meta.head_metadata_checked && meta.head_checksum_checked
    } else {
        // Plain cached HEADs also require the HEAD metadata surface because a
        // GET fill does not observe HEAD-only headers such as
        // x-amz-archive-status.
        meta.head_metadata_checked
    }
}

fn build_cached_head_response(
    meta: &CacheMeta,
    request_id: &str,
    cache_status: &str,
    include_checksum_headers: bool,
) -> Response<Body> {
    let head_output = crate::backend::models::HeadObjectOutput {
        content_type: meta.content_type.clone(),
        content_length: Some(meta.content_length),
        etag: meta.etag.clone(),
        last_modified: meta.last_modified,
        metadata: meta.metadata.clone(),
        extra_headers: {
            let mut headers = meta
                .extra_headers
                .iter()
                .filter(|(name, _)| !crate::s3::headers::is_checksum_response_header(name))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect::<std::collections::HashMap<_, _>>();
            headers.extend(meta.head_extra_headers.clone());
            if include_checksum_headers {
                headers.extend(meta.head_checksum_headers.clone());
            }
            headers
        },
    };

    let mut headers = head_object_headers(&head_output, include_checksum_headers);
    let common = common_headers(request_id);
    headers.extend(common);
    with_cache_status(&mut headers, cache_status);

    let mut response = Response::builder().status(200);
    for (k, v) in headers.iter() {
        response = response.header(k, v);
    }
    response.body(Body::empty()).unwrap()
}

fn build_fresh_head_response(
    output: &crate::backend::models::HeadObjectOutput,
    request_id: &str,
    cache_status: Option<&str>,
    include_checksum_headers: bool,
) -> Response<Body> {
    let mut headers = head_object_headers(output, include_checksum_headers);
    let common = common_headers(request_id);
    headers.extend(common);
    if let Some(cache_status) = cache_status {
        with_cache_status(&mut headers, cache_status);
    }

    let mut response = Response::builder().status(200);
    for (k, v) in headers.iter() {
        response = response.header(k, v);
    }
    response.body(Body::empty()).unwrap()
}

async fn note_refresh_miss<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    request_id: &str,
    key: &str,
) {
    if let Err(miss_err) = state.cache.note_miss().await {
        tracing::warn!(
            request_id = %request_id,
            error = %miss_err,
            operation = "HeadObject",
            key = key,
            "failed to record cache miss"
        );
    }
}

/// Handle a HeadObject request.
///
/// If the key is cacheable and we have a cached entry, serve metadata from cache.
/// Otherwise, passthrough to the backend.
pub async fn handle_head<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
) -> Response<Body> {
    let read_options = parsed.read_options();
    let mut cache_refresh_target: Option<Arc<CacheMeta>> = None;
    let cache_key = CacheKey::new(&*state.backend_bucket, key);

    // Probe cache first without accounting so refresh-only HEAD checks do not
    // look like cache hits when the response still has to go upstream.
    if state.policy.is_cacheable(key) {
        match state.cache.peek(&cache_key).await {
            Ok(Some(entry)) => {
                if !cache_entry_satisfies_head_request(&entry.meta, read_options) {
                    // Defer note_miss until after the backend response, because
                    // the stale-on-error path may call note_hit instead.
                    cache_refresh_target = Some(entry.meta.clone());
                    tracing::info!(
                        request_id = %parsed.request_id,
                        operation = "HeadObject",
                        key = key,
                        "cache entry missing requested HEAD metadata, fetching HEAD from backend"
                    );
                } else {
                    if let Err(e) = state.cache.note_hit(&cache_key, &entry.meta).await {
                        tracing::warn!(
                            request_id = %parsed.request_id,
                            error = %e,
                            operation = "HeadObject",
                            key = key,
                            "failed to record cache hit"
                        );
                    }
                    tracing::info!(
                        request_id = %parsed.request_id,
                        operation = "HeadObject",
                        key = key,
                        cache_status = "HIT",
                        "serving HEAD from cache"
                    );
                    return build_cached_head_response(
                        &entry.meta,
                        &parsed.request_id,
                        "HIT",
                        read_options.wants_checksum_headers(),
                    );
                }
            }
            Ok(None) => {
                if let Err(e) = state.cache.note_miss().await {
                    tracing::warn!(
                        request_id = %parsed.request_id,
                        error = %e,
                        operation = "HeadObject",
                        key = key,
                        "failed to record cache miss"
                    );
                }
                // Cache miss, fall through to backend
            }
            Err(e) => {
                note_refresh_miss(state, &parsed.request_id, key).await;
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

    // Passthrough to backend (retry handled by the backend client)
    let result = state
        .backend
        .head_object(HeadObjectInput {
            bucket: &state.backend_bucket,
            key,
            options: read_options,
        })
        .await;

    match result {
        Ok(output) => {
            if let Some(ref cached_meta) = cache_refresh_target {
                match refreshed_cache_meta(
                    cached_meta,
                    &output,
                    read_options.wants_checksum_headers(),
                ) {
                    CacheRefreshOutcome::Updated(updated_meta) => {
                        if let Err(e) = state
                            .cache
                            .update_metadata_if_unchanged(
                                &cache_key,
                                cached_meta.fill_id,
                                *updated_meta,
                            )
                            .await
                        {
                            tracing::warn!(
                                request_id = %parsed.request_id,
                                error = %e,
                                operation = "HeadObject",
                                key = key,
                                "failed to persist refreshed cache metadata after HEAD"
                            );
                        }
                    }
                    CacheRefreshOutcome::EtagMismatch => {
                        const ETAG_MISMATCH_MSGS: InvalidationMessages = InvalidationMessages {
                            purge_success: "purged stale cache entry after HEAD etag mismatch",
                            purge_changed: "HEAD etag mismatch observed, but cache entry changed before invalidation",
                            purge_fail: "failed to purge stale cache entry after HEAD etag mismatch",
                            poison_success: "poisoned stale cache entry after purge failure",
                            poison_fail: "failed to poison stale cache entry after purge failure",
                        };
                        let _ = purge_then_poison_if_unchanged(
                            &state.cache,
                            &cache_key,
                            cached_meta.fill_id,
                            &parsed.request_id,
                            "HeadObject",
                            key,
                            &ETAG_MISMATCH_MSGS,
                        )
                        .await;
                    }
                    CacheRefreshOutcome::NoStrongMatch => {
                        tracing::info!(
                            request_id = %parsed.request_id,
                            operation = "HeadObject",
                            key = key,
                            "skipping HEAD-refresh metadata cache update because HEAD did not strongly match cached object"
                        );
                    }
                }
            }

            // Record the miss now — the stale-on-error path records a hit
            // instead, so we only count here when actually serving from backend.
            if cache_refresh_target.is_some() {
                note_refresh_miss(state, &parsed.request_id, key).await;
            }

            tracing::info!(
                request_id = %parsed.request_id,
                operation = "HeadObject",
                key = key,
                "served from backend"
            );

            build_fresh_head_response(
                &output,
                &parsed.request_id,
                None,
                read_options.wants_checksum_headers(),
            )
        }
        Err(e) => {
            if let Some(cached_meta) = cache_refresh_target.as_ref() {
                match &e {
                    crate::error::ProxyError::UpstreamS3 {
                        status_code: 404, ..
                    } => {
                        const HEAD_404_MSGS: InvalidationMessages = InvalidationMessages {
                            purge_success: "purged stale cache entry after HEAD returned not found",
                            purge_changed: "HEAD returned not found, but cache entry changed before invalidation",
                            purge_fail: "failed to purge stale cache entry after HEAD returned not found",
                            poison_success: "poisoned stale cache entry after purge failure following HEAD not found",
                            poison_fail: "failed to poison stale cache entry after purge failure following HEAD not found",
                        };
                        let invalidated = purge_then_poison_if_unchanged(
                            &state.cache,
                            &cache_key,
                            cached_meta.fill_id,
                            &parsed.request_id,
                            "HeadObject",
                            key,
                            &HEAD_404_MSGS,
                        )
                        .await;
                        if !invalidated {
                            // A concurrent refill replaced the entry — the 404
                            // is stale. Re-probe: if the newer entry satisfies
                            // the request, serve it. Same pattern as the
                            // transient-error re-probe below.
                            if let Ok(Some(current)) = state.cache.peek(&cache_key).await
                                && cache_entry_satisfies_head_request(&current.meta, read_options)
                            {
                                if let Err(hit_err) =
                                    state.cache.note_hit(&cache_key, &current.meta).await
                                {
                                    tracing::warn!(
                                        request_id = %parsed.request_id,
                                        error = %hit_err,
                                        "failed to record cache hit after 404 re-probe"
                                    );
                                }
                                return build_cached_head_response(
                                    &current.meta,
                                    &parsed.request_id,
                                    "HIT",
                                    read_options.wants_checksum_headers(),
                                );
                            }
                            // Newer entry exists but doesn't satisfy HEAD yet
                            // (e.g. only GET-warmed). Retry backend HEAD once
                            // to enrich the newer generation instead of
                            // returning the stale 404.
                            if let Ok(Some(newer)) = state.cache.peek(&cache_key).await {
                                if cache_entry_satisfies_head_request(&newer.meta, read_options) {
                                    if let Err(hit_err) =
                                        state.cache.note_hit(&cache_key, &newer.meta).await
                                    {
                                        tracing::warn!(
                                            request_id = %parsed.request_id,
                                            error = %hit_err,
                                            "failed to record cache hit after second 404 re-probe"
                                        );
                                    }
                                    return build_cached_head_response(
                                        &newer.meta,
                                        &parsed.request_id,
                                        "HIT",
                                        read_options.wants_checksum_headers(),
                                    );
                                }
                                match state
                                    .backend
                                    .head_object(HeadObjectInput {
                                        bucket: &state.backend_bucket,
                                        key,
                                        options: read_options,
                                    })
                                    .await
                                {
                                    Ok(retry_output) => {
                                        note_refresh_miss(state, &parsed.request_id, key).await;
                                        // Enrich the newer entry with HEAD metadata.
                                        let outcome = refreshed_cache_meta(
                                            &newer.meta,
                                            &retry_output,
                                            read_options.wants_checksum_headers(),
                                        );
                                        match outcome {
                                            CacheRefreshOutcome::Updated(updated_meta) => {
                                                let updated_meta = *updated_meta;
                                                let _ = state
                                                    .cache
                                                    .update_metadata_if_unchanged(
                                                        &cache_key,
                                                        newer.meta.fill_id,
                                                        updated_meta.clone(),
                                                    )
                                                    .await;
                                                return build_cached_head_response(
                                                    &updated_meta,
                                                    &parsed.request_id,
                                                    "MISS",
                                                    read_options.wants_checksum_headers(),
                                                );
                                            }
                                            CacheRefreshOutcome::EtagMismatch
                                            | CacheRefreshOutcome::NoStrongMatch => {
                                                const RETRY_VALIDATION_MSGS: InvalidationMessages =
                                                    InvalidationMessages {
                                                        purge_success: "purged disproved cache entry after retry HEAD validation failed",
                                                        purge_changed: "retry HEAD validation failed, but replacement entry changed before invalidation",
                                                        purge_fail: "failed to purge disproved cache entry after retry HEAD validation failed",
                                                        poison_success: "poisoned disproved cache entry after retry HEAD purge failure",
                                                        poison_fail: "failed to poison disproved cache entry after retry HEAD purge failure",
                                                    };
                                                let _ = purge_then_poison_if_unchanged(
                                                    &state.cache,
                                                    &cache_key,
                                                    newer.meta.fill_id,
                                                    &parsed.request_id,
                                                    "HeadObject",
                                                    key,
                                                    &RETRY_VALIDATION_MSGS,
                                                )
                                                .await;
                                                // The retry HEAD proved the object exists.
                                                // Even if the cache metadata doesn't strongly
                                                // match, the disproved cached replacement must
                                                // not remain cacheable. Return the fresh HEAD
                                                // response itself instead of the stale original
                                                // 404.
                                                return build_fresh_head_response(
                                                    &retry_output,
                                                    &parsed.request_id,
                                                    Some("MISS"),
                                                    read_options.wants_checksum_headers(),
                                                );
                                            }
                                        }
                                    }
                                    Err(retry_err) => {
                                        if matches!(
                                            retry_err,
                                            crate::error::ProxyError::UpstreamS3 {
                                                status_code: 404,
                                                ..
                                            }
                                        ) {
                                            const RETRY_404_MSGS: InvalidationMessages =
                                                InvalidationMessages {
                                                    purge_success: "purged disproved cache entry after retry HEAD returned not found",
                                                    purge_changed: "retry HEAD returned not found, but replacement entry changed before invalidation",
                                                    purge_fail: "failed to purge disproved cache entry after retry HEAD returned not found",
                                                    poison_success: "poisoned disproved cache entry after retry HEAD purge failure",
                                                    poison_fail: "failed to poison disproved cache entry after retry HEAD purge failure",
                                                };
                                            let _ = purge_then_poison_if_unchanged(
                                                &state.cache,
                                                &cache_key,
                                                newer.meta.fill_id,
                                                &parsed.request_id,
                                                "HeadObject",
                                                key,
                                                &RETRY_404_MSGS,
                                            )
                                            .await;
                                        }
                                        note_refresh_miss(state, &parsed.request_id, key).await;
                                        // Retry HEAD also failed. Return the
                                        // retry error (not the original stale
                                        // 404) since we know a newer generation
                                        // exists.
                                        let s3err = S3Error::from_proxy_error(
                                            &retry_err,
                                            &parsed.request_id,
                                            Some(&format!("/{}/{}", state.frontend_bucket, key)),
                                        );
                                        return s3err.to_response();
                                    }
                                }
                            }
                        }
                    }
                    _ if state.config.cache_serve_stale_on_error && e.is_transient() => {
                        match state.cache.peek(&cache_key).await {
                            // Accept any current entry that satisfies the
                            // request — not just the original fill_id. A
                            // concurrent refresh may have replaced the entry
                            // with a newer one that already has HEAD metadata.
                            Ok(Some(current_entry))
                                if cache_entry_satisfies_head_request(
                                    &current_entry.meta,
                                    read_options,
                                ) =>
                            {
                                tracing::warn!(
                                    request_id = %parsed.request_id,
                                    error = %e,
                                    operation = "HeadObject",
                                    key = key,
                                    cache_status = "STALE",
                                    "backend HEAD failed, serving cached metadata"
                                );
                                if let Err(hit_err) =
                                    state.cache.note_hit(&cache_key, &current_entry.meta).await
                                {
                                    tracing::warn!(
                                        request_id = %parsed.request_id,
                                        error = %hit_err,
                                        "failed to record stale HEAD hit"
                                    );
                                }
                                return build_cached_head_response(
                                    &current_entry.meta,
                                    &parsed.request_id,
                                    "STALE",
                                    read_options.wants_checksum_headers(),
                                );
                            }
                            Ok(Some(_)) => {
                                tracing::info!(
                                    request_id = %parsed.request_id,
                                    operation = "HeadObject",
                                    key = key,
                                    "backend HEAD failed, but cache entry changed before stale fallback"
                                );
                            }
                            Ok(None) => {
                                tracing::info!(
                                    request_id = %parsed.request_id,
                                    operation = "HeadObject",
                                    key = key,
                                    "backend HEAD failed, but cache entry was invalidated before stale fallback"
                                );
                            }
                            Err(lookup_err) => {
                                tracing::warn!(
                                    request_id = %parsed.request_id,
                                    error = %lookup_err,
                                    operation = "HeadObject",
                                    key = key,
                                    "failed to re-check cache ownership before stale fallback"
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Record miss for refresh paths that didn't serve stale.
            if cache_refresh_target.is_some() {
                note_refresh_miss(state, &parsed.request_id, key).await;
            }
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "HeadObject",
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
    use crate::backend::models::{
        AbortMultipartUploadInput, CompleteMultipartOutput, CreateMultipartOutput,
        CreateMultipartUploadInput, DeleteObjectInput, DeleteObjectOutput, GetObjectInput,
        HeadObjectInput, HeadObjectOutput, ListObjectsInput, ListObjectsOutput, PutObjectInput,
        PutObjectOutput, ReadOptions, UploadPartInput, UploadPartOutput,
    };
    use crate::error::ProxyError;
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{Notify, oneshot};

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
            content_headers: std::collections::HashMap::new(),
        }
    }

    fn make_parsed_with_checksum(key: &str) -> ParsedRequest {
        let mut parsed = make_parsed(key);
        parsed
            .extra_amz_headers
            .insert("x-amz-checksum-mode".to_string(), "ENABLED".to_string());
        parsed
    }

    /// GET-shaped ParsedRequest with checksum mode enabled, for use in tests
    /// that call `handle_get` from head.rs test module.
    fn make_get_parsed_with_checksum(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::GetObject {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
            },
            request_id: format!("test-{key}"),
            content_type: None,
            content_length: None,
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: {
                let mut h = std::collections::HashMap::new();
                h.insert("x-amz-checksum-mode".to_string(), "ENABLED".to_string());
                h
            },
            content_headers: std::collections::HashMap::new(),
        }
    }

    fn build_state_with_backend<B: Backend + 'static>(
        backend: B,
        cache: MockCache,
    ) -> Arc<AppState<B, MockCache>> {
        let mut config = test_config();
        config.cache_dir = cache.temp_dir.path().to_path_buf();
        let tmp_dir = cache.temp_dir.path().join("tmp");
        let _ = std::fs::create_dir_all(&tmp_dir);

        Arc::new(AppState {
            backend: Arc::new(backend),
            cache: Arc::new(cache),
            singleflight: Arc::new(crate::cache::SingleFlight::new()),
            auth: Arc::new(MockAuth::allow_all()),
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

    struct Sequential404Then200HeadBackend {
        head_calls: std::sync::Mutex<Vec<ReadOptions>>,
        count: AtomicUsize,
        success_output: std::sync::Mutex<Option<HeadObjectOutput>>,
    }

    impl Sequential404Then200HeadBackend {
        fn new(success_output: HeadObjectOutput) -> Self {
            Self {
                head_calls: std::sync::Mutex::new(Vec::new()),
                count: AtomicUsize::new(0),
                success_output: std::sync::Mutex::new(Some(success_output)),
            }
        }
    }

    impl Backend for Sequential404Then200HeadBackend {
        async fn get_object(
            &self,
            _req: GetObjectInput<'_>,
        ) -> Result<
            (
                crate::backend::models::GetObjectMeta,
                crate::backend::BoxByteStream,
            ),
            ProxyError,
        > {
            Err(ProxyError::Backend {
                source: "unexpected get_object".into(),
                operation: "get_object".into(),
            })
        }

        async fn head_object(
            &self,
            req: HeadObjectInput<'_>,
        ) -> Result<HeadObjectOutput, ProxyError> {
            self.head_calls.lock().unwrap().push(req.options);
            let call = self.count.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Err(ProxyError::UpstreamS3 {
                    status_code: 404,
                    s3_code: "NoSuchKey".into(),
                    message: "deleted".into(),
                    operation: "head_object".into(),
                })
            } else {
                Ok(self.success_output.lock().unwrap().take().unwrap())
            }
        }

        async fn put_object(&self, _req: PutObjectInput) -> Result<PutObjectOutput, ProxyError> {
            unreachable!()
        }
        async fn delete_object(
            &self,
            _req: DeleteObjectInput<'_>,
        ) -> Result<DeleteObjectOutput, ProxyError> {
            unreachable!()
        }
        async fn list_objects(
            &self,
            _req: ListObjectsInput,
        ) -> Result<ListObjectsOutput, ProxyError> {
            unreachable!()
        }
        async fn create_multipart_upload(
            &self,
            _req: CreateMultipartUploadInput<'_>,
        ) -> Result<CreateMultipartOutput, ProxyError> {
            unreachable!()
        }
        async fn upload_part(&self, _req: UploadPartInput) -> Result<UploadPartOutput, ProxyError> {
            unreachable!()
        }
        async fn complete_multipart_upload(
            &self,
            _req: crate::backend::models::CompleteMultipartInput,
        ) -> Result<CompleteMultipartOutput, ProxyError> {
            unreachable!()
        }
        async fn abort_multipart_upload(
            &self,
            _req: AbortMultipartUploadInput<'_>,
        ) -> Result<(), ProxyError> {
            unreachable!()
        }
    }

    struct Sequential404ThenErrorHeadBackend {
        head_calls: std::sync::Mutex<Vec<ReadOptions>>,
        count: AtomicUsize,
    }

    impl Sequential404ThenErrorHeadBackend {
        fn new() -> Self {
            Self {
                head_calls: std::sync::Mutex::new(Vec::new()),
                count: AtomicUsize::new(0),
            }
        }
    }

    impl Backend for Sequential404ThenErrorHeadBackend {
        async fn get_object(
            &self,
            _req: GetObjectInput<'_>,
        ) -> Result<
            (
                crate::backend::models::GetObjectMeta,
                crate::backend::BoxByteStream,
            ),
            ProxyError,
        > {
            Err(ProxyError::Backend {
                source: "unexpected get_object".into(),
                operation: "get_object".into(),
            })
        }
        async fn head_object(
            &self,
            req: HeadObjectInput<'_>,
        ) -> Result<HeadObjectOutput, ProxyError> {
            self.head_calls.lock().unwrap().push(req.options);
            let call = self.count.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Err(ProxyError::UpstreamS3 {
                    status_code: 404,
                    s3_code: "NoSuchKey".into(),
                    message: "deleted".into(),
                    operation: "head_object".into(),
                })
            } else {
                Err(ProxyError::Backend {
                    source: "retry failed".into(),
                    operation: "head_object".into(),
                })
            }
        }
        async fn put_object(&self, _req: PutObjectInput) -> Result<PutObjectOutput, ProxyError> {
            unreachable!()
        }
        async fn delete_object(
            &self,
            _req: DeleteObjectInput<'_>,
        ) -> Result<DeleteObjectOutput, ProxyError> {
            unreachable!()
        }
        async fn list_objects(
            &self,
            _req: ListObjectsInput,
        ) -> Result<ListObjectsOutput, ProxyError> {
            unreachable!()
        }
        async fn create_multipart_upload(
            &self,
            _req: CreateMultipartUploadInput<'_>,
        ) -> Result<CreateMultipartOutput, ProxyError> {
            unreachable!()
        }
        async fn upload_part(&self, _req: UploadPartInput) -> Result<UploadPartOutput, ProxyError> {
            unreachable!()
        }
        async fn complete_multipart_upload(
            &self,
            _req: crate::backend::models::CompleteMultipartInput,
        ) -> Result<CompleteMultipartOutput, ProxyError> {
            unreachable!()
        }
        async fn abort_multipart_upload(
            &self,
            _req: AbortMultipartUploadInput<'_>,
        ) -> Result<(), ProxyError> {
            unreachable!()
        }
    }

    struct Sequential404Then404HeadBackend {
        head_calls: std::sync::Mutex<Vec<ReadOptions>>,
        count: AtomicUsize,
    }

    impl Sequential404Then404HeadBackend {
        fn new() -> Self {
            Self {
                head_calls: std::sync::Mutex::new(Vec::new()),
                count: AtomicUsize::new(0),
            }
        }
    }

    impl Backend for Sequential404Then404HeadBackend {
        async fn get_object(
            &self,
            _req: GetObjectInput<'_>,
        ) -> Result<
            (
                crate::backend::models::GetObjectMeta,
                crate::backend::BoxByteStream,
            ),
            ProxyError,
        > {
            Err(ProxyError::Backend {
                source: "unexpected get_object".into(),
                operation: "get_object".into(),
            })
        }
        async fn head_object(
            &self,
            req: HeadObjectInput<'_>,
        ) -> Result<HeadObjectOutput, ProxyError> {
            self.head_calls.lock().unwrap().push(req.options);
            let call = self.count.fetch_add(1, Ordering::SeqCst);
            let message = if call == 0 {
                "deleted"
            } else {
                "still deleted"
            };
            Err(ProxyError::UpstreamS3 {
                status_code: 404,
                s3_code: "NoSuchKey".into(),
                message: message.into(),
                operation: "head_object".into(),
            })
        }
        async fn put_object(&self, _req: PutObjectInput) -> Result<PutObjectOutput, ProxyError> {
            unreachable!()
        }
        async fn delete_object(
            &self,
            _req: DeleteObjectInput<'_>,
        ) -> Result<DeleteObjectOutput, ProxyError> {
            unreachable!()
        }
        async fn list_objects(
            &self,
            _req: ListObjectsInput,
        ) -> Result<ListObjectsOutput, ProxyError> {
            unreachable!()
        }
        async fn create_multipart_upload(
            &self,
            _req: CreateMultipartUploadInput<'_>,
        ) -> Result<CreateMultipartOutput, ProxyError> {
            unreachable!()
        }
        async fn upload_part(&self, _req: UploadPartInput) -> Result<UploadPartOutput, ProxyError> {
            unreachable!()
        }
        async fn complete_multipart_upload(
            &self,
            _req: crate::backend::models::CompleteMultipartInput,
        ) -> Result<CompleteMultipartOutput, ProxyError> {
            unreachable!()
        }
        async fn abort_multipart_upload(
            &self,
            _req: AbortMultipartUploadInput<'_>,
        ) -> Result<(), ProxyError> {
            unreachable!()
        }
    }

    struct BlockingHeadErrorBackend {
        started: std::sync::Mutex<Option<oneshot::Sender<()>>>,
        release: Arc<Notify>,
        head_read_calls: std::sync::Mutex<Vec<ReadOptions>>,
    }

    impl BlockingHeadErrorBackend {
        fn new(started: oneshot::Sender<()>, release: Arc<Notify>) -> Self {
            Self {
                started: std::sync::Mutex::new(Some(started)),
                release,
                head_read_calls: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl Backend for BlockingHeadErrorBackend {
        async fn get_object(
            &self,
            _req: GetObjectInput<'_>,
        ) -> Result<
            (
                crate::backend::models::GetObjectMeta,
                crate::backend::BoxByteStream,
            ),
            ProxyError,
        > {
            Err(ProxyError::Backend {
                source: "unexpected get_object".into(),
                operation: "get_object".into(),
            })
        }
        async fn head_object(
            &self,
            req: HeadObjectInput<'_>,
        ) -> Result<HeadObjectOutput, ProxyError> {
            self.head_read_calls.lock().unwrap().push(req.options);
            if let Some(tx) = self.started.lock().unwrap().take() {
                let _ = tx.send(());
            }
            self.release.notified().await;
            Err(ProxyError::Backend {
                source: "backend down".into(),
                operation: "head_object".into(),
            })
        }
        async fn put_object(&self, _req: PutObjectInput) -> Result<PutObjectOutput, ProxyError> {
            Err(ProxyError::Backend {
                source: "unexpected put_object".into(),
                operation: "put_object".into(),
            })
        }
        async fn delete_object(
            &self,
            _req: DeleteObjectInput<'_>,
        ) -> Result<DeleteObjectOutput, ProxyError> {
            Err(ProxyError::Backend {
                source: "unexpected delete_object".into(),
                operation: "delete_object".into(),
            })
        }
        async fn list_objects(
            &self,
            _req: ListObjectsInput,
        ) -> Result<ListObjectsOutput, ProxyError> {
            Err(ProxyError::Backend {
                source: "unexpected list_objects".into(),
                operation: "list_objects".into(),
            })
        }
        async fn create_multipart_upload(
            &self,
            _req: CreateMultipartUploadInput<'_>,
        ) -> Result<CreateMultipartOutput, ProxyError> {
            Err(ProxyError::Backend {
                source: "unexpected create_multipart_upload".into(),
                operation: "create_multipart_upload".into(),
            })
        }
        async fn upload_part(&self, _req: UploadPartInput) -> Result<UploadPartOutput, ProxyError> {
            Err(ProxyError::Backend {
                source: "unexpected upload_part".into(),
                operation: "upload_part".into(),
            })
        }
        async fn complete_multipart_upload(
            &self,
            _req: crate::backend::models::CompleteMultipartInput,
        ) -> Result<CompleteMultipartOutput, ProxyError> {
            Err(ProxyError::Backend {
                source: "unexpected complete_multipart_upload".into(),
                operation: "complete_multipart_upload".into(),
            })
        }
        async fn abort_multipart_upload(
            &self,
            _req: AbortMultipartUploadInput<'_>,
        ) -> Result<(), ProxyError> {
            Err(ProxyError::Backend {
                source: "unexpected abort_multipart_upload".into(),
                operation: "abort_multipart_upload".into(),
            })
        }
    }

    #[tokio::test]
    async fn test_head_from_backend() {
        let key = "logs/file.txt";

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(1024),
            etag: Some("\"head-etag\"".to_string()),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: HashMap::new(),
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
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_head_cache_miss_records_miss() {
        let key = "script_bundle/head-miss.js";

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(128),
            etag: Some("\"head-miss-etag\"".to_string()),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: HashMap::new(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            state
                .cache
                .note_miss_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_head_cache_peek_error_records_miss() {
        let key = "script_bundle/head-peek-error.js";

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(128),
            etag: Some("\"head-peek-error-etag\"".to_string()),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: HashMap::new(),
        }));

        let cache = MockCache::new().with_next_peek_error(ProxyError::Cache {
            source: "mock peek failure".into(),
            operation: "peek".into(),
        });
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            state
                .cache
                .note_miss_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_head_from_cache() {
        let key = "script_bundle/cached.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.head_metadata_checked = true;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);

        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let resp = handle_head(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-cache").unwrap().to_str().unwrap(),
            "HIT"
        );
        assert_eq!(
            state
                .cache
                .peek_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            state
                .cache
                .peek_body_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
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
        // Body should be empty for HEAD
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn test_head_cache_filters_checksum_headers_when_not_requested() {
        let key = "script_bundle/head-checksum-filter.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.extra_headers
            .insert("x-amz-checksum-crc32".to_string(), "crc32".to_string());
        meta.checksum_mode_checked = true;
        meta.head_metadata_checked = true;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);
        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert!(resp.headers().get("x-amz-checksum-crc32").is_none());
    }

    #[tokio::test]
    async fn test_head_cache_filters_mixed_case_checksum_headers_when_not_requested() {
        let key = "script_bundle/head-checksum-filter-mixed-case.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.extra_headers
            .insert("X-Amz-Checksum-CRC32".to_string(), "crc32".to_string());
        meta.checksum_mode_checked = true;
        meta.head_metadata_checked = true;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);
        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert!(resp.headers().get("x-amz-checksum-crc32").is_none());
    }

    #[tokio::test]
    async fn test_head_checksum_mode_uses_checked_cache_entry() {
        let key = "script_bundle/head-checksum-cached.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachesum".to_string());
        meta.head_extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );
        meta.head_checksum_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachesum".to_string());
        meta.checksum_mode_checked = true;
        meta.head_metadata_checked = true;
        meta.head_checksum_checked = true;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);
        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed_with_checksum(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "cachesum"
        );
        assert_eq!(
            resp.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );
        assert_eq!(state.backend.head_read_calls.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_checksum_head_bypasses_checksum_get_only_cache_entry() {
        let key = "script_bundle/head-checksum-get-only.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachedsum".to_string());
        meta.checksum_mode_checked = true;
        meta.head_metadata_checked = false;

        let mut extra_headers = HashMap::new();
        extra_headers.insert("x-amz-checksum-sha256".to_string(), "cachedsum".to_string());
        extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: meta.etag.clone(),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);
        let state = build_state_with_backend(backend, cache);

        let first = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(first.status(), 200);
        assert!(first.headers().get("x-cache").is_none());
        assert_eq!(
            first.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );

        let second = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(second.status(), 200);
        assert_eq!(second.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            second.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );
        assert_eq!(
            second.headers().get("x-amz-checksum-sha256").unwrap(),
            "cachedsum"
        );

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        assert!(head_calls[0].wants_checksum_headers());
    }

    /// An empty-checksum HEAD must NOT flip checksum_mode_checked — it is
    /// not authoritative for the GET checksum surface. HEAD-specific state
    /// (head_checksum_checked) should still be set.
    #[tokio::test]
    async fn test_checksum_head_no_checksums_does_not_warm_get() {
        let key = "script_bundle/head-no-checksum.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.head_metadata_checked = true;

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: meta.etag.clone(),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: HashMap::new(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);
        let state = build_state_with_backend(backend, cache);

        let resp = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(resp.status(), 200);

        let updated = state.cache.peek(&cache_key).await.unwrap().unwrap();
        assert!(
            !updated.meta.checksum_mode_checked,
            "empty-checksum HEAD must not flip checksum_mode_checked"
        );
        assert!(updated.meta.head_checksum_checked);

        // A second checksum HEAD should be a cache HIT and must NOT leak
        // GET-side checksum headers into the HEAD response.
        let second = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(second.status(), 200);
        assert_eq!(second.headers().get("x-cache").unwrap(), "HIT");
        assert!(second.headers().get("x-amz-checksum-sha256").is_none());
    }

    /// When a checksum HEAD returns no checksums, the HEAD-specific surface
    /// (head_checksum_headers) should be empty, but GET-shared checksum
    /// headers in extra_headers must survive because some backends return
    /// checksums on GET but not HEAD.
    #[tokio::test]
    async fn test_checksum_head_preserves_get_checksums_when_backend_returns_none() {
        let key = "script_bundle/head-checksum-preserve.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "getsum".to_string());
        meta.checksum_mode_checked = true;
        meta.head_metadata_checked = true;

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: meta.etag.clone(),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: HashMap::new(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);
        let state = build_state_with_backend(backend, cache);

        let head_resp = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(head_resp.status(), 200);

        let updated = state.cache.peek(&cache_key).await.unwrap().unwrap();
        // GET-shared checksums survive.
        assert_eq!(
            updated
                .meta
                .extra_headers
                .get("x-amz-checksum-sha256")
                .unwrap(),
            "getsum"
        );
        // HEAD-specific checksum surface is empty (HEAD returned none).
        assert!(updated.meta.head_checksum_headers.is_empty());

        // A checksum GET should still return the GET-side checksum.
        let get_resp =
            crate::handlers::get::handle_get(&state, &make_get_parsed_with_checksum(key), key)
                .await;
        assert_eq!(get_resp.status(), 200);
        assert_eq!(
            get_resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "getsum"
        );
    }

    #[tokio::test]
    async fn test_head_checksum_mode_bypasses_unchecked_cache_entry() {
        let key = "script_bundle/head-checksum-refresh.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, b"cached body");

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "backendsum".to_string(),
        );

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: Some("\"head-etag\"".to_string()),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_state_with_backend(backend, cache);

        let resp = handle_head(&state, &make_parsed_with_checksum(key), key).await;

        assert_eq!(resp.status(), 200);
        assert!(resp.headers().get("x-cache").is_none());
        assert_eq!(
            resp.headers().get("x-amz-checksum-sha256").unwrap(),
            "backendsum"
        );

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        assert!(head_calls[0].wants_checksum_headers());
    }

    #[tokio::test]
    async fn test_plain_head_refreshes_get_warmed_cache_entry_before_hitting_cache() {
        let key = "script_bundle/head-plain-cache-hit.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, b"cached body");

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: stale_meta.etag.clone(),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        }));

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let first = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(first.status(), 200);
        assert!(first.headers().get("x-cache").is_none());
        assert_eq!(
            first.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );

        let second = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(second.status(), 200);
        assert_eq!(second.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            second.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
    }

    #[tokio::test]
    async fn test_plain_head_uses_checksum_get_warmed_cache_entry() {
        let key = "script_bundle/head-plain-refresh-from-checksum-get.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut stale_meta = test_cache_meta("test-backend", key, b"cached body");
        stale_meta
            .extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachedsum".to_string());
        stale_meta.checksum_mode_checked = true;

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: stale_meta.etag.clone(),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let first = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(first.status(), 200);
        assert!(first.headers().get("x-cache").is_none());
        assert_eq!(
            first.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );

        let second = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(second.status(), 200);
        assert_eq!(second.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            second.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );
        assert!(second.headers().get("x-amz-checksum-sha256").is_none());

        let checksum_get =
            crate::handlers::get::handle_get(&state, &make_get_parsed_with_checksum(key), key)
                .await;
        assert_eq!(checksum_get.status(), 200);
        assert_eq!(checksum_get.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            checksum_get.headers().get("x-amz-checksum-sha256").unwrap(),
            "cachedsum"
        );
        assert_eq!(state.backend.get_read_calls.lock().unwrap().len(), 0);

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        assert!(!head_calls[0].wants_checksum_headers());
    }

    /// Known limitation: once HEAD-only metadata is cached, it is replayed
    /// until eviction or a new body fill. This test documents that a backend
    /// archive-status change on the same ETag is NOT reflected in cached HEAD
    /// responses until the cache entry is replaced.
    #[tokio::test]
    async fn test_head_only_metadata_staleness_is_documented_limitation() {
        let key = "script_bundle/head-stale-archive.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        meta.head_metadata_checked = true;
        meta.head_extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta);
        // Backend would return different archive status, but it's never called.
        let state = build_app_state(MockBackend::new(), cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        // Known limitation: stale archive status is returned from cache.
        assert_eq!(
            resp.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );
        // No backend call made — the HEAD-enriched entry is trusted.
        assert_eq!(state.backend.head_read_calls.lock().unwrap().len(), 0);
    }

    /// When head_metadata_checked=true, a plain HEAD is a direct cache HIT —
    /// the backend is never called. The backend mock is set to fail to prove
    /// no backend call is made.
    #[tokio::test]
    async fn test_plain_head_cache_hit_with_head_enriched_entry() {
        let key = "script_bundle/head-plain-stale-fallback.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut stale_meta = test_cache_meta("test-backend", key, b"cached body");
        stale_meta
            .extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachedsum".to_string());
        stale_meta.checksum_mode_checked = true;
        stale_meta.head_metadata_checked = true;

        let backend = MockBackend::new().with_head(Err(crate::error::ProxyError::Backend {
            source: "backend down".into(),
            operation: "head_object".into(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        // head_metadata_checked=true means the entry already satisfies
        // plain HEAD — it's a direct HIT, no backend call needed.
        let resp = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert!(resp.headers().get("x-amz-checksum-sha256").is_none());
    }

    /// A checksum-warmed entry WITHOUT head_metadata_checked must NOT
    /// be served as stale when the backend HEAD fails — it lacks HEAD-only
    /// headers and serving it would be incomplete.
    #[tokio::test]
    async fn test_plain_head_stale_fallback_refused_for_get_only_entry() {
        let key = "script_bundle/head-plain-stale-refused.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut stale_meta = test_cache_meta("test-backend", key, b"cached body");
        stale_meta.checksum_mode_checked = true;
        // head_metadata_checked = false (GET-only entry)

        let backend = MockBackend::new().with_head(Err(crate::error::ProxyError::Backend {
            source: "backend down".into(),
            operation: "head_object".into(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;
        // Must surface the backend error, not serve incomplete stale metadata.
        assert_eq!(resp.status(), 502);
        assert!(resp.headers().get("x-cache").is_none());
    }

    /// If the cache entry is replaced with a newer satisfiable entry while
    /// the backend HEAD is failing, stale fallback should serve the newer
    /// entry instead of returning the backend error.
    #[tokio::test]
    async fn test_plain_head_stale_fallback_serves_newer_satisfiable_entry() {
        let key = "script_bundle/head-plain-stale-newer.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut meta = test_cache_meta("test-backend", key, b"cached body");
        // Make initial entry NOT satisfy HEAD (needs refresh).
        meta.head_metadata_checked = false;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", meta.clone());

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let backend = BlockingHeadErrorBackend::new(started_tx, std::sync::Arc::clone(&release));
        let state = build_state_with_backend(backend, cache);
        let original_fill_id = state
            .cache
            .peek(&cache_key)
            .await
            .unwrap()
            .unwrap()
            .meta
            .fill_id;

        let state_for_req = std::sync::Arc::clone(&state);
        let parsed = make_parsed(key);
        let handle = tokio::spawn(async move { handle_head(&state_for_req, &parsed, key).await });

        // Wait for HEAD to start, then replace cache entry with a satisfiable one.
        started_rx.await.unwrap();
        let mut newer_meta = meta;
        newer_meta.head_metadata_checked = true;
        newer_meta.head_extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );
        state
            .cache
            .replace_entry_with_new_generation(&cache_key, b"replacement body", newer_meta);
        release.notify_one();

        let resp = handle.await.unwrap();
        // Should serve the newer satisfiable entry, not the backend error.
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "STALE");
        assert_eq!(
            resp.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );
        let newer_entry = state.cache.peek(&cache_key).await.unwrap().unwrap();
        assert_ne!(newer_entry.meta.fill_id, original_fill_id);
    }

    /// End-to-end: HEAD returns 404, purge_if_unchanged swaps in a newer
    /// satisfiable entry (simulating concurrent refill), handler re-probes
    /// and serves it as HIT. Backend HEAD IS called (the entry needed
    /// refresh), and note_hit IS recorded.
    #[tokio::test]
    async fn test_head_404_with_concurrent_refill_serves_newer_entry() {
        let key = "script_bundle/head-404-refill.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut old_meta = test_cache_meta("test-backend", key, b"cached body");
        old_meta.head_metadata_checked = false; // forces HEAD refresh

        let backend = MockBackend::new().with_head(Err(crate::error::ProxyError::UpstreamS3 {
            status_code: 404,
            s3_code: "NoSuchKey".into(),
            message: "deleted upstream".into(),
            operation: "head_object".into(),
        }));

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", old_meta);

        // Stage replacement: when purge_if_unchanged runs after HEAD 404,
        // it swaps in a newer satisfiable entry and returns false.
        let mut new_meta = test_cache_meta("test-backend", key, b"cached body");
        new_meta.head_metadata_checked = true;
        new_meta
            .head_extra_headers
            .insert("x-amz-archive-status".to_string(), "RESTORED".to_string());
        cache.stage_purge_replacement(&cache_key, b"cached body", new_meta);

        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;

        // Newer entry served — NOT 404.
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            resp.headers().get("x-amz-archive-status").unwrap(),
            "RESTORED"
        );
        // Backend HEAD WAS called (the old entry needed refresh).
        assert_eq!(state.backend.head_read_calls.lock().unwrap().len(), 1);
        // note_hit was recorded for the re-probed entry.
        assert_eq!(
            state
                .cache
                .note_hit_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    /// Regression: HEAD returns 404, concurrent GET-only refill replaces the
    /// entry (head_metadata_checked == false). The handler retries HEAD against
    /// the newer generation, enriches it, and returns 200.
    #[tokio::test]
    async fn test_head_404_with_get_only_refill_retries_head_and_enriches() {
        let key = "script_bundle/head-404-get-refill.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut old_meta = test_cache_meta("test-backend", key, b"cached body");
        old_meta.head_metadata_checked = false;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", old_meta);

        // Stage a GET-only replacement (head_metadata_checked = false).
        let mut get_only_meta = test_cache_meta("test-backend", key, b"new body");
        get_only_meta.head_metadata_checked = false;
        // Use a different ETag from the retry HEAD response so refreshed_cache_meta()
        // returns EtagMismatch and we exercise the "return fresh HEAD response
        // directly" branch instead of the Updated branch.
        get_only_meta.etag = Some("\"replacement-etag\"".to_string());
        cache.stage_purge_replacement(&cache_key, b"new body", get_only_meta);

        let mut retry_extra = HashMap::new();
        retry_extra.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        // Real end-to-end sequence: first HEAD returns 404, retry HEAD
        // against the newer generation returns 200 with enrichable metadata.
        let backend = Sequential404Then200HeadBackend::new(HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(8),
            etag: Some("\"retry-etag\"".to_string()),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: retry_extra,
        });

        let state = build_state_with_backend(backend, cache);

        let resp = handle_head(&state, &make_parsed(key), key).await;

        // Retry succeeded — must return 200, not the stale 404.
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");
        // Fresh HEAD response is returned directly even though cache refresh
        // did not strongly match (EtagMismatch path).
        assert_eq!(resp.headers().get("etag").unwrap(), "\"retry-etag\"");
        assert_eq!(
            resp.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );

        // Backend HEAD was called twice: initial 404 + retry.
        assert_eq!(state.backend.head_calls.lock().unwrap().len(), 2);
        assert_eq!(
            state
                .cache
                .note_miss_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(state.cache.lookup(&cache_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_head_404_with_get_only_refill_retry_no_strong_match_invalidates_cache() {
        let key = "script_bundle/head-404-get-refill-no-strong-match.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut old_meta = test_cache_meta("test-backend", key, b"cached body");
        old_meta.head_metadata_checked = false;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", old_meta);

        let mut get_only_meta = test_cache_meta("test-backend", key, b"new body");
        get_only_meta.head_metadata_checked = false;
        get_only_meta.etag = Some("\"replacement-etag\"".to_string());
        cache.stage_purge_replacement(&cache_key, b"new body", get_only_meta);

        let backend = Sequential404Then200HeadBackend::new(HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(8),
            etag: None,
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: HashMap::new(),
        });

        let state = build_state_with_backend(backend, cache);

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");
        assert!(state.cache.lookup(&cache_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_head_404_second_reprobe_serves_newly_satisfiable_entry() {
        let key = "script_bundle/head-404-second-reprobe-hit.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut old_meta = test_cache_meta("test-backend", key, b"cached body");
        old_meta.head_metadata_checked = false;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", old_meta);

        let mut get_only_meta = test_cache_meta("test-backend", key, b"new body");
        get_only_meta.head_metadata_checked = false;
        cache.stage_purge_replacement(&cache_key, b"new body", get_only_meta);

        let mut refreshed_head_extra_headers = HashMap::new();
        refreshed_head_extra_headers
            .insert("x-amz-archive-status".to_string(), "RESTORED".to_string());
        cache.publish_head_state_after_nth_peek(
            &cache_key,
            2,
            refreshed_head_extra_headers,
            HashMap::new(),
            true,
            false,
        );

        let backend = MockBackend::new().with_head(Err(ProxyError::UpstreamS3 {
            status_code: 404,
            s3_code: "NoSuchKey".into(),
            message: "gone".into(),
            operation: "head_object".into(),
        }));

        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            resp.headers().get("x-amz-archive-status").unwrap(),
            "RESTORED"
        );
        assert_eq!(state.backend.head_read_calls.lock().unwrap().len(), 1);
        assert_eq!(
            state
                .cache
                .note_hit_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            state
                .cache
                .note_miss_count
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn test_head_404_retry_error_records_miss() {
        let key = "script_bundle/head-404-retry-error.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut old_meta = test_cache_meta("test-backend", key, b"cached body");
        old_meta.head_metadata_checked = false;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", old_meta);

        let mut get_only_meta = test_cache_meta("test-backend", key, b"new body");
        get_only_meta.head_metadata_checked = false;
        cache.stage_purge_replacement(&cache_key, b"new body", get_only_meta);

        let backend = Sequential404ThenErrorHeadBackend::new();
        let state = build_state_with_backend(backend, cache);

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 502);
        assert_eq!(state.backend.head_calls.lock().unwrap().len(), 2);
        assert_eq!(
            state
                .cache
                .note_miss_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn test_head_404_retry_not_found_invalidates_replacement() {
        let key = "script_bundle/head-404-retry-not-found.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut old_meta = test_cache_meta("test-backend", key, b"cached body");
        old_meta.head_metadata_checked = false;

        let cache = MockCache::new().with_entry(&cache_key, b"cached body", old_meta);

        let mut get_only_meta = test_cache_meta("test-backend", key, b"new body");
        get_only_meta.head_metadata_checked = false;
        cache.stage_purge_replacement(&cache_key, b"new body", get_only_meta);

        let backend = Sequential404Then404HeadBackend::new();
        let state = build_state_with_backend(backend, cache);

        let resp = handle_head(&state, &make_parsed(key), key).await;

        assert_eq!(resp.status(), 404);
        assert_eq!(state.backend.head_calls.lock().unwrap().len(), 2);
        assert_eq!(
            state
                .cache
                .note_miss_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(state.cache.lookup(&cache_key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_plain_head_stale_fallback_aborts_if_entry_invalidated_during_backend_error() {
        let key = "script_bundle/head-plain-stale-invalidated.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, b"cached body");
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);

        let (started_tx, started_rx) = oneshot::channel();
        let release = Arc::new(Notify::new());
        let backend = BlockingHeadErrorBackend::new(started_tx, Arc::clone(&release));
        let state = build_state_with_backend(backend, cache);

        let state_for_request = Arc::clone(&state);
        let parsed = make_parsed(key);
        let handle =
            tokio::spawn(async move { handle_head(&state_for_request, &parsed, key).await });

        started_rx.await.unwrap();
        assert!(state.cache.purge(&cache_key).await.unwrap());
        release.notify_one();

        let resp = handle.await.unwrap();
        assert_eq!(resp.status(), 502);
        assert!(resp.headers().get("x-cache").is_none());
        assert!(state.cache.lookup(&cache_key).await.unwrap().is_none());

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        assert!(!head_calls[0].wants_checksum_headers());
    }

    #[tokio::test]
    async fn test_plain_head_no_stale_fallback_on_upstream_403() {
        let key = "script_bundle/head-plain-stale-403.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut stale_meta = test_cache_meta("test-backend", key, b"cached body");
        stale_meta
            .extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachedsum".to_string());
        stale_meta.checksum_mode_checked = true;

        let backend = MockBackend::new().with_head(Err(crate::error::ProxyError::UpstreamS3 {
            status_code: 403,
            s3_code: "AccessDenied".into(),
            message: "denied upstream".into(),
            operation: "head_object".into(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(resp.status(), 403);
        assert!(resp.headers().get("x-cache").is_none());

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        assert!(!head_calls[0].wants_checksum_headers());
    }

    #[tokio::test]
    async fn test_plain_head_respects_stale_on_error_disabled() {
        let key = "script_bundle/head-plain-no-stale.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut stale_meta = test_cache_meta("test-backend", key, b"cached body");
        stale_meta
            .extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachedsum".to_string());
        stale_meta.checksum_mode_checked = true;

        let backend = MockBackend::new().with_head(Err(crate::error::ProxyError::Backend {
            source: "backend down".into(),
            operation: "head_object".into(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);

        let mut config = test_config();
        config.cache_dir = cache.temp_dir.path().to_path_buf();
        config.cache_serve_stale_on_error = false;
        let tmp_dir = cache.temp_dir.path().join("tmp");
        let _ = std::fs::create_dir_all(&tmp_dir);

        let state = Arc::new(AppState {
            backend: Arc::new(backend),
            cache: Arc::new(cache),
            singleflight: Arc::new(crate::cache::SingleFlight::new()),
            auth: Arc::new(MockAuth::allow_all()),
            policy: crate::cache::policy::CachePolicy::new(
                config.cacheable_prefixes.clone(),
                config.cache_max_object_bytes,
            ),
            frontend_bucket: Arc::from(config.frontend_bucket.as_str()),
            backend_bucket: Arc::from(config.backend_bucket.as_str()),
            http_client: reqwest::Client::new(),
            config: Arc::new(config),
        });

        let resp = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(resp.status(), 502);

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        assert!(!head_calls[0].wants_checksum_headers());
    }

    #[tokio::test]
    async fn test_plain_head_not_found_purges_checksum_warmed_cache_entry() {
        let key = "script_bundle/head-plain-not-found.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut stale_meta = test_cache_meta("test-backend", key, b"cached body");
        stale_meta
            .extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "cachedsum".to_string());
        stale_meta.checksum_mode_checked = true;

        let backend = MockBackend::new().with_head(Err(crate::error::ProxyError::UpstreamS3 {
            status_code: 404,
            s3_code: "NoSuchKey".into(),
            message: "deleted upstream".into(),
            operation: "head_object".into(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let resp = handle_head(&state, &make_parsed(key), key).await;
        assert_eq!(resp.status(), 404);
        assert!(state.cache.lookup(&cache_key).await.unwrap().is_none());
        assert_eq!(state.cache.purge_calls.lock().unwrap().len(), 1);
        assert!(state.cache.poison_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_checksum_head_enriches_cache_for_future_hits() {
        let key = "script_bundle/head-checksum-hit.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, b"cached body");
        let matching_etag = stale_meta.etag.clone();

        let mut metadata = HashMap::new();
        metadata.insert("fresh".to_string(), "meta".to_string());

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "backendsum".to_string(),
        );
        extra_headers.insert("cache-control".to_string(), "no-store".to_string());
        extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: matching_etag,
            last_modified: None,
            metadata,
            extra_headers,
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let first = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(first.status(), 200);
        assert!(first.headers().get("x-cache").is_none());
        assert_eq!(
            first.headers().get("x-amz-checksum-sha256").unwrap(),
            "backendsum"
        );

        let second = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(second.status(), 200);
        assert_eq!(second.headers().get("x-cache").unwrap(), "HIT");
        assert_eq!(
            second.headers().get("x-amz-checksum-sha256").unwrap(),
            "backendsum"
        );
        assert_eq!(second.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(second.headers().get("x-amz-meta-fresh").unwrap(), "meta");
        assert!(second.headers().get("x-amz-meta-existing").is_none());
        assert_eq!(
            second.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 1);
        assert!(head_calls[0].wants_checksum_headers());
    }

    #[tokio::test]
    async fn test_checksum_head_removes_stale_cached_metadata_on_match() {
        let key = "script_bundle/head-checksum-prune.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let mut stale_meta = test_cache_meta("test-backend", key, b"cached body");
        stale_meta
            .metadata
            .insert("existing".to_string(), "meta".to_string());
        stale_meta
            .extra_headers
            .insert("cache-control".to_string(), "max-age=60".to_string());
        let matching_etag = stale_meta.etag.clone();

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "backendsum".to_string(),
        );

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(11),
            etag: matching_etag,
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers,
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let first = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(first.status(), 200);
        assert!(first.headers().get("x-cache").is_none());
        assert!(first.headers().get("cache-control").is_none());
        assert!(first.headers().get("x-amz-meta-existing").is_none());

        let second = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(second.status(), 200);
        assert_eq!(second.headers().get("x-cache").unwrap(), "HIT");
        assert!(second.headers().get("cache-control").is_none());
        assert!(second.headers().get("x-amz-meta-existing").is_none());
        assert_eq!(
            second.headers().get("x-amz-checksum-sha256").unwrap(),
            "backendsum"
        );
    }

    #[tokio::test]
    async fn test_checksum_head_keeps_head_only_headers_for_head_but_not_get() {
        let key = "script_bundle/head-checksum-archive-status.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, b"cached body");
        let matching_etag = stale_meta.etag.clone();

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "backendsum".to_string(),
        );
        extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );

        let mut get_extra = HashMap::new();
        get_extra.insert("x-amz-checksum-sha256".to_string(), "getsum".to_string());

        let backend = MockBackend::new()
            .with_head(Ok(crate::backend::models::HeadObjectOutput {
                content_type: Some("text/plain".to_string()),
                content_length: Some(11),
                etag: matching_etag.clone(),
                last_modified: None,
                metadata: HashMap::new(),
                extra_headers,
            }))
            .with_get(Ok(crate::handlers::test_utils::MockGetResponse {
                body: b"cached body".to_vec(),
                content_type: Some("text/plain".to_string()),
                etag: matching_etag,
                extra_headers: get_extra,
            }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let first_head = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(first_head.status(), 200);
        assert_eq!(
            first_head.headers().get("x-amz-archive-status").unwrap(),
            "ARCHIVE_ACCESS"
        );

        let second_head = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(second_head.status(), 200);
        assert_eq!(second_head.headers().get("x-cache").unwrap(), "HIT");

        // Checksum GET falls through to backend GET (HEAD can't flip
        // checksum_mode_checked) and gets GET-derived checksums.
        let get =
            crate::handlers::get::handle_get(&state, &make_get_parsed_with_checksum(key), key)
                .await;
        assert_eq!(get.status(), 200);
        assert_eq!(get.headers().get("x-cache").unwrap(), "MISS");
        // GET response has GET-derived checksum, not HEAD-derived.
        assert_eq!(
            get.headers().get("x-amz-checksum-sha256").unwrap(),
            "getsum"
        );
        assert!(get.headers().get("x-amz-archive-status").is_none());

        // Both HEAD and GET backend calls were made.
        assert_eq!(state.backend.head_read_calls.lock().unwrap().len(), 2); // refresh + GET's HEAD probe
        assert_eq!(state.backend.get_read_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_checksum_head_mismatched_etag_purges_stale_cache_entry() {
        let key = "script_bundle/head-checksum-mismatch.js";
        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let stale_meta = test_cache_meta("test-backend", key, b"cached body");

        let mut extra_headers = HashMap::new();
        extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "backendsum".to_string(),
        );

        let backend = MockBackend::new().with_head(Ok(crate::backend::models::HeadObjectOutput {
            content_type: Some("text/plain".to_string()),
            content_length: Some(10),
            etag: Some("\"head-etag\"".to_string()),
            last_modified: None,
            metadata: HashMap::new(),
            extra_headers: extra_headers.clone(),
        }));
        let cache = MockCache::new().with_entry(&cache_key, b"cached body", stale_meta);
        let state = build_app_state(backend, cache, MockAuth::allow_all());

        let first = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(first.status(), 200);
        assert!(first.headers().get("x-cache").is_none());
        assert_eq!(
            first.headers().get("x-amz-checksum-sha256").unwrap(),
            "backendsum"
        );
        assert!(state.cache.lookup(&cache_key).await.unwrap().is_none());
        assert_eq!(state.cache.purge_calls.lock().unwrap().len(), 1);
        assert!(state.cache.poison_calls.lock().unwrap().is_empty());

        let fresh_body = b"fresh body".to_vec();
        *state.backend.get_response.lock().unwrap() =
            Some(Ok(crate::handlers::test_utils::MockGetResponse {
                body: fresh_body.clone(),
                content_type: Some("text/plain".to_string()),
                etag: Some("\"head-etag\"".to_string()),
                extra_headers: HashMap::new(),
            }));

        let get_resp =
            crate::handlers::get::handle_get(&state, &make_get_parsed_with_checksum(key), key)
                .await;
        assert_eq!(get_resp.status(), 200);
        assert_eq!(get_resp.headers().get("x-cache").unwrap(), "MISS");
        let get_body = axum::body::to_bytes(get_resp.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(get_body.as_ref(), fresh_body.as_slice());

        *state.backend.head_response.lock().unwrap() =
            Some(Ok(crate::backend::models::HeadObjectOutput {
                content_type: Some("text/plain".to_string()),
                content_length: Some(10),
                etag: Some("\"head-etag\"".to_string()),
                last_modified: None,
                metadata: HashMap::new(),
                extra_headers,
            }));

        let second = handle_head(&state, &make_parsed_with_checksum(key), key).await;
        assert_eq!(second.status(), 200);
        assert!(second.headers().get("x-cache").is_none());
        assert_eq!(
            second.headers().get("x-amz-checksum-sha256").unwrap(),
            "backendsum"
        );

        let head_calls = state.backend.head_read_calls.lock().unwrap();
        assert_eq!(head_calls.len(), 2);
        assert!(head_calls.iter().all(|call| call.wants_checksum_headers()));
        let get_calls = state.backend.get_read_calls.lock().unwrap();
        assert_eq!(get_calls.len(), 1);
        assert!(get_calls[0].wants_checksum_headers());
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
