pub mod aws_chunked;
pub mod delete;
pub mod get;
pub mod head;
pub mod list;
mod modifiers;
pub mod multipart;
pub mod passthrough;
pub mod put;

use modifiers::*;

use std::sync::Arc;
use std::time::Instant;

/// Log messages for cache invalidation operations.
pub(crate) struct InvalidationMessages {
    pub purge_success: &'static str,
    pub purge_changed: &'static str,
    pub purge_fail: &'static str,
    pub poison_success: &'static str,
    pub poison_fail: &'static str,
}

/// Shared invalidation helper used by both GET and HEAD handlers.
/// Returns `true` if the entry was successfully purged/poisoned (the 404
/// is authoritative for the observed generation), or `false` if the entry
/// was replaced by a newer generation (the 404 may be stale — callers
/// should re-probe the cache instead of returning the 404).
pub(crate) async fn purge_then_poison_if_unchanged<C: crate::cache::CacheStore>(
    cache: &Arc<C>,
    cache_key: &crate::cache::key::CacheKey,
    expected_fill_id: crate::cache::FillId,
    request_id: &str,
    operation: &str,
    key: &str,
    msgs: &InvalidationMessages,
) -> bool {
    match cache.purge_if_unchanged(cache_key, expected_fill_id).await {
        Ok(true) => {
            tracing::warn!(
                request_id = request_id,
                operation = operation,
                key = key,
                "{}",
                msgs.purge_success
            );
            true
        }
        Ok(false) => {
            tracing::info!(
                request_id = request_id,
                operation = operation,
                key = key,
                "{}",
                msgs.purge_changed
            );
            false
        }
        Err(purge_err) => {
            tracing::warn!(
                request_id = request_id,
                operation = operation,
                key = key,
                error = %purge_err,
                "{}",
                msgs.purge_fail
            );
            match cache.poison_if_unchanged(cache_key, expected_fill_id).await {
                Ok(true) => {
                    tracing::warn!(
                        request_id = request_id,
                        operation = operation,
                        key = key,
                        "{}",
                        msgs.poison_success
                    );
                    true
                }
                Ok(false) => false,
                Err(poison_err) => {
                    tracing::warn!(
                        request_id = request_id,
                        operation = operation,
                        key = key,
                        error = %poison_err,
                        "{}",
                        msgs.poison_fail
                    );
                    // Both purge and poison failed — treat as invalidated
                    // (conservative: don't return stale 404).
                    true
                }
            }
        }
    }
}

use axum::body::Body;
use axum::extract::State;
use http::{Request, Response};
use metrics::{counter, gauge, histogram};

use crate::auth::RequestGate;
use crate::auth::sigv4::SigV4Verifier;
use crate::backend::Backend;
use crate::cache::policy::CachePolicy;
use crate::cache::{CacheStore, SingleFlight};
use crate::config::Config;
use crate::s3::errors::S3Error;
use crate::s3::ops::S3Operation;
use crate::s3::parse::parse_request;

/// Shared application state passed to all handlers.
/// Generic over Backend and CacheStore to support both real and mock implementations,
/// since these traits use `async fn` and are not dyn-compatible.
pub struct AppState<B: Backend, C: CacheStore> {
    pub backend: Arc<B>,
    pub cache: Arc<C>,
    pub singleflight: Arc<SingleFlight>,
    pub auth: Arc<dyn RequestGate>,
    /// Optional strict-mode SigV4 verifier. When `Some`, replaces the
    /// `auth` gate for normal (non-streaming, non-presigned) requests —
    /// see `handle_s3_request`.
    pub inbound_sigv4: Option<Arc<SigV4Verifier>>,
    pub policy: CachePolicy,
    pub config: Arc<Config>,
    pub frontend_bucket: Arc<str>,
    pub backend_bucket: Arc<str>,
    pub http_client: reqwest::Client,
}

/// Main S3 request handler. All S3 API calls go through this function.
pub async fn handle_s3_request<B: Backend + 'static, C: CacheStore + 'static>(
    State(state): State<Arc<AppState<B, C>>>,
    req: Request<Body>,
) -> Response<Body> {
    let start = Instant::now();
    gauge!("s3proxy_in_flight_requests").increment(1.0);

    // Split request into parts and body so we can parse headers/URI
    // without consuming the body (needed for PUT/POST handlers).
    let (parts, body) = req.into_parts();
    let parse_req = Request::from_parts(parts, ());
    let parsed = parse_request(&parse_req);
    let (parts, _) = parse_req.into_parts();
    // `body` may need to be replaced after we buffer it for strict
    // payload-hash verification; rebind as mut for that branch.
    let mut body = body;

    let op_name = parsed.operation.name();

    // Reject HTTP methods that S3 never uses. This check runs before auth
    // and bucket validation so that TRACE *, CONNECT host:443, etc. never
    // reach deeper routing logic.
    const S3_METHODS: &[&str] = &["GET", "HEAD", "PUT", "POST", "DELETE"];
    if !S3_METHODS.contains(&parts.method.as_str()) {
        let s3err = S3Error::from_proxy_error(
            &crate::error::ProxyError::UnsupportedOperation {
                operation: format!("{} {}", parts.method, parts.uri.path()),
            },
            &parsed.request_id,
            None,
        );
        let response = s3err.to_response();
        record_metrics(op_name, &response, start);
        return response;
    }

    // Record request body size for writes (from content-length header).
    // Reject negative Content-Length with 400 Bad Request and only record
    // valid non-negative values in metrics.
    if let Some(cl) = parts.headers.get("content-length")
        && let Ok(s) = cl.to_str()
        && let Ok(n) = s.parse::<i64>()
    {
        if n < 0 {
            let s3err = S3Error::from_proxy_error(
                &crate::error::ProxyError::InvalidRequest {
                    message: "Content-Length must not be negative".to_string(),
                },
                &parsed.request_id,
                None,
            );
            let response = s3err.to_response();
            record_metrics(op_name, &response, start);
            return response;
        }
        histogram!("s3proxy_request_size_bytes", "operation" => op_name).record(n as f64);
    }

    // Auth check (applies to ALL operations including passthrough).
    //
    // When strict-mode SigV4 verification is configured, it REPLACES the
    // legacy `RequestGate`. The verifier authenticates the request via
    // signature comparison rather than gating on access-key allowlist /
    // trust-the-network. We hold onto the VerifiedRequest so we can drive
    // the (optional) body-hash check after bucket validation.
    let verified = if let Some(verifier) = &state.inbound_sigv4 {
        match verifier.verify(&parts, &parsed.request_id) {
            Ok(v) => Some(v),
            Err(s3err) => {
                let response = s3err.to_response();
                record_metrics(op_name, &response, start);
                return response;
            }
        }
    } else {
        if let Err(e) = state.auth.check_access(&parsed) {
            let s3err = S3Error::from_proxy_error(&e, &parsed.request_id, None);
            let response = s3err.to_response();
            record_metrics(op_name, &response, start);
            return response;
        }
        None
    };

    // Check bucket is allowed (must match frontend_bucket).
    // For Unsupported operations, extract the bucket from the raw path.
    let op_bucket = match &parsed.operation {
        S3Operation::Unsupported { path, .. } => {
            // Path is like "/bucket/key" or "/bucket" — extract first segment.
            path.strip_prefix('/')
                .unwrap_or(path)
                .split('/')
                .next()
                .unwrap_or("")
        }
        other => other.bucket(),
    };
    if op_bucket != &*state.frontend_bucket {
        let s3err = S3Error::no_such_bucket(op_bucket, &parsed.request_id);
        let response = s3err.to_response();
        record_metrics(op_name, &response, start);
        return response;
    }

    // Strict mode body-hash verification. When the client signed a concrete
    // payload digest (x-amz-content-sha256 is hex, not UNSIGNED-PAYLOAD or a
    // streaming sentinel), buffer the body up to max_request_body_bytes,
    // confirm SHA-256 matches the signed value, then put the bytes back so
    // the downstream handler can read them. We deliberately do this AFTER
    // bucket validation so an unrelated bucket gets the cheaper NoSuchBucket
    // response rather than burning a body read first.
    if let (Some(v), Some(verifier)) = (verified.as_ref(), state.inbound_sigv4.as_ref())
        && v.payload.requires_body_bytes()
    {
        match axum::body::to_bytes(body, state.config.max_request_body_bytes as usize).await {
            Ok(bytes) => {
                if let Err(s3err) = verifier.verify_payload_hash(v, &bytes, &parsed.request_id) {
                    let response = s3err.to_response();
                    record_metrics(op_name, &response, start);
                    return response;
                }
                body = Body::from(bytes);
            }
            Err(e) => {
                let s3err = S3Error::from_body_error(&e, &parsed.request_id);
                let response = s3err.to_response();
                record_metrics(op_name, &response, start);
                return response;
            }
        }
    }

    // Handle unsupported S3 operations by proxying to the backend.
    // (Non-S3 methods like PATCH/TRACE/CONNECT are already rejected above.)
    if let S3Operation::Unsupported {
        ref method,
        ref path,
    } = parsed.operation
    {
        tracing::warn!(
            request_id = %parsed.request_id,
            method = %method,
            path = %path,
            "unsupported operation, attempting passthrough to backend"
        );

        let response = route_to_passthrough(&state, &parts, body, &parsed.request_id).await;
        record_metrics(op_name, &response, start);
        return response;
    }

    // Dispatch to handler based on operation
    let response = match &parsed.operation {
        S3Operation::GetObject { key, .. } => {
            if has_unsupported_get_modifiers(&parts.headers) {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            } else {
                get::handle_get(&state, &parsed, key).await
            }
        }
        S3Operation::HeadObject { key, .. } => {
            if has_unsupported_get_modifiers(&parts.headers) {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            } else {
                head::handle_head(&state, &parsed, key).await
            }
        }
        S3Operation::PutObject { key, .. } => {
            match classify_put_body_route(&parsed.extra_amz_headers, &parts.headers) {
                WriteBodyRoute::Typed => put::handle_put(&state, &parsed, key, body).await,
                WriteBodyRoute::DecodeAwsChunked => {
                    aws_chunked::handle_put_decode_aws_chunked(
                        &state,
                        &parsed,
                        key,
                        &parts.headers,
                        body,
                    )
                    .await
                }
                WriteBodyRoute::Passthrough => {
                    route_to_passthrough(&state, &parts, body, &parsed.request_id).await
                }
                WriteBodyRoute::RejectUnsupportedSignature => {
                    reject_unsupported_signature(&parsed.request_id)
                }
            }
        }
        S3Operation::DeleteObject { key, .. } => {
            if has_unsupported_write_modifiers(&parsed.extra_amz_headers, &parts.headers) {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            } else {
                delete::handle_delete(&state, &parsed, key).await
            }
        }
        S3Operation::ListObjectsV1 { params, .. } | S3Operation::ListObjectsV2 { params, .. } => {
            if has_unsupported_list_modifiers(parts.uri.query(), &parts.headers) {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            } else {
                let is_v2 = matches!(&parsed.operation, S3Operation::ListObjectsV2 { .. });
                list::handle_list(&state, &parsed, params, is_v2).await
            }
        }
        S3Operation::CreateMultipartUpload { key, .. } => {
            if has_unsupported_multipart_modifiers(&parsed.extra_amz_headers, &parts.headers) {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            } else {
                multipart::handle_create_multipart(&state, &parsed, key).await
            }
        }
        S3Operation::UploadPart {
            key,
            part_number,
            upload_id,
            ..
        } => match classify_upload_part_body_route(&parsed.extra_amz_headers, &parts.headers) {
            WriteBodyRoute::Typed => {
                multipart::handle_upload_part(&state, &parsed, key, *part_number, upload_id, body)
                    .await
            }
            WriteBodyRoute::DecodeAwsChunked => {
                aws_chunked::handle_upload_part_decode_aws_chunked(
                    &state,
                    &parsed,
                    key,
                    *part_number,
                    upload_id,
                    &parts.headers,
                    body,
                )
                .await
            }
            WriteBodyRoute::Passthrough => {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            }
            WriteBodyRoute::RejectUnsupportedSignature => {
                reject_unsupported_signature(&parsed.request_id)
            }
        },
        S3Operation::CompleteMultipartUpload { key, upload_id, .. } => {
            if has_unsupported_multipart_modifiers(&parsed.extra_amz_headers, &parts.headers) {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            } else {
                // Read the body eagerly so we can check for per-part checksum
                // XML elements (ChecksumCRC32, ChecksumCRC32C, ChecksumCRC64NVME,
                // ChecksumSHA1, ChecksumSHA256). The typed path drops these —
                // route through passthrough to preserve integrity validation.
                match axum::body::to_bytes(body, state.config.max_request_body_bytes as usize).await
                {
                    Err(e) => {
                        let s3err = S3Error::from_body_error(&e, &parsed.request_id);
                        s3err.to_response()
                    }
                    Ok(body_bytes) if crate::s3::xml::body_has_checksum_elements(&body_bytes) => {
                        route_to_passthrough(
                            &state,
                            &parts,
                            Body::from(body_bytes),
                            &parsed.request_id,
                        )
                        .await
                    }
                    Ok(body_bytes) => {
                        multipart::handle_complete_multipart(
                            &state, &parsed, key, upload_id, body_bytes,
                        )
                        .await
                    }
                }
            }
        }
        S3Operation::AbortMultipartUpload { key, upload_id, .. } => {
            if has_unsupported_multipart_modifiers(&parsed.extra_amz_headers, &parts.headers) {
                route_to_passthrough(&state, &parts, body, &parsed.request_id).await
            } else {
                multipart::handle_abort_multipart(&state, &parsed, key, upload_id).await
            }
        }
        S3Operation::Unsupported { .. } => {
            // Already handled above; this branch is unreachable.
            unreachable!("Unsupported operations are handled before dispatch")
        }
    };

    record_metrics(op_name, &response, start);
    response
}

/// Emit an `UnsupportedSignature` error response without contacting the
/// backend. Used by the aws-chunked dispatch path when the routing
/// classifier returns `RejectUnsupportedSignature` — currently for
/// ECDSA-signed streaming uploads, whose inbound `chunk-signature` values
/// are bound to the client's private key and cannot be re-signed or
/// validated by the proxy.
fn reject_unsupported_signature(request_id: &str) -> Response<Body> {
    S3Error::unsupported_signature(
        "aws-chunked ECDSA streaming uploads (STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*) \
         are not supported by this proxy",
        request_id,
    )
    .to_response()
}

/// Route through raw passthrough, rewriting the bucket in the path.
async fn route_to_passthrough<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parts: &http::request::Parts,
    body: Body,
    request_id: &str,
) -> Response<Body> {
    let raw_path = parts.uri.path();
    let rewritten = rewrite_bucket_in_path(raw_path, &state.frontend_bucket, &state.backend_bucket);
    let query = parts.uri.query();
    passthrough::handle_passthrough(
        state,
        parts.method.as_str(),
        &rewritten,
        query,
        &parts.headers,
        body,
        request_id,
    )
    .await
}

/// Rewrite the bucket portion of a path-style S3 URL.
/// E.g. `/frontend-bucket/key` → `/backend-bucket/key`.
fn rewrite_bucket_in_path(path: &str, frontend_bucket: &str, backend_bucket: &str) -> String {
    let stripped = path.strip_prefix('/').unwrap_or(path);
    if let Some(rest) = stripped.strip_prefix(frontend_bucket) {
        if let Some(key_part) = rest.strip_prefix('/') {
            return format!("/{}/{}", backend_bucket, key_part);
        } else if rest.is_empty() {
            return format!("/{}", backend_bucket);
        }
    }
    path.to_owned()
}

/// Map common HTTP status codes to static strings, avoiding allocation.
fn status_str(status: http::StatusCode) -> &'static str {
    match status.as_u16() {
        200 => "200",
        204 => "204",
        206 => "206",
        400 => "400",
        403 => "403",
        404 => "404",
        500 => "500",
        501 => "501",
        502 => "502",
        503 => "503",
        504 => "504",
        _ => "other",
    }
}

/// Record request metrics (counter + histogram + in-flight + cache + response size).
///
/// Metrics are recorded at handler completion, before the response body is
/// streamed to the client. For streamed GET/passthrough responses, this means:
/// - `request_duration_seconds` measures handler-setup time (backend fetch +
///   cache logic), not end-to-end transfer time. This is intentional: setup
///   time reflects proxy performance, while transfer time is dominated by
///   client bandwidth and is not actionable.
/// - `in_flight_requests` decrements before the body finishes streaming. For
///   a caching proxy with mostly small/fast responses this is a minor
///   inaccuracy that avoids the complexity of wrapping every response body.
fn record_metrics(operation: &'static str, response: &Response<Body>, start: Instant) {
    gauge!("s3proxy_in_flight_requests").decrement(1.0);

    let duration = start.elapsed().as_secs_f64();
    let status = status_str(response.status());
    counter!("s3proxy_requests_total", "operation" => operation, "status" => status).increment(1);
    histogram!("s3proxy_request_duration_seconds", "operation" => operation).record(duration);

    // Cache hit/miss/bypass/stale tracking.
    if let Some(cache_status) = response.headers().get("x-cache")
        && let Ok(cs) = cache_status.to_str()
    {
        let label: &'static str = match cs {
            "HIT" => "HIT",
            "MISS" => "MISS",
            "BYPASS" => "BYPASS",
            "STALE" => "STALE",
            _ => "OTHER",
        };
        counter!("s3proxy_cache_total", "status" => label).increment(1);
    }

    // Response body size.
    if let Some(cl) = response.headers().get("content-length")
        && let Ok(size) = cl.to_str().unwrap_or("0").parse::<f64>()
    {
        histogram!("s3proxy_response_size_bytes", "operation" => operation).record(size);
    }
}

/// Purge a cache key with one retry, falling back to a poison marker on failure.
/// Also cancels any in-flight singleflight for the key.
pub(crate) async fn invalidate_cache_key<C: CacheStore>(
    cache: &Arc<C>,
    singleflight: &Arc<SingleFlight>,
    cache_key: &crate::cache::key::CacheKey,
    operation: &str,
    object_key: &str,
    request_id: &str,
) {
    if let Err(e) = cache.purge(cache_key).await {
        tracing::warn!(
            request_id = %request_id,
            error = %e,
            operation = operation,
            key = object_key,
            "cache purge failed, retrying once"
        );
        if let Err(e2) = cache.purge(cache_key).await {
            tracing::error!(
                request_id = %request_id,
                error = %e2,
                operation = operation,
                key = object_key,
                "cache purge failed on retry — poisoning key to block stale reads"
            );
            if let Err(e3) = cache.poison(cache_key).await {
                tracing::error!(
                    request_id = %request_id,
                    error = %e3,
                    operation = operation,
                    key = object_key,
                    "CRITICAL: cache purge AND poison marker both failed — stale data may be served"
                );
            }
        }
    }
    singleflight.cancel(cache_key).await;
}

#[cfg(test)]
pub mod test_utils {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use bytes::Bytes;
    use chrono::Utc;

    use crate::auth::RequestGate;
    use crate::backend::models::*;
    use crate::backend::{Backend, BoxByteStream};
    use crate::cache::entry::CacheEntry;
    use crate::cache::key::CacheKey;
    use crate::cache::metadata::CacheMeta;
    use crate::cache::{CacheStatsSnapshot, CacheStore, FillGuard, FillId};
    use crate::error::ProxyError;
    use crate::s3::ops::ParsedRequest;

    // ---- MockBackend ----

    #[derive(Clone)]
    pub struct MockGetResponse {
        pub body: Vec<u8>,
        pub content_type: Option<String>,
        pub etag: Option<String>,
        pub extra_headers: HashMap<String, String>,
    }

    /// Convert a Vec<u8> into a BoxByteStream (single-chunk stream).
    fn vec_to_stream(data: Vec<u8>) -> BoxByteStream {
        let stream = tokio_stream::once(Ok::<Bytes, std::io::Error>(Bytes::from(data)));
        Box::pin(stream)
    }

    pub struct MockBackend {
        pub get_response: Mutex<Option<Result<MockGetResponse, ProxyError>>>,
        pub head_response: Mutex<Option<Result<HeadObjectOutput, ProxyError>>>,
        pub put_response: Mutex<Option<Result<PutObjectOutput, ProxyError>>>,
        pub delete_response: Mutex<Option<Result<DeleteObjectOutput, ProxyError>>>,
        pub list_response: Mutex<Option<Result<ListObjectsOutput, ProxyError>>>,
        pub create_multipart_response: Mutex<Option<Result<CreateMultipartOutput, ProxyError>>>,
        pub upload_part_response: Mutex<Option<Result<UploadPartOutput, ProxyError>>>,
        pub complete_multipart_response: Mutex<Option<Result<CompleteMultipartOutput, ProxyError>>>,
        pub abort_multipart_response: Mutex<Option<Result<(), ProxyError>>>,
        pub get_read_calls: Mutex<Vec<ReadOptions>>,
        pub head_read_calls: Mutex<Vec<ReadOptions>>,
        pub put_calls: Mutex<Vec<PutObjectInput>>,
        pub put_spool_calls: Mutex<Vec<PutObjectSpoolInput>>,
        pub upload_part_spool_calls: Mutex<Vec<UploadPartSpoolInput>>,
        pub delete_calls: Mutex<Vec<(String, String)>>,
        /// Total number of Backend trait method invocations.
        pub total_calls: std::sync::atomic::AtomicU32,
    }

    impl MockBackend {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self {
                get_response: Mutex::new(None),
                head_response: Mutex::new(None),
                put_response: Mutex::new(None),
                delete_response: Mutex::new(None),
                list_response: Mutex::new(None),
                create_multipart_response: Mutex::new(None),
                upload_part_response: Mutex::new(None),
                complete_multipart_response: Mutex::new(None),
                abort_multipart_response: Mutex::new(None),
                get_read_calls: Mutex::new(Vec::new()),
                head_read_calls: Mutex::new(Vec::new()),
                put_calls: Mutex::new(Vec::new()),
                put_spool_calls: Mutex::new(Vec::new()),
                upload_part_spool_calls: Mutex::new(Vec::new()),
                delete_calls: Mutex::new(Vec::new()),
                total_calls: std::sync::atomic::AtomicU32::new(0),
            }
        }

        pub fn with_get(self, resp: Result<MockGetResponse, ProxyError>) -> Self {
            *self.get_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_head(self, resp: Result<HeadObjectOutput, ProxyError>) -> Self {
            *self.head_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_put(self, resp: Result<PutObjectOutput, ProxyError>) -> Self {
            *self.put_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_delete(self, resp: Result<DeleteObjectOutput, ProxyError>) -> Self {
            *self.delete_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_list(self, resp: Result<ListObjectsOutput, ProxyError>) -> Self {
            *self.list_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_create_multipart(
            self,
            resp: Result<CreateMultipartOutput, ProxyError>,
        ) -> Self {
            *self.create_multipart_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_upload_part(self, resp: Result<UploadPartOutput, ProxyError>) -> Self {
            *self.upload_part_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_complete_multipart(
            self,
            resp: Result<CompleteMultipartOutput, ProxyError>,
        ) -> Self {
            *self.complete_multipart_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_abort_multipart(self, resp: Result<(), ProxyError>) -> Self {
            *self.abort_multipart_response.lock().unwrap() = Some(resp);
            self
        }
    }

    impl Backend for MockBackend {
        async fn get_object(
            &self,
            req: GetObjectInput<'_>,
        ) -> Result<(GetObjectMeta, BoxByteStream), ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.get_read_calls.lock().unwrap().push(req.options);
            let resp = self.get_response.lock().unwrap().take().unwrap_or_else(|| {
                Err(ProxyError::Backend {
                    source: "no mock response configured".into(),
                    operation: "get_object".into(),
                })
            });
            match resp {
                Ok(mock) => {
                    let meta = GetObjectMeta {
                        content_type: mock.content_type.clone(),
                        content_length: Some(mock.body.len() as i64),
                        etag: mock.etag.clone(),
                        last_modified: Some(Utc::now()),
                        metadata: HashMap::new(),
                        extra_headers: mock.extra_headers.clone(),
                    };
                    let stream = vec_to_stream(mock.body);
                    Ok((meta, stream))
                }
                Err(e) => Err(e),
            }
        }

        async fn head_object(
            &self,
            req: HeadObjectInput<'_>,
        ) -> Result<HeadObjectOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.head_read_calls.lock().unwrap().push(req.options);
            self.head_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "head_object".into(),
                    })
                })
        }

        async fn put_object(&self, req: PutObjectInput) -> Result<PutObjectOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.put_calls.lock().unwrap().push(PutObjectInput {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                body: req.body.clone(),
                content_type: req.content_type.clone(),
                content_md5: req.content_md5.clone(),
                metadata: req.metadata.clone(),
                extra_amz_headers: req.extra_amz_headers.clone(),
                content_headers: req.content_headers.clone(),
            });
            self.put_response.lock().unwrap().take().unwrap_or_else(|| {
                Err(ProxyError::Backend {
                    source: "no mock response configured".into(),
                    operation: "put_object".into(),
                })
            })
        }

        async fn put_object_from_path(
            &self,
            req: PutObjectSpoolInput,
        ) -> Result<PutObjectOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.put_spool_calls
                .lock()
                .unwrap()
                .push(PutObjectSpoolInput {
                    bucket: req.bucket.clone(),
                    key: req.key.clone(),
                    path: req.path.clone(),
                    len: req.len,
                    sha256_hex: req.sha256_hex.clone(),
                    content_type: req.content_type.clone(),
                    content_md5: req.content_md5.clone(),
                    metadata: req.metadata.clone(),
                    extra_amz_headers: req.extra_amz_headers.clone(),
                    content_headers: req.content_headers.clone(),
                    checksum: req.checksum.clone(),
                });
            self.put_response.lock().unwrap().take().unwrap_or_else(|| {
                Err(ProxyError::Backend {
                    source: "no mock response configured".into(),
                    operation: "put_object_from_path".into(),
                })
            })
        }

        async fn delete_object(
            &self,
            req: DeleteObjectInput<'_>,
        ) -> Result<DeleteObjectOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.delete_calls
                .lock()
                .unwrap()
                .push((req.bucket.to_string(), req.key.to_string()));
            self.delete_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "delete_object".into(),
                    })
                })
        }

        async fn list_objects(
            &self,
            _req: ListObjectsInput,
        ) -> Result<ListObjectsOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.list_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "list_objects".into(),
                    })
                })
        }

        async fn create_multipart_upload(
            &self,
            _req: CreateMultipartUploadInput<'_>,
        ) -> Result<CreateMultipartOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.create_multipart_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "create_multipart_upload".into(),
                    })
                })
        }

        async fn upload_part(&self, _req: UploadPartInput) -> Result<UploadPartOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.upload_part_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "upload_part".into(),
                    })
                })
        }

        async fn upload_part_from_path(
            &self,
            req: UploadPartSpoolInput,
        ) -> Result<UploadPartOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.upload_part_spool_calls
                .lock()
                .unwrap()
                .push(UploadPartSpoolInput {
                    bucket: req.bucket.clone(),
                    key: req.key.clone(),
                    upload_id: req.upload_id.clone(),
                    part_number: req.part_number,
                    path: req.path.clone(),
                    len: req.len,
                    sha256_hex: req.sha256_hex.clone(),
                    content_md5: req.content_md5.clone(),
                    extra_amz_headers: req.extra_amz_headers.clone(),
                    checksum: req.checksum.clone(),
                });
            self.upload_part_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "upload_part_from_path".into(),
                    })
                })
        }

        async fn complete_multipart_upload(
            &self,
            _req: CompleteMultipartInput,
        ) -> Result<CompleteMultipartOutput, ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.complete_multipart_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "complete_multipart_upload".into(),
                    })
                })
        }

        async fn abort_multipart_upload(
            &self,
            _req: AbortMultipartUploadInput<'_>,
        ) -> Result<(), ProxyError> {
            self.total_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.abort_multipart_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "abort_multipart_upload".into(),
                    })
                })
        }
    }

    // ---- MockCache ----
    //
    // Stores cache entries on disk in a temp directory so that
    // CacheEntry.body_path is a real file that can be streamed.

    struct MockCommitFillPause {
        started: Option<tokio::sync::oneshot::Sender<()>>,
        release: std::sync::Arc<tokio::sync::Notify>,
    }

    struct PendingPeekHeadStateUpdate {
        call: u32,
        key_hash: String,
        head_extra_headers: HashMap<String, String>,
        head_checksum_headers: HashMap<String, String>,
        head_metadata_checked: bool,
        head_checksum_checked: bool,
    }

    pub struct MockCache {
        pub entries: Mutex<HashMap<String, CacheEntry>>,
        next_fill_id: std::sync::atomic::AtomicU64,
        fill_generation: std::sync::atomic::AtomicU64,
        pub poisoned: Mutex<std::collections::HashSet<String>>,
        pub lookup_count: std::sync::atomic::AtomicU32,
        pub peek_count: std::sync::atomic::AtomicU32,
        pub peek_body_count: std::sync::atomic::AtomicU32,
        pub note_hit_count: std::sync::atomic::AtomicU32,
        pub note_miss_count: std::sync::atomic::AtomicU32,
        pub purge_calls: Mutex<Vec<CacheKey>>,
        pub fill_calls: Mutex<Vec<CacheKey>>,
        pub poison_calls: Mutex<Vec<CacheKey>>,
        pub purge_should_fail: Mutex<bool>,
        peek_error: Mutex<Option<ProxyError>>,
        /// When set, purge_if_unchanged swaps in this replacement entry
        /// (simulating a concurrent refill) and returns false.
        pub purge_swaps_entry: Mutex<Option<(String, CacheEntry)>>,
        peek_head_state_update: Mutex<Option<PendingPeekHeadStateUpdate>>,
        commit_fill_pause: Mutex<Option<MockCommitFillPause>>,
        pub temp_dir: tempfile::TempDir,
    }

    impl MockCache {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                next_fill_id: std::sync::atomic::AtomicU64::new(1),
                fill_generation: std::sync::atomic::AtomicU64::new(0),
                poisoned: Mutex::new(std::collections::HashSet::new()),
                lookup_count: std::sync::atomic::AtomicU32::new(0),
                peek_count: std::sync::atomic::AtomicU32::new(0),
                peek_body_count: std::sync::atomic::AtomicU32::new(0),
                note_hit_count: std::sync::atomic::AtomicU32::new(0),
                note_miss_count: std::sync::atomic::AtomicU32::new(0),
                purge_calls: Mutex::new(Vec::new()),
                fill_calls: Mutex::new(Vec::new()),
                poison_calls: Mutex::new(Vec::new()),
                purge_should_fail: Mutex::new(false),
                peek_error: Mutex::new(None),
                purge_swaps_entry: Mutex::new(None),
                peek_head_state_update: Mutex::new(None),
                commit_fill_pause: Mutex::new(None),
                temp_dir: tempfile::TempDir::new().expect("create mock cache temp dir"),
            }
        }

        pub fn with_next_peek_error(self, error: ProxyError) -> Self {
            *self.peek_error.lock().unwrap() = Some(error);
            self
        }

        pub fn publish_head_state_after_nth_peek(
            &self,
            key: &CacheKey,
            call: u32,
            head_extra_headers: HashMap<String, String>,
            head_checksum_headers: HashMap<String, String>,
            head_metadata_checked: bool,
            head_checksum_checked: bool,
        ) {
            *self.peek_head_state_update.lock().unwrap() = Some(PendingPeekHeadStateUpdate {
                call,
                key_hash: key.hash_hex().to_string(),
                head_extra_headers,
                head_checksum_headers,
                head_metadata_checked,
                head_checksum_checked,
            });
        }

        pub fn pause_next_commit_fill(
            &self,
        ) -> (
            tokio::sync::oneshot::Receiver<()>,
            std::sync::Arc<tokio::sync::Notify>,
        ) {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let release = std::sync::Arc::new(tokio::sync::Notify::new());
            *self.commit_fill_pause.lock().unwrap() = Some(MockCommitFillPause {
                started: Some(started_tx),
                release: std::sync::Arc::clone(&release),
            });
            (started_rx, release)
        }

        /// Stage a replacement entry that will be swapped in when
        /// `purge_if_unchanged` is called, simulating a concurrent refill.
        /// The purge will return `Ok(false)` and subsequent reads will see
        /// the replacement.
        pub fn stage_purge_replacement(&self, key: &CacheKey, body: &[u8], mut meta: CacheMeta) {
            use std::sync::atomic::{AtomicU64, Ordering};
            static MOCK_COUNTER: AtomicU64 = AtomicU64::new(100_000);
            let id = MOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
            meta.fill_id = FillId::from(
                self.next_fill_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            );
            meta.metadata_version = 0;
            let body_path = self.temp_dir.path().join(format!("{}.body", id));
            std::fs::write(&body_path, body).expect("write mock body");
            let entry = CacheEntry {
                meta: Arc::new(meta),
                body_path,
                body_file: None,
            };
            *self.purge_swaps_entry.lock().unwrap() = Some((key.hash_hex().to_string(), entry));
        }

        /// Replace the current entry with a freshly published generation.
        pub fn replace_entry_with_new_generation(
            &self,
            key: &CacheKey,
            body: &[u8],
            mut meta: CacheMeta,
        ) {
            use std::sync::atomic::{AtomicU64, Ordering};
            static MOCK_COUNTER: AtomicU64 = AtomicU64::new(200_000);
            let id = MOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
            meta.fill_id = FillId::from(
                self.next_fill_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            );
            meta.metadata_version = 0;
            let body_path = self.temp_dir.path().join(format!("{}.body", id));
            std::fs::write(&body_path, body).expect("write mock body");
            let entry = CacheEntry {
                meta: Arc::new(meta),
                body_path,
                body_file: None,
            };
            self.entries
                .lock()
                .unwrap()
                .insert(key.hash_hex().to_string(), entry);
            self.poisoned.lock().unwrap().remove(key.hash_hex());
        }

        pub fn with_purge_failing(self) -> Self {
            *self.purge_should_fail.lock().unwrap() = true;
            self
        }

        /// Add a cache entry, writing the body to a temp file.
        /// Stamps a fresh `fill_id` and resets `metadata_version` to match
        /// `DiskCache::commit_fill` semantics.
        pub fn with_entry(self, key: &CacheKey, body: &[u8], mut meta: CacheMeta) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static MOCK_COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = MOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
            meta.fill_id = FillId::from(
                self.next_fill_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            );
            meta.metadata_version = 0;
            let body_path = self.temp_dir.path().join(format!("{}.body", id));
            std::fs::write(&body_path, body).expect("write mock body");
            let entry = CacheEntry {
                meta: Arc::new(meta),
                body_path,
                body_file: None,
            };
            self.entries
                .lock()
                .unwrap()
                .insert(key.hash_hex().to_string(), entry);
            self.poisoned.lock().unwrap().remove(key.hash_hex());
            self
        }
    }

    impl CacheStore for MockCache {
        async fn lookup(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
            self.lookup_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.poisoned.lock().unwrap().contains(key.hash_hex()) {
                return Ok(None);
            }
            let snapshot = {
                let entries = self.entries.lock().unwrap();
                entries
                    .get(key.hash_hex())
                    .map(|e| (e.meta.clone(), e.body_path.clone()))
            };
            match snapshot {
                Some((meta, body_path)) => {
                    let body_file = Some(tokio::fs::File::open(&body_path).await.map_err(|e| {
                        ProxyError::Cache {
                            source: Box::new(e),
                            operation: "mock lookup open body".into(),
                        }
                    })?);
                    Ok(Some(CacheEntry {
                        meta,
                        body_path,
                        body_file,
                    }))
                }
                None => Ok(None),
            }
        }

        async fn peek(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
            let call = self
                .peek_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            if let Some(error) = self.peek_error.lock().unwrap().take() {
                return Err(error);
            }
            if self.poisoned.lock().unwrap().contains(key.hash_hex()) {
                return Ok(None);
            }
            let entries = self.entries.lock().unwrap();
            let entry = entries.get(key.hash_hex()).map(|e| CacheEntry {
                meta: e.meta.clone(),
                body_path: e.body_path.clone(),
                body_file: None,
            });
            drop(entries);

            let pending_update = {
                let mut pending = self.peek_head_state_update.lock().unwrap();
                match pending.take() {
                    Some(update) if update.call == call => Some(update),
                    Some(update) => {
                        *pending = Some(update);
                        None
                    }
                    None => None,
                }
            };
            if let Some(update) = pending_update
                && let Some(current) = self.entries.lock().unwrap().get_mut(&update.key_hash)
            {
                let meta = Arc::make_mut(&mut current.meta);
                meta.head_extra_headers = update.head_extra_headers;
                meta.head_checksum_headers = update.head_checksum_headers;
                meta.head_metadata_checked = update.head_metadata_checked;
                meta.head_checksum_checked = update.head_checksum_checked;
            }
            Ok(entry)
        }

        async fn peek_body(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
            self.peek_body_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.poisoned.lock().unwrap().contains(key.hash_hex()) {
                return Ok(None);
            }
            let snapshot = {
                let entries = self.entries.lock().unwrap();
                entries
                    .get(key.hash_hex())
                    .map(|e| (e.meta.clone(), e.body_path.clone()))
            };
            match snapshot {
                Some((meta, body_path)) => {
                    let body_file = Some(tokio::fs::File::open(&body_path).await.map_err(|e| {
                        ProxyError::Cache {
                            source: Box::new(e),
                            operation: "mock peek_body open body".into(),
                        }
                    })?);
                    Ok(Some(CacheEntry {
                        meta,
                        body_path,
                        body_file,
                    }))
                }
                None => Ok(None),
            }
        }

        async fn note_hit(&self, _key: &CacheKey, _meta: &CacheMeta) -> Result<(), ProxyError> {
            self.note_hit_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn note_miss(&self) -> Result<(), ProxyError> {
            self.note_miss_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn begin_fill(&self, key: &CacheKey) -> Result<FillGuard, ProxyError> {
            self.fill_calls.lock().unwrap().push(key.clone());
            let current_gen = self
                .fill_generation
                .load(std::sync::atomic::Ordering::Relaxed);
            Ok(FillGuard {
                key: key.clone(),
                temp_dir: self.temp_dir.path().to_path_buf(),
                generation: current_gen,
            })
        }

        async fn abort_fill(&self, _guard: FillGuard) {
            // No-op for mock — no internal state to clean up.
        }

        async fn commit_fill(
            &self,
            guard: FillGuard,
            temp_body_path: PathBuf,
            mut meta: CacheMeta,
        ) -> Result<(), ProxyError> {
            let pause = { self.commit_fill_pause.lock().unwrap().take() };
            if let Some(mut pause) = pause {
                if let Some(started) = pause.started.take() {
                    let _ = started.send(());
                }
                pause.release.notified().await;
            }

            // Hold both locks atomically, then recheck generation inside the
            // critical section so a concurrent purge/poison cannot race in.
            let mut entries = self.entries.lock().unwrap();
            let mut poisoned = self.poisoned.lock().unwrap();
            let current_gen = self
                .fill_generation
                .load(std::sync::atomic::Ordering::Relaxed);
            if guard.generation != current_gen {
                return Ok(());
            }
            if let Some(current) = entries.get(guard.key.hash_hex()) {
                meta.preserve_same_etag_head_state_from(&current.meta);
            }
            meta.fill_id = FillId::from(
                self.next_fill_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            );
            meta.metadata_version = 0;
            let entry = CacheEntry {
                meta: Arc::new(meta),
                body_path: temp_body_path,
                body_file: None,
            };
            entries.insert(guard.key.hash_hex().to_string(), entry);
            poisoned.remove(guard.key.hash_hex());
            Ok(())
        }

        async fn purge(&self, key: &CacheKey) -> Result<bool, ProxyError> {
            if *self.purge_should_fail.lock().unwrap() {
                return Err(ProxyError::Cache {
                    source: "mock purge failure".into(),
                    operation: "purge".into(),
                });
            }
            // Lock order: entries → poisoned → purge_calls (consistent everywhere)
            let removed = {
                let mut entries = self.entries.lock().unwrap();
                let mut poisoned = self.poisoned.lock().unwrap();
                let removed = entries.remove(key.hash_hex()).is_some();
                // Always advance generation — even if no entry exists, this
                // ensures any in-flight begin_fill sees the invalidation fence.
                self.fill_generation
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                poisoned.remove(key.hash_hex());
                removed
            };
            self.purge_calls.lock().unwrap().push(key.clone());
            Ok(removed)
        }

        async fn purge_if_unchanged(
            &self,
            key: &CacheKey,
            expected_fill_id: FillId,
        ) -> Result<bool, ProxyError> {
            if *self.purge_should_fail.lock().unwrap() {
                return Err(ProxyError::Cache {
                    source: "mock purge_if_unchanged failure".into(),
                    operation: "purge_if_unchanged".into(),
                });
            }
            // If a pending replacement is staged, swap it in and return false
            // (simulates a concurrent refill between probe and purge).
            {
                let mut pending = self.purge_swaps_entry.lock().unwrap();
                if let Some((hash, replacement)) = pending.take() {
                    if hash == key.hash_hex() {
                        let mut entries = self.entries.lock().unwrap();
                        entries.insert(hash, replacement);
                        return Ok(false);
                    }
                    *pending = Some((hash, replacement));
                }
            }
            let removed = {
                let mut entries = self.entries.lock().unwrap();
                match entries.get(key.hash_hex()) {
                    Some(entry) if entry.meta.fill_id == expected_fill_id => {
                        let mut poisoned = self.poisoned.lock().unwrap();
                        entries.remove(key.hash_hex());
                        self.fill_generation
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        poisoned.remove(key.hash_hex());
                        true
                    }
                    _ => false,
                }
            };
            if removed {
                self.purge_calls.lock().unwrap().push(key.clone());
            }
            Ok(removed)
        }

        async fn poison(&self, key: &CacheKey) -> Result<(), crate::error::ProxyError> {
            // Lock order: entries → poisoned (consistent with commit_fill).
            let _entries = self.entries.lock().unwrap();
            let mut poisoned = self.poisoned.lock().unwrap();
            self.fill_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            poisoned.insert(key.hash_hex().to_string());
            drop(poisoned);
            drop(_entries);
            self.poison_calls.lock().unwrap().push(key.clone());
            Ok(())
        }

        async fn poison_if_unchanged(
            &self,
            key: &CacheKey,
            expected_fill_id: FillId,
        ) -> Result<bool, ProxyError> {
            let key_hash = key.hash_hex().to_string();
            let poisoned = {
                let entries = self.entries.lock().unwrap();
                match entries.get(&key_hash) {
                    Some(entry) if entry.meta.fill_id == expected_fill_id => {
                        let mut poisoned = self.poisoned.lock().unwrap();
                        self.fill_generation
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        poisoned.insert(key_hash);
                        true
                    }
                    _ => false,
                }
            };
            if poisoned {
                self.poison_calls.lock().unwrap().push(key.clone());
            }
            Ok(poisoned)
        }

        async fn update_metadata_if_unchanged(
            &self,
            key: &CacheKey,
            expected_fill_id: FillId,
            meta: CacheMeta,
        ) -> Result<bool, ProxyError> {
            let mut entries = self.entries.lock().unwrap();
            let Some(entry) = entries.get_mut(key.hash_hex()) else {
                return Ok(false);
            };
            if entry.meta.fill_id != expected_fill_id
                || entry.meta.metadata_version != meta.metadata_version
            {
                return Ok(false);
            }
            let mut meta = meta;
            meta.cache_written_at = entry.meta.cache_written_at;
            meta.fill_id = entry.meta.fill_id;
            meta.last_accessed_at = entry.meta.last_accessed_at;
            meta.hit_count = entry.meta.hit_count;
            meta.source_status = entry.meta.source_status;
            // Intentionally bumps metadata_version to match DiskCache behavior
            // (src/cache/disk.rs update_metadata_if_unchanged). Preserving
            // the old version would diverge from production and weaken
            // refresh-collision test coverage — follow-up updates that should
            // fail the CAS check would silently succeed in tests.
            meta.metadata_version = entry.meta.metadata_version.saturating_add(1);
            entry.meta = Arc::new(meta);
            Ok(true)
        }

        async fn stats(&self) -> CacheStatsSnapshot {
            CacheStatsSnapshot::default()
        }
    }

    // ---- MockAuth ----

    pub struct MockAuth {
        pub allow: bool,
    }

    impl MockAuth {
        pub fn allow_all() -> Self {
            Self { allow: true }
        }

        pub fn deny_all() -> Self {
            Self { allow: false }
        }
    }

    impl RequestGate for MockAuth {
        fn check_access(&self, _req: &ParsedRequest) -> Result<(), ProxyError> {
            if self.allow {
                Ok(())
            } else {
                Err(ProxyError::Auth {
                    message: "access denied".to_string(),
                })
            }
        }
    }

    // ---- Helper to build AppState ----

    use super::AppState;
    use crate::cache::SingleFlight;
    use crate::cache::policy::CachePolicy;
    use crate::config::{AuthMode, Config};
    use std::sync::Arc;

    pub fn test_config() -> Config {
        Config {
            s3_listen_addr: "0.0.0.0:8080".to_string(),
            admin_listen_addr: "0.0.0.0:9090".to_string(),
            frontend_bucket: "test-frontend".to_string(),
            auth_mode: AuthMode::TrustedInternal,
            allowed_frontend_keys: vec![],
            backend_endpoint: "http://127.0.0.1:1".to_string(),
            backend_region: "auto".to_string(),
            backend_bucket: "test-backend".to_string(),
            backend_access_key_id: "AKID".to_string(),
            backend_secret_access_key: "secret".to_string(),
            backend_use_path_style: true,
            backend_allow_http: false,
            cache_dir: std::path::PathBuf::from("/tmp/test-cache"),
            cache_max_bytes: 1024 * 1024,
            cache_max_object_bytes: 512 * 1024,
            cacheable_prefixes: vec!["script_bundle/".to_string(), "tar/".to_string()],
            cache_serve_stale_on_error: true,
            cache_eviction_interval_secs: 300,
            get_max_attempts: 1,
            head_max_attempts: 1,
            list_max_attempts: 1,
            put_max_attempts: 1,
            delete_max_attempts: 1,
            retry_base_backoff_ms: 10,
            upstream_connect_timeout_ms: 5000,
            upstream_request_timeout_ms: 30000,
            max_request_body_bytes: 268_435_456,
            passthrough_unsigned_payload: false,
            inbound_auth_verify_signatures: false,
            inbound_credentials_path: None,
            inbound_auth_max_skew_secs: 900,
        }
    }

    pub fn build_app_state(
        backend: MockBackend,
        cache: MockCache,
        auth: MockAuth,
    ) -> Arc<AppState<MockBackend, MockCache>> {
        let mut config = test_config();
        // Point cache_dir to the MockCache's temp dir so tee tasks can write there
        config.cache_dir = cache.temp_dir.path().to_path_buf();
        // Create the tmp sub-directory that the tee task expects
        let tmp_dir = cache.temp_dir.path().join("tmp");
        let _ = std::fs::create_dir_all(&tmp_dir);

        Arc::new(AppState {
            backend: Arc::new(backend),
            cache: Arc::new(cache),
            singleflight: Arc::new(SingleFlight::new()),
            auth: Arc::new(auth),
            inbound_sigv4: None,
            policy: CachePolicy::new(
                config.cacheable_prefixes.clone(),
                config.cache_max_object_bytes,
            ),
            frontend_bucket: Arc::from(config.frontend_bucket.as_str()),
            backend_bucket: Arc::from(config.backend_bucket.as_str()),
            http_client: reqwest::Client::new(),
            config: Arc::new(config),
        })
    }

    /// Build a ParsedRequest with the given operation and default values for all other fields.
    pub fn test_parsed_request(
        operation: crate::s3::ops::S3Operation,
    ) -> crate::s3::ops::ParsedRequest {
        crate::s3::ops::ParsedRequest {
            operation,
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

    /// Build a test CacheMeta for a given key/body.
    pub fn test_cache_meta(bucket: &str, key: &str, body: &[u8]) -> CacheMeta {
        CacheMeta {
            bucket: bucket.to_string(),
            key: key.to_string(),
            etag: Some("\"test-etag\"".to_string()),
            last_modified: Some(Utc::now()),
            content_type: Some("application/octet-stream".to_string()),
            content_length: body.len() as i64,
            cache_written_at: Utc::now(),
            fill_id: FillId::from(1), // non-zero so conditional ops match
            metadata_version: 0,
            last_accessed_at: Utc::now(),
            hit_count: 0,
            source_status: 200,
            metadata: HashMap::new(),
            extra_headers: HashMap::new(),
            head_extra_headers: HashMap::new(),
            head_checksum_headers: HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_utils::*;
    use axum::body::Body;
    use http::Request;

    fn build_request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_non_s3_method_returns_501() {
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::allow_all());

        // PATCH is not a valid S3 method and should be rejected with 501.
        let req = build_request("PATCH", "/test-frontend/some-key");
        let resp = handle_s3_request(State(state), req).await;
        assert_eq!(resp.status(), 501);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("NotImplemented"));
    }

    #[tokio::test]
    async fn test_wrong_bucket_returns_404() {
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::allow_all());

        let req = build_request("GET", "/wrong-bucket/some-key");
        let resp = handle_s3_request(State(state), req).await;

        assert_eq!(resp.status(), 404);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("NoSuchBucket"));
    }

    #[tokio::test]
    async fn test_non_s3_method_rejected_before_auth() {
        // Non-S3 methods should return 501 even when auth would deny.
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::deny_all());

        let req = build_request("PATCH", "/test-frontend/some-key");
        let resp = handle_s3_request(State(state), req).await;

        // 501 because PATCH is rejected before auth runs
        assert_eq!(resp.status(), 501);
    }

    #[tokio::test]
    async fn test_trace_returns_501_before_bucket_check() {
        // TRACE * never has a bucket path — should get 501, not NoSuchBucket.
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::allow_all());

        let req = Request::builder()
            .method("TRACE")
            .uri("*")
            .body(Body::empty())
            .unwrap();
        let resp = handle_s3_request(State(state), req).await;
        assert_eq!(resp.status(), 501);
    }

    #[tokio::test]
    async fn test_connect_returns_501() {
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::allow_all());

        // CONNECT uses authority-form URI (host:port), not a path.
        let req = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Body::empty())
            .unwrap();
        let resp = handle_s3_request(State(state), req).await;
        assert_eq!(resp.status(), 501);
    }

    #[tokio::test]
    async fn test_patch_rejected_without_calling_backend() {
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::allow_all());

        let req = build_request("PATCH", "/test-frontend/some-key");
        let resp = handle_s3_request(State(state.clone()), req).await;
        assert_eq!(resp.status(), 501);

        // Verify the backend was never invoked via the call counter.
        let calls = state
            .backend
            .total_calls
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(calls, 0, "backend should not be called for non-S3 methods");
    }

    #[tokio::test]
    async fn test_negative_content_length_returns_400() {
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::allow_all());

        let req = Request::builder()
            .method("PUT")
            .uri("/test-frontend/some-key")
            .header("content-length", "-1")
            .body(Body::empty())
            .unwrap();
        let resp = handle_s3_request(State(state), req).await;
        assert_eq!(resp.status(), 400);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("InvalidRequest"),
            "expected InvalidRequest error for negative Content-Length, got: {}",
            body_str
        );
    }

    #[tokio::test]
    async fn test_auth_failure_returns_403() {
        let state = build_app_state(MockBackend::new(), MockCache::new(), MockAuth::deny_all());

        let req = build_request("GET", "/test-frontend/some-key");
        let resp = handle_s3_request(State(state), req).await;

        assert_eq!(resp.status(), 403);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("AccessDenied"));
    }

    /// PUT with an ECDSA-signed aws-chunked streaming sentinel must be
    /// rejected up front with HTTP 400 `UnsupportedSignature` before the
    /// typed PUT path OR any upstream contact. The inbound `chunk-signature`
    /// values are bound to the client's private key, so the previous
    /// "route to passthrough" behaviour only ever failed on the upstream
    /// after pointless backend traffic. The handler-level dispatch must
    /// short-circuit; this test pins that shape.
    ///
    /// The companion integration test
    /// `test_aws_chunked_ecdsa_streaming_rejected_as_unsupported_signature`
    /// exercises the same routing through the full server stack.
    #[tokio::test]
    async fn test_aws_chunked_put_ecdsa_rejected_as_unsupported_signature() {
        use axum::routing::any;
        use std::sync::atomic::{AtomicU32, Ordering};

        // Well-formed-looking aws-chunked frame for "hello". The bytes never
        // matter because dispatch rejects before any body parse / forward.
        let framed_body: &[u8] =
            b"5;chunk-signature=deadbeef\r\nhello\r\n0;chunk-signature=cafef00d\r\n\r\n";

        // Mock upstream that bumps a counter on any request received. The
        // load-bearing assertion is that this counter stays at 0.
        let call_count = std::sync::Arc::new(AtomicU32::new(0));
        let call_count_for_handler = call_count.clone();
        let app = axum::Router::new().route(
            "/{*path}",
            any(move |_req: http::Request<Body>| {
                let cc = call_count_for_handler.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    http::Response::builder()
                        .status(200)
                        .body(Body::from("ok"))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let cache = MockCache::new();
        let mut config = test_config();
        config.backend_endpoint = format!("http://{addr}");
        config.cache_dir = cache.temp_dir.path().to_path_buf();
        let _ = std::fs::create_dir_all(cache.temp_dir.path().join("tmp"));
        let backend = std::sync::Arc::new(MockBackend::new());
        let state = std::sync::Arc::new(AppState {
            backend: backend.clone(),
            cache: std::sync::Arc::new(cache),
            singleflight: std::sync::Arc::new(crate::cache::SingleFlight::new()),
            auth: std::sync::Arc::new(MockAuth::allow_all()),
            inbound_sigv4: None,
            policy: crate::cache::policy::CachePolicy::new(
                config.cacheable_prefixes.clone(),
                config.cache_max_object_bytes,
            ),
            frontend_bucket: std::sync::Arc::from(config.frontend_bucket.as_str()),
            backend_bucket: std::sync::Arc::from(config.backend_bucket.as_str()),
            http_client: reqwest::Client::new(),
            config: std::sync::Arc::new(config),
        });

        let req = Request::builder()
            .method("PUT")
            .uri("/test-frontend/key")
            .header("content-encoding", "aws-chunked")
            .header(
                "x-amz-content-sha256",
                "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
            )
            .header("x-amz-decoded-content-length", "5")
            .body(Body::from(framed_body.to_vec()))
            .unwrap();

        let resp = handle_s3_request(State(state), req).await;
        assert_eq!(
            resp.status(),
            400,
            "ECDSA streaming must be rejected at dispatch with HTTP 400",
        );
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(
            body_str.contains("<Code>UnsupportedSignature</Code>"),
            "expected UnsupportedSignature S3 error code, got: {body_str}",
        );
        // Typed PUT path must NOT have been invoked.
        let typed_calls = backend.total_calls.load(Ordering::Relaxed);
        assert_eq!(
            typed_calls, 0,
            "typed Backend path must not be invoked when ECDSA is rejected (got {typed_calls} calls)",
        );
        // Upstream HTTP mock must NOT have been contacted — the
        // "rejected before backend contact" contract.
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "upstream handler must not be invoked when ECDSA is rejected up front",
        );
    }

    #[tokio::test]
    async fn test_mock_cache_purge_if_unchanged_only_consumes_matching_staged_replacement() {
        let key_a = crate::cache::key::CacheKey::new("test-backend", "script_bundle/a.js");
        let key_b = crate::cache::key::CacheKey::new("test-backend", "script_bundle/b.js");

        let cache = MockCache::new()
            .with_entry(
                &key_a,
                b"body-a",
                test_cache_meta("test-backend", "script_bundle/a.js", b"body-a"),
            )
            .with_entry(
                &key_b,
                b"body-b",
                test_cache_meta("test-backend", "script_bundle/b.js", b"body-b"),
            );

        let entry_a = cache.peek(&key_a).await.unwrap().unwrap();
        let entry_b = cache.peek(&key_b).await.unwrap().unwrap();
        let fill_id_a = entry_a.meta.fill_id;
        let fill_id_b = entry_b.meta.fill_id;

        let mut replacement_b = test_cache_meta("test-backend", "script_bundle/b.js", b"new-b");
        replacement_b.head_metadata_checked = true;
        cache.stage_purge_replacement(&key_b, b"new-b", replacement_b);

        assert!(cache.purge_if_unchanged(&key_a, fill_id_a).await.unwrap());
        assert!(cache.peek(&key_a).await.unwrap().is_none());

        {
            let pending = cache.purge_swaps_entry.lock().unwrap();
            assert_eq!(
                pending.as_ref().map(|(hash, _)| hash.as_str()),
                Some(key_b.hash_hex())
            );
        }

        assert!(!cache.purge_if_unchanged(&key_b, fill_id_b).await.unwrap());
        let newer_b = cache.peek(&key_b).await.unwrap().unwrap();
        assert_ne!(newer_b.meta.fill_id, fill_id_b);
        assert!(cache.purge_swaps_entry.lock().unwrap().is_none());
    }

    // ---- rewrite_bucket_in_path tests ----

    #[test]
    fn test_rewrite_bucket_in_path_with_key() {
        let result = rewrite_bucket_in_path("/frontend/key/path", "frontend", "backend");
        assert_eq!(result, "/backend/key/path");
    }

    #[test]
    fn test_rewrite_bucket_in_path_bucket_only() {
        let result = rewrite_bucket_in_path("/frontend", "frontend", "backend");
        assert_eq!(result, "/backend");
    }

    #[test]
    fn test_rewrite_bucket_in_path_no_match() {
        let result = rewrite_bucket_in_path("/other/key", "frontend", "backend");
        assert_eq!(result, "/other/key");
    }

    // ---- has_unsupported_get_modifiers tests ----

    #[test]
    fn test_has_unsupported_get_modifiers_range() {
        let mut headers = http::HeaderMap::new();
        headers.insert("range", "bytes=0-100".parse().unwrap());
        assert!(has_unsupported_get_modifiers(&headers));
    }

    #[test]
    fn test_has_unsupported_get_modifiers_if_match() {
        let mut headers = http::HeaderMap::new();
        headers.insert("if-match", "\"etag\"".parse().unwrap());
        assert!(has_unsupported_get_modifiers(&headers));
    }

    #[test]
    fn test_has_unsupported_get_modifiers_if_none_match() {
        let mut headers = http::HeaderMap::new();
        headers.insert("if-none-match", "\"etag\"".parse().unwrap());
        assert!(has_unsupported_get_modifiers(&headers));
    }

    #[test]
    fn test_has_unsupported_get_modifiers_ssec() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-server-side-encryption-customer-algorithm",
            "AES256".parse().unwrap(),
        );
        assert!(has_unsupported_get_modifiers(&headers));
    }

    #[test]
    fn test_has_unsupported_get_modifiers_checksum_mode() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-checksum-mode", "ENABLED".parse().unwrap());
        assert!(!has_unsupported_get_modifiers(&headers));
    }

    #[test]
    fn test_has_unsupported_get_modifiers_invalid_checksum_mode() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-checksum-mode", "DISABLED".parse().unwrap());
        assert!(has_unsupported_get_modifiers(&headers));
    }

    #[test]
    fn test_has_unsupported_get_modifiers_multiple_checksum_mode_headers() {
        let mut headers = http::HeaderMap::new();
        headers.append("x-amz-checksum-mode", "ENABLED".parse().unwrap());
        headers.append("x-amz-checksum-mode", "ENABLED".parse().unwrap());
        assert!(has_unsupported_get_modifiers(&headers));
    }

    #[test]
    fn test_has_unsupported_get_modifiers_clean() {
        let headers = http::HeaderMap::new();
        assert!(!has_unsupported_get_modifiers(&headers));
    }

    // ---- has_unsupported_write_modifiers tests ----

    #[test]
    fn test_has_unsupported_write_modifiers_storage_class() {
        let mut extra_amz = std::collections::HashMap::new();
        extra_amz.insert("x-amz-storage-class".to_string(), "GLACIER".to_string());
        let headers = http::HeaderMap::new();
        assert!(has_unsupported_write_modifiers(&extra_amz, &headers));
    }

    #[test]
    fn test_has_unsupported_write_modifiers_if_match() {
        let extra_amz = std::collections::HashMap::new();
        let mut headers = http::HeaderMap::new();
        headers.insert("if-match", "\"etag\"".parse().unwrap());
        assert!(has_unsupported_write_modifiers(&extra_amz, &headers));
    }

    #[test]
    fn test_has_unsupported_write_modifiers_clean() {
        let extra_amz = std::collections::HashMap::new();
        let headers = http::HeaderMap::new();
        assert!(!has_unsupported_write_modifiers(&extra_amz, &headers));
    }

    // ---- has_unsupported_multipart_modifiers tests ----

    #[test]
    fn test_has_unsupported_multipart_modifiers_checksum() {
        let mut extra_amz = std::collections::HashMap::new();
        extra_amz.insert("x-amz-checksum-algorithm".to_string(), "SHA256".to_string());
        let headers = http::HeaderMap::new();
        assert!(has_unsupported_multipart_modifiers(&extra_amz, &headers));
    }

    #[test]
    fn test_has_unsupported_multipart_modifiers_clean() {
        let extra_amz = std::collections::HashMap::new();
        let headers = http::HeaderMap::new();
        assert!(!has_unsupported_multipart_modifiers(&extra_amz, &headers));
    }

    // ---- aws-chunked / SigV4 streaming upload indicators ----

    #[test]
    fn test_streaming_indicator_content_encoding_aws_chunked() {
        let extra_amz = std::collections::HashMap::new();
        let mut headers = http::HeaderMap::new();
        headers.insert("content-encoding", "aws-chunked".parse().unwrap());
        assert!(has_unsupported_write_modifiers(&extra_amz, &headers));
        assert!(has_unsupported_multipart_modifiers(&extra_amz, &headers));
    }

    #[test]
    fn test_streaming_indicator_content_encoding_comma_list() {
        let extra_amz = std::collections::HashMap::new();
        let mut headers = http::HeaderMap::new();
        // Comma list with leading whitespace before the aws-chunked token.
        headers.insert("content-encoding", "gzip,  aws-chunked".parse().unwrap());
        assert!(has_unsupported_write_modifiers(&extra_amz, &headers));
        assert!(has_unsupported_multipart_modifiers(&extra_amz, &headers));
    }

    #[test]
    fn test_streaming_indicator_amz_content_sha256_canonical_values() {
        let extra_amz = std::collections::HashMap::new();
        for sentinel in [
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert("x-amz-content-sha256", sentinel.parse().unwrap());
            assert!(
                has_unsupported_write_modifiers(&extra_amz, &headers),
                "write gate should match {sentinel}",
            );
            assert!(
                has_unsupported_multipart_modifiers(&extra_amz, &headers),
                "multipart gate should match {sentinel}",
            );
        }
    }

    #[test]
    fn test_streaming_indicator_amz_content_sha256_duplicate_values() {
        // A client could send two x-amz-content-sha256 headers — first
        // UNSIGNED-PAYLOAD, then a STREAMING-* sentinel — to slip past a
        // single-value check. The gate must inspect every value.
        let extra_amz = std::collections::HashMap::new();
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::HeaderName::from_static("x-amz-content-sha256"),
            http::header::HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
        headers.append(
            http::header::HeaderName::from_static("x-amz-content-sha256"),
            http::header::HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
        );
        assert!(
            has_s3_streaming_upload_indicators(&headers),
            "streaming sentinel in second x-amz-content-sha256 value must trip the helper"
        );
        assert!(
            has_unsupported_write_modifiers(&extra_amz, &headers),
            "write gate must trip when a later x-amz-content-sha256 value is STREAMING-*"
        );
        assert!(
            has_unsupported_multipart_modifiers(&extra_amz, &headers),
            "multipart gate must trip when a later x-amz-content-sha256 value is STREAMING-*"
        );
    }

    #[test]
    fn test_streaming_indicator_decoded_content_length() {
        let extra_amz = std::collections::HashMap::new();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "5".parse().unwrap());
        assert!(has_unsupported_write_modifiers(&extra_amz, &headers));
        assert!(has_unsupported_multipart_modifiers(&extra_amz, &headers));
    }

    #[test]
    fn test_streaming_indicator_amz_trailer() {
        let extra_amz = std::collections::HashMap::new();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());
        assert!(has_unsupported_write_modifiers(&extra_amz, &headers));
        assert!(has_unsupported_multipart_modifiers(&extra_amz, &headers));
    }

    #[test]
    fn test_streaming_indicator_negative_unsigned_payload_gzip() {
        // gzip + UNSIGNED-PAYLOAD is a perfectly normal compressed upload —
        // it must not be flagged as an aws-chunked streaming upload.
        let extra_amz = std::collections::HashMap::new();
        let mut headers = http::HeaderMap::new();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        assert!(!has_unsupported_write_modifiers(&extra_amz, &headers));
        assert!(!has_unsupported_multipart_modifiers(&extra_amz, &headers));
    }

    // ---- has_unsupported_list_modifiers tests ----

    #[test]
    fn test_has_unsupported_list_modifiers_fetch_owner() {
        let headers = http::HeaderMap::new();
        assert!(has_unsupported_list_modifiers(
            Some("list-type=2&fetch-owner=true"),
            &headers
        ));
    }

    #[test]
    fn test_has_unsupported_list_modifiers_request_payer() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-request-payer", "requester".parse().unwrap());
        assert!(has_unsupported_list_modifiers(None, &headers));
    }

    #[test]
    fn test_has_unsupported_list_modifiers_clean() {
        let headers = http::HeaderMap::new();
        assert!(!has_unsupported_list_modifiers(
            Some("list-type=2&prefix=foo/"),
            &headers
        ));
    }

    #[test]
    fn test_has_unsupported_list_modifiers_encoded_fetch_owner() {
        let headers = http::HeaderMap::new();
        assert!(has_unsupported_list_modifiers(
            Some("list-type=2&fetch%2Downer=true"),
            &headers
        ));
    }

    #[test]
    fn test_has_unsupported_list_modifiers_encoded_optional_object_attributes() {
        let headers = http::HeaderMap::new();
        assert!(has_unsupported_list_modifiers(
            Some("list-type=2&optional%2Dobject%2Dattributes=RestoreStatus"),
            &headers
        ));
    }

    #[test]
    fn test_has_unsupported_list_modifiers_encoded_fetch_owner_no_value() {
        let headers = http::HeaderMap::new();
        assert!(has_unsupported_list_modifiers(
            Some("list-type=2&fetch%2Downer"),
            &headers
        ));
    }
}
