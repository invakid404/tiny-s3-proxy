//! Helpers shared between the aws-chunked PUT and UploadPart paths.
//!
//! The bulk of this module is the `UploadSpoolGuard`: it owns a single
//! temporary file under `<cache_dir>/tmp/` that the decoded body bytes are
//! streamed into before the SDK uploads them. The guard ensures the spool
//! file is removed exactly once — explicitly via `cleanup()` on the happy
//! path, or as a best-effort Drop fallback for panics/early returns.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::body::Body;
use http::Response;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio_util::io::StreamReader;

use crate::backend::Backend;
use crate::backend::models::{PutObjectSpoolInput, UploadPartSpoolInput};
use crate::cache::CacheStore;
use crate::cache::key::CacheKey;
use crate::handlers::AppState;
use crate::s3::aws_chunked::{AwsChunkedDecoder, AwsChunkedError};
use crate::s3::errors::S3Error;
use crate::s3::headers::{append_extra_headers, common_headers, put_object_headers};
use crate::s3::ops::ParsedRequest;

/// Process-local counter feeding the filename pattern
/// `{pid}-{counter}.upload-spool.tmp`. Combined with the PID, this guarantees
/// uniqueness across concurrent spools without coordinating with peers.
static UPLOAD_SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Owns the lifecycle of one decoded-body spool file. Drop is a best-effort
/// backstop; callers should explicitly `.cleanup().await` on both the happy
/// and error paths so failures to delete are logged.
pub(super) struct UploadSpoolGuard {
    path: PathBuf,
    armed: bool,
}

impl UploadSpoolGuard {
    /// Create a fresh spool file under `<cache_dir>/tmp/`. Returns the guard
    /// plus an open `File` handle positioned at offset 0 with write
    /// permission. Uses `create_new` so collisions with a stale file abort
    /// rather than silently overwrite.
    pub(super) async fn create(cache_dir: &Path) -> std::io::Result<(Self, File)> {
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await?;

        let pid = std::process::id();
        let counter = UPLOAD_SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = tmp_dir.join(format!("{pid}-{counter}.upload-spool.tmp"));

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;

        Ok((Self { path, armed: true }, file))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the spool file. Disarms the Drop fallback so the file is
    /// removed exactly once. Returns the underlying I/O error if removal
    /// fails — callers can decide whether to log/escalate.
    pub(super) async fn cleanup(mut self) -> std::io::Result<()> {
        self.armed = false;
        tokio::fs::remove_file(&self.path).await
    }
}

impl Drop for UploadSpoolGuard {
    fn drop(&mut self) {
        if self.armed {
            // Best-effort sync removal; the async runtime may already be
            // tearing down. Errors are intentionally swallowed because Drop
            // can run during a panic and we can't return them anyway. The
            // startup tmp sweep will pick up any survivors on next boot.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Read the `x-amz-decoded-content-length` header. Required on aws-chunked
/// uploads — the decoder uses it to size the spool and validate the framing
/// totals exactly. Returns the typed `S3Error` so the caller can map it to
/// a response after collecting any other state.
fn read_declared_decoded_length(
    raw_headers: &http::HeaderMap,
    request_id: &str,
) -> Result<u64, S3Error> {
    let raw = raw_headers
        .get("x-amz-decoded-content-length")
        .ok_or_else(|| {
            S3Error::invalid_argument(
                "aws-chunked upload missing required header x-amz-decoded-content-length",
                request_id,
            )
        })?;
    let s = raw.to_str().map_err(|_| {
        S3Error::invalid_argument(
            "x-amz-decoded-content-length header was not valid ASCII",
            request_id,
        )
    })?;
    s.parse::<u64>().map_err(|_| {
        S3Error::invalid_argument(
            "x-amz-decoded-content-length header was not a non-negative integer",
            request_id,
        )
    })
}

/// Strip the `aws-chunked` token from a comma-separated `Content-Encoding`
/// header value (case-insensitive). Returns the surviving tokens joined with
/// `, `. Returns `None` if no tokens remain (so the caller can drop the
/// header entirely).
fn content_encoding_without_aws_chunked(value: &str) -> Option<String> {
    let surviving: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|tok| !tok.eq_ignore_ascii_case("aws-chunked") && !tok.is_empty())
        .collect();
    if surviving.is_empty() {
        None
    } else {
        Some(surviving.join(", "))
    }
}

/// Build the content-headers map forwarded to the backend, dropping the
/// `aws-chunked` token from `Content-Encoding` so the upstream object isn't
/// tagged as still-aws-chunked. Other tokens (e.g. `gzip`) are preserved.
fn content_headers_for_decoded(
    parsed: &ParsedRequest,
) -> std::collections::HashMap<String, String> {
    let mut out = parsed.content_headers.clone();
    if let Some(ce) = out.remove("content-encoding")
        && let Some(stripped) = content_encoding_without_aws_chunked(&ce)
    {
        out.insert("content-encoding".into(), stripped);
    }
    out
}

/// Map an `AwsChunkedError` to the matching `S3Error`. Framing errors all
/// surface as `IncompleteBody` (HTTP 400) except the chunk-size minimum,
/// which gets its own `InvalidChunkSizeError`. I/O errors surface as
/// `InternalError` (HTTP 500).
fn map_decode_error(err: AwsChunkedError, request_id: &str) -> S3Error {
    match err {
        AwsChunkedError::InvalidChunkSize { .. } => {
            S3Error::invalid_chunk_size(&err.to_string(), request_id)
        }
        AwsChunkedError::Io(io_err) => S3Error::internal_error(
            &format!("aws-chunked decode I/O error: {io_err}"),
            request_id,
        ),
        AwsChunkedError::MalformedFrame { .. }
        | AwsChunkedError::DecodedLengthMismatch { .. }
        | AwsChunkedError::DecodedLengthExceeded { .. }
        | AwsChunkedError::Truncated
        | AwsChunkedError::TrailingData
        | AwsChunkedError::ChunkHeaderTooLarge { .. } => {
            S3Error::incomplete_body(&err.to_string(), request_id)
        }
    }
}

/// Decode the inbound aws-chunked body into a spool file. Returns the spool
/// guard, the decoded length, and the SHA-256 of the decoded body. On error,
/// the spool file is cleaned up by Drop (we never returned the guard).
async fn decode_into_spool<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    body: Body,
    declared_len: u64,
) -> Result<(UploadSpoolGuard, u64, String), S3Error> {
    use futures_compat::body_to_io_stream;

    let (mut guard, file) = UploadSpoolGuard::create(&state.config.cache_dir)
        .await
        .map_err(|e| {
            S3Error::internal_error(
                &format!("failed to create aws-chunked spool file: {e}"),
                &parsed.request_id,
            )
        })?;

    let reader = StreamReader::new(body_to_io_stream(body));
    let mut writer = BufWriter::new(file);
    let summary = AwsChunkedDecoder::new(reader, declared_len)
        .decode_to_writer(&mut writer)
        .await
        .map_err(|e| map_decode_error(e, &parsed.request_id))?;

    if let Err(e) = writer.flush().await {
        return Err(S3Error::internal_error(
            &format!("failed to flush aws-chunked spool file: {e}"),
            &parsed.request_id,
        ));
    }
    // Drop the underlying file handle so any later open-for-read sees the
    // final buffered contents and OS state is consistent.
    let file = writer.into_inner();
    drop(file);

    // Hand `guard` back to the caller; arm stays true so cleanup() runs.
    let _ = &mut guard;
    Ok((guard, summary.decoded_len, summary.sha256_hex))
}

mod futures_compat {
    use axum::body::Body;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio_stream::Stream;

    /// Adapt an axum `Body` data stream to a
    /// `Stream<Item = Result<Bytes, io::Error>>`, the input shape
    /// `tokio_util::io::StreamReader` expects. We don't depend on
    /// `futures-util`, so this is a hand-rolled error-mapping wrapper.
    struct IoErrorMap {
        inner: http_body_util::BodyDataStream<Body>,
    }

    impl Stream for IoErrorMap {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            // Safety: we never move `self`; `inner` is structurally pinned.
            let this = unsafe { self.get_unchecked_mut() };
            let pinned = unsafe { Pin::new_unchecked(&mut this.inner) };
            match pinned.poll_next(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(Ok(bytes))) => Poll::Ready(Some(Ok(bytes))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(std::io::Error::other(
                    format!("request body stream error: {e}"),
                )))),
            }
        }
    }

    pub(super) fn body_to_io_stream(
        body: Body,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> {
        Box::pin(IoErrorMap {
            inner: BodyExt::into_data_stream(body),
        })
    }
}

/// Reject if the declared decoded length exceeds the configured request body
/// cap. We can decide this BEFORE reading any body bytes — the cap is on the
/// decoded body, not the wire body. Saves us from spooling oversized
/// uploads.
fn reject_if_oversized<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    declared_len: u64,
) -> Option<Response<Body>> {
    if declared_len > state.config.max_request_body_bytes {
        let s3err = S3Error::entity_too_large(
            &format!(
                "x-amz-decoded-content-length {declared_len} exceeds configured \
                 max_request_body_bytes ({})",
                state.config.max_request_body_bytes,
            ),
            &parsed.request_id,
        );
        return Some(s3err.to_response());
    }
    None
}

/// Run the aws-chunked PUT pipeline: decode → spool → upload → purge cache.
pub async fn handle_put_decode_aws_chunked<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    raw_headers: &http::HeaderMap,
    body: Body,
) -> Response<Body> {
    let declared_len = match read_declared_decoded_length(raw_headers, &parsed.request_id) {
        Ok(n) => n,
        Err(e) => return e.to_response(),
    };
    if let Some(resp) = reject_if_oversized(state, parsed, declared_len) {
        return resp;
    }

    let (guard, decoded_len, sha256_hex) =
        match decode_into_spool(state, parsed, body, declared_len).await {
            Ok(v) => v,
            Err(e) => return e.to_response(),
        };

    let input = PutObjectSpoolInput {
        bucket: state.backend_bucket.to_string(),
        key: key.to_string(),
        path: guard.path().to_path_buf(),
        len: decoded_len,
        sha256_hex,
        content_type: parsed.content_type.clone(),
        content_md5: parsed.content_md5.clone(),
        metadata: parsed.user_metadata.clone(),
        extra_amz_headers: parsed.extra_amz_headers.clone(),
        content_headers: content_headers_for_decoded(parsed),
    };

    let result = state.backend.put_object_from_path(input).await;

    // Clean up the spool regardless of upstream success.
    let cleanup_result = guard.cleanup().await;
    if let Err(e) = cleanup_result {
        tracing::warn!(
            request_id = %parsed.request_id,
            error = %e,
            operation = "PutObject",
            key = key,
            "failed to delete aws-chunked spool file; startup tmp-sweep will reclaim it",
        );
    }

    match result {
        Ok(output) => {
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
                decoded_len = decoded_len,
                "aws-chunked put object success",
            );

            let headers = put_object_headers(output.etag.as_deref(), &parsed.request_id);
            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            if let Some(ref vid) = output.version_id {
                response = response.header("x-amz-version-id", vid);
            }
            response = append_extra_headers(response, &output.extra_headers);
            response.body(Body::empty()).unwrap()
        }
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "PutObject",
                key = key,
                "backend error after aws-chunked decode",
            );
            S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.frontend_bucket, key)),
            )
            .to_response()
        }
    }
}

/// Run the aws-chunked UploadPart pipeline.
pub async fn handle_upload_part_decode_aws_chunked<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    part_number: i32,
    upload_id: &str,
    raw_headers: &http::HeaderMap,
    body: Body,
) -> Response<Body> {
    if !(1..=10000).contains(&part_number) {
        return S3Error::invalid_argument(
            &format!("Part number must be between 1 and 10000, got {part_number}"),
            &parsed.request_id,
        )
        .to_response();
    }

    let declared_len = match read_declared_decoded_length(raw_headers, &parsed.request_id) {
        Ok(n) => n,
        Err(e) => return e.to_response(),
    };
    if let Some(resp) = reject_if_oversized(state, parsed, declared_len) {
        return resp;
    }

    let (guard, decoded_len, sha256_hex) =
        match decode_into_spool(state, parsed, body, declared_len).await {
            Ok(v) => v,
            Err(e) => return e.to_response(),
        };

    let input = UploadPartSpoolInput {
        bucket: state.backend_bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
        part_number,
        path: guard.path().to_path_buf(),
        len: decoded_len,
        sha256_hex,
        content_md5: parsed.content_md5.clone(),
        extra_amz_headers: parsed.extra_amz_headers.clone(),
    };

    let result = state.backend.upload_part_from_path(input).await;

    if let Err(e) = guard.cleanup().await {
        tracing::warn!(
            request_id = %parsed.request_id,
            error = %e,
            operation = "UploadPart",
            key = key,
            "failed to delete aws-chunked spool file; startup tmp-sweep will reclaim it",
        );
    }

    match result {
        Ok(output) => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "UploadPart",
                key = key,
                part_number = part_number,
                decoded_len = decoded_len,
                "aws-chunked upload part success",
            );

            let mut headers = common_headers(&parsed.request_id);
            if let Ok(val) = http::header::HeaderValue::from_str(&output.etag) {
                headers.insert("etag", val);
            }

            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            response = append_extra_headers(response, &output.extra_headers);
            response.body(Body::empty()).unwrap()
        }
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "UploadPart",
                key = key,
                part_number = part_number,
                "backend error after aws-chunked decode",
            );
            S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.frontend_bucket, key)),
            )
            .to_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::models::PutObjectOutput;
    use crate::cache::key::CacheKey;
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};
    use std::collections::HashMap;

    const SIG: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn make_parsed(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::PutObject {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
            },
            request_id: "test-req-id".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            content_length: Some(8),
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

    fn aws_chunked_single_chunk(payload: &[u8]) -> Vec<u8> {
        // <hex-size>;chunk-signature=<sig>\r\n<payload>\r\n0;chunk-signature=<sig>\r\n\r\n
        let mut out = Vec::new();
        out.extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", payload.len()).as_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("0;chunk-signature={SIG}\r\n\r\n").as_bytes());
        out
    }

    #[tokio::test]
    async fn test_decode_put_invokes_put_object_from_path_with_decoded_body() {
        let key = "decoded/upload.bin";
        let backend = MockBackend::new().with_put(Ok(PutObjectOutput {
            etag: Some("\"decoded-etag\"".into()),
            version_id: None,
            extra_headers: HashMap::new(),
        }));
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        headers.insert("content-encoding", "aws-chunked".parse().unwrap());

        let body = Body::from(aws_chunked_single_chunk(b"abcdefgh"));
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("etag").unwrap().to_str().unwrap(),
            "\"decoded-etag\""
        );

        let calls = state.backend.put_spool_calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "backend must be invoked exactly once");
        let call = &calls[0];
        assert_eq!(call.bucket, "test-backend");
        assert_eq!(call.key, key);
        assert_eq!(call.len, 8);
        // Body on disk: the spool file is removed by cleanup; but the path
        // was written under cache_dir/tmp.
        assert!(
            call.path.starts_with(state.config.cache_dir.join("tmp")),
            "spool path should live under cache_dir/tmp, got {}",
            call.path.display(),
        );
        // SHA-256 of "abcdefgh".
        assert_eq!(
            call.sha256_hex,
            "9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab"
        );
        // Content-encoding has had `aws-chunked` stripped — and since there
        // was no other token, the header is dropped entirely.
        assert!(
            !call.content_headers.contains_key("content-encoding"),
            "content-encoding should be dropped when aws-chunked was the only token",
        );
    }

    #[tokio::test]
    async fn test_decode_put_strips_aws_chunked_from_mixed_content_encoding() {
        let key = "decoded/mixed-ce.bin";
        let backend = MockBackend::new().with_put(Ok(PutObjectOutput {
            etag: Some("\"e\"".into()),
            version_id: None,
            extra_headers: HashMap::new(),
        }));
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let mut parsed = make_parsed(key);
        // Simulate parse_request having put `content-encoding: gzip, aws-chunked`
        // into parsed.content_headers (lower-cased per typical handler).
        parsed
            .content_headers
            .insert("content-encoding".into(), "gzip, aws-chunked".into());

        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        headers.insert("content-encoding", "gzip, aws-chunked".parse().unwrap());
        let body = Body::from(aws_chunked_single_chunk(b"abcdefgh"));
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;
        assert_eq!(resp.status(), 200);

        let calls = state.backend.put_spool_calls.lock().unwrap();
        let ce = calls[0]
            .content_headers
            .get("content-encoding")
            .expect("content-encoding survives with gzip");
        assert_eq!(ce, "gzip");
    }

    #[tokio::test]
    async fn test_decode_put_missing_decoded_length_header_returns_invalid_argument() {
        let key = "x";
        let backend = MockBackend::new();
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);
        let headers = http::HeaderMap::new();
        let body = Body::from(aws_chunked_single_chunk(b"abcdefgh"));
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;
        assert_eq!(resp.status(), 400);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("InvalidArgument"),
            "expected InvalidArgument, got: {body_str}",
        );
        // Backend must NOT be called.
        assert_eq!(
            state
                .backend
                .total_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
    }

    #[tokio::test]
    async fn test_decode_put_oversized_declared_length_returns_entity_too_large() {
        let key = "x";
        let backend = MockBackend::new();
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        // Squeeze the cap to something tiny.
        let mut config = (*state.config).clone();
        config.max_request_body_bytes = 4;
        let state = Arc::new(crate::handlers::AppState {
            backend: state.backend.clone(),
            cache: state.cache.clone(),
            singleflight: state.singleflight.clone(),
            auth: state.auth.clone(),
            policy: state.policy.clone(),
            config: Arc::new(config),
            frontend_bucket: state.frontend_bucket.clone(),
            backend_bucket: state.backend_bucket.clone(),
            http_client: state.http_client.clone(),
        });
        let parsed = make_parsed(key);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        let body = Body::from(aws_chunked_single_chunk(b"abcdefgh"));
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;
        assert_eq!(resp.status(), 400);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("EntityTooLarge"),
            "expected EntityTooLarge, got: {body_str}",
        );
        // Backend must NOT be called and no spool file should be created.
        assert_eq!(
            state
                .backend
                .total_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        let tmp = state.config.cache_dir.join("tmp");
        if tmp.exists() {
            let mut entries = tokio::fs::read_dir(&tmp).await.unwrap();
            while let Some(e) = entries.next_entry().await.unwrap() {
                let name = e.file_name();
                assert!(
                    !name.to_string_lossy().ends_with(".upload-spool.tmp"),
                    "no spool file should exist on rejected oversized request, found {name:?}",
                );
            }
        }
    }

    #[tokio::test]
    async fn test_decode_put_malformed_body_returns_incomplete_body() {
        let key = "x";
        let backend = MockBackend::new();
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        // Truncated frame: header says 8 bytes but body has 3 and then EOF.
        let body = Body::from(format!("8;chunk-signature={SIG}\r\nabc").into_bytes());
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;
        assert_eq!(resp.status(), 400);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("IncompleteBody"),
            "expected IncompleteBody, got: {body_str}",
        );
        assert_eq!(
            state
                .backend
                .total_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
        );
        // Spool file should have been cleaned up by Drop (the guard was
        // dropped without cleanup() because decode_into_spool returned Err).
        let tmp = state.config.cache_dir.join("tmp");
        if tmp.exists() {
            let mut entries = tokio::fs::read_dir(&tmp).await.unwrap();
            while let Some(e) = entries.next_entry().await.unwrap() {
                let name = e.file_name();
                assert!(
                    !name.to_string_lossy().ends_with(".upload-spool.tmp"),
                    "spool file must be cleaned up after decode error, found {name:?}",
                );
            }
        }
    }

    #[tokio::test]
    async fn test_decode_put_invalid_chunk_size_returns_specific_s3_error() {
        let key = "x";
        let backend = MockBackend::new();
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);
        let mut headers = http::HeaderMap::new();
        // Two chunks: a 100-byte chunk (below 8192) followed by a 9000-byte
        // chunk and the final zero chunk.
        let small = vec![b'x'; 100];
        let big = vec![b'y'; 9000];
        let total = small.len() + big.len();
        headers.insert(
            "x-amz-decoded-content-length",
            total.to_string().parse().unwrap(),
        );

        let mut frame = Vec::new();
        frame.extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", small.len()).as_bytes());
        frame.extend_from_slice(&small);
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", big.len()).as_bytes());
        frame.extend_from_slice(&big);
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(format!("0;chunk-signature={SIG}\r\n\r\n").as_bytes());

        let body = Body::from(frame);
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;
        assert_eq!(resp.status(), 400);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("InvalidChunkSizeError"),
            "expected InvalidChunkSizeError, got: {body_str}",
        );
    }

    #[tokio::test]
    async fn test_decode_put_success_purges_cache() {
        let key = "script_bundle/decoded.js";
        let cache_key = CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, b"old");
        let cache = MockCache::new().with_entry(&cache_key, b"old", meta);
        let backend = MockBackend::new().with_put(Ok(PutObjectOutput {
            etag: Some("\"new\"".into()),
            version_id: None,
            extra_headers: HashMap::new(),
        }));
        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed(key);

        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        let body = Body::from(aws_chunked_single_chunk(b"abcdefgh"));
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;
        assert_eq!(resp.status(), 200);

        let cached = state.cache.lookup(&cache_key).await.unwrap();
        assert!(cached.is_none(), "decode PUT must purge the cache entry");
    }

    #[tokio::test]
    async fn test_decode_put_cleans_up_spool_after_upstream_failure() {
        let key = "x";
        let backend = MockBackend::new().with_put(Err(crate::error::ProxyError::Backend {
            source: "upstream down".into(),
            operation: "put_object_from_path".into(),
        }));
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        let body = Body::from(aws_chunked_single_chunk(b"abcdefgh"));
        let resp = handle_put_decode_aws_chunked(&state, &parsed, key, &headers, body).await;
        assert_eq!(resp.status(), 502);

        let tmp = state.config.cache_dir.join("tmp");
        if tmp.exists() {
            let mut entries = tokio::fs::read_dir(&tmp).await.unwrap();
            while let Some(e) = entries.next_entry().await.unwrap() {
                let name = e.file_name();
                assert!(
                    !name.to_string_lossy().ends_with(".upload-spool.tmp"),
                    "spool must be cleaned up after upstream failure, found {name:?}",
                );
            }
        }
    }

    #[tokio::test]
    async fn test_decode_upload_part_invokes_upload_part_from_path() {
        let key = "mp/upload.bin";
        let backend =
            MockBackend::new().with_upload_part(Ok(crate::backend::models::UploadPartOutput {
                etag: "\"part-etag\"".into(),
                extra_headers: HashMap::new(),
            }));
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let mut parsed = make_parsed(key);
        parsed.operation = S3Operation::UploadPart {
            bucket: "test-frontend".into(),
            key: key.into(),
            part_number: 3,
            upload_id: "u".into(),
        };

        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        let body = Body::from(aws_chunked_single_chunk(b"abcdefgh"));

        let resp =
            handle_upload_part_decode_aws_chunked(&state, &parsed, key, 3, "u", &headers, body)
                .await;
        assert_eq!(resp.status(), 200);
        let calls = state.backend.upload_part_spool_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].part_number, 3);
        assert_eq!(calls[0].len, 8);
        assert_eq!(calls[0].upload_id, "u");
    }

    #[tokio::test]
    async fn test_spool_create_writes_into_tmp_subdir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (guard, mut file) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        let path = guard.path().to_path_buf();
        assert!(path.starts_with(tmp.path().join("tmp")));
        assert!(path.exists());

        use tokio::io::AsyncWriteExt;
        file.write_all(b"hello").await.unwrap();
        file.flush().await.unwrap();
        drop(file);

        let body = tokio::fs::read(&path).await.unwrap();
        assert_eq!(body, b"hello");

        guard.cleanup().await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn test_spool_drop_removes_file_when_not_cleaned_up() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = {
            let (guard, _file) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
            let path = guard.path().to_path_buf();
            assert!(path.exists());
            path
        };
        // Guard dropped — Drop runs the best-effort sync remove.
        assert!(!path.exists(), "Drop should remove the spool file");
    }

    #[tokio::test]
    async fn test_spool_concurrent_creates_use_unique_filenames() {
        // Two concurrent spools must not collide on the same filename.
        let tmp = tempfile::TempDir::new().unwrap();
        let (g1, _f1) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        let (g2, _f2) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        assert_ne!(g1.path(), g2.path());
    }
}
