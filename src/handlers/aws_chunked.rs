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
use tokio::fs::File;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio_util::io::StreamReader;

use crate::backend::Backend;
use crate::backend::models::{PutObjectSpoolInput, UploadPartSpoolInput};
use crate::cache::CacheStore;
use crate::cache::key::CacheKey;
use crate::cache::perms::{create_dir_secure, open_file_secure};
use crate::handlers::AppState;
use crate::s3::aws_chunked::{
    AwsChunkedDecoder, AwsChunkedError, DecodedSummary, DecoderMode,
    STREAMING_AWS4_HMAC_SHA256_PAYLOAD, STREAMING_AWS4_HMAC_SHA256_PAYLOAD_TRAILER,
    STREAMING_UNSIGNED_PAYLOAD_TRAILER,
};
use crate::s3::checksum::{ChecksumAlgorithm, ChecksumHeader};
use crate::s3::errors::S3Error;
use crate::s3::headers::{append_extra_headers, common_headers, put_object_headers};
use crate::s3::ops::ParsedRequest;

/// Process-local counter feeding the filename pattern
/// `{pid}-{counter}.upload-spool.tmp`. Combined with the PID, this guarantees
/// uniqueness across concurrent spools without coordinating with peers.
static UPLOAD_SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create the spool file `O_CREAT | O_EXCL | O_WRONLY` with owner-only
/// permissions on Unix. The decoded body contains the object payload, so
/// group/other readability under a typical 022 umask would be a needless
/// exposure. Delegates to `cache::perms::open_file_secure` so the
/// `0o600` policy stays centralized with the rest of the cache tree.
async fn open_upload_spool_file(path: &Path) -> std::io::Result<File> {
    open_file_secure(path, |o| {
        o.write(true).create_new(true);
    })
    .await
}

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
    /// rather than silently overwrite, and (on Unix) `mode(0o600)` so the
    /// decoded body isn't readable by group/other regardless of umask.
    pub(super) async fn create(cache_dir: &Path) -> std::io::Result<(Self, File)> {
        let tmp_dir = cache_dir.join("tmp");
        create_dir_secure(&tmp_dir).await?;

        let pid = std::process::id();
        let counter = UPLOAD_SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = tmp_dir.join(format!("{pid}-{counter}.upload-spool.tmp"));

        let file = open_upload_spool_file(&path).await?;

        Ok((Self { path, armed: true }, file))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the spool file. Disarms the Drop fallback only on a
    /// successful remove — if the async remove fails, `self` is dropped
    /// with `armed = true` and the synchronous Drop gets one more
    /// best-effort attempt. This guarantees the spool file is at least
    /// retried, and never silently leaked because we cleared the flag
    /// before the I/O succeeded.
    pub(super) async fn cleanup(mut self) -> std::io::Result<()> {
        tokio::fs::remove_file(&self.path).await?;
        self.armed = false;
        Ok(())
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
    // Reject zero or multiple values for the same reason
    // `decoder_mode_from_headers` rejects duplicate `x-amz-content-sha256`:
    // `.get()` alone would silently pick the first value and drop any
    // others, letting a contradictory second declaration past this gate.
    let values: Vec<&http::HeaderValue> = raw_headers
        .get_all("x-amz-decoded-content-length")
        .iter()
        .collect();
    let raw = match values.as_slice() {
        [] => {
            return Err(S3Error::invalid_argument(
                "aws-chunked upload missing required header x-amz-decoded-content-length",
                request_id,
            ));
        }
        [single] => *single,
        _ => {
            return Err(S3Error::invalid_argument(
                "aws-chunked upload has multiple x-amz-decoded-content-length headers; only one is supported",
                request_id,
            ));
        }
    };
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

/// Reject x-amz-* headers that only make sense on the aws-chunked wire
/// format and would be wrong on the decoded backend request.
///
/// - `x-amz-content-sha256` / `x-amz-decoded-content-length` describe the
///   streaming framing the proxy just decoded out of; forwarding them to a
///   non-streaming PUT would lie about the body shape.
/// - `x-amz-trailer` advertises HTTP trailers; we've already consumed and
///   validated the trailer inline, and the decoded request has no trailer
///   to deliver.
/// - `x-amz-sdk-checksum-algorithm` is the SDK-internal switch that tells
///   AWS SDKs to wrap the body in aws-chunked streaming-checksum framing.
///   If forwarded to the backend SDK it would re-activate exactly the
///   re-encoding we paid a streaming decode to avoid. The
///   per-algorithm `.checksum_*()` setters in client.rs ARE the supported
///   way to forward the actual checksum value.
fn is_streaming_only_amz_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-amz-content-sha256")
        || name.eq_ignore_ascii_case("x-amz-decoded-content-length")
        || name.eq_ignore_ascii_case("x-amz-trailer")
        || name.eq_ignore_ascii_case("x-amz-sdk-checksum-algorithm")
}

/// Defense-in-depth filter for the `extra_amz_headers` map handed to the
/// decoded backend request. Drops streaming-only x-amz-* headers that
/// would be wrong on a normal PUT/UploadPart (see
/// `is_streaming_only_amz_header`). Production is gated by the dispatch
/// routing — the trailer-mode parser consumes `x-amz-trailer` inline before
/// reaching the backend, and `parse.rs` strips `x-amz-content-sha256` and
/// `x-amz-decoded-content-length` from `extra_amz_headers` — but this
/// filter ensures that even if dispatch or `parse.rs` regresses, the
/// decoded backend inputs stay clean.
///
/// `x-amz-checksum-*` headers are explicitly NOT filtered: those are
/// legitimate non-streaming S3 checksum advertisements that the decoded
/// PutObject path must forward intact.
fn extra_amz_headers_for_decoded(
    parsed: &ParsedRequest,
) -> std::collections::HashMap<String, String> {
    parsed
        .extra_amz_headers
        .iter()
        .filter(|(k, _)| !is_streaming_only_amz_header(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Map an `AwsChunkedError` to the matching `S3Error`. Framing errors all
/// surface as `IncompleteBody` (HTTP 400) except the chunk-size minimum,
/// which gets its own `InvalidChunkSizeError`. I/O is split by cause:
/// inbound stream errors are client-caused → 400 `IncompleteBody`; spool
/// write errors are server-caused → 500 `InternalError`.
fn map_decode_error(err: AwsChunkedError, request_id: &str) -> S3Error {
    match err {
        AwsChunkedError::InvalidChunkSize { .. } => {
            S3Error::invalid_chunk_size(&err.to_string(), request_id)
        }
        // Inbound stream errors are client-caused (truncated socket, mid-stream
        // reset, …) → 400 IncompleteBody, same as the framing errors below.
        AwsChunkedError::InboundIo { .. } => S3Error::incomplete_body(&err.to_string(), request_id),
        // Spool write errors are server-caused (ENOSPC, EACCES, …) →
        // 500 InternalError.
        AwsChunkedError::SpoolIo { .. } => {
            S3Error::internal_error(&format!("aws-chunked decode I/O error: {err}"), request_id)
        }
        AwsChunkedError::MalformedFrame { .. }
        | AwsChunkedError::DecodedLengthMismatch { .. }
        | AwsChunkedError::DecodedLengthExceeded { .. }
        | AwsChunkedError::Truncated
        | AwsChunkedError::TrailingData
        | AwsChunkedError::ChunkHeaderTooLarge { .. } => {
            S3Error::incomplete_body(&err.to_string(), request_id)
        }
        // Trailer framing / signature errors: malformed structure → InvalidRequest.
        AwsChunkedError::InvalidTrailer { .. }
        | AwsChunkedError::MissingTrailer { .. }
        | AwsChunkedError::InvalidTrailerSignature { .. } => {
            S3Error::invalid_request(&err.to_string(), request_id)
        }
        // The trailer value parsed cleanly but wasn't a valid digest →
        // InvalidDigest. Distinguished from a mismatch (real checksum failure)
        // so clients can tell "your trailer is the wrong shape" from "your
        // trailer doesn't match what we computed".
        AwsChunkedError::InvalidTrailerChecksum { .. } => {
            S3Error::invalid_digest(&err.to_string(), request_id)
        }
        // The trailer was well-formed and parsed to the right length, but
        // doesn't match the computed digest. This is the load-bearing
        // integrity error → BadDigest.
        AwsChunkedError::TrailerChecksumMismatch { .. } => {
            S3Error::bad_digest(&err.to_string(), request_id)
        }
    }
}

/// Decode the inbound aws-chunked body into a spool file. Returns the spool
/// guard and the full decoded summary (length, SHA-256, optional validated
/// trailer). On error, the spool file is cleaned up by Drop (we never
/// returned the guard).
async fn decode_into_spool<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    body: Body,
    declared_len: u64,
    mode: DecoderMode,
) -> Result<(UploadSpoolGuard, DecodedSummary), S3Error> {
    use futures_compat::body_to_io_stream;

    let (guard, file) = UploadSpoolGuard::create(&state.config.cache_dir)
        .await
        .map_err(|e| {
            S3Error::internal_error(
                &format!("failed to create aws-chunked spool file: {e}"),
                &parsed.request_id,
            )
        })?;

    let reader = StreamReader::new(body_to_io_stream(body));
    let mut writer = BufWriter::new(file);
    let summary = AwsChunkedDecoder::with_mode(reader, declared_len, mode)
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

    Ok((guard, summary))
}

/// Inspect the inbound `x-amz-content-sha256` sentinel plus the
/// `x-amz-trailer` header on `raw_headers` and produce the matching
/// `DecoderMode`. The dispatch routing already diverts unsupported
/// sentinels off the decode path — ECDSA streams reject up front with
/// `UnsupportedSignature`, and unknown / contradictory shapes fall through
/// to passthrough — so this helper assumes the request is going through
/// the decode path and rejects the residual cases (no sentinel match,
/// trailer-mode without a usable trailer header) with `InvalidRequest`.
///
/// `x-amz-content-sha256` must appear exactly once with an ASCII, non-empty
/// value. The dispatch classifier inspects every value defensively, so a
/// client that sent two contradictory sentinels could be routed by one and
/// decoded under another if we picked a different value here. Reject the
/// ambiguity outright instead.
pub(super) fn decoder_mode_from_headers(
    raw_headers: &http::HeaderMap,
    request_id: &str,
) -> Result<DecoderMode, S3Error> {
    let values: Vec<&http::HeaderValue> =
        raw_headers.get_all("x-amz-content-sha256").iter().collect();
    let raw = match values.as_slice() {
        [] => {
            return Err(S3Error::invalid_request(
                "aws-chunked decode path requires x-amz-content-sha256 header",
                request_id,
            ));
        }
        [single] => *single,
        _ => {
            return Err(S3Error::invalid_request(
                "aws-chunked decode path has multiple x-amz-content-sha256 headers; only one is supported",
                request_id,
            ));
        }
    };
    let sentinel = raw
        .to_str()
        .map_err(|_| {
            S3Error::invalid_request(
                "x-amz-content-sha256 header was not valid ASCII",
                request_id,
            )
        })?
        .trim();
    if sentinel.is_empty() {
        return Err(S3Error::invalid_request(
            "x-amz-content-sha256 header was empty",
            request_id,
        ));
    }
    let upper = sentinel.to_ascii_uppercase();
    if upper == STREAMING_AWS4_HMAC_SHA256_PAYLOAD {
        return Ok(DecoderMode::NonTrailer);
    }

    let header = read_declared_trailer(raw_headers, request_id)?;
    if upper == STREAMING_UNSIGNED_PAYLOAD_TRAILER {
        Ok(DecoderMode::UnsignedTrailer {
            expected_trailer_name: header.name,
            algorithm: header.algorithm,
        })
    } else if upper == STREAMING_AWS4_HMAC_SHA256_PAYLOAD_TRAILER {
        Ok(DecoderMode::SignedTrailer {
            expected_trailer_name: header.name,
            algorithm: header.algorithm,
        })
    } else {
        Err(S3Error::invalid_request(
            &format!("unsupported aws-chunked sentinel `{sentinel}` reached the decode path"),
            request_id,
        ))
    }
}

/// Read and validate the `x-amz-trailer` header on a trailer-mode request.
/// Exactly one header value must be present, and it must name a supported
/// `x-amz-checksum-<algo>` header. Zero or multiple values, or an unsupported
/// algorithm, all surface as `InvalidRequest`.
///
/// Duplicate `x-amz-trailer` headers must be rejected outright: `.get()`
/// alone would silently pick the first and drop the rest, which lets a
/// client smuggle a second contradictory trailer declaration past the
/// classifier. Different headers expressing different intents is a contract
/// violation regardless of which one we'd pick — better to reject.
fn read_declared_trailer(
    raw_headers: &http::HeaderMap,
    request_id: &str,
) -> Result<ChecksumHeader, S3Error> {
    let values: Vec<&http::HeaderValue> = raw_headers.get_all("x-amz-trailer").iter().collect();
    let raw = match values.as_slice() {
        [] => {
            return Err(S3Error::invalid_request(
                "trailer-mode aws-chunked upload missing required x-amz-trailer header",
                request_id,
            ));
        }
        [single] => *single,
        _ => {
            return Err(S3Error::invalid_request(
                "trailer-mode aws-chunked upload has multiple x-amz-trailer headers; only one is supported",
                request_id,
            ));
        }
    };
    let value = raw.to_str().map_err(|_| {
        S3Error::invalid_request("x-amz-trailer header was not valid ASCII", request_id)
    })?;
    let trimmed = value.trim();
    let algo = ChecksumAlgorithm::from_header_name(trimmed).ok_or_else(|| {
        S3Error::invalid_request(
            &format!("x-amz-trailer declared unsupported trailer header `{trimmed}`"),
            request_id,
        )
    })?;
    // The trailer VALUE isn't known until the body is consumed — this
    // declaration is shape-only. The decoder fills the validated `value` in
    // when it parses the trailer line.
    Ok(ChecksumHeader {
        algorithm: algo,
        name: algo.header_name().to_string(),
        value: String::new(),
    })
}

mod futures_compat {
    use axum::body::Body;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio_stream::Stream;

    // Adapt an axum `Body` data stream to a
    // `Stream<Item = Result<Bytes, io::Error>>`, the input shape
    // `tokio_util::io::StreamReader` expects. We don't depend on
    // `futures-util`, so this is a hand-rolled error-mapping wrapper.
    pin_project_lite::pin_project! {
        struct IoErrorMap {
            #[pin]
            inner: http_body_util::BodyDataStream<Body>,
        }
    }

    impl Stream for IoErrorMap {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.project();
            match this.inner.poll_next(cx) {
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

    let mode = match decoder_mode_from_headers(raw_headers, &parsed.request_id) {
        Ok(m) => m,
        Err(e) => return e.to_response(),
    };

    let (guard, summary) = match decode_into_spool(state, parsed, body, declared_len, mode).await {
        Ok(v) => v,
        Err(e) => return e.to_response(),
    };
    let decoded_len = summary.decoded_len;

    let input = PutObjectSpoolInput {
        bucket: state.backend_bucket.to_string(),
        key: key.to_string(),
        path: guard.path().to_path_buf(),
        len: decoded_len,
        sha256_hex: summary.sha256_hex,
        content_type: parsed.content_type.clone(),
        content_md5: parsed.content_md5.clone(),
        metadata: parsed.user_metadata.clone(),
        extra_amz_headers: extra_amz_headers_for_decoded(parsed),
        content_headers: content_headers_for_decoded(parsed),
        checksum: summary.trailer,
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

    let mode = match decoder_mode_from_headers(raw_headers, &parsed.request_id) {
        Ok(m) => m,
        Err(e) => return e.to_response(),
    };

    let (guard, summary) = match decode_into_spool(state, parsed, body, declared_len, mode).await {
        Ok(v) => v,
        Err(e) => return e.to_response(),
    };
    let decoded_len = summary.decoded_len;

    let input = UploadPartSpoolInput {
        bucket: state.backend_bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
        part_number,
        path: guard.path().to_path_buf(),
        len: decoded_len,
        sha256_hex: summary.sha256_hex,
        content_md5: parsed.content_md5.clone(),
        extra_amz_headers: extra_amz_headers_for_decoded(parsed),
        checksum: summary.trailer,
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
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
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
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
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
            inbound_sigv4: None,
            policy: state.policy.clone(),
            config: Arc::new(config),
            frontend_bucket: state.frontend_bucket.clone(),
            backend_bucket: state.backend_bucket.clone(),
            http_client: state.http_client.clone(),
        });
        let parsed = make_parsed(key);
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amz-decoded-content-length", "8".parse().unwrap());
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
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
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
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
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
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
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
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
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
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
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
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

    /// Spool files carry decoded request bodies (object payload), so on
    /// Unix they must be created owner-only (0600) regardless of the
    /// process umask. Asserts no group/other bits are set on the created
    /// file. `OpenOptions::mode(0o600)` is still subject to umask (umask
    /// can only REMOVE bits, never add), so checking `mode & 0o077 == 0`
    /// is the right invariant — it catches the regression where the
    /// helper falls back to umask-respecting defaults under 022.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_spool_create_uses_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let (guard, file) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        drop(file);

        let mode = tokio::fs::metadata(guard.path())
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "spool file must not be group/other readable; got mode {:o}",
            mode,
        );

        guard.cleanup().await.unwrap();
    }

    /// Pins CodeRabbit Finding 2: if the async `remove_file` inside
    /// `cleanup()` fails (here simulated by removing the file out from
    /// under the guard), the guard must drop with `armed = true` so the
    /// synchronous Drop fallback fires. We can't directly observe the
    /// disarm bit from outside, but we CAN prove the function doesn't
    /// disarm prematurely: if the previous ordering (`armed = false` then
    /// `remove`) had survived, the Drop fallback wouldn't have anything to
    /// retry and we'd still see the function return Err — the bug is
    /// the *silent leak* it would cause if the remove had genuinely failed
    /// for a recoverable reason. Bug-revert reasoning is documented inline.
    #[tokio::test]
    async fn test_spool_cleanup_returns_err_when_file_already_gone() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (guard, file) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        let path = guard.path().to_path_buf();
        drop(file);
        // Yank the file out from under the guard so the cleanup remove
        // call fails with NotFound.
        tokio::fs::remove_file(&path).await.unwrap();

        let result = guard.cleanup().await;
        assert!(
            result.is_err(),
            "cleanup() must surface the underlying remove failure to the caller",
        );
        // File is gone either way (we removed it manually), so the Drop
        // fallback running on the still-armed guard is a no-op. The
        // test's bug-revert value is: if the ordering regressed (armed
        // cleared BEFORE remove), this assertion would still pass — the
        // failure mode is a silent leak when remove ACTUALLY fails for a
        // recoverable reason. A direct test of "Drop did retry" would
        // need a mock filesystem; we rely on visual review of the
        // ordering plus the regression guard above.
        assert!(!path.exists());
    }

    // ---- map_decode_error: InboundIo vs SpoolIo split ----

    /// Inbound stream errors come from the client side of the connection
    /// (truncated socket, mid-stream reset, …) so they must surface as
    /// `IncompleteBody` (HTTP 400). Pins CodeRabbit Finding 1's split.
    #[test]
    fn test_inbound_io_failure_maps_to_incomplete_body() {
        let err = AwsChunkedError::InboundIo {
            source: std::io::Error::other("client reset connection"),
        };
        let s3err = map_decode_error(err, "req-test");
        assert_eq!(s3err.code, "IncompleteBody");
        assert_eq!(s3err.http_status, http::StatusCode::BAD_REQUEST);
    }

    /// Spool write errors are server-caused (ENOSPC, EACCES, …) so they
    /// must surface as `InternalError` (HTTP 500). Pins CodeRabbit
    /// Finding 1's split — the previous blanket `Io` variant would have
    /// mis-mapped this to 500 too, but a blanket switch to IncompleteBody
    /// would have hidden it as a 400. The split keeps both directions
    /// correct.
    #[test]
    fn test_spool_write_failure_maps_to_internal_error() {
        let err = AwsChunkedError::SpoolIo {
            source: std::io::Error::from(std::io::ErrorKind::StorageFull),
        };
        let s3err = map_decode_error(err, "req-test");
        assert_eq!(s3err.code, "InternalError");
        assert_eq!(s3err.http_status, http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ---- extra_amz_headers_for_decoded: streaming-only header filter ----

    /// Defense-in-depth filter must drop `x-amz-content-sha256`,
    /// `x-amz-decoded-content-length`, and `x-amz-trailer` from the
    /// decoded request's `extra_amz_headers` map. Non-streaming x-amz-*
    /// headers (checksums, SSE, …) must survive — these are legitimate
    /// on a normal PUT.
    #[test]
    fn test_extra_amz_headers_for_decoded_strips_streaming_only_headers() {
        let mut parsed = make_parsed("k");
        parsed.extra_amz_headers.insert(
            "x-amz-content-sha256".into(),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".into(),
        );
        parsed
            .extra_amz_headers
            .insert("x-amz-decoded-content-length".into(), "8".into());
        parsed
            .extra_amz_headers
            .insert("x-amz-trailer".into(), "x-amz-checksum-crc32".into());
        // Should be preserved.
        parsed
            .extra_amz_headers
            .insert("x-amz-checksum-crc32".into(), "abc=".into());
        parsed
            .extra_amz_headers
            .insert("x-amz-server-side-encryption".into(), "AES256".into());

        let filtered = extra_amz_headers_for_decoded(&parsed);
        assert!(!filtered.contains_key("x-amz-content-sha256"));
        assert!(!filtered.contains_key("x-amz-decoded-content-length"));
        assert!(
            !filtered.contains_key("x-amz-trailer"),
            "x-amz-trailer must be filtered — parse.rs doesn't strip it",
        );
        assert_eq!(
            filtered.get("x-amz-checksum-crc32").map(String::as_str),
            Some("abc="),
            "non-streaming checksum headers must be preserved",
        );
        assert_eq!(
            filtered
                .get("x-amz-server-side-encryption")
                .map(String::as_str),
            Some("AES256"),
            "non-streaming SSE headers must be preserved",
        );
    }

    /// HTTP header names are case-insensitive. The classifier must match
    /// regardless of how the parser cased the key in `extra_amz_headers`.
    #[test]
    fn test_is_streaming_only_amz_header_case_insensitive() {
        assert!(is_streaming_only_amz_header("X-Amz-Trailer"));
        assert!(is_streaming_only_amz_header("x-AMZ-Decoded-Content-Length"));
        assert!(is_streaming_only_amz_header("X-AMZ-CONTENT-SHA256"));
        assert!(!is_streaming_only_amz_header("x-amz-checksum-crc32"));
        assert!(!is_streaming_only_amz_header(
            "x-amz-server-side-encryption"
        ));
    }

    /// `x-amz-sdk-checksum-algorithm` must be filtered from
    /// `extra_amz_headers` on the decoded backend request — if forwarded, it
    /// would re-activate the SDK's outbound aws-chunked re-encoding. The
    /// per-algorithm `.checksum_*()` setters on the backend client are the
    /// supported way to forward the checksum value.
    #[test]
    fn test_is_streaming_only_amz_header_includes_sdk_checksum_algorithm() {
        assert!(is_streaming_only_amz_header("x-amz-sdk-checksum-algorithm"));
        assert!(is_streaming_only_amz_header("X-AMZ-SDK-CHECKSUM-ALGORITHM"));
    }

    // ---- content_encoding_without_aws_chunked ----
    //
    // The strip helper is the load-bearing complement to
    // `header_str_combined` in `parse.rs`: the parser merges repeated
    // `Content-Encoding` headers into one comma list, and the strip helper
    // must split that list correctly, drop every `aws-chunked` token
    // (case-insensitive, including duplicates), and preserve order + spacing
    // for the remaining tokens. These tests pin each edge case in isolation
    // so a regression in either side surfaces before the full PUT pipeline.

    /// Already-comma-joined `aws-chunked,gzip` strips down to just `gzip`.
    /// The classic single-header shape.
    #[test]
    fn test_content_encoding_strip_single_header_comma_list() {
        let stripped = content_encoding_without_aws_chunked("aws-chunked,gzip");
        assert_eq!(stripped.as_deref(), Some("gzip"));
    }

    /// The shape produced by `header_str_combined` after merging two
    /// separate `Content-Encoding` lines: `"aws-chunked, gzip"` (with the
    /// `", "` separator). Must strip the same way as the comma-only form —
    /// the trim in `content_encoding_without_aws_chunked` is load-bearing
    /// here.
    ///
    /// Bug-revert reasoning: dropping the `str::trim` from the strip
    /// helper turns the `" gzip"` token into a non-match for any case of
    /// `aws-chunked` and leaves it as `" gzip"` (with the leading space),
    /// so the upstream `Content-Encoding` would contain a phantom space
    /// token. This assertion (`Some("gzip")`, not `Some(" gzip")`) flips.
    #[test]
    fn test_content_encoding_strip_combined_repeated_header_shape() {
        let stripped = content_encoding_without_aws_chunked("aws-chunked, gzip");
        assert_eq!(stripped.as_deref(), Some("gzip"));
    }

    /// Duplicate `aws-chunked, aws-chunked` (a misbehaving client that
    /// repeated the token) must strip BOTH copies and result in no
    /// surviving tokens → the caller drops `Content-Encoding` entirely.
    ///
    /// Bug-revert reasoning: a strip implementation that only removed the
    /// first occurrence (`replace_first` style) would leave `"aws-chunked"`
    /// as the surviving token, and the assertion would flip from `None` to
    /// `Some("aws-chunked")`.
    #[test]
    fn test_content_encoding_strip_drops_all_duplicate_aws_chunked_tokens() {
        let stripped = content_encoding_without_aws_chunked("aws-chunked, aws-chunked");
        assert_eq!(
            stripped, None,
            "all aws-chunked tokens must strip; nothing left → drop the header",
        );
    }

    /// Case-insensitive match: `AWS-CHUNKED, gzip` → `gzip`. AWS docs and
    /// the SigV4 reference don't fix the case of the encoding token; the
    /// strip helper must not be lulled into shipping an `AWS-CHUNKED` token
    /// to the upstream just because the casing differs.
    #[test]
    fn test_content_encoding_strip_case_insensitive() {
        let stripped = content_encoding_without_aws_chunked("AWS-CHUNKED, gzip");
        assert_eq!(stripped.as_deref(), Some("gzip"));
    }

    /// Mixed-case repetition: `Aws-Chunked, gzip, AWS-CHUNKED` strips both
    /// chunked tokens and keeps `gzip`. Combines the case-insensitive and
    /// duplicate-elimination contracts in one shape.
    #[test]
    fn test_content_encoding_strip_mixed_case_duplicates_and_gzip_preserved() {
        let stripped = content_encoding_without_aws_chunked("Aws-Chunked, gzip, AWS-CHUNKED");
        assert_eq!(stripped.as_deref(), Some("gzip"));
    }

    /// Empty input → `None`. A `Content-Encoding: ` empty value or a
    /// stripped-to-nothing value must not produce a phantom empty header
    /// on the decoded backend request.
    #[test]
    fn test_content_encoding_strip_empty_input_returns_none() {
        assert_eq!(content_encoding_without_aws_chunked(""), None);
    }

    // ---- decoder_mode_from_headers ----

    use crate::s3::aws_chunked::DecoderMode;

    fn make_headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn test_decoder_mode_from_headers_non_trailer() {
        let h = make_headers(&[("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")]);
        assert_eq!(
            decoder_mode_from_headers(&h, "r").unwrap(),
            DecoderMode::NonTrailer,
        );
    }

    #[test]
    fn test_decoder_mode_from_headers_unsigned_trailer() {
        let h = make_headers(&[
            ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ]);
        let mode = decoder_mode_from_headers(&h, "r").unwrap();
        match mode {
            DecoderMode::UnsignedTrailer {
                expected_trailer_name,
                algorithm,
            } => {
                assert_eq!(expected_trailer_name, "x-amz-checksum-crc32");
                assert_eq!(algorithm, ChecksumAlgorithm::Crc32);
            }
            other => panic!("expected UnsignedTrailer, got {other:?}"),
        }
    }

    #[test]
    fn test_decoder_mode_from_headers_signed_trailer() {
        let h = make_headers(&[
            (
                "x-amz-content-sha256",
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            ),
            ("x-amz-trailer", "x-amz-checksum-sha256"),
        ]);
        let mode = decoder_mode_from_headers(&h, "r").unwrap();
        match mode {
            DecoderMode::SignedTrailer {
                expected_trailer_name,
                algorithm,
            } => {
                assert_eq!(expected_trailer_name, "x-amz-checksum-sha256");
                assert_eq!(algorithm, ChecksumAlgorithm::Sha256);
            }
            other => panic!("expected SignedTrailer, got {other:?}"),
        }
    }

    /// Trailer mode declared but the x-amz-trailer header points at an
    /// unsupported algorithm — must surface InvalidRequest so the handler
    /// can return 400 rather than route the request through the decode path
    /// with an unrecognised algorithm.
    #[test]
    fn test_decoder_mode_from_headers_unsupported_trailer_algo() {
        let h = make_headers(&[
            ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
            ("x-amz-trailer", "x-amz-checksum-md5"),
        ]);
        let err = decoder_mode_from_headers(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
    }

    /// Trailer mode declared but x-amz-trailer is missing entirely.
    #[test]
    fn test_decoder_mode_from_headers_missing_trailer_header() {
        let h = make_headers(&[("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")]);
        let err = decoder_mode_from_headers(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
    }

    /// Missing `x-amz-trailer` surfaces InvalidRequest from
    /// `read_declared_trailer`. Companion to the integration-level coverage,
    /// pinning the exact S3 error code at the helper boundary.
    #[test]
    fn test_read_declared_trailer_rejects_missing_header() {
        let h = http::HeaderMap::new();
        let err = read_declared_trailer(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
        assert!(
            err.message.contains("missing"),
            "error should explain why, got: {}",
            err.message,
        );
    }

    /// Two `x-amz-trailer` headers MUST be rejected outright: the helper
    /// can't safely pick one (they may name different algorithms) and
    /// `.get()` alone would silently drop all but the first, letting a
    /// contradictory second declaration slip through the classifier.
    ///
    /// Bug-revert reasoning: reverting `read_declared_trailer` to a single
    /// `raw_headers.get("x-amz-trailer")` call returns `Ok` on this input
    /// (picks the first value), and this assertion flips to a panic on the
    /// `.unwrap_err()` call.
    #[test]
    fn test_read_declared_trailer_rejects_duplicate_headers() {
        let mut h = http::HeaderMap::new();
        h.append("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());
        h.append("x-amz-trailer", "x-amz-checksum-sha256".parse().unwrap());
        let err = read_declared_trailer(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
        assert!(
            err.message.contains("multiple"),
            "error should mention the duplicate, got: {}",
            err.message,
        );
    }

    /// Two `x-amz-content-sha256` headers must be rejected outright. The
    /// dispatch classifier (`classify_aws_chunked_upload`) inspects every
    /// value defensively to detect smuggled sentinels, but
    /// `decoder_mode_from_headers` chose a single value to decode under —
    /// without this guard, a client could route via one sentinel and
    /// decode under another.
    ///
    /// Bug-revert reasoning: reverting `decoder_mode_from_headers` to the
    /// previous `get_all().filter_map(to_str).find(!is_empty)` chain
    /// returns `Ok(DecoderMode::NonTrailer)` on this input (picks the
    /// first usable value), and this assertion flips to a panic on the
    /// `.unwrap_err()` call.
    #[test]
    fn test_decoder_mode_from_headers_rejects_duplicate_content_sha256() {
        let mut h = http::HeaderMap::new();
        h.append(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        h.append(
            "x-amz-content-sha256",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD".parse().unwrap(),
        );
        let err = decoder_mode_from_headers(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
        assert!(
            err.message.contains("multiple"),
            "error should mention the duplicate, got: {}",
            err.message,
        );
    }

    /// Non-ASCII bytes in `x-amz-content-sha256` are nonsensical for any of
    /// the recognised STREAMING-* sentinels and must be rejected.
    #[test]
    fn test_decoder_mode_from_headers_rejects_non_ascii_content_sha256() {
        let mut h = http::HeaderMap::new();
        // 0x80 is invalid as a standalone byte in UTF-8 / ASCII.
        let val = http::HeaderValue::from_bytes(&[0x80]).unwrap();
        h.insert("x-amz-content-sha256", val);
        let err = decoder_mode_from_headers(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
    }

    /// Empty `x-amz-content-sha256` value is rejected. Catches the case
    /// where the header is technically present but conveys no sentinel.
    #[test]
    fn test_decoder_mode_from_headers_rejects_empty_content_sha256() {
        let h = make_headers(&[("x-amz-content-sha256", "   ")]);
        let err = decoder_mode_from_headers(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
        assert!(
            err.message.contains("empty"),
            "error should mention emptiness, got: {}",
            err.message,
        );
    }

    /// Defense-in-depth: if an ECDSA streaming sentinel somehow reaches
    /// `decoder_mode_from_headers` (i.e. the dispatch routing regresses and
    /// no longer rejects ECDSA up front), the decoder must still refuse to
    /// build a `DecoderMode` — silently treating it as something we can
    /// decode would mean accepting a stream we can't validate. Production
    /// dispatch routes ECDSA to `RejectUnsupportedSignature` before reaching
    /// here; this test pins the decode-path backstop.
    ///
    /// Even with a usable `x-amz-trailer` present (which would otherwise
    /// short-circuit the missing-trailer guard for trailer-mode sentinels),
    /// the ECDSA sentinel must still surface as `InvalidRequest` via the
    /// `unsupported aws-chunked sentinel reached the decode path` branch.
    ///
    /// Bug-revert reasoning: replacing the fall-through `Err` branch with a
    /// permissive ECDSA mapping (e.g. routing it through `DecoderMode::
    /// SignedTrailer` because the suffix looks similar) flips this assertion
    /// to a panic on `.unwrap_err()`.
    #[test]
    fn test_decoder_mode_from_headers_rejects_ecdsa_sentinel() {
        let h = make_headers(&[
            (
                "x-amz-content-sha256",
                "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER",
            ),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ]);
        let err = decoder_mode_from_headers(&h, "r").unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
        assert!(
            err.message.to_ascii_lowercase().contains("unsupported"),
            "error should mention the unsupported sentinel, got: {}",
            err.message,
        );
    }

    /// Two `x-amz-decoded-content-length` headers must be rejected. Same
    /// failure mode as `x-amz-content-sha256` duplicates: `.get()` alone
    /// picks the first value, letting a contradictory second declaration
    /// past the gate that the rest of the decode pipeline (oversize
    /// preflight, decoder length-match check) relies on.
    ///
    /// Bug-revert reasoning: reverting `read_declared_decoded_length` to a
    /// single `raw_headers.get("x-amz-decoded-content-length")` call
    /// returns `Ok(8)` on this input, and this assertion flips to a panic
    /// on the `.unwrap_err()` call.
    #[test]
    fn test_read_declared_decoded_length_rejects_duplicate_headers() {
        let mut h = http::HeaderMap::new();
        h.append("x-amz-decoded-content-length", "8".parse().unwrap());
        h.append("x-amz-decoded-content-length", "16".parse().unwrap());
        let err = read_declared_decoded_length(&h, "r").unwrap_err();
        // Existing missing-case uses InvalidArgument; the new "multiple"
        // case mirrors it.
        assert_eq!(err.code, "InvalidArgument");
        assert!(
            err.message.contains("multiple"),
            "error should mention the duplicate, got: {}",
            err.message,
        );
    }

    /// End-to-end unsigned-trailer PUT: builds a valid CRC32 trailer frame,
    /// asserts the decode succeeds, and asserts the validated checksum
    /// reaches the backend as a `ChecksumHeader` (NOT via extra_amz_headers).
    #[tokio::test]
    async fn test_decode_put_unsigned_trailer_forwards_checksum_to_backend() {
        use crate::s3::checksum::ChecksumAlgorithm;
        let key = "trailer/unsigned.bin";
        let backend = MockBackend::new().with_put(Ok(PutObjectOutput {
            etag: Some("\"trailer-etag\"".into()),
            version_id: None,
            extra_headers: HashMap::new(),
        }));
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        // Compute the expected CRC32 trailer value via smithy.
        let mut hasher = algo.into_smithy_impl();
        aws_smithy_checksums::Checksum::update(hasher.as_mut(), payload);
        let bytes = aws_smithy_checksums::Checksum::finalize(hasher);
        let value = aws_smithy_types::base64::encode(&bytes[..]);

        // Build the frame: bare-size chunk + trailer + closing CRLF.
        let mut frame = Vec::new();
        frame.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n0\r\n");
        frame.extend_from_slice(format!("{}:{value}\r\n", algo.header_name()).as_bytes());
        frame.extend_from_slice(b"\r\n");

        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-decoded-content-length",
            payload.len().to_string().parse().unwrap(),
        );
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".parse().unwrap(),
        );
        headers.insert("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());

        let resp =
            handle_put_decode_aws_chunked(&state, &parsed, key, &headers, Body::from(frame)).await;
        assert_eq!(resp.status(), 200);

        let calls = state.backend.put_spool_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let checksum = calls[0]
            .checksum
            .as_ref()
            .expect("trailer-mode PUT must forward the validated checksum to the backend");
        assert_eq!(checksum.algorithm, ChecksumAlgorithm::Crc32);
        assert_eq!(checksum.name, "x-amz-checksum-crc32");
        assert_eq!(checksum.value, value);
        // The checksum field is the contract — extra_amz_headers must NOT
        // also carry the trailer or the sdk-checksum-algorithm header.
        assert!(!calls[0].extra_amz_headers.contains_key("x-amz-trailer"));
        assert!(
            !calls[0]
                .extra_amz_headers
                .contains_key("x-amz-sdk-checksum-algorithm"),
        );
    }

    /// A trailer with a wrong checksum must produce a BadDigest 400 BEFORE
    /// the backend is contacted. Pins the load-bearing integrity guard.
    #[tokio::test]
    async fn test_decode_put_trailer_mismatch_returns_bad_digest() {
        use crate::s3::checksum::ChecksumAlgorithm;
        let key = "trailer/mismatch.bin";
        let backend = MockBackend::new();
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed(key);

        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        // Right shape (4 bytes of base64), wrong value.
        let wrong = aws_smithy_types::base64::encode(b"WRNG");

        let mut frame = Vec::new();
        frame.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n0\r\n");
        frame.extend_from_slice(format!("{}:{wrong}\r\n", algo.header_name()).as_bytes());
        frame.extend_from_slice(b"\r\n");

        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-decoded-content-length",
            payload.len().to_string().parse().unwrap(),
        );
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".parse().unwrap(),
        );
        headers.insert("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());

        let resp =
            handle_put_decode_aws_chunked(&state, &parsed, key, &headers, Body::from(frame)).await;
        assert_eq!(resp.status(), 400);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("BadDigest"),
            "expected BadDigest, got: {body_str}",
        );
        // Backend must NOT be called.
        assert_eq!(
            state
                .backend
                .total_calls
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "trailer-mismatch must reject before backend contact",
        );
    }
}
