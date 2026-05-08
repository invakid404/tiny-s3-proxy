use std::sync::Arc;
use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4::SigningParams;
use axum::body::Body;
use http::Response;

use crate::backend::Backend;
use crate::cache::CacheStore;
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::common_headers;

/// Standard HTTP hop-by-hop headers (RFC 9110, Section 7.6.1) that MUST be
/// consumed by an intermediary and MUST NOT be forwarded end-to-end.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Additional request-side headers that must not be forwarded because they
/// are set by the SigV4 signer or managed by the HTTP client.
const SKIP_REQUEST_HEADERS: &[&str] = &[
    "authorization",
    "x-amz-date",
    "x-amz-content-sha256",
    "x-amz-security-token",
    "host",
    "content-length", // reqwest sets this from body
];

/// Compute the lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest.as_slice() {
        write!(hex, "{byte:02x}").unwrap();
    }
    hex
}

/// Collect header names nominated as hop-by-hop by `Connection` headers.
/// Per RFC 9110 Section 7.6.1, each token in `Connection` names a header
/// that the sender considers hop-by-hop and that MUST be removed by the
/// first intermediary.
fn collect_connection_nominated(headers: &http::HeaderMap) -> Vec<String> {
    let mut nominated = Vec::new();
    for conn_val in headers.get_all("connection") {
        if let Ok(s) = conn_val.to_str() {
            for token in s.split(',') {
                let name = token.trim().to_lowercase();
                if !name.is_empty() {
                    nominated.push(name);
                }
            }
        }
    }
    nominated
}

/// Handle an unsupported S3 operation by proxying the raw HTTP request
/// to the backend, re-signing it with the backend credentials.
///
/// # Architecture note
///
/// This handler intentionally bypasses the `Backend` trait. The Backend
/// trait exposes typed methods (get_object, put_object, etc.) for operations
/// the proxy understands. Passthrough exists for operations the proxy does
/// NOT model — it forwards the raw HTTP request with all its headers and
/// body intact. Re-signing with SigV4 requires access to the raw URL, headers,
/// and body bytes, which typed trait methods cannot provide. Abstracting
/// this behind a trait would either leak HTTP details into the trait or
/// require a second "raw proxy" trait that duplicates the HTTP client logic.
pub async fn handle_passthrough<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    method: &str,
    path: &str,
    query: Option<&str>,
    original_headers: &http::HeaderMap,
    body: Body,
    request_id: &str,
) -> Response<Body> {
    handle_passthrough_with_clock(
        state,
        method,
        path,
        query,
        original_headers,
        body,
        request_id,
        SystemTime::now,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_passthrough_with_clock<B, C, Now>(
    state: &Arc<AppState<B, C>>,
    method: &str,
    path: &str,
    query: Option<&str>,
    original_headers: &http::HeaderMap,
    body: Body,
    request_id: &str,
    now: Now,
) -> Response<Body>
where
    B: Backend,
    C: CacheStore,
    Now: Fn() -> SystemTime + Send + Sync,
{
    // 1. Build the upstream URL.
    // When backend_use_path_style is false, rewrite to virtual-hosted-style:
    //   https://bucket.endpoint/key  instead of  https://endpoint/bucket/key
    let upstream_url = if !state.config.backend_use_path_style {
        // path is "/<bucket>/<key>" — extract bucket from first segment.
        let trimmed = path.strip_prefix('/').unwrap_or(path);
        let (bucket_part, remainder) = trimmed.split_once('/').unwrap_or((trimmed, ""));
        let endpoint = state.config.backend_endpoint.trim_end_matches('/');
        // Insert bucket as a subdomain: https://bucket.host/key
        let virtual_url = if let Some(stripped) = endpoint.strip_prefix("https://") {
            format!("https://{bucket_part}.{stripped}/{remainder}")
        } else if let Some(stripped) = endpoint.strip_prefix("http://") {
            format!("http://{bucket_part}.{stripped}/{remainder}")
        } else {
            // Fallback to path-style if scheme is unrecognized
            format!("{endpoint}{path}")
        };
        match query {
            Some(q) if !q.is_empty() => format!("{virtual_url}?{q}"),
            _ => virtual_url,
        }
    } else {
        let backend_endpoint = state.config.backend_endpoint.trim_end_matches('/');
        match query {
            Some(q) if !q.is_empty() => format!("{backend_endpoint}{path}?{q}"),
            _ => format!("{backend_endpoint}{path}"),
        }
    };

    tracing::info!(
        request_id = %request_id,
        method = %method,
        path = %path,
        "passthrough: proxying unsupported operation to backend"
    );

    // 2. Determine retry strategy BEFORE reading the body so we know whether
    //    to buffer (needed for retries) or stream (avoids buffering large uploads).
    // Idempotent methods (GET, HEAD, DELETE) are retried on transport errors
    // and retryable status codes, using the same config-driven attempt counts
    // and backoff as the typed backend path. Non-idempotent methods are sent
    // once to avoid duplicate side effects.
    let (is_idempotent, max_attempts, base_backoff_ms) = match method {
        "GET" => (
            true,
            state.config.get_max_attempts.max(1),
            state.config.retry_base_backoff_ms,
        ),
        "HEAD" => (
            true,
            state.config.head_max_attempts.max(1),
            state.config.retry_base_backoff_ms,
        ),
        "DELETE" => (
            true,
            state.config.delete_max_attempts.max(1),
            state.config.retry_base_backoff_ms,
        ),
        _ => (false, 1, 0),
    };

    let unsigned_payload = state.config.passthrough_unsigned_payload;
    // Buffer the body when payload signing requires the bytes, OR we may
    // retry (idempotent methods need the body available for each attempt).
    let needs_buffer = !unsigned_payload || is_idempotent;

    // 3. Conditionally buffer the body or keep it as a stream.
    let (body_bytes, stream_body) = if needs_buffer {
        let bytes =
            match axum::body::to_bytes(body, state.config.max_request_body_bytes as usize).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(error = %e, "passthrough: failed to read request body");
                    let s3err = S3Error::from_body_error(&e, request_id);
                    return s3err.to_response();
                }
            };
        (Some(bytes), None)
    } else {
        // Non-retryable + unsigned payload: stream directly, no buffering.
        (None, Some(body))
    };

    // 4. Build "base headers" for signing — filtered original headers without
    //    auth/hop-by-hop headers. These don't change across retry attempts.
    let mut base_headers = http::HeaderMap::new();
    let connection_nominated = collect_connection_nominated(original_headers);
    for (name, value) in original_headers {
        let name_str = name.as_str();
        if SKIP_REQUEST_HEADERS.contains(&name_str)
            || HOP_BY_HOP_HEADERS.contains(&name_str)
            || connection_nominated.iter().any(|h| h == name_str)
        {
            continue;
        }
        base_headers.append(name.clone(), value.clone());
    }

    // 5. Prepare credentials and signing settings outside the loop (they don't change).
    let credentials = Credentials::new(
        &state.config.backend_access_key_id,
        &state.config.backend_secret_access_key,
        None,
        None,
        "tiny-s3-proxy-passthrough",
    );
    let identity = credentials.into();

    // S3-specific signing settings:
    // - Single URI-encoding: S3 does NOT double-encode, unlike generic SigV4.
    //   The URI we sign is already percent-encoded from the client request, so
    //   we must not re-encode it during canonicalization.
    // - No path normalization: preserve // and . segments in object keys.
    // - Payload checksum: include x-amz-content-sha256 header as S3 requires.
    let mut signing_settings = SigningSettings::default();
    signing_settings.percent_encoding_mode = aws_sigv4::http_request::PercentEncodingMode::Single;
    signing_settings.uri_path_normalization_mode =
        aws_sigv4::http_request::UriPathNormalizationMode::Disabled;
    signing_settings.payload_checksum_kind =
        aws_sigv4::http_request::PayloadChecksumKind::XAmzSha256;

    // 6. Pre-compute the payload hash once. It does not change across retry
    //    attempts (the body bytes are buffered), so re-hashing per attempt
    //    would be wasted CPU. For UNSIGNED-PAYLOAD the literal sentinel is
    //    used; for the streaming path the signer emits the same sentinel via
    //    SignableBody::UnsignedPayload directly.
    let precomputed_payload_hash: Option<String> = match (body_bytes.as_ref(), unsigned_payload) {
        (Some(bytes), false) => Some(sha256_hex(bytes.as_ref())),
        _ => None,
    };

    let reqwest_method = match reqwest::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            let s3err = S3Error::not_implemented(method, request_id);
            return s3err.to_response();
        }
    };

    // 7. Send the request via reqwest (reuse client from AppState).
    //    Two send paths:
    //    - Buffered: body_bytes is Some → retry loop with O(1) Bytes::clone.
    //    - Streaming: stream_body is Some → single attempt, body streamed
    //      directly. The streaming path is only taken for non-retryable
    //      methods with unsigned payload, so a retry loop is not applicable.
    let upstream_resp = if let Some(body_bytes) = body_bytes {
        // -- Buffered path (retryable or signed-payload) --
        let mut last_err = None;
        let mut resp = None;
        for attempt in 1..=max_attempts {
            // Re-sign on every attempt so that x-amz-date and the authorization
            // header reflect the current wall-clock time. Without this, retries
            // after backoff can fail with stale-signature errors.
            let signing_params = match SigningParams::builder()
                .identity(&identity)
                .region(&state.config.backend_region)
                .name("s3")
                .time(now())
                .settings(signing_settings.clone())
                .build()
            {
                Ok(params) => params,
                Err(e) => {
                    tracing::error!(error = %e, "passthrough: failed to build signing params");
                    let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                    return s3err.to_response();
                }
            };

            // Build a fresh http::Request from the base headers for signing.
            let mut sign_req_builder = http::Request::builder().method(method).uri(&upstream_url);
            for (name, value) in &base_headers {
                sign_req_builder = sign_req_builder.header(name, value);
            }
            let mut signable_request = match sign_req_builder.body(()) {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!(error = %e, "passthrough: failed to build signable request");
                    let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                    return s3err.to_response();
                }
            };

            let signable_body = if unsigned_payload {
                SignableBody::UnsignedPayload
            } else {
                SignableBody::Precomputed(
                    precomputed_payload_hash
                        .as_ref()
                        .expect("payload hash precomputed when payload is signed")
                        .clone(),
                )
            };
            let signable = match SignableRequest::new(
                signable_request.method().as_str(),
                signable_request.uri().to_string(),
                signable_request
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap_or(""))),
                signable_body,
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "passthrough: failed to create signable request");
                    let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                    return s3err.to_response();
                }
            };

            let (signing_instructions, _signature) = match sign(signable, &signing_params.into()) {
                Ok(output) => output.into_parts(),
                Err(e) => {
                    tracing::error!(error = %e, "passthrough: failed to sign request");
                    let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                    return s3err.to_response();
                }
            };

            // Apply signing instructions (adds Authorization, x-amz-date, etc.).
            signing_instructions.apply_to_request_http1x(&mut signable_request);

            let mut req_builder = state
                .http_client
                .request(reqwest_method.clone(), &upstream_url);
            for (name, value) in signable_request.headers() {
                if let Ok(v) = value.to_str() {
                    req_builder = req_builder.header(name.as_str(), v);
                }
            }
            // Bytes clone is O(1) (reference-counted), safe for retries.
            if !body_bytes.is_empty() {
                req_builder = req_builder.body(body_bytes.clone());
            }

            match req_builder.send().await {
                Ok(r) => {
                    // Retry on retryable status codes for idempotent methods.
                    let status = r.status().as_u16();
                    if is_idempotent
                        && attempt < max_attempts
                        && matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
                    {
                        let delay = base_backoff_ms
                            .saturating_mul(2u64.saturating_pow(attempt - 1))
                            .min(30_000);
                        tracing::warn!(
                            status,
                            attempt,
                            max_attempts,
                            delay_ms = delay,
                            "passthrough: retrying idempotent request on retryable status"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        continue;
                    }
                    resp = Some(r);
                    break;
                }
                Err(e) => {
                    if attempt < max_attempts {
                        let delay = base_backoff_ms
                            .saturating_mul(2u64.saturating_pow(attempt - 1))
                            .min(30_000);
                        tracing::warn!(
                            error = %e,
                            attempt,
                            max_attempts,
                            delay_ms = delay,
                            "passthrough: retrying idempotent request"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                    last_err = Some(e);
                }
            }
        }

        match resp {
            Some(r) => r,
            None => {
                let e = last_err.unwrap();
                tracing::error!(error = %e, "passthrough: upstream request failed after {max_attempts} attempts");
                let proxy_err = if e.is_timeout() {
                    crate::error::ProxyError::Timeout {
                        operation: "passthrough".into(),
                    }
                } else {
                    crate::error::ProxyError::Backend {
                        source: format!("{e}").into(),
                        operation: "passthrough".into(),
                    }
                };
                let s3err = S3Error::from_proxy_error(&proxy_err, request_id, None);
                return s3err.to_response();
            }
        }
    } else {
        // -- Streaming path (unsigned payload, non-retryable) --
        let stream_body = stream_body.expect("stream_body must be Some when body_bytes is None");

        let signing_params = match SigningParams::builder()
            .identity(&identity)
            .region(&state.config.backend_region)
            .name("s3")
            .time(now())
            .settings(signing_settings.clone())
            .build()
        {
            Ok(params) => params,
            Err(e) => {
                tracing::error!(error = %e, "passthrough: failed to build signing params");
                let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                return s3err.to_response();
            }
        };

        let mut sign_req_builder = http::Request::builder().method(method).uri(&upstream_url);
        for (name, value) in &base_headers {
            sign_req_builder = sign_req_builder.header(name, value);
        }
        let mut signable_request = match sign_req_builder.body(()) {
            Ok(req) => req,
            Err(e) => {
                tracing::error!(error = %e, "passthrough: failed to build signable request");
                let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                return s3err.to_response();
            }
        };

        let signable = match SignableRequest::new(
            signable_request.method().as_str(),
            signable_request.uri().to_string(),
            signable_request
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap_or(""))),
            SignableBody::UnsignedPayload,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "passthrough: failed to create signable request");
                let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                return s3err.to_response();
            }
        };

        let (signing_instructions, _signature) = match sign(signable, &signing_params.into()) {
            Ok(output) => output.into_parts(),
            Err(e) => {
                tracing::error!(error = %e, "passthrough: failed to sign request");
                let s3err = S3Error::internal_error("An internal error occurred.", request_id);
                return s3err.to_response();
            }
        };

        signing_instructions.apply_to_request_http1x(&mut signable_request);

        let mut req_builder = state.http_client.request(reqwest_method, &upstream_url);
        for (name, value) in signable_request.headers() {
            if let Ok(v) = value.to_str() {
                req_builder = req_builder.header(name.as_str(), v);
            }
        }
        req_builder = req_builder.body(reqwest::Body::wrap_stream(stream_body.into_data_stream()));

        match req_builder.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "passthrough: streaming upstream request failed");
                let proxy_err = if e.is_timeout() {
                    crate::error::ProxyError::Timeout {
                        operation: "passthrough".into(),
                    }
                } else {
                    crate::error::ProxyError::Backend {
                        source: format!("{e}").into(),
                        operation: "passthrough".into(),
                    }
                };
                let s3err = S3Error::from_proxy_error(&proxy_err, request_id, None);
                return s3err.to_response();
            }
        }
    };

    // 6. Forward the upstream response back to the client.
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // Stream the response body.
    let body_stream = upstream_resp.bytes_stream();
    let axum_body = Body::from_stream(body_stream);

    let mut response = Response::builder().status(status.as_u16());

    // Copy upstream response headers, stripping hop-by-hop headers that
    // pertain to the proxy-to-backend connection, not the client connection.
    let resp_connection_nominated = collect_connection_nominated(&resp_headers);
    for (name, value) in &resp_headers {
        let name_lower = name.as_str();
        if HOP_BY_HOP_HEADERS.contains(&name_lower)
            || resp_connection_nominated
                .iter()
                .any(|h| h.as_str() == name_lower)
        {
            continue;
        }
        response = response.header(name, value);
    }

    // Add our proxy headers (without overwriting upstream headers).
    let common = common_headers(request_id);
    for (k, v) in common.iter() {
        // Only add if not already present from upstream.
        if !resp_headers.contains_key(k) {
            response = response.header(k, v);
        }
    }

    response.body(axum_body).unwrap_or_else(|e| {
        tracing::error!(error = %e, "passthrough: failed to build response");
        S3Error::internal_error("failed to build response", request_id).to_response()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::SingleFlight;
    use crate::cache::policy::CachePolicy;
    use crate::config::{AuthMode, Config};
    use crate::handlers::AppState;
    use crate::handlers::test_utils::*;

    use axum::body::Body;
    use axum::routing::any;
    use http::HeaderMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    /// State shared with the mock upstream server.
    struct MockUpstream {
        /// (method, uri, headers, body) for each request received.
        requests: tokio::sync::Mutex<Vec<(String, String, HeaderMap, bytes::Bytes)>>,
        /// Status code the mock will return. Can be mutated between calls.
        response_status: AtomicU32,
        /// How many times the mock has been called.
        call_count: AtomicU32,
        /// Fixed response headers to include.
        response_headers: tokio::sync::Mutex<Vec<(String, String)>>,
    }

    impl MockUpstream {
        fn new(status: u16) -> Arc<Self> {
            Arc::new(Self {
                requests: tokio::sync::Mutex::new(Vec::new()),
                response_status: AtomicU32::new(status as u32),
                call_count: AtomicU32::new(0),
                response_headers: tokio::sync::Mutex::new(Vec::new()),
            })
        }
    }

    /// Spin up a mock upstream HTTP server. Returns (address, mock_state).
    async fn start_mock_upstream(mock: Arc<MockUpstream>) -> String {
        let app = axum::Router::new()
            .route("/{*path}", any(mock_handler))
            .route("/", any(mock_handler))
            .with_state(mock.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{}", addr)
    }

    async fn mock_handler(
        axum::extract::State(state): axum::extract::State<Arc<MockUpstream>>,
        req: http::Request<Body>,
    ) -> http::Response<Body> {
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        let headers = req.headers().clone();
        let body_bytes = axum::body::to_bytes(req.into_body(), 64 * 1024 * 1024)
            .await
            .unwrap_or_default();
        state
            .requests
            .lock()
            .await
            .push((method, uri, headers, body_bytes));
        let count = state.call_count.fetch_add(1, Ordering::SeqCst);

        let status = state.response_status.load(Ordering::SeqCst);
        let resp_headers = state.response_headers.lock().await;

        let mut builder = http::Response::builder().status(status as u16);
        for (k, v) in resp_headers.iter() {
            builder = builder.header(k.as_str(), v.as_str());
        }
        // Include the call count in a custom header for test inspection.
        builder = builder.header("x-mock-call-count", (count + 1).to_string());
        builder.body(Body::from("mock response")).unwrap()
    }

    fn test_config_for_passthrough(endpoint: &str) -> Config {
        Config {
            s3_listen_addr: "0.0.0.0:8080".to_string(),
            admin_listen_addr: "0.0.0.0:9090".to_string(),
            frontend_bucket: "test-frontend".to_string(),
            auth_mode: AuthMode::TrustedInternal,
            allowed_frontend_keys: vec![],
            backend_endpoint: endpoint.to_string(),
            backend_region: "us-east-1".to_string(),
            backend_bucket: "test-backend".to_string(),
            backend_access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            backend_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            backend_use_path_style: true,
            backend_allow_http: true,
            cache_dir: "/tmp/test-cache".to_string(),
            cache_max_bytes: 1024 * 1024,
            cache_max_object_bytes: 512 * 1024,
            cacheable_prefixes: vec![],
            cache_serve_stale_on_error: false,
            cache_eviction_interval_secs: 300,
            get_max_attempts: 1,
            head_max_attempts: 1,
            list_max_attempts: 1,
            put_max_attempts: 1,
            delete_max_attempts: 1,
            retry_base_backoff_ms: 1, // tiny backoff for fast tests
            upstream_connect_timeout_ms: 5000,
            upstream_request_timeout_ms: 30000,
            max_request_body_bytes: 268_435_456,
            passthrough_unsigned_payload: false,
        }
    }

    fn build_passthrough_state(config: Config) -> Arc<AppState<MockBackend, MockCache>> {
        let cache = MockCache::new();
        Arc::new(AppState {
            backend: Arc::new(MockBackend::new()),
            cache: Arc::new(cache),
            singleflight: Arc::new(SingleFlight::new()),
            auth: Arc::new(MockAuth::allow_all()),
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

    // ---- URL construction (path-style) ----
    #[tokio::test]
    async fn test_url_construction_path_style() {
        let mock = MockUpstream::new(200);
        let addr = start_mock_upstream(mock.clone()).await;

        let config = test_config_for_passthrough(&addr);
        let state = build_passthrough_state(config);

        let headers = HeaderMap::new();
        let _resp = handle_passthrough(
            &state,
            "GET",
            "/test-backend/key",
            Some("list-type=2"),
            &headers,
            Body::empty(),
            "req-1",
        )
        .await;

        let reqs = mock.requests.lock().await;
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].1, "/test-backend/key?list-type=2");
    }

    // ---- URL construction (virtual-hosted-style) ----
    #[tokio::test]
    async fn test_url_construction_virtual_hosted_style() {
        // Virtual-hosted style rewrites bucket to subdomain.
        // DNS won't resolve bucket.127.0.0.1, so expect a connection error
        // (ProxyError::Backend), not an internal error.
        let mut config = test_config_for_passthrough("http://127.0.0.1:19999");
        config.backend_use_path_style = false;
        let state = build_passthrough_state(config);

        let headers = HeaderMap::new();
        let resp = handle_passthrough(
            &state,
            "GET",
            "/mybucket/mykey",
            None,
            &headers,
            Body::empty(),
            "req-vh",
        )
        .await;

        // Should be a backend error (502 Bad Gateway) — not 500 Internal.
        assert_eq!(resp.status(), 502);
    }

    // ---- Header stripping: auth/hop-by-hop headers not forwarded to upstream ----
    #[tokio::test]
    async fn test_header_stripping_on_upstream_request() {
        let mock = MockUpstream::new(200);
        let addr = start_mock_upstream(mock.clone()).await;

        let config = test_config_for_passthrough(&addr);
        let state = build_passthrough_state(config);

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "AWS4-HMAC-SHA256 old".parse().unwrap());
        headers.insert("x-amz-date", "20250101T000000Z".parse().unwrap());
        headers.insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
        headers.insert("host", "frontend.example.com".parse().unwrap());
        headers.insert("connection", "keep-alive, x-custom-hop".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        headers.insert("proxy-authorization", "Basic abc".parse().unwrap());
        headers.insert("x-custom-hop", "should-be-stripped".parse().unwrap());
        // Also add a normal header that SHOULD be forwarded.
        headers.insert("x-custom-normal", "should-pass".parse().unwrap());

        let _resp = handle_passthrough(
            &state,
            "GET",
            "/test-backend/key",
            None,
            &headers,
            Body::empty(),
            "req-strip",
        )
        .await;

        let reqs = mock.requests.lock().await;
        assert_eq!(reqs.len(), 1);
        let upstream_headers = &reqs[0].2;

        // These must NOT appear in what the upstream receives.
        assert!(
            !upstream_headers.contains_key("x-custom-hop"),
            "connection-nominated header x-custom-hop should be stripped"
        );
        assert!(
            !upstream_headers.contains_key("keep-alive"),
            "hop-by-hop header keep-alive should be stripped"
        );
        assert!(
            !upstream_headers.contains_key("transfer-encoding"),
            "hop-by-hop header transfer-encoding should be stripped"
        );
        assert!(
            !upstream_headers.contains_key("proxy-authorization"),
            "hop-by-hop header proxy-authorization should be stripped"
        );
        assert!(
            !upstream_headers.contains_key("connection"),
            "hop-by-hop header connection should be stripped"
        );

        // Normal header should pass through.
        assert_eq!(
            upstream_headers.get("x-custom-normal").unwrap(),
            "should-pass"
        );
    }

    // ---- SigV4 headers added to upstream request ----
    #[tokio::test]
    async fn test_sigv4_headers_added() {
        let mock = MockUpstream::new(200);
        let addr = start_mock_upstream(mock.clone()).await;

        let config = test_config_for_passthrough(&addr);
        let state = build_passthrough_state(config);

        let headers = HeaderMap::new();
        let _resp = handle_passthrough(
            &state,
            "GET",
            "/test-backend/key",
            None,
            &headers,
            Body::empty(),
            "req-sig",
        )
        .await;

        let reqs = mock.requests.lock().await;
        assert_eq!(reqs.len(), 1);
        let upstream_headers = &reqs[0].2;

        let auth = upstream_headers
            .get("authorization")
            .expect("authorization header must be present")
            .to_str()
            .unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256"),
            "authorization should start with AWS4-HMAC-SHA256, got: {auth}"
        );

        assert!(
            upstream_headers.contains_key("x-amz-date"),
            "x-amz-date header must be present"
        );
        assert!(
            upstream_headers.contains_key("x-amz-content-sha256"),
            "x-amz-content-sha256 header must be present"
        );
    }

    // ---- Response hop-by-hop header stripping ----
    #[tokio::test]
    async fn test_response_hop_by_hop_stripping() {
        let mock = MockUpstream::new(200);
        {
            let mut rh = mock.response_headers.lock().await;
            // Note: we do NOT set transfer-encoding manually because hyper
            // manages HTTP framing headers itself; manually setting it creates
            // a malformed response. The passthrough handler still strips
            // transfer-encoding from whatever reqwest reports in the response.
            rh.push(("connection".to_string(), "keep-alive".to_string()));
            rh.push(("keep-alive".to_string(), "timeout=5".to_string()));
            rh.push(("content-type".to_string(), "application/xml".to_string()));
            rh.push(("etag".to_string(), "\"abc123\"".to_string()));
            rh.push(("x-amz-version-id".to_string(), "v1".to_string()));
        }
        let addr = start_mock_upstream(mock.clone()).await;

        let config = test_config_for_passthrough(&addr);
        let state = build_passthrough_state(config);

        let headers = HeaderMap::new();
        let resp = handle_passthrough(
            &state,
            "GET",
            "/test-backend/key",
            None,
            &headers,
            Body::empty(),
            "req-resp-hop",
        )
        .await;

        // Hop-by-hop headers should NOT be in the response.
        assert!(
            !resp.headers().contains_key("transfer-encoding"),
            "transfer-encoding should be stripped from response"
        );
        assert!(
            !resp.headers().contains_key("keep-alive"),
            "keep-alive should be stripped from response"
        );
        assert!(
            !resp.headers().contains_key("connection"),
            "connection should be stripped from response"
        );

        // Normal headers SHOULD be in the response.
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/xml"
        );
        assert_eq!(resp.headers().get("etag").unwrap(), "\"abc123\"");
        assert_eq!(resp.headers().get("x-amz-version-id").unwrap(), "v1");
    }

    // ---- Retry on 503 for GET ----
    #[tokio::test]
    async fn test_retry_on_503_for_get() {
        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        // Custom handler that returns 503 twice then 200.
        let app = axum::Router::new().route(
            "/{*path}",
            any(move |_req: http::Request<Body>| {
                let cc = call_count_clone.clone();
                async move {
                    let count = cc.fetch_add(1, Ordering::SeqCst);
                    let status = if count < 2 { 503u16 } else { 200u16 };
                    http::Response::builder()
                        .status(status)
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

        let mut config = test_config_for_passthrough(&format!("http://{}", addr));
        config.get_max_attempts = 3;

        let state = build_passthrough_state(config);
        let headers = HeaderMap::new();

        let resp = handle_passthrough(
            &state,
            "GET",
            "/test-backend/key",
            None,
            &headers,
            Body::empty(),
            "req-retry",
        )
        .await;

        assert_eq!(resp.status(), 200);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    // ---- No retry for POST on 503 ----
    #[tokio::test]
    async fn test_no_retry_for_post_on_503() {
        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let app = axum::Router::new().route(
            "/{*path}",
            any(move |_req: http::Request<Body>| {
                let cc = call_count_clone.clone();
                async move {
                    cc.fetch_add(1, Ordering::SeqCst);
                    http::Response::builder()
                        .status(503u16)
                        .body(Body::from("service unavailable"))
                        .unwrap()
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = test_config_for_passthrough(&format!("http://{}", addr));
        config.get_max_attempts = 3; // would retry for GET, but not POST

        let state = build_passthrough_state(config);
        let headers = HeaderMap::new();

        let resp = handle_passthrough(
            &state,
            "POST",
            "/test-backend/key",
            None,
            &headers,
            Body::empty(),
            "req-no-retry",
        )
        .await;

        assert_eq!(resp.status(), 503);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "POST should not retry"
        );
    }

    // ---- Retry re-signs with fresh timestamp ----
    #[tokio::test]
    async fn test_retry_resigns_with_fresh_timestamp() {
        // Custom handler: 503 on first call, 200 on second. Records headers.
        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();
        let requests_for_handler: Arc<tokio::sync::Mutex<Vec<(String, String, HeaderMap)>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let requests_clone = requests_for_handler.clone();

        let app = axum::Router::new().route(
            "/{*path}",
            any(move |req: http::Request<Body>| {
                let cc = call_count_clone.clone();
                let reqs = requests_clone.clone();
                async move {
                    let method = req.method().to_string();
                    let uri = req.uri().to_string();
                    let headers = req.headers().clone();
                    reqs.lock().await.push((method, uri, headers));

                    let count = cc.fetch_add(1, Ordering::SeqCst);
                    let status = if count == 0 { 503u16 } else { 200u16 };
                    http::Response::builder()
                        .status(status)
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

        let mut config = test_config_for_passthrough(&format!("http://{}", addr));
        config.get_max_attempts = 2;
        config.retry_base_backoff_ms = 1; // minimal backoff for test speed

        let state = build_passthrough_state(config);
        let headers = HeaderMap::new();

        // Inject a deterministic clock that advances by 2 seconds between
        // calls, guaranteeing each retry's signing timestamp lands in a
        // different SigV4 second. Without this, both attempts could share a
        // wall-clock second and produce identical Authorization/x-amz-date,
        // letting the test pass even if production reverted to one-time
        // pre-loop signing.
        let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock_calls = Arc::new(std::sync::Mutex::new(0u32));
        let clock = {
            let clock_calls = clock_calls.clone();
            move || {
                let mut n = clock_calls.lock().unwrap();
                let t = base_time + Duration::from_secs(u64::from(*n) * 2);
                *n += 1;
                t
            }
        };

        let resp = handle_passthrough_with_clock(
            &state,
            "GET",
            "/test-backend/key",
            None,
            &headers,
            Body::empty(),
            "req-resign",
            clock,
        )
        .await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "should have made 2 attempts"
        );

        let reqs = requests_for_handler.lock().await;
        assert_eq!(reqs.len(), 2, "mock should have recorded 2 requests");

        // Both requests must have authorization and x-amz-date headers.
        for (i, (_method, _uri, hdrs)) in reqs.iter().enumerate() {
            let auth = hdrs
                .get("authorization")
                .unwrap_or_else(|| {
                    panic!("attempt {}: authorization header must be present", i + 1)
                })
                .to_str()
                .unwrap();
            assert!(
                auth.starts_with("AWS4-HMAC-SHA256"),
                "attempt {}: authorization should start with AWS4-HMAC-SHA256, got: {auth}",
                i + 1
            );
            assert!(
                hdrs.contains_key("x-amz-date"),
                "attempt {}: x-amz-date header must be present",
                i + 1
            );
        }

        // Verify both have valid x-amz-date format (YYYYMMDDTHHMMSSZ).
        let date1 = reqs[0].2.get("x-amz-date").unwrap().to_str().unwrap();
        let date2 = reqs[1].2.get("x-amz-date").unwrap().to_str().unwrap();
        assert_eq!(date1.len(), 16, "x-amz-date should be 16 chars: {date1}");
        assert_eq!(date2.len(), 16, "x-amz-date should be 16 chars: {date2}");
        assert!(
            date1.ends_with('Z'),
            "x-amz-date should end with Z: {date1}"
        );
        assert!(
            date2.ends_with('Z'),
            "x-amz-date should end with Z: {date2}"
        );

        let auth1 = reqs[0].2.get("authorization").unwrap().to_str().unwrap();
        let auth2 = reqs[1].2.get("authorization").unwrap().to_str().unwrap();
        assert!(
            auth1.contains("Credential="),
            "first auth missing Credential"
        );
        assert!(
            auth2.contains("Credential="),
            "second auth missing Credential"
        );
        assert!(auth1.contains("Signature="), "first auth missing Signature");
        assert!(
            auth2.contains("Signature="),
            "second auth missing Signature"
        );

        // The injected clock advances by 2s per call, so the two attempts
        // must produce distinct timestamps. If signing were lifted out of
        // the retry loop (the bug), both attempts would carry the SAME
        // x-amz-date and Signature.
        assert_ne!(date1, date2, "retry must be signed with a fresh x-amz-date");
        assert_ne!(
            auth1, auth2,
            "retry must be signed with a fresh Authorization signature"
        );
    }

    // ---- UNSIGNED-PAYLOAD header set for GET when enabled ----
    #[tokio::test]
    async fn test_unsigned_payload_header_set() {
        let mock = MockUpstream::new(200);
        let addr = start_mock_upstream(mock.clone()).await;

        let mut config = test_config_for_passthrough(&addr);
        config.passthrough_unsigned_payload = true;
        let state = build_passthrough_state(config);

        let headers = HeaderMap::new();
        let resp = handle_passthrough(
            &state,
            "GET",
            "/test-backend/key",
            None,
            &headers,
            Body::empty(),
            "req-unsigned",
        )
        .await;

        assert_eq!(resp.status(), 200);

        let reqs = mock.requests.lock().await;
        assert_eq!(reqs.len(), 1);
        let upstream_headers = &reqs[0].2;
        let sha_header = upstream_headers
            .get("x-amz-content-sha256")
            .expect("x-amz-content-sha256 header must be present")
            .to_str()
            .unwrap();
        assert_eq!(
            sha_header, "UNSIGNED-PAYLOAD",
            "expected UNSIGNED-PAYLOAD, got: {sha_header}"
        );
    }

    // ---- UNSIGNED-PAYLOAD streaming PUT ----
    #[tokio::test]
    async fn test_unsigned_payload_streaming_put() {
        let mock = MockUpstream::new(200);
        let addr = start_mock_upstream(mock.clone()).await;

        let mut config = test_config_for_passthrough(&addr);
        config.passthrough_unsigned_payload = true;
        let state = build_passthrough_state(config);

        let payload = b"hello streaming world";
        let headers = HeaderMap::new();
        let resp = handle_passthrough(
            &state,
            "PUT",
            "/test-backend/upload-key",
            None,
            &headers,
            Body::from(&payload[..]),
            "req-unsigned-put",
        )
        .await;

        assert_eq!(resp.status(), 200);

        let reqs = mock.requests.lock().await;
        assert_eq!(reqs.len(), 1);

        // Verify the upstream received the body.
        let upstream_body = &reqs[0].3;
        assert_eq!(
            upstream_body.as_ref(),
            payload,
            "upstream should receive the full body"
        );

        // Verify UNSIGNED-PAYLOAD header.
        let upstream_headers = &reqs[0].2;
        let sha_header = upstream_headers
            .get("x-amz-content-sha256")
            .expect("x-amz-content-sha256 header must be present")
            .to_str()
            .unwrap();
        assert_eq!(
            sha_header, "UNSIGNED-PAYLOAD",
            "expected UNSIGNED-PAYLOAD, got: {sha_header}"
        );
    }
}
