use std::sync::Arc;
use std::time::SystemTime;

use axum::body::Body;
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, SignableBody, SignableRequest, SigningSettings,
};
use aws_sigv4::sign::v4::SigningParams;
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
pub async fn handle_passthrough<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    method: &str,
    path: &str,
    query: Option<&str>,
    original_headers: &http::HeaderMap,
    body: Body,
    request_id: &str,
) -> Response<Body> {
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

    // 2. Read the body bytes (needed for signing and forwarding).
    let body_bytes = match axum::body::to_bytes(body, state.config.max_request_body_bytes as usize).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(error = %e, "passthrough: failed to read request body");
            let s3err = S3Error::from_body_error(&e, request_id);
            return s3err.to_response();
        }
    };

    // 3. Build an http::Request for signing.
    let mut req_builder = http::Request::builder()
        .method(method)
        .uri(&upstream_url);

    // Copy headers from the original request, stripping SigV4/auth headers,
    // standard hop-by-hop headers, and any headers nominated by Connection.
    let connection_nominated = collect_connection_nominated(original_headers);
    for (name, value) in original_headers {
        let name_lower = name.as_str().to_lowercase();
        if SKIP_REQUEST_HEADERS.contains(&name_lower.as_str())
            || HOP_BY_HOP_HEADERS.contains(&name_lower.as_str())
            || connection_nominated.iter().any(|h| h == &name_lower)
        {
            continue;
        }
        req_builder = req_builder.header(name, value);
    }

    let mut signable_request = match req_builder.body(()) {
        Ok(req) => req,
        Err(e) => {
            tracing::error!(error = %e, "passthrough: failed to build signable request");
            let s3err = S3Error::internal_error(
                &format!("request build error: {}", e),
                request_id,
            );
            return s3err.to_response();
        }
    };

    // 4. Sign the request with AWS SigV4 using backend credentials.
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
    signing_settings.percent_encoding_mode =
        aws_sigv4::http_request::PercentEncodingMode::Single;
    signing_settings.uri_path_normalization_mode =
        aws_sigv4::http_request::UriPathNormalizationMode::Disabled;
    signing_settings.payload_checksum_kind =
        aws_sigv4::http_request::PayloadChecksumKind::XAmzSha256;
    let signing_params = match SigningParams::builder()
        .identity(&identity)
        .region(&state.config.backend_region)
        .name("s3")
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()
    {
        Ok(params) => params,
        Err(e) => {
            tracing::error!(error = %e, "passthrough: failed to build signing params");
            let s3err = S3Error::internal_error(
                &format!("signing error: {}", e),
                request_id,
            );
            return s3err.to_response();
        }
    };

    let signable_body = SignableBody::Bytes(body_bytes.as_ref());
    let signable = match SignableRequest::new(
        signable_request.method().as_str(),
        signable_request.uri().to_string(),
        signable_request.headers().iter().map(|(k, v)| {
            (k.as_str(), std::str::from_utf8(v.as_bytes()).unwrap_or(""))
        }),
        signable_body,
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "passthrough: failed to create signable request");
            let s3err = S3Error::internal_error(
                &format!("signing error: {}", e),
                request_id,
            );
            return s3err.to_response();
        }
    };

    let (signing_instructions, _signature) = match sign(signable, &signing_params.into()) {
        Ok(output) => output.into_parts(),
        Err(e) => {
            tracing::error!(error = %e, "passthrough: failed to sign request");
            let s3err = S3Error::internal_error(
                &format!("signing error: {}", e),
                request_id,
            );
            return s3err.to_response();
        }
    };

    // Apply signing instructions (adds Authorization, x-amz-date, etc.).
    signing_instructions.apply_to_request_http1x(&mut signable_request);

    // 5. Send the request via reqwest (reuse client from AppState).
    // Idempotent methods (GET, HEAD, DELETE) are retried on transport errors
    // and retryable status codes, using the same config-driven attempt counts
    // and backoff as the typed backend path. Non-idempotent methods are sent
    // once to avoid duplicate side effects.
    let (is_idempotent, max_attempts, base_backoff_ms) = match method {
        "GET" => (true, state.config.get_max_attempts.max(1), state.config.retry_base_backoff_ms),
        "HEAD" => (true, state.config.head_max_attempts.max(1), state.config.retry_base_backoff_ms),
        "DELETE" => (true, state.config.delete_max_attempts.max(1), state.config.retry_base_backoff_ms),
        _ => (false, 1, 0),
    };

    let mut last_err = None;
    let mut upstream_resp = None;
    for attempt in 1..=max_attempts {
        let mut req_builder = state.http_client.request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
            &upstream_url,
        );
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
            Ok(resp) => {
                // Retry on retryable status codes for idempotent methods.
                let status = resp.status().as_u16();
                if is_idempotent
                    && attempt < max_attempts
                    && matches!(status, 408 | 429 | 500 | 502 | 503 | 504)
                {
                    let delay = base_backoff_ms.saturating_mul(2u64.saturating_pow(attempt - 1)).min(30_000);
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
                upstream_resp = Some(resp);
                break;
            }
            Err(e) => {
                if attempt < max_attempts {
                    let delay = base_backoff_ms.saturating_mul(2u64.saturating_pow(attempt - 1)).min(30_000);
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

    let upstream_resp = match upstream_resp {
        Some(resp) => resp,
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
            || resp_connection_nominated.iter().any(|h| h.as_str() == name_lower)
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
