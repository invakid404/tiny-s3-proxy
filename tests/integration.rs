//! Integration tests for tiny-s3-proxy.
//!
//! These tests spin up a VersityGW container (S3-compatible backend) via
//! testcontainers, build the full proxy stack, and exercise end-to-end
//! S3 operations through the proxy.
//!
//! Requirements:
//!   - Docker must be running
//!   - The `versity/versitygw:latest` image must be pullable
//!
//! Run with: `cargo test -- --ignored`

use std::sync::Arc;

use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use tiny_s3_proxy::auth;
use tiny_s3_proxy::backend;
use tiny_s3_proxy::cache;
use tiny_s3_proxy::config::{AuthMode, Config};
use tiny_s3_proxy::handlers;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

const TEST_ACCESS_KEY: &str = "testuser";
const TEST_SECRET_KEY: &str = "secret";
const TEST_BUCKET: &str = "test-bucket";

/// Start a VersityGW container and return it along with the endpoint URL.
async fn start_versitygw() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    // NOTE: GenericImage methods (with_entrypoint, with_exposed_port, with_wait_for)
    // must be called before ImageExt methods (with_env_var, with_cmd) since the
    // latter consume the GenericImage into ContainerRequest.
    // Pinned to a specific digest for reproducible CI.
    let container = GenericImage::new(
        "versity/versitygw",
        "latest@sha256:a86791b684a1dd3c5a255ca755bb51783a72696cf1b5a843f800b08bfd6f921c",
    )
    .with_entrypoint("sh")
    .with_exposed_port(10000.into())
    .with_wait_for(WaitFor::message_on_stdout("listening on"))
    .with_env_var("ROOT_ACCESS_KEY", TEST_ACCESS_KEY)
    .with_env_var("ROOT_SECRET_KEY", TEST_SECRET_KEY)
    .with_cmd([
        "-c",
        "mkdir -p /tmp/data /tmp/iam && versitygw --port :10000 --iam-dir /tmp/iam posix /tmp/data",
    ])
    .start()
    .await
    .expect("Failed to start VersityGW container");

    let port = container.get_host_port_ipv4(10000).await.unwrap();
    let endpoint = format!("http://127.0.0.1:{}", port);
    (container, endpoint)
}

/// Build a raw S3 client pointed at the given endpoint.
async fn build_raw_s3_client(
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
) -> aws_sdk_s3::Client {
    let creds = aws_credential_types::Credentials::new(access_key, secret_key, None, None, "test");
    let config = aws_sdk_s3::config::Builder::new()
        .endpoint_url(endpoint)
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(creds)
        .force_path_style(true)
        .behavior_version_latest()
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

/// Build the default test `Config` aimed at `backend_endpoint`, using the
/// given auth mode / allowed keys and rooting the cache at `cache_dir`. Pulled
/// out so tests that need a non-default Config (e.g. a small
/// `max_request_body_bytes`, or `passthrough_unsigned_payload`) can start from
/// this baseline and mutate via `build_proxy_stack_with_opts`.
fn default_proxy_test_config(
    backend_endpoint: &str,
    auth_mode: AuthMode,
    allowed_keys: Vec<String>,
    cache_dir: &std::path::Path,
) -> Config {
    Config {
        s3_listen_addr: "127.0.0.1:0".to_string(),
        admin_listen_addr: "127.0.0.1:0".to_string(),
        frontend_bucket: TEST_BUCKET.to_string(),
        auth_mode,
        allowed_frontend_keys: allowed_keys,
        backend_endpoint: backend_endpoint.to_string(),
        backend_region: "us-east-1".to_string(),
        backend_bucket: TEST_BUCKET.to_string(),
        backend_access_key_id: TEST_ACCESS_KEY.to_string(),
        backend_secret_access_key: TEST_SECRET_KEY.to_string(),
        backend_use_path_style: true,
        backend_allow_http: true,
        cache_dir: cache_dir.to_path_buf(),
        cache_max_bytes: 100 * 1024 * 1024,
        cache_max_object_bytes: 10 * 1024 * 1024,
        cacheable_prefixes: vec!["script_bundle/".into(), "bun_bundle/".into(), "tar/".into()],
        cache_serve_stale_on_error: true,
        cache_eviction_interval_secs: 3600,
        get_max_attempts: 3,
        head_max_attempts: 3,
        list_max_attempts: 3,
        put_max_attempts: 1,
        delete_max_attempts: 2,
        retry_base_backoff_ms: 50,
        upstream_connect_timeout_ms: 5000,
        upstream_request_timeout_ms: 30000,
        max_request_body_bytes: 268_435_456,
        passthrough_unsigned_payload: false,
    }
}

/// Shared proxy stack builder. `build_proxy_stack`, `build_proxy_stack_allowlist`
/// and `build_proxy_stack_with_opts` delegate here. The caller owns the
/// `cache_dir` `TempDir` (returned in the result tuple) and supplies a
/// `mutate_config` closure that can patch the default `Config` before the
/// stack is spun up. Pass an identity closure when no overrides are needed.
async fn build_proxy_stack_inner<F>(
    backend_endpoint: &str,
    auth_mode: AuthMode,
    allowed_keys: Vec<String>,
    cache_dir: tempfile::TempDir,
    mutate_config: F,
) -> (
    aws_sdk_s3::Client,
    reqwest::Client,
    String,
    tempfile::TempDir,
)
where
    F: FnOnce(&mut Config),
{
    let mut config =
        default_proxy_test_config(backend_endpoint, auth_mode, allowed_keys, cache_dir.path());
    mutate_config(&mut config);

    let s3_backend = backend::client::S3Backend::from_config(&config)
        .await
        .expect("build S3 backend");

    let cache_policy = cache::policy::CachePolicy::new(
        config.cacheable_prefixes.clone(),
        config.cache_max_object_bytes,
    );
    let disk_cache = cache::DiskCache::new(
        config.cache_dir.clone(),
        config.cache_max_bytes,
        cache_policy.clone(),
    )
    .await
    .expect("build disk cache");

    let singleflight = Arc::new(cache::SingleFlight::new());
    let authenticator = Arc::from(auth::create_request_gate(&config));

    let state = Arc::new(handlers::AppState {
        backend: Arc::new(s3_backend),
        cache: Arc::new(disk_cache),
        singleflight,
        auth: authenticator,
        policy: cache_policy,
        config: Arc::new(config),
        frontend_bucket: Arc::from(TEST_BUCKET),
        backend_bucket: Arc::from(TEST_BUCKET),
        http_client: reqwest::Client::new(),
    });

    let app = axum::Router::new()
        .fallback(handlers::handle_s3_request)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let proxy_endpoint = format!("http://127.0.0.1:{}", addr.port());
    let proxy_client = build_raw_s3_client(&proxy_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    let http_client = reqwest::Client::new();

    (proxy_client, http_client, proxy_endpoint, cache_dir)
}

async fn build_proxy_stack_allowlist(
    backend_endpoint: &str,
    allowed_keys: Vec<String>,
) -> (
    aws_sdk_s3::Client,
    reqwest::Client,
    String,
    tempfile::TempDir,
) {
    let cache_dir = tempfile::TempDir::new().expect("create temp cache dir");
    build_proxy_stack_inner(
        backend_endpoint,
        AuthMode::AccessKeyAllowlist,
        allowed_keys,
        cache_dir,
        |_cfg| {},
    )
    .await
}

async fn build_proxy_stack(
    backend_endpoint: &str,
) -> (
    aws_sdk_s3::Client,
    reqwest::Client,
    String,
    tempfile::TempDir,
) {
    let cache_dir = tempfile::TempDir::new().expect("create temp cache dir");
    build_proxy_stack_inner(
        backend_endpoint,
        AuthMode::TrustedInternal,
        vec![],
        cache_dir,
        |_cfg| {},
    )
    .await
}

/// Spin up a proxy stack with a pre-existing `cache_dir` (preplanted files
/// survive into startup) and an arbitrary `Config` override applied to the
/// default test config. Required for the startup-sweep test (preplant
/// `<cache_dir>/tmp/*.body` before `DiskCache::new`) and for tests that need
/// a tweaked `Config` (e.g. small `max_request_body_bytes`,
/// `passthrough_unsigned_payload`).
async fn build_proxy_stack_with_opts<F>(
    backend_endpoint: &str,
    cache_dir: tempfile::TempDir,
    mutate_config: F,
) -> (
    aws_sdk_s3::Client,
    reqwest::Client,
    String,
    tempfile::TempDir,
)
where
    F: FnOnce(&mut Config),
{
    build_proxy_stack_inner(
        backend_endpoint,
        AuthMode::TrustedInternal,
        vec![],
        cache_dir,
        mutate_config,
    )
    .await
}

/// Helper: PUT an object through the given S3 client.
async fn put_object(client: &aws_sdk_s3::Client, key: &str, body: &[u8]) {
    client
        .put_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .body(aws_sdk_s3::primitives::ByteStream::from(body.to_vec()))
        .send()
        .await
        .unwrap_or_else(|e| panic!("put_object({}) failed: {:?}", key, e));
}

/// Helper: GET an object via raw HTTP and return (status, body, x-cache header).
async fn raw_get_with_checksum_mode(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    key: &str,
    checksum_mode: Option<&str>,
) -> (u16, Vec<u8>, Option<String>) {
    let url = format!("{}/{}/{}", proxy_endpoint, TEST_BUCKET, key);
    let mut request = http_client.get(&url);
    if let Some(value) = checksum_mode {
        request = request.header("x-amz-checksum-mode", value);
    }
    let resp = request.send().await.expect("raw GET request failed");
    let status = resp.status().as_u16();
    let x_cache = resp
        .headers()
        .get("x-cache")
        .map(|v| v.to_str().unwrap().to_string());
    let body = resp.bytes().await.expect("read response body").to_vec();
    (status, body, x_cache)
}

/// Helper: GET an object via raw HTTP and return (status, body, x-cache header).
async fn raw_get(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    key: &str,
) -> (u16, Vec<u8>, Option<String>) {
    raw_get_with_checksum_mode(http_client, proxy_endpoint, key, None).await
}

async fn raw_head(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    key: &str,
    checksum_mode: Option<&str>,
) -> (u16, Option<String>) {
    let url = format!("{}/{}/{}", proxy_endpoint, TEST_BUCKET, key);
    let mut request = http_client.head(&url);
    if let Some(value) = checksum_mode {
        request = request.header("x-amz-checksum-mode", value);
    }
    let resp = request.send().await.expect("raw HEAD request failed");
    let status = resp.status().as_u16();
    let x_cache = resp
        .headers()
        .get("x-cache")
        .map(|v| v.to_str().unwrap().to_string());
    (status, x_cache)
}

/// Raw HTTP `GET /<bucket>?<raw_query>` against the proxy. The raw query is
/// inserted into the URL verbatim — unlike `reqwest::Client::get(...).query()`,
/// which would percent-encode/normalize the query — so percent-encoded keys
/// (e.g. `fetch%2Downer`) reach the proxy with their exact wire form. Returns
/// `(status, body_bytes)`.
async fn raw_list_query(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    bucket: &str,
    raw_query: &str,
) -> (u16, Vec<u8>) {
    let url = format!("{}/{}?{}", proxy_endpoint, bucket, raw_query);
    let parsed = reqwest::Url::parse(&url).expect("parse raw LIST URL");
    let resp = http_client
        .get(parsed)
        .send()
        .await
        .expect("raw LIST request failed");
    let status = resp.status().as_u16();
    let body = resp.bytes().await.expect("read LIST body").to_vec();
    (status, body)
}

/// Send a hand-rolled HTTP/1.1 request to `addr` (`host:port`) as a raw byte
/// stream, then read the entire response off the socket and return the parsed
/// `(status_code, full_response_bytes)`. The whole response is returned
/// verbatim — including any `Transfer-Encoding: chunked` framing — because the
/// tests that need this helper assert on substrings (status line, error
/// codes) rather than a structurally-decoded body. This sidesteps the work of
/// writing a chunked-decoder and avoids `reqwest`'s body-length reconciliation
/// that would otherwise prevent us from sending a `Content-Length` mismatched
/// with the actual body.
async fn raw_tcp_request(addr: &str, request: &[u8]) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("raw tcp: connect to proxy failed");
    stream
        .write_all(request)
        .await
        .expect("raw tcp: write request failed");
    stream.flush().await.expect("raw tcp: flush failed");
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .expect("raw tcp: read response failed");

    // Parse `HTTP/1.1 NNN ...` from the start of the response.
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("raw tcp: response missing header/body separator");
    let first_line_end = buf[..header_end]
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(header_end);
    let first_line =
        std::str::from_utf8(&buf[..first_line_end]).expect("raw tcp: status line not UTF-8");
    let mut parts = first_line.split_whitespace();
    let _version = parts.next().expect("raw tcp: missing HTTP version");
    let status_str = parts.next().expect("raw tcp: missing status code");
    let status: u16 = status_str
        .parse()
        .expect("raw tcp: status code not numeric");
    (status, buf)
}

/// Counting mock upstream for passthrough integration tests. `received_count`
/// is incremented on the FIRST line of the handler (before any body read), so
/// it catches the upstream being contacted even when the body stream errors
/// out mid-flight. The test cases that use this helper want to prove that the
/// proxy rejected before contacting the upstream at all.
#[derive(Default)]
struct CountingMockUpstream {
    received_count: std::sync::atomic::AtomicU32,
}

impl CountingMockUpstream {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// Spawn the counting mock upstream and return its `http://host:port` URL.
/// The returned `Arc<CountingMockUpstream>` lets the caller assert on
/// `received_count` after sending requests through the proxy.
async fn start_counting_mock_upstream(mock: Arc<CountingMockUpstream>) -> String {
    use axum::routing::any;
    let app = axum::Router::new()
        .route(
            "/{*path}",
            any({
                let mock = mock.clone();
                move |_req: http::Request<axum::body::Body>| {
                    let mock = mock.clone();
                    async move {
                        mock.received_count
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // Don't even read the body — the tests assert this
                        // handler is never reached, so the response is
                        // irrelevant. Returning 200 keeps the noise minimal
                        // if the mock IS reached (then the test fails on the
                        // received_count assertion with a clearer signal).
                        http::Response::builder()
                            .status(200)
                            .body(axum::body::Body::from("mock"))
                            .unwrap()
                    }
                }
            }),
        )
        .route(
            "/",
            any({
                let mock = mock.clone();
                move |_req: http::Request<axum::body::Body>| {
                    let mock = mock.clone();
                    async move {
                        mock.received_count
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        http::Response::builder()
                            .status(200)
                            .body(axum::body::Body::from("mock"))
                            .unwrap()
                    }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock upstream bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

/// A single request captured by `CapturingMockUpstream`. Records the inbound
/// HTTP shape we need to assert routing — method, the path the proxy chose
/// when constructing the upstream URL, the forwarded header set, and the
/// fully-drained body bytes.
#[derive(Clone)]
struct CapturedRequest {
    method: http::Method,
    path: String,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

/// Capturing mock upstream for routing assertions. Unlike
/// `CountingMockUpstream` (which intentionally doesn't read the body so it
/// can prove "upstream was never contacted"), this mock fully drains the
/// body and stores the entire request shape so the test can assert on
/// individual headers reaching the upstream. The 200 response carries a
/// plausible `ETag` so that a regression which routed the request to the
/// typed PUT path would still parse the upstream response cleanly — the
/// test then fails on the routing-signal assertion, not on a response-shape
/// error that would obscure the actual signal.
struct CapturingMockUpstream {
    requests: tokio::sync::Mutex<Vec<CapturedRequest>>,
}

impl CapturingMockUpstream {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            requests: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    async fn last_request(&self) -> Option<CapturedRequest> {
        self.requests.lock().await.last().cloned()
    }

    async fn request_count(&self) -> usize {
        self.requests.lock().await.len()
    }
}

/// Spawn the capturing mock upstream and return its `http://host:port` URL.
/// The returned `Arc<CapturingMockUpstream>` lets the caller assert on the
/// recorded request after sending one through the proxy.
async fn start_capturing_mock_upstream(mock: Arc<CapturingMockUpstream>) -> String {
    use axum::routing::any;

    async fn handle(
        mock: Arc<CapturingMockUpstream>,
        req: http::Request<axum::body::Body>,
    ) -> http::Response<axum::body::Body> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let headers = req.headers().clone();
        let body_bytes = axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024)
            .await
            .expect("failed to drain request body for mock capture");
        mock.requests.lock().await.push(CapturedRequest {
            method,
            path,
            headers,
            body: body_bytes.to_vec(),
        });
        http::Response::builder()
            .status(200)
            .header("ETag", "\"mock-etag\"")
            .body(axum::body::Body::empty())
            .unwrap()
    }

    let app = axum::Router::new()
        .route(
            "/{*path}",
            any({
                let mock = mock.clone();
                move |req: http::Request<axum::body::Body>| {
                    let mock = mock.clone();
                    async move { handle(mock, req).await }
                }
            }),
        )
        .route(
            "/",
            any({
                let mock = mock.clone();
                move |req: http::Request<axum::body::Body>| {
                    let mock = mock.clone();
                    async move { handle(mock, req).await }
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("capturing mock upstream bind");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

async fn wait_for_head_cache_status(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    key: &str,
    checksum_mode: Option<&str>,
    expected: Option<&str>,
) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (status, x_cache) = raw_head(http_client, proxy_endpoint, key, checksum_mode).await;
            if status == 200 && x_cache.as_deref() == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for expected HEAD cache status");
}

async fn wait_for_get_cache_status(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    key: &str,
    checksum_mode: Option<&str>,
    expected_body: &[u8],
    expected: Option<&str>,
) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (status, body, x_cache) =
                raw_get_with_checksum_mode(http_client, proxy_endpoint, key, checksum_mode).await;
            if status == 200 && body == expected_body && x_cache.as_deref() == expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("timed out waiting for expected GET cache status");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test 1: Full CRUD cycle through the proxy.
#[tokio::test]
#[ignore] // Requires Docker with versity/versitygw image
async fn test_full_crud_through_proxy() {
    let (_container, backend_endpoint) = start_versitygw().await;

    // Create bucket directly on the backend
    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, _http_client, _proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "crud/test-object.txt";
    let content = b"hello world from integration test";

    // PUT
    put_object(&proxy_client, key, content).await;

    // GET
    let get_resp = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("get_object failed");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(body.as_ref(), content);

    // HEAD
    let head_resp = proxy_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("head_object failed");
    assert_eq!(head_resp.content_length(), Some(content.len() as i64));

    // DELETE
    proxy_client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("delete_object failed");

    // GET after DELETE should fail
    let get_after_delete = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await;
    assert!(
        get_after_delete.is_err(),
        "GET after DELETE should fail but got: {:?}",
        get_after_delete
    );
}

/// Test 2: GET caching for cacheable prefix -- MISS then HIT.
#[tokio::test]
#[ignore]
async fn test_get_caching_for_cacheable_prefix() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "script_bundle/test.js";
    let content = b"console.log('hello');";

    // PUT via proxy
    put_object(&proxy_client, key, content).await;

    // First GET -> MISS (cache is cold)
    let (status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(status, 200);
    assert_eq!(body, content);
    assert_eq!(
        x_cache.as_deref(),
        Some("MISS"),
        "first GET should be a cache MISS"
    );

    // Second GET -> HIT (served from cache)
    let (status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(status, 200);
    assert_eq!(body, content);
    assert_eq!(
        x_cache.as_deref(),
        Some("HIT"),
        "second GET should be a cache HIT"
    );
}

/// Test 3: SDK GET with checksum mode still fills the cache.
#[tokio::test]
#[ignore]
async fn test_get_with_checksum_mode_fills_cache() {
    let (container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "script_bundle/checksum-mode.js";
    let content = b"console.log('checksum mode');";

    put_object(&proxy_client, key, content).await;

    let get_resp = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .expect("get_object with checksum_mode failed");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(body.as_ref(), content);

    container.stop().await.expect("stop backend after SDK GET");

    wait_for_get_cache_status(
        &http_client,
        &proxy_endpoint,
        key,
        Some("ENABLED"),
        content,
        Some("HIT"),
    )
    .await;

    // Prove the SDK client can also retrieve the cached checksum-mode object
    // after the backend is gone — a malformed cached response would fail here.
    let cached_resp = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .expect("cached get_object with checksum_mode failed");
    let cached_body = cached_resp
        .body
        .collect()
        .await
        .expect("read cached body")
        .into_bytes();
    assert_eq!(cached_body.as_ref(), content);
}

/// Test 4: HEAD with checksum mode uses a checksum-enriched cached entry.
#[tokio::test]
#[ignore]
async fn test_head_with_checksum_mode_uses_cached_entry() {
    let (container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "script_bundle/checksum-head.js";
    let content = b"console.log('checksum head');";

    put_object(&proxy_client, key, content).await;

    let get_resp = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .expect("get_object with checksum_mode failed");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(body.as_ref(), content);

    wait_for_get_cache_status(
        &http_client,
        &proxy_endpoint,
        key,
        Some("ENABLED"),
        content,
        Some("HIT"),
    )
    .await;

    let head_resp = proxy_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .expect("initial head_object with checksum_mode failed");
    assert_eq!(head_resp.content_length(), Some(content.len() as i64));

    container
        .stop()
        .await
        .expect("stop backend after cache warmup");

    wait_for_head_cache_status(
        &http_client,
        &proxy_endpoint,
        key,
        Some("ENABLED"),
        Some("HIT"),
    )
    .await;

    let head_resp = proxy_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .expect("head_object with checksum_mode failed");
    assert_eq!(head_resp.content_length(), Some(content.len() as i64));
}

/// Test 5: A checksum HEAD can enrich metadata after a plain cache fill.
#[tokio::test]
#[ignore]
async fn test_checksum_head_after_plain_cache_fill_enriches_cache() {
    let (container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "script_bundle/checksum-head-refresh.js";
    let content = b"console.log('plain fill then checksum head');";

    put_object(&proxy_client, key, content).await;

    let (status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(status, 200);
    assert_eq!(body, content);
    assert_eq!(x_cache.as_deref(), Some("MISS"));

    wait_for_get_cache_status(
        &http_client,
        &proxy_endpoint,
        key,
        None,
        content,
        Some("HIT"),
    )
    .await;

    let head_resp = proxy_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .expect("head_object with checksum_mode failed");
    assert_eq!(head_resp.content_length(), Some(content.len() as i64));

    container
        .stop()
        .await
        .expect("stop backend after checksum HEAD refresh");

    wait_for_head_cache_status(
        &http_client,
        &proxy_endpoint,
        key,
        Some("ENABLED"),
        Some("HIT"),
    )
    .await;

    // Verify the SDK client also gets a complete cached HEAD after shutdown.
    let cached_head = proxy_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled)
        .send()
        .await
        .expect("cached head_object with checksum_mode after shutdown failed");
    assert_eq!(cached_head.content_length(), Some(content.len() as i64));
}

/// Test 6: Non-cacheable prefix bypasses the cache entirely.
#[tokio::test]
#[ignore]
async fn test_non_cacheable_prefix_bypasses_cache() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "logs/test.log";
    let content = b"log data here";

    put_object(&proxy_client, key, content).await;

    // First GET -> BYPASS
    let (status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(status, 200);
    assert_eq!(body, content);
    assert_eq!(
        x_cache.as_deref(),
        Some("BYPASS"),
        "non-cacheable key should BYPASS cache"
    );

    // Second GET -> still BYPASS
    let (status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(status, 200);
    assert_eq!(body, content);
    assert_eq!(
        x_cache.as_deref(),
        Some("BYPASS"),
        "non-cacheable key should always BYPASS"
    );
}

/// Test 7: PUT purges the cache so subsequent GET sees updated content.
#[tokio::test]
#[ignore]
async fn test_put_purges_cache() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "script_bundle/versioned.js";

    // PUT v1
    put_object(&proxy_client, key, b"version-1").await;

    // GET -> MISS, fills cache
    let (status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"version-1");
    assert_eq!(x_cache.as_deref(), Some("MISS"));

    // GET -> HIT
    let (_status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(body, b"version-1");
    assert_eq!(x_cache.as_deref(), Some("HIT"));

    // PUT v2 (overwrites, should purge cache)
    put_object(&proxy_client, key, b"version-2").await;

    // GET -> MISS (cache was purged by PUT), content is v2
    let (status, body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(status, 200);
    assert_eq!(body, b"version-2");
    assert_eq!(
        x_cache.as_deref(),
        Some("MISS"),
        "GET after PUT should be a cache MISS"
    );
}

/// Test 8: DELETE purges the cache so subsequent GET returns 404/error.
#[tokio::test]
#[ignore]
async fn test_delete_purges_cache() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "script_bundle/to-delete.js";

    // PUT and fill cache
    put_object(&proxy_client, key, b"delete-me").await;
    let (_status, _body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(x_cache.as_deref(), Some("MISS"));
    let (_status, _body, x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_eq!(x_cache.as_deref(), Some("HIT"));

    // DELETE
    proxy_client
        .delete_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("delete_object");

    // GET after DELETE should NOT serve stale cache; should error
    let (status, _body, _x_cache) = raw_get(&http_client, &proxy_endpoint, key).await;
    assert_ne!(
        status, 200,
        "GET after DELETE should not return 200 (got stale cache?)"
    );
}

/// Test 9: ListObjectsV2 through the proxy.
#[tokio::test]
#[ignore]
async fn test_list_objects_v2() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, _http_client, _proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    // PUT a few objects with a unique prefix per test run
    let prefix = format!(
        "list-{}-{}/",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let key_a = format!("{}a.txt", prefix);
    let key_b = format!("{}b.txt", prefix);
    let key_c = format!("{}c.txt", prefix);

    put_object(&proxy_client, &key_a, b"aaa").await;
    put_object(&proxy_client, &key_b, b"bbb").await;
    put_object(&proxy_client, &key_c, b"ccc").await;

    // Small delay to allow VersityGW posix backend to sync
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // List all objects (without prefix filter) and then filter client-side,
    // since VersityGW posix backend may have quirks with prefix-based listing.
    let list_resp = proxy_client
        .list_objects_v2()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("list_objects_v2 failed");

    let all_keys: Vec<String> = list_resp
        .contents()
        .iter()
        .filter_map(|obj| obj.key().map(|k| k.to_string()))
        .collect();

    let matching_keys: Vec<&String> = all_keys.iter().filter(|k| k.starts_with(&prefix)).collect();

    assert_eq!(
        matching_keys.len(),
        3,
        "should find 3 objects with prefix '{}', all keys: {:?}",
        prefix,
        all_keys
    );
    assert!(all_keys.contains(&key_a));
    assert!(all_keys.contains(&key_b));
    assert!(all_keys.contains(&key_c));
}

/// Test 10: Multipart upload through the proxy.
#[tokio::test]
#[ignore]
async fn test_multipart_upload() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, _http_client, _proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    let key = "multipart/assembled.bin";

    // CreateMultipartUpload
    let create_resp = proxy_client
        .create_multipart_upload()
        .bucket(TEST_BUCKET)
        .key(key)
        .content_type("application/octet-stream")
        .send()
        .await
        .expect("create_multipart_upload failed");
    let upload_id = create_resp.upload_id().expect("should have upload_id");

    // UploadPart (minimum 5MB for multi-part, but with a single part we can use any size)
    // VersityGW may enforce minimum part size for multi-part; use a single-part upload
    // with the minimum chunk.
    let part_data = vec![42u8; 5 * 1024 * 1024]; // 5MB
    let upload_part_resp = proxy_client
        .upload_part()
        .bucket(TEST_BUCKET)
        .key(key)
        .upload_id(upload_id)
        .part_number(1)
        .body(aws_sdk_s3::primitives::ByteStream::from(part_data.clone()))
        .send()
        .await
        .expect("upload_part failed");
    let part_etag = upload_part_resp
        .e_tag()
        .expect("upload_part should return ETag");

    // CompleteMultipartUpload
    let completed_part = aws_sdk_s3::types::CompletedPart::builder()
        .e_tag(part_etag)
        .part_number(1)
        .build();
    let completed_upload = aws_sdk_s3::types::CompletedMultipartUpload::builder()
        .parts(completed_part)
        .build();

    proxy_client
        .complete_multipart_upload()
        .bucket(TEST_BUCKET)
        .key(key)
        .upload_id(upload_id)
        .multipart_upload(completed_upload)
        .send()
        .await
        .expect("complete_multipart_upload failed");

    // Verify by GET
    let get_resp = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("get_object after multipart failed");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(body.len(), 5 * 1024 * 1024);
    assert!(body.iter().all(|&b| b == 42));
}

/// Test 11: Request to wrong bucket returns NoSuchBucket error.
#[tokio::test]
#[ignore]
async fn test_wrong_bucket_returns_error() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (_proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    // Request a bucket that doesn't match the configured frontend_bucket
    let url = format!("{}/wrong-bucket/some-key", proxy_endpoint);
    let resp = http_client.get(&url).send().await.expect("raw GET request");

    assert_eq!(resp.status().as_u16(), 404);

    let body = resp.text().await.expect("read body");
    assert!(
        body.contains("NoSuchBucket"),
        "response should contain NoSuchBucket error, got: {}",
        body
    );
}

/// Test 12: Allowlist mode accepts requests with a known access key.
#[tokio::test]
#[ignore]
async fn test_allowlist_mode_accepts_known_key() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    // Build proxy in allowlist mode, allowing TEST_ACCESS_KEY
    let (proxy_client, _http_client, _proxy_endpoint, _cache_dir) =
        build_proxy_stack_allowlist(&backend_endpoint, vec![TEST_ACCESS_KEY.to_string()]).await;

    let key = "allowlist/accepted.txt";
    let content = b"accepted-by-allowlist";

    // PUT should succeed because the client's access key is in the allowlist
    proxy_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .body(aws_sdk_s3::primitives::ByteStream::from(content.to_vec()))
        .send()
        .await
        .expect("put_object with allowed key should succeed");

    // GET should also succeed
    let get_resp = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("get_object with allowed key should succeed");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(body.as_ref(), content);
}

/// Test 13: Allowlist mode rejects requests with an unknown access key.
#[tokio::test]
#[ignore]
async fn test_allowlist_mode_rejects_unknown_key() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    // Build proxy in allowlist mode with a DIFFERENT allowed key
    let (_proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_allowlist(&backend_endpoint, vec!["SOME-OTHER-KEY".to_string()]).await;

    // Build a client that signs with TEST_ACCESS_KEY (not in the allowlist)
    let rejected_client =
        build_raw_s3_client(&proxy_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;

    // PUT should fail with 403 (access denied)
    let put_result = rejected_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("allowlist/rejected.txt")
        .body(aws_sdk_s3::primitives::ByteStream::from(
            b"should-be-rejected".to_vec(),
        ))
        .send()
        .await;
    assert!(
        put_result.is_err(),
        "PUT with unknown access key should be rejected"
    );

    // Also verify via raw HTTP that the response is 403 with AccessDenied
    let url = format!("{}/{}/allowlist/rejected.txt", proxy_endpoint, TEST_BUCKET);
    let resp = http_client
        .get(&url)
        .header("authorization", "AWS4-HMAC-SHA256 Credential=UNKNOWN-KEY/20240101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc")
        .send()
        .await
        .expect("raw GET request");

    assert_eq!(resp.status().as_u16(), 403);
    let body = resp.text().await.expect("read body");
    assert!(
        body.contains("AccessDenied"),
        "response should contain AccessDenied, got: {}",
        body
    );
}

// ---------------------------------------------------------------------------
// Cold-review regression coverage (issue #48) — backfills end-to-end coverage
// for the production fixes shipped in PRs #52 (issue #44), #54 (issue #43),
// #57 (issue #46), #58 (issue #47), #60 (issue #45), and #49 (issue #40).
// ---------------------------------------------------------------------------

/// Backfills coverage for PR #57 (issue #46): the LIST modifier gate must
/// percent-decode query-string keys before deciding whether a request needs to
/// route to passthrough. A client sending `fetch%2Downer=true` (an encoded
/// `-`) intends `fetch-owner=true`. The typed LIST path does not model the
/// owner field — its XML serializer emits no `<Owner>` element at all — so
/// hitting the typed path silently drops the response data the client asked
/// for.
///
/// Bug-revert reasoning: if the decode in `has_unsupported_list_modifiers`
/// were removed, the gate would compare the raw `fetch%2Downer` key against
/// the literal `"fetch-owner"`, miss, and fall through to the typed LIST. The
/// typed serializer (`serialize_list_objects_v2` in `src/s3/xml.rs`) writes no
/// `<Owner>` element, so the assertion below would fail.
#[tokio::test]
#[ignore] // Requires Docker with versity/versitygw image
async fn test_list_v2_encoded_fetch_owner_routes_to_passthrough_and_preserves_owner() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let (proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    // Put one object so the LIST has something to enumerate.
    put_object(
        &proxy_client,
        "cold-review/fetch-owner-encoded.txt",
        b"owner-probe",
    )
    .await;

    // `fetch%2Downer` is the URL-encoded form of `fetch-owner`. Send it raw,
    // not decoded, so the proxy receives the exact wire bytes a misbehaving
    // (or strict) client would send.
    let (status, body) = raw_list_query(
        &http_client,
        &proxy_endpoint,
        TEST_BUCKET,
        "list-type=2&fetch%2Downer=true",
    )
    .await;
    assert_eq!(status, 200, "encoded fetch-owner LIST should succeed");
    let body_str = String::from_utf8_lossy(&body);
    // Passthrough mode forwards the upstream LIST response, which includes the
    // <Owner> block when fetch-owner=true. The typed LIST path would emit none.
    assert!(
        body_str.contains("<Owner>"),
        "passthrough LIST must include <Owner> when fetch-owner=true; got: {body_str}"
    );
    assert!(
        body_str.contains(&format!("<ID>{TEST_ACCESS_KEY}</ID>")),
        "Owner block must carry the upstream owner ID; got: {body_str}"
    );
}

/// Backfills coverage for PR #60 (issue #40, follow-up #49 area): the typed
/// LIST response must preserve `ChecksumAlgorithm` and `ChecksumType` metadata
/// that the upstream reports for each object. Without this, SDK clients
/// (notably anything verifying object integrity on the listing side) see a
/// LIST output whose checksum fields are silently dropped.
///
/// Setup intentionally PUTs directly to the backend with `Crc32` checksum so
/// the LIST path is exercised in isolation — the proxy's typed PUT/passthrough
/// paths have their own checksum handling and would entangle this test.
///
/// Bug-revert reasoning: if `map_sdk_object` (`src/backend/client.rs`) stopped
/// copying `checksum_algorithm` / `checksum_type`, those fields would be empty
/// in `ObjectInfo`, and `serialize_list_objects_v2` would skip the
/// `<ChecksumAlgorithm>` / `<ChecksumType>` elements. The assertions below
/// would fail.
#[tokio::test]
#[ignore] // Requires Docker with versity/versitygw image
async fn test_list_v2_preserves_checksum_algorithm_and_type_xml() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    // PUT through the backend with a checksum algorithm so VersityGW records
    // ChecksumAlgorithm + ChecksumType on the stored object. Bypasses the
    // proxy on PUT so the LIST behavior is isolated.
    let key = "cold-review/checksum-list.txt";
    backend_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .checksum_algorithm(aws_sdk_s3::types::ChecksumAlgorithm::Crc32)
        .body(aws_sdk_s3::primitives::ByteStream::from(
            b"crc32-probe".to_vec(),
        ))
        .send()
        .await
        .expect("checksum PUT direct to backend");

    let (_proxy_client, http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack(&backend_endpoint).await;

    // Plain LIST (no modifiers) — typed path; the typed path is the one PR #60 fixed.
    let (status, body) =
        raw_list_query(&http_client, &proxy_endpoint, TEST_BUCKET, "list-type=2").await;
    assert_eq!(status, 200, "plain typed LIST should succeed");
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        body_str.contains("<ChecksumAlgorithm>CRC32</ChecksumAlgorithm>"),
        "typed LIST XML must preserve the per-object ChecksumAlgorithm; got: {body_str}"
    );
    assert!(
        body_str.contains("<ChecksumType>FULL_OBJECT</ChecksumType>"),
        "typed LIST XML must preserve the per-object ChecksumType; got: {body_str}"
    );
}

/// Backfills coverage for PR #54 (issue #43): on startup, `DiskCache::new`
/// must sweep the `<cache_dir>/tmp/` directory of stale temp files left by a
/// previous crashed run. The allowlist includes the `{pid}-{pid}-{counter}.body`
/// fill-body temp shape used by `handlers/get.rs`; the sweep should remove it
/// even though we know nothing about the dead process that wrote it.
///
/// Bug-revert reasoning: if `super::tmp_sweep::sweep_tmp_dir(...)` were
/// removed from `DiskCache::new`, the preplanted `1-1-1.body` file would
/// survive the proxy startup, leaving an accumulating leak across crashes.
/// The post-startup `assert!(!planted.exists(), ...)` would then fail.
#[tokio::test]
#[ignore] // Requires Docker with versity/versitygw image
async fn test_startup_sweeps_stale_cache_tmp_fill_body_file() {
    let (_container, backend_endpoint) = start_versitygw().await;

    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    // Build the cache_dir layout and plant a stale fill_body before the proxy
    // starts. The sweep runs synchronously inside `DiskCache::new`, so by the
    // time `build_proxy_stack_with_opts` returns the file should be gone.
    let cache_dir = tempfile::TempDir::new().expect("create cache dir");
    let tmp_dir = cache_dir.path().join("tmp");
    let objects_dir = cache_dir.path().join("objects");
    tokio::fs::create_dir_all(&tmp_dir).await.unwrap();
    tokio::fs::create_dir_all(&objects_dir).await.unwrap();
    let planted = tmp_dir.join("1-1-1.body");
    tokio::fs::write(&planted, b"stale fill body from a dead proxy")
        .await
        .expect("plant stale fill_body");
    assert!(planted.exists(), "precondition: planted file must exist");

    let (proxy_client, _http_client, _proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&backend_endpoint, cache_dir, |_cfg| {}).await;

    assert!(
        !planted.exists(),
        "DiskCache::new must sweep allowlisted fill_body temp files at startup; \
         expected {} to be removed",
        planted.display()
    );

    // Sanity: the proxy is still healthy after sweep (startup didn't abort).
    put_object(&proxy_client, "cold-review/post-sweep.txt", b"alive").await;
    let get_resp = proxy_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("cold-review/post-sweep.txt")
        .send()
        .await
        .expect("post-sweep GET should succeed");
    let body = get_resp.body.collect().await.unwrap().into_bytes();
    assert_eq!(body.as_ref(), b"alive");
}

/// Backfills coverage for PR #58 (issue #47): the streaming passthrough path
/// must reject an inbound request whose declared `Content-Length` exceeds
/// `max_request_body_bytes` BEFORE contacting the upstream. The earlier
/// `Limited` body wrapper only fires after `reqwest::send()` starts streaming
/// the body, which (a) means the upstream sees a torn request, and (b) means
/// the proxy can return inconsistent response framing once the upstream's
/// reply has already started flowing. The preflight closes that window.
///
/// Setup intentionally points the proxy at a counting mock upstream rather
/// than VersityGW: the assertion that the upstream was never contacted is the
/// load-bearing one, and exposing a real S3 backend here would make a torn
/// request indistinguishable from "the backend rejected it." The PUT is
/// forced down the passthrough STREAMING branch via two switches:
///
///   * `passthrough_unsigned_payload=true` flips the buffered/streaming
///     selection in `handle_passthrough`: with unsigned payload + a
///     non-idempotent method (PUT), `needs_buffer` evaluates to false and
///     the streaming branch is chosen.
///   * `Content-Encoding: aws-chunked` makes
///     `has_s3_streaming_upload_indicators` return true, which makes
///     `has_unsupported_write_modifiers` return true, which routes the
///     PutObject dispatch through `route_to_passthrough` instead of the
///     typed `put::handle_put` path.
///
/// Bug-revert reasoning: if the preflight at the top of the streaming branch
/// were removed (the regression #58 fixed), the `Limited` wrapper alone would
/// still abort when the body actually exceeded the cap — but in THIS test the
/// body is 8 bytes, well under the 16-byte cap. Limited would NOT fire, the
/// request would be sent to the upstream, `received_count` would increment to
/// 1, and the test would fail on the no-upstream-contact assertion.
///
/// Why raw TCP: `reqwest` reconciles a body's declared and actual length when
/// sending. We need to send `Content-Length: 32` with only 8 bytes of body to
/// pre-fail the preflight without arming the `Limited` backstop, and the
/// cleanest way to send that mismatch is a hand-rolled HTTP/1.1 byte stream.
#[tokio::test]
#[ignore] // Spawns an in-process mock upstream; Docker not required, but kept
// `#[ignore]` for parity with the rest of this suite.
async fn test_unsigned_streaming_put_oversized_content_length_rejected_before_backend_contact() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;

    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    // Use the with_opts path so we can flip `passthrough_unsigned_payload`
    // (forces the streaming branch in passthrough) and pin a tiny
    // `max_request_body_bytes` (so we can hit the cap without lifting more
    // than a few bytes of network traffic). Building Config directly bypasses
    // `Config::from_env`, which would reject http + unsigned-payload at boot.
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |cfg| {
            cfg.passthrough_unsigned_payload = true;
            cfg.max_request_body_bytes = 16;
        })
        .await;

    let proxy_host = proxy_endpoint
        .strip_prefix("http://")
        .expect("proxy endpoint should be http://host:port");

    // Hand-rolled HTTP/1.1 PUT:
    //   * declared Content-Length 32 > cap 16 → preflight rejects
    //   * actual body 8 bytes < cap 16        → Limited backstop would NOT fire
    //   * STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER with x-amz-trailer:
    //     trailer-mode aws-chunked still routes through passthrough (PR #2
    //     of issue #50 will move trailer-mode into the in-house decoder).
    //     The non-trailer variant now goes through the decoder, so using
    //     it here would no longer exercise the passthrough preflight.
    let request = format!(
        "PUT /{TEST_BUCKET}/cold-review/oversized-cl HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: 32\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: 8\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         Connection: close\r\n\
         \r\n\
         AAAAAAAA"
    );
    let (status, raw_response) = raw_tcp_request(proxy_host, request.as_bytes()).await;

    assert_eq!(
        status, 400,
        "oversized Content-Length must be rejected with 400 EntityTooLarge"
    );
    let response_text = String::from_utf8_lossy(&raw_response);
    assert!(
        response_text.contains("EntityTooLarge"),
        "response body should contain EntityTooLarge error code; got: {response_text}"
    );

    // Load-bearing assertion: the preflight must reject BEFORE any
    // `req_builder.send()` reaches the upstream. `received_count` is bumped
    // at the very top of the mock handler — before body read — so it catches
    // even torn-body requests where the `Limited` backstop would abort the
    // upstream send mid-flight. If this assertion fires, the preflight has
    // regressed.
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "preflight must reject before contacting upstream"
    );
}

/// Backfills coverage for PR #52 (issue #45): the binary must reject a
/// `BACKEND_ENDPOINT` that embeds URL userinfo (e.g.
/// `https://user:pass@host`), and the rejection message must NOT leak the
/// embedded credentials or the host portion of the URL into stderr / process
/// logs. Configuration errors are surfaced via `expect("Failed to load
/// configuration")` in `main.rs`, so the panic message lands directly on
/// stderr where logging pipelines pick it up.
///
/// This test spawns the actual compiled `tiny-s3-proxy` binary as a
/// subprocess (via the Cargo-set `CARGO_BIN_EXE_*` env var) rather than
/// invoking `Config::from_env` in-process. The reason is that the userinfo
/// leak surface is the panic message produced by `expect`, which Rust prints
/// through the default panic hook to the parent process's stderr — we need
/// real fork + stderr capture to assert on what an operator would actually
/// see.
///
/// Bug-revert reasoning: if the `endpoint_has_userinfo` check were removed
/// from `Config::from_env`, the binary would attempt to bind sockets and
/// reach the SDK construction step, at which point logs and request errors
/// might format the endpoint into strings — leaking `alice:supersecret`
/// and `s3.example.com:9443` into stderr. The negative assertions below
/// would fail.
#[tokio::test]
#[ignore]
async fn test_backend_endpoint_userinfo_rejected_without_leaking_endpoint_parts() {
    use tokio::time::{Duration, timeout};

    let bin_path = env!("CARGO_BIN_EXE_tiny-s3-proxy");

    let mut cmd = tokio::process::Command::new(bin_path);
    // Start from a clean environment so the parent shell's BACKEND_*/FRONTEND_*
    // values don't accidentally satisfy or shadow what we want to test.
    cmd.env_clear()
        .env("FRONTEND_BUCKET", "test-frontend")
        .env(
            "BACKEND_ENDPOINT",
            "https://alice:supersecret@s3.example.com:9443/root",
        )
        .env("BACKEND_BUCKET", "test-backend")
        .env("BACKEND_ACCESS_KEY_ID", "AKID")
        .env("BACKEND_SECRET_ACCESS_KEY", "shouldnotappearinerror")
        .env("S3_LISTEN_ADDR", "127.0.0.1:0")
        .env("ADMIN_LISTEN_ADDR", "127.0.0.1:0")
        // RUST_LOG=off keeps tracing-subscriber's default warning about the
        // missing env filter out of stderr so the assertions below see only
        // the panic message (and surrounding cargo/runtime noise).
        .env("RUST_LOG", "off")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    let child = cmd.spawn().expect("spawn tiny-s3-proxy binary");
    let output = timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("tiny-s3-proxy did not exit within 15s")
        .expect("read tiny-s3-proxy output");

    assert!(
        !output.status.success(),
        "binary should exit non-zero when BACKEND_ENDPOINT carries userinfo; got: {:?}",
        output.status,
    );

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Positive: the error must name the relevant env vars so operators can
    // act on it without guesswork.
    for needle in [
        "BACKEND_ENDPOINT",
        "BACKEND_ACCESS_KEY_ID",
        "BACKEND_SECRET_ACCESS_KEY",
    ] {
        assert!(
            stderr.contains(needle),
            "stderr should reference {needle} so the operator can fix the config; got:\n{stderr}"
        );
    }

    // Negative: under no circumstances should the userinfo or host portions
    // of the embedded URL reach stderr. These four needles together cover the
    // username, password, host, and port portion of the planted URL.
    for forbidden in ["alice", "supersecret", "s3.example.com", "9443"] {
        assert!(
            !stderr.contains(forbidden),
            "stderr must not leak `{forbidden}` from the rejected BACKEND_ENDPOINT; got:\n{stderr}"
        );
    }
}

/// Pins the routing decision for aws-chunked TRAILER-mode uploads — those
/// must still go through passthrough because PR #1 of issue #50 only handles
/// non-trailer mode. PR #2 will add trailer support.
///
/// Signal: `x-amz-decoded-content-length` + `x-amz-trailer` reach the upstream.
/// Passthrough forwards both verbatim; typed PUT strips
/// `x-amz-decoded-content-length` during request parsing
/// (`src/s3/parse.rs`) and the decode path would consume the body before
/// forwarding the framing. Seeing the trailer header at the upstream proves
/// we routed through passthrough.
///
/// Replaces the earlier non-trailer routing test from PR #62 — non-trailer
/// aws-chunked now goes through the in-house decoder (issue #50 PR #1), so
/// the routing target has changed. Trailer mode remains on passthrough until
/// PR #2 lands.
#[tokio::test]
#[ignore] // Spawns an in-process mock upstream; Docker not required, but kept
// `#[ignore]` for parity with the rest of this suite.
async fn test_aws_chunked_trailer_mode_routes_to_passthrough() {
    let mock = CapturingMockUpstream::new();
    let mock_endpoint = start_capturing_mock_upstream(mock.clone()).await;

    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;

    let proxy_host = proxy_endpoint
        .strip_prefix("http://")
        .expect("proxy endpoint should be http://host:port");

    // Same 180-byte aws-chunked body as the original PR #62 test. The body
    // shape is only checked for byte-for-byte preservation; the routing
    // signal is the trailer header below.
    let body: Vec<u8> =
        b"8;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        abcdefgh\r\n\
        0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        \r\n"
            .to_vec();
    assert_eq!(
        body.len(),
        180,
        "aws-chunked body must be exactly 180 bytes"
    );

    // Trailer-mode indicators force passthrough routing:
    //   * x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
    //   * x-amz-trailer: x-amz-checksum-crc32
    let headers = format!(
        "PUT /{TEST_BUCKET}/cold-review/aws-chunked-trailer-routing HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: 180\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: 8\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         Connection: close\r\n\
         \r\n"
    );
    let mut request_bytes = headers.into_bytes();
    request_bytes.extend_from_slice(&body);

    let (status, _raw_response) = raw_tcp_request(proxy_host, &request_bytes).await;
    assert_eq!(
        status, 200,
        "proxy should return the upstream's 200; got {status}"
    );

    let captured = mock
        .last_request()
        .await
        .expect("upstream must have received the request");
    assert_eq!(mock.request_count().await, 1);
    assert_eq!(captured.method, http::Method::PUT);
    assert_eq!(
        captured.path,
        format!("/{TEST_BUCKET}/cold-review/aws-chunked-trailer-routing"),
    );
    // x-amz-trailer reaching the upstream proves passthrough — the typed
    // path and the decode path both strip this.
    let trailer = captured
        .headers
        .get("x-amz-trailer")
        .expect(
            "x-amz-trailer must reach the upstream; if missing, the request \
             was decoded by the proxy rather than passed through",
        )
        .to_str()
        .unwrap();
    assert_eq!(trailer, "x-amz-checksum-crc32");
    // The raw aws-chunked framing must also have reached the upstream
    // byte-for-byte (passthrough byte preservation).
    assert_eq!(
        captured.body.as_slice(),
        body.as_slice(),
        "upstream should receive the trailer-framed body byte-for-byte",
    );
}

/// ECDSA-signed streaming uploads (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD`)
/// are out of scope for the in-house decoder — they must continue to route
/// through passthrough. Pins the routing decision so a future change to the
/// aws-chunked classifier doesn't accidentally swallow ECDSA frames.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_ecdsa_streaming_routes_to_passthrough() {
    let mock = CapturingMockUpstream::new();
    let mock_endpoint = start_capturing_mock_upstream(mock.clone()).await;
    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Single-chunk framed body, same shape as the trailer-mode test.
    let body: Vec<u8> =
        b"8;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        abcdefgh\r\n\
        0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        \r\n"
            .to_vec();
    let headers = format!(
        "PUT /{TEST_BUCKET}/cold-review/aws-chunked-ecdsa-routing HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD\r\n\
         x-amz-decoded-content-length: 8\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = body.len(),
    );
    let mut request_bytes = headers.into_bytes();
    request_bytes.extend_from_slice(&body);
    let (status, _raw_response) = raw_tcp_request(proxy_host, &request_bytes).await;
    assert_eq!(status, 200);
    let captured = mock
        .last_request()
        .await
        .expect("upstream must have received the request");
    assert_eq!(mock.request_count().await, 1);
    // Body must reach upstream byte-for-byte — proves passthrough (the
    // decode path would strip the chunk-signature framing). Note that
    // passthrough re-signs the outbound request, so we can't rely on
    // `x-amz-content-sha256` reaching the upstream as-is — the byte
    // preservation check above is the load-bearing routing signal.
    assert_eq!(captured.body.as_slice(), body.as_slice());
    // x-amz-decoded-content-length is preserved by passthrough but the
    // decode path strips it before forwarding. Use that as a positive
    // routing signal alongside the body-byte check.
    let decoded_cl = captured
        .headers
        .get("x-amz-decoded-content-length")
        .expect(
            "x-amz-decoded-content-length must reach the upstream; if missing, \
             the request was decoded by the proxy rather than passed through",
        )
        .to_str()
        .unwrap();
    assert_eq!(decoded_cl, "8");
}

/// A non-trailer aws-chunked PUT whose `x-amz-decoded-content-length` exceeds
/// the configured `max_request_body_bytes` must be rejected with
/// `EntityTooLarge` (HTTP 400) **before** the proxy contacts the backend —
/// no spool file should leak under `<cache_dir>/tmp/`.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_decoded_length_exceeds_max_returns_entity_too_large() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir_holder = tempfile::TempDir::new().expect("cache dir");
    let cache_dir_path = cache_dir_holder.path().to_path_buf();
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir_holder, |cfg| {
            cfg.max_request_body_bytes = 4;
        })
        .await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Declared 8 > cap 4. Body bytes don't matter — the handler rejects on
    // the header alone.
    let body =
        b"8;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        abcdefgh\r\n\
        0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        \r\n";
    let headers = format!(
        "PUT /{TEST_BUCKET}/oversized-decoded HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\
         x-amz-decoded-content-length: 8\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(body);

    let (status, raw_response) = raw_tcp_request(proxy_host, &request).await;
    assert_eq!(
        status, 400,
        "oversized aws-chunked decoded length must be rejected with 400"
    );
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert!(
        resp_text.contains("EntityTooLarge"),
        "expected EntityTooLarge error body, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "upstream must not be contacted when the decoded length cap is exceeded",
    );
    // No spool file should have been planted.
    let tmp = cache_dir_path.join("tmp");
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

/// Malformed aws-chunked framing (truncated chunk data) must produce an
/// `IncompleteBody` 400 with no backend contact and no spool leak. Catches
/// regressions in the decoder error → S3 error mapping.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_malformed_frame_returns_error_without_backend_contact() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir_holder = tempfile::TempDir::new().expect("cache dir");
    let cache_dir_path = cache_dir_holder.path().to_path_buf();
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir_holder, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Header claims 8 bytes of payload, body has 3 then EOF — Truncated.
    let body: &[u8] =
        b"8;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\nabc";
    let headers = format!(
        "PUT /{TEST_BUCKET}/malformed HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\
         x-amz-decoded-content-length: 8\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(body);

    let (status, raw_response) = raw_tcp_request(proxy_host, &request).await;
    assert_eq!(status, 400);
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert!(
        resp_text.contains("IncompleteBody"),
        "expected IncompleteBody, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "upstream must not be contacted on a malformed aws-chunked body",
    );
    // Spool file should be cleaned up by Drop after decode error.
    let tmp = cache_dir_path.join("tmp");
    if tmp.exists() {
        let mut entries = tokio::fs::read_dir(&tmp).await.unwrap();
        while let Some(e) = entries.next_entry().await.unwrap() {
            let name = e.file_name();
            assert!(
                !name.to_string_lossy().ends_with(".upload-spool.tmp"),
                "spool must be cleaned up after decode error, found {name:?}",
            );
        }
    }
}

/// The runtime HTTPS guard in `S3Backend::put_object_from_path` must fire
/// when the decode path tries to upload over an `http://` backend. The
/// startup config validation is the primary defence; this guard is the
/// runtime backstop. Result: HTTP 500 InternalError, no backend contact.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_decode_path_rejects_http_backend_via_runtime_guard() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Well-formed single-chunk frame for `abcdefgh`.
    let body =
        b"8;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        abcdefgh\r\n\
        0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        \r\n";
    let headers = format!(
        "PUT /{TEST_BUCKET}/decode-over-http HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\
         x-amz-decoded-content-length: 8\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(body);
    let (status, raw_response) = raw_tcp_request(proxy_host, &request).await;
    // ProxyError::Cache maps to 500 InternalError via S3Error::from_proxy_error.
    assert_eq!(
        status, 500,
        "HTTPS guard must reject http:// backend with InternalError",
    );
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert!(
        resp_text.contains("InternalError"),
        "expected InternalError, got: {resp_text}",
    );
    // Upstream must not have been contacted.
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "upstream must not be contacted when the HTTPS guard rejects",
    );
}

/// Abandoned upload-spool files (`{pid}-{counter}.upload-spool.tmp`) planted
/// before startup must be cleaned up by the tmp sweep. Mirrors the existing
/// startup-sweep coverage in `src/cache/tmp_sweep.rs` but exercises the
/// pattern end-to-end through `DiskCache::new`.
#[tokio::test]
#[ignore]
async fn test_tmp_sweep_removes_abandoned_upload_spool_files() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;

    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let tmp_dir = cache_dir.path().join("tmp");
    tokio::fs::create_dir_all(&tmp_dir).await.unwrap();
    let abandoned = tmp_dir.join("12345-7.upload-spool.tmp");
    tokio::fs::write(&abandoned, b"abandoned spool body")
        .await
        .unwrap();
    assert!(abandoned.exists());

    // build_proxy_stack_with_opts -> DiskCache::new -> tmp sweep runs at
    // startup. After it returns, abandoned files of the allowlisted shape
    // must be gone.
    let (_proxy_client, _http_client, _proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;

    assert!(
        !abandoned.exists(),
        "tmp sweep should have removed the abandoned upload-spool file at {}",
        abandoned.display(),
    );
}
