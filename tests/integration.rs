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
    let mut config = default_proxy_test_config(
        backend_endpoint,
        auth_mode,
        allowed_keys,
        cache_dir.path(),
    );
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

/// Raw HTTP `PUT /<bucket>/<key>` against the proxy with caller-supplied
/// headers. Returns `(status, body_bytes)`. Used by tests that need to control
/// `Content-Length` independently of the actual body length (which `reqwest`
/// would otherwise reconcile for them).
async fn raw_put_with_headers(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    key: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (u16, Vec<u8>) {
    let url = format!("{}/{}/{}", proxy_endpoint, TEST_BUCKET, key);
    let mut req = http_client.put(&url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = req.body(body).send().await.expect("raw PUT request failed");
    let status = resp.status().as_u16();
    let body = resp.bytes().await.expect("read PUT body").to_vec();
    (status, body)
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
// for the production fixes shipped in PRs #43, #44, #45, #46, #47, and #49.
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
        .body(aws_sdk_s3::primitives::ByteStream::from(b"crc32-probe".to_vec()))
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
