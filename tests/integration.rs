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

use std::path::PathBuf;
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
    let container = GenericImage::new("versity/versitygw", "latest")
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
    let creds =
        aws_credential_types::Credentials::new(access_key, secret_key, None, None, "test");
    let config = aws_sdk_s3::config::Builder::new()
        .endpoint_url(endpoint)
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(creds)
        .force_path_style(true)
        .behavior_version_latest()
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

/// Build the full proxy stack and return:
/// - An S3 client pointed at the proxy
/// - A reqwest client for raw HTTP (to inspect headers)
/// - The proxy endpoint URL
/// - The TempDir (must be kept alive for the cache directory)
async fn build_proxy_stack(
    backend_endpoint: &str,
) -> (aws_sdk_s3::Client, reqwest::Client, String, tempfile::TempDir) {
    let cache_dir = tempfile::TempDir::new().expect("create temp cache dir");

    let config = Config {
        s3_listen_addr: "127.0.0.1:0".to_string(),
        admin_listen_addr: "127.0.0.1:0".to_string(),
        frontend_bucket: TEST_BUCKET.to_string(),
        auth_mode: AuthMode::TrustedInternal,
        allowed_frontend_keys: vec![],
        backend_endpoint: backend_endpoint.to_string(),
        backend_region: "us-east-1".to_string(),
        backend_bucket: TEST_BUCKET.to_string(),
        backend_access_key_id: TEST_ACCESS_KEY.to_string(),
        backend_secret_access_key: TEST_SECRET_KEY.to_string(),
        backend_use_path_style: true,
        backend_allow_http: true,
        cache_dir: cache_dir.path().to_str().unwrap().to_string(),
        cache_max_bytes: 100 * 1024 * 1024,
        cache_max_object_bytes: 10 * 1024 * 1024,
        cacheable_prefixes: vec![
            "script_bundle/".into(),
            "bun_bundle/".into(),
            "tar/".into(),
        ],
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
        max_request_body_bytes: 5_368_709_120,
    };

    // Build backend
    let s3_backend = backend::client::S3Backend::from_config(&config)
        .await
        .expect("build S3 backend");

    // Build cache
    let cache_policy = cache::policy::CachePolicy::new(
        config.cacheable_prefixes.clone(),
        config.cache_max_object_bytes,
    );
    let disk_cache = cache::DiskCache::new(
        PathBuf::from(&config.cache_dir),
        config.cache_max_bytes,
        cache_policy.clone(),
    )
    .await
    .expect("build disk cache");

    let singleflight = Arc::new(cache::SingleFlight::new());
    let authenticator = Arc::from(auth::create_authenticator(&config));

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

    // Build axum router
    let app = axum::Router::new()
        .fallback(handlers::handle_s3_request)
        .with_state(state);

    // Bind to a random port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let proxy_endpoint = format!("http://127.0.0.1:{}", addr.port());

    let proxy_client =
        build_raw_s3_client(&proxy_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;

    let http_client = reqwest::Client::new();

    (proxy_client, http_client, proxy_endpoint, cache_dir)
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
async fn raw_get(
    http_client: &reqwest::Client,
    proxy_endpoint: &str,
    key: &str,
) -> (u16, Vec<u8>, Option<String>) {
    let url = format!("{}/{}/{}", proxy_endpoint, TEST_BUCKET, key);
    let resp = http_client
        .get(&url)
        .send()
        .await
        .expect("raw GET request failed");
    let status = resp.status().as_u16();
    let x_cache = resp
        .headers()
        .get("x-cache")
        .map(|v| v.to_str().unwrap().to_string());
    let body = resp.bytes().await.expect("read response body").to_vec();
    (status, body, x_cache)
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

/// Test 3: Non-cacheable prefix bypasses the cache entirely.
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

/// Test 4: PUT purges the cache so subsequent GET sees updated content.
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

/// Test 5: DELETE purges the cache so subsequent GET returns 404/error.
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

/// Test 6: ListObjectsV2 through the proxy.
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
    let prefix = format!("list-{}-{}/", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
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

    let matching_keys: Vec<&String> = all_keys
        .iter()
        .filter(|k| k.starts_with(&prefix))
        .collect();

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

/// Test 7: Multipart upload through the proxy.
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

/// Test 8: Request to wrong bucket returns NoSuchBucket error.
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
    let resp = http_client
        .get(&url)
        .send()
        .await
        .expect("raw GET request");

    assert_eq!(resp.status().as_u16(), 404);

    let body = resp.text().await.expect("read body");
    assert!(
        body.contains("NoSuchBucket"),
        "response should contain NoSuchBucket error, got: {}",
        body
    );
}
