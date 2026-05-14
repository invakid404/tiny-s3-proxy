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

/// Variant of `build_raw_s3_client` that uses a caller-supplied
/// `SharedHttpClient`. Used to talk DIRECTLY to the HTTPS VersityGW
/// fixture with a TLS trust store that pins the test CA.
async fn build_raw_s3_client_with_http_client(
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    http_client: aws_sdk_s3::config::SharedHttpClient,
) -> aws_sdk_s3::Client {
    let creds = aws_credential_types::Credentials::new(access_key, secret_key, None, None, "test");
    let config = aws_sdk_s3::config::Builder::new()
        .endpoint_url(endpoint)
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(creds)
        .force_path_style(true)
        .http_client(http_client)
        .behavior_version_latest()
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

/// Test TLS material: a self-signed CA and a leaf certificate signed by
/// that CA with SANs for `127.0.0.1` and `localhost`. Generated fresh for
/// each fixture invocation — short-lived, never persisted.
struct TestTls {
    /// CA certificate PEM. Loaded into the SDK trust store on both the
    /// test-direct and proxy-outbound clients.
    ca_pem: String,
    /// Leaf cert followed by the CA cert (PEM concatenation), suitable for
    /// VersityGW's `--cert` flag.
    server_chain_pem: String,
    /// Leaf key PEM for VersityGW's `--key` flag.
    server_key_pem: String,
}

/// Generate a fresh self-signed CA + leaf cert for the HTTPS VersityGW
/// fixture. Uses rcgen's default ECDSA-P256 + SHA256, which both rustls
/// (test SDK) and Go's crypto/tls (VersityGW server) accept out of the
/// box.
fn generate_test_tls() -> TestTls {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType,
    };
    use std::net::IpAddr;

    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("CA params: empty SAN cannot fail");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "tiny-s3-proxy test CA");
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_key = KeyPair::generate().expect("generate CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let issuer = Issuer::new(ca_params, ca_key);

    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params: known-good SAN");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "127.0.0.1");
    leaf_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().expect("localhost is valid IA5")),
        SanType::IpAddress("127.0.0.1".parse::<IpAddr>().expect("127.0.0.1 is valid")),
    ];
    leaf_params
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    leaf_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let leaf_key = KeyPair::generate().expect("generate leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign leaf cert");

    let ca_pem = ca_cert.pem();
    let server_chain_pem = format!("{}{}", leaf_cert.pem(), ca_pem);
    let server_key_pem = leaf_key.serialize_pem();
    TestTls {
        ca_pem,
        server_chain_pem,
        server_key_pem,
    }
}

/// Start a VersityGW container speaking native TLS via the `--cert`/`--key`
/// flags. The supplied chain and key are copied into the container at
/// `/tls/server.pem` and `/tls/server.key`, then VersityGW is launched
/// listening on container port 10000. Returns the container handle (must
/// be held to keep the container alive) and the `https://127.0.0.1:<port>`
/// endpoint URL.
async fn start_versitygw_https(
    tls: &TestTls,
) -> (testcontainers::ContainerAsync<GenericImage>, String) {
    let container = GenericImage::new(
        "versity/versitygw",
        "latest@sha256:a86791b684a1dd3c5a255ca755bb51783a72696cf1b5a843f800b08bfd6f921c",
    )
    .with_entrypoint("sh")
    .with_exposed_port(10000.into())
    .with_wait_for(WaitFor::message_on_stdout("listening on"))
    .with_env_var("ROOT_ACCESS_KEY", TEST_ACCESS_KEY)
    .with_env_var("ROOT_SECRET_KEY", TEST_SECRET_KEY)
    .with_copy_to("/tls/server.pem", tls.server_chain_pem.as_bytes().to_vec())
    .with_copy_to("/tls/server.key", tls.server_key_pem.as_bytes().to_vec())
    .with_cmd([
        "-c",
        "mkdir -p /tmp/data /tmp/iam && \
         versitygw --port :10000 --cert /tls/server.pem --key /tls/server.key \
         --iam-dir /tmp/iam posix /tmp/data",
    ])
    .start()
    .await
    .expect("Failed to start HTTPS VersityGW container");

    let port = container.get_host_port_ipv4(10000).await.unwrap();
    let endpoint = format!("https://127.0.0.1:{}", port);
    (container, endpoint)
}

/// Build an AWS SDK `SharedHttpClient` whose rustls (aws-lc) backend
/// trusts ONLY the supplied CA PEM. Native roots are disabled so a real
/// CA can never silently substitute for the test trust anchor.
fn aws_http_client_trusting(ca_pem: &str) -> aws_sdk_s3::config::SharedHttpClient {
    use aws_smithy_http_client::Builder;
    use aws_smithy_http_client::tls::{self, TlsContext, TrustStore, rustls_provider::CryptoMode};

    let trust_store = TrustStore::empty()
        .with_native_roots(false)
        .with_pem_certificate(ca_pem.as_bytes().to_vec());
    let tls_context = TlsContext::builder()
        .with_trust_store(trust_store)
        .build()
        .expect("build TLS context");
    Builder::new()
        .tls_provider(tls::Provider::Rustls(CryptoMode::AwsLc))
        .tls_context(tls_context)
        .build_https()
}

/// Build a `reqwest::Client` whose trust store contains ONLY the supplied
/// CA PEM — native / built-in roots are explicitly disabled by
/// `tls_certs_only`, mirroring the AWS-SDK helper's
/// `TrustStore::empty().with_native_roots(false)` behaviour so a real CA
/// can never silently substitute for the test trust anchor. Used for the
/// proxy's OUTBOUND passthrough client in the HTTPS fixture —
/// `passthrough::handle_passthrough` issues requests via
/// `state.http_client` (a `reqwest::Client`), so without this the
/// passthrough route would fail TLS verification against the
/// self-signed test leaf even though the typed/decode path's AWS-SDK
/// client trusts it just fine.
fn reqwest_client_trusting(ca_pem: &str) -> reqwest::Client {
    let cert =
        reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("parse test CA PEM for reqwest");
    reqwest::Client::builder()
        .tls_certs_only(std::iter::once(cert))
        .build()
        .expect("build reqwest client trusting test CA")
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
        inbound_auth_verify_signatures: false,
        inbound_credentials_path: None,
        inbound_auth_max_skew_secs: 900,
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
        inbound_sigv4: None,
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

/// Variant of `build_proxy_stack_with_opts` that points the proxy at an
/// `https://` backend and supplies a trusting `SharedHttpClient` (CA-pinned
/// rustls) so the SDK can validate the test fixture's self-signed leaf.
/// Mirrors `build_proxy_stack_inner` line-for-line aside from the
/// `from_config_with_http_client` swap.
async fn build_proxy_stack_with_https_backend(
    backend_endpoint: &str,
    ca_pem: &str,
) -> (
    aws_sdk_s3::Client,
    reqwest::Client,
    String,
    tempfile::TempDir,
) {
    let cache_dir = tempfile::TempDir::new().expect("create temp cache dir");
    let config = default_proxy_test_config(
        backend_endpoint,
        AuthMode::TrustedInternal,
        vec![],
        cache_dir.path(),
    );

    let aws_http_client = aws_http_client_trusting(ca_pem);
    let s3_backend =
        backend::client::S3Backend::from_config_with_http_client(&config, aws_http_client)
            .await
            .expect("build S3 backend (HTTPS)");

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

    // Passthrough handler issues outbound requests via `state.http_client`
    // against the same HTTPS backend, so this reqwest client must also
    // trust the self-signed test CA — a default `reqwest::Client::new()`
    // would fail TLS verification on every passthrough request.
    let passthrough_http_client = reqwest_client_trusting(ca_pem);

    let state = Arc::new(handlers::AppState {
        backend: Arc::new(s3_backend),
        cache: Arc::new(disk_cache),
        singleflight,
        auth: authenticator,
        inbound_sigv4: None,
        policy: cache_policy,
        config: Arc::new(config),
        frontend_bucket: Arc::from(TEST_BUCKET),
        backend_bucket: Arc::from(TEST_BUCKET),
        http_client: passthrough_http_client,
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
    // Test-facing client talks to the proxy over plain HTTP — it does NOT
    // need to trust the test CA. Distinct from the `passthrough_http_client`
    // stored inside `AppState`, which DOES need the CA pinned.
    let test_http_client = reqwest::Client::new();

    (proxy_client, test_http_client, proxy_endpoint, cache_dir)
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
    //   * STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER with `x-amz-trailer:
    //     x-amz-checksum-md5`: trailer-mode with an unsupported algorithm
    //     routes to passthrough via `AwsChunkedUploadMode::OtherStreaming`.
    //     This is the only remaining shape that exercises the passthrough
    //     preflight after issue #50 PR #2 moved supported-algorithm trailer
    //     modes into the in-house decoder (which has its own preflight
    //     keyed on `x-amz-decoded-content-length`, not `Content-Length`).
    let request = format!(
        "PUT /{TEST_BUCKET}/cold-review/oversized-cl HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: 32\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: 8\r\n\
         x-amz-trailer: x-amz-checksum-md5\r\n\
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

/// Compute the canonical base64-encoded checksum for `body` under the given
/// algorithm — the value a compliant client SDK would emit in the
/// `x-amz-checksum-<algo>` trailer line.
fn compute_smithy_checksum_b64(
    algo: tiny_s3_proxy::s3::checksum::ChecksumAlgorithm,
    body: &[u8],
) -> String {
    let mut hasher = algo.into_smithy_impl();
    aws_smithy_checksums::Checksum::update(hasher.as_mut(), body);
    let bytes = aws_smithy_checksums::Checksum::finalize(hasher);
    aws_smithy_types::base64::encode(&bytes[..])
}

/// Build an unsigned-trailer aws-chunked frame: bare-size chunk header,
/// payload, final `0\r\n`, trailer line, closing `\r\n`.
fn build_unsigned_trailer_frame_bytes(
    payload: &[u8],
    trailer_name: &str,
    trailer_value: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n0\r\n");
    out.extend_from_slice(format!("{trailer_name}:{trailer_value}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// Build a signed-trailer aws-chunked frame.
fn build_signed_trailer_frame_bytes(
    payload: &[u8],
    trailer_name: &str,
    trailer_value: &str,
) -> Vec<u8> {
    const SIG: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut out = Vec::new();
    out.extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("0;chunk-signature={SIG}\r\n").as_bytes());
    out.extend_from_slice(format!("{trailer_name}:{trailer_value}\r\n").as_bytes());
    out.extend_from_slice(format!("x-amz-trailer-signature:{SIG}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// Pins the routing decision for aws-chunked TRAILER-mode uploads: trailer
/// mode with a supported algorithm routes to the in-house decoder. A
/// well-formed unsigned-trailer body must:
/// 1. Pass trailer-checksum validation (we do NOT see the 400 BadDigest
///    response that a mismatched trailer would produce).
/// 2. Reach the upstream-contact stage, which over HTTP triggers the HTTPS
///    guard (`require_https_for_unsigned_payload`) and produces 500
///    InternalError with no upstream contact.
///
/// This indirect signal pins routing because the alternative routes have
/// distinguishable response shapes:
/// - Typed PUT path: would 200 against the HTTP mock with the raw
///   aws-chunked bytes stored as the object body.
/// - Passthrough: would 200 against the HTTP mock (no HTTPS guard there).
/// - Decode path: 500 InternalError, message references the HTTPS guard,
///   mock count == 0.
///
/// Companion happy-path coverage that the upstream actually sees the
/// decoded body + per-algorithm checksum header lives in the handler-level
/// unit tests (`test_decode_put_unsigned_trailer_forwards_checksum_to_backend`),
/// which uses MockBackend and isn't subject to the HTTPS guard.
///
/// Flipped from the earlier PR #62 test that asserted passthrough — that
/// test asserted the pre-trailer-decoder behavior and is no longer valid.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_unsigned_trailer_put_routes_to_decoder() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;

    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let payload = b"abcdefgh";
    let algo = tiny_s3_proxy::s3::checksum::ChecksumAlgorithm::Crc32;
    let value = compute_smithy_checksum_b64(algo, payload);
    let frame = build_unsigned_trailer_frame_bytes(payload, algo.header_name(), &value);

    let headers = format!(
        "PUT /{TEST_BUCKET}/cold-review/aws-chunked-trailer-routing HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = frame.len(),
        payload_len = payload.len(),
    );
    let mut request_bytes = headers.into_bytes();
    request_bytes.extend_from_slice(&frame);

    let (status, raw_response) = raw_tcp_request(proxy_host, &request_bytes).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    // 500 InternalError from the HTTPS guard proves we reached the
    // upstream-contact stage. A 400 here would mean trailer validation
    // failed — the regression we're guarding against. A 200 would mean we
    // routed to typed or passthrough instead.
    assert_eq!(
        status, 500,
        "trailer mode must route to decode path (HTTPS guard fires); got status {status} \
         with body: {resp_text}",
    );
    assert!(
        resp_text.contains("InternalError"),
        "expected InternalError, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "decode path must reject HTTP upstream before contact",
    );
}

/// Sweep all five trailer algorithms (unsigned-trailer mode). For each
/// algorithm: build a frame with the canonical checksum, send through the
/// proxy, assert the request reaches the HTTPS guard (status 500
/// InternalError, zero upstream contact). Per-algorithm forwarding of the
/// checksum value to the upstream is covered by the handler unit tests.
///
/// Each algorithm is independently validated; a regression in one
/// algorithm's wiring (wrong `into_smithy_impl` mapping, wrong header name,
/// wrong digest_len) would surface as a 400 InvalidDigest / BadDigest
/// instead of the 500 we expect.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_unsigned_trailer_all_algorithms_route_to_decoder() {
    use tiny_s3_proxy::s3::checksum::ChecksumAlgorithm;

    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let payload = b"the quick brown fox";

    for algo in [
        ChecksumAlgorithm::Crc32,
        ChecksumAlgorithm::Crc32C,
        ChecksumAlgorithm::Crc64Nvme,
        ChecksumAlgorithm::Sha1,
        ChecksumAlgorithm::Sha256,
    ] {
        let value = compute_smithy_checksum_b64(algo, payload);
        let frame = build_unsigned_trailer_frame_bytes(payload, algo.header_name(), &value);
        let key = format!("trailer-sweep/{}.bin", algo.header_name());
        let headers = format!(
            "PUT /{TEST_BUCKET}/{key} HTTP/1.1\r\n\
             Host: {proxy_host}\r\n\
             Content-Length: {body_len}\r\n\
             Content-Encoding: aws-chunked\r\n\
             x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\
             x-amz-decoded-content-length: {payload_len}\r\n\
             x-amz-trailer: {trailer_name}\r\n\
             Connection: close\r\n\
             \r\n",
            body_len = frame.len(),
            payload_len = payload.len(),
            trailer_name = algo.header_name(),
        );
        let mut request = headers.into_bytes();
        request.extend_from_slice(&frame);
        let (status, raw) = raw_tcp_request(proxy_host, &request).await;
        let resp_text = String::from_utf8_lossy(&raw);
        assert_eq!(
            status, 500,
            "{algo:?}: trailer must validate and route to decode (HTTPS guard fires). \
             Got status {status} with body: {resp_text}",
        );
        assert!(
            resp_text.contains("InternalError"),
            "{algo:?}: expected InternalError, got: {resp_text}",
        );
    }
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no algorithm should contact the HTTP upstream",
    );
}

/// Signed-trailer (HMAC-SHA256) variant. Same routing assertion as the
/// unsigned sweep but with `;chunk-signature=...` extensions on every chunk
/// header plus a trailing `x-amz-trailer-signature` line.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_signed_trailer_put_routes_to_decoder() {
    use tiny_s3_proxy::s3::checksum::ChecksumAlgorithm;

    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let payload = b"abcdefgh";
    let algo = ChecksumAlgorithm::Sha256;
    let value = compute_smithy_checksum_b64(algo, payload);
    let frame = build_signed_trailer_frame_bytes(payload, algo.header_name(), &value);

    let headers = format!(
        "PUT /{TEST_BUCKET}/trailer/signed-sha256.bin HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         x-amz-trailer: x-amz-checksum-sha256\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = frame.len(),
        payload_len = payload.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(&frame);
    let (status, raw) = raw_tcp_request(proxy_host, &request).await;
    let resp_text = String::from_utf8_lossy(&raw);
    assert_eq!(
        status, 500,
        "signed-trailer must reach decode-path HTTPS guard. body: {resp_text}",
    );
    assert!(resp_text.contains("InternalError"));
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
    );
}

/// Load-bearing integrity guard: a trailer with a wrong checksum value must
/// produce a BadDigest 400 BEFORE the proxy contacts the upstream. The
/// `CountingMockUpstream`'s `received_count == 0` assertion is what makes
/// this a regression guard rather than a happy-path smoke test.
///
/// Bug-revert reasoning: removing the `if computed != expected_bytes` guard
/// in `AwsChunkedDecoder::finalize` (the same bug-revert verified by the
/// unit-level `test_trailer_checksum_mismatch_rejected`) would let this
/// request reach the upstream — `received_count` would bump to 1 and the
/// assertion would fail.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_trailer_checksum_mismatch_rejected_before_backend() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir_holder = tempfile::TempDir::new().expect("cache dir");
    let cache_dir_path = cache_dir_holder.path().to_path_buf();
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir_holder, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let payload = b"abcdefgh";
    // 4 bytes of zeros — a valid-shape CRC32 trailer value that is NOT the
    // actual CRC32 of the payload.
    let wrong_value = aws_smithy_types::base64::encode([0u8; 4]);
    let frame = build_unsigned_trailer_frame_bytes(payload, "x-amz-checksum-crc32", &wrong_value);

    let headers = format!(
        "PUT /{TEST_BUCKET}/trailer/mismatch.bin HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = frame.len(),
        payload_len = payload.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(&frame);
    let (status, raw) = raw_tcp_request(proxy_host, &request).await;
    assert_eq!(status, 400);
    let resp_text = String::from_utf8_lossy(&raw);
    assert!(
        resp_text.contains("BadDigest"),
        "expected BadDigest in response body, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "trailer checksum mismatch must reject before backend contact",
    );
    // Spool file must be cleaned up after the decode error.
    let tmp = cache_dir_path.join("tmp");
    if tmp.exists() {
        let mut entries = tokio::fs::read_dir(&tmp).await.unwrap();
        while let Some(e) = entries.next_entry().await.unwrap() {
            let name = e.file_name();
            assert!(
                !name.to_string_lossy().ends_with(".upload-spool.tmp"),
                "spool must be cleaned up after trailer mismatch, found {name:?}",
            );
        }
    }
}

/// Trailer mode declared via `x-amz-trailer` but the body has no trailer
/// line — the stream ends right after `0\r\n`. Must surface as 400
/// InvalidRequest with no backend contact.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_trailer_missing_rejected() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let payload = b"abcdefgh";
    // No trailer line: `0\r\n\r\n` ends the frame directly.
    let mut frame = Vec::new();
    frame.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(b"\r\n0\r\n\r\n");
    let headers = format!(
        "PUT /{TEST_BUCKET}/trailer/missing.bin HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = frame.len(),
        payload_len = payload.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(&frame);
    let (status, raw) = raw_tcp_request(proxy_host, &request).await;
    assert_eq!(status, 400);
    let resp_text = String::from_utf8_lossy(&raw);
    assert!(
        resp_text.contains("InvalidRequest"),
        "expected InvalidRequest, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
    );
}

/// UploadPart variant: trailer mode for multipart parts must route to the
/// decoder even though `x-amz-sdk-checksum-algorithm` (which AWS SDKs send
/// alongside `x-amz-trailer`) would normally force passthrough via the
/// multipart checksum gate. Pins the classifier-before-multipart-gate
/// ordering.
///
/// Signal: 500 InternalError from the HTTPS guard proves the request
/// reached the decode path. A 200 would mean the multipart gate forced
/// passthrough (the regression we're guarding against, since the gate
/// would happily forward the trailer framing to upstream verbatim).
#[tokio::test]
#[ignore]
async fn test_aws_chunked_unsigned_trailer_upload_part_routes_to_decoder() {
    use tiny_s3_proxy::s3::checksum::ChecksumAlgorithm;

    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir = tempfile::TempDir::new().expect("cache dir");
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let key = "trailer/upload-part-multipart.bin";
    // Small payload — the upload-part-min-size enforcement happens at
    // CompleteMultipartUpload time, not on individual parts.
    let payload = b"abcdefgh";
    let algo = ChecksumAlgorithm::Crc32;
    let value = compute_smithy_checksum_b64(algo, payload);
    let frame = build_unsigned_trailer_frame_bytes(payload, algo.header_name(), &value);

    let headers = format!(
        "PUT /{TEST_BUCKET}/{key}?partNumber=1&uploadId=fake-upload-id HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         x-amz-sdk-checksum-algorithm: CRC32\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = frame.len(),
        payload_len = payload.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(&frame);
    let (status, raw) = raw_tcp_request(proxy_host, &request).await;
    let resp_text = String::from_utf8_lossy(&raw);
    assert_eq!(
        status, 500,
        "trailer-mode UploadPart must route to decoder (HTTPS guard fires). Got: {resp_text}",
    );
    assert!(resp_text.contains("InternalError"));
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "decode path must reject HTTP upstream before contact",
    );
}

/// ECDSA-signed streaming uploads (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD`)
/// must be rejected up front with `UnsupportedSignature` (HTTP 400) rather
/// than silently routed through passthrough. The inbound `chunk-signature`
/// values are bound to the client's private key, so passthrough would
/// re-sign with the proxy backend credentials and the chunk signatures
/// would never validate on the upstream — failing fast avoids pointless
/// backend traffic.
///
/// Pins HTTP 400 + `<Code>UnsupportedSignature</Code>` + zero upstream
/// contact, so a regression that routes ECDSA back to passthrough flips
/// all three assertions.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_ecdsa_streaming_rejected_as_unsupported_signature() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
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
    let (status, raw_response) = raw_tcp_request(proxy_host, &request_bytes).await;
    assert_eq!(
        status, 400,
        "ECDSA streaming must be rejected with HTTP 400",
    );
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert!(
        resp_text.contains("<Code>UnsupportedSignature</Code>"),
        "expected UnsupportedSignature S3 error code, got: {resp_text}",
    );
    // Upstream must not have been contacted: this is the load-bearing
    // "rejected before backend contact" assertion.
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "upstream must not be contacted when ECDSA is rejected up front",
    );
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

/// Oversize chunk-header line (above `MAX_CHUNK_HEADER_LINE_BYTES`) is a
/// framing violation that must fail with `IncompleteBody` (HTTP 400), zero
/// backend contact, and no spool leak. The decoder bails out as soon as the
/// header bytes overflow the limit, before any payload is read.
///
/// Without the `MAX_CHUNK_HEADER_LINE_BYTES` cap, a misbehaving (or
/// adversarial) client could send an unbounded chunk-header line — the
/// `BufReader::read_until` call would buffer the entire line in memory.
/// This test pins the failure mode end-to-end.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_oversize_chunk_header_rejected_at_decode_path() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir_holder = tempfile::TempDir::new().expect("cache dir");
    let cache_dir_path = cache_dir_holder.path().to_path_buf();
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir_holder, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Build a chunk header whose extension byte length exceeds the cap.
    // The decoder limit is 4096 bytes per line; pad the extension with a
    // long opaque token after the (valid-shape) `chunk-signature=...` so
    // the read overruns before the line terminator.
    let padding = "x".repeat(8192);
    let oversize_line = format!(
        "8;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000;\
         pad={padding}\r\n",
    );
    let mut body: Vec<u8> = oversize_line.into_bytes();
    body.extend_from_slice(b"abcdefgh\r\n");
    body.extend_from_slice(
        b"0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        \r\n",
    );

    let headers = format!(
        "PUT /{TEST_BUCKET}/aws-chunked-oversize-header HTTP/1.1\r\n\
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
    request.extend_from_slice(&body);
    let (status, raw_response) = raw_tcp_request(proxy_host, &request).await;
    assert_eq!(
        status, 400,
        "oversize chunk header must be rejected with 400"
    );
    let resp_text = String::from_utf8_lossy(&raw_response);
    // Match the tag, not the bare substring — proves we're returning an S3
    // XML error rather than a body that happens to contain the word
    // `IncompleteBody` (e.g. a passthrough-shaped response).
    assert!(
        resp_text.contains("<Code>IncompleteBody</Code>"),
        "expected <Code>IncompleteBody</Code>, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "upstream must not be contacted when the decoder rejects oversize chunk headers",
    );
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

/// A signature-mode chunk header whose `chunk-signature=...` value is the
/// wrong length / contains non-hex bytes is a framing violation. The
/// decoder must reject it with `IncompleteBody`, never spool, and never
/// touch the backend.
///
/// This pins the structural validation the decoder performs on the
/// signature field shape — separate from cryptographic signature
/// verification, which the proxy does not do.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_bad_chunk_signature_shape_rejected_at_decode_path() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir_holder = tempfile::TempDir::new().expect("cache dir");
    let cache_dir_path = cache_dir_holder.path().to_path_buf();
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir_holder, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // 63 hex chars + 1 non-hex char `Z` → wrong shape on both axes. Either
    // the length check or the lowercase-hex check fires first; both surface
    // as a MalformedFrame → IncompleteBody.
    let body: &[u8] =
        b"8;chunk-signature=000000000000000000000000000000000000000000000000000000000000000Z\r\n\
        abcdefgh\r\n\
        0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        \r\n";
    let headers = format!(
        "PUT /{TEST_BUCKET}/aws-chunked-bad-sig-shape HTTP/1.1\r\n\
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
        "malformed chunk-signature shape must be rejected with 400"
    );
    let resp_text = String::from_utf8_lossy(&raw_response);
    // Match the tag, not the bare substring — proves the response is an
    // S3 XML error rather than a body that incidentally contains the word.
    assert!(
        resp_text.contains("<Code>IncompleteBody</Code>"),
        "expected <Code>IncompleteBody</Code>, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "upstream must not be contacted on a malformed chunk-signature",
    );
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

/// A `x-amz-decoded-content-length` that exceeds the actual decoded body
/// (here: declared 16 bytes, body only delivers an 8-byte chunk before the
/// terminating zero chunk) is a `DecodedLengthMismatch`. Must surface as
/// `IncompleteBody`, zero backend contact, no spool leak. Distinct from
/// `DecodedLengthExceeded` (oversize-during-streaming) and from the
/// oversize-against-max-config gate.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_decoded_length_mismatch_rejected_at_decode_path() {
    let mock = CountingMockUpstream::new();
    let mock_endpoint = start_counting_mock_upstream(mock.clone()).await;
    let cache_dir_holder = tempfile::TempDir::new().expect("cache dir");
    let cache_dir_path = cache_dir_holder.path().to_path_buf();
    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_opts(&mock_endpoint, cache_dir_holder, |_cfg| {}).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Body delivers 8 bytes of payload + terminating zero chunk, but the
    // header declares 16 bytes — the decoder reaches end-of-stream short
    // of the declared total and emits DecodedLengthMismatch.
    let body: &[u8] =
        b"8;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        abcdefgh\r\n\
        0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\
        \r\n";
    let headers = format!(
        "PUT /{TEST_BUCKET}/aws-chunked-length-mismatch HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\
         x-amz-decoded-content-length: 16\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(body);
    let (status, raw_response) = raw_tcp_request(proxy_host, &request).await;
    assert_eq!(
        status, 400,
        "decoded-length mismatch must be rejected with 400"
    );
    let resp_text = String::from_utf8_lossy(&raw_response);
    // Match the tag, not the bare substring — proves the response is an
    // S3 XML error rather than a body that incidentally contains the word.
    assert!(
        resp_text.contains("<Code>IncompleteBody</Code>"),
        "expected <Code>IncompleteBody</Code>, got: {resp_text}",
    );
    assert_eq!(
        mock.received_count
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "upstream must not be contacted when declared and actual decoded lengths disagree",
    );
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
    // ProxyError::Internal maps to 500 InternalError via S3Error::from_proxy_error.
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

/// Build a non-trailer signed aws-chunked frame for a single payload chunk.
/// Chunk signatures are dummy zero hex — the proxy does not cryptographically
/// verify them (it decodes and forwards). Shape:
///   `<hex-size>;chunk-signature=<64-hex>\r\n<payload>\r\n0;chunk-signature=<64-hex>\r\n\r\n`.
fn build_signed_non_trailer_frame_bytes(payload: &[u8]) -> Vec<u8> {
    const SIG: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut out = Vec::new();
    out.extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", payload.len()).as_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("0;chunk-signature={SIG}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out
}

/// End-to-end aws-chunked round-trip against a REAL HTTPS-backed VersityGW.
/// Sends an unsigned-trailer PUT with a CRC32 trailer through the proxy,
/// then reads back via a direct (trust-pinned) SDK GET against the same
/// VersityGW. Asserts the upstream sees the decoded payload bytes — proving
/// that the aws-chunked decode path actually rewrites the wire body rather
/// than just routing to it.
///
/// What this test does NOT cover: with aws-sdk-s3 1.132.0 +
/// aws-smithy-checksums 0.64.7 and the per-algorithm checksum setters
/// (`.checksum_crc32(...)` etc), the SDK does not re-frame outbound bodies
/// as aws-chunked — the outbound wire is `Content-Length: N` + raw bytes +
/// `x-amz-content-sha256: UNSIGNED-PAYLOAD` regardless of the
/// `RequestChecksumCalculation::WhenRequired` + `disable_payload_signing()`
/// overrides in `S3Backend::put_object_from_path`. Flipping those
/// overrides does NOT cause this test to fail today. It stays as a
/// forward regression guard against a future SDK / smithy revision that
/// re-introduces outbound aws-chunked framing on the decode path.
///
/// Docker + the pinned `versity/versitygw` image required.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_unsigned_trailer_crc32_full_https_backend_round_trip() {
    use tiny_s3_proxy::s3::checksum::ChecksumAlgorithm;

    let tls = generate_test_tls();
    let (_container, backend_endpoint) = start_versitygw_https(&tls).await;

    // Direct SDK client over HTTPS for bucket setup + GET verification.
    let direct_http_client = aws_http_client_trusting(&tls.ca_pem);
    let direct_client = build_raw_s3_client_with_http_client(
        &backend_endpoint,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        direct_http_client,
    )
    .await;
    direct_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket on HTTPS VersityGW");

    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_https_backend(&backend_endpoint, &tls.ca_pem).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let key = "https-backend/unsigned-trailer-crc32.bin";
    let payload: &[u8] = b"hello aws-chunked unsigned trailer over https";
    let value = compute_smithy_checksum_b64(ChecksumAlgorithm::Crc32, payload);
    let frame = build_unsigned_trailer_frame_bytes(payload, "x-amz-checksum-crc32", &value);
    let headers = format!(
        "PUT /{TEST_BUCKET}/{key} HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = frame.len(),
        payload_len = payload.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(&frame);

    let (status, raw_response) = raw_tcp_request(proxy_host, &request).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert_eq!(
        status, 200,
        "PUT through proxy to HTTPS VersityGW must succeed; got status {status} with body: {resp_text}",
    );

    // Read back DIRECTLY from VersityGW (bypassing the proxy) and assert
    // the upstream sees the decoded payload bytes. The proxy claims to
    // decode aws-chunked into a plain body before forwarding — this is
    // the load-bearing assertion.
    let get_resp = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("get_object on HTTPS VersityGW");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(
        body.as_ref(),
        payload,
        "decoded body on HTTPS VersityGW must match the original payload — if this fails the aws-chunked framing leaked through the proxy to the upstream",
    );
}

/// End-to-end aws-chunked round-trip for the SIGNED non-trailer mode
/// (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`). Same shape as the unsigned-trailer
/// test but exercises the other major decode branch — chunk-signature
/// framing without a checksum trailer. Chunk signatures are dummy zeros:
/// the proxy decodes and forwards without verifying chunk signatures
/// cryptographically.
///
/// Docker + the pinned `versity/versitygw` image required.
#[tokio::test]
#[ignore]
async fn test_aws_chunked_signed_non_trailer_full_https_backend_round_trip() {
    let tls = generate_test_tls();
    let (_container, backend_endpoint) = start_versitygw_https(&tls).await;

    let direct_http_client = aws_http_client_trusting(&tls.ca_pem);
    let direct_client = build_raw_s3_client_with_http_client(
        &backend_endpoint,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        direct_http_client,
    )
    .await;
    direct_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket on HTTPS VersityGW");

    let (_proxy_client, _http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_https_backend(&backend_endpoint, &tls.ca_pem).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let key = "https-backend/signed-non-trailer.bin";
    let payload: &[u8] = b"hello aws-chunked signed non-trailer over https";
    let frame = build_signed_non_trailer_frame_bytes(payload);
    let headers = format!(
        "PUT /{TEST_BUCKET}/{key} HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {body_len}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         Connection: close\r\n\
         \r\n",
        body_len = frame.len(),
        payload_len = payload.len(),
    );
    let mut request = headers.into_bytes();
    request.extend_from_slice(&frame);

    let (status, raw_response) = raw_tcp_request(proxy_host, &request).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert_eq!(
        status, 200,
        "signed non-trailer PUT through proxy must succeed; got status {status} with body: {resp_text}",
    );

    let get_resp = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("get_object on HTTPS VersityGW");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(
        body.as_ref(),
        payload,
        "decoded body on HTTPS VersityGW must match the original payload",
    );
}

/// Passthrough smoke test against a REAL HTTPS-backed VersityGW. A
/// `Range:` header on a GET forces the request through
/// `route_to_passthrough` (see `has_unsupported_get_modifiers`), which
/// issues outbound requests via `state.http_client` — a `reqwest::Client`.
/// That client must trust the test CA, otherwise every passthrough
/// request to the HTTPS backend fails TLS verification.
///
/// Bug-revert signal: swap `AppState.http_client` back to
/// `reqwest::Client::new()` and this test fails with a `Backend`-mapped
/// error (TLS handshake failure surfaces as HTTP 5xx from the proxy with
/// an `InternalError` / `connection/dispatch failure` body referencing
/// certificate trust).
///
/// Docker + the pinned `versity/versitygw` image required.
#[tokio::test]
#[ignore]
async fn test_passthrough_range_get_full_https_backend_round_trip() {
    let tls = generate_test_tls();
    let (_container, backend_endpoint) = start_versitygw_https(&tls).await;

    // Direct (trust-pinned) SDK client for bucket setup + seeding.
    let direct_client = build_raw_s3_client_with_http_client(
        &backend_endpoint,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        aws_http_client_trusting(&tls.ca_pem),
    )
    .await;
    direct_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket on HTTPS VersityGW");

    let key = "passthrough/range-test.bin";
    let payload: &[u8] = b"hello https passthrough world";
    direct_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .body(aws_sdk_s3::primitives::ByteStream::from(payload.to_vec()))
        .send()
        .await
        .expect("seed object on HTTPS VersityGW");

    let (_proxy_client, test_http_client, proxy_endpoint, _cache_dir) =
        build_proxy_stack_with_https_backend(&backend_endpoint, &tls.ca_pem).await;

    let url = format!("{proxy_endpoint}/{TEST_BUCKET}/{key}");
    let resp = test_http_client
        .get(&url)
        .header("Range", "bytes=0-4")
        .send()
        .await
        .expect("Range GET via proxy passthrough");
    let status = resp.status().as_u16();
    let body = resp
        .bytes()
        .await
        .expect("read passthrough response body")
        .to_vec();
    assert_eq!(
        status,
        206,
        "Range GET through proxy passthrough must return 206 Partial Content from HTTPS VersityGW; got status {status} with body: {}",
        String::from_utf8_lossy(&body),
    );
    assert_eq!(
        body.as_slice(),
        &payload[0..5],
        "passthrough response body must equal the first 5 bytes of the seeded payload",
    );
}

// ---------------------------------------------------------------------------
// Strict inbound SigV4 verification (issue #63, PR 1 of 5).
// ---------------------------------------------------------------------------
//
// These tests exercise the full pipeline: a real AWS SDK client signs a
// request, the proxy verifies it with the same key material, and the
// request hits a real VersityGW backend. Each negative path tampers with
// exactly one piece of the signed payload so the failure mode is
// unambiguous.

/// Frontend (inbound) credential pair used by strict-mode tests. Distinct
/// from `TEST_ACCESS_KEY`/`TEST_SECRET_KEY` (backend credentials), so a bug
/// that mixes them up surfaces as `InvalidAccessKeyId` instead of silently
/// passing.
const STRICT_INBOUND_KEY: &str = "AKID-FRONTEND";
const STRICT_INBOUND_SECRET: &str = "frontend-secret-do-not-leak";

/// Build a strict-mode proxy stack rooted at `backend_endpoint`. Returns
/// `(strict_sdk_client, wrong_creds_sdk_client, proxy_endpoint,
/// cache_dir_guard, creds_file_guard)`. The two SDK clients exist so each
/// test can pick the right keys for what it's exercising without having to
/// rebuild a config.
async fn build_strict_proxy_stack(
    backend_endpoint: &str,
) -> (
    aws_sdk_s3::Client,
    aws_sdk_s3::Client,
    String,
    tempfile::TempDir,
    tempfile::NamedTempFile,
) {
    use std::io::Write;

    let mut creds_file =
        tempfile::NamedTempFile::new().expect("create strict-mode credentials tempfile");
    let creds_json = serde_json::json!({
        "version": 1,
        "credentials": [
            { "access_key_id": STRICT_INBOUND_KEY, "secret_access_key": STRICT_INBOUND_SECRET }
        ]
    });
    creds_file
        .write_all(creds_json.to_string().as_bytes())
        .expect("write strict-mode credentials");

    let cache_dir = tempfile::TempDir::new().expect("create temp cache dir");
    let mut config = default_proxy_test_config(
        backend_endpoint,
        AuthMode::TrustedInternal,
        vec![],
        cache_dir.path(),
    );
    config.inbound_auth_verify_signatures = true;
    config.inbound_credentials_path = Some(creds_file.path().to_path_buf());

    let s3_backend = backend::client::S3Backend::from_config(&config)
        .await
        .expect("build S3 backend (strict mode)");

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

    let store = auth::credentials::StaticInboundCredentials::load_from_file(creds_file.path())
        .expect("load strict-mode credentials");
    let resolver: Arc<dyn auth::credentials::InboundCredentialResolver> = Arc::new(store);
    let verifier = Arc::new(auth::sigv4::SigV4Verifier::new(
        resolver,
        std::time::Duration::from_secs(config.inbound_auth_max_skew_secs),
    ));

    let state = Arc::new(handlers::AppState {
        backend: Arc::new(s3_backend),
        cache: Arc::new(disk_cache),
        singleflight,
        auth: authenticator,
        inbound_sigv4: Some(verifier),
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

    let strict_client =
        build_raw_s3_client(&proxy_endpoint, STRICT_INBOUND_KEY, STRICT_INBOUND_SECRET).await;
    let wrong_client = build_raw_s3_client(&proxy_endpoint, "BOGUS-KEY", "bogus-secret").await;

    (
        strict_client,
        wrong_client,
        proxy_endpoint,
        cache_dir,
        creds_file,
    )
}

/// Pre-create the bucket on the backend; strict-mode tests don't care
/// about its contents until they PUT/GET.
async fn ensure_test_bucket(backend_endpoint: &str) {
    let backend_client =
        build_raw_s3_client(backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    let _ = backend_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await;
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_accepts_valid_sdk_get() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;

    // Seed an object via the backend so the GET has something to return.
    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    backend_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("strict-get.txt")
        .body(b"strict-mode payload".to_vec().into())
        .send()
        .await
        .expect("seed object");

    let (strict_client, _wrong, _ep, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    let resp = strict_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("strict-get.txt")
        .send()
        .await
        .expect("strict GET should succeed");
    let body = resp.body.collect().await.unwrap().into_bytes();
    assert_eq!(body.as_ref(), b"strict-mode payload");
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_accepts_valid_sdk_put_with_signed_payload() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (strict_client, _wrong, _ep, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    // The SDK signs PUTs with a real SHA-256 of the body by default. This
    // exercises the SignedSha256 → verify_payload_hash path end-to-end.
    strict_client
        .put_object()
        .bucket(TEST_BUCKET)
        .key("strict-put.txt")
        .body(b"signed-payload-body".to_vec().into())
        .send()
        .await
        .expect("strict PUT with signed payload should succeed");

    // Round-trip: read it back.
    let backend_client =
        build_raw_s3_client(&backend_endpoint, TEST_ACCESS_KEY, TEST_SECRET_KEY).await;
    let resp = backend_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("strict-put.txt")
        .send()
        .await
        .expect("get_object after strict PUT");
    let body = resp.body.collect().await.unwrap().into_bytes();
    assert_eq!(body.as_ref(), b"signed-payload-body");
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_unknown_access_key() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (_strict, wrong_client, _ep, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    let err = wrong_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("any.txt")
        .send()
        .await
        .expect_err("wrong credentials must fail");

    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("InvalidAccessKeyId"),
        "expected InvalidAccessKeyId, got: {dbg}"
    );
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_tampered_signed_header() {
    // The SDK signs the request normally; we replay it via raw HTTP with
    // one signed header value mutated so the canonical request — and
    // therefore the signature — diverges from what the proxy computes.
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (strict_client, _wrong, proxy_endpoint, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    // Use a presign so we get to inspect the full signed request shape.
    // Actually, presigned URLs are fail-closed in strict mode, so instead
    // we drive a real PUT via the SDK and rely on the SDK adding x-amz-meta
    // headers. To produce a tamper, we make a raw request whose
    // Authorization header was signed for a different value of host.
    //
    // The simplest tamper that's robust to SDK choices: drive an unsigned
    // raw HTTP request that carries an Authorization header copied from a
    // legitimate signed request, then mutate `host`.
    let _ = strict_client; // Keep the SDK live until the proxy is fully torn down.

    let http_client = reqwest::Client::new();
    let url = format!("{proxy_endpoint}/{TEST_BUCKET}/tamper.txt");

    // Build a manually-signed PUT request, then rewrite the host header
    // before sending. The signature was computed for the original host;
    // changing it must produce SignatureDoesNotMatch.
    let body_bytes = b"tamper-test-body".to_vec();
    let body_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&body_bytes);
        let digest = h.finalize();
        let mut out = String::with_capacity(64);
        for b in digest.iter() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    };
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date_yyyymmdd = &amz_date[..8];
    let original_host = format!(
        "127.0.0.1:{}",
        proxy_endpoint
            .rsplit(':')
            .next()
            .unwrap()
            .trim_end_matches('/')
    );
    let canonical = format!(
        "PUT\n/{TEST_BUCKET}/tamper.txt\n\nhost:{original_host}\nx-amz-content-sha256:{body_hash}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{body_hash}"
    );

    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    type HmacSha256 = Hmac<Sha256>;
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    let creq_hex = {
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        let d = h.finalize();
        let mut out = String::with_capacity(64);
        for b in d.iter() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    };
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date_yyyymmdd}/us-east-1/s3/aws4_request\n{creq_hex}"
    );
    let k_date = hmac(
        format!("AWS4{STRICT_INBOUND_SECRET}").as_bytes(),
        date_yyyymmdd.as_bytes(),
    );
    let k_region = hmac(&k_date, b"us-east-1");
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature_bytes = hmac(&k_signing, sts.as_bytes());
    let signature_hex = signature_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={STRICT_INBOUND_KEY}/{date_yyyymmdd}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature_hex}"
    );

    // Now send with the WRONG host header — same Authorization line, but
    // proxy will canonicalize using the actual host header value.
    let resp = http_client
        .put(&url)
        .header("host", "evil.example")
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_hash)
        .header("authorization", &auth)
        .body(body_bytes)
        .send()
        .await
        .expect("send tampered request");
    assert_eq!(resp.status().as_u16(), 403);
    let body = resp.bytes().await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("SignatureDoesNotMatch"),
        "expected SignatureDoesNotMatch, got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_stale_date() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (_strict, _wrong, proxy_endpoint, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    let http_client = reqwest::Client::new();
    // Manually craft a request signed for a date well outside the skew
    // window (default 900s). The proxy must reject with
    // RequestTimeTooSkewed before doing the body hash check.
    let amz_date = "20200101T000000Z";
    let date_yyyymmdd = "20200101";
    let body_hash = "UNSIGNED-PAYLOAD";
    let host = proxy_endpoint
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let canonical = format!(
        "GET\n/{TEST_BUCKET}/stale.txt\n\nhost:{host}\nx-amz-content-sha256:{body_hash}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{body_hash}"
    );
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    type HmacSha256 = Hmac<Sha256>;
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    let creq_hex = {
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        hex::encode(h.finalize())
    };
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date_yyyymmdd}/us-east-1/s3/aws4_request\n{creq_hex}"
    );
    let k_date = hmac(
        format!("AWS4{STRICT_INBOUND_SECRET}").as_bytes(),
        date_yyyymmdd.as_bytes(),
    );
    let k_region = hmac(&k_date, b"us-east-1");
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, sts.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={STRICT_INBOUND_KEY}/{date_yyyymmdd}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
    );

    let resp = http_client
        .get(format!("{proxy_endpoint}/{TEST_BUCKET}/stale.txt"))
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", body_hash)
        .header("authorization", &auth)
        .send()
        .await
        .expect("stale request");
    assert_eq!(resp.status().as_u16(), 403);
    let body = String::from_utf8_lossy(&resp.bytes().await.unwrap()).to_string();
    assert!(
        body.contains("RequestTimeTooSkewed"),
        "expected RequestTimeTooSkewed, got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_body_under_signed_payload() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (_strict, _wrong, proxy_endpoint, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    // Sign a request for body "good", then send body "bad-tampered".
    let http_client = reqwest::Client::new();
    let url = format!("{proxy_endpoint}/{TEST_BUCKET}/bad-body.txt");
    let signed_body = b"good";
    let actual_body = b"bad-tampered";

    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    type HmacSha256 = Hmac<Sha256>;
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    let body_hash = hex::encode({
        let mut h = Sha256::new();
        h.update(signed_body);
        h.finalize()
    });
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date_yyyymmdd = &amz_date[..8];
    let host = proxy_endpoint
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let canonical = format!(
        "PUT\n/{TEST_BUCKET}/bad-body.txt\n\nhost:{host}\nx-amz-content-sha256:{body_hash}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{body_hash}"
    );
    let creq_hex = hex::encode({
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        h.finalize()
    });
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{date_yyyymmdd}/us-east-1/s3/aws4_request\n{creq_hex}"
    );
    let k_date = hmac(
        format!("AWS4{STRICT_INBOUND_SECRET}").as_bytes(),
        date_yyyymmdd.as_bytes(),
    );
    let k_region = hmac(&k_date, b"us-east-1");
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, sts.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={STRICT_INBOUND_KEY}/{date_yyyymmdd}/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
    );

    let resp = http_client
        .put(&url)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &body_hash)
        .header("authorization", &auth)
        .body(actual_body.to_vec())
        .send()
        .await
        .expect("send tampered body");
    assert_eq!(resp.status().as_u16(), 403);
    let body = String::from_utf8_lossy(&resp.bytes().await.unwrap()).to_string();
    assert!(
        body.contains("SignatureDoesNotMatch"),
        "expected SignatureDoesNotMatch, got: {body}"
    );
    assert!(
        body.contains("x-amz-content-sha256 mismatch"),
        "expected payload mismatch message, got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_presigned_url_as_missing_token() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (strict_client, _wrong, proxy_endpoint, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    // Use the SDK to presign a GET so we have a real X-Amz-Signature query
    // parameter on the URL — our raw HTTP call below replays it.
    let presigning =
        aws_sdk_s3::presigning::PresigningConfig::expires_in(std::time::Duration::from_secs(60))
            .expect("presigning config");
    let presigned = strict_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("presigned.txt")
        .presigned(presigning)
        .await
        .expect("presign GET");
    let uri = presigned.uri().to_string();
    // The presigned URI may point at the SDK's hostname rather than our
    // proxy; rewrite host:port portion so the request actually reaches the
    // proxy. The query string carries the X-Amz-Signature.
    let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
    let url = format!("{proxy_endpoint}/{TEST_BUCKET}/presigned.txt?{query}");

    let http_client = reqwest::Client::new();
    let resp = http_client
        .get(&url)
        .send()
        .await
        .expect("send presigned request");
    assert_eq!(resp.status().as_u16(), 403);
    let body = String::from_utf8_lossy(&resp.bytes().await.unwrap()).to_string();
    assert!(
        body.contains("MissingAuthenticationToken"),
        "expected MissingAuthenticationToken, got: {body}"
    );
}

#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_sts_token_as_invalid_token() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (_strict, _wrong, proxy_endpoint, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;

    // Build an SDK client with a session-token credential. The SDK will
    // include `x-amz-security-token` in SignedHeaders, which strict mode
    // rejects up front.
    let creds = aws_credential_types::Credentials::new(
        STRICT_INBOUND_KEY,
        STRICT_INBOUND_SECRET,
        Some("session-token-value".to_string()),
        None,
        "test",
    );
    let cfg = aws_sdk_s3::config::Builder::new()
        .endpoint_url(&proxy_endpoint)
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(creds)
        .force_path_style(true)
        .behavior_version_latest()
        .build();
    let sts_client = aws_sdk_s3::Client::from_conf(cfg);

    let err = sts_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key("sts.txt")
        .send()
        .await
        .expect_err("STS token must reject");
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("InvalidToken"),
        "expected InvalidToken, got: {dbg}"
    );
}

// ---------------------------------------------------------------------------
// Strict-mode aws-chunked signature verification (PR 2 of #63)
// ---------------------------------------------------------------------------

/// Build a strict-mode proxy stack against an HTTPS-backed VersityGW. Same
/// shape as `build_strict_proxy_stack` + `build_proxy_stack_with_https_backend`
/// — needed for the signed-aws-chunked round-trip tests where the SDK we
/// hand-roll the request for needs an HTTPS upstream the proxy can forward
/// the decoded body to.
async fn build_strict_proxy_stack_with_https_backend(
    backend_endpoint: &str,
    ca_pem: &str,
) -> (String, tempfile::TempDir, tempfile::NamedTempFile) {
    use std::io::Write;

    let mut creds_file =
        tempfile::NamedTempFile::new().expect("create strict-mode credentials tempfile");
    let creds_json = serde_json::json!({
        "version": 1,
        "credentials": [
            { "access_key_id": STRICT_INBOUND_KEY, "secret_access_key": STRICT_INBOUND_SECRET }
        ]
    });
    creds_file
        .write_all(creds_json.to_string().as_bytes())
        .expect("write strict-mode credentials");

    let cache_dir = tempfile::TempDir::new().expect("create temp cache dir");
    let mut config = default_proxy_test_config(
        backend_endpoint,
        AuthMode::TrustedInternal,
        vec![],
        cache_dir.path(),
    );
    config.inbound_auth_verify_signatures = true;
    config.inbound_credentials_path = Some(creds_file.path().to_path_buf());

    let aws_http_client = aws_http_client_trusting(ca_pem);
    let s3_backend =
        backend::client::S3Backend::from_config_with_http_client(&config, aws_http_client)
            .await
            .expect("build S3 backend (strict + HTTPS)");

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

    let store = auth::credentials::StaticInboundCredentials::load_from_file(creds_file.path())
        .expect("load strict-mode credentials");
    let resolver: Arc<dyn auth::credentials::InboundCredentialResolver> = Arc::new(store);
    let verifier = Arc::new(auth::sigv4::SigV4Verifier::new(
        resolver,
        std::time::Duration::from_secs(config.inbound_auth_max_skew_secs),
    ));

    let passthrough_http_client = reqwest_client_trusting(ca_pem);

    let state = Arc::new(handlers::AppState {
        backend: Arc::new(s3_backend),
        cache: Arc::new(disk_cache),
        singleflight,
        auth: authenticator,
        inbound_sigv4: Some(verifier),
        policy: cache_policy,
        config: Arc::new(config),
        frontend_bucket: Arc::from(TEST_BUCKET),
        backend_bucket: Arc::from(TEST_BUCKET),
        http_client: passthrough_http_client,
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

    (proxy_endpoint, cache_dir, creds_file)
}

/// Inputs for a manually-constructed signed aws-chunked PUT. Used so the
/// strict-mode tests can mint a request whose chunk signatures actually
/// validate against the strict verifier, AND so they can mutate the
/// emitted bytes (corrupt a chunk signature) to exercise the
/// `SignatureDoesNotMatch` rejection path.
struct SignedChunkedPut {
    request_bytes: Vec<u8>,
    payload_len: usize,
}

/// Sign + frame a `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` PUT request against
/// the strict-mode credentials. Returns the full HTTP/1.1 request bytes
/// suitable for `raw_tcp_request`. `chunks` is the split of the payload
/// into wire-level chunks; the helper appends the zero terminator chunk.
///
/// If `tamper_chunk_index` is `Some(i)`, the i-th chunk's signature byte
/// is flipped so the wire-level signature no longer chains. This is the
/// `expect_err`-style hook for the mismatch tests.
fn build_signed_aws_chunked_put_non_trailer(
    proxy_host: &str,
    bucket: &str,
    key: &str,
    chunks: &[&[u8]],
    tamper_chunk_index: Option<usize>,
) -> SignedChunkedPut {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    type HmacSha256 = Hmac<Sha256>;
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = HmacSha256::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date_yyyymmdd = amz_date[..8].to_string();
    let scope = format!("{date_yyyymmdd}/us-east-1/s3/aws4_request");
    let body_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

    let payload_len: usize = chunks.iter().map(|c| c.len()).sum();
    // Worked out content-length: sum of (hex-size + ";chunk-signature=" + 64 +
    // "\r\n" + chunk_len + "\r\n") for each data chunk, plus the same for
    // the zero terminator (size "0", empty payload, trailing "\r\n").
    let mut content_length: usize = 0;
    for c in chunks {
        let hex_size = format!("{:x}", c.len());
        content_length += hex_size.len() + ";chunk-signature=".len() + 64 + 2 + c.len() + 2;
    }
    // Zero chunk: "0" + ";chunk-signature=" + 64 + "\r\n" + "\r\n"
    content_length += 1 + ";chunk-signature=".len() + 64 + 2 + 2;

    // Build the canonical request. Signed headers (alphabetical):
    // content-encoding, content-length, host, x-amz-content-sha256,
    // x-amz-date, x-amz-decoded-content-length.
    let canonical = format!(
        "PUT\n/{bucket}/{key}\n\n\
         content-encoding:aws-chunked\n\
         content-length:{content_length}\n\
         host:{proxy_host}\n\
         x-amz-content-sha256:{body_hash}\n\
         x-amz-date:{amz_date}\n\
         x-amz-decoded-content-length:{payload_len}\n\n\
         content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length\n\
         {body_hash}"
    );
    let creq_hex = hex::encode({
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        h.finalize()
    });
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{creq_hex}");
    let k_date = hmac(
        format!("AWS4{STRICT_INBOUND_SECRET}").as_bytes(),
        date_yyyymmdd.as_bytes(),
    );
    let k_region = hmac(&k_date, b"us-east-1");
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let seed_signature = hex::encode(hmac(&k_signing, sts.as_bytes()));
    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={STRICT_INBOUND_KEY}/{scope}, \
         SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length, \
         Signature={seed_signature}"
    );

    // Build the body: each chunk's signature is HMAC-SHA256(kSigning, STS)
    // chained from the previous signature, with `EMPTY_SHA256_HEX` for the
    // "empty" line and the chunk SHA-256 for the "current chunk" line.
    const EMPTY_SHA256_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    fn chunk_sig(
        k_signing: &[u8],
        amz_date: &str,
        scope: &str,
        prev_sig: &str,
        chunk_hash_hex: &str,
    ) -> String {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev_sig}\n{EMPTY_SHA256_HEX}\n{chunk_hash_hex}",
        );
        let mut m = HmacSha256::new_from_slice(k_signing).unwrap();
        m.update(sts.as_bytes());
        hex::encode(m.finalize().into_bytes())
    }

    let mut body = Vec::with_capacity(content_length);
    let mut prev = seed_signature.clone();
    for (i, c) in chunks.iter().enumerate() {
        let chunk_hash = hex::encode(Sha256::digest(c));
        let mut sig = chunk_sig(&k_signing, &amz_date, &scope, &prev, &chunk_hash);
        if tamper_chunk_index == Some(i) {
            // Flip one hex char so the signature no longer matches.
            let mut sig_bytes = sig.into_bytes();
            sig_bytes[0] = if sig_bytes[0] == b'0' { b'1' } else { b'0' };
            sig = String::from_utf8(sig_bytes).unwrap();
        }
        body.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", c.len()).as_bytes());
        body.extend_from_slice(c);
        body.extend_from_slice(b"\r\n");
        prev = sig;
    }
    // Zero terminator chunk.
    let zero_sig = chunk_sig(&k_signing, &amz_date, &scope, &prev, EMPTY_SHA256_HEX);
    body.extend_from_slice(format!("0;chunk-signature={zero_sig}\r\n\r\n").as_bytes());
    assert_eq!(
        body.len(),
        content_length,
        "computed content-length mismatch"
    );

    let headers = format!(
        "PUT /{bucket}/{key} HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {content_length}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: {body_hash}\r\n\
         x-amz-date: {amz_date}\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         authorization: {auth_header}\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let mut request_bytes = headers.into_bytes();
    request_bytes.extend_from_slice(&body);
    SignedChunkedPut {
        request_bytes,
        payload_len,
    }
}

/// SDK signs a real PUT under strict mode. With `aws-sdk-s3` 1.132.0 and
/// `RequestChecksumCalculation::WhenRequired` + `disable_payload_signing()`
/// the outbound body is NOT aws-chunked, but the INBOUND request from the
/// SDK to the proxy IS signed with `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
/// when the body is bigger than the SDK's threshold. We use a manually
/// signed request instead because the SDK behaviour around inbound
/// streaming is version-dependent — driving the wire format ourselves
/// pins exactly what the strict-mode decode path is being asked to
/// validate.
///
/// Asserts: signed aws-chunked PUT decodes + uploads, GET back from
/// VersityGW returns the same bytes the test sent.
#[tokio::test]
#[ignore]
async fn test_strict_sigv4_signed_non_trailer_full_https_backend_round_trip() {
    let tls = generate_test_tls();
    let (_container, backend_endpoint) = start_versitygw_https(&tls).await;

    let direct_http_client = aws_http_client_trusting(&tls.ca_pem);
    let direct_client = build_raw_s3_client_with_http_client(
        &backend_endpoint,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        direct_http_client,
    )
    .await;
    direct_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket on HTTPS VersityGW");

    let (proxy_endpoint, _cache_dir, _creds_file) =
        build_strict_proxy_stack_with_https_backend(&backend_endpoint, &tls.ca_pem).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let key = "strict/signed-non-trailer.bin";
    // Multi-chunk: the first (non-final) chunk must be ≥ 8 KiB to clear
    // the `MIN_NON_FINAL_CHUNK_BYTES` floor, and we use a distinct second
    // chunk so the strict-mode chain-advance behavior is exercised at
    // the integration tier — not just the unit tests. With a single-chunk
    // success case, a regression that broke chain advancement (e.g.
    // failing to update `previous_signature_hex` on a verified chunk)
    // would still pass this test because there's no chunk-2 STS to
    // validate against the chained signature.
    let chunk1: Vec<u8> = vec![b'A'; 8192];
    let chunk2: Vec<u8> = b"strict-mode multi-chunk tail payload".to_vec();
    let mut full_payload = chunk1.clone();
    full_payload.extend_from_slice(&chunk2);
    let request = build_signed_aws_chunked_put_non_trailer(
        proxy_host,
        TEST_BUCKET,
        key,
        &[&chunk1, &chunk2],
        None,
    );

    let (status, raw_response) = raw_tcp_request(proxy_host, &request.request_bytes).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert_eq!(
        status, 200,
        "strict signed aws-chunked PUT must succeed; got {status} with body: {resp_text}",
    );

    // Verify the decoded bytes landed on VersityGW.
    let get_resp = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("get_object after strict signed PUT");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(body.as_ref(), full_payload.as_slice());
    assert_eq!(full_payload.len(), request.payload_len);
}

/// Same as the round-trip test but the first chunk's `chunk-signature=`
/// is corrupted. The decoder MUST reject with `SignatureDoesNotMatch`
/// rather than silently uploading the body.
///
/// Bug-revert reasoning: routing strict-mode signed aws-chunked through
/// `ChunkSignaturePolicy::ShapeOnly` (instead of `Verify`) flips this
/// assertion — the corrupt signature still passes the lowercase-hex
/// shape check, the body decodes, and the backend gets contacted.
#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_signed_aws_chunked_with_bad_chunk_signature() {
    let tls = generate_test_tls();
    let (_container, backend_endpoint) = start_versitygw_https(&tls).await;

    let direct_http_client = aws_http_client_trusting(&tls.ca_pem);
    let direct_client = build_raw_s3_client_with_http_client(
        &backend_endpoint,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        direct_http_client,
    )
    .await;
    direct_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket on HTTPS VersityGW");

    let (proxy_endpoint, _cache_dir, _creds_file) =
        build_strict_proxy_stack_with_https_backend(&backend_endpoint, &tls.ca_pem).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let key = "strict/bad-chunk-signature.bin";
    let payload: &[u8] = b"strict-mode signed aws-chunked tampered chunk signature";
    let request =
        build_signed_aws_chunked_put_non_trailer(proxy_host, TEST_BUCKET, key, &[payload], Some(0));

    let (status, raw_response) = raw_tcp_request(proxy_host, &request.request_bytes).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert_eq!(
        status, 403,
        "tampered chunk signature must produce HTTP 403; got {status} with body: {resp_text}",
    );
    assert!(
        resp_text.contains("SignatureDoesNotMatch"),
        "expected SignatureDoesNotMatch in response body; got: {resp_text}",
    );

    // Object must NOT have been written to the backend.
    let head = direct_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await;
    assert!(
        head.is_err(),
        "object must not exist on the backend after a tampered-signature PUT was rejected"
    );
}

/// Strict mode + unsigned-trailer (`STREAMING-UNSIGNED-PAYLOAD-TRAILER`)
/// still works: chunk signatures aren't part of the wire format, so the
/// decoder runs with `ChunkSignaturePolicy::ShapeOnly` regardless of
/// strict mode, and the existing trailer checksum validation continues
/// to gate integrity.
#[tokio::test]
#[ignore]
async fn test_strict_sigv4_unsigned_trailer_still_works() {
    use tiny_s3_proxy::s3::checksum::ChecksumAlgorithm;

    let tls = generate_test_tls();
    let (_container, backend_endpoint) = start_versitygw_https(&tls).await;

    let direct_http_client = aws_http_client_trusting(&tls.ca_pem);
    let direct_client = build_raw_s3_client_with_http_client(
        &backend_endpoint,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        direct_http_client,
    )
    .await;
    direct_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket on HTTPS VersityGW");

    let (proxy_endpoint, _cache_dir, _creds_file) =
        build_strict_proxy_stack_with_https_backend(&backend_endpoint, &tls.ca_pem).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Sign the request envelope with the unsigned-trailer sentinel as the
    // payload hash. Strict-mode verification will accept this because the
    // sentinel is in the canonical request and matches what we signed.
    let key = "strict/unsigned-trailer.bin";
    let payload: &[u8] = b"strict-mode unsigned trailer crc32 payload";
    let value = compute_smithy_checksum_b64(ChecksumAlgorithm::Crc32, payload);
    let frame = build_unsigned_trailer_frame_bytes(payload, "x-amz-checksum-crc32", &value);

    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date_yyyymmdd = &amz_date[..8];
    let scope = format!("{date_yyyymmdd}/us-east-1/s3/aws4_request");
    let body_hash = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    type HmacSha256 = Hmac<Sha256>;
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = HmacSha256::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }

    let content_length = frame.len();
    let canonical = format!(
        "PUT\n/{TEST_BUCKET}/{key}\n\n\
         content-encoding:aws-chunked\n\
         content-length:{content_length}\n\
         host:{proxy_host}\n\
         x-amz-content-sha256:{body_hash}\n\
         x-amz-date:{amz_date}\n\
         x-amz-decoded-content-length:{payload_len}\n\
         x-amz-trailer:x-amz-checksum-crc32\n\n\
         content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-trailer\n\
         {body_hash}",
        payload_len = payload.len(),
    );
    let creq_hex = hex::encode({
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        h.finalize()
    });
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{creq_hex}");
    let k_date = hmac(
        format!("AWS4{STRICT_INBOUND_SECRET}").as_bytes(),
        date_yyyymmdd.as_bytes(),
    );
    let k_region = hmac(&k_date, b"us-east-1");
    let k_service = hmac(&k_region, b"s3");
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, sts.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={STRICT_INBOUND_KEY}/{scope}, \
         SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-trailer, \
         Signature={signature}"
    );

    let headers = format!(
        "PUT /{TEST_BUCKET}/{key} HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {content_length}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: {body_hash}\r\n\
         x-amz-date: {amz_date}\r\n\
         x-amz-decoded-content-length: {payload_len}\r\n\
         x-amz-trailer: x-amz-checksum-crc32\r\n\
         authorization: {auth}\r\n\
         Connection: close\r\n\
         \r\n",
        payload_len = payload.len(),
    );
    let mut request_bytes = headers.into_bytes();
    request_bytes.extend_from_slice(&frame);

    let (status, raw_response) = raw_tcp_request(proxy_host, &request_bytes).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert_eq!(
        status, 200,
        "strict-mode unsigned-trailer must succeed; got {status} with body: {resp_text}",
    );

    let get_resp = direct_client
        .get_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await
        .expect("get_object after strict unsigned-trailer PUT");
    let body = get_resp
        .body
        .collect()
        .await
        .expect("read body")
        .into_bytes();
    assert_eq!(body.as_ref(), payload);
}

/// Strict mode + `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` paired with
/// an `x-amz-trailer` header whose algorithm the decoder doesn't model
/// (e.g. `x-amz-checksum-md5`) must NOT be routed to passthrough — the
/// body-route classifier downgrades the upload to `OtherStreaming →
/// Passthrough`, and passthrough re-signs with the proxy's outbound
/// credentials without verifying the inbound chunk chain. Under strict
/// mode we reject up front with `UnsupportedSignature` rather than
/// silently leaking a signed-aws-chunked upload past the chunk verifier.
///
/// Bug-revert reasoning: deleting `enforce_signed_streaming_decode_route`
/// (or removing the strict gate at the PUT dispatch site) flips this
/// from HTTP 400 `UnsupportedSignature` to passthrough-eventual-error
/// (likely 4xx/5xx from VersityGW after the re-signed body arrives).
/// The test would no longer find `UnsupportedSignature` in the body.
#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_signed_streaming_with_unsupported_trailer_algo() {
    let (_container, backend_endpoint) = start_versitygw().await;
    ensure_test_bucket(&backend_endpoint).await;
    let (_strict, _wrong, proxy_endpoint, _cache, _creds) =
        build_strict_proxy_stack(&backend_endpoint).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    // Build a SigV4-signed envelope using STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
    // and an unsupported trailer algorithm. The body content doesn't
    // matter — the dispatch-time strict gate fails closed before the
    // decoder reads a single byte.
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date_yyyymmdd = &amz_date[..8];
    let scope = format!("{date_yyyymmdd}/us-east-1/s3/aws4_request");
    let body_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
    let bucket = TEST_BUCKET;
    let key = "strict/signed-streaming-unsupported-trailer.bin";
    let body_bytes = b"AAAAAAAA".to_vec();
    let content_length = body_bytes.len();
    let decoded_len = 0u64;

    let canonical = format!(
        "PUT\n/{bucket}/{key}\n\n\
         content-encoding:aws-chunked\n\
         content-length:{content_length}\n\
         host:{proxy_host}\n\
         x-amz-content-sha256:{body_hash}\n\
         x-amz-date:{amz_date}\n\
         x-amz-decoded-content-length:{decoded_len}\n\
         x-amz-trailer:x-amz-checksum-md5\n\n\
         content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-trailer\n\
         {body_hash}",
    );
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    type HmacSha256 = Hmac<Sha256>;
    fn h(k: &[u8], d: &[u8]) -> Vec<u8> {
        let mut m = HmacSha256::new_from_slice(k).unwrap();
        m.update(d);
        m.finalize().into_bytes().to_vec()
    }
    let creq_hex = hex::encode({
        let mut hash = Sha256::new();
        hash.update(canonical.as_bytes());
        hash.finalize()
    });
    let sts = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{creq_hex}");
    let k_date = h(
        format!("AWS4{STRICT_INBOUND_SECRET}").as_bytes(),
        date_yyyymmdd.as_bytes(),
    );
    let k_region = h(&k_date, b"us-east-1");
    let k_service = h(&k_region, b"s3");
    let k_signing = h(&k_service, b"aws4_request");
    let signature = hex::encode(h(&k_signing, sts.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={STRICT_INBOUND_KEY}/{scope}, \
         SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-trailer, \
         Signature={signature}"
    );

    let headers = format!(
        "PUT /{bucket}/{key} HTTP/1.1\r\n\
         Host: {proxy_host}\r\n\
         Content-Length: {content_length}\r\n\
         Content-Encoding: aws-chunked\r\n\
         x-amz-content-sha256: {body_hash}\r\n\
         x-amz-date: {amz_date}\r\n\
         x-amz-decoded-content-length: {decoded_len}\r\n\
         x-amz-trailer: x-amz-checksum-md5\r\n\
         authorization: {auth}\r\n\
         Connection: close\r\n\
         \r\n",
    );
    let mut request_bytes = headers.into_bytes();
    request_bytes.extend_from_slice(&body_bytes);

    let (status, raw_response) = raw_tcp_request(proxy_host, &request_bytes).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert_eq!(
        status, 400,
        "signed-streaming + unsupported trailer must reject with HTTP 400 in strict mode; \
         got {status} body: {resp_text}",
    );
    assert!(
        resp_text.contains("<Code>UnsupportedSignature</Code>"),
        "expected UnsupportedSignature, got: {resp_text}",
    );
}

/// Strict mode + multi-chunk signed aws-chunked PUT where chunk index 1
/// (the second data chunk, not the first) has its signature tampered.
/// The decoder must reject with `SignatureDoesNotMatch`, and the
/// upstream must not see the body. Chunk 0's signature is correct so
/// the chain advances normally; the mismatch surfaces at chunk 1.
///
/// Bug-revert reasoning: failing to advance `previous_signature_hex`
/// after a successful chunk-0 verify leaves chunk 1's STS computed
/// against the seed signature. Chunk 1's wire-level signature in this
/// test is computed against chunk 0's signature (with one byte
/// flipped); against the seed it doesn't match either, so a buggy
/// chain-advance would still surface as `SignatureDoesNotMatch` — but
/// at chunk index 0 of the second STS, not chunk index 1. A second
/// regression — skipping the `Verify` branch entirely for chunks
/// after the first — would flip this test to 200 OK with the tampered
/// body landing on the upstream. The 403 + zero-object assertions
/// catch both classes.
#[tokio::test]
#[ignore]
async fn test_strict_sigv4_rejects_bad_signature_on_non_first_chunk() {
    let tls = generate_test_tls();
    let (_container, backend_endpoint) = start_versitygw_https(&tls).await;

    let direct_http_client = aws_http_client_trusting(&tls.ca_pem);
    let direct_client = build_raw_s3_client_with_http_client(
        &backend_endpoint,
        TEST_ACCESS_KEY,
        TEST_SECRET_KEY,
        direct_http_client,
    )
    .await;
    direct_client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket on HTTPS VersityGW");

    let (proxy_endpoint, _cache_dir, _creds_file) =
        build_strict_proxy_stack_with_https_backend(&backend_endpoint, &tls.ca_pem).await;
    let proxy_host = proxy_endpoint.strip_prefix("http://").unwrap();

    let key = "strict/bad-non-first-chunk-signature.bin";
    let chunk1: Vec<u8> = vec![b'A'; 8192];
    let chunk2: Vec<u8> = b"tail chunk to be reached after a clean chunk-0 verify".to_vec();
    let request = build_signed_aws_chunked_put_non_trailer(
        proxy_host,
        TEST_BUCKET,
        key,
        &[&chunk1, &chunk2],
        Some(1),
    );

    let (status, raw_response) = raw_tcp_request(proxy_host, &request.request_bytes).await;
    let resp_text = String::from_utf8_lossy(&raw_response);
    assert_eq!(
        status, 403,
        "tampered chunk-1 signature must produce HTTP 403; got {status} with body: {resp_text}",
    );
    assert!(
        resp_text.contains("SignatureDoesNotMatch"),
        "expected SignatureDoesNotMatch in response body; got: {resp_text}",
    );

    let head = direct_client
        .head_object()
        .bucket(TEST_BUCKET)
        .key(key)
        .send()
        .await;
    assert!(
        head.is_err(),
        "object must not exist on the backend after a tampered-chunk-1 PUT was rejected"
    );
}
