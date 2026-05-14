use std::sync::Arc;

use metrics_exporter_prometheus::{Matcher, PrometheusHandle};

use tiny_s3_proxy::admin;
use tiny_s3_proxy::auth;
use tiny_s3_proxy::backend;
use tiny_s3_proxy::cache;
use tiny_s3_proxy::config;
use tiny_s3_proxy::handlers;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // 2. Load config
    let config = config::Config::from_env().expect("Failed to load configuration");
    log_startup_config(&config);

    if config.auth_mode == config::AuthMode::TrustedInternal {
        tracing::warn!(
            "AUTH_MODE is trusted_internal: ALL requests are accepted without authentication. \
             This is only safe behind a trusted network boundary (e.g. VPC)."
        );
    }

    if config.cacheable_prefixes.is_empty() {
        tracing::warn!(
            "CACHEABLE_PREFIXES is empty — all GET requests will bypass the cache. \
             Set CACHEABLE_PREFIXES to enable caching for specific key prefixes."
        );
    }

    let config = Arc::new(config);

    // Install the Prometheus recorder before any cache or eviction code runs
    // so the startup scan and the first eviction tick are captured. The
    // returned handle is plumbed into the admin router below.
    let prometheus_handle = setup_metrics();

    // 3. Create auth
    let auth = Arc::from(auth::create_request_gate(&config));

    // 4. Create backend
    let backend = backend::client::S3Backend::from_config(&config).await?;
    tracing::info!("backend S3 client initialized");

    // 5. Create cache
    let cache_policy = cache::policy::CachePolicy::new(
        config.cacheable_prefixes.clone(),
        config.cache_max_object_bytes,
    );
    let disk_cache = cache::DiskCache::new(
        config.cache_dir.clone(),
        config.cache_max_bytes,
        cache_policy.clone(),
    )
    .await?;

    // Grab the stats reference from DiskCache before wrapping in Arc
    let disk_cache = Arc::new(disk_cache);
    let eviction_stats = disk_cache.stats_ref().clone();
    tracing::info!(cache_dir = %config.cache_dir.display(), "disk cache initialized");

    let singleflight = Arc::new(cache::SingleFlight::new());

    // 6. Build shared app state
    let state = Arc::new(handlers::AppState {
        backend: Arc::new(backend),
        cache: disk_cache.clone(),
        singleflight: singleflight.clone(),
        auth,
        policy: cache_policy,
        config: config.clone(),
        frontend_bucket: Arc::from(config.frontend_bucket.as_str()),
        backend_bucket: Arc::from(config.backend_bucket.as_str()),
        // Locked-down passthrough client:
        // - No redirect following: S3 3xx responses must reach the client unchanged.
        // - No system proxy: the proxy re-signs requests with backend credentials,
        //   so honoring HTTP_PROXY/HTTPS_PROXY would leak creds and object data.
        // - Connect + read timeouts only (no hard total deadline) so streaming
        //   uploads/downloads are not cut off.
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_millis(
                config.upstream_connect_timeout_ms,
            ))
            .read_timeout(std::time::Duration::from_millis(
                config.upstream_request_timeout_ms,
            ))
            .build()
            .expect("failed to build HTTP client"),
    });

    // 7. Spawn eviction loop
    let eviction_cache_dir = config.cache_dir.clone();
    let eviction_max = config.cache_max_bytes;
    let eviction_interval = config.cache_eviction_interval_secs;
    let eviction_disk_cache = disk_cache.clone();
    tokio::spawn(async move {
        cache::eviction::run_eviction_loop(
            eviction_cache_dir,
            eviction_max,
            eviction_interval,
            eviction_stats,
            Some(eviction_disk_cache),
        )
        .await;
    });

    // 8. Build S3 router
    let s3_app = build_s3_router(state);

    // 9. Build admin router
    let admin_state = admin::AdminState {
        prometheus_handle,
        cache_dir: config.cache_dir.clone(),
    };
    let admin_app = admin::build_admin_router(admin_state);

    // 11. Start both listeners
    let s3_addr: std::net::SocketAddr = config.s3_listen_addr.parse()?;
    let admin_addr: std::net::SocketAddr = config.admin_listen_addr.parse()?;

    tracing::info!(%s3_addr, "S3 listener starting");
    tracing::info!(%admin_addr, "admin listener starting");

    let s3_listener = tokio::net::TcpListener::bind(s3_addr).await?;
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;

    // Run both servers concurrently with graceful shutdown.
    // Both listeners receive the same shutdown signal via a watch channel
    // and are awaited with try_join! so both fully drain before exit.
    //
    // Subscribe BEFORE spawning the signal task so there is no window
    // where send(true) could fire before the receivers exist (a watch
    // receiver created after send() treats the value as already-seen
    // and changed().await would block forever).
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let mut s3_shutdown_rx = shutdown_tx.subscribe();
    let mut admin_shutdown_rx = shutdown_tx.subscribe();

    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let s3_shutdown = async move {
        let _ = s3_shutdown_rx.changed().await;
    };
    let admin_shutdown = async move {
        let _ = admin_shutdown_rx.changed().await;
    };

    let s3_future = axum::serve(s3_listener, s3_app).with_graceful_shutdown(s3_shutdown);
    let admin_future =
        axum::serve(admin_listener, admin_app).with_graceful_shutdown(admin_shutdown);

    let (s3_result, admin_result) = tokio::try_join!(s3_future, admin_future)?;
    // try_join! returns Ok(((), ())) when both complete. If either returns
    // Err, it propagates immediately. The graceful shutdown signal ensures
    // both servers stop accepting new connections and drain in-flight
    // requests before returning.
    let _ = (s3_result, admin_result);

    tracing::info!("shutdown complete");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("shutdown signal received, draining connections...");
}

/// Emit the structured "starting" event for the loaded config. Extracted so
/// the redaction of `backend_endpoint` (which may carry `user:pass@` userinfo)
/// can be exercised by a unit test — `config.backend_endpoint` itself is left
/// untouched so the SDK still gets the raw URL.
fn log_startup_config(config: &config::Config) {
    let redacted_backend_endpoint = config::redact_url_userinfo(&config.backend_endpoint);

    tracing::info!(
        s3_addr = %config.s3_listen_addr,
        admin_addr = %config.admin_listen_addr,
        backend_endpoint = %redacted_backend_endpoint,
        backend_bucket = %config.backend_bucket,
        frontend_bucket = %config.frontend_bucket,
        cache_dir = %config.cache_dir.display(),
        auth_mode = ?config.auth_mode,
        "starting tiny-s3-proxy"
    );
}

/// Build the S3 router. All requests are routed through the S3 handler via fallback.
fn build_s3_router<B, C>(state: Arc<handlers::AppState<B, C>>) -> axum::Router
where
    B: backend::Backend + 'static,
    C: cache::CacheStore + 'static,
{
    axum::Router::new()
        .fallback(handlers::handle_s3_request)
        .with_state(state)
}

/// Install the Prometheus metrics recorder globally and return a handle
/// for rendering collected metrics.
fn setup_metrics() -> PrometheusHandle {
    // Override buckets only for the cache scan duration histogram so the
    // existing request-duration histograms keep their default-builder
    // (summary-shaped) rendering. The default builder emits histograms
    // without bucket series, so the new metric needs an explicit override
    // to be rendered as a Prometheus histogram with bucket lines.
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("s3proxy_cache_scan_duration_seconds".to_string()),
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0,
            ],
        )
        .expect("failed to configure cache scan duration buckets");
    builder
        .install_recorder()
        .expect("failed to install metrics recorder")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tiny_s3_proxy::config::{AuthMode, Config};

    fn config_with_backend_endpoint(endpoint: &str) -> Config {
        Config {
            s3_listen_addr: "0.0.0.0:8080".to_string(),
            admin_listen_addr: "0.0.0.0:9090".to_string(),
            frontend_bucket: "test-frontend".to_string(),
            auth_mode: AuthMode::TrustedInternal,
            allowed_frontend_keys: vec![],
            backend_endpoint: endpoint.to_string(),
            backend_region: "auto".to_string(),
            backend_bucket: "test-backend".to_string(),
            backend_access_key_id: "AKID".to_string(),
            backend_secret_access_key: "secret".to_string(),
            backend_use_path_style: true,
            backend_allow_http: false,
            cache_dir: std::path::PathBuf::from("/tmp/test-cache"),
            cache_max_bytes: 1024 * 1024,
            cache_max_object_bytes: 512 * 1024,
            cacheable_prefixes: vec![],
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

    /// The startup log must show the host/port/path of `BACKEND_ENDPOINT`
    /// (operators need it to debug connectivity) but never the userinfo —
    /// users sometimes embed credentials there, and process logs may flow
    /// to less-trusted log sinks. Pin the contract: redacted form present,
    /// raw user/pass tokens absent.
    #[test]
    #[tracing_test::traced_test]
    fn test_log_startup_config_redacts_backend_endpoint_userinfo() {
        let config =
            config_with_backend_endpoint("https://alice:supersecret@s3.example.com:9443/root");
        log_startup_config(&config);

        assert!(
            logs_contain("starting tiny-s3-proxy"),
            "expected the structured 'starting' event in captured logs"
        );
        assert!(
            logs_contain("https://s3.example.com:9443/root"),
            "expected redacted backend endpoint to appear in logs"
        );
        assert!(
            !logs_contain("alice"),
            "userinfo username must not appear in startup logs"
        );
        assert!(
            !logs_contain("supersecret"),
            "userinfo password must not appear in startup logs"
        );
    }
}
