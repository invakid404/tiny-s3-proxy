use std::path::PathBuf;
use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;

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
    tracing::info!(
        s3_addr = %config.s3_listen_addr,
        admin_addr = %config.admin_listen_addr,
        backend_endpoint = %config.backend_endpoint,
        backend_bucket = %config.backend_bucket,
        frontend_bucket = %config.frontend_bucket,
        cache_dir = %config.cache_dir,
        auth_mode = ?config.auth_mode,
        "starting tiny-s3-proxy"
    );

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
        PathBuf::from(&config.cache_dir),
        config.cache_max_bytes,
        cache_policy.clone(),
    )
    .await?;

    // Grab the stats reference from DiskCache before wrapping in Arc
    let disk_cache = Arc::new(disk_cache);
    let eviction_stats = disk_cache.stats_ref().clone();
    tracing::info!(cache_dir = %config.cache_dir, "disk cache initialized");

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
    let eviction_cache_dir = PathBuf::from(&config.cache_dir);
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
        prometheus_handle: setup_metrics(),
        cache_dir: PathBuf::from(&config.cache_dir),
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
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    builder
        .install_recorder()
        .expect("failed to install metrics recorder")
}
