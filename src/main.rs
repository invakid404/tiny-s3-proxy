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
    let config = Arc::new(config);

    // 3. Create auth
    let auth = Arc::from(auth::create_authenticator(&config));

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
    let eviction_stats = disk_cache.stats_ref().clone();
    tracing::info!(cache_dir = %config.cache_dir, "disk cache initialized");

    let singleflight = Arc::new(cache::SingleFlight::new());

    // 6. Build shared app state
    let state = Arc::new(handlers::AppState {
        backend: Arc::new(backend),
        cache: Arc::new(disk_cache),
        singleflight: singleflight.clone(),
        auth,
        policy: cache_policy,
        config: config.clone(),
        frontend_bucket: Arc::from(config.frontend_bucket.as_str()),
        backend_bucket: Arc::from(config.backend_bucket.as_str()),
        http_client: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(config.upstream_connect_timeout_ms))
            .timeout(std::time::Duration::from_millis(config.upstream_request_timeout_ms))
            .build()
            .expect("failed to build HTTP client"),
    });

    // 7. Spawn eviction loop
    let eviction_cache_dir = PathBuf::from(&config.cache_dir);
    let eviction_max = config.cache_max_bytes;
    let eviction_interval = config.cache_eviction_interval_secs;
    tokio::spawn(async move {
        cache::eviction::run_eviction_loop(
            eviction_cache_dir,
            eviction_max,
            eviction_interval,
            eviction_stats,
        )
        .await;
    });

    // 8. Set up Prometheus metrics recorder
    let prometheus_handle = setup_metrics();

    // 9. Build S3 router
    let s3_app = build_s3_router(state);

    // 10. Build admin router
    let admin_app = admin::build_admin_router(prometheus_handle);

    // 11. Start both listeners
    let s3_addr: std::net::SocketAddr = config.s3_listen_addr.parse()?;
    let admin_addr: std::net::SocketAddr = config.admin_listen_addr.parse()?;

    tracing::info!(%s3_addr, "S3 listener starting");
    tracing::info!(%admin_addr, "admin listener starting");

    let s3_listener = tokio::net::TcpListener::bind(s3_addr).await?;
    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;

    // Run both servers concurrently; exit if either fails.
    tokio::select! {
        result = axum::serve(s3_listener, s3_app) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "S3 server error");
            }
        }
        result = axum::serve(admin_listener, admin_app) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "admin server error");
            }
        }
    }

    Ok(())
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
