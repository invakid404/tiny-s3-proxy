pub mod health;
pub mod metrics;

use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;

/// Build the admin HTTP router (health checks + Prometheus metrics).
pub fn build_admin_router(prometheus_handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(health::health_check))
        .route("/readyz", axum::routing::get(health::ready_check))
        .route("/metrics", axum::routing::get(metrics::metrics_handler))
        .with_state(prometheus_handle)
}
