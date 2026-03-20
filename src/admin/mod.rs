pub mod health;
pub mod metrics;

use std::sync::Arc;

use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;

/// Shared state for the admin router.
pub struct AdminState {
    pub prometheus_handle: PrometheusHandle,
    pub cache_dir: std::path::PathBuf,
}

/// Build the admin HTTP router (health checks + Prometheus metrics).
pub fn build_admin_router(state: AdminState) -> Router {
    let shared = Arc::new(state);

    // Health/readyz routes share Arc<AdminState>; metrics uses PrometheusHandle.
    let health_routes = Router::new()
        .route("/healthz", axum::routing::get(health::health_check))
        .route("/readyz", axum::routing::get(health::ready_check))
        .with_state(Arc::clone(&shared));

    let metrics_routes = Router::new()
        .route("/metrics", axum::routing::get(metrics::metrics_handler))
        .with_state(shared.prometheus_handle.clone());

    health_routes.merge(metrics_routes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt; // for oneshot

    fn test_router() -> (Router, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("tmp")).unwrap();
        let state = AdminState {
            prometheus_handle: metrics_exporter_prometheus::PrometheusBuilder::new()
                .build_recorder()
                .handle(),
            cache_dir: tmp.path().to_path_buf(),
        };
        (build_admin_router(state), tmp)
    }

    #[tokio::test]
    async fn test_healthz_returns_200() {
        let (app, _tmp) = test_router();
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_readyz_returns_200() {
        let (app, _tmp) = test_router();
        let req = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_200() {
        let (app, _tmp) = test_router();
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(ct.contains("text/plain"));
    }

    #[tokio::test]
    async fn test_unknown_route_returns_404() {
        let (app, _tmp) = test_router();
        let req = Request::builder()
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 404);
    }
}
