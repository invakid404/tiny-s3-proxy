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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt; // for oneshot

    fn test_router() -> Router {
        let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();
        build_admin_router(handle)
    }

    #[tokio::test]
    async fn test_healthz_returns_200() {
        let app = test_router();
        let req = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_readyz_returns_200() {
        let app = test_router();
        let req = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_200() {
        let app = test_router();
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
        let app = test_router();
        let req = Request::builder()
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 404);
    }
}
