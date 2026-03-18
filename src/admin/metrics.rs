use axum::extract::State;
use axum::response::IntoResponse;
use http::StatusCode;
use metrics_exporter_prometheus::PrometheusHandle;

/// Serve Prometheus metrics in text exposition format.
pub async fn metrics_handler(State(handle): State<PrometheusHandle>) -> impl IntoResponse {
    let metrics = handle.render();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics,
    )
}
