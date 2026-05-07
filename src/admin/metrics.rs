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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn test_metrics_handler_returns_200() {
        let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();
        let resp = metrics_handler(State(handle)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        // Check content-type header
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "text/plain; version=0.0.4");
    }

    #[tokio::test]
    async fn test_metrics_handler_returns_valid_utf8_body() {
        let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .build_recorder()
            .handle();
        let resp = metrics_handler(State(handle)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        // Body must be valid UTF-8 (prometheus text exposition format).
        let text = std::str::from_utf8(&body).expect("metrics body must be valid UTF-8");
        // The body must not contain any non-ASCII control characters that
        // would indicate binary/corrupt output.
        assert!(
            !text
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\r'),
            "metrics body should not contain control characters"
        );
    }
}
