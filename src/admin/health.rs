use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use http::StatusCode;

/// Liveness check — always returns 200 if the process is alive.
pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness check — returns 200 when the cache directory is writable.
pub async fn ready_check(State(state): State<Arc<super::AdminState>>) -> impl IntoResponse {
    let probe = state.cache_dir.join("tmp").join(".readyz-probe");
    match tokio::fs::write(&probe, b"ok").await {
        Ok(_) => {
            let _ = tokio::fs::remove_file(&probe).await;
            (StatusCode::OK, "ready")
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "cache directory not writable",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use http::StatusCode;

    #[tokio::test]
    async fn test_health_check_returns_200() {
        let resp = health_check().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_body_content() {
        let resp = health_check().await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn test_ready_check_writable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        // Create the tmp subdir that readyz probes
        std::fs::create_dir_all(tmp.path().join("tmp")).unwrap();
        let state = Arc::new(super::super::AdminState {
            prometheus_handle: metrics_exporter_prometheus::PrometheusBuilder::new()
                .build_recorder()
                .handle(),
            cache_dir: tmp.path().to_path_buf(),
        });
        let resp = ready_check(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), b"ready");
    }

    #[tokio::test]
    async fn test_ready_check_non_writable_dir() {
        // Point at a path that doesn't exist — write will fail
        let state = Arc::new(super::super::AdminState {
            prometheus_handle: metrics_exporter_prometheus::PrometheusBuilder::new()
                .build_recorder()
                .handle(),
            cache_dir: std::path::PathBuf::from("/nonexistent/path/that/does/not/exist"),
        });
        let resp = ready_check(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(body.as_ref(), b"cache directory not writable");
    }
}
