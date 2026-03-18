use axum::response::IntoResponse;
use http::StatusCode;

/// Liveness check — always returns 200 if the process is alive.
pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Readiness check — returns 200 when the service is ready to serve.
/// For v1, this is the same as liveness.
pub async fn ready_check() -> impl IntoResponse {
    (StatusCode::OK, "ready")
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
    async fn test_ready_check_returns_200() {
        let resp = ready_check().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
