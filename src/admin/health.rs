use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use http::StatusCode;

use crate::cache::perms::open_file_secure;
use tokio::io::AsyncWriteExt;

/// Liveness check — always returns 200 if the process is alive.
pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Write the readyz probe file at `path` with `SECURE_FILE_MODE`. Extracted
/// so tests can exercise the exact same writer the handler uses without
/// racing `ready_check`'s immediate `remove_file`. `create(true).truncate(true)`
/// matches the original `tokio::fs::write` semantics: replace any stale
/// probe file (e.g. from a previous crash) rather than fail.
async fn write_readyz_probe(path: &Path) -> std::io::Result<()> {
    let mut f = open_file_secure(path, |o| {
        o.write(true).create(true).truncate(true);
    })
    .await?;
    f.write_all(b"ok").await
}

/// Readiness check — returns 200 when the cache directory is writable.
pub async fn ready_check(State(state): State<Arc<super::AdminState>>) -> impl IntoResponse {
    let probe = state.cache_dir.join("tmp").join(".readyz-probe");
    let result = write_readyz_probe(&probe).await;
    let _ = tokio::fs::remove_file(&probe).await;
    if result.is_ok() {
        (StatusCode::OK, "ready")
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "cache directory not writable",
        )
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

    /// Pin the readyz probe permissions contract from issue #66:
    /// `write_readyz_probe` (the writer `ready_check` uses) must produce
    /// a file at 0o600 on Unix. Tested via the extracted helper to avoid
    /// racing `ready_check`'s immediate `remove_file`.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_readyz_probe_written_with_0o600_mode() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let tmp_dir = tmp.path().join("tmp");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let probe = tmp_dir.join(".readyz-probe");

        write_readyz_probe(&probe).await.unwrap();

        let mode = std::fs::metadata(&probe).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "readyz probe must be 0o600, got {mode:#o}");
    }
}
