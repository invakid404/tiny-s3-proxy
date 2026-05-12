//! Helpers shared between the aws-chunked PUT and UploadPart paths.
//!
//! The bulk of this module is the `UploadSpoolGuard`: it owns a single
//! temporary file under `<cache_dir>/tmp/` that the decoded body bytes are
//! streamed into before the SDK uploads them. The guard ensures the spool
//! file is removed exactly once — explicitly via `cleanup()` on the happy
//! path, or as a best-effort Drop fallback for panics/early returns.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs::{File, OpenOptions};

/// Process-local counter feeding the filename pattern
/// `{pid}-{counter}.upload-spool.tmp`. Combined with the PID, this guarantees
/// uniqueness across concurrent spools without coordinating with peers.
static UPLOAD_SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Owns the lifecycle of one decoded-body spool file. Drop is a best-effort
/// backstop; callers should explicitly `.cleanup().await` on both the happy
/// and error paths so failures to delete are logged.
pub(super) struct UploadSpoolGuard {
    path: PathBuf,
    armed: bool,
}

impl UploadSpoolGuard {
    /// Create a fresh spool file under `<cache_dir>/tmp/`. Returns the guard
    /// plus an open `File` handle positioned at offset 0 with write
    /// permission. Uses `create_new` so collisions with a stale file abort
    /// rather than silently overwrite.
    pub(super) async fn create(cache_dir: &Path) -> std::io::Result<(Self, File)> {
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await?;

        let pid = std::process::id();
        let counter = UPLOAD_SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = tmp_dir.join(format!("{pid}-{counter}.upload-spool.tmp"));

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await?;

        Ok((
            Self {
                path,
                armed: true,
            },
            file,
        ))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the spool file. Disarms the Drop fallback so the file is
    /// removed exactly once. Returns the underlying I/O error if removal
    /// fails — callers can decide whether to log/escalate.
    pub(super) async fn cleanup(mut self) -> std::io::Result<()> {
        self.armed = false;
        tokio::fs::remove_file(&self.path).await
    }
}

impl Drop for UploadSpoolGuard {
    fn drop(&mut self) {
        if self.armed {
            // Best-effort sync removal; the async runtime may already be
            // tearing down. Errors are intentionally swallowed because Drop
            // can run during a panic and we can't return them anyway. The
            // startup tmp sweep will pick up any survivors on next boot.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spool_create_writes_into_tmp_subdir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (guard, mut file) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        let path = guard.path().to_path_buf();
        assert!(path.starts_with(tmp.path().join("tmp")));
        assert!(path.exists());

        use tokio::io::AsyncWriteExt;
        file.write_all(b"hello").await.unwrap();
        file.flush().await.unwrap();
        drop(file);

        let body = tokio::fs::read(&path).await.unwrap();
        assert_eq!(body, b"hello");

        guard.cleanup().await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn test_spool_drop_removes_file_when_not_cleaned_up() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = {
            let (guard, _file) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
            let path = guard.path().to_path_buf();
            assert!(path.exists());
            path
        };
        // Guard dropped — Drop runs the best-effort sync remove.
        assert!(!path.exists(), "Drop should remove the spool file");
    }

    #[tokio::test]
    async fn test_spool_concurrent_creates_use_unique_filenames() {
        // Two concurrent spools must not collide on the same filename.
        let tmp = tempfile::TempDir::new().unwrap();
        let (g1, _f1) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        let (g2, _f2) = UploadSpoolGuard::create(tmp.path()).await.unwrap();
        assert_ne!(g1.path(), g2.path());
    }

}
