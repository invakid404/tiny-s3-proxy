//! Secure default permissions for cache-tree files and directories.
//!
//! On Unix, the proxy creates cache files with `0600` and cache directories
//! with `0700`. Group/other access is never granted to any path the proxy
//! creates inside `CACHE_DIR`. Operators who pre-create `CACHE_DIR` with
//! looser permissions keep their setting — `create_dir_secure` logs a
//! warning and leaves the directory alone rather than silently chmod'ing
//! operator-owned state. On non-Unix targets the helpers fall back to the
//! platform default (Windows ACLs are a different model).
//!
//! Use these wrappers everywhere a writer creates or replaces a file under
//! `CACHE_DIR`: passing `mode(0o600)` to `OpenOptions` directly still works,
//! but the helpers keep the policy in one place and ensure new writers
//! inherit it.

use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Mode for newly-created cache files (owner read/write only).
pub(crate) const SECURE_FILE_MODE: u32 = 0o600;

/// Mode for newly-created cache directories (owner read/write/execute only).
pub(crate) const SECURE_DIR_MODE: u32 = 0o700;

/// Bits in a Unix file mode that indicate group or other access. Used to
/// detect "loose" pre-existing directories.
#[cfg(unix)]
const GROUP_OTHER_BITS: u32 = 0o077;

/// Create a directory at `path` with `SECURE_DIR_MODE`. If the directory
/// already exists, leaves it alone — when its mode allows group/other
/// access, emits a `warn!` so operators see the divergence but the proxy
/// does not silently chmod operator-owned state.
///
/// On non-Unix this is a thin wrapper around `create_dir` (or no-op when
/// the directory exists) without mode bits.
pub(crate) async fn create_dir_secure(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        match tokio::fs::DirBuilder::new()
            .mode(SECURE_DIR_MODE)
            .create(path)
            .await
        {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                warn_if_loose_dir(path).await;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(unix))]
    {
        match tokio::fs::create_dir(path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Like `create_dir_secure` but creates missing parent components too.
/// Each newly-created level uses `SECURE_DIR_MODE`. Existing parents are
/// not chmod'd; loose existing dirs are warned about exactly once each.
pub(crate) async fn create_dir_all_secure(path: &Path) -> io::Result<()> {
    let mut stack: Vec<&Path> = Vec::new();
    let mut current = path.parent();
    while let Some(p) = current {
        match tokio::fs::metadata(p).await {
            Ok(m) if m.is_dir() => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a directory", p.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                stack.push(p);
                current = p.parent();
            }
            Err(e) => return Err(e),
        }
    }
    for p in stack.into_iter().rev() {
        create_dir_secure(p).await?;
    }
    // Always pass the leaf through `create_dir_secure` so its
    // warn-and-leave contract fires even when the target already exists.
    create_dir_secure(path).await
}

/// Open a file at `path` with `SECURE_FILE_MODE`. The `configure` closure
/// runs after the helper has set the secure mode and is the place to set
/// flags like `write` / `read` / `create_new` / `truncate` / `append`.
///
/// Callers that want create-or-open semantics should call `configure` to
/// set `.create(true)` (umask still drops the listed bits and our explicit
/// `0o600` mode is honored when the file is freshly created).
pub(crate) async fn open_file_secure<F>(path: &Path, configure: F) -> io::Result<tokio::fs::File>
where
    F: FnOnce(&mut tokio::fs::OpenOptions),
{
    let mut opts = tokio::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        opts.mode(SECURE_FILE_MODE);
    }
    configure(&mut opts);
    opts.open(path).await
}

/// Atomically create `path` and write `contents` to it with
/// `SECURE_FILE_MODE`. Errors with `AlreadyExists` if `path` is present —
/// callers wanting replace semantics should write to a tmp path under
/// `CACHE_DIR/tmp/` and rename into place.
pub(crate) async fn write_file_secure(path: &Path, contents: &[u8]) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut file = open_file_secure(path, |o| {
        o.write(true).create_new(true);
    })
    .await?;
    file.write_all(contents).await?;
    file.flush().await?;
    Ok(())
}

/// Sync counterpart to `open_file_secure` for blocking call sites like the
/// `<cache_dir>/.lock` open path (which uses `fs2::FileExt` on a
/// `std::fs::File`).
pub(crate) fn open_std_file_secure<F>(path: &Path, configure: F) -> io::Result<std::fs::File>
where
    F: FnOnce(&mut std::fs::OpenOptions),
{
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(SECURE_FILE_MODE);
    }
    configure(&mut opts);
    opts.open(path)
}

/// Tighten an existing file's mode to `SECURE_FILE_MODE`. Used after
/// `rename` operations (e.g. publishing a `.prev.body` backup) where the
/// renamed file inherits its original creation mode and may have been
/// created before this hardening shipped. No-op on non-Unix.
pub(crate) async fn tighten_file_mode(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(SECURE_FILE_MODE)).await
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(unix)]
async fn warn_if_loose_dir(path: &Path) {
    match tokio::fs::metadata(path).await {
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o7777;
            if mode & GROUP_OTHER_BITS != 0 {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:#o}", mode),
                    "cache directory pre-exists with group/other access; \
                     leaving operator-set permissions intact — proxy will \
                     not silently chmod operator-owned state"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "cache directory pre-exists but stat failed; cannot check \
                 permissions"
            );
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[tokio::test]
    async fn test_create_dir_secure_creates_with_0700() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("fresh");
        create_dir_secure(&target).await.unwrap();
        assert_eq!(mode_of(&target), 0o700);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_create_dir_secure_warns_and_leaves_existing_loose_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("preexisting");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();

        create_dir_secure(&target).await.unwrap();

        // Mode unchanged — the proxy must not silently tighten operator state.
        assert_eq!(mode_of(&target), 0o755);
        assert!(logs_contain(
            "cache directory pre-exists with group/other access"
        ));
    }

    #[tokio::test]
    async fn test_create_dir_secure_idempotent_on_already_tight_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("tight");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        create_dir_secure(&target).await.unwrap();
        assert_eq!(mode_of(&target), 0o700);
    }

    #[tokio::test]
    async fn test_create_dir_all_secure_creates_each_level_with_0700() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("a").join("b").join("c");
        create_dir_all_secure(&target).await.unwrap();
        assert_eq!(mode_of(&tmp.path().join("a")), 0o700);
        assert_eq!(mode_of(&tmp.path().join("a").join("b")), 0o700);
        assert_eq!(mode_of(&target), 0o700);
    }

    #[tokio::test]
    async fn test_open_file_secure_creates_with_0600() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("fresh.bin");
        let _f = open_file_secure(&target, |o| {
            o.write(true).create_new(true);
        })
        .await
        .unwrap();
        assert_eq!(mode_of(&target), 0o600);
    }

    #[tokio::test]
    async fn test_write_file_secure_creates_with_0600() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("fresh.txt");
        write_file_secure(&target, b"hello").await.unwrap();
        assert_eq!(mode_of(&target), 0o600);
        let contents = std::fs::read(&target).unwrap();
        assert_eq!(contents, b"hello");
    }

    #[tokio::test]
    async fn test_write_file_secure_refuses_to_replace() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("conflict.txt");
        std::fs::write(&target, b"original").unwrap();
        let err = write_file_secure(&target, b"new").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn test_open_std_file_secure_creates_with_0600() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("std.bin");
        let _f = open_std_file_secure(&target, |o| {
            o.write(true).create_new(true);
        })
        .unwrap();
        assert_eq!(mode_of(&target), 0o600);
    }

    #[tokio::test]
    async fn test_tighten_file_mode_sets_0600() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = tmp.path().join("loose.txt");
        std::fs::write(&target, b"data").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        tighten_file_mode(&target).await.unwrap();
        assert_eq!(mode_of(&target), 0o600);
    }
}
