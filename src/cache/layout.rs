use std::path::{Path, PathBuf};

/// Result of enumerating cache hash directories under `objects/XX/YY/`.
pub(super) struct HashDirCollection {
    pub(super) dirs: Vec<PathBuf>,
    pub(super) incomplete: bool,
}

#[derive(Clone, Copy)]
enum WalkMode {
    Strict,
    BestEffort,
}

fn contextual_io_error(
    operation: &'static str,
    path: &Path,
    error: std::io::Error,
) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}

fn handle_walk_error(
    mode: WalkMode,
    incomplete: &mut bool,
    operation: &'static str,
    path: &Path,
    error: std::io::Error,
    message: &'static str,
) -> Result<(), std::io::Error> {
    match mode {
        WalkMode::Strict => Err(contextual_io_error(operation, path, error)),
        WalkMode::BestEffort => {
            *incomplete = true;
            tracing::warn!(path = %path.display(), error = %error, "{message}");
            Ok(())
        }
    }
}

async fn collect_hash_dirs_inner(
    objects_dir: &Path,
    mode: WalkMode,
) -> Result<HashDirCollection, std::io::Error> {
    let mut collection = HashDirCollection {
        dirs: Vec::new(),
        incomplete: false,
    };

    let mut d1_entries = match tokio::fs::read_dir(objects_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(collection),
        Err(e) => {
            handle_walk_error(
                mode,
                &mut collection.incomplete,
                "read objects dir",
                objects_dir,
                e,
                "failed to read objects directory during cache scan",
            )?;
            return Ok(collection);
        }
    };

    loop {
        let d1_entry = match d1_entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                handle_walk_error(
                    mode,
                    &mut collection.incomplete,
                    "iterate objects dir",
                    objects_dir,
                    e,
                    "failed to iterate objects directory during cache scan",
                )?;
                break;
            }
        };
        let d1_path = d1_entry.path();
        if !d1_path.is_dir() {
            continue;
        }

        let mut d2_entries = match tokio::fs::read_dir(&d1_path).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                handle_walk_error(
                    mode,
                    &mut collection.incomplete,
                    "read hash prefix dir",
                    &d1_path,
                    e,
                    "failed to read cache subtree during scan",
                )?;
                continue;
            }
        };

        loop {
            let d2_entry = match d2_entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(e) => {
                    handle_walk_error(
                        mode,
                        &mut collection.incomplete,
                        "iterate hash prefix dir",
                        &d1_path,
                        e,
                        "failed to iterate cache subtree during scan",
                    )?;
                    break;
                }
            };
            let d2_path = d2_entry.path();
            if !d2_path.is_dir() {
                continue;
            }
            collection.dirs.push(d2_path);
        }
    }

    Ok(collection)
}

pub(super) async fn collect_hash_dirs_best_effort(objects_dir: &Path) -> HashDirCollection {
    match collect_hash_dirs_inner(objects_dir, WalkMode::BestEffort).await {
        Ok(collection) => collection,
        Err(_) => unreachable!("best-effort hash dir walk should not fail"),
    }
}

pub(super) async fn collect_hash_dirs_strict(
    objects_dir: &Path,
) -> Result<Vec<PathBuf>, std::io::Error> {
    collect_hash_dirs_inner(objects_dir, WalkMode::Strict)
        .await
        .map(|collection| collection.dirs)
}
