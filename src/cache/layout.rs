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

/// Cache shard directories are always two lowercase hex chars (see
/// `CacheKey::dir_prefix` and the lowercase `{:02x}` formatter used to
/// derive hashes). Anything else under `objects/` is unrelated to our
/// layout and must not be walked — otherwise unrelated subtrees could
/// be picked up by the scan and their files mistaken for orphan
/// `.body` / `.poisoned` / `.meta.json` entries during eviction.
fn is_hash_shard_name(name: &std::ffi::OsStr) -> bool {
    let Some(s) = name.to_str() else {
        return false;
    };
    s.len() == 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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
        if !is_hash_shard_name(&d1_entry.file_name()) {
            continue;
        }
        match d1_entry.file_type().await {
            Ok(ft) if ft.is_dir() => {}
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                handle_walk_error(
                    mode,
                    &mut collection.incomplete,
                    "check hash prefix dir type",
                    &d1_path,
                    e,
                    "failed to check cache subtree type during scan",
                )?;
                continue;
            }
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
            if !is_hash_shard_name(&d2_entry.file_name()) {
                continue;
            }
            match d2_entry.file_type().await {
                Ok(ft) if ft.is_dir() => {
                    collection.dirs.push(d2_path);
                }
                Ok(_) => continue,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    handle_walk_error(
                        mode,
                        &mut collection.incomplete,
                        "check hash cache dir type",
                        &d2_path,
                        e,
                        "failed to check cache subtree type during scan",
                    )?;
                    continue;
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn is_hash_shard_name_accepts_lowercase_hex_pairs() {
        assert!(is_hash_shard_name(OsStr::new("00")));
        assert!(is_hash_shard_name(OsStr::new("ab")));
        assert!(is_hash_shard_name(OsStr::new("0f")));
        assert!(is_hash_shard_name(OsStr::new("ff")));
    }

    #[test]
    fn is_hash_shard_name_rejects_invalid_names() {
        // Wrong length
        assert!(!is_hash_shard_name(OsStr::new("")));
        assert!(!is_hash_shard_name(OsStr::new("a")));
        assert!(!is_hash_shard_name(OsStr::new("abc")));
        assert!(!is_hash_shard_name(OsStr::new("0000")));
        // Uppercase (cache writes lowercase only)
        assert!(!is_hash_shard_name(OsStr::new("AB")));
        assert!(!is_hash_shard_name(OsStr::new("aB")));
        assert!(!is_hash_shard_name(OsStr::new("Ab")));
        // Non-hex
        assert!(!is_hash_shard_name(OsStr::new("zz")));
        assert!(!is_hash_shard_name(OsStr::new("g0")));
        assert!(!is_hash_shard_name(OsStr::new("..")));
        assert!(!is_hash_shard_name(OsStr::new(".x")));
    }

    #[tokio::test]
    async fn walk_skips_non_hex_siblings_under_objects() {
        let tmp = tempfile::TempDir::new().unwrap();
        let objects_dir = tmp.path().join("objects");
        // Valid shard path: objects/ab/cd/
        let valid = objects_dir.join("ab").join("cd");
        tokio::fs::create_dir_all(&valid).await.unwrap();
        // Non-hex sibling at d1 level — must NOT be collected.
        tokio::fs::create_dir_all(objects_dir.join("not-a-shard"))
            .await
            .unwrap();
        // Wrong-case sibling at d1 level — must NOT be collected.
        tokio::fs::create_dir_all(objects_dir.join("AB").join("cd"))
            .await
            .unwrap();
        // Non-hex sibling at d2 level under a valid d1 — must NOT be collected.
        tokio::fs::create_dir_all(objects_dir.join("ab").join("zz"))
            .await
            .unwrap();
        // Stray file at d1 level — must NOT be collected.
        tokio::fs::write(objects_dir.join("README"), b"hi")
            .await
            .unwrap();

        let dirs = collect_hash_dirs_strict(&objects_dir).await.unwrap();
        assert_eq!(
            dirs,
            vec![valid],
            "only the canonical lowercase-hex shard path should be collected"
        );

        let best_effort = collect_hash_dirs_best_effort(&objects_dir).await;
        assert!(!best_effort.incomplete);
        let mut be_dirs = best_effort.dirs;
        be_dirs.sort();
        assert_eq!(be_dirs, vec![objects_dir.join("ab").join("cd")]);
    }
}
