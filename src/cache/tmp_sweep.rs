//! Best-effort startup sweep of `<cache_dir>/tmp` for stale temp files left
//! by prior crashed runs (motivated by GitHub issue #43).
//!
//! Production writers join exactly one filename directly under `tmp/`. The
//! allowlist below covers every such writer; anything else is preserved.
//! The single-owner lockfile at `<cache_dir>/.lock` (see `CacheDirLock`)
//! prevents a concurrent peer from observing an in-flight temp file during
//! sweep, so removing matched names is safe.
//!
//! Allowlist (filename shape → writer):
//!   - `{pid}-{pid}-{counter}.body`            → `handlers/get.rs`: cache-fill body temp
//!   - `{pid}-{counter}.fill_id_counter.tmp`   → `cache/disk.rs`: durable fill_id counter rewrite
//!   - `{pid}-{counter}.meta.json`             → `cache/disk.rs`: commit-time metadata temp
//!   - `{pid}-{hash32}-{counter}.meta.tmp`     → `cache/disk.rs`: HEAD/access metadata rewrite
//!   - `{pid}-{counter}.prev.body`             → `cache/disk.rs`: publish-time body backup
//!   - `{pid}-{counter}.prev.meta.json`        → `cache/disk.rs`: publish-time metadata backup
//!   - `.readyz-probe`                         → `admin/health.rs`: readiness probe file
//!
//! Hand-written suffix parsers (no regex dep). Longest suffix wins: `.prev.body`
//! is matched before `.body`, `.prev.meta.json` before `.meta.json`.

use std::path::Path;

use tokio::fs;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TmpSweepKind {
    FillBody,
    FillIdCounter,
    CommitMeta,
    MetadataTmp,
    PublishBackupBody,
    PublishBackupMeta,
    ReadyzProbe,
}

impl TmpSweepKind {
    pub(super) fn as_label(self) -> &'static str {
        match self {
            Self::FillBody => "fill_body",
            Self::FillIdCounter => "fill_id_counter",
            Self::CommitMeta => "commit_meta",
            Self::MetadataTmp => "metadata_tmp",
            Self::PublishBackupBody => "publish_backup_body",
            Self::PublishBackupMeta => "publish_backup_meta",
            Self::ReadyzProbe => "readyz_probe",
        }
    }
}

impl std::fmt::Display for TmpSweepKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TmpSweepFailureReason {
    ReadDir,
    ReadEntry,
    Metadata,
    Remove,
    #[allow(dead_code)]
    Other,
}

impl TmpSweepFailureReason {
    pub(super) fn as_label(self) -> &'static str {
        match self {
            Self::ReadDir => "read_dir",
            Self::ReadEntry => "read_entry",
            Self::Metadata => "metadata",
            Self::Remove => "remove",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for TmpSweepFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_label())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TmpSweepSkipReason {
    UnknownPattern,
    NonUtf8,
    Symlink,
    NonRegular,
}

impl TmpSweepSkipReason {
    pub(super) fn as_label(self) -> &'static str {
        match self {
            Self::UnknownPattern => "unknown_pattern",
            Self::NonUtf8 => "non_utf8",
            Self::Symlink => "symlink",
            Self::NonRegular => "non_regular",
        }
    }
}

impl std::fmt::Display for TmpSweepSkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_label())
    }
}

fn is_ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_lowercase_hex_32(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_two_digit_segments(stem: &str) -> bool {
    match stem.split_once('-') {
        Some((a, b)) => is_ascii_digits(a) && is_ascii_digits(b),
        None => false,
    }
}

fn is_three_digit_segments(stem: &str) -> bool {
    let mut parts = stem.split('-');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    is_ascii_digits(a) && is_ascii_digits(b) && is_ascii_digits(c)
}

/// Classify a `tmp/`-relative filename against the allowlist. Returns
/// `Some(kind)` on match, `None` for anything else. Suffix order matters: the
/// `.prev.*` and `.meta.tmp` shapes must be checked before less-specific
/// `.body` / `.meta.json` so they aren't mis-classified.
pub(super) fn classify(name: &str) -> Option<TmpSweepKind> {
    if name == ".readyz-probe" {
        return Some(TmpSweepKind::ReadyzProbe);
    }
    if let Some(stem) = name.strip_suffix(".prev.body") {
        return is_two_digit_segments(stem).then_some(TmpSweepKind::PublishBackupBody);
    }
    if let Some(stem) = name.strip_suffix(".prev.meta.json") {
        return is_two_digit_segments(stem).then_some(TmpSweepKind::PublishBackupMeta);
    }
    if let Some(stem) = name.strip_suffix(".fill_id_counter.tmp") {
        return is_two_digit_segments(stem).then_some(TmpSweepKind::FillIdCounter);
    }
    if let Some(stem) = name.strip_suffix(".meta.tmp") {
        // `{pid}-{hash32}-{counter}` — hash is fixed-width lowercase hex with
        // no `-`, so split_once + rsplit_once is unambiguous.
        let (pid, rest) = stem.split_once('-')?;
        let (hash, counter) = rest.rsplit_once('-')?;
        return (is_ascii_digits(pid) && is_lowercase_hex_32(hash) && is_ascii_digits(counter))
            .then_some(TmpSweepKind::MetadataTmp);
    }
    if let Some(stem) = name.strip_suffix(".meta.json") {
        return is_two_digit_segments(stem).then_some(TmpSweepKind::CommitMeta);
    }
    if let Some(stem) = name.strip_suffix(".body") {
        return is_three_digit_segments(stem).then_some(TmpSweepKind::FillBody);
    }
    None
}

fn record_failed(reason: TmpSweepFailureReason) {
    metrics::counter!(
        "s3proxy_cache_tmp_sweep_failed_total",
        "reason" => reason.as_label(),
    )
    .increment(1);
}

fn record_skipped(reason: TmpSweepSkipReason) {
    metrics::counter!(
        "s3proxy_cache_tmp_sweep_skipped_total",
        "reason" => reason.as_label(),
    )
    .increment(1);
}

fn record_removed(kind: TmpSweepKind, bytes: u64) {
    metrics::counter!(
        "s3proxy_cache_tmp_sweep_removed_files_total",
        "kind" => kind.as_label(),
    )
    .increment(1);
    metrics::counter!(
        "s3proxy_cache_tmp_sweep_removed_bytes_total",
        "kind" => kind.as_label(),
    )
    .increment(bytes);
}

/// Best-effort sweep of `tmp_dir`. Removes only allowlisted filename shapes,
/// preserves everything else, and never aborts startup — any I/O error is
/// logged and counted in the `failed_total` counter. Flat (no descent).
pub(super) async fn sweep_tmp_dir(tmp_dir: &Path) {
    let mut entries = match fs::read_dir(tmp_dir).await {
        Ok(e) => e,
        Err(e) => {
            record_failed(TmpSweepFailureReason::ReadDir);
            tracing::warn!(
                path = %tmp_dir.display(),
                error = %e,
                "tmp sweep: failed to read tmp directory; skipping startup sweep"
            );
            tracing::info!(
                tmp_dir = %tmp_dir.display(),
                removed_files = 0u64,
                removed_bytes = 0u64,
                failed = 1u64,
                skipped = 0u64,
                "tmp sweep complete",
            );
            return;
        }
    };

    let mut removed_files: u64 = 0;
    let mut removed_bytes: u64 = 0;
    let mut failed: u64 = 0;
    let mut skipped: u64 = 0;

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                record_failed(TmpSweepFailureReason::ReadEntry);
                failed = failed.saturating_add(1);
                tracing::warn!(
                    path = %tmp_dir.display(),
                    error = %e,
                    "tmp sweep: read_dir entry failed; continuing"
                );
                continue;
            }
        };
        let path = entry.path();

        // symlink_metadata to inspect the entry itself without following
        // links — otherwise a dangling symlink would surface as a stat
        // failure and a valid-target symlink would look like a regular file.
        let meta = match fs::symlink_metadata(&path).await {
            Ok(m) => m,
            Err(e) => {
                record_failed(TmpSweepFailureReason::Metadata);
                failed = failed.saturating_add(1);
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "tmp sweep: stat failed; skipping entry"
                );
                continue;
            }
        };
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            record_skipped(TmpSweepSkipReason::Symlink);
            skipped = skipped.saturating_add(1);
            tracing::warn!(
                path = %path.display(),
                "tmp sweep: symlink in tmp directory; preserving"
            );
            continue;
        }
        if !file_type.is_file() {
            record_skipped(TmpSweepSkipReason::NonRegular);
            skipped = skipped.saturating_add(1);
            tracing::warn!(
                path = %path.display(),
                "tmp sweep: non-regular entry in tmp directory; preserving"
            );
            continue;
        }

        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(s) => s,
            None => {
                record_skipped(TmpSweepSkipReason::NonUtf8);
                skipped = skipped.saturating_add(1);
                tracing::warn!(
                    path = %path.display(),
                    "tmp sweep: non-UTF-8 filename in tmp directory; preserving"
                );
                continue;
            }
        };

        let kind = match classify(name) {
            Some(k) => k,
            None => {
                record_skipped(TmpSweepSkipReason::UnknownPattern);
                skipped = skipped.saturating_add(1);
                tracing::warn!(
                    path = %path.display(),
                    "tmp sweep: unrecognized filename in tmp directory; preserving"
                );
                continue;
            }
        };

        let size = meta.len();
        match fs::remove_file(&path).await {
            Ok(()) => {
                record_removed(kind, size);
                removed_files = removed_files.saturating_add(1);
                removed_bytes = removed_bytes.saturating_add(size);
            }
            Err(e) => {
                record_failed(TmpSweepFailureReason::Remove);
                failed = failed.saturating_add(1);
                tracing::warn!(
                    path = %path.display(),
                    kind = kind.as_label(),
                    error = %e,
                    "tmp sweep: failed to remove allowlisted tmp file; continuing"
                );
            }
        }
    }

    tracing::info!(
        tmp_dir = %tmp_dir.display(),
        removed_files = removed_files,
        removed_bytes = removed_bytes,
        failed = failed,
        skipped = skipped,
        "tmp sweep complete",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::DiskCache;
    use crate::cache::policy::CachePolicy;

    fn test_policy() -> CachePolicy {
        CachePolicy::new(
            vec![
                "script_bundle/".to_string(),
                "bun_bundle/".to_string(),
                "tar/".to_string(),
            ],
            512 * 1024 * 1024,
        )
    }

    /// 32 lowercase hex chars used in metadata_tmp tests.
    const HASH32: &str = "0123456789abcdef0123456789abcdef";

    /// Plant one file for each of the seven allowlist patterns. Sizes are
    /// chosen distinct per kind so the per-kind `removed_bytes_total` can be
    /// asserted unambiguously.
    struct PlantedFiles {
        fill_body: (std::path::PathBuf, u64),
        fill_id_counter: (std::path::PathBuf, u64),
        commit_meta: (std::path::PathBuf, u64),
        metadata_tmp: (std::path::PathBuf, u64),
        prev_body: (std::path::PathBuf, u64),
        prev_meta: (std::path::PathBuf, u64),
        readyz_probe: (std::path::PathBuf, u64),
    }

    async fn plant_all_patterns(tmp_dir: &std::path::Path) -> PlantedFiles {
        async fn write_n(path: &std::path::Path, n: usize) -> u64 {
            tokio::fs::write(path, vec![b'x'; n]).await.unwrap();
            n as u64
        }
        let fill_body_p = tmp_dir.join("1-1-1.body");
        let fill_body_sz = write_n(&fill_body_p, 11).await;

        let fill_id_counter_p = tmp_dir.join("2-2.fill_id_counter.tmp");
        let fill_id_counter_sz = write_n(&fill_id_counter_p, 22).await;

        let commit_meta_p = tmp_dir.join("3-3.meta.json");
        let commit_meta_sz = write_n(&commit_meta_p, 33).await;

        let metadata_tmp_p = tmp_dir.join(format!("4-{HASH32}-4.meta.tmp"));
        let metadata_tmp_sz = write_n(&metadata_tmp_p, 44).await;

        let prev_body_p = tmp_dir.join("5-5.prev.body");
        let prev_body_sz = write_n(&prev_body_p, 55).await;

        let prev_meta_p = tmp_dir.join("6-6.prev.meta.json");
        let prev_meta_sz = write_n(&prev_meta_p, 66).await;

        let readyz_p = tmp_dir.join(".readyz-probe");
        let readyz_sz = write_n(&readyz_p, 2).await;

        PlantedFiles {
            fill_body: (fill_body_p, fill_body_sz),
            fill_id_counter: (fill_id_counter_p, fill_id_counter_sz),
            commit_meta: (commit_meta_p, commit_meta_sz),
            metadata_tmp: (metadata_tmp_p, metadata_tmp_sz),
            prev_body: (prev_body_p, prev_body_sz),
            prev_meta: (prev_meta_p, prev_meta_sz),
            readyz_probe: (readyz_p, readyz_sz),
        }
    }

    fn assert_removed_kind(rendered: &str, kind: &str, count: u64, bytes: u64) {
        let files_line =
            format!("s3proxy_cache_tmp_sweep_removed_files_total{{kind=\"{kind}\"}} {count}");
        let bytes_line =
            format!("s3proxy_cache_tmp_sweep_removed_bytes_total{{kind=\"{kind}\"}} {bytes}");
        assert!(
            rendered.contains(&files_line),
            "expected `{files_line}` in rendered metrics, got:\n{rendered}",
        );
        assert!(
            rendered.contains(&bytes_line),
            "expected `{bytes_line}` in rendered metrics, got:\n{rendered}",
        );
    }

    /// Bug-revert guard for the whole sweep: every allowlisted pattern must
    /// be removed and each kind's `removed_*_total` counter must be bumped
    /// with the expected file count and size.
    #[tokio::test(flavor = "current_thread")]
    async fn test_tmp_sweep_removes_all_allowlisted_patterns() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();

        let planted = plant_all_patterns(&tmp_dir).await;

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let cache = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .expect("DiskCache::new should succeed");
        drop(cache);

        for (label, (path, _)) in [
            ("fill_body", &planted.fill_body),
            ("fill_id_counter", &planted.fill_id_counter),
            ("commit_meta", &planted.commit_meta),
            ("metadata_tmp", &planted.metadata_tmp),
            ("publish_backup_body", &planted.prev_body),
            ("publish_backup_meta", &planted.prev_meta),
            ("readyz_probe", &planted.readyz_probe),
        ] {
            assert!(
                !path.exists(),
                "{label} file should be removed by sweep: {}",
                path.display(),
            );
        }

        let rendered = handle.render();
        assert_removed_kind(&rendered, "fill_body", 1, planted.fill_body.1);
        assert_removed_kind(&rendered, "fill_id_counter", 1, planted.fill_id_counter.1);
        assert_removed_kind(&rendered, "commit_meta", 1, planted.commit_meta.1);
        assert_removed_kind(&rendered, "metadata_tmp", 1, planted.metadata_tmp.1);
        assert_removed_kind(&rendered, "publish_backup_body", 1, planted.prev_body.1);
        assert_removed_kind(&rendered, "publish_backup_meta", 1, planted.prev_meta.1);
        assert_removed_kind(&rendered, "readyz_probe", 1, planted.readyz_probe.1);
    }

    /// Files outside the allowlist (random names, near-miss patterns,
    /// subdirectories) must be preserved, each preserved entry must produce
    /// a WARN log, and the rendered Prometheus surface must report exact
    /// per-reason skip counts.
    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn test_tmp_sweep_preserves_unknown_files_and_warns() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();

        let random_path = tmp_dir.join("random.txt");
        tokio::fs::write(&random_path, b"a").await.unwrap();
        let notes_path = tmp_dir.join("notes.md");
        tokio::fs::write(&notes_path, b"b").await.unwrap();
        // Near-miss: looks like a fill_body but the middle segment is not digits.
        let near_miss_path = tmp_dir.join("12345-foo-9.body");
        tokio::fs::write(&near_miss_path, b"c").await.unwrap();

        let subdir = tmp_dir.join("subfolder");
        tokio::fs::create_dir(&subdir).await.unwrap();
        let inside = subdir.join("inside.txt");
        tokio::fs::write(&inside, b"d").await.unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let cache = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .expect("DiskCache::new should succeed");
        drop(cache);

        assert!(random_path.exists(), "random.txt must survive sweep");
        assert!(notes_path.exists(), "notes.md must survive sweep");
        assert!(
            near_miss_path.exists(),
            "near-miss .body must survive sweep"
        );
        assert!(subdir.is_dir(), "subdir must survive sweep");
        assert!(inside.exists(), "file inside subdir must survive sweep");

        // Each preserved entry must produce a WARN log mentioning its path.
        assert!(logs_contain("tmp sweep: unrecognized filename"));
        assert!(logs_contain("random.txt"));
        assert!(logs_contain("notes.md"));
        assert!(logs_contain("12345-foo-9.body"));
        assert!(logs_contain("tmp sweep: non-regular entry"));
        assert!(logs_contain("subfolder"));

        let rendered = handle.render();
        assert!(
            rendered
                .contains("s3proxy_cache_tmp_sweep_skipped_total{reason=\"unknown_pattern\"} 3"),
            "expected 3 unknown_pattern skips, got:\n{rendered}",
        );
        assert!(
            rendered.contains("s3proxy_cache_tmp_sweep_skipped_total{reason=\"non_regular\"} 1"),
            "expected 1 non_regular skip, got:\n{rendered}",
        );
    }

    /// A zero-byte allowlisted file is still allowlisted — it must be
    /// removed and its 0-byte size recorded.
    #[tokio::test(flavor = "current_thread")]
    async fn test_tmp_sweep_removes_zero_byte_allowlisted_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();

        let zero_path = tmp_dir.join("1-1.fill_id_counter.tmp");
        tokio::fs::write(&zero_path, b"").await.unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let cache = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .expect("DiskCache::new should succeed");
        drop(cache);

        assert!(
            !zero_path.exists(),
            "zero-byte allowlisted file must be removed",
        );
        let rendered = handle.render();
        assert!(
            rendered.contains(
                "s3proxy_cache_tmp_sweep_removed_files_total{kind=\"fill_id_counter\"} 1",
            ),
            "expected fill_id_counter removed=1, got:\n{rendered}",
        );
        assert!(
            rendered.contains(
                "s3proxy_cache_tmp_sweep_removed_bytes_total{kind=\"fill_id_counter\"} 0",
            ),
            "expected fill_id_counter removed_bytes=0, got:\n{rendered}",
        );
    }

    /// Symlinks and subdirectories must be preserved even when the symlink's
    /// name matches an allowlist pattern. The skip reasons must be
    /// classified separately.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_tmp_sweep_preserves_symlink_and_subdir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();

        // Symlink whose name LOOKS allowlisted (fill_body shape). It points
        // at /dev/null; using symlink_metadata in the sweep means we never
        // follow the link, so a missing target is irrelevant.
        let link_path = tmp_dir.join("1-2-3.body");
        std::os::unix::fs::symlink("/dev/null", &link_path).unwrap();

        let subdir = tmp_dir.join("scratch");
        tokio::fs::create_dir(&subdir).await.unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let cache = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .expect("DiskCache::new should succeed");
        drop(cache);

        std::fs::symlink_metadata(&link_path).expect("symlink must still exist after sweep");
        assert!(subdir.is_dir(), "subdir must still exist after sweep");

        let rendered = handle.render();
        assert!(
            rendered.contains("s3proxy_cache_tmp_sweep_skipped_total{reason=\"symlink\"} 1"),
            "expected 1 symlink skip, got:\n{rendered}",
        );
        assert!(
            rendered.contains("s3proxy_cache_tmp_sweep_skipped_total{reason=\"non_regular\"} 1"),
            "expected 1 non_regular skip, got:\n{rendered}",
        );
    }

    /// End-to-end metrics check via the local Prometheus recorder with a
    /// mixture of allowlisted, unknown, symlink, and zero-byte entries. Pins
    /// the rendered exposition surface — guards against silent removal of a
    /// metric series or label.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_tmp_sweep_metrics_emit_via_recorder() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();

        let allow_path = tmp_dir.join("7-7.meta.json");
        tokio::fs::write(&allow_path, vec![b'x'; 17]).await.unwrap();
        let zero_path = tmp_dir.join("8-8.fill_id_counter.tmp");
        tokio::fs::write(&zero_path, b"").await.unwrap();
        let unknown_path = tmp_dir.join("totally-random-name");
        tokio::fs::write(&unknown_path, b"q").await.unwrap();
        let link_path = tmp_dir.join("1-2-3.body");
        std::os::unix::fs::symlink("/dev/null", &link_path).unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let cache = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .expect("DiskCache::new should succeed");
        drop(cache);

        let rendered = handle.render();
        // Allowlisted removals
        assert!(
            rendered
                .contains("s3proxy_cache_tmp_sweep_removed_files_total{kind=\"commit_meta\"} 1",),
            "expected commit_meta removed=1, got:\n{rendered}",
        );
        assert!(
            rendered
                .contains("s3proxy_cache_tmp_sweep_removed_bytes_total{kind=\"commit_meta\"} 17",),
            "expected commit_meta bytes=17, got:\n{rendered}",
        );
        assert!(
            rendered.contains(
                "s3proxy_cache_tmp_sweep_removed_files_total{kind=\"fill_id_counter\"} 1",
            ),
            "expected fill_id_counter removed=1, got:\n{rendered}",
        );
        // Skips
        assert!(
            rendered
                .contains("s3proxy_cache_tmp_sweep_skipped_total{reason=\"unknown_pattern\"} 1",),
            "expected 1 unknown_pattern skip, got:\n{rendered}",
        );
        assert!(
            rendered.contains("s3proxy_cache_tmp_sweep_skipped_total{reason=\"symlink\"} 1"),
            "expected 1 symlink skip, got:\n{rendered}",
        );
        // Survivors still on disk
        assert!(unknown_path.exists());
        std::fs::symlink_metadata(&link_path).unwrap();
        assert!(!allow_path.exists());
        assert!(!zero_path.exists());
    }

    /// `chmod 0o000` on the tmp directory makes `read_dir` fail with EACCES.
    /// The sweep must NOT abort startup: `DiskCache::new` returns Ok, the
    /// `failed_total{reason="read_dir"}` counter is incremented exactly once,
    /// and a WARN log is emitted.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn test_tmp_sweep_read_dir_failure_warns_and_continues() {
        use std::os::unix::fs::PermissionsExt;

        #[cfg(unix)]
        struct ChmodOnDrop {
            path: std::path::PathBuf,
            original: std::fs::Permissions,
        }
        #[cfg(unix)]
        impl ChmodOnDrop {
            fn new(path: &std::path::Path) -> Self {
                let original = std::fs::metadata(path).unwrap().permissions();
                Self {
                    path: path.to_path_buf(),
                    original,
                }
            }
        }
        #[cfg(unix)]
        impl Drop for ChmodOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.path, self.original.clone());
            }
        }

        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        // Pre-create tmp/ ourselves so DiskCache::new's create_dir_all is a
        // no-op and the chmod survives into the sweep.
        let tmp_dir = cache_dir.join("tmp");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();
        let _restore = ChmodOnDrop::new(&tmp_dir);
        std::fs::set_permissions(&tmp_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let cache = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .expect("DiskCache::new must remain Ok when sweep read_dir fails");
        drop(cache);

        let rendered = handle.render();
        assert!(
            rendered.contains("s3proxy_cache_tmp_sweep_failed_total{reason=\"read_dir\"} 1"),
            "expected failed_total{{reason=\"read_dir\"}} == 1, got:\n{rendered}",
        );
        assert!(
            logs_contain("tmp sweep: failed to read tmp directory"),
            "expected WARN log for read_dir failure",
        );
    }

    // Unit-level coverage for `classify`. Keeps the parser surface pinned
    // independently of the integration tests above so a regression in
    // suffix ordering or digit/hex predicates fails fast.
    #[test]
    fn test_classify_matches_each_pattern() {
        assert_eq!(classify(".readyz-probe"), Some(TmpSweepKind::ReadyzProbe));
        assert_eq!(classify("1-2-3.body"), Some(TmpSweepKind::FillBody));
        assert_eq!(
            classify("99-7.fill_id_counter.tmp"),
            Some(TmpSweepKind::FillIdCounter),
        );
        assert_eq!(classify("4-5.meta.json"), Some(TmpSweepKind::CommitMeta));
        assert_eq!(
            classify(&format!("6-{HASH32}-2.meta.tmp")),
            Some(TmpSweepKind::MetadataTmp),
        );
        assert_eq!(
            classify("8-9.prev.body"),
            Some(TmpSweepKind::PublishBackupBody),
        );
        assert_eq!(
            classify("8-9.prev.meta.json"),
            Some(TmpSweepKind::PublishBackupMeta),
        );
    }

    #[test]
    fn test_classify_rejects_unknown_shapes() {
        assert_eq!(classify("readme.md"), None);
        assert_eq!(classify("12345.body"), None); // only one segment
        assert_eq!(classify("a-b-c.body"), None); // non-digits
        assert_eq!(classify("1-2.body"), None); // fill_body needs three segments
        assert_eq!(classify("1-2-3-4.body"), None); // too many segments
        // hash too short
        assert_eq!(classify("1-deadbeef-2.meta.tmp"), None);
        // hash uppercase
        assert_eq!(
            classify("1-0123456789ABCDEF0123456789ABCDEF-2.meta.tmp"),
            None,
        );
        // .meta.json with three segments belongs to no pattern
        assert_eq!(classify("1-2-3.meta.json"), None);
    }

    /// Suffix ordering regression: `.prev.body` must NOT be classified as a
    /// fill_body even though it also ends in `.body`. Same for `.prev.meta.json`
    /// vs `.meta.json`.
    #[test]
    fn test_classify_prefers_longest_matching_suffix() {
        assert_eq!(
            classify("1-2.prev.body"),
            Some(TmpSweepKind::PublishBackupBody),
        );
        assert_eq!(
            classify("1-2.prev.meta.json"),
            Some(TmpSweepKind::PublishBackupMeta),
        );
    }

    #[test]
    fn test_label_round_trips() {
        for kind in [
            TmpSweepKind::FillBody,
            TmpSweepKind::FillIdCounter,
            TmpSweepKind::CommitMeta,
            TmpSweepKind::MetadataTmp,
            TmpSweepKind::PublishBackupBody,
            TmpSweepKind::PublishBackupMeta,
            TmpSweepKind::ReadyzProbe,
        ] {
            assert_eq!(kind.to_string(), kind.as_label());
        }
        for reason in [
            TmpSweepFailureReason::ReadDir,
            TmpSweepFailureReason::ReadEntry,
            TmpSweepFailureReason::Metadata,
            TmpSweepFailureReason::Remove,
            TmpSweepFailureReason::Other,
        ] {
            assert_eq!(reason.to_string(), reason.as_label());
        }
        for reason in [
            TmpSweepSkipReason::UnknownPattern,
            TmpSweepSkipReason::NonUtf8,
            TmpSweepSkipReason::Symlink,
            TmpSweepSkipReason::NonRegular,
        ] {
            assert_eq!(reason.to_string(), reason.as_label());
        }
    }
}
