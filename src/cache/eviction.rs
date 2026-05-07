use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::cache::metadata::CacheMeta;

use super::CacheStats;
use super::layout::collect_hash_dirs_strict;
use super::scan::{CACHE_HASH_DIR_SCAN_CONCURRENCY, bounded_parallel_scan};

/// Per-pass observability fields shared between the success summary log and
/// the `cache_unreclaimed_bytes` gauge. Populated incrementally as the pass
/// progresses; consumed at the end of `run_eviction_pass_inner`.
struct EvictionPassSummary {
    hash_dirs: usize,
    candidate_count: u64,
    candidate_bytes: u64,
    deferred_cleanup_count: u64,
    deferred_cleanup_failed: u64,
    scan_total_bytes: u64,
    max_bytes: u64,
    over_budget_bytes_before: u64,
    evicted: u64,
    final_size_bytes: u64,
    over_budget_bytes_after: u64,
}

/// Finite failure-classification enum used as the `reason` label for
/// `s3proxy_cache_scan_failed_total{phase="eviction"}`. Each error-returning
/// site in the eviction scan path constructs an [`EvictionScanError`] with
/// the matching variant; the label is recorded directly via
/// [`ScanFailureReason::as_label`] without any string parsing. Keeping the
/// classification typed means a renamed error message in an unrelated PR
/// cannot silently degrade the metric to `reason="other"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanFailureReason {
    /// `tokio::fs::try_exists(objects_dir)` failed before any walk began.
    ObjectsDirProbe,
    /// Strict layout walk over `objects/XX/YY/` returned an I/O error.
    HashDirWalk,
    /// Per-shard scan inside `scan_hash_dir_for_eviction` failed (read_dir,
    /// next_entry, metadata, or non-UTF-8 filename).
    HashDirScan,
    /// `bounded_parallel_scan` reported a `JoinError` (a shard task panicked).
    Join,
    /// `process_deferred_cleanups` skipped, partially failed, or aborted.
    DeferredCleanup,
    /// Reserved for unforeseen error paths. Should stay empty in practice
    /// because every existing return site maps explicitly above.
    #[allow(dead_code)]
    Other,
}

impl ScanFailureReason {
    fn as_label(self) -> &'static str {
        match self {
            Self::ObjectsDirProbe => "objects_dir_probe",
            Self::HashDirWalk => "hash_dir_walk",
            Self::HashDirScan => "hash_dir_scan",
            Self::Join => "join",
            Self::DeferredCleanup => "deferred_cleanup",
            Self::Other => "other",
        }
    }
}

/// Tagged eviction-scan error: the reason variant carries the metric label
/// directly so the failure-path metric can be emitted without inspecting the
/// inner error's display string.
#[derive(Debug)]
struct EvictionScanError {
    reason: ScanFailureReason,
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl EvictionScanError {
    fn new(
        reason: ScanFailureReason,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self {
            reason,
            source: source.into(),
        }
    }
}

impl std::fmt::Display for EvictionScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "eviction scan failure ({}): {}",
            self.reason.as_label(),
            self.source
        )
    }
}

impl std::error::Error for EvictionScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

/// Construct an [`EvictionScanError`] from an `io::Error` while preserving
/// the operation/path context that the existing log lines and tests expect.
fn eviction_io_error(
    reason: ScanFailureReason,
    operation: &'static str,
    path: &std::path::Path,
    error: std::io::Error,
) -> EvictionScanError {
    EvictionScanError::new(
        reason,
        std::io::Error::new(
            error.kind(),
            format!("{operation} {}: {error}", path.display()),
        ),
    )
}

/// Entry info for eviction sorting.
#[derive(Debug)]
struct EvictionCandidate {
    body_path: PathBuf,
    meta_path: PathBuf,
    hash: String,
    fill_id: u64,
    last_accessed_at: chrono::DateTime<chrono::Utc>,
    size: u64,
}

/// Per-directory scan results collected by a parallel task.
struct DirScanResult {
    candidates: Vec<EvictionCandidate>,
    total_bytes: u64,
    entry_count: u64,
    /// Orphans and corrupt entries that need cleanup under per-key locks.
    /// Each item is `(file_path, hash, OrphanKind)`.
    deferred_cleanups: Vec<DeferredCleanup>,
}

/// The three files that make up a cache entry.
struct EntryPaths {
    meta_path: PathBuf,
    body_path: PathBuf,
    poison_path: PathBuf,
    hash: String,
}

/// Deferred cleanup actions that require per-key lock coordination.
enum DeferredCleanup {
    /// Body file exists without matching metadata.
    OrphanBody { body_path: PathBuf, hash: String },
    /// Poisoned marker exists without matching metadata.
    OrphanPoison { poison_path: PathBuf, hash: String },
    /// Corrupt or unparseable metadata — re-read under lock, delete if
    /// still corrupt.
    CorruptEntry(EntryPaths),
    /// Malformed hash filename stem — unconditionally delete all files.
    MalformedHash(EntryPaths),
    /// Body was missing on initial probe — needs locked recheck.
    MissingBody(EntryPaths),
}

/// Run the eviction loop as a background task.
///
/// Periodically scans the cache directory, reconciles stats against filesystem
/// reality, and evicts the least-recently-accessed entries when the total cache
/// size exceeds `max_bytes`.
///
/// ## Stats reconciliation model
///
/// Cache stats (`total_bytes`, `entry_count`) follow a "periodic reconciliation"
/// model instead of trying to maintain perfect incremental accuracy:
///
/// - **This scan is the source of truth.** [`collect_candidates`] walks the
///   entire cache directory and computes authoritative totals from the actual
///   filesystem state, then overwrites the atomics.
/// - **Between scans, incremental adjustments are best-effort.** `commit_fill`,
///   `purge`, and eviction deletions adjust stats incrementally for
///   responsiveness, but concurrent operations can cause transient drift.
/// - **Any drift self-corrects on the next scan.** Since the eviction loop runs
///   periodically, stats never stay wrong for long. A few bytes of drift
///   between scans is acceptable for a caching proxy.
///
/// This design eliminates an entire class of stat-accounting races that are
/// impossible to fix with lock-free incremental updates alone (e.g., eviction
/// deleting a file that `commit_fill` just replaced, or partial removal leaving
/// stats carrying sizes of deleted fragments).
pub async fn run_eviction_loop(
    cache_dir: PathBuf,
    max_bytes: u64,
    interval_secs: u64,
    stats: Arc<CacheStats>,
    disk_cache: Option<Arc<super::DiskCache>>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if let Err(e) =
            run_eviction_pass_inner(&cache_dir, max_bytes, &stats, disk_cache.as_deref()).await
        {
            tracing::warn!(error = %e, "eviction pass failed");
        }
        // Sweep stale per-key meta locks after each pass to prevent
        // unbounded growth from keys that have been evicted.
        if let Some(ref dc) = disk_cache {
            dc.sweep_stale_meta_locks().await;
        }
    }
}

fn boxed_io_error(
    operation: &'static str,
    path: &std::path::Path,
    error: std::io::Error,
) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    ))
}

/// Scan a single hash directory and return candidates, stats, and deferred
/// cleanups that require per-key locks (which cannot be acquired inside a
/// spawned task because `DiskCache` is not `Send`-safe across spawn boundaries).
///
/// All error returns are tagged with [`ScanFailureReason::HashDirScan`] so
/// the call-site at `run_eviction_pass_inner` can record the correct metric
/// label without parsing the error display string.
async fn scan_hash_dir_for_eviction(d2_path: PathBuf) -> Result<DirScanResult, EvictionScanError> {
    let mut result = DirScanResult {
        candidates: Vec::new(),
        total_bytes: 0,
        entry_count: 0,
        deferred_cleanups: Vec::new(),
    };

    let mut file_entries = match tokio::fs::read_dir(&d2_path).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(result),
        Err(e) => {
            return Err(eviction_io_error(
                ScanFailureReason::HashDirScan,
                "read hash shard dir",
                &d2_path,
                e,
            ));
        }
    };

    loop {
        let file_entry = match file_entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                return Err(eviction_io_error(
                    ScanFailureReason::HashDirScan,
                    "iterate hash shard dir",
                    &d2_path,
                    e,
                ));
            }
        };
        let file_path = file_entry.path();
        // The cache writer only emits UTF-8 hex-hash filenames + ASCII
        // suffixes (.body / .meta.json / .poisoned). A non-UTF-8 name
        // inside a hash shard is foreign content we don't own — skipping
        // it could undercount orphan/cleanup detection, and synthesizing
        // a fallback identifier would risk wrong locking semantics on
        // something that's almost certainly external junk. Abort the
        // scan and surface the offending path so an operator can
        // investigate.
        let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => {
                return Err(eviction_io_error(
                    ScanFailureReason::HashDirScan,
                    "non-UTF-8 filename inside cache hash shard",
                    &file_path,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "filename is not valid UTF-8",
                    ),
                ));
            }
        };

        if !file_name.ends_with(".meta.json") {
            // Detect orphan .body files and stale .poisoned markers.
            // The actual cleanup under per-key lock is deferred.
            if file_name.ends_with(".body") {
                let hash = file_name.trim_end_matches(".body").to_string();
                let meta_path = d2_path.join(format!("{}.meta.json", hash));
                match tokio::fs::try_exists(&meta_path).await {
                    Ok(false) => {
                        result.deferred_cleanups.push(DeferredCleanup::OrphanBody {
                            body_path: file_path,
                            hash,
                        });
                    }
                    Ok(true) => {} // meta exists, not an orphan
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // race: dir vanished
                    Err(e) => {
                        return Err(eviction_io_error(
                            ScanFailureReason::HashDirScan,
                            "probe orphan metadata",
                            &meta_path,
                            e,
                        ));
                    }
                }
            } else if file_name.ends_with(".poisoned") {
                let hash = file_name.trim_end_matches(".poisoned").to_string();
                let meta_path = d2_path.join(format!("{}.meta.json", hash));
                match tokio::fs::try_exists(&meta_path).await {
                    Ok(false) => {
                        result
                            .deferred_cleanups
                            .push(DeferredCleanup::OrphanPoison {
                                poison_path: file_path,
                                hash,
                            });
                    }
                    Ok(true) => {} // meta exists, not an orphan
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // race
                    Err(e) => {
                        return Err(eviction_io_error(
                            ScanFailureReason::HashDirScan,
                            "probe orphan metadata",
                            &meta_path,
                            e,
                        ));
                    }
                }
            }
            continue;
        }

        let hash_for_cleanup = file_name.trim_end_matches(".meta.json");
        // Read metadata, distinguishing I/O errors from parse errors.
        let meta_bytes = match tokio::fs::read(&file_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, // race: entry removed
            Err(e) => {
                return Err(eviction_io_error(
                    ScanFailureReason::HashDirScan,
                    "read metadata during eviction scan",
                    &file_path,
                    e,
                ));
            }
        };
        let meta: CacheMeta = match serde_json::from_slice::<CacheMeta>(&meta_bytes) {
            Ok(m) => m,
            Err(_) => {
                // Genuinely corrupt metadata — defer locked cleanup.
                let hash = hash_for_cleanup.to_string();
                let body = d2_path.join(format!("{}.body", hash));
                let poison = d2_path.join(format!("{hash}.poisoned"));
                result
                    .deferred_cleanups
                    .push(DeferredCleanup::CorruptEntry(EntryPaths {
                        meta_path: file_path,
                        body_path: body,
                        poison_path: poison,
                        hash,
                    }));
                continue;
            }
        };

        let hash = hash_for_cleanup;
        if hash.len() < 5 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            let body = d2_path.join(format!("{hash}.body"));
            let poison = d2_path.join(format!("{hash}.poisoned"));
            result
                .deferred_cleanups
                .push(DeferredCleanup::MalformedHash(EntryPaths {
                    meta_path: file_path,
                    body_path: body,
                    poison_path: poison,
                    hash: hash.to_string(),
                }));
            continue;
        }
        let body_path = d2_path.join(format!("{}.body", hash));

        let body_size = match tokio::fs::metadata(&body_path).await {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Body appears missing — defer locked recheck.
                let poison = d2_path.join(format!("{hash}.poisoned"));
                result
                    .deferred_cleanups
                    .push(DeferredCleanup::MissingBody(EntryPaths {
                        meta_path: file_path,
                        body_path,
                        poison_path: poison,
                        hash: hash.to_string(),
                    }));
                continue;
            }
            Err(e) => {
                return Err(eviction_io_error(
                    ScanFailureReason::HashDirScan,
                    "stat body during eviction scan",
                    &body_path,
                    e,
                ));
            }
        };

        let entry_size = body_size + meta_bytes.len() as u64;

        // Count this complete entry toward the authoritative scan totals.
        result.total_bytes += entry_size;
        result.entry_count += 1;

        result.candidates.push(EvictionCandidate {
            body_path,
            meta_path: file_path,
            hash: hash.to_string(),
            fill_id: meta.fill_id,
            last_accessed_at: meta.last_accessed_at,
            size: entry_size,
        });
    }

    Ok(result)
}

/// Try to remove a file. Returns the bytes the caller should attribute as
/// "still on disk" for this path:
///   - `Ok(0)` when the remove succeeded or returned NotFound (file is gone).
///   - `Ok(measured)` when remove failed but the post-remove stat succeeded.
///   - `Ok(pre)` when remove failed, post-remove stat failed, and a pre-stat
///     baseline was captured (bytes are still on disk; size known from just
///     before the remove attempt).
///   - `Err` when remove failed AND both pre- and post-remove stats failed
///     with hard I/O errors — the remaining size is genuinely unknown and
///     silently zeroing it would undercount `scan_total_bytes`. The caller
///     aborts the pass; the next eviction tick retries.
///
/// Captures a pre-stat baseline before issuing the remove so a transient
/// stat failure during cleanup cannot silently collapse the unreclaimed
/// bytes to 0 — that would undercount `scan_total_bytes` and let the cache
/// stay over `max_bytes` until the next pass that doesn't hit the stat
/// failure.
async fn remove_file_or_reclaim_size(
    path: &std::path::Path,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let pre_size = pre_stat_size(path).await;

    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => measure_unreclaimed_after_failed_remove(path, pre_size, &e).await,
    }
}

/// Stat a path and return its size, distinguishing NotFound (file is gone:
/// `Some(0)`) from real I/O errors (size unknown: `None`). Used to capture a
/// pre-attempt baseline so callers don't silently treat a later stat failure
/// as "0 bytes remaining".
async fn pre_stat_size(path: &std::path::Path) -> Option<u64> {
    match tokio::fs::metadata(path).await {
        Ok(m) => Some(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
        Err(_) => None,
    }
}

/// After a remove_file call has failed with a non-NotFound error, measure
/// how many bytes still occupy disk for this path.
///
/// Tries a post-remove stat first; on stat failure falls back to `pre_known`
/// (typically a pre-remove stat result captured right before the remove).
/// Returns `Ok(0)` only when the post-remove stat is NotFound (the file
/// vanished between the remove and the stat). Returns `Err` when the
/// post-remove stat fails with a non-NotFound error AND no pre-stat baseline
/// is available — silently zeroing that case would let unreclaimed bytes drop
/// out of `scan_total_bytes`. Never silently treats an uncertain state as
/// "fully reclaimed".
async fn measure_unreclaimed_after_failed_remove(
    path: &std::path::Path,
    pre_known: Option<u64>,
    remove_err: &std::io::Error,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    match tokio::fs::metadata(path).await {
        Ok(m) => {
            tracing::warn!(
                path = %path.display(),
                error = %remove_err,
                size = m.len(),
                "failed to remove cache file, counting bytes as unreclaimed"
            );
            Ok(m.len())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => match pre_known {
            Some(pre) => {
                tracing::warn!(
                    path = %path.display(),
                    remove_error = %remove_err,
                    stat_error_kind = ?e.kind(),
                    pre,
                    "failed to remove cache file and post-stat unavailable, falling back to pre-stat baseline"
                );
                Ok(pre)
            }
            None => {
                tracing::warn!(
                    path = %path.display(),
                    remove_error = %remove_err,
                    stat_error_kind = ?e.kind(),
                    "failed to remove cache file with no pre-stat baseline AND post-stat failed — aborting eviction pass"
                );
                Err(boxed_io_error(
                    "stat after failed remove during eviction cleanup",
                    path,
                    e,
                ))
            }
        },
    }
}

/// Remove all three entry files, returning the total bytes that could not be
/// reclaimed (so the caller can keep accounting accurate). Propagates the
/// `Err` from `remove_file_or_reclaim_size` when remaining bytes are unknown.
async fn remove_entry_files(
    paths: &EntryPaths,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let mut unreclaimed = 0u64;
    unreclaimed += remove_file_or_reclaim_size(&paths.meta_path).await?;
    unreclaimed += remove_file_or_reclaim_size(&paths.body_path).await?;
    unreclaimed += remove_file_or_reclaim_size(&paths.poison_path).await?;
    Ok(unreclaimed)
}

/// Outcome of attempting to recover a cache entry under lock.
enum RecoverOutcome {
    /// Entry is valid — body exists and metadata parsed successfully.
    Recovered {
        size: u64,
        candidate: EvictionCandidate,
    },
    /// Body file does not exist (NotFound).
    MissingBody,
    /// Body file exists but could not be stat'd (I/O or permission error).
    BodyStatError(std::io::Error),
    /// Metadata file could not be read (I/O error).
    MetaReadError(std::io::Error),
    /// Metadata file was read but could not be parsed (corrupt JSON).
    MetaParseError(serde_json::Error),
}

/// Try to read metadata and body size under lock and promote the entry to an
/// eviction candidate.
async fn try_recover_entry(paths: &EntryPaths) -> RecoverOutcome {
    let body_sz = match tokio::fs::metadata(&paths.body_path).await {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RecoverOutcome::MissingBody,
        Err(e) => return RecoverOutcome::BodyStatError(e),
    };
    let meta_bytes = match tokio::fs::read(&paths.meta_path).await {
        Ok(b) => b,
        Err(e) => return RecoverOutcome::MetaReadError(e),
    };
    let meta = match serde_json::from_slice::<CacheMeta>(&meta_bytes) {
        Ok(m) => m,
        Err(e) => return RecoverOutcome::MetaParseError(e),
    };
    let size = body_sz + meta_bytes.len() as u64;
    RecoverOutcome::Recovered {
        size,
        candidate: EvictionCandidate {
            body_path: paths.body_path.clone(),
            meta_path: paths.meta_path.clone(),
            hash: paths.hash.clone(),
            fill_id: meta.fill_id,
            last_accessed_at: meta.last_accessed_at,
            size,
        },
    }
}

/// Acquire the per-key meta lock if a DiskCache is available.
async fn acquire_meta_lock(
    disk_cache: Option<&super::DiskCache>,
    hash: &str,
) -> Option<tokio::sync::OwnedMutexGuard<()>> {
    match disk_cache {
        Some(dc) => Some(dc.meta_lock_for_hash(hash).lock_owned().await),
        None => None,
    }
}

/// Bump the kind-labeled `s3proxy_cache_deferred_cleanup_failed_total` counter
/// and increment the per-pass failure count. Used for skip / partial-failure /
/// abort branches inside `process_deferred_cleanups`.
fn record_deferred_cleanup_failure(failed: &mut u64, kind: &'static str) {
    *failed += 1;
    metrics::counter!(
        "s3proxy_cache_deferred_cleanup_failed_total",
        "kind" => kind,
    )
    .increment(1);
}

/// Wrap a `Box<dyn Error>` returned by a per-file helper as an
/// [`EvictionScanError`] tagged with [`ScanFailureReason::DeferredCleanup`]
/// after bumping the kind-labeled counter for the originating cleanup.
fn deferred_cleanup_err(
    failed: &mut u64,
    kind: &'static str,
    source: Box<dyn std::error::Error + Send + Sync>,
) -> EvictionScanError {
    record_deferred_cleanup_failure(failed, kind);
    EvictionScanError::new(ScanFailureReason::DeferredCleanup, source)
}

/// Record an unreclaimed-byte tally from a per-file removal helper. Adds the
/// bytes to `scan_total_bytes` and flips `partial` to true when the helper
/// signaled a partial failure (`Ok(>0)` per the `remove_file_or_reclaim_size`
/// /`remove_entry_files` contract: zero means gone, nonzero means still on
/// disk). Each cleanup branch records the kind-labeled counter at most once
/// after all of its removals, regardless of how many of them returned bytes.
fn account_unreclaimed(scan_total_bytes: &mut u64, partial: &mut bool, unreclaimed: u64) {
    *scan_total_bytes += unreclaimed;
    if unreclaimed > 0 {
        *partial = true;
    }
}

/// Process deferred cleanups that require per-key lock coordination.
///
/// `deferred_cleanup_failed` is incremented (and the corresponding
/// kind-labeled counter is bumped) on every branch that skips, partially
/// fails, or aborts a cleanup. Successful cleanups do not bump it. Every
/// `Err` return is tagged with [`ScanFailureReason::DeferredCleanup`].
async fn process_deferred_cleanups(
    cleanups: Vec<DeferredCleanup>,
    disk_cache: Option<&super::DiskCache>,
    candidates: &mut Vec<EvictionCandidate>,
    scan_total_bytes: &mut u64,
    scan_entry_count: &mut u64,
    deferred_cleanup_failed: &mut u64,
) -> Result<(), EvictionScanError> {
    for cleanup in cleanups {
        match cleanup {
            DeferredCleanup::OrphanBody { body_path, hash } => {
                let _guard = acquire_meta_lock(disk_cache, &hash).await;
                let meta_path = body_path
                    .parent()
                    .unwrap()
                    .join(format!("{}.meta.json", hash));
                match tokio::fs::try_exists(&meta_path).await {
                    Ok(false) => {
                        let unreclaimed =
                            remove_file_or_reclaim_size(&body_path).await.map_err(|e| {
                                deferred_cleanup_err(deferred_cleanup_failed, "orphan_body", e)
                            })?;
                        let mut partial = false;
                        account_unreclaimed(scan_total_bytes, &mut partial, unreclaimed);
                        if partial {
                            record_deferred_cleanup_failure(deferred_cleanup_failed, "orphan_body");
                        }
                        tracing::debug!(path = %body_path.display(), "removed orphan body file");
                    }
                    Ok(true) => {} // meta appeared (concurrent fill), not an orphan
                    Err(e) => {
                        // Can't confirm orphan status. Try to count the body
                        // bytes conservatively so stats don't undercount, but
                        // do NOT silently treat a stat failure as 0 — that
                        // would let on-disk bytes drop out of the budget.
                        match tokio::fs::metadata(&body_path).await {
                            Ok(m) => {
                                *scan_total_bytes += m.len();
                                record_deferred_cleanup_failure(
                                    deferred_cleanup_failed,
                                    "orphan_body",
                                );
                                tracing::warn!(
                                    path = %meta_path.display(),
                                    try_exists_error = %e,
                                    size = m.len(),
                                    "failed to recheck orphan body status under lock, counting body bytes conservatively"
                                );
                            }
                            Err(e2) if e2.kind() == std::io::ErrorKind::NotFound => {
                                // Body vanished between scan and locked
                                // recheck — genuinely gone, no bytes to count.
                                tracing::debug!(
                                    path = %body_path.display(),
                                    "orphan body vanished before locked recheck"
                                );
                            }
                            Err(e2) => {
                                // Both probes failed with non-NotFound errors:
                                // remaining bytes are unknown. Abort the pass
                                // rather than silently zero — the next eviction
                                // tick will retry, and a persistent failure
                                // (e.g., permanently inaccessible directory)
                                // surfaces as a logged eviction error instead
                                // of accumulating undercounted disk usage.
                                record_deferred_cleanup_failure(
                                    deferred_cleanup_failed,
                                    "orphan_body",
                                );
                                tracing::warn!(
                                    path = %body_path.display(),
                                    try_exists_error = %e,
                                    stat_error_kind = ?e2.kind(),
                                    "failed to recheck orphan body status AND stat the body — aborting eviction pass"
                                );
                                return Err(eviction_io_error(
                                    ScanFailureReason::DeferredCleanup,
                                    "stat orphan body during locked eviction cleanup",
                                    &body_path,
                                    e2,
                                ));
                            }
                        }
                    }
                }
            }
            DeferredCleanup::OrphanPoison { poison_path, hash } => {
                let _guard = acquire_meta_lock(disk_cache, &hash).await;
                let meta_path = poison_path
                    .parent()
                    .unwrap()
                    .join(format!("{}.meta.json", hash));
                match tokio::fs::try_exists(&meta_path).await {
                    Ok(false) => {
                        let unreclaimed =
                            remove_file_or_reclaim_size(&poison_path)
                                .await
                                .map_err(|e| {
                                    deferred_cleanup_err(
                                        deferred_cleanup_failed,
                                        "orphan_poison",
                                        e,
                                    )
                                })?;
                        let mut partial = false;
                        account_unreclaimed(scan_total_bytes, &mut partial, unreclaimed);
                        if partial {
                            record_deferred_cleanup_failure(
                                deferred_cleanup_failed,
                                "orphan_poison",
                            );
                        }
                        tracing::debug!(path = %poison_path.display(), "removed orphan poison marker");
                    }
                    Ok(true) => {} // meta appeared, poison is valid
                    Err(e) => {
                        record_deferred_cleanup_failure(deferred_cleanup_failed, "orphan_poison");
                        tracing::warn!(
                            path = %meta_path.display(),
                            error = %e,
                            "failed to recheck orphan poison status under lock, skipping cleanup"
                        );
                    }
                }
            }
            DeferredCleanup::CorruptEntry(paths) => {
                let _guard = acquire_meta_lock(disk_cache, &paths.hash).await;
                // Re-read under lock — a concurrent fill may have repaired
                // the entry since the unlocked check.
                match try_recover_entry(&paths).await {
                    RecoverOutcome::Recovered { size, candidate } => {
                        *scan_total_bytes += size;
                        *scan_entry_count += 1;
                        candidates.push(candidate);
                    }
                    RecoverOutcome::MissingBody => {
                        // Body gone and meta was already proven corrupt —
                        // clean up the leftover meta and poison. The kind
                        // counter is bumped at most once for this cleanup
                        // even if both removals leave bytes on disk.
                        let mut partial = false;
                        let meta_unreclaimed = remove_file_or_reclaim_size(&paths.meta_path)
                            .await
                            .map_err(|e| {
                                deferred_cleanup_err(deferred_cleanup_failed, "corrupt_entry", e)
                            })?;
                        account_unreclaimed(scan_total_bytes, &mut partial, meta_unreclaimed);
                        let poison_unreclaimed = remove_file_or_reclaim_size(&paths.poison_path)
                            .await
                            .map_err(|e| {
                                deferred_cleanup_err(deferred_cleanup_failed, "corrupt_entry", e)
                            })?;
                        account_unreclaimed(scan_total_bytes, &mut partial, poison_unreclaimed);
                        if partial {
                            record_deferred_cleanup_failure(
                                deferred_cleanup_failed,
                                "corrupt_entry",
                            );
                        }
                        tracing::debug!(path = %paths.meta_path.display(), "removed corrupt entry with missing body");
                    }
                    RecoverOutcome::BodyStatError(e) => {
                        record_deferred_cleanup_failure(deferred_cleanup_failed, "corrupt_entry");
                        return Err(eviction_io_error(
                            ScanFailureReason::DeferredCleanup,
                            "stat body during locked eviction cleanup",
                            &paths.body_path,
                            e,
                        ));
                    }
                    RecoverOutcome::MetaReadError(e) => {
                        record_deferred_cleanup_failure(deferred_cleanup_failed, "corrupt_entry");
                        return Err(eviction_io_error(
                            ScanFailureReason::DeferredCleanup,
                            "read metadata during locked eviction cleanup",
                            &paths.meta_path,
                            e,
                        ));
                    }
                    RecoverOutcome::MetaParseError(e) => {
                        tracing::warn!(path = %paths.meta_path.display(), error = %e, "corrupt entry meta still unparseable under lock, removing");
                        let unreclaimed = remove_entry_files(&paths).await.map_err(|e| {
                            deferred_cleanup_err(deferred_cleanup_failed, "corrupt_entry", e)
                        })?;
                        let mut partial = false;
                        account_unreclaimed(scan_total_bytes, &mut partial, unreclaimed);
                        if partial {
                            record_deferred_cleanup_failure(
                                deferred_cleanup_failed,
                                "corrupt_entry",
                            );
                        }
                    }
                }
            }
            DeferredCleanup::MalformedHash(paths) => {
                let _guard = acquire_meta_lock(disk_cache, &paths.hash).await;
                let unreclaimed = remove_entry_files(&paths).await.map_err(|e| {
                    deferred_cleanup_err(deferred_cleanup_failed, "malformed_hash", e)
                })?;
                let mut partial = false;
                account_unreclaimed(scan_total_bytes, &mut partial, unreclaimed);
                if partial {
                    record_deferred_cleanup_failure(deferred_cleanup_failed, "malformed_hash");
                }
                tracing::warn!(
                    path = %paths.meta_path.display(),
                    "removed cache entry with malformed filename stem"
                );
            }
            DeferredCleanup::MissingBody(paths) => {
                let _guard = acquire_meta_lock(disk_cache, &paths.hash).await;
                match try_recover_entry(&paths).await {
                    RecoverOutcome::Recovered { size, candidate } => {
                        // Body appeared after taking the lock (concurrent commit_fill).
                        *scan_total_bytes += size;
                        *scan_entry_count += 1;
                        candidates.push(candidate);
                    }
                    RecoverOutcome::MissingBody => {
                        // Still missing — clean up the leftover meta and
                        // poison. The kind counter is bumped at most once
                        // for this cleanup even if both removals leave
                        // bytes on disk.
                        let mut partial = false;
                        let meta_unreclaimed = remove_file_or_reclaim_size(&paths.meta_path)
                            .await
                            .map_err(|e| {
                                deferred_cleanup_err(deferred_cleanup_failed, "missing_body", e)
                            })?;
                        account_unreclaimed(scan_total_bytes, &mut partial, meta_unreclaimed);
                        let poison_unreclaimed = remove_file_or_reclaim_size(&paths.poison_path)
                            .await
                            .map_err(|e| {
                                deferred_cleanup_err(deferred_cleanup_failed, "missing_body", e)
                            })?;
                        account_unreclaimed(scan_total_bytes, &mut partial, poison_unreclaimed);
                        if partial {
                            record_deferred_cleanup_failure(
                                deferred_cleanup_failed,
                                "missing_body",
                            );
                        }
                    }
                    RecoverOutcome::BodyStatError(e) => {
                        record_deferred_cleanup_failure(deferred_cleanup_failed, "missing_body");
                        return Err(eviction_io_error(
                            ScanFailureReason::DeferredCleanup,
                            "stat body during locked missing-body cleanup",
                            &paths.body_path,
                            e,
                        ));
                    }
                    RecoverOutcome::MetaReadError(e) => {
                        record_deferred_cleanup_failure(deferred_cleanup_failed, "missing_body");
                        return Err(eviction_io_error(
                            ScanFailureReason::DeferredCleanup,
                            "read metadata during locked missing-body cleanup",
                            &paths.meta_path,
                            e,
                        ));
                    }
                    RecoverOutcome::MetaParseError(_) => {
                        // Body missing and meta is broken — clean up everything.
                        let unreclaimed = remove_entry_files(&paths).await.map_err(|e| {
                            deferred_cleanup_err(deferred_cleanup_failed, "missing_body", e)
                        })?;
                        let mut partial = false;
                        account_unreclaimed(scan_total_bytes, &mut partial, unreclaimed);
                        if partial {
                            record_deferred_cleanup_failure(
                                deferred_cleanup_failed,
                                "missing_body",
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Walk the objects directory, collect all cache entries as eviction candidates,
/// clean up orphans, and **reconcile stats** to match filesystem reality.
///
/// Hash directories (`objects/XX/YY/`) are processed in parallel using a
/// streaming `JoinSet` pump that caps in-flight shard scans at
/// `CACHE_HASH_DIR_SCAN_CONCURRENCY`. Deferred cleanups that require per-key
/// locks are processed sequentially after the parallel scan completes.
///
/// After this function returns, `stats.total_bytes` and `stats.entry_count`
/// reflect the actual on-disk state (minus any concurrent mutations that raced
/// with the scan — those will be corrected on the next pass).
/// Result of a full cache scan: eviction candidates plus the reconciled
/// on-disk byte total (which may exceed the candidate sum when cleanup
/// deletions failed and left unreclaimed bytes).
struct ScanResult {
    candidates: Vec<EvictionCandidate>,
    /// Authoritative on-disk byte total, including unreclaimed bytes from
    /// failed orphan/corrupt cleanup deletions.
    total_bytes: u64,
    /// Number of `objects/XX/YY/` shards walked during this scan.
    hash_dirs: usize,
    /// Number of deferred cleanups produced by the parallel shard scan.
    deferred_cleanup_count: u64,
    /// Number of deferred cleanups that skipped, partially failed, or aborted.
    /// Mirrors `s3proxy_cache_deferred_cleanup_failed_total` for this pass.
    deferred_cleanup_failed: u64,
}

async fn collect_candidates(
    objects_dir: &std::path::Path,
    stats: &Arc<CacheStats>,
    disk_cache: Option<&super::DiskCache>,
) -> Result<ScanResult, EvictionScanError> {
    // Phase 1: Collect all hash directory paths.
    let hash_dirs = collect_hash_dirs_strict(objects_dir)
        .await
        .map_err(|e| EvictionScanError::new(ScanFailureReason::HashDirWalk, e))?;
    if hash_dirs.is_empty() {
        stats.total_bytes.store(0, Ordering::Relaxed);
        stats.entry_count.store(0, Ordering::Relaxed);
        return Ok(ScanResult {
            candidates: Vec::new(),
            total_bytes: 0,
            hash_dirs: 0,
            deferred_cleanup_count: 0,
            deferred_cleanup_failed: 0,
        });
    }
    let hash_dir_count = hash_dirs.len();

    // Phase 2: Process each hash directory in parallel with a bounded
    // streaming JoinSet pump (at most CACHE_HASH_DIR_SCAN_CONCURRENCY tasks
    // alive at once).
    let dir_results = bounded_parallel_scan(
        hash_dirs,
        CACHE_HASH_DIR_SCAN_CONCURRENCY,
        scan_hash_dir_for_eviction,
        |e| {
            EvictionScanError::new(
                ScanFailureReason::Join,
                std::io::Error::other(format!("eviction hash-dir scan task failed: {e}")),
            )
        },
    )
    .await?;

    // Phase 3: Aggregate results from all parallel tasks.
    let mut candidates = Vec::new();
    let mut scan_total_bytes: u64 = 0;
    let mut scan_entry_count: u64 = 0;
    let mut all_cleanups = Vec::new();

    for dir_result in dir_results {
        candidates.extend(dir_result.candidates);
        scan_total_bytes += dir_result.total_bytes;
        scan_entry_count += dir_result.entry_count;
        all_cleanups.extend(dir_result.deferred_cleanups);
    }
    let deferred_cleanup_count = all_cleanups.len() as u64;

    // Phase 4: Process deferred cleanups under per-key locks.
    let mut deferred_cleanup_failed: u64 = 0;
    process_deferred_cleanups(
        all_cleanups,
        disk_cache,
        &mut candidates,
        &mut scan_total_bytes,
        &mut scan_entry_count,
        &mut deferred_cleanup_failed,
    )
    .await?;

    // Reconcile: overwrite atomics with the authoritative filesystem totals.
    // Any drift from concurrent commit_fill/purge since the last reconciliation
    // is corrected here.
    stats.total_bytes.store(scan_total_bytes, Ordering::Relaxed);
    stats.entry_count.store(scan_entry_count, Ordering::Relaxed);

    Ok(ScanResult {
        candidates,
        total_bytes: scan_total_bytes,
        hash_dirs: hash_dir_count,
        deferred_cleanup_count,
        deferred_cleanup_failed,
    })
}

/// Single eviction pass: scan cache (reconciling stats), sort by LRU, evict
/// until under limit. Requires a `DiskCache` reference for per-key lock
/// coordination with concurrent fills and metadata writes.
pub async fn run_eviction_pass(
    cache_dir: &std::path::Path,
    max_bytes: u64,
    stats: &Arc<CacheStats>,
    disk_cache: &super::DiskCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let result = run_eviction_pass_inner(cache_dir, max_bytes, stats, Some(disk_cache)).await;
    disk_cache.sweep_stale_meta_locks().await;
    result
}

/// Inner implementation that accepts an optional DiskCache for testability.
///
/// Wraps the actual pass body with start/end timing and emits these
/// observability signals at the end of every pass:
///   - `s3proxy_cache_scan_duration_seconds{phase="eviction"}` on success
///   - `s3proxy_cache_scan_failed_total{phase="eviction",reason=...}` on Err
///     and on the `objects_dir` probe-skip branch
///   - `s3proxy_cache_unreclaimed_bytes` on success (set from this pass's
///     `scan_total_bytes - candidate_bytes`)
///   - One info-level summary log line on every successful pass
async fn run_eviction_pass_inner(
    cache_dir: &std::path::Path,
    max_bytes: u64,
    stats: &Arc<CacheStats>,
    disk_cache: Option<&super::DiskCache>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let objects_dir = cache_dir.join("objects");
    let scan = match tokio::fs::try_exists(&objects_dir).await {
        Ok(true) => {
            // collect_candidates walks the filesystem and reconciles stats.
            // The reason label is taken directly from the typed
            // `ScanFailureReason` variant carried by the error, so renaming
            // the inner error message can never silently degrade
            // observability to `reason="other"`.
            match collect_candidates(&objects_dir, stats, disk_cache).await {
                Ok(s) => s,
                Err(e) => {
                    metrics::counter!(
                        "s3proxy_cache_scan_failed_total",
                        "phase" => "eviction",
                        "reason" => e.reason.as_label(),
                    )
                    .increment(1);
                    return Err(Box::new(e));
                }
            }
        }
        Ok(false) => {
            // No objects directory — reconcile stats to zero and fall
            // through to the same success emission the populated path
            // takes. Returning early here would skip the duration
            // histogram, leave `s3proxy_cache_unreclaimed_bytes` stale
            // from the previous pass, and drop the per-pass summary log.
            stats.entry_count.store(0, Ordering::Relaxed);
            stats.total_bytes.store(0, Ordering::Relaxed);
            ScanResult {
                candidates: Vec::new(),
                total_bytes: 0,
                hash_dirs: 0,
                deferred_cleanup_count: 0,
                deferred_cleanup_failed: 0,
            }
        }
        Err(e) => {
            // Probe failure is per-spec counted under `objects_dir_probe`
            // even though the pass returns Ok (existing skip-on-probe-error
            // semantics are preserved so a transient stat error does not
            // crash the eviction loop).
            metrics::counter!(
                "s3proxy_cache_scan_failed_total",
                "phase" => "eviction",
                "reason" => ScanFailureReason::ObjectsDirProbe.as_label(),
            )
            .increment(1);
            tracing::warn!(
                path = %objects_dir.display(),
                error = %e,
                "failed to check objects directory for eviction, skipping pass"
            );
            return Ok(());
        }
    };
    let candidate_count = scan.candidates.len() as u64;
    let candidate_bytes: u64 = scan.candidates.iter().map(|c| c.size).sum();
    let scan_total_bytes = scan.total_bytes;
    let hash_dirs = scan.hash_dirs;
    let deferred_cleanup_count = scan.deferred_cleanup_count;
    let deferred_cleanup_failed = scan.deferred_cleanup_failed;
    let mut candidates = scan.candidates;

    // Sort by last_accessed_at ascending (oldest first = evicted first)
    candidates.sort_by_key(|c| c.last_accessed_at);

    // Use the reconciled on-disk total for the eviction budget, not just
    // the candidate sum. This ensures unreclaimed bytes (from failed cleanup
    // deletions) count toward the limit — otherwise the cache could stay
    // over budget indefinitely when some files can't be removed.
    let over_budget_bytes_before = scan_total_bytes.saturating_sub(max_bytes);
    let mut current_size = scan_total_bytes;
    let mut evicted = 0u64;
    if scan_total_bytes > max_bytes {
        // Evict oldest entries until under limit. Stat adjustments here are
        // best-effort for between-scan responsiveness; the next scan
        // reconciles any drift from concurrent operations.
        for candidate in &candidates {
            if current_size <= max_bytes {
                break;
            }
            try_evict_candidate(
                candidate,
                &mut current_size,
                &mut evicted,
                stats,
                disk_cache,
            )
            .await;
        }
        stats.eviction_count.fetch_add(evicted, Ordering::Relaxed);
    }

    let summary = EvictionPassSummary {
        hash_dirs,
        candidate_count,
        candidate_bytes,
        deferred_cleanup_count,
        deferred_cleanup_failed,
        scan_total_bytes,
        max_bytes,
        over_budget_bytes_before,
        evicted,
        final_size_bytes: current_size,
        over_budget_bytes_after: current_size.saturating_sub(max_bytes),
    };

    let duration = start.elapsed().as_secs_f64();
    metrics::histogram!(
        "s3proxy_cache_scan_duration_seconds",
        "phase" => "eviction",
    )
    .record(duration);
    let unreclaimed_bytes = scan_total_bytes.saturating_sub(candidate_bytes);
    metrics::gauge!("s3proxy_cache_unreclaimed_bytes").set(unreclaimed_bytes as f64);
    tracing::info!(
        duration_seconds = duration,
        hash_dirs = summary.hash_dirs,
        candidate_count = summary.candidate_count,
        candidate_bytes = summary.candidate_bytes,
        deferred_cleanup_count = summary.deferred_cleanup_count,
        deferred_cleanup_failed = summary.deferred_cleanup_failed,
        unreclaimed_bytes = unreclaimed_bytes,
        scan_total_bytes = summary.scan_total_bytes,
        max_bytes = summary.max_bytes,
        over_budget_bytes_before = summary.over_budget_bytes_before,
        evicted = summary.evicted,
        final_size_bytes = summary.final_size_bytes,
        over_budget_bytes_after = summary.over_budget_bytes_after,
        "cache eviction pass complete",
    );

    Ok(())
}

/// Attempt to evict a single candidate under its per-key meta lock. Updates
/// `current_size`, `evicted`, and the global `stats` in place. Errors during
/// removal or stat are logged and do not propagate — eviction is best-effort
/// between scans.
async fn try_evict_candidate(
    candidate: &EvictionCandidate,
    current_size: &mut u64,
    evicted: &mut u64,
    stats: &Arc<CacheStats>,
    disk_cache: Option<&super::DiskCache>,
) {
    // Acquire the per-key metadata lock (if the DiskCache is available) so
    // eviction cannot race with rewrite_last_accessed or metadata updates
    // on the same entry.
    let meta_lock = disk_cache.map(|dc| dc.meta_lock_for_hash(&candidate.hash));
    let _meta_guard = match meta_lock.as_ref() {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };

    // Re-read metadata under the lock to decide whether to evict.
    //
    // Four cases:
    //   1. Read Ok + parse Ok + identity changed: entry was replaced by a
    //      concurrent commit_fill — remeasure on-disk size and skip the
    //      delete (existing branch from 03ce64c).
    //   2. Read Ok + parse Ok + identity unchanged: proceed to delete.
    //   3. Read Ok + parse Err: meta is corrupt. Treat as cache-owned
    //      garbage and proceed to delete (matches the existing semantics
    //      for corrupt entries cleaned up under lock elsewhere).
    //   4. Read Err(NotFound): meta is gone. Proceed to delete (cleans up
    //      any leftover body).
    //   5. Read Err(other): hard I/O error (PermissionDenied, EIO, …).
    //      Identity is unknown. Skip this candidate without deleting —
    //      otherwise we could destroy bytes that may belong to a
    //      concurrent fill or a still-valid entry. Leave current_size
    //      and global stats untouched; the next eviction tick retries.
    match tokio::fs::read(&candidate.meta_path).await {
        Ok(meta_bytes) => match serde_json::from_slice::<CacheMeta>(&meta_bytes) {
            Ok(meta) => {
                if meta.fill_id != candidate.fill_id
                    || meta.last_accessed_at != candidate.last_accessed_at
                {
                    // Case 1: entry changed since scan — remeasure and
                    // skip the delete. Classify each stat: Some(len) on
                    // Ok, Some(0) on NotFound, None on other I/O error.
                    // Replace candidate.size in current_size ONLY when
                    // both stats are known; otherwise leave current_size
                    // unchanged so candidate.size stays counted (silently
                    // treating an unknown size as 0 would undercount the
                    // budget for the rest of the pass).
                    //
                    // Local-budget hygiene only; reconciled global stats
                    // are not touched on this branch.
                    let body_size: Option<u64> = match tokio::fs::metadata(&candidate.body_path)
                        .await
                    {
                        Ok(m) => Some(m.len()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
                        Err(e) => {
                            tracing::warn!(
                                path = %candidate.body_path.display(),
                                error_kind = ?e.kind(),
                                "eviction: changed-entry remeasure of body stat failed, treating size as unknown"
                            );
                            None
                        }
                    };
                    let meta_size: Option<u64> = match tokio::fs::metadata(&candidate.meta_path)
                        .await
                    {
                        Ok(m) => Some(m.len()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
                        Err(e) => {
                            tracing::warn!(
                                path = %candidate.meta_path.display(),
                                error_kind = ?e.kind(),
                                "eviction: changed-entry remeasure of meta stat failed, treating size as unknown"
                            );
                            None
                        }
                    };
                    if let (Some(b), Some(m)) = (body_size, meta_size) {
                        let actual_size = b + m;
                        *current_size = current_size
                            .saturating_sub(candidate.size)
                            .saturating_add(actual_size);
                    }
                    return;
                }
                // Case 2: identity unchanged — fall through to delete.
            }
            Err(e) => {
                // Case 3: corrupt metadata. Cache-owned garbage; clean up.
                tracing::warn!(
                    path = %candidate.meta_path.display(),
                    error = %e,
                    "metadata became corrupt during eviction recheck, treating as cache-owned garbage and removing"
                );
                // Fall through to delete.
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Case 4: meta gone — fall through to delete (cleans up any
            // leftover body).
        }
        Err(e) => {
            // Case 5: hard I/O error — identity unknown. Skip this
            // candidate to avoid deleting bytes that may belong to a
            // concurrent fill or a still-valid entry. Leave current_size,
            // evicted, and global stats untouched. The loop continues to
            // later candidates and the next eviction tick retries.
            tracing::warn!(
                path = %candidate.meta_path.display(),
                error_kind = ?e.kind(),
                "eviction: locked meta read failed with hard I/O error, skipping candidate"
            );
            return;
        }
    }

    let body_res = tokio::fs::remove_file(&candidate.body_path).await;
    let meta_res = tokio::fs::remove_file(&candidate.meta_path).await;

    // "Gone" means the file is no longer on disk: either we removed it
    // (Ok) or it was already missing (NotFound). Other errors (permission
    // denied, EIO, etc.) indicate the bytes are likely still occupying
    // disk space and must NOT be treated as reclaimed.
    let is_gone = |res: &std::io::Result<()>| match res {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    };
    let body_gone = is_gone(&body_res);
    let meta_gone = is_gone(&meta_res);

    if body_gone || meta_gone {
        // Clear poison marker whenever either file is gone — the stale
        // content is (at least partially) gone.
        let poison_path = candidate.body_path.with_extension("poisoned");
        let _ = tokio::fs::remove_file(&poison_path).await;
    }

    if body_gone && meta_gone {
        // Both files are off disk (removed by us or already missing).
        // Best-effort: use the scan-measured size. If commit_fill replaced
        // the files between scan and delete, this may be stale — the next
        // scan reconciles.
        *current_size = current_size.saturating_sub(candidate.size);
        *evicted += 1;
        let _ = stats
            .entry_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                Some(c.saturating_sub(1))
            });
        let _ = stats
            .total_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                Some(c.saturating_sub(candidate.size))
            });
        tracing::debug!(
            path = %candidate.body_path.display(),
            size = candidate.size,
            "evicted cache entry"
        );
        return;
    }

    // At least one removal failed with a non-NotFound error — bytes
    // are still (at least partially) on disk. Try to measure what's
    // actually remaining via remaining_bytes_after_failed_remove. If
    // any path's remaining size is uncertain (stat failed with a
    // non-NotFound error), leave current_size unchanged so the entry's
    // full candidate.size stays counted toward the budget.
    //
    // Do NOT decrement entry_count / total_bytes here under any
    // outcome — those reconcile on the next scan.
    let body_remaining =
        remaining_bytes_after_failed_remove(body_gone, &candidate.body_path, "body").await;
    let meta_remaining =
        remaining_bytes_after_failed_remove(meta_gone, &candidate.meta_path, "meta").await;

    if let (Some(b), Some(m)) = (body_remaining, meta_remaining) {
        let actual_remaining = b + m;
        *current_size = current_size
            .saturating_sub(candidate.size)
            .saturating_add(actual_remaining);
        tracing::warn!(
            path = %candidate.body_path.display(),
            body_error = ?body_res.as_ref().err().map(|e| e.kind()),
            meta_error = ?meta_res.as_ref().err().map(|e| e.kind()),
            actual_remaining,
            "eviction: removal failed with I/O error, budget adjusted to measured remaining size"
        );
    } else {
        // Stat uncertainty on at least one path. Leave current_size
        // unchanged so the entry's full candidate.size stays counted
        // toward the budget — this is the conservative direction.
        tracing::warn!(
            path = %candidate.body_path.display(),
            body_error = ?body_res.as_ref().err().map(|e| e.kind()),
            meta_error = ?meta_res.as_ref().err().map(|e| e.kind()),
            "eviction: removal failed and stat uncertain, keeping full entry size in budget"
        );
    }
}

/// After a remove_file call, classify how many bytes that path still
/// contributes to the cache footprint.
///
/// Returns:
///   - `Some(0)` if `gone` (the remove succeeded or returned NotFound — the
///     file is genuinely off disk).
///   - `Some(0)` if the post-remove stat returns NotFound (the file vanished
///     between the remove and the stat call).
///   - `Some(m.len())` if the post-remove stat returns Ok.
///   - `None` if the post-remove stat returns any other error — remaining
///     size is unknown and the caller must treat the bytes as still on disk.
async fn remaining_bytes_after_failed_remove(
    gone: bool,
    path: &std::path::Path,
    label: &'static str,
) -> Option<u64> {
    if gone {
        return Some(0);
    }
    match tokio::fs::metadata(path).await {
        Ok(m) => Some(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(0),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                label,
                error_kind = ?e.kind(),
                "eviction: stat after failed remove returned error, assuming bytes still on disk"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::key::CacheKey;
    use crate::cache::metadata::CacheMeta;
    use chrono::Utc;

    async fn setup_cache_entry(
        cache_dir: &std::path::Path,
        key: &CacheKey,
        body: &[u8],
        last_accessed_at: chrono::DateTime<Utc>,
    ) {
        let hash = key.hash_hex();
        let (d1, d2) = key.dir_prefix();
        let dir = cache_dir.join("objects").join(d1).join(d2);
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let body_path = dir.join(format!("{}.body", hash));
        let meta_path = dir.join(format!("{}.meta.json", hash));

        tokio::fs::write(&body_path, body).await.unwrap();

        let meta = CacheMeta {
            bucket: key.bucket.clone(),
            key: key.object_key.clone(),
            etag: None,
            last_modified: None,
            content_type: Some("application/octet-stream".into()),
            content_length: body.len() as i64,
            cache_written_at: last_accessed_at,
            fill_id: 0,
            metadata_version: 0,
            last_accessed_at,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
            head_extra_headers: std::collections::HashMap::new(),
            head_checksum_headers: std::collections::HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        };
        let meta_json = serde_json::to_vec(&meta).unwrap();
        tokio::fs::write(&meta_path, &meta_json).await.unwrap();
    }

    #[tokio::test]
    async fn test_eviction_pass_under_limit_does_nothing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        tokio::fs::create_dir_all(cache_dir.join("objects"))
            .await
            .unwrap();

        let key = CacheKey::new("bucket", "script_bundle/small.js");
        let body = b"small body";
        setup_cache_entry(&cache_dir, &key, body, Utc::now()).await;

        let stats = Arc::new(CacheStats::default());
        // Stats start at zero — the scan reconciles them to filesystem reality.

        // Set limit very high
        run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .unwrap();

        // Entry should still exist
        let hash = key.hash_hex();
        let (d1, d2) = key.dir_prefix();
        let body_path = cache_dir
            .join("objects")
            .join(d1)
            .join(d2)
            .join(format!("{}.body", hash));
        assert!(body_path.exists());

        let snap = stats.snapshot();
        // Reconciliation should have set entry_count to 1 and total_bytes > 0.
        assert_eq!(snap.entry_count, 1);
        assert!(
            snap.total_bytes > 0,
            "reconciliation should have computed total_bytes"
        );
        assert_eq!(snap.eviction_count, 0);
    }

    #[tokio::test]
    async fn test_eviction_pass_removes_oldest_entries() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        tokio::fs::create_dir_all(cache_dir.join("objects"))
            .await
            .unwrap();

        let now = Utc::now();

        // Create 3 entries with different access times
        let key_old = CacheKey::new("bucket", "script_bundle/old.js");
        let key_mid = CacheKey::new("bucket", "script_bundle/mid.js");
        let key_new = CacheKey::new("bucket", "script_bundle/new.js");

        // Use 1000-byte bodies so we know the sizes
        let body = vec![0u8; 1000];

        setup_cache_entry(
            &cache_dir,
            &key_old,
            &body,
            now - chrono::Duration::hours(3),
        )
        .await;
        setup_cache_entry(
            &cache_dir,
            &key_mid,
            &body,
            now - chrono::Duration::hours(2),
        )
        .await;
        setup_cache_entry(&cache_dir, &key_new, &body, now).await;

        // Stats start at zero — the scan reconciles them from disk.
        let stats = Arc::new(CacheStats::default());

        // Set limit so only ~1 entry fits (body + meta ~= 1200 bytes each, so ~1500 is one entry)
        run_eviction_pass_inner(&cache_dir, 1500, &stats, None)
            .await
            .unwrap();

        // The oldest entries should be evicted, newest should remain
        let hash_old = key_old.hash_hex();
        let (d1, d2) = key_old.dir_prefix();
        let body_path_old = cache_dir
            .join("objects")
            .join(d1)
            .join(d2)
            .join(format!("{}.body", hash_old));
        assert!(
            !body_path_old.exists(),
            "oldest entry should have been evicted"
        );

        let hash_new = key_new.hash_hex();
        let (d1, d2) = key_new.dir_prefix();
        let body_path_new = cache_dir
            .join("objects")
            .join(d1)
            .join(d2)
            .join(format!("{}.body", hash_new));
        assert!(body_path_new.exists(), "newest entry should remain");

        let snap = stats.snapshot();
        assert!(snap.eviction_count >= 1, "at least one entry evicted");
        assert_eq!(snap.entry_count, 1);
    }

    // Note: the lock-aware eviction paths (meta_lock_for_hash) are exercised
    // indirectly through DiskCache integration tests. Adding a standalone test
    // here requires trait-method dispatch that conflicts with Rust's type
    // inference for impl-Future-returning traits.

    /// Verify that an entry whose body was initially missing but appeared
    /// before the scan is counted in totals and survives under-limit eviction.
    /// Note: this exercises the steady-state path (body exists when scanned);
    /// the lock-aware race branch requires a real DiskCache which cannot be
    /// easily constructed in unit tests due to trait dispatch constraints.
    #[tokio::test]
    async fn test_eviction_scan_counts_entry_with_late_body() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let key = CacheKey::new("bucket", "script_bundle/race.js");
        let now = Utc::now();

        // Write only the metadata — no body yet.
        let hash = key.hash_hex();
        let (d1, d2) = key.dir_prefix();
        let dir = cache_dir.join("objects").join(d1).join(d2);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let meta = CacheMeta {
            bucket: "bucket".into(),
            key: "script_bundle/race.js".into(),
            etag: None,
            last_modified: None,
            content_type: None,
            content_length: 5,
            cache_written_at: now,
            fill_id: 99,
            metadata_version: 0,
            last_accessed_at: now,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
            head_extra_headers: std::collections::HashMap::new(),
            head_checksum_headers: std::collections::HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        };
        let meta_path = dir.join(format!("{hash}.meta.json"));
        let body_path = dir.join(format!("{hash}.body"));
        tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap())
            .await
            .unwrap();
        // Body is missing — simulate the race window.

        // Now write the body (as if commit_fill completed mid-scan).
        tokio::fs::write(&body_path, b"hello").await.unwrap();

        let stats = Arc::new(CacheStats::default());
        run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .unwrap();

        // The entry should be counted despite the initial body-missing probe.
        assert_eq!(stats.entry_count.load(Ordering::Relaxed), 1);
        assert!(stats.total_bytes.load(Ordering::Relaxed) > 0);
        // Files should still exist (under limit).
        assert!(tokio::fs::try_exists(&body_path).await.unwrap());
        assert!(tokio::fs::try_exists(&meta_path).await.unwrap());
    }

    #[tokio::test]
    async fn test_eviction_on_empty_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        // Don't even create the objects dir
        let stats = Arc::new(CacheStats::default());

        // Should not error
        let result = run_eviction_pass_inner(&cache_dir, 1000, &stats, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_eviction_on_empty_objects_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        tokio::fs::create_dir_all(cache_dir.join("objects"))
            .await
            .unwrap();

        let stats = Arc::new(CacheStats::default());

        let result = run_eviction_pass_inner(&cache_dir, 1000, &stats, None).await;
        assert!(result.is_ok());

        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 0);
        assert_eq!(snap.total_bytes, 0);
    }

    #[tokio::test]
    async fn test_reconciliation_corrects_drifted_stats() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        tokio::fs::create_dir_all(cache_dir.join("objects"))
            .await
            .unwrap();

        let key = CacheKey::new("bucket", "script_bundle/item.js");
        let body = b"some body content";
        setup_cache_entry(&cache_dir, &key, body, Utc::now()).await;

        // Simulate drifted stats: entry_count and total_bytes are wrong.
        let stats = Arc::new(CacheStats::default());
        stats.entry_count.store(99, Ordering::Relaxed);
        stats.total_bytes.store(999_999, Ordering::Relaxed);

        // Run eviction with a high limit (no eviction needed).
        run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .unwrap();

        // Stats should be reconciled to actual filesystem state.
        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 1, "reconciliation should fix entry_count");
        assert!(
            snap.total_bytes < 1000,
            "reconciliation should fix total_bytes"
        );
        assert!(
            snap.total_bytes > 0,
            "total_bytes should reflect actual files"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_eviction_body_stat_error_aborts_without_reconciling_stats() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let key = CacheKey::new("bucket", "script_bundle/bad-body.js");
        let hash = key.hash_hex();
        let (d1, d2) = key.dir_prefix();
        let dir = cache_dir.join("objects").join(d1).join(d2);
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let now = Utc::now();
        let meta = CacheMeta {
            bucket: "bucket".into(),
            key: "script_bundle/bad-body.js".into(),
            etag: None,
            last_modified: None,
            content_type: Some("application/octet-stream".into()),
            content_length: 5,
            cache_written_at: now,
            fill_id: 0,
            metadata_version: 0,
            last_accessed_at: now,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
            head_extra_headers: std::collections::HashMap::new(),
            head_checksum_headers: std::collections::HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        };
        let meta_path = dir.join(format!("{hash}.meta.json"));
        let body_path = dir.join(format!("{hash}.body"));
        tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap())
            .await
            .unwrap();
        std::os::unix::fs::symlink(&body_path, &body_path).unwrap();

        let stats = Arc::new(CacheStats::default());
        stats.entry_count.store(9, Ordering::Relaxed);
        stats.total_bytes.store(999, Ordering::Relaxed);

        let err = run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("stat body during eviction scan"));

        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 9);
        assert_eq!(snap.total_bytes, 999);
    }

    #[tokio::test]
    async fn test_orphan_cleanup_without_stat_adjustments() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let objects_dir = cache_dir.join("objects");
        tokio::fs::create_dir_all(&objects_dir).await.unwrap();

        // Create a valid entry
        let key = CacheKey::new("bucket", "script_bundle/valid.js");
        let body = b"valid content";
        setup_cache_entry(&cache_dir, &key, body, Utc::now()).await;

        // Create an orphan body file (no matching metadata)
        let orphan_dir = objects_dir.join("ab").join("cd");
        tokio::fs::create_dir_all(&orphan_dir).await.unwrap();
        let orphan_body = orphan_dir.join("abcd0000dead0000.body");
        tokio::fs::write(&orphan_body, b"orphan data")
            .await
            .unwrap();

        // Simulate overstated stats (as if the orphan was still counted).
        let stats = Arc::new(CacheStats::default());
        stats.entry_count.store(2, Ordering::Relaxed);
        stats.total_bytes.store(999_999, Ordering::Relaxed);

        run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .unwrap();

        // Orphan should be removed.
        assert!(!orphan_body.exists(), "orphan body should be cleaned up");

        // Stats should be reconciled to just the valid entry.
        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 1);
        assert!(snap.total_bytes < 1000);
    }

    /// RAII guard that captures a directory's permissions on construction
    /// and restores them on drop. Used to keep TempDir cleanup robust when a
    /// test panics mid-way through a chmod-locked region.
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
            // Best effort: if perms can't be restored, TempDir cleanup will
            // surface the problem on its own.
            let _ = std::fs::set_permissions(&self.path, self.original.clone());
        }
    }

    /// Documents the broader "remove failed → counts not decremented" contract
    /// using parent dir mode 0o500 (r-x, no write): remove_file fails with
    /// EACCES while metadata still succeeds (the exec bit lets stat traverse).
    ///
    /// Note: this scenario does NOT exercise the stat-failure undercount fix
    /// from this commit — under both the old `unwrap_or(0)` and the new
    /// `Option<u64>` classifier the `actual_remaining` would equal
    /// `candidate.size` and produce identical observable counters. The
    /// stat-failure regression is locked in by
    /// `test_try_evict_candidate_keeps_budget_when_remove_and_stat_fail`
    /// below.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_eviction_remove_failure_does_not_decrement_counts() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        tokio::fs::create_dir_all(cache_dir.join("objects"))
            .await
            .unwrap();

        let key = CacheKey::new("bucket", "script_bundle/locked.js");
        let body = vec![0u8; 1000];
        setup_cache_entry(
            &cache_dir,
            &key,
            &body,
            Utc::now() - chrono::Duration::hours(1),
        )
        .await;

        let (d1, d2) = key.dir_prefix();
        let parent = cache_dir.join("objects").join(d1).join(d2);
        let _restore = ChmodOnDrop::new(&parent);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();

        let stats = Arc::new(CacheStats::default());
        run_eviction_pass_inner(&cache_dir, 1, &stats, None)
            .await
            .unwrap();

        let hash = key.hash_hex();
        assert!(parent.join(format!("{hash}.body")).exists());
        assert!(parent.join(format!("{hash}.meta.json")).exists());

        let snap = stats.snapshot();
        assert_eq!(
            snap.entry_count, 1,
            "failed eviction must not decrement entry_count"
        );
        assert_eq!(
            snap.eviction_count, 0,
            "failed eviction must not bump eviction_count"
        );
        assert!(
            snap.total_bytes > 0,
            "total_bytes should still reflect on-disk bytes"
        );
    }

    /// Locks in the stat-failure regression: when both remove_file AND the
    /// follow-up metadata fail with non-NotFound errors (here forced via
    /// parent dir mode 0o000: no read, no exec, no write — path traversal
    /// fails), `try_evict_candidate` must leave `current_size` unchanged.
    ///
    /// Under the old `unwrap_or(0)` implementation the classifier would
    /// have produced `actual_remaining = 0`, shrunk current_size by the
    /// full candidate.size, and recreated the "hard failure counted as
    /// reclaimed" bug Finding 2 was supposed to fix. The new
    /// `Option<u64>` classifier returns `None` and the partial branch
    /// leaves the budget alone.
    ///
    /// Calls `try_evict_candidate` directly because the scan above
    /// `run_eviction_pass_inner` requires the same `r+x` traversal that
    /// 0o000 forbids — there's no portable way to scan-then-lock between
    /// the two stages of one pass.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_try_evict_candidate_keeps_budget_when_remove_and_stat_fail() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let body_path = dir.join("hh.body");
        let meta_path = dir.join("hh.meta.json");
        // Contents irrelevant — chmod 0o000 below makes both remove and
        // stat fail before any file content matters.
        tokio::fs::write(&body_path, vec![0u8; 1000]).await.unwrap();
        tokio::fs::write(&meta_path, b"{}").await.unwrap();

        let candidate = EvictionCandidate {
            body_path: body_path.clone(),
            meta_path: meta_path.clone(),
            hash: "hh".into(),
            fill_id: 0,
            last_accessed_at: Utc::now(),
            size: 1500,
        };

        // Block traversal so both remove_file and metadata fail with EACCES.
        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let stats = Arc::new(CacheStats::default());
        stats.entry_count.store(1, Ordering::Relaxed);
        stats.total_bytes.store(1500, Ordering::Relaxed);

        let mut current_size: u64 = 1500;
        let mut evicted: u64 = 0;
        try_evict_candidate(&candidate, &mut current_size, &mut evicted, &stats, None).await;

        // The regression: under unwrap_or(0) this would be 0. Under the
        // Option<u64> classifier (returning None on stat failure) the
        // partial branch leaves current_size untouched.
        assert_eq!(
            current_size, 1500,
            "stat-failure path must not undercount the budget"
        );
        assert_eq!(evicted, 0, "stat-failure path must not bump evicted count");
        let snap = stats.snapshot();
        assert_eq!(
            snap.entry_count, 1,
            "stat-failure path must not decrement entry_count"
        );
        assert_eq!(
            snap.total_bytes, 1500,
            "stat-failure path must not decrement total_bytes"
        );
    }

    /// Common-case coverage for `measure_unreclaimed_after_failed_remove`:
    /// when the post-remove stat succeeds, the measured size wins over any
    /// `pre_known` baseline.
    #[tokio::test]
    async fn test_measure_unreclaimed_uses_post_stat_when_available() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("file");
        tokio::fs::write(&path, vec![0u8; 1500]).await.unwrap();

        let remove_err =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic test error");
        let result = measure_unreclaimed_after_failed_remove(&path, Some(99_999), &remove_err)
            .await
            .unwrap();
        assert_eq!(
            result, 1500,
            "post-stat measurement should win over pre_known when it succeeds"
        );
    }

    /// Common-case coverage: when the post-remove stat returns NotFound
    /// (the file vanished between the remove and the stat), return 0
    /// regardless of `pre_known` — the bytes are genuinely off disk.
    #[tokio::test]
    async fn test_measure_unreclaimed_returns_zero_on_post_stat_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("never-existed");

        let remove_err =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic test error");
        let result = measure_unreclaimed_after_failed_remove(&path, Some(99_999), &remove_err)
            .await
            .unwrap();
        assert_eq!(
            result, 0,
            "NotFound post-stat means the file is genuinely gone"
        );
    }

    /// Locks in the regression behind this commit: when both `remove_file`
    /// AND the follow-up `metadata` fail with non-NotFound errors (here
    /// forced via parent dir mode 0o000: no read, no exec, no write — path
    /// traversal fails), `measure_unreclaimed_after_failed_remove` must fall
    /// back to the pre-known baseline rather than silently returning 0.
    ///
    /// Under the old `unwrap_or(0)` implementation the function would have
    /// returned 0, the caller's `*scan_total_bytes += 0` would have left
    /// orphan/corrupt bytes uncounted, and the eviction loop's budget would
    /// have undercounted disk usage indefinitely (until a future scan didn't
    /// hit the stat failure). The helper now matches on `pre_known`:
    /// `Some(pre) => Ok(pre)` so the caller-supplied baseline survives the
    /// stat failure, and `None => Err(...)` so the residual silent-zero
    /// case aborts the pass instead of undercounting.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_measure_unreclaimed_falls_back_to_pre_known_when_stat_fails() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("locked");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("orphan.body");
        tokio::fs::write(&path, vec![0u8; 1500]).await.unwrap();

        // Block traversal so the post-remove stat fails with EACCES.
        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let remove_err =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic test error");
        // Caller knows the size from a prior observation (e.g. pre-stat).
        let result = measure_unreclaimed_after_failed_remove(&path, Some(1500), &remove_err)
            .await
            .unwrap();

        assert_eq!(
            result, 1500,
            "stat failure must fall back to pre_known size, not silently zero"
        );
    }

    /// Locks in the regression behind this commit: when the OrphanBody
    /// recheck `try_exists(meta_path)` fails AND the conservative-count
    /// `metadata(body_path)` fallback also fails (here forced via parent dir
    /// mode 0o000: no read, no exec, no write — both probes hit EACCES),
    /// `process_deferred_cleanups` must abort with an error rather than
    /// silently treating the unreclaimed bytes as zero.
    ///
    /// Under the old `unwrap_or(0)` implementation the function returned Ok
    /// with `scan_total_bytes` left unchanged (zero added for an unknown
    /// body), which let on-disk bytes silently drop out of the eviction
    /// budget. The new code returns Err on a non-NotFound stat failure;
    /// `collect_candidates` propagates the Err and `run_eviction_loop` logs
    /// "eviction pass failed", leaving stats at their pre-pass values so
    /// the next pass can retry without corrupted reconciliation.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_orphan_body_stat_failure_aborts_reconciliation() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let body_path = dir.join("hh.body");
        tokio::fs::write(&body_path, vec![0u8; 1500]).await.unwrap();

        // Block traversal so both try_exists(meta_path) and
        // metadata(body_path) fail with EACCES.
        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let cleanup = DeferredCleanup::OrphanBody {
            body_path: body_path.clone(),
            hash: "hh".into(),
        };

        let mut candidates = Vec::new();
        let mut total_bytes = 0u64;
        let mut entry_count = 0u64;
        let mut deferred_cleanup_failed = 0u64;
        let result = process_deferred_cleanups(
            vec![cleanup],
            None,
            &mut candidates,
            &mut total_bytes,
            &mut entry_count,
            &mut deferred_cleanup_failed,
        )
        .await;

        // Bug behavior: result.is_ok() && total_bytes == 0 — silent zero.
        // Fix behavior: result.is_err() — abort and let next pass retry.
        assert!(
            result.is_err(),
            "stat failure must abort cleanup, not silently zero unreclaimed bytes"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("stat orphan body"),
            "error should identify the failing operation, got: {err_msg}"
        );
    }

    /// Locks in the regression behind this commit: when the changed-entry
    /// remeasure branch in `try_evict_candidate` cannot stat one of the
    /// candidate's files (here forced via a self-symlink at `body_path`,
    /// which makes `metadata` follow the symlink and fail with ELOOP),
    /// `current_size` must be left unchanged for this candidate.
    ///
    /// Under the old `unwrap_or(0)` implementation the body stat would
    /// have collapsed to 0 and `current_size` would have been
    /// `current_size - candidate.size + meta_size` — an undercount of the
    /// budget that could stop the eviction loop early. The fix classifies
    /// each stat as `Some(len) | Some(0) | None` and only adjusts when
    /// both are `Some`.
    ///
    /// Reconciled global stats (`stats.total_bytes`, `stats.entry_count`)
    /// must also be untouched on this branch — this is local-budget
    /// hygiene only.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_changed_entry_remeasure_keeps_budget_when_stat_fails() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        // Write a meta whose fill_id differs from the candidate's, so the
        // "entry changed since scan" branch is entered.
        let now = Utc::now();
        let on_disk_meta = CacheMeta {
            bucket: "bucket".into(),
            key: "k".into(),
            etag: None,
            last_modified: None,
            content_type: None,
            content_length: 0,
            cache_written_at: now,
            // Different from candidate.fill_id below — triggers the
            // changed-entry branch.
            fill_id: 99,
            metadata_version: 0,
            last_accessed_at: now,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
            head_extra_headers: std::collections::HashMap::new(),
            head_checksum_headers: std::collections::HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        };
        let meta_path = dir.join("hh.meta.json");
        let body_path = dir.join("hh.body");
        tokio::fs::write(&meta_path, serde_json::to_vec(&on_disk_meta).unwrap())
            .await
            .unwrap();
        // Self-symlink: tokio::fs::metadata follows symlinks, so this
        // returns ELOOP — a non-NotFound stat error.
        std::os::unix::fs::symlink(&body_path, &body_path).unwrap();

        let candidate = EvictionCandidate {
            body_path: body_path.clone(),
            meta_path: meta_path.clone(),
            hash: "hh".into(),
            // fill_id mismatch with on-disk meta triggers the changed branch.
            fill_id: 0,
            last_accessed_at: now,
            size: 1500,
        };

        let stats = Arc::new(CacheStats::default());
        stats.entry_count.store(7, Ordering::Relaxed);
        stats.total_bytes.store(7777, Ordering::Relaxed);

        let mut current_size: u64 = 1500;
        let mut evicted: u64 = 0;
        try_evict_candidate(&candidate, &mut current_size, &mut evicted, &stats, None).await;

        // The regression: under unwrap_or(0) this would be
        // 1500 - 1500 + meta_size ≈ a few hundred bytes. Under the fix it
        // stays at 1500 because the body stat is unknown.
        assert_eq!(
            current_size, 1500,
            "stat-failure path must not undercount current_size"
        );
        assert_eq!(evicted, 0, "changed-entry branch must not bump evicted");
        // Reconciled global stats must be untouched on this branch.
        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 7, "global entry_count must be untouched");
        assert_eq!(
            snap.total_bytes, 7777,
            "global total_bytes must be untouched"
        );
    }

    /// Locks in the regression behind this commit: when scan_hash_dir_for_eviction
    /// encounters a file whose name is not valid UTF-8, the function must
    /// abort with an error including the offending path rather than silently
    /// skipping the entry. Silent skipping would undercount orphan/cleanup
    /// detection; synthesizing a lossy fallback identifier would risk wrong
    /// locking semantics on what is almost certainly external junk (the
    /// cache writer only emits UTF-8 hex-hash filenames + ASCII suffixes).
    ///
    /// Linux-only: macOS APFS / HFS+ reject non-UTF-8 filenames at the
    /// filesystem layer with "Illegal byte sequence", so the test setup
    /// can't even create the offending file there. CI runs on Linux
    /// (ubuntu-latest in .github/workflows/ci.yml), where this works.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_scan_aborts_on_non_utf8_filename() {
        use std::os::unix::ffi::OsStringExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        // Bytes that are NOT valid UTF-8: 0xff is never a valid continuation
        // byte and never a valid leading byte either.
        let bad_name = std::ffi::OsString::from_vec(vec![0xff, 0xfe, 0xfd]);
        let bad_path = dir.join(&bad_name);
        std::fs::write(&bad_path, b"junk").unwrap();

        let err = match scan_hash_dir_for_eviction(dir.clone()).await {
            Ok(_) => panic!("non-UTF-8 filename inside hash shard must abort the scan"),
            Err(e) => e,
        };
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("non-UTF-8") || err_msg.contains("not valid UTF-8"),
            "error should identify the cause, got: {err_msg}"
        );
    }

    /// Locks in the regression behind this commit: when the locked meta
    /// reread in `try_evict_candidate` hits a hard I/O error (here forced
    /// by chmod 0o000 on the meta file itself — read fails with EACCES
    /// while remove_file still succeeds because unlink only needs
    /// write+exec on the parent dir), the function must skip the
    /// candidate without falling through to the delete path.
    ///
    /// Under the old chained `if let` the read error would have caused
    /// the chain to short-circuit and the unconditional remove_file
    /// calls below would have deleted the body and meta — which is
    /// unsafe because the entry's identity is unknown and the bytes may
    /// belong to a concurrent fill or a still-valid entry.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_locked_meta_read_io_error_skips_candidate_without_deleting() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let now = Utc::now();
        let on_disk_meta = CacheMeta {
            bucket: "bucket".into(),
            key: "k".into(),
            etag: None,
            last_modified: None,
            content_type: None,
            content_length: 1000,
            cache_written_at: now,
            fill_id: 0,
            metadata_version: 0,
            last_accessed_at: now,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
            head_extra_headers: std::collections::HashMap::new(),
            head_checksum_headers: std::collections::HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        };
        let meta_path = dir.join("hh.meta.json");
        let body_path = dir.join("hh.body");
        tokio::fs::write(&meta_path, serde_json::to_vec(&on_disk_meta).unwrap())
            .await
            .unwrap();
        tokio::fs::write(&body_path, vec![0u8; 1000]).await.unwrap();

        // Chmod the meta file (not the parent) to 0o000: read(meta) fails
        // with EACCES, but unlink(meta) and unlink(body) still succeed
        // because they only need write+exec on the parent dir. This is
        // exactly the setup where the bug would silently delete the
        // entry — observable as "body file no longer exists" after the
        // call.
        let _restore = ChmodOnDrop::new(&meta_path);
        std::fs::set_permissions(&meta_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let candidate = EvictionCandidate {
            body_path: body_path.clone(),
            meta_path: meta_path.clone(),
            hash: "hh".into(),
            fill_id: 0,
            last_accessed_at: now,
            size: 1500,
        };

        let stats = Arc::new(CacheStats::default());
        stats.entry_count.store(3, Ordering::Relaxed);
        stats.total_bytes.store(3333, Ordering::Relaxed);

        let mut current_size: u64 = 1500;
        let mut evicted: u64 = 0;
        try_evict_candidate(&candidate, &mut current_size, &mut evicted, &stats, None).await;

        // Under the bug (chained if-let): both files would have been
        // deleted, current_size would be 0, evicted would be 1, stats
        // decremented. Under the fix: hard read error → return early
        // without touching anything.
        assert!(
            body_path.exists(),
            "fix must NOT delete body when meta read fails with hard I/O error"
        );
        assert!(
            meta_path.exists(),
            "fix must NOT delete meta when meta read fails with hard I/O error"
        );
        assert_eq!(
            current_size, 1500,
            "hard meta-read error must not shrink current_size"
        );
        assert_eq!(evicted, 0, "hard meta-read error must not bump evicted");
        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 3, "global entry_count must be untouched");
        assert_eq!(
            snap.total_bytes, 3333,
            "global total_bytes must be untouched"
        );
    }

    /// Companion to the above: when the meta file is corrupt (read Ok,
    /// parse Err), `try_evict_candidate` must fall through to the delete
    /// path. Corrupt metadata is treated as cache-owned garbage; the same
    /// semantics are used elsewhere when corrupt entries are cleaned up
    /// under lock.
    #[tokio::test]
    async fn test_locked_meta_parse_failure_falls_through_to_delete() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let meta_path = dir.join("hh.meta.json");
        let body_path = dir.join("hh.body");
        tokio::fs::write(&meta_path, b"this is not valid json {{{")
            .await
            .unwrap();
        tokio::fs::write(&body_path, vec![0u8; 1000]).await.unwrap();

        let candidate = EvictionCandidate {
            body_path: body_path.clone(),
            meta_path: meta_path.clone(),
            hash: "hh".into(),
            fill_id: 0,
            last_accessed_at: Utc::now(),
            size: 1500,
        };

        let stats = Arc::new(CacheStats::default());
        stats.entry_count.store(1, Ordering::Relaxed);
        stats.total_bytes.store(1500, Ordering::Relaxed);

        let mut current_size: u64 = 1500;
        let mut evicted: u64 = 0;
        try_evict_candidate(&candidate, &mut current_size, &mut evicted, &stats, None).await;

        // Corrupt meta is treated as cache-owned garbage and removed.
        assert!(!body_path.exists(), "body should be deleted on parse error");
        assert!(!meta_path.exists(), "meta should be deleted on parse error");
        assert_eq!(
            current_size, 0,
            "current_size should drop by candidate.size"
        );
        assert_eq!(
            evicted, 1,
            "eviction should be counted on parse-error cleanup"
        );
    }

    /// Closes the residual silent-zero hole in `remove_file_or_reclaim_size`:
    /// when the internal pre-stat fails, the remove fails, AND the post-stat
    /// also fails (here forced via parent dir mode 0o000 — every probe hits
    /// EACCES), the helper must return `Err` so callers abort the pass
    /// rather than silently treating the unreclaimed bytes as zero.
    ///
    /// Under the prior `(path) -> u64` shape this case fell through to
    /// `pre_known.unwrap_or(0) = 0`, undercounting `scan_total_bytes` until
    /// a future pass that didn't hit the stat failure.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_remove_file_or_reclaim_size_errs_when_remove_and_both_stats_fail() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("locked");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("body");
        tokio::fs::write(&path, vec![0u8; 1500]).await.unwrap();

        // Block traversal so pre-stat, remove, and post-stat all fail with
        // EACCES — the residual silent-zero case.
        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let result = remove_file_or_reclaim_size(&path).await;

        let err = result.expect_err(
            "remove_file_or_reclaim_size must Err when remove fails AND no size is knowable",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("stat after failed remove"),
            "error should identify the failing operation, got: {msg}"
        );
    }

    /// Closes the residual silent-zero hole at the call-site level:
    /// `process_deferred_cleanups` must propagate the `Err` from
    /// `remove_entry_files` when the parent directory is locked down so all
    /// child file ops fail. `MalformedHash` is the cleanest variant for
    /// this — it goes through `remove_entry_files` directly, with no
    /// `try_exists` short-circuit ahead of it.
    ///
    /// Under the prior `(path) -> u64` shape this returned `Ok(())` with
    /// `scan_total_bytes` left at 0 — silent zero, reconciliation overwrote
    /// stats with an undercounted total, and the cache could stay over
    /// `max_bytes` indefinitely. With the fix, the `Err` aborts the pass
    /// before stats are touched and the next tick retries.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_malformed_hash_cleanup_propagates_unknown_remaining_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let meta_path = dir.join("hh.meta.json");
        let body_path = dir.join("hh.body");
        let poison_path = dir.join("hh.poisoned");
        tokio::fs::write(&meta_path, b"{}").await.unwrap();
        tokio::fs::write(&body_path, vec![0u8; 1500]).await.unwrap();
        tokio::fs::write(&poison_path, b"").await.unwrap();

        // Block traversal: pre-stat, remove, and post-stat all fail with
        // EACCES for every child path.
        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let cleanup = DeferredCleanup::MalformedHash(EntryPaths {
            meta_path,
            body_path,
            poison_path,
            hash: "hh".into(),
        });

        let mut candidates = Vec::new();
        let mut total_bytes = 0u64;
        let mut entry_count = 0u64;
        let mut deferred_cleanup_failed = 0u64;
        let result = process_deferred_cleanups(
            vec![cleanup],
            None,
            &mut candidates,
            &mut total_bytes,
            &mut entry_count,
            &mut deferred_cleanup_failed,
        )
        .await;

        // Bug behavior: result.is_ok() && total_bytes == 0 — silent zero
        // would propagate to reconciliation and undercount the budget.
        // Fix behavior: result.is_err() — abort and let the next pass retry.
        let err = result.expect_err(
            "MalformedHash cleanup must Err when remaining bytes are unknown, not silently zero",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("stat after failed remove"),
            "error should identify the failing operation, got: {msg}"
        );
        assert_eq!(
            deferred_cleanup_failed, 1,
            "MalformedHash abort must bump deferred_cleanup_failed",
        );
    }

    /// A successful eviction pass must record the duration histogram with
    /// the `phase="eviction"` label and publish the unreclaimed-bytes gauge.
    /// Uses the metrics-exporter-prometheus local recorder so the assertions
    /// can read back the exact rendered output without touching the global
    /// recorder (which would conflict with parallel tests).
    #[tokio::test(flavor = "current_thread")]
    async fn test_eviction_pass_emits_observability_metrics() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        tokio::fs::create_dir_all(cache_dir.join("objects"))
            .await
            .unwrap();
        let key = CacheKey::new("bucket", "script_bundle/observed.js");
        setup_cache_entry(&cache_dir, &key, b"observed body", Utc::now()).await;

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let stats = Arc::new(CacheStats::default());
        run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .unwrap();

        let rendered = handle.render();
        assert!(
            rendered.contains("s3proxy_cache_scan_duration_seconds"),
            "expected scan duration metric to be present, got:\n{rendered}",
        );
        assert!(
            rendered.contains("phase=\"eviction\""),
            "expected phase=\"eviction\" label on the duration metric, got:\n{rendered}",
        );
        // Single completed entry → candidate_bytes == scan_total_bytes,
        // unreclaimed_bytes is exactly 0.
        assert!(
            rendered.contains("s3proxy_cache_unreclaimed_bytes 0"),
            "expected unreclaimed_bytes gauge to be 0 for a clean pass, got:\n{rendered}",
        );
    }

    /// A failed eviction pass — here triggered by a self-symlink at the
    /// body path that makes `tokio::fs::metadata` follow the loop and fail
    /// with ELOOP — must increment `s3proxy_cache_scan_failed_total` with
    /// `reason="hash_dir_scan"` (the failing site is inside
    /// `scan_hash_dir_for_eviction`, not the deferred-cleanup phase).
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_eviction_pass_failure_emits_failed_counter() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let key = CacheKey::new("bucket", "script_bundle/symlink.js");
        let hash = key.hash_hex();
        let (d1, d2) = key.dir_prefix();
        let dir = cache_dir.join("objects").join(d1).join(d2);
        tokio::fs::create_dir_all(&dir).await.unwrap();

        let now = Utc::now();
        let meta = CacheMeta {
            bucket: "bucket".into(),
            key: "script_bundle/symlink.js".into(),
            etag: None,
            last_modified: None,
            content_type: Some("application/octet-stream".into()),
            content_length: 5,
            cache_written_at: now,
            fill_id: 0,
            metadata_version: 0,
            last_accessed_at: now,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
            head_extra_headers: std::collections::HashMap::new(),
            head_checksum_headers: std::collections::HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        };
        let meta_path = dir.join(format!("{hash}.meta.json"));
        let body_path = dir.join(format!("{hash}.body"));
        tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap())
            .await
            .unwrap();
        std::os::unix::fs::symlink(&body_path, &body_path).unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let stats = Arc::new(CacheStats::default());
        let err = run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .expect_err("self-symlink ELOOP should propagate as scan error");
        assert!(
            err.to_string().contains("stat body during eviction scan"),
            "unexpected error: {err}",
        );

        let rendered = handle.render();
        assert!(
            rendered.contains(
                "s3proxy_cache_scan_failed_total{phase=\"eviction\",reason=\"hash_dir_scan\"} 1",
            ),
            "expected scan_failed_total{{phase=eviction,reason=hash_dir_scan}}, got:\n{rendered}",
        );
    }

    /// `process_deferred_cleanups` must increment
    /// `s3proxy_cache_deferred_cleanup_failed_total{kind="malformed_hash"}`
    /// when a `MalformedHash` cleanup aborts — exercises the kind-labeled
    /// counter directly without needing the full scan path.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_process_deferred_cleanups_failure_emits_kind_counter() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let meta_path = dir.join("hh.meta.json");
        let body_path = dir.join("hh.body");
        let poison_path = dir.join("hh.poisoned");
        tokio::fs::write(&meta_path, b"{}").await.unwrap();
        tokio::fs::write(&body_path, vec![0u8; 1500]).await.unwrap();
        tokio::fs::write(&poison_path, b"").await.unwrap();

        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let cleanup = DeferredCleanup::MalformedHash(EntryPaths {
            meta_path,
            body_path,
            poison_path,
            hash: "hh".into(),
        });

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let mut candidates = Vec::new();
        let mut total_bytes = 0u64;
        let mut entry_count = 0u64;
        let mut deferred_cleanup_failed = 0u64;
        let result = process_deferred_cleanups(
            vec![cleanup],
            None,
            &mut candidates,
            &mut total_bytes,
            &mut entry_count,
            &mut deferred_cleanup_failed,
        )
        .await;
        assert!(result.is_err(), "MalformedHash cleanup must Err");

        let rendered = handle.render();
        assert!(
            rendered.contains(
                "s3proxy_cache_deferred_cleanup_failed_total{kind=\"malformed_hash\"} 1",
            ),
            "expected deferred_cleanup_failed_total{{kind=malformed_hash}}, got:\n{rendered}",
        );
    }

    /// Regression test: when `read_dir(d2_path)` inside
    /// `scan_hash_dir_for_eviction` fails (here forced by chmod 0o000 on the
    /// leaf shard dir while leaving the layout walk intact), the failure
    /// must be classified as `reason="hash_dir_scan"` — not `reason="other"`.
    ///
    /// Under the prior substring-matching `eviction_failure_reason` helper,
    /// this leaf path returned a raw `Box<io::Error>` with no operation tag
    /// in its display string and was misclassified as `other`. The typed
    /// `ScanFailureReason::HashDirScan` carried in `EvictionScanError`
    /// removes that ambiguity.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_eviction_pass_classifies_hash_dir_read_dir_failure() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let shard = cache_dir.join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&shard).await.unwrap();

        // Block read_dir(shard) without breaking the d1 layout walk above
        // it. file_type() on the shard entry uses DT_TYPE from getdents and
        // does not require traversal, so the strict layout walk succeeds.
        let _restore = ChmodOnDrop::new(&shard);
        std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o000)).unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let stats = Arc::new(CacheStats::default());
        let err = run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .expect_err("read_dir on locked shard should propagate as scan error");
        assert!(
            err.to_string().contains("read hash shard dir"),
            "unexpected error: {err}",
        );

        let rendered = handle.render();
        assert!(
            rendered.contains(
                "s3proxy_cache_scan_failed_total{phase=\"eviction\",reason=\"hash_dir_scan\"} 1",
            ),
            "expected scan_failed_total{{reason=hash_dir_scan}}, got:\n{rendered}",
        );
    }

    /// Regression test: when the strict layout walk in
    /// `collect_hash_dirs_strict` fails (here forced by chmod 0o000 on a
    /// `objects/<d1>/` hash-prefix dir so `read_dir(d1)` returns EACCES),
    /// the failure must be classified as `reason="hash_dir_walk"` — not
    /// `reason="other"`.
    ///
    /// The previous substring matcher only recognized `"read objects dir"`
    /// and `"iterate objects dir"`; the actual layout-walk operations are
    /// `"read hash prefix dir"` / `"iterate hash prefix dir"` (and their
    /// `check ... type` siblings). Routing through
    /// `ScanFailureReason::HashDirWalk` removes the dependency on the
    /// operation name.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_eviction_pass_classifies_layout_walk_failure() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let d1 = cache_dir.join("objects").join("aa");
        tokio::fs::create_dir_all(d1.join("bb")).await.unwrap();

        // Block read_dir(d1) without affecting the objects_dir probe above.
        // The probe's try_exists only stats objects_dir itself and succeeds.
        // file_type() on d1 (from objects_dir's getdents) does not need
        // traversal, so the walk reaches the read_dir(d1) call before
        // failing.
        let _restore = ChmodOnDrop::new(&d1);
        std::fs::set_permissions(&d1, std::fs::Permissions::from_mode(0o000)).unwrap();

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let stats = Arc::new(CacheStats::default());
        let err = run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .expect_err("strict layout walk on locked prefix dir should propagate");
        assert!(
            err.to_string().contains("read hash prefix dir")
                || err.to_string().contains("iterate hash prefix dir"),
            "unexpected error: {err}",
        );

        let rendered = handle.render();
        assert!(
            rendered.contains(
                "s3proxy_cache_scan_failed_total{phase=\"eviction\",reason=\"hash_dir_walk\"} 1",
            ),
            "expected scan_failed_total{{reason=hash_dir_walk}}, got:\n{rendered}",
        );
    }

    /// Regression test for the partial-cleanup recording fix:
    /// `remove_file_or_reclaim_size` returning `Ok(>0)` means the unlink
    /// failed but the bytes are still measurable on disk — that's a partial
    /// cleanup failure per the helper contract. Forced here via parent dir
    /// mode 0o500 (read+exec, no write): unlink fails with EACCES while the
    /// post-stat still succeeds, so the helper returns the file's size as
    /// `Ok(>0)`.
    ///
    /// Before the fix the bytes were folded into `scan_total_bytes` but
    /// neither the per-pass `deferred_cleanup_failed` count nor the
    /// kind-labeled counter were bumped, so partial failures were
    /// invisible to operators. After the fix both must rise by exactly 1.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_partial_orphan_body_cleanup_records_failure() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let body_path = dir.join("hh.body");
        tokio::fs::write(&body_path, vec![0u8; 1500]).await.unwrap();

        // 0o500: stat traverses, unlink fails with EACCES, so
        // remove_file_or_reclaim_size returns Ok(1500).
        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let cleanup = DeferredCleanup::OrphanBody {
            body_path: body_path.clone(),
            hash: "hh".into(),
        };

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let mut candidates = Vec::new();
        let mut total_bytes = 0u64;
        let mut entry_count = 0u64;
        let mut deferred_cleanup_failed = 0u64;
        process_deferred_cleanups(
            vec![cleanup],
            None,
            &mut candidates,
            &mut total_bytes,
            &mut entry_count,
            &mut deferred_cleanup_failed,
        )
        .await
        .expect("partial cleanup is a successful (lossy) outcome, not an Err return");

        assert_eq!(
            total_bytes, 1500,
            "unreclaimed bytes from the failed unlink must still be counted"
        );
        assert_eq!(
            deferred_cleanup_failed, 1,
            "partial cleanup must bump the per-pass failure count"
        );
        let rendered = handle.render();
        assert!(
            rendered
                .contains("s3proxy_cache_deferred_cleanup_failed_total{kind=\"orphan_body\"} 1"),
            "expected deferred_cleanup_failed_total{{kind=orphan_body}} = 1, got:\n{rendered}",
        );
    }

    /// Regression test: the `MissingBody::MissingBody` cleanup variant
    /// invokes `remove_file_or_reclaim_size` twice (meta + poison). When
    /// both removals partially fail, the kind-labeled counter must rise
    /// by exactly 1 — not 2. The per-pass `deferred_cleanup_failed`
    /// counter is a cleanup-count, not a per-file count.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn test_partial_two_remove_cleanup_counts_once() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("objects").join("aa").join("bb");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let meta_path = dir.join("hh.meta.json");
        let poison_path = dir.join("hh.poisoned");
        let body_path = dir.join("hh.body"); // intentionally absent
        // Write a meta whose JSON is broken so try_recover_entry returns
        // MetaParseError... actually we want MissingBody outcome from
        // try_recover_entry: body absent, meta valid. Easier: write valid
        // meta JSON.
        let now = Utc::now();
        let meta = CacheMeta {
            bucket: "bucket".into(),
            key: "k".into(),
            etag: None,
            last_modified: None,
            content_type: None,
            content_length: 0,
            cache_written_at: now,
            fill_id: 0,
            metadata_version: 0,
            last_accessed_at: now,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
            head_extra_headers: std::collections::HashMap::new(),
            head_checksum_headers: std::collections::HashMap::new(),
            checksum_mode_checked: false,
            head_metadata_checked: false,
            head_checksum_checked: false,
        };
        tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap())
            .await
            .unwrap();
        // Non-empty poison so its unreclaimed-bytes value is > 0; with an
        // empty file the partial-failure path silently returns Ok(0) and
        // a buggy per-file recorder would dodge the double-count check.
        tokio::fs::write(&poison_path, b"poisoned").await.unwrap();

        // 0o500: unlink fails (no write), stat still works (read+exec).
        let _restore = ChmodOnDrop::new(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let cleanup = DeferredCleanup::MissingBody(EntryPaths {
            meta_path: meta_path.clone(),
            body_path,
            poison_path: poison_path.clone(),
            hash: "hh".into(),
        });

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let mut candidates = Vec::new();
        let mut total_bytes = 0u64;
        let mut entry_count = 0u64;
        let mut deferred_cleanup_failed = 0u64;
        process_deferred_cleanups(
            vec![cleanup],
            None,
            &mut candidates,
            &mut total_bytes,
            &mut entry_count,
            &mut deferred_cleanup_failed,
        )
        .await
        .expect("partial cleanup must not abort the pass");

        // Both files still on disk → total_bytes = meta_size + poison_size.
        assert!(
            total_bytes > 0,
            "two failed unlinks must still count their bytes"
        );
        assert_eq!(
            deferred_cleanup_failed, 1,
            "two partial removals in one cleanup must count as one failure"
        );
        let rendered = handle.render();
        assert!(
            rendered
                .contains("s3proxy_cache_deferred_cleanup_failed_total{kind=\"missing_body\"} 1"),
            "expected exactly one missing_body increment, got:\n{rendered}",
        );
        assert!(
            !rendered
                .contains("s3proxy_cache_deferred_cleanup_failed_total{kind=\"missing_body\"} 2"),
            "two-remove cleanup must not double-count, got:\n{rendered}",
        );
    }

    /// Regression test for the no-objects-dir fast path: a pass that finds
    /// the cache directory missing must still emit the duration histogram,
    /// publish a fresh `s3proxy_cache_unreclaimed_bytes 0`, and reconcile
    /// stats to zero. Returning early skipped all three signals and left
    /// the gauge stale at the previous pass's value — invisible to
    /// operators that the cache is empty now.
    #[tokio::test(flavor = "current_thread")]
    async fn test_eviction_pass_no_objects_dir_emits_success_signals() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        // Don't create cache_dir/objects.

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let stats = Arc::new(CacheStats::default());
        // Seed with stale values so the test exercises the reconciliation
        // side too — the empty-cache pass must zero them.
        stats.entry_count.store(7, Ordering::Relaxed);
        stats.total_bytes.store(7777, Ordering::Relaxed);

        run_eviction_pass_inner(&cache_dir, 1_000_000, &stats, None)
            .await
            .expect("missing objects dir must not be a failure case");

        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 0, "stats must be reconciled to zero");
        assert_eq!(snap.total_bytes, 0, "stats must be reconciled to zero");

        let rendered = handle.render();
        assert!(
            rendered.contains("s3proxy_cache_scan_duration_seconds"),
            "duration histogram must be emitted on empty pass, got:\n{rendered}",
        );
        assert!(
            rendered.contains("phase=\"eviction\""),
            "duration histogram must carry phase=eviction label, got:\n{rendered}",
        );
        assert!(
            rendered.contains("s3proxy_cache_unreclaimed_bytes 0"),
            "empty pass must publish unreclaimed_bytes=0 (fresh, not stale), got:\n{rendered}",
        );
        assert!(
            !rendered.contains("s3proxy_cache_scan_failed_total"),
            "empty pass is a success, not a failure, got:\n{rendered}",
        );
    }
}
