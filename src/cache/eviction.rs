use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::cache::metadata::CacheMeta;

use super::CacheStats;

/// Concurrency limit for parallel hash-directory scans during eviction.
const EVICTION_SCAN_CONCURRENCY: usize = 64;

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

/// Collect all `objects/XX/YY/` directory paths for parallel processing.
async fn collect_hash_dirs(
    objects_dir: &std::path::Path,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error + Send + Sync>> {
    let mut hash_dirs = Vec::new();
    let mut d1_entries = tokio::fs::read_dir(objects_dir).await?;

    while let Some(d1_entry) = d1_entries.next_entry().await? {
        let d1_path = d1_entry.path();
        if !d1_path.is_dir() {
            continue;
        }

        let mut d2_entries = match tokio::fs::read_dir(&d1_path).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Box::new(e)),
        };

        while let Some(d2_entry) = d2_entries.next_entry().await? {
            let d2_path = d2_entry.path();
            if !d2_path.is_dir() {
                continue;
            }
            hash_dirs.push(d2_path);
        }
    }

    Ok(hash_dirs)
}

/// Scan a single hash directory and return candidates, stats, and deferred
/// cleanups that require per-key locks (which cannot be acquired inside a
/// spawned task because `DiskCache` is not `Send`-safe across spawn boundaries).
async fn scan_hash_dir_for_eviction(
    d2_path: PathBuf,
) -> Result<DirScanResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut result = DirScanResult {
        candidates: Vec::new(),
        total_bytes: 0,
        entry_count: 0,
        deferred_cleanups: Vec::new(),
    };

    let mut file_entries = match tokio::fs::read_dir(&d2_path).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(result),
        Err(e) => return Err(Box::new(e)),
    };

    loop {
        let file_entry = match file_entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => return Err(Box::new(e)),
        };
        let file_path = file_entry.path();
        let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
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
                        tracing::warn!(path = %meta_path.display(), error = %e, "orphan body probe failed, skipping");
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
                        tracing::warn!(path = %meta_path.display(), error = %e, "orphan poison probe failed, skipping");
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
                // Unreadable metadata — defer locked recheck rather than
                // aborting the entire eviction pass.
                tracing::warn!(
                    path = %file_path.display(),
                    error = %e,
                    "metadata unreadable during eviction scan, deferring cleanup"
                );
                let hash = hash_for_cleanup.to_string();
                let body = d2_path.join(format!("{}.body", hash));
                let poison = d2_path.join(format!("{hash}.poisoned"));
                result.deferred_cleanups.push(DeferredCleanup::CorruptEntry(EntryPaths {
                    meta_path: file_path,
                    body_path: body,
                    poison_path: poison,
                    hash,
                }));
                continue;
            }
        };
        let meta: CacheMeta = match serde_json::from_slice::<CacheMeta>(&meta_bytes) {
            Ok(m) => m,
            Err(_) => {
                // Genuinely corrupt metadata — defer locked cleanup.
                let hash = hash_for_cleanup.to_string();
                let body = d2_path.join(format!("{}.body", hash));
                let poison = d2_path.join(format!("{hash}.poisoned"));
                result.deferred_cleanups.push(DeferredCleanup::CorruptEntry(EntryPaths {
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
                result.deferred_cleanups.push(DeferredCleanup::MissingBody(EntryPaths {
                    meta_path: file_path,
                    body_path,
                    poison_path: poison,
                    hash: hash.to_string(),
                }));
                continue;
            }
            Err(e) => {
                // Non-NotFound body stat error — skip this entry without
                // aborting the whole shard. Byte count will be slightly off;
                // self-corrects on next eviction pass.
                tracing::warn!(
                    path = %body_path.display(),
                    error = %e,
                    "body stat failed during eviction scan, skipping entry"
                );
                continue;
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

/// Try to remove a file. If removal fails with a non-NotFound error, return
/// the file's size so the caller can add it back to the scan totals and keep
/// accounting accurate.
async fn remove_file_or_reclaim_size(path: &std::path::Path) -> u64 {
    match tokio::fs::remove_file(path).await {
        Ok(()) => 0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            let size = tokio::fs::metadata(path).await.map(|m| m.len()).unwrap_or(0);
            tracing::warn!(
                path = %path.display(),
                error = %e,
                size,
                "failed to remove cache file, counting bytes as unreclaimed"
            );
            size
        }
    }
}

/// Remove all three entry files, returning the total bytes that could not be
/// reclaimed (so the caller can keep accounting accurate).
async fn remove_entry_files(paths: &EntryPaths) -> u64 {
    let mut unreclaimed = 0u64;
    unreclaimed += remove_file_or_reclaim_size(&paths.meta_path).await;
    unreclaimed += remove_file_or_reclaim_size(&paths.body_path).await;
    unreclaimed += remove_file_or_reclaim_size(&paths.poison_path).await;
    unreclaimed
}

/// Outcome of attempting to recover a cache entry under lock.
enum RecoverOutcome {
    /// Entry is valid — body exists and metadata parsed successfully.
    Recovered { size: u64, candidate: EvictionCandidate },
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

/// Process deferred cleanups that require per-key lock coordination.
async fn process_deferred_cleanups(
    cleanups: Vec<DeferredCleanup>,
    disk_cache: Option<&super::DiskCache>,
    candidates: &mut Vec<EvictionCandidate>,
    scan_total_bytes: &mut u64,
    scan_entry_count: &mut u64,
) {
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
                        *scan_total_bytes += remove_file_or_reclaim_size(&body_path).await;
                        tracing::debug!(path = %body_path.display(), "removed orphan body file");
                    }
                    Ok(true) => {} // meta appeared (concurrent fill), not an orphan
                    Err(e) => {
                        // Can't confirm orphan status — conservatively count body bytes
                        // so stats don't undercount.
                        let size = tokio::fs::metadata(&body_path).await.map(|m| m.len()).unwrap_or(0);
                        *scan_total_bytes += size;
                        tracing::warn!(
                            path = %meta_path.display(),
                            error = %e,
                            "failed to recheck orphan body status under lock, counting bytes conservatively"
                        );
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
                        *scan_total_bytes += remove_file_or_reclaim_size(&poison_path).await;
                        tracing::debug!(path = %poison_path.display(), "removed orphan poison marker");
                    }
                    Ok(true) => {} // meta appeared, poison is valid
                    Err(e) => {
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
                        // clean up the leftover meta and poison.
                        *scan_total_bytes += remove_file_or_reclaim_size(&paths.meta_path).await;
                        *scan_total_bytes += remove_file_or_reclaim_size(&paths.poison_path).await;
                        tracing::debug!(path = %paths.meta_path.display(), "removed corrupt entry with missing body");
                    }
                    RecoverOutcome::BodyStatError(e) => {
                        // Body exists but unreadable — don't delete, treat as transient.
                        tracing::warn!(path = %paths.body_path.display(), error = %e, "corrupt entry body unreadable under lock, skipping");
                    }
                    RecoverOutcome::MetaReadError(e) => {
                        tracing::warn!(path = %paths.meta_path.display(), error = %e, "corrupt entry meta unreadable under lock, removing");
                        *scan_total_bytes += remove_entry_files(&paths).await;
                    }
                    RecoverOutcome::MetaParseError(e) => {
                        tracing::warn!(path = %paths.meta_path.display(), error = %e, "corrupt entry meta still unparseable under lock, removing");
                        *scan_total_bytes += remove_entry_files(&paths).await;
                    }
                }
            }
            DeferredCleanup::MalformedHash(paths) => {
                let _guard = acquire_meta_lock(disk_cache, &paths.hash).await;
                *scan_total_bytes += remove_entry_files(&paths).await;
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
                        // Still missing — clean up the leftover meta and poison.
                        *scan_total_bytes += remove_file_or_reclaim_size(&paths.meta_path).await;
                        *scan_total_bytes += remove_file_or_reclaim_size(&paths.poison_path).await;
                    }
                    RecoverOutcome::BodyStatError(e) => {
                        // Body unreadable — don't delete, treat as transient.
                        tracing::warn!(path = %paths.body_path.display(), error = %e, "missing-body entry body stat failed under lock, skipping");
                    }
                    RecoverOutcome::MetaReadError(_) | RecoverOutcome::MetaParseError(_) => {
                        // Body missing and meta is broken — clean up everything.
                        *scan_total_bytes += remove_entry_files(&paths).await;
                    }
                }
            }
        }
    }
}

/// Walk the objects directory, collect all cache entries as eviction candidates,
/// clean up orphans, and **reconcile stats** to match filesystem reality.
///
/// Hash directories (`objects/XX/YY/`) are processed in parallel using a
/// `JoinSet` with a semaphore-based concurrency limit. Deferred cleanups
/// that require per-key locks are processed sequentially after the parallel
/// scan completes.
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
}

async fn collect_candidates(
    objects_dir: &std::path::Path,
    stats: &Arc<CacheStats>,
    disk_cache: Option<&super::DiskCache>,
) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
    // Phase 1: Collect all hash directory paths.
    let hash_dirs = collect_hash_dirs(objects_dir).await?;
    if hash_dirs.is_empty() {
        stats.total_bytes.store(0, Ordering::Relaxed);
        stats.entry_count.store(0, Ordering::Relaxed);
        return Ok(ScanResult { candidates: Vec::new(), total_bytes: 0 });
    }

    // Phase 2: Process each hash directory in parallel.
    let semaphore = Arc::new(tokio::sync::Semaphore::new(EVICTION_SCAN_CONCURRENCY));
    let mut join_set = tokio::task::JoinSet::new();

    for dir_path in hash_dirs {
        let sem = semaphore.clone();
        join_set.spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            scan_hash_dir_for_eviction(dir_path).await
        });
    }

    // Phase 3: Aggregate results from all parallel tasks.
    let mut candidates = Vec::new();
    let mut scan_total_bytes: u64 = 0;
    let mut scan_entry_count: u64 = 0;
    let mut all_cleanups = Vec::new();

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(dir_result)) => {
                candidates.extend(dir_result.candidates);
                scan_total_bytes += dir_result.total_bytes;
                scan_entry_count += dir_result.entry_count;
                all_cleanups.extend(dir_result.deferred_cleanups);
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Err(e) => {
                return Err(Box::new(e));
            }
        }
    }

    // Phase 4: Process deferred cleanups under per-key locks.
    process_deferred_cleanups(
        all_cleanups,
        disk_cache,
        &mut candidates,
        &mut scan_total_bytes,
        &mut scan_entry_count,
    )
    .await;

    // Reconcile: overwrite atomics with the authoritative filesystem totals.
    // Any drift from concurrent commit_fill/purge since the last reconciliation
    // is corrected here.
    stats.total_bytes.store(scan_total_bytes, Ordering::Relaxed);
    stats.entry_count.store(scan_entry_count, Ordering::Relaxed);

    Ok(ScanResult { candidates, total_bytes: scan_total_bytes })
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
async fn run_eviction_pass_inner(
    cache_dir: &std::path::Path,
    max_bytes: u64,
    stats: &Arc<CacheStats>,
    disk_cache: Option<&super::DiskCache>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let objects_dir = cache_dir.join("objects");
    match tokio::fs::try_exists(&objects_dir).await {
        Ok(true) => {} // proceed
        Ok(false) => {
            // No objects directory — reconcile stats to zero.
            stats.entry_count.store(0, Ordering::Relaxed);
            stats.total_bytes.store(0, Ordering::Relaxed);
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(
                path = %objects_dir.display(),
                error = %e,
                "failed to check objects directory for eviction, skipping pass"
            );
            return Ok(());
        }
    }

    // collect_candidates walks the filesystem and reconciles stats.
    let scan = collect_candidates(&objects_dir, stats, disk_cache).await?;
    let mut candidates = scan.candidates;

    // Sort by last_accessed_at ascending (oldest first = evicted first)
    candidates.sort_by_key(|c| c.last_accessed_at);

    // Use the reconciled on-disk total for the eviction budget, not just
    // the candidate sum. This ensures unreclaimed bytes (from failed cleanup
    // deletions) count toward the limit — otherwise the cache could stay
    // over budget indefinitely when some files can't be removed.
    if scan.total_bytes <= max_bytes {
        return Ok(());
    }

    // Evict oldest entries until under limit. Stat adjustments here are
    // best-effort for between-scan responsiveness; the next scan reconciles
    // any drift from concurrent operations.
    let mut current_size = scan.total_bytes;
    let mut evicted = 0u64;
    for candidate in &candidates {
        if current_size <= max_bytes {
            break;
        }

        // Acquire the per-key metadata lock (if the DiskCache is available) so
        // eviction cannot race with rewrite_last_accessed or metadata updates
        // on the same entry.
        let meta_lock = disk_cache.map(|dc| dc.meta_lock_for_hash(&candidate.hash));
        let _meta_guard = match meta_lock.as_ref() {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };

        // Re-read metadata under the lock to confirm this is still the same
        // entry we scanned. A concurrent commit_fill() may have replaced it.
        if let Ok(meta_bytes) = tokio::fs::read(&candidate.meta_path).await
            && let Ok(meta) = serde_json::from_slice::<CacheMeta>(&meta_bytes)
            && (meta.fill_id != candidate.fill_id
                || meta.last_accessed_at != candidate.last_accessed_at)
        {
            // Entry changed since scan — skip eviction but adjust
            // current_size to reflect the actual on-disk size (the
            // entry still exists, possibly at a different size).
            let actual_body = tokio::fs::metadata(&candidate.body_path)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            let actual_meta = tokio::fs::metadata(&candidate.meta_path)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            let actual_size = actual_body + actual_meta;
            // Replace the scanned size with the measured size.
            current_size = current_size
                .saturating_sub(candidate.size)
                .saturating_add(actual_size);
            continue;
        }

        let body_removed = tokio::fs::remove_file(&candidate.body_path).await.is_ok();
        let meta_removed = tokio::fs::remove_file(&candidate.meta_path).await.is_ok();
        if body_removed || meta_removed {
            // Clear poison marker whenever either file is removed — the stale
            // content is (at least partially) gone.
            let poison_path = candidate.body_path.with_extension("poisoned");
            let _ = tokio::fs::remove_file(&poison_path).await;
        }
        if body_removed && meta_removed {
            // Best-effort: use the scan-measured size. If commit_fill replaced
            // the files between scan and delete, this may be stale — the next
            // scan reconciles.
            current_size = current_size.saturating_sub(candidate.size);
            evicted += 1;
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
        } else {
            // Partial or already-gone — subtract scanned size so the loop
            // doesn't over-evict. Stats reconcile on the next scan.
            current_size = current_size.saturating_sub(candidate.size);
            tracing::warn!(
                path = %candidate.body_path.display(),
                body_removed,
                meta_removed,
                "eviction: partial removal, stats reconcile on next scan"
            );
        }
    }

    stats.eviction_count.fetch_add(evicted, Ordering::Relaxed);

    if evicted > 0 {
        tracing::info!(evicted, current_size, max_bytes, "eviction pass complete");
    }

    Ok(())
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
        run_eviction_pass_inner(&cache_dir, 1500, &stats, None).await.unwrap();

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
}
