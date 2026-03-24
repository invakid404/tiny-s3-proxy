use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::cache::metadata::CacheMeta;

use super::CacheStats;

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

/// Walk the objects directory, collect all cache entries as eviction candidates,
/// clean up orphans, and **reconcile stats** to match filesystem reality.
///
/// After this function returns, `stats.total_bytes` and `stats.entry_count`
/// reflect the actual on-disk state (minus any concurrent mutations that raced
/// with the scan — those will be corrected on the next pass).
async fn collect_candidates(
    objects_dir: &std::path::Path,
    stats: &Arc<CacheStats>,
    disk_cache: Option<&super::DiskCache>,
) -> Result<Vec<EvictionCandidate>, Box<dyn std::error::Error + Send + Sync>> {
    let mut candidates = Vec::new();
    let mut scan_total_bytes: u64 = 0;
    let mut scan_entry_count: u64 = 0;

    // Walk <objects_dir>/<d1>/<d2>/<hash>.meta.json
    let mut d1_entries = tokio::fs::read_dir(objects_dir).await?;
    while let Some(d1_entry) = d1_entries.next_entry().await? {
        let d1_path = d1_entry.path();
        if !d1_path.is_dir() {
            continue;
        }

        let mut d2_entries = tokio::fs::read_dir(&d1_path).await?;
        while let Some(d2_entry) = d2_entries.next_entry().await? {
            let d2_path = d2_entry.path();
            if !d2_path.is_dir() {
                continue;
            }

            let mut file_entries = tokio::fs::read_dir(&d2_path).await?;
            while let Some(file_entry) = file_entries.next_entry().await? {
                let file_path = file_entry.path();
                let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };

                if !file_name.ends_with(".meta.json") {
                    // Clean up orphan .body files and stale .poisoned markers.
                    // No stat adjustments needed — orphans are not counted in the
                    // scan totals, so reconciliation handles them automatically.
                    if file_name.ends_with(".body") {
                        let hash = file_name.trim_end_matches(".body");
                        let meta_path = d2_path.join(format!("{}.meta.json", hash));
                        // Acquire the per-key lock to avoid racing with
                        // commit_fill which writes body before meta.
                        let meta_lock = disk_cache.map(|dc| dc.meta_lock_for_hash(hash));
                        let _guard = match meta_lock.as_ref() {
                            Some(lock) => Some(lock.lock().await),
                            None => None,
                        };
                        if !tokio::fs::try_exists(&meta_path).await.unwrap_or(true) {
                            let size = tokio::fs::metadata(&file_path)
                                .await
                                .map(|m| m.len())
                                .unwrap_or(0);
                            let _ = tokio::fs::remove_file(&file_path).await;
                            tracing::debug!(path = %file_path.display(), size, "removed orphan body file");
                        }
                    } else if file_name.ends_with(".poisoned") {
                        let hash = file_name.trim_end_matches(".poisoned");
                        let meta_path = d2_path.join(format!("{}.meta.json", hash));
                        if !tokio::fs::try_exists(&meta_path).await.unwrap_or(true) {
                            let _ = tokio::fs::remove_file(&file_path).await;
                            tracing::debug!(path = %file_path.display(), "removed orphan poison marker");
                        }
                    }
                    continue;
                }

                // Read and parse metadata. Corrupt/unreadable metadata is
                // treated as a broken entry — delete both files so the entry
                // doesn't leak disk space indefinitely outside of eviction's
                // accounting.
                let hash_for_cleanup = file_name.trim_end_matches(".meta.json");
                // Try reading metadata. On failure, acquire the per-key lock
                // and re-read to avoid racing with a concurrent fill/repair.
                let meta: CacheMeta = match tokio::fs::read(&file_path).await
                    .ok()
                    .and_then(|b| serde_json::from_slice::<CacheMeta>(&b).ok())
                {
                    Some(m) => m,
                    None => {
                        let body = d2_path.join(format!("{}.body", hash_for_cleanup));
                        let meta_lock =
                            disk_cache.map(|dc| dc.meta_lock_for_hash(hash_for_cleanup));
                        let _guard = match meta_lock.as_ref() {
                            Some(lock) => Some(lock.lock().await),
                            None => None,
                        };
                        // Re-read under lock — a concurrent fill may have
                        // repaired the entry since the unlocked check.
                        match tokio::fs::read(&file_path).await
                            .ok()
                            .and_then(|b| serde_json::from_slice::<CacheMeta>(&b).ok())
                        {
                            Some(m) => m,
                            None => {
                                let poison = d2_path.join(format!("{hash_for_cleanup}.poisoned"));
                                let _ = tokio::fs::remove_file(&file_path).await;
                                let _ = tokio::fs::remove_file(&body).await;
                                let _ = tokio::fs::remove_file(&poison).await;
                                tracing::warn!(path = %file_path.display(), "removed corrupt cache entry after locked recheck");
                                continue;
                            }
                        }
                    }
                };

                let hash = file_name.trim_end_matches(".meta.json");
                if hash.len() < 5 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let body = d2_path.join(format!("{hash}.body"));
                    let meta_lock = disk_cache.map(|dc| dc.meta_lock_for_hash(hash));
                    let _guard = match meta_lock.as_ref() {
                        Some(lock) => Some(lock.lock().await),
                        None => None,
                    };
                    let poison = d2_path.join(format!("{hash}.poisoned"));
                    let _ = tokio::fs::remove_file(&file_path).await;
                    let _ = tokio::fs::remove_file(&body).await;
                    let _ = tokio::fs::remove_file(&poison).await;
                    tracing::warn!(
                        path = %file_path.display(),
                        "removed cache entry with malformed filename stem"
                    );
                    continue;
                }
                let body_path = d2_path.join(format!("{}.body", hash));

                let body_size = match tokio::fs::metadata(&body_path).await {
                    Ok(m) => m.len(),
                    Err(_) => {
                        // Body appears missing — acquire per-key lock and
                        // re-check to avoid racing with commit_fill().
                        let meta_lock = disk_cache.map(|dc| dc.meta_lock_for_hash(hash));
                        let _guard = match meta_lock.as_ref() {
                            Some(lock) => Some(lock.lock().await),
                            None => None,
                        };
                        if let Ok(body_meta) = tokio::fs::metadata(&body_path).await {
                            // Body appeared after taking the lock (concurrent
                            // commit_fill). Re-read metadata and add as a
                            // candidate so it's both counted and evictable.
                            // Only update accounting after metadata parses.
                            let body_sz = body_meta.len();
                            let meta_sz = tokio::fs::metadata(&file_path)
                                .await
                                .map(|m| m.len())
                                .unwrap_or(0);
                            let entry_size = body_sz + meta_sz;
                            match tokio::fs::read(&file_path).await {
                                Ok(mb) => match serde_json::from_slice::<CacheMeta>(&mb) {
                                    Ok(m) => {
                                        scan_total_bytes += entry_size;
                                        scan_entry_count += 1;
                                        candidates.push(EvictionCandidate {
                                            body_path: body_path.clone(),
                                            meta_path: file_path.clone(),
                                            hash: hash.to_string(),
                                            fill_id: m.fill_id,
                                            last_accessed_at: m.last_accessed_at,
                                            size: entry_size,
                                        });
                                    }
                                    Err(e) => {
                                        tracing::trace!(
                                            hash = hash,
                                            error = %e,
                                            "raced-in entry metadata unparseable, skipping"
                                        );
                                    }
                                },
                                Err(e) => {
                                    tracing::trace!(
                                        hash = hash,
                                        error = %e,
                                        "raced-in entry metadata unreadable, skipping"
                                    );
                                }
                            }
                            continue;
                        }
                        let poison = d2_path.join(format!("{hash}.poisoned"));
                        let _ = tokio::fs::remove_file(&file_path).await;
                        let _ = tokio::fs::remove_file(&poison).await;
                        continue;
                    }
                };

                let meta_size = tokio::fs::metadata(&file_path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                let entry_size = body_size + meta_size;

                // Count this complete entry toward the authoritative scan totals.
                scan_total_bytes += entry_size;
                scan_entry_count += 1;

                candidates.push(EvictionCandidate {
                    body_path,
                    meta_path: file_path,
                    hash: hash.to_string(),
                    fill_id: meta.fill_id,
                    last_accessed_at: meta.last_accessed_at,
                    size: entry_size,
                });
            }
        }
    }

    // Reconcile: overwrite atomics with the authoritative filesystem totals.
    // Any drift from concurrent commit_fill/purge since the last reconciliation
    // is corrected here.
    stats.total_bytes.store(scan_total_bytes, Ordering::Relaxed);
    stats.entry_count.store(scan_entry_count, Ordering::Relaxed);

    Ok(candidates)
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
    let mut candidates = collect_candidates(&objects_dir, stats, disk_cache).await?;

    // Sort by last_accessed_at ascending (oldest first = evicted first)
    candidates.sort_by_key(|c| c.last_accessed_at);

    // Use the scan-measured total (identical to the reconciled stats value).
    let total_size: u64 = candidates.iter().map(|c| c.size).sum();

    if total_size <= max_bytes {
        return Ok(());
    }

    // Evict oldest entries until under limit. Stat adjustments here are
    // best-effort for between-scan responsiveness; the next scan reconciles
    // any drift from concurrent operations.
    let mut current_size = total_size;
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
        if let Ok(meta_bytes) = tokio::fs::read(&candidate.meta_path).await {
            if let Ok(meta) = serde_json::from_slice::<CacheMeta>(&meta_bytes) {
                if meta.fill_id != candidate.fill_id
                    || meta.last_accessed_at != candidate.last_accessed_at
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
            }
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
            // Partial removal — stats will reconcile on the next scan.
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
        let dir = cache_dir.join("objects").join(&d1).join(&d2);
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
            .join(&d1)
            .join(&d2)
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
            .join(&d1)
            .join(&d2)
            .join(format!("{}.body", hash_old));
        assert!(
            !body_path_old.exists(),
            "oldest entry should have been evicted"
        );

        let hash_new = key_new.hash_hex();
        let (d1, d2) = key_new.dir_prefix();
        let body_path_new = cache_dir
            .join("objects")
            .join(&d1)
            .join(&d2)
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
        let dir = cache_dir.join("objects").join(&d1).join(&d2);
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
