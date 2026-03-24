use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::cache::entry::CacheEntry;
use crate::cache::key::CacheKey;
use crate::cache::metadata::CacheMeta;
use crate::cache::policy::CachePolicy;
use crate::cache::{CacheStats, CacheStatsSnapshot, CacheStore, FillGuard};
use crate::error::ProxyError;

/// Monotonic counter for `CacheMeta.fill_id`. Seeded from the highest
/// on-disk `fill_id` at startup so IDs remain unique across restarts.
static FILL_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Check if a path exists, distinguishing NotFound from real I/O errors.
async fn check_exists(path: &std::path::Path, operation: &str) -> Result<bool, ProxyError> {
    match tokio::fs::try_exists(path).await {
        Ok(exists) => Ok(exists),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ProxyError::Cache {
            source: Box::new(e),
            operation: operation.into(),
        }),
    }
}

/// Per-key fill tracking: refcount + generation counter + commit lock.
/// Both counter fields are atomic so they can be read/written through shared
/// `Arc`. The commit lock serializes same-key file operations during
/// `commit_fill` without blocking unrelated keys.
struct FillEntry {
    refcount: std::sync::atomic::AtomicUsize,
    generation: std::sync::atomic::AtomicU64,
    /// Per-key mutex serializing the critical section of `commit_fill`
    /// (old-entry removal, rename, stats update). Only same-key operations
    /// need serialization — different keys write to different file paths.
    commit_lock: tokio::sync::Mutex<()>,
}

/// Disk-backed implementation of `CacheStore`.
///
/// Stores cached objects on the filesystem using a two-level directory hash
/// scheme for even distribution. Writes are atomic (write to tmp, fsync, rename).
pub struct DiskCache {
    cache_dir: PathBuf,
    stats: Arc<CacheStats>,
    /// Per-key fill tracking: refcount + generation counter + commit lock.
    /// purge() takes a read lock to bump the generation atomically without
    /// blocking behind any per-key commit_lock. begin_fill takes a write
    /// lock to create/increment entries atomically, so purge cannot slip
    /// between registration and counter creation.
    active_fills: tokio::sync::RwLock<HashMap<CacheKey, Arc<FillEntry>>>,
    /// Per-key metadata-write lock. Both commit_fill (when renaming the
    /// final .meta.json) and the background access-time updater acquire
    /// this lock so their read-check-rename sequences cannot interleave.
    /// Entries are created on demand and never removed (the overhead is
    /// one Arc<Mutex> per unique key that has ever been written or hit).
    meta_locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    #[cfg(test)]
    commit_rename_fail_after_body_for_test: std::sync::atomic::AtomicBool,
}

impl DiskCache {
    /// Create a new DiskCache, initializing directory structure and loading
    /// stats from any existing cached files on disk.
    pub async fn new(
        cache_dir: PathBuf,
        _max_bytes: u64,
        _policy: CachePolicy,
    ) -> Result<Self, ProxyError> {
        // Create directory structure
        tokio::fs::create_dir_all(cache_dir.join("objects"))
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "create objects dir".into(),
            })?;
        tokio::fs::create_dir_all(cache_dir.join("tmp"))
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "create tmp dir".into(),
            })?;

        // Load stats from existing cached files and discover the highest
        // fill_id already persisted so the counter starts above it.
        let (stats, max_fill_id) = Self::scan_existing_stats(&cache_dir).await?;
        FILL_ID_COUNTER.fetch_max(max_fill_id.saturating_add(1), Ordering::Relaxed);

        Ok(Self {
            cache_dir,
            stats: Arc::new(stats),
            active_fills: tokio::sync::RwLock::new(HashMap::new()),
            meta_locks: std::sync::Mutex::new(HashMap::new()),
            #[cfg(test)]
            commit_rename_fail_after_body_for_test: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[cfg(test)]
    fn arm_commit_rename_fail_after_body_for_test(&self) {
        self.commit_rename_fail_after_body_for_test
            .store(true, Ordering::Relaxed);
    }

    /// Scan the objects directory to compute initial stats at startup and
    /// discover the highest `fill_id` already on disk. The periodic eviction
    /// scan reconciles stats against filesystem reality on every pass.
    async fn scan_existing_stats(
        cache_dir: &std::path::Path,
    ) -> Result<(CacheStats, u64), ProxyError> {
        let objects_dir = cache_dir.join("objects");
        let stats = CacheStats::default();
        let mut max_fill_id: u64 = 0;

        let mut d1_entries = match tokio::fs::read_dir(&objects_dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((stats, max_fill_id));
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to read objects directory during scan");
                return Ok((stats, max_fill_id));
            }
        };

        while let Some(d1_entry) = d1_entries
            .next_entry()
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "scan d1 dirs".into(),
            })?
        {
            let d1_path = d1_entry.path();
            if !d1_path.is_dir() {
                continue;
            }

            let mut d2_entries = match tokio::fs::read_dir(&d1_path).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    tracing::warn!(path = %d1_path.display(), error = %e, "failed to scan cache subtree");
                    continue;
                }
            };

            while let Some(d2_entry) =
                d2_entries
                    .next_entry()
                    .await
                    .map_err(|e| ProxyError::Cache {
                        source: Box::new(e),
                        operation: "scan d2 dirs".into(),
                    })?
            {
                let d2_path = d2_entry.path();
                if !d2_path.is_dir() {
                    continue;
                }

                let mut file_entries = match tokio::fs::read_dir(&d2_path).await {
                    Ok(entries) => entries,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        tracing::warn!(path = %d2_path.display(), error = %e, "failed to scan cache leaf directory");
                        continue;
                    }
                };

                while let Some(file_entry) =
                    file_entries
                        .next_entry()
                        .await
                        .map_err(|e| ProxyError::Cache {
                            source: Box::new(e),
                            operation: "scan files".into(),
                        })?
                {
                    let file_path = file_entry.path();
                    let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };

                    if file_name.ends_with(".body") {
                        let hash = file_name.trim_end_matches(".body");
                        let meta_path = file_path
                            .parent()
                            .unwrap()
                            .join(format!("{hash}.meta.json"));
                        match tokio::fs::try_exists(&meta_path).await {
                            Ok(true) => {
                                match tokio::fs::metadata(&file_path).await {
                                    Ok(m) => {
                                        stats.total_bytes.fetch_add(m.len(), Ordering::Relaxed);
                                        stats.entry_count.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(e) => {
                                        tracing::warn!(
                                            path = %file_path.display(),
                                            error = %e,
                                            "failed to stat body during startup scan"
                                        );
                                    }
                                }
                                match tokio::fs::metadata(&meta_path).await {
                                    Ok(m) => {
                                        stats.total_bytes.fetch_add(m.len(), Ordering::Relaxed);
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(e) => {
                                        tracing::warn!(
                                            path = %meta_path.display(),
                                            error = %e,
                                            "failed to stat metadata during startup scan"
                                        );
                                    }
                                }
                                match tokio::fs::read(&meta_path).await {
                                    Ok(meta_bytes) => {
                                        match serde_json::from_slice::<CacheMeta>(&meta_bytes) {
                                            Ok(meta) => {
                                                max_fill_id = max_fill_id.max(meta.fill_id);
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    path = %meta_path.display(),
                                                    error = %e,
                                                    "failed to parse metadata during startup scan"
                                                );
                                            }
                                        }
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(e) => {
                                        tracing::warn!(
                                            path = %meta_path.display(),
                                            error = %e,
                                            "failed to read metadata during startup scan"
                                        );
                                    }
                                }
                            }
                            Ok(false) => {
                                let _ = tokio::fs::remove_file(&file_path).await;
                            }
                            Err(e) => {
                                tracing::warn!(path = %meta_path.display(), error = %e, "failed to probe metadata during startup scan");
                            }
                        }
                    }
                }
            }
        }

        Ok((stats, max_fill_id))
    }

    /// Build paths for the body and metadata files for a given key.
    /// Computes the hash once and derives both paths.
    fn paths_for_key(&self, key: &CacheKey) -> (PathBuf, PathBuf) {
        let hash = key.hash_hex();
        let dir = self
            .cache_dir
            .join("objects")
            .join(&hash[..2])
            .join(&hash[2..4]);
        let body = dir.join(format!("{hash}.body"));
        let meta = dir.join(format!("{hash}.meta.json"));
        (body, meta)
    }

    /// Path for the durable poison marker for a key. A `.poisoned` file next
    /// to the entry signals that a purge failed and the entry must not be served.
    /// This survives process restarts, unlike an in-memory set.
    fn poison_path_for_key(&self, key: &CacheKey) -> PathBuf {
        let hash = key.hash_hex();
        let dir = self
            .cache_dir
            .join("objects")
            .join(&hash[..2])
            .join(&hash[2..4]);
        dir.join(format!("{hash}.poisoned"))
    }

    /// Get or create the per-key metadata-write lock.
    fn meta_lock_for(&self, key: &CacheKey) -> Arc<tokio::sync::Mutex<()>> {
        self.meta_lock_for_hash(key.hash_hex())
    }

    /// Get or create the per-key metadata-write lock by hash hex string.
    /// Used by both key-based operations and the eviction loop (which only
    /// has the raw hash from the filesystem path).
    pub(crate) fn meta_lock_for_hash(&self, hash: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.meta_locks
            .lock()
            .unwrap()
            .entry(hash.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Remove `meta_locks` entries whose cache files no longer exist on disk.
    /// Called periodically by the eviction loop to prevent unbounded growth.
    pub async fn sweep_stale_meta_locks(&self) {
        // Snapshot current hashes and their lock Arcs.
        let entries: Vec<(String, Arc<tokio::sync::Mutex<()>>)> = {
            let locks = self.meta_locks.lock().unwrap();
            locks
                .iter()
                .map(|(hash, lock)| (hash.clone(), Arc::clone(lock)))
                .collect()
        };
        let mut stale = Vec::new();
        for (hash, lock) in &entries {
            // Skip if another task currently holds or is waiting on this lock.
            // The snapshot clone adds 1 ref, plus the map entry is 1 — anything
            // above 2 means a writer is active.
            if Arc::strong_count(lock) > 2 {
                continue;
            }
            if hash.len() < 5 {
                // Malformed hash — mark for removal from the lock map.
                stale.push(hash.clone());
                continue;
            }
            let (d1, d2) = (&hash[..2], &hash[2..4]);
            let meta_path = self
                .cache_dir
                .join("objects")
                .join(d1)
                .join(d2)
                .join(format!("{hash}.meta.json"));
            if !tokio::fs::try_exists(&meta_path).await.unwrap_or(true) {
                stale.push(hash.clone());
            }
        }
        drop(entries);
        if !stale.is_empty() {
            let mut locks = self.meta_locks.lock().unwrap();
            for key in &stale {
                // Re-check: only remove if no one else grabbed a reference
                // between the scan and this removal.
                if matches!(locks.get(key), Some(lock) if Arc::strong_count(lock) == 1) {
                    locks.remove(key);
                }
            }
        }
    }

    /// Get a reference to the stats.
    pub fn stats_ref(&self) -> &Arc<CacheStats> {
        &self.stats
    }

    async fn restore_publish_backup(
        final_path: &std::path::Path,
        backup_path: &std::path::Path,
        description: &str,
    ) {
        match tokio::fs::rename(backup_path, final_path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::error!(
                    path = %final_path.display(),
                    backup = %backup_path.display(),
                    error = %e,
                    "failed to restore cached {} after publish failure",
                    description
                );
            }
        }
    }

    /// Decrement the active fill refcount for a key. When the count reaches
    /// zero, remove the entry so future purges don't needlessly bump generations.
    async fn finish_fill(&self, key: &CacheKey) {
        let mut fills = self.active_fills.write().await;
        if let Some(entry) = fills.get(key) {
            let prev = entry.refcount.fetch_sub(1, Ordering::Relaxed);
            if prev <= 1 {
                fills.remove(key);
            }
        }
    }

    async fn rewrite_last_accessed(
        stats: Arc<CacheStats>,
        meta_lock: Arc<tokio::sync::Mutex<()>>,
        meta_path: PathBuf,
        tmp_dir: PathBuf,
        hash: String,
        expected_fill_id: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        static ACCESS_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);

        let _guard = meta_lock.lock().await;

        let (mut current_meta, current_len) = if let Ok(current_bytes) = tokio::fs::read(&meta_path).await {
            if let Ok(current_meta) = serde_json::from_slice::<CacheMeta>(&current_bytes) {
                if current_meta.fill_id != expected_fill_id {
                    return;
                }
                (current_meta, current_bytes.len() as u64)
            } else {
                return;
            }
        } else {
            return;
        };
        if current_meta.last_accessed_at >= now {
            return;
        }
        current_meta.last_accessed_at = now;
        if let Ok(bytes) = serde_json::to_vec(&current_meta) {
            let counter = ACCESS_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let tmp_path = tmp_dir.join(format!(
                "{}-{}-{}.meta.tmp",
                std::process::id(),
                hash,
                counter,
            ));
            if tokio::fs::write(&tmp_path, &bytes).await.is_ok() {
                if tokio::fs::rename(&tmp_path, &meta_path).await.is_ok() {
                    let new_len = bytes.len() as u64;
                    match new_len.cmp(&current_len) {
                        std::cmp::Ordering::Greater => {
                            stats.total_bytes.fetch_add(new_len - current_len, Ordering::Relaxed);
                        }
                        std::cmp::Ordering::Less => {
                            let delta = current_len - new_len;
                            let _ = stats.total_bytes.fetch_update(
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                                |current| Some(current.saturating_sub(delta)),
                            );
                        }
                        std::cmp::Ordering::Equal => {}
                    }
                } else {
                    // Rename failed — clean up the temp file.
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                }
            } else {
                // Write failed — clean up the temp file.
                let _ = tokio::fs::remove_file(&tmp_path).await;
            }
        }
    }

    /// Inner implementation of commit_fill. Separated so the public method
    /// can guarantee `finish_fill` runs on every exit path.
    async fn commit_fill_inner(
        &self,
        guard: &FillGuard,
        temp_body_path: PathBuf,
        meta: CacheMeta,
    ) -> Result<(), ProxyError> {
        // Early check: read generation counter via RwLock (no fill_state needed).
        // Early generation check via read lock (no fill_state needed).
        {
            let fills = self.active_fills.read().await;
            let current_gen = fills
                .get(&guard.key)
                .map(|e| e.generation.load(Ordering::Acquire))
                .unwrap_or(0);
            if current_gen != guard.generation {
                tracing::info!(
                    key = %guard.key.object_key,
                    "cache fill rejected (early check): key invalidated during fill"
                );
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                return Ok(());
            }
        }

        static COMMIT_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = COMMIT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();

        // The body file has already been written and fsynced by the caller.
        let body_size = tokio::fs::metadata(&temp_body_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        let mut meta = meta;
        let temp_meta = guard.temp_dir.join(format!("{pid}-{id}.meta.json"));

        // Create parent directories for final location
        let (final_body, final_meta) = self.paths_for_key(&guard.key);
        if let Some(parent) = final_body.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "create object dir".into(),
                });
            }
        }

        // Pre-publish generation check via read lock (doesn't block purge).
        {
            let fills = self.active_fills.read().await;
            let cur_gen = fills
                .get(&guard.key)
                .map(|e| e.generation.load(Ordering::Acquire))
                .unwrap_or(0);
            if cur_gen != guard.generation {
                tracing::info!(key = %guard.key.object_key, "cache fill rejected (pre-publish)");
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Ok(());
            }
        }

        // Acquire per-key commit lock. The FillEntry Arc is cloned so the
        // lock outlives the brief active_fills read lock. Different keys
        // proceed concurrently; only same-key operations serialize.
        let fill_entry = {
            let fills = self.active_fills.read().await;
            fills.get(&guard.key).cloned()
        };
        let fill_entry = match fill_entry {
            Some(e) => e,
            None => {
                // Shouldn't happen (refcount > 0 keeps the entry alive),
                // but treat as invalidated defensively.
                tracing::warn!(key = %guard.key.object_key, "cache fill rejected: fill entry missing");
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Ok(());
            }
        };
        {
            let _commit_lock = fill_entry.commit_lock.lock().await;
            // Hold the per-key metadata lock for the full replace window so a
            // background access-time updater cannot rewrite stale metadata
            // after the new body is published but before the new metadata is
            // installed.
            let meta_lock = self.meta_lock_for(&guard.key);
            let _meta_guard = meta_lock.lock().await;

            // Re-check generation BEFORE touching live files — purge() bumps
            // it under the same commit_lock, so a stale fill must not delete
            // the currently published snapshot.
            {
                let fills = self.active_fills.read().await;
                let cur_gen = fills
                    .get(&guard.key)
                    .map(|e| e.generation.load(Ordering::Acquire))
                    .unwrap_or(0);
                if cur_gen != guard.generation {
                    tracing::info!(key = %guard.key.object_key, "cache fill rejected (late check)");
                    let _ = tokio::fs::remove_file(&temp_body_path).await;
                    return Ok(());
                }
            }

            if let Ok(current_bytes) = tokio::fs::read(&final_meta).await {
                if let Ok(current_meta) = serde_json::from_slice::<CacheMeta>(&current_bytes) {
                    meta.preserve_same_etag_head_state_from(&current_meta);
                }
            }

            meta.fill_id = FILL_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
            meta.metadata_version = 0;

            // Write metadata to temp file after reconciling against the latest
            // published same-ETag entry under the publish lock.
            let meta_bytes = match serde_json::to_vec(&meta) {
                Ok(b) => b,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&temp_body_path).await;
                    return Err(ProxyError::Cache {
                        source: Box::new(e),
                        operation: "serialize metadata".into(),
                    });
                }
            };
            if let Err(e) = tokio::fs::write(&temp_meta, &meta_bytes).await {
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "write temp metadata".into(),
                });
            }

            // fsync metadata after the commit-time reconciliation so the
            // published file matches the merged snapshot exactly.
            let meta_file = match tokio::fs::File::open(&temp_meta).await {
                Ok(f) => f,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&temp_body_path).await;
                    let _ = tokio::fs::remove_file(&temp_meta).await;
                    return Err(ProxyError::Cache {
                        source: Box::new(e),
                        operation: "open temp meta for fsync".into(),
                    });
                }
            };
            if let Err(e) = meta_file.sync_all().await {
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "fsync temp metadata".into(),
                });
            }

            // Snapshot any previously published files so a transient publish
            // failure cannot destroy a healthy entry.
            let old_body = tokio::fs::metadata(&final_body).await.ok();
            let old_meta = tokio::fs::metadata(&final_meta).await.ok();
            let old_body_exists = old_body.is_some();
            let old_meta_exists = old_meta.is_some();
            let old_body_size = old_body.as_ref().map(|m| m.len()).unwrap_or(0);
            let old_meta_size = old_meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let backup_body = guard.temp_dir.join(format!("{pid}-{id}.prev.body"));
            let backup_meta = guard.temp_dir.join(format!("{pid}-{id}.prev.meta.json"));

            if old_body_exists {
                if let Err(e) = tokio::fs::rename(&final_body, &backup_body).await {
                    let _ = tokio::fs::remove_file(&temp_body_path).await;
                    let _ = tokio::fs::remove_file(&temp_meta).await;
                    return Err(ProxyError::Cache {
                        source: Box::new(e),
                        operation: "backup existing body".into(),
                    });
                }
            }
            if old_meta_exists {
                if let Err(e) = tokio::fs::rename(&final_meta, &backup_meta).await {
                    if old_body_exists {
                        Self::restore_publish_backup(&final_body, &backup_body, "body").await;
                    }
                    let _ = tokio::fs::remove_file(&temp_body_path).await;
                    let _ = tokio::fs::remove_file(&temp_meta).await;
                    return Err(ProxyError::Cache {
                        source: Box::new(e),
                        operation: "backup existing metadata".into(),
                    });
                }
            }

            if let Err(e) = tokio::fs::rename(&temp_body_path, &final_body).await {
                if old_body_exists {
                    Self::restore_publish_backup(&final_body, &backup_body, "body").await;
                }
                if old_meta_exists {
                    Self::restore_publish_backup(&final_meta, &backup_meta, "metadata").await;
                }
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "rename body".into(),
                });
            }

            #[cfg(test)]
            if self
                .commit_rename_fail_after_body_for_test
                .swap(false, Ordering::Relaxed)
            {
                if old_body_exists {
                    Self::restore_publish_backup(&final_body, &backup_body, "body").await;
                } else {
                    let _ = tokio::fs::remove_file(&final_body).await;
                }
                if old_meta_exists {
                    Self::restore_publish_backup(&final_meta, &backup_meta, "metadata").await;
                }
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Err(ProxyError::Cache {
                    source: "injected rename metadata failure".into(),
                    operation: "rename metadata".into(),
                });
            }

            if let Err(e) = tokio::fs::rename(&temp_meta, &final_meta).await {
                if old_body_exists {
                    Self::restore_publish_backup(&final_body, &backup_body, "body").await;
                } else {
                    let _ = tokio::fs::remove_file(&final_body).await;
                }
                if old_meta_exists {
                    Self::restore_publish_backup(&final_meta, &backup_meta, "metadata").await;
                }
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "rename metadata".into(),
                });
            }

            if old_body_exists {
                let _ = tokio::fs::remove_file(&backup_body).await;
            }
            if old_meta_exists {
                let _ = tokio::fs::remove_file(&backup_meta).await;
            }

            // Adjust stats after successful publish.
            if old_body_size > 0 || old_meta_size > 0 {
                let _ = self.stats.entry_count.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |c| Some(c.saturating_sub(1)),
                );
                let _ = self.stats.total_bytes.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |c| Some(c.saturating_sub(old_body_size + old_meta_size)),
                );
            }

            // Best-effort: add the new entry's size. The periodic eviction scan
            // reconciles any drift from concurrent operations.
            let new_size = body_size + meta_bytes.len() as u64;
            self.stats.entry_count.fetch_add(1, Ordering::Relaxed);
            self.stats
                .total_bytes
                .fetch_add(new_size, Ordering::Relaxed);
            self.stats.fill_count.fetch_add(1, Ordering::Relaxed);

            // Clear any stale poison marker while the publish locks are still
            // held so a newer poison() call cannot race and have its marker
            // erased by this fill.
            let _ = tokio::fs::remove_file(&self.poison_path_for_key(&guard.key)).await;
        }

        Ok(())
    }
}

impl CacheStore for DiskCache {
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
        self.lookup_inner(key, true, true).await
    }

    async fn peek(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
        self.lookup_inner(key, false, false).await
    }

    async fn peek_body(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
        self.lookup_inner(key, false, true).await
    }

    async fn note_hit(&self, key: &CacheKey, meta: &CacheMeta) -> Result<(), ProxyError> {
        self.note_hit_inner(key, meta);
        Ok(())
    }

    async fn note_miss(&self) -> Result<(), ProxyError> {
        self.note_miss_inner();
        Ok(())
    }

    async fn begin_fill(&self, key: &CacheKey) -> Result<FillGuard, ProxyError> {
        // Register active fill AND capture generation in a single write lock.
        // This is atomic w.r.t. purge() which takes a read lock to bump the
        // generation — purge cannot slip between registration and capture.
        let generation = {
            let mut fills = self.active_fills.write().await;
            let entry = fills.entry(key.clone()).or_insert_with(|| {
                Arc::new(FillEntry {
                    refcount: std::sync::atomic::AtomicUsize::new(0),
                    generation: std::sync::atomic::AtomicU64::new(0),
                    commit_lock: tokio::sync::Mutex::new(()),
                })
            });
            entry.refcount.fetch_add(1, Ordering::Relaxed);
            entry.generation.load(Ordering::Acquire)
        };
        let temp_dir = self.cache_dir.join("tmp");
        Ok(FillGuard {
            key: key.clone(),
            temp_dir,
            generation,
        })
    }

    async fn abort_fill(&self, guard: FillGuard) {
        self.finish_fill(&guard.key).await;
    }

    async fn commit_fill(
        &self,
        guard: FillGuard,
        temp_body_path: PathBuf,
        meta: CacheMeta,
    ) -> Result<(), ProxyError> {
        // Delegate to an inner function so we can guarantee finish_fill runs
        // on every exit path (success, rejection, or error).
        // Delegate to the inherent method; guarantee finish_fill runs on
        // every exit path (success, rejection, or error).
        let result = self.commit_fill_inner(&guard, temp_body_path, meta).await;
        self.finish_fill(&guard.key).await;
        result
    }

    async fn purge(&self, key: &CacheKey) -> Result<bool, ProxyError> {
        // Look up the per-key fill entry. If an active fill exists, acquire
        // its commit_lock so we serialize against commit_fill's publish step,
        // then bump the generation inside the critical section. This prevents
        // the race where purge bumps the generation after commit_fill's final
        // check but before the rename.
        let fill_entry = {
            let fills = self.active_fills.read().await;
            fills.get(key).cloned()
        };
        let _commit_lock = match fill_entry {
            Some(ref entry) => {
                let guard = entry.commit_lock.lock().await;
                entry.generation.fetch_add(1, Ordering::Release);
                Some(guard)
            }
            // No active fill — nothing to synchronize with.
            None => None,
        };

        let (body_path, meta_path) = self.paths_for_key(key);
        let meta_lock = self.meta_lock_for(key);
        let _meta_guard = meta_lock.lock().await;

        // Use async filesystem checks instead of blocking .exists()
        let body_exists = check_exists(&body_path, "check body for purge").await?;
        let meta_exists = check_exists(&meta_path, "check meta for purge").await?;

        if !body_exists && !meta_exists {
            let _ = tokio::fs::remove_file(&self.poison_path_for_key(key)).await;
            return Ok(false);
        }

        let body_size = tokio::fs::metadata(&body_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let meta_size = tokio::fs::metadata(&meta_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        let mut removed = false;
        if body_exists {
            tokio::fs::remove_file(&body_path)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "remove body".into(),
                })?;
            removed = true;
        }
        if meta_exists {
            tokio::fs::remove_file(&meta_path)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "remove metadata".into(),
                })?;
            removed = true;
        }

        if removed {
            let _ = self.stats.entry_count.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(1)),
            );
            let total_removed = body_size + meta_size;
            let _ = self.stats.total_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(total_removed)),
            );
        }

        let _ = tokio::fs::remove_file(&self.poison_path_for_key(key)).await;

        Ok(removed)
    }

    async fn purge_if_unchanged(
        &self,
        key: &CacheKey,
        expected_fill_id: u64,
    ) -> Result<bool, ProxyError> {
        let fill_entry = {
            let fills = self.active_fills.read().await;
            fills.get(key).cloned()
        };
        let _commit_lock = match fill_entry {
            Some(ref entry) => {
                let guard = entry.commit_lock.lock().await;
                Some(guard)
            }
            None => None,
        };

        let (body_path, meta_path) = self.paths_for_key(key);
        let meta_lock = self.meta_lock_for(key);
        let _meta_guard = meta_lock.lock().await;

        let current_bytes = match tokio::fs::read(&meta_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "read metadata for conditional purge".into(),
                });
            }
        };
        let current_meta =
            serde_json::from_slice::<CacheMeta>(&current_bytes).map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "parse metadata for conditional purge".into(),
            })?;
        if current_meta.fill_id != expected_fill_id {
            return Ok(false);
        }
        if let Some(ref entry) = fill_entry {
            entry.generation.fetch_add(1, Ordering::Release);
        }

        let body_exists = check_exists(&body_path, "check body for conditional purge").await?;
        let meta_exists = check_exists(&meta_path, "check meta for conditional purge").await?;

        if !body_exists && !meta_exists {
            let _ = tokio::fs::remove_file(&self.poison_path_for_key(key)).await;
            return Ok(false);
        }

        let body_size = tokio::fs::metadata(&body_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let meta_size = tokio::fs::metadata(&meta_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        let mut removed = false;
        if body_exists {
            tokio::fs::remove_file(&body_path)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "remove body".into(),
                })?;
            removed = true;
        }
        if meta_exists {
            tokio::fs::remove_file(&meta_path)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "remove metadata".into(),
                })?;
            removed = true;
        }

        if removed {
            let _ = self.stats.entry_count.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(1)),
            );
            let total_removed = body_size + meta_size;
            let _ = self.stats.total_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(total_removed)),
            );
        }

        let _ = tokio::fs::remove_file(&self.poison_path_for_key(key)).await;

        Ok(removed)
    }

    async fn poison(&self, key: &CacheKey) -> Result<(), ProxyError> {
        // Acquire the same locks that commit_fill() holds so an in-flight fill
        // cannot publish after the poison marker is written. Bumping the
        // generation ensures the fill's late generation check will reject it.
        let fill_entry = {
            let fills = self.active_fills.read().await;
            fills.get(key).cloned()
        };
        let _commit_lock = match fill_entry {
            Some(ref entry) => {
                let guard = entry.commit_lock.lock().await;
                Some(guard)
            }
            None => None,
        };
        if let Some(ref entry) = fill_entry {
            entry.generation.fetch_add(1, Ordering::Release);
        }

        let meta_lock = self.meta_lock_for(key);
        let _guard = meta_lock.lock().await;

        let path = self.poison_path_for_key(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "create poison marker dir".into(),
                })?;
        }
        tokio::fs::write(&path, b"")
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "write poison marker".into(),
            })
    }

    async fn poison_if_unchanged(
        &self,
        key: &CacheKey,
        expected_fill_id: u64,
    ) -> Result<bool, ProxyError> {
        let fill_entry = {
            let fills = self.active_fills.read().await;
            fills.get(key).cloned()
        };
        let _commit_lock = match fill_entry {
            Some(ref entry) => {
                let guard = entry.commit_lock.lock().await;
                Some(guard)
            }
            None => None,
        };

        let (_, meta_path) = self.paths_for_key(key);
        let meta_lock = self.meta_lock_for(key);
        let _guard = meta_lock.lock().await;

        let current_bytes = match tokio::fs::read(&meta_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "read metadata for poison".into(),
                });
            }
        };
        let current_meta =
            serde_json::from_slice::<CacheMeta>(&current_bytes).map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "parse metadata for poison".into(),
            })?;
        if current_meta.fill_id != expected_fill_id {
            return Ok(false);
        }
        if let Some(ref entry) = fill_entry {
            entry.generation.fetch_add(1, Ordering::Release);
        }

        let poison_path = self.poison_path_for_key(key);
        if let Some(parent) = poison_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "create poison marker dir".into(),
                })?;
        }
        tokio::fs::write(&poison_path, b"")
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "write poison marker".into(),
            })?;

        Ok(true)
    }

    async fn update_metadata_if_unchanged(
        &self,
        key: &CacheKey,
        expected_fill_id: u64,
        meta: CacheMeta,
    ) -> Result<bool, ProxyError> {
        static UPDATE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let (body_path, meta_path) = self.paths_for_key(key);
        let meta_lock = self.meta_lock_for(key);
        let _guard = meta_lock.lock().await;

        if !check_exists(&body_path, "check body for metadata update").await?
            || !check_exists(&meta_path, "check meta for metadata update").await?
        {
            return Ok(false);
        }

        let current_bytes = match tokio::fs::read(&meta_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "read metadata for update".into(),
                });
            }
        };
        let current_meta =
            serde_json::from_slice::<CacheMeta>(&current_bytes).map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "parse metadata for update".into(),
            })?;

        if current_meta.fill_id != expected_fill_id
            || current_meta.metadata_version != meta.metadata_version
        {
            return Ok(false);
        }

        let mut updated_meta = meta;
        updated_meta.cache_written_at = current_meta.cache_written_at;
        updated_meta.fill_id = current_meta.fill_id;
        updated_meta.last_accessed_at = current_meta.last_accessed_at;
        updated_meta.hit_count = current_meta.hit_count;
        updated_meta.source_status = current_meta.source_status;
        updated_meta.metadata_version = current_meta.metadata_version.saturating_add(1);

        let tmp_dir = self.cache_dir.join("tmp");
        let counter = UPDATE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = tmp_dir.join(format!(
            "{}-{}-{}.meta.tmp",
            std::process::id(),
            key.hash_hex(),
            counter,
        ));
        let meta_bytes = serde_json::to_vec(&updated_meta).map_err(|e| ProxyError::Cache {
            source: Box::new(e),
            operation: "serialize metadata update".into(),
        })?;

        // Intentionally skip fsync for metadata-only updates (HEAD enrichment,
        // access-time rewrites). The performance cost of fsync per refresh is
        // not justified — the data can be re-learned from the backend on the
        // next miss after an unclean shutdown. commit_fill_inner uses fsync
        // for body data which is more expensive to re-fetch.
        if let Err(e) = tokio::fs::write(&tmp_path, &meta_bytes).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(ProxyError::Cache {
                source: Box::new(e),
                operation: "write metadata update".into(),
            });
        }
        if let Err(e) = tokio::fs::rename(&tmp_path, &meta_path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(ProxyError::Cache {
                source: Box::new(e),
                operation: "rename metadata update".into(),
            });
        }

        let old_len = current_bytes.len() as u64;
        let new_len = meta_bytes.len() as u64;
        match new_len.cmp(&old_len) {
            std::cmp::Ordering::Greater => {
                self.stats
                    .total_bytes
                    .fetch_add(new_len - old_len, Ordering::Relaxed);
            }
            std::cmp::Ordering::Less => {
                let delta = old_len - new_len;
                let _ = self.stats.total_bytes.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |current| Some(current.saturating_sub(delta)),
                );
            }
            std::cmp::Ordering::Equal => {}
        }

        Ok(true)
    }

    async fn stats(&self) -> CacheStatsSnapshot {
        self.stats.snapshot()
    }
}

impl DiskCache {
    fn note_miss_inner(&self) {
        self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
    }

    fn note_hit_inner(&self, key: &CacheKey, meta: &CacheMeta) {
        self.stats.hit_count.fetch_add(1, Ordering::Relaxed);

        let now = chrono::Utc::now();
        if now.signed_duration_since(meta.last_accessed_at) > chrono::Duration::hours(1) {
            let expected_fill_id = meta.fill_id;
            let meta_path_owned = self.paths_for_key(key).1;
            let tmp_dir = self.cache_dir.join("tmp");
            let hash = key.hash_hex().to_string();
            let meta_lock = self.meta_lock_for(key);
            let stats = Arc::clone(&self.stats);
            tokio::spawn(async move {
                Self::rewrite_last_accessed(
                    stats,
                    meta_lock,
                    meta_path_owned,
                    tmp_dir,
                    hash,
                    expected_fill_id,
                    now,
                )
                .await;
            });
        }
    }

    async fn lookup_inner(
        &self,
        key: &CacheKey,
        track_access: bool,
        pin_body: bool,
    ) -> Result<Option<CacheEntry>, ProxyError> {
        let poison_path = self.poison_path_for_key(key);
        if check_exists(&poison_path, "check poison marker").await? {
            if track_access {
                self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(None);
        }

        let (body_path, meta_path) = self.paths_for_key(key);
        let meta_lock = self.meta_lock_for(key);
        let meta_guard = meta_lock.lock().await;

        // Re-check the poison marker after acquiring meta_lock.
        if check_exists(&poison_path, "recheck poison marker").await? {
            drop(meta_guard);
            if track_access {
                self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(None);
        }

        let meta_bytes = match tokio::fs::read(&meta_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Metadata gone — clean up any orphaned body file and stats.
                let body_meta = tokio::fs::metadata(&body_path).await.ok();
                let body_size = body_meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let body_existed = body_meta.is_some();
                let body_removed = match tokio::fs::remove_file(&body_path).await {
                    Ok(()) => true,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                    Err(_) => false,
                };
                drop(meta_guard);
                if body_removed && body_existed {
                    let _ = self.stats.entry_count.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |c| Some(c.saturating_sub(1)),
                    );
                    if body_size > 0 {
                        let _ = self.stats.total_bytes.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |c| Some(c.saturating_sub(body_size)),
                        );
                    }
                }
                if track_access {
                    self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(None);
            }
            Err(e) => {
                drop(meta_guard);
                if track_access {
                    self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                }
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "read metadata".into(),
                });
            }
        };

        let meta: CacheMeta = match serde_json::from_slice(&meta_bytes) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(key = %key.object_key, error = %e, "corrupt cache metadata, cleaning up");
                let body_size = tokio::fs::metadata(&body_path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                let meta_size = meta_bytes.len() as u64;
                let _ = tokio::fs::remove_file(&meta_path).await;
                let _ = tokio::fs::remove_file(&body_path).await;
                drop(meta_guard);
                let _ = self.stats.entry_count.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |c| Some(c.saturating_sub(1)),
                );
                let _ = self.stats.total_bytes.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |c| Some(c.saturating_sub(meta_size + body_size)),
                );
                if track_access {
                    self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(None);
            }
        };

        if meta.bucket != key.bucket || meta.key != key.object_key {
            tracing::warn!(
                expected_bucket = %key.bucket,
                expected_key = %key.object_key,
                actual_bucket = %meta.bucket,
                actual_key = %meta.key,
                "cache hash collision detected — treating as miss"
            );
            drop(meta_guard);
            if track_access {
                self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(None);
        }

        let body_file = if pin_body {
            // Open the body file when the caller needs a stable inode snapshot
            // for streaming. Metadata-only probes can skip the file descriptor.
            match tokio::fs::File::open(&body_path).await {
                Ok(file) => Some(file),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let _ = tokio::fs::remove_file(&meta_path).await;
                    drop(meta_guard);
                    if track_access {
                        self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                    }
                    let meta_size = meta_bytes.len() as u64;
                    let body_size = meta.content_length.max(0) as u64;
                    let _ = self.stats.entry_count.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |c| Some(c.saturating_sub(1)),
                    );
                    let _ = self.stats.total_bytes.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |c| Some(c.saturating_sub(meta_size + body_size)),
                    );
                    return Ok(None);
                }
                Err(e) => {
                    drop(meta_guard);
                    if track_access {
                        self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(ProxyError::Cache {
                        source: Box::new(e),
                        operation: "open body".into(),
                    });
                }
            }
        } else {
            // Peek: verify the body exists without opening it so the
            // caller gets metadata without file-descriptor overhead.
            match tokio::fs::try_exists(&body_path).await {
                Ok(true) => None,
                Ok(false) => {
                    let _ = tokio::fs::remove_file(&meta_path).await;
                    drop(meta_guard);
                    let meta_size = meta_bytes.len() as u64;
                    let body_size = meta.content_length.max(0) as u64;
                    let _ = self.stats.entry_count.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |c| Some(c.saturating_sub(1)),
                    );
                    let _ = self.stats.total_bytes.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |c| Some(c.saturating_sub(meta_size + body_size)),
                    );
                    return Ok(None);
                }
                Err(e) => {
                    drop(meta_guard);
                    return Err(ProxyError::Cache {
                        source: Box::new(e),
                        operation: "check body exists".into(),
                    });
                }
            }
        };

        drop(meta_guard);

        if track_access {
            self.note_hit_inner(key, &meta);
        }

        Ok(Some(CacheEntry {
            meta,
            body_path,
            body_file,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    fn test_key() -> CacheKey {
        CacheKey::new("test-bucket", "script_bundle/app.js")
    }

    fn test_meta(body_len: usize) -> CacheMeta {
        let now = Utc::now();
        CacheMeta {
            bucket: "test-bucket".into(),
            key: "script_bundle/app.js".into(),
            etag: Some("\"abc123\"".into()),
            last_modified: Some(now),
            content_type: Some("application/javascript".into()),
            content_length: body_len as i64,
            cache_written_at: now,
            fill_id: 0, // stamped by commit_fill
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
        }
    }

    /// Helper: write body data to a temp file in the cache's tmp dir and return its path.
    async fn write_temp_body(cache_dir: &std::path::Path, data: &[u8]) -> PathBuf {
        use std::sync::atomic::AtomicU64;
        static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

        let tmp_dir = cache_dir.join("tmp");
        let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let temp_path = tmp_dir.join(format!("{pid}-{id}.body"));
        let mut f = tokio::fs::File::create(&temp_path).await.unwrap();
        f.write_all(data).await.unwrap();
        f.sync_all().await.unwrap();
        temp_path
    }

    #[tokio::test]
    async fn test_lookup_empty_cache_returns_none() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let result = cache.lookup(&test_key()).await.unwrap();
        assert!(result.is_none());

        let stats = cache.stats().await;
        assert_eq!(stats.miss_count, 1);
        assert_eq!(stats.hit_count, 0);
    }

    #[tokio::test]
    async fn test_commit_fill_then_lookup() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"console.log('hello');".to_vec();
        let meta = test_meta(body.len());

        // Write body to temp file, then commit
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache
            .commit_fill(guard, temp_path, meta.clone())
            .await
            .unwrap();

        // Lookup
        let entry = cache.lookup(&key).await.unwrap().expect("should hit");
        // Verify body by reading from body_path
        let read_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(read_body, body);
        assert_eq!(entry.meta.bucket, "test-bucket");
        assert_eq!(entry.meta.key, "script_bundle/app.js");
        assert_eq!(entry.meta.etag, Some("\"abc123\"".into()));
        assert_eq!(
            entry.meta.content_type,
            Some("application/javascript".into())
        );
        assert_eq!(entry.meta.content_length, body.len() as i64);
        assert_eq!(entry.meta.source_status, 200);
        // hit_count is no longer incremented on-disk per hit, stays at 0 in meta
        assert_eq!(entry.meta.hit_count, 0);
    }

    #[tokio::test]
    async fn test_commit_fill_failure_restores_previous_snapshot() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let old_body = b"old body".to_vec();
        let mut old_meta = test_meta(old_body.len());
        old_meta.etag = Some("\"old-etag\"".into());
        let old_temp_path = write_temp_body(tmp.path(), &old_body).await;
        let old_guard = cache.begin_fill(&key).await.unwrap();
        cache
            .commit_fill(old_guard, old_temp_path, old_meta)
            .await
            .unwrap();

        cache.arm_commit_rename_fail_after_body_for_test();

        let new_body = b"new body".to_vec();
        let mut new_meta = test_meta(new_body.len());
        new_meta.etag = Some("\"new-etag\"".into());
        let new_temp_path = write_temp_body(tmp.path(), &new_body).await;
        let new_guard = cache.begin_fill(&key).await.unwrap();
        let err = cache.commit_fill(new_guard, new_temp_path, new_meta).await.unwrap_err();
        assert!(err.to_string().contains("rename metadata"));

        let entry = cache.lookup(&key).await.unwrap().unwrap();
        assert_eq!(entry.meta.etag.as_deref(), Some("\"old-etag\""));
        let restored_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(restored_body, old_body);
        let stats = cache.stats().await;
        assert_eq!(stats.entry_count, 1);
    }

    #[tokio::test]
    async fn test_purge_removes_entry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"data".to_vec();
        let meta = test_meta(body.len());

        // Fill
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        // Verify exists
        assert!(cache.lookup(&key).await.unwrap().is_some());

        // Purge
        let removed = cache.purge(&key).await.unwrap();
        assert!(removed);

        // Verify gone
        assert!(cache.lookup(&key).await.unwrap().is_none());

        // Purge again should return false
        let removed_again = cache.purge(&key).await.unwrap();
        assert!(!removed_again);
    }

    #[tokio::test]
    async fn test_commit_fill_creates_correct_filesystem_structure() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"test data".to_vec();
        let meta = test_meta(body.len());

        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        // Verify filesystem layout
        let hash = key.hash_hex();
        let (d1, d2) = key.dir_prefix();

        let body_path = tmp
            .path()
            .join("objects")
            .join(&d1)
            .join(&d2)
            .join(format!("{}.body", hash));
        let meta_path = tmp
            .path()
            .join("objects")
            .join(&d1)
            .join(&d2)
            .join(format!("{}.meta.json", hash));

        assert!(
            body_path.exists(),
            "body file should exist at expected path"
        );
        assert!(
            meta_path.exists(),
            "meta file should exist at expected path"
        );

        // Verify d1 and d2 are the correct hex prefixes
        assert_eq!(d1.len(), 2);
        assert_eq!(d2.len(), 2);
        assert!(d1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(d2.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_stats_updated_correctly() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        // Initial stats
        let s = cache.stats().await;
        assert_eq!(s.entry_count, 0);
        assert_eq!(s.total_bytes, 0);
        assert_eq!(s.hit_count, 0);
        assert_eq!(s.miss_count, 0);
        assert_eq!(s.fill_count, 0);

        // Miss
        let key = test_key();
        let _ = cache.lookup(&key).await.unwrap();
        let s = cache.stats().await;
        assert_eq!(s.miss_count, 1);

        // Fill
        let body = b"test body content".to_vec();
        let meta = test_meta(body.len());
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        let s = cache.stats().await;
        assert_eq!(s.entry_count, 1);
        assert_eq!(s.fill_count, 1);
        assert!(s.total_bytes > 0);

        // Hit
        let _ = cache.lookup(&key).await.unwrap();
        let s = cache.stats().await;
        assert_eq!(s.hit_count, 1);

        // Purge
        cache.purge(&key).await.unwrap();
        let s = cache.stats().await;
        assert_eq!(s.entry_count, 0);
        assert_eq!(s.total_bytes, 0);
    }

    #[tokio::test]
    async fn test_lookup_metadata_miss_cleans_up_zero_byte_orphan_entry_count() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = Vec::new();
        let meta = test_meta(body.len());
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();
        assert_eq!(cache.stats().await.entry_count, 1);

        let (_, meta_path) = cache.paths_for_key(&key);
        tokio::fs::remove_file(&meta_path).await.unwrap();

        assert!(cache.lookup(&key).await.unwrap().is_none());
        assert_eq!(cache.stats().await.entry_count, 0);
    }

    #[tokio::test]
    async fn test_concurrent_fills_different_keys() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = Arc::new(
            DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
                .await
                .unwrap(),
        );

        let key1 = CacheKey::new("bucket", "script_bundle/a.js");
        let key2 = CacheKey::new("bucket", "script_bundle/b.js");

        let cache1 = cache.clone();
        let cache2 = cache.clone();
        let tmp_path = tmp.path().to_path_buf();

        let h1 = tokio::spawn({
            let tmp_path = tmp_path.clone();
            async move {
                let body = b"content a".to_vec();
                let meta = CacheMeta {
                    bucket: "bucket".into(),
                    key: "script_bundle/a.js".into(),
                    etag: None,
                    last_modified: None,
                    content_type: None,
                    content_length: body.len() as i64,
                    cache_written_at: Utc::now(),
                    fill_id: 0,
                    metadata_version: 0,
                    last_accessed_at: Utc::now(),
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
                let temp_path = write_temp_body(&tmp_path, &body).await;
                let guard = cache1.begin_fill(&key1).await.unwrap();
                cache1.commit_fill(guard, temp_path, meta).await.unwrap();
            }
        });

        let h2 = tokio::spawn(async move {
            let body = b"content b".to_vec();
            let meta = CacheMeta {
                bucket: "bucket".into(),
                key: "script_bundle/b.js".into(),
                etag: None,
                last_modified: None,
                content_type: None,
                content_length: body.len() as i64,
                cache_written_at: Utc::now(),
                fill_id: 0,
                metadata_version: 0,
                last_accessed_at: Utc::now(),
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
            let temp_path = write_temp_body(&tmp_path, &body).await;
            let guard = cache2.begin_fill(&key2).await.unwrap();
            cache2.commit_fill(guard, temp_path, meta).await.unwrap();
        });

        h1.await.unwrap();
        h2.await.unwrap();

        let key1 = CacheKey::new("bucket", "script_bundle/a.js");
        let key2 = CacheKey::new("bucket", "script_bundle/b.js");

        let entry1 = cache.lookup(&key1).await.unwrap().expect("a should exist");
        let entry2 = cache.lookup(&key2).await.unwrap().expect("b should exist");
        let body1 = tokio::fs::read(&entry1.body_path).await.unwrap();
        let body2 = tokio::fs::read(&entry2.body_path).await.unwrap();
        assert_eq!(body1, b"content a");
        assert_eq!(body2, b"content b");

        let s = cache.stats().await;
        assert_eq!(s.entry_count, 2);
        assert_eq!(s.fill_count, 2);
    }

    #[tokio::test]
    async fn test_fill_with_large_body() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 100_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        // 1MB body
        let body = vec![42u8; 1_024 * 1_024];
        let meta = test_meta(body.len());

        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        let entry = cache.lookup(&key).await.unwrap().expect("should hit");
        let read_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(read_body.len(), 1_024 * 1_024);
        assert_eq!(read_body, body);
    }

    #[tokio::test]
    async fn test_new_loads_existing_stats() {
        let tmp = tempfile::TempDir::new().unwrap();

        // First instance: fill some data
        {
            let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
                .await
                .unwrap();
            let key = test_key();
            let body = b"existing data".to_vec();
            let meta = test_meta(body.len());
            let temp_path = write_temp_body(tmp.path(), &body).await;
            let guard = cache.begin_fill(&key).await.unwrap();
            cache.commit_fill(guard, temp_path, meta).await.unwrap();
        }

        // Second instance: should load stats from disk
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();
        let s = cache.stats().await;
        assert_eq!(s.entry_count, 1);
        assert!(s.total_bytes > 0);
    }

    #[tokio::test]
    async fn test_update_metadata_if_unchanged_updates_total_bytes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"existing data".to_vec();
        let meta = test_meta(body.len());
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        let (_, meta_path) = cache.paths_for_key(&key);
        let before_size = tokio::fs::metadata(&meta_path).await.unwrap().len();
        let before_stats = cache.stats().await;

        let mut updated_meta = cache.lookup(&key).await.unwrap().unwrap().meta;
        updated_meta.extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "a-very-long-checksum-value-to-grow-the-metadata-file".to_string(),
        );
        let expected_fill_id = updated_meta.fill_id;

        assert!(cache
            .update_metadata_if_unchanged(&key, expected_fill_id, updated_meta)
            .await
            .unwrap());

        let after_size = tokio::fs::metadata(&meta_path).await.unwrap().len();
        let after_stats = cache.stats().await;
        assert_eq!(
            after_stats.total_bytes,
            before_stats.total_bytes + after_size - before_size
        );
    }

    #[tokio::test]
    async fn test_update_metadata_if_unchanged_preserves_newer_refresh_fields() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"existing data".to_vec();
        let meta = test_meta(body.len());
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        let (_, meta_path) = cache.paths_for_key(&key);
        let mut current_meta: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(&meta_path).await.unwrap()).unwrap();
        current_meta.checksum_mode_checked = true;
        current_meta.head_metadata_checked = true;
        current_meta.head_checksum_checked = true;
        current_meta.extra_headers.insert(
            "x-amz-checksum-sha256".to_string(),
            "current-sum".to_string(),
        );
        current_meta.head_extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );
        current_meta
            .head_checksum_headers
            .insert("x-amz-checksum-sha256".to_string(), "head-sum".to_string());
        current_meta.metadata_version = 1;
        tokio::fs::write(&meta_path, serde_json::to_vec(&current_meta).unwrap())
            .await
            .unwrap();

        let mut stale_incoming = test_meta(body.len());
        stale_incoming.cache_written_at = current_meta.cache_written_at;
        stale_incoming.fill_id = current_meta.fill_id;
        stale_incoming
            .metadata
            .insert("fresh".to_string(), "meta".to_string());
        stale_incoming.head_metadata_checked = true;

        assert!(!cache
            .update_metadata_if_unchanged(&key, current_meta.fill_id, stale_incoming,)
            .await
            .unwrap());

        let updated: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(&meta_path).await.unwrap()).unwrap();
        assert!(updated.checksum_mode_checked);
        assert!(updated.head_metadata_checked);
        assert!(updated.head_checksum_checked);
        assert_eq!(
            updated.extra_headers.get("x-amz-checksum-sha256").unwrap(),
            "current-sum"
        );
        assert_eq!(
            updated
                .head_extra_headers
                .get("x-amz-archive-status")
                .unwrap(),
            "ARCHIVE_ACCESS"
        );
        assert_eq!(
            updated
                .head_checksum_headers
                .get("x-amz-checksum-sha256")
                .unwrap(),
            "head-sum"
        );
        assert!(updated.metadata.get("fresh").is_none());
        assert_eq!(updated.metadata_version, 1);
    }

    #[tokio::test]
    async fn test_lookup_access_time_update_preserves_refreshed_metadata() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"existing data".to_vec();
        let mut meta = test_meta(body.len());
        meta.last_accessed_at = chrono::Utc::now() - chrono::Duration::hours(2);
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        let looked_up = cache.lookup(&key).await.unwrap().unwrap();
        assert!(looked_up.meta.last_accessed_at < chrono::Utc::now() - chrono::Duration::hours(1));

        let (_, meta_path) = cache.paths_for_key(&key);
        let tmp_dir = cache.cache_dir.join("tmp");
        let hash = key.hash_hex().to_string();
        let expected_fill_id = looked_up.meta.fill_id;
        let meta_lock = cache.meta_lock_for(&key);
        let meta_guard = meta_lock.lock().await;
        let update = tokio::spawn(DiskCache::rewrite_last_accessed(
            Arc::clone(cache.stats_ref()),
            Arc::clone(&meta_lock),
            meta_path.clone(),
            tmp_dir,
            hash,
            expected_fill_id,
            chrono::Utc::now(),
        ));

        let mut current_meta: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(&meta_path).await.unwrap()).unwrap();
        current_meta.checksum_mode_checked = true;
        current_meta.head_metadata_checked = true;
        current_meta
            .extra_headers
            .insert("x-amz-checksum-sha256".to_string(), "preserved".to_string());
        current_meta.head_extra_headers.insert(
            "x-amz-archive-status".to_string(),
            "ARCHIVE_ACCESS".to_string(),
        );
        tokio::fs::write(&meta_path, serde_json::to_vec(&current_meta).unwrap())
            .await
            .unwrap();

        drop(meta_guard);
        update.await.unwrap();

        let refreshed: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(&meta_path).await.unwrap()).unwrap();
        assert!(refreshed.last_accessed_at > looked_up.meta.last_accessed_at);
        assert!(refreshed.checksum_mode_checked);
        assert!(refreshed.head_metadata_checked);
        assert_eq!(
            refreshed
                .extra_headers
                .get("x-amz-checksum-sha256")
                .unwrap(),
            "preserved"
        );
        assert_eq!(
            refreshed
                .head_extra_headers
                .get("x-amz-archive-status")
                .unwrap(),
            "ARCHIVE_ACCESS"
        );
    }

    #[tokio::test]
    async fn test_rewrite_last_accessed_updates_total_bytes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"existing data".to_vec();
        let mut meta = test_meta(body.len());
        meta.last_accessed_at = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        let (_, meta_path) = cache.paths_for_key(&key);
        let before_size = tokio::fs::metadata(&meta_path).await.unwrap().len();
        let before_stats = cache.stats().await;
        let current_meta: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(&meta_path).await.unwrap()).unwrap();
        let meta_lock = cache.meta_lock_for(&key);

        DiskCache::rewrite_last_accessed(
            Arc::clone(cache.stats_ref()),
            meta_lock,
            meta_path.clone(),
            cache.cache_dir.join("tmp"),
            key.hash_hex().to_string(),
            current_meta.fill_id,
            chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00.123456789Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .await;

        let after_size = tokio::fs::metadata(&meta_path).await.unwrap().len();
        let after_stats = cache.stats().await;
        let expected_total_bytes = match after_size.cmp(&before_size) {
            std::cmp::Ordering::Greater => before_stats.total_bytes + (after_size - before_size),
            std::cmp::Ordering::Less => {
                before_stats.total_bytes.saturating_sub(before_size - after_size)
            }
            std::cmp::Ordering::Equal => before_stats.total_bytes,
        };
        assert_eq!(after_stats.total_bytes, expected_total_bytes);
    }

    /// Verify that DiskCache::new seeds the counter from on-disk fill_ids.
    #[tokio::test]
    async fn test_fill_id_survives_restart() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        let key = test_key();
        let body = b"restart data".to_vec();
        let old_fill_id = 1_000_000_000_000_000_000u64;

        // Seed the cache directory with a very large on-disk fill_id so the
        // reseed path is exercised without mutating the process-wide counter
        // from the test body.
        let cache1 = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .unwrap();
        let (body_path, meta_path) = cache1.paths_for_key(&key);
        if let Some(parent) = body_path.parent() {
            tokio::fs::create_dir_all(parent).await.unwrap();
        }
        let mut meta = test_meta(body.len());
        meta.fill_id = old_fill_id;
        tokio::fs::write(&body_path, &body).await.unwrap();
        tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap())
            .await
            .unwrap();
        drop(cache1);

        // DiskCache::new must re-seed from the on-disk max.
        let cache2 = DiskCache::new(cache_dir.clone(), 1_000_000, test_policy())
            .await
            .unwrap();

        // Verify counter was re-seeded above the on-disk max.
        assert!(
            FILL_ID_COUNTER.load(Ordering::Relaxed) > old_fill_id,
            "FILL_ID_COUNTER was not re-seeded from disk"
        );
        let body2 = b"new restart data".to_vec();
        let meta2 = test_meta(body2.len());
        let temp_path2 = write_temp_body(tmp.path(), &body2).await;
        let guard2 = cache2.begin_fill(&key).await.unwrap();
        cache2.commit_fill(guard2, temp_path2, meta2).await.unwrap();
        let new_fill_id = cache2.lookup(&key).await.unwrap().unwrap().meta.fill_id;

        assert!(
            new_fill_id > old_fill_id,
            "fill_id did not survive restart: old={old_fill_id}, new={new_fill_id}"
        );

        assert!(!cache2
            .purge_if_unchanged(&key, old_fill_id)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_purge_if_unchanged_removes_entry_and_updates_stats() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"existing data".to_vec();
        let meta = test_meta(body.len());
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        let entry = cache.lookup(&key).await.unwrap().unwrap();
        let expected_fill_id = entry.meta.fill_id;

        assert!(cache
            .purge_if_unchanged(&key, expected_fill_id)
            .await
            .unwrap());
        assert!(cache.lookup(&key).await.unwrap().is_none());

        let s = cache.stats().await;
        assert_eq!(s.entry_count, 0);
        assert_eq!(s.total_bytes, 0);
    }

    #[tokio::test]
    async fn test_purge_if_unchanged_mismatch_does_not_reject_active_fill() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let original_body = b"old data".to_vec();
        let original_meta = test_meta(original_body.len());
        let original_temp_path = write_temp_body(tmp.path(), &original_body).await;
        let original_guard = cache.begin_fill(&key).await.unwrap();
        cache
            .commit_fill(original_guard, original_temp_path, original_meta)
            .await
            .unwrap();

        let fill_guard = cache.begin_fill(&key).await.unwrap();
        let new_body = b"new data".to_vec();
        let new_temp_path = write_temp_body(tmp.path(), &new_body).await;
        let new_meta = test_meta(new_body.len());

        let wrong_fill_id = u64::MAX;
        assert!(!cache
            .purge_if_unchanged(&key, wrong_fill_id)
            .await
            .unwrap());

        cache
            .commit_fill(fill_guard, new_temp_path, new_meta)
            .await
            .unwrap();

        let entry = cache.lookup(&key).await.unwrap().unwrap();
        let body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(body, new_body);
    }

    #[tokio::test]
    async fn test_poison_if_unchanged_rejects_older_active_fill() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let existing_body = b"existing data".to_vec();
        let existing_meta = test_meta(existing_body.len());
        let existing_temp_path = write_temp_body(tmp.path(), &existing_body).await;
        let existing_guard = cache.begin_fill(&key).await.unwrap();
        cache
            .commit_fill(existing_guard, existing_temp_path, existing_meta)
            .await
            .unwrap();
        let expected_fill_id = cache.lookup(&key).await.unwrap().unwrap().meta.fill_id;

        let stale_guard = cache.begin_fill(&key).await.unwrap();

        assert!(cache
            .poison_if_unchanged(&key, expected_fill_id)
            .await
            .unwrap());
        let poison_path = cache.poison_path_for_key(&key);
        assert!(tokio::fs::try_exists(&poison_path).await.unwrap());

        let replacement_body = b"replacement data".to_vec();
        let replacement_meta = test_meta(replacement_body.len());
        let replacement_temp_path = write_temp_body(tmp.path(), &replacement_body).await;
        cache
            .commit_fill(stale_guard, replacement_temp_path, replacement_meta)
            .await
            .unwrap();

        let (body_path, _) = cache.paths_for_key(&key);
        let cached_body = tokio::fs::read(&body_path).await.unwrap();
        assert_eq!(cached_body, existing_body);
        assert!(tokio::fs::try_exists(&poison_path).await.unwrap());
        assert!(cache.lookup(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_lookup_updates_last_accessed_at_when_stale() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"console.log('hello');".to_vec();
        let mut meta = test_meta(body.len());
        // Set last_accessed_at to 2 hours ago to trigger the update
        meta.last_accessed_at = Utc::now() - chrono::Duration::hours(2);

        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        // Lookup should trigger access time update
        let entry = cache.lookup(&key).await.unwrap().expect("should hit");
        assert!(entry.meta.last_accessed_at < Utc::now() - chrono::Duration::minutes(90));

        // Wait for the background task to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Re-read metadata from disk to verify it was updated
        let (_, meta_path) = cache.paths_for_key(&key);
        let meta_bytes = tokio::fs::read(&meta_path).await.unwrap();
        let updated_meta: CacheMeta = serde_json::from_slice(&meta_bytes).unwrap();
        // The updated last_accessed_at should be recent (within last few seconds)
        let age = Utc::now().signed_duration_since(updated_meta.last_accessed_at);
        assert!(
            age < chrono::Duration::seconds(5),
            "last_accessed_at should have been updated to now, age: {:?}",
            age
        );
    }

    #[tokio::test]
    async fn test_poison_blocks_lookup() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"cached data".to_vec();
        let meta = test_meta(body.len());

        // Fill the cache entry
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        // Verify lookup returns Some before poisoning
        assert!(cache.lookup(&key).await.unwrap().is_some());

        // Poison the key
        cache.poison(&key).await.unwrap();

        // Lookup should now return None (cache miss)
        assert!(cache.lookup(&key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_poison_cleared_on_successful_purge() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"cached data".to_vec();
        let meta = test_meta(body.len());

        // Fill → poison → purge
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();
        cache.poison(&key).await.unwrap();
        cache.purge(&key).await.unwrap();

        // Refill with new data
        let new_body = b"fresh data".to_vec();
        let new_meta = test_meta(new_body.len());
        let temp_path = write_temp_body(tmp.path(), &new_body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, new_meta).await.unwrap();

        // Lookup should return the new entry (poison was cleared by purge)
        let entry = cache
            .lookup(&key)
            .await
            .unwrap()
            .expect("should hit after purge cleared poison");
        let read_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(read_body, b"fresh data");
    }

    #[tokio::test]
    async fn test_poison_cleared_on_new_fill() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"old data".to_vec();
        let meta = test_meta(body.len());

        // Fill → poison
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();
        cache.poison(&key).await.unwrap();

        // Verify poisoned
        assert!(cache.lookup(&key).await.unwrap().is_none());

        // begin_fill + commit_fill with new data should clear the poison marker
        let new_body = b"new data after poison".to_vec();
        let new_meta = test_meta(new_body.len());
        let temp_path = write_temp_body(tmp.path(), &new_body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, new_meta).await.unwrap();

        // Lookup should return the new entry
        let entry = cache
            .lookup(&key)
            .await
            .unwrap()
            .expect("should hit after fill cleared poison");
        let read_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(read_body, b"new data after poison");
    }

    #[tokio::test]
    async fn test_lookup_without_poison_marker_works() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"normal data".to_vec();
        let meta = test_meta(body.len());

        // Fill without any poisoning
        let temp_path = write_temp_body(tmp.path(), &body).await;
        let guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(guard, temp_path, meta).await.unwrap();

        // Lookup should return Some (no poison marker)
        let entry = cache
            .lookup(&key)
            .await
            .unwrap()
            .expect("should hit with no poison marker");
        let read_body = tokio::fs::read(&entry.body_path).await.unwrap();
        assert_eq!(read_body, b"normal data");
    }

    #[tokio::test]
    async fn test_commit_fill_rejected_after_purge() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let body = b"stale content".to_vec();
        let meta = test_meta(body.len());

        let temp_path = write_temp_body(tmp.path(), &body).await;

        // 1. Begin fill — captures generation BEFORE download starts
        let guard = cache.begin_fill(&key).await.unwrap();
        assert_eq!(guard.generation, 0);

        // 2. Simulate concurrent purge (PUT/DELETE on the same key)
        let _ = cache.purge(&key).await;

        // 3. Commit fill — should detect generation mismatch and reject
        cache
            .commit_fill(guard, temp_path.clone(), meta)
            .await
            .unwrap();

        // The entry should NOT be in the cache
        let entry = cache.lookup(&key).await.unwrap();
        assert!(
            entry.is_none(),
            "stale fill should have been rejected after purge"
        );
    }

    #[tokio::test]
    async fn test_commit_fill_waits_for_meta_lock_before_publishing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let old_body = b"old body".to_vec();
        let mut old_meta = test_meta(old_body.len());
        old_meta.etag = Some("\"old-etag\"".into());

        let old_temp = write_temp_body(tmp.path(), &old_body).await;
        let old_guard = cache.begin_fill(&key).await.unwrap();
        cache
            .commit_fill(old_guard, old_temp, old_meta)
            .await
            .unwrap();

        let new_body = b"new body".to_vec();
        let mut new_meta = test_meta(new_body.len());
        new_meta.etag = Some("\"new-etag\"".into());
        let new_temp = write_temp_body(tmp.path(), &new_body).await;
        let new_guard = cache.begin_fill(&key).await.unwrap();

        let (final_body, final_meta) = cache.paths_for_key(&key);
        let meta_lock = cache.meta_lock_for(&key);
        let meta_guard = meta_lock.lock().await;

        let commit = cache.commit_fill(new_guard, new_temp, new_meta);
        tokio::pin!(commit);

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut commit)
                .await
                .is_err()
        );

        let body_during_block = tokio::fs::read(&final_body).await.unwrap();
        assert_eq!(body_during_block, old_body);
        let meta_during_block: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(&final_meta).await.unwrap()).unwrap();
        assert_eq!(meta_during_block.etag.as_deref(), Some("\"old-etag\""));

        drop(meta_guard);

        commit.await.unwrap();

        let body_after_publish = tokio::fs::read(&final_body).await.unwrap();
        assert_eq!(body_after_publish, new_body);
        let meta_after_publish: CacheMeta =
            serde_json::from_slice(&tokio::fs::read(&final_meta).await.unwrap()).unwrap();
        assert_eq!(meta_after_publish.etag.as_deref(), Some("\"new-etag\""));
    }

    #[tokio::test]
    async fn test_lookup_pins_body_snapshot_across_fill_replacement() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = DiskCache::new(tmp.path().to_path_buf(), 1_000_000, test_policy())
            .await
            .unwrap();

        let key = test_key();
        let old_body = b"old body".to_vec();
        let mut old_meta = test_meta(old_body.len());
        old_meta.etag = Some("\"old-etag\"".into());
        let old_temp = write_temp_body(tmp.path(), &old_body).await;
        let old_guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(old_guard, old_temp, old_meta).await.unwrap();

        let looked_up = cache.lookup(&key).await.unwrap().unwrap();
        assert_eq!(looked_up.meta.etag.as_deref(), Some("\"old-etag\""));

        let new_body = b"new body".to_vec();
        let mut new_meta = test_meta(new_body.len());
        new_meta.etag = Some("\"new-etag\"".into());
        let new_temp = write_temp_body(tmp.path(), &new_body).await;
        let new_guard = cache.begin_fill(&key).await.unwrap();
        cache.commit_fill(new_guard, new_temp, new_meta).await.unwrap();

        let mut pinned_file = looked_up.body_file.unwrap();
        let mut pinned_bytes = Vec::new();
        pinned_file.read_to_end(&mut pinned_bytes).await.unwrap();
        assert_eq!(pinned_bytes, old_body);

        let latest = cache.lookup(&key).await.unwrap().unwrap();
        let latest_body = tokio::fs::read(&latest.body_path).await.unwrap();
        assert_eq!(latest_body, new_body);
        assert_eq!(latest.meta.etag.as_deref(), Some("\"new-etag\""));
    }
}
