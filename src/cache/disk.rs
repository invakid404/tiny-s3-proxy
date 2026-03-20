use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::cache::entry::CacheEntry;
use crate::cache::key::CacheKey;
use crate::cache::metadata::CacheMeta;
use crate::cache::policy::CachePolicy;
use crate::cache::{CacheStats, CacheStatsSnapshot, CacheStore, FillGuard};
use crate::error::ProxyError;

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
    meta_locks: std::sync::Mutex<HashMap<CacheKey, Arc<tokio::sync::Mutex<()>>>>,
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

        // Load stats from existing cached files
        let stats = Self::scan_existing_stats(&cache_dir).await?;

        Ok(Self {
            cache_dir,
            stats: Arc::new(stats),
            active_fills: tokio::sync::RwLock::new(HashMap::new()),
            meta_locks: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Scan the objects directory to compute initial stats at startup.
    /// These provide the baseline; the periodic eviction scan reconciles
    /// them against filesystem reality on every pass thereafter.
    async fn scan_existing_stats(cache_dir: &std::path::Path) -> Result<CacheStats, ProxyError> {
        let objects_dir = cache_dir.join("objects");
        let stats = CacheStats::default();

        let mut d1_entries = match tokio::fs::read_dir(&objects_dir).await {
            Ok(entries) => entries,
            Err(_) => return Ok(stats), // empty or missing, no entries
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

            let mut d2_entries =
                match tokio::fs::read_dir(&d1_path).await {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };

            while let Some(d2_entry) = d2_entries
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

                let mut file_entries =
                    match tokio::fs::read_dir(&d2_path).await {
                        Ok(entries) => entries,
                        Err(_) => continue,
                    };

                while let Some(file_entry) = file_entries
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
                        let meta_path = file_path.parent().unwrap().join(format!("{hash}.meta.json"));
                        if tokio::fs::try_exists(&meta_path).await.unwrap_or(false) {
                            if let Ok(m) = tokio::fs::metadata(&file_path).await {
                                stats.total_bytes.fetch_add(m.len(), Ordering::Relaxed);
                                stats.entry_count.fetch_add(1, Ordering::Relaxed);
                            }
                            if let Ok(m) = tokio::fs::metadata(&meta_path).await {
                                stats.total_bytes.fetch_add(m.len(), Ordering::Relaxed);
                            }
                        } else {
                            let _ = tokio::fs::remove_file(&file_path).await;
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Build paths for the body and metadata files for a given key.
    /// Computes the hash once and derives both paths.
    fn paths_for_key(&self, key: &CacheKey) -> (PathBuf, PathBuf) {
        let hash = key.hash_hex();
        let dir = self.cache_dir.join("objects").join(&hash[..2]).join(&hash[2..4]);
        let body = dir.join(format!("{hash}.body"));
        let meta = dir.join(format!("{hash}.meta.json"));
        (body, meta)
    }

    /// Path for the durable poison marker for a key. A `.poisoned` file next
    /// to the entry signals that a purge failed and the entry must not be served.
    /// This survives process restarts, unlike an in-memory set.
    fn poison_path_for_key(&self, key: &CacheKey) -> PathBuf {
        let hash = key.hash_hex();
        let dir = self.cache_dir.join("objects").join(&hash[..2]).join(&hash[2..4]);
        dir.join(format!("{hash}.poisoned"))
    }

    /// Get or create the per-key metadata-write lock.
    fn meta_lock_for(&self, key: &CacheKey) -> Arc<tokio::sync::Mutex<()>> {
        self.meta_locks
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Remove `meta_locks` entries whose cache files no longer exist on disk.
    /// Called periodically by the eviction loop to prevent unbounded growth.
    pub async fn sweep_stale_meta_locks(&self) {
        // Snapshot current keys under a brief std::sync::Mutex hold.
        let keys: Vec<CacheKey> = self.meta_locks.lock().unwrap().keys().cloned().collect();
        let mut stale = Vec::new();
        for key in &keys {
            let (_, meta_path) = self.paths_for_key(key);
            if !tokio::fs::try_exists(&meta_path).await.unwrap_or(true) {
                stale.push(key.clone());
            }
        }
        if !stale.is_empty() {
            let mut locks = self.meta_locks.lock().unwrap();
            for key in &stale {
                locks.remove(key);
            }
        }
    }

    /// Get a reference to the stats.
    pub fn stats_ref(&self) -> &Arc<CacheStats> {
        &self.stats
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
            let current_gen = fills.get(&guard.key)
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

        // Write metadata to temp file
        let temp_meta = guard.temp_dir.join(format!("{pid}-{id}.meta.json"));
        let meta_bytes = serde_json::to_vec(&meta).map_err(|e| ProxyError::Cache {
            source: Box::new(e),
            operation: "serialize metadata".into(),
        })?;
        tokio::fs::write(&temp_meta, &meta_bytes)
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "write temp metadata".into(),
            })?;

        // fsync metadata
        let meta_file = tokio::fs::File::open(&temp_meta)
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "open temp meta for fsync".into(),
            })?;
        meta_file
            .sync_all()
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "fsync temp metadata".into(),
            })?;

        // Create parent directories for final location
        let (final_body, final_meta) = self.paths_for_key(&guard.key);
        if let Some(parent) = final_body.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "create object dir".into(),
                })?;
        }

        // Pre-publish generation check via read lock (doesn't block purge).
        {
            let fills = self.active_fills.read().await;
            let cur_gen = fills.get(&guard.key).map(|e| e.generation.load(Ordering::Acquire)).unwrap_or(0);
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

            // Best-effort incremental stat adjustment: subtract the old entry's
            // size before replacing it. This may race with eviction (which could
            // delete or replace the same files concurrently), but any drift is
            // corrected by the periodic eviction scan which reconciles stats
            // from filesystem reality. See eviction::run_eviction_loop docs.
            let old_body_size = tokio::fs::metadata(&final_body).await.map(|m| m.len()).unwrap_or(0);
            let old_meta_size = tokio::fs::metadata(&final_meta).await.map(|m| m.len()).unwrap_or(0);
            if old_body_size > 0 || old_meta_size > 0 {
                let _ = tokio::fs::remove_file(&final_body).await;
                let _ = tokio::fs::remove_file(&final_meta).await;
                let _ = self.stats.entry_count.fetch_update(
                    Ordering::Relaxed, Ordering::Relaxed,
                    |c| Some(c.saturating_sub(1)),
                );
                let _ = self.stats.total_bytes.fetch_update(
                    Ordering::Relaxed, Ordering::Relaxed,
                    |c| Some(c.saturating_sub(old_body_size + old_meta_size)),
                );
            }

            // Re-check generation — purge() bumps it under the same commit_lock.
            {
                let fills = self.active_fills.read().await;
                let cur_gen = fills.get(&guard.key).map(|e| e.generation.load(Ordering::Acquire)).unwrap_or(0);
                if cur_gen != guard.generation {
                    tracing::info!(key = %guard.key.object_key, "cache fill rejected (late check)");
                    let _ = tokio::fs::remove_file(&temp_body_path).await;
                    let _ = tokio::fs::remove_file(&temp_meta).await;
                    return Ok(());
                }
            }

            // Atomic rename — publish the new cache entry.
            tokio::fs::rename(&temp_body_path, &final_body)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "rename body".into(),
                })?;
            // Acquire the per-key meta lock so the metadata rename cannot
            // interleave with a background access-time updater's
            // read-check-rename sequence.
            {
                let meta_lock = self.meta_lock_for(&guard.key);
                let _meta_guard = meta_lock.lock().await;
                if let Err(e) = tokio::fs::rename(&temp_meta, &final_meta).await {
                    let _ = tokio::fs::remove_file(&final_body).await;
                    return Err(ProxyError::Cache {
                        source: Box::new(e),
                        operation: "rename metadata".into(),
                    });
                }
            }

            // Best-effort: add the new entry's size. The periodic eviction scan
            // reconciles any drift from concurrent operations.
            let new_size = body_size + meta_bytes.len() as u64;
            self.stats.entry_count.fetch_add(1, Ordering::Relaxed);
            self.stats.total_bytes.fetch_add(new_size, Ordering::Relaxed);
            self.stats.fill_count.fetch_add(1, Ordering::Relaxed);
        }

        // Fresh content published — clear any stale poison marker for this key.
        let _ = tokio::fs::remove_file(&self.poison_path_for_key(&guard.key)).await;

        Ok(())
    }
}

impl CacheStore for DiskCache {
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
        // If the key was poisoned (purge failed after a write), treat as miss.
        // The .poisoned marker is durable on disk so it survives restarts.
        if tokio::fs::try_exists(&self.poison_path_for_key(key)).await.unwrap_or(false) {
            self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        let (body_path, meta_path) = self.paths_for_key(key);

        // Single syscall: try to read metadata. NotFound = cache miss.
        let meta_bytes = match tokio::fs::read(&meta_path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }
            Err(e) => {
                self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "read metadata".into(),
                });
            }
        };

        let meta: CacheMeta = match serde_json::from_slice(&meta_bytes) {
            Ok(m) => m,
            Err(e) => {
                // Corrupt metadata — delete the whole entry and treat as miss.
                // Without cleanup, this entry would leak disk space indefinitely
                // since the eviction scan also skips unreadable metadata.
                tracing::warn!(key = %key.object_key, error = %e, "corrupt cache metadata, cleaning up");
                let _ = tokio::fs::remove_file(&meta_path).await;
                let _ = tokio::fs::remove_file(&body_path).await;
                self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }
        };

        // Defense in depth: verify the metadata actually belongs to this key.
        // A hash collision (extremely unlikely with 64-bit ahash) would
        // otherwise serve the wrong object.
        if meta.bucket != key.bucket || meta.key != key.object_key {
            tracing::warn!(
                expected_bucket = %key.bucket,
                expected_key = %key.object_key,
                actual_bucket = %meta.bucket,
                actual_key = %meta.key,
                "cache hash collision detected — treating as miss"
            );
            self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        // Verify body file exists (cheap stat, not a full read).
        // If the body is gone but metadata remains, eagerly clean up the orphan
        // and do a best-effort stat adjustment. The periodic eviction scan
        // reconciles any inaccuracy from the estimated body_size.
        if !tokio::fs::try_exists(&body_path).await.unwrap_or(false) {
            self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
            if tokio::fs::remove_file(&meta_path).await.is_ok() {
                let meta_size = meta_bytes.len() as u64;
                let body_size = meta.content_length.max(0) as u64;
                let _ = self.stats.entry_count.fetch_update(
                    Ordering::Relaxed, Ordering::Relaxed,
                    |c| Some(c.saturating_sub(1)),
                );
                let _ = self.stats.total_bytes.fetch_update(
                    Ordering::Relaxed, Ordering::Relaxed,
                    |c| Some(c.saturating_sub(meta_size + body_size)),
                );
            }
            return Ok(None);
        }

        // Record hit
        self.stats.hit_count.fetch_add(1, Ordering::Relaxed);

        // Update last_accessed_at on disk if older than 1 hour.
        // This is throttled to avoid a disk write on every single cache hit.
        // Uses temp-file + atomic rename so a crash/ENOSPC during the write
        // cannot corrupt the live metadata file.
        //
        // Guard: acquires a dedicated per-key meta lock (shared with
        // commit_fill's rename step) so the read-check-rename cannot
        // interleave with a concurrent fill — regardless of whether an
        // active_fills entry exists yet.
        let now = chrono::Utc::now();
        if now.signed_duration_since(meta.last_accessed_at) > chrono::Duration::hours(1) {
            let mut updated_meta = meta.clone();
            updated_meta.last_accessed_at = now;
            let expected_written_at = meta.cache_written_at;
            let meta_path_owned = meta_path.clone();
            let tmp_dir = self.cache_dir.join("tmp");
            let hash = key.hash_hex().to_string();
            let meta_lock = self.meta_lock_for(key);
            tokio::spawn(async move {
                static ACCESS_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

                // Hold the per-key meta lock for the entire check+rename.
                let _guard = meta_lock.lock().await;

                // Re-read current metadata to verify no newer fill overwrote it.
                if let Ok(current_bytes) = tokio::fs::read(&meta_path_owned).await {
                    if let Ok(current_meta) = serde_json::from_slice::<CacheMeta>(&current_bytes) {
                        if current_meta.cache_written_at != expected_written_at {
                            return;
                        }
                    }
                } else {
                    return;
                }
                if let Ok(bytes) = serde_json::to_vec(&updated_meta) {
                    let counter = ACCESS_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let tmp_path = tmp_dir.join(format!(
                        "{}-{}-{}.meta.tmp",
                        std::process::id(),
                        hash,
                        counter,
                    ));
                    if tokio::fs::write(&tmp_path, &bytes).await.is_ok() {
                        let _ = tokio::fs::rename(&tmp_path, &meta_path_owned).await;
                    }
                }
            });
        }

        Ok(Some(CacheEntry { meta, body_path }))
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

        // Use async filesystem checks instead of blocking .exists()
        let body_exists = tokio::fs::try_exists(&body_path).await.unwrap_or(false);
        let meta_exists = tokio::fs::try_exists(&meta_path).await.unwrap_or(false);

        if !body_exists && !meta_exists {
            // Still clear any leftover poison marker — the stale entry is gone.
            let _ = tokio::fs::remove_file(&self.poison_path_for_key(key)).await;
            return Ok(false);
        }

        // Track sizes for stats update
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
            // Best-effort incremental stat adjustment. If only one file was
            // removed (the other errored via `?`), the function already
            // returned Err above and stats are not adjusted — the periodic
            // eviction scan reconciles from filesystem reality on the next pass.
            let _ = self.stats.entry_count.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            });
            let total_removed = body_size + meta_size;
            let _ = self.stats.total_bytes.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(total_removed))
            });
        }

        // Always clear the poison marker: if files were removed the stale data
        // is gone, and if they were already absent there's nothing stale to block.
        let _ = tokio::fs::remove_file(&self.poison_path_for_key(key)).await;

        // Clean up the per-key meta lock — the cache entry is gone so no
        // access-time updater can be in flight for this key.
        self.meta_locks.lock().unwrap().remove(key);

        Ok(removed)
    }

    async fn poison(&self, key: &CacheKey) -> Result<(), ProxyError> {
        let path = self.poison_path_for_key(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "create poison marker dir".into(),
            })?;
        }
        tokio::fs::write(&path, b"").await.map_err(|e| ProxyError::Cache {
            source: Box::new(e),
            operation: "write poison marker".into(),
        })
    }

    async fn stats(&self) -> CacheStatsSnapshot {
        self.stats.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tokio::io::AsyncWriteExt;

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
            last_accessed_at: now,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
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
        assert_eq!(entry.meta.content_type, Some("application/javascript".into()));
        assert_eq!(entry.meta.content_length, body.len() as i64);
        assert_eq!(entry.meta.source_status, 200);
        // hit_count is no longer incremented on-disk per hit, stays at 0 in meta
        assert_eq!(entry.meta.hit_count, 0);
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
        cache
            .commit_fill(guard, temp_path, meta)
            .await
            .unwrap();

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

        assert!(body_path.exists(), "body file should exist at expected path");
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
        cache
            .commit_fill(guard, temp_path, meta)
            .await
            .unwrap();

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
                    last_accessed_at: Utc::now(),
                    hit_count: 0,
                    source_status: 200,
                    metadata: std::collections::HashMap::new(),
                    extra_headers: std::collections::HashMap::new(),
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
                last_accessed_at: Utc::now(),
                hit_count: 0,
                source_status: 200,
                metadata: std::collections::HashMap::new(),
                extra_headers: std::collections::HashMap::new(),
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
        cache
            .commit_fill(guard, temp_path, meta)
            .await
            .unwrap();

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
        let entry = cache.lookup(&key).await.unwrap().expect("should hit after purge cleared poison");
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
        let entry = cache.lookup(&key).await.unwrap().expect("should hit after fill cleared poison");
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
        let entry = cache.lookup(&key).await.unwrap().expect("should hit with no poison marker");
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
        cache.commit_fill(guard, temp_path.clone(), meta).await.unwrap();

        // The entry should NOT be in the cache
        let entry = cache.lookup(&key).await.unwrap();
        assert!(entry.is_none(), "stale fill should have been rejected after purge");
    }
}
