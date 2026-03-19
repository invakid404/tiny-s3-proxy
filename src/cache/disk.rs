use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::cache::entry::CacheEntry;
use crate::cache::key::CacheKey;
use crate::cache::metadata::CacheMeta;
use crate::cache::policy::CachePolicy;
use crate::cache::singleflight::SingleFlight;
use crate::cache::{CacheStats, CacheStatsSnapshot, CacheStore, FillGuard};
use crate::error::ProxyError;

/// Tracks in-flight fills and per-key invalidation generations.
///
/// `active_fills` is a reference count of outstanding `FillGuard`s per key,
/// so overlapping fills (e.g. after singleflight cancel + re-acquire) are
/// tracked independently. `purge()` only creates a generation entry when
/// the count is > 0. Both maps are bounded by the number of concurrent fills.
#[derive(Default)]
struct FillState {
    active_fills: HashMap<CacheKey, usize>,
    generations: HashMap<CacheKey, u64>,
}

/// Disk-backed implementation of `CacheStore`.
///
/// Stores cached objects on the filesystem using a two-level directory hash
/// scheme for even distribution. Writes are atomic (write to tmp, fsync, rename).
pub struct DiskCache {
    cache_dir: PathBuf,
    #[allow(dead_code)]
    max_bytes: u64,
    #[allow(dead_code)]
    policy: CachePolicy,
    stats: Arc<CacheStats>,
    singleflight: Arc<SingleFlight>,
    /// Cache invalidation state, protected by a single mutex to ensure
    /// atomicity between generation checks and cache publishing.
    ///
    /// `active_fills` tracks keys with in-flight fill operations. `purge()`
    /// only creates a generation entry when an active fill exists for that key,
    /// so the map is bounded by the number of concurrent fills (not total purges).
    ///
    /// `generations` maps keys to a counter that is bumped by `purge()` and
    /// captured by `begin_fill()`. `commit_fill()` re-checks the counter
    /// under this lock immediately before the atomic rename.
    fill_state: tokio::sync::Mutex<FillState>,

}

impl DiskCache {
    /// Create a new DiskCache, initializing directory structure and loading
    /// stats from any existing cached files on disk.
    pub async fn new(
        cache_dir: PathBuf,
        max_bytes: u64,
        policy: CachePolicy,
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
            max_bytes,
            policy,
            stats: Arc::new(stats),
            singleflight: Arc::new(SingleFlight::new()),
            fill_state: tokio::sync::Mutex::new(FillState::default()),
        })
    }

    /// Scan the objects directory to compute initial stats.
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
                        // Build the expected meta path: replace .body extension
                        // Note: file_path is like /cache/objects/ab/cd/abcdef1234.body
                        // The meta would be /cache/objects/ab/cd/abcdef1234.meta.json
                        let hash = file_name.trim_end_matches(".body");
                        let meta_path = file_path.parent().unwrap().join(format!("{}.meta.json", hash));
                        if tokio::fs::try_exists(&meta_path).await.unwrap_or(false) {
                            // Complete entry: count body + meta
                            if let Ok(body_meta) = tokio::fs::metadata(&file_path).await {
                                stats.total_bytes.fetch_add(body_meta.len(), Ordering::Relaxed);
                                stats.entry_count.fetch_add(1, Ordering::Relaxed);
                            }
                            if let Ok(meta_meta) = tokio::fs::metadata(&meta_path).await {
                                stats.total_bytes.fetch_add(meta_meta.len(), Ordering::Relaxed);
                            }
                        } else {
                            // Orphan body file (no matching metadata): remove it.
                            let _ = tokio::fs::remove_file(&file_path).await;
                            tracing::debug!(
                                path = %file_path.display(),
                                "removed orphan body file during startup scan"
                            );
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

    /// Get a reference to the singleflight instance.
    pub fn singleflight(&self) -> &Arc<SingleFlight> {
        &self.singleflight
    }

    /// Get a reference to the stats.
    pub fn stats_ref(&self) -> &Arc<CacheStats> {
        &self.stats
    }

    /// Decrement the active fill refcount for a key. When the count reaches
    /// zero, remove the active_fills and generations entries so future purges
    /// don't needlessly bump generations for a key with no in-flight fills.
    async fn finish_fill(&self, key: &CacheKey) {
        let mut state = self.fill_state.lock().await;
        if let Some(count) = state.active_fills.get_mut(key) {
            *count -= 1;
            if *count == 0 {
                state.active_fills.remove(key);
                state.generations.remove(key);
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
        // Early check: bail fast if already invalidated (avoids unnecessary I/O).
        {
            let state = self.fill_state.lock().await;
            if state.generations.get(&guard.key).copied().unwrap_or(0) != guard.generation {
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

        // Re-check generation under lock and do atomic rename while holding it.
        // purge() also acquires this lock before incrementing, so the check +
        // rename is atomic with respect to invalidation.
        {
            let state = self.fill_state.lock().await;
            if state.generations.get(&guard.key).copied().unwrap_or(0) != guard.generation {
                tracing::info!(
                    key = %guard.key.object_key,
                    "cache fill rejected (pre-publish): key invalidated during fill"
                );
                drop(state);
                let _ = tokio::fs::remove_file(&temp_body_path).await;
                let _ = tokio::fs::remove_file(&temp_meta).await;
                return Ok(());
            }

            // Atomic rename — publish the cache entry while holding the lock.
            tokio::fs::rename(&temp_body_path, &final_body)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "rename body".into(),
                })?;
            if let Err(e) = tokio::fs::rename(&temp_meta, &final_meta).await {
                let _ = tokio::fs::remove_file(&final_body).await;
                return Err(ProxyError::Cache {
                    source: Box::new(e),
                    operation: "rename metadata".into(),
                });
            }
        }

        // Fresh content published — clear any stale poison marker for this key.
        let _ = tokio::fs::remove_file(&self.poison_path_for_key(&guard.key)).await;

        // Update stats atomically (outside lock)
        self.stats.entry_count.fetch_add(1, Ordering::Relaxed);
        self.stats.total_bytes.fetch_add(body_size + meta_bytes.len() as u64, Ordering::Relaxed);
        self.stats.fill_count.fetch_add(1, Ordering::Relaxed);

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

        let meta: CacheMeta = serde_json::from_slice(&meta_bytes).map_err(|e| ProxyError::Cache {
            source: Box::new(e),
            operation: "parse metadata".into(),
        })?;

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
        // If the body is gone but metadata remains, clean up the orphan so
        // cache accounting stays accurate and a future refill doesn't
        // double-count the entry.
        if !tokio::fs::try_exists(&body_path).await.unwrap_or(false) {
            self.stats.miss_count.fetch_add(1, Ordering::Relaxed);
            // Clean up orphan metadata and adjust stats so a future refill
            // doesn't double-count this entry.
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
        let now = chrono::Utc::now();
        if now.signed_duration_since(meta.last_accessed_at) > chrono::Duration::hours(1) {
            let mut updated_meta = meta.clone();
            updated_meta.last_accessed_at = now;
            let meta_path_owned = meta_path.clone();
            let tmp_dir = self.cache_dir.join("tmp");
            let hash = key.hash_hex();
            tokio::spawn(async move {
                static ACCESS_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
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
        let generation = {
            let mut state = self.fill_state.lock().await;
            *state.active_fills.entry(key.clone()).or_insert(0) += 1;
            state.generations.get(key).copied().unwrap_or(0)
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
        // Only bump the generation counter if there's an active fill for this
        // key. This bounds the map to the number of concurrent fills — a purge
        // without a concurrent fill has nothing to invalidate.
        {
            let mut state = self.fill_state.lock().await;
            if state.active_fills.get(key).copied().unwrap_or(0) > 0 {
                let counter = state.generations.entry(key.clone()).or_insert(0);
                *counter += 1;
            }
        }

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
            // Use saturating subtraction to avoid wrapping on partial/orphan entries.
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
