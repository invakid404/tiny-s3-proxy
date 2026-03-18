use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::cache::entry::CacheEntry;
use crate::cache::key::CacheKey;
use crate::cache::metadata::CacheMeta;
use crate::cache::policy::CachePolicy;
use crate::cache::singleflight::SingleFlight;
use crate::cache::{CacheStats, CacheStore, FillGuard};
use crate::error::ProxyError;

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
    stats: Arc<RwLock<CacheStats>>,
    singleflight: Arc<SingleFlight>,
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
            stats: Arc::new(RwLock::new(stats)),
            singleflight: Arc::new(SingleFlight::new()),
        })
    }

    /// Scan the objects directory to compute initial stats.
    async fn scan_existing_stats(cache_dir: &PathBuf) -> Result<CacheStats, ProxyError> {
        let objects_dir = cache_dir.join("objects");
        let mut stats = CacheStats::default();

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

                    // Only count .body files to avoid double-counting
                    if file_name.ends_with(".body") {
                        if let Ok(metadata) = tokio::fs::metadata(&file_path).await {
                            stats.total_bytes += metadata.len();
                            stats.entry_count += 1;
                        }
                        // Also add the size of the corresponding .meta.json
                        let meta_path = file_path.with_extension("meta.json");
                        if let Ok(metadata) = tokio::fs::metadata(&meta_path).await {
                            stats.total_bytes += metadata.len();
                        }
                    }
                }
            }
        }

        Ok(stats)
    }

    /// Build the path to the body file for a given key.
    fn body_path(&self, key: &CacheKey) -> PathBuf {
        let hash = key.hash();
        let (d1, d2) = key.dir_prefix();
        self.cache_dir
            .join("objects")
            .join(d1)
            .join(d2)
            .join(format!("{}.body", hash))
    }

    /// Build the path to the metadata file for a given key.
    fn meta_path(&self, key: &CacheKey) -> PathBuf {
        let hash = key.hash();
        let (d1, d2) = key.dir_prefix();
        self.cache_dir
            .join("objects")
            .join(d1)
            .join(d2)
            .join(format!("{}.meta.json", hash))
    }

    /// Get a reference to the singleflight instance.
    pub fn singleflight(&self) -> &Arc<SingleFlight> {
        &self.singleflight
    }

    /// Get a reference to the stats.
    pub fn stats_ref(&self) -> &Arc<RwLock<CacheStats>> {
        &self.stats
    }
}

impl CacheStore for DiskCache {
    async fn lookup(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
        let body_path = self.body_path(key);
        let meta_path = self.meta_path(key);

        // Check if both files exist (use async try_exists to avoid blocking)
        if !tokio::fs::try_exists(&body_path).await.unwrap_or(false)
            || !tokio::fs::try_exists(&meta_path).await.unwrap_or(false)
        {
            let mut s = self.stats.write().await;
            s.miss_count += 1;
            return Ok(None);
        }

        // Read metadata only (small JSON file)
        let meta_bytes =
            tokio::fs::read(&meta_path)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "read metadata".into(),
                })?;
        let mut meta: CacheMeta =
            serde_json::from_slice(&meta_bytes).map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "parse metadata".into(),
            })?;

        // Update access metadata (best-effort)
        meta.last_accessed_at = chrono::Utc::now();
        meta.hit_count += 1;
        if let Ok(updated_json) = serde_json::to_vec_pretty(&meta) {
            let _ = tokio::fs::write(&meta_path, &updated_json).await;
        }

        // Update stats
        {
            let mut s = self.stats.write().await;
            s.hit_count += 1;
        }

        Ok(Some(CacheEntry { meta, body_path }))
    }

    async fn begin_fill(&self, key: &CacheKey) -> Result<FillGuard, ProxyError> {
        let temp_dir = self.cache_dir.join("tmp");
        Ok(FillGuard {
            key: key.clone(),
            temp_dir,
        })
    }

    async fn commit_fill(
        &self,
        guard: FillGuard,
        temp_body_path: PathBuf,
        meta: CacheMeta,
    ) -> Result<(), ProxyError> {
        let id = uuid::Uuid::new_v4();

        // The body file has already been written and fsynced by the caller.
        // Get its size for stats.
        let body_size = tokio::fs::metadata(&temp_body_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);

        // Write metadata to temp file
        let temp_meta = guard.temp_dir.join(format!("{}.meta.json", id));
        let meta_bytes = serde_json::to_vec_pretty(&meta).map_err(|e| ProxyError::Cache {
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
        let final_body = self.body_path(&guard.key);
        let final_meta = self.meta_path(&guard.key);
        if let Some(parent) = final_body.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "create object dir".into(),
                })?;
        }

        // Atomic rename
        tokio::fs::rename(&temp_body_path, &final_body)
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "rename body".into(),
            })?;
        tokio::fs::rename(&temp_meta, &final_meta)
            .await
            .map_err(|e| ProxyError::Cache {
                source: Box::new(e),
                operation: "rename metadata".into(),
            })?;

        // Update stats
        {
            let mut s = self.stats.write().await;
            s.entry_count += 1;
            s.total_bytes += body_size + meta_bytes.len() as u64;
            s.fill_count += 1;
        }

        Ok(())
    }

    async fn purge(&self, key: &CacheKey) -> Result<bool, ProxyError> {
        let body_path = self.body_path(key);
        let meta_path = self.meta_path(key);

        if !body_path.exists() && !meta_path.exists() {
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
        if body_path.exists() {
            tokio::fs::remove_file(&body_path)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "remove body".into(),
                })?;
            removed = true;
        }
        if meta_path.exists() {
            tokio::fs::remove_file(&meta_path)
                .await
                .map_err(|e| ProxyError::Cache {
                    source: Box::new(e),
                    operation: "remove metadata".into(),
                })?;
            removed = true;
        }

        if removed {
            let mut s = self.stats.write().await;
            s.entry_count = s.entry_count.saturating_sub(1);
            s.total_bytes = s.total_bytes.saturating_sub(body_size + meta_size);
        }

        Ok(removed)
    }

    async fn stats(&self) -> CacheStats {
        self.stats.read().await.clone()
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
        }
    }

    /// Helper: write body data to a temp file in the cache's tmp dir and return its path.
    async fn write_temp_body(cache_dir: &std::path::Path, data: &[u8]) -> PathBuf {
        let tmp_dir = cache_dir.join("tmp");
        let temp_path = tmp_dir.join(format!("{}.body", uuid::Uuid::new_v4()));
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
        // hit_count should be incremented
        assert_eq!(entry.meta.hit_count, 1);
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
        let hash = key.hash();
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
}
