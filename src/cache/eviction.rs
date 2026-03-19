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
    last_accessed_at: chrono::DateTime<chrono::Utc>,
    size: u64,
}

/// Run the eviction loop as a background task.
///
/// Periodically scans the cache directory and evicts the least-recently-accessed
/// entries when the total cache size exceeds `max_bytes`.
pub async fn run_eviction_loop(
    cache_dir: PathBuf,
    max_bytes: u64,
    interval_secs: u64,
    stats: Arc<CacheStats>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        if let Err(e) = run_eviction_pass(&cache_dir, max_bytes, &stats).await {
            tracing::warn!(error = %e, "eviction pass failed");
        }
    }
}

/// Walk the objects directory and collect all cache entries as eviction candidates.
async fn collect_candidates(
    objects_dir: &std::path::Path,
) -> Result<Vec<EvictionCandidate>, Box<dyn std::error::Error + Send + Sync>> {
    let mut candidates = Vec::new();

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
                    // Clean up orphan .body files: body exists but no matching metadata.
                    // This can happen if the hash algorithm changes across builds or if
                    // the process crashed between body and metadata writes in commit_fill.
                    if file_name.ends_with(".body") {
                        let hash = file_name.trim_end_matches(".body");
                        let meta_path = d2_path.join(format!("{}.meta.json", hash));
                        if !tokio::fs::try_exists(&meta_path).await.unwrap_or(true) {
                            let size = tokio::fs::metadata(&file_path).await.map(|m| m.len()).unwrap_or(0);
                            let _ = tokio::fs::remove_file(&file_path).await;
                            tracing::debug!(
                                path = %file_path.display(),
                                size,
                                "removed orphan body file (no matching metadata)"
                            );
                        }
                    }
                    continue;
                }

                // Read and parse metadata
                let meta_bytes = match tokio::fs::read(&file_path).await {
                    Ok(b) => b,
                    Err(_) => continue, // skip unreadable files
                };
                let meta: CacheMeta = match serde_json::from_slice(&meta_bytes) {
                    Ok(m) => m,
                    Err(_) => continue, // skip unparseable metadata
                };

                // Derive body path from meta path
                let hash = file_name.trim_end_matches(".meta.json");
                let body_path = d2_path.join(format!("{}.body", hash));

                // Get body file size
                let body_size = match tokio::fs::metadata(&body_path).await {
                    Ok(m) => m.len(),
                    Err(_) => {
                        // Body file missing; clean up orphaned metadata
                        let _ = tokio::fs::remove_file(&file_path).await;
                        continue;
                    }
                };

                // Include metadata file size in total
                let meta_size = meta_bytes.len() as u64;

                candidates.push(EvictionCandidate {
                    body_path,
                    meta_path: file_path,
                    last_accessed_at: meta.last_accessed_at,
                    size: body_size + meta_size,
                });
            }
        }
    }

    Ok(candidates)
}

/// Single eviction pass: scan cache, sort by LRU, evict until under limit.
pub async fn run_eviction_pass(
    cache_dir: &std::path::Path,
    max_bytes: u64,
    stats: &Arc<CacheStats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let objects_dir = cache_dir.join("objects");
    if !tokio::fs::try_exists(&objects_dir).await.unwrap_or(false) {
        return Ok(());
    }

    let mut candidates = collect_candidates(&objects_dir).await?;

    // Sort by last_accessed_at ascending (oldest first = evicted first)
    candidates.sort_by_key(|c| c.last_accessed_at);

    // Calculate current total size
    let total_size: u64 = candidates.iter().map(|c| c.size).sum();

    if total_size <= max_bytes {
        // Update stats with accurate count from disk scan
        stats.total_bytes.store(total_size, Ordering::Relaxed);
        stats.entry_count.store(candidates.len() as u64, Ordering::Relaxed);
        return Ok(());
    }

    // Evict oldest entries until under limit
    let mut current_size = total_size;
    let mut evicted = 0u64;
    for candidate in &candidates {
        if current_size <= max_bytes {
            break;
        }
        let body_removed = tokio::fs::remove_file(&candidate.body_path).await.is_ok();
        let meta_removed = tokio::fs::remove_file(&candidate.meta_path).await.is_ok();
        if body_removed && meta_removed {
            current_size -= candidate.size;
            evicted += 1;
            tracing::debug!(
                path = %candidate.body_path.display(),
                size = candidate.size,
                "evicted cache entry"
            );
        } else {
            tracing::warn!(
                path = %candidate.body_path.display(),
                body_removed,
                meta_removed,
                "eviction: partial removal, skipping size accounting"
            );
        }
    }

    // Update stats atomically
    stats.total_bytes.store(current_size, Ordering::Relaxed);
    stats.entry_count.store(candidates.len() as u64 - evicted, Ordering::Relaxed);
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
            last_accessed_at,
            hit_count: 0,
            source_status: 200,
            metadata: std::collections::HashMap::new(),
            extra_headers: std::collections::HashMap::new(),
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

        // Set limit very high
        run_eviction_pass(&cache_dir, 1_000_000, &stats).await.unwrap();

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
        assert_eq!(snap.entry_count, 1);
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

        let stats = Arc::new(CacheStats::default());

        // Set limit so only ~1 entry fits (body + meta ~= 1200 bytes each, so ~1500 is one entry)
        run_eviction_pass(&cache_dir, 1500, &stats).await.unwrap();

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

    #[tokio::test]
    async fn test_eviction_on_empty_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().to_path_buf();
        // Don't even create the objects dir
        let stats = Arc::new(CacheStats::default());

        // Should not error
        let result = run_eviction_pass(&cache_dir, 1000, &stats).await;
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

        let result = run_eviction_pass(&cache_dir, 1000, &stats).await;
        assert!(result.is_ok());

        let snap = stats.snapshot();
        assert_eq!(snap.entry_count, 0);
        assert_eq!(snap.total_bytes, 0);
    }
}
