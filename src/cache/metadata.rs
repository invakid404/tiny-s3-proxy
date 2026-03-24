use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata stored alongside a cached object body.
///
/// Fields added after the initial schema use `#[serde(default)]` so older
/// JSON files deserialize without error — missing keys get their type's
/// default value. This is sufficient for forward compatibility because the
/// project has no production deployments with older cache formats; there is
/// no legacy data on disk that would need an active migration step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    pub bucket: String,
    pub key: String,
    pub etag: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
    pub content_type: Option<String>,
    pub content_length: i64,
    pub cache_written_at: DateTime<Utc>,
    /// Monotonic per-fill generation token. Each fresh `commit_fill()` assigns
    /// a globally unique counter value so conditional operations
    /// (`purge_if_unchanged`, `poison_if_unchanged`, `update_metadata_if_unchanged`)
    /// can safely distinguish entries even when `cache_written_at` collides
    /// due to clock resolution.
    #[serde(default)]
    pub fill_id: u64,
    #[serde(default)]
    pub metadata_version: u64,
    pub last_accessed_at: DateTime<Utc>,
    /// Deprecated: per-entry hit count is never incremented. Retained for
    /// struct-literal compatibility; the global `CacheStats.hit_count` is the
    /// authoritative counter.
    #[serde(default)]
    pub hit_count: u64,
    pub source_status: u16,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
    #[serde(default)]
    pub head_extra_headers: HashMap<String, String>,
    #[serde(default)]
    pub head_checksum_headers: HashMap<String, String>,
    /// True once this object version has cached shared checksum headers that
    /// are safe to reuse for checksum-mode GET responses.
    ///
    /// This intentionally tracks the shared GET/HEAD response surface only.
    /// A checksum-mode HEAD can still be incomplete for cached checksum HEAD
    /// replay if HEAD-only checksum metadata has not been fetched yet.
    #[serde(default)]
    pub checksum_mode_checked: bool,
    /// True once the HEAD-only response surface has been fetched for this
    /// object version, allowing cached HEAD responses to preserve headers not
    /// present on GET.
    #[serde(default)]
    pub head_metadata_checked: bool,
    /// True once the checksum-mode HEAD response surface has been fetched for
    /// this object version, allowing cached checksum HEAD responses to match
    /// what the backend HEAD returned even when that differs from GET.
    ///
    /// This is kept separate from `checksum_mode_checked` on purpose: a cached
    /// GET may be safe to replay with checksum headers even when a cached HEAD
    /// still lacks HEAD-specific checksum metadata, and vice versa.
    #[serde(default)]
    pub head_checksum_checked: bool,
}

#[cfg(test)]
mod tests {
    use super::CacheMeta;

    #[test]
    fn deserialize_legacy_metadata_defaults_new_fields() {
        let meta: CacheMeta = serde_json::from_str(
            r#"{
                "bucket": "bucket",
                "key": "script_bundle/app.js",
                "etag": "\"etag\"",
                "last_modified": null,
                "content_type": "application/javascript",
                "content_length": 42,
                "cache_written_at": "2026-03-23T00:00:00Z",
                "last_accessed_at": "2026-03-23T00:00:00Z",
                "source_status": 200
            }"#,
        )
        .unwrap();

        assert_eq!(meta.fill_id, 0);
        assert_eq!(meta.metadata_version, 0);
        assert!(meta.metadata.is_empty());
        assert!(meta.extra_headers.is_empty());
        assert!(meta.head_extra_headers.is_empty());
        assert!(meta.head_checksum_headers.is_empty());
        assert!(!meta.checksum_mode_checked);
        assert!(!meta.head_metadata_checked);
        assert!(!meta.head_checksum_checked);
    }
}
