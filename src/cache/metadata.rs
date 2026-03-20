use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Metadata stored alongside a cached object body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    pub bucket: String,
    pub key: String,
    pub etag: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
    pub content_type: Option<String>,
    pub content_length: i64,
    pub cache_written_at: DateTime<Utc>,
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
}
