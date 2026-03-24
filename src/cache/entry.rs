use std::path::PathBuf;

use super::metadata::CacheMeta;

/// A cache entry with metadata and a stable snapshot of the body file.
///
/// `body_file` is `Some` for pinned-body lookups (`lookup`, `peek_body`) so
/// the response streams the exact inode that matched the observed metadata,
/// even if another fill later replaces the path on disk. It is `None` for
/// metadata-only probes (`peek`); in that case `open_file_stream` reopens
/// via `body_path`.
pub struct CacheEntry {
    pub meta: CacheMeta,
    pub body_path: PathBuf,
    pub body_file: Option<tokio::fs::File>,
}

impl std::fmt::Debug for CacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheEntry")
            .field("meta", &self.meta)
            .field("body_path", &self.body_path)
            .field("body_file", &self.body_file.is_some())
            .finish()
    }
}
