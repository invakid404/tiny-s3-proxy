use std::path::PathBuf;

use super::metadata::CacheMeta;

/// A cache entry with metadata and a path to the body file on disk.
#[derive(Debug)]
pub struct CacheEntry {
    pub meta: CacheMeta,
    pub body_path: PathBuf,
}
