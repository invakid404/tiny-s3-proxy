use super::metadata::CacheMeta;

/// A cache entry combining metadata and body data.
#[derive(Debug)]
pub struct CacheEntry {
    pub meta: CacheMeta,
    pub body: Vec<u8>,
}
