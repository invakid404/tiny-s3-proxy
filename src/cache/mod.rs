pub mod disk;
pub mod entry;
pub mod eviction;
pub mod key;
pub mod metadata;
pub mod policy;
pub mod singleflight;

use crate::error::ProxyError;
use entry::CacheEntry;
use key::CacheKey;
use metadata::CacheMeta;

pub use disk::DiskCache;
pub use singleflight::{FlightResult, FlightWaiter, SingleFlight};

/// Trait defining the cache storage interface.
pub trait CacheStore: Send + Sync {
    /// Look up a cached entry. Returns None on miss.
    fn lookup(&self, key: &CacheKey) -> impl std::future::Future<Output = Result<Option<CacheEntry>, ProxyError>> + Send;

    /// Begin filling a cache entry. Returns a FillGuard that must be committed or dropped.
    fn begin_fill(&self, key: &CacheKey) -> impl std::future::Future<Output = Result<FillGuard, ProxyError>> + Send;

    /// Commit a completed fill to the cache.
    fn commit_fill(
        &self,
        guard: FillGuard,
        data: Vec<u8>,
        meta: CacheMeta,
    ) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;

    /// Remove a cached entry.
    fn purge(&self, key: &CacheKey) -> impl std::future::Future<Output = Result<bool, ProxyError>> + Send;

    /// Get current cache statistics.
    fn stats(&self) -> impl std::future::Future<Output = CacheStats> + Send;
}

/// Guard returned by begin_fill. Holds the temp file path.
#[derive(Debug)]
pub struct FillGuard {
    pub key: CacheKey,
    pub temp_dir: std::path::PathBuf,
}

/// Cache statistics for metrics/admin.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub total_bytes: u64,
    pub entry_count: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub fill_count: u64,
    pub eviction_count: u64,
}
