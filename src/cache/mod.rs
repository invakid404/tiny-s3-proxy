pub mod disk;
pub mod entry;
pub mod eviction;
pub mod key;
pub mod metadata;
pub mod policy;
pub mod singleflight;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// `temp_body_path` is a fully-written temp file that will be renamed into the cache.
    fn commit_fill(
        &self,
        guard: FillGuard,
        temp_body_path: PathBuf,
        meta: CacheMeta,
    ) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;

    /// Abandon a fill without committing. Cleans up internal tracking state.
    /// Must be called if a FillGuard from begin_fill is not passed to commit_fill.
    fn abort_fill(&self, guard: FillGuard) -> impl std::future::Future<Output = ()> + Send;

    /// Remove a cached entry.
    fn purge(&self, key: &CacheKey) -> impl std::future::Future<Output = Result<bool, ProxyError>> + Send;

    /// Get current cache statistics snapshot.
    fn stats(&self) -> impl std::future::Future<Output = CacheStatsSnapshot> + Send;
}

/// Guard returned by begin_fill. Holds the temp file path.
#[derive(Debug)]
pub struct FillGuard {
    pub key: CacheKey,
    pub temp_dir: std::path::PathBuf,
    /// Generation counter captured at begin_fill time. If the generation
    /// has changed by commit_fill, the fill is rejected (a purge happened).
    pub generation: u64,
}

/// Cache statistics for metrics/admin, using atomics for lock-free updates.
#[derive(Debug)]
pub struct CacheStats {
    pub total_bytes: AtomicU64,
    pub entry_count: AtomicU64,
    pub hit_count: AtomicU64,
    pub miss_count: AtomicU64,
    pub fill_count: AtomicU64,
    pub eviction_count: AtomicU64,
}

impl Default for CacheStats {
    fn default() -> Self {
        Self {
            total_bytes: AtomicU64::new(0),
            entry_count: AtomicU64::new(0),
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
            fill_count: AtomicU64::new(0),
            eviction_count: AtomicU64::new(0),
        }
    }
}

impl CacheStats {
    /// Snapshot the current stats into a plain struct for reporting.
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            total_bytes: self.total_bytes.load(Ordering::Relaxed),
            entry_count: self.entry_count.load(Ordering::Relaxed),
            hit_count: self.hit_count.load(Ordering::Relaxed),
            miss_count: self.miss_count.load(Ordering::Relaxed),
            fill_count: self.fill_count.load(Ordering::Relaxed),
            eviction_count: self.eviction_count.load(Ordering::Relaxed),
        }
    }
}

/// Cloneable snapshot of cache statistics for reporting.
#[derive(Debug, Clone, Default)]
pub struct CacheStatsSnapshot {
    pub total_bytes: u64,
    pub entry_count: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub fill_count: u64,
    pub eviction_count: u64,
}
