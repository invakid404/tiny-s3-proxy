pub mod disk;
pub mod entry;
pub mod eviction;
pub mod key;
mod layout;
pub mod metadata;
pub(crate) mod perms;
pub mod policy;
mod scan;
pub mod singleflight;
mod tmp_sweep;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::ProxyError;
use entry::CacheEntry;
use key::CacheKey;
use metadata::CacheMeta;

pub use disk::DiskCache;
pub use singleflight::{FlightResult, FlightWaiter, SingleFlight};

/// Monotonic per-fill generation token. `FillId::ZERO` represents an
/// unassigned / legacy-missing / pre-commit placeholder; real committed fill
/// IDs start at `1`. `#[serde(transparent)]` preserves the on-disk JSON shape
/// from when the field was a raw `u64`, so existing `.meta.json` files keep
/// deserializing unchanged. Arithmetic stays explicit through `as_u64()` /
/// `FillId::from(...)` at counter boundaries (no `Add` / `Deref` impls).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct FillId(u64);

impl FillId {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for FillId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<FillId> for u64 {
    fn from(value: FillId) -> Self {
        value.0
    }
}

impl std::fmt::Display for FillId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Trait defining the cache storage interface.
pub trait CacheStore: Send + Sync {
    /// Look up a cached entry. Returns None on miss.
    /// Implementations may update hit/miss counters and access-time metadata.
    fn lookup(
        &self,
        key: &CacheKey,
    ) -> impl std::future::Future<Output = Result<Option<CacheEntry>, ProxyError>> + Send;

    /// Probe a cached entry without mutating hit/miss counters or access-time
    /// metadata. Use this when the caller is only checking whether the cached
    /// entry is semantically usable for the current request shape.
    fn peek(
        &self,
        key: &CacheKey,
    ) -> impl std::future::Future<Output = Result<Option<CacheEntry>, ProxyError>> + Send;

    /// Probe a cached entry without mutating hit/miss counters or access-time
    /// metadata, but still pin the body so callers can safely stream the same
    /// cached object version that matched the observed metadata.
    fn peek_body(
        &self,
        key: &CacheKey,
    ) -> impl std::future::Future<Output = Result<Option<CacheEntry>, ProxyError>> + Send;

    /// Record that a previously probed entry was served from cache.
    /// Implementations must use `meta.fill_id` as the identity fence when
    /// mutating per-entry access state, since a refill between the probe
    /// and this call can change the entry under the same key.
    fn note_hit(
        &self,
        key: &CacheKey,
        meta: &CacheMeta,
    ) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;

    /// Record that a cacheable read had to go upstream after probing the cache.
    fn note_miss(&self) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;

    /// Begin filling a cache entry. Returns a FillGuard that must be committed or dropped.
    fn begin_fill(
        &self,
        key: &CacheKey,
    ) -> impl std::future::Future<Output = Result<FillGuard, ProxyError>> + Send;

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

    /// Remove a cached entry. On success, implementations must also fence
    /// any older in-flight fills so they cannot republish the stale value
    /// via `commit_fill`. This ensures the entry stays invisible after
    /// purge returns.
    fn purge(
        &self,
        key: &CacheKey,
    ) -> impl std::future::Future<Output = Result<bool, ProxyError>> + Send;

    /// Remove a cached entry only if it still has the expected
    /// `fill_id` generation token observed by the caller.
    ///
    /// On success the stale entry becomes invisible to all future
    /// `peek` / `peek_body` / `lookup` calls, and any `FillGuard` that
    /// observed the old entry cannot later commit via `commit_fill`.
    fn purge_if_unchanged(
        &self,
        key: &CacheKey,
        expected_fill_id: FillId,
    ) -> impl std::future::Future<Output = Result<bool, ProxyError>> + Send;

    /// Mark a key as poisoned so lookup returns miss until the entry is
    /// successfully purged, evicted, or replaced by a successful `commit_fill`
    /// with a fresh generation (which clears the poison marker).
    ///
    /// Implementations must ensure that once poison succeeds, `peek`,
    /// `peek_body`, and `lookup` all return `None` for this key, and any
    /// in-flight `FillGuard` that observed the old entry is rejected by
    /// `commit_fill`. A successful `commit_fill` with a fresh generation
    /// clears the poison marker, making the new content visible.
    fn poison(
        &self,
        key: &CacheKey,
    ) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;

    /// Mark a key as poisoned only if the cached entry still has the expected
    /// `fill_id` generation token observed by the caller.
    ///
    /// On success the entry is invisible to future probes and any
    /// `FillGuard` from the old generation is rejected by `commit_fill`.
    fn poison_if_unchanged(
        &self,
        key: &CacheKey,
        expected_fill_id: FillId,
    ) -> impl std::future::Future<Output = Result<bool, ProxyError>> + Send;

    /// Update metadata for an existing cached entry when the stored entry
    /// still has the expected `fill_id` generation token **and** the stored
    /// `metadata_version` matches `meta.metadata_version`.
    ///
    /// On success the supplied `CacheMeta` becomes the authoritative
    /// snapshot: the store replaces the entry's metadata, extra headers,
    /// and head-specific header maps with the provided values. Only
    /// store-owned accounting fields (`cache_written_at`, `fill_id`,
    /// `last_accessed_at`, `hit_count`, `source_status`) and the bumped
    /// `metadata_version` are preserved from the prior entry.
    fn update_metadata_if_unchanged(
        &self,
        key: &CacheKey,
        expected_fill_id: FillId,
        meta: CacheMeta,
    ) -> impl std::future::Future<Output = Result<bool, ProxyError>> + Send;

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
///
/// ## Reconciliation model
///
/// `total_bytes` and `entry_count` follow a "periodic reconciliation" model:
/// - The eviction scan ([`eviction::run_eviction_loop`]) is the **source of
///   truth**: it walks the filesystem and overwrites these atomics with
///   authoritative values on every pass.
/// - Between scans, `commit_fill`, `purge`, and eviction deletions adjust
///   these fields incrementally for responsiveness, but concurrent operations
///   can cause transient drift.
/// - Any drift self-corrects on the next eviction scan.
///
/// This eliminates stat-accounting races that are impossible to fix with
/// lock-free incremental updates alone (e.g., eviction deleting a file that
/// `commit_fill` just replaced, or partial removal leaving stats carrying
/// sizes of deleted fragments).
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

#[cfg(test)]
mod tests {
    use super::FillId;

    /// Documents that `FillId` round-trips as a bare JSON number.
    /// Note: this does NOT specifically protect against removal of
    /// `#[serde(transparent)]` — serde_json already serializes tuple
    /// newtypes (`struct FillId(u64)`) as their inner value regardless.
    /// The on-disk invariant is pinned by the `CacheMeta` test in
    /// `metadata.rs`. This is documentation colocated with the type.
    #[test]
    fn fill_id_serde_round_trips_as_bare_number() {
        let fill_id: FillId = serde_json::from_str("123").unwrap();
        assert_eq!(fill_id, FillId::from(123));

        let json = serde_json::to_string(&fill_id).unwrap();
        assert_eq!(json, "123");
    }
}
