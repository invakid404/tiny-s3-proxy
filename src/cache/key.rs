use ahash::AHasher;
use std::hash::{Hash, Hasher};

/// A cache key derived from bucket + object key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub bucket: String,
    pub object_key: String,
}

impl CacheKey {
    pub fn new(bucket: impl Into<String>, object_key: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            object_key: object_key.into(),
        }
    }

    /// Returns a hex-encoded hash for filesystem paths.
    /// Uses ahash (AES-NI accelerated) instead of SHA-256 for speed.
    ///
    /// # Stability
    /// ahash does not guarantee hash stability across library versions or platforms.
    /// `AHasher::default()` uses fixed (non-random) keys, so hashes are stable within
    /// a single binary build, but a dependency update could change the output. If that
    /// happens, existing cache entries become unreachable ("orphaned") — lookups and
    /// purges won't find them. This is safe because:
    /// - The eviction loop walks the filesystem directly (by `.meta.json` pattern),
    ///   so orphaned entries are still counted and evicted normally.
    /// - After one full eviction sweep the cache re-converges with no manual intervention.
    /// - The cache is ephemeral by design; data loss only means a temporary miss storm.
    ///
    /// If stronger durability guarantees are needed (e.g. surviving rolling upgrades
    /// without a cold-cache spike), replace ahash with a stable hash like SHA-256.
    pub fn hash_hex(&self) -> String {
        let mut hasher = AHasher::default();
        self.bucket.hash(&mut hasher);
        0u8.hash(&mut hasher); // null separator
        self.object_key.hash(&mut hasher);
        let h = hasher.finish();
        format!("{h:016x}")
    }

    /// Returns the two-level directory prefix (first 2 + next 2 hex chars).
    pub fn dir_prefix(&self) -> (String, String) {
        let h = self.hash_hex();
        (h[..2].to_string(), h[2..4].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_stability() {
        let key = CacheKey::new("my-bucket", "path/to/object.tar.gz");
        let hash1 = key.hash_hex();
        let hash2 = key.hash_hex();
        assert_eq!(hash1, hash2, "same input must produce same hash");
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let key1 = CacheKey::new("bucket-a", "key1");
        let key2 = CacheKey::new("bucket-a", "key2");
        let key3 = CacheKey::new("bucket-b", "key1");

        assert_ne!(
            key1.hash_hex(),
            key2.hash_hex(),
            "different keys should differ"
        );
        assert_ne!(
            key1.hash_hex(),
            key3.hash_hex(),
            "different buckets should differ"
        );
        assert_ne!(key2.hash_hex(), key3.hash_hex());
    }

    #[test]
    fn test_hash_is_hex_and_correct_length() {
        let key = CacheKey::new("b", "k");
        let h = key.hash_hex();
        // ahash u64 hex output is 16 chars.
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_dir_prefix_extracts_correct_chars() {
        let key = CacheKey::new("test-bucket", "some/key");
        let h = key.hash_hex();
        let (d1, d2) = key.dir_prefix();
        assert_eq!(d1, &h[..2]);
        assert_eq!(d2, &h[2..4]);
        assert_eq!(d1.len(), 2);
        assert_eq!(d2.len(), 2);
    }

    #[test]
    fn test_null_separator_prevents_collisions() {
        // "bucket\0" + "key" vs "bucket" + "\0key" should differ
        // because the null byte is always between bucket and key fields.
        let key1 = CacheKey::new("abc", "def");
        let key2 = CacheKey::new("abc\0", "def");
        // These should produce different hashes due to the extra null.
        assert_ne!(key1.hash_hex(), key2.hash_hex());
    }
}
