use std::fmt::Write;

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
    ///
    /// Uses SHA-256 (truncated to 128 bits / 32 hex chars) for collision
    /// resistance and unconditional stability across restarts, library
    /// upgrades, and platforms. The AWS SDK already depends on the `sha2`
    /// crate transitively, so this adds no new dependency weight.
    ///
    /// The input is `bucket + "\0" + object_key`, where the null byte
    /// prevents ambiguous concatenation (e.g. bucket "a" + key "bc" vs
    /// bucket "ab" + key "c").
    pub fn hash_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.bucket.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.object_key.as_bytes());
        let result = hasher.finalize();
        // Truncate to 128 bits (16 bytes / 32 hex chars) for shorter filenames.
        // Birthday bound is ~2^64 entries for 50% collision probability, far
        // beyond any realistic cache size. The metadata identity check in
        // lookup() provides additional defense in depth.
        let mut hex = String::with_capacity(32);
        for byte in &result[..16] {
            write!(hex, "{byte:02x}").unwrap();
        }
        hex
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
    fn test_hash_stable_across_calls() {
        // SHA-256 is deterministic — this is the fundamental guarantee.
        let key = CacheKey::new("test-bucket", "test-key");
        let h1 = key.hash_hex();
        let h2 = key.hash_hex();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let key1 = CacheKey::new("bucket-a", "key1");
        let key2 = CacheKey::new("bucket-a", "key2");
        let key3 = CacheKey::new("bucket-b", "key1");

        assert_ne!(key1.hash_hex(), key2.hash_hex(), "different keys should differ");
        assert_ne!(key1.hash_hex(), key3.hash_hex(), "different buckets should differ");
        assert_ne!(key2.hash_hex(), key3.hash_hex());
    }

    #[test]
    fn test_hash_is_hex_and_correct_length() {
        let key = CacheKey::new("b", "k");
        let h = key.hash_hex();
        // SHA-256 truncated to 128 bits = 32 hex chars
        assert_eq!(h.len(), 32);
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
        let key1 = CacheKey::new("abc", "def");
        let key2 = CacheKey::new("abc\0", "def");
        assert_ne!(key1.hash_hex(), key2.hash_hex());
    }
}
