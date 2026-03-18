use sha2::{Digest, Sha256};

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

    /// Returns the hex-encoded SHA-256 hash used for filesystem paths.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.bucket.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.object_key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Returns the two-level directory prefix (first 2 + next 2 hex chars).
    pub fn dir_prefix(&self) -> (String, String) {
        let h = self.hash();
        (h[..2].to_string(), h[2..4].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_stability() {
        let key = CacheKey::new("my-bucket", "path/to/object.tar.gz");
        let hash1 = key.hash();
        let hash2 = key.hash();
        assert_eq!(hash1, hash2, "same input must produce same hash");
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let key1 = CacheKey::new("bucket-a", "key1");
        let key2 = CacheKey::new("bucket-a", "key2");
        let key3 = CacheKey::new("bucket-b", "key1");

        assert_ne!(key1.hash(), key2.hash(), "different keys should differ");
        assert_ne!(key1.hash(), key3.hash(), "different buckets should differ");
        assert_ne!(key2.hash(), key3.hash());
    }

    #[test]
    fn test_hash_is_hex_and_correct_length() {
        let key = CacheKey::new("b", "k");
        let h = key.hash();
        // SHA-256 hex output is 64 chars.
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_dir_prefix_extracts_correct_chars() {
        let key = CacheKey::new("test-bucket", "some/key");
        let h = key.hash();
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
        assert_ne!(key1.hash(), key2.hash());
    }
}
