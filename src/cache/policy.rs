/// Determines whether a given object key is cacheable based on configured prefixes.
#[derive(Debug, Clone)]
pub struct CachePolicy {
    pub cacheable_prefixes: Vec<String>,
    pub max_object_bytes: u64,
}

impl CachePolicy {
    pub fn new(prefixes: Vec<String>, max_object_bytes: u64) -> Self {
        Self {
            cacheable_prefixes: prefixes,
            max_object_bytes,
        }
    }

    /// Returns true if the object key matches a cacheable prefix.
    pub fn is_cacheable(&self, key: &str) -> bool {
        self.cacheable_prefixes.iter().any(|p| key.starts_with(p))
    }

    /// Returns true if the object size is within cache limits.
    pub fn is_size_cacheable(&self, size: u64) -> bool {
        size <= self.max_object_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> CachePolicy {
        CachePolicy::new(
            vec![
                "script_bundle/".to_string(),
                "bun_bundle/".to_string(),
                "tar/".to_string(),
            ],
            512 * 1024 * 1024, // 512 MB
        )
    }

    #[test]
    fn test_cacheable_prefix_match() {
        let policy = test_policy();
        assert!(policy.is_cacheable("script_bundle/v1/app.js"));
        assert!(policy.is_cacheable("bun_bundle/something"));
        assert!(policy.is_cacheable("tar/archive.tar.gz"));
    }

    #[test]
    fn test_non_cacheable_prefix() {
        let policy = test_policy();
        assert!(!policy.is_cacheable("logs/output.log"));
        assert!(!policy.is_cacheable("uploads/photo.jpg"));
        assert!(!policy.is_cacheable(""));
    }

    #[test]
    fn test_prefix_must_be_at_start() {
        let policy = test_policy();
        // "tar/" prefix should not match if it's in the middle.
        assert!(!policy.is_cacheable("some/tar/file"));
    }

    #[test]
    fn test_size_cacheable() {
        let policy = test_policy();
        assert!(policy.is_size_cacheable(0));
        assert!(policy.is_size_cacheable(100));
        assert!(policy.is_size_cacheable(512 * 1024 * 1024));
    }

    #[test]
    fn test_size_not_cacheable() {
        let policy = test_policy();
        assert!(!policy.is_size_cacheable(512 * 1024 * 1024 + 1));
        assert!(!policy.is_size_cacheable(u64::MAX));
    }

    #[test]
    fn test_empty_prefixes_nothing_cacheable() {
        let policy = CachePolicy::new(vec![], 1024);
        assert!(!policy.is_cacheable("anything"));
        assert!(!policy.is_cacheable("script_bundle/foo"));
    }
}
