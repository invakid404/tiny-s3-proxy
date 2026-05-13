//! Object-checksum algorithm catalogue used by the aws-chunked trailer decoder
//! and the typed-write backend path. Wraps `aws-smithy-checksums` so we have a
//! single place that knows the algorithm set we accept, the canonical header
//! names AWS uses for each, and the expected post-base64 digest length — all
//! load-bearing for trailer validation.

use aws_smithy_checksums as smithy;

/// The five trailer-checksum algorithms S3 advertises via `x-amz-trailer` /
/// `x-amz-checksum-*`. ECDSA-signed trailers are NOT a separate algorithm
/// here; ECDSA is a signing scheme, not a digest, and trailer streams that
/// use ECDSA still carry one of these five digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    Crc32,
    Crc32C,
    Crc64Nvme,
    Sha1,
    Sha256,
}

/// A validated `x-amz-checksum-*` header parsed from an inbound request. The
/// `value` is already base64-validated and has the expected decoded length for
/// the algorithm; downstream code can forward it byte-for-byte to the
/// upstream's per-algorithm SDK setter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChecksumHeader {
    pub algorithm: ChecksumAlgorithm,
    /// Canonical lowercase header name (e.g. `x-amz-checksum-crc32`).
    pub name: String,
    /// Base64-encoded checksum value, trimmed of surrounding whitespace.
    pub value: String,
}

impl ChecksumAlgorithm {
    /// Parse a header name like `x-amz-checksum-crc32` into the matching
    /// algorithm. Case-insensitive. Returns `None` for any name we don't
    /// understand, including the bare `x-amz-checksum-` prefix and unknown
    /// algorithm suffixes (`md5`, ECDSA, etc.).
    pub fn from_header_name(name: &str) -> Option<Self> {
        let suffix = name.strip_prefix_ignore_ascii_case("x-amz-checksum-")?;
        match suffix.to_ascii_lowercase().as_str() {
            "crc32" => Some(Self::Crc32),
            "crc32c" => Some(Self::Crc32C),
            "crc64nvme" => Some(Self::Crc64Nvme),
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }

    /// The canonical lowercase header name S3 uses for this algorithm. Stable
    /// — used both for parsing inbound requests and constructing outbound
    /// backend request headers.
    pub fn header_name(&self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32C => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
        }
    }

    /// Length in bytes of the raw (post-base64-decode) digest. Used to reject
    /// trailer values whose decoded length doesn't match the declared
    /// algorithm — guards against a base64-valid but algorithmically-wrong
    /// trailer being forwarded to upstream.
    pub fn digest_len(&self) -> usize {
        match self {
            Self::Crc32 | Self::Crc32C => 4,
            Self::Crc64Nvme => 8,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Construct a streaming checksum hasher backed by `aws-smithy-checksums`.
    /// Reused for trailer validation: feed decoded bytes via `Checksum::update`
    /// then compare `Checksum::finalize()` against the declared trailer value.
    pub fn into_smithy_impl(&self) -> Box<dyn smithy::http::HttpChecksum> {
        match self {
            Self::Crc32 => smithy::ChecksumAlgorithm::Crc32.into_impl(),
            Self::Crc32C => smithy::ChecksumAlgorithm::Crc32c.into_impl(),
            Self::Crc64Nvme => smithy::ChecksumAlgorithm::Crc64Nvme.into_impl(),
            Self::Sha1 => smithy::ChecksumAlgorithm::Sha1.into_impl(),
            Self::Sha256 => smithy::ChecksumAlgorithm::Sha256.into_impl(),
        }
    }
}

/// Case-insensitive `str::strip_prefix`. `str` itself doesn't expose one in
/// stable Rust, so we hand-roll the byte-level comparison rather than pay for
/// an upfront ASCII lowercasing of the whole input.
trait StrExt {
    fn strip_prefix_ignore_ascii_case<'a>(&'a self, prefix: &str) -> Option<&'a str>;
}

impl StrExt for str {
    fn strip_prefix_ignore_ascii_case<'a>(&'a self, prefix: &str) -> Option<&'a str> {
        if self.len() < prefix.len() {
            return None;
        }
        let (head, rest) = self.split_at(prefix.len());
        if head.eq_ignore_ascii_case(prefix) {
            Some(rest)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_header_name_round_trip() {
        for algo in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32C,
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumAlgorithm::Sha1,
            ChecksumAlgorithm::Sha256,
        ] {
            let name = algo.header_name();
            assert_eq!(
                ChecksumAlgorithm::from_header_name(name),
                Some(algo),
                "round-trip for {name}",
            );
        }
    }

    #[test]
    fn test_from_header_name_case_insensitive() {
        assert_eq!(
            ChecksumAlgorithm::from_header_name("X-AMZ-CHECKSUM-CRC32"),
            Some(ChecksumAlgorithm::Crc32),
        );
        assert_eq!(
            ChecksumAlgorithm::from_header_name("X-Amz-Checksum-Sha256"),
            Some(ChecksumAlgorithm::Sha256),
        );
        assert_eq!(
            ChecksumAlgorithm::from_header_name("x-AmZ-cHeCkSuM-CRC32C"),
            Some(ChecksumAlgorithm::Crc32C),
        );
    }

    #[test]
    fn test_from_header_name_rejects_unknown() {
        assert_eq!(
            ChecksumAlgorithm::from_header_name("x-amz-checksum-md5"),
            None
        );
        assert_eq!(ChecksumAlgorithm::from_header_name("x-amz-checksum-"), None);
        assert_eq!(ChecksumAlgorithm::from_header_name("x-amz-checksum"), None);
        assert_eq!(ChecksumAlgorithm::from_header_name("content-md5"), None);
        assert_eq!(ChecksumAlgorithm::from_header_name(""), None);
    }

    #[test]
    fn test_digest_len_per_algorithm() {
        assert_eq!(ChecksumAlgorithm::Crc32.digest_len(), 4);
        assert_eq!(ChecksumAlgorithm::Crc32C.digest_len(), 4);
        assert_eq!(ChecksumAlgorithm::Crc64Nvme.digest_len(), 8);
        assert_eq!(ChecksumAlgorithm::Sha1.digest_len(), 20);
        assert_eq!(ChecksumAlgorithm::Sha256.digest_len(), 32);
    }

    /// Confirms `into_smithy_impl` returns a hasher whose `finalize()` produces
    /// a `Bytes` whose length matches `digest_len()`. Catches an algorithm
    /// being routed to the wrong smithy variant.
    #[test]
    fn test_into_smithy_impl_size_matches_digest_len() {
        for algo in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32C,
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumAlgorithm::Sha1,
            ChecksumAlgorithm::Sha256,
        ] {
            let mut hasher = algo.into_smithy_impl();
            // Empty input — we only care about output length, not value.
            aws_smithy_checksums::Checksum::update(hasher.as_mut(), b"");
            let bytes = aws_smithy_checksums::Checksum::finalize(hasher);
            assert_eq!(
                bytes.len(),
                algo.digest_len(),
                "smithy hasher for {algo:?} produced {} bytes, expected {}",
                bytes.len(),
                algo.digest_len(),
            );
        }
    }
}
