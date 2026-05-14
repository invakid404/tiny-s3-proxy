//! Chunk-and-trailer signature verification for aws-chunked streaming
//! uploads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` / `-TRAILER`).
//!
//! The seed signature (the `Signature=` value in the inbound Authorization
//! header) and the derived `kSigning` are produced by the request-level
//! verifier in `mod.rs`; this module just chains forward from there:
//!
//! ```text
//!   chunk_n.signature = HMAC-SHA256(kSigning, string_to_sign_n)
//! ```
//!
//! where the string-to-sign for a payload chunk is
//!
//! ```text
//!   AWS4-HMAC-SHA256-PAYLOAD
//!   <amz-date>
//!   <credential-scope>
//!   <previous-signature-hex>
//!   <sha256-empty-hex>
//!   <sha256-current-chunk-data-hex>
//! ```
//!
//! and for the trailer chunk
//!
//! ```text
//!   AWS4-HMAC-SHA256-TRAILER
//!   <amz-date>
//!   <credential-scope>
//!   <previous-signature-hex>   (== final zero-chunk signature)
//!   sha256(canonical-trailer-bytes)
//! ```
//!
//! `previous_signature_hex` is the inbound seed signature on the first
//! chunk and is advanced to each verified payload chunk's signature
//! afterwards. The trailer signature is terminal and does NOT advance the
//! chain.

use super::VerifiedRequest;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// SHA-256 of empty input. AWS chunk string-to-sign hard-codes this for the
/// "empty hash" line per the streaming SigV4 spec.
pub const EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Per-request signing context for HMAC-SHA256 streaming uploads. Seeded
/// from a successfully [`VerifiedRequest`]; advances its
/// `previous_signature_hex` chain as each payload chunk verifies.
pub struct StreamingSigV4Context {
    signing_key: Zeroizing<[u8; 32]>,
    amz_date: String,
    scope: String,
    previous_signature_hex: String,
}

impl std::fmt::Debug for StreamingSigV4Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingSigV4Context")
            .field("amz_date", &self.amz_date)
            .field("scope", &self.scope)
            .field("previous_signature_hex", &self.previous_signature_hex)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StreamingSigV4Error {
    #[error("chunk signature mismatch")]
    ChunkSignatureMismatch,
    #[error("trailer signature mismatch")]
    TrailerSignatureMismatch,
    #[error("invalid signature hex: {0}")]
    InvalidSignatureHex(String),
}

impl StreamingSigV4Context {
    /// Seed a streaming context from the request-level verification result.
    /// The seed signature for the first chunk is the request's own signature
    /// (`request_signature_hex`); subsequent chunks chain forward from there.
    ///
    /// Returns `None` for SigV4A requests; their per-chunk verification
    /// uses ECDSA, not HMAC, and is built by
    /// [`crate::auth::sigv4a::streaming::StreamingSigV4aContext::from_verified`]
    /// instead (added in a follow-up commit).
    pub fn from_verified(verified: &VerifiedRequest) -> Option<Self> {
        let signing_key = verified.hmac_signing_key()?;
        Some(Self {
            signing_key: signing_key.clone_bytes(),
            amz_date: verified.amz_date.clone(),
            scope: verified.credential_scope.credential_scope_string(),
            previous_signature_hex: verified.request_signature_hex.clone(),
        })
    }

    /// Testing seam: build a context from raw inputs. Production callers
    /// should use [`StreamingSigV4Context::from_verified`] so the seed
    /// signature and signing key always come from a successfully verified
    /// request.
    #[cfg(test)]
    pub(crate) fn from_parts(
        signing_key_bytes: [u8; 32],
        amz_date: impl Into<String>,
        scope: impl Into<String>,
        seed_signature_hex: impl Into<String>,
    ) -> Self {
        Self {
            signing_key: Zeroizing::new(signing_key_bytes),
            amz_date: amz_date.into(),
            scope: scope.into(),
            previous_signature_hex: seed_signature_hex.into(),
        }
    }

    pub fn previous_signature_hex(&self) -> &str {
        &self.previous_signature_hex
    }

    /// Verify a single payload chunk signature against the chained HMAC.
    /// `chunk_sha256_hex` is the SHA-256 of the chunk payload bytes (use
    /// [`EMPTY_SHA256_HEX`] for the zero-byte terminator chunk). On success,
    /// advances `previous_signature_hex` to the supplied signature so the
    /// next chunk's chain is correctly seeded.
    pub fn verify_payload_chunk(
        &mut self,
        chunk_sha256_hex: &str,
        supplied_signature_hex: &str,
    ) -> Result<(), StreamingSigV4Error> {
        let supplied_bytes = parse_hex32(supplied_signature_hex).ok_or_else(|| {
            StreamingSigV4Error::InvalidSignatureHex(supplied_signature_hex.into())
        })?;

        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.amz_date,
            self.scope,
            self.previous_signature_hex,
            EMPTY_SHA256_HEX,
            chunk_sha256_hex,
        );
        let computed = hmac_sha256(&self.signing_key[..], sts.as_bytes());

        if computed.ct_eq(&supplied_bytes).unwrap_u8() != 1 {
            return Err(StreamingSigV4Error::ChunkSignatureMismatch);
        }

        // Advance the chain only on a verified chunk — never on a mismatch.
        self.previous_signature_hex = supplied_signature_hex.to_string();
        Ok(())
    }

    /// Verify the trailer signature line on a signed-trailer upload. The
    /// canonical trailer bytes are `<lowercased-name>:<value>\n` per the AWS
    /// docs (the `x-amz-trailer-signature` line itself is NOT included).
    /// Does NOT advance `previous_signature_hex`: the trailer is terminal.
    pub fn verify_trailer(
        &self,
        canonical_trailer_bytes: &[u8],
        supplied_signature_hex: &str,
    ) -> Result<(), StreamingSigV4Error> {
        let supplied_bytes = parse_hex32(supplied_signature_hex).ok_or_else(|| {
            StreamingSigV4Error::InvalidSignatureHex(supplied_signature_hex.into())
        })?;

        let mut hasher = Sha256::new();
        hasher.update(canonical_trailer_bytes);
        let trailer_hash_hex = hex_lower(&hasher.finalize());

        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.amz_date, self.scope, self.previous_signature_hex, trailer_hash_hex,
        );
        let computed = hmac_sha256(&self.signing_key[..], sts.as_bytes());

        if computed.ct_eq(&supplied_bytes).unwrap_u8() != 1 {
            return Err(StreamingSigV4Error::TrailerSignatureMismatch);
        }
        Ok(())
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signing key derived from the AWS S3 streaming docs example
    /// credentials: AKID `AKIAIOSFODNN7EXAMPLE`, secret
    /// `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, date `20130524`, region
    /// `us-east-1`, service `s3`. With this exact secret the documented
    /// AWS streaming seed/chunk/trailer signatures reproduce bit-for-bit
    /// — see the vectors below. Note the SLASH before `bPx`; the
    /// ubiquitous EC2-example secret has a PLUS there instead, and feeding
    /// that secret into the streaming math reproduces NEITHER the
    /// published seed nor any of the published chunk signatures.
    /// References:
    /// - <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html>
    /// - <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html>
    fn example_signing_key() -> [u8; 32] {
        use hmac::{Hmac, KeyInit, Mac};
        type HmacSha256 = Hmac<Sha256>;
        fn h(k: &[u8], d: &[u8]) -> Vec<u8> {
            let mut m = HmacSha256::new_from_slice(k).unwrap();
            m.update(d);
            m.finalize().into_bytes().to_vec()
        }
        let k_date = h(b"AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", b"20130524");
        let k_region = h(&k_date, b"us-east-1");
        let k_service = h(&k_region, b"s3");
        let k_signing = h(&k_service, b"aws4_request");
        let mut out = [0u8; 32];
        out.copy_from_slice(&k_signing);
        out
    }

    fn example_ctx(seed_sig_hex: &str) -> StreamingSigV4Context {
        StreamingSigV4Context::from_parts(
            example_signing_key(),
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
            seed_sig_hex,
        )
    }

    // ---- AWS-published reference vectors ----
    //
    // Non-trailer mode (sigv4-streaming.html, 64KB+1KB+0 chunks of 'a'):
    //   seed:       4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9
    //   chunk 1:    ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648
    //   chunk 2:    0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497
    //   zero chunk: b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9
    //
    // Trailer mode (sigv4-streaming-trailers.html, same chunks + CRC32C
    //  trailer `sOO8/Q==`):
    //   seed:       106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e
    //   chunk 1:    b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2
    //   chunk 2:    1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7
    //   zero chunk: 2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992
    //   trailer:    d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435

    /// AWS reference non-trailer chunk 1: 65536 'a' bytes chained from
    /// the documented non-trailer seed signature.
    #[test]
    fn test_payload_chunk_signature_aws_vector_1() {
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let mut ctx = example_ctx(seed);
        // SHA-256 of 65536 'a' bytes (from AWS streaming docs).
        let chunk_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        let expected = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";
        ctx.verify_payload_chunk(chunk_sha, expected)
            .expect("AWS-published non-trailer chunk 1 signature must verify");
        assert_eq!(ctx.previous_signature_hex(), expected);
    }

    /// AWS reference non-trailer chunk 2: 1024 'a' bytes chained from
    /// chunk 1's signature.
    #[test]
    fn test_payload_chunk_signature_aws_vector_2() {
        let prev = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";
        let mut ctx = example_ctx(prev);
        // SHA-256 of 1024 'a' bytes.
        let chunk_sha = "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a";
        let expected = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497";
        ctx.verify_payload_chunk(chunk_sha, expected)
            .expect("AWS-published non-trailer chunk 2 signature must verify");
    }

    /// AWS reference non-trailer zero chunk: empty payload chained from
    /// chunk 2's signature.
    #[test]
    fn test_zero_chunk_signature_with_aws_vector() {
        let prev = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497";
        let mut ctx = example_ctx(prev);
        let expected = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9";
        ctx.verify_payload_chunk(EMPTY_SHA256_HEX, expected)
            .expect("AWS-published non-trailer zero chunk signature must verify");
    }

    /// AWS reference trailer signature: the trailer canonical bytes are
    /// `x-amz-checksum-crc32c:sOO8/Q==\n` and the previous-signature is
    /// the trailer-mode zero-chunk signature `2ca2aba2…` (a different
    /// chain than the non-trailer one because the seed signature
    /// differs).
    #[test]
    fn test_trailer_signature_aws_vector() {
        let prev = "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992";
        let ctx = example_ctx(prev);
        let canonical = b"x-amz-checksum-crc32c:sOO8/Q==\n";
        let expected = "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435";
        ctx.verify_trailer(canonical, expected)
            .expect("AWS-published trailer signature must verify");
    }

    /// AWS reference trailer-mode chunk 1: the seed signature differs
    /// from the non-trailer chain (because the canonical request signs
    /// the trailer headers), so chunk 1's signature differs too.
    #[test]
    fn test_payload_chunk_signature_aws_trailer_vector_1() {
        let seed = "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e";
        let mut ctx = example_ctx(seed);
        let chunk_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        let expected = "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2";
        ctx.verify_payload_chunk(chunk_sha, expected)
            .expect("AWS-published trailer-mode chunk 1 signature must verify");
    }

    /// AWS reference trailer-mode zero chunk: chained through chunks 1
    /// and 2 of the trailer chain. Drives the full sequence so the test
    /// also covers chain advancement across all four signatures.
    #[test]
    fn test_zero_chunk_signature_aws_trailer_vector() {
        let seed = "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e";
        let mut ctx = example_ctx(seed);
        let chunk1_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        let chunk1_sig = "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2";
        let chunk2_sha = "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a";
        let chunk2_sig = "1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7";
        let zero_sig = "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992";
        ctx.verify_payload_chunk(chunk1_sha, chunk1_sig)
            .expect("trailer-mode chunk 1");
        ctx.verify_payload_chunk(chunk2_sha, chunk2_sig)
            .expect("trailer-mode chunk 2");
        ctx.verify_payload_chunk(EMPTY_SHA256_HEX, zero_sig)
            .expect("trailer-mode zero chunk");
    }

    /// A signature mismatch surfaces as `ChunkSignatureMismatch` and the
    /// chain stays pinned to the previous (verified) signature so a later
    /// chunk's chain stays consistent with the legitimate prefix.
    ///
    /// Bug-revert reasoning: advancing `previous_signature_hex` BEFORE the
    /// HMAC comparison (or unconditionally on the unhappy path) lets a
    /// tampered chunk poison the chain — the next legitimate chunk would
    /// then fail its own verify because its seed sig no longer chains. The
    /// `chain stays pinned` assertion catches this.
    #[test]
    fn test_chunk_signature_mismatch_returns_error() {
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let mut ctx = example_ctx(seed);
        let chunk_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        // Flip one hex digit of the correct AWS-published signature.
        let bad = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288649";
        let err = ctx
            .verify_payload_chunk(chunk_sha, bad)
            .expect_err("tampered chunk signature must error");
        assert!(matches!(err, StreamingSigV4Error::ChunkSignatureMismatch));
        // Chain MUST NOT have advanced to the bogus signature.
        assert_eq!(ctx.previous_signature_hex(), seed);
    }

    #[test]
    fn test_trailer_signature_mismatch_returns_error() {
        let prev = "2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992";
        let ctx = example_ctx(prev);
        let canonical = b"x-amz-checksum-crc32c:sOO8/Q==\n";
        let bad = "d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e434";
        let err = ctx
            .verify_trailer(canonical, bad)
            .expect_err("tampered trailer signature must error");
        assert!(matches!(err, StreamingSigV4Error::TrailerSignatureMismatch));
    }

    /// Non-hex / wrong-length signatures are caught before the HMAC is
    /// computed and surface as `InvalidSignatureHex`. Catching this BEFORE
    /// the comparison keeps a malformed input from looking like a chunk
    /// mismatch (which would be a misleading 403 SignatureDoesNotMatch in
    /// the wire) — clients should see InvalidRequest-shaped errors for
    /// shape problems.
    #[test]
    fn test_invalid_signature_hex_format() {
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let mut ctx = example_ctx(seed);
        let chunk_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";

        // Wrong length.
        let err = ctx.verify_payload_chunk(chunk_sha, "deadbeef").unwrap_err();
        assert!(matches!(err, StreamingSigV4Error::InvalidSignatureHex(_)));

        // Non-hex character.
        let bad = "z".to_string() + &"0".repeat(63);
        let err = ctx.verify_payload_chunk(chunk_sha, &bad).unwrap_err();
        assert!(matches!(err, StreamingSigV4Error::InvalidSignatureHex(_)));

        // Same for the trailer entry point.
        let err = ctx
            .verify_trailer(b"x-amz-checksum-crc32c:sOO8/Q==\n", "00")
            .unwrap_err();
        assert!(matches!(err, StreamingSigV4Error::InvalidSignatureHex(_)));
    }

    /// After a successful payload-chunk verify, the chain must advance so
    /// the next chunk's string-to-sign uses the just-verified signature
    /// as `previous-signature`. Drive two successive chunks and confirm
    /// chunk 2 only verifies once chunk 1 has advanced the chain.
    ///
    /// Bug-revert reasoning: failing to advance the chain (i.e. dropping
    /// `self.previous_signature_hex = ...` on the happy path) leaves
    /// chunk 2's STS computed against the seed signature instead of
    /// chunk 1's, and the HMAC diverges from the pinned `chunk2_sig`.
    #[test]
    fn test_chain_advances_on_success() {
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let mut ctx = example_ctx(seed);
        let chunk1_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        let chunk1_sig = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";
        let chunk2_sha = "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a";
        let chunk2_sig = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497";

        ctx.verify_payload_chunk(chunk1_sha, chunk1_sig)
            .expect("chunk 1 verifies");
        assert_eq!(ctx.previous_signature_hex(), chunk1_sig);
        ctx.verify_payload_chunk(chunk2_sha, chunk2_sig)
            .expect("chunk 2 verifies once the chain is advanced");
        assert_eq!(ctx.previous_signature_hex(), chunk2_sig);
    }
}
