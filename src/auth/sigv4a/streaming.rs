//! Chunk-and-trailer signature verification for SigV4A aws-chunked
//! streaming uploads (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD` /
//! `-TRAILER`).
//!
//! Mirrors [`crate::auth::sigv4::streaming::StreamingSigV4Context`] but
//! uses ECDSA-P256/SHA-256 instead of HMAC. The seed signature (the
//! `Signature=` value in the inbound Authorization header / the
//! `X-Amz-Signature` query param on a presigned URL) and the derived
//! `VerifyingKey` are produced by the request-level SigV4A verifier;
//! this module just chains forward.
//!
//! String-to-sign for a payload chunk:
//!
//! ```text
//!   AWS4-ECDSA-P256-SHA256-PAYLOAD
//!   <amz-date>
//!   <credential-scope>   ← `<yyyymmdd>/s3/aws4_request` (regionless)
//!   <previous-signature-hex>
//!   <sha256-empty-hex>
//!   <sha256-current-chunk-data-hex>
//! ```
//!
//! For the trailer:
//!
//! ```text
//!   AWS4-ECDSA-P256-SHA256-TRAILER
//!   <amz-date>
//!   <credential-scope>
//!   <previous-signature-hex>   (== final zero-chunk signature)
//!   sha256(canonical-trailer-bytes)
//! ```
//!
//! Two SigV4A-specific differences from HMAC streaming:
//!
//! - Chunk signatures are lowercase hex of a DER ECDSA P-256/SHA-256
//!   signature, variable length up to 144 hex chars, AWS CRT right-pads
//!   chunk / trailer signatures with `*` to that width. The padding is
//!   stripped before hex decoding and before being threaded into the
//!   next chunk's chain.
//! - Verification uses [`crate::auth::sigv4a::crypto::verify_sigv4a_der_signature`]
//!   instead of an HMAC compare.

use super::VerifiedRequest;
use super::crypto::{
    SigV4aVerifyingKey, parse_streaming_der_signature_hex_padded, verify_sigv4a_der_signature,
};
use sha2::{Digest, Sha256};

/// SHA-256 of empty input. Used as the "empty hash" line of every
/// payload-chunk string-to-sign per the SigV4A streaming spec.
pub const EMPTY_SHA256_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Per-request signing context for ECDSA-P256 streaming uploads. Seeded
/// from a successfully verified SigV4A request; advances its
/// `previous_signature_hex` as each payload chunk verifies.
pub struct StreamingSigV4aContext {
    verifying_key: SigV4aVerifyingKey,
    amz_date: String,
    scope: String,
    previous_signature_hex: String,
}

impl std::fmt::Debug for StreamingSigV4aContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingSigV4aContext")
            .field("amz_date", &self.amz_date)
            .field("scope", &self.scope)
            .field("previous_signature_hex", &self.previous_signature_hex)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StreamingSigV4aError {
    #[error("chunk signature mismatch")]
    ChunkSignatureMismatch,
    #[error("trailer signature mismatch")]
    TrailerSignatureMismatch,
    #[error("invalid SigV4A streaming signature hex: {0}")]
    InvalidSignatureHex(String),
}

impl StreamingSigV4aContext {
    /// Seed a streaming context from the request-level SigV4A
    /// verification result. The seed signature for the first chunk is
    /// the request's own signature; subsequent chunks chain from there.
    ///
    /// Returns `None` if `verified` isn't a SigV4A request — the caller
    /// (the aws-chunked policy selector) uses that to keep the HMAC and
    /// ECDSA streaming code paths symmetric, fail-closing if a context
    /// of the wrong type is requested.
    pub fn from_verified(verified: &VerifiedRequest) -> Option<Self> {
        let verifying_key = verified.sigv4a_verifying_key()?;
        Some(Self {
            verifying_key: verifying_key.clone(),
            amz_date: verified.amz_date.clone(),
            scope: verified.credential_scope.credential_scope_string(),
            previous_signature_hex: verified.request_signature_hex.clone(),
        })
    }

    /// Testing seam: build a context directly without going through a
    /// full SigV4A verify. Production callers should use
    /// [`StreamingSigV4aContext::from_verified`].
    #[cfg(test)]
    pub(crate) fn from_parts(
        verifying_key: SigV4aVerifyingKey,
        amz_date: impl Into<String>,
        scope: impl Into<String>,
        seed_signature_hex: impl Into<String>,
    ) -> Self {
        Self {
            verifying_key,
            amz_date: amz_date.into(),
            scope: scope.into(),
            previous_signature_hex: seed_signature_hex.into(),
        }
    }

    pub fn previous_signature_hex(&self) -> &str {
        &self.previous_signature_hex
    }

    /// Verify a single payload chunk signature.
    ///
    /// `chunk_sha256_hex` is the SHA-256 of the chunk payload bytes;
    /// `supplied_signature_hex_with_padding` is the raw value from the
    /// chunk header (which may carry trailing `*` padding from AWS
    /// CRT's fixed-width wire format). On success, advances
    /// `previous_signature_hex` to the **trimmed** supplied signature
    /// so the next chunk's chain is correctly seeded.
    pub fn verify_payload_chunk(
        &mut self,
        chunk_sha256_hex: &str,
        supplied_signature_hex_with_padding: &str,
    ) -> Result<(), StreamingSigV4aError> {
        let trimmed = supplied_signature_hex_with_padding.trim_end_matches('*');
        let signature_der = parse_streaming_der_signature_hex_padded(
            supplied_signature_hex_with_padding,
        )
        .map_err(|_| {
            StreamingSigV4aError::InvalidSignatureHex(
                supplied_signature_hex_with_padding.to_string(),
            )
        })?;
        let sts = format!(
            "AWS4-ECDSA-P256-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.amz_date,
            self.scope,
            self.previous_signature_hex,
            EMPTY_SHA256_HEX,
            chunk_sha256_hex,
        );
        verify_sigv4a_der_signature(&self.verifying_key, sts.as_bytes(), &signature_der)
            .map_err(|_| StreamingSigV4aError::ChunkSignatureMismatch)?;

        // Advance the chain only on a verified chunk; on the next
        // chunk's string-to-sign we use the trimmed (unpadded) value
        // so the chain shape is independent of the wire padding.
        self.previous_signature_hex = trimmed.to_string();
        Ok(())
    }

    /// Verify the trailer signature line on a signed-trailer upload.
    /// `canonical_trailer_bytes` are `<lowercased-name>:<value>\n` per
    /// the AWS spec (the `x-amz-trailer-signature` line is NOT
    /// included). Does not advance `previous_signature_hex`: the
    /// trailer is terminal.
    pub fn verify_trailer(
        &self,
        canonical_trailer_bytes: &[u8],
        supplied_signature_hex_with_padding: &str,
    ) -> Result<(), StreamingSigV4aError> {
        let signature_der = parse_streaming_der_signature_hex_padded(
            supplied_signature_hex_with_padding,
        )
        .map_err(|_| {
            StreamingSigV4aError::InvalidSignatureHex(
                supplied_signature_hex_with_padding.to_string(),
            )
        })?;
        let mut hasher = Sha256::new();
        hasher.update(canonical_trailer_bytes);
        let trailer_hash_hex = hex_lower(&hasher.finalize());

        let sts = format!(
            "AWS4-ECDSA-P256-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.amz_date, self.scope, self.previous_signature_hex, trailer_hash_hex,
        );
        verify_sigv4a_der_signature(&self.verifying_key, sts.as_bytes(), &signature_der)
            .map_err(|_| StreamingSigV4aError::TrailerSignatureMismatch)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sigv4a::crypto::{
        MAX_SIGV4A_DER_SIGNATURE_HEX_LEN, derive_sigv4a_verifying_key,
    };
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};

    const EXAMPLE_AKID: &str = "AKIDEXAMPLE";
    const EXAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    fn example_verifying_key() -> SigV4aVerifyingKey {
        derive_sigv4a_verifying_key(EXAMPLE_AKID, EXAMPLE_SECRET).expect("derives")
    }

    fn example_signing_key() -> SigningKey {
        let scalar = aws_sigv4::sign::v4a::generate_signing_key(EXAMPLE_AKID, EXAMPLE_SECRET);
        SigningKey::from_bytes(scalar.as_ref()).expect("signing key")
    }

    fn sign_chunk_payload(
        signing_key: &SigningKey,
        amz_date: &str,
        scope: &str,
        prev_sig: &str,
        chunk_sha256_hex: &str,
    ) -> String {
        let sts = format!(
            "AWS4-ECDSA-P256-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev_sig}\n{EMPTY_SHA256_HEX}\n{chunk_sha256_hex}"
        );
        let sig: Signature = signing_key.sign(sts.as_bytes());
        hex::encode(sig.to_der().as_ref())
    }

    fn sign_trailer(
        signing_key: &SigningKey,
        amz_date: &str,
        scope: &str,
        prev_sig: &str,
        canonical_trailer: &[u8],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(canonical_trailer);
        let trailer_hash_hex = hex_lower(&hasher.finalize());
        let sts = format!(
            "AWS4-ECDSA-P256-SHA256-TRAILER\n{amz_date}\n{scope}\n{prev_sig}\n{trailer_hash_hex}"
        );
        let sig: Signature = signing_key.sign(sts.as_bytes());
        hex::encode(sig.to_der().as_ref())
    }

    /// Round-trip happy path: sign two payload chunks + the zero chunk +
    /// a trailer using the same KDF + p256 pipeline AWS SDKs would, then
    /// verify the chain advances correctly.
    #[test]
    fn round_trip_two_chunks_zero_chunk_and_trailer() {
        let amz_date = "20260101T120000Z";
        let scope = "20260101/s3/aws4_request";
        let seed = "0".repeat(64);

        let signing_key = example_signing_key();
        let chunk1_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        let chunk1_sig = sign_chunk_payload(&signing_key, amz_date, scope, &seed, chunk1_sha);
        let chunk2_sha = "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a";
        let chunk2_sig = sign_chunk_payload(
            &signing_key,
            amz_date,
            scope,
            chunk1_sig.trim_end_matches('*'),
            chunk2_sha,
        );
        let zero_sig = sign_chunk_payload(
            &signing_key,
            amz_date,
            scope,
            chunk2_sig.trim_end_matches('*'),
            EMPTY_SHA256_HEX,
        );
        let canonical_trailer = b"x-amz-checksum-crc32c:sOO8/Q==\n";
        let trailer_sig = sign_trailer(&signing_key, amz_date, scope, &zero_sig, canonical_trailer);

        let vk = example_verifying_key();
        let mut ctx = StreamingSigV4aContext::from_parts(vk, amz_date, scope, &seed);

        ctx.verify_payload_chunk(chunk1_sha, &chunk1_sig)
            .expect("chunk 1 verifies");
        assert_eq!(ctx.previous_signature_hex(), chunk1_sig);
        ctx.verify_payload_chunk(chunk2_sha, &chunk2_sig)
            .expect("chunk 2 verifies once chain advanced");
        ctx.verify_payload_chunk(EMPTY_SHA256_HEX, &zero_sig)
            .expect("zero chunk verifies");
        ctx.verify_trailer(canonical_trailer, &trailer_sig)
            .expect("trailer verifies");
    }

    /// `*`-padded chunk signatures (the AWS CRT wire format) must
    /// verify and the chain must advance using the **trimmed** value
    /// so a second chunk signed against the unpadded previous-signature
    /// also verifies. Bug-revert reasoning: keeping the `*` padding on
    /// `previous_signature_hex` would make the next chunk's STS
    /// diverge from what the signer used, flipping this to
    /// `ChunkSignatureMismatch`.
    #[test]
    fn padded_chunk_signature_trims_before_advancing_chain() {
        let amz_date = "20260101T120000Z";
        let scope = "20260101/s3/aws4_request";
        let seed = "0".repeat(64);

        let signing_key = example_signing_key();
        let chunk_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        let chunk_sig = sign_chunk_payload(&signing_key, amz_date, scope, &seed, chunk_sha);
        let padded = format!(
            "{}{}",
            chunk_sig,
            "*".repeat(MAX_SIGV4A_DER_SIGNATURE_HEX_LEN - chunk_sig.len()),
        );

        let vk = example_verifying_key();
        let mut ctx = StreamingSigV4aContext::from_parts(vk, amz_date, scope, &seed);
        ctx.verify_payload_chunk(chunk_sha, &padded)
            .expect("padded verifies");
        assert_eq!(
            ctx.previous_signature_hex(),
            chunk_sig,
            "chain must hold the trimmed signature, not the padded form",
        );
    }

    /// A signature mismatch surfaces as `ChunkSignatureMismatch` and
    /// the chain stays pinned to the previous (verified) signature so
    /// a later chunk's chain stays consistent with the legitimate
    /// prefix.
    ///
    /// Bug-revert reasoning: advancing `previous_signature_hex` BEFORE
    /// the ECDSA verify (or unconditionally on the unhappy path) lets
    /// a tampered chunk poison the chain. The pinned `seed` assertion
    /// catches this.
    #[test]
    fn chunk_signature_mismatch_returns_error() {
        let amz_date = "20260101T120000Z";
        let scope = "20260101/s3/aws4_request";
        let seed = "0".repeat(64);

        // Sign chunk 1 correctly, then flip a hex digit so the
        // signature decodes as DER but doesn't verify.
        let signing_key = example_signing_key();
        let chunk_sha = "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a";
        let chunk_sig = sign_chunk_payload(&signing_key, amz_date, scope, &seed, chunk_sha);
        let mut tampered = chunk_sig.clone();
        let last = tampered.pop().unwrap();
        // Flip to a different lowercase hex digit so DER shape stays valid.
        tampered.push(if last == 'a' { 'b' } else { 'a' });

        let vk = example_verifying_key();
        let mut ctx = StreamingSigV4aContext::from_parts(vk, amz_date, scope, &seed);
        let err = ctx.verify_payload_chunk(chunk_sha, &tampered).unwrap_err();
        assert!(matches!(err, StreamingSigV4aError::ChunkSignatureMismatch));
        assert_eq!(ctx.previous_signature_hex(), seed);
    }
}
