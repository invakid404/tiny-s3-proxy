//! Classify the `x-amz-content-sha256` header for SigV4 strict verification.
//!
//! Five values land in the canonical request directly:
//! - a 64-char lowercase hex digest (the body's SHA-256)
//! - the sentinel `UNSIGNED-PAYLOAD`
//! - the sentinel `STREAMING-UNSIGNED-PAYLOAD-TRAILER`
//! - the sentinel `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
//! - the sentinel `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`
//!
//! HMAC-SHA256 streaming sentinels are verified chunk-by-chunk by the
//! aws-chunked decoder (`crate::auth::sigv4::streaming`), so the request-
//! level classifier surfaces them as their own variants rather than
//! demanding a buffered body hash.
//!
//! ECDSA streaming variants (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*`)
//! remain fail-closed: the inbound chunk signatures are bound to the
//! client's private key, so neither the proxy nor an upstream re-signer
//! could ever validate them. PR 5 of #63 will address that path.

use crate::s3::errors::S3Error;
use sha2::{Digest, Sha256};

/// What the canonical request's hashed-payload field should be, plus enough
/// context for downstream code to know whether the body still needs hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadHashForSigning {
    SignedSha256 {
        hex: String,
        bytes: [u8; 32],
    },
    UnsignedPayload,
    StreamingUnsignedPayloadTrailer,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` — signed chunks, no trailer.
    /// Per-chunk HMAC verification happens in the aws-chunked decoder.
    StreamingAws4HmacSha256Payload,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` — signed chunks plus a
    /// signed trailer. Per-chunk and trailer HMAC verification both happen
    /// in the aws-chunked decoder.
    StreamingAws4HmacSha256PayloadTrailer,
}

impl PayloadHashForSigning {
    /// String form that goes into the canonical request's hashed-payload line.
    pub fn canonical_string(&self) -> &str {
        match self {
            PayloadHashForSigning::SignedSha256 { hex, .. } => hex.as_str(),
            PayloadHashForSigning::UnsignedPayload => "UNSIGNED-PAYLOAD",
            PayloadHashForSigning::StreamingUnsignedPayloadTrailer => {
                "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
            }
            PayloadHashForSigning::StreamingAws4HmacSha256Payload => {
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
            }
            PayloadHashForSigning::StreamingAws4HmacSha256PayloadTrailer => {
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
            }
        }
    }

    /// Whether the verifier still needs to buffer the request body to
    /// confirm it matches the signed digest. False for HMAC streaming
    /// variants: the body never arrives as a single buffered SHA-256, it's
    /// validated frame-by-frame by the decoder.
    pub fn requires_body_bytes(&self) -> bool {
        matches!(self, PayloadHashForSigning::SignedSha256 { .. })
    }
}

pub fn classify_payload_header(
    value: &str,
    request_id: &str,
) -> Result<PayloadHashForSigning, S3Error> {
    if value == "UNSIGNED-PAYLOAD" {
        return Ok(PayloadHashForSigning::UnsignedPayload);
    }
    if value == "STREAMING-UNSIGNED-PAYLOAD-TRAILER" {
        return Ok(PayloadHashForSigning::StreamingUnsignedPayloadTrailer);
    }
    // HMAC-SHA256 streaming variants: verified chunk-by-chunk by the
    // aws-chunked decoder (see `crate::auth::sigv4::streaming`).
    if value == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
        return Ok(PayloadHashForSigning::StreamingAws4HmacSha256Payload);
    }
    if value == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" {
        return Ok(PayloadHashForSigning::StreamingAws4HmacSha256PayloadTrailer);
    }

    // ECDSA streaming variants are still fail-closed: the inbound chunk
    // signatures are bound to the client's private key, so neither the
    // proxy nor the upstream can validate them. PR 5 of issue #63 will
    // address that path.
    if value.starts_with("STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD") {
        return Err(S3Error::unsupported_signature(
            "ECDSA-signed aws-chunked streaming uploads are not supported in strict mode; \
             tracked in PR 5 of issue #63",
            request_id,
        ));
    }

    // Otherwise we expect a 64-char lowercase hex digest.
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hi = hex_nibble(value.as_bytes()[2 * i]).ok_or_else(|| {
                S3Error::authorization_header_malformed(
                    "x-amz-content-sha256 contains non-hex characters",
                    request_id,
                )
            })?;
            let lo = hex_nibble(value.as_bytes()[2 * i + 1]).ok_or_else(|| {
                S3Error::authorization_header_malformed(
                    "x-amz-content-sha256 contains non-hex characters",
                    request_id,
                )
            })?;
            *byte = (hi << 4) | lo;
        }
        return Ok(PayloadHashForSigning::SignedSha256 {
            hex: value.to_string(),
            bytes,
        });
    }

    Err(S3Error::authorization_header_malformed(
        "x-amz-content-sha256 is not a valid SHA-256 hex digest, UNSIGNED-PAYLOAD, or supported \
         streaming sentinel",
        request_id,
    ))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Confirm that the actual body bytes hash to the signed digest. Called only
/// after a request has been buffered and the parser returned
/// `SignedSha256`.
pub fn verify_payload_matches_hash(
    body_bytes: &[u8],
    expected_hex: &str,
    request_id: &str,
) -> Result<(), S3Error> {
    let mut hasher = Sha256::new();
    hasher.update(body_bytes);
    let digest = hasher.finalize();
    let actual_hex = hex_encode_32(&digest.into());
    if actual_hex != expected_hex {
        return Err(S3Error::signature_does_not_match(
            "x-amz-content-sha256 mismatch with actual body",
            request_id,
        ));
    }
    Ok(())
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid() -> &'static str {
        "req-test"
    }

    #[test]
    fn test_unsigned_payload_sentinel() {
        let p = classify_payload_header("UNSIGNED-PAYLOAD", rid()).unwrap();
        assert_eq!(p, PayloadHashForSigning::UnsignedPayload);
        assert!(!p.requires_body_bytes());
        assert_eq!(p.canonical_string(), "UNSIGNED-PAYLOAD");
    }

    #[test]
    fn test_streaming_unsigned_trailer_sentinel() {
        let p = classify_payload_header("STREAMING-UNSIGNED-PAYLOAD-TRAILER", rid()).unwrap();
        assert_eq!(p, PayloadHashForSigning::StreamingUnsignedPayloadTrailer);
        assert!(!p.requires_body_bytes());
    }

    #[test]
    fn test_signed_sha256_hex_classified() {
        let hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let p = classify_payload_header(hex, rid()).unwrap();
        match &p {
            PayloadHashForSigning::SignedSha256 { hex: h, bytes } => {
                assert_eq!(h, hex);
                assert_eq!(bytes[0], 0xe3);
                assert_eq!(bytes[31], 0x55);
            }
            other => panic!("expected SignedSha256, got {other:?}"),
        }
        assert!(p.requires_body_bytes());
    }

    #[test]
    fn test_streaming_hmac_sentinel_classified() {
        let p = classify_payload_header("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", rid())
            .expect("hmac streaming is now classified (verified by the decoder)");
        assert_eq!(p, PayloadHashForSigning::StreamingAws4HmacSha256Payload);
        // No buffered body hash — the decoder verifies chunk-by-chunk.
        assert!(!p.requires_body_bytes());
        assert_eq!(p.canonical_string(), "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
    }

    #[test]
    fn test_streaming_hmac_trailer_sentinel_classified() {
        let p = classify_payload_header("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", rid())
            .expect("hmac streaming trailer is now classified");
        assert_eq!(
            p,
            PayloadHashForSigning::StreamingAws4HmacSha256PayloadTrailer
        );
        assert!(!p.requires_body_bytes());
        assert_eq!(
            p.canonical_string(),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
        );
    }

    #[test]
    fn test_streaming_ecdsa_sentinel_unsupported() {
        let err = classify_payload_header("STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD", rid())
            .expect_err("ecdsa streaming fail-closed");
        assert_eq!(err.code, "UnsupportedSignature");
        let err =
            classify_payload_header("STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER", rid())
                .expect_err("ecdsa streaming trailer fail-closed");
        assert_eq!(err.code, "UnsupportedSignature");
    }

    #[test]
    fn test_invalid_hex_rejected() {
        let err = classify_payload_header("not-a-hex-digest-just-random-stuff-here-not-64", rid())
            .expect_err("non-hex string must reject");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");

        // Uppercase hex: AWS canonicalization uses lowercase, and so do the
        // SDK signers; uppercase here would never round-trip cleanly.
        let err = classify_payload_header(
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
            rid(),
        )
        .expect_err("uppercase hex must reject");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_verify_payload_matches() {
        // SHA-256 of empty string.
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        verify_payload_matches_hash(b"", expected, rid()).expect("empty body matches");

        let err = verify_payload_matches_hash(b"data", expected, rid()).expect_err("body mismatch");
        assert_eq!(err.code, "SignatureDoesNotMatch");
        assert!(err.message.contains("mismatch"));
    }
}
