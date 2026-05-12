//! Decoder for the AWS aws-chunked wire format (non-trailer mode only).
//!
//! Parses the framing produced by SigV4 streaming uploads with
//! `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and writes the
//! decoded body bytes to an async writer. Chunk signatures are validated for
//! syntactic shape (64 hex chars) but NOT cryptographically verified — strict
//! verification is tracked in issue #63.
//!
//! Trailer-mode variants (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`,
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER`, ECDSA streaming) are out of scope and
//! must be routed to passthrough by the caller.

use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// The non-trailer SigV4 streaming sentinel that this decoder handles.
pub const STREAMING_AWS4_HMAC_SHA256_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

/// Maximum bytes for a single chunk-header line (`<hex-size>;chunk-signature=<hex>\r\n`).
/// Way larger than any legitimate header — bounds the worst-case allocation when
/// a malformed/never-terminating header line is sent.
pub const MAX_CHUNK_HEADER_LINE_BYTES: usize = 4096;

/// Required length of the hex-encoded chunk signature.
pub const CHUNK_SIGNATURE_HEX_LEN: usize = 64;

/// AWS-documented minimum size of any non-final signed chunk (8 KiB). Smaller
/// non-final chunks fragment the signature stream and are rejected.
pub const MIN_NON_FINAL_CHUNK_BYTES: u64 = 8192;

/// Summary of a successful decode pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSummary {
    pub decoded_len: u64,
    pub sha256: [u8; 32],
    pub sha256_hex: String,
}

/// Decoder errors. Maps to S3 errors at the handler boundary.
#[derive(Debug, thiserror::Error)]
pub enum AwsChunkedError {
    #[error("malformed aws-chunked frame: {message}")]
    MalformedFrame { message: String },

    #[error("invalid aws-chunked chunk size at chunk {chunk_index}: {size} (min {min})")]
    InvalidChunkSize {
        chunk_index: u64,
        size: u64,
        min: u64,
    },

    #[error("decoded length mismatch: declared {declared}, actual {actual}")]
    DecodedLengthMismatch { declared: u64, actual: u64 },

    #[error("decoded length exceeded: declared {declared}, attempted {attempted}")]
    DecodedLengthExceeded { declared: u64, attempted: u64 },

    #[error("truncated aws-chunked body")]
    Truncated,

    #[error("aws-chunked body contained data after the final chunk")]
    TrailingData,

    #[error("aws-chunked chunk header exceeded {limit} bytes")]
    ChunkHeaderTooLarge { limit: usize },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Streaming aws-chunked decoder. Reads frames from `inner`, validates them,
/// and writes the decoded payload bytes to a caller-supplied writer.
///
/// The decoder enforces:
/// - Each chunk header is exactly `<hex-size>;chunk-signature=<64 hex>\r\n`.
/// - Each chunk payload is followed by `\r\n`.
/// - The final chunk has size `0` and is followed by a terminating `\r\n`
///   (no trailers; trailer-mode is out of scope for this PR).
/// - The sum of chunk sizes equals `declared_decoded_len` exactly.
/// - Every non-final data chunk is at least `MIN_NON_FINAL_CHUNK_BYTES`.
/// - There is no data after the final chunk's terminating CRLF.
pub struct AwsChunkedDecoder<R> {
    inner: BufReader<R>,
    declared_decoded_len: u64,
    decoded_len: u64,
    hasher: Sha256,
    chunk_index: u64,
    previous_data_chunk_size: Option<u64>,
}

impl<R: AsyncRead + Unpin> AwsChunkedDecoder<R> {
    pub fn new(inner: R, declared_decoded_len: u64) -> Self {
        Self {
            inner: BufReader::new(inner),
            declared_decoded_len,
            decoded_len: 0,
            hasher: Sha256::new(),
            chunk_index: 0,
            previous_data_chunk_size: None,
        }
    }

    /// Drive the decode loop. Reads chunks until the final `0`-size chunk and
    /// writes decoded payload bytes to `writer`. Returns a summary including
    /// the SHA-256 of the decoded payload.
    pub async fn decode_to_writer<W>(
        mut self,
        writer: &mut W,
    ) -> Result<DecodedSummary, AwsChunkedError>
    where
        W: AsyncWrite + Unpin,
    {
        loop {
            let header = self.read_chunk_header_line().await?;
            let chunk_size = parse_chunk_header(&header)?;

            if chunk_size == 0 {
                // Final chunk: must be followed by a single CRLF terminator
                // and nothing else (no trailer headers in non-trailer mode).
                self.expect_crlf().await?;
                self.expect_eof().await?;

                if self.decoded_len != self.declared_decoded_len {
                    return Err(AwsChunkedError::DecodedLengthMismatch {
                        declared: self.declared_decoded_len,
                        actual: self.decoded_len,
                    });
                }

                let digest = self.hasher.finalize();
                let mut sha256 = [0u8; 32];
                sha256.copy_from_slice(&digest);
                return Ok(DecodedSummary {
                    decoded_len: self.decoded_len,
                    sha256,
                    sha256_hex: hex_encode_lower(&sha256),
                });
            }

            // A previous data chunk that was below the minimum is only an
            // error if ANOTHER non-zero chunk follows it. Apply the check
            // here, once we know there's another chunk coming.
            if let Some(prev) = self.previous_data_chunk_size
                && prev < MIN_NON_FINAL_CHUNK_BYTES
            {
                return Err(AwsChunkedError::InvalidChunkSize {
                    chunk_index: self.chunk_index - 1,
                    size: prev,
                    min: MIN_NON_FINAL_CHUNK_BYTES,
                });
            }

            // Reject before consuming any payload bytes if this chunk would
            // push us past the declared decoded length.
            let attempted = self.decoded_len.saturating_add(chunk_size);
            if attempted > self.declared_decoded_len {
                return Err(AwsChunkedError::DecodedLengthExceeded {
                    declared: self.declared_decoded_len,
                    attempted,
                });
            }

            self.copy_chunk_payload(writer, chunk_size).await?;
            self.expect_crlf().await?;

            self.decoded_len += chunk_size;
            self.previous_data_chunk_size = Some(chunk_size);
            self.chunk_index += 1;
        }
    }

    /// Read a single chunk-header line (terminated by `\r\n`) using a bounded
    /// buffer. Strips the trailing `\r\n` from the returned string.
    async fn read_chunk_header_line(&mut self) -> Result<String, AwsChunkedError> {
        let mut buf: Vec<u8> = Vec::with_capacity(128);
        loop {
            let read_n = self
                .inner
                .read_until(b'\n', &mut buf)
                .await
                .map_err(AwsChunkedError::Io)?;
            if read_n == 0 {
                // EOF before we found a `\n`.
                if buf.is_empty() {
                    return Err(AwsChunkedError::Truncated);
                }
                return Err(AwsChunkedError::MalformedFrame {
                    message: "chunk header missing CRLF terminator".to_string(),
                });
            }
            if buf.len() > MAX_CHUNK_HEADER_LINE_BYTES {
                return Err(AwsChunkedError::ChunkHeaderTooLarge {
                    limit: MAX_CHUNK_HEADER_LINE_BYTES,
                });
            }
            // `read_until` stops *after* the delimiter; we got the `\n` if the
            // last byte is `\n`. (Should always be the case unless EOF.)
            if buf.last() == Some(&b'\n') {
                break;
            }
        }

        // Strip trailing \r\n; must be present and exact.
        if buf.len() < 2 || buf[buf.len() - 2] != b'\r' || buf[buf.len() - 1] != b'\n' {
            return Err(AwsChunkedError::MalformedFrame {
                message: "chunk header not terminated by CRLF".to_string(),
            });
        }
        let header_bytes = &buf[..buf.len() - 2];
        std::str::from_utf8(header_bytes)
            .map(|s| s.to_string())
            .map_err(|_| AwsChunkedError::MalformedFrame {
                message: "chunk header contained non-UTF-8 bytes".to_string(),
            })
    }

    /// Copy `chunk_size` bytes of payload from the inner reader to `writer`,
    /// updating the running SHA-256 hasher along the way.
    async fn copy_chunk_payload<W>(
        &mut self,
        writer: &mut W,
        chunk_size: u64,
    ) -> Result<(), AwsChunkedError>
    where
        W: AsyncWrite + Unpin,
    {
        let mut remaining = chunk_size;
        let mut buf = [0u8; 16 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = self
                .inner
                .read(&mut buf[..want])
                .await
                .map_err(AwsChunkedError::Io)?;
            if n == 0 {
                return Err(AwsChunkedError::Truncated);
            }
            self.hasher.update(&buf[..n]);
            writer
                .write_all(&buf[..n])
                .await
                .map_err(AwsChunkedError::Io)?;
            remaining -= n as u64;
        }
        Ok(())
    }

    /// Consume exactly `\r\n` from the inner reader. Anything else is a
    /// framing error.
    async fn expect_crlf(&mut self) -> Result<(), AwsChunkedError> {
        let mut crlf = [0u8; 2];
        match self.inner.read_exact(&mut crlf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(AwsChunkedError::Truncated);
            }
            Err(e) => return Err(AwsChunkedError::Io(e)),
        }
        if crlf != *b"\r\n" {
            return Err(AwsChunkedError::MalformedFrame {
                message: "expected CRLF after chunk payload or final chunk".to_string(),
            });
        }
        Ok(())
    }

    /// The body must end after the final chunk's terminating CRLF. Any
    /// further bytes — including a stray CRLF — are a framing error.
    async fn expect_eof(&mut self) -> Result<(), AwsChunkedError> {
        let mut scratch = [0u8; 1];
        match self.inner.read(&mut scratch).await {
            Ok(0) => Ok(()),
            Ok(_) => Err(AwsChunkedError::TrailingData),
            Err(e) => Err(AwsChunkedError::Io(e)),
        }
    }
}

/// Parse a chunk header line of the form `<hex-size>;chunk-signature=<64 hex>`.
/// Returns the chunk size on success.
fn parse_chunk_header(line: &str) -> Result<u64, AwsChunkedError> {
    // Split on the first `;`. Anything before is the hex size; the remainder
    // must be exactly `chunk-signature=<64 hex>` (no extra extensions; the
    // AWS aws-chunked wire format defines only the signature extension).
    let (size_part, sig_part) =
        line.split_once(';')
            .ok_or_else(|| AwsChunkedError::MalformedFrame {
                message: format!("chunk header missing `;chunk-signature=` extension: `{line}`"),
            })?;

    if size_part.is_empty() {
        return Err(AwsChunkedError::MalformedFrame {
            message: "chunk header had empty size field".to_string(),
        });
    }
    let size = u64::from_str_radix(size_part, 16).map_err(|_| AwsChunkedError::MalformedFrame {
        message: format!("chunk size is not valid hex: `{size_part}`"),
    })?;

    let sig_hex = sig_part.strip_prefix("chunk-signature=").ok_or_else(|| {
        AwsChunkedError::MalformedFrame {
            message: format!("chunk header extension is not `chunk-signature=...`: `{sig_part}`"),
        }
    })?;
    if sig_hex.len() != CHUNK_SIGNATURE_HEX_LEN {
        return Err(AwsChunkedError::MalformedFrame {
            message: format!(
                "chunk-signature must be {CHUNK_SIGNATURE_HEX_LEN} hex chars, got {}",
                sig_hex.len()
            ),
        });
    }
    if !sig_hex.bytes().all(is_lower_hex_byte) {
        return Err(AwsChunkedError::MalformedFrame {
            message: "chunk-signature must be lowercase hex".to_string(),
        });
    }

    Ok(size)
}

fn is_lower_hex_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
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
    use sha2::Digest;
    use tokio::io::BufWriter;

    const SIG: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn build_frame(chunks: &[&[u8]]) -> Vec<u8> {
        // chunks is a list of payloads; we append a final zero chunk after.
        let mut out = Vec::new();
        for c in chunks {
            out.extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("0;chunk-signature={SIG}\r\n\r\n").as_bytes());
        out
    }

    async fn decode(
        frame: &[u8],
        declared_len: u64,
    ) -> Result<(Vec<u8>, DecodedSummary), AwsChunkedError> {
        let mut sink: BufWriter<Vec<u8>> = BufWriter::new(Vec::new());
        let summary = AwsChunkedDecoder::new(frame, declared_len)
            .decode_to_writer(&mut sink)
            .await?;
        sink.flush().await.unwrap();
        Ok((sink.into_inner(), summary))
    }

    fn expected_sha256(bytes: &[u8]) -> ([u8; 32], String) {
        let digest = sha2::Sha256::digest(bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&digest);
        (arr, hex_encode_lower(&arr))
    }

    // Test 1: single chunk decodes to expected payload + SHA.
    #[tokio::test]
    async fn test_single_chunk_decodes_and_hashes() {
        let payload = b"abcdefgh";
        let frame = build_frame(&[payload]);
        let (decoded, summary) = decode(&frame, payload.len() as u64).await.unwrap();
        assert_eq!(decoded, payload);
        let (sha, sha_hex) = expected_sha256(payload);
        assert_eq!(summary.decoded_len, payload.len() as u64);
        assert_eq!(summary.sha256, sha);
        assert_eq!(summary.sha256_hex, sha_hex);
    }

    // Test 2: multi-chunk decodes correctly (all non-final chunks ≥ 8192).
    #[tokio::test]
    async fn test_multi_chunk_decodes() {
        // 3 data chunks, each 10_000 bytes (>= 8192), distinct content.
        let chunks: Vec<Vec<u8>> = (0u8..3).map(|i| vec![b'A' + i; 10_000]).collect();
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let frame = build_frame(&chunk_refs);
        let total: u64 = chunks.iter().map(|c| c.len() as u64).sum();
        let (decoded, summary) = decode(&frame, total).await.unwrap();
        let expected: Vec<u8> = chunks.iter().flatten().copied().collect();
        assert_eq!(decoded, expected);
        let (_, sha_hex) = expected_sha256(&expected);
        assert_eq!(summary.sha256_hex, sha_hex);
        assert_eq!(summary.decoded_len, total);
    }

    // Test 3: empty object — just the final zero chunk — decodes to empty.
    #[tokio::test]
    async fn test_empty_object_decodes() {
        let frame = build_frame(&[]);
        let (decoded, summary) = decode(&frame, 0).await.unwrap();
        assert!(decoded.is_empty());
        assert_eq!(summary.decoded_len, 0);
        let (_, sha_hex) = expected_sha256(b"");
        assert_eq!(summary.sha256_hex, sha_hex);
    }

    // Test 4: header missing `;chunk-signature=` extension.
    #[tokio::test]
    async fn test_missing_signature_extension_errors() {
        let frame = b"8\r\nabcdefgh\r\n0\r\n\r\n".to_vec();
        let err = decode(&frame, 8).await.unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }

    // Test 5: signature is the wrong length.
    #[tokio::test]
    async fn test_signature_wrong_length_errors() {
        let frame = b"8;chunk-signature=deadbeef\r\nabcdefgh\r\n0;chunk-signature=deadbeef\r\n\r\n"
            .to_vec();
        let err = decode(&frame, 8).await.unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }

    // Test 6: signature contains non-hex characters.
    #[tokio::test]
    async fn test_signature_non_hex_errors() {
        // 64 chars including a non-hex 'z'.
        let sig = "z".to_string() + &"0".repeat(63);
        let frame =
            format!("8;chunk-signature={sig}\r\nabcdefgh\r\n0;chunk-signature={SIG}\r\n\r\n");
        let err = decode(frame.as_bytes(), 8).await.unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }

    // Test 7: missing CRLF after header (the header reader sees EOF instead).
    #[tokio::test]
    async fn test_missing_crlf_after_header_errors() {
        // Header without trailing \r\n, then EOF. Decoder reads until EOF
        // without finding `\n` — returns either Truncated or MalformedFrame.
        let frame = format!("8;chunk-signature={SIG}");
        let err = decode(frame.as_bytes(), 8).await.unwrap_err();
        assert!(
            matches!(
                err,
                AwsChunkedError::Truncated | AwsChunkedError::MalformedFrame { .. }
            ),
            "got {err:?}",
        );
    }

    // Test 8: missing CRLF after chunk data.
    #[tokio::test]
    async fn test_missing_crlf_after_chunk_data_errors() {
        // Replace the post-payload \r\n with `xx` to invalidate the framing.
        let frame = format!("8;chunk-signature={SIG}\r\nabcdefghxx0;chunk-signature={SIG}\r\n\r\n");
        let err = decode(frame.as_bytes(), 8).await.unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }

    // Test 9: truncated chunk data (payload shorter than declared size).
    #[tokio::test]
    async fn test_truncated_chunk_data_errors() {
        // Declares 8-byte chunk but supplies only 3, then EOF.
        let frame = format!("8;chunk-signature={SIG}\r\nabc");
        let err = decode(frame.as_bytes(), 8).await.unwrap_err();
        assert!(matches!(err, AwsChunkedError::Truncated), "got {err:?}");
    }

    // Test 10: final chunk's terminator missing (we stop right after `0;...\r\n`).
    #[tokio::test]
    async fn test_final_chunk_missing_terminator_errors() {
        // Data chunk OK, final chunk header OK, but no terminating CRLF after.
        let frame = format!("8;chunk-signature={SIG}\r\nabcdefgh\r\n0;chunk-signature={SIG}\r\n",);
        let err = decode(frame.as_bytes(), 8).await.unwrap_err();
        assert!(
            matches!(
                err,
                AwsChunkedError::Truncated | AwsChunkedError::MalformedFrame { .. }
            ),
            "got {err:?}",
        );
    }

    // Test 11: trailing data after the final chunk's terminator.
    #[tokio::test]
    async fn test_trailing_data_errors() {
        let mut frame =
            format!("8;chunk-signature={SIG}\r\nabcdefgh\r\n0;chunk-signature={SIG}\r\n\r\n")
                .into_bytes();
        frame.extend_from_slice(b"EXTRA");
        let err = decode(&frame, 8).await.unwrap_err();
        assert!(matches!(err, AwsChunkedError::TrailingData), "got {err:?}");
    }

    // Test 12: declared decoded length is greater than actual sum of chunks.
    #[tokio::test]
    async fn test_decoded_length_short_errors() {
        // Sum of payloads is 8 but the caller declared 16. The final 0-chunk
        // is hit first; we then notice the mismatch.
        let frame = build_frame(&[b"abcdefgh"]);
        let err = decode(&frame, 16).await.unwrap_err();
        match err {
            AwsChunkedError::DecodedLengthMismatch { declared, actual } => {
                assert_eq!(declared, 16);
                assert_eq!(actual, 8);
            }
            other => panic!("expected DecodedLengthMismatch, got {other:?}"),
        }
    }

    // Test 13: a chunk would push us past the declared decoded length.
    #[tokio::test]
    async fn test_decoded_length_exceeded_errors() {
        // Declared 4, but a single 8-byte data chunk is offered.
        let frame = build_frame(&[b"abcdefgh"]);
        let err = decode(&frame, 4).await.unwrap_err();
        match err {
            AwsChunkedError::DecodedLengthExceeded {
                declared,
                attempted,
            } => {
                assert_eq!(declared, 4);
                assert_eq!(attempted, 8);
            }
            other => panic!("expected DecodedLengthExceeded, got {other:?}"),
        }
    }

    // Test 14: non-final chunk under 8192 followed by another non-zero chunk.
    #[tokio::test]
    async fn test_non_final_chunk_under_minimum_errors() {
        // chunk 0 is 100 bytes; chunk 1 is 9000 bytes — chunk 0 violates the
        // 8192 minimum because it isn't the final data chunk.
        let small = vec![b'x'; 100];
        let big = vec![b'y'; 9_000];
        let frame = build_frame(&[&small, &big]);
        let err = decode(&frame, (small.len() + big.len()) as u64)
            .await
            .unwrap_err();
        match err {
            AwsChunkedError::InvalidChunkSize { size, min, .. } => {
                assert_eq!(size, 100);
                assert_eq!(min, MIN_NON_FINAL_CHUNK_BYTES);
            }
            other => panic!("expected InvalidChunkSize, got {other:?}"),
        }
    }

    // Companion: a SINGLE small data chunk (followed only by the final zero
    // chunk) is fine — the 8192 minimum applies only to non-final chunks.
    #[tokio::test]
    async fn test_single_small_chunk_is_allowed() {
        let small = vec![b'x'; 100];
        let frame = build_frame(&[&small]);
        let (decoded, _) = decode(&frame, small.len() as u64).await.unwrap();
        assert_eq!(decoded, small);
    }

    // Test 15: chunk header line larger than MAX_CHUNK_HEADER_LINE_BYTES.
    #[tokio::test]
    async fn test_chunk_header_too_large_errors() {
        // A header padded with a long, otherwise-valid-looking extension that
        // never terminates within the budget. We don't even include `\r\n`,
        // so the limit is the only thing that can stop the read.
        let oversized = vec![b'a'; MAX_CHUNK_HEADER_LINE_BYTES + 64];
        let err = decode(&oversized, 8).await.unwrap_err();
        match err {
            AwsChunkedError::ChunkHeaderTooLarge { limit } => {
                assert_eq!(limit, MAX_CHUNK_HEADER_LINE_BYTES);
            }
            // Could also surface as Truncated if the buffer exactly hits the
            // limit at the same call that detects no `\n` — both are fine.
            AwsChunkedError::Truncated | AwsChunkedError::MalformedFrame { .. } => {}
            other => panic!("expected ChunkHeaderTooLarge, got {other:?}"),
        }
    }

    // ---- parse_chunk_header unit-level coverage ----

    #[test]
    fn test_parse_header_uppercase_hex_signature_rejected() {
        // 64 uppercase hex characters — protocol mandates lowercase.
        let upper = "0".repeat(63) + "A";
        let line = format!("8;chunk-signature={upper}");
        let err = parse_chunk_header(&line).unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_parse_header_empty_size_rejected() {
        let line = format!(";chunk-signature={SIG}");
        let err = parse_chunk_header(&line).unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }
}
