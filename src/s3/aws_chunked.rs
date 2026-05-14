//! Decoder for the AWS aws-chunked wire format. Handles three modes:
//!
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (non-trailer): signed chunks, no
//!   HTTP trailers after the final zero chunk.
//! - `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: bare-size chunk headers (no
//!   signature), followed by a single `x-amz-checksum-*` trailer line.
//! - `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: signed chunks PLUS a
//!   trailer line PLUS an `x-amz-trailer-signature` line. Trailer-signature
//!   is shape-validated only (64 hex chars); the crypto check is #63.
//!
//! For trailer modes the decoder ALSO validates that the declared checksum
//! matches the computed checksum over the decoded body. A mismatch fails the
//! decode before any backend contact happens.
//!
//! ECDSA streaming variants (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*`)
//! are out of scope: the inbound `chunk-signature` values are bound to the
//! client's private key, so the proxy can neither validate them nor have
//! the upstream re-validate them after re-signing. The dispatch layer
//! rejects these requests outright with `UnsupportedSignature` (HTTP 400)
//! — they never reach this decoder. See
//! `handlers::modifiers::WriteBodyRoute::RejectUnsupportedSignature` and
//! issue #63.

use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::auth::sigv4::streaming::{StreamingSigV4Context, StreamingSigV4Error};
use crate::s3::checksum::{ChecksumAlgorithm, ChecksumHeader};

/// The non-trailer SigV4 streaming sentinel.
pub const STREAMING_AWS4_HMAC_SHA256_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

/// Unsigned-trailer streaming sentinel — chunks carry no signature, but the
/// stream ends with a single `x-amz-checksum-*` trailer line.
pub const STREAMING_UNSIGNED_PAYLOAD_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

/// Signed-trailer streaming sentinel — chunks carry signatures AND the stream
/// ends with a trailer line plus an `x-amz-trailer-signature` line.
pub const STREAMING_AWS4_HMAC_SHA256_PAYLOAD_TRAILER: &str =
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";

/// Maximum bytes for a single trailer header line. Trailers are short
/// (`x-amz-checksum-<algo>:<base64>`) so the cap is intentionally generous,
/// matching the chunk-header cap rather than introducing a separate constant
/// to bound the read.
pub const MAX_TRAILER_LINE_BYTES: usize = MAX_CHUNK_HEADER_LINE_BYTES;

/// Maximum bytes for a single chunk-header line (`<hex-size>;chunk-signature=<hex>\r\n`).
/// Way larger than any legitimate header — bounds the worst-case allocation when
/// a malformed/never-terminating header line is sent.
pub const MAX_CHUNK_HEADER_LINE_BYTES: usize = 4096;

/// Required length of the hex-encoded chunk signature.
pub const CHUNK_SIGNATURE_HEX_LEN: usize = 64;

/// AWS-documented minimum size of any non-final signed chunk (8 KiB). Smaller
/// non-final chunks fragment the signature stream and are rejected.
pub const MIN_NON_FINAL_CHUNK_BYTES: u64 = 8192;

/// Wire-format mode the decoder should expect. The caller derives this from
/// the inbound `x-amz-content-sha256` sentinel plus the `x-amz-trailer`
/// header — see `handlers::aws_chunked::decoder_mode_from_headers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderMode {
    /// Non-trailer SigV4 streaming. Chunk headers carry `;chunk-signature=...`,
    /// no trailers follow the final zero chunk.
    NonTrailer,
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`. Chunk headers are bare
    /// `<hex-size>\r\n` (signature MUST be absent), and the stream ends with
    /// a single `x-amz-checksum-<algo>:<base64>` trailer line.
    UnsignedTrailer {
        expected_trailer_name: String,
        algorithm: ChecksumAlgorithm,
    },
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`. Chunk headers carry
    /// `;chunk-signature=...`, the stream ends with a trailer line followed
    /// by `x-amz-trailer-signature:<64 hex>`.
    SignedTrailer {
        expected_trailer_name: String,
        algorithm: ChecksumAlgorithm,
    },
}

impl DecoderMode {
    fn expects_chunk_signature(&self) -> bool {
        !matches!(self, DecoderMode::UnsignedTrailer { .. })
    }

    fn trailer_info(&self) -> Option<(&str, ChecksumAlgorithm, bool)> {
        match self {
            DecoderMode::NonTrailer => None,
            DecoderMode::UnsignedTrailer {
                expected_trailer_name,
                algorithm,
            } => Some((expected_trailer_name.as_str(), *algorithm, false)),
            DecoderMode::SignedTrailer {
                expected_trailer_name,
                algorithm,
            } => Some((expected_trailer_name.as_str(), *algorithm, true)),
        }
    }
}

/// Summary of a successful decode pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSummary {
    pub decoded_len: u64,
    pub sha256: [u8; 32],
    pub sha256_hex: String,
    /// `Some(_)` for trailer-mode decodes, populated only after the trailer
    /// has been parsed AND the declared checksum has been verified against
    /// the decoded body. The handler forwards this verbatim to the upstream
    /// backend as a non-streaming `x-amz-checksum-*` request header.
    pub trailer: Option<ChecksumHeader>,
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

    /// I/O error reading the inbound aws-chunked body. The client is the
    /// proximate cause (truncated socket, mid-stream reset, etc.) so this
    /// maps to a 400 `IncompleteBody` at the handler boundary.
    #[error("aws-chunked inbound body read I/O error: {source}")]
    InboundIo {
        #[source]
        source: std::io::Error,
    },

    /// I/O error writing the decoded body to the spool file on disk. The
    /// proxy is the proximate cause (no space, permission, etc.) so this
    /// maps to a 500 `InternalError` at the handler boundary.
    #[error("aws-chunked spool write I/O error: {source}")]
    SpoolIo {
        #[source]
        source: std::io::Error,
    },

    /// Trailer header line was syntactically malformed (missing colon, wrong
    /// name, multiple lines where one expected, invalid line terminator).
    /// Maps to 400 `InvalidRequest` at the handler boundary.
    #[error("invalid aws-chunked trailer header: {message}")]
    InvalidTrailer { message: String },

    /// Stream ended where a trailer header line was expected. Distinguished
    /// from `InvalidTrailer` so the handler can surface a more specific
    /// `InvalidRequest` message (the trailer the request advertised never
    /// arrived). Maps to 400 `InvalidRequest`.
    #[error("missing aws-chunked trailer header: {name}")]
    MissingTrailer { name: String },

    /// Trailer value was not valid base64, or decoded to a length that
    /// doesn't match the algorithm's expected digest size. Maps to 400
    /// `InvalidDigest` at the handler boundary.
    #[error("invalid trailer checksum: {message}")]
    InvalidTrailerChecksum { message: String },

    /// Trailer was syntactically well-formed but the computed checksum over
    /// the decoded body didn't match the declared value. The load-bearing
    /// integrity check for trailer-mode uploads. Maps to 400 `BadDigest`.
    #[error("trailer checksum mismatch for {name}")]
    TrailerChecksumMismatch { name: String },

    /// `x-amz-trailer-signature` line was missing or malformed on a signed
    /// trailer upload. Shape-validation only; the cryptographic
    /// comparison surfaces as [`Self::TrailerSignatureMismatch`] instead.
    /// Maps to 400 `InvalidRequest`.
    #[error("invalid trailer signature: {message}")]
    InvalidTrailerSignature { message: String },

    /// Strict-mode chunk signature verification failed: the supplied
    /// `chunk-signature=` value did not match the HMAC computed from the
    /// chained kSigning + string-to-sign. `chunk_index` identifies the
    /// failing chunk (0-based, counting payload chunks). Maps to 403
    /// `SignatureDoesNotMatch` at the handler boundary.
    #[error("aws-chunked chunk signature mismatch at chunk {chunk_index}")]
    ChunkSignatureMismatch { chunk_index: u64 },

    /// Strict-mode trailer signature verification failed: the
    /// `x-amz-trailer-signature` value did not match the HMAC computed
    /// from the final zero-chunk signature + canonical trailer hash.
    /// Maps to 403 `SignatureDoesNotMatch` at the handler boundary.
    #[error("aws-chunked trailer signature mismatch")]
    TrailerSignatureMismatch,
}

/// What the decoder should do with each chunk's (and the trailer's)
/// signature when shape-parsing has succeeded.
///
/// - [`ChunkSignaturePolicy::ShapeOnly`] preserves the trust-mode shape
///   check: the signature has to be 64 lowercase hex chars, but its
///   value isn't compared against anything. Used when strict-mode SigV4
///   isn't configured.
/// - [`ChunkSignaturePolicy::Verify`] additionally verifies each chunk
///   signature (and the trailer signature on signed-trailer mode) against
///   the chained HMAC seeded from the request's verified signature.
pub enum ChunkSignaturePolicy {
    ShapeOnly,
    Verify(StreamingSigV4Context),
}

/// Streaming aws-chunked decoder. Reads frames from `inner`, validates them,
/// and writes the decoded payload bytes to a caller-supplied writer.
///
/// The decoder enforces:
/// - For non-trailer / signed-trailer modes: each chunk header is exactly
///   `<hex-size>;chunk-signature=<64 hex>\r\n`. For unsigned-trailer mode:
///   each chunk header is exactly `<hex-size>\r\n` (signature MUST be absent).
/// - Each chunk payload is followed by `\r\n`.
/// - The final chunk has size `0`. For non-trailer mode it is followed by a
///   terminating `\r\n`. For trailer modes the final chunk header is
///   followed by `x-amz-checksum-<algo>:<base64>` (and `x-amz-trailer-signature`
///   on signed trailers), then a closing `\r\n`.
/// - The sum of chunk sizes equals `declared_decoded_len` exactly.
/// - Every non-final data chunk is at least `MIN_NON_FINAL_CHUNK_BYTES`.
/// - There is no data after the closing CRLF.
/// - For trailer modes: the declared checksum value (post-base64-decode)
///   exactly equals the algorithm's digest of the decoded body.
pub struct AwsChunkedDecoder<R> {
    inner: BufReader<R>,
    declared_decoded_len: u64,
    decoded_len: u64,
    hasher: Sha256,
    chunk_index: u64,
    previous_data_chunk_size: Option<u64>,
    mode: DecoderMode,
    /// Side-channel hasher for trailer-mode checksum validation. Built upfront
    /// (in `with_mode`) for every non-SHA256 trailer algorithm; left `None`
    /// for non-trailer mode and for SHA256 trailers (the body SHA256 we
    /// always compute satisfies that case directly).
    algo_hasher: Option<Box<dyn aws_smithy_checksums::http::HttpChecksum>>,
    /// Per-chunk + trailer signature verification policy. Owned by the
    /// decoder so the [`StreamingSigV4Context`] (with its kSigning) is
    /// dropped — and zeroized — when the decode completes.
    signature_policy: ChunkSignaturePolicy,
}

impl<R: AsyncRead + Unpin> AwsChunkedDecoder<R> {
    /// Build a non-trailer decoder. Equivalent to
    /// `with_mode(inner, declared_decoded_len, DecoderMode::NonTrailer)`.
    pub fn new(inner: R, declared_decoded_len: u64) -> Self {
        Self::with_mode(inner, declared_decoded_len, DecoderMode::NonTrailer)
    }

    /// Build a decoder for the specified wire-format mode in trust mode
    /// (signatures are shape-validated but not cryptographically
    /// verified). Equivalent to
    /// [`AwsChunkedDecoder::with_mode_and_signature_policy`] with
    /// [`ChunkSignaturePolicy::ShapeOnly`].
    pub fn with_mode(inner: R, declared_decoded_len: u64, mode: DecoderMode) -> Self {
        Self::with_mode_and_signature_policy(
            inner,
            declared_decoded_len,
            mode,
            ChunkSignaturePolicy::ShapeOnly,
        )
    }

    /// Build a decoder for the specified wire-format mode AND chunk-
    /// signature policy. Strict-mode callers pass
    /// [`ChunkSignaturePolicy::Verify`] with a [`StreamingSigV4Context`]
    /// seeded from the request's verified signature so each chunk (and,
    /// for signed-trailer mode, the trailer signature) is verified
    /// against the chained HMAC before the decoded bytes are released.
    pub fn with_mode_and_signature_policy(
        inner: R,
        declared_decoded_len: u64,
        mode: DecoderMode,
        signature_policy: ChunkSignaturePolicy,
    ) -> Self {
        let algo_hasher = match mode.trailer_info() {
            Some((_, ChecksumAlgorithm::Sha256, _)) | None => None,
            Some((_, algo, _)) => Some(algo.into_smithy_impl()),
        };
        Self {
            inner: BufReader::new(inner),
            declared_decoded_len,
            decoded_len: 0,
            hasher: Sha256::new(),
            chunk_index: 0,
            previous_data_chunk_size: None,
            mode,
            algo_hasher,
            signature_policy,
        }
    }

    /// Drive the decode loop. Reads chunks until the final `0`-size chunk and
    /// writes decoded payload bytes to `writer`. Returns a summary including
    /// the SHA-256 of the decoded payload (and, for trailer modes, the
    /// validated checksum trailer).
    pub async fn decode_to_writer<W>(
        mut self,
        writer: &mut W,
    ) -> Result<DecodedSummary, AwsChunkedError>
    where
        W: AsyncWrite + Unpin,
    {
        let expects_signature = self.mode.expects_chunk_signature();

        loop {
            let header = self.read_chunk_header_line().await?;
            let parsed = parse_chunk_header(&header, expects_signature)?;
            let chunk_size = parsed.size;

            if chunk_size == 0 {
                return self
                    .finalize(writer, parsed.signature_hex.map(str::to_owned))
                    .await;
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

            let chunk_sha = self.copy_chunk_payload(writer, chunk_size).await?;
            self.expect_crlf().await?;

            // Strict-mode verification: each chunk's signature must match
            // the chained HMAC. Verification happens AFTER the payload +
            // CRLF have been consumed off the wire, so a mismatch can't
            // be confused with a framing error. Gated on `expects_signature`
            // so unsigned-trailer mode never tries to verify a signature
            // that the wire format doesn't carry.
            if expects_signature
                && let ChunkSignaturePolicy::Verify(ctx) = &mut self.signature_policy
            {
                let supplied = parsed.signature_hex.expect(
                    "signed mode guarantees chunk-signature is present (parse_chunk_header would \
                     have errored otherwise)",
                );
                let chunk_sha_hex = hex_encode_lower(&chunk_sha);
                match ctx.verify_payload_chunk(&chunk_sha_hex, supplied) {
                    Ok(()) => {}
                    Err(StreamingSigV4Error::ChunkSignatureMismatch) => {
                        return Err(AwsChunkedError::ChunkSignatureMismatch {
                            chunk_index: self.chunk_index,
                        });
                    }
                    Err(StreamingSigV4Error::InvalidSignatureHex(_)) => {
                        // `parse_chunk_header` already validated lowercase + 64-char.
                        // Reaching this arm would indicate a shape regression there.
                        return Err(AwsChunkedError::MalformedFrame {
                            message: format!(
                                "chunk-signature failed hex validation at chunk {}",
                                self.chunk_index,
                            ),
                        });
                    }
                    Err(StreamingSigV4Error::TrailerSignatureMismatch) => {
                        // verify_payload_chunk never produces this variant.
                        unreachable!("verify_payload_chunk does not produce TrailerSignatureMismatch");
                    }
                }
            }

            self.decoded_len += chunk_size;
            self.previous_data_chunk_size = Some(chunk_size);
            self.chunk_index += 1;
        }
    }

    /// Final-chunk handling. Validates the decoded length, consumes any
    /// trailer line(s) the mode requires, verifies the trailer checksum
    /// against the computed digest, and returns the summary.
    ///
    /// `zero_chunk_signature_hex` is the value from the
    /// `0;chunk-signature=...` header (when the mode expects one).
    /// Strict-mode verification of the zero-chunk signature happens here
    /// rather than inline in the loop because the zero chunk has no
    /// payload to hash — `EMPTY_SHA256_HEX` substitutes for both the
    /// "empty" line and the "current chunk" line of the STS.
    async fn finalize<W>(
        mut self,
        _writer: &mut W,
        zero_chunk_signature_hex: Option<String>,
    ) -> Result<DecodedSummary, AwsChunkedError>
    where
        W: AsyncWrite + Unpin,
    {
        // Verify the zero-chunk signature before anything else: a tampered
        // final chunk should fail-closed even if trailers are well-formed.
        // Skip when the mode is unsigned-trailer — `parse_chunk_header`
        // returns `signature_hex: None` there, and there's nothing for the
        // streaming context to verify against.
        let expects_signature = self.mode.expects_chunk_signature();
        if expects_signature
            && let ChunkSignaturePolicy::Verify(ctx) = &mut self.signature_policy
        {
            let supplied = zero_chunk_signature_hex
                .as_deref()
                .expect("signed mode guarantees final chunk-signature is present");
            match ctx.verify_payload_chunk(
                crate::auth::sigv4::streaming::EMPTY_SHA256_HEX,
                supplied,
            ) {
                Ok(()) => {}
                Err(StreamingSigV4Error::ChunkSignatureMismatch) => {
                    return Err(AwsChunkedError::ChunkSignatureMismatch {
                        chunk_index: self.chunk_index,
                    });
                }
                Err(StreamingSigV4Error::InvalidSignatureHex(_)) => {
                    return Err(AwsChunkedError::MalformedFrame {
                        message: "final chunk-signature failed hex validation".to_string(),
                    });
                }
                Err(StreamingSigV4Error::TrailerSignatureMismatch) => {
                    unreachable!("verify_payload_chunk does not produce TrailerSignatureMismatch");
                }
            }
        }

        let algo_hasher = self.algo_hasher.take();
        // The trailer info needs to be cloned out before we move chunks of
        // `self` into helper methods.
        let trailer_expectation = self
            .mode
            .trailer_info()
            .map(|(name, algo, signed)| (name.to_string(), algo, signed));

        let trailer = match trailer_expectation {
            None => {
                // Non-trailer: a single CRLF terminator and EOF.
                self.expect_crlf().await?;
                self.expect_eof().await?;
                None
            }
            Some((expected_name, algo, signed)) => {
                let parsed = self.read_and_validate_trailer(&expected_name, algo).await?;
                if signed {
                    let trailer_sig = self.read_and_validate_trailer_signature().await?;
                    // Strict-mode trailer signature verification. The canonical
                    // trailer bytes are `<lowercase-name>:<value>\n` — the
                    // `x-amz-trailer-signature` line itself is NOT included.
                    if let ChunkSignaturePolicy::Verify(ctx) = &self.signature_policy {
                        let mut canonical = Vec::with_capacity(parsed.name.len() + parsed.value.len() + 2);
                        canonical.extend_from_slice(parsed.name.to_ascii_lowercase().as_bytes());
                        canonical.push(b':');
                        canonical.extend_from_slice(parsed.value.as_bytes());
                        canonical.push(b'\n');
                        match ctx.verify_trailer(&canonical, &trailer_sig) {
                            Ok(()) => {}
                            Err(StreamingSigV4Error::TrailerSignatureMismatch) => {
                                return Err(AwsChunkedError::TrailerSignatureMismatch);
                            }
                            Err(StreamingSigV4Error::InvalidSignatureHex(_)) => {
                                return Err(AwsChunkedError::InvalidTrailerSignature {
                                    message: "x-amz-trailer-signature failed hex validation"
                                        .to_string(),
                                });
                            }
                            Err(StreamingSigV4Error::ChunkSignatureMismatch) => {
                                unreachable!("verify_trailer does not produce ChunkSignatureMismatch");
                            }
                        }
                    }
                }
                self.expect_crlf().await?;
                self.expect_eof().await?;
                Some(parsed)
            }
        };

        if self.decoded_len != self.declared_decoded_len {
            return Err(AwsChunkedError::DecodedLengthMismatch {
                declared: self.declared_decoded_len,
                actual: self.decoded_len,
            });
        }

        let digest = self.hasher.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);

        // If a trailer was declared, verify its decoded value against the
        // computed checksum. SHA-256 reuses the body SHA-256 above; every
        // other algorithm has its own hasher we drove during `copy_chunk_payload`.
        let trailer = if let Some(header) = trailer {
            let expected_bytes = aws_smithy_types::base64::decode(&header.value).map_err(|e| {
                AwsChunkedError::InvalidTrailerChecksum {
                    message: format!("base64 decode failed: {e}"),
                }
            })?;
            let computed: Vec<u8> = match header.algorithm {
                ChecksumAlgorithm::Sha256 => sha256.to_vec(),
                _ => {
                    let hasher = algo_hasher.expect(
                        "side-channel hasher was constructed for non-SHA256 trailer algorithms",
                    );
                    aws_smithy_checksums::Checksum::finalize(hasher).to_vec()
                }
            };
            if computed != expected_bytes {
                return Err(AwsChunkedError::TrailerChecksumMismatch {
                    name: header.name.clone(),
                });
            }
            Some(header)
        } else {
            None
        };

        Ok(DecodedSummary {
            decoded_len: self.decoded_len,
            sha256,
            sha256_hex: hex_encode_lower(&sha256),
            trailer,
        })
    }

    /// Read a single chunk-header line (terminated by `\r\n`) using a
    /// strictly bounded buffer. Returns the header bytes WITHOUT the
    /// trailing `\r\n`. Implemented with `fill_buf` / `consume` so we can
    /// abort with `ChunkHeaderTooLarge` BEFORE allocating past
    /// `MAX_CHUNK_HEADER_LINE_BYTES` — a malicious client that never sends
    /// `\n` can't drive unbounded memory growth.
    async fn read_chunk_header_line(&mut self) -> Result<String, AwsChunkedError> {
        let mut buf: Vec<u8> = Vec::with_capacity(128);
        let raw = loop {
            let chunk = self
                .inner
                .fill_buf()
                .await
                .map_err(|source| AwsChunkedError::InboundIo { source })?;
            if chunk.is_empty() {
                // EOF before we found a `\n`.
                if buf.is_empty() {
                    return Err(AwsChunkedError::Truncated);
                }
                return Err(AwsChunkedError::MalformedFrame {
                    message: "chunk header missing CRLF terminator".to_string(),
                });
            }
            if let Some(idx) = chunk.iter().position(|&b| b == b'\n') {
                // Including the newline byte in the line.
                let line_bytes_in_chunk = idx + 1;
                if buf.len() + line_bytes_in_chunk > MAX_CHUNK_HEADER_LINE_BYTES {
                    return Err(AwsChunkedError::ChunkHeaderTooLarge {
                        limit: MAX_CHUNK_HEADER_LINE_BYTES,
                    });
                }
                buf.extend_from_slice(&chunk[..line_bytes_in_chunk]);
                self.inner.consume(line_bytes_in_chunk);
                break buf;
            }
            // No newline in this batch — append everything we saw (subject
            // to the cap) and loop. The cap check fires BEFORE the
            // allocation that would exceed it.
            if buf.len() + chunk.len() > MAX_CHUNK_HEADER_LINE_BYTES {
                return Err(AwsChunkedError::ChunkHeaderTooLarge {
                    limit: MAX_CHUNK_HEADER_LINE_BYTES,
                });
            }
            buf.extend_from_slice(chunk);
            let consumed = chunk.len();
            self.inner.consume(consumed);
        };

        // Strip trailing \r\n; must be present and exact.
        if raw.len() < 2 || raw[raw.len() - 2] != b'\r' || raw[raw.len() - 1] != b'\n' {
            return Err(AwsChunkedError::MalformedFrame {
                message: "chunk header not terminated by CRLF".to_string(),
            });
        }
        let header_bytes = &raw[..raw.len() - 2];
        std::str::from_utf8(header_bytes)
            .map(|s| s.to_string())
            .map_err(|_| AwsChunkedError::MalformedFrame {
                message: "chunk header contained non-UTF-8 bytes".to_string(),
            })
    }

    /// Copy `chunk_size` bytes of payload from the inner reader to `writer`,
    /// updating the running body SHA-256 hasher, (for trailer modes) the
    /// algorithm-specific side-channel hasher, AND a per-chunk SHA-256
    /// hasher whose digest is returned. Strict-mode callers use the
    /// per-chunk digest as the `current-chunk-data` line of the chunk
    /// signature string-to-sign without re-reading the bytes.
    async fn copy_chunk_payload<W>(
        &mut self,
        writer: &mut W,
        chunk_size: u64,
    ) -> Result<[u8; 32], AwsChunkedError>
    where
        W: AsyncWrite + Unpin,
    {
        let mut chunk_hasher = Sha256::new();
        let mut remaining = chunk_size;
        let mut buf = [0u8; 16 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = self
                .inner
                .read(&mut buf[..want])
                .await
                .map_err(|source| AwsChunkedError::InboundIo { source })?;
            if n == 0 {
                return Err(AwsChunkedError::Truncated);
            }
            self.hasher.update(&buf[..n]);
            chunk_hasher.update(&buf[..n]);
            if let Some(h) = self.algo_hasher.as_deref_mut() {
                aws_smithy_checksums::Checksum::update(h, &buf[..n]);
            }
            writer
                .write_all(&buf[..n])
                .await
                .map_err(|source| AwsChunkedError::SpoolIo { source })?;
            remaining -= n as u64;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&chunk_hasher.finalize());
        Ok(out)
    }

    /// Read the post-final-chunk trailer line and validate it.
    ///
    /// Accepts `<name>:<value>\r\n` OR `<name>:<value>\n` — AWS docs are not
    /// consistent about whether a real SDK emits the bare-LF form, and we'd
    /// rather accept both than fail integration with a particular SDK build.
    /// The trailer NAME must case-insensitively equal `expected_name`. The
    /// trailer VALUE must be valid base64, and its decoded length must match
    /// the algorithm's expected digest size. The actual checksum-vs-body
    /// comparison happens in `finalize()`.
    async fn read_and_validate_trailer(
        &mut self,
        expected_name: &str,
        algorithm: ChecksumAlgorithm,
    ) -> Result<ChecksumHeader, AwsChunkedError> {
        let line = self.read_trailer_line(expected_name).await?;

        let (name, value) =
            line.split_once(':')
                .ok_or_else(|| AwsChunkedError::InvalidTrailer {
                    message: format!("trailer header missing `:` separator: `{line}`"),
                })?;
        let trimmed_name = name.trim();
        let trimmed_value = value.trim();

        if !trimmed_name.eq_ignore_ascii_case(expected_name) {
            return Err(AwsChunkedError::InvalidTrailer {
                message: format!(
                    "trailer header name `{trimmed_name}` does not match declared `{expected_name}`",
                ),
            });
        }

        let decoded = aws_smithy_types::base64::decode(trimmed_value).map_err(|e| {
            AwsChunkedError::InvalidTrailerChecksum {
                message: format!("base64 decode failed: {e}"),
            }
        })?;
        if decoded.len() != algorithm.digest_len() {
            return Err(AwsChunkedError::InvalidTrailerChecksum {
                message: format!(
                    "trailer for {expected_name} decoded to {} bytes, expected {}",
                    decoded.len(),
                    algorithm.digest_len(),
                ),
            });
        }

        Ok(ChecksumHeader {
            algorithm,
            name: algorithm.header_name().to_string(),
            value: trimmed_value.to_string(),
        })
    }

    /// Read the `x-amz-trailer-signature:<64 hex>` line that follows the
    /// declared trailer on signed-trailer uploads. Shape-validates the
    /// 64-lowercase-hex form and returns the value so a strict-mode
    /// caller can drive [`StreamingSigV4Context::verify_trailer`] over it.
    /// The trailing line terminator (CRLF or bare LF) is consumed.
    async fn read_and_validate_trailer_signature(&mut self) -> Result<String, AwsChunkedError> {
        let line = self
            .read_trailer_line("x-amz-trailer-signature")
            .await
            .map_err(|e| match e {
                AwsChunkedError::Truncated | AwsChunkedError::MissingTrailer { .. } => {
                    AwsChunkedError::InvalidTrailerSignature {
                        message: "x-amz-trailer-signature line missing".to_string(),
                    }
                }
                other => other,
            })?;

        let (name, value) =
            line.split_once(':')
                .ok_or_else(|| AwsChunkedError::InvalidTrailerSignature {
                    message: format!("missing `:` separator: `{line}`"),
                })?;
        if !name.trim().eq_ignore_ascii_case("x-amz-trailer-signature") {
            return Err(AwsChunkedError::InvalidTrailerSignature {
                message: format!("unexpected name `{name}`"),
            });
        }
        let sig = value.trim();
        if sig.len() != CHUNK_SIGNATURE_HEX_LEN {
            return Err(AwsChunkedError::InvalidTrailerSignature {
                message: format!(
                    "x-amz-trailer-signature must be {CHUNK_SIGNATURE_HEX_LEN} hex chars, got {}",
                    sig.len(),
                ),
            });
        }
        if !sig.bytes().all(is_lower_hex_byte) {
            return Err(AwsChunkedError::InvalidTrailerSignature {
                message: "x-amz-trailer-signature must be lowercase hex".to_string(),
            });
        }
        Ok(sig.to_string())
    }

    /// Read one trailer line. Accepts either `\r\n` or bare `\n` as terminator;
    /// the returned string excludes that terminator. The line bytes are
    /// bounded by `MAX_TRAILER_LINE_BYTES` (same cap as chunk headers).
    /// `expected_name` is used only for error messages — name validation is
    /// done by the caller.
    async fn read_trailer_line(&mut self, expected_name: &str) -> Result<String, AwsChunkedError> {
        let mut buf: Vec<u8> = Vec::with_capacity(64);
        let raw = loop {
            let chunk = self
                .inner
                .fill_buf()
                .await
                .map_err(|source| AwsChunkedError::InboundIo { source })?;
            if chunk.is_empty() {
                if buf.is_empty() {
                    return Err(AwsChunkedError::MissingTrailer {
                        name: expected_name.to_string(),
                    });
                }
                return Err(AwsChunkedError::InvalidTrailer {
                    message: "trailer line missing LF terminator".to_string(),
                });
            }
            if let Some(idx) = chunk.iter().position(|&b| b == b'\n') {
                let line_bytes_in_chunk = idx + 1;
                if buf.len() + line_bytes_in_chunk > MAX_TRAILER_LINE_BYTES {
                    return Err(AwsChunkedError::InvalidTrailer {
                        message: format!("trailer line exceeded {MAX_TRAILER_LINE_BYTES} bytes",),
                    });
                }
                buf.extend_from_slice(&chunk[..line_bytes_in_chunk]);
                self.inner.consume(line_bytes_in_chunk);
                break buf;
            }
            if buf.len() + chunk.len() > MAX_TRAILER_LINE_BYTES {
                return Err(AwsChunkedError::InvalidTrailer {
                    message: format!("trailer line exceeded {MAX_TRAILER_LINE_BYTES} bytes"),
                });
            }
            buf.extend_from_slice(chunk);
            let consumed = chunk.len();
            self.inner.consume(consumed);
        };

        // Strip terminator: accept CRLF or bare LF.
        let line_bytes = if raw.ends_with(b"\r\n") {
            &raw[..raw.len() - 2]
        } else if raw.ends_with(b"\n") {
            &raw[..raw.len() - 1]
        } else {
            return Err(AwsChunkedError::InvalidTrailer {
                message: "trailer line not terminated by LF".to_string(),
            });
        };

        if line_bytes.is_empty() {
            return Err(AwsChunkedError::MissingTrailer {
                name: expected_name.to_string(),
            });
        }

        std::str::from_utf8(line_bytes)
            .map(|s| s.to_string())
            .map_err(|_| AwsChunkedError::InvalidTrailer {
                message: "trailer line contained non-UTF-8 bytes".to_string(),
            })
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
            Err(source) => return Err(AwsChunkedError::InboundIo { source }),
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
            Err(source) => Err(AwsChunkedError::InboundIo { source }),
        }
    }
}

/// A parsed chunk-header line. `signature_hex` is borrowed from the
/// supplied `line` so callers can hand it to the verification context
/// without re-allocating; it's only `Some` when the mode expected a
/// signature AND the header carried a syntactically valid one.
#[derive(Debug, PartialEq, Eq)]
struct ParsedChunkHeader<'a> {
    size: u64,
    signature_hex: Option<&'a str>,
}

/// Parse a chunk header line.
///
/// When `expects_signature` is true (non-trailer and signed-trailer modes),
/// the form is `<hex-size>;chunk-signature=<64 hex>`. When false (unsigned
/// trailer mode), the form is the bare `<hex-size>` with no extensions; any
/// `;`-extension is rejected.
fn parse_chunk_header(
    line: &str,
    expects_signature: bool,
) -> Result<ParsedChunkHeader<'_>, AwsChunkedError> {
    if expects_signature {
        // Split on the first `;`. Anything before is the hex size; the
        // remainder must be exactly `chunk-signature=<64 hex>`.
        let (size_part, sig_part) =
            line.split_once(';')
                .ok_or_else(|| AwsChunkedError::MalformedFrame {
                    message: format!(
                        "chunk header missing `;chunk-signature=` extension: `{line}`",
                    ),
                })?;

        let size = parse_chunk_size(size_part)?;

        let sig_hex = sig_part.strip_prefix("chunk-signature=").ok_or_else(|| {
            AwsChunkedError::MalformedFrame {
                message: format!(
                    "chunk header extension is not `chunk-signature=...`: `{sig_part}`",
                ),
            }
        })?;
        if sig_hex.len() != CHUNK_SIGNATURE_HEX_LEN {
            return Err(AwsChunkedError::MalformedFrame {
                message: format!(
                    "chunk-signature must be {CHUNK_SIGNATURE_HEX_LEN} hex chars, got {}",
                    sig_hex.len(),
                ),
            });
        }
        if !sig_hex.bytes().all(is_lower_hex_byte) {
            return Err(AwsChunkedError::MalformedFrame {
                message: "chunk-signature must be lowercase hex".to_string(),
            });
        }
        Ok(ParsedChunkHeader {
            size,
            signature_hex: Some(sig_hex),
        })
    } else {
        // Unsigned trailer mode: bare `<hex-size>`. Any extension — including
        // a spurious `chunk-signature` — is a framing violation. Rejecting
        // here is the load-bearing classifier: a signature appearing on an
        // unsigned-trailer chunk is the kind of thing a client SDK might do
        // by mistake, and forwarding it would mean we accepted a stream we
        // didn't actually validate.
        if line.contains(';') {
            return Err(AwsChunkedError::MalformedFrame {
                message: format!(
                    "unsigned-trailer chunk header must be bare `<hex-size>` without extensions, got `{line}`",
                ),
            });
        }
        Ok(ParsedChunkHeader {
            size: parse_chunk_size(line)?,
            signature_hex: None,
        })
    }
}

fn parse_chunk_size(size_part: &str) -> Result<u64, AwsChunkedError> {
    if size_part.is_empty() {
        return Err(AwsChunkedError::MalformedFrame {
            message: "chunk header had empty size field".to_string(),
        });
    }
    u64::from_str_radix(size_part, 16).map_err(|_| AwsChunkedError::MalformedFrame {
        message: format!("chunk size is not valid hex: `{size_part}`"),
    })
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

    /// Proves `MAX_CHUNK_HEADER_LINE_BYTES` is enforced incrementally during
    /// the header read — a malicious stream that emits bytes in small
    /// batches WITHOUT a `\n` must abort with `ChunkHeaderTooLarge` rather
    /// than buffer the entire stream first.
    #[tokio::test]
    async fn test_chunk_header_unbounded_without_newline_errors() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncRead, ReadBuf};

        /// AsyncRead that yields one chunk of `chunk_bytes` `a`s per poll, up
        /// to `chunks` polls, then EOF. Never emits `\n`. By sizing chunks to
        /// `MAX_CHUNK_HEADER_LINE_BYTES / 4` we force the decoder to either
        /// (a) bail out partway with `ChunkHeaderTooLarge`, or (b) keep
        /// accumulating bytes past the limit (the bug we're guarding).
        struct DripReader {
            chunk_bytes: usize,
            chunks_remaining: usize,
        }
        impl AsyncRead for DripReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if self.chunks_remaining == 0 {
                    return Poll::Ready(Ok(()));
                }
                let want = buf.remaining().min(self.chunk_bytes);
                buf.put_slice(&vec![b'a'; want]);
                self.chunks_remaining -= 1;
                Poll::Ready(Ok(()))
            }
        }

        // Emit ~8 KiB total in 5 batches, no newline. The load-bearing
        // guarantee: the decoder must reject before extending its buffer
        // past `MAX_CHUNK_HEADER_LINE_BYTES`, regardless of how the bytes
        // are paced. We size each batch as a quarter of the cap so the
        // cap fires partway through this stream rather than after the
        // entire 8 KiB has been buffered.
        let reader = DripReader {
            chunk_bytes: MAX_CHUNK_HEADER_LINE_BYTES / 4,
            chunks_remaining: 5,
        };
        let mut sink: tokio::io::BufWriter<Vec<u8>> = tokio::io::BufWriter::new(Vec::new());
        let err = AwsChunkedDecoder::new(reader, 1)
            .decode_to_writer(&mut sink)
            .await
            .expect_err("must error before exhausting the drip stream");
        match err {
            AwsChunkedError::ChunkHeaderTooLarge { limit } => {
                assert_eq!(limit, MAX_CHUNK_HEADER_LINE_BYTES);
            }
            other => panic!("expected ChunkHeaderTooLarge, got {other:?}"),
        }
    }

    // ---- trailer-mode coverage ----

    use crate::s3::checksum::ChecksumAlgorithm;
    use aws_smithy_types::base64;

    /// Compute the base64-encoded checksum that the spec says should appear in
    /// the trailer for the given algorithm + body. Matches what a compliant
    /// client SDK emits.
    fn compute_trailer_value(algo: ChecksumAlgorithm, body: &[u8]) -> String {
        match algo {
            ChecksumAlgorithm::Sha256 => {
                use sha2::Digest;
                let bytes = sha2::Sha256::digest(body);
                base64::encode(&bytes[..])
            }
            _ => {
                let mut hasher = algo.into_smithy_impl();
                aws_smithy_checksums::Checksum::update(hasher.as_mut(), body);
                let bytes = aws_smithy_checksums::Checksum::finalize(hasher);
                base64::encode(&bytes[..])
            }
        }
    }

    /// Build an unsigned-trailer frame: bare-size chunks (no signature) +
    /// final `0\r\n` + trailer line + closing `\r\n`.
    fn build_unsigned_trailer_frame(
        chunks: &[&[u8]],
        trailer_name: &str,
        trailer_value: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            out.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n");
        out.extend_from_slice(format!("{trailer_name}:{trailer_value}\r\n").as_bytes());
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Build a signed-trailer frame: signed chunks (with `;chunk-signature=`)
    /// + signed final `0;chunk-signature=...\r\n` + trailer line + trailer
    ///   signature line + closing `\r\n`.
    fn build_signed_trailer_frame(
        chunks: &[&[u8]],
        trailer_name: &str,
        trailer_value: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            out.extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("0;chunk-signature={SIG}\r\n").as_bytes());
        out.extend_from_slice(format!("{trailer_name}:{trailer_value}\r\n").as_bytes());
        out.extend_from_slice(format!("x-amz-trailer-signature:{SIG}\r\n").as_bytes());
        out.extend_from_slice(b"\r\n");
        out
    }

    async fn decode_with_mode(
        frame: &[u8],
        declared_len: u64,
        mode: DecoderMode,
    ) -> Result<(Vec<u8>, DecodedSummary), AwsChunkedError> {
        let mut sink: BufWriter<Vec<u8>> = BufWriter::new(Vec::new());
        let summary = AwsChunkedDecoder::with_mode(frame, declared_len, mode)
            .decode_to_writer(&mut sink)
            .await?;
        sink.flush().await.unwrap();
        Ok((sink.into_inner(), summary))
    }

    fn unsigned_mode(algo: ChecksumAlgorithm) -> DecoderMode {
        DecoderMode::UnsignedTrailer {
            expected_trailer_name: algo.header_name().to_string(),
            algorithm: algo,
        }
    }

    fn signed_mode(algo: ChecksumAlgorithm) -> DecoderMode {
        DecoderMode::SignedTrailer {
            expected_trailer_name: algo.header_name().to_string(),
            algorithm: algo,
        }
    }

    /// Tests that every algorithm decodes a well-formed unsigned-trailer
    /// frame and reports the validated trailer in the summary. Sweeps the
    /// full algorithm matrix so a typo in `header_name()` or `digest_len()`
    /// is caught at the algorithm boundary.
    #[tokio::test]
    async fn test_unsigned_trailer_success_per_algorithm() {
        let payload = b"abcdefgh";
        for algo in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32C,
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumAlgorithm::Sha1,
            ChecksumAlgorithm::Sha256,
        ] {
            let value = compute_trailer_value(algo, payload);
            let frame = build_unsigned_trailer_frame(&[payload], algo.header_name(), &value);
            let (decoded, summary) =
                decode_with_mode(&frame, payload.len() as u64, unsigned_mode(algo))
                    .await
                    .unwrap_or_else(|e| panic!("decode for {algo:?} failed: {e:?}"));
            assert_eq!(decoded, payload);
            let trailer = summary.trailer.expect("trailer must be present");
            assert_eq!(trailer.algorithm, algo);
            assert_eq!(trailer.name, algo.header_name());
            assert_eq!(trailer.value, value);
        }
    }

    /// Same matrix as unsigned-trailer, against the signed-trailer mode.
    #[tokio::test]
    async fn test_signed_trailer_success_per_algorithm() {
        let payload = b"abcdefgh";
        for algo in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32C,
            ChecksumAlgorithm::Crc64Nvme,
            ChecksumAlgorithm::Sha1,
            ChecksumAlgorithm::Sha256,
        ] {
            let value = compute_trailer_value(algo, payload);
            let frame = build_signed_trailer_frame(&[payload], algo.header_name(), &value);
            let (decoded, summary) =
                decode_with_mode(&frame, payload.len() as u64, signed_mode(algo))
                    .await
                    .unwrap_or_else(|e| panic!("signed decode for {algo:?} failed: {e:?}"));
            assert_eq!(decoded, payload);
            let trailer = summary.trailer.expect("trailer must be present");
            assert_eq!(trailer.algorithm, algo);
            assert_eq!(trailer.value, value);
        }
    }

    /// AWS docs are inconsistent about whether trailer lines end with CRLF or
    /// bare LF; we accept both so we don't fail integration with a specific
    /// SDK build. This proves bare-LF works on the unsigned path.
    #[tokio::test]
    async fn test_unsigned_trailer_bare_lf_terminator_accepted() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        // Hand-build the frame with bare LF after the trailer value.
        let mut frame = Vec::new();
        frame.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n0\r\n");
        frame.extend_from_slice(format!("{}:{value}\n", algo.header_name()).as_bytes());
        frame.extend_from_slice(b"\r\n");
        let (_, summary) = decode_with_mode(&frame, payload.len() as u64, unsigned_mode(algo))
            .await
            .unwrap();
        assert_eq!(summary.trailer.unwrap().value, value);
    }

    /// Companion: bare-LF after the trailer line is accepted on signed mode
    /// too. The trailer-signature line still uses CRLF so we can isolate the
    /// terminator-flexibility test to just the trailer line itself.
    #[tokio::test]
    async fn test_signed_trailer_bare_lf_terminator_accepted() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Sha1;
        let value = compute_trailer_value(algo, payload);
        let mut frame = Vec::new();
        frame
            .extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(format!("0;chunk-signature={SIG}\r\n").as_bytes());
        // Bare LF after the trailer value.
        frame.extend_from_slice(format!("{}:{value}\n", algo.header_name()).as_bytes());
        frame.extend_from_slice(format!("x-amz-trailer-signature:{SIG}\r\n").as_bytes());
        frame.extend_from_slice(b"\r\n");
        let (_, summary) = decode_with_mode(&frame, payload.len() as u64, signed_mode(algo))
            .await
            .unwrap();
        assert_eq!(summary.trailer.unwrap().value, value);
    }

    /// Declared trailer was CRC32 but the body carries `x-amz-checksum-sha256`.
    /// Reject as InvalidTrailer — the proxy must not silently accept a
    /// mismatched name because the value happens to base64-decode.
    #[tokio::test]
    async fn test_trailer_name_mismatch_rejected() {
        let payload = b"abcdefgh";
        let value = compute_trailer_value(ChecksumAlgorithm::Sha256, payload);
        // Frame uses the SHA256 trailer name but the mode expects CRC32.
        let frame = build_unsigned_trailer_frame(&[payload], "x-amz-checksum-sha256", &value);
        let err = decode_with_mode(
            &frame,
            payload.len() as u64,
            unsigned_mode(ChecksumAlgorithm::Crc32),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::InvalidTrailer { .. }),
            "got {err:?}",
        );
    }

    /// No trailer line at all on a mode that requires one — the stream just
    /// ends after the final `0\r\n`. Surface MissingTrailer so the handler
    /// can produce a specific InvalidRequest message.
    #[tokio::test]
    async fn test_trailer_missing_rejected() {
        let payload = b"abcdefgh";
        // Skip the trailer line entirely: `0\r\n` then closing `\r\n`.
        let mut frame = Vec::new();
        frame.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n0\r\n\r\n");
        let err = decode_with_mode(
            &frame,
            payload.len() as u64,
            unsigned_mode(ChecksumAlgorithm::Crc32),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MissingTrailer { .. }),
            "got {err:?}",
        );
    }

    /// A SECOND trailer-style line after the declared one is illegal — only
    /// one trailer is allowed per upload. The decoder rejects on the EOF
    /// expectation after the closing CRLF.
    #[tokio::test]
    async fn test_extra_trailer_line_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        let mut frame = Vec::new();
        frame.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n0\r\n");
        // Two trailer lines, then closing CRLF.
        frame.extend_from_slice(format!("{}:{value}\r\n", algo.header_name()).as_bytes());
        frame.extend_from_slice(b"x-amz-extra-thing:abc\r\n");
        frame.extend_from_slice(b"\r\n");
        let err = decode_with_mode(&frame, payload.len() as u64, unsigned_mode(algo))
            .await
            .unwrap_err();
        // The extra line is read as "the closing \r\n", which makes
        // expect_eof fire on the next bytes — but the more common surfaced
        // error is TrailingData. Accept either of those framing errors.
        assert!(
            matches!(
                err,
                AwsChunkedError::TrailingData
                    | AwsChunkedError::InvalidTrailer { .. }
                    | AwsChunkedError::MalformedFrame { .. }
            ),
            "got {err:?}",
        );
    }

    /// Trailer value isn't valid base64. Reject as InvalidTrailerChecksum so
    /// the handler can produce an InvalidDigest response.
    #[tokio::test]
    async fn test_trailer_invalid_base64_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        // `!` is not a valid base64 char.
        let frame = build_unsigned_trailer_frame(&[payload], algo.header_name(), "!!!!");
        let err = decode_with_mode(&frame, payload.len() as u64, unsigned_mode(algo))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::InvalidTrailerChecksum { .. }),
            "got {err:?}",
        );
    }

    /// Trailer value decodes cleanly but the decoded length doesn't match
    /// the declared algorithm. Catches a CRC32 trailer-name carrying a
    /// SHA-256 value, for example.
    #[tokio::test]
    async fn test_trailer_wrong_digest_length_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        // Use a SHA-256-sized digest (32 bytes) as the trailer value.
        let oversized = base64::encode(vec![0u8; 32]);
        let frame = build_unsigned_trailer_frame(&[payload], algo.header_name(), &oversized);
        let err = decode_with_mode(&frame, payload.len() as u64, unsigned_mode(algo))
            .await
            .unwrap_err();
        match err {
            AwsChunkedError::InvalidTrailerChecksum { message } => {
                assert!(
                    message.contains("decoded to 32 bytes"),
                    "error should cite the wrong byte count, got: {message}",
                );
            }
            other => panic!("expected InvalidTrailerChecksum, got {other:?}"),
        }
    }

    /// Load-bearing integrity check: a well-formed, correctly-sized trailer
    /// whose value doesn't match the actual digest must produce
    /// `TrailerChecksumMismatch`. This is the case where the handler returns
    /// `BadDigest`.
    ///
    /// Bug-revert reasoning: removing the checksum comparison inside
    /// `finalize()` would make this test pass with `Ok(...)`. We verified
    /// that by temporarily commenting out the `if computed != expected_bytes`
    /// branch before re-enabling it; with the check disabled the assertion
    /// here flips and the test fails with "expected error, got Ok(...)".
    #[tokio::test]
    async fn test_trailer_checksum_mismatch_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        // Right shape (4 bytes of base64), wrong value.
        let wrong = base64::encode(b"WRNG");
        let frame = build_unsigned_trailer_frame(&[payload], algo.header_name(), &wrong);
        let err = decode_with_mode(&frame, payload.len() as u64, unsigned_mode(algo))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::TrailerChecksumMismatch { .. }),
            "got {err:?}",
        );
    }

    /// Signed-trailer mode whose `x-amz-trailer-signature` line is missing
    /// (frame ends right after the data trailer's CRLF). Surface as
    /// InvalidTrailerSignature so the handler returns InvalidRequest.
    #[tokio::test]
    async fn test_signed_trailer_missing_signature_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        let mut frame = Vec::new();
        frame
            .extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(format!("0;chunk-signature={SIG}\r\n").as_bytes());
        frame.extend_from_slice(format!("{}:{value}\r\n", algo.header_name()).as_bytes());
        // Trailer signature omitted; just a closing CRLF.
        frame.extend_from_slice(b"\r\n");
        let err = decode_with_mode(&frame, payload.len() as u64, signed_mode(algo))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                AwsChunkedError::InvalidTrailerSignature { .. }
                    | AwsChunkedError::MissingTrailer { .. }
            ),
            "got {err:?}",
        );
    }

    /// Signed-trailer with a non-hex `x-amz-trailer-signature` value. Catches
    /// regressions in the shape-check (which is the only check we do until #63).
    #[tokio::test]
    async fn test_signed_trailer_non_hex_signature_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        // 64-char signature but with a non-hex `z` planted at the front.
        let bad_sig = "z".to_string() + &"0".repeat(63);
        let mut frame = Vec::new();
        frame
            .extend_from_slice(format!("{:x};chunk-signature={SIG}\r\n", payload.len()).as_bytes());
        frame.extend_from_slice(payload);
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(format!("0;chunk-signature={SIG}\r\n").as_bytes());
        frame.extend_from_slice(format!("{}:{value}\r\n", algo.header_name()).as_bytes());
        frame.extend_from_slice(format!("x-amz-trailer-signature:{bad_sig}\r\n").as_bytes());
        frame.extend_from_slice(b"\r\n");
        let err = decode_with_mode(&frame, payload.len() as u64, signed_mode(algo))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::InvalidTrailerSignature { .. }),
            "got {err:?}",
        );
    }

    /// Unsigned-trailer mode must reject a chunk header that carries a
    /// `;chunk-signature=` extension. Bug-revert reasoning: removing the
    /// `line.contains(';')` guard in `parse_chunk_header(_, false)` would let
    /// signed framing slip past the unsigned classifier and the proxy would
    /// silently accept a stream it never validated as unsigned. Verified by
    /// commenting out the guard — the assertion below flipped to Ok().
    #[tokio::test]
    async fn test_unsigned_mode_with_signed_chunk_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        // Build a SIGNED frame, then try to decode it in UNSIGNED mode.
        let frame = build_signed_trailer_frame(&[payload], algo.header_name(), &value);
        let err = decode_with_mode(&frame, payload.len() as u64, unsigned_mode(algo))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}",
        );
    }

    /// Signed mode with a bare-size chunk header (no signature). Must reject
    /// — these are framing classes we explicitly route differently.
    #[tokio::test]
    async fn test_signed_mode_with_bare_size_chunk_rejected() {
        let payload = b"abcdefgh";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        // Build an UNSIGNED frame, then try to decode it in SIGNED mode.
        let frame = build_unsigned_trailer_frame(&[payload], algo.header_name(), &value);
        let err = decode_with_mode(&frame, payload.len() as u64, signed_mode(algo))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}",
        );
    }

    // ---- parse_chunk_header unit-level coverage ----

    #[test]
    fn test_parse_header_uppercase_hex_signature_rejected() {
        // 64 uppercase hex characters — protocol mandates lowercase.
        let upper = "0".repeat(63) + "A";
        let line = format!("8;chunk-signature={upper}");
        let err = parse_chunk_header(&line, true).unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_parse_header_empty_size_rejected() {
        let line = format!(";chunk-signature={SIG}");
        let err = parse_chunk_header(&line, true).unwrap_err();
        assert!(
            matches!(err, AwsChunkedError::MalformedFrame { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn test_parse_header_returns_signature_hex() {
        let line = format!("8;chunk-signature={SIG}");
        let parsed = parse_chunk_header(&line, true).expect("valid signed header");
        assert_eq!(parsed.size, 8);
        assert_eq!(parsed.signature_hex, Some(SIG));
    }

    #[test]
    fn test_parse_header_unsigned_has_no_signature() {
        let parsed = parse_chunk_header("8", false).expect("valid unsigned header");
        assert_eq!(parsed.size, 8);
        assert_eq!(parsed.signature_hex, None);
    }

    // ---- strict-mode chunk-signature verification coverage ----

    use crate::auth::sigv4::streaming::{EMPTY_SHA256_HEX, StreamingSigV4Context};

    /// Test signing key shared across the verification tests below. Same
    /// derivation as `streaming.rs::tests::example_signing_key`, kept
    /// inline so the verification tests don't depend on a `#[cfg(test)]`
    /// import from another module.
    fn test_signing_key() -> [u8; 32] {
        use hmac::{Hmac, KeyInit, Mac};
        type HmacSha256 = Hmac<Sha256>;
        fn h(k: &[u8], d: &[u8]) -> Vec<u8> {
            let mut m = HmacSha256::new_from_slice(k).unwrap();
            m.update(d);
            m.finalize().into_bytes().to_vec()
        }
        let k_date = h(b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", b"20130524");
        let k_region = h(&k_date, b"us-east-1");
        let k_service = h(&k_region, b"s3");
        let k_signing = h(&k_service, b"aws4_request");
        let mut out = [0u8; 32];
        out.copy_from_slice(&k_signing);
        out
    }

    const TEST_AMZ_DATE: &str = "20130524T000000Z";
    const TEST_SCOPE: &str = "20130524/us-east-1/s3/aws4_request";
    const TEST_SEED_SIG: &str =
        "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";

    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        use hmac::{Hmac, KeyInit, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut m = HmacSha256::new_from_slice(key).unwrap();
        m.update(data);
        let r = m.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    }

    /// Compute the expected chunk signature for the given chunk payload
    /// chained from `prev_sig`. Returns `(sig_hex, sig_chain_next)` where
    /// `sig_chain_next` is just the same hex, surfaced for ergonomics so
    /// the caller can thread it into the next chunk's seed.
    fn compute_chunk_sig(key: &[u8; 32], prev_sig: &str, chunk: &[u8]) -> String {
        let chunk_hash = sha2::Sha256::digest(chunk);
        let chunk_hash_hex = hex_encode_lower(&chunk_hash);
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{TEST_AMZ_DATE}\n{TEST_SCOPE}\n{prev_sig}\n{EMPTY_SHA256_HEX}\n{chunk_hash_hex}",
        );
        hex_encode_lower(&hmac_sha256(key, sts.as_bytes()))
    }

    fn compute_zero_chunk_sig(key: &[u8; 32], prev_sig: &str) -> String {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{TEST_AMZ_DATE}\n{TEST_SCOPE}\n{prev_sig}\n{EMPTY_SHA256_HEX}\n{EMPTY_SHA256_HEX}",
        );
        hex_encode_lower(&hmac_sha256(key, sts.as_bytes()))
    }

    fn compute_trailer_sig(key: &[u8; 32], prev_sig: &str, canonical_bytes: &[u8]) -> String {
        let trailer_hash = sha2::Sha256::digest(canonical_bytes);
        let trailer_hash_hex = hex_encode_lower(&trailer_hash);
        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{TEST_AMZ_DATE}\n{TEST_SCOPE}\n{prev_sig}\n{trailer_hash_hex}",
        );
        hex_encode_lower(&hmac_sha256(key, sts.as_bytes()))
    }

    /// Build a non-trailer signed chunk stream with valid chained
    /// signatures over `chunks` (data) plus the terminating zero chunk.
    fn build_signed_non_trailer_stream(key: &[u8; 32], chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = TEST_SEED_SIG.to_string();
        for c in chunks {
            let sig = compute_chunk_sig(key, &prev, c);
            out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
            prev = sig;
        }
        let zero_sig = compute_zero_chunk_sig(key, &prev);
        out.extend_from_slice(format!("0;chunk-signature={zero_sig}\r\n\r\n").as_bytes());
        out
    }

    /// Build a signed-trailer stream including a valid trailer line +
    /// trailer signature.
    fn build_signed_trailer_stream(
        key: &[u8; 32],
        chunks: &[&[u8]],
        trailer_name: &str,
        trailer_value: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = TEST_SEED_SIG.to_string();
        for c in chunks {
            let sig = compute_chunk_sig(key, &prev, c);
            out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
            prev = sig;
        }
        let zero_sig = compute_zero_chunk_sig(key, &prev);
        out.extend_from_slice(format!("0;chunk-signature={zero_sig}\r\n").as_bytes());

        let canonical = format!("{}:{}\n", trailer_name.to_ascii_lowercase(), trailer_value);
        let trailer_sig = compute_trailer_sig(key, &zero_sig, canonical.as_bytes());

        out.extend_from_slice(format!("{trailer_name}:{trailer_value}\r\n").as_bytes());
        out.extend_from_slice(format!("x-amz-trailer-signature:{trailer_sig}\r\n").as_bytes());
        out.extend_from_slice(b"\r\n");
        out
    }

    fn verify_ctx() -> ChunkSignaturePolicy {
        ChunkSignaturePolicy::Verify(StreamingSigV4Context::from_parts(
            test_signing_key(),
            TEST_AMZ_DATE,
            TEST_SCOPE,
            TEST_SEED_SIG,
        ))
    }

    async fn decode_with_policy(
        frame: &[u8],
        declared_len: u64,
        mode: DecoderMode,
        policy: ChunkSignaturePolicy,
    ) -> Result<(Vec<u8>, DecodedSummary), AwsChunkedError> {
        let mut sink: BufWriter<Vec<u8>> = BufWriter::new(Vec::new());
        let summary = AwsChunkedDecoder::with_mode_and_signature_policy(
            frame,
            declared_len,
            mode,
            policy,
        )
        .decode_to_writer(&mut sink)
        .await?;
        sink.flush().await.unwrap();
        Ok((sink.into_inner(), summary))
    }

    /// A well-formed signed non-trailer stream decodes cleanly under
    /// `Verify`. The 8 KiB minimum applies to non-final chunks so a
    /// single-chunk stream uses a small payload.
    #[tokio::test]
    async fn test_decoder_verifies_signed_non_trailer_chunks() {
        let key = test_signing_key();
        let payload = b"hello-streaming";
        let frame = build_signed_non_trailer_stream(&key, &[payload]);
        let (decoded, summary) = decode_with_policy(
            &frame,
            payload.len() as u64,
            DecoderMode::NonTrailer,
            verify_ctx(),
        )
        .await
        .expect("valid signed chunks must verify");
        assert_eq!(decoded, payload);
        assert_eq!(summary.decoded_len, payload.len() as u64);
    }

    /// Well-formed signed-trailer stream + valid trailer signature decodes
    /// cleanly under `Verify`.
    #[tokio::test]
    async fn test_decoder_verifies_signed_trailer_chunks_and_trailer() {
        let key = test_signing_key();
        let payload = b"hello-trailer";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        let frame =
            build_signed_trailer_stream(&key, &[payload], algo.header_name(), &value);
        let mode = signed_mode(algo);
        let (decoded, summary) = decode_with_policy(&frame, payload.len() as u64, mode, verify_ctx())
            .await
            .expect("valid signed trailer stream must verify");
        assert_eq!(decoded, payload);
        let t = summary.trailer.unwrap();
        assert_eq!(t.value, value);
    }

    /// Corrupting a payload chunk's signature must surface
    /// `ChunkSignatureMismatch` with the right chunk index.
    ///
    /// Bug-revert reasoning: removing the `Verify(...)` branch in the
    /// decoder loop OR forgetting to propagate `verify_payload_chunk`'s
    /// error makes this test pass with `Ok(...)`. Validated by
    /// temporarily commenting out the verification branch — the test
    /// fails with "expected error, got Ok(_)".
    #[tokio::test]
    async fn test_decoder_rejects_chunk_signature_mismatch() {
        let key = test_signing_key();
        let payload = b"hello-streaming";
        let mut frame = build_signed_non_trailer_stream(&key, &[payload]);
        // Locate the chunk header and flip one hex char of the signature.
        let sig_idx = frame
            .windows(b"chunk-signature=".len())
            .position(|w| w == b"chunk-signature=")
            .unwrap()
            + b"chunk-signature=".len();
        // Bump the byte if it's '0' to '1', else swap to '0'.
        frame[sig_idx] = if frame[sig_idx] == b'0' { b'1' } else { b'0' };
        let err = decode_with_policy(
            &frame,
            payload.len() as u64,
            DecoderMode::NonTrailer,
            verify_ctx(),
        )
        .await
        .expect_err("tampered chunk signature must fail");
        match err {
            AwsChunkedError::ChunkSignatureMismatch { chunk_index } => {
                assert_eq!(chunk_index, 0, "first chunk's signature was tampered");
            }
            other => panic!("expected ChunkSignatureMismatch, got {other:?}"),
        }
    }

    /// Valid data chunks but corrupted zero-chunk signature must surface
    /// `ChunkSignatureMismatch` (the zero chunk is still a signed payload
    /// chunk from the protocol's perspective).
    #[tokio::test]
    async fn test_decoder_rejects_zero_chunk_signature_mismatch() {
        let key = test_signing_key();
        let payload = b"hello-streaming";
        let mut frame = build_signed_non_trailer_stream(&key, &[payload]);
        // Find the zero chunk's `chunk-signature=` (the LAST occurrence).
        let occurrences: Vec<usize> = frame
            .windows(b"chunk-signature=".len())
            .enumerate()
            .filter_map(|(i, w)| (w == b"chunk-signature=").then_some(i))
            .collect();
        let zero_sig_idx = *occurrences.last().unwrap() + b"chunk-signature=".len();
        frame[zero_sig_idx] = if frame[zero_sig_idx] == b'0' { b'1' } else { b'0' };
        let err = decode_with_policy(
            &frame,
            payload.len() as u64,
            DecoderMode::NonTrailer,
            verify_ctx(),
        )
        .await
        .expect_err("tampered zero-chunk signature must fail");
        assert!(
            matches!(err, AwsChunkedError::ChunkSignatureMismatch { .. }),
            "got {err:?}",
        );
    }

    /// Valid chunks + trailer line, but corrupted
    /// `x-amz-trailer-signature` value must surface
    /// `TrailerSignatureMismatch`.
    ///
    /// Bug-revert reasoning: dropping the trailer-signature verification
    /// in `finalize()` (i.e. ignoring the return of
    /// `read_and_validate_trailer_signature`) lets this test pass with
    /// `Ok(...)` — the assertion flips.
    #[tokio::test]
    async fn test_decoder_rejects_trailer_signature_mismatch() {
        let key = test_signing_key();
        let payload = b"hello-trailer";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        let mut frame =
            build_signed_trailer_stream(&key, &[payload], algo.header_name(), &value);
        // Tamper the x-amz-trailer-signature value.
        let needle = b"x-amz-trailer-signature:";
        let idx = frame.windows(needle.len()).position(|w| w == needle).unwrap()
            + needle.len();
        frame[idx] = if frame[idx] == b'0' { b'1' } else { b'0' };
        let err = decode_with_policy(&frame, payload.len() as u64, signed_mode(algo), verify_ctx())
            .await
            .expect_err("tampered trailer signature must fail");
        assert!(
            matches!(err, AwsChunkedError::TrailerSignatureMismatch),
            "got {err:?}",
        );
    }

    /// A second chunk whose signature does NOT chain from the first
    /// chunk's signature must reject. The helper signs each chunk
    /// correctly, so we tamper by swapping in a signature computed
    /// against the SEED (wrong previous-sig).
    #[tokio::test]
    async fn test_decoder_rejects_mid_chain_signature_mismatch() {
        let key = test_signing_key();
        let c1 = vec![b'A'; 10_000];
        let c2 = vec![b'B'; 10_000];
        // Build the legitimate stream, then replace chunk 2's signature
        // with one computed against the SEED instead of chunk 1's sig.
        let mut frame = build_signed_non_trailer_stream(&key, &[&c1, &c2]);
        // Wrong "previous" — the seed signature — so the chain breaks.
        let wrong_c2_sig = compute_chunk_sig(&key, TEST_SEED_SIG, &c2);

        // Find chunk 2's `chunk-signature=` (the SECOND occurrence).
        let occurrences: Vec<usize> = frame
            .windows(b"chunk-signature=".len())
            .enumerate()
            .filter_map(|(i, w)| (w == b"chunk-signature=").then_some(i))
            .collect();
        let target = occurrences[1] + b"chunk-signature=".len();
        frame[target..target + 64].copy_from_slice(wrong_c2_sig.as_bytes());

        let total = (c1.len() + c2.len()) as u64;
        let err = decode_with_policy(&frame, total, DecoderMode::NonTrailer, verify_ctx())
            .await
            .expect_err("broken chain must fail");
        match err {
            AwsChunkedError::ChunkSignatureMismatch { chunk_index } => {
                assert_eq!(chunk_index, 1);
            }
            other => panic!("expected ChunkSignatureMismatch on chunk 1, got {other:?}"),
        }
    }

    /// `ShapeOnly` (trust mode) accepts a stream whose `chunk-signature=`
    /// values are all-zeros — exactly the behavior before strict mode
    /// existed. Ensures we didn't accidentally couple verification to
    /// shape-validation.
    #[tokio::test]
    async fn test_decoder_shape_only_still_accepts_dummy_signatures() {
        let payload = b"hello-streaming";
        let frame = build_frame(&[payload]);
        let (decoded, _) = decode_with_policy(
            &frame,
            payload.len() as u64,
            DecoderMode::NonTrailer,
            ChunkSignaturePolicy::ShapeOnly,
        )
        .await
        .expect("shape-only mode must accept dummy signatures");
        assert_eq!(decoded, payload);
    }

    /// Unsigned-trailer mode has no chunk signatures to verify. Even
    /// when a `Verify` policy is supplied, the decoder must NOT touch the
    /// streaming context — there's nothing to verify per-chunk, and
    /// trailer-signature isn't part of the unsigned-trailer wire format.
    #[tokio::test]
    async fn test_unsigned_trailer_unaffected_by_chunk_policy() {
        let payload = b"unsigned-trailer-payload";
        let algo = ChecksumAlgorithm::Crc32;
        let value = compute_trailer_value(algo, payload);
        let frame = build_unsigned_trailer_frame(&[payload], algo.header_name(), &value);
        // `Verify` policy is supplied, but unsigned-trailer mode never
        // calls verify_*, so the context is harmless and the decode
        // succeeds.
        let (_decoded, summary) = decode_with_policy(
            &frame,
            payload.len() as u64,
            unsigned_mode(algo),
            verify_ctx(),
        )
        .await
        .expect("unsigned trailer must decode even with Verify policy");
        assert!(summary.trailer.is_some());
    }
}
