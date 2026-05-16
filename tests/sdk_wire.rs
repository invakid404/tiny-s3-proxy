//! SDK wire-shape regression tests for the aws-chunked override behavior in
//! `S3Backend::put_object_from_path` / `upload_part_from_path`.
//!
//! These tests pin the behavior of `aws-sdk-s3 1.132.0` /
//! `aws-smithy-checksums 0.64.7` against the override choices documented
//! in those functions. See issue #72 and the introducing PR #65.
//!
//! Each test spins up a single-shot raw `TcpListener` on `127.0.0.1:0`,
//! drives one `PutObject` call against it with a 17-byte payload, captures
//! the request bytes verbatim (no HTTP framework decoding), and asserts the
//! wire framing. The fake server returns a minimal `200 OK` with an `ETag`
//! so the SDK call completes.

use std::collections::BTreeMap;
use std::error::Error;
use std::io::Write as _;
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_sdk_s3::config::{Builder as S3ConfigBuilder, Region, RequestChecksumCalculation};
use aws_sdk_s3::primitives::ByteStream;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PAYLOAD: &[u8] = b"issue-72-payload\n";
const FAKE_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nETag: \"issue-72-etag\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[derive(Debug)]
struct CapturedRequest {
    raw: Vec<u8>,
    headers: BTreeMap<String, String>,
    header_len: usize,
}

impl CapturedRequest {
    fn body(&self) -> &[u8] {
        &self.raw[self.header_len..]
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// What override knobs to apply to the `PutObject` call.
#[derive(Clone, Copy, Default)]
struct CaseOverrides {
    per_algo_checksum_crc32: bool,
    when_required: bool,
    disable_payload_signing: bool,
}

/// Run a single PutObject against a one-shot raw HTTP listener and capture
/// the request bytes the SDK actually emitted on the wire.
async fn run_case(
    overrides: CaseOverrides,
) -> Result<CapturedRequest, Box<dyn Error + Send + Sync>> {
    let mut spool = NamedTempFile::new()?;
    spool.write_all(PAYLOAD)?;
    spool.flush()?;
    let path = spool.path().to_path_buf();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let endpoint = format!("http://{addr}");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let captured = read_http_request(&mut stream).await?;
        stream.write_all(FAKE_RESPONSE).await?;
        let _ = stream.shutdown().await;
        Ok::<CapturedRequest, Box<dyn Error + Send + Sync>>(captured)
    });

    let creds = Credentials::new("issue-72-access", "issue-72-secret", None, None, "static");
    let config = aws_sdk_s3::config::Builder::new()
        .endpoint_url(endpoint)
        .region(Region::new("us-east-1"))
        .credentials_provider(creds)
        .force_path_style(true)
        .behavior_version_latest()
        .build();
    let client = aws_sdk_s3::Client::from_conf(config);

    let body = ByteStream::from_path(&path).await?;
    let mut builder = client
        .put_object()
        .bucket("issue-72-bucket")
        .key("issue-72-key")
        .body(body);

    if overrides.per_algo_checksum_crc32 {
        // CRC32 of a zero-byte digest representation; the fake server doesn't
        // validate, so any well-formed base64 value works.
        builder = builder.checksum_crc32("AAAAAA==");
    }

    let mut customized = builder.customize();
    if overrides.when_required {
        customized = customized.config_override(
            S3ConfigBuilder::new()
                .request_checksum_calculation(RequestChecksumCalculation::WhenRequired),
        );
    }
    if overrides.disable_payload_signing {
        customized = customized.disable_payload_signing();
    }
    // The SDK send() returns an error when the connection closes without a
    // full response body, but it generally completes for our minimal 200 OK
    // before we read the captured request back. Ignore send errors — the
    // assertion is over the captured wire bytes.
    let _ = customized.send().await;

    let captured = server.await??;
    Ok(captured)
}

async fn read_http_request(
    stream: &mut TcpStream,
) -> Result<CapturedRequest, Box<dyn Error + Send + Sync>> {
    let mut raw = Vec::new();
    let header_len = loop {
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte)).await??;
        if read == 0 {
            return Err("connection closed before headers completed".into());
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break raw.len();
        }
    };

    let headers = parse_headers(&raw[..header_len])?;

    if let Some(expect) = headers.get("expect")
        && expect.eq_ignore_ascii_case("100-continue")
    {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    }

    if let Some(content_length) = headers.get("content-length") {
        let len: usize = content_length.trim().parse()?;
        read_exact_raw(stream, &mut raw, len).await?;
    } else if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        read_chunked_raw(stream, &mut raw).await?;
    }

    Ok(CapturedRequest {
        raw,
        headers,
        header_len,
    })
}

async fn read_exact_raw(
    stream: &mut TcpStream,
    raw: &mut Vec<u8>,
    len: usize,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let start = raw.len();
    raw.resize(start + len, 0);
    tokio::time::timeout(
        Duration::from_secs(10),
        stream.read_exact(&mut raw[start..]),
    )
    .await??;
    Ok(())
}

async fn read_chunked_raw(
    stream: &mut TcpStream,
    raw: &mut Vec<u8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let line = read_line_raw(stream, raw).await?;
        let size_text = line
            .split(|b| *b == b';')
            .next()
            .ok_or("missing chunk size")?;
        let size = usize::from_str_radix(std::str::from_utf8(size_text)?.trim(), 16)?;
        if size == 0 {
            loop {
                let trailer = read_line_raw(stream, raw).await?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        read_exact_raw(stream, raw, size + 2).await?;
    }
}

async fn read_line_raw(
    stream: &mut TcpStream,
    raw: &mut Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut byte)).await??;
        if read == 0 {
            return Err("connection closed mid-line".into());
        }
        raw.push(byte[0]);
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}

fn parse_headers(
    raw_headers: &[u8],
) -> Result<BTreeMap<String, String>, Box<dyn Error + Send + Sync>> {
    let text = std::str::from_utf8(raw_headers)?;
    let mut headers = BTreeMap::new();
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    Ok(headers)
}

fn has_chunk_signature(body: &[u8]) -> bool {
    body.windows(b";chunk-signature=".len())
        .any(|w| w == b";chunk-signature=")
}

// ── tests ────────────────────────────────────────────────────────────────

/// Documents the bug case: with default settings and no per-algorithm
/// checksum setter, `aws-sdk-s3 1.132.0` re-frames the file body as
/// `content-encoding: aws-chunked` with a trailer CRC32. This is the
/// behavior the overrides in `put_object_from_path` exist to suppress.
#[tokio::test]
async fn test_sdk_default_byte_stream_from_path_reframes_as_aws_chunked() {
    let captured = run_case(CaseOverrides::default()).await.expect("run_case");

    assert_eq!(
        captured.header("content-encoding"),
        Some("aws-chunked"),
        "expected aws-chunked re-framing under default SDK settings, headers={:#?}",
        captured.headers,
    );
    assert_eq!(
        captured.header("x-amz-trailer"),
        Some("x-amz-checksum-crc32"),
        "expected x-amz-trailer with CRC32, headers={:#?}",
        captured.headers,
    );
    assert_eq!(
        captured.header("x-amz-content-sha256"),
        Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"),
        "expected streaming signed trailer payload sha256, headers={:#?}",
        captured.headers,
    );
    assert!(
        has_chunk_signature(captured.body()),
        "expected body to contain aws-chunked `;chunk-signature=` framing"
    );
    assert_ne!(
        captured.body(),
        PAYLOAD,
        "body must NOT equal raw payload in the re-framed case"
    );
}

/// `request_checksum_calculation(WhenRequired)` is the load-bearing
/// override in `put_object_from_path` / `upload_part_from_path`. With it
/// applied (and no per-algorithm checksum setter), the SDK emits the raw
/// payload bytes with `UNSIGNED-PAYLOAD` sha256 and no aws-chunked
/// framing — exactly what the proxy's decode-to-raw-body path requires.
///
/// If this test starts failing with re-framed output, the `WhenRequired`
/// override has been removed or the SDK behavior shifted; investigate
/// before touching the call sites.
#[tokio::test]
async fn test_sdk_when_required_override_suppresses_reframing() {
    let captured = run_case(CaseOverrides {
        when_required: true,
        disable_payload_signing: true,
        ..CaseOverrides::default()
    })
    .await
    .expect("run_case");

    assert_eq!(
        captured.header("content-length"),
        Some(PAYLOAD.len().to_string().as_str()),
        "expected raw content-length={}, headers={:#?}",
        PAYLOAD.len(),
        captured.headers,
    );
    assert_eq!(
        captured.header("content-encoding"),
        None,
        "expected no content-encoding header in raw-body mode"
    );
    assert_eq!(
        captured.header("x-amz-trailer"),
        None,
        "expected no x-amz-trailer header in raw-body mode"
    );
    assert_eq!(
        captured.header("x-amz-content-sha256"),
        Some("UNSIGNED-PAYLOAD"),
        "expected UNSIGNED-PAYLOAD with disable_payload_signing, headers={:#?}",
        captured.headers,
    );
    assert_eq!(
        captured.body(),
        PAYLOAD,
        "expected wire body to equal the raw payload bytes"
    );
}

/// Per-algorithm checksum setters (`.checksum_crc32(...)`, etc.) also
/// suppress re-framing in `aws-sdk-s3 1.132.0`. The proxy uses this path
/// when a decoded aws-chunked upload carries a validated trailer
/// checksum (see `summary.trailer` in `put_object_from_path`).
///
/// This is the trailer-checksum path; the `WhenRequired` override is
/// still required for the `checksum: None` decoded-non-trailer path
/// covered by the test above.
#[tokio::test]
async fn test_sdk_per_algorithm_checksum_setter_suppresses_reframing() {
    let captured = run_case(CaseOverrides {
        per_algo_checksum_crc32: true,
        ..CaseOverrides::default()
    })
    .await
    .expect("run_case");

    assert_eq!(
        captured.header("content-length"),
        Some(PAYLOAD.len().to_string().as_str()),
        "expected raw content-length={}, headers={:#?}",
        PAYLOAD.len(),
        captured.headers,
    );
    assert_eq!(
        captured.header("content-encoding"),
        None,
        "expected no content-encoding header when per-algorithm checksum setter is used"
    );
    assert_eq!(
        captured.header("x-amz-trailer"),
        None,
        "expected no x-amz-trailer header when per-algorithm checksum setter is used"
    );
    assert_eq!(
        captured.header("x-amz-checksum-crc32"),
        Some("AAAAAA=="),
        "expected the per-algorithm checksum to be forwarded as a request header, headers={:#?}",
        captured.headers,
    );
    assert_eq!(
        captured.body(),
        PAYLOAD,
        "expected wire body to equal the raw payload bytes"
    );
}
