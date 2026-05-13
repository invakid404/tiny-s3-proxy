use std::collections::HashMap;
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{Builder as S3ConfigBuilder, Region, RequestChecksumCalculation};
use aws_sdk_s3::primitives::ByteStream;
use aws_smithy_types::byte_stream::Length;
use aws_smithy_types::timeout::TimeoutConfig;
use tokio_util::io::ReaderStream;

use crate::backend::models::*;
use crate::backend::retry::{RetryPolicy, with_retry};
use crate::backend::{Backend, BoxByteStream};
use crate::config::{Config, endpoint_scheme};
use crate::error::ProxyError;
use crate::s3::checksum::ChecksumAlgorithm;

/// S3 backend client that uses the aws-sdk-s3 crate to talk to an S3-compatible backend.
pub struct S3Backend {
    client: Client,
    #[allow(dead_code)]
    default_bucket: String,
    /// Whether the configured backend endpoint uses HTTPS. The aws-chunked
    /// decode path forwards bodies with `x-amz-content-sha256:
    /// UNSIGNED-PAYLOAD`, which relies on TLS for body integrity — the
    /// `put_object_from_path` / `upload_part_from_path` methods refuse to
    /// run over plaintext when this is false.
    backend_endpoint_is_https: bool,
    get_policy: RetryPolicy,
    head_policy: RetryPolicy,
    list_policy: RetryPolicy,
    put_policy: RetryPolicy,
    delete_policy: RetryPolicy,
}

impl S3Backend {
    /// Build an S3Backend from the application configuration.
    pub async fn from_config(config: &Config) -> Result<Self, ProxyError> {
        Self::from_config_inner(config, None).await
    }

    /// Build an S3Backend using a caller-supplied outbound HTTP client. The
    /// integration test harness uses this to inject a TLS-trusting client for
    /// the HTTPS-backed VersityGW fixture; production callers should keep
    /// using `from_config`.
    pub async fn from_config_with_http_client(
        config: &Config,
        http_client: aws_sdk_s3::config::SharedHttpClient,
    ) -> Result<Self, ProxyError> {
        Self::from_config_inner(config, Some(http_client)).await
    }

    async fn from_config_inner(
        config: &Config,
        http_client: Option<aws_sdk_s3::config::SharedHttpClient>,
    ) -> Result<Self, ProxyError> {
        // Enforce BACKEND_ALLOW_HTTP: reject http:// endpoints unless explicitly allowed.
        let scheme = endpoint_scheme(&config.backend_endpoint);
        if !config.backend_allow_http && scheme.eq_ignore_ascii_case("http") {
            return Err(ProxyError::InvalidRequest {
                message: format!(
                    "backend endpoint uses HTTP (scheme \"{}\") but BACKEND_ALLOW_HTTP is not enabled; \
                     set BACKEND_ALLOW_HTTP=true to allow plaintext connections",
                    scheme,
                ),
            });
        }

        let credentials = Credentials::new(
            &config.backend_access_key_id,
            &config.backend_secret_access_key,
            None, // session token
            None, // expiry
            "tiny-s3-proxy-static",
        );

        let timeout_config = TimeoutConfig::builder()
            .connect_timeout(Duration::from_millis(config.upstream_connect_timeout_ms))
            .read_timeout(Duration::from_millis(config.upstream_request_timeout_ms))
            .build();

        let mut builder = aws_sdk_s3::config::Builder::new()
            .endpoint_url(&config.backend_endpoint)
            .region(Region::new(config.backend_region.clone()))
            .credentials_provider(credentials)
            .force_path_style(config.backend_use_path_style)
            .timeout_config(timeout_config)
            .behavior_version_latest();
        if let Some(http_client) = http_client {
            builder = builder.http_client(http_client);
        }
        let sdk_config = builder.build();

        let client = Client::from_conf(sdk_config);

        let base_ms = config.retry_base_backoff_ms;

        Ok(Self {
            client,
            default_bucket: config.backend_bucket.clone(),
            backend_endpoint_is_https: scheme.eq_ignore_ascii_case("https"),
            get_policy: RetryPolicy::for_reads(config.get_max_attempts, base_ms),
            head_policy: RetryPolicy::for_reads(config.head_max_attempts, base_ms),
            list_policy: RetryPolicy::for_reads(config.list_max_attempts, base_ms),
            put_policy: RetryPolicy::for_writes(config.put_max_attempts, base_ms),
            delete_policy: RetryPolicy::for_idempotent_writes(config.delete_max_attempts, base_ms),
        })
    }

    /// Defense-in-depth: refuse to send an `UNSIGNED-PAYLOAD` body over a
    /// plaintext backend. Body integrity in that mode depends entirely on
    /// TLS — over HTTP, a network attacker could tamper undetectably. The
    /// config layer should already reject this combination at startup; this
    /// runtime check exists so a misconstructed backend can't silently
    /// downgrade.
    fn require_https_for_unsigned_payload(&self, operation: &str) -> Result<(), ProxyError> {
        if self.backend_endpoint_is_https {
            return Ok(());
        }
        // `ProxyError::Internal` is the right variant for a transport-safety
        // configuration guard: this isn't a cache I/O failure (which is what
        // `ProxyError::Cache` is conceptually reserved for in this codebase),
        // it's the proxy refusing to ship an unsigned body over plaintext.
        // Both variants render the same wire response (HTTP 500 +
        // InternalError), so this change is type-accuracy without behaviour
        // drift — but it stops misclassifying the guard as a cache fault in
        // logs, metrics, and future error-handling branches.
        Err(ProxyError::Internal {
            source: format!(
                "{operation}: refusing to forward UNSIGNED-PAYLOAD body over plaintext HTTP \
                 backend; the aws-chunked decode path requires HTTPS for body integrity. \
                 Use an https:// BACKEND_ENDPOINT.",
            )
            .into(),
        })
    }
}

/// Map an AWS SDK error to our ProxyError type.
fn map_sdk_error<E: std::fmt::Debug>(
    err: aws_sdk_s3::error::SdkError<E>,
    operation: &str,
) -> ProxyError {
    match &err {
        aws_sdk_s3::error::SdkError::ConstructionFailure(_) => ProxyError::Internal {
            source: format!("{operation}: SDK construction failure: {err:?}").into(),
        },
        aws_sdk_s3::error::SdkError::TimeoutError(_) => ProxyError::Timeout {
            operation: operation.to_string(),
        },
        aws_sdk_s3::error::SdkError::DispatchFailure(_) => ProxyError::Backend {
            source: format!("connection/dispatch failure: {err:?}").into(),
            operation: operation.to_string(),
        },
        aws_sdk_s3::error::SdkError::ResponseError(resp_err) => {
            let status = resp_err.raw().status().as_u16();
            if status == 403 {
                ProxyError::Auth {
                    message: format!("{operation}: access denied from backend"),
                }
            } else {
                ProxyError::UpstreamS3 {
                    status_code: status,
                    s3_code: default_s3_code_for_status(status).to_string(),
                    message: format!("response error (HTTP {status}): {err:?}"),
                    operation: operation.to_string(),
                }
            }
        }
        aws_sdk_s3::error::SdkError::ServiceError(svc_err) => {
            let status = svc_err.raw().status().as_u16();
            match status {
                403 => ProxyError::Auth {
                    message: format!("{operation}: access denied from backend"),
                },
                _ => {
                    let s3_code = extract_s3_code(svc_err.err(), status);
                    let message = format!("{err:?}");
                    ProxyError::UpstreamS3 {
                        status_code: status,
                        s3_code,
                        message,
                        operation: operation.to_string(),
                    }
                }
            }
        }
        _ => ProxyError::Backend {
            source: format!("unknown SDK error: {err:?}").into(),
            operation: operation.to_string(),
        },
    }
}

/// Try to extract an S3 error code from the SDK error's Debug representation.
/// Falls back to a status-code-based default.
fn extract_s3_code<E: std::fmt::Debug>(err: &E, status: u16) -> String {
    let debug = format!("{:?}", err);
    // AWS SDK errors format as "VariantName(InnerType { ... })"
    if let Some(pos) = debug.find('(') {
        let candidate = &debug[..pos];
        if !candidate.is_empty()
            && candidate.chars().next().unwrap().is_uppercase()
            && candidate.chars().all(|c| c.is_alphanumeric())
        {
            return candidate.to_string();
        }
    }
    // Fallback based on HTTP status
    default_s3_code_for_status(status).to_string()
}

/// Map an HTTP status code to a reasonable default S3 error code.
fn default_s3_code_for_status(status: u16) -> &'static str {
    match status {
        304 => "NotModified",
        400 => "InvalidArgument",
        404 => "NoSuchKey",
        405 => "MethodNotAllowed",
        409 => "OperationAborted",
        412 => "PreconditionFailed",
        416 => "InvalidRange",
        _ => "InternalError",
    }
}

/// Convert an AWS SDK DateTime to a chrono DateTime<Utc>.
fn to_chrono(dt: &aws_smithy_types::DateTime) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(dt.secs(), dt.subsec_nanos())
}

/// Extract S3 response headers shared by both GetObjectOutput and
/// HeadObjectOutput into a HashMap. This covers every typed SDK accessor
/// present on both response types as of aws-sdk-s3 1.127.0.
macro_rules! extract_extra_headers {
    ($resp:expr) => {{
        let mut extra = HashMap::new();
        // Standard content headers
        if let Some(v) = $resp.content_encoding() {
            extra.insert("content-encoding".into(), v.to_string());
        }
        if let Some(v) = $resp.content_disposition() {
            extra.insert("content-disposition".into(), v.to_string());
        }
        if let Some(v) = $resp.content_language() {
            extra.insert("content-language".into(), v.to_string());
        }
        if let Some(v) = $resp.cache_control() {
            extra.insert("cache-control".into(), v.to_string());
        }
        if let Some(v) = $resp.expires_string() {
            extra.insert("expires".into(), v.to_string());
        }
        if let Some(v) = $resp.accept_ranges() {
            extra.insert("accept-ranges".into(), v.to_string());
        }
        if let Some(v) = $resp.content_range() {
            extra.insert("content-range".into(), v.to_string());
        }
        if let Some(v) = $resp.request_charged() {
            extra.insert("x-amz-request-charged".into(), v.as_str().to_string());
        }
        if let Some(v) = $resp.missing_meta() {
            extra.insert("x-amz-missing-meta".into(), v.to_string());
        }
        // Versioning / lifecycle / replication
        if let Some(v) = $resp.version_id() {
            extra.insert("x-amz-version-id".into(), v.to_string());
        }
        if $resp.delete_marker().unwrap_or(false) {
            extra.insert("x-amz-delete-marker".into(), "true".into());
        }
        if let Some(v) = $resp.expiration() {
            extra.insert("x-amz-expiration".into(), v.to_string());
        }
        if let Some(v) = $resp.restore() {
            extra.insert("x-amz-restore".into(), v.to_string());
        }
        if let Some(v) = $resp.replication_status() {
            extra.insert("x-amz-replication-status".into(), v.as_str().to_string());
        }
        // Encryption
        if let Some(v) = $resp.server_side_encryption() {
            extra.insert(
                "x-amz-server-side-encryption".into(),
                v.as_str().to_string(),
            );
        }
        if let Some(v) = $resp.ssekms_key_id() {
            extra.insert(
                "x-amz-server-side-encryption-aws-kms-key-id".into(),
                v.to_string(),
            );
        }
        if let Some(v) = $resp.sse_customer_algorithm() {
            extra.insert(
                "x-amz-server-side-encryption-customer-algorithm".into(),
                v.to_string(),
            );
        }
        if let Some(v) = $resp.sse_customer_key_md5() {
            extra.insert(
                "x-amz-server-side-encryption-customer-key-md5".into(),
                v.to_string(),
            );
        }
        if $resp.bucket_key_enabled().unwrap_or(false) {
            extra.insert(
                "x-amz-server-side-encryption-bucket-key-enabled".into(),
                "true".into(),
            );
        }
        // Storage / object-lock
        if let Some(v) = $resp.storage_class() {
            extra.insert("x-amz-storage-class".into(), v.as_str().to_string());
        }
        if let Some(v) = $resp.object_lock_mode() {
            extra.insert("x-amz-object-lock-mode".into(), v.as_str().to_string());
        }
        if let Some(v) = $resp.object_lock_retain_until_date() {
            extra.insert("x-amz-object-lock-retain-until-date".into(), format!("{v}"));
        }
        if let Some(v) = $resp.object_lock_legal_hold_status() {
            extra.insert(
                "x-amz-object-lock-legal-hold".into(),
                v.as_str().to_string(),
            );
        }
        // Multipart / redirect
        if let Some(v) = $resp.parts_count() {
            extra.insert("x-amz-mp-parts-count".into(), v.to_string());
        }
        if let Some(v) = $resp.website_redirect_location() {
            extra.insert("x-amz-website-redirect-location".into(), v.to_string());
        }
        // Tagging
        if let Some(v) = $resp.tag_count() {
            extra.insert("x-amz-tagging-count".into(), v.to_string());
        }
        // Checksums
        if let Some(v) = $resp.checksum_crc32() {
            extra.insert("x-amz-checksum-crc32".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_crc32_c() {
            extra.insert("x-amz-checksum-crc32c".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_crc64_nvme() {
            extra.insert("x-amz-checksum-crc64nvme".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_sha1() {
            extra.insert("x-amz-checksum-sha1".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_sha256() {
            extra.insert("x-amz-checksum-sha256".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_type() {
            extra.insert("x-amz-checksum-type".into(), v.as_str().to_string());
        }
        extra
    }};
}

/// Extract response headers that appear on write responses (PutObject,
/// UploadPart, CompleteMultipartUpload). Covers SSE, checksums, expiration,
/// and request-charged — the metadata that typed write callers lose without
/// passthrough.
macro_rules! extract_write_extra_headers {
    ($resp:expr) => {{
        let mut extra = HashMap::new();
        // Encryption (SSE-C headers omitted: requests with SSE-C route through
        // passthrough via has_unsupported_write_modifiers, so the typed path
        // never produces sse_customer_algorithm / sse_customer_key_md5).
        if let Some(v) = $resp.server_side_encryption() {
            extra.insert(
                "x-amz-server-side-encryption".into(),
                v.as_str().to_string(),
            );
        }
        if let Some(v) = $resp.ssekms_key_id() {
            extra.insert(
                "x-amz-server-side-encryption-aws-kms-key-id".into(),
                v.to_string(),
            );
        }
        if $resp.bucket_key_enabled().unwrap_or(false) {
            extra.insert(
                "x-amz-server-side-encryption-bucket-key-enabled".into(),
                "true".into(),
            );
        }
        // Checksums
        if let Some(v) = $resp.checksum_crc32() {
            extra.insert("x-amz-checksum-crc32".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_crc32_c() {
            extra.insert("x-amz-checksum-crc32c".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_sha1() {
            extra.insert("x-amz-checksum-sha1".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_sha256() {
            extra.insert("x-amz-checksum-sha256".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_crc64_nvme() {
            extra.insert("x-amz-checksum-crc64nvme".into(), v.to_string());
        }
        // Request charged
        if let Some(v) = $resp.request_charged() {
            extra.insert("x-amz-request-charged".into(), v.as_str().to_string());
        }
        extra
    }};
}

/// Supplementary write-response headers only present on PutObject and
/// CompleteMultipartUpload (not UploadPart).
macro_rules! extract_write_extra_headers_full {
    ($resp:expr, $extra:expr) => {
        if let Some(v) = $resp.expiration() {
            $extra.insert("x-amz-expiration".into(), v.to_string());
        }
        if let Some(v) = $resp.checksum_type() {
            $extra.insert("x-amz-checksum-type".into(), v.as_str().to_string());
        }
    };
}

/// Extract HEAD-only response headers not present on GetObjectOutput.
macro_rules! extract_head_extra_headers {
    ($resp:expr, $extra:expr) => {
        if let Some(v) = $resp.archive_status() {
            $extra.insert("x-amz-archive-status".into(), v.as_str().to_string());
        }
    };
}

impl Backend for S3Backend {
    async fn get_object(
        &self,
        req: GetObjectInput<'_>,
    ) -> Result<(GetObjectMeta, BoxByteStream), ProxyError> {
        let GetObjectInput {
            bucket,
            key,
            options,
        } = req;
        let bucket = bucket.to_string();
        let key = key.to_string();

        // Retry only the send() call. Once we have a successful response,
        // the body stream is returned without further retry wrapping —
        // a mid-stream error will propagate to the client.
        let resp = with_retry(&self.get_policy, "get_object", |_attempt| {
            let client = self.client.clone();
            let bucket = bucket.clone();
            let key = key.clone();
            async move {
                let mut request = client.get_object().bucket(&bucket).key(&key);
                if options.wants_checksum_headers() {
                    request = request.checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled);
                }
                request
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "get_object"))
            }
        })
        .await?;

        let meta = GetObjectMeta {
            content_type: resp.content_type().map(|s| s.to_string()),
            content_length: resp.content_length(),
            etag: resp.e_tag().map(|s| s.to_string()),
            last_modified: resp.last_modified().and_then(to_chrono),
            metadata: resp
                .metadata()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect::<HashMap<String, String>>()
                })
                .unwrap_or_default(),
            extra_headers: extract_extra_headers!(resp),
        };

        // Convert ByteStream → AsyncRead → Stream<Item = Result<Bytes, io::Error>>
        let stream = ReaderStream::new(resp.body.into_async_read());
        Ok((meta, Box::pin(stream)))
    }

    async fn head_object(&self, req: HeadObjectInput<'_>) -> Result<HeadObjectOutput, ProxyError> {
        let HeadObjectInput {
            bucket,
            key,
            options,
        } = req;
        let bucket = bucket.to_string();
        let key = key.to_string();

        with_retry(&self.head_policy, "head_object", |_attempt| {
            let client = &self.client;
            let bucket = bucket.clone();
            let key = key.clone();
            async move {
                let mut request = client.head_object().bucket(&bucket).key(&key);
                if options.wants_checksum_headers() {
                    request = request.checksum_mode(aws_sdk_s3::types::ChecksumMode::Enabled);
                }
                let resp = request
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "head_object"))?;

                let content_type = resp.content_type().map(|s| s.to_string());
                let content_length = resp.content_length();
                let etag = resp.e_tag().map(|s| s.to_string());
                let last_modified = resp.last_modified().and_then(to_chrono);
                let metadata = resp
                    .metadata()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect::<HashMap<String, String>>()
                    })
                    .unwrap_or_default();

                let mut extra_headers = extract_extra_headers!(resp);
                extract_head_extra_headers!(resp, extra_headers);

                Ok(HeadObjectOutput {
                    content_type,
                    content_length,
                    etag,
                    last_modified,
                    metadata,
                    extra_headers,
                })
            }
        })
        .await
    }

    async fn put_object(&self, req: PutObjectInput) -> Result<PutObjectOutput, ProxyError> {
        let body_bytes = req.body.clone();

        with_retry(&self.put_policy, "put_object", |_attempt| {
            let client = &self.client;
            let bucket = req.bucket.clone();
            let key = req.key.clone();
            let content_type = req.content_type.clone();
            let content_md5 = req.content_md5.clone();
            let metadata = req.metadata.clone();
            let extra_amz_headers = req.extra_amz_headers.clone();
            let content_headers = req.content_headers.clone();
            let body = body_bytes.clone();
            async move {
                let mut builder = client
                    .put_object()
                    .bucket(&bucket)
                    .key(&key)
                    .body(ByteStream::from(body));

                if let Some(ct) = content_type {
                    builder = builder.content_type(ct);
                }
                if let Some(md5) = content_md5 {
                    builder = builder.content_md5(md5);
                }
                for (k, v) in &metadata {
                    builder = builder.metadata(k, v);
                }

                // Forward standard content headers via typed SDK setters.
                if let Some(v) = content_headers.get("content-encoding") {
                    builder = builder.content_encoding(v);
                }
                if let Some(v) = content_headers.get("content-disposition") {
                    builder = builder.content_disposition(v);
                }
                if let Some(v) = content_headers.get("content-language") {
                    builder = builder.content_language(v);
                }
                if let Some(v) = content_headers.get("cache-control") {
                    builder = builder.cache_control(v);
                }

                // Forward extra x-amz-* headers and `expires` as raw headers.
                let expires_val = content_headers.get("expires").cloned();
                let resp = builder
                    .customize()
                    .mutate_request(move |req| {
                        for (k, v) in &extra_amz_headers {
                            if let (Ok(name), Ok(val)) = (
                                http::header::HeaderName::from_bytes(k.as_bytes()),
                                http::header::HeaderValue::from_str(v),
                            ) {
                                req.headers_mut().insert(name, val);
                            }
                        }
                        if let Some(exp) = &expires_val
                            && let Ok(val) = http::header::HeaderValue::from_str(exp)
                        {
                            req.headers_mut().insert(http::header::EXPIRES, val);
                        }
                    })
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "put_object"))?;

                let mut extra_headers = extract_write_extra_headers!(&resp);
                extract_write_extra_headers_full!(&resp, extra_headers);
                Ok(PutObjectOutput {
                    etag: resp.e_tag().map(|s| s.to_string()),
                    version_id: resp.version_id().map(|s| s.to_string()),
                    extra_headers,
                })
            }
        })
        .await
    }

    async fn put_object_from_path(
        &self,
        req: PutObjectSpoolInput,
    ) -> Result<PutObjectOutput, ProxyError> {
        self.require_https_for_unsigned_payload("put_object_from_path")?;

        with_retry(&self.put_policy, "put_object_from_path", |_attempt| {
            let client = &self.client;
            let bucket = req.bucket.clone();
            let key = req.key.clone();
            let path = req.path.clone();
            let len = req.len;
            let content_type = req.content_type.clone();
            let content_md5 = req.content_md5.clone();
            let metadata = req.metadata.clone();
            let extra_amz_headers = req.extra_amz_headers.clone();
            let content_headers = req.content_headers.clone();
            let checksum = req.checksum.clone();
            async move {
                // Length::Exact pins Content-Length to the value we just decoded.
                // ByteStream::from_path defaults to file metadata, which races
                // with concurrent writers; we own the spool exclusively so the
                // file isn't growing, but pinning is cheaper than reasoning.
                let body = ByteStream::read_from()
                    .path(&path)
                    .length(Length::Exact(len))
                    .build()
                    .await
                    .map_err(|e| ProxyError::Backend {
                        source: format!("build ByteStream from spool {}: {e}", path.display())
                            .into(),
                        operation: "put_object_from_path".into(),
                    })?;

                let mut builder = client
                    .put_object()
                    .bucket(&bucket)
                    .key(&key)
                    .content_length(len as i64)
                    .body(body);

                if let Some(ct) = content_type {
                    builder = builder.content_type(ct);
                }
                if let Some(md5) = content_md5 {
                    builder = builder.content_md5(md5);
                }
                for (k, v) in &metadata {
                    builder = builder.metadata(k, v);
                }
                if let Some(v) = content_headers.get("content-encoding") {
                    builder = builder.content_encoding(v);
                }
                if let Some(v) = content_headers.get("content-disposition") {
                    builder = builder.content_disposition(v);
                }
                if let Some(v) = content_headers.get("content-language") {
                    builder = builder.content_language(v);
                }
                if let Some(v) = content_headers.get("cache-control") {
                    builder = builder.cache_control(v);
                }

                // Forward a trailer-mode checksum via the per-algorithm SDK
                // setter. Critically, we do NOT call `.checksum_algorithm()`
                // here — that re-activates the SDK's outbound aws-chunked
                // re-encoding (the very thing we just decoded out of). The
                // per-algorithm setter sends the validated digest as a plain
                // `x-amz-checksum-<algo>` request header without changing
                // the body framing.
                if let Some(c) = &checksum {
                    builder = match c.algorithm {
                        ChecksumAlgorithm::Crc32 => builder.checksum_crc32(c.value.clone()),
                        ChecksumAlgorithm::Crc32C => builder.checksum_crc32_c(c.value.clone()),
                        ChecksumAlgorithm::Crc64Nvme => {
                            builder.checksum_crc64_nvme(c.value.clone())
                        }
                        ChecksumAlgorithm::Sha1 => builder.checksum_sha1(c.value.clone()),
                        ChecksumAlgorithm::Sha256 => builder.checksum_sha256(c.value.clone()),
                    };
                }

                let expires_val = content_headers.get("expires").cloned();

                // `RequestChecksumCalculation::WhenRequired` disables the SDK's
                // outbound aws-chunked re-encoding: the default `WhenSupported`
                // value triggers the checksum interceptor to wrap the body in
                // the streaming-checksum framing, which is exactly what we
                // just decoded out of. `disable_payload_signing()` makes the
                // SDK send `x-amz-content-sha256: UNSIGNED-PAYLOAD` — body
                // integrity is delegated to the TLS transport. The HTTPS guard
                // above enforces that delegation.
                let resp = builder
                    .customize()
                    .mutate_request(move |req| {
                        for (k, v) in &extra_amz_headers {
                            if let (Ok(name), Ok(val)) = (
                                http::header::HeaderName::from_bytes(k.as_bytes()),
                                http::header::HeaderValue::from_str(v),
                            ) {
                                req.headers_mut().insert(name, val);
                            }
                        }
                        if let Some(exp) = &expires_val
                            && let Ok(val) = http::header::HeaderValue::from_str(exp)
                        {
                            req.headers_mut().insert(http::header::EXPIRES, val);
                        }
                    })
                    .config_override(
                        S3ConfigBuilder::new()
                            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired),
                    )
                    .disable_payload_signing()
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "put_object_from_path"))?;

                let mut extra_headers = extract_write_extra_headers!(&resp);
                extract_write_extra_headers_full!(&resp, extra_headers);
                Ok(PutObjectOutput {
                    etag: resp.e_tag().map(|s| s.to_string()),
                    version_id: resp.version_id().map(|s| s.to_string()),
                    extra_headers,
                })
            }
        })
        .await
    }

    async fn delete_object(
        &self,
        req: DeleteObjectInput<'_>,
    ) -> Result<DeleteObjectOutput, ProxyError> {
        let DeleteObjectInput { bucket, key } = req;
        let bucket = bucket.to_string();
        let key = key.to_string();

        with_retry(&self.delete_policy, "delete_object", |_attempt| {
            let client = &self.client;
            let bucket = bucket.clone();
            let key = key.clone();
            async move {
                let resp = client
                    .delete_object()
                    .bucket(&bucket)
                    .key(&key)
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "delete_object"))?;

                Ok(DeleteObjectOutput {
                    delete_marker: resp.delete_marker,
                    version_id: resp.version_id().map(|s| s.to_string()),
                })
            }
        })
        .await
    }

    async fn list_objects(&self, req: ListObjectsInput) -> Result<ListObjectsOutput, ProxyError> {
        with_retry(&self.list_policy, "list_objects", |_attempt| {
            let client = &self.client;
            let req = req.clone();
            async move {
                if req.is_v2 {
                    list_objects_v2(client, &req).await
                } else {
                    list_objects_v1(client, &req).await
                }
            }
        })
        .await
    }

    async fn create_multipart_upload(
        &self,
        req: CreateMultipartUploadInput<'_>,
    ) -> Result<CreateMultipartOutput, ProxyError> {
        let CreateMultipartUploadInput {
            bucket,
            key,
            content_type,
            metadata,
            content_headers,
        } = req;
        let mut builder = self
            .client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key);

        if let Some(ct) = content_type {
            builder = builder.content_type(ct);
        }
        for (k, v) in metadata {
            builder = builder.metadata(k, v);
        }

        // Forward standard content headers via typed SDK setters.
        if let Some(v) = content_headers.get("content-encoding") {
            builder = builder.content_encoding(v);
        }
        if let Some(v) = content_headers.get("content-disposition") {
            builder = builder.content_disposition(v);
        }
        if let Some(v) = content_headers.get("content-language") {
            builder = builder.content_language(v);
        }
        if let Some(v) = content_headers.get("cache-control") {
            builder = builder.cache_control(v);
        }

        // Forward `expires` as a raw header via customize.
        let expires_val = content_headers.get("expires").cloned();
        let resp = if let Some(exp) = expires_val {
            builder
                .customize()
                .mutate_request(move |req| {
                    if let Ok(val) = http::header::HeaderValue::from_str(&exp) {
                        req.headers_mut().insert(http::header::EXPIRES, val);
                    }
                })
                .send()
                .await
                .map_err(|e| map_sdk_error(e, "create_multipart_upload"))?
        } else {
            builder
                .send()
                .await
                .map_err(|e| map_sdk_error(e, "create_multipart_upload"))?
        };

        let upload_id = resp
            .upload_id()
            .ok_or_else(|| ProxyError::Internal {
                source: "create_multipart_upload returned no upload_id".into(),
            })?
            .to_string();

        // CreateMultipartUploadOutput has a different accessor set than data
        // responses (no individual checksums, no expiration), so extract directly.
        let mut extra_headers = HashMap::new();
        if let Some(v) = resp.server_side_encryption() {
            extra_headers.insert(
                "x-amz-server-side-encryption".into(),
                v.as_str().to_string(),
            );
        }
        if let Some(v) = resp.ssekms_key_id() {
            extra_headers.insert(
                "x-amz-server-side-encryption-aws-kms-key-id".into(),
                v.to_string(),
            );
        }
        if resp.bucket_key_enabled().unwrap_or(false) {
            extra_headers.insert(
                "x-amz-server-side-encryption-bucket-key-enabled".into(),
                "true".into(),
            );
        }
        if let Some(v) = resp.checksum_algorithm() {
            extra_headers.insert("x-amz-checksum-algorithm".into(), v.as_str().to_string());
        }
        if let Some(v) = resp.checksum_type() {
            extra_headers.insert("x-amz-checksum-type".into(), v.as_str().to_string());
        }
        if let Some(v) = resp.request_charged() {
            extra_headers.insert("x-amz-request-charged".into(), v.as_str().to_string());
        }
        Ok(CreateMultipartOutput {
            upload_id,
            extra_headers,
        })
    }

    async fn upload_part(&self, req: UploadPartInput) -> Result<UploadPartOutput, ProxyError> {
        let mut builder = self
            .client
            .upload_part()
            .bucket(&req.bucket)
            .key(&req.key)
            .upload_id(&req.upload_id)
            .part_number(req.part_number)
            .body(ByteStream::from(req.body));

        if let Some(md5) = &req.content_md5 {
            builder = builder.content_md5(md5);
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "upload_part"))?;

        let etag = resp
            .e_tag()
            .ok_or_else(|| ProxyError::Internal {
                source: "upload_part returned no ETag".into(),
            })?
            .to_string();

        let extra_headers = extract_write_extra_headers!(&resp);
        Ok(UploadPartOutput {
            etag,
            extra_headers,
        })
    }

    async fn upload_part_from_path(
        &self,
        req: UploadPartSpoolInput,
    ) -> Result<UploadPartOutput, ProxyError> {
        self.require_https_for_unsigned_payload("upload_part_from_path")?;

        let body = ByteStream::read_from()
            .path(&req.path)
            .length(Length::Exact(req.len))
            .build()
            .await
            .map_err(|e| ProxyError::Backend {
                source: format!("build ByteStream from spool {}: {e}", req.path.display()).into(),
                operation: "upload_part_from_path".into(),
            })?;

        let mut builder = self
            .client
            .upload_part()
            .bucket(&req.bucket)
            .key(&req.key)
            .upload_id(&req.upload_id)
            .part_number(req.part_number)
            .content_length(req.len as i64)
            .body(body);

        if let Some(md5) = &req.content_md5 {
            builder = builder.content_md5(md5);
        }

        // Per-algorithm checksum forwarding — see `put_object_from_path` for
        // the rationale around NOT calling `.checksum_algorithm()`.
        if let Some(c) = &req.checksum {
            builder = match c.algorithm {
                ChecksumAlgorithm::Crc32 => builder.checksum_crc32(c.value.clone()),
                ChecksumAlgorithm::Crc32C => builder.checksum_crc32_c(c.value.clone()),
                ChecksumAlgorithm::Crc64Nvme => builder.checksum_crc64_nvme(c.value.clone()),
                ChecksumAlgorithm::Sha1 => builder.checksum_sha1(c.value.clone()),
                ChecksumAlgorithm::Sha256 => builder.checksum_sha256(c.value.clone()),
            };
        }

        let extra_amz_headers = req.extra_amz_headers.clone();
        let resp = builder
            .customize()
            .mutate_request(move |req| {
                for (k, v) in &extra_amz_headers {
                    if let (Ok(name), Ok(val)) = (
                        http::header::HeaderName::from_bytes(k.as_bytes()),
                        http::header::HeaderValue::from_str(v),
                    ) {
                        req.headers_mut().insert(name, val);
                    }
                }
            })
            .config_override(
                S3ConfigBuilder::new()
                    .request_checksum_calculation(RequestChecksumCalculation::WhenRequired),
            )
            .disable_payload_signing()
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "upload_part_from_path"))?;

        let etag = resp
            .e_tag()
            .ok_or_else(|| ProxyError::Internal {
                source: "upload_part_from_path returned no ETag".into(),
            })?
            .to_string();

        let extra_headers = extract_write_extra_headers!(&resp);
        Ok(UploadPartOutput {
            etag,
            extra_headers,
        })
    }

    async fn complete_multipart_upload(
        &self,
        req: CompleteMultipartInput,
    ) -> Result<CompleteMultipartOutput, ProxyError> {
        let sdk_parts: Vec<aws_sdk_s3::types::CompletedPart> = req
            .parts
            .iter()
            .map(|p| {
                aws_sdk_s3::types::CompletedPart::builder()
                    .e_tag(&p.etag)
                    .part_number(p.part_number)
                    .build()
            })
            .collect();

        let completed_upload = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(sdk_parts))
            .build();

        let resp = self
            .client
            .complete_multipart_upload()
            .bucket(&req.bucket)
            .key(&req.key)
            .upload_id(&req.upload_id)
            .multipart_upload(completed_upload)
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "complete_multipart_upload"))?;

        let mut extra_headers = extract_write_extra_headers!(&resp);
        extract_write_extra_headers_full!(&resp, extra_headers);
        Ok(CompleteMultipartOutput {
            etag: resp.e_tag().map(|s| s.to_string()),
            location: resp.location().map(|s| s.to_string()),
            version_id: resp.version_id().map(|s| s.to_string()),
            extra_headers,
        })
    }

    async fn abort_multipart_upload(
        &self,
        req: AbortMultipartUploadInput<'_>,
    ) -> Result<(), ProxyError> {
        let AbortMultipartUploadInput {
            bucket,
            key,
            upload_id,
        } = req;
        let bucket = bucket.to_string();
        let key = key.to_string();
        let upload_id = upload_id.to_string();

        with_retry(&self.delete_policy, "abort_multipart_upload", |_attempt| {
            let client = &self.client;
            let bucket = bucket.clone();
            let key = key.clone();
            let upload_id = upload_id.clone();
            async move {
                client
                    .abort_multipart_upload()
                    .bucket(&bucket)
                    .key(&key)
                    .upload_id(&upload_id)
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "abort_multipart_upload"))?;

                Ok(())
            }
        })
        .await
    }
}

/// Map an SDK `Object` (returned by both ListObjectsV1 and ListObjectsV2)
/// into the reduced `ObjectInfo` model. Stringifies SDK enums at the
/// boundary so we don't leak AWS SDK types into our model and preserve
/// unknown variants verbatim.
pub(crate) fn map_sdk_object(obj: &aws_sdk_s3::types::Object) -> ObjectInfo {
    ObjectInfo {
        key: obj.key().unwrap_or_default().to_string(),
        last_modified: obj.last_modified().and_then(to_chrono),
        etag: obj.e_tag().map(|s| s.to_string()),
        size: obj.size(),
        storage_class: obj.storage_class().map(|sc| sc.as_str().to_string()),
        checksum_algorithm: obj
            .checksum_algorithm()
            .iter()
            .map(|a| a.as_str().to_string())
            .collect(),
        checksum_type: obj.checksum_type().map(|t| t.as_str().to_string()),
    }
}

/// Execute a ListObjectsV2 call and map the response.
async fn list_objects_v2(
    client: &Client,
    req: &ListObjectsInput,
) -> Result<ListObjectsOutput, ProxyError> {
    let mut builder = client.list_objects_v2().bucket(&req.bucket);

    if let Some(prefix) = &req.prefix {
        builder = builder.prefix(prefix);
    }
    if let Some(delimiter) = &req.delimiter {
        builder = builder.delimiter(delimiter);
    }
    if let Some(max_keys) = req.max_keys {
        builder = builder.max_keys(max_keys);
    }
    if let Some(token) = &req.continuation_token {
        builder = builder.continuation_token(token);
    }
    if let Some(start_after) = &req.start_after {
        builder = builder.start_after(start_after);
    }
    if let Some(encoding_type) = &req.encoding_type
        && encoding_type == "url"
    {
        builder = builder.encoding_type(aws_sdk_s3::types::EncodingType::Url);
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| map_sdk_error(e, "list_objects_v2"))?;

    let contents = resp.contents().iter().map(map_sdk_object).collect();

    let common_prefixes = resp
        .common_prefixes()
        .iter()
        .filter_map(|cp| cp.prefix().map(|s| s.to_string()))
        .collect();

    Ok(ListObjectsOutput {
        is_truncated: resp.is_truncated().unwrap_or(false),
        contents,
        common_prefixes,
        name: resp.name().unwrap_or_default().to_string(),
        prefix: resp.prefix().map(|s| s.to_string()),
        delimiter: resp.delimiter().map(|s| s.to_string()),
        max_keys: resp.max_keys().unwrap_or(1000),
        encoding_type: resp.encoding_type().map(|et| et.as_str().to_string()),
        key_count: resp.key_count(),
        continuation_token: req.continuation_token.clone(),
        next_continuation_token: resp.next_continuation_token().map(|s| s.to_string()),
        start_after: resp.start_after().map(|s| s.to_string()),
        marker: None,
        next_marker: None,
    })
}

/// Execute a ListObjects (v1) call and map the response.
async fn list_objects_v1(
    client: &Client,
    req: &ListObjectsInput,
) -> Result<ListObjectsOutput, ProxyError> {
    let mut builder = client.list_objects().bucket(&req.bucket);

    if let Some(prefix) = &req.prefix {
        builder = builder.prefix(prefix);
    }
    if let Some(delimiter) = &req.delimiter {
        builder = builder.delimiter(delimiter);
    }
    if let Some(max_keys) = req.max_keys {
        builder = builder.max_keys(max_keys);
    }
    if let Some(marker) = &req.marker {
        builder = builder.marker(marker);
    }
    if let Some(encoding_type) = &req.encoding_type
        && encoding_type == "url"
    {
        builder = builder.encoding_type(aws_sdk_s3::types::EncodingType::Url);
    }

    let resp = builder
        .send()
        .await
        .map_err(|e| map_sdk_error(e, "list_objects"))?;

    let contents = resp.contents().iter().map(map_sdk_object).collect();

    let common_prefixes = resp
        .common_prefixes()
        .iter()
        .filter_map(|cp| cp.prefix().map(|s| s.to_string()))
        .collect();

    Ok(ListObjectsOutput {
        is_truncated: resp.is_truncated().unwrap_or(false),
        contents,
        common_prefixes,
        name: resp.name().unwrap_or_default().to_string(),
        prefix: resp.prefix().map(|s| s.to_string()),
        delimiter: resp.delimiter().map(|s| s.to_string()),
        max_keys: resp.max_keys().unwrap_or(1000),
        encoding_type: resp.encoding_type().map(|et| et.as_str().to_string()),
        key_count: None,
        continuation_token: None,
        next_continuation_token: None,
        start_after: None,
        marker: resp.marker().map(|s| s.to_string()),
        next_marker: resp.next_marker().map(|s| s.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMode, Config};

    // ── helpers ──────────────────────────────────────────────────────

    /// Helper to build a Config for from_config tests.
    fn test_config() -> Config {
        Config {
            s3_listen_addr: "0.0.0.0:8080".to_string(),
            admin_listen_addr: "0.0.0.0:9090".to_string(),
            frontend_bucket: "test-frontend".to_string(),
            auth_mode: AuthMode::TrustedInternal,
            allowed_frontend_keys: vec![],
            backend_endpoint: "https://s3.example.com".to_string(),
            backend_region: "auto".to_string(),
            backend_bucket: "test-backend".to_string(),
            backend_access_key_id: "AKID".to_string(),
            backend_secret_access_key: "secret".to_string(),
            backend_use_path_style: true,
            backend_allow_http: false,
            cache_dir: std::path::PathBuf::from("/tmp/test-cache"),
            cache_max_bytes: 1024 * 1024,
            cache_max_object_bytes: 512 * 1024,
            cacheable_prefixes: vec!["script_bundle/".to_string(), "tar/".to_string()],
            cache_serve_stale_on_error: true,
            cache_eviction_interval_secs: 300,
            get_max_attempts: 1,
            head_max_attempts: 1,
            list_max_attempts: 1,
            put_max_attempts: 1,
            delete_max_attempts: 1,
            retry_base_backoff_ms: 10,
            upstream_connect_timeout_ms: 5000,
            upstream_request_timeout_ms: 30000,
            max_request_body_bytes: 268_435_456,
            passthrough_unsigned_payload: false,
        }
    }

    /// A wrapper whose Debug formats as `NoSuchKey(SomeInner { ... })`.
    struct FakeVariant;
    impl std::fmt::Debug for FakeVariant {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "NoSuchKey(SomeInner {{ message: \"not found\" }})")
        }
    }

    /// Debug has no parenthesis at all.
    struct NoParen;
    impl std::fmt::Debug for NoParen {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "JustAPlainString")
        }
    }

    /// Debug starts with a lowercase letter.
    struct LowercaseStart;
    impl std::fmt::Debug for LowercaseStart {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "notUpperCase(inner)")
        }
    }

    /// Debug has a non-alphanumeric character before the `(`.
    struct SpecialChars;
    impl std::fmt::Debug for SpecialChars {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Not-Valid(inner)")
        }
    }

    // ── extract_s3_code tests ───────────────────────────────────────

    #[test]
    fn test_extract_s3_code_variant_name() {
        let code = extract_s3_code(&FakeVariant, 500);
        assert_eq!(code, "NoSuchKey");
    }

    #[test]
    fn test_extract_s3_code_no_paren() {
        let code = extract_s3_code(&NoParen, 404);
        assert_eq!(code, "NoSuchKey"); // falls back to default_s3_code_for_status(404)
    }

    #[test]
    fn test_extract_s3_code_lowercase_start() {
        let code = extract_s3_code(&LowercaseStart, 400);
        assert_eq!(code, "InvalidArgument"); // falls back
    }

    #[test]
    fn test_extract_s3_code_with_special_chars() {
        let code = extract_s3_code(&SpecialChars, 409);
        assert_eq!(code, "OperationAborted"); // falls back
    }

    // ── default_s3_code_for_status tests ────────────────────────────

    #[test]
    fn test_default_s3_code_304() {
        assert_eq!(default_s3_code_for_status(304), "NotModified");
    }

    #[test]
    fn test_default_s3_code_400() {
        assert_eq!(default_s3_code_for_status(400), "InvalidArgument");
    }

    #[test]
    fn test_default_s3_code_404() {
        assert_eq!(default_s3_code_for_status(404), "NoSuchKey");
    }

    #[test]
    fn test_default_s3_code_405() {
        assert_eq!(default_s3_code_for_status(405), "MethodNotAllowed");
    }

    #[test]
    fn test_default_s3_code_409() {
        assert_eq!(default_s3_code_for_status(409), "OperationAborted");
    }

    #[test]
    fn test_default_s3_code_412() {
        assert_eq!(default_s3_code_for_status(412), "PreconditionFailed");
    }

    #[test]
    fn test_default_s3_code_416() {
        assert_eq!(default_s3_code_for_status(416), "InvalidRange");
    }

    #[test]
    fn test_default_s3_code_500() {
        assert_eq!(default_s3_code_for_status(500), "InternalError");
    }

    #[test]
    fn test_default_s3_code_unknown() {
        assert_eq!(default_s3_code_for_status(418), "InternalError");
    }

    // ── to_chrono tests ─────────────────────────────────────────────

    #[test]
    fn test_to_chrono_valid() {
        let dt = aws_smithy_types::DateTime::from_secs(1_700_000_000);
        let chrono_dt = to_chrono(&dt).expect("should convert");
        assert_eq!(chrono_dt.timestamp(), 1_700_000_000);
    }

    #[test]
    fn test_to_chrono_epoch() {
        let dt = aws_smithy_types::DateTime::from_secs(0);
        let chrono_dt = to_chrono(&dt).expect("should convert");
        assert_eq!(chrono_dt.format("%Y-%m-%d").to_string(), "1970-01-01");
    }

    // ── from_config validation tests ────────────────────────────────

    #[tokio::test]
    async fn test_from_config_rejects_http_without_allow() {
        let mut config = test_config();
        // Use an endpoint with userinfo so we can pin that the rejection
        // message never echoes credentials, host, or path. This rejection
        // path bubbles out through `?` in main.rs and lands in process
        // logs, so leaking the raw endpoint here is the same exposure as
        // the startup-log leak fixed alongside this.
        config.backend_endpoint = "http://alice:supersecret@insecure.example/root".to_string();
        config.backend_allow_http = false;

        let result = S3Backend::from_config(&config).await;
        match result {
            Err(ProxyError::InvalidRequest { message }) => {
                assert!(
                    message.contains("BACKEND_ALLOW_HTTP"),
                    "error should mention BACKEND_ALLOW_HTTP, got: {message}"
                );
                assert!(
                    message.contains("scheme \"http\""),
                    "error should cite the scheme so operators know what tripped the check, got: {message}"
                );
                assert!(
                    !message.contains("alice"),
                    "error must not echo userinfo username, got: {message}"
                );
                assert!(
                    !message.contains("supersecret"),
                    "error must not echo userinfo password, got: {message}"
                );
                assert!(
                    !message.contains("insecure.example"),
                    "error must not echo the host portion, got: {message}"
                );
                assert!(
                    !message.contains("http://alice:supersecret@insecure.example/root"),
                    "error must not echo the raw endpoint, got: {message}"
                );
            }
            Err(other) => panic!("expected InvalidRequest, got: {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_from_config_allows_http_with_flag() {
        let mut config = test_config();
        config.backend_endpoint = "http://example.com".to_string();
        config.backend_allow_http = true;

        let result = S3Backend::from_config(&config).await;
        assert!(
            result.is_ok(),
            "from_config should succeed with http:// when backend_allow_http is true, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_scheme_extraction_is_case_insensitive() {
        for url in &[
            "http://example.com",
            "HTTP://example.com",
            "Http://example.com",
        ] {
            let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or_default();
            assert!(
                scheme.eq_ignore_ascii_case("http"),
                "should detect http scheme in {url}"
            );
        }
        for url in &["https://example.com", "HTTPS://example.com"] {
            let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or_default();
            assert!(
                !scheme.eq_ignore_ascii_case("http"),
                "should not detect http scheme in {url}"
            );
        }
    }
}
