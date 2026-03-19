use std::collections::HashMap;
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use aws_smithy_types::timeout::TimeoutConfig;
use tokio_util::io::ReaderStream;

use crate::backend::models::*;
use crate::backend::retry::{with_retry, RetryPolicy};
use crate::backend::{Backend, BoxByteStream};
use crate::config::Config;
use crate::error::ProxyError;

/// S3 backend client that uses the aws-sdk-s3 crate to talk to an S3-compatible backend.
pub struct S3Backend {
    client: Client,
    #[allow(dead_code)]
    default_bucket: String,
    get_policy: RetryPolicy,
    head_policy: RetryPolicy,
    list_policy: RetryPolicy,
    put_policy: RetryPolicy,
    delete_policy: RetryPolicy,
}

impl S3Backend {
    /// Build an S3Backend from the application configuration.
    pub async fn from_config(config: &Config) -> Result<Self, ProxyError> {
        // Enforce BACKEND_ALLOW_HTTP: reject http:// endpoints unless explicitly allowed.
        if !config.backend_allow_http
            && config.backend_endpoint.starts_with("http://")
        {
            return Err(ProxyError::InvalidRequest {
                message: format!(
                    "backend endpoint uses HTTP ({}) but BACKEND_ALLOW_HTTP is not enabled; \
                     set BACKEND_ALLOW_HTTP=true to allow plaintext connections",
                    config.backend_endpoint,
                ),
            });
        }

        let credentials = Credentials::new(
            &config.backend_access_key_id,
            &config.backend_secret_access_key,
            None,  // session token
            None,  // expiry
            "tiny-s3-proxy-static",
        );

        let timeout_config = TimeoutConfig::builder()
            .connect_timeout(Duration::from_millis(config.upstream_connect_timeout_ms))
            .read_timeout(Duration::from_millis(config.upstream_request_timeout_ms))
            .build();

        let sdk_config = aws_sdk_s3::config::Builder::new()
            .endpoint_url(&config.backend_endpoint)
            .region(Region::new(config.backend_region.clone()))
            .credentials_provider(credentials)
            .force_path_style(config.backend_use_path_style)
            .timeout_config(timeout_config)
            .behavior_version_latest()
            .build();

        let client = Client::from_conf(sdk_config);

        let base_ms = config.retry_base_backoff_ms;

        Ok(Self {
            client,
            default_bucket: config.backend_bucket.clone(),
            get_policy: RetryPolicy::for_reads(config.get_max_attempts, base_ms),
            head_policy: RetryPolicy::for_reads(config.head_max_attempts, base_ms),
            list_policy: RetryPolicy::for_reads(config.list_max_attempts, base_ms),
            put_policy: RetryPolicy::for_writes(config.put_max_attempts, base_ms),
            delete_policy: RetryPolicy::for_idempotent_writes(config.delete_max_attempts, base_ms),
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
            extra.insert("x-amz-server-side-encryption".into(), v.as_str().to_string());
        }
        if let Some(v) = $resp.ssekms_key_id() {
            extra.insert("x-amz-server-side-encryption-aws-kms-key-id".into(), v.to_string());
        }
        if let Some(v) = $resp.sse_customer_algorithm() {
            extra.insert("x-amz-server-side-encryption-customer-algorithm".into(), v.to_string());
        }
        if let Some(v) = $resp.sse_customer_key_md5() {
            extra.insert("x-amz-server-side-encryption-customer-key-md5".into(), v.to_string());
        }
        if $resp.bucket_key_enabled().unwrap_or(false) {
            extra.insert("x-amz-server-side-encryption-bucket-key-enabled".into(), "true".into());
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
            extra.insert("x-amz-object-lock-legal-hold".into(), v.as_str().to_string());
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

/// Extract HEAD-only response headers not present on GetObjectOutput.
macro_rules! extract_head_extra_headers {
    ($resp:expr, $extra:expr) => {
        if let Some(v) = $resp.archive_status() {
            $extra.insert("x-amz-archive-status".into(), v.as_str().to_string());
        }
    };
}

impl Backend for S3Backend {
    async fn get_object(&self, bucket: &str, key: &str) -> Result<(GetObjectMeta, BoxByteStream), ProxyError> {
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
                client
                    .get_object()
                    .bucket(&bucket)
                    .key(&key)
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

    async fn head_object(&self, bucket: &str, key: &str) -> Result<HeadObjectOutput, ProxyError> {
        let bucket = bucket.to_string();
        let key = key.to_string();

        with_retry(&self.head_policy, "head_object", |_attempt| {
            let client = &self.client;
            let bucket = bucket.clone();
            let key = key.clone();
            async move {
                let resp = client
                    .head_object()
                    .bucket(&bucket)
                    .key(&key)
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

                // Forward extra x-amz-* headers as custom headers.
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
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "put_object"))?;

                Ok(PutObjectOutput {
                    etag: resp.e_tag().map(|s| s.to_string()),
                })
            }
        })
        .await
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProxyError> {
        let bucket = bucket.to_string();
        let key = key.to_string();

        with_retry(&self.delete_policy, "delete_object", |_attempt| {
            let client = &self.client;
            let bucket = bucket.clone();
            let key = key.clone();
            async move {
                client
                    .delete_object()
                    .bucket(&bucket)
                    .key(&key)
                    .send()
                    .await
                    .map_err(|e| map_sdk_error(e, "delete_object"))?;

                Ok(())
            }
        })
        .await
    }

    async fn list_objects(
        &self,
        req: ListObjectsInput,
    ) -> Result<ListObjectsOutput, ProxyError> {
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
        bucket: &str,
        key: &str,
        content_type: Option<&str>,
        metadata: &HashMap<String, String>,
    ) -> Result<CreateMultipartOutput, ProxyError> {
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

        let resp = builder
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "create_multipart_upload"))?;

        let upload_id = resp
            .upload_id()
            .ok_or_else(|| ProxyError::Internal {
                source: "create_multipart_upload returned no upload_id".into(),
            })?
            .to_string();

        Ok(CreateMultipartOutput { upload_id })
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

        Ok(UploadPartOutput { etag })
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

        Ok(CompleteMultipartOutput {
            etag: resp.e_tag().map(|s| s.to_string()),
            location: resp.location().map(|s| s.to_string()),
        })
    }

    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), ProxyError> {
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

    let contents = resp
        .contents()
        .iter()
        .map(|obj| ObjectInfo {
            key: obj.key().unwrap_or_default().to_string(),
            last_modified: obj.last_modified().and_then(to_chrono),
            etag: obj.e_tag().map(|s| s.to_string()),
            size: obj.size(),
            storage_class: obj
                .storage_class()
                .map(|sc| sc.as_str().to_string()),
        })
        .collect();

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
        encoding_type: resp
            .encoding_type()
            .map(|et| et.as_str().to_string()),
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

    let contents = resp
        .contents()
        .iter()
        .map(|obj| ObjectInfo {
            key: obj.key().unwrap_or_default().to_string(),
            last_modified: obj.last_modified().and_then(to_chrono),
            etag: obj.e_tag().map(|s| s.to_string()),
            size: obj.size(),
            storage_class: obj
                .storage_class()
                .map(|sc| sc.as_str().to_string()),
        })
        .collect();

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
        encoding_type: resp
            .encoding_type()
            .map(|et| et.as_str().to_string()),
        key_count: None,
        continuation_token: None,
        next_continuation_token: None,
        start_after: None,
        marker: resp.marker().map(|s| s.to_string()),
        next_marker: resp.next_marker().map(|s| s.to_string()),
    })
}
