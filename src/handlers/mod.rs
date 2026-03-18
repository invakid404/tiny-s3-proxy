pub mod delete;
pub mod get;
pub mod head;
pub mod list;
pub mod multipart;
pub mod passthrough;
pub mod put;

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::State;
use http::{Request, Response};
use metrics::{counter, gauge, histogram};

use crate::auth::Authenticator;
use crate::backend::Backend;
use crate::cache::policy::CachePolicy;
use crate::cache::{CacheStore, SingleFlight};
use crate::config::Config;
use crate::s3::errors::S3Error;
use crate::s3::ops::S3Operation;
use crate::s3::parse::parse_request;

/// Shared application state passed to all handlers.
/// Generic over Backend and CacheStore to support both real and mock implementations,
/// since these traits use `async fn` and are not dyn-compatible.
pub struct AppState<B: Backend, C: CacheStore> {
    pub backend: Arc<B>,
    pub cache: Arc<C>,
    pub singleflight: Arc<SingleFlight>,
    pub auth: Arc<dyn Authenticator>,
    pub policy: CachePolicy,
    pub config: Arc<Config>,
    pub frontend_bucket: Arc<str>,
    pub backend_bucket: Arc<str>,
    pub http_client: reqwest::Client,
}

/// Main S3 request handler. All S3 API calls go through this function.
pub async fn handle_s3_request<B: Backend + 'static, C: CacheStore + 'static>(
    State(state): State<Arc<AppState<B, C>>>,
    req: Request<Body>,
) -> Response<Body> {
    let start = Instant::now();
    gauge!("s3proxy_in_flight_requests").increment(1.0);

    // Split request into parts and body so we can parse headers/URI
    // without consuming the body (needed for PUT/POST handlers).
    let (parts, body) = req.into_parts();
    let parse_req = Request::from_parts(parts, ());
    let parsed = parse_request(&parse_req);
    let (parts, _) = parse_req.into_parts();

    let op_name = parsed.operation.name();

    // Record request body size for writes (from content-length header).
    if let Some(cl) = parts.headers.get("content-length")
        && let Ok(size) = cl.to_str().unwrap_or("0").parse::<f64>()
    {
        histogram!("s3proxy_request_size_bytes", "operation" => op_name).record(size);
    }

    // Handle unsupported operations by proxying to the backend.
    if let S3Operation::Unsupported { ref method, ref path } = parsed.operation {
        tracing::warn!(
            request_id = %parsed.request_id,
            method = %method,
            path = %path,
            "unsupported operation, attempting passthrough to backend"
        );

        // Rewrite path: replace frontend bucket with backend bucket.
        let rewritten_path = rewrite_bucket_in_path(path, &state.frontend_bucket, &state.backend_bucket);
        let query = parts.uri.query();
        let response = passthrough::handle_passthrough(
            &state,
            method,
            &rewritten_path,
            query,
            &parts.headers,
            body,
            &parsed.request_id,
        )
        .await;
        record_metrics(op_name, &response, start);
        return response;
    }

    // Auth check
    if let Err(e) = state.auth.authenticate(&parsed) {
        let s3err = S3Error::from_proxy_error(&e, &parsed.request_id, None);
        let response = s3err.to_response();
        record_metrics(op_name, &response, start);
        return response;
    }

    // Check bucket is allowed (must match frontend_bucket)
    let op_bucket = parsed.operation.bucket();
    if op_bucket != &*state.frontend_bucket {
        let s3err = S3Error::no_such_bucket(op_bucket, &parsed.request_id);
        let response = s3err.to_response();
        record_metrics(op_name, &response, start);
        return response;
    }

    // Dispatch to handler based on operation
    let response = match &parsed.operation {
        S3Operation::GetObject { key, .. } => get::handle_get(&state, &parsed, key).await,
        S3Operation::HeadObject { key, .. } => head::handle_head(&state, &parsed, key).await,
        S3Operation::PutObject { key, .. } => put::handle_put(&state, &parsed, key, body).await,
        S3Operation::DeleteObject { key, .. } => {
            delete::handle_delete(&state, &parsed, key).await
        }
        S3Operation::ListObjectsV1 { params, .. }
        | S3Operation::ListObjectsV2 { params, .. } => {
            let is_v2 = matches!(&parsed.operation, S3Operation::ListObjectsV2 { .. });
            list::handle_list(&state, &parsed, params, is_v2).await
        }
        S3Operation::CreateMultipartUpload { key, .. } => {
            multipart::handle_create_multipart(&state, &parsed, key).await
        }
        S3Operation::UploadPart {
            key,
            part_number,
            upload_id,
            ..
        } => {
            multipart::handle_upload_part(&state, &parsed, key, *part_number, upload_id, body)
                .await
        }
        S3Operation::CompleteMultipartUpload { key, upload_id, .. } => {
            multipart::handle_complete_multipart(&state, &parsed, key, upload_id, body).await
        }
        S3Operation::AbortMultipartUpload { key, upload_id, .. } => {
            multipart::handle_abort_multipart(&state, &parsed, key, upload_id).await
        }
        S3Operation::Unsupported { .. } => {
            // Already handled above; this branch is unreachable.
            unreachable!("Unsupported operations are handled before dispatch")
        }
    };

    record_metrics(op_name, &response, start);
    response
}

/// Rewrite the bucket portion of a path-style S3 URL.
/// E.g. `/frontend-bucket/key` → `/backend-bucket/key`.
fn rewrite_bucket_in_path(path: &str, frontend_bucket: &str, backend_bucket: &str) -> String {
    let prefix = format!("/{}/", frontend_bucket);
    if path.starts_with(&prefix) {
        format!("/{}/{}", backend_bucket, &path[prefix.len()..])
    } else if path == format!("/{}", frontend_bucket) {
        format!("/{}", backend_bucket)
    } else {
        // Can't rewrite — pass through as-is.
        path.to_string()
    }
}

/// Map common HTTP status codes to static strings, avoiding allocation.
fn status_str(status: http::StatusCode) -> &'static str {
    match status.as_u16() {
        200 => "200", 204 => "204", 206 => "206",
        400 => "400", 403 => "403", 404 => "404",
        500 => "500", 501 => "501", 502 => "502", 503 => "503", 504 => "504",
        _ => "other",
    }
}

/// Record request metrics (counter + histogram + in-flight + cache + response size).
fn record_metrics(operation: &'static str, response: &Response<Body>, start: Instant) {
    gauge!("s3proxy_in_flight_requests").decrement(1.0);

    let duration = start.elapsed().as_secs_f64();
    let status = status_str(response.status());
    counter!("s3proxy_requests_total", "operation" => operation, "status" => status).increment(1);
    histogram!("s3proxy_request_duration_seconds", "operation" => operation).record(duration);

    // Cache hit/miss/bypass/stale tracking.
    if let Some(cache_status) = response.headers().get("x-cache")
        && let Ok(cs) = cache_status.to_str()
    {
        counter!("s3proxy_cache_total", "status" => cs.to_string()).increment(1);
    }

    // Response body size.
    if let Some(cl) = response.headers().get("content-length")
        && let Ok(size) = cl.to_str().unwrap_or("0").parse::<f64>()
    {
        histogram!("s3proxy_response_size_bytes", "operation" => operation).record(size);
    }
}

#[cfg(test)]
pub mod test_utils {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use bytes::Bytes;
    use chrono::Utc;

    use crate::auth::Authenticator;
    use crate::backend::models::*;
    use crate::backend::{Backend, BoxByteStream};
    use crate::cache::entry::CacheEntry;
    use crate::cache::key::CacheKey;
    use crate::cache::metadata::CacheMeta;
    use crate::cache::{CacheStatsSnapshot, CacheStore, FillGuard};
    use crate::error::ProxyError;
    use crate::s3::ops::ParsedRequest;

    // ---- MockBackend ----

    #[derive(Clone)]
    pub struct MockGetResponse {
        pub body: Vec<u8>,
        pub content_type: Option<String>,
        pub etag: Option<String>,
    }

    /// Convert a Vec<u8> into a BoxByteStream (single-chunk stream).
    fn vec_to_stream(data: Vec<u8>) -> BoxByteStream {
        let stream = futures_util::stream::once(async move {
            Ok::<Bytes, std::io::Error>(Bytes::from(data))
        });
        Box::pin(stream)
    }

    pub struct MockBackend {
        pub get_response: Mutex<Option<Result<MockGetResponse, ProxyError>>>,
        pub head_response: Mutex<Option<Result<HeadObjectOutput, ProxyError>>>,
        pub put_response: Mutex<Option<Result<PutObjectOutput, ProxyError>>>,
        pub delete_response: Mutex<Option<Result<(), ProxyError>>>,
        pub list_response: Mutex<Option<Result<ListObjectsOutput, ProxyError>>>,
        pub create_multipart_response: Mutex<Option<Result<CreateMultipartOutput, ProxyError>>>,
        pub upload_part_response: Mutex<Option<Result<UploadPartOutput, ProxyError>>>,
        pub complete_multipart_response:
            Mutex<Option<Result<CompleteMultipartOutput, ProxyError>>>,
        pub abort_multipart_response: Mutex<Option<Result<(), ProxyError>>>,
        pub put_calls: Mutex<Vec<PutObjectInput>>,
        pub delete_calls: Mutex<Vec<(String, String)>>,
    }

    impl MockBackend {
        pub fn new() -> Self {
            Self {
                get_response: Mutex::new(None),
                head_response: Mutex::new(None),
                put_response: Mutex::new(None),
                delete_response: Mutex::new(None),
                list_response: Mutex::new(None),
                create_multipart_response: Mutex::new(None),
                upload_part_response: Mutex::new(None),
                complete_multipart_response: Mutex::new(None),
                abort_multipart_response: Mutex::new(None),
                put_calls: Mutex::new(Vec::new()),
                delete_calls: Mutex::new(Vec::new()),
            }
        }

        pub fn with_get(self, resp: Result<MockGetResponse, ProxyError>) -> Self {
            *self.get_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_head(self, resp: Result<HeadObjectOutput, ProxyError>) -> Self {
            *self.head_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_put(self, resp: Result<PutObjectOutput, ProxyError>) -> Self {
            *self.put_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_delete(self, resp: Result<(), ProxyError>) -> Self {
            *self.delete_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_list(self, resp: Result<ListObjectsOutput, ProxyError>) -> Self {
            *self.list_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_create_multipart(
            self,
            resp: Result<CreateMultipartOutput, ProxyError>,
        ) -> Self {
            *self.create_multipart_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_upload_part(self, resp: Result<UploadPartOutput, ProxyError>) -> Self {
            *self.upload_part_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_complete_multipart(
            self,
            resp: Result<CompleteMultipartOutput, ProxyError>,
        ) -> Self {
            *self.complete_multipart_response.lock().unwrap() = Some(resp);
            self
        }

        pub fn with_abort_multipart(self, resp: Result<(), ProxyError>) -> Self {
            *self.abort_multipart_response.lock().unwrap() = Some(resp);
            self
        }
    }

    impl Backend for MockBackend {
        async fn get_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> Result<(GetObjectMeta, BoxByteStream), ProxyError> {
            let resp = self
                .get_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "get_object".into(),
                    })
                });
            match resp {
                Ok(mock) => {
                    let meta = GetObjectMeta {
                        content_type: mock.content_type.clone(),
                        content_length: Some(mock.body.len() as i64),
                        etag: mock.etag.clone(),
                        last_modified: Some(Utc::now()),
                        metadata: HashMap::new(),
                    };
                    let stream = vec_to_stream(mock.body);
                    Ok((meta, stream))
                }
                Err(e) => Err(e),
            }
        }

        async fn head_object(
            &self,
            _bucket: &str,
            _key: &str,
        ) -> Result<HeadObjectOutput, ProxyError> {
            self.head_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "head_object".into(),
                    })
                })
        }

        async fn put_object(&self, req: PutObjectInput) -> Result<PutObjectOutput, ProxyError> {
            self.put_calls.lock().unwrap().push(PutObjectInput {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                body: req.body.clone(),
                content_type: req.content_type.clone(),
                content_md5: req.content_md5.clone(),
                metadata: req.metadata.clone(),
            });
            self.put_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "put_object".into(),
                    })
                })
        }

        async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), ProxyError> {
            self.delete_calls
                .lock()
                .unwrap()
                .push((bucket.to_string(), key.to_string()));
            self.delete_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "delete_object".into(),
                    })
                })
        }

        async fn list_objects(
            &self,
            _req: ListObjectsInput,
        ) -> Result<ListObjectsOutput, ProxyError> {
            self.list_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "list_objects".into(),
                    })
                })
        }

        async fn create_multipart_upload(
            &self,
            _bucket: &str,
            _key: &str,
            _content_type: Option<&str>,
        ) -> Result<CreateMultipartOutput, ProxyError> {
            self.create_multipart_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "create_multipart_upload".into(),
                    })
                })
        }

        async fn upload_part(
            &self,
            _req: UploadPartInput,
        ) -> Result<UploadPartOutput, ProxyError> {
            self.upload_part_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "upload_part".into(),
                    })
                })
        }

        async fn complete_multipart_upload(
            &self,
            _req: CompleteMultipartInput,
        ) -> Result<CompleteMultipartOutput, ProxyError> {
            self.complete_multipart_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "complete_multipart_upload".into(),
                    })
                })
        }

        async fn abort_multipart_upload(
            &self,
            _bucket: &str,
            _key: &str,
            _upload_id: &str,
        ) -> Result<(), ProxyError> {
            self.abort_multipart_response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| {
                    Err(ProxyError::Backend {
                        source: "no mock response configured".into(),
                        operation: "abort_multipart_upload".into(),
                    })
                })
        }
    }

    // ---- MockCache ----
    //
    // Stores cache entries on disk in a temp directory so that
    // CacheEntry.body_path is a real file that can be streamed.

    pub struct MockCache {
        pub entries: Mutex<HashMap<String, CacheEntry>>,
        pub purge_calls: Mutex<Vec<CacheKey>>,
        pub fill_calls: Mutex<Vec<CacheKey>>,
        pub temp_dir: tempfile::TempDir,
    }

    impl MockCache {
        pub fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                purge_calls: Mutex::new(Vec::new()),
                fill_calls: Mutex::new(Vec::new()),
                temp_dir: tempfile::TempDir::new().expect("create mock cache temp dir"),
            }
        }

        /// Add a cache entry, writing the body to a temp file.
        pub fn with_entry(self, key: &CacheKey, body: &[u8], meta: CacheMeta) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static MOCK_COUNTER: AtomicU64 = AtomicU64::new(0);
            let id = MOCK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let body_path = self
                .temp_dir
                .path()
                .join(format!("{}.body", id));
            std::fs::write(&body_path, body).expect("write mock body");
            let entry = CacheEntry {
                meta,
                body_path,
            };
            self.entries.lock().unwrap().insert(key.hash_hex(), entry);
            self
        }
    }

    impl CacheStore for MockCache {
        async fn lookup(&self, key: &CacheKey) -> Result<Option<CacheEntry>, ProxyError> {
            let entries = self.entries.lock().unwrap();
            let entry = entries.get(&key.hash_hex()).map(|e| CacheEntry {
                meta: e.meta.clone(),
                body_path: e.body_path.clone(),
            });
            Ok(entry)
        }

        async fn begin_fill(&self, key: &CacheKey) -> Result<FillGuard, ProxyError> {
            self.fill_calls.lock().unwrap().push(key.clone());
            Ok(FillGuard {
                key: key.clone(),
                temp_dir: self.temp_dir.path().to_path_buf(),
            })
        }

        async fn commit_fill(
            &self,
            guard: FillGuard,
            temp_body_path: PathBuf,
            meta: CacheMeta,
        ) -> Result<(), ProxyError> {
            // For the mock, the temp_body_path already has the data.
            // Just store the entry with that path.
            let entry = CacheEntry {
                meta,
                body_path: temp_body_path,
            };
            self.entries
                .lock()
                .unwrap()
                .insert(guard.key.hash_hex(), entry);
            Ok(())
        }

        async fn purge(&self, key: &CacheKey) -> Result<bool, ProxyError> {
            self.purge_calls.lock().unwrap().push(key.clone());
            let removed = self.entries.lock().unwrap().remove(&key.hash_hex()).is_some();
            Ok(removed)
        }

        async fn stats(&self) -> CacheStatsSnapshot {
            CacheStatsSnapshot::default()
        }
    }

    // ---- MockAuth ----

    pub struct MockAuth {
        pub allow: bool,
    }

    impl MockAuth {
        pub fn allow_all() -> Self {
            Self { allow: true }
        }

        pub fn deny_all() -> Self {
            Self { allow: false }
        }
    }

    impl Authenticator for MockAuth {
        fn authenticate(&self, _req: &ParsedRequest) -> Result<(), ProxyError> {
            if self.allow {
                Ok(())
            } else {
                Err(ProxyError::Auth {
                    message: "access denied".to_string(),
                })
            }
        }
    }

    // ---- Helper to build AppState ----

    use super::AppState;
    use crate::cache::policy::CachePolicy;
    use crate::cache::SingleFlight;
    use crate::config::{AuthMode, Config};
    use std::sync::Arc;

    pub fn test_config() -> Config {
        Config {
            s3_listen_addr: "0.0.0.0:8080".to_string(),
            admin_listen_addr: "0.0.0.0:9090".to_string(),
            frontend_bucket: "test-frontend".to_string(),
            auth_mode: AuthMode::TrustedInternal,
            allowed_frontend_keys: vec![],
            backend_endpoint: "https://example.com".to_string(),
            backend_region: "auto".to_string(),
            backend_bucket: "test-backend".to_string(),
            backend_access_key_id: "AKID".to_string(),
            backend_secret_access_key: "secret".to_string(),
            backend_use_path_style: true,
            backend_allow_http: false,
            cache_dir: "/tmp/test-cache".to_string(),
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
            max_request_body_bytes: 5_368_709_120,
        }
    }

    pub fn build_app_state(
        backend: MockBackend,
        cache: MockCache,
        auth: MockAuth,
    ) -> Arc<AppState<MockBackend, MockCache>> {
        let mut config = test_config();
        // Point cache_dir to the MockCache's temp dir so tee tasks can write there
        config.cache_dir = cache.temp_dir.path().to_str().unwrap().to_string();
        // Create the tmp sub-directory that the tee task expects
        let tmp_dir = cache.temp_dir.path().join("tmp");
        let _ = std::fs::create_dir_all(&tmp_dir);

        Arc::new(AppState {
            backend: Arc::new(backend),
            cache: Arc::new(cache),
            singleflight: Arc::new(SingleFlight::new()),
            auth: Arc::new(auth),
            policy: CachePolicy::new(
                config.cacheable_prefixes.clone(),
                config.cache_max_object_bytes,
            ),
            frontend_bucket: Arc::from(config.frontend_bucket.as_str()),
            backend_bucket: Arc::from(config.backend_bucket.as_str()),
            http_client: reqwest::Client::new(),
            config: Arc::new(config),
        })
    }

    /// Build a test CacheMeta for a given key/body.
    pub fn test_cache_meta(bucket: &str, key: &str, body: &[u8]) -> CacheMeta {
        CacheMeta {
            bucket: bucket.to_string(),
            key: key.to_string(),
            etag: Some("\"test-etag\"".to_string()),
            last_modified: Some(Utc::now()),
            content_type: Some("application/octet-stream".to_string()),
            content_length: body.len() as i64,
            cache_written_at: Utc::now(),
            last_accessed_at: Utc::now(),
            hit_count: 0,
            source_status: 200,
            metadata: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_utils::*;
    use axum::body::Body;
    use http::Request;

    fn build_request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_unsupported_operation_attempts_passthrough() {
        let state = build_app_state(
            MockBackend::new(),
            MockCache::new(),
            MockAuth::allow_all(),
        );

        let req = build_request("PATCH", "/test-frontend/some-key");
        let resp = handle_s3_request(State(state), req).await;

        // Unsupported operations are now proxied to the backend.
        // The response depends on the backend's answer. In tests with
        // the example.com endpoint the status varies, so just verify
        // we did NOT get 501 (the old behaviour).
        assert_ne!(resp.status(), 501);
    }

    #[tokio::test]
    async fn test_wrong_bucket_returns_404() {
        let state = build_app_state(
            MockBackend::new(),
            MockCache::new(),
            MockAuth::allow_all(),
        );

        let req = build_request("GET", "/wrong-bucket/some-key");
        let resp = handle_s3_request(State(state), req).await;

        assert_eq!(resp.status(), 404);
        let body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("NoSuchBucket"));
    }

    #[tokio::test]
    async fn test_auth_failure_returns_403() {
        let state = build_app_state(
            MockBackend::new(),
            MockCache::new(),
            MockAuth::deny_all(),
        );

        let req = build_request("GET", "/test-frontend/some-key");
        let resp = handle_s3_request(State(state), req).await;

        assert_eq!(resp.status(), 403);
        let body = axum::body::to_bytes(resp.into_body(), 4096)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("AccessDenied"));
    }
}
