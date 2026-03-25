use std::sync::Arc;

use axum::body::Body;
use bytes::Bytes;
use http::Response;

use crate::backend::Backend;
use crate::backend::models::{
    AbortMultipartUploadInput, CompleteMultipartInput, CreateMultipartUploadInput, UploadPartInput,
};
use crate::cache::CacheStore;
use crate::cache::key::CacheKey;
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::{append_extra_headers, common_headers};
use crate::s3::ops::ParsedRequest;
use crate::s3::xml::{
    parse_complete_multipart_body, serialize_complete_multipart, serialize_initiate_multipart,
};

/// Handle CreateMultipartUpload. Passthrough to backend.
pub async fn handle_create_multipart<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
) -> Response<Body> {
    let result = state
        .backend
        .create_multipart_upload(CreateMultipartUploadInput {
            bucket: &state.backend_bucket,
            key,
            content_type: parsed.content_type.as_deref(),
            metadata: &parsed.user_metadata,
            content_headers: &parsed.content_headers,
        })
        .await;

    match result {
        Ok(output) => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "CreateMultipartUpload",
                key = key,
                upload_id = %output.upload_id,
                "multipart upload initiated"
            );

            let xml = serialize_initiate_multipart(&state.frontend_bucket, key, &output.upload_id);

            let headers = common_headers(&parsed.request_id);
            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            response = append_extra_headers(response, &output.extra_headers);
            response
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "CreateMultipartUpload",
                key = key,
                "backend error"
            );
            let s3err = S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.frontend_bucket, key)),
            );
            s3err.to_response()
        }
    }
}

/// Handle UploadPart. Passthrough to backend.
pub async fn handle_upload_part<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    part_number: i32,
    upload_id: &str,
    body: Body,
) -> Response<Body> {
    // Validate partNumber: S3 requires 1..=10000
    if !(1..=10000).contains(&part_number) {
        let s3err = S3Error::invalid_argument(
            &format!(
                "Part number must be between 1 and 10000, got {}",
                part_number
            ),
            &parsed.request_id,
        );
        return s3err.to_response();
    }

    // Read body bytes
    let body_bytes =
        match axum::body::to_bytes(body, state.config.max_request_body_bytes as usize).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    request_id = %parsed.request_id,
                    error = %e,
                    operation = "UploadPart",
                    key = key,
                    "failed to read request body"
                );
                let s3err = S3Error::from_body_error(&e, &parsed.request_id);
                return s3err.to_response();
            }
        };

    let input = UploadPartInput {
        bucket: state.backend_bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
        part_number,
        body: body_bytes,
        content_md5: parsed.content_md5.clone(),
    };

    // No retry for upload_part (handled by the backend client)
    let result = state.backend.upload_part(input).await;

    match result {
        Ok(output) => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "UploadPart",
                key = key,
                part_number = part_number,
                "part uploaded"
            );

            let mut headers = common_headers(&parsed.request_id);
            if let Ok(val) = http::header::HeaderValue::from_str(&output.etag) {
                headers.insert("etag", val);
            }

            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            response = append_extra_headers(response, &output.extra_headers);
            response.body(Body::empty()).unwrap()
        }
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "UploadPart",
                key = key,
                part_number = part_number,
                "backend error"
            );
            let s3err = S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.frontend_bucket, key)),
            );
            s3err.to_response()
        }
    }
}

/// Handle CompleteMultipartUpload. On success, purges cache for the final object key.
pub async fn handle_complete_multipart<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    upload_id: &str,
    body_bytes: Bytes,
) -> Response<Body> {
    // Parse the CompleteMultipartUpload XML
    let parts = match parse_complete_multipart_body(&body_bytes) {
        Ok(parts) => parts,
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "CompleteMultipartUpload",
                key = key,
                "failed to parse CompleteMultipartUpload XML"
            );
            let s3err = S3Error::malformed_xml(
                &format!("failed to parse CompleteMultipartUpload XML: {}", e),
                &parsed.request_id,
            );
            return s3err.to_response();
        }
    };

    let input = CompleteMultipartInput {
        bucket: state.backend_bucket.to_string(),
        key: key.to_string(),
        upload_id: upload_id.to_string(),
        parts,
    };

    let result = state.backend.complete_multipart_upload(input).await;

    match result {
        Ok(output) => {
            // Purge cache for the final object key (best-effort with one retry)
            let cache_key = CacheKey::new(&*state.backend_bucket, key);
            super::invalidate_cache_key(
                &state.cache,
                &state.singleflight,
                &cache_key,
                "CompleteMultipartUpload",
                key,
                &parsed.request_id,
            )
            .await;

            tracing::info!(
                request_id = %parsed.request_id,
                operation = "CompleteMultipartUpload",
                key = key,
                upload_id = upload_id,
                "multipart upload completed"
            );

            // Omit the backend Location — it contains the internal backend
            // endpoint/bucket which would leak to clients. The proxy cannot
            // reliably reconstruct the correct public-facing URL.
            let xml = serialize_complete_multipart(
                &state.frontend_bucket,
                key,
                output.etag.as_deref(),
                None,
            );

            let headers = common_headers(&parsed.request_id);
            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            if let Some(ref vid) = output.version_id {
                response = response.header("x-amz-version-id", vid);
            }
            response = append_extra_headers(response, &output.extra_headers);
            response
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "CompleteMultipartUpload",
                key = key,
                upload_id = upload_id,
                "backend error"
            );
            let s3err = S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.frontend_bucket, key)),
            );
            s3err.to_response()
        }
    }
}

/// Handle AbortMultipartUpload. Passthrough to backend.
pub async fn handle_abort_multipart<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    key: &str,
    upload_id: &str,
) -> Response<Body> {
    let result = state
        .backend
        .abort_multipart_upload(AbortMultipartUploadInput {
            bucket: &state.backend_bucket,
            key,
            upload_id,
        })
        .await;

    match result {
        Ok(()) => {
            tracing::info!(
                request_id = %parsed.request_id,
                operation = "AbortMultipartUpload",
                key = key,
                upload_id = upload_id,
                "multipart upload aborted"
            );

            let headers = common_headers(&parsed.request_id);
            let mut response = Response::builder().status(204);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            response.body(Body::empty()).unwrap()
        }
        Err(e) => {
            tracing::error!(
                request_id = %parsed.request_id,
                error = %e,
                operation = "AbortMultipartUpload",
                key = key,
                upload_id = upload_id,
                "backend error"
            );
            let s3err = S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}/{}", state.frontend_bucket, key)),
            );
            s3err.to_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::models::{
        CompleteMultipartOutput, CreateMultipartOutput, UploadPartOutput,
    };
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ParsedRequest, S3Operation};

    fn make_parsed_create(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::CreateMultipartUpload {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
            },
            request_id: "test-req-id".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            content_length: None,
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
            content_headers: std::collections::HashMap::new(),
        }
    }

    fn make_parsed_upload_part(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::UploadPart {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
                part_number: 1,
                upload_id: "upload-123".to_string(),
            },
            request_id: "test-req-id".to_string(),
            content_type: None,
            content_length: Some(5),
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
            content_headers: std::collections::HashMap::new(),
        }
    }

    fn make_parsed_complete(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::CompleteMultipartUpload {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
                upload_id: "upload-123".to_string(),
            },
            request_id: "test-req-id".to_string(),
            content_type: Some("application/xml".to_string()),
            content_length: None,
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
            content_headers: std::collections::HashMap::new(),
        }
    }

    fn make_parsed_abort(key: &str) -> ParsedRequest {
        ParsedRequest {
            operation: S3Operation::AbortMultipartUpload {
                bucket: "test-frontend".to_string(),
                key: key.to_string(),
                upload_id: "upload-123".to_string(),
            },
            request_id: "test-req-id".to_string(),
            content_type: None,
            content_length: None,
            content_md5: None,
            authorization: None,
            amz_date: None,
            amz_content_sha256: None,
            range: None,
            user_metadata: std::collections::HashMap::new(),
            extra_amz_headers: std::collections::HashMap::new(),
            content_headers: std::collections::HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_create_multipart_success() {
        let key = "uploads/file.bin";
        let backend = MockBackend::new().with_create_multipart(Ok(CreateMultipartOutput {
            upload_id: "new-upload-id".to_string(),
            extra_headers: std::collections::HashMap::new(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed_create(key);

        let resp = handle_create_multipart(&state, &parsed, key).await;

        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("<UploadId>new-upload-id</UploadId>"));
        assert!(body_str.contains("<Bucket>test-frontend</Bucket>"));
    }

    #[tokio::test]
    async fn test_upload_part_success() {
        let key = "uploads/file.bin";
        let backend = MockBackend::new().with_upload_part(Ok(UploadPartOutput {
            etag: "\"part-etag\"".to_string(),
            extra_headers: std::collections::HashMap::new(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed_upload_part(key);

        let body = Body::from(b"hello".to_vec());
        let resp = handle_upload_part(&state, &parsed, key, 1, "upload-123", body).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("etag").unwrap().to_str().unwrap(),
            "\"part-etag\""
        );
    }

    #[tokio::test]
    async fn test_complete_multipart_success_purges_cache() {
        let key = "script_bundle/assembled.js";
        let backend = MockBackend::new().with_complete_multipart(Ok(CompleteMultipartOutput {
            etag: Some("\"final-etag\"".to_string()),
            location: None,
            version_id: None,
            extra_headers: std::collections::HashMap::new(),
        }));

        let cache_key = crate::cache::key::CacheKey::new("test-backend", key);
        let meta = test_cache_meta("test-backend", key, b"old");
        let cache = MockCache::new().with_entry(&cache_key, b"old", meta);

        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed_complete(key);

        let xml_body = br#"<CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>"e1"</ETag></Part>
        </CompleteMultipartUpload>"#;
        let body = Bytes::from(xml_body.to_vec());

        let resp = handle_complete_multipart(&state, &parsed, key, "upload-123", body).await;

        assert_eq!(resp.status(), 200);
        let resp_body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8_lossy(&resp_body);
        assert!(body_str.contains("<ETag>\"final-etag\"</ETag>"));

        // Verify cache was purged
        let cached = state.cache.lookup(&cache_key).await.unwrap();
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_complete_multipart_calls_poison_on_purge_failure() {
        let key = "script_bundle/assembled.js";
        let backend = MockBackend::new().with_complete_multipart(Ok(CompleteMultipartOutput {
            etag: Some("\"final-etag\"".to_string()),
            location: None,
            version_id: None,
            extra_headers: std::collections::HashMap::new(),
        }));

        let cache = MockCache::new().with_purge_failing();
        let state = build_app_state(backend, cache, MockAuth::allow_all());
        let parsed = make_parsed_complete(key);

        let xml_body = br#"<CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>"e1"</ETag></Part>
        </CompleteMultipartUpload>"#;
        let body = Bytes::from(xml_body.to_vec());

        let resp = handle_complete_multipart(&state, &parsed, key, "upload-123", body).await;

        // Complete should succeed even though purge failed
        assert_eq!(resp.status(), 200);

        // Poison should have been called
        let poison_calls = state.cache.poison_calls.lock().unwrap();
        assert_eq!(poison_calls.len(), 1);
        let expected_key = crate::cache::key::CacheKey::new("test-backend", key);
        assert_eq!(poison_calls[0], expected_key);
    }

    #[tokio::test]
    async fn test_abort_multipart_success() {
        let key = "uploads/file.bin";
        let backend = MockBackend::new().with_abort_multipart(Ok(()));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed_abort(key);

        let resp = handle_abort_multipart(&state, &parsed, key, "upload-123").await;

        assert_eq!(resp.status(), 204);
    }

    #[tokio::test]
    async fn test_create_multipart_backend_error() {
        let key = "uploads/file.bin";
        let backend =
            MockBackend::new().with_create_multipart(Err(crate::error::ProxyError::Backend {
                source: "create failed".into(),
                operation: "create_multipart_upload".into(),
            }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let parsed = make_parsed_create(key);

        let resp = handle_create_multipart(&state, &parsed, key).await;

        assert_eq!(resp.status(), 502);
    }
}
