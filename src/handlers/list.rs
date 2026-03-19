use std::sync::Arc;

use axum::body::Body;
use http::Response;

use crate::backend::models::ListObjectsInput;
use crate::backend::Backend;
use crate::cache::CacheStore;
use crate::handlers::AppState;
use crate::s3::errors::S3Error;
use crate::s3::headers::common_headers;
use crate::s3::ops::{ListParams, ParsedRequest};
use crate::s3::xml::{serialize_list_objects_v1, serialize_list_objects_v2};

/// Handle a ListObjects (V1 or V2) request. Passthrough to backend.
pub async fn handle_list<B: Backend, C: CacheStore>(
    state: &Arc<AppState<B, C>>,
    parsed: &ParsedRequest,
    params: &ListParams,
    is_v2: bool,
) -> Response<Body> {
    let input = ListObjectsInput {
        bucket: state.backend_bucket.to_string(),
        prefix: params.prefix.clone(),
        delimiter: params.delimiter.clone(),
        max_keys: params.max_keys,
        continuation_token: params.continuation_token.clone(),
        marker: params.marker.clone(),
        start_after: params.start_after.clone(),
        encoding_type: params.encoding_type.clone(),
        is_v2,
    };

    // Retry handled by the backend client
    let result = state.backend.list_objects(input).await;

    match result {
        Ok(output) => {
            // Rewrite the bucket name from backend to frontend so clients
            // see the bucket name they addressed, not the internal backend name.
            let mut output = output;
            output.name = state.frontend_bucket.to_string();

            let xml = if is_v2 {
                serialize_list_objects_v2(&output)
            } else {
                serialize_list_objects_v1(&output)
            };

            tracing::info!(
                request_id = %parsed.request_id,
                operation = if is_v2 { "ListObjectsV2" } else { "ListObjectsV1" },
                object_count = output.contents.len(),
                is_truncated = output.is_truncated,
                "list objects success"
            );

            let headers = common_headers(&parsed.request_id);

            let mut response = Response::builder().status(200);
            for (k, v) in headers.iter() {
                response = response.header(k, v);
            }
            response
                .header("content-type", "application/xml")
                .body(Body::from(xml))
                .unwrap()
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                operation = "ListObjects",
                "backend error"
            );
            let s3err = S3Error::from_proxy_error(
                &e,
                &parsed.request_id,
                Some(&format!("/{}", state.frontend_bucket)),
            );
            s3err.to_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::models::{ListObjectsOutput, ObjectInfo};
    use crate::handlers::test_utils::*;
    use crate::s3::ops::{ListParams, ParsedRequest, S3Operation};

    fn make_parsed_v2() -> (ParsedRequest, ListParams) {
        let params = ListParams {
            prefix: Some("scripts/".to_string()),
            delimiter: Some("/".to_string()),
            max_keys: Some(100),
            continuation_token: None,
            marker: None,
            start_after: None,
            encoding_type: None,
        };
        let parsed = ParsedRequest {
            operation: S3Operation::ListObjectsV2 {
                bucket: "test-frontend".to_string(),
                params: params.clone(),
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
        };
        (parsed, params)
    }

    #[tokio::test]
    async fn test_list_v2_returns_correct_xml() {
        let list_output = ListObjectsOutput {
            is_truncated: false,
            contents: vec![ObjectInfo {
                key: "scripts/app.js".to_string(),
                last_modified: None,
                etag: Some("\"abc\"".to_string()),
                size: Some(100),
                storage_class: Some("STANDARD".to_string()),
            }],
            common_prefixes: vec![],
            name: "test-backend".to_string(),
            prefix: Some("scripts/".to_string()),
            delimiter: Some("/".to_string()),
            max_keys: 100,
            encoding_type: None,
            key_count: Some(1),
            continuation_token: None,
            next_continuation_token: None,
            start_after: None,
            marker: None,
            next_marker: None,
        };

        let backend = MockBackend::new().with_list(Ok(list_output));
        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let (parsed, params) = make_parsed_v2();

        let resp = handle_list(&state, &parsed, &params, true).await;

        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/xml"
        );

        let body = axum::body::to_bytes(resp.into_body(), 8192)
            .await
            .unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("<ListBucketResult"));
        assert!(body_str.contains("<Key>scripts/app.js</Key>"));
        assert!(body_str.contains("<KeyCount>1</KeyCount>"));
    }

    #[tokio::test]
    async fn test_list_backend_error() {
        let backend = MockBackend::new().with_list(Err(crate::error::ProxyError::Backend {
            source: "list failed".into(),
            operation: "list_objects".into(),
        }));

        let state = build_app_state(backend, MockCache::new(), MockAuth::allow_all());
        let (parsed, params) = make_parsed_v2();

        let resp = handle_list(&state, &parsed, &params, true).await;

        assert_eq!(resp.status(), 502);
    }
}
