pub mod client;
pub mod models;
pub mod retry;

use std::pin::Pin;

use bytes::Bytes;
use tokio_stream::Stream;

use crate::error::ProxyError;
use models::*;

/// A streaming body type for GET responses.
pub type BoxByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// Trait defining the typed S3 backend interface.
/// All operations return typed results, not raw HTTP.
pub trait Backend: Send + Sync {
    fn get_object(
        &self,
        bucket: &str,
        key: &str,
        options: ReadOptions,
    ) -> impl std::future::Future<Output = Result<(GetObjectMeta, BoxByteStream), ProxyError>> + Send;
    fn head_object(
        &self,
        bucket: &str,
        key: &str,
        options: ReadOptions,
    ) -> impl std::future::Future<Output = Result<HeadObjectOutput, ProxyError>> + Send;
    fn put_object(
        &self,
        req: PutObjectInput,
    ) -> impl std::future::Future<Output = Result<PutObjectOutput, ProxyError>> + Send;
    fn delete_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> impl std::future::Future<Output = Result<DeleteObjectOutput, ProxyError>> + Send;
    fn list_objects(
        &self,
        req: ListObjectsInput,
    ) -> impl std::future::Future<Output = Result<ListObjectsOutput, ProxyError>> + Send;
    fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<&str>,
        metadata: &std::collections::HashMap<String, String>,
        content_headers: &std::collections::HashMap<String, String>,
    ) -> impl std::future::Future<Output = Result<CreateMultipartOutput, ProxyError>> + Send;
    fn upload_part(
        &self,
        req: UploadPartInput,
    ) -> impl std::future::Future<Output = Result<UploadPartOutput, ProxyError>> + Send;
    fn complete_multipart_upload(
        &self,
        req: CompleteMultipartInput,
    ) -> impl std::future::Future<Output = Result<CompleteMultipartOutput, ProxyError>> + Send;
    fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;
}
