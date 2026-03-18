pub mod client;
pub mod models;
pub mod retry;

use crate::error::ProxyError;
use models::*;

/// Trait defining the typed S3 backend interface.
/// All operations return typed results, not raw HTTP.
pub trait Backend: Send + Sync {
    fn get_object(&self, bucket: &str, key: &str) -> impl std::future::Future<Output = Result<GetObjectOutput, ProxyError>> + Send;
    fn head_object(&self, bucket: &str, key: &str) -> impl std::future::Future<Output = Result<HeadObjectOutput, ProxyError>> + Send;
    fn put_object(&self, req: PutObjectInput) -> impl std::future::Future<Output = Result<PutObjectOutput, ProxyError>> + Send;
    fn delete_object(&self, bucket: &str, key: &str) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;
    fn list_objects(&self, req: ListObjectsInput) -> impl std::future::Future<Output = Result<ListObjectsOutput, ProxyError>> + Send;
    fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: Option<&str>,
    ) -> impl std::future::Future<Output = Result<CreateMultipartOutput, ProxyError>> + Send;
    fn upload_part(&self, req: UploadPartInput) -> impl std::future::Future<Output = Result<UploadPartOutput, ProxyError>> + Send;
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
