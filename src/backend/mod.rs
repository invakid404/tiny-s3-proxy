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
    /// Retrieve an object's body and metadata.
    fn get_object(
        &self,
        req: GetObjectInput<'_>,
    ) -> impl std::future::Future<Output = Result<(GetObjectMeta, BoxByteStream), ProxyError>> + Send;
    /// Retrieve an object's metadata without its body.
    fn head_object(
        &self,
        req: HeadObjectInput<'_>,
    ) -> impl std::future::Future<Output = Result<HeadObjectOutput, ProxyError>> + Send;
    /// Upload an object.
    fn put_object(
        &self,
        req: PutObjectInput,
    ) -> impl std::future::Future<Output = Result<PutObjectOutput, ProxyError>> + Send;
    /// Upload an object whose body lives in a single-owner spool file on disk.
    /// Used by the aws-chunked decode path so the decoded body can be streamed
    /// from disk rather than held in memory.
    fn put_object_from_path(
        &self,
        req: PutObjectSpoolInput,
    ) -> impl std::future::Future<Output = Result<PutObjectOutput, ProxyError>> + Send;
    /// Delete an object.
    fn delete_object(
        &self,
        req: DeleteObjectInput<'_>,
    ) -> impl std::future::Future<Output = Result<DeleteObjectOutput, ProxyError>> + Send;
    /// List objects in a bucket.
    fn list_objects(
        &self,
        req: ListObjectsInput,
    ) -> impl std::future::Future<Output = Result<ListObjectsOutput, ProxyError>> + Send;
    /// Initiate a multipart upload and return an upload ID.
    fn create_multipart_upload(
        &self,
        req: CreateMultipartUploadInput<'_>,
    ) -> impl std::future::Future<Output = Result<CreateMultipartOutput, ProxyError>> + Send;
    /// Upload a single part of a multipart upload.
    fn upload_part(
        &self,
        req: UploadPartInput,
    ) -> impl std::future::Future<Output = Result<UploadPartOutput, ProxyError>> + Send;
    /// Upload a single part of a multipart upload from a spool file on disk.
    fn upload_part_from_path(
        &self,
        req: UploadPartSpoolInput,
    ) -> impl std::future::Future<Output = Result<UploadPartOutput, ProxyError>> + Send;
    /// Finalize a multipart upload by assembling its parts.
    fn complete_multipart_upload(
        &self,
        req: CompleteMultipartInput,
    ) -> impl std::future::Future<Output = Result<CompleteMultipartOutput, ProxyError>> + Send;
    /// Cancel a multipart upload and discard uploaded parts.
    fn abort_multipart_upload(
        &self,
        req: AbortMultipartUploadInput<'_>,
    ) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;
}
