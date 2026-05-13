use bytes::Bytes;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::PathBuf;
use typed_builder::TypedBuilder;

/// Input for get_object operations.
#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct GetObjectInput<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub options: ReadOptions,
}

/// Input for head_object operations.
#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct HeadObjectInput<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub options: ReadOptions,
}

/// Input for delete_object operations.
#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct DeleteObjectInput<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
}

/// Input for create_multipart_upload operations.
#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct CreateMultipartUploadInput<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    #[builder(default)]
    pub content_type: Option<&'a str>,
    pub metadata: &'a HashMap<String, String>,
    pub content_headers: &'a HashMap<String, String>,
}

/// Input for abort_multipart_upload operations.
#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct AbortMultipartUploadInput<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub upload_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumMode {
    Enabled,
}

impl ChecksumMode {
    pub fn from_header_value(value: &str) -> Option<Self> {
        (value == "ENABLED").then_some(Self::Enabled)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadOptions {
    pub checksum_mode: Option<ChecksumMode>,
}

impl ReadOptions {
    pub fn wants_checksum_headers(self) -> bool {
        matches!(self.checksum_mode, Some(ChecksumMode::Enabled))
    }
}

/// Metadata from a GET response (no body).
#[derive(Debug, Clone)]
pub struct GetObjectMeta {
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub etag: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
    /// Standard S3 response headers not modeled as explicit fields, captured
    /// via typed SDK accessors. See `extract_extra_headers!` in client.rs for
    /// the exact list (covers every typed accessor on GetObjectOutput as of
    /// aws-sdk-s3 1.127.0).
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct HeadObjectOutput {
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub etag: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
    /// Standard S3 response headers not modeled as explicit fields, captured
    /// via typed SDK accessors. See `extract_extra_headers!` +
    /// `extract_head_extra_headers!` in client.rs for the exact list (covers
    /// every typed accessor on HeadObjectOutput, including HEAD-only fields
    /// like archive_status, as of aws-sdk-s3 1.127.0).
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct PutObjectInput {
    pub bucket: String,
    pub key: String,
    pub body: Bytes,
    #[builder(default)]
    pub content_type: Option<String>,
    #[builder(default)]
    pub content_md5: Option<String>,
    #[builder(default)]
    pub metadata: HashMap<String, String>,
    #[builder(default)]
    pub extra_amz_headers: HashMap<String, String>,
    /// Standard content headers to forward (content-encoding, content-disposition, etc.).
    #[builder(default)]
    pub content_headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct PutObjectOutput {
    pub etag: Option<String>,
    pub version_id: Option<String>,
    /// SSE, checksum, expiration, and other write-response headers captured
    /// from the SDK response. See `extract_write_extra_headers!` in client.rs.
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct DeleteObjectOutput {
    pub delete_marker: Option<bool>,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, TypedBuilder)]
#[non_exhaustive]
pub struct ListObjectsInput {
    pub bucket: String,
    #[builder(default)]
    pub prefix: Option<String>,
    #[builder(default)]
    pub delimiter: Option<String>,
    #[builder(default)]
    pub max_keys: Option<i32>,
    #[builder(default)]
    pub continuation_token: Option<String>,
    #[builder(default)]
    pub marker: Option<String>,
    #[builder(default)]
    pub start_after: Option<String>,
    #[builder(default)]
    pub encoding_type: Option<String>,
    pub is_v2: bool,
}

#[derive(Debug, Clone)]
pub struct ListObjectsOutput {
    pub is_truncated: bool,
    pub contents: Vec<ObjectInfo>,
    pub common_prefixes: Vec<String>,
    pub name: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: i32,
    pub encoding_type: Option<String>,
    // V2 fields
    pub key_count: Option<i32>,
    pub continuation_token: Option<String>,
    pub next_continuation_token: Option<String>,
    pub start_after: Option<String>,
    // V1 fields
    pub marker: Option<String>,
    pub next_marker: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub last_modified: Option<DateTime<Utc>>,
    pub etag: Option<String>,
    pub size: Option<i64>,
    pub storage_class: Option<String>,
    pub checksum_algorithm: Vec<String>,
    pub checksum_type: Option<String>,
}

#[derive(Debug)]
pub struct CreateMultipartOutput {
    pub upload_id: String,
    /// SSE, checksum, and other write-response headers captured from the SDK
    /// response. See `extract_write_extra_headers!` in client.rs.
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct UploadPartInput {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub part_number: i32,
    pub body: Bytes,
    #[builder(default)]
    pub content_md5: Option<String>,
}

/// Input for `put_object_from_path`. Identical to `PutObjectInput` except the
/// body is read from a single-owner spool file on disk rather than held in
/// memory. Used by the aws-chunked decode path so very large decoded bodies
/// don't need to be buffered in RAM.
#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct PutObjectSpoolInput {
    pub bucket: String,
    pub key: String,
    pub path: PathBuf,
    pub len: u64,
    /// SHA-256 of the decoded body, computed by the aws-chunked decoder.
    /// Informational for now; strict verification is tracked in #63.
    pub sha256_hex: String,
    #[builder(default)]
    pub content_type: Option<String>,
    #[builder(default)]
    pub content_md5: Option<String>,
    #[builder(default)]
    pub metadata: HashMap<String, String>,
    #[builder(default)]
    pub extra_amz_headers: HashMap<String, String>,
    #[builder(default)]
    pub content_headers: HashMap<String, String>,
}

/// Input for `upload_part_from_path`. Spool-file counterpart to
/// `UploadPartInput`.
#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct UploadPartSpoolInput {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub part_number: i32,
    pub path: PathBuf,
    pub len: u64,
    pub sha256_hex: String,
    #[builder(default)]
    pub content_md5: Option<String>,
    #[builder(default)]
    pub extra_amz_headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct UploadPartOutput {
    pub etag: String,
    /// SSE, checksum, and other write-response headers captured from the SDK
    /// response. See `extract_write_extra_headers!` in client.rs.
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct CompletedPart {
    pub etag: String,
    pub part_number: i32,
}

#[derive(Debug, TypedBuilder)]
#[non_exhaustive]
pub struct CompleteMultipartInput {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub parts: Vec<CompletedPart>,
}

#[derive(Debug)]
pub struct CompleteMultipartOutput {
    pub etag: Option<String>,
    pub location: Option<String>,
    pub version_id: Option<String>,
    /// SSE, checksum, expiration, and other write-response headers captured
    /// from the SDK response. See `extract_write_extra_headers!` in client.rs.
    pub extra_headers: HashMap<String, String>,
}
