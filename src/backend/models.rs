use bytes::Bytes;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug)]
pub struct GetObjectOutput {
    /// The full object body. For v1, we buffer the whole body; can switch to streaming later.
    pub body: Vec<u8>,
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub etag: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug)]
pub struct HeadObjectOutput {
    pub content_type: Option<String>,
    pub content_length: Option<i64>,
    pub etag: Option<String>,
    pub last_modified: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug)]
pub struct PutObjectInput {
    pub bucket: String,
    pub key: String,
    pub body: Bytes,
    pub content_type: Option<String>,
    pub content_md5: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug)]
pub struct PutObjectOutput {
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ListObjectsInput {
    pub bucket: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub max_keys: Option<i32>,
    pub continuation_token: Option<String>,
    pub marker: Option<String>,
    pub start_after: Option<String>,
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
}

#[derive(Debug)]
pub struct CreateMultipartOutput {
    pub upload_id: String,
}

#[derive(Debug)]
pub struct UploadPartInput {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub part_number: i32,
    pub body: Bytes,
    pub content_md5: Option<String>,
}

#[derive(Debug)]
pub struct UploadPartOutput {
    pub etag: String,
}

#[derive(Debug)]
pub struct CompletedPart {
    pub etag: String,
    pub part_number: i32,
}

#[derive(Debug)]
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
}
