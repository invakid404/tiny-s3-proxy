/// Headers that modify write semantics and cannot be preserved by any typed
/// path. Shared base for both PutObject and multipart gates.
pub(super) const WRITE_MODIFYING_BASE: &[&str] = &[
    "x-amz-storage-class",
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-bucket-key-enabled",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-request-payer",
    "x-amz-expected-bucket-owner",
    "x-amz-bypass-governance-retention",
    "x-amz-mfa",
    "x-amz-tagging",
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-object-lock-legal-hold",
    "x-amz-website-redirect-location",
    "x-amz-mp-object-size",
    "x-amz-if-match-last-modified-time",
    "x-amz-if-match-size",
    "x-amz-if-match-initiated-time",
    "x-amz-acl",
    "x-amz-grant-full-control",
    "x-amz-grant-read",
    "x-amz-grant-read-acp",
    "x-amz-grant-write-acp",
    // Append-mode PUTs have different semantics (conditional offset writes,
    // x-amz-object-size in the response) that the typed path wasn't designed for.
    "x-amz-write-offset-bytes",
];

/// Additional checksum headers that the typed multipart paths don't forward.
/// The typed PutObject path handles these end-to-end (request forwarded via
/// extra_amz_headers + customize().mutate_request(), response captured via
/// extract_write_extra_headers!), but CreateMultipartUpload, UploadPart, and
/// CompleteMultipartUpload do NOT forward checksum request headers, so they
/// must route to passthrough when these are present.
pub(super) const MULTIPART_CHECKSUM_HEADERS: &[&str] = &[
    "x-amz-checksum-algorithm",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
    "x-amz-checksum-type",
    "x-amz-sdk-checksum-algorithm",
];

/// Check if the request contains headers that the typed GET/HEAD backend
/// API cannot forward. When present, the request must go through the raw
/// HTTP passthrough to preserve semantics.
pub(super) fn checksum_mode_requires_passthrough(headers: &http::HeaderMap) -> bool {
    let mut values = headers.get_all("x-amz-checksum-mode").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(crate::backend::models::ChecksumMode::from_header_value)
        .is_none()
}

pub(super) fn has_unsupported_get_modifiers(headers: &http::HeaderMap) -> bool {
    headers.contains_key("range")
        || headers.contains_key("if-match")
        || headers.contains_key("if-none-match")
        || headers.contains_key("if-modified-since")
        || headers.contains_key("if-unmodified-since")
        || headers.contains_key("x-amz-request-payer")
        || headers.contains_key("x-amz-expected-bucket-owner")
        || checksum_mode_requires_passthrough(headers)
        || headers.keys().any(|k| {
            k.as_str()
                .starts_with("x-amz-server-side-encryption-customer-")
        })
}

/// Check for standard HTTP conditionals that typed write paths don't forward.
pub(super) fn has_unsupported_http_conditionals(raw_headers: &http::HeaderMap) -> bool {
    raw_headers.contains_key("if-match") || raw_headers.contains_key("if-none-match")
}

/// Detect SigV4 streaming (aws-chunked) upload indicators on the inbound
/// request. The typed PUT/UploadPart paths buffer the raw body and forward it
/// verbatim — they do not decode aws-chunked framing — so chunk-signature
/// frames would end up stored as object body bytes. Route these through
/// passthrough instead.
///
/// IMPORTANT: this inspects the raw inbound `HeaderMap` rather than the
/// `extra_amz_headers` map produced by `parse_s3_request`, because the parser
/// strips `x-amz-content-sha256` and `x-amz-decoded-content-length` before
/// they reach `extra_amz_headers`.
pub(super) fn has_s3_streaming_upload_indicators(raw_headers: &http::HeaderMap) -> bool {
    // 1. Content-Encoding may carry aws-chunked as one token in a comma list
    //    (e.g. `gzip, aws-chunked`), possibly via multiple header values.
    for value in raw_headers.get_all("content-encoding") {
        if let Ok(s) = value.to_str() {
            for tok in s.split(',') {
                if tok.trim().eq_ignore_ascii_case("aws-chunked") {
                    return true;
                }
            }
        }
    }

    // 2. x-amz-content-sha256 set to a STREAMING-* sentinel. Match the
    //    canonical values defensively via case-insensitive prefix.
    if let Some(value) = raw_headers.get("x-amz-content-sha256")
        && let Ok(s) = value.to_str()
    {
        let trimmed = s.trim();
        if trimmed.len() >= "STREAMING-".len()
            && trimmed[.."STREAMING-".len()].eq_ignore_ascii_case("STREAMING-")
        {
            return true;
        }
    }

    // 3/4. Decoded length and trailer headers only appear on aws-chunked
    //      uploads; presence alone is sufficient signal.
    raw_headers.contains_key("x-amz-decoded-content-length")
        || raw_headers.contains_key("x-amz-trailer")
}

/// Gate for PutObject and DeleteObject. Checksum headers are NOT gated here
/// because the typed PutObject path forwards them end-to-end.
pub(super) fn has_unsupported_write_modifiers(
    extra_amz: &std::collections::HashMap<String, String>,
    raw_headers: &http::HeaderMap,
) -> bool {
    if has_unsupported_http_conditionals(raw_headers) {
        return true;
    }
    if has_s3_streaming_upload_indicators(raw_headers) {
        return true;
    }
    extra_amz
        .keys()
        .any(|k| WRITE_MODIFYING_BASE.contains(&k.as_str()))
}

/// Gate for multipart operations. Includes checksum headers because the typed
/// multipart paths (CreateMultipartUpload, UploadPart, CompleteMultipartUpload)
/// don't forward checksum request headers or XML checksum elements.
pub(super) fn has_unsupported_multipart_modifiers(
    extra_amz: &std::collections::HashMap<String, String>,
    raw_headers: &http::HeaderMap,
) -> bool {
    if has_unsupported_http_conditionals(raw_headers) {
        return true;
    }
    if has_s3_streaming_upload_indicators(raw_headers) {
        return true;
    }
    extra_amz.keys().any(|k| {
        WRITE_MODIFYING_BASE.contains(&k.as_str())
            || MULTIPART_CHECKSUM_HEADERS.contains(&k.as_str())
    })
}

/// Check if the LIST request contains query params or headers that the typed
/// list path doesn't model. When present, the request must go through raw
/// passthrough so the backend can handle them.
pub(super) fn has_unsupported_list_modifiers(
    query: Option<&str>,
    headers: &http::HeaderMap,
) -> bool {
    // Query parameters the typed LIST path doesn't forward.
    if let Some(q) = query {
        for pair in q.split('&') {
            let key = pair.split('=').next().unwrap_or("");
            if key == "fetch-owner" || key == "optional-object-attributes" {
                return true;
            }
        }
    }
    // Headers the typed LIST path doesn't forward.
    headers.contains_key("x-amz-request-payer")
        || headers.contains_key("x-amz-expected-bucket-owner")
}
