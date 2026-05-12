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

/// What body-handling path a write request should take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteBodyRoute {
    /// Normal typed PUT/UploadPart path — the body is forwarded as opaque
    /// bytes via the SDK.
    Typed,
    /// aws-chunked non-trailer streaming upload — decode the framing to a
    /// disk spool, then forward the decoded body via the SDK.
    DecodeAwsChunked,
    /// Pass the raw request through to the upstream byte-for-byte.
    Passthrough,
}

/// Granular classification of an aws-chunked upload's mode, derived from the
/// `x-amz-content-sha256` header. Used to decide between the in-house decode
/// path (non-trailer) and passthrough (everything else).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AwsChunkedUploadMode {
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` — handled by the decoder in PR #1.
    NonTrailerHmacSha256,
    /// Any trailer-mode variant (e.g.
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`,
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`). Will be handled in PR #2.
    Trailer,
    /// ECDSA-signed streaming. Out of scope for this PR series; goes to
    /// passthrough.
    Ecdsa,
    /// Some other `STREAMING-*` sentinel we don't recognise. Conservative
    /// fallback: route through passthrough.
    OtherStreaming,
}

/// Inspect the inbound headers and classify the aws-chunked upload mode if
/// one is present. Returns `None` for plain (non-streaming) requests.
///
/// IMPORTANT: this inspects the raw inbound `HeaderMap` rather than the
/// `extra_amz_headers` map produced by `parse_s3_request`, because the parser
/// strips `x-amz-content-sha256` and `x-amz-decoded-content-length` before
/// they reach `extra_amz_headers`.
pub(super) fn classify_aws_chunked_upload(
    raw_headers: &http::HeaderMap,
) -> Option<AwsChunkedUploadMode> {
    // First-pass signal: `Content-Encoding: aws-chunked` (potentially in a
    // comma list, possibly via multiple header values).
    let mut content_encoding_has_aws_chunked = false;
    for value in raw_headers.get_all("content-encoding") {
        if let Ok(s) = value.to_str() {
            for tok in s.split(',') {
                if tok.trim().eq_ignore_ascii_case("aws-chunked") {
                    content_encoding_has_aws_chunked = true;
                    break;
                }
            }
        }
    }

    // Inspect every `x-amz-content-sha256` value defensively: a client could
    // send multiple headers (e.g. UNSIGNED-PAYLOAD plus a STREAMING-* one)
    // to try to slip a streaming sentinel past a single-value check.
    let mut mode: Option<AwsChunkedUploadMode> = None;
    for value in raw_headers.get_all("x-amz-content-sha256") {
        let Ok(s) = value.to_str() else { continue };
        let trimmed = s.trim();
        if trimmed.is_empty() {
            continue;
        }
        let upper = trimmed.to_ascii_uppercase();
        let candidate = if upper == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
            Some(AwsChunkedUploadMode::NonTrailerHmacSha256)
        } else if upper.contains("ECDSA") && upper.starts_with("STREAMING-") {
            Some(AwsChunkedUploadMode::Ecdsa)
        } else if upper.ends_with("-TRAILER") && upper.starts_with("STREAMING-") {
            Some(AwsChunkedUploadMode::Trailer)
        } else if upper.starts_with("STREAMING-") {
            Some(AwsChunkedUploadMode::OtherStreaming)
        } else {
            None
        };
        // Conservative escalation: prefer the most restrictive mode if the
        // request happens to advertise more than one. Anything but the plain
        // non-trailer mode routes to passthrough, so once we see Trailer/Ecdsa
        // we don't downgrade back to NonTrailer.
        mode = match (mode, candidate) {
            (None, c) => c,
            (Some(AwsChunkedUploadMode::NonTrailerHmacSha256), Some(c))
                if c != AwsChunkedUploadMode::NonTrailerHmacSha256 =>
            {
                Some(c)
            }
            (existing, _) => existing,
        };
    }

    // Trailer headers and decoded-content-length headers are aws-chunked
    // markers — if they're present but no STREAMING-* sentinel was seen, the
    // request is malformed but we still route it through passthrough to
    // preserve historical behaviour. If x-amz-trailer is present we treat
    // the request as trailer-mode regardless of the sha256 sentinel.
    if raw_headers.contains_key("x-amz-trailer") {
        return Some(mode.unwrap_or(AwsChunkedUploadMode::Trailer));
    }
    if mode.is_some() {
        return mode;
    }
    if content_encoding_has_aws_chunked || raw_headers.contains_key("x-amz-decoded-content-length")
    {
        // No STREAMING-* sentinel observed but aws-chunked framing is
        // advertised. Treat as something we don't model directly.
        return Some(AwsChunkedUploadMode::OtherStreaming);
    }
    None
}

/// Pick the body-handling route for a PUT request.
pub(super) fn classify_put_body_route(
    extra_amz: &std::collections::HashMap<String, String>,
    raw_headers: &http::HeaderMap,
) -> WriteBodyRoute {
    // HTTP conditional headers (If-Match / If-None-Match) can't be modeled by
    // the typed write path; passthrough is required to preserve semantics.
    if has_unsupported_http_conditionals(raw_headers) {
        return WriteBodyRoute::Passthrough;
    }
    // Modifiers the typed path can't carry. Same precedent as the existing
    // gate: anything here forces passthrough.
    if extra_amz
        .keys()
        .any(|k| WRITE_MODIFYING_BASE.contains(&k.as_str()))
    {
        return WriteBodyRoute::Passthrough;
    }
    match classify_aws_chunked_upload(raw_headers) {
        None => WriteBodyRoute::Typed,
        Some(AwsChunkedUploadMode::NonTrailerHmacSha256) => WriteBodyRoute::DecodeAwsChunked,
        Some(_) => WriteBodyRoute::Passthrough,
    }
}

/// Pick the body-handling route for an UploadPart request. Multipart gating
/// is stricter than PUT — checksum headers also force passthrough — but the
/// aws-chunked routing decision is identical.
pub(super) fn classify_upload_part_body_route(
    extra_amz: &std::collections::HashMap<String, String>,
    raw_headers: &http::HeaderMap,
) -> WriteBodyRoute {
    if has_unsupported_http_conditionals(raw_headers) {
        return WriteBodyRoute::Passthrough;
    }
    if extra_amz.keys().any(|k| {
        WRITE_MODIFYING_BASE.contains(&k.as_str())
            || MULTIPART_CHECKSUM_HEADERS.contains(&k.as_str())
    }) {
        return WriteBodyRoute::Passthrough;
    }
    match classify_aws_chunked_upload(raw_headers) {
        None => WriteBodyRoute::Typed,
        Some(AwsChunkedUploadMode::NonTrailerHmacSha256) => WriteBodyRoute::DecodeAwsChunked,
        Some(_) => WriteBodyRoute::Passthrough,
    }
}

/// Detect SigV4 streaming (aws-chunked) upload indicators on the inbound
/// request. Kept for the multipart gates that don't decode aws-chunked yet —
/// CreateMultipartUpload, CompleteMultipartUpload, AbortMultipartUpload, and
/// the DeleteObject path. PUT and UploadPart route through
/// `classify_put_body_route` / `classify_upload_part_body_route` instead.
///
/// IMPORTANT: this inspects the raw inbound `HeaderMap` rather than the
/// `extra_amz_headers` map produced by `parse_s3_request`, because the parser
/// strips `x-amz-content-sha256` and `x-amz-decoded-content-length` before
/// they reach `extra_amz_headers`.
pub(super) fn has_s3_streaming_upload_indicators(raw_headers: &http::HeaderMap) -> bool {
    classify_aws_chunked_upload(raw_headers).is_some()
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
            // Percent-decode before matching: encoded equivalents like
            // `fetch%2Downer` would otherwise bypass the gate (issue #46).
            // Match parse_query()'s lossy decoding semantics so gating and
            // parsing agree on the same key set.
            let decoded_key = percent_encoding::percent_decode_str(key).decode_utf8_lossy();
            if decoded_key == "fetch-owner" || decoded_key == "optional-object-attributes" {
                return true;
            }
        }
    }
    // Headers the typed LIST path doesn't forward.
    headers.contains_key("x-amz-request-payer")
        || headers.contains_key("x-amz-expected-bucket-owner")
}
