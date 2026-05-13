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
    /// Reject the request up front before any backend contact with the
    /// `UnsupportedSignature` S3 error. Currently used only for ECDSA-signed
    /// streaming uploads: the inbound `chunk-signature` values are bound to
    /// the client's private key, so passthrough would re-sign with the proxy
    /// backend credentials and the chunk signatures would never validate
    /// against either side. Failing fast avoids pointless backend traffic.
    RejectUnsupportedSignature,
}

/// Granular classification of an aws-chunked upload's mode, derived from the
/// `x-amz-content-sha256` header plus the `x-amz-trailer` header. Used to
/// decide between the in-house decode path and passthrough.
///
/// Trailer modes only route to decode when `x-amz-trailer` declares one of
/// the five supported `x-amz-checksum-<algo>` algorithms (CRC32, CRC32C,
/// CRC64NVME, SHA1, SHA256). Anything else — missing trailer header, unknown
/// algorithm — falls back to passthrough so we don't reject requests we
/// don't know how to validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AwsChunkedUploadMode {
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` — non-trailer signed streaming.
    NonTrailerHmacSha256,
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER` with a supported `x-amz-trailer`.
    UnsignedTrailer,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` with a supported
    /// `x-amz-trailer`.
    SignedTrailerHmacSha256,
    /// ECDSA-signed streaming (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD*`).
    /// Out of scope; routes to a fail-fast `UnsupportedSignature` reject. The
    /// inbound `chunk-signature` values are bound to the client's private
    /// key, so passthrough would only fail on the upstream after pointless
    /// backend contact.
    Ecdsa,
    /// Some other `STREAMING-*` sentinel we don't recognise, or a trailer
    /// variant whose `x-amz-trailer` declares an algorithm we don't support.
    /// Conservative fallback: passthrough.
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
    let trailer_algo_is_supported = trailer_algorithm_supported(raw_headers);

    // `Content-Encoding: aws-chunked` (potentially in a comma list, possibly
    // via multiple header values) is a fallback streaming signal when no
    // STREAMING-* sentinel is present.
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
        let candidate = if upper == crate::s3::aws_chunked::STREAMING_AWS4_HMAC_SHA256_PAYLOAD {
            Some(AwsChunkedUploadMode::NonTrailerHmacSha256)
        } else if upper.contains("ECDSA") && upper.starts_with("STREAMING-") {
            // ECDSA streaming is out of scope (#63) regardless of trailer
            // state: the dispatch layer rejects this mode up front with
            // `UnsupportedSignature` (HTTP 400) — see `aws_chunked_route_for`.
            Some(AwsChunkedUploadMode::Ecdsa)
        } else if upper == "STREAMING-UNSIGNED-PAYLOAD-TRAILER" {
            if trailer_algo_is_supported {
                Some(AwsChunkedUploadMode::UnsignedTrailer)
            } else {
                Some(AwsChunkedUploadMode::OtherStreaming)
            }
        } else if upper == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" {
            if trailer_algo_is_supported {
                Some(AwsChunkedUploadMode::SignedTrailerHmacSha256)
            } else {
                Some(AwsChunkedUploadMode::OtherStreaming)
            }
        } else if upper.starts_with("STREAMING-") {
            Some(AwsChunkedUploadMode::OtherStreaming)
        } else {
            None
        };
        // Conservative escalation: prefer the most restrictive mode if the
        // request happens to advertise more than one. We only "downgrade"
        // from a recognised non-trailer/trailer mode if we see an Ecdsa
        // (→ `RejectUnsupportedSignature`) or `OtherStreaming` (→
        // `Passthrough`) variant later, both of which route away from the
        // decode path.
        mode = match (mode, candidate) {
            (None, c) => c,
            (
                Some(
                    AwsChunkedUploadMode::NonTrailerHmacSha256
                    | AwsChunkedUploadMode::UnsignedTrailer
                    | AwsChunkedUploadMode::SignedTrailerHmacSha256,
                ),
                Some(c @ (AwsChunkedUploadMode::Ecdsa | AwsChunkedUploadMode::OtherStreaming)),
            ) => Some(c),
            (existing, _) => existing,
        };
    }

    // `x-amz-trailer` on a request whose `x-amz-content-sha256` doesn't
    // advertise a trailer-mode sentinel (or advertises the non-trailer
    // sentinel) is contradictory — either the sentinel is wrong or the
    // client is trying to slip trailer framing past a single-header check.
    // Conservative fallback: passthrough, where the upstream gets to decide
    // what to do with the contradictory headers.
    //
    // Without this check a request with `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
    // + `x-amz-trailer` would classify as `NonTrailerHmacSha256` and route
    // to the decoder, which builds `DecoderMode::NonTrailer`, strips the
    // trailer header via the streaming-only filter, and silently accepts a
    // trailerless body — bypassing the "trailer declared but absent →
    // reject" contract.
    if raw_headers.contains_key("x-amz-trailer")
        && !matches!(
            mode,
            Some(
                AwsChunkedUploadMode::UnsignedTrailer
                    | AwsChunkedUploadMode::SignedTrailerHmacSha256
                    | AwsChunkedUploadMode::Ecdsa,
            ),
        )
    {
        return Some(AwsChunkedUploadMode::OtherStreaming);
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

/// True if `x-amz-trailer` is present AND its value names a supported
/// `x-amz-checksum-<algo>` header. Used by the classifier to decide between
/// `UnsignedTrailer` / `SignedTrailerHmacSha256` (we can validate it) and
/// `OtherStreaming` (we can't, so passthrough).
fn trailer_algorithm_supported(raw_headers: &http::HeaderMap) -> bool {
    raw_headers
        .get("x-amz-trailer")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .and_then(crate::s3::checksum::ChecksumAlgorithm::from_header_name)
        .is_some()
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
    aws_chunked_route_for(raw_headers)
}

/// Pick the body-handling route for an UploadPart request. Multipart gating
/// is stricter than PUT — checksum headers also force passthrough — EXCEPT
/// when the upload is a supported aws-chunked variant that we're going to
/// decode and forward via the per-algorithm SDK setters. In that case the
/// trailer is the checksum and `x-amz-sdk-checksum-algorithm` is a benign
/// SDK-internal switch (which we filter from extra_amz_headers anyway), so
/// gating on `MULTIPART_CHECKSUM_HEADERS` here would incorrectly force
/// passthrough for the very requests the trailer decoder exists to handle.
///
/// Order matters: classify aws-chunked FIRST, then apply the multipart
/// gate, and skip the gate entirely when the decode path is chosen.
pub(super) fn classify_upload_part_body_route(
    extra_amz: &std::collections::HashMap<String, String>,
    raw_headers: &http::HeaderMap,
) -> WriteBodyRoute {
    if has_unsupported_http_conditionals(raw_headers) {
        return WriteBodyRoute::Passthrough;
    }
    let route = aws_chunked_route_for(raw_headers);
    // aws-chunked classification is authoritative for both decode AND
    // explicit-reject routes: the multipart checksum-header gate below must
    // not override an `UnsupportedSignature` reject by re-routing the ECDSA
    // request through passthrough.
    if matches!(
        route,
        WriteBodyRoute::DecodeAwsChunked | WriteBodyRoute::RejectUnsupportedSignature,
    ) {
        return route;
    }
    if extra_amz.keys().any(|k| {
        WRITE_MODIFYING_BASE.contains(&k.as_str())
            || MULTIPART_CHECKSUM_HEADERS.contains(&k.as_str())
    }) {
        return WriteBodyRoute::Passthrough;
    }
    route
}

/// Shared aws-chunked routing decision: maps a classified upload mode to
/// the `WriteBodyRoute` for the typed PUT / UploadPart paths.
fn aws_chunked_route_for(raw_headers: &http::HeaderMap) -> WriteBodyRoute {
    match classify_aws_chunked_upload(raw_headers) {
        None => WriteBodyRoute::Typed,
        Some(
            AwsChunkedUploadMode::NonTrailerHmacSha256
            | AwsChunkedUploadMode::UnsignedTrailer
            | AwsChunkedUploadMode::SignedTrailerHmacSha256,
        ) => WriteBodyRoute::DecodeAwsChunked,
        Some(AwsChunkedUploadMode::Ecdsa) => WriteBodyRoute::RejectUnsupportedSignature,
        Some(AwsChunkedUploadMode::OtherStreaming) => WriteBodyRoute::Passthrough,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Unsigned trailer mode with a supported algorithm now routes to the
    /// in-house decoder. The earlier (PR #62) test asserted the opposite,
    /// when the trailer decoder didn't exist; this is the positive flip of
    /// that test, pinning the new behavior.
    #[test]
    fn test_unsigned_trailer_supported_algo_routes_to_decode() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".parse().unwrap(),
        );
        headers.insert("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());
        assert_eq!(
            classify_aws_chunked_upload(&headers),
            Some(AwsChunkedUploadMode::UnsignedTrailer),
        );
        let extra_amz = std::collections::HashMap::new();
        assert_eq!(
            classify_put_body_route(&extra_amz, &headers),
            WriteBodyRoute::DecodeAwsChunked,
        );
        assert_eq!(
            classify_upload_part_body_route(&extra_amz, &headers),
            WriteBodyRoute::DecodeAwsChunked,
        );
    }

    /// Signed trailer mode with a supported algorithm routes to decode.
    #[test]
    fn test_signed_trailer_supported_algo_routes_to_decode() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
                .parse()
                .unwrap(),
        );
        headers.insert("x-amz-trailer", "x-amz-checksum-sha256".parse().unwrap());
        assert_eq!(
            classify_aws_chunked_upload(&headers),
            Some(AwsChunkedUploadMode::SignedTrailerHmacSha256),
        );
        let extra_amz = std::collections::HashMap::new();
        assert_eq!(
            classify_put_body_route(&extra_amz, &headers),
            WriteBodyRoute::DecodeAwsChunked,
        );
    }

    /// Trailer mode with an UNSUPPORTED algorithm (e.g. md5) falls back to
    /// passthrough so we don't reject requests we don't know how to validate.
    #[test]
    fn test_trailer_with_unsupported_algorithm_falls_back_to_passthrough() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".parse().unwrap(),
        );
        headers.insert("x-amz-trailer", "x-amz-checksum-md5".parse().unwrap());
        assert_eq!(
            classify_aws_chunked_upload(&headers),
            Some(AwsChunkedUploadMode::OtherStreaming),
        );
        let extra_amz = std::collections::HashMap::new();
        assert_eq!(
            classify_put_body_route(&extra_amz, &headers),
            WriteBodyRoute::Passthrough,
        );
    }

    /// ECDSA-signed streaming uploads must be rejected up front with
    /// `UnsupportedSignature` rather than routed to passthrough. The inbound
    /// `chunk-signature` values are bound to the client's private key, so
    /// passthrough would re-sign with the proxy backend credentials and the
    /// signatures would never validate — failing fast avoids pointless
    /// backend contact.
    ///
    /// Bug-revert reasoning: routing ECDSA back to `Passthrough` here flips
    /// the assertion to a panic, and the matching integration test (which
    /// pins HTTP 400 + `UnsupportedSignature` + zero backend hits) flips
    /// alongside it.
    #[test]
    fn test_ecdsa_streaming_rejected_as_unsupported_signature() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD".parse().unwrap(),
        );
        assert_eq!(
            classify_aws_chunked_upload(&headers),
            Some(AwsChunkedUploadMode::Ecdsa),
        );
        let extra_amz = std::collections::HashMap::new();
        assert_eq!(
            classify_put_body_route(&extra_amz, &headers),
            WriteBodyRoute::RejectUnsupportedSignature,
        );
        assert_eq!(
            classify_upload_part_body_route(&extra_amz, &headers),
            WriteBodyRoute::RejectUnsupportedSignature,
        );
    }

    /// Multipart UploadPart with an ECDSA streaming sentinel plus the kind of
    /// `x-amz-sdk-checksum-algorithm` side-channel a real SDK would set must
    /// still route to the `UnsupportedSignature` reject — the multipart
    /// checksum-header gate must NOT silently convert it back to passthrough.
    #[test]
    fn test_upload_part_ecdsa_rejected_even_with_sdk_checksum_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD".parse().unwrap(),
        );
        let mut extra_amz = std::collections::HashMap::new();
        extra_amz.insert(
            "x-amz-sdk-checksum-algorithm".to_string(),
            "CRC32".to_string(),
        );
        assert_eq!(
            classify_upload_part_body_route(&extra_amz, &headers),
            WriteBodyRoute::RejectUnsupportedSignature,
        );
    }

    /// `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (non-trailer
    /// sentinel) PLUS `x-amz-trailer` is contradictory — the sentinel says
    /// "no trailer follows" but the header says "expect a trailer". The
    /// classifier must reclassify as `OtherStreaming` and the route must be
    /// `Passthrough` for both PUT and UploadPart.
    ///
    /// Bug-revert reasoning: without the contradiction guard the classifier
    /// returns `NonTrailerHmacSha256`, the route is `DecodeAwsChunked`, the
    /// handler builds `DecoderMode::NonTrailer`, the streaming-only filter
    /// strips `x-amz-trailer` from the decoded backend request, and the
    /// trailer-declared-but-absent contract is silently violated.
    #[test]
    fn test_non_trailer_sentinel_with_trailer_header_routes_to_passthrough() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".parse().unwrap(),
        );
        headers.insert("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());

        assert_eq!(
            classify_aws_chunked_upload(&headers),
            Some(AwsChunkedUploadMode::OtherStreaming),
        );
        let extra_amz = std::collections::HashMap::new();
        assert_eq!(
            classify_put_body_route(&extra_amz, &headers),
            WriteBodyRoute::Passthrough,
        );
        assert_eq!(
            classify_upload_part_body_route(&extra_amz, &headers),
            WriteBodyRoute::Passthrough,
        );
    }

    /// UploadPart route MUST classify aws-chunked BEFORE the multipart
    /// checksum-header gate. Otherwise `x-amz-sdk-checksum-algorithm` (set
    /// by AWS SDKs alongside `x-amz-trailer`) would force passthrough for
    /// the very requests the trailer decoder exists to handle.
    #[test]
    fn test_upload_part_aws_chunked_classified_before_checksum_gate() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER".parse().unwrap(),
        );
        headers.insert("x-amz-trailer", "x-amz-checksum-crc32".parse().unwrap());
        // SDK side-channel switch — present on real SDK requests.
        let mut extra_amz = std::collections::HashMap::new();
        extra_amz.insert(
            "x-amz-sdk-checksum-algorithm".to_string(),
            "CRC32".to_string(),
        );
        assert_eq!(
            classify_upload_part_body_route(&extra_amz, &headers),
            WriteBodyRoute::DecodeAwsChunked,
            "aws-chunked trailer UploadPart must route to decode even with sdk-checksum-algorithm set",
        );
    }
}
