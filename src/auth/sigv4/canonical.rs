//! Build the SigV4 canonical request string for an incoming HTTP request.
//!
//! S3 has well-known deviations from the general SigV4 spec:
//!
//! - Path is used **as-is** from the URI; we do not normalize and do not
//!   double-encode. The general SigV4 spec would normalize and percent-encode
//!   `%` to `%25`, but S3 documents the exception so client signatures match.
//! - Query is decoded, then each key/value re-encoded with AWS canonical
//!   encoding (everything outside `[A-Za-z0-9-_.~]` percent-encoded with
//!   uppercase hex). Sorted by encoded key, then encoded value.
//! - Headers in `SignedHeaders` are looked up in order; each value is trimmed
//!   of leading/trailing ASCII spaces and internal runs of spaces are
//!   collapsed to one. Repeated headers (same name) are joined with `,`.
//!
//! We accept that the parser already validated SignedHeaders is sorted,
//! lowercase, unique, and contains `host`.

use crate::auth::sigv4::parser::SigV4Authorization;
use crate::auth::sigv4::payload::PayloadHashForSigning;
use crate::s3::errors::S3Error;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// AWS canonical query encoding: encode every byte that isn't an "unreserved"
/// character per RFC 3986. Unreserved = `A-Z / a-z / 0-9 / - / . / _ / ~`.
///
/// `NON_ALPHANUMERIC` percent-encodes everything except `[A-Za-z0-9]`. We
/// subtract `-`, `.`, `_`, `~` (the additional unreserved chars).
const AWS_CANONICAL_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The result of canonicalizing a request. The canonical_request string is
/// the one fed into the string-to-sign; the other fields are kept for
/// diagnostics / future plumbing.
#[derive(Debug)]
pub struct CanonicalRequest {
    pub canonical_request: String,
    pub canonical_headers: String,
    pub signed_headers: String,
    pub hashed_payload: String,
}

pub fn build_canonical_request(
    parts: &http::request::Parts,
    auth: &SigV4Authorization,
    payload: &PayloadHashForSigning,
    request_id: &str,
) -> Result<CanonicalRequest, S3Error> {
    let method = parts.method.as_str(); // already uppercase
    let path = parts.uri.path();

    let canonical_query = canonicalize_query(parts.uri.query().unwrap_or(""), request_id)?;
    let (canonical_headers, signed_headers) = canonicalize_headers(parts, auth, request_id)?;

    let hashed_payload = payload.canonical_string().to_owned();

    let mut creq = String::with_capacity(
        method.len()
            + path.len()
            + canonical_query.len()
            + canonical_headers.len()
            + signed_headers.len()
            + hashed_payload.len()
            + 16,
    );
    creq.push_str(method);
    creq.push('\n');
    creq.push_str(path);
    creq.push('\n');
    creq.push_str(&canonical_query);
    creq.push('\n');
    creq.push_str(&canonical_headers);
    creq.push('\n');
    creq.push_str(&signed_headers);
    creq.push('\n');
    creq.push_str(&hashed_payload);

    Ok(CanonicalRequest {
        canonical_request: creq,
        canonical_headers,
        signed_headers,
        hashed_payload,
    })
}

/// Encode a string with AWS canonical encoding (RFC 3986 unreserved set,
/// uppercase percent escapes).
pub(crate) fn aws_uri_encode(s: &str) -> String {
    utf8_percent_encode(s, AWS_CANONICAL_ENCODE).to_string()
}

/// Decode a single percent-encoded query component. Tolerates `+` as a
/// literal space (form-encoded behavior, which is how SDKs sign). Invalid
/// percent escapes preserve the raw bytes so we can still produce *some*
/// canonical string — a downstream signature mismatch will surface the
/// problem clearly.
fn percent_decode_for_query(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'+' {
            out.push(b' ');
            i += 1;
        } else if b == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
            } else {
                out.push(b);
                i += 1;
            }
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn canonicalize_query(raw_query: &str, request_id: &str) -> Result<String, S3Error> {
    if raw_query.is_empty() {
        return Ok(String::new());
    }

    let mut pairs: Vec<(String, String)> = Vec::new();
    for chunk in raw_query.split('&') {
        if chunk.is_empty() {
            // An empty chunk (e.g. consecutive `&&`) is benign in URLs; we
            // skip it rather than treat the request as malformed.
            continue;
        }
        let (raw_k, raw_v) = match chunk.split_once('=') {
            Some((k, v)) => (k, v),
            None => (chunk, ""),
        };

        // Reject presigned-URL query keys up front. Strict mode does not yet
        // verify presigned URLs (PR 3 of issue #63); silently accepting them
        // would either bypass verification or produce confusing
        // SignatureDoesNotMatch errors. Surfacing
        // MissingAuthenticationToken at this stage mirrors what S3 returns
        // for an unsigned request and points the client at the real cause.
        if raw_k.eq_ignore_ascii_case("X-Amz-Signature")
            || percent_decode_for_query(raw_k).eq_ignore_ascii_case("X-Amz-Signature")
        {
            return Err(S3Error::missing_authentication_token(
                "presigned URLs (X-Amz-Signature) are not supported in strict mode; \
                 tracked in PR 3 of issue #63",
                request_id,
            ));
        }

        let decoded_k = percent_decode_for_query(raw_k);
        let decoded_v = percent_decode_for_query(raw_v);
        pairs.push((aws_uri_encode(&decoded_k), aws_uri_encode(&decoded_v)));
    }

    pairs.sort();

    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(v);
    }
    Ok(out)
}

fn canonicalize_headers(
    parts: &http::request::Parts,
    auth: &SigV4Authorization,
    request_id: &str,
) -> Result<(String, String), S3Error> {
    let mut canonical = String::new();
    let mut signed_list = String::new();

    for (i, name) in auth.signed_headers.iter().enumerate() {
        // If the request declares x-amz-date in signed headers, it MUST be
        // present in the request. Same for any signed header — a missing one
        // means the canonical request can't be reconstructed and silently
        // accepting a stub would let a client lie about what they signed.
        let mut iter = parts.headers.get_all(name).iter();
        let first = iter.next().ok_or_else(|| {
            S3Error::authorization_header_malformed(
                &format!(
                    "SignedHeaders references '{}' but the request does not carry it",
                    name.as_str()
                ),
                request_id,
            )
        })?;

        let mut value = String::new();
        let raw = std::str::from_utf8(first.as_bytes()).map_err(|_| {
            S3Error::authorization_header_malformed(
                &format!("header '{}' has non-UTF-8 bytes", name.as_str()),
                request_id,
            )
        })?;
        value.push_str(&trim_ws(raw));
        for extra in iter {
            value.push(',');
            let raw = std::str::from_utf8(extra.as_bytes()).map_err(|_| {
                S3Error::authorization_header_malformed(
                    &format!("header '{}' has non-UTF-8 bytes", name.as_str()),
                    request_id,
                )
            })?;
            value.push_str(&trim_ws(raw));
        }

        canonical.push_str(name.as_str());
        canonical.push(':');
        canonical.push_str(&value);
        canonical.push('\n');

        if i > 0 {
            signed_list.push(';');
        }
        signed_list.push_str(name.as_str());
    }

    Ok((canonical, signed_list))
}

/// AWS SigV4 header-value normalization: trim leading/trailing ASCII spaces
/// (only `' '`, not tabs / other whitespace) and collapse runs of spaces to
/// a single space. The aws-sigv4 reference implementation does the same.
fn trim_ws(s: &str) -> String {
    let trimmed = s.trim_matches(' ');
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_space = false;
    for ch in trimmed.chars() {
        if ch == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sigv4::parser::{CredentialScope, SigV4Authorization};
    use chrono::NaiveDate;
    use http::HeaderName;
    use http::Request;
    use std::str::FromStr;

    fn auth_with_signed_headers(names: &[&str]) -> SigV4Authorization {
        SigV4Authorization {
            access_key_id: "AKID".to_string(),
            scope: CredentialScope {
                date: NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
                date_yyyymmdd: "20260101".to_string(),
                region: "us-east-1".to_string(),
                service: "s3".to_string(),
            },
            signed_headers: names
                .iter()
                .map(|n| HeaderName::from_str(n).unwrap())
                .collect(),
            signature: [0u8; 32],
            signature_hex: "0".repeat(64),
        }
    }

    fn parts_with(uri: &str, method: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut b = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let req = b.body(()).unwrap();
        let (parts, _) = req.into_parts();
        parts
    }

    #[test]
    fn test_path_is_used_as_is_no_double_encoding() {
        // S3 does NOT double-encode the path. A space in the path would be
        // sent already as `%20`; the canonical path keeps it as `%20`.
        let parts = parts_with(
            "/bucket/has%20space/file%2Bone",
            "GET",
            &[("host", "example.com")],
        );
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[1], "/bucket/has%20space/file%2Bone");
    }

    #[test]
    fn test_query_encoding_uppercase_hex() {
        // `=` in the value must be encoded as %3D (uppercase).
        let parts = parts_with("/b/k?a=value%3Dwith%3Dequals", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], "a=value%3Dwith%3Dequals");
    }

    #[test]
    fn test_query_sorted_by_encoded_key() {
        let parts = parts_with("/b?b=2&a=1&c=3", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], "a=1&b=2&c=3");
    }

    #[test]
    fn test_bare_query_key_encoded_with_empty_value() {
        let parts = parts_with("/b?delete", "DELETE", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], "delete=");
    }

    #[test]
    fn test_duplicate_query_keys_sorted_by_value() {
        let parts = parts_with("/b?x=2&x=1", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], "x=1&x=2");
    }

    #[test]
    fn test_header_value_is_trimmed() {
        let parts = parts_with(
            "/b",
            "GET",
            &[("host", "  example.com  "), ("x-amz-foo", " bar baz ")],
        );
        let auth = auth_with_signed_headers(&["host", "x-amz-foo"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[3], "host:example.com");
        assert_eq!(lines[4], "x-amz-foo:bar baz");
    }

    #[test]
    fn test_internal_whitespace_compressed() {
        let parts = parts_with(
            "/b",
            "GET",
            &[("host", "h"), ("x-amz-meta-x", "a    b   c")],
        );
        let auth = auth_with_signed_headers(&["host", "x-amz-meta-x"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[4], "x-amz-meta-x:a b c");
    }

    #[test]
    fn test_duplicate_header_values_joined_with_comma() {
        // http::HeaderMap::append preserves duplicate header values; the
        // canonicalizer joins them with `,` per AWS spec.
        let req = Request::builder()
            .method("GET")
            .uri("/b")
            .header("host", "h")
            .header("x-amz-foo", "one")
            .header("x-amz-foo", "two")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let auth = auth_with_signed_headers(&["host", "x-amz-foo"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[4], "x-amz-foo:one,two");
    }

    #[test]
    fn test_missing_signed_header_rejected() {
        let parts = parts_with("/b", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host", "x-amz-date"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let err = build_canonical_request(&parts, &auth, &payload, "rid")
            .expect_err("missing x-amz-date");
        assert_eq!(err.code, "AuthorizationHeaderMalformed");
    }

    #[test]
    fn test_presigned_query_rejected() {
        let parts = parts_with("/b?X-Amz-Signature=abc&foo=1", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let err = build_canonical_request(&parts, &auth, &payload, "rid")
            .expect_err("presigned must reject");
        assert_eq!(err.code, "MissingAuthenticationToken");
    }

    #[test]
    fn test_hashed_payload_section() {
        let parts = parts_with("/b", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::SignedSha256 {
            hex: "abc".to_string(),
            bytes: [0u8; 32],
        };
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        assert!(cr.canonical_request.ends_with("\nabc"));
    }
}
