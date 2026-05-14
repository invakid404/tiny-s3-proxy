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
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

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

/// Encode raw bytes with AWS canonical encoding (RFC 3986 unreserved set,
/// uppercase percent escapes).
///
/// Takes a byte slice rather than a `&str` because the decode-then-re-encode
/// round trip in `canonicalize_query` operates on raw bytes: a
/// percent-encoded query may carry arbitrary non-UTF-8 sequences and we
/// must preserve them byte-for-byte across the canonical round trip.
fn aws_uri_encode_bytes(bytes: &[u8]) -> String {
    percent_encode(bytes, AWS_CANONICAL_ENCODE).to_string()
}

/// Decode a single percent-encoded query component to its raw bytes.
///
/// SigV4 (not form-encoding) semantics:
/// - `%XX` decodes to the single byte with that hex value (both nibbles
///   required; uppercase or lowercase).
/// - `+` is a LITERAL plus sign — NOT a space. AWS S3 SigV4 specifies byte
///   level URI encoding where space is `%20`. Treating `+` as space here
///   would cause `prefix=a+b` to canonicalize to `a%20b` and the client's
///   signature would never match.
/// - Any other byte (including a `%` that isn't followed by two hex digits)
///   is passed through verbatim, so the canonical request stays defined
///   even for slightly malformed inputs; a real signature mismatch will
///   surface the actual problem.
///
/// Returns `Vec<u8>` rather than `String` because percent-decoded query
/// values may contain arbitrary bytes (e.g., a binary value carried via
/// `%FF`). Converting through `String::from_utf8_lossy` would replace those
/// bytes with U+FFFD and corrupt the canonical request.
fn percent_decode_for_query(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }

    out
}

/// ASCII-case-insensitive byte-slice comparison. Used for the
/// presigned-URL key detection so a percent-encoded `X-Amz-Signature` is
/// recognised regardless of casing or encoding form.
fn eq_ignore_ascii_case_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
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
        //
        // We compare decoded BYTES (not lossy strings) so a percent-encoded
        // key such as `X%2DAmz%2DSignature` is still recognised; the byte
        // form means non-UTF-8 oddities can't sneak past the check via the
        // lossy-decode replacement character.
        let decoded_k = percent_decode_for_query(raw_k);
        let decoded_v = percent_decode_for_query(raw_v);
        if eq_ignore_ascii_case_bytes(raw_k.as_bytes(), b"X-Amz-Signature")
            || eq_ignore_ascii_case_bytes(&decoded_k, b"X-Amz-Signature")
        {
            return Err(S3Error::missing_authentication_token(
                "presigned URLs (X-Amz-Signature) are not supported in strict mode; \
                 tracked in PR 3 of issue #63",
                request_id,
            ));
        }

        pairs.push((
            aws_uri_encode_bytes(&decoded_k),
            aws_uri_encode_bytes(&decoded_v),
        ));
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

    // ── Byte-level query decoding round-trip ─────────────────────────────
    //
    // SigV4 (not form-encoding) semantics: `+` is a literal `+`, space is
    // `%20`, and arbitrary non-UTF-8 byte values round-trip cleanly.

    #[test]
    fn test_literal_plus_in_query_value_not_form_decoded() {
        // `a+b` on the wire is the literal three-character string `a+b`.
        // AWS encoding emits `+` as `%2B`. Form-encoding semantics would
        // (incorrectly) decode `+` to a space and re-encode it as `%20`,
        // which would never match an AWS SDK signer's canonical form.
        let parts = parts_with("/b?prefix=a+b", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], "prefix=a%2Bb");
    }

    #[test]
    fn test_non_utf8_byte_value_round_trips() {
        // A percent-encoded value `%FF%2B` is the two bytes [0xFF, 0x2B].
        // A lossy UTF-8 decode would turn 0xFF into U+FFFD and corrupt the
        // canonical request; the byte-level decoder must preserve 0xFF.
        let parts = parts_with("/b?x=%FF%2B", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], "x=%FF%2B");
    }

    #[test]
    fn test_percent_encoded_x_amz_signature_key_still_rejected() {
        // `X%2DAmz%2DSignature` decodes (byte-level) to `X-Amz-Signature`.
        // Our presigned-URL detection compares decoded bytes
        // case-insensitively, so the encoded form must still trigger
        // MissingAuthenticationToken.
        let parts = parts_with(
            "/b?X%2DAmz%2DSignature=deadbeef&foo=1",
            "GET",
            &[("host", "h")],
        );
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let err = build_canonical_request(&parts, &auth, &payload, "rid")
            .expect_err("encoded presigned key must reject");
        assert_eq!(err.code, "MissingAuthenticationToken");

        // Case variation too: lower-case raw key.
        let parts = parts_with("/b?x-amz-signature=abc", "GET", &[("host", "h")]);
        let err = build_canonical_request(&parts, &auth, &payload, "rid")
            .expect_err("lowercase presigned key must reject");
        assert_eq!(err.code, "MissingAuthenticationToken");
    }

    #[test]
    fn test_trailing_bare_percent_passes_through() {
        // A bare `%` at end-of-string is malformed; we pass it through
        // verbatim rather than erroring (signature mismatch will surface
        // the real issue if it matters).
        let parts = parts_with("/b?x=foo%", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        // `%` is encoded as `%25` on re-encode.
        assert_eq!(lines[2], "x=foo%25");
    }

    #[test]
    fn test_malformed_single_hex_digit_passes_through() {
        // `%X` (one hex digit) is malformed; verbatim pass-through means
        // the `%` and `X` both survive into the decoded bytes and then get
        // re-encoded as `%25X`.
        let parts = parts_with("/b?x=%X", "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], "x=%25X");
    }

    #[test]
    fn test_aws_get_vanilla_query_unreserved_vector() {
        // AWS reference vector "get-vanilla-query-unreserved" exercises a
        // query string of all RFC 3986 unreserved characters — none of
        // them should be percent-encoded by the canonicalizer. Confirms
        // the byte-level decoder doesn't accidentally rewrite unreserved
        // characters.
        let unreserved = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let raw_query = format!("{unreserved}={unreserved}");
        let parts = parts_with(&format!("/?{raw_query}"), "GET", &[("host", "h")]);
        let auth = auth_with_signed_headers(&["host"]);
        let payload = PayloadHashForSigning::UnsignedPayload;
        let cr = build_canonical_request(&parts, &auth, &payload, "rid").unwrap();
        let lines: Vec<&str> = cr.canonical_request.split('\n').collect();
        assert_eq!(lines[2], raw_query);
    }
}
