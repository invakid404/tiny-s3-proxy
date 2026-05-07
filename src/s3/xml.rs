use quick_xml::Writer;
use quick_xml::escape::partial_escape;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};

use crate::backend::models::{CompletedPart, ListObjectsOutput};

/// Helper: write a simple `<Tag>text</Tag>` element.
/// Uses partial_escape so quotes in text content (e.g. ETags) are preserved.
fn write_text_element(writer: &mut Writer<Vec<u8>>, tag: &str, text: &str) {
    writer
        .write_event(Event::Start(BytesStart::new(tag)))
        .unwrap();
    writer
        .write_event(Event::Text(BytesText::from_escaped(partial_escape(text))))
        .unwrap();
    writer.write_event(Event::End(BytesEnd::new(tag))).unwrap();
}

/// Helper: write an optional text element — only emits the element if the value is Some.
fn write_optional_element(writer: &mut Writer<Vec<u8>>, tag: &str, value: &Option<String>) {
    if let Some(ref v) = *value {
        write_text_element(writer, tag, v);
    }
}

/// Format a DateTime for S3 XML responses (ISO 8601 with milliseconds).
fn format_datetime(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Write the common `<Contents>` elements for a list response.
fn write_contents(writer: &mut Writer<Vec<u8>>, contents: &[crate::backend::models::ObjectInfo]) {
    for obj in contents {
        writer
            .write_event(Event::Start(BytesStart::new("Contents")))
            .unwrap();

        write_text_element(writer, "Key", &obj.key);

        if let Some(ref dt) = obj.last_modified {
            write_text_element(writer, "LastModified", &format_datetime(dt));
        }
        if let Some(ref etag) = obj.etag {
            write_text_element(writer, "ETag", etag);
        }
        if let Some(size) = obj.size {
            write_text_element(writer, "Size", &size.to_string());
        }
        if let Some(ref sc) = obj.storage_class {
            write_text_element(writer, "StorageClass", sc);
        }

        writer
            .write_event(Event::End(BytesEnd::new("Contents")))
            .unwrap();
    }
}

/// Write the `<CommonPrefixes>` elements.
fn write_common_prefixes(writer: &mut Writer<Vec<u8>>, prefixes: &[String]) {
    for prefix in prefixes {
        writer
            .write_event(Event::Start(BytesStart::new("CommonPrefixes")))
            .unwrap();
        write_text_element(writer, "Prefix", prefix);
        writer
            .write_event(Event::End(BytesEnd::new("CommonPrefixes")))
            .unwrap();
    }
}

/// Serialize a ListObjectsOutput to S3-compatible ListBucketResult XML (V2).
pub fn serialize_list_objects_v2(output: &ListObjectsOutput) -> String {
    let mut writer = Writer::new(Vec::new());

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let mut root = BytesStart::new("ListBucketResult");
    root.push_attribute(("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/"));
    writer.write_event(Event::Start(root)).unwrap();

    write_text_element(&mut writer, "Name", &output.name);

    write_optional_element(&mut writer, "Prefix", &output.prefix);
    write_optional_element(&mut writer, "Delimiter", &output.delimiter);
    write_optional_element(&mut writer, "EncodingType", &output.encoding_type);

    if let Some(key_count) = output.key_count {
        write_text_element(&mut writer, "KeyCount", &key_count.to_string());
    }

    write_text_element(&mut writer, "MaxKeys", &output.max_keys.to_string());
    write_text_element(
        &mut writer,
        "IsTruncated",
        if output.is_truncated { "true" } else { "false" },
    );

    write_optional_element(&mut writer, "ContinuationToken", &output.continuation_token);
    write_optional_element(
        &mut writer,
        "NextContinuationToken",
        &output.next_continuation_token,
    );
    write_optional_element(&mut writer, "StartAfter", &output.start_after);

    write_contents(&mut writer, &output.contents);
    write_common_prefixes(&mut writer, &output.common_prefixes);

    writer
        .write_event(Event::End(BytesEnd::new("ListBucketResult")))
        .unwrap();

    String::from_utf8(writer.into_inner()).unwrap()
}

/// Serialize a ListObjectsOutput to S3-compatible ListBucketResult XML (V1).
pub fn serialize_list_objects_v1(output: &ListObjectsOutput) -> String {
    let mut writer = Writer::new(Vec::new());

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let mut root = BytesStart::new("ListBucketResult");
    root.push_attribute(("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/"));
    writer.write_event(Event::Start(root)).unwrap();

    write_text_element(&mut writer, "Name", &output.name);

    write_optional_element(&mut writer, "Prefix", &output.prefix);
    write_optional_element(&mut writer, "Delimiter", &output.delimiter);
    write_optional_element(&mut writer, "EncodingType", &output.encoding_type);
    write_optional_element(&mut writer, "Marker", &output.marker);
    write_optional_element(&mut writer, "NextMarker", &output.next_marker);

    write_text_element(&mut writer, "MaxKeys", &output.max_keys.to_string());
    write_text_element(
        &mut writer,
        "IsTruncated",
        if output.is_truncated { "true" } else { "false" },
    );

    write_contents(&mut writer, &output.contents);
    write_common_prefixes(&mut writer, &output.common_prefixes);

    writer
        .write_event(Event::End(BytesEnd::new("ListBucketResult")))
        .unwrap();

    String::from_utf8(writer.into_inner()).unwrap()
}

/// Parse a CompleteMultipartUpload request body XML into a list of CompletedParts.
///
/// Expected input format:
/// ```xml
/// <CompleteMultipartUpload>
///   <Part>
///     <PartNumber>1</PartNumber>
///     <ETag>"etag1"</ETag>
///   </Part>
///   ...
/// </CompleteMultipartUpload>
/// ```
/// Check whether a CompleteMultipartUpload XML body contains per-part
/// checksum elements (`ChecksumCRC32`, `ChecksumCRC32C`, `ChecksumSHA1`,
/// `ChecksumSHA256`, `ChecksumCRC64NVME`). Uses the quick-xml parser
/// so it handles whitespace, namespace prefixes, and other legal XML
/// variants that a raw byte scan would miss.
pub fn body_has_checksum_elements(xml_body: &[u8]) -> bool {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    const CHECKSUM_NAMES: &[&str] = &[
        "ChecksumCRC32",
        "ChecksumCRC32C",
        "ChecksumCRC64NVME",
        "ChecksumSHA1",
        "ChecksumSHA256",
    ];

    let mut reader = Reader::from_reader(xml_body);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let local = e.local_name();
                let name = String::from_utf8_lossy(local.as_ref());
                if CHECKSUM_NAMES.contains(&name.as_ref()) {
                    return true;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    false
}

pub fn parse_complete_multipart_body(xml_body: &[u8]) -> Result<Vec<CompletedPart>, String> {
    use quick_xml::Reader;

    let mut reader = Reader::from_reader(xml_body);
    reader.config_mut().trim_text(true);

    let mut parts = Vec::new();
    let mut current_part_number: Option<i32> = None;
    let mut current_etag: Option<String> = None;
    let mut inside_part = false;
    let mut found_root = false;
    let mut depth: u32 = 0;
    let mut current_element = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match name.as_str() {
                    "CompleteMultipartUpload" if depth == 0 => {
                        found_root = true;
                    }
                    // Part must be a direct child of the root (depth 1).
                    "Part" if found_root && depth == 1 => {
                        inside_part = true;
                        current_part_number = None;
                        current_etag = None;
                    }
                    // PartNumber/ETag must be direct children of Part (depth 2).
                    "PartNumber" if inside_part && depth == 2 => {
                        if current_part_number.is_some() {
                            return Err("Duplicate PartNumber in Part element".to_string());
                        }
                        current_element = name;
                    }
                    "ETag" if inside_part && depth == 2 => {
                        if current_etag.is_some() {
                            return Err("Duplicate ETag in Part element".to_string());
                        }
                        current_element = name;
                    }
                    _ => {}
                }
                depth += 1;
            }
            Ok(Event::Empty(ref e)) => {
                // Self-closing <CompleteMultipartUpload/> at depth 0 is a
                // valid root but will have zero parts, caught by the
                // post-parse check. Nested occurrences are ignored.
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "CompleteMultipartUpload" && depth == 0 {
                    found_root = true;
                }
                // Empty elements don't change depth (no matching End).
            }
            Ok(Event::Text(ref e)) if inside_part => {
                let text = e
                    .decode()
                    .map_err(|err| format!("XML decode error: {}", err))?
                    .to_string();
                match current_element.as_str() {
                    "PartNumber" => {
                        current_part_number = Some(
                            text.parse::<i32>()
                                .map_err(|e| format!("Invalid PartNumber: {}", e))?,
                        );
                    }
                    "ETag" => {
                        current_etag = Some(text);
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                depth = depth.saturating_sub(1);
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "Part" && inside_part {
                    let part_number = current_part_number
                        .ok_or_else(|| "Missing PartNumber in Part element".to_string())?;
                    let etag = current_etag
                        .take()
                        .ok_or_else(|| "Missing ETag in Part element".to_string())?;
                    parts.push(CompletedPart { etag, part_number });
                    inside_part = false;
                }
                current_element.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    if !found_root {
        return Err("Missing CompleteMultipartUpload root element".to_string());
    }
    if parts.is_empty() {
        return Err("No Part elements found in CompleteMultipartUpload".to_string());
    }

    Ok(parts)
}

/// Serialize an InitiateMultipartUploadResult response.
pub fn serialize_initiate_multipart(bucket: &str, key: &str, upload_id: &str) -> String {
    let mut writer = Writer::new(Vec::new());

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let mut root = BytesStart::new("InitiateMultipartUploadResult");
    root.push_attribute(("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/"));
    writer.write_event(Event::Start(root)).unwrap();

    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    write_text_element(&mut writer, "UploadId", upload_id);

    writer
        .write_event(Event::End(BytesEnd::new("InitiateMultipartUploadResult")))
        .unwrap();

    String::from_utf8(writer.into_inner()).unwrap()
}

/// Serialize a CompleteMultipartUploadResult response.
pub fn serialize_complete_multipart(
    bucket: &str,
    key: &str,
    etag: Option<&str>,
    location: Option<&str>,
) -> String {
    let mut writer = Writer::new(Vec::new());

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .unwrap();

    let mut root = BytesStart::new("CompleteMultipartUploadResult");
    root.push_attribute(("xmlns", "http://s3.amazonaws.com/doc/2006-03-01/"));
    writer.write_event(Event::Start(root)).unwrap();

    if let Some(loc) = location {
        write_text_element(&mut writer, "Location", loc);
    }
    write_text_element(&mut writer, "Bucket", bucket);
    write_text_element(&mut writer, "Key", key);
    if let Some(etag) = etag {
        write_text_element(&mut writer, "ETag", etag);
    }

    writer
        .write_event(Event::End(BytesEnd::new("CompleteMultipartUploadResult")))
        .unwrap();

    String::from_utf8(writer.into_inner()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::models::{ListObjectsOutput, ObjectInfo};
    use chrono::TimeZone;

    fn sample_output() -> ListObjectsOutput {
        ListObjectsOutput {
            is_truncated: false,
            contents: vec![
                ObjectInfo {
                    key: "file1.txt".to_string(),
                    last_modified: Some(chrono::Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
                    etag: Some("\"abc123\"".to_string()),
                    size: Some(1234),
                    storage_class: Some("STANDARD".to_string()),
                },
                ObjectInfo {
                    key: "file2.txt".to_string(),
                    last_modified: Some(
                        chrono::Utc
                            .with_ymd_and_hms(2024, 6, 15, 12, 30, 0)
                            .unwrap(),
                    ),
                    etag: Some("\"def456\"".to_string()),
                    size: Some(5678),
                    storage_class: Some("STANDARD".to_string()),
                },
            ],
            common_prefixes: vec!["logs/".to_string()],
            name: "mybucket".to_string(),
            prefix: Some("".to_string()),
            delimiter: Some("/".to_string()),
            max_keys: 1000,
            encoding_type: None,
            key_count: Some(2),
            continuation_token: None,
            next_continuation_token: None,
            start_after: None,
            marker: None,
            next_marker: None,
        }
    }

    #[test]
    fn test_v2_list_with_objects_and_prefixes() {
        let output = sample_output();
        let xml = serialize_list_objects_v2(&output);
        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<ListBucketResult"));
        assert!(xml.contains("<Name>mybucket</Name>"));
        assert!(xml.contains("<KeyCount>2</KeyCount>"));
        assert!(xml.contains("<MaxKeys>1000</MaxKeys>"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
        assert!(xml.contains("<Key>file1.txt</Key>"));
        assert!(xml.contains("<Key>file2.txt</Key>"));
        assert!(xml.contains("<ETag>\"abc123\"</ETag>"));
        assert!(xml.contains("<Size>1234</Size>"));
        assert!(xml.contains("<StorageClass>STANDARD</StorageClass>"));
        assert!(xml.contains("<CommonPrefixes><Prefix>logs/</Prefix></CommonPrefixes>"));
        assert!(xml.contains("<LastModified>2024-01-01T00:00:00.000Z</LastModified>"));
    }

    #[test]
    fn test_v2_list_empty_result() {
        let output = ListObjectsOutput {
            is_truncated: false,
            contents: vec![],
            common_prefixes: vec![],
            name: "empty-bucket".to_string(),
            prefix: None,
            delimiter: None,
            max_keys: 1000,
            encoding_type: None,
            key_count: Some(0),
            continuation_token: None,
            next_continuation_token: None,
            start_after: None,
            marker: None,
            next_marker: None,
        };
        let xml = serialize_list_objects_v2(&output);
        assert!(xml.contains("<Name>empty-bucket</Name>"));
        assert!(xml.contains("<KeyCount>0</KeyCount>"));
        assert!(xml.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!xml.contains("<Contents>"));
        assert!(!xml.contains("<CommonPrefixes>"));
    }

    #[test]
    fn test_v2_list_truncated_with_continuation() {
        let output = ListObjectsOutput {
            is_truncated: true,
            contents: vec![ObjectInfo {
                key: "obj1".to_string(),
                last_modified: None,
                etag: None,
                size: Some(100),
                storage_class: None,
            }],
            common_prefixes: vec![],
            name: "mybucket".to_string(),
            prefix: None,
            delimiter: None,
            max_keys: 1,
            encoding_type: None,
            key_count: Some(1),
            continuation_token: Some("token-prev".to_string()),
            next_continuation_token: Some("token-next".to_string()),
            start_after: None,
            marker: None,
            next_marker: None,
        };
        let xml = serialize_list_objects_v2(&output);
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        assert!(xml.contains("<ContinuationToken>token-prev</ContinuationToken>"));
        assert!(xml.contains("<NextContinuationToken>token-next</NextContinuationToken>"));
    }

    #[test]
    fn test_v1_list_with_marker() {
        let output = ListObjectsOutput {
            is_truncated: true,
            contents: vec![ObjectInfo {
                key: "obj1".to_string(),
                last_modified: None,
                etag: None,
                size: Some(100),
                storage_class: None,
            }],
            common_prefixes: vec![],
            name: "mybucket".to_string(),
            prefix: Some("pre/".to_string()),
            delimiter: None,
            max_keys: 10,
            encoding_type: None,
            key_count: None,
            continuation_token: None,
            next_continuation_token: None,
            start_after: None,
            marker: Some("marker-val".to_string()),
            next_marker: Some("next-marker-val".to_string()),
        };
        let xml = serialize_list_objects_v1(&output);
        assert!(xml.contains("<Marker>marker-val</Marker>"));
        assert!(xml.contains("<NextMarker>next-marker-val</NextMarker>"));
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        // V1 should NOT have KeyCount or ContinuationToken
        assert!(!xml.contains("<KeyCount>"));
        assert!(!xml.contains("<ContinuationToken>"));
    }

    #[test]
    fn test_parse_complete_multipart_body() {
        let body = br#"<CompleteMultipartUpload>
            <Part>
                <PartNumber>1</PartNumber>
                <ETag>"etag1"</ETag>
            </Part>
            <Part>
                <PartNumber>2</PartNumber>
                <ETag>"etag2"</ETag>
            </Part>
        </CompleteMultipartUpload>"#;

        let parts = parse_complete_multipart_body(body).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].part_number, 1);
        assert_eq!(parts[0].etag, "\"etag1\"");
        assert_eq!(parts[1].part_number, 2);
        assert_eq!(parts[1].etag, "\"etag2\"");
    }

    #[test]
    fn test_parse_complete_multipart_wrong_root_rejected() {
        let body = b"<NotCompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e\"</ETag></Part></NotCompleteMultipartUpload>";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Missing CompleteMultipartUpload root element")
        );
    }

    #[test]
    fn test_parse_complete_multipart_empty_body_rejected() {
        let body = b"";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_complete_multipart_empty_parts_rejected() {
        let body = b"<CompleteMultipartUpload></CompleteMultipartUpload>";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No Part elements"));
    }

    #[test]
    fn test_parse_complete_multipart_nested_root_rejected() {
        // CompleteMultipartUpload nested inside another element is not a valid root.
        let body = b"<Wrapper><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"e\"</ETag></Part></CompleteMultipartUpload></Wrapper>";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Missing CompleteMultipartUpload root element")
        );
    }

    #[test]
    fn test_parse_complete_multipart_part_wrong_depth_rejected() {
        // Part nested inside a wrapper element (depth 2 instead of 1).
        let body = b"<CompleteMultipartUpload><Wrapper><Part><PartNumber>1</PartNumber><ETag>\"e\"</ETag></Part></Wrapper></CompleteMultipartUpload>";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_complete_multipart_duplicate_part_number_rejected() {
        let body = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><PartNumber>2</PartNumber><ETag>\"e\"</ETag></Part></CompleteMultipartUpload>";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate PartNumber"));
    }

    #[test]
    fn test_parse_complete_multipart_duplicate_etag_rejected() {
        let body = b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"a\"</ETag><ETag>\"b\"</ETag></Part></CompleteMultipartUpload>";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate ETag"));
    }

    #[test]
    fn test_parse_complete_multipart_self_closing_root_rejected() {
        let body = b"<CompleteMultipartUpload/>";
        let result = parse_complete_multipart_body(body);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No Part elements"));
    }

    #[test]
    fn test_serialize_initiate_multipart() {
        let xml = serialize_initiate_multipart("mybucket", "mykey", "upload-id-123");
        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<InitiateMultipartUploadResult"));
        assert!(xml.contains("<Bucket>mybucket</Bucket>"));
        assert!(xml.contains("<Key>mykey</Key>"));
        assert!(xml.contains("<UploadId>upload-id-123</UploadId>"));
        assert!(xml.contains("</InitiateMultipartUploadResult>"));
    }

    #[test]
    fn test_serialize_complete_multipart() {
        let xml = serialize_complete_multipart(
            "mybucket",
            "mykey",
            Some("\"final-etag\""),
            Some("http://mybucket.s3.amazonaws.com/mykey"),
        );
        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<CompleteMultipartUploadResult"));
        assert!(xml.contains("<Bucket>mybucket</Bucket>"));
        assert!(xml.contains("<Key>mykey</Key>"));
        assert!(xml.contains("<ETag>\"final-etag\"</ETag>"));
        assert!(xml.contains("<Location>http://mybucket.s3.amazonaws.com/mykey</Location>"));
        assert!(xml.contains("</CompleteMultipartUploadResult>"));
    }

    // --- body_has_checksum_elements tests ---

    #[test]
    fn test_checksum_crc32_detected() {
        let body = br#"<CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>"e1"</ETag><ChecksumCRC32>abc</ChecksumCRC32></Part>
        </CompleteMultipartUpload>"#;
        assert!(body_has_checksum_elements(body));
    }

    #[test]
    fn test_checksum_sha256_detected() {
        let body = br#"<CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>"e1"</ETag><ChecksumSHA256>abc</ChecksumSHA256></Part>
        </CompleteMultipartUpload>"#;
        assert!(body_has_checksum_elements(body));
    }

    #[test]
    fn test_no_checksum_not_detected() {
        let body = br#"<CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>"e1"</ETag></Part>
        </CompleteMultipartUpload>"#;
        assert!(!body_has_checksum_elements(body));
    }

    #[test]
    fn test_checksum_crc32c_detected() {
        let body = b"<Part><ChecksumCRC32C>x</ChecksumCRC32C></Part>";
        assert!(body_has_checksum_elements(body));
    }

    #[test]
    fn test_checksum_sha1_detected() {
        let body = b"<Part><ChecksumSHA1>x</ChecksumSHA1></Part>";
        assert!(body_has_checksum_elements(body));
    }

    #[test]
    fn test_checksum_crc64nvme_detected() {
        let body = b"<Part><ChecksumCRC64NVME>x</ChecksumCRC64NVME></Part>";
        assert!(body_has_checksum_elements(body));
    }

    #[test]
    fn test_checksum_namespace_prefixed() {
        let body = b"<Part><s3:ChecksumSHA256>abc</s3:ChecksumSHA256></Part>";
        assert!(body_has_checksum_elements(body));
    }

    #[test]
    fn test_checksum_self_closing_element() {
        let body = b"<Part><ChecksumCRC32/></Part>";
        assert!(body_has_checksum_elements(body));
    }

    #[test]
    fn test_checksum_whitespace_before_close() {
        let body = b"<Part><ChecksumSHA1 >abc</ChecksumSHA1></Part>";
        assert!(body_has_checksum_elements(body));
    }
}
