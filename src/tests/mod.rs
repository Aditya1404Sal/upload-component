#[cfg(test)]
use crate::{bindings::betty_blocks::data_api::data_api_utilities::PolicyField, upload};

#[test]
fn test_generate_boundary() {
    let boundary = upload::generate_boundary();
    assert!(!boundary.is_empty());
    assert!(boundary.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_generate_boundary_unique() {
    let boundary1 = upload::generate_boundary();
    let boundary2 = upload::generate_boundary();
    // Boundaries should be different (very high probability)
    // We can't guarantee this 100% but nanosecond precision makes collision unlikely
    assert_ne!(boundary1, boundary2);
}

#[test]
fn test_build_multipart_body_structure() {
    let boundary = "testboundary123";
    let fields = vec![
        PolicyField {
            key: "key1".to_string(),
            value: "value1".to_string(),
        },
        PolicyField {
            key: "key2".to_string(),
            value: "value2".to_string(),
        },
    ];
    let file_data = b"test file content";
    let filename = "test.pdf";
    let content_type = "application/pdf";

    let result =
        upload::build_multipart_body(boundary, &fields, file_data, filename, content_type).unwrap();
    let body_str = String::from_utf8_lossy(&result);

    // Check that all fields are present
    assert!(body_str.contains("--testboundary123"));
    assert!(body_str.contains("name=\"key1\""));
    assert!(body_str.contains("value1"));
    assert!(body_str.contains("name=\"key2\""));
    assert!(body_str.contains("value2"));

    // Check file field with actual filename and content type
    assert!(body_str.contains("name=\"file\""));
    assert!(body_str.contains("filename=\"test.pdf\""));
    assert!(body_str.contains("Content-Type: application/pdf"));
    assert!(body_str.contains("test file content"));

    // Check final boundary
    assert!(body_str.contains("--testboundary123--"));
}

#[test]
fn test_build_multipart_body_empty_fields() {
    let boundary = "boundary";
    let fields = vec![];
    let file_data = b"content";
    let filename = "file.txt";
    let content_type = "text/plain";

    let result =
        upload::build_multipart_body(boundary, &fields, file_data, filename, content_type).unwrap();
    let body_str = String::from_utf8_lossy(&result);

    // Should still have file field and boundaries
    assert!(body_str.contains("--boundary"));
    assert!(body_str.contains("name=\"file\""));
    assert!(body_str.contains("filename=\"file.txt\""));
    assert!(body_str.contains("Content-Type: text/plain"));
    assert!(body_str.contains("content"));
    assert!(body_str.contains("--boundary--"));
}

#[test]
fn test_build_multipart_body_empty_file() {
    let boundary = "boundary";
    let fields = vec![PolicyField {
        key: "test".to_string(),
        value: "value".to_string(),
    }];
    let file_data = b"";
    let filename = "empty.bin";
    let content_type = "application/octet-stream";

    let result =
        upload::build_multipart_body(boundary, &fields, file_data, filename, content_type).unwrap();
    let body_str = String::from_utf8_lossy(&result);

    // Should handle empty file
    assert!(body_str.contains("name=\"test\""));
    assert!(body_str.contains("name=\"file\""));
    assert!(body_str.contains("filename=\"empty.bin\""));
    assert!(body_str.contains("Content-Type: application/octet-stream"));
}

#[test]
fn test_build_multipart_body_special_characters() {
    let boundary = "boundary";
    let fields = vec![PolicyField {
        key: "Content-Type".to_string(),
        value: "application/pdf".to_string(),
    }];
    let file_data = b"\xFF\xFE binary data \x00";
    let filename = "special-file.bin";
    let content_type = "application/octet-stream";

    let result = upload::build_multipart_body(boundary, &fields, file_data, filename, content_type);
    assert!(result.is_ok());

    let body = result.unwrap();
    // Binary data should be preserved
    assert!(body.contains(&0xFF));
    assert!(body.contains(&0xFE));
    assert!(body.contains(&0x00));
}
