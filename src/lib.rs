use anyhow::{Context, Result};

mod bindings {
    wit_bindgen::generate!({
        generate_all,
    });
}

use bindings::{
    bettyblocks::data_api::data_api::HelperContext,
    bettyblocks::data_api::data_api_utilities::{self, PolicyField, PresignedUploadUrl, Property},
    exports::bettyblocks::file::uploader::{
        Guest as UploaderGuest, Model, UploadConfig, UploadResult,
    },
    exports::wasi::http::incoming_handler::Guest,
    wasi::{
        http::outgoing_handler,
        http::types::{
            Fields, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse,
            ResponseOutparam, Scheme,
        },
        io::streams::StreamError,
    },
};

use serde::Deserialize;

use bindings::wasi::filesystem::{
    preopens::get_directories,
    types::{DescriptorFlags, OpenFlags, PathFlags},
};

// Intermediate structs for JSON deserialization
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UploadRequestPayload {
    #[serde(alias = "application_id")]
    application_id: String,
    #[serde(alias = "action_id")]
    action_id: String,
    #[serde(alias = "log_id")]
    log_id: String,
    #[serde(alias = "encrypted_configurations")]
    encrypted_configurations: Option<Vec<String>>,
    jwt: Option<String>,
    model: ModelName,
    property: PropertyField,
    url: String,
    filename: String,
    #[serde(rename = "content-type")]
    content_type: String,
    headers: Option<Vec<HeaderPair>>,
}

#[derive(Debug, Deserialize)]
struct ModelName {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PropertyField {
    Single(PropertyName),
    Array(Vec<PropertyName>),
}

#[derive(Debug, Deserialize)]
struct PropertyName {
    name: String,
}

#[derive(Debug, Deserialize)]
struct HeaderPair {
    key: String,
    value: String,
}

struct Component;

impl Guest for Component {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        match handle_request(request) {
            Ok(message) => {
                eprintln!("✅ {}", message);
                send_response(response_out, 200, message.as_bytes());
            }
            Err(e) => {
                eprintln!("❌ Error: {}", e);
                let error_msg = format!("Failed to upload file: {e}");
                send_response(response_out, 500, error_msg.as_bytes());
            }
        }
    }
}

impl UploaderGuest for Component {
    fn upload(helper_context: HelperContext, config: UploadConfig) -> Result<UploadResult, String> {
        upload_file_internal(helper_context, config).map_err(|e| e.to_string())
    }
}

fn handle_request(request: IncomingRequest) -> Result<String> {
    eprintln!("📤 Processing incoming upload request");

    let body_content = read_request_body(request)?;
    let (helper_context, config) = parse_upload_request(&body_content)?;

    let result = upload_file_internal(helper_context, config)?;

    Ok(format!(
        "File uploaded successfully! Reference: {}, Size: {} bytes",
        result.reference, result.file_size
    ))
}

fn parse_upload_request(body_content: &str) -> Result<(HelperContext, UploadConfig)> {
    let payload: UploadRequestPayload =
        serde_json::from_str(body_content).context("Request body must be valid JSON")?;

    let helper_context = HelperContext {
        application_id: payload.application_id,
        action_id: payload.action_id,
        log_id: payload.log_id,
        encrypted_configurations: payload.encrypted_configurations,
        jwt: payload.jwt,
    };

    let property_name = match payload.property {
        PropertyField::Single(prop) => prop.name,
        PropertyField::Array(props) => props
            .first()
            .ok_or_else(|| anyhow::anyhow!("Property array is empty"))?
            .name
            .clone(),
    };

    let source_headers = payload.headers.map(|headers| {
        headers
            .into_iter()
            .map(|h| (h.key, h.value))
            .collect::<Vec<_>>()
    });

    let config = UploadConfig {
        model: Model {
            name: payload.model.name,
        },
        property: Property {
            name: property_name,
            filename: payload.filename,
            file_size: 0,
            content_type: payload.content_type,
        },
        source_url: payload.url,
        source_headers,
    };

    Ok((helper_context, config))
}

fn upload_file_internal(
    _helper_context: HelperContext,
    config: UploadConfig,
) -> Result<UploadResult> {
    eprintln!("Downloading source file: {}", config.source_url);

    let file_data = match download_from_url(&config.source_url, &config.source_headers) {
        Ok(data) => {
            eprintln!("✅ Successfully downloaded {} bytes", data.len());
            data
        }
        Err(e) => {
            eprintln!(
                "❌ Failed to download file from {}: {}",
                config.source_url, e
            );
            return Err(e.context(format!(
                "Failed to download file from {}",
                config.source_url
            )));
        }
    };

    let file_size = file_data.len() as u64;

    if let Err(e) = save_to_filesystem(&config.property.filename, &file_data) {
        eprintln!("❌ Failed to save file to filesystem: {}", e);
        return Err(e.context(format!(
            "Failed to save file '{}' to filesystem",
            config.property.filename
        )));
    }
    eprintln!("✅ Saved file to filesystem");

    eprintln!(
        "Fetching presigned POST for model: {}, property: {}",
        config.model.name, config.property.name
    );

    let presigned_upload_url = match fetch_presigned_upload_url(&config) {
        Ok(post) => {
            eprintln!("✅ Successfully fetched presigned POST URL");
            post
        }
        Err(e) => {
            eprintln!("❌ Failed to fetch presigned POST: {}", e);
            return Err(e.context("Failed to fetch presigned POST URL"));
        }
    };

    // Read file from filesystem for upload
    let file_data_from_disk = match read_from_filesystem(&config.property.filename) {
        Ok(data) => {
            eprintln!("✅ Read {} bytes from filesystem", data.len());
            data
        }
        Err(e) => {
            eprintln!("❌ Failed to read file from filesystem: {}", e);
            // Try to clean up
            let _ = delete_from_filesystem(&config.property.filename);
            return Err(e.context(format!(
                "Failed to read file '{}' from filesystem",
                config.property.filename
            )));
        }
    };

    eprintln!(
        "Uploading {} bytes to Wasabi via presigned POST",
        file_data_from_disk.len()
    );

    if let Err(e) = upload_to_presigned_post(
        &presigned_upload_url,
        &file_data_from_disk,
        &config.property.filename,
        &config.property.content_type,
    ) {
        eprintln!("❌ Upload to Wasabi failed: {}", e);

        // Try to clean up the temporary file even if upload failed
        if let Err(cleanup_err) = delete_from_filesystem(&config.property.filename) {
            eprintln!(
                "⚠️ Warning: Failed to cleanup temporary file after upload failure: {}",
                cleanup_err
            );
        }

        return Err(e.context("Failed to upload file to Wasabi"));
    }
    eprintln!("✅ Successfully uploaded to Wasabi");

    if let Err(e) = delete_from_filesystem(&config.property.filename) {
        eprintln!("⚠️ Warning: Failed to delete temporary file: {}", e);
        // Don't fail the entire operation if cleanup fails
        // The upload was successful, so we continue
    } else {
        eprintln!("✅ Cleaned up temporary file");
    }

    Ok(UploadResult {
        reference: presigned_upload_url.reference.clone(),
        file_size,
        message: Some("Upload successful".into()),
    })
}

fn upload_to_presigned_post(
    presigned_post: &PresignedUploadUrl,
    file_data: &[u8],
    filename: &str,
    content_type: &str,
) -> Result<()> {
    let boundary = format!("----wasmcloud{}", generate_boundary());
    let body = build_multipart_body(
        &boundary,
        &presigned_post.fields,
        file_data,
        filename,
        content_type,
    )?;

    eprintln!("📤 Uploading multipart body: {} bytes", body.len());

    let headers = Fields::new();
    headers
        .append(
            "content-type",
            format!("multipart/form-data; boundary={}", boundary).as_bytes(),
        )
        .map_err(|_| anyhow::anyhow!("failed to set content-type"))?;

    let request = OutgoingRequest::new(headers);
    request
        .set_method(&Method::Post)
        .map_err(|_| anyhow::anyhow!("failed to set method"))?;
    request
        .set_scheme(Some(&Scheme::Https))
        .map_err(|_| anyhow::anyhow!("failed to set scheme"))?;

    // Parse the presigned URL to extract authority and path
    let parsed_url = parse_url(&presigned_post.url)?;

    request
        .set_authority(Some(&parsed_url.authority))
        .map_err(|_| anyhow::anyhow!("failed to set authority"))?;
    request
        .set_path_with_query(Some(&parsed_url.path_and_query))
        .map_err(|_| anyhow::anyhow!("failed to set path"))?;

    let request_body = request
        .body()
        .map_err(|_| anyhow::anyhow!("failed to get request body"))?;

    let future = outgoing_handler::handle(request, None)
        .map_err(|e| anyhow::anyhow!("handle failed: {:?}", e))?;

    let stream = request_body
        .write()
        .map_err(|_| anyhow::anyhow!("failed to open body stream"))?;

    // Write in chunks with progress reporting every 10%
    let mut offset = 0;
    let total_size = body.len();
    let mut last_reported_progress = 0;

    while offset < total_size {
        let chunk_size = std::cmp::min(4096, total_size - offset);
        let chunk = &body[offset..offset + chunk_size];

        // Use non-blocking write with check
        loop {
            match stream.check_write() {
                Ok(0) => {
                    stream.subscribe().block();
                    continue;
                }
                Ok(available) => {
                    let to_write = std::cmp::min(available as usize, chunk.len());
                    stream
                        .write(&chunk[..to_write])
                        .map_err(|e| anyhow::anyhow!("write failed: {:?}", e))?;
                    break;
                }
                Err(e) => return Err(anyhow::anyhow!("check_write failed: {:?}", e)),
            }
        }

        offset += chunk_size;

        // Report progress every 10%
        let progress = (offset * 100) / total_size;
        if progress >= last_reported_progress + 10 {
            eprintln!(
                "  📊 Upload progress: {}% ({}/{} bytes)",
                progress, offset, total_size
            );
            last_reported_progress = progress;
        }
    }

    eprintln!("✅ All data written, flushing...");
    stream
        .flush()
        .map_err(|e| anyhow::anyhow!("flush failed: {:?}", e))?;
    stream.subscribe().block();

    drop(stream);

    OutgoingBody::finish(request_body, None)
        .map_err(|_| anyhow::anyhow!("failed to finish body"))?;

    eprintln!("⏳ Waiting for response...");
    future.subscribe().block();

    let response = future
        .get()
        .ok_or_else(|| anyhow::anyhow!("no response"))?
        .map_err(|e| anyhow::anyhow!("response err: {:?}", e))??;

    let status = response.status();
    eprintln!("📊 Status: {}", status);

    if status >= 300 {
        let err = read_response_body(&response).unwrap_or_default();
        eprintln!("❌ Error body: {}", err);
        return Err(anyhow::anyhow!(
            "upload failed with status {}: {}",
            status,
            err
        ));
    }

    eprintln!("✅ Presigned POST upload succeeded");
    Ok(())
}

fn build_multipart_body(
    boundary: &str,
    fields: &[PolicyField],
    file_data: &[u8],
    filename: &str,
    content_type: &str,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    // Add all form fields first
    for field in fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{}\"\r\n\r\n",
                field.key
            )
            .as_bytes(),
        );
        body.extend_from_slice(field.value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }

    // Add file as the last field - S3 expects this pattern
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
            filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", content_type).as_bytes());
    body.extend_from_slice(file_data);
    body.extend_from_slice(b"\r\n");

    // Final boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    Ok(body)
}

fn read_from_filesystem(filename: &str) -> Result<Vec<u8>> {
    let preopens = get_directories();
    if preopens.is_empty() {
        return Err(anyhow::anyhow!("No preopened directories available"));
    }

    let (dir, _) = &preopens[0];

    // Open file with READ permission
    let file = dir
        .open_at(
            PathFlags::empty(),
            filename,
            OpenFlags::empty(),
            DescriptorFlags::READ,
        )
        .map_err(|e| anyhow::anyhow!("Failed to open file for reading: {e:?}"))?;

    // Get file size
    let stat = file
        .stat()
        .map_err(|e| anyhow::anyhow!("Failed to get file stats: {e:?}"))?;

    let file_size = stat.size;
    eprintln!("📖 Reading file of size: {} bytes", file_size);

    // Read from position 0
    let stream = file
        .read_via_stream(0)
        .map_err(|e| anyhow::anyhow!("Failed to get read stream: {e:?}"))?;

    let mut data = Vec::with_capacity(file_size as usize);
    loop {
        match stream.blocking_read(8192) {
            Ok(chunk) if chunk.is_empty() => break,
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => return Err(anyhow::anyhow!("Stream error while reading file: {e:?}")),
        }
    }

    drop(stream);
    drop(file);

    eprintln!("📖 Read {} bytes from {}", data.len(), filename);

    Ok(data)
}

fn fetch_presigned_upload_url(
    cfg: &UploadConfig,
) -> Result<PresignedUploadUrl> {
    let presigned_obj =
        data_api_utilities::fetch_presigned_upload_url(&cfg.model.name, &cfg.property)
            .map_err(|e| anyhow::anyhow!("Failed to fetch presigned URL: {}", e))?;
    Ok(presigned_obj)
}

fn download_from_url(url: &str, headers: &Option<Vec<(String, String)>>) -> Result<Vec<u8>> {
    eprintln!("🌐 Downloading from: {}", url);

    let parsed_url = parse_url(url)?;
    let request_headers = Fields::new();

    // Add custom headers if provided
    if let Some(custom_headers) = headers {
        for (key, value) in custom_headers {
            request_headers
                .append(&key.to_lowercase(), value.as_bytes())
                .map_err(|_| anyhow::anyhow!("Failed to set header: {}", key))?;
        }
    }

    let outgoing_request = OutgoingRequest::new(request_headers);

    outgoing_request
        .set_method(&Method::Get)
        .map_err(|_| anyhow::anyhow!("Failed to set method"))?;

    outgoing_request
        .set_scheme(Some(&parsed_url.scheme))
        .map_err(|_| anyhow::anyhow!("Failed to set scheme"))?;

    outgoing_request
        .set_authority(Some(&parsed_url.authority))
        .map_err(|_| anyhow::anyhow!("Failed to set authority"))?;

    outgoing_request
        .set_path_with_query(Some(&parsed_url.path_and_query))
        .map_err(|_| anyhow::anyhow!("Failed to set path"))?;

    let future_response = outgoing_handler::handle(outgoing_request, None)
        .map_err(|e| anyhow::anyhow!("Failed to send HTTP request: {e:?}"))?;

    let incoming_response = match future_response.get() {
        Some(result) => result.map_err(|e| anyhow::anyhow!("HTTP request failed: {e:?}"))?,
        None => {
            future_response.subscribe().block();
            future_response
                .get()
                .ok_or_else(|| anyhow::anyhow!("Failed to get response"))?
                .map_err(|e| anyhow::anyhow!("HTTP request failed: {e:?}"))?
        }
    }
    .map_err(|e| anyhow::anyhow!("HTTP response error: {e:?}"))?;

    let status = incoming_response.status();
    if status < 200 || status >= 300 {
        return Err(anyhow::anyhow!(
            "HTTP request failed with status code: {}",
            status
        ));
    }

    let response_body = incoming_response
        .consume()
        .map_err(|_| anyhow::anyhow!("Failed to consume response"))?;

    let input_stream = response_body
        .stream()
        .map_err(|_| anyhow::anyhow!("Failed to get response stream"))?;

    let mut data = Vec::new();
    loop {
        match input_stream.blocking_read(8192) {
            Ok(chunk) if chunk.is_empty() => break,
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Stream error while reading response: {e:?}"
                ))
            }
        }
    }

    eprintln!("📦 Downloaded {} bytes from URL", data.len());

    Ok(data)
}

fn generate_boundary() -> String {
    use std::time::SystemTime;

    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("{:x}", nanos)
}

fn read_response_body(response: &bindings::wasi::http::types::IncomingResponse) -> Result<String> {
    let response_body = response
        .consume()
        .map_err(|_| anyhow::anyhow!("Failed to consume response"))?;

    let input_stream = response_body
        .stream()
        .map_err(|_| anyhow::anyhow!("Failed to get response stream"))?;

    let mut data = Vec::new();
    loop {
        match input_stream.blocking_read(8192) {
            Ok(chunk) if chunk.is_empty() => break,
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Stream error while reading response: {e:?}"
                ))
            }
        }
    }

    String::from_utf8(data).context("Invalid UTF-8 in response body")
}

fn save_to_filesystem(filename: &str, data: &[u8]) -> Result<()> {
    let preopens = get_directories();
    if preopens.is_empty() {
        return Err(anyhow::anyhow!("No preopened directories available"));
    }

    let (dir, _) = &preopens[0];

    // Open file with CREATE flag and READ|WRITE permissions
    let file = dir
        .open_at(
            PathFlags::empty(),
            filename,
            OpenFlags::CREATE,
            DescriptorFlags::READ | DescriptorFlags::WRITE,
        )
        .map_err(|e| anyhow::anyhow!("Failed to open file for writing: {e:?}"))?;

    // Write from position 0
    let stream = file
        .write_via_stream(0)
        .map_err(|e| anyhow::anyhow!("Failed to get write stream: {e:?}"))?;

    write_stream_in_chunks(&stream, data)?;

    drop(stream);
    drop(file);

    eprintln!("💾 Saved {} bytes to {}", data.len(), filename);

    Ok(())
}

fn delete_from_filesystem(filename: &str) -> Result<()> {
    let preopens = get_directories();
    if preopens.is_empty() {
        return Err(anyhow::anyhow!("No preopened directories available"));
    }

    let (dir, _) = &preopens[0];

    dir.unlink_file_at(filename)
        .map_err(|e| anyhow::anyhow!("Failed to delete file: {e:?}"))?;

    eprintln!("🗑️ Deleted temporary file: {}", filename);

    Ok(())
}

fn write_stream_in_chunks(
    stream: &bindings::wasi::io::streams::OutputStream,
    data: &[u8],
) -> Result<()> {
    for chunk in data.chunks(4096) {
        stream
            .blocking_write_and_flush(chunk)
            .map_err(|e| anyhow::anyhow!("Stream write error: {e:?}"))?;
    }
    Ok(())
}

fn read_request_body(request: IncomingRequest) -> Result<String> {
    let body_stream = request
        .consume()
        .map_err(|_| anyhow::anyhow!("Failed to consume request"))?;

    let input_stream = body_stream
        .stream()
        .map_err(|_| anyhow::anyhow!("Failed to get stream"))?;

    let mut body_data = Vec::new();
    loop {
        match input_stream.blocking_read(8192) {
            Ok(chunk) if chunk.is_empty() => break,
            Ok(chunk) => body_data.extend_from_slice(&chunk),
            Err(StreamError::Closed) => break,
            Err(e) => return Err(anyhow::anyhow!("Stream error: {e:?}")),
        }
    }

    String::from_utf8(body_data).context("Invalid UTF-8 in request body")
}

struct ParsedUrl {
    scheme: Scheme,
    authority: String,
    path_and_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl> {
    let (scheme_str, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("Invalid URL: missing scheme"))?;

    let scheme = match scheme_str.to_lowercase().as_str() {
        "http" => Scheme::Http,
        "https" => Scheme::Https,
        other => Scheme::Other(other.to_string()),
    };

    let (authority, path_and_query) = if let Some(idx) = rest.find('/') {
        let (auth, path) = rest.split_at(idx);
        (auth.to_string(), path.to_string())
    } else {
        (rest.to_string(), "/".to_string())
    };

    Ok(ParsedUrl {
        scheme,
        authority,
        path_and_query,
    })
}

fn send_response(response_out: ResponseOutparam, status: u16, body: &[u8]) {
    let response = OutgoingResponse::new(Fields::new());
    response.set_status_code(status).unwrap();
    let response_body = response.body().unwrap();
    ResponseOutparam::set(response_out, Ok(response));
    let stream = response_body.write().unwrap();
    stream.blocking_write_and_flush(body).unwrap();
    drop(stream);
    OutgoingBody::finish(response_body, None).unwrap();
}

bindings::export!(Component with_types_in bindings);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generate_boundary() {
        let boundary = generate_boundary();
        assert!(!boundary.is_empty());
        assert!(boundary.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_boundary_unique() {
        let boundary1 = generate_boundary();
        let boundary2 = generate_boundary();
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
            build_multipart_body(boundary, &fields, file_data, filename, content_type).unwrap();
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
            build_multipart_body(boundary, &fields, file_data, filename, content_type).unwrap();
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
            build_multipart_body(boundary, &fields, file_data, filename, content_type).unwrap();
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

        let result = build_multipart_body(boundary, &fields, file_data, filename, content_type);
        assert!(result.is_ok());

        let body = result.unwrap();
        // Binary data should be preserved
        assert!(body.contains(&0xFF));
        assert!(body.contains(&0xFE));
        assert!(body.contains(&0x00));
    }
}
