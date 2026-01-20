use anyhow::{Context, Result};

mod bindings {
    wit_bindgen::generate!({
        generate_all,
    });
}

use bindings::{
    bettyblocks::data_api::data_api::{self, HelperContext},
    exports::bettyblocks::file::uploader::{
        Guest as UploaderGuest, Model, Property, UploadConfig, UploadResult,
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

#[cfg(feature = "fs")]
use bindings::wasi::filesystem::{
    preopens::get_directories,
    types::{DescriptorFlags, OpenFlags, PathFlags},
};

use serde_json::Value;
use tracing::debug;

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
        },
        filename: payload.filename,
        content_type: payload.content_type,
        source_url: payload.url,
        source_headers,
    };

    Ok((helper_context, config))
}

fn upload_file_internal(
    helper_context: HelperContext,
    config: UploadConfig,
) -> Result<UploadResult> {
    eprintln!(
        "Fetching presigned URL for model: {}, property: {}",
        config.model.name, config.property.name
    );

    // Fetch presigned URL from data-api
    let presigned_post = fetch_presigned_post(&helper_context, &config)?;

    eprintln!("Downloading file from: {}", config.source_url);

    // Download from source URL
    let file_data = download_from_url(&config.source_url, &config.source_headers)?;

    #[cfg(feature = "fs")]
    {
        // Determine filename
        let filename = &config.filename;

        eprintln!(
            "Temporarily saving {} bytes as: {}",
            file_data.len(),
            filename
        );

        // Save to temporary filesystem
        save_to_filesystem(filename, &file_data)?;

        eprintln!("Uploading to presigned URL");

        // Upload to presigned S3 URL
        upload_to_presigned_url(&presigned_post.url, &file_data, &presigned_post.fields)?;

        delete_from_filesystem(filename)?;

        eprintln!("Upload complete, temporary file cleaned up");
    }

    #[cfg(not(feature = "fs"))]
    {
        eprintln!(
            "Uploading {} bytes directly to presigned URL (in-memory)",
            file_data.len()
        );

        // Upload directly from memory without filesystem operations
        upload_to_presigned_url(&presigned_post.url, &file_data, &presigned_post.fields)?;

        eprintln!("Upload complete (in-memory mode)");
    }

    Ok(UploadResult {
        reference: presigned_post.reference.to_string(),
        file_size: file_data.len() as u64,
        message: Some(format!("Successfully uploaded {} bytes", file_data.len())),
    })
}

struct PresignedPost {
    url: String,
    fields: Vec<(String, String)>,
    reference: String,
}

fn fetch_presigned_post(ctx: &HelperContext, cfg: &UploadConfig) -> Result<PresignedPost> {
    let mutation = r#"
      mutation GenerateUpload(
        $model: String!,
        $property: String!,
        $contentType: String!,
        $fileName: String!
      ) {
        generateFileUploadRequest(
          modelName: $model
          propertyName: $property
          contentType: $contentType
          fileName: $fileName
        ) {
          ... on PresignedPostRequest {
            url
            fields
            reference
          }
        }
      }
    "#;

    let vars = serde_json::json!({
        "model": cfg.model.name,
        "property": cfg.property.name,
        "contentType": cfg.content_type,
        "fileName": cfg.filename,
    });

    let resp = data_api::request(ctx, mutation, &vars.to_string())
        .map_err(|e| anyhow::anyhow!("data-api request failed: {}", e))?;

    let json: Value = serde_json::from_str(&resp)?;
    let post = &json["data"]["generateFileUploadRequest"];

    Ok(PresignedPost {
        url: post["url"].as_str().unwrap().to_string(),
        reference: post["reference"].as_str().unwrap().to_string(),
        fields: post["fields"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect(),
    })
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

fn upload_to_presigned_url(
    presigned_url: &str,
    file_data: &[u8],
    fields: &Vec<(String, String)>,
) -> Result<()> {
    let parsed_url = parse_url(presigned_url)?;

    // Generate a boundary for multipart/form-data
    let boundary = format!("----WebKitFormBoundary{}", generate_boundary());

    // Build the multipart body
    let body = build_multipart_body(&boundary, fields, file_data)?;

    debug!("Built multipart body with {} bytes", body.len());

    let headers = Fields::new();

    // Set Content-Type header with boundary
    let content_type = format!("multipart/form-data; boundary={}", boundary);
    headers
        .append("content-type", content_type.as_bytes())
        .map_err(|_| anyhow::anyhow!("Failed to set content-type header"))?;

    // Set Content-Length header
    let content_length = body.len().to_string();
    headers
        .append("content-length", content_length.as_bytes())
        .map_err(|_| anyhow::anyhow!("Failed to set content-length header"))?;

    let outgoing_request = OutgoingRequest::new(headers);

    // Use POST for presigned POST (not PUT)
    outgoing_request
        .set_method(&Method::Post)
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

    // Write the request body
    let request_body = outgoing_request
        .body()
        .map_err(|_| anyhow::anyhow!("Failed to get request body"))?;

    let output_stream = request_body
        .write()
        .map_err(|_| anyhow::anyhow!("Failed to get output stream"))?;

    write_stream_in_chunks(&output_stream, &body)?;

    drop(output_stream);
    OutgoingBody::finish(request_body, None)
        .map_err(|_| anyhow::anyhow!("Failed to finish request body"))?;

    let future_response = outgoing_handler::handle(outgoing_request, None)
        .map_err(|e| anyhow::anyhow!("Failed to send upload request: {e:?}"))?;

    let incoming_response = match future_response.get() {
        Some(result) => result.map_err(|e| anyhow::anyhow!("Upload request failed: {e:?}"))?,
        None => {
            future_response.subscribe().block();
            future_response
                .get()
                .ok_or_else(|| anyhow::anyhow!("Failed to get response"))?
                .map_err(|e| anyhow::anyhow!("Upload request failed: {e:?}"))?
        }
    }
    .map_err(|e| anyhow::anyhow!("Upload response error: {e:?}"))?;

    let status = incoming_response.status();
    if status < 200 || status >= 300 {
        // Try to read error response body for debugging
        let error_body = read_response_body(&incoming_response).unwrap_or_default();
        eprintln!("❌ Upload failed response: {}", error_body);
        return Err(anyhow::anyhow!(
            "Upload failed with status code: {}",
            status
        ));
    }

    eprintln!("✅ Upload successful with status: {}", status);

    Ok(())
}

fn build_multipart_body(
    boundary: &str,
    fields: &Vec<(String, String)>,
    file_data: &[u8],
) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    // Add all form fields first (these come from the presigned POST response)
    for (key, value) in fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{}\"\r\n\r\n", key).as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }

    // Add the file data last (S3 requires 'file' to be the last field)
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"file\"; filename=\"file\"\r\n");
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(file_data);
    body.extend_from_slice(b"\r\n");

    // Final boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    Ok(body)
}

fn generate_boundary() -> String {
    // Generate a simple random boundary
    // In production, you might want to use a proper random generator
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

#[cfg(feature = "fs")]
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

    eprintln!("Saved {} bytes to {}", data.len(), filename);

    Ok(())
}

#[cfg(feature = "fs")]
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
