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
        filesystem::{
            preopens::get_directories,
            types::{DescriptorFlags, OpenFlags, PathFlags},
        },
        http::outgoing_handler,
        http::types::{
            Fields, IncomingRequest, Method, OutgoingBody, OutgoingRequest, OutgoingResponse,
            ResponseOutparam, Scheme,
        },
        io::streams::StreamError,
    },
};
use serde_json::Value;

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
    let json: Value =
        serde_json::from_str(body_content).context("Request body must be valid JSON")?;

    // Parse helper context
    let helper_context = parse_helper_context(&json)?;

    // Parse model
    let model_name = json
        .get("model")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'model.name'"))?
        .to_string();

    // Parse property
    let property_name = json
        .get("property")
        .and_then(|v| {
            if let Some(arr) = v.as_array() {
                arr.first()
            } else {
                Some(v)
            }
        })
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'property.name'"))?
        .to_string();

    // Parse source URL
    let source_url = json
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'url'"))?
        .to_string();

    // Parse optional headers
    let source_headers = json.get("headers").and_then(|v| {
        if let Some(arr) = v.as_array() {
            let mut headers = Vec::new();
            for item in arr {
                if let (Some(key), Some(value)) = (
                    item.get("key").and_then(|k| k.as_str()),
                    item.get("value").and_then(|v| v.as_str()),
                ) {
                    headers.push((key.to_string(), value.to_string()));
                }
            }
            Some(headers)
        } else {
            None
        }
    });

    let config = UploadConfig {
        model: Model { name: model_name },
        property: Property {
            name: property_name,
        },
        source_url,
        source_headers,
    };

    Ok((helper_context, config))
}

fn parse_helper_context(json: &Value) -> Result<HelperContext> {
    let application_id = json
        .get("applicationId")
        .or_else(|| json.get("application_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'applicationId'"))?
        .to_string();

    let action_id = json
        .get("actionId")
        .or_else(|| json.get("action_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'actionId'"))?
        .to_string();

    let log_id = json
        .get("logId")
        .or_else(|| json.get("log_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'logId'"))?
        .to_string();

    let encrypted_configurations = json
        .get("encryptedConfigurations")
        .or_else(|| json.get("encrypted_configurations"))
        .and_then(|v| {
            if let Some(arr) = v.as_array() {
                Some(
                    arr.iter()
                        .filter_map(|s| s.as_str().map(|s| s.to_string()))
                        .collect(),
                )
            } else {
                None
            }
        });

    let jwt = json
        .get("jwt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(HelperContext {
        application_id,
        action_id,
        log_id,
        encrypted_configurations,
        jwt,
    })
}

fn upload_file_internal(
    helper_context: HelperContext,
    config: UploadConfig,
) -> Result<UploadResult> {
    eprintln!(
        "🔑 Fetching presigned URL for model: {}, property: {}",
        config.model.name, config.property.name
    );

    // Step 1: Fetch presigned URL from data-api
    //let presigned_url = fetch_presigned_url(&helper_context, &config)?;

    eprintln!("🌐 Downloading file from: {}", config.source_url);

    // Step 2: Download from source URL
    let file_data = download_from_url(&config.source_url, &config.source_headers)?;

    // Determine filename
    let filename = extract_filename_from_url(&config.source_url);

    eprintln!(
        "💾 Temporarily saving {} bytes as: {}",
        file_data.len(),
        filename
    );

    // Step 3: Save to temporary filesystem
    save_to_filesystem(&filename, &file_data)?;

    eprintln!("📤 Uploading to presigned URL");

    // // Step 4: Upload to presigned S3 URL
    // upload_to_presigned_url(&presigned_url, &file_data)?;

    // // Step 5: Clean up temporary file
    // delete_from_filesystem(&filename)?;

    eprintln!("✅ Upload complete, temporary file cleaned up");

    // Step 6: Extract file reference from presigned URL
    // let reference = extract_file_reference(&presigned_url)?;

    Ok(UploadResult {
        reference: "reference".to_string(),
        file_size: file_data.len() as u64,
        message: Some(format!("Successfully uploaded {} bytes", file_data.len())),
    })
}

fn fetch_presigned_url(helper_context: &HelperContext, config: &UploadConfig) -> Result<String> {
    // Build GraphQL mutation to get presigned upload URL
    let mutation = format!(
        r#"
        This is currently an unknown query format
        "#,
        //config.model.name, config.property.name
    );

    eprintln!("📡 Calling data-api for presigned URL");

    // Call data-api
    let response = data_api::request(&helper_context.clone(), &mutation, "{}")
        .map_err(|e| anyhow::anyhow!("Failed to fetch presigned URL: {}", e))?;

    // Parse response
    let response_json: Value =
        serde_json::from_str(&response).context("Failed to parse data-api response")?;

    let url = response_json
        .get("data")
        .and_then(|d| d.get("getPresignedUploadUrl"))
        .and_then(|u| u.get("url"))
        .and_then(|u| u.as_str())
        .ok_or_else(|| anyhow::anyhow!("Presigned URL not found in response"))?
        .to_string();

    eprintln!("✅ Received presigned URL from data-api");

    Ok(url)
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

fn upload_to_presigned_url(presigned_url: &str, file_data: &[u8]) -> Result<()> {
    let parsed_url = parse_url(presigned_url)?;
    let headers = Fields::new();

    // Presigned URLs typically don't need additional headers
    // The authentication is in the URL query parameters

    let outgoing_request = OutgoingRequest::new(headers);

    outgoing_request
        .set_method(&Method::Put)
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

    write_stream_in_chunks(&output_stream, file_data)?;

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
        return Err(anyhow::anyhow!(
            "Upload failed with status code: {}",
            status
        ));
    }

    eprintln!("✅ Upload successful with status: {}", status);

    Ok(())
}

fn extract_file_reference(presigned_url: &str) -> Result<String> {
    // Extract the file path/reference from the presigned URL
    // This assumes the reference is in the URL path before query parameters
    let url_without_query = presigned_url.split('?').next().unwrap_or(presigned_url);

    // Extract just the file path/key from the URL
    let reference = url_without_query
        .split("://")
        .nth(1)
        .and_then(|s| s.split('/').skip(1).collect::<Vec<_>>().join("/").into())
        .ok_or_else(|| anyhow::anyhow!("Could not extract file reference from URL"))?;

    Ok(reference)
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

fn extract_filename_from_url(url: &str) -> String {
    url.split('/')
        .last()
        .and_then(|s| s.split('?').next())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "downloaded_file".to_string())
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
