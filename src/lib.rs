use anyhow::{Context, Result};
use serde::Deserialize;

pub mod download;
pub mod tests;
pub mod upload;

pub mod bindings {
    wit_bindgen::generate!({
        generate_all,
    });
}

use bindings::{
    bettyblocks::data_api::{data_api::HelperContext, data_api_utilities::Property},
    exports::bettyblocks::file::uploader::{
        Guest as UploaderGuest, Model, UploadConfig, UploadResult,
    },
    exports::wasi::http::incoming_handler::Guest,
    wasi::{
        http::types::{Fields, IncomingRequest, OutgoingBody, OutgoingResponse, ResponseOutparam},
        io::streams::StreamError,
    },
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
        upload::upload_file_internal(helper_context, config).map_err(|e| e.to_string())
    }
}

fn handle_request(request: IncomingRequest) -> Result<String> {
    eprintln!("📤 Processing incoming upload request");

    let body_content = read_request_body(request)?;
    let (helper_context, config) = parse_upload_request(&body_content)?;

    let result = upload::upload_file_internal(helper_context, config)?;

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
