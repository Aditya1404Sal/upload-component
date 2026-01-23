use anyhow::{Context, Result};

use crate::bindings::{
    bettyblocks::data_api::data_api::HelperContext,
    bettyblocks::data_api::data_api_utilities::{self, PolicyField, PresignedUploadUrl},
    exports::bettyblocks::file::uploader::{UploadConfig, UploadResult},
    wasi::{
        http::outgoing_handler,
        http::types::{Fields, Method, OutgoingBody, OutgoingRequest, Scheme},
        io::streams::StreamError,
    },
};

pub fn upload_file_internal(
    _helper_context: HelperContext,
    config: UploadConfig,
) -> Result<UploadResult> {
    eprintln!("Downloading source file: {}", config.source_url);

    let file_data =
        match crate::download::download_from_url(&config.source_url, &config.source_headers) {
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

    if let Err(e) = crate::download::save_to_filesystem(&config.property.filename, &file_data) {
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
    let file_data_from_disk = match crate::download::read_from_filesystem(&config.property.filename)
    {
        Ok(data) => {
            eprintln!("✅ Read {} bytes from filesystem", data.len());
            data
        }
        Err(e) => {
            eprintln!("❌ Failed to read file from filesystem: {}", e);
            // Try to clean up
            let _ = crate::download::delete_from_filesystem(&config.property.filename);
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
        if let Err(cleanup_err) = crate::download::delete_from_filesystem(&config.property.filename)
        {
            eprintln!(
                "⚠️ Warning: Failed to cleanup temporary file after upload failure: {}",
                cleanup_err
            );
        }

        return Err(e.context("Failed to upload file to Wasabi"));
    }
    eprintln!("✅ Successfully uploaded to Wasabi");

    if let Err(e) = crate::download::delete_from_filesystem(&config.property.filename) {
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
    let parsed_url = crate::download::parse_url(&presigned_post.url)?;

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

pub fn build_multipart_body(
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

fn fetch_presigned_upload_url(cfg: &UploadConfig) -> Result<PresignedUploadUrl> {
    let presigned_obj =
        data_api_utilities::fetch_presigned_upload_url(&cfg.model.name, &cfg.property)
            .map_err(|e| anyhow::anyhow!("Failed to fetch presigned URL: {}", e))?;
    Ok(presigned_obj)
}

pub fn generate_boundary() -> String {
    use std::time::SystemTime;

    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    format!("{:x}", nanos)
}

fn read_response_body(
    response: &crate::bindings::wasi::http::types::IncomingResponse,
) -> Result<String> {
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
