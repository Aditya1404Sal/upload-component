use anyhow::{Context, Result};

use crate::bindings::{
    bettyblocks::data_api::data_api_utilities::{
        self, Model, PolicyField, PresignedPost, Property,
    },
    exports::bettyblocks::file::uploader::{DownloadHeaders, UploadResult},
    wasi::{
        http::{
            outgoing_handler,
            types::{Fields, Method, OutgoingBody, OutgoingRequest, Scheme},
        },
        io::streams::StreamError,
    },
};

/// Extracts filename and content type from a download URL
fn extract_file_info_from_url(url: &str) -> Result<(String, String)> {
    // Parse the URL to get the path component
    let url_path = url
        .split('?')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid URL format"))?;

    // Extract filename from the path
    let filename = url_path
        .split('/')
        .last()
        .ok_or_else(|| anyhow::anyhow!("Could not extract filename from URL"))?
        .to_string();

    // If filename is empty, use a default
    let filename = if filename.is_empty() {
        "downloaded_file".to_string()
    } else {
        // URL decode the filename
        urlencoding::decode(&filename)
            .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&filename))
            .to_string()
    };

    // Guess content type from filename extension using mime_guess
    let content_type = mime_guess::from_path(&filename)
        .first_or_octet_stream()
        .to_string();

    Ok((filename, content_type))
}

pub fn upload_file_internal(
    model: Model,
    property: Property,
    download_url: String,
    download_headers: DownloadHeaders,
) -> Result<UploadResult> {
    eprintln!("Downloading source file: {}", download_url);

    let file_data = match crate::download::download_from_url(&download_url, &download_headers) {
        Ok(data) => {
            eprintln!("✅ Successfully downloaded {} bytes", data.len());
            data
        }
        Err(e) => {
            eprintln!("❌ Failed to download file from {}: {}", download_url, e);
            return Err(e.context(format!("Failed to download file from {}", download_url)));
        }
    };

    // Extract filename and content type from the download URL
    let (file_name, content_type) = extract_file_info_from_url(&download_url)
        .context("Failed to extract file info from URL")?;

    eprintln!("📄 Extracted filename: {}", file_name);
    eprintln!("📋 Detected content type: {}", content_type);

    let file_size = file_data.len() as u64;

    if let Err(e) = crate::download::save_to_filesystem(&file_name, &file_data) {
        eprintln!("❌ Failed to save file to filesystem: {}", e);
        return Err(e.context(format!("Failed to save file '{}' to filesystem", file_name)));
    }
    eprintln!("✅ Saved file to filesystem");

    eprintln!(
        "Fetching presigned POST for model: {}, property: {}",
        model.name, property.name
    );

    let presigned_upload_url =
        match fetch_presigned_upload_url(&model, &property, &content_type, &file_name) {
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
    let file_data_from_disk = match crate::download::read_from_filesystem(&file_name) {
        Ok(data) => {
            eprintln!("✅ Read {} bytes from filesystem", data.len());
            data
        }
        Err(e) => {
            eprintln!("❌ Failed to read file from filesystem: {}", e);
            // Try to clean up
            let _ = crate::download::delete_from_filesystem(&file_name);
            return Err(e.context(format!(
                "Failed to read file '{}' from filesystem",
                file_name
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
        &file_name,
        &content_type,
    ) {
        eprintln!("❌ Upload to Wasabi failed: {}", e);

        // Try to clean up the temporary file even if upload failed
        if let Err(cleanup_err) = crate::download::delete_from_filesystem(&file_name) {
            eprintln!(
                "⚠️ Warning: Failed to cleanup temporary file after upload failure: {}",
                cleanup_err
            );
        }

        return Err(e.context("Failed to upload file to Wasabi"));
    }
    eprintln!("✅ Successfully uploaded to Wasabi");

    if let Err(e) = crate::download::delete_from_filesystem(&file_name) {
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
    presigned_post: &PresignedPost,
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

fn fetch_presigned_upload_url(
    model: &Model,
    property: &Property,
    content_type: &str,
    file_name: &str,
) -> Result<PresignedPost> {
    let presigned_obj =
        data_api_utilities::fetch_presigned_post(&model, property, content_type, file_name)
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
