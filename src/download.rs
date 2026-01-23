use anyhow::Result;

use crate::bindings::wasi::{
    filesystem::{
        preopens::get_directories,
        types::{DescriptorFlags, OpenFlags, PathFlags},
    },
    http::outgoing_handler,
    http::types::{Fields, Method, OutgoingRequest, Scheme},
    io::streams::StreamError,
};

pub struct ParsedUrl {
    pub(crate) scheme: Scheme,
    pub(crate) authority: String,
    pub(crate) path_and_query: String,
}

pub fn download_from_url(url: &str, headers: &Option<Vec<(String, String)>>) -> Result<Vec<u8>> {
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

pub fn parse_url(url: &str) -> Result<ParsedUrl> {
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

pub fn read_from_filesystem(filename: &str) -> Result<Vec<u8>> {
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

pub fn save_to_filesystem(filename: &str, data: &[u8]) -> Result<()> {
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

pub fn delete_from_filesystem(filename: &str) -> Result<()> {
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
    stream: &crate::bindings::wasi::io::streams::OutputStream,
    data: &[u8],
) -> Result<()> {
    for chunk in data.chunks(4096) {
        stream
            .blocking_write_and_flush(chunk)
            .map_err(|e| anyhow::anyhow!("Stream write error: {e:?}"))?;
    }
    Ok(())
}
