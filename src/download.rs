use anyhow::{Context, Result};
use tracing::debug;

use crate::bindings::wasi::{
    http::outgoing_handler,
    http::types::{Fields, Method, OutgoingRequest, Scheme},
    io::streams::StreamError,
};

pub struct ParsedUrl {
    pub(crate) scheme: Scheme,
    pub(crate) authority: String,
    pub(crate) path_and_query: String,
}

pub fn download_from_url(
    url: &str,
    headers: &Option<Vec<(String, String)>>,
) -> Result<(Vec<u8>, String, String)> {
    debug!("Downloading from: {}", url);

    let parsed_url = parse_url(url)?;
    let request_headers = Fields::new();

    let (file_name, content_type) =
        extract_file_info_from_url(url).context("Failed to extract file info from URL")?;

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
    if !(200..300).contains(&status) {
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

    debug!("Downloaded {} bytes from URL", data.len());

    Ok((data, file_name, content_type))
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

pub fn extract_file_info_from_url(url: &str) -> Result<(String, String)> {
    let url_path = url
        .split('?')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid URL format"))?;

    let filename = url_path
        .split('/')
        .next_back()
        .ok_or_else(|| anyhow::anyhow!("Could not extract filename from URL"))?
        .to_string();

    let filename = urlencoding::decode(&filename)
        .unwrap_or_else(|_| std::borrow::Cow::Borrowed(&filename))
        .to_string();

    let content_type = mime_guess::from_path(&filename)
        .first_or_octet_stream()
        .to_string();

    Ok((filename, content_type))
}
