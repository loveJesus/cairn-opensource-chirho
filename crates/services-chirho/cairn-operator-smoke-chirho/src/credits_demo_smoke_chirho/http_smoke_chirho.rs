// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Raw HTTP helpers and SSR balance parsing for the credits-demo served arc.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct HttpSmokeResponseChirho {
    pub status_chirho: u16,
    pub headers_chirho: BTreeMap<String, String>,
    pub body_chirho: Vec<u8>,
}

impl HttpSmokeResponseChirho {
    pub fn body_text_chirho(&self) -> String {
        String::from_utf8_lossy(&self.body_chirho).to_string()
    }
}

pub fn try_http_get_chirho(
    addr_chirho: &str,
    path_chirho: &str,
) -> Result<HttpSmokeResponseChirho> {
    try_http_request_chirho(addr_chirho, "GET", path_chirho, &[], &[])
}

pub fn try_http_request_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> Result<HttpSmokeResponseChirho> {
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho)
        .with_context(|| format!("connect to {addr_chirho}"))?;
    stream_chirho.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut request_chirho = format!(
        "{method_chirho} {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\n"
    );
    for (name_chirho, value_chirho) in headers_chirho {
        request_chirho.push_str(name_chirho);
        request_chirho.push_str(": ");
        request_chirho.push_str(value_chirho);
        request_chirho.push_str("\r\n");
    }
    if !body_chirho.is_empty() {
        request_chirho.push_str(&format!("content-length: {}\r\n", body_chirho.len()));
    }
    request_chirho.push_str("\r\n");
    stream_chirho.write_all(request_chirho.as_bytes())?;
    stream_chirho.write_all(body_chirho)?;
    let mut response_chirho = Vec::new();
    stream_chirho.read_to_end(&mut response_chirho)?;
    let header_end_chirho = response_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("missing HTTP headers"))?;
    let header_text_chirho = String::from_utf8_lossy(&response_chirho[..header_end_chirho]);
    let mut lines_chirho = header_text_chirho.lines();
    let status_chirho = lines_chirho
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status line"))?
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status code"))?
        .parse::<u16>()?;
    let mut headers_map_chirho = BTreeMap::new();
    for line_chirho in lines_chirho {
        if let Some((name_chirho, value_chirho)) = line_chirho.split_once(':') {
            headers_map_chirho.insert(
                name_chirho.trim().to_ascii_lowercase(),
                value_chirho.trim().to_string(),
            );
        }
    }
    Ok(HttpSmokeResponseChirho {
        status_chirho,
        headers_chirho: headers_map_chirho,
        body_chirho: response_chirho[header_end_chirho + 4..].to_vec(),
    })
}

pub fn wait_for_serve_health_chirho(addr_chirho: &str) -> Result<()> {
    for _attempt_chirho in 0..200 {
        if let Ok(response_chirho) = try_http_get_chirho(addr_chirho, "/healthz-chirho") {
            if response_chirho.status_chirho == 200 {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    bail!("configured host did not become healthy at {addr_chirho}");
}

pub fn unused_local_port_chirho() -> Result<u16> {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener_chirho.local_addr()?.port())
}

/// Parse the integer balance the SSR balance page renders in `class="balance-chirho"><strong>N</strong>`.
pub fn parse_ssr_balance_chirho(body_chirho: &str) -> Option<u64> {
    let anchor_chirho = body_chirho.find("class=\"balance-chirho\"")?;
    let tail_chirho = &body_chirho[anchor_chirho..];
    let strong_chirho = tail_chirho.find("<strong>")? + "<strong>".len();
    let end_chirho = tail_chirho[strong_chirho..].find("</strong>")?;
    tail_chirho[strong_chirho..strong_chirho + end_chirho]
        .trim()
        .parse::<u64>()
        .ok()
}

/// Parse the projection source seq the SSR staleness line renders (`source seq N`).
pub fn parse_ssr_source_seq_chirho(body_chirho: &str) -> Option<u64> {
    let anchor_chirho = body_chirho.find("source seq ")? + "source seq ".len();
    let tail_chirho = &body_chirho[anchor_chirho..];
    let digits_chirho: String = tail_chirho
        .chars()
        .take_while(|character_chirho| character_chirho.is_ascii_digit())
        .collect();
    digits_chirho.parse::<u64>().ok()
}

/// Parse one bounded `data-<name>="value"` attribute from the SSR body (#6071).
pub fn parse_data_attribute_chirho(body_chirho: &str, name_chirho: &str) -> Option<String> {
    let needle_chirho = format!("data-{name_chirho}=\"");
    let start_chirho = body_chirho.find(&needle_chirho)? + needle_chirho.len();
    let tail_chirho = &body_chirho[start_chirho..];
    let end_chirho = tail_chirho.find('"')?;
    Some(tail_chirho[..end_chirho].to_string())
}

/// True when the SSR staleness verdict is the viewer-scoped fresh marker.
pub fn ssr_is_fresh_chirho(body_chirho: &str) -> bool {
    body_chirho.contains("data-projection-verdict-chirho=\"fresh-chirho\"")
}

/// Count the balance rows rendered in the body (each viewer-scoped balance row carries one
/// `class="balance-chirho"`). A missing-viewer refusal renders none.
pub fn balance_rows_in_body_chirho(body_chirho: &str) -> usize {
    body_chirho.matches("class=\"balance-chirho\"").count()
}

/// Count occurrences of a specific member principal string in the body (settlement leakage guard).
pub fn principal_occurrences_chirho(body_chirho: &str, principal_chirho: &str) -> usize {
    body_chirho.matches(principal_chirho).count()
}
