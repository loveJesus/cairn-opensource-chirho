// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Local HTTP helpers for the contact example smoke.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use super::types_chirho::HttpSmokeResponseChirho;

pub(super) fn try_http_get_for_smoke_chirho(
    addr_chirho: &str,
    path_chirho: &str,
) -> Result<HttpSmokeResponseChirho> {
    try_http_request_for_smoke_chirho(addr_chirho, "GET", path_chirho, &[], &[])
}

pub(super) fn try_http_request_for_smoke_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> Result<HttpSmokeResponseChirho> {
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho)
        .with_context(|| format!("connect to {addr_chirho}"))?;
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
    let status_line_chirho = lines_chirho
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP status line"))?;
    let status_chirho = status_line_chirho
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

pub(super) fn http_body_text_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    String::from_utf8_lossy(&response_chirho.body_chirho).to_string()
}

pub(super) fn wait_for_serve_health_chirho(addr_chirho: &str) -> Result<()> {
    for _attempt_chirho in 0..100 {
        if let Ok(response_chirho) = try_http_get_for_smoke_chirho(addr_chirho, "/healthz-chirho") {
            if response_chirho.status_chirho == 200 {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    bail!("serve_chirho did not become healthy at {addr_chirho}");
}

pub(super) fn unused_local_port_chirho() -> Result<u16> {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(listener_chirho.local_addr()?.port())
}
