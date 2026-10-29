// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

static NEVER_STOP_HTTP_READ_CHIRHO: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(super) fn read_mock_http_request_chirho(stream_chirho: &mut std::net::TcpStream) -> String {
    read_mock_http_request_from_chirho(stream_chirho, &NEVER_STOP_HTTP_READ_CHIRHO)
}

fn read_mock_http_request_from_chirho<ReaderChirho: std::io::Read>(
    reader_chirho: &mut ReaderChirho,
    stop_chirho: &std::sync::atomic::AtomicBool,
) -> String {
    let mut bytes_chirho = Vec::new();
    loop {
        let mut buf_chirho = [0_u8; 1024];
        match reader_chirho.read(&mut buf_chirho) {
            Ok(0) => {
                if stop_chirho.load(std::sync::atomic::Ordering::Acquire) {
                    return String::new();
                }
                assert!(
                    bytes_chirho.is_empty() || http_request_complete_chirho(&bytes_chirho),
                    "mock HTTP peer closed before the complete request arrived"
                );
                break;
            }
            Ok(n_chirho) => {
                bytes_chirho.extend_from_slice(&buf_chirho[..n_chirho]);
                if http_request_complete_chirho(&bytes_chirho) {
                    break;
                }
            }
            Err(error_chirho)
                if matches!(
                    error_chirho.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                if stop_chirho.load(std::sync::atomic::Ordering::Acquire) {
                    return String::new();
                }
            }
            Err(error_chirho) => panic!("mock HTTP request read failed: {error_chirho}"),
        }
    }
    String::from_utf8_lossy(&bytes_chirho).to_string()
}

#[test]
fn mock_http_request_retries_interrupt_timeout_and_would_block_chirho() {
    struct FragmentedReaderChirho {
        step_chirho: u8,
    }

    impl std::io::Read for FragmentedReaderChirho {
        fn read(&mut self, buffer_chirho: &mut [u8]) -> std::io::Result<usize> {
            let fragment_chirho = match self.step_chirho {
                0 => {
                    self.step_chirho += 1;
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
                }
                1 => b"POST / HTTP/1.1\r\ncontent-length: 4\r\n\r\nte".as_slice(),
                2 => {
                    self.step_chirho += 1;
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
                }
                3 => {
                    self.step_chirho += 1;
                    return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
                }
                4 => b"st".as_slice(),
                _ => return Ok(0),
            };
            self.step_chirho += 1;
            buffer_chirho[..fragment_chirho.len()].copy_from_slice(fragment_chirho);
            Ok(fragment_chirho.len())
        }
    }

    let stop_chirho = std::sync::atomic::AtomicBool::new(false);
    let mut reader_chirho = FragmentedReaderChirho { step_chirho: 0 };
    assert_eq!(
        read_mock_http_request_from_chirho(&mut reader_chirho, &stop_chirho),
        "POST / HTTP/1.1\r\ncontent-length: 4\r\n\r\ntest"
    );
}

pub(super) fn write_mock_http_response_chirho(
    stream_chirho: &mut std::net::TcpStream,
    content_type_chirho: &str,
    body_chirho: &[u8],
) {
    use std::io::Write;

    let response_chirho = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type_chirho}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body_chirho.len()
    );
    stream_chirho.write_all(response_chirho.as_bytes()).unwrap();
    stream_chirho.write_all(body_chirho).unwrap();
}

pub(super) fn accept_with_timeout_chirho(
    listener_chirho: &std::net::TcpListener,
    timeout_chirho: std::time::Duration,
) -> std::net::TcpStream {
    listener_chirho.set_nonblocking(true).unwrap();
    let start_chirho = std::time::Instant::now();
    loop {
        match listener_chirho.accept() {
            Ok((stream_chirho, _)) => {
                stream_chirho.set_nonblocking(false).unwrap();
                stream_chirho
                    .set_read_timeout(Some(timeout_chirho))
                    .unwrap();
                stream_chirho
                    .set_write_timeout(Some(timeout_chirho))
                    .unwrap();
                return stream_chirho;
            }
            Err(ref e_chirho) if e_chirho.kind() == std::io::ErrorKind::WouldBlock => {
                if start_chirho.elapsed() > timeout_chirho {
                    panic!("TcpListener accept timed out after {:?}", timeout_chirho);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e_chirho) => {
                panic!("TcpListener accept failed: {}", e_chirho);
            }
        }
    }
}

pub(super) fn node_available_for_smoke_chirho(label_chirho: &str) -> bool {
    let Ok(version_chirho) = std::process::Command::new("node").arg("--version").output() else {
        eprintln!("skipping {label_chirho}: node not found");
        return false;
    };
    if !version_chirho.status.success() {
        eprintln!("skipping {label_chirho}: node --version failed");
        return false;
    }
    true
}

pub(super) fn runtime_package_host_file_url_chirho() -> String {
    let host_path_chirho = workspace_root_for_test_chirho()
        .join("client-chirho/runtime-package-host-chirho.js")
        .canonicalize()
        .unwrap();
    format!("file://{}", host_path_chirho.display())
}

fn workspace_root_for_test_chirho() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .to_path_buf()
}

pub(super) struct HttpSmokeResponseChirho {
    pub(super) status_chirho: u16,
    pub(super) headers_chirho: std::collections::BTreeMap<String, String>,
    pub(super) body_chirho: Vec<u8>,
}

pub(super) struct WebSocketSmokeUpgradeChirho {
    pub(super) status_chirho: u16,
    pub(super) body_chirho: Vec<u8>,
}

pub(super) fn try_http_get_for_smoke_chirho(
    addr_chirho: &str,
    path_chirho: &str,
) -> std::io::Result<HttpSmokeResponseChirho> {
    try_http_request_for_smoke_chirho(addr_chirho, "GET", path_chirho, &[], &[])
}

pub(super) fn try_http_request_for_smoke_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> std::io::Result<HttpSmokeResponseChirho> {
    use std::io::Write;

    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho)?;
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
    let response_chirho = read_http_response_for_smoke_chirho(&mut stream_chirho)?;
    let header_end_chirho = response_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP headers")
        })?;
    let header_text_chirho = String::from_utf8_lossy(&response_chirho[..header_end_chirho]);
    let mut lines_chirho = header_text_chirho.lines();
    let status_line_chirho = lines_chirho.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP status line")
    })?;
    let status_chirho = status_line_chirho
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP status code")
        })?
        .parse::<u16>()
        .map_err(|e_chirho| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad HTTP status code: {e_chirho}"),
            )
        })?;
    let mut headers_chirho = std::collections::BTreeMap::new();
    for line_chirho in lines_chirho {
        if let Some((name_chirho, value_chirho)) = line_chirho.split_once(':') {
            headers_chirho.insert(
                name_chirho.trim().to_ascii_lowercase(),
                value_chirho.trim().to_string(),
            );
        }
    }
    Ok(HttpSmokeResponseChirho {
        status_chirho,
        headers_chirho,
        body_chirho: response_chirho[header_end_chirho + 4..].to_vec(),
    })
}

fn read_http_response_for_smoke_chirho<ReaderChirho: std::io::Read>(
    reader_chirho: &mut ReaderChirho,
) -> std::io::Result<Vec<u8>> {
    let mut response_chirho = Vec::new();
    loop {
        let mut buffer_chirho = [0_u8; 4096];
        match reader_chirho.read(&mut buffer_chirho) {
            Ok(0) => return Ok(response_chirho),
            Ok(read_chirho) => response_chirho.extend_from_slice(&buffer_chirho[..read_chirho]),
            Err(error_chirho)
                if error_chirho.kind() == std::io::ErrorKind::ConnectionReset
                    && http_response_complete_chirho(&response_chirho) =>
            {
                // An early authorization refusal may close while unread request-body bytes remain,
                // which macOS can report as RST after the complete response has already arrived.
                return Ok(response_chirho);
            }
            Err(error_chirho) => return Err(error_chirho),
        }
    }
}

fn http_response_complete_chirho(bytes_chirho: &[u8]) -> bool {
    let Some(header_end_chirho) = bytes_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
    else {
        return false;
    };
    let header_chirho = String::from_utf8_lossy(&bytes_chirho[..header_end_chirho]);
    let Some(content_length_chirho) = header_chirho.lines().find_map(|line_chirho| {
        let (name_chirho, value_chirho) = line_chirho.split_once(':')?;
        name_chirho
            .eq_ignore_ascii_case("content-length")
            .then(|| value_chirho.trim().parse::<usize>().ok())
            .flatten()
    }) else {
        return false;
    };
    bytes_chirho.len() >= header_end_chirho + 4 + content_length_chirho
}

#[test]
fn complete_http_response_survives_reset_but_partial_response_fails_chirho() {
    struct ResetAfterBytesReaderChirho {
        bytes_chirho: Vec<u8>,
        read_chirho: bool,
    }

    impl std::io::Read for ResetAfterBytesReaderChirho {
        fn read(&mut self, buffer_chirho: &mut [u8]) -> std::io::Result<usize> {
            if self.read_chirho {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
            }
            self.read_chirho = true;
            buffer_chirho[..self.bytes_chirho.len()].copy_from_slice(&self.bytes_chirho);
            Ok(self.bytes_chirho.len())
        }
    }

    let complete_chirho =
        b"HTTP/1.1 403 Forbidden\r\ncontent-length: 9\r\nconnection: close\r\n\r\nforbidden";
    let mut complete_reader_chirho = ResetAfterBytesReaderChirho {
        bytes_chirho: complete_chirho.to_vec(),
        read_chirho: false,
    };
    assert_eq!(
        read_http_response_for_smoke_chirho(&mut complete_reader_chirho).unwrap(),
        complete_chirho
    );

    let mut partial_reader_chirho = ResetAfterBytesReaderChirho {
        bytes_chirho:
            b"HTTP/1.1 403 Forbidden\r\ncontent-length: 9\r\nconnection: close\r\n\r\nfor".to_vec(),
        read_chirho: false,
    };
    assert_eq!(
        read_http_response_for_smoke_chirho(&mut partial_reader_chirho)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::ConnectionReset
    );
}

pub(super) fn http_get_for_smoke_chirho(
    addr_chirho: &str,
    path_chirho: &str,
) -> HttpSmokeResponseChirho {
    try_http_get_for_smoke_chirho(addr_chirho, path_chirho).unwrap()
}

pub(super) fn http_request_for_smoke_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> HttpSmokeResponseChirho {
    try_http_request_for_smoke_chirho(
        addr_chirho,
        method_chirho,
        path_chirho,
        headers_chirho,
        body_chirho,
    )
    .unwrap()
}

pub(super) fn http_body_text_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    String::from_utf8_lossy(&response_chirho.body_chirho).to_string()
}

pub(super) fn websocket_upgrade_for_smoke_chirho(
    addr_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
) -> WebSocketSmokeUpgradeChirho {
    try_websocket_upgrade_for_smoke_chirho(addr_chirho, path_chirho, headers_chirho).unwrap()
}

pub(super) fn try_websocket_upgrade_for_smoke_chirho(
    addr_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
) -> std::io::Result<WebSocketSmokeUpgradeChirho> {
    use std::io::{Read, Write};

    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho)?;
    stream_chirho.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    stream_chirho.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    let mut request_chirho = format!(
        "GET {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: Upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    );
    for (name_chirho, value_chirho) in headers_chirho {
        request_chirho.push_str(name_chirho);
        request_chirho.push_str(": ");
        request_chirho.push_str(value_chirho);
        request_chirho.push_str("\r\n");
    }
    request_chirho.push_str("\r\n");
    stream_chirho.write_all(request_chirho.as_bytes())?;

    let mut header_bytes_chirho = Vec::new();
    loop {
        let mut byte_chirho = [0_u8; 1];
        stream_chirho.read_exact(&mut byte_chirho)?;
        header_bytes_chirho.push(byte_chirho[0]);
        if header_bytes_chirho.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header_text_chirho = String::from_utf8_lossy(&header_bytes_chirho);
    let mut lines_chirho = header_text_chirho.lines();
    let status_line_chirho = lines_chirho.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing websocket status line",
        )
    })?;
    let status_chirho = status_line_chirho
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "missing websocket status")
        })?
        .parse::<u16>()
        .map_err(|e_chirho| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad websocket status: {e_chirho}"),
            )
        })?;
    let mut parsed_headers_chirho = std::collections::BTreeMap::new();
    for line_chirho in lines_chirho {
        if let Some((name_chirho, value_chirho)) = line_chirho.split_once(':') {
            parsed_headers_chirho.insert(
                name_chirho.trim().to_ascii_lowercase(),
                value_chirho.trim().to_string(),
            );
        }
    }
    let mut body_chirho = Vec::new();
    if status_chirho != 101 {
        if let Some(length_chirho) = parsed_headers_chirho
            .get("content-length")
            .and_then(|value_chirho| value_chirho.parse::<usize>().ok())
        {
            body_chirho.resize(length_chirho, 0);
            stream_chirho.read_exact(&mut body_chirho)?;
        }
    }
    Ok(WebSocketSmokeUpgradeChirho {
        status_chirho,
        body_chirho,
    })
}

pub(super) fn wait_for_serve_health_chirho(addr_chirho: &str) {
    for _attempt_chirho in 0..100 {
        if let Ok(response_chirho) = try_http_get_for_smoke_chirho(addr_chirho, "/healthz-chirho") {
            if response_chirho.status_chirho == 200 {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("serve_chirho did not become healthy at {addr_chirho}");
}

pub(super) fn unused_local_port_chirho() -> u16 {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener_chirho.local_addr().unwrap().port()
}

pub(super) fn http_request_complete_chirho(bytes_chirho: &[u8]) -> bool {
    let Some(header_end_chirho) = bytes_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
    else {
        return false;
    };
    let header_chirho = String::from_utf8_lossy(&bytes_chirho[..header_end_chirho]);
    let content_length_chirho = header_chirho.lines().find_map(|line_chirho| {
        let (name_chirho, value_chirho) = line_chirho.split_once(':')?;
        if name_chirho.eq_ignore_ascii_case("content-length") {
            value_chirho.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    let body_start_chirho = header_end_chirho + 4;
    bytes_chirho.len() >= body_start_chirho + content_length_chirho.unwrap_or(0)
}
