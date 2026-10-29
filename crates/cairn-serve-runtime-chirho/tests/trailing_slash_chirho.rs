// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use cairn_serve_runtime_chirho::serve_quiet_chirho;
use std::collections::BTreeMap;

struct HttpResponseChirho {
    status_chirho: u16,
    headers_chirho: BTreeMap<String, String>,
}

#[test]
fn app_root_get_redirects_to_trailing_slash_chirho() {
    let root_chirho = temp_root_chirho("app-root-trailing-slash");
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_health_chirho(&addr_chirho);

        let redirect_chirho = http_request_chirho(&addr_chirho, "GET", "/app-chirho/pizzeria");
        assert_eq!(redirect_chirho.status_chirho, 308);
        assert_eq!(
            redirect_chirho
                .headers_chirho
                .get("location")
                .map(String::as_str),
            Some("/app-chirho/pizzeria/")
        );

        let slash_chirho = http_request_chirho(&addr_chirho, "GET", "/app-chirho/pizzeria/");
        assert_eq!(slash_chirho.status_chirho, 404);

        let post_chirho = http_request_chirho(&addr_chirho, "POST", "/app-chirho/pizzeria");
        assert_eq!(post_chirho.status_chirho, 404);

        server_chirho.abort();
    });
}

fn temp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    let unique_chirho = format!(
        "cairn-{label_chirho}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root_chirho = std::env::temp_dir().join(unique_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn unused_local_port_chirho() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_health_chirho(addr_chirho: &str) {
    for _ in 0..100 {
        if let Ok(response_chirho) = try_http_request_chirho(addr_chirho, "GET", "/healthz") {
            if response_chirho.status_chirho == 200 {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("server did not become healthy");
}

fn http_request_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
) -> HttpResponseChirho {
    try_http_request_chirho(addr_chirho, method_chirho, path_chirho).unwrap()
}

fn try_http_request_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
) -> std::io::Result<HttpResponseChirho> {
    use std::io::{Read, Write};

    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho)?;
    let request_chirho =
        format!("{method_chirho} {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\n\r\n");
    stream_chirho.write_all(request_chirho.as_bytes())?;
    let mut response_chirho = Vec::new();
    stream_chirho.read_to_end(&mut response_chirho)?;
    let header_end_chirho = response_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing headers"))?;
    let header_text_chirho = String::from_utf8_lossy(&response_chirho[..header_end_chirho]);
    let mut lines_chirho = header_text_chirho.lines();
    let status_line_chirho = lines_chirho
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing status"))?;
    let status_chirho = status_line_chirho
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing code"))?
        .parse::<u16>()
        .map_err(|e_chirho| std::io::Error::new(std::io::ErrorKind::InvalidData, e_chirho))?;
    let mut headers_chirho = BTreeMap::new();
    for line_chirho in lines_chirho {
        if let Some((name_chirho, value_chirho)) = line_chirho.split_once(':') {
            headers_chirho.insert(
                name_chirho.trim().to_ascii_lowercase(),
                value_chirho.trim().to_string(),
            );
        }
    }
    Ok(HttpResponseChirho {
        status_chirho,
        headers_chirho,
    })
}
