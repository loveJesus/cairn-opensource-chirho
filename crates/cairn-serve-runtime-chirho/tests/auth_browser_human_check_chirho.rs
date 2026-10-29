// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::identity_chirho;
use cairn_serve_runtime_chirho::{serve_quiet_chirho, serve_quiet_with_registration_token_chirho};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
};

#[test]
fn json_human_check_route_returns_verifiable_register_fields_chirho() {
    let root_chirho = temp_root_chirho("json-human-check");
    let registration_token_chirho = "browser-registration-token-chirho";
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_with_registration_token_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                String::new(),
                registration_token_chirho.to_string(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let register_page_chirho = http_get_chirho(&addr_chirho, "/auth-chirho/register-chirho");
        assert_eq!(register_page_chirho.status_chirho, 200);
        let register_html_chirho = String::from_utf8(register_page_chirho.body_chirho).unwrap();
        assert!(register_html_chirho.contains("name=\"registration_token_chirho\""));
        assert!(!register_html_chirho.contains(registration_token_chirho));
        assert!(!register_html_chirho
            .contains("<form method=\"post\" action=\"/auth-chirho/login-chirho\""));
        assert!(register_html_chirho.contains("href=\"/auth-chirho/login-chirho\""));

        let login_page_chirho = http_get_chirho(&addr_chirho, "/auth-chirho/login-chirho");
        assert_eq!(login_page_chirho.status_chirho, 200);
        let login_html_chirho = String::from_utf8(login_page_chirho.body_chirho).unwrap();
        assert!(login_html_chirho
            .contains("<form method=\"post\" action=\"/auth-chirho/login-chirho\""));
        assert!(login_html_chirho.contains("href=\"/auth-chirho/register-chirho\""));
        assert!(!login_html_chirho.contains("human_check_token_chirho"));
        assert!(!login_html_chirho.contains("registration_token_chirho"));

        let response_chirho = http_get_chirho(&addr_chirho, "/auth-chirho/human-check-chirho");
        assert_eq!(response_chirho.status_chirho, 200);
        assert!(response_chirho
            .headers_chirho
            .iter()
            .any(|header_chirho| header_chirho
                .to_ascii_lowercase()
                .starts_with("content-type: application/json")));
        assert_json_human_check_chirho(&root_chirho, &response_chirho.body_chirho);

        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn disabled_registration_gets_refuse_before_signing_key_creation_chirho() {
    let root_chirho = temp_root_chirho("disabled-registration-get");
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let login_chirho = http_get_chirho(&addr_chirho, "/auth-chirho/login-chirho");
        assert_eq!(login_chirho.status_chirho, 200);
        assert!(String::from_utf8_lossy(&login_chirho.body_chirho)
            .contains("<form method=\"post\" action=\"/auth-chirho/login-chirho\""));
        for path_chirho in [
            "/auth-chirho/register-chirho",
            "/auth-chirho/human-check-chirho",
        ] {
            let response_chirho = http_get_chirho(&addr_chirho, path_chirho);
            assert_eq!(response_chirho.status_chirho, 503);
            assert!(String::from_utf8_lossy(&response_chirho.body_chirho)
                .contains("public registration is disabled"));
        }
        assert!(!root_chirho.join("signing-key-chirho.bin").exists());
        assert!(!root_chirho.join("pubkey-chirho.hex").exists());

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn assert_json_human_check_chirho(root_chirho: &std::path::Path, body_chirho: &[u8]) {
    let json_chirho: serde_json::Value = serde_json::from_slice(body_chirho).unwrap();
    assert_eq!(json_chirho["ok_chirho"], true);
    let question_chirho = json_chirho["question_chirho"].as_str().unwrap();
    let token_chirho = json_chirho["human_check_token_chirho"].as_str().unwrap();
    assert!(!question_chirho.trim().is_empty());
    assert!(!token_chirho.trim().is_empty());
    assert!(json_chirho.get("credential_chirho").is_none());
    assert!(json_chirho.get("auth-session-chirho").is_none());

    let answer_chirho = (0..=40)
        .map(|answer_chirho| answer_chirho.to_string())
        .find(|answer_chirho| {
            identity_chirho::verify_auth_human_check_chirho(
                root_chirho,
                token_chirho,
                answer_chirho,
            )
            .is_ok()
        })
        .expect("issued JSON challenge should be solvable");
    identity_chirho::verify_auth_human_check_chirho(root_chirho, token_chirho, &answer_chirho)
        .unwrap();
}

fn temp_root_chirho(name_chirho: &str) -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-auth-browser-{name_chirho}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn unused_local_port_chirho() -> u16 {
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    listener_chirho.local_addr().unwrap().port()
}

fn wait_for_serve_health_chirho(addr_chirho: &str) {
    for _attempt_chirho in 0..100 {
        if let Ok(response_chirho) = try_http_get_chirho(addr_chirho, "/healthz-chirho") {
            if response_chirho.status_chirho == 200 {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("serve did not become healthy at {addr_chirho}");
}

fn http_get_chirho(addr_chirho: &str, path_chirho: &str) -> HttpResponseChirho {
    try_http_get_chirho(addr_chirho, path_chirho).unwrap()
}

fn try_http_get_chirho(
    addr_chirho: &str,
    path_chirho: &str,
) -> std::io::Result<HttpResponseChirho> {
    let mut stream_chirho = TcpStream::connect(addr_chirho)?;
    write!(
        stream_chirho,
        "GET {path_chirho} HTTP/1.1\r\nHost: {addr_chirho}\r\nConnection: close\r\n\r\n"
    )?;
    stream_chirho.flush()?;
    let mut bytes_chirho = Vec::new();
    stream_chirho.read_to_end(&mut bytes_chirho)?;
    Ok(parse_http_response_chirho(&bytes_chirho))
}

fn parse_http_response_chirho(bytes_chirho: &[u8]) -> HttpResponseChirho {
    let text_chirho = String::from_utf8_lossy(bytes_chirho);
    let (head_chirho, body_chirho) = text_chirho
        .split_once("\r\n\r\n")
        .expect("HTTP response should have headers");
    let mut lines_chirho = head_chirho.lines();
    let status_line_chirho = lines_chirho.next().unwrap();
    let status_chirho = status_line_chirho
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    HttpResponseChirho {
        status_chirho,
        headers_chirho: lines_chirho.map(str::to_string).collect(),
        body_chirho: body_chirho.as_bytes().to_vec(),
    }
}

struct HttpResponseChirho {
    status_chirho: u16,
    headers_chirho: Vec<String>,
    body_chirho: Vec<u8>,
}
