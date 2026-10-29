// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::{
    app_chirho, cas_chirho, identity_chirho, model_chirho, store_chirho, tenant_chirho,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct HttpResponseChirho {
    status_chirho: u16,
    body_chirho: Vec<u8>,
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("cairn-ha1-{label_chirho}-{now_chirho}-{n_chirho}"))
}

fn unused_port_chirho() -> u16 {
    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener_chirho.local_addr().unwrap().port()
}

fn http_request_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    body_chirho: &[u8],
) -> HttpResponseChirho {
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho).unwrap();
    let request_chirho = format!(
        "{method_chirho} {path_chirho} HTTP/1.1\r\nhost: {addr_chirho}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body_chirho.len()
    );
    stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
    stream_chirho.write_all(body_chirho).unwrap();
    let mut response_chirho = Vec::new();
    stream_chirho.read_to_end(&mut response_chirho).unwrap();
    let header_end_chirho = response_chirho
        .windows(4)
        .position(|window_chirho| window_chirho == b"\r\n\r\n")
        .unwrap();
    let header_text_chirho = String::from_utf8_lossy(&response_chirho[..header_end_chirho]);
    let status_chirho = header_text_chirho
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    HttpResponseChirho {
        status_chirho,
        body_chirho: response_chirho[header_end_chirho + 4..].to_vec(),
    }
}

fn wait_for_health_chirho(addr_chirho: &str) {
    for _attempt_chirho in 0..100 {
        if let Ok(mut stream_chirho) = std::net::TcpStream::connect(addr_chirho) {
            let request_chirho = format!(
                "GET /healthz-chirho HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\n\r\n"
            );
            if stream_chirho.write_all(request_chirho.as_bytes()).is_ok() {
                let mut response_chirho = String::new();
                if stream_chirho.read_to_string(&mut response_chirho).is_ok()
                    && response_chirho.contains("200 OK")
                {
                    return;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("serve_chirho did not become healthy at {addr_chirho}");
}

fn deploy_write_app_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
    input_mode_chirho: app_chirho::AppInputModeChirho,
) {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let wasm_hash_chirho = cas_chirho::add_chirho(
        root_chirho,
        include_str!("../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    )
    .unwrap();
    let node_chirho = model_chirho::NodeDefChirho {
        name_chirho: "ha1_write_node_chirho".to_string(),
        impl_wasm_chirho: wasm_hash_chirho,
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![model_chirho::CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "ha1-write-guard-chirho".to_string(),
        }],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    let dag_chirho = model_chirho::DagChirho {
        nodes_chirho: vec![node_hash_chirho],
        edges_chirho: Vec::new(),
    };
    let dag_hash_chirho = store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    app_chirho::deploy_app_chirho(root_chirho, app_name_chirho, dag_hash_chirho, &owner_chirho)
        .unwrap();
    app_chirho::set_app_input_policy_chirho(
        root_chirho,
        app_name_chirho,
        None,
        &owner_chirho,
        input_mode_chirho,
    )
    .unwrap();
}

fn start_server_chirho(
    root_chirho: PathBuf,
) -> (
    tokio::runtime::Runtime,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    String,
) {
    let port_chirho = unused_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let server_chirho = runtime_chirho.spawn(async move {
        cairn_serve_runtime_chirho::serve_quiet_chirho(&root_chirho, port_chirho, 8, String::new())
            .await
    });
    wait_for_health_chirho(&addr_chirho);
    (runtime_chirho, server_chirho, addr_chirho)
}

#[test]
fn platform_root_write_store_app_route_fails_before_private_input_chirho() {
    let root_chirho = temp_root_chirho("platform-write");
    deploy_write_app_chirho(
        &root_chirho,
        "ha1write-chirho",
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "ha1-private-subject-chirho".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    );
    let (runtime_chirho, server_chirho, addr_chirho) = start_server_chirho(root_chirho.clone());
    runtime_chirho.block_on(async {
        let response_chirho = http_request_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/ha1write-chirho",
            b"private body should not persist",
        );
        assert_eq!(response_chirho.status_chirho, 403);
        // The tenant-root gate's own fixed identity; the operator detail stays out of the body.
        let body_chirho = String::from_utf8(response_chirho.body_chirho).unwrap();
        assert_eq!(body_chirho, "error: app-write-not-available-chirho\n");
        server_chirho.abort();
    });
    assert!(!root_chirho
        .join("privacy-blob-records-chirho.jsonl")
        .exists());
    assert!(!root_chirho.join("versioned-chirho.redb").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn tenant_root_write_store_app_route_still_runs_chirho() {
    let platform_root_chirho = temp_root_chirho("tenant-write-platform");
    let tenant_root_chirho = tenant_chirho::root_for_tenant_chirho(
        &platform_root_chirho,
        &tenant_chirho::TenantIdChirho::TenantChirho("ha1-write-tenant-chirho".to_string()),
    )
    .unwrap();
    deploy_write_app_chirho(
        &tenant_root_chirho,
        "ha1write-chirho",
        app_chirho::AppInputModeChirho::PlainChirho,
    );
    let (runtime_chirho, server_chirho, addr_chirho) =
        start_server_chirho(tenant_root_chirho.clone());
    runtime_chirho.block_on(async {
        let response_chirho = http_request_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/ha1write-chirho",
            b"hello",
        );
        assert_eq!(response_chirho.status_chirho, 200);
        assert_eq!(response_chirho.body_chirho, b"hello");
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&platform_root_chirho);
}

#[test]
fn platform_root_write_store_invoke_fails_before_private_input_chirho() {
    let root_chirho = temp_root_chirho("platform-invoke");
    deploy_write_app_chirho(
        &root_chirho,
        "ha1invoke-chirho",
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "ha1-invoke-private-subject-chirho".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    );
    let (runtime_chirho, server_chirho, addr_chirho) = start_server_chirho(root_chirho.clone());
    runtime_chirho.block_on(async {
        let response_chirho = http_request_chirho(
            &addr_chirho,
            "POST",
            "/invoke-chirho",
            br#"{"target_chirho":"ha1invoke-chirho","payload_chirho":"private invoke body"}"#,
        );
        // The same gate and status as the app road (403, no longer 400), answered as JSON because the
        // invoke transport speaks JSON; the operator detail stays out of the body.
        assert_eq!(response_chirho.status_chirho, 403);
        let body_chirho = String::from_utf8(response_chirho.body_chirho).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body_chirho).unwrap(),
            serde_json::json!({ "ok_chirho": false, "error_chirho": "app-write-not-available-chirho" })
        );
        server_chirho.abort();
    });
    assert!(!root_chirho
        .join("privacy-blob-records-chirho.jsonl")
        .exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn platform_root_write_store_ssr_fails_before_private_input_chirho() {
    let root_chirho = temp_root_chirho("platform-ssr");
    deploy_write_app_chirho(
        &root_chirho,
        "ha1ssr-chirho",
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "ha1-ssr-private-subject-chirho".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    );
    let (runtime_chirho, server_chirho, addr_chirho) = start_server_chirho(root_chirho.clone());
    runtime_chirho.block_on(async {
        let response_chirho =
            http_request_chirho(&addr_chirho, "GET", "/ssr-chirho/ha1ssr-chirho", b"");
        assert_eq!(response_chirho.status_chirho, 403);
        // The tenant-root gate's own fixed identity; the operator detail stays out of the body.
        let body_chirho = String::from_utf8(response_chirho.body_chirho).unwrap();
        assert_eq!(body_chirho, "error: app-write-not-available-chirho\n");
        server_chirho.abort();
    });
    assert!(!root_chirho
        .join("privacy-blob-records-chirho.jsonl")
        .exists());
    assert!(!root_chirho.join("versioned-chirho.redb").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn tenant_root_write_store_ssr_still_runs_chirho() {
    let platform_root_chirho = temp_root_chirho("tenant-ssr-platform");
    let tenant_root_chirho = tenant_chirho::root_for_tenant_chirho(
        &platform_root_chirho,
        &tenant_chirho::TenantIdChirho::TenantChirho("ha1-ssr-tenant-chirho".to_string()),
    )
    .unwrap();
    deploy_write_app_chirho(
        &tenant_root_chirho,
        "ha1ssr-chirho",
        app_chirho::AppInputModeChirho::PlainChirho,
    );
    let (runtime_chirho, server_chirho, addr_chirho) =
        start_server_chirho(tenant_root_chirho.clone());
    runtime_chirho.block_on(async {
        let response_chirho =
            http_request_chirho(&addr_chirho, "GET", "/ssr-chirho/ha1ssr-chirho", b"");
        assert_eq!(response_chirho.status_chirho, 200);
        let body_chirho = String::from_utf8(response_chirho.body_chirho).unwrap();
        assert!(body_chirho.starts_with("<!doctype html>"));
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&platform_root_chirho);
}
