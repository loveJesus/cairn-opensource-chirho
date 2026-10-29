// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Dispatch tests, part A (moved verbatim from the old src/main.rs test mod).

use crate::credential_cli_chirho::{
    read_cli_private_credential_file_chirho, resolve_cli_optional_credential_chirho,
    resolve_cli_required_credential_chirho,
};
use crate::parse_helpers_chirho::{parse_dns_record_spec_chirho, review_source_evidence_chirho};
use crate::runtime_package_cli_chirho::{
    smoke_runtime_package_artifacts_chirho, RUNTIME_PACKAGE_SMOKE_EXECUTION_SCHEMA_CHIRHO,
    RUNTIME_PACKAGE_SMOKE_REPORT_SCHEMA_CHIRHO,
};
use cairn_chirho::model_chirho::{HashChirho, NodeDefChirho, PortChirho};
use cairn_chirho::runtime_profile_chirho;
use cairn_chirho::{cas_chirho, dag_author_chirho, dag_module_chirho, store_chirho};
use std::path::Path;

fn tmp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("cairn-main-{label_chirho}-{nanos_chirho}"))
}

#[test]
fn dns_record_cli_specs_reject_malformed_numeric_fields_chirho() {
    let record_chirho = parse_dns_record_spec_chirho("MX,@,mail.example,1800,10").unwrap();
    assert_eq!(record_chirho.type_chirho, "MX");
    assert_eq!(record_chirho.ttl_chirho, 1800);
    assert_eq!(record_chirho.priority_chirho, Some(10));

    assert!(parse_dns_record_spec_chirho("A,@,192.0.2.1,badttl").is_err());
    assert!(parse_dns_record_spec_chirho("MX,@,mail.example,1800,badpriority").is_err());
    assert!(parse_dns_record_spec_chirho("A,@,192.0.2.1,").is_err());
}

fn read_mock_http_request_chirho(stream_chirho: &mut std::net::TcpStream) -> String {
    use std::io::Read;
    let mut bytes_chirho = Vec::new();
    let mut buf = [0_u8; 1024];
    while let Ok(n) = stream_chirho.read(&mut buf) {
        if n == 0 {
            break;
        }
        bytes_chirho.extend_from_slice(&buf[..n]);
        if bytes_chirho.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&bytes_chirho).to_string()
}

fn write_mock_http_response_chirho(stream: &mut std::net::TcpStream, ct: &str, body: &[u8]) {
    use std::io::Write;
    let resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {ct}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream
        .write_all(resp.as_bytes())
        .and_then(|_| stream.write_all(body));
}

fn accept_with_timeout_chirho(
    listener: &std::net::TcpListener,
    t: std::time::Duration,
) -> std::net::TcpStream {
    let _ = listener.set_nonblocking(true);
    let start = std::time::Instant::now();
    while start.elapsed() < t {
        if let Ok((s, _)) = listener.accept() {
            let _ = s
                .set_nonblocking(false)
                .and_then(|_| s.set_read_timeout(Some(t)))
                .and_then(|_| s.set_write_timeout(Some(t)));
            return s;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("TcpListener accept timed out");
}

fn store_runtime_package_module_chirho(root_chirho: &Path) -> HashChirho {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let wasm_hash_chirho = cas_chirho::add_chirho(
        root_chirho,
        include_str!("../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    )
    .unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: "runtime_package_smoke_upcase_chirho".to_string(),
        impl_wasm_chirho: wasm_hash_chirho,
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: Vec::new(),
        effect_contract_set_chirho: None,
        fuel_limit_chirho: 1_000_000,
        max_output_bytes_chirho: cairn_chirho::model_chirho::DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
        max_memory_bytes_chirho: cairn_chirho::model_chirho::DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    let (_dag_chirho, dag_hash_chirho) = dag_author_chirho::build_dag_chirho(
        root_chirho,
        dag_author_chirho::DagBuildInputChirho {
            nodes_chirho: vec![node_hash_chirho.clone()],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let (_module_chirho, module_hash_chirho) = dag_module_chirho::build_dag_module_chirho(
        root_chirho,
        dag_module_chirho::DagModuleBuildInputChirho {
            name_chirho: "runtime_package_smoke_upcase_chirho".to_string(),
            dag_chirho: dag_hash_chirho,
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![dag_module_chirho::DagModuleBindingInputChirho {
                public_name_chirho: "request".to_string(),
                node_chirho: node_hash_chirho.clone(),
                node_port_chirho: "in".to_string(),
            }],
            output_bindings_chirho: vec![dag_module_chirho::DagModuleBindingInputChirho {
                public_name_chirho: "response".to_string(),
                node_chirho: node_hash_chirho,
                node_port_chirho: "out".to_string(),
            }],
            route_labels_chirho: Vec::new(),
            metadata_chirho: std::collections::BTreeMap::new(),
        },
    )
    .unwrap();
    module_hash_chirho
}

#[test]
fn runtime_package_smoke_cli_verifies_remote_artifacts_chirho() {
    let root_chirho = tmp_root_chirho("runtime-package-smoke-cli");
    let module_hash_chirho = store_runtime_package_module_chirho(&root_chirho);
    let (package_chirho, package_hash_chirho) =
        runtime_profile_chirho::build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
    let manifest_bytes_chirho = serde_json::to_vec(&package_chirho).unwrap();
    let executable_bytes_chirho =
        cas_chirho::get_chirho(&root_chirho, &package_chirho.executable_chirho).unwrap();

    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let server_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let manifest_for_thread_chirho = manifest_bytes_chirho.clone();
    let executable_for_thread_chirho = executable_bytes_chirho.clone();
    let server_thread_chirho = std::thread::spawn(move || {
        let mut manifest_stream_chirho =
            accept_with_timeout_chirho(&listener_chirho, std::time::Duration::from_secs(5));
        let manifest_request_chirho = read_mock_http_request_chirho(&mut manifest_stream_chirho);
        assert!(manifest_request_chirho.contains("/manifest-chirho"));
        write_mock_http_response_chirho(
            &mut manifest_stream_chirho,
            "application/json",
            &manifest_for_thread_chirho,
        );

        let mut executable_stream_chirho =
            accept_with_timeout_chirho(&listener_chirho, std::time::Duration::from_secs(5));
        let executable_request_chirho =
            read_mock_http_request_chirho(&mut executable_stream_chirho);
        assert!(executable_request_chirho.contains("/executable-chirho"));
        write_mock_http_response_chirho(
            &mut executable_stream_chirho,
            "application/wasm",
            &executable_for_thread_chirho,
        );
    });

    let report_chirho = smoke_runtime_package_artifacts_chirho(
        &root_chirho,
        &server_chirho,
        &package_hash_chirho,
        Some(b"hello, smoke"),
        Some(b"HELLO, SMOKE"),
    )
    .unwrap();
    assert_eq!(
        report_chirho.schema_chirho,
        RUNTIME_PACKAGE_SMOKE_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.package_chirho, package_hash_chirho);
    assert_eq!(
        report_chirho.executable_chirho,
        package_chirho.executable_chirho
    );
    assert_eq!(report_chirho.entry_chirho, package_chirho.entry_chirho);
    assert_eq!(report_chirho.entry_chirho, "upcase_chirho");
    assert_eq!(
        report_chirho.executable_bytes_chirho,
        executable_bytes_chirho.len()
    );
    assert_eq!(
        report_chirho.manifest_content_type_chirho,
        "application/json"
    );
    assert_eq!(
        report_chirho.executable_content_type_chirho,
        "application/wasm"
    );
    let execution_chirho = report_chirho.execution_chirho.as_ref().unwrap();
    assert_eq!(
        execution_chirho.schema_chirho,
        RUNTIME_PACKAGE_SMOKE_EXECUTION_SCHEMA_CHIRHO
    );
    assert_eq!(execution_chirho.entry_chirho, "upcase_chirho");
    assert_eq!(execution_chirho.input_bytes_chirho, b"hello, smoke".len());
    assert_eq!(
        execution_chirho.input_chirho,
        cas_chirho::hash_chirho(b"hello, smoke")
    );
    assert_eq!(execution_chirho.output_bytes_chirho, b"HELLO, SMOKE".len());
    assert_eq!(
        execution_chirho.output_chirho,
        cas_chirho::hash_chirho(b"HELLO, SMOKE")
    );
    assert_eq!(
        execution_chirho.expected_output_chirho,
        Some(cas_chirho::hash_chirho(b"HELLO, SMOKE"))
    );
    assert_eq!(execution_chirho.expected_output_matches_chirho, Some(true));
    let report_json_chirho = serde_json::to_value(&report_chirho).unwrap();
    assert_eq!(
        report_json_chirho["schema_chirho"],
        RUNTIME_PACKAGE_SMOKE_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_json_chirho["entry_chirho"], "upcase_chirho");
    assert_eq!(
        report_json_chirho["execution_chirho"]["schema_chirho"],
        RUNTIME_PACKAGE_SMOKE_EXECUTION_SCHEMA_CHIRHO
    );
    let report_json_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_json_text_chirho.contains("hello, smoke"));
    assert!(!report_json_text_chirho.contains("HELLO, SMOKE"));
    assert_eq!(
        report_json_chirho["manifest_url_chirho"],
        format!(
            "{server_chirho}/runtime-package-chirho/{}/manifest-chirho",
            package_hash_chirho.0
        )
    );
    assert_eq!(
        report_json_chirho["executable_url_chirho"],
        format!(
            "{server_chirho}/runtime-package-chirho/{}/executable-chirho",
            package_hash_chirho.0
        )
    );
    server_thread_chirho.join().unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn cli_credential_file_resolver_is_no_argv_compatible_chirho() {
    let root_chirho = tmp_root_chirho("credential-file");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let credential_path_chirho = root_chirho.join("credential-chirho.txt");
    std::fs::write(&credential_path_chirho, "file-secret-chirho\n").unwrap();

    let resolved_chirho =
        resolve_cli_optional_credential_chirho(None, Some(credential_path_chirho.clone()))
            .unwrap()
            .unwrap();
    assert_eq!(resolved_chirho, "file-secret-chirho");
    assert!(resolve_cli_optional_credential_chirho(
        Some("inline-secret-chirho".to_string()),
        Some(credential_path_chirho.clone()),
    )
    .unwrap_err()
    .to_string()
    .contains("cannot be used together"));
    assert!(resolve_cli_required_credential_chirho(None, None)
        .unwrap_err()
        .to_string()
        .contains("--credential or --credential-file is required"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn cli_private_credential_file_requires_mode_600_chirho() {
    let root_chirho = tmp_root_chirho("private-credential-file");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let credential_path_chirho = root_chirho.join("credential-chirho.txt");
    std::fs::write(&credential_path_chirho, "file-secret-chirho\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &credential_path_chirho,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            read_cli_private_credential_file_chirho(&credential_path_chirho)
                .unwrap_err()
                .to_string()
                .contains("must be mode 600")
        );
        std::fs::set_permissions(
            &credential_path_chirho,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let resolved_chirho = read_cli_private_credential_file_chirho(&credential_path_chirho).unwrap();
    assert_eq!(resolved_chirho, "file-secret-chirho");
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn review_source_evidence_requires_manifest_with_raw_hash_chirho() {
    let report_hash_chirho = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(
        review_source_evidence_chirho(Some(report_hash_chirho.to_string()), None, None)
            .unwrap()
            .0
            .is_some()
    );
    assert!(
        review_source_evidence_chirho(None, None, Some(report_hash_chirho.to_string()))
            .unwrap_err()
            .to_string()
            .contains("--raw-manifest requires --source-manifest")
    );
}
