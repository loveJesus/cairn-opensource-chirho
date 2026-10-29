// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::dag_chirho;
use crate::model_chirho::{DagChirho, NodeDefChirho, PortChirho};
use crate::store_chirho;
use ed25519_dalek::{Signer as _, SigningKey};
use std::io::Write;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-effect-test-{nanos_chirho}-{n_chirho}"))
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    let mut s_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for b_chirho in bytes_chirho {
        s_chirho.push_str(&format!("{b_chirho:02x}"));
    }
    s_chirho
}

/// Unseals what the `ReadStoreChirho` arm returned at brick S2 — the row's sealed envelope.
///
/// MIGRATION PATH: brick S3 moves the unseal inside the arm, viewer-scoped, with the live-read
/// response forced private. When it lands, callers of this helper collapse to a plain byte
/// comparison. If a caller starts seeing PLAINTEXT here before S3, do not simply delete the
/// helper: check that the live-read response is not resting in public CAS, because that is the
/// regression an early unseal would cause.
fn read_arm_plaintext_chirho(root_chirho: &Path, response_bytes_chirho: &[u8]) -> Vec<u8> {
    match crate::store_seal_chirho::detect_sealed_store_value_chirho(response_bytes_chirho).unwrap()
    {
        crate::store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) => {
            crate::store_seal_chirho::unseal_store_value_chirho(root_chirho, &sealed_chirho)
                .unwrap()
        }
        crate::store_seal_chirho::StoreValueViewChirho::NotSealedChirho => {
            response_bytes_chirho.to_vec()
        }
    }
}

fn write_fixed_signing_seed_chirho(root_chirho: &Path, seed_chirho: [u8; 32]) {
    std::fs::create_dir_all(root_chirho).unwrap();
    std::fs::write(root_chirho.join("signing-key-chirho.bin"), seed_chirho).unwrap();
}

fn spawn_net_server_chirho(
    body_chirho: &'static [u8],
) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
    let mut response_chirho = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body_chirho.len()
    )
    .into_bytes();
    response_chirho.extend_from_slice(body_chirho);
    spawn_raw_net_server_chirho(response_chirho)
}

fn spawn_raw_net_server_chirho(
    response_chirho: Vec<u8>,
) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener_chirho = TcpListener::bind("127.0.0.1:0").unwrap();
    let address_chirho = listener_chirho.local_addr().unwrap();
    let count_chirho = Arc::new(AtomicUsize::new(0));
    let count_for_thread_chirho = count_chirho.clone();
    let handle_chirho = std::thread::spawn(move || {
        listener_chirho.set_nonblocking(true).unwrap();
        let start_chirho = std::time::Instant::now();
        let timeout_chirho = std::time::Duration::from_secs(30);
        let mut stream_chirho = None;
        loop {
            match listener_chirho.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    stream_chirho = Some(s);
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start_chirho.elapsed() > timeout_chirho {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        if let Some(mut stream_chirho) = stream_chirho {
            count_for_thread_chirho.fetch_add(1, Ordering::SeqCst);
            let _ = stream_chirho.set_read_timeout(Some(Duration::from_secs(30)));
            let mut buffer_chirho = [0_u8; 4096];
            let _ = stream_chirho.read(&mut buffer_chirho);
            let _ = stream_chirho.write_all(&response_chirho);
        }
    });
    (
        format!("http://{address_chirho}"),
        count_chirho,
        handle_chirho,
    )
}

fn net_effect_dag_chirho(root_chirho: &Path, allowlist_chirho: Vec<String>) -> DagChirho {
    let impl_hash_chirho = cas_chirho::add_chirho(root_chirho, b"net-effect-host").unwrap();
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"net-request-response").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: "net_get_chirho".to_string(),
        impl_wasm_chirho: impl_hash_chirho,
        entry_chirho: "net_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![CapabilityChirho::NetChirho { allowlist_chirho }],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    DagChirho {
        nodes_chirho: vec![node_hash_chirho],
        edges_chirho: vec![],
    }
}

#[test]
fn clock_effect_records_then_replays_chirho() {
    let root_chirho = tmp_root_chirho();
    let idem_chirho = HashChirho("idem-clock".to_string());

    let e1_chirho = run_effect_chirho(
        &root_chirho,
        0,
        idem_chirho.clone(),
        CapabilityChirho::ClockChirho,
        b"{}",
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let e2_chirho = run_effect_chirho(
        &root_chirho,
        0,
        idem_chirho,
        CapabilityChirho::ClockChirho,
        b"{}",
    )
    .unwrap();

    assert_eq!(e2_chirho.response_chirho, e1_chirho.response_chirho);
    assert_eq!(e2_chirho.at_chirho, e1_chirho.at_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn random_effect_replays_chirho() {
    let root_chirho = tmp_root_chirho();
    let idem_chirho = HashChirho("idem-rand".to_string());
    let e1_chirho = run_effect_chirho(
        &root_chirho,
        0,
        idem_chirho.clone(),
        CapabilityChirho::RandomChirho,
        b"{}",
    )
    .unwrap();
    let e2_chirho = run_effect_chirho(
        &root_chirho,
        0,
        idem_chirho,
        CapabilityChirho::RandomChirho,
        b"{}",
    )
    .unwrap();
    assert_eq!(e1_chirho.response_chirho, e2_chirho.response_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reify_then_read_through_effects_chirho() {
    let root_chirho = tmp_root_chirho();

    // reify x = "hello": key in the capability, value as raw input bytes.
    let write_effect_chirho = run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("idem-write".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "x".to_string(),
        },
        b"hello",
    )
    .unwrap();
    // reify is a passthrough — it returns the value it wrote, and the F4 seal keeps that response
    // identity byte-identical: the hash is still blake3(plaintext). The response copy now goes
    // through the private policy; for this legacy shape the same address is also reachable through
    // the request copy, which is the §2.6 residual pinned in
    // `legacy_reify_leaves_its_request_copy_public_while_the_store_row_is_sealed_chirho`.
    let response_hash_chirho = write_effect_chirho.response_chirho.unwrap();
    assert_eq!(response_hash_chirho, cas_chirho::hash_chirho(b"hello"));
    let written_chirho = dag_private_value_chirho::load_private_dag_value_bytes_chirho(
        &root_chirho,
        &crate::store_seal_chirho::store_seal_subject_chirho(None, "x").unwrap(),
        &response_hash_chirho,
    )
    .unwrap();
    assert_eq!(String::from_utf8(written_chirho).unwrap(), "hello");

    // live read of "x" returns the current row (input ignored). At brick S2 the row IS the sealed
    // envelope and the read arm returns it verbatim — fail-safe (no plaintext leaves the store)
    // and functionally incomplete until S3; see `read_arm_plaintext_chirho`'s migration path.
    let read_effect_chirho = run_effect_chirho(
        &root_chirho,
        1,
        HashChirho("idem-read".to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "x".to_string(),
        },
        b"",
    )
    .unwrap();
    let value_bytes_chirho =
        cas_chirho::get_chirho(&root_chirho, &read_effect_chirho.response_chirho.unwrap()).unwrap();
    assert_eq!(
        read_arm_plaintext_chirho(&root_chirho, &value_bytes_chirho),
        b"hello"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn generic_paid_effect_refuses_typed_before_effect_or_ledger_mutation_chirho() {
    let root_chirho = tmp_root_chirho();
    let refusal_chirho = run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("generic-paid-none".to_string()),
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: "echo_paid_chirho".to_string(),
            caller_chirho: "alice".to_string(),
        },
        b"should-not-charge",
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<LegacyMoneyRoadRefusedChirho>(),
        Some(&LegacyMoneyRoadRefusedChirho::new_chirho(
            LegacyMoneyRoadChirho::PaidEffectChirho,
            "echo_paid_chirho",
        ))
    );
    assert!(
        load_effect_chirho(&root_chirho, &HashChirho("generic-paid-none".to_string()))
            .unwrap()
            .is_none()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn volatile_effect_display_marks_tampered_rows_invalid_chirho() {
    let root_chirho = tmp_root_chirho();

    run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("display-write".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "display/key".to_string(),
        },
        b"hello display",
    )
    .unwrap();
    run_effect_chirho(
        &root_chirho,
        1,
        HashChirho("display-read".to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "display/key".to_string(),
        },
        b"",
    )
    .unwrap();

    let valid_display_chirho =
        load_volatile_effect_records_for_display_chirho(&root_chirho).unwrap();
    assert_eq!(valid_display_chirho.len(), 1);
    assert!(valid_display_chirho[0].valid_chirho());
    assert!(valid_display_chirho[0].validation_error_chirho.is_none());

    let path_chirho = volatile_effect_records_path_chirho(&root_chirho);
    let tampered_chirho = std::fs::read_to_string(&path_chirho)
        .unwrap()
        .replace("display-read", "display-forged");
    std::fs::write(&path_chirho, tampered_chirho).unwrap();

    assert!(load_volatile_effect_records_chirho(&root_chirho).is_err());
    let invalid_display_chirho =
        load_volatile_effect_records_for_display_chirho(&root_chirho).unwrap();
    assert_eq!(invalid_display_chirho.len(), 1);
    assert!(!invalid_display_chirho[0].valid_chirho());
    assert!(invalid_display_chirho[0].record_chirho.is_some());
    assert!(invalid_display_chirho[0]
        .validation_error_chirho
        .as_ref()
        .is_some_and(|error_chirho| error_chirho.contains("signature verification")));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn scoped_write_store_request_writes_under_prefix_chirho() {
    let root_chirho = tmp_root_chirho();
    let request_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contacts-chirho/submission-001".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(b"safe contact ref"),
    };
    let request_bytes_chirho = serde_json::to_vec(&request_chirho).unwrap();

    let write_effect_chirho = run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("idem-scoped-write".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contacts-chirho".to_string(),
        },
        &request_bytes_chirho,
    )
    .unwrap();
    let response_hash_chirho = write_effect_chirho.response_chirho.unwrap();
    assert_eq!(
        response_hash_chirho,
        cas_chirho::hash_chirho(b"safe contact ref")
    );
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert_eq!(
        crate::store_seal_chirho::test_store_row_plaintext_chirho(
            &root_chirho,
            &store_chirho,
            "contacts-chirho/submission-001",
        )
        .unwrap()
        .as_deref(),
        Some(&b"safe contact ref"[..])
    );
    assert!(store_chirho
        .get_chirho("contacts-chirho")
        .unwrap()
        .is_none());

    let out_of_scope_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contact-secret-chirho/submission-002".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(b"nope"),
    };
    assert!(run_effect_chirho(
        &root_chirho,
        1,
        HashChirho("idem-scoped-write-oos".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contacts-chirho".to_string(),
        },
        &serde_json::to_vec(&out_of_scope_chirho).unwrap(),
    )
    .is_err());

    let sibling_prefix_chirho = ScopedWriteStoreRequestChirho {
        schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "contacts-chirho-secret/submission-003".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(b"nope"),
    };
    assert!(run_effect_chirho(
        &root_chirho,
        2,
        HashChirho("idem-scoped-write-sibling".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contacts-chirho".to_string(),
        },
        &serde_json::to_vec(&sibling_prefix_chirho).unwrap(),
    )
    .is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn tenant_marked_effect_store_paths_are_isolated_chirho() {
    let platform_root_chirho = tmp_root_chirho();
    let root_a_chirho =
        crate::tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, "tenant-a-chirho")
            .unwrap();
    let root_b_chirho =
        crate::tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, "tenant-b-chirho")
            .unwrap();

    run_effect_chirho(
        &root_a_chirho,
        0,
        HashChirho("write-a".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "shared-key".to_string(),
        },
        b"alpha",
    )
    .unwrap();
    run_effect_chirho(
        &root_b_chirho,
        0,
        HashChirho("write-b".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "shared-key".to_string(),
        },
        b"beta",
    )
    .unwrap();

    let read_a_chirho = run_effect_chirho(
        &root_a_chirho,
        1,
        HashChirho("read-a".to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "shared-key".to_string(),
        },
        b"",
    )
    .unwrap();
    let read_b_chirho = run_effect_chirho(
        &root_b_chirho,
        1,
        HashChirho("read-b".to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "shared-key".to_string(),
        },
        b"",
    )
    .unwrap();
    let value_a_chirho = crate::cas_chirho::get_chirho(
        &root_a_chirho,
        read_a_chirho.response_chirho.as_ref().unwrap(),
    )
    .unwrap();
    let value_b_chirho = crate::cas_chirho::get_chirho(
        &root_b_chirho,
        read_b_chirho.response_chirho.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(
        read_arm_plaintext_chirho(&root_a_chirho, &value_a_chirho),
        b"alpha"
    );
    assert_eq!(
        read_arm_plaintext_chirho(&root_b_chirho, &value_b_chirho),
        b"beta"
    );

    let b_hash_chirho = crate::cas_chirho::add_chirho(&root_b_chirho, b"known-to-b").unwrap();
    assert!(crate::cas_chirho::get_chirho(&root_a_chirho, &b_hash_chirho).is_err());

    assert!(run_effect_chirho(
        &root_a_chirho,
        2,
        HashChirho("read-traversal".to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "../shared-key".to_string(),
        },
        b"",
    )
    .is_err());

    let cross_miss_chirho = run_effect_chirho(
        &root_a_chirho,
        3,
        HashChirho("read-cross-miss".to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "tenant-b-chirho/shared-key".to_string(),
        },
        b"",
    )
    .unwrap();
    assert_eq!(
        crate::cas_chirho::get_chirho(
            &root_a_chirho,
            cross_miss_chirho.response_chirho.as_ref().unwrap(),
        )
        .unwrap(),
        b""
    );

    let _ = std::fs::remove_dir_all(&platform_root_chirho);
}

#[test]
fn query_effect_refuses_before_request_decode_or_projection_chirho() {
    let root_chirho = tmp_root_chirho();
    assert!(is_volatile_chirho(&CapabilityChirho::QueryChirho {
        prefix_chirho: "user".to_string(),
        caller_chirho: "alice".to_string(),
        max_rows_chirho: 10,
    }));
    let error_chirho = run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("query-idem".to_string()),
        CapabilityChirho::QueryChirho {
            prefix_chirho: "user".to_string(),
            caller_chirho: "alice".to_string(),
            max_rows_chirho: 10,
        },
        b"not even a query request",
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<LegacyMoneyRoadRefusedChirho>(),
        Some(&LegacyMoneyRoadRefusedChirho::new_chirho(
            LegacyMoneyRoadChirho::QueryEffectChirho,
            "query_chirho",
        ))
    );
    assert!(!root_chirho.join("query-projection-chirho.json").exists());
    assert!(!volatile_effect_records_path_chirho(&root_chirho).exists());
    assert!(!root_chirho.join("effects-chirho").exists());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn realtime_protocol_uses_the_one_typed_legacy_money_refusal_chirho() {
    let error_chirho = refuse_legacy_realtime_money_road_chirho().unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<LegacyMoneyRoadRefusedChirho>(),
        Some(&LegacyMoneyRoadRefusedChirho::new_chirho(
            LegacyMoneyRoadChirho::RealtimeSessionChirho,
            "realtime_chirho",
        ))
    );
}

#[test]
fn net_effect_runs_through_dag_and_replays_chirho() {
    let root_chirho = tmp_root_chirho();
    let (base_chirho, count_chirho, handle_chirho) = spawn_net_server_chirho(b"net-ok");
    let dag_chirho = net_effect_dag_chirho(&root_chirho, vec![format!("{base_chirho}/allowed")]);
    let request_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: format!("{base_chirho}/allowed/path"),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(64),
    };
    let request_bytes_chirho = serde_json::to_vec(&request_chirho).unwrap();

    let first_chirho =
        dag_chirho::run_dag_chirho(&root_chirho, &dag_chirho, &request_bytes_chirho).unwrap();
    handle_chirho.join().unwrap();
    assert_eq!(count_chirho.load(Ordering::SeqCst), 1);
    let response_chirho: NetResponseChirho =
        serde_json::from_slice(&first_chirho.payload_chirho).unwrap();
    assert_eq!(response_chirho.status_chirho, 200);
    assert_eq!(
        BASE64_CHIRHO
            .decode(response_chirho.body_base64_chirho.as_bytes())
            .unwrap(),
        b"net-ok"
    );
    assert_eq!(response_chirho.response_body_bytes_chirho, 6);
    let effect_chirho =
        load_effect_chirho(&root_chirho, &first_chirho.node_runs_chirho[0].run_chirho)
            .unwrap()
            .unwrap();
    assert!(matches!(
        effect_chirho.capability_chirho,
        CapabilityChirho::NetChirho { .. }
    ));
    verify_effect_chirho(&root_chirho, &effect_chirho).unwrap();

    let second_chirho =
        dag_chirho::run_dag_chirho(&root_chirho, &dag_chirho, &request_bytes_chirho).unwrap();
    assert_eq!(count_chirho.load(Ordering::SeqCst), 1);
    assert!(second_chirho.node_runs_chirho[0].cached_chirho);
    assert_eq!(second_chirho.payload_chirho, first_chirho.payload_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn net_effect_rejects_scope_and_secret_headers_chirho() {
    let root_chirho = tmp_root_chirho();
    let (base_chirho, count_chirho, handle_chirho) = spawn_net_server_chirho(b"unused");
    let dag_chirho = net_effect_dag_chirho(&root_chirho, vec![format!("{base_chirho}/allowed")]);
    let blocked_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: format!("{base_chirho}/allowedness"),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(64),
    };
    assert!(dag_chirho::run_dag_chirho(
        &root_chirho,
        &dag_chirho,
        &serde_json::to_vec(&blocked_chirho).unwrap(),
    )
    .unwrap_err()
    .to_string()
    .contains("outside the capability allowlist"));
    let mut headers_chirho = BTreeMap::new();
    headers_chirho.insert(
        "Authorization".to_string(),
        "Bearer should-not-enter-cas".to_string(),
    );
    let secret_header_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: format!("{base_chirho}/allowed"),
        headers_chirho,
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(64),
    };
    let secret_header_bytes_chirho = serde_json::to_vec(&secret_header_chirho).unwrap();
    let secret_header_hash_chirho = HashChirho(
        blake3::hash(&secret_header_bytes_chirho)
            .to_hex()
            .to_string(),
    );
    assert!(
        dag_chirho::run_dag_chirho(&root_chirho, &dag_chirho, &secret_header_bytes_chirho,)
            .unwrap_err()
            .to_string()
            .contains("not safe for immutable logging")
    );
    assert!(cas_chirho::get_chirho(&root_chirho, &secret_header_hash_chirho).is_err());
    let non_http_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: "file:///etc/passwd".to_string(),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(64),
    };
    assert!(dag_chirho::run_dag_chirho(
        &root_chirho,
        &dag_chirho,
        &serde_json::to_vec(&non_http_chirho).unwrap(),
    )
    .unwrap_err()
    .to_string()
    .contains("http and https"));
    let userinfo_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: format!(
            "http://allowed.example@{}/allowed",
            base_chirho.strip_prefix("http://").unwrap()
        ),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(64),
    };
    assert!(dag_chirho::run_dag_chirho(
        &root_chirho,
        &dag_chirho,
        &serde_json::to_vec(&userinfo_chirho).unwrap(),
    )
    .unwrap_err()
    .to_string()
    .contains("must not contain credentials"));
    assert!(!net_url_allowed_chirho(
        &["https://api.example.com/v1".to_string()],
        &Url::parse("https://api.example.com.evil/v1").unwrap(),
    )
    .unwrap());
    assert_eq!(count_chirho.load(Ordering::SeqCst), 0);
    drop(dag_chirho);
    let _ = std::net::TcpStream::connect(base_chirho.strip_prefix("http://").unwrap());
    handle_chirho.join().unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn net_effect_does_not_follow_redirects_chirho() {
    let root_chirho = tmp_root_chirho();
    let raw_response_chirho = b"HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/latest/meta-data\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec();
    let (base_chirho, count_chirho, handle_chirho) =
        spawn_raw_net_server_chirho(raw_response_chirho);
    let dag_chirho = net_effect_dag_chirho(&root_chirho, vec![base_chirho.clone()]);
    let request_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: format!("{base_chirho}/redirect"),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(64),
    };
    let report_chirho = dag_chirho::run_dag_chirho(
        &root_chirho,
        &dag_chirho,
        &serde_json::to_vec(&request_chirho).unwrap(),
    )
    .unwrap();
    handle_chirho.join().unwrap();
    assert_eq!(count_chirho.load(Ordering::SeqCst), 1);
    let response_chirho: NetResponseChirho =
        serde_json::from_slice(&report_chirho.payload_chirho).unwrap();
    assert_eq!(response_chirho.status_chirho, 302);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn net_effect_enforces_response_byte_budget_chirho() {
    let root_chirho = tmp_root_chirho();
    let (base_chirho, count_chirho, handle_chirho) = spawn_net_server_chirho(b"too-long");
    let dag_chirho = net_effect_dag_chirho(&root_chirho, vec![base_chirho.clone()]);
    let request_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: format!("{base_chirho}/"),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(3),
    };

    assert!(dag_chirho::run_dag_chirho(
        &root_chirho,
        &dag_chirho,
        &serde_json::to_vec(&request_chirho).unwrap(),
    )
    .unwrap_err()
    .to_string()
    .contains("response exceeded byte budget"));
    handle_chirho.join().unwrap();
    assert_eq!(count_chirho.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_net_success_uses_subject_private_body_refs_chirho() {
    let root_chirho = tmp_root_chirho();
    let response_body_chirho = b"private model response with Alice";
    let (base_chirho, _count_chirho, handle_chirho) = spawn_net_server_chirho(response_body_chirho);
    let request_body_chirho = br#"{"prompt_chirho":"write for Alice at alice@example.com"}"#;
    let request_chirho = NetRequestChirho {
        method_chirho: "POST".to_string(),
        url_chirho: format!("{base_chirho}/private"),
        headers_chirho: BTreeMap::from([(
            "content-type".to_string(),
            "application/json".to_string(),
        )]),
        body_base64_chirho: Some(BASE64_CHIRHO.encode(request_body_chirho)),
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(256),
    };
    let mut private_headers_chirho = BTreeMap::new();
    private_headers_chirho.insert(
        "Authorization".to_string(),
        "Bearer private-test-key".to_string(),
    );
    let effect_chirho = run_net_request_with_private_headers_chirho(
        &root_chirho,
        0,
        HashChirho("private-net-success-chirho".to_string()),
        std::slice::from_ref(&base_chirho),
        &serde_json::to_vec(&request_chirho).unwrap(),
        PrivateNetPartsChirho {
            headers_chirho: &private_headers_chirho,
            body_subject_chirho: Some("user/private-net-success-chirho"),
            attribution_chirho:
                &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                    "user/private-net-success-chirho",
                ),
        },
    )
    .unwrap()
    .0;
    handle_chirho.join().unwrap();

    let logged_request_chirho =
        cas_chirho::get_chirho(&root_chirho, &effect_chirho.request_chirho).unwrap();
    let logged_request_text_chirho = String::from_utf8(logged_request_chirho).unwrap();
    assert!(!logged_request_text_chirho.contains("alice@example.com"));
    assert!(!logged_request_text_chirho.contains("body_base64_chirho"));

    let response_hash_chirho = effect_chirho.response_chirho.as_ref().unwrap();
    let response_bytes_chirho = cas_chirho::get_chirho(&root_chirho, response_hash_chirho).unwrap();
    let response_chirho: NetResponseChirho =
        serde_json::from_slice(&response_bytes_chirho).unwrap();
    assert_eq!(
        response_chirho.request_body_hash_chirho,
        cas_chirho::hash_chirho(request_body_chirho)
    );
    assert_eq!(
        response_chirho.response_body_hash_chirho,
        cas_chirho::hash_chirho(response_body_chirho)
    );
    assert!(response_chirho.body_base64_chirho.is_empty());
    assert!(response_chirho.request_body_private_ref_chirho.is_some());
    assert!(response_chirho.response_body_private_ref_chirho.is_some());
    assert!(
        cas_chirho::get_chirho(&root_chirho, &response_chirho.request_body_hash_chirho).is_err()
    );
    assert!(
        cas_chirho::get_chirho(&root_chirho, &response_chirho.response_body_hash_chirho).is_err()
    );
    assert_eq!(
        net_response_body_bytes_chirho(&root_chirho, &response_chirho).unwrap(),
        response_body_chirho
    );
    let export_chirho = crate::privacy_chirho::export_subject_data_chirho(
        &root_chirho,
        "user/private-net-success-chirho",
        true,
    )
    .unwrap();
    assert_eq!(export_chirho.private_blobs_chirho.len(), 2);
    assert!(export_chirho
        .private_blobs_chirho
        .iter()
        .any(|blob_chirho| {
            blob_chirho
                .plaintext_base64_chirho
                .as_deref()
                .is_some_and(|text_chirho| {
                    BASE64_CHIRHO.decode(text_chirho).unwrap() == request_body_chirho
                })
        }));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_net_rejects_error_status_and_secret_reflection_before_cache_chirho() {
    let root_chirho = tmp_root_chirho();
    let mut private_headers_chirho = BTreeMap::new();
    private_headers_chirho.insert(
        "Authorization".to_string(),
        "Bearer private-test-key".to_string(),
    );

    let error_body_chirho = b"temporary provider error".to_vec();
    let raw_error_chirho = format!(
        "HTTP/1.1 502 Bad Gateway\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        error_body_chirho.len(),
        String::from_utf8_lossy(&error_body_chirho)
    )
    .into_bytes();
    let (error_base_chirho, _count_chirho, error_handle_chirho) =
        spawn_raw_net_server_chirho(raw_error_chirho);
    let error_request_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: error_base_chirho.clone(),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(128),
    };
    let error_idem_chirho = HashChirho("private-net-error-chirho".to_string());
    let error_chirho = run_net_request_with_private_headers_chirho(
        &root_chirho,
        0,
        error_idem_chirho.clone(),
        std::slice::from_ref(&error_base_chirho),
        &serde_json::to_vec(&error_request_chirho).unwrap(),
        PrivateNetPartsChirho {
            headers_chirho: &private_headers_chirho,
            body_subject_chirho: Some("user/private-net-error-chirho"),
            attribution_chirho:
                &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                    "user/private-net-error-chirho",
                ),
        },
    )
    .unwrap_err();
    error_handle_chirho.join().unwrap();
    assert!(error_chirho.to_string().contains("status 502"));
    assert!(load_effect_chirho(&root_chirho, &error_idem_chirho)
        .unwrap()
        .is_none());
    assert!(
        cas_chirho::get_chirho(&root_chirho, &cas_chirho::hash_chirho(&error_body_chirho)).is_err()
    );

    let reflected_body_chirho = b"debug reflected private-test-key".to_vec();
    let raw_reflected_chirho = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        reflected_body_chirho.len(),
        String::from_utf8_lossy(&reflected_body_chirho)
    )
    .into_bytes();
    let (reflected_base_chirho, _count_chirho, reflected_handle_chirho) =
        spawn_raw_net_server_chirho(raw_reflected_chirho);
    let reflected_request_chirho = NetRequestChirho {
        method_chirho: "GET".to_string(),
        url_chirho: reflected_base_chirho.clone(),
        headers_chirho: BTreeMap::new(),
        body_base64_chirho: None,
        timeout_ms_chirho: Some(2_000),
        max_response_bytes_chirho: Some(128),
    };
    let reflected_idem_chirho = HashChirho("private-net-reflect-chirho".to_string());
    let reflected_error_chirho = run_net_request_with_private_headers_chirho(
        &root_chirho,
        0,
        reflected_idem_chirho.clone(),
        std::slice::from_ref(&reflected_base_chirho),
        &serde_json::to_vec(&reflected_request_chirho).unwrap(),
        PrivateNetPartsChirho {
            headers_chirho: &private_headers_chirho,
            body_subject_chirho: Some("user/private-net-reflect-chirho"),
            attribution_chirho:
                &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                    "user/private-net-reflect-chirho",
                ),
        },
    )
    .unwrap_err();
    reflected_handle_chirho.join().unwrap();
    assert!(reflected_error_chirho
        .to_string()
        .contains("private bearer"));
    assert!(load_effect_chirho(&root_chirho, &reflected_idem_chirho)
        .unwrap()
        .is_none());
    assert!(cas_chirho::get_chirho(
        &root_chirho,
        &cas_chirho::hash_chirho(&reflected_body_chirho)
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn effect_signature_verifies_and_detects_tamper_chirho() {
    let root_chirho = tmp_root_chirho();
    let effect_chirho = run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("idem-sig".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "x".to_string(),
        },
        b"v",
    )
    .unwrap();

    // A genuine effect has a real 64-byte (128-hex) ed25519 signature that verifies.
    assert_eq!(effect_chirho.sig_chirho.len(), 128);
    assert_ne!(effect_chirho.sig_chirho, "unsigned-v0");
    assert!(verify_effect_chirho(&root_chirho, &effect_chirho).is_ok());

    // Tampering with the response makes verification fail.
    let mut tampered_chirho = effect_chirho.clone();
    tampered_chirho.response_chirho = Some(HashChirho("deadbeef".to_string()));
    assert!(verify_effect_chirho(&root_chirho, &tampered_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn signer_extraction_preserves_fixed_seed_bytes_chirho() {
    let root_chirho = tmp_root_chirho();
    let seed_chirho = [0x23; 32];
    write_fixed_signing_seed_chirho(&root_chirho, seed_chirho);
    let key_chirho = SigningKey::from_bytes(&seed_chirho);
    let message_chirho = b"fixed signer extraction compatibility message";

    assert_eq!(
        signer_chirho::pubkey_hex_chirho(&root_chirho).unwrap(),
        hex_encode_chirho(key_chirho.verifying_key().as_bytes())
    );
    assert_eq!(
        signer_chirho::sign_message_chirho(&root_chirho, message_chirho).unwrap(),
        hex_encode_chirho(&key_chirho.sign(message_chirho).to_bytes())
    );
    assert_eq!(
        derive_instance_key_chirho(&root_chirho, "cairn-mailbox-local-part-index-v1-chirho")
            .unwrap(),
        blake3::derive_key("cairn-mailbox-local-part-index-v1-chirho", &seed_chirho)
    );
    assert_eq!(
        derive_instance_key_chirho(&root_chirho, "cairn-run-intent-scope-index-v1-chirho").unwrap(),
        blake3::derive_key("cairn-run-intent-scope-index-v1-chirho", &seed_chirho)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[cfg(unix)]
#[test]
fn signing_key_file_is_private_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let root_chirho = tmp_root_chirho();
    let _sig_chirho =
        signer_chirho::sign_message_chirho(&root_chirho, b"check permissions").unwrap();
    let mode_chirho = std::fs::metadata(root_chirho.join("signing-key-chirho.bin"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode_chirho, 0o600);
    let _ = std::fs::remove_dir_all(&root_chirho);
}
