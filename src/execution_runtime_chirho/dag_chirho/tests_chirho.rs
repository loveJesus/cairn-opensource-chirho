// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::model_chirho::{
    builtin_phi_node_def_chirho, CapabilityChirho, EdgePrivacyChirho,
    EdgePrivacySubjectSourceChirho, PortChirho, RequestContextChirho, RunStatusChirho,
    SKIPPED_STONE_BYTES_CHIRHO,
};
use crate::provider_test_support_chirho::{
    current_effect_contract_set_chirho, llm_request_bytes_chirho,
};
use cairn_signer_chirho::signer_chirho;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-dag-test-{nanos_chirho}-{n_chirho}"))
}

fn cas_object_path_chirho(root_chirho: &Path, addr_chirho: &HashChirho) -> PathBuf {
    let hex_chirho = &addr_chirho.0;
    root_chirho
        .join("objects-chirho")
        .join(&hex_chirho[0..2])
        .join(&hex_chirho[2..])
}

pub(super) fn store_bytes_node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    wat_chirho: &[u8],
    entry_chirho: &str,
) -> (NodeDefChirho, HashChirho) {
    let impl_hash_chirho = cas_chirho::add_chirho(root_chirho, wat_chirho).unwrap();
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: impl_hash_chirho,
        entry_chirho: entry_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    (node_chirho, node_hash_chirho)
}

pub(crate) fn skipped_wat_chirho() -> &'static str {
    r#"(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 2048))
  (data (i32.const 1024) "{\"schema_chirho\":\"skipped-stone-v1-chirho\",\"skipped_chirho\":true}")
  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap_chirho
    local.set $p
    global.get $heap_chirho
    local.get $len
    i32.add
    global.set $heap_chirho
    local.get $p)
  (func (export "emit_skipped_chirho") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.const 1024) (i64.const 32))
      (i64.const 65))))"#
}

pub(super) fn store_skipped_node_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
    let (_node_chirho, node_hash_chirho) = store_bytes_node_chirho(
        root_chirho,
        name_chirho,
        skipped_wat_chirho().as_bytes(),
        "emit_skipped_chirho",
    );
    node_hash_chirho
}

fn store_invalid_wasm_node_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: HashChirho("missing-wasm-object-chirho".to_string()),
        entry_chirho: "must_not_run_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000,
        ..Default::default()
    };
    store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
}

fn store_phi_node_chirho(root_chirho: &Path, input_ports_chirho: &[&str]) -> HashChirho {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let input_ports_chirho: Vec<String> = input_ports_chirho
        .iter()
        .map(|port_chirho| (*port_chirho).to_string())
        .collect();
    let node_chirho =
        builtin_phi_node_def_chirho("phi_chirho", &input_ports_chirho, "out", schema_hash_chirho);
    store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
}

fn store_write_node_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(root_chirho, b"builtin:write").unwrap(),
        entry_chirho: "write_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "orders".to_string(),
        }],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
}

pub(super) fn edge_chirho(
    from_node_chirho: &HashChirho,
    from_port_chirho: &str,
    to_node_chirho: &HashChirho,
    to_port_chirho: &str,
) -> EdgeChirho {
    EdgeChirho {
        from_node_chirho: from_node_chirho.clone(),
        from_port_chirho: from_port_chirho.to_string(),
        to_node_chirho: to_node_chirho.clone(),
        to_port_chirho: to_port_chirho.to_string(),
        privacy_chirho: None,
    }
}

fn run_record_count_chirho(root_chirho: &Path) -> usize {
    let path_chirho = root_chirho.join("runs-chirho");
    if !path_chirho.exists() {
        return 0;
    }
    std::fs::read_dir(path_chirho).unwrap().count()
}

#[test]
fn two_node_chain_runs_caches_and_records_provenance_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let reverse_wat_chirho = include_str!("../../../examples-chirho/reverse-chirho.wat");

    let (_u_chirho, u_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "upcase_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_r_chirho, r_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "reverse_chirho",
        reverse_wat_chirho.as_bytes(),
        "reverse_chirho",
    );

    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![u_hash_chirho.clone(), r_hash_chirho.clone()],
        edges_chirho: vec![EdgeChirho {
            from_node_chirho: u_hash_chirho.clone(),
            from_port_chirho: "out".to_string(),
            to_node_chirho: r_hash_chirho.clone(),
            to_port_chirho: "in".to_string(),
            privacy_chirho: None,
        }],
    };

    let report_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"Hello, World").unwrap();
    assert_eq!(
        String::from_utf8(report_chirho.payload_chirho.clone()).unwrap(),
        "DLROW ,OLLEH"
    );
    assert_eq!(report_chirho.node_runs_chirho.len(), 2);
    assert!(report_chirho
        .node_runs_chirho
        .iter()
        .all(|nr_chirho| !nr_chirho.cached_chirho));

    let upcase_run_chirho = &report_chirho.node_runs_chirho[0].run_chirho;
    let reverse_run_chirho = &report_chirho.node_runs_chirho[1].run_chirho;
    let reverse_result_chirho = cache_chirho::load_result_chirho(&root_chirho, reverse_run_chirho)
        .unwrap()
        .unwrap();
    assert_eq!(
        reverse_result_chirho.parents_chirho,
        vec![upcase_run_chirho.clone()]
    );

    let report2_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"Hello, World").unwrap();
    assert!(report2_chirho
        .node_runs_chirho
        .iter()
        .all(|nr_chirho| nr_chirho.cached_chirho));
    assert_eq!(report2_chirho.payload_chirho, report_chirho.payload_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_edge_keeps_intermediate_value_out_of_plaintext_cas_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let reverse_wat_chirho = include_str!("../../../examples-chirho/reverse-chirho.wat");
    let (_u_chirho, u_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "upcase_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_r_chirho, r_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "reverse_chirho",
        reverse_wat_chirho.as_bytes(),
        "reverse_chirho",
    );
    let mut edge_chirho = edge_chirho(&u_hash_chirho, "out", &r_hash_chirho, "in");
    edge_chirho.privacy_chirho = Some(EdgePrivacyChirho::PrivateBlobRefChirho {
        subject_source_chirho: EdgePrivacySubjectSourceChirho::RequestUserChirho,
    });
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![u_hash_chirho.clone(), r_hash_chirho.clone()],
        edges_chirho: vec![edge_chirho],
    };
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "user/private-edge-chirho".to_string(),
        app_chirho: "private-edge-app-chirho".to_string(),
        owner_principal_chirho: "owner/private-edge-chirho".to_string(),
        client_id_chirho: "browser-session-chirho".to_string(),
        token_hash_chirho: "token-private-edge-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let report_chirho = run_dag_with_context_chirho(
        &root_chirho,
        &dag_obj_chirho,
        b"secret",
        Some(&context_chirho),
    )
    .unwrap();
    assert_eq!(report_chirho.payload_chirho, b"TERCES");

    let upcase_run_chirho = &report_chirho.node_runs_chirho[0].run_chirho;
    let upcase_result_chirho = cache_chirho::load_result_chirho(&root_chirho, upcase_run_chirho)
        .unwrap()
        .unwrap();
    let upcase_output_chirho = upcase_result_chirho
        .outputs_chirho
        .get("out")
        .expect("upcase output hash")
        .clone();
    assert!(
        cas_chirho::get_chirho(&root_chirho, &upcase_output_chirho).is_err(),
        "private edge output must never be plaintext CAS"
    );
    assert!(
        dag_private_value_chirho::private_dag_value_recorded_for_subject_chirho(
            &root_chirho,
            &context_chirho.user_principal_chirho,
            &upcase_output_chirho,
        )
        .unwrap()
    );
    let private_bytes_chirho = dag_private_value_chirho::load_private_dag_value_bytes_chirho(
        &root_chirho,
        &context_chirho.user_principal_chirho,
        &upcase_output_chirho,
    )
    .unwrap();
    assert_eq!(private_bytes_chirho, b"SECRET");
    crate::verify_chirho::verify_run_cache_chirho(&root_chirho).unwrap();

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn early_cutoff_keeps_downstream_run_key_when_output_stone_matches_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let reverse_wat_chirho = include_str!("../../../examples-chirho/reverse-chirho.wat");

    let (_u_chirho, u_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "upcase_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_r_chirho, r_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "reverse_chirho",
        reverse_wat_chirho.as_bytes(),
        "reverse_chirho",
    );

    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![u_hash_chirho.clone(), r_hash_chirho.clone()],
        edges_chirho: vec![EdgeChirho {
            from_node_chirho: u_hash_chirho.clone(),
            from_port_chirho: "out".to_string(),
            to_node_chirho: r_hash_chirho,
            to_port_chirho: "in".to_string(),
            privacy_chirho: None,
        }],
    };

    let report_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"same").unwrap();
    assert_eq!(report_chirho.payload_chirho, b"EMAS");
    assert_eq!(report_chirho.node_runs_chirho.len(), 2);
    assert!(report_chirho
        .node_runs_chirho
        .iter()
        .all(|run_chirho| !run_chirho.cached_chirho));
    assert_eq!(
        run_record_count_chirho(&root_chirho),
        2,
        "first DAG run should create one run record per node"
    );

    let first_upcase_run_chirho = &report_chirho.node_runs_chirho[0].run_chirho;
    let first_reverse_run_chirho = &report_chirho.node_runs_chirho[1].run_chirho;
    let first_upcase_result_chirho =
        cache_chirho::load_result_chirho(&root_chirho, first_upcase_run_chirho)
            .unwrap()
            .unwrap();
    let first_upcase_output_chirho = first_upcase_result_chirho
        .outputs_chirho
        .get("out")
        .unwrap()
        .clone();
    let first_reverse_key_chirho =
        cache_chirho::load_run_key_chirho(&root_chirho, first_reverse_run_chirho)
            .unwrap()
            .unwrap();
    assert_eq!(
        first_reverse_key_chirho.inputs_chirho.get("in"),
        Some(&first_upcase_output_chirho)
    );

    let report2_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"SAME").unwrap();
    assert_eq!(report2_chirho.payload_chirho, report_chirho.payload_chirho);
    assert!(!report2_chirho.node_runs_chirho[0].cached_chirho);
    assert!(report2_chirho.node_runs_chirho[1].cached_chirho);
    assert_ne!(
        report2_chirho.node_runs_chirho[0].run_chirho,
        *first_upcase_run_chirho
    );
    assert_eq!(
        report2_chirho.node_runs_chirho[1].run_chirho,
        *first_reverse_run_chirho
    );
    assert_eq!(
        run_record_count_chirho(&root_chirho),
        3,
        "second DAG run should add only A's changed-input record, not a new B record"
    );

    let second_upcase_result_chirho = cache_chirho::load_result_chirho(
        &root_chirho,
        &report2_chirho.node_runs_chirho[0].run_chirho,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        second_upcase_result_chirho.outputs_chirho.get("out"),
        Some(&first_upcase_output_chirho)
    );
    let second_reverse_key_chirho =
        cache_chirho::load_run_key_chirho(&root_chirho, first_reverse_run_chirho)
            .unwrap()
            .unwrap();
    assert_eq!(second_reverse_key_chirho, first_reverse_key_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn dag_run_aggregate_output_cap_rejects_fanout_growth_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let reverse_wat_chirho = include_str!("../../../examples-chirho/reverse-chirho.wat");

    let (_up_node_chirho, up_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "upcase_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_rev_node_chirho, rev_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "reverse_chirho",
        reverse_wat_chirho.as_bytes(),
        "reverse_chirho",
    );
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![up_hash_chirho.clone(), rev_hash_chirho.clone()],
        edges_chirho: vec![edge_chirho(&up_hash_chirho, "out", &rev_hash_chirho, "in")],
    };

    let error_chirho = run_dag_with_context_and_parents_and_output_cap_chirho(
        &root_chirho,
        &dag_obj_chirho,
        DagRunInputChirho {
            value_chirho: DagInputValueChirho::PublicBytesChirho(b"hello".to_vec()),
            admitted_request_chirho: None,
        },
        None,
        &[],
        8,
        effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho(),
    )
    .unwrap_err();
    assert!(
        error_chirho.to_string().contains("aggregate bytes"),
        "{error_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn skipped_input_auto_propagates_through_pure_node_and_phi_chooses_live_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let (_live_chirho, live_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "live_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let skip_hash_chirho = store_skipped_node_chirho(&root_chirho, "skip_branch_chirho");
    let invalid_hash_chirho =
        store_invalid_wasm_node_chirho(&root_chirho, "must_not_execute_chirho");
    let phi_hash_chirho =
        store_phi_node_chirho(&root_chirho, &["live_in_chirho", "skipped_in_chirho"]);
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![
            live_hash_chirho.clone(),
            skip_hash_chirho.clone(),
            invalid_hash_chirho.clone(),
            phi_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            edge_chirho(&skip_hash_chirho, "out", &invalid_hash_chirho, "in"),
            edge_chirho(&live_hash_chirho, "out", &phi_hash_chirho, "live_in_chirho"),
            edge_chirho(
                &invalid_hash_chirho,
                "out",
                &phi_hash_chirho,
                "skipped_in_chirho",
            ),
        ],
    };

    let report_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"hello").unwrap();
    assert_eq!(report_chirho.payload_chirho, b"HELLO");
    let invalid_run_chirho = report_chirho
        .node_runs_chirho
        .iter()
        .find(|run_chirho| run_chirho.node_name_chirho == "must_not_execute_chirho")
        .unwrap();
    let invalid_result_chirho =
        cache_chirho::load_result_chirho(&root_chirho, &invalid_run_chirho.run_chirho)
            .unwrap()
            .unwrap();
    assert!(matches!(
        invalid_result_chirho.status_chirho,
        RunStatusChirho::SkippedChirho { .. }
    ));
    let skipped_hash_chirho = cache_chirho::skipped_stone_hash_chirho(&root_chirho).unwrap();
    assert_eq!(
        invalid_result_chirho.outputs_chirho.get("out"),
        Some(&skipped_hash_chirho)
    );

    let report2_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"hello").unwrap();
    assert_eq!(report2_chirho.payload_chirho, report_chirho.payload_chirho);
    assert!(report2_chirho
        .node_runs_chirho
        .iter()
        .all(|run_chirho| run_chirho.cached_chirho));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn blessed_node_receiving_skipped_logs_skip_and_does_not_write_chirho() {
    use crate::versioned_chirho::VersionedStoreChirho;

    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let (_live_chirho, live_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "live_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let skip_hash_chirho = store_skipped_node_chirho(&root_chirho, "skip_branch_chirho");
    let write_hash_chirho = store_write_node_chirho(&root_chirho, "save_order_chirho");
    let phi_hash_chirho =
        store_phi_node_chirho(&root_chirho, &["live_in_chirho", "skipped_in_chirho"]);
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![
            live_hash_chirho.clone(),
            skip_hash_chirho.clone(),
            write_hash_chirho.clone(),
            phi_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            edge_chirho(&skip_hash_chirho, "out", &write_hash_chirho, "in"),
            edge_chirho(&live_hash_chirho, "out", &phi_hash_chirho, "live_in_chirho"),
            edge_chirho(
                &write_hash_chirho,
                "out",
                &phi_hash_chirho,
                "skipped_in_chirho",
            ),
        ],
    };

    let report_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"hello").unwrap();
    assert_eq!(report_chirho.payload_chirho, b"HELLO");
    let write_run_chirho = report_chirho
        .node_runs_chirho
        .iter()
        .find(|run_chirho| run_chirho.node_name_chirho == "save_order_chirho")
        .unwrap();
    let write_result_chirho =
        cache_chirho::load_result_chirho(&root_chirho, &write_run_chirho.run_chirho)
            .unwrap()
            .unwrap();
    assert!(matches!(
        write_result_chirho.status_chirho,
        RunStatusChirho::SkippedChirho { .. }
    ));
    assert_eq!(write_result_chirho.effects_chirho.len(), 1);
    let skip_effect_chirho = &write_result_chirho.effects_chirho[0];
    effect_chirho::verify_effect_chirho(&root_chirho, skip_effect_chirho).unwrap();
    let skipped_hash_chirho = cache_chirho::skipped_stone_hash_chirho(&root_chirho).unwrap();
    assert_eq!(skip_effect_chirho.request_chirho, skipped_hash_chirho);
    assert_eq!(
        skip_effect_chirho.response_chirho.as_ref(),
        Some(&skipped_hash_chirho)
    );
    let vstore_chirho =
        VersionedStoreChirho::open_chirho(&root_chirho.join("versioned-chirho.redb")).unwrap();
    let orders_key_chirho =
        crate::tenant_chirho::validated_store_key_for_root_chirho(&root_chirho, "orders").unwrap();
    assert_eq!(vstore_chirho.get_chirho(&orders_key_chirho).unwrap(), None);
    let verify_report_chirho = crate::verify_chirho::verify_run_cache_chirho(&root_chirho)
        .expect("builtin phi and skipped effect runs should verify");
    assert_eq!(verify_report_chirho.runs_chirho, 4);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn phi_fails_closed_on_zero_or_two_live_inputs_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let reverse_wat_chirho = include_str!("../../../examples-chirho/reverse-chirho.wat");
    let (_up_chirho, up_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "upcase_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    let (_rev_chirho, rev_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "reverse_chirho",
        reverse_wat_chirho.as_bytes(),
        "reverse_chirho",
    );
    let phi_hash_chirho = store_phi_node_chirho(&root_chirho, &["left_chirho", "right_chirho"]);
    let two_live_dag_chirho = DagChirho {
        nodes_chirho: vec![
            up_hash_chirho.clone(),
            rev_hash_chirho.clone(),
            phi_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            edge_chirho(&up_hash_chirho, "out", &phi_hash_chirho, "left_chirho"),
            edge_chirho(&rev_hash_chirho, "out", &phi_hash_chirho, "right_chirho"),
        ],
    };
    let error_chirho = run_dag_chirho(&root_chirho, &two_live_dag_chirho, b"hi")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("requires exactly one live input; found 2"));

    let left_skip_chirho = store_skipped_node_chirho(&root_chirho, "left_skip_chirho");
    let right_skip_chirho = store_skipped_node_chirho(&root_chirho, "right_skip_chirho");
    let phi2_hash_chirho = store_phi_node_chirho(&root_chirho, &["left_chirho", "right_chirho"]);
    let zero_live_dag_chirho = DagChirho {
        nodes_chirho: vec![
            left_skip_chirho.clone(),
            right_skip_chirho.clone(),
            phi2_hash_chirho.clone(),
        ],
        edges_chirho: vec![
            edge_chirho(&left_skip_chirho, "out", &phi2_hash_chirho, "left_chirho"),
            edge_chirho(&right_skip_chirho, "out", &phi2_hash_chirho, "right_chirho"),
        ],
    };
    let error_chirho = run_dag_chirho(&root_chirho, &zero_live_dag_chirho, b"hi")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("requires exactly one live input; found 0"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn skipped_at_dag_surface_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let skipped_hash_chirho = store_skipped_node_chirho(&root_chirho, "skip_surface_chirho");
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![skipped_hash_chirho],
        edges_chirho: vec![],
    };

    let error_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"input")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("DAG surface output resolved to SkippedChirho"));
    assert_eq!(
        cache_chirho::skipped_stone_hash_chirho(&root_chirho).unwrap(),
        cas_chirho::hash_chirho(SKIPPED_STONE_BYTES_CHIRHO)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn dag_rejects_tampered_wasm_before_execution_chirho() {
    let root_chirho = tmp_root_chirho();
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let reverse_wat_chirho = include_str!("../../../examples-chirho/reverse-chirho.wat");

    let (node_chirho, node_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "upcase_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );
    std::fs::write(
        cas_object_path_chirho(&root_chirho, &node_chirho.impl_wasm_chirho),
        reverse_wat_chirho.as_bytes(),
    )
    .unwrap();
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![node_hash_chirho],
        edges_chirho: vec![],
    };

    let error_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"Hello")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("loading wasm for 'upcase_chirho'"));
    assert!(error_chirho.contains("content address mismatch"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn effect_node_in_dag_records_and_replays_chirho() {
    use crate::versioned_chirho::VersionedStoreChirho;

    let root_chirho = tmp_root_chirho();

    {
        let vstore_chirho =
            VersionedStoreChirho::open_chirho(&root_chirho.join("versioned-chirho.redb")).unwrap();
        vstore_chirho.put_chirho("msg", b"hello").unwrap();
    }

    let read_node_chirho = NodeDefChirho {
        name_chirho: "read_chirho".to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(&root_chirho, b"builtin:read").unwrap(),
        entry_chirho: "read".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("kvreq".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho: vec![CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "msg".to_string(),
        }],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let read_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &read_node_chirho).unwrap();

    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    let (_up_chirho, up_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "upcase_chirho",
        upcase_wat_chirho.as_bytes(),
        "upcase_chirho",
    );

    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![read_hash_chirho.clone(), up_hash_chirho.clone()],
        edges_chirho: vec![EdgeChirho {
            from_node_chirho: read_hash_chirho,
            from_port_chirho: "out".to_string(),
            to_node_chirho: up_hash_chirho,
            to_port_chirho: "in".to_string(),
            privacy_chirho: None,
        }],
    };

    // The read's key comes from its capability; the DAG input is ignored by the read.
    let report_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"").unwrap();
    assert_eq!(
        String::from_utf8(report_chirho.payload_chirho.clone()).unwrap(),
        "HELLO"
    );

    // Re-run: the live read re-executes (volatile, not cached); the downstream pure
    // upcase is served from cache; the payload is identical (store unchanged).
    let report2_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"").unwrap();
    assert!(!report2_chirho.node_runs_chirho[0].cached_chirho);
    assert!(report2_chirho.node_runs_chirho[1].cached_chirho);
    assert_eq!(report2_chirho.payload_chirho, report_chirho.payload_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn native_node_in_dag_propagates_typed_legacy_money_refusal_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let executable_chirho = root_chirho.join("native-placeholder-chirho");
    std::fs::write(&executable_chirho, b"not-executed").unwrap();
    let (_spec_chirho, spec_hash_chirho) = native_worker_chirho::build_native_program_chirho(
        &root_chirho,
        &executable_chirho,
        native_worker_chirho::NativeProgramBuildRequestChirho {
            name_chirho: "native-paid-dag-chirho".to_string(),
            argv_chirho: Vec::new(),
            sandbox_mode_chirho: native_worker_chirho::NativeSandboxModeChirho::BestEffortChirho,
            allowed_syscalls_chirho: native_worker_chirho::default_native_syscalls_chirho(),
            capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
                effect_chirho: "llm_chirho".to_string(),
                caller_chirho: "ignored_until_context_chirho".to_string(),
            }],
            timeout_ms_chirho: 1000,
            max_memory_bytes_chirho: 16 * 1024 * 1024,
            max_input_bytes_chirho: 1024,
            max_output_bytes_chirho: 1024,
            warm_pool_size_chirho: 1,
        },
    )
    .unwrap();
    let (mut node_chirho, _legacy_node_hash_chirho) =
        native_worker_chirho::build_native_node_def_chirho(&root_chirho, &spec_hash_chirho, None)
            .unwrap();
    node_chirho.effect_contract_set_chirho = Some(current_effect_contract_set_chirho());
    let node_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![node_hash_chirho.clone()],
        edges_chirho: vec![],
    };
    let dag_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &dag_obj_chirho).unwrap();

    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "nativedagapp",
        dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    let mut effect_prices_chirho = BTreeMap::new();
    effect_prices_chirho.insert("llm_chirho".to_string(), 7);
    let (book_hash_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "nativedagapp",
        &owner_chirho,
        Some(1),
        effect_prices_chirho,
        0,
    )
    .unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "ctx/native-user".to_string(),
        app_chirho: "nativedagapp".to_string(),
        owner_principal_chirho: owner_chirho,
        client_id_chirho: "client/native-dag".to_string(),
        token_hash_chirho: "token/native-dag".to_string(),
        price_book_chirho: Some(book_hash_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let request_chirho = llm_request_bytes_chirho("native dag paid");

    let mut dishonest_node_chirho = node_chirho.clone();
    dishonest_node_chirho.capabilities_chirho.clear();
    let dishonest_node_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &dishonest_node_chirho).unwrap();
    let dishonest_dag_chirho = DagChirho {
        nodes_chirho: vec![dishonest_node_hash_chirho],
        edges_chirho: vec![],
    };
    let error_chirho = run_dag_chirho(&root_chirho, &dishonest_dag_chirho, &request_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("capabilities must match"));

    let error_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, &request_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("requires verified RequestContextChirho"));

    let refusal_chirho = run_dag_with_context_chirho(
        &root_chirho,
        &dag_obj_chirho,
        &request_chirho,
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    // The native node's paid llm_chirho target passes v2 admission; with no served-LLM composition
    // injected it refuses at the uninstalled composition, and that typed refusal propagates through
    // the DAG. (llm_chirho routes to the served ladder since S2b/S2c, not the legacy money road.)
    assert!(
        refusal_chirho.contains("served LLM provider composition is not installed"),
        "the native DAG node propagates the paid target's served composition refusal: {refusal_chirho}"
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn native_node_publish_install_roundtrip_keeps_native_closure_chirho() {
    let src_chirho = tmp_root_chirho();
    let dst_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::create_dir_all(&dst_chirho).unwrap();

    // Native specs are admitted by the platform key. This round trip represents moving a
    // package inside the same admitted platform trust boundary.
    let _ = signer_chirho::pubkey_hex_chirho(&src_chirho).unwrap();
    std::fs::copy(
        src_chirho.join("signing-key-chirho.bin"),
        dst_chirho.join("signing-key-chirho.bin"),
    )
    .unwrap();
    std::fs::copy(
        src_chirho.join("pubkey-chirho.hex"),
        dst_chirho.join("pubkey-chirho.hex"),
    )
    .unwrap();

    let executable_chirho = src_chirho.join("native-placeholder-chirho");
    std::fs::write(&executable_chirho, b"not-executed").unwrap();
    let (spec_chirho, spec_hash_chirho) = native_worker_chirho::build_native_program_chirho(
        &src_chirho,
        &executable_chirho,
        native_worker_chirho::NativeProgramBuildRequestChirho {
            name_chirho: "native-write-publish-chirho".to_string(),
            argv_chirho: Vec::new(),
            sandbox_mode_chirho: native_worker_chirho::NativeSandboxModeChirho::BestEffortChirho,
            allowed_syscalls_chirho: native_worker_chirho::default_native_syscalls_chirho(),
            capabilities_chirho: vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "native-publish-roundtrip-chirho".to_string(),
            }],
            timeout_ms_chirho: 1000,
            max_memory_bytes_chirho: 16 * 1024 * 1024,
            max_input_bytes_chirho: 1024,
            max_output_bytes_chirho: 1024,
            warm_pool_size_chirho: 1,
        },
    )
    .unwrap();
    let (mut node_chirho, _legacy_node_hash_chirho) =
        native_worker_chirho::build_native_node_def_chirho(&src_chirho, &spec_hash_chirho, None)
            .unwrap();
    node_chirho.effect_contract_set_chirho = Some(
        cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho(
            &cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho(),
        )
        .unwrap(),
    );
    let node_hash_chirho = store_chirho::put_object_chirho(&src_chirho, &node_chirho).unwrap();
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![node_hash_chirho],
        edges_chirho: vec![],
    };
    let dag_hash_chirho = store_chirho::put_object_chirho(&src_chirho, &dag_obj_chirho).unwrap();

    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &dst_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let source_manifest_chirho = crate::app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: crate::app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO
            .to_string(),
        app_chirho: "nativepub".to_string(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: crate::app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                crate::app_source_manifest_chirho::AppSourceDeploySourceChirho::StoredDagChirho {
                    hash_chirho: dag_hash_chirho.clone(),
                },
            ),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                crate::app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let candidate_chirho = crate::app_source_manifest_chirho::build_app_source_candidate_chirho(
        &src_chirho,
        Path::new("."),
        &source_manifest_chirho,
    )
    .unwrap();
    let bindings_chirho = candidate_chirho.undo_plan_bindings_chirho.unwrap();
    let mut package_chirho = crate::publish_chirho::build_package_chirho(
        &src_chirho,
        "nativepub",
        &dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    crate::publish_chirho::attach_descriptor_v2_bindings_chirho(
        &src_chirho,
        &mut package_chirho,
        &bindings_chirho,
    )
    .unwrap();
    let object_hashes_chirho: std::collections::BTreeSet<&str> = package_chirho
        .objects_chirho
        .iter()
        .map(|object_chirho| object_chirho.hash_chirho.as_str())
        .collect();
    assert!(object_hashes_chirho.contains(spec_hash_chirho.0.as_str()));
    assert!(object_hashes_chirho.contains(spec_chirho.executable_chirho.0.as_str()));

    crate::publish_chirho::install_package_chirho(&dst_chirho, &package_chirho).unwrap();
    let verification_chirho =
        native_worker_chirho::verify_native_program_chirho(&dst_chirho, &spec_hash_chirho).unwrap();
    assert_eq!(
        verification_chirho.executable_chirho,
        spec_chirho.executable_chirho
    );

    let installed_dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&dst_chirho, &dag_hash_chirho).unwrap();
    // Its WriteStore node seals a row, and a context-free run must say whose container that joins.
    let operator_chirho =
        crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho();
    let report_chirho = run_dag_with_context_and_effect_runtime_chirho(
        &dst_chirho,
        &installed_dag_chirho,
        b"12345678",
        None,
        effect_chirho::DagEffectRuntimePortsChirho {
            private_attribution_chirho: Some(&operator_chirho),
            ..effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho()
        },
    )
    .unwrap();
    assert_eq!(report_chirho.payload_chirho.len(), 8);
    assert_eq!(report_chirho.node_runs_chirho.len(), 1);
    assert!(!report_chirho.node_runs_chirho[0].cached_chirho);
    let cached_report_chirho =
        run_dag_chirho(&dst_chirho, &installed_dag_chirho, b"12345678").unwrap();
    assert!(cached_report_chirho.node_runs_chirho[0].cached_chirho);
    assert_eq!(
        cached_report_chirho.payload_hash_chirho,
        report_chirho.payload_hash_chirho
    );

    let _ = std::fs::remove_dir_all(&src_chirho);
    let _ = std::fs::remove_dir_all(&dst_chirho);
}

#[test]
fn native_invoke_node_propagates_typed_paid_target_refusal_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();

    let target_node_chirho = NodeDefChirho {
        name_chirho: "native_invoke_paid_target_chirho".to_string(),
        impl_wasm_chirho: cas_chirho::add_chirho(&root_chirho, b"builtin:paid").unwrap(),
        entry_chirho: "paid".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_string(),
            caller_chirho: "ignored_until_context_chirho".to_string(),
        }],
        effect_contract_set_chirho: Some(current_effect_contract_set_chirho()),
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let target_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &target_node_chirho).unwrap();

    let executable_chirho = root_chirho.join("native-placeholder-chirho");
    std::fs::write(&executable_chirho, b"not-executed").unwrap();
    let (_spec_chirho, spec_hash_chirho) = native_worker_chirho::build_native_program_chirho(
        &root_chirho,
        &executable_chirho,
        native_worker_chirho::NativeProgramBuildRequestChirho {
            name_chirho: "native-invoke-dag-chirho".to_string(),
            argv_chirho: Vec::new(),
            sandbox_mode_chirho: native_worker_chirho::NativeSandboxModeChirho::BestEffortChirho,
            allowed_syscalls_chirho: native_worker_chirho::default_native_syscalls_chirho(),
            capabilities_chirho: vec![CapabilityChirho::InvokeChirho {
                node_chirho: target_hash_chirho.clone(),
            }],
            timeout_ms_chirho: 1000,
            max_memory_bytes_chirho: 16 * 1024 * 1024,
            max_input_bytes_chirho: 1024,
            max_output_bytes_chirho: 1024,
            warm_pool_size_chirho: 1,
        },
    )
    .unwrap();
    let (_node_chirho, node_hash_chirho) =
        native_worker_chirho::build_native_node_def_chirho(&root_chirho, &spec_hash_chirho, None)
            .unwrap();
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![node_hash_chirho.clone()],
        edges_chirho: vec![],
    };
    let dag_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &dag_obj_chirho).unwrap();

    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        "nativeinvokeapp",
        dag_hash_chirho,
        &owner_chirho,
    )
    .unwrap();
    let mut effect_prices_chirho = BTreeMap::new();
    effect_prices_chirho.insert("llm_chirho".to_string(), 17);
    let (book_hash_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "nativeinvokeapp",
        &owner_chirho,
        Some(1),
        effect_prices_chirho,
        0,
    )
    .unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: "ctx/native-invoke-user".to_string(),
        app_chirho: "nativeinvokeapp".to_string(),
        owner_principal_chirho: owner_chirho,
        client_id_chirho: "client/native-invoke".to_string(),
        token_hash_chirho: "token/native-invoke".to_string(),
        price_book_chirho: Some(book_hash_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let request_chirho = llm_request_bytes_chirho("native invoke paid");

    // The invoke node wraps a v2-gated llm_chirho paid target; with no served-LLM composition
    // injected, the target refuses at the uninstalled composition and that typed refusal propagates
    // up through the native invoke node. (Since S2b/S2c llm_chirho routes to the served ladder, not
    // the legacy road, so the propagated refusal is the served pre-effect one.)
    let refusal_chirho = run_dag_with_context_chirho(
        &root_chirho,
        &dag_obj_chirho,
        &request_chirho,
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(
        refusal_chirho.contains("served LLM provider composition is not installed"),
        "the invoke node propagates the paid target's served composition refusal: {refusal_chirho}"
    );
    assert!(
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(&root_chirho)
            .unwrap_or_default()
            .is_empty()
    );
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn native_invoke_node_inherits_nested_fuel_budget_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();

    let (mut target_node_chirho, _target_hash_chirho) = store_bytes_node_chirho(
        &root_chirho,
        "over_budget_upcase_chirho",
        include_str!("../../../examples-chirho/upcase-chirho.wat").as_bytes(),
        "upcase_chirho",
    );
    target_node_chirho.fuel_limit_chirho = 50_000_001;
    let target_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &target_node_chirho).unwrap();

    let executable_chirho = root_chirho.join("native-placeholder-chirho");
    std::fs::write(&executable_chirho, b"not-executed").unwrap();
    let (_spec_chirho, spec_hash_chirho) = native_worker_chirho::build_native_program_chirho(
        &root_chirho,
        &executable_chirho,
        native_worker_chirho::NativeProgramBuildRequestChirho {
            name_chirho: "native-invoke-budget-chirho".to_string(),
            argv_chirho: Vec::new(),
            sandbox_mode_chirho: native_worker_chirho::NativeSandboxModeChirho::BestEffortChirho,
            allowed_syscalls_chirho: native_worker_chirho::default_native_syscalls_chirho(),
            capabilities_chirho: vec![CapabilityChirho::InvokeChirho {
                node_chirho: target_hash_chirho,
            }],
            timeout_ms_chirho: 1000,
            max_memory_bytes_chirho: 16 * 1024 * 1024,
            max_input_bytes_chirho: 1024,
            max_output_bytes_chirho: 1024,
            warm_pool_size_chirho: 1,
        },
    )
    .unwrap();
    let (_node_chirho, node_hash_chirho) =
        native_worker_chirho::build_native_node_def_chirho(&root_chirho, &spec_hash_chirho, None)
            .unwrap();
    let dag_obj_chirho = DagChirho {
        nodes_chirho: vec![node_hash_chirho],
        edges_chirho: vec![],
    };

    let error_chirho = run_dag_chirho(&root_chirho, &dag_obj_chirho, b"hello")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("nested invoke budget"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
