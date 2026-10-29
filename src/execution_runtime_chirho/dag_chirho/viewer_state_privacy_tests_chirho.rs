// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::model_chirho::{CapabilityChirho, PortChirho};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-viewer-state-dag-privacy-{nanos_chirho}-{count_chirho}"
    ))
}

fn request_context_chirho() -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: "user/viewer-state-dag-chirho".to_string(),
        app_chirho: "viewer-state-dag-app-chirho".to_string(),
        owner_principal_chirho: "owner/viewer-state-dag-chirho".to_string(),
        client_id_chirho: "browser/viewer-state-dag-chirho".to_string(),
        token_hash_chirho: "token-viewer-state-dag-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn store_node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    wasm_chirho: &[u8],
    entry_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let wasm_hash_chirho = cas_chirho::add_chirho(root_chirho, wasm_chirho).expect("store wasm");
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").expect("store schema");
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: wasm_hash_chirho,
        entry_chirho: entry_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho,
        }],
        capabilities_chirho,
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    store_chirho::put_object_chirho(root_chirho, &node_chirho).expect("store node")
}

#[test]
fn private_input_scope_propagates_through_sink_and_cached_result_chirho() {
    let root_chirho = temp_root_chirho();
    let node_chirho = store_node_chirho(
        &root_chirho,
        "viewer_state_private_render_chirho",
        include_bytes!("../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        Vec::new(),
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![node_chirho],
        edges_chirho: Vec::new(),
    };
    let context_chirho = request_context_chirho();

    let first_chirho = run_dag_with_context_and_private_input_chirho(
        &root_chirho,
        &dag_chirho,
        &context_chirho.user_principal_chirho,
        b"private workspace title",
        Some(&context_chirho),
    )
    .expect("first private render");
    assert_eq!(first_chirho.payload_chirho, b"PRIVATE WORKSPACE TITLE");
    assert!(
        cas_chirho::get_chirho(&root_chirho, &first_chirho.payload_hash_chirho).is_err(),
        "a private sink payload must not rest in public CAS"
    );
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            &root_chirho,
            &context_chirho.user_principal_chirho,
            &first_chirho.payload_hash_chirho,
        )
        .expect("verify private output record")
        .is_some()
    );

    let second_chirho = run_dag_with_context_and_private_input_chirho(
        &root_chirho,
        &dag_chirho,
        &context_chirho.user_principal_chirho,
        b"private workspace title",
        Some(&context_chirho),
    )
    .expect("cached private render");
    assert!(second_chirho.node_runs_chirho[0].cached_chirho);
    assert_eq!(second_chirho.payload_chirho, first_chirho.payload_chirho);
    assert!(cas_chirho::get_chirho(&root_chirho, &second_chirho.payload_hash_chirho).is_err());

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn viewer_state_root_effect_refuses_public_input_before_cas_chirho() {
    let root_chirho = temp_root_chirho();
    let node_chirho = store_node_chirho(
        &root_chirho,
        "viewer_state_public_input_probe_chirho",
        b"not-executed-chirho",
        "not_executed_chirho",
        vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: effect_chirho::viewer_state_capability_prefix_chirho().to_string(),
        }],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![node_chirho],
        edges_chirho: Vec::new(),
    };
    let context_chirho = request_context_chirho();
    let request_chirho = br#"{"schema_chirho":"viewer-state-request-v1-chirho","action_chirho":"write-chirho","key_chirho":"workspace-name-chirho","value_base64_chirho":"c2VjcmV0"}"#;
    let request_hash_chirho = cas_chirho::hash_chirho(request_chirho);

    let error_chirho = run_dag_with_context_chirho(
        &root_chirho,
        &dag_chirho,
        request_chirho,
        Some(&context_chirho),
    )
    .expect_err("public viewer-state input must refuse");
    assert!(error_chirho.to_string().contains("private input plane"));
    assert!(
        cas_chirho::get_chirho(&root_chirho, &request_hash_chirho).is_err(),
        "refusal must happen before the request can enter public CAS"
    );
    assert!(!root_chirho.join("viewer-state-chirho.redb").exists());
    assert!(!root_chirho.join("effects-chirho").exists());

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn viewer_state_effect_refuses_an_unmarked_upstream_edge_before_execution_chirho() {
    let root_chirho = temp_root_chirho();
    let source_chirho = store_node_chirho(
        &root_chirho,
        "viewer_state_request_builder_chirho",
        include_bytes!("../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        Vec::new(),
    );
    let effect_node_chirho = store_node_chirho(
        &root_chirho,
        "viewer_state_unmarked_effect_chirho",
        b"not-executed-chirho",
        "not_executed_chirho",
        vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: effect_chirho::viewer_state_capability_prefix_chirho().to_string(),
        }],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![source_chirho.clone(), effect_node_chirho.clone()],
        edges_chirho: vec![EdgeChirho {
            from_node_chirho: source_chirho,
            from_port_chirho: "out".to_string(),
            to_node_chirho: effect_node_chirho,
            to_port_chirho: "in".to_string(),
            privacy_chirho: None,
        }],
    };
    let context_chirho = request_context_chirho();

    let error_chirho = run_dag_with_context_chirho(
        &root_chirho,
        &dag_chirho,
        b"must not execute",
        Some(&context_chirho),
    )
    .expect_err("unmarked viewer-state edge must refuse");
    assert!(error_chirho
        .to_string()
        .contains("request-user-private input edges"));
    assert!(!root_chirho.join("viewer-state-chirho.redb").exists());

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn viewer_state_effect_behind_private_edge_refuses_anonymous_dag_before_cas_chirho() {
    let root_chirho = temp_root_chirho();
    let source_chirho = store_node_chirho(
        &root_chirho,
        "viewer_state_anonymous_request_builder_chirho",
        include_bytes!("../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        Vec::new(),
    );
    let effect_node_chirho = store_node_chirho(
        &root_chirho,
        "viewer_state_anonymous_effect_chirho",
        b"not-executed-chirho",
        "not_executed_chirho",
        vec![CapabilityChirho::ReadStoreChirho {
            prefix_chirho: effect_chirho::viewer_state_capability_prefix_chirho().to_string(),
        }],
    );
    let dag_chirho = DagChirho {
        nodes_chirho: vec![source_chirho.clone(), effect_node_chirho.clone()],
        edges_chirho: vec![EdgeChirho {
            from_node_chirho: source_chirho,
            from_port_chirho: "out".to_string(),
            to_node_chirho: effect_node_chirho,
            to_port_chirho: "in".to_string(),
            privacy_chirho: Some(
                crate::model_chirho::EdgePrivacyChirho::PrivateBlobRefChirho {
                    subject_source_chirho:
                        crate::model_chirho::EdgePrivacySubjectSourceChirho::RequestUserChirho,
                },
            ),
        }],
    };
    let request_chirho = b"anonymous viewer-state request must never enter CAS";
    let request_hash_chirho = cas_chirho::hash_chirho(request_chirho);

    let error_chirho = run_dag_with_context_chirho(&root_chirho, &dag_chirho, request_chirho, None)
        .expect_err("an anonymous viewer-state DAG must refuse before upstream execution");
    assert!(error_chirho
        .to_string()
        .contains("viewer-state DAG requires a signed-in request user"));
    assert!(
        cas_chirho::get_chirho(&root_chirho, &request_hash_chirho).is_err(),
        "anonymous input must be refused before it enters public CAS"
    );
    assert!(!root_chirho.join("viewer-state-chirho.redb").exists());
    assert!(!root_chirho.join("effects-chirho").exists());

    let _ = std::fs::remove_dir_all(root_chirho);
}
