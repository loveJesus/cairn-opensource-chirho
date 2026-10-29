// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::{CapabilityChirho, PortChirho, SKIPPED_STONE_BYTES_CHIRHO};
use refusal_chirho::{
    dag_execution_refusal_observation_chirho, DagExecutionKnowledgeChirho,
    DagExecutionRefusalIdentityChirho,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_stage_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-dag-stage-test-chirho-{nanos_chirho}-{count_chirho}"
    ))
}

fn store_stage_node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    capability_chirho: Option<CapabilityChirho>,
    implementation_chirho: HashChirho,
) -> HashChirho {
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: implementation_chirho,
        entry_chirho: "run_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho,
        }],
        capabilities_chirho: capability_chirho.into_iter().collect(),
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
}

fn store_read_stage_node_chirho(root_chirho: &Path, key_chirho: &str) -> HashChirho {
    let implementation_chirho = cas_chirho::add_chirho(root_chirho, b"builtin:read").unwrap();
    store_stage_node_chirho(
        root_chirho,
        "stage_read_chirho",
        Some(CapabilityChirho::ReadStoreChirho {
            prefix_chirho: key_chirho.to_string(),
        }),
        implementation_chirho,
    )
}

fn store_invalid_pure_stage_node_chirho(root_chirho: &Path, name_chirho: &str) -> HashChirho {
    store_stage_node_chirho(
        root_chirho,
        name_chirho,
        None,
        HashChirho("missing-stage-wasm-object-chirho".to_string()),
    )
}

fn stage_edge_chirho(from_chirho: &HashChirho, to_chirho: &HashChirho) -> EdgeChirho {
    EdgeChirho {
        from_node_chirho: from_chirho.clone(),
        from_port_chirho: "out".to_string(),
        to_node_chirho: to_chirho.clone(),
        to_port_chirho: "in".to_string(),
        privacy_chirho: None,
    }
}

fn put_stage_value_chirho(root_chirho: &Path, key_chirho: &str, value_chirho: &[u8]) {
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    store_chirho.put_chirho(key_chirho, value_chirho).unwrap();
}

fn assert_stage_identity_chirho(
    error_chirho: &anyhow::Error,
    expected_chirho: DagExecutionRefusalIdentityChirho,
    expected_knowledge_chirho: DagExecutionKnowledgeChirho,
    neighbours_chirho: &[DagExecutionRefusalIdentityChirho],
) {
    let observation_chirho = dag_execution_refusal_observation_chirho(error_chirho);
    assert_eq!(observation_chirho.identity_chirho(), expected_chirho);
    assert_eq!(
        observation_chirho.execution_knowledge_chirho(),
        expected_knowledge_chirho
    );
    for neighbour_chirho in neighbours_chirho {
        assert_ne!(observation_chirho.identity_chirho(), *neighbour_chirho);
    }
}

#[test]
fn pure_failure_before_an_effect_is_not_post_effect_chirho() {
    let root_chirho = tmp_stage_root_chirho();
    let pure_chirho = store_invalid_pure_stage_node_chirho(&root_chirho, "pre_effect_chirho");
    let dag_chirho = DagChirho {
        nodes_chirho: vec![pure_chirho],
        edges_chirho: vec![],
    };

    let error_chirho = run_dag_chirho(&root_chirho, &dag_chirho, b"input").unwrap_err();
    assert_stage_identity_chirho(
        &error_chirho,
        DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho,
        DagExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        &[
            DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho,
            DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
        ],
    );
    assert_eq!(
        dag_execution_refusal_observation_chirho(&error_chirho).execution_knowledge_chirho(),
        DagExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn provider_terminal_then_effect_audit_failure_has_its_own_class_chirho() {
    let root_chirho = tmp_stage_root_chirho();
    put_stage_value_chirho(&root_chirho, "stage/audit", b"committed-response-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("effects-chirho"),
        b"blocks-effect-directory-chirho",
    )
    .unwrap();
    let effect_chirho = store_read_stage_node_chirho(&root_chirho, "stage/audit");
    let dag_chirho = DagChirho {
        nodes_chirho: vec![effect_chirho],
        edges_chirho: vec![],
    };

    let error_chirho = run_dag_chirho(&root_chirho, &dag_chirho, b"input").unwrap_err();
    assert_stage_identity_chirho(
        &error_chirho,
        DagExecutionRefusalIdentityChirho::DagEffectTerminalAuditRefusedChirho,
        DagExecutionKnowledgeChirho::MayHaveExecutedChirho,
        &[
            DagExecutionRefusalIdentityChirho::DagEffectProviderRefusedChirho,
            DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
        ],
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn effect_result_accounting_failure_is_not_terminal_audit_or_surface_chirho() {
    let root_chirho = tmp_stage_root_chirho();
    put_stage_value_chirho(&root_chirho, "stage/accounting", b"too-large-chirho");
    let effect_chirho = store_read_stage_node_chirho(&root_chirho, "stage/accounting");
    let dag_chirho = DagChirho {
        nodes_chirho: vec![effect_chirho],
        edges_chirho: vec![],
    };

    let error_chirho = run_dag_with_context_and_parents_and_output_cap_chirho(
        &root_chirho,
        &dag_chirho,
        DagRunInputChirho {
            value_chirho: DagInputValueChirho::PublicBytesChirho(b"input".to_vec()),
            admitted_request_chirho: None,
        },
        None,
        &[],
        1,
        effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho(),
    )
    .unwrap_err();
    assert_stage_identity_chirho(
        &error_chirho,
        DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
        DagExecutionKnowledgeChirho::MayHaveExecutedChirho,
        &[
            DagExecutionRefusalIdentityChirho::DagEffectTerminalAuditRefusedChirho,
            DagExecutionRefusalIdentityChirho::DagPostEffectSurfaceRefusedChirho,
        ],
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn downstream_pure_failure_after_effect_is_not_effect_accounting_chirho() {
    let root_chirho = tmp_stage_root_chirho();
    put_stage_value_chirho(&root_chirho, "stage/downstream", b"render-me-chirho");
    let effect_chirho = store_read_stage_node_chirho(&root_chirho, "stage/downstream");
    let pure_chirho = store_invalid_pure_stage_node_chirho(&root_chirho, "post_effect_chirho");
    let dag_chirho = DagChirho {
        nodes_chirho: vec![effect_chirho.clone(), pure_chirho.clone()],
        edges_chirho: vec![stage_edge_chirho(&effect_chirho, &pure_chirho)],
    };

    let error_chirho = run_dag_chirho(&root_chirho, &dag_chirho, b"input").unwrap_err();
    assert_stage_identity_chirho(
        &error_chirho,
        DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho,
        DagExecutionKnowledgeChirho::MayHaveExecutedChirho,
        &[
            DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho,
            DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
            DagExecutionRefusalIdentityChirho::DagPostEffectSurfaceRefusedChirho,
        ],
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn surface_failure_after_effect_is_not_downstream_pure_chirho() {
    let root_chirho = tmp_stage_root_chirho();
    put_stage_value_chirho(&root_chirho, "stage/surface", SKIPPED_STONE_BYTES_CHIRHO);
    let effect_chirho = store_read_stage_node_chirho(&root_chirho, "stage/surface");
    let dag_chirho = DagChirho {
        nodes_chirho: vec![effect_chirho],
        edges_chirho: vec![],
    };

    let error_chirho = run_dag_chirho(&root_chirho, &dag_chirho, b"input").unwrap_err();
    assert_stage_identity_chirho(
        &error_chirho,
        DagExecutionRefusalIdentityChirho::DagPostEffectSurfaceRefusedChirho,
        DagExecutionKnowledgeChirho::MayHaveExecutedChirho,
        &[
            DagExecutionRefusalIdentityChirho::DagPostEffectPureNodeRefusedChirho,
            DagExecutionRefusalIdentityChirho::DagEffectResultAccountingRefusedChirho,
        ],
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
