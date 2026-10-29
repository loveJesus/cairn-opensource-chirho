// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::undo_plan_binding_chirho::{
    derive_and_store_app_source_undo_plan_bindings_chirho,
    load_verified_app_source_undo_plan_reviews_chirho,
    validate_descriptor_v2_node_with_authority_chirho, verify_app_source_undo_plan_bindings_chirho,
};
use super::{
    review_app_source_candidate_chirho, validate_reviewed_source_report_for_promotion_chirho,
    AppSourceCandidateReportChirho, AppSourceCandidateRouteReportChirho,
    APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO,
};
use crate::blessed_chirho::registry_v2_message_from_contract_set_chirho;
use crate::model_chirho::{CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho};
use crate::{cas_chirho, store_chirho};
use cairn_ledger_model_chirho::asset_op_chirho::ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO;
use cairn_undo_plan_chirho::canonical_chirho::{
    canonical_undo_plan_bytes_chirho, contract_set_digest_chirho, parse_canonical_undo_plan_chirho,
    undo_plan_hash_chirho,
};
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, AssetOpPortRequirementChirho,
    BlessedContractKeyChirho,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

fn tmp_root_chirho() -> PathBuf {
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let unique_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-undo-plan-binding-test-{nanos_chirho}-{unique_chirho}-chirho"
    ))
}

fn stored_dag_chirho(
    root_chirho: &std::path::Path,
    label_chirho: &str,
    capability_chirho: CapabilityChirho,
) -> HashChirho {
    stored_capabilities_dag_chirho(root_chirho, label_chirho, vec![capability_chirho])
}

fn stored_capabilities_dag_chirho(
    root_chirho: &std::path::Path,
    label_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let node_chirho = NodeDefChirho {
        name_chirho: format!("{label_chirho}-node-chirho"),
        capabilities_chirho,
        effect_contract_set_chirho: Some(
            contract_set_digest_chirho(&canonical_authoring_reversion_contract_set_chirho())
                .unwrap(),
        ),
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

fn stored_write_dag_chirho(root_chirho: &std::path::Path, label_chirho: &str) -> HashChirho {
    stored_dag_chirho(
        root_chirho,
        label_chirho,
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: format!("{label_chirho}-records-chirho"),
        },
    )
}

fn candidate_chirho(
    root_dag_chirho: HashChirho,
    route_dag_chirho: HashChirho,
) -> AppSourceCandidateReportChirho {
    AppSourceCandidateReportChirho {
        request_access_policy_chirho: None,
        schema_chirho: APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO.to_string(),
        source_manifest_chirho: None,
        app_chirho: "undo-plan-binding-app-chirho".to_string(),
        owner_chirho: "owner/undo-plan-binding-chirho".to_string(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        undo_plan_bindings_chirho: None,
        root_dag_chirho,
        input_mode_chirho: None,
        request_body_policy_chirho: None,
        response_content_type_chirho: None,
        routes_chirho: vec![
            AppSourceCandidateRouteReportChirho {
                route_chirho: "first-chirho".to_string(),
                dag_chirho: route_dag_chirho.clone(),
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                key_access_chirho: None,
            },
            AppSourceCandidateRouteReportChirho {
                route_chirho: "same-dag-again-chirho".to_string(),
                dag_chirho: route_dag_chirho,
                input_mode_chirho: None,
                request_body_policy_chirho: None,
                response_content_type_chirho: None,
                key_access_chirho: None,
            },
        ],
    }
}

fn rewrite_first_dag_node_chirho(
    root_chirho: &std::path::Path,
    dag_hash_chirho: &HashChirho,
    rewrite_chirho: impl FnOnce(&mut NodeDefChirho),
) -> HashChirho {
    let mut dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, dag_hash_chirho).unwrap();
    let mut node_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(root_chirho, &dag_chirho.nodes_chirho[0]).unwrap();
    rewrite_chirho(&mut node_chirho);
    dag_chirho.nodes_chirho[0] =
        store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
}

fn point_candidate_at_one_dag_chirho(
    candidate_chirho: &mut AppSourceCandidateReportChirho,
    dag_chirho: HashChirho,
) {
    candidate_chirho.root_dag_chirho = dag_chirho.clone();
    for route_chirho in &mut candidate_chirho.routes_chirho {
        route_chirho.dag_chirho = dag_chirho.clone();
    }
}

#[test]
fn descriptor_v2_verifier_requires_exact_asset_op_port_schema_chirho() {
    let mut contract_set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let contract_chirho = contract_set_chirho
        .contracts_chirho
        .iter_mut()
        .find(|contract_chirho| {
            contract_chirho.contract_key_chirho == BlessedContractKeyChirho("llm-chirho".to_owned())
        })
        .unwrap();
    contract_chirho.asset_op_ports_chirho = vec![AssetOpPortRequirementChirho {
        port_chirho: "asset-op-chirho".to_owned(),
        schema_chirho: HashChirho(ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO.to_owned()),
    }];
    let set_digest_chirho = contract_set_digest_chirho(&contract_set_chirho).unwrap();
    let registry_chirho =
        registry_v2_message_from_contract_set_chirho(&contract_set_chirho).unwrap();
    let mut node_chirho = NodeDefChirho {
        name_chirho: "asset-op-deploy-node-chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "asset-op-chirho".to_owned(),
            schema_chirho: HashChirho(ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO.to_owned()),
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_owned(),
            caller_chirho: "descriptor-caller-chirho".to_owned(),
        }],
        effect_contract_set_chirho: Some(set_digest_chirho.clone()),
        ..Default::default()
    };
    validate_descriptor_v2_node_with_authority_chirho(
        &node_chirho,
        &contract_set_chirho,
        &registry_chirho,
        &set_digest_chirho,
    )
    .unwrap();

    node_chirho.inputs_chirho[0].schema_chirho = HashChirho("0".repeat(64));
    let error_chirho = validate_descriptor_v2_node_with_authority_chirho(
        &node_chirho,
        &contract_set_chirho,
        &registry_chirho,
        &set_digest_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("does not name the canonical schema"));
}

#[test]
fn root_and_route_dags_receive_complete_deduplicated_bindings_chirho() {
    let root_chirho = tmp_root_chirho();
    let root_dag_chirho = stored_write_dag_chirho(&root_chirho, "root");
    let route_dag_chirho = stored_capabilities_dag_chirho(
        &root_chirho,
        "route",
        vec![
            CapabilityChirho::QueryChirho {
                prefix_chirho: "private-query-scope-chirho".into(),
                caller_chirho: "private-query-caller-chirho".into(),
                max_rows_chirho: 50,
            },
            CapabilityChirho::UserIdentityChirho {
                principal_chirho: "private-query-caller-chirho".into(),
                client_id_chirho: "private-client-chirho".into(),
                token_hash_chirho: "private-token-hash-chirho".into(),
            },
        ],
    );
    let executable_dags_chirho =
        BTreeSet::from([root_dag_chirho.clone(), route_dag_chirho.clone()]);
    let bindings_chirho = derive_and_store_app_source_undo_plan_bindings_chirho(
        &root_chirho,
        &executable_dags_chirho,
    )
    .unwrap();
    assert_eq!(bindings_chirho.len(), 2);
    assert!(bindings_chirho[0].dag_chirho < bindings_chirho[1].dag_chirho);

    let mut candidate_chirho = candidate_chirho(root_dag_chirho, route_dag_chirho);
    candidate_chirho.undo_plan_bindings_chirho = Some(bindings_chirho);
    verify_app_source_undo_plan_bindings_chirho(&root_chirho, &candidate_chirho).unwrap();
    let reviews_chirho =
        load_verified_app_source_undo_plan_reviews_chirho(&root_chirho, &candidate_chirho).unwrap();
    assert_eq!(reviews_chirho.len(), 2);
    assert!(reviews_chirho
        .iter()
        .all(|review_chirho| review_chirho.effect_count_chirho == 1));
    let write_review_chirho = reviews_chirho
        .iter()
        .find(|review_chirho| {
            review_chirho.doors_chirho[0].effect_kind_chirho == "write-store-chirho"
        })
        .unwrap();
    assert_eq!(
        write_review_chirho.doors_chirho[0].contract_chirho,
        "write-store-chirho"
    );
    let query_review_chirho = reviews_chirho
        .iter()
        .find(|review_chirho| review_chirho.doors_chirho[0].effect_kind_chirho == "query-chirho")
        .unwrap();
    assert_eq!(
        query_review_chirho.doors_chirho[0].supporting_kinds_chirho,
        vec!["user-identity-chirho"]
    );
    assert_eq!(
        query_review_chirho.doors_chirho[0].privacy_class_chirho,
        "direct-chirho"
    );
    let redacted_chirho = format!("{reviews_chirho:?}");
    assert!(!redacted_chirho.contains("root-records-chirho"));
    for private_value_chirho in [
        "private-query-scope-chirho",
        "private-query-caller-chirho",
        "private-client-chirho",
        "private-token-hash-chirho",
    ] {
        assert!(!redacted_chirho.contains(private_value_chirho));
    }

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn partial_mixed_and_cross_dag_plan_bindings_fail_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let root_dag_chirho = stored_write_dag_chirho(&root_chirho, "root");
    let route_dag_chirho = stored_write_dag_chirho(&root_chirho, "route");
    let executable_dags_chirho =
        BTreeSet::from([root_dag_chirho.clone(), route_dag_chirho.clone()]);
    let bindings_chirho = derive_and_store_app_source_undo_plan_bindings_chirho(
        &root_chirho,
        &executable_dags_chirho,
    )
    .unwrap();
    let mut candidate_chirho = candidate_chirho(root_dag_chirho, route_dag_chirho);
    candidate_chirho.undo_plan_bindings_chirho = Some(bindings_chirho);

    let mut promotion_report_chirho =
        review_app_source_candidate_chirho(&root_chirho, candidate_chirho.clone()).unwrap();
    promotion_report_chirho
        .candidate_chirho
        .undo_plan_bindings_chirho
        .as_mut()
        .unwrap()
        .pop();
    assert!(validate_reviewed_source_report_for_promotion_chirho(
        &root_chirho,
        &promotion_report_chirho.candidate_chirho.app_chirho,
        &promotion_report_chirho.candidate_chirho.owner_chirho,
        &promotion_report_chirho,
        None,
    )
    .unwrap_err()
    .to_string()
    .contains("exactly cover"));

    let mut partial_chirho = candidate_chirho.clone();
    partial_chirho
        .undo_plan_bindings_chirho
        .as_mut()
        .unwrap()
        .pop();
    assert!(
        verify_app_source_undo_plan_bindings_chirho(&root_chirho, &partial_chirho)
            .unwrap_err()
            .to_string()
            .contains("exactly cover")
    );
    assert!(
        review_app_source_candidate_chirho(&root_chirho, partial_chirho)
            .unwrap_err()
            .to_string()
            .contains("exactly cover")
    );

    let mut mixed_chirho = candidate_chirho.clone();
    mixed_chirho.undo_plan_bindings_chirho.as_mut().unwrap()[0].contract_set_digest_chirho =
        HashChirho("0".repeat(64));
    assert!(
        verify_app_source_undo_plan_bindings_chirho(&root_chirho, &mixed_chirho)
            .unwrap_err()
            .to_string()
            .contains("mixes or drifts")
    );

    let mut crossed_chirho = candidate_chirho;
    let bindings_chirho = crossed_chirho.undo_plan_bindings_chirho.as_mut().unwrap();
    let first_plan_cas_chirho = bindings_chirho[0].plan_cas_chirho.clone();
    bindings_chirho[0].plan_cas_chirho = bindings_chirho[1].plan_cas_chirho.clone();
    bindings_chirho[1].plan_cas_chirho = first_plan_cas_chirho;
    assert!(
        verify_app_source_undo_plan_bindings_chirho(&root_chirho, &crossed_chirho)
            .unwrap_err()
            .to_string()
            .contains("source DAG differs")
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn self_consistent_plan_from_wrong_dag_fails_exact_rederivation_chirho() {
    let root_chirho = tmp_root_chirho();
    let target_dag_chirho = stored_write_dag_chirho(&root_chirho, "target");
    let donor_dag_chirho = stored_write_dag_chirho(&root_chirho, "donor");
    let mut forged_binding_chirho = derive_and_store_app_source_undo_plan_bindings_chirho(
        &root_chirho,
        &BTreeSet::from([donor_dag_chirho]),
    )
    .unwrap()
    .remove(0);
    let donor_bytes_chirho =
        cas_chirho::get_chirho(&root_chirho, &forged_binding_chirho.plan_cas_chirho).unwrap();
    let mut forged_plan_chirho =
        parse_canonical_undo_plan_chirho(std::str::from_utf8(&donor_bytes_chirho).unwrap())
            .unwrap();
    forged_plan_chirho.source_dag_chirho = target_dag_chirho.clone();
    let forged_bytes_chirho = canonical_undo_plan_bytes_chirho(&forged_plan_chirho).unwrap();
    forged_binding_chirho.dag_chirho = target_dag_chirho.clone();
    forged_binding_chirho.plan_cas_chirho =
        cas_chirho::add_chirho(&root_chirho, &forged_bytes_chirho).unwrap();
    forged_binding_chirho.plan_digest_chirho = undo_plan_hash_chirho(&forged_plan_chirho).unwrap();

    let mut candidate_chirho = candidate_chirho(target_dag_chirho.clone(), target_dag_chirho);
    candidate_chirho.undo_plan_bindings_chirho = Some(vec![forged_binding_chirho]);
    assert!(
        verify_app_source_undo_plan_bindings_chirho(&root_chirho, &candidate_chirho)
            .unwrap_err()
            .to_string()
            .contains("exact re-derivation")
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pre_v2_candidate_without_plan_claim_remains_readable_chirho() {
    let root_chirho = tmp_root_chirho();
    let root_dag_chirho = stored_write_dag_chirho(&root_chirho, "legacy-root");
    let candidate_chirho = candidate_chirho(root_dag_chirho.clone(), root_dag_chirho);
    verify_app_source_undo_plan_bindings_chirho(&root_chirho, &candidate_chirho).unwrap();
    assert!(
        load_verified_app_source_undo_plan_reviews_chirho(&root_chirho, &candidate_chirho)
            .unwrap()
            .is_empty()
    );
    assert!(
        review_app_source_candidate_chirho(&root_chirho, candidate_chirho)
            .unwrap_err()
            .to_string()
            .contains("requires complete undo-plan bindings")
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn review_refuses_missing_stale_and_unknown_descriptor_v2_bindings_chirho() {
    let root_chirho = tmp_root_chirho();
    let valid_dag_chirho = stored_write_dag_chirho(&root_chirho, "descriptor-v2");
    let bindings_chirho = derive_and_store_app_source_undo_plan_bindings_chirho(
        &root_chirho,
        &BTreeSet::from([valid_dag_chirho.clone()]),
    )
    .unwrap();
    let mut valid_candidate_chirho =
        candidate_chirho(valid_dag_chirho.clone(), valid_dag_chirho.clone());
    valid_candidate_chirho.undo_plan_bindings_chirho = Some(bindings_chirho);

    let missing_dag_chirho =
        rewrite_first_dag_node_chirho(&root_chirho, &valid_dag_chirho, |node_chirho| {
            node_chirho.effect_contract_set_chirho = None
        });
    let mut missing_candidate_chirho = valid_candidate_chirho.clone();
    point_candidate_at_one_dag_chirho(&mut missing_candidate_chirho, missing_dag_chirho);
    assert!(
        review_app_source_candidate_chirho(&root_chirho, missing_candidate_chirho)
            .unwrap_err()
            .to_string()
            .contains("does not name the current verified contract set")
    );

    let stale_dag_chirho =
        rewrite_first_dag_node_chirho(&root_chirho, &valid_dag_chirho, |node_chirho| {
            node_chirho.effect_contract_set_chirho = Some(HashChirho("0".repeat(64)));
        });
    let mut stale_candidate_chirho = valid_candidate_chirho.clone();
    point_candidate_at_one_dag_chirho(&mut stale_candidate_chirho, stale_dag_chirho);
    assert!(
        review_app_source_candidate_chirho(&root_chirho, stale_candidate_chirho)
            .unwrap_err()
            .to_string()
            .contains("does not name the current verified contract set")
    );

    let unknown_dag_chirho =
        rewrite_first_dag_node_chirho(&root_chirho, &valid_dag_chirho, |node_chirho| {
            node_chirho.capabilities_chirho = vec![CapabilityChirho::PaidEffectChirho {
                effect_chirho: "unknown-paid-subtype-chirho".into(),
                caller_chirho: "user/descriptor-v2-chirho".into(),
            }];
        });
    let mut unknown_candidate_chirho = valid_candidate_chirho;
    point_candidate_at_one_dag_chirho(&mut unknown_candidate_chirho, unknown_dag_chirho);
    assert!(
        review_app_source_candidate_chirho(&root_chirho, unknown_candidate_chirho)
            .unwrap_err()
            .to_string()
            .contains("effect coordinate is not registered under blessed registry v2")
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn candidate_plan_derivation_rejects_uncontracted_effect_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_chirho = stored_dag_chirho(
        &root_chirho,
        "uncontracted-paid",
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: "echo_paid_chirho".to_string(),
            caller_chirho: "user/demo-chirho".to_string(),
        },
    );
    let error_chirho = derive_and_store_app_source_undo_plan_bindings_chirho(
        &root_chirho,
        &BTreeSet::from([dag_chirho]),
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("effect coordinate is not registered under blessed registry v2"));
    let _ = std::fs::remove_dir_all(root_chirho);
}
