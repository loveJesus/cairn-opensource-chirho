// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::tests_chirho::{build_roster_chirho, NodeSpecChirho};
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_authority_chirho::{
    tenant_placement_intent_digest_chirho,
    unsigned_tenant_placement_held_observer_readiness_message_chirho,
    unsigned_tenant_placement_readiness_message_chirho,
    unsigned_tenant_placement_record_message_chirho, verify_tenant_placement_record_chirho,
    TenantPlacementHeldObserverReadinessReceiptChirho, TenantPlacementIntentChirho,
    TenantPlacementNodeBindingChirho, TenantPlacementNodeReadinessReceiptChirho,
    TenantPlacementRecordChirho, TenantPlacementResidencyChirho, VerifiedTenantPlacementChirho,
    TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO, TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO, TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO, TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO,
};
use std::path::PathBuf;

struct PlacementRosterFixtureChirho {
    _temp_chirho: tempfile::TempDir,
    roster_operator_root_chirho: PathBuf,
    roster_operator_key_chirho: String,
    roster_specs_chirho: Vec<NodeSpecChirho>,
    roster_lines_chirho: Vec<Vec<u8>>,
    roster_head_chirho: Vec<u8>,
    placement_chirho: VerifiedTenantPlacementChirho,
    held_observer_node_id_chirho: String,
    held_observer_raft_id_chirho: u64,
}

fn placement_roster_fixture_chirho(
    held_observer_region_chirho: &str,
    assigned_region_chirho: &str,
) -> PlacementRosterFixtureChirho {
    let temp_chirho = tempfile::tempdir().unwrap();
    let roster_operator_root_chirho = temp_chirho.path().join("roster-operator-chirho");
    let placement_root_chirho = temp_chirho.path().join("placement-operator-chirho");
    let plan_root_chirho = temp_chirho.path().join("plan-operator-chirho");
    for root_chirho in [
        &roster_operator_root_chirho,
        &placement_root_chirho,
        &plan_root_chirho,
    ] {
        sign_message_chirho(root_chirho, b"provision-authority-chirho").unwrap();
    }
    let roster_operator_key_chirho = pubkey_hex_chirho(&roster_operator_root_chirho).unwrap();
    let placement_key_chirho = pubkey_hex_chirho(&placement_root_chirho).unwrap();
    let plan_key_chirho = pubkey_hex_chirho(&plan_root_chirho).unwrap();

    let mut nodes_chirho = (0..4)
        .map(|index_chirho| {
            let root_chirho = temp_chirho
                .path()
                .join(format!("node-{index_chirho}-chirho"));
            sign_message_chirho(&root_chirho, b"provision-node-chirho").unwrap();
            let pubkey_chirho = pubkey_hex_chirho(&root_chirho).unwrap();
            let raft_id_chirho = 40 - u64::try_from(index_chirho).unwrap() * 10;
            (
                NodeSpecChirho {
                    pubkey_chirho,
                    raft_id_chirho,
                    wg_pubkey_chirho: format!("wg-{index_chirho}-chirho"),
                    mesh_ip_chirho: format!("10.101.0.{}", index_chirho + 1),
                    endpoint_chirho: format!("node-{index_chirho}-chirho:51820"),
                },
                root_chirho,
            )
        })
        .collect::<Vec<_>>();
    nodes_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho
            .0
            .pubkey_chirho
            .cmp(&right_chirho.0.pubkey_chirho)
    });
    let held_observer_chirho = nodes_chirho.pop().unwrap();

    let assigned_nodes_chirho = nodes_chirho
        .iter()
        .enumerate()
        .map(
            |(index_chirho, (spec_chirho, _root_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: spec_chirho.pubkey_chirho.clone(),
                failure_domain_chirho: FailureDomainChirho {
                    provider_chirho: format!("provider-{index_chirho}-chirho"),
                    region_chirho: assigned_region_chirho.to_string(),
                },
                expected_root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    char::from(b'a' + u8::try_from(index_chirho).unwrap())
                        .to_string()
                        .repeat(64)
                ),
                expected_cluster_config_blake3_chirho: char::from(
                    b'd' + u8::try_from(index_chirho).unwrap(),
                )
                .to_string()
                .repeat(64),
            },
        )
        .collect::<Vec<_>>();
    let held_observer_node_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: held_observer_chirho.0.pubkey_chirho.clone(),
        failure_domain_chirho: FailureDomainChirho {
            provider_chirho: "observer-provider-chirho".to_string(),
            region_chirho: held_observer_region_chirho.to_string(),
        },
        expected_root_binding_chirho: format!(
            "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
            "1".repeat(64)
        ),
        expected_cluster_config_blake3_chirho: "2".repeat(64),
    };
    let mut allowed_domains_chirho = assigned_nodes_chirho
        .iter()
        .map(|node_chirho| node_chirho.failure_domain_chirho.clone())
        .collect::<Vec<_>>();
    allowed_domains_chirho.sort();
    let intent_chirho = TenantPlacementIntentChirho {
        schema_chirho: TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        digest_domain_chirho: TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO.to_string(),
        revision_chirho: 0,
        previous_assignment_digest_chirho: None,
        tenant_id_chirho: "placement-join-chirho".to_string(),
        consistency_group_id_chirho: "tenant-chirho:placement-join-chirho".to_string(),
        preferred_node_chirho: assigned_nodes_chirho[0].node_id_chirho.clone(),
        assigned_nodes_chirho,
        held_observer_node_chirho,
        demand_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 500,
            memory_bytes_chirho: 1_024,
            durable_bytes_chirho: 4_096,
        },
        residency_chirho: TenantPlacementResidencyChirho {
            allowed_domains_chirho,
        },
        topology_plan_digest_chirho: "f".repeat(64),
    };
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&intent_chirho).unwrap();
    let serving_readiness_receipts_chirho = nodes_chirho
        .iter()
        .zip(&intent_chirho.assigned_nodes_chirho)
        .map(|((spec_chirho, root_chirho), node_chirho)| {
            let mut receipt_chirho = TenantPlacementNodeReadinessReceiptChirho {
                schema_chirho: TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO.to_string(),
                signature_domain_chirho: TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO
                    .to_string(),
                intent_digest_chirho: intent_digest_chirho.clone(),
                node_id_chirho: spec_chirho.pubkey_chirho.clone(),
                failure_domain_chirho: node_chirho.failure_domain_chirho.clone(),
                root_binding_chirho: node_chirho.expected_root_binding_chirho.clone(),
                cluster_config_blake3_chirho: node_chirho
                    .expected_cluster_config_blake3_chirho
                    .clone(),
                activation_anchor_digest_chirho: None,
                prepared_at_ms_chirho: 1_786_543_000_000,
                signer_key_id_chirho: spec_chirho.pubkey_chirho.clone(),
                sig_chirho: String::new(),
            };
            let message_chirho =
                unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho).unwrap();
            receipt_chirho.sig_chirho = sign_message_chirho(root_chirho, &message_chirho).unwrap();
            receipt_chirho
        })
        .collect::<Vec<_>>();
    let mut held_observer_receipt_chirho = TenantPlacementHeldObserverReadinessReceiptChirho {
        schema_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
            .to_string(),
        intent_digest_chirho: intent_digest_chirho.clone(),
        node_id_chirho: held_observer_chirho.0.pubkey_chirho.clone(),
        failure_domain_chirho: intent_chirho
            .held_observer_node_chirho
            .failure_domain_chirho
            .clone(),
        root_binding_chirho: intent_chirho
            .held_observer_node_chirho
            .expected_root_binding_chirho
            .clone(),
        cluster_config_blake3_chirho: intent_chirho
            .held_observer_node_chirho
            .expected_cluster_config_blake3_chirho
            .clone(),
        prepared_at_ms_chirho: 1_786_543_000_001,
        signer_key_id_chirho: held_observer_chirho.0.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_tenant_placement_held_observer_readiness_message_chirho(
        &held_observer_receipt_chirho,
    )
    .unwrap();
    held_observer_receipt_chirho.sig_chirho =
        sign_message_chirho(&held_observer_chirho.1, &message_chirho).unwrap();

    let mut record_chirho = TenantPlacementRecordChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        serving_readiness_receipts_chirho,
        held_observer_readiness_receipt_chirho: held_observer_receipt_chirho,
        placement_key_id_chirho: placement_key_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        sign_message_chirho(&placement_root_chirho, &message_chirho).unwrap();
    let placement_chirho = verify_tenant_placement_record_chirho(
        record_chirho,
        &placement_key_chirho,
        &roster_operator_key_chirho,
        &plan_key_chirho,
    )
    .unwrap();

    let mut roster_specs_chirho = nodes_chirho
        .into_iter()
        .map(|(spec_chirho, _root_chirho)| spec_chirho)
        .collect::<Vec<_>>();
    let held_observer_node_id_chirho = held_observer_chirho.0.pubkey_chirho.clone();
    let held_observer_raft_id_chirho = held_observer_chirho.0.raft_id_chirho;
    roster_specs_chirho.push(held_observer_chirho.0);
    let (roster_lines_chirho, roster_head_chirho) =
        build_roster_chirho(&roster_operator_root_chirho, &roster_specs_chirho);
    PlacementRosterFixtureChirho {
        _temp_chirho: temp_chirho,
        roster_operator_root_chirho,
        roster_operator_key_chirho,
        roster_specs_chirho,
        roster_lines_chirho,
        roster_head_chirho,
        placement_chirho,
        held_observer_node_id_chirho,
        held_observer_raft_id_chirho,
    }
}

#[test]
fn placement_roster_join_derives_three_voters_and_one_held_learner_chirho() {
    let fixture_chirho = placement_roster_fixture_chirho("region-chirho", "region-chirho");
    let local_node_chirho = &fixture_chirho.roster_specs_chirho[0].pubkey_chirho;
    let (config_chirho, evidence_chirho) = derive_tenant_placement_elector_config_chirho(
        &fixture_chirho.roster_lines_chirho,
        &fixture_chirho.roster_head_chirho,
        &fixture_chirho.roster_operator_key_chirho,
        local_node_chirho,
        &fixture_chirho.placement_chirho,
    )
    .unwrap();
    assert_eq!(config_chirho.members_chirho.len(), 4);
    assert_eq!(
        config_chirho
            .members_chirho
            .iter()
            .filter(|member_chirho| !member_chirho.learner_chirho)
            .count(),
        3
    );
    let held_chirho = config_chirho
        .members_chirho
        .iter()
        .find(|member_chirho| member_chirho.learner_chirho)
        .unwrap();
    assert_eq!(
        held_chirho.pubkey_chirho,
        fixture_chirho.held_observer_node_id_chirho
    );
    assert_eq!(
        held_chirho.raft_id_chirho,
        fixture_chirho.held_observer_raft_id_chirho
    );
    assert_eq!(evidence_chirho.assigned_node_ids_chirho.len(), 3);
    assert_eq!(evidence_chirho.assigned_raft_ids_chirho.len(), 3);
    assert_eq!(
        evidence_chirho.held_observer_node_id_chirho,
        fixture_chirho.held_observer_node_id_chirho
    );
    assert!(evidence_chirho.local_node_assigned_chirho);
    assert!(!evidence_chirho.local_node_held_observer_chirho);
}

#[test]
fn placement_roster_join_refuses_observer_region_disagreement_chirho() {
    let fixture_chirho = placement_roster_fixture_chirho("other-region-chirho", "region-chirho");
    let error_chirho = derive_tenant_placement_elector_config_chirho(
        &fixture_chirho.roster_lines_chirho,
        &fixture_chirho.roster_head_chirho,
        &fixture_chirho.roster_operator_key_chirho,
        &fixture_chirho.roster_specs_chirho[0].pubkey_chirho,
        &fixture_chirho.placement_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .starts_with("TenantPlacementRosterRegionDisagreementChirho:"));
}

#[test]
fn placement_roster_join_refuses_assigned_region_disagreement_by_identity_chirho() {
    let fixture_chirho = placement_roster_fixture_chirho("region-chirho", "other-region-chirho");
    let expected_node_chirho = fixture_chirho.placement_chirho.assigned_nodes_chirho()[0]
        .node_id_chirho
        .clone();
    let error_chirho = derive_tenant_placement_elector_config_chirho(
        &fixture_chirho.roster_lines_chirho,
        &fixture_chirho.roster_head_chirho,
        &fixture_chirho.roster_operator_key_chirho,
        &fixture_chirho.roster_specs_chirho[0].pubkey_chirho,
        &fixture_chirho.placement_chirho,
    )
    .unwrap_err();
    let detail_chirho = error_chirho.to_string();
    assert_eq!(
        detail_chirho,
        format!("TenantPlacementRosterRegionDisagreementChirho: {expected_node_chirho}")
    );
    assert!(!detail_chirho.starts_with("TenantPlacementRosterAssignedNodeInactiveChirho:"));
    assert!(!detail_chirho.starts_with("TenantPlacementRosterHeldObserverInactiveChirho:"));
}

#[test]
fn placement_roster_join_refuses_inactive_held_observer_chirho() {
    let fixture_chirho = placement_roster_fixture_chirho("region-chirho", "region-chirho");
    let (serving_lines_chirho, serving_head_chirho) = build_roster_chirho(
        &fixture_chirho.roster_operator_root_chirho,
        &fixture_chirho.roster_specs_chirho[..3],
    );
    let error_chirho = derive_tenant_placement_elector_config_chirho(
        &serving_lines_chirho,
        &serving_head_chirho,
        &fixture_chirho.roster_operator_key_chirho,
        &fixture_chirho.roster_specs_chirho[0].pubkey_chirho,
        &fixture_chirho.placement_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .starts_with("TenantPlacementRosterHeldObserverInactiveChirho:"));
}
