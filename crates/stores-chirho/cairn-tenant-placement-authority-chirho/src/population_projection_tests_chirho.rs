// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::population_projection_chirho::{
    load_and_project_tenant_placement_population_chirho,
    project_tenant_placement_population_bytes_chirho,
    render_tenant_placement_population_projection_chirho,
    tenant_placement_authority_pin_digest_chirho, TenantPlacementPopulationProjectionRefusalChirho,
    TENANT_PLACEMENT_AUTHORITY_PIN_DIGEST_PREFIX_V1_CHIRHO,
    TENANT_PLACEMENT_POPULATION_PROJECTION_SCHEMA_V2_CHIRHO,
};
use crate::tests_chirho::fixture_chirho;
use crate::{
    unsigned_tenant_placement_readiness_message_chirho,
    unsigned_tenant_placement_record_message_chirho, verify_tenant_placement_record_chirho,
    TenantPlacementRefusalChirho, TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO, TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::sign_message_chirho;

#[test]
fn projection_derives_only_bounded_non_identifying_population_fields_chirho() {
    let fixture_chirho = fixture_chirho();
    let expected_slot_anchors_chirho = fixture_chirho
        .record_chirho
        .intent_chirho
        .assigned_nodes_chirho
        .iter()
        .zip(
            &fixture_chirho
                .record_chirho
                .serving_readiness_receipts_chirho,
        )
        .map(|(node_chirho, receipt_chirho)| {
            (
                node_chirho.node_id_chirho.clone(),
                receipt_chirho
                    .activation_anchor_digest_chirho
                    .clone()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let record_bytes_chirho = serde_json::to_vec(&fixture_chirho.record_chirho).unwrap();
    let projection_chirho = project_tenant_placement_population_bytes_chirho(
        &record_bytes_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();

    assert_eq!(
        projection_chirho.schema_chirho,
        TENANT_PLACEMENT_POPULATION_PROJECTION_SCHEMA_V2_CHIRHO
    );
    assert_eq!(projection_chirho.assigned_node_count_chirho, 3);
    assert_eq!(projection_chirho.ordered_assigned_node_ids_chirho.len(), 3);
    assert_eq!(
        projection_chirho
            .ordered_activation_anchor_digests_chirho
            .len(),
        3
    );
    assert!(projection_chirho
        .ordered_activation_anchor_digests_chirho
        .iter()
        .all(|digest_chirho| digest_chirho.len() == 64));
    assert_eq!(
        projection_chirho
            .ordered_assigned_node_ids_chirho
            .iter()
            .cloned()
            .zip(
                projection_chirho
                    .ordered_activation_anchor_digests_chirho
                    .iter()
                    .cloned(),
            )
            .collect::<Vec<_>>(),
        expected_slot_anchors_chirho,
    );
    assert!(!projection_chirho
        .ordered_assigned_node_ids_chirho
        .contains(&projection_chirho.held_observer_node_id_chirho));
    assert!(projection_chirho
        .authority_pin_digest_chirho
        .starts_with(TENANT_PLACEMENT_AUTHORITY_PIN_DIGEST_PREFIX_V1_CHIRHO));

    let rendered_chirho =
        render_tenant_placement_population_projection_chirho(&projection_chirho).unwrap();
    for private_needle_chirho in [
        "credits-demo-chirho",
        "tenant-root-binding",
        "hetzner-chirho",
        "ovh-chirho",
        "de-fsn-chirho",
        fixture_chirho.placement_key_chirho.as_str(),
        fixture_chirho.roster_key_chirho.as_str(),
        fixture_chirho.plan_key_chirho.as_str(),
        "prepared_at_ms_chirho",
    ] {
        assert!(
            !rendered_chirho.contains(private_needle_chirho),
            "projection leaked private or authority input needle {private_needle_chirho}"
        );
    }
    assert!(!rendered_chirho.contains('/'));
}

#[test]
fn whitespace_transplant_changes_raw_sha_but_not_verified_assignment_chirho() {
    let fixture_chirho = fixture_chirho();
    let compact_chirho = serde_json::to_vec(&fixture_chirho.record_chirho).unwrap();
    let pretty_chirho = serde_json::to_vec_pretty(&fixture_chirho.record_chirho).unwrap();
    assert_ne!(compact_chirho, pretty_chirho);

    let compact_projection_chirho = project_tenant_placement_population_bytes_chirho(
        &compact_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    let pretty_projection_chirho = project_tenant_placement_population_bytes_chirho(
        &pretty_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();

    assert_eq!(
        compact_projection_chirho.assignment_digest_chirho,
        pretty_projection_chirho.assignment_digest_chirho
    );
    assert_ne!(
        compact_projection_chirho.record_sha256_chirho,
        pretty_projection_chirho.record_sha256_chirho
    );
}

#[test]
fn authority_pin_digest_binds_roster_and_geo_inputs_that_only_separate_keys_chirho() {
    let primary_fixture_chirho = fixture_chirho();
    let alternate_chirho = fixture_chirho();
    let record_bytes_chirho = serde_json::to_vec(&primary_fixture_chirho.record_chirho).unwrap();
    let expected_chirho = project_tenant_placement_population_bytes_chirho(
        &record_bytes_chirho,
        &primary_fixture_chirho.placement_key_chirho,
        &primary_fixture_chirho.roster_key_chirho,
        &primary_fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    let wrong_roster_chirho = project_tenant_placement_population_bytes_chirho(
        &record_bytes_chirho,
        &primary_fixture_chirho.placement_key_chirho,
        &alternate_chirho.roster_key_chirho,
        &primary_fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    let wrong_geo_chirho = project_tenant_placement_population_bytes_chirho(
        &record_bytes_chirho,
        &primary_fixture_chirho.placement_key_chirho,
        &primary_fixture_chirho.roster_key_chirho,
        &alternate_chirho.plan_key_chirho,
    )
    .unwrap();

    assert_eq!(
        expected_chirho.assignment_digest_chirho,
        wrong_roster_chirho.assignment_digest_chirho
    );
    assert_eq!(
        expected_chirho.assignment_digest_chirho,
        wrong_geo_chirho.assignment_digest_chirho
    );
    assert_ne!(
        expected_chirho.authority_pin_digest_chirho,
        wrong_roster_chirho.authority_pin_digest_chirho
    );
    assert_ne!(
        expected_chirho.authority_pin_digest_chirho,
        wrong_geo_chirho.authority_pin_digest_chirho
    );
}

#[test]
fn authority_pin_digest_has_cross_language_ordered_fixed_vector_chirho() {
    let placement_key_chirho = "11".repeat(32);
    let roster_key_chirho = "22".repeat(32);
    let geo_key_chirho = "33".repeat(32);

    assert_eq!(
        tenant_placement_authority_pin_digest_chirho(
            &placement_key_chirho,
            &roster_key_chirho,
            &geo_key_chirho,
        )
        .unwrap(),
        "tenant-placement-authority-pins-sha256-v1-chirho:\
9ac96677ff3c6d098bc710218e33a5f2558850385d4e370bc66cbd8d4ec9aaa9"
    );
}

#[test]
fn same_count_node_substitution_refuses_as_binding_not_population_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut altered_chirho = fixture_chirho.record_chirho;
    let replacement_chirho = "0".repeat(64);
    altered_chirho.intent_chirho.assigned_nodes_chirho[0].node_id_chirho =
        replacement_chirho.clone();
    altered_chirho.intent_chirho.preferred_node_chirho = replacement_chirho;
    let error_chirho = project_tenant_placement_population_bytes_chirho(
        &serde_json::to_vec(&altered_chirho).unwrap(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap_err();

    assert_eq!(
        error_chirho,
        TenantPlacementPopulationProjectionRefusalChirho::RecordVerificationChirho(
            TenantPlacementRefusalChirho::IntentDigestChirho
        )
    );
    assert_ne!(
        error_chirho,
        TenantPlacementPopulationProjectionRefusalChirho::RecordVerificationChirho(
            TenantPlacementRefusalChirho::AssignedNodePopulationChirho
        )
    );
}

#[test]
fn valid_v1_placement_never_falls_back_to_an_applicability_projection_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut legacy_record_chirho = fixture_chirho.record_chirho.clone();
    legacy_record_chirho.schema_chirho = TENANT_PLACEMENT_RECORD_SCHEMA_V1_CHIRHO.to_owned();
    legacy_record_chirho.signature_domain_chirho =
        TENANT_PLACEMENT_RECORD_DOMAIN_V1_CHIRHO.to_owned();
    for (receipt_chirho, node_root_chirho) in legacy_record_chirho
        .serving_readiness_receipts_chirho
        .iter_mut()
        .zip(&fixture_chirho.serving_node_roots_chirho)
    {
        receipt_chirho.schema_chirho = TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V1_CHIRHO.to_owned();
        receipt_chirho.signature_domain_chirho =
            TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V1_CHIRHO.to_owned();
        receipt_chirho.activation_anchor_digest_chirho = None;
        receipt_chirho.sig_chirho = sign_message_chirho(
            node_root_chirho,
            &unsigned_tenant_placement_readiness_message_chirho(receipt_chirho).unwrap(),
        )
        .unwrap();
    }
    legacy_record_chirho.sig_chirho = sign_message_chirho(
        &fixture_chirho.placement_root_chirho,
        &unsigned_tenant_placement_record_message_chirho(&legacy_record_chirho).unwrap(),
    )
    .unwrap();
    verify_tenant_placement_record_chirho(
        legacy_record_chirho.clone(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();

    assert_eq!(
        project_tenant_placement_population_bytes_chirho(
            &serde_json::to_vec(&legacy_record_chirho).unwrap(),
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        )
        .unwrap_err(),
        TenantPlacementPopulationProjectionRefusalChirho::ActivationAnchorRequiredChirho
    );
}

#[test]
fn v2_receipt_missing_its_anchor_refuses_without_population_fallback_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut missing_anchor_chirho = fixture_chirho.record_chirho.clone();
    let receipt_chirho = &mut missing_anchor_chirho.serving_readiness_receipts_chirho[0];
    receipt_chirho.activation_anchor_digest_chirho = None;
    receipt_chirho.sig_chirho = sign_message_chirho(
        &fixture_chirho.serving_node_roots_chirho[0],
        &unsigned_tenant_placement_readiness_message_chirho(receipt_chirho).unwrap(),
    )
    .unwrap();
    missing_anchor_chirho.sig_chirho = sign_message_chirho(
        &fixture_chirho.placement_root_chirho,
        &unsigned_tenant_placement_record_message_chirho(&missing_anchor_chirho).unwrap(),
    )
    .unwrap();
    let refusal_chirho = project_tenant_placement_population_bytes_chirho(
        &serde_json::to_vec(&missing_anchor_chirho).unwrap(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        TenantPlacementPopulationProjectionRefusalChirho::RecordVerificationChirho(
            TenantPlacementRefusalChirho::ActivationAnchorBindingChirho
        )
    );
    assert_ne!(
        refusal_chirho,
        TenantPlacementPopulationProjectionRefusalChirho::RecordVerificationChirho(
            TenantPlacementRefusalChirho::ReadinessPopulationChirho
        )
    );
}

#[test]
fn held_observer_cannot_enter_the_projected_assigned_population_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut altered_chirho = fixture_chirho.record_chirho;
    altered_chirho.intent_chirho.assigned_nodes_chirho[2] = altered_chirho
        .intent_chirho
        .held_observer_node_chirho
        .clone();
    let error_chirho = project_tenant_placement_population_bytes_chirho(
        &serde_json::to_vec(&altered_chirho).unwrap(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap_err();

    assert_eq!(
        error_chirho,
        TenantPlacementPopulationProjectionRefusalChirho::RecordVerificationChirho(
            TenantPlacementRefusalChirho::HeldObserverIdentityChirho
        )
    );
}

#[test]
fn projection_loader_reads_one_bounded_regular_record_population_chirho() {
    let fixture_chirho = fixture_chirho();
    let temp_chirho = tempfile::tempdir().unwrap();
    let record_path_chirho = temp_chirho.path().join("placement-record-chirho.json");
    std::fs::write(
        &record_path_chirho,
        serde_json::to_vec(&fixture_chirho.record_chirho).unwrap(),
    )
    .unwrap();
    let projection_chirho = load_and_project_tenant_placement_population_chirho(
        &record_path_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .unwrap();
    assert_eq!(projection_chirho.assigned_node_count_chirho, 3);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link_chirho = temp_chirho.path().join("linked-placement-chirho.json");
        symlink(&record_path_chirho, &link_chirho).unwrap();
        assert_eq!(
            load_and_project_tenant_placement_population_chirho(
                &link_chirho,
                &fixture_chirho.placement_key_chirho,
                &fixture_chirho.roster_key_chirho,
                &fixture_chirho.plan_key_chirho,
            )
            .unwrap_err(),
            TenantPlacementPopulationProjectionRefusalChirho::StoreEntryTypeChirho
        );
    }
}
