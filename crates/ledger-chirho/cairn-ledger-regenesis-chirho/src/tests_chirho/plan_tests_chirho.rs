// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::money_stage_chirho::prepare_money_stage_chirho;
use crate::plan_chirho::load_verified_plan_chirho;

fn assert_namespace_layout_refuses_without_any_namespace_write_chirho(
    mutate_plan_chirho: impl FnOnce(&mut LedgerRegenesisPlanV1Chirho),
    config_from_chirho: &str,
    config_to_chirho: &str,
) {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    mutate_plan_chirho(&mut plan_chirho);
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho).unwrap();
    let updated_config_chirho = config_chirho.replace(config_from_chirho, config_to_chirho);
    assert_ne!(updated_config_chirho, config_chirho);
    fs::write(&fixture_chirho.config_path_chirho, updated_config_chirho).unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::NamespaceLayoutRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn canonical_plan_dually_binds_raw_bytes_and_review_digest_chirho() {
    let fixture_chirho = fixture_chirho();
    let verified_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &fixture_chirho.expected_digest_chirho,
    )
    .unwrap();
    assert_eq!(
        verified_chirho.plan_digest_chirho,
        fixture_chirho.expected_digest_chirho
    );
    assert_eq!(verified_chirho.storage_child_chirho, "ledger-chirho");
    assert_eq!(verified_chirho.monitor_child_chirho, "ops-chirho");
}

#[test]
fn identity_shaped_initial_owner_reaches_verified_plan_without_writes_chirho() {
    for owner_chirho in ["user/0123456789abcdef", "owner/fedcba9876543210"] {
        let mut fixture_chirho = fixture_chirho();
        bind_fixture_initial_owner_chirho(&mut fixture_chirho, owner_chirho);
        let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
        let verified_chirho = load_verified_plan_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.config_path_chirho,
            &fixture_chirho.plan_path_chirho,
            &fixture_chirho.expected_digest_chirho,
        )
        .unwrap();
        assert_eq!(
            verified_chirho.plan_chirho.initial_owner_chirho,
            owner_chirho
        );
        assert_eq!(
            verified_chirho.config_chirho.members_chirho[0].owner_chirho,
            owner_chirho
        );
        assert_eq!(
            snapshot_tree_chirho(&fixture_chirho.root_chirho),
            before_chirho
        );
    }
}

#[test]
fn identity_shaped_member_cannot_replace_the_plan_issuer_chirho() {
    let owner_chirho = "user/0123456789abcdef";
    let mut fixture_chirho = fixture_chirho();
    bind_fixture_initial_owner_chirho(&mut fixture_chirho, owner_chirho);
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.issuer_principal_chirho = owner_chirho.to_owned();
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &fixture_chirho.expected_digest_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn noncanonical_plan_refuses_even_when_raw_digest_was_reviewed_chirho() {
    let fixture_chirho = fixture_chirho();
    let canonical_chirho = fs::read(&fixture_chirho.plan_path_chirho).unwrap();
    let mut noncanonical_chirho = canonical_chirho.clone();
    noncanonical_chirho.push(b'\n');
    fs::write(&fixture_chirho.plan_path_chirho, &noncanonical_chirho).unwrap();
    let raw_digest_chirho = plan_digest_chirho(&noncanonical_chirho);
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &raw_digest_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::PlanNonCanonicalChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn expected_digest_mismatch_refuses_without_any_namespace_write_chirho() {
    let fixture_chirho = fixture_chirho();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &"0".repeat(64),
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::PlanDigestMismatchChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn config_namespace_cross_check_refuses_before_staging_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.storage_namespace_chirho =
        "fresh-ledger-parent-chirho/other-ledger-chirho".to_owned();
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &fixture_chirho.expected_digest_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::ConfigPlanMismatchChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn fresh_and_staging_parent_equality_refuses_without_any_namespace_write_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.staging_parent_chirho = plan_chirho.fresh_parent_chirho.clone();
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::NamespaceLayoutRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn namespace_outside_fresh_parent_refuses_without_any_namespace_write_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.storage_namespace_chirho = "foreign-parent-chirho/ledger-chirho".to_owned();
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho)
        .unwrap()
        .replace(
            "storage_namespace_chirho = \"fresh-ledger-parent-chirho/ledger-chirho\"",
            "storage_namespace_chirho = \"foreign-parent-chirho/ledger-chirho\"",
        );
    fs::write(&fixture_chirho.config_path_chirho, config_chirho).unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::NamespaceLayoutRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn fixed_storage_object_paths_must_be_injective_before_any_namespace_write_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.kind_registry_path_chirho = plan_chirho.journal_path_chirho.clone();
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho)
        .unwrap()
        .replace(
            "kind_registry_path_chirho = \"registries/kinds-chirho.jsonl\"",
            "kind_registry_path_chirho = \"journals/main-chirho.jsonl\"",
        );
    fs::write(&fixture_chirho.config_path_chirho, config_chirho).unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn namespace_shape_and_monitor_parent_containment_refuse_without_writes_chirho() {
    assert_namespace_layout_refuses_without_any_namespace_write_chirho(
        |plan_chirho| {
            plan_chirho.storage_namespace_chirho =
                "fresh-ledger-parent-chirho/ledger-chirho/extra-chirho".to_owned();
        },
        "storage_namespace_chirho = \"fresh-ledger-parent-chirho/ledger-chirho\"",
        "storage_namespace_chirho = \"fresh-ledger-parent-chirho/ledger-chirho/extra-chirho\"",
    );
    assert_namespace_layout_refuses_without_any_namespace_write_chirho(
        |plan_chirho| {
            plan_chirho.monitor_evidence_namespace_chirho =
                "fresh-ledger-parent-chirho/ops-chirho/extra-chirho".to_owned();
        },
        "monitor_evidence_namespace_chirho = \"fresh-ledger-parent-chirho/ops-chirho\"",
        "monitor_evidence_namespace_chirho = \"fresh-ledger-parent-chirho/ops-chirho/extra-chirho\"",
    );
    assert_namespace_layout_refuses_without_any_namespace_write_chirho(
        |plan_chirho| {
            plan_chirho.monitor_evidence_namespace_chirho =
                "foreign-parent-chirho/ops-chirho".to_owned();
        },
        "monitor_evidence_namespace_chirho = \"fresh-ledger-parent-chirho/ops-chirho\"",
        "monitor_evidence_namespace_chirho = \"foreign-parent-chirho/ops-chirho\"",
    );
}

#[test]
fn plan_parse_refuses_pii_shaped_owner_before_staging_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.initial_owner_chirho = "owner@example.com".to_owned();
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &fixture_chirho.expected_digest_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn two_routes_sharing_one_head_refuse_without_any_namespace_write_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho
        .projection_routes_chirho
        .push(LedgerRegenesisProjectionRoutePlanChirho {
            projection_name_chirho: "credits-shadow-chirho".to_owned(),
            head_path_chirho: plan_chirho.projection_routes_chirho[0]
                .head_path_chirho
                .clone(),
        });
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho)
        .unwrap()
        .replace(
            "projection_routes_chirho = [{ projection_name_chirho = \"credits-balance-chirho\", head_path_chirho = \"published/credits-balance-head-chirho.json\" }]",
            "projection_routes_chirho = [{ projection_name_chirho = \"credits-balance-chirho\", head_path_chirho = \"published/credits-balance-head-chirho.json\" }, { projection_name_chirho = \"credits-shadow-chirho\", head_path_chirho = \"published/credits-balance-head-chirho.json\" }]",
        );
    fs::write(&fixture_chirho.config_path_chirho, config_chirho).unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn route_head_colliding_with_journal_refuses_without_any_namespace_write_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.projection_routes_chirho[0].head_path_chirho =
        plan_chirho.journal_path_chirho.clone();
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);
    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho)
        .unwrap()
        .replace(
            "head_path_chirho = \"published/credits-balance-head-chirho.json\"",
            "head_path_chirho = \"journals/main-chirho.jsonl\"",
        );
    fs::write(&fixture_chirho.config_path_chirho, config_chirho).unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}
