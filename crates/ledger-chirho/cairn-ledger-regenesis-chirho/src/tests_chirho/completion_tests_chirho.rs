// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::completion_chirho::{
    complete_money_stage_chirho, ledger_regenesis_evidence_packet_digest_chirho,
    parse_canonical_ledger_regenesis_evidence_packet_chirho, run_ledger_regenesis_chirho,
    LedgerRegenesisCaveatChirho, LedgerRegenesisProjectionVerdictChirho,
    LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO,
    LEDGER_REGENESIS_EVIDENCE_PACKET_SCHEMA_V2_CHIRHO,
};
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::money_stage_chirho::prepare_money_stage_chirho;
use cairn_ledger_read_model_chirho::ProjectionCostClassChirho;

#[test]
fn completed_stage_writes_one_canonical_fresh_conservation_packet_chirho() {
    let fixture_chirho = fixture_chirho();
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    let completed_chirho = complete_money_stage_chirho(stage_chirho).unwrap();
    let packet_path_chirho = completed_chirho
        .money_stage_chirho
        .staged_monitor_namespace_root_chirho()
        .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO);
    let packet_bytes_chirho = fs::read(packet_path_chirho).unwrap();
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap();

    assert_eq!(
        packet_chirho.schema_chirho,
        LEDGER_REGENESIS_EVIDENCE_PACKET_SCHEMA_V2_CHIRHO
    );
    assert_eq!(
        packet_chirho.plan_digest_chirho,
        fixture_chirho.expected_digest_chirho
    );
    assert_eq!(packet_chirho.money_chirho.initial_mint_amount_chirho, 600);
    assert_eq!(packet_chirho.money_chirho.replayed_supply_chirho, 600);
    assert!(
        packet_chirho
            .money_chirho
            .stale_policy_classified_superseded_chirho
    );
    assert_eq!(packet_chirho.projections_chirho.len(), 1);
    let projection_chirho = &packet_chirho.projections_chirho[0];
    assert_eq!(
        projection_chirho.projection_name_chirho,
        "credits-balance-chirho"
    );
    assert_eq!(projection_chirho.account_net_chirho, 600);
    assert_eq!(
        projection_chirho.cost_class_chirho,
        ProjectionCostClassChirho::StandingWriteRateChirho
    );
    assert!(matches!(
        projection_chirho.verdict_chirho,
        LedgerRegenesisProjectionVerdictChirho::FreshChirho { lag_ms_chirho: 0 }
    ));
    assert_eq!(
        packet_chirho
            .conservation_chirho
            .covered_record_count_chirho,
        1
    );
    assert_eq!(
        packet_chirho
            .conservation_chirho
            .money_group_kind_scopes_checked_chirho,
        1
    );
    assert_eq!(
        packet_chirho
            .conservation_chirho
            .domain_kind_rollups_checked_chirho,
        1
    );
    assert_eq!(
        packet_chirho
            .conservation_chirho
            .global_supplies_checked_chirho,
        1
    );
    assert_eq!(
        packet_chirho.caveats_chirho,
        vec![
            LedgerRegenesisCaveatChirho::SignedPerMintAmountBoundRequiredBeforeProductionChirho,
            LedgerRegenesisCaveatChirho::RequestFastopenRepaymentRequiredBeforeClientServingChirho,
            LedgerRegenesisCaveatChirho::RootConfigSingleOperatorCustodyChirho,
        ]
    );
    assert_eq!(
        completed_chirho.packet_digest_chirho,
        ledger_regenesis_evidence_packet_digest_chirho(&packet_bytes_chirho)
    );
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho")
        .exists());
}

#[test]
fn identity_owner_and_distinct_settlement_survive_the_completed_packet_chirho() {
    let owner_chirho = "user/0123456789abcdef";
    let settlement_owner_chirho = "credits-demo-settlement-chirho";
    let mut fixture_chirho = fixture_chirho();
    bind_fixture_initial_owner_chirho(&mut fixture_chirho, owner_chirho);
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.initial_policy_chirho.settlement_owner_chirho =
        Some(settlement_owner_chirho.to_owned());
    plan_chirho.amended_policy_chirho.settlement_owner_chirho =
        Some(settlement_owner_chirho.to_owned());
    write_fixture_plan_chirho(&mut fixture_chirho, plan_chirho);

    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho).unwrap();
    let old_members_chirho = format!(
        "members_chirho = [{{ owner_chirho = \"{owner_chirho}\", kind_id_chirho = \"prepaid-credit-chirho\" }}]"
    );
    let new_members_chirho = format!(
        "members_chirho = [{{ owner_chirho = \"{owner_chirho}\", kind_id_chirho = \"prepaid-credit-chirho\" }}, {{ owner_chirho = \"{settlement_owner_chirho}\", kind_id_chirho = \"prepaid-credit-chirho\" }}]"
    );
    let updated_config_chirho = config_chirho.replace(&old_members_chirho, &new_members_chirho);
    assert_ne!(updated_config_chirho, config_chirho);
    fs::write(&fixture_chirho.config_path_chirho, updated_config_chirho).unwrap();
    refresh_fixture_activation_authorization_chirho(&mut fixture_chirho);

    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    assert!(stage_chirho
        .config_chirho
        .members_chirho
        .iter()
        .any(|member_chirho| {
            member_chirho.owner_chirho == settlement_owner_chirho
                && member_chirho.kind_id_chirho == "prepaid-credit-chirho"
        }));
    let completed_chirho = complete_money_stage_chirho(stage_chirho).unwrap();
    let packet_bytes_chirho = fs::read(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap();
    assert_eq!(packet_chirho.money_chirho.initial_mint_amount_chirho, 600);
    assert_eq!(packet_chirho.money_chirho.replayed_supply_chirho, 600);
    assert_eq!(packet_chirho.projections_chirho.len(), 1);
    assert_eq!(
        packet_chirho.projections_chirho[0]
            .account_chirho
            .owner_chirho,
        owner_chirho
    );
    assert_eq!(packet_chirho.projections_chirho[0].account_net_chirho, 600);
    assert_ne!(owner_chirho, settlement_owner_chirho);
}

#[test]
fn completed_packet_refuses_malformed_account_owner_principals_chirho() {
    let fixture_chirho = fixture_chirho();
    let completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap(),
    )
    .unwrap();
    let packet_bytes_chirho = fs::read(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap();

    for invalid_owner_chirho in [
        "user/0123456789abcdef/extra",
        "service/0123456789abcdef",
        "user/0123456789abcdeF",
        "viewer@example.com",
    ] {
        let mut malformed_chirho = packet_chirho.clone();
        malformed_chirho.projections_chirho[0]
            .account_chirho
            .owner_chirho = invalid_owner_chirho.to_owned();
        assert_eq!(
            crate::completion_chirho::canonical_ledger_regenesis_evidence_packet_chirho(
                &malformed_chirho
            )
            .unwrap_err(),
            LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho
        );
    }
}

#[test]
fn packet_is_reproducible_and_contains_no_host_or_key_coordinates_chirho() {
    let first_fixture_chirho = fixture_chirho();
    let second_fixture_chirho = fixture_chirho();
    let first_completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&first_fixture_chirho)).unwrap(),
    )
    .unwrap();
    let second_completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&second_fixture_chirho)).unwrap(),
    )
    .unwrap();
    let first_bytes_chirho = fs::read(
        first_completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    let second_bytes_chirho = fs::read(
        second_completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    assert_eq!(first_bytes_chirho, second_bytes_chirho);

    let packet_text_chirho = String::from_utf8(first_bytes_chirho).unwrap();
    assert!(!packet_text_chirho.contains(first_fixture_chirho.root_chirho.to_str().unwrap()));
    assert!(!packet_text_chirho.contains(&first_fixture_chirho.issuer_secret_name_chirho));
    for secret_name_chirho in RUNTIME_SECRET_NAMES_CHIRHO {
        assert!(!packet_text_chirho.contains(secret_name_chirho));
    }
    let issuer_key_chirho = SigningKey::from_bytes(&[7; 32]);
    assert!(!packet_text_chirho.contains(&hex_encode_chirho(
        issuer_key_chirho.verifying_key().as_bytes()
    )));
}

#[test]
fn publication_is_one_final_parent_with_the_packet_inside_ops_chirho() {
    let fixture_chirho = fixture_chirho();
    let receipt_chirho = run_ledger_regenesis_chirho(request_chirho(&fixture_chirho)).unwrap();
    let final_parent_chirho = fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho");
    let packet_bytes_chirho = fs::read(
        final_parent_chirho
            .join("ops-chirho")
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    assert_eq!(
        receipt_chirho.final_parent_name_chirho,
        "fresh-ledger-parent-chirho"
    );
    assert_eq!(
        receipt_chirho.plan_digest_chirho,
        fixture_chirho.expected_digest_chirho
    );
    assert_eq!(
        receipt_chirho.packet_digest_chirho,
        ledger_regenesis_evidence_packet_digest_chirho(&packet_bytes_chirho)
    );
    assert!(final_parent_chirho.join("ledger-chirho").is_dir());
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-staging-chirho")
        .exists());
}

#[test]
fn noncanonical_packet_bytes_refuse_chirho() {
    let fixture_chirho = fixture_chirho();
    let completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap(),
    )
    .unwrap();
    let mut packet_bytes_chirho = fs::read(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    packet_bytes_chirho.push(b'\n');
    assert_eq!(
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap_err(),
        LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho
    );
}

#[test]
fn canonical_packet_refuses_internally_divergent_evidence_chirho() {
    let fixture_chirho = fixture_chirho();
    let completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap(),
    )
    .unwrap();
    let packet_bytes_chirho = fs::read(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap();

    let mut wrong_net_chirho = packet_chirho.clone();
    wrong_net_chirho.projections_chirho[0].account_net_chirho += 1;
    let mut wrong_source_chirho = packet_chirho.clone();
    wrong_source_chirho.projections_chirho[0].source_family_id_chirho =
        "journal:foreign-cluster-chirho".to_owned();
    let mut wrong_privacy_chirho = packet_chirho;
    wrong_privacy_chirho
        .source_privacy_chirho
        .privacy_evidence_ref_chirho
        .0 = "0".repeat(64);

    for divergent_chirho in [wrong_net_chirho, wrong_source_chirho, wrong_privacy_chirho] {
        assert_eq!(
            crate::completion_chirho::canonical_ledger_regenesis_evidence_packet_chirho(
                &divergent_chirho
            )
            .unwrap_err(),
            LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho
        );
    }
}

#[test]
fn canonical_packet_refuses_money_evidence_tampering_chirho() {
    let fixture_chirho = fixture_chirho();
    let completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap(),
    )
    .unwrap();
    let packet_bytes_chirho = fs::read(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap();

    let mut equal_policy_refs_chirho = packet_chirho.clone();
    equal_policy_refs_chirho
        .money_chirho
        .current_policy_ref_chirho = equal_policy_refs_chirho
        .money_chirho
        .initial_policy_ref_chirho
        .clone();
    let mut stale_policy_unproven_chirho = packet_chirho.clone();
    stale_policy_unproven_chirho
        .money_chirho
        .stale_policy_classified_superseded_chirho = false;
    let mut supply_mismatch_chirho = packet_chirho;
    supply_mismatch_chirho.money_chirho.replayed_supply_chirho += 1;

    for tampered_chirho in [
        equal_policy_refs_chirho,
        stale_policy_unproven_chirho,
        supply_mismatch_chirho,
    ] {
        assert_eq!(
            crate::completion_chirho::canonical_ledger_regenesis_evidence_packet_chirho(
                &tampered_chirho
            )
            .unwrap_err(),
            LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho
        );
    }
}

#[test]
fn canonical_packet_refuses_activation_and_canary_mismatches_chirho() {
    let fixture_chirho = fixture_chirho();
    let completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap(),
    )
    .unwrap();
    let packet_bytes_chirho = fs::read(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap();

    let mut wrong_activation_plan_chirho = packet_chirho.clone();
    wrong_activation_plan_chirho
        .money_chirho
        .activation_chirho
        .plan_digest_chirho = blake3::hash(b"foreign-activation-plan-chirho")
        .to_hex()
        .to_string();
    let mut zero_append_seq_chirho = packet_chirho.clone();
    zero_append_seq_chirho
        .money_chirho
        .activation_chirho
        .append_seq_chirho = 0;
    let mut malformed_append_digest_chirho = packet_chirho.clone();
    malformed_append_digest_chirho
        .money_chirho
        .activation_chirho
        .append_record_digest_chirho
        .0 = "malformed-append-digest-chirho".to_owned();
    let mut zero_hlc_physical_chirho = packet_chirho.clone();
    zero_hlc_physical_chirho
        .money_chirho
        .activation_chirho
        .append_hlc_physical_ms_chirho = 0;
    let mut wrong_hlc_logical_chirho = packet_chirho.clone();
    wrong_hlc_logical_chirho
        .money_chirho
        .activation_chirho
        .append_hlc_logical_chirho += 1;
    let mut zero_process_generation_chirho = packet_chirho.clone();
    zero_process_generation_chirho
        .money_chirho
        .activation_chirho
        .process_generation_chirho = 0;
    let mut zero_durable_term_chirho = packet_chirho.clone();
    zero_durable_term_chirho
        .money_chirho
        .activation_chirho
        .durable_term_chirho = 0;
    let mut zero_fence_epoch_chirho = packet_chirho.clone();
    zero_fence_epoch_chirho
        .money_chirho
        .activation_chirho
        .fence_epoch_chirho = 0;
    let mut wrong_canary_evidence_seq_chirho = packet_chirho.clone();
    wrong_canary_evidence_seq_chirho
        .money_chirho
        .canary_chirho
        .evidence_seq_chirho = 2;
    let mut wrong_canary_window_len_chirho = packet_chirho.clone();
    wrong_canary_window_len_chirho
        .money_chirho
        .canary_chirho
        .window_len_chirho = 2;
    let mut wrong_canary_permit_count_chirho = packet_chirho.clone();
    wrong_canary_permit_count_chirho
        .money_chirho
        .canary_chirho
        .permit_count_chirho = 0;
    let mut wrong_canary_refusal_count_chirho = packet_chirho.clone();
    wrong_canary_refusal_count_chirho
        .money_chirho
        .canary_chirho
        .refusal_count_chirho = 1;
    let mut wrong_canary_append_seq_chirho = packet_chirho.clone();
    wrong_canary_append_seq_chirho
        .money_chirho
        .canary_chirho
        .append_seq_chirho += 1;
    let mut wrong_canary_append_digest_chirho = packet_chirho.clone();
    wrong_canary_append_digest_chirho
        .money_chirho
        .canary_chirho
        .append_record_digest_chirho
        .0 = blake3::hash(b"foreign-canary-append-chirho")
        .to_hex()
        .to_string();
    let mut wrong_canary_term_chirho = packet_chirho.clone();
    wrong_canary_term_chirho
        .money_chirho
        .canary_chirho
        .durable_term_chirho += 1;
    let mut wrong_canary_fence_chirho = packet_chirho.clone();
    wrong_canary_fence_chirho
        .money_chirho
        .canary_chirho
        .fence_epoch_chirho += 1;

    for mismatched_chirho in [
        wrong_activation_plan_chirho,
        zero_append_seq_chirho,
        malformed_append_digest_chirho,
        zero_hlc_physical_chirho,
        wrong_hlc_logical_chirho,
        zero_process_generation_chirho,
        zero_durable_term_chirho,
        zero_fence_epoch_chirho,
        wrong_canary_evidence_seq_chirho,
        wrong_canary_window_len_chirho,
        wrong_canary_permit_count_chirho,
        wrong_canary_refusal_count_chirho,
        wrong_canary_append_seq_chirho,
        wrong_canary_append_digest_chirho,
        wrong_canary_term_chirho,
        wrong_canary_fence_chirho,
    ] {
        assert_eq!(
            crate::completion_chirho::canonical_ledger_regenesis_evidence_packet_chirho(
                &mismatched_chirho
            )
            .unwrap_err(),
            LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho
        );
    }
}

#[test]
fn canonical_packet_refuses_initial_mint_amount_binding_mismatches_chirho() {
    let fixture_chirho = fixture_chirho();
    let completed_chirho = complete_money_stage_chirho(
        prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap(),
    )
    .unwrap();
    let packet_bytes_chirho = fs::read(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO),
    )
    .unwrap();
    let packet_chirho =
        parse_canonical_ledger_regenesis_evidence_packet_chirho(&packet_bytes_chirho).unwrap();

    let mut replay_mismatch_chirho = packet_chirho.clone();
    replay_mismatch_chirho
        .money_chirho
        .initial_mint_amount_chirho += 1;
    let mut projection_mismatch_chirho = packet_chirho;
    projection_mismatch_chirho
        .money_chirho
        .initial_mint_amount_chirho += 1;
    projection_mismatch_chirho
        .money_chirho
        .replayed_supply_chirho += 1;

    for mismatched_chirho in [replay_mismatch_chirho, projection_mismatch_chirho] {
        assert_eq!(
            crate::completion_chirho::canonical_ledger_regenesis_evidence_packet_chirho(
                &mismatched_chirho
            )
            .unwrap_err(),
            LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho
        );
    }
}

#[test]
fn all_routes_are_reserved_after_all_feeds_before_completion_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    stage_chirho.plan_chirho.projection_routes_chirho.push(
        LedgerRegenesisProjectionRoutePlanChirho {
            projection_name_chirho: "credits-shadow-chirho".to_owned(),
            head_path_chirho: "published/credits-balance-head-chirho.json".to_owned(),
        },
    );
    let result_chirho = complete_money_stage_chirho(stage_chirho);
    assert!(matches!(
        result_chirho,
        Err(LedgerRegenesisRefusalChirho::ProjectionCompletionRefusedChirho)
    ));
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho")
        .exists());
}
