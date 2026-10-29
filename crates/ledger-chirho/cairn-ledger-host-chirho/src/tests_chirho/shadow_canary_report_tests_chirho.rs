// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::temp_root_chirho;
use crate::shadow_canary_report_chirho::{
    configured_shadow_canary_bound_verdict_bytes_chirho,
    configured_shadow_canary_bound_verdict_chirho, configured_shadow_canary_report_bytes_chirho,
    configured_shadow_canary_report_read_only_chirho,
    verify_configured_shadow_canary_bound_verdict_bytes_chirho,
    verify_required_configured_shadow_canary_report_bytes_chirho,
    ConfiguredShadowCanaryBoundVerdictRefusalChirho,
    ConfiguredShadowCanaryBoundVerdictRequirementsChirho,
    ConfiguredShadowCanaryQualificationChirho, ConfiguredShadowCanaryReportBuildRefusalChirho,
    ConfiguredShadowCanaryReportRefusalChirho, ConfiguredShadowCanaryReportStatusChirho,
    CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V1_CHIRHO,
    CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V2_CHIRHO,
    CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V3_CHIRHO,
};
use cairn_config_chirho::config_chirho::{
    serialize_config_chirho, ConfigChirho, LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho,
    LedgerHostMemberConfigChirho, LedgerHostProjectionRouteConfigChirho,
    LedgerHostSignerRefsConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_activation_anchor_chirho::ShadowCanaryActivationAnchorInputChirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::{
    ShadowCanaryAppendCutChirho, ShadowCanaryChirho, ShadowCanaryEvidenceStoreChirho,
    SHADOW_CANARY_SCHEMA_CHIRHO,
};
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::{
    ShadowCanaryAdoptionGenerationInputChirho, ShadowCanaryGenerationStoreChirho,
    ShadowCanaryLedgerCutChirho,
};
use cairn_writer_elector_chirho::shadow_canary_proof_chirho::ShadowCanaryWindowProofRefusalChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const MONITOR_NAMESPACE_CHIRHO: &str = "monitor-evidence-chirho";

struct ReportFixtureChirho {
    root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    node_chirho: NodeIdChirho,
}

impl ReportFixtureChirho {
    fn new_chirho(tag_chirho: &str) -> Self {
        let root_chirho = temp_root_chirho(tag_chirho);
        fs::create_dir_all(&root_chirho).unwrap();
        sign_message_chirho(&root_chirho, b"provision configured canary reporter").unwrap();
        let node_chirho = NodeIdChirho(pubkey_hex_chirho(&root_chirho).unwrap());
        let config_path_chirho = root_chirho.join("cairn-shadow-report-config-chirho.toml");
        let runtime_config_chirho = ConfigChirho {
            root_chirho: root_chirho.to_string_lossy().into_owned(),
            ledger_host_chirho: Some(host_config_chirho()),
            ..ConfigChirho::default()
        };
        fs::write(
            &config_path_chirho,
            serialize_config_chirho(&runtime_config_chirho).unwrap(),
        )
        .unwrap();
        set_private_mode_chirho(&config_path_chirho);
        Self {
            root_chirho,
            config_path_chirho,
            node_chirho,
        }
    }

    fn provision_window_chirho(&self, observation_count_chirho: u64) {
        self.provision_window_with_refusal_chirho(observation_count_chirho, None);
    }

    fn provision_window_with_refusal_chirho(
        &self,
        observation_count_chirho: u64,
        refusal_seq_chirho: Option<u64>,
    ) {
        let group_chirho = consistency_group_for_root_chirho(&self.root_chirho).unwrap();
        let canary_root_chirho = self.canary_root_chirho();
        fs::create_dir_all(canary_root_chirho.parent().unwrap()).unwrap();
        let activation_cut_chirho = ShadowCanaryAppendCutChirho {
            append_seq_chirho: 1,
            append_record_digest_chirho: format!("{:064x}", 1),
            append_hlc_physical_ms_chirho: 10_001,
            append_hlc_logical_chirho: 0,
            process_generation_chirho: 1,
            durable_term_chirho: 7,
            fence_epoch_chirho: 11,
            fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        };
        let store_chirho = ShadowCanaryEvidenceStoreChirho::create_activation_chirho(
            &canary_root_chirho,
            &self.root_chirho,
            group_chirho.clone(),
            self.node_chirho.clone(),
            ShadowCanaryActivationAnchorInputChirho {
                activation_authorization_digest_chirho: format!(
                    "activation-authorization-v1-chirho:{}",
                    "a".repeat(64)
                ),
                activation_plan_digest_chirho: "b".repeat(64),
                resident_identity_digest_chirho: format!(
                    "resident-identity-v1-chirho:{}",
                    "c".repeat(64)
                ),
                activation_append_cut_chirho: activation_cut_chirho,
            },
        )
        .unwrap();
        for append_seq_chirho in 1..=observation_count_chirho {
            let permit_chirho = refusal_seq_chirho != Some(append_seq_chirho);
            store_chirho
                .append_observation_chirho(ShadowCanaryChirho {
                    schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
                    group_chirho: group_chirho.clone(),
                    minter_node_id_chirho: self.node_chirho.clone(),
                    append_cut_chirho: ShadowCanaryAppendCutChirho {
                        append_seq_chirho,
                        append_record_digest_chirho: format!("{append_seq_chirho:064x}"),
                        append_hlc_physical_ms_chirho: 10_000 + append_seq_chirho,
                        append_hlc_logical_chirho: 0,
                        process_generation_chirho: 1,
                        durable_term_chirho: 7,
                        fence_epoch_chirho: 11,
                        fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho)
                            .unwrap(),
                    },
                    raft_leader_id_chirho: Some(self.node_chirho.clone()),
                    raft_term_chirho: 7,
                    raft_lease_valid_chirho: permit_chirho,
                    cutover_would_permit_chirho: permit_chirho,
                    at_ms_chirho: 20_000 + append_seq_chirho,
                })
                .unwrap();
        }
    }

    fn provision_legacy_window_chirho(&self) {
        let group_chirho = consistency_group_for_root_chirho(&self.root_chirho).unwrap();
        let store_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
            &self.canary_root_chirho(),
            &self.root_chirho,
            group_chirho.clone(),
            self.node_chirho.clone(),
        )
        .unwrap();
        store_chirho
            .append_observation_chirho(ShadowCanaryChirho {
                schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
                group_chirho: group_chirho.clone(),
                minter_node_id_chirho: self.node_chirho.clone(),
                append_cut_chirho: ShadowCanaryAppendCutChirho {
                    append_seq_chirho: 1,
                    append_record_digest_chirho: format!("{:064x}", 1),
                    append_hlc_physical_ms_chirho: 10_001,
                    append_hlc_logical_chirho: 0,
                    process_generation_chirho: 1,
                    durable_term_chirho: 7,
                    fence_epoch_chirho: 11,
                    fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho)
                        .unwrap(),
                },
                raft_leader_id_chirho: Some(self.node_chirho.clone()),
                raft_term_chirho: 7,
                raft_lease_valid_chirho: true,
                cutover_would_permit_chirho: true,
                at_ms_chirho: 20_001,
            })
            .unwrap();
    }

    fn provision_adopted_window_chirho(&self) {
        self.provision_window_chirho(2);
        let group_chirho = consistency_group_for_root_chirho(&self.root_chirho).unwrap();
        let store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
            &self.canary_root_chirho(),
            &self.root_chirho,
            group_chirho.clone(),
            self.node_chirho.clone(),
        )
        .unwrap();
        store_chirho
            .commit_adoption_generation_chirho(ShadowCanaryAdoptionGenerationInputChirho {
                adopted_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
                    5,
                    format!("{:064x}", 5),
                    10_005,
                    0,
                    11,
                    &group_chirho,
                )
                .unwrap(),
                cluster_id_chirho: "cluster-chirho".to_owned(),
                journal_genesis_digest_chirho: "9".repeat(64),
                assignment_digest_chirho: "a".repeat(64),
                historical_leader_node_id_chirho: "8".repeat(64),
                holder_node_ids_chirho: ["6".repeat(64), "7".repeat(64)],
                historical_term_chirho: 5,
                historical_membership_view_digest_chirho: "1".repeat(64),
                elected_term_chirho: 7,
                membership_view_digest_chirho: "b".repeat(64),
                holder_receipt_digests_chirho: ["c".repeat(64), "d".repeat(64)],
                holder_receipt_wires_chirho: [
                    br#"{"receipt_chirho":"first-chirho"}"#.to_vec(),
                    br#"{"receipt_chirho":"second-chirho"}"#.to_vec(),
                ],
                candidate_journal_binding_digest_chirho: "e".repeat(64),
                candidate_journal_digest_chirho: "f".repeat(64),
            })
            .unwrap();
        for append_seq_chirho in 6..=7 {
            store_chirho
                .append_observation_chirho(ShadowCanaryChirho {
                    schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_owned(),
                    group_chirho: group_chirho.clone(),
                    minter_node_id_chirho: self.node_chirho.clone(),
                    append_cut_chirho: ShadowCanaryAppendCutChirho {
                        append_seq_chirho,
                        append_record_digest_chirho: format!("{append_seq_chirho:064x}"),
                        append_hlc_physical_ms_chirho: 10_000 + append_seq_chirho,
                        append_hlc_logical_chirho: 0,
                        process_generation_chirho: 2,
                        durable_term_chirho: 7,
                        fence_epoch_chirho: 11,
                        fence_group_digest_chirho: consistency_group_digest_chirho(&group_chirho)
                            .unwrap(),
                    },
                    raft_leader_id_chirho: Some(self.node_chirho.clone()),
                    raft_term_chirho: 7,
                    raft_lease_valid_chirho: true,
                    cutover_would_permit_chirho: true,
                    at_ms_chirho: 20_000 + append_seq_chirho,
                })
                .unwrap();
        }
    }

    fn canary_root_chirho(&self) -> PathBuf {
        self.root_chirho
            .join(MONITOR_NAMESPACE_CHIRHO)
            .join("writer-canary-chirho")
    }
}

impl Drop for ReportFixtureChirho {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_chirho);
    }
}

fn host_config_chirho() -> LedgerHostConfigChirho {
    LedgerHostConfigChirho {
        schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
        storage_namespace_chirho: "ledger-storage-chirho".to_owned(),
        monitor_evidence_namespace_chirho: MONITOR_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_path_chirho: "cycles/conservation-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-chirho".to_owned(),
        cluster_id_chirho: "cluster-chirho".to_owned(),
        journal_path_chirho: "journals-chirho/money-chirho.jsonl".to_owned(),
        local_epoch_chirho: 1,
        members_chirho: vec![LedgerHostMemberConfigChirho {
            owner_chirho: "platform-owner-chirho".to_owned(),
            kind_id_chirho: "credits-chirho".to_owned(),
        }],
        kind_registry_path_chirho: "registries-chirho/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-chirho".to_owned(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: "offline-kind-issuer-chirho".to_owned(),
            verifying_key_hex_chirho: "1".repeat(64),
        },
        activation_authority_chirho: None,
        projection_registry_path_chirho: "registries-chirho/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-chirho".to_owned(),
        source_registry_path_chirho: "registries-chirho/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-chirho".to_owned(),
        projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
            projection_name_chirho: "account-net-chirho".to_owned(),
            head_path_chirho: "projection-heads-chirho/account-net-chirho.json".to_owned(),
        }],
        signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
            journal_chirho: "private-journal-secret-chirho".to_owned(),
            config_chirho: "private-config-secret-chirho".to_owned(),
            feeder_chirho: "private-feeder-secret-chirho".to_owned(),
            kind_root_chirho: "private-kind-root-secret-chirho".to_owned(),
            effect_intent_chirho: "private-effect-intent-secret-chirho".to_owned(),
            effect_terminal_chirho: "private-effect-terminal-secret-chirho".to_owned(),
        },
        migration_destination_authority_chirho: None,
        held_verifier_pins_chirho: None,
        monitor_cadence_ms_chirho: 5_000,
        postgres_effect_chirho: None,
        control_plane_chirho: None,
        test_kind_chirho: None,
        adopt_migrated_root_chirho: false,
    }
}

fn writer_requirements_chirho(
    minimum_observation_count_chirho: u64,
    minimum_interval_millis_chirho: u64,
) -> ConfiguredShadowCanaryBoundVerdictRequirementsChirho {
    ConfiguredShadowCanaryBoundVerdictRequirementsChirho {
        minimum_observation_count_chirho,
        minimum_interval_millis_chirho,
    }
}

#[cfg(unix)]
fn set_private_mode_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_private_mode_chirho(_path_chirho: &Path) {}

#[test]
fn missing_store_is_present_and_named_but_never_verifies_as_a_window_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-report-absent");
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    assert_eq!(
        report_chirho.status_chirho,
        ConfiguredShadowCanaryReportStatusChirho::StoreAbsentChirho
    );
    assert!(report_chirho.proof_chirho.is_none());
    let bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    assert_eq!(
        verify_required_configured_shadow_canary_report_bytes_chirho(&bytes_chirho).unwrap_err(),
        ConfiguredShadowCanaryReportRefusalChirho::StoreAbsentChirho
    );
    assert!(String::from_utf8(bytes_chirho)
        .unwrap()
        .contains("store-absent-chirho"));
}

#[test]
fn missing_store_emits_a_byte_bound_non_green_verdict_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-absent");
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    let requirements_chirho = writer_requirements_chirho(2, 1);
    let verdict_chirho =
        configured_shadow_canary_bound_verdict_chirho(&report_bytes_chirho, requirements_chirho)
            .unwrap();
    assert_eq!(
        verdict_chirho.qualification_chirho,
        ConfiguredShadowCanaryQualificationChirho::StoreAbsentChirho
    );
    assert_eq!(verdict_chirho.node_id_chirho, fixture_chirho.node_chirho.0);
    assert_eq!(
        verdict_chirho.schema_chirho,
        CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V1_CHIRHO
    );
    assert!(verdict_chirho.activation_anchor_digest_chirho.is_none());
    assert!(verdict_chirho.latest_ledger_cut_chirho.is_none());
    assert!(verdict_chirho.oldest_observed_at_ms_chirho.is_none());
    assert_eq!(
        verdict_chirho.report_sha256_chirho,
        format!("{:x}", Sha256::digest(&report_bytes_chirho))
    );
}

#[test]
fn existing_non_directory_store_is_unreadable_and_never_absent_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-report-nondirectory");
    let canary_root_chirho = fixture_chirho.canary_root_chirho();
    fs::create_dir_all(canary_root_chirho.parent().unwrap()).unwrap();
    fs::write(&canary_root_chirho, b"not-a-canary-store-chirho").unwrap();

    assert_eq!(
        configured_shadow_canary_report_read_only_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.config_path_chirho,
        )
        .unwrap_err(),
        ConfiguredShadowCanaryReportBuildRefusalChirho::StoreUnreadableChirho
    );
}

#[test]
fn configured_report_derives_a_path_free_two_observation_proof_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-report-present");
    fixture_chirho.provision_window_chirho(2);
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    assert_eq!(
        report_chirho.status_chirho,
        ConfiguredShadowCanaryReportStatusChirho::ProofAvailableChirho
    );
    let bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    let verified_chirho =
        verify_required_configured_shadow_canary_report_bytes_chirho(&bytes_chirho).unwrap();
    assert_eq!(verified_chirho.node_id_chirho, fixture_chirho.node_chirho.0);
    assert_eq!(verified_chirho.window_chirho.unwrap().window_len_chirho, 2);
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    assert!(!text_chirho.contains(fixture_chirho.root_chirho.to_string_lossy().as_ref()));
    assert!(!text_chirho.contains("private-journal-secret-chirho"));
    assert!(!text_chirho.contains("receipt_chirho"));
}

#[test]
fn one_activation_is_named_without_becoming_a_writer_window_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-activation");
    fixture_chirho.provision_window_chirho(1);
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    let verdict_chirho = configured_shadow_canary_bound_verdict_chirho(
        &report_bytes_chirho,
        writer_requirements_chirho(2, 1),
    )
    .unwrap();
    assert_eq!(
        verdict_chirho.qualification_chirho,
        ConfiguredShadowCanaryQualificationChirho::ActivationOnlyChirho
    );
    assert_eq!(verdict_chirho.window_len_chirho, Some(1));
    assert_eq!(verdict_chirho.permit_count_chirho, Some(1));
    assert_eq!(verdict_chirho.refusal_count_chirho, Some(0));
    assert_eq!(
        verdict_chirho.schema_chirho,
        CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V2_CHIRHO
    );
    assert!(verdict_chirho.activation_anchor_digest_chirho.is_some());
    assert!(verdict_chirho.oldest_observed_at_ms_chirho.is_none());
    assert!(verdict_chirho.latest_observed_at_ms_chirho.is_none());
}

#[test]
fn bound_verdict_preserves_each_signature_verified_activation_anchor_chirho() {
    let first_fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-anchor-first");
    let second_fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-anchor-second");
    first_fixture_chirho.provision_window_chirho(1);
    second_fixture_chirho.provision_window_chirho(1);

    let mut expected_anchor_digests_chirho = Vec::new();
    let mut verdict_anchor_digests_chirho = Vec::new();
    for fixture_chirho in [&first_fixture_chirho, &second_fixture_chirho] {
        let report_chirho = configured_shadow_canary_report_read_only_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.config_path_chirho,
        )
        .unwrap();
        let report_bytes_chirho =
            configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
        let verified_chirho =
            verify_required_configured_shadow_canary_report_bytes_chirho(&report_bytes_chirho)
                .unwrap();
        expected_anchor_digests_chirho
            .push(verified_chirho.activation_anchor_digest_chirho.unwrap());
        verdict_anchor_digests_chirho.push(
            configured_shadow_canary_bound_verdict_chirho(
                &report_bytes_chirho,
                writer_requirements_chirho(2, 1),
            )
            .unwrap()
            .activation_anchor_digest_chirho
            .unwrap(),
        );
    }

    assert_ne!(
        expected_anchor_digests_chirho[0],
        expected_anchor_digests_chirho[1]
    );
    assert_eq!(
        verdict_anchor_digests_chirho,
        expected_anchor_digests_chirho
    );
}

#[test]
fn legacy_present_proof_never_falls_back_to_an_applicable_verdict_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-legacy");
    fixture_chirho.provision_legacy_window_chirho();
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    assert_eq!(
        configured_shadow_canary_bound_verdict_chirho(
            &report_bytes_chirho,
            writer_requirements_chirho(2, 1),
        )
        .unwrap_err(),
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::ActivationAnchorRequiredChirho
    );
}

#[test]
fn qualified_window_exposes_only_its_derived_interval_and_cut_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-qualified");
    fixture_chirho.provision_window_chirho(2);
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    let verdict_chirho = configured_shadow_canary_bound_verdict_chirho(
        &report_bytes_chirho,
        writer_requirements_chirho(2, 1),
    )
    .unwrap();
    assert_eq!(
        verdict_chirho.qualification_chirho,
        ConfiguredShadowCanaryQualificationChirho::WindowQualifiedChirho
    );
    assert_eq!(verdict_chirho.oldest_observed_at_ms_chirho, Some(20_001));
    assert_eq!(verdict_chirho.latest_observed_at_ms_chirho, Some(20_002));
    assert_eq!(
        verdict_chirho
            .latest_ledger_cut_chirho
            .unwrap()
            .append_seq_chirho,
        2
    );
}

#[test]
fn adopted_verdict_carries_only_the_verified_wire_free_projection_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-adopted");
    fixture_chirho.provision_adopted_window_chirho();
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    let verdict_chirho = configured_shadow_canary_bound_verdict_chirho(
        &report_bytes_chirho,
        writer_requirements_chirho(2, 1),
    )
    .unwrap();
    assert_eq!(
        verdict_chirho.schema_chirho,
        CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V3_CHIRHO
    );
    assert_eq!(
        verdict_chirho.qualification_chirho,
        ConfiguredShadowCanaryQualificationChirho::WindowQualifiedChirho
    );
    let projection_chirho = verdict_chirho
        .adoption_proof_projection_chirho
        .as_ref()
        .unwrap();
    assert_eq!(projection_chirho.historical_term_chirho, 5);
    assert_eq!(projection_chirho.elected_term_chirho, 7);
    assert_eq!(
        projection_chirho.historical_membership_view_digest_chirho,
        "1".repeat(64)
    );
    let verdict_bytes_chirho = configured_shadow_canary_bound_verdict_bytes_chirho(
        &report_bytes_chirho,
        writer_requirements_chirho(2, 1),
    )
    .unwrap();
    let verdict_text_chirho = String::from_utf8(verdict_bytes_chirho.clone()).unwrap();
    assert!(!verdict_text_chirho.contains("first-chirho"));
    assert!(!verdict_text_chirho.contains("second-chirho"));
    assert_eq!(
        verify_configured_shadow_canary_bound_verdict_bytes_chirho(
            &report_bytes_chirho,
            &verdict_bytes_chirho,
            writer_requirements_chirho(2, 1),
        )
        .unwrap(),
        verdict_chirho
    );
}

#[test]
fn verdict_load_refuses_v3_without_projection_and_v2_with_projection_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-schema-shape");
    fixture_chirho.provision_adopted_window_chirho();
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    let requirements_chirho = writer_requirements_chirho(2, 1);
    let verdict_chirho =
        configured_shadow_canary_bound_verdict_chirho(&report_bytes_chirho, requirements_chirho)
            .unwrap();
    assert!(verdict_chirho.adoption_proof_projection_chirho.is_some());

    let mut missing_projection_chirho = verdict_chirho.clone();
    missing_projection_chirho.adoption_proof_projection_chirho = None;
    let missing_projection_bytes_chirho = serde_json::to_vec(&missing_projection_chirho).unwrap();
    assert_eq!(
        verify_configured_shadow_canary_bound_verdict_bytes_chirho(
            &report_bytes_chirho,
            &missing_projection_bytes_chirho,
            requirements_chirho,
        )
        .unwrap_err(),
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::ShapeRefusedChirho
    );

    let mut legacy_schema_with_projection_chirho = verdict_chirho;
    legacy_schema_with_projection_chirho.schema_chirho =
        CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V2_CHIRHO.to_owned();
    let legacy_schema_bytes_chirho =
        serde_json::to_vec(&legacy_schema_with_projection_chirho).unwrap();
    assert_eq!(
        verify_configured_shadow_canary_bound_verdict_bytes_chirho(
            &report_bytes_chirho,
            &legacy_schema_bytes_chirho,
            requirements_chirho,
        )
        .unwrap_err(),
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::ShapeRefusedChirho
    );
}

#[test]
fn valid_present_proof_below_a_larger_population_remains_non_green_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-not-qualified");
    fixture_chirho.provision_window_chirho(2);
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    let verdict_chirho = configured_shadow_canary_bound_verdict_chirho(
        &report_bytes_chirho,
        writer_requirements_chirho(3, 1),
    )
    .unwrap();
    assert_eq!(
        verdict_chirho.qualification_chirho,
        ConfiguredShadowCanaryQualificationChirho::PresentNotWindowQualifiedChirho
    );
    assert!(verdict_chirho.oldest_observed_at_ms_chirho.is_none());
    assert!(verdict_chirho.latest_observed_at_ms_chirho.is_none());
}

#[test]
fn signed_refusal_window_refuses_instead_of_becoming_not_qualified_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-refusal");
    fixture_chirho.provision_window_with_refusal_chirho(1, Some(1));
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    assert_eq!(
        configured_shadow_canary_bound_verdict_chirho(
            &report_bytes_chirho,
            writer_requirements_chirho(2, 1),
        )
        .unwrap_err(),
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::WindowRefusedChirho(
            ShadowCanaryWindowProofRefusalChirho::WriterRefusalObservedChirho,
        )
    );
}

#[test]
fn bound_verdict_cannot_move_to_equivalent_other_bytes_or_requirements_chirho() {
    let first_chirho = ReportFixtureChirho::new_chirho("canary-verdict-first");
    first_chirho.provision_window_chirho(2);
    let first_report_chirho = configured_shadow_canary_report_read_only_chirho(
        &first_chirho.root_chirho,
        &first_chirho.config_path_chirho,
    )
    .unwrap();
    let first_bytes_chirho =
        configured_shadow_canary_report_bytes_chirho(&first_report_chirho).unwrap();
    let mut equivalent_other_bytes_chirho = first_bytes_chirho.clone();
    equivalent_other_bytes_chirho.push(b'\n');
    let requirements_chirho = writer_requirements_chirho(2, 1);
    let verdict_bytes_chirho = configured_shadow_canary_bound_verdict_bytes_chirho(
        &first_bytes_chirho,
        requirements_chirho,
    )
    .unwrap();
    assert_eq!(
        verify_configured_shadow_canary_bound_verdict_bytes_chirho(
            &equivalent_other_bytes_chirho,
            &verdict_bytes_chirho,
            requirements_chirho,
        )
        .unwrap_err(),
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::BindingRefusedChirho
    );
    assert_eq!(
        verify_configured_shadow_canary_bound_verdict_bytes_chirho(
            &first_bytes_chirho,
            &verdict_bytes_chirho,
            writer_requirements_chirho(3, 1),
        )
        .unwrap_err(),
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::BindingRefusedChirho
    );
}

#[test]
fn caller_cannot_define_a_single_observation_or_zero_time_window_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-requirements");
    fixture_chirho.provision_window_chirho(2);
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let report_bytes_chirho = configured_shadow_canary_report_bytes_chirho(&report_chirho).unwrap();
    for requirements_chirho in [
        writer_requirements_chirho(1, 1),
        writer_requirements_chirho(2, 0),
    ] {
        assert_eq!(
            configured_shadow_canary_bound_verdict_chirho(
                &report_bytes_chirho,
                requirements_chirho,
            )
            .unwrap_err(),
            ConfiguredShadowCanaryBoundVerdictRefusalChirho::RequirementsRefusedChirho
        );
    }
}

#[test]
fn malformed_inner_signature_refuses_instead_of_becoming_absent_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-verdict-signature");
    fixture_chirho.provision_window_chirho(2);
    let mut report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    report_chirho.proof_chirho.as_mut().unwrap().sig_chirho = "invalid-signature-chirho".to_owned();
    let report_bytes_chirho = serde_json::to_vec(&report_chirho).unwrap();
    assert_eq!(
        configured_shadow_canary_bound_verdict_chirho(
            &report_bytes_chirho,
            writer_requirements_chirho(2, 1),
        )
        .unwrap_err(),
        ConfiguredShadowCanaryBoundVerdictRefusalChirho::ReportRefusedChirho(
            ConfiguredShadowCanaryReportRefusalChirho::ProofRefusedChirho(
                ShadowCanaryWindowProofRefusalChirho::SignatureRefusedChirho,
            ),
        )
    );
}

#[test]
fn outer_node_or_group_substitution_cannot_relabel_an_inner_proof_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-report-binding");
    fixture_chirho.provision_window_chirho(2);
    let report_chirho = configured_shadow_canary_report_read_only_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
    )
    .unwrap();
    let mut node_substitution_chirho = report_chirho.clone();
    node_substitution_chirho.node_id_chirho = "2".repeat(64);
    assert_eq!(
        configured_shadow_canary_report_bytes_chirho(&node_substitution_chirho).unwrap_err(),
        ConfiguredShadowCanaryReportRefusalChirho::BindingRefusedChirho
    );
    let bytes_chirho = serde_json::to_vec(&node_substitution_chirho).unwrap();
    assert_eq!(
        verify_required_configured_shadow_canary_report_bytes_chirho(&bytes_chirho).unwrap_err(),
        ConfiguredShadowCanaryReportRefusalChirho::BindingRefusedChirho
    );

    let mut group_substitution_chirho = report_chirho;
    group_substitution_chirho.consistency_group_digest_chirho =
        format!("writer-fence-group-blake3-chirho:{}", "2".repeat(64));
    assert_eq!(
        configured_shadow_canary_report_bytes_chirho(&group_substitution_chirho).unwrap_err(),
        ConfiguredShadowCanaryReportRefusalChirho::BindingRefusedChirho
    );
}

#[test]
fn reviewed_config_cannot_be_reused_for_a_different_selected_root_chirho() {
    let fixture_chirho = ReportFixtureChirho::new_chirho("canary-report-root-binding");
    let other_root_chirho = temp_root_chirho("canary-report-other-root");
    fs::create_dir_all(&other_root_chirho).unwrap();
    assert_eq!(
        configured_shadow_canary_report_read_only_chirho(
            &other_root_chirho,
            &fixture_chirho.config_path_chirho,
        )
        .unwrap_err(),
        ConfiguredShadowCanaryReportBuildRefusalChirho::ConfigRootBindingRefusedChirho
    );
    fs::remove_dir_all(other_root_chirho).unwrap();
}
