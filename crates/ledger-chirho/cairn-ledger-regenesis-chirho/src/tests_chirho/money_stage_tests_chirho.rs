// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::completion_chirho::{
    complete_money_stage_chirho, LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO,
};
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::money_stage_chirho::prepare_money_stage_chirho;
use crate::plan_chirho::load_verified_plan_chirho;
use crate::publication_verify_chirho::LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO;
use crate::staging_chirho::{
    begin_staging_chirho, bounded_recursive_fsync_chirho, no_replace_rename_chirho,
    publish_completed_stage_chirho,
};
use cairn_ledger_host_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};

#[test]
fn r1_mint_r2_supersession_replays_and_stale_append_refuses_chirho() {
    let fixture_chirho = fixture_chirho();
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    let proof_chirho = stage_chirho.proof_chirho();
    assert_eq!(proof_chirho.initial_mint_amount_chirho, 600);
    assert_eq!(proof_chirho.replayed_supply_chirho, 600);
    assert!(proof_chirho.stale_policy_classified_superseded_chirho);
    assert_ne!(
        proof_chirho.initial_policy_ref_chirho,
        proof_chirho.current_policy_ref_chirho
    );
    assert_eq!(
        proof_chirho.activation_chirho.plan_digest_chirho,
        fixture_chirho.expected_digest_chirho
    );
    assert_eq!(proof_chirho.activation_chirho.append_seq_chirho, 1);
    assert_eq!(
        proof_chirho.activation_chirho.append_hlc_physical_ms_chirho,
        fixture_chirho.plan_chirho.mint_physical_ms_chirho
    );
    assert_eq!(
        proof_chirho.canary_chirho.append_seq_chirho,
        proof_chirho.activation_chirho.append_seq_chirho
    );
    assert_eq!(
        proof_chirho.canary_chirho.append_record_digest_chirho,
        proof_chirho.activation_chirho.append_record_digest_chirho
    );
    assert_eq!(
        proof_chirho.canary_chirho.durable_term_chirho,
        proof_chirho.activation_chirho.durable_term_chirho
    );
    assert_eq!(
        proof_chirho.canary_chirho.fence_epoch_chirho,
        proof_chirho.activation_chirho.fence_epoch_chirho
    );
    assert_eq!(proof_chirho.canary_chirho.window_len_chirho, 1);
    assert_eq!(proof_chirho.canary_chirho.permit_count_chirho, 1);
    assert_eq!(proof_chirho.canary_chirho.refusal_count_chirho, 0);
    assert_eq!(
        stage_chirho.staging_parent_name_chirho(),
        Some("fresh-ledger-staging-chirho")
    );
    assert!(stage_chirho.staged_storage_namespace_root_chirho().is_dir());
    assert!(stage_chirho.staged_monitor_namespace_root_chirho().is_dir());
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho")
        .exists());
    let journal_chirho = fs::read(
        stage_chirho
            .staged_storage_namespace_root_chirho()
            .join("journals/main-chirho.jsonl"),
    )
    .unwrap();
    assert_eq!(
        journal_chirho
            .iter()
            .filter(|byte_chirho| **byte_chirho == b'\n')
            .count(),
        2
    );
}

#[test]
fn activation_canary_separates_dormant_append_hlc_from_observation_time_chirho() {
    let fixture_chirho = fixture_chirho();
    let before_chirho = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_millis(),
    )
    .expect("test clock fits u64 milliseconds");
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    let after_chirho = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_millis(),
    )
    .expect("test clock fits u64 milliseconds");
    let record_path_chirho = stage_chirho
        .staged_monitor_namespace_root_chirho()
        .join("writer-canary-chirho/records-chirho/slot-0001-chirho.json");
    let record_chirho: cairn_writer_elector_chirho::shadow_canary_chirho::SignedShadowCanaryEvidenceChirho =
        serde_json::from_slice(&fs::read(record_path_chirho).unwrap()).unwrap();
    let observation_chirho = record_chirho.observation_chirho;

    assert_eq!(
        observation_chirho
            .append_cut_chirho
            .append_hlc_physical_ms_chirho,
        fixture_chirho.plan_chirho.mint_physical_ms_chirho,
        "Cf8ActivationCanaryAppendHlcBindingRefusedChirho"
    );
    assert_ne!(
        observation_chirho.at_ms_chirho, fixture_chirho.plan_chirho.mint_physical_ms_chirho,
        "Cf8ActivationCanaryObservationClockMutationSurvivedChirho"
    );
    assert!(
        observation_chirho.at_ms_chirho >= before_chirho,
        "Cf8ActivationCanaryObservationPreActivationRefusedChirho"
    );
    assert!(
        observation_chirho.at_ms_chirho <= after_chirho,
        "Cf8ActivationCanaryObservationFutureRefusedChirho"
    );
}

#[test]
fn staged_resident_publication_verification_is_tree_read_only_chirho() {
    let fixture_chirho = fixture_chirho();
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    let expected_activation_chirho = stage_chirho.proof_chirho().activation_chirho.clone();
    let expected_resident_identity_digest_chirho = stage_chirho
        .activation_receipt_chirho
        .resident_identity_digest_chirho
        .clone();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);

    let publication_proof_chirho =
        crate::publication_verify_chirho::verify_staged_resident_chirho(&stage_chirho).unwrap();

    assert_eq!(
        publication_proof_chirho.journal_tail_seq_chirho,
        expected_activation_chirho.append_seq_chirho
    );
    assert_eq!(
        publication_proof_chirho.journal_tail_digest_chirho,
        expected_activation_chirho.append_record_digest_chirho
    );
    assert_eq!(
        publication_proof_chirho.resident_identity_digest_chirho,
        expected_resident_identity_digest_chirho
    );
    assert_eq!(
        publication_proof_chirho.fence_epoch_chirho,
        expected_activation_chirho.fence_epoch_chirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho,
        "publication verification must not mutate the staged or selected root"
    );
}

#[test]
fn execution_consumes_the_presigned_artifact_without_activation_key_custody_chirho() {
    let fixture_chirho = fixture_chirho();
    fs::remove_file(
        fixture_chirho
            .root_chirho
            .join(cairn_secret_chirho::secret_chirho::SECRETS_DIR_CHIRHO)
            .join(format!(
                "{}.secret-chirho",
                fixture_chirho.activation_secret_name_chirho
            )),
    )
    .unwrap();
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    assert_eq!(
        stage_chirho
            .proof_chirho()
            .activation_chirho
            .append_seq_chirho,
        1
    );
}

#[test]
fn existing_final_or_staging_namespace_refuses_without_modification_chirho() {
    for existing_name_chirho in ["fresh-ledger-parent-chirho", "fresh-ledger-staging-chirho"] {
        let fixture_chirho = fixture_chirho();
        fs::create_dir(fixture_chirho.root_chirho.join(existing_name_chirho)).unwrap();
        let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
        let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
        let expected_chirho = if existing_name_chirho == "fresh-ledger-parent-chirho" {
            LedgerRegenesisRefusalChirho::FinalNamespaceExistsChirho
        } else {
            LedgerRegenesisRefusalChirho::StagingNamespaceExistsChirho
        };
        assert_eq!(error_chirho, expected_chirho);
        assert_eq!(
            snapshot_tree_chirho(&fixture_chirho.root_chirho),
            before_chirho
        );
    }
}

#[test]
fn bad_issuer_refuses_before_any_staging_or_final_write_chirho() {
    let mut fixture_chirho = fixture_chirho();
    fixture_chirho.issuer_secret_name_chirho = "missing-offline-issuer-chirho".to_owned();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-staging-chirho")
        .exists());
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho")
        .exists());
}

#[test]
fn missing_activation_config_refuses_before_any_staging_or_final_write_chirho() {
    let fixture_chirho = fixture_chirho();
    let mut config_chirho =
        cairn_config_chirho::config_chirho::load_config_chirho(&fixture_chirho.config_path_chirho)
            .unwrap();
    config_chirho
        .ledger_host_chirho
        .as_mut()
        .unwrap()
        .activation_authority_chirho = None;
    fs::write(
        &fixture_chirho.config_path_chirho,
        cairn_config_chirho::config_chirho::serialize_config_chirho(&config_chirho).unwrap(),
    )
    .unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    assert_eq!(
        prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err(),
        LedgerRegenesisRefusalChirho::ActivationConfigMissingChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-staging-chirho")
        .exists());
}

#[test]
fn missing_tampered_or_wrong_digest_authorization_refuses_before_staging_chirho() {
    let missing_fixture_chirho = fixture_chirho();
    fs::remove_file(&missing_fixture_chirho.activation_authorization_path_chirho).unwrap();
    let missing_before_chirho = snapshot_tree_chirho(&missing_fixture_chirho.root_chirho);
    assert_eq!(
        prepare_money_stage_chirho(request_chirho(&missing_fixture_chirho)).unwrap_err(),
        LedgerRegenesisRefusalChirho::ActivationAuthorizationUnavailableChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&missing_fixture_chirho.root_chirho),
        missing_before_chirho
    );

    let tampered_fixture_chirho = fixture_chirho();
    let mut tampered_bytes_chirho =
        fs::read(&tampered_fixture_chirho.activation_authorization_path_chirho).unwrap();
    tampered_bytes_chirho.push(b'\n');
    fs::write(
        &tampered_fixture_chirho.activation_authorization_path_chirho,
        tampered_bytes_chirho,
    )
    .unwrap();
    let tampered_before_chirho = snapshot_tree_chirho(&tampered_fixture_chirho.root_chirho);
    assert_eq!(
        prepare_money_stage_chirho(request_chirho(&tampered_fixture_chirho)).unwrap_err(),
        LedgerRegenesisRefusalChirho::ActivationStatementRefusedChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&tampered_fixture_chirho.root_chirho),
        tampered_before_chirho
    );

    let mut wrong_digest_fixture_chirho = fixture_chirho();
    wrong_digest_fixture_chirho.expected_activation_authorization_digest_chirho = format!(
        "resident-ledger-activation-authorization-blake3-v1-chirho:{}",
        "00".repeat(32)
    );
    let wrong_digest_before_chirho = snapshot_tree_chirho(&wrong_digest_fixture_chirho.root_chirho);
    assert_eq!(
        prepare_money_stage_chirho(request_chirho(&wrong_digest_fixture_chirho)).unwrap_err(),
        LedgerRegenesisRefusalChirho::ActivationAuthorizationDigestMismatchChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&wrong_digest_fixture_chirho.root_chirho),
        wrong_digest_before_chirho
    );
}

#[test]
fn activation_secret_name_must_differ_from_the_kind_issuer_chirho() {
    let mut fixture_chirho = fixture_chirho();
    fixture_chirho.activation_secret_name_chirho = fixture_chirho.issuer_secret_name_chirho.clone();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    assert_eq!(
        crate::money_stage_chirho::author_ledger_regenesis_activation_chirho(
            crate::money_stage_chirho::LedgerRegenesisActivationAuthorRequestChirho {
                selected_root_chirho: &fixture_chirho.root_chirho,
                config_path_chirho: &fixture_chirho.config_path_chirho,
                plan_path_chirho: &fixture_chirho.plan_path_chirho,
                expected_plan_digest_chirho: &fixture_chirho.expected_digest_chirho,
                issuer_secret_name_chirho: &fixture_chirho.issuer_secret_name_chirho,
                activation_secret_name_chirho: &fixture_chirho.activation_secret_name_chirho,
            },
        )
        .unwrap_err(),
        LedgerRegenesisRefusalChirho::ActivationSecretMatchesIssuerChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn bad_initial_membership_refuses_before_any_staging_or_final_write_chirho() {
    let fixture_chirho = fixture_chirho();
    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho)
        .unwrap()
        .replace(
            "owner_chirho = \"platform-credits-owner-chirho\"",
            "owner_chirho = \"different-credits-owner-chirho\"",
        );
    fs::write(&fixture_chirho.config_path_chirho, config_chirho).unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let error_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::ConfigPlanMismatchChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-staging-chirho")
        .exists());
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho")
        .exists());
}

#[test]
fn crash_before_publication_leaves_only_nonlive_staging_chirho() {
    let fixture_chirho = fixture_chirho();
    let verified_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &fixture_chirho.expected_digest_chirho,
    )
    .unwrap();
    let begun_chirho = begin_staging_chirho(&verified_chirho).unwrap();
    assert!(begun_chirho.storage_chirho.namespace_root_chirho().is_dir());
    assert!(verified_chirho.staging_parent_chirho.is_dir());
    assert!(!verified_chirho.final_parent_chirho.exists());
}

#[test]
fn completed_stage_publishes_by_one_parent_rename_chirho() {
    let fixture_chirho = fixture_chirho();
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    let expected_authorization_digest_chirho = stage_chirho
        .activation_receipt_chirho
        .authorization_digest_chirho
        .clone();
    let expected_identity_digest_chirho = stage_chirho
        .activation_receipt_chirho
        .resident_identity_digest_chirho
        .clone();
    let expected_append_seq_chirho = stage_chirho.activation_receipt_chirho.append_seq_chirho;
    let expected_append_digest_chirho = stage_chirho
        .activation_receipt_chirho
        .append_record_digest_chirho
        .clone();
    let expected_durable_term_chirho = stage_chirho.activation_receipt_chirho.durable_term_chirho;
    let expected_canary_digest_chirho = stage_chirho.canary_evidence_digest_chirho.clone();
    let completed_chirho = complete_money_stage_chirho(stage_chirho).unwrap();
    let packet_digest_chirho = completed_chirho.packet_digest_chirho.clone();
    let receipt_chirho = publish_completed_stage_chirho(completed_chirho).unwrap();
    assert_eq!(receipt_chirho.packet_digest_chirho, packet_digest_chirho);
    assert_eq!(
        receipt_chirho.final_parent_name_chirho,
        "fresh-ledger-parent-chirho"
    );
    assert_eq!(
        receipt_chirho
            .publication_proof_chirho
            .activation_authorization_digest_chirho,
        expected_authorization_digest_chirho
    );
    assert_eq!(
        receipt_chirho
            .publication_proof_chirho
            .canary_evidence_digest_chirho,
        expected_canary_digest_chirho
    );
    assert_eq!(
        receipt_chirho
            .publication_proof_chirho
            .resident_identity_digest_chirho,
        expected_identity_digest_chirho
    );
    assert_eq!(
        receipt_chirho
            .publication_proof_chirho
            .journal_tail_seq_chirho,
        expected_append_seq_chirho
    );
    assert_eq!(
        receipt_chirho
            .publication_proof_chirho
            .journal_tail_digest_chirho,
        expected_append_digest_chirho
    );
    assert!(
        receipt_chirho.publication_proof_chirho.durable_term_chirho >= expected_durable_term_chirho
    );
    assert!(fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho/ledger-chirho")
        .is_dir());
    assert!(!fixture_chirho
        .root_chirho
        .join("fresh-ledger-staging-chirho")
        .exists());
}

#[test]
fn published_activation_cannot_replay_after_final_namespace_removal_chirho() {
    let fixture_chirho = fixture_chirho();
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    let completed_chirho = complete_money_stage_chirho(stage_chirho).unwrap();
    let published_chirho = publish_completed_stage_chirho(completed_chirho).unwrap();
    assert_eq!(
        published_chirho
            .publication_proof_chirho
            .journal_tail_seq_chirho,
        1
    );
    let final_parent_chirho = fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho");
    fs::remove_dir_all(&final_parent_chirho).unwrap();

    let replay_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho));
    assert_eq!(
        replay_chirho.unwrap_err(),
        LedgerRegenesisRefusalChirho::MoneyProvisionRefusedChirho
    );
    let retry_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
        &fixture_chirho
            .root_chirho
            .join("fresh-ledger-staging-chirho/ledger-chirho"),
    )
    .unwrap();
    assert_eq!(
        retry_storage_chirho
            .read_all_chirho(&StoragePathChirho::new_chirho(
                &fixture_chirho.plan_chirho.journal_path_chirho,
            ))
            .unwrap(),
        None,
        "the consumed authorization must not append a second mint even after final deletion"
    );
}

#[test]
fn packet_or_publication_manifest_tamper_refuses_before_rename_chirho() {
    for tamper_chirho in ["packet-chirho", "manifest-chirho"] {
        let fixture_chirho = fixture_chirho();
        let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
        let completed_chirho = complete_money_stage_chirho(stage_chirho).unwrap();
        let monitor_root_chirho = completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .to_path_buf();
        let target_chirho = match tamper_chirho {
            "packet-chirho" => {
                monitor_root_chirho.join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO)
            }
            "manifest-chirho" => {
                monitor_root_chirho.join(LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO)
            }
            _ => unreachable!("the tamper set is fixed"),
        };
        fs::write(&target_chirho, b"{\"tampered_chirho\":true}").unwrap();
        assert!(publish_completed_stage_chirho(completed_chirho).is_err());
        assert!(!fixture_chirho
            .root_chirho
            .join("fresh-ledger-parent-chirho")
            .exists());
        assert!(fixture_chirho
            .root_chirho
            .join("fresh-ledger-staging-chirho")
            .is_dir());
    }
}

#[test]
fn publication_rename_never_replaces_an_existing_destination_chirho() {
    let fixture_chirho = fixture_chirho();
    let from_chirho = fixture_chirho.root_chirho.join("rename-from-chirho");
    let to_chirho = fixture_chirho.root_chirho.join("rename-to-chirho");
    fs::create_dir(&from_chirho).unwrap();
    fs::create_dir(&to_chirho).unwrap();
    let sentinel_chirho = to_chirho.join("sentinel-chirho");
    fs::write(&sentinel_chirho, b"destination-survives-chirho").unwrap();

    let error_chirho = no_replace_rename_chirho(&from_chirho, &to_chirho).unwrap_err();
    assert_eq!(error_chirho.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(from_chirho.is_dir());
    assert_eq!(
        fs::read(&sentinel_chirho).unwrap(),
        b"destination-survives-chirho"
    );
}

#[test]
fn publication_fsync_refuses_a_tree_beyond_the_depth_budget_chirho() {
    let fixture_chirho = fixture_chirho();
    let bounded_root_chirho = fixture_chirho.root_chirho.join("bounded-tree-chirho");
    fs::create_dir(&bounded_root_chirho).unwrap();
    let mut cursor_chirho = bounded_root_chirho.clone();
    for depth_chirho in 0..34 {
        cursor_chirho = cursor_chirho.join(format!("depth-{depth_chirho}-chirho"));
        fs::create_dir(&cursor_chirho).unwrap();
    }
    assert_eq!(
        bounded_recursive_fsync_chirho(&bounded_root_chirho).unwrap_err(),
        LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho
    );
}

#[test]
fn publication_refuses_a_missing_moved_canary_without_recreating_it_chirho() {
    let fixture_chirho = fixture_chirho();
    let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
    let completed_chirho = complete_money_stage_chirho(stage_chirho).unwrap();
    let monitor_child_chirho = completed_chirho
        .money_stage_chirho
        .staged_monitor_namespace_root_chirho()
        .file_name()
        .unwrap()
        .to_owned();
    fs::remove_dir_all(
        completed_chirho
            .money_stage_chirho
            .staged_monitor_namespace_root_chirho()
            .join("writer-canary-chirho"),
    )
    .unwrap();
    let final_parent_chirho = fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho");
    let staging_parent_chirho = fixture_chirho
        .root_chirho
        .join("fresh-ledger-staging-chirho");
    let result_chirho = publish_completed_stage_chirho(completed_chirho);
    assert_eq!(
        result_chirho.unwrap_err(),
        LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho
    );
    assert!(!final_parent_chirho.exists());
    assert!(staging_parent_chirho.is_dir());
    assert!(!staging_parent_chirho
        .join(monitor_child_chirho)
        .join("writer-canary-chirho")
        .exists());
}

#[test]
fn publication_refuses_activation_receipt_tail_or_canary_cut_mismatches_chirho() {
    for mismatch_chirho in [
        "seq-chirho",
        "digest-chirho",
        "hlc-physical-chirho",
        "hlc-logical-chirho",
        "generation-chirho",
        "term-chirho",
        "fence-chirho",
        "group-chirho",
    ] {
        let fixture_chirho = fixture_chirho();
        let stage_chirho = prepare_money_stage_chirho(request_chirho(&fixture_chirho)).unwrap();
        let mut completed_chirho = complete_money_stage_chirho(stage_chirho).unwrap();
        let stage_chirho = &mut completed_chirho.money_stage_chirho;
        match mismatch_chirho {
            "seq-chirho" => {
                stage_chirho.activation_receipt_chirho.append_seq_chirho += 1;
            }
            "digest-chirho" => {
                let digest_chirho = &mut stage_chirho
                    .activation_receipt_chirho
                    .append_record_digest_chirho;
                let first_chirho = if digest_chirho.0.starts_with('0') {
                    "1"
                } else {
                    "0"
                };
                digest_chirho.0.replace_range(0..1, first_chirho);
            }
            "hlc-physical-chirho" => {
                stage_chirho
                    .activation_receipt_chirho
                    .append_hlc_physical_ms_chirho += 1;
            }
            "hlc-logical-chirho" => {
                stage_chirho
                    .activation_receipt_chirho
                    .append_hlc_logical_chirho += 1;
            }
            "generation-chirho" => {
                stage_chirho
                    .activation_receipt_chirho
                    .process_generation_chirho += 1;
            }
            "term-chirho" => {
                let term_chirho = &mut stage_chirho.activation_receipt_chirho.durable_term_chirho;
                *term_chirho = if *term_chirho == 0 {
                    1
                } else {
                    *term_chirho - 1
                };
            }
            "fence-chirho" => {
                stage_chirho.activation_receipt_chirho.fence_epoch_chirho += 1;
            }
            "group-chirho" => {
                stage_chirho
                    .activation_receipt_chirho
                    .fence_group_digest_chirho
                    .replace_range(0..1, "x");
            }
            _ => unreachable!("the mismatch set is fixed"),
        }
        let result_chirho = publish_completed_stage_chirho(completed_chirho);
        assert_eq!(
            result_chirho.unwrap_err(),
            LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho,
            "{mismatch_chirho} must fail exact prepublication binding"
        );
        assert!(!fixture_chirho
            .root_chirho
            .join("fresh-ledger-parent-chirho")
            .exists());
        assert!(fixture_chirho
            .root_chirho
            .join("fresh-ledger-staging-chirho")
            .is_dir());
    }
}
