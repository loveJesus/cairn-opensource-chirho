// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_ledger_sim_chirho::fault_chirho::{FaultKindChirho, FaultPlanChirho};
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};

struct TestTransferSignerChirho {
    key_id_chirho: String,
}

impl TestTransferSignerChirho {
    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut bytes_chirho = self.key_id_chirho.as_bytes().to_vec();
        bytes_chirho.extend_from_slice(line_chirho.as_bytes());
        blake3::hash(&bytes_chirho).to_hex().to_string()
    }
}

impl Gd7ReconciliationVerifierPortChirho for TestTransferSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(canonical_unsigned_chirho) == sig_chirho
    }
}

impl Gd7ReconciliationSignerPortChirho for TestTransferSignerChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> anyhow::Result<String> {
        Ok(self.signature_chirho(canonical_unsigned_chirho))
    }
}

fn identity_chirho() -> Gd7HeldViewTransferIdentityChirho {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-held-transfer-crash-order-chirho".to_owned(),
    };
    Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        reconciliation_checkpoint_ref_chirho: "c".repeat(64),
        winner_node_chirho: "a".repeat(64),
        held_node_chirho: "b".repeat(64),
        winner_term_chirho: 7,
    }
}

fn challenge_bytes_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    held_node_chirho: String,
    transfer_identity_digest_chirho: String,
) -> Vec<u8> {
    challenge_bytes_with_nonce_chirho(
        identity_chirho,
        held_node_chirho,
        transfer_identity_digest_chirho,
        "d".repeat(64),
    )
}

fn challenge_bytes_with_nonce_chirho(
    identity_chirho: &Gd7HeldViewTransferIdentityChirho,
    held_node_chirho: String,
    transfer_identity_digest_chirho: String,
    nonce_chirho: String,
) -> Vec<u8> {
    Gd7WinnerCurrentViewChallengeChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO.to_owned(),
        nonce_chirho,
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        expected_winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        held_node_chirho,
        transfer_identity_digest_chirho,
        raft_term_chirho: identity_chirho.winner_term_chirho,
    }
    .canonical_bytes_chirho()
    .expect("encode held transfer challenge")
}

struct CompleteCheckpointFixtureChirho {
    identity_chirho: Gd7HeldViewTransferIdentityChirho,
    expected_bundle_root_chirho: String,
    held_signer_chirho: TestTransferSignerChirho,
    winner_verifier_chirho: TestTransferSignerChirho,
    checkpoint_ref_chirho: String,
    checkpoint_chirho: Gd7HeldViewTransferCheckpointChirho,
}

fn sign_checkpoint_and_ref_chirho(
    checkpoint_chirho: &mut Gd7HeldViewTransferCheckpointChirho,
    held_signer_chirho: &TestTransferSignerChirho,
) -> String {
    checkpoint_chirho.key_id_chirho = checkpoint_chirho.identity_chirho.held_node_chirho.clone();
    checkpoint_chirho.sig_chirho.clear();
    let unsigned_bytes_chirho =
        canonical_json_chirho(checkpoint_chirho).expect("encode unsigned held checkpoint");
    checkpoint_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(
            std::str::from_utf8(&unsigned_bytes_chirho)
                .expect("held checkpoint canonical JSON is UTF-8"),
        )
        .expect("sign held checkpoint");
    digest_bytes_chirho(
        &canonical_json_chirho(checkpoint_chirho).expect("encode signed held checkpoint"),
    )
}

fn complete_checkpoint_fixture_chirho() -> CompleteCheckpointFixtureChirho {
    let identity_chirho = identity_chirho();
    let held_signer_chirho = TestTransferSignerChirho {
        key_id_chirho: identity_chirho.held_node_chirho.clone(),
    };
    let winner_verifier_chirho = TestTransferSignerChirho {
        key_id_chirho: identity_chirho.winner_node_chirho.clone(),
    };
    let identity_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&identity_chirho).expect("encode held transfer identity"),
    );
    let challenge_bytes_chirho = challenge_bytes_chirho(
        &identity_chirho,
        identity_chirho.held_node_chirho.clone(),
        identity_digest_chirho,
    );
    let challenge_digest_chirho = digest_bytes_chirho(&challenge_bytes_chirho);
    let source_cut_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: compose_writer_epoch_chirho(identity_chirho.winner_term_chirho, 1)
            .expect("compose winner epoch"),
        seq_chirho: 11,
        record_digest_chirho: "e".repeat(64),
    };
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "1".repeat(64),
        source_cut_chirho: source_cut_chirho.clone(),
        lowest_page_ref_chirho: None,
        page_count_chirho: 0,
        row_count_chirho: 0,
    };
    let root_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&root_chirho).expect("encode zero-page bundle root"),
    );
    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho,
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        raft_term_chirho: identity_chirho.winner_term_chirho,
        winner_process_generation_chirho: 19,
        winner_journal_genesis_digest_chirho: root_chirho
            .winner_journal_genesis_digest_chirho
            .clone(),
        latest_verified_journal_cut_chirho: source_cut_chirho,
        view_bundle_root_chirho: root_digest_chirho.clone(),
        key_id_chirho: identity_chirho.winner_node_chirho.clone(),
        sig_chirho: String::new(),
    };
    let unsigned_evidence_bytes_chirho =
        canonical_json_chirho(&evidence_chirho).expect("encode unsigned winner evidence");
    evidence_chirho.sig_chirho = winner_verifier_chirho
        .sign_chirho(
            std::str::from_utf8(&unsigned_evidence_bytes_chirho)
                .expect("winner evidence canonical JSON is UTF-8"),
        )
        .expect("sign winner evidence");
    let evidence_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&evidence_chirho).expect("encode signed winner evidence"),
    );
    let inspection_chirho = Gd7WinnerCurrentViewInspectionChirho {
        evidence_object_digest_chirho: evidence_digest_chirho,
        evidence_chirho,
        bundle_root_object_digest_chirho: root_digest_chirho.clone(),
        bundle_root_chirho: root_chirho,
    };
    let mut checkpoint_chirho = Gd7HeldViewTransferCheckpointChirho {
        schema_chirho: GD7_HELD_VIEW_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: identity_chirho.clone(),
        transition_seq_chirho: 3,
        previous_checkpoint_ref_chirho: Some("2".repeat(64)),
        phase_chirho: Gd7HeldViewTransferPhaseChirho::CompleteChirho,
        expected_stage_index_chirho: 1,
        canonical_challenge_chirho: Some(
            String::from_utf8(challenge_bytes_chirho)
                .expect("held transfer challenge canonical JSON is UTF-8"),
        ),
        staged_bundle_root_ref_chirho: Some(root_digest_chirho.clone()),
        staged_page_count_chirho: Some(0),
        staged_row_count_chirho: Some(0),
        inspection_chirho: Some(inspection_chirho),
        next_page_grant_chirho: None,
        received_page_count_chirho: 0,
        received_row_count_chirho: 0,
        latest_received_page_ref_chirho: None,
        stale_reason_chirho: None,
        key_id_chirho: String::new(),
        sig_chirho: String::new(),
    };
    let checkpoint_ref_chirho =
        sign_checkpoint_and_ref_chirho(&mut checkpoint_chirho, &held_signer_chirho);
    CompleteCheckpointFixtureChirho {
        identity_chirho,
        expected_bundle_root_chirho: root_digest_chirho,
        held_signer_chirho,
        winner_verifier_chirho,
        checkpoint_ref_chirho,
        checkpoint_chirho,
    }
}

fn verify_complete_fixture_chirho(
    fixture_chirho: &CompleteCheckpointFixtureChirho,
    checkpoint_ref_chirho: &str,
    checkpoint_chirho: &Gd7HeldViewTransferCheckpointChirho,
    expected_bundle_root_chirho: &str,
) -> Result<(), Gd7HeldViewTransferStoreRefusalChirho> {
    verify_complete_gd7_held_view_transfer_checkpoint_chirho(
        checkpoint_ref_chirho,
        checkpoint_chirho,
        &fixture_chirho.identity_chirho,
        expected_bundle_root_chirho,
        &fixture_chirho.held_signer_chirho,
        &fixture_chirho.winner_verifier_chirho,
    )
}

#[test]
fn complete_checkpoint_verifier_accepts_exact_signed_authority_chirho() {
    let fixture_chirho = complete_checkpoint_fixture_chirho();

    verify_complete_fixture_chirho(
        &fixture_chirho,
        &fixture_chirho.checkpoint_ref_chirho,
        &fixture_chirho.checkpoint_chirho,
        &fixture_chirho.expected_bundle_root_chirho,
    )
    .expect("the exact held-signed Complete checkpoint is valid winner-handoff authority");
}

#[test]
fn complete_checkpoint_verifier_rejects_digest_or_held_signature_mismatch_chirho() {
    let fixture_chirho = complete_checkpoint_fixture_chirho();
    assert_eq!(
        verify_complete_fixture_chirho(
            &fixture_chirho,
            &"f".repeat(64),
            &fixture_chirho.checkpoint_chirho,
            &fixture_chirho.expected_bundle_root_chirho,
        )
        .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::DigestMismatchChirho
    );

    let mut invalid_signature_chirho = fixture_chirho.checkpoint_chirho.clone();
    invalid_signature_chirho.sig_chirho = "0".repeat(64);
    let invalid_signature_ref_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&invalid_signature_chirho)
            .expect("encode checkpoint with invalid held signature"),
    );
    assert_eq!(
        verify_complete_fixture_chirho(
            &fixture_chirho,
            &invalid_signature_ref_chirho,
            &invalid_signature_chirho,
            &fixture_chirho.expected_bundle_root_chirho,
        )
        .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::InvalidCheckpointSignatureChirho
    );
}

#[test]
fn complete_checkpoint_verifier_binds_every_transfer_identity_field_chirho() {
    let fixture_chirho = complete_checkpoint_fixture_chirho();
    let other_group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-other-held-transfer-chirho".to_owned(),
    };
    let mut wrong_identities_chirho = Vec::new();

    let mut wrong_group_chirho = fixture_chirho.identity_chirho.clone();
    wrong_group_chirho.consistency_group_digest_chirho =
        consistency_group_digest_chirho(&other_group_chirho).expect("digest other group");
    wrong_identities_chirho.push(("consistency group", wrong_group_chirho));

    let mut wrong_reconciliation_chirho = fixture_chirho.identity_chirho.clone();
    wrong_reconciliation_chirho.reconciliation_checkpoint_ref_chirho = "9".repeat(64);
    wrong_identities_chirho.push(("reconciliation checkpoint", wrong_reconciliation_chirho));

    let mut wrong_winner_chirho = fixture_chirho.identity_chirho.clone();
    wrong_winner_chirho.winner_node_chirho = "8".repeat(64);
    wrong_identities_chirho.push(("winner node", wrong_winner_chirho));

    let mut wrong_held_chirho = fixture_chirho.identity_chirho.clone();
    wrong_held_chirho.held_node_chirho = "7".repeat(64);
    wrong_identities_chirho.push(("held node", wrong_held_chirho));

    let mut wrong_term_chirho = fixture_chirho.identity_chirho.clone();
    wrong_term_chirho.winner_term_chirho += 1;
    wrong_identities_chirho.push(("winner term", wrong_term_chirho));

    for (field_chirho, wrong_identity_chirho) in wrong_identities_chirho {
        let mut checkpoint_chirho = fixture_chirho.checkpoint_chirho.clone();
        checkpoint_chirho.identity_chirho = wrong_identity_chirho.clone();
        let matching_held_signer_chirho = TestTransferSignerChirho {
            key_id_chirho: wrong_identity_chirho.held_node_chirho,
        };
        let checkpoint_ref_chirho =
            sign_checkpoint_and_ref_chirho(&mut checkpoint_chirho, &matching_held_signer_chirho);
        assert_eq!(
            verify_complete_fixture_chirho(
                &fixture_chirho,
                &checkpoint_ref_chirho,
                &checkpoint_chirho,
                &fixture_chirho.expected_bundle_root_chirho,
            )
            .unwrap_err(),
            Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho,
            "{field_chirho} must bind the exact completed held transfer"
        );
    }
}

#[test]
fn complete_checkpoint_verifier_rejects_non_complete_or_wrong_root_chirho() {
    let fixture_chirho = complete_checkpoint_fixture_chirho();
    let mut non_complete_chirho = fixture_chirho.checkpoint_chirho.clone();
    non_complete_chirho.phase_chirho = Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho;
    non_complete_chirho.inspection_chirho = None;
    let non_complete_ref_chirho = sign_checkpoint_and_ref_chirho(
        &mut non_complete_chirho,
        &fixture_chirho.held_signer_chirho,
    );
    assert_eq!(
        verify_complete_fixture_chirho(
            &fixture_chirho,
            &non_complete_ref_chirho,
            &non_complete_chirho,
            &fixture_chirho.expected_bundle_root_chirho,
        )
        .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::InvalidStateChirho
    );

    assert_eq!(
        verify_complete_fixture_chirho(
            &fixture_chirho,
            &fixture_chirho.checkpoint_ref_chirho,
            &fixture_chirho.checkpoint_chirho,
            &"9".repeat(64),
        )
        .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho
    );
}

#[test]
fn complete_checkpoint_verifier_rejects_invalid_winner_signature_or_challenge_chirho() {
    let fixture_chirho = complete_checkpoint_fixture_chirho();
    let mut invalid_signature_chirho = fixture_chirho.checkpoint_chirho.clone();
    let invalid_signature_inspection_chirho = invalid_signature_chirho
        .inspection_chirho
        .as_mut()
        .expect("complete checkpoint has winner inspection");
    invalid_signature_inspection_chirho
        .evidence_chirho
        .sig_chirho = "0".repeat(64);
    invalid_signature_inspection_chirho.evidence_object_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&invalid_signature_inspection_chirho.evidence_chirho)
            .expect("encode winner evidence with invalid signature"),
    );
    let invalid_signature_ref_chirho = sign_checkpoint_and_ref_chirho(
        &mut invalid_signature_chirho,
        &fixture_chirho.held_signer_chirho,
    );
    assert_eq!(
        verify_complete_fixture_chirho(
            &fixture_chirho,
            &invalid_signature_ref_chirho,
            &invalid_signature_chirho,
            &fixture_chirho.expected_bundle_root_chirho,
        )
        .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho
    );

    let mut invalid_challenge_chirho = fixture_chirho.checkpoint_chirho.clone();
    let identity_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&fixture_chirho.identity_chirho)
            .expect("encode held transfer identity"),
    );
    invalid_challenge_chirho.canonical_challenge_chirho = Some(
        String::from_utf8(challenge_bytes_with_nonce_chirho(
            &fixture_chirho.identity_chirho,
            fixture_chirho.identity_chirho.held_node_chirho.clone(),
            identity_digest_chirho,
            "6".repeat(64),
        ))
        .expect("alternate canonical challenge is UTF-8"),
    );
    let invalid_challenge_ref_chirho = sign_checkpoint_and_ref_chirho(
        &mut invalid_challenge_chirho,
        &fixture_chirho.held_signer_chirho,
    );
    assert_eq!(
        verify_complete_fixture_chirho(
            &fixture_chirho,
            &invalid_challenge_ref_chirho,
            &invalid_challenge_chirho,
            &fixture_chirho.expected_bundle_root_chirho,
        )
        .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho
    );
}

#[test]
fn complete_checkpoint_verifier_rejects_staged_or_received_count_mismatch_chirho() {
    let fixture_chirho = complete_checkpoint_fixture_chirho();
    let mut count_mismatches_chirho = Vec::new();

    let mut staged_count_chirho = fixture_chirho.checkpoint_chirho.clone();
    staged_count_chirho.staged_page_count_chirho = Some(1);
    count_mismatches_chirho.push(("staged page count", staged_count_chirho));

    let mut received_count_chirho = fixture_chirho.checkpoint_chirho.clone();
    received_count_chirho.received_row_count_chirho = 1;
    count_mismatches_chirho.push(("received row count", received_count_chirho));

    for (count_chirho, mut checkpoint_chirho) in count_mismatches_chirho {
        let checkpoint_ref_chirho = sign_checkpoint_and_ref_chirho(
            &mut checkpoint_chirho,
            &fixture_chirho.held_signer_chirho,
        );
        assert_eq!(
            verify_complete_fixture_chirho(
                &fixture_chirho,
                &checkpoint_ref_chirho,
                &checkpoint_chirho,
                &fixture_chirho.expected_bundle_root_chirho,
            )
            .unwrap_err(),
            Gd7HeldViewTransferStoreRefusalChirho::InvalidWinnerEvidenceChirho,
            "{count_chirho} must match the signed winner root"
        );
    }
}

#[test]
fn challenge_must_bind_the_exact_held_transfer_before_head_advance_chirho() {
    let held_signer_chirho = TestTransferSignerChirho {
        key_id_chirho: "b".repeat(64),
    };
    let winner_verifier_chirho = TestTransferSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let identity_chirho = identity_chirho();
    let store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        identity_chirho.clone(),
    )
    .expect("open exact held transfer store");
    let initial_chirho = store_chirho
        .ensure_initialized_chirho()
        .expect("initialize held transfer");
    let staged_root_chirho = "e".repeat(64);

    let wrong_held_chirho = challenge_bytes_chirho(
        &identity_chirho,
        "f".repeat(64),
        store_chirho.identity_digest_chirho().to_owned(),
    );
    assert_eq!(
        store_chirho
            .commit_challenge_issued_chirho(
                &initial_chirho.checkpoint_ref_chirho,
                0,
                staged_root_chirho.clone(),
                1,
                1,
                &wrong_held_chirho,
            )
            .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho
    );

    let wrong_identity_chirho = challenge_bytes_chirho(
        &identity_chirho,
        identity_chirho.held_node_chirho.clone(),
        "1".repeat(64),
    );
    assert_eq!(
        store_chirho
            .commit_challenge_issued_chirho(
                &initial_chirho.checkpoint_ref_chirho,
                0,
                staged_root_chirho.clone(),
                1,
                1,
                &wrong_identity_chirho,
            )
            .unwrap_err(),
        Gd7HeldViewTransferStoreRefusalChirho::InvalidTransitionChirho
    );
    assert_eq!(
        store_chirho
            .load_active_chirho()
            .expect("reload unchanged held transfer")
            .expect("held transfer head remains present"),
        initial_chirho,
        "either mismatched challenge must refuse before durable head advance"
    );

    let exact_chirho = challenge_bytes_chirho(
        &identity_chirho,
        identity_chirho.held_node_chirho.clone(),
        store_chirho.identity_digest_chirho().to_owned(),
    );
    let committed_chirho = store_chirho
        .commit_challenge_issued_chirho(
            &initial_chirho.checkpoint_ref_chirho,
            0,
            staged_root_chirho,
            1,
            1,
            &exact_chirho,
        )
        .expect("exact held transfer challenge advances the durable head");
    assert_eq!(
        committed_chirho.checkpoint_chirho.phase_chirho,
        Gd7HeldViewTransferPhaseChirho::ChallengeIssuedChirho
    );
}

#[test]
fn immutable_checkpoint_precedes_head_and_retry_recovers_exactly_chirho() {
    let held_signer_chirho = TestTransferSignerChirho {
        key_id_chirho: "b".repeat(64),
    };
    let winner_verifier_chirho = TestTransferSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let initial_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let initial_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &initial_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        identity_chirho(),
    )
    .unwrap();
    let initial_chirho = initial_store_chirho.ensure_initialized_chirho().unwrap();
    let initial_snapshot_chirho = initial_storage_chirho.snapshot_chirho();

    let crashing_storage_chirho = SimStorageChirho::restore_chirho(
        initial_snapshot_chirho,
        FaultPlanChirho::single_chirho(1, FaultKindChirho::CrashBeforeChirho),
    );
    let crashing_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &crashing_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        identity_chirho(),
    )
    .unwrap();
    assert!(
        crashing_store_chirho
            .commit_stage_advanced_chirho(&initial_chirho.checkpoint_ref_chirho, 0)
            .is_err(),
        "a crash before the fixed-head write must not report the transition committed"
    );
    assert!(crashing_storage_chirho.is_crashed_chirho());

    let recovered_storage_chirho = SimStorageChirho::restore_chirho(
        crashing_storage_chirho.snapshot_chirho(),
        FaultPlanChirho::none_chirho(),
    );
    let recovered_store_chirho = Gd7HeldViewTransferStoreChirho::new_chirho(
        &recovered_storage_chirho,
        &held_signer_chirho,
        &winner_verifier_chirho,
        identity_chirho(),
    )
    .unwrap();
    let recovered_prior_chirho = recovered_store_chirho
        .load_active_chirho()
        .unwrap()
        .expect("the old fixed head survives the interrupted transition");
    assert_eq!(recovered_prior_chirho, initial_chirho);
    recovered_store_chirho
        .commit_stage_advanced_chirho(&recovered_prior_chirho.checkpoint_ref_chirho, 0)
        .expect("retry reuses the exact immutable checkpoint and advances the head");
    let advanced_chirho = recovered_store_chirho
        .load_active_chirho()
        .unwrap()
        .expect("advanced transfer head reloads");
    assert_eq!(
        advanced_chirho
            .checkpoint_chirho
            .expected_stage_index_chirho,
        1
    );
    assert_eq!(advanced_chirho.checkpoint_chirho.transition_seq_chirho, 1);
}
