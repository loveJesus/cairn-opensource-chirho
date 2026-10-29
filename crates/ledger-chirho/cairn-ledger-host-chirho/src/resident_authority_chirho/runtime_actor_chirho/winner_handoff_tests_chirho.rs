// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::{
    active_from_committed_chirho, apply_aborted_commit_outcome_chirho,
    apply_preparing_commit_outcome_chirho, reconcile_unconfirmed_chirho,
    verify_historical_readiness_chirho, ResidentGd7WinnerHandoffRefusalChirho,
    ResidentGd7WinnerHandoffRuntimeChirho, ResidentLedgerAuthorityReadinessChirho,
};
use crate::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_winner_handoff_attempt_digest_chirho,
    generate_gd7_winner_current_view_challenge_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, Gd7ForkCoordinateChirho,
    Gd7HeldViewTransferIdentityChirho, Gd7JournalTailCoordinateChirho,
    Gd7ReconciliationCheckpointChirho, Gd7ReconciliationCheckpointStateChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationStoreRefusalChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerCurrentViewEvidenceChirho,
    Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerHandoffAttemptIdentityChirho,
    Gd7WinnerHandoffPhaseChirho, Gd7WinnerHandoffStoreChirho, Gd7WinnerViewBundleRootChirho,
    GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO,
    GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_read_model_chirho::account_net_projection_fold_ref_chirho;
use cairn_ledger_sim_chirho::fault_chirho::FaultPlanChirho;
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::cell::Cell;

struct InstalledAtomicWriteSyncFaultStorageChirho {
    inner_chirho: SimStorageChirho,
    fail_after_atomic_install_chirho: Cell<bool>,
}

impl InstalledAtomicWriteSyncFaultStorageChirho {
    fn new_chirho() -> Self {
        Self {
            inner_chirho: SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho()),
            fail_after_atomic_install_chirho: Cell::new(false),
        }
    }

    fn set_atomic_install_fault_chirho(&self, enabled_chirho: bool) {
        self.fail_after_atomic_install_chirho.set(enabled_chirho);
    }
}

impl LedgerStoragePortChirho for InstalledAtomicWriteSyncFaultStorageChirho {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<CreateDurableOutcomeChirho> {
        self.inner_chirho
            .create_durable_chirho(path_chirho, bytes_chirho)
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<()> {
        self.inner_chirho
            .append_durable_chirho(path_chirho, bytes_chirho)
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<Option<Vec<u8>>> {
        self.inner_chirho.read_all_chirho(path_chirho)
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<Option<u64>> {
        self.inner_chirho.object_len_chirho(path_chirho)
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.inner_chirho
            .read_exact_range_chirho(path_chirho, offset_chirho, len_chirho)
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<()> {
        self.inner_chirho
            .atomic_write_chirho(path_chirho, bytes_chirho)?;
        if self.fail_after_atomic_install_chirho.get() {
            return Err(anyhow::anyhow!(
                "test atomic write installed bytes but parent sync remained unconfirmed chirho"
            ));
        }
        Ok(())
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        new_len_chirho: u64,
    ) -> anyhow::Result<()> {
        self.inner_chirho
            .truncate_durable_chirho(path_chirho, new_len_chirho)
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> anyhow::Result<()> {
        self.inner_chirho.rename_chirho(from_chirho, to_chirho)
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<()> {
        self.inner_chirho.remove_chirho(path_chirho)
    }

    fn list_chirho(
        &self,
        prefix_chirho: &StoragePathChirho,
    ) -> anyhow::Result<Vec<StoragePathChirho>> {
        self.inner_chirho.list_chirho(prefix_chirho)
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<bool> {
        self.inner_chirho.exists_chirho(path_chirho)
    }
}

struct TestWinnerHandoffSignerChirho {
    key_id_chirho: String,
}

impl TestWinnerHandoffSignerChirho {
    fn signature_chirho(&self, canonical_unsigned_chirho: &str) -> String {
        let mut bytes_chirho = self.key_id_chirho.as_bytes().to_vec();
        bytes_chirho.extend_from_slice(canonical_unsigned_chirho.as_bytes());
        blake3::hash(&bytes_chirho).to_hex().to_string()
    }
}

impl Gd7ReconciliationVerifierPortChirho for TestWinnerHandoffSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(canonical_unsigned_chirho) == sig_chirho
    }
}

impl Gd7ReconciliationSignerPortChirho for TestWinnerHandoffSignerChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> anyhow::Result<String> {
        Ok(self.signature_chirho(canonical_unsigned_chirho))
    }
}

struct WinnerHandoffFixtureChirho {
    elector_chirho: RaftWriterElectorChirho,
    group_digest_chirho: String,
    attempt_identity_chirho: Gd7WinnerHandoffAttemptIdentityChirho,
    challenge_bytes_chirho: Vec<u8>,
    inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
}

fn digest_serialized_chirho<ValueChirho: serde::Serialize>(value_chirho: &ValueChirho) -> String {
    blake3::hash(&serde_json::to_vec(value_chirho).expect("serialize test value chirho"))
        .to_hex()
        .to_string()
}

fn handoff_fixture_chirho() -> WinnerHandoffFixtureChirho {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-actor-handoff-ambiguity-chirho".to_owned(),
    };
    let group_digest_chirho = consistency_group_digest_chirho(&group_chirho).unwrap();
    let winner_node_chirho = NodeIdChirho("a".repeat(64));
    let held_node_chirho = NodeIdChirho("b".repeat(64));
    let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        winner_node_chirho.clone(),
        group_chirho.clone(),
    )
    .unwrap()
    .with_leadership_warmup_lease_chirho();
    elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        let _outbound_messages_chirho = elector_chirho.tick_chirho();
    }
    let winner_term_chirho = elector_chirho.leadership_chirho(&group_chirho).term_chirho;
    let transfer_identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        reconciliation_checkpoint_ref_chirho: "c".repeat(64),
        winner_node_chirho: winner_node_chirho.0.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_term_chirho,
    };
    let transfer_identity_digest_chirho = digest_serialized_chirho(&transfer_identity_chirho);
    let issued_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        &elector_chirho,
        &group_chirho,
        &winner_node_chirho,
        &held_node_chirho,
        &transfer_identity_digest_chirho,
    )
    .unwrap();
    let challenge_bytes_chirho = issued_challenge_chirho.canonical_bytes_chirho().unwrap();
    let challenge_chirho =
        parse_canonical_gd7_winner_current_view_challenge_chirho(&challenge_bytes_chirho).unwrap();
    let challenge_digest_chirho = challenge_chirho.digest_chirho().unwrap();
    let source_cut_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: compose_writer_epoch_chirho(winner_term_chirho, 1).unwrap(),
        seq_chirho: 11,
        record_digest_chirho: "e".repeat(64),
    };
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "1".repeat(64),
        source_cut_chirho: source_cut_chirho.clone(),
        lowest_page_ref_chirho: None,
        page_count_chirho: 0,
        row_count_chirho: 0,
    };
    let root_digest_chirho = digest_serialized_chirho(&root_chirho);
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: winner_node_chirho.0.clone(),
    };
    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho: challenge_digest_chirho.clone(),
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        winner_node_chirho: winner_node_chirho.0.clone(),
        raft_term_chirho: winner_term_chirho,
        winner_process_generation_chirho: 19,
        winner_journal_genesis_digest_chirho: "1".repeat(64),
        latest_verified_journal_cut_chirho: source_cut_chirho,
        view_bundle_root_chirho: root_digest_chirho.clone(),
        key_id_chirho: winner_node_chirho.0.clone(),
        sig_chirho: String::new(),
    };
    evidence_chirho.sig_chirho = signer_chirho
        .sign_chirho(std::str::from_utf8(&serde_json::to_vec(&evidence_chirho).unwrap()).unwrap())
        .unwrap();
    let evidence_digest_chirho = digest_serialized_chirho(&evidence_chirho);
    WinnerHandoffFixtureChirho {
        elector_chirho,
        group_digest_chirho,
        attempt_identity_chirho: Gd7WinnerHandoffAttemptIdentityChirho {
            held_transfer_identity_chirho: transfer_identity_chirho,
            held_transfer_checkpoint_ref_chirho: "4".repeat(64),
            expected_bundle_root_object_digest_chirho: root_digest_chirho.clone(),
            challenge_digest_chirho,
        },
        challenge_bytes_chirho,
        inspection_chirho: Gd7WinnerCurrentViewInspectionChirho {
            evidence_object_digest_chirho: evidence_digest_chirho,
            evidence_chirho,
            bundle_root_object_digest_chirho: root_digest_chirho,
            bundle_root_chirho: root_chirho,
        },
    }
}

fn signed_plan_checkpoint_chirho(
    fixture_chirho: &WinnerHandoffFixtureChirho,
    held_signer_chirho: &TestWinnerHandoffSignerChirho,
) -> (String, Gd7ReconciliationCheckpointChirho) {
    let held_transfer_identity_chirho = &fixture_chirho
        .attempt_identity_chirho
        .held_transfer_identity_chirho;
    let winner_term_chirho = held_transfer_identity_chirho.winner_term_chirho;
    let losing_term_chirho = winner_term_chirho.saturating_sub(1);
    let winner_genesis_chirho = fixture_chirho
        .inspection_chirho
        .bundle_root_chirho
        .winner_journal_genesis_digest_chirho
        .clone();
    let plan_ref_chirho = "7".repeat(64);
    let mut checkpoint_chirho = Gd7ReconciliationCheckpointChirho {
        schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho: Gd7ReconciliationIdentityChirho {
            consistency_group_digest_chirho: fixture_chirho.group_digest_chirho.clone(),
            winner_node_chirho: held_transfer_identity_chirho.winner_node_chirho.clone(),
            held_node_chirho: held_transfer_identity_chirho.held_node_chirho.clone(),
            winner_term_chirho,
            losing_term_chirho,
            winner_journal_genesis_digest_chirho: winner_genesis_chirho.clone(),
            winner_journal_tail_chirho: fixture_chirho
                .inspection_chirho
                .bundle_root_chirho
                .source_cut_chirho
                .clone(),
            fork_chirho: Gd7ForkCoordinateChirho {
                epoch_chirho: compose_writer_epoch_chirho(losing_term_chirho, 1).unwrap(),
                seq_chirho: 1,
                record_digest_chirho: "5".repeat(64),
            },
            losing_journal_genesis_digest_chirho: winner_genesis_chirho,
            losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
                epoch_chirho: compose_writer_epoch_chirho(losing_term_chirho, 1).unwrap(),
                seq_chirho: 2,
                record_digest_chirho: "6".repeat(64),
            },
        },
        winner_fork_witness_object_digest_chirho: "4".repeat(64),
        state_chirho: Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
            transition_seq_chirho: 2,
            previous_checkpoint_ref_chirho: Some("1".repeat(64)),
            manifest_head_ref_chirho: Some("2".repeat(64)),
            manifest_page_count_chirho: 1,
            manifest_record_count_chirho: 1,
            plan_head_ref_chirho: Some(plan_ref_chirho.clone()),
            plan_page_count_chirho: 1,
            sealed_plan_ref_chirho: Some(plan_ref_chirho),
            effect_obligation_count_chirho: 0,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: None,
        },
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    checkpoint_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(
            std::str::from_utf8(
                &serde_json::to_vec(&checkpoint_chirho)
                    .expect("encode unsigned PlanSealed checkpoint"),
            )
            .expect("PlanSealed checkpoint is UTF-8"),
        )
        .expect("sign PlanSealed checkpoint");
    (
        digest_serialized_chirho(&checkpoint_chirho),
        checkpoint_chirho,
    )
}

fn assert_handoff_active_chirho(
    local_authority_chirho: &cairn_writer_elector_chirho::LocalAppendAuthorityHandleChirho,
) {
    assert!(matches!(
        local_authority_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
}

fn bind_inspection_generation_chirho(
    inspection_chirho: &mut Gd7WinnerCurrentViewInspectionChirho,
    signer_chirho: &TestWinnerHandoffSignerChirho,
    process_generation_chirho: u64,
) {
    inspection_chirho
        .evidence_chirho
        .winner_process_generation_chirho = process_generation_chirho;
    inspection_chirho.evidence_chirho.sig_chirho.clear();
    inspection_chirho.evidence_chirho.sig_chirho = signer_chirho
        .sign_chirho(
            std::str::from_utf8(
                &serde_json::to_vec(&inspection_chirho.evidence_chirho)
                    .expect("encode generation-bound winner evidence"),
            )
            .expect("winner evidence is UTF-8"),
        )
        .expect("sign generation-bound winner evidence");
    inspection_chirho.evidence_object_digest_chirho =
        digest_serialized_chirho(&inspection_chirho.evidence_chirho);
}

/// FLOORS-ONLY, and that is the entire contract this pins.
///
/// # WHY THIS TEST WAS RETARGETED — a pin that survived the loosening it pinned
///
/// It used to assert that `journal_tail_seq_chirho + 1` REFUSES, expecting
/// `WinnerStateChangedChirho`. Both halves went stale when strictness moved UP to
/// `verify_historical_cut_chirho`: this function's epoch/seq comparisons became FLOORS, so a tail
/// past the cut now passes, and the variant it asserted is not the one this path returns on a floor
/// violation. The test then failed with `unwrap_err()` on an `Ok` — **the pin outlived the property
/// it was written for, exactly as this function's own header warns a stale comment once did here.**
///
/// So it now pins what the subject ACTUALLY guarantees, in both directions: floors ADMIT a tail past
/// the cut (by design — the winner-side compensation lane is the one lawful mutation that moves it),
/// and floors still REFUSE a tail behind it.
///
/// **THE SAFETY PROPERTY IS NOT HERE.** "Every post-cut record is compensation-class and the
/// traversal reached the anchor" lives at the PAIR — `verify_historical_cut_chirho` plus
/// `verify_post_cut_extension_class_and_anchor_chirho` — and that traversal has NO test of its own.
/// Do not read this green as extension coverage; it is snapshot-floor coverage.
#[test]
fn historical_readiness_floors_admit_drift_past_the_cut_and_refuse_behind_it_chirho() {
    let fixture_chirho = handoff_fixture_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let winner_node_chirho = fixture_chirho
        .attempt_identity_chirho
        .held_transfer_identity_chirho
        .winner_node_chirho
        .clone();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: winner_node_chirho.clone(),
    };
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        fixture_chirho.group_digest_chirho.clone(),
        winner_node_chirho.clone(),
    )
    .unwrap();
    let (committed_chirho, durable_chirho) = store_chirho
        .commit_preparing_chirho(
            fixture_chirho.attempt_identity_chirho.clone(),
            &fixture_chirho.challenge_bytes_chirho,
            fixture_chirho.inspection_chirho.clone(),
            19,
        )
        .unwrap()
        .into_parts_chirho();
    assert!(durable_chirho);
    let active_chirho = active_from_committed_chirho(committed_chirho);
    let source_cut_chirho = &fixture_chirho
        .inspection_chirho
        .bundle_root_chirho
        .source_cut_chirho;
    let mut readiness_chirho = ResidentLedgerAuthorityReadinessChirho {
        consistency_group_chirho: fixture_chirho
            .elector_chirho
            .local_append_authority_handle_chirho()
            .consistency_group_chirho()
            .clone(),
        local_node_chirho: NodeIdChirho(winner_node_chirho),
        process_generation_chirho: 19,
        published_raft_term_chirho: fixture_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho
            .winner_term_chirho,
        journal_epoch_chirho: source_cut_chirho.epoch_chirho,
        membership_epoch_chirho: source_cut_chirho.epoch_chirho,
        journal_tail_seq_chirho: source_cut_chirho.seq_chirho,
        journal_tail_digest_chirho: cairn_ledger_model_chirho::ids_chirho::DigestChirho(
            source_cut_chirho.record_digest_chirho.clone(),
        ),
        genesis_digest_chirho: cairn_ledger_model_chirho::ids_chirho::DigestChirho(
            fixture_chirho
                .inspection_chirho
                .bundle_root_chirho
                .winner_journal_genesis_digest_chirho
                .clone(),
        ),
        resident_identity_digest_chirho: "4".repeat(64),
    };
    verify_historical_readiness_chirho(&readiness_chirho, &active_chirho)
        .expect("the exact sealed winner cut revalidates");

    // ABOVE the cut: ADMITTED, by design. The winner-side compensation lane is the one lawful
    // mutation that can move this tail, and refusing here would make its own handoff un-restorable.
    readiness_chirho.journal_tail_seq_chirho = source_cut_chirho.seq_chirho + 1;
    verify_historical_readiness_chirho(&readiness_chirho, &active_chirho).expect(
        "readiness floors must ADMIT a tail past the cut. If this now REFUSES, the floors were \
         tightened back to equality and the compensation lane's own handoff became un-restorable \
         — the failure ruled (a) was built to prevent. If instead it refuses for a DIFFERENT \
         reason, read the variant: only the floors are pinned here.",
    );

    // BEHIND the cut: REFUSED. A floor with no direction is not a floor, and without this arm the
    // one above would pass on a function that had stopped checking anything.
    readiness_chirho.journal_tail_seq_chirho = source_cut_chirho.seq_chirho.saturating_sub(1);
    assert_eq!(
        verify_historical_readiness_chirho(&readiness_chirho, &active_chirho).unwrap_err(),
        ResidentGd7WinnerHandoffRefusalChirho::HistoricalCutSnapshotRefusedChirho,
        "a tail BEHIND the sealed cut must refuse at the snapshot floors, and must refuse with the \
         snapshot variant rather than any tail/extension cause — the four causes were split apart \
         precisely so an arm could tell them apart"
    );
}

#[test]
fn ambiguous_preparing_activates_before_return_and_reconciles_without_unfreeze_chirho() {
    let mut fixture_chirho = handoff_fixture_chirho();
    let local_authority_chirho = fixture_chirho
        .elector_chirho
        .local_append_authority_handle_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho();
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        fixture_chirho.group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let attempt_digest_chirho =
        gd7_winner_handoff_attempt_digest_chirho(&fixture_chirho.attempt_identity_chirho).unwrap();
    let preparation_chirho = local_authority_chirho
        .try_prepare_handoff_chirho(&attempt_digest_chirho)
        .unwrap();
    bind_inspection_generation_chirho(
        &mut fixture_chirho.inspection_chirho,
        &signer_chirho,
        preparation_chirho.process_generation_chirho(),
    );

    storage_chirho.set_atomic_install_fault_chirho(true);
    let preparing_outcome_chirho = store_chirho
        .commit_preparing_chirho(
            fixture_chirho.attempt_identity_chirho,
            &fixture_chirho.challenge_bytes_chirho,
            fixture_chirho.inspection_chirho,
            preparation_chirho.process_generation_chirho(),
        )
        .unwrap();
    let (expected_preparing_chirho, preparing_durable_chirho) =
        preparing_outcome_chirho.clone().into_parts_chirho();
    assert!(!preparing_durable_chirho);
    let mut runtime_chirho = ResidentGd7WinnerHandoffRuntimeChirho::default();
    assert!(matches!(
        apply_preparing_commit_outcome_chirho(
            &mut runtime_chirho,
            preparation_chirho,
            preparing_outcome_chirho,
        ),
        Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho)
    ));
    assert_handoff_active_chirho(&local_authority_chirho);
    let installed_preparing_chirho = store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("the installed signed Preparing head is visible");
    assert_eq!(
        installed_preparing_chirho.checkpoint_ref_chirho,
        expected_preparing_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        installed_preparing_chirho.attempt_digest_chirho,
        expected_preparing_chirho.attempt_digest_chirho
    );
    assert_eq!(
        installed_preparing_chirho.checkpoint_chirho,
        expected_preparing_chirho.checkpoint_chirho
    );
    assert_eq!(
        installed_preparing_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::PreparingChirho
    );

    storage_chirho.set_atomic_install_fault_chirho(false);
    reconcile_unconfirmed_chirho(&mut runtime_chirho, &store_chirho, &local_authority_chirho)
        .expect("the exact installed Preparing head becomes durable");
    assert_handoff_active_chirho(&local_authority_chirho);
    reconcile_unconfirmed_chirho(&mut runtime_chirho, &store_chirho, &local_authority_chirho)
        .expect("repeating completed reconciliation is idempotent");
    assert_handoff_active_chirho(&local_authority_chirho);
    let confirmed_preparing_chirho = store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("Preparing remains the exact active head");
    assert_eq!(
        confirmed_preparing_chirho.checkpoint_ref_chirho,
        expected_preparing_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        confirmed_preparing_chirho.checkpoint_chirho,
        expected_preparing_chirho.checkpoint_chirho
    );
}

#[test]
fn ambiguous_aborted_releases_only_after_exact_durable_reconciliation_chirho() {
    let mut fixture_chirho = handoff_fixture_chirho();
    let local_authority_chirho = fixture_chirho
        .elector_chirho
        .local_append_authority_handle_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho();
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        fixture_chirho.group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let attempt_digest_chirho =
        gd7_winner_handoff_attempt_digest_chirho(&fixture_chirho.attempt_identity_chirho).unwrap();
    let preparation_chirho = local_authority_chirho
        .try_prepare_handoff_chirho(&attempt_digest_chirho)
        .unwrap();
    bind_inspection_generation_chirho(
        &mut fixture_chirho.inspection_chirho,
        &signer_chirho,
        preparation_chirho.process_generation_chirho(),
    );
    let preparing_outcome_chirho = store_chirho
        .commit_preparing_chirho(
            fixture_chirho.attempt_identity_chirho,
            &fixture_chirho.challenge_bytes_chirho,
            fixture_chirho.inspection_chirho,
            preparation_chirho.process_generation_chirho(),
        )
        .unwrap();
    let mut runtime_chirho = ResidentGd7WinnerHandoffRuntimeChirho::default();
    let (active_preparing_chirho, preparing_guard_chirho) = apply_preparing_commit_outcome_chirho(
        &mut runtime_chirho,
        preparation_chirho,
        preparing_outcome_chirho,
    )
    .expect("fault-free Preparing activates durably");
    drop(preparing_guard_chirho);
    assert_handoff_active_chirho(&local_authority_chirho);

    let abort_guard_chirho = local_authority_chirho
        .try_acquire_handoff_chirho(&attempt_digest_chirho)
        .unwrap();
    storage_chirho.set_atomic_install_fault_chirho(true);
    let aborted_outcome_chirho = store_chirho
        .commit_aborted_chirho(
            &attempt_digest_chirho,
            &active_preparing_chirho.checkpoint_ref_chirho,
        )
        .unwrap();
    let (expected_aborted_chirho, aborted_durable_chirho) =
        aborted_outcome_chirho.clone().into_parts_chirho();
    assert!(!aborted_durable_chirho);
    assert!(matches!(
        apply_aborted_commit_outcome_chirho(
            &mut runtime_chirho,
            abort_guard_chirho,
            aborted_outcome_chirho,
        ),
        Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho)
    ));
    assert_handoff_active_chirho(&local_authority_chirho);
    let installed_aborted_chirho = store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("the installed signed Aborted head is visible");
    assert_eq!(
        installed_aborted_chirho.checkpoint_ref_chirho,
        expected_aborted_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        installed_aborted_chirho.attempt_digest_chirho,
        expected_aborted_chirho.attempt_digest_chirho
    );
    assert_eq!(
        installed_aborted_chirho.checkpoint_chirho,
        expected_aborted_chirho.checkpoint_chirho
    );
    assert_eq!(
        installed_aborted_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AbortedChirho
    );

    assert!(matches!(
        reconcile_unconfirmed_chirho(&mut runtime_chirho, &store_chirho, &local_authority_chirho,),
        Err(ResidentGd7WinnerHandoffRefusalChirho::DurabilityUnconfirmedChirho)
    ));
    assert_handoff_active_chirho(&local_authority_chirho);

    storage_chirho.set_atomic_install_fault_chirho(false);
    reconcile_unconfirmed_chirho(&mut runtime_chirho, &store_chirho, &local_authority_chirho)
        .expect("the exact installed Aborted head becomes durable before release");
    drop(
        local_authority_chirho
            .try_acquire_chirho()
            .expect("ordinary append authority returns only after durable abort reconciliation"),
    );
    reconcile_unconfirmed_chirho(&mut runtime_chirho, &store_chirho, &local_authority_chirho)
        .expect("repeating completed abort reconciliation is idempotent");
    drop(
        local_authority_chirho
            .try_acquire_chirho()
            .expect("idempotent retry cannot re-freeze ordinary append authority"),
    );
    let confirmed_aborted_chirho = store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("Aborted remains the exact durable head after release");
    assert_eq!(
        confirmed_aborted_chirho.checkpoint_ref_chirho,
        expected_aborted_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        confirmed_aborted_chirho.checkpoint_chirho,
        expected_aborted_chirho.checkpoint_chirho
    );
}

#[test]
fn handoff_authority_loads_signed_plan_content_and_refuses_each_wrong_binding_chirho() {
    let fixture_chirho = handoff_fixture_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let winner_signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let held_signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "b".repeat(64),
    };
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &winner_signer_chirho,
        fixture_chirho.group_digest_chirho.clone(),
        "a".repeat(64),
    )
    .unwrap();
    let (checkpoint_ref_chirho, checkpoint_chirho) =
        signed_plan_checkpoint_chirho(&fixture_chirho, &held_signer_chirho);
    let mut expected_transfer_chirho = fixture_chirho
        .attempt_identity_chirho
        .held_transfer_identity_chirho
        .clone();
    expected_transfer_chirho.reconciliation_checkpoint_ref_chirho = checkpoint_ref_chirho.clone();
    let expected_genesis_chirho = fixture_chirho
        .inspection_chirho
        .bundle_root_chirho
        .winner_journal_genesis_digest_chirho
        .clone();

    store_chirho
        .verify_and_retain_plan_sealed_checkpoint_chirho(
            &checkpoint_ref_chirho,
            &checkpoint_chirho,
            &expected_transfer_chirho,
            &expected_genesis_chirho,
            &held_signer_chirho,
        )
        .expect("exact signed PlanSealed content authorizes the handoff prerequisite");
    let checkpoint_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&checkpoint_ref_chirho).unwrap();
    assert_eq!(
        storage_chirho
            .read_all_chirho(&checkpoint_path_chirho)
            .unwrap(),
        Some(serde_json::to_vec(&checkpoint_chirho).unwrap()),
        "the exact verified object is retained content-addressed for restart audit"
    );

    let mut wrong_phase_chirho = checkpoint_chirho.clone();
    wrong_phase_chirho.state_chirho.phase_chirho = Gd7ReconciliationPhaseChirho::ManifestingChirho;
    assert_eq!(
        store_chirho.verify_and_retain_plan_sealed_checkpoint_chirho(
            &checkpoint_ref_chirho,
            &wrong_phase_chirho,
            &expected_transfer_chirho,
            &expected_genesis_chirho,
            &held_signer_chirho,
        ),
        Err(Gd7ReconciliationStoreRefusalChirho::WrongIdentityChirho)
    );

    for mut wrong_identity_chirho in [
        {
            let mut checkpoint_chirho = checkpoint_chirho.clone();
            checkpoint_chirho
                .identity_chirho
                .consistency_group_digest_chirho =
                format!("writer-fence-group-blake3-chirho:{}", "9".repeat(64));
            checkpoint_chirho
        },
        {
            let mut checkpoint_chirho = checkpoint_chirho.clone();
            checkpoint_chirho.identity_chirho.winner_node_chirho = "8".repeat(64);
            checkpoint_chirho
        },
        {
            let mut checkpoint_chirho = checkpoint_chirho.clone();
            checkpoint_chirho.identity_chirho.held_node_chirho = "7".repeat(64);
            checkpoint_chirho
        },
        {
            let mut checkpoint_chirho = checkpoint_chirho.clone();
            checkpoint_chirho.identity_chirho.winner_term_chirho += 1;
            checkpoint_chirho
        },
        {
            let mut checkpoint_chirho = checkpoint_chirho.clone();
            checkpoint_chirho
                .identity_chirho
                .winner_journal_genesis_digest_chirho = "6".repeat(64);
            checkpoint_chirho
        },
    ] {
        wrong_identity_chirho.sig_chirho.clear();
        assert_eq!(
            store_chirho.verify_and_retain_plan_sealed_checkpoint_chirho(
                &checkpoint_ref_chirho,
                &wrong_identity_chirho,
                &expected_transfer_chirho,
                &expected_genesis_chirho,
                &held_signer_chirho,
            ),
            Err(Gd7ReconciliationStoreRefusalChirho::WrongIdentityChirho)
        );
    }

    let mut invalid_signature_chirho = checkpoint_chirho.clone();
    invalid_signature_chirho.sig_chirho = "invalid-signature-chirho".to_owned();
    let invalid_signature_ref_chirho = digest_serialized_chirho(&invalid_signature_chirho);
    let mut signature_transfer_chirho = expected_transfer_chirho.clone();
    signature_transfer_chirho.reconciliation_checkpoint_ref_chirho =
        invalid_signature_ref_chirho.clone();
    assert_eq!(
        store_chirho.verify_and_retain_plan_sealed_checkpoint_chirho(
            &invalid_signature_ref_chirho,
            &invalid_signature_chirho,
            &signature_transfer_chirho,
            &expected_genesis_chirho,
            &held_signer_chirho,
        ),
        Err(Gd7ReconciliationStoreRefusalChirho::InvalidCheckpointSignatureChirho)
    );

    let mut missing_object_transfer_chirho = expected_transfer_chirho;
    missing_object_transfer_chirho.reconciliation_checkpoint_ref_chirho = "f".repeat(64);
    assert_eq!(
        store_chirho.verify_and_retain_plan_sealed_checkpoint_chirho(
            &"f".repeat(64),
            &checkpoint_chirho,
            &missing_object_transfer_chirho,
            &expected_genesis_chirho,
            &held_signer_chirho,
        ),
        Err(Gd7ReconciliationStoreRefusalChirho::CheckpointReferenceMismatchChirho),
        "knowing a digest without presenting matching signed content cannot authorize a freeze"
    );
}

#[test]
fn winner_handoff_store_reuses_same_preparing_digest_directly_chirho() {
    let fixture_chirho = handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        fixture_chirho.group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();

    let first_outcome_chirho = store_chirho
        .commit_preparing_chirho(
            fixture_chirho.attempt_identity_chirho.clone(),
            &fixture_chirho.challenge_bytes_chirho,
            fixture_chirho.inspection_chirho.clone(),
            19,
        )
        .expect("the first direct store commit creates Preparing");
    let (first_checkpoint_chirho, first_durable_chirho) = first_outcome_chirho.into_parts_chirho();
    assert!(first_durable_chirho);
    assert_eq!(
        first_checkpoint_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::PreparingChirho
    );

    // This second call intentionally reaches the store directly, bypassing the actor's accepted
    // replay short-circuit. The same digest must return the exact durable checkpoint rather than
    // minting a second Preparing head or rewriting its transition sequence.
    let second_outcome_chirho = store_chirho
        .commit_preparing_chirho(
            fixture_chirho.attempt_identity_chirho,
            &fixture_chirho.challenge_bytes_chirho,
            fixture_chirho.inspection_chirho,
            19,
        )
        .expect("the same direct-store digest reuses Preparing");
    let (second_checkpoint_chirho, second_durable_chirho) =
        second_outcome_chirho.into_parts_chirho();
    assert!(second_durable_chirho);
    assert_eq!(second_checkpoint_chirho, first_checkpoint_chirho);
    assert_eq!(
        second_checkpoint_chirho.attempt_digest_chirho,
        first_checkpoint_chirho.attempt_digest_chirho,
        "same identity must reuse the same attempt digest"
    );
}
