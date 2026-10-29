// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::reconciliation_chirho::Gd7LedgerRecordVerifierPortChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_sim_chirho::fault_chirho::{FaultKindChirho, FaultPlanChirho};
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::cell::Cell;
use std::collections::BTreeMap;

pub(super) struct InstalledAtomicWriteSyncFaultStorageChirho {
    inner_chirho: SimStorageChirho,
    fail_after_atomic_install_chirho: Cell<bool>,
    list_calls_chirho: Cell<u64>,
}

impl InstalledAtomicWriteSyncFaultStorageChirho {
    pub(super) fn new_chirho(fail_after_atomic_install_chirho: bool) -> Self {
        Self {
            inner_chirho: SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho()),
            fail_after_atomic_install_chirho: Cell::new(fail_after_atomic_install_chirho),
            list_calls_chirho: Cell::new(0),
        }
    }

    pub(super) fn restore_chirho(
        snapshot_chirho: BTreeMap<String, Vec<u8>>,
        fail_after_atomic_install_chirho: bool,
    ) -> Self {
        Self {
            inner_chirho: SimStorageChirho::restore_chirho(
                snapshot_chirho,
                FaultPlanChirho::none_chirho(),
            ),
            fail_after_atomic_install_chirho: Cell::new(fail_after_atomic_install_chirho),
            list_calls_chirho: Cell::new(0),
        }
    }

    pub(super) fn snapshot_chirho(&self) -> BTreeMap<String, Vec<u8>> {
        self.inner_chirho.snapshot_chirho()
    }

    fn set_atomic_install_fault_chirho(&self, enabled_chirho: bool) {
        self.fail_after_atomic_install_chirho.set(enabled_chirho);
    }

    fn durability_call_count_chirho(&self) -> u64 {
        self.inner_chirho
            .operation_counts_chirho()
            .durability_call_count_chirho()
    }

    fn read_call_count_chirho(&self) -> u64 {
        self.inner_chirho
            .read_operation_counts_chirho()
            .total_read_calls_chirho()
    }

    fn list_call_count_chirho(&self) -> u64 {
        self.list_calls_chirho.get()
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
        self.list_calls_chirho.set(self.list_calls_chirho.get() + 1);
        self.inner_chirho.list_chirho(prefix_chirho)
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<bool> {
        self.inner_chirho.exists_chirho(path_chirho)
    }
}

pub(super) struct TestWinnerHandoffSignerChirho {
    key_id_chirho: String,
}

impl TestWinnerHandoffSignerChirho {
    pub(super) fn new_chirho(key_id_chirho: String) -> Self {
        Self { key_id_chirho }
    }

    fn signature_chirho(&self, line_chirho: &str) -> String {
        let mut bytes_chirho = self.key_id_chirho.as_bytes().to_vec();
        bytes_chirho.extend_from_slice(line_chirho.as_bytes());
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

impl LedgerSignerPortChirho for TestWinnerHandoffSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> anyhow::Result<String> {
        Ok(self.signature_chirho(signed_content_line_chirho))
    }

    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

impl Gd7LedgerRecordVerifierPortChirho for TestWinnerHandoffSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(signed_content_line_chirho) == sig_chirho
    }
}

pub(super) fn durable_commit_chirho(
    outcome_chirho: Gd7WinnerHandoffCommitOutcomeChirho,
) -> CommittedGd7WinnerHandoffChirho {
    match outcome_chirho {
        Gd7WinnerHandoffCommitOutcomeChirho::DurableChirho(committed_chirho) => committed_chirho,
        Gd7WinnerHandoffCommitOutcomeChirho::DurabilityUnconfirmedChirho(_committed_chirho) => {
            panic!("fault-free storage must confirm the fixed head durable")
        }
    }
}

fn unconfirmed_commit_chirho(
    outcome_chirho: Gd7WinnerHandoffCommitOutcomeChirho,
) -> CommittedGd7WinnerHandoffChirho {
    match outcome_chirho {
        Gd7WinnerHandoffCommitOutcomeChirho::DurabilityUnconfirmedChirho(committed_chirho) => {
            committed_chirho
        }
        Gd7WinnerHandoffCommitOutcomeChirho::DurableChirho(_committed_chirho) => {
            panic!("installed-then-error storage must report durability unconfirmed")
        }
    }
}

fn assert_active_matches_commit_chirho(
    active_chirho: &ActiveGd7WinnerHandoffChirho,
    committed_chirho: &CommittedGd7WinnerHandoffChirho,
) {
    assert_eq!(
        active_chirho.attempt_digest_chirho,
        committed_chirho.attempt_digest_chirho
    );
    assert_eq!(
        active_chirho.checkpoint_ref_chirho,
        committed_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        active_chirho.checkpoint_chirho,
        committed_chirho.checkpoint_chirho
    );
}

fn handoff_fixture_chirho() -> (
    String,
    Gd7WinnerHandoffAttemptIdentityChirho,
    Vec<u8>,
    Gd7WinnerCurrentViewInspectionChirho,
) {
    handoff_fixture_for_cut_chirho(
        "c".repeat(64),
        "1".repeat(64),
        Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(7, 1).unwrap(),
            seq_chirho: 11,
            record_digest_chirho: "e".repeat(64),
        },
    )
}

pub(super) fn handoff_fixture_for_cut_chirho(
    reconciliation_checkpoint_ref_chirho: String,
    winner_journal_genesis_digest_chirho: String,
    source_cut_chirho: Gd7JournalTailCoordinateChirho,
) -> (
    String,
    Gd7WinnerHandoffAttemptIdentityChirho,
    Vec<u8>,
    Gd7WinnerCurrentViewInspectionChirho,
) {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-winner-handoff-chirho".to_owned(),
    };
    let group_digest_chirho = consistency_group_digest_chirho(&group_chirho).unwrap();
    let winner_node_chirho = "a".repeat(64);
    let held_node_chirho = "b".repeat(64);
    let transfer_identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        reconciliation_checkpoint_ref_chirho,
        winner_node_chirho: winner_node_chirho.clone(),
        held_node_chirho: held_node_chirho.clone(),
        winner_term_chirho: 7,
    };
    let transfer_identity_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&transfer_identity_chirho).expect("encode transfer identity"),
    );
    let challenge_chirho = Gd7WinnerCurrentViewChallengeChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO.to_owned(),
        nonce_chirho: "d".repeat(64),
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        expected_winner_node_chirho: winner_node_chirho.clone(),
        held_node_chirho,
        transfer_identity_digest_chirho,
        raft_term_chirho: 7,
    };
    let challenge_bytes_chirho = challenge_chirho.canonical_bytes_chirho().unwrap();
    let challenge_digest_chirho = challenge_chirho.digest_chirho().unwrap();
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: winner_journal_genesis_digest_chirho.clone(),
        source_cut_chirho: source_cut_chirho.clone(),
        lowest_page_ref_chirho: None,
        page_count_chirho: 0,
        row_count_chirho: 0,
    };
    let root_bytes_chirho = canonical_json_chirho(&root_chirho).unwrap();
    let root_digest_chirho = digest_bytes_chirho(&root_bytes_chirho);
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: winner_node_chirho.clone(),
    };
    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho: challenge_digest_chirho.clone(),
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        winner_node_chirho: winner_node_chirho.clone(),
        raft_term_chirho: 7,
        winner_process_generation_chirho: 19,
        winner_journal_genesis_digest_chirho,
        latest_verified_journal_cut_chirho: source_cut_chirho,
        view_bundle_root_chirho: root_digest_chirho.clone(),
        key_id_chirho: winner_node_chirho.clone(),
        sig_chirho: String::new(),
    };
    let unsigned_bytes_chirho = canonical_json_chirho(&evidence_chirho).unwrap();
    evidence_chirho.sig_chirho = Gd7ReconciliationSignerPortChirho::sign_chirho(
        &signer_chirho,
        std::str::from_utf8(&unsigned_bytes_chirho).unwrap(),
    )
    .unwrap();
    let evidence_digest_chirho =
        digest_bytes_chirho(&canonical_json_chirho(&evidence_chirho).unwrap());
    (
        group_digest_chirho,
        Gd7WinnerHandoffAttemptIdentityChirho {
            held_transfer_identity_chirho: transfer_identity_chirho,
            held_transfer_checkpoint_ref_chirho: "4".repeat(64),
            expected_bundle_root_object_digest_chirho: root_digest_chirho.clone(),
            challenge_digest_chirho,
        },
        challenge_bytes_chirho,
        Gd7WinnerCurrentViewInspectionChirho {
            evidence_object_digest_chirho: evidence_digest_chirho,
            evidence_chirho,
            bundle_root_object_digest_chirho: root_digest_chirho,
            bundle_root_chirho: root_chirho,
        },
    )
}

fn preparing_admission_io_delta_chirho(unrelated_object_count_chirho: usize) -> (u64, u64, u64) {
    let (group_digest_chirho, identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho(false);
    for index_chirho in 0..unrelated_object_count_chirho {
        storage_chirho
            .create_durable_chirho(
                &StoragePathChirho::new_chirho(format!(
                    "unrelated-history-chirho/{index_chirho:04}-chirho"
                )),
                b"unrelated-chirho",
            )
            .expect("seed an unrelated durable object");
    }
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let before_writes_chirho = storage_chirho.durability_call_count_chirho();
    let before_reads_chirho = storage_chirho.read_call_count_chirho();
    let before_lists_chirho = storage_chirho.list_call_count_chirho();
    durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .expect("admit one exact Preparing transition"),
    );
    (
        storage_chirho.durability_call_count_chirho() - before_writes_chirho,
        storage_chirho.read_call_count_chirho() - before_reads_chirho,
        storage_chirho.list_call_count_chirho() - before_lists_chirho,
    )
}

#[test]
fn preparing_admission_io_count_is_independent_of_unrelated_history_chirho() {
    let empty_history_chirho = preparing_admission_io_delta_chirho(0);
    let larger_history_chirho = preparing_admission_io_delta_chirho(512);
    assert_eq!(
        larger_history_chirho, empty_history_chirho,
        "one handoff admission must use the same point-I/O count as unrelated history grows"
    );
    assert_eq!(
        empty_history_chirho.2, 0,
        "handoff admission must not list growing storage"
    );
}

#[test]
fn preparing_installed_with_unconfirmed_sync_reconciles_exactly_across_restart_chirho() {
    let (group_digest_chirho, identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho(true);
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho.clone(),
        "a".repeat(64),
    )
    .unwrap();

    let preparing_chirho = unconfirmed_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .expect("the installed Preparing head remains an inspectable outcome"),
    );
    assert_eq!(
        preparing_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::PreparingChirho
    );
    let installed_active_chirho = store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("the intended signed Preparing head was installed before sync failed");
    assert_active_matches_commit_chirho(&installed_active_chirho, &preparing_chirho);
    assert_eq!(
        unconfirmed_commit_chirho(
            store_chirho
                .confirm_active_chirho(&installed_active_chirho)
                .expect("reconciliation remains retryable while sync is unconfirmed"),
        ),
        preparing_chirho,
        "reconciliation must reuse the same signed checkpoint and fixed-head ref"
    );

    let restarted_storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::restore_chirho(
        storage_chirho.snapshot_chirho(),
        true,
    );
    let restarted_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &restarted_storage_chirho,
        &signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let restarted_active_chirho = restarted_store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("a fresh store over the survived bytes restores Preparing");
    assert_active_matches_commit_chirho(&restarted_active_chirho, &preparing_chirho);
    assert_eq!(
        unconfirmed_commit_chirho(
            restarted_store_chirho
                .confirm_active_chirho(&restarted_active_chirho)
                .expect("restart reconciliation stays on the same logical transition"),
        ),
        preparing_chirho
    );

    restarted_storage_chirho.set_atomic_install_fault_chirho(false);
    assert_eq!(
        durable_commit_chirho(
            restarted_store_chirho
                .confirm_active_chirho(&restarted_active_chirho)
                .expect("clearing the sync fault confirms the existing Preparing head"),
        ),
        preparing_chirho
    );
}

#[test]
fn aborted_installed_with_unconfirmed_sync_reconciles_exactly_across_restart_chirho() {
    let (group_digest_chirho, identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho(false);
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho.clone(),
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .expect("Preparing is durable before the ambiguous abort"),
    );

    storage_chirho.set_atomic_install_fault_chirho(true);
    let aborted_chirho = unconfirmed_commit_chirho(
        store_chirho
            .commit_aborted_chirho(
                &preparing_chirho.attempt_digest_chirho,
                &preparing_chirho.checkpoint_ref_chirho,
            )
            .expect("the installed Aborted head remains an inspectable outcome"),
    );
    assert_eq!(
        aborted_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AbortedChirho
    );
    let installed_active_chirho = store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("the intended signed Aborted head was installed before sync failed");
    assert_active_matches_commit_chirho(&installed_active_chirho, &aborted_chirho);
    assert_eq!(
        unconfirmed_commit_chirho(
            store_chirho
                .commit_aborted_chirho(
                    &preparing_chirho.attempt_digest_chirho,
                    &preparing_chirho.checkpoint_ref_chirho,
                )
                .expect("a lost abort response reconciles the installed Aborted head"),
        ),
        aborted_chirho,
        "abort reconciliation must not create a new transition"
    );

    let restarted_storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::restore_chirho(
        storage_chirho.snapshot_chirho(),
        true,
    );
    let restarted_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &restarted_storage_chirho,
        &signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let restarted_active_chirho = restarted_store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("a fresh store over the survived bytes restores Aborted");
    assert_active_matches_commit_chirho(&restarted_active_chirho, &aborted_chirho);
    assert_eq!(
        unconfirmed_commit_chirho(
            restarted_store_chirho
                .confirm_active_chirho(&restarted_active_chirho)
                .expect("restart reconciliation preserves the installed Aborted decision"),
        ),
        aborted_chirho
    );

    restarted_storage_chirho.set_atomic_install_fault_chirho(false);
    assert_eq!(
        durable_commit_chirho(
            restarted_store_chirho
                .confirm_active_chirho(&restarted_active_chirho)
                .expect("clearing the sync fault confirms the existing Aborted head"),
        ),
        aborted_chirho
    );
}

#[test]
fn winner_handoff_fixed_head_recovers_exact_preparing_and_accepts_once_chirho() {
    let (group_digest_chirho, identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho.clone(),
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                identity_chirho.clone(),
                &challenge_bytes_chirho,
                inspection_chirho.clone(),
                19,
            )
            .expect("commit exact preparing checkpoint"),
    );
    assert_eq!(
        preparing_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::PreparingChirho
    );
    assert_eq!(
        durable_commit_chirho(
            store_chirho
                .commit_preparing_chirho(
                    identity_chirho,
                    &challenge_bytes_chirho,
                    inspection_chirho,
                    19,
                )
                .expect("lost-response retry returns the same checkpoint"),
        ),
        preparing_chirho
    );

    let restored_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let restored_chirho = restored_store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("restart point-loads the exact preparing checkpoint");
    assert_eq!(
        restored_chirho.checkpoint_ref_chirho,
        preparing_chirho.checkpoint_ref_chirho
    );
    let accepted_chirho = durable_commit_chirho(
        restored_store_chirho
            .commit_accepted_chirho(
                &restored_chirho.attempt_digest_chirho,
                &restored_chirho.checkpoint_ref_chirho,
                23,
            )
            .expect("exact attempt advances to accepted"),
    );
    assert_eq!(
        accepted_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho
    );
    assert_eq!(
        accepted_chirho
            .checkpoint_chirho
            .accepting_process_generation_chirho,
        Some(23)
    );
    assert_eq!(
        durable_commit_chirho(
            restored_store_chirho
                .commit_accepted_chirho(
                    &accepted_chirho.attempt_digest_chirho,
                    &accepted_chirho.checkpoint_ref_chirho,
                    23,
                )
                .expect("accepted lost-response retry is idempotent"),
        ),
        accepted_chirho
    );
    assert_eq!(
        restored_store_chirho
            .commit_aborted_chirho(
                &accepted_chirho.attempt_digest_chirho,
                &accepted_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho,
        "the held-side abort transition cannot release an accepted barrier; a future elected-winner revocation is separate authority"
    );
}

#[test]
fn post_restart_retry_refuses_each_mismatched_attempt_field_chirho() {
    let (group_digest_chirho, identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let initial_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho.clone(),
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        initial_store_chirho
            .commit_preparing_chirho(
                identity_chirho.clone(),
                &challenge_bytes_chirho,
                inspection_chirho.clone(),
                19,
            )
            .expect("commit the one durable active attempt"),
    );

    let restarted_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let mut mismatched_identities_chirho = Vec::new();

    let mut wrong_group_chirho = identity_chirho.clone();
    wrong_group_chirho
        .held_transfer_identity_chirho
        .consistency_group_digest_chirho =
        consistency_group_digest_chirho(&ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/tmp/gd7-other-group-chirho".to_owned(),
        })
        .unwrap();
    mismatched_identities_chirho.push(("consistency group", wrong_group_chirho));

    let mut wrong_reconciliation_checkpoint_chirho = identity_chirho.clone();
    wrong_reconciliation_checkpoint_chirho
        .held_transfer_identity_chirho
        .reconciliation_checkpoint_ref_chirho = "f".repeat(64);
    mismatched_identities_chirho.push((
        "reconciliation checkpoint",
        wrong_reconciliation_checkpoint_chirho,
    ));

    let mut wrong_winner_chirho = identity_chirho.clone();
    wrong_winner_chirho
        .held_transfer_identity_chirho
        .winner_node_chirho = "9".repeat(64);
    mismatched_identities_chirho.push(("winner node", wrong_winner_chirho));

    let mut wrong_held_chirho = identity_chirho.clone();
    wrong_held_chirho
        .held_transfer_identity_chirho
        .held_node_chirho = "8".repeat(64);
    mismatched_identities_chirho.push(("held node", wrong_held_chirho));

    let mut wrong_term_chirho = identity_chirho.clone();
    wrong_term_chirho
        .held_transfer_identity_chirho
        .winner_term_chirho += 1;
    mismatched_identities_chirho.push(("winner term", wrong_term_chirho));

    let mut wrong_held_checkpoint_chirho = identity_chirho.clone();
    wrong_held_checkpoint_chirho.held_transfer_checkpoint_ref_chirho = "7".repeat(64);
    mismatched_identities_chirho.push(("held transfer checkpoint", wrong_held_checkpoint_chirho));

    let mut wrong_bundle_root_chirho = identity_chirho.clone();
    wrong_bundle_root_chirho.expected_bundle_root_object_digest_chirho = "6".repeat(64);
    mismatched_identities_chirho.push(("expected bundle root", wrong_bundle_root_chirho));

    let mut wrong_challenge_chirho = identity_chirho;
    wrong_challenge_chirho.challenge_digest_chirho = "5".repeat(64);
    mismatched_identities_chirho.push(("challenge", wrong_challenge_chirho));

    for (field_chirho, mismatched_identity_chirho) in mismatched_identities_chirho {
        assert_eq!(
            restarted_store_chirho
                .commit_preparing_chirho(
                    mismatched_identity_chirho,
                    &challenge_bytes_chirho,
                    inspection_chirho.clone(),
                    23,
                )
                .unwrap_err(),
            Gd7WinnerHandoffStoreRefusalChirho::ActiveAttemptMismatchChirho,
            "a post-restart retry differing only in {field_chirho} must not replace the active attempt"
        );
    }

    let restored_chirho = restarted_store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("the exact original Preparing attempt remains active");
    assert_active_matches_commit_chirho(&restored_chirho, &preparing_chirho);
}

#[test]
fn interrupted_head_write_keeps_prior_decision_and_retry_reuses_checkpoint_chirho() {
    let (group_digest_chirho, identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let initial_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let initial_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &initial_storage_chirho,
        &signer_chirho,
        group_digest_chirho.clone(),
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        initial_store_chirho
            .commit_preparing_chirho(
                identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .unwrap(),
    );
    let snapshot_chirho = initial_storage_chirho.snapshot_chirho();

    let crashing_storage_chirho = SimStorageChirho::restore_chirho(
        snapshot_chirho,
        FaultPlanChirho::single_chirho(1, FaultKindChirho::CrashBeforeChirho),
    );
    let crashing_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &crashing_storage_chirho,
        &signer_chirho,
        group_digest_chirho.clone(),
        "a".repeat(64),
    )
    .unwrap();
    let unconfirmed_accepted_chirho = unconfirmed_commit_chirho(
        crashing_store_chirho
            .commit_accepted_chirho(
                &preparing_chirho.attempt_digest_chirho,
                &preparing_chirho.checkpoint_ref_chirho,
                23,
            )
            .expect("an interrupted fixed-head write reports an ambiguous durability outcome"),
    );
    assert_eq!(
        unconfirmed_accepted_chirho
            .checkpoint_chirho
            .phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AcceptedChirho,
        "the immutable Accepted checkpoint exists even though its fixed-head install is unconfirmed"
    );
    let recovered_storage_chirho = SimStorageChirho::restore_chirho(
        crashing_storage_chirho.snapshot_chirho(),
        FaultPlanChirho::none_chirho(),
    );
    let recovered_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &recovered_storage_chirho,
        &signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let recovered_chirho = recovered_store_chirho
        .load_current_chirho()
        .unwrap()
        .expect("old fixed head remains authoritative");
    assert_eq!(
        recovered_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::PreparingChirho
    );
    recovered_store_chirho
        .commit_accepted_chirho(
            &recovered_chirho.attempt_digest_chirho,
            &recovered_chirho.checkpoint_ref_chirho,
            23,
        )
        .expect("retry reuses immutable accepted checkpoint and advances the fixed head");
}

#[test]
fn abort_is_preparing_only_and_allows_one_fresh_challenge_chirho() {
    let (group_digest_chirho, identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_chirho();
    let signer_chirho = TestWinnerHandoffSignerChirho {
        key_id_chirho: "a".repeat(64),
    };
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                identity_chirho.clone(),
                &challenge_bytes_chirho,
                inspection_chirho.clone(),
                19,
            )
            .unwrap(),
    );
    let aborted_chirho = durable_commit_chirho(
        store_chirho
            .commit_aborted_chirho(
                &preparing_chirho.attempt_digest_chirho,
                &preparing_chirho.checkpoint_ref_chirho,
            )
            .expect("preparing may be durably aborted"),
    );
    assert_eq!(
        aborted_chirho.checkpoint_chirho.phase_chirho,
        Gd7WinnerHandoffPhaseChirho::AbortedChirho
    );
    assert_eq!(
        store_chirho
            .commit_preparing_chirho(
                identity_chirho.clone(),
                &challenge_bytes_chirho,
                inspection_chirho.clone(),
                19,
            )
            .unwrap_err(),
        Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho,
        "an aborted challenge cannot be replayed as a new attempt"
    );

    let mut fresh_identity_chirho = identity_chirho;
    fresh_identity_chirho.challenge_digest_chirho = "2".repeat(64);
    let mut fresh_challenge_chirho =
        parse_canonical_gd7_winner_current_view_challenge_chirho(&challenge_bytes_chirho).unwrap();
    fresh_challenge_chirho.nonce_chirho = "3".repeat(64);
    let fresh_challenge_bytes_chirho = fresh_challenge_chirho.canonical_bytes_chirho().unwrap();
    fresh_identity_chirho.challenge_digest_chirho = fresh_challenge_chirho.digest_chirho().unwrap();
    let mut fresh_inspection_chirho = inspection_chirho;
    fresh_inspection_chirho
        .evidence_chirho
        .challenge_digest_chirho = fresh_identity_chirho.challenge_digest_chirho.clone();
    fresh_inspection_chirho.evidence_chirho.sig_chirho.clear();
    let unsigned_bytes_chirho =
        canonical_json_chirho(&fresh_inspection_chirho.evidence_chirho).unwrap();
    fresh_inspection_chirho.evidence_chirho.sig_chirho =
        Gd7ReconciliationSignerPortChirho::sign_chirho(
            &signer_chirho,
            std::str::from_utf8(&unsigned_bytes_chirho).unwrap(),
        )
        .unwrap();
    fresh_inspection_chirho.evidence_object_digest_chirho = digest_bytes_chirho(
        &canonical_json_chirho(&fresh_inspection_chirho.evidence_chirho).unwrap(),
    );
    let fresh_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                fresh_identity_chirho,
                &fresh_challenge_bytes_chirho,
                fresh_inspection_chirho,
                19,
            )
            .expect("a new challenge starts only after the old preparing attempt is aborted"),
    );
    assert_ne!(
        fresh_chirho.attempt_digest_chirho,
        aborted_chirho.attempt_digest_chirho
    );
    assert_eq!(
        fresh_chirho
            .checkpoint_chirho
            .previous_checkpoint_ref_chirho
            .as_deref(),
        Some(aborted_chirho.checkpoint_ref_chirho.as_str())
    );
}
