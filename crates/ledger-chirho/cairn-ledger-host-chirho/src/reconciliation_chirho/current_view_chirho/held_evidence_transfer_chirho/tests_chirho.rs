// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::fork_baseline_tests_chirho::{
    with_fork_baseline_fixture_chirho, ForkBaselineTailBindingChirho, ForkBaselineTestContextChirho,
};
use super::super::*;
use super::*;
use crate::reconciliation_chirho::{
    gd7_reconciliation_identity_digest_chirho, Gd7LedgerRecordVerifierPortChirho,
    Gd7ReconciliationSignerPortChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_sim_chirho::fault_chirho::{FaultKindChirho, FaultPlanChirho};
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;
use serde::Serialize;

struct RejectingWinnerLedgerVerifierChirho;

impl Gd7LedgerRecordVerifierPortChirho for RejectingWinnerLedgerVerifierChirho {
    fn key_id_chirho(&self) -> String {
        "journal-chirho:shared-winner-journal-secret-chirho".to_owned()
    }

    fn verify_chirho(&self, _signed_content_line_chirho: &str, _sig_chirho: &str) -> bool {
        false
    }
}

pub(super) fn stage_evidence_manifest_chirho(
    context_chirho: &ForkBaselineTestContextChirho<'_>,
) -> Gd7WinnerEvidenceManifestChirho {
    stage_evidence_manifest_for_view_chirho(context_chirho, "d".repeat(64))
}

pub(super) fn stage_evidence_manifest_for_view_chirho(
    context_chirho: &ForkBaselineTestContextChirho<'_>,
    held_view_transfer_checkpoint_ref_chirho: String,
) -> Gd7WinnerEvidenceManifestChirho {
    let mut restart_chirho = None;
    let winner_history_root_chirho = loop {
        match context_chirho
            .store_chirho
            .stage_next_accepted_winner_history_page_chirho(
                context_chirho.plan_checkpoint_ref_chirho,
                context_chirho.plan_checkpoint_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_journal_chirho,
                restart_chirho.as_ref(),
            )
            .expect("stage one accepted winner-history page")
        {
            Gd7WinnerHistoryStageOutcomeChirho::ContinueChirho {
                restart_chirho: next_chirho,
            } => restart_chirho = Some(next_chirho),
            Gd7WinnerHistoryStageOutcomeChirho::CompleteChirho { root_chirho } => {
                break root_chirho;
            }
        }
    };
    let fork_baseline_root_chirho = context_chirho
        .store_chirho
        .stage_accepted_fork_baseline_chirho(
            context_chirho.plan_checkpoint_ref_chirho,
            context_chirho.plan_checkpoint_chirho,
            context_chirho.held_signer_chirho,
            context_chirho.journal_ports_chirho,
            context_chirho.journal_path_chirho,
            context_chirho.cluster_chirho,
        )
        .expect("stage accepted fork baseline");
    build_gd7_winner_evidence_manifest_chirho(
        Gd7HeldEvidenceTransferIdentityChirho {
            reconciliation_identity_chirho: context_chirho
                .plan_checkpoint_chirho
                .identity_chirho
                .clone(),
            reconciliation_checkpoint_ref_chirho: context_chirho
                .plan_checkpoint_ref_chirho
                .to_owned(),
            held_view_transfer_checkpoint_ref_chirho,
            winner_handoff_attempt_digest_chirho: context_chirho
                .accepted_attempt_digest_chirho
                .to_owned(),
        },
        &winner_history_root_chirho,
        &fork_baseline_root_chirho,
        context_chirho.winner_signer_chirho,
    )
    .expect("build accepted evidence manifest")
}

pub(super) fn fetch_next_chirho(
    context_chirho: &ForkBaselineTestContextChirho<'_>,
    manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
    active_chirho: &ActiveGd7HeldEvidenceTransferChirho,
) -> Gd7WinnerEvidencePageTransferChirho {
    fetch_gd7_winner_evidence_page_chirho(
        context_chirho.storage_chirho,
        manifest_chirho,
        &manifest_chirho
            .transfer_identity_chirho
            .reconciliation_identity_chirho
            .held_node_chirho,
        active_chirho
            .checkpoint_chirho
            .next_grant_chirho()
            .expect("receiving checkpoint carries a next grant")
            .clone(),
        context_chirho.winner_signer_chirho,
    )
    .expect("winner fetches its exact granted page")
}

fn resign_test_value_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &mut ValueChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
) {
    signature_chirho(value_chirho).clear();
    let unsigned_bytes_chirho =
        canonical_json_chirho(value_chirho).expect("canonicalize changed signed test value");
    let unsigned_line_chirho =
        std::str::from_utf8(&unsigned_bytes_chirho).expect("signed test value is UTF-8");
    *signature_chirho(value_chirho) = signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .expect("re-sign internally consistent hostile fixture");
}

#[test]
fn separate_held_storage_restarts_then_completes_only_after_both_chains_verify_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let manifest_chirho = stage_evidence_manifest_chirho(&context_chirho);
            let mut invalid_manifest_chirho = manifest_chirho.clone();
            invalid_manifest_chirho.sig_chirho = "0".repeat(64);
            assert_eq!(
                verify_gd7_winner_evidence_manifest_chirho(
                    &invalid_manifest_chirho,
                    context_chirho.winner_signer_chirho,
                )
                .unwrap_err(),
                Gd7WinnerEvidenceTransferRefusalChirho::InvalidManifestChirho,
                "a manifest signature failure must not be mislabeled as a page-grant failure"
            );
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &held_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .expect("open separate held evidence store");
            let initial_chirho = held_store_chirho
                .begin_chirho(&manifest_chirho)
                .expect("initialize held evidence transfer");
            assert_eq!(
                initial_chirho.checkpoint_chirho.phase_chirho,
                Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho
            );
            assert_eq!(
                held_storage_chirho
                    .object_len_chirho(
                        &gd7_winner_history_page_path_chirho(
                            &initial_chirho
                                .checkpoint_chirho
                                .next_grant_chirho()
                                .unwrap()
                                .page_object_digest_chirho,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                None,
                "the held store starts without winner page bytes; shared storage cannot satisfy it"
            );

            let first_transfer_chirho =
                fetch_next_chirho(&context_chirho, &manifest_chirho, &initial_chirho);
            let after_first_chirho = held_store_chirho
                .receive_page_chirho(
                    &initial_chirho.checkpoint_ref_chirho,
                    &first_transfer_chirho,
                )
                .expect("retain first page in held-local storage");
            assert_eq!(
                after_first_chirho.checkpoint_chirho.phase_chirho,
                Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho,
                "one completed family must not imply both evidence families verified"
            );

            let recovered_storage_chirho = SimStorageChirho::restore_chirho(
                held_storage_chirho.snapshot_chirho(),
                FaultPlanChirho::none_chirho(),
            );
            let recovered_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &recovered_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .expect("reopen held evidence store after restart");
            let recovered_chirho = recovered_store_chirho
                .begin_chirho(&manifest_chirho)
                .expect("resume exact retained manifest");
            assert_eq!(recovered_chirho, after_first_chirho);

            let mut active_chirho = recovered_chirho;
            while active_chirho.checkpoint_chirho.phase_chirho
                == Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho
            {
                let transfer_chirho =
                    fetch_next_chirho(&context_chirho, &manifest_chirho, &active_chirho);
                active_chirho = recovered_store_chirho
                    .receive_page_chirho(&active_chirho.checkpoint_ref_chirho, &transfer_chirho)
                    .expect("verify and retain the next held-local evidence page");
            }
            assert_eq!(
                active_chirho.checkpoint_chirho.phase_chirho,
                Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
            );
            assert_eq!(
                active_chirho
                    .checkpoint_chirho
                    .received_winner_history_pages_chirho,
                manifest_chirho.winner_history_root_chirho.page_count_chirho
            );
            assert_eq!(
                active_chirho
                    .checkpoint_chirho
                    .received_fork_baseline_pages_chirho,
                manifest_chirho.fork_baseline_root_chirho.page_count_chirho
            );
        },
    );
}

#[test]
fn reordered_tampered_or_unverified_pages_cannot_advance_to_complete_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let manifest_chirho = stage_evidence_manifest_chirho(&context_chirho);
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let rejecting_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &held_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                &RejectingWinnerLedgerVerifierChirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .unwrap();
            let initial_chirho = rejecting_store_chirho
                .begin_chirho(&manifest_chirho)
                .unwrap();

            let baseline_grant_chirho = manifest_chirho
                .fork_baseline_first_grant_chirho
                .clone()
                .expect("non-empty baseline has a first grant");
            let baseline_first_chirho = fetch_gd7_winner_evidence_page_chirho(
                context_chirho.storage_chirho,
                &manifest_chirho,
                &manifest_chirho
                    .transfer_identity_chirho
                    .reconciliation_identity_chirho
                    .held_node_chirho,
                baseline_grant_chirho,
                context_chirho.winner_signer_chirho,
            )
            .unwrap();
            assert_eq!(
                rejecting_store_chirho
                    .receive_page_chirho(
                        &initial_chirho.checkpoint_ref_chirho,
                        &baseline_first_chirho,
                    )
                    .unwrap_err(),
                Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransferChirho,
                "a valid baseline page presented before the required history page must refuse by identity"
            );
            assert_eq!(
                rejecting_store_chirho.load_active_chirho().unwrap(),
                Some(initial_chirho.clone()),
                "a reordered page must not advance the held checkpoint"
            );

            let mut tampered_history_chirho =
                fetch_next_chirho(&context_chirho, &manifest_chirho, &initial_chirho);
            tampered_history_chirho.canonical_page_bytes_chirho[0] ^= 1;
            assert!(matches!(
                rejecting_store_chirho.receive_page_chirho(
                    &initial_chirho.checkpoint_ref_chirho,
                    &tampered_history_chirho,
                ),
                Err(Gd7HeldEvidenceTransferStoreRefusalChirho::TransferChirho(
                    Gd7WinnerEvidenceTransferRefusalChirho::HistoryChirho(
                        Gd7WinnerHistoryRefusalChirho::ObjectDigestMismatchChirho
                    )
                ))
            ));
            assert_eq!(
                rejecting_store_chirho.load_active_chirho().unwrap(),
                Some(initial_chirho.clone()),
                "tampered bytes must not advance the held checkpoint"
            );

            let valid_history_chirho =
                fetch_next_chirho(&context_chirho, &manifest_chirho, &initial_chirho);
            let after_history_chirho = rejecting_store_chirho
                .receive_page_chirho(&initial_chirho.checkpoint_ref_chirho, &valid_history_chirho)
                .unwrap();
            let final_baseline_chirho =
                fetch_next_chirho(&context_chirho, &manifest_chirho, &after_history_chirho);
            assert_eq!(
                rejecting_store_chirho
                    .receive_page_chirho(
                        &after_history_chirho.checkpoint_ref_chirho,
                        &final_baseline_chirho,
                    )
                    .unwrap_err(),
                Gd7HeldEvidenceTransferStoreRefusalChirho::WinnerHistoryChirho(
                    Gd7WinnerHistoryRefusalChirho::InvalidLedgerSignatureChirho,
                ),
                "held Complete must depend on the independent full ledger-signature verifier"
            );
            assert_eq!(
                rejecting_store_chirho.load_active_chirho().unwrap(),
                Some(after_history_chirho.clone()),
                "failed final reverification leaves the exact receiving checkpoint active"
            );

            let valid_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &held_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .unwrap();
            let complete_chirho = valid_store_chirho
                .receive_page_chirho(
                    &after_history_chirho.checkpoint_ref_chirho,
                    &final_baseline_chirho,
                )
                .expect("the identical final page completes under the real ledger verifier");
            assert_eq!(
                complete_chirho.checkpoint_chirho.phase_chirho,
                Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
            );
        },
    );
}

#[test]
fn interrupted_head_write_reopens_the_prior_receiving_checkpoint_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let manifest_chirho = stage_evidence_manifest_chirho(&context_chirho);
            let initial_storage_chirho =
                SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let initial_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &initial_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .unwrap();
            let initial_chirho = initial_store_chirho.begin_chirho(&manifest_chirho).unwrap();
            let first_transfer_chirho =
                fetch_next_chirho(&context_chirho, &manifest_chirho, &initial_chirho);

            let crashing_storage_chirho = SimStorageChirho::restore_chirho(
                initial_storage_chirho.snapshot_chirho(),
                FaultPlanChirho::single_chirho(1, FaultKindChirho::CrashBeforeChirho),
            );
            let crashing_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &crashing_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .unwrap();
            assert!(
                crashing_store_chirho
                    .receive_page_chirho(
                        &initial_chirho.checkpoint_ref_chirho,
                        &first_transfer_chirho,
                    )
                    .is_err(),
                "an interrupted fixed-head write must not report page receipt committed"
            );

            let recovered_storage_chirho = SimStorageChirho::restore_chirho(
                crashing_storage_chirho.snapshot_chirho(),
                FaultPlanChirho::none_chirho(),
            );
            let recovered_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &recovered_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .unwrap();
            assert_eq!(
                recovered_store_chirho.load_active_chirho().unwrap(),
                Some(initial_chirho.clone())
            );
            recovered_store_chirho
                .receive_page_chirho(
                    &initial_chirho.checkpoint_ref_chirho,
                    &first_transfer_chirho,
                )
                .expect("retry advances from the exact prior checkpoint");
        },
    );
}

#[test]
fn retained_manifest_refuses_signed_drift_in_an_unconsumed_identity_field_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let manifest_chirho = stage_evidence_manifest_chirho(&context_chirho);
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_store_chirho = Gd7HeldEvidenceTransferStoreChirho::new_chirho(
                &held_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho.winner_signer_chirho,
                context_chirho.winner_journal_signer_chirho,
                manifest_chirho.transfer_identity_chirho.clone(),
            )
            .expect("open held store against the exact accepted identity");

            let mut foreign_chirho = manifest_chirho;
            foreign_chirho
                .transfer_identity_chirho
                .reconciliation_identity_chirho
                .losing_journal_tail_chirho
                .record_digest_chirho = "d".repeat(64);
            let foreign_reconciliation_chirho = foreign_chirho
                .transfer_identity_chirho
                .reconciliation_identity_chirho
                .clone();
            let foreign_reconciliation_digest_chirho =
                gd7_reconciliation_identity_digest_chirho(&foreign_reconciliation_chirho)
                    .expect("digest the internally consistent foreign reconciliation");
            foreign_chirho
                .winner_history_root_chirho
                .identity_chirho
                .reconciliation_identity_chirho = foreign_reconciliation_chirho.clone();
            foreign_chirho
                .winner_history_root_chirho
                .identity_chirho
                .reconciliation_identity_digest_chirho =
                foreign_reconciliation_digest_chirho.clone();
            foreign_chirho
                .fork_baseline_root_chirho
                .identity_chirho
                .reconciliation_identity_chirho = foreign_reconciliation_chirho;
            foreign_chirho
                .fork_baseline_root_chirho
                .identity_chirho
                .reconciliation_identity_digest_chirho = foreign_reconciliation_digest_chirho;
            resign_test_value_chirho(
                &mut foreign_chirho.winner_history_root_chirho,
                context_chirho.winner_signer_chirho,
                |root_chirho| &mut root_chirho.sig_chirho,
            );
            foreign_chirho.winner_history_root_object_digest_chirho = digest_bytes_chirho(
                &canonical_json_chirho(&foreign_chirho.winner_history_root_chirho)
                    .expect("canonicalize foreign winner-history root"),
            );
            resign_test_value_chirho(
                &mut foreign_chirho.fork_baseline_root_chirho,
                context_chirho.winner_signer_chirho,
                |root_chirho| &mut root_chirho.sig_chirho,
            );
            foreign_chirho.fork_baseline_root_object_digest_chirho = digest_bytes_chirho(
                &canonical_json_chirho(&foreign_chirho.fork_baseline_root_chirho)
                    .expect("canonicalize foreign fork-baseline root"),
            );
            let foreign_transfer_digest_chirho = gd7_held_evidence_transfer_identity_digest_chirho(
                &foreign_chirho.transfer_identity_chirho,
            )
            .expect("digest foreign held-evidence identity");
            foreign_chirho
                .winner_history_first_grant_chirho
                .transfer_identity_digest_chirho = foreign_transfer_digest_chirho.clone();
            foreign_chirho
                .winner_history_first_grant_chirho
                .root_object_digest_chirho = foreign_chirho
                .winner_history_root_object_digest_chirho
                .clone();
            resign_test_value_chirho(
                &mut foreign_chirho.winner_history_first_grant_chirho,
                context_chirho.winner_signer_chirho,
                |grant_chirho| &mut grant_chirho.sig_chirho,
            );
            if let Some(grant_chirho) = foreign_chirho.fork_baseline_first_grant_chirho.as_mut() {
                grant_chirho.transfer_identity_digest_chirho = foreign_transfer_digest_chirho;
                grant_chirho.root_object_digest_chirho = foreign_chirho
                    .fork_baseline_root_object_digest_chirho
                    .clone();
                resign_test_value_chirho(
                    grant_chirho,
                    context_chirho.winner_signer_chirho,
                    |grant_chirho| &mut grant_chirho.sig_chirho,
                );
            }
            resign_test_value_chirho(
                &mut foreign_chirho,
                context_chirho.winner_signer_chirho,
                |manifest_chirho| &mut manifest_chirho.sig_chirho,
            );
            verify_gd7_winner_evidence_manifest_chirho(
                &foreign_chirho,
                context_chirho.winner_signer_chirho,
            )
            .expect("hostile manifest is signed and internally self-consistent");

            assert_eq!(
                held_store_chirho
                    .retain_then_load_manifest_for_test_chirho(&foreign_chirho)
                    .unwrap_err(),
                Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidManifestChirho,
                "the retained store identity must reject even a valid manifest whose unused losing-tail field drifted"
            );
        },
    );
}
