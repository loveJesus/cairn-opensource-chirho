// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::super::fork_baseline_tests_chirho::{
    with_fork_baseline_fixture_chirho, ForkBaselineTailBindingChirho, ForkBaselineTestContextChirho,
};
use super::super::tests_chirho::stage_evidence_manifest_for_view_chirho;
use super::account_net_composition_tests_chirho::{
    complete_evidence_transfer_chirho, complete_view_transfer_chirho, expected_rows_chirho,
    sealed_plan_snapshot_for_context_chirho,
};
use crate::reconciliation_chirho::{
    gd7_held_evidence_transfer_head_path_chirho, gd7_read_only_branch_head_path_chirho,
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_head_path_chirho,
    gd7_reconciliation_identity_digest_chirho, Gd7HeldEvidenceTransferCheckpointChirho,
    Gd7HeldEvidenceTransferHeadChirho, Gd7HeldEvidenceTransferIdentityChirho,
    Gd7HeldEvidenceTransferPhaseChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationHeadChirho, Gd7ReconciliationPhaseChirho, Gd7ReconciliationSignerPortChirho,
    Gd7ReconciliationStoreChirho, GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO,
};
use crate::resident_authority_chirho::{
    commit_or_reload_gd7_held_adoption_for_test_chirho,
    gd7_adoption_staging_journal_path_for_test_chirho,
    materialize_gd7_held_adoption_candidate_chirho,
    materialize_gd7_held_adoption_candidate_with_projection_for_test_chirho,
    verify_active_gd7_held_adoption_for_test_chirho, Gd7HeldAdoptionCommitPortsForTestChirho,
    Gd7HeldAdoptionMaterializationPortsChirho, ResidentGd7HeldAdoptionCommitOutcomeChirho,
    ResidentGd7HeldAdoptionCommitRefusalChirho,
    ResidentGd7HeldAdoptionMaterializationRefusalChirho, ResidentGd7HeldPreparedAdoptionChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{CreateDurableOutcomeChirho, LedgerStoragePortChirho};
use cairn_ledger_read_model_chirho::{
    canonical_account_net_projection_view_chirho, AccountNetProjectionViewChirho,
    ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_sim_chirho::fault_chirho::{FaultKindChirho, FaultPlanChirho};
use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;

#[path = "obligation_mint_actor_tests_chirho.rs"]
mod obligation_mint_actor_tests_chirho;

#[test]
fn one_row_candidate_projection_mismatch_refuses_before_publication_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let rows_chirho = expected_rows_chirho(&context_chirho);
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                rows_chirho.clone(),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            let active_evidence_chirho = held_store_chirho
                .load_active_chirho()
                .expect("load complete evidence transfer")
                .expect("complete evidence transfer remains active");
            let active_branch_chirho = held_store_chirho
                .prepare_and_install_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("install exact branch before the hostile fold");
            let mut mismatched_rows_chirho = rows_chirho;
            mismatched_rows_chirho[0].account_net_chirho = mismatched_rows_chirho[0]
                .account_net_chirho
                .checked_add(1)
                .expect("fixture row remains bounded");
            let mismatched_projection_chirho =
                canonical_account_net_projection_view_chirho(&AccountNetProjectionViewChirho {
                    schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_owned(),
                    rows_chirho: mismatched_rows_chirho,
                })
                .expect("one-row mismatch remains a canonical projection");

            let refusal_chirho =
                materialize_gd7_held_adoption_candidate_with_projection_for_test_chirho(
                    &held_store_chirho,
                    &sealed_plan_snapshot_for_context_chirho(&context_chirho),
                    &active_evidence_chirho.checkpoint_ref_chirho,
                    &active_branch_chirho.checkpoint_ref_chirho,
                    materialization_ports_chirho(&held_storage_chirho, &context_chirho),
                    |_folded_chirho| mismatched_projection_chirho,
                )
                .expect_err("one changed account row must refuse the adoption candidate");
            assert_eq!(
                refusal_chirho,
                ResidentGd7HeldAdoptionMaterializationRefusalChirho::CurrentViewMismatchChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("differs from the accepted winner"));
            assert!(!rendered_chirho.contains("journal verification failed"));
            assert!(!rendered_chirho.contains("immutable object collided"));
            assert!(
                held_storage_chirho
                    .snapshot_chirho()
                    .keys()
                    .all(|path_chirho| {
                        !path_chirho.starts_with("gd7-adoption-materialization-chirho/")
                    }),
                "a mismatch removes staging and publishes no candidate object"
            );
        },
    );
}

#[test]
fn held_signed_evidence_head_rollback_refuses_before_candidate_publication_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                expected_rows_chirho(&context_chirho),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            let active_evidence_chirho = held_store_chirho
                .load_active_chirho()
                .expect("load complete evidence transfer")
                .expect("complete evidence transfer remains active");
            let active_branch_chirho = held_store_chirho
                .prepare_and_install_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("install exact branch before the rollback arm");

            let refusal_chirho =
                materialize_gd7_held_adoption_candidate_with_projection_for_test_chirho(
                    &held_store_chirho,
                    &sealed_plan_snapshot_for_context_chirho(&context_chirho),
                    &active_evidence_chirho.checkpoint_ref_chirho,
                    &active_branch_chirho.checkpoint_ref_chirho,
                    materialization_ports_chirho(&held_storage_chirho, &context_chirho),
                    |projection_bytes_chirho| {
                        rollback_evidence_head_to_receiving_chirho(
                            &held_storage_chirho,
                            &context_chirho,
                            &manifest_chirho.transfer_identity_chirho,
                            &active_evidence_chirho.checkpoint_ref_chirho,
                        );
                        projection_bytes_chirho
                    },
                )
                .expect_err("a valid held-signed head rollback must stale the candidate inputs");
            assert_eq!(
                refusal_chirho,
                ResidentGd7HeldAdoptionMaterializationRefusalChirho::StaleEvidenceChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("changed during materialization"));
            assert!(!rendered_chirho.contains("differs from the accepted winner"));
            assert!(!rendered_chirho.contains("journal verification failed"));
            assert!(
                held_storage_chirho
                    .snapshot_chirho()
                    .keys()
                    .all(|path_chirho| {
                        !path_chirho.starts_with("gd7-adoption-materialization-chirho/")
                    }),
                "a stale evidence head removes staging and publishes no candidate object"
            );
        },
    );
}

#[test]
fn partial_staging_rebuild_reuses_complete_objects_without_touching_evidence_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                expected_rows_chirho(&context_chirho),
            );
            let manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &context_chirho,
                held_view_checkpoint_ref_chirho,
            );
            let held_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &context_chirho,
                &manifest_chirho,
            );
            let active_evidence_chirho = held_store_chirho
                .load_active_chirho()
                .expect("load complete evidence transfer")
                .expect("complete evidence transfer remains active");
            let active_branch_chirho = held_store_chirho
                .prepare_and_install_read_only_branch_evidence_chirho(
                    context_chirho.losing_journal_chirho,
                    context_chirho.expected_genesis_chirho,
                )
                .expect("install exact branch before materialization");
            let sealed_plan_chirho = sealed_plan_snapshot_for_context_chirho(&context_chirho);
            let first_chirho = materialize_gd7_held_adoption_candidate_chirho(
                &held_store_chirho,
                &sealed_plan_chirho,
                &active_evidence_chirho.checkpoint_ref_chirho,
                &active_branch_chirho.checkpoint_ref_chirho,
                materialization_ports_chirho(&held_storage_chirho, &context_chirho),
            )
            .expect("first materialization publishes complete immutable objects");
            let evidence_before_chirho = evidence_snapshot_chirho(&held_storage_chirho);
            let journal_before_chirho = held_storage_chirho
                .read_all_chirho(first_chirho.candidate_journal_path_chirho())
                .expect("read first candidate journal")
                .expect("first candidate journal exists");
            let projection_before_chirho = held_storage_chirho
                .read_all_chirho(first_chirho.candidate_projection_path_chirho())
                .expect("read first candidate projection")
                .expect("first candidate projection exists");
            let staging_path_chirho = gd7_adoption_staging_journal_path_for_test_chirho(
                first_chirho.input_binding_digest_chirho(),
            );
            assert!(matches!(
                held_storage_chirho
                    .create_durable_chirho(&staging_path_chirho, b"partial-candidate-chirho")
                    .expect("plant partial staging residue"),
                CreateDurableOutcomeChirho::CreatedChirho
            ));

            let retried_chirho = materialize_gd7_held_adoption_candidate_chirho(
                &held_store_chirho,
                &sealed_plan_chirho,
                &active_evidence_chirho.checkpoint_ref_chirho,
                &active_branch_chirho.checkpoint_ref_chirho,
                materialization_ports_chirho(&held_storage_chirho, &context_chirho),
            )
            .expect("retry deletes partial staging and reuses exact completed objects");
            assert_eq!(retried_chirho, first_chirho);
            assert_eq!(
                held_storage_chirho
                    .object_len_chirho(&staging_path_chirho)
                    .expect("inspect staging residue after retry"),
                None
            );
            assert_eq!(
                evidence_snapshot_chirho(&held_storage_chirho),
                evidence_before_chirho
            );
            assert_eq!(
                held_storage_chirho
                    .read_all_chirho(first_chirho.candidate_journal_path_chirho())
                    .expect("reload reused candidate journal")
                    .expect("reused candidate journal exists"),
                journal_before_chirho
            );
            assert_eq!(
                held_storage_chirho
                    .read_all_chirho(first_chirho.candidate_projection_path_chirho())
                    .expect("reload reused candidate projection")
                    .expect("reused candidate projection exists"),
                projection_before_chirho
            );
        },
    );
}

#[test]
fn different_reconciliations_select_distinct_candidates_before_integrity_checks_chirho() {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |first_context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let first_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                &held_storage_chirho,
                &first_context_chirho,
                expected_rows_chirho(&first_context_chirho),
            );
            let first_manifest_chirho = stage_evidence_manifest_for_view_chirho(
                &first_context_chirho,
                first_view_checkpoint_ref_chirho,
            );
            let first_store_chirho = complete_evidence_transfer_chirho(
                &held_storage_chirho,
                &first_context_chirho,
                &first_manifest_chirho,
            );
            let first_evidence_chirho = first_store_chirho
                .load_active_chirho()
                .expect("load first evidence transfer")
                .expect("first evidence transfer is complete");
            let first_branch_chirho = first_store_chirho
                .prepare_and_install_read_only_branch_evidence_chirho(
                    first_context_chirho.losing_journal_chirho,
                    first_context_chirho.expected_genesis_chirho,
                )
                .expect("install first read-only branch");
            let first_prepared_chirho = materialize_gd7_held_adoption_candidate_chirho(
                &first_store_chirho,
                &sealed_plan_snapshot_for_context_chirho(&first_context_chirho),
                &first_evidence_chirho.checkpoint_ref_chirho,
                &first_branch_chirho.checkpoint_ref_chirho,
                materialization_ports_chirho(&held_storage_chirho, &first_context_chirho),
            )
            .expect("materialize first reconciliation candidate");
            let first_journal_bytes_chirho = held_storage_chirho
                .read_all_chirho(first_prepared_chirho.candidate_journal_path_chirho())
                .expect("read first candidate")
                .expect("first candidate exists");

            with_fork_baseline_fixture_chirho(
                1,
                true,
                ForkBaselineTailBindingChirho::ActualChirho,
                |second_context_chirho| {
                    let second_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
                        &held_storage_chirho,
                        &second_context_chirho,
                        expected_rows_chirho(&second_context_chirho),
                    );
                    let second_manifest_chirho = stage_evidence_manifest_for_view_chirho(
                        &second_context_chirho,
                        second_view_checkpoint_ref_chirho,
                    );
                    let second_store_chirho = complete_evidence_transfer_chirho(
                        &held_storage_chirho,
                        &second_context_chirho,
                        &second_manifest_chirho,
                    );
                    let second_evidence_chirho = second_store_chirho
                        .load_active_chirho()
                        .expect("load second evidence transfer")
                        .expect("second evidence transfer is complete");
                    let second_branch_chirho = second_store_chirho
                        .prepare_and_install_read_only_branch_evidence_chirho(
                            second_context_chirho.losing_journal_chirho,
                            second_context_chirho.expected_genesis_chirho,
                        )
                        .expect("install second read-only branch");
                    let second_prepared_chirho = materialize_gd7_held_adoption_candidate_chirho(
                        &second_store_chirho,
                        &sealed_plan_snapshot_for_context_chirho(&second_context_chirho),
                        &second_evidence_chirho.checkpoint_ref_chirho,
                        &second_branch_chirho.checkpoint_ref_chirho,
                        materialization_ports_chirho(&held_storage_chirho, &second_context_chirho),
                    )
                    .expect("materialize second reconciliation candidate");

                    assert_ne!(
                        first_prepared_chirho.input_binding_digest_chirho(),
                        second_prepared_chirho.input_binding_digest_chirho(),
                        "the exact reconciliation inputs select the candidate before integrity confirms it"
                    );
                    assert_ne!(
                        first_prepared_chirho.candidate_journal_path_chirho(),
                        second_prepared_chirho.candidate_journal_path_chirho()
                    );
                    assert_ne!(
                        first_prepared_chirho.candidate_projection_path_chirho(),
                        second_prepared_chirho.candidate_projection_path_chirho()
                    );
                    assert_eq!(
                        held_storage_chirho
                            .read_all_chirho(
                                first_prepared_chirho.candidate_journal_path_chirho(),
                            )
                            .expect("reload first candidate after second materialization")
                            .expect("first candidate remains present"),
                        first_journal_bytes_chirho,
                        "a genuine second reconciliation cannot silently reuse or rewrite the first candidate"
                    );
                },
            );
        },
    );
}

/// CLAIM CORRECTED AT ITS LINE (claude2_chirho, 2026-08-06, verified against
/// `store_chirho.rs::commit_checkpoint_internal_chirho`): production's mutation order is
/// checkpoint-create at index 0, SIBLING-HOLD create at index 1, atomic head replacement at
/// index 2 — so the index-1 crash below lands on the SIBLING HOLD, not the head replacement this
/// arm's expect-message names. The assertion still holds (adoption cannot commit when any
/// pre-head mutation crashes), but this arm does NOT isolate the checkpoint-before-head cut: the
/// state where checkpoint AND hold survive with the head unmoved — the availability-not-safety
/// state the store's own SIBLING-FIRST comment describes — is untested here. The retarget/split
/// belongs to the item-6 durability-bridge brick
/// (`item6-durability-bridge-design-chirho.md` §4.2, arms `cut2_*`), with trace calibration so a
/// future mutation-order change moves the arm rather than silently moving the cut.
#[test]
fn adoption_checkpoint_without_head_commit_restarts_plan_sealed_then_retries_exactly_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            let head_path_chirho = gd7_reconciliation_head_path_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
            )
            .expect("derive fixture reconciliation head path");
            let plan_head_bytes_chirho = held_storage_chirho
                .read_all_chirho(&head_path_chirho)
                .expect("read fixture PlanSealed head")
                .expect("fixture PlanSealed head exists");
            let crash_storage_chirho = SimStorageChirho::restore_chirho(
                held_storage_chirho.snapshot_chirho(),
                FaultPlanChirho::single_chirho(1, FaultKindChirho::CrashBeforeChirho),
            );

            let refusal_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(&crash_storage_chirho, context_chirho),
            )
            .expect_err("crash before the atomic head replacement must not commit adoption");
            assert!(
                matches!(
                    refusal_chirho,
                    ResidentGd7HeldAdoptionCommitRefusalChirho::ReconciliationStoreChirho(_)
                ),
                "unexpected pre-head refusal: {refusal_chirho:?}"
            );
            assert!(refusal_chirho.to_string().contains("store refused"));
            assert!(!refusal_chirho.to_string().contains("already committed"));
            assert!(crash_storage_chirho.is_crashed_chirho());
            assert_eq!(
                crash_storage_chirho.mutating_op_count_chirho(),
                2,
                "mutation zero creates the immutable checkpoint and mutation one is the refused head commit"
            );
            assert_eq!(
                crash_storage_chirho
                    .read_all_chirho(&head_path_chirho)
                    .expect("read head after crash")
                    .expect("PlanSealed head survives crash"),
                plan_head_bytes_chirho,
                "creating the adoption checkpoint is not the commit point"
            );
            assert_eq!(
                crash_storage_chirho
                    .snapshot_chirho()
                    .values()
                    .filter_map(|bytes_chirho| {
                        serde_json::from_slice::<Gd7ReconciliationCheckpointChirho>(bytes_chirho)
                            .ok()
                    })
                    .filter(|checkpoint_chirho| {
                        checkpoint_chirho.state_chirho.phase_chirho
                            == Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
                    })
                    .count(),
                1,
                "the immutable adoption checkpoint survives as non-authoritative crash residue"
            );

            let recovered_storage_chirho = SimStorageChirho::restore_chirho(
                crash_storage_chirho.snapshot_chirho(),
                FaultPlanChirho::none_chirho(),
            );
            let recovered_store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
                &recovered_storage_chirho,
                context_chirho.held_signer_chirho,
                context_chirho
                    .plan_checkpoint_chirho
                    .identity_chirho
                    .clone(),
                context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho
                    .clone(),
            )
            .expect("reopen reconciliation store after crash");
            assert_eq!(
                recovered_store_chirho
                    .load_active_chirho()
                    .expect("load active checkpoint after crash")
                    .expect("PlanSealed remains active")
                    .checkpoint_chirho
                    .state_chirho
                    .phase_chirho,
                Gd7ReconciliationPhaseChirho::PlanSealedChirho
            );

            let committed_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(&recovered_storage_chirho, context_chirho),
            )
            .expect("retry commits the exact survived candidate");
            let ResidentGd7HeldAdoptionCommitOutcomeChirho::CommittedChirho(
                committed_snapshot_chirho,
            ) = committed_chirho
            else {
                panic!("the first successful head replacement must report CommittedChirho");
            };
            let restart_snapshot_chirho = verify_active_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &adoption_commit_ports_chirho(&recovered_storage_chirho, context_chirho),
            )
            .expect("restart fully reverifies the committed selector");
            assert_eq!(restart_snapshot_chirho, committed_snapshot_chirho);

            let retried_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(&recovered_storage_chirho, context_chirho),
            )
            .expect("a lost-response retry fully reverifies before reporting exact adoption");
            assert_eq!(
                retried_chirho,
                ResidentGd7HeldAdoptionCommitOutcomeChirho::AlreadyAdoptedExactChirho(
                    committed_snapshot_chirho
                )
            );
        },
    );
}

#[test]
fn adopted_restart_refuses_one_tampered_candidate_without_moving_the_head_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
            )
            .expect("commit the control adoption selector");
            let head_path_chirho = gd7_reconciliation_head_path_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
            )
            .expect("derive committed reconciliation head path");
            let head_before_chirho = held_storage_chirho
                .read_all_chirho(&head_path_chirho)
                .expect("read committed head")
                .expect("committed head exists");
            assert_eq!(
                held_storage_chirho
                    .atomic_write_chirho(
                        prepared_chirho.candidate_journal_path_chirho(),
                        b"tampered-adopted-candidate-chirho",
                    )
                    .expect("plant one candidate-object mutation"),
                ()
            );

            let refusal_chirho = verify_active_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
            )
            .expect_err("restart must reject the altered candidate bytes");
            assert_eq!(
                refusal_chirho,
                ResidentGd7HeldAdoptionCommitRefusalChirho::CandidateDigestMismatchChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("digest or length differs"));
            assert!(!rendered_chirho.contains("projection differs"));
            assert!(!rendered_chirho.contains("already committed"));
            assert_eq!(
                held_storage_chirho
                    .read_all_chirho(&head_path_chirho)
                    .expect("read head after restart refusal")
                    .expect("committed head remains present"),
                head_before_chirho,
                "restart verification never rewrites the selector head"
            );
        },
    );
}

#[test]
fn held_signed_adoption_checkpoint_with_preserved_field_drift_refuses_prior_link_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            let committed_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
            )
            .expect("commit the control adoption selector");
            let committed_snapshot_chirho = match committed_chirho {
                ResidentGd7HeldAdoptionCommitOutcomeChirho::CommittedChirho(snapshot_chirho) => {
                    snapshot_chirho
                }
                ResidentGd7HeldAdoptionCommitOutcomeChirho::AlreadyAdoptedExactChirho(_) => {
                    panic!("the fixture must perform the first adoption commit")
                }
            };
            let committed_checkpoint_path_chirho = gd7_reconciliation_checkpoint_path_chirho(
                committed_snapshot_chirho.checkpoint_ref_chirho(),
            )
            .expect("derive committed adoption checkpoint path");
            let mut drifted_checkpoint_chirho: Gd7ReconciliationCheckpointChirho =
                serde_json::from_slice(
                    &held_storage_chirho
                        .read_all_chirho(&committed_checkpoint_path_chirho)
                        .expect("read committed adoption checkpoint")
                        .expect("committed adoption checkpoint exists"),
                )
                .expect("parse committed adoption checkpoint");
            assert_eq!(
                drifted_checkpoint_chirho.state_chirho.phase_chirho,
                Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
            );
            drifted_checkpoint_chirho
                .state_chirho
                .effect_obligation_count_chirho = drifted_checkpoint_chirho
                .state_chirho
                .effect_obligation_count_chirho
                .checked_add(1)
                .expect("fixture obligation count remains bounded");
            let drifted_checkpoint_ref_chirho = publish_reconciliation_checkpoint_as_active_chirho(
                held_storage_chirho,
                drifted_checkpoint_chirho,
                context_chirho.held_signer_chirho,
            );
            assert_ne!(
                drifted_checkpoint_ref_chirho,
                committed_snapshot_chirho.checkpoint_ref_chirho(),
                "the held-signed hostile checkpoint must alter exactly one preserved field"
            );

            let refusal_chirho = verify_active_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
            )
            .expect_err("restart must bind every adopted field to the exact prior checkpoint");
            assert_eq!(
                refusal_chirho,
                ResidentGd7HeldAdoptionCommitRefusalChirho::PriorCheckpointMismatchChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("prior PlanSealed checkpoint does not match"));
            assert!(!rendered_chirho.contains("candidate digest"));
            assert!(!rendered_chirho.contains("active checkpoint changed"));
        },
    );
}

#[test]
fn stale_plan_head_refuses_prepared_adoption_before_candidate_reuse_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            let journal_before_chirho = held_storage_chirho
                .read_all_chirho(prepared_chirho.candidate_journal_path_chirho())
                .expect("read prepared journal")
                .expect("prepared journal exists");
            let mut resealed_plan_chirho = context_chirho.plan_checkpoint_chirho.clone();
            resealed_plan_chirho
                .state_chirho
                .effect_obligation_count_chirho = 1;
            let resealed_ref_chirho = publish_reconciliation_checkpoint_as_active_chirho(
                held_storage_chirho,
                resealed_plan_chirho,
                context_chirho.held_signer_chirho,
            );
            assert_ne!(
                resealed_ref_chirho,
                prepared_chirho.plan_checkpoint_ref_chirho(),
                "the held-signed reseal must genuinely move the active checkpoint"
            );

            let refusal_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
            )
            .expect_err("a prepared value cannot outlive its exact active PlanSealed checkpoint");
            assert_eq!(
                refusal_chirho,
                ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveCheckpointChangedChirho
            );
            assert!(refusal_chirho
                .to_string()
                .contains("active checkpoint changed"));
            assert!(!refusal_chirho.to_string().contains("digest or length"));
            assert!(!refusal_chirho.to_string().contains("already committed"));
            assert_eq!(
                held_storage_chirho
                    .read_all_chirho(prepared_chirho.candidate_journal_path_chirho())
                    .expect("reload candidate after stale refusal")
                    .expect("candidate remains present"),
                journal_before_chirho,
                "stale-head refusal neither reuses nor rewrites the candidate"
            );
        },
    );
}

#[test]
fn stale_completed_evidence_head_refuses_prepared_adoption_before_commit_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, context_chirho, prepared_chirho| {
            let journal_before_chirho = held_storage_chirho
                .read_all_chirho(prepared_chirho.candidate_journal_path_chirho())
                .expect("read prepared journal")
                .expect("prepared journal exists");
            let (complete_checkpoint_ref_chirho, complete_checkpoint_chirho) = held_storage_chirho
                .snapshot_chirho()
                .into_values()
                .filter_map(|bytes_chirho| {
                    serde_json::from_slice::<Gd7HeldEvidenceTransferCheckpointChirho>(&bytes_chirho)
                        .ok()
                        .map(|checkpoint_chirho| {
                            (
                                blake3::hash(&bytes_chirho).to_hex().to_string(),
                                checkpoint_chirho,
                            )
                        })
                })
                .find(|(_checkpoint_ref_chirho, checkpoint_chirho)| {
                    checkpoint_chirho.phase_chirho
                        == Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
                        && checkpoint_chirho
                            .identity_chirho
                            .reconciliation_identity_chirho
                            == context_chirho.plan_checkpoint_chirho.identity_chirho
                })
                .expect("fixture retains the exact completed transfer checkpoint");
            let evidence_head_path_chirho = gd7_held_evidence_transfer_head_path_chirho(
                &complete_checkpoint_chirho.identity_chirho,
            )
            .expect("derive active evidence head path");
            let evidence_head_bytes_chirho = held_storage_chirho
                .read_all_chirho(&evidence_head_path_chirho)
                .expect("read active complete evidence head")
                .expect("complete evidence head exists");
            rollback_evidence_head_to_receiving_chirho(
                held_storage_chirho,
                context_chirho,
                &complete_checkpoint_chirho.identity_chirho,
                &complete_checkpoint_ref_chirho,
            );

            let refusal_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
            )
            .expect_err("a prepared value cannot outlive its active completed evidence head");
            assert_eq!(
                refusal_chirho,
                ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveEvidenceChangedChirho
            );
            let rendered_chirho = refusal_chirho.to_string();
            assert!(rendered_chirho.contains("active evidence checkpoint changed"));
            assert!(!rendered_chirho.contains("active checkpoint changed"));
            assert!(!rendered_chirho.contains("read-only branch changed"));
            assert_eq!(
                held_storage_chirho
                    .read_all_chirho(prepared_chirho.candidate_journal_path_chirho())
                    .expect("reload candidate after evidence-head refusal")
                    .expect("candidate remains present"),
                journal_before_chirho,
                "a stale evidence head neither reuses nor rewrites the prepared candidate"
            );

            held_storage_chirho
                .atomic_write_chirho(&evidence_head_path_chirho, &evidence_head_bytes_chirho)
                .expect("restore the exact completed evidence head for the sibling arm");
            let branch_head_path_chirho =
                gd7_read_only_branch_head_path_chirho(&complete_checkpoint_chirho.identity_chirho)
                    .expect("derive exact read-only branch head path");
            held_storage_chirho
                .remove_chirho(&branch_head_path_chirho)
                .expect("plant one missing active branch-head mutation");
            let branch_refusal_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                &context_chirho.plan_checkpoint_chirho.identity_chirho,
                &context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &prepared_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, context_chirho),
            )
            .expect_err("a prepared value cannot outlive its active read-only branch head");
            assert_eq!(
                branch_refusal_chirho,
                ResidentGd7HeldAdoptionCommitRefusalChirho::ActiveReadOnlyBranchChangedChirho
            );
            let branch_rendered_chirho = branch_refusal_chirho.to_string();
            assert!(branch_rendered_chirho.contains("active read-only branch changed"));
            assert!(!branch_rendered_chirho.contains("active evidence checkpoint changed"));
            assert!(!branch_rendered_chirho.contains("digest or length"));
        },
    );
}

#[test]
fn already_adopted_different_genuine_candidate_has_distinct_identity_chirho() {
    with_complete_adoption_candidate_chirho(
        |held_storage_chirho, first_context_chirho, first_prepared_chirho| {
            commit_or_reload_gd7_held_adoption_for_test_chirho(
                &first_context_chirho.plan_checkpoint_chirho.identity_chirho,
                &first_context_chirho
                    .plan_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho,
                &first_prepared_chirho,
                &adoption_commit_ports_chirho(held_storage_chirho, first_context_chirho),
            )
            .expect("commit the first genuine candidate");

            with_fork_baseline_fixture_chirho(
                1,
                true,
                ForkBaselineTailBindingChirho::ActualChirho,
                |second_context_chirho| {
                    let second_prepared_chirho = materialize_candidate_for_context_chirho(
                        held_storage_chirho,
                        &second_context_chirho,
                    );
                    assert_ne!(
                        first_prepared_chirho.input_binding_digest_chirho(),
                        second_prepared_chirho.input_binding_digest_chirho(),
                        "the retry arm must present a genuinely different input-selected pair"
                    );

                    let refusal_chirho = commit_or_reload_gd7_held_adoption_for_test_chirho(
                        &first_context_chirho.plan_checkpoint_chirho.identity_chirho,
                        &first_context_chirho
                            .plan_checkpoint_chirho
                            .winner_fork_witness_object_digest_chirho,
                        &second_prepared_chirho,
                        &adoption_commit_ports_chirho(held_storage_chirho, first_context_chirho),
                    )
                    .expect_err("an adopted selector cannot report an inexact retry as success");
                    assert_eq!(
                        refusal_chirho,
                        ResidentGd7HeldAdoptionCommitRefusalChirho::AlreadyAdoptedDifferentCandidateChirho
                    );
                    let rendered_chirho = refusal_chirho.to_string();
                    assert!(rendered_chirho.contains("different candidate pair"));
                    assert!(!rendered_chirho.contains("active checkpoint changed"));
                    assert!(!rendered_chirho.contains("digest or length"));
                },
            );
        },
    );
}

fn with_complete_adoption_candidate_chirho(
    test_chirho: impl FnOnce(
        &SimStorageChirho,
        &ForkBaselineTestContextChirho<'_>,
        ResidentGd7HeldPreparedAdoptionChirho,
    ),
) {
    with_fork_baseline_fixture_chirho(
        2,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let held_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
            let prepared_chirho =
                materialize_candidate_for_context_chirho(&held_storage_chirho, &context_chirho);
            let published_plan_ref_chirho = publish_reconciliation_checkpoint_as_active_chirho(
                &held_storage_chirho,
                context_chirho.plan_checkpoint_chirho.clone(),
                context_chirho.held_signer_chirho,
            );
            assert_eq!(
                published_plan_ref_chirho, context_chirho.plan_checkpoint_ref_chirho,
                "the active-at-commit fixture must publish the exact checkpoint Cut A named"
            );
            test_chirho(&held_storage_chirho, &context_chirho, prepared_chirho);
        },
    );
}

fn materialize_candidate_for_context_chirho(
    held_storage_chirho: &SimStorageChirho,
    context_chirho: &ForkBaselineTestContextChirho<'_>,
) -> ResidentGd7HeldPreparedAdoptionChirho {
    let held_view_checkpoint_ref_chirho = complete_view_transfer_chirho(
        held_storage_chirho,
        context_chirho,
        expected_rows_chirho(context_chirho),
    );
    let manifest_chirho =
        stage_evidence_manifest_for_view_chirho(context_chirho, held_view_checkpoint_ref_chirho);
    let held_store_chirho =
        complete_evidence_transfer_chirho(held_storage_chirho, context_chirho, &manifest_chirho);
    let active_evidence_chirho = held_store_chirho
        .load_active_chirho()
        .expect("load completed evidence transfer")
        .expect("completed evidence transfer is active");
    let active_branch_chirho = held_store_chirho
        .prepare_and_install_read_only_branch_evidence_chirho(
            context_chirho.losing_journal_chirho,
            context_chirho.expected_genesis_chirho,
        )
        .expect("install exact read-only branch");
    materialize_gd7_held_adoption_candidate_chirho(
        &held_store_chirho,
        &sealed_plan_snapshot_for_context_chirho(context_chirho),
        &active_evidence_chirho.checkpoint_ref_chirho,
        &active_branch_chirho.checkpoint_ref_chirho,
        materialization_ports_chirho(held_storage_chirho, context_chirho),
    )
    .expect("materialize exact complete adoption candidate")
}

fn adoption_commit_ports_chirho<'fixture_chirho>(
    held_storage_chirho: &'fixture_chirho SimStorageChirho,
    context_chirho: &'fixture_chirho ForkBaselineTestContextChirho<'fixture_chirho>,
) -> Gd7HeldAdoptionCommitPortsForTestChirho<'fixture_chirho> {
    Gd7HeldAdoptionCommitPortsForTestChirho {
        authority_storage_chirho: held_storage_chirho,
        candidate_storage_chirho: held_storage_chirho,
        held_signer_chirho: context_chirho.held_signer_chirho,
        winner_control_verifier_chirho: context_chirho.winner_signer_chirho,
        winner_ledger_verifier_chirho: context_chirho.winner_journal_signer_chirho,
        clock_chirho: context_chirho.journal_ports_chirho.clock_chirho,
        membership_chirho: context_chirho.journal_ports_chirho.membership_chirho,
        kind_registry_chirho: context_chirho.journal_ports_chirho.kind_registry_chirho,
        authority_chirho: context_chirho.journal_ports_chirho.authority_chirho,
        cluster_id_chirho: context_chirho.cluster_chirho,
    }
}

fn publish_reconciliation_checkpoint_as_active_chirho(
    held_storage_chirho: &SimStorageChirho,
    mut checkpoint_chirho: Gd7ReconciliationCheckpointChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> String {
    checkpoint_chirho.key_id_chirho = held_signer_chirho.key_id_chirho();
    checkpoint_chirho.sig_chirho.clear();
    let checkpoint_unsigned_chirho =
        serde_json::to_vec(&checkpoint_chirho).expect("encode unsigned reconciliation checkpoint");
    checkpoint_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(
            std::str::from_utf8(&checkpoint_unsigned_chirho)
                .expect("checkpoint JSON remains UTF-8"),
        )
        .expect("held signer signs reconciliation checkpoint");
    let checkpoint_bytes_chirho =
        serde_json::to_vec(&checkpoint_chirho).expect("encode signed reconciliation checkpoint");
    let checkpoint_ref_chirho = blake3::hash(&checkpoint_bytes_chirho).to_hex().to_string();
    let checkpoint_path_chirho = gd7_reconciliation_checkpoint_path_chirho(&checkpoint_ref_chirho)
        .expect("derive reconciliation checkpoint path");
    match held_storage_chirho
        .create_durable_chirho(&checkpoint_path_chirho, &checkpoint_bytes_chirho)
        .expect("persist signed reconciliation checkpoint")
    {
        CreateDurableOutcomeChirho::CreatedChirho => {}
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            assert_eq!(
                held_storage_chirho
                    .read_all_chirho(&checkpoint_path_chirho)
                    .expect("read retained checkpoint")
                    .expect("retained checkpoint exists"),
                checkpoint_bytes_chirho
            );
        }
    }

    let mut head_chirho = Gd7ReconciliationHeadChirho {
        schema_chirho: GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: checkpoint_chirho
            .identity_chirho
            .consistency_group_digest_chirho
            .clone(),
        reconciliation_identity_digest_chirho: gd7_reconciliation_identity_digest_chirho(
            &checkpoint_chirho.identity_chirho,
        )
        .expect("digest reconciliation identity"),
        active_checkpoint_ref_chirho: checkpoint_ref_chirho.clone(),
        transition_seq_chirho: checkpoint_chirho.state_chirho.transition_seq_chirho,
        phase_chirho: checkpoint_chirho.state_chirho.phase_chirho,
        key_id_chirho: held_signer_chirho.key_id_chirho(),
        sig_chirho: String::new(),
    };
    let head_unsigned_chirho =
        serde_json::to_vec(&head_chirho).expect("encode unsigned reconciliation head");
    head_chirho.sig_chirho = held_signer_chirho
        .sign_chirho(std::str::from_utf8(&head_unsigned_chirho).expect("head JSON remains UTF-8"))
        .expect("held signer signs reconciliation head");
    held_storage_chirho
        .atomic_write_chirho(
            &gd7_reconciliation_head_path_chirho(&checkpoint_chirho.identity_chirho)
                .expect("derive reconciliation head path"),
            &serde_json::to_vec(&head_chirho).expect("encode signed reconciliation head"),
        )
        .expect("publish signed reconciliation head");
    checkpoint_ref_chirho
}

fn materialization_ports_chirho<'fixture_chirho>(
    held_storage_chirho: &'fixture_chirho SimStorageChirho,
    context_chirho: &'fixture_chirho ForkBaselineTestContextChirho<'fixture_chirho>,
) -> Gd7HeldAdoptionMaterializationPortsChirho<'fixture_chirho> {
    Gd7HeldAdoptionMaterializationPortsChirho {
        candidate_storage_chirho: held_storage_chirho,
        winner_ledger_verifier_chirho: context_chirho.winner_journal_signer_chirho,
        clock_chirho: context_chirho.journal_ports_chirho.clock_chirho,
        membership_chirho: context_chirho.journal_ports_chirho.membership_chirho,
        kind_registry_chirho: context_chirho.journal_ports_chirho.kind_registry_chirho,
        authority_chirho: context_chirho.journal_ports_chirho.authority_chirho,
        cluster_id_chirho: context_chirho.cluster_chirho,
    }
}

fn evidence_snapshot_chirho(
    held_storage_chirho: &SimStorageChirho,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    held_storage_chirho
        .snapshot_chirho()
        .into_iter()
        .filter(|(path_chirho, _bytes_chirho)| {
            !path_chirho.starts_with("gd7-adoption-materialization-chirho/")
        })
        .collect()
}

fn rollback_evidence_head_to_receiving_chirho(
    held_storage_chirho: &SimStorageChirho,
    context_chirho: &ForkBaselineTestContextChirho<'_>,
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
    complete_checkpoint_ref_chirho: &str,
) {
    let (receiving_checkpoint_ref_chirho, receiving_checkpoint_chirho) = held_storage_chirho
        .snapshot_chirho()
        .into_values()
        .filter_map(|bytes_chirho| {
            serde_json::from_slice::<Gd7HeldEvidenceTransferCheckpointChirho>(&bytes_chirho)
                .ok()
                .map(|checkpoint_chirho| {
                    (
                        blake3::hash(&bytes_chirho).to_hex().to_string(),
                        checkpoint_chirho,
                    )
                })
        })
        .filter(|(_checkpoint_ref_chirho, checkpoint_chirho)| {
            checkpoint_chirho.identity_chirho == *identity_chirho
                && checkpoint_chirho.phase_chirho
                    == Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho
        })
        .max_by_key(|(_checkpoint_ref_chirho, checkpoint_chirho)| {
            checkpoint_chirho.transition_seq_chirho
        })
        .expect("completed transfer retains a valid receiving checkpoint");
    assert_ne!(
        receiving_checkpoint_ref_chirho, complete_checkpoint_ref_chirho,
        "the rollback target must differ from the completed checkpoint"
    );
    let head_path_chirho = gd7_held_evidence_transfer_head_path_chirho(identity_chirho)
        .expect("derive exact evidence head path");
    let current_head_bytes_chirho = held_storage_chirho
        .read_all_chirho(&head_path_chirho)
        .expect("read current evidence head")
        .expect("current evidence head exists");
    let mut rolled_back_head_chirho =
        serde_json::from_slice::<Gd7HeldEvidenceTransferHeadChirho>(&current_head_bytes_chirho)
            .expect("parse current evidence head");
    rolled_back_head_chirho.active_checkpoint_ref_chirho = receiving_checkpoint_ref_chirho;
    rolled_back_head_chirho.transition_seq_chirho =
        receiving_checkpoint_chirho.transition_seq_chirho;
    rolled_back_head_chirho.phase_chirho = receiving_checkpoint_chirho.phase_chirho;
    rolled_back_head_chirho.sig_chirho.clear();
    let unsigned_bytes_chirho =
        serde_json::to_vec(&rolled_back_head_chirho).expect("encode unsigned rollback head");
    rolled_back_head_chirho.sig_chirho = context_chirho
        .held_signer_chirho
        .sign_chirho(std::str::from_utf8(&unsigned_bytes_chirho).expect("head JSON is UTF-8"))
        .expect("held signer signs rollback head");
    held_storage_chirho
        .atomic_write_chirho(
            &head_path_chirho,
            &serde_json::to_vec(&rolled_back_head_chirho)
                .expect("encode held-signed rollback head"),
        )
        .expect("publish held-signed rollback head");
}
