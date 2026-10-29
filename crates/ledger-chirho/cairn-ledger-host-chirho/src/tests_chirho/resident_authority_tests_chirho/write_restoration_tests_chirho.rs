// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The D4 property, executed in both directions: after D3 ordinary writes REFUSE, after D4 they ADMIT.

use super::super::reconciliation_witness_tests_chirho::{
    empty_verified_losing_tail_chirho, held_winner_import_fixture_for_group_and_term_chirho,
    FakeGd7ControlSignerChirho, FakeWinnerLedgerSignerChirho,
};
use super::strand_fence_liveness_tests_chirho::install_adopted_cut_in_resident_root_chirho;
use super::with_unbound_resident_fixture_chirho;
use crate::reconciliation_chirho::{
    gd7_reconciliation_group_has_any_active_hold_chirho,
    gd7_reconciliation_group_ordinary_writes_withheld_chirho,
    signed_converged_read_replica_for_release_test_chirho, Gd7WinnerWitnessReaderChirho,
};
use crate::resident_authority_chirho::write_restoration_chirho::{
    commit_write_restoration_chirho, load_verified_write_restoration_confirmation_chirho,
    parse_and_verify_write_restoration_confirmation_chirho,
    Gd7WriteRestorationConfirmationInputChirho, Gd7WriteRestorationOutcomeChirho,
    Gd7WriteRestorationRefusalChirho,
};
use crate::{ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityRefusalChirho};
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_digest_chirho;

/// Evidence a confirmation binds. Only `retained_adopted_checkpoint_ref_chirho` and the group are
/// instance coordinates; the rest are the clause-6 bindings this brick does not yet MEASURE (the
/// D4 gate does that), so they are fixture values here and the arm says so rather than implying
/// the gate exists.
fn confirmation_input_chirho(
    group_digest_chirho: &str,
    adopted_ref_chirho: &str,
) -> Gd7WriteRestorationConfirmationInputChirho {
    let digest_chirho = |nibble_chirho: char| -> String { nibble_chirho.to_string().repeat(64) };
    Gd7WriteRestorationConfirmationInputChirho {
        consistency_group_digest_chirho: group_digest_chirho.to_owned(),
        retained_adopted_checkpoint_ref_chirho: adopted_ref_chirho.to_owned(),
        superseded_head_checkpoint_ref_chirho: adopted_ref_chirho.to_owned(),
        accepted_winner_identity_chirho: "winner-identity-chirho".to_owned(),
        accepted_winner_term_chirho: 7,
        convergence_certificate_digest_chirho: digest_chirho('a'),
        closed_population_digest_chirho: digest_chirho('b'),
        completed_count_chirho: 3,
        disposed_count_chirho: 1,
        elector_grant_identity_chirho: "elector-grant-chirho".to_owned(),
        elector_grant_term_chirho: 9,
    }
}

/// THE D4 PROPERTY, both directions in one run.
///
/// The reason this must be one test rather than two: the ADMIT half is only meaningful if the
/// SAME append, in the SAME state, refused a moment earlier. Split across fixtures, an admit arm
/// can pass because the barrier was never planted — the exact green-by-emptiness this brick's own
/// mutation round caught elsewhere.
#[test]
fn ordinary_writes_refuse_after_release_and_admit_only_after_confirmed_restoration_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4-restore",
        |root_chirho,
         group_chirho,
         local_node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mesh_chirho =
                super::strand_fence_liveness_tests_chirho::ElectorMeshChirho::new_chirho(
                    group_chirho,
                    local_node_chirho,
                );
            let term_chirho = mesh_chirho.elect_chirho(1, None);
            let birth_permit_chirho = crate::ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            drop(
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    birth_permit_chirho,
                    ports_chirho,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("bound resident is born on the mesh leader"),
            );
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    mesh_chirho
                        .node_chirho(1)
                        .local_append_authority_handle_chirho(),
                )
                .expect("bound resident opens at its birth term");

            // CONTROL, before any reconciliation exists: the ordinary append SUCCEEDS. Without
            // this, a later refusal could be caused by anything in the fixture and the arm would
            // be measuring the wrong thing.
            resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4-control-before-chirho"),
                )
                .expect("with no reconciliation open, an ordinary write must be admitted");

            let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open the resident root");
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            let control_signer_chirho =
                FakeGd7ControlSignerChirho::new_chirho("a".repeat(64), 0x31);
            let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x32);
            let losing_tail_chirho = empty_verified_losing_tail_chirho(
                &storage_chirho,
                &ledger_signer_chirho,
                "d4-chirho",
            );
            let fixture_chirho = held_winner_import_fixture_for_group_and_term_chirho(
                &storage_chirho,
                &control_signer_chirho,
                &ledger_signer_chirho,
                &losing_tail_chirho,
                group_chirho,
                term_chirho,
            );
            let observation_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
                &storage_chirho,
                &control_signer_chirho,
                &ledger_signer_chirho,
            )
            .import_authenticated_deposed_fork_observation_chirho(
                &fixture_chirho.identity_chirho,
                &fixture_chirho.index_bytes_chirho,
                &fixture_chirho.witness_bytes_chirho,
                &losing_tail_chirho,
            )
            .expect("import the genuine authenticated observation into the resident root");
            let held_signer_chirho = FakeGd7ControlSignerChirho::new_chirho(
                observation_chirho
                    .identity_chirho()
                    .held_node_chirho
                    .clone(),
                0x41,
            );
            let adopted_ref_chirho = install_adopted_cut_in_resident_root_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &observation_chirho,
            );

            // BOTH BARRIERS STAND. The sibling was planted BEFORE the head (the strand-safe
            // order), so a crash during open can only over-withhold, never under-withhold.
            assert!(
                gd7_reconciliation_group_has_any_active_hold_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the head"),
                "the adopted cut is itself an active head"
            );
            assert!(
                gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the ordinary-write hold"),
                "opening a reconciliation must plant the ordinary-write hold"
            );

            // D3 — THE RELEASE. The head goes; the sibling MUST NOT.
            resident_chirho
                .release_converged_gd7_hold_chirho(
                    &adopted_ref_chirho,
                    &signed_converged_read_replica_for_release_test_chirho(
                        adopted_ref_chirho.clone(),
                        &held_signer_chirho,
                    ),
                    &held_signer_chirho,
                )
                .expect("release the converged hold");
            assert!(
                !gd7_reconciliation_group_has_any_active_hold_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the head after release"),
                "D3 supersedes the head"
            );
            assert!(
                gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                    &storage_chirho,
                    &group_digest_chirho
                )
                .expect("probe the ordinary-write hold after release"),
                "D3 must NOT lift the ordinary-write barrier — that is D4's act alone"
            );

            // THE REFUSE HALF. Before this brick, this append SUCCEEDED at this exact point: the
            // head was gone and nothing else withheld ordinary writes, so a winner's old victory
            // plus an absent head reopened ordinary writes with no later elector grant. That is
            // the gap this barrier closes, and this assertion is where it is measured.
            let refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4-after-release-chirho"),
                )
                .expect_err("after D3 alone, ordinary writes must still be withheld");
            assert!(
                matches!(
                    refusal_chirho,
                    ResidentLedgerAuthorityRefusalChirho::Gd7OrdinaryWritesWithheldChirho
                ),
                "the refusal must be the ORDINARY-WRITE barrier, not the head hold or a fence \
                 refusal — a right answer for the wrong reason would hide a missing barrier. \
                 MIGRATION: if this now reports Gd7ReconciliationHoldActiveChirho, D3 stopped \
                 removing the head; if it reports a fence refusal, the fixture drifted and the \
                 barrier is untested. Got: {refusal_chirho:?}"
            );

            // D4 — the transaction. Confirmation first, verified, and only then the hold removal.
            let input_chirho = confirmation_input_chirho(&group_digest_chirho, &adopted_ref_chirho);
            let outcome_chirho = commit_write_restoration_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &input_chirho,
            )
            .expect("the restoration transaction commits");
            assert_eq!(
                outcome_chirho,
                Gd7WriteRestorationOutcomeChirho::RestoredChirho,
                "the first restoration reports RestoredChirho, not an idempotent replay"
            );

            // THE ADMIT HALF — the same append, the same resident, now admitted.
            resident_chirho
                .append_preactivation_chirho(
                    &crate::ResidentLedgerAppendPermitChirho::for_test_chirho(),
                    super::resident_mint_request_chirho(100, "d4-after-restore-chirho"),
                )
                .expect("after a confirmed restoration, ordinary writes are admitted again");

            // The artifact is reloadable and bound to THIS instance — clause 8's crash-after
            // outcome, observed rather than asserted.
            let confirmation_chirho = load_verified_write_restoration_confirmation_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &group_digest_chirho,
                &adopted_ref_chirho,
            )
            .expect("the confirmation reloads")
            .expect("the confirmation is present after a reported restoration");
            assert!(
                confirmation_chirho.head_absent_chirho(),
                "the confirmation carries the explicit absent-head marker"
            );
            assert_eq!(
                confirmation_chirho
                    .verified_closed_population_total_chirho()
                    .expect("counts do not overflow"),
                4,
                "completed + disposed is derived from the bound parts, by value"
            );

            // IDEMPOTENT RETRY. A crash between the artifact write and the hold removal leaves the
            // artifact standing; the retry must complete the removal and report the replay
            // distinctly, never a second RestoredChirho and never a collision.
            let replay_chirho = commit_write_restoration_chirho(
                &storage_chirho,
                &held_signer_chirho,
                &held_signer_chirho,
                &input_chirho,
            )
            .expect("an identical retry is idempotent, not a collision");
            assert_eq!(
                replay_chirho,
                Gd7WriteRestorationOutcomeChirho::AlreadyRestoredChirho,
                "the retry is reported as a replay, so an operator can tell it apart"
            );
        },
    );
}

/// A confirmation cannot be reused for another instance, and every clause-6 binding is covered by
/// the signature: altering ANY bound byte changes the signed line, so verification refuses.
#[test]
fn a_confirmation_refuses_for_a_foreign_instance_and_any_altered_binding_chirho() {
    with_unbound_resident_fixture_chirho(
        "d4-binding",
        |root_chirho,
         group_chirho,
         _local_node_chirho,
         _ports_chirho,
         _journal_chirho,
         _cluster_chirho| {
            let storage_chirho = crate::FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open the resident root");
            let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
            let signer_chirho = FakeGd7ControlSignerChirho::new_chirho("e".repeat(64), 0x51);
            let adopted_ref_chirho = "c".repeat(64);
            let input_chirho = confirmation_input_chirho(&group_digest_chirho, &adopted_ref_chirho);
            commit_write_restoration_chirho(
                &storage_chirho,
                &signer_chirho,
                &signer_chirho,
                &input_chirho,
            )
            .expect("the restoration transaction commits");

            let path_chirho =
                crate::resident_authority_chirho::write_restoration_chirho::gd7_write_restoration_confirmation_path_chirho(
                    &group_digest_chirho,
                    &adopted_ref_chirho,
                )
                .expect("path");
            let bytes_chirho =
                cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho::read_all_chirho(
                    &storage_chirho,
                    &path_chirho,
                )
                .expect("read")
                .expect("present");

            // A FOREIGN ADOPTED CHECKPOINT — the same group, a different instance.
            let foreign_chirho = parse_and_verify_write_restoration_confirmation_chirho(
                &bytes_chirho,
                &signer_chirho,
                &group_digest_chirho,
                &"d".repeat(64),
            )
            .expect_err("a confirmation for instance N must not verify for instance N+1");
            assert!(
                matches!(
                    foreign_chirho,
                    Gd7WriteRestorationRefusalChirho::WrongAdoptedCheckpointChirho
                ),
                "the refusal must name the instance mismatch, not a signature failure. Got: \
                 {foreign_chirho:?}"
            );

            // EVERY BOUND FIELD, one tamper each, and each asserts its OWN reason. The counts are
            // the interesting ones: they are what a later consumer reads as evidence about
            // disposed obligations, so a silently editable count would be a laundering path.
            //
            // The absent-head marker is expected to refuse EARLIER than the signature, because it
            // is checked before the signature is verified. Asserting the reason rather than mere
            // Err-ness is what distinguishes "the marker is enforced" from "the signature happened
            // to catch it" — the marker must be load-bearing on its own.
            for (needle_chirho, replacement_chirho, label_chirho, expected_chirho) in [
                (
                    "\"completed_count_chirho\":3",
                    "\"completed_count_chirho\":9",
                    "completed count",
                    Gd7WriteRestorationRefusalChirho::InvalidConfirmationSignatureChirho,
                ),
                (
                    "\"disposed_count_chirho\":1",
                    "\"disposed_count_chirho\":0",
                    "disposed count",
                    Gd7WriteRestorationRefusalChirho::InvalidConfirmationSignatureChirho,
                ),
                (
                    "\"accepted_winner_term_chirho\":7",
                    "\"accepted_winner_term_chirho\":8",
                    "winner term",
                    Gd7WriteRestorationRefusalChirho::InvalidConfirmationSignatureChirho,
                ),
                (
                    "\"elector_grant_term_chirho\":9",
                    "\"elector_grant_term_chirho\":1",
                    "grant term",
                    Gd7WriteRestorationRefusalChirho::InvalidConfirmationSignatureChirho,
                ),
                (
                    "\"head_absent_chirho\":true",
                    "\"head_absent_chirho\":false",
                    "absent-head marker",
                    Gd7WriteRestorationRefusalChirho::HeadNotMarkedAbsentChirho,
                ),
            ] {
                let original_chirho = std::str::from_utf8(&bytes_chirho).expect("utf8");
                assert!(
                    original_chirho.contains(needle_chirho),
                    "the tamper anchor for {label_chirho} must exist in the artifact, or this arm \
                     tests nothing. MIGRATION: if the field was renamed or its fixture value \
                     changed, retarget the anchor — do not delete the case."
                );
                let tampered_chirho = original_chirho.replace(needle_chirho, replacement_chirho);
                assert_ne!(
                    tampered_chirho.as_bytes(),
                    bytes_chirho.as_slice(),
                    "the {label_chirho} tamper must actually change the bytes"
                );
                let refusal_chirho = parse_and_verify_write_restoration_confirmation_chirho(
                    tampered_chirho.as_bytes(),
                    &signer_chirho,
                    &group_digest_chirho,
                    &adopted_ref_chirho,
                )
                .expect_err("a tampered binding must refuse");
                assert_eq!(
                    refusal_chirho, expected_chirho,
                    "the {label_chirho} tamper must refuse for its OWN reason"
                );
            }
        },
    );
}
