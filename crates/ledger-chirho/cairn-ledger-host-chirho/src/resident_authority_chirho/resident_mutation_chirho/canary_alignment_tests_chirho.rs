// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Arms for the readiness/canary alignment classifier — the instrument the loss-drill fix is verified with.
//!
//! Written 2026-08-17 as A5 of the re-scoped epoch-wedge brick. The classifier and its four
//! coordinates shipped with ZERO test coverage and were pinned by nothing but one hosted observation;
//! an adversarial review named that as a reason not to build the fix first, because a fix would then
//! be measured with an unmeasured instrument.
//!
//! Two properties matter here and both are pinned below: that each coordinate is reported for its OWN
//! mismatch, and that the documented most-specific-first ORDER holds when several differ at once —
//! the second being a deliberate choice in `classify_readiness_canary_alignment_chirho` that carried
//! no pin at all.

use super::resident_mutation_envelope_chirho::{
    classify_readiness_canary_alignment_chirho, verify_readiness_canary_alignment_chirho,
    ResidentCanaryAlignmentMismatchChirho,
};
use crate::resident_authority_chirho::ResidentLedgerAuthorityReadinessChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::ShadowCanaryLedgerCutChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;

const TAIL_DIGEST_CHIRHO: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_DIGEST_CHIRHO: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const ALIGNED_SEQ_CHIRHO: u64 = 7;
const ALIGNED_EPOCH_CHIRHO: u64 = 4;

fn group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "canary-alignment-arm-chirho".to_owned(),
    }
}

fn other_group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "canary-alignment-other-arm-chirho".to_owned(),
    }
}

fn cut_chirho(group_chirho: &ConsistencyGroupIdChirho) -> ShadowCanaryLedgerCutChirho {
    ShadowCanaryLedgerCutChirho::new_chirho(
        ALIGNED_SEQ_CHIRHO,
        TAIL_DIGEST_CHIRHO.to_owned(),
        1_700_000_000_000,
        0,
        ALIGNED_EPOCH_CHIRHO,
        group_chirho,
    )
    .expect("the arm's canary cut is well shaped")
}

fn readiness_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
) -> ResidentLedgerAuthorityReadinessChirho {
    ResidentLedgerAuthorityReadinessChirho {
        consistency_group_chirho: group_chirho.clone(),
        local_node_chirho: NodeIdChirho("canary-alignment-node-chirho".to_owned()),
        process_generation_chirho: 1,
        published_raft_term_chirho: 1,
        journal_epoch_chirho: ALIGNED_EPOCH_CHIRHO,
        membership_epoch_chirho: ALIGNED_EPOCH_CHIRHO,
        journal_tail_seq_chirho: ALIGNED_SEQ_CHIRHO,
        journal_tail_digest_chirho: DigestChirho(TAIL_DIGEST_CHIRHO.to_owned()),
        genesis_digest_chirho: DigestChirho(OTHER_DIGEST_CHIRHO.to_owned()),
        resident_identity_digest_chirho: OTHER_DIGEST_CHIRHO.to_owned(),
    }
}

/// POSITIVE CONTROL. Without this, every mismatch arm below could pass on a fixture that is simply
/// never aligned, and the classifier would look discriminating while reporting a constant.
#[test]
fn aligned_readiness_and_cut_report_no_mismatch_chirho() {
    let group_chirho = group_chirho();
    let mismatch_chirho = classify_readiness_canary_alignment_chirho(
        &readiness_chirho(&group_chirho),
        &cut_chirho(&group_chirho),
        &group_chirho,
    )
    .expect("classification succeeds on a well-formed pair");
    assert_eq!(mismatch_chirho, None);
    verify_readiness_canary_alignment_chirho(
        &readiness_chirho(&group_chirho),
        &cut_chirho(&group_chirho),
        &group_chirho,
    )
    .expect("an aligned pair must not refuse");
}

#[test]
fn a_moved_tail_seq_reports_the_tail_seq_coordinate_chirho() {
    let group_chirho = group_chirho();
    let mut readiness_chirho = readiness_chirho(&group_chirho);
    readiness_chirho.journal_tail_seq_chirho = ALIGNED_SEQ_CHIRHO + 1;
    let mismatch_chirho = classify_readiness_canary_alignment_chirho(
        &readiness_chirho,
        &cut_chirho(&group_chirho),
        &group_chirho,
    )
    .expect("classification succeeds");
    assert_eq!(
        mismatch_chirho,
        Some(ResidentCanaryAlignmentMismatchChirho::TailSeqChirho)
    );
}

#[test]
fn a_changed_tail_digest_reports_the_tail_digest_coordinate_chirho() {
    let group_chirho = group_chirho();
    let mut readiness_chirho = readiness_chirho(&group_chirho);
    readiness_chirho.journal_tail_digest_chirho = DigestChirho(OTHER_DIGEST_CHIRHO.to_owned());
    let mismatch_chirho = classify_readiness_canary_alignment_chirho(
        &readiness_chirho,
        &cut_chirho(&group_chirho),
        &group_chirho,
    )
    .expect("classification succeeds");
    assert_eq!(
        mismatch_chirho,
        Some(ResidentCanaryAlignmentMismatchChirho::TailDigestChirho)
    );
}

#[test]
fn a_different_consistency_group_reports_the_group_coordinate_chirho() {
    let group_chirho = group_chirho();
    // The cut was recorded under a DIFFERENT group than the one now being verified.
    let mismatch_chirho = classify_readiness_canary_alignment_chirho(
        &readiness_chirho(&group_chirho),
        &cut_chirho(&other_group_chirho()),
        &group_chirho,
    )
    .expect("classification succeeds");
    assert_eq!(
        mismatch_chirho,
        Some(ResidentCanaryAlignmentMismatchChirho::ConsistencyGroupChirho)
    );
}

/// THE ORDERING PIN — RETARGETED 2026-08-17, not deleted.
///
/// It previously pinned that the JOURNAL-EPOCH coordinate masked a simultaneous tail mismatch. That
/// coordinate was removed (it refused a state the journal explicitly supports — see the classifier),
/// so the arm now pins the precedence that remains: the CONSISTENCY-GROUP coordinate is checked
/// before either tail coordinate, so a cut recorded under a different group reports the group rather
/// than the tail differences it also has.
///
/// Still load-bearing for the same reason as before: the hosted drills read the reported coordinate
/// as the answer, so which one wins when several differ is not cosmetic.
#[test]
fn the_group_coordinate_takes_precedence_over_simultaneous_tail_mismatches_chirho() {
    let group_chirho = group_chirho();
    let mut readiness_chirho = readiness_chirho(&group_chirho);
    readiness_chirho.journal_tail_seq_chirho = ALIGNED_SEQ_CHIRHO + 1;
    readiness_chirho.journal_tail_digest_chirho = DigestChirho(OTHER_DIGEST_CHIRHO.to_owned());
    let mismatch_chirho = classify_readiness_canary_alignment_chirho(
        &readiness_chirho,
        &cut_chirho(&other_group_chirho()),
        &group_chirho,
    )
    .expect("classification succeeds");
    assert_eq!(
        mismatch_chirho,
        Some(ResidentCanaryAlignmentMismatchChirho::ConsistencyGroupChirho),
        "group is checked first, so it masks the two tail coordinates"
    );
}

/// The classifier and the gate must agree: anything the classifier calls a mismatch must REFUSE.
/// Without this, the split could drift into a display-only annotation while the gate used other
/// logic — the shape where a diagnostic and the check it describes quietly disagree.
#[test]
fn every_classified_mismatch_also_refuses_at_the_gate_chirho() {
    let group_chirho = group_chirho();
    // The epoch case was REMOVED with its coordinate: a moved grant epoch is no longer a mismatch,
    // so including it here would assert the gate refuses a state it now correctly accepts.
    let mut moved_seq_chirho = readiness_chirho(&group_chirho);
    moved_seq_chirho.journal_tail_seq_chirho = ALIGNED_SEQ_CHIRHO + 1;
    let mut moved_digest_chirho = readiness_chirho(&group_chirho);
    moved_digest_chirho.journal_tail_digest_chirho = DigestChirho(OTHER_DIGEST_CHIRHO.to_owned());
    for readiness_chirho in [&moved_seq_chirho, &moved_digest_chirho] {
        let classified_chirho = classify_readiness_canary_alignment_chirho(
            readiness_chirho,
            &cut_chirho(&group_chirho),
            &group_chirho,
        )
        .expect("classification succeeds");
        assert!(classified_chirho.is_some(), "the arm's fixture must differ");
        assert!(
            verify_readiness_canary_alignment_chirho(
                readiness_chirho,
                &cut_chirho(&group_chirho),
                &group_chirho,
            )
            .is_err(),
            "a classified mismatch must refuse at the gate, not merely be labelled"
        );
    }
}

/// A2 of the epoch-wedge brick — the WEDGE CONDITION reproduced on a real resident.
///
/// The arms above pin the classifier on synthetic inputs; A1 pins that a real refused append leaves
/// the epoch advanced. This one composes them: a real resident, a real successful append that
/// establishes an aligned canary cut, a REOPEN (which is what production's adoption-aligned start
/// does), then a real FAILED first append — and shows the alignment gate now refuses on the epoch
/// coordinate. That is the state the served path cannot leave without another restart.
///
/// HONEST LIMIT, stated because it is the difference between this and the full reproduction: it does
/// NOT drive `handle_actor_command_chirho`, so it does not prove the actor loop then refuses every
/// subsequent mutation. It proves the PRECONDITION that makes it refuse. The actor-loop arm still
/// needs the 18-argument fixture the review priced, and remains open.
///
/// MIGRATION PATH: if the final assertion stops refusing, the fix has landed — retarget this to
/// assert the gate ACCEPTS after a refused append, and keep the successful-append control.
#[test]
fn a_failed_first_append_after_reopen_wedges_the_alignment_gate_chirho() {
    crate::tests_chirho::with_bound_resident_fixture_chirho(
        "canary-alignment-epoch-wedge",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho =
                crate::tests_chirho::warm_single_node_elector_chirho(node_chirho, group_chirho);
            let permit_chirho =
                crate::resident_authority_chirho::ResidentLedgerAppendPermitChirho::for_test_chirho(
                );

            // One SUCCESSFUL append establishes the aligned canary cut, exactly as a healthy window
            // does. Its receipt is the only thing that ever moves the cut.
            let mut resident_chirho =
                crate::resident_authority_chirho::ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("the resident opens for the successful append");
            let receipt_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    crate::tests_chirho::resident_mint_request_chirho(
                        5,
                        "canary-alignment-good-chirho",
                    ),
                )
                .expect("a well-formed mint commits and yields the canary receipt");
            let aligned_cut_chirho = ShadowCanaryLedgerCutChirho::new_chirho(
                receipt_chirho.append_chirho.seq_chirho,
                receipt_chirho.append_chirho.record_digest_chirho.0.clone(),
                receipt_chirho.append_chirho.hlc_chirho.physical_ms_chirho,
                receipt_chirho.append_chirho.hlc_chirho.logical_chirho,
                receipt_chirho.fence_chirho.epoch_chirho,
                group_chirho,
            )
            .expect("the cut binds to the committed receipt");
            drop(resident_chirho);

            // REOPEN — production's adoption-aligned start. The gate must accept here; if it did
            // not, every arm below would pass for the wrong reason.
            let mut resident_chirho =
                crate::resident_authority_chirho::ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("the resident reopens on its existing journal");
            let reopened_chirho = resident_chirho.probe_chirho().unwrap();
            verify_readiness_canary_alignment_chirho(
                &reopened_chirho,
                &aligned_cut_chirho,
                group_chirho,
            )
            .expect("POSITIVE CONTROL: a reopened resident starts ALIGNED with its canary cut");

            // The FAILED first append after that open. Nothing is written, and the epoch moves.
            let refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    crate::tests_chirho::resident_mint_request_chirho(
                        0,
                        "canary-alignment-rejected-chirho",
                    ),
                )
                .unwrap_err();
            assert!(matches!(
                refusal_chirho,
                crate::resident_authority_chirho::ResidentLedgerAuthorityRefusalChirho::JournalMutationRefusedChirho { .. }
            ));
            let wedged_chirho = resident_chirho.probe_chirho().unwrap();
            assert_eq!(
                wedged_chirho.journal_tail_seq_chirho, reopened_chirho.journal_tail_seq_chirho,
                "the refused append must not write a record"
            );

            // RETARGETED 2026-08-17, exactly as this arm's migration path instructed. It previously
            // asserted the wedge — `Some(JournalEpochChirho)` and a refusing gate. The grant-domain
            // epoch coordinate has since been REMOVED (it refused a state the journal explicitly
            // supports), so the arm now pins the property that removal was for: **a refused append no
            // longer wedges the writer.**
            //
            // The steps above are untouched, which is what makes this green a statement about the
            // code rather than about the test: same real resident, same real refused append, same
            // real cut.
            assert_eq!(
                classify_readiness_canary_alignment_chirho(
                    &wedged_chirho,
                    &aligned_cut_chirho,
                    group_chirho,
                )
                .expect("classification succeeds"),
                None,
                "a refused append writes no record, so nothing the canary cut pins has moved"
            );
            verify_readiness_canary_alignment_chirho(
                &wedged_chirho,
                &aligned_cut_chirho,
                group_chirho,
            )
            .expect(
                "THE FIX: after a refused append the alignment gate ACCEPTS, so the writer is not \
                 wedged and needs no restart to resume",
            );
        },
    );
}

/// A3 of the epoch-wedge brick — THE ARM THAT CATCHES A PARTIAL FIX.
///
/// A refused append advances TWO coordinates, not one: the journal epoch and the membership epoch
/// (`rebind_epoch_chirho`, verified strictly monotone — it refuses any `requested < current` with
/// `MembershipEpochRegressionChirho`, so like the journal advance it has no inverse).
///
/// This matters because the obvious repair is to fix "the journal epoch". An adversarial review
/// measured that doing only that MOVES the wall rather than removing it: the resident then refuses
/// `MembershipAheadOfJournalChirho` from `validate_epoch_posture_chirho`, which runs inside
/// `probe_chirho()` — i.e. EARLIER than the canary check this brick started from. A fix that lands
/// with only the journal half addressed will pass A1 and A2 and still leave the writer wedged.
///
/// MIGRATION PATH: if either assertion stops holding, one coordinate is being scoped or reverted.
/// That is progress ONLY if the other is handled in the same change — check both before concluding
/// the wedge is closed, and re-run A2, which observes the gate rather than the coordinates.
#[test]
fn a_refused_append_advances_membership_as_well_as_the_journal_chirho() {
    crate::tests_chirho::with_bound_resident_fixture_chirho(
        "canary-alignment-membership-twin",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho =
                crate::tests_chirho::warm_single_node_elector_chirho(node_chirho, group_chirho);
            let permit_chirho =
                crate::resident_authority_chirho::ResidentLedgerAppendPermitChirho::for_test_chirho(
                );
            let mut resident_chirho =
                crate::resident_authority_chirho::ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("the resident opens");
            let before_chirho = resident_chirho.probe_chirho().unwrap();
            let _refusal_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    crate::tests_chirho::resident_mint_request_chirho(
                        0,
                        "canary-alignment-membership-rejected-chirho",
                    ),
                )
                .unwrap_err();
            let after_chirho = resident_chirho.probe_chirho().unwrap();
            assert!(
                after_chirho.journal_epoch_chirho > before_chirho.journal_epoch_chirho,
                "the journal epoch advances on a refused append"
            );
            assert!(
                after_chirho.membership_epoch_chirho > before_chirho.membership_epoch_chirho,
                "the MEMBERSHIP epoch advances too ({} -> {}); a fix that reverts only the journal \
                 half leaves membership ahead and trips MembershipAheadOfJournalChirho earlier",
                before_chirho.membership_epoch_chirho,
                after_chirho.membership_epoch_chirho
            );
            assert_eq!(
                after_chirho.journal_epoch_chirho, after_chirho.membership_epoch_chirho,
                "both coordinates are rebound to the same fence epoch, which is why reverting one \
                 alone creates the ahead-of condition rather than restoring the prior state"
            );
        },
    );
}

/// A4 of the epoch-wedge brick — REPLAY DISCIPLINE. Rejected → rejected → valid.
///
/// Two properties the single-shot arms cannot show, and both matter for how the defect behaves in
/// the field rather than in one snapshot:
///
/// 1. THE WEDGE IS STABLE, NOT ESCALATING. A second refused append does not advance the epoch
///    again, because the fence token is now cached and a new fence only issues when the term differs
///    or none is held. So the damage is done once, at the first refused append after an open, and
///    repeated bad input does not make it worse. That is worth pinning: "it degrades further on
///    every retry" would be a materially different defect and a different urgency.
///
/// 2. A SUBSEQUENT VALID APPEND DOES NOT CLEAR IT. The divergence is not self-healing — this is what
///    makes it a wedge rather than a transient. Note the valid append itself may still COMMIT here,
///    because this arm exercises the direct append door; what it cannot do is restore alignment,
///    which is the precondition the served path checks first.
///
/// MIGRATION PATH: if assertion 1 fails, the epoch is now climbing per rejection — worse than
/// recorded, and the severity note in the tasklist must be corrected at its own line. If assertion 2
/// fails because alignment is restored by a later valid append, the wedge is self-healing and this
/// whole brick's premise needs re-measuring before any fix.
#[test]
fn repeated_rejections_do_not_escalate_and_a_later_valid_append_does_not_realign_chirho() {
    crate::tests_chirho::with_bound_resident_fixture_chirho(
        "canary-alignment-replay",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho =
                crate::tests_chirho::warm_single_node_elector_chirho(node_chirho, group_chirho);
            let permit_chirho =
                crate::resident_authority_chirho::ResidentLedgerAppendPermitChirho::for_test_chirho(
                );
            let mut resident_chirho =
                crate::resident_authority_chirho::ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("the resident opens");

            let _first_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    crate::tests_chirho::resident_mint_request_chirho(
                        0,
                        "replay-rejected-one-chirho",
                    ),
                )
                .unwrap_err();
            let after_first_chirho = resident_chirho.probe_chirho().unwrap();

            let _second_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    crate::tests_chirho::resident_mint_request_chirho(
                        0,
                        "replay-rejected-two-chirho",
                    ),
                )
                .unwrap_err();
            let after_second_chirho = resident_chirho.probe_chirho().unwrap();

            assert_eq!(
                after_second_chirho.journal_epoch_chirho, after_first_chirho.journal_epoch_chirho,
                "the wedge is STABLE: a second rejection reuses the cached fence and does not \
                 advance the epoch again"
            );
            assert_eq!(
                after_second_chirho.membership_epoch_chirho,
                after_first_chirho.membership_epoch_chirho,
                "membership does not climb per rejection either"
            );
            assert_eq!(
                after_second_chirho.journal_tail_seq_chirho, 0,
                "neither rejection wrote a record"
            );

            // The cut a healthy predecessor would have left, at the PRE-advance epoch. A later valid
            // append must not restore alignment against it.
            let stale_cut_chirho = ShadowCanaryLedgerCutChirho::new_chirho(
                1,
                TAIL_DIGEST_CHIRHO.to_owned(),
                1_700_000_000_000,
                0,
                1,
                group_chirho,
            )
            .expect("the stale cut is well shaped");
            assert!(
                verify_readiness_canary_alignment_chirho(
                    &after_second_chirho,
                    &stale_cut_chirho,
                    group_chirho,
                )
                .is_err(),
                "alignment is refused while wedged"
            );

            let _committed_chirho = resident_chirho
                .append_preactivation_chirho(
                    &permit_chirho,
                    crate::tests_chirho::resident_mint_request_chirho(5, "replay-valid-chirho"),
                )
                .expect("the direct append door still commits a well-formed mint");
            let after_valid_chirho = resident_chirho.probe_chirho().unwrap();
            assert!(
                verify_readiness_canary_alignment_chirho(
                    &after_valid_chirho,
                    &stale_cut_chirho,
                    group_chirho,
                )
                .is_err(),
                "NOT SELF-HEALING: a later valid append does not restore alignment against the cut \
                 recorded before the advance — which is what makes this a wedge and not a transient"
            );
        },
    );
}
