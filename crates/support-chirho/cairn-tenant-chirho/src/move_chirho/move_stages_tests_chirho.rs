// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the tenant-root move ordering.
//!
//! Two of these are checked EXHAUSTIVELY over every stage rather than sampled, because they are the
//! properties the whole design exists for and a sampled check would pass while a single stage violated
//! them: [`exactly_one_side_may_write_at_every_stage_chirho`] and
//! [`the_signing_key_is_never_in_zero_places_chirho`].

use super::*;

const ALL_STAGES_CHIRHO: [MoveStageChirho; 5] = [
    MoveStageChirho::PreparedChirho,
    MoveStageChirho::SurfacesCarriedChirho,
    MoveStageChirho::CustodyPlacedChirho,
    MoveStageChirho::WriterHandedOffChirho,
    MoveStageChirho::SourceRetiredChirho,
];

#[test]
fn the_whole_sequence_advances_in_order_chirho() {
    // Positive control: every refusal below would pass against a model that refused every advance.
    let mut stage_chirho = None;
    for next_chirho in ALL_STAGES_CHIRHO {
        let applied_chirho =
            advance_stage_chirho(stage_chirho, next_chirho).expect("each step in order applies");
        assert_eq!(applied_chirho, next_chirho);
        stage_chirho = Some(applied_chirho);
    }
}

#[test]
fn prepared_is_the_only_stage_that_can_begin_a_move_chirho() {
    assert_eq!(
        advance_stage_chirho(None, MoveStageChirho::PreparedChirho).expect("prepared begins"),
        MoveStageChirho::PreparedChirho
    );
    for offered_chirho in [
        MoveStageChirho::SurfacesCarriedChirho,
        MoveStageChirho::CustodyPlacedChirho,
        MoveStageChirho::WriterHandedOffChirho,
        MoveStageChirho::SourceRetiredChirho,
    ] {
        assert_eq!(
            advance_stage_chirho(None, offered_chirho).expect_err("cannot self-establish"),
            MoveAdvanceRefusalChirho::FirstStageMustBePreparedChirho { offered_chirho }
        );
    }
}

#[test]
fn exactly_one_side_may_write_at_every_stage_chirho() {
    // EXHAUSTIVE. `writer_at_chirho` returns one value by construction, so what this really pins is
    // WHERE the transition happens: the writer must be the source through custody placement and the
    // target from handoff onward. A model that moved the writer one stage early would put a writer on
    // a root that cannot sign; one stage late would leave the source writing after it was retired.
    for stage_chirho in ALL_STAGES_CHIRHO {
        let expected_chirho = match stage_chirho {
            MoveStageChirho::PreparedChirho
            | MoveStageChirho::SurfacesCarriedChirho
            | MoveStageChirho::CustodyPlacedChirho => MoveWriterChirho::SourceChirho,
            MoveStageChirho::WriterHandedOffChirho | MoveStageChirho::SourceRetiredChirho => {
                MoveWriterChirho::TargetChirho
            }
        };
        assert_eq!(
            writer_at_chirho(stage_chirho),
            expected_chirho,
            "writer at {stage_chirho:?}"
        );
    }
}

#[test]
fn the_signing_key_is_never_in_zero_places_chirho() {
    // EXHAUSTIVE, and this is what justifies the deliberate two-copy window. A move that never had two
    // copies had a moment with zero, which is an unsignable root — data loss, not a security win.
    for stage_chirho in ALL_STAGES_CHIRHO {
        assert!(
            source_holds_key_at_chirho(stage_chirho) || target_holds_key_at_chirho(stage_chirho),
            "no key anywhere at {stage_chirho:?}"
        );
    }
    // And the writer always has one: a writer that cannot sign is the other way to lose a root.
    for stage_chirho in ALL_STAGES_CHIRHO {
        let has_key_chirho = match writer_at_chirho(stage_chirho) {
            MoveWriterChirho::SourceChirho => source_holds_key_at_chirho(stage_chirho),
            MoveWriterChirho::TargetChirho => target_holds_key_at_chirho(stage_chirho),
        };
        assert!(
            has_key_chirho,
            "the writer at {stage_chirho:?} holds no key"
        );
    }
}

#[test]
fn handing_the_writer_over_before_custody_is_refused_by_its_own_name_chirho() {
    // Its own identity, not a generic wrong-stage: this mistake and the next are opposites with
    // opposite fixes, and telling an operator "wrong stage" would send them the wrong way.
    assert_eq!(
        advance_stage_chirho(
            Some(MoveStageChirho::SurfacesCarriedChirho),
            MoveStageChirho::WriterHandedOffChirho
        )
        .expect_err("handoff before custody"),
        MoveAdvanceRefusalChirho::HandoffBeforeCustodyChirho
    );
}

#[test]
fn retiring_the_source_before_handoff_is_refused_by_its_own_name_chirho() {
    // The opposite mistake: erase first and a crash leaves no key anywhere.
    assert_eq!(
        advance_stage_chirho(
            Some(MoveStageChirho::CustodyPlacedChirho),
            MoveStageChirho::SourceRetiredChirho
        )
        .expect_err("retirement before handoff"),
        MoveAdvanceRefusalChirho::RetirementBeforeHandoffChirho
    );
}

#[test]
fn skipping_a_stage_is_refused_chirho() {
    assert_eq!(
        advance_stage_chirho(
            Some(MoveStageChirho::PreparedChirho),
            MoveStageChirho::CustodyPlacedChirho
        )
        .expect_err("skipping"),
        MoveAdvanceRefusalChirho::NotTheNextStageChirho {
            current_chirho: MoveStageChirho::PreparedChirho,
            offered_chirho: MoveStageChirho::CustodyPlacedChirho,
        }
    );
}

#[test]
fn re_offering_the_current_stage_is_a_no_op_so_a_resumed_move_is_safe_chirho() {
    // A resumed move cannot know whether its last write landed, so it re-drives. Erroring here would
    // tempt a caller to retry DIFFERENTLY, which is how a resume turns into a skip.
    for stage_chirho in ALL_STAGES_CHIRHO {
        assert_eq!(
            advance_stage_chirho(Some(stage_chirho), stage_chirho).expect("re-driving is safe"),
            stage_chirho
        );
    }
}

#[test]
fn a_finished_move_accepts_no_further_stage_chirho() {
    for stage_chirho in ALL_STAGES_CHIRHO {
        if stage_chirho == MoveStageChirho::SourceRetiredChirho {
            continue;
        }
        assert_eq!(
            advance_stage_chirho(Some(MoveStageChirho::SourceRetiredChirho), stage_chirho)
                .expect_err("a completed move is not a place to add stages"),
            MoveAdvanceRefusalChirho::AlreadyRetiredChirho
        );
    }
}

#[test]
fn going_backwards_is_refused_chirho() {
    // Not merely "not the next stage" in spirit: a backwards step would un-hand-off a writer, and the
    // arm exists so that a future successor table cannot quietly allow it.
    assert!(advance_stage_chirho(
        Some(MoveStageChirho::WriterHandedOffChirho),
        MoveStageChirho::CustodyPlacedChirho
    )
    .is_err());
}

#[test]
fn the_move_stays_reversible_until_retirement_chirho() {
    // ADDED AFTER A SURVIVING MUTATION, and the mutation is why this arm exists. Making the source
    // erase its key AT handoff killed nothing: the target holds the key by then, so "never zero
    // places" still held and "the writer has a key" still held. Both arms were true and neither was
    // measuring the property the module's own header claims —
    //
    //   "the key outlives the authority so that a crash during handoff leaves a recoverable move
    //    rather than an unsignable root"
    //
    // — which is about REVERSIBILITY, not about zero keys. A prose claim no arm pinned, in my own
    // module. So: the source must still be able to sign after the writer has moved, and stop only at
    // retirement. That is what makes retirement the point of no return rather than handoff.
    assert!(
        source_holds_key_at_chirho(MoveStageChirho::WriterHandedOffChirho),
        "after handoff the source must still hold its key, or the move cannot be reversed"
    );
    assert!(
        !source_holds_key_at_chirho(MoveStageChirho::SourceRetiredChirho),
        "and retirement is exactly where that stops -- otherwise erasure never happened"
    );
    // Stated as the boundary rather than two points: retirement is the ONLY stage without a source key.
    for stage_chirho in ALL_STAGES_CHIRHO {
        assert_eq!(
            source_holds_key_at_chirho(stage_chirho),
            stage_chirho != MoveStageChirho::SourceRetiredChirho,
            "source key at {stage_chirho:?}"
        );
    }
}
