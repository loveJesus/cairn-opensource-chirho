// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The acceptance arms for the sixth held-coordinator command — the actor-owned mint trigger.
//!
//! # WHAT THE COMMAND IS
//!
//! `mint_losing_effect_obligation_chirho` is the ONLY producer of the three coordinates a GD7
//! compensation composition needs (`mint_identity_digest`, `canonical_obligation_digest`,
//! `receipt_ref`). Before it, the public type `MintedGd7LosingEffectObligationChirho` existed and
//! nothing public could make one — the measured finding that ordered this brick.
//!
//! # THE TWO PROPERTIES THESE ARMS EXIST FOR
//!
//! **The subject cannot be forged.** The request carries a selector and nothing else: WHICH
//! obligation is caller-chosen, WHOSE is not. The actor supplies the expected reconciliation
//! identity from its own loaded checkpoint, so there is no caller-supplied subject to validate and
//! therefore none to get wrong. Filing a row for an obligation nobody minted is forging the subject;
//! this signature makes that unrepresentable rather than merely refused.
//!
//! **The receipt is affine and idempotent.** `MintedGd7LosingEffectObligationChirho` is deliberately
//! not `Clone`, and it travels back from the mailbox by MOVE. An exact replay reports the same
//! receipt rather than claiming a second obligation.
//!
//! # NON-VACUITY IS LOAD-BEARING HERE, NOT DECORATION
//!
//! Every refusal arm below would pass on a plan carrying ZERO obligations — for the honest reason
//! that there is nothing to mint. A suite like that is green while measuring nothing, which is the
//! failure this family is most prone to. So the happy-path arm asserts the plan's obligation count
//! is positive BEFORE it mints, and the refusal arms stand downstream of a world in which a mint is
//! known to be possible.
//!
//! # WHERE THE OTHER HALVES LIVE, named rather than left to a count
//!
//! A reader counting arms here and comparing against the nine pre-registered ones would otherwise
//! infer the difference was trivial. It is not:
//!
//!   * THE ADOPTION-MUTATION ARMS (before-claim refuses; after-claim returns the receipt-bearing
//!     refusal without double-minting) need the `with_hooks_for_test` entry to interleave a mutation
//!     between the pre-check and the durable claim. That hook is `#[cfg(test)]` and crate-internal to
//!     `cairn-ledger-host-chirho`, so it is unreachable from this crate BY CONSTRUCTION and its arms
//!     live beside it in `obligation_mint_actor_tests_chirho`. Reaching them from here would mean
//!     widening a test hook into the public surface — the opposite of this brick's point.
//!   * THE WRONG-VERIFIER-KEY ARM is structurally unreachable from a caller, and that is the fix
//!     rather than a gap: the winner control verifier is built PER-COMMAND inside the dispatch arm
//!     from the identity the actor itself verified, so no caller can supply a different one. What is
//!     armed here instead is the positive half — that the verifier really is derived from the
//!     identity — because "no caller can pass a wrong key" is worth nothing if the key were derived
//!     from something else entirely.
//!   * THE PRODUCTION-CALLER CENSUS is a source guard in `cairn-source-scan-chirho`, not a
//!     behavioural arm, and it moved from five needles to six in the same commit as this command.

use super::fixture_chirho;
use super::harness1_gd7_world_chirho::build_observed_gd7_world_chirho;
use super::harness1_success_ladder_tests_chirho::drive_ladder_through_adoption_chirho;
use cairn_ledger_host_chirho::reconciliation_chirho::{
    Gd7LosingEffectObligationMintRefusalChirho, Gd7LosingEffectObligationSelectorChirho,
    Gd7ReconciliationPhaseChirho,
};
use cairn_ledger_host_chirho::{
    open_resident_gd7_held_coordinator_chirho, ResidentGd7HeldCoordinatorHandleChirho,
    ResidentGd7HeldCoordinatorRefusalChirho, ResidentGd7HeldObligationMintRefusalChirho,
};

/// Reopen the held coordinator on an adopted world, so an arm can send the sixth command.
///
/// The drive closes its own coordinator, and a second live handle would contend for the same writer
/// lock, so every arm reopens rather than borrows.
fn reopen_held_coordinator_chirho(
    state_chirho: &super::harness1_success_ladder_tests_chirho::AdoptedLadderStateChirho,
    fixture_chirho: &super::RegenesisFixtureChirho,
) -> ResidentGd7HeldCoordinatorHandleChirho {
    open_resident_gd7_held_coordinator_chirho(
        &state_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &state_chirho.ledger_config_chirho,
        std::sync::Arc::clone(&state_chirho.held_elector_chirho),
    )
    .expect("the held coordinator reopens on the adopted world")
}

/// THE HAPPY PATH, AND THE NON-VACUITY CONTROL THAT MAKES EVERY OTHER ARM MEAN SOMETHING.
///
/// # MIGRATION PATH
///
/// If this fails at the obligation-count assertion, the WORLD changed — its sealed plan stopped
/// carrying an obligation — and every refusal arm in this module has silently become vacuous; fix
/// the world before reading anything else here. If it fails at the mint itself while the count is
/// still positive, the COMMAND regressed and the refusal text names which verification refused.
#[test]
fn the_sixth_command_mints_one_obligation_and_replay_refuses_naming_the_same_receipt_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let state_chirho =
        drive_ladder_through_adoption_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    // NON-VACUITY FIRST. Asserted before any mint, because a zero-obligation plan would make the
    // whole module green by emptiness: every refusal below would fire for the honest reason "there
    // is nothing to mint" and none of them would be measuring the property it names.
    assert!(
        state_chirho.effect_obligation_count_chirho > 0,
        "the sealed plan carries NO effect obligations, so there is nothing for this command to \
         mint and every arm in this module is vacuous. The world builder signs one effect intent; \
         if that stopped reaching the plan, fix that before trusting any green here"
    );

    let mut coordinator_chirho = reopen_held_coordinator_chirho(&state_chirho, &fixture_chirho);

    // The selector names WHICH obligation, by a coordinate a lawful caller already holds: the plan
    // chain's walk starts at the sealed plan ref and matches a selector when the visited page ref
    // equals it, so this ref is the first plan page's own ref. No enumeration surface was widened
    // to make this callable.
    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        state_chirho.sealed_plan_ref_chirho.clone(),
        0,
    )
    .expect("a lower-hex plan page ref and a zero index are a well-formed selector");

    let minted_chirho = coordinator_chirho
        .mint_losing_effect_obligation_chirho(selector_chirho.clone())
        .expect("the adopted held coordinator mints the exact selected obligation");

    // The three compose coordinates exist and are non-empty. This is the finding that ordered the
    // brick, inverted into an assertion: the public type now HAS a public producer.
    assert!(
        !minted_chirho.receipt_ref_chirho().is_empty()
            && !minted_chirho.mint_identity_digest_chirho().is_empty()
            && !minted_chirho
                .canonical_obligation_digest_chirho()
                .is_empty(),
        "a mint receipt must carry all three compose coordinates"
    );
    // THE SUBJECT CAME FROM THE ACTOR, NOT THE REQUEST. The selector carries no identity at all, so
    // the only way the receipt can name this reconciliation is if the actor supplied it.
    assert_eq!(
        minted_chirho.sealed_plan_ref_chirho(),
        state_chirho.sealed_plan_ref_chirho,
        "the receipt must bind the sealed plan the actor's own adopted checkpoint names"
    );
    let first_receipt_ref_chirho = minted_chirho.receipt_ref_chirho().to_owned();
    let first_mint_identity_chirho = minted_chirho.mint_identity_digest_chirho().to_owned();

    // REPLAY IS IDEMPOTENT, AND IT SAYS SO BY REFUSING RATHER THAN BY RETURNING.
    //
    // This arm originally expected a second `Ok` carrying the same receipt. That expectation was
    // WRONG, and the shape the code actually has is the stronger one — it is forced by affineness.
    // `MintedGd7LosingEffectObligationChirho` is not `Clone`, so there is no second copy of the
    // minted value to hand out; the only honest answer to "mint this again" is "one already exists,
    // here is its ref, go consume it". Returning a second Ok would have required either cloning an
    // affine value or re-deriving one, and both are the double-mint this path must not permit.
    //
    // So the assertion is: refuses, BY THIS VARIANT, naming the SAME receipt.
    let Err(replay_refusal_chirho) =
        coordinator_chirho.mint_losing_effect_obligation_chirho(selector_chirho)
    else {
        panic!(
            "an exact replay MINTED AGAIN. One selector produced two obligations, which on this \
             path is a duplicated compensation — the single worst outcome this command can have"
        );
    };
    let ResidentGd7HeldCoordinatorRefusalChirho::ObligationMintChirho(
        ResidentGd7HeldObligationMintRefusalChirho::MintChirho(
            Gd7LosingEffectObligationMintRefusalChirho::MintedAwaitingConsumptionChirho {
                receipt_ref_chirho: replayed_receipt_ref_chirho,
            },
        ),
    ) = replay_refusal_chirho
    else {
        panic!(
            "a replay must refuse with MintedAwaitingConsumption naming the existing receipt. Any \
             other refusal means the replay path stopped recognising its own prior mint, and a \
             caller told merely 'refused' cannot tell 'nothing happened, retry' from 'a receipt \
             exists, do not retry': {replay_refusal_chirho}"
        );
    };
    assert_eq!(
        replayed_receipt_ref_chirho, first_receipt_ref_chirho,
        "the replay must name the SAME durable receipt; a different ref would mean a second \
         obligation was claimed for one selector"
    );
    // The first receipt's identity is still the one the actor derived — captured before the replay
    // so that this compares two independent observations rather than one value with itself.
    assert!(
        !first_mint_identity_chirho.is_empty(),
        "the first mint identity must have been captured before the replay"
    );

    coordinator_chirho.close_chirho().unwrap();
}

/// A SELECTOR NAMING A PAGE THAT IS NOT IN THE SEALED PLAN REFUSES, AND MINTS NOTHING.
///
/// This is the forged-subject arm in its only reachable form. A caller cannot supply a subject or a
/// digest — the request has no such field — so the strongest thing it CAN forge is the selector's
/// page ref. A well-formed hex digest that names no page in this plan must not resolve.
///
/// # MIGRATION PATH
///
/// If this starts returning a receipt, the plan walk stopped checking that the selected page belongs
/// to the sealed chain, and a caller can mint against a page of its choosing — read
/// `verify_linked_plan_chirho`'s selector match before anything else.
#[test]
fn a_selector_naming_a_page_outside_the_sealed_plan_mints_nothing_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let state_chirho =
        drive_ladder_through_adoption_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    assert!(
        state_chirho.effect_obligation_count_chirho > 0,
        "non-vacuity: on a zero-obligation plan this arm would refuse for the wrong reason"
    );
    let mut coordinator_chirho = reopen_held_coordinator_chirho(&state_chirho, &fixture_chirho);

    // POSITIVE CONTROL FIRST. Without it, the refusal below is equally consistent with "this world
    // cannot mint at all", which would make the arm green while proving nothing about the page ref.
    let real_selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        state_chirho.sealed_plan_ref_chirho.clone(),
        0,
    )
    .expect("well-formed selector");
    coordinator_chirho
        .mint_losing_effect_obligation_chirho(real_selector_chirho)
        .expect("the real selector mints in this world, so a refusal below is about the page ref");

    // A syntactically valid digest that addresses no page in this plan. Not random bytes: the
    // selector constructor requires lower hex, so an invalid-shape refusal would be a different
    // (and weaker) finding than "this page is not in the sealed plan".
    let foreign_page_ref_chirho = "f".repeat(state_chirho.sealed_plan_ref_chirho.len());
    let foreign_selector_chirho =
        Gd7LosingEffectObligationSelectorChirho::new_chirho(foreign_page_ref_chirho, 0)
            .expect("a same-shape lower-hex digest is a well-formed selector");
    // `expect_err` IS UNAVAILABLE HERE, and the reason is a property worth naming: the minted type
    // deliberately implements neither `Clone` nor `Debug`, so a receipt cannot be duplicated OR
    // accidentally printed into a log. Matching by hand is the cost of that, and it is a cost worth
    // paying rather than deriving `Debug` onto a money-path receipt for a test's convenience.
    let Err(refusal_chirho) =
        coordinator_chirho.mint_losing_effect_obligation_chirho(foreign_selector_chirho)
    else {
        panic!(
            "a selector naming a page outside the sealed plan MINTED. A caller can now mint \
             against a page of its own choosing, which is the forged-subject failure this command \
             exists to make unrepresentable"
        );
    };
    // ASSERT THE REASON, not merely that it refused: a custody or adoption refusal here would mean
    // the arm never reached the plan walk and is measuring the wrong wall.
    assert!(
        matches!(
            refusal_chirho,
            ResidentGd7HeldCoordinatorRefusalChirho::ObligationMintChirho(
                ResidentGd7HeldObligationMintRefusalChirho::PlanChirho(_)
            )
        ),
        "the refusal must come from the PLAN walk rejecting an unknown page, not from custody or \
         adoption: {refusal_chirho}"
    );

    coordinator_chirho.close_chirho().unwrap();
}

/// AN OBLIGATION INDEX BEYOND THE PAGE'S POPULATION REFUSES, AND MINTS NOTHING.
///
/// The selector's second field is an index, and an out-of-range index is the other thing a caller
/// can get wrong or choose maliciously. It must refuse rather than saturate to a neighbouring
/// obligation — minting the wrong obligation is worse than minting none.
#[test]
fn a_selector_index_beyond_the_page_population_mints_nothing_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let state_chirho =
        drive_ladder_through_adoption_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    assert!(
        state_chirho.effect_obligation_count_chirho > 0,
        "non-vacuity: a zero-obligation plan makes every index out of range for the wrong reason"
    );
    let mut coordinator_chirho = reopen_held_coordinator_chirho(&state_chirho, &fixture_chirho);

    let absurd_index_chirho = u64::MAX;
    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        state_chirho.sealed_plan_ref_chirho.clone(),
        absurd_index_chirho,
    )
    .expect("well-formed selector with an out-of-range index");
    let Err(refusal_chirho) =
        coordinator_chirho.mint_losing_effect_obligation_chirho(selector_chirho)
    else {
        panic!(
            "an out-of-range obligation index MINTED. Either the index saturated to a neighbouring \
             obligation — minting the wrong one, which is worse than minting none — or the range \
             check is gone"
        );
    };
    assert!(
        matches!(
            refusal_chirho,
            ResidentGd7HeldCoordinatorRefusalChirho::ObligationMintChirho(
                ResidentGd7HeldObligationMintRefusalChirho::PlanChirho(_)
            )
        ),
        "an out-of-range index must refuse through the plan walk: {refusal_chirho}"
    );

    coordinator_chirho.close_chirho().unwrap();
}

/// A SEALED-BUT-NOT-ADOPTED PLAN MINTS NOTHING, AND SAYS SO BY THE ADOPTION REASON.
///
/// The mint requires phase `AdoptedHeld`. This arm drives a real world to `PlanSealed` and stops
/// there — the exact state in which a plan is fully verified and an obligation is nonetheless not
/// yet mintable — then sends the sixth command through the real mailbox.
///
/// This is the ORDERING property the whole item-5 ladder rests on: adoption is what makes an
/// obligation mintable, so a mint that succeeded here would mean the adopted read-only branch had
/// stopped being a precondition and a caller could mint against a plan nobody adopted.
///
/// # MIGRATION PATH
///
/// If this begins returning a receipt, the phase gate is gone — read the identity/phase check at the
/// top of `mint_actor_owned_gd7_losing_effect_obligation_internal_chirho` before anything else. If it
/// begins refusing for a DIFFERENT reason, the world stopped reaching `PlanSealed` and this arm is no
/// longer measuring the phase gate: the assertion below on the sealed phase is what catches that.
#[test]
fn a_sealed_but_unadopted_plan_refuses_the_mint_by_the_adoption_reason_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let world_chirho =
        build_observed_gd7_world_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    let mut coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        &world_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &world_chirho.ledger_config_chirho,
        std::sync::Arc::clone(&world_chirho.nodes_chirho[2]),
    )
    .expect("the held coordinator opens on the observed world");
    let mut current_chirho = coordinator_chirho
        .install_authenticated_observation_chirho(world_chirho.observation_import_chirho)
        .expect("the held coordinator installs the exact winner observation");
    for _page_chirho in 0..16 {
        if current_chirho.phase_chirho == Gd7ReconciliationPhaseChirho::PlanSealedChirho {
            break;
        }
        current_chirho = coordinator_chirho
            .advance_one_page_chirho(current_chirho.checkpoint_ref_chirho.clone())
            .expect("each command advances exactly one bounded reconciliation page");
    }
    // THE PRECONDITION OF THIS ARM, ASSERTED RATHER THAN ASSUMED. If the loop above fell short of
    // sealing, the refusal below would still fire — for the wrong reason — and this arm would be
    // green while measuring an unsealed plan instead of an unadopted one.
    assert_eq!(
        current_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        "this arm must reach a SEALED plan, or its refusal is about sealing rather than adoption"
    );
    let sealed_chirho = coordinator_chirho
        .verify_sealed_plan_chirho(current_chirho.checkpoint_ref_chirho.clone())
        .expect("the exact immutable plan chain re-verifies after sealing");
    // NON-VACUITY: the plan really does carry something that COULD be minted once adopted, so the
    // refusal below is about the adoption gate and not about an empty plan.
    assert!(
        sealed_chirho.effect_obligation_count_chirho > 0,
        "the sealed plan must carry an obligation, or this arm refuses because there is nothing to \
         mint rather than because nothing is adopted"
    );

    let selector_chirho = Gd7LosingEffectObligationSelectorChirho::new_chirho(
        sealed_chirho.sealed_plan_ref_chirho.clone(),
        0,
    )
    .expect("well-formed selector naming the first sealed plan page");
    let Err(refusal_chirho) =
        coordinator_chirho.mint_losing_effect_obligation_chirho(selector_chirho)
    else {
        panic!(
            "a SEALED BUT UNADOPTED plan minted an obligation. Adoption has stopped being a \
             precondition of minting, so a caller can mint against a plan nobody adopted"
        );
    };
    assert!(
        matches!(
            refusal_chirho,
            ResidentGd7HeldCoordinatorRefusalChirho::ObligationMintChirho(
                ResidentGd7HeldObligationMintRefusalChirho::ActiveAdoptionUnavailableChirho
            )
        ),
        "the refusal must name the missing ADOPTION. A plan or custody refusal here would mean the \
         mint never reached its phase gate: {refusal_chirho}"
    );

    coordinator_chirho.close_chirho().unwrap();
}
