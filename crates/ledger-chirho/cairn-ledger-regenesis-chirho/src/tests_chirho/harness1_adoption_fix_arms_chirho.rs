// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The acceptance arms for the barrier-ref adoption plan resolution.
//!
//! # WHAT THE FIX WAS, so these arms can be read without opening the production file
//!
//! `Gd7WinnerHandoffStoreChirho::load_accepted_plan_chirho` resolved the held-signed sealed plan
//! through a fixed reconciliation group-HEAD read on the WINNER's own storage. That head is written
//! only by the held reconciliation store on the HELD root, so on a genuine two-root deployment —
//! the only deployment the geo driver exists for — the read found nothing and the winner's whole
//! adoption-evidence surface refused before it could stage anything. It now resolves by the ACCEPTED
//! BARRIER's own checkpoint ref through the content-addressed loader, and the head read is gone
//! rather than guarded.
//!
//! # WHY THESE LIVE IN THEIR OWN MODULE
//!
//! They were written at the tail of `harness1_success_ladder_tests_chirho`, because each one needs
//! a real two-root world carrying a durable ACCEPTED barrier and a committed adoption. That file
//! crossed the 1500-line cap, and the recorded response was the real refactor rather than trimming
//! comments to get under a number: the ladder's drive became
//! `drive_ladder_through_adoption_chirho`, and these arms now stand on it as a second consumer.
//! The arms are byte-identical to the ones that were proven; only their home changed.
//!
//! # WHAT IS HERE AND WHAT IS NOT
//!
//! Arms 2, 7 and arm 1's PREDICATE HALF. Arm 4 is not here and belongs where it is — it must run
//! mid-drive, before the first successful preparation, because `prepare_chirho` memoises its
//! manifest once it reaches Ready and any perturbation arm run afterwards is green regardless of
//! what is on disk. Arm 6 is a source census in `cairn-source-scan-chirho`. Arm 5 is structurally
//! unbuildable and discharged by arm 6. Arm 1's APPEND half is here too, in its own test with its
//! own pre-handoff world — it cannot share the adopted one, because once the winner's handoff is
//! Accepted its actor refuses to reopen at all.
//!
//! # ARM 3 SPLITS IN TWO, and only half of it is discharged
//!
//! Arm 3 asked for a foreign OR stale valid checkpoint to refuse by a distinct reason with no head
//! fallback. Measured, those are different questions:
//!
//!   * THE FOREIGN HALF IS UNREPRESENTABLE, and content addressing is why. The loader derives its
//!     path from the barrier's ref and then checks `digest(bytes) == ref`. A checkpoint from
//!     another group, node or term hashes differently, so it cannot occupy that address; writing it
//!     there makes the digest check fire, which is arm 4 — already built and mutation-proven to
//!     refuse `CheckpointReferenceMismatchChirho` BY VARIANT. Discharged.
//!   * THE STALE HALF IS PARTLY DISCHARGED — see STALE-BARRIER-1a at the bottom of this file, and
//!     read its MEASURED SCOPE before counting it. The half splits again once measured: the case
//!     where the head names a LATER PHASE OF THE SAME reconciliation is now armed; the case where a
//!     genuinely SECOND reconciliation identity exists is not, and its price is recorded at that
//!     arm rather than guessed. Building the second remains a brick, not a rider.
//!
//! That second half matters more than its size suggests: it is EXACTLY the property the fix gave
//! up. Resolving by the barrier's ref traded away the head's current-active selection, and the
//! honest question that leaves is "should an accepted barrier still resolve its own plan once the
//! head names something newer?" The answer this code gives is YES — the barrier decided when it
//! accepted. Named here rather than in a report, because a reader counting arms would otherwise see
//! six of seven and infer the seventh was trivial.

use super::harness1_gd7_world_chirho::{
    build_observed_gd7_world_chirho, try_append_resident_record_chirho,
};
use super::harness1_success_ladder_tests_chirho::drive_ladder_through_adoption_chirho;
use super::{drive_ticks_chirho, fixture_chirho};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_group_has_any_active_hold_chirho,
    gd7_reconciliation_group_head_path_chirho,
    load_authenticated_active_gd7_reconciliation_for_group_chirho, ExistingNodeGd7SignerChirho,
    Gd7ReconciliationPhaseChirho, Gd7WinnerHandoffStoreChirho, PinnedNodeGd7VerifierChirho,
};
use cairn_ledger_host_chirho::{open_resident_gd7_held_coordinator_chirho, FsLedgerStorageChirho};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use std::sync::Arc;

/// The adoption fix's acceptance arms, over a world driven to a committed adoption.
///
/// # MIGRATION PATH
///
/// If these start failing while the ladder itself stays green, the fix regressed rather than the
/// ladder: read `load_accepted_plan_chirho` before touching anything here. If BOTH fail, the world
/// changed and `harness1_gd7_world_chirho` is where to start.
#[test]
fn adoption_fix_arms_prove_the_barrier_ref_resolution_costs_no_hold_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let state_chirho =
        drive_ladder_through_adoption_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    //
    // These two are pure storage reads and need no actor, which is fortunate: the winner actor
    // CANNOT BE REOPENED while its own handoff is Accepted. Measured while building these arms —
    // the opener refuses startup with "resident ledger mutation is frozen by an active GD7 winner
    // handoff". That is the append fence being DURABLE ACROSS RESTART rather than merely
    // in-memory, and it is why the tamper arm above runs on the live actor before the manifest is
    // ever memoised, instead of on a fresh one afterwards.
    let winner_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.winner_source_root_chirho)
            .expect("the winner root's own storage opens");
    let group_head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(&state_chirho.group_digest_chirho)
            .expect("derive the fixed reconciliation group-head path");

    // ARM 2 — THE HEAD IS ABSENT ON THE WINNER ROOT, MEASURED RATHER THAN ASSUMED. This is the
    // whole premise of the fix: the read that used to sit in `load_accepted_plan_chirho` had
    // nothing to find here. Everything above passed while this was true, so rung 5 succeeded
    // through the barrier-ref path and could not have succeeded through a head.
    assert!(
        winner_storage_chirho
            .read_all_chirho(&group_head_path_chirho)
            .expect("reading an absent head is not an error")
            .is_none(),
        "the winner root must have NO reconciliation group head; if one appeared, something is \
         writing held-side reconciliation state onto the winner root and the fix's premise is gone"
    );
    // POSITIVE CONTROL for that absence, because "not found" is equally consistent with "I asked
    // at the wrong path". The SAME path on the held root must find the real head.
    assert!(
        held_storage_chirho
            .read_all_chirho(&group_head_path_chirho)
            .expect("reading the held head is not an error")
            .is_some(),
        "the same path must resolve a head on the HELD root, or the absence above is an artifact \
         of a wrong path rather than a fact about the winner root"
    );

    // ARM 7 — THE ADOPTION READ CREATED NO HOLD ON THE WINNER ROOT. The append funnel treats a
    // group head as an ACTIVE HOLD by bare presence, never parsed, so replicating one would strand
    // the winner's own ordinary writes. This asserts through the funnel's OWN predicate rather
    // than through the path check above, so it is a second instrument on the same property.
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &winner_storage_chirho,
            &state_chirho.group_digest_chirho
        )
        .expect("the hold predicate answers on the winner root"),
        "resolving the adoption plan by ref must not create an active hold on the winner root — \
         that is precisely the outage the rejected head-replication alternative would have caused"
    );

    // ARM 1, PREDICATE HALF — WHY REPLICATING THE HEAD WAS REJECTED, MADE EXECUTABLE. The design
    // alternative to this fix was to copy the held root's group head onto the winner root so the
    // old head read would find something. This plants exactly that — the REAL held-signed head
    // bytes, byte-identical, no forgery — and asks the append funnel's own predicate what it
    // thinks. It flips to TRUE: a replicated head IS an active hold, because the predicate is an
    // `object_len` PRESENCE test and never parses the bytes. The funnel consults it before every
    // ordinary mutation and answers `Gd7ReconciliationHoldActiveChirho`, so the winner would have
    // stranded its own ordinary writes to make a read work. Arm 7 above is the before; this is the
    // after; removing the plant restores it, which is what makes the flip attributable to the head
    // rather than to anything else this test did.
    //
    // MEASURED SCOPE, and it is narrower than the pre-registered arm: this proves the PREDICATE,
    // not the append refusal. Driving an ordinary winner append to its refusal needs a world whose
    // handoff has not yet been Accepted — the winner actor cannot even reopen once it has — so the
    // append half belongs to its own test and is NOT claimed here. Stated at the arm rather than
    // only in a report, because a reader who takes this for the full arm 1 would overcount it.
    let planted_head_bytes_chirho = held_storage_chirho
        .read_all_chirho(&group_head_path_chirho)
        .expect("read the held root's real signed group head")
        .expect("the held root has a group head to replicate");
    winner_storage_chirho
        .atomic_write_chirho(&group_head_path_chirho, &planted_head_bytes_chirho)
        .expect("plant the byte-identical held-signed head on the winner root");
    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(
            &winner_storage_chirho,
            &state_chirho.group_digest_chirho
        )
        .expect("the hold predicate answers with the head planted"),
        "a replicated group head MUST read as an active hold — if this is false the predicate \
         stopped being presence-only, and the whole reason head replication was rejected has \
         changed. That is a design-relevant fact, not a test to loosen"
    );
    winner_storage_chirho
        .remove_chirho(&group_head_path_chirho)
        .expect("remove the planted head");
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &winner_storage_chirho,
            &state_chirho.group_digest_chirho
        )
        .expect("the hold predicate answers after the plant is removed"),
        "removing the plant must restore the winner root to no-hold, or the flip above is not \
         attributable to the planted head"
    );
}

/// ARM 1, APPEND HALF — a replicated group head really does strand the winner's ordinary writes.
///
/// # WHY THIS NEEDS ITS OWN WORLD
///
/// The predicate half lives on the adopted world, but the APPEND half cannot: once the winner's
/// handoff reaches `AcceptedChirho` its own actor refuses to even reopen ("resident ledger mutation
/// is frozen by an active GD7 winner handoff" — the append fence is durable across restart, not
/// merely in memory). So this arm builds a world and stops BEFORE the handoff, where an ordinary
/// winner append is still lawful and its refusal can be attributed to the plant alone.
///
/// # WHAT IT PROVES
///
/// That replicating the held root's group head onto the winner root — the design alternative to
/// resolving the adoption plan by its accepted barrier's ref — costs the winner its own write path.
/// The funnel's first barrier tests the group head for PRESENCE ONLY, never parsing it, so bytes
/// that mean "the held node is reconciling" read on the winner root as "this node is held". The
/// plant is byte-identical real held-signed head bytes; nothing here is forged.
///
/// # THE TWO BARRIERS, AND WHY THE ARM NAMES BOTH
///
/// `Gd7ReconciliationHoldActiveChirho` (head present) and `Gd7OrdinaryWritesWithheldChirho`
/// (ordinary-write hold) sit four lines apart in the funnel and both refuse an ordinary append. An
/// arm that only asserted "it refused" would be satisfied by either and would pin neither, so this
/// asserts the first is present AND the second is absent.
///
/// MEASURED SCOPE, stated because it is weaker than it looks: the resident wire FLATTENS its typed
/// refusal into `EffectCommitJournalPortErrorChirho::RefusedChirho { detail_chirho: String }`, so
/// the discrimination is on the refusal's own message text rather than on a variant. That is the
/// granularity this seam offers today; a dedicated variant would be the fix when the surface is
/// next touched, and it is the same name-flattening shape already recorded as the F4 residual.
#[test]
fn arm_one_a_replicated_head_strands_the_winners_own_ordinary_writes_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let world_chirho =
        build_observed_gd7_world_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);
    drive_ticks_chirho(&world_chirho.nodes_chirho, 0, 10);

    // The salt is a HEX character, not an arbitrary one: it is repeated 64 times to form the
    // intent's `request_ref_chirho` digest, so a non-hex salt refuses at signing with
    // `InvalidCoordinateChirho`. The world itself uses '1' and '8'; these three are distinct from
    // those and from each other so the three appends are three different intents.
    //
    // POSITIVE CONTROL FIRST. Without it, a refusal after the plant is equally consistent with the
    // winner having been unable to append in this world at all — which would make the arm green for
    // a reason that has nothing to do with the head.
    try_append_resident_record_chirho(
        &world_chirho.winner_source_root_chirho,
        &winner_fixture_chirho,
        &world_chirho.winner_ledger_config_chirho,
        &world_chirho.winner_signers_chirho,
        &world_chirho.nodes_chirho[0],
        '2',
    )
    .expect("the winner's ordinary append is lawful in this world before anything is planted");

    // The head to plant has to EXIST first, and a fresh world has none: the reconciliation group
    // head is minted by the held coordinator's own first command. So the held side installs its
    // authenticated observation — one real mailbox command, the ladder's rung-1 first step — and
    // the arm then replicates the head THAT produced. Plants must be real signed artifacts; the
    // alternative is writing bytes of my own into a presence-checked path, which would prove that
    // the funnel notices a file rather than that it notices a HEAD.
    let mut held_coordinator_chirho = open_resident_gd7_held_coordinator_chirho(
        &world_chirho.canonical_root_chirho,
        &fixture_chirho.config_path_chirho,
        &world_chirho.ledger_config_chirho,
        Arc::clone(&world_chirho.nodes_chirho[2]),
    )
    .expect("the held coordinator opens on the observed world");
    held_coordinator_chirho
        .install_authenticated_observation_chirho(world_chirho.observation_import_chirho)
        .expect("the held coordinator installs the exact winner observation");
    held_coordinator_chirho.close_chirho().unwrap();

    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&world_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    let winner_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&world_chirho.winner_source_root_chirho)
            .expect("the winner root's own storage opens");
    let group_head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(&world_chirho.group_digest_chirho)
            .expect("derive the fixed reconciliation group-head path");
    let planted_head_bytes_chirho = held_storage_chirho
        .read_all_chirho(&group_head_path_chirho)
        .expect("read the held root's real signed group head")
        .expect("the held root has a group head to replicate");
    winner_storage_chirho
        .atomic_write_chirho(&group_head_path_chirho, &planted_head_bytes_chirho)
        .expect("plant the byte-identical held-signed head on the winner root");

    let refusal_chirho = try_append_resident_record_chirho(
        &world_chirho.winner_source_root_chirho,
        &winner_fixture_chirho,
        &world_chirho.winner_ledger_config_chirho,
        &world_chirho.winner_signers_chirho,
        &world_chirho.nodes_chirho[0],
        '3',
    )
    .expect_err("the same append must refuse once a group head sits on the winner root");
    let refusal_text_chirho = refusal_chirho.to_string();
    assert!(
        refusal_text_chirho.contains("held by active GD7 reconciliation"),
        "the refusal must be the ACTIVE-HOLD barrier — the one a replicated head trips. Got: \
         {refusal_text_chirho}"
    );
    assert!(
        !refusal_text_chirho.contains("ordinary writes are withheld"),
        "the refusal must NOT be the ordinary-write hold. The two barriers sit four lines apart in \
         the funnel and both refuse an ordinary append; an arm that cannot tell them apart pins \
         neither, and this plant is about the FIRST one. Got: {refusal_text_chirho}"
    );

    // Removing the plant restores the winner's write path, which is what makes the refusal
    // attributable to the head rather than to anything the failed attempt left behind.
    winner_storage_chirho
        .remove_chirho(&group_head_path_chirho)
        .expect("remove the planted head");
    try_append_resident_record_chirho(
        &world_chirho.winner_source_root_chirho,
        &winner_fixture_chirho,
        &world_chirho.winner_ledger_config_chirho,
        &world_chirho.winner_signers_chirho,
        &world_chirho.nodes_chirho[0],
        '4',
    )
    .expect("removing the plant must give the winner its own write path back");
}

/// STALE-BARRIER-1a — an ACCEPTED barrier outranks a group head that has moved PAST its plan.
///
/// # THE PROPERTY, and why it stood unarmed
///
/// `load_accepted_plan_chirho` used to resolve the sealed plan through a group-HEAD read and then
/// check the head-selected ref against the barrier's. The fix resolves BY THE BARRIER'S OWN ref and
/// deletes the head read outright, which trades away the head's current-active selection. The honest
/// question that leaves is "should an accepted barrier still resolve its own plan once the head
/// names something newer?", and the answer this code gives is YES — the barrier decided when it
/// accepted. The module header above recorded that answer as UNARMED. This is the arm.
///
/// # WHY THE PLANT IS THE WHOLE ARM, and why without it this would be TRUE BY CONSTRUCTION
///
/// Arm 2 measured that the winner root carries NO reconciliation group head. So on the world as it
/// stands there is nothing else `load_accepted_plan_chirho` COULD have returned, and an arm that
/// merely asserted "it returned the barrier's plan" would be true by the SHAPE OF THE WORLD rather
/// than by any decision the code made — a green that measures nothing. So this arm puts the stale
/// alternative exactly where the deleted read looked: the held root's real, held-signed bytes,
/// byte-identical and unforged, planted on the winner root — the head at the group-head path, where
/// it names the ADOPTED checkpoint rather than the sealed plan. Then the resolution is asked which
/// one it follows.
///
/// TWO OBJECTS ARE PLANTED, NOT ONE, and the second is here because the first control caught that
/// a head alone is INERT. Arm 1's predicate half plants only the head, which is enough for a
/// PRESENCE test; this arm needs the head to RESOLVE, and a head whose checkpoint object is absent
/// refuses `MissingReferencedCheckpointChirho`. So the adopted checkpoint is planted too, at the
/// address of its own digest — which is why copying it forges nothing: a content-addressed object
/// at the address of its own digest IS that object, and this is the replication a head-following
/// design would actually have performed.
///
/// The POSITIVE CONTROL is what makes the plant count as an alternative rather than as noise: the
/// planted pair is proven fully resolvable ON THE WINNER ROOT through the very loader the old code
/// called, returning the adopted checkpoint. Without it, "the barrier won" would be equally
/// consistent with "the plant was unreadable and every path refused" — the same green. That control
/// is not decorative; it is what went red and forced the second object.
///
/// # MEASURED SCOPE — NARROWER THAN ARM 3'S STALE HALF, stated so it cannot be overcounted
///
/// This is the head-moved-PAST-its-plan case: the head names a LATER PHASE OF THE SAME
/// reconciliation identity. A genuinely SECOND reconciliation is a different identity and is NOT
/// built here. Its price is measured rather than guessed: one consistency group has exactly ONE
/// reconciliation head, and `parse_and_verify_head_chirho` refuses `WrongIdentityChirho` when the
/// stored head's identity digest is not the opening store's — so a second reconciliation cannot
/// install while the first head stands. It needs the D4 release to REMOVE the head
/// (`sink_term_revoke_chirho`) and a new winner term to mint a new identity. That world is a brick.
///
/// What this arm does cover that the narrower reading misses: the code path under test does not
/// branch on WHY the head disagrees. It reads the head or it does not, and this proves it does not.
///
/// # MIGRATION PATH
///
/// If this fails while the ladder stays green, read `load_accepted_plan_chirho` first — a head read
/// re-entering it is exactly what this catches. If the returned plan is `AdoptedHeldChirho`, the
/// resolution followed the HEAD. If it REFUSES, a head read returned and mismatched against the
/// barrier, which is the pre-fix behaviour. If the PLANT's own control fails instead, the world
/// changed rather than the fix: start at `harness1_gd7_world_chirho`.
#[test]
fn an_accepted_barrier_outranks_a_head_that_moved_past_its_plan_chirho() {
    let mut fixture_chirho = fixture_chirho();
    let mut winner_fixture_chirho = super::fixture_chirho();
    let state_chirho =
        drive_ladder_through_adoption_chirho(&mut fixture_chirho, &mut winner_fixture_chirho);

    // A COORDINATE TRAP, RECORDED BECAUSE IT COST A CYCLE AND ITS OWN GUARD CAUGHT IT.
    // `AdoptedLadderStateChirho::sealed_plan_ref_chirho` is the first PLAN PAGE's ref, as its own
    // doc comment says — NOT the PlanSealed reconciliation CHECKPOINT's ref, which is what the
    // barrier names and what this arm is about. A first draft used it here and the predecessor
    // guard below went red naming two different digests, which is the guard working. The sealed
    // checkpoint is therefore identified below through TWO artifacts that must agree, rather than
    // through any ref this test carried in from the drive.
    let held_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.canonical_root_chirho)
            .expect("the held root's own storage opens");
    let winner_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&state_chirho.winner_source_root_chirho)
            .expect("the winner root's own storage opens");
    let group_head_path_chirho =
        gd7_reconciliation_group_head_path_chirho(&state_chirho.group_digest_chirho)
            .expect("derive the fixed reconciliation group-head path");
    let held_verifier_chirho =
        PinnedNodeGd7VerifierChirho::new_chirho(state_chirho.held_node_chirho.clone())
            .expect("the winner side pins the held node by id, holding no held signing power");

    // NON-VACUITY 2 — the HELD head really names the ADOPTED checkpoint, measured through the same
    // loader the deleted read used rather than by trusting the drive's own return value back at it.
    let held_active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        &held_storage_chirho,
        &held_verifier_chirho,
        &state_chirho.group_digest_chirho,
    )
    .expect("the held root's active reconciliation loads")
    .expect("the held root has an active reconciliation after adoption");
    assert_eq!(
        held_active_chirho.checkpoint_ref_chirho, state_chirho.adopted_checkpoint_ref_chirho,
        "the held head must name the ADOPTED checkpoint — that is what makes it 'newer than the \
         plan' rather than merely 'a head'"
    );
    assert_eq!(
        held_active_chirho
            .checkpoint_chirho
            .state_chirho
            .phase_chirho,
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho,
        "the head's checkpoint must carry a phase DISTINCT from PlanSealed, because that phase is \
         the by-value discriminator every assertion below leans on"
    );
    // THE SEALED CHECKPOINT'S OWN COORDINATE, taken from the HEAD'S RECORD OF ITS PREDECESSOR.
    // This is the M4 two-coordinate contract read back off disk: the adopted cut A authenticates
    // the sealed cut S as its predecessor. Nothing here is supplied by the test.
    let expected_plan_ref_chirho = held_active_chirho
        .checkpoint_chirho
        .state_chirho
        .previous_checkpoint_ref_chirho
        .clone()
        .expect("the adopted checkpoint must record the sealed cut as its predecessor");
    // NON-VACUITY 3 — the head names something OTHER than the plan. If these were equal there
    // would be no stale alternative at all and every assertion below would be about nothing.
    assert_ne!(
        expected_plan_ref_chirho, state_chirho.adopted_checkpoint_ref_chirho,
        "adoption must advance the active checkpoint PAST the sealed cut, or this arm has no stale \
         alternative to offer the resolution and its green would mean nothing"
    );

    // The winner-side store, opened on the winner root's OWN key custody — never a synthetic signer.
    let winner_signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
        &state_chirho.winner_source_root_chirho,
        &state_chirho.winner_node_chirho,
    )
    .expect("the winner root's own key custody opens as its GD7 checkpoint signer");
    let handoff_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &winner_storage_chirho,
        &winner_signer_chirho,
        state_chirho.group_digest_chirho.clone(),
        state_chirho.winner_node_chirho.0.clone(),
    )
    .expect("the winner handoff store opens on the winner's own group and node");

    // BASELINE — with NO head on the winner root (arm 2's measured state) the barrier resolves its
    // own plan. Recorded first so the plant's effect is a COMPARISON rather than a single reading.
    let (_, baseline_plan_chirho) = handoff_store_chirho
        .load_accepted_plan_chirho(&held_verifier_chirho)
        .expect("the accepted barrier resolves its own plan with no head present");
    assert_eq!(
        baseline_plan_chirho.state_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        "the baseline resolution must be the SEALED PLAN"
    );

    // THE PLANT — TWO OBJECTS, and the second one is here because the first control caught that one
    // alone is INERT. A head names a checkpoint by ref; planting only the head gave the winner root
    // a head whose checkpoint was absent, and the loader refused `MissingReferencedCheckpointChirho`
    // — so "the barrier won" would have been indistinguishable from "there was nothing to lose to".
    // Both objects are the held root's own real signed bytes, byte-identical, and the checkpoint
    // goes to ITS OWN content-addressed address, so nothing here is forged: a content-addressed
    // object copied to the address of its own digest is that object, which is what makes this the
    // replication a head-following design would actually have performed.
    let planted_head_bytes_chirho = held_storage_chirho
        .read_all_chirho(&group_head_path_chirho)
        .expect("read the held root's real signed group head")
        .expect("the held root has a group head to replicate");
    let adopted_checkpoint_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&state_chirho.adopted_checkpoint_ref_chirho)
            .expect("derive the adopted checkpoint's content-addressed path");
    let planted_checkpoint_bytes_chirho = held_storage_chirho
        .read_all_chirho(&adopted_checkpoint_path_chirho)
        .expect("read the held root's real adopted checkpoint")
        .expect("the held root holds the adopted checkpoint object");
    winner_storage_chirho
        .atomic_write_chirho(
            &adopted_checkpoint_path_chirho,
            &planted_checkpoint_bytes_chirho,
        )
        .expect("plant the byte-identical adopted checkpoint at its own content-addressed address");
    winner_storage_chirho
        .atomic_write_chirho(&group_head_path_chirho, &planted_head_bytes_chirho)
        .expect("plant the byte-identical held-signed head on the winner root");

    // POSITIVE CONTROL FOR THE PLANT — it is not noise. On the WINNER root, through the very loader
    // the deleted read called, the planted head resolves a fully authenticated checkpoint, and that
    // checkpoint is the ADOPTED one. So the stale alternative is genuinely available at the exact
    // address; if the resolution below still returns the plan, that is a decision and not an
    // accident of what happened to be readable.
    let winner_visible_active_chirho =
        load_authenticated_active_gd7_reconciliation_for_group_chirho(
            &winner_storage_chirho,
            &held_verifier_chirho,
            &state_chirho.group_digest_chirho,
        )
        .expect("the planted head must LOAD on the winner root")
        .expect("the planted head must RESOLVE to a checkpoint on the winner root");
    assert_eq!(
        winner_visible_active_chirho.checkpoint_ref_chirho, state_chirho.adopted_checkpoint_ref_chirho,
        "the plant must offer the ADOPTED checkpoint on the winner root. If this fails the plant is \
         inert and the arm below proves nothing about which coordinate the code chose"
    );
    // And the funnel agrees a head is present, which is the other half of why replicating it was
    // rejected as a design — recorded here because this arm plants one deliberately.
    assert!(
        gd7_reconciliation_group_has_any_active_hold_chirho(
            &winner_storage_chirho,
            &state_chirho.group_digest_chirho
        )
        .expect("the hold predicate answers with the head planted"),
        "a planted head reads as an active hold; this arm accepts that cost deliberately and \
         removes the plant below"
    );

    // THE ARM. Two authentic, fully resolvable coordinates are now reachable from this store's own
    // storage — the barrier's PlanSealed plan and the head's newer AdoptedHeld checkpoint — and the
    // resolution must take the BARRIER'S.
    let (accepted_barrier_chirho, resolved_plan_chirho) = handoff_store_chirho
        .load_accepted_plan_chirho(&held_verifier_chirho)
        .expect(
            "the accepted barrier must still resolve its own plan while a NEWER head stands on \
             this very storage; a refusal here is the pre-fix head read returning and mismatching",
        );
    assert_eq!(
        resolved_plan_chirho.state_chirho.phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho,
        "the resolution must return the SEALED PLAN, not the head's newer AdoptedHeld checkpoint. \
         Got phase {:?} at transition_seq {}",
        resolved_plan_chirho.state_chirho.phase_chirho,
        resolved_plan_chirho.state_chirho.transition_seq_chirho
    );
    // THE TWO ARTIFACTS MUST AGREE, and that agreement is what identifies 'the plan' by value here.
    // The barrier's own ref (winner side, durable since accept) and the head's record of its
    // predecessor (held side, written by adoption) are independent artifacts written by different
    // nodes at different times; if they name the same checkpoint, then the coordinate the
    // resolution bound to is the sealed cut and not something this test chose.
    assert_eq!(
        accepted_barrier_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho
            .reconciliation_checkpoint_ref_chirho,
        expected_plan_ref_chirho,
        "the coordinate the resolution bound to must be the BARRIER'S OWN ref, and it must equal \
         the sealed cut the adopted checkpoint names as its predecessor"
    );
    assert!(
        resolved_plan_chirho.state_chirho.transition_seq_chirho
            < held_active_chirho
                .checkpoint_chirho
                .state_chirho
                .transition_seq_chirho,
        "the resolved plan must sit STRICTLY BEHIND the head's checkpoint, which is the whole \
         meaning of 'the barrier resolves a stale coordinate on purpose'"
    );
    assert_eq!(
        resolved_plan_chirho, baseline_plan_chirho,
        "the plant must not have changed the resolution AT ALL — same checkpoint, byte for byte"
    );

    // REMOVE THE PLANT and re-resolve. Unchanged again, which is what makes the green above
    // attributable to the barrier rather than to some interaction with the planted bytes. Both
    // planted objects go, so the winner root is left as this arm found it.
    winner_storage_chirho
        .remove_chirho(&group_head_path_chirho)
        .expect("remove the planted head");
    winner_storage_chirho
        .remove_chirho(&adopted_checkpoint_path_chirho)
        .expect("remove the planted adopted checkpoint");
    let (_, after_removal_plan_chirho) = handoff_store_chirho
        .load_accepted_plan_chirho(&held_verifier_chirho)
        .expect("the barrier resolves its own plan again once the plant is gone");
    assert_eq!(
        after_removal_plan_chirho, baseline_plan_chirho,
        "removing the plant must leave the resolution identical; if it differs, the resolution was \
         reading the head after all and this arm has caught it"
    );
    assert!(
        !gd7_reconciliation_group_has_any_active_hold_chirho(
            &winner_storage_chirho,
            &state_chirho.group_digest_chirho
        )
        .expect("the hold predicate answers after the plant is removed"),
        "the winner root must be left with no hold, or this arm has stranded its write path"
    );
}
