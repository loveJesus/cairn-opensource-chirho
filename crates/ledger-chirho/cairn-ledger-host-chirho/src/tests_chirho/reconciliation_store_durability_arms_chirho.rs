// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Item 6.2 cut 2 — the crash window INSIDE one reconciliation checkpoint commit.
//!
//! # WHY THIS IS THE ONE INTRA-FUNCTION CUT
//!
//! Every other cut in the item 6.2 matrix is cross-store: the obligation state machine writes one
//! atomic mutation per transition, so its crash windows fall between calls. `commit_checkpoint_
//! internal_chirho` is the exception — it performs THREE durable mutations in one body (the
//! immutable checkpoint object, the ordinary-write hold, then the head), so a crash can land
//! between them with the caller none the wiser.
//!
//! # WHAT THIS ARM ADDS OVER THE ORPHAN TEST THAT ALREADY EXISTS
//!
//! `reconciliation_store_tests_chirho::orphan_checkpoint_recovers_while_immutable_collision_
//! refuses_chirho` already proves two things, and this arm deliberately does not repeat them: that
//! a store holding a checkpoint object with no head RECOVERS on retry, and that differing bytes at
//! the same checkpoint path REFUSE with `ImmutableCollisionChirho`. That is the byte-compare's
//! teeth, and it is measured there.
//!
//! What it does NOT prove is that a crash actually PRODUCES that state. It plants the orphan with
//! `force_put_chirho` — so it establishes "the store recovers from a state someone placed", not
//! "the store recovers from a state a crash left". Those are different propositions, and only the
//! second one is what a durability bridge claims. This arm supplies it: a scripted crash at the
//! measured head-write boundary, the residue asserted as the crash left it, and the retry driven
//! over exactly those surviving bytes.
//!
//! Together they are the complete cut-2 story — this arm for the residue, the orphan test for the
//! collision guard that makes resuming over that residue safe rather than merely permissive.

use super::reconciliation_store_tests_chirho::{
    identity_chirho, observed_state_chirho, FakeReconciliationSignerChirho,
};
use crate::reconciliation_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_head_path_chirho,
    Gd7ReconciliationStoreChirho,
};
use cairn_ledger_sim_chirho::fault_chirho::{FaultKindChirho, FaultPlanChirho};
use cairn_ledger_sim_chirho::storage_chirho::{SimStorageChirho, StorageMutationKindChirho};

/// CUT 2 — RESUME-IDEMPOTENT across the checkpoint-object / head window.
///
/// A crash after the immutable checkpoint object is durable but before the head moves must leave a
/// state that the SAME commit, replayed, carries forward to the SAME checkpoint ref — never a
/// second object, never a different identity, never a refusal that strands the reconciliation.
///
/// The boundary is MEASURED rather than hardcoded: the head write is the commit's only atomic
/// write, so it is resolved from the mutation trace by kind. A commit that gained or lost a durable
/// step moves this arm's crash point with it instead of silently leaving the real window untested.
#[test]
fn a_crash_between_the_checkpoint_object_and_the_head_resumes_idempotently_chirho() {
    let signer_chirho = FakeReconciliationSignerChirho::new_chirho(0x52);
    let identity_chirho = identity_chirho();

    // ---- PROBE: learn where the head write lands, and what a clean commit produces ----
    let probe_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let probe_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &probe_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .expect("probe: open the reconciliation store");
    let probe_commit_chirho = probe_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .expect("probe: the clean commit must succeed, or this arm has no boundary to crash at");

    let head_write_index_chirho = probe_chirho
        .mutation_trace_chirho()
        .into_iter()
        .find(|event_chirho| {
            event_chirho.kind_chirho == StorageMutationKindChirho::AtomicWriteChirho
        })
        .expect("the commit must move the head with an atomic write")
        .index_chirho;
    // NON-VACUITY: the head write cannot be the first mutation — the immutable checkpoint object
    // and the ordinary-write hold both precede it. An index of 0 would mean the window this arm
    // exists to test does not exist, and the crash below would be testing an empty commit.
    assert!(
        head_write_index_chirho >= 2,
        "the head write must follow the checkpoint object and the ordinary-write hold (index \
         {head_write_index_chirho} seen); a lower index means the commit no longer has the \
         intra-function window cut 2 names"
    );

    let checkpoint_path_chirho =
        gd7_reconciliation_checkpoint_path_chirho(&probe_commit_chirho.checkpoint_ref_chirho)
            .expect("the committed checkpoint has a path");
    let head_path_chirho = gd7_reconciliation_head_path_chirho(&identity_chirho)
        .expect("the identity has a head path");

    // ---- CRASH exactly at the head write ----
    let crashed_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
        head_write_index_chirho,
        FaultKindChirho::CrashBeforeChirho,
    ));
    let crashed_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &crashed_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .expect("open the store that will crash");
    assert!(
        crashed_store_chirho
            .commit_checkpoint_chirho(None, observed_state_chirho())
            .is_err(),
        "the scripted crash must actually fire — a success here means the measured index no longer \
         names the head write and this arm is measuring nothing"
    );
    assert!(
        crashed_chirho.is_crashed_chirho(),
        "the store must be crash-latched, else the commit failed for an unrelated reason"
    );

    // ---- THE RESIDUE, as the crash left it ----
    let residue_chirho = crashed_chirho.snapshot_chirho();
    assert!(
        residue_chirho.contains_key(checkpoint_path_chirho.key_chirho()),
        "the immutable checkpoint object is durable BEFORE the head moves — that ordering is what \
         makes the window resumable at all"
    );
    assert!(
        !residue_chirho.contains_key(head_path_chirho.key_chirho()),
        "and the head did NOT move: a head pointing at this checkpoint would mean the crash \
         published a reconciliation the commit never finished"
    );

    // ---- RECOVER over exactly the surviving bytes, and replay the SAME commit ----
    let restored_chirho =
        SimStorageChirho::restore_chirho(residue_chirho, FaultPlanChirho::none_chirho());
    let restored_store_chirho = Gd7ReconciliationStoreChirho::new_chirho(
        &restored_chirho,
        &signer_chirho,
        identity_chirho.clone(),
    )
    .expect("reopen the store after recovery");
    let retried_chirho = restored_store_chirho
        .commit_checkpoint_chirho(None, observed_state_chirho())
        .expect(
            "the replayed commit must RESUME over the surviving checkpoint object; a refusal here \
             would strand the reconciliation with an object it can neither use nor replace",
        );

    // THE BRANCH, by name: resume-idempotent. Same commit, same checkpoint identity.
    assert_eq!(
        retried_chirho.checkpoint_ref_chirho, probe_commit_chirho.checkpoint_ref_chirho,
        "the retry must converge on the SAME checkpoint ref — a different one would mean the crash \
         plus retry minted a second checkpoint identity for one reconciliation step"
    );
    assert!(
        restored_chirho
            .snapshot_chirho()
            .contains_key(head_path_chirho.key_chirho()),
        "and the retry finished the job the crash interrupted: the head is now published"
    );

    // COUNTED, not inferred: the recovering process re-issued both creates and moved the head once.
    // The checkpoint create is the one that returned `AlreadyExistsChirho` and went through the
    // guarded byte-compare — the path whose refusing half is pinned by
    // `orphan_checkpoint_recovers_while_immutable_collision_refuses_chirho`.
    let counts_chirho = restored_chirho.operation_counts_chirho();
    assert_eq!(
        counts_chirho.create_durable_calls_chirho, 2,
        "the retry re-issues the checkpoint create and the ordinary-write hold; it must not skip \
         either on the strength of the surviving object"
    );
    assert_eq!(
        counts_chirho.atomic_write_calls_chirho, 1,
        "and it moves the head exactly once"
    );

    // The surviving object was REUSED, not rewritten: byte-identical to the clean commit's.
    assert_eq!(
        restored_chirho
            .snapshot_chirho()
            .get(checkpoint_path_chirho.key_chirho()),
        probe_chirho
            .snapshot_chirho()
            .get(checkpoint_path_chirho.key_chirho()),
        "the resumed commit must leave the crash-surviving checkpoint bytes exactly as they were — \
         an immutable object that a retry rewrote would not be immutable"
    );
}
