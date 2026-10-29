// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The leg that carries an observed compensation from provider outcome to `CompletedChirho`.
//!
//! # WHY THIS IS A SEPARATE ACT FROM THE COMPOSITION
//!
//! `compose_gd7_provider_result_chirho` ends at `ProviderObservedChirho` (observed) or
//! `HeldManualChirho` (in doubt). It never reaches `CompletedChirho`, because completion needs a
//! **journal receipt ref**, and the only sensible source of one is the compensation journal append
//! — which is the FENCED append (`resident_authority_chirho`'s sink-term check). So the chain is:
//!
//! ```text
//! D2 advance unlocks the fence -> the fenced append succeeds -> its record digest is the receipt
//! ref -> JournalRecordedChirho -> CompletedChirho -> D1's classifier can certify
//! ```
//!
//! Before this module, `record_gd7_journal_receipt_chirho` and `mark_gd7_obligation_completed_chirho`
//! had ZERO production callers, so every obligation classified OPEN and the convergence certificate
//! was production-unreachable. This is the wire that makes the terminal state reachable.
//!
//! # THE DECISION IS PURE, AND IT RUNS BEFORE THE APPEND
//!
//! The append is durable and cannot be withdrawn. A readiness gate placed after it could only
//! strand a compensation record in the journal with no state transition to match — the failure
//! shape the obligation state machine exists to prevent. So the decision of whether to append at
//! all is taken by [`plan_gd7_compensation_completion_chirho`], which touches no storage and holds
//! no authority, and the caller cannot reach the append without having gone through it.
//!
//! # REPLAY APPENDS NOTHING
//!
//! An obligation already at `JournalRecordedChirho` or `CompletedChirho` has had its append. Re-
//! running this leg must not produce a second compensation record, so the plan for those states is
//! [`Gd7CompensationCompletionPlanChirho::FinishWithoutAppendChirho`] and no journal call is made.
//! `record_gd7_journal_receipt_chirho` independently refuses a DIFFERENT receipt ref for an
//! already-recorded obligation, so even a caller that ignored the plan could not rebind the receipt.

use super::gd7_compensation_composition_chirho::Gd7CompensationProviderRefusalChirho;
use crate::reconciliation_chirho::{
    mark_gd7_obligation_completed_chirho, record_gd7_journal_receipt_chirho,
    Gd7ObligationProcessingRefusalChirho, Gd7ObligationProcessingStateChirho,
    Gd7ObligationTerminalProgressChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;

/// Exact reason a compensation could not be carried to `CompletedChirho`.
///
/// `pub` because it is the error type of the now-`pub`
/// `ResidentEffectJournalHandleChirho::complete_gd7_compensation_chirho` wire method, and a public
/// method whose error type is crate-private is a `private_interfaces` warning — the caller could
/// receive the value but not name it. Widening the method without widening this would have left a
/// warning standing in a zero-warning gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gd7CompensationCompletionRefusalChirho {
    /// Tenant migration freezes the resident root and all adjacent external-effect progression.
    TenantMigrationSourceFenceActiveChirho,
    /// The fenced compensation append was refused.
    ///
    /// This is the STRAND a mid-life winner-term bump produces: the sink cell is behind the
    /// current term, so `verify_supplied_winner_term_is_strictly_current_chirho` refuses, and the
    /// obligation stays at `ProviderObservedChirho` until the lawful D2 advance lifts the fence.
    JournalAppendRefusedChirho { detail_chirho: String },
    /// The obligation state machine refused the receipt or the completion.
    ProcessingChirho(Gd7ObligationProcessingRefusalChirho),
    /// The obligation has no observed provider outcome, so there is nothing to complete.
    ///
    /// Named separately from `ProcessingChirho` because it is the ordering guard rather than a
    /// state-machine fault: it is what keeps the durable append from running too early.
    NotProviderObservedChirho {
        progress_chirho: Gd7ObligationTerminalProgressChirho,
    },
    /// The actor mailbox was unreachable.
    ProviderChirho(Gd7CompensationProviderRefusalChirho),
}

impl std::fmt::Display for Gd7CompensationCompletionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TenantMigrationSourceFenceActiveChirho => formatter_chirho
                .write_str("Gd7CompensationCompletionTenantMigrationSourceFenceActiveChirho"),
            Self::JournalAppendRefusedChirho { detail_chirho } => write!(
                formatter_chirho,
                "Gd7CompensationCompletionJournalAppendRefusedChirho: {detail_chirho}"
            ),
            Self::ProcessingChirho(refusal_chirho) => write!(
                formatter_chirho,
                "Gd7CompensationCompletionProcessingChirho: {refusal_chirho}"
            ),
            Self::NotProviderObservedChirho { progress_chirho } => write!(
                formatter_chirho,
                "Gd7CompensationCompletionNotProviderObservedChirho: progress {progress_chirho:?}"
            ),
            Self::ProviderChirho(refusal_chirho) => write!(
                formatter_chirho,
                "Gd7CompensationCompletionProviderChirho: {refusal_chirho:?}"
            ),
        }
    }
}

impl std::error::Error for Gd7CompensationCompletionRefusalChirho {}

/// Whether this obligation still owes a durable compensation append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gd7CompensationCompletionPlanChirho {
    /// `ProviderObservedChirho`: the provider outcome is observed and no receipt is bound yet.
    AppendThenFinishChirho,
    /// `JournalRecordedChirho` / `CompletedChirho`: the append already happened. Replay must not
    /// produce a second compensation record.
    FinishWithoutAppendChirho,
}

/// Decide whether a durable append is owed, without touching storage or holding any authority.
///
/// Pure on purpose, following `verify_supplied_winner_term_is_strictly_current_chirho` in the fence
/// module: the ordering rule — no append before the provider outcome is observed — is testable by
/// value, and because [`finish_gd7_compensation_completion_chirho`] is the only path to the state
/// transitions, no caller can reach a completion that skipped this decision.
pub(crate) fn plan_gd7_compensation_completion_chirho(
    state_chirho: &Gd7ObligationProcessingStateChirho,
) -> Result<Gd7CompensationCompletionPlanChirho, Gd7CompensationCompletionRefusalChirho> {
    match state_chirho.terminal_progress_chirho() {
        Gd7ObligationTerminalProgressChirho::ProviderObservedChirho => {
            Ok(Gd7CompensationCompletionPlanChirho::AppendThenFinishChirho)
        }
        Gd7ObligationTerminalProgressChirho::JournalRecordedChirho
        | Gd7ObligationTerminalProgressChirho::CompletedChirho => {
            Ok(Gd7CompensationCompletionPlanChirho::FinishWithoutAppendChirho)
        }
        progress_chirho @ (Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho
        | Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho
        | Gd7ObligationTerminalProgressChirho::HeldManualChirho) => Err(
            Gd7CompensationCompletionRefusalChirho::NotProviderObservedChirho { progress_chirho },
        ),
    }
}

/// Drive the state transitions that finish one compensation.
///
/// `receipt_ref_chirho` is `Some` exactly when the caller performed the append this leg planned;
/// `None` is the replay path, where the receipt is already bound.
pub(crate) fn finish_gd7_compensation_completion_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    state_chirho: &Gd7ObligationProcessingStateChirho,
    receipt_ref_chirho: Option<&str>,
) -> Result<Gd7ObligationProcessingStateChirho, Gd7CompensationCompletionRefusalChirho> {
    let journalled_state_chirho = match receipt_ref_chirho {
        Some(receipt_ref_chirho) => {
            record_gd7_journal_receipt_chirho(storage_chirho, state_chirho, receipt_ref_chirho)
                .map_err(Gd7CompensationCompletionRefusalChirho::ProcessingChirho)?
        }
        None => state_chirho.clone(),
    };
    mark_gd7_obligation_completed_chirho(storage_chirho, &journalled_state_chirho)
        .map_err(Gd7CompensationCompletionRefusalChirho::ProcessingChirho)
}

#[cfg(test)]
mod completed_leg_tests_chirho {
    use super::*;
    use crate::reconciliation_chirho::{
        create_or_load_gd7_obligation_processing_state_chirho, record_gd7_provider_intent_chirho,
        record_gd7_provider_observation_chirho,
    };
    use crate::FsLedgerStorageChirho;
    use std::fs;

    const MINT_DIGEST_CHIRHO: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OBLIGATION_DIGEST_CHIRHO: &str =
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    const RECEIPT_REF_CHIRHO: &str =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fn open_leg_storage_chirho(label_chirho: &str) -> (std::path::PathBuf, FsLedgerStorageChirho) {
        let directory_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-completed-leg-{label_chirho}-{}-chirho",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory_chirho);
        fs::create_dir_all(&directory_chirho).expect("completed leg test storage");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&directory_chirho)
            .expect("open completed leg test storage");
        (directory_chirho, storage_chirho)
    }

    fn fresh_state_chirho(
        storage_chirho: &FsLedgerStorageChirho,
        label_chirho: &str,
    ) -> Gd7ObligationProcessingStateChirho {
        create_or_load_gd7_obligation_processing_state_chirho(
            storage_chirho,
            MINT_DIGEST_CHIRHO,
            &format!("receipt-{label_chirho}-chirho"),
            OBLIGATION_DIGEST_CHIRHO,
            &format!("inverse-{label_chirho}-chirho"),
            &format!("action-{label_chirho}-chirho"),
        )
        .expect("create the obligation processing state")
    }

    /// Drive one obligation to `ProviderObservedChirho` through the real state machine, so the leg
    /// under test receives a state the composition could actually have produced.
    fn observed_state_chirho(
        storage_chirho: &FsLedgerStorageChirho,
        label_chirho: &str,
    ) -> Gd7ObligationProcessingStateChirho {
        let state_chirho = fresh_state_chirho(storage_chirho, label_chirho);
        let intent_chirho = record_gd7_provider_intent_chirho(
            storage_chirho,
            &state_chirho,
            &format!("provider-key-{label_chirho}-chirho"),
            OBLIGATION_DIGEST_CHIRHO,
        )
        .expect("persist the provider intent");
        record_gd7_provider_observation_chirho(
            storage_chirho,
            &intent_chirho,
            &format!("observation-{label_chirho}-chirho"),
            &format!("provider-effect-{label_chirho}-chirho"),
        )
        .expect("record the observed provider outcome")
    }

    #[test]
    fn no_append_is_owed_before_the_provider_outcome_is_observed_chirho() {
        // THE ORDERING PROPERTY, and it is the money-relevant one: the durable append must not run
        // for an obligation whose provider outcome is not observed. A gate placed after the append
        // could only strand a compensation record with no state transition to match it.
        let (_directory_chirho, storage_chirho) = open_leg_storage_chirho("awaiting");
        let state_chirho = fresh_state_chirho(&storage_chirho, "awaiting");
        assert_eq!(
            state_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho,
            "a fresh obligation starts awaiting its provider"
        );

        // Assert the REASON, and assert the negative: the ordering guard fires, not a state fault.
        match plan_gd7_compensation_completion_chirho(&state_chirho) {
            Err(Gd7CompensationCompletionRefusalChirho::NotProviderObservedChirho {
                progress_chirho,
            }) => assert_eq!(
                progress_chirho,
                Gd7ObligationTerminalProgressChirho::AwaitingProviderChirho,
                "the refusal must name the progress it refused at"
            ),
            other_chirho => panic!(
                "expected the ordering guard NotProviderObservedChirho, got {other_chirho:?}; a \
                 different refusal means the append ordering is being enforced somewhere else"
            ),
        }
    }

    #[test]
    fn a_held_manual_obligation_is_never_completed_chirho() {
        // HeldManual is the in-doubt terminal the composition writes when the provider outcome is
        // unknown. Completing it would assert an outcome nobody observed.
        let (_directory_chirho, storage_chirho) = open_leg_storage_chirho("held-manual");
        let state_chirho = fresh_state_chirho(&storage_chirho, "held-manual");
        let held_manual_chirho =
            crate::reconciliation_chirho::mark_gd7_obligation_held_manual_chirho(
                &storage_chirho,
                &state_chirho,
            )
            .expect("mark the obligation held-manual");

        assert!(
            matches!(
                plan_gd7_compensation_completion_chirho(&held_manual_chirho),
                Err(
                    Gd7CompensationCompletionRefusalChirho::NotProviderObservedChirho {
                        progress_chirho: Gd7ObligationTerminalProgressChirho::HeldManualChirho,
                    }
                )
            ),
            "an in-doubt obligation must never be planned for completion"
        );
    }

    #[test]
    fn an_observed_obligation_owes_an_append_then_reaches_completed_chirho() {
        // THE SUCCESS PATH of the leg itself: observed -> append owed -> receipt bound -> Completed.
        let (_directory_chirho, storage_chirho) = open_leg_storage_chirho("observed");
        let observed_chirho = observed_state_chirho(&storage_chirho, "observed");
        assert_eq!(
            observed_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::ProviderObservedChirho
        );

        assert_eq!(
            plan_gd7_compensation_completion_chirho(&observed_chirho),
            Ok(Gd7CompensationCompletionPlanChirho::AppendThenFinishChirho),
            "an observed obligation is exactly the state that owes a durable append"
        );

        let completed_chirho = finish_gd7_compensation_completion_chirho(
            &storage_chirho,
            &observed_chirho,
            Some(RECEIPT_REF_CHIRHO),
        )
        .expect("the receipt binds and the obligation completes");
        assert_eq!(
            completed_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::CompletedChirho,
            "this is the terminal state D1's classifier requires; before this wire nothing in \
             production could reach it"
        );
        assert_eq!(
            completed_chirho.journal_receipt_ref_chirho(),
            Some(RECEIPT_REF_CHIRHO),
            "the bound receipt is the exact journal record digest the append returned"
        );
    }

    #[test]
    fn replay_owes_no_second_append_and_cannot_rebind_the_receipt_chirho() {
        // REPLAY SAFETY. A second run must not produce a second compensation record. The plan says
        // so, and the state machine independently refuses a DIFFERENT receipt — two mechanisms, so
        // a caller that ignored the plan still could not rebind.
        let (_directory_chirho, storage_chirho) = open_leg_storage_chirho("replay");
        let observed_chirho = observed_state_chirho(&storage_chirho, "replay");
        let completed_chirho = finish_gd7_compensation_completion_chirho(
            &storage_chirho,
            &observed_chirho,
            Some(RECEIPT_REF_CHIRHO),
        )
        .expect("first completion");

        assert_eq!(
            plan_gd7_compensation_completion_chirho(&completed_chirho),
            Ok(Gd7CompensationCompletionPlanChirho::FinishWithoutAppendChirho),
            "a completed obligation owes NO further append — this is what keeps a retry from \
             writing a second compensation record"
        );
        assert_eq!(
            finish_gd7_compensation_completion_chirho(&storage_chirho, &completed_chirho, None)
                .expect("replay finishes idempotently")
                .terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::CompletedChirho
        );

        // The independent second mechanism: a DIFFERENT receipt is refused outright.
        assert!(
            matches!(
                finish_gd7_compensation_completion_chirho(
                    &storage_chirho,
                    &completed_chirho,
                    Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                ),
                Err(Gd7CompensationCompletionRefusalChirho::ProcessingChirho(_))
            ),
            "rebinding a completed obligation to a different journal receipt must refuse"
        );
    }
}

/// Item 6.2 durability-bridge arms: what a crash between two cuts leaves, and what retry does.
///
/// These are SEPARATE from `completed_leg_tests_chirho` because they assert a different class of
/// property. Those arms ask "does the leg decide correctly"; these ask "if the machine dies at an
/// arbitrary durable boundary, does retry land in a DEFINED branch with the RIGHT payload".
///
/// # WHY SimStorage AND NOT A REAL FILESYSTEM
///
/// The crash matrix needs a crash at an EXACT durable boundary, which only the sim's scripted
/// `FaultPlanChirho` provides (`FaultKindChirho::CrashBeforeChirho`'s own doc states the modelling
/// rule these arms rely on: *a crash BETWEEN two cuts is a `CrashBefore` on the SECOND cut*). The
/// obligation state machine takes `&dyn LedgerStoragePortChirho`, so the sim injects DIRECTLY — no
/// test-only opener exists or is needed here, and the production concrete-storage guarantees
/// (`ResidentLedgerLocalPortsChirho`, `ResidentGd7PlanPortsChirho`, and
/// `StableLedgerExclusiveLockGuardChirho::storage_chirho`) are untouched by these arms.
#[cfg(test)]
mod durability_bridge_arms_chirho {
    use super::*;
    use crate::reconciliation_chirho::{
        create_or_load_gd7_obligation_processing_state_chirho,
        load_gd7_obligation_processing_state_chirho, plant_gd7_ordinary_write_hold_chirho,
        record_gd7_provider_intent_chirho, record_gd7_provider_observation_chirho,
        remove_gd7_ordinary_write_hold_chirho,
    };
    use cairn_ledger_sim_chirho::fault_chirho::{FaultKindChirho, FaultPlanChirho};
    use cairn_ledger_sim_chirho::storage_chirho::SimStorageChirho;

    const MINT_DIGEST_CHIRHO: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OBLIGATION_DIGEST_CHIRHO: &str =
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    const RECEIPT_REF_CHIRHO: &str =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    /// A consistency-group digest in the exact shape the store requires:
    /// `WRITER_FENCE_GROUP_DIGEST_PREFIX_CHIRHO` (`contract_chirho.rs:39`) followed by a 64-char
    /// lower-hex digest. The prefix is spelled rather than resolved because it is neither re-exported
    /// from `reconciliation_chirho` nor worth widening production surface for a fixture — and the
    /// failure mode is LOUD, not silent: a changed prefix makes
    /// `consistency_group_digest_suffix_chirho` return `None` and these arms fail with
    /// `InvalidIdentityChirho` rather than quietly passing against a path nobody uses.
    const GROUP_DIGEST_CHIRHO: &str = concat!(
        "writer-fence-group-blake3-chirho:",
        "1111111111111111111111111111111111111111111111111111111111111111"
    );

    /// Drive one obligation to `ProviderObservedChirho` through the REAL state machine.
    ///
    /// Errors are returned rather than unwrapped: under a scripted crash any step may legitimately
    /// refuse, and an arm that unwrapped here would turn the crash it is testing into a panic.
    fn drive_to_observed_chirho(
        storage_chirho: &dyn LedgerStoragePortChirho,
        label_chirho: &str,
    ) -> Result<Gd7ObligationProcessingStateChirho, Gd7ObligationProcessingRefusalChirho> {
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            storage_chirho,
            MINT_DIGEST_CHIRHO,
            &format!("receipt-{label_chirho}-chirho"),
            OBLIGATION_DIGEST_CHIRHO,
            &format!("inverse-{label_chirho}-chirho"),
            &format!("action-{label_chirho}-chirho"),
        )?;
        let intent_chirho = record_gd7_provider_intent_chirho(
            storage_chirho,
            &state_chirho,
            &format!("provider-key-{label_chirho}-chirho"),
            OBLIGATION_DIGEST_CHIRHO,
        )?;
        record_gd7_provider_observation_chirho(
            storage_chirho,
            &intent_chirho,
            &format!("observation-{label_chirho}-chirho"),
            &format!("provider-effect-{label_chirho}-chirho"),
        )
    }

    /// GAP 1, the ONE non-window refusal arm that did not already exist.
    ///
    /// `completed_leg_tests_chirho` already pins the Awaiting and HeldManual progress payloads. The
    /// `ProviderIntentPersistedChirho` case was unpinned: it is the state where a provider call is
    /// in flight, which is exactly the state a careless completion would mis-read as "observed".
    /// Asserts the PAYLOAD is the right value, and asserts the negative so a different refusal
    /// cannot satisfy the arm.
    #[test]
    fn an_intent_persisted_obligation_owes_no_append_and_names_its_progress_chirho() {
        let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &storage_chirho,
            MINT_DIGEST_CHIRHO,
            "receipt-intent-chirho",
            OBLIGATION_DIGEST_CHIRHO,
            "inverse-intent-chirho",
            "action-intent-chirho",
        )
        .expect("create the obligation processing state");
        let intent_chirho = record_gd7_provider_intent_chirho(
            &storage_chirho,
            &state_chirho,
            "provider-key-intent-chirho",
            OBLIGATION_DIGEST_CHIRHO,
        )
        .expect("persist the provider intent");

        assert_eq!(
            intent_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho,
            "the fixture must actually sit at IntentPersisted, or this arm pins nothing"
        );
        match plan_gd7_compensation_completion_chirho(&intent_chirho) {
            Err(Gd7CompensationCompletionRefusalChirho::NotProviderObservedChirho {
                progress_chirho,
            }) => assert_eq!(
                progress_chirho,
                Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho,
                "a refusal carrying the WRONG progress is worse than one carrying none — a caller \
                 reading it would believe the obligation is at a different waypoint"
            ),
            other_chirho => panic!(
                "expected the ordering guard NotProviderObservedChirho at IntentPersisted, got \
                 {other_chirho:?}; a persisted-but-unobserved provider intent must never be \
                 planned for a durable append"
            ),
        }
    }

    /// CUT 3 — RESUME-FORWARD across the `ProviderObservedChirho` waypoint.
    ///
    /// A crash between the intent write and the observation write must leave the obligation at its
    /// earlier waypoint with nothing invented, and retry must move it FORWARD to observed. The
    /// distinguishing assertion is that recovery is forward motion, not a repair: nothing rewinds
    /// and no waypoint is skipped.
    #[test]
    fn a_crash_before_the_observation_write_resumes_forward_chirho() {
        // Learn where the observation write lands rather than hardcoding an index that would drift
        // silently the moment the state machine gains or loses a durable step.
        let probe_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let probe_state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
            &probe_chirho,
            MINT_DIGEST_CHIRHO,
            "receipt-cut3-chirho",
            OBLIGATION_DIGEST_CHIRHO,
            "inverse-cut3-chirho",
            "action-cut3-chirho",
        )
        .expect("probe: create");
        record_gd7_provider_intent_chirho(
            &probe_chirho,
            &probe_state_chirho,
            "provider-key-cut3-chirho",
            OBLIGATION_DIGEST_CHIRHO,
        )
        .expect("probe: intent");
        let observation_op_index_chirho = probe_chirho.mutating_op_count_chirho();

        // Crash exactly AT the observation write: the intent survived, the observation did not.
        let crashed_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
            observation_op_index_chirho,
            FaultKindChirho::CrashBeforeChirho,
        ));
        let crash_result_chirho = drive_to_observed_chirho(&crashed_chirho, "cut3");
        assert!(
            crash_result_chirho.is_err(),
            "the scripted crash must actually fire — a success here means the fault index no \
             longer names the observation write and this arm is measuring nothing"
        );
        assert!(
            crashed_chirho.is_crashed_chirho(),
            "the store must be crash-latched, else the drive failed for an unrelated reason"
        );

        // Recover: only durable bytes survive.
        let survived_chirho = crashed_chirho.snapshot_chirho();
        let restored_chirho =
            SimStorageChirho::restore_chirho(survived_chirho, FaultPlanChirho::none_chirho());
        let reloaded_chirho =
            load_gd7_obligation_processing_state_chirho(&restored_chirho, MINT_DIGEST_CHIRHO)
                .expect("the obligation row survived the crash and reloads");
        assert_eq!(
            reloaded_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::ProviderIntentPersistedChirho,
            "the crash was AT the observation write, so the durable state must still be the \
             earlier waypoint — an observed state here would mean the crash left a claim the \
             provider never confirmed"
        );

        // RESUME-FORWARD: re-running the observation moves the waypoint on.
        let observed_chirho = record_gd7_provider_observation_chirho(
            &restored_chirho,
            &reloaded_chirho,
            "observation-cut3-chirho",
            "provider-effect-cut3-chirho",
        )
        .expect("retry records the observation");
        assert_eq!(
            observed_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::ProviderObservedChirho,
            "recovery is FORWARD motion across the waypoint, not a repair of a torn state"
        );
        assert_eq!(
            plan_gd7_compensation_completion_chirho(&observed_chirho),
            Ok(Gd7CompensationCompletionPlanChirho::AppendThenFinishChirho),
            "and only now is the durable append owed"
        );
    }

    /// CUT 5 — RESUME-IDEMPOTENT for an obligation already at `CompletedChirho`.
    ///
    /// # THE CERTIFICATE PRECONDITION IS CALLER-STATE, NOT STORE-STATE
    ///
    /// Measured in item 6.2 step 0: the convergence certificate has NO store — it is constructed,
    /// signed, and passed in memory, and no write primitive anywhere takes a
    /// `ConvergedReadReplicaChirho`. So "certificate absent" cannot be a store fixture. This arm
    /// realises it as caller state: it never calls `converge_and_certify_chirho` and holds no
    /// certificate value. That is the whole precondition.
    ///
    /// The payload assertion is the load-bearing one: replay must not merely succeed, it must
    /// preserve the ORIGINAL receipt. A retry that completed while rebinding the receipt would be a
    /// second compensation identity for one obligation.
    #[test]
    fn a_completed_row_replays_idempotently_and_adds_no_durable_write_chirho() {
        let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let observed_chirho =
            drive_to_observed_chirho(&storage_chirho, "cut5").expect("drive to observed");
        let completed_chirho = finish_gd7_compensation_completion_chirho(
            &storage_chirho,
            &observed_chirho,
            Some(RECEIPT_REF_CHIRHO),
        )
        .expect("first completion");
        assert_eq!(
            completed_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::CompletedChirho
        );

        // The BRANCH, by name.
        assert_eq!(
            plan_gd7_compensation_completion_chirho(&completed_chirho),
            Ok(Gd7CompensationCompletionPlanChirho::FinishWithoutAppendChirho),
            "a Completed row owes no append; this is the dispatch arm cut 5 names"
        );

        // COUNTED, not inferred: the replay must add zero durable mutations.
        let before_chirho = storage_chirho.operation_counts_chirho();
        let replayed_chirho =
            finish_gd7_compensation_completion_chirho(&storage_chirho, &completed_chirho, None)
                .expect("replay finishes idempotently");
        let after_chirho = storage_chirho.operation_counts_chirho();
        assert_eq!(
            after_chirho.durability_call_count_chirho(),
            before_chirho.durability_call_count_chirho(),
            "replaying a Completed obligation must cross the durability port ZERO further times; \
             any new call is a second write for an obligation that already terminated"
        );

        // The PAYLOAD: same terminal state, same receipt, nothing rebound.
        assert_eq!(
            replayed_chirho.terminal_progress_chirho(),
            Gd7ObligationTerminalProgressChirho::CompletedChirho
        );
        assert_eq!(
            replayed_chirho.journal_receipt_ref_chirho(),
            Some(RECEIPT_REF_CHIRHO),
            "replay must preserve the ORIGINAL receipt — a rebound receipt would give one \
             obligation two compensation identities"
        );
    }

    /// CUT 6, NARROW — remove-idempotency of the ordinary-write hold, COUNTED.
    ///
    /// # SCOPE LIMIT, STATED RATHER THAN IMPLIED
    ///
    /// This arm covers the REMOVAL SEMANTICS only. It does NOT cover the guarded release path:
    /// `release_converged_reconciliation_hold_chirho` is one flat function whose guard chain
    /// (cert-ref / phase / group / active-head) runs inline against
    /// `StableLedgerExclusiveLockGuardChirho::storage_chirho()`, which is CONCRETE by design — its
    /// own doc states that concreteness is what makes a storage/guard mismatch unconstructible
    /// rather than merely checked. There is no separately-callable `&dyn` guard layer, so
    /// "a second RELEASE is refused through the guards" is not expressible here and belongs to the
    /// 6.4 lock-guard + SimStorage composition.
    ///
    /// A future seat may be tempted to reassemble the chain's individual loaders (both take `&dyn`)
    /// in order against SimStorage. That would prove the TEST's composition, not production's — the
    /// ordering, the early returns, and the single-lock context are precisely what the real function
    /// contributes. 6.4's arm must drive the real function with a real guard.
    #[test]
    fn removing_the_ordinary_write_hold_is_idempotent_and_removes_exactly_once_chirho() {
        let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        plant_gd7_ordinary_write_hold_chirho(&storage_chirho, GROUP_DIGEST_CHIRHO)
            .expect("plant the ordinary-write hold");
        assert_eq!(
            storage_chirho.snapshot_chirho().len(),
            1,
            "the planted hold must be the one durable object, or the arm is watching the wrong key"
        );

        remove_gd7_ordinary_write_hold_chirho(&storage_chirho, GROUP_DIGEST_CHIRHO)
            .expect("first removal succeeds");
        assert!(
            storage_chirho.snapshot_chirho().is_empty(),
            "the hold is gone after the first removal"
        );

        // ABSENT IS OK: this is what makes an interrupted restoration completable by retry. If this
        // refused, a retry after a fully-successful restoration would fail — the shape of the
        // tracked cut-6 finding, which is why it is asserted here rather than trusted from the
        // doc comment.
        remove_gd7_ordinary_write_hold_chirho(&storage_chirho, GROUP_DIGEST_CHIRHO)
            .expect("a second removal over an ABSENT hold must succeed, not refuse");
        assert!(
            storage_chirho.snapshot_chirho().is_empty(),
            "the head stays absent; a reappearing hold would re-block ordinary writes"
        );
        assert_eq!(
            storage_chirho.operation_counts_chirho().remove_calls_chirho,
            2,
            "both removals reached the storage port — so the idempotence above is the PORT's \
             absent-is-Ok contract, not a caller that skipped the second call"
        );
    }

    /// CUT 6, NARROW — a crash AT the removal leaves the hold standing, and retry completes it.
    ///
    /// Same scope limit as the arm above: removal semantics, not the guarded release path.
    #[test]
    fn a_crash_at_the_hold_removal_leaves_writes_held_and_retry_completes_chirho() {
        let planted_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        plant_gd7_ordinary_write_hold_chirho(&planted_chirho, GROUP_DIGEST_CHIRHO)
            .expect("plant the hold");
        let removal_op_index_chirho = planted_chirho.mutating_op_count_chirho();
        let planted_snapshot_chirho = planted_chirho.snapshot_chirho();

        // Rebuild the same durable state under a plan that crashes exactly at the removal.
        let crashed_chirho = SimStorageChirho::restore_chirho(
            planted_snapshot_chirho,
            FaultPlanChirho::single_chirho(
                removal_op_index_chirho - 1,
                FaultKindChirho::CrashBeforeChirho,
            ),
        );
        assert!(
            remove_gd7_ordinary_write_hold_chirho(&crashed_chirho, GROUP_DIGEST_CHIRHO).is_err(),
            "the scripted crash must fire at the removal"
        );
        assert_eq!(
            crashed_chirho.snapshot_chirho().len(),
            1,
            "FAIL-CLOSED: the crash leaves the hold STANDING. Ordinary writes stay withheld, which \
             is the only safe direction — writable state with the hold silently gone would be the \
             failure this ordering exists to prevent"
        );

        // Retry after recovery completes the removal.
        let restored_chirho = SimStorageChirho::restore_chirho(
            crashed_chirho.snapshot_chirho(),
            FaultPlanChirho::none_chirho(),
        );
        remove_gd7_ordinary_write_hold_chirho(&restored_chirho, GROUP_DIGEST_CHIRHO)
            .expect("retry completes the removal");
        assert!(
            restored_chirho.snapshot_chirho().is_empty(),
            "exactly one EFFECTIVE removal across crash+retry"
        );
        assert_eq!(
            restored_chirho
                .operation_counts_chirho()
                .remove_calls_chirho,
            1,
            "and the recovering process issued exactly one removal call"
        );
    }

    /// NO UNDEFINED RECOVERY, swept over EVERY durable boundary of the completion drive.
    ///
    /// The five named cuts are the windows we reasoned about. This arm asserts the general property
    /// they exist to serve: crash at ANY durable boundary of observed -> Completed, recover, retry,
    /// and the obligation converges on `CompletedChirho` bound to the ORIGINAL receipt — never a
    /// panic, never a second receipt identity, never a stuck state.
    ///
    /// The boundary count is MEASURED by a no-fault probe rather than hardcoded, so a state machine
    /// that gains or loses a durable step widens or narrows this sweep automatically instead of
    /// silently leaving a new boundary untested.
    #[test]
    fn every_durable_boundary_of_the_completion_drive_recovers_to_one_receipt_chirho() {
        let probe_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let probe_observed_chirho =
            drive_to_observed_chirho(&probe_chirho, "sweep").expect("probe drive");
        finish_gd7_compensation_completion_chirho(
            &probe_chirho,
            &probe_observed_chirho,
            Some(RECEIPT_REF_CHIRHO),
        )
        .expect("probe completion");
        let boundary_count_chirho = probe_chirho.mutating_op_count_chirho();
        assert!(
            boundary_count_chirho >= 3,
            "the drive must cross several durable boundaries ({boundary_count_chirho} seen); a \
             tiny count means the probe is not exercising the completion path"
        );

        for crash_at_chirho in 0..boundary_count_chirho {
            let crashed_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
                crash_at_chirho,
                FaultKindChirho::CrashBeforeChirho,
            ));
            // Every step may legitimately refuse once the crash latches; none may panic.
            if let Ok(observed_chirho) = drive_to_observed_chirho(&crashed_chirho, "sweep") {
                let _ = finish_gd7_compensation_completion_chirho(
                    &crashed_chirho,
                    &observed_chirho,
                    Some(RECEIPT_REF_CHIRHO),
                );
            }

            // Recover and drive the SAME sequence again.
            let restored_chirho = SimStorageChirho::restore_chirho(
                crashed_chirho.snapshot_chirho(),
                FaultPlanChirho::none_chirho(),
            );
            let observed_chirho = drive_to_observed_chirho(&restored_chirho, "sweep")
                .unwrap_or_else(|refusal_chirho| {
                    panic!(
                        "crash at boundary {crash_at_chirho}: retry could not reach observed \
                         ({refusal_chirho:?}) — a crash there leaves an obligation that cannot be \
                         driven forward, which is an UNDEFINED recovery, not a defined one"
                    )
                });
            let recovered_chirho = finish_gd7_compensation_completion_chirho(
                &restored_chirho,
                &observed_chirho,
                Some(RECEIPT_REF_CHIRHO),
            )
            .unwrap_or_else(|refusal_chirho| {
                panic!(
                    "crash at boundary {crash_at_chirho}: retry could not complete \
                     ({refusal_chirho:?})"
                )
            });

            assert_eq!(
                recovered_chirho.terminal_progress_chirho(),
                Gd7ObligationTerminalProgressChirho::CompletedChirho,
                "crash at boundary {crash_at_chirho} must converge on Completed after retry"
            );
            assert_eq!(
                recovered_chirho.journal_receipt_ref_chirho(),
                Some(RECEIPT_REF_CHIRHO),
                "crash at boundary {crash_at_chirho} must leave exactly the ORIGINAL receipt — a \
                 different one would mean the crash+retry minted a second compensation identity"
            );
        }
    }
}
