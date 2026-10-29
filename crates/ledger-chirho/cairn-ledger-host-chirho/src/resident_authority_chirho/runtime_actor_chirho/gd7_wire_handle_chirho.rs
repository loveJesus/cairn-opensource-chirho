// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Handle methods for the GD7 wire commands, each the outer edge of an actor mailbox send.
//!
//! These live beside the mailbox variants they construct rather than in the actor module, because
//! they are one purpose — the outermost edge of the wire that makes the D2 advance and the
//! obligation terminal state reachable — and the actor module is about running the loop.
//!
//! All are UNWIRED AT THIS EDGE ONLY. Everything inward is production-compiled: the mailbox
//! variants, the dispatch arms, `ResidentLedgerAuthorityChirho::accept_new_winner_term_chirho`, and
//! the completed leg. The triggers are D3's release path and R4's composition surface.
//!
//! # WHY THESE ARE `pub`, AND WHAT CARRIES THE SAFETY
//!
//! The custody-verified actor world these must be driven against lives in
//! `cairn-ledger-regenesis-chirho`, which depends on this crate — so `pub(crate)` put the world and
//! the wire on opposite sides of a crate boundary and left the mailbox path with no caller at all.
//! Widening is deliberate, and safety does not rest on it: a
//! [`ResidentEffectJournalHandleChirho`] is obtainable ONLY through the custody-verified opener, so
//! holding one already implies an admitted world; and every verification — the two-coordinate
//! advance, the checkpoint-bound release, the fenced append — lives INWARD of the mailbox send,
//! where it is mutation-proven. Visibility was never the barrier, so removing it removes no barrier.
//!
//! What replaces the visibility signal is a WATCH, not a wall: the production caller census in
//! `cairn-source-scan-chirho` pins this family's production population, so a new production caller
//! is a reviewed event rather than a silent one.

use super::gd7_compensation_composition_chirho::Gd7CompensationCompositionRefusalChirho;
use super::gd7_completed_leg_chirho::Gd7CompensationCompletionRefusalChirho;
use super::mailbox_chirho::ResidentEffectJournalCommandChirho;
use super::{
    Gd7CompensationProviderRefusalChirho, ResidentEffectJournalHandleChirho,
    ResidentLedgerAuthorityRefusalChirho,
};
use crate::reconciliation_chirho::{
    AuthenticatedGd7DeposedForkObservationChirho, ConvergedReadReplicaChirho, Gd7PlanRefusalChirho,
};
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use std::sync::mpsc::sync_channel;

impl ResidentEffectJournalHandleChirho {
    /// Send the release across the mailbox to the resident that owns the hold.
    ///
    /// WIRE WRAPPER. The authority-bearing implementation is
    /// `ResidentLedgerAuthorityChirho::release_converged_gd7_hold_chirho`, which carries the same
    /// name one layer inward and does the checkpoint re-authentication and the ref supersede. The
    /// duplicate name is a delegation pattern and not a defect, but it IS a search trap: a census
    /// of this name returns BOTH layers, so resolve which receiver a call site has before reading
    /// a count as evidence about either.
    #[allow(
        dead_code,
        reason = "no production caller yet: the capstone frontier arm is the first (test) consumer; D3's release path remains the production trigger"
    )]
    pub fn release_converged_gd7_hold_chirho(
        &self,
        adopted_checkpoint_ref_chirho: &str,
        convergence_chirho: &ConvergedReadReplicaChirho,
    ) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
        let sender_chirho = self.command_sender_chirho.as_ref().ok_or_else(|| {
            ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho {
                detail_chirho: "resident effect-journal actor is already closed".to_owned(),
            }
        })?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::ReleaseConvergedGd7HoldChirho {
                    adopted_checkpoint_ref_chirho: adopted_checkpoint_ref_chirho.to_owned(),
                    convergence_chirho: Box::new(convergence_chirho.clone()),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|error_chirho| {
                ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho {
                detail_chirho: "resident effect-journal actor stopped before release reply"
                    .to_owned(),
            }
        })?
    }

    /// Advance this group's sink winner-term cell under verified revoke evidence.
    ///
    /// Returns the accepted term. The term is not an argument: it is read out of the signed
    /// observation by the lawful advance, so a caller cannot ask for a term to be accepted.
    ///
    /// UNWIRED AT THE OUTERMOST EDGE ONLY. Everything inward of this method is production-compiled
    /// and reachable: the mailbox variant, the dispatch arm, and
    /// `ResidentLedgerAuthorityChirho::accept_new_winner_term_chirho`, which is now the lawful
    /// advance's FIRST production caller. What is missing is a trigger, and its owner is D3's
    /// release path.
    ///
    /// DRIVEN AND LANDED THROUGH THE REAL MAILBOX (2026-08-05): the capstone frontier arm in
    /// `cairn-ledger-regenesis-chirho` (`harness1_compensated_terminal_arms_chirho`) drives THIS
    /// method against a real custody-verified actor with the world's own authenticated
    /// deposed-fork observation, and the advance LANDS — the accepted term equals the witness's
    /// term, asserted by value. (An earlier version of this comment over-claimed exactly this
    /// before any arm existed and was corrected; the claim is restored now that the arm is real.
    /// The B3c full-chain ladder still drives the RESIDENT directly, one layer inward, and says so
    /// in its own header.)
    ///
    /// WIRE WRAPPER. The authority-bearing implementation is
    /// `ResidentLedgerAuthorityChirho::accept_new_winner_term_chirho` — a different name at this
    /// seam, unlike the release pair, so no census trap here.
    #[allow(
        dead_code,
        reason = "D3's release path is the trigger for the lawful advance; this brick wires the command, dispatch, and resident entry"
    )]
    pub fn advance_gd7_sink_term_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        adopted_checkpoint_ref_chirho: &str,
    ) -> Result<u64, ResidentLedgerAuthorityRefusalChirho> {
        let sender_chirho = self.command_sender_chirho.as_ref().ok_or_else(|| {
            ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho {
                detail_chirho: "resident effect-journal actor is already closed".to_owned(),
            }
        })?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::AdvanceGd7SinkTermChirho {
                    observation_chirho: Box::new(observation_chirho.clone()),
                    adopted_checkpoint_ref_chirho: adopted_checkpoint_ref_chirho.to_owned(),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|error_chirho| {
                ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho {
                detail_chirho: "resident effect-journal actor stopped before advance reply"
                    .to_owned(),
            }
        })?
    }

    /// Carry one provider-observed compensation to `CompletedChirho` through its fenced append.
    ///
    /// Same frontier as [`Self::advance_gd7_sink_term_chirho`]: the leg itself is production-
    /// compiled, and `record_gd7_journal_receipt_chirho` / `mark_gd7_obligation_completed_chirho`
    /// now have a production caller for the first time. R4's composition surface owns the trigger.
    ///
    /// MEASURED THROUGH THE REAL MAILBOX, AND IT NOW REACHES `CompletedChirho`.
    /// `harness1_gd7_mailbox_tests_chirho` proves a refusal travels the whole wire; the capstone
    /// arms (`harness1_compensated_terminal_arms_chirho`) drive THIS method against a real
    /// PROVIDER-OBSERVED obligation with the strand lifted and the hold released.
    ///
    /// Two steps closed the path that this comment previously described as open: the post-adoption
    /// resume step (`020dac08`), and the winner-own-term sink-cell advance. On the WINNER,
    /// `route_a_winner_reaches_completed_after_the_winner_own_term_cell_advance_chirho` now drives
    /// this method to `CompletedChirho`, with the bound receipt equal to the winner's new tail
    /// record digest and an exact replay owing no second append. On the HELD root the arm still
    /// refuses, by design: ruled (a) deliberately gives the deposed root no way to carry the
    /// compensation, so the post-commit winner-first-record refusal there is fork-detection working.
    ///
    /// **SCOPE, and it is the only reason to keep reading carefully:** that is LOCAL PROOF on a
    /// fixture world — two in-test roots and an in-test provider on one machine. Nothing here has
    /// run against a hosted deployment, and no hosted claim changes because of it. Read these arms
    /// as a locally proven completed-compensation path, never as a live one.
    #[allow(
        dead_code,
        reason = "R4's composition surface is the trigger; this brick wires the command, dispatch, and completed leg"
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "the five obligation coordinates plus the compensation append inputs are one fixed request shape"
    )]
    pub fn complete_gd7_compensation_chirho(
        &self,
        mint_identity_digest_chirho: &str,
        obligation_receipt_ref_chirho: &str,
        canonical_obligation_digest_chirho: &str,
        inverse_authority_ref_chirho: &str,
        action_idempotency_key_chirho: &str,
        canonical_intent_line_chirho: &str,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<
        crate::reconciliation_chirho::Gd7ObligationProcessingStateChirho,
        Gd7CompensationCompletionRefusalChirho,
    > {
        let sender_chirho = self.command_sender_chirho.as_ref().ok_or_else(|| {
            Gd7CompensationCompletionRefusalChirho::ProviderChirho(
                Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                    detail_chirho: "resident effect-journal actor is already closed".to_owned(),
                },
            )
        })?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::CompleteGd7CompensationChirho {
                    mint_identity_digest_chirho: mint_identity_digest_chirho.to_owned(),
                    obligation_receipt_ref_chirho: obligation_receipt_ref_chirho.to_owned(),
                    canonical_obligation_digest_chirho: canonical_obligation_digest_chirho
                        .to_owned(),
                    inverse_authority_ref_chirho: inverse_authority_ref_chirho.to_owned(),
                    action_idempotency_key_chirho: action_idempotency_key_chirho.to_owned(),
                    canonical_intent_line_chirho: canonical_intent_line_chirho.to_owned(),
                    authorization_chirho: authorization_chirho.clone(),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|error_chirho| {
                Gd7CompensationCompletionRefusalChirho::ProviderChirho(
                    Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            Gd7CompensationCompletionRefusalChirho::ProviderChirho(
                Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                    detail_chirho: "resident effect-journal actor stopped before completion reply"
                        .to_owned(),
                },
            )
        })?
    }

    /// Create-or-load one obligation's processing row and take it one bounded provider step.
    ///
    /// MOVED HERE AND WIDENED, and both halves matter. It used to sit in the actor module as
    /// `pub(crate)` under a `dead_code` allow reading "the public composition caller is wired by
    /// the later GD7 actor integration surface". This IS that moment: the caller is the success
    /// ladder's route to a lawfully held obligation, and it lives in
    /// `cairn-ledger-regenesis-chirho` — the custody-verified world DOWNSTREAM of this crate,
    /// exactly the crate-boundary situation this module's header describes for its four siblings.
    /// So the allow died by consumption rather than by suppression, and the method joins the
    /// production caller census in `cairn-source-scan-chirho` (four needles became five) in the
    /// same commit that widened it — the watch replaces the visibility signal, as ruled.
    ///
    /// # WHAT IT DOES WHEN NO PROVIDER IS CONFIGURED, WHICH IS PRODUCTION'S DEFAULT
    ///
    /// The actor wires `RefusingGd7CompensationProviderChirho` at every opener site, and its
    /// dedup retention is `Duration::ZERO`. So the first call persists the provider INTENT and
    /// refuses `ProviderNotConfiguredChirho`; the second finds the resume window already elapsed,
    /// refuses `ResumeWindowExpiredChirho`, and marks the obligation `HeldManualChirho` on its way
    /// out. That is not a degenerate path — it is the system's designed answer to "no compensation
    /// provider exists and the retry window has closed": stop trying, and hold it for an operator
    /// whose authority is checked against the signed roster at READ time.
    pub fn compose_gd7_compensation_chirho(
        &self,
        mint_identity_digest_chirho: &str,
        obligation_receipt_ref_chirho: &str,
        canonical_obligation_digest_chirho: &str,
        inverse_authority_ref_chirho: &str,
        action_idempotency_key_chirho: &str,
        bounded_payload_chirho: &[u8],
    ) -> Result<
        crate::reconciliation_chirho::Gd7ObligationProcessingStateChirho,
        Gd7CompensationCompositionRefusalChirho,
    > {
        let sender_chirho = self.command_sender_chirho.as_ref().ok_or_else(|| {
            Gd7CompensationCompositionRefusalChirho::ProviderChirho(
                Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                    detail_chirho: "resident effect-journal actor is already closed".to_owned(),
                },
            )
        })?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::ComposeGd7CompensationChirho {
                    mint_identity_digest_chirho: mint_identity_digest_chirho.to_owned(),
                    obligation_receipt_ref_chirho: obligation_receipt_ref_chirho.to_owned(),
                    canonical_obligation_digest_chirho: canonical_obligation_digest_chirho
                        .to_owned(),
                    inverse_authority_ref_chirho: inverse_authority_ref_chirho.to_owned(),
                    action_idempotency_key_chirho: action_idempotency_key_chirho.to_owned(),
                    bounded_payload_chirho: bounded_payload_chirho.to_vec(),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|error_chirho| {
                Gd7CompensationCompositionRefusalChirho::ProviderChirho(
                    Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                        detail_chirho: error_chirho.to_string(),
                    },
                )
            })?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            Gd7CompensationCompositionRefusalChirho::ProviderChirho(
                Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                    detail_chirho: "resident effect-journal actor stopped before composition reply"
                        .to_owned(),
                },
            )
        })?
    }

    /// Verify and certify the exact GD7 world inside the resident actor.
    ///
    /// This is a read-only verifier operation: it derives a signed v2 certificate from the
    /// actor-owned custody and conservation provider and never accepts caller-supplied authority.
    pub fn converge_and_certify_gd7_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        checkpoint_ref_chirho: &str,
        binding_chirho: crate::reconciliation_chirho::Gd7ConvergenceBindingInputChirho,
        unmeasured_chirho: crate::reconciliation_chirho::Gd7ConvergenceUnmeasuredPredicatesChirho,
    ) -> Result<ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
        let sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(Gd7PlanRefusalChirho::StorageChirho)?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::ConvergeAndCertifyGd7Chirho {
                    observation_chirho: Box::new(observation_chirho.clone()),
                    checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
                    binding_chirho,
                    unmeasured_chirho,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?
    }

    /// Persist the held-signed converged-import row for a TRANSFERRED winner compensation record, so
    /// a later `converge_and_certify_gd7_chirho` certifies the deposed compensated obligation.
    ///
    /// The record line is re-verified inside the resident actor with the held node's own authority;
    /// this handle passes only the transferred bytes and derives no authority from them. Returns the
    /// verified receipt digest the persisted row binds.
    pub fn import_converged_compensation_receipt_gd7_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        checkpoint_ref_chirho: &str,
        winner_compensation_record_line_chirho: &str,
    ) -> Result<String, Gd7PlanRefusalChirho> {
        let sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(Gd7PlanRefusalChirho::StorageChirho)?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::ImportConvergedCompensationReceiptGd7Chirho {
                    observation_chirho: Box::new(observation_chirho.clone()),
                    checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
                    winner_compensation_record_line_chirho: winner_compensation_record_line_chirho
                        .to_owned(),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?;
        reply_receiver_chirho
            .recv()
            .map_err(|_| Gd7PlanRefusalChirho::StorageChirho)?
    }
}
