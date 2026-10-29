// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fixed command contract for the resident effect-journal actor mailbox.
//!
//! Command execution remains in `command_dispatch_chirho.rs`; this module owns only the bounded
//! messages exchanged with the actor.

use super::super::{
    ResidentTestkindLossWitnessOutcomeChirho, ResidentTestkindLossWitnessPhaseChirho,
    ResidentTestkindLossWitnessRefusalChirho,
};
use super::gd7_compensation_composition_chirho::{
    Gd7CompensationCompositionRefusalChirho, Gd7CompensationProviderObservationChirho,
    Gd7CompensationProviderRefusalChirho,
};
use super::gd7_completed_leg_chirho::Gd7CompensationCompletionRefusalChirho;
use super::tenant_migration_operation_chirho::{
    ResidentTenantMigrationOperationCommandChirho, ResidentTenantMigrationOperationOutcomeChirho,
    ResidentTenantMigrationOperationRefusalChirho,
};
use super::winner_adoption_evidence_chirho::{
    ResidentGd7WinnerAdoptionEvidenceCommandChirho, ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
    ResidentGd7WinnerAdoptionEvidenceReplyChirho,
};
use super::winner_evidence_chirho::{
    ResidentGd7WinnerForkObservationChirho, ResidentGd7WinnerForkObservationRefusalChirho,
    ResidentGd7WinnerViewSealChirho, ResidentGd7WinnerViewStageInspectionChirho,
};
use super::winner_handoff_chirho::{
    ResidentGd7WinnerHandoffCommandChirho, ResidentGd7WinnerHandoffRefusalChirho,
    ResidentGd7WinnerHandoffStatusChirho,
};
use super::{
    ResidentEffectJournalResultChirho, ResidentLedgerAuthorityReadinessChirho,
    ResidentLedgerAuthorityRefusalChirho,
};
use crate::reconciliation_chirho::Gd7ObligationProcessingStateChirho;
use crate::reconciliation_chirho::{
    AuthenticatedGd7DeposedForkObservationChirho, ConvergedReadReplicaChirho,
    Gd7JournalTailCoordinateChirho, Gd7PlanPageDriveOutcomeChirho, Gd7PlanRefusalChirho,
    Gd7WinnerCurrentViewChallengeChirho, Gd7WinnerCurrentViewInspectionChirho,
    Gd7WinnerCurrentViewRefusalChirho, Gd7WinnerViewPageGrantChirho,
    Gd7WinnerViewPageTransferChirho, VerifiedGd7SealedPlanProofChirho,
};
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitContinuationViewChirho, EffectCommitJournalReceiptChirho,
    EffectIntentJournalStateChirho, VerifiedEffectReceiptInventoryEntryChirho,
};
use cairn_effect_commit_chirho::intent_chirho::EffectIntentJournalCutChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;

#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(super) enum ResidentEffectJournalCommandChirho {
    TestkindLossWitnessCurrentChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentTestkindLossWitnessOutcomeChirho,
                ResidentTestkindLossWitnessRefusalChirho,
            >,
        >,
    },
    TestkindLossWitnessSustainedChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentTestkindLossWitnessOutcomeChirho,
                ResidentTestkindLossWitnessRefusalChirho,
            >,
        >,
    },
    TestkindLossWitnessDeposedSinkChirho {
        phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentTestkindLossWitnessOutcomeChirho,
                ResidentTestkindLossWitnessRefusalChirho,
            >,
        >,
    },
    AppendHoldChirho {
        canonical_intent_line_chirho: String,
        reply_chirho:
            SyncSender<ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho>>,
    },
    AppendCompensationHoldChirho {
        canonical_intent_line_chirho: String,
        authorization_chirho: VerifiedEffectCompensationChirho,
        reply_chirho:
            SyncSender<ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho>>,
    },
    #[allow(
        dead_code,
        reason = "the composition command is exposed for the actor-owned R4 adapter seam"
    )]
    ExecuteGd7CompensationProviderChirho {
        canonical_obligation_digest_chirho: String,
        action_idempotency_key_chirho: String,
        bounded_payload_chirho: Vec<u8>,
        reply_chirho: SyncSender<
            std::result::Result<
                Gd7CompensationProviderObservationChirho,
                Gd7CompensationProviderRefusalChirho,
            >,
        >,
    },
    #[allow(
        dead_code,
        reason = "the actor composition command is the typed R4 dispatch seam"
    )]
    ComposeGd7CompensationChirho {
        mint_identity_digest_chirho: String,
        obligation_receipt_ref_chirho: String,
        canonical_obligation_digest_chirho: String,
        inverse_authority_ref_chirho: String,
        action_idempotency_key_chirho: String,
        bounded_payload_chirho: Vec<u8>,
        reply_chirho: SyncSender<
            std::result::Result<
                Gd7ObligationProcessingStateChirho,
                Gd7CompensationCompositionRefusalChirho,
            >,
        >,
    },
    #[allow(
        dead_code,
        reason = "constructed by advance_gd7_sink_term_chirho, whose trigger is D3's release path"
    )]
    /// Advance this group's sink winner-term cell under verified revoke evidence.
    ///
    /// This is the actor seam for the D2 lawful mid-life advance — the command that lifts the
    /// compensation fence after a term bump stranded it. The winner term is NOT a field: it is
    /// read out of the signed observation inside the operation, so a caller cannot name the term
    /// it wants accepted. The observation is boxed because it carries a full signed witness and
    /// would otherwise dominate every other variant's size.
    AdvanceGd7SinkTermChirho {
        observation_chirho: Box<AuthenticatedGd7DeposedForkObservationChirho>,
        adopted_checkpoint_ref_chirho: String,
        reply_chirho: SyncSender<std::result::Result<u64, ResidentLedgerAuthorityRefusalChirho>>,
    },
    #[allow(
        dead_code,
        reason = "D3's actor integration harness is the first consumer of the release command"
    )]
    ReleaseConvergedGd7HoldChirho {
        adopted_checkpoint_ref_chirho: String,
        convergence_chirho: Box<ConvergedReadReplicaChirho>,
        reply_chirho: SyncSender<std::result::Result<(), ResidentLedgerAuthorityRefusalChirho>>,
    },
    #[allow(
        dead_code,
        reason = "constructed by complete_gd7_compensation_chirho, whose trigger is R4's composition surface"
    )]
    /// Carry one provider-observed compensation to `CompletedChirho` through its fenced append.
    ///
    /// Carries its own Result type, following the `ComposeGd7CompensationChirho` precedent: the
    /// completion's natural refusal distinguishes a fence strand from a state-machine fault, and
    /// collapsing it into the journal port error would erase that distinction.
    CompleteGd7CompensationChirho {
        mint_identity_digest_chirho: String,
        obligation_receipt_ref_chirho: String,
        canonical_obligation_digest_chirho: String,
        inverse_authority_ref_chirho: String,
        action_idempotency_key_chirho: String,
        canonical_intent_line_chirho: String,
        authorization_chirho: VerifiedEffectCompensationChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                Gd7ObligationProcessingStateChirho,
                Gd7CompensationCompletionRefusalChirho,
            >,
        >,
    },
    AppendTerminalChirho {
        canonical_intent_line_chirho: String,
        canonical_terminal_line_chirho: String,
        reply_chirho:
            SyncSender<ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho>>,
    },
    ActiveHoldIntentRefsChirho {
        reply_chirho: SyncSender<ResidentEffectJournalResultChirho<Vec<DigestChirho>>>,
    },
    ReceiptByIntentRefChirho {
        intent_ref_chirho: DigestChirho,
        reply_chirho:
            SyncSender<ResidentEffectJournalResultChirho<Option<EffectIntentJournalStateChirho>>>,
    },
    EffectIntentCutChirho {
        reply_chirho: SyncSender<ResidentEffectJournalResultChirho<EffectIntentJournalCutChirho>>,
    },
    CurrentContinuationChirho {
        kind_id_chirho: AssetKindIdChirho,
        reply_chirho: SyncSender<
            ResidentEffectJournalResultChirho<Option<EffectCommitContinuationViewChirho>>,
        >,
    },
    VerifiedReceiptInventoryChirho {
        reply_chirho: SyncSender<
            ResidentEffectJournalResultChirho<Vec<VerifiedEffectReceiptInventoryEntryChirho>>,
        >,
    },
    DriveGd7PlanPageChirho {
        observation_chirho: Box<AuthenticatedGd7DeposedForkObservationChirho>,
        expected_checkpoint_ref_chirho: String,
        reply_chirho:
            SyncSender<std::result::Result<Gd7PlanPageDriveOutcomeChirho, Gd7PlanRefusalChirho>>,
    },
    VerifyGd7SealedPlanChirho {
        observation_chirho: Box<AuthenticatedGd7DeposedForkObservationChirho>,
        expected_checkpoint_ref_chirho: String,
        reply_chirho:
            SyncSender<std::result::Result<VerifiedGd7SealedPlanProofChirho, Gd7PlanRefusalChirho>>,
    },
    ConvergeAndCertifyGd7Chirho {
        observation_chirho: Box<AuthenticatedGd7DeposedForkObservationChirho>,
        checkpoint_ref_chirho: String,
        binding_chirho: crate::reconciliation_chirho::Gd7ConvergenceBindingInputChirho,
        unmeasured_chirho: crate::reconciliation_chirho::Gd7ConvergenceUnmeasuredPredicatesChirho,
        reply_chirho:
            SyncSender<std::result::Result<ConvergedReadReplicaChirho, Gd7PlanRefusalChirho>>,
    },
    ImportConvergedCompensationReceiptGd7Chirho {
        observation_chirho: Box<AuthenticatedGd7DeposedForkObservationChirho>,
        checkpoint_ref_chirho: String,
        winner_compensation_record_line_chirho: String,
        reply_chirho: SyncSender<std::result::Result<String, Gd7PlanRefusalChirho>>,
    },
    ProbeGd7WinnerChirho {
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentLedgerAuthorityReadinessChirho,
                ResidentLedgerAuthorityRefusalChirho,
            >,
        >,
    },
    ObserveGd7DeposedForkChirho {
        expected_winner_term_chirho: u64,
        held_node_chirho: NodeIdChirho,
        losing_journal_genesis_digest_chirho: String,
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho,
        cancellation_chirho: Arc<AtomicBool>,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7WinnerForkObservationChirho,
                ResidentGd7WinnerForkObservationRefusalChirho,
            >,
        >,
    },
    StageGd7WinnerViewPageChirho {
        expected_stage_index_chirho: Option<u64>,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7WinnerViewStageInspectionChirho,
                Gd7WinnerCurrentViewRefusalChirho,
            >,
        >,
    },
    IssueFirstGd7WinnerViewPageGrantChirho {
        held_node_chirho: NodeIdChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                Option<Gd7WinnerViewPageGrantChirho>,
                Gd7WinnerCurrentViewRefusalChirho,
            >,
        >,
    },
    FetchGrantedGd7WinnerViewPageChirho {
        requester_chirho: NodeIdChirho,
        grant_chirho: Gd7WinnerViewPageGrantChirho,
        reply_chirho: SyncSender<
            std::result::Result<Gd7WinnerViewPageTransferChirho, Gd7WinnerCurrentViewRefusalChirho>,
        >,
    },
    SealGd7WinnerCurrentViewChirho {
        challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                Gd7WinnerCurrentViewInspectionChirho,
                Gd7WinnerCurrentViewRefusalChirho,
            >,
        >,
    },
    SealGd7WinnerCurrentViewForHeldChirho {
        challenge_chirho: Gd7WinnerCurrentViewChallengeChirho,
        held_node_chirho: NodeIdChirho,
        reply_chirho: SyncSender<
            std::result::Result<ResidentGd7WinnerViewSealChirho, Gd7WinnerCurrentViewRefusalChirho>,
        >,
    },
    Gd7WinnerHandoffChirho {
        command_chirho: ResidentGd7WinnerHandoffCommandChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7WinnerHandoffStatusChirho,
                ResidentGd7WinnerHandoffRefusalChirho,
            >,
        >,
    },
    Gd7WinnerAdoptionEvidenceChirho {
        command_chirho: ResidentGd7WinnerAdoptionEvidenceCommandChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentGd7WinnerAdoptionEvidenceReplyChirho,
                ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
            >,
        >,
    },
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "crate-private until target activation can consume the migration mailbox"
        )
    )]
    TenantMigrationOperationChirho {
        command_chirho: ResidentTenantMigrationOperationCommandChirho,
        reply_chirho: SyncSender<
            std::result::Result<
                ResidentTenantMigrationOperationOutcomeChirho,
                ResidentTenantMigrationOperationRefusalChirho,
            >,
        >,
    },
    ShutdownChirho,
}
