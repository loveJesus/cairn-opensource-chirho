// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable GD7 reconciliation evidence and held state for resident and later coordinators.
//!
//! This slice authenticates the exact local committed tail plus winner term-first index/witness,
//! installs a signed `ObservedHeld` checkpoint, and can persist one bounded losing-manifest page per
//! restart-stable transition. A paired bounded reducer can classify one page, persist signed
//! terminal markers, inductively seal the exact plan at the fork anchor, and reverify the complete
//! linked plan read-only before adoption. The geo-node composition now transports the initial
//! observation, drives the bounded transitions through `PlanSealed`, and can atomically select one
//! restart-reverified Cut A journal/projection pair as `AdoptedHeld` while retaining the fixed group
//! head. This module still cannot move served or application refs, compensate, release the winner
//! barrier, converge membership, or re-enable writes.

mod contract_chirho;
mod current_view_chirho;
mod manifest_chirho;
mod observer_chirho;
mod plan_chirho;
mod signer_adapter_chirho;
pub mod sink_term_fence_chirho;
mod store_chirho;
mod winner_witness_chirho;

pub use plan_chirho::load_verified_gd7_converged_read_replica_chirho;
pub use plan_chirho::obligation_processing_chirho::dispose_gd7_obligation_held_manual_chirho;
pub use plan_chirho::obligation_processing_chirho::load_gd7_obligation_processing_for_display_chirho;
pub use plan_chirho::obligation_processing_chirho::load_gd7_obligation_processing_state_chirho;
/// `Gd7ObligationProcessingRefusalChirho` is `pub` here and NOT `pub(crate)`, deliberately.
///
/// It is the payload of the public `dispose_gd7_obligation_held_manual_chirho`'s error and of
/// `Gd7CompensationCompositionRefusalChirho::ProcessingChirho`, so an out-of-crate operator caller
/// already RECEIVES these values — it simply could not name them. That is the precise shape the
/// fleet has ruled against on this path: a caller that cannot name an error cannot assert WHICH
/// refusal fired, and here the difference between `StateCollisionChirho` (already disposed — do not
/// retry) and `InvalidStateChirho` (the disposition does not bind this row) is the difference
/// between a safe replay and a silent authority failure. Widening an error enum grants no
/// capability: every producer of these values stays crate-internal.
pub use plan_chirho::obligation_processing_chirho::Gd7ObligationProcessingRefusalChirho;
pub(crate) use plan_chirho::obligation_processing_chirho::{
    create_or_load_gd7_obligation_processing_state_chirho, mark_gd7_obligation_completed_chirho,
    mark_gd7_obligation_held_manual_chirho, prepare_gd7_provider_resume_chirho,
    record_gd7_journal_receipt_chirho, record_gd7_provider_intent_chirho,
    record_gd7_provider_observation_chirho, Gd7ObligationProcessingStateChirho,
};
pub use plan_chirho::obligation_processing_chirho::{
    Gd7HeldManualClassificationChirho, Gd7HeldManualDispositionChirho,
    Gd7ObligationTerminalProgressChirho,
};
#[cfg(test)]
pub(crate) use plan_chirho::sign_converged_read_replica_for_test_chirho;
#[cfg(test)]
pub(crate) use plan_chirho::signed_converged_read_replica_for_release_test_chirho;

/// Shared shape validators, so a sibling module binds identities with the SAME predicates the
/// store does rather than growing a second, quietly divergent notion of a valid digest or label.
pub(crate) use contract_chirho::{
    consistency_group_digest_suffix_chirho, is_bounded_label_chirho, is_lower_hex_digest_chirho,
    validate_key_and_signature_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO,
};
pub use contract_chirho::{
    Gd7AdoptionCheckpointBindingChirho, Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationHeadChirho,
    Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    GD7_ADOPTION_CHECKPOINT_BINDING_SCHEMA_V1_CHIRHO,
    GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO,
    MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO, MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO,
};
pub use current_view_chirho::{
    build_gd7_winner_evidence_manifest_chirho, fetch_gd7_winner_evidence_page_chirho,
    gd7_fork_baseline_page_path_chirho, gd7_fork_baseline_root_path_chirho,
    gd7_held_evidence_transfer_checkpoint_path_chirho, gd7_held_evidence_transfer_head_path_chirho,
    gd7_held_evidence_transfer_identity_digest_chirho,
    gd7_held_view_transfer_checkpoint_path_chirho, gd7_held_view_transfer_head_path_chirho,
    gd7_held_view_transfer_received_page_path_chirho, gd7_read_only_branch_checkpoint_path_chirho,
    gd7_read_only_branch_head_path_chirho, gd7_read_only_branch_prefix_page_path_chirho,
    gd7_read_only_branch_prefix_root_path_chirho, gd7_winner_current_view_path_chirho,
    gd7_winner_handoff_attempt_digest_chirho, gd7_winner_handoff_checkpoint_path_chirho,
    gd7_winner_handoff_head_path_chirho, gd7_winner_history_cursor_path_chirho,
    gd7_winner_history_page_path_chirho, gd7_winner_history_root_path_chirho,
    gd7_winner_view_bundle_root_path_chirho, generate_gd7_winner_current_view_challenge_chirho,
    inspect_challenged_gd7_winner_current_view_chirho, load_verified_gd7_fork_baseline_root_chirho,
    load_verified_gd7_winner_history_root_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho,
    verify_complete_gd7_fork_baseline_chirho,
    verify_complete_gd7_held_view_transfer_checkpoint_chirho,
    verify_complete_gd7_held_winner_view_chain_chirho,
    verify_complete_gd7_winner_history_chain_chirho,
    verify_fresh_gd7_held_winner_view_evidence_chirho, verify_gd7_winner_evidence_manifest_chirho,
    verify_gd7_winner_evidence_page_transfer_chirho, ActiveGd7HeldEvidenceTransferChirho,
    ActiveGd7HeldViewTransferChirho, ActiveGd7ReadOnlyBranchChirho, ActiveGd7WinnerHandoffChirho,
    CommittedGd7HeldViewTransferChirho, CommittedGd7WinnerHandoffChirho,
    Gd7AccountNetCompositionRefusalChirho, Gd7ForkBaselineIdentityChirho,
    Gd7ForkBaselineRefusalChirho, Gd7ForkBaselineRootChirho,
    Gd7HeldEvidenceTransferCheckpointChirho, Gd7HeldEvidenceTransferHeadChirho,
    Gd7HeldEvidenceTransferIdentityChirho, Gd7HeldEvidenceTransferPhaseChirho,
    Gd7HeldEvidenceTransferStoreChirho, Gd7HeldEvidenceTransferStoreRefusalChirho,
    Gd7HeldViewTransferCheckpointChirho, Gd7HeldViewTransferHeadChirho,
    Gd7HeldViewTransferIdentityChirho, Gd7HeldViewTransferPhaseChirho,
    Gd7HeldViewTransferStaleReasonChirho, Gd7HeldViewTransferStoreChirho,
    Gd7HeldViewTransferStoreRefusalChirho, Gd7HeldWinnerViewVerificationRefusalChirho,
    Gd7ReadOnlyBranchCheckpointChirho, Gd7ReadOnlyBranchHeadChirho,
    Gd7ReadOnlyBranchPrefixRootChirho, Gd7ReadOnlyBranchRefusalChirho,
    Gd7WinnerCurrentViewChallengeChirho, Gd7WinnerCurrentViewEvidenceChirho,
    Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho,
    Gd7WinnerEvidenceFamilyChirho, Gd7WinnerEvidenceManifestChirho,
    Gd7WinnerEvidencePageGrantChirho, Gd7WinnerEvidencePageTransferChirho,
    Gd7WinnerEvidenceTransferRefusalChirho, Gd7WinnerHandoffAttemptIdentityChirho,
    Gd7WinnerHandoffCheckpointChirho, Gd7WinnerHandoffCommitOutcomeChirho,
    Gd7WinnerHandoffHeadChirho, Gd7WinnerHandoffPhaseChirho, Gd7WinnerHandoffStoreChirho,
    Gd7WinnerHandoffStoreRefusalChirho, Gd7WinnerHistoryIdentityChirho,
    Gd7WinnerHistoryRefusalChirho, Gd7WinnerHistoryRestartChirho, Gd7WinnerHistoryRootChirho,
    Gd7WinnerHistoryStageOutcomeChirho, Gd7WinnerViewBundleRestartChirho,
    Gd7WinnerViewBundleRootChirho, Gd7WinnerViewBundleStageOutcomeChirho,
    Gd7WinnerViewPageGrantChirho, Gd7WinnerViewPageTransferChirho,
    IssuedGd7WinnerCurrentViewChallengeChirho, PreparedGd7ReadOnlyBranchChirho,
    VerifiedGd7AccountNetCompositionChirho, VerifiedGd7ForkBaselineChirho,
    VerifiedGd7ForkBaselineRootChirho, VerifiedGd7HeldWinnerViewChainChirho,
    VerifiedGd7HeldWinnerViewFreshnessEvidenceChirho, VerifiedGd7ReadOnlyBranchChirho,
    VerifiedGd7WinnerHistoryChainChirho, VerifiedGd7WinnerHistoryRootChirho,
    VerifiedGd7WinnerViewBundleRootChirho, GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO,
    GD7_FORK_BASELINE_ROOT_SCHEMA_V1_CHIRHO,
    GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_HELD_EVIDENCE_TRANSFER_HEAD_SCHEMA_V1_CHIRHO,
    GD7_HELD_VIEW_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_HELD_VIEW_TRANSFER_HEAD_SCHEMA_V1_CHIRHO, GD7_READ_ONLY_BRANCH_CHECKPOINT_SCHEMA_V1_CHIRHO,
    GD7_READ_ONLY_BRANCH_HEAD_SCHEMA_V1_CHIRHO, GD7_READ_ONLY_BRANCH_PREFIX_ROOT_SCHEMA_V1_CHIRHO,
    GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO,
    GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO,
    GD7_WINNER_EVIDENCE_MANIFEST_SCHEMA_V1_CHIRHO, GD7_WINNER_EVIDENCE_PAGE_GRANT_SCHEMA_V1_CHIRHO,
    GD7_WINNER_HANDOFF_CHECKPOINT_SCHEMA_V1_CHIRHO, GD7_WINNER_HANDOFF_HEAD_SCHEMA_V1_CHIRHO,
    GD7_WINNER_HISTORY_ROOT_SCHEMA_V1_CHIRHO, GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO,
    GD7_WINNER_VIEW_PAGE_GRANT_SCHEMA_V1_CHIRHO, MAX_GD7_FORK_BASELINE_PAGE_BYTES_CHIRHO,
    MAX_GD7_FORK_BASELINE_ROOT_BYTES_CHIRHO,
    MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_HELD_EVIDENCE_TRANSFER_HEAD_BYTES_CHIRHO,
    MAX_GD7_HELD_VIEW_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_HELD_VIEW_TRANSFER_HEAD_BYTES_CHIRHO, MAX_GD7_READ_ONLY_BRANCH_CHECKPOINT_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_HEAD_BYTES_CHIRHO, MAX_GD7_READ_ONLY_BRANCH_PREFIX_PAGE_BYTES_CHIRHO,
    MAX_GD7_READ_ONLY_BRANCH_PREFIX_ROOT_BYTES_CHIRHO,
    MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO,
    MAX_GD7_WINNER_CURRENT_VIEW_EVIDENCE_BYTES_CHIRHO,
    MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO, MAX_GD7_WINNER_EVIDENCE_PAGE_GRANT_BYTES_CHIRHO,
    MAX_GD7_WINNER_HANDOFF_CHECKPOINT_BYTES_CHIRHO, MAX_GD7_WINNER_HANDOFF_HEAD_BYTES_CHIRHO,
    MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO, MAX_GD7_WINNER_HISTORY_ROOT_BYTES_CHIRHO,
    MAX_GD7_WINNER_VIEW_BUNDLE_ROOT_BYTES_CHIRHO, MAX_GD7_WINNER_VIEW_PAGE_GRANT_BYTES_CHIRHO,
};
pub(crate) use current_view_chirho::{
    fetch_granted_gd7_winner_view_page_chirho, issue_first_gd7_winner_view_page_grant_chirho,
    seal_gd7_winner_current_view_chirho, seal_gd7_winner_current_view_during_handoff_chirho,
    stage_next_gd7_winner_view_bundle_page_chirho, Gd7WinnerJournalSnapshotChirho,
    Gd7WinnerViewPageFetchContextChirho,
};
pub use manifest_chirho::{
    drive_authenticated_losing_manifest_page_chirho, gd7_losing_manifest_cursor_path_chirho,
    gd7_losing_manifest_page_path_chirho, Gd7LosingManifestPageChirho,
    Gd7LosingManifestRecordChirho, Gd7ManifestPageBudgetChirho, Gd7ManifestPageDriveOutcomeChirho,
    Gd7ManifestRefusalChirho, VerifiedGd7LosingManifestPageChirho,
    GD7_LOSING_MANIFEST_PAGE_SCHEMA_V1_CHIRHO, MAX_GD7_LOSING_MANIFEST_PAGE_BYTES_CHIRHO,
};
pub use observer_chirho::ensure_authenticated_deposed_fork_observed_held_chirho;
#[cfg(test)]
pub(crate) use plan_chirho::converged_read_replica_for_release_test_chirho;
pub(crate) use plan_chirho::import_converged_compensation_receipt_over_population_chirho;
pub use plan_chirho::operator_roster_chirho::{
    write_gd7_operator_roster_chirho, Gd7OperatorRosterChirho, Gd7OperatorRosterMemberChirho,
    Gd7OperatorRosterRefusalChirho, Gd7OperatorRosterRoleChirho,
    GD7_OPERATOR_ROSTER_SCHEMA_V1_CHIRHO,
};
#[cfg(test)]
pub(crate) use plan_chirho::verified_gd7_sealed_plan_obligation_for_test_chirho;
pub(crate) use plan_chirho::verify_sealed_gd7_reconciliation_plan_chirho;
pub(crate) use plan_chirho::{
    claim_verified_gd7_losing_effect_obligation_chirho,
    verify_gd7_sealed_plan_obligation_at_checkpoint_chirho, VerifiedGd7SealedPlanObligationChirho,
};
pub use plan_chirho::{
    drive_gd7_reconciliation_plan_page_chirho,
    gd7_conservation_snapshot_signed_content_line_chirho,
    gd7_losing_effect_obligation_mint_receipt_path_chirho,
    gd7_reconciliation_plan_page_path_chirho, gd7_terminal_marker_path_chirho,
    load_verified_gd7_reconciliation_plan_page_chirho, verify_gd7_convergence_chirho,
    verify_signed_gd7_converged_read_replica_chirho, ConvergedReadReplicaChirho,
    Gd7ConservationEvidenceChirho, Gd7ConservationProofPortsChirho,
    Gd7ConservationSnapshotProviderChirho, Gd7ConservationSnapshotProviderRefChirho,
    Gd7ConservationSnapshotSourcePortChirho, Gd7ConservationSnapshotVerifierPortChirho,
    Gd7ConvergenceBindingInputChirho, Gd7ConvergenceTerminalEvidenceChirho,
    Gd7ConvergenceUnmeasuredPredicatesChirho, Gd7EffectEvidenceReaderPortChirho,
    Gd7EffectLineageChirho, Gd7EffectPlanObligationChirho, Gd7EffectPlanObligationKindChirho,
    Gd7EffectProofPortsChirho, Gd7LosingEffectObligationMintRefusalChirho,
    Gd7LosingEffectObligationSelectorChirho, Gd7LosingEffectObligationTerminalStateChirho,
    Gd7PlanPageDriveOutcomeChirho, Gd7PlanPageFactCountsChirho, Gd7PlanRefusalChirho,
    Gd7ReconciliationPlanPageChirho, Gd7TerminalDispositionChirho, Gd7TerminalMarkerChirho,
    MintedGd7LosingEffectObligationChirho, RootGd7EffectEvidenceReaderChirho,
    SignedGd7ConservationSnapshotChirho, VerifiedGd7ReconciliationPlanPageChirho,
    VerifiedGd7SealedPlanProofChirho, VerifiedGd7TerminalMarkerChirho,
    GD7_CONSERVATION_SNAPSHOT_SCHEMA_V1_CHIRHO, GD7_CONVERGED_READ_REPLICA_SCHEMA_V1_CHIRHO,
    GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO, GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO,
    GD7_TERMINAL_MARKER_SCHEMA_V1_CHIRHO, MAX_GD7_EFFECT_INTENT_LINE_BYTES_CHIRHO,
    MAX_GD7_EFFECT_TERMINAL_LINE_BYTES_CHIRHO, MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO,
    MAX_GD7_TERMINAL_MARKER_BYTES_CHIRHO,
};
pub use signer_adapter_chirho::{
    ExistingNodeGd7SignerChirho, PinnedGd7LedgerRecordVerifierChirho, PinnedNodeGd7VerifierChirho,
    PinnedTenantMigrationDestinationAuthorityChirho,
};
pub use store_chirho::{
    gd7_reconciliation_checkpoint_path_chirho, gd7_reconciliation_group_has_any_active_hold_chirho,
    gd7_reconciliation_group_head_path_chirho,
    gd7_reconciliation_group_ordinary_write_hold_path_chirho,
    gd7_reconciliation_group_ordinary_writes_withheld_chirho, gd7_reconciliation_head_path_chirho,
    gd7_reconciliation_identity_digest_chirho, inspect_gd7_reconciliation_released_state_chirho,
    load_authenticated_active_gd7_reconciliation_for_group_chirho,
    plant_gd7_ordinary_write_hold_chirho, remove_gd7_ordinary_write_hold_chirho,
    ActiveGd7ReconciliationChirho, CommittedGd7ReconciliationCheckpointChirho,
    Gd7ObservedHeldOutcomeChirho, Gd7ReconciliationReleasedStateChirho,
    Gd7ReconciliationStoreChirho, Gd7ReconciliationStoreRefusalChirho,
};
pub(crate) use store_chirho::{
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho,
    verify_and_retain_gd7_reconciliation_checkpoint_chirho,
};
pub use winner_witness_chirho::{
    winner_first_record_coordinate_digest_chirho, winner_first_record_path_chirho,
    winner_fork_witness_path_chirho, AuthenticatedGd7DeposedForkObservationChirho,
    Gd7WinnerFirstRecordIndexChirho, Gd7WinnerForkWitnessChirho, Gd7WinnerWitnessReaderChirho,
    Gd7WinnerWitnessRefusalChirho, Gd7WinnerWitnessStoreChirho,
    VerifiedGd7WinnerFirstRecordIndexChirho, VerifiedGd7WinnerForkWitnessChirho,
    GD7_WINNER_FIRST_RECORD_SCHEMA_V1_CHIRHO, GD7_WINNER_FORK_WITNESS_SCHEMA_V1_CHIRHO,
    MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO, MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO,
};
