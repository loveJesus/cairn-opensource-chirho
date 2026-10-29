// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Bounded newest-to-anchor reduction and inductive GD7 plan sealing.

mod authority_chirho;
mod conservation_chirho;
mod contract_chirho;
mod converged_import_chirho;
mod evidence_adapter_chirho;
mod marker_chirho;
mod object_chirho;
mod obligation_mint_chirho;
pub(crate) mod obligation_processing_chirho;
pub mod operator_roster_chirho;
mod reducer_chirho;

#[cfg(test)]
pub(crate) use authority_chirho::{
    converged_read_replica_for_release_test_chirho, sign_converged_read_replica_for_test_chirho,
    signed_converged_read_replica_for_release_test_chirho,
};
pub use authority_chirho::{
    load_verified_gd7_converged_read_replica_chirho, verify_gd7_convergence_chirho,
    verify_signed_gd7_converged_read_replica_chirho, ConvergedReadReplicaChirho,
    Gd7ConvergenceBindingInputChirho, Gd7ConvergenceTerminalEvidenceChirho,
    Gd7ConvergenceUnmeasuredPredicatesChirho, VerifiedGd7SealedPlanProofChirho,
    GD7_CONVERGED_READ_REPLICA_SCHEMA_V1_CHIRHO, GD7_CONVERGED_READ_REPLICA_SCHEMA_V2_CHIRHO,
};
pub(crate) use authority_chirho::{
    verify_gd7_sealed_plan_obligation_at_checkpoint_chirho,
    verify_sealed_gd7_reconciliation_plan_chirho,
};
pub use conservation_chirho::{
    gd7_conservation_snapshot_signed_content_line_chirho, Gd7ConservationEvidenceChirho,
    Gd7ConservationProofPortsChirho, Gd7ConservationSnapshotProviderChirho,
    Gd7ConservationSnapshotProviderRefChirho, Gd7ConservationSnapshotSourcePortChirho,
    Gd7ConservationSnapshotVerifierPortChirho, SignedGd7ConservationSnapshotChirho,
    GD7_CONSERVATION_SNAPSHOT_SCHEMA_V1_CHIRHO,
};
pub use contract_chirho::{
    Gd7EffectEvidenceReaderPortChirho, Gd7EffectLineageChirho, Gd7EffectPlanObligationChirho,
    Gd7EffectPlanObligationKindChirho, Gd7PlanPageDriveOutcomeChirho, Gd7PlanPageFactCountsChirho,
    Gd7PlanRefusalChirho, Gd7ReconciliationPlanPageChirho, Gd7TerminalDispositionChirho,
    Gd7TerminalMarkerChirho, VerifiedGd7ReconciliationPlanPageChirho,
    VerifiedGd7TerminalMarkerChirho, GD7_RECONCILIATION_PLAN_PAGE_SCHEMA_V1_CHIRHO,
    GD7_TERMINAL_MARKER_SCHEMA_V1_CHIRHO, MAX_GD7_EFFECT_INTENT_LINE_BYTES_CHIRHO,
    MAX_GD7_EFFECT_TERMINAL_LINE_BYTES_CHIRHO, MAX_GD7_RECONCILIATION_PLAN_PAGE_BYTES_CHIRHO,
    MAX_GD7_TERMINAL_MARKER_BYTES_CHIRHO,
};
pub(crate) use converged_import_chirho::import_converged_compensation_receipt_over_population_chirho;
pub use evidence_adapter_chirho::RootGd7EffectEvidenceReaderChirho;
pub use marker_chirho::gd7_terminal_marker_path_chirho;
pub use object_chirho::gd7_reconciliation_plan_page_path_chirho;
#[cfg(test)]
pub(crate) use obligation_mint_chirho::verified_gd7_sealed_plan_obligation_for_test_chirho;
pub(crate) use obligation_mint_chirho::{
    claim_verified_gd7_losing_effect_obligation_chirho, VerifiedGd7SealedPlanObligationChirho,
};
pub use obligation_mint_chirho::{
    gd7_losing_effect_obligation_mint_receipt_path_chirho,
    Gd7LosingEffectObligationMintRefusalChirho, Gd7LosingEffectObligationSelectorChirho,
    Gd7LosingEffectObligationTerminalStateChirho, MintedGd7LosingEffectObligationChirho,
};
pub use reducer_chirho::{
    drive_gd7_reconciliation_plan_page_chirho, load_verified_gd7_reconciliation_plan_page_chirho,
    Gd7EffectProofPortsChirho,
};

#[cfg(test)]
mod tests_chirho;
