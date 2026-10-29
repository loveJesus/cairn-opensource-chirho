// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Driven host adapters for the ledger ports.
//!
//! This crate is the downward-only H1 boundary from the CF6 regenesis workflow. It owns
//! filesystem, clock, secret-backed signer mechanics, and fail-closed read-only authority views.
//! One reviewed H3 activation capsule consumes a dedicated offline signature and elected local
//! handle to author the initial journal. Serving may reopen only that existing authority behind one
//! bounded process-resident actor and expose its neutral effect-journal port. This crate does not
//! author policy, discover ambient configuration, or own server lifecycle.

pub use cairn_ledger_authority_chirho as authority_chirho;
pub mod clock_chirho;
pub mod custody_chirho;
#[cfg(test)]
mod elected_authority_chirho;
pub use cairn_ledger_elected_head_transition_chirho as elected_head_transition_chirho;
pub mod reconciliation_chirho;
mod resident_authority_chirho;
mod resident_ledger_identity_chirho;
pub mod shadow_canary_report_chirho;
pub mod signer_chirho;
pub mod test_kind_fence_chirho;
/// The filesystem storage adapter, EXTRACTED to `cairn-ledger-host-storage-chirho` (lane-D wave 1,
/// stone 1) and re-bound here under its original path.
///
/// The alias is deliberate: every `crate::storage_chirho::…` inside this crate keeps resolving, so
/// the move stays a move. It is not concealment — the crate boundary is real and its consequences
/// are pinned by `storage_custody_exports_have_no_external_consumer_chirho` in the source-scan
/// suite, because a boundary cannot carry `pub(crate)` and the custody surface would otherwise have
/// widened silently.
pub use cairn_ledger_host_storage_chirho as storage_chirho;

pub use authority_chirho::{
    ClosedMintBurnAuthorityChirho, ElectedClusterMembershipChirho,
    HostLedgerAuthorityRefusalChirho, PinnedKindIssuerVerifierChirho,
    PinnedLedgerActivationVerifierChirho, PlatformPolicyMintAuthorityChirho,
    StaticClusterMembershipChirho,
};
/// Re-exported so the serve runtime can NAME an externally signed destination authorization
/// without taking a dependency on the durable-migration crate. The value crosses this boundary; the
/// authority to mint one does not — that port verifies and cannot sign.
///
/// The intent shape, its digest and the exact signed message travel with it so an OPERATOR-side
/// tool can mint one without either crate becoming a new dependency edge of the drill binary. Note
/// what is deliberately NOT here: nothing that signs. The signing key is the operator's.
pub use cairn_ledger_tenant_migration_chirho::VerifiedTenantMigrationRootChirho;
pub use cairn_ledger_tenant_migration_durable_chirho::{
    tenant_migration_destination_intent_digest_chirho,
    unsigned_tenant_migration_destination_message_chirho, TenantMigrationDestinationIntentChirho,
    TenantMigrationDestinationRecordChirho, TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO,
};
pub use clock_chirho::{ResidentLedgerClockChirho, SystemLedgerClockChirho};
pub use custody_chirho::{
    inspect_host_ledger_signer_custody_chirho, verify_host_ledger_config_custody_chirho,
    HostLedgerConfigCustodyRefusalChirho, HostLedgerSignerCustodyInventoryChirho,
    LedgerSignerSecretPostureChirho,
};
pub use elected_head_transition_chirho::{
    ElectedHeadTransitionAdapterChirho, ElectedHeadTransitionRefusalChirho,
};
pub use resident_authority_chirho::{
    activate_reviewed_h3_chirho, canonical_resident_ledger_activation_authorization_chirho,
    canonical_resident_ledger_activation_statement_chirho, commit_write_restoration_chirho,
    load_verified_write_restoration_confirmation_chirho,
    open_resident_effect_journal_handle_chirho,
    open_resident_effect_journal_handle_testkind_chirho,
    open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho,
    open_resident_effect_journal_handle_with_shared_elector_and_capacity_admission_chirho,
    open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho,
    open_resident_gd7_held_coordinator_chirho,
    parse_and_verify_write_restoration_confirmation_chirho,
    parse_canonical_resident_ledger_activation_authorization_chirho,
    resident_ledger_activation_authorization_digest_chirho,
    resident_ledger_activation_statement_chirho, restore_ordinary_writes_chirho,
    tenant_migration_writer_adoption_intent_digest_chirho,
    unsigned_tenant_migration_writer_adoption_message_chirho,
    verify_resident_ledger_activation_authorization_chirho, Gd7CompensationCompletionRefusalChirho,
    Gd7CompensationCompositionRefusalChirho, Gd7CompensationProviderAdapterChirho,
    Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho,
    Gd7WriteRestorationConfirmationChirho, Gd7WriteRestorationConfirmationInputChirho,
    Gd7WriteRestorationOutcomeChirho, Gd7WriteRestorationRefusalChirho,
    ResidentActorServiceCompositionChirho, ResidentEffectJournalHandleChirho,
    ResidentGd7HeldAdoptedSnapshotChirho, ResidentGd7HeldAdoptionCommitOutcomeChirho,
    ResidentGd7HeldAdoptionCommitRefusalChirho,
    ResidentGd7HeldAdoptionMaterializationRefusalChirho,
    ResidentGd7HeldAdoptionMaterializationRequestChirho, ResidentGd7HeldBootstrapSnapshotChirho,
    ResidentGd7HeldCoordinatorHandleChirho, ResidentGd7HeldCoordinatorMonitorChirho,
    ResidentGd7HeldCoordinatorRefusalChirho, ResidentGd7HeldCoordinatorSnapshotChirho,
    ResidentGd7HeldObligationMintRefusalChirho, ResidentGd7HeldObservationImportChirho,
    ResidentGd7HeldPreparedAdoptionChirho, ResidentGd7HeldSealedPlanSnapshotChirho,
    ResidentGd7WinnerAdoptionEvidenceHandleChirho,
    ResidentGd7WinnerAdoptionEvidenceInspectionChirho,
    ResidentGd7WinnerAdoptionEvidenceRefusalChirho, ResidentGd7WinnerEvidenceHandleChirho,
    ResidentGd7WinnerEvidenceRefusalChirho, ResidentGd7WinnerForkObservationChirho,
    ResidentGd7WinnerForkObservationRefusalChirho, ResidentGd7WinnerHandoffHandleChirho,
    ResidentGd7WinnerHandoffRefusalChirho, ResidentGd7WinnerHandoffStatusChirho,
    ResidentGd7WinnerViewSealChirho, ResidentGd7WinnerViewStageInspectionChirho,
    ResidentLedgerActivationAuthorizationChirho, ResidentLedgerActivationInputChirho,
    ResidentLedgerActivationReceiptChirho, ResidentLedgerActivationStatementChirho,
    ResidentLedgerActivationStatementInputChirho, ResidentLedgerAppendPermitChirho,
    ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityChirho,
    ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho,
    ResidentLedgerBirthPermitChirho, ResidentLedgerLocalPortsChirho,
    ResidentLedgerMintIntentChirho, ResidentSinkTermCellRefusalChirho,
    ResidentTenantMigrationOperationHandleChirho, ResidentTenantMigrationOperationRefusalChirho,
    ResidentTenantMigrationSourceFenceStatusChirho,
    ResidentTenantMigrationTargetActivatedStatusChirho, ResidentTestkindLossWitnessCommitChirho,
    ResidentTestkindLossWitnessHandleChirho, ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessPhaseChirho, ResidentTestkindLossWitnessRefusalChirho,
    TenantMigrationCapacityAdmissionCompositionChirho,
    TenantMigrationCapacityCompositionRefusalChirho,
    TenantMigrationWriterAdoptionConsumptionRefusalChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho, TenantMigrationWriterAdoptionIntentChirho,
    TenantMigrationWriterAdoptionRecordChirho, TenantMigrationWriterAdoptionRefusalChirho,
    MAX_RESIDENT_LEDGER_ACTIVATION_AUTHORIZATION_BYTES_CHIRHO,
    MAX_TENANT_MIGRATION_WRITER_ADOPTION_RECORD_BYTES_CHIRHO,
    RESIDENT_LEDGER_ACTIVATION_STATEMENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO,
};
pub use shadow_canary_report_chirho::{
    configured_shadow_canary_bound_verdict_bytes_chirho,
    configured_shadow_canary_bound_verdict_chirho, configured_shadow_canary_report_bytes_chirho,
    configured_shadow_canary_report_read_only_chirho,
    verify_configured_shadow_canary_bound_verdict_bytes_chirho,
    verify_required_configured_shadow_canary_report_bytes_chirho,
    verify_required_configured_shadow_canary_report_chirho,
    ConfiguredShadowCanaryBoundVerdictChirho, ConfiguredShadowCanaryBoundVerdictRefusalChirho,
    ConfiguredShadowCanaryBoundVerdictRequirementsChirho,
    ConfiguredShadowCanaryQualificationChirho, ConfiguredShadowCanaryReportBuildRefusalChirho,
    ConfiguredShadowCanaryReportChirho, ConfiguredShadowCanaryReportRefusalChirho,
    ConfiguredShadowCanaryReportStatusChirho,
    CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_SCHEMA_V1_CHIRHO,
    CONFIGURED_SHADOW_CANARY_REPORT_SCHEMA_V1_CHIRHO,
    MAX_CONFIGURED_SHADOW_CANARY_BOUND_VERDICT_BYTES_CHIRHO,
    MAX_CONFIGURED_SHADOW_CANARY_REPORT_BYTES_CHIRHO,
};
pub use signer_chirho::{
    configured_held_gd7_journal_verifier_chirho, configured_resident_gd7_journal_verifier_chirho,
    host_ledger_signer_refs_from_config_chirho, HostLedgerSignerRefusalChirho,
    HostLedgerSignerSecretRefsChirho, HostLedgerSignersChirho, LedgerSignerRoleChirho,
    RoleBoundLedgerSignerChirho,
};
pub use storage_chirho::{
    FsLedgerStorageChirho, FsMonitorEvidenceSinkChirho, HostLedgerStorageRefusalChirho,
};
pub use test_kind_fence_chirho::{
    refuse_test_kind_marked_host_config_chirho, require_test_kind_marked_host_config_chirho,
    NON_TEST_KIND_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO,
    TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO,
};

#[cfg(test)]
mod tests_chirho;
