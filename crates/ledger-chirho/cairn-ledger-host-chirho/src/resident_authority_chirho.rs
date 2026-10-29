// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Production-compiled resident authority readiness for one exact ledger coordinate.
//!
//! This module seals or recovers an exact Pending-to-Bound birth, then joins an elector-owned local
//! generation handle, lifetime resident lease, stable directory identities, and exact
//! expected-genesis journal. One reviewed H3 activation capsule may construct and consume the birth
//! and activation append permits. Serving reopens only the existing authority and exposes typed
//! effect mutations through a bounded resident actor; raw journal and election authority remain
//! inside this module.

mod activation_chirho;
mod birth_chirho;
mod effect_warrant_publisher_chirho;
mod held_coordinator_chirho;
mod ordinary_term_acceptance_chirho;
#[path = "resident_authority_chirho/resident_mutation_chirho/authority_append_chirho.rs"]
mod resident_mutation_append_chirho;
#[path = "resident_authority_chirho/resident_mutation_chirho/authority_open_view_chirho.rs"]
mod resident_mutation_open_view_chirho;
mod runtime_actor_chirho;
pub(crate) mod sink_term_lifecycle_chirho;
pub(crate) mod sink_term_revoke_chirho;
#[cfg(test)]
mod startup_contention_tests_chirho;
mod testkind_loss_witness_chirho;
#[cfg(test)]
#[path = "resident_authority_chirho/testkind_loss_witness_tests_chirho.rs"]
mod testkind_loss_witness_tests_chirho;
pub mod write_restoration_chirho;
#[path = "resident_authority_chirho/runtime_actor_chirho/migration_chirho/writer_adoption_chirho/mod.rs"]
mod writer_adoption_chirho;

pub use writer_adoption_chirho::{
    tenant_migration_writer_adoption_intent_digest_chirho,
    unsigned_tenant_migration_writer_adoption_message_chirho,
    TenantMigrationWriterAdoptionConsumptionRefusalChirho,
    TenantMigrationWriterAdoptionGateRefusalChirho, TenantMigrationWriterAdoptionIntentChirho,
    TenantMigrationWriterAdoptionRecordChirho, TenantMigrationWriterAdoptionRefusalChirho,
    MAX_TENANT_MIGRATION_WRITER_ADOPTION_RECORD_BYTES_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_WRITER_ADOPTION_RECORD_SCHEMA_V1_CHIRHO,
};

pub use activation_chirho::{
    activate_reviewed_h3_chirho, canonical_resident_ledger_activation_authorization_chirho,
    canonical_resident_ledger_activation_statement_chirho,
    parse_canonical_resident_ledger_activation_authorization_chirho,
    resident_ledger_activation_authorization_digest_chirho,
    resident_ledger_activation_statement_chirho,
    verify_resident_ledger_activation_authorization_chirho,
    ResidentLedgerActivationAuthorizationChirho, ResidentLedgerActivationInputChirho,
    ResidentLedgerActivationReceiptChirho, ResidentLedgerActivationStatementChirho,
    ResidentLedgerActivationStatementInputChirho, ResidentLedgerMintIntentChirho,
    MAX_RESIDENT_LEDGER_ACTIVATION_AUTHORIZATION_BYTES_CHIRHO,
    RESIDENT_LEDGER_ACTIVATION_STATEMENT_SCHEMA_V1_CHIRHO,
};
pub use birth_chirho::ResidentLedgerBirthPermitChirho;
#[cfg(test)]
pub(crate) use birth_chirho::{
    install_resident_birth_post_genesis_test_hook_chirho,
    install_resident_birth_post_sink_term_cell_test_hook_chirho,
};
#[cfg(test)]
pub(crate) use held_coordinator_chirho::{
    commit_or_reload_gd7_held_adoption_for_test_chirho,
    gd7_adoption_staging_journal_path_for_test_chirho,
    materialize_gd7_held_adoption_candidate_chirho,
    materialize_gd7_held_adoption_candidate_with_projection_for_test_chirho,
    mint_actor_owned_gd7_losing_effect_obligation_with_hooks_for_test_chirho,
    verify_active_gd7_held_adoption_for_test_chirho, Gd7HeldAdoptionCommitPortsForTestChirho,
    Gd7HeldAdoptionMaterializationPortsChirho, ResidentGd7HeldObligationMintActorPortsChirho,
};
// The mint REFUSAL is public; the mint PORTS stay crate-internal above. That split is the whole
// widening: a caller must be able to name which refusal it got — `AdoptionChangedAfterMint` carries
// a durable receipt and must never be retried — while nothing outside this crate may assemble the
// thirteen ports that would let it mint.
pub use held_coordinator_chirho::{
    open_resident_gd7_held_coordinator_chirho, ResidentGd7HeldAdoptedSnapshotChirho,
    ResidentGd7HeldAdoptionCommitOutcomeChirho, ResidentGd7HeldAdoptionCommitRefusalChirho,
    ResidentGd7HeldAdoptionMaterializationRefusalChirho,
    ResidentGd7HeldAdoptionMaterializationRequestChirho, ResidentGd7HeldBootstrapSnapshotChirho,
    ResidentGd7HeldCoordinatorHandleChirho, ResidentGd7HeldCoordinatorMonitorChirho,
    ResidentGd7HeldCoordinatorRefusalChirho, ResidentGd7HeldCoordinatorSnapshotChirho,
    ResidentGd7HeldObligationMintRefusalChirho, ResidentGd7HeldObservationImportChirho,
    ResidentGd7HeldPreparedAdoptionChirho, ResidentGd7HeldSealedPlanSnapshotChirho,
};
use runtime_actor_chirho::derive_current_gd7_winner_compensation_authority_chirho;
#[cfg(test)]
pub(crate) use runtime_actor_chirho::ResidentGd7PlanPortsChirho;
pub(crate) use runtime_actor_chirho::RESIDENT_EFFECT_JOURNAL_CANARY_DIR_CHIRHO;
pub use runtime_actor_chirho::{
    open_resident_effect_journal_handle_chirho,
    open_resident_effect_journal_handle_testkind_chirho,
    open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho,
    open_resident_effect_journal_handle_with_shared_elector_and_capacity_admission_chirho,
    open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho,
    open_resident_effect_journal_handle_with_shared_elector_chirho,
    Gd7CompensationCompletionRefusalChirho, Gd7CompensationCompositionRefusalChirho,
    Gd7CompensationProviderAdapterChirho, Gd7CompensationProviderObservationChirho,
    Gd7CompensationProviderRefusalChirho, ResidentActorServiceCompositionChirho,
    ResidentEffectJournalHandleChirho, ResidentGd7WinnerAdoptionEvidenceHandleChirho,
    ResidentGd7WinnerAdoptionEvidenceInspectionChirho,
    ResidentGd7WinnerAdoptionEvidenceRefusalChirho, ResidentGd7WinnerEvidenceHandleChirho,
    ResidentGd7WinnerEvidenceRefusalChirho, ResidentGd7WinnerForkObservationChirho,
    ResidentGd7WinnerForkObservationRefusalChirho, ResidentGd7WinnerHandoffHandleChirho,
    ResidentGd7WinnerHandoffRefusalChirho, ResidentGd7WinnerHandoffStatusChirho,
    ResidentGd7WinnerViewSealChirho, ResidentGd7WinnerViewStageInspectionChirho,
    ResidentTestkindLossWitnessHandleChirho, TenantMigrationCapacityAdmissionCompositionChirho,
    TenantMigrationCapacityCompositionRefusalChirho,
};
pub use runtime_actor_chirho::{
    ResidentTenantMigrationOperationHandleChirho, ResidentTenantMigrationOperationRefusalChirho,
    ResidentTenantMigrationSourceFenceStatusChirho,
    ResidentTenantMigrationTargetActivatedStatusChirho,
};
pub use sink_term_lifecycle_chirho::ResidentSinkTermCellRefusalChirho;
use sink_term_revoke_chirho::{
    release_converged_reconciliation_hold_chirho, revoke_and_accept_new_winner_term_chirho,
};
pub use write_restoration_chirho::{
    commit_write_restoration_chirho, load_verified_write_restoration_confirmation_chirho,
    parse_and_verify_write_restoration_confirmation_chirho, restore_ordinary_writes_chirho,
    Gd7WriteRestorationConfirmationChirho, Gd7WriteRestorationConfirmationInputChirho,
    Gd7WriteRestorationOutcomeChirho, Gd7WriteRestorationRefusalChirho,
};

pub use self::effect_warrant_publisher_chirho::ResidentEffectWarrantRefusalChirho;
use self::effect_warrant_publisher_chirho::{
    publish_effect_intent_warrant_chirho, publish_effect_terminal_warrant_chirho,
};
#[cfg(test)]
pub(crate) use self::effect_warrant_publisher_chirho::{
    publish_effect_intent_warrant_chirho as publish_effect_intent_warrant_for_tests_chirho,
    publish_effect_terminal_warrant_chirho as publish_effect_terminal_warrant_for_tests_chirho,
};
use self::sink_term_revoke_chirho::advance_sink_term_from_winner_witness_chirho;
use crate::authority_chirho::{ElectedClusterMembershipChirho, PlatformPolicyMintAuthorityChirho};
use crate::reconciliation_chirho::sink_term_fence_chirho::{
    read_sink_term_fence_chirho, verify_supplied_winner_term_is_strictly_current_chirho,
    SinkTermFenceRefusalChirho,
};
use crate::reconciliation_chirho::{
    fetch_granted_gd7_winner_view_page_chirho, gd7_reconciliation_group_has_any_active_hold_chirho,
    gd7_reconciliation_group_ordinary_writes_withheld_chirho,
    issue_first_gd7_winner_view_page_grant_chirho,
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho,
    seal_gd7_winner_current_view_chirho, seal_gd7_winner_current_view_during_handoff_chirho,
    stage_next_gd7_winner_view_bundle_page_chirho, ActiveGd7WinnerHandoffChirho,
    AuthenticatedGd7DeposedForkObservationChirho, ConvergedReadReplicaChirho,
    ExistingNodeGd7SignerChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationVerifierPortChirho, Gd7WinnerCurrentViewChallengeChirho,
    Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerCurrentViewRefusalChirho,
    Gd7WinnerHandoffPhaseChirho, Gd7WinnerHandoffStoreChirho, Gd7WinnerHandoffStoreRefusalChirho,
    Gd7WinnerHistoryRestartChirho, Gd7WinnerHistoryStageOutcomeChirho,
    Gd7WinnerJournalSnapshotChirho, Gd7WinnerViewBundleRestartChirho,
    Gd7WinnerViewBundleStageOutcomeChirho, Gd7WinnerViewPageFetchContextChirho,
    Gd7WinnerViewPageGrantChirho, Gd7WinnerViewPageTransferChirho, Gd7WinnerWitnessStoreChirho,
    PinnedNodeGd7VerifierChirho, VerifiedGd7ForkBaselineRootChirho,
    VerifiedGd7WinnerViewBundleRootChirho,
};
use crate::resident_ledger_identity_chirho::{
    verify_bound_identity_chirho, verify_legacy_v3_bound_identity_chirho,
    ResidentLedgerCoordinateSourceChirho, RESIDENT_LEDGER_IDENTITY_KIND_CHIRHO,
    RESIDENT_LEDGER_LEGACY_V3_IDENTITY_KIND_CHIRHO,
};
use crate::storage_chirho::{
    FsLedgerStorageChirho, StableLedgerExclusiveLockGuardChirho,
    StableLedgerExclusiveLockHandleChirho, StableLedgerNamespaceSnapshotChirho,
};
use crate::{ResidentLedgerClockChirho, RoleBoundLedgerSignerChirho};
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitContinuationViewChirho, EffectIntentJournalStateChirho,
    VerifiedEffectReceiptInventoryEntryChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    EffectIntentJournalCutChirho, EffectIntentSignerPortChirho,
};
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho;
use cairn_kind_registry_chirho::chain_chirho::VerifiedRegistryChirho;
use cairn_ledger_log_chirho::append_mirror_chirho::LedgerAppendMirrorPortChirho;
use cairn_ledger_log_chirho::effect_record_fact_chirho::{
    classify_effect_record_fact_chirho, EffectHoldLineageChirho, EffectRecordFactChirho,
};
use cairn_ledger_log_chirho::epoch_first_record_chirho::EpochFirstRecordEvidenceChirho;
use cairn_ledger_log_chirho::journal_chirho::{
    AppendReceiptChirho, AppendRequestChirho, ExpectedLedgerGenesisChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixCoordinateChirho, LosingSuffixJournalIdentityChirho, LosingSuffixPageRequestChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho,
    LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho, LedgerMirrorRecoveryPortChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_read_model_chirho::account_net_projection_page_chirho;
use cairn_ledger_read_model_chirho::feeder_chirho::VerifiedSourceStateChirho;
use cairn_seqlog_chirho::seqlog_chirho::named_lock_storage_key_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::{
    LocalActiveHandoffAppendGenerationGuardChirho, LocalAppendAuthorityHandleChirho,
    LocalAppendAuthorityRefusalChirho, LocalAppendHandoffGenerationGuardChirho,
    LocalAppendHandoffPreparationChirho, LocalAppendHandoffReadGenerationChirho,
    LocalLeadershipGenerationGuardChirho, LocalStartupCoordinatesGuardChirho,
};
use cairn_writer_head_chirho::resident_writer_chirho::{
    try_inspect_resident_writer_identity_in_custody_chirho, ResidentWriterLeaseChirho,
    ResidentWriterRootCustodyChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho,
    prepare_reused_or_issued_elected_writer_fence_chirho, split_writer_epoch_chirho,
    writer_fence_storage_key_chirho, ConsistencyGroupIdChirho, WriterFenceTokenChirho,
    MAX_WRITER_FENCE_FILE_BYTES_CHIRHO, WRITER_FENCE_LOCK_CHIRHO,
};
use ordinary_term_acceptance_chirho::{
    advance_sink_term_from_ordinary_election_chirho,
    verify_ordinary_election_sink_term_acceptance_chirho,
};
use sink_term_lifecycle_chirho::{
    current_bound_identity_refusal_chirho, expected_genesis_open_refusal_chirho,
    expected_genesis_refusal_chirho, legacy_bound_resident_sink_term_cell_refusal_chirho,
    local_generation_refusal_chirho, resident_identity_refusal_chirho,
    resident_lease_refusal_chirho, stable_namespace_refusal_chirho,
    verify_resident_sink_term_cell_for_bound_open_chirho, writer_fence_refusal_chirho,
};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
pub use testkind_loss_witness_chirho::{
    ResidentTestkindLossWitnessCommitChirho, ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessPhaseChirho, ResidentTestkindLossWitnessRefusalChirho,
};

/// Page shape for the post-cut extension walk. These bound MEMORY PER PAGE, never how much of the
/// extension must be read — termination is by reaching the anchor. The page cap is a runaway
/// backstop that REFUSES rather than certifying a prefix, so a larger extension fails closed.
const POST_CUT_EXTENSION_PAGE_RECORDS_CHIRHO: usize = 256;
const POST_CUT_EXTENSION_PAGE_BYTES_CHIRHO: usize = 1 << 20;
const MAX_POST_CUT_EXTENSION_PAGES_CHIRHO: usize = 1_024;

const RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO: usize = 1_000;
const RESIDENT_GENERATION_CONTENTION_PAUSE_CHIRHO: Duration = Duration::from_millis(1);

/// Exact concrete local ports retained by the preactivation resident journal.
///
/// No trait-object substitution or outbound provider adapter can enter this bundle. The journal type
/// remains private inside [`ResidentLedgerAuthorityChirho`].
#[derive(Clone, Copy)]
pub struct ResidentLedgerLocalPortsChirho<'ports_chirho> {
    pub storage_chirho: &'ports_chirho FsLedgerStorageChirho,
    pub signer_chirho: &'ports_chirho RoleBoundLedgerSignerChirho,
    pub clock_chirho: &'ports_chirho ResidentLedgerClockChirho,
    pub membership_chirho: &'ports_chirho ElectedClusterMembershipChirho,
    pub kind_registry_chirho: &'ports_chirho VerifiedRegistryChirho,
    pub authority_chirho: &'ports_chirho PlatformPolicyMintAuthorityChirho<'ports_chirho>,
}

/// Why a bound resident ledger could not be opened or observed as locally ready.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentLedgerAuthorityRefusalChirho {
    RootGroupMismatchChirho {
        expected_group_chirho: ConsistencyGroupIdChirho,
        actual_group_chirho: ConsistencyGroupIdChirho,
    },
    StorageOutsideSelectedRootChirho,
    LocalGenerationRefusedChirho {
        reason_chirho: LocalAppendAuthorityRefusalChirho,
    },
    LocalGenerationChangedChirho {
        initial_generation_chirho: u64,
        observed_generation_chirho: u64,
        initial_term_chirho: u64,
        observed_term_chirho: u64,
    },
    StableNamespaceRefusedChirho {
        detail_chirho: String,
    },
    ResidentIdentityRefusedChirho {
        detail_chirho: String,
    },
    ResidentIdentityKindMismatchChirho,
    ResidentIdentityChangedChirho,
    SinkTermCellRefusedChirho {
        reason_chirho: ResidentSinkTermCellRefusalChirho,
    },
    CompensationFenceRefusedChirho {
        reason_chirho: SinkTermFenceRefusalChirho,
    },
    /// The complete two-holder ACK population could not freshly re-attest the exact local tail.
    OrdinaryElectionSinkTermAcceptanceRefusedChirho {
        detail_chirho: String,
    },
    /// The sink cell is behind, but the resident lacks the configured source or placement binding
    /// needed to gather the mandatory exact two-holder acceptance pair.
    OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
    /// The public warrant could not be published, so the money append it would warrant is refused.
    ///
    /// The typed reason survives BY NAME: a forged or malformed line, a coordinate already binding
    /// different bytes, and an unavailable projection are different facts about a money path.
    EffectWarrantPublicationRefusedChirho {
        reason_chirho: ResidentEffectWarrantRefusalChirho,
    },
    ResidentLeaseRefusedChirho {
        detail_chirho: String,
    },
    ExpectedGenesisRefusedChirho {
        detail_chirho: String,
    },
    OpeningMembershipEpochMismatchChirho {
        opening_epoch_chirho: u64,
        membership_epoch_chirho: u64,
    },
    ExistingJournalWithoutVerifiedPendingIdentityChirho,
    PendingJournalNotPristineChirho {
        tail_seq_chirho: u64,
        current_epoch_chirho: u64,
        opening_epoch_chirho: u64,
    },
    JournalCompositionRefusedChirho {
        detail_chirho: String,
    },
    ResidentGenesisMismatchChirho,
    MembershipAheadOfJournalChirho {
        journal_epoch_chirho: u64,
        membership_epoch_chirho: u64,
    },
    JournalAheadOfPublishedRaftTermChirho {
        journal_epoch_chirho: u64,
        published_raft_term_chirho: u64,
    },
    MembershipAheadOfPublishedRaftTermChirho {
        membership_epoch_chirho: u64,
        published_raft_term_chirho: u64,
    },
    WriterFenceRefusedChirho {
        detail_chirho: String,
    },
    JournalAheadOfDurableFenceStateChirho {
        journal_epoch_chirho: u64,
        fence_state_epoch_chirho: u64,
    },
    MembershipAheadOfDurableFenceStateChirho {
        membership_epoch_chirho: u64,
        fence_state_epoch_chirho: u64,
    },
    FenceTermMismatchChirho {
        published_raft_term_chirho: u64,
        fence_term_chirho: u64,
    },
    JournalAheadOfFenceChirho {
        journal_epoch_chirho: u64,
        fence_epoch_chirho: u64,
    },
    MembershipAheadOfFenceChirho {
        membership_epoch_chirho: u64,
        fence_epoch_chirho: u64,
    },
    JournalMutationRefusedChirho {
        detail_chirho: String,
    },
    MirrorReconciliationRefusedChirho {
        detail_chirho: String,
    },
    MirrorPrepareRefusedChirho {
        detail_chirho: String,
    },
    MirrorCommittedEvidencePendingChirho {
        receipt_chirho: Box<ResidentLedgerAppendReceiptChirho>,
        detail_chirho: String,
    },
    MembershipMutationRefusedChirho {
        detail_chirho: String,
    },
    Gd7ReconciliationHoldActiveChirho,
    Gd7ReconciliationHoldInspectionRefusedChirho {
        detail_chirho: String,
    },
    /// Tenant migration owns the resident root's append fence, so adjacent GD7 state may not move.
    TenantMigrationSourceFenceActiveChirho,
    /// Ordinary writes are still withheld: this group was reconciled and D3 released its head, but
    /// D4 has not yet verified a later elector grant and written its signed confirmation. The
    /// compensation legs that FINISH the reconciliation are exempt and keep flowing.
    Gd7OrdinaryWritesWithheldChirho,
    /// The test-kind loss witness must remain an ordinary mutation. Entering the private
    /// compensation-only handoff lane would invalidate its final-sink refusal claim.
    TestkindLossWitnessExemptLaneRefusedChirho,
    /// The winner-side compensation lane was NOT admitted while a handoff freeze is active, so the
    /// freeze stands whole. `detail_chirho` names which of the lane's own gates declined — no
    /// durable head owned by this node, a head that is not `AcceptedChirho`, or a store/signer that
    /// would not open — never a caller's assertion about any of them.
    Gd7CompensationLaneRefusedChirho {
        detail_chirho: String,
    },
    /// A handoff's post-cut journal extension was not verifiable as compensation-class reaching the
    /// cut anchor. Covers wrong-class records AND traversal that never reached the cut anchor —
    /// a prefix that classifies clean is not evidence about records nobody read.
    Gd7PostCutExtensionRefusedChirho {
        detail_chirho: String,
    },
    /// A mid-life sink winner-term advance was refused. `detail_chirho` carries the exact
    /// `LawfulSinkTermAdvanceRefusalChirho` display, so the failed binding survives the conversion.
    LawfulSinkTermAdvanceRefusedChirho {
        detail_chirho: String,
    },
    ActivationIntentRefusedChirho,
    ActivationStatementRefusedChirho,
    ActivationSignatureRefusedChirho,
    ActivationReceiptRefusedChirho,
}

impl fmt::Display for ResidentLedgerAuthorityRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::RootGroupMismatchChirho { .. } => {
                "resident authority root and elector consistency group differ"
            }
            Self::StorageOutsideSelectedRootChirho => {
                "resident ledger storage is outside the selected authority root"
            }
            Self::LocalGenerationRefusedChirho {
                reason_chirho: LocalAppendAuthorityRefusalChirho::HandoffActiveChirho,
            } => "resident ledger mutation is frozen by an active GD7 winner handoff",
            Self::LocalGenerationRefusedChirho { reason_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident authority local generation was refused: {reason_chirho}"
                );
            }
            Self::LocalGenerationChangedChirho { .. } => {
                "resident authority local generation changed during open"
            }
            Self::StableNamespaceRefusedChirho { .. } => {
                "resident authority stable namespace was refused"
            }
            Self::ResidentIdentityRefusedChirho { detail_chirho } => {
                // The detail is CARRIED and was being thrown away, which made every distinct cause
                // arrive as one sentence. Its sibling `WriterFenceRefusedChirho` prints its detail,
                // and that asymmetry is exactly why a fence refusal was diagnosable on a real host
                // in minutes while this one was not: an operator reading "Bound identity was
                // refused" cannot tell a missing identity from a mismatched one from an unreadable
                // one, and the answers are entirely different actions.
                return write!(
                    formatter_chirho,
                    "resident ledger Bound identity was refused: {detail_chirho}"
                );
            }
            Self::ResidentIdentityKindMismatchChirho => {
                "resident ledger identity kind does not match"
            }
            Self::ResidentIdentityChangedChirho => {
                "resident ledger identity changed after lifetime acquisition"
            }
            Self::SinkTermCellRefusedChirho { reason_chirho } => {
                return write!(formatter_chirho, "{reason_chirho}");
            }
            Self::CompensationFenceRefusedChirho { reason_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident compensation sink fence refused: {reason_chirho:?}"
                );
            }
            Self::OrdinaryElectionSinkTermAcceptanceRefusedChirho { detail_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident ordinary-election sink-term acceptance was refused: {detail_chirho}"
                );
            }
            Self::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho => {
                "resident ordinary-election sink-term acceptance inputs are unavailable"
            }
            Self::EffectWarrantPublicationRefusedChirho { reason_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident effect warrant was not published, so its append is refused: \
                     {reason_chirho}"
                );
            }
            Self::ResidentLeaseRefusedChirho { .. } => "resident ledger lifetime lease was refused",
            Self::ExpectedGenesisRefusedChirho { .. } => {
                "resident ledger expected-genesis open was refused"
            }
            Self::OpeningMembershipEpochMismatchChirho { .. } => {
                "resident birth membership epoch differs from its opening epoch"
            }
            Self::ExistingJournalWithoutVerifiedPendingIdentityChirho => {
                "existing resident journal lacks an exact verified Pending identity"
            }
            Self::PendingJournalNotPristineChirho { .. } => {
                "Pending resident identity names a non-pristine journal"
            }
            Self::JournalCompositionRefusedChirho { detail_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident journal composition was refused: {detail_chirho}"
                );
            }
            Self::ResidentGenesisMismatchChirho => {
                "resident Bound identity and journal genesis differ"
            }
            Self::MembershipAheadOfJournalChirho { .. } => {
                "resident membership epoch is ahead of the journal"
            }
            Self::JournalAheadOfPublishedRaftTermChirho { .. } => {
                "resident journal is ahead of the published local Raft term"
            }
            Self::MembershipAheadOfPublishedRaftTermChirho { .. } => {
                "resident membership is ahead of the published local Raft term"
            }
            Self::WriterFenceRefusedChirho { detail_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident descriptor-owned writer fence was refused: {detail_chirho}"
                );
            }
            Self::JournalAheadOfDurableFenceStateChirho { .. } => {
                "resident journal is ahead of the durable writer-fence state"
            }
            Self::MembershipAheadOfDurableFenceStateChirho { .. } => {
                "resident membership is ahead of the durable writer-fence state"
            }
            Self::FenceTermMismatchChirho { .. } => {
                "resident writer fence does not match the durable local term"
            }
            Self::JournalAheadOfFenceChirho { .. } => {
                "resident journal is ahead of the selected writer fence"
            }
            Self::MembershipAheadOfFenceChirho { .. } => {
                "resident membership is ahead of the selected writer fence"
            }
            Self::JournalMutationRefusedChirho { detail_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident journal mutation was refused: {detail_chirho}"
                );
            }
            Self::MirrorReconciliationRefusedChirho { .. } => {
                "resident ledger mirror reconciliation was refused"
            }
            Self::MirrorPrepareRefusedChirho { .. } => "resident ledger mirror prepare was refused",
            Self::MirrorCommittedEvidencePendingChirho { .. } => {
                "resident journal committed while mirror evidence remains pending"
            }
            Self::MembershipMutationRefusedChirho { .. } => {
                "resident membership mutation was refused"
            }
            Self::Gd7ReconciliationHoldActiveChirho => {
                "resident ledger writes are held by active GD7 reconciliation"
            }
            Self::Gd7ReconciliationHoldInspectionRefusedChirho { .. } => {
                "resident ledger could not verify the GD7 reconciliation hold interlock"
            }
            Self::TenantMigrationSourceFenceActiveChirho => {
                "tenant migration source fence blocks resident-root mutation"
            }
            Self::Gd7OrdinaryWritesWithheldChirho => {
                "resident ordinary writes are withheld until GD7 write restoration is confirmed"
            }
            Self::TestkindLossWitnessExemptLaneRefusedChirho => {
                "Cf8LossWitnessMutationExemptionRefusedChirho"
            }
            // THE DETAIL TRAVELS. Most arms here write a fixed message and keep their detail for
            // `Debug`, but this refusal crosses the actor's wire boundary as a Display string, and
            // its whole operational value is naming WHICH gate declined — "this node owns no
            // durable head" and "the head is Preparing, not accepted" are different situations with
            // different operator responses. A fixed message would make them indistinguishable to
            // every caller outside this crate.
            Self::Gd7PostCutExtensionRefusedChirho { detail_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident ledger refused a handoff post-cut journal extension: {detail_chirho}"
                );
            }
            Self::Gd7CompensationLaneRefusedChirho { detail_chirho } => {
                return write!(
                    formatter_chirho,
                    "resident ledger refused the GD7 winner-side compensation append lane: \
                     {detail_chirho}"
                );
            }
            Self::LawfulSinkTermAdvanceRefusedChirho { .. } => {
                "resident ledger refused a mid-life sink winner-term advance"
            }
            Self::ActivationIntentRefusedChirho => {
                "resident ledger activation mint intent was refused"
            }
            Self::ActivationStatementRefusedChirho => {
                "resident ledger activation statement was refused"
            }
            Self::ActivationSignatureRefusedChirho => {
                "resident ledger activation signature was refused"
            }
            Self::ActivationReceiptRefusedChirho => {
                "resident ledger activation receipt was refused"
            }
        })
    }
}

impl Error for ResidentLedgerAuthorityRefusalChirho {}

/// Fixed-size readiness evidence from one locally sealed authority generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentLedgerAuthorityReadinessChirho {
    pub consistency_group_chirho: ConsistencyGroupIdChirho,
    pub local_node_chirho: NodeIdChirho,
    pub process_generation_chirho: u64,
    pub published_raft_term_chirho: u64,
    pub journal_epoch_chirho: u64,
    pub membership_epoch_chirho: u64,
    pub journal_tail_seq_chirho: u64,
    pub journal_tail_digest_chirho: DigestChirho,
    pub genesis_digest_chirho: DigestChirho,
    pub resident_identity_digest_chirho: String,
}

/// Sealed append capability. Exactly one reviewed child capsule may construct it in production.
#[derive(Debug)]
pub struct ResidentLedgerAppendPermitChirho {
    _sealed_chirho: (),
}

impl ResidentLedgerAppendPermitChirho {
    #[cfg(test)]
    pub(crate) fn for_test_chirho() -> Self {
        Self { _sealed_chirho: () }
    }
}

/// One append bound to the exact resident generation, published Raft term, and writer fence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentLedgerAppendReceiptChirho {
    pub append_chirho: AppendReceiptChirho,
    pub fence_chirho: WriterFenceTokenChirho,
    pub process_generation_chirho: u64,
    pub published_raft_term_chirho: u64,
}

/// Lifetime-exclusive, production-compiled resident authority object.
///
/// The object holds one Bound resident lease and the exact authority/storage directory descriptors.
/// `probe_chirho` performs fixed generation checks plus bounded control/identity reads. The sealed
/// preactivation append path performs O(1)-sized fence I/O and one journal append; no served caller or
/// permit constructor is production-compiled.
pub struct ResidentLedgerAuthorityChirho<'ports_chirho> {
    canonical_root_chirho: PathBuf,
    identity_storage_namespace_chirho: PathBuf,
    group_chirho: ConsistencyGroupIdChirho,
    local_node_chirho: NodeIdChirho,
    journal_path_chirho: StoragePathChirho,
    cluster_id_chirho: ClusterIdChirho,
    opening_epoch_chirho: u64,
    ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
    local_authority_chirho: LocalAppendAuthorityHandleChirho,
    resident_identity_digest_chirho: String,
    authority_storage_chirho: FsLedgerStorageChirho,
    authority_root_snapshot_chirho: StableLedgerNamespaceSnapshotChirho,
    storage_snapshot_chirho: StableLedgerNamespaceSnapshotChirho,
    writer_lock_chirho: StableLedgerExclusiveLockHandleChirho,
    active_fence_chirho: Option<WriterFenceTokenChirho>,
    journal_chirho: Option<LedgerJournalChirho<'ports_chirho>>,
    ordinary_term_acceptance_source_chirho:
        Option<Arc<dyn LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho>>,
    ordinary_term_acceptance_placement_binding_chirho:
        Option<LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho>,
    resident_lease_chirho: Option<ResidentWriterLeaseChirho>,
}

/// Which acquisition sealed the generation an append is running under.
///
/// Both variants hold the elector's authority mutex for the same span, so the lock lifetime of the
/// append funnel is identical either way; only the ADMISSION differs. The types are distinct rather
/// than collapsed because the ordinary guard's name asserts "acquired with no active handoff", and
/// the compensation lane's acquisition is exactly the opposite.
enum ResidentAppendGenerationGuardChirho<'guard_chirho> {
    OrdinaryChirho(LocalLeadershipGenerationGuardChirho<'guard_chirho>),
    ActiveHandoffCompensationChirho(LocalActiveHandoffAppendGenerationGuardChirho<'guard_chirho>),
}

impl ResidentAppendGenerationGuardChirho<'_> {
    fn process_generation_chirho(&self) -> u64 {
        match self {
            Self::OrdinaryChirho(guard_chirho) => guard_chirho.process_generation_chirho(),
            Self::ActiveHandoffCompensationChirho(guard_chirho) => {
                guard_chirho.process_generation_chirho()
            }
        }
    }

    fn published_raft_term_chirho(&self) -> u64 {
        match self {
            Self::OrdinaryChirho(guard_chirho) => guard_chirho.published_raft_term_chirho(),
            Self::ActiveHandoffCompensationChirho(guard_chirho) => {
                guard_chirho.published_raft_term_chirho()
            }
        }
    }
}

#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
enum ResidentLedgerMutationChirho<'mutation_chirho> {
    ReviewedActivationChirho {
        request_chirho: AppendRequestChirho,
    },
    EffectHoldChirho {
        canonical_intent_line_chirho: &'mutation_chirho str,
        verifier_chirho: &'mutation_chirho dyn EffectIntentSignerPortChirho,
    },
    EffectCompensationHoldChirho {
        canonical_intent_line_chirho: &'mutation_chirho str,
        verifier_chirho: &'mutation_chirho dyn EffectIntentSignerPortChirho,
        authorization_chirho: &'mutation_chirho VerifiedEffectCompensationChirho,
    },
    EffectTerminalChirho {
        canonical_intent_line_chirho: &'mutation_chirho str,
        intent_verifier_chirho: &'mutation_chirho dyn EffectIntentSignerPortChirho,
        canonical_terminal_line_chirho: &'mutation_chirho str,
        terminal_verifier_chirho: &'mutation_chirho dyn EffectTerminalSignerPortChirho,
    },
    TestkindLossWitnessTransferChirho {
        request_chirho: AppendRequestChirho,
    },
}

impl ResidentLedgerMutationChirho<'_> {
    /// The complete active-handoff exemption set. New mutation variants remain ordinary unless
    /// this exact constructor match is deliberately changed and its causal witness is rerun.
    const fn allows_active_handoff_chirho(&self) -> bool {
        matches!(self, Self::EffectCompensationHoldChirho { .. })
    }
}

/// Publish this mutation's signed warrant, if it carries one, before its append is attempted.
///
/// A reviewed activation carries no effect warrant. Both hold doors publish the INTENT line; the
/// terminal door publishes the TERMINAL OUTCOME line, because the intent warrant was already
/// published when its hold landed — the same split the CF3 coordinator makes.
fn publish_effect_warrant_for_mutation_chirho(
    canonical_root_chirho: &Path,
    mutation_chirho: &ResidentLedgerMutationChirho<'_>,
) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
    match mutation_chirho {
        ResidentLedgerMutationChirho::ReviewedActivationChirho { .. }
        | ResidentLedgerMutationChirho::TestkindLossWitnessTransferChirho { .. } => Ok(()),
        ResidentLedgerMutationChirho::EffectHoldChirho {
            canonical_intent_line_chirho,
            verifier_chirho,
        }
        | ResidentLedgerMutationChirho::EffectCompensationHoldChirho {
            canonical_intent_line_chirho,
            verifier_chirho,
            ..
        } => publish_effect_intent_warrant_chirho(
            canonical_root_chirho,
            canonical_intent_line_chirho,
            *verifier_chirho,
        )
        .map(|_intent_ref_chirho| ()),
        ResidentLedgerMutationChirho::EffectTerminalChirho {
            canonical_terminal_line_chirho,
            terminal_verifier_chirho,
            ..
        } => publish_effect_terminal_warrant_chirho(
            canonical_root_chirho,
            canonical_terminal_line_chirho,
            *terminal_verifier_chirho,
        )
        .map(|_outcome_ref_chirho| ()),
    }
    .map_err(|reason_chirho| {
        ResidentLedgerAuthorityRefusalChirho::EffectWarrantPublicationRefusedChirho {
            reason_chirho,
        }
    })
}

impl<'ports_chirho> ResidentLedgerAuthorityChirho<'ports_chirho> {
    /// Re-seed the CURRENT mirror holders from this node's live journal.
    ///
    /// Exists because seeding is otherwise startup-only, and startup is the one moment it cannot work
    /// for the case that matters: a node adopting after a leader loss seeds while the holder it must
    /// seed is still unreachable. Measured on the fleet -- the returning holder then carries no
    /// continuity anchor for the rest of the sequence and every later prepare refuses.
    ///
    /// The tail is taken from the RETAINED journal at call time, never from a value captured earlier.
    /// A stale tail would seed a holder to a position the leader has already moved past, which is a
    /// worse defect than the one this closes.
    ///
    /// This grants nothing and relaxes nothing: it is the same signed prefix seal the startup path
    /// performs, at a later moment. A holder still accepts only what its own continuity check admits.
    pub(crate) fn reseed_current_holders_chirho(
        &self,
        recovery_chirho: &dyn LedgerMirrorRecoveryPortChirho,
    ) -> Result<(), String> {
        let journal_chirho = self
            .journal_chirho
            .as_ref()
            .ok_or_else(|| "ResidentReseedJournalUnavailableChirho".to_owned())?;
        let tail_chirho = journal_chirho.verified_append_mirror_tail_chirho();
        recovery_chirho
            .ensure_verified_prefix_bootstrapped_chirho(&tail_chirho, journal_chirho)
            .map_err(|error_chirho| error_chirho.detail_chirho().to_owned())
    }

    /// The exact ACCEPTED winner-handoff attempt this node's own durable signed head names.
    ///
    /// Read from the resident's OWN storage and re-verified through the winner-handoff store's own
    /// head/checkpoint signature and canonicality checks — never from an actor precheck, never from
    /// a caller argument, never from unverified bytes. Two gates live here and both fail closed:
    ///
    /// * PHASE. Only `AcceptedChirho` yields a digest. During `PreparingChirho` the transferred cut
    ///   is not yet fixed, so the freeze must hold whole — a compensation append then has no
    ///   settled cut to be "after".
    /// * OWNERSHIP. The head path is keyed by the WINNER node, and this store is opened with this
    ///   node's own identity and signer, so a node that is not the winner of this handoff finds no
    ///   head at all. The lane is winner-side by construction, not by a caller's assertion.
    ///
    /// Advance this winner's OWN sink winner-term cell, on demand, from its own signed fork witness.
    ///
    /// Ruled (i) by L.J. 2026-08-06. Called ONLY when a lawful compensation append has found its own
    /// cell behind its published term — a handoff that never carries a compensation never moves the
    /// fence.
    ///
    /// RESOLVE, NOT MATCH — the safety argument in one line. The accepted handoff's transfer identity
    /// and the fork witness overlap in only four comparable fields (group, winner node, held node,
    /// winner term), all of which two sibling losing forks can share. The field that separates them,
    /// the reconciliation checkpoint ref, is one the witness carries nothing to compare against. So
    /// this resolves that ref through this node's own storage, authenticates the plan-sealed
    /// checkpoint, recovers the full ten-field identity, and looks the witness up against THAT.
    /// (gpt_chirho's pre-registered arm SIBLING-WITNESS-SUBSTITUTION-1 forced this before it shipped;
    /// severity is representable-at-the-type, reachability unmeasured.)
    ///
    /// Nothing here is caller-supplied: the coordinates come from this node's durable
    /// signature-verified accepted handoff head, and the TERM comes by value out of the witness's own
    /// signed identity.
    #[allow(
        clippy::too_many_arguments,
        reason = "a free function over DISJOINT resident fields: the writer-lock guard already holds a mutable borrow of self, so a &self method cannot run beneath it"
    )]
    fn advance_own_winner_term_sink_cell_chirho(
        canonical_root_chirho: &Path,
        local_node_chirho: &NodeIdChirho,
        journal_signer_chirho: &RoleBoundLedgerSignerChirho,
        writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
        group_digest_chirho: &str,
        accepted_handoff_chirho: &ActiveGd7WinnerHandoffChirho,
        published_raft_term_chirho: u64,
    ) -> Result<u64, ResidentLedgerAuthorityRefusalChirho> {
        let lane_refusal_chirho = |detail_chirho: String| {
            ResidentLedgerAuthorityRefusalChirho::Gd7CompensationLaneRefusedChirho { detail_chirho }
        };
        let transfer_identity_chirho = &accepted_handoff_chirho
            .checkpoint_chirho
            .attempt_identity_chirho
            .held_transfer_identity_chirho;

        // The HELD node signed the plan-sealed checkpoint, so the verifier is pinned to the held
        // node named by this node's own signature-verified handoff — never to a key any artifact
        // selects for itself.
        let held_verifier_chirho = PinnedNodeGd7VerifierChirho::new_from_key_id_chirho(
            transfer_identity_chirho.held_node_chirho.clone(),
        )
        .map_err(|error_chirho| lane_refusal_chirho(error_chirho.to_string()))?;
        // The storage comes OUT of the lock, never alongside it. A separately-supplied storage is
        // the pairing that let a guard authorize a write to a disk it never locked - measured, a
        // root-A guard wrote term 7 to root B. Taking the guard alone makes that unconstructible
        // rather than merely checked.
        let checkpoint_chirho = load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
            writer_lock_guard_chirho.storage_chirho(),
            &held_verifier_chirho,
            &transfer_identity_chirho.reconciliation_checkpoint_ref_chirho,
        )
        .map_err(|refusal_chirho| lane_refusal_chirho(format!("{refusal_chirho:?}")))?;
        let identity_chirho = &checkpoint_chirho.identity_chirho;

        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            canonical_root_chirho,
            local_node_chirho,
        )
        .map_err(|error_chirho| lane_refusal_chirho(error_chirho.to_string()))?;
        let witness_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
            writer_lock_guard_chirho.storage_chirho(),
            &signer_chirho,
            journal_signer_chirho,
        );
        let verified_index_chirho = witness_store_chirho
            .load_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                identity_chirho.winner_term_chirho,
                &identity_chirho.winner_journal_genesis_digest_chirho,
            )
            .map_err(|refusal_chirho| lane_refusal_chirho(format!("{refusal_chirho:?}")))?
            .ok_or_else(|| {
                lane_refusal_chirho("this winner holds no signed first-record index".to_owned())
            })?;
        let witness_chirho = witness_store_chirho
            .load_winner_fork_witness_chirho(identity_chirho, &verified_index_chirho)
            .map_err(|refusal_chirho| lane_refusal_chirho(format!("{refusal_chirho:?}")))?
            .ok_or_else(|| {
                lane_refusal_chirho("this winner holds no signed fork witness".to_owned())
            })?;

        advance_sink_term_from_winner_witness_chirho(
            writer_lock_guard_chirho,
            group_digest_chirho,
            &witness_chirho,
            identity_chirho,
            published_raft_term_chirho,
        )
        .map_err(|refusal_chirho| lane_refusal_chirho(refusal_chirho.to_string()))
    }

    /// The whole verified ACCEPTED head, for consumers that need more than its digest.
    ///
    /// Same two fail-closed gates as the digest form — phase and ownership — because it IS the digest
    /// form's implementation. Kept as one loader so the lane and the cell advance can never end up
    /// reasoning about two different handoffs.
    fn accepted_gd7_winner_handoff_chirho(
        &self,
    ) -> Result<ActiveGd7WinnerHandoffChirho, ResidentLedgerAuthorityRefusalChirho> {
        let lane_refusal_chirho = |detail_chirho: String| {
            ResidentLedgerAuthorityRefusalChirho::Gd7CompensationLaneRefusedChirho { detail_chirho }
        };
        let group_digest_chirho = consistency_group_digest_chirho(&self.group_chirho)
            .map_err(|error_chirho| lane_refusal_chirho(error_chirho.to_string()))?;
        let signer_chirho = ExistingNodeGd7SignerChirho::open_existing_chirho(
            &self.canonical_root_chirho,
            &self.local_node_chirho,
        )
        .map_err(|error_chirho| lane_refusal_chirho(error_chirho.to_string()))?;
        let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
            &self.authority_storage_chirho,
            &signer_chirho,
            group_digest_chirho,
            self.local_node_chirho.0.clone(),
        )
        .map_err(|error_chirho| lane_refusal_chirho(error_chirho.to_string()))?;
        let current_chirho = store_chirho
            .load_current_chirho()
            .map_err(|error_chirho| lane_refusal_chirho(error_chirho.to_string()))?
            .ok_or_else(|| {
                lane_refusal_chirho("this node owns no durable GD7 winner handoff head".to_owned())
            })?;
        if current_chirho.checkpoint_chirho.phase_chirho
            != Gd7WinnerHandoffPhaseChirho::AcceptedChirho
        {
            return Err(lane_refusal_chirho(format!(
                "the durable GD7 winner handoff is {:?}, not accepted",
                current_chirho.checkpoint_chirho.phase_chirho
            )));
        }
        Ok(current_chirho)
    }

    fn append_with_current_fence_chirho(
        &mut self,
        mutation_chirho: ResidentLedgerMutationChirho<'_>,
    ) -> Result<ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityRefusalChirho> {
        // This acquisition is the sink-level handoff interlock for every resident mutation method.
        // Actor prechecks improve diagnosis, but bypassing them cannot bypass an active marker.
        //
        // THE ONE LAWFUL NARROWING OF THAT MARKER (GD7 resume step, ruled (a) by L.J. 2026-08-05),
        // stated for the reviewer rather than hidden: the fenced compensation append — and ONLY it —
        // may proceed while this node's own handoff is ACCEPTED, because ruled (a) puts the
        // compensation on the live winner's journal under the winner's own term. Every other
        // mutation kind keeps the unchanged refusal, including `EffectTerminalChirho`.
        //
        // Four independent gates hold this lane, and no caller supplies any of them:
        //   1. KIND — the match below is on the mutation the funnel is already executing, so
        //      nothing that merely calls itself a compensation can enter; only the private
        //      `EffectCompensationHoldChirho` variant does. Measured, because "one door" would have
        //      been the tempting wording and is wrong: that variant has ONE constructor
        //      (`record_effect_compensation_hold_chirho`) reached by TWO wire commands — the direct
        //      `AppendCompensationHoldChirho` and the completion path. Both are the same fenced,
        //      CF3-authorized compensation append, which is why both are lawful here; the gate is
        //      the variant, not a count of callers.
        //   2. PHASE + OWNERSHIP — the digest comes from this node's own durable, SIGNATURE-VERIFIED
        //      handoff head, accepted-only, at a path keyed by the winner node.
        //   3. IDENTITY — the elector admits the lane only for the EXACT active in-memory marker;
        //      a stale or forged head naming any other attempt refuses rather than falling back.
        //   4. NO RELEASE — the lane's guard type cannot retire the marker it appends under.
        // Below this point the compensation append still passes barrier 1 (the reconciliation hold,
        // which has NO exemption), the sink-term fence, and CF3 authorization, exactly as before.
        let local_authority_chirho = self.local_authority_chirho.clone();
        // The handoff evidence is loaded in the refusing branch below before the narrower handoff
        // guard is acquired. Ordinary-election receipts are different: they are gathered later
        // while the successful local-generation guard remains held. Both evidence paths stay above
        // the long-lived writer lock so no network or evidence read can hold that lock.
        let mut accepted_handoff_for_advance_chirho: Option<ActiveGd7WinnerHandoffChirho> = None;
        let generation_guard_chirho = match local_authority_chirho.try_acquire_chirho() {
            Ok(ordinary_guard_chirho) => {
                ResidentAppendGenerationGuardChirho::OrdinaryChirho(ordinary_guard_chirho)
            }
            Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
                if mutation_chirho.allows_active_handoff_chirho() =>
            {
                let accepted_handoff_chirho = self.accepted_gd7_winner_handoff_chirho()?;
                let accepted_attempt_digest_chirho =
                    accepted_handoff_chirho.attempt_digest_chirho.clone();
                accepted_handoff_for_advance_chirho = Some(accepted_handoff_chirho);
                ResidentAppendGenerationGuardChirho::ActiveHandoffCompensationChirho(
                    local_authority_chirho
                        .try_acquire_active_handoff_append_chirho(&accepted_attempt_digest_chirho)
                        .map_err(local_generation_refusal_chirho)?,
                )
            }
            Err(reason_chirho) => return Err(local_generation_refusal_chirho(reason_chirho)),
        };
        self.verify_fixed_resident_evidence_chirho()?;
        let process_generation_chirho = generation_guard_chirho.process_generation_chirho();
        let published_raft_term_chirho = generation_guard_chirho.published_raft_term_chirho();
        let current_winner_authority_chirho = match &mutation_chirho {
            ResidentLedgerMutationChirho::EffectCompensationHoldChirho {
                authorization_chirho,
                ..
            } => Some(
                derive_current_gd7_winner_compensation_authority_chirho(
                    published_raft_term_chirho,
                    authorization_chirho,
                )
                .map_err(|detail_chirho| {
                    ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho {
                        detail_chirho: detail_chirho.to_owned(),
                    }
                })?,
            ),
            _ => None,
        };
        let ordinary_term_acceptance_proof_chirho = match (
            accepted_handoff_for_advance_chirho.as_ref(),
            current_winner_authority_chirho.as_ref(),
        ) {
            (None, Some(authority_chirho)) => verify_ordinary_election_sink_term_acceptance_chirho(
                self,
                authority_chirho.published_raft_term_chirho(),
            )?,
            _ => None,
        };
        let ordinary_term_acceptance_inputs_unavailable_chirho = accepted_handoff_for_advance_chirho
            .is_none()
            && current_winner_authority_chirho.is_some()
            && (self.ordinary_term_acceptance_source_chirho.is_none()
                || self
                    .ordinary_term_acceptance_placement_binding_chirho
                    .is_none());
        let writer_fence_path_chirho = StoragePathChirho::new_chirho(
            writer_fence_storage_key_chirho(&self.group_chirho)
                .map_err(writer_fence_refusal_chirho)?,
        );
        let writer_lock_guard_chirho = self
            .writer_lock_chirho
            .try_acquire_chirho()
            .map_err(writer_fence_refusal_chirho)?;
        let group_digest_chirho =
            consistency_group_digest_chirho(&self.group_chirho).map_err(|error_chirho| {
                ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldInspectionRefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?;
        if gd7_reconciliation_group_has_any_active_hold_chirho(
            &self.authority_storage_chirho,
            &group_digest_chirho,
        )
        .map_err(|error_chirho| {
            ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldInspectionRefusedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })? {
            return Err(ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldActiveChirho);
        }
        // THE SECOND BARRIER — the ONLY presence site of the ordinary-write hold in the tree.
        //
        // EXACTLY ONE kind is exempt: the fenced compensation append, which is the leg D3's
        // release exists to unstrand. Everything else — reviewed activations, fresh effect
        // intents, AND effect terminals — is ordinary work and stays withheld until D4 confirms.
        //
        // The exemption set is MEASURED, not reasoned. An earlier draft also exempted
        // `EffectTerminalChirho` on the theory that it is how a compensation reaches
        // `CompletedChirho`; two mutations against the landed B3c full-chain arm refuted that.
        // Dropping the compensation exemption turns that arm RED at LINK 6, so this one is
        // load-bearing; dropping the terminal exemption leaves it GREEN, because LINK 7 completes
        // through the GD7 obligation-processing storage, never through this funnel. The only
        // production caller of `record_effect_terminal_chirho` is the generic `AppendTerminalChirho`
        // command, i.e. ordinary effect lifecycle. Exempting it would have admitted a whole class
        // of ordinary writes the barrier exists to withhold.
        //
        // Absence of the hold is pass-through, never a grant; the bytes are not read (`object_len`
        // only), so stale or malformed content can never admit a writer.
        if !mutation_chirho.allows_active_handoff_chirho()
            && gd7_reconciliation_group_ordinary_writes_withheld_chirho(
                &self.authority_storage_chirho,
                &group_digest_chirho,
            )
            .map_err(|error_chirho| {
                ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldInspectionRefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                }
            })?
        {
            return Err(ResidentLedgerAuthorityRefusalChirho::Gd7OrdinaryWritesWithheldChirho);
        }
        let max_fence_bytes_chirho = u64::try_from(MAX_WRITER_FENCE_FILE_BYTES_CHIRHO)
            .expect("fixed writer-fence byte bound fits u64");
        let durable_state_bytes_chirho = self
            .authority_storage_chirho
            .read_bounded_object_chirho(&writer_fence_path_chirho, max_fence_bytes_chirho)
            .map_err(writer_fence_refusal_chirho)?;
        let prepared_fence_chirho = prepare_reused_or_issued_elected_writer_fence_chirho(
            &self.group_chirho,
            published_raft_term_chirho,
            self.active_fence_chirho.as_ref(),
            durable_state_bytes_chirho.as_deref(),
            self.ports_chirho.clock_chirho.physical_now_ms_chirho(),
        )
        .map_err(writer_fence_refusal_chirho)?;
        let durable_state_epoch_before_chirho = prepared_fence_chirho
            .durable_state_epoch_before_chirho()
            .unwrap_or(0);
        let journal_epoch_before_chirho = self
            .journal_chirho
            .as_ref()
            .expect("resident authority retains its journal")
            .current_epoch_chirho();
        let membership_epoch_before_chirho =
            self.ports_chirho.membership_chirho.current_epoch_chirho();
        let unfenced_pregeo_birth_chirho = prepared_fence_chirho
            .durable_state_epoch_before_chirho()
            .is_none()
            && self.active_fence_chirho.is_none()
            && split_writer_epoch_chirho(journal_epoch_before_chirho).geo_term_chirho == 0
            && split_writer_epoch_chirho(membership_epoch_before_chirho).geo_term_chirho == 0;
        if journal_epoch_before_chirho > durable_state_epoch_before_chirho
            && !unfenced_pregeo_birth_chirho
        {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::JournalAheadOfDurableFenceStateChirho {
                    journal_epoch_chirho: journal_epoch_before_chirho,
                    fence_state_epoch_chirho: durable_state_epoch_before_chirho,
                },
            );
        }
        if membership_epoch_before_chirho > durable_state_epoch_before_chirho
            && !unfenced_pregeo_birth_chirho
        {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfDurableFenceStateChirho {
                    membership_epoch_chirho: membership_epoch_before_chirho,
                    fence_state_epoch_chirho: durable_state_epoch_before_chirho,
                },
            );
        }
        if let Some(replacement_state_bytes_chirho) =
            prepared_fence_chirho.replacement_state_bytes_chirho()
        {
            self.authority_storage_chirho
                .atomic_write_chirho(&writer_fence_path_chirho, replacement_state_bytes_chirho)
                .map_err(writer_fence_refusal_chirho)?;
        }
        let fence_chirho = prepared_fence_chirho.token_chirho().clone();
        self.active_fence_chirho = Some(fence_chirho.clone());

        let fence_term_chirho =
            u64::from(split_writer_epoch_chirho(fence_chirho.epoch_chirho).geo_term_chirho);
        if fence_term_chirho != published_raft_term_chirho {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::FenceTermMismatchChirho {
                    published_raft_term_chirho,
                    fence_term_chirho,
                },
            );
        }
        if journal_epoch_before_chirho > fence_chirho.epoch_chirho {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::JournalAheadOfFenceChirho {
                    journal_epoch_chirho: journal_epoch_before_chirho,
                    fence_epoch_chirho: fence_chirho.epoch_chirho,
                },
            );
        }
        if membership_epoch_before_chirho > fence_chirho.epoch_chirho {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfFenceChirho {
                    membership_epoch_chirho: membership_epoch_before_chirho,
                    fence_epoch_chirho: fence_chirho.epoch_chirho,
                },
            );
        }
        let journal_chirho = self
            .journal_chirho
            .as_mut()
            .expect("resident authority retains its journal");
        if journal_epoch_before_chirho < fence_chirho.epoch_chirho {
            journal_chirho
                .advance_epoch_chirho(fence_chirho.epoch_chirho)
                .map_err(|error_chirho| {
                    ResidentLedgerAuthorityRefusalChirho::JournalMutationRefusedChirho {
                        detail_chirho: format!("{error_chirho:?}"),
                    }
                })?;
        }
        self.ports_chirho
            .membership_chirho
            .rebind_epoch_chirho(fence_chirho.epoch_chirho)
            .map_err(|error_chirho| {
                ResidentLedgerAuthorityRefusalChirho::MembershipMutationRefusedChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                }
            })?;
        writer_lock_guard_chirho
            .verify_custody_chirho()
            .map_err(writer_fence_refusal_chirho)?;
        if matches!(
            &mutation_chirho,
            ResidentLedgerMutationChirho::EffectCompensationHoldChirho { .. }
        ) {
            let mut sink_term_fence_state_chirho =
                read_sink_term_fence_chirho(&writer_lock_guard_chirho, &group_digest_chirho)
                    .map_err(|error_chirho| {
                        ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho {
                            detail_chirho: format!("{error_chirho:?}"),
                        }
                    })?;
            // THE WINNER-OWN-TERM ADVANCE, ON DEMAND (D1, ruled (i) 2026-08-06). Before this, a
            // winner whose own cell sat at its birth term refused its own lawful compensation with
            // `UnseenWinnerTermChirho` and had no lawful mover — the fence advanced only on evidence
            // of somebody ELSE's deposition.
            //
            // Narrow by construction, three ways: it runs only for the compensation mutation, only
            // when a cell EXISTS and is strictly BEHIND the published term, and it moves the cell to
            // a term read out of this node's own signed fork witness. An ABSENT cell is deliberately
            // left to the unchanged refusal below — creating a fence from nothing is birth's job,
            // not a compensation's, and failing closed there costs only an operator round trip.
            let published_winner_term_chirho = current_winner_authority_chirho
                .as_ref()
                .expect("compensation authority is derived for the compensation mutation")
                .published_raft_term_chirho();
            let cell_is_behind_chirho =
                sink_term_fence_state_chirho
                    .as_ref()
                    .is_some_and(|state_chirho| {
                        state_chirho.highest_accepted_winner_term_chirho
                            < published_winner_term_chirho
                    });
            // BOTH conditions, and the second is the one the strand tests taught me. A behind cell
            // is NOT sufficient: an UNFROZEN node whose cell is behind is the held-side strand, and
            // it must keep refusing until the witness-bounded D2 advance lifts it. Only a winner
            // that came through the exempt lane — and therefore holds its own verified ACCEPTED
            // handoff — may teach its own fence. Gating on the handoff's presence rather than on a
            // separate flag keeps the two facts from drifting apart.
            if let Some(accepted_handoff_chirho) = accepted_handoff_for_advance_chirho
                .as_ref()
                .filter(|_handoff_chirho| cell_is_behind_chirho)
            {
                Self::advance_own_winner_term_sink_cell_chirho(
                    &self.canonical_root_chirho,
                    &self.local_node_chirho,
                    self.ports_chirho.signer_chirho,
                    &writer_lock_guard_chirho,
                    &group_digest_chirho,
                    accepted_handoff_chirho,
                    published_winner_term_chirho,
                )?;
                // Re-read rather than trust the advance's return: the check below must decide on
                // what is DURABLE, not on what this call believes it wrote.
                sink_term_fence_state_chirho =
                    read_sink_term_fence_chirho(&writer_lock_guard_chirho, &group_digest_chirho)
                        .map_err(|error_chirho| {
                            ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho {
                                detail_chirho: format!("{error_chirho:?}"),
                            }
                        })?;
            }
            if let Some(proof_chirho) = ordinary_term_acceptance_proof_chirho.as_ref() {
                let current_tail_chirho = journal_chirho.verified_append_mirror_tail_chirho();
                if current_tail_chirho.tail_seq_chirho() != proof_chirho.tail_seq_chirho()
                    || current_tail_chirho.tail_record_digest_chirho().0
                        != proof_chirho.tail_record_digest_chirho()
                {
                    return Err(
                        ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceRefusedChirho {
                            detail_chirho:
                                "OrdinaryElectionSinkTermLocalTailChangedBeforeAdvanceChirho"
                                    .to_owned(),
                        },
                    );
                }
                advance_sink_term_from_ordinary_election_chirho(
                    &writer_lock_guard_chirho,
                    &self.group_chirho,
                    published_winner_term_chirho,
                    proof_chirho,
                )
                .map_err(|error_chirho| {
                    ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceRefusedChirho {
                        detail_chirho: error_chirho.to_string(),
                    }
                })?;
                // The strict check below consumes only a durable reread, never the mover's return.
                sink_term_fence_state_chirho =
                    read_sink_term_fence_chirho(&writer_lock_guard_chirho, &group_digest_chirho)
                        .map_err(|error_chirho| {
                            ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho {
                                detail_chirho: format!("{error_chirho:?}"),
                            }
                        })?;
            }
            verify_supplied_winner_term_is_strictly_current_chirho(
                sink_term_fence_state_chirho.as_ref(),
                current_winner_authority_chirho
                    .as_ref()
                    .expect("compensation authority is derived for the compensation mutation")
                    .published_raft_term_chirho(),
            )
            .map_err(|reason_chirho| {
                if ordinary_term_acceptance_inputs_unavailable_chirho
                    && matches!(
                        reason_chirho,
                        SinkTermFenceRefusalChirho::UnseenWinnerTermChirho { .. }
                    )
                {
                    ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho
                } else {
                    ResidentLedgerAuthorityRefusalChirho::CompensationFenceRefusedChirho {
                        reason_chirho,
                    }
                }
            })?;
        }
        // THE WARRANT PRECEDES THE MONEY. Every effect mutation publishes its signed line to the
        // bounded public projection here — after all authority is established, and before the
        // journal append below. A crash between the two leaves an ORPHAN warrant, which is inert:
        // every production reader looks a warrant up by a ref taken from a record it already found
        // in the journal, so a warrant with no record is unreachable. The reverse order would leave
        // a committed losing-suffix record that GD7 reconciliation cannot compensate. This composes
        // the SAME order as the CF3 commit coordinator, not a second doctrine.
        publish_effect_warrant_for_mutation_chirho(&self.canonical_root_chirho, &mutation_chirho)?;
        let append_chirho = match mutation_chirho {
            ResidentLedgerMutationChirho::ReviewedActivationChirho { request_chirho } => {
                journal_chirho.append_chirho(request_chirho)
            }
            ResidentLedgerMutationChirho::EffectHoldChirho {
                canonical_intent_line_chirho,
                verifier_chirho,
            } => journal_chirho
                .append_effect_intent_chirho(canonical_intent_line_chirho, verifier_chirho),
            ResidentLedgerMutationChirho::EffectCompensationHoldChirho {
                canonical_intent_line_chirho,
                verifier_chirho,
                authorization_chirho,
            } => journal_chirho
                .append_effect_compensation_chirho(
                    canonical_intent_line_chirho,
                    verifier_chirho,
                    authorization_chirho,
                )
                .map_err(|error_chirho| match error_chirho {
                    cairn_ledger_log_chirho::EffectCompensationJournalErrorChirho::JournalChirho(
                        journal_error_chirho,
                    ) => journal_error_chirho,
                    error_chirho => cairn_ledger_log_chirho::journal_chirho::JournalErrorChirho::EffectIntentChirho {
                        detail_chirho: format!("{error_chirho:?}"),
                    },
                }),
            ResidentLedgerMutationChirho::EffectTerminalChirho {
                canonical_intent_line_chirho,
                intent_verifier_chirho,
                canonical_terminal_line_chirho,
                terminal_verifier_chirho,
            } => journal_chirho.append_effect_terminal_chirho(
                canonical_intent_line_chirho,
                intent_verifier_chirho,
                canonical_terminal_line_chirho,
                terminal_verifier_chirho,
            ),
            ResidentLedgerMutationChirho::TestkindLossWitnessTransferChirho {
                request_chirho,
            } => journal_chirho.append_chirho(request_chirho),
        }
        .map_err(|error_chirho| match error_chirho {
            cairn_ledger_log_chirho::journal_chirho::JournalErrorChirho::MirrorReconciliationRefusedChirho {
                detail_chirho,
            } => ResidentLedgerAuthorityRefusalChirho::MirrorReconciliationRefusedChirho {
                detail_chirho,
            },
            cairn_ledger_log_chirho::journal_chirho::JournalErrorChirho::MirrorPrepareRefusedChirho {
                detail_chirho,
            } => ResidentLedgerAuthorityRefusalChirho::MirrorPrepareRefusedChirho {
                detail_chirho,
            },
            cairn_ledger_log_chirho::journal_chirho::JournalErrorChirho::MirrorCommittedEvidencePendingChirho {
                receipt_chirho,
                detail_chirho,
            } => ResidentLedgerAuthorityRefusalChirho::MirrorCommittedEvidencePendingChirho {
                receipt_chirho: Box::new(ResidentLedgerAppendReceiptChirho {
                    append_chirho: *receipt_chirho,
                    fence_chirho: fence_chirho.clone(),
                    process_generation_chirho,
                    published_raft_term_chirho,
                }),
                detail_chirho,
            },
            error_chirho => ResidentLedgerAuthorityRefusalChirho::JournalMutationRefusedChirho {
                detail_chirho: format!("{error_chirho:?}"),
            },
        })?;
        Ok(ResidentLedgerAppendReceiptChirho {
            append_chirho,
            fence_chirho,
            process_generation_chirho,
            published_raft_term_chirho,
        })
    }
}

impl Drop for ResidentLedgerAuthorityChirho<'_> {
    fn drop(&mut self) {
        drop(self.journal_chirho.take());
        drop(self.resident_lease_chirho.take());
    }
}

fn journal_ports_chirho<'ports_chirho>(
    ports_chirho: ResidentLedgerLocalPortsChirho<'ports_chirho>,
) -> JournalPortsChirho<'ports_chirho> {
    JournalPortsChirho {
        storage_chirho: ports_chirho.storage_chirho,
        signer_chirho: ports_chirho.signer_chirho,
        clock_chirho: ports_chirho.clock_chirho,
        membership_chirho: ports_chirho.membership_chirho,
        kind_registry_chirho: ports_chirho.kind_registry_chirho,
        authority_chirho: ports_chirho.authority_chirho,
    }
}

fn validate_epoch_posture_chirho(
    journal_epoch_chirho: u64,
    membership_epoch_chirho: u64,
    published_raft_term_chirho: u64,
) -> Result<(), ResidentLedgerAuthorityRefusalChirho> {
    if membership_epoch_chirho > journal_epoch_chirho {
        return Err(
            ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfJournalChirho {
                journal_epoch_chirho,
                membership_epoch_chirho,
            },
        );
    }
    if u64::from(split_writer_epoch_chirho(journal_epoch_chirho).geo_term_chirho)
        > published_raft_term_chirho
    {
        return Err(
            ResidentLedgerAuthorityRefusalChirho::JournalAheadOfPublishedRaftTermChirho {
                journal_epoch_chirho,
                published_raft_term_chirho,
            },
        );
    }
    if u64::from(split_writer_epoch_chirho(membership_epoch_chirho).geo_term_chirho)
        > published_raft_term_chirho
    {
        return Err(
            ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfPublishedRaftTermChirho {
                membership_epoch_chirho,
                published_raft_term_chirho,
            },
        );
    }
    Ok(())
}

/// Wait through only the two self-clearing local transition-contention states.
///
/// Every authority or leadership refusal still returns immediately. The attempt cap keeps a stuck
/// transition fail-closed and bounds each caller's wait to less than one second of pauses. Startup
/// uses this for generation bracketing; the post-append path uses it only for its read-only reprobe.
///
/// HANDOFF-AWARE, not handoff-exempt (GD7 resume step, ruled (a) 2026-08-05). It acquires
/// coordinates through `try_acquire_startup_coordinates_chirho`, which an active winner-handoff
/// marker does not refuse — so a frozen WINNER can open its resident and carry its own compensation.
/// Opening is not appending: the returned type is accepted by no append path, and the append funnel
/// still reacquires ordinary authority at the sink and still sees `HandoffActiveChirho` for every
/// mutation but the one exempt lane. `HandoffActiveChirho` is deliberately absent from the retry set
/// below and must stay absent: a freeze propagates immediately, it never spins.
fn acquire_resident_startup_generation_chirho(
    local_authority_chirho: &LocalAppendAuthorityHandleChirho,
) -> Result<LocalStartupCoordinatesGuardChirho<'_>, LocalAppendAuthorityRefusalChirho> {
    retry_resident_generation_contention_chirho(
        || local_authority_chirho.try_acquire_startup_coordinates_chirho(),
        |reason_chirho| Some(*reason_chirho),
        |_reason_chirho| {},
        || thread::sleep(RESIDENT_GENERATION_CONTENTION_PAUSE_CHIRHO),
        RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO,
    )
}

fn retry_resident_generation_contention_chirho<TChirho, ErrorChirho>(
    mut operation_chirho: impl FnMut() -> Result<TChirho, ErrorChirho>,
    mut local_refusal_chirho: impl FnMut(&ErrorChirho) -> Option<LocalAppendAuthorityRefusalChirho>,
    mut observe_contention_chirho: impl FnMut(LocalAppendAuthorityRefusalChirho),
    mut pause_chirho: impl FnMut(),
    attempt_limit_chirho: usize,
) -> Result<TChirho, ErrorChirho> {
    assert!(
        attempt_limit_chirho > 0,
        "resident generation contention retry requires at least one attempt"
    );
    for attempt_index_chirho in 0..attempt_limit_chirho {
        let outcome_chirho = operation_chirho();
        let contention_chirho = outcome_chirho
            .as_ref()
            .err()
            .and_then(&mut local_refusal_chirho)
            .filter(|reason_chirho| {
                matches!(
                    reason_chirho,
                    LocalAppendAuthorityRefusalChirho::TransitionPendingChirho
                        | LocalAppendAuthorityRefusalChirho::GuardBusyChirho
                )
            });
        let Some(reason_chirho) = contention_chirho else {
            return outcome_chirho;
        };
        observe_contention_chirho(reason_chirho);
        if attempt_index_chirho + 1 == attempt_limit_chirho {
            return outcome_chirho;
        }
        pause_chirho();
    }
    unreachable!("positive resident contention attempt limit always returns from the loop")
}
