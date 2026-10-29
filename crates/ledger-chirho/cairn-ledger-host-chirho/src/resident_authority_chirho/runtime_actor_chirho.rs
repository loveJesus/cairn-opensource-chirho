// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! H4's process-resident journal authority.
//!
//! One bounded mailbox owns the recovered elector, resident lease, journal, signers, verified
//! registry, receipt-bound canary store, and held-only GD7 plan ports for their full lifetimes.
//! Effect callers receive only the neutral effect-journal port; the concrete host handle can also
//! reduce one already-manifested GD7 page or reverify one complete sealed plan without exposing any
//! path, raw journal, writer fence, signer, elector, observation, compensation, adoption, or
//! write-reenable authority.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
//! GD7 workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::testkind_loss_witness_chirho::{
    derive_resident_testkind_loss_witness_plan_chirho, ResidentTestkindLossWitnessOpenerModeChirho,
    ResidentTestkindLossWitnessPlanChirho, ResidentTestkindLossWitnessRoleChirho,
};
use super::{
    retry_resident_generation_contention_chirho, ResidentLedgerAppendReceiptChirho,
    ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityReadinessChirho,
    ResidentLedgerAuthorityRefusalChirho, ResidentLedgerLocalPortsChirho,
    ResidentTestkindLossWitnessCommitChirho, ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessPhaseChirho, ResidentTestkindLossWitnessRefusalChirho,
    RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO, RESIDENT_GENERATION_CONTENTION_PAUSE_CHIRHO,
};
use crate::authority_chirho::{
    PinnedKindIssuerVerifierChirho, PinnedLedgerActivationVerifierChirho,
    PlatformPolicyMintAuthorityChirho, StaticClusterMembershipChirho,
};
use crate::custody_chirho::verify_host_ledger_config_custody_chirho;
use crate::elected_head_transition_chirho::ElectedHeadTransitionAdapterChirho;
use crate::reconciliation_chirho::{
    drive_gd7_reconciliation_plan_page_chirho, verify_sealed_gd7_reconciliation_plan_chirho,
    AuthenticatedGd7DeposedForkObservationChirho, ConvergedReadReplicaChirho,
    ExistingNodeGd7SignerChirho, Gd7ConservationProofPortsChirho,
    Gd7ConservationSnapshotProviderChirho, Gd7ConservationSnapshotProviderRefChirho,
    Gd7ConservationSnapshotSourcePortChirho, Gd7ConservationSnapshotVerifierPortChirho,
    Gd7ConvergenceBindingInputChirho, Gd7ConvergenceUnmeasuredPredicatesChirho,
    Gd7EffectProofPortsChirho, Gd7LedgerRecordVerifierPortChirho,
    Gd7ObligationProcessingStateChirho, Gd7PlanPageDriveOutcomeChirho, Gd7PlanRefusalChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    Gd7WinnerHandoffStoreChirho, Gd7WinnerWitnessStoreChirho,
    PinnedTenantMigrationDestinationAuthorityChirho, RootGd7EffectEvidenceReaderChirho,
    VerifiedGd7SealedPlanProofChirho,
};
use crate::signer_chirho::{host_ledger_signer_refs_from_config_chirho, HostLedgerSignersChirho};
use crate::storage_chirho::FsLedgerStorageChirho;
use crate::test_kind_fence_chirho::{
    refuse_test_kind_marked_host_config_chirho, require_test_kind_marked_host_config_chirho,
};
use crate::ResidentLedgerClockChirho;
use anyhow::{anyhow, bail, Context, Result};
use cairn_config_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitContinuationViewChirho, EffectCommitJournalCommittedEvidenceIdentityChirho,
    EffectCommitJournalMirrorRefusalIdentityChirho, EffectCommitJournalPortChirho,
    EffectCommitJournalPortErrorChirho, EffectCommitJournalReceiptChirho,
    EffectCommitJournalResidentRefusalIdentityChirho, EffectCommitJournalViewPortChirho,
    EffectIntentJournalStateChirho, VerifiedEffectReceiptInventoryEntryChirho,
};
use cairn_effect_commit_chirho::intent_chirho::EffectIntentJournalCutChirho;
use cairn_kind_registry_chirho::chain_chirho::{
    load_verified_registry_chirho, KindRegistryPortsChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_log_chirho::recovery_mirror_chirho::LedgerMirrorRuntimePortsChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_tenant_migration_chirho::TenantLedgerVerificationViewsChirho;
use cairn_ledger_tenant_migration_durable_chirho::TenantMigrationDestinationAuthorityPortChirho;
use cairn_ledger_tenant_migration_durable_chirho::TenantMigrationStoreChirho;
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::{
    observe_shadow_canary_chirho, ShadowCanaryAppendCutChirho, ShadowCanaryChirho,
};
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::{
    ShadowCanaryGenerationStoreChirho, ShadowCanaryLedgerCutChirho,
    VerifiedShadowCanaryCurrentGenerationChirho,
};
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityHandleChirho, LocalAppendAuthorityRefusalChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, consistency_group_for_root_chirho, split_writer_epoch_chirho,
    ConsistencyGroupIdChirho,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

#[path = "runtime_actor_chirho/migration_chirho/append_barrier_chirho.rs"]
mod append_barrier_chirho;
#[cfg(test)]
#[path = "resident_mutation_chirho/canary_alignment_tests_chirho.rs"]
mod canary_alignment_tests_chirho;
#[path = "runtime_actor_chirho/command_dispatch_chirho.rs"]
mod command_dispatch_chirho;
#[path = "runtime_actor_chirho/gd7_compensation_composition_chirho.rs"]
mod gd7_compensation_composition_chirho;
#[path = "runtime_actor_chirho/journal_port_refusal_chirho.rs"]
mod journal_port_refusal_chirho;
#[path = "resident_mutation_chirho/envelope_chirho.rs"]
mod resident_mutation_envelope_chirho;
#[cfg(test)]
#[path = "resident_mutation_chirho/shutdown_tests_chirho.rs"]
mod shutdown_tests_chirho;
#[path = "resident_mutation_chirho/testkind_handle_chirho.rs"]
mod testkind_loss_witness_handle_chirho;
use journal_port_refusal_chirho::{
    bounded_inventory_chirho, committed_pending_chirho, effect_receipt_chirho, refused_chirho,
    resident_refusal_chirho, resident_refused_chirho, unavailable_chirho,
};
#[path = "runtime_actor_chirho/migration_chirho/operation_dispatch_tests_chirho.rs"]
#[cfg(test)]
mod operation_dispatch_tests_chirho;
pub(super) use gd7_compensation_composition_chirho::{
    derive_current_gd7_winner_compensation_authority_chirho,
    derive_gd7_compensation_provider_idempotency_key_chirho,
    execute_gd7_compensation_provider_chirho, RefusingGd7CompensationProviderChirho,
};
/// `Gd7CompensationCompositionRefusalChirho` joins this list for the reason its neighbour
/// `Gd7CompensationCompletionRefusalChirho` already carries: it is the error type of the `pub`
/// wire method `compose_gd7_compensation_chirho`, whose caller is the success ladder in
/// `cairn-ledger-regenesis-chirho`. A caller that cannot NAME an error cannot assert WHICH refusal
/// it received — and on this path the two refusals mean opposite things (`ProviderNotConfigured`
/// = the intent is persisted, compose again; `ResumeWindowExpired` = the obligation is now held for
/// an operator). Widening an ERROR type adds no capability: nothing here produces an obligation,
/// mints, or touches custody.
///
/// `Gd7CompensationProviderAdapterChirho` and `Gd7CompensationProviderObservationChirho` join for
/// the capstone's layer 2: the completing provider is implemented in the regenesis crate and
/// supplied through the ONE opener that accepts one
/// (`open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho`). The REFUSING
/// default deliberately stays `pub(super)`: no caller outside this module needs to name it,
/// because absence (`None`) IS the refusing posture.
pub use gd7_compensation_composition_chirho::{
    Gd7CompensationCompositionRefusalChirho, Gd7CompensationProviderAdapterChirho,
    Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho,
};
#[path = "runtime_actor_chirho/gd7_committed_evidence_arms_chirho.rs"]
#[cfg(test)]
mod gd7_committed_evidence_arms_chirho;
#[path = "runtime_actor_chirho/gd7_completed_leg_chirho.rs"]
mod gd7_completed_leg_chirho;
/// Re-exported `pub` for the reason the enum's own doc already carries: it is the error type of
/// the `pub` wire method `complete_gd7_compensation_chirho`, and the capstone arms must assert
/// WHICH refusal came back — the append family versus anything upstream — not merely that some
/// error arrived. An error type adds no capability.
pub use gd7_completed_leg_chirho::Gd7CompensationCompletionRefusalChirho;
pub(super) use gd7_completed_leg_chirho::{
    finish_gd7_compensation_completion_chirho, plan_gd7_compensation_completion_chirho,
    Gd7CompensationCompletionPlanChirho,
};
#[path = "runtime_actor_chirho/migration_chirho/capacity_admission_runtime_chirho.rs"]
mod capacity_admission_runtime_chirho;
#[path = "runtime_actor_chirho/migration_chirho/configured_namespace_chirho.rs"]
mod configured_namespace_chirho;
#[path = "runtime_actor_chirho/gd7_wire_handle_chirho.rs"]
mod gd7_wire_handle_chirho;
#[path = "runtime_actor_chirho/mailbox_chirho.rs"]
mod mailbox_chirho;
#[path = "runtime_actor_chirho/post_append_reprobe_chirho.rs"]
mod post_append_reprobe_chirho;
#[path = "runtime_actor_chirho/recovery_adoption_chirho.rs"]
mod recovery_adoption_chirho;
#[path = "runtime_actor_chirho/migration_chirho/target_adoption_chirho.rs"]
pub(super) mod target_adoption_chirho;
#[path = "runtime_actor_chirho/migration_chirho/tenant_migration_operation_chirho.rs"]
mod tenant_migration_operation_chirho;
#[path = "runtime_actor_chirho/winner_adoption_evidence_chirho.rs"]
mod winner_adoption_evidence_chirho;
#[path = "runtime_actor_chirho/winner_evidence_chirho.rs"]
mod winner_evidence_chirho;
#[path = "runtime_actor_chirho/winner_handoff_chirho.rs"]
mod winner_handoff_chirho;
#[cfg(test)]
#[path = "runtime_actor_chirho/migration_chirho/writer_adoption_chirho/tests_chirho.rs"]
mod writer_adoption_tests_chirho;
use super::writer_adoption_chirho::consume_writer_adoption_warrant_chirho;
use append_barrier_chirho::ResidentAppendBarrierRuntimeChirho;
#[cfg(test)]
pub(crate) use capacity_admission_runtime_chirho::admitting_test_capacity_composition_chirho;
pub use capacity_admission_runtime_chirho::{
    TenantMigrationCapacityAdmissionCompositionChirho,
    TenantMigrationCapacityCompositionRefusalChirho,
};
use command_dispatch_chirho::{
    handle_actor_command_chirho, ResidentTenantMigrationAdmittedCommandChirho,
};
use mailbox_chirho::ResidentEffectJournalCommandChirho;
use post_append_reprobe_chirho::{
    probe_after_committed_append_chirho, PostAppendReprobeRefusalChirho,
    ResidentMutationCommandKindChirho,
};
use recovery_adoption_chirho::{
    prepare_resident_recovery_adoption_chirho, ResidentCurrentHolderWriteReadinessChirho,
    ResidentRecoveryAdoptionInputChirho,
};
use resident_mutation_envelope_chirho::{
    complete_resident_mutation_chirho, ensure_canary_ready_chirho,
    execute_resident_mutation_chirho, prepare_resident_mutation_chirho,
    sticky_committed_refusal_chirho, verify_canary_generation_posture_chirho,
    verify_preflight_canary_alignment_chirho, verify_readiness_canary_alignment_chirho,
    ResidentMutationEnvelopeChirho, ResidentMutationLaneChirho,
};
use tenant_migration_operation_chirho::ResidentTenantMigrationOperationRuntimeChirho;
#[cfg(test)]
pub(crate) use tenant_migration_operation_chirho::{
    seed_migration_reference_chirho, stage_adopted_writer_identity_chirho,
    stage_migration_target_surfaces_chirho,
};
/// Re-exported for the OPERATOR PATH only. The handle is how a live winner process is asked to
/// activate a tenant-root migration; nothing else outside this crate needs it, and the socket that
/// names it exists only in the test-kind geo-node binary.
pub use tenant_migration_operation_chirho::{
    ResidentTenantMigrationOperationHandleChirho, ResidentTenantMigrationOperationRefusalChirho,
    ResidentTenantMigrationSourceFenceStatusChirho,
    ResidentTenantMigrationTargetActivatedStatusChirho,
};
pub use testkind_loss_witness_handle_chirho::ResidentTestkindLossWitnessHandleChirho;
use winner_adoption_evidence_chirho::{
    handle_resident_gd7_winner_adoption_evidence_chirho,
    ResidentGd7WinnerAdoptionEvidenceStateChirho,
};
pub use winner_adoption_evidence_chirho::{
    ResidentGd7WinnerAdoptionEvidenceHandleChirho,
    ResidentGd7WinnerAdoptionEvidenceInspectionChirho,
    ResidentGd7WinnerAdoptionEvidenceRefusalChirho,
};
use winner_evidence_chirho::{
    fetch_resident_gd7_winner_view_page_chirho,
    issue_first_resident_gd7_winner_view_page_grant_chirho,
    observe_resident_gd7_deposed_fork_chirho, seal_resident_gd7_winner_current_view_chirho,
    seal_resident_gd7_winner_current_view_for_held_chirho,
    stage_resident_gd7_winner_view_page_chirho, ResidentGd7WinnerViewStateChirho,
};
pub use winner_evidence_chirho::{
    ResidentGd7WinnerEvidenceHandleChirho, ResidentGd7WinnerEvidenceRefusalChirho,
    ResidentGd7WinnerForkObservationChirho, ResidentGd7WinnerForkObservationRefusalChirho,
    ResidentGd7WinnerViewSealChirho, ResidentGd7WinnerViewStageInspectionChirho,
};
use winner_handoff_chirho::{
    handle_resident_gd7_winner_handoff_chirho, ResidentGd7WinnerHandoffRuntimeChirho,
};
pub use winner_handoff_chirho::{
    ResidentGd7WinnerHandoffHandleChirho, ResidentGd7WinnerHandoffRefusalChirho,
    ResidentGd7WinnerHandoffStatusChirho,
};

const RESIDENT_EFFECT_JOURNAL_MAILBOX_CAPACITY_CHIRHO: usize = 32;
const RESIDENT_EFFECT_JOURNAL_TICK_INTERVAL_MS_CHIRHO: u64 = 50;
/// Ticks between holder re-seed attempts while the write population is unseeded. At the 50ms tick
/// above this is ~2s: slow enough that an unreachable holder cannot turn the retry into a busy loop
/// on the ordering-critical actor, fast enough that a holder which returns mid-drill is picked up
/// within one phase rather than one window.
const RESIDENT_HOLDER_RESEED_TICKS_CHIRHO: u32 = 40;
const RESIDENT_EFFECT_JOURNAL_WARMUP_TICKS_CHIRHO: u8 = 10;
const RESIDENT_EFFECT_JOURNAL_ELECTION_DIR_CHIRHO: &str = "writer-election-chirho";
pub(crate) const RESIDENT_EFFECT_JOURNAL_CANARY_DIR_CHIRHO: &str = "writer-canary-chirho";

type ResidentEffectJournalResultChirho<OutputChirho> =
    std::result::Result<OutputChirho, EffectCommitJournalPortErrorChirho>;

enum ResidentElectionCompositionChirho {
    ReopenOwnedSingleNodeChirho,
    UseSharedClusterElectorChirho(Weak<RaftWriterElectorChirho>),
}

/// Optional resident services that must travel as one actor-startup composition.
///
/// Fields stay private so callers cannot partially initialize the money-adjacent provider lane.
/// The completing-provider constructor is deliberately explicit and remains exported only through
/// the existing compensation-provider door.
pub struct ResidentActorServiceCompositionChirho {
    mirror_runtime_chirho: Option<LedgerMirrorRuntimePortsChirho>,
    conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
    capacity_admission_chirho: Option<TenantMigrationCapacityAdmissionCompositionChirho>,
    gd7_compensation_provider_chirho: Option<Box<dyn Gd7CompensationProviderAdapterChirho + Send>>,
}

impl ResidentActorServiceCompositionChirho {
    fn with_refusing_compensation_chirho(
        mirror_runtime_chirho: Option<LedgerMirrorRuntimePortsChirho>,
        conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
        capacity_admission_chirho: Option<TenantMigrationCapacityAdmissionCompositionChirho>,
    ) -> Self {
        Self {
            mirror_runtime_chirho,
            conservation_provider_chirho,
            capacity_admission_chirho,
            gd7_compensation_provider_chirho: None,
        }
    }

    pub fn with_gd7_compensation_provider_chirho(
        mirror_runtime_chirho: Option<LedgerMirrorRuntimePortsChirho>,
        conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
        capacity_admission_chirho: Option<TenantMigrationCapacityAdmissionCompositionChirho>,
        gd7_compensation_provider_chirho: Box<dyn Gd7CompensationProviderAdapterChirho + Send>,
    ) -> Self {
        Self {
            mirror_runtime_chirho,
            conservation_provider_chirho,
            capacity_admission_chirho,
            gd7_compensation_provider_chirho: Some(gd7_compensation_provider_chirho),
        }
    }
}

struct ResidentActorStartupChirho {
    local_append_authority_chirho: LocalAppendAuthorityHandleChirho,
    ledger_config_chirho: LedgerHostConfigChirho,
}

struct PendingCanaryObservationChirho {
    receipt_chirho: EffectCommitJournalReceiptChirho,
    origin_identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
    observation_chirho: ShadowCanaryChirho,
}

struct StickyCommittedRefusalChirho {
    receipt_chirho: EffectCommitJournalReceiptChirho,
    origin_identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
    detail_chirho: String,
}

struct ResidentCanaryStateChirho {
    latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho,
    pending_chirho: Option<PendingCanaryObservationChirho>,
    sticky_refusal_chirho: Option<StickyCommittedRefusalChirho>,
}

pub(crate) struct ResidentGd7PlanPortsChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho FsLedgerStorageChirho,
    held_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
    losing_record_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
    evidence_chirho: RootGd7EffectEvidenceReaderChirho,
    intent_verifier_chirho:
        &'ports_chirho dyn cairn_effect_commit_chirho::intent_chirho::EffectIntentSignerPortChirho,
    terminal_verifier_chirho:
        &'ports_chirho dyn cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho,
    conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
}

impl ResidentGd7PlanPortsChirho<'_> {
    pub(crate) fn new_chirho<'ports_chirho>(
        storage_chirho: &'ports_chirho FsLedgerStorageChirho,
        root_chirho: &Path,
        held_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
        losing_record_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
        intent_verifier_chirho: &'ports_chirho dyn cairn_effect_commit_chirho::intent_chirho::EffectIntentSignerPortChirho,
        terminal_verifier_chirho: &'ports_chirho dyn cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho,
        conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
    ) -> ResidentGd7PlanPortsChirho<'ports_chirho> {
        ResidentGd7PlanPortsChirho {
            storage_chirho,
            held_signer_chirho,
            losing_record_verifier_chirho,
            evidence_chirho: RootGd7EffectEvidenceReaderChirho::new_chirho(root_chirho),
            intent_verifier_chirho,
            terminal_verifier_chirho,
            conservation_provider_chirho,
        }
    }

    /// The held node's verification root, for paths that verify rather than sign.
    ///
    /// `Gd7ReconciliationVerifierPortChirho` is `Gd7ReconciliationSignerPortChirho`'s SUPERTRAIT
    /// (`contract_chirho.rs:29`), so the held signer already IS a verifier and coerces implicitly.
    /// Carrying a second field would give a caller two independently-settable roots for one node —
    /// a verifier that could disagree with the signer is a way to authenticate a cut against the
    /// wrong key. One field, one root, narrowed at the use site.
    pub(crate) fn held_verifier_chirho(&self) -> &dyn Gd7ReconciliationVerifierPortChirho {
        self.held_signer_chirho
    }

    pub(crate) fn converge_and_certify_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        checkpoint_ref_chirho: &str,
        binding_chirho: Gd7ConvergenceBindingInputChirho,
        unmeasured_chirho: Gd7ConvergenceUnmeasuredPredicatesChirho,
    ) -> Result<ConvergedReadReplicaChirho, Gd7PlanRefusalChirho> {
        let provider_chirho = self
            .conservation_provider_chirho
            .as_ref()
            .ok_or(Gd7PlanRefusalChirho::ConservationSnapshotUnavailableChirho)?;
        let effect_ports_chirho = Gd7EffectProofPortsChirho::new_chirho(
            &self.evidence_chirho,
            self.intent_verifier_chirho,
            self.terminal_verifier_chirho,
        );
        let proof_chirho = verify_sealed_gd7_reconciliation_plan_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            self.losing_record_verifier_chirho,
            &effect_ports_chirho,
            observation_chirho,
            checkpoint_ref_chirho,
        )?;
        let checkpoint_chirho = crate::reconciliation_chirho::load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            checkpoint_ref_chirho,
        )
        .map_err(Gd7PlanRefusalChirho::StoreChirho)?;
        let source_chirho = ProviderBackedGd7ConservationSourceChirho {
            provider_chirho: provider_chirho.as_ref(),
        };
        let verifier_chirho = ReconciliationBackedGd7ConservationVerifierChirho {
            verifier_chirho: self.held_signer_chirho,
        };
        let conservation_ports_chirho =
            Gd7ConservationProofPortsChirho::new_chirho(&source_chirho, &verifier_chirho);
        crate::reconciliation_chirho::verify_gd7_convergence_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            self.losing_record_verifier_chirho,
            &effect_ports_chirho,
            &conservation_ports_chirho,
            &checkpoint_chirho,
            &proof_chirho,
            binding_chirho,
            unmeasured_chirho,
        )
    }

    /// Production write-side of Shape A': re-verify a TRANSFERRED winner compensation record and
    /// persist the held-signed converged-import row, so a later `converge_and_certify_chirho`
    /// certifies the deposed compensated obligation instead of classifying it OPEN.
    ///
    /// The winner record line is a transferred object — this method re-verifies it with the held
    /// node's own authority (`self.losing_record_verifier_chirho` is the config-pinned journal
    /// verifier, the same trust root the winner fork witness uses) and never gains live
    /// winner-journal access. The obligation subject is derived from the held root's enumerated
    /// population, never from the transferred line. Returns the verified receipt digest.
    pub(crate) fn import_converged_compensation_receipt_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        checkpoint_ref_chirho: &str,
        winner_compensation_record_line_chirho: &str,
    ) -> Result<String, Gd7PlanRefusalChirho> {
        let effect_ports_chirho = Gd7EffectProofPortsChirho::new_chirho(
            &self.evidence_chirho,
            self.intent_verifier_chirho,
            self.terminal_verifier_chirho,
        );
        let proof_chirho = verify_sealed_gd7_reconciliation_plan_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            self.losing_record_verifier_chirho,
            &effect_ports_chirho,
            observation_chirho,
            checkpoint_ref_chirho,
        )?;
        let checkpoint_chirho = crate::reconciliation_chirho::load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            checkpoint_ref_chirho,
        )
        .map_err(Gd7PlanRefusalChirho::StoreChirho)?;
        crate::reconciliation_chirho::import_converged_compensation_receipt_over_population_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            self.losing_record_verifier_chirho,
            &effect_ports_chirho,
            &checkpoint_chirho,
            &proof_chirho,
            checkpoint_ref_chirho,
            winner_compensation_record_line_chirho,
        )
    }

    pub(crate) fn drive_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        expected_checkpoint_ref_chirho: &str,
    ) -> std::result::Result<Gd7PlanPageDriveOutcomeChirho, Gd7PlanRefusalChirho> {
        let effect_proof_ports_chirho = Gd7EffectProofPortsChirho::new_chirho(
            &self.evidence_chirho,
            self.intent_verifier_chirho,
            self.terminal_verifier_chirho,
        );
        drive_gd7_reconciliation_plan_page_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            &effect_proof_ports_chirho,
            observation_chirho,
            expected_checkpoint_ref_chirho,
        )
    }

    pub(crate) fn verify_sealed_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        expected_checkpoint_ref_chirho: &str,
    ) -> std::result::Result<VerifiedGd7SealedPlanProofChirho, Gd7PlanRefusalChirho> {
        let effect_proof_ports_chirho = Gd7EffectProofPortsChirho::new_chirho(
            &self.evidence_chirho,
            self.intent_verifier_chirho,
            self.terminal_verifier_chirho,
        );
        verify_sealed_gd7_reconciliation_plan_chirho(
            self.storage_chirho,
            self.held_signer_chirho,
            self.losing_record_verifier_chirho,
            &effect_proof_ports_chirho,
            observation_chirho,
            expected_checkpoint_ref_chirho,
        )
    }
}

struct ProviderBackedGd7ConservationSourceChirho<'provider_chirho> {
    provider_chirho: &'provider_chirho dyn Gd7ConservationSnapshotProviderChirho,
}

struct ReconciliationBackedGd7ConservationVerifierChirho<'verifier_chirho> {
    verifier_chirho: &'verifier_chirho dyn Gd7ReconciliationVerifierPortChirho,
}

impl Gd7ConservationSnapshotVerifierPortChirho
    for ReconciliationBackedGd7ConservationVerifierChirho<'_>
{
    fn key_id_chirho(&self) -> String {
        self.verifier_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verifier_chirho
            .verify_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl Gd7ConservationSnapshotSourcePortChirho for ProviderBackedGd7ConservationSourceChirho<'_> {
    fn load_signed_conservation_snapshot_chirho(
        &self,
    ) -> Result<
        crate::reconciliation_chirho::SignedGd7ConservationSnapshotChirho,
        Gd7PlanRefusalChirho,
    > {
        self.provider_chirho
            .load_signed_conservation_snapshot_chirho()
    }
}

pub struct ResidentEffectJournalHandleChirho {
    command_sender_chirho: Option<SyncSender<ResidentEffectJournalCommandChirho>>,
    actor_thread_chirho: Option<JoinHandle<()>>,
    selected_root_chirho: PathBuf,
    ledger_config_chirho: LedgerHostConfigChirho,
    head_transition_authority_chirho: ElectedHeadTransitionAdapterChirho,
}

impl ResidentEffectJournalHandleChirho {
    /// Effective verified ledger configuration selected by resident startup.
    ///
    /// After F1 adoption this differs from the static host file only in the journal path, which
    /// names the inert candidate whose signed canary generation committed last. Higher-level read
    /// and effect runtimes must use this exact value rather than reopening the stale source path.
    pub fn effective_ledger_config_chirho(&self) -> &LedgerHostConfigChirho {
        &self.ledger_config_chirho
    }

    /// Borrow the elected head-transition adapter backed by this actor's exact resident elector.
    ///
    /// The adapter owns only a restricted local-authority handle. The resident handle still owns
    /// the actor and elector lifetime, so dropping it ends both journal and head-transition use.
    pub fn head_transition_authority_chirho(&self) -> &ElectedHeadTransitionAdapterChirho {
        &self.head_transition_authority_chirho
    }

    /// Verify that a higher-level runtime is composing this actor with its exact root and config.
    ///
    /// This prevents an injected shared-elector actor for one ledger identity from being paired
    /// with another root's database, projection, billing kind, or signer coordinates.
    pub fn verify_runtime_binding_chirho(
        &self,
        selected_root_chirho: &Path,
        ledger_config_chirho: &LedgerHostConfigChirho,
    ) -> Result<()> {
        let canonical_root_chirho = selected_root_chirho
            .canonicalize()
            .context("canonicalize resident runtime binding root")?;
        if canonical_root_chirho != self.selected_root_chirho {
            bail!("resident effect-journal actor is bound to another root");
        }
        if ledger_config_chirho != &self.ledger_config_chirho {
            bail!("resident effect-journal actor is bound to another ledger config");
        }
        Ok(())
    }

    /// Derive a restricted winner-evidence view of this exact resident actor.
    ///
    /// The returned handle owns no actor or election state. Dropping this full handle still shuts
    /// down the sole actor, after which every derived evidence handle fails closed.
    pub fn gd7_winner_evidence_handle_chirho(
        &self,
    ) -> Result<ResidentGd7WinnerEvidenceHandleChirho> {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or_else(|| anyhow!("resident effect-journal actor is already closed"))?
            .clone();
        Ok(ResidentGd7WinnerEvidenceHandleChirho {
            command_sender_chirho,
        })
    }

    /// Derive the bounded winner-handoff control surface of this exact resident actor.
    pub fn gd7_winner_handoff_handle_chirho(&self) -> Result<ResidentGd7WinnerHandoffHandleChirho> {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or_else(|| anyhow!("resident effect-journal actor is already closed"))?
            .clone();
        Ok(ResidentGd7WinnerHandoffHandleChirho {
            command_sender_chirho,
        })
    }

    /// Derive the accepted-barrier-bound adoption-input evidence surface.
    pub fn gd7_winner_adoption_evidence_handle_chirho(
        &self,
    ) -> Result<ResidentGd7WinnerAdoptionEvidenceHandleChirho> {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or_else(|| anyhow!("resident effect-journal actor is already closed"))?
            .clone();
        Ok(ResidentGd7WinnerAdoptionEvidenceHandleChirho {
            command_sender_chirho,
        })
    }

    fn request_chirho<OutputChirho>(
        &self,
        command_chirho: impl FnOnce(
            SyncSender<ResidentEffectJournalResultChirho<OutputChirho>>,
        ) -> ResidentEffectJournalCommandChirho,
    ) -> ResidentEffectJournalResultChirho<OutputChirho> {
        let sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or_else(|| unavailable_chirho("resident effect-journal actor is already closed"))?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        match sender_chirho.try_send(command_chirho(reply_sender_chirho)) {
            Ok(()) => {}
            Err(TrySendError::Full(_command_chirho)) => {
                return Err(unavailable_chirho(
                    "resident effect-journal mailbox is at its fixed capacity",
                ));
            }
            Err(TrySendError::Disconnected(_command_chirho)) => {
                return Err(unavailable_chirho(
                    "resident effect-journal actor is unavailable",
                ));
            }
        }
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            unavailable_chirho("resident effect-journal actor stopped before replying")
        })?
    }

    /// Reduce at most one already-manifested GD7 page inside the resident authority actor.
    ///
    /// The opaque observation was authenticated before it crossed this boundary. This command
    /// cannot observe a fork, authorize compensation, adopt a winner view, or re-enable writes.
    pub fn drive_authenticated_gd7_plan_page_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        expected_checkpoint_ref_chirho: &str,
    ) -> Result<Gd7PlanPageDriveOutcomeChirho> {
        let sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or_else(|| anyhow!("resident effect-journal actor is already closed"))?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        let command_chirho = ResidentEffectJournalCommandChirho::DriveGd7PlanPageChirho {
            observation_chirho: Box::new(observation_chirho.clone()),
            expected_checkpoint_ref_chirho: expected_checkpoint_ref_chirho.to_owned(),
            reply_chirho: reply_sender_chirho,
        };
        match sender_chirho.try_send(command_chirho) {
            Ok(()) => {}
            Err(TrySendError::Full(_command_chirho)) => {
                bail!("resident effect-journal mailbox is at its fixed capacity");
            }
            Err(TrySendError::Disconnected(_command_chirho)) => {
                bail!("resident effect-journal actor is unavailable");
            }
        }
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                anyhow!("resident effect-journal actor stopped before replying")
            })?
            .map_err(anyhow::Error::new)
    }

    /// Reverify one exact sealed GD7 plan inside the resident authority actor.
    ///
    /// This reads the complete linked plan once with O(page) memory and returns only an opaque
    /// proof. It cannot authorize compensation, move a ref, adopt a winner view, or re-enable
    /// writes.
    pub fn verify_authenticated_gd7_sealed_plan_chirho(
        &self,
        observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
        expected_checkpoint_ref_chirho: &str,
    ) -> Result<VerifiedGd7SealedPlanProofChirho> {
        let sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or_else(|| anyhow!("resident effect-journal actor is already closed"))?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        let command_chirho = ResidentEffectJournalCommandChirho::VerifyGd7SealedPlanChirho {
            observation_chirho: Box::new(observation_chirho.clone()),
            expected_checkpoint_ref_chirho: expected_checkpoint_ref_chirho.to_owned(),
            reply_chirho: reply_sender_chirho,
        };
        match sender_chirho.try_send(command_chirho) {
            Ok(()) => {}
            Err(TrySendError::Full(_command_chirho)) => {
                bail!("resident effect-journal mailbox is at its fixed capacity");
            }
            Err(TrySendError::Disconnected(_command_chirho)) => {
                bail!("resident effect-journal actor is unavailable");
            }
        }
        reply_receiver_chirho
            .recv()
            .map_err(|_error_chirho| {
                anyhow!("resident effect-journal actor stopped before replying")
            })?
            .map_err(anyhow::Error::new)
    }
}

impl Drop for ResidentEffectJournalHandleChirho {
    fn drop(&mut self) {
        shutdown_resident_effect_journal_actor_chirho(
            self.command_sender_chirho.take(),
            self.actor_thread_chirho.take(),
        );
    }
}

fn shutdown_resident_effect_journal_actor_chirho(
    command_sender_chirho: Option<SyncSender<ResidentEffectJournalCommandChirho>>,
    actor_thread_chirho: Option<JoinHandle<()>>,
) {
    if let Some(sender_chirho) = command_sender_chirho {
        let _shutdown_result_chirho =
            sender_chirho.send(ResidentEffectJournalCommandChirho::ShutdownChirho);
        drop(sender_chirho);
    }
    if let Some(actor_thread_chirho) = actor_thread_chirho {
        let _join_result_chirho = actor_thread_chirho.join();
    }
}

impl ResidentEffectJournalHandleChirho {
    #[allow(
        dead_code,
        reason = "the typed provider handle is the actor-owned composition seam exercised by R4 adapters"
    )]
    pub(crate) fn execute_gd7_compensation_provider_chirho(
        &self,
        canonical_obligation_digest_chirho: &str,
        action_idempotency_key_chirho: &str,
        bounded_payload_chirho: &[u8],
    ) -> Result<Gd7CompensationProviderObservationChirho, Gd7CompensationProviderRefusalChirho>
    {
        let sender_chirho = self.command_sender_chirho.as_ref().ok_or_else(|| {
            Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                detail_chirho: "resident effect-journal actor is already closed".to_owned(),
            }
        })?;
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::ExecuteGd7CompensationProviderChirho {
                    canonical_obligation_digest_chirho: canonical_obligation_digest_chirho
                        .to_owned(),
                    action_idempotency_key_chirho: action_idempotency_key_chirho.to_owned(),
                    bounded_payload_chirho: bounded_payload_chirho.to_vec(),
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(
                |error_chirho| Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            Gd7CompensationProviderRefusalChirho::UnavailableChirho {
                detail_chirho: "resident effect-journal actor stopped before provider reply"
                    .to_owned(),
            }
        })?
    }
}

impl EffectCommitJournalPortChirho for ResidentEffectJournalHandleChirho {
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho> {
        self.request_chirho(
            |reply_chirho| ResidentEffectJournalCommandChirho::AppendHoldChirho {
                canonical_intent_line_chirho: canonical_intent_line_chirho.to_owned(),
                reply_chirho,
            },
        )
    }

    fn append_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho> {
        self.request_chirho(|reply_chirho| {
            ResidentEffectJournalCommandChirho::AppendCompensationHoldChirho {
                canonical_intent_line_chirho: canonical_intent_line_chirho.to_owned(),
                authorization_chirho: authorization_chirho.clone(),
                reply_chirho,
            }
        })
    }

    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> ResidentEffectJournalResultChirho<EffectCommitJournalReceiptChirho> {
        self.request_chirho(|reply_chirho| {
            ResidentEffectJournalCommandChirho::AppendTerminalChirho {
                canonical_intent_line_chirho: canonical_intent_line_chirho.to_owned(),
                canonical_terminal_line_chirho: canonical_terminal_line_chirho.to_owned(),
                reply_chirho,
            }
        })
    }

    fn active_hold_intent_refs_chirho(
        &self,
    ) -> ResidentEffectJournalResultChirho<Vec<DigestChirho>> {
        self.request_chirho(|reply_chirho| {
            ResidentEffectJournalCommandChirho::ActiveHoldIntentRefsChirho { reply_chirho }
        })
    }

    fn receipt_by_intent_ref_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> ResidentEffectJournalResultChirho<Option<EffectIntentJournalStateChirho>> {
        self.request_chirho(|reply_chirho| {
            ResidentEffectJournalCommandChirho::ReceiptByIntentRefChirho {
                intent_ref_chirho: intent_ref_chirho.clone(),
                reply_chirho,
            }
        })
    }
}

impl EffectCommitJournalViewPortChirho for ResidentEffectJournalHandleChirho {
    fn effect_intent_cut_chirho(
        &self,
    ) -> ResidentEffectJournalResultChirho<EffectIntentJournalCutChirho> {
        self.request_chirho(|reply_chirho| {
            ResidentEffectJournalCommandChirho::EffectIntentCutChirho { reply_chirho }
        })
    }

    fn current_continuation_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> ResidentEffectJournalResultChirho<Option<EffectCommitContinuationViewChirho>> {
        self.request_chirho(|reply_chirho| {
            ResidentEffectJournalCommandChirho::CurrentContinuationChirho {
                kind_id_chirho: kind_id_chirho.clone(),
                reply_chirho,
            }
        })
    }

    fn verified_effect_receipt_inventory_chirho(
        &self,
    ) -> ResidentEffectJournalResultChirho<Vec<VerifiedEffectReceiptInventoryEntryChirho>> {
        self.request_chirho(|reply_chirho| {
            ResidentEffectJournalCommandChirho::VerifiedReceiptInventoryChirho { reply_chirho }
        })
    }
}

/// Reopen the exact H3 authority and run it behind one resident actor. This compatibility surface
/// owns a durable single-voter self-election: it provides process-local restart authority, not a
/// multi-voter quorum or A6 geo authority. Geo serving must use
/// [`open_resident_effect_journal_handle_with_shared_elector_chirho`] instead. This creates no
/// ledger, canary, key, registry, or identity artifact; every authority-bearing component must
/// already exist.
pub fn open_resident_effect_journal_handle_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
) -> Result<ResidentEffectJournalHandleChirho> {
    // PRODUCTION DOOR — the test-kind fence lives on the two provider-LESS openers and on neither
    // compensation-provider door, because that pair is already the codebase's production/test-kind
    // fork. See `crate::test_kind_fence_chirho` for why this is defence in depth over custody rather
    // than the guarantee itself.
    refuse_test_kind_marked_host_config_chirho(config_chirho)?;
    open_resident_effect_journal_handle_with_election_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        ResidentElectionCompositionChirho::ReopenOwnedSingleNodeChirho,
        ResidentActorServiceCompositionChirho::with_refusing_compensation_chirho(
            None,
            conservation_provider_chirho,
            None,
        ),
        ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
    )
}

/// The DEV-ONLY test-kind TWIN of [`open_resident_effect_journal_handle_chirho`]: reopen the exact H3
/// authority behind one resident actor on a SYNTHETIC test-kind root (a1's dev-bootstrap root and the
/// drill roots), which the production single-node door refuses by design.
///
/// It is byte-for-byte the production door above — the SAME `ReopenOwnedSingleNodeChirho` durable
/// single-voter self-election, the SAME REFUSING compensation composition (ZERO compensation
/// capability: absence of a provider IS the refusing posture, so this door can complete nothing), and
/// the SAME downstream `config.validate_chirho()` + `verify_host_ledger_config_custody_chirho` inside
/// [`open_resident_effect_journal_handle_with_election_chirho`] — differing ONLY in the fence
/// DIRECTION. Where the production door calls `refuse_test_kind_marked_host_config_chirho`, this door
/// calls `require_test_kind_marked_host_config_chirho`: it opens a marked test-kind root and fails
/// closed on a production (unmarked) one. It yields the SAME fenced `ResidentEffectJournalHandleChirho`
/// the production door yields and relaxes NOTHING — not the elected-writer fence, not the lease, not
/// the mailbox serialization. This is NOT a compensation door.
///
/// "Dev-only" is a statement about who may CALL it, never about what it CAN DO: the source guard
/// `open_resident_effect_journal_handle_testkind_door_has_no_shipping_binary_caller_chirho` confines
/// the lawful callers to the definition site plus the dev-only `cairn-ledger-geo-node-testkind-chirho`
/// crate, which no production build links.
pub fn open_resident_effect_journal_handle_testkind_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
) -> Result<ResidentEffectJournalHandleChirho> {
    // DEV-ONLY TEST-KIND DOOR — the exact inverse of the production door's fence. `require_` fails
    // closed on a production (unmarked) config; everything below is IDENTICAL to the production door,
    // so nothing it checks (custody, validation, election posture, refusing compensation) is relaxed.
    require_test_kind_marked_host_config_chirho(config_chirho)?;
    open_resident_effect_journal_handle_with_election_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        ResidentElectionCompositionChirho::ReopenOwnedSingleNodeChirho,
        ResidentActorServiceCompositionChirho::with_refusing_compensation_chirho(
            None,
            conservation_provider_chirho,
            None,
        ),
        // ONLY this dev door permits the CF8 loss-witness exemption; the actor still consistency-checks
        // the single-node + no-compensation shape before honoring an exempt marker.
        ResidentTestkindLossWitnessOpenerModeChirho::NormalSettlementExemptionPermittedChirho,
    )
}

/// Reopen the exact H3 authority around an already-running production cluster elector.
///
/// The caller retains the elector and its sole clock driver. This actor never campaigns or ticks it;
/// every local append and winner-view proof instead acquires the generation published by that exact
/// shared instance. The elector must already report this node as the warm, promotable local leader.
pub fn open_resident_effect_journal_handle_with_shared_elector_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    elector_chirho: &Arc<RaftWriterElectorChirho>,
    mirror_runtime_chirho: Option<LedgerMirrorRuntimePortsChirho>,
    conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
) -> Result<ResidentEffectJournalHandleChirho> {
    // PRODUCTION DOOR — see the sibling opener above. This is the one the shipping geo voter reaches
    // through `default_resident_opener_chirho`; the test-kind binary injects an opener that goes to
    // the compensation-provider door instead, which is exactly why the fence sits here and not at
    // the shared config-parse or issuer-pin conversion both binaries pass through.
    refuse_test_kind_marked_host_config_chirho(config_chirho)?;
    open_resident_effect_journal_handle_with_election_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        ResidentElectionCompositionChirho::UseSharedClusterElectorChirho(Arc::downgrade(
            elector_chirho,
        )),
        ResidentActorServiceCompositionChirho::with_refusing_compensation_chirho(
            mirror_runtime_chirho,
            conservation_provider_chirho,
            None,
        ),
        ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
    )
}

/// Production geo-voter door for a resident actor whose tenant migrations are capacity/load gated.
///
/// The ordinary shared-elector opener remains available for roots that never expose migration
/// commands. A migration command on such an actor refuses by named absence; only this door installs
/// the signed-evidence admission composition that can produce a v2 durable operation identity.
pub fn open_resident_effect_journal_handle_with_shared_elector_and_capacity_admission_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    elector_chirho: &Arc<RaftWriterElectorChirho>,
    mirror_runtime_chirho: Option<LedgerMirrorRuntimePortsChirho>,
    conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
    capacity_admission_chirho: TenantMigrationCapacityAdmissionCompositionChirho,
) -> Result<ResidentEffectJournalHandleChirho> {
    refuse_test_kind_marked_host_config_chirho(config_chirho)?;
    open_resident_effect_journal_handle_with_election_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        ResidentElectionCompositionChirho::UseSharedClusterElectorChirho(Arc::downgrade(
            elector_chirho,
        )),
        ResidentActorServiceCompositionChirho::with_refusing_compensation_chirho(
            mirror_runtime_chirho,
            conservation_provider_chirho,
            Some(capacity_admission_chirho),
        ),
        ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
    )
}

/// Reopen the exact H3 authority with a caller-supplied GD7 compensation provider adapter.
///
/// THE CAPSTONE'S ONE DOOR. Identical to [`open_resident_effect_journal_handle_chirho`] in every
/// custody check and election posture (durable single-voter self-election); the only difference is
/// that the actor's compensation composition consults the supplied provider instead of the
/// refusing default. Absence remains the refusing posture: every other opener passes `None`, so a
/// composition that does not explicitly hand a provider through THIS door still completes nothing.
/// The provider REPORTS settlement — cairn records the claim against a persisted,
/// idempotency-keyed intent and never verifies the external side. A provider that moves real money
/// is a separate, operator-configured, hard-gated decision that no code in this crate takes.
///
/// The single-voter shape is measured, not preferred: this door owns a durable self-election, so it
/// serves a root that carries its own authority. AFTER the GD7 resume step (ruled (a) 2026-08-05) a
/// handoff-frozen WINNER can also open — startup is handoff-aware and no longer refuses at open —
/// but the winner's compensation belongs behind
/// [`open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho`],
/// which keeps the winner on the exact shared elector that holds its accepted handoff marker.
/// (Superseded claim, recorded because it travelled: this comment previously said opening the winner
/// actor "refuses at startup with 'resident ledger mutation is frozen by an active GD7 winner
/// handoff'". Startup no longer refuses; the append seam still does, for every mutation but the one
/// exempt compensation lane.)
pub fn open_resident_effect_journal_handle_with_gd7_compensation_provider_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    conservation_provider_chirho: Option<Gd7ConservationSnapshotProviderRefChirho>,
    gd7_compensation_provider_chirho: Box<dyn Gd7CompensationProviderAdapterChirho + Send>,
) -> Result<ResidentEffectJournalHandleChirho> {
    open_resident_effect_journal_handle_with_election_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        ResidentElectionCompositionChirho::ReopenOwnedSingleNodeChirho,
        ResidentActorServiceCompositionChirho::with_gd7_compensation_provider_chirho(
            None,
            conservation_provider_chirho,
            None,
            gd7_compensation_provider_chirho,
        ),
        ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
    )
}

/// THE WINNER-SIDE CAPSTONE DOOR: a shared cluster elector AND a compensation provider.
///
/// Ruled (a) puts the compensation append on the LIVE WINNER's journal under the winner's own term,
/// and the winner's freeze lives in the elector's in-memory marker — so the winner's actor must be
/// composed on the EXACT shared elector instance that carries that marker, not a fresh self-election
/// that would know nothing about the handoff. That is the whole reason this door exists beside the
/// two it combines; it adds no authority that either one lacks.
///
/// Both fail-closed defaults are unchanged. Absence of a provider is still the refusing posture at
/// every other opener, and the shared elector must already report this node as the warm, promotable
/// local leader. A provider that moves real money remains a separate, operator-configured, hard-gated
/// decision that no code in this crate takes.
pub fn open_resident_effect_journal_handle_with_shared_elector_and_gd7_compensation_provider_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    elector_chirho: &Arc<RaftWriterElectorChirho>,
    services_chirho: ResidentActorServiceCompositionChirho,
) -> Result<ResidentEffectJournalHandleChirho> {
    open_resident_effect_journal_handle_with_election_chirho(
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        ResidentElectionCompositionChirho::UseSharedClusterElectorChirho(Arc::downgrade(
            elector_chirho,
        )),
        services_chirho,
        ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
    )
}

fn open_resident_effect_journal_handle_with_election_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    election_composition_chirho: ResidentElectionCompositionChirho,
    services_chirho: ResidentActorServiceCompositionChirho,
    opener_mode_chirho: ResidentTestkindLossWitnessOpenerModeChirho,
) -> Result<ResidentEffectJournalHandleChirho> {
    config_chirho.validate_chirho()?;
    verify_host_ledger_config_custody_chirho(selected_root_chirho, config_path_chirho)?;
    let bound_root_chirho = selected_root_chirho
        .canonicalize()
        .context("canonicalize resident actor binding root")?;
    let selected_root_chirho = selected_root_chirho.to_path_buf();
    let config_path_chirho = config_path_chirho.to_path_buf();
    let config_chirho = config_chirho.clone();
    let (command_sender_chirho, command_receiver_chirho) =
        sync_channel(RESIDENT_EFFECT_JOURNAL_MAILBOX_CAPACITY_CHIRHO);
    let (startup_sender_chirho, startup_receiver_chirho) =
        sync_channel::<std::result::Result<ResidentActorStartupChirho, String>>(1);
    let actor_thread_chirho = std::thread::Builder::new()
        .name("resident-effect-journal-chirho".to_owned())
        .spawn(move || {
            let result_chirho = run_resident_effect_journal_actor_chirho(
                ResidentActorStartupCompositionChirho {
                    selected_root_chirho,
                    config_path_chirho,
                    config_chirho,
                    election_composition_chirho,
                    services_chirho,
                    opener_mode_chirho,
                },
                command_receiver_chirho,
                &startup_sender_chirho,
            );
            if let Err(error_chirho) = result_chirho {
                let _startup_result_chirho =
                    startup_sender_chirho.try_send(Err(error_chirho.to_string()));
            }
        })
        .context("spawn resident effect-journal actor")?;
    match startup_receiver_chirho.recv() {
        Ok(Ok(startup_chirho)) => {
            let head_transition_authority_chirho =
                match ElectedHeadTransitionAdapterChirho::new_chirho(
                    &bound_root_chirho,
                    startup_chirho.local_append_authority_chirho,
                ) {
                    Ok(authority_chirho) => authority_chirho,
                    Err(error_chirho) => {
                        drop(command_sender_chirho);
                        let _join_result_chirho = actor_thread_chirho.join();
                        return Err(error_chirho)
                            .context("bind resident elected head-transition adapter");
                    }
                };
            Ok(ResidentEffectJournalHandleChirho {
                command_sender_chirho: Some(command_sender_chirho),
                actor_thread_chirho: Some(actor_thread_chirho),
                selected_root_chirho: bound_root_chirho,
                ledger_config_chirho: startup_chirho.ledger_config_chirho,
                head_transition_authority_chirho,
            })
        }
        Ok(Err(detail_chirho)) => {
            drop(command_sender_chirho);
            let _join_result_chirho = actor_thread_chirho.join();
            bail!("resident effect-journal actor refused startup: {detail_chirho}");
        }
        Err(_error_chirho) => {
            drop(command_sender_chirho);
            let _join_result_chirho = actor_thread_chirho.join();
            bail!("resident effect-journal actor stopped during startup");
        }
    }
}

/// The full resident actor-startup composition an opener door assembles: the root/config
/// coordinates, the election posture, the optional service providers, and the opener-selected
/// loss-witness mode. Grouping them lets the private runner take one composition value plus its
/// mailbox/startup channels without tripping the argument-count lint, while each door still selects
/// its own `opener_mode_chirho` (only the A+ door NormalSettlementExemptionPermitted; every other
/// door MandatoryWitnessOrProduction).
struct ResidentActorStartupCompositionChirho {
    selected_root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    config_chirho: LedgerHostConfigChirho,
    election_composition_chirho: ResidentElectionCompositionChirho,
    services_chirho: ResidentActorServiceCompositionChirho,
    opener_mode_chirho: ResidentTestkindLossWitnessOpenerModeChirho,
}

fn run_resident_effect_journal_actor_chirho(
    startup_composition_chirho: ResidentActorStartupCompositionChirho,
    command_receiver_chirho: Receiver<ResidentEffectJournalCommandChirho>,
    startup_sender_chirho: &SyncSender<std::result::Result<ResidentActorStartupChirho, String>>,
) -> Result<()> {
    let ResidentActorStartupCompositionChirho {
        selected_root_chirho,
        config_path_chirho,
        config_chirho,
        election_composition_chirho,
        services_chirho,
        opener_mode_chirho,
    } = startup_composition_chirho;
    let ResidentActorServiceCompositionChirho {
        mirror_runtime_chirho,
        conservation_provider_chirho,
        capacity_admission_chirho,
        gd7_compensation_provider_chirho,
    } = services_chirho;
    config_chirho.validate_chirho()?;
    verify_host_ledger_config_custody_chirho(&selected_root_chirho, &config_path_chirho)?;
    let canonical_root_chirho = selected_root_chirho.canonicalize()?;
    let storage_namespace_chirho =
        canonical_root_chirho.join(&config_chirho.storage_namespace_chirho);
    let monitor_namespace_chirho =
        canonical_root_chirho.join(&config_chirho.monitor_evidence_namespace_chirho);
    let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_namespace_chirho)?;
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho)?;
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&canonical_root_chirho, &signer_refs_chirho)?;
    let issuer_verifier_chirho =
        PinnedKindIssuerVerifierChirho::from_config_chirho(&config_chirho.kind_issuer_chirho)?;
    let registry_ports_chirho = KindRegistryPortsChirho {
        storage_chirho: &storage_chirho,
        registry_root_chirho: &signers_chirho.kind_root_chirho,
        issuer_verify_chirho: &issuer_verifier_chirho,
    };
    let kind_registry_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &StoragePathChirho::new_chirho(&config_chirho.kind_registry_path_chirho),
        &config_chirho.kind_registry_id_chirho,
    )
    .map_err(|error_chirho| anyhow!("resident kind registry refused: {error_chirho:?}"))?;
    // The CF8 loss-witness exemption is confined by WHO opened the actor (`opener_mode_chirho`,
    // threaded from the door), with the single-node + no-compensation shape as consistency
    // defense-in-depth. These two bools capture that shape from THIS actor's composition.
    let election_reopen_owned_single_node_chirho = matches!(
        election_composition_chirho,
        ResidentElectionCompositionChirho::ReopenOwnedSingleNodeChirho
    );
    let compensation_provider_present_chirho = gd7_compensation_provider_chirho.is_some();
    let testkind_loss_witness_plan_chirho = derive_resident_testkind_loss_witness_plan_chirho(
        &config_chirho,
        &kind_registry_chirho,
        opener_mode_chirho,
        election_reopen_owned_single_node_chirho,
        compensation_provider_present_chirho,
    )
    .map_err(|refusal_chirho| {
        anyhow!("resident test-kind loss witness plan refused: {refusal_chirho}")
    })?;
    let money_authority_chirho =
        PlatformPolicyMintAuthorityChirho::new_chirho(&kind_registry_chirho);
    let static_membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
        config_chirho.local_epoch_chirho,
        &config_chirho.members_chirho,
    )?;
    let elected_membership_chirho = static_membership_chirho.elected_view_chirho();
    let clock_chirho = ResidentLedgerClockChirho::system_chirho();
    let cluster_chirho = ClusterIdChirho(config_chirho.cluster_id_chirho.clone());
    let node_chirho = NodeIdChirho(existing_keypair_pubkey_hex_chirho(&canonical_root_chirho)?);
    let group_chirho = consistency_group_for_root_chirho(&canonical_root_chirho)?;
    let gd7_authority_storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&canonical_root_chirho)?;
    let gd7_control_signer_chirho =
        ExistingNodeGd7SignerChirho::open_existing_chirho(&canonical_root_chirho, &node_chirho)?;
    // Bind both migration authorities before the resident journal opens. A target-root adoption
    // warrant is consumed during that open, while source-side migration operations borrow the same
    // exact verifiers later in the actor lifetime.
    let tenant_migration_destination_authority_chirho = match &config_chirho
        .migration_destination_authority_chirho
    {
        Some(configured_chirho) => {
            if configured_chirho.verifying_key_hex_chirho == node_chirho.0 {
                bail!(
                    "tenant migration destination authority must not be this node's own key: a node that authorizes its own destination is not authorized at all"
                );
            }
            Some(PinnedTenantMigrationDestinationAuthorityChirho::new_chirho(
                configured_chirho.key_id_chirho.clone(),
                configured_chirho.verifying_key_hex_chirho.clone(),
            )?)
        }
        None => None,
    };
    let tenant_migration_activation_verifier_chirho = config_chirho
        .activation_authority_chirho
        .as_ref()
        .map(PinnedLedgerActivationVerifierChirho::from_config_chirho)
        .transpose()?;
    let gd7_winner_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &gd7_authority_storage_chirho,
        &gd7_control_signer_chirho,
        &signers_chirho.journal_chirho,
    );
    let gd7_winner_handoff_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &gd7_authority_storage_chirho,
        &gd7_control_signer_chirho,
        consistency_group_digest_chirho(&group_chirho)?,
        node_chirho.0.clone(),
    )
    .map_err(|error_chirho| anyhow!("open GD7 winner handoff store: {error_chirho}"))?;
    let tenant_migration_store_chirho = match &group_chirho {
        ConsistencyGroupIdChirho::TenantChirho { .. } => Some(
            TenantMigrationStoreChirho::new_chirho(
                &gd7_authority_storage_chirho,
                &gd7_control_signer_chirho,
                consistency_group_digest_chirho(&group_chirho)?,
                node_chirho.0.clone(),
            )
            .map_err(|error_chirho| anyhow!("open tenant migration store: {error_chirho}"))?,
        ),
        ConsistencyGroupIdChirho::RootPathChirho { .. } => None,
    };
    let gd7_plan_ports_chirho = ResidentGd7PlanPortsChirho::new_chirho(
        &gd7_authority_storage_chirho,
        &canonical_root_chirho,
        &gd7_control_signer_chirho,
        &signers_chirho.journal_chirho,
        &signers_chirho.effect_intent_chirho,
        &signers_chirho.effect_terminal_chirho,
        conservation_provider_chirho,
    );
    // Fail-closed default: absence IS the refusing posture. Only the one opener that accepts a
    // provider can replace this, so a composition that says nothing completes nothing.
    let gd7_compensation_provider_chirho: Box<dyn Gd7CompensationProviderAdapterChirho + Send> =
        gd7_compensation_provider_chirho
            .unwrap_or_else(|| Box::new(RefusingGd7CompensationProviderChirho));
    let (
        owned_elector_chirho,
        elector_weak_chirho,
        local_authority_chirho,
        actor_owns_election_clock_chirho,
    ) = match election_composition_chirho {
        ResidentElectionCompositionChirho::ReopenOwnedSingleNodeChirho => {
            let elector_chirho = RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
                monitor_namespace_chirho.join(RESIDENT_EFFECT_JOURNAL_ELECTION_DIR_CHIRHO),
                node_chirho.clone(),
                group_chirho.clone(),
            )?
            .with_message_authentication_chirho(canonical_root_chirho.clone())
            .with_leadership_warmup_lease_chirho();
            let _campaign_messages_chirho = elector_chirho.campaign_chirho()?;
            for _warmup_tick_chirho in 0..RESIDENT_EFFECT_JOURNAL_WARMUP_TICKS_CHIRHO {
                let _outbound_messages_chirho = elector_chirho.tick_chirho();
            }
            let elector_chirho = Arc::new(elector_chirho);
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            (
                Some(Arc::clone(&elector_chirho)),
                Arc::downgrade(&elector_chirho),
                local_authority_chirho,
                true,
            )
        }
        ResidentElectionCompositionChirho::UseSharedClusterElectorChirho(elector_weak_chirho) => {
            let elector_chirho = elector_weak_chirho
                .upgrade()
                .ok_or_else(|| anyhow!("shared cluster elector is unavailable"))?;
            let local_authority_chirho = elector_chirho.local_append_authority_handle_chirho();
            if local_authority_chirho.consistency_group_chirho() != &group_chirho {
                bail!("shared cluster elector names a different consistency group");
            }
            if local_authority_chirho.node_id_chirho() != &node_chirho {
                bail!("shared cluster elector names a different local node");
            }
            (None, elector_weak_chirho, local_authority_chirho, false)
        }
    };
    let handoff_local_authority_chirho = local_authority_chirho.clone();
    let handoff_control_chirho = handoff_local_authority_chirho.handoff_control_handle_chirho();
    let journal_ports_chirho = JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signers_chirho.journal_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &elected_membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &money_authority_chirho,
    };
    let recovery_outcome_chirho =
        prepare_resident_recovery_adoption_chirho(ResidentRecoveryAdoptionInputChirho {
            storage_chirho: &storage_chirho,
            authority_storage_chirho: &gd7_authority_storage_chirho,
            journal_ports_chirho,
            config_chirho: &config_chirho,
            monitor_namespace_chirho: &monitor_namespace_chirho,
            sign_root_chirho: &canonical_root_chirho,
            cluster_chirho: &cluster_chirho,
            group_chirho: &group_chirho,
            node_chirho: &node_chirho,
            mirror_runtime_chirho: mirror_runtime_chirho.as_ref(),
            gd7_store_chirho: &gd7_winner_handoff_store_chirho,
            migration_store_chirho: tenant_migration_store_chirho.as_ref(),
            handoff_control_chirho: &handoff_control_chirho,
            local_authority_chirho: &handoff_local_authority_chirho,
            // The same pause startup bracketing uses between contended attempts.
            contention_pause_chirho: &|| {
                std::thread::sleep(super::RESIDENT_GENERATION_CONTENTION_PAUSE_CHIRHO)
            },
        })?;
    let journal_path_chirho = recovery_outcome_chirho.journal_path_chirho;
    let canary_store_chirho = recovery_outcome_chirho.canary_store_chirho;
    let current_canary_chirho = recovery_outcome_chirho.current_canary_chirho;
    // THE WRITE PATH MAY ALREADY BE DEAD HERE, and this is the only place that can say so.
    //
    // If seeding the remote write population refused, this node serves reads normally while every
    // mutation will refuse at a holder, three components away, with a refusal naming the holder's
    // continuity rather than this cause. Staying readable is DELIBERATE -- surviving-region read
    // availability is a Clause 14 requirement, and exiting instead would trade a documented
    // degradation for a flapping node. What was not deliberate is that the degradation was
    // unobservable: this outcome was previously destructured away one frame after being computed,
    // so the state existed and nothing could consult it.
    //
    // This announces it once, at the moment it becomes true, with a fixed identity. It deliberately
    // does NOT refuse: refusing here would take reads down for a write-path fault.
    match recovery_outcome_chirho.current_holder_write_readiness_chirho {
        ResidentCurrentHolderWriteReadinessChirho::RefusedChirho => {
            eprintln!(
                "ResidentServedWithDeadWritePathChirho:reads=available:writes=refused-at-holder"
            );
        }
        // NotAttempted is NOT success -- it means this path never reached the bootstrap. It is left
        // silent because it is the ordinary posture for a node with no mirror runtime and for the
        // candidate path, and announcing it would make the refused case harder to see.
        ResidentCurrentHolderWriteReadinessChirho::NotAttemptedChirho
        | ResidentCurrentHolderWriteReadinessChirho::BootstrappedChirho => {}
    }
    // A HOLDER THAT COULD NOT BE SEEDED AT STARTUP MUST BE SEEDED LATER.
    //
    // Seeding is otherwise startup-only, and startup is the one moment it cannot work for the case
    // that matters: a node adopting after a leader loss seeds while the holder it must seed -- the
    // former leader -- is still unreachable. Measured across two hosted windows, the returning holder
    // then carries no anchor for the entire sequence and every later prepare refuses.
    //
    // The trigger is this node's OWN startup observation, never anything a holder can influence. Only
    // `BootstrappedChirho` means the holders were actually seeded; both other outcomes leave work to
    // do, and `NotAttemptedChirho` with no mirror runtime has nothing to seed WITH, so it is excluded.
    let mut holder_reseed_pending_chirho = mirror_runtime_chirho.is_some()
        && !matches!(
            recovery_outcome_chirho.current_holder_write_readiness_chirho,
            ResidentCurrentHolderWriteReadinessChirho::BootstrappedChirho
        );
    let mut ticks_since_reseed_attempt_chirho = 0_u32;
    let mut effective_config_chirho = config_chirho.clone();
    effective_config_chirho.journal_path_chirho = journal_path_chirho.key_chirho().to_owned();
    let tenant_migration_journal_path_chirho = journal_path_chirho.clone();
    let tenant_migration_cluster_chirho = cluster_chirho.clone();
    let resident_ports_chirho = ResidentLedgerLocalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &signers_chirho.journal_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &elected_membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &money_authority_chirho,
    };
    // The config bit expresses local intent only. The authority to mint a resident-writer identity
    // comes from the destination-authority selection record, activation-authority co-signature,
    // source-node witness, and the target-local one-use consumption record verified here.
    if config_chirho.adopt_migrated_root_chirho {
        consume_writer_adoption_warrant_chirho(
            &canonical_root_chirho,
            storage_chirho.namespace_root_chirho(),
            &journal_path_chirho,
            &cluster_chirho,
            config_chirho.local_epoch_chirho,
            resident_ports_chirho,
            local_authority_chirho.clone(),
            tenant_migration_activation_verifier_chirho.as_ref(),
            tenant_migration_destination_authority_chirho
                .as_ref()
                .map(|authority_chirho| {
                    authority_chirho as &dyn TenantMigrationDestinationAuthorityPortChirho
                }),
        )
        .map_err(|refusal_chirho| {
            anyhow!("tenant migration writer adoption refused: {refusal_chirho:?}")
        })?;
    }
    let mut resident_chirho = ResidentLedgerAuthorityChirho::open_bound_serving_chirho(
        &canonical_root_chirho,
        resident_ports_chirho,
        journal_path_chirho,
        cluster_chirho,
        config_chirho.local_epoch_chirho,
        local_authority_chirho,
    )?;
    if let Some(mirror_runtime_chirho) = &mirror_runtime_chirho {
        resident_chirho.install_mirror_runtime_chirho(
            mirror_runtime_chirho.append_mirror_chirho(),
            mirror_runtime_chirho.ordinary_term_acceptance_source_chirho(),
            mirror_runtime_chirho.ordinary_term_acceptance_placement_binding_chirho(),
        );
    }
    let (mut append_barrier_state_chirho, readiness_chirho) =
        ResidentAppendBarrierRuntimeChirho::restore_chirho(
            &gd7_winner_handoff_store_chirho,
            tenant_migration_store_chirho.as_ref(),
            &handoff_control_chirho,
            &resident_chirho,
            &handoff_local_authority_chirho,
        )
        .map_err(|error_chirho| anyhow!("restore resident append barrier: {error_chirho}"))?;
    let mut tenant_migration_operation_runtime_chirho = tenant_migration_store_chirho
        .map(|store_chirho| {
            ResidentTenantMigrationOperationRuntimeChirho::new_chirho(
                &canonical_root_chirho,
                &storage_chirho,
                &config_chirho.storage_namespace_chirho,
                TenantLedgerVerificationViewsChirho {
                    signer_chirho: &signers_chirho.journal_chirho,
                    clock_chirho: &clock_chirho,
                    membership_chirho: &elected_membership_chirho,
                    kind_registry_chirho: &kind_registry_chirho,
                    authority_chirho: &money_authority_chirho,
                },
                tenant_migration_journal_path_chirho,
                tenant_migration_cluster_chirho,
                store_chirho,
                handoff_control_chirho.clone(),
                // Absent unless configured, in which case BEGIN refuses
                // `DestinationAuthorityUnavailableChirho`. Fail-closed by absence: an unconfigured
                // host cannot select a migration destination at all.
                tenant_migration_destination_authority_chirho
                    .as_ref()
                    .map(|authority_chirho| {
                        authority_chirho as &dyn TenantMigrationDestinationAuthorityPortChirho
                    }),
                capacity_admission_chirho,
                mirror_runtime_chirho
                    .as_ref()
                    .map(LedgerMirrorRuntimePortsChirho::append_mirror_chirho),
                tenant_migration_activation_verifier_chirho.as_ref(),
                &gd7_control_signer_chirho,
                config_chirho.local_epoch_chirho,
            )
        })
        .transpose()
        .map_err(|error_chirho| {
            anyhow!("open resident tenant migration operations: {error_chirho}")
        })?;
    ensure_startup_winner_term_index_chirho(
        &resident_chirho,
        &readiness_chirho,
        &gd7_winner_store_chirho,
        &group_chirho,
        &node_chirho,
    )?;
    verify_readiness_canary_alignment_chirho(
        &readiness_chirho,
        current_canary_chirho.latest_ledger_cut_chirho(),
        &group_chirho,
    )?;
    let mut canary_state_chirho = ResidentCanaryStateChirho {
        latest_ledger_cut_chirho: current_canary_chirho.latest_ledger_cut_chirho().clone(),
        pending_chirho: None,
        sticky_refusal_chirho: None,
    };
    let mut winner_view_state_chirho = ResidentGd7WinnerViewStateChirho::default();
    let mut winner_adoption_evidence_state_chirho =
        ResidentGd7WinnerAdoptionEvidenceStateChirho::default();
    startup_sender_chirho
        .send(Ok(ResidentActorStartupChirho {
            local_append_authority_chirho: handoff_local_authority_chirho.clone(),
            ledger_config_chirho: effective_config_chirho,
        }))
        .map_err(|_error_chirho| anyhow!("resident actor startup receiver closed"))?;

    loop {
        let command_chirho = if actor_owns_election_clock_chirho {
            match command_receiver_chirho.recv_timeout(Duration::from_millis(
                RESIDENT_EFFECT_JOURNAL_TICK_INTERVAL_MS_CHIRHO,
            )) {
                Ok(command_chirho) => command_chirho,
                Err(RecvTimeoutError::Timeout) => {
                    let _outbound_messages_chirho = owned_elector_chirho
                        .as_ref()
                        .expect("clock-owning resident actor retains its elector")
                        .tick_chirho();
                    // THE TICK ARM IS THE ONLY MOMENT THIS LOOP IS NOT ORDERING A COMMAND, which is
                    // why the re-seed lives here and nowhere else. The loop's single consumer totally
                    // orders appends; a network seed inline with a command would stall a working write
                    // path for exactly as long as an unreachable holder takes to time out.
                    //
                    // It runs ONLY while `holder_reseed_pending_chirho` holds -- that is, while the
                    // holders were never successfully seeded, so the write path is already dead and a
                    // brief occupancy costs nothing that is not already lost. It stops permanently on
                    // the first success. Bounded to one attempt per N ticks so an unreachable holder
                    // cannot turn this into a busy loop.
                    if holder_reseed_pending_chirho {
                        ticks_since_reseed_attempt_chirho =
                            ticks_since_reseed_attempt_chirho.saturating_add(1);
                        if ticks_since_reseed_attempt_chirho >= RESIDENT_HOLDER_RESEED_TICKS_CHIRHO
                        {
                            ticks_since_reseed_attempt_chirho = 0;
                            if let Some(mirror_runtime_chirho) = mirror_runtime_chirho.as_ref() {
                                match resident_chirho.reseed_current_holders_chirho(
                                    mirror_runtime_chirho.recovery_source_chirho().as_ref(),
                                ) {
                                    Ok(()) => {
                                        holder_reseed_pending_chirho = false;
                                        eprintln!("ResidentHolderReseedBootstrappedChirho");
                                    }
                                    Err(detail_chirho) => {
                                        eprintln!(
                                            "ResidentHolderReseedRefusedChirho:{}",
                                            detail_chirho
                                        );
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            // MEASURED 2026-08-18: this branch is why the first re-seed attempt never executed. A
            // non-clock-owning actor blocked in `recv()` forever, so the timeout arm above -- where the
            // re-seed lived -- could not fire, and BOTH re-seed identities censused zero on the host.
            // Not a wrong shape, a wrong PLACEMENT.
            //
            // It now wakes on the same interval so the re-seed has a moment to run here too. It does
            // NOT tick the elector: that stays the clock owner's job, and this actor explicitly does
            // not own it.
            match command_receiver_chirho.recv_timeout(Duration::from_millis(
                RESIDENT_EFFECT_JOURNAL_TICK_INTERVAL_MS_CHIRHO,
            )) {
                Ok(command_chirho) => command_chirho,
                Err(RecvTimeoutError::Timeout) => {
                    if holder_reseed_pending_chirho {
                        ticks_since_reseed_attempt_chirho =
                            ticks_since_reseed_attempt_chirho.saturating_add(1);
                        if ticks_since_reseed_attempt_chirho >= RESIDENT_HOLDER_RESEED_TICKS_CHIRHO
                        {
                            ticks_since_reseed_attempt_chirho = 0;
                            if let Some(mirror_runtime_chirho) = mirror_runtime_chirho.as_ref() {
                                match resident_chirho.reseed_current_holders_chirho(
                                    mirror_runtime_chirho.recovery_source_chirho().as_ref(),
                                ) {
                                    Ok(()) => {
                                        holder_reseed_pending_chirho = false;
                                        eprintln!("ResidentHolderReseedBootstrappedChirho");
                                    }
                                    Err(detail_chirho) => {
                                        eprintln!(
                                            "ResidentHolderReseedRefusedChirho:{}",
                                            detail_chirho
                                        );
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        };
        let Some(elector_chirho) = elector_weak_chirho.upgrade() else {
            break;
        };
        // Safety invariant: this single consumer totally orders accepted append and winner-handoff
        // commands. Running mutation commands concurrently requires a replacement cut-order proof.
        let admitted_command_chirho = ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
            command_chirho,
            &append_barrier_state_chirho,
        );
        let should_stop_chirho = admitted_command_chirho.is_some_and(|command_chirho| {
            handle_actor_command_chirho(
                command_chirho,
                &mut resident_chirho,
                &signers_chirho,
                elector_chirho.as_ref(),
                &gd7_winner_store_chirho,
                &gd7_winner_handoff_store_chirho,
                &handoff_local_authority_chirho,
                &gd7_plan_ports_chirho,
                &testkind_loss_witness_plan_chirho,
                gd7_compensation_provider_chirho.as_ref(),
                &canary_store_chirho,
                &group_chirho,
                &node_chirho,
                &mut canary_state_chirho,
                &mut winner_view_state_chirho,
                &mut append_barrier_state_chirho,
                &mut tenant_migration_operation_runtime_chirho,
                &mut winner_adoption_evidence_state_chirho,
            )
        });
        if actor_owns_election_clock_chirho {
            let _outbound_messages_chirho = elector_chirho.tick_chirho();
        }
        if should_stop_chirho {
            break;
        }
    }
    drop(owned_elector_chirho);
    Ok(())
}

fn ensure_startup_winner_term_index_chirho(
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    readiness_chirho: &ResidentLedgerAuthorityReadinessChirho,
    winner_store_chirho: &Gd7WinnerWitnessStoreChirho<'_>,
    group_chirho: &ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
) -> Result<()> {
    if readiness_chirho.consistency_group_chirho != *group_chirho
        || readiness_chirho.local_node_chirho != *node_chirho
    {
        bail!("resident readiness differs from the GD7 winner coordinate");
    }
    let winner_term_chirho = readiness_chirho.published_raft_term_chirho;
    if winner_term_chirho == 0 {
        return Ok(());
    }
    let journal_term_chirho =
        u64::from(split_writer_epoch_chirho(readiness_chirho.journal_epoch_chirho).geo_term_chirho);
    if journal_term_chirho < winner_term_chirho {
        return Ok(());
    }
    if journal_term_chirho != winner_term_chirho {
        bail!("resident journal term is ahead of its GD7 winner coordinate");
    }
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho)?;
    if winner_store_chirho
        .load_winner_first_record_chirho(
            &group_digest_chirho,
            &node_chirho.0,
            winner_term_chirho,
            &readiness_chirho.genesis_digest_chirho.0,
        )
        .map_err(|error_chirho| anyhow!("GD7 winner index verification refused: {error_chirho}"))?
        .is_some()
    {
        return Ok(());
    }
    let tail_evidence_chirho = resident_chirho
        .tail_epoch_first_record_evidence_chirho()?
        .ok_or_else(|| {
            anyhow!(
                "current-term journal lacks both a winner index and exact-tail recovery evidence"
            )
        })?;
    winner_store_chirho
        .ensure_winner_first_record_chirho(
            &group_digest_chirho,
            &node_chirho.0,
            winner_term_chirho,
            &readiness_chirho.genesis_digest_chirho.0,
            &tail_evidence_chirho,
        )
        .map_err(|error_chirho| anyhow!("GD7 winner index recovery refused: {error_chirho}"))?;
    Ok(())
}

fn ensure_append_winner_term_index_chirho(
    winner_store_chirho: &Gd7WinnerWitnessStoreChirho<'_>,
    group_chirho: &ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
    before_chirho: &ResidentLedgerAuthorityReadinessChirho,
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
) -> Result<()> {
    let winner_term_chirho = receipt_chirho.published_raft_term_chirho;
    // TERM 0 IS PRE-ELECTION, SO THIS IS A CORRECT NO-OP RATHER THAN A PERMISSIVE SKIP -- and the
    // reason is written here because its absence cost two seats an evening. The branch bypasses four
    // money-path checks below (fence/receipt term equality, the `before > winner` monotonicity
    // refusal, the first-record anchor requirement, and winner-index persistence), so it reads exactly
    // like a fail-open unless you already know why it cannot fire.
    //
    // It cannot fire, proven two independent ways:
    //   * PROVENANCE — this receipt is produced locally by the `append_chirho` immediately above the
    //     single (private) caller; nothing external reaches this parameter. That append holds a guard
    //     from `try_acquire_chirho` OR, on the GD7 winner-side compensation lane, from
    //     `try_acquire_active_handoff_append_chirho` — BOTH call `validate_observation_chirho` with
    //     `?` BEFORE constructing their guard, and that validator refuses
    //     `published_raft_term_chirho == 0` outright with `PublishedRaftTermOutOfRangeChirho`. The
    //     exempt lane changes WHICH marker state admits the append, never whether the observation
    //     was validated.
    //   * RAFT ITSELF — in vendored raft-0.7.0, `become_candidate` raises the term (`self.term + 1`)
    //     and `become_leader` asserts Follower -> Leader is impossible. The only route to leadership
    //     runs through Candidate, so any node reporting `StateRole::Leader` has term >= 1.
    //
    // KEEP THE BRANCH. Removing it adds a refusal path to the genesis-critical append for a value that
    // cannot occur. What must not happen is this line drifting away from its guarantee: if
    // `validate_observation_chirho` is ever loosened to admit a zero term, this becomes a SILENT skip
    // of a money-path cross-check and nothing here goes red.
    if winner_term_chirho == 0 {
        return Ok(());
    }
    let fence_term_chirho = u64::from(
        split_writer_epoch_chirho(receipt_chirho.fence_chirho.epoch_chirho).geo_term_chirho,
    );
    if fence_term_chirho != winner_term_chirho
        || before_chirho.published_raft_term_chirho > winner_term_chirho
    {
        bail!("resident receipt term differs from its GD7 winner coordinate");
    }
    let before_term_chirho =
        u64::from(split_writer_epoch_chirho(before_chirho.journal_epoch_chirho).geo_term_chirho);
    let evidence_chirho = receipt_chirho
        .append_chirho
        .epoch_first_record_chirho
        .as_ref();
    if before_term_chirho < winner_term_chirho && evidence_chirho.is_none() {
        bail!("first committed record in a winner term omitted its bounded anchor evidence");
    }
    let Some(evidence_chirho) = evidence_chirho else {
        return Ok(());
    };
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho)?;
    winner_store_chirho
        .ensure_winner_first_record_chirho(
            &group_digest_chirho,
            &node_chirho.0,
            winner_term_chirho,
            &before_chirho.genesis_digest_chirho.0,
            evidence_chirho,
        )
        .map_err(|error_chirho| anyhow!("GD7 winner index persistence refused: {error_chirho}"))?;
    Ok(())
}
