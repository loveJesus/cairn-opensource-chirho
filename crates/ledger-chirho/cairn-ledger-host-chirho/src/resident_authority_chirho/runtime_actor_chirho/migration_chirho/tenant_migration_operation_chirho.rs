// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Crate-private resident-actor custody for a durable tenant source fence.
//!
//! The mailbox handle can request begin, recovery, or exact-current abort. It cannot name a store,
//! signer, verified cut, append authority, marker controller, or activation operation. Target paths
//! are descriptor-opened inside the actor and checked as distinct roots of the same tenant; this is
//! root binding. BEGIN separately verifies externally signed destination authority against that
//! exact opened target before any eligibility check, durable mutation, or source fence.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use super::super::writer_adoption_chirho::{
    encode_verified_operation_authority_for_begin_chirho, parse_operation_authority_chirho,
    publish_writer_adoption_warrant_chirho, verify_operation_authority_for_begin_chirho,
    verify_recovered_operation_authority_chirho,
    TenantMigrationWriterAdoptionConsumptionRefusalChirho,
    TenantMigrationWriterAdoptionCoordinatesChirho, TenantMigrationWriterAdoptionGateRefusalChirho,
    TenantMigrationWriterAdoptionRecordChirho,
};
use super::append_barrier_chirho::ResidentAppendBarrierRuntimeChirho;
use super::capacity_admission_runtime_chirho::{
    TenantMigrationCapacityAdmissionCompositionChirho,
    TenantMigrationCapacityCompositionRefusalChirho,
};
use super::configured_namespace_chirho::ConfiguredMigrationNamespaceChirho;
use super::target_adoption_chirho::{
    inspect_target_adoption_posture_chirho, TargetAdoptionRefusalChirho,
};
use super::{ResidentEffectJournalCommandChirho, ResidentEffectJournalHandleChirho};
use crate::authority_chirho::PinnedLedgerActivationVerifierChirho;
use cairn_ledger_host_storage_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::append_mirror_chirho::{
    LedgerAppendMirrorPortChirho, LedgerAppendMirrorPortErrorChirho,
};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_tenant_migration_chirho::{
    TenantLedgerVerificationViewsChirho, TenantMigrationRefusalChirho,
    VerifiedTenantMigrationRootChirho,
};
use cairn_ledger_tenant_migration_durable_chirho::{
    restore_tenant_migration_startup_chirho, verify_tenant_migration_destination_record_chirho,
    ActiveTenantMigrationChirho, TenantMigrationActivationInputsChirho,
    TenantMigrationControlSignerPortChirho, TenantMigrationCoordinatorRefusalChirho,
    TenantMigrationDestinationAuthorityPortChirho, TenantMigrationDestinationRecordChirho,
    TenantMigrationDestinationRefusalChirho, TenantMigrationOperationAuthorityBindingChirho,
    TenantMigrationOperationInputsChirho, TenantMigrationPhaseChirho,
    TenantMigrationStartupBarrierChirho, TenantMigrationStoreChirho,
    VerifiedTenantMigrationDestinationChirho,
};
// Fixture-only imports. Kept separate and `cfg(test)`-gated so the shipping build carries no unused
// import: the items below exist to BUILD authorizations, and production only ever verifies them.
#[cfg(test)]
use cairn_ledger_tenant_migration_durable_chirho::{
    tenant_migration_destination_intent_digest_chirho, TenantMigrationDestinationIntentChirho,
    TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO,
    TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_tenant_chirho::capacity_admission_chirho::TenantCapacityAdmissionVerdictChirho;
use cairn_tenant_chirho::migration_completeness_chirho::{
    PreliminaryMigrationCheckChirho, PreliminaryMigrationHalfFailureChirho,
};
use cairn_tenant_chirho::migration_eligibility_chirho::{
    preliminary_check_for_root_chirho, MigrationEligibilityRefusalChirho,
};
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityRefusalChirho, LocalAppendHandoffControlHandleChirho,
};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;

#[cfg(test)]
#[path = "tenant_migration_fixture_chirho.rs"]
mod tenant_migration_fixture_chirho;
#[cfg(test)]
pub(crate) use tenant_migration_fixture_chirho::{
    seed_migration_reference_chirho, stage_adopted_writer_identity_chirho,
    stage_migration_target_surfaces_chirho,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentTenantMigrationSourceFenceStatusChirho {
    pub attempt_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub phase_chirho: TenantMigrationPhaseChirho,
    pub marker_activation_generation_chirho: u64,
}

/// Its own type rather than reusing the source-fence status: a value named for a source FENCE that
/// carried an ACTIVATED phase would assert the opposite of what it holds, and this repo has paid for
/// that shape before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentTenantMigrationTargetActivatedStatusChirho {
    pub attempt_digest_chirho: String,
    pub checkpoint_ref_chirho: String,
    pub phase_chirho: TenantMigrationPhaseChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResidentTenantMigrationAbortStatusChirho {
    pub(crate) attempt_digest_chirho: String,
    pub(crate) checkpoint_ref_chirho: String,
    pub(crate) released_owned_marker_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum ResidentTenantMigrationOperationOutcomeChirho {
    SourceFencedChirho(ResidentTenantMigrationSourceFenceStatusChirho),
    TargetActivatedChirho(ResidentTenantMigrationTargetActivatedStatusChirho),
    AbortedChirho(ResidentTenantMigrationAbortStatusChirho),
}

#[derive(Debug)]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "crate-private until an operator path can name it; target activation itself \
                  landed 2026-08-19 and now consumes the source-fence capability"
    )
)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum ResidentTenantMigrationOperationRefusalChirho {
    MailboxFullChirho,
    ActorUnavailableChirho,
    ActorProtocolMismatchChirho,
    ResidentRootIsNotTenantChirho,
    AnyAppendBarrierOwnerActiveChirho,
    MigrationContractChirho(TenantMigrationRefusalChirho),
    CoordinatorChirho(TenantMigrationCoordinatorRefusalChirho),
    /// No destination authority is configured, so no target may be selected at all. Deliberately
    /// distinct from a refused authorization: "nobody can authorize destinations here" and "this
    /// authorization is bad" send an operator to different places.
    DestinationAuthorityUnavailableChirho,
    DestinationAuthorityChirho(TenantMigrationDestinationRefusalChirho),
    /// The resident actor was opened without the production capacity/load composition. A migration
    /// may not turn that absence into the old five-half admission road.
    CapacityAdmissionUnavailableChirho,
    CapacityAdmissionChirho(TenantMigrationCapacityCompositionRefusalChirho),
    /// A v1 operation can still be parsed for an already-completed writer-adoption consumption,
    /// but it cannot recover or activate under the v2 capacity-driven migration contract.
    CapacityAdmissionIdentityUnavailableChirho,
    CapacityAdmissionIdentityChangedChirho,
    SourceMirrorPendingChirho(LedgerAppendMirrorPortErrorChirho),
    WriterAdoptionAuthorityChirho(TenantMigrationWriterAdoptionGateRefusalChirho),
    WriterAdoptionConsumptionChirho(TenantMigrationWriterAdoptionConsumptionRefusalChirho),
    TargetWriterIdentityChirho(TargetAdoptionRefusalChirho),
    /// The target root could not be inspected; distinct from a readable root that failed a half.
    TargetRootUnreadableChirho,
    /// The readable target's configured ledger namespace could not be opened.
    TargetLedgerNamespaceUnopenableChirho,
    /// The readable target failed one or more independently attributed eligibility halves.
    TargetNotEligibleChirho {
        failed_halves_chirho: Vec<PreliminaryMigrationHalfFailureChirho>,
    },
    /// The target cannot be OPENED as a resident writer, so fencing the source toward it would
    /// leave the tenant with no writer at all. Distinct from `TargetNotEligibleChirho` on purpose:
    /// eligibility asks whether the target's CONTENTS are right, this asks whether it can serve.
    TargetNotAdoptableChirho {
        reason_chirho: String,
    },
    BarrierReconciliationChirho {
        operation_detail_chirho: String,
        reconciliation_detail_chirho: String,
    },
}

impl fmt::Display for ResidentTenantMigrationOperationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetRootUnreadableChirho => {
                formatter_chirho.write_str("the target root could not be inspected")
            }
            Self::TargetLedgerNamespaceUnopenableChirho => formatter_chirho
                .write_str("the target's ledger namespace could not be opened"),
            Self::TargetNotAdoptableChirho { reason_chirho } => write!(
                formatter_chirho,
                "the target is eligible but cannot be adopted as a writer: {reason_chirho}"
            ),
            Self::TargetNotEligibleChirho {
                failed_halves_chirho,
            } => write!(
                formatter_chirho,
                "the target is readable but not eligible; halves refused: {}",
                failed_halves_chirho
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::MailboxFullChirho => {
                formatter_chirho.write_str("resident tenant-migration mailbox is at capacity")
            }
            Self::ActorUnavailableChirho => {
                formatter_chirho.write_str("resident tenant-migration actor is unavailable")
            }
            Self::ActorProtocolMismatchChirho => formatter_chirho
                .write_str("resident tenant-migration actor returned the wrong operation outcome"),
            Self::ResidentRootIsNotTenantChirho => {
                formatter_chirho.write_str("resident root is not a tenant consistency group")
            }
            Self::AnyAppendBarrierOwnerActiveChirho => formatter_chirho
                .write_str("an existing GD7 or tenant-migration owner holds the append barrier"),
            Self::MigrationContractChirho(refusal_chirho) => {
                write!(formatter_chirho, "tenant migration contract refused: {refusal_chirho}")
            }
            Self::CoordinatorChirho(refusal_chirho) => {
                write!(formatter_chirho, "tenant migration coordinator refused: {refusal_chirho}")
            }
            Self::DestinationAuthorityUnavailableChirho => formatter_chirho.write_str(
                "no tenant migration destination authority is configured, so no target may be selected",
            ),
            Self::DestinationAuthorityChirho(refusal_chirho) => write!(
                formatter_chirho,
                "tenant migration destination authorization refused: {refusal_chirho:?}"
            ),
            Self::CapacityAdmissionUnavailableChirho => formatter_chirho.write_str(
                "tenant migration capacity/load admission is not configured on this resident actor",
            ),
            Self::CapacityAdmissionChirho(refusal_chirho) => write!(
                formatter_chirho,
                "tenant migration capacity/load admission could not be evaluated: {refusal_chirho:?}"
            ),
            Self::CapacityAdmissionIdentityUnavailableChirho => formatter_chirho.write_str(
                "the active migration predates durable capacity/load admission and cannot continue",
            ),
            Self::CapacityAdmissionIdentityChangedChirho => formatter_chirho.write_str(
                "the capacity/load admission identity changed since migration begin",
            ),
            Self::SourceMirrorPendingChirho(refusal_chirho) => write!(
                formatter_chirho,
                "the source mirror has an unreconciled pending append: {refusal_chirho}"
            ),
            Self::WriterAdoptionAuthorityChirho(refusal_chirho) => write!(
                formatter_chirho,
                "tenant migration writer adoption authorization refused: {refusal_chirho:?}"
            ),
            Self::WriterAdoptionConsumptionChirho(refusal_chirho) => write!(
                formatter_chirho,
                "tenant migration writer adoption warrant refused: {refusal_chirho:?}"
            ),
            Self::TargetWriterIdentityChirho(refusal_chirho) => write!(
                formatter_chirho,
                "tenant migration target writer identity refused: {refusal_chirho:?}"
            ),
            Self::BarrierReconciliationChirho {
                operation_detail_chirho,
                reconciliation_detail_chirho,
            } => write!(
                formatter_chirho,
                "tenant migration operation refused ({operation_detail_chirho}); append barrier reconciliation also refused ({reconciliation_detail_chirho})"
            ),
        }
    }
}

impl Error for ResidentTenantMigrationOperationRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::MigrationContractChirho(refusal_chirho) => Some(refusal_chirho),
            Self::CoordinatorChirho(refusal_chirho) => Some(refusal_chirho),
            Self::SourceMirrorPendingChirho(refusal_chirho) => Some(refusal_chirho),
            Self::TargetRootUnreadableChirho
            | Self::TargetLedgerNamespaceUnopenableChirho
            | Self::TargetNotEligibleChirho { .. }
            | Self::TargetNotAdoptableChirho { .. }
            | Self::MailboxFullChirho
            | Self::ActorUnavailableChirho
            | Self::ActorProtocolMismatchChirho
            | Self::ResidentRootIsNotTenantChirho
            | Self::AnyAppendBarrierOwnerActiveChirho
            | Self::DestinationAuthorityUnavailableChirho
            | Self::CapacityAdmissionUnavailableChirho
            | Self::CapacityAdmissionChirho(_)
            | Self::CapacityAdmissionIdentityUnavailableChirho
            | Self::CapacityAdmissionIdentityChangedChirho
            // A plain value rather than an Error, so there is no source to chain; its identity
            // already travels in the Display text.
            | Self::DestinationAuthorityChirho(_)
            | Self::WriterAdoptionAuthorityChirho(_)
            | Self::WriterAdoptionConsumptionChirho(_)
            | Self::TargetWriterIdentityChirho(_)
            | Self::BarrierReconciliationChirho { .. } => None,
        }
    }
}

impl From<TenantMigrationRefusalChirho> for ResidentTenantMigrationOperationRefusalChirho {
    fn from(refusal_chirho: TenantMigrationRefusalChirho) -> Self {
        Self::MigrationContractChirho(refusal_chirho)
    }
}

impl From<TenantMigrationCoordinatorRefusalChirho>
    for ResidentTenantMigrationOperationRefusalChirho
{
    fn from(refusal_chirho: TenantMigrationCoordinatorRefusalChirho) -> Self {
        Self::CoordinatorChirho(refusal_chirho)
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "crate-private until an operator path can name it; target activation itself \
                  landed 2026-08-19 and now consumes the source-fence capability"
    )
)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub(super) enum ResidentTenantMigrationOperationCommandChirho {
    /// Begin an attempt and fence the source, toward an EXTERNALLY AUTHORIZED destination.
    ///
    /// Carries no preliminary check, for the same reason activation does not: the type is
    /// un-constructible outside the layer that can compute it honestly, so the actor computes it.
    BeginSourceFenceChirho {
        target_root_chirho: PathBuf,
        /// Externally signed permission to move ONTO this target. A path alone is a request; this is
        /// what makes it a selection the node was authorized to make. The opposite kind of value
        /// from the precheck: minted elsewhere, verifiable here, and designed to cross a boundary.
        destination_chirho: Box<TenantMigrationDestinationRecordChirho>,
        /// Independent activation-authority signature. Required only when the target has no
        /// resident identity; an existing identity and an adoption grant may not be combined.
        writer_adoption_chirho: Option<Box<TenantMigrationWriterAdoptionRecordChirho>>,
    },
    RecoverSourceFenceChirho {
        target_root_chirho: PathBuf,
    },
    /// Activate the target for the current attempt.
    ///
    /// Carries the same non-authoritative preliminary evidence begin and recovery carry, because
    /// activation RE-RUNS recovery first: the source-fence witness is an in-memory value that is
    /// deliberately never persisted, so it must be re-established before it can be consumed. No
    /// caller-selected attempt digest or checkpoint ref appears here — the actor loads the current
    /// signed head and selects that exact identity itself.
    ActivateTargetChirho {
        target_root_chirho: PathBuf,
    },
    AbortCurrentChirho,
}

impl ResidentTenantMigrationOperationCommandChirho {
    pub(super) fn begins_source_fence_chirho(&self) -> bool {
        matches!(self, Self::BeginSourceFenceChirho { .. })
    }
}

/// Mailbox-only outage capability. It remains unnameable outside this crate until target
/// activation and target-selection authority exist together.
#[derive(Clone)]
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "crate-private until an operator path can name it; target activation itself \
                  landed 2026-08-19 and now consumes the source-fence capability"
    )
)]
pub struct ResidentTenantMigrationOperationHandleChirho {
    command_sender_chirho: SyncSender<ResidentEffectJournalCommandChirho>,
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "crate-private until an operator path can name it; target activation itself \
                  landed 2026-08-19 and now consumes the source-fence capability"
    )
)]
impl ResidentTenantMigrationOperationHandleChirho {
    /// Begin an attempt and fence the source toward an externally authorized destination.
    ///
    /// `pub` as of 2026-08-19: the operator path this type's own `dead_code` note was waiting for
    /// now exists. The eligibility precheck is NOT a parameter — the actor computes it, because it
    /// is the only layer holding the configured namespace name and the source object resolver.
    pub fn begin_source_fence_chirho(
        &self,
        target_root_chirho: &Path,
        destination_chirho: TenantMigrationDestinationRecordChirho,
    ) -> Result<
        ResidentTenantMigrationSourceFenceStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        self.begin_source_fence_with_writer_adoption_chirho(
            target_root_chirho,
            destination_chirho,
            None,
        )
    }

    pub fn begin_source_fence_with_writer_adoption_chirho(
        &self,
        target_root_chirho: &Path,
        destination_chirho: TenantMigrationDestinationRecordChirho,
        writer_adoption_chirho: Option<TenantMigrationWriterAdoptionRecordChirho>,
    ) -> Result<
        ResidentTenantMigrationSourceFenceStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        match self.request_chirho(
            ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                target_root_chirho: target_root_chirho.to_path_buf(),
                destination_chirho: Box::new(destination_chirho),
                writer_adoption_chirho: writer_adoption_chirho.map(Box::new),
            },
        )? {
            ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(status_chirho) => {
                Ok(status_chirho)
            }
            ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(_)
            | ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(_) => {
                Err(ResidentTenantMigrationOperationRefusalChirho::ActorProtocolMismatchChirho)
            }
        }
    }

    pub(crate) fn recover_source_fence_chirho(
        &self,
        target_root_chirho: &Path,
    ) -> Result<
        ResidentTenantMigrationSourceFenceStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        match self.request_chirho(
            ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                target_root_chirho: target_root_chirho.to_path_buf(),
            },
        )? {
            ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(status_chirho) => {
                Ok(status_chirho)
            }
            ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(_)
            | ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(_) => {
                Err(ResidentTenantMigrationOperationRefusalChirho::ActorProtocolMismatchChirho)
            }
        }
    }

    pub fn activate_target_chirho(
        &self,
        target_root_chirho: &Path,
    ) -> Result<
        ResidentTenantMigrationTargetActivatedStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        match self.request_chirho(
            ResidentTenantMigrationOperationCommandChirho::ActivateTargetChirho {
                target_root_chirho: target_root_chirho.to_path_buf(),
            },
        )? {
            ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(status_chirho) => {
                Ok(status_chirho)
            }
            ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(_)
            | ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(_) => {
                Err(ResidentTenantMigrationOperationRefusalChirho::ActorProtocolMismatchChirho)
            }
        }
    }

    pub(crate) fn abort_current_chirho(
        &self,
    ) -> Result<
        ResidentTenantMigrationAbortStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        match self
            .request_chirho(ResidentTenantMigrationOperationCommandChirho::AbortCurrentChirho)?
        {
            ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(status_chirho) => {
                Ok(status_chirho)
            }
            ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(_)
            | ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(_) => {
                Err(ResidentTenantMigrationOperationRefusalChirho::ActorProtocolMismatchChirho)
            }
        }
    }

    fn request_chirho(
        &self,
        command_chirho: ResidentTenantMigrationOperationCommandChirho,
    ) -> Result<
        ResidentTenantMigrationOperationOutcomeChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
        self.command_sender_chirho
            .try_send(
                ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
                    command_chirho,
                    reply_chirho: reply_sender_chirho,
                },
            )
            .map_err(|error_chirho| match error_chirho {
                TrySendError::Full(_command_chirho) => {
                    ResidentTenantMigrationOperationRefusalChirho::MailboxFullChirho
                }
                TrySendError::Disconnected(_command_chirho) => {
                    ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho
                }
            })?;
        reply_receiver_chirho.recv().map_err(|_error_chirho| {
            ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho
        })?
    }
}

impl ResidentEffectJournalHandleChirho {
    #[allow(
        dead_code,
        reason = "crate-private until an operator path can name it; target activation itself \
                  landed 2026-08-19 and now consumes the source-fence capability"
    )]
    pub fn tenant_migration_operation_handle_chirho(
        &self,
    ) -> Result<
        ResidentTenantMigrationOperationHandleChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let command_sender_chirho = self
            .command_sender_chirho
            .as_ref()
            .ok_or(ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho)?
            .clone();
        Ok(ResidentTenantMigrationOperationHandleChirho {
            command_sender_chirho,
        })
    }
}

pub(super) struct ResidentTenantMigrationOperationRuntimeChirho<'ports_chirho> {
    source_root_chirho: VerifiedTenantMigrationRootChirho,
    source_storage_chirho: &'ports_chirho FsLedgerStorageChirho,
    configured_namespace_chirho: ConfiguredMigrationNamespaceChirho,
    source_views_chirho: TenantLedgerVerificationViewsChirho<'ports_chirho>,
    journal_path_chirho: StoragePathChirho,
    expected_cluster_chirho: ClusterIdChirho,
    store_chirho: TenantMigrationStoreChirho<'ports_chirho>,
    control_chirho: LocalAppendHandoffControlHandleChirho,
    /// Absent means no destination may be selected. Fail-closed by absence: a node without a
    /// configured authority refuses to begin rather than trusting the caller's path.
    destination_authority_chirho:
        Option<&'ports_chirho dyn TenantMigrationDestinationAuthorityPortChirho>,
    capacity_admission_chirho: Option<TenantMigrationCapacityAdmissionCompositionChirho>,
    source_mirror_chirho: Option<Arc<dyn LedgerAppendMirrorPortChirho>>,
    activation_verifier_chirho: Option<&'ports_chirho PinnedLedgerActivationVerifierChirho>,
    source_control_signer_chirho: &'ports_chirho dyn TenantMigrationControlSignerPortChirho,
    source_control_node_id_chirho: String,
    opening_epoch_chirho: u64,
}

impl<'ports_chirho> ResidentTenantMigrationOperationRuntimeChirho<'ports_chirho> {
    #[allow(
        clippy::too_many_arguments,
        reason = "one fixed actor-owned source verification and marker-control bundle"
    )]
    /// Refuse a begin whose destination was not authorized for THIS tenant and THIS source.
    ///
    /// The source digest is re-derived from the live verified root rather than taken from the
    /// command, so an authorization cannot be satisfied by a caller who also supplies the source it
    /// claims to be moving.
    fn require_authorized_destination_chirho(
        &self,
        destination_chirho: &TenantMigrationDestinationRecordChirho,
        target_root_chirho: &VerifiedTenantMigrationRootChirho,
    ) -> Result<
        VerifiedTenantMigrationDestinationChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let authority_chirho = self.destination_authority_chirho.ok_or(
            ResidentTenantMigrationOperationRefusalChirho::DestinationAuthorityUnavailableChirho,
        )?;
        let source_digest_chirho = self
            .source_root_chirho
            .binding_identity_digest_hex_chirho()?;
        let target_digest_chirho = target_root_chirho.binding_identity_digest_hex_chirho()?;
        verify_tenant_migration_destination_record_chirho(
            destination_chirho,
            authority_chirho,
            self.source_root_chirho.tenant_id_chirho(),
            &source_digest_chirho,
            &target_digest_chirho,
        )
        .map_err(ResidentTenantMigrationOperationRefusalChirho::DestinationAuthorityChirho)
    }

    fn require_same_tenant_target_chirho(
        &self,
        target_root_chirho: &VerifiedTenantMigrationRootChirho,
    ) -> Result<(), ResidentTenantMigrationOperationRefusalChirho> {
        if target_root_chirho.tenant_id_chirho() == self.source_root_chirho.tenant_id_chirho() {
            return Ok(());
        }
        Err(
            ResidentTenantMigrationOperationRefusalChirho::CoordinatorChirho(
                TenantMigrationCoordinatorRefusalChirho::MigrationContractChirho(
                    TenantMigrationRefusalChirho::TenantMismatchChirho,
                ),
            ),
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the actor runtime binds one fixed source-verification and authority bundle"
    )]
    pub(super) fn new_chirho(
        source_root_path_chirho: &Path,
        source_storage_chirho: &'ports_chirho FsLedgerStorageChirho,
        configured_storage_namespace_chirho: &str,
        source_views_chirho: TenantLedgerVerificationViewsChirho<'ports_chirho>,
        journal_path_chirho: StoragePathChirho,
        expected_cluster_chirho: ClusterIdChirho,
        store_chirho: TenantMigrationStoreChirho<'ports_chirho>,
        control_chirho: LocalAppendHandoffControlHandleChirho,
        destination_authority_chirho: Option<
            &'ports_chirho dyn TenantMigrationDestinationAuthorityPortChirho,
        >,
        capacity_admission_chirho: Option<TenantMigrationCapacityAdmissionCompositionChirho>,
        source_mirror_chirho: Option<Arc<dyn LedgerAppendMirrorPortChirho>>,
        activation_verifier_chirho: Option<&'ports_chirho PinnedLedgerActivationVerifierChirho>,
        source_control_signer_chirho: &'ports_chirho dyn TenantMigrationControlSignerPortChirho,
        opening_epoch_chirho: u64,
    ) -> Result<Self, ResidentTenantMigrationOperationRefusalChirho> {
        let source_root_chirho =
            VerifiedTenantMigrationRootChirho::open_existing_chirho(source_root_path_chirho)?;
        let configured_namespace_chirho =
            ConfiguredMigrationNamespaceChirho::parse_chirho(configured_storage_namespace_chirho)
                .ok_or(ResidentTenantMigrationOperationRefusalChirho::ActorProtocolMismatchChirho)?;
        let source_control_node_id_chirho = store_chirho.source_node_chirho().to_owned();
        Ok(Self {
            source_root_chirho,
            source_storage_chirho,
            configured_namespace_chirho,
            source_views_chirho,
            journal_path_chirho,
            expected_cluster_chirho,
            store_chirho,
            control_chirho,
            destination_authority_chirho,
            capacity_admission_chirho,
            source_mirror_chirho,
            activation_verifier_chirho,
            source_control_signer_chirho,
            source_control_node_id_chirho,
            opening_epoch_chirho,
        })
    }

    pub(super) fn handle_chirho(
        &mut self,
        command_chirho: ResidentTenantMigrationOperationCommandChirho,
        append_barrier_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    ) -> Result<
        ResidentTenantMigrationOperationOutcomeChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        match command_chirho {
            ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                target_root_chirho,
                destination_chirho,
                writer_adoption_chirho,
            } => self.begin_or_recover_chirho(
                target_root_chirho,
                Some(destination_chirho.as_ref()),
                writer_adoption_chirho.as_deref(),
                append_barrier_chirho,
            ),
            ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                target_root_chirho,
            } => {
                self.begin_or_recover_chirho(target_root_chirho, None, None, append_barrier_chirho)
            }
            ResidentTenantMigrationOperationCommandChirho::ActivateTargetChirho {
                target_root_chirho,
            } => self.activate_target_chirho(target_root_chirho, append_barrier_chirho),
            ResidentTenantMigrationOperationCommandChirho::AbortCurrentChirho => {
                self.abort_current_chirho(append_barrier_chirho)
            }
        }
    }

    /// Compute this target's eligibility precheck. ONE definition, shared by begin and activate.
    ///
    /// It is computed HERE rather than at the operator socket because three facts live only at this
    /// layer, and all three were found the hard way against a real drill root on 2026-08-19:
    ///
    /// - the CONFIGURED ledger namespace name, which the socket cannot know (it holds a path). A
    ///   root whose journal sits under an operator-chosen directory otherwise refuses on its own
    ///   journal's parent;
    /// - the SOURCE root as an object oracle. Without it a 64-hex token that resolves in neither
    ///   root cannot be told from a lost object, so every public key and idempotency digest in the
    ///   logs reads as a dangling reference — 79 of 95 tokens on a healthy serving root;
    /// - the SOURCE root's own surfaces, which is the only way to see what the TARGET is MISSING.
    ///
    /// The precheck type has private fields and no `Serialize`, so no caller can hand one in. That
    /// is deliberate, and this is the other half of it: the layer that CAN compute it honestly is
    /// the only layer that does.
    fn preliminary_check_chirho(
        &self,
        target_root_chirho: &VerifiedTenantMigrationRootChirho,
        target_root_path_chirho: &Path,
        namespace_root_surface_chirho: &str,
        capacity_admission_chirho: &TenantCapacityAdmissionVerdictChirho,
    ) -> Result<PreliminaryMigrationCheckChirho, ResidentTenantMigrationOperationRefusalChirho>
    {
        // TENANT IDENTITY FIRST, and the order is the point. Every half below compares this target
        // against THIS source — its surfaces, its objects, its namespace. Against a root belonging
        // to another tenant those comparisons are not merely wrong, they are meaningless, and they
        // would report a foreign root as "incomplete" rather than as FOREIGN. The contract refuses
        // the same mismatch later; this raises the same refusal before anything spends effort
        // measuring a root it should never have been pointed at.
        self.require_same_tenant_target_chirho(target_root_chirho)?;
        let source_surfaces_chirho = self.source_root_chirho.observed_surfaces_chirho();
        preliminary_check_for_root_chirho(
            target_root_path_chirho,
            Some(namespace_root_surface_chirho),
            Some(&self.source_root_chirho.object_resolver_chirho()),
            Some(&source_surfaces_chirho),
            Some(capacity_admission_chirho),
        )
        .map_err(|refusal_chirho| match refusal_chirho {
            MigrationEligibilityRefusalChirho::RootUnreadableChirho => {
                ResidentTenantMigrationOperationRefusalChirho::TargetRootUnreadableChirho
            }
            MigrationEligibilityRefusalChirho::HalvesFailedChirho { failed_chirho } => {
                ResidentTenantMigrationOperationRefusalChirho::TargetNotEligibleChirho {
                    failed_halves_chirho: failed_chirho,
                }
            }
        })
    }

    fn capacity_admission_chirho(
        &self,
        target_root_path_chirho: &Path,
    ) -> Result<TenantCapacityAdmissionVerdictChirho, ResidentTenantMigrationOperationRefusalChirho>
    {
        self.capacity_admission_chirho
            .as_ref()
            .ok_or(
                ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionUnavailableChirho,
            )?
            .admit_target_root_chirho(target_root_path_chirho)
            .map_err(ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionChirho)
    }

    fn operation_authority_binding_chirho(
        &self,
        target_root_path_chirho: &Path,
        target_root_chirho: &VerifiedTenantMigrationRootChirho,
        begin_chirho: Option<(
            &TenantMigrationDestinationRecordChirho,
            Option<&TenantMigrationWriterAdoptionRecordChirho>,
        )>,
    ) -> Result<
        (
            TenantMigrationOperationAuthorityBindingChirho,
            TenantCapacityAdmissionVerdictChirho,
        ),
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let target_posture_chirho = inspect_target_adoption_posture_chirho(target_root_path_chirho)
            .map_err(ResidentTenantMigrationOperationRefusalChirho::TargetWriterIdentityChirho)?;
        let coordinates_chirho = || TenantMigrationWriterAdoptionCoordinatesChirho {
            source_control_node_id_chirho: &self.source_control_node_id_chirho,
            storage_namespace_chirho: self.configured_namespace_chirho.full_relative_key_chirho(),
            journal_path_chirho: self.journal_path_chirho.key_chirho(),
            cluster_id_chirho: &self.expected_cluster_chirho.0,
            opening_epoch_chirho: self.opening_epoch_chirho,
        };
        if let Some((destination_chirho, writer_adoption_chirho)) = begin_chirho {
            let verified_destination_chirho =
                self.require_authorized_destination_chirho(destination_chirho, target_root_chirho)?;
            self.require_same_tenant_target_chirho(target_root_chirho)?;
            let verified_begin_chirho = verify_operation_authority_for_begin_chirho(
                destination_chirho,
                &verified_destination_chirho,
                writer_adoption_chirho,
                self.activation_verifier_chirho,
                target_root_path_chirho,
                &target_posture_chirho,
                coordinates_chirho(),
            )
            .map_err(ResidentTenantMigrationOperationRefusalChirho::WriterAdoptionAuthorityChirho);
            let verified_begin_chirho = verified_begin_chirho?;
            // Authority precedes evidence. A caller cannot spend a target-controlled evidence read
            // to learn about a root it was never authorized to select.
            let capacity_admission_chirho =
                self.capacity_admission_chirho(target_root_path_chirho)?;
            let operation_authority_chirho = encode_verified_operation_authority_for_begin_chirho(
                verified_begin_chirho,
                &capacity_admission_chirho.evidence_identity_chirho,
            )
            .map_err(
                ResidentTenantMigrationOperationRefusalChirho::WriterAdoptionAuthorityChirho,
            )?;
            return Ok((operation_authority_chirho, capacity_admission_chirho));
        }
        let active_chirho = self
            .store_chirho
            .load_current_chirho()
            .map_err(TenantMigrationCoordinatorRefusalChirho::from)?
            .ok_or(TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho)?;
        let operation_authority_chirho = active_chirho.operation_authority_chirho().clone();
        let envelope_chirho = parse_operation_authority_chirho(&operation_authority_chirho)
            .map_err(
                ResidentTenantMigrationOperationRefusalChirho::WriterAdoptionAuthorityChirho,
            )?;
        let verified_destination_chirho = self.require_authorized_destination_chirho(
            envelope_chirho.destination_chirho(),
            target_root_chirho,
        )?;
        self.require_same_tenant_target_chirho(target_root_chirho)?;
        verify_recovered_operation_authority_chirho(
            &envelope_chirho,
            &verified_destination_chirho,
            self.activation_verifier_chirho,
            target_root_path_chirho,
            &target_posture_chirho,
            coordinates_chirho(),
        )
        .map_err(ResidentTenantMigrationOperationRefusalChirho::WriterAdoptionAuthorityChirho)?;
        // Recompute from the externally pinned evidence only after both destination and adoption
        // authority have been re-verified. The exact identity stored at begin is the durable gate;
        // a new legitimate report intentionally requires an operator-reviewed new snapshot.
        let capacity_admission_chirho = self.capacity_admission_chirho(target_root_path_chirho)?;
        let expected_capacity_identity_chirho = envelope_chirho
            .capacity_admission_identity_chirho()
            .ok_or(
                ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionIdentityUnavailableChirho,
            )?;
        if expected_capacity_identity_chirho != capacity_admission_chirho.evidence_identity_chirho {
            return Err(
                ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionIdentityChangedChirho,
            );
        }
        Ok((operation_authority_chirho, capacity_admission_chirho))
    }

    fn begin_or_recover_chirho(
        &mut self,
        target_root_path_chirho: PathBuf,
        destination_chirho: Option<&TenantMigrationDestinationRecordChirho>,
        writer_adoption_chirho: Option<&TenantMigrationWriterAdoptionRecordChirho>,
        append_barrier_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    ) -> Result<
        ResidentTenantMigrationOperationOutcomeChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let begin_chirho = destination_chirho.is_some();
        if begin_chirho && append_barrier_chirho.any_owner_blocks_mutations_chirho() {
            return Err(
                ResidentTenantMigrationOperationRefusalChirho::AnyAppendBarrierOwnerActiveChirho,
            );
        }
        let target_root_chirho =
            VerifiedTenantMigrationRootChirho::open_existing_chirho(&target_root_path_chirho)?;
        let (operation_authority_chirho, capacity_admission_chirho) = self
            .operation_authority_binding_chirho(
                &target_root_path_chirho,
                &target_root_chirho,
                destination_chirho
                    .map(|destination_chirho| (destination_chirho, writer_adoption_chirho)),
            )?;
        let preliminary_check_chirho = self.preliminary_check_chirho(
            &target_root_chirho,
            &target_root_path_chirho,
            self.configured_namespace_chirho.root_surface_chirho(),
            &capacity_admission_chirho,
        )?;
        if begin_chirho {
            if let Some(source_mirror_chirho) = &self.source_mirror_chirho {
                // BEGIN and appends share this resident actor's serialized command loop. Checking
                // here, immediately before durable fencing, therefore has no external-check race:
                // either an earlier append fully cleared its intent, or BEGIN refuses while the
                // source remains the live rollback anchor.
                source_mirror_chirho
                    .require_no_unreconciled_pending_append_chirho()
                    .map_err(
                        ResidentTenantMigrationOperationRefusalChirho::SourceMirrorPendingChirho,
                    )?;
            }
        }
        let inputs_chirho = TenantMigrationOperationInputsChirho::new_chirho(
            self.source_root_chirho.clone(),
            target_root_chirho,
            preliminary_check_chirho,
            self.source_storage_chirho,
            self.source_views_chirho,
            &self.journal_path_chirho,
            &self.expected_cluster_chirho,
            operation_authority_chirho,
        );
        let operation_result_chirho = self
            .store_chirho
            .bind_operation_session_chirho(&self.control_chirho)
            .and_then(|mut session_chirho| {
                if begin_chirho {
                    session_chirho.begin_source_fenced_chirho(inputs_chirho)
                } else {
                    session_chirho.recover_source_fenced_chirho(inputs_chirho)
                }
            })
            .map_err(ResidentTenantMigrationOperationRefusalChirho::CoordinatorChirho)
            .and_then(|prepared_chirho| {
                self.source_fenced_status_chirho(&prepared_chirho.active_chirho)
            })
            .map(ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho);
        self.finish_operation_chirho(operation_result_chirho, append_barrier_chirho)
    }

    /// Re-establish the fence witness, then activate, in ONE session.
    ///
    /// Recovery runs first because the source-fence witness is an in-memory verified value that is
    /// deliberately never persisted; nothing resurrects one from disk. Doing both inside a single
    /// bound session is also what makes this correct after a restart rather than only on the happy
    /// path that never crashed.
    fn activate_target_chirho(
        &mut self,
        target_root_path_chirho: PathBuf,
        append_barrier_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    ) -> Result<
        ResidentTenantMigrationOperationOutcomeChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let target_root_chirho =
            VerifiedTenantMigrationRootChirho::open_existing_chirho(&target_root_path_chirho)?;
        let (operation_authority_chirho, capacity_admission_chirho) = self
            .operation_authority_binding_chirho(
                &target_root_path_chirho,
                &target_root_chirho,
                None,
            )?;
        // The full relative namespace comes from this node's validated config, never from the
        // operator command. Eligibility uses its first component because it sees root surfaces;
        // target storage uses the whole path. Collapsing those coordinates made every nested
        // namespace pass neither boundary correctly.
        let target_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(
            &self
                .configured_namespace_chirho
                .target_namespace_path_chirho(&target_root_path_chirho),
        )
        .map_err(|_error_chirho| {
            ResidentTenantMigrationOperationRefusalChirho::TargetLedgerNamespaceUnopenableChirho
        })?;
        let preliminary_check_chirho = self.preliminary_check_chirho(
            &target_root_chirho,
            &target_root_path_chirho,
            self.configured_namespace_chirho.root_surface_chirho(),
            &capacity_admission_chirho,
        )?;
        let current_chirho = self
            .store_chirho
            .load_current_chirho()
            .map_err(TenantMigrationCoordinatorRefusalChirho::from)?
            .ok_or(TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho)?;
        if current_chirho.phase_chirho()
            == TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
        {
            publish_writer_adoption_warrant_chirho(
                &target_root_path_chirho,
                &current_chirho,
                self.source_control_signer_chirho,
            )
            .map_err(
                ResidentTenantMigrationOperationRefusalChirho::WriterAdoptionConsumptionChirho,
            )?;
            let outcome_chirho = Ok(
                ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(
                    self.target_activated_status_chirho(&current_chirho),
                ),
            );
            return self.finish_operation_chirho(outcome_chirho, append_barrier_chirho);
        }
        let recover_inputs_chirho = TenantMigrationOperationInputsChirho::new_chirho(
            self.source_root_chirho.clone(),
            target_root_chirho.clone(),
            preliminary_check_chirho,
            self.source_storage_chirho,
            self.source_views_chirho,
            &self.journal_path_chirho,
            &self.expected_cluster_chirho,
            operation_authority_chirho,
        );
        let activation_inputs_chirho = TenantMigrationActivationInputsChirho::new_chirho(
            target_root_chirho,
            &target_storage_chirho,
            self.source_views_chirho,
            &self.journal_path_chirho,
            &self.expected_cluster_chirho,
        );
        let operation_result_chirho = self
            .store_chirho
            .bind_operation_session_chirho(&self.control_chirho)
            .and_then(|mut session_chirho| {
                let prepared_chirho =
                    session_chirho.recover_source_fenced_chirho(recover_inputs_chirho)?;
                session_chirho
                    .activate_target_chirho(prepared_chirho.move_chirho, activation_inputs_chirho)
            })
            .map_err(ResidentTenantMigrationOperationRefusalChirho::CoordinatorChirho)
            .and_then(|activated_chirho| {
                publish_writer_adoption_warrant_chirho(
                    &target_root_path_chirho,
                    &activated_chirho.active_chirho,
                    self.source_control_signer_chirho,
                )
                .map_err(
                    ResidentTenantMigrationOperationRefusalChirho::WriterAdoptionConsumptionChirho,
                )?;
                Ok(
                    ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(
                        self.target_activated_status_chirho(&activated_chirho.active_chirho),
                    ),
                )
            });
        self.finish_operation_chirho(operation_result_chirho, append_barrier_chirho)
    }

    fn target_activated_status_chirho(
        &self,
        active_chirho: &ActiveTenantMigrationChirho,
    ) -> ResidentTenantMigrationTargetActivatedStatusChirho {
        ResidentTenantMigrationTargetActivatedStatusChirho {
            attempt_digest_chirho: active_chirho.attempt_digest_chirho().to_owned(),
            checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho().to_owned(),
            phase_chirho: active_chirho.phase_chirho(),
        }
    }

    fn abort_current_chirho(
        &mut self,
        append_barrier_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    ) -> Result<
        ResidentTenantMigrationOperationOutcomeChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let operation_result_chirho = self
            .store_chirho
            .bind_operation_session_chirho(&self.control_chirho)
            .and_then(|mut session_chirho| session_chirho.abort_current_chirho())
            .map_err(ResidentTenantMigrationOperationRefusalChirho::CoordinatorChirho)
            .map(|aborted_chirho| {
                let status_chirho = ResidentTenantMigrationAbortStatusChirho {
                    attempt_digest_chirho: aborted_chirho
                        .active_chirho
                        .attempt_digest_chirho()
                        .to_owned(),
                    checkpoint_ref_chirho: aborted_chirho
                        .active_chirho
                        .checkpoint_ref_chirho()
                        .to_owned(),
                    released_owned_marker_chirho: aborted_chirho.released_owned_marker_chirho,
                };
                ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(status_chirho)
            });
        self.finish_operation_chirho(operation_result_chirho, append_barrier_chirho)
    }

    fn source_fenced_status_chirho(
        &self,
        active_chirho: &ActiveTenantMigrationChirho,
    ) -> Result<
        ResidentTenantMigrationSourceFenceStatusChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        let observed_chirho = self
            .control_chirho
            .handoff_read_handle_chirho()
            .try_acquire_handoff_read_chirho(active_chirho.attempt_digest_chirho())
            .map_err(|refusal_chirho| {
                ResidentTenantMigrationOperationRefusalChirho::CoordinatorChirho(
                    TenantMigrationCoordinatorRefusalChirho::LocalAuthorityChirho(refusal_chirho),
                )
            })?;
        Ok(ResidentTenantMigrationSourceFenceStatusChirho {
            attempt_digest_chirho: active_chirho.attempt_digest_chirho().to_owned(),
            checkpoint_ref_chirho: active_chirho.checkpoint_ref_chirho().to_owned(),
            phase_chirho: active_chirho.phase_chirho(),
            marker_activation_generation_chirho: observed_chirho
                .handoff_activation_generation_chirho(),
        })
    }

    fn finish_operation_chirho(
        &self,
        operation_result_chirho: Result<
            ResidentTenantMigrationOperationOutcomeChirho,
            ResidentTenantMigrationOperationRefusalChirho,
        >,
        append_barrier_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    ) -> Result<
        ResidentTenantMigrationOperationOutcomeChirho,
        ResidentTenantMigrationOperationRefusalChirho,
    > {
        match operation_result_chirho {
            Ok(outcome_chirho) => {
                append_barrier_chirho.replace_migration_chirho(match &outcome_chirho {
                    ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                        status_chirho,
                    ) => TenantMigrationStartupBarrierChirho::ActiveChirho {
                        attempt_digest_chirho: status_chirho.attempt_digest_chirho.clone(),
                        phase_chirho: status_chirho.phase_chirho,
                    },
                    // Activation changes WHO may write; it never releases the source. The barrier
                    // variant says so in its own name, blocks mutations exactly like the active
                    // one, and is what startup restores after a crash — so a live activation and a
                    // recovered one land the resident runtime in the same state.
                    ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(
                        status_chirho,
                    ) => TenantMigrationStartupBarrierChirho::TargetActivatedSourceRetainedChirho {
                        attempt_digest_chirho: status_chirho.attempt_digest_chirho.clone(),
                    },
                    ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(status_chirho) => {
                        TenantMigrationStartupBarrierChirho::AbortedChirho {
                            attempt_digest_chirho: status_chirho.attempt_digest_chirho.clone(),
                            released_owned_marker_chirho: status_chirho
                                .released_owned_marker_chirho,
                        }
                    }
                });
                Ok(outcome_chirho)
            }
            Err(operation_refusal_chirho) => {
                if let Err(reconciliation_refusal_chirho) =
                    self.reconcile_barrier_chirho(append_barrier_chirho)
                {
                    return Err(
                        ResidentTenantMigrationOperationRefusalChirho::BarrierReconciliationChirho {
                            operation_detail_chirho: operation_refusal_chirho.to_string(),
                            reconciliation_detail_chirho: reconciliation_refusal_chirho.to_string(),
                        },
                    );
                }
                Err(operation_refusal_chirho)
            }
        }
    }

    fn reconcile_barrier_chirho(
        &self,
        append_barrier_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    ) -> Result<(), ResidentTenantMigrationOperationRefusalChirho> {
        let reconciliation_chirho = self
            .store_chirho
            .load_current_chirho()
            .map_err(TenantMigrationCoordinatorRefusalChirho::StoreChirho)
            .and_then(|inspected_chirho| {
                restore_tenant_migration_startup_chirho(
                    &self.store_chirho,
                    &self.control_chirho,
                    inspected_chirho,
                )
            })
            .map_err(ResidentTenantMigrationOperationRefusalChirho::CoordinatorChirho);
        match reconciliation_chirho {
            Ok(migration_chirho) => {
                append_barrier_chirho.replace_migration_chirho(migration_chirho);
                Ok(())
            }
            Err(refusal_chirho) => {
                append_barrier_chirho.fail_closed_migration_operation_chirho();
                Err(refusal_chirho)
            }
        }
    }
}

impl From<LocalAppendAuthorityRefusalChirho> for ResidentTenantMigrationOperationRefusalChirho {
    fn from(refusal_chirho: LocalAppendAuthorityRefusalChirho) -> Self {
        Self::CoordinatorChirho(
            TenantMigrationCoordinatorRefusalChirho::LocalAuthorityChirho(refusal_chirho),
        )
    }
}

/// Test-only destination authority and record fixtures.
///
/// They live in this file, at file level, because it owns both the command and the runtime, and
/// because every other migration test module already reaches this module by name — so the fixtures
/// need no new `mod` line. That matters here: every `mod` in this crate's actor block carries a
/// `#[path]`, and inserting one above another silently steals its path.
#[cfg(test)]
pub(super) struct AcceptingDestinationAuthorityChirho;

#[cfg(test)]
impl TenantMigrationDestinationAuthorityPortChirho for AcceptingDestinationAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        "test-destination-authority-chirho".to_owned()
    }
    fn verify_chirho(&self, _canonical_unsigned_chirho: &str, _sig_chirho: &str) -> bool {
        true
    }
}

/// Build an authorization bound to the REAL binding digests of both roots.
///
/// Deriving it rather than letting a test hand-write a digest is the point: a hand-written value
/// would pass whatever the gate happens to compare and prove nothing about the binding.
#[cfg(test)]
pub(super) fn destination_record_for_roots_chirho(
    source_root_chirho: &Path,
    destination_root_chirho: &Path,
) -> TenantMigrationDestinationRecordChirho {
    let verified_source_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(source_root_chirho)
            .expect("open the source root for a destination fixture");
    let verified_destination_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(destination_root_chirho)
            .expect("open the destination root for a destination fixture");
    destination_record_chirho(
        &verified_source_chirho
            .binding_identity_digest_hex_chirho()
            .expect("derive the source binding digest"),
        &verified_destination_chirho
            .binding_identity_digest_hex_chirho()
            .expect("derive the destination binding digest"),
        verified_source_chirho.tenant_id_chirho(),
    )
}

#[cfg(test)]
pub(super) fn destination_record_chirho(
    source_root_digest_chirho: &str,
    destination_root_digest_chirho: &str,
    tenant_id_chirho: &str,
) -> TenantMigrationDestinationRecordChirho {
    let intent_chirho = TenantMigrationDestinationIntentChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
        digest_domain_chirho: TENANT_MIGRATION_DESTINATION_INTENT_DOMAIN_V1_CHIRHO.to_owned(),
        tenant_id_chirho: tenant_id_chirho.to_owned(),
        source_root_digest_chirho: source_root_digest_chirho.to_owned(),
        destination_root_digest_chirho: destination_root_digest_chirho.to_owned(),
        revision_chirho: 1,
    };
    let intent_digest_chirho = tenant_migration_destination_intent_digest_chirho(&intent_chirho)
        .expect("encode the destination intent");
    TenantMigrationDestinationRecordChirho {
        schema_chirho: TENANT_MIGRATION_DESTINATION_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        signature_domain_chirho: TENANT_MIGRATION_DESTINATION_RECORD_DOMAIN_V1_CHIRHO.to_owned(),
        intent_chirho,
        intent_digest_chirho,
        authority_key_id_chirho: "test-destination-authority-chirho".to_owned(),
        sig_chirho: "test-signature-chirho".to_owned(),
    }
}

/// Structurally valid, bound to a source that exists nowhere. For call sites that must supply the
/// field but are expected to refuse BEFORE the destination gate runs.
#[cfg(test)]
pub(super) fn unusable_destination_record_chirho() -> TenantMigrationDestinationRecordChirho {
    destination_record_chirho(&"0".repeat(64), &"f".repeat(64), "tenant-never-chirho")
}

#[cfg(test)]
#[path = "tenant_migration_operation_tests_chirho.rs"]
mod tests_chirho;
