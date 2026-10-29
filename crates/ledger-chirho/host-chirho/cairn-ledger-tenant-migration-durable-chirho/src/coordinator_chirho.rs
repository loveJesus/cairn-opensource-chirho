// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::model_chirho::{
    ActiveTenantMigrationChirho, TenantMigrationCutClaimChirho,
    TenantMigrationOperationAuthorityBindingChirho, TenantMigrationPhaseChirho,
    TenantMigrationStoreRefusalChirho,
};
use crate::store_chirho::TenantMigrationStoreChirho;
use cairn_ledger_host_storage_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_ledger_tenant_migration_chirho::{
    open_verified_tenant_ledger_prefix_chirho, open_verified_tenant_ledger_tail_chirho,
    RootMoveChirho, TenantLedgerVerificationViewsChirho, TenantMigrationFenceIdentityChirho,
    TenantMigrationRefusalChirho, VerifiedTenantMigrationRootChirho,
};
use cairn_ledger_tenant_migration_local_fence_chirho::{
    LocalTenantMigrationFenceRefusalChirho, LocalTenantMigrationFenceWitnessChirho,
};
use cairn_tenant_chirho::migration_completeness_chirho::PreliminaryMigrationCheckChirho;
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityRefusalChirho, LocalAppendHandoffControlHandleChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::error::Error;
use std::fmt;

/// Startup-only view consumed by the resident append-barrier composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantMigrationStartupBarrierChirho {
    NoneChirho,
    ActiveChirho {
        attempt_digest_chirho: String,
        phase_chirho: TenantMigrationPhaseChirho,
    },
    AbortedChirho {
        attempt_digest_chirho: String,
        released_owned_marker_chirho: bool,
    },
    /// The target is authoritative and this root is the RETAINED source.
    ///
    /// The source keeps its fence rather than releasing it. Aborting releases because the migration
    /// was abandoned and the source legitimately resumes; activation is the opposite fact, so the
    /// source must never resume, and the safe direction is to stay frozen until retirement.
    TargetActivatedSourceRetainedChirho {
        attempt_digest_chirho: String,
    },
}

impl TenantMigrationStartupBarrierChirho {
    pub fn active_attempt_digest_chirho(&self) -> Option<&str> {
        match self {
            Self::ActiveChirho {
                attempt_digest_chirho,
                ..
            } => Some(attempt_digest_chirho),
            Self::TargetActivatedSourceRetainedChirho {
                attempt_digest_chirho,
            } => Some(attempt_digest_chirho),
            Self::NoneChirho | Self::AbortedChirho { .. } => None,
        }
    }

    /// Whether this root may still mutate. Deliberately an EXHAUSTIVE match rather than a predicate
    /// derived from the digest accessor: a future barrier outcome must CHOOSE its answer here
    /// instead of inheriting one from whatever another accessor happens to return.
    pub fn blocks_mutations_chirho(&self) -> bool {
        match self {
            Self::ActiveChirho { .. } | Self::TargetActivatedSourceRetainedChirho { .. } => true,
            Self::NoneChirho | Self::AbortedChirho { .. } => false,
        }
    }

    /// The fixed reason this root is frozen, so a retained source is never reported as a live fence.
    pub fn mutation_freeze_reason_chirho(&self) -> Option<&'static str> {
        match self {
            Self::ActiveChirho { .. } => {
                Some("resident ledger mutation is frozen by an active tenant migration source fence")
            }
            Self::TargetActivatedSourceRetainedChirho { .. } => Some(
                "resident ledger mutation is refused because the migration target is activated and this root is the retained source",
            ),
            Self::NoneChirho | Self::AbortedChirho { .. } => None,
        }
    }
}

#[derive(Debug)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub enum TenantMigrationCoordinatorRefusalChirho {
    StoreChirho(TenantMigrationStoreRefusalChirho),
    LocalAuthorityChirho(LocalAppendAuthorityRefusalChirho),
    MigrationContractChirho(TenantMigrationRefusalChirho),
    FenceAdapterChirho(LocalTenantMigrationFenceRefusalChirho),
    DurableHeadChangedChirho,
    AuthorityBindingMismatchChirho,
    DurableIdentityMismatchChirho,
    DurabilityUnconfirmedChirho,
    UnsupportedReservedPhaseChirho,
    NoActiveAttemptChirho,
}

impl fmt::Display for TenantMigrationCoordinatorRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{self:?}")
    }
}

impl Error for TenantMigrationCoordinatorRefusalChirho {}

impl From<TenantMigrationStoreRefusalChirho> for TenantMigrationCoordinatorRefusalChirho {
    fn from(refusal_chirho: TenantMigrationStoreRefusalChirho) -> Self {
        Self::StoreChirho(refusal_chirho)
    }
}

impl From<LocalAppendAuthorityRefusalChirho> for TenantMigrationCoordinatorRefusalChirho {
    fn from(refusal_chirho: LocalAppendAuthorityRefusalChirho) -> Self {
        Self::LocalAuthorityChirho(refusal_chirho)
    }
}

impl From<TenantMigrationRefusalChirho> for TenantMigrationCoordinatorRefusalChirho {
    fn from(refusal_chirho: TenantMigrationRefusalChirho) -> Self {
        Self::MigrationContractChirho(refusal_chirho)
    }
}

impl From<LocalTenantMigrationFenceRefusalChirho> for TenantMigrationCoordinatorRefusalChirho {
    fn from(refusal_chirho: LocalTenantMigrationFenceRefusalChirho) -> Self {
        Self::FenceAdapterChirho(refusal_chirho)
    }
}

/// Restore or retire the already inspected exact migration head before resident exposure.
///
/// The caller inspects GD7 and migration heads together before calling this function. We reload the
/// migration head and require byte-equivalent state so passing `None` cannot suppress a durable
/// owner. Active phases claim their own marker before re-fsyncing the head (fail toward freeze).
/// Aborted phases confirm first, discover ownership read-only, and release only the exact observed
/// activation lifetime; they never claim a marker merely to discover who owns it.
pub fn restore_tenant_migration_startup_chirho(
    store_chirho: &TenantMigrationStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    inspected_chirho: Option<ActiveTenantMigrationChirho>,
) -> Result<TenantMigrationStartupBarrierChirho, TenantMigrationCoordinatorRefusalChirho> {
    require_authority_binding_chirho(store_chirho, control_chirho)?;
    if store_chirho.load_current_chirho()? != inspected_chirho {
        return Err(TenantMigrationCoordinatorRefusalChirho::DurableHeadChangedChirho);
    }
    let Some(active_chirho) = inspected_chirho else {
        return Ok(TenantMigrationStartupBarrierChirho::NoneChirho);
    };
    match active_chirho.phase_chirho() {
        TenantMigrationPhaseChirho::PreparingChirho
        | TenantMigrationPhaseChirho::SourceFencedChirho => {
            // ACTIVE durable owners fail toward more freeze: restore before a potentially ambiguous
            // fixed-head fsync, and never expose the resident if either operation refuses.
            control_chirho.restore_handoff_chirho(active_chirho.attempt_digest_chirho())?;
            require_durable_confirmation_chirho(store_chirho, &active_chirho)?;
            control_chirho
                .handoff_read_handle_chirho()
                .try_acquire_handoff_read_chirho(active_chirho.attempt_digest_chirho())?;
            Ok(TenantMigrationStartupBarrierChirho::ActiveChirho {
                attempt_digest_chirho: active_chirho.attempt_digest_chirho().to_owned(),
                phase_chirho: active_chirho.phase_chirho(),
            })
        }
        TenantMigrationPhaseChirho::AbortedChirho => {
            require_durable_confirmation_chirho(store_chirho, &active_chirho)?;
            let released_owned_marker_chirho = control_chirho
                .release_if_observed_owner_chirho(active_chirho.attempt_digest_chirho())?;
            Ok(TenantMigrationStartupBarrierChirho::AbortedChirho {
                attempt_digest_chirho: active_chirho.attempt_digest_chirho().to_owned(),
                released_owned_marker_chirho,
            })
        }
        TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho => {
            // Same fail-toward-freeze order as the active arm, for the same reason: restore the
            // handoff BEFORE confirming, so a refusal anywhere leaves the source frozen rather than
            // briefly writable. Activation makes that permanent rather than temporary.
            control_chirho.restore_handoff_chirho(active_chirho.attempt_digest_chirho())?;
            require_durable_confirmation_chirho(store_chirho, &active_chirho)?;
            control_chirho
                .handoff_read_handle_chirho()
                .try_acquire_handoff_read_chirho(active_chirho.attempt_digest_chirho())?;
            Ok(
                TenantMigrationStartupBarrierChirho::TargetActivatedSourceRetainedChirho {
                    attempt_digest_chirho: active_chirho.attempt_digest_chirho().to_owned(),
                },
            )
        }
    }
}

/// Opaque custody held only inside one store-and-controller-bound operation session.
struct TenantMigrationOperationCustodyChirho {
    _sealed_chirho: (),
}

/// Scoped capability for beginning, recovering, or aborting one durable source fence.
///
/// The session exposes neither the migration store nor the handoff controller. It exclusively
/// borrows the exact store and carries only the already-attenuated marker-control surface. The
/// resident actor's serialized mailbox excludes competing operation calls; the borrow alone does
/// not claim to revoke pre-existing aliases of the cloneable control handle.
pub struct TenantMigrationOperationSessionChirho<'session_chirho, 'ports_chirho> {
    custody_chirho: TenantMigrationOperationCustodyChirho,
    store_chirho: &'session_chirho mut TenantMigrationStoreChirho<'ports_chirho>,
    control_chirho: &'session_chirho LocalAppendHandoffControlHandleChirho,
}

impl<'ports_chirho> TenantMigrationStoreChirho<'ports_chirho> {
    pub fn bind_operation_session_chirho<'session_chirho>(
        &'session_chirho mut self,
        control_chirho: &'session_chirho LocalAppendHandoffControlHandleChirho,
    ) -> Result<
        TenantMigrationOperationSessionChirho<'session_chirho, 'ports_chirho>,
        TenantMigrationCoordinatorRefusalChirho,
    > {
        require_authority_binding_chirho(self, control_chirho)?;
        Ok(TenantMigrationOperationSessionChirho {
            custody_chirho: TenantMigrationOperationCustodyChirho { _sealed_chirho: () },
            store_chirho: self,
            control_chirho,
        })
    }
}

impl TenantMigrationOperationSessionChirho<'_, '_> {
    pub fn begin_source_fenced_chirho(
        &mut self,
        inputs_chirho: TenantMigrationOperationInputsChirho<'_>,
    ) -> Result<PreparedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
        begin_source_fenced_inner_chirho(
            &mut self.custody_chirho,
            self.store_chirho,
            self.control_chirho,
            inputs_chirho,
        )
    }

    pub fn recover_source_fenced_chirho(
        &mut self,
        inputs_chirho: TenantMigrationOperationInputsChirho<'_>,
    ) -> Result<PreparedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
        recover_source_fenced_inner_chirho(
            &mut self.custody_chirho,
            self.store_chirho,
            self.control_chirho,
            inputs_chirho,
        )
    }

    /// Activate the target for the exact current signed head selected inside this scoped session.
    ///
    /// Takes the `RootMoveChirho` that begin or recovery produced, because the source-fence WITNESS
    /// is an in-memory verified value that is deliberately never persisted. After a restart the
    /// caller must re-establish it through recovery first; there is no path that resurrects a
    /// witness from disk, and that is the point.
    pub fn activate_target_chirho(
        &mut self,
        move_chirho: RootMoveChirho,
        inputs_chirho: TenantMigrationActivationInputsChirho<'_>,
    ) -> Result<ActivatedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
        activate_target_inner_chirho(
            &mut self.custody_chirho,
            self.store_chirho,
            self.control_chirho,
            move_chirho,
            inputs_chirho,
        )
    }

    /// Abort only the exact current signed head selected inside this scoped session.
    pub fn abort_current_chirho(
        &mut self,
    ) -> Result<AbortedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
        let active_chirho = self
            .store_chirho
            .load_current_chirho()?
            .ok_or(TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho)?;
        abort_current_inner_chirho(
            &mut self.custody_chirho,
            self.store_chirho,
            self.control_chirho,
            active_chirho.attempt_digest_chirho(),
            active_chirho.checkpoint_ref_chirho(),
        )
    }
}

/// Verified inputs assembled only while opaque operation custody is held.
pub struct TenantMigrationOperationInputsChirho<'inputs_chirho> {
    source_root_chirho: VerifiedTenantMigrationRootChirho,
    target_root_chirho: VerifiedTenantMigrationRootChirho,
    preliminary_check_chirho: PreliminaryMigrationCheckChirho,
    source_storage_chirho: &'inputs_chirho FsLedgerStorageChirho,
    source_views_chirho: TenantLedgerVerificationViewsChirho<'inputs_chirho>,
    journal_path_chirho: &'inputs_chirho StoragePathChirho,
    expected_cluster_chirho: &'inputs_chirho ClusterIdChirho,
    operation_authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
}

impl<'inputs_chirho> TenantMigrationOperationInputsChirho<'inputs_chirho> {
    #[allow(
        clippy::too_many_arguments,
        reason = "one fixed source verification bundle"
    )]
    pub fn new_chirho(
        source_root_chirho: VerifiedTenantMigrationRootChirho,
        target_root_chirho: VerifiedTenantMigrationRootChirho,
        preliminary_check_chirho: PreliminaryMigrationCheckChirho,
        source_storage_chirho: &'inputs_chirho FsLedgerStorageChirho,
        source_views_chirho: TenantLedgerVerificationViewsChirho<'inputs_chirho>,
        journal_path_chirho: &'inputs_chirho StoragePathChirho,
        expected_cluster_chirho: &'inputs_chirho ClusterIdChirho,
        operation_authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
    ) -> Self {
        Self {
            source_root_chirho,
            target_root_chirho,
            preliminary_check_chirho,
            source_storage_chirho,
            source_views_chirho,
            journal_path_chirho,
            expected_cluster_chirho,
            operation_authority_chirho,
        }
    }
}

pub struct PreparedTenantMigrationChirho {
    pub move_chirho: RootMoveChirho,
    pub active_chirho: ActiveTenantMigrationChirho,
}

/// Everything needed to verify the TARGET root fresh, at the exact cut the source fenced at.
pub struct TenantMigrationActivationInputsChirho<'inputs_chirho> {
    target_root_chirho: VerifiedTenantMigrationRootChirho,
    target_storage_chirho: &'inputs_chirho FsLedgerStorageChirho,
    target_views_chirho: TenantLedgerVerificationViewsChirho<'inputs_chirho>,
    journal_path_chirho: &'inputs_chirho StoragePathChirho,
    expected_cluster_chirho: &'inputs_chirho ClusterIdChirho,
}

impl<'inputs_chirho> TenantMigrationActivationInputsChirho<'inputs_chirho> {
    pub fn new_chirho(
        target_root_chirho: VerifiedTenantMigrationRootChirho,
        target_storage_chirho: &'inputs_chirho FsLedgerStorageChirho,
        target_views_chirho: TenantLedgerVerificationViewsChirho<'inputs_chirho>,
        journal_path_chirho: &'inputs_chirho StoragePathChirho,
        expected_cluster_chirho: &'inputs_chirho ClusterIdChirho,
    ) -> Self {
        Self {
            target_root_chirho,
            target_storage_chirho,
            target_views_chirho,
            journal_path_chirho,
            expected_cluster_chirho,
        }
    }
}

pub struct ActivatedTenantMigrationChirho {
    pub move_chirho: RootMoveChirho,
    pub active_chirho: ActiveTenantMigrationChirho,
}

pub struct AbortedTenantMigrationChirho {
    pub active_chirho: ActiveTenantMigrationChirho,
    pub released_owned_marker_chirho: bool,
}

/// Begin through `SourceFencedChirho` with durable-before-marker ordering.
fn begin_source_fenced_inner_chirho(
    _custody_chirho: &mut TenantMigrationOperationCustodyChirho,
    store_chirho: &TenantMigrationStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    inputs_chirho: TenantMigrationOperationInputsChirho<'_>,
) -> Result<PreparedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
    require_authority_binding_chirho(store_chirho, control_chirho)?;
    let preliminary_source_cut_chirho = open_verified_tenant_ledger_tail_chirho(
        inputs_chirho.source_root_chirho.clone(),
        inputs_chirho.source_storage_chirho,
        inputs_chirho.source_views_chirho,
        inputs_chirho.journal_path_chirho,
        inputs_chirho.expected_cluster_chirho,
    )?;
    let preliminary_claim_chirho = TenantMigrationCutClaimChirho::from_verified_chirho(
        preliminary_source_cut_chirho.cut_chirho(),
    );
    let mut move_chirho = RootMoveChirho::new_with_operation_authority_binding_chirho(
        inputs_chirho.source_root_chirho.clone(),
        inputs_chirho.target_root_chirho,
        inputs_chirho
            .operation_authority_chirho
            .binding_digest_chirho()
            .to_owned(),
    )?;
    move_chirho.begin_preparing_chirho()?;
    move_chirho.record_preliminary_target_check_chirho(inputs_chirho.preliminary_check_chirho)?;
    let attempt_chirho =
        move_chirho.prepare_source_append_fence_attempt_chirho(preliminary_source_cut_chirho)?;
    let preparation_chirho =
        control_chirho.try_prepare_handoff_chirho(attempt_chirho.digest_chirho())?;
    let preparing_outcome_chirho = store_chirho.commit_preparing_chirho(
        attempt_chirho.tenant_id_chirho().to_owned(),
        inputs_chirho.expected_cluster_chirho.0.clone(),
        inputs_chirho.journal_path_chirho.key_chirho().to_owned(),
        attempt_chirho.digest_chirho().to_owned(),
        preliminary_claim_chirho,
        inputs_chirho.operation_authority_chirho,
    )?;
    let (preparing_committed_chirho, preparing_durable_chirho) =
        preparing_outcome_chirho.into_parts_chirho();
    // Even an ambiguous fixed-head write must not coexist with source appends. Activating while the
    // preparation mutex is still held makes the uncertain outcome fail toward more freeze.
    let active_guard_chirho = preparation_chirho.activate_chirho();
    drop(active_guard_chirho);
    if !preparing_durable_chirho {
        return Err(TenantMigrationCoordinatorRefusalChirho::DurabilityUnconfirmedChirho);
    }
    finish_source_fence_chirho(
        store_chirho,
        control_chirho,
        inputs_chirho.source_root_chirho,
        inputs_chirho.source_storage_chirho,
        inputs_chirho.source_views_chirho,
        inputs_chirho.journal_path_chirho,
        inputs_chirho.expected_cluster_chirho,
        move_chirho,
        attempt_chirho,
        preparing_committed_chirho.active_chirho,
    )
}

/// Activate the target: verify it FRESH at the source's fenced cut, then commit the one transition.
///
/// The persisted `post_fence_source_cut_chirho` is a coordinate and never authority — its own type
/// says so. This rebuilds a prefix REQUEST from it and re-verifies the target against that request,
/// so nothing that reaches the migration contract came from disk as an already-verified claim.
///
/// Ordering is fail-toward-freeze, like every sibling: the durable transition is committed only
/// after the contract has accepted activation, so a refusal anywhere leaves the source fenced
/// rather than half-moved. The source is NOT released here — activation changes who may write, and
/// retiring the source is a separate later step.
fn activate_target_inner_chirho(
    _custody_chirho: &mut TenantMigrationOperationCustodyChirho,
    store_chirho: &TenantMigrationStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    mut move_chirho: RootMoveChirho,
    inputs_chirho: TenantMigrationActivationInputsChirho<'_>,
) -> Result<ActivatedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
    require_authority_binding_chirho(store_chirho, control_chirho)?;
    // Select the exact signed head here. The caller names no attempt and no checkpoint ref, so it
    // cannot steer activation onto a state of its choosing.
    let active_chirho = store_chirho
        .load_current_chirho()?
        .ok_or(TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho)?;
    if active_chirho.phase_chirho() != TenantMigrationPhaseChirho::SourceFencedChirho {
        // EXHAUSTIVE, and each phase gets the answer that is TRUE of it. An earlier version used a
        // catch-all that told a caller activating from `PreparingChirho` there was "no active
        // attempt" — there IS one, it is simply not fenced yet, and that is a different fact. A
        // catch-all here would also have swallowed any phase added later.
        return Err(match active_chirho.phase_chirho() {
            TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho => {
                TenantMigrationCoordinatorRefusalChirho::UnsupportedReservedPhaseChirho
            }
            // Preparing means the source is not provably frozen yet. Activating there could leave
            // two writers, so it is an illegal TRANSITION rather than a missing attempt.
            TenantMigrationPhaseChirho::PreparingChirho => {
                TenantMigrationCoordinatorRefusalChirho::StoreChirho(
                    TenantMigrationStoreRefusalChirho::InvalidTransitionChirho,
                )
            }
            TenantMigrationPhaseChirho::AbortedChirho => {
                TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho
            }
            TenantMigrationPhaseChirho::SourceFencedChirho => unreachable!(
                "the enclosing condition already established this phase is not source-fenced"
            ),
        });
    }
    // A fenced checkpoint that recorded no post-fence cut is malformed: there is no coordinate to
    // verify the target against, and inventing one would be the worst possible response.
    let post_fence_request_chirho = active_chirho
        .checkpoint_chirho
        .post_fence_source_cut_chirho
        .as_ref()
        .ok_or(TenantMigrationCoordinatorRefusalChirho::StoreChirho(
            TenantMigrationStoreRefusalChirho::MalformedCheckpointChirho,
        ))?
        .request_chirho();
    let target_cut_chirho = open_verified_tenant_ledger_prefix_chirho(
        inputs_chirho.target_root_chirho,
        inputs_chirho.target_storage_chirho,
        inputs_chirho.target_views_chirho,
        inputs_chirho.journal_path_chirho,
        inputs_chirho.expected_cluster_chirho,
        &post_fence_request_chirho,
    )?;
    // The contract re-checks that this cut binds to the SAME content the source fenced at, and only
    // then issues the warrant. Activation consumes that warrant rather than the caller's word.
    let warrant_chirho = move_chirho.record_post_fence_target_verified_chirho(target_cut_chirho)?;
    move_chirho.activate_target_chirho(&warrant_chirho)?;
    let activated_chirho = store_chirho.commit_target_activated_chirho(
        active_chirho.attempt_digest_chirho(),
        active_chirho.checkpoint_ref_chirho(),
        warrant_chirho.fence_identity_digest_chirho(),
    )?;
    let (committed_chirho, durable_chirho) = activated_chirho.into_parts_chirho();
    if !durable_chirho {
        return Err(TenantMigrationCoordinatorRefusalChirho::DurabilityUnconfirmedChirho);
    }
    Ok(ActivatedTenantMigrationChirho {
        move_chirho,
        active_chirho: committed_chirho.active_chirho,
    })
}

/// Resume an active durable attempt after a crash without trusting its persisted cut claims.
fn recover_source_fenced_inner_chirho(
    _custody_chirho: &mut TenantMigrationOperationCustodyChirho,
    store_chirho: &TenantMigrationStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    inputs_chirho: TenantMigrationOperationInputsChirho<'_>,
) -> Result<PreparedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
    require_authority_binding_chirho(store_chirho, control_chirho)?;
    let active_chirho = store_chirho
        .load_current_chirho()?
        .ok_or(TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho)?;
    if !active_chirho.phase_chirho().is_active_source_fence_chirho() {
        return Err(match active_chirho.phase_chirho() {
            TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho => {
                TenantMigrationCoordinatorRefusalChirho::UnsupportedReservedPhaseChirho
            }
            TenantMigrationPhaseChirho::AbortedChirho => {
                TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho
            }
            TenantMigrationPhaseChirho::PreparingChirho
            | TenantMigrationPhaseChirho::SourceFencedChirho => unreachable!(),
        });
    }
    control_chirho.restore_handoff_chirho(active_chirho.attempt_digest_chirho())?;
    require_durable_confirmation_chirho(store_chirho, &active_chirho)?;
    let checkpoint_chirho = active_chirho.checkpoint_chirho();
    if checkpoint_chirho.tenant_id_chirho != inputs_chirho.source_root_chirho.tenant_id_chirho()
        || checkpoint_chirho.cluster_id_chirho != inputs_chirho.expected_cluster_chirho.0
        || checkpoint_chirho.journal_path_chirho != inputs_chirho.journal_path_chirho.key_chirho()
        || checkpoint_chirho.operation_authority_chirho != inputs_chirho.operation_authority_chirho
    {
        return Err(TenantMigrationCoordinatorRefusalChirho::DurableIdentityMismatchChirho);
    }
    let preliminary_source_cut_chirho = open_verified_tenant_ledger_prefix_chirho(
        inputs_chirho.source_root_chirho.clone(),
        inputs_chirho.source_storage_chirho,
        inputs_chirho.source_views_chirho,
        inputs_chirho.journal_path_chirho,
        inputs_chirho.expected_cluster_chirho,
        &checkpoint_chirho
            .preliminary_source_cut_chirho
            .request_chirho(),
    )?;
    let mut move_chirho = RootMoveChirho::new_with_operation_authority_binding_chirho(
        inputs_chirho.source_root_chirho.clone(),
        inputs_chirho.target_root_chirho,
        inputs_chirho
            .operation_authority_chirho
            .binding_digest_chirho()
            .to_owned(),
    )?;
    move_chirho.begin_preparing_chirho()?;
    move_chirho.record_preliminary_target_check_chirho(inputs_chirho.preliminary_check_chirho)?;
    let attempt_chirho =
        move_chirho.prepare_source_append_fence_attempt_chirho(preliminary_source_cut_chirho)?;
    if attempt_chirho.digest_chirho() != active_chirho.attempt_digest_chirho() {
        return Err(TenantMigrationCoordinatorRefusalChirho::DurableIdentityMismatchChirho);
    }
    finish_source_fence_chirho(
        store_chirho,
        control_chirho,
        inputs_chirho.source_root_chirho,
        inputs_chirho.source_storage_chirho,
        inputs_chirho.source_views_chirho,
        inputs_chirho.journal_path_chirho,
        inputs_chirho.expected_cluster_chirho,
        move_chirho,
        attempt_chirho,
        active_chirho,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one fixed post-fence verification boundary"
)]
fn finish_source_fence_chirho(
    store_chirho: &TenantMigrationStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    source_root_chirho: VerifiedTenantMigrationRootChirho,
    source_storage_chirho: &FsLedgerStorageChirho,
    source_views_chirho: TenantLedgerVerificationViewsChirho<'_>,
    journal_path_chirho: &StoragePathChirho,
    expected_cluster_chirho: &ClusterIdChirho,
    mut move_chirho: RootMoveChirho,
    attempt_chirho: cairn_ledger_tenant_migration_chirho::TenantMigrationAttemptIdentityChirho,
    active_chirho: ActiveTenantMigrationChirho,
) -> Result<PreparedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
    let post_fence_source_cut_chirho = open_verified_tenant_ledger_tail_chirho(
        source_root_chirho,
        source_storage_chirho,
        source_views_chirho,
        journal_path_chirho,
        expected_cluster_chirho,
    )?;
    let post_fence_claim_chirho = TenantMigrationCutClaimChirho::from_verified_chirho(
        post_fence_source_cut_chirho.cut_chirho(),
    );
    if let Some(expected_post_fence_chirho) = active_chirho
        .checkpoint_chirho()
        .post_fence_source_cut_chirho
        .as_ref()
    {
        if expected_post_fence_chirho != &post_fence_claim_chirho {
            return Err(TenantMigrationCoordinatorRefusalChirho::DurableIdentityMismatchChirho);
        }
    }
    let fence_identity_chirho =
        TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
            attempt_chirho,
            post_fence_source_cut_chirho,
        )?;
    if active_chirho
        .checkpoint_chirho()
        .fence_identity_digest_chirho
        .as_deref()
        .is_some_and(|expected_chirho| expected_chirho != fence_identity_chirho.digest_chirho())
    {
        return Err(TenantMigrationCoordinatorRefusalChirho::DurableIdentityMismatchChirho);
    }
    let witness_chirho = LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
        fence_identity_chirho.clone(),
        control_chirho.handoff_read_handle_chirho(),
    )?;
    move_chirho.record_source_append_fence_chirho(witness_chirho)?;
    let source_fenced_chirho =
        if active_chirho.phase_chirho() == TenantMigrationPhaseChirho::SourceFencedChirho {
            require_durable_confirmation_chirho(store_chirho, &active_chirho)?;
            active_chirho
        } else {
            let outcome_chirho = store_chirho.commit_source_fenced_chirho(
                active_chirho.attempt_digest_chirho(),
                active_chirho.checkpoint_ref_chirho(),
                post_fence_claim_chirho,
                fence_identity_chirho.digest_chirho().to_owned(),
            )?;
            let (committed_chirho, durable_chirho) = outcome_chirho.into_parts_chirho();
            if !durable_chirho {
                return Err(TenantMigrationCoordinatorRefusalChirho::DurabilityUnconfirmedChirho);
            }
            committed_chirho.active_chirho
        };
    Ok(PreparedTenantMigrationChirho {
        move_chirho,
        active_chirho: source_fenced_chirho,
    })
}

fn abort_current_inner_chirho(
    _custody_chirho: &mut TenantMigrationOperationCustodyChirho,
    store_chirho: &TenantMigrationStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    attempt_digest_chirho: &str,
    expected_prior_ref_chirho: &str,
) -> Result<AbortedTenantMigrationChirho, TenantMigrationCoordinatorRefusalChirho> {
    require_authority_binding_chirho(store_chirho, control_chirho)?;
    let outcome_chirho =
        store_chirho.commit_aborted_chirho(attempt_digest_chirho, expected_prior_ref_chirho)?;
    let (committed_chirho, durable_chirho) = outcome_chirho.into_parts_chirho();
    if !durable_chirho {
        return Err(TenantMigrationCoordinatorRefusalChirho::DurabilityUnconfirmedChirho);
    }
    let released_owned_marker_chirho =
        control_chirho.release_if_observed_owner_chirho(attempt_digest_chirho)?;
    Ok(AbortedTenantMigrationChirho {
        active_chirho: committed_chirho.active_chirho,
        released_owned_marker_chirho,
    })
}

fn require_authority_binding_chirho(
    store_chirho: &TenantMigrationStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
) -> Result<(), TenantMigrationCoordinatorRefusalChirho> {
    let group_digest_chirho =
        consistency_group_digest_chirho(control_chirho.consistency_group_chirho()).map_err(
            |_error_chirho| TenantMigrationCoordinatorRefusalChirho::AuthorityBindingMismatchChirho,
        )?;
    if group_digest_chirho != store_chirho.consistency_group_digest_chirho()
        || control_chirho.node_id_chirho().0 != store_chirho.source_node_chirho()
        || !matches!(
            control_chirho.consistency_group_chirho(),
            ConsistencyGroupIdChirho::TenantChirho { .. }
        )
    {
        return Err(TenantMigrationCoordinatorRefusalChirho::AuthorityBindingMismatchChirho);
    }
    Ok(())
}

fn require_durable_confirmation_chirho(
    store_chirho: &TenantMigrationStoreChirho<'_>,
    active_chirho: &ActiveTenantMigrationChirho,
) -> Result<(), TenantMigrationCoordinatorRefusalChirho> {
    let (_committed_chirho, durable_chirho) = store_chirho
        .confirm_active_chirho(active_chirho)?
        .into_parts_chirho();
    if durable_chirho {
        Ok(())
    } else {
        Err(TenantMigrationCoordinatorRefusalChirho::DurabilityUnconfirmedChirho)
    }
}
