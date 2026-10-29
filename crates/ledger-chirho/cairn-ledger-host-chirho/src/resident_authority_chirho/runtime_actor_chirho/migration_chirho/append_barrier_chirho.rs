// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! One resident read/mutation barrier over the shared GD7 and tenant-migration marker slot.

use super::winner_handoff_chirho::{
    ResidentGd7WinnerHandoffRefusalChirho, ResidentGd7WinnerHandoffRuntimeChirho,
};
use super::{
    ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityReadinessChirho,
    ResidentLedgerAuthorityRefusalChirho,
};
use crate::reconciliation_chirho::{
    ActiveGd7WinnerHandoffChirho, Gd7WinnerHandoffPhaseChirho, Gd7WinnerHandoffStoreChirho,
};
use cairn_ledger_tenant_migration_durable_chirho::{
    restore_tenant_migration_startup_chirho, ActiveTenantMigrationChirho,
    TenantMigrationCoordinatorRefusalChirho, TenantMigrationPhaseChirho,
    TenantMigrationStartupBarrierChirho, TenantMigrationStoreChirho,
};
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityHandleChirho, LocalAppendAuthorityRefusalChirho,
    LocalAppendHandoffControlHandleChirho, LocalAppendHandoffReadGenerationChirho,
};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants carry the Chirho suffix"
)]
pub(super) enum ResidentAppendBarrierRefusalChirho {
    Gd7Chirho(ResidentGd7WinnerHandoffRefusalChirho),
    MigrationChirho(TenantMigrationCoordinatorRefusalChirho),
    TwoActiveDurableOwnersChirho,
    Gd7RecoveryOwnerActiveChirho,
    MigrationRecoveryOwnerActiveChirho,
    LocalRecoverySlotChirho(LocalAppendAuthorityRefusalChirho),
    ReservedMigrationPhaseChirho,
    ReadinessChirho(ResidentLedgerAuthorityRefusalChirho),
}

impl fmt::Display for ResidentAppendBarrierRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gd7Chirho(refusal_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 append barrier refused: {refusal_chirho}"
                )
            }
            Self::MigrationChirho(refusal_chirho) => write!(
                formatter_chirho,
                "tenant migration append barrier refused: {refusal_chirho}"
            ),
            Self::TwoActiveDurableOwnersChirho => formatter_chirho
                .write_str("GD7 and tenant migration both claim the resident append barrier"),
            Self::Gd7RecoveryOwnerActiveChirho => {
                formatter_chirho.write_str("active GD7 owner blocks F1 recovery adoption")
            }
            Self::MigrationRecoveryOwnerActiveChirho => formatter_chirho
                .write_str("active tenant migration owner blocks F1 recovery adoption"),
            Self::LocalRecoverySlotChirho(refusal_chirho) => write!(
                formatter_chirho,
                "local append handoff slot blocks F1 recovery adoption: {refusal_chirho}"
            ),
            Self::ReservedMigrationPhaseChirho => formatter_chirho
                .write_str("tenant migration target-activation phase is reserved and unsupported"),
            Self::ReadinessChirho(refusal_chirho) => {
                write!(
                    formatter_chirho,
                    "resident readiness refused: {refusal_chirho}"
                )
            }
        }
    }
}

impl Error for ResidentAppendBarrierRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Gd7Chirho(refusal_chirho) => Some(refusal_chirho),
            Self::MigrationChirho(refusal_chirho) => Some(refusal_chirho),
            Self::ReadinessChirho(refusal_chirho) => Some(refusal_chirho),
            Self::LocalRecoverySlotChirho(refusal_chirho) => Some(refusal_chirho),
            Self::TwoActiveDurableOwnersChirho
            | Self::Gd7RecoveryOwnerActiveChirho
            | Self::MigrationRecoveryOwnerActiveChirho
            | Self::ReservedMigrationPhaseChirho => None,
        }
    }
}

struct InspectedResidentAppendOwnersChirho {
    gd7_chirho: Option<ActiveGd7WinnerHandoffChirho>,
    migration_chirho: Option<ActiveTenantMigrationChirho>,
}

/// Require both durable owner stores to be readable and terminal or absent, release only a
/// terminal head's exact observed marker, then prove the shared in-memory slot is empty.
///
/// Recovery calls this before writing its first inert staging byte. An unreadable store, active
/// durable owner, foreign marker, or internally inconsistent marker lifetime all refuse closed.
pub(super) fn require_recovery_adoption_slot_chirho(
    gd7_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    migration_store_chirho: Option<&TenantMigrationStoreChirho<'_>>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
) -> Result<(), ResidentAppendBarrierRefusalChirho> {
    let inspected_chirho = inspect_durable_owners_chirho(gd7_store_chirho, migration_store_chirho)?;
    if gd7_is_active_chirho(inspected_chirho.gd7_chirho.as_ref()) {
        return Err(ResidentAppendBarrierRefusalChirho::Gd7RecoveryOwnerActiveChirho);
    }
    if migration_is_active_chirho(inspected_chirho.migration_chirho.as_ref()) {
        return Err(ResidentAppendBarrierRefusalChirho::MigrationRecoveryOwnerActiveChirho);
    }
    if let Some(gd7_chirho) = &inspected_chirho.gd7_chirho {
        control_chirho
            .release_if_observed_owner_chirho(&gd7_chirho.attempt_digest_chirho)
            .map_err(ResidentAppendBarrierRefusalChirho::LocalRecoverySlotChirho)?;
    }
    if let Some(migration_chirho) = &inspected_chirho.migration_chirho {
        control_chirho
            .release_if_observed_owner_chirho(migration_chirho.attempt_digest_chirho())
            .map_err(ResidentAppendBarrierRefusalChirho::LocalRecoverySlotChirho)?;
    }
    control_chirho
        .handoff_read_handle_chirho()
        .require_no_active_handoff_chirho()
        .map_err(ResidentAppendBarrierRefusalChirho::LocalRecoverySlotChirho)
}

/// Runtime owner of the only marker-aware read and mutation decision in the resident actor.
pub(super) struct ResidentAppendBarrierRuntimeChirho {
    gd7_chirho: ResidentGd7WinnerHandoffRuntimeChirho,
    migration_chirho: TenantMigrationStartupBarrierChirho,
    migration_operation_fault_chirho: bool,
}

impl ResidentAppendBarrierRuntimeChirho {
    /// Inspect both signed heads before any marker action, then restore only the sole active owner.
    pub(super) fn restore_chirho(
        gd7_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
        migration_store_chirho: Option<&TenantMigrationStoreChirho<'_>>,
        control_chirho: &LocalAppendHandoffControlHandleChirho,
        resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
        local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    ) -> Result<(Self, ResidentLedgerAuthorityReadinessChirho), ResidentAppendBarrierRefusalChirho>
    {
        let inspected_chirho =
            inspect_durable_owners_chirho(gd7_store_chirho, migration_store_chirho)?;
        let inspected_gd7_chirho = inspected_chirho.gd7_chirho;
        let inspected_migration_chirho = inspected_chirho.migration_chirho;
        let gd7_active_chirho = gd7_is_active_chirho(inspected_gd7_chirho.as_ref());
        let migration_active_chirho =
            migration_is_active_chirho(inspected_migration_chirho.as_ref());

        let (gd7_chirho, migration_chirho) = if gd7_active_chirho {
            let gd7_chirho = restore_gd7_chirho(
                gd7_store_chirho,
                control_chirho,
                resident_chirho,
                inspected_gd7_chirho,
            )?;
            let migration_chirho = restore_migration_chirho(
                migration_store_chirho,
                control_chirho,
                inspected_migration_chirho,
            )?;
            (gd7_chirho, migration_chirho)
        } else if migration_active_chirho {
            let migration_chirho = restore_migration_chirho(
                migration_store_chirho,
                control_chirho,
                inspected_migration_chirho,
            )?;
            let gd7_chirho = restore_gd7_chirho(
                gd7_store_chirho,
                control_chirho,
                resident_chirho,
                inspected_gd7_chirho,
            )?;
            (gd7_chirho, migration_chirho)
        } else {
            let gd7_chirho = restore_gd7_chirho(
                gd7_store_chirho,
                control_chirho,
                resident_chirho,
                inspected_gd7_chirho,
            )?;
            let migration_chirho = restore_migration_chirho(
                migration_store_chirho,
                control_chirho,
                inspected_migration_chirho,
            )?;
            (gd7_chirho, migration_chirho)
        };
        let runtime_chirho = Self {
            gd7_chirho,
            migration_chirho,
            migration_operation_fault_chirho: false,
        };
        let readiness_chirho = runtime_chirho
            .probe_resident_chirho(resident_chirho, local_authority_chirho)
            .map_err(ResidentAppendBarrierRefusalChirho::ReadinessChirho)?;
        Ok((runtime_chirho, readiness_chirho))
    }

    pub(super) fn mutation_refusal_detail_chirho(&self) -> Option<&'static str> {
        if self.migration_operation_fault_chirho {
            Some("resident ledger mutation is frozen by an unreconciled tenant migration operation")
        } else if let Some(reason_chirho) = self.migration_chirho.mutation_freeze_reason_chirho() {
            // The barrier names its own reason so an ACTIVATED migration's retained source is not
            // reported as a live source fence. Both freeze; they are not the same fact, and a
            // reader of the refusal should not have to guess which one they are looking at.
            Some(reason_chirho)
        } else if self.gd7_chirho.blocks_mutations_chirho() {
            Some("resident ledger mutation is frozen by an active GD7 winner handoff")
        } else {
            None
        }
    }

    pub(super) fn migration_blocks_mutations_chirho(&self) -> bool {
        self.migration_operation_fault_chirho || self.migration_chirho.blocks_mutations_chirho()
    }

    pub(super) fn any_owner_blocks_mutations_chirho(&self) -> bool {
        self.migration_blocks_mutations_chirho() || self.gd7_chirho.blocks_mutations_chirho()
    }

    pub(super) fn replace_migration_chirho(
        &mut self,
        migration_chirho: TenantMigrationStartupBarrierChirho,
    ) {
        self.migration_chirho = migration_chirho;
        self.migration_operation_fault_chirho = false;
    }

    /// Preserve the high-level freeze when an operation cannot reconcile its durable head and
    /// low-level marker. The actor may still recover or abort through the migration command lane,
    /// but no resident or provider mutation is admitted from this state.
    pub(super) fn fail_closed_migration_operation_chirho(&mut self) {
        self.migration_operation_fault_chirho = true;
    }

    pub(super) fn accepted_gd7_attempt_digest_chirho(&self) -> Option<&str> {
        (!self.migration_blocks_mutations_chirho())
            .then(|| self.gd7_chirho.accepted_attempt_digest_chirho())
            .flatten()
    }

    pub(super) fn gd7_chirho(&self) -> &ResidentGd7WinnerHandoffRuntimeChirho {
        &self.gd7_chirho
    }

    pub(super) fn gd7_mut_chirho(&mut self) -> &mut ResidentGd7WinnerHandoffRuntimeChirho {
        &mut self.gd7_chirho
    }

    pub(super) fn probe_resident_chirho(
        &self,
        resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
        local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    ) -> Result<ResidentLedgerAuthorityReadinessChirho, ResidentLedgerAuthorityRefusalChirho> {
        self.read_resident_chirho(
            resident_chirho,
            local_authority_chirho,
            |resident_chirho, handoff_read_chirho| match handoff_read_chirho {
                Some(handoff_read_chirho) => {
                    resident_chirho.probe_during_handoff_read_chirho(handoff_read_chirho)
                }
                None => resident_chirho.probe_chirho(),
            },
        )
    }

    pub(super) fn read_resident_chirho<OutputChirho>(
        &self,
        resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
        local_authority_chirho: &LocalAppendAuthorityHandleChirho,
        read_chirho: impl FnOnce(
            &ResidentLedgerAuthorityChirho<'_>,
            Option<&LocalAppendHandoffReadGenerationChirho>,
        ) -> Result<OutputChirho, ResidentLedgerAuthorityRefusalChirho>,
    ) -> Result<OutputChirho, ResidentLedgerAuthorityRefusalChirho> {
        if self.migration_operation_fault_chirho {
            return Err(
                ResidentLedgerAuthorityRefusalChirho::TenantMigrationSourceFenceActiveChirho,
            );
        }
        if let Some(attempt_digest_chirho) = self.migration_chirho.active_attempt_digest_chirho() {
            let handoff_read_chirho = local_authority_chirho
                .try_acquire_handoff_read_chirho(attempt_digest_chirho)
                .map_err(|reason_chirho| {
                    ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                        reason_chirho,
                    }
                })?;
            return read_chirho(resident_chirho, Some(&handoff_read_chirho));
        }
        self.gd7_chirho
            .read_resident_chirho(resident_chirho, local_authority_chirho, read_chirho)
    }
}

fn inspect_durable_owners_chirho(
    gd7_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    migration_store_chirho: Option<&TenantMigrationStoreChirho<'_>>,
) -> Result<InspectedResidentAppendOwnersChirho, ResidentAppendBarrierRefusalChirho> {
    let gd7_chirho = gd7_store_chirho
        .load_current_chirho()
        .map_err(|refusal_chirho| {
            ResidentAppendBarrierRefusalChirho::Gd7Chirho(
                ResidentGd7WinnerHandoffRefusalChirho::StoreChirho(refusal_chirho),
            )
        })?;
    let migration_chirho = migration_store_chirho
        .map(TenantMigrationStoreChirho::load_current_chirho)
        .transpose()
        .map_err(|refusal_chirho| {
            ResidentAppendBarrierRefusalChirho::MigrationChirho(
                TenantMigrationCoordinatorRefusalChirho::StoreChirho(refusal_chirho),
            )
        })?
        .flatten();
    if migration_chirho.as_ref().is_some_and(|active_chirho| {
        active_chirho.phase_chirho()
            == TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
    }) {
        return Err(ResidentAppendBarrierRefusalChirho::ReservedMigrationPhaseChirho);
    }
    if gd7_is_active_chirho(gd7_chirho.as_ref())
        && migration_is_active_chirho(migration_chirho.as_ref())
    {
        return Err(ResidentAppendBarrierRefusalChirho::TwoActiveDurableOwnersChirho);
    }
    Ok(InspectedResidentAppendOwnersChirho {
        gd7_chirho,
        migration_chirho,
    })
}

fn gd7_is_active_chirho(active_chirho: Option<&ActiveGd7WinnerHandoffChirho>) -> bool {
    active_chirho.is_some_and(|active_chirho| {
        matches!(
            active_chirho.checkpoint_chirho.phase_chirho,
            Gd7WinnerHandoffPhaseChirho::PreparingChirho
                | Gd7WinnerHandoffPhaseChirho::AcceptedChirho
        )
    })
}

fn migration_is_active_chirho(active_chirho: Option<&ActiveTenantMigrationChirho>) -> bool {
    active_chirho
        .is_some_and(|active_chirho| active_chirho.phase_chirho().is_active_source_fence_chirho())
}

fn restore_gd7_chirho(
    store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    resident_chirho: &ResidentLedgerAuthorityChirho<'_>,
    inspected_chirho: Option<ActiveGd7WinnerHandoffChirho>,
) -> Result<ResidentGd7WinnerHandoffRuntimeChirho, ResidentAppendBarrierRefusalChirho> {
    ResidentGd7WinnerHandoffRuntimeChirho::restore_chirho(
        store_chirho,
        control_chirho,
        resident_chirho,
        inspected_chirho,
    )
    .map_err(ResidentAppendBarrierRefusalChirho::Gd7Chirho)
}

fn restore_migration_chirho(
    store_chirho: Option<&TenantMigrationStoreChirho<'_>>,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
    inspected_chirho: Option<ActiveTenantMigrationChirho>,
) -> Result<TenantMigrationStartupBarrierChirho, ResidentAppendBarrierRefusalChirho> {
    let Some(store_chirho) = store_chirho else {
        debug_assert!(inspected_chirho.is_none());
        return Ok(TenantMigrationStartupBarrierChirho::NoneChirho);
    };
    restore_tenant_migration_startup_chirho(store_chirho, control_chirho, inspected_chirho)
        .map_err(ResidentAppendBarrierRefusalChirho::MigrationChirho)
}

#[cfg(test)]
#[path = "append_barrier_tests_chirho.rs"]
mod tests_chirho;
