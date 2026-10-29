// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Creates the sink winner-term cell inside resident birth and verifies it on every Bound reopen.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/p5-cutover-and-lease-design-chirho.md` §4.
//! Birth create-or-recover is a resident lifecycle operation, not the GD7 semantic seed removed by
//! this brick. The generation witness supplies current authority; the resident writer lock makes the
//! durable read-modify-write indivisible across processes.
//!
//! Fresh birth checks for an existing cell before writing Pending. After Pending exists, an unowned
//! pre-birth cell and this attempt's own crash residue are indistinguishable, so refusing only after
//! the write would turn the next retry into accidental adoption. This exclusion depends on every
//! lifecycle mutator taking the same writer lock in the same storage namespace; the future revoke
//! path must not introduce an unlocked or different-namespace advance.

use crate::reconciliation_chirho::sink_term_fence_chirho::{
    advance_accepted_winner_term_chirho, create_sink_term_fence_at_birth_chirho,
    read_sink_term_fence_chirho, SinkTermFenceStateChirho,
};
use crate::resident_ledger_identity_chirho::ResidentLedgerBoundIdentityVerificationRefusalChirho;
use crate::storage_chirho::StableLedgerExclusiveLockGuardChirho;
use cairn_ledger_log_chirho::journal_chirho::ExpectedGenesisOpenErrorChirho;
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityRefusalChirho, LocalLeadershipGenerationGuardChirho,
    LocalStartupCoordinatesGuardChirho,
};
use cairn_writer_head_chirho::resident_writer_chirho::ResidentWriterReservationOutcomeChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::error::Error;
use std::fmt;

/// Affine evidence that the exact group cell was written or recovered at the live birth term.
///
/// A reusable current-authorization capability may be cloneable. This historical once-only birth
/// proof is not: cloning it would let two Bound identities claim one lifecycle transition. Fields
/// and construction remain private, and no serde/default/plain-value conversion exists.
pub(crate) struct VerifiedResidentSinkTermCellAtBirthChirho {
    group_digest_chirho: String,
    accepted_term_chirho: u64,
}

impl VerifiedResidentSinkTermCellAtBirthChirho {
    pub(crate) fn group_digest_chirho(&self) -> &str {
        &self.group_digest_chirho
    }

    pub(crate) fn accepted_term_chirho(&self) -> u64 {
        self.accepted_term_chirho
    }
}

/// Exact lifecycle reason a resident cell could not be created, recovered, or reopened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResidentSinkTermCellRefusalChirho {
    StorageChirho {
        detail_chirho: String,
    },
    LegacyBoundCellMissingChirho,
    LegacyBoundIdentityGenerationChirho,
    UnownedResidueAtFreshBirthChirho {
        existing_term_chirho: u64,
    },
    RecoveredCellAheadOfCurrentAuthorityChirho {
        accepted_term_chirho: u64,
        current_term_chirho: u64,
    },
    CurrentBoundCellMissingChirho {
        current_term_chirho: u64,
    },
    CurrentBoundIdentityMissingSignedBirthTermChirho,
    /// Detects rollback only below the term signed at birth. A rollback of a later advance that stays
    /// within `[signed birth, live authority]` is not observable from the birth identity. Item 5b's
    /// revoke path may tighten this floor if it introduces signed evidence for later advances.
    CurrentBoundCellBelowSignedBirthTermChirho {
        accepted_term_chirho: u64,
        signed_birth_term_chirho: u64,
    },
    CurrentBoundCellAheadOfAuthorityChirho {
        accepted_term_chirho: u64,
        current_term_chirho: u64,
    },
}

impl fmt::Display for ResidentSinkTermCellRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageChirho { detail_chirho } => {
                write!(formatter_chirho, "sink term cell storage refused: {detail_chirho}")
            }
            Self::LegacyBoundCellMissingChirho => formatter_chirho.write_str(
                "Bound coordinate with no sink cell - not openable under the cell-at-birth invariant",
            ),
            Self::LegacyBoundIdentityGenerationChirho => formatter_chirho.write_str(
                "legacy Bound identity generation is not openable under the cell-at-birth invariant",
            ),
            Self::UnownedResidueAtFreshBirthChirho { .. } => formatter_chirho.write_str(
                "fresh resident birth found an unowned pre-existing sink term cell",
            ),
            Self::RecoveredCellAheadOfCurrentAuthorityChirho { .. } => formatter_chirho.write_str(
                "recovered Pending resident sink term cell is ahead of current authority",
            ),
            Self::CurrentBoundCellMissingChirho { .. } => formatter_chirho.write_str(
                "current-generation Bound coordinate is missing its required sink term cell",
            ),
            Self::CurrentBoundIdentityMissingSignedBirthTermChirho => formatter_chirho.write_str(
                "current-generation Bound identity is missing its signed sink-cell birth term",
            ),
            Self::CurrentBoundCellBelowSignedBirthTermChirho { .. } => formatter_chirho.write_str(
                "Bound resident sink term cell is below its signed birth-term floor",
            ),
            Self::CurrentBoundCellAheadOfAuthorityChirho { .. } => formatter_chirho.write_str(
                "Bound resident sink term cell is ahead of current authority",
            ),
        }
    }
}

impl Error for ResidentSinkTermCellRefusalChirho {}

impl From<ResidentSinkTermCellRefusalChirho> for super::ResidentLedgerAuthorityRefusalChirho {
    fn from(reason_chirho: ResidentSinkTermCellRefusalChirho) -> Self {
        Self::SinkTermCellRefusedChirho { reason_chirho }
    }
}

pub(super) fn local_generation_refusal_chirho(
    reason_chirho: LocalAppendAuthorityRefusalChirho,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    super::ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho { reason_chirho }
}

pub(super) fn stable_namespace_refusal_chirho(
    error_chirho: anyhow::Error,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    super::ResidentLedgerAuthorityRefusalChirho::StableNamespaceRefusedChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

pub(super) fn writer_fence_refusal_chirho(
    error_chirho: anyhow::Error,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    super::ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

pub(super) fn resident_identity_refusal_chirho(
    error_chirho: anyhow::Error,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    super::ResidentLedgerAuthorityRefusalChirho::ResidentIdentityRefusedChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

pub(super) fn current_bound_identity_refusal_chirho(
    error_chirho: anyhow::Error,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    if error_chirho.downcast_ref::<ResidentLedgerBoundIdentityVerificationRefusalChirho>()
        == Some(
            &ResidentLedgerBoundIdentityVerificationRefusalChirho::CurrentBirthTermMissingChirho,
        )
    {
        return super::ResidentLedgerAuthorityRefusalChirho::from(
            ResidentSinkTermCellRefusalChirho::CurrentBoundIdentityMissingSignedBirthTermChirho,
        );
    }
    resident_identity_refusal_chirho(error_chirho)
}

pub(super) fn resident_lease_refusal_chirho(
    error_chirho: anyhow::Error,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    super::ResidentLedgerAuthorityRefusalChirho::ResidentLeaseRefusedChirho {
        detail_chirho: error_chirho.to_string(),
    }
}

pub(super) fn expected_genesis_refusal_chirho(
    detail_chirho: String,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    super::ResidentLedgerAuthorityRefusalChirho::ExpectedGenesisRefusedChirho { detail_chirho }
}

pub(super) fn expected_genesis_open_refusal_chirho(
    error_chirho: ExpectedGenesisOpenErrorChirho,
) -> super::ResidentLedgerAuthorityRefusalChirho {
    expected_genesis_refusal_chirho(format!("{error_chirho:?}"))
}

pub(super) fn create_or_recover_resident_sink_term_cell_at_birth_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    generation_guard_chirho: &LocalLeadershipGenerationGuardChirho<'_>,
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    reservation_outcome_chirho: ResidentWriterReservationOutcomeChirho,
) -> Result<VerifiedResidentSinkTermCellAtBirthChirho, ResidentSinkTermCellRefusalChirho> {
    create_or_recover_resident_sink_term_cell_at_term_chirho(
        group_chirho,
        generation_guard_chirho.published_raft_term_chirho(),
        writer_lock_guard_chirho,
        reservation_outcome_chirho,
    )
}

/// Refuse unowned cell residue before a fresh attempt can leave a retryable Pending identity.
pub(super) fn require_no_sink_term_cell_before_fresh_pending_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
) -> Result<(), ResidentSinkTermCellRefusalChirho> {
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .map_err(storage_refusal_chirho)?;
    let group_digest_chirho =
        consistency_group_digest_chirho(group_chirho).map_err(storage_refusal_chirho)?;
    if let Some(existing_chirho) =
        read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho)
            .map_err(storage_refusal_chirho)?
    {
        return Err(
            ResidentSinkTermCellRefusalChirho::UnownedResidueAtFreshBirthChirho {
                existing_term_chirho: existing_chirho.highest_accepted_winner_term_chirho,
            },
        );
    }
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .map_err(storage_refusal_chirho)
}

#[cfg(test)]
pub(crate) fn create_or_recover_resident_sink_term_cell_at_term_for_test_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    current_term_chirho: u64,
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    reservation_outcome_chirho: ResidentWriterReservationOutcomeChirho,
) -> Result<VerifiedResidentSinkTermCellAtBirthChirho, ResidentSinkTermCellRefusalChirho> {
    create_or_recover_resident_sink_term_cell_at_term_chirho(
        group_chirho,
        current_term_chirho,
        writer_lock_guard_chirho,
        reservation_outcome_chirho,
    )
}

fn create_or_recover_resident_sink_term_cell_at_term_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    current_term_chirho: u64,
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    reservation_outcome_chirho: ResidentWriterReservationOutcomeChirho,
) -> Result<VerifiedResidentSinkTermCellAtBirthChirho, ResidentSinkTermCellRefusalChirho> {
    let group_digest_chirho =
        consistency_group_digest_chirho(group_chirho).map_err(storage_refusal_chirho)?;
    let existing_chirho =
        read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho)
            .map_err(storage_refusal_chirho)?;

    let persisted_chirho = match (reservation_outcome_chirho, existing_chirho) {
        (
            ResidentWriterReservationOutcomeChirho::CreatedPendingChirho
            | ResidentWriterReservationOutcomeChirho::CompletedPendingReservationChirho,
            Some(existing_chirho),
        ) => {
            return Err(
                ResidentSinkTermCellRefusalChirho::UnownedResidueAtFreshBirthChirho {
                    existing_term_chirho: existing_chirho.highest_accepted_winner_term_chirho,
                },
            );
        }
        (ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho, Some(existing_chirho))
            if existing_chirho.highest_accepted_winner_term_chirho > current_term_chirho =>
        {
            return Err(
                ResidentSinkTermCellRefusalChirho::RecoveredCellAheadOfCurrentAuthorityChirho {
                    accepted_term_chirho: existing_chirho.highest_accepted_winner_term_chirho,
                    current_term_chirho,
                },
            );
        }
        (ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho, Some(existing_chirho))
            if existing_chirho.highest_accepted_winner_term_chirho == current_term_chirho =>
        {
            existing_chirho
        }
        (ResidentWriterReservationOutcomeChirho::RecoveredPendingChirho, Some(_)) => {
            advance_accepted_winner_term_chirho(
                writer_lock_guard_chirho,
                &group_digest_chirho,
                current_term_chirho,
            )
            .map_err(storage_refusal_chirho)?
        }
        (_, None) => create_sink_term_fence_at_birth_chirho(
            writer_lock_guard_chirho,
            &group_digest_chirho,
            current_term_chirho,
        )
        .map_err(storage_refusal_chirho)?,
    };

    if persisted_chirho.group_digest_chirho != group_digest_chirho
        || persisted_chirho.highest_accepted_winner_term_chirho != current_term_chirho
    {
        return Err(ResidentSinkTermCellRefusalChirho::StorageChirho {
            detail_chirho: "ResidentSinkTermCellBirthRereadMismatchChirho".to_owned(),
        });
    }

    Ok(VerifiedResidentSinkTermCellAtBirthChirho {
        group_digest_chirho,
        accepted_term_chirho: current_term_chirho,
    })
}

/// The bound-open cell check takes the STARTUP coordinate seal, not an ordinary append guard.
///
/// It reads one scalar — the published Raft term — and performs no mutation, so the coordinate-only
/// startup type is exactly the authority this check needs. It is also what lets a handoff-frozen
/// winner verify its own cell at open: an ordinary guard cannot exist while the marker is active.
pub(super) fn verify_resident_sink_term_cell_for_bound_open_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    signed_birth_term_chirho: u64,
    generation_guard_chirho: &LocalStartupCoordinatesGuardChirho<'_>,
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
) -> Result<SinkTermFenceStateChirho, ResidentSinkTermCellRefusalChirho> {
    verify_resident_sink_term_cell_at_term_chirho(
        group_chirho,
        signed_birth_term_chirho,
        generation_guard_chirho.published_raft_term_chirho(),
        writer_lock_guard_chirho,
    )
}

pub(super) fn legacy_bound_resident_sink_term_cell_refusal_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
) -> ResidentSinkTermCellRefusalChirho {
    if let Err(error_chirho) = writer_lock_guard_chirho.verify_custody_chirho() {
        return storage_refusal_chirho(error_chirho);
    }
    let group_digest_chirho = match consistency_group_digest_chirho(group_chirho) {
        Ok(group_digest_chirho) => group_digest_chirho,
        Err(error_chirho) => return storage_refusal_chirho(error_chirho),
    };
    match read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho) {
        Ok(None) => ResidentSinkTermCellRefusalChirho::LegacyBoundCellMissingChirho,
        Ok(Some(_state_chirho)) => {
            ResidentSinkTermCellRefusalChirho::LegacyBoundIdentityGenerationChirho
        }
        Err(error_chirho) => storage_refusal_chirho(error_chirho),
    }
}

fn verify_resident_sink_term_cell_at_term_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    signed_birth_term_chirho: u64,
    current_term_chirho: u64,
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
) -> Result<SinkTermFenceStateChirho, ResidentSinkTermCellRefusalChirho> {
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .map_err(storage_refusal_chirho)?;
    let group_digest_chirho =
        consistency_group_digest_chirho(group_chirho).map_err(storage_refusal_chirho)?;
    let state_chirho = read_sink_term_fence_chirho(writer_lock_guard_chirho, &group_digest_chirho)
        .map_err(storage_refusal_chirho)?
        .ok_or(
            ResidentSinkTermCellRefusalChirho::CurrentBoundCellMissingChirho {
                current_term_chirho,
            },
        )?;
    if state_chirho.highest_accepted_winner_term_chirho > current_term_chirho {
        return Err(
            ResidentSinkTermCellRefusalChirho::CurrentBoundCellAheadOfAuthorityChirho {
                accepted_term_chirho: state_chirho.highest_accepted_winner_term_chirho,
                current_term_chirho,
            },
        );
    }
    if state_chirho.highest_accepted_winner_term_chirho < signed_birth_term_chirho {
        return Err(
            ResidentSinkTermCellRefusalChirho::CurrentBoundCellBelowSignedBirthTermChirho {
                accepted_term_chirho: state_chirho.highest_accepted_winner_term_chirho,
                signed_birth_term_chirho,
            },
        );
    }
    writer_lock_guard_chirho
        .verify_custody_chirho()
        .map_err(storage_refusal_chirho)?;
    Ok(state_chirho)
}

fn storage_refusal_chirho(error_chirho: anyhow::Error) -> ResidentSinkTermCellRefusalChirho {
    ResidentSinkTermCellRefusalChirho::StorageChirho {
        detail_chirho: error_chirho.to_string(),
    }
}
