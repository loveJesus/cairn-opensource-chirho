// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Waiting out a local Raft transition before a recovery effect, without waiting on anything else.
//!
//! The local append authority never blocks: while the elector runs a tick or a step it refuses
//! `TransitionPendingChirho`, and a durable step can hold that window for milliseconds while it
//! persists hard state. Recovery adoption revalidates before each of its effects, so an open that
//! overlapped an elector tick used to fail, and in production that is a geo-node exit and a restart.
//!
//! This module keeps each attempt's refusal TYPED until the actor's shared contention retry has
//! decided from it (`retry_resident_generation_contention_chirho`, the helper startup bracketing
//! already uses). That helper waits only on a pending transition or a busy guard, and returns every
//! other refusal at once. Its bound is an ATTEMPT budget, not a deadline: at most
//! `RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO` attempts with one requested pause between each
//! pair. The requested sleep is nominal, and each attempt's own checks also take time, so the budget
//! is not a wall-clock bound and says nothing about the lease. Each acquired guard still proves the
//! live lease for itself.

use super::super::super::{
    retry_resident_generation_contention_chirho, RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO,
};
use super::ResidentAppendBarrierRefusalChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use std::fmt;

/// Why one revalidation attempt before a recovery effect refused.
#[derive(Debug)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(super) enum RecoveryRevalidationRefusalChirho {
    /// The recovery port no longer vouches for the candidate. The detail is the port's own.
    AuthorityChirho(String),
    /// A durable owner or the local handoff slot refused.
    SlotChirho(ResidentAppendBarrierRefusalChirho),
    /// The local append authority refused the guard.
    LocalAuthorityChirho(LocalAppendAuthorityRefusalChirho),
}

impl RecoveryRevalidationRefusalChirho {
    /// The local-authority refusal inside this one, from either source, for the shared retry to
    /// classify. The retry itself keeps only a pending transition or a busy guard.
    pub(super) fn local_refusal_chirho(&self) -> Option<LocalAppendAuthorityRefusalChirho> {
        match self {
            Self::SlotChirho(ResidentAppendBarrierRefusalChirho::LocalRecoverySlotChirho(
                refusal_chirho,
            ))
            | Self::LocalAuthorityChirho(refusal_chirho) => Some(*refusal_chirho),
            Self::AuthorityChirho(_) | Self::SlotChirho(_) => None,
        }
    }
}

impl fmt::Display for RecoveryRevalidationRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityChirho(detail_chirho) => {
                write!(
                    formatter_chirho,
                    "revalidate F1 recovery authority: {detail_chirho}"
                )
            }
            Self::SlotChirho(refusal_chirho) => {
                write!(
                    formatter_chirho,
                    "F1 recovery append barrier refused: {refusal_chirho}"
                )
            }
            Self::LocalAuthorityChirho(refusal_chirho) => {
                write!(
                    formatter_chirho,
                    "F1 recovery local authority refused: {refusal_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for RecoveryRevalidationRefusalChirho {}

/// What a revalidation's contention cost. `contended_attempts_chirho` counts attempts that met
/// contention, including a final one at the budget, so it can exceed the pauses taken by one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecoveryContentionTallyChirho {
    pub(super) contended_attempts_chirho: usize,
    pub(super) pauses_chirho: usize,
}

/// Run one revalidation attempt until it succeeds, refuses with anything but contention, or spends
/// the attempt budget. Every attempt is the caller's WHOLE check, so nothing validated by an earlier
/// attempt is carried into a later one.
pub(super) fn retry_recovery_revalidation_chirho<TChirho>(
    attempt_chirho: impl FnMut() -> Result<TChirho, RecoveryRevalidationRefusalChirho>,
    mut pause_chirho: impl FnMut(),
) -> (
    Result<TChirho, RecoveryRevalidationRefusalChirho>,
    RecoveryContentionTallyChirho,
) {
    let mut tally_chirho = RecoveryContentionTallyChirho {
        contended_attempts_chirho: 0,
        pauses_chirho: 0,
    };
    let outcome_chirho = retry_resident_generation_contention_chirho(
        attempt_chirho,
        RecoveryRevalidationRefusalChirho::local_refusal_chirho,
        |_reason_chirho| tally_chirho.contended_attempts_chirho += 1,
        || {
            tally_chirho.pauses_chirho += 1;
            pause_chirho();
        },
        RESIDENT_GENERATION_CONTENTION_ATTEMPTS_CHIRHO,
    );
    (outcome_chirho, tally_chirho)
}

#[cfg(test)]
#[path = "recovery_contention_tests_chirho.rs"]
mod recovery_contention_tests_chirho;
