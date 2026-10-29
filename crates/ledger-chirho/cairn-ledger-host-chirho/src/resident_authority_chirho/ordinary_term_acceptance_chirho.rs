// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fourth sink-term mover for an ordinary Raft election.
//!
//! This mover receives neither transport nor signer authority. Its private proof was minted only
//! after the resident verified the complete two-holder ACK population against the exact local tail
//! while holding one local leadership generation. The mover rebinds that proof to this resident's
//! group and term before changing the durable sink cell.

use super::sink_term_lifecycle_chirho::writer_fence_refusal_chirho;
use super::{ResidentLedgerAuthorityChirho, ResidentLedgerAuthorityRefusalChirho};
use crate::reconciliation_chirho::sink_term_fence_chirho::{
    advance_accepted_winner_term_chirho, read_sink_term_fence_chirho,
};
use crate::storage_chirho::StableLedgerExclusiveLockGuardChirho;
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
    LedgerMirrorOrdinaryTermAcceptanceExpectationChirho, RawCanonicalGroupIdDigestChirho,
    VerifiedOrdinaryElectionSinkTermAcceptanceChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use rand_core::{OsRng, RngCore};
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct OrdinaryElectionSinkTermAdvanceRefusalChirho {
    detail_chirho: String,
}

impl OrdinaryElectionSinkTermAdvanceRefusalChirho {
    fn group_binding_refused_chirho() -> Self {
        Self {
            detail_chirho: "OrdinaryElectionSinkTermProofGroupBindingRefusedChirho".to_owned(),
        }
    }

    fn term_binding_refused_chirho() -> Self {
        Self {
            detail_chirho: "OrdinaryElectionSinkTermProofTermBindingRefusedChirho".to_owned(),
        }
    }

    fn storage_refused_chirho(detail_chirho: String) -> Self {
        Self {
            detail_chirho: format!("OrdinaryElectionSinkTermStorageRefusedChirho:{detail_chirho}"),
        }
    }

    fn durable_reread_refused_chirho() -> Self {
        Self {
            detail_chirho: "OrdinaryElectionSinkTermDurableRereadRefusedChirho".to_owned(),
        }
    }
}

impl fmt::Display for OrdinaryElectionSinkTermAdvanceRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(&self.detail_chirho)
    }
}

impl Error for OrdinaryElectionSinkTermAdvanceRefusalChirho {}

fn ordinary_term_acceptance_refusal_chirho(
    detail_chirho: String,
) -> ResidentLedgerAuthorityRefusalChirho {
    ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceRefusedChirho {
        detail_chirho,
    }
}

/// Collect and verify the exact two-holder ACK evidence while the caller retains one local
/// leadership-generation guard. This helper never owns or releases that guard.
pub(super) fn verify_ordinary_election_sink_term_acceptance_chirho(
    resident_chirho: &mut ResidentLedgerAuthorityChirho<'_>,
    published_winner_term_chirho: u64,
) -> Result<
    Option<VerifiedOrdinaryElectionSinkTermAcceptanceChirho>,
    ResidentLedgerAuthorityRefusalChirho,
> {
    let tagged_group_digest_chirho = consistency_group_digest_chirho(&resident_chirho.group_chirho)
        .map_err(|error_chirho| {
            ordinary_term_acceptance_refusal_chirho(error_chirho.to_string())
        })?;
    let inspection_guard_chirho = resident_chirho
        .writer_lock_chirho
        .try_acquire_chirho()
        .map_err(writer_fence_refusal_chirho)?;
    let inspected_sink_term_chirho =
        read_sink_term_fence_chirho(&inspection_guard_chirho, &tagged_group_digest_chirho)
            .map_err(|error_chirho| {
                ordinary_term_acceptance_refusal_chirho(error_chirho.to_string())
            })?;
    drop(inspection_guard_chirho);
    let ordinary_cell_is_behind_chirho =
        inspected_sink_term_chirho
            .as_ref()
            .is_some_and(|state_chirho| {
                state_chirho.highest_accepted_winner_term_chirho < published_winner_term_chirho
            });
    if !ordinary_cell_is_behind_chirho {
        return Ok(None);
    }
    let (Some(source_chirho), Some(placement_binding_chirho)) = (
        resident_chirho
            .ordinary_term_acceptance_source_chirho
            .as_ref(),
        resident_chirho
            .ordinary_term_acceptance_placement_binding_chirho
            .as_ref(),
    ) else {
        return Ok(None);
    };
    let local_tail_chirho = resident_chirho
        .journal_chirho
        .as_ref()
        .expect("resident authority retains its journal")
        .verified_append_mirror_tail_chirho();
    let mut entropy_chirho = [0_u8; 32];
    OsRng.try_fill_bytes(&mut entropy_chirho).map_err(|_| {
        ordinary_term_acceptance_refusal_chirho(
            "OrdinaryElectionSinkTermChallengeEntropyRefusedChirho".to_owned(),
        )
    })?;
    let challenge_chirho =
        LedgerMirrorOrdinaryTermAcceptanceChallengeChirho::from_entropy_chirho(entropy_chirho);
    let receipt_wires_chirho = source_chirho
        .read_ordinary_term_acceptance_receipts_chirho(&challenge_chirho, &local_tail_chirho)
        .map_err(|error_chirho| {
            ordinary_term_acceptance_refusal_chirho(error_chirho.detail_chirho().to_owned())
        })?;
    let canonical_group_id_chirho = resident_chirho.group_chirho.canonical_id_chirho();
    let raw_group_digest_chirho =
        RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(&canonical_group_id_chirho);
    VerifiedOrdinaryElectionSinkTermAcceptanceChirho::verify_chirho(
        &receipt_wires_chirho,
        LedgerMirrorOrdinaryTermAcceptanceExpectationChirho {
            challenge_chirho: &challenge_chirho,
            consistency_group_digest_chirho: &raw_group_digest_chirho,
            placement_binding_chirho,
            local_leader_node_id_chirho: resident_chirho.local_node_chirho.0.as_str(),
            published_raft_term_chirho: published_winner_term_chirho,
            local_tail_chirho: &local_tail_chirho,
        },
    )
    .map(Some)
    .map_err(|error_chirho| {
        ordinary_term_acceptance_refusal_chirho(error_chirho.detail_chirho().to_owned())
    })
}

/// Advance one existing sink cell from an independently verified ordinary-election proof.
///
/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
pub(super) fn advance_sink_term_from_ordinary_election_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    group_chirho: &ConsistencyGroupIdChirho,
    published_raft_term_chirho: u64,
    proof_chirho: &VerifiedOrdinaryElectionSinkTermAcceptanceChirho,
) -> Result<u64, OrdinaryElectionSinkTermAdvanceRefusalChirho> {
    let canonical_group_id_chirho = group_chirho.canonical_id_chirho();
    let expected_raw_group_digest_chirho =
        RawCanonicalGroupIdDigestChirho::from_canonical_group_id_chirho(&canonical_group_id_chirho);
    if proof_chirho.consistency_group_digest_chirho() != &expected_raw_group_digest_chirho {
        return Err(OrdinaryElectionSinkTermAdvanceRefusalChirho::group_binding_refused_chirho());
    }
    if proof_chirho.accepted_term_chirho() != published_raft_term_chirho {
        return Err(OrdinaryElectionSinkTermAdvanceRefusalChirho::term_binding_refused_chirho());
    }
    let tagged_group_digest_chirho =
        consistency_group_digest_chirho(group_chirho).map_err(|error_chirho| {
            OrdinaryElectionSinkTermAdvanceRefusalChirho::storage_refused_chirho(
                error_chirho.to_string(),
            )
        })?;
    let persisted_chirho = advance_accepted_winner_term_chirho(
        writer_lock_guard_chirho,
        &tagged_group_digest_chirho,
        published_raft_term_chirho,
    )
    .map_err(|error_chirho| {
        OrdinaryElectionSinkTermAdvanceRefusalChirho::storage_refused_chirho(
            error_chirho.to_string(),
        )
    })?;
    if persisted_chirho.group_digest_chirho != tagged_group_digest_chirho
        || persisted_chirho.highest_accepted_winner_term_chirho != published_raft_term_chirho
    {
        return Err(OrdinaryElectionSinkTermAdvanceRefusalChirho::durable_reread_refused_chirho());
    }
    Ok(persisted_chirho.highest_accepted_winner_term_chirho)
}
