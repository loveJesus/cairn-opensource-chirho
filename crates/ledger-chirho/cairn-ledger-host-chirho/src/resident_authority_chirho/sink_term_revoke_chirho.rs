// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The GD7 witness-bounded paths that may advance the sink winner-term cell mid-life.
//!
//! # TWO COORDINATES, AND NEITHER ALONE MAY ADVANCE THE CELL
//!
//! Advancing this cell is what unlocks compensation, and compensation stands in front of an
//! irreversible provider call (see `sink_term_fence_chirho`'s header). So the advance binds BOTH:
//!
//! - **Authority** — the winner term carried by a signature-verified, identity-bound
//!   [`AuthenticatedGd7DeposedForkObservationChirho`]. This is cross-host truth about which fork
//!   won. On its own it is STALE-ABLE: it is evidence about a past election and cannot know a newer
//!   one has since happened.
//! - **Freshness** — equality with the local elector's published term. On its own this is
//!   PARTITION-BLIND: `cairn-writer-elector-chirho`'s own header states that guard "seals only
//!   locally observed transitions", "cannot observe an unseen remote higher term", and "is not a
//!   durable or cross-host fence". A locally-mistaken or partitioned leader believing it won would
//!   otherwise advance the cell and unlock money movement on a losing fork.
//!
//! The two failure modes are complementary, which is why the contract is conjunction rather than
//! choice. Binding only the witness lets a superseded winner advance; binding only the local term
//! lets a partitioned node advance. Both are silent — the suite stays green either way.
//!
//! # THE CUT IS THE ADOPTION CUT, NOT THE CONVERGENCE CERTIFICATE
//!
//! Ruled during this brick, because the alternative is circular: the compensation append is fenced
//! by the very cell this module advances, so obligations cannot reach a terminal outcome while the
//! cell is behind. Requiring D1's `ConvergedReadReplicaChirho` to authorize the advance would mean
//! the advance could never run in exactly the mid-life term bump it exists to lift. D3 owns
//! certificate binding; this module binds the adopted checkpoint.
//!
//! # CONFINEMENT IS BY BIRTH WITNESS, NOT BY AN ALLOWLIST
//!
//! [`VerifiedLawfulSinkTermAdvanceChirho`] has private fields and exactly one construction site —
//! the tail of the verified operation below, after every check has passed. A caller cannot name the
//! fields, so it cannot forge the evidence that a lawful advance happened. This matters precisely
//! because this primitive has multiple production-compiled callers: an allowlist is where another
//! quietly arrives, and a type boundary is where it cannot. The ordinary-election sibling uses a
//! different private proof type and never consumes this GD7 witness.
//!
//! Every check runs BEFORE the durable write. A gate that fired after the advance could only strand
//! a half-moved cell.

#![allow(
    dead_code,
    reason = "D3 release and D4 write restoration are the consumers of this lawful advance; this brick lands the operation and its witness confinement, and deliberately wires no composition point. The operation is exercised by its arms, not by production."
)]

use super::sink_term_lifecycle_chirho::ResidentSinkTermCellRefusalChirho;
use crate::reconciliation_chirho::sink_term_fence_chirho::advance_accepted_winner_term_chirho;
use crate::reconciliation_chirho::{
    load_authenticated_active_gd7_reconciliation_for_group_chirho,
    load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho,
    verify_signed_gd7_converged_read_replica_chirho, AuthenticatedGd7DeposedForkObservationChirho,
    ConvergedReadReplicaChirho, Gd7ReconciliationCheckpointChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationPhaseChirho, Gd7ReconciliationVerifierPortChirho,
    VerifiedGd7WinnerForkWitnessChirho,
};
use crate::storage_chirho::StableLedgerExclusiveLockGuardChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_writer_elector_chirho::LocalLeadershipGenerationGuardChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::error::Error;
use std::fmt;

/// Affine evidence that one exact group's cell was lawfully advanced mid-life.
///
/// Fields and construction are private. The only construction site is the tail of
/// [`revoke_and_accept_new_winner_term_chirho`], so holding this value is proof that both
/// coordinates were verified — it cannot be assembled by a caller that skipped them.
///
/// A caller outside this module cannot name the fields (E0451), so the evidence cannot be forged:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::resident_authority_chirho::sink_term_revoke_chirho::VerifiedLawfulSinkTermAdvanceChirho;
/// let _forged_chirho = VerifiedLawfulSinkTermAdvanceChirho {
///     group_digest_chirho: String::new(),
///     accepted_term_chirho: 0,
/// };
/// ```
///
/// It has no default value:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::resident_authority_chirho::sink_term_revoke_chirho::VerifiedLawfulSinkTermAdvanceChirho;
/// let _forged_chirho = VerifiedLawfulSinkTermAdvanceChirho::default();
/// ```
pub(crate) struct VerifiedLawfulSinkTermAdvanceChirho {
    group_digest_chirho: String,
    accepted_term_chirho: u64,
}

impl VerifiedLawfulSinkTermAdvanceChirho {
    pub(crate) fn group_digest_chirho(&self) -> &str {
        &self.group_digest_chirho
    }

    pub(crate) fn accepted_term_chirho(&self) -> u64 {
        self.accepted_term_chirho
    }
}

/// Exact reason a mid-life advance was refused. Each variant names one failed binding.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum LawfulSinkTermAdvanceRefusalChirho {
    /// The observation describes a different consistency group than the one being advanced.
    ForeignGroupChirho {
        expected_group_digest_chirho: String,
        observed_group_digest_chirho: String,
    },
    /// The signed witness's own identity disagrees with the observation carrying it.
    WitnessIdentityMismatchChirho,
    /// The named adopted checkpoint could not be loaded, digest-matched, or signature-verified.
    AdoptedCutUnauthenticatedChirho {
        detail_chirho: String,
    },
    /// The convergence certificate did not verify against the held verifier — its schema, key id, or
    /// signature failed. A fabricated or tampered certificate cannot release the reconciliation hold,
    /// because the checkpoint-ref equality alone is an unauthenticated field getter.
    ConvergenceCertificateUnverifiedChirho {
        detail_chirho: String,
    },
    /// The adopted checkpoint authenticated, but there is no active reconciliation head to supersede
    /// — the hold is already released. Distinct from `AdoptedCutUnauthenticatedChirho`: nothing
    /// failed to authenticate; a crash-and-retry after a prior release lands here.
    ActiveHeadAlreadyAbsentChirho,
    /// The adopted checkpoint describes a different reconciliation than the observation.
    AdoptedCutIdentityMismatchChirho,
    /// The adopted checkpoint names a different winner fork witness than the observation.
    AdoptedCutWitnessMismatchChirho {
        checkpoint_witness_digest_chirho: String,
        observed_witness_digest_chirho: String,
    },
    /// The cut has not reached the adopted phase, so there is nothing lawfully adopted to accept.
    AdoptedCutNotAdoptedChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho,
    },
    /// The adopted phase carries no adoption binding, so the cut is unproven.
    AdoptedCutMissingAdoptionBindingChirho,
    /// This node has not yet observed the winner's term: it is not the live writer at that term.
    LocalTermBehindWitnessChirho {
        local_term_chirho: u64,
        witness_winner_term_chirho: u64,
    },
    /// This node has observed a HIGHER term than the witness names, so the witness is superseded.
    /// Advancing to its older term would accept a winner the cluster has already moved past.
    LocalTermAheadOfWitnessChirho {
        local_term_chirho: u64,
        witness_winner_term_chirho: u64,
    },
    StorageChirho {
        detail_chirho: String,
    },
    /// The winner-side advance found no signed fork witness for the identity its own accepted
    /// handoff names. Without the witness there is no signed field to read a term out of.
    WinnerForkWitnessMissingChirho,
    /// The accepted handoff's held-transfer identity is not the identity the witness signs.
    /// The winner-side analogue of the adopted-cut binding: it ties the advance to the exact
    /// accepted handoff instead of to any witness this root happens to hold.
    HandoffIdentityMismatchChirho,
}

impl fmt::Display for LawfulSinkTermAdvanceRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignGroupChirho {
                expected_group_digest_chirho,
                observed_group_digest_chirho,
            } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceForeignGroupChirho: expected {expected_group_digest_chirho}, observed {observed_group_digest_chirho}"
            ),
            Self::WitnessIdentityMismatchChirho => {
                formatter_chirho.write_str("LawfulSinkTermAdvanceWitnessIdentityMismatchChirho")
            }
            Self::AdoptedCutUnauthenticatedChirho { detail_chirho } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceAdoptedCutUnauthenticatedChirho: {detail_chirho}"
            ),
            Self::ConvergenceCertificateUnverifiedChirho { detail_chirho } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceConvergenceCertificateUnverifiedChirho: {detail_chirho}"
            ),
            Self::ActiveHeadAlreadyAbsentChirho => {
                formatter_chirho.write_str("LawfulSinkTermAdvanceActiveHeadAlreadyAbsentChirho")
            }
            Self::AdoptedCutIdentityMismatchChirho => {
                formatter_chirho.write_str("LawfulSinkTermAdvanceAdoptedCutIdentityMismatchChirho")
            }
            Self::AdoptedCutWitnessMismatchChirho {
                checkpoint_witness_digest_chirho,
                observed_witness_digest_chirho,
            } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceAdoptedCutWitnessMismatchChirho: checkpoint {checkpoint_witness_digest_chirho}, observation {observed_witness_digest_chirho}"
            ),
            Self::AdoptedCutNotAdoptedChirho { phase_chirho } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceAdoptedCutNotAdoptedChirho: phase {phase_chirho:?}"
            ),
            Self::AdoptedCutMissingAdoptionBindingChirho => formatter_chirho
                .write_str("LawfulSinkTermAdvanceAdoptedCutMissingAdoptionBindingChirho"),
            Self::WinnerForkWitnessMissingChirho => {
                formatter_chirho.write_str("LawfulSinkTermAdvanceWinnerForkWitnessMissingChirho")
            }
            Self::HandoffIdentityMismatchChirho => {
                formatter_chirho.write_str("LawfulSinkTermAdvanceHandoffIdentityMismatchChirho")
            }
            Self::LocalTermBehindWitnessChirho {
                local_term_chirho,
                witness_winner_term_chirho,
            } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceLocalTermBehindWitnessChirho: local {local_term_chirho}, witness {witness_winner_term_chirho}"
            ),
            Self::LocalTermAheadOfWitnessChirho {
                local_term_chirho,
                witness_winner_term_chirho,
            } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceLocalTermAheadOfWitnessChirho: local {local_term_chirho}, witness {witness_winner_term_chirho}"
            ),
            Self::StorageChirho { detail_chirho } => write!(
                formatter_chirho,
                "LawfulSinkTermAdvanceStorageChirho: {detail_chirho}"
            ),
        }
    }
}

impl Error for LawfulSinkTermAdvanceRefusalChirho {}

impl From<LawfulSinkTermAdvanceRefusalChirho> for ResidentSinkTermCellRefusalChirho {
    fn from(refusal_chirho: LawfulSinkTermAdvanceRefusalChirho) -> Self {
        Self::StorageChirho {
            detail_chirho: refusal_chirho.to_string(),
        }
    }
}

/// Decide whether a mid-life advance is authorized, and to what term.
///
/// Pure on purpose, following `verify_supplied_winner_term_is_strictly_current_chirho` in the fence
/// module: the decision is testable without a store, and because
/// [`revoke_and_accept_new_winner_term_chirho`] is the only path to the durable write, no caller can
/// reach a variant of this decision that skipped the I/O.
///
/// Returns the term the witness authorizes. The term is never a caller argument — a caller-named
/// term would make the operation authorize whatever it was handed.
pub(crate) fn authorize_lawful_sink_term_advance_chirho(
    group_digest_chirho: &str,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    adopted_checkpoint_chirho: &Gd7ReconciliationCheckpointChirho,
    local_term_chirho: u64,
) -> Result<u64, LawfulSinkTermAdvanceRefusalChirho> {
    let identity_chirho = observation_chirho.identity_chirho();
    if identity_chirho.consistency_group_digest_chirho != group_digest_chirho {
        return Err(LawfulSinkTermAdvanceRefusalChirho::ForeignGroupChirho {
            expected_group_digest_chirho: group_digest_chirho.to_owned(),
            observed_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        });
    }

    // The witness's own signed identity is the authority. If the observation's identity has drifted
    // from it, the term below would be read from an unsigned field.
    let witness_chirho = observation_chirho.winner_fork_witness_chirho();
    if &witness_chirho.witness_chirho().identity_chirho != identity_chirho {
        return Err(LawfulSinkTermAdvanceRefusalChirho::WitnessIdentityMismatchChirho);
    }

    if &adopted_checkpoint_chirho.identity_chirho != identity_chirho {
        return Err(LawfulSinkTermAdvanceRefusalChirho::AdoptedCutIdentityMismatchChirho);
    }
    if adopted_checkpoint_chirho.winner_fork_witness_object_digest_chirho
        != witness_chirho.object_digest_chirho()
    {
        return Err(
            LawfulSinkTermAdvanceRefusalChirho::AdoptedCutWitnessMismatchChirho {
                checkpoint_witness_digest_chirho: adopted_checkpoint_chirho
                    .winner_fork_witness_object_digest_chirho
                    .clone(),
                observed_witness_digest_chirho: witness_chirho.object_digest_chirho().to_owned(),
            },
        );
    }
    if adopted_checkpoint_chirho.state_chirho.phase_chirho
        != Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
    {
        return Err(
            LawfulSinkTermAdvanceRefusalChirho::AdoptedCutNotAdoptedChirho {
                phase_chirho: adopted_checkpoint_chirho.state_chirho.phase_chirho,
            },
        );
    }
    if adopted_checkpoint_chirho
        .state_chirho
        .adoption_binding_chirho
        .is_none()
    {
        return Err(LawfulSinkTermAdvanceRefusalChirho::AdoptedCutMissingAdoptionBindingChirho);
    }

    // Freshness, and it is deliberately an equality rather than a floor. Below means this node is
    // not the live writer at the winner's term; above means the cluster has already elected past
    // this witness and accepting its term would install a superseded winner.
    let witness_winner_term_chirho = identity_chirho.winner_term_chirho;
    if local_term_chirho < witness_winner_term_chirho {
        return Err(
            LawfulSinkTermAdvanceRefusalChirho::LocalTermBehindWitnessChirho {
                local_term_chirho,
                witness_winner_term_chirho,
            },
        );
    }
    if local_term_chirho > witness_winner_term_chirho {
        return Err(
            LawfulSinkTermAdvanceRefusalChirho::LocalTermAheadOfWitnessChirho {
                local_term_chirho,
                witness_winner_term_chirho,
            },
        );
    }
    Ok(witness_winner_term_chirho)
}

/// Authorize the WINNER's own-term sink advance from the winner's own signed fork witness.
///
/// Ruled (i) by L.J. 2026-08-06. The held-side authorizer above answers "may I accept the term of
/// the node that deposed me"; this one answers the question that had no lawful mover at all: **may
/// the winner's own fence learn the term the winner already holds.** Everything structural is
/// deliberately the same — group equality, witness-signs-its-own-identity, an external binding
/// artifact, and equality-not-floor freshness — because the two advances differ in WHICH artifact
/// binds them, not in how much proof they demand.
///
/// WHAT BINDS IT, in place of the held side's adopted checkpoint: the ACCEPTED winner-handoff head —
/// but through a RESOLVED identity, not a matched tuple, and the difference is the whole safety
/// argument.
///
/// THE CHECKPOINT REF MUST BE RESOLVED, NOT MATCHED. The handoff's `held_transfer_identity_chirho`
/// carries five fields; the fork witness carries the ten-field `Gd7ReconciliationIdentityChirho` and
/// NO checkpoint ref at all. So the fields directly comparable between the two are only the FOUR in
/// their overlap — group, winner node, held node, winner term — and all four can be equal for two
/// sibling losing forks that share a held node. The one field that separates siblings, the
/// checkpoint ref, is exactly the field a direct comparison cannot use, because the witness has
/// nothing to compare it against.
///
/// Hence the caller resolves it: load the plan-sealed reconciliation checkpoint that ref names from
/// this node's own storage, authenticate it, recover the full ten-field identity, and pass THAT
/// here. The witness is then looked up and checked against a fully distinguishing identity rather
/// than a coarse tuple.
///
/// SEVERITY, at its measured scope and no wider. Storage is SETTLED AND PERMISSIVE: the identity
/// digest is blake3 over all ten canonical fields, so two sibling identities hash differently and
/// the persistence layer would hold both side by side — no storage collision makes the case
/// self-limiting (measured by claude2_chirho at `store_chirho.rs:1213`). What remains unmeasured is
/// purely PROTOCOL-level: can one held node be reconciled twice, at two fork points, while the
/// winner holds one term? A DIFFERENT held node is already separated by the four-field overlap, so
/// the residual shape is specifically same-held-node. Do not look at storage, keying, or the type to
/// settle it — those are answered. Do not upgrade this to a live vulnerability, or downgrade it to
/// theory, without that protocol measurement.
///
/// NOT A NOVELTY: `cf8-gd7-deposed-fork-reconciliation-design-chirho.md:469` already states that
/// full reconciliation identity equality blocks cross-term artifact splicing. Full-identity equality
/// is the ESTABLISHED pattern on this seam; this brings the winner side into line with what the
/// completed-store composition already does, rather than inventing a rule for it.
///
/// Found by gpt_chirho's pre-registered review arm SIBLING-WITNESS-SUBSTITUTION-1, selected blind
/// from the ruled design before this code existed.
///
/// WHAT IS NOT A CALLER ARGUMENT, per the standing shared veto: the term. It is read by value out
/// of the witness's own signed identity. A caller supplies coordinates to LOOK UP evidence; it never
/// supplies the value the fence moves to, and no in-memory elector observation reaches this decision.
///
/// The scope of L.J.'s ruling, recorded so it is not widened by precedent: a self-signed,
/// custody-verified witness suffices FOR THIS ADVANCE. It establishes no general doctrine; a future
/// mover proposing self-signed evidence argues its own case.
pub(crate) fn authorize_winner_own_term_sink_advance_chirho(
    group_digest_chirho: &str,
    witness_chirho: &VerifiedGd7WinnerForkWitnessChirho,
    accepted_handoff_identity_chirho: &Gd7ReconciliationIdentityChirho,
    local_term_chirho: u64,
) -> Result<u64, LawfulSinkTermAdvanceRefusalChirho> {
    let identity_chirho = &witness_chirho.witness_chirho().identity_chirho;
    if identity_chirho.consistency_group_digest_chirho != group_digest_chirho {
        return Err(LawfulSinkTermAdvanceRefusalChirho::ForeignGroupChirho {
            expected_group_digest_chirho: group_digest_chirho.to_owned(),
            observed_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        });
    }
    // The accepted handoff is this advance's binding artifact. Identity equality is the whole of it:
    // a witness for any other reconciliation cannot move this cell.
    if identity_chirho != accepted_handoff_identity_chirho {
        return Err(LawfulSinkTermAdvanceRefusalChirho::HandoffIdentityMismatchChirho);
    }
    // Freshness, equality rather than a floor, for the same two reasons the held-side advance gives:
    // below means this node is not the live writer at the witness's term; above means the cluster
    // has already elected past this witness and accepting its term would install a superseded winner.
    let witness_winner_term_chirho = identity_chirho.winner_term_chirho;
    if local_term_chirho < witness_winner_term_chirho {
        return Err(
            LawfulSinkTermAdvanceRefusalChirho::LocalTermBehindWitnessChirho {
                local_term_chirho,
                witness_winner_term_chirho,
            },
        );
    }
    if local_term_chirho > witness_winner_term_chirho {
        return Err(
            LawfulSinkTermAdvanceRefusalChirho::LocalTermAheadOfWitnessChirho {
                local_term_chirho,
                witness_winner_term_chirho,
            },
        );
    }
    Ok(witness_winner_term_chirho)
}

/// Advance the sink cell to the GD7 winner's own term — the second production-reachable mover of
/// `advance_accepted_winner_term_chirho` after birth recovery.
///
/// Census-pinned to its lawful consumer. The ordinary-election sibling was separately argued as new
/// money-fence authority and receives a disjoint two-holder proof; it cannot name this function's
/// GD7 witness inputs.
///
/// ON DEMAND, never eager: the caller invokes this only when a lawful compensation append has found
/// its own cell behind. A handoff that never carries a compensation never moves the fence.
pub(crate) fn advance_sink_term_from_winner_witness_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    group_digest_chirho: &str,
    witness_chirho: &VerifiedGd7WinnerForkWitnessChirho,
    accepted_handoff_identity_chirho: &Gd7ReconciliationIdentityChirho,
    local_term_chirho: u64,
) -> Result<u64, LawfulSinkTermAdvanceRefusalChirho> {
    let witness_winner_term_chirho = authorize_winner_own_term_sink_advance_chirho(
        group_digest_chirho,
        witness_chirho,
        accepted_handoff_identity_chirho,
        local_term_chirho,
    )?;
    let persisted_chirho = advance_accepted_winner_term_chirho(
        writer_lock_guard_chirho,
        group_digest_chirho,
        witness_winner_term_chirho,
    )
    .map_err(
        |error_chirho| LawfulSinkTermAdvanceRefusalChirho::StorageChirho {
            detail_chirho: format!("{error_chirho:?}"),
        },
    )?;
    Ok(persisted_chirho.highest_accepted_winner_term_chirho)
}

/// Advance the sink cell mid-life, under verified revoke / accept-new-winner evidence.
///
/// This is the SECOND production caller of `advance_accepted_winner_term_chirho`; birth recovery is
/// the first. It uses the same resident writer lock and the same storage namespace, as
/// `sink_term_lifecycle_chirho`'s header requires of exactly this path.
/// The adopted cut is taken by REF and authenticated here, never accepted as a caller-built value.
/// `Gd7ReconciliationCheckpointChirho` is a plain struct with public fields, so a checkpoint passed
/// by value would let a caller assert an adoption that never happened. Loading it by ref through the
/// guard's own storage — the same namespace `sink_term_lifecycle_chirho`'s header requires — makes
/// the cut proven rather than asserted.
pub(crate) fn revoke_and_accept_new_winner_term_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    group_chirho: &ConsistencyGroupIdChirho,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
    adopted_checkpoint_ref_chirho: &str,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    local_generation_guard_chirho: &LocalLeadershipGenerationGuardChirho<'_>,
) -> Result<VerifiedLawfulSinkTermAdvanceChirho, LawfulSinkTermAdvanceRefusalChirho> {
    let group_digest_chirho =
        consistency_group_digest_chirho(group_chirho).map_err(|error_chirho| {
            LawfulSinkTermAdvanceRefusalChirho::StorageChirho {
                detail_chirho: format!("{error_chirho:?}"),
            }
        })?;
    let adopted_checkpoint_chirho = load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
        writer_lock_guard_chirho.storage_chirho(),
        held_verifier_chirho,
        adopted_checkpoint_ref_chirho,
    )
    .map_err(|refusal_chirho| {
        LawfulSinkTermAdvanceRefusalChirho::AdoptedCutUnauthenticatedChirho {
            detail_chirho: format!("{refusal_chirho:?}"),
        }
    })?;
    let witness_winner_term_chirho = authorize_lawful_sink_term_advance_chirho(
        &group_digest_chirho,
        observation_chirho,
        &adopted_checkpoint_chirho,
        local_generation_guard_chirho.published_raft_term_chirho(),
    )?;

    let persisted_chirho = advance_accepted_winner_term_chirho(
        writer_lock_guard_chirho,
        &group_digest_chirho,
        witness_winner_term_chirho,
    )
    .map_err(
        |error_chirho| LawfulSinkTermAdvanceRefusalChirho::StorageChirho {
            detail_chirho: format!("{error_chirho:?}"),
        },
    )?;

    Ok(VerifiedLawfulSinkTermAdvanceChirho {
        group_digest_chirho: persisted_chirho.group_digest_chirho,
        accepted_term_chirho: persisted_chirho.highest_accepted_winner_term_chirho,
    })
}

/// Supersede the resident reconciliation head only after the adopted cut and convergence proof
/// name the same checkpoint. The prior head/checkpoint remains immutable and content-addressed;
/// removing the active ref is the release, so no presence-based granting object exists.
pub(crate) fn release_converged_reconciliation_hold_chirho(
    writer_lock_guard_chirho: &StableLedgerExclusiveLockGuardChirho<'_>,
    group_chirho: &ConsistencyGroupIdChirho,
    adopted_checkpoint_ref_chirho: &str,
    convergence_chirho: &ConvergedReadReplicaChirho,
    held_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), LawfulSinkTermAdvanceRefusalChirho> {
    // BIND THE CERTIFICATE TO THE CUT BEING SUPERSEDED by its `adopted_checkpoint_ref_chirho` field.
    // A genuine convergence certificate carries TWO refs: `checkpoint_ref_chirho` names the
    // PlanSealed plan cut where obligations were sealed, and `adopted_checkpoint_ref_chirho` names the
    // AdoptedHeld cut this door supersedes. They are never equal after a real adoption. This door
    // loads and phase-checks `adopted_checkpoint_ref_chirho` (AdoptedHeld) below, so it must bind the
    // certificate by that same field; binding by `checkpoint_ref_chirho` (the plan cut) would reject
    // every genuine certificate at this equality check. (This is an unauthenticated field getter — a
    // fabricated certificate can assert any value here — which is exactly why the signature
    // verification below is what makes the release lawful.)
    if convergence_chirho.adopted_checkpoint_ref_chirho() != adopted_checkpoint_ref_chirho {
        return Err(LawfulSinkTermAdvanceRefusalChirho::AdoptedCutIdentityMismatchChirho);
    }
    // BIND THE CERTIFICATE'S SIGNATURE, mirroring `restore_ordinary_writes_chirho`
    // (`write_restoration_chirho.rs`). The equality above is an unauthenticated field getter, so on
    // its own a fabricated certificate would release the hold. This re-verifies the certificate at
    // the authority boundary — v2 schema, the held verifier's own key id, and a signature over the
    // canonical bytes — before any head is superseded. A tampered signed field reserializes to
    // different canonical bytes and fails here, at the signature rather than at a later shape check.
    verify_signed_gd7_converged_read_replica_chirho(convergence_chirho, held_verifier_chirho)
        .map_err(|refusal_chirho| {
            LawfulSinkTermAdvanceRefusalChirho::ConvergenceCertificateUnverifiedChirho {
                detail_chirho: format!("{refusal_chirho:?}"),
            }
        })?;
    let checkpoint_chirho = load_authenticated_gd7_reconciliation_checkpoint_by_ref_chirho(
        writer_lock_guard_chirho.storage_chirho(),
        held_verifier_chirho,
        adopted_checkpoint_ref_chirho,
    )
    .map_err(|refusal_chirho| {
        LawfulSinkTermAdvanceRefusalChirho::AdoptedCutUnauthenticatedChirho {
            detail_chirho: format!("{refusal_chirho:?}"),
        }
    })?;
    if checkpoint_chirho.state_chirho.phase_chirho
        != Gd7ReconciliationPhaseChirho::AdoptedHeldChirho
    {
        return Err(
            LawfulSinkTermAdvanceRefusalChirho::AdoptedCutNotAdoptedChirho {
                phase_chirho: checkpoint_chirho.state_chirho.phase_chirho,
            },
        );
    }
    if checkpoint_chirho
        .identity_chirho
        .consistency_group_digest_chirho
        != consistency_group_digest_chirho(group_chirho).map_err(|error_chirho| {
            LawfulSinkTermAdvanceRefusalChirho::StorageChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?
    {
        return Err(LawfulSinkTermAdvanceRefusalChirho::AdoptedCutIdentityMismatchChirho);
    }
    let active_chirho = load_authenticated_active_gd7_reconciliation_for_group_chirho(
        writer_lock_guard_chirho.storage_chirho(),
        held_verifier_chirho,
        &checkpoint_chirho
            .identity_chirho
            .consistency_group_digest_chirho,
    )
    .map_err(
        |error_chirho| LawfulSinkTermAdvanceRefusalChirho::AdoptedCutUnauthenticatedChirho {
            detail_chirho: format!("{error_chirho:?}"),
        },
    )?
    // The adopted checkpoint authenticated; a MISSING active head here means the hold is already
    // released (e.g. a crash-and-retry after a prior release removed it). That is a distinct outcome
    // from an unauthenticated cut — nothing failed to authenticate — so it carries its own variant.
    .ok_or(LawfulSinkTermAdvanceRefusalChirho::ActiveHeadAlreadyAbsentChirho)?;
    if active_chirho.checkpoint_ref_chirho != adopted_checkpoint_ref_chirho {
        return Err(LawfulSinkTermAdvanceRefusalChirho::AdoptedCutIdentityMismatchChirho);
    }
    let head_path_chirho = crate::reconciliation_chirho::gd7_reconciliation_group_head_path_chirho(
        &checkpoint_chirho
            .identity_chirho
            .consistency_group_digest_chirho,
    )
    .map_err(
        |error_chirho| LawfulSinkTermAdvanceRefusalChirho::StorageChirho {
            detail_chirho: format!("{error_chirho:?}"),
        },
    )?;
    writer_lock_guard_chirho
        .storage_chirho()
        .remove_chirho(&head_path_chirho)
        .map_err(
            |error_chirho| LawfulSinkTermAdvanceRefusalChirho::StorageChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )
}
