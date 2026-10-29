// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.3 slice 3: the safe convergence APPLY. Given a running elector and the verified derived target, it
//! proposes the ONE next safe step toward the target — a pure executor over the pre-classified slice-2
//! plan — and `converge_chirho` loops that step plus a caller-supplied transport drive until the group
//! matches the target. Every primitive here is election/membership-only: it mints no fence and moves no
//! head, so convergence stays inside the shadow (non-authoritative) envelope.

use crate::plan_convergence_chirho;
use anyhow::Result;
use cairn_roster_config_chirho::ElectorMemberChirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::{
    AddLearnerOutcomeChirho, PromoteOutcomeChirho, RaftWriterElectorChirho, RemoveOutcomeChirho,
};
use std::collections::BTreeSet;

/// What one convergence step did — or why it made no membership change (always surfaced, never wedged).
/// `Serialize`/`Deserialize` so the A1.5 `/converge-chirho` control endpoint can return the executed step
/// as its JSON evidence body (drill artifacts come from responses, not log scraping).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConvergenceStepChirho {
    /// A brand-new target member was authenticated and proposed as a LEARNER (learner-before-voter).
    AddedLearnerChirho { raft_id_chirho: u64 },
    /// A caught-up learner was promoted to a voter.
    PromotedChirho { raft_id_chirho: u64 },
    /// A promotion target is not yet caught up — no change this step; the loop drives + retries.
    AwaitingCatchupChirho { raft_id_chirho: u64 },
    /// A group member absent from the target was removed (and dropped from the authenticated set).
    RemovedChirho { raft_id_chirho: u64 },
    /// The removal target is the current leader — leadership must transfer first (R4); no change made.
    BlockedOnLeaderTransferChirho { leader_raft_id_chirho: u64 },
    /// Removing the target would drop below a live majority — refused (quorum never breaks); surfaced.
    RemoveRefusedWouldBreakQuorumChirho { raft_id_chirho: u64 },
    /// The group already matches the target — nothing to do.
    ConvergedChirho,
}

/// Propose the ONE next safe step that moves `elector_chirho`'s running group toward the verified
/// `target_members_chirho`.
///
/// Reads the live `ConfState`, reconciles the auth set DOWN to it (drop any id that has left the group),
/// plans (slice 2, pre-classified), and applies the highest-priority step: NEW_VOTERS (authenticate the
/// peer, then `add_learner` — never a voter directly) BEFORE PROMOTIONS (`promote_learner_if_caught_up`)
/// BEFORE REMOVES (`remove_node`, quorum-checked). Adds-before-removes + learner-before-voter + one change
/// at a time ⇒ quorum never dips; a departing node is dropped from the auth set only AFTER it leaves
/// ConfState (so its ack can still commit its own removal). Every call re-reads live state, so a stale
/// plan self-corrects. This is the pure executor over the plan; the driving loop is [`converge_chirho`].
/// It mints nothing and moves no head.
pub fn apply_one_convergence_step_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    target_members_chirho: &[ElectorMemberChirho],
) -> Result<ConvergenceStepChirho> {
    let (voters_chirho, learners_chirho) = elector_chirho.membership_snapshot_chirho()?;

    // RECONCILE-DOWN (invariant: the auth set ⊇ the live ConfState members). A departed node leaves
    // ConfState only at APPLY (post-commit), and it MUST stay authenticated until then — its ack can be
    // part of the OLD-config majority that commits its OWN removal, so auth-excluding it any earlier could
    // starve that majority and STALL the removal. So drop an authenticated id ONLY once it has actually
    // left voters∪learners. This runs every step, so it also self-heals any auth-set drift. (Adds
    // include-before-add below, which only ADDS to the set — it never drops a current member.)
    let live_ids_chirho: BTreeSet<u64> = voters_chirho
        .iter()
        .chain(learners_chirho.iter())
        .copied()
        .collect();
    let current_auth_chirho = elector_chirho.authenticated_members_chirho();
    let reconciled_chirho: Vec<(u64, NodeIdChirho)> = current_auth_chirho
        .iter()
        .filter(|(id_chirho, _)| live_ids_chirho.contains(id_chirho))
        .cloned()
        .collect();
    if reconciled_chirho.len() != current_auth_chirho.len() {
        elector_chirho.update_members_chirho(reconciled_chirho)?;
    }

    let plan_chirho =
        plan_convergence_chirho(target_members_chirho, &voters_chirho, &learners_chirho)?;

    if let Some(new_voter_chirho) = plan_chirho.new_voters_chirho.first() {
        // LIVE-PEER-SET ATOMIC (add side): authenticate the joining peer BEFORE proposing its learner-add,
        // so it can never be rejected the instant it starts replicating (no reject-added window).
        let mut auth_chirho = elector_chirho.authenticated_members_chirho();
        if !auth_chirho
            .iter()
            .any(|(id_chirho, _)| *id_chirho == new_voter_chirho.raft_id_chirho)
        {
            auth_chirho.push((
                new_voter_chirho.raft_id_chirho,
                NodeIdChirho(new_voter_chirho.pubkey_hex_chirho.clone()),
            ));
            elector_chirho.update_members_chirho(auth_chirho)?;
        }
        // LEARNER-BEFORE-VOTER: add as a non-voting learner, never straight as a voter, so a lagging new
        // node cannot count toward quorum. (Already-a-learner / already-a-voter are safe no-ops the
        // re-plan reclassifies.)
        match elector_chirho.add_learner_chirho(new_voter_chirho.raft_id_chirho)? {
            AddLearnerOutcomeChirho::ProposedChirho(_)
            | AddLearnerOutcomeChirho::AlreadyLearnerChirho { .. }
            | AddLearnerOutcomeChirho::AlreadyVoterChirho { .. } => {
                Ok(ConvergenceStepChirho::AddedLearnerChirho {
                    raft_id_chirho: new_voter_chirho.raft_id_chirho,
                })
            }
        }
    } else if let Some(promotion_chirho) = plan_chirho.promotions_chirho.first() {
        match elector_chirho.promote_learner_if_caught_up_chirho(promotion_chirho.raft_id_chirho)? {
            PromoteOutcomeChirho::ProposedChirho(_) => Ok(ConvergenceStepChirho::PromotedChirho {
                raft_id_chirho: promotion_chirho.raft_id_chirho,
            }),
            // Not caught up (or no progress tracked yet) — defer, never wedge; the loop drives + retries.
            PromoteOutcomeChirho::NotCaughtUpChirho { .. }
            | PromoteOutcomeChirho::UnknownMemberChirho => {
                Ok(ConvergenceStepChirho::AwaitingCatchupChirho {
                    raft_id_chirho: promotion_chirho.raft_id_chirho,
                })
            }
        }
    } else if let Some(&remove_id_chirho) = plan_chirho.removes_chirho.first() {
        match elector_chirho.remove_node_chirho(remove_id_chirho)? {
            // Do NOT auth-exclude the departing node here: the removal commits at APPLY (post-commit), and
            // until then it is still a ConfState voter whose ack can be part of the old-config majority
            // that commits its own removal — excluding it now could stall that commit. The reconcile-down
            // at the top drops it one iteration after it has actually left ConfState (never rejecting a
            // still-voting member).
            RemoveOutcomeChirho::ProposedChirho(_) => Ok(ConvergenceStepChirho::RemovedChirho {
                raft_id_chirho: remove_id_chirho,
            }),
            RemoveOutcomeChirho::MustTransferLeadershipFirstChirho {
                leader_raft_id_chirho,
            } => Ok(ConvergenceStepChirho::BlockedOnLeaderTransferChirho {
                leader_raft_id_chirho,
            }),
            // QUORUM NEVER BREAKS: a remove that would drop below a live majority is refused, surfaced.
            RemoveOutcomeChirho::WouldBreakQuorumChirho { .. } => {
                Ok(ConvergenceStepChirho::RemoveRefusedWouldBreakQuorumChirho {
                    raft_id_chirho: remove_id_chirho,
                })
            }
        }
    } else {
        Ok(ConvergenceStepChirho::ConvergedChirho)
    }
}

/// Loop: apply one safe step, let the caller DRIVE the transport (deliver messages / tick / let learners
/// catch up) so the proposed change commits, then re-plan against fresh live state — until the group
/// matches the target or `max_steps_chirho` is exhausted (never wedged). Returns the final step:
/// `ConvergedChirho` on success, or the last non-converged step if the bound was hit (e.g. a learner that
/// never catches up, or a remove blocked on a leader transfer the caller must perform).
pub fn converge_chirho<DriveChirho: FnMut()>(
    elector_chirho: &RaftWriterElectorChirho,
    target_members_chirho: &[ElectorMemberChirho],
    mut drive_between_steps_chirho: DriveChirho,
    max_steps_chirho: usize,
) -> Result<ConvergenceStepChirho> {
    let mut last_chirho = ConvergenceStepChirho::ConvergedChirho;
    for _ in 0..max_steps_chirho {
        last_chirho = apply_one_convergence_step_chirho(elector_chirho, target_members_chirho)?;
        if matches!(last_chirho, ConvergenceStepChirho::ConvergedChirho) {
            return Ok(last_chirho);
        }
        // Let the proposed change commit (and any learner replicate) before re-planning.
        drive_between_steps_chirho();
    }
    Ok(last_chirho)
}

#[cfg(test)]
mod tests_chirho;
