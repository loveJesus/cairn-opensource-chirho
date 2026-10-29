// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.3 roster-convergence: the PURE plan (slice 2) that diffs a running group's LIVE membership against
//! the VERIFIED derived target roster and yields the typed steps that move the group toward the roster.
//!
//! The roster drives membership ONE-WAY: this crate reads the fail-closed derived target
//! (`ElectorMemberChirho`, the output of A2's `derive_elector_config_chirho`) and the live `ConfState`
//! (voter + learner ids from the elector's `membership_snapshot_chirho`), and produces a
//! [`ConvergencePlanChirho`]. It NEVER writes the roster, NEVER mutates the elector, and holds no
//! head-mutation authority — the safe apply that drives these steps through the elector's
//! learner→promote / quorum-checked-remove primitives is slice 3.
//!
//! **VERIFIED-TARGET-ONLY:** `target_members_chirho` MUST be the output of a fail-closed
//! `derive_elector_config_chirho` — a tampered roster cannot reach here as a valid target, so the plan
//! trusts the target's identities and only diffs. The plan is deterministic (raft-id order) and
//! fail-closed (an empty, zero-id, or duplicate-id target refuses).

use anyhow::{bail, Result};
use cairn_roster_config_chirho::ElectorMemberChirho;
use std::collections::BTreeSet;

/// One target member the plan wants in the voter set, carrying its raft id + pubkey hex (= the elector's
/// `NodeIdChirho` inner, so slice 3 can add it to the authenticated peer set as it joins).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConvergenceMemberChirho {
    pub raft_id_chirho: u64,
    pub pubkey_hex_chirho: String,
}

/// The steps that move a running group ONE convergence pass toward the verified target roster,
/// PRE-CLASSIFIED so the apply (slice 3) is a pure executor that never re-reads the live state or guesses
/// add-vs-promote. Slice 3 drives them safely: new_voters (adds) BEFORE removes, each new voter as a
/// learner then promote-when-caught-up, each promotion straight to voter, each remove behind its quorum
/// precheck, ONE change committed at a time — so quorum never dips.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConvergencePlanChirho {
    /// Target members not in the group AT ALL (neither voter nor learner), sorted by raft id — slice 3
    /// adds each as a learner, then promotes it once caught up.
    pub new_voters_chirho: Vec<ConvergenceMemberChirho>,
    /// Target members that are ALREADY live learners, sorted by raft id — slice 3 just promotes them.
    /// Classified HERE (in the pure plan), not in the apply, because `add_learner` on an existing learner
    /// is a raft ConfChange error — so the plan tells the executor promote-not-add and it never guesses.
    pub promotions_chirho: Vec<ConvergenceMemberChirho>,
    /// Live group members (voters + learners) NOT in the target, sorted ascending — to be removed.
    pub removes_chirho: Vec<u64>,
}

impl ConvergencePlanChirho {
    /// True when the group already matches the target (nothing to add, promote, or remove) — the
    /// IDEMPOTENT case, so re-running convergence on a converged group is a no-op.
    pub fn is_converged_chirho(&self) -> bool {
        self.new_voters_chirho.is_empty()
            && self.promotions_chirho.is_empty()
            && self.removes_chirho.is_empty()
    }
}

/// Diff the live membership against the verified derived target into a [`ConvergencePlanChirho`].
///
/// `target_members_chirho` MUST be the output of a fail-closed `derive_elector_config_chirho`
/// (VERIFIED-TARGET-ONLY). `live_voter_ids_chirho` / `live_learner_ids_chirho` are the running
/// `ConfState` (from the elector's `membership_snapshot_chirho`).
///
/// Each target member is classified against the live state: already a live voter → no action; a live
/// learner → **promotion**; in neither set → **new_voter** (add-as-learner then promote). Anything live
/// (voter or learner) not in the target → **remove**.
///
/// Deterministic (raft-id order, so two nodes plan identically) and fail-closed: an EMPTY target (would
/// strand the group with no voters), a zero raft id (raft-rs reserves 0), or a duplicate target raft id
/// all refuse rather than emit a dangerous plan.
pub fn plan_convergence_chirho(
    target_members_chirho: &[ElectorMemberChirho],
    live_voter_ids_chirho: &[u64],
    live_learner_ids_chirho: &[u64],
) -> Result<ConvergencePlanChirho> {
    // Fail-closed: never plan toward an empty target — that would remove every voter and strand the group.
    if target_members_chirho.is_empty() {
        bail!("convergence: refusing a plan toward an EMPTY target (would remove every voter)");
    }
    // The verified target already guarantees unique, non-zero raft ids (A2-R1); re-check defensively so a
    // hand-built (non-derived) target can never make the plan double-add or touch reserved id 0.
    let mut target_ids_chirho: BTreeSet<u64> = BTreeSet::new();
    for member_chirho in target_members_chirho {
        if member_chirho.raft_id_chirho == 0 {
            bail!("convergence: target member has raft id 0 (reserved); refusing");
        }
        if !target_ids_chirho.insert(member_chirho.raft_id_chirho) {
            bail!(
                "convergence: duplicate raft id {} in the target; refusing",
                member_chirho.raft_id_chirho
            );
        }
    }

    let live_voters_chirho: BTreeSet<u64> = live_voter_ids_chirho.iter().copied().collect();
    let live_learners_chirho: BTreeSet<u64> = live_learner_ids_chirho.iter().copied().collect();

    // Classify each target member against the live state (pre-split, so slice 3 never guesses add-vs-
    // promote and never `add_learner`s a node that is already a learner).
    let mut new_voters_chirho: Vec<ConvergenceMemberChirho> = Vec::new();
    let mut promotions_chirho: Vec<ConvergenceMemberChirho> = Vec::new();
    for member_chirho in target_members_chirho {
        if live_voters_chirho.contains(&member_chirho.raft_id_chirho) {
            continue; // already a voter — no action
        }
        let entry_chirho = ConvergenceMemberChirho {
            raft_id_chirho: member_chirho.raft_id_chirho,
            pubkey_hex_chirho: member_chirho.pubkey_chirho.clone(),
        };
        if live_learners_chirho.contains(&member_chirho.raft_id_chirho) {
            promotions_chirho.push(entry_chirho); // already a learner — just promote
        } else {
            new_voters_chirho.push(entry_chirho); // not in the group — add as learner, then promote
        }
    }
    new_voters_chirho.sort_by_key(|member_chirho| member_chirho.raft_id_chirho);
    promotions_chirho.sort_by_key(|member_chirho| member_chirho.raft_id_chirho);

    // REMOVES: live voters + learners not in the target (union is sorted + unique), ascending.
    let removes_chirho: Vec<u64> = live_voters_chirho
        .union(&live_learners_chirho)
        .copied()
        .filter(|id_chirho| !target_ids_chirho.contains(id_chirho))
        .collect();

    Ok(ConvergencePlanChirho {
        new_voters_chirho,
        promotions_chirho,
        removes_chirho,
    })
}

pub mod apply_chirho;
pub use apply_chirho::{apply_one_convergence_step_chirho, converge_chirho, ConvergenceStepChirho};

pub mod preferred_leader_chirho;
pub use preferred_leader_chirho::{re_home_step_chirho, ReHomeStepChirho};

#[cfg(test)]
mod tests_chirho;
