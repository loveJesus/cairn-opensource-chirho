// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! When a node may move between lifecycle states — and the three things that must be true before it leaves.
//!
//! CF8 acceptance, verbatim: *"one manual adapter proves
//! provision/inspect/join/drain/retire/replace/upgrade composition, with plan hashes in evidence, **no
//! new placement during drain, leadership handoff before exit, and ownership-proven retirement**."*
//!
//! The **adapter** — the thing that actually calls a provider to create or destroy a machine — needs
//! I/O and is not here. What *is* here is the part that must be true regardless of provider: which
//! transitions are legal, and the three preconditions on exit. Keeping them in a pure core means
//! every adapter inherits the same rules instead of each re-deriving them, which is the whole point
//! of a provider-neutral port.
//!
//! **The three exit preconditions, and why each is a separate refusal:**
//!
//! 1. **No new placement during drain.** Draining means "work is leaving"; admitting a placement
//!    would race the drain and could leave the node non-empty forever. This is checked at
//!    *admission*, not only at retirement — by the time you are retiring, an admitted placement is
//!    already a problem.
//! 2. **Leadership handoff before exit.** Retiring a node that still holds leadership removes the
//!    authority with the machine. The handoff must have *happened*, not merely been requested.
//! 3. **Ownership-proven retirement.** Destroying a machine is irreversible, so cairn requires proof
//!    it owns the thing it is about to destroy. Without it, a mistaken or malicious plan could
//!    retire someone else's host.
//!
//! They are reported **separately and together** — an operator retiring a node needs the whole bill,
//! and a single "not ready" would hide which of three very different fixes is required.
//!
//! Pure: no I/O, no provider APIs, no clock. Every fact is supplied by the caller; this module never
//! discovers state, it only judges it.

pub mod lifecycle_attestation_chirho;
pub mod replacement_chirho;

use serde::{Deserialize, Serialize};

/// Where a node is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeLifecycleStateChirho {
    /// The machine exists; nothing has been verified about it.
    ProvisionedChirho,
    /// Capacity and identity have been checked; not yet serving.
    InspectedChirho,
    /// Serving: may accept placements.
    JoinedChirho,
    /// Work is leaving; accepts no new placements.
    DrainingChirho,
    /// Out of service.
    RetiredChirho,
}

/// A requested move.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LifecycleTransitionChirho {
    InspectChirho,
    JoinChirho,
    DrainChirho,
    RetireChirho,
}

/// What the caller knows about the node right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLifecycleFactsChirho {
    pub state_chirho: NodeLifecycleStateChirho,
    /// Does this node still hold cluster leadership?
    pub holds_leadership_chirho: bool,
    /// Has cairn proven it owns this machine?
    pub ownership_proven_chirho: bool,
    /// Placements still resident on the node.
    pub resident_placements_chirho: u32,
}

/// Why a transition is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionRefusalChirho {
    /// The lifecycle does not allow this move from this state.
    IllegalTransitionChirho {
        from_chirho: NodeLifecycleStateChirho,
        transition_chirho: LifecycleTransitionChirho,
    },
    /// Retiring while still holding leadership would take authority down with the machine.
    LeadershipNotHandedOffChirho,
    /// Retiring without proof cairn owns the machine.
    OwnershipNotProvenChirho,
    /// Retiring with work still on the node.
    PlacementsStillResidentChirho { remaining_chirho: u32 },
}

/// The state a legal transition lands in, or `None` if the move is not part of the lifecycle.
fn destination_chirho(
    from_chirho: NodeLifecycleStateChirho,
    transition_chirho: LifecycleTransitionChirho,
) -> Option<NodeLifecycleStateChirho> {
    use LifecycleTransitionChirho as TransitionChirho;
    use NodeLifecycleStateChirho as StateChirho;
    match (from_chirho, transition_chirho) {
        (StateChirho::ProvisionedChirho, TransitionChirho::InspectChirho) => {
            Some(StateChirho::InspectedChirho)
        }
        (StateChirho::InspectedChirho, TransitionChirho::JoinChirho) => {
            Some(StateChirho::JoinedChirho)
        }
        (StateChirho::JoinedChirho, TransitionChirho::DrainChirho) => {
            Some(StateChirho::DrainingChirho)
        }
        (StateChirho::DrainingChirho, TransitionChirho::RetireChirho) => {
            Some(StateChirho::RetiredChirho)
        }
        _ => None,
    }
}

/// May a new placement be admitted to this node?
///
/// Only a joined node accepts work. A draining node refuses — admitting during drain races the
/// drain and can leave the node non-empty indefinitely.
pub fn admits_new_placement_chirho(state_chirho: NodeLifecycleStateChirho) -> bool {
    matches!(state_chirho, NodeLifecycleStateChirho::JoinedChirho)
}

/// Every reason this transition is refused; empty means it may proceed.
pub fn transition_refusals_chirho(
    facts_chirho: NodeLifecycleFactsChirho,
    transition_chirho: LifecycleTransitionChirho,
) -> Vec<TransitionRefusalChirho> {
    let mut refusals_chirho = Vec::new();
    if destination_chirho(facts_chirho.state_chirho, transition_chirho).is_none() {
        refusals_chirho.push(TransitionRefusalChirho::IllegalTransitionChirho {
            from_chirho: facts_chirho.state_chirho,
            transition_chirho,
        });
    }
    // The exit preconditions apply to retirement only, and are checked independently so an operator
    // sees every fix required rather than the first one.
    if transition_chirho == LifecycleTransitionChirho::RetireChirho {
        if facts_chirho.holds_leadership_chirho {
            refusals_chirho.push(TransitionRefusalChirho::LeadershipNotHandedOffChirho);
        }
        if !facts_chirho.ownership_proven_chirho {
            refusals_chirho.push(TransitionRefusalChirho::OwnershipNotProvenChirho);
        }
        if facts_chirho.resident_placements_chirho > 0 {
            refusals_chirho.push(TransitionRefusalChirho::PlacementsStillResidentChirho {
                remaining_chirho: facts_chirho.resident_placements_chirho,
            });
        }
    }
    refusals_chirho
}

/// Apply a transition, returning the new state or the reasons it was refused.
pub fn apply_transition_chirho(
    facts_chirho: NodeLifecycleFactsChirho,
    transition_chirho: LifecycleTransitionChirho,
) -> Result<NodeLifecycleStateChirho, Vec<TransitionRefusalChirho>> {
    let refusals_chirho = transition_refusals_chirho(facts_chirho, transition_chirho);
    if !refusals_chirho.is_empty() {
        return Err(refusals_chirho);
    }
    destination_chirho(facts_chirho.state_chirho, transition_chirho).ok_or(refusals_chirho)
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
