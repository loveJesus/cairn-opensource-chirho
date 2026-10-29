// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Replacing a node is a COMPOSITION of two lifecycles, and the replacement joins before the incumbent drains.
//!
//! CF8 asks that *"one manual adapter proves provision/inspect/join/drain/retire/replace/upgrade
//! composition."* Replace is the one that is not a single transition: it is two lifecycles run against
//! each other, and the whole value is in their **interleaving**.
//!
//! **THE INVARIANT: capacity never dips.** The candidate must be **serving** before the incumbent
//! stops. Drain-then-join is the intuitive order and it is wrong — it leaves the cluster short by one
//! node for the entire provision-and-inspect window, which is exactly when a second failure is least
//! survivable. So the plan is fixed: provision → inspect → **join candidate** → drain incumbent →
//! retire incumbent, and the step order itself is the property under test.
//!
//! **This is also where [`super::super::capacity_chirho::capacity_dominance_chirho`] finally has a caller.** A
//! replacement must DOMINATE — `>=` in every hard dimension plus feature containment — because
//! swapping in a node that is merely "better overall" silently sheds capacity in whichever dimension
//! it happens to be worse at. Refusals come straight from the dominance rule, so a caller gets the
//! failing dimension and both numbers rather than a bare no.
//!
//! Pure: no I/O, no provider APIs. A "manual adapter" is one that carries these steps out by hand and
//! records the evidence; this module owns only what must be true regardless of who executes them.

use super::super::capacity_chirho::capacity_dominance_chirho::{
    replacement_refusals_chirho, AllocatableCapacityChirho, ReplacementRefusalChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// One ordered step of a node replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplacementStepChirho {
    ProvisionCandidateChirho,
    InspectCandidateChirho,
    /// The candidate begins serving. Everything after this point is safe to lose the incumbent.
    JoinCandidateChirho,
    DrainIncumbentChirho,
    RetireIncumbentChirho,
}

/// The fixed, ordered replacement plan. Exposed as a constant so the ORDER is a value a test can
/// assert against, not a shape re-derived inside each caller.
pub const REPLACEMENT_PLAN_CHIRHO: [ReplacementStepChirho; 5] = [
    ReplacementStepChirho::ProvisionCandidateChirho,
    ReplacementStepChirho::InspectCandidateChirho,
    ReplacementStepChirho::JoinCandidateChirho,
    ReplacementStepChirho::DrainIncumbentChirho,
    ReplacementStepChirho::RetireIncumbentChirho,
];

/// Plan a replacement, or return every reason the candidate is unfit.
///
/// The candidate must dominate the incumbent in all three hard dimensions and carry its features.
/// A returned plan is always [`REPLACEMENT_PLAN_CHIRHO`] — there is no variant ordering, because the
/// order is the safety property.
pub fn plan_replacement_chirho(
    incumbent_capacity_chirho: &AllocatableCapacityChirho,
    incumbent_features_chirho: &BTreeSet<String>,
    candidate_capacity_chirho: &AllocatableCapacityChirho,
    candidate_features_chirho: &BTreeSet<String>,
) -> Result<[ReplacementStepChirho; 5], Vec<ReplacementRefusalChirho>> {
    let refusals_chirho = replacement_refusals_chirho(
        incumbent_capacity_chirho,
        candidate_capacity_chirho,
        incumbent_features_chirho,
        candidate_features_chirho,
    );
    if !refusals_chirho.is_empty() {
        return Err(refusals_chirho);
    }
    Ok(REPLACEMENT_PLAN_CHIRHO)
}

/// Is the incumbent safe to drain at this point in the plan? True only once the candidate has joined.
///
/// A manual adapter calls this before touching the incumbent, so an operator working the steps out of
/// order is refused by the same rule that orders the plan.
pub fn incumbent_safe_to_drain_chirho(completed_chirho: &[ReplacementStepChirho]) -> bool {
    completed_chirho.contains(&ReplacementStepChirho::JoinCandidateChirho)
}

#[cfg(test)]
#[path = "replacement_tests_chirho.rs"]
mod replacement_tests_chirho;
