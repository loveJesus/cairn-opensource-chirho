// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The planner: authority is checked before any work is planned, and the result must still be survivable.
//!
//! The registry answers "may this placement land on this node". The planner answers the question
//! above it — **"is this change permitted, and does the topology it produces still tolerate a
//! failure"** — and it is where the grant and the replacement rules finally have a caller.
//!
//! **AUTHORITY FIRST, AND NOTHING ELSE IS EVEN COMPUTED.** If the plan exceeds its grant, the planner
//! returns those refusals **alone** and plans nothing. That ordering is the point, not an
//! optimisation: computing a replacement sequence for an unauthorised plan produces a *ready-to-run
//! set of steps* whose only protection is that some later caller remembers to check a separate
//! result. Refusing before planning means the steps do not exist to be misused.
//!
//! **AND THE OUTCOME MUST STILL BE SURVIVABLE.** A plan can satisfy every bound in its grant and still
//! leave the fleet in one failure domain — the grant bounds *cost and count*, spread bounds
//! *survival*, and neither implies the other. So the resulting layout is checked against the minimum
//! spread as a separate clause, and a plan that is affordable but fragile is refused.
//!
//! Pure: no I/O, no provider APIs, no clock. The planner reads a registry value and returns steps for
//! someone else to execute.

use super::topology_grant_attestation_chirho::VerifiedTopologyGrantChirho;
use super::topology_grant_chirho::{
    plan_refusals_chirho, DesiredTopologyPlanChirho, PlanRefusalChirho,
};
use crate::capacity_chirho::capacity_dominance_chirho::{
    AllocatableCapacityChirho, ReplacementRefusalChirho,
};
use crate::failure_domain_chirho::{MinimumSpreadChirho, SpreadRefusalChirho};
use crate::node_lifecycle_chirho::replacement_chirho::{
    plan_replacement_chirho, ReplacementStepChirho,
};
use crate::placement_registry_chirho::PlacementRegistryChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Why a topology change is refused. The three sources stay distinct so an operator knows whether to
/// raise a grant, pick a different candidate, or add a failure domain — three very different actions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerRefusalChirho {
    /// The plan exceeds the authority it cites.
    GrantChirho(PlanRefusalChirho),
    /// The replacement candidate does not dominate the node it would replace.
    ReplacementChirho(ReplacementRefusalChirho),
    /// The topology the plan produces does not tolerate the required failure spread.
    SpreadChirho(SpreadRefusalChirho),
    /// The plan names a node the registry does not know.
    UnknownIncumbentChirho { node_id_chirho: String },
}

/// A permitted change: the ordered steps to carry out, for a caller that executes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyChangeChirho {
    pub replacement_steps_chirho: Vec<(String, Vec<ReplacementStepChirho>)>,
}

/// Validate a desired topology change and, if permitted, return its steps.
///
/// Order is load-bearing: grant → replacement fitness → resulting spread. An unauthorised plan gets
/// its grant refusals and nothing else.
pub fn plan_topology_change_chirho(
    registry_chirho: &PlacementRegistryChirho,
    plan_chirho: &DesiredTopologyPlanChirho,
    grant_chirho: &VerifiedTopologyGrantChirho,
    replacements_chirho: &[(String, AllocatableCapacityChirho, BTreeSet<String>)],
    minimum_spread_chirho: MinimumSpreadChirho,
) -> Result<TopologyChangeChirho, Vec<PlannerRefusalChirho>> {
    // 1. AUTHORITY FIRST. Nothing below runs for an over-bound or self-modifying plan.
    let grant_refusals_chirho = plan_refusals_chirho(plan_chirho, grant_chirho.grant_chirho());
    if !grant_refusals_chirho.is_empty() {
        return Err(grant_refusals_chirho
            .into_iter()
            .map(PlannerRefusalChirho::GrantChirho)
            .collect());
    }

    let mut refusals_chirho = Vec::new();
    let mut steps_chirho = Vec::new();

    // 2. Each replacement candidate must dominate the node it replaces.
    for (incumbent_id_chirho, candidate_capacity_chirho, candidate_features_chirho) in
        replacements_chirho
    {
        let Some(incumbent_chirho) = registry_chirho.node_chirho(incumbent_id_chirho) else {
            refusals_chirho.push(PlannerRefusalChirho::UnknownIncumbentChirho {
                node_id_chirho: incumbent_id_chirho.clone(),
            });
            continue;
        };
        match plan_replacement_chirho(
            incumbent_chirho.allocatable_chirho(),
            &BTreeSet::new(),
            candidate_capacity_chirho,
            candidate_features_chirho,
        ) {
            Ok(plan_steps_chirho) => {
                steps_chirho.push((incumbent_id_chirho.clone(), plan_steps_chirho.to_vec()))
            }
            Err(replacement_refusals_chirho) => refusals_chirho.extend(
                replacement_refusals_chirho
                    .into_iter()
                    .map(PlannerRefusalChirho::ReplacementChirho),
            ),
        }
    }

    // 3. The topology this produces must still tolerate the required spread. Affordable is not the
    //    same as survivable.
    refusals_chirho.extend(
        registry_chirho
            .spread_refusals_chirho(minimum_spread_chirho)
            .into_iter()
            .map(PlannerRefusalChirho::SpreadChirho),
    );

    if refusals_chirho.is_empty() {
        Ok(TopologyChangeChirho {
            replacement_steps_chirho: steps_chirho,
        })
    } else {
        Err(refusals_chirho)
    }
}

#[cfg(test)]
#[path = "topology_planner_tests_chirho.rs"]
mod topology_planner_tests_chirho;
