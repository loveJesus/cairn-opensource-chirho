// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A topology plan is checked against the grant that authorizes it — and may never raise its own bounds.
//!
//! CF8 acceptance, verbatim: *"the topology-plan principal carries a signed grant with explicit
//! node-count, spend-rate, provider-allowlist, and minimum-control/storage-floor bounds; over-bound
//! plans, floor-breaking plans, and self-modification are refused … and app workers may scale to zero
//! independently of the protected three-triple floor."*
//!
//! **Self-modification is the load-bearing refusal.** Every other bound here is a number a planner
//! could legitimately approach. But a plan that carries a *new grant* is not asking for capacity — it
//! is asking to become its own authority, and no ceiling constrains a planner that can raise its own
//! ceiling. So it is refused unconditionally, before any bound is even evaluated, and modelled
//! structurally: `proposed_grant_chirho` exists on the plan **only so that an attempt is
//! representable and therefore refusable**. A design where a plan simply could not express a new
//! grant would look safer and would silently pass an attempt made through some other door.
//!
//! **Roles do not substitute for one another** — the same no-exchange-rate rule as
//! [`crate::capacity_chirho::capacity_dominance_chirho`]. A hundred workers do not cover a missing control node.
//! This is what makes "workers may scale to zero" safe to allow: the floors are counted **per role**,
//! so an empty worker fleet cannot breach a control or storage floor, and a full worker fleet cannot
//! satisfy one. A naive total-node count would get both of those backwards — refusing a legitimate
//! scale-to-zero and admitting a plan that had drained its control plane.
//!
//! Pure: no I/O, no provider APIs, no money movement. **Spend rate here is a declared number checked
//! against a declared ceiling** — this module authorizes nothing and spends nothing. Signature
//! verification of the grant is the caller's.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// What a node is for. Roles are protected independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeRoleChirho {
    /// Carries authority/control-plane duty; protected by a floor.
    ControlChirho,
    /// Carries durable data; protected by a floor.
    StorageChirho,
    /// Runs app work; may scale to zero.
    WorkerChirho,
}

/// The bounds a signed grant places on any plan that cites it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyGrantChirho {
    pub grant_id_chirho: String,
    pub max_nodes_chirho: u32,
    pub max_spend_rate_micros_per_hour_chirho: u64,
    pub allowed_providers_chirho: BTreeSet<String>,
    pub minimum_control_nodes_chirho: u32,
    pub minimum_storage_nodes_chirho: u32,
}

/// One node a plan asks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedNodeChirho {
    pub provider_chirho: String,
    pub role_chirho: NodeRoleChirho,
}

/// A desired-state topology plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredTopologyPlanChirho {
    /// The grant this plan claims authority under.
    pub cited_grant_id_chirho: String,
    pub nodes_chirho: Vec<PlannedNodeChirho>,
    pub spend_rate_micros_per_hour_chirho: u64,
    /// A grant the plan proposes to install. Present ONLY so a self-modification attempt is
    /// representable and therefore refusable; it is never honoured.
    pub proposed_grant_chirho: Option<TopologyGrantChirho>,
}

/// Why a plan is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanRefusalChirho {
    /// The plan proposes to change the grant that bounds it.
    SelfModificationChirho,
    /// The plan cites a grant other than the one it was checked against.
    GrantMismatchChirho {
        cited_chirho: String,
        checked_chirho: String,
    },
    NodeCountOverBoundChirho {
        limit_chirho: u32,
        planned_chirho: u32,
    },
    SpendRateOverBoundChirho {
        limit_micros_per_hour_chirho: u64,
        planned_micros_per_hour_chirho: u64,
    },
    ProviderNotAllowedChirho {
        provider_chirho: String,
    },
    RoleFloorBreachedChirho {
        role_chirho: NodeRoleChirho,
        minimum_chirho: u32,
        planned_chirho: u32,
    },
}

/// How many nodes the plan assigns to one role.
pub fn nodes_in_role_chirho(
    plan_chirho: &DesiredTopologyPlanChirho,
    role_chirho: NodeRoleChirho,
) -> u32 {
    plan_chirho
        .nodes_chirho
        .iter()
        .filter(|node_chirho| node_chirho.role_chirho == role_chirho)
        .count()
        .min(u32::MAX as usize) as u32
}

/// Every reason this plan is refused under this grant; empty means it may be applied.
///
/// Self-modification is checked first and reported alone: a plan trying to become its own authority
/// should not have its capacity numbers discussed as though the rest were a negotiation.
pub fn plan_refusals_chirho(
    plan_chirho: &DesiredTopologyPlanChirho,
    grant_chirho: &TopologyGrantChirho,
) -> Vec<PlanRefusalChirho> {
    if plan_chirho.proposed_grant_chirho.is_some() {
        return vec![PlanRefusalChirho::SelfModificationChirho];
    }
    let mut refusals_chirho = Vec::new();
    if plan_chirho.cited_grant_id_chirho != grant_chirho.grant_id_chirho {
        refusals_chirho.push(PlanRefusalChirho::GrantMismatchChirho {
            cited_chirho: plan_chirho.cited_grant_id_chirho.clone(),
            checked_chirho: grant_chirho.grant_id_chirho.clone(),
        });
    }
    let planned_nodes_chirho = plan_chirho.nodes_chirho.len().min(u32::MAX as usize) as u32;
    if planned_nodes_chirho > grant_chirho.max_nodes_chirho {
        refusals_chirho.push(PlanRefusalChirho::NodeCountOverBoundChirho {
            limit_chirho: grant_chirho.max_nodes_chirho,
            planned_chirho: planned_nodes_chirho,
        });
    }
    if plan_chirho.spend_rate_micros_per_hour_chirho
        > grant_chirho.max_spend_rate_micros_per_hour_chirho
    {
        refusals_chirho.push(PlanRefusalChirho::SpendRateOverBoundChirho {
            limit_micros_per_hour_chirho: grant_chirho.max_spend_rate_micros_per_hour_chirho,
            planned_micros_per_hour_chirho: plan_chirho.spend_rate_micros_per_hour_chirho,
        });
    }
    let mut refused_providers_chirho = BTreeSet::new();
    for node_chirho in &plan_chirho.nodes_chirho {
        if !grant_chirho
            .allowed_providers_chirho
            .contains(&node_chirho.provider_chirho)
            && refused_providers_chirho.insert(node_chirho.provider_chirho.clone())
        {
            refusals_chirho.push(PlanRefusalChirho::ProviderNotAllowedChirho {
                provider_chirho: node_chirho.provider_chirho.clone(),
            });
        }
    }
    // Floors are per role; a surplus in one role never covers a shortfall in another, which is
    // exactly what lets workers reach zero without breaching anything.
    for (role_chirho, minimum_chirho) in [
        (
            NodeRoleChirho::ControlChirho,
            grant_chirho.minimum_control_nodes_chirho,
        ),
        (
            NodeRoleChirho::StorageChirho,
            grant_chirho.minimum_storage_nodes_chirho,
        ),
    ] {
        let planned_chirho = nodes_in_role_chirho(plan_chirho, role_chirho);
        if planned_chirho < minimum_chirho {
            refusals_chirho.push(PlanRefusalChirho::RoleFloorBreachedChirho {
                role_chirho,
                minimum_chirho,
                planned_chirho,
            });
        }
    }
    refusals_chirho
}

#[cfg(test)]
#[path = "topology_grant_tests_chirho.rs"]
mod topology_grant_tests_chirho;
