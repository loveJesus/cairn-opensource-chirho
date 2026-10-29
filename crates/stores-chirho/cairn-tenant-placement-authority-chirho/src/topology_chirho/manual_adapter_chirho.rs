// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The manual adapter: what to do, in what order, bound to the plan it came from.
//!
//! `plan_topology_change_chirho`'s own header says it "returns steps for someone else to execute".
//! This is that someone else — and it is the piece CF8 clause 9 names when it asks that a signed
//! desired-state plan be *applied only through the placement/migration and provider-neutral
//! node-lifecycle ports*, with *one manual adapter proving provision/inspect/join/drain/retire/replace
//! composition, with plan hashes in evidence*.
//!
//! **MANUAL is a scope claim, not modesty.** Clause 15 disclaims live provider APIs, so this adapter
//! provisions nothing and talks to no provider. What it does is compute and ORDER the steps and bind
//! each one to the resolved plan's digest; a human authorizes each step by signing a lifecycle
//! transition, and the durable lifecycle store enforces the order through its from-state check and
//! sequence high-water mark. So no step can be taken out of order even if the operator tries, and no
//! step is signed against a bare intention — every one names the plan it came from.
//!
//! **Everything it reasons from comes off disk through a signature check**: the grant from the durable
//! grant store (replay-protected, so a superseded ceiling cannot authorize this), the plan from the
//! plan store's resolver (resolved AND re-hashed, so a digest naming nothing is refused), and the
//! registry from the capacity, lifecycle and usage logs.
//!
//! **AUTHORITY-FIRST PROPAGATES.** The planner returns refusals ALONE for an over-bound or
//! self-modifying plan and computes no steps; this adapter emits none either. A ready-to-run step list
//! for an unauthorised plan is exactly the artifact that ordering exists to prevent, and it would be
//! more dangerous coming from here than from the planner, because these steps look actionable.
//!
//! **AND THE PRICED MAXIMUM IS CHECKED BEFORE ANY PROVISION STEP EXISTS.** CF8 clause 11 asks that a
//! budget *"reserves a priced maximum BEFORE simulated provision"*, and this is where those two halves
//! finally meet: the change's price is checked against the budget replayed from its signed events, and
//! a change the budget cannot afford yields NO STEPS — the same shape as the authority check, for the
//! same reason. A provision step for a change nobody can pay for is exactly the ready-to-run artifact
//! that ordering exists to prevent.
//!
//! The adapter does not RESERVE, because it cannot sign. It reports the reservation an operator must
//! authorize, and the durable store refuses that reservation if the balance moved in between — so
//! affordability is checked twice. Neither check makes the other redundant: the first stops useless
//! work, the second is the one that binds credits.
//!
//! The step order itself is not re-derived: `plan_replacement_chirho` already returns
//! provision → inspect → JOIN → drain → retire, and the join-before-drain position is what keeps
//! capacity from dipping. Re-deriving it here would be a second place for that invariant to be wrong.

use super::grant_store_chirho::{
    load_current_verified_grant_chirho, TopologyGrantStoreRefusalChirho,
};
use super::plan_reference_chirho::{
    verify_topology_plan_reference_chirho, TopologyPlanReferenceRefusalChirho,
};
use super::plan_store_chirho::RootPlanResolverChirho;
use crate::attestation_stores_chirho::budget_event_store_chirho::{
    replay_budget_chirho, BudgetStoreRefusalChirho,
};
use crate::placement_registry_load_chirho::{
    load_verified_placement_registry_chirho, NodeMeasurementAuthorityResolverChirho,
    RegistryLoadRefusalChirho,
};
use cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::BudgetAuthorityPortChirho;
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::NodeRegistrationAuthorityPortChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::MinimumSpreadChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::LifecycleAuthorityPortChirho;
use cairn_placement_chirho::node_lifecycle_chirho::replacement_chirho::ReplacementStepChirho;
use cairn_placement_chirho::placement_registry_chirho::{
    CapacityAdvanceChirho, CapacityAdvanceRefusalChirho,
};
use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::TopologyGrantAuthorityPortChirho;
use cairn_placement_chirho::topology_chirho::topology_planner_chirho::{
    plan_topology_change_chirho, PlannerRefusalChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub const MANUAL_TOPOLOGY_STEPS_SCHEMA_V1_CHIRHO: &str = "manual-topology-steps-v1-chirho";

/// One thing an operator is being asked to authorize.
///
/// Two shapes, because CF8 clause 9 names *replace* and *upgrade* separately and they genuinely are
/// separate: replace exchanges one node for another and needs the candidate to dominate; upgrade
/// re-grants the SAME node, which keeps serving throughout — no swap, no lifecycle transition.
/// Collapsing them would tell an operator to drain a node that never needed draining.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyStepChirho {
    ReplacementChirho(ReplacementStepChirho),
    /// Re-grant this node's capacity in place. The operator signs a new capacity attestation and the
    /// registry applies it through `advance_node_capacity_chirho`, which refuses a domain change and a
    /// shrink below what is already placed.
    UpgradeCapacityChirho {
        to_chirho: AllocatableCapacityChirho,
    },
}

/// One step an operator is being asked to authorize, and the plan it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBoundStepChirho {
    /// Position in the whole sequence. Explicit rather than implied by list order, so a step that
    /// travels alone — into a ticket, a runbook, a signing prompt — still carries where it belongs.
    pub order_chirho: u32,
    /// The plan digest this step was derived from. THIS is "plan hashes in evidence": an operator
    /// signs a transition bound to a specific resolved plan rather than to a bare intention.
    pub plan_digest_chirho: String,
    pub incumbent_node_id_chirho: String,
    pub step_chirho: TopologyStepChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualTopologyStepsChirho {
    pub schema_chirho: String,
    pub plan_digest_chirho: String,
    pub principal_chirho: String,
    /// The reservation an operator must authorize before acting on these steps. REPORTED, not taken —
    /// this adapter cannot sign.
    pub required_reservation_micros_chirho: u64,
    pub budget_available_micros_chirho: u64,
    pub steps_chirho: Vec<PlanBoundStepChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManualAdapterRefusalChirho {
    /// No grant on record for this principal — there is no authority to plan against.
    GrantChirho {
        refusal_chirho: TopologyGrantStoreRefusalChirho,
    },
    /// The plan digest did not resolve, or resolved to a different plan.
    PlanReferenceChirho {
        refusal_chirho: TopologyPlanReferenceRefusalChirho,
    },
    /// The registry could not be built from durable evidence.
    RegistryChirho {
        refusal_chirho: RegistryLoadRefusalChirho,
    },
    /// The change is not permitted. Carries every reason, and NO STEPS — see the module header.
    PlannerChirho {
        refusals_chirho: Vec<PlannerRefusalChirho>,
    },
    /// The budget could not be read. Distinct from unaffordable: nothing was priced.
    BudgetChirho {
        refusal_chirho: BudgetStoreRefusalChirho,
    },
    /// Permitted, and the prepaid budget has no room for its priced maximum. A different thing to tell
    /// an operator than "not allowed", and a different thing to fix.
    UnaffordableChirho {
        priced_maximum_micros_chirho: u64,
        available_micros_chirho: u64,
    },
    /// A required capacity cannot be applied to that node. Carries the REGISTRY's own refusal, so a
    /// shrink below placed demand keeps its identity rather than becoming a generic "cannot upgrade".
    UpgradeChirho {
        node_id_chirho: String,
        refusal_chirho: CapacityAdvanceRefusalChirho,
    },
}

/// What the adapter reads from.
pub struct ManualAdapterInputsChirho<'a> {
    pub root_chirho: &'a Path,
    /// Separately custodied immutable funding and monotone budget checkpoint state. This root must
    /// canonicalize outside and non-nested with `root_chirho`.
    pub budget_authority_root_chirho: &'a Path,
    pub principal_chirho: &'a str,
    pub plan_digest_chirho: &'a str,
    pub node_ids_chirho: &'a [String],
    pub replacements_chirho: &'a [(String, AllocatableCapacityChirho, BTreeSet<String>)],
    pub minimum_spread_chirho: MinimumSpreadChirho,
    /// Which signed immutable budget pays. The priced maximum remains caller context; the available
    /// ceiling does not, and is resolved from authenticated funding by the budget store.
    pub budget_id_chirho: String,
    pub priced_maximum_micros_chirho: u64,
    /// What the plan needs each named node to have. A node already at or above its requirement yields
    /// NO step — an upgrade nobody needs is noise in a list an operator is meant to act on.
    pub required_capacities_chirho: &'a [(String, AllocatableCapacityChirho)],
}

/// The verifiers every piece of evidence is checked against. Grouped so no caller can supply three of
/// four and silently skip one.
pub struct ManualAdapterAuthoritiesChirho<'a> {
    pub grant_chirho: &'a dyn TopologyGrantAuthorityPortChirho,
    pub capacity_chirho: &'a dyn NodeRegistrationAuthorityPortChirho,
    pub lifecycle_chirho: &'a dyn LifecycleAuthorityPortChirho,
    pub measurement_chirho: &'a dyn NodeMeasurementAuthorityResolverChirho,
    pub budget_chirho: &'a dyn BudgetAuthorityPortChirho,
}

/// Compute the ordered, plan-bound steps for a topology change. Applies nothing.
pub fn plan_manual_topology_steps_chirho(
    inputs_chirho: &ManualAdapterInputsChirho<'_>,
    authorities_chirho: &ManualAdapterAuthoritiesChirho<'_>,
) -> Result<ManualTopologyStepsChirho, ManualAdapterRefusalChirho> {
    // The grant first: a change planned against a grant nobody holds is a calculation about nothing.
    let grant_chirho = load_current_verified_grant_chirho(
        inputs_chirho.root_chirho,
        inputs_chirho.principal_chirho,
        authorities_chirho.grant_chirho,
    )
    .map_err(|refusal_chirho| ManualAdapterRefusalChirho::GrantChirho { refusal_chirho })?;

    // Then the plan, RESOLVED and re-hashed. A digest naming nothing is evidence of nothing.
    let reference_chirho = verify_topology_plan_reference_chirho(
        inputs_chirho.plan_digest_chirho,
        &RootPlanResolverChirho::new_chirho(inputs_chirho.root_chirho),
    )
    .map_err(|refusal_chirho| ManualAdapterRefusalChirho::PlanReferenceChirho { refusal_chirho })?;

    // Then the fleet as durable evidence describes it — never as a caller describes it.
    let registry_chirho = load_verified_placement_registry_chirho(
        inputs_chirho.root_chirho,
        inputs_chirho.node_ids_chirho,
        authorities_chirho.capacity_chirho,
        authorities_chirho.lifecycle_chirho,
        authorities_chirho.measurement_chirho,
    )
    .map_err(|refusal_chirho| ManualAdapterRefusalChirho::RegistryChirho { refusal_chirho })?;

    let change_chirho = plan_topology_change_chirho(
        &registry_chirho,
        reference_chirho.plan_chirho(),
        &grant_chirho,
        inputs_chirho.replacements_chirho,
        inputs_chirho.minimum_spread_chirho,
    )
    .map_err(|refusals_chirho| ManualAdapterRefusalChirho::PlannerChirho { refusals_chirho })?;

    // Affordability comes LAST among the checks and BEFORE any step exists. Last because a change that
    // is not permitted should not have its price discussed — the same reason the planner reports an
    // over-bound plan alone.
    let budget_chirho = replay_budget_chirho(
        inputs_chirho.root_chirho,
        inputs_chirho.budget_authority_root_chirho,
        &inputs_chirho.budget_id_chirho,
        authorities_chirho.budget_chirho,
    )
    .map_err(|refusal_chirho| ManualAdapterRefusalChirho::BudgetChirho { refusal_chirho })?;
    let available_chirho = budget_chirho.available_micros_chirho();
    if inputs_chirho.priced_maximum_micros_chirho > available_chirho {
        return Err(ManualAdapterRefusalChirho::UnaffordableChirho {
            priced_maximum_micros_chirho: inputs_chirho.priced_maximum_micros_chirho,
            available_micros_chirho: available_chirho,
        });
    }

    let mut steps_chirho = Vec::new();
    let mut order_chirho = 0u32;
    for (incumbent_node_id_chirho, replacement_steps_chirho) in
        &change_chirho.replacement_steps_chirho
    {
        for step_chirho in replacement_steps_chirho {
            steps_chirho.push(PlanBoundStepChirho {
                order_chirho,
                plan_digest_chirho: reference_chirho.digest_chirho().to_string(),
                incumbent_node_id_chirho: incumbent_node_id_chirho.clone(),
                step_chirho: TopologyStepChirho::ReplacementChirho(*step_chirho),
            });
            order_chirho = order_chirho.saturating_add(1);
        }
    }

    // UPGRADE steps, after the replacements. Validated by ASKING THE REGISTRY rather than
    // re-implementing its rule here — `capacity_advance_refusal_chirho` is the same check the applying
    // path uses, so a shrink below placed demand cannot be refused in one place and allowed in the
    // other. Deliberately NOT done by probing with a fabricated `VerifiedNodeCapacityChirho`: that type
    // exists precisely so verification is the only way to obtain one, and adding a constructor for
    // convenience here would be the hole this session spent its time closing.
    for (node_id_chirho, required_chirho) in inputs_chirho.required_capacities_chirho {
        if let Some(refusal_chirho) =
            registry_chirho.capacity_advance_refusal_chirho(node_id_chirho, required_chirho)
        {
            return Err(ManualAdapterRefusalChirho::UpgradeChirho {
                node_id_chirho: node_id_chirho.clone(),
                refusal_chirho,
            });
        }
        if registry_chirho.capacity_advance_outcome_chirho(node_id_chirho, required_chirho)
            == Some(CapacityAdvanceChirho::RaisedChirho)
        {
            steps_chirho.push(PlanBoundStepChirho {
                order_chirho,
                plan_digest_chirho: reference_chirho.digest_chirho().to_string(),
                incumbent_node_id_chirho: node_id_chirho.clone(),
                step_chirho: TopologyStepChirho::UpgradeCapacityChirho {
                    to_chirho: *required_chirho,
                },
            });
            order_chirho = order_chirho.saturating_add(1);
        }
    }

    Ok(ManualTopologyStepsChirho {
        schema_chirho: MANUAL_TOPOLOGY_STEPS_SCHEMA_V1_CHIRHO.to_string(),
        plan_digest_chirho: reference_chirho.digest_chirho().to_string(),
        principal_chirho: inputs_chirho.principal_chirho.to_string(),
        required_reservation_micros_chirho: inputs_chirho.priced_maximum_micros_chirho,
        budget_available_micros_chirho: available_chirho,
        steps_chirho,
    })
}

#[cfg(test)]
#[path = "manual_adapter_tests_chirho.rs"]
mod manual_adapter_tests_chirho;
