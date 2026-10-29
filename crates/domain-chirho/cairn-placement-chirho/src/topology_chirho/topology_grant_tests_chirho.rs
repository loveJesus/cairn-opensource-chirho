// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Self-modification is refused outright; role floors hold independently so workers may reach zero.

use super::*;

fn grant_chirho() -> TopologyGrantChirho {
    TopologyGrantChirho {
        grant_id_chirho: "grant-a-chirho".to_string(),
        max_nodes_chirho: 12,
        max_spend_rate_micros_per_hour_chirho: 500_000,
        allowed_providers_chirho: ["hetzner-chirho".to_string(), "ovh-chirho".to_string()]
            .into_iter()
            .collect(),
        minimum_control_nodes_chirho: 3,
        minimum_storage_nodes_chirho: 3,
    }
}

fn node_chirho(provider_chirho: &str, role_chirho: NodeRoleChirho) -> PlannedNodeChirho {
    PlannedNodeChirho {
        provider_chirho: provider_chirho.to_string(),
        role_chirho,
    }
}

/// A plan meeting both floors on allowed providers, with `workers_chirho` app workers.
fn plan_with_workers_chirho(workers_chirho: usize) -> DesiredTopologyPlanChirho {
    let mut nodes_chirho = Vec::new();
    for _ in 0..3 {
        nodes_chirho.push(node_chirho("hetzner-chirho", NodeRoleChirho::ControlChirho));
        nodes_chirho.push(node_chirho("ovh-chirho", NodeRoleChirho::StorageChirho));
    }
    for _ in 0..workers_chirho {
        nodes_chirho.push(node_chirho("hetzner-chirho", NodeRoleChirho::WorkerChirho));
    }
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "grant-a-chirho".to_string(),
        nodes_chirho,
        spend_rate_micros_per_hour_chirho: 100_000,
        proposed_grant_chirho: None,
    }
}

#[test]
fn a_plan_inside_every_bound_is_accepted_chirho() {
    assert!(plan_refusals_chirho(&plan_with_workers_chirho(2), &grant_chirho()).is_empty());
}

#[test]
fn app_workers_may_scale_to_zero_without_breaching_the_floor_chirho() {
    // THE INDEPENDENCE PROPERTY. A total-node floor would refuse this legitimate scale-to-zero.
    // Floors are per role, so an empty worker fleet leaves control and storage untouched.
    let plan_chirho = plan_with_workers_chirho(0);
    assert_eq!(
        nodes_in_role_chirho(&plan_chirho, NodeRoleChirho::WorkerChirho),
        0
    );
    assert!(
        plan_refusals_chirho(&plan_chirho, &grant_chirho()).is_empty(),
        "workers reaching zero must not read as a floor breach"
    );
}

#[test]
fn workers_never_substitute_for_a_missing_control_node_chirho() {
    // The other half of independence, and the one a total count gets backwards: a large worker
    // fleet must NOT satisfy the control floor.
    let mut plan_chirho = plan_with_workers_chirho(6);
    plan_chirho
        .nodes_chirho
        .retain(|node_chirho| node_chirho.role_chirho != NodeRoleChirho::ControlChirho);
    let refusals_chirho = plan_refusals_chirho(&plan_chirho, &grant_chirho());
    assert_eq!(
        refusals_chirho,
        vec![PlanRefusalChirho::RoleFloorBreachedChirho {
            role_chirho: NodeRoleChirho::ControlChirho,
            minimum_chirho: 3,
            planned_chirho: 0,
        }],
        "workers must not cover a drained control plane"
    );
}

#[test]
fn a_plan_proposing_a_new_grant_is_refused_outright_chirho() {
    // THE LOAD-BEARING REFUSAL. No ceiling constrains a planner that can raise its own ceiling.
    let mut plan_chirho = plan_with_workers_chirho(1);
    let mut bigger_chirho = grant_chirho();
    bigger_chirho.max_nodes_chirho = 10_000;
    bigger_chirho.max_spend_rate_micros_per_hour_chirho = u64::MAX;
    plan_chirho.proposed_grant_chirho = Some(bigger_chirho);

    assert_eq!(
        plan_refusals_chirho(&plan_chirho, &grant_chirho()),
        vec![PlanRefusalChirho::SelfModificationChirho],
        "a plan that proposes its own grant is refused, and refused ALONE"
    );
}

#[test]
fn self_modification_short_circuits_a_plan_that_also_breaks_another_bound_chirho() {
    // THE DISCRIMINATING FIXTURE. Its two siblings both assert `vec![SelfModificationChirho]` on a
    // plan that violates NOTHING ELSE -- so they are single-element by FIXTURE, and cannot tell
    // "reported alone by construction" from "alone because nothing else could fire". Measured: with
    // the early return demoted to a late push, both siblings still pass 33/33.
    //
    // This one breaks a SECOND bound as well, so the two behaviours diverge: short-circuit yields
    // exactly one refusal, while a non-short-circuiting version also reports the grant mismatch.
    //
    // MIGRATION PATH: if this ever reports MORE than the self-modification refusal, the short-circuit
    // was removed -- and the doc's promise that a self-modifying plan "should not have its capacity
    // numbers discussed as though the rest were a negotiation" no longer holds. That is a real change
    // to how an escalation attempt is reported, not a cosmetic one.
    let mut plan_chirho = plan_with_workers_chirho(1);
    plan_chirho.cited_grant_id_chirho = "a-grant-this-plan-does-not-hold-chirho".to_owned();
    plan_chirho.proposed_grant_chirho = Some(grant_chirho());

    let refusals_chirho = plan_refusals_chirho(&plan_chirho, &grant_chirho());
    assert_eq!(
        refusals_chirho,
        vec![PlanRefusalChirho::SelfModificationChirho],
        "self-modification must short-circuit: the grant mismatch this plan ALSO has must not be \
         reported alongside it, or the refusal set becomes a negotiation over an escalation attempt"
    );
}

#[test]
fn self_modification_is_refused_even_when_every_other_bound_is_satisfied_chirho() {
    // The attempt must not be excused by an otherwise-modest plan — that is exactly how a
    // privilege escalation would be dressed.
    let mut plan_chirho = plan_with_workers_chirho(0);
    plan_chirho.spend_rate_micros_per_hour_chirho = 1;
    plan_chirho.proposed_grant_chirho = Some(grant_chirho()); // even an IDENTICAL grant
    assert_eq!(
        plan_refusals_chirho(&plan_chirho, &grant_chirho()),
        vec![PlanRefusalChirho::SelfModificationChirho]
    );
}

#[test]
fn an_over_bound_node_count_is_refused_chirho() {
    let plan_chirho = plan_with_workers_chirho(7); // 6 floor nodes + 7 workers = 13 > 12
    assert!(
        plan_refusals_chirho(&plan_chirho, &grant_chirho()).contains(
            &PlanRefusalChirho::NodeCountOverBoundChirho {
                limit_chirho: 12,
                planned_chirho: 13,
            }
        )
    );
}

#[test]
fn an_over_bound_spend_rate_is_refused_chirho() {
    let mut plan_chirho = plan_with_workers_chirho(1);
    plan_chirho.spend_rate_micros_per_hour_chirho = 500_001;
    assert!(
        plan_refusals_chirho(&plan_chirho, &grant_chirho()).contains(
            &PlanRefusalChirho::SpendRateOverBoundChirho {
                limit_micros_per_hour_chirho: 500_000,
                planned_micros_per_hour_chirho: 500_001,
            }
        )
    );
}

#[test]
fn a_provider_outside_the_allowlist_is_refused_once_per_provider_chirho() {
    let mut plan_chirho = plan_with_workers_chirho(0);
    for _ in 0..3 {
        plan_chirho
            .nodes_chirho
            .push(node_chirho("aws-chirho", NodeRoleChirho::WorkerChirho));
    }
    let refusals_chirho = plan_refusals_chirho(&plan_chirho, &grant_chirho());
    assert_eq!(
        refusals_chirho,
        vec![PlanRefusalChirho::ProviderNotAllowedChirho {
            provider_chirho: "aws-chirho".to_string(),
        }],
        "three nodes at one disallowed provider is one problem, not three"
    );
}

#[test]
fn a_plan_citing_another_grant_is_refused_chirho() {
    let mut plan_chirho = plan_with_workers_chirho(0);
    plan_chirho.cited_grant_id_chirho = "grant-b-chirho".to_string();
    assert!(
        plan_refusals_chirho(&plan_chirho, &grant_chirho()).contains(
            &PlanRefusalChirho::GrantMismatchChirho {
                cited_chirho: "grant-b-chirho".to_string(),
                checked_chirho: "grant-a-chirho".to_string(),
            }
        )
    );
}

#[test]
fn every_violated_bound_is_reported_so_an_operator_sees_the_whole_bill_chirho() {
    let mut plan_chirho = plan_with_workers_chirho(0);
    plan_chirho
        .nodes_chirho
        .retain(|node_chirho| node_chirho.role_chirho == NodeRoleChirho::ControlChirho);
    plan_chirho.spend_rate_micros_per_hour_chirho = 900_000;
    plan_chirho
        .nodes_chirho
        .push(node_chirho("aws-chirho", NodeRoleChirho::WorkerChirho));
    let refusals_chirho = plan_refusals_chirho(&plan_chirho, &grant_chirho());
    assert!(
        refusals_chirho.len() >= 3,
        "spend, provider and storage floor should all report: {refusals_chirho:?}"
    );
}
