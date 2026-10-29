// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Authority is checked before anything is planned, and affordable is not the same as survivable.

use super::*;
use crate::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use crate::failure_domain_chirho::FailureDomainChirho;
use crate::node_lifecycle_chirho::NodeLifecycleStateChirho;
use crate::placement_registry_chirho::RegisteredNodeChirho;
use crate::topology_chirho::topology_grant_attestation_chirho::VerifiedTopologyGrantChirho;
use crate::topology_chirho::topology_grant_chirho::TopologyGrantChirho;
use crate::topology_chirho::topology_grant_chirho::{NodeRoleChirho, PlannedNodeChirho};

fn capacity_chirho(c_chirho: u64, m_chirho: u64, d_chirho: u64) -> AllocatableCapacityChirho {
    AllocatableCapacityChirho {
        cpu_millicores_chirho: c_chirho,
        memory_bytes_chirho: m_chirho,
        durable_bytes_chirho: d_chirho,
    }
}

fn node_chirho(
    id_chirho: &str,
    provider_chirho: &str,
    region_chirho: &str,
) -> RegisteredNodeChirho {
    let mut node_chirho = RegisteredNodeChirho::unattested_for_test_chirho(
        id_chirho.to_string(),
        FailureDomainChirho {
            provider_chirho: provider_chirho.to_string(),
            region_chirho: region_chirho.to_string(),
        },
        capacity_chirho(4_000, 16 << 30, 512 << 30),
        NodeLifecycleStateChirho::JoinedChirho,
    );
    node_chirho.set_measurement_for_test_chirho(Some(MeasurementStampChirho {
        hlc_millis_chirho: 1_000,
        sequence_chirho: 7,
    }));
    node_chirho
}

/// Two providers, two regions — satisfies a 2/2 spread.
fn spread_registry_chirho() -> PlacementRegistryChirho {
    let mut r_chirho = PlacementRegistryChirho::new_chirho();
    r_chirho.upsert_node_chirho(node_chirho("a-chirho", "hetzner-chirho", "fsn1-chirho"));
    r_chirho.upsert_node_chirho(node_chirho("b-chirho", "ovh-chirho", "fr-chirho"));
    r_chirho
}

/// The planner now requires a VERIFIED grant. These arms are about plan arithmetic and spread, not
/// about signatures, so they use the `cfg(test)` wrapper rather than each carrying a signing fixture.
/// The attestation's own arms cover verification.
fn grant_chirho() -> VerifiedTopologyGrantChirho {
    VerifiedTopologyGrantChirho::unverified_for_test_chirho(
        raw_grant_chirho(),
        "planner-test-chirho",
    )
}

fn raw_grant_chirho() -> TopologyGrantChirho {
    TopologyGrantChirho {
        grant_id_chirho: "grant-a-chirho".to_string(),
        max_nodes_chirho: 12,
        max_spend_rate_micros_per_hour_chirho: 500_000,
        allowed_providers_chirho: ["hetzner-chirho".to_string(), "ovh-chirho".to_string()]
            .into_iter()
            .collect(),
        minimum_control_nodes_chirho: 1,
        minimum_storage_nodes_chirho: 1,
    }
}

fn lawful_plan_chirho() -> DesiredTopologyPlanChirho {
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "grant-a-chirho".to_string(),
        nodes_chirho: vec![
            PlannedNodeChirho {
                provider_chirho: "hetzner-chirho".to_string(),
                role_chirho: NodeRoleChirho::ControlChirho,
            },
            PlannedNodeChirho {
                provider_chirho: "ovh-chirho".to_string(),
                role_chirho: NodeRoleChirho::StorageChirho,
            },
        ],
        spend_rate_micros_per_hour_chirho: 100_000,
        proposed_grant_chirho: None,
    }
}

fn spread_2_2_chirho() -> MinimumSpreadChirho {
    MinimumSpreadChirho {
        distinct_providers_chirho: 2,
        distinct_regions_chirho: 2,
    }
}

#[test]
fn a_lawful_plan_with_a_dominating_replacement_yields_steps_chirho() {
    // Positive control: without it, every refusal test below could pass because the planner refuses
    // everything.
    let change_chirho = plan_topology_change_chirho(
        &spread_registry_chirho(),
        &lawful_plan_chirho(),
        &grant_chirho(),
        &[(
            "a-chirho".to_string(),
            capacity_chirho(8_000, 32 << 30, 1_024 << 30),
            BTreeSet::new(),
        )],
        spread_2_2_chirho(),
    )
    .expect("lawful plan, dominating candidate, adequate spread");
    assert_eq!(change_chirho.replacement_steps_chirho.len(), 1);
    assert_eq!(change_chirho.replacement_steps_chirho[0].0, "a-chirho");
}

#[test]
fn a_self_modifying_plan_is_refused_and_no_steps_are_computed_chirho() {
    // THE ORDERING PROPERTY. A plan that proposes its own grant must not get a ready-to-run
    // replacement sequence whose only protection is that a later caller checks a separate result.
    // The steps must not exist to be misused.
    let mut plan_chirho = lawful_plan_chirho();
    plan_chirho.proposed_grant_chirho = Some(raw_grant_chirho());
    let refusals_chirho = plan_topology_change_chirho(
        &spread_registry_chirho(),
        &plan_chirho,
        &grant_chirho(),
        &[(
            "a-chirho".to_string(),
            capacity_chirho(8_000, 32 << 30, 1_024 << 30),
            BTreeSet::new(),
        )],
        spread_2_2_chirho(),
    )
    .expect_err("a self-modifying plan is refused");
    assert_eq!(
        refusals_chirho,
        vec![PlannerRefusalChirho::GrantChirho(
            PlanRefusalChirho::SelfModificationChirho
        )],
        "grant refusals must come back ALONE — nothing else may be computed for an unauthorised plan"
    );
}

#[test]
fn an_over_bound_plan_reports_only_grant_refusals_chirho() {
    let mut plan_chirho = lawful_plan_chirho();
    plan_chirho.spend_rate_micros_per_hour_chirho = 900_000;
    let refusals_chirho = plan_topology_change_chirho(
        &spread_registry_chirho(),
        &plan_chirho,
        &grant_chirho(),
        &[(
            "a-chirho".to_string(),
            capacity_chirho(1, 1, 1), // would ALSO fail replacement — must not be reported
            BTreeSet::new(),
        )],
        spread_2_2_chirho(),
    )
    .expect_err("over-bound spend is refused");
    assert!(
        refusals_chirho
            .iter()
            .all(|r_chirho| matches!(r_chirho, PlannerRefusalChirho::GrantChirho(_))),
        "authority-first means the unfit candidate is never even examined: {refusals_chirho:?}"
    );
}

#[test]
fn a_non_dominating_candidate_is_refused_under_a_lawful_plan_chirho() {
    let refusals_chirho = plan_topology_change_chirho(
        &spread_registry_chirho(),
        &lawful_plan_chirho(),
        &grant_chirho(),
        &[(
            "a-chirho".to_string(),
            capacity_chirho(4_000, (16 << 30) - 1, 512 << 30), // one byte short
            BTreeSet::new(),
        )],
        spread_2_2_chirho(),
    )
    .expect_err("a candidate short in any dimension is not a replacement");
    assert!(refusals_chirho
        .iter()
        .any(|r_chirho| matches!(r_chirho, PlannerRefusalChirho::ReplacementChirho(_))));
}

#[test]
fn an_affordable_plan_that_leaves_one_failure_domain_is_refused_chirho() {
    // AFFORDABLE IS NOT SURVIVABLE. The grant bounds cost and count; spread bounds survival. This
    // registry sits entirely at one provider, so a plan well within its grant is still refused.
    let mut single_domain_chirho = PlacementRegistryChirho::new_chirho();
    single_domain_chirho.upsert_node_chirho(node_chirho(
        "a-chirho",
        "hetzner-chirho",
        "fsn1-chirho",
    ));
    single_domain_chirho.upsert_node_chirho(node_chirho(
        "b-chirho",
        "hetzner-chirho",
        "nbg1-chirho",
    ));
    let refusals_chirho = plan_topology_change_chirho(
        &single_domain_chirho,
        &lawful_plan_chirho(),
        &grant_chirho(),
        &[],
        spread_2_2_chirho(),
    )
    .expect_err("two regions at one provider does not meet a 2-provider spread");
    assert!(
        refusals_chirho
            .iter()
            .any(|r_chirho| matches!(r_chirho, PlannerRefusalChirho::SpreadChirho(_))),
        "{refusals_chirho:?}"
    );
}

#[test]
fn an_unknown_incumbent_is_named_rather_than_silently_skipped_chirho() {
    let refusals_chirho = plan_topology_change_chirho(
        &spread_registry_chirho(),
        &lawful_plan_chirho(),
        &grant_chirho(),
        &[(
            "ghost-chirho".to_string(),
            capacity_chirho(8_000, 32 << 30, 1_024 << 30),
            BTreeSet::new(),
        )],
        spread_2_2_chirho(),
    )
    .expect_err("replacing a node the registry does not know is a mistake, not a no-op");
    assert!(
        refusals_chirho.contains(&PlannerRefusalChirho::UnknownIncumbentChirho {
            node_id_chirho: "ghost-chirho".to_string(),
        })
    );
}
