// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The encoding is injective: no two different plans share bytes, including the boundary-shift pair.

use super::super::topology_grant_chirho::{
    DesiredTopologyPlanChirho, NodeRoleChirho, PlannedNodeChirho, TopologyGrantChirho,
};
use super::*;
use std::collections::BTreeSet;

fn plan_chirho(nodes_chirho: Vec<PlannedNodeChirho>) -> DesiredTopologyPlanChirho {
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "grant-a-chirho".to_string(),
        nodes_chirho,
        spend_rate_micros_per_hour_chirho: 100_000,
        proposed_grant_chirho: None,
    }
}

fn node_chirho(provider_chirho: &str, role_chirho: NodeRoleChirho) -> PlannedNodeChirho {
    PlannedNodeChirho {
        provider_chirho: provider_chirho.to_string(),
        role_chirho,
    }
}

#[test]
fn the_same_plan_hashes_the_same_every_time_chirho() {
    let a_chirho = plan_chirho(vec![node_chirho(
        "hetzner-chirho",
        NodeRoleChirho::ControlChirho,
    )]);
    let b_chirho = plan_chirho(vec![node_chirho(
        "hetzner-chirho",
        NodeRoleChirho::ControlChirho,
    )]);
    assert_eq!(plan_hash_chirho(&a_chirho), plan_hash_chirho(&b_chirho));
}

#[test]
fn adjacent_free_fields_cannot_collide_chirho() {
    // THE HAZARD, TESTED WHERE IT IS ACTUALLY CONSTRUCTIBLE. Two adjacent caller-controlled strings
    // are the collision risk: unprefixed, ("ab","c") and ("a","bc") both flatten to `abc`. This
    // exercises the encoder primitive rather than a whole plan, because in the CURRENT plan shape a
    // fixed-set role label always separates the two free-form provider fields — so a plan-level
    // fixture passes for a reason unrelated to the prefix and proves nothing about it.
    let mut left_chirho = Vec::new();
    push_field_chirho(&mut left_chirho, b"ab");
    push_field_chirho(&mut left_chirho, b"c");
    let mut right_chirho = Vec::new();
    push_field_chirho(&mut right_chirho, b"a");
    push_field_chirho(&mut right_chirho, b"bc");
    assert_ne!(
        left_chirho, right_chirho,
        "adjacent variable-length fields must not be able to shift their boundary"
    );
}

#[test]
fn a_boundary_shift_in_the_current_plan_shape_does_not_collide_chirho() {
    // Weaker than it looks, and recorded as such: in TODAY's plan shape this passes because the
    // fixed-set role label separates the providers, not because of the length prefix. Kept as a
    // regression guard for the plan shape itself — if a field is ever added that puts two free-form
    // strings adjacent, this becomes load-bearing and the primitive test above is what protects it.
    let left_chirho = plan_chirho(vec![
        node_chirho("ab", NodeRoleChirho::ControlChirho),
        node_chirho("c", NodeRoleChirho::WorkerChirho),
    ]);
    let right_chirho = plan_chirho(vec![
        node_chirho("a", NodeRoleChirho::ControlChirho),
        node_chirho("bc", NodeRoleChirho::WorkerChirho),
    ]);
    assert_ne!(
        plan_hash_chirho(&left_chirho),
        plan_hash_chirho(&right_chirho)
    );
}

#[test]
fn splitting_one_node_into_two_does_not_collide_with_the_original_chirho() {
    // The count prefix earns its place here: without it, one node named "ab" and two nodes named
    // "a" and "b" could flatten alike.
    let one_chirho = plan_chirho(vec![node_chirho("ab", NodeRoleChirho::WorkerChirho)]);
    let two_chirho = plan_chirho(vec![
        node_chirho("a", NodeRoleChirho::WorkerChirho),
        node_chirho("b", NodeRoleChirho::WorkerChirho),
    ]);
    assert_ne!(plan_hash_chirho(&one_chirho), plan_hash_chirho(&two_chirho));
}

#[test]
fn node_order_is_significant_chirho() {
    // Two plans differing only in node order read differently to an operator, so they are different
    // plans and must hash differently.
    let forward_chirho = plan_chirho(vec![
        node_chirho("hetzner-chirho", NodeRoleChirho::ControlChirho),
        node_chirho("ovh-chirho", NodeRoleChirho::StorageChirho),
    ]);
    let reversed_chirho = plan_chirho(vec![
        node_chirho("ovh-chirho", NodeRoleChirho::StorageChirho),
        node_chirho("hetzner-chirho", NodeRoleChirho::ControlChirho),
    ]);
    assert_ne!(
        plan_hash_chirho(&forward_chirho),
        plan_hash_chirho(&reversed_chirho)
    );
}

#[test]
fn a_role_change_alone_changes_the_hash_chirho() {
    let control_chirho = plan_chirho(vec![node_chirho("p-chirho", NodeRoleChirho::ControlChirho)]);
    let worker_chirho = plan_chirho(vec![node_chirho("p-chirho", NodeRoleChirho::WorkerChirho)]);
    assert_ne!(
        plan_hash_chirho(&control_chirho),
        plan_hash_chirho(&worker_chirho)
    );
}

#[test]
fn a_spend_rate_change_alone_changes_the_hash_chirho() {
    let mut dearer_chirho =
        plan_chirho(vec![node_chirho("p-chirho", NodeRoleChirho::WorkerChirho)]);
    let base_chirho = plan_chirho(vec![node_chirho("p-chirho", NodeRoleChirho::WorkerChirho)]);
    dearer_chirho.spend_rate_micros_per_hour_chirho += 1;
    assert_ne!(
        plan_hash_chirho(&base_chirho),
        plan_hash_chirho(&dearer_chirho)
    );
}

#[test]
fn a_cited_grant_change_alone_changes_the_hash_chirho() {
    let mut other_chirho = plan_chirho(vec![node_chirho("p-chirho", NodeRoleChirho::WorkerChirho)]);
    let base_chirho = plan_chirho(vec![node_chirho("p-chirho", NodeRoleChirho::WorkerChirho)]);
    other_chirho.cited_grant_id_chirho = "grant-b-chirho".to_string();
    assert_ne!(
        plan_hash_chirho(&base_chirho),
        plan_hash_chirho(&other_chirho)
    );
}

#[test]
fn a_self_modifying_plan_does_not_hash_like_its_lawful_twin_chirho() {
    // Otherwise evidence produced for the lawful plan could be presented as evidence for the
    // escalating one — the exact substitution the plan hash exists to prevent.
    let lawful_chirho = plan_chirho(vec![node_chirho("p-chirho", NodeRoleChirho::ControlChirho)]);
    let mut escalating_chirho = lawful_chirho.clone();
    escalating_chirho.proposed_grant_chirho = Some(TopologyGrantChirho {
        grant_id_chirho: "grant-a-chirho".to_string(),
        max_nodes_chirho: 10_000,
        max_spend_rate_micros_per_hour_chirho: u64::MAX,
        allowed_providers_chirho: BTreeSet::new(),
        minimum_control_nodes_chirho: 0,
        minimum_storage_nodes_chirho: 0,
    });
    assert_ne!(
        plan_hash_chirho(&lawful_chirho),
        plan_hash_chirho(&escalating_chirho)
    );
}
