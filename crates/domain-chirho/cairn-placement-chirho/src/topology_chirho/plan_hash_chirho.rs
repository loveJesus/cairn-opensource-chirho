// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A plan's hash, over an encoding where no two different plans can produce the same bytes.
//!
//! CF8 asks that the lifecycle composition carry *"plan hashes in evidence"*. The point of that is
//! **anti-substitution**: evidence produced from plan A must not be presentable as proof that plan B
//! was executed. That guarantee is only as strong as the encoding underneath it, so the encoding is
//! what this module is actually about.
//!
//! **THE HAZARD IS FIELD-BOUNDARY AMBIGUITY, and it is easy to miss.** The obvious encoding —
//! concatenate the strings — collides: a node at provider `"ab"` region `"c"` and a node at provider
//! `"a"` region `"bc"` both flatten to `abc`. Two genuinely different topologies, one hash, and an
//! attacker who can choose names can manufacture the pair. So every variable-length field is written
//! **length-prefixed**: the reader of these bytes can always tell where one field ended, which is
//! exactly what makes the encoding injective.
//!
//! **Written by hand rather than derived.** A serde-based encoding would work today and is one
//! dependency bump away from silently changing the bytes — and a hash that changes for a reason
//! nobody chose invalidates every piece of evidence that cites it. Field order here is explicit and
//! is part of the contract; adding a field to the plan **must** extend this function, and the tests
//! below fail loudly if a new field is silently ignored.
//!
//! Pure: no I/O. Only `blake3` via `cairn-core-chirho`, which this crate already depends on — no new
//! dependency for a domain crate that is deliberately dep-light.

use super::topology_grant_chirho::{DesiredTopologyPlanChirho, NodeRoleChirho};
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;

/// Append one length-prefixed field. The prefix is what makes ADJACENT free-form fields
/// unambiguous — see `adjacent_free_fields_cannot_collide_chirho`, which is where the hazard is
/// actually constructible.
pub(crate) fn push_field_chirho(out_chirho: &mut Vec<u8>, bytes_chirho: &[u8]) {
    out_chirho.extend_from_slice(&(bytes_chirho.len() as u64).to_be_bytes());
    out_chirho.extend_from_slice(bytes_chirho);
}

/// A role's stable wire label. Named rather than derived from the enum's discriminant so reordering
/// the enum cannot silently change every historical plan hash.
fn role_label_chirho(role_chirho: NodeRoleChirho) -> &'static str {
    match role_chirho {
        NodeRoleChirho::ControlChirho => "control-chirho",
        NodeRoleChirho::StorageChirho => "storage-chirho",
        NodeRoleChirho::WorkerChirho => "worker-chirho",
    }
}

/// Canonical, injective bytes for a desired-state plan.
///
/// Node order is significant and preserved: two plans differing only in node order are different
/// plans to an operator reading them, so they hash differently.
pub fn canonical_plan_bytes_chirho(plan_chirho: &DesiredTopologyPlanChirho) -> Vec<u8> {
    let mut out_chirho = Vec::new();
    push_field_chirho(&mut out_chirho, b"topology-plan-v1-chirho");
    push_field_chirho(
        &mut out_chirho,
        plan_chirho.cited_grant_id_chirho.as_bytes(),
    );
    out_chirho.extend_from_slice(&plan_chirho.spend_rate_micros_per_hour_chirho.to_be_bytes());
    out_chirho.extend_from_slice(&(plan_chirho.nodes_chirho.len() as u64).to_be_bytes());
    for node_chirho in &plan_chirho.nodes_chirho {
        push_field_chirho(&mut out_chirho, node_chirho.provider_chirho.as_bytes());
        push_field_chirho(
            &mut out_chirho,
            role_label_chirho(node_chirho.role_chirho).as_bytes(),
        );
    }
    // A self-modifying plan must not hash the same as its otherwise-identical lawful twin, or
    // evidence for the lawful one could be presented for the escalating one.
    push_field_chirho(
        &mut out_chirho,
        if plan_chirho.proposed_grant_chirho.is_some() {
            b"proposes-grant-chirho"
        } else {
            b"no-proposed-grant-chirho"
        },
    );
    out_chirho
}

/// The plan's content address.
pub fn plan_hash_chirho(plan_chirho: &DesiredTopologyPlanChirho) -> HashChirho {
    hash_chirho(&canonical_plan_bytes_chirho(plan_chirho))
}

#[cfg(test)]
#[path = "plan_hash_tests_chirho.rs"]
mod plan_hash_tests_chirho;
