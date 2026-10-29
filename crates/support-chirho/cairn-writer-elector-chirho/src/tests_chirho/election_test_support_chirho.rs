// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Shared test-only helpers for the election robustness suites (partition/crash chaos + WAN-latency): a
//! voter-roster builder, the LCG step that drives the seed-deterministic adversarial schedules, and the
//! two invariants both suites check — never two distinct leaders in one term (safety), and convergence on
//! exactly one agreed leader (liveness). Note: the LCG makes the SCHEDULE reproducible, but raft-rs draws
//! its election timeout from `thread_rng`, so exact leaders/terms vary run to run — the suites are robust
//! across that variation rather than bit-reproducible.

use crate::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::collections::HashMap;

/// A voter roster of `count_chirho` members, each id a distinct 64-hex-char digit run (as the other
/// elector tests use).
pub(crate) fn voters_chirho(count_chirho: u64) -> Vec<(u64, NodeIdChirho)> {
    (1..=count_chirho)
        .map(|id_chirho| (id_chirho, NodeIdChirho(format!("{id_chirho}").repeat(64))))
        .collect()
}

/// One step of the LCG (Knuth MMIX constants) that drives the deterministic pseudo-random schedules.
pub(crate) fn next_lcg_chirho(lcg_chirho: u64) -> u64 {
    lcg_chirho
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
}

/// The core election-safety assertion: across all nodes, at most one DISTINCT node believes itself leader
/// in any single term. (Two leaders in DIFFERENT terms is just staleness and is fine.)
pub(crate) fn assert_no_two_leaders_in_one_term_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    group_chirho: &ConsistencyGroupIdChirho,
    context_chirho: &str,
) {
    let mut leader_by_term_chirho: HashMap<u64, NodeIdChirho> = HashMap::new();
    for node_chirho in nodes_chirho {
        let view_chirho = node_chirho.leadership_chirho(group_chirho);
        if !view_chirho.is_leader_chirho {
            continue;
        }
        let id_chirho = node_chirho.node_id_chirho().clone();
        match leader_by_term_chirho.get(&view_chirho.term_chirho) {
            Some(existing_chirho) => assert_eq!(
                existing_chirho, &id_chirho,
                "{context_chirho}: two distinct leaders in term {} — election safety violated",
                view_chirho.term_chirho
            ),
            None => {
                leader_by_term_chirho.insert(view_chirho.term_chirho, id_chirho);
            }
        }
    }
}

/// The convergence/liveness check: exactly one node believes itself leader and EVERY node agrees on that
/// same leader id.
pub(crate) fn converged_on_one_leader_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    group_chirho: &ConsistencyGroupIdChirho,
) -> bool {
    let leaders_chirho: Vec<NodeIdChirho> = nodes_chirho
        .iter()
        .filter_map(|node_chirho| {
            let view_chirho = node_chirho.leadership_chirho(group_chirho);
            view_chirho
                .is_leader_chirho
                .then(|| node_chirho.node_id_chirho().clone())
        })
        .collect();
    leaders_chirho.len() == 1
        && nodes_chirho.iter().all(|node_chirho| {
            node_chirho
                .leadership_chirho(group_chirho)
                .leader_id_chirho
                .as_ref()
                == leaders_chirho.first()
        })
}
