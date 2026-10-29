// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Randomized election-SAFETY soak for the durable Raft electors: under a seeded pseudo-random schedule
//! of network partitions and durable crash/restart, the cluster never elects two DISTINCT leaders in the
//! SAME term (the single-leader-per-term invariant the eventual P5 fence-mint will bet money on), and once
//! the partition heals it converges on exactly one agreed leader (liveness). This is broad INTEGRATION
//! coverage: durable nodes crash, restart, and rejoin under a shifting partition and the cluster stays
//! safe and re-converges.
//!
//! Two honesty notes (from the adversarial audit of this file — see the P5 design §3):
//! 1. The SCHEDULE (partition sides, crash timing) is seed-deterministic, but raft-rs draws its election
//!    timeout from `thread_rng`, so the exact leaders and terms VARY run to run. The soak is robust across
//!    that variation, not bit-reproducible from the seed.
//! 2. It does NOT isolate the durable-vote mechanism: with pre-vote on, a node that forgot its persisted
//!    vote just bumps the term rather than double-voting the old one, so a durable-store regression is
//!    invisible here. The "a restarted node honors its prior vote" guarantee is proven by the single-node
//!    unit test `durable_elector_recovers_term_and_vote_across_restart_chirho`, not by this soak. What this
//!    soak adds is that the durable elector survives crash+restart under partition without breaking the
//!    cluster's single-leader-per-term invariant or its ability to re-converge.

use super::election_test_support_chirho::{
    assert_no_two_leaders_in_one_term_chirho, converged_on_one_leader_chirho, next_lcg_chirho,
    voters_chirho,
};
use crate::elector_port_chirho::WriterElectorChirho;
use crate::monotonic_clock_chirho::FakeMonotonicClockChirho;
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const NODES_CHIRHO: u64 = 5;
const SUBROUNDS_CHIRHO: usize = 160;
const CHAOS_ROUNDS_CHIRHO: usize = 200;
const HEAL_ROUNDS_CHIRHO: usize = 220;

/// A unique, non-existent temp directory for one node (pid + an atomic counter — no wall clock).
fn temp_dir_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-elector-chaos-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

/// Build a fresh durable cluster: one `new_durable_cluster_node_chirho` per voter, each with its own dir.
fn build_cluster_chirho(
    seed_tag_chirho: &str,
    group_chirho: &ConsistencyGroupIdChirho,
) -> (Vec<PathBuf>, Vec<RaftWriterElectorChirho>) {
    let roster_chirho = voters_chirho(NODES_CHIRHO);
    let mut dirs_chirho = Vec::new();
    let mut nodes_chirho = Vec::new();
    for raft_id_chirho in 1..=NODES_CHIRHO {
        let dir_chirho = temp_dir_chirho(&format!("{seed_tag_chirho}-n{raft_id_chirho}"));
        let node_chirho = RaftWriterElectorChirho::new_durable_cluster_node_chirho(
            dir_chirho.clone(),
            group_chirho.clone(),
            raft_id_chirho,
            roster_chirho.clone(),
        )
        .expect("build durable cluster node");
        dirs_chirho.push(dir_chirho);
        nodes_chirho.push(node_chirho);
    }
    (dirs_chirho, nodes_chirho)
}

/// Tick every node once, then route the resulting messages for a bounded number of sub-rounds — but
/// deliver a message ONLY when its sender and receiver are on the same partition side this round
/// (`side_chirho[i]` is the side of the node with raft id `i + 1`). A cross-partition link drops the
/// message, exactly as a real network partition would.
fn tick_and_route_partitioned_chirho(nodes_chirho: &[RaftWriterElectorChirho], side_chirho: &[u8]) {
    // (from_raft_id, to_raft_id, encoded_message_bytes)
    let mut bus_chirho: Vec<(u64, u64, Vec<u8>)> = Vec::new();
    for node_chirho in nodes_chirho {
        let from_chirho = node_chirho.local_raft_id_chirho();
        for (to_chirho, bytes_chirho) in node_chirho.tick_encoded_chirho().expect("tick a node") {
            bus_chirho.push((from_chirho, to_chirho, bytes_chirho));
        }
    }
    for _sub_chirho in 0..SUBROUNDS_CHIRHO {
        if bus_chirho.is_empty() {
            break;
        }
        let mut next_chirho: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        for (from_chirho, to_chirho, bytes_chirho) in bus_chirho.drain(..) {
            if side_chirho[(from_chirho - 1) as usize] != side_chirho[(to_chirho - 1) as usize] {
                continue; // partitioned link: nothing crosses
            }
            if let Some(target_chirho) = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == to_chirho)
            {
                for (next_to_chirho, next_bytes_chirho) in target_chirho
                    .step_encoded_chirho(&bytes_chirho)
                    .expect("step an encoded message")
                {
                    next_chirho.push((to_chirho, next_to_chirho, next_bytes_chirho));
                }
            }
        }
        bus_chirho = next_chirho;
    }
}

#[test]
fn durable_elector_never_double_elects_under_partition_and_crash_chirho() {
    for seed_chirho in 0..3u64 {
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: format!("/var/lib/cairn-chaos-{seed_chirho}-chirho"),
        };
        let (dirs_chirho, mut nodes_chirho) =
            build_cluster_chirho(&format!("seed{seed_chirho}"), &group_chirho);
        let roster_chirho = voters_chirho(NODES_CHIRHO);
        let mut lcg_chirho: u64 = 0x9e37_79b9_7f4a_7c15 ^ seed_chirho.wrapping_mul(0x1000_0001);

        // Chaos phase: seeded random partitions, with occasional durable crash/restart of a node.
        for _round_chirho in 0..CHAOS_ROUNDS_CHIRHO {
            lcg_chirho = next_lcg_chirho(lcg_chirho);

            // 1-in-4 rounds fully heal (all one side); otherwise each node draws a partition side bit,
            // giving 5-0/4-1/3-2 splits — a side with a majority (>= 3) can elect, a minority cannot.
            let heal_chirho = lcg_chirho.is_multiple_of(4);
            let side_chirho: Vec<u8> = (0..NODES_CHIRHO)
                .map(|index_chirho| {
                    if heal_chirho {
                        0
                    } else {
                        ((lcg_chirho >> (index_chirho + 8)) & 1) as u8
                    }
                })
                .collect();

            tick_and_route_partitioned_chirho(&nodes_chirho, &side_chirho);
            assert_no_two_leaders_in_one_term_chirho(&nodes_chirho, &group_chirho, "chaos");

            // Occasional crash+restart: drop a node and reopen it from its durable dir (it loses RAM but
            // not disk), exercising durable recovery + rejoin under a live partition. (Honesty note: with
            // pre-vote on this does NOT force a same-term double-vote, so it does not by itself prove the
            // durable vote — that is the single-node unit test's job; here it is integration coverage.)
            if lcg_chirho.is_multiple_of(12) {
                let victim_chirho = ((lcg_chirho >> 20) % NODES_CHIRHO) as usize;
                nodes_chirho[victim_chirho] =
                    RaftWriterElectorChirho::new_durable_cluster_node_chirho(
                        dirs_chirho[victim_chirho].clone(),
                        group_chirho.clone(),
                        (victim_chirho as u64) + 1,
                        roster_chirho.clone(),
                    )
                    .expect("reopen a crashed node from its durable dir");
                assert_no_two_leaders_in_one_term_chirho(
                    &nodes_chirho,
                    &group_chirho,
                    "post-restart",
                );
            }
        }

        // Heal phase: no more partitions or crashes — within a bounded number of rounds the cluster must
        // converge on exactly one leader that every node agrees on.
        let all_together_chirho: Vec<u8> = vec![0; NODES_CHIRHO as usize];
        let mut converged_chirho = false;
        for _round_chirho in 0..HEAL_ROUNDS_CHIRHO {
            tick_and_route_partitioned_chirho(&nodes_chirho, &all_together_chirho);
            assert_no_two_leaders_in_one_term_chirho(&nodes_chirho, &group_chirho, "heal");
            if converged_on_one_leader_chirho(&nodes_chirho, &group_chirho) {
                converged_chirho = true;
                break;
            }
        }
        assert!(
            converged_chirho,
            "seed {seed_chirho}: after healing, the cluster converges on exactly one agreed leader"
        );

        for dir_chirho in dirs_chirho {
            let _ = std::fs::remove_dir_all(dir_chirho);
        }
    }
}

/// THE COMPOSITION THE F1 LEASE DEPENDS ON, pinned.
///
/// The lease's expiry clause detects exactly one thing: that the local tick driver stopped. It does
/// NOT detect loss of authority — a tick fires whether or not any peer is still reachable, so an
/// isolated node with a healthy ticker refreshes its confirmation forever. Quorum loss is caught
/// somewhere else entirely: raft's `check_quorum` steps the leader down, the role bit drops, and the
/// lease's `is_leader` clause fails.
///
/// Each of those clauses has its own test. What had NO test was the claim that they are together
/// SUFFICIENT — which means the safety of the lease rested on an assumption about a different
/// component that nothing re-checked when that component changed. This pins it: partition the leader
/// away while it keeps ticking, and its lease must go invalid anyway.
#[test]
fn a_partitioned_leader_loses_its_lease_through_step_down_not_expiry_chirho() {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-lease-composition-chirho".to_string(),
    };
    let roster_chirho = voters_chirho(NODES_CHIRHO);
    let mut nodes_chirho = Vec::new();
    for raft_id_chirho in 1..=NODES_CHIRHO {
        let dir_chirho = temp_dir_chirho(&format!("lease-composition-n{raft_id_chirho}"));
        // Expiry is longer than the clock ever advances here, so only step-down can invalidate it.
        nodes_chirho.push(
            RaftWriterElectorChirho::new_durable_cluster_node_with_monotonic_leadership_lease_chirho(
                dir_chirho,
                group_chirho.clone(),
                raft_id_chirho,
                roster_chirho.clone(),
                clock_chirho.clone(),
                100,
                1_000_000,
            )
            .expect("build durable cluster node"),
        );
    }

    // Whole cluster together until someone holds a valid lease.
    let together_chirho = [0_u8; NODES_CHIRHO as usize];
    let mut leader_index_chirho = None;
    for _round_chirho in 0..80 {
        clock_chirho.advance_millis_chirho(20);
        tick_and_route_partitioned_chirho(&nodes_chirho, &together_chirho);
        if let Some(index_chirho) = nodes_chirho.iter().position(|node_chirho| {
            node_chirho
                .leadership_chirho(&group_chirho)
                .lease_valid_chirho
        }) {
            leader_index_chirho = Some(index_chirho);
            break;
        }
    }
    let leader_index_chirho = leader_index_chirho.expect("a leader takes a valid lease");

    // Cut that leader off from both peers. It KEEPS TICKING, so its confirmation keeps refreshing and
    // the expiry clause never fires — the only thing that can invalidate its lease is losing the role.
    let mut side_chirho = [0_u8; NODES_CHIRHO as usize];
    side_chirho[leader_index_chirho] = 1;
    let mut lease_after_chirho = true;
    for _round_chirho in 0..120 {
        clock_chirho.advance_millis_chirho(20);
        tick_and_route_partitioned_chirho(&nodes_chirho, &side_chirho);
        let view_chirho = nodes_chirho[leader_index_chirho].leadership_chirho(&group_chirho);
        if !view_chirho.lease_valid_chirho {
            lease_after_chirho = false;
            assert!(
                !view_chirho.is_leader_chirho,
                "the lease must have gone invalid because the node STEPPED DOWN, not for any other \
                 reason -- if it is still leader here, the composition is not what this test claims"
            );
            break;
        }
    }
    assert!(
        !lease_after_chirho,
        "a partitioned leader must lose its lease even while its own ticker is perfectly healthy; \
         the expiry clause cannot see quorum loss, so this is check_quorum's step-down doing the work"
    );
}
