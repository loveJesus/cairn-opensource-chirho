// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Election robustness on a realistic cross-geo WAN with NO partition: links are UP but slow. Every
//! message is delivered after a seeded 1..=MAX-tick delay (so messages arrive OUT of send order), and in
//! the first phase a seeded fraction is dropped (a lossy link raft must retransmit around). Throughout,
//! the cluster never elects two DISTINCT leaders in one term (safety under reordering + loss); and once
//! the link settles to merely-slow (still delayed, no loss), it converges on exactly one agreed leader
//! (liveness). The message SCHEDULE (delay/reorder/loss) is seed-deterministic via an LCG + a logical
//! arrival-tick queue, with no wall clock/threads/sockets; raft-rs's own election-timeout randomization
//! is entropy-driven (`thread_rng`), so the exact leaders/terms vary run to run — the soak is robust
//! across that variation, not bit-reproducible from the seed.
//!
//! The max delay is kept BELOW the election timeout on purpose: that is the healthy cross-geo operating
//! point (size `tick_interval` so `election_tick` spans well over the WAN round-trip) and is the concrete
//! form of the performance answer — with the timeout comfortably above link latency, a slow WAN does not
//! cause election churn, so writes are not blocked by cross-geo consensus flapping.

use super::election_test_support_chirho::{
    assert_no_two_leaders_in_one_term_chirho, converged_on_one_leader_chirho, next_lcg_chirho,
    voters_chirho,
};
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;

const NODES_CHIRHO: u64 = 5;
/// Per-message latency ceiling, in logical ticks. Deliberately < the elector's `election_tick` (10) — the
/// healthy regime where a slow link does not trip election timeouts.
const MAX_DELAY_TICKS_CHIRHO: u64 = 6;
/// ~1-in-N messages dropped on the lossy link (raft retransmits around loss).
const DROP_ONE_IN_CHIRHO: u64 = 8;
const LOSSY_STEPS_CHIRHO: usize = 400;
const SETTLE_STEPS_CHIRHO: usize = 400;

/// Build an EPHEMERAL voter cluster (crash-durability is the chaos soak's concern; here the focus is
/// message timing, so the lighter in-memory store keeps the sim fast).
fn build_ephemeral_cluster_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
) -> Vec<RaftWriterElectorChirho> {
    let roster_chirho = voters_chirho(NODES_CHIRHO);
    (1..=NODES_CHIRHO)
        .map(|raft_id_chirho| {
            RaftWriterElectorChirho::new_cluster_node_chirho(
                group_chirho.clone(),
                raft_id_chirho,
                roster_chirho.clone(),
            )
            .expect("build an ephemeral cluster node")
        })
        .collect()
}

/// Schedule one outbound encoded message onto the in-flight queue. With `lossy_chirho`, a seeded fraction
/// is dropped; the rest arrive after a seeded 1..=MAX delay (variable latency, which reorders messages
/// relative to send order). Advances and returns the LCG.
fn schedule_message_chirho(
    inflight_chirho: &mut Vec<(u64, u64, Vec<u8>)>,
    now_chirho: u64,
    to_chirho: u64,
    bytes_chirho: Vec<u8>,
    lossy_chirho: bool,
    lcg_chirho: u64,
) -> u64 {
    let lcg_chirho = next_lcg_chirho(lcg_chirho);
    if lossy_chirho && lcg_chirho.is_multiple_of(DROP_ONE_IN_CHIRHO) {
        return lcg_chirho; // dropped on the lossy link — raft will retransmit
    }
    let delay_chirho = 1 + (lcg_chirho >> 8) % MAX_DELAY_TICKS_CHIRHO;
    inflight_chirho.push((now_chirho + delay_chirho, to_chirho, bytes_chirho));
    lcg_chirho
}

/// Run one WAN phase for `steps_chirho` logical ticks: each tick, tick every node and schedule its
/// outbound with delay/loss, then deliver every in-flight message whose arrival tick has come (stepping
/// it and scheduling its replies). Asserts the safety invariant after every tick. Returns the LCG.
fn run_wan_phase_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    group_chirho: &ConsistencyGroupIdChirho,
    inflight_chirho: &mut Vec<(u64, u64, Vec<u8>)>,
    now_chirho: &mut u64,
    steps_chirho: usize,
    lossy_chirho: bool,
    mut lcg_chirho: u64,
) -> u64 {
    let context_chirho = if lossy_chirho {
        "lossy-slow-wan"
    } else {
        "slow-wan-settle"
    };
    for _step_chirho in 0..steps_chirho {
        *now_chirho += 1;

        // Tick every node; schedule the messages the ticks emit.
        for node_chirho in nodes_chirho {
            for (to_chirho, bytes_chirho) in node_chirho.tick_encoded_chirho().expect("tick a node")
            {
                lcg_chirho = schedule_message_chirho(
                    inflight_chirho,
                    *now_chirho,
                    to_chirho,
                    bytes_chirho,
                    lossy_chirho,
                    lcg_chirho,
                );
            }
        }

        // Partition the in-flight queue into due (arrival <= now) and still-in-flight, without cloning.
        let mut due_chirho: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut future_chirho: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        for (arrival_chirho, to_chirho, bytes_chirho) in inflight_chirho.drain(..) {
            if arrival_chirho <= *now_chirho {
                due_chirho.push((to_chirho, bytes_chirho));
            } else {
                future_chirho.push((arrival_chirho, to_chirho, bytes_chirho));
            }
        }
        *inflight_chirho = future_chirho;

        // Deliver the due messages; their replies re-enter the queue with their own delay/loss.
        for (to_chirho, bytes_chirho) in due_chirho {
            if let Some(target_chirho) = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == to_chirho)
            {
                for (next_to_chirho, next_bytes_chirho) in target_chirho
                    .step_encoded_chirho(&bytes_chirho)
                    .expect("step a delivered message")
                {
                    lcg_chirho = schedule_message_chirho(
                        inflight_chirho,
                        *now_chirho,
                        next_to_chirho,
                        next_bytes_chirho,
                        lossy_chirho,
                        lcg_chirho,
                    );
                }
            }
        }

        assert_no_two_leaders_in_one_term_chirho(nodes_chirho, group_chirho, context_chirho);
    }
    lcg_chirho
}

#[test]
fn election_is_safe_under_wan_latency_reordering_and_loss_chirho() {
    for seed_chirho in 0..3u64 {
        let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: format!("/var/lib/cairn-wan-{seed_chirho}-chirho"),
        };
        let nodes_chirho = build_ephemeral_cluster_chirho(&group_chirho);
        let mut inflight_chirho: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        let mut now_chirho: u64 = 0;
        let mut lcg_chirho: u64 = 0x9e37_79b9_7f4a_7c15 ^ seed_chirho.wrapping_mul(0x51ed_2701);

        // Phase 1: a lossy, reordering, high-latency WAN — safety must hold every tick.
        lcg_chirho = run_wan_phase_chirho(
            &nodes_chirho,
            &group_chirho,
            &mut inflight_chirho,
            &mut now_chirho,
            LOSSY_STEPS_CHIRHO,
            true,
            lcg_chirho,
        );

        // Phase 2: the link settles to merely-slow (still delayed, no loss) — the cluster must converge.
        run_wan_phase_chirho(
            &nodes_chirho,
            &group_chirho,
            &mut inflight_chirho,
            &mut now_chirho,
            SETTLE_STEPS_CHIRHO,
            false,
            lcg_chirho,
        );

        assert!(
            converged_on_one_leader_chirho(&nodes_chirho, &group_chirho),
            "seed {seed_chirho}: once the lossy WAN settles to merely-slow, the cluster converges on \
             exactly one agreed leader"
        );
    }
}
