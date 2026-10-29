// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The raft-rs-backed single-node elector runs real consensus: a fresh node is a follower, and after
//! campaigning the sole voter self-elects to leader with its own identity and a valid lease at term >= 1.

use crate::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use crate::local_append_authority_chirho::LocalAppendAuthorityRefusalChirho;
use crate::monotonic_clock_chirho::{FakeMonotonicClockChirho, MonotonicClockChirho};
use crate::raft_elector_chirho::{
    election_timeout_upper_bound_chirho, validate_election_timeout_relay_margin_chirho,
    RaftWriterElectorChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::{Message, MessageType};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Deliberately violates the monotonic-clock contract so defensive fail-closed behavior is executable.
#[derive(Debug)]
struct RegressingClockFixtureChirho {
    now_millis_chirho: AtomicU64,
}

impl RegressingClockFixtureChirho {
    fn new_chirho(now_millis_chirho: u64) -> Arc<Self> {
        Arc::new(Self {
            now_millis_chirho: AtomicU64::new(now_millis_chirho),
        })
    }

    fn set_millis_chirho(&self, now_millis_chirho: u64) {
        self.now_millis_chirho
            .store(now_millis_chirho, Ordering::Release);
    }
}

impl MonotonicClockChirho for RegressingClockFixtureChirho {
    fn now_millis_chirho(&self) -> u64 {
        self.now_millis_chirho.load(Ordering::Acquire)
    }
}

#[test]
fn relay_margin_refuses_when_healthy_remaining_exactly_equals_transit_chirho() {
    let equal_budget_chirho = NonZeroU64::new(252).expect("test transit budget is nonzero");
    let refusal_chirho = validate_election_timeout_relay_margin_chirho(
        std::time::Duration::from_millis(28),
        equal_budget_chirho,
    )
    .expect_err("zero post-deduction duration must refuse");
    assert!(
        refusal_chirho
            .to_string()
            .contains("RelayLeaseTransitBudgetIncompatibleChirho"),
        "equality must keep the named fail-closed compatibility identity"
    );
    validate_election_timeout_relay_margin_chirho(
        std::time::Duration::from_millis(28),
        NonZeroU64::new(251).expect("test transit budget is nonzero"),
    )
    .expect("one positive millisecond after deduction is compatible");
}

#[test]
fn election_timeout_upper_bound_outlasts_every_randomized_timeout_chirho() {
    // raft keeps every randomized election timeout strictly below `max_election_tick`, which
    // defaults to twice the configured election tick, so the bound is two election timeouts.
    let tick_chirho = std::time::Duration::from_millis(250);
    let bound_chirho = election_timeout_upper_bound_chirho(tick_chirho).expect("valid tick");
    let election_timeout_chirho = tick_chirho
        .checked_mul(crate::lease_composition_chirho::ELECTION_TICK_CHIRHO as u32)
        .expect("one election timeout");
    assert_eq!(bound_chirho, election_timeout_chirho * 2);
    assert!(
        election_timeout_upper_bound_chirho(std::time::Duration::ZERO).is_err(),
        "a zero tick has no election timeout and must refuse"
    );
    assert!(
        election_timeout_upper_bound_chirho(std::time::Duration::from_micros(250_500)).is_err(),
        "a tick that is not a whole number of milliseconds must refuse, as the lease does"
    );
}

#[test]
fn single_node_raft_elector_self_elects_chirho() {
    let node_id_chirho = NodeIdChirho("b".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-root-chirho".to_string(),
    };
    let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        node_id_chirho.clone(),
        group_chirho.clone(),
    )
    .expect("build a single-node raft elector");

    // A fresh node is a follower until it campaigns.
    let before_chirho = elector_chirho.leadership_chirho(&group_chirho);
    assert!(
        !before_chirho.is_leader_chirho,
        "a fresh node is a follower until it campaigns"
    );

    // Campaigning brings the sole voter to leadership.
    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");
    let after_chirho = elector_chirho.leadership_chirho(&group_chirho);
    assert!(
        after_chirho.is_leader_chirho,
        "a single-voter group self-elects its sole member"
    );
    assert_eq!(
        after_chirho.leader_id_chirho.as_ref(),
        Some(&node_id_chirho)
    );
    assert!(
        after_chirho.term_chirho >= 1,
        "the elected leader holds a term"
    );
    assert!(
        after_chirho.lease_valid_chirho,
        "a quorum-holding leader has a valid lease"
    );

    // This elector governs exactly one group; a different group is not-leader here.
    let other_group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "other-tenant-chirho".to_string(),
    };
    assert!(
        !elector_chirho
            .leadership_chirho(&other_group_chirho)
            .is_leader_chirho
    );

    assert_eq!(elector_chirho.node_id_chirho(), &node_id_chirho);
}

#[test]
fn three_node_cluster_elects_one_stable_leader_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-3node-chirho".to_string(),
    };
    let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
        (3, NodeIdChirho("3".repeat(64))),
    ];
    let nodes_chirho: Vec<RaftWriterElectorChirho> = (1..=3)
        .map(|raft_id_chirho| {
            RaftWriterElectorChirho::new_cluster_node_chirho(
                group_chirho.clone(),
                raft_id_chirho,
                voters_chirho.clone(),
            )
            .expect("build a cluster-member elector")
        })
        .collect();

    // In-memory router: node 1 campaigns to start the election; deliver every outbound message to its
    // target's step(), collecting the responses, until the bus drains (the election + no-op commit
    // settle). No ticks fire, so once consensus settles no new messages are produced.
    let mut bus_chirho: Vec<Message> = nodes_chirho[0].campaign_chirho().expect("node 1 campaigns");
    for _round_chirho in 0..1000 {
        if bus_chirho.is_empty() {
            break;
        }
        let mut next_chirho: Vec<Message> = Vec::new();
        for message_chirho in bus_chirho.drain(..) {
            let to_chirho = message_chirho.to;
            if let Some(target_chirho) = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == to_chirho)
            {
                next_chirho.extend(
                    target_chirho
                        .step_chirho(message_chirho)
                        .expect("step message"),
                );
            }
        }
        bus_chirho = next_chirho;
    }

    // Exactly one leader emerges, and every node agrees on that same leader at a real term.
    let leaders_chirho: Vec<&RaftWriterElectorChirho> = nodes_chirho
        .iter()
        .filter(|node_chirho| {
            node_chirho
                .leadership_chirho(&group_chirho)
                .is_leader_chirho
        })
        .collect();
    assert_eq!(leaders_chirho.len(), 1, "exactly one leader emerges");

    let leader_view_chirho = leaders_chirho[0].leadership_chirho(&group_chirho);
    assert!(leader_view_chirho.leader_id_chirho.is_some());
    assert!(leader_view_chirho.lease_valid_chirho);
    for node_chirho in &nodes_chirho {
        let leadership_chirho = node_chirho.leadership_chirho(&group_chirho);
        assert_eq!(
            leadership_chirho.leader_id_chirho, leader_view_chirho.leader_id_chirho,
            "all nodes agree on the same leader"
        );
        assert!(leadership_chirho.term_chirho >= 1);
    }
}

fn three_node_cluster_chirho(
    label_chirho: &str,
) -> (ConsistencyGroupIdChirho, Vec<RaftWriterElectorChirho>) {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-{label_chirho}-chirho"),
    };
    let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
        (3, NodeIdChirho("3".repeat(64))),
    ];
    let nodes_chirho = (1..=3)
        .map(|raft_id_chirho| {
            RaftWriterElectorChirho::new_cluster_node_chirho(
                group_chirho.clone(),
                raft_id_chirho,
                voters_chirho.clone(),
            )
            .expect("build a cluster-member elector")
        })
        .collect();
    (group_chirho, nodes_chirho)
}

#[test]
fn three_node_election_converges_over_the_encoded_wire_chirho() {
    let (group_chirho, nodes_chirho) = three_node_cluster_chirho("3node-wire");

    // Drive the whole election through the ENCODED (bytes) API: every message is prost-encoded by the
    // sender and decoded by the receiver — exactly what a transport moves. If the wire format did not
    // round-trip, consensus would not converge.
    let mut bus_chirho: Vec<(u64, Vec<u8>)> = nodes_chirho[0]
        .campaign_encoded_chirho()
        .expect("node 1 campaigns over the wire");
    for _round_chirho in 0..1000 {
        if bus_chirho.is_empty() {
            break;
        }
        let mut next_chirho: Vec<(u64, Vec<u8>)> = Vec::new();
        for (to_chirho, message_bytes_chirho) in bus_chirho.drain(..) {
            if let Some(target_chirho) = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == to_chirho)
            {
                next_chirho.extend(
                    target_chirho
                        .step_encoded_chirho(&message_bytes_chirho)
                        .expect("step an encoded message"),
                );
            }
        }
        bus_chirho = next_chirho;
    }

    let leaders_chirho: Vec<&RaftWriterElectorChirho> = nodes_chirho
        .iter()
        .filter(|node_chirho| {
            node_chirho
                .leadership_chirho(&group_chirho)
                .is_leader_chirho
        })
        .collect();
    assert_eq!(
        leaders_chirho.len(),
        1,
        "exactly one leader emerges over the encoded wire"
    );
    let leader_id_chirho = leaders_chirho[0]
        .leadership_chirho(&group_chirho)
        .leader_id_chirho;
    for node_chirho in &nodes_chirho {
        assert_eq!(
            node_chirho
                .leadership_chirho(&group_chirho)
                .leader_id_chirho,
            leader_id_chirho,
            "all nodes agree on the leader after crossing the wire format"
        );
    }
}

#[test]
fn three_node_cluster_elects_from_tick_timeouts_without_campaign_chirho() {
    // The PRODUCTION election path: no explicit `campaign`. Drive the cluster purely by TICKING every
    // node (what a background driver does on a timer); a node whose election timeout elapses starts the
    // election on its own. This is deterministic — it advances raft's logical clock by counting `tick`
    // calls, using no wall clock or real timer, so it cannot be flaky — and bounded by raft's liveness.
    let (group_chirho, nodes_chirho) = three_node_cluster_chirho("3node-tick");

    let mut elected_chirho = false;
    for _round_chirho in 0..2000 {
        // Tick every node once; collect whatever outbound messages the ticks produce.
        let mut bus_chirho: Vec<(u64, Vec<u8>)> = Vec::new();
        for node_chirho in &nodes_chirho {
            bus_chirho.extend(node_chirho.tick_encoded_chirho().expect("tick a node"));
        }
        // Route those messages (and their replies) to convergence before the next tick round.
        for _sub_round_chirho in 0..1000 {
            if bus_chirho.is_empty() {
                break;
            }
            let mut next_chirho: Vec<(u64, Vec<u8>)> = Vec::new();
            for (to_chirho, message_bytes_chirho) in bus_chirho.drain(..) {
                if let Some(target_chirho) = nodes_chirho
                    .iter()
                    .find(|node_chirho| node_chirho.local_raft_id_chirho() == to_chirho)
                {
                    next_chirho.extend(
                        target_chirho
                            .step_encoded_chirho(&message_bytes_chirho)
                            .expect("step a ticked message"),
                    );
                }
            }
            bus_chirho = next_chirho;
        }
        if nodes_chirho.iter().any(|node_chirho| {
            node_chirho
                .leadership_chirho(&group_chirho)
                .is_leader_chirho
        }) {
            elected_chirho = true;
            break;
        }
    }

    assert!(
        elected_chirho,
        "an election starts from tick timeouts alone (no explicit campaign) and converges"
    );
    let leaders_chirho: Vec<&RaftWriterElectorChirho> = nodes_chirho
        .iter()
        .filter(|node_chirho| {
            node_chirho
                .leadership_chirho(&group_chirho)
                .is_leader_chirho
        })
        .collect();
    assert_eq!(
        leaders_chirho.len(),
        1,
        "exactly one leader emerges from the tick-driven election"
    );
    let leader_id_chirho = leaders_chirho[0]
        .leadership_chirho(&group_chirho)
        .leader_id_chirho;
    assert!(leader_id_chirho.is_some());
    for node_chirho in &nodes_chirho {
        assert_eq!(
            node_chirho
                .leadership_chirho(&group_chirho)
                .leader_id_chirho,
            leader_id_chirho,
            "all nodes agree on the tick-elected leader"
        );
    }
}

#[test]
fn warmup_lease_is_invalid_until_leadership_held_for_an_election_timeout_chirho() {
    // Option A: with the warm-up lease enabled, a freshly-elected leader is is_leader immediately but
    // NOT lease-valid until it has held leadership for a full election timeout of ticks — so a
    // deposed/flapped leader (whose role bit drops within one timeout) is never lease-valid.
    let node_id_chirho = NodeIdChirho("d".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-warmup-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_id_chirho, group_chirho.clone())
            .expect("build elector")
            .with_leadership_warmup_lease_chirho();

    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");
    let after_campaign_chirho = elector_chirho.leadership_chirho(&group_chirho);
    assert!(
        after_campaign_chirho.is_leader_chirho,
        "single node self-elects"
    );
    assert!(
        !after_campaign_chirho.lease_valid_chirho,
        "warm-up lease is NOT valid immediately after election"
    );

    // Nine ticks of continuous leadership is still short of the election-timeout warm-up.
    for _tick_chirho in 0..9 {
        elector_chirho.tick_chirho();
    }
    assert!(
        !elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "still warming up before a full election timeout of leadership"
    );

    // The tenth tick completes the warm-up: the lease is now valid.
    elector_chirho.tick_chirho();
    let warmed_chirho = elector_chirho.leadership_chirho(&group_chirho);
    assert!(warmed_chirho.is_leader_chirho);
    assert!(
        warmed_chirho.lease_valid_chirho,
        "after a full election timeout of continuous leadership the warm-up lease is valid"
    );
}

#[test]
fn warmed_lease_never_decays_because_it_counts_ticks_rather_than_time_chirho() {
    // The OTHER direction of the warm-up lease, and the one that decides how it may be USED.
    //
    // The sibling test above proves the lease is not valid UNTIL an election timeout of ticks. This
    // proves it never becomes invalid AFTERWARDS on its own: `lease_valid` is
    // `is_leader && leader_tick_count >= ELECTION_TICK`, and `leadership_chirho` reads status and a
    // counter — it never ticks and never consults a clock. So the lease measures TICKS OBSERVED, not
    // TIME ELAPSED, and a warmed leader whose tick driver stops reports a valid lease indefinitely.
    //
    // This is the DOCUMENTED design, not a defect: the elector's own comment says the value is
    // "OBSERVED only (the canary; later the cutover mint gate), never authoritative here". The test
    // exists so that property is EXECUTABLE — anyone later tempted to treat `lease_valid` as
    // authority for a money write has a running assertion telling them what it actually measures.
    //
    // RECONCILING THIS WITH AUDIT FINDING F1, which calls the same behaviour the most critical
    // blocker: both are true, at different scopes, and a reviewer meeting one should know the other.
    // TODAY the value is observed-only, so counting ticks is sound and this test simply says what it
    // measures. F1 is about the A6 wiring, where the elected fence would GATE money writes — at that
    // moment a lease that cannot expire stops being a harmless counter, because a partitioned leader
    // whose tick driver died would still present a valid one. So F1 is a LATENT defect: not wrong
    // now, disqualifying the instant this value becomes authority. That is precisely why the failure
    // message below treats a real expiry as good news rather than a regression.
    let node_id_chirho = NodeIdChirho("f".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-lease-decay-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_id_chirho, group_chirho.clone())
            .expect("build elector")
            .with_leadership_warmup_lease_chirho();

    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");
    for _tick_chirho in 0..10 {
        elector_chirho.tick_chirho();
    }
    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "warm-up should have completed after a full election timeout of ticks"
    );

    // Now STOP ticking entirely — the shape of a dead tick driver — and observe repeatedly.
    // Every read still reports a valid lease. No wall-clock decay exists to expire it.
    for observation_chirho in 0..25 {
        let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
        assert!(
            leadership_chirho.lease_valid_chirho,
            "observation {observation_chirho}: the warmed lease is still reported valid with zero \
             intervening ticks. This is a COUNTER, not a CLOCK — if this ever starts failing, the \
             lease grew a real expiry and the 'observed only, never authoritative' note on \
             lease_valid_chirho should be revisited. Expiry would close local dead-ticker liveness; \
             it would not by itself prove quorum recency or final-sink exclusion"
        );
    }
}

#[test]
fn default_lease_is_the_immediate_role_bit_without_the_warmup_optin_chirho() {
    // Without `with_leadership_warmup_lease_chirho`, `lease_valid` stays the raw is_leader bit — valid as
    // soon as the node is elected (the single-host shadow behavior the warm-up is opt-in on top of).
    let node_id_chirho = NodeIdChirho("e".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-nowarmup-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_id_chirho, group_chirho.clone())
            .expect("build elector");

    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");
    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "the default (non-warm-up) lease is valid immediately on election"
    );
}

/// Route encoded messages (and their replies) to convergence over the in-process cluster.
fn route_encoded_to_convergence_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    mut bus_chirho: Vec<(u64, Vec<u8>)>,
) {
    for _round_chirho in 0..1000 {
        if bus_chirho.is_empty() {
            break;
        }
        let mut next_chirho: Vec<(u64, Vec<u8>)> = Vec::new();
        for (to_chirho, message_bytes_chirho) in bus_chirho.drain(..) {
            if let Some(target_chirho) = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == to_chirho)
            {
                next_chirho.extend(
                    target_chirho
                        .step_encoded_chirho(&message_bytes_chirho)
                        .expect("step an encoded message"),
                );
            }
        }
        bus_chirho = next_chirho;
    }
}

#[test]
fn leadership_transfers_from_the_elected_leader_to_a_target_chirho() {
    // The "pin the master back to its home region on heal" primitive: an elected leader hands leadership
    // to a chosen target, and the target takes over at a strictly newer term with every node agreeing.
    let (group_chirho, nodes_chirho) = three_node_cluster_chirho("3node-transfer");

    // Node 1 wins the initial election.
    let bus_chirho = nodes_chirho[0]
        .campaign_encoded_chirho()
        .expect("node 1 campaigns");
    route_encoded_to_convergence_chirho(&nodes_chirho, bus_chirho);
    assert!(
        nodes_chirho[0]
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "node 1 is the initial leader"
    );
    let first_term_chirho = nodes_chirho[0].leadership_chirho(&group_chirho).term_chirho;

    // Transfer leadership from node 1 to node 2, then let it settle.
    let transfer_bus_chirho = nodes_chirho[0]
        .transfer_leadership_to_chirho(2)
        .expect("initiate leadership transfer to node 2");
    route_encoded_to_convergence_chirho(&nodes_chirho, transfer_bus_chirho);

    // Node 2 is now the leader, at a strictly newer term, node 1 stepped down, and every node agrees.
    let node2_view_chirho = nodes_chirho[1].leadership_chirho(&group_chirho);
    assert!(
        node2_view_chirho.is_leader_chirho,
        "leadership transferred to node 2"
    );
    assert!(
        node2_view_chirho.term_chirho > first_term_chirho,
        "the transfer advances the term"
    );
    assert!(
        !nodes_chirho[0]
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "the old leader stepped down"
    );
    let leader_id_chirho = node2_view_chirho.leader_id_chirho;
    for node_chirho in &nodes_chirho {
        assert_eq!(
            node_chirho
                .leadership_chirho(&group_chirho)
                .leader_id_chirho,
            leader_id_chirho,
            "all nodes agree on the transferred leader"
        );
    }
}

#[test]
fn a_learner_replicates_but_is_never_elected_chirho() {
    // The geo-DR primitive: a non-voting learner (a remote async replica). It replicates the log and
    // follows the elected leader, but it does NOT count toward the commit quorum and can never win —
    // which is what lets a home-region voter quorum commit without waiting on a distant replica.
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-learner-chirho".to_string(),
    };
    let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
        (3, NodeIdChirho("3".repeat(64))),
    ];
    let learners_chirho: Vec<(u64, NodeIdChirho)> = vec![(4, NodeIdChirho("4".repeat(64)))];

    // Four electors: raft ids 1-3 are voters, raft id 4 is the learner — all with the same membership.
    let nodes_chirho: Vec<RaftWriterElectorChirho> = (1..=4)
        .map(|raft_id_chirho| {
            RaftWriterElectorChirho::new_cluster_node_with_learners_chirho(
                group_chirho.clone(),
                raft_id_chirho,
                voters_chirho.clone(),
                learners_chirho.clone(),
            )
            .expect("build a voter/learner elector")
        })
        .collect();

    // A voter campaigns; the learner takes part only as a replication target.
    let bus_chirho = nodes_chirho[0]
        .campaign_encoded_chirho()
        .expect("node 1 campaigns");
    route_encoded_to_convergence_chirho(&nodes_chirho, bus_chirho);

    // Exactly one leader, and it is a VOTER — never the learner.
    let leaders_chirho: Vec<&RaftWriterElectorChirho> = nodes_chirho
        .iter()
        .filter(|node_chirho| {
            node_chirho
                .leadership_chirho(&group_chirho)
                .is_leader_chirho
        })
        .collect();
    assert_eq!(leaders_chirho.len(), 1, "exactly one leader emerges");
    assert_ne!(
        leaders_chirho[0].local_raft_id_chirho(),
        4,
        "the learner is never elected leader"
    );

    // The learner (raft id 4) is a follower that has replicated and agrees on the elected leader.
    let learner_view_chirho = nodes_chirho[3].leadership_chirho(&group_chirho);
    assert!(
        !learner_view_chirho.is_leader_chirho,
        "the learner is not the leader"
    );
    assert_eq!(
        learner_view_chirho.leader_id_chirho,
        leaders_chirho[0]
            .leadership_chirho(&group_chirho)
            .leader_id_chirho,
        "the learner replicated from and follows the elected leader"
    );
}

#[test]
fn a_voter_and_learner_id_collision_is_a_clean_error_not_a_panic_chirho() {
    // raft-rs panics on a conf state where an id is both a voter and a learner; the elector must reject
    // that membership config as a clean error at construction, not crash the caller thread.
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-collision-chirho".to_string(),
    };
    let voters_chirho: Vec<(u64, NodeIdChirho)> = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
    ];
    // raft id 2 is listed as BOTH a voter and a learner.
    let learners_chirho: Vec<(u64, NodeIdChirho)> = vec![(2, NodeIdChirho("9".repeat(64)))];

    let result_chirho = RaftWriterElectorChirho::new_cluster_node_with_learners_chirho(
        group_chirho,
        1,
        voters_chirho,
        learners_chirho,
    );
    assert!(
        result_chirho.is_err(),
        "an id listed as both voter and learner is a clean error, not a panic"
    );
}

#[test]
fn the_monotonic_lease_decays_when_nobody_is_ticking_chirho() {
    // F1, THE WHOLE POINT. The old lease counted ticks, so once warmed it stayed valid forever — a
    // leader whose tick driver died reported a good lease indefinitely, because the mechanism that
    // would notice the staleness is the mechanism that stopped. A liveness check that depends on the
    // liveness it checks cannot report its own death.
    //
    // Here the lease is measured on an injected monotonic clock: held long enough to be warm, AND
    // confirmed recently enough to still be alive. Nobody has to call anything for it to expire —
    // time passing is sufficient, which is exactly the criterion the second seat set.
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-monotonic-lease-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("a".repeat(64)),
            group_chirho.clone(),
            clock_chirho.clone(),
            500,
            500,
        )
        .expect("build elector");

    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");

    // BEFORE the warm-up elapses the lease must NOT be valid, even though raft already reports this
    // node as leader. Without this the warm-up clause is untested -- removing it entirely broke
    // nothing, which is how a just-elected or freshly flapped leader would present as warmed.
    clock_chirho.advance_millis_chirho(100);
    elector_chirho.tick_chirho();
    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "raft considers this node leader immediately"
    );
    assert!(
        !elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "but the lease must not be valid until the warm-up duration of REAL time has elapsed"
    );

    // Warm up: tick while time advances, until the lease reports valid.
    for _step_chirho in 0..20 {
        clock_chirho.advance_millis_chirho(50);
        elector_chirho.tick_chirho();
    }
    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "the lease must become valid once leadership has been held for the warm-up duration"
    );

    // The control: keep ticking as time passes and it STAYS valid, so the expiry below is not just
    // the lease being broken in the other direction.
    for _step_chirho in 0..10 {
        clock_chirho.advance_millis_chirho(100);
        elector_chirho.tick_chirho();
        assert!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .lease_valid_chirho,
            "a leader that is still ticking must keep its lease"
        );
    }

    // THE PROPERTY: the tick driver dies. Nothing is called on the elector at all — only time moves.
    clock_chirho.advance_millis_chirho(501);
    assert!(
        !elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "the lease must EXPIRE with nobody calling anything -- a dead tick driver is precisely the \
         case where no one is left to notice, and raft still reports this node as leader"
    );
    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "and raft still says leader, which is why the lease -- not the role bit -- has to be the gate"
    );
}

#[test]
fn monotonic_refresh_preserves_one_constructor_minted_generation_chirho() {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-monotonic-generation-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("e".repeat(64)),
            group_chirho.clone(),
            clock_chirho.clone(),
            100,
            100,
        )
        .expect("build generation-stability elector");

    elector_chirho
        .campaign_chirho()
        .expect("campaign generation-stability elector");
    clock_chirho.advance_millis_chirho(1);
    elector_chirho.tick_chirho();
    clock_chirho.advance_millis_chirho(100);
    elector_chirho.tick_chirho();

    let current_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let first_generation_chirho = current_handle_chirho
        .try_acquire_chirho()
        .expect("warm monotonic handle acquires")
        .process_generation_chirho();
    assert_eq!(
        elector_chirho.current_lease_remaining_millis_chirho(),
        Some(100)
    );

    clock_chirho.advance_millis_chirho(20);
    assert_eq!(
        elector_chirho.current_lease_remaining_millis_chirho(),
        Some(80),
        "elapsed time must consume the published confirmation before refresh"
    );
    elector_chirho.tick_chirho();
    assert_eq!(
        elector_chirho.current_lease_remaining_millis_chirho(),
        Some(100),
        "a healthy tick must publish a later confirmation"
    );
    let refreshed_generation_chirho = current_handle_chirho
        .try_acquire_chirho()
        .expect("refreshed monotonic handle acquires")
        .process_generation_chirho();
    assert_eq!(
        refreshed_generation_chirho, first_generation_chirho,
        "refreshing only the confirmation timestamp must not mint a new authority generation"
    );

    clock_chirho.advance_millis_chirho(100);
    assert_eq!(elector_chirho.current_lease_remaining_millis_chirho(), None);
    assert!(matches!(
        current_handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
    ));
}

#[test]
fn a_clock_regression_refuses_wire_and_local_authority_chirho() {
    let clock_chirho = RegressingClockFixtureChirho::new_chirho(1_000);
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-regressing-clock-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("f".repeat(64)),
            group_chirho.clone(),
            clock_chirho.clone(),
            100,
            100,
        )
        .expect("build regressing-clock elector");
    elector_chirho
        .campaign_chirho()
        .expect("campaign regressing-clock elector");
    elector_chirho.tick_chirho();
    clock_chirho.set_millis_chirho(1_100);
    elector_chirho.tick_chirho();
    clock_chirho.set_millis_chirho(1_200);
    elector_chirho.tick_chirho();
    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "precondition: the fixture must be warm and current before its clock regresses"
    );
    let current_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    drop(
        current_handle_chirho
            .try_acquire_chirho()
            .expect("pre-regression local authority is live"),
    );

    clock_chirho.set_millis_chirho(1_150);
    let regressed_chirho = elector_chirho.leadership_chirho(&group_chirho);
    assert!(
        regressed_chirho.is_leader_chirho && !regressed_chirho.lease_valid_chirho,
        "a clock reading before the latest confirmation must fail closed without changing the stale role"
    );
    assert_eq!(
        elector_chirho.current_lease_remaining_millis_chirho(),
        None,
        "a future-dated confirmation must emit no wire duration"
    );
    assert!(matches!(
        current_handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
    ));
}

#[test]
fn only_a_clock_tick_may_refresh_the_lease_never_an_inbound_message_chirho() {
    // F1's hazard is a leader whose TICK DRIVER DIED, so the lease must be anchored to ticks and to
    // NOTHING ELSE. That distinction was unpinned: making `step_chirho` record a confirmation passed
    // every test in both elector crates, because the existing decay arm is single-node and never
    // steps a message -- it stops ticking AND stops stepping, so it cannot tell "only ticks refresh"
    // from "anything refreshes". A leader that is partitioned from its tick driver but still
    // receiving traffic would then hold authority forever on the strength of the traffic.
    //
    // MIGRATION PATH: if this arm ever fails, read WHICH assertion fired. A failure on the final
    // assert means some non-tick path now refreshes `leadership_confirmed_ms_chirho` -- that is the
    // F1 regression, and the fix belongs in the caller that started passing `is_clock_tick = true`,
    // not here. A failure on the mid-test `lease_valid` assert means the warm-up stopped working and
    // this arm never reached the property it exists to pin.
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-tick-only-lease-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("c".repeat(64)),
            group_chirho.clone(),
            clock_chirho.clone(),
            500,
            500,
        )
        .expect("build elector");

    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");
    for _step_chirho in 0..20 {
        clock_chirho.advance_millis_chirho(50);
        elector_chirho.tick_chirho();
    }
    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "precondition: the lease must be warm and valid before we stop ticking, or this arm proves \
         nothing about what refreshes it"
    );

    // The tick driver dies HERE. From now on the only thing happening is inbound raft traffic.
    // A heartbeat response from this node's own raft id keeps it Leader and is accepted by `step`,
    // so it reaches the confirmation recorder -- which is what makes this arm load-bearing rather
    // than a message that gets dropped at the boundary (a `MsgSnapshot`, say, returns early and
    // would let this test pass while exercising nothing).
    let mut traffic_chirho = Message::default();
    traffic_chirho.set_msg_type(MessageType::MsgHeartbeatResponse);
    traffic_chirho.from = elector_chirho.local_raft_id_chirho();
    traffic_chirho.to = elector_chirho.local_raft_id_chirho();

    for _beat_chirho in 0..10 {
        clock_chirho.advance_millis_chirho(200);
        let _ = elector_chirho.step_chirho(traffic_chirho.clone());
    }

    assert!(
        elector_chirho
            .leadership_chirho(&group_chirho)
            .is_leader_chirho,
        "raft still reports this node leader -- nothing deposed it, which is precisely the F1 \
         situation: the role bit is stale because the mechanism that would clear it stopped"
    );
    assert!(
        !elector_chirho
            .leadership_chirho(&group_chirho)
            .lease_valid_chirho,
        "the lease MUST have decayed: 2000ms of traffic with no tick is not a confirmation. If this \
         fails, an inbound message is refreshing leadership and a partitioned leader keeps authority \
         for as long as anyone keeps talking to it"
    );
}

#[test]
fn an_unwarmed_leader_advertises_no_lease_on_the_wire_chirho() {
    // The COMPANION hole to the tick-refresh one, in the value that actually crosses a process
    // boundary. `lease_remaining_millis_chirho` is gated on `lease_valid_chirho`; removing that gate
    // survived every test in both elector crates, so the gate was load-bearing and unpinned.
    //
    // Two of its three failure paths are independently fail-closed: a non-leader never passes the
    // validity gate, while an expired or future-dated confirmation produces no remaining duration.
    //
    // The WARM-UP path is not saved, and that is what this arm pins. A leader that has just been
    // confirmed by its first tick has `elapsed == 0`, so without the gate it would advertise a FULL
    // lease -- the maximum possible value -- at exactly the moment it is least entitled to one. On
    // the wire that would defeat the documented warm-up defense even though this signal does not
    // claim quorum recency or cross-host exclusion.
    //
    // MIGRATION PATH: if this fails, read which assertion fired. The `lease_valid` assert failing
    // means the warm-up changed and the arm never reached its property. The `None` assert failing
    // means an unwarmed leader is now advertising a lease, and the fix belongs at the gate in
    // `lease_remaining_millis_chirho`, not here.
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-unwarmed-wire-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("d".repeat(64)),
            group_chirho.clone(),
            clock_chirho.clone(),
            500,
            500,
        )
        .expect("build elector");

    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");

    // One tick, well short of the 500ms warm-up. This node IS the raft leader and its confirmation
    // is as fresh as a confirmation can be -- the worst case for the wire value, not the best.
    clock_chirho.advance_millis_chirho(100);
    elector_chirho.tick_chirho();

    let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
    assert!(
        leadership_chirho.is_leader_chirho,
        "precondition: raft reports leader immediately after campaigning"
    );
    assert!(
        !leadership_chirho.lease_valid_chirho,
        "precondition: 100ms of a 500ms warm-up has elapsed, so the lease is not yet valid -- if \
         this fails the arm never reaches the wire property it exists to pin"
    );

    assert_eq!(
        elector_chirho.lease_remaining_millis_chirho(&group_chirho),
        None,
        "a leader that is not yet warm must advertise NO lease. Its confirmation is fresh, so the \
         remaining-duration arithmetic alone would hand out the FULL lease here -- only the \
         lease_valid gate prevents an unwarmed leader from telling a peer it holds authority"
    );
    assert_eq!(
        elector_chirho.current_lease_remaining_millis_chirho(),
        None,
        "and the same through the public wire accessor, which is what the HTTP layer serialises"
    );
}
