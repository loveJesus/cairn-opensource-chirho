// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.2 safe membership primitives: a cold node joins as a non-voting learner; a learner is promoted to
//! a voter ONLY once it has caught up (recent-active + `matched` within `CATCHUP_SLACK_CHIRHO` of the
//! leader's last index), otherwise the promotion is deferred and never wedged; a removal that would drop
//! the group below a live majority is refused; and removing the CURRENT leader is refused in favour of
//! transferring leadership away first (R4). In-process routing proves the multi-node legs
//! deterministically. Election-only throughout — nothing mints.

use crate::durable_store_chirho::DurableRaftStoreChirho;
use crate::elector_port_chirho::NodeIdChirho;
use crate::raft_elector_chirho::{
    AddLearnerOutcomeChirho, PromoteOutcomeChirho, RaftWriterElectorChirho, RemoveOutcomeChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::Message;
use raft::storage::Storage;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// A unique, non-existent temp directory for one durable-node test (pid + counter, no wall clock).
fn temp_dir_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-a1-2-durable-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

/// A tick budget comfortably past the elector's election timeout (10), so `check_quorum` has reset a
/// silent peer's `recent_active`.
const PAST_ELECTION_TIMEOUT_CHIRHO: usize = 14;

fn group_chirho(label_chirho: &str) -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-a1-2-{label_chirho}-chirho"),
    }
}

/// A one-voter leader (raft id 1) plus one seeded non-voting learner (raft id 2), both carrying the same
/// membership so the leader tracks the learner's progress.
fn leader_and_learner_chirho(
    label_chirho: &str,
) -> (ConsistencyGroupIdChirho, Vec<RaftWriterElectorChirho>) {
    let group_chirho = group_chirho(label_chirho);
    let voters_chirho = vec![(1u64, NodeIdChirho("1".repeat(64)))];
    let learners_chirho = vec![(2u64, NodeIdChirho("2".repeat(64)))];
    let nodes_chirho = [1u64, 2u64]
        .into_iter()
        .map(|raft_id_chirho| {
            RaftWriterElectorChirho::new_cluster_node_with_learners_chirho(
                group_chirho.clone(),
                raft_id_chirho,
                voters_chirho.clone(),
                learners_chirho.clone(),
            )
            .expect("build leader/learner node")
        })
        .collect();
    (group_chirho, nodes_chirho)
}

/// Three voters (raft ids 1..=3) — the shape for the remove-quorum prechecks.
fn three_voters_chirho(
    label_chirho: &str,
) -> (ConsistencyGroupIdChirho, Vec<RaftWriterElectorChirho>) {
    let group_chirho = group_chirho(label_chirho);
    let voters_chirho: Vec<(u64, NodeIdChirho)> = (1..=3)
        .map(|raft_id_chirho| {
            (
                raft_id_chirho,
                NodeIdChirho(format!("{raft_id_chirho}").repeat(64)),
            )
        })
        .collect();
    let nodes_chirho = (1..=3)
        .map(|raft_id_chirho| {
            RaftWriterElectorChirho::new_cluster_node_chirho(
                group_chirho.clone(),
                raft_id_chirho,
                voters_chirho.clone(),
            )
            .expect("build three-voter node")
        })
        .collect();
    (group_chirho, nodes_chirho)
}

/// Route a message bus among the nodes until it drains, dropping every message addressed to any id in
/// `silence_chirho` (to model peers that are unreachable and so never replicate or answer).
fn drain_bus_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    mut bus_chirho: Vec<Message>,
    silence_chirho: &[u64],
) {
    for _round_chirho in 0..1000 {
        bus_chirho.retain(|message_chirho| !silence_chirho.contains(&message_chirho.to));
        if bus_chirho.is_empty() {
            break;
        }
        let mut next_chirho: Vec<Message> = Vec::new();
        for message_chirho in bus_chirho.drain(..) {
            if let Some(target_chirho) = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == message_chirho.to)
            {
                next_chirho.extend(target_chirho.step_chirho(message_chirho).expect("step"));
            }
        }
        bus_chirho = next_chirho;
    }
}

/// Tick the leader `count` times, routing its output each tick while silencing `silence_chirho`.
fn tick_leader_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    leader_chirho: &RaftWriterElectorChirho,
    count_chirho: usize,
    silence_chirho: &[u64],
) {
    for _ in 0..count_chirho {
        drain_bus_chirho(nodes_chirho, leader_chirho.tick_chirho(), silence_chirho);
    }
}

#[test]
fn cold_add_joins_as_learner_chirho() {
    // A cold node is admitted as a NON-VOTING learner, never straight as a voter — so it cannot count
    // toward quorum or split the vote before it has caught up.
    let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        NodeIdChirho("a".repeat(64)),
        group_chirho("cold-add"),
    )
    .unwrap();
    elector_chirho.campaign_chirho().expect("self-elect");
    assert!(
        matches!(
            elector_chirho.add_learner_chirho(2).expect("add learner 2"),
            AddLearnerOutcomeChirho::ProposedChirho(_)
        ),
        "adding a brand-new id proposes a learner add"
    );
    for _ in 0..5 {
        let _ = elector_chirho.tick_chirho();
    }
    let (voters_chirho, learners_chirho) = elector_chirho.membership_snapshot_chirho().unwrap();
    assert_eq!(
        voters_chirho,
        vec![1],
        "the cold node did NOT join as a voter"
    );
    assert_eq!(
        learners_chirho,
        vec![2],
        "it joined as a non-voting learner"
    );
}

#[test]
fn promote_only_after_catchup_chirho() {
    // The seeded learner (2) is promoted to a voter ONLY after it has replicated the leader's log.
    let (_group_chirho, nodes_chirho) = leader_and_learner_chirho("promote");
    let leader_chirho = &nodes_chirho[0];
    drain_bus_chirho(
        &nodes_chirho,
        leader_chirho.campaign_chirho().expect("campaign"),
        &[],
    );
    assert!(leader_chirho.current_leadership_chirho().is_leader_chirho);
    assert!(
        leader_chirho.learner_caught_up_chirho(2),
        "the learner replicated the log and is caught up"
    );

    match leader_chirho
        .promote_learner_if_caught_up_chirho(2)
        .expect("promote")
    {
        PromoteOutcomeChirho::ProposedChirho(_messages_chirho) => {
            // Drive the proposed promotion to commit + apply.
            tick_leader_chirho(&nodes_chirho, leader_chirho, 5, &[]);
        }
        other_chirho => panic!("a caught-up learner must be promotable, got {other_chirho:?}"),
    }

    let (voters_chirho, _learners_chirho) = leader_chirho.membership_snapshot_chirho().unwrap();
    assert!(
        voters_chirho.contains(&2),
        "the caught-up learner was promoted to a voter (voters {voters_chirho:?})"
    );
}

#[test]
fn learner_never_catches_up_surfaces_not_wedged_chirho() {
    // A learner that never becomes reachable is never promoted (surfaced as NotCaughtUp), and the group
    // is NOT wedged — the sole voter keeps leading.
    let (_group_chirho, nodes_chirho) = leader_and_learner_chirho("never-catchup");
    let leader_chirho = &nodes_chirho[0];
    // Campaign and run, but the learner (2) is silenced throughout — it never replicates or answers.
    drain_bus_chirho(
        &nodes_chirho,
        leader_chirho.campaign_chirho().expect("campaign"),
        &[2],
    );
    tick_leader_chirho(
        &nodes_chirho,
        leader_chirho,
        PAST_ELECTION_TIMEOUT_CHIRHO,
        &[2],
    );
    assert!(
        leader_chirho.current_leadership_chirho().is_leader_chirho,
        "the group is not wedged — the sole voter still leads"
    );
    assert!(
        !leader_chirho.learner_caught_up_chirho(2),
        "a silent learner is not caught up"
    );
    match leader_chirho
        .promote_learner_if_caught_up_chirho(2)
        .expect("promote")
    {
        PromoteOutcomeChirho::NotCaughtUpChirho { .. } => {}
        other_chirho => panic!("a silent learner must NOT be promoted, got {other_chirho:?}"),
    }
    let (voters_chirho, learners_chirho) = leader_chirho.membership_snapshot_chirho().unwrap();
    assert_eq!(voters_chirho, vec![1], "no promotion happened");
    assert_eq!(learners_chirho, vec![2], "2 stays a harmless learner");
}

#[test]
fn reject_remove_that_breaks_quorum_chirho() {
    // Three voters; node 1 wins the election, then 2 and 3 go silent. Removing a voter would leave a
    // group with no live majority — the removal (which itself needs a quorum to commit) is refused.
    let (_group_chirho, nodes_chirho) = three_voters_chirho("break-quorum");
    let leader_chirho = &nodes_chirho[0];
    drain_bus_chirho(
        &nodes_chirho,
        leader_chirho.campaign_chirho().expect("campaign"),
        &[],
    );
    assert!(leader_chirho.current_leadership_chirho().is_leader_chirho);
    // Silence 2 and 3 for a full window so check_quorum marks them not-recent-active.
    tick_leader_chirho(
        &nodes_chirho,
        leader_chirho,
        PAST_ELECTION_TIMEOUT_CHIRHO,
        &[2, 3],
    );
    match leader_chirho
        .remove_node_chirho(3)
        .expect("remove precheck")
    {
        RemoveOutcomeChirho::WouldBreakQuorumChirho { .. } => {}
        other_chirho => {
            panic!("removing a voter with no live majority must be refused, got {other_chirho:?}")
        }
    }
}

#[test]
fn remove_of_current_leader_transfers_first_chirho() {
    // The driver must never propose removing the CURRENT leader outright — that would leave the group's
    // leader outside its own config. The precheck returns MustTransferLeadershipFirst.
    let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        NodeIdChirho("d".repeat(64)),
        group_chirho("remove-leader"),
    )
    .unwrap();
    elector_chirho.campaign_chirho().expect("self-elect");
    let local_chirho = elector_chirho.local_raft_id_chirho();
    match elector_chirho
        .remove_node_chirho(local_chirho)
        .expect("precheck")
    {
        RemoveOutcomeChirho::MustTransferLeadershipFirstChirho {
            leader_raft_id_chirho,
        } => assert_eq!(leader_raft_id_chirho, local_chirho),
        other_chirho => {
            panic!("removing the current leader must transfer first, got {other_chirho:?}")
        }
    }
}

#[test]
fn follower_applies_and_persists_committed_conf_change_chirho() {
    // T4 — the leg where A1.1f's crash window bit: a FOLLOWER (not the proposer) receives a committed
    // conf change and must APPLY it and DURABLY persist it. Two durable voters; node 1 leads and proposes
    // add-learner 3; the follower (node 2) receives the commit, applies it, and persists the new
    // membership — recoverable across a reopen of the follower's own store.
    let group_chirho = group_chirho("follower-apply");
    let dir1_chirho = temp_dir_chirho("f1");
    let dir2_chirho = temp_dir_chirho("f2");
    let voters_chirho = vec![
        (1u64, NodeIdChirho("1".repeat(64))),
        (2u64, NodeIdChirho("2".repeat(64))),
    ];
    let nodes_chirho = vec![
        RaftWriterElectorChirho::new_durable_cluster_node_chirho(
            dir1_chirho.clone(),
            group_chirho.clone(),
            1,
            voters_chirho.clone(),
        )
        .unwrap(),
        RaftWriterElectorChirho::new_durable_cluster_node_chirho(
            dir2_chirho.clone(),
            group_chirho.clone(),
            2,
            voters_chirho.clone(),
        )
        .unwrap(),
    ];

    drain_bus_chirho(
        &nodes_chirho,
        nodes_chirho[0].campaign_chirho().expect("campaign"),
        &[],
    );
    assert!(
        nodes_chirho[0].current_leadership_chirho().is_leader_chirho,
        "node 1 leads the two-voter group"
    );

    // The leader proposes add-learner 3 (a new id); committing it needs BOTH voters, so the follower
    // participates.
    assert!(
        matches!(
            nodes_chirho[0]
                .add_learner_chirho(3)
                .expect("propose add-learner 3"),
            AddLearnerOutcomeChirho::ProposedChirho(_)
        ),
        "adding a brand-new id proposes a learner add"
    );
    tick_leader_chirho(&nodes_chirho, &nodes_chirho[0], 12, &[]);

    // The FOLLOWER applied the committed conf change to its own live membership.
    let (_v_chirho, follower_learners_chirho) =
        nodes_chirho[1].membership_snapshot_chirho().unwrap();
    assert_eq!(
        follower_learners_chirho,
        vec![3],
        "the follower applied the committed conf change"
    );

    // ...and PERSISTED it: reopening only the follower's store recovers learner 3.
    drop(nodes_chirho);
    let follower_store_chirho =
        DurableRaftStoreChirho::open_chirho(dir2_chirho.clone(), vec![1, 2]).unwrap();
    assert_eq!(
        follower_store_chirho
            .initial_state()
            .unwrap()
            .conf_state
            .learners,
        vec![3],
        "the follower durably persisted the committed conf change"
    );

    let _ = std::fs::remove_dir_all(&dir1_chirho);
    let _ = std::fs::remove_dir_all(&dir2_chirho);
}

#[test]
fn add_learner_refuses_to_demote_a_voter_chirho() {
    // A1.2f — in raft-rs, an AddLearnerNode on a CURRENT VOTER is not an add but a DEMOTION (voter ->
    // learner), silently shrinking the voting quorum (the exact hazard remove_node_chirho guards).
    // add_learner_chirho must REFUSE it (AlreadyVoter) and leave membership unchanged, so a mistranslated
    // roster row (a re-listed voter id) can never become a quorum shrink.
    let (_group_chirho, nodes_chirho) = three_voters_chirho("no-demote");
    let leader_chirho = &nodes_chirho[0];
    drain_bus_chirho(
        &nodes_chirho,
        leader_chirho.campaign_chirho().expect("campaign"),
        &[],
    );
    assert!(leader_chirho.current_leadership_chirho().is_leader_chirho);
    let (voters_before_chirho, _learners_before_chirho) =
        leader_chirho.membership_snapshot_chirho().unwrap();
    assert_eq!(voters_before_chirho, vec![1, 2, 3]);

    match leader_chirho
        .add_learner_chirho(2)
        .expect("add_learner precheck")
    {
        AddLearnerOutcomeChirho::AlreadyVoterChirho { raft_id_chirho } => {
            assert_eq!(raft_id_chirho, 2)
        }
        other_chirho => {
            panic!("adding a current voter as a learner must be refused, got {other_chirho:?}")
        }
    }

    // No change was proposed; letting the group settle leaves the membership exactly as it was.
    tick_leader_chirho(&nodes_chirho, leader_chirho, 5, &[]);
    let (voters_after_chirho, learners_after_chirho) =
        leader_chirho.membership_snapshot_chirho().unwrap();
    assert_eq!(
        voters_after_chirho,
        vec![1, 2, 3],
        "the live voter was NOT demoted"
    );
    assert!(
        learners_after_chirho.is_empty(),
        "no learner was created from a voter"
    );
}

#[test]
fn coherent_election_observation_binds_leadership_membership_and_identities_chirho() {
    let (_group_chirho, nodes_chirho) = three_voters_chirho("coherent-observation");
    drain_bus_chirho(
        &nodes_chirho,
        nodes_chirho[0].campaign_chirho().expect("campaign"),
        &[],
    );

    let observation_chirho = nodes_chirho[0]
        .current_election_observation_chirho()
        .expect("one coherent election observation");
    assert_eq!(
        observation_chirho
            .leadership_chirho()
            .leader_id_chirho
            .as_ref()
            .map(|node_chirho| node_chirho.0.as_str()),
        Some("1111111111111111111111111111111111111111111111111111111111111111")
    );
    assert_eq!(observation_chirho.voter_raft_ids_chirho(), &[1, 2, 3]);
    assert!(observation_chirho.learner_raft_ids_chirho().is_empty());
    assert_eq!(observation_chirho.authenticated_members_chirho().len(), 3);
    assert_eq!(observation_chirho.applied_conf_index_chirho(), 0);
}
