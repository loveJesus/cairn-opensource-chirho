// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.3 slice 3 (safe convergence apply) + A1.4 slice 2b (the transfer-back re-home driver), which share
//! this crate's in-process byte-bus drive machinery. Convergence: a new target member joins as a LEARNER
//! (never straight a voter); a full group converges to the target by promoting a caught-up learner then
//! removing a dropped voter, with the authenticated peer set tracking membership; a quorum-breaking
//! remove is REFUSED not forced; a departing node stays authenticated until its removal commits; an
//! already-converged group is a no-op. Re-home: leadership transfers back to the operator's preferred
//! voter, leaves put when the preferred is down (transfer times out safely) or is a non-voter, and is a
//! no-op when already preferred or from a non-leader.

use super::*;
use crate::preferred_leader_chirho::{re_home_step_chirho, ReHomeStepChirho};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::ConsistencyGroupIdChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn group_chirho(tag_chirho: &str) -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-a1-3-apply-{tag_chirho}-chirho"),
    }
}

/// The node identity pattern the roster/tests use: raft id N -> the 64-char run of its digit.
fn node_id_chirho(raft_id_chirho: u64) -> NodeIdChirho {
    NodeIdChirho(format!("{raft_id_chirho}").repeat(64))
}

/// A target member whose pubkey matches [`node_id_chirho`] so the auth-set update stays a valid bijection.
fn member_chirho(raft_id_chirho: u64) -> ElectorMemberChirho {
    ElectorMemberChirho {
        raft_id_chirho,
        pubkey_chirho: format!("{raft_id_chirho}").repeat(64),
        url_chirho: format!("http://10.100.0.{raft_id_chirho}:8300"),
        learner_chirho: false,
    }
}

fn target_chirho(ids_chirho: &[u64]) -> Vec<ElectorMemberChirho> {
    ids_chirho
        .iter()
        .map(|id_chirho| member_chirho(*id_chirho))
        .collect()
}

fn build_cluster_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    voter_ids_chirho: &[u64],
    learner_ids_chirho: &[u64],
) -> Vec<RaftWriterElectorChirho> {
    let voters_chirho: Vec<(u64, NodeIdChirho)> = voter_ids_chirho
        .iter()
        .map(|id_chirho| (*id_chirho, node_id_chirho(*id_chirho)))
        .collect();
    let learners_chirho: Vec<(u64, NodeIdChirho)> = learner_ids_chirho
        .iter()
        .map(|id_chirho| (*id_chirho, node_id_chirho(*id_chirho)))
        .collect();
    voter_ids_chirho
        .iter()
        .chain(learner_ids_chirho.iter())
        .map(|id_chirho| {
            RaftWriterElectorChirho::new_cluster_node_with_learners_chirho(
                group_chirho.clone(),
                *id_chirho,
                voters_chirho.clone(),
                learners_chirho.clone(),
            )
            .expect("build cluster node")
        })
        .collect()
}

/// Route a byte bus among the nodes until it drains (bare wire — the cluster is unsigned), dropping any
/// message addressed to a `silence_chirho` id (to model unreachable peers). A `step` that fails because a
/// peer was removed mid-convergence is tolerated (the message is dropped) rather than panicking.
fn drain_bus_silenced_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    mut bus_chirho: Vec<(u64, Vec<u8>)>,
    silence_chirho: &[u64],
) {
    for _round_chirho in 0..2000 {
        bus_chirho.retain(|(to_chirho, _)| !silence_chirho.contains(to_chirho));
        if bus_chirho.is_empty() {
            break;
        }
        let mut next_chirho: Vec<(u64, Vec<u8>)> = Vec::new();
        for (to_chirho, bytes_chirho) in bus_chirho.drain(..) {
            if let Some(node_chirho) = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == to_chirho)
            {
                if let Ok(out_chirho) = node_chirho.step_encoded_chirho(&bytes_chirho) {
                    next_chirho.extend(out_chirho);
                }
            }
        }
        bus_chirho = next_chirho;
    }
}

fn drain_bus_chirho(nodes_chirho: &[RaftWriterElectorChirho], bus_chirho: Vec<(u64, Vec<u8>)>) {
    drain_bus_silenced_chirho(nodes_chirho, bus_chirho, &[]);
}

/// Tick the leader `count` times, routing its output each tick while silencing `silence_chirho`.
fn tick_leader_silenced_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    leader_chirho: &RaftWriterElectorChirho,
    count_chirho: usize,
    silence_chirho: &[u64],
) {
    for _ in 0..count_chirho {
        drain_bus_silenced_chirho(
            nodes_chirho,
            leader_chirho.tick_encoded_chirho().expect("tick"),
            silence_chirho,
        );
    }
}

/// One drive pass: tick the leader a few times, routing its output each tick so proposals commit and
/// learners replicate.
fn drive_once_chirho(
    nodes_chirho: &[RaftWriterElectorChirho],
    leader_chirho: &RaftWriterElectorChirho,
) {
    tick_leader_silenced_chirho(nodes_chirho, leader_chirho, 6, &[]);
}

/// Elect `nodes[0]` and settle the cluster so any learner has replicated.
fn elect_leader_chirho(nodes_chirho: &[RaftWriterElectorChirho]) {
    drain_bus_chirho(
        nodes_chirho,
        nodes_chirho[0].campaign_encoded_chirho().expect("campaign"),
    );
    drive_once_chirho(nodes_chirho, &nodes_chirho[0]);
    assert!(
        nodes_chirho[0].current_leadership_chirho().is_leader_chirho,
        "nodes[0] should be the leader"
    );
}

#[test]
fn apply_adds_a_new_target_member_as_a_learner_chirho() {
    // A brand-new target member (2) joins as a non-voting LEARNER, and is authenticated as it joins —
    // never straight a voter. (Single-node leader: enough to prove the new_voter -> add_learner path +
    // the auth-set include, without a second node to catch up.)
    let group_chirho = group_chirho("add-learner");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1], &[]);
    elect_leader_chirho(&nodes_chirho);

    let step_chirho =
        apply_one_convergence_step_chirho(&nodes_chirho[0], &target_chirho(&[1, 2])).unwrap();
    assert_eq!(
        step_chirho,
        ConvergenceStepChirho::AddedLearnerChirho { raft_id_chirho: 2 }
    );
    for _ in 0..5 {
        let _ = nodes_chirho[0].tick_encoded_chirho();
    }
    let (voters_chirho, learners_chirho) = nodes_chirho[0].membership_snapshot_chirho().unwrap();
    assert_eq!(
        voters_chirho,
        vec![1],
        "the new member did NOT join as a voter"
    );
    assert_eq!(
        learners_chirho,
        vec![2],
        "it joined as a non-voting learner"
    );
    assert!(
        nodes_chirho[0]
            .authenticated_member_ids_chirho()
            .contains(&2),
        "the joining peer was authenticated as it joined"
    );
}

#[test]
fn converges_by_promoting_a_learner_and_removing_a_dropped_voter_chirho() {
    // The full loop: voters {1,2,3} + learner {4}, target {1,2,4}. Convergence promotes the caught-up
    // learner 4 to a voter, then removes 3 — adds-before-removes, one change at a time, so quorum never
    // dips — landing on voters {1,2,4} with the authenticated peer set tracking membership.
    let group_chirho = group_chirho("converge");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[4]);
    elect_leader_chirho(&nodes_chirho);

    let outcome_chirho = converge_chirho(
        &nodes_chirho[0],
        &target_chirho(&[1, 2, 4]),
        || drive_once_chirho(&nodes_chirho, &nodes_chirho[0]),
        40,
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        ConvergenceStepChirho::ConvergedChirho,
        "convergence reached the target"
    );

    let (voters_chirho, learners_chirho) = nodes_chirho[0].membership_snapshot_chirho().unwrap();
    assert_eq!(
        voters_chirho,
        vec![1, 2, 4],
        "voters converged to the target"
    );
    assert!(learners_chirho.is_empty(), "no learners remain");
    assert_eq!(
        nodes_chirho[0].authenticated_member_ids_chirho(),
        vec![1, 2, 4],
        "the authenticated peer set tracks the membership (3 was dropped)"
    );
}

#[test]
fn a_removed_node_stays_authenticated_until_its_removal_commits_chirho() {
    // MEDIUM (claude2): the departing node must stay authenticated until its removal APPLIES (post-commit)
    // — its ack can be part of the OLD-config majority that commits its own removal, so excluding it on
    // propose could starve that majority and STALL. So the auth-exclude fires on the RECONCILE-DOWN one
    // iteration AFTER the node has left ConfState, never on propose.
    let group_chirho = group_chirho("remove-timing");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[]);
    elect_leader_chirho(&nodes_chirho);

    // Propose removing 3 (target {1,2}); no drive yet, so the removal has NOT committed.
    let step_chirho =
        apply_one_convergence_step_chirho(&nodes_chirho[0], &target_chirho(&[1, 2])).unwrap();
    assert_eq!(
        step_chirho,
        ConvergenceStepChirho::RemovedChirho { raft_id_chirho: 3 }
    );
    assert!(
        nodes_chirho[0]
            .authenticated_member_ids_chirho()
            .contains(&3),
        "the departing node stays authenticated until its removal commits (its ack may be needed)"
    );

    // Drive to commit the removal (3 leaves ConfState), then the next step's reconcile-down drops it.
    drive_once_chirho(&nodes_chirho, &nodes_chirho[0]);
    let step2_chirho =
        apply_one_convergence_step_chirho(&nodes_chirho[0], &target_chirho(&[1, 2])).unwrap();
    assert_eq!(step2_chirho, ConvergenceStepChirho::ConvergedChirho);
    assert!(
        !nodes_chirho[0]
            .authenticated_member_ids_chirho()
            .contains(&3),
        "once the removal committed and 3 left ConfState, reconcile-down dropped it from auth"
    );
}

#[test]
fn quorum_never_breaks_a_remove_is_refused_not_forced_chirho() {
    // Three voters {1,2,3}, but 2 and 3 are unreachable, so only the leader is live. Converging toward a
    // target that would remove a voter must REFUSE the remove (it would strand the group below a live
    // majority) rather than force it — surfaced, never wedged, membership unchanged.
    let group_chirho = group_chirho("quorum");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[]);
    // Elect 1 while 2 and 3 answer, then silence them for a full election timeout so check_quorum marks
    // them not-recent-active — a remove then has no live post-remove majority to commit it.
    drain_bus_chirho(
        &nodes_chirho,
        nodes_chirho[0].campaign_encoded_chirho().expect("campaign"),
    );
    assert!(nodes_chirho[0].current_leadership_chirho().is_leader_chirho);
    tick_leader_silenced_chirho(&nodes_chirho, &nodes_chirho[0], 14, &[2, 3]);

    // Target drops voter 3; with 2 and 3 unreachable, the remove precheck refuses (no live post-remove
    // majority) rather than forcing it.
    let step_chirho =
        apply_one_convergence_step_chirho(&nodes_chirho[0], &target_chirho(&[1, 2])).unwrap();
    assert!(
        matches!(
            step_chirho,
            ConvergenceStepChirho::RemoveRefusedWouldBreakQuorumChirho { raft_id_chirho: 3 }
                | ConvergenceStepChirho::BlockedOnLeaderTransferChirho { .. }
        ),
        "an unsafe remove is refused/deferred, not forced: {step_chirho:?}"
    );
    let (voters_chirho, _learners_chirho) = nodes_chirho[0].membership_snapshot_chirho().unwrap();
    assert!(
        voters_chirho.contains(&3),
        "the refused remove left membership unchanged"
    );
}

#[test]
fn an_already_converged_group_is_a_no_op_chirho() {
    // IDEMPOTENT: applying convergence to a group that already matches the target changes nothing.
    let group_chirho = group_chirho("noop");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1], &[]);
    elect_leader_chirho(&nodes_chirho);
    let step_chirho =
        apply_one_convergence_step_chirho(&nodes_chirho[0], &target_chirho(&[1])).unwrap();
    assert_eq!(step_chirho, ConvergenceStepChirho::ConvergedChirho);
    let (voters_chirho, learners_chirho) = nodes_chirho[0].membership_snapshot_chirho().unwrap();
    assert_eq!(voters_chirho, vec![1]);
    assert!(learners_chirho.is_empty());
}

// ---- signed-cluster regression: the auth set actually gates messages here -------------------------

fn signed_temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-a1-3-signed-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

/// A SIGNED cluster: each node has a real signing root, the roster maps each raft id to its real pubkey,
/// and message authentication is on — so the authenticated peer set actually gates inbound messages.
/// Returns the nodes, the (raft_id, node_id) roster, and the roots (for cleanup).
#[allow(clippy::type_complexity)]
fn build_signed_cluster_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    ids_chirho: &[u64],
) -> (
    Vec<RaftWriterElectorChirho>,
    Vec<(u64, NodeIdChirho)>,
    Vec<PathBuf>,
) {
    let provisioned_chirho: Vec<(u64, PathBuf, NodeIdChirho)> = ids_chirho
        .iter()
        .map(|id_chirho| {
            let root_chirho = signed_temp_root_chirho(&format!("n{id_chirho}"));
            sign_message_chirho(&root_chirho, b"provision node key").unwrap();
            let node_chirho = NodeIdChirho(pubkey_hex_chirho(&root_chirho).unwrap());
            (*id_chirho, root_chirho, node_chirho)
        })
        .collect();
    let roster_chirho: Vec<(u64, NodeIdChirho)> = provisioned_chirho
        .iter()
        .map(|(id_chirho, _, node_chirho)| (*id_chirho, node_chirho.clone()))
        .collect();
    let nodes_chirho = provisioned_chirho
        .iter()
        .map(|(id_chirho, root_chirho, _)| {
            RaftWriterElectorChirho::new_cluster_node_chirho(
                group_chirho.clone(),
                *id_chirho,
                roster_chirho.clone(),
            )
            .expect("build signed node")
            .with_message_authentication_chirho(root_chirho.clone())
        })
        .collect();
    let roots_chirho = provisioned_chirho
        .into_iter()
        .map(|(_, root_chirho, _)| root_chirho)
        .collect();
    (nodes_chirho, roster_chirho, roots_chirho)
}

/// A target over the SIGNED roster's real pubkeys (so the auth-set update stays a valid bijection).
fn signed_target_chirho(
    roster_chirho: &[(u64, NodeIdChirho)],
    ids_chirho: &[u64],
) -> Vec<ElectorMemberChirho> {
    ids_chirho
        .iter()
        .map(|id_chirho| {
            let node_chirho = roster_chirho
                .iter()
                .find(|(rid_chirho, _)| rid_chirho == id_chirho)
                .map(|(_, node_chirho)| node_chirho.0.clone())
                .expect("id in roster");
            ElectorMemberChirho {
                raft_id_chirho: *id_chirho,
                pubkey_chirho: node_chirho,
                url_chirho: format!("http://10.100.0.{id_chirho}:8300"),
                learner_chirho: false,
            }
        })
        .collect()
}

#[test]
fn a_remove_needing_the_departing_nodes_ack_still_completes_chirho() {
    // MEDIUM end-to-end (claude2): committing the removal of node 4 needs a majority of the OLD config
    // {1,2,3,4} = 3. With node 3 down, that majority is {1,2,4} — INCLUDING the departing node 4. On a
    // SIGNED cluster (the auth set actually gates messages), auth-excluding 4 on propose would make the
    // leader reject 4's ack -> the removal can never reach 3 acks -> STALL. With the fix (4 stays
    // authenticated until its removal commits), the removal completes.
    let group_chirho = group_chirho("remove-needs-ack");
    let (nodes_chirho, roster_chirho, roots_chirho) =
        build_signed_cluster_chirho(&group_chirho, &[1, 2, 3, 4]);
    // Elect 1 with node 3 down ({1,2,4} = 3 votes suffice), and keep 3 down throughout.
    drain_bus_silenced_chirho(
        &nodes_chirho,
        nodes_chirho[0].campaign_encoded_chirho().expect("campaign"),
        &[3],
    );
    tick_leader_silenced_chirho(&nodes_chirho, &nodes_chirho[0], 6, &[3]);
    assert!(
        nodes_chirho[0].current_leadership_chirho().is_leader_chirho,
        "1 elected with node 3 down"
    );

    // Converge to {1,2,3}: remove 4, keep the (down) voter 3. Node 3 stays silenced.
    let outcome_chirho = converge_chirho(
        &nodes_chirho[0],
        &signed_target_chirho(&roster_chirho, &[1, 2, 3]),
        || tick_leader_silenced_chirho(&nodes_chirho, &nodes_chirho[0], 6, &[3]),
        40,
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        ConvergenceStepChirho::ConvergedChirho,
        "the removal completed despite node 3 being down (node 4's ack was still available)"
    );
    let (voters_chirho, _learners_chirho) = nodes_chirho[0].membership_snapshot_chirho().unwrap();
    assert_eq!(
        voters_chirho,
        vec![1, 2, 3],
        "4 removed; 3 (down) remains a voter"
    );

    for root_chirho in roots_chirho {
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

// ---- A1.4 slice 2b: the transfer-back (re-home) driver --------------------------------------------

#[test]
fn re_home_transfers_leadership_back_to_the_preferred_voter_chirho() {
    // The move-back: node 1 leads but node 2 is the operator's preferred leader. re_home initiates a
    // transfer; delivering it re-homes leadership to node 2.
    let group_chirho = group_chirho("rehome-back");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[]);
    elect_leader_chirho(&nodes_chirho);

    let (outcome_chirho, messages_chirho) = re_home_step_chirho(&nodes_chirho[0], Some(2)).unwrap();
    assert!(matches!(
        outcome_chirho,
        ReHomeStepChirho::TransferringChirho {
            to_raft_id_chirho: 2
        }
    ));
    drain_bus_chirho(&nodes_chirho, messages_chirho); // deliver the TimeoutNow -> node 2 campaigns + wins
    drive_once_chirho(&nodes_chirho, &nodes_chirho[1]); // settle the new leader

    assert!(
        nodes_chirho[1].current_leadership_chirho().is_leader_chirho,
        "leadership re-homed to the preferred voter 2"
    );
    assert!(
        !nodes_chirho[0].current_leadership_chirho().is_leader_chirho,
        "the old leader (node 1) stepped down"
    );
}

#[test]
fn re_home_leaves_leadership_put_when_the_preferred_is_down_chirho() {
    // The preferred (node 3) is down: the transfer times out safely and node 1 stays leader (no
    // availability loss) — the group would re-home once 3 heals.
    let group_chirho = group_chirho("rehome-down");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[]);
    elect_leader_chirho(&nodes_chirho);

    let (outcome_chirho, messages_chirho) = re_home_step_chirho(&nodes_chirho[0], Some(3)).unwrap();
    assert!(matches!(
        outcome_chirho,
        ReHomeStepChirho::TransferringChirho {
            to_raft_id_chirho: 3
        }
    ));
    // Deliver the transfer with node 3 SILENCED (down), then run past the election timeout.
    drain_bus_silenced_chirho(&nodes_chirho, messages_chirho, &[3]);
    tick_leader_silenced_chirho(&nodes_chirho, &nodes_chirho[0], 14, &[3]);
    assert!(
        nodes_chirho[0].current_leadership_chirho().is_leader_chirho,
        "with the preferred down, the transfer times out and node 1 stays leader"
    );
}

#[test]
fn re_home_is_a_no_op_when_already_the_preferred_leader_chirho() {
    let group_chirho = group_chirho("rehome-already");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[]);
    elect_leader_chirho(&nodes_chirho); // node 1 leads
    let (outcome_chirho, messages_chirho) = re_home_step_chirho(&nodes_chirho[0], Some(1)).unwrap();
    assert_eq!(outcome_chirho, ReHomeStepChirho::AlreadyPreferredChirho);
    assert!(messages_chirho.is_empty());
    assert!(nodes_chirho[0].current_leadership_chirho().is_leader_chirho);
}

#[test]
fn re_home_leaves_put_with_no_preference_chirho() {
    let group_chirho = group_chirho("rehome-none");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[]);
    elect_leader_chirho(&nodes_chirho);
    let (outcome_chirho, messages_chirho) = re_home_step_chirho(&nodes_chirho[0], None).unwrap();
    assert_eq!(outcome_chirho, ReHomeStepChirho::NoPreferenceChirho);
    assert!(messages_chirho.is_empty());
    assert!(nodes_chirho[0].current_leadership_chirho().is_leader_chirho);
}

#[test]
fn re_home_does_not_transfer_to_a_non_voter_chirho() {
    // The preferred (node 3) is a learner, not a voter -> it cannot lead; leave leadership put.
    let group_chirho = group_chirho("rehome-nonvoter");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2], &[3]);
    elect_leader_chirho(&nodes_chirho);
    let (outcome_chirho, messages_chirho) = re_home_step_chirho(&nodes_chirho[0], Some(3)).unwrap();
    assert_eq!(
        outcome_chirho,
        ReHomeStepChirho::PreferredNotVoterChirho { raft_id_chirho: 3 }
    );
    assert!(messages_chirho.is_empty());
    assert!(nodes_chirho[0].current_leadership_chirho().is_leader_chirho);
}

#[test]
fn re_home_does_nothing_from_a_non_leader_chirho() {
    // Only the current leader can hand off leadership; a follower re-home step is a no-op.
    let group_chirho = group_chirho("rehome-follower");
    let nodes_chirho = build_cluster_chirho(&group_chirho, &[1, 2, 3], &[]);
    elect_leader_chirho(&nodes_chirho); // node 1 leads; nodes[1] is a follower
    let (outcome_chirho, messages_chirho) = re_home_step_chirho(&nodes_chirho[1], Some(1)).unwrap();
    assert_eq!(outcome_chirho, ReHomeStepChirho::NotLeaderChirho);
    assert!(messages_chirho.is_empty());
}
