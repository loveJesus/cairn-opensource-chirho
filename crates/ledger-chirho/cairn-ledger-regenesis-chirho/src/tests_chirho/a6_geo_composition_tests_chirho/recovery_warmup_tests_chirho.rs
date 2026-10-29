// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! The recovery warm-up helper, driven through each way leadership can reach the adopter: the
//! adopter wins, the other survivor wins and hands over, and a split vote resolves either way.

use super::*;

/// A fresh real three-voter cluster in which nobody leads yet. Pre-vote and check-quorum are on, so a
/// follower inside a live leader's lease would refuse a forced campaign; these arms start leaderless.
fn open_leaderless_recovery_cluster_chirho(
) -> (RegenesisFixtureChirho, ReopenedA6ClusterFleetChirho) {
    let fixture_chirho = fixture_chirho();
    run_ledger_regenesis_chirho(request_chirho(&fixture_chirho))
        .expect("the reviewed H3 fixture publishes");
    let fleet_chirho = open_reopened_a6_cluster_nodes_chirho(&fixture_chirho);
    for node_chirho in &fleet_chirho.nodes_chirho {
        assert!(
            !node_chirho
                .elector_chirho()
                .current_leadership_chirho()
                .is_leader_chirho,
            "a freshly reopened cluster has no leader yet"
        );
    }
    (fixture_chirho, fleet_chirho)
}

/// One vote-phase message the campaign drain delivered between the two survivors.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VoteTrafficChirho {
    /// raft's message kind by its variant name, so these arms need no raft dependency of their own.
    kind_chirho: String,
    from_chirho: u64,
    to_chirho: u64,
    term_chirho: u64,
    reject_chirho: bool,
}

/// Start a campaign on each listed survivor, collecting all of their traffic BEFORE delivering any,
/// then drain it among the survivors with the old leader and the held learner silent. A lone
/// campaigner wins; two campaigning in the same round split the vote. Returns every vote-phase
/// message it delivered, so an arm can show the ballots it relies on actually happened.
fn drive_survivor_campaigns_chirho(
    nodes_chirho: &[ClusterNodeChirho],
    campaigners_chirho: &[usize],
) -> Vec<VoteTrafficChirho> {
    let mut traffic_chirho = Vec::new();
    let mut messages_chirho = Vec::new();
    for index_chirho in campaigners_chirho {
        messages_chirho.extend(
            nodes_chirho[*index_chirho]
                .elector_chirho()
                .campaign_chirho()
                .expect("a leaderless survivor starts a campaign"),
        );
    }
    for _round_chirho in 0..1_000 {
        if messages_chirho.is_empty() {
            return traffic_chirho;
        }
        let mut next_chirho = Vec::new();
        for message_chirho in messages_chirho.drain(..) {
            if matches!(message_chirho.to, 1 | 4) {
                continue;
            }
            let kind_chirho = format!("{:?}", message_chirho.msg_type());
            if kind_chirho.contains("Vote") {
                traffic_chirho.push(VoteTrafficChirho {
                    kind_chirho,
                    from_chirho: message_chirho.from,
                    to_chirho: message_chirho.to,
                    term_chirho: message_chirho.term,
                    reject_chirho: message_chirho.reject,
                });
            }
            let target_chirho = nodes_chirho
                .iter()
                .find(|node_chirho| {
                    node_chirho.elector_chirho().local_raft_id_chirho() == message_chirho.to
                })
                .expect("every surviving campaign target is present");
            next_chirho.extend(
                target_chirho
                    .elector_chirho()
                    .step_chirho(message_chirho)
                    .expect("a survivor accepts campaign traffic"),
            );
        }
        messages_chirho = next_chirho;
    }
    panic!("the survivors' campaign traffic did not drain within the fixed bound");
}

/// The adopter leads with a warm, live lease and the other survivor does not lead. Returns the
/// adopter's term.
fn assert_adopter_leads_warm_chirho(nodes_chirho: &[ClusterNodeChirho]) -> u64 {
    let adopter_chirho = nodes_chirho[1].elector_chirho().current_leadership_chirho();
    assert!(
        adopter_chirho.is_leader_chirho && adopter_chirho.lease_valid_chirho,
        "the warm-up exits only on the ADOPTER's own warm lease"
    );
    assert!(
        !nodes_chirho[2]
            .elector_chirho()
            .current_leadership_chirho()
            .is_leader_chirho,
        "the other survivor no longer leads"
    );
    adopter_chirho.term_chirho
}

#[test]
fn the_adopter_winning_the_election_needs_no_transfer_chirho() {
    let (_fixture_chirho, fleet_chirho) = open_leaderless_recovery_cluster_chirho();
    drive_survivor_campaigns_chirho(&fleet_chirho.nodes_chirho, &[1]);
    assert!(
        fleet_chirho.nodes_chirho[1]
            .elector_chirho()
            .current_leadership_chirho()
            .is_leader_chirho
    );
    let report_chirho =
        drive_recovery_until_adopter_warm_without_old_leader_chirho(&fleet_chirho.nodes_chirho);
    assert_adopter_leads_warm_chirho(&fleet_chirho.nodes_chirho);
    assert!(
        report_chirho.transfers_chirho.is_empty(),
        "{report_chirho:?}"
    );
}

#[test]
fn the_other_survivor_winning_hands_over_without_waiting_for_its_own_lease_chirho() {
    let (_fixture_chirho, fleet_chirho) = open_leaderless_recovery_cluster_chirho();
    drive_survivor_campaigns_chirho(&fleet_chirho.nodes_chirho, &[2]);
    let other_chirho = fleet_chirho.nodes_chirho[2]
        .elector_chirho()
        .current_leadership_chirho();
    assert!(other_chirho.is_leader_chirho);
    let report_chirho =
        drive_recovery_until_adopter_warm_without_old_leader_chirho(&fleet_chirho.nodes_chirho);
    let adopter_term_chirho = assert_adopter_leads_warm_chirho(&fleet_chirho.nodes_chirho);
    // Waiting for the outgoing leader's lease would record this transfer as from a WARM leader.
    assert_eq!(
        report_chirho.transfers_chirho,
        vec![RecoveryWarmupTransferChirho {
            from_term_chirho: other_chirho.term_chirho,
            from_lease_valid_chirho: false,
        }],
        "exactly one transfer, started before the outgoing leader's lease warmed"
    );
    assert!(adopter_term_chirho > other_chirho.term_chirho);
}

#[test]
fn a_split_vote_is_resolved_and_the_adopter_still_ends_up_warm_chirho() {
    let (_fixture_chirho, fleet_chirho) = open_leaderless_recovery_cluster_chirho();
    // A fresh cluster already has two non-leaders at one term, so that alone proves no split
    // (gpt #29802). The arm needs the campaigns to MOVE both survivors into a new, contested term,
    // and it needs the two same-term ballots and their cross-rejections in the delivered traffic.
    let pre_terms_chirho = [1, 2].map(|index_chirho| {
        fleet_chirho.nodes_chirho[index_chirho]
            .elector_chirho()
            .current_leadership_chirho()
            .term_chirho
    });
    assert_eq!(pre_terms_chirho[0], pre_terms_chirho[1]);
    let contested_term_chirho = pre_terms_chirho[0] + 1;
    let traffic_chirho = drive_survivor_campaigns_chirho(&fleet_chirho.nodes_chirho, &[1, 2]);
    for (voter_chirho, peer_chirho) in [(2, 3), (3, 2)] {
        assert!(
            traffic_chirho.contains(&VoteTrafficChirho {
                kind_chirho: "MsgRequestVote".to_string(),
                from_chirho: voter_chirho,
                to_chirho: peer_chirho,
                term_chirho: contested_term_chirho,
                reject_chirho: false,
            }),
            "raft id {voter_chirho} asked for a vote at the contested term: {traffic_chirho:?}"
        );
        assert!(
            traffic_chirho.contains(&VoteTrafficChirho {
                kind_chirho: "MsgRequestVoteResponse".to_string(),
                from_chirho: peer_chirho,
                to_chirho: voter_chirho,
                term_chirho: contested_term_chirho,
                reject_chirho: true,
            }),
            "raft id {peer_chirho} refused that vote, having voted for itself: {traffic_chirho:?}"
        );
    }
    let adopter_chirho = fleet_chirho.nodes_chirho[1]
        .elector_chirho()
        .current_leadership_chirho();
    let other_chirho = fleet_chirho.nodes_chirho[2]
        .elector_chirho()
        .current_leadership_chirho();
    assert!(
        !adopter_chirho.is_leader_chirho && !other_chirho.is_leader_chirho,
        "two campaigns in one round split the vote"
    );
    assert_eq!(
        (adopter_chirho.term_chirho, other_chirho.term_chirho),
        (contested_term_chirho, contested_term_chirho),
        "both campaigns reached the contested term"
    );
    let split_term_chirho = contested_term_chirho;
    let report_chirho =
        drive_recovery_until_adopter_warm_without_old_leader_chirho(&fleet_chirho.nodes_chirho);
    let adopter_term_chirho = assert_adopter_leads_warm_chirho(&fleet_chirho.nodes_chirho);
    assert!(
        adopter_term_chirho > split_term_chirho,
        "a later election resolved the split: {report_chirho:?}"
    );
    assert!(
        report_chirho
            .transfers_chirho
            .iter()
            .all(|transfer_chirho| !transfer_chirho.from_lease_valid_chirho),
        "{report_chirho:?}"
    );
}
