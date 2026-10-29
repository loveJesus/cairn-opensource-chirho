// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Election checks for the held GD7 actor.
//!
//! The immutable reconciliation identity always retains its historical winner term. Read-only
//! startup, bootstrap/monitor, and inspection may observe that same winner at a later term so the
//! caller can reach an exact retained handoff barrier. State-producing commands remain bound to
//! the historical term until an actor-owned retained-barrier proof is explicitly threaded into
//! them; this module does not provide that authority.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::ResidentGd7HeldCoordinatorRefusalChirho;
use crate::reconciliation_chirho::Gd7ReconciliationIdentityChirho;
use cairn_ledger_log_chirho::losing_suffix_chirho::VerifiedLosingJournalTailChirho;
use cairn_writer_elector_chirho::elector_port_chirho::{
    LeadershipChirho, NodeIdChirho, WriterElectorChirho,
};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    split_writer_epoch_chirho, ConsistencyGroupIdChirho,
};

pub(super) type HeldIdentityElectionVerifierChirho =
    fn(
        &RaftWriterElectorChirho,
        &ConsistencyGroupIdChirho,
        &Gd7ReconciliationIdentityChirho,
        &NodeIdChirho,
    ) -> std::result::Result<LeadershipChirho, ResidentGd7HeldCoordinatorRefusalChirho>;

pub(super) fn verify_held_read_only_election_observation_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    local_node_chirho: &NodeIdChirho,
) -> std::result::Result<LeadershipChirho, ResidentGd7HeldCoordinatorRefusalChirho> {
    require_elector_node_chirho(elector_chirho.node_id_chirho(), local_node_chirho)?;
    let leadership_chirho = elector_chirho.leadership_chirho(group_chirho);
    validate_read_only_election_observation_chirho(&leadership_chirho, identity_chirho)?;
    Ok(leadership_chirho)
}

pub(super) fn verify_held_historical_mutation_election_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    local_node_chirho: &NodeIdChirho,
) -> std::result::Result<LeadershipChirho, ResidentGd7HeldCoordinatorRefusalChirho> {
    let leadership_chirho = verify_held_read_only_election_observation_chirho(
        elector_chirho,
        group_chirho,
        identity_chirho,
        local_node_chirho,
    )?;
    if leadership_chirho.term_chirho > identity_chirho.winner_term_chirho {
        return Err(
            ResidentGd7HeldCoordinatorRefusalChirho::NewerWinnerTermWithoutRetainedBarrierChirho,
        );
    }
    Ok(leadership_chirho)
}

pub(super) fn verify_held_bootstrap_election_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    local_node_chirho: &NodeIdChirho,
    losing_tail_chirho: &VerifiedLosingJournalTailChirho,
) -> std::result::Result<LeadershipChirho, ResidentGd7HeldCoordinatorRefusalChirho> {
    require_elector_node_chirho(elector_chirho.node_id_chirho(), local_node_chirho)?;
    let leadership_chirho = elector_chirho.leadership_chirho(group_chirho);
    let losing_term_chirho = u64::from(
        split_writer_epoch_chirho(losing_tail_chirho.record_epoch_chirho()).geo_term_chirho,
    );
    validate_bootstrap_election_observation_chirho(&leadership_chirho, losing_term_chirho)?;
    Ok(leadership_chirho)
}

pub(super) fn require_stable_election_observation_chirho(
    before_chirho: &LeadershipChirho,
    after_chirho: &LeadershipChirho,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    if before_chirho != after_chirho {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::ElectionObservationChangedChirho);
    }
    Ok(())
}

fn require_elector_node_chirho(
    elector_node_chirho: &NodeIdChirho,
    local_node_chirho: &NodeIdChirho,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    if elector_node_chirho != local_node_chirho {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::ElectorNodeMismatchChirho);
    }
    Ok(())
}

fn validate_bootstrap_election_observation_chirho(
    leadership_chirho: &LeadershipChirho,
    losing_term_chirho: u64,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    if leadership_chirho.is_leader_chirho {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::HeldNodeBecameLeaderChirho);
    }
    if leadership_chirho.leader_id_chirho.is_none() {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::NoElectedWinnerObservedChirho);
    }
    if leadership_chirho.term_chirho <= losing_term_chirho {
        return Err(
            ResidentGd7HeldCoordinatorRefusalChirho::WinnerTermDoesNotDeposeLosingTermChirho,
        );
    }
    Ok(())
}

fn validate_read_only_election_observation_chirho(
    leadership_chirho: &LeadershipChirho,
    identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> std::result::Result<(), ResidentGd7HeldCoordinatorRefusalChirho> {
    if leadership_chirho.is_leader_chirho {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::HeldNodeBecameLeaderChirho);
    }
    let observed_winner_chirho = leadership_chirho
        .leader_id_chirho
        .as_ref()
        .ok_or(ResidentGd7HeldCoordinatorRefusalChirho::NoElectedWinnerObservedChirho)?;
    if leadership_chirho.term_chirho < identity_chirho.winner_term_chirho {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::WinnerTermRegressedChirho);
    }
    if observed_winner_chirho.0 != identity_chirho.winner_node_chirho {
        return Err(ResidentGd7HeldCoordinatorRefusalChirho::WinnerNodeChangedChirho);
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::{
        require_elector_node_chirho, validate_bootstrap_election_observation_chirho,
        validate_read_only_election_observation_chirho,
    };
    use crate::reconciliation_chirho::{
        Gd7ForkCoordinateChirho, Gd7JournalTailCoordinateChirho, Gd7ReconciliationIdentityChirho,
    };
    use crate::resident_authority_chirho::held_coordinator_chirho::ResidentGd7HeldCoordinatorRefusalChirho;
    use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};

    fn identity_chirho() -> Gd7ReconciliationIdentityChirho {
        Gd7ReconciliationIdentityChirho {
            consistency_group_digest_chirho: "1".repeat(64),
            winner_node_chirho: "2".repeat(64),
            held_node_chirho: "3".repeat(64),
            winner_term_chirho: 7,
            losing_term_chirho: 5,
            winner_journal_genesis_digest_chirho: "4".repeat(64),
            winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
                epoch_chirho: 7,
                seq_chirho: 11,
                record_digest_chirho: "5".repeat(64),
            },
            fork_chirho: Gd7ForkCoordinateChirho {
                epoch_chirho: 5,
                seq_chirho: 8,
                record_digest_chirho: "6".repeat(64),
            },
            losing_journal_genesis_digest_chirho: "7".repeat(64),
            losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
                epoch_chirho: 5,
                seq_chirho: 10,
                record_digest_chirho: "8".repeat(64),
            },
        }
    }

    fn leadership_chirho() -> LeadershipChirho {
        LeadershipChirho {
            is_leader_chirho: false,
            leader_id_chirho: Some(NodeIdChirho("2".repeat(64))),
            term_chirho: 8,
            lease_valid_chirho: false,
        }
    }

    #[test]
    fn read_only_observation_names_each_fail_closed_identity_chirho() {
        let identity_chirho = identity_chirho();
        validate_read_only_election_observation_chirho(&leadership_chirho(), &identity_chirho)
            .expect("the same winner at a newer term remains readable");

        let mut held_leader_chirho = leadership_chirho();
        held_leader_chirho.is_leader_chirho = true;
        assert_eq!(
            validate_read_only_election_observation_chirho(&held_leader_chirho, &identity_chirho,),
            Err(ResidentGd7HeldCoordinatorRefusalChirho::HeldNodeBecameLeaderChirho)
        );

        let mut missing_winner_chirho = leadership_chirho();
        missing_winner_chirho.leader_id_chirho = None;
        assert_eq!(
            validate_read_only_election_observation_chirho(
                &missing_winner_chirho,
                &identity_chirho,
            ),
            Err(ResidentGd7HeldCoordinatorRefusalChirho::NoElectedWinnerObservedChirho)
        );

        let mut regressed_term_chirho = leadership_chirho();
        regressed_term_chirho.term_chirho = identity_chirho.winner_term_chirho - 1;
        assert_eq!(
            validate_read_only_election_observation_chirho(
                &regressed_term_chirho,
                &identity_chirho,
            ),
            Err(ResidentGd7HeldCoordinatorRefusalChirho::WinnerTermRegressedChirho)
        );

        let mut changed_winner_chirho = leadership_chirho();
        changed_winner_chirho.leader_id_chirho = Some(NodeIdChirho("9".repeat(64)));
        assert_eq!(
            validate_read_only_election_observation_chirho(
                &changed_winner_chirho,
                &identity_chirho,
            ),
            Err(ResidentGd7HeldCoordinatorRefusalChirho::WinnerNodeChangedChirho)
        );
    }

    #[test]
    fn bootstrap_and_elector_binding_name_their_distinct_refusals_chirho() {
        let held_node_chirho = NodeIdChirho("3".repeat(64));
        assert_eq!(
            require_elector_node_chirho(&NodeIdChirho("4".repeat(64)), &held_node_chirho),
            Err(ResidentGd7HeldCoordinatorRefusalChirho::ElectorNodeMismatchChirho)
        );

        let mut bootstrap_chirho = leadership_chirho();
        bootstrap_chirho.term_chirho = 5;
        assert_eq!(
            validate_bootstrap_election_observation_chirho(&bootstrap_chirho, 5),
            Err(ResidentGd7HeldCoordinatorRefusalChirho::WinnerTermDoesNotDeposeLosingTermChirho)
        );
    }
}
