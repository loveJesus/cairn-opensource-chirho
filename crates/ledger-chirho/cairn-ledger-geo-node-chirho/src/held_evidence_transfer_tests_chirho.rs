// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::held_evidence_transfer_chirho::{
    handoff_term_disposition_chirho, invoke_actor_owned_adoption_materialization_chirho,
    require_original_term_before_begin_chirho, winner_transport_term_from_observation_chirho,
    Gd7HeldHandoffContinuationRefusalChirho, Gd7HeldHandoffTermDispositionChirho,
};
use super::{held_geo_recovery_route_chirho, HeldGeoRecoveryRouteChirho};
use cairn_ledger_host_chirho::reconciliation_chirho::{
    Gd7ForkCoordinateChirho, Gd7HeldEvidenceTransferIdentityChirho, Gd7JournalTailCoordinateChirho,
    Gd7ReconciliationIdentityChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use std::cell::Cell;

#[test]
fn same_winner_re_election_supplies_the_current_transport_term_chirho() {
    let winner_node_chirho = NodeIdChirho("winner-chirho".to_owned());
    let leadership_chirho = LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: Some(winner_node_chirho.clone()),
        term_chirho: 8,
        lease_valid_chirho: false,
    };

    assert_eq!(
        winner_transport_term_from_observation_chirho(
            &leadership_chirho,
            &winner_node_chirho,
            7,
        )
        .expect("same winner at a later term remains the transport target"),
        8,
        "transport authentication must use the fresh term while the handoff identity retains term 7"
    );

    let foreign_winner_chirho = NodeIdChirho("foreign-winner-chirho".to_owned());
    assert!(
        winner_transport_term_from_observation_chirho(
            &leadership_chirho,
            &foreign_winner_chirho,
            7,
        )
        .unwrap_err()
        .to_string()
        .contains("exact historical winner"),
        "a new leader is reconciliation drift, not a term refresh"
    );
}

#[test]
fn newer_term_cannot_begin_without_the_retained_accepted_barrier_chirho() {
    require_original_term_before_begin_chirho(7, 7)
        .expect("the historical term may establish or resume its original handoff");
    assert_eq!(
        require_original_term_before_begin_chirho(7, 8),
        Err(Gd7HeldHandoffContinuationRefusalChirho::NewerWinnerTermWithoutRetainedBarrierChirho)
    );

    let begin_handoff_reached_chirho = Cell::new(false);
    let retained_chirho = handoff_term_disposition_chirho(true, 7, 8)
        .expect("the exact retained accepted attempt stays reachable at the newer term");
    assert_eq!(
        retained_chirho,
        Gd7HeldHandoffTermDispositionChirho::ReuseRetainedAcceptedChirho
    );
    assert!(!begin_handoff_reached_chirho.get());

    let refusal_chirho = handoff_term_disposition_chirho(false, 7, 8).unwrap_err();
    assert_eq!(
        refusal_chirho,
        Gd7HeldHandoffContinuationRefusalChirho::NewerWinnerTermWithoutRetainedBarrierChirho
    );
    assert!(
        !refusal_chirho
            .to_string()
            .contains("historical winner changed")
            && !refusal_chirho.to_string().contains("regressed"),
        "the no-barrier refusal stays distinct from winner drift and term regression"
    );
    assert!(
        !begin_handoff_reached_chirho.get(),
        "a newer term with no retained AcceptedChirho barrier must refuse before BeginHandoffChirho"
    );

    let historical_begin_chirho = handoff_term_disposition_chirho(false, 7, 7)
        .expect("the historical term may reach the original begin path");
    if historical_begin_chirho == Gd7HeldHandoffTermDispositionChirho::BeginAtHistoricalTermChirho {
        begin_handoff_reached_chirho.set(true);
    }
    assert!(begin_handoff_reached_chirho.get());
}

#[test]
fn completed_geo_evidence_invokes_the_actor_owned_materialization_command_chirho() {
    let reconciliation_identity_chirho = Gd7ReconciliationIdentityChirho {
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
    };
    let identity_chirho = Gd7HeldEvidenceTransferIdentityChirho {
        reconciliation_identity_chirho,
        reconciliation_checkpoint_ref_chirho: "9".repeat(64),
        held_view_transfer_checkpoint_ref_chirho: "a".repeat(64),
        winner_handoff_attempt_digest_chirho: "b".repeat(64),
    };
    let expected_checkpoint_ref_chirho = "c".repeat(64);
    let invoked_chirho = Cell::new(false);

    let result_chirho = invoke_actor_owned_adoption_materialization_chirho(
        &identity_chirho,
        &expected_checkpoint_ref_chirho,
        |request_chirho| {
            invoked_chirho.set(true);
            assert_eq!(request_chirho.transfer_identity_chirho, identity_chirho);
            assert_eq!(
                request_chirho.expected_evidence_checkpoint_ref_chirho,
                expected_checkpoint_ref_chirho
            );
            Ok(17_u64)
        },
    )
    .expect("the geo completion seam invokes the actor-owned command");
    assert!(invoked_chirho.get(), "the production geo seam was reached");
    assert_eq!(result_chirho, 17);
}

#[test]
fn adopted_geo_restart_routes_only_to_monitor_without_plan_producers_chirho() {
    use cairn_ledger_host_chirho::reconciliation_chirho::Gd7ReconciliationPhaseChirho;

    let plan_producer_calls_chirho = Cell::new(0_u64);
    let monitor_resume_calls_chirho = Cell::new(0_u64);
    let route_chirho =
        held_geo_recovery_route_chirho(Some(Gd7ReconciliationPhaseChirho::AdoptedHeldChirho));
    match route_chirho {
        HeldGeoRecoveryRouteChirho::DrivePlanSealedProducersChirho => {
            plan_producer_calls_chirho.set(plan_producer_calls_chirho.get() + 1);
        }
        HeldGeoRecoveryRouteChirho::ResumeAdoptedMonitorChirho => {
            monitor_resume_calls_chirho.set(monitor_resume_calls_chirho.get() + 1);
        }
    }
    assert_eq!(
        plan_producer_calls_chirho.get(),
        0,
        "an adopted restart must not call observation, plan, view, evidence, or materialization producers"
    );
    assert_eq!(
        monitor_resume_calls_chirho.get(),
        1,
        "the same execution arm proves the adopted branch is not green by doing nothing"
    );
    assert_eq!(
        held_geo_recovery_route_chirho(Some(Gd7ReconciliationPhaseChirho::PlanSealedChirho)),
        HeldGeoRecoveryRouteChirho::DrivePlanSealedProducersChirho,
        "PlanSealed remains the positive control for the producer path"
    );
}
