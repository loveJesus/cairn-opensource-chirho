// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The lifecycle order holds, drain closes admission, and all three exit preconditions are separate.

use super::*;

fn ready_to_retire_chirho() -> NodeLifecycleFactsChirho {
    NodeLifecycleFactsChirho {
        state_chirho: NodeLifecycleStateChirho::DrainingChirho,
        holds_leadership_chirho: false,
        ownership_proven_chirho: true,
        resident_placements_chirho: 0,
    }
}

fn facts_at_chirho(state_chirho: NodeLifecycleStateChirho) -> NodeLifecycleFactsChirho {
    NodeLifecycleFactsChirho {
        state_chirho,
        holds_leadership_chirho: false,
        ownership_proven_chirho: true,
        resident_placements_chirho: 0,
    }
}

#[test]
fn the_lifecycle_runs_provision_inspect_join_drain_retire_chirho() {
    let mut state_chirho = NodeLifecycleStateChirho::ProvisionedChirho;
    for transition_chirho in [
        LifecycleTransitionChirho::InspectChirho,
        LifecycleTransitionChirho::JoinChirho,
        LifecycleTransitionChirho::DrainChirho,
        LifecycleTransitionChirho::RetireChirho,
    ] {
        let mut facts_chirho = facts_at_chirho(state_chirho);
        facts_chirho.ownership_proven_chirho = true;
        state_chirho = apply_transition_chirho(facts_chirho, transition_chirho).unwrap_or_else(
            |refusals_chirho| {
                panic!("{transition_chirho:?} refused from {state_chirho:?}: {refusals_chirho:?}")
            },
        );
    }
    assert_eq!(state_chirho, NodeLifecycleStateChirho::RetiredChirho);
}

#[test]
fn a_node_cannot_join_before_it_is_inspected_chirho() {
    // Skipping inspection would put unverified capacity into service.
    let refusals_chirho = transition_refusals_chirho(
        facts_at_chirho(NodeLifecycleStateChirho::ProvisionedChirho),
        LifecycleTransitionChirho::JoinChirho,
    );
    assert_eq!(
        refusals_chirho,
        vec![TransitionRefusalChirho::IllegalTransitionChirho {
            from_chirho: NodeLifecycleStateChirho::ProvisionedChirho,
            transition_chirho: LifecycleTransitionChirho::JoinChirho,
        }]
    );
}

#[test]
fn only_a_joined_node_admits_new_placement_chirho() {
    // THE DRAIN PROPERTY, checked at ADMISSION rather than only at retirement: by the time you are
    // retiring, a placement admitted during drain is already a problem.
    assert!(admits_new_placement_chirho(
        NodeLifecycleStateChirho::JoinedChirho
    ));
    for closed_chirho in [
        NodeLifecycleStateChirho::ProvisionedChirho,
        NodeLifecycleStateChirho::InspectedChirho,
        NodeLifecycleStateChirho::DrainingChirho,
        NodeLifecycleStateChirho::RetiredChirho,
    ] {
        assert!(
            !admits_new_placement_chirho(closed_chirho),
            "{closed_chirho:?} must not admit new placement"
        );
    }
}

#[test]
fn retirement_waits_for_leadership_handoff_chirho() {
    // Retiring a leader takes the authority down with the machine. The handoff must have HAPPENED.
    let mut facts_chirho = ready_to_retire_chirho();
    facts_chirho.holds_leadership_chirho = true;
    assert_eq!(
        transition_refusals_chirho(facts_chirho, LifecycleTransitionChirho::RetireChirho),
        vec![TransitionRefusalChirho::LeadershipNotHandedOffChirho]
    );
}

#[test]
fn retirement_requires_proven_ownership_chirho() {
    // Destroying a machine is irreversible; without proof, a mistaken or malicious plan could
    // retire someone else's host.
    let mut facts_chirho = ready_to_retire_chirho();
    facts_chirho.ownership_proven_chirho = false;
    assert_eq!(
        transition_refusals_chirho(facts_chirho, LifecycleTransitionChirho::RetireChirho),
        vec![TransitionRefusalChirho::OwnershipNotProvenChirho]
    );
}

#[test]
fn retirement_waits_for_the_node_to_be_empty_chirho() {
    let mut facts_chirho = ready_to_retire_chirho();
    facts_chirho.resident_placements_chirho = 2;
    assert_eq!(
        transition_refusals_chirho(facts_chirho, LifecycleTransitionChirho::RetireChirho),
        vec![TransitionRefusalChirho::PlacementsStillResidentChirho {
            remaining_chirho: 2
        }]
    );
}

#[test]
fn all_three_exit_preconditions_report_together_chirho() {
    // An operator needs the whole bill. A single "not ready" would hide which of three very
    // different fixes is required — hand off leadership, prove ownership, or drain the work.
    let facts_chirho = NodeLifecycleFactsChirho {
        state_chirho: NodeLifecycleStateChirho::DrainingChirho,
        holds_leadership_chirho: true,
        ownership_proven_chirho: false,
        resident_placements_chirho: 5,
    };
    let refusals_chirho =
        transition_refusals_chirho(facts_chirho, LifecycleTransitionChirho::RetireChirho);
    assert_eq!(
        refusals_chirho,
        vec![
            TransitionRefusalChirho::LeadershipNotHandedOffChirho,
            TransitionRefusalChirho::OwnershipNotProvenChirho,
            TransitionRefusalChirho::PlacementsStillResidentChirho {
                remaining_chirho: 5
            },
        ],
        "all three, in a deterministic order"
    );
}

#[test]
fn the_exit_preconditions_do_not_block_earlier_transitions_chirho() {
    // A node that holds leadership and has work on it may still be DRAINED — draining is how it
    // stops being those things. Applying the retirement preconditions to every transition would
    // deadlock the lifecycle: you could never reach the state that clears them.
    let facts_chirho = NodeLifecycleFactsChirho {
        state_chirho: NodeLifecycleStateChirho::JoinedChirho,
        holds_leadership_chirho: true,
        ownership_proven_chirho: false,
        resident_placements_chirho: 9,
    };
    assert_eq!(
        apply_transition_chirho(facts_chirho, LifecycleTransitionChirho::DrainChirho),
        Ok(NodeLifecycleStateChirho::DrainingChirho)
    );
}

#[test]
fn a_retired_node_cannot_be_moved_again_chirho() {
    for transition_chirho in [
        LifecycleTransitionChirho::InspectChirho,
        LifecycleTransitionChirho::JoinChirho,
        LifecycleTransitionChirho::DrainChirho,
        LifecycleTransitionChirho::RetireChirho,
    ] {
        assert!(
            apply_transition_chirho(
                facts_at_chirho(NodeLifecycleStateChirho::RetiredChirho),
                transition_chirho
            )
            .is_err(),
            "retired is terminal, but {transition_chirho:?} was allowed"
        );
    }
}
