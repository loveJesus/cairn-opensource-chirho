// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Admission is a conjunction: each of the four clauses is shown independently necessary.

use super::*;
use crate::capacity_chirho::capacity_dominance_chirho::CapacityDimensionChirho;

fn capacity_chirho(
    cpu_millicores_chirho: u64,
    memory_bytes_chirho: u64,
    durable_bytes_chirho: u64,
) -> AllocatableCapacityChirho {
    AllocatableCapacityChirho {
        cpu_millicores_chirho,
        memory_bytes_chirho,
        durable_bytes_chirho,
    }
}

fn stamp_chirho(hlc_millis_chirho: u64, sequence_chirho: u64) -> MeasurementStampChirho {
    MeasurementStampChirho {
        hlc_millis_chirho,
        sequence_chirho,
    }
}

fn healthy_node_chirho() -> RegisteredNodeChirho {
    RegisteredNodeChirho {
        node_id_chirho: "node-a-chirho".to_string(),
        domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fsn1-chirho".to_string(),
        },
        allocatable_chirho: capacity_chirho(8_000, 32 << 30, 1_024 << 30),
        lifecycle_chirho: NodeLifecycleStateChirho::JoinedChirho,
        last_measurement_chirho: Some(stamp_chirho(1_000, 7)),
        last_observed_usage_chirho: Some(capacity_chirho(0, 0, 0)),
        // A healthy node is a MEASURED node: its own evidence permits work. Leaving this frozen would
        // make every admission arm below fail for a reason it is not testing.
        scaling_posture_chirho: posture_for_verdict_chirho(MeasurementVerdictChirho::FreshChirho),
    }
}

fn registry_with_healthy_node_chirho() -> PlacementRegistryChirho {
    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    registry_chirho.upsert_node_chirho(healthy_node_chirho());
    registry_chirho
}

/// A modest demand, generous headroom, and a strictly newer measurement — admissible on a healthy node.
fn admissible_call_chirho(
    registry_chirho: &PlacementRegistryChirho,
) -> Vec<PlacementRefusalChirho> {
    registry_chirho.placement_refusals_chirho(
        "node-a-chirho",
        &capacity_chirho(1_000, 4 << 30, 64 << 30),
        &capacity_chirho(500, 1 << 30, 16 << 30),
        stamp_chirho(2_000, 8),
    )
}

#[test]
fn a_healthy_node_admits_a_modest_placement_chirho() {
    // The positive control. Without it, every "refused" assertion below could be passing because the
    // registry refuses everything.
    assert!(admissible_call_chirho(&registry_with_healthy_node_chirho()).is_empty());
}

#[test]
fn clause_one_an_unknown_node_is_refused_and_nothing_else_is_reported_chirho() {
    let registry_chirho = registry_with_healthy_node_chirho();
    let refusals_chirho = registry_chirho.placement_refusals_chirho(
        "ghost-chirho",
        &capacity_chirho(1, 1, 1),
        &capacity_chirho(0, 0, 0),
        stamp_chirho(2_000, 8),
    );
    assert_eq!(
        refusals_chirho,
        vec![PlacementRefusalChirho::UnknownNodeChirho {
            node_id_chirho: "ghost-chirho".to_string(),
        }],
        "an unknown node has no facts to check, so nothing else should be claimed about it"
    );
}

#[test]
fn clause_two_a_draining_node_is_refused_though_it_has_ample_capacity_chirho() {
    // CLAUSE INDEPENDENCE: capacity and freshness are both fine here. Only the lifecycle differs.
    let mut registry_chirho = registry_with_healthy_node_chirho();
    let mut node_chirho = healthy_node_chirho();
    node_chirho.lifecycle_chirho = NodeLifecycleStateChirho::DrainingChirho;
    registry_chirho.upsert_node_chirho(node_chirho);
    assert_eq!(
        admissible_call_chirho(&registry_chirho),
        vec![PlacementRefusalChirho::LifecycleClosedChirho {
            state_chirho: NodeLifecycleStateChirho::DrainingChirho,
        }]
    );
}

#[test]
fn clause_three_a_replayed_measurement_is_refused_though_the_node_is_joined_and_roomy_chirho() {
    // CLAUSE INDEPENDENCE: lifecycle open, capacity ample — only the measurement is stale.
    let registry_chirho = registry_with_healthy_node_chirho();
    let refusals_chirho = registry_chirho.placement_refusals_chirho(
        "node-a-chirho",
        &capacity_chirho(1_000, 4 << 30, 64 << 30),
        &capacity_chirho(0, 0, 0),
        stamp_chirho(9_999, 7), // same sequence as last accepted = replay
    );
    assert_eq!(
        refusals_chirho,
        vec![PlacementRefusalChirho::MeasurementNotFreshChirho {
            verdict_chirho: MeasurementVerdictChirho::ReplayedChirho {
                last_sequence_chirho: 7,
                offered_sequence_chirho: 7,
            },
        }]
    );
}

#[test]
fn clause_four_capacity_is_refused_though_lifecycle_and_freshness_pass_chirho() {
    // CLAUSE INDEPENDENCE: the node is joined and the measurement is fresh; only the numbers fail.
    let registry_chirho = registry_with_healthy_node_chirho();
    let refusals_chirho = registry_chirho.placement_refusals_chirho(
        "node-a-chirho",
        &capacity_chirho(9_000, 1 << 30, 1 << 30), // 9_000 > 8_000 allocatable
        &capacity_chirho(0, 0, 0),
        stamp_chirho(2_000, 8),
    );
    assert_eq!(
        refusals_chirho,
        vec![PlacementRefusalChirho::CapacityChirho(
            AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
                dimension_chirho: CapacityDimensionChirho::CpuMillicoresChirho,
                free_chirho: 8_000,
                demand_chirho: 9_000,
                headroom_chirho: 0,
            }
        )]
    );
}

#[test]
fn reserved_capacity_is_derived_from_placements_and_shrinks_what_is_admissible_chirho() {
    // The registry has no `reserved` field to drift; it folds placed demands every time. Placing work
    // must therefore change what the NEXT placement sees.
    let mut registry_chirho = registry_with_healthy_node_chirho();
    assert_eq!(
        registry_chirho.reserved_for_chirho("node-a-chirho"),
        capacity_chirho(0, 0, 0)
    );
    assert!(admissible_call_chirho(&registry_chirho).is_empty());

    registry_chirho.record_placement_chirho(
        "node-a-chirho",
        PlacedDemandChirho {
            placement_id_chirho: "p1-chirho".to_string(),
            demand_chirho: capacity_chirho(7_500, 1 << 30, 1 << 30),
        },
    );
    assert_eq!(
        registry_chirho.reserved_for_chirho("node-a-chirho"),
        capacity_chirho(7_500, 1 << 30, 1 << 30)
    );
    // The same call that was admissible a moment ago is now short on CPU.
    let refusals_chirho = admissible_call_chirho(&registry_chirho);
    assert!(
        refusals_chirho.iter().any(|r_chirho| matches!(
            r_chirho,
            PlacementRefusalChirho::CapacityChirho(
                AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
                    dimension_chirho: CapacityDimensionChirho::CpuMillicoresChirho,
                    ..
                }
            )
        )),
        "placing work must reduce what the next placement may take: {refusals_chirho:?}"
    );
}

#[test]
fn every_failing_clause_reports_together_chirho() {
    // An operator gets the whole bill: a draining node with a replayed stamp and an oversized demand
    // should name all three, not stop at the first.
    let mut registry_chirho = registry_with_healthy_node_chirho();
    let mut node_chirho = healthy_node_chirho();
    node_chirho.lifecycle_chirho = NodeLifecycleStateChirho::RetiredChirho;
    registry_chirho.upsert_node_chirho(node_chirho);
    let refusals_chirho = registry_chirho.placement_refusals_chirho(
        "node-a-chirho",
        &capacity_chirho(99_000, 1 << 30, 1 << 30),
        &capacity_chirho(0, 0, 0),
        stamp_chirho(1, 1),
    );
    assert!(
        refusals_chirho.len() >= 3,
        "lifecycle, freshness and capacity should all report: {refusals_chirho:?}"
    );
}

/// Build a node the way production does — out of a capacity grant — so a node's failure domain in an
/// arm comes from the same place it comes from at runtime.
fn node_from_grant_chirho(
    node_id_chirho: &str,
    provider_chirho: &str,
    region_chirho: &str,
) -> RegisteredNodeChirho {
    RegisteredNodeChirho::from_verified_capacity_chirho(
        &VerifiedNodeCapacityChirho::unverified_for_test_chirho(
            node_id_chirho,
            FailureDomainChirho {
                provider_chirho: provider_chirho.to_string(),
                region_chirho: region_chirho.to_string(),
            },
            capacity_chirho(8_000, 32 << 30, 1_024 << 30),
        ),
    )
}

#[test]
fn registry_spread_is_computed_over_the_registered_layout_chirho() {
    // The nodes here are built FROM GRANTS rather than by assigning a domain onto a node, and that is
    // the point rather than tidiness. `spread_refusals_chirho` derives the fleet layout by reading
    // each node's `domain_chirho`, so if a domain could be assigned after construction, a caller could
    // verify grants for three nodes in one region and relabel two of them to satisfy a minimum spread
    // that no real failure domain backs. The field is private and comes from the grant, so the only
    // way to change what this check sees is to present a different signed grant.
    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    registry_chirho.upsert_node_chirho(node_from_grant_chirho(
        "node-a-chirho",
        "hetzner-chirho",
        "fsn1-chirho",
    ));
    // One provider, one region so far.
    assert!(!registry_chirho
        .spread_refusals_chirho(MinimumSpreadChirho {
            distinct_providers_chirho: 2,
            distinct_regions_chirho: 2,
        })
        .is_empty());

    registry_chirho.upsert_node_chirho(node_from_grant_chirho(
        "node-b-chirho",
        "ovh-chirho",
        "fr-chirho",
    ));
    assert!(registry_chirho
        .spread_refusals_chirho(MinimumSpreadChirho {
            distinct_providers_chirho: 2,
            distinct_regions_chirho: 2,
        })
        .is_empty());
}

// ---- Advancing the accepted measurement from verified node-signed evidence ----
//
// Before this existed the field was public and no production code ever advanced it, so admission's
// freshness clause compared every offer against `None` and classified FRESH. The freeze was
// unreachable on a real node while the arms that exercise it passed, because they set the baseline by
// hand. These arms are about the production route to that state.

fn verified_measurement_chirho(
    node_id_chirho: &str,
    stamp_chirho: MeasurementStampChirho,
) -> VerifiedUsageMeasurementChirho {
    verified_measurement_with_usage_chirho(
        node_id_chirho,
        stamp_chirho,
        capacity_chirho(1_500, 2 << 30, 40 << 30),
    )
}

fn verified_measurement_with_usage_chirho(
    node_id_chirho: &str,
    stamp_chirho: MeasurementStampChirho,
    observed_usage_chirho: AllocatableCapacityChirho,
) -> VerifiedUsageMeasurementChirho {
    VerifiedUsageMeasurementChirho::unverified_for_test_chirho(
        node_id_chirho,
        stamp_chirho,
        observed_usage_chirho,
    )
}

#[test]
fn a_verified_fresh_measurement_advances_the_accepted_stamp_chirho() {
    let mut node_chirho = healthy_node_chirho();
    let verdict_chirho = node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
            "node-a-chirho",
            stamp_chirho(2_000, 9),
        ))
        .expect("same node");
    assert!(verdict_chirho.is_fresh_chirho());
    assert_eq!(
        node_chirho.last_measurement_chirho(),
        Some(stamp_chirho(2_000, 9))
    );
    assert_eq!(
        node_chirho.last_observed_usage_chirho(),
        Some(&capacity_chirho(1_500, 2 << 30, 40 << 30))
    );
}

#[test]
fn a_replayed_measurement_does_not_re_anchor_the_baseline_chirho() {
    // The subtle half, and the reason the advance is conditional rather than unconditional. A node
    // sits at sequence 7. A replay at 5 must be REPORTED as replayed and must NOT become the baseline
    // -- because if it did, the next report at 6 would be judged against 5 and look FRESH, so one
    // replayed report would launder every stale report after it.
    let mut node_chirho = healthy_node_chirho();
    assert_eq!(
        node_chirho.last_measurement_chirho(),
        Some(stamp_chirho(1_000, 7))
    );

    let replay_chirho = node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
            "node-a-chirho",
            stamp_chirho(2_000, 5),
        ))
        .expect("same node");
    assert!(
        !replay_chirho.is_fresh_chirho(),
        "sequence 5 does not advance past 7"
    );
    assert_eq!(
        node_chirho.last_measurement_chirho(),
        Some(stamp_chirho(1_000, 7)),
        "the refused report must not become the baseline"
    );

    let follow_up_chirho = node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
            "node-a-chirho",
            stamp_chirho(3_000, 6),
        ))
        .expect("same node");
    assert!(
        !follow_up_chirho.is_fresh_chirho(),
        "sequence 6 is still behind 7 -- it would look fresh only if the replay had re-anchored"
    );
    assert_eq!(
        node_chirho.last_measurement_chirho(),
        Some(stamp_chirho(1_000, 7)),
        "and the baseline is still the last FRESH report, not either refused one"
    );
}

#[test]
fn replayed_evidence_does_not_replace_the_last_accepted_load_chirho() {
    let mut node_chirho = healthy_node_chirho();
    node_chirho.set_measurement_for_test_chirho(None);
    node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_with_usage_chirho(
            "node-a-chirho",
            stamp_chirho(1_000, 7),
            capacity_chirho(6_000, 6 << 30, 60 << 30),
        ))
        .expect("fresh baseline");
    node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_with_usage_chirho(
            "node-a-chirho",
            stamp_chirho(2_000, 6),
            capacity_chirho(1, 1, 1),
        ))
        .expect("authentic replay is retained as freeze evidence");
    assert_eq!(
        node_chirho.last_observed_usage_chirho(),
        Some(&capacity_chirho(6_000, 6 << 30, 60 << 30)),
        "sequence ordering must judge reports, never reorder a replay into the accepted load"
    );
    assert!(!node_chirho
        .scaling_posture_chirho()
        .scale_out_allowed_chirho());
}

#[test]
fn retained_placement_admission_is_closed_by_real_load_without_double_counting_chirho() {
    let mut node_chirho = healthy_node_chirho();
    node_chirho.set_measurement_for_test_chirho(None);
    node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_with_usage_chirho(
            "node-a-chirho",
            stamp_chirho(2_000, 8),
            capacity_chirho(7_000, 2 << 30, 40 << 30),
        ))
        .expect("fresh load");
    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    registry_chirho.upsert_node_chirho(node_chirho);
    registry_chirho.record_placement_chirho(
        "node-a-chirho",
        PlacedDemandChirho {
            placement_id_chirho: "existing-tenant-chirho".to_string(),
            demand_chirho: capacity_chirho(3_000, 1 << 30, 20 << 30),
        },
    );

    assert_eq!(
        registry_chirho.effective_occupied_for_chirho("node-a-chirho"),
        Some(capacity_chirho(7_000, 2 << 30, 40 << 30)),
        "observed host load is larger here and must drive the decision"
    );
    assert_eq!(
        registry_chirho
            .retained_placement_refusals_chirho("node-a-chirho", &capacity_chirho(1_001, 0, 0),),
        vec![PlacementRefusalChirho::CapacityChirho(
            AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
                dimension_chirho: CapacityDimensionChirho::CpuMillicoresChirho,
                free_chirho: 1_000,
                demand_chirho: 0,
                headroom_chirho: 1_001,
            },
        )],
        "the existing placement is already reserved, so only load plus headroom is required"
    );
}

#[test]
fn a_measurement_for_another_node_cannot_advance_this_one_chirho() {
    // Verified evidence is verified FOR A NODE. Without this check a caller could verify one node's
    // report and apply it to a different node, which is the same shape as verifying a capacity grant
    // for one node and registering it as another.
    let mut node_chirho = healthy_node_chirho();
    assert_eq!(
        node_chirho
            .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
                "node-b-chirho",
                stamp_chirho(9_000, 99),
            ))
            .expect_err("a different node's report must refuse"),
        MeasurementAdvanceRefusalChirho::NodeIdMismatchChirho {
            registered_chirho: "node-a-chirho".to_string(),
            measured_chirho: "node-b-chirho".to_string(),
        }
    );
    assert_eq!(
        node_chirho.last_measurement_chirho(),
        Some(stamp_chirho(1_000, 7))
    );
}

#[test]
fn admission_freezes_a_node_whose_baseline_came_from_verified_evidence_chirho() {
    // The composition, and the point of the whole change: the freeze is now reachable WITHOUT any arm
    // hand-setting the baseline. The node's accepted stamp is advanced only through verified evidence,
    // and a replayed offer against that baseline is then refused by admission.
    let mut node_chirho = healthy_node_chirho();
    node_chirho.set_measurement_for_test_chirho(None); // start from a node that was never measured
    node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
            "node-a-chirho",
            stamp_chirho(5_000, 20),
        ))
        .expect("same node");

    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    registry_chirho.upsert_node_chirho(node_chirho);
    let refusals_chirho = registry_chirho.placement_refusals_chirho(
        "node-a-chirho",
        &capacity_chirho(100, 1 << 30, 1 << 30),
        &capacity_chirho(0, 0, 0),
        stamp_chirho(6_000, 20), // same sequence: a replay
    );
    // Exactly one refusal, and it is the freshness one. Asserting only that a freshness refusal is
    // PRESENT would still pass if the fixture happened to fail capacity or lifecycle too, and then the
    // arm would not be isolating the clause it names.
    assert_eq!(
        refusals_chirho.len(),
        1,
        "the fixture must fail freshness ALONE, or this arm is not about freshness: {refusals_chirho:?}"
    );
    assert!(
        matches!(
            refusals_chirho[0],
            PlacementRefusalChirho::MeasurementNotFreshChirho { .. }
        ),
        "a replay against a verified-evidence baseline must freeze scale-out: {refusals_chirho:?}"
    );
}

// ---- A node is frozen by ITS OWN evidence, not by what a requester offers ----

#[test]
fn a_never_measured_node_is_refused_even_when_everything_else_is_fine_chirho() {
    // Clause 7 makes a fresh measurement a REQUIREMENT for admission, so the absence of one is not
    // permission. Before the posture was carried, a never-measured node classified FRESH against
    // `None` and sailed through the freshness clause on any offer.
    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    let mut node_chirho = node_from_grant_chirho("node-a-chirho", "hetzner-chirho", "fsn1-chirho");
    // Give it a lifecycle that admits, so the ONLY thing left to refuse is the missing measurement.
    node_chirho.set_measurement_for_test_chirho(None);
    registry_chirho.upsert_node_chirho(node_chirho);

    let refusals_chirho = registry_chirho.placement_refusals_chirho(
        "node-a-chirho",
        &capacity_chirho(100, 1 << 30, 1 << 30),
        &capacity_chirho(0, 0, 0),
        stamp_chirho(9_000, 99),
    );
    assert!(
        refusals_chirho.iter().any(|refusal_chirho| matches!(
            refusal_chirho,
            PlacementRefusalChirho::FrozenByItsOwnEvidenceChirho
        )),
        "a node that has never reported must not be admitted: {refusals_chirho:?}"
    );
}

#[test]
fn a_generous_offered_stamp_cannot_thaw_a_node_its_own_evidence_froze_chirho() {
    // THE arm. The offered stamp is a caller-supplied NUMBER — a requester can always present one that
    // looks fresh. If the freeze depended only on that comparison, "stale evidence freezes this node"
    // would be defeated by the party asking for the placement.
    let mut node_chirho = healthy_node_chirho();
    node_chirho.set_measurement_for_test_chirho(None);
    node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
            "node-a-chirho",
            stamp_chirho(1_000, 5),
        ))
        .expect("first report");
    let replay_chirho = node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
            "node-a-chirho",
            stamp_chirho(2_000, 5),
        ))
        .expect("replay recorded");
    assert!(!replay_chirho.is_fresh_chirho());

    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    registry_chirho.upsert_node_chirho(node_chirho);

    // A requester offering a far-future, strictly-advancing stamp. Judged only against the node's
    // baseline this is FRESH, so the offer-side clause alone would let the placement through.
    let refusals_chirho = registry_chirho.placement_refusals_chirho(
        "node-a-chirho",
        &capacity_chirho(100, 1 << 30, 1 << 30),
        &capacity_chirho(0, 0, 0),
        stamp_chirho(999_000, 9_999),
    );
    assert!(
        refusals_chirho.iter().any(|refusal_chirho| matches!(
            refusal_chirho,
            PlacementRefusalChirho::FrozenByItsOwnEvidenceChirho
        )),
        "the node's own replayed evidence must freeze it whatever the requester offers: \
         {refusals_chirho:?}"
    );
    assert!(
        !refusals_chirho
            .iter()
            .any(|refusal_chirho| matches!(
                refusal_chirho,
                PlacementRefusalChirho::MeasurementNotFreshChirho { .. }
            )),
        "and the OFFER-side clause is genuinely satisfied here, so this arm is not passing for the \
         wrong reason: {refusals_chirho:?}"
    );
}

#[test]
fn a_fresh_report_thaws_what_a_replay_froze_chirho() {
    let mut node_chirho = healthy_node_chirho();
    node_chirho.set_measurement_for_test_chirho(None);
    for stamp_chirho in [stamp_chirho(1_000, 5), stamp_chirho(2_000, 5)] {
        node_chirho
            .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
                "node-a-chirho",
                stamp_chirho,
            ))
            .expect("applied");
    }
    assert!(!node_chirho
        .scaling_posture_chirho()
        .scale_out_allowed_chirho());

    node_chirho
        .advance_by_verified_measurement_chirho(&verified_measurement_chirho(
            "node-a-chirho",
            stamp_chirho(3_000, 6),
        ))
        .expect("a genuinely fresh report");
    assert!(node_chirho
        .scaling_posture_chirho()
        .scale_out_allowed_chirho());
    assert!(node_chirho
        .scaling_posture_chirho()
        .scale_in_allowed_chirho());
}

// ---- UPGRADE: capacity changes in place, no node swap ----
//
// CF8 clause 9 names provision/inspect/join/drain/retire/replace/UPGRADE, and upgrade genuinely is not
// replace: `an_equal_candidate_still_replaces_chirho` records that replacement does not imply an
// upgrade, since dominance is `>=`. Replace exchanges one node for another; upgrade re-grants the same
// node, which keeps serving throughout.

fn grant_for_chirho(
    node_id_chirho: &str,
    provider_chirho: &str,
    region_chirho: &str,
    allocatable_chirho: AllocatableCapacityChirho,
) -> VerifiedNodeCapacityChirho {
    VerifiedNodeCapacityChirho::unverified_for_test_chirho(
        node_id_chirho,
        FailureDomainChirho {
            provider_chirho: provider_chirho.to_string(),
            region_chirho: region_chirho.to_string(),
        },
        allocatable_chirho,
    )
}

fn registry_with_upgradeable_node_chirho() -> PlacementRegistryChirho {
    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    registry_chirho.upsert_node_chirho(healthy_node_chirho());
    registry_chirho
}

#[test]
fn a_re_grant_raises_capacity_in_place_without_swapping_the_node_chirho() {
    // THE upgrade arm, and the distinction from replace is what it asserts: same node id, same
    // lifecycle, larger capacity. Nothing was provisioned, joined or drained.
    let mut registry_chirho = registry_with_upgradeable_node_chirho();
    let before_chirho = registry_chirho.node_chirho("node-a-chirho").expect("node");
    let lifecycle_before_chirho = before_chirho.lifecycle_chirho();

    assert_eq!(
        registry_chirho
            .advance_node_capacity_chirho(&grant_for_chirho(
                "node-a-chirho",
                "hetzner-chirho",
                "fsn1-chirho",
                capacity_chirho(16_000, 64 << 30, 2_048 << 30),
            ))
            .expect("a larger re-grant applies"),
        CapacityAdvanceChirho::RaisedChirho
    );

    let after_chirho = registry_chirho.node_chirho("node-a-chirho").expect("node");
    assert_eq!(
        after_chirho.allocatable_chirho().cpu_millicores_chirho,
        16_000
    );
    assert_eq!(
        after_chirho.lifecycle_chirho(),
        lifecycle_before_chirho,
        "an upgrade is NOT a replace: no lifecycle transition happens"
    );
    assert_eq!(
        after_chirho.node_id_chirho(),
        "node-a-chirho",
        "and no node was swapped"
    );
}

#[test]
fn a_re_grant_cannot_move_a_node_between_failure_domains_chirho() {
    // The safety centrepiece. `domain_chirho` was made private so a caller could not relabel a node and
    // fabricate the spread clause 12 constrains — and a signed RE-GRANT is the other route to the same
    // place. A node that genuinely moved is a different node.
    let mut registry_chirho = registry_with_upgradeable_node_chirho();
    assert_eq!(
        registry_chirho
            .advance_node_capacity_chirho(&grant_for_chirho(
                "node-a-chirho",
                "ovh-chirho",
                "fr-chirho",
                capacity_chirho(16_000, 64 << 30, 2_048 << 30),
            ))
            .expect_err("a domain change must refuse"),
        CapacityAdvanceRefusalChirho::FailureDomainChangedChirho {
            from_chirho: FailureDomainChirho {
                provider_chirho: "hetzner-chirho".to_string(),
                region_chirho: "fsn1-chirho".to_string(),
            },
            to_chirho: FailureDomainChirho {
                provider_chirho: "ovh-chirho".to_string(),
                region_chirho: "fr-chirho".to_string(),
            },
        }
    );
    // And nothing moved: the refusal happens before the capacity is applied.
    assert_eq!(
        registry_chirho
            .node_chirho("node-a-chirho")
            .expect("node")
            .allocatable_chirho()
            .cpu_millicores_chirho,
        8_000
    );
}

#[test]
fn a_re_grant_below_what_is_already_placed_here_is_refused_chirho() {
    // The placements do not disappear because the grant shrank. Shrinking below them produces an
    // instantly over-committed node, which is the state admission control exists to prevent.
    let mut registry_chirho = registry_with_upgradeable_node_chirho();
    registry_chirho.record_placement_chirho(
        "node-a-chirho",
        PlacedDemandChirho {
            placement_id_chirho: "placement-1-chirho".to_string(),
            demand_chirho: capacity_chirho(6_000, 8 << 30, 100 << 30),
        },
    );

    assert_eq!(
        registry_chirho
            .advance_node_capacity_chirho(&grant_for_chirho(
                "node-a-chirho",
                "hetzner-chirho",
                "fsn1-chirho",
                capacity_chirho(1_000, 64 << 30, 2_048 << 30),
            ))
            .expect_err("below reserved must refuse"),
        CapacityAdvanceRefusalChirho::BelowReservedChirho {
            dimension_chirho: CapacityDimensionChirho::CpuMillicoresChirho,
            reserved_chirho: 6_000,
            offered_chirho: 1_000,
        }
    );
}

#[test]
fn a_lowering_that_still_covers_its_placements_is_allowed_chirho() {
    // Capacity must not be a ratchet: resizing a node down is legitimate while it still covers what is
    // placed. Without this arm the refusal above would be indistinguishable from "lowering is banned".
    let mut registry_chirho = registry_with_upgradeable_node_chirho();
    registry_chirho.record_placement_chirho(
        "node-a-chirho",
        PlacedDemandChirho {
            placement_id_chirho: "placement-1-chirho".to_string(),
            demand_chirho: capacity_chirho(1_000, 1 << 30, 10 << 30),
        },
    );
    assert_eq!(
        registry_chirho
            .advance_node_capacity_chirho(&grant_for_chirho(
                "node-a-chirho",
                "hetzner-chirho",
                "fsn1-chirho",
                capacity_chirho(4_000, 16 << 30, 512 << 30),
            ))
            .expect("still covers its placements"),
        CapacityAdvanceChirho::LoweredChirho
    );
}

#[test]
fn a_re_grant_restating_the_same_capacity_reports_unchanged_chirho() {
    let mut registry_chirho = registry_with_upgradeable_node_chirho();
    assert_eq!(
        registry_chirho
            .advance_node_capacity_chirho(&grant_for_chirho(
                "node-a-chirho",
                "hetzner-chirho",
                "fsn1-chirho",
                capacity_chirho(8_000, 32 << 30, 1_024 << 30),
            ))
            .expect("restating applies"),
        CapacityAdvanceChirho::UnchangedChirho
    );
}

#[test]
fn a_re_grant_for_a_node_that_was_never_registered_refuses_chirho() {
    let mut registry_chirho = registry_with_upgradeable_node_chirho();
    assert_eq!(
        registry_chirho
            .advance_node_capacity_chirho(&grant_for_chirho(
                "node-never-registered-chirho",
                "hetzner-chirho",
                "fsn1-chirho",
                capacity_chirho(16_000, 64 << 30, 2_048 << 30),
            ))
            .expect_err("unknown node"),
        CapacityAdvanceRefusalChirho::UnknownNodeChirho {
            node_id_chirho: "node-never-registered-chirho".to_string(),
        }
    );
}
