// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Scaling twins: a node's cost tracks ITS assigned placements, never the fleet's global count.
//!
//! CF8 acceptance, verbatim: *"scaling twins prove per-node durable bytes and active memory scale with
//! **assigned placements** rather than global app/user count."*
//!
//! **Why twins rather than a benchmark.** A timing or allocation measurement would answer "is it fast
//! enough today", which drifts with hardware and tells you nothing about the shape of the growth. A
//! twin answers the structural question instead: **build two registries that differ ONLY in global
//! scale, and require the per-node answer to be byte-identical.** If a node's reserved capacity ever
//! depended on the fleet's size, these twins diverge — and they diverge by an exact value, not by a
//! threshold someone has to argue about.
//!
//! The three claims each get a twin:
//! 1. **Derived reserved capacity** is a function of the node's own placements alone.
//! 2. **Admission decisions** are unchanged by unrelated fleet growth.
//! 3. **Per-node retained state** (what the registry holds *for that node*) grows with its own
//!    placements and is flat in the global count — the "active memory" half of the criterion, measured
//!    structurally as retained rows rather than as bytes of RSS, which is the honest thing a pure
//!    domain layer can claim.
//!
//! **The twins are only meaningful with a positive control**, so each includes the *other* direction:
//! adding placements to the node under test MUST change its answer. A pair of tests where both sides
//! are constant would pass for a system that ignores placements entirely.

use super::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use super::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho;
use super::capacity_chirho::reserved_capacity_chirho::PlacedDemandChirho;
use super::failure_domain_chirho::FailureDomainChirho;
use super::node_lifecycle_chirho::NodeLifecycleStateChirho;
use super::placement_registry_chirho::{PlacementRegistryChirho, RegisteredNodeChirho};

const SUBJECT_CHIRHO: &str = "subject-node-chirho";

fn capacity_chirho(c_chirho: u64, m_chirho: u64, d_chirho: u64) -> AllocatableCapacityChirho {
    AllocatableCapacityChirho {
        cpu_millicores_chirho: c_chirho,
        memory_bytes_chirho: m_chirho,
        durable_bytes_chirho: d_chirho,
    }
}

fn node_chirho(id_chirho: &str) -> RegisteredNodeChirho {
    let mut node_chirho = RegisteredNodeChirho::unattested_for_test_chirho(
        id_chirho.to_string(),
        FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fsn1-chirho".to_string(),
        },
        capacity_chirho(64_000, 256 << 30, 8_192 << 30),
        NodeLifecycleStateChirho::JoinedChirho,
    );
    node_chirho.set_measurement_for_test_chirho(Some(MeasurementStampChirho {
        hlc_millis_chirho: 1_000,
        sequence_chirho: 7,
    }));
    node_chirho
}

fn demand_chirho(id_chirho: &str) -> PlacedDemandChirho {
    PlacedDemandChirho {
        placement_id_chirho: id_chirho.to_string(),
        demand_chirho: capacity_chirho(10, 1 << 20, 1 << 20),
    }
}

/// A registry holding the subject node with `own_chirho` placements, plus `global_chirho` placements
/// spread across OTHER nodes — the only axis the twins differ on.
fn registry_chirho(own_chirho: usize, global_chirho: usize) -> PlacementRegistryChirho {
    let mut registry_chirho = PlacementRegistryChirho::new_chirho();
    registry_chirho.upsert_node_chirho(node_chirho(SUBJECT_CHIRHO));
    for i_chirho in 0..own_chirho {
        registry_chirho
            .record_placement_chirho(SUBJECT_CHIRHO, demand_chirho(&format!("own-{i_chirho}")));
    }
    for i_chirho in 0..global_chirho {
        let other_chirho = format!("other-{}-chirho", i_chirho % 50);
        registry_chirho.upsert_node_chirho(node_chirho(&other_chirho));
        registry_chirho
            .record_placement_chirho(&other_chirho, demand_chirho(&format!("global-{i_chirho}")));
    }
    registry_chirho
}

#[test]
fn twin_reserved_capacity_is_flat_in_global_fleet_size_chirho() {
    // TWIN: identical own-placements, wildly different global scale.
    let small_chirho = registry_chirho(3, 0);
    let huge_chirho = registry_chirho(3, 5_000);
    assert_eq!(
        small_chirho.reserved_for_chirho(SUBJECT_CHIRHO),
        huge_chirho.reserved_for_chirho(SUBJECT_CHIRHO),
        "a node's reserved capacity must not move when the FLEET grows"
    );
}

#[test]
fn positive_control_reserved_capacity_does_track_its_own_placements_chirho() {
    // Without this, the twin above would also pass for a registry that ignores placements entirely.
    assert_ne!(
        registry_chirho(3, 0).reserved_for_chirho(SUBJECT_CHIRHO),
        registry_chirho(9, 0).reserved_for_chirho(SUBJECT_CHIRHO),
        "reserved MUST move when the node's OWN placements change"
    );
}

#[test]
fn twin_admission_is_unchanged_by_unrelated_fleet_growth_chirho() {
    let demand_chirho = capacity_chirho(1_000, 4 << 30, 64 << 30);
    let headroom_chirho = capacity_chirho(100, 1 << 30, 1 << 30);
    let stamp_chirho = MeasurementStampChirho {
        hlc_millis_chirho: 2_000,
        sequence_chirho: 8,
    };
    let small_chirho = registry_chirho(2, 0).placement_refusals_chirho(
        SUBJECT_CHIRHO,
        &demand_chirho,
        &headroom_chirho,
        stamp_chirho,
    );
    let huge_chirho = registry_chirho(2, 5_000).placement_refusals_chirho(
        SUBJECT_CHIRHO,
        &demand_chirho,
        &headroom_chirho,
        stamp_chirho,
    );
    assert_eq!(
        small_chirho, huge_chirho,
        "an admission decision must not depend on how many placements exist elsewhere"
    );
    assert!(
        small_chirho.is_empty(),
        "the fixture must be admissible, or this twin compares two refusals and proves nothing"
    );
}

#[test]
fn twin_per_node_retained_state_is_flat_in_global_size_and_grows_with_its_own_chirho() {
    // The "active memory" half, measured structurally as RETAINED ROWS FOR THIS NODE rather than as
    // bytes of RSS — the honest thing a pure domain layer can claim, and the quantity the criterion
    // actually names ("scale with assigned placements").
    assert_eq!(
        registry_chirho(3, 0).placement_count_for_chirho(SUBJECT_CHIRHO),
        registry_chirho(3, 5_000).placement_count_for_chirho(SUBJECT_CHIRHO),
        "per-node retained rows must be identical across a 5,000-placement fleet difference"
    );
    // And the same measure must be SENSITIVE to the node's own load, or it measures nothing.
    assert_ne!(
        registry_chirho(3, 0).placement_count_for_chirho(SUBJECT_CHIRHO),
        registry_chirho(400, 0).placement_count_for_chirho(SUBJECT_CHIRHO),
        "the same measure must move with the node's OWN placements"
    );
}
