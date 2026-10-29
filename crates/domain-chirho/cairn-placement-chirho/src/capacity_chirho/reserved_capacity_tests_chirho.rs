// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Derivation is deterministic and unwrappable; admission respects headroom per dimension.

use super::*;

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

fn placed_chirho(id_chirho: &str, demand_chirho: AllocatableCapacityChirho) -> PlacedDemandChirho {
    PlacedDemandChirho {
        placement_id_chirho: id_chirho.to_string(),
        demand_chirho,
    }
}

#[test]
fn reserved_is_the_sum_of_placed_demands_chirho() {
    let placed_list_chirho = vec![
        placed_chirho("a-chirho", capacity_chirho(1_000, 2 << 30, 10 << 30)),
        placed_chirho("b-chirho", capacity_chirho(500, 1 << 30, 5 << 30)),
    ];
    assert_eq!(
        derive_reserved_capacity_chirho(&placed_list_chirho),
        capacity_chirho(1_500, 3 << 30, 15 << 30)
    );
}

#[test]
fn an_empty_registry_reserves_nothing_chirho() {
    assert_eq!(
        derive_reserved_capacity_chirho(&[]),
        capacity_chirho(0, 0, 0)
    );
}

#[test]
fn derivation_is_order_independent_chirho() {
    // Two holders of the same registry must derive the same reserved figure regardless of
    // iteration order, or they will disagree about what fits.
    let a_chirho = placed_chirho("a-chirho", capacity_chirho(1_000, 2 << 30, 10 << 30));
    let b_chirho = placed_chirho("b-chirho", capacity_chirho(500, 1 << 30, 5 << 30));
    let c_chirho = placed_chirho("c-chirho", capacity_chirho(250, 4 << 30, 1 << 30));
    let forward_chirho =
        derive_reserved_capacity_chirho(&[a_chirho.clone(), b_chirho.clone(), c_chirho.clone()]);
    let reversed_chirho = derive_reserved_capacity_chirho(&[c_chirho, b_chirho, a_chirho]);
    assert_eq!(forward_chirho, reversed_chirho);
}

#[test]
fn a_corrupt_registry_cannot_wrap_reserved_into_looking_empty_chirho() {
    // THE HAZARD: if the sum wrapped, two enormous rows would derive a TINY reserved figure and the
    // node would look almost free — manufacturing capacity out of an overflow. Saturation fails
    // toward "full", which refuses admission.
    let placed_list_chirho = vec![
        placed_chirho(
            "huge-a-chirho",
            capacity_chirho(u64::MAX, u64::MAX, u64::MAX),
        ),
        placed_chirho(
            "huge-b-chirho",
            capacity_chirho(u64::MAX, u64::MAX, u64::MAX),
        ),
    ];
    let reserved_chirho = derive_reserved_capacity_chirho(&placed_list_chirho);
    assert_eq!(
        reserved_chirho,
        capacity_chirho(u64::MAX, u64::MAX, u64::MAX),
        "the sum must saturate at the ceiling, never wrap toward zero"
    );

    // And the saturated figure must actually refuse a subsequent placement.
    let refusals_chirho = admission_refusals_chirho(
        &capacity_chirho(64_000, 256 << 30, 8_192 << 30),
        &reserved_chirho,
        &capacity_chirho(1, 1, 1),
        &capacity_chirho(0, 0, 0),
    );
    assert_eq!(refusals_chirho.len(), 3, "every dimension is exhausted");
}

#[test]
fn occupied_capacity_keeps_the_larger_signal_per_dimension_chirho() {
    let reserved_chirho = capacity_chirho(3_000, 4 << 30, 500 << 30);
    let observed_chirho = capacity_chirho(2_500, 6 << 30, 400 << 30);
    assert_eq!(
        effective_occupied_capacity_chirho(&reserved_chirho, &observed_chirho),
        capacity_chirho(3_000, 6 << 30, 500 << 30),
        "reservation and measured load must each remain able to close one dimension"
    );
}

#[test]
fn over_reservation_reads_as_zero_free_not_as_a_huge_number_chirho() {
    // A node that shrank can carry reserved above allocatable. Free must floor at zero; an
    // underflow here would wrap to ~u64::MAX and admit everything.
    let free_chirho = free_in_dimension_chirho(
        &capacity_chirho(1_000, 1 << 30, 1 << 30),
        &capacity_chirho(4_000, 8 << 30, 8 << 30),
        CapacityDimensionChirho::CpuMillicoresChirho,
    );
    assert_eq!(free_chirho, 0);
}

#[test]
fn admission_requires_headroom_beyond_the_demand_chirho() {
    let allocatable_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    let reserved_chirho = capacity_chirho(3_000, 12 << 30, 256 << 30);
    // Free is exactly 1_000 / 4Gi / 256Gi.
    let demand_chirho = capacity_chirho(1_000, 4 << 30, 256 << 30);

    // With no headroom the demand fits exactly.
    assert!(admission_refusals_chirho(
        &allocatable_chirho,
        &reserved_chirho,
        &demand_chirho,
        &capacity_chirho(0, 0, 0)
    )
    .is_empty());

    // One millicore of headroom makes it not fit — headroom is required, not advisory.
    let refusals_chirho = admission_refusals_chirho(
        &allocatable_chirho,
        &reserved_chirho,
        &demand_chirho,
        &capacity_chirho(1, 0, 0),
    );
    assert_eq!(
        refusals_chirho,
        vec![AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
            dimension_chirho: CapacityDimensionChirho::CpuMillicoresChirho,
            free_chirho: 1_000,
            demand_chirho: 1_000,
            headroom_chirho: 1,
        }]
    );
}

#[test]
fn a_surplus_in_one_dimension_never_pays_for_a_shortage_in_another_chirho() {
    // The same no-exchange-rate rule as capacity dominance. This node has enormous free memory and
    // durable storage and is one millicore short of CPU; any pooled or scored admission accepts it.
    let allocatable_chirho = capacity_chirho(1_000, 1_024 << 30, 65_536 << 30);
    let reserved_chirho = capacity_chirho(0, 0, 0);
    let demand_chirho = capacity_chirho(1_001, 1 << 30, 1 << 30);
    let refusals_chirho = admission_refusals_chirho(
        &allocatable_chirho,
        &reserved_chirho,
        &demand_chirho,
        &capacity_chirho(0, 0, 0),
    );
    assert_eq!(
        refusals_chirho,
        vec![AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
            dimension_chirho: CapacityDimensionChirho::CpuMillicoresChirho,
            free_chirho: 1_000,
            demand_chirho: 1_001,
            headroom_chirho: 0,
        }]
    );
}

#[test]
fn an_absurd_headroom_refuses_rather_than_wrapping_into_acceptance_chirho() {
    // demand + headroom must saturate; wrapping would turn a colossal margin into a tiny
    // requirement and admit the placement.
    let refusals_chirho = admission_refusals_chirho(
        &capacity_chirho(64_000, 256 << 30, 8_192 << 30),
        &capacity_chirho(0, 0, 0),
        &capacity_chirho(u64::MAX, 1, 1),
        &capacity_chirho(u64::MAX, 0, 0),
    );
    assert!(
        refusals_chirho.iter().any(|refusal_chirho| matches!(
            refusal_chirho,
            AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
                dimension_chirho: CapacityDimensionChirho::CpuMillicoresChirho,
                ..
            }
        )),
        "saturating demand+headroom must refuse, not wrap: {refusals_chirho:?}"
    );
}

/// Each dimension is measured in ITS OWN units — the clause's *"placement demand uses the same
/// units"*, asserted on the two dimensions nothing else reaches.
///
/// Measured 2026-08-21: all six `InsufficientFreeCapacityChirho` assertions in this crate name
/// `CpuMillicoresChirho`. **Zero named memory or durable.** So two thirds of the admission decision
/// were never asserted, and a unit confusion there — reading the CPU demand while checking bytes, the
/// classic copy-paste in a hand-unrolled dimension check — passed every test. Mutation-confirmed:
/// substituting `CAPACITY_DIMENSIONS_CHIRHO[0]` for the loop's own dimension when reading demand left
/// the whole suite GREEN.
///
/// The loop being generic over the dimension is exactly what makes this easy to miss: genericity
/// makes the code LOOK uniformly covered while the arms only ever exercise one arm of it. The sibling
/// no-exchange-rate arm has the same shape and is also CPU-short, so it does not reach these either.
///
/// Each case asserts the FREE and DEMAND numbers in that dimension's own magnitude — gibibytes, not
/// millicores — which is what makes a substituted unit fail rather than merely refuse differently.
#[test]
fn each_dimension_is_measured_in_its_own_units_chirho() {
    let no_headroom_chirho = capacity_chirho(0, 0, 0);
    let nothing_reserved_chirho = capacity_chirho(0, 0, 0);

    // Ample CPU and durable, one gibibyte short of MEMORY.
    let refusals_chirho = admission_refusals_chirho(
        &capacity_chirho(64_000, 4 << 30, 65_536 << 30),
        &nothing_reserved_chirho,
        &capacity_chirho(1_000, 5 << 30, 1 << 30),
        &no_headroom_chirho,
    );
    assert_eq!(
        refusals_chirho,
        vec![AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
            dimension_chirho: CapacityDimensionChirho::MemoryBytesChirho,
            free_chirho: 4 << 30,
            demand_chirho: 5 << 30,
            headroom_chirho: 0,
        }],
        "a memory shortage must refuse naming MEMORY and carrying memory-sized numbers"
    );

    // Ample CPU and memory, one gibibyte short of DURABLE.
    let refusals_chirho = admission_refusals_chirho(
        &capacity_chirho(64_000, 1_024 << 30, 8 << 30),
        &nothing_reserved_chirho,
        &capacity_chirho(1_000, 1 << 30, 9 << 30),
        &no_headroom_chirho,
    );
    assert_eq!(
        refusals_chirho,
        vec![AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
            dimension_chirho: CapacityDimensionChirho::DurableBytesChirho,
            free_chirho: 8 << 30,
            demand_chirho: 9 << 30,
            headroom_chirho: 0,
        }],
        "and a durable shortage must refuse naming DURABLE"
    );

    // HEADROOM is read per dimension too: this fits exactly without headroom and must refuse with it.
    let fits_exactly_chirho = admission_refusals_chirho(
        &capacity_chirho(64_000, 1_024 << 30, 8 << 30),
        &nothing_reserved_chirho,
        &capacity_chirho(1_000, 1 << 30, 8 << 30),
        &no_headroom_chirho,
    );
    assert!(
        fits_exactly_chirho.is_empty(),
        "control: without headroom this demand fits exactly, so the refusal below is the headroom's"
    );
    let refusals_chirho = admission_refusals_chirho(
        &capacity_chirho(64_000, 1_024 << 30, 8 << 30),
        &nothing_reserved_chirho,
        &capacity_chirho(1_000, 1 << 30, 8 << 30),
        &capacity_chirho(0, 0, 1),
    );
    assert_eq!(
        refusals_chirho,
        vec![AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
            dimension_chirho: CapacityDimensionChirho::DurableBytesChirho,
            free_chirho: 8 << 30,
            demand_chirho: 8 << 30,
            headroom_chirho: 1,
        }],
        "ONE byte of durable headroom must refuse, and in the DURABLE dimension — headroom is not \
         pooled across dimensions any more than demand is"
    );
}
