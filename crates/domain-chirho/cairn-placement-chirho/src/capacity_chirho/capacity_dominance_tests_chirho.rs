// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The dominance rule's three commitments, one test each — plus the anti-scalar test that is the
//! whole point of the criterion.

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

fn features_chirho(labels_chirho: &[&str]) -> BTreeSet<String> {
    labels_chirho
        .iter()
        .map(|label_chirho| (*label_chirho).to_string())
        .collect()
}

#[test]
fn an_equal_node_dominates_because_replacement_is_not_strict_improvement_chirho() {
    let incumbent_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    let none_chirho = features_chirho(&[]);
    assert!(replacement_dominates_chirho(
        &incumbent_chirho,
        &incumbent_chirho,
        &none_chirho,
        &none_chirho
    ));
}

#[test]
fn a_strictly_larger_node_dominates_chirho() {
    let incumbent_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    let candidate_chirho = capacity_chirho(8_000, 32 << 30, 1024 << 30);
    let none_chirho = features_chirho(&[]);
    assert!(replacement_dominates_chirho(
        &incumbent_chirho,
        &candidate_chirho,
        &none_chirho,
        &none_chirho
    ));
}

#[test]
fn a_shortfall_in_any_single_dimension_refuses_and_names_it_chirho() {
    let incumbent_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    let none_chirho = features_chirho(&[]);
    // One dimension short at a time; each must refuse, naming that dimension and both numbers.
    for (candidate_chirho, expected_chirho) in [
        (
            capacity_chirho(3_999, 16 << 30, 512 << 30),
            CapacityDimensionChirho::CpuMillicoresChirho,
        ),
        (
            capacity_chirho(4_000, (16 << 30) - 1, 512 << 30),
            CapacityDimensionChirho::MemoryBytesChirho,
        ),
        (
            capacity_chirho(4_000, 16 << 30, (512 << 30) - 1),
            CapacityDimensionChirho::DurableBytesChirho,
        ),
    ] {
        let refusals_chirho = replacement_refusals_chirho(
            &incumbent_chirho,
            &candidate_chirho,
            &none_chirho,
            &none_chirho,
        );
        assert_eq!(
            refusals_chirho.len(),
            1,
            "exactly one dimension is short for {expected_chirho:?}"
        );
        match &refusals_chirho[0] {
            ReplacementRefusalChirho::DimensionShortfallChirho {
                dimension_chirho,
                incumbent_chirho: incumbent_value_chirho,
                candidate_chirho: candidate_value_chirho,
            } => {
                assert_eq!(*dimension_chirho, expected_chirho);
                assert!(candidate_value_chirho < incumbent_value_chirho);
            }
            other_chirho => panic!("expected a dimension shortfall, got {other_chirho:?}"),
        }
    }
}

#[test]
fn a_huge_surplus_cannot_pay_for_a_one_byte_deficit_chirho() {
    // THE POINT OF THE CRITERION. This candidate is 100x the CPU and 100x the durable storage, and
    // is short exactly ONE BYTE of memory. Any scalar strength score — any weighted sum, any ratio,
    // any "overall better" — would accept it. Dominance refuses it, because there is no exchange
    // rate between millicores and bytes. If this test ever goes green while the numbers below are
    // unchanged, the rule has collapsed into a score and the criterion is lost.
    let incumbent_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    let candidate_chirho = capacity_chirho(400_000, (16 << 30) - 1, 51_200 << 30);
    let none_chirho = features_chirho(&[]);

    let refusals_chirho = replacement_refusals_chirho(
        &incumbent_chirho,
        &candidate_chirho,
        &none_chirho,
        &none_chirho,
    );
    assert_eq!(
        refusals_chirho,
        vec![ReplacementRefusalChirho::DimensionShortfallChirho {
            dimension_chirho: CapacityDimensionChirho::MemoryBytesChirho,
            incumbent_chirho: 16 << 30,
            candidate_chirho: (16 << 30) - 1,
        }],
        "a surplus in other dimensions must never offset a shortfall"
    );
}

#[test]
fn features_filter_rather_than_score_chirho() {
    let incumbent_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    let bigger_chirho = capacity_chirho(64_000, 256 << 30, 8_192 << 30);
    let needs_chirho = features_chirho(&["gpu-chirho", "nvme-chirho"]);

    // Missing a required feature refuses however large the candidate is.
    let refusals_chirho = replacement_refusals_chirho(
        &incumbent_chirho,
        &bigger_chirho,
        &needs_chirho,
        &features_chirho(&["nvme-chirho"]),
    );
    assert_eq!(
        refusals_chirho,
        vec![ReplacementRefusalChirho::MissingRequiredFeatureChirho {
            feature_chirho: "gpu-chirho".to_string(),
        }]
    );

    // Extra features are free — containment, not equality.
    assert!(replacement_dominates_chirho(
        &incumbent_chirho,
        &bigger_chirho,
        &needs_chirho,
        &features_chirho(&["gpu-chirho", "nvme-chirho", "sgx-chirho"]),
    ));
}

#[test]
fn every_failing_dimension_is_reported_not_just_the_first_chirho() {
    // An operator replacing a node needs the whole bill, not one line of it.
    let incumbent_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    let smaller_chirho = capacity_chirho(1_000, 4 << 30, 128 << 30);
    let needs_chirho = features_chirho(&["gpu-chirho"]);
    let refusals_chirho = replacement_refusals_chirho(
        &incumbent_chirho,
        &smaller_chirho,
        &needs_chirho,
        &features_chirho(&[]),
    );
    assert_eq!(
        refusals_chirho.len(),
        4,
        "three dimensions plus one feature: {refusals_chirho:?}"
    );
    // Deterministic order, so refusal text is stable across runs.
    let dimensions_chirho = refusals_chirho
        .iter()
        .filter_map(|refusal_chirho| match refusal_chirho {
            ReplacementRefusalChirho::DimensionShortfallChirho {
                dimension_chirho, ..
            } => Some(*dimension_chirho),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(dimensions_chirho, CAPACITY_DIMENSIONS_CHIRHO.to_vec());
}

#[test]
fn dimension_labels_are_distinct_and_unit_bearing_chirho() {
    // Refusals reach operators; a label that does not say its unit invites the wrong fix.
    let labels_chirho = CAPACITY_DIMENSIONS_CHIRHO
        .iter()
        .map(|dimension_chirho| dimension_chirho.label_chirho())
        .collect::<BTreeSet<_>>();
    assert_eq!(labels_chirho.len(), CAPACITY_DIMENSIONS_CHIRHO.len());
    assert!(labels_chirho.iter().all(|label_chirho| {
        label_chirho.contains("millicores") || label_chirho.contains("bytes")
    }));
}
