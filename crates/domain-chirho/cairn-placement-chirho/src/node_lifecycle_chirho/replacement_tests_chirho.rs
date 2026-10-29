// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The candidate joins before the incumbent drains, and a non-dominating candidate is refused.

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

fn features_chirho(labels_chirho: &[&str]) -> BTreeSet<String> {
    labels_chirho
        .iter()
        .map(|l_chirho| (*l_chirho).to_string())
        .collect()
}

#[test]
fn the_candidate_joins_before_the_incumbent_drains_chirho() {
    // THE COMPOSITION INVARIANT. Drain-then-join is the intuitive order and it is wrong: it leaves
    // the cluster short by one node for the whole provision-and-inspect window. If this assertion is
    // ever "fixed" by reordering, capacity dips during every replacement.
    let join_chirho = REPLACEMENT_PLAN_CHIRHO
        .iter()
        .position(|s_chirho| *s_chirho == ReplacementStepChirho::JoinCandidateChirho)
        .expect("plan must join the candidate");
    let drain_chirho = REPLACEMENT_PLAN_CHIRHO
        .iter()
        .position(|s_chirho| *s_chirho == ReplacementStepChirho::DrainIncumbentChirho)
        .expect("plan must drain the incumbent");
    let retire_chirho = REPLACEMENT_PLAN_CHIRHO
        .iter()
        .position(|s_chirho| *s_chirho == ReplacementStepChirho::RetireIncumbentChirho)
        .expect("plan must retire the incumbent");
    assert!(
        join_chirho < drain_chirho,
        "the candidate must be SERVING before the incumbent stops taking work"
    );
    assert!(drain_chirho < retire_chirho, "drain precedes retire");
}

#[test]
fn a_dominating_candidate_yields_the_fixed_plan_chirho() {
    let plan_chirho = plan_replacement_chirho(
        &capacity_chirho(4_000, 16 << 30, 512 << 30),
        &features_chirho(&["nvme-chirho"]),
        &capacity_chirho(8_000, 32 << 30, 1_024 << 30),
        &features_chirho(&["nvme-chirho", "gpu-chirho"]),
    )
    .expect("a dominating candidate with the required feature is admissible");
    assert_eq!(plan_chirho, REPLACEMENT_PLAN_CHIRHO);
}

#[test]
fn a_candidate_short_in_one_dimension_is_refused_with_that_dimension_named_chirho() {
    // The dominance rule's whole point, reached through replace: a candidate with far more CPU and
    // storage but less memory sheds memory capacity silently under any "better overall" test.
    let refusals_chirho = plan_replacement_chirho(
        &capacity_chirho(4_000, 16 << 30, 512 << 30),
        &features_chirho(&[]),
        &capacity_chirho(400_000, (16 << 30) - 1, 51_200 << 30),
        &features_chirho(&[]),
    )
    .expect_err("a candidate short in any dimension is not a replacement");
    assert_eq!(
        refusals_chirho,
        vec![ReplacementRefusalChirho::DimensionShortfallChirho {
            dimension_chirho: CapacityDimensionChirho::MemoryBytesChirho,
            incumbent_chirho: 16 << 30,
            candidate_chirho: (16 << 30) - 1,
        }]
    );
}

#[test]
fn a_candidate_missing_a_required_feature_is_refused_chirho() {
    let refusals_chirho = plan_replacement_chirho(
        &capacity_chirho(4_000, 16 << 30, 512 << 30),
        &features_chirho(&["gpu-chirho"]),
        &capacity_chirho(64_000, 256 << 30, 8_192 << 30),
        &features_chirho(&[]),
    )
    .expect_err("size never substitutes for a missing feature");
    assert_eq!(
        refusals_chirho,
        vec![ReplacementRefusalChirho::MissingRequiredFeatureChirho {
            feature_chirho: "gpu-chirho".to_string(),
        }]
    );
}

#[test]
fn draining_the_incumbent_is_refused_until_the_candidate_has_joined_chirho() {
    // The same invariant enforced against an operator working the steps by hand, rather than only
    // expressed in the plan's order — a manual adapter is exactly where out-of-order execution
    // happens.
    assert!(!incumbent_safe_to_drain_chirho(&[]));
    assert!(!incumbent_safe_to_drain_chirho(&[
        ReplacementStepChirho::ProvisionCandidateChirho,
        ReplacementStepChirho::InspectCandidateChirho,
    ]));
    assert!(incumbent_safe_to_drain_chirho(&[
        ReplacementStepChirho::ProvisionCandidateChirho,
        ReplacementStepChirho::InspectCandidateChirho,
        ReplacementStepChirho::JoinCandidateChirho,
    ]));
}

#[test]
fn an_equal_candidate_still_replaces_chirho() {
    // Replacement is not required to be an UPGRADE — swapping failing hardware for identical
    // hardware is a legitimate replace, and dominance is `>=` for exactly this case.
    let same_chirho = capacity_chirho(4_000, 16 << 30, 512 << 30);
    assert!(plan_replacement_chirho(
        &same_chirho,
        &features_chirho(&[]),
        &same_chirho,
        &features_chirho(&[])
    )
    .is_ok());
}
