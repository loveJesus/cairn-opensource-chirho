// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! CF8 clause 8's egress half: a PRICED affinity that can never become a hard capacity dimension.
//!
//! The clause splits into two claims that fail in opposite directions, so each gets its own arm.
//! *Priced* fails if an expensive node is silently preferred; *not a capacity dimension* fails if an
//! expensive node is refused outright. The arm that matters most is
//! [`an_egress_affinity_changes_score_but_never_eligibility_chirho`], because that is the one a
//! future "just make egress a hard constraint" change would break.

use super::*;
use cairn_core_chirho::model_chirho::HashChirho;

fn candidate_chirho(name_chirho: &str, egress_chirho: Option<u64>) -> PlacementCandidateChirho {
    PlacementCandidateChirho {
        candidate_chirho: name_chirho.to_string(),
        region_chirho: "eu-central-chirho".to_string(),
        hardware_chirho: Vec::new(),
        features_chirho: Vec::new(),
        resident_modules_chirho: Vec::new(),
        user_caches_chirho: Vec::new(),
        resident_models_chirho: Vec::new(),
        data_regions_chirho: Vec::new(),
        accelerators_chirho: Vec::new(),
        egress_price_micros_per_gib_chirho: egress_chirho,
    }
}

fn descriptor_with_ceiling_chirho(ceiling_chirho: u64) -> PlacementDescriptorChirho {
    PlacementDescriptorChirho {
        module_chirho: HashChirho("a".repeat(64)),
        hard_constraints_chirho: Vec::new(),
        affinities_chirho: vec![PlacementAffinityChirho {
            kind_chirho: PlacementAffinityKindChirho::EgressPriceCeilingChirho {
                max_micros_per_gib_chirho: ceiling_chirho,
            },
            weight_chirho: 40,
        }],
        metadata_chirho: BTreeMap::new(),
    }
}

fn score_of_chirho(scores_chirho: &[PlacementCandidateScoreChirho], name_chirho: &str) -> i64 {
    scores_chirho
        .iter()
        .find(|score_chirho| score_chirho.candidate_chirho == name_chirho)
        .unwrap_or_else(|| panic!("candidate {name_chirho} is missing from the ranking"))
        .score_chirho
}

#[test]
fn a_candidate_at_or_below_the_ceiling_earns_the_affinity_chirho() {
    let scores_chirho = rank_placement_candidates_chirho(
        &descriptor_with_ceiling_chirho(500),
        &[
            candidate_chirho("cheap-chirho", Some(100)),
            candidate_chirho("exactly-at-chirho", Some(500)),
        ],
    )
    .expect("rank candidates");
    assert_eq!(score_of_chirho(&scores_chirho, "cheap-chirho"), 40);
    // At the ceiling is within it: a price ceiling is a limit, not a strict inequality.
    assert_eq!(score_of_chirho(&scores_chirho, "exactly-at-chirho"), 40);
}

#[test]
fn a_candidate_above_the_ceiling_earns_nothing_chirho() {
    let scores_chirho = rank_placement_candidates_chirho(
        &descriptor_with_ceiling_chirho(500),
        &[candidate_chirho("pricey-chirho", Some(501))],
    )
    .expect("rank candidates");
    assert_eq!(score_of_chirho(&scores_chirho, "pricey-chirho"), 0);
}

#[test]
fn an_unmeasured_egress_price_never_earns_the_affinity_chirho() {
    // The clause refuses to let "unmeasured" stand in for "cheap". A candidate that has reported no
    // price must rank BELOW one measured under the ceiling, never level with it.
    let scores_chirho = rank_placement_candidates_chirho(
        &descriptor_with_ceiling_chirho(500),
        &[
            candidate_chirho("unmeasured-chirho", None),
            candidate_chirho("measured-cheap-chirho", Some(100)),
        ],
    )
    .expect("rank candidates");
    assert_eq!(score_of_chirho(&scores_chirho, "unmeasured-chirho"), 0);
    assert!(
        score_of_chirho(&scores_chirho, "unmeasured-chirho")
            < score_of_chirho(&scores_chirho, "measured-cheap-chirho"),
        "an unmeasured price must not rank level with a measured cheap one"
    );
}

#[test]
fn an_egress_affinity_changes_score_but_never_eligibility_chirho() {
    // THE clause claim: egress is a priced affinity, not a hard capacity dimension. An arbitrarily
    // expensive candidate still stands for election; it merely ranks lower.
    let scores_chirho = rank_placement_candidates_chirho(
        &descriptor_with_ceiling_chirho(10),
        &[
            candidate_chirho("ruinously-expensive-chirho", Some(u64::MAX)),
            candidate_chirho("unmeasured-chirho", None),
        ],
    )
    .expect("rank candidates");
    for score_chirho in &scores_chirho {
        assert!(
            score_chirho.eligible_chirho,
            "egress price must never make {} ineligible — that would make it a hard capacity \
             dimension, which clause 8 forbids",
            score_chirho.candidate_chirho
        );
        assert!(
            score_chirho.violations_chirho.is_empty(),
            "egress price must never produce a hard-constraint violation"
        );
    }
}

#[test]
fn egress_is_absent_from_the_hard_capacity_dimensions_chirho() {
    // The negative half, pinned where a future author would add a fourth dimension.
    use crate::capacity_chirho::capacity_dominance_chirho::CAPACITY_DIMENSIONS_CHIRHO;
    assert_eq!(
        CAPACITY_DIMENSIONS_CHIRHO.len(),
        3,
        "egress must stay a priced affinity; adding it as a hard capacity dimension is exactly what \
         clause 8 rules out"
    );
}

#[test]
fn a_zero_egress_ceiling_is_refused_as_a_field_error_chirho() {
    // Zero is the value that arrives by default-initialisation, and it would silently mean "nothing
    // can ever qualify" — so it is refused rather than quietly accepted.
    let error_chirho =
        validate_placement_descriptor_fields_chirho(&descriptor_with_ceiling_chirho(0))
            .expect_err("a zero ceiling must refuse");
    assert!(
        error_chirho.to_string().contains("greater than zero"),
        "the refusal should name the rule, got: {error_chirho}"
    );
}
