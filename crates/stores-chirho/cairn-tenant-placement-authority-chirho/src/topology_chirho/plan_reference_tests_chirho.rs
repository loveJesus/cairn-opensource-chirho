// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for resolving a signed plan reference.
//!
//! The control comes first, because a verifier that refused every reference would make all four
//! negative arms pass while proving nothing.
//!
//! **Two arms assert a refusal is NOT the absent refusal, and they are the reason this module exists.**
//! The obvious implementation collapses unreadable and mismatched into "absent" and looks correct; a
//! two-case arm set cannot tell the difference. These are the third and fourth cases.

use super::*;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::{
    NodeRoleChirho, PlannedNodeChirho,
};

fn plan_chirho(provider_chirho: &str) -> DesiredTopologyPlanChirho {
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "grant-a-chirho".to_string(),
        nodes_chirho: vec![PlannedNodeChirho {
            provider_chirho: provider_chirho.to_string(),
            role_chirho: NodeRoleChirho::ControlChirho,
        }],
        spend_rate_micros_per_hour_chirho: 100_000,
        proposed_grant_chirho: None,
    }
}

/// Answers with one fixed outcome, whatever it is asked.
struct FixedResolverChirho {
    outcome_chirho: TopologyPlanResolutionChirho,
}

impl TopologyPlanResolverPortChirho for FixedResolverChirho {
    fn resolve_plan_chirho(&self, _digest_chirho: &str) -> TopologyPlanResolutionChirho {
        self.outcome_chirho.clone()
    }
}

/// Panics if consulted. Proves the shape check runs BEFORE any resolution is attempted.
struct NeverConsultedResolverChirho;

impl TopologyPlanResolverPortChirho for NeverConsultedResolverChirho {
    fn resolve_plan_chirho(&self, _digest_chirho: &str) -> TopologyPlanResolutionChirho {
        panic!("the resolver must not be consulted for a malformed digest");
    }
}

fn found_chirho(plan_chirho: DesiredTopologyPlanChirho) -> FixedResolverChirho {
    FixedResolverChirho {
        outcome_chirho: TopologyPlanResolutionChirho::FoundChirho(Box::new(plan_chirho)),
    }
}

#[test]
fn a_resolved_plan_that_rehashes_to_its_digest_verifies_chirho() {
    let plan_chirho = plan_chirho("hetzner-chirho");
    let digest_chirho = plan_hash_chirho(&plan_chirho).0;
    let verified_chirho =
        verify_topology_plan_reference_chirho(&digest_chirho, &found_chirho(plan_chirho.clone()))
            .expect("a plan that resolves and re-hashes must verify");
    assert_eq!(verified_chirho.digest_chirho(), digest_chirho);
    assert_eq!(verified_chirho.plan_chirho(), &plan_chirho);
}

#[test]
fn a_well_formed_digest_naming_nothing_refuses_as_absent_chirho() {
    // The dangling reference the design doc describes: shape passes, referent does not exist. Before
    // this module, this was ACCEPTED.
    let digest_chirho = "a".repeat(64);
    let refusal_chirho = verify_topology_plan_reference_chirho(
        &digest_chirho,
        &FixedResolverChirho {
            outcome_chirho: TopologyPlanResolutionChirho::AbsentChirho,
        },
    )
    .expect_err("a digest naming nothing must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::PlanAbsentChirho { .. }
        ),
        "expected PlanAbsent, got {refusal_chirho:?}"
    );
}

#[test]
fn an_unreadable_plan_refuses_as_unreadable_and_not_as_absent_chirho() {
    // THE THIRD CASE. Present-but-unreadable is fail-closed; absent is a miss. An implementation that
    // folded this into AbsentChirho would pass a two-case arm set and rescue a corrupt object.
    let digest_chirho = "b".repeat(64);
    let refusal_chirho = verify_topology_plan_reference_chirho(
        &digest_chirho,
        &FixedResolverChirho {
            outcome_chirho: TopologyPlanResolutionChirho::UnreadableChirho,
        },
    )
    .expect_err("an unreadable plan must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::PlanUnreadableChirho { .. }
        ),
        "expected PlanUnreadable, got {refusal_chirho:?}"
    );
    assert!(
        !matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::PlanAbsentChirho { .. }
        ),
        "present-but-unreadable must NEVER take the absent path"
    );
}

#[test]
fn a_substituted_plan_refuses_on_the_rehash_and_not_as_absent_chirho() {
    // A resolver that returns SOME plan for the digest — just not the one the digest names. The
    // re-hash is the only thing that catches this, which is why it is not optional.
    let declared_chirho = plan_hash_chirho(&plan_chirho("hetzner-chirho")).0;
    let refusal_chirho = verify_topology_plan_reference_chirho(
        &declared_chirho,
        &found_chirho(plan_chirho("ovh-chirho")),
    )
    .expect_err("a substituted plan must refuse");
    match &refusal_chirho {
        TopologyPlanReferenceRefusalChirho::PlanDigestMismatchChirho {
            declared_chirho: d_chirho,
            recomputed_chirho,
        } => {
            assert_eq!(d_chirho, &declared_chirho);
            assert_ne!(recomputed_chirho, &declared_chirho);
        }
        other_chirho => panic!("expected PlanDigestMismatch, got {other_chirho:?}"),
    }
    assert!(
        !matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::PlanAbsentChirho { .. }
        ),
        "a substituted plan is present and wrong, never absent"
    );
}

#[test]
fn a_malformed_digest_refuses_before_the_resolver_is_consulted_chirho() {
    // Order is a contract: shape first. The resolver panics if reached, so this arm fails loudly
    // rather than silently if the order is ever inverted.
    let refusal_chirho =
        verify_topology_plan_reference_chirho("NOT-HEX-chirho", &NeverConsultedResolverChirho)
            .expect_err("a malformed digest must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::MalformedDigestChirho { .. }
        ),
        "expected MalformedDigest, got {refusal_chirho:?}"
    );
}

#[test]
fn shape_alone_is_not_resolution_chirho() {
    // The claim the module exists to make, stated as an arm: the crate's existing lower-hex check
    // accepts a digest that resolves to nothing, so passing it proves only that the field is
    // well-formed.
    let dangling_chirho = "c".repeat(64);
    assert!(
        crate::is_lower_hex_digest_chirho(&dangling_chirho),
        "the existing shape check accepts this digest"
    );
    assert!(
        verify_topology_plan_reference_chirho(
            &dangling_chirho,
            &FixedResolverChirho {
                outcome_chirho: TopologyPlanResolutionChirho::AbsentChirho,
            },
        )
        .is_err(),
        "and resolution rejects it — shape and resolution are different claims"
    );
}

#[test]
fn a_tampered_object_refuses_as_tampered_and_not_as_absent_or_unreadable_chirho() {
    // THE FOURTH CASE, and it exists because cas_chirho can already tell it apart: bytes filed under
    // an address they do not produce read FINE and are wrong. Collapsing this into unreadable would
    // be the same mistake one notch further along.
    let digest_chirho = "d".repeat(64);
    let refusal_chirho = verify_topology_plan_reference_chirho(
        &digest_chirho,
        &FixedResolverChirho {
            outcome_chirho: TopologyPlanResolutionChirho::TamperedChirho,
        },
    )
    .expect_err("a tampered object must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::PlanTamperedChirho { .. }
        ),
        "expected PlanTampered, got {refusal_chirho:?}"
    );
    assert!(
        !matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::PlanAbsentChirho { .. }
                | TopologyPlanReferenceRefusalChirho::PlanUnreadableChirho { .. }
        ),
        "tampered is neither absent nor unreadable — it read fine and is wrong"
    );
}
