// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the root-backed plan store and its resolver.
//!
//! The centrepiece is [`a_hostile_index_row_refuses_rather_than_deceiving_chirho`]. The whole design
//! rests on the index being ALLOWED to be wrong: it is a hint, and the declared digest is the proof.
//! An arm that only checked the happy path would leave that claim untested, and the claim is what
//! justifies storing an untrusted mapping at all.

use super::*;
use crate::topology_chirho::plan_reference_chirho::{
    verify_topology_plan_reference_chirho, TopologyPlanReferenceRefusalChirho,
};
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::{
    NodeRoleChirho, PlannedNodeChirho,
};

fn plan_chirho(spend_rate_chirho: u64) -> DesiredTopologyPlanChirho {
    DesiredTopologyPlanChirho {
        cited_grant_id_chirho: "grant-a-chirho".to_string(),
        nodes_chirho: vec![PlannedNodeChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            role_chirho: NodeRoleChirho::ControlChirho,
        }],
        spend_rate_micros_per_hour_chirho: spend_rate_chirho,
        proposed_grant_chirho: None,
    }
}

fn object_path_chirho(root_chirho: &Path, address_chirho: &str) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&address_chirho[0..2])
        .join(&address_chirho[2..])
}

#[test]
fn a_stored_plan_resolves_and_reverifies_end_to_end_chirho() {
    // The positive control. Every refusal arm below would pass against a resolver that returned
    // nothing at all, so this is what makes them discriminating.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let stored_chirho = plan_chirho(1_000);
    let digest_chirho = store_topology_plan_chirho(root_chirho, &stored_chirho).expect("store");

    let verified_chirho = verify_topology_plan_reference_chirho(
        &digest_chirho,
        &RootPlanResolverChirho::new_chirho(root_chirho),
    )
    .expect("a stored plan must resolve and re-hash");
    assert_eq!(verified_chirho.digest_chirho(), digest_chirho);
    assert_eq!(verified_chirho.plan_chirho(), &stored_chirho);
}

#[test]
fn the_canonical_bytes_land_at_exactly_the_declared_digest_chirho() {
    // The identity the index log's self-containment depends on. If this ever stops holding, every
    // index row becomes a dangling 64-hex reference and migration refuses -- so the store checks it
    // and this arm checks the store.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &plan_chirho(1_000)).expect("store");
    assert!(
        object_path_chirho(root_chirho, &digest_chirho).exists(),
        "the declared digest must resolve as an object in this root"
    );
}

#[test]
fn an_unstored_digest_is_absent_not_unreadable_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    store_topology_plan_chirho(root_chirho, &plan_chirho(1_000)).expect("store");
    let other_chirho = plan_hash_chirho(&plan_chirho(9_999)).0;
    assert_eq!(
        verify_topology_plan_reference_chirho(
            &other_chirho,
            &RootPlanResolverChirho::new_chirho(root_chirho)
        )
        .expect_err("an unstored plan must refuse"),
        TopologyPlanReferenceRefusalChirho::PlanAbsentChirho {
            digest_chirho: other_chirho,
        }
    );
}

#[test]
fn a_hostile_index_row_refuses_rather_than_deceiving_chirho() {
    // THE arm, and the justification for storing an untrusted mapping at all. The index is pointed at
    // a DIFFERENT plan's serde object under the first plan's digest -- the exact substitution an
    // attacker with write access to the index would attempt. The resolver dutifully returns what the
    // row names, and the re-hash catches it. A refusal, never an acceptance.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let honest_chirho = plan_chirho(1_000);
    let honest_digest_chirho = plan_hash_chirho(&honest_chirho).0;
    let substitute_chirho = plan_chirho(9_999);
    let substitute_address_chirho =
        cairn_core_chirho::store_chirho::put_object_chirho(root_chirho, &substitute_chirho)
            .expect("store the substitute's serde object");
    // Also store the honest plan's canonical bytes, so the digest itself resolves and the ONLY thing
    // wrong is the mapping.
    cairn_core_chirho::cas_chirho::add_chirho(
        root_chirho,
        &canonical_plan_bytes_chirho(&honest_chirho),
    )
    .expect("canonical bytes");

    let row_chirho = TopologyPlanIndexRowChirho {
        plan_hash_chirho: honest_digest_chirho.clone(),
        serde_address_chirho: substitute_address_chirho.0,
    };
    let mut line_chirho = serde_json::to_vec(&row_chirho).unwrap();
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(
        &root_chirho.join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO),
        &line_chirho,
    )
    .expect("write the hostile row");

    let refusal_chirho = verify_topology_plan_reference_chirho(
        &honest_digest_chirho,
        &RootPlanResolverChirho::new_chirho(root_chirho),
    )
    .expect_err("a substituted plan must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyPlanReferenceRefusalChirho::PlanDigestMismatchChirho { .. }
        ),
        "the re-hash must catch the substitution, and by its own identity: {refusal_chirho:?}"
    );
    // Not the absent arm: the row resolved to a real, readable, correctly-addressed plan. It was
    // simply the WRONG plan, and that distinction is the one this repo has paid for before.
    assert!(!matches!(
        refusal_chirho,
        TopologyPlanReferenceRefusalChirho::PlanAbsentChirho { .. }
    ));
}

#[test]
fn a_tampered_serde_object_refuses_as_tampered_not_absent_chirho() {
    // Present-but-wrong must never take the absent path.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let digest_chirho =
        store_topology_plan_chirho(root_chirho, &plan_chirho(1_000)).expect("store");
    let serde_address_chirho =
        cairn_core_chirho::store_chirho::hash_object_chirho(&plan_chirho(1_000))
            .expect("serde address")
            .0;
    std::fs::write(
        object_path_chirho(root_chirho, &serde_address_chirho),
        b"these bytes do not hash to this address",
    )
    .expect("tamper");

    assert_eq!(
        verify_topology_plan_reference_chirho(
            &digest_chirho,
            &RootPlanResolverChirho::new_chirho(root_chirho)
        )
        .expect_err("a tampered object must refuse"),
        TopologyPlanReferenceRefusalChirho::PlanTamperedChirho {
            digest_chirho: digest_chirho.clone(),
        }
    );
}

#[test]
fn a_correctly_addressed_object_that_is_not_a_plan_is_unreadable_not_tampered_chirho() {
    // The judgement call this module makes, pinned: TAMPERED means the bytes do not produce their
    // address. These do -- they are simply not a plan -- so the honest answer is unreadable.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let honest_chirho = plan_chirho(1_000);
    let honest_digest_chirho = plan_hash_chirho(&honest_chirho).0;
    cairn_core_chirho::cas_chirho::add_chirho(
        root_chirho,
        &canonical_plan_bytes_chirho(&honest_chirho),
    )
    .expect("canonical bytes");
    let junk_address_chirho =
        cairn_core_chirho::cas_chirho::add_chirho(root_chirho, b"{\"not\":\"a plan\"}")
            .expect("store junk at its own correct address");

    let row_chirho = TopologyPlanIndexRowChirho {
        plan_hash_chirho: honest_digest_chirho.clone(),
        serde_address_chirho: junk_address_chirho.0,
    };
    let mut line_chirho = serde_json::to_vec(&row_chirho).unwrap();
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(
        &root_chirho.join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO),
        &line_chirho,
    )
    .expect("write the row");

    assert_eq!(
        verify_topology_plan_reference_chirho(
            &honest_digest_chirho,
            &RootPlanResolverChirho::new_chirho(root_chirho)
        )
        .expect_err("unparseable must refuse"),
        TopologyPlanReferenceRefusalChirho::PlanUnreadableChirho {
            digest_chirho: honest_digest_chirho,
        }
    );
}

#[test]
fn a_root_with_no_index_at_all_is_absent_not_unreadable_chirho() {
    // A root that has never stored a plan genuinely holds nothing; that is a miss, not a failure.
    let temp_chirho = tempfile::tempdir().unwrap();
    let digest_chirho = plan_hash_chirho(&plan_chirho(1_000)).0;
    assert_eq!(
        verify_topology_plan_reference_chirho(
            &digest_chirho,
            &RootPlanResolverChirho::new_chirho(temp_chirho.path())
        )
        .expect_err("nothing stored must refuse"),
        TopologyPlanReferenceRefusalChirho::PlanAbsentChirho {
            digest_chirho: digest_chirho.clone(),
        }
    );
}
