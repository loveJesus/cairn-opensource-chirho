// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the durable lifecycle store.
//!
//! The centrepiece is [`a_transition_signed_against_a_stale_state_refuses_even_with_a_fresh_sequence_chirho`].
//! It is the arm that proves the two protections are INDEPENDENT: it offers a record with a sequence
//! above the high-water mark, so the replay check passes it, and it is refused anyway because it was
//! signed against a state the node has since left. A store with only a sequence check would accept it.

use super::*;
use cairn_core_chirho::cas_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::*;
use cairn_placement_chirho::node_lifecycle_chirho::LifecycleTransitionChirho;

const KEY_CHIRHO: &str = "lifecycle-authority-key-1-chirho";
const NODE_CHIRHO: &str = "node-a-chirho";

struct TestAuthorityChirho;

impl LifecycleAuthorityPortChirho for TestAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{canonical_unsigned_chirho}")
    }
}

fn signed_chirho(
    from_chirho: NodeLifecycleStateChirho,
    transition_chirho: LifecycleTransitionChirho,
    seq_chirho: u64,
) -> LifecycleTransitionAttestationChirho {
    let intent_chirho = LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
        from_state_chirho: from_chirho,
        transition_chirho,
        asserted_facts_chirho: AssertedLifecycleFactsChirho {
            holds_leadership_chirho: false,
            ownership_proven_chirho: true,
            resident_placements_chirho: 0,
        },
        transition_seq_chirho: seq_chirho,
    };
    let digest_chirho = lifecycle_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = LifecycleTransitionAttestationChirho {
        schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_lifecycle_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn a_node_with_no_transitions_is_at_the_entry_state_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    assert_eq!(
        current_lifecycle_state_chirho(temp_chirho.path(), NODE_CHIRHO, &TestAuthorityChirho)
            .unwrap(),
        NodeLifecycleStateChirho::ProvisionedChirho
    );
}

#[test]
fn the_chain_replays_provisioned_to_inspected_to_joined_chirho() {
    // Positive control for the whole store: without it, every refusal arm below could pass against a
    // store that refused everything and reported the entry state forever.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    assert_eq!(
        append_verified_lifecycle_transition_chirho(
            root_chirho,
            &signed_chirho(
                NodeLifecycleStateChirho::ProvisionedChirho,
                LifecycleTransitionChirho::InspectChirho,
                1
            ),
            &TestAuthorityChirho
        )
        .unwrap(),
        NodeLifecycleStateChirho::InspectedChirho
    );
    assert_eq!(
        append_verified_lifecycle_transition_chirho(
            root_chirho,
            &signed_chirho(
                NodeLifecycleStateChirho::InspectedChirho,
                LifecycleTransitionChirho::JoinChirho,
                2
            ),
            &TestAuthorityChirho
        )
        .unwrap(),
        NodeLifecycleStateChirho::JoinedChirho
    );
    assert_eq!(
        current_lifecycle_state_chirho(root_chirho, NODE_CHIRHO, &TestAuthorityChirho).unwrap(),
        NodeLifecycleStateChirho::JoinedChirho,
        "the current state must be DERIVED from the replayed log, not stored"
    );
}

#[test]
fn a_transition_signed_against_a_stale_state_refuses_even_with_a_fresh_sequence_chirho() {
    // THE arm. Advance the node to Inspected, then offer a transition signed against Provisioned with
    // sequence 9 -- comfortably ABOVE the high-water mark, so the replay check lets it through. It is
    // refused on the state, which is the protection a sequence check alone does not provide.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_lifecycle_transition_chirho(
        root_chirho,
        &signed_chirho(
            NodeLifecycleStateChirho::ProvisionedChirho,
            LifecycleTransitionChirho::InspectChirho,
            1,
        ),
        &TestAuthorityChirho,
    )
    .expect("first transition");

    let refusal_chirho = append_verified_lifecycle_transition_chirho(
        root_chirho,
        &signed_chirho(
            NodeLifecycleStateChirho::ProvisionedChirho,
            LifecycleTransitionChirho::InspectChirho,
            9,
        ),
        &TestAuthorityChirho,
    )
    .expect_err("a stale-view transition must refuse");
    match refusal_chirho {
        LifecycleStoreRefusalChirho::StaleViewChirho {
            signed_against_chirho,
            actual_chirho,
            ..
        } => {
            assert_eq!(
                signed_against_chirho,
                NodeLifecycleStateChirho::ProvisionedChirho
            );
            assert_eq!(actual_chirho, NodeLifecycleStateChirho::InspectedChirho);
        }
        other_chirho => panic!("expected StaleView, got {other_chirho:?}"),
    }
    assert!(
        !matches!(
            refusal_chirho,
            LifecycleStoreRefusalChirho::ReplayedTransitionChirho { .. }
        ),
        "sequence 9 is above the high-water mark, so this is NOT a replay -- the two protections \
         catch different things and this arm exists to keep them distinct"
    );
}

#[test]
fn a_replayed_sequence_refuses_and_names_both_numbers_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_lifecycle_transition_chirho(
        root_chirho,
        &signed_chirho(
            NodeLifecycleStateChirho::ProvisionedChirho,
            LifecycleTransitionChirho::InspectChirho,
            5,
        ),
        &TestAuthorityChirho,
    )
    .expect("first transition");
    let refusal_chirho = append_verified_lifecycle_transition_chirho(
        root_chirho,
        &signed_chirho(
            NodeLifecycleStateChirho::InspectedChirho,
            LifecycleTransitionChirho::JoinChirho,
            5,
        ),
        &TestAuthorityChirho,
    )
    .expect_err("a repeated sequence must refuse");
    match refusal_chirho {
        LifecycleStoreRefusalChirho::ReplayedTransitionChirho {
            offered_chirho,
            highest_recorded_chirho,
            ..
        } => {
            assert_eq!(offered_chirho, 5);
            assert_eq!(highest_recorded_chirho, 5);
        }
        other_chirho => panic!("expected ReplayedTransition, got {other_chirho:?}"),
    }
}

#[test]
fn an_unverifiable_transition_never_touches_the_log_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let mut forged_chirho = signed_chirho(
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        1,
    );
    forged_chirho.sig_chirho = "sig-over:not-the-real-message-chirho".to_string();
    assert!(append_verified_lifecycle_transition_chirho(
        root_chirho,
        &forged_chirho,
        &TestAuthorityChirho
    )
    .is_err());
    assert!(!root_chirho
        .join(NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO)
        .exists());
    assert_eq!(
        current_lifecycle_state_chirho(root_chirho, NODE_CHIRHO, &TestAuthorityChirho).unwrap(),
        NodeLifecycleStateChirho::ProvisionedChirho
    );
}

#[test]
fn the_stored_intent_resolves_in_cas_at_its_declared_digest_chirho() {
    // Same self-containment property as capacity grants: this log is a declared surface, so every
    // 64-hex token in it must resolve as an object in this root.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let record_chirho = signed_chirho(
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        1,
    );
    let declared_chirho = record_chirho.intent_digest_chirho.clone();
    append_verified_lifecycle_transition_chirho(root_chirho, &record_chirho, &TestAuthorityChirho)
        .expect("append");
    assert!(
        cas_chirho::get_chirho(root_chirho, &HashChirho(declared_chirho)).is_ok(),
        "the declared intent digest must resolve as a CAS object, or the declared log surface would \
         carry a dangling reference and refuse migration"
    );
}
