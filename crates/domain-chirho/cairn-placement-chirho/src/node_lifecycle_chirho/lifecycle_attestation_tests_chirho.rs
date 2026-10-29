// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the signed lifecycle transition.
//!
//! Control first, because a verifier that refused everything would make every negative arm pass while
//! proving nothing. The centrepiece is
//! [`an_authentic_but_illegal_transition_refuses_on_the_RULE_chirho`]: a correctly signed record from
//! the right authority is still refused if the rule would not have allowed it. Authenticity buys
//! attribution, never permission.

use super::*;

const LIFECYCLE_KEY_CHIRHO: &str = "lifecycle-authority-key-1-chirho";
const NODE_CHIRHO: &str = "node-a-chirho";

struct TestAuthorityChirho;

impl LifecycleAuthorityPortChirho for TestAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        LIFECYCLE_KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{canonical_unsigned_chirho}")
    }
}

fn facts_chirho(
    holds_leadership_chirho: bool,
    ownership_proven_chirho: bool,
    resident_placements_chirho: u32,
) -> AssertedLifecycleFactsChirho {
    AssertedLifecycleFactsChirho {
        holds_leadership_chirho,
        ownership_proven_chirho,
        resident_placements_chirho,
    }
}

fn intent_chirho(
    from_chirho: NodeLifecycleStateChirho,
    transition_chirho: LifecycleTransitionChirho,
    asserted_chirho: AssertedLifecycleFactsChirho,
) -> LifecycleTransitionIntentChirho {
    LifecycleTransitionIntentChirho {
        schema_chirho: LIFECYCLE_TRANSITION_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: NODE_CHIRHO.to_string(),
        from_state_chirho: from_chirho,
        transition_chirho,
        asserted_facts_chirho: asserted_chirho,
        transition_seq_chirho: 1,
    }
}

fn signed_chirho(
    intent_chirho: LifecycleTransitionIntentChirho,
) -> LifecycleTransitionAttestationChirho {
    let digest_chirho = lifecycle_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = LifecycleTransitionAttestationChirho {
        schema_chirho: LIFECYCLE_TRANSITION_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: LIFECYCLE_TRANSITION_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: LIFECYCLE_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_lifecycle_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn a_legal_signed_transition_verifies_and_names_its_resulting_state_chirho() {
    let record_chirho = signed_chirho(intent_chirho(
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        facts_chirho(false, true, 0),
    ));
    let verified_chirho =
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, NODE_CHIRHO)
            .expect("a legal signed transition must verify");
    assert_eq!(
        verified_chirho.from_state_chirho(),
        NodeLifecycleStateChirho::ProvisionedChirho
    );
    assert_eq!(
        verified_chirho.resulting_state_chirho(),
        NodeLifecycleStateChirho::InspectedChirho
    );
}

#[test]
fn an_authentic_but_illegal_transition_refuses_on_the_rule_chirho() {
    // THE property. This record is signed by the right authority over bytes that verify -- and it
    // retires a node that still holds leadership and still has placements resident. Authenticity buys
    // attribution, never permission, and every reason is reported rather than the first.
    let record_chirho = signed_chirho(intent_chirho(
        NodeLifecycleStateChirho::DrainingChirho,
        LifecycleTransitionChirho::RetireChirho,
        facts_chirho(true, false, 3),
    ));
    let refusal_chirho =
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, NODE_CHIRHO)
            .expect_err("an illegal transition must refuse even when authentic");
    match refusal_chirho {
        LifecycleAttestationRefusalChirho::IllegalTransitionChirho { reasons_chirho } => {
            assert!(
                reasons_chirho.len() >= 3,
                "leadership, ownership and resident placements are three separate fixes and an \
                 operator should see them all at once, got {reasons_chirho:?}"
            );
            assert!(reasons_chirho
                .iter()
                .any(|r_chirho| r_chirho.contains("Leadership")));
            assert!(reasons_chirho
                .iter()
                .any(|r_chirho| r_chirho.contains("Ownership")));
            assert!(reasons_chirho
                .iter()
                .any(|r_chirho| r_chirho.contains("Placements")));
        }
        other_chirho => panic!("expected IllegalTransition, got {other_chirho:?}"),
    }
}

#[test]
fn skipping_a_state_refuses_even_when_the_exit_facts_are_clean_chirho() {
    // Provisioned -> Join is not a legal edge; only Inspect is. Clean facts must not buy a skip.
    let record_chirho = signed_chirho(intent_chirho(
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::JoinChirho,
        facts_chirho(false, true, 0),
    ));
    let refusal_chirho =
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, NODE_CHIRHO)
            .expect_err("skipping inspection must refuse");
    assert!(matches!(
        refusal_chirho,
        LifecycleAttestationRefusalChirho::IllegalTransitionChirho { .. }
    ));
}

#[test]
fn an_unsigned_illegal_transition_refuses_on_the_signature_not_the_rule_chirho() {
    // Ordering: the rule check is LAST on purpose. A record nobody signed should report that, rather
    // than a rule complaint about bytes with no author.
    let mut record_chirho = signed_chirho(intent_chirho(
        NodeLifecycleStateChirho::DrainingChirho,
        LifecycleTransitionChirho::RetireChirho,
        facts_chirho(true, false, 3),
    ));
    record_chirho.sig_chirho = "sig-over:not-the-real-message-chirho".to_string();
    let refusal_chirho =
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, NODE_CHIRHO)
            .expect_err("an unsigned record must refuse");
    assert_eq!(
        refusal_chirho,
        LifecycleAttestationRefusalChirho::SignatureInvalidChirho
    );
    assert!(
        !matches!(
            refusal_chirho,
            LifecycleAttestationRefusalChirho::IllegalTransitionChirho { .. }
        ),
        "authenticity is checked before legality"
    );
}

#[test]
fn tampering_with_the_asserted_facts_refuses_on_the_recomputed_digest_chirho() {
    // The attack: sign a retire with leadership held, then edit the record to claim it was not. The
    // facts are INSIDE the signed intent, so editing them breaks the digest.
    let mut record_chirho = signed_chirho(intent_chirho(
        NodeLifecycleStateChirho::DrainingChirho,
        LifecycleTransitionChirho::RetireChirho,
        facts_chirho(true, false, 3),
    ));
    record_chirho.intent_chirho.asserted_facts_chirho = facts_chirho(false, true, 0);
    let refusal_chirho =
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, NODE_CHIRHO)
            .expect_err("edited facts must refuse");
    assert!(matches!(
        refusal_chirho,
        LifecycleAttestationRefusalChirho::IntentDigestMismatchChirho { .. }
    ));
}

#[test]
fn an_unknown_authority_refuses_as_an_unknown_key_not_a_bad_signature_chirho() {
    let mut record_chirho = signed_chirho(intent_chirho(
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        facts_chirho(false, true, 0),
    ));
    record_chirho.authority_key_id_chirho = "some-other-authority-chirho".to_string();
    let refusal_chirho =
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, NODE_CHIRHO)
            .expect_err("an unknown authority must refuse");
    assert!(matches!(
        refusal_chirho,
        LifecycleAttestationRefusalChirho::UnknownAuthorityKeyChirho { .. }
    ));
    assert_ne!(
        refusal_chirho,
        LifecycleAttestationRefusalChirho::SignatureInvalidChirho
    );
}

#[test]
fn a_transition_for_another_node_refuses_chirho() {
    let record_chirho = signed_chirho(intent_chirho(
        NodeLifecycleStateChirho::ProvisionedChirho,
        LifecycleTransitionChirho::InspectChirho,
        facts_chirho(false, true, 0),
    ));
    let refusal_chirho =
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, "node-b-chirho")
            .expect_err("a transition naming another node must refuse");
    assert!(matches!(
        refusal_chirho,
        LifecycleAttestationRefusalChirho::NodeIdMismatchChirho { .. }
    ));
}

/// Arms for the registry's advance path, placed HERE rather than beside the registry on purpose: the
/// registry's own test file is `#[path]`-included into its module and would therefore reach the private
/// field directly, testing a surface no external caller has. From here the only way in is the public
/// method, which is what a production caller actually gets.
mod advance_path_chirho {
    use super::*;
    use crate::capacity_chirho::capacity_attestation_chirho::VerifiedNodeCapacityChirho;
    use crate::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
    use crate::failure_domain_chirho::FailureDomainChirho;
    use crate::placement_registry_chirho::{LifecycleAdvanceRefusalChirho, RegisteredNodeChirho};

    fn node_chirho(node_id_chirho: &str) -> RegisteredNodeChirho {
        RegisteredNodeChirho::from_verified_capacity_chirho(
            &VerifiedNodeCapacityChirho::unverified_for_test_chirho(
                node_id_chirho,
                FailureDomainChirho {
                    provider_chirho: "hetzner-chirho".to_string(),
                    region_chirho: "eu-central-chirho".to_string(),
                },
                AllocatableCapacityChirho {
                    cpu_millicores_chirho: 4000,
                    memory_bytes_chirho: 8 << 30,
                    durable_bytes_chirho: 200 << 30,
                },
            ),
        )
    }

    fn verified_chirho(
        node_id_chirho: &str,
        from_chirho: NodeLifecycleStateChirho,
        transition_chirho: LifecycleTransitionChirho,
    ) -> VerifiedLifecycleTransitionChirho {
        let mut intent_chirho =
            intent_chirho(from_chirho, transition_chirho, facts_chirho(false, true, 0));
        intent_chirho.node_id_chirho = node_id_chirho.to_string();
        let record_chirho = signed_chirho(intent_chirho);
        verify_lifecycle_attestation_chirho(&record_chirho, &TestAuthorityChirho, node_id_chirho)
            .expect("the fixture transition must verify")
    }

    #[test]
    fn a_verified_transition_advances_the_node_chirho() {
        let mut node_chirho = node_chirho(NODE_CHIRHO);
        assert_eq!(
            node_chirho.lifecycle_chirho(),
            NodeLifecycleStateChirho::ProvisionedChirho
        );
        let advanced_chirho = node_chirho
            .advance_by_verified_transition_chirho(&verified_chirho(
                NODE_CHIRHO,
                NodeLifecycleStateChirho::ProvisionedChirho,
                LifecycleTransitionChirho::InspectChirho,
            ))
            .expect("a matching verified transition must advance the node");
        assert_eq!(advanced_chirho, NodeLifecycleStateChirho::InspectedChirho);
        assert_eq!(
            node_chirho.lifecycle_chirho(),
            NodeLifecycleStateChirho::InspectedChirho
        );
    }

    #[test]
    fn another_nodes_verified_transition_is_refused_chirho() {
        // A real, verified transition -- for somebody else. Without this check, one node's signed
        // Join could advance every node in the registry.
        let mut node_chirho = node_chirho(NODE_CHIRHO);
        let refusal_chirho = node_chirho
            .advance_by_verified_transition_chirho(&verified_chirho(
                "node-b-chirho",
                NodeLifecycleStateChirho::ProvisionedChirho,
                LifecycleTransitionChirho::InspectChirho,
            ))
            .expect_err("another node's transition must refuse");
        assert!(matches!(
            refusal_chirho,
            LifecycleAdvanceRefusalChirho::NodeIdMismatchChirho { .. }
        ));
        assert_eq!(
            node_chirho.lifecycle_chirho(),
            NodeLifecycleStateChirho::ProvisionedChirho,
            "a refused advance must leave the state untouched"
        );
    }

    #[test]
    fn a_transition_signed_against_another_state_is_refused_chirho() {
        // Verified, this node's, and out of order: signed against Inspected while the node is still
        // Provisioned. Applying it would skip inspection.
        let mut node_chirho = node_chirho(NODE_CHIRHO);
        let refusal_chirho = node_chirho
            .advance_by_verified_transition_chirho(&verified_chirho(
                NODE_CHIRHO,
                NodeLifecycleStateChirho::InspectedChirho,
                LifecycleTransitionChirho::JoinChirho,
            ))
            .expect_err("an out-of-order transition must refuse");
        match refusal_chirho {
            LifecycleAdvanceRefusalChirho::StateMismatchChirho {
                signed_against_chirho,
                actual_chirho,
            } => {
                assert_eq!(
                    signed_against_chirho,
                    NodeLifecycleStateChirho::InspectedChirho
                );
                assert_eq!(actual_chirho, NodeLifecycleStateChirho::ProvisionedChirho);
            }
            other_chirho => panic!("expected StateMismatch, got {other_chirho:?}"),
        }
        assert_ne!(
            node_chirho.lifecycle_chirho(),
            NodeLifecycleStateChirho::JoinedChirho,
            "an out-of-order Join must never reach Joined -- that is the state admission keys off"
        );
    }
}
