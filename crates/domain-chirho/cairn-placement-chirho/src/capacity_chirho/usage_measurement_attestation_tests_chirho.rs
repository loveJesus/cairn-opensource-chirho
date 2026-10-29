// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the node-signed usage measurement.
//!
//! The centrepiece is [`one_nodes_key_cannot_report_usage_for_another_chirho`]. That is what signing
//! buys here: a usage figure is not made TRUE by a signature, but it becomes unforgeable by other
//! nodes — so one node cannot report a peer as idle to have it drained, or as full to have work kept
//! off it.

use super::*;

const NODE_A_KEY_CHIRHO: &str = "node-a-key-chirho";
const NODE_B_KEY_CHIRHO: &str = "node-b-key-chirho";
const NODE_A_CHIRHO: &str = "node-a-chirho";

struct NodeAuthorityChirho {
    key_chirho: String,
}

impl NodeMeasurementAuthorityPortChirho for NodeAuthorityChirho {
    fn node_key_id_chirho(&self) -> String {
        self.key_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        // The signature is bound to the KEY, so a message signed by node B never verifies as node A's.
        sig_chirho == format!("sig-by-{}:{canonical_unsigned_chirho}", self.key_chirho)
    }
}

fn authority_for_chirho(key_chirho: &str) -> NodeAuthorityChirho {
    NodeAuthorityChirho {
        key_chirho: key_chirho.to_string(),
    }
}

fn signed_by_chirho(
    node_id_chirho: &str,
    signing_key_chirho: &str,
    sequence_chirho: u64,
) -> UsageMeasurementAttestationChirho {
    let intent_chirho = UsageMeasurementIntentChirho {
        schema_chirho: USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_id_chirho.to_string(),
        stamp_chirho: MeasurementStampChirho {
            hlc_millis_chirho: 1_000,
            sequence_chirho,
        },
        observed_usage_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 1500,
            memory_bytes_chirho: 2 << 30,
            durable_bytes_chirho: 40 << 30,
        },
    };
    let digest_chirho = usage_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = UsageMeasurementAttestationChirho {
        schema_chirho: USAGE_MEASUREMENT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: USAGE_MEASUREMENT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        node_key_id_chirho: signing_key_chirho.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-by-{signing_key_chirho}:{}",
        unsigned_usage_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn a_node_signed_usage_report_verifies_and_carries_its_stamp_chirho() {
    let record_chirho = signed_by_chirho(NODE_A_CHIRHO, NODE_A_KEY_CHIRHO, 7);
    let verified_chirho = verify_usage_measurement_chirho(
        &record_chirho,
        &authority_for_chirho(NODE_A_KEY_CHIRHO),
        NODE_A_CHIRHO,
    )
    .expect("a node's own signed report must verify");
    assert_eq!(verified_chirho.node_id_chirho(), NODE_A_CHIRHO);
    assert_eq!(verified_chirho.stamp_chirho().sequence_chirho, 7);
    assert_eq!(verified_chirho.stamp_chirho().hlc_millis_chirho, 1_000);
    assert_eq!(
        verified_chirho
            .observed_usage_chirho()
            .cpu_millicores_chirho,
        1500
    );
}

#[test]
fn one_nodes_key_cannot_report_usage_for_another_chirho() {
    // THE property. Node B signs a report claiming to be node A's usage, with a valid signature under
    // B's own key. Read as node A, it refuses on the KEY -- before any signature work -- so an operator
    // is told the report is signed by the wrong node rather than "bad signature".
    //
    // Without this, one node could report a peer as idle to have it drained, or as full to keep work
    // off it. Freshness rules would classify that number happily: they answer "is this recent", never
    // "whose is it".
    let forged_chirho = signed_by_chirho(NODE_A_CHIRHO, NODE_B_KEY_CHIRHO, 7);
    let refusal_chirho = verify_usage_measurement_chirho(
        &forged_chirho,
        &authority_for_chirho(NODE_A_KEY_CHIRHO),
        NODE_A_CHIRHO,
    )
    .expect_err("another node's key must not report this node's usage");
    match &refusal_chirho {
        UsageMeasurementRefusalChirho::UnknownNodeKeyChirho {
            found_chirho,
            expected_chirho,
        } => {
            assert_eq!(found_chirho, NODE_B_KEY_CHIRHO);
            assert_eq!(expected_chirho, NODE_A_KEY_CHIRHO);
        }
        other_chirho => panic!("expected UnknownNodeKey, got {other_chirho:?}"),
    }
    assert_ne!(
        refusal_chirho,
        UsageMeasurementRefusalChirho::SignatureInvalidChirho,
        "key before signature: the operator is told WHICH mistake was made"
    );
}

#[test]
fn a_report_about_another_node_refuses_even_when_authentic_chirho() {
    // Authentic and somebody else's: node B's own genuine report, read while asking about node A.
    let record_chirho = signed_by_chirho("node-b-chirho", NODE_B_KEY_CHIRHO, 3);
    let refusal_chirho = verify_usage_measurement_chirho(
        &record_chirho,
        &authority_for_chirho(NODE_B_KEY_CHIRHO),
        NODE_A_CHIRHO,
    )
    .expect_err("a report about another node must refuse");
    assert!(matches!(
        refusal_chirho,
        UsageMeasurementRefusalChirho::NodeIdMismatchChirho { .. }
    ));
}

#[test]
fn editing_the_reported_usage_refuses_on_the_recomputed_digest_chirho() {
    // The attack: take a real low-usage report and inflate it, or take a real high one and zero it.
    // The usage is inside the signed intent, so editing it breaks the digest.
    let mut record_chirho = signed_by_chirho(NODE_A_CHIRHO, NODE_A_KEY_CHIRHO, 7);
    record_chirho
        .intent_chirho
        .observed_usage_chirho
        .cpu_millicores_chirho = 1;
    let refusal_chirho = verify_usage_measurement_chirho(
        &record_chirho,
        &authority_for_chirho(NODE_A_KEY_CHIRHO),
        NODE_A_CHIRHO,
    )
    .expect_err("edited usage must refuse");
    assert!(matches!(
        refusal_chirho,
        UsageMeasurementRefusalChirho::IntentDigestMismatchChirho { .. }
    ));
}

#[test]
fn a_signature_from_another_domain_refuses_chirho() {
    let mut record_chirho = signed_by_chirho(NODE_A_CHIRHO, NODE_A_KEY_CHIRHO, 7);
    record_chirho.signature_domain_chirho = USAGE_MEASUREMENT_INTENT_SCHEMA_V1_CHIRHO.to_string();
    let refusal_chirho = verify_usage_measurement_chirho(
        &record_chirho,
        &authority_for_chirho(NODE_A_KEY_CHIRHO),
        NODE_A_CHIRHO,
    )
    .expect_err("a cross-domain signature must refuse");
    assert!(matches!(
        refusal_chirho,
        UsageMeasurementRefusalChirho::SignatureDomainMismatchChirho { .. }
    ));
}
