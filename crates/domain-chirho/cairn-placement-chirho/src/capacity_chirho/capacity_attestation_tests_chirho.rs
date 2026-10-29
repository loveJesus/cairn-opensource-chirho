// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the registrar-signed capacity grant.
//!
//! The control comes first deliberately: a verifier that refuses everything would make every negative
//! arm below pass while proving nothing, so
//! [`a_registrar_signed_grant_verifies_and_yields_its_capacity_chirho`] is what earns them.
//!
//! Two arms assert a refusal is NOT some other refusal, which is the part worth keeping. Check order
//! is a contract here: an unknown key must refuse as an unknown key rather than as a bad signature,
//! and a tampered value must refuse on the recomputed digest rather than sliding through to a
//! signature check that happens to fail for a different reason.

use super::*;
use crate::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;

const REGISTRAR_KEY_CHIRHO: &str = "registrar-key-1-chirho";

/// Binds the signature to the exact message, so any change upstream of it invalidates the signature.
struct TestRegistrarChirho {
    key_chirho: String,
}

impl NodeRegistrationAuthorityPortChirho for TestRegistrarChirho {
    fn authority_key_id_chirho(&self) -> String {
        self.key_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{canonical_unsigned_chirho}")
    }
}

fn registrar_chirho() -> TestRegistrarChirho {
    TestRegistrarChirho {
        key_chirho: REGISTRAR_KEY_CHIRHO.to_string(),
    }
}

fn intent_chirho(node_chirho: &str, cpu_chirho: u64) -> NodeCapacityIntentChirho {
    NodeCapacityIntentChirho {
        schema_chirho: NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_chirho.to_string(),
        domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "eu-central-chirho".to_string(),
        },
        allocatable_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: cpu_chirho,
            memory_bytes_chirho: 8 * 1024 * 1024 * 1024,
            durable_bytes_chirho: 200 * 1024 * 1024 * 1024,
        },
        registration_seq_chirho: 7,
    }
}

/// A well-formed, correctly signed grant. Every negative arm mutates exactly one thing from here.
fn signed_record_chirho(intent_chirho: NodeCapacityIntentChirho) -> NodeCapacityAttestationChirho {
    let digest_chirho = node_capacity_intent_digest_chirho(&intent_chirho).expect("digest intent");
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: REGISTRAR_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_node_capacity_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn a_registrar_signed_grant_verifies_and_yields_its_capacity_chirho() {
    let record_chirho = signed_record_chirho(intent_chirho("node-a-chirho", 4000));
    let verified_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect("a correctly signed grant must verify");
    assert_eq!(verified_chirho.node_id_chirho(), "node-a-chirho");
    assert_eq!(
        verified_chirho.allocatable_chirho().cpu_millicores_chirho,
        4000
    );
    assert_eq!(verified_chirho.registration_seq_chirho(), 7);
    assert_eq!(
        verified_chirho.domain_chirho().provider_chirho,
        "hetzner-chirho"
    );
}

#[test]
fn an_unknown_authority_key_refuses_as_an_unknown_key_not_a_bad_signature_chirho() {
    let mut record_chirho = signed_record_chirho(intent_chirho("node-a-chirho", 4000));
    record_chirho.authority_key_id_chirho = "some-other-key-chirho".to_string();
    let refusal_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect_err("a grant from an unknown registrar must refuse");
    // The ORDER is the property: an operator who pasted the wrong key is told that, not "bad
    // signature". Asserting it is not the signature refusal is what makes this arm about ordering.
    assert!(
        matches!(
            refusal_chirho,
            CapacityAttestationRefusalChirho::UnknownAuthorityKeyChirho { .. }
        ),
        "expected UnknownAuthorityKey, got {refusal_chirho:?}"
    );
    assert_ne!(
        refusal_chirho,
        CapacityAttestationRefusalChirho::SignatureInvalidChirho
    );
}

#[test]
fn an_inflated_capacity_refuses_on_the_recomputed_digest_chirho() {
    // The attack this exists to stop: a node that wants more capacity than it was granted.
    let mut record_chirho = signed_record_chirho(intent_chirho("node-a-chirho", 4000));
    record_chirho
        .intent_chirho
        .allocatable_chirho
        .cpu_millicores_chirho = 999_999;
    let refusal_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect_err("an inflated capacity must refuse");
    assert!(
        matches!(
            refusal_chirho,
            CapacityAttestationRefusalChirho::IntentDigestMismatchChirho { .. }
        ),
        "expected IntentDigestMismatch — the digest is RECOMPUTED, not trusted; got {refusal_chirho:?}"
    );
}

#[test]
fn a_self_consistent_but_unsigned_forgery_refuses_on_the_signature_chirho() {
    // A forger who recomputes the digest after tampering gets a record consistent with ITSELF. Only
    // the signature separates that from a real grant, which is why the digest check cannot be the
    // last word.
    let mut record_chirho = signed_record_chirho(intent_chirho("node-a-chirho", 4000));
    record_chirho
        .intent_chirho
        .allocatable_chirho
        .cpu_millicores_chirho = 999_999;
    record_chirho.intent_digest_chirho =
        node_capacity_intent_digest_chirho(&record_chirho.intent_chirho).expect("re-digest");
    let refusal_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect_err("a re-digested forgery must still refuse");
    assert_eq!(
        refusal_chirho,
        CapacityAttestationRefusalChirho::SignatureInvalidChirho
    );
}

#[test]
fn a_grant_for_another_node_refuses_chirho() {
    // A real, correctly signed grant — for somebody else. Replaying a peer's grant is the cheapest
    // way to claim capacity you were never given.
    let record_chirho = signed_record_chirho(intent_chirho("node-b-chirho", 4000));
    let refusal_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect_err("a grant naming another node must refuse");
    assert!(
        matches!(
            refusal_chirho,
            CapacityAttestationRefusalChirho::NodeIdMismatchChirho { .. }
        ),
        "expected NodeIdMismatch, got {refusal_chirho:?}"
    );
}

#[test]
fn a_zero_dimension_refuses_and_names_the_dimension_chirho() {
    let mut base_chirho = intent_chirho("node-a-chirho", 4000);
    base_chirho.allocatable_chirho.memory_bytes_chirho = 0;
    let record_chirho = signed_record_chirho(base_chirho);
    let refusal_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect_err("a zero dimension must refuse");
    match refusal_chirho {
        CapacityAttestationRefusalChirho::ZeroCapacityDimensionChirho { dimension_chirho } => {
            assert!(
                dimension_chirho.contains("Memory"),
                "the refusal must name which dimension was zero, got {dimension_chirho}"
            );
        }
        other_chirho => panic!("expected ZeroCapacityDimension, got {other_chirho:?}"),
    }
}

#[test]
fn a_signature_from_another_domain_refuses_chirho() {
    // Domain separation: a signature minted for the intent domain must not be replayable as a record
    // signature.
    let mut record_chirho = signed_record_chirho(intent_chirho("node-a-chirho", 4000));
    record_chirho.signature_domain_chirho = NODE_CAPACITY_INTENT_DOMAIN_V1_CHIRHO.to_string();
    let refusal_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect_err("a cross-domain signature must refuse");
    assert!(
        matches!(
            refusal_chirho,
            CapacityAttestationRefusalChirho::SignatureDomainMismatchChirho { .. }
        ),
        "expected SignatureDomainMismatch, got {refusal_chirho:?}"
    );
}

#[test]
fn an_overlong_field_refuses_and_names_the_field_chirho() {
    let mut base_chirho = intent_chirho("node-a-chirho", 4000);
    base_chirho.node_id_chirho = "n".repeat(MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO + 1);
    let record_chirho = signed_record_chirho(base_chirho);
    let refusal_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        &"n".repeat(MAX_NODE_CAPACITY_TOKEN_BYTES_CHIRHO + 1),
    )
    .expect_err("an overlong field must refuse");
    match refusal_chirho {
        CapacityAttestationRefusalChirho::FieldTooLongChirho { field_chirho, .. } => {
            assert_eq!(field_chirho, "node_id_chirho");
        }
        other_chirho => panic!("expected FieldTooLong naming the field, got {other_chirho:?}"),
    }
}

#[test]
fn a_registered_node_takes_its_identity_and_capacity_from_the_grant_chirho() {
    // The gating property. `from_verified_capacity_chirho` reads node id, domain and capacity out of
    // the VERIFIED grant rather than from caller arguments, so there is no seam where a caller
    // verifies one node's grant and registers it under another name or with a different figure.
    use crate::node_lifecycle_chirho::NodeLifecycleStateChirho;
    use crate::placement_registry_chirho::RegisteredNodeChirho;

    let record_chirho = signed_record_chirho(intent_chirho("node-a-chirho", 4000));
    let verified_chirho = verify_node_capacity_attestation_chirho(
        &record_chirho,
        &registrar_chirho(),
        "node-a-chirho",
    )
    .expect("grant verifies");

    let node_chirho = RegisteredNodeChirho::from_verified_capacity_chirho(&verified_chirho);
    assert_eq!(node_chirho.node_id_chirho(), "node-a-chirho");
    assert_eq!(node_chirho.allocatable_chirho().cpu_millicores_chirho, 4000);
    assert_eq!(
        node_chirho.domain_chirho().provider_chirho,
        "hetzner-chirho"
    );
    // A grant justifies exactly the ENTRY state. This arm previously passed `JoinedChirho` in as a
    // parameter and asserted it came back -- proving only that the constructor stored what it was
    // handed. A grant says how much a node may offer; it says nothing about whether the node has been
    // inspected or joined, and `ProvisionedChirho` is the only state with no inbound transition.
    assert_eq!(
        node_chirho.lifecycle_chirho(),
        NodeLifecycleStateChirho::ProvisionedChirho
    );
    assert_ne!(
        node_chirho.lifecycle_chirho(),
        NodeLifecycleStateChirho::JoinedChirho,
        "a capacity grant must never be able to produce a JOINED node -- admission is gated on \
         Joined, so that would let a signed capacity figure alone open a node to placements"
    );
    // A freshly registered node has no measurement yet, so admission cannot pass on a stale stamp
    // carried in at registration time.
    assert!(node_chirho.last_measurement_chirho().is_none());
}

#[test]
fn a_correctly_signed_old_grant_still_verifies_because_replay_is_the_callers_job_chirho() {
    // This arm pins a LIMIT, not a feature, so that the limit is executable rather than only prose.
    //
    // MIGRATION PATH: if this now REFUSES, someone has added replay protection to verification. That
    // is a welcome hardening, not a regression — retarget this arm at the new refusal identity and
    // delete the "DOES NOT ENFORCE" paragraph on `registration_seq_chirho`, which will have become
    // false. If it still returns Ok, verification is still stateless and a caller that does not keep
    // the highest sequence per node is replayable.
    let old_chirho = signed_record_chirho({
        let mut i_chirho = intent_chirho("node-a-chirho", 4000);
        i_chirho.registration_seq_chirho = 1;
        i_chirho
    });
    let new_chirho = signed_record_chirho({
        let mut i_chirho = intent_chirho("node-a-chirho", 4000);
        i_chirho.registration_seq_chirho = 99;
        i_chirho
    });
    let newer_chirho =
        verify_node_capacity_attestation_chirho(&new_chirho, &registrar_chirho(), "node-a-chirho")
            .expect("the newer grant verifies");
    assert_eq!(newer_chirho.registration_seq_chirho(), 99);

    // Verification holds ONE record; it has nothing to compare a sequence against.
    let older_chirho =
        verify_node_capacity_attestation_chirho(&old_chirho, &registrar_chirho(), "node-a-chirho")
            .expect("a correctly signed older grant verifies too — see MIGRATION PATH above");
    assert_eq!(older_chirho.registration_seq_chirho(), 1);
}
