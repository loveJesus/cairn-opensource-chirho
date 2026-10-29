// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the durable capacity-grant store.
//!
//! Control first, because a store that refused every append would make every replay arm below pass while
//! proving nothing. The two arms that carry the design are
//! [`the_stored_intent_resolves_in_cas_at_its_declared_digest_chirho`] — the property that keeps a
//! declared log surface self-contained — and the replay pair, which is the protection the pure verifier
//! documents as the caller's job.

use super::*;
use cairn_core_chirho::cas_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::NodeCapacityIntentChirho;

const REGISTRAR_KEY_CHIRHO: &str = "registrar-key-1-chirho";

struct TestRegistrarChirho;

impl NodeRegistrationAuthorityPortChirho for TestRegistrarChirho {
    fn authority_key_id_chirho(&self) -> String {
        REGISTRAR_KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{canonical_unsigned_chirho}")
    }
}

fn signed_record_chirho(node_chirho: &str, seq_chirho: u64) -> NodeCapacityAttestationChirho {
    let intent_chirho = NodeCapacityIntentChirho {
        schema_chirho: cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::NODE_CAPACITY_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        node_id_chirho: node_chirho.to_string(),
        domain_chirho: cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "eu-central-chirho".to_string(),
        },
        allocatable_chirho: cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho {
            cpu_millicores_chirho: 4000,
            memory_bytes_chirho: 8 * 1024 * 1024 * 1024,
            durable_bytes_chirho: 200 * 1024 * 1024 * 1024,
        },
        registration_seq_chirho: seq_chirho,
    };
    let digest_chirho = cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::node_capacity_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = NodeCapacityAttestationChirho {
        schema_chirho: cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::NODE_CAPACITY_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::NODE_CAPACITY_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: REGISTRAR_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::unsigned_node_capacity_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn a_signed_grant_appends_and_loads_back_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let record_chirho = signed_record_chirho("node-a-chirho", 1);
    append_verified_capacity_attestation_chirho(root_chirho, &record_chirho, &TestRegistrarChirho)
        .expect("a signed grant must append");
    let loaded_chirho =
        load_current_verified_capacity_chirho(root_chirho, "node-a-chirho", &TestRegistrarChirho)
            .expect("the appended grant must load back");
    assert_eq!(loaded_chirho.registration_seq_chirho(), 1);
    assert_eq!(
        loaded_chirho.allocatable_chirho().cpu_millicores_chirho,
        4000
    );
}

#[test]
fn the_stored_intent_resolves_in_cas_at_its_declared_digest_chirho() {
    // THE design property. The log is a declared surface, so self-containment requires every 64-hex
    // token in it to resolve as a CAS object in THIS root. That holds only because
    // hash_object_chirho(intent) IS the CAS address of the intent's serde bytes -- so the digest the
    // record names and the address the intent lands at are the same string by construction.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let record_chirho = signed_record_chirho("node-a-chirho", 1);
    let declared_chirho = record_chirho.intent_digest_chirho.clone();
    append_verified_capacity_attestation_chirho(root_chirho, &record_chirho, &TestRegistrarChirho)
        .expect("append");
    let fetched_chirho = cas_chirho::get_chirho(root_chirho, &HashChirho(declared_chirho.clone()));
    assert!(
        fetched_chirho.is_ok(),
        "the declared intent digest must resolve as a CAS object in this root, or a declared log \
         surface would carry a dangling reference and refuse migration"
    );
    let round_chirho: NodeCapacityIntentChirho =
        serde_json::from_slice(&fetched_chirho.unwrap()).expect("the stored object is the intent");
    assert_eq!(round_chirho, record_chirho.intent_chirho);
}

#[test]
fn a_replayed_sequence_is_refused_and_names_both_numbers_chirho() {
    // The protection the pure verifier documents as the caller's. Verification is stateless, so a
    // correctly signed OLD grant verifies identically -- only durable state can refuse it.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_capacity_attestation_chirho(
        root_chirho,
        &signed_record_chirho("node-a-chirho", 5),
        &TestRegistrarChirho,
    )
    .expect("first append");

    for offered_chirho in [5u64, 3u64] {
        let refusal_chirho = append_verified_capacity_attestation_chirho(
            root_chirho,
            &signed_record_chirho("node-a-chirho", offered_chirho),
            &TestRegistrarChirho,
        )
        .expect_err("a sequence at or below the high-water mark must refuse");
        match refusal_chirho {
            CapacityAttestationStoreRefusalChirho::ReplayedRegistrationChirho {
                offered_chirho: got_chirho,
                highest_recorded_chirho,
                ..
            } => {
                assert_eq!(got_chirho, offered_chirho);
                assert_eq!(highest_recorded_chirho, 5);
            }
            other_chirho => panic!("expected ReplayedRegistration, got {other_chirho:?}"),
        }
    }
}

#[test]
fn a_higher_sequence_supersedes_and_becomes_current_chirho() {
    // The positive half of the replay pair: refusing old grants must not also refuse NEW ones.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_capacity_attestation_chirho(
        root_chirho,
        &signed_record_chirho("node-a-chirho", 5),
        &TestRegistrarChirho,
    )
    .expect("first append");
    append_verified_capacity_attestation_chirho(
        root_chirho,
        &signed_record_chirho("node-a-chirho", 6),
        &TestRegistrarChirho,
    )
    .expect("a higher sequence must be accepted");
    let current_chirho =
        load_current_verified_capacity_chirho(root_chirho, "node-a-chirho", &TestRegistrarChirho)
            .expect("load current");
    assert_eq!(current_chirho.registration_seq_chirho(), 6);
    assert_eq!(
        highest_recorded_sequence_chirho(root_chirho, "node-a-chirho").unwrap(),
        Some(6)
    );
}

#[test]
fn an_unverifiable_record_never_touches_the_log_chirho() {
    // A record that does not verify must not move the high-water mark or leave a row behind, because a
    // row in a declared surface is a reference self-containment will later insist on resolving.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let mut forged_chirho = signed_record_chirho("node-a-chirho", 9);
    forged_chirho.sig_chirho = "sig-over:not-the-real-message-chirho".to_string();
    assert!(append_verified_capacity_attestation_chirho(
        root_chirho,
        &forged_chirho,
        &TestRegistrarChirho
    )
    .is_err());
    assert!(
        !root_chirho
            .join(NODE_CAPACITY_ATTESTATION_LOG_CHIRHO)
            .exists(),
        "a refused record must leave no log at all"
    );
    assert_eq!(
        highest_recorded_sequence_chirho(root_chirho, "node-a-chirho").unwrap(),
        None,
        "a refused record must not move the high-water mark"
    );
}

#[test]
fn a_node_with_no_grant_refuses_by_name_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_capacity_attestation_chirho(
        root_chirho,
        &signed_record_chirho("node-a-chirho", 1),
        &TestRegistrarChirho,
    )
    .expect("append");
    // Another node's grant in the same log must not answer for this one.
    let refusal_chirho =
        load_current_verified_capacity_chirho(root_chirho, "node-b-chirho", &TestRegistrarChirho)
            .expect_err("an unknown node must refuse");
    assert!(matches!(
        refusal_chirho,
        CapacityAttestationStoreRefusalChirho::NoGrantForNodeChirho { .. }
    ));
}
