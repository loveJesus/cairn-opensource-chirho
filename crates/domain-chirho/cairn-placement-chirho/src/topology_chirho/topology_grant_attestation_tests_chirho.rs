// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the signed topology grant.
//!
//! Control first — a verifier refusing everything would make every negative arm pass while proving
//! nothing. The centrepiece is
//! [`a_planner_raising_its_own_ceiling_refuses_on_the_recomputed_digest_chirho`]: the whole point of a
//! signed grant is that the principal bound by it cannot edit it, and that arm is the one an attacker
//! would need to defeat.

use super::*;
use std::collections::BTreeSet;

const GRANT_KEY_CHIRHO: &str = "grant-authority-key-1-chirho";
const PRINCIPAL_CHIRHO: &str = "planner-a-chirho";

struct TestGrantAuthorityChirho {
    key_chirho: String,
}

impl TopologyGrantAuthorityPortChirho for TestGrantAuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        self.key_chirho.clone()
    }
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{canonical_unsigned_chirho}")
    }
}

fn authority_chirho() -> TestGrantAuthorityChirho {
    TestGrantAuthorityChirho {
        key_chirho: GRANT_KEY_CHIRHO.to_string(),
    }
}

fn grant_chirho(max_nodes_chirho: u32) -> TopologyGrantChirho {
    let mut providers_chirho = BTreeSet::new();
    providers_chirho.insert("hetzner-chirho".to_string());
    providers_chirho.insert("ovh-chirho".to_string());
    TopologyGrantChirho {
        grant_id_chirho: "grant-a-chirho".to_string(),
        max_nodes_chirho,
        max_spend_rate_micros_per_hour_chirho: 500_000,
        allowed_providers_chirho: providers_chirho,
        minimum_control_nodes_chirho: 3,
        minimum_storage_nodes_chirho: 2,
    }
}

fn intent_chirho(grant_chirho: TopologyGrantChirho) -> TopologyGrantIntentChirho {
    TopologyGrantIntentChirho {
        schema_chirho: TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        principal_chirho: PRINCIPAL_CHIRHO.to_string(),
        grant_chirho,
        issued_seq_chirho: 4,
    }
}

fn signed_record_chirho(
    intent_chirho: TopologyGrantIntentChirho,
) -> TopologyGrantAttestationChirho {
    let digest_chirho =
        topology_grant_intent_digest_chirho(&intent_chirho).expect("digest the intent");
    let mut record_chirho = TopologyGrantAttestationChirho {
        schema_chirho: TOPOLOGY_GRANT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TOPOLOGY_GRANT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: GRANT_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_topology_grant_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn a_signed_grant_verifies_and_yields_its_bounds_chirho() {
    let record_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    let verified_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect("a correctly signed grant must verify");
    assert_eq!(verified_chirho.principal_chirho(), PRINCIPAL_CHIRHO);
    assert_eq!(verified_chirho.grant_chirho().max_nodes_chirho, 10);
    assert_eq!(verified_chirho.issued_seq_chirho(), 4);
}

#[test]
fn a_planner_raising_its_own_ceiling_refuses_on_the_recomputed_digest_chirho() {
    // THE attack a signed grant exists to stop. The principal is bound by these bounds, so editing
    // them is the one thing it must not be able to do — and the digest is RECOMPUTED, not trusted.
    let mut record_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    record_chirho.intent_chirho.grant_chirho.max_nodes_chirho = 10_000;
    record_chirho
        .intent_chirho
        .grant_chirho
        .max_spend_rate_micros_per_hour_chirho = 999_999_999;
    let refusal_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect_err("a raised ceiling must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyGrantAttestationRefusalChirho::IntentDigestMismatchChirho { .. }
        ),
        "expected IntentDigestMismatch, got {refusal_chirho:?}"
    );
}

#[test]
fn a_re_digested_raised_ceiling_still_refuses_on_the_signature_chirho() {
    // A planner that recomputes the digest after editing gets a record consistent with ITSELF. Only
    // the signature separates that from a real grant.
    let mut record_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    record_chirho.intent_chirho.grant_chirho.max_nodes_chirho = 10_000;
    record_chirho.intent_digest_chirho =
        topology_grant_intent_digest_chirho(&record_chirho.intent_chirho).expect("re-digest");
    let refusal_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect_err("a re-digested edit must still refuse");
    assert_eq!(
        refusal_chirho,
        TopologyGrantAttestationRefusalChirho::SignatureInvalidChirho
    );
}

#[test]
fn an_unknown_authority_key_refuses_as_an_unknown_key_not_a_bad_signature_chirho() {
    // Order arm. The key id is part of the signed message, so one planted defect reaches both checks
    // — asserting it is NOT the signature refusal is what pins key-before-signature.
    let mut record_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    record_chirho.authority_key_id_chirho = "some-other-authority-chirho".to_string();
    let refusal_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect_err("an unknown grant authority must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyGrantAttestationRefusalChirho::UnknownAuthorityKeyChirho { .. }
        ),
        "expected UnknownAuthorityKey, got {refusal_chirho:?}"
    );
    assert_ne!(
        refusal_chirho,
        TopologyGrantAttestationRefusalChirho::SignatureInvalidChirho
    );
}

#[test]
fn a_grant_issued_to_another_principal_refuses_chirho() {
    // A real, correctly signed grant — for someone else. Citing a peer's grant is the cheapest way to
    // plan within bounds you were never given.
    let record_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    let refusal_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        "planner-b-chirho",
    )
    .expect_err("a grant naming another principal must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyGrantAttestationRefusalChirho::PrincipalMismatchChirho { .. }
        ),
        "expected PrincipalMismatch, got {refusal_chirho:?}"
    );
}

#[test]
fn an_unsatisfiable_grant_refuses_and_names_both_numbers_chirho() {
    // Floors of 3 control + 2 storage cannot fit inside a 4-node ceiling. No plan could ever satisfy
    // it, so it is far more likely a mistake than an intention.
    let record_chirho = signed_record_chirho(intent_chirho(grant_chirho(4)));
    let refusal_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect_err("an unsatisfiable grant must refuse");
    match refusal_chirho {
        TopologyGrantAttestationRefusalChirho::UnsatisfiableGrantChirho {
            minimum_total_chirho,
            max_nodes_chirho,
        } => {
            assert_eq!(minimum_total_chirho, 5);
            assert_eq!(max_nodes_chirho, 4);
        }
        other_chirho => panic!("expected UnsatisfiableGrant, got {other_chirho:?}"),
    }
}

#[test]
fn a_zero_node_ceiling_refuses_chirho() {
    let record_chirho = signed_record_chirho(intent_chirho(grant_chirho(0)));
    let refusal_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect_err("a zero ceiling must refuse");
    assert_eq!(
        refusal_chirho,
        TopologyGrantAttestationRefusalChirho::ZeroNodeCeilingChirho
    );
}

#[test]
fn a_signature_from_another_domain_refuses_chirho() {
    let mut record_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    record_chirho.signature_domain_chirho = TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO.to_string();
    let refusal_chirho = verify_topology_grant_attestation_chirho(
        &record_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect_err("a cross-domain signature must refuse");
    assert!(
        matches!(
            refusal_chirho,
            TopologyGrantAttestationRefusalChirho::SignatureDomainMismatchChirho { .. }
        ),
        "expected SignatureDomainMismatch, got {refusal_chirho:?}"
    );
}

/// Oversized fields are refused BY THEIR BOUND, before any signature work happens.
///
/// Measured 2026-08-21: `FieldTooLongChirho` had no arm. It is the only one of this enum's four
/// unpinned identities that guards a resource rather than a shape — the other three are schema
/// declarations whose values sit inside the signed bytes, and an encode failure that is not
/// reachable.
///
/// **The ordering is the property, not merely the refusal.** These bounds run before the authority
/// key check, the digest recomputation and the signature verification, so an attacker-supplied
/// megabyte signature is dropped on a length comparison instead of being handed to the verifier.
/// Each case therefore asserts the bound identity AND asserts it is NOT the neighbour that would
/// fire if the bound were removed — without that second half the arm would still pass with the
/// bounds deleted, because the record would simply refuse one step later for a different reason.
#[test]
fn an_oversized_field_refuses_by_its_bound_before_any_signature_work_chirho() {
    // A signature past its bound must not reach the verifier.
    let mut oversized_signature_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    oversized_signature_chirho.sig_chirho =
        "x".repeat(MAX_TOPOLOGY_GRANT_SIGNATURE_BYTES_CHIRHO + 1);
    assert_eq!(
        verify_topology_grant_attestation_chirho(
            &oversized_signature_chirho,
            &authority_chirho(),
            PRINCIPAL_CHIRHO,
        ),
        Err(TopologyGrantAttestationRefusalChirho::FieldTooLongChirho {
            field_chirho: "sig_chirho".to_string(),
            bytes_chirho: MAX_TOPOLOGY_GRANT_SIGNATURE_BYTES_CHIRHO + 1,
        }),
        "an oversized signature must be refused on its LENGTH, not verified and found invalid"
    );

    // A token field past its bound must not reach the digest recomputation either.
    let mut oversized_token_chirho = signed_record_chirho(intent_chirho(grant_chirho(10)));
    oversized_token_chirho
        .intent_chirho
        .grant_chirho
        .grant_id_chirho = "g".repeat(MAX_TOPOLOGY_GRANT_TOKEN_BYTES_CHIRHO + 1);
    let token_refusal_chirho = verify_topology_grant_attestation_chirho(
        &oversized_token_chirho,
        &authority_chirho(),
        PRINCIPAL_CHIRHO,
    )
    .expect_err("an oversized grant id must refuse");
    assert_eq!(
        token_refusal_chirho,
        TopologyGrantAttestationRefusalChirho::FieldTooLongChirho {
            field_chirho: "grant_id_chirho".to_string(),
            bytes_chirho: MAX_TOPOLOGY_GRANT_TOKEN_BYTES_CHIRHO + 1,
        },
        "and by the BOUND rather than by the digest mismatch that editing the intent also causes — \
         which is what proves the bound runs first: {token_refusal_chirho:?}"
    );
}
