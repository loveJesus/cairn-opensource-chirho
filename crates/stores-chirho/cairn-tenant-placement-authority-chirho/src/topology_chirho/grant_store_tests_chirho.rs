// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)
//! Arms for the durable topology grant store.
//!
//! The centrepiece is [`a_superseded_higher_ceiling_cannot_be_replayed_back_chirho`]. A topology grant
//! is a CEILING, and its verifier is stateless — so a correctly signed OLD grant verifies exactly as
//! well as the current one. Replaying a superseded grant is how a planner gets back a node count,
//! spend rate, or provider allowlist that was deliberately reduced, and nothing in the pure module can
//! refuse it.

use super::*;
use cairn_core_chirho::cas_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::*;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::TopologyGrantChirho;

const AUTHORITY_KEY_CHIRHO: &str = "topology-authority-key-chirho";
const PRINCIPAL_CHIRHO: &str = "planner-principal-chirho";

struct AuthorityChirho;

impl TopologyGrantAuthorityPortChirho for AuthorityChirho {
    fn authority_key_id_chirho(&self) -> String {
        AUTHORITY_KEY_CHIRHO.to_string()
    }
    fn verify_chirho(&self, msg_chirho: &str, sig_chirho: &str) -> bool {
        sig_chirho == format!("sig-over:{msg_chirho}")
    }
}

fn grant_record_chirho(
    max_nodes_chirho: u32,
    issued_seq_chirho: u64,
) -> TopologyGrantAttestationChirho {
    let intent_chirho = TopologyGrantIntentChirho {
        schema_chirho: TOPOLOGY_GRANT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        principal_chirho: PRINCIPAL_CHIRHO.to_string(),
        grant_chirho: TopologyGrantChirho {
            grant_id_chirho: "grant-a-chirho".to_string(),
            max_nodes_chirho,
            max_spend_rate_micros_per_hour_chirho: 1_000_000,
            allowed_providers_chirho: ["hetzner-chirho".to_string()].into_iter().collect(),
            minimum_control_nodes_chirho: 1,
            minimum_storage_nodes_chirho: 1,
        },
        issued_seq_chirho,
    };
    let digest_chirho = topology_grant_intent_digest_chirho(&intent_chirho).expect("digest");
    let mut record_chirho = TopologyGrantAttestationChirho {
        schema_chirho: TOPOLOGY_GRANT_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TOPOLOGY_GRANT_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho: digest_chirho,
        authority_key_id_chirho: AUTHORITY_KEY_CHIRHO.to_string(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = format!(
        "sig-over:{}",
        unsigned_topology_grant_message_chirho(&record_chirho)
    );
    record_chirho
}

#[test]
fn a_verified_grant_appends_and_loads_back_chirho() {
    // Positive control: every refusal arm below would pass against a store that refused everything.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_topology_grant_chirho(
        root_chirho,
        &grant_record_chirho(10, 1),
        &AuthorityChirho,
    )
    .expect("a verified grant must append");

    let current_chirho =
        load_current_verified_grant_chirho(root_chirho, PRINCIPAL_CHIRHO, &AuthorityChirho)
            .expect("load");
    assert_eq!(current_chirho.grant_chirho().max_nodes_chirho, 10);
    assert_eq!(current_chirho.issued_seq_chirho(), 1);
}

#[test]
fn a_superseded_higher_ceiling_cannot_be_replayed_back_chirho() {
    // THE arm. The ceiling is REDUCED from 10 to 3, and the old, still-perfectly-valid grant for 10 is
    // offered again. Verification alone cannot refuse it -- the signature is genuine and the module
    // that checks it is stateless by design -- so the durable high-water mark is the only thing
    // standing between a planner and a ceiling somebody deliberately took away.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let generous_chirho = grant_record_chirho(10, 1);
    append_verified_topology_grant_chirho(root_chirho, &generous_chirho, &AuthorityChirho)
        .expect("first grant");
    append_verified_topology_grant_chirho(
        root_chirho,
        &grant_record_chirho(3, 2),
        &AuthorityChirho,
    )
    .expect("the reduced ceiling supersedes it");

    assert_eq!(
        append_verified_topology_grant_chirho(root_chirho, &generous_chirho, &AuthorityChirho)
            .expect_err("replaying the superseded ceiling must refuse"),
        TopologyGrantStoreRefusalChirho::ReplayedIssuedSeqChirho {
            principal_chirho: PRINCIPAL_CHIRHO.to_string(),
            highest_recorded_chirho: 2,
            offered_chirho: 1,
        }
    );
    // And the current ceiling is still the reduced one, so the refusal actually protected something.
    assert_eq!(
        load_current_verified_grant_chirho(root_chirho, PRINCIPAL_CHIRHO, &AuthorityChirho)
            .expect("load")
            .grant_chirho()
            .max_nodes_chirho,
        3
    );
}

#[test]
fn re_offering_the_exact_current_sequence_is_refused_too_chirho() {
    // `<=`, not `<`. An exact re-offer is the cheapest replay to attempt and the easiest boundary to
    // get wrong.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let record_chirho = grant_record_chirho(10, 7);
    append_verified_topology_grant_chirho(root_chirho, &record_chirho, &AuthorityChirho)
        .expect("first");
    assert!(matches!(
        append_verified_topology_grant_chirho(root_chirho, &record_chirho, &AuthorityChirho)
            .expect_err("an exact replay must refuse"),
        TopologyGrantStoreRefusalChirho::ReplayedIssuedSeqChirho { .. }
    ));
}

#[test]
fn a_forged_grant_leaves_no_log_at_all_chirho() {
    // Ordering is the contract: verify, refuse replay, store intent, append. A forged record must not
    // reach any of the later steps.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let mut forged_chirho = grant_record_chirho(10, 1);
    forged_chirho.sig_chirho = "sig-over:not-the-real-message-chirho".to_string();
    assert_eq!(
        append_verified_topology_grant_chirho(root_chirho, &forged_chirho, &AuthorityChirho)
            .expect_err("a forged grant must refuse"),
        TopologyGrantStoreRefusalChirho::NotVerifiedChirho
    );
    assert!(!root_chirho
        .join(TOPOLOGY_GRANT_ATTESTATION_LOG_CHIRHO)
        .exists());
}

#[test]
fn the_stored_intent_resolves_in_cas_at_its_declared_digest_chirho() {
    // The log is a DECLARED surface, so every 64-hex token in it must resolve as an object in this
    // root or migration refuses on a dangling reference.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    let record_chirho = grant_record_chirho(10, 1);
    let declared_chirho = record_chirho.intent_digest_chirho.clone();
    append_verified_topology_grant_chirho(root_chirho, &record_chirho, &AuthorityChirho)
        .expect("append");
    assert!(cas_chirho::get_chirho(root_chirho, &HashChirho(declared_chirho)).is_ok());
}

#[test]
fn a_principal_with_no_grant_refuses_rather_than_returning_a_default_ceiling_chirho() {
    // A default ceiling is the most dangerous possible answer to "what may this principal do": it is
    // either unbounded or zero, and both are wrong for a question whose honest answer is "none".
    let temp_chirho = tempfile::tempdir().unwrap();
    assert_eq!(
        load_current_verified_grant_chirho(
            temp_chirho.path(),
            "principal-with-nothing-chirho",
            &AuthorityChirho
        )
        .expect_err("no grant must refuse"),
        TopologyGrantStoreRefusalChirho::NoGrantForPrincipalChirho {
            principal_chirho: "principal-with-nothing-chirho".to_string(),
        }
    );
}

#[test]
fn one_principals_grant_is_not_anothers_chirho() {
    // The grant is bound to a principal, and the store is keyed the same way -- otherwise one
    // principal's ceiling would raise everybody's.
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();
    append_verified_topology_grant_chirho(
        root_chirho,
        &grant_record_chirho(10, 1),
        &AuthorityChirho,
    )
    .expect("append");
    assert!(matches!(
        load_current_verified_grant_chirho(
            root_chirho,
            "another-principal-chirho",
            &AuthorityChirho
        )
        .expect_err("another principal has no grant here"),
        TopologyGrantStoreRefusalChirho::NoGrantForPrincipalChirho { .. }
    ));
}
