// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::RelayExecutionKnowledgeChirho;
use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::OsRng;

#[path = "ingress_tests_chirho.rs"]
mod ingress_tests_chirho;

trait RelayTestResultChirho<T> {
    fn expect_error_chirho(self) -> RelayContractErrorChirho;
}

impl<T> RelayTestResultChirho<T> for Result<T, RelayContractErrorChirho> {
    fn expect_error_chirho(self) -> RelayContractErrorChirho {
        match self {
            Ok(_value_chirho) => panic!("relay fixture unexpectedly passed"),
            Err(error_chirho) => error_chirho,
        }
    }
}

struct RelayFixtureChirho {
    origin_key_chirho: SigningKey,
    target_key_chirho: SigningKey,
    origin_id_chirho: String,
    target_id_chirho: String,
    group_digest_chirho: String,
    caller_key_chirho: CallerIdempotencyKeyChirho,
    roster_chirho: RelayRosterChirho,
}

impl RelayFixtureChirho {
    fn new_chirho() -> Self {
        let origin_key_chirho = SigningKey::generate(&mut OsRng);
        let target_key_chirho = SigningKey::generate(&mut OsRng);
        let origin_id_chirho = encode_hex_chirho(origin_key_chirho.verifying_key().as_bytes());
        let target_id_chirho = encode_hex_chirho(target_key_chirho.verifying_key().as_bytes());
        let roster_chirho =
            RelayRosterChirho::new_chirho(vec![origin_id_chirho.clone(), target_id_chirho.clone()])
                .unwrap();
        Self {
            origin_key_chirho,
            target_key_chirho,
            origin_id_chirho,
            target_id_chirho,
            group_digest_chirho: relay_tenant_consistency_group_digest_chirho("demo-chirho")
                .expect("derive canonical relay tenant-group digest"),
            caller_key_chirho: CallerIdempotencyKeyChirho::new_chirho(
                "caller-operation-0001-chirho",
            )
            .unwrap(),
            roster_chirho,
        }
    }

    fn signed_request_chirho(&self) -> ServedWriteRelayRequestV1Chirho {
        let prepared_chirho = PreparedServedWriteRelayRequestV1Chirho::new_chirho(
            ServedWriteRelayRequestInputChirho {
                ingress_admission_chirho: None,
                origin_node_id_chirho: self.origin_id_chirho.clone(),
                target_node_id_chirho: self.target_id_chirho.clone(),
                consistency_group_digest_chirho: self.group_digest_chirho.clone(),
                expected_term_chirho: 7,
                caller_idempotency_key_chirho: self.caller_key_chirho.clone(),
                method_chirho: "POST".to_string(),
                uri_chirho: "/app-chirho/demo-chirho/spend-chirho?bounded=1".to_string(),
                end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho(vec![
                    (
                        "authorization".to_string(),
                        "Bearer private-relay-fixture-chirho".to_string(),
                    ),
                    ("content-type".to_string(), "application/json".to_string()),
                ])
                .unwrap(),
                body_chirho: br#"{"amount_chirho":7}"#.to_vec(),
                relay_budget_remaining_millis_chirho: 2_500,
            },
        )
        .unwrap();
        let signature_chirho = self
            .origin_key_chirho
            .sign(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(encode_hex_chirho(&signature_chirho.to_bytes()))
            .unwrap()
    }

    fn verified_request_chirho(&self) -> VerifiedServedWriteRelayRequestChirho {
        let wire_chirho = self.signed_request_chirho().to_wire_bytes_chirho().unwrap();
        decode_and_verify_served_write_relay_request_chirho(
            &wire_chirho,
            &self.group_digest_chirho,
            &self.target_id_chirho,
            &self.roster_chirho,
        )
        .unwrap()
    }

    fn signed_response_chirho(&self) -> ServedWriteRelayResponseV1Chirho {
        let verified_request_chirho = self.verified_request_chirho();
        let prepared_chirho = PreparedServedWriteRelayResponseV1Chirho::new_chirho(
            ServedWriteRelayResponseInputChirho {
                request_digest_chirho: verified_request_chirho.request_digest_chirho().to_string(),
                caller_idempotency_key_digest_chirho: self.caller_key_chirho.digest_hex_chirho(),
                responder_node_id_chirho: self.target_id_chirho.clone(),
                consistency_group_digest_chirho: self.group_digest_chirho.clone(),
                actual_term_chirho: 7,
                outcome_class_chirho: RelayOutcomeClassChirho::ServedResponseChirho,
                outcome_identity_chirho: None,
                status_chirho: 200,
                end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_response_chirho(vec![(
                    "content-type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                )])
                .unwrap(),
                body_chirho: b"<main>verified response chirho</main>".to_vec(),
            },
        )
        .unwrap();
        let signature_chirho = self
            .target_key_chirho
            .sign(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(encode_hex_chirho(&signature_chirho.to_bytes()))
            .unwrap()
    }
}

#[test]
fn tenant_group_digest_is_canonical_domain_separated_and_stable_chirho() {
    let digest_chirho =
        relay_tenant_consistency_group_digest_chirho("demo-chirho").expect("derive group digest");
    assert_eq!(
        digest_chirho, "920fcebd0f2343f77e960e6d639eb86ddf3375343c87463fd7668a301746710b",
        "equal canonical tenant ids must retain one stable relay identity"
    );
    assert_eq!(digest_chirho.len(), RELAY_DIGEST_HEX_BYTES_CHIRHO);
    assert!(digest_chirho
        .bytes()
        .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho)));
    assert_ne!(
        digest_chirho,
        blake3::hash(b"demo-chirho").to_hex().to_string(),
        "the relay tenant-group domain must separate this digest from a raw content hash"
    );
    assert_ne!(
        digest_chirho,
        relay_tenant_consistency_group_digest_chirho("demo-two-chirho")
            .expect("derive distinct group digest"),
        "different tenant groups must not share a relay identity"
    );
}

#[test]
fn tenant_group_digest_refuses_path_and_noncanonical_inputs_chirho() {
    for invalid_chirho in [
        "",
        "/srv/cairn/tenant-chirho",
        "Tenant-Chirho",
        "-tenant-chirho",
        "tenant-chirho-",
        "tenant_chirho",
        "a2345678901234567890123456789012345678901234567890123456789012345",
    ] {
        let error_chirho =
            relay_tenant_consistency_group_digest_chirho(invalid_chirho).expect_error_chirho();
        assert_eq!(
            error_chirho.identity_chirho(),
            RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
            "invalid tenant group {invalid_chirho:?} must fail with the group refusal"
        );
    }
}

#[test]
fn signed_request_round_trips_with_exact_semantics_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let verified_chirho = fixture_chirho.verified_request_chirho();
    assert_eq!(
        verified_chirho.origin_node_id_chirho(),
        fixture_chirho.origin_id_chirho
    );
    assert_eq!(
        verified_chirho.target_node_id_chirho(),
        fixture_chirho.target_id_chirho
    );
    assert_eq!(verified_chirho.expected_term_chirho(), 7);
    assert_eq!(verified_chirho.method_chirho(), "POST");
    assert_eq!(
        verified_chirho.uri_chirho(),
        "/app-chirho/demo-chirho/spend-chirho?bounded=1"
    );
    assert_eq!(verified_chirho.body_chirho(), br#"{"amount_chirho":7}"#);
    assert_eq!(
        verified_chirho
            .end_to_end_headers_chirho()
            .iter_chirho()
            .count(),
        2
    );
}

#[test]
fn prepared_attempt_binds_the_exact_resolved_owner_group_and_term_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let attempt_chirho = PreparedServedWriteRelayAttemptChirho::new_chirho(
        fixture_chirho.signed_request_chirho(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .unwrap();
    assert!(!attempt_chirho.signed_request_wire_chirho().is_empty());
    assert_eq!(
        attempt_chirho.caller_key_digest_chirho(),
        fixture_chirho.caller_key_chirho.digest_hex_chirho()
    );
    attempt_chirho
        .require_resolution_chirho(
            &fixture_chirho.group_digest_chirho,
            &fixture_chirho.target_id_chirho,
            7,
        )
        .unwrap();

    let term_error_chirho = attempt_chirho
        .require_resolution_chirho(
            &fixture_chirho.group_digest_chirho,
            &fixture_chirho.target_id_chirho,
            8,
        )
        .expect_err("a moved term must invalidate the prepared relay attempt");
    assert_eq!(
        term_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho
    );
    assert_ne!(
        term_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayRecipientMismatchChirho
    );
}

#[test]
fn request_tamper_refuses_by_the_field_that_failed_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let signed_chirho = fixture_chirho.signed_request_chirho();
    let mut value_chirho = serde_json::to_value(&signed_chirho).unwrap();
    value_chirho["method_chirho"] = serde_json::Value::String("PUT".to_string());
    let wire_chirho = serde_json::to_vec(&value_chirho).unwrap();
    let error_chirho = decode_and_verify_served_write_relay_request_chirho(
        &wire_chirho,
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayRequestDigestMismatchChirho
    );
    assert_eq!(
        error_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
    );
    assert!(!error_chirho
        .to_string()
        .contains("private-relay-fixture-chirho"));

    let mut hop_value_chirho = serde_json::to_value(&signed_chirho).unwrap();
    hop_value_chirho["hop_count_chirho"] = serde_json::Value::from(2);
    let hop_error_chirho = decode_and_verify_served_write_relay_request_chirho(
        &serde_json::to_vec(&hop_value_chirho).unwrap(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        hop_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayHopInvalidChirho
    );
    assert_ne!(
        hop_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayRequestDigestMismatchChirho
    );
}

#[test]
fn request_binding_refusals_stay_distinct_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let wire_chirho = fixture_chirho
        .signed_request_chirho()
        .to_wire_bytes_chirho()
        .unwrap();
    let wrong_group_chirho = blake3::hash(b"other-group-chirho").to_hex().to_string();
    let authenticated_chirho = decode_and_authenticate_served_write_relay_request_chirho(
        &wire_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect("a rostered sender's exact signed request authenticates before destination binding");
    let group_error_chirho = authenticated_chirho
        .bind_destination_chirho(
            &wrong_group_chirho,
            &fixture_chirho.target_id_chirho,
            &fixture_chirho.roster_chirho,
        )
        .expect_error_chirho();
    assert_eq!(
        group_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho
    );
    assert_eq!(
        group_error_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho
    );

    let other_recipient_chirho =
        encode_hex_chirho(SigningKey::generate(&mut OsRng).verifying_key().as_bytes());
    let recipient_error_chirho = decode_and_verify_served_write_relay_request_chirho(
        &wire_chirho,
        &fixture_chirho.group_digest_chirho,
        &other_recipient_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        recipient_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayRecipientMismatchChirho
    );

    let target_only_roster_chirho =
        RelayRosterChirho::new_chirho(vec![fixture_chirho.target_id_chirho.clone()]).unwrap();
    let roster_error_chirho = decode_and_verify_served_write_relay_request_chirho(
        &wire_chirho,
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &target_only_roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        roster_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOriginUnrosteredChirho
    );
}

#[test]
fn wrong_request_signature_refuses_without_exposing_private_fields_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let signed_chirho = fixture_chirho.signed_request_chirho();
    let mut value_chirho = serde_json::to_value(&signed_chirho).unwrap();
    value_chirho["sig_hex_chirho"] = serde_json::Value::String("0".repeat(128));
    let error_chirho = decode_and_verify_served_write_relay_request_chirho(
        &serde_json::to_vec(&value_chirho).unwrap(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayRequestSignatureInvalidChirho
    );
    let rendered_key_chirho = format!("{:?}", fixture_chirho.caller_key_chirho);
    assert_eq!(
        rendered_key_chirho,
        "CallerIdempotencyKeyChirho(<redacted>)"
    );
    assert!(!rendered_key_chirho.contains("caller-operation"));
}

#[test]
fn unknown_request_fields_and_oversized_bodies_fail_closed_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let signed_chirho = fixture_chirho.signed_request_chirho();
    let mut value_chirho = serde_json::to_value(&signed_chirho).unwrap();
    value_chirho["invented_authority_chirho"] = serde_json::Value::Bool(true);
    let error_chirho = decode_and_verify_served_write_relay_request_chirho(
        &serde_json::to_vec(&value_chirho).unwrap(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayWireDecodeRefusedChirho
    );

    let oversized_error_chirho =
        PreparedServedWriteRelayRequestV1Chirho::new_chirho(ServedWriteRelayRequestInputChirho {
            ingress_admission_chirho: None,
            origin_node_id_chirho: fixture_chirho.origin_id_chirho.clone(),
            target_node_id_chirho: fixture_chirho.target_id_chirho.clone(),
            consistency_group_digest_chirho: fixture_chirho.group_digest_chirho.clone(),
            expected_term_chirho: 7,
            caller_idempotency_key_chirho: fixture_chirho.caller_key_chirho.clone(),
            method_chirho: "POST".to_string(),
            uri_chirho: "/invoke-chirho".to_string(),
            end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho(Vec::new())
                .unwrap(),
            body_chirho: vec![0; RELAY_BODY_MAX_BYTES_CHIRHO + 1],
            relay_budget_remaining_millis_chirho: 1,
        })
        .err()
        .expect("oversized request must refuse");
    assert_eq!(
        oversized_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayBodyTooLargeChirho
    );
}

#[test]
fn header_and_roster_construction_rejects_ambiguous_inputs_chirho() {
    let routing_header_error_chirho = RelayEndToEndHeadersChirho::try_request_chirho(vec![(
        "x-forwarded-for".to_string(),
        "127.0.0.1".to_string(),
    )])
    .expect_error_chirho();
    assert_eq!(
        routing_header_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayHeaderInvalidChirho
    );
    let unreviewed_header_error_chirho = RelayEndToEndHeadersChirho::try_request_chirho(vec![(
        "x-client-metadata-chirho".to_string(),
        "not-reviewed-chirho".to_string(),
    )])
    .expect_error_chirho();
    assert_eq!(
        unreviewed_header_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayHeaderInvalidChirho
    );
    assert!(
        RelayEndToEndHeadersChirho::try_response_chirho(vec![(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        )])
        .is_ok(),
        "a reviewed end-to-end response header must remain representable"
    );
    let repeated_headers_chirho = RelayEndToEndHeadersChirho::try_response_chirho(vec![
        (
            "set-cookie".to_string(),
            "session_chirho=first; Secure".to_string(),
        ),
        (
            "set-cookie".to_string(),
            "csrf_chirho=second; Secure".to_string(),
        ),
    ])
    .unwrap();
    assert_eq!(
        repeated_headers_chirho.iter_chirho().collect::<Vec<_>>(),
        vec![
            ("set-cookie", "session_chirho=first; Secure"),
            ("set-cookie", "csrf_chirho=second; Secure"),
        ],
        "repeated response headers must preserve exact per-name value order"
    );
    let member_chirho = "a".repeat(64);
    let roster_error_chirho =
        RelayRosterChirho::new_chirho(vec![member_chirho.clone(), member_chirho])
            .expect_error_chirho();
    assert_eq!(
        roster_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayOriginNodeInvalidChirho
    );
}

#[test]
fn request_digest_is_stable_across_header_insertion_order_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let build_chirho = |headers_chirho: Vec<(String, String)>| {
        PreparedServedWriteRelayRequestV1Chirho::new_chirho(ServedWriteRelayRequestInputChirho {
            ingress_admission_chirho: None,
            origin_node_id_chirho: fixture_chirho.origin_id_chirho.clone(),
            target_node_id_chirho: fixture_chirho.target_id_chirho.clone(),
            consistency_group_digest_chirho: fixture_chirho.group_digest_chirho.clone(),
            expected_term_chirho: 7,
            caller_idempotency_key_chirho: fixture_chirho.caller_key_chirho.clone(),
            method_chirho: "POST".to_string(),
            uri_chirho: "/invoke-chirho".to_string(),
            end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho(
                headers_chirho,
            )
            .unwrap(),
            body_chirho: b"same body chirho".to_vec(),
            relay_budget_remaining_millis_chirho: 1_000,
        })
        .unwrap()
        .signing_digest_chirho()
    };
    let first_chirho = build_chirho(vec![
        ("content-type".to_string(), "application/json".to_string()),
        (
            "authorization".to_string(),
            "Bearer same-chirho".to_string(),
        ),
    ]);
    let second_chirho = build_chirho(vec![
        (
            "authorization".to_string(),
            "Bearer same-chirho".to_string(),
        ),
        ("content-type".to_string(), "application/json".to_string()),
    ]);
    assert_eq!(first_chirho, second_chirho);
}

#[test]
fn request_uri_must_be_one_canonical_path_and_query_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let build_chirho = |uri_chirho: &str| {
        PreparedServedWriteRelayRequestV1Chirho::new_chirho(ServedWriteRelayRequestInputChirho {
            ingress_admission_chirho: None,
            origin_node_id_chirho: fixture_chirho.origin_id_chirho.clone(),
            target_node_id_chirho: fixture_chirho.target_id_chirho.clone(),
            consistency_group_digest_chirho: fixture_chirho.group_digest_chirho.clone(),
            expected_term_chirho: 7,
            caller_idempotency_key_chirho: fixture_chirho.caller_key_chirho.clone(),
            method_chirho: "POST".to_string(),
            uri_chirho: uri_chirho.to_string(),
            end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho(Vec::new())
                .unwrap(),
            body_chirho: Vec::new(),
            relay_budget_remaining_millis_chirho: 1_000,
        })
    };
    assert!(build_chirho("/invoke-chirho?name_chirho=Love%20Jesus").is_ok());
    for invalid_chirho in [
        "//invoke-chirho",
        "/a-chirho/../invoke-chirho",
        "/invoke-chirho?",
        "/invoke%2fhidden-chirho",
        "/invoke%2Fhidden-chirho",
        "/invoké-chirho",
    ] {
        let error_chirho = build_chirho(invalid_chirho).expect_error_chirho();
        assert_eq!(
            error_chirho.identity_chirho(),
            RelayRefusalIdentityChirho::RelayUriInvalidChirho,
            "{invalid_chirho}"
        );
    }
}

#[test]
fn signed_response_round_trips_and_binds_the_exact_request_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let verified_request_chirho = fixture_chirho.verified_request_chirho();
    let wire_chirho = fixture_chirho
        .signed_response_chirho()
        .to_wire_bytes_chirho()
        .unwrap();
    let verified_chirho = decode_and_verify_served_write_relay_response_chirho(
        &wire_chirho,
        verified_request_chirho.request_digest_chirho(),
        &fixture_chirho.caller_key_chirho.digest_hex_chirho(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .unwrap();
    assert_eq!(verified_chirho.status_chirho(), 200);
    assert_eq!(
        verified_chirho.outcome_class_chirho(),
        RelayOutcomeClassChirho::ServedResponseChirho
    );
    assert_eq!(
        verified_chirho.body_chirho(),
        b"<main>verified response chirho</main>"
    );

    let wrong_request_chirho = "f".repeat(64);
    let error_chirho = decode_and_verify_served_write_relay_response_chirho(
        &wire_chirho,
        &wrong_request_chirho,
        &fixture_chirho.caller_key_chirho.digest_hex_chirho(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho
    );
}

#[test]
fn prepared_attempt_accepts_only_the_exact_signed_term_change_exception_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let attempt_chirho = PreparedServedWriteRelayAttemptChirho::new_chirho(
        fixture_chirho.signed_request_chirho(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .unwrap();
    let build_response_chirho = |outcome_class_chirho, outcome_identity_chirho: Option<String>| {
        let prepared_chirho = PreparedServedWriteRelayResponseV1Chirho::new_chirho(
            ServedWriteRelayResponseInputChirho {
                request_digest_chirho: attempt_chirho.request_digest_chirho().to_string(),
                caller_idempotency_key_digest_chirho: attempt_chirho
                    .caller_key_digest_chirho()
                    .to_string(),
                responder_node_id_chirho: fixture_chirho.target_id_chirho.clone(),
                consistency_group_digest_chirho: fixture_chirho.group_digest_chirho.clone(),
                actual_term_chirho: 8,
                outcome_class_chirho,
                outcome_identity_chirho,
                status_chirho: 409,
                end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_response_chirho(
                    Vec::new(),
                )
                .unwrap(),
                body_chirho: Vec::new(),
            },
        )
        .unwrap();
        let signature_chirho = fixture_chirho
            .target_key_chirho
            .sign(&prepared_chirho.signing_digest_chirho());
        prepared_chirho
            .into_signed_chirho(encode_hex_chirho(&signature_chirho.to_bytes()))
            .unwrap()
            .to_wire_bytes_chirho()
            .unwrap()
    };
    let false_success_chirho =
        build_response_chirho(RelayOutcomeClassChirho::ServedResponseChirho, None);
    let false_success_error_chirho = attempt_chirho
        .verify_response_chirho(&false_success_chirho, &fixture_chirho.roster_chirho)
        .expect_error_chirho();
    assert_eq!(
        false_success_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayResponseAuthenticationRefusedChirho
    );
    assert_eq!(
        false_success_error_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::MayHaveExecutedChirho
    );

    let term_refusal_chirho = build_response_chirho(
        RelayOutcomeClassChirho::RelayRefusalChirho,
        Some(
            RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho
                .as_str_chirho()
                .to_string(),
        ),
    );
    let verified_chirho = attempt_chirho
        .verify_response_chirho(&term_refusal_chirho, &fixture_chirho.roster_chirho)
        .expect("the exact signed term-change refusal is the only moved-term exception");
    assert_eq!(verified_chirho.actual_term_chirho(), 8);
}

#[test]
fn response_tamper_and_outcome_mismatch_refuse_by_name_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let verified_request_chirho = fixture_chirho.verified_request_chirho();
    let signed_chirho = fixture_chirho.signed_response_chirho();
    let mut tampered_chirho = serde_json::to_value(&signed_chirho).unwrap();
    tampered_chirho["status_chirho"] = serde_json::Value::from(201);
    let error_chirho = decode_and_verify_served_write_relay_response_chirho(
        &serde_json::to_vec(&tampered_chirho).unwrap(),
        verified_request_chirho.request_digest_chirho(),
        &fixture_chirho.caller_key_chirho.digest_hex_chirho(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayResponseDigestMismatchChirho
    );
    assert_eq!(
        error_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::MayHaveExecutedChirho
    );

    let malformed_chirho = decode_and_verify_served_write_relay_response_chirho(
        b"not-json-chirho",
        verified_request_chirho.request_digest_chirho(),
        &fixture_chirho.caller_key_chirho.digest_hex_chirho(),
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
    .expect_error_chirho();
    assert_eq!(
        malformed_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayWireDecodeRefusedChirho
    );
    assert_eq!(
        malformed_chirho.execution_knowledge_chirho(),
        RelayExecutionKnowledgeChirho::MayHaveExecutedChirho,
        "the public response verifier must upgrade every current and future inner error"
    );

    let outcome_error_chirho =
        PreparedServedWriteRelayResponseV1Chirho::new_chirho(ServedWriteRelayResponseInputChirho {
            request_digest_chirho: verified_request_chirho.request_digest_chirho().to_string(),
            caller_idempotency_key_digest_chirho: fixture_chirho
                .caller_key_chirho
                .digest_hex_chirho(),
            responder_node_id_chirho: fixture_chirho.target_id_chirho.clone(),
            consistency_group_digest_chirho: fixture_chirho.group_digest_chirho.clone(),
            actual_term_chirho: 7,
            outcome_class_chirho: RelayOutcomeClassChirho::DoorRefusalChirho,
            outcome_identity_chirho: None,
            status_chirho: 409,
            end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_response_chirho(Vec::new())
                .unwrap(),
            body_chirho: b"named refusal missing chirho".to_vec(),
        })
        .err()
        .expect("door refusal without identity must refuse");
    assert_eq!(
        outcome_error_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayResponseOutcomeInvalidChirho
    );

    for (outcome_class_chirho, outcome_identity_chirho, body_chirho) in [
        (
            RelayOutcomeClassChirho::DoorRefusalChirho,
            "ElectedAuthorityDeposedChirho",
            b"error: ElectedAuthorityExpiredChirho\n".to_vec(),
        ),
        (
            RelayOutcomeClassChirho::RelayRefusalChirho,
            "UnknownRelayOutcomeChirho",
            Vec::new(),
        ),
    ] {
        let error_chirho = PreparedServedWriteRelayResponseV1Chirho::new_chirho(
            ServedWriteRelayResponseInputChirho {
                request_digest_chirho: verified_request_chirho.request_digest_chirho().to_string(),
                caller_idempotency_key_digest_chirho: fixture_chirho
                    .caller_key_chirho
                    .digest_hex_chirho(),
                responder_node_id_chirho: fixture_chirho.target_id_chirho.clone(),
                consistency_group_digest_chirho: fixture_chirho.group_digest_chirho.clone(),
                actual_term_chirho: 7,
                outcome_class_chirho,
                outcome_identity_chirho: Some(outcome_identity_chirho.to_string()),
                status_chirho: 409,
                end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_response_chirho(
                    Vec::new(),
                )
                .unwrap(),
                body_chirho,
            },
        )
        .expect_error_chirho();
        assert_eq!(
            error_chirho.identity_chirho(),
            RelayRefusalIdentityChirho::RelayResponseOutcomeInvalidChirho
        );
    }
}

#[test]
fn caller_keys_are_bounded_opaque_and_domain_separated_chirho() {
    let first_chirho = CallerIdempotencyKeyChirho::new_chirho("same-visible-key-chirho").unwrap();
    let second_chirho = CallerIdempotencyKeyChirho::new_chirho("other-visible-key-chirho").unwrap();
    assert_ne!(
        first_chirho.digest_hex_chirho(),
        blake3::hash(first_chirho.as_str_chirho().as_bytes())
            .to_hex()
            .to_string()
    );
    assert_ne!(
        first_chirho.digest_hex_chirho(),
        second_chirho.digest_hex_chirho()
    );
    let invalid_chirho =
        CallerIdempotencyKeyChirho::new_chirho("line\nbreak-chirho").expect_error_chirho();
    assert_eq!(
        invalid_chirho.identity_chirho(),
        RelayRefusalIdentityChirho::RelayCallerKeyInvalidChirho
    );
}

#[test]
fn caller_operation_binding_is_bounded_opaque_and_domain_separated_chirho() {
    let first_chirho = CallerOperationBindingChirho::new_chirho(
        "POST",
        "/app-chirho/credits-demo-chirho/spend-chirho?bounded=1",
    )
    .unwrap();
    let changed_method_chirho = CallerOperationBindingChirho::new_chirho(
        "GET",
        "/app-chirho/credits-demo-chirho/spend-chirho?bounded=1",
    )
    .unwrap();
    let changed_uri_chirho = CallerOperationBindingChirho::new_chirho(
        "POST",
        "/app-chirho/credits-demo-chirho/spend-chirho?bounded=2",
    )
    .unwrap();
    assert_ne!(
        first_chirho.digest_hex_chirho(),
        changed_method_chirho.digest_hex_chirho()
    );
    assert_ne!(
        first_chirho.digest_hex_chirho(),
        changed_uri_chirho.digest_hex_chirho()
    );
    assert_eq!(
        format!("{first_chirho:?}"),
        "CallerOperationBindingChirho(<redacted>)"
    );
    assert_eq!(
        CallerOperationBindingChirho::new_chirho(
            "post",
            "/app-chirho/credits-demo-chirho/spend-chirho"
        )
        .expect_error_chirho()
        .identity_chirho(),
        RelayRefusalIdentityChirho::RelayMethodInvalidChirho
    );
}

#[test]
fn contract_manifest_has_no_authority_or_transport_dependency_chirho() {
    let manifest_chirho =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    for forbidden_chirho in [
        "cairn-writer-head-chirho",
        "cairn-writer-elector-chirho",
        "cairn-durable-chirho",
        "cairn-signer-chirho",
        "axum",
        "tokio",
    ] {
        assert!(
            !manifest_chirho.contains(forbidden_chirho),
            "relay contract acquired forbidden dependency {forbidden_chirho}"
        );
    }
    for source_chirho in [
        include_str!("../protocol_chirho.rs"),
        include_str!("../port_chirho.rs"),
    ] {
        for forbidden_chirho in [
            "std::path::Path",
            "PreparedElectedWriterFenceChirho",
            "CommitReady",
            "with_head_transition_scope_chirho",
        ] {
            assert!(
                !source_chirho.contains(forbidden_chirho),
                "relay contract acquired authority-bearing surface {forbidden_chirho}"
            );
        }
    }
}

fn encode_hex_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        encoded_chirho.push(HEX_CHIRHO[(byte_chirho >> 4) as usize] as char);
        encoded_chirho.push(HEX_CHIRHO[(byte_chirho & 0x0f) as usize] as char);
    }
    encoded_chirho
}
