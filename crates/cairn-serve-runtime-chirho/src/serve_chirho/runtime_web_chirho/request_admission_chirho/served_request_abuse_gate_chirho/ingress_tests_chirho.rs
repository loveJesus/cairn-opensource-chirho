// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_write_relay_chirho::{
    decode_and_verify_served_write_relay_request_chirho, CallerIdempotencyKeyChirho,
    PreparedServedWriteRelayRequestV1Chirho, RelayEndToEndHeadersChirho, RelayRosterChirho,
    ServedWriteRelayRequestInputChirho, VerifiedServedWriteRelayRequestChirho,
};
use ed25519_dalek::{Signer as _, SigningKey};

fn limits_chirho() -> ServedRequestAbuseLimitsChirho {
    ServedRequestAbuseLimitsChirho {
        window_ms_chirho: 1_000,
        actor_max_requests_chirho: 1,
        actor_max_body_bytes_chirho: 10,
        global_max_requests_chirho: 8,
        global_max_body_bytes_chirho: 80,
        actor_bucket_cap_chirho: 32,
        ..Default::default()
    }
}

fn peer_chirho(index_chirho: u8) -> Option<SocketAddr> {
    Some(SocketAddr::from(([192, 0, 2, index_chirho], 41000)))
}

fn hex_chirho(bytes_chirho: &[u8]) -> String {
    bytes_chirho
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

fn verified_ingress_chirho(
    admission_chirho: Option<RelayIngressAdmissionChirho>,
) -> (
    VerifiedServedWriteRelayRequestChirho,
    RelayIngressScopeChirho,
) {
    verified_ingress_with_body_chirho(admission_chirho, Vec::new())
}

fn verified_ingress_with_body_chirho(
    admission_chirho: Option<RelayIngressAdmissionChirho>,
    body_chirho: Vec<u8>,
) -> (
    VerifiedServedWriteRelayRequestChirho,
    RelayIngressScopeChirho,
) {
    let origin_chirho = SigningKey::from_bytes(&[0x31; 32]);
    let target_chirho = SigningKey::from_bytes(&[0x52; 32]);
    let origin_id_chirho = hex_chirho(origin_chirho.verifying_key().as_bytes());
    let target_id_chirho = hex_chirho(target_chirho.verifying_key().as_bytes());
    let group_chirho = blake3::hash(b"ingress-test-group-chirho")
        .to_hex()
        .to_string();
    let roster_chirho =
        RelayRosterChirho::new_chirho([origin_id_chirho.clone(), target_id_chirho.clone()])
            .unwrap();
    let prepared_chirho =
        PreparedServedWriteRelayRequestV1Chirho::new_chirho(ServedWriteRelayRequestInputChirho {
            origin_node_id_chirho: origin_id_chirho,
            target_node_id_chirho: target_id_chirho.clone(),
            consistency_group_digest_chirho: group_chirho.clone(),
            expected_term_chirho: 7,
            caller_idempotency_key_chirho: CallerIdempotencyKeyChirho::new_chirho(
                "ingress-operation-chirho",
            )
            .unwrap(),
            method_chirho: if body_chirho.is_empty() {
                "GET"
            } else {
                "POST"
            }
            .to_string(),
            uri_chirho: "/app-chirho/test-chirho/view-chirho".to_string(),
            end_to_end_headers_chirho: RelayEndToEndHeadersChirho::try_request_chirho([]).unwrap(),
            body_chirho,
            relay_budget_remaining_millis_chirho: 1000,
            ingress_admission_chirho: admission_chirho,
        })
        .unwrap();
    let signature_chirho = hex_chirho(
        &origin_chirho
            .sign(&prepared_chirho.signing_digest_chirho())
            .to_bytes(),
    );
    let wire_chirho = prepared_chirho
        .into_signed_chirho(signature_chirho)
        .unwrap()
        .to_wire_bytes_chirho()
        .unwrap();
    let request_chirho = decode_and_verify_served_write_relay_request_chirho(
        &wire_chirho,
        &group_chirho,
        &target_id_chirho,
        &roster_chirho,
    )
    .unwrap();
    let scope_chirho =
        RelayIngressScopeChirho::new_chirho(target_id_chirho, group_chirho, &roster_chirho)
            .unwrap();
    (request_chirho, scope_chirho)
}

#[test]
fn a_zero_origin_share_refuses_construction_chirho() {
    let (_, scope_chirho) = verified_ingress_chirho(None);
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        global_max_requests_chirho: 1,
        ..limits_chirho()
    };
    assert!(ServedRequestAbuseGateChirho::with_relay_scope_chirho(
        limits_chirho,
        Some(scope_chirho)
    )
    .is_err());
}

#[test]
fn ingress_promotion_uses_one_slot_and_one_rate_charge_chirho() {
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(ServedRequestAbuseLimitsChirho {
        global_max_requests_chirho: 1,
        ..limits_chirho()
    })
    .unwrap();
    let inflight_chirho = Arc::new(Semaphore::new(1));
    let ingress_chirho = gate_chirho
        .admit_ingress_at_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(1),
            &HeaderMap::new(),
            1,
            0,
        )
        .unwrap();
    let admitted_chirho = gate_chirho
        .promote_ingress_at_chirho(ingress_chirho, Some("user/verified-chirho"), 1)
        .unwrap();
    assert_eq!(inflight_chirho.available_permits(), 0);
    drop(admitted_chirho);
    assert_eq!(inflight_chirho.available_permits(), 1);
    assert!(
        gate_chirho
            .admit_ingress_at_chirho(
                Arc::clone(&inflight_chirho),
                peer_chirho(2),
                &HeaderMap::new(),
                1,
                2
            )
            .is_err(),
        "the one global charge remains, without a second promotion charge"
    );
}

#[test]
fn dropping_failed_auth_custody_frees_concurrency_but_keeps_the_rate_charge_chirho() {
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(limits_chirho()).unwrap();
    let inflight_chirho = Arc::new(Semaphore::new(1));
    let ingress_chirho = gate_chirho
        .admit_ingress_at_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(1),
            &HeaderMap::new(),
            1,
            0,
        )
        .unwrap();
    drop(ingress_chirho);
    assert_eq!(inflight_chirho.available_permits(), 1);
    assert!(gate_chirho
        .admit_ingress_at_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(1),
            &HeaderMap::new(),
            1,
            1
        )
        .is_err());
    let other_chirho = gate_chirho
        .admit_ingress_at_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(2),
            &HeaderMap::new(),
            1,
            1,
        )
        .unwrap();
    drop(other_chirho);
    assert_eq!(inflight_chirho.available_permits(), 1);
}

#[test]
fn a_principal_is_charged_at_promotion_time_not_old_ingress_time_chirho() {
    let gate_chirho = ServedRequestAbuseGateChirho::new_chirho(limits_chirho()).unwrap();
    let inflight_chirho = Arc::new(Semaphore::new(2));
    let old_chirho = gate_chirho
        .admit_ingress_at_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(1),
            &HeaderMap::new(),
            1,
            0,
        )
        .unwrap();
    drop(
        gate_chirho
            .promote_ingress_at_chirho(old_chirho, Some("user/verified-chirho"), 1000)
            .unwrap(),
    );
    let new_chirho = gate_chirho
        .admit_ingress_at_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(2),
            &HeaderMap::new(),
            1,
            1001,
        )
        .unwrap();
    assert!(gate_chirho
        .promote_ingress_at_chirho(new_chirho, Some("user/verified-chirho"), 1001)
        .is_err());
    assert_eq!(inflight_chirho.available_permits(), 2);
}

#[test]
fn a_foreign_gate_cannot_promote_an_admission_chirho() {
    let first_chirho = ServedRequestAbuseGateChirho::new_chirho(limits_chirho()).unwrap();
    let second_chirho = ServedRequestAbuseGateChirho::new_chirho(limits_chirho()).unwrap();
    let inflight_chirho = Arc::new(Semaphore::new(1));
    let ingress_chirho = first_chirho
        .admit_ingress_at_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(1),
            &HeaderMap::new(),
            0,
            0,
        )
        .unwrap();
    assert!(second_chirho
        .promote_ingress_at_chirho(ingress_chirho, Some("user/verified-chirho"), 1)
        .is_err());
    assert_eq!(inflight_chirho.available_permits(), 1);
    assert_eq!(second_chirho.actor_bucket_count_for_test_chirho(), 0);
}

#[test]
fn a_signed_high_ceiling_cannot_spend_the_owners_reserved_origin_share_chirho() {
    let assertion_chirho =
        RelayIngressAdmissionChirho::new_chirho(1000, 1, 10, u64::MAX, u64::MAX).unwrap();
    let (request_chirho, scope_chirho) = verified_ingress_chirho(Some(assertion_chirho));
    let gate_chirho =
        ServedRequestAbuseGateChirho::with_relay_scope_chirho(limits_chirho(), Some(scope_chirho))
            .unwrap();
    let inflight_chirho = Arc::new(Semaphore::new(1));
    for _index_chirho in 0..4 {
        drop(
            gate_chirho
                .admit_relay_ingress_chirho(Arc::clone(&inflight_chirho), &request_chirho)
                .unwrap(),
        );
    }
    assert!(
        gate_chirho
            .admit_relay_ingress_chirho(Arc::clone(&inflight_chirho), &request_chirho)
            .is_err(),
        "the signed ceiling cannot buy a fifth request out of the owner's share"
    );
    for index_chirho in 1..=4 {
        drop(
            gate_chirho
                .admit_ingress_chirho(
                    Arc::clone(&inflight_chirho),
                    peer_chirho(index_chirho),
                    &HeaderMap::new(),
                    0,
                )
                .unwrap(),
        );
    }
    assert!(gate_chirho
        .admit_ingress_chirho(
            Arc::clone(&inflight_chirho),
            peer_chirho(5),
            &HeaderMap::new(),
            0
        )
        .is_err());
}

#[test]
fn missing_or_weaker_signed_source_policy_is_not_an_ingress_permit_chirho() {
    for assertion_chirho in [
        None,
        Some(RelayIngressAdmissionChirho::new_chirho(2000, 1, 10, 4, 40).unwrap()),
        Some(RelayIngressAdmissionChirho::new_chirho(1000, 2, 10, 4, 40).unwrap()),
    ] {
        let (request_chirho, scope_chirho) = verified_ingress_chirho(assertion_chirho);
        let gate_chirho = ServedRequestAbuseGateChirho::with_relay_scope_chirho(
            limits_chirho(),
            Some(scope_chirho),
        )
        .unwrap();
        assert!(!gate_chirho.accepts_relay_ingress_chirho(&request_chirho));
        let inflight_chirho = Arc::new(Semaphore::new(1));
        assert!(gate_chirho
            .admit_relay_ingress_chirho(Arc::clone(&inflight_chirho), &request_chirho)
            .is_err());
        assert_eq!(inflight_chirho.available_permits(), 1);
        assert_eq!(gate_chirho.actor_bucket_count_for_test_chirho(), 0);
    }
}

#[test]
fn the_origin_byte_share_is_clamped_independently_of_its_request_share_chirho() {
    let assertion_chirho =
        RelayIngressAdmissionChirho::new_chirho(1000, 1, 10, u64::MAX, u64::MAX).unwrap();
    let (request_chirho, scope_chirho) =
        verified_ingress_with_body_chirho(Some(assertion_chirho), vec![b'x'; 5]);
    let gate_chirho = ServedRequestAbuseGateChirho::with_relay_scope_chirho(
        ServedRequestAbuseLimitsChirho {
            global_max_body_bytes_chirho: 20,
            ..limits_chirho()
        },
        Some(scope_chirho),
    )
    .unwrap();
    let inflight_chirho = Arc::new(Semaphore::new(1));
    for _index_chirho in 0..2 {
        drop(
            gate_chirho
                .admit_relay_ingress_chirho(Arc::clone(&inflight_chirho), &request_chirho)
                .unwrap(),
        );
    }
    assert!(
        gate_chirho
            .admit_relay_ingress_chirho(Arc::clone(&inflight_chirho), &request_chirho)
            .is_err(),
        "a third 5-byte request exceeds the origin's 10-byte share before its four-request share"
    );
    assert_eq!(inflight_chirho.available_permits(), 1);
}
