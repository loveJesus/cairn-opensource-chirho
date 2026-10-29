// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

fn admission_chirho() -> RelayIngressAdmissionChirho {
    RelayIngressAdmissionChirho::new_chirho(60_000, 60, 8 * 1024 * 1024, 300, 32 * 1024 * 1024)
        .expect("bounded source admission")
}

fn signed_admission_chirho(fixture_chirho: &RelayFixtureChirho) -> ServedWriteRelayRequestV1Chirho {
    let mut request_chirho = fixture_chirho.signed_request_chirho();
    request_chirho.ingress_admission_chirho = Some(admission_chirho());
    request_chirho.request_digest_chirho = request_digest_hex_chirho(&request_chirho);
    request_chirho.sig_hex_chirho = encode_hex_chirho(
        &fixture_chirho
            .origin_key_chirho
            .sign(
                &decode_hex_32_chirho(&request_chirho.request_digest_chirho)
                    .expect("request digest"),
            )
            .to_bytes(),
    );
    request_chirho
}

fn verify_wire_chirho(
    fixture_chirho: &RelayFixtureChirho,
    wire_chirho: &[u8],
) -> Result<VerifiedServedWriteRelayRequestChirho, RelayContractErrorChirho> {
    decode_and_verify_served_write_relay_request_chirho(
        wire_chirho,
        &fixture_chirho.group_digest_chirho,
        &fixture_chirho.target_id_chirho,
        &fixture_chirho.roster_chirho,
    )
}

#[test]
fn every_signed_admission_coordinate_is_bound_to_this_request_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let signed_chirho = signed_admission_chirho(&fixture_chirho);
    let wire_chirho = signed_chirho.to_wire_bytes_chirho().expect("signed wire");
    let verified_chirho =
        verify_wire_chirho(&fixture_chirho, &wire_chirho).expect("verified admission");
    assert_eq!(
        verified_chirho.ingress_admission_chirho(),
        Some(&admission_chirho())
    );
    for field_chirho in [
        "window_ms_chirho",
        "source_max_requests_chirho",
        "source_max_body_bytes_chirho",
        "ingress_max_requests_chirho",
        "ingress_max_body_bytes_chirho",
    ] {
        let mut value_chirho: serde_json::Value = serde_json::from_slice(&wire_chirho).unwrap();
        let old_chirho = value_chirho["ingress_admission_chirho"][field_chirho]
            .as_u64()
            .unwrap();
        value_chirho["ingress_admission_chirho"][field_chirho] = (old_chirho + 1).into();
        let error_chirho =
            verify_wire_chirho(&fixture_chirho, &serde_json::to_vec(&value_chirho).unwrap())
                .expect_error_chirho();
        assert_eq!(
            error_chirho.identity_chirho(),
            RelayRefusalIdentityChirho::RelayRequestDigestMismatchChirho,
            "{field_chirho}"
        );
    }
    let mut copied_chirho = fixture_chirho.signed_request_chirho();
    copied_chirho.ingress_admission_chirho = Some(admission_chirho());
    assert_eq!(
        verify_wire_chirho(
            &fixture_chirho,
            &copied_chirho.to_wire_bytes_chirho().unwrap()
        )
        .expect_error_chirho()
        .identity_chirho(),
        RelayRefusalIdentityChirho::RelayRequestDigestMismatchChirho,
        "an assertion cannot be lifted onto a separately signed legacy request"
    );
}

#[test]
fn legacy_absence_decodes_but_unknown_or_zero_admission_does_not_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let legacy_chirho = fixture_chirho
        .signed_request_chirho()
        .to_wire_bytes_chirho()
        .unwrap();
    assert!(!String::from_utf8_lossy(&legacy_chirho).contains("ingress_admission_chirho"));
    assert!(verify_wire_chirho(&fixture_chirho, &legacy_chirho)
        .unwrap()
        .ingress_admission_chirho()
        .is_none());
    let wire_chirho = signed_admission_chirho(&fixture_chirho)
        .to_wire_bytes_chirho()
        .unwrap();
    let mut value_chirho: serde_json::Value = serde_json::from_slice(&wire_chirho).unwrap();
    value_chirho["ingress_admission_chirho"]["policy_chirho"] = "UnknownPolicyChirho".into();
    assert_eq!(
        verify_wire_chirho(&fixture_chirho, &serde_json::to_vec(&value_chirho).unwrap())
            .expect_error_chirho()
            .identity_chirho(),
        RelayRefusalIdentityChirho::RelayWireDecodeRefusedChirho
    );
    value_chirho["ingress_admission_chirho"]["policy_chirho"] = "NetworkSourceV1Chirho".into();
    value_chirho["ingress_admission_chirho"]["ingress_max_requests_chirho"] = 0.into();
    assert_eq!(
        verify_wire_chirho(&fixture_chirho, &serde_json::to_vec(&value_chirho).unwrap())
            .expect_error_chirho()
            .identity_chirho(),
        RelayRefusalIdentityChirho::RelayIngressAdmissionInvalidChirho
    );
}

#[test]
fn a_scope_binds_the_owner_group_and_exact_authorised_origin_population_chirho() {
    let fixture_chirho = RelayFixtureChirho::new_chirho();
    let request_chirho = verify_wire_chirho(
        &fixture_chirho,
        &signed_admission_chirho(&fixture_chirho)
            .to_wire_bytes_chirho()
            .unwrap(),
    )
    .unwrap();
    let scope_chirho = RelayIngressScopeChirho::new_chirho(
        fixture_chirho.target_id_chirho.clone(),
        fixture_chirho.group_digest_chirho.clone(),
        &fixture_chirho.roster_chirho,
    )
    .unwrap();
    assert_eq!(scope_chirho.origin_count_chirho(), 2);
    assert!(scope_chirho.accepts_request_chirho(&request_chirho));
    let other_chirho = encode_hex_chirho(
        SigningKey::from_bytes(&[0x65; 32])
            .verifying_key()
            .as_bytes(),
    );
    let different_roster_chirho = RelayRosterChirho::new_chirho([
        fixture_chirho.origin_id_chirho.clone(),
        fixture_chirho.target_id_chirho.clone(),
        other_chirho,
    ])
    .unwrap();
    let changed_chirho = RelayIngressScopeChirho::new_chirho(
        fixture_chirho.target_id_chirho.clone(),
        fixture_chirho.group_digest_chirho.clone(),
        &different_roster_chirho,
    )
    .unwrap();
    assert!(!changed_chirho.accepts_request_chirho(&request_chirho));
    let wrong_owner_chirho = RelayIngressScopeChirho::new_chirho(
        fixture_chirho.origin_id_chirho.clone(),
        fixture_chirho.group_digest_chirho.clone(),
        &fixture_chirho.roster_chirho,
    )
    .unwrap();
    assert!(!wrong_owner_chirho.accepts_request_chirho(&request_chirho));
}
