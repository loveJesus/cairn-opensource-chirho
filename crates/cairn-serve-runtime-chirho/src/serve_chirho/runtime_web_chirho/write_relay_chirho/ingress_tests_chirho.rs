// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::ServedRequestAbuseLimitsChirho;

#[tokio::test]
async fn verified_destination_repeats_admission_before_any_local_execution_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("destination-admission");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).expect("tenant root");
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .expect("geo-latch tenant root");
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::OwnerUnknownChirho);
    let limits_chirho = ServedRequestAbuseLimitsChirho {
        actor_max_body_bytes_chirho: 1,
        global_max_body_bytes_chirho: 2,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    let state_chirho =
        state_with_dispatch_and_limits_chirho(&root_chirho, dispatch_chirho.clone(), limits_chirho);
    let slot_chirho = ServedWriteRelayDestinationSlotChirho::new_chirho();
    install_relay_destination_chirho(&slot_chirho, state_chirho)
        .expect("install process-local destination once");
    let request_chirho = verified_relay_request_chirho(b"too-large-chirho".to_vec());

    let response_chirho = slot_chirho.execute_verified_chirho(&request_chirho).await;
    let (class_chirho, identity_chirho, status_chirho, headers_chirho, body_chirho) =
        response_chirho.into_parts_chirho();

    assert_eq!(
        class_chirho,
        cairn_write_relay_chirho::RelayOutcomeClassChirho::ServedResponseChirho
    );
    assert!(identity_chirho.is_none());
    assert_eq!(status_chirho, StatusCode::TOO_MANY_REQUESTS.as_u16());
    assert_eq!(body_chirho, b"served request unavailable\n");
    assert!(!headers_chirho
        .iter_chirho()
        .any(|(name_chirho, _)| name_chirho == "set-cookie"));
    assert_eq!(
        dispatch_chirho.calls_chirho(),
        0,
        "destination admission must refuse before reentry can reach dispatch or local selection"
    );
}

#[tokio::test]
async fn a_signed_request_without_ingress_evidence_refuses_before_any_root_read_chirho() {
    let (_platform_chirho, state_chirho, dispatch_chirho) = elected_spend_state_chirho(
        "missing-ingress",
        StubDispatchOutcomeChirho::ExecuteLocallyChirho,
    );
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho();
    std::fs::write(
        root_chirho.join("refs-chirho.json"),
        b"unreadable refs-chirho",
    )
    .unwrap();
    let before_chirho = snapshot_files_chirho(root_chirho);
    let slot_chirho = ServedWriteRelayDestinationSlotChirho::new_chirho();
    install_relay_destination_chirho(&slot_chirho, state_chirho.clone()).unwrap();
    let request_chirho = verified_relay_request_with_ingress_chirho(Vec::new(), None);
    let (_, identity_chirho, _, _, _) = slot_chirho
        .execute_verified_chirho(&request_chirho)
        .await
        .into_parts_chirho();
    assert_eq!(
        identity_chirho.as_deref(),
        Some("RelayIngressAdmissionInvalidChirho")
    );
    assert_eq!(dispatch_chirho.calls_chirho(), 0);
    assert_eq!(snapshot_files_chirho(root_chirho), before_chirho);
}

#[test]
fn a_reentry_marker_yields_its_ingress_custody_only_once_chirho() {
    let (_platform_chirho, state_chirho, _dispatch_chirho) = elected_spend_state_chirho(
        "affine-reentry",
        StubDispatchOutcomeChirho::ExecuteLocallyChirho,
    );
    let capacity_chirho = state_chirho.inflight_chirho.available_permits();
    let ingress_chirho = state_chirho
        .served_request_abuse_gate_chirho
        .admit_ingress_chirho(
            state_chirho.inflight_chirho.clone(),
            None,
            &HeaderMap::new(),
            0,
        )
        .unwrap();
    let marker_chirho = RelayedRequestMarkerChirho::from_verified_chirho(
        &verified_relay_request_chirho(Vec::new()),
        ingress_chirho,
    )
    .unwrap();
    let taken_chirho = marker_chirho.take_ingress_chirho().unwrap();
    assert!(marker_chirho.take_ingress_chirho().is_err());
    drop(
        state_chirho
            .served_request_abuse_gate_chirho
            .promote_ingress_chirho(taken_chirho, None)
            .unwrap(),
    );
    assert_eq!(
        state_chirho.inflight_chirho.available_permits(),
        capacity_chirho
    );
}

#[tokio::test]
async fn an_owner_ingress_429_negotiates_from_accept_without_route_lookup_chirho() {
    let platform_chirho = TestPlatformRootChirho::new_chirho("json-ingress");
    let root_chirho = tenant_root_chirho(platform_chirho.path_chirho());
    std::fs::create_dir_all(&root_chirho).unwrap();
    cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho(
        &root_chirho,
        7,
    )
    .unwrap();
    std::fs::write(root_chirho.join("refs-chirho.json"), b"invalid refs-chirho").unwrap();
    let dispatch_chirho =
        StubDispatchChirho::new_chirho(StubDispatchOutcomeChirho::ExecuteLocallyChirho);
    let state_chirho = state_with_dispatch_and_limits_chirho(
        &root_chirho,
        dispatch_chirho.clone(),
        ServedRequestAbuseLimitsChirho {
            actor_max_body_bytes_chirho: 1,
            global_max_body_bytes_chirho: 2,
            ..Default::default()
        },
    );
    let before_chirho = snapshot_files_chirho(&root_chirho);
    let slot_chirho = ServedWriteRelayDestinationSlotChirho::new_chirho();
    install_relay_destination_chirho(&slot_chirho, state_chirho).unwrap();
    let request_chirho = verified_relay_request_with_headers_chirho(
        b"exceeds-one-byte-chirho".to_vec(),
        Some(RelayIngressAdmissionChirho::new_chirho(60_000, 60, 1, 300, 1).unwrap()),
        RelayEndToEndHeadersChirho::try_request_chirho([(
            "accept".to_string(),
            "application/json".to_string(),
        )])
        .unwrap(),
    );
    let (class_chirho, identity_chirho, status_chirho, headers_chirho, body_chirho) = slot_chirho
        .execute_verified_chirho(&request_chirho)
        .await
        .into_parts_chirho();
    assert_eq!(class_chirho, RelayOutcomeClassChirho::ServedResponseChirho);
    assert!(identity_chirho.is_none());
    assert_eq!(status_chirho, 429);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body_chirho).unwrap(),
        serde_json::json!({"ok_chirho": false, "error_chirho": "served-request-unavailable-chirho"})
    );
    assert!(headers_chirho
        .iter_chirho()
        .any(|(name_chirho, value_chirho)| name_chirho == "content-type"
            && value_chirho == "application/json"));
    assert!(headers_chirho
        .iter_chirho()
        .any(|(name_chirho, value_chirho)| name_chirho == "retry-after" && value_chirho == "60"));
    assert!(!headers_chirho
        .iter_chirho()
        .any(|(name_chirho, _)| name_chirho == "set-cookie"));
    assert_eq!(dispatch_chirho.calls_chirho(), 0);
    assert_eq!(snapshot_files_chirho(&root_chirho), before_chirho);
}
