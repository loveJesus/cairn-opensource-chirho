// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;

async fn get_from_peer_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: &str,
) -> ResponsePartsChirho {
    get_from_peer_with_headers_chirho(state_chirho, peer_chirho, headers_chirho()).await
}

async fn get_from_peer_with_headers_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: &str,
    headers_chirho: HeaderMap,
) -> ResponsePartsChirho {
    response_parts_chirho(
        app_http_chirho::app_route_get_chirho(
            State(state_chirho.clone()),
            Some(ConnectInfo(
                peer_chirho.parse::<SocketAddr>().expect("test peer"),
            )),
            headers_chirho,
            AxPath((APP_CHIRHO.to_string(), ROUTE_CHIRHO.to_string())),
            OriginalUri(
                format!("/app-chirho/{APP_CHIRHO}/{ROUTE_CHIRHO}")
                    .parse()
                    .expect("named GET URI"),
            ),
        )
        .await,
    )
    .await
}

fn source_limits_chirho() -> serve_chirho::ServedRequestAbuseLimitsChirho {
    serve_chirho::ServedRequestAbuseLimitsChirho {
        actor_max_requests_chirho: 1,
        global_max_requests_chirho: 8,
        ..Default::default()
    }
}

fn follower_chirho(
    fixture_chirho: &FixtureChirho,
    transport_chirho: Arc<SignedTransportChirho>,
    limits_chirho: serve_chirho::ServedRequestAbuseLimitsChirho,
) -> AppStateChirho {
    fixture_chirho.latch_chirho();
    corrupt_follower_chirho(fixture_chirho);
    state_chirho(
        fixture_chirho,
        transport_chirho,
        AuthorityChirho::new_chirho(Some(0)),
        limits_chirho,
    )
}

#[tokio::test]
async fn distinct_follower_peers_do_not_share_the_owner_unknown_network_bucket_chirho() {
    let owner_chirho = FixtureChirho::new_chirho(Vec::new());
    owner_chirho.latch_chirho();
    let owner_state_chirho = state_chirho(
        &owner_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        source_limits_chirho(),
    );
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho)
        .expect("owner destination");
    let transport_chirho =
        SignedTransportChirho::new_chirho(slot_chirho, TransportModeChirho::DeliverChirho);
    let follower_fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    let follower_state_chirho = follower_chirho(
        &follower_fixture_chirho,
        transport_chirho.clone(),
        source_limits_chirho(),
    );
    let owner_before_chirho = owner_chirho.snapshot_chirho();
    let follower_before_chirho = follower_fixture_chirho.snapshot_chirho();
    let first_chirho = get_from_peer_chirho(&follower_state_chirho, "192.0.2.10:41000").await;
    let second_chirho = get_from_peer_chirho(&follower_state_chirho, "192.0.2.11:41001").await;
    assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
    assert_eq!(
        follower_fixture_chirho.snapshot_chirho(),
        follower_before_chirho
    );
    assert_wasm_output_chirho(&first_chirho, None);
    assert_eq!(
        second_chirho.status_chirho,
        StatusCode::OK,
        "a distinct admitted peer must not spend the first peer's owner-side network quota"
    );
    assert_eq!(transport_chirho.calls_chirho.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn an_over_limit_follower_peer_is_refused_before_signed_transport_chirho() {
    let owner_chirho = FixtureChirho::new_chirho(Vec::new());
    owner_chirho.latch_chirho();
    let owner_state_chirho = state_chirho(
        &owner_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho)
        .expect("owner destination");
    let transport_chirho =
        SignedTransportChirho::new_chirho(slot_chirho, TransportModeChirho::DeliverChirho);
    let follower_fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    let follower_state_chirho = follower_chirho(
        &follower_fixture_chirho,
        transport_chirho.clone(),
        source_limits_chirho(),
    );
    let owner_before_chirho = owner_chirho.snapshot_chirho();
    let follower_before_chirho = follower_fixture_chirho.snapshot_chirho();
    let first_chirho = get_from_peer_chirho(&follower_state_chirho, "192.0.2.10:41000").await;
    let second_chirho = get_from_peer_chirho(&follower_state_chirho, "192.0.2.10:41001").await;
    assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
    assert_eq!(
        follower_fixture_chirho.snapshot_chirho(),
        follower_before_chirho
    );
    assert_wasm_output_chirho(&first_chirho, None);
    assert_eq!(
        second_chirho.status_chirho,
        StatusCode::TOO_MANY_REQUESTS,
        "the follower must enforce its own normalized-peer ceiling"
    );
    assert_eq!(
        transport_chirho.calls_chirho.load(Ordering::SeqCst),
        1,
        "a refused ingress must not cross the signed transport"
    );
}

#[tokio::test]
async fn two_verified_origins_and_the_owner_have_separate_allocations_chirho() {
    let owner_chirho = FixtureChirho::new_chirho(Vec::new());
    owner_chirho.latch_chirho();
    let seeds_chirho = [0x31, 0x41, 0x52];
    let limits_chirho = serve_chirho::ServedRequestAbuseLimitsChirho {
        global_max_requests_chirho: 9,
        ..source_limits_chirho()
    };
    let owner_dispatch_chirho = Arc::new(LocalDispatchChirho {
        calls_chirho: AtomicUsize::new(0),
        scope_chirho: scope_for_seeds_chirho(0x52, &seeds_chirho),
    });
    let owner_state_chirho = state_chirho(
        &owner_chirho,
        owner_dispatch_chirho,
        AuthorityChirho::new_chirho(None),
        limits_chirho,
    );
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho.clone())
        .unwrap();
    let owner_before_chirho = owner_chirho.snapshot_chirho();
    for origin_chirho in [0x31, 0x41] {
        let transport_chirho = SignedTransportChirho::with_origins_chirho(
            slot_chirho.clone(),
            TransportModeChirho::DeliverChirho,
            origin_chirho,
            seeds_chirho.to_vec(),
        );
        let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
        let state_chirho =
            follower_chirho(&fixture_chirho, transport_chirho.clone(), limits_chirho);
        let before_chirho = fixture_chirho.snapshot_chirho();
        for index_chirho in 1..=3 {
            assert_wasm_output_chirho(
                &get_from_peer_chirho(&state_chirho, &format!("192.0.2.{index_chirho}:41000"))
                    .await,
                None,
            );
        }
        let refused_chirho = get_from_peer_chirho(&state_chirho, "192.0.2.4:41000").await;
        assert_eq!(refused_chirho.status_chirho, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(transport_chirho.calls_chirho.load(Ordering::SeqCst), 3);
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
    for index_chirho in 1..=3 {
        assert_wasm_output_chirho(
            &get_from_peer_chirho(
                &owner_state_chirho,
                &format!("198.51.100.{index_chirho}:41000"),
            )
            .await,
            None,
        );
    }
    assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
}

#[tokio::test]
async fn failed_auth_releases_both_slots_but_keeps_the_followers_source_charge_chirho() {
    let owner_chirho = FixtureChirho::new_chirho(Vec::new());
    owner_chirho.require_cookie_chirho();
    owner_chirho.latch_chirho();
    let mut owner_state_chirho = state_chirho(
        &owner_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        source_limits_chirho(),
    );
    owner_state_chirho.inflight_chirho = Arc::new(tokio::sync::Semaphore::new(1));
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho.clone())
        .unwrap();
    let transport_chirho =
        SignedTransportChirho::new_chirho(slot_chirho, TransportModeChirho::DeliverChirho);
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    let mut state_chirho = follower_chirho(
        &fixture_chirho,
        transport_chirho.clone(),
        source_limits_chirho(),
    );
    state_chirho.inflight_chirho = Arc::new(tokio::sync::Semaphore::new(1));
    let owner_before_chirho = owner_chirho.snapshot_chirho();
    let before_chirho = fixture_chirho.snapshot_chirho();
    let first_chirho = get_from_peer_chirho(&state_chirho, "192.0.2.10:41000").await;
    assert_eq!(first_chirho.status_chirho, StatusCode::UNAUTHORIZED);
    assert_eq!(owner_state_chirho.inflight_chirho.available_permits(), 1);
    assert_eq!(state_chirho.inflight_chirho.available_permits(), 1);
    let same_chirho = get_from_peer_chirho(&state_chirho, "192.0.2.10:41001").await;
    assert_eq!(same_chirho.status_chirho, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(transport_chirho.calls_chirho.load(Ordering::SeqCst), 1);
    let other_chirho = get_from_peer_chirho(&state_chirho, "192.0.2.11:41000").await;
    assert_eq!(other_chirho.status_chirho, StatusCode::UNAUTHORIZED);
    assert_eq!(transport_chirho.calls_chirho.load(Ordering::SeqCst), 2);
    assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn a_local_owner_with_one_slot_never_reacquires_its_ingress_permit_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let mut state_chirho = state_chirho(
        &fixture_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        source_limits_chirho(),
    );
    state_chirho.inflight_chirho = Arc::new(tokio::sync::Semaphore::new(1));
    let before_chirho = fixture_chirho.snapshot_chirho();
    assert_wasm_output_chirho(
        &get_from_peer_chirho(&state_chirho, "192.0.2.10:41000").await,
        None,
    );
    assert_eq!(state_chirho.inflight_chirho.available_permits(), 1);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn a_non_loopback_peer_cannot_rotate_its_forwarded_source_claim_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let dispatch_chirho = LocalDispatchChirho::new_chirho();
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        AuthorityChirho::new_chirho(None),
        source_limits_chirho(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    for (claimed_chirho, expected_chirho) in [
        ("198.51.100.10", StatusCode::OK),
        ("198.51.100.11", StatusCode::TOO_MANY_REQUESTS),
    ] {
        let mut headers_chirho = headers_chirho();
        headers_chirho.insert(
            "x-forwarded-for",
            HeaderValue::from_str(claimed_chirho).unwrap(),
        );
        assert_eq!(
            get_from_peer_with_headers_chirho(&state_chirho, "192.0.2.10:41000", headers_chirho)
                .await
                .status_chirho,
            expected_chirho
        );
    }
    assert_eq!(dispatch_chirho.calls_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn an_edge_ingress_429_negotiates_from_accept_without_dispatch_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let dispatch_chirho = LocalDispatchChirho::new_chirho();
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        AuthorityChirho::new_chirho(None),
        source_limits_chirho(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    assert_wasm_output_chirho(
        &get_from_peer_chirho(&state_chirho, "192.0.2.10:41000").await,
        None,
    );
    let mut headers_chirho = headers_chirho();
    headers_chirho.insert("accept", HeaderValue::from_static("application/json"));
    let response_chirho =
        get_from_peer_with_headers_chirho(&state_chirho, "192.0.2.10:41001", headers_chirho).await;
    assert_eq!(response_chirho.status_chirho, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response_chirho.body_chirho).unwrap(),
        serde_json::json!({"ok_chirho": false, "error_chirho": "served-request-unavailable-chirho"})
    );
    assert_eq!(
        response_chirho.headers_chirho.get(RETRY_AFTER).unwrap(),
        "60"
    );
    assert!(response_chirho.headers_chirho.get("set-cookie").is_none());
    assert_eq!(dispatch_chirho.calls_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[test]
fn a_relay_scope_for_another_tenant_is_refused_at_runtime_construction_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    let before_chirho = fixture_chirho.snapshot_chirho();
    let dispatch_chirho = Arc::new(LocalDispatchChirho {
        calls_chirho: AtomicUsize::new(0),
        scope_chirho: RelayIngressScopeChirho::new_chirho(
            hex_chirho(
                SigningKey::from_bytes(&[0x52; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            relay_tenant_consistency_group_digest_chirho("another-tenant-chirho").unwrap(),
            &roster_for_seeds_chirho(&[0x31, 0x52]),
        )
        .unwrap(),
    });
    let result_chirho = try_state_chirho(
        &fixture_chirho,
        dispatch_chirho,
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    assert!(
        result_chirho.is_err(),
        "a dispatch scope from tenant A cannot be attached to tenant B's runtime"
    );
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    assert!(try_state_chirho(
        &fixture_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default()
    )
    .is_ok());
}
