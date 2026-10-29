// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[tokio::test]
async fn signed_two_node_get_forwards_before_follower_refs_and_cookie_reads_chirho() {
    let owner_chirho = FixtureChirho::new_chirho(Vec::new());
    owner_chirho.require_cookie_chirho();
    let (cookie_chirho, user_chirho) = owner_chirho.cookie_chirho();
    owner_chirho.latch_chirho();
    let owner_authority_chirho = AuthorityChirho::new_chirho(None);
    let owner_dispatch_chirho = LocalDispatchChirho::new_chirho();
    let owner_state_chirho = state_chirho(
        &owner_chirho,
        owner_dispatch_chirho.clone(),
        owner_authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho)
        .expect("real destination");
    let transport_chirho =
        SignedTransportChirho::new_chirho(slot_chirho, TransportModeChirho::DeliverChirho);
    let follower_chirho = FixtureChirho::new_chirho(Vec::new());
    follower_chirho.latch_chirho();
    corrupt_follower_chirho(&follower_chirho);
    let follower_authority_chirho = AuthorityChirho::new_chirho(Some(0));
    let follower_state_chirho = state_chirho(
        &follower_chirho,
        transport_chirho.clone(),
        follower_authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let owner_before_chirho = owner_chirho.snapshot_chirho();
    let follower_before_chirho = follower_chirho.snapshot_chirho();
    let mut headers_chirho = headers_chirho();
    headers_chirho.insert(COOKIE, cookie_chirho);
    assert_wasm_output_chirho(
        &get_chirho(&follower_state_chirho, headers_chirho).await,
        Some(&user_chirho),
    );
    assert_eq!(transport_chirho.calls_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(
        transport_chirho
            .destination_calls_chirho
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        transport_chirho
            .records_chirho
            .lock()
            .expect("recorded request")
            .as_slice(),
        &[(
            "GET".to_string(),
            format!("/app-chirho/{APP_CHIRHO}/{ROUTE_CHIRHO}?probe_chirho=kept"),
            Vec::new()
        )]
    );
    assert_eq!(
        owner_dispatch_chirho.calls_chirho.load(Ordering::SeqCst),
        0,
        "destination must not relay again"
    );
    assert_eq!(
        owner_authority_chirho
            .confirms_chirho
            .load(Ordering::SeqCst),
        2
    );
    assert_eq!(
        follower_authority_chirho
            .begin_chirho
            .load(Ordering::SeqCst),
        0
    );
    assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
    assert_eq!(follower_chirho.snapshot_chirho(), follower_before_chirho);
}

#[tokio::test]
async fn signed_destination_401_and_429_keep_status_body_and_retry_headers_chirho() {
    for status_chirho in [StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS] {
        let owner_chirho = FixtureChirho::new_chirho(Vec::new());
        owner_chirho.require_cookie_chirho();
        let mut request_headers_chirho = headers_chirho();
        let user_chirho = if status_chirho == StatusCode::TOO_MANY_REQUESTS {
            let (cookie_chirho, user_chirho) = owner_chirho.cookie_chirho();
            request_headers_chirho.insert(COOKIE, cookie_chirho);
            Some(user_chirho)
        } else {
            None
        };
        owner_chirho.latch_chirho();
        let limits_chirho = serve_chirho::ServedRequestAbuseLimitsChirho {
            actor_max_requests_chirho: 1,
            ..Default::default()
        };
        let owner_authority_chirho = AuthorityChirho::new_chirho(None);
        let owner_dispatch_chirho = LocalDispatchChirho::new_chirho();
        let owner_state_chirho = state_chirho(
            &owner_chirho,
            owner_dispatch_chirho.clone(),
            owner_authority_chirho,
            limits_chirho,
        );
        if status_chirho == StatusCode::TOO_MANY_REQUESTS {
            assert_wasm_output_chirho(
                &get_chirho(&owner_state_chirho, request_headers_chirho.clone()).await,
                user_chirho.as_deref(),
            );
        }
        let expected_chirho = get_chirho(&owner_state_chirho, request_headers_chirho.clone()).await;
        assert_eq!(expected_chirho.status_chirho, status_chirho);
        if status_chirho == StatusCode::UNAUTHORIZED {
            assert_eq!(
                expected_chirho.body_chirho,
                app_http_chirho::APP_AUTHENTICATION_REQUIRED_BODY_CHIRHO.as_bytes()
            );
            assert!(expected_chirho.headers_chirho.get(RETRY_AFTER).is_none());
        } else {
            assert_eq!(
                expected_chirho
                    .headers_chirho
                    .get(RETRY_AFTER)
                    .expect("retry promise"),
                "60"
            );
            assert_eq!(expected_chirho.body_chirho, b"served request unavailable\n");
        }
        let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
        relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho)
            .expect("real refusal destination");
        let transport_chirho =
            SignedTransportChirho::new_chirho(slot_chirho, TransportModeChirho::DeliverChirho);
        let follower_chirho = FixtureChirho::new_chirho(Vec::new());
        follower_chirho.latch_chirho();
        corrupt_follower_chirho(&follower_chirho);
        let follower_authority_chirho = AuthorityChirho::new_chirho(Some(0));
        let follower_state_chirho = state_chirho(
            &follower_chirho,
            transport_chirho.clone(),
            follower_authority_chirho.clone(),
            limits_chirho,
        );
        let owner_before_chirho = owner_chirho.snapshot_chirho();
        let follower_before_chirho = follower_chirho.snapshot_chirho();
        let calls_before_chirho = owner_dispatch_chirho.calls_chirho.load(Ordering::SeqCst);
        let actual_chirho = get_chirho(&follower_state_chirho, request_headers_chirho).await;
        assert_eq!(actual_chirho.status_chirho, expected_chirho.status_chirho);
        assert_eq!(actual_chirho.body_chirho, expected_chirho.body_chirho);
        for name_chirho in [CONTENT_TYPE, CACHE_CONTROL, RETRY_AFTER] {
            assert_eq!(
                actual_chirho.headers_chirho.get(&name_chirho),
                expected_chirho.headers_chirho.get(&name_chirho)
            );
        }
        assert_eq!(
            transport_chirho
                .destination_calls_chirho
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(
            owner_dispatch_chirho.calls_chirho.load(Ordering::SeqCst),
            calls_before_chirho
        );
        assert_eq!(
            follower_authority_chirho
                .begin_chirho
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
        assert_eq!(follower_chirho.snapshot_chirho(), follower_before_chirho);
    }
}

#[tokio::test]
async fn unknown_ambiguous_and_lost_response_never_execute_on_follower_chirho() {
    for (mode_chirho, status_chirho, identity_chirho, executions_chirho) in [
        (
            TransportModeChirho::UnknownChirho,
            StatusCode::SERVICE_UNAVAILABLE,
            "RelayOwnerUnknownChirho",
            0,
        ),
        (
            TransportModeChirho::AmbiguousChirho,
            StatusCode::GATEWAY_TIMEOUT,
            "RelayOutcomeAmbiguousChirho",
            0,
        ),
        (
            TransportModeChirho::LoseResponseChirho,
            StatusCode::GATEWAY_TIMEOUT,
            "RelayResponseUnavailableAfterExecutionChirho",
            1,
        ),
    ] {
        let owner_chirho = FixtureChirho::new_chirho(Vec::new());
        owner_chirho.latch_chirho();
        let owner_authority_chirho = AuthorityChirho::new_chirho(None);
        let owner_state_chirho = state_chirho(
            &owner_chirho,
            LocalDispatchChirho::new_chirho(),
            owner_authority_chirho.clone(),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
        relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho)
            .expect("real destination");
        let transport_chirho = SignedTransportChirho::new_chirho(slot_chirho, mode_chirho);
        let follower_chirho = FixtureChirho::new_chirho(Vec::new());
        follower_chirho.latch_chirho();
        // Keep valid local content: a fallback could succeed, so refusal is not a corrupt-store accident.
        let follower_authority_chirho = AuthorityChirho::new_chirho(None);
        let follower_state_chirho = state_chirho(
            &follower_chirho,
            transport_chirho.clone(),
            follower_authority_chirho.clone(),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let owner_before_chirho = owner_chirho.snapshot_chirho();
        let follower_before_chirho = follower_chirho.snapshot_chirho();
        let response_chirho = get_chirho(&follower_state_chirho, headers_chirho()).await;
        assert_eq!(response_chirho.status_chirho, status_chirho);
        assert_eq!(
            response_chirho.body_chirho,
            format!("error: {identity_chirho}\n").as_bytes()
        );
        assert_eq!(
            transport_chirho.calls_chirho.load(Ordering::SeqCst),
            1,
            "no retry on unknown outcomes"
        );
        assert_eq!(
            transport_chirho
                .destination_calls_chirho
                .load(Ordering::SeqCst),
            executions_chirho
        );
        assert_eq!(
            owner_authority_chirho
                .confirms_chirho
                .load(Ordering::SeqCst),
            executions_chirho * 2
        );
        assert_eq!(
            follower_authority_chirho
                .begin_chirho
                .load(Ordering::SeqCst),
            0
        );
        assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
        assert_eq!(follower_chirho.snapshot_chirho(), follower_before_chirho);
    }
}

#[tokio::test]
async fn signed_pure_get_cannot_downgrade_to_a_local_era_executor_chirho() {
    let owner_chirho = FixtureChirho::new_chirho(Vec::new());
    let owner_authority_chirho = AuthorityChirho::new_chirho(None);
    let owner_state_chirho = state_chirho(
        &owner_chirho,
        LocalDispatchChirho::new_chirho(),
        owner_authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho)
        .expect("real destination");
    let transport_chirho =
        SignedTransportChirho::new_chirho(slot_chirho, TransportModeChirho::DeliverChirho);
    let follower_chirho = FixtureChirho::new_chirho(Vec::new());
    follower_chirho.latch_chirho();
    let follower_state_chirho = state_chirho(
        &follower_chirho,
        transport_chirho,
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let owner_before_chirho = owner_chirho.snapshot_chirho();
    let follower_before_chirho = follower_chirho.snapshot_chirho();
    let response_chirho = get_chirho(&follower_state_chirho, headers_chirho()).await;
    assert_eq!(
        response_chirho.status_chirho,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response_chirho.body_chirho,
        b"error: RelayLocalAuthorityUnavailableChirho\n"
    );
    assert_eq!(
        owner_authority_chirho.begin_chirho.load(Ordering::SeqCst),
        0
    );
    assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
    assert_eq!(follower_chirho.snapshot_chirho(), follower_before_chirho);
}
