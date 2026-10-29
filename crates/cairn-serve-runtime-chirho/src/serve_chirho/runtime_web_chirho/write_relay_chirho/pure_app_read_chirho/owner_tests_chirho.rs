// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

struct BlockedAuthorityChirho {
    began_chirho: Notify,
    release_chirho: (Mutex<bool>, std::sync::Condvar),
}

impl ServedLocalReadAuthorityPortChirho for BlockedAuthorityChirho {
    fn begin_local_read_chirho(
        &self,
    ) -> Result<ServedLocalReadAuthorityWitnessChirho, ServedWriteRelayFailureChirho> {
        Ok(ServedLocalReadAuthorityWitnessChirho::new_chirho(
            "owner-node-chirho".to_string(),
            TERM_CHIRHO,
        ))
    }

    fn confirm_local_read_chirho(
        &self,
        _witness_chirho: &ServedLocalReadAuthorityWitnessChirho,
    ) -> Result<(), ServedWriteRelayFailureChirho> {
        self.began_chirho.notify_one();
        let (release_chirho, condition_chirho) = &self.release_chirho;
        let mut released_chirho = release_chirho.lock().expect("blocking authority lock");
        while !*released_chirho {
            released_chirho = condition_chirho
                .wait(released_chirho)
                .expect("blocking authority release");
        }
        Ok(())
    }
}

#[tokio::test]
async fn cancelled_owner_get_keeps_execution_permit_until_blocking_work_finishes_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let authority_chirho = Arc::new(BlockedAuthorityChirho {
        began_chirho: Notify::new(),
        release_chirho: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let mut state_chirho = state_chirho(
        &fixture_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    state_chirho.local_read_authority_chirho = Some(authority_chirho.clone());
    let before_chirho = fixture_chirho.snapshot_chirho();
    let capacity_chirho = state_chirho.inflight_chirho.available_permits();
    let task_state_chirho = state_chirho.clone();
    let task_chirho =
        tokio::spawn(async move { get_chirho(&task_state_chirho, headers_chirho()).await });
    let began_chirho = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        authority_chirho.began_chirho.notified(),
    )
    .await;
    let held_before_chirho = state_chirho.inflight_chirho.available_permits();
    task_chirho.abort();
    let cancelled_chirho = task_chirho
        .await
        .expect_err("GET future cancelled")
        .is_cancelled();
    let held_after_chirho = state_chirho.inflight_chirho.available_permits();
    // Release before asserting: even a failing arm must not leave a blocking worker behind.
    *authority_chirho
        .release_chirho
        .0
        .lock()
        .expect("release lock") = true;
    authority_chirho.release_chirho.1.notify_all();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while state_chirho.inflight_chirho.available_permits() != capacity_chirho {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("blocking execution must retire");
    began_chirho.expect("owner blocking work must start");
    assert!(cancelled_chirho);
    assert_eq!(held_before_chirho, capacity_chirho - 1);
    assert_eq!(held_after_chirho, capacity_chirho - 1);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn cancelled_signed_reentry_keeps_the_owners_slot_until_execution_finishes_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let authority_chirho = Arc::new(BlockedAuthorityChirho {
        began_chirho: Notify::new(),
        release_chirho: (Mutex::new(false), std::sync::Condvar::new()),
    });
    let mut state_chirho = state_chirho(
        &fixture_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    state_chirho.local_read_authority_chirho = Some(authority_chirho.clone());
    state_chirho.inflight_chirho = Arc::new(tokio::sync::Semaphore::new(1));
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, state_chirho.clone()).unwrap();
    let origin_chirho = SigningKey::from_bytes(&[0x31; 32]);
    let target_chirho = hex_chirho(
        SigningKey::from_bytes(&[0x52; 32])
            .verifying_key()
            .as_bytes(),
    );
    let group_chirho = relay_tenant_consistency_group_digest_chirho(TENANT_CHIRHO).unwrap();
    let prepared_chirho =
        PreparedServedWriteRelayRequestV1Chirho::new_chirho(ServedWriteRelayRequestInputChirho {
            ingress_admission_chirho: Some(
                cairn_write_relay_chirho::RelayIngressAdmissionChirho::new_chirho(
                    60_000,
                    60,
                    8 * 1024 * 1024,
                    300,
                    32 * 1024 * 1024,
                )
                .unwrap(),
            ),
            origin_node_id_chirho: hex_chirho(origin_chirho.verifying_key().as_bytes()),
            target_node_id_chirho: target_chirho.clone(),
            consistency_group_digest_chirho: group_chirho.clone(),
            expected_term_chirho: TERM_CHIRHO,
            caller_idempotency_key_chirho:
                cairn_write_relay_chirho::CallerIdempotencyKeyChirho::new_chirho(
                    "cancelled-reentry-chirho",
                )
                .unwrap(),
            method_chirho: "GET".to_string(),
            uri_chirho: format!("/app-chirho/{APP_CHIRHO}/{ROUTE_CHIRHO}"),
            end_to_end_headers_chirho:
                cairn_write_relay_chirho::RelayEndToEndHeadersChirho::try_request_chirho([])
                    .unwrap(),
            body_chirho: Vec::new(),
            relay_budget_remaining_millis_chirho: 2500,
        })
        .unwrap();
    let signature_chirho = hex_chirho(
        &origin_chirho
            .sign(&prepared_chirho.signing_digest_chirho())
            .to_bytes(),
    );
    let request_chirho = decode_and_verify_served_write_relay_request_chirho(
        &prepared_chirho
            .into_signed_chirho(signature_chirho)
            .unwrap()
            .to_wire_bytes_chirho()
            .unwrap(),
        &group_chirho,
        &target_chirho,
        &roster_for_seeds_chirho(&[0x31, 0x52]),
    )
    .unwrap();
    let before_chirho = fixture_chirho.snapshot_chirho();
    let task_chirho =
        tokio::spawn(async move { slot_chirho.execute_verified_chirho(&request_chirho).await });
    let began_chirho = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        authority_chirho.began_chirho.notified(),
    )
    .await;
    let held_before_chirho = state_chirho.inflight_chirho.available_permits();
    task_chirho.abort();
    let cancelled_chirho =
        matches!(task_chirho.await, Err(error_chirho) if error_chirho.is_cancelled());
    let held_after_chirho = state_chirho.inflight_chirho.available_permits();
    *authority_chirho.release_chirho.0.lock().unwrap() = true;
    authority_chirho.release_chirho.1.notify_all();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while state_chirho.inflight_chirho.available_permits() != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("owner reentry work retires after release");
    began_chirho.expect("signed reentry reaches held owner work");
    assert!(cancelled_chirho);
    assert_eq!(held_before_chirho, 0);
    assert_eq!(
        held_after_chirho, 0,
        "cancelling reentry cannot release the owner's execution permit"
    );
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn elected_named_get_executes_wasm_with_params_and_changes_no_durable_path_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let authority_chirho = AuthorityChirho::new_chirho(None);
    let dispatch_chirho = LocalDispatchChirho::new_chirho();
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    for _attempt_chirho in 0..2 {
        assert_wasm_output_chirho(&get_chirho(&state_chirho, headers_chirho()).await, None);
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
    assert_eq!(dispatch_chirho.calls_chirho.load(Ordering::SeqCst), 2);
    assert_eq!(authority_chirho.begin_chirho.load(Ordering::SeqCst), 2);
    assert_eq!(authority_chirho.confirms_chirho.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn elected_cookie_user_reaches_wasm_without_auth_or_effect_appends_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.require_cookie_chirho();
    let (cookie_chirho, user_chirho) = fixture_chirho.cookie_chirho();
    fixture_chirho.latch_chirho();
    let state_chirho = state_chirho(
        &fixture_chirho,
        LocalDispatchChirho::new_chirho(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    let mut headers_chirho = headers_chirho();
    headers_chirho.insert(COOKIE, cookie_chirho);
    assert_wasm_output_chirho(
        &get_chirho(&state_chirho, headers_chirho).await,
        Some(&user_chirho),
    );
    let refused_chirho = get_chirho(&state_chirho, self::headers_chirho()).await;
    assert_eq!(refused_chirho.status_chirho, StatusCode::UNAUTHORIZED);
    assert_eq!(
        refused_chirho.body_chirho,
        app_http_chirho::APP_AUTHENTICATION_REQUIRED_BODY_CHIRHO.as_bytes()
    );
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn effect_capabilities_refuse_without_falling_back_to_durable_executor_chirho() {
    for capability_chirho in [
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "private-chirho".to_string(),
        },
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "private-chirho".to_string(),
        },
        CapabilityChirho::QueryChirho {
            prefix_chirho: "private-chirho".to_string(),
            caller_chirho: "fixture-chirho".to_string(),
            max_rows_chirho: 1,
        },
        CapabilityChirho::PaidEffectChirho {
            effect_chirho: "email-chirho".to_string(),
            caller_chirho: "fixture-chirho".to_string(),
        },
    ] {
        let fixture_chirho = FixtureChirho::new_chirho(vec![capability_chirho]);
        fixture_chirho.latch_chirho();
        let state_chirho = state_chirho(
            &fixture_chirho,
            LocalDispatchChirho::new_chirho(),
            AuthorityChirho::new_chirho(None),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let before_chirho = fixture_chirho.snapshot_chirho();
        let response_chirho = get_chirho(&state_chirho, headers_chirho()).await;
        assert_eq!(
            response_chirho.status_chirho,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response_chirho.body_chirho,
            b"error: RelayMutationFamilyUnconvertedChirho\n"
        );
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
}

#[tokio::test]
async fn bearer_is_refused_before_dispatch_or_auth_records_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let dispatch_chirho = LocalDispatchChirho::new_chirho();
    let authority_chirho = AuthorityChirho::new_chirho(None);
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    for bearer_chirho in [
        "Bearer planted-token-chirho",
        "Bearer",
        "Basic planted-chirho",
    ] {
        let mut headers_chirho = headers_chirho();
        headers_chirho.insert(
            AUTHORIZATION,
            bearer_chirho.parse().expect("authorization fixture"),
        );
        let response_chirho = get_chirho(&state_chirho, headers_chirho).await;
        assert_eq!(
            response_chirho.status_chirho,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response_chirho.body_chirho,
            b"error: RelayMutationFamilyUnconvertedChirho\n"
        );
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
    assert_eq!(dispatch_chirho.calls_chirho.load(Ordering::SeqCst), 0);
    assert_eq!(authority_chirho.begin_chirho.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deposition_at_begin_pre_execute_or_pre_release_never_releases_payload_chirho() {
    for stage_chirho in 0..=2 {
        let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
        fixture_chirho.latch_chirho();
        let authority_chirho = AuthorityChirho::new_chirho(Some(stage_chirho));
        let state_chirho = state_chirho(
            &fixture_chirho,
            LocalDispatchChirho::new_chirho(),
            authority_chirho.clone(),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let before_chirho = fixture_chirho.snapshot_chirho();
        let response_chirho = get_chirho(&state_chirho, headers_chirho()).await;
        assert_eq!(
            response_chirho.status_chirho,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let identity_chirho = if stage_chirho == 0 {
            "RelayLocalAuthorityUnavailableChirho"
        } else {
            "RelayOwnerTermChangedChirho"
        };
        assert_eq!(
            response_chirho.body_chirho,
            format!("error: {identity_chirho}\n").as_bytes()
        );
        assert_eq!(authority_chirho.begin_chirho.load(Ordering::SeqCst), 1);
        assert_eq!(
            authority_chirho.confirms_chirho.load(Ordering::SeqCst),
            stage_chirho
        );
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
}

#[tokio::test]
async fn request_metering_refuses_without_appending_usage_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    cairn_chirho::resource_chirho::set_resource_policy_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        &fixture_chirho.owner_chirho,
        vec![cairn_chirho::resource_chirho::ResourceMeterChirho {
            resource_chirho: "pure-read-request-chirho".to_string(),
            unit_chirho: "request-chirho".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(10),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: cairn_chirho::resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![cairn_chirho::resource_chirho::ResourceActionPolicyChirho {
            section_chirho: serve_chirho::REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: serve_chirho::REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![cairn_chirho::resource_chirho::ResourceChargeChirho {
                resource_chirho: "pure-read-request-chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .expect("signed request meter");
    fixture_chirho.latch_chirho();
    let authority_chirho = AuthorityChirho::new_chirho(None);
    let state_chirho = state_chirho(
        &fixture_chirho,
        LocalDispatchChirho::new_chirho(),
        authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    let response_chirho = get_chirho(&state_chirho, headers_chirho()).await;
    assert_eq!(
        response_chirho.status_chirho,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response_chirho.body_chirho,
        b"error: RelayMutationFamilyUnconvertedChirho\n"
    );
    assert_eq!(authority_chirho.confirms_chirho.load(Ordering::SeqCst), 0);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

struct BlockedDispatchChirho {
    began_chirho: Notify,
    release_chirho: Notify,
    finished_chirho: Notify,
}

impl ServedWriteDispatchPortChirho for BlockedDispatchChirho {
    fn dispatch_chirho<'a>(
        &'a self,
        _input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async move {
            self.began_chirho.notify_one();
            self.release_chirho.notified().await;
            self.finished_chirho.notify_one();
            Err(RelayContractErrorChirho::owner_unknown_chirho().into())
        })
    }
}

#[tokio::test]
async fn cancelled_get_keeps_dispatch_permit_until_transport_finishes_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let dispatch_chirho = Arc::new(BlockedDispatchChirho {
        began_chirho: Notify::new(),
        release_chirho: Notify::new(),
        finished_chirho: Notify::new(),
    });
    let authority_chirho = AuthorityChirho::new_chirho(None);
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    let capacity_chirho = state_chirho.inflight_chirho.available_permits();
    let task_state_chirho = state_chirho.clone();
    let task_chirho =
        tokio::spawn(async move { get_chirho(&task_state_chirho, headers_chirho()).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        dispatch_chirho.began_chirho.notified(),
    )
    .await
    .expect("dispatch must start");
    assert_eq!(
        state_chirho.inflight_chirho.available_permits(),
        capacity_chirho - 1
    );
    task_chirho.abort();
    assert!(task_chirho
        .await
        .expect_err("GET future cancelled")
        .is_cancelled());
    assert_eq!(
        state_chirho.inflight_chirho.available_permits(),
        capacity_chirho - 1,
        "a disconnected caller must not release transport custody"
    );
    dispatch_chirho.release_chirho.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        dispatch_chirho.finished_chirho.notified().await;
        while state_chirho.inflight_chirho.available_permits() != capacity_chirho {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dispatch completion releases custody");
    assert_eq!(authority_chirho.begin_chirho.load(Ordering::SeqCst), 0);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn browser_get_without_caller_key_executes_pure_wasm_without_durable_writes_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let dispatch_chirho = LocalDispatchChirho::new_chirho();
    let authority_chirho = AuthorityChirho::new_chirho(None);
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    assert_wasm_output_chirho(&get_chirho(&state_chirho, HeaderMap::new()).await, None);
    assert_eq!(dispatch_chirho.calls_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(authority_chirho.confirms_chirho.load(Ordering::SeqCst), 2);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn supplied_invalid_or_duplicate_read_keys_are_never_replaced_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    fixture_chirho.latch_chirho();
    let dispatch_chirho = LocalDispatchChirho::new_chirho();
    let authority_chirho = AuthorityChirho::new_chirho(None);
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        authority_chirho.clone(),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    let mut empty_chirho = HeaderMap::new();
    empty_chirho.insert(
        relay_web_chirho::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static(""),
    );
    let mut non_ascii_chirho = HeaderMap::new();
    non_ascii_chirho.insert(
        relay_web_chirho::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_bytes(b"\xff").expect("HTTP obs-text fixture"),
    );
    let mut duplicate_chirho = headers_chirho();
    duplicate_chirho.append(
        relay_web_chirho::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        HeaderValue::from_static("second-key-chirho"),
    );
    for supplied_chirho in [empty_chirho, non_ascii_chirho, duplicate_chirho] {
        let response_chirho = get_chirho(&state_chirho, supplied_chirho).await;
        assert_eq!(response_chirho.status_chirho, StatusCode::BAD_REQUEST);
        assert_eq!(
            response_chirho.body_chirho,
            b"error: RelayCallerKeyInvalidChirho\n"
        );
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
    assert_eq!(dispatch_chirho.calls_chirho.load(Ordering::SeqCst), 0);
    assert_eq!(authority_chirho.begin_chirho.load(Ordering::SeqCst), 0);
}
