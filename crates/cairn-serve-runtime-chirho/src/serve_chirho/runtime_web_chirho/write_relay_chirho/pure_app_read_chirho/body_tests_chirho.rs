// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use axum::body::Body;
use axum::http::Request;

#[test]
fn transient_routing_preserves_only_the_composed_card_paid_post_chirho() {
    let surface_chirho = Some(("card-app-chirho", "draft-chirho"));
    let tenant_chirho = TenantIdChirho::TenantChirho("routing-fixture-chirho".into());
    assert!(!routes_to_transient_executor_chirho("card-app-chirho", Some("draft-chirho"), &Method::POST, surface_chirho, &tenant_chirho),
        "the composed paid POST must reach its own money/authority admission, not the pure executor");
    for (app_chirho, route_chirho, method_chirho, surface_chirho) in [
        (
            "card-app-chirho",
            "review-chirho",
            Method::POST,
            surface_chirho,
        ),
        (
            "other-app-chirho",
            "draft-chirho",
            Method::POST,
            surface_chirho,
        ),
        (
            "card-app-chirho",
            "draft-chirho",
            Method::GET,
            surface_chirho,
        ),
        ("card-app-chirho", "draft-chirho", Method::POST, None),
    ] {
        assert!(
            routes_to_transient_executor_chirho(
                app_chirho,
                Some(route_chirho),
                &method_chirho,
                surface_chirho,
                &tenant_chirho
            ),
            "composition must not exempt another app, route, method or an uncomposed root"
        );
    }
}

#[test]
fn transient_posts_do_not_intercept_the_unconverted_platform_road_chirho() {
    for surface_chirho in [None, Some(("card-app-chirho", "draft-chirho"))] {
        assert!(!routes_to_transient_executor_chirho(
            "other-app-chirho",
            Some("draft-chirho"),
            &Method::POST,
            surface_chirho,
            &TenantIdChirho::PlatformRootChirho,
        ));
        assert!(routes_to_transient_executor_chirho(
            "other-app-chirho",
            Some("draft-chirho"),
            &Method::GET,
            surface_chirho,
            &TenantIdChirho::PlatformRootChirho,
        ));
    }
}

fn input_boundary_context_chirho(
    fixture_chirho: &FixtureChirho,
) -> cairn_core_chirho::model_chirho::RequestContextChirho {
    let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
    serve_chirho::app_session_chirho::prepare_app_request_context_chirho(
        &fixture_chirho.root_chirho,
        &form_headers_chirho(cookie_chirho),
        APP_CHIRHO,
        Some(ROUTE_CHIRHO),
    )
    .expect("verified fixture session")
    .context_chirho()
    .cloned()
    .expect("signed-in context")
}

#[test]
fn request_input_boundary_preserves_plain_get_bytes_and_verified_context_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    let context_chirho = input_boundary_context_chirho(&fixture_chirho);
    let runtime_chirho = serve_chirho::runtime_ports_chirho::ServedRuntimeRootChirho::new_chirho(
        &fixture_chirho.root_chirho,
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    for context_chirho in [None, Some(&context_chirho)] {
        for form_chirho in [false, true] {
            let mut headers_chirho = HeaderMap::new();
            if form_chirho {
                headers_chirho.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
            }
            let actual_chirho = runtime_chirho
                .pure_app_read_input_chirho(
                    APP_CHIRHO,
                    ROUTE_CHIRHO,
                    context_chirho,
                    &headers_chirho,
                )
                .expect("write-free plain GET assembly");
            let legacy_chirho = serve_chirho::app_session_chirho::app_http_dag_input_chirho(
                &fixture_chirho.root_chirho,
                APP_CHIRHO,
                Some(ROUTE_CHIRHO),
                context_chirho,
                &headers_chirho,
                Vec::new(),
            )
            .expect("unchanged local input assembly");
            assert_eq!(actual_chirho, legacy_chirho);
            let value_chirho: serde_json::Value = serde_json::from_slice(&actual_chirho).unwrap();
            assert_eq!(
                value_chirho["app_params_chirho"]["message_chirho"],
                "hello from wasm"
            );
            assert_eq!(
                value_chirho
                    .get("user_principal_chirho")
                    .and_then(serde_json::Value::as_str),
                context_chirho.map(|context_chirho| context_chirho.user_principal_chirho.as_str()),
            );
            assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
        }
    }
}

#[test]
fn request_input_boundary_preserves_empty_form_get_without_context_or_params_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    let route_chirho = "empty-input-chirho";
    app_chirho::deploy_app_route_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        route_chirho,
        fixture_chirho.dag_chirho.clone(),
        &fixture_chirho.owner_chirho,
    )
    .unwrap();
    app_chirho::set_app_input_policy_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        Some(route_chirho),
        &fixture_chirho.owner_chirho,
        app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let runtime_chirho = serve_chirho::runtime_ports_chirho::ServedRuntimeRootChirho::new_chirho(
        &fixture_chirho.root_chirho,
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    let mut headers_chirho = HeaderMap::new();
    assert!(runtime_chirho
        .pure_app_read_input_chirho(APP_CHIRHO, route_chirho, None, &headers_chirho)
        .unwrap()
        .is_empty());
    headers_chirho.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    assert_eq!(
        runtime_chirho
            .pure_app_read_input_chirho(APP_CHIRHO, route_chirho, None, &headers_chirho)
            .unwrap(),
        b"{}"
    );
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[test]
fn request_input_boundary_keeps_private_empty_gets_and_review_bytes_unsealed_chirho() {
    for (subject_chirho, metadata_chirho) in [
        ("request-user-chirho", Vec::new()),
        ("declared-private-chirho", Vec::new()),
        (
            "request-user-chirho",
            vec![app_chirho::AppPrivateInputSafeMetadataChirho {
                key_chirho: "request_kind_chirho".into(),
                allowed_values_chirho: vec!["review_chirho".into()],
            }],
        ),
    ] {
        let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
        let context_chirho = input_boundary_context_chirho(&fixture_chirho);
        app_chirho::set_app_input_policy_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            Some(ROUTE_CHIRHO),
            &fixture_chirho.owner_chirho,
            app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: subject_chirho.into(),
                safe_metadata_chirho: metadata_chirho.clone(),
            },
        )
        .unwrap();
        let runtime_chirho =
            serve_chirho::runtime_ports_chirho::ServedRuntimeRootChirho::new_chirho(
                &fixture_chirho.root_chirho,
            );
        let before_chirho = fixture_chirho.snapshot_chirho();
        let bytes_chirho = b"private-review-chirho\0\xff";
        assert!(runtime_chirho
            .pure_app_read_input_chirho(APP_CHIRHO, ROUTE_CHIRHO, None, &HeaderMap::new())
            .unwrap()
            .is_empty());
        let review_chirho = runtime_chirho
            .pure_app_body_input_chirho(
                APP_CHIRHO,
                ROUTE_CHIRHO,
                Some(&context_chirho),
                bytes_chirho.to_vec(),
            )
            .unwrap();
        if subject_chirho == "request-user-chirho" && metadata_chirho.is_empty() {
            assert_eq!(review_chirho.as_deref(), Some(bytes_chirho.as_slice()));
        } else {
            assert!(review_chirho.is_none());
        }
        assert!(runtime_chirho
            .pure_app_body_input_chirho(APP_CHIRHO, ROUTE_CHIRHO, None, bytes_chirho.to_vec())
            .unwrap()
            .is_none());
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
}

#[test]
fn request_input_boundary_refuses_torn_policy_and_params_without_repair_chirho() {
    for log_chirho in [
        "app-input-policy-records-chirho.jsonl",
        "app-params-records-chirho.jsonl",
    ] {
        let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
        let context_chirho = input_boundary_context_chirho(&fixture_chirho);
        let path_chirho = fixture_chirho.root_chirho.join(log_chirho);
        let mut bytes_chirho = std::fs::read(&path_chirho).unwrap();
        assert!(!bytes_chirho.is_empty());
        bytes_chirho.push(b'{');
        std::fs::write(path_chirho, bytes_chirho).unwrap();
        let runtime_chirho =
            serve_chirho::runtime_ports_chirho::ServedRuntimeRootChirho::new_chirho(
                &fixture_chirho.root_chirho,
            );
        let before_chirho = fixture_chirho.snapshot_chirho();
        let result_chirho = runtime_chirho.pure_app_read_input_chirho(
            APP_CHIRHO,
            ROUTE_CHIRHO,
            Some(&context_chirho),
            &HeaderMap::new(),
        );
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
        assert!(
            result_chirho.is_err(),
            "{log_chirho} must be verified, not repaired or ignored"
        );
    }
}

const REVIEW_BODY_CHIRHO: &[u8] = b"document_chirho=private%20review%26content";
const REVIEW_FORM_CHIRHO: &[u8] =
    b"document_chirho=private%20review%26content&idempotency_key_chirho=review-key-chirho";

fn private_review_chirho(fixture_chirho: &FixtureChirho) {
    fixture_chirho.require_cookie_chirho();
    app_chirho::set_app_input_policy_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        Some(ROUTE_CHIRHO),
        &fixture_chirho.owner_chirho,
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "request-user-chirho".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .expect("private request-user review policy");
}

/// Two no-body pages beside the fixture's route: one answering HTML, one answering JSON.
fn deploy_landing_routes_chirho(fixture_chirho: &FixtureChirho) {
    let route_chirho = |route_chirho: &str, answer_chirho: &str| {
        cairn_chirho::app_manifest_chirho::AppDeployRouteManifestChirho {
            route_chirho: route_chirho.to_string(),
            source_chirho: cairn_chirho::app_manifest_chirho::AppDeployDagSourceChirho::DagChirho {
                hash_chirho: fixture_chirho.dag_chirho.clone(),
            },
            input_mode_chirho: None,
            request_body_policy_chirho: Some(
                app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho,
            ),
            response_content_type_chirho: Some(answer_chirho.to_string()),
            params_chirho: None,
            key_access_chirho: None,
        }
    };
    cairn_chirho::app_manifest_chirho::deploy_app_manifest_chirho(
        &fixture_chirho.root_chirho,
        &cairn_chirho::app_manifest_chirho::AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: cairn_chirho::app_manifest_chirho::APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO
                .to_string(),
            app_chirho: APP_CHIRHO.to_string(),
            owner_chirho: fixture_chirho.owner_chirho.clone(),
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![
                route_chirho("page-chirho", "text/html"),
                route_chirho("data-chirho", "application/json"),
            ],
            runtime_packages_chirho: Vec::new(),
        },
    )
    .expect("landing routes");
}

fn form_headers_chirho(cookie_chirho: HeaderValue) -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(COOKIE, cookie_chirho);
    headers_chirho.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers_chirho
}

async fn post_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: HeaderMap,
    body_chirho: &[u8],
) -> ResponsePartsChirho {
    let response_chirho = app_http_chirho::app_route_post_request_chirho(
        State(state_chirho.clone()),
        None,
        headers_chirho,
        AxPath((APP_CHIRHO.to_string(), ROUTE_CHIRHO.to_string())),
        Request::builder()
            .method(Method::POST)
            .uri(format!("/app-chirho/{APP_CHIRHO}/{ROUTE_CHIRHO}"))
            .body(Body::from(body_chirho.to_vec()))
            .expect("bounded review POST"),
    )
    .await;
    response_parts_chirho(response_chirho).await
}

#[derive(Default)]
struct BodyDispatchChirho {
    bodies_chirho: Mutex<Vec<Vec<u8>>>,
}

impl ServedWriteDispatchPortChirho for BodyDispatchChirho {
    fn ingress_scope_chirho(&self) -> Option<RelayIngressScopeChirho> {
        Some(ingress_scope_chirho(true))
    }

    fn dispatch_chirho<'a>(
        &'a self,
        input_chirho: ServedWriteDispatchInputChirho,
    ) -> ServedWriteDispatchFutureChirho<'a> {
        Box::pin(async move {
            assert_eq!(input_chirho.method_chirho, "POST");
            self.bodies_chirho
                .lock()
                .expect("recorded review bodies")
                .push(input_chirho.body_chirho);
            Ok(ServedWriteDispatchOutcomeChirho::ExecuteLocallyChirho)
        })
    }
}

#[tokio::test]
async fn transient_review_recomputes_changed_body_with_same_key_without_any_root_write_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    private_review_chirho(&fixture_chirho);
    let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
    fixture_chirho.latch_chirho();
    let dispatch_chirho = Arc::new(BodyDispatchChirho::default());
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    for body_chirho in [
        REVIEW_FORM_CHIRHO,
        b"document_chirho=changed&idempotency_key_chirho=review-key-chirho",
    ] {
        let response_chirho = post_chirho(
            &state_chirho,
            form_headers_chirho(cookie_chirho.clone()),
            body_chirho,
        )
        .await;
        assert_eq!(response_chirho.status_chirho, StatusCode::OK);
        let business_chirho = body_chirho
            .split(|byte_chirho| *byte_chirho == b'&')
            .next()
            .unwrap();
        assert_eq!(
            response_chirho.body_chirho,
            business_chirho.to_ascii_uppercase()
        );
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
    assert_eq!(
        dispatch_chirho.bodies_chirho.lock().unwrap().as_slice(),
        &[
            REVIEW_BODY_CHIRHO.to_vec(),
            b"document_chirho=changed".to_vec()
        ]
    );
}

#[tokio::test]
async fn signed_review_post_strips_carrier_and_never_reads_stale_follower_state_chirho() {
    let owner_chirho = FixtureChirho::new_chirho(Vec::new());
    private_review_chirho(&owner_chirho);
    let (cookie_chirho, _user_chirho) = owner_chirho.cookie_chirho();
    owner_chirho.latch_chirho();
    let owner_dispatch_chirho = Arc::new(BodyDispatchChirho::default());
    let owner_state_chirho = state_chirho(
        &owner_chirho,
        owner_dispatch_chirho.clone(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
    relay_web_chirho::install_relay_destination_chirho(&slot_chirho, owner_state_chirho)
        .expect("real review destination");
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
    let response_chirho = post_chirho(
        &follower_state_chirho,
        form_headers_chirho(cookie_chirho),
        REVIEW_FORM_CHIRHO,
    )
    .await;
    assert_eq!(response_chirho.status_chirho, StatusCode::OK);
    assert_eq!(
        response_chirho.body_chirho,
        REVIEW_BODY_CHIRHO.to_ascii_uppercase()
    );
    assert_eq!(transport_chirho.calls_chirho.load(Ordering::SeqCst), 1);
    assert_eq!(
        transport_chirho
            .destination_calls_chirho
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        transport_chirho.records_chirho.lock().unwrap()[0].2,
        REVIEW_BODY_CHIRHO
    );
    assert!(
        owner_dispatch_chirho
            .bodies_chirho
            .lock()
            .unwrap()
            .is_empty(),
        "signed reentry must not relay again"
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
async fn review_refuses_effects_and_lost_owner_authority_without_any_root_write_chirho() {
    for (capabilities_chirho, refuse_at_chirho) in [
        (
            vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "never-written-chirho".into(),
            }],
            None,
        ),
        (Vec::new(), Some(0)),
        (Vec::new(), Some(1)),
        (Vec::new(), Some(2)),
    ] {
        let fixture_chirho = FixtureChirho::new_chirho(capabilities_chirho);
        private_review_chirho(&fixture_chirho);
        let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
        fixture_chirho.latch_chirho();
        let state_chirho = state_chirho(
            &fixture_chirho,
            Arc::new(BodyDispatchChirho::default()),
            AuthorityChirho::new_chirho(refuse_at_chirho),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let before_chirho = fixture_chirho.snapshot_chirho();
        let response_chirho = post_chirho(
            &state_chirho,
            form_headers_chirho(cookie_chirho),
            REVIEW_FORM_CHIRHO,
        )
        .await;
        assert_eq!(response_chirho.status_chirho, StatusCode::SEE_OTHER);
        assert!(response_chirho.headers_chirho[axum::http::header::LOCATION]
            .to_str()
            .unwrap()
            .ends_with("#refusal-write-unavailable-chirho"));
        assert!(!response_chirho
            .body_chirho
            .windows(REVIEW_BODY_CHIRHO.len())
            .any(|window_chirho| window_chirho == REVIEW_BODY_CHIRHO));
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
}

#[tokio::test]
async fn review_requires_owner_session_and_rejects_bad_carriers_before_dispatch_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    private_review_chirho(&fixture_chirho);
    let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
    fixture_chirho.latch_chirho();
    let dispatch_chirho = Arc::new(BodyDispatchChirho::default());
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    for body_chirho in [
        REVIEW_BODY_CHIRHO,
        b"idempotency_key_chirho=a&idempotency_key_chirho=b&document_chirho=private",
        b"idempotency_key_chirho=&document_chirho=private",
    ] {
        let response_chirho = post_chirho(
            &state_chirho,
            form_headers_chirho(cookie_chirho.clone()),
            body_chirho,
        )
        .await;
        assert_eq!(response_chirho.status_chirho, StatusCode::SEE_OTHER);
        assert!(response_chirho.headers_chirho[axum::http::header::LOCATION]
            .to_str()
            .unwrap()
            .ends_with("#refusal-caller-key-invalid-chirho"));
    }
    assert!(dispatch_chirho.bodies_chirho.lock().unwrap().is_empty());
    let mut headers_chirho = form_headers_chirho(cookie_chirho);
    headers_chirho.remove(COOKIE);
    let response_chirho = post_chirho(&state_chirho, headers_chirho, REVIEW_FORM_CHIRHO).await;
    assert_eq!(response_chirho.status_chirho, StatusCode::UNAUTHORIZED);
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn transient_review_html_answers_issue_fresh_save_keys_without_durable_render_state_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    // Identity WASM returns exactly the posted bytes, so the real outer HTML carrier must fill them.
    let wasm_chirho = cairn_chirho::cas_chirho::add_chirho(&fixture_chirho.root_chirho, br#"
        (module
          (memory (export "memory") 1)
          (func (export "alloc_chirho") (param $len_chirho i32) (result i32) (i32.const 1024))
          (func (export "review_chirho") (param $ptr_chirho i32) (param $len_chirho i32) (result i64)
            (i64.or (i64.shl (i64.extend_i32_u (local.get $ptr_chirho)) (i64.const 32))
                    (i64.extend_i32_u (local.get $len_chirho)))))
    "#).expect("identity WASM");
    let node_chirho = cairn_chirho::store_chirho::put_object_chirho(
        &fixture_chirho.root_chirho,
        &NodeDefChirho {
            name_chirho: "transient-html-review-chirho".into(),
            impl_wasm_chirho: wasm_chirho,
            entry_chirho: "review_chirho".into(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in_chirho".into(),
                schema_chirho: HashChirho("bytes-chirho".into()),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out_chirho".into(),
                schema_chirho: HashChirho("bytes-chirho".into()),
            }],
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .expect("HTML review node");
    let dag_chirho = cairn_chirho::store_chirho::put_object_chirho(
        &fixture_chirho.root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .expect("HTML review DAG");
    app_chirho::deploy_app_route_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        ROUTE_CHIRHO,
        dag_chirho,
        &fixture_chirho.owner_chirho,
    )
    .expect("HTML review route");
    app_chirho::set_app_route_response_policy_chirho(
        &fixture_chirho.root_chirho,
        APP_CHIRHO,
        ROUTE_CHIRHO,
        &fixture_chirho.owner_chirho,
        "text/html",
    )
    .expect("declared HTML answer");
    private_review_chirho(&fixture_chirho);
    let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
    fixture_chirho.latch_chirho();
    let state_chirho = state_chirho(
        &fixture_chirho,
        Arc::new(BodyDispatchChirho::default()),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    let placeholder_chirho =
        relay_web_chirho::caller_key_carrier_chirho::FORM_CALLER_KEY_PLACEHOLDER_CHIRHO;
    let body_chirho = format!("<p>private review</p>{placeholder_chirho}{placeholder_chirho}");
    let mut keys_chirho = std::collections::BTreeSet::new();
    for _attempt_chirho in 0..2 {
        let mut headers_chirho = headers_chirho();
        headers_chirho.insert(COOKIE, cookie_chirho.clone());
        headers_chirho.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        let response_chirho =
            post_chirho(&state_chirho, headers_chirho, body_chirho.as_bytes()).await;
        assert_eq!(response_chirho.status_chirho, StatusCode::OK);
        assert_eq!(
            response_chirho.headers_chirho[CONTENT_TYPE]
                .to_str()
                .unwrap()
                .split(';')
                .next(),
            Some("text/html")
        );
        let html_chirho = std::str::from_utf8(&response_chirho.body_chirho).unwrap();
        assert!(html_chirho.starts_with("<p>private review</p>"));
        let issued_chirho = html_chirho
            .split("name=\"idempotency_key_chirho\" value=\"")
            .skip(1)
            .map(|part_chirho| part_chirho.split('"').next().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(issued_chirho.len(), 2);
        for key_chirho in issued_chirho {
            assert_eq!(key_chirho.len(), 43);
            assert!(
                keys_chirho.insert(key_chirho.to_string()),
                "every rendered Save needs its own fresh key"
            );
        }
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
}

#[tokio::test]
async fn transient_review_refuses_plain_or_declared_subject_input_without_sealing_chirho() {
    for mode_chirho in [
        app_chirho::AppInputModeChirho::PlainChirho,
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "shared-review-chirho".into(),
            safe_metadata_chirho: Vec::new(),
        },
    ] {
        let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
        fixture_chirho.require_cookie_chirho();
        app_chirho::set_app_input_policy_chirho(
            &fixture_chirho.root_chirho,
            APP_CHIRHO,
            Some(ROUTE_CHIRHO),
            &fixture_chirho.owner_chirho,
            mode_chirho,
        )
        .expect("unsupported input policy");
        let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
        fixture_chirho.latch_chirho();
        let state_chirho = state_chirho(
            &fixture_chirho,
            Arc::new(BodyDispatchChirho::default()),
            AuthorityChirho::new_chirho(None),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let before_chirho = fixture_chirho.snapshot_chirho();
        let response_chirho = post_chirho(
            &state_chirho,
            form_headers_chirho(cookie_chirho),
            REVIEW_FORM_CHIRHO,
        )
        .await;
        assert_eq!(response_chirho.status_chirho, StatusCode::SEE_OTHER);
        assert!(response_chirho.headers_chirho[axum::http::header::LOCATION]
            .to_str()
            .unwrap()
            .ends_with("#refusal-write-unavailable-chirho"));
        assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
    }
}

#[tokio::test]
async fn transient_review_collects_a_bounded_body_before_dispatch_chirho() {
    let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
    private_review_chirho(&fixture_chirho);
    let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
    fixture_chirho.latch_chirho();
    let dispatch_chirho = Arc::new(BodyDispatchChirho::default());
    let state_chirho = state_chirho(
        &fixture_chirho,
        dispatch_chirho.clone(),
        AuthorityChirho::new_chirho(None),
        serve_chirho::ServedRequestAbuseLimitsChirho::default(),
    );
    let before_chirho = fixture_chirho.snapshot_chirho();
    let response_chirho = app_http_chirho::app_route_post_request_chirho(
        State(state_chirho),
        None,
        form_headers_chirho(cookie_chirho),
        AxPath((APP_CHIRHO.to_string(), ROUTE_CHIRHO.to_string())),
        Request::builder()
            .method(Method::POST)
            .uri(format!("/app-chirho/{APP_CHIRHO}/{ROUTE_CHIRHO}"))
            .body(Body::from(vec![b'x'; 2 * 1024 * 1024 + 1]))
            .unwrap(),
    )
    .await;
    assert_eq!(response_chirho.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(dispatch_chirho.bodies_chirho.lock().unwrap().is_empty());
    assert_eq!(fixture_chirho.snapshot_chirho(), before_chirho);
}

#[tokio::test]
async fn relayed_review_owner_refusals_keep_the_browser_unavailable_notice_chirho() {
    for (capabilities_chirho, refuse_at_chirho) in [
        (
            vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "unconverted-save-chirho".into(),
            }],
            None,
        ),
        (Vec::new(), Some(0)),
    ] {
        let owner_chirho = FixtureChirho::new_chirho(capabilities_chirho);
        private_review_chirho(&owner_chirho);
        let (cookie_chirho, _user_chirho) = owner_chirho.cookie_chirho();
        owner_chirho.latch_chirho();
        let slot_chirho = relay_web_chirho::ServedWriteRelayDestinationSlotChirho::new_chirho();
        relay_web_chirho::install_relay_destination_chirho(
            &slot_chirho,
            state_chirho(
                &owner_chirho,
                Arc::new(BodyDispatchChirho::default()),
                AuthorityChirho::new_chirho(refuse_at_chirho),
                serve_chirho::ServedRequestAbuseLimitsChirho::default(),
            ),
        )
        .expect("real refusing review destination");
        let transport_chirho =
            SignedTransportChirho::new_chirho(slot_chirho, TransportModeChirho::DeliverChirho);
        let follower_chirho = FixtureChirho::new_chirho(Vec::new());
        follower_chirho.latch_chirho();
        corrupt_follower_chirho(&follower_chirho);
        let follower_state_chirho = state_chirho(
            &follower_chirho,
            transport_chirho.clone(),
            AuthorityChirho::new_chirho(Some(0)),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let owner_before_chirho = owner_chirho.snapshot_chirho();
        let follower_before_chirho = follower_chirho.snapshot_chirho();
        let response_chirho = post_chirho(
            &follower_state_chirho,
            form_headers_chirho(cookie_chirho),
            REVIEW_FORM_CHIRHO,
        )
        .await;
        assert_eq!(response_chirho.status_chirho, StatusCode::SEE_OTHER);
        assert!(response_chirho.headers_chirho[axum::http::header::LOCATION]
            .to_str()
            .unwrap()
            .ends_with("#refusal-write-unavailable-chirho"));
        assert_eq!(
            transport_chirho
                .destination_calls_chirho
                .load(Ordering::SeqCst),
            1
        );
        assert_eq!(owner_chirho.snapshot_chirho(), owner_before_chirho);
        assert_eq!(follower_chirho.snapshot_chirho(), follower_before_chirho);
    }
}

/// A refused browser form returns to its Referer only when that page is a landing: declared, bodyless
/// and answering HTML (PFE #29303, #29320). This drives the relay's refusal answer, one of the
/// landing check's two call sites. A no-body page that answers JSON sends the browser to the app's home.
#[tokio::test]
async fn a_refused_review_lands_back_only_on_a_bodyless_html_page_chirho() {
    for (route_chirho, expected_chirho) in [
        (
            "page-chirho",
            format!("/app-chirho/{APP_CHIRHO}/page-chirho#refusal-write-unavailable-chirho"),
        ),
        (
            "data-chirho",
            format!("/app-chirho/{APP_CHIRHO}/#refusal-write-unavailable-chirho"),
        ),
    ] {
        let fixture_chirho = FixtureChirho::new_chirho(Vec::new());
        private_review_chirho(&fixture_chirho);
        deploy_landing_routes_chirho(&fixture_chirho);
        let (cookie_chirho, _user_chirho) = fixture_chirho.cookie_chirho();
        fixture_chirho.latch_chirho();
        let state_chirho = state_chirho(
            &fixture_chirho,
            Arc::new(BodyDispatchChirho::default()),
            AuthorityChirho::new_chirho(Some(0)),
            serve_chirho::ServedRequestAbuseLimitsChirho::default(),
        );
        let mut headers_chirho = form_headers_chirho(cookie_chirho);
        headers_chirho.insert(
            axum::http::header::HOST,
            HeaderValue::from_static("landing.example"),
        );
        headers_chirho.insert(
            axum::http::header::REFERER,
            HeaderValue::from_str(&format!(
                "https://landing.example/app-chirho/{APP_CHIRHO}/{route_chirho}"
            ))
            .expect("referer"),
        );
        let response_chirho = post_chirho(&state_chirho, headers_chirho, REVIEW_FORM_CHIRHO).await;
        assert_eq!(
            response_chirho.status_chirho,
            StatusCode::SEE_OTHER,
            "{route_chirho}"
        );
        assert_eq!(
            response_chirho.headers_chirho[axum::http::header::LOCATION]
                .to_str()
                .expect("location"),
            expected_chirho,
            "{route_chirho}"
        );
    }
}
