// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn domain_routing_serves_bound_host_path_over_http_chirho() {
    // H1 keystone: an unmatched (Host, path) resolves through the signed binding table into
    // the bound app's gated serve path when domain routing is on; unbound paths and the
    // routing-off server both keep the exact legacy 404.
    let root_chirho = temp_root_chirho("domain-routing-http");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "shopapp",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_for_owner_chirho(
        &root_chirho,
        "shopapp",
        "home",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "shopapp",
        Some("home"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    // host 127.0.0.1 is a valid binding host (digit labels), and the test client sends
    // `Host: 127.0.0.1:<port>`, which the resolver port-strips to match.
    domain_binding_chirho::emit_domain_binding_chirho(
        &root_chirho,
        domain_binding_chirho::DomainBindingInputChirho {
            owner_principal_chirho: owner_chirho.clone(),
            host_chirho: "127.0.0.1".to_string(),
            path_prefix_chirho: "/shop".to_string(),
            app_chirho: "shopapp".to_string(),
            route_base_chirho: Some("home".to_string()),
            status_chirho: domain_binding_chirho::DomainBindingStatusChirho::ActiveChirho,
        },
    )
    .unwrap();

    // Routing ON: the bound path serves the app; an unbound path stays 404.
    let port_on_chirho = unused_local_port_chirho();
    let addr_on_chirho = format!("127.0.0.1:{port_on_chirho}");
    let root_on_chirho = root_chirho.clone();
    let runtime_on_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_on_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_with_domain_routing_chirho(
                &root_on_chirho,
                port_on_chirho,
                8,
                String::new(),
                String::new(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_on_chirho);

        let bound_chirho =
            try_http_request_for_smoke_chirho(&addr_on_chirho, "POST", "/shop", &[], b"hello")
                .unwrap();
        assert_eq!(
            bound_chirho.status_chirho, 200,
            "bound host/path should serve the app"
        );
        assert_eq!(
            String::from_utf8_lossy(&bound_chirho.body_chirho),
            "HELLO",
            "the bound app (upcase) should transform the body"
        );

        let unbound_chirho = http_get_for_smoke_chirho(&addr_on_chirho, "/not-bound-chirho");
        assert_eq!(
            unbound_chirho.status_chirho, 404,
            "unbound path keeps legacy 404"
        );

        let binding_path_chirho = root_chirho.join("domain-bindings-chirho.jsonl");
        let binding_text_chirho = std::fs::read_to_string(&binding_path_chirho).unwrap();
        std::fs::write(
            &binding_path_chirho,
            binding_text_chirho.replace("\"shopapp\"", "\"forged-shopapp\""),
        )
        .unwrap();
        let tampered_chirho =
            try_http_request_for_smoke_chirho(&addr_on_chirho, "POST", "/shop", &[], b"hello")
                .unwrap();
        assert_eq!(
            tampered_chirho.status_chirho, 503,
            "tampered domain binding log must fail closed instead of routing"
        );
        assert_eq!(
            String::from_utf8_lossy(&tampered_chirho.body_chirho),
            "domain routing unavailable"
        );

        server_chirho.abort();
    });

    // Routing OFF: the same bound path 404s (flag governs everything).
    let port_off_chirho = unused_local_port_chirho();
    let addr_off_chirho = format!("127.0.0.1:{port_off_chirho}");
    let root_off_chirho = root_chirho.clone();
    let runtime_off_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_off_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_off_chirho, port_off_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_off_chirho);
        let off_chirho = http_get_for_smoke_chirho(&addr_off_chirho, "/shop");
        assert_eq!(
            off_chirho.status_chirho, 404,
            "routing-off server keeps the legacy 404 for the bound path"
        );
        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn domain_bound_root_and_named_no_body_surfaces_reject_before_body_collection_chirho() {
    let root_chirho = temp_root_chirho("domain-no-body");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "domainbody",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        "domainbody",
        "status",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho,
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "domainbody",
        Some("status"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    cairn_chirho::app_manifest_chirho::deploy_app_manifest_chirho(
        &root_chirho,
        &cairn_chirho::app_manifest_chirho::AppDeployManifestChirho {
            request_access_policy_chirho: None,
            schema_chirho: cairn_chirho::app_manifest_chirho::APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO
                .to_string(),
            app_chirho: "domainbody".to_string(),
            owner_chirho: owner_chirho.clone(),
            root_chirho: None,
            input_mode_chirho: Some(cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho),
            request_body_policy_chirho: Some(
                cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho,
            ),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        },
    )
    .unwrap();
    domain_binding_chirho::emit_domain_binding_chirho(
        &root_chirho,
        domain_binding_chirho::DomainBindingInputChirho {
            owner_principal_chirho: owner_chirho.clone(),
            host_chirho: "127.0.0.1".to_string(),
            path_prefix_chirho: "/body".to_string(),
            app_chirho: "domainbody".to_string(),
            route_base_chirho: Some("status".to_string()),
            status_chirho: domain_binding_chirho::DomainBindingStatusChirho::ActiveChirho,
        },
    )
    .unwrap();
    domain_binding_chirho::emit_domain_binding_chirho(
        &root_chirho,
        domain_binding_chirho::DomainBindingInputChirho {
            owner_principal_chirho: owner_chirho,
            host_chirho: "127.0.0.1".to_string(),
            path_prefix_chirho: "/root-body".to_string(),
            app_chirho: "domainbody".to_string(),
            route_base_chirho: None,
            status_chirho: domain_binding_chirho::DomainBindingStatusChirho::ActiveChirho,
        },
    )
    .unwrap();

    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let server_root_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_with_domain_routing_chirho(
                &server_root_chirho,
                port_chirho,
                8,
                String::new(),
                String::new(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);
        let response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/body",
            &[],
            b"must-not-reach-domain-route",
        )
        .unwrap();
        assert_eq!(response_chirho.status_chirho, 405);
        assert_eq!(runtime_tree_snapshot_chirho(&root_chirho), before_chirho);
        let root_before_chirho = runtime_tree_snapshot_chirho(&root_chirho);
        let root_response_chirho = try_http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/root-body",
            &[],
            b"must-not-reach-domain-root",
        )
        .unwrap();
        assert_eq!(root_response_chirho.status_chirho, 405);
        assert_eq!(
            runtime_tree_snapshot_chirho(&root_chirho),
            root_before_chirho
        );
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn binding_route_mapping_boundaries_chirho() {
    // Root prefix: whole host bound; one segment names an app route; deeper paths are not servable.
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/", "/"),
        Some(None)
    );
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/", "/contact"),
        Some(Some("contact".to_string()))
    );
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/", "/contact/"),
        Some(Some("contact".to_string()))
    );
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/", "/a/b"),
        None
    );
    // Named prefix: the prefix itself is the default surface; one extra segment is a route.
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/shop", "/shop"),
        Some(None)
    );
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/shop", "/shop/orders"),
        Some(Some("orders".to_string()))
    );
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/shop", "/shop/a/b"),
        None
    );
    // Non-matching paths never map (the resolver guarantees the prefix matched upstream).
    assert_eq!(
        app_http_chirho::binding_route_for_path_chirho("/shop", "/other"),
        None
    );
}

#[test]
fn ssr_route_honors_selected_input_policy_before_dag_chirho() {
    let private_root_chirho = temp_root_chirho("ssr-private-policy");
    let private_owner_chirho = identity_chirho::register_identity_chirho(
        &private_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &private_root_chirho,
        "ssrprivate",
        &private_owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &private_root_chirho,
        "ssrprivate",
        None,
        &private_owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/ssrprivate/inbox".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    let private_state_chirho = app_state_for_root_chirho(&private_root_chirho);
    let private_runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    private_runtime_chirho.block_on(async {
        let mut after_first_get_chirho = None;
        for attempt_chirho in 0..3 {
            let response_chirho = ssr_get_chirho(
                State(private_state_chirho.clone()),
                None,
                HeaderMap::new(),
                AxPath("ssrprivate".to_string()),
            )
            .await;
            assert_eq!(response_chirho.status(), StatusCode::OK);
            let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_chirho = String::from_utf8_lossy(&body_chirho);
            assert!(!body_chirho.contains("APP-PRIVATE-INPUT-REF-V1-CHIRHO"));
            assert!(!body_chirho.contains("APP/SSRPRIVATE/INBOX"));
            let snapshot_chirho = runtime_tree_snapshot_chirho(&private_root_chirho);
            if attempt_chirho == 0 {
                after_first_get_chirho = Some(snapshot_chirho);
            } else {
                assert_eq!(
                    snapshot_chirho.keys().collect::<Vec<_>>(),
                    after_first_get_chirho
                        .as_ref()
                        .unwrap()
                        .keys()
                        .collect::<Vec<_>>(),
                    "zero-body private-mode GETs may append lifecycle audit rows but must add none of the seven persistent request files"
                );
            }
        }
    });
    let private_blobs_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&private_root_chirho)
            .unwrap();
    assert!(private_blobs_chirho.is_empty());
    let _ = std::fs::remove_dir_all(&private_root_chirho);

    let tampered_policy_chirho = contact_control_plane_http_fixture_chirho("ssr-tampered-policy");
    let mut policy_records_chirho = cairn_chirho::app_chirho::load_app_input_policy_records_chirho(
        &tampered_policy_chirho.root_chirho,
    )
    .unwrap();
    policy_records_chirho[0].mode_chirho =
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho;
    write_jsonl_rows_chirho(
        &tampered_policy_chirho
            .root_chirho
            .join("app-input-policy-records-chirho.jsonl"),
        &policy_records_chirho,
    );
    let tampered_response_chirho =
        get_ssr_over_http_chirho(&tampered_policy_chirho.root_chirho, "contact", &[]);
    assert_eq!(tampered_response_chirho.status_chirho, 400);
    // Selection verifies the input-policy records, so a tampered one is refused there; the verifier names the cause.
    assert_eq!(
        String::from_utf8_lossy(&tampered_response_chirho.body_chirho),
        "error: app-selection-refused-chirho\n"
    );
    assert_verifier_names_chirho(
        contact_input_mode_chirho(&tampered_policy_chirho.root_chirho),
        "app input policy record 0 signature invalid",
    );
    assert_optional_dir_empty_chirho(
        &tampered_policy_chirho.root_chirho.join("runs-chirho"),
        "runs-chirho",
    );
    assert_optional_dir_empty_chirho(
        &tampered_policy_chirho.root_chirho.join("effects-chirho"),
        "effects-chirho",
    );
    assert_eq!(
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(
            &tampered_policy_chirho.root_chirho
        )
        .unwrap()
        .len(),
        0
    );
    let _ = std::fs::remove_dir_all(&tampered_policy_chirho.root_chirho);

    let missing_policy_chirho = contact_control_plane_http_fixture_chirho("ssr-missing-policy");
    std::fs::write(
        missing_policy_chirho
            .root_chirho
            .join("app-input-policy-records-chirho.jsonl"),
        "",
    )
    .unwrap();
    let missing_response_chirho =
        get_ssr_over_http_chirho(&missing_policy_chirho.root_chirho, "contact", &[]);
    assert_eq!(missing_response_chirho.status_chirho, 400);
    // A missing policy passes selection (which verifies the records that exist) and is refused where the
    // input mode is resolved, so the body is the input site's fixed identity; the verifier names the cause.
    assert_eq!(
        String::from_utf8_lossy(&missing_response_chirho.body_chirho),
        "error: app-input-refused-chirho\n"
    );
    assert_verifier_names_chirho(
        contact_input_mode_chirho(&missing_policy_chirho.root_chirho),
        "needs a signed input policy",
    );
    assert_optional_dir_empty_chirho(
        &missing_policy_chirho.root_chirho.join("runs-chirho"),
        "runs-chirho",
    );
    assert_optional_dir_empty_chirho(
        &missing_policy_chirho.root_chirho.join("effects-chirho"),
        "effects-chirho",
    );
    assert_eq!(
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(
            &missing_policy_chirho.root_chirho
        )
        .unwrap()
        .len(),
        0
    );
    let _ = std::fs::remove_dir_all(&missing_policy_chirho.root_chirho);

    let routed_root_chirho = temp_root_chirho("ssr-routed-policy");
    let routed_owner_chirho = identity_chirho::register_identity_chirho(
        &routed_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &routed_root_chirho,
        "ssrgate",
        &routed_owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_for_owner_chirho(
        &routed_root_chirho,
        "ssrgate",
        "plainfallback",
        &routed_owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/reverse-chirho.wat"),
        "reverse_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &routed_root_chirho,
        "ssrgate",
        None,
        &routed_owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/ssrgate/root".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &routed_root_chirho,
        "ssrgate",
        Some("plainfallback"),
        &routed_owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let (_user_chirho, routed_headers_chirho) = scoped_headers_for_app_chirho(
        &routed_root_chirho,
        "ssrgate",
        &routed_owner_chirho.principal_chirho,
        "ssr-routed-secret",
    );
    resource_chirho::set_resource_policy_chirho(
        &routed_root_chirho,
        "ssrgate",
        &routed_owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "ssr_credit_chirho".to_string(),
            unit_chirho: "credit".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(1),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::RouteChirho {
                route_chirho: "plainfallback".to_string(),
                forward_request_body_chirho: false,
            },
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "ssr_credit_chirho".to_string(),
                amount_chirho: 2,
            }],
        }],
    )
    .unwrap();
    let auth_header_chirho = routed_headers_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let routed_response_chirho = get_ssr_over_http_chirho(
        &routed_root_chirho,
        "ssrgate",
        &[("authorization", auth_header_chirho.as_str())],
    );
    assert_eq!(
        routed_response_chirho.status_chirho,
        200,
        "{}",
        String::from_utf8_lossy(&routed_response_chirho.body_chirho)
    );
    assert_eq!(
            cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&routed_root_chirho)
                .unwrap()
                .len(),
            0,
            "SSR should use the selected PlainChirho fallback route policy, not the root PrivateBlobRefChirho policy"
        );
    let routed_usage_chirho =
        resource_chirho::load_resource_usage_chirho(&routed_root_chirho).unwrap();
    assert_eq!(routed_usage_chirho.len(), 1);
    assert!(matches!(
        routed_usage_chirho[0].decision_chirho,
        resource_chirho::ResourceDecisionChirho::RoutedChirho { .. }
    ));
    let _ = std::fs::remove_dir_all(&routed_root_chirho);
}

#[test]
fn served_dag_transport_call_sites_stay_policy_bound_chirho() {
    let source_chirho = include_str!("../../serve_chirho.rs");
    let runtime_ports_source_chirho = include_str!("../runtime_ports_chirho.rs");
    let app_root_source_chirho = include_str!("../app_web_chirho/app_root_chirho.rs");
    let app_http_source_chirho = include_str!("../runtime_web_chirho/app_http_chirho.rs");
    let invoke_source_chirho = include_str!("../runtime_web_chirho/invoke_transport_chirho.rs");
    let ssr_source_chirho = include_str!("../runtime_web_chirho/ssr_web_chirho.rs");
    let production_chirho = source_chirho
        .split("#[path = \"serve_chirho/tests_chirho.rs\"]")
        .next()
        .expect("serve source should contain the test module marker");
    assert_eq!(
        production_chirho
            .matches("try_run_with_context_chirho(")
            .count(),
        2,
        "only the pure public run door and its helper may use synchronous served execution"
    );
    assert!(!production_chirho.contains("postgres_effect_chirho.with_runtime_chirho("));
    let startup_source_chirho = include_str!("../runtime_lifecycle_chirho/startup_chirho.rs");
    assert!(startup_source_chirho
        .contains("resume_unfinished_run_intents_for_served_effect_runtime_chirho("));
    assert!(startup_source_chirho.contains(".await?;"));

    assert!(ssr_source_chirho.contains("app_dag_input_chirho("));
    assert!(ssr_source_chirho.contains("try_run_served_with_context_chirho("));
    assert!(!ssr_source_chirho.contains("try_run_with_context_chirho("));

    assert!(app_http_source_chirho.contains("app_http_dag_input_value_chirho("));
    assert!(app_http_source_chirho.contains("try_run_served_input_with_context_chirho("));
    assert!(!app_http_source_chirho.contains("try_run_input_with_context_chirho("));
    assert!(app_root_source_chirho.contains("run_app_http_with_method_for_served_request_chirho("));

    assert!(invoke_source_chirho.contains("app_dag_input_chirho("));
    assert!(invoke_source_chirho.contains("try_run_served_with_context_and_caller_key_chirho("));
    assert!(!invoke_source_chirho.contains("try_run_with_context_chirho("));

    for handler_source_chirho in [
        app_root_source_chirho,
        app_http_source_chirho,
        invoke_source_chirho,
        ssr_source_chirho,
    ] {
        assert!(!handler_source_chirho.contains("postgres_effect_chirho.with_runtime_chirho("));
        assert!(!handler_source_chirho.contains("tokio::task::spawn_blocking("));
    }

    assert_eq!(
        runtime_ports_source_chirho
            .matches("tokio::task::spawn_blocking(task_chirho)")
            .count(),
        1,
        "all blocking work must go through the facade's one blocking hop"
    );
    // Served-overload (ii): startup Resume enters the typed provider boundary directly; the served public and private
    // runs enter it through the served-run boundary, which executes EVERY served run on the blocking pool and sends a
    // Postgres configuration through the same typed boundary.
    assert_eq!(
        runtime_ports_source_chirho
            .matches("spawn_blocking_provider_task_chirho(move ||")
            .count(),
        1,
        "startup Resume must move its whole provider section off-worker"
    );
    assert_eq!(
        runtime_ports_source_chirho
            .matches("spawn_blocking_served_run_chirho(self.postgres_effect_chirho.is_some(), move ||")
            .count(),
        2,
        "public and private served runs must move their whole sections off-worker in every configuration"
    );
    assert_eq!(
        runtime_ports_source_chirho
            .matches("postgres_effect_chirho.with_runtime_chirho(")
            .count(),
        3,
        "the provider mutex may be acquired only inside the three synchronous sections owned by the blocking facade"
    );
    assert!(runtime_ports_source_chirho
        .contains("run_dag_with_intent_for_served_request_and_caller_key_chirho("));
    assert!(runtime_ports_source_chirho
        .contains("run_dag_with_private_input_intent_for_served_request_chirho("));
    assert!(runtime_ports_source_chirho
        .contains("run_dag_with_intent_and_effect_runtime_and_caller_key_chirho("));
    // C5 2a: every served run enters through a ports-taking entry, which carries a signed-out request's declared
    // owner. The projection-read convenience entries carry none, so the facade must not call them.
    for convenience_chirho in [
        "run_dag_with_intent_and_projection_read_chirho(",
        "run_dag_with_intent_and_projection_read_and_caller_key_chirho(",
        "run_dag_with_private_input_intent_and_projection_read_chirho(",
        "run_dag_with_private_input_intent_and_projection_read_and_caller_key_chirho(",
    ] {
        assert!(
            !runtime_ports_source_chirho.contains(convenience_chirho),
            "the facade calls {convenience_chirho}, which cannot carry a declared owner"
        );
    }
    // Reversed by served-overload (ii) (PFE #26386, b8be185): an inline projection-only run held the async worker for
    // its synchronous writes, so the in-flight cap could not shed at the door. No served run executes inline now.
    assert_eq!(
        runtime_ports_source_chirho
            .matches("self.postgres_effect_chirho.is_none()")
            .count(),
        0,
        "no served run may keep an inline path on the async worker"
    );

    // C5 2a: the plain lane takes the combined runtime bundle too (it carries the injected projection-read port AND a
    // signed-out request's declared owner), so each entry appears once per lane: plain, postgres Descriptor-D and dev
    // llm-served. The projection-read convenience entries are refused above.
    assert_eq!(
        runtime_ports_source_chirho
            .matches("run_dag_with_intent_and_effect_runtime_chirho(")
            .count(),
        3,
        "served public execution uses the one combined runtime bundle once per lane (plain, postgres Descriptor-D, dev llm-served)"
    );
    assert_eq!(
        runtime_ports_source_chirho
            .matches("run_dag_with_private_input_intent_and_effect_runtime_chirho(")
            .count(),
        3,
        "served private execution uses the one combined runtime bundle once per lane (plain, postgres Descriptor-D, dev llm-served)"
    );
    // The dev served-LLM composition mutex may be acquired only inside the two served-run
    // dispatchers (public + private), mirroring the postgres provider-mutex confinement above.
    assert_eq!(
        runtime_ports_source_chirho
            .matches("llm_served_chirho.with_composition_chirho(")
            .count(),
        2,
        "the dev served-LLM composition mutex is acquired only inside the two served-run dispatchers"
    );
    assert_eq!(
        runtime_ports_source_chirho
            .matches("self.projection_read_chirho.as_deref()")
            .count(),
        6,
        "public/private and projection-only/effect/llm-served paths must use the same root-owned projection authority"
    );

    let run_http_chirho = include_str!("../runtime_web_chirho/public_run_chirho.rs");
    assert!(run_http_chirho.contains("ensure_public_run_dag_is_pure_wasm_chirho("));
    assert!(run_http_chirho.contains("try_run_chirho("));
}

#[test]
fn invoke_transport_honors_private_input_policy_before_dag_chirho() {
    let raw_body_chirho =
            b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery";
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_body_chirho);
    let pii_needles_chirho = ["Alice", "alice@example.com", "bakery"];

    let baseline_chirho = contact_control_plane_http_fixture_chirho("invoke-private-policy");
    let caller_key_chirho = "invoke-private-policy-operation-0001-chirho";
    let response_chirho = post_invoke_over_http_chirho(
        &baseline_chirho.root_chirho,
        "contact",
        raw_body_chirho,
        &[(
            cairn_write_relay_chirho::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
            caller_key_chirho,
        )],
    );
    assert_eq!(
        response_chirho.status_chirho,
        200,
        "{}",
        String::from_utf8_lossy(&response_chirho.body_chirho)
    );
    let response_json_chirho: serde_json::Value =
        serde_json::from_slice(&response_chirho.body_chirho).unwrap();
    assert_eq!(response_json_chirho["ok_chirho"], true);
    let payload_chirho = response_json_chirho["payload_chirho"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(String::from_utf8_lossy(&payload_chirho).contains("data-contact-chirho"));
    assert_no_contact_pii_chirho(
        "invoke private response",
        &payload_chirho,
        &pii_needles_chirho,
    );
    assert!(
        cairn_chirho::cas_chirho::get_chirho(&baseline_chirho.root_chirho, &raw_hash_chirho)
            .is_err(),
        "invoke persisted the raw payload as a CAS object"
    );
    // One person blob; the rest are F4 store-seal artifacts under `app-store/`.
    let blob_records_chirho = cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(
        &baseline_chirho.root_chirho,
    )
    .unwrap();
    assert_eq!(
        non_store_seal_blob_subjects_chirho(&baseline_chirho.root_chirho),
        vec!["app/contact/inbox".to_string()]
    );
    let person_blob_chirho = blob_records_chirho
        .iter()
        .find(|record_chirho| record_chirho.subject_chirho == "app/contact/inbox")
        .unwrap();
    assert_eq!(
        cairn_chirho::privacy_chirho::load_private_blob_chirho(
            &baseline_chirho.root_chirho,
            &person_blob_chirho.blob_chirho
        )
        .unwrap(),
        raw_body_chirho
    );
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &baseline_chirho.root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let contact_view_chirho = store_chirho.current_view_chirho().unwrap();
    let stored_contact_chirho = store_chirho
        .get_chirho("contacts-chirho/latest")
        .unwrap()
        .unwrap();
    drop(store_chirho);
    assert!(
        String::from_utf8_lossy(&stored_contact_chirho).contains("app-private-input-ref-v1-chirho")
    );
    assert_no_contact_pii_chirho(
        "invoke stored contact row",
        &stored_contact_chirho,
        &pii_needles_chirho,
    );
    assert_contact_persisted_surfaces_no_pii_chirho(
        &baseline_chirho.root_chirho,
        &[contact_view_chirho],
        &pii_needles_chirho,
    );
    let run_intents_chirho =
        cairn_chirho::effect_chirho::run_intent_chirho::load_run_intent_records_chirho(
            &baseline_chirho.root_chirho,
        )
        .unwrap();
    let caller_key_digest_chirho = HashChirho(
        cairn_write_relay_chirho::CallerIdempotencyKeyChirho::new_chirho(caller_key_chirho)
            .unwrap()
            .digest_hex_chirho(),
    );
    assert_eq!(
        run_intents_chirho.len(),
        3,
        "one keyed invoke must persist pending, running, and done records"
    );
    assert!(run_intents_chirho.iter().all(|record_chirho| {
        record_chirho.schema_chirho
            == cairn_chirho::effect_chirho::run_intent_chirho::RUN_INTENT_RECORD_SCHEMA_V2_CHIRHO
            && record_chirho.caller_idempotency_key_digest_chirho.as_ref()
                == Some(&caller_key_digest_chirho)
    }));
    let run_intent_bytes_chirho =
        std::fs::read(baseline_chirho.root_chirho.join("run-intents-chirho.jsonl")).unwrap();
    assert!(
        !String::from_utf8_lossy(&run_intent_bytes_chirho).contains(caller_key_chirho),
        "the caller key itself must never enter the durable intent log"
    );
    let _ = std::fs::remove_dir_all(&baseline_chirho.root_chirho);

    let ws_chirho = contact_control_plane_http_fixture_chirho("invoke-ws-helper-policy");
    let state_chirho = app_state_for_root_chirho(&ws_chirho.root_chirho);
    let req_chirho = serde_json::to_string(&serde_json::json!({
        "target_chirho": "contact",
        "payload_chirho": std::str::from_utf8(raw_body_chirho).unwrap(),
    }))
    .unwrap();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let ws_caller_key_chirho = "invoke-ws-handshake-key-must-not-bind-chirho";
    let mut ws_headers_chirho = HeaderMap::new();
    ws_headers_chirho.insert(
        cairn_write_relay_chirho::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
        axum::http::HeaderValue::from_static(ws_caller_key_chirho),
    );
    let ws_response_chirho = runtime_chirho.block_on(async {
        invoke_transport_chirho::process_invoke_json_with_headers_chirho(
            &state_chirho,
            &req_chirho,
            Some(&ws_headers_chirho),
            None,
        )
        .await
    });
    let ws_json_chirho: serde_json::Value = serde_json::from_str(&ws_response_chirho).unwrap();
    assert_eq!(ws_json_chirho["ok_chirho"], true);
    assert!(
        cairn_chirho::cas_chirho::get_chirho(&ws_chirho.root_chirho, &raw_hash_chirho).is_err(),
        "ws shared invoke helper persisted the raw payload as a CAS object"
    );
    let ws_store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &ws_chirho.root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let ws_view_chirho = ws_store_chirho.current_view_chirho().unwrap();
    drop(ws_store_chirho);
    assert_contact_persisted_surfaces_no_pii_chirho(
        &ws_chirho.root_chirho,
        &[ws_view_chirho],
        &pii_needles_chirho,
    );
    let ws_run_intents_chirho =
        cairn_chirho::effect_chirho::run_intent_chirho::load_run_intent_records_chirho(
            &ws_chirho.root_chirho,
        )
        .unwrap();
    assert_eq!(
        ws_run_intents_chirho.len(),
        3,
        "the WebSocket invoke must still execute through the legacy intent path"
    );
    assert!(ws_run_intents_chirho.iter().all(|record_chirho| {
        record_chirho.schema_chirho
            == cairn_chirho::effect_chirho::run_intent_chirho::RUN_INTENT_RECORD_SCHEMA_CHIRHO
            && record_chirho.caller_idempotency_key_digest_chirho.is_none()
    }));
    assert!(
        !std::fs::read_to_string(ws_chirho.root_chirho.join("run-intents-chirho.jsonl"))
            .unwrap()
            .contains(ws_caller_key_chirho),
        "a WebSocket handshake key must not become one idempotency key for many messages"
    );
    let _ = std::fs::remove_dir_all(&ws_chirho.root_chirho);

    let invalid_key_chirho = contact_control_plane_http_fixture_chirho("invoke-invalid-caller-key");
    let invalid_key_response_chirho = post_invoke_over_http_chirho(
        &invalid_key_chirho.root_chirho,
        "contact",
        raw_body_chirho,
        &[(
            cairn_write_relay_chirho::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO,
            "invalid caller key chirho",
        )],
    );
    assert_eq!(invalid_key_response_chirho.status_chirho, 400);
    let invalid_key_body_chirho = String::from_utf8_lossy(&invalid_key_response_chirho.body_chirho);
    assert!(
        invalid_key_body_chirho.contains("RelayCallerKeyInvalidChirho"),
        "{invalid_key_body_chirho}"
    );
    assert!(
        !invalid_key_body_chirho.contains("RelayCallerKeyCollisionChirho"),
        "{invalid_key_body_chirho}"
    );
    assert!(
        cairn_chirho::effect_chirho::run_intent_chirho::load_run_intent_records_chirho(
            &invalid_key_chirho.root_chirho,
        )
        .unwrap()
        .is_empty(),
        "an invalid caller key must refuse before any run-intent row"
    );
    let _ = std::fs::remove_dir_all(&invalid_key_chirho.root_chirho);

    let tampered_policy_chirho =
        contact_control_plane_http_fixture_chirho("invoke-tampered-policy");
    let mut policy_records_chirho = cairn_chirho::app_chirho::load_app_input_policy_records_chirho(
        &tampered_policy_chirho.root_chirho,
    )
    .unwrap();
    policy_records_chirho[0].mode_chirho =
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho;
    write_jsonl_rows_chirho(
        &tampered_policy_chirho
            .root_chirho
            .join("app-input-policy-records-chirho.jsonl"),
        &policy_records_chirho,
    );
    let tampered_response_chirho = post_invoke_over_http_chirho(
        &tampered_policy_chirho.root_chirho,
        "contact",
        raw_body_chirho,
        &[],
    );
    assert_served_control_plane_attack_blocked_chirho(
        &tampered_policy_chirho.root_chirho,
        &tampered_response_chirho,
        raw_body_chirho,
        &pii_needles_chirho,
        400,
        Some("app-selection-refused-chirho"),
    );
    assert_verifier_names_chirho(
        contact_input_mode_chirho(&tampered_policy_chirho.root_chirho),
        "app input policy record 0 signature invalid",
    );
    let _ = std::fs::remove_dir_all(&tampered_policy_chirho.root_chirho);

    let missing_policy_chirho = contact_control_plane_http_fixture_chirho("invoke-missing-policy");
    std::fs::write(
        missing_policy_chirho
            .root_chirho
            .join("app-input-policy-records-chirho.jsonl"),
        "",
    )
    .unwrap();
    let missing_response_chirho = post_invoke_over_http_chirho(
        &missing_policy_chirho.root_chirho,
        "contact",
        raw_body_chirho,
        &[],
    );
    assert_served_control_plane_attack_blocked_chirho(
        &missing_policy_chirho.root_chirho,
        &missing_response_chirho,
        raw_body_chirho,
        &pii_needles_chirho,
        400,
        Some("app-input-refused-chirho"),
    );
    assert_verifier_names_chirho(
        contact_input_mode_chirho(&missing_policy_chirho.root_chirho),
        "needs a signed input policy",
    );
    let _ = std::fs::remove_dir_all(&missing_policy_chirho.root_chirho);

    let plain_root_chirho = temp_root_chirho("invoke-plain-policy");
    let plain_owner_chirho = identity_chirho::register_identity_chirho(
        &plain_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &plain_root_chirho,
        "plainwire",
        &plain_owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(
        &plain_root_chirho,
        "plainwire",
        &plain_owner_chirho,
    );
    let plain_response_chirho =
        post_invoke_over_http_chirho(&plain_root_chirho, "plainwire", b"plain ok", &[]);
    assert_eq!(plain_response_chirho.status_chirho, 200);
    let plain_json_chirho: serde_json::Value =
        serde_json::from_slice(&plain_response_chirho.body_chirho).unwrap();
    assert_eq!(plain_json_chirho["payload_chirho"], "PLAIN OK");
    let _ = std::fs::remove_dir_all(&plain_root_chirho);
}

#[test]
fn invoke_transport_uses_selected_route_input_policy_chirho() {
    let root_chirho = temp_root_chirho("invoke-resource-route-policy");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "premiumgate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "premiumgate",
        None,
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/premiumgate/inbox".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    deploy_transform_app_route_for_owner_chirho(
        &root_chirho,
        "premiumgate",
        "litegate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/reverse-chirho.wat"),
        "reverse_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "premiumgate",
        Some("litegate"),
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let (_user_chirho, headers_chirho) = scoped_headers_for_app_chirho(
        &root_chirho,
        "premiumgate",
        &owner_chirho.principal_chirho,
        "invoke-route-secret",
    );
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "premiumgate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "labs_credit_chirho".to_string(),
            unit_chirho: "credit".to_string(),
            stack_chirho: Some("labs".to_string()),
            per_user_limit_chirho: Some(1),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::RouteChirho {
                route_chirho: "litegate".to_string(),
                forward_request_body_chirho: true,
            },
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "labs_credit_chirho".to_string(),
                amount_chirho: 2,
            }],
        }],
    )
    .unwrap();
    let authorization_chirho = headers_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let response_chirho = post_invoke_over_http_chirho(
        &root_chirho,
        "premiumgate",
        b"abc",
        &[("authorization", &authorization_chirho)],
    );
    assert_eq!(
        response_chirho.status_chirho,
        200,
        "{}",
        String::from_utf8_lossy(&response_chirho.body_chirho)
    );
    let response_json_chirho: serde_json::Value =
        serde_json::from_slice(&response_chirho.body_chirho).unwrap();
    assert_eq!(response_json_chirho["payload_chirho"], "cba");
    assert!(
            cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
                .unwrap()
                .is_empty(),
            "resource-routed invoke should use the selected route PlainChirho policy, not the root PrivateBlobRefChirho policy"
        );
    let usage_chirho = resource_chirho::load_resource_usage_chirho(&root_chirho).unwrap();
    assert_eq!(usage_chirho.len(), 1);
    assert!(matches!(
        usage_chirho[0].decision_chirho,
        resource_chirho::ResourceDecisionChirho::RoutedChirho { .. }
    ));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn invoke_and_ws_reroutes_discard_payload_for_reviewed_no_body_route_chirho() {
    fn reverse_output_json_chirho(output_chirho: &str) -> serde_json::Value {
        let input_chirho = output_chirho.chars().rev().collect::<String>();
        serde_json::from_str(&input_chirho).unwrap()
    }

    let root_chirho = temp_root_chirho("invoke-no-body-route");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "bodygate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(
        &root_chirho,
        "bodygate",
        &owner_chirho.principal_chirho,
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        "bodygate",
        "status",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../examples-chirho/reverse-chirho.wat"),
        "reverse_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho,
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "bodygate",
        Some("status"),
        &owner_chirho.principal_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let (_user_chirho, headers_chirho) = scoped_headers_for_app_chirho(
        &root_chirho,
        "bodygate",
        &owner_chirho.principal_chirho,
        "invoke-no-body-secret",
    );
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "bodygate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "body_credit_chirho".to_string(),
            unit_chirho: "credit".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(1),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::RouteChirho {
                route_chirho: "status".to_string(),
                forward_request_body_chirho: true,
            },
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "body_credit_chirho".to_string(),
                amount_chirho: 2,
            }],
        }],
    )
    .unwrap();

    let raw_payload_chirho = b"must-not-reach-the-selected-route-chirho";
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_payload_chirho);
    let authorization_chirho = headers_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let http_response_chirho = post_invoke_over_http_chirho(
        &root_chirho,
        "bodygate",
        raw_payload_chirho,
        &[("authorization", &authorization_chirho)],
    );
    assert_eq!(http_response_chirho.status_chirho, 200);
    let http_json_chirho: serde_json::Value =
        serde_json::from_slice(&http_response_chirho.body_chirho).unwrap();
    let http_input_chirho =
        reverse_output_json_chirho(http_json_chirho["payload_chirho"].as_str().unwrap());
    assert_eq!(
        http_input_chirho.as_object().unwrap().len(),
        1,
        "the selected no-body route may receive verified context but no request payload"
    );
    assert!(http_input_chirho.get("user_principal_chirho").is_some());

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let wire_chirho = serde_json::to_string(&serde_json::json!({
        "target_chirho": "bodygate",
        "payload_chirho": std::str::from_utf8(raw_payload_chirho).unwrap(),
    }))
    .unwrap();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let ws_response_chirho = runtime_chirho.block_on(
        invoke_transport_chirho::process_invoke_json_with_headers_chirho(
            &state_chirho,
            &wire_chirho,
            Some(&headers_chirho),
            None,
        ),
    );
    let ws_json_chirho: serde_json::Value = serde_json::from_str(&ws_response_chirho).unwrap();
    assert_eq!(ws_json_chirho["ok_chirho"], true);
    let ws_input_chirho =
        reverse_output_json_chirho(ws_json_chirho["payload_chirho"].as_str().unwrap());
    assert_eq!(ws_input_chirho, http_input_chirho);
    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &raw_hash_chirho).is_err());
    assert_eq!(
        resource_chirho::load_resource_usage_chirho(&root_chirho)
            .unwrap()
            .len(),
        2,
        "bounded resource metering may append before the final selected-route body ceiling"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn html_lower_wraps_body_chirho() {
    let root_chirho = temp_root_chirho("html-lower");
    let html_chirho =
        ssr_web_chirho::html_lower_chirho(&root_chirho, b"<h1>hi</h1>", "app", "abc123");
    assert!(html_chirho.contains("<!doctype html>"));
    assert!(html_chirho.contains("<h1>hi</h1>"));
    assert!(html_chirho.contains("</body>"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn wire_request_defaults_chirho() {
    let req_chirho: invoke_transport_chirho::WireRequestChirho =
        serde_json::from_str(r#"{"target_chirho":"counter"}"#).unwrap();
    assert_eq!(req_chirho.target_chirho, "counter");
    assert_eq!(req_chirho.payload_chirho, "");
    assert_eq!(req_chirho.base_version_chirho, None);
}

#[test]
fn public_run_route_accepts_only_pure_wasm_dags_chirho() {
    let root_chirho = temp_root_chirho("public-run-pure-only");
    let pure_dag_chirho = store_transform_dag_chirho(
        &root_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    let write_key_chirho = "public-run-write-chirho/latest";
    let write_dag_chirho = store_write_effect_dag_chirho(&root_chirho, write_key_chirho);
    let denied_body_chirho = b"m182-public-run-raw-body-should-not-enter-cas-or-store@example.com";
    let denied_body_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(denied_body_chirho);
    let pure_dag_object_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &pure_dag_chirho).unwrap();
    let write_dag_object_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &write_dag_chirho).unwrap();
    let mut mixed_nodes_chirho = pure_dag_object_chirho.nodes_chirho.clone();
    mixed_nodes_chirho.extend(write_dag_object_chirho.nodes_chirho.clone());
    let mixed_dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: mixed_nodes_chirho,
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let mixed_body_chirho = b"m182-public-run-mixed-node-body-should-not-enter-cas";
    let mixed_body_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(mixed_body_chirho);
    let native_schema_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
    let native_spec_hash_chirho = HashChirho("a".repeat(64));
    let native_node_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &NodeDefChirho {
            name_chirho: "public_run_native_marker_chirho".to_string(),
            impl_wasm_chirho: cairn_chirho::native_worker_chirho::native_node_impl_hash_chirho(
                &native_spec_hash_chirho,
            ),
            entry_chirho: "run-chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: native_schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: native_schema_hash_chirho,
            }],
            capabilities_chirho: Vec::new(),
            fuel_limit_chirho: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let native_dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![native_node_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let native_body_chirho = b"m182-public-run-native-body-should-not-enter-cas";
    let native_body_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(native_body_chirho);

    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let pure_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("/run-chirho/{}", pure_dag_chirho.0),
            &[],
            b"hello public run",
        );
        assert_eq!(pure_response_chirho.status_chirho, 200);
        assert_eq!(pure_response_chirho.body_chirho, b"HELLO PUBLIC RUN");

        let denied_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("/run-chirho/{}", write_dag_chirho.0),
            &[],
            denied_body_chirho,
        );
        assert_eq!(denied_response_chirho.status_chirho, 403);
        let denied_text_chirho = http_body_text_chirho(&denied_response_chirho);
        // The policy refusal's identity, with no node name or capability count.
        assert_eq!(
            denied_text_chirho,
            "error: capability-free-dag-required-chirho\n"
        );
        assert!(!denied_text_chirho.contains("m182-public-run-raw-body"));

        let mixed_denied_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("/run-chirho/{}", mixed_dag_chirho.0),
            &[],
            mixed_body_chirho,
        );
        assert_eq!(mixed_denied_chirho.status_chirho, 403);
        let mixed_denied_text_chirho = http_body_text_chirho(&mixed_denied_chirho);
        // The policy refusal's identity, with no node name or capability count.
        assert_eq!(
            mixed_denied_text_chirho,
            "error: capability-free-dag-required-chirho\n"
        );
        assert!(!mixed_denied_text_chirho.contains("m182-public-run-mixed-node-body"));

        let native_denied_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("/run-chirho/{}", native_dag_chirho.0),
            &[],
            native_body_chirho,
        );
        assert_eq!(native_denied_chirho.status_chirho, 403);
        let native_denied_text_chirho = http_body_text_chirho(&native_denied_chirho);
        // The policy refusal's identity, with no node name or capability count.
        assert_eq!(
            native_denied_text_chirho,
            "error: wasm-dag-required-chirho\n"
        );
        assert!(!native_denied_text_chirho.contains("m182-public-run-native-body"));

        server_chirho.abort();
        let _ = server_chirho.await;
    });

    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &denied_body_hash_chirho).is_err());
    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &mixed_body_hash_chirho).is_err());
    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &native_body_hash_chirho).is_err());
    assert!(!root_chirho.join("effects-chirho").exists());
    assert!(!root_chirho.join("versioned-chirho.redb").exists());

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let admission_chirho =
        served_admission_for_state_chirho(&state_chirho, denied_body_chirho.len());
    // The control: run directly with an operator's declaration, the denied DAG does write. A public run declares no
    // owner (it belongs to no app), so its private store would refuse; that is not what this control measures.
    let operator_chirho =
        cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho::not_account_scoped_chirho(
            cairn_chirho::privacy_chirho::NotAccountScopedReasonChirho::OperatorRunChirho,
        );
    let direct_payload_chirho = try_run_with_context_chirho(
        &state_chirho,
        &admission_chirho,
        &write_dag_chirho.0,
        denied_body_chirho,
        None,
        Some(&operator_chirho),
    )
    .unwrap();
    assert_eq!(direct_payload_chirho, denied_body_chirho);
    assert_eq!(
        cairn_chirho::cas_chirho::get_chirho(&root_chirho, &denied_body_hash_chirho).unwrap(),
        denied_body_chirho
    );
    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, write_key_chirho).unwrap(),
        denied_body_chirho
    );
    assert_eq!(
        std::fs::read_dir(root_chirho.join("effects-chirho"))
            .unwrap()
            .count(),
        1
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
