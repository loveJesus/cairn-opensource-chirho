// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn app_execution_refusal_body_is_fixed_and_detail_free_chirho() {
    let root_chirho = temp_root_chirho("app-execution-refusal-body");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let detail_needle_chirho = "private_execution_detail_needle_chirho";
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "execution-refusal",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        detail_needle_chirho,
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "execution-refusal",
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("execution-refusal".to_string()),
            Bytes::from_static(b"trigger execution refusal"),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::BAD_REQUEST);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        // The entry the node names does not exist, so the run refuses before any effect: the trusted
        // observation says its DAG effects definitely did not run, on a first attempt.
        assert_eq!(
            String::from_utf8_lossy(&body_chirho),
            crate::serve_chirho::public_error_chirho::execution_refusal_plain_body_chirho(
                cairn_chirho::dag_chirho::refusal_chirho::DagExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
                cairn_chirho::dag_chirho::refusal_chirho::DagExecutionAttemptOrdinalChirho::FirstChirho,
            )
        );
        assert!(!String::from_utf8_lossy(&body_chirho).contains(detail_needle_chirho));
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn contact_manifest_deploy_runs_through_app_route_handler_chirho() {
    let root_chirho = temp_root_chirho("contact-manifest");
    let schema_hash_chirho = cairn_chirho::cas_chirho::add_chirho(&root_chirho, b"bytes").unwrap();
    let wasm_hash_chirho = cairn_chirho::cas_chirho::add_chirho(
        &root_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    )
    .unwrap();
    let node_chirho = cairn_chirho::model_chirho::NodeDefChirho {
        name_chirho: "contact_form_chirho".to_string(),
        impl_wasm_chirho: wasm_hash_chirho,
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (_dag_chirho, dag_hash_chirho) = cairn_chirho::dag_author_chirho::build_dag_chirho(
        &root_chirho,
        cairn_chirho::dag_author_chirho::DagBuildInputChirho {
            nodes_chirho: vec![node_hash_chirho.clone()],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let (_module_chirho, module_hash_chirho) =
        cairn_chirho::dag_module_chirho::build_dag_module_chirho(
            &root_chirho,
            cairn_chirho::dag_module_chirho::DagModuleBuildInputChirho {
                name_chirho: "contact_form_chirho".to_string(),
                dag_chirho: dag_hash_chirho.clone(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![
                    cairn_chirho::dag_module_chirho::DagModuleBindingInputChirho {
                        public_name_chirho: "request_chirho".to_string(),
                        node_chirho: node_hash_chirho.clone(),
                        node_port_chirho: "in".to_string(),
                    },
                ],
                output_bindings_chirho: vec![
                    cairn_chirho::dag_module_chirho::DagModuleBindingInputChirho {
                        public_name_chirho: "response_chirho".to_string(),
                        node_chirho: node_hash_chirho,
                        node_port_chirho: "out".to_string(),
                    },
                ],
                route_labels_chirho: vec!["contact-chirho".to_string()],
                metadata_chirho: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    cairn_chirho::app_manifest_chirho::deploy_app_manifest_chirho(
        &root_chirho,
        &cairn_chirho::app_manifest_chirho::AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: cairn_chirho::app_manifest_chirho::APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO
                .to_string(),
            app_chirho: "contact".to_string(),
            owner_chirho,
            root_chirho: Some(
                cairn_chirho::app_manifest_chirho::AppDeployDagSourceChirho::ModuleChirho {
                    hash_chirho: module_hash_chirho,
                },
            ),
            input_mode_chirho: Some(cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
        },
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("contact".to_string()),
            Bytes::from_static(b"hello contact"),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body_chirho[..], b"HELLO CONTACT");
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn root_no_body_policy_returns_405_without_persisting_request_chirho() {
    let root_chirho = temp_root_chirho("root-no-body-policy");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "root-no-body",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_manifest_chirho::deploy_app_manifest_chirho(
        &root_chirho,
        &cairn_chirho::app_manifest_chirho::AppDeployManifestChirho {
            request_access_policy_chirho: None,
            schema_chirho: cairn_chirho::app_manifest_chirho::APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO
                .to_string(),
            app_chirho: "root-no-body".to_string(),
            owner_chirho,
            root_chirho: None,
            input_mode_chirho: Some(
                cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                    subject_chirho: "app/root-no-body/input".to_string(),
                    safe_metadata_chirho: Vec::new(),
                },
            ),
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

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let before_post_chirho = runtime_tree_snapshot_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("root-no-body".to_string()),
            Bytes::from_static(b"must-never-persist-chirho"),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            runtime_tree_snapshot_chirho(&root_chirho),
            before_post_chirho,
            "root no-body refusal must precede privacy keys, CAS, run intent, and DAG execution"
        );

        let get_response_chirho = app_get_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            "/app-chirho/root-no-body/".parse().unwrap(),
            AxPath("root-no-body".to_string()),
        )
        .await;
        assert_eq!(get_response_chirho.status(), StatusCode::OK);

        let after_cold_get_chirho = runtime_tree_snapshot_chirho(&root_chirho);
        let warm_get_response_chirho = app_get_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            "/app-chirho/root-no-body/".parse().unwrap(),
            AxPath("root-no-body".to_string()),
        )
        .await;
        assert_eq!(warm_get_response_chirho.status(), StatusCode::OK);
        assert_eq!(
            runtime_tree_snapshot_chirho(&root_chirho),
            after_cold_get_chirho,
            "a warm pure root GET must not add runtime records or other entries"
        );
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_app_input_policy_shreds_body_before_dag_run_chirho() {
    let root_chirho = temp_root_chirho("private-app-input");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "contact-private",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact-private",
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact-private/inbox".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let raw_body_chirho =
        br#"{"name_chirho":"Alice","email_chirho":"alice@example.com","message_chirho":"secret"}"#;
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_body_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        for _attempt_chirho in 0..2 {
            let response_chirho = app_post_chirho(
                State(state_chirho.clone()),
                None,
                HeaderMap::new(),
                AxPath("contact-private".to_string()),
                Bytes::from_static(raw_body_chirho),
            )
            .await;
            assert_eq!(response_chirho.status(), StatusCode::OK);
            let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
                .await
                .unwrap();
            let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
            assert!(body_text_chirho.contains("APP-PRIVATE-INPUT-REF-V1-CHIRHO"));
            assert!(!body_text_chirho.contains("ALICE@EXAMPLE.COM"));
        }
    });
    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &raw_hash_chirho).is_err());
    let intents_chirho =
        cairn_chirho::effect_chirho::run_intent_chirho::load_run_intent_records_chirho(
            &root_chirho,
        )
        .unwrap();
    assert_eq!(intents_chirho.len(), 6);
    let journal_chirho = std::fs::read_to_string(
        cairn_chirho::effect_chirho::run_intent_chirho::run_intent_records_path_chirho(
            &root_chirho,
        ),
    )
    .unwrap();
    let request_stone_chirho =
        cairn_chirho::cas_chirho::get_chirho(&root_chirho, &intents_chirho[0].request_chirho)
            .unwrap();
    let request_text_chirho = String::from_utf8(request_stone_chirho).unwrap();
    assert!(request_text_chirho.contains("app-private-input-ref-v1-chirho"));
    for needle_chirho in ["Alice", "alice@example.com", "secret"] {
        assert!(!journal_chirho.contains(needle_chirho));
        assert!(!request_text_chirho.contains(needle_chirho));
    }
    let blob_records_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(blob_records_chirho.len(), 2);
    assert_ne!(
        blob_records_chirho[0].blob_chirho, blob_records_chirho[1].blob_chirho,
        "nonempty private inputs must retain randomized sealing and reveal no equality oracle"
    );
    for blob_record_chirho in &blob_records_chirho {
        assert_eq!(
            blob_record_chirho.subject_chirho,
            "app/contact-private/inbox"
        );
        assert_eq!(
            cairn_chirho::privacy_chirho::load_private_blob_chirho(
                &root_chirho,
                &blob_record_chirho.blob_chirho
            )
            .unwrap(),
            raw_body_chirho
        );
    }
    assert_eq!(
        cairn_chirho::app_chirho::verify_app_input_policies_chirho(&root_chirho).unwrap(),
        1
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn served_request_overage_returns_generic_429_before_any_root_write_chirho() {
    let root_chirho = temp_root_chirho("served-request-overage");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "limited-app",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "limited-app",
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let mut state_chirho = app_state_for_root_chirho(&root_chirho);
    state_chirho.served_request_abuse_gate_chirho = Arc::new(
        ServedRequestAbuseGateChirho::new_chirho(ServedRequestAbuseLimitsChirho {
            window_ms_chirho: 60_000,
            actor_max_requests_chirho: 1,
            actor_max_body_bytes_chirho: 1_024,
            global_max_requests_chirho: 1,
            global_max_body_bytes_chirho: 1_024,
            actor_bucket_cap_chirho: 4,
            ..ServedRequestAbuseLimitsChirho::default()
        })
        .unwrap(),
    );
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let accepted_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("limited-app".to_string()),
            Bytes::from_static(b"first"),
        )
        .await;
        assert_eq!(accepted_chirho.status(), StatusCode::OK);
        let before_denied_chirho = runtime_tree_snapshot_chirho(&root_chirho);

        let denied_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("limited-app".to_string()),
            Bytes::from_static(b"never-persist-chirho"),
        )
        .await;
        assert_eq!(denied_chirho.status(), StatusCode::TOO_MANY_REQUESTS);
        let denied_body_chirho = axum::body::to_bytes(denied_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&denied_body_chirho[..], b"served request unavailable\n");
        assert_eq!(
            runtime_tree_snapshot_chirho(&root_chirho),
            before_denied_chirho,
            "a rejected served request must not create CAS, run, privacy, effect, resource, projection, or sentinel state"
        );
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_response_policy_sets_verified_content_type_chirho() {
    let root_chirho = temp_root_chirho("app-root-content-type");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "htmlroot",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "htmlroot", &owner_chirho);
    cairn_chirho::app_chirho::set_app_response_policy_chirho(
        &root_chirho,
        "htmlroot",
        &owner_chirho,
        "text/html",
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath("htmlroot".to_string()),
            Bytes::from_static(b"<h1>ok</h1>"),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        assert_eq!(
            response_chirho
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            response_chirho
                .headers()
                .get("x-content-type-options")
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            response_chirho
                .headers()
                .get("content-security-policy")
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some("default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'; style-src 'self' 'unsafe-inline'; img-src 'none'; font-src 'none'")
        );
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body_chirho[..], b"<H1>OK</H1>");

        let mut records_chirho =
            cairn_chirho::app_chirho::load_app_response_policy_records_chirho(&root_chirho).unwrap();
        records_chirho[0]
            .response_content_type_chirho
            .push_str("-tamper");
        let mut out_chirho = String::new();
        for record_chirho in &records_chirho {
            out_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
            out_chirho.push('\n');
        }
        std::fs::write(
            root_chirho.join("app-response-policy-records-chirho.jsonl"),
            out_chirho,
        )
        .unwrap();

        let tampered_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("htmlroot".to_string()),
            Bytes::from_static(b"<h1>ok</h1>"),
        )
        .await;
        assert_eq!(tampered_chirho.status(), StatusCode::BAD_REQUEST);
        let tampered_body_chirho = axum::body::to_bytes(tampered_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&tampered_body_chirho).contains("<H1>OK</H1>"));
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_route_response_policy_sets_verified_content_type_chirho() {
    let root_chirho = temp_root_chirho("app-route-content-type");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "htmlapp",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_for_owner_chirho(
        &root_chirho,
        "htmlapp",
        "preview",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "htmlapp",
        Some("preview"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_route_response_policy_chirho(
        &root_chirho,
        "htmlapp",
        "preview",
        &owner_chirho,
        "text/html",
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_route_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(("htmlapp".to_string(), "preview".to_string())),
            Bytes::from_static(b"<h1>ok</h1>"),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        assert_eq!(
            response_chirho
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(
            response_chirho
                .headers()
                .get("x-content-type-options")
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            response_chirho
                .headers()
                .get("content-security-policy")
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some(APP_ROUTE_HTML_CSP_CHIRHO)
        );
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body_chirho[..], b"<H1>OK</H1>");

        let mut records_chirho =
            cairn_chirho::app_chirho::load_app_route_response_policy_records_chirho(&root_chirho)
                .unwrap();
        records_chirho[0]
            .response_content_type_chirho
            .push_str("-tamper");
        let mut out_chirho = String::new();
        for record_chirho in &records_chirho {
            out_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
            out_chirho.push('\n');
        }
        std::fs::write(
            root_chirho.join("app-route-response-policy-records-chirho.jsonl"),
            out_chirho,
        )
        .unwrap();

        let tampered_chirho = app_route_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath(("htmlapp".to_string(), "preview".to_string())),
            Bytes::from_static(b"<h1>ok</h1>"),
        )
        .await;
        assert_eq!(tampered_chirho.status(), StatusCode::BAD_REQUEST);
        let tampered_body_chirho = axum::body::to_bytes(tampered_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&tampered_body_chirho).contains("<H1>OK</H1>"));
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn unreviewed_dev_routes_emit_header_reviewed_routes_do_not_chirho() {
    let root_chirho = temp_root_chirho("app-route-unreviewed-dev-header");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "reviewedapp",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_for_owner_chirho(
        &root_chirho,
        "reviewedapp",
        "preview",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "reviewedapp",
        Some("preview"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let unreviewed_dag_chirho = store_transform_dag_chirho(
        &root_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "devapp",
        unreviewed_dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::deploy_app_route_unreviewed_dev_chirho(
        &root_chirho,
        "devapp",
        "preview",
        unreviewed_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "devapp",
        Some("preview"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let reviewed_response_chirho = app_route_post_chirho(
            State(state_chirho.clone()),
            None,
            HeaderMap::new(),
            AxPath(("reviewedapp".to_string(), "preview".to_string())),
            Bytes::from_static(b"reviewed"),
        )
        .await;
        assert_eq!(reviewed_response_chirho.status(), StatusCode::OK);
        assert!(reviewed_response_chirho
            .headers()
            .get(cairn_chirho::app_chirho::APP_UNREVIEWED_DEV_HEADER_CHIRHO)
            .is_none());

        let unreviewed_response_chirho = app_route_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath(("devapp".to_string(), "preview".to_string())),
            Bytes::from_static(b"dev"),
        )
        .await;
        assert_eq!(unreviewed_response_chirho.status(), StatusCode::OK);
        assert_eq!(
            unreviewed_response_chirho
                .headers()
                .get(cairn_chirho::app_chirho::APP_UNREVIEWED_DEV_HEADER_CHIRHO)
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some(cairn_chirho::app_chirho::APP_UNREVIEWED_DEV_HEADER_VALUE_CHIRHO)
        );
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_route_csp_tightens_when_static_css_assets_exist_chirho() {
    let root_chirho = temp_root_chirho("app-root-csp-tighten");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "cspapp",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "cspapp", &owner_chirho);
    cairn_chirho::app_chirho::set_app_response_policy_chirho(
        &root_chirho,
        "cspapp",
        &owner_chirho,
        "text/html",
    )
    .unwrap();

    // Register signed static assets to trigger manifest-derived CSP directives.
    cairn_chirho::app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "cspapp",
        &owner_chirho,
        "style-chirho.css",
        "text/css",
        b".body-chirho { color: green; }",
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "cspapp",
        &owner_chirho,
        "logo-chirho.png",
        "image/png",
        b"\x89PNG\r\n\x1a\ncsp-proof-chirho",
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "cspapp",
        &owner_chirho,
        "brand-chirho.woff2",
        "font/woff2",
        b"wOF2 csp font proof chirho",
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
            let response_chirho = app_post_chirho(
                State(state_chirho.clone()),
            None,
                HeaderMap::new(),
                AxPath("cspapp".to_string()),
                Bytes::from_static(b"<h1>ok</h1>"),
            )
            .await;
            assert_eq!(response_chirho.status(), StatusCode::OK);
            assert_eq!(
                response_chirho
                    .headers()
                    .get("content-security-policy")
                    .and_then(|value_chirho| value_chirho.to_str().ok()),
                Some("default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'; style-src 'self'; img-src 'self'; font-src 'self'")
            );
        });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_route_csp_keeps_inline_style_for_static_css_app_with_inline_style_chirho() {
    let root_chirho = temp_root_chirho("app-root-csp-inline-style");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "inlinecspapp",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(&root_chirho, "inlinecspapp", &owner_chirho);
    cairn_chirho::app_chirho::set_app_response_policy_chirho(
        &root_chirho,
        "inlinecspapp",
        &owner_chirho,
        "text/html",
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_static_asset_bytes_chirho(
        &root_chirho,
        "inlinecspapp",
        &owner_chirho,
        "style-chirho.css",
        "text/css",
        b".body-chirho { color: green; }",
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_post_chirho(
            State(state_chirho),
            None,
            HeaderMap::new(),
            AxPath("inlinecspapp".to_string()),
            Bytes::from_static(b"<style>.x{color:red}</style><h1>ok</h1>"),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        assert_eq!(
            response_chirho
                .headers()
                .get("content-security-policy")
                .and_then(|value_chirho| value_chirho.to_str().ok()),
            Some(APP_ROUTE_HTML_CSP_CHIRHO)
        );
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A refused browser form lands only on a route that is declared, takes no body and answers HTML (PFE
/// #29303, #29320), each read from the app's verified records. A route that accepts a body, has no body
/// policy, answers JSON or plain text, has no answer type, or is not declared is not a landing, and
/// neither is a route of an app that does not exist.
#[test]
fn a_refusal_landing_is_a_declared_bodyless_route_that_answers_html_chirho() {
    use cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::{
        AcceptBodyChirho, NoBodyChirho,
    };
    let root_chirho = temp_root_chirho("refusal-landing");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let wat_chirho = include_str!("../../../../../examples-chirho/upcase-chirho.wat");
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "landing-app-chirho",
        &owner_chirho,
        wat_chirho,
        "upcase_chirho",
    );
    let dag_chirho = store_transform_dag_chirho(&root_chirho, wat_chirho, "upcase_chirho");
    let routes_chirho = [
        ("page-chirho", Some(NoBodyChirho), Some("text/html"), true),
        (
            "form-chirho",
            Some(AcceptBodyChirho),
            Some("text/html"),
            false,
        ),
        ("unset-body-chirho", None, Some("text/html"), false),
        (
            "data-chirho",
            Some(NoBodyChirho),
            Some("application/json"),
            false,
        ),
        ("text-chirho", Some(NoBodyChirho), Some("text/plain"), false),
        ("bare-chirho", Some(NoBodyChirho), None, false),
    ];
    cairn_chirho::app_manifest_chirho::deploy_app_manifest_chirho(
        &root_chirho,
        &cairn_chirho::app_manifest_chirho::AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: cairn_chirho::app_manifest_chirho::APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO
                .to_string(),
            app_chirho: "landing-app-chirho".to_string(),
            owner_chirho: owner_chirho.clone(),
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: routes_chirho
                .iter()
                .map(
                    |(route_chirho, body_chirho, answer_chirho, _landing_chirho)| {
                        cairn_chirho::app_manifest_chirho::AppDeployRouteManifestChirho {
                        route_chirho: route_chirho.to_string(),
                        source_chirho:
                            cairn_chirho::app_manifest_chirho::AppDeployDagSourceChirho::DagChirho {
                                hash_chirho: dag_chirho.clone(),
                            },
                        input_mode_chirho: None,
                        request_body_policy_chirho: body_chirho.clone(),
                        response_content_type_chirho: answer_chirho.map(str::to_string),
                        params_chirho: None,
                        key_access_chirho: None,
                    }
                    },
                )
                .collect(),
            runtime_packages_chirho: Vec::new(),
        },
    )
    .unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    for (route_chirho, _body_chirho, _answer_chirho, landing_chirho) in &routes_chirho {
        assert_eq!(
            state_chirho
                .runtime_chirho
                .direct_app_route_is_refusal_landing_chirho("landing-app-chirho", route_chirho),
            *landing_chirho,
            "{route_chirho}"
        );
    }
    for (app_chirho, route_chirho) in [
        ("landing-app-chirho", "missing-chirho"),
        ("no-such-app-chirho", "page-chirho"),
    ] {
        assert!(
            !state_chirho
                .runtime_chirho
                .direct_app_route_is_refusal_landing_chirho(app_chirho, route_chirho),
            "{app_chirho}/{route_chirho}"
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}
