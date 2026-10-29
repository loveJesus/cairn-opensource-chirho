// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn app_build_request_owner_write_is_private_idempotent_and_effectless_chirho() {
    let root_chirho = temp_root_chirho("app-build-request-http");
    let owner_a_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-a-build-secret",
    )
    .unwrap();
    let owner_b_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-b-build-secret",
    )
    .unwrap();
    deploy_empty_app_for_owner_chirho(
        &root_chirho,
        "buildintakea",
        &owner_a_chirho.principal_chirho,
    );
    deploy_empty_app_for_owner_chirho(
        &root_chirho,
        "buildintakeb",
        &owner_b_chirho.principal_chirho,
    );
    let app_status_before_chirho =
        app_chirho::app_status_chirho(&root_chirho, "buildintakea").unwrap();
    let headers_a_map_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_a_chirho.principal_chirho,
        "owner-a-build-secret",
    );
    let headers_b_map_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_b_chirho.principal_chirho,
        "owner-b-build-secret",
    );
    let authorization_a_chirho = headers_a_map_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let authorization_b_chirho = headers_b_map_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let form_headers_a_chirho = [
        ("authorization", authorization_a_chirho.as_str()),
        ("content-type", "application/x-www-form-urlencoded"),
    ];
    let headers_a_chirho = [("authorization", authorization_a_chirho.as_str())];
    let headers_b_chirho = [("authorization", authorization_b_chirho.as_str())];

    let sentinel_email_chirho = "sentinel-m95@example.test";
    let sentinel_token_chirho = "m95-token-secret-value-chirho";
    let sentinel_path_chirho = "/private/sentinel-m95-request-path-chirho".to_string();
    let sentinel_draft_var_chirho = "draft_var_m95_private_value_chirho";
    let owner_goal_chirho = format!(
        "Build a customer intake app for {sentinel_email_chirho}; token={sentinel_token_chirho}; path={sentinel_path_chirho}; owner={}; {sentinel_draft_var_chirho}=true",
        owner_a_chirho.principal_chirho
    );
    let notes_chirho = "Private notes stay encrypted; no source review, deploy, provider, or promote effect may run.";
    let create_body_chirho = app_build_request_form_body_chirho(
        "nonce-1-chirho",
        &owner_goal_chirho,
        notes_chirho,
        &["private-intake-chirho", "reviewed-preview-chirho"],
    );
    let conflict_body_chirho = app_build_request_form_body_chirho(
        "nonce-1-chirho",
        "changed private body must conflict and not persist",
        notes_chirho,
        &["private-intake-chirho"],
    );
    let invalid_module_sentinel_chirho = "invalid module private body must not persist";
    let invalid_module_body_chirho = app_build_request_form_body_chirho(
        "nonce-invalid-chirho",
        invalid_module_sentinel_chirho,
        notes_chirho,
        &["unknown-module-chirho"],
    );
    let cross_owner_sentinel_chirho = "cross-owner app build private body must not persist";
    let cross_owner_body_chirho = app_build_request_form_body_chirho(
        "nonce-cross-chirho",
        cross_owner_sentinel_chirho,
        notes_chirho,
        &["private-intake-chirho"],
    );
    let preview_sentinel_chirho = "preview private body must not persist";
    let preview_body_chirho = app_build_request_form_body_chirho(
        "nonce-preview-chirho",
        preview_sentinel_chirho,
        notes_chirho,
        &["owner-admin-chirho"],
    );
    let missing_auth_sentinel_chirho = "missing-auth app build private body must not persist";
    let missing_auth_body_chirho = app_build_request_form_body_chirho(
        "nonce-missing-auth-chirho",
        missing_auth_sentinel_chirho,
        notes_chirho,
        &["private-intake-chirho"],
    );

    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let (kind_a_chirho, id_a_chirho) =
            owner_path_parts_chirho(&owner_a_chirho.principal_chirho);
        let (kind_b_chirho, id_b_chirho) =
            owner_path_parts_chirho(&owner_b_chirho.principal_chirho);
        let base_a_chirho =
            format!("/app-build-request-chirho/{kind_a_chirho}/{id_a_chirho}/buildintakea");
        let base_b_chirho =
            format!("/app-build-request-chirho/{kind_b_chirho}/{id_b_chirho}/buildintakeb");
        let base_a_to_b_app_chirho =
            format!("/app-build-request-chirho/{kind_a_chirho}/{id_a_chirho}/buildintakeb");

        let missing_auth_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_a_chirho}/create-chirho"),
            &[("content-type", "application/x-www-form-urlencoded")],
            missing_auth_body_chirho.as_bytes(),
        );
        assert_eq!(missing_auth_chirho.status_chirho, 401);

        let preview_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_a_chirho}/preview-chirho"),
            &form_headers_a_chirho,
            preview_body_chirho.as_bytes(),
        );
        assert_eq!(preview_chirho.status_chirho, 200);
        let preview_text_chirho = http_body_text_chirho(&preview_chirho);
        assert!(preview_text_chirho.contains("no_store=true"));
        assert!(!preview_text_chirho.contains(preview_sentinel_chirho));
        assert_eq!(
            app_build_request_chirho::load_app_build_request_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            0
        );

        let invalid_module_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_a_chirho}/create-chirho"),
            &form_headers_a_chirho,
            invalid_module_body_chirho.as_bytes(),
        );
        assert_eq!(invalid_module_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&invalid_module_chirho).contains("unknown module"));

        let cross_owner_app_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_a_to_b_app_chirho}/create-chirho"),
            &form_headers_a_chirho,
            cross_owner_body_chirho.as_bytes(),
        );
        assert_eq!(cross_owner_app_chirho.status_chirho, 404);

        let owner_b_as_a_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_b_chirho}/create-chirho"),
            &form_headers_a_chirho,
            cross_owner_body_chirho.as_bytes(),
        );
        assert_eq!(owner_b_as_a_chirho.status_chirho, 403);

        let create_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_a_chirho}/create-chirho"),
            &form_headers_a_chirho,
            create_body_chirho.as_bytes(),
        );
        assert_eq!(create_chirho.status_chirho, 200);
        let create_text_chirho = http_body_text_chirho(&create_chirho);
        assert!(create_text_chirho.contains("data-app-build-request-chirho=\"created\""));
        for needle_chirho in [
            sentinel_email_chirho,
            sentinel_token_chirho,
            &sentinel_path_chirho,
            &owner_a_chirho.principal_chirho,
            sentinel_draft_var_chirho,
            "signing-key-chirho",
        ] {
            assert!(
                !create_text_chirho.contains(needle_chirho),
                "safe app build create response leaked {needle_chirho}"
            );
        }

        let replay_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_a_chirho}/create-chirho"),
            &form_headers_a_chirho,
            create_body_chirho.as_bytes(),
        );
        assert_eq!(replay_chirho.status_chirho, 200);
        assert!(http_body_text_chirho(&replay_chirho).contains("seq #0"));

        let conflict_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_a_chirho}/create-chirho"),
            &form_headers_a_chirho,
            conflict_body_chirho.as_bytes(),
        );
        assert_eq!(conflict_chirho.status_chirho, 409);
        assert!(!http_body_text_chirho(&conflict_chirho).contains("changed private body"));

        let list_a_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &base_a_chirho,
            &headers_a_chirho,
            &[],
        );
        assert_eq!(list_a_chirho.status_chirho, 200);
        let list_a_text_chirho = http_body_text_chirho(&list_a_chirho);
        assert!(list_a_text_chirho.contains("safe request rows 1"));
        assert!(list_a_text_chirho.contains("buildintakea"));
        for needle_chirho in [
            sentinel_email_chirho,
            sentinel_token_chirho,
            &sentinel_path_chirho,
            &owner_a_chirho.principal_chirho,
            sentinel_draft_var_chirho,
            "signing-key-chirho",
        ] {
            assert!(
                !list_a_text_chirho.contains(needle_chirho),
                "safe app build list leaked {needle_chirho}"
            );
        }

        let owner_b_list_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &base_b_chirho,
            &headers_b_chirho,
            &[],
        );
        assert_eq!(owner_b_list_chirho.status_chirho, 200);
        let owner_b_text_chirho = http_body_text_chirho(&owner_b_list_chirho);
        assert!(owner_b_text_chirho.contains("safe request rows 0"));
        assert!(!owner_b_text_chirho.contains("buildintakea"));

        server_chirho.abort();
    });

    let records_chirho =
        app_build_request_chirho::load_app_build_request_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 1);
    assert_eq!(records_chirho[0].app_chirho, "buildintakea");
    app_build_request_chirho::verify_app_build_request_records_chirho(
        &root_chirho,
        &records_chirho,
    )
    .unwrap();
    let private_blobs_chirho =
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(private_blobs_chirho.len(), 1);
    let private_payload_chirho = privacy_chirho::load_private_blob_chirho(
        &root_chirho,
        &records_chirho[0].request_private_ref_chirho,
    )
    .unwrap();
    let private_payload_text_chirho = String::from_utf8(private_payload_chirho).unwrap();
    assert!(private_payload_text_chirho.contains(sentinel_email_chirho));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "buildintakea").unwrap(),
        app_status_before_chirho
    );
    assert_optional_dir_empty_chirho(&root_chirho.join("effects-chirho"), "effects-chirho");
    assert_optional_file_empty_chirho(
        &root_chirho.join("volatile-effects-chirho.jsonl"),
        "volatile-effects-chirho.jsonl",
    );
    for needle_chirho in [
        sentinel_email_chirho.as_bytes(),
        sentinel_token_chirho.as_bytes(),
        sentinel_path_chirho.as_bytes(),
        sentinel_draft_var_chirho.as_bytes(),
        preview_sentinel_chirho.as_bytes(),
        invalid_module_sentinel_chirho.as_bytes(),
        cross_owner_sentinel_chirho.as_bytes(),
        missing_auth_sentinel_chirho.as_bytes(),
        b"changed private body must conflict and not persist".as_slice(),
    ] {
        assert_runtime_tree_excludes_bytes_chirho(&root_chirho, needle_chirho);
    }

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_build_request_resource_admission_blocks_before_private_storage_chirho() {
    let root_chirho = temp_root_chirho("app-build-request-resource");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-build-resource-secret",
    )
    .unwrap();
    deploy_empty_app_for_owner_chirho(&root_chirho, "buildlimited", &owner_chirho.principal_chirho);
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "buildlimited",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "private_write_chirho".to_string(),
            unit_chirho: "write".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(1),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: app_build_request_chirho::APP_BUILD_REQUEST_RESOURCE_SECTION_CHIRHO
                .to_string(),
            action_chirho: app_build_request_chirho::APP_BUILD_REQUEST_RESOURCE_ACTION_CHIRHO
                .to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "private_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let headers_map_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-build-resource-secret",
    );
    let authorization_chirho = headers_map_chirho
        .get(AUTHORIZATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let form_headers_chirho = [
        ("authorization", authorization_chirho.as_str()),
        ("content-type", "application/x-www-form-urlencoded"),
    ];
    let (kind_chirho, id_chirho) = owner_path_parts_chirho(&owner_chirho.principal_chirho);
    let base_chirho = format!("/app-build-request-chirho/{kind_chirho}/{id_chirho}/buildlimited");
    let first_body_chirho = app_build_request_form_body_chirho(
        "nonce-1-chirho",
        "first private build request",
        "",
        &["private-intake-chirho"],
    );
    let blocked_sentinel_chirho = "blocked overcap build request must not persist";
    let second_body_chirho = app_build_request_form_body_chirho(
        "nonce-2-chirho",
        blocked_sentinel_chirho,
        "",
        &["private-intake-chirho"],
    );

    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let first_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_chirho}/create-chirho"),
            &form_headers_chirho,
            first_body_chirho.as_bytes(),
        );
        assert_eq!(first_chirho.status_chirho, 200);

        let second_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{base_chirho}/create-chirho"),
            &form_headers_chirho,
            second_body_chirho.as_bytes(),
        );
        assert_eq!(second_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&second_chirho).contains("resource"));
        assert!(!http_body_text_chirho(&second_chirho).contains(blocked_sentinel_chirho));

        server_chirho.abort();
    });

    assert_eq!(
        app_build_request_chirho::load_app_build_request_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        resource_chirho::load_resource_usage_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_runtime_tree_excludes_bytes_chirho(&root_chirho, blocked_sentinel_chirho.as_bytes());
    assert_optional_dir_empty_chirho(&root_chirho.join("effects-chirho"), "effects-chirho");

    let _ = std::fs::remove_dir_all(&root_chirho);
}
