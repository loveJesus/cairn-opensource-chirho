// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn public_index_and_dashboard_are_non_listing_and_admin_gated_chirho() {
    let root_chirho = temp_root_chirho("admin-dashboard-http");
    let owner_a_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let owner_b_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_a_ref_chirho = deploy_empty_app_for_owner_chirho(
        &root_chirho,
        "dashboardpublica",
        &owner_a_chirho.principal_chirho,
    );
    let app_b_ref_chirho = deploy_empty_app_for_owner_chirho(
        &root_chirho,
        "dashboardpublicb",
        &owner_b_chirho.principal_chirho,
    );
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "dashboard-private-ref-chirho",
        app_a_ref_chirho.clone(),
    )
    .unwrap();
    refs_chirho::compare_and_set_branch_chirho(
        &root_chirho,
        "dashboard-private-ref-chirho",
        &app_a_ref_chirho,
        app_b_ref_chirho.clone(),
        "dashboard private reflog reason",
    )
    .unwrap();

    let global_needles_chirho = vec![
        "dashboardpublica".to_string(),
        "dashboardpublicb".to_string(),
        owner_a_chirho.principal_chirho.clone(),
        owner_b_chirho.principal_chirho.clone(),
        app_a_ref_chirho.0[..app_a_ref_chirho.0.len().min(16)].to_string(),
        app_b_ref_chirho.0[..app_b_ref_chirho.0.len().min(16)].to_string(),
        "dashboard-private-ref-chirho".to_string(),
        "dashboard private reflog reason".to_string(),
    ];

    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let disabled_port_chirho = unused_local_port_chirho();
        let disabled_addr_chirho = format!("127.0.0.1:{disabled_port_chirho}");
        let disabled_root_chirho = root_chirho.clone();
        let disabled_server_chirho = tokio::spawn(async move {
            serve_chirho(
                &disabled_root_chirho,
                disabled_port_chirho,
                8,
                String::new(),
            )
            .await
        });
        wait_for_serve_health_chirho(&disabled_addr_chirho);
        let disabled_dashboard_chirho =
            http_get_for_smoke_chirho(&disabled_addr_chirho, "/dashboard-chirho");
        assert_eq!(disabled_dashboard_chirho.status_chirho, 503);
        let disabled_text_chirho = http_body_text_chirho(&disabled_dashboard_chirho);
        assert!(disabled_text_chirho.contains("admin dashboard disabled"));
        assert_text_excludes_needles_chirho(&disabled_text_chirho, &global_needles_chirho);
        disabled_server_chirho.abort();
        let _ = disabled_server_chirho.await;

        let admin_token_chirho = "m181-dashboard-admin-token-chirho";
        let admin_header_chirho = format!("Bearer {admin_token_chirho}");
        let port_chirho = unused_local_port_chirho();
        let addr_chirho = format!("127.0.0.1:{port_chirho}");
        let root_for_server_chirho = root_chirho.clone();
        let server_chirho = tokio::spawn(async move {
            serve_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                admin_token_chirho.to_string(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let index_chirho = http_get_for_smoke_chirho(&addr_chirho, "/");
        assert_eq!(index_chirho.status_chirho, 200);
        let index_text_chirho = http_body_text_chirho(&index_chirho);
        assert!(index_text_chirho.contains("admin-token gated"));
        assert_text_excludes_needles_chirho(&index_text_chirho, &global_needles_chirho);

        let missing_auth_chirho = http_get_for_smoke_chirho(&addr_chirho, "/dashboard-chirho");
        assert_eq!(missing_auth_chirho.status_chirho, 401);
        assert_text_excludes_needles_chirho(
            &http_body_text_chirho(&missing_auth_chirho),
            &global_needles_chirho,
        );

        let malformed_auth_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            "/dashboard-chirho",
            &[("authorization", "Basic not-a-bearer-token")],
            &[],
        );
        assert_eq!(malformed_auth_chirho.status_chirho, 401);
        assert_text_excludes_needles_chirho(
            &http_body_text_chirho(&malformed_auth_chirho),
            &global_needles_chirho,
        );

        let wrong_auth_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            "/dashboard-chirho",
            &[("authorization", "Bearer wrong-dashboard-token-chirho")],
            &[],
        );
        assert_eq!(wrong_auth_chirho.status_chirho, 403);
        assert_text_excludes_needles_chirho(
            &http_body_text_chirho(&wrong_auth_chirho),
            &global_needles_chirho,
        );

        let admin_dashboard_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            "/dashboard-chirho",
            &[("authorization", &admin_header_chirho)],
            &[],
        );
        assert_eq!(admin_dashboard_chirho.status_chirho, 200);
        let admin_text_chirho = http_body_text_chirho(&admin_dashboard_chirho);
        assert!(admin_text_chirho.contains("dashboardpublica"));
        assert!(admin_text_chirho.contains("dashboardpublicb"));
        assert!(admin_text_chirho.contains(&owner_a_chirho.principal_chirho));
        assert!(admin_text_chirho.contains(&owner_b_chirho.principal_chirho));
        assert!(admin_text_chirho.contains("dashboard-private-ref-chirho"));
        assert!(admin_text_chirho.contains("dashboard private reflog reason"));
        assert!(admin_text_chirho.contains("2 verified principal record"));

        let mut app_records_chirho = app_chirho::load_app_records_chirho(&root_chirho).unwrap();
        app_records_chirho[0].sig_chirho = "00".repeat(64);
        write_jsonl_chirho(
            &root_chirho.join("app-records-chirho.jsonl"),
            &app_records_chirho,
        );
        let tampered_dashboard_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            "/dashboard-chirho",
            &[("authorization", &admin_header_chirho)],
            &[],
        );
        assert_eq!(tampered_dashboard_chirho.status_chirho, 400);
        let tampered_text_chirho = http_body_text_chirho(&tampered_dashboard_chirho);
        assert!(tampered_text_chirho.contains("dashboard verification failed"));
        assert_text_excludes_needles_chirho(&tampered_text_chirho, &global_needles_chirho);

        server_chirho.abort();
        let _ = server_chirho.await;
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn publish_auth_accepts_admin_or_matching_owner_session_chirho() {
    let root_chirho = temp_root_chirho("publish-auth");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let login_chirho =
        identity_chirho::login_identity_chirho(&root_chirho, &owner_chirho.principal_chirho)
            .unwrap();
    let package_chirho = cairn_chirho::publish_chirho::PublishPackageChirho {
        name_chirho: "ownedapp".to_string(),
        owner_chirho: owner_chirho.principal_chirho.clone(),
        dag_chirho: "deadbeef".to_string(),
        input_mode_chirho: None,
        response_content_type_chirho: None,
        routes_chirho: Vec::new(),
        runtime_packages_chirho: Vec::new(),
        undo_plan_bindings_chirho: None,
        objects_chirho: vec![],
    };

    let missing_chirho = publish_dashboard_web_chirho::require_publish_auth_chirho(
        &root_chirho,
        &HeaderMap::new(),
        &package_chirho,
        "",
    )
    .unwrap();
    assert_eq!(missing_chirho.status(), StatusCode::UNAUTHORIZED);

    let mut admin_headers_chirho = HeaderMap::new();
    admin_headers_chirho.insert(AUTHORIZATION, "Bearer admin-token".parse().unwrap());
    assert!(publish_dashboard_web_chirho::require_publish_auth_chirho(
        &root_chirho,
        &admin_headers_chirho,
        &package_chirho,
        "admin-token",
    )
    .is_none());

    let mut owner_headers_chirho = HeaderMap::new();
    owner_headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", login_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    assert!(publish_dashboard_web_chirho::require_publish_auth_chirho(
        &root_chirho,
        &owner_headers_chirho,
        &package_chirho,
        "different-admin-token",
    )
    .is_none());

    let mut other_package_chirho = package_chirho;
    other_package_chirho.owner_chirho = "owner/not-this-token".to_string();
    let wrong_owner_chirho = publish_dashboard_web_chirho::require_publish_auth_chirho(
        &root_chirho,
        &owner_headers_chirho,
        &other_package_chirho,
        "",
    )
    .unwrap();
    assert_eq!(wrong_owner_chirho.status(), StatusCode::FORBIDDEN);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn publish_route_http_is_admin_or_owner_gated_chirho() {
    let root_chirho = temp_root_chirho("publish-http");
    let src_chirho = temp_root_chirho("publish-http-src");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let login_chirho =
        identity_chirho::login_identity_chirho(&root_chirho, &owner_chirho.principal_chirho)
            .unwrap();
    let existing_owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let existing_hijack_dag_chirho = deploy_empty_app_for_owner_chirho(
        &root_chirho,
        "publishhijackhttp",
        &existing_owner_chirho.principal_chirho,
    );
    let owner_dag_chirho = store_empty_dag_chirho(&src_chirho);
    let owner_package_chirho = cairn_chirho::publish_chirho::build_package_chirho(
        &src_chirho,
        "publishownerhttp",
        &owner_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let owner_body_chirho = serde_json::to_vec(&owner_package_chirho).unwrap();

    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let empty_token_port_chirho = unused_local_port_chirho();
        let empty_token_addr_chirho = format!("127.0.0.1:{empty_token_port_chirho}");
        let empty_token_root_chirho = root_chirho.clone();
        let empty_token_server_chirho = tokio::spawn(async move {
            serve_chirho(
                &empty_token_root_chirho,
                empty_token_port_chirho,
                8,
                String::new(),
            )
            .await
        });
        wait_for_serve_health_chirho(&empty_token_addr_chirho);

        let missing_chirho = http_request_for_smoke_chirho(
            &empty_token_addr_chirho,
            "POST",
            "/publish-chirho",
            &[("content-type", "application/json")],
            &owner_body_chirho,
        );
        assert_eq!(missing_chirho.status_chirho, 401);
        assert_eq!(
            app_chirho::verified_app_owner_chirho(&root_chirho, "publishownerhttp").unwrap(),
            None
        );

        let arbitrary_admin_chirho = http_request_for_smoke_chirho(
            &empty_token_addr_chirho,
            "POST",
            "/publish-chirho",
            &[
                ("authorization", "Bearer arbitrary-admin-token-chirho"),
                ("content-type", "application/json"),
            ],
            &owner_body_chirho,
        );
        assert_eq!(arbitrary_admin_chirho.status_chirho, 403);
        assert_eq!(
            app_chirho::verified_app_owner_chirho(&root_chirho, "publishownerhttp").unwrap(),
            None
        );

        let owner_publish_chirho = http_request_for_smoke_chirho(
            &empty_token_addr_chirho,
            "POST",
            "/publish-chirho",
            &[
                (
                    "authorization",
                    &format!("Bearer {}", login_chirho.token_chirho),
                ),
                ("content-type", "application/json"),
            ],
            &owner_body_chirho,
        );
        assert_eq!(owner_publish_chirho.status_chirho, 200);
        assert_eq!(
            app_chirho::verified_app_owner_chirho(&root_chirho, "publishownerhttp").unwrap(),
            Some(owner_chirho.principal_chirho.clone())
        );

        let hijack_dag_chirho = store_empty_dag_chirho(&src_chirho);
        let hijack_package_chirho = cairn_chirho::publish_chirho::build_package_chirho(
            &src_chirho,
            "publishhijackhttp",
            &hijack_dag_chirho,
            &owner_chirho.principal_chirho,
        )
        .unwrap();
        let hijack_chirho = http_request_for_smoke_chirho(
            &empty_token_addr_chirho,
            "POST",
            "/publish-chirho",
            &[
                (
                    "authorization",
                    &format!("Bearer {}", login_chirho.token_chirho),
                ),
                ("content-type", "application/json"),
            ],
            &serde_json::to_vec(&hijack_package_chirho).unwrap(),
        );
        assert_eq!(hijack_chirho.status_chirho, 400);
        assert_eq!(
            app_chirho::verified_app_owner_chirho(&root_chirho, "publishhijackhttp").unwrap(),
            Some(existing_owner_chirho.principal_chirho.clone())
        );
        assert_eq!(
            refs_chirho::load_refs_chirho(&root_chirho)
                .unwrap()
                .branches_chirho
                .get("app/publishhijackhttp"),
            Some(&existing_hijack_dag_chirho)
        );
        empty_token_server_chirho.abort();
        let _ = empty_token_server_chirho.await;

        let admin_token_chirho = "m189-publish-admin-token-chirho";
        let admin_port_chirho = unused_local_port_chirho();
        let admin_addr_chirho = format!("127.0.0.1:{admin_port_chirho}");
        let admin_root_chirho = root_chirho.clone();
        let admin_server_chirho = tokio::spawn(async move {
            serve_chirho(
                &admin_root_chirho,
                admin_port_chirho,
                8,
                admin_token_chirho.to_string(),
            )
            .await
        });
        wait_for_serve_health_chirho(&admin_addr_chirho);

        let admin_dag_chirho = store_empty_dag_chirho(&src_chirho);
        let admin_package_chirho = cairn_chirho::publish_chirho::build_package_chirho(
            &src_chirho,
            "publishadminhttp",
            &admin_dag_chirho,
            &owner_chirho.principal_chirho,
        )
        .unwrap();
        let admin_body_chirho = serde_json::to_vec(&admin_package_chirho).unwrap();
        let admin_publish_chirho = http_request_for_smoke_chirho(
            &admin_addr_chirho,
            "POST",
            "/publish-chirho",
            &[
                ("authorization", &format!("Bearer {admin_token_chirho}")),
                ("content-type", "application/json"),
            ],
            &admin_body_chirho,
        );
        assert_eq!(admin_publish_chirho.status_chirho, 200);
        assert_eq!(
            app_chirho::verified_app_owner_chirho(&root_chirho, "publishadminhttp").unwrap(),
            Some(owner_chirho.principal_chirho.clone())
        );

        let wrong_owner_package_chirho = cairn_chirho::publish_chirho::build_package_chirho(
            &src_chirho,
            "publishwrongownerhttp",
            &admin_dag_chirho,
            "owner/not-this-token",
        )
        .unwrap();
        let wrong_owner_chirho = http_request_for_smoke_chirho(
            &admin_addr_chirho,
            "POST",
            "/publish-chirho",
            &[
                (
                    "authorization",
                    &format!("Bearer {}", login_chirho.token_chirho),
                ),
                ("content-type", "application/json"),
            ],
            &serde_json::to_vec(&wrong_owner_package_chirho).unwrap(),
        );
        assert_eq!(wrong_owner_chirho.status_chirho, 403);
        assert_eq!(
            app_chirho::verified_app_owner_chirho(&root_chirho, "publishwrongownerhttp").unwrap(),
            None
        );

        let tamper_dag_chirho = store_empty_dag_chirho(&src_chirho);
        let mut tampered_package_chirho = cairn_chirho::publish_chirho::build_package_chirho(
            &src_chirho,
            "publishtamperedhttp",
            &tamper_dag_chirho,
            &owner_chirho.principal_chirho,
        )
        .unwrap();
        tampered_package_chirho.objects_chirho[0]
            .bytes_hex_chirho
            .push_str("00");
        let tampered_chirho = http_request_for_smoke_chirho(
            &admin_addr_chirho,
            "POST",
            "/publish-chirho",
            &[
                ("authorization", &format!("Bearer {admin_token_chirho}")),
                ("content-type", "application/json"),
            ],
            &serde_json::to_vec(&tampered_package_chirho).unwrap(),
        );
        assert_eq!(tampered_chirho.status_chirho, 400);
        assert_eq!(
            app_chirho::verified_app_owner_chirho(&root_chirho, "publishtamperedhttp").unwrap(),
            None
        );

        admin_server_chirho.abort();
        let _ = admin_server_chirho.await;
    });

    let _ = std::fs::remove_dir_all(&src_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}
