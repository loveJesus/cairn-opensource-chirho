// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::super::*;

#[test]
fn owner_app_review_promote_installs_reviewed_routes_and_rolls_back_chirho() {
    let root_chirho = temp_root_chirho("owner-app-review-promote");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-review-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) =
        split_owner_principal_for_path_chirho(&owner_chirho.principal_chirho);
    let headers_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-review-secret",
    );
    let app_name_chirho = "review-http-app-chirho";
    let route_chirho = "preview-chirho";
    let subject_chirho = "app/review-http-app-chirho/input";
    let (source_review_report_chirho, candidate_chirho, report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            route_chirho,
            &owner_chirho.principal_chirho,
            subject_chirho,
        );
    let reviewed_asset_hash_chirho = report_chirho.candidate_chirho.assets_chirho[0]
        .asset_chirho
        .clone();
    assert!(review_chirho::load_review_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_review_promote_post_chirho(
            State(state_chirho.clone()),
            headers_chirho.clone(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                app_name_chirho.to_string(),
            )),
            Form(AppReviewPromoteRequestChirho {
                candidate_chirho: candidate_chirho.0.clone(),
                source_review_report_chirho: source_review_report_chirho.0.clone(),
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
            }),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::OK);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains("data-app-review-promote-chirho=\"ok\""));
        assert!(body_text_chirho.contains(&candidate_chirho.0));
        assert!(!body_text_chirho.contains("owner-review-secret"));

        let status_chirho = app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
        assert!(status_chirho.active_chirho);
        assert_eq!(status_chirho.dag_chirho, Some(candidate_chirho.clone()));
        assert_eq!(
            status_chirho.routes_chirho.get(route_chirho),
            Some(&candidate_chirho)
        );
        assert_eq!(
            app_chirho::app_static_asset_bytes_chirho(
                &root_chirho,
                &app_chirho::app_static_asset_by_name_chirho(
                    &root_chirho,
                    app_name_chirho,
                    "reviewed-source-chirho.css",
                )
                .unwrap()
                .expect("review promotion must install reviewed by-name asset"),
            )
            .unwrap(),
            b".reviewed-source-chirho{color:#123456}\n"
        );
        let reviewed_names_chirho = report_chirho
            .candidate_chirho
            .assets_chirho
            .iter()
            .map(|asset_chirho| asset_chirho.name_chirho.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let served_names_chirho = app_chirho::load_app_static_asset_records_chirho(&root_chirho)
            .unwrap()
            .into_iter()
            .filter(|record_chirho| {
                record_chirho.app_chirho == app_name_chirho && !record_chirho.removed_chirho
            })
            .map(|record_chirho| record_chirho.name_chirho)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(served_names_chirho, reviewed_names_chirho);
        assert_eq!(
            app_chirho::app_input_mode_chirho(
                &root_chirho,
                app_name_chirho,
                None,
                &owner_chirho.principal_chirho,
            )
            .unwrap(),
            app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: subject_chirho.to_string(),
                safe_metadata_chirho: Vec::new(),
            }
        );
        assert_eq!(
            app_chirho::app_input_mode_chirho(
                &root_chirho,
                app_name_chirho,
                Some(route_chirho),
                &owner_chirho.principal_chirho,
            )
            .unwrap(),
            app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: subject_chirho.to_string(),
                safe_metadata_chirho: Vec::new(),
            }
        );
        let app_records_after_first_chirho = app_chirho::load_app_records_chirho(&root_chirho)
            .unwrap()
            .len();
        let route_records_after_first_chirho =
            app_chirho::load_app_route_records_chirho(&root_chirho)
                .unwrap()
                .len();
        let asset_records_after_first_chirho =
            app_chirho::load_app_static_asset_records_chirho(&root_chirho)
                .unwrap()
                .len();

        let second_response_chirho = app_review_promote_post_chirho(
            State(state_chirho.clone()),
            headers_chirho.clone(),
            AxPath((
                kind_chirho.clone(),
                id_chirho.clone(),
                app_name_chirho.to_string(),
            )),
            Form(AppReviewPromoteRequestChirho {
                candidate_chirho: candidate_chirho.0.clone(),
                source_review_report_chirho: source_review_report_chirho.0.clone(),
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
            }),
        )
        .await;
        let second_status_chirho = second_response_chirho.status();
        let second_body_chirho =
            axum::body::to_bytes(second_response_chirho.into_body(), usize::MAX)
                .await
                .unwrap();
        let second_body_text_chirho = String::from_utf8(second_body_chirho.to_vec()).unwrap();
        assert_eq!(
            second_status_chirho,
            StatusCode::OK,
            "{second_body_text_chirho}"
        );
        assert!(second_body_text_chirho.contains("data-app-review-promote-chirho=\"ok\""));
        assert_eq!(
            app_chirho::load_app_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            app_records_after_first_chirho
        );
        assert_eq!(
            app_chirho::load_app_route_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            route_records_after_first_chirho
        );
        assert_eq!(
            app_chirho::load_app_static_asset_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            asset_records_after_first_chirho
        );
        assert_eq!(
            review_chirho::verify_review_records_chirho(&root_chirho).unwrap(),
            1
        );

        let rollback_chirho = app_review_rollback_post_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, app_name_chirho.to_string())),
            Form(AppReviewRollbackRequestChirho {
                source_review_report_chirho: source_review_report_chirho.0.clone(),
            }),
        )
        .await;
        assert_eq!(rollback_chirho.status(), StatusCode::OK);
        let rollback_body_chirho = axum::body::to_bytes(rollback_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let rollback_text_chirho = String::from_utf8(rollback_body_chirho.to_vec()).unwrap();
        assert!(rollback_text_chirho.contains("data-app-review-rollback-chirho=\"ok\""));
    });

    let status_chirho = app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.dag_chirho, None);
    assert!(!status_chirho.routes_chirho.contains_key(route_chirho));
    assert!(app_chirho::app_static_asset_by_name_chirho(
        &root_chirho,
        app_name_chirho,
        "reviewed-source-chirho.css",
    )
    .unwrap()
    .is_none());
    assert!(app_chirho::app_static_asset_by_hash_chirho(
        &root_chirho,
        app_name_chirho,
        &reviewed_asset_hash_chirho,
    )
    .unwrap()
    .is_none());
    assert_eq!(
        review_chirho::verify_review_records_chirho(&root_chirho).unwrap(),
        1
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn owner_app_review_promote_rejects_missing_bearer_and_cross_owner_chirho() {
    let root_chirho = temp_root_chirho("owner-app-review-deny");
    let owner_a_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-a-review-secret",
    )
    .unwrap();
    let owner_b_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-b-review-secret",
    )
    .unwrap();
    let (kind_b_chirho, id_b_chirho) =
        split_owner_principal_for_path_chirho(&owner_b_chirho.principal_chirho);
    let headers_b_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_b_chirho.principal_chirho,
        "owner-b-review-secret",
    );
    let app_name_chirho = "review-denied-app-chirho";
    let route_chirho = "preview-chirho";
    let (source_review_report_chirho, candidate_chirho, _report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            route_chirho,
            &owner_a_chirho.principal_chirho,
            "app/review-denied-app-chirho/input",
        );
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let missing_bearer_chirho = app_review_promote_post_chirho(
            State(state_chirho.clone()),
            HeaderMap::new(),
            AxPath((
                kind_b_chirho.clone(),
                id_b_chirho.clone(),
                app_name_chirho.to_string(),
            )),
            Form(AppReviewPromoteRequestChirho {
                candidate_chirho: candidate_chirho.0.clone(),
                source_review_report_chirho: source_review_report_chirho.0.clone(),
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
            }),
        )
        .await;
        assert_eq!(missing_bearer_chirho.status(), StatusCode::UNAUTHORIZED);

        let cross_owner_chirho = app_review_promote_post_chirho(
            State(state_chirho),
            headers_b_chirho,
            AxPath((kind_b_chirho, id_b_chirho, app_name_chirho.to_string())),
            Form(AppReviewPromoteRequestChirho {
                candidate_chirho: candidate_chirho.0.clone(),
                source_review_report_chirho: source_review_report_chirho.0.clone(),
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
            }),
        )
        .await;
        assert_eq!(cross_owner_chirho.status(), StatusCode::BAD_REQUEST);
        let body_chirho = axum::body::to_bytes(cross_owner_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains("owner does not match authenticated owner"));
        assert!(!body_text_chirho.contains("owner-a-review-secret"));
        assert!(!body_text_chirho.contains("owner-b-review-secret"));
    });

    let status_chirho = app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.dag_chirho, None);
    assert!(status_chirho.routes_chirho.is_empty());
    assert!(review_chirho::load_review_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn owner_app_review_promote_rejects_bad_review_route_before_ref_move_chirho() {
    let root_chirho = temp_root_chirho("owner-app-review-bad-route");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-bad-route-secret",
    )
    .unwrap();
    let (kind_chirho, id_chirho) =
        split_owner_principal_for_path_chirho(&owner_chirho.principal_chirho);
    let headers_chirho = owner_bearer_headers_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        "owner-bad-route-secret",
    );
    let app_name_chirho = "review-bad-route-app-chirho";
    let (source_review_report_chirho, candidate_chirho, mut report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            "preview-chirho",
            &owner_chirho.principal_chirho,
            "app/review-bad-route-app-chirho/input",
        );
    let _source_review_report_chirho = source_review_report_chirho;
    report_chirho.candidate_chirho.routes_chirho[0].route_chirho = "bad route name".to_string();
    report_chirho.source_review_report_chirho = None;
    let bad_report_hash_chirho = app_source_manifest_chirho::put_app_source_review_report_chirho(
        &root_chirho,
        &report_chirho,
    )
    .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let response_chirho = app_review_promote_post_chirho(
            State(state_chirho),
            headers_chirho,
            AxPath((kind_chirho, id_chirho, app_name_chirho.to_string())),
            Form(AppReviewPromoteRequestChirho {
                candidate_chirho: candidate_chirho.0.clone(),
                source_review_report_chirho: bad_report_hash_chirho.0.clone(),
                accept_capability_escalation_chirho: false,
                accept_cost_increase_chirho: false,
            }),
        )
        .await;
        assert_eq!(response_chirho.status(), StatusCode::BAD_REQUEST);
        let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_text_chirho = String::from_utf8(body_chirho.to_vec()).unwrap();
        assert!(body_text_chirho.contains("route"));
        assert!(!body_text_chirho.contains("owner-bad-route-secret"));
    });

    let status_chirho = app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.dag_chirho, None);
    assert!(status_chirho.routes_chirho.is_empty());
    assert!(review_chirho::load_review_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn owner_app_review_promote_rejects_bad_review_asset_before_ref_move_chirho() {
    let root_chirho = temp_root_chirho("owner-app-review-bad-asset");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-bad-asset-secret",
    )
    .unwrap();
    let app_name_chirho = "review-bad-asset-app-chirho";
    let (_source_review_report_chirho, candidate_chirho, mut report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            "preview-chirho",
            &owner_chirho.principal_chirho,
            "app/review-bad-asset-app-chirho/input",
        );
    report_chirho.candidate_chirho.assets_chirho[0].byte_len_chirho += 1;
    report_chirho.source_review_report_chirho = None;
    let bad_report_hash_chirho = app_source_manifest_chirho::put_app_source_review_report_chirho(
        &root_chirho,
        &report_chirho,
    )
    .unwrap();

    let error_chirho =
        app_source_manifest_chirho::load_app_source_review_report_for_promotion_chirho(
            &root_chirho,
            app_name_chirho,
            &owner_chirho.principal_chirho,
            &bad_report_hash_chirho,
            Some(&candidate_chirho),
        )
        .unwrap_err();
    assert!(error_chirho.to_string().contains("asset"));

    let status_chirho = app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.dag_chirho, None);
    assert!(status_chirho.routes_chirho.is_empty());
    assert!(
        app_chirho::load_app_static_asset_records_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );
    assert!(review_chirho::load_review_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reviewed_source_asset_install_failure_tears_down_partial_surface_chirho() {
    let root_chirho = temp_root_chirho("owner-app-review-asset-install-fail");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-install-fail-secret",
    )
    .unwrap();
    let app_name_chirho = "review-install-fail-app-chirho";
    let route_chirho = "preview-chirho";
    let (_source_review_report_chirho, _candidate_chirho, mut report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            route_chirho,
            &owner_chirho.principal_chirho,
            "app/review-install-fail-app-chirho/input",
        );
    let second_asset_chirho = cas_chirho::add_chirho(
        &root_chirho,
        b".reviewed-source-extra-chirho{display:block}\n",
    )
    .unwrap();
    report_chirho.candidate_chirho.assets_chirho.push(
        app_source_manifest_chirho::AppSourceAssetReportChirho {
            name_chirho: "reviewed-source-extra-chirho.css".to_string(),
            asset_chirho: second_asset_chirho,
            content_type_chirho: app_chirho::APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO.to_string(),
            byte_len_chirho: 45,
        },
    );

    app_source_manifest_chirho::set_reviewed_asset_install_fail_after_for_test_chirho(Some(1));
    let error_chirho = app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        &report_chirho,
    )
    .unwrap_err();
    app_source_manifest_chirho::set_reviewed_asset_install_fail_after_for_test_chirho(None);
    assert!(error_chirho.to_string().contains("injected reviewed asset"));

    let status_chirho = app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.dag_chirho, None);
    assert!(!status_chirho.routes_chirho.contains_key(route_chirho));
    for asset_chirho in &report_chirho.candidate_chirho.assets_chirho {
        assert!(app_chirho::app_static_asset_by_name_chirho(
            &root_chirho,
            app_name_chirho,
            &asset_chirho.name_chirho,
        )
        .unwrap()
        .is_none());
        assert!(app_chirho::app_static_asset_by_hash_chirho(
            &root_chirho,
            app_name_chirho,
            &asset_chirho.asset_chirho,
        )
        .unwrap()
        .is_none());
    }

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reviewed_source_install_is_idempotent_when_surface_is_current_chirho() {
    let root_chirho = temp_root_chirho("owner-app-review-idempotent-install");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-idempotent-install-secret",
    )
    .unwrap();
    let app_name_chirho = "review-idempotent-install-app-chirho";
    let (_source_review_report_chirho, _candidate_chirho, report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            "preview-chirho",
            &owner_chirho.principal_chirho,
            "app/review-idempotent-install-app-chirho/input",
        );

    let first_report_chirho =
        app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            &report_chirho,
        )
        .unwrap();
    assert!(!first_report_chirho.already_current_chirho);
    assert_eq!(first_report_chirho.route_count_chirho, 1);
    assert_eq!(first_report_chirho.asset_count_chirho, 1);
    let app_records_chirho = app_chirho::load_app_records_chirho(&root_chirho)
        .unwrap()
        .len();
    let route_records_chirho = app_chirho::load_app_route_records_chirho(&root_chirho)
        .unwrap()
        .len();
    let asset_records_chirho = app_chirho::load_app_static_asset_records_chirho(&root_chirho)
        .unwrap()
        .len();

    let second_report_chirho =
        app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            &report_chirho,
        )
        .unwrap();
    assert!(second_report_chirho.already_current_chirho);
    assert_eq!(
        second_report_chirho.routes_chirho,
        first_report_chirho.routes_chirho
    );
    assert_eq!(
        second_report_chirho.assets_chirho,
        first_report_chirho.assets_chirho
    );
    assert_eq!(
        app_chirho::load_app_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        app_records_chirho
    );
    assert_eq!(
        app_chirho::load_app_route_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        route_records_chirho
    );
    assert_eq!(
        app_chirho::load_app_static_asset_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        asset_records_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reviewed_source_install_prunes_unreviewed_route_and_asset_ridealong_chirho() {
    let root_chirho = temp_root_chirho("owner-app-review-no-ridealong");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-no-ridealong-secret",
    )
    .unwrap();
    let app_name_chirho = "review-no-ridealong-app-chirho";
    let reviewed_route_chirho = "preview-chirho";
    let (_source_review_report_chirho, candidate_chirho, report_chirho) =
        build_private_review_report_for_owner_chirho(
            &root_chirho,
            app_name_chirho,
            reviewed_route_chirho,
            &owner_chirho.principal_chirho,
            "app/review-no-ridealong-app-chirho/input",
        );
    app_chirho::deploy_app_chirho(
        &root_chirho,
        app_name_chirho,
        candidate_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    app_chirho::deploy_app_route_chirho(
        &root_chirho,
        app_name_chirho,
        reviewed_route_chirho,
        candidate_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        app_name_chirho,
        None,
        &owner_chirho.principal_chirho,
        report_chirho
            .candidate_chirho
            .input_mode_chirho
            .clone()
            .unwrap(),
    )
    .unwrap();
    app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        app_name_chirho,
        Some(reviewed_route_chirho),
        &owner_chirho.principal_chirho,
        report_chirho.candidate_chirho.routes_chirho[0]
            .input_mode_chirho
            .clone()
            .unwrap(),
    )
    .unwrap();
    let reviewed_asset_chirho = &report_chirho.candidate_chirho.assets_chirho[0];
    app_chirho::set_app_static_asset_hash_chirho(
        &root_chirho,
        app_name_chirho,
        &owner_chirho.principal_chirho,
        &reviewed_asset_chirho.name_chirho,
        reviewed_asset_chirho.asset_chirho.clone(),
        &reviewed_asset_chirho.content_type_chirho,
        reviewed_asset_chirho.byte_len_chirho,
    )
    .unwrap();
    let extra_route_chirho = "unreviewed-preview-chirho";
    app_chirho::deploy_app_route_chirho(
        &root_chirho,
        app_name_chirho,
        extra_route_chirho,
        candidate_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let extra_asset_bytes_chirho = b".unreviewed-ridealong-chirho{}\n";
    let extra_asset_hash_chirho =
        cas_chirho::add_chirho(&root_chirho, extra_asset_bytes_chirho).unwrap();
    app_chirho::set_app_static_asset_hash_chirho(
        &root_chirho,
        app_name_chirho,
        &owner_chirho.principal_chirho,
        "unreviewed-ridealong-chirho.css",
        extra_asset_hash_chirho.clone(),
        app_chirho::APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO,
        extra_asset_bytes_chirho.len() as u64,
    )
    .unwrap();
    let app_records_before_chirho = app_chirho::load_app_records_chirho(&root_chirho)
        .unwrap()
        .len();
    let route_records_before_chirho = app_chirho::load_app_route_records_chirho(&root_chirho)
        .unwrap()
        .len();
    let asset_records_before_chirho =
        app_chirho::load_app_static_asset_records_chirho(&root_chirho)
            .unwrap()
            .len();

    let install_report_chirho =
        app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
            &root_chirho,
            &owner_chirho.principal_chirho,
            &report_chirho,
        )
        .unwrap();
    assert!(!install_report_chirho.already_current_chirho);
    assert_eq!(install_report_chirho.route_count_chirho, 1);
    assert_eq!(install_report_chirho.asset_count_chirho, 1);
    let status_chirho = app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
    assert_eq!(
        status_chirho
            .routes_chirho
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([reviewed_route_chirho.to_string()])
    );
    assert!(app_chirho::app_static_asset_by_name_chirho(
        &root_chirho,
        app_name_chirho,
        "unreviewed-ridealong-chirho.css",
    )
    .unwrap()
    .is_none());
    assert!(app_chirho::app_static_asset_by_hash_chirho(
        &root_chirho,
        app_name_chirho,
        &extra_asset_hash_chirho,
    )
    .unwrap()
    .is_none());
    assert_eq!(
        app_chirho::load_app_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        app_records_before_chirho
    );
    assert_eq!(
        app_chirho::load_app_route_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        route_records_before_chirho + 1
    );
    assert_eq!(
        app_chirho::load_app_static_asset_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        asset_records_before_chirho + 1
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
