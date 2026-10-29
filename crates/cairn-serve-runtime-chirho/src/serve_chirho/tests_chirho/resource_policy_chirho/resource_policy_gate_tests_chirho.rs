// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn resource_gate_routes_to_owner_matched_fallback_chirho() {
    let root_chirho = temp_root_chirho("resource-route");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let premium_dag_chirho = deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "premiumgate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    let lite_dag_chirho = deploy_transform_app_route_for_owner_chirho(
        &root_chirho,
        "premiumgate",
        "litegate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/reverse-chirho.wat"),
        "reverse_chirho",
    );
    let (_user_chirho, headers_chirho) = scoped_headers_for_app_chirho(
        &root_chirho,
        "premiumgate",
        &owner_chirho.principal_chirho,
        "resource-route-secret",
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

    let context_chirho =
        request_context_for_app_chirho(&root_chirho, &headers_chirho, "premiumgate")
            .unwrap()
            .unwrap();
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let selection_chirho = select_app_dag_with_resource_gate_chirho(
        &root_chirho,
        &refs_chirho,
        "premiumgate",
        Some(&context_chirho),
    )
    .unwrap();
    assert_eq!(
        refs_chirho.branches_chirho["app/premiumgate"],
        premium_dag_chirho
    );
    assert_eq!(selection_chirho.dag_chirho, lite_dag_chirho);
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let admission_chirho = served_admission_for_state_chirho(&state_chirho, 3);
    let payload_chirho = try_run_with_context_chirho(
        &state_chirho,
        &admission_chirho,
        &selection_chirho.dag_chirho.0,
        b"abc",
        Some(&context_chirho),
        None,
    )
    .unwrap();
    assert_eq!(String::from_utf8(payload_chirho).unwrap(), "cba");
    let usage_chirho = resource_chirho::load_resource_usage_chirho(&root_chirho).unwrap();
    assert_eq!(usage_chirho.len(), 1);
    assert!(matches!(
        usage_chirho[0].decision_chirho,
        resource_chirho::ResourceDecisionChirho::RoutedChirho { .. }
    ));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resource_gate_fail_closed_refuses_before_app_run_chirho() {
    let root_chirho = temp_root_chirho("resource-fail-closed");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "closedgate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    let (_user_chirho, headers_chirho) = scoped_headers_for_app_chirho(
        &root_chirho,
        "closedgate",
        &owner_chirho.principal_chirho,
        "resource-closed-secret",
    );
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "closedgate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "labs_credit_chirho".to_string(),
            unit_chirho: "credit".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(1),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::FailClosedChirho,
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
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let response_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_chirho,
        "closedgate",
        None,
        b"abc".to_vec(),
    );
    assert_eq!(response_chirho.status(), StatusCode::BAD_REQUEST);
    assert!(resource_chirho::load_resource_usage_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(!root_chirho.join("runs-chirho").exists());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resource_gate_unreceipted_policy_absence_never_serves_unmetered_chirho() {
    let root_chirho = temp_root_chirho("resource-unreceipted-absence");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "absentgate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    let (_user_chirho, headers_chirho) = scoped_headers_for_app_chirho(
        &root_chirho,
        "absentgate",
        &owner_chirho.principal_chirho,
        "resource-absent-secret",
    );
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "absentgate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "labs_credit_chirho".to_string(),
            unit_chirho: "credit".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(5),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "labs_credit_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    assert!(cairn_chirho::refs_chirho::remove_branch_chirho(
        &root_chirho,
        "resource-policy/absentgate"
    )
    .unwrap());

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let response_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_chirho,
        "absentgate",
        None,
        b"abc".to_vec(),
    );
    assert_eq!(
        response_chirho.status(),
        StatusCode::BAD_REQUEST,
        "an unreceipted policy absence must error, never serve unmetered"
    );
    assert!(resource_chirho::load_resource_usage_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(!root_chirho.join("runs-chirho").exists());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resource_gate_requires_scoped_token_unless_anonymous_opted_in_chirho() {
    let root_chirho = temp_root_chirho("resource-anon-default-closed");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "anonclosedgate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "anonclosedgate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "public_write_chirho".to_string(),
            unit_chirho: "write".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: None,
            app_limit_chirho: Some(1),
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "public_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let headers_chirho = HeaderMap::new();
    let response_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_chirho,
        "anonclosedgate",
        None,
        b"anonymous should not run".to_vec(),
    );
    assert_eq!(response_chirho.status(), StatusCode::BAD_REQUEST);
    assert!(resource_chirho::load_resource_usage_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(!root_chirho.join("runs-chirho").exists());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn direct_route_resource_gate_requires_session_before_body_persistence_chirho() {
    let root_chirho = temp_root_chirho("direct-resource-anon-closed");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "directclosedgate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_for_owner_chirho(
        &root_chirho,
        "directclosedgate",
        "build-chirho",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/reverse-chirho.wat"),
        "reverse_chirho",
    );
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "directclosedgate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "build_request_chirho".to_string(),
            unit_chirho: "request".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(1),
            app_limit_chirho: None,
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "build_request_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let needle_chirho = b"anonymous direct route body must not persist";
    let response_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &HeaderMap::new(),
        "directclosedgate",
        Some("build-chirho"),
        needle_chirho.to_vec(),
    );
    assert_eq!(response_chirho.status(), StatusCode::BAD_REQUEST);
    assert!(resource_chirho::load_resource_usage_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(!root_chirho.join("runs-chirho").exists());
    assert_runtime_tree_excludes_bytes_chirho(&root_chirho, needle_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn anonymous_resource_gate_fail_closed_denies_before_private_body_persistence_chirho() {
    fn count_files_chirho(path_chirho: &std::path::Path) -> usize {
        if !path_chirho.exists() {
            return 0;
        }
        if path_chirho.is_file() {
            return 1;
        }
        std::fs::read_dir(path_chirho)
            .unwrap()
            .map(|entry_chirho| count_files_chirho(&entry_chirho.unwrap().path()))
            .sum()
    }

    let root_chirho = temp_root_chirho("resource-anon-private-fail");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "anonwritegate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "anonwritegate",
        None,
        &owner_chirho.principal_chirho,
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/anonwritegate/intake".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "anonwritegate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "public_write_chirho".to_string(),
            unit_chirho: "write".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: None,
            app_limit_chirho: Some(1),
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "public_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let headers_chirho = HeaderMap::new();
    let first_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_chirho,
        "anonwritegate",
        None,
        b"first anonymous private body".to_vec(),
    );
    assert_eq!(first_chirho.status(), StatusCode::OK);
    let usage_before_chirho = resource_chirho::load_resource_usage_chirho(&root_chirho).unwrap();
    assert_eq!(usage_before_chirho.len(), 1);
    assert_eq!(usage_before_chirho[0].user_chirho, "anon/app/anonwritegate");
    let blobs_before_chirho =
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(blobs_before_chirho.len(), 1);
    let run_files_before_chirho = count_files_chirho(&root_chirho.join("runs-chirho"));

    let second_needle_chirho = b"second anonymous private body must not persist";
    let second_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_chirho,
        "anonwritegate",
        None,
        second_needle_chirho.to_vec(),
    );
    assert_eq!(second_chirho.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resource_chirho::load_resource_usage_chirho(&root_chirho)
            .unwrap()
            .len(),
        usage_before_chirho.len()
    );
    assert_eq!(
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        blobs_before_chirho.len()
    );
    assert_eq!(
        count_files_chirho(&root_chirho.join("runs-chirho")),
        run_files_before_chirho
    );
    assert_runtime_tree_excludes_bytes_chirho(&root_chirho, second_needle_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn scoped_resource_gate_per_user_limit_denies_before_private_body_persistence_chirho() {
    fn count_files_chirho(path_chirho: &std::path::Path) -> usize {
        if !path_chirho.exists() {
            return 0;
        }
        if path_chirho.is_file() {
            return 1;
        }
        std::fs::read_dir(path_chirho)
            .unwrap()
            .map(|entry_chirho| count_files_chirho(&entry_chirho.unwrap().path()))
            .sum()
    }

    let root_chirho = temp_root_chirho("resource-scoped-private-fail");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-secret-value",
    )
    .unwrap();
    let user_a_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "user-a-secret-value",
    )
    .unwrap();
    let user_b_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "user-b-secret-value",
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "scopedwritegate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "scopedwritegate",
        None,
        &owner_chirho.principal_chirho,
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/scopedwritegate/intake".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "scopedwritegate",
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
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: false,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "private_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let client_chirho = oauth_chirho::register_client_chirho(
        &root_chirho,
        "scopedwritegate",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_a_chirho = oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &user_a_chirho.principal_chirho,
        "user-a-secret-value",
        &client_chirho.client_id_chirho,
        vec!["invoke".to_string()],
    )
    .unwrap();
    let token_b_chirho = oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &user_b_chirho.principal_chirho,
        "user-b-secret-value",
        &client_chirho.client_id_chirho,
        vec!["invoke".to_string()],
    )
    .unwrap();
    let mut headers_a_chirho = HeaderMap::new();
    headers_a_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_a_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    let mut headers_b_chirho = HeaderMap::new();
    headers_b_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_b_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    let state_chirho = app_state_for_root_chirho(&root_chirho);

    let first_a_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_a_chirho,
        "scopedwritegate",
        None,
        b"first scoped user private body".to_vec(),
    );
    assert_eq!(first_a_chirho.status(), StatusCode::OK);
    let usage_before_chirho = resource_chirho::load_resource_usage_chirho(&root_chirho).unwrap();
    assert_eq!(usage_before_chirho.len(), 1);
    assert_eq!(
        usage_before_chirho[0].user_chirho,
        user_a_chirho.principal_chirho
    );
    let blobs_before_chirho =
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(blobs_before_chirho.len(), 1);
    let run_files_before_chirho = count_files_chirho(&root_chirho.join("runs-chirho"));

    let second_a_needle_chirho = b"second scoped user private body must not persist";
    let second_a_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_a_chirho,
        "scopedwritegate",
        None,
        second_a_needle_chirho.to_vec(),
    );
    assert_eq!(second_a_chirho.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        resource_chirho::load_resource_usage_chirho(&root_chirho)
            .unwrap()
            .len(),
        usage_before_chirho.len()
    );
    assert_eq!(
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        blobs_before_chirho.len()
    );
    assert_eq!(
        count_files_chirho(&root_chirho.join("runs-chirho")),
        run_files_before_chirho
    );
    assert_runtime_tree_excludes_bytes_chirho(&root_chirho, second_a_needle_chirho);

    let first_b_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_b_chirho,
        "scopedwritegate",
        None,
        b"first different scoped user private body".to_vec(),
    );
    assert_eq!(first_b_chirho.status(), StatusCode::OK);
    let usage_after_b_chirho = resource_chirho::load_resource_usage_chirho(&root_chirho).unwrap();
    assert_eq!(usage_after_b_chirho.len(), 2);
    assert_eq!(
        usage_after_b_chirho[1].user_chirho,
        user_b_chirho.principal_chirho
    );
    assert_eq!(
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        2
    );

    let status_chirho =
        resource_chirho::resource_status_chirho(&root_chirho, Some("scopedwritegate"), None)
            .unwrap();
    assert!(status_chirho.iter().any(|row_chirho| {
        row_chirho.scope_chirho == resource_chirho::ResourceBalanceScopeChirho::UserChirho
            && row_chirho.subject_chirho == user_a_chirho.principal_chirho
            && row_chirho.resource_chirho == "private_write_chirho"
            && row_chirho.used_chirho == 1
            && row_chirho.remaining_chirho == 0
    }));
    assert!(status_chirho.iter().any(|row_chirho| {
        row_chirho.scope_chirho == resource_chirho::ResourceBalanceScopeChirho::UserChirho
            && row_chirho.subject_chirho == user_b_chirho.principal_chirho
            && row_chirho.resource_chirho == "private_write_chirho"
            && row_chirho.used_chirho == 1
            && row_chirho.remaining_chirho == 0
    }));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn anonymous_resource_gate_routed_overage_discards_private_body_chirho() {
    let root_chirho = temp_root_chirho("resource-anon-private-route");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "anonroutegate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_for_owner_chirho(
        &root_chirho,
        "anonroutegate",
        "overage",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/reverse-chirho.wat"),
        "reverse_chirho",
    );
    app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "anonroutegate",
        None,
        &owner_chirho.principal_chirho,
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/anonroutegate/intake".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "anonroutegate",
        Some("overage"),
        &owner_chirho.principal_chirho,
        app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "anonroutegate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "public_write_chirho".to_string(),
            unit_chirho: "write".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: None,
            app_limit_chirho: Some(1),
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::RouteChirho {
                route_chirho: "overage".to_string(),
                forward_request_body_chirho: false,
            },
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "public_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let headers_chirho = HeaderMap::new();
    let first_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_chirho,
        "anonroutegate",
        None,
        b"first anonymous private body".to_vec(),
    );
    assert_eq!(first_chirho.status(), StatusCode::OK);
    let blobs_before_chirho =
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(blobs_before_chirho.len(), 1);

    let second_needle_chirho = b"second routed overage private body must not persist";
    let second_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &headers_chirho,
        "anonroutegate",
        None,
        second_needle_chirho.to_vec(),
    );
    assert_eq!(second_chirho.status(), StatusCode::OK);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let body_chirho = runtime_chirho
        .block_on(async { axum::body::to_bytes(second_chirho.into_body(), usize::MAX).await })
        .unwrap();
    assert!(
        body_chirho.is_empty(),
        "fallback route must receive empty input instead of echoing/reversing the rejected body"
    );
    let usage_chirho = resource_chirho::load_resource_usage_chirho(&root_chirho).unwrap();
    assert_eq!(usage_chirho.len(), 2);
    assert!(matches!(
        usage_chirho[1].decision_chirho,
        resource_chirho::ResourceDecisionChirho::RoutedChirho { .. }
    ));
    assert_eq!(
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        blobs_before_chirho.len()
    );
    assert_runtime_tree_excludes_bytes_chirho(&root_chirho, second_needle_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn orphan_resource_policy_does_not_record_usage_for_undeployed_app_chirho() {
    fn count_files_chirho(path_chirho: &std::path::Path) -> usize {
        if !path_chirho.exists() {
            return 0;
        }
        if path_chirho.is_file() {
            return 1;
        }
        std::fs::read_dir(path_chirho)
            .unwrap()
            .map(|entry_chirho| count_files_chirho(&entry_chirho.unwrap().path()))
            .sum()
    }

    let root_chirho = temp_root_chirho("resource-orphan-policy");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "orphanwritegate",
        &owner_chirho.principal_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "orphanwritegate",
        None,
        &owner_chirho.principal_chirho,
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/orphanwritegate/intake".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    resource_chirho::set_resource_policy_chirho(
        &root_chirho,
        "orphanwritegate",
        &owner_chirho.principal_chirho,
        vec![resource_chirho::ResourceMeterChirho {
            resource_chirho: "public_write_chirho".to_string(),
            unit_chirho: "write".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: None,
            app_limit_chirho: Some(10),
            window_ms_chirho: None,
            overage_chirho: resource_chirho::ResourceOverageChirho::FailClosedChirho,
        }],
        vec![resource_chirho::ResourceActionPolicyChirho {
            section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                resource_chirho: "public_write_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();
    assert!(app_chirho::undeploy_app_chirho(
        &root_chirho,
        "orphanwritegate",
        &owner_chirho.principal_chirho
    )
    .unwrap());
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let needle_chirho = b"orphan resource policy body must not persist";
    let response_chirho = run_app_http_chirho(
        &state_chirho,
        None,
        &HeaderMap::new(),
        "orphanwritegate",
        None,
        needle_chirho.to_vec(),
    );
    assert_eq!(response_chirho.status(), StatusCode::NOT_FOUND);
    assert!(resource_chirho::load_resource_usage_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(
        privacy_chirho::load_privacy_blob_records_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );
    assert_eq!(count_files_chirho(&root_chirho.join("runs-chirho")), 0);
    assert_runtime_tree_excludes_bytes_chirho(&root_chirho, needle_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn scoped_token_rate_limit_refuses_before_app_run_chirho() {
    let root_chirho = temp_root_chirho("request-rate-limit");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-secret-value",
    )
    .unwrap();
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "user-secret-value",
    )
    .unwrap();
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "limitedapp",
        dag_hash_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let client_chirho = oauth_chirho::register_client_chirho(
        &root_chirho,
        "limitedapp",
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let token_chirho = oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
        &root_chirho,
        &user_chirho.principal_chirho,
        "user-secret-value",
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
        Some(oauth_chirho::ScopedTokenRateLimitChirho {
            window_ms_chirho: 60_000,
            max_invokes_chirho: 1,
            device_id_chirho: Some("device-rate-test".to_string()),
        }),
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    assert!(
        request_context_for_app_chirho(&root_chirho, &headers_chirho, "limitedapp")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        oauth_chirho::load_scoped_token_uses_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    let ledger_before_chirho =
        cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
            .unwrap()
            .len();
    let err_chirho =
        request_context_for_app_chirho(&root_chirho, &headers_chirho, "limitedapp").unwrap_err();
    assert_eq!(
        request_context_error_status_chirho(&err_chirho),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        oauth_chirho::load_scoped_token_uses_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        cairn_chirho::legacy_ledger_evidence_chirho::load_entries_chirho(&root_chirho)
            .unwrap()
            .len(),
        ledger_before_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn runtime_owner_gate_requires_verified_app_record_chirho() {
    let root_chirho = temp_root_chirho("runtime-owner-gate-verified");
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
    deploy_empty_app_for_owner_chirho(&root_chirho, "tamper-app", &owner_a_chirho.principal_chirho);
    ensure_owner_controls_app_chirho(&root_chirho, &owner_a_chirho.principal_chirho, "tamper-app")
        .unwrap();

    let mut records_chirho = app_chirho::load_app_records_chirho(&root_chirho).unwrap();
    records_chirho[0].owner_principal_chirho = owner_b_chirho.principal_chirho.clone();
    let mut jsonl_chirho = String::new();
    for record_chirho in &records_chirho {
        jsonl_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        jsonl_chirho.push('\n');
    }
    std::fs::write(root_chirho.join("app-records-chirho.jsonl"), jsonl_chirho).unwrap();
    assert_eq!(
        app_chirho::app_owner_chirho(&root_chirho, "tamper-app").unwrap(),
        Some(owner_b_chirho.principal_chirho.clone())
    );

    let error_chirho = ensure_owner_controls_app_chirho(
        &root_chirho,
        &owner_b_chirho.principal_chirho,
        "tamper-app",
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("app record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The bearer road's statuses for its use-recording refusals (brick 4a-2): a rate limit is 429, the use window
/// catching up after a clock step back is a transient 503 a client retries, and an above-ceiling key is a 403 with
/// its reason to reissue.
#[test]
fn bearer_use_refusals_render_their_statuses_chirho() {
    let rate_limit_chirho = anyhow::Error::from(oauth_chirho::RateLimitExceededChirho {
        principal_chirho: "user/0".to_string(),
        app_chirho: "limitedapp".to_string(),
        device_id_chirho: None,
        window_ms_chirho: 60_000,
        max_invokes_chirho: 1,
    });
    assert_eq!(
        request_context_error_status_chirho(&rate_limit_chirho),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        request_context_error_status_chirho(&anyhow::Error::from(
            oauth_chirho::UseWindowCatchingUpChirho
        )),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request_context_error_status_chirho(&anyhow::Error::from(
            oauth_chirho::ScopedTokenPolicyAboveCeilingChirho
        )),
        StatusCode::FORBIDDEN
    );
}
