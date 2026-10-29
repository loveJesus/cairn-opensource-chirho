// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn owner_resource_policy_http_preview_apply_is_hash_bound_and_fail_closed_chirho() {
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

    fn resource_policy_input_json_chirho(
        resource_chirho: &str,
        limit_chirho: i64,
        window_ms_chirho: Option<u64>,
        allow_anonymous_chirho: bool,
        overage_chirho: resource_chirho::ResourceOverageChirho,
    ) -> String {
        serde_json::to_string(&resource_chirho::ResourcePolicyInputChirho {
            meters_chirho: vec![resource_chirho::ResourceMeterChirho {
                resource_chirho: resource_chirho.to_string(),
                unit_chirho: "request".to_string(),
                stack_chirho: Some("owner-authored".to_string()),
                per_user_limit_chirho: Some(limit_chirho),
                app_limit_chirho: Some(limit_chirho * 10),
                window_ms_chirho,
                overage_chirho,
            }],
            actions_chirho: vec![resource_chirho::ResourceActionPolicyChirho {
                section_chirho: REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
                action_chirho: REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
                effect_chirho: None,
                allow_anonymous_chirho,
                charges_chirho: vec![resource_chirho::ResourceChargeChirho {
                    resource_chirho: resource_chirho.to_string(),
                    amount_chirho: 1,
                }],
            }],
        })
        .unwrap()
    }

    fn resource_policy_form_chirho(fields_chirho: &[(&str, String)]) -> Vec<u8> {
        fields_chirho
            .iter()
            .map(|(key_chirho, value_chirho)| {
                format!(
                    "{}={}",
                    encode_query_value_chirho(key_chirho),
                    encode_query_value_chirho(value_chirho)
                )
            })
            .collect::<Vec<_>>()
            .join("&")
            .into_bytes()
    }

    fn hidden_input_value_chirho(html_chirho: &str, name_chirho: &str) -> String {
        let needle_chirho = format!("name=\"{name_chirho}\" value=\"");
        let start_chirho = html_chirho.find(&needle_chirho).unwrap() + needle_chirho.len();
        let rest_chirho = &html_chirho[start_chirho..];
        rest_chirho[..rest_chirho.find('"').unwrap()].to_string()
    }

    let root_chirho = temp_root_chirho("owner-resource-policy-http");
    let owner_a_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-resource-policy-a-secret",
    )
    .unwrap();
    let owner_b_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-resource-policy-b-secret",
    )
    .unwrap();
    let owner_a_login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_a_chirho.principal_chirho,
        "owner-resource-policy-a-secret",
    )
    .unwrap();
    let owner_b_login_chirho = identity_chirho::login_identity_with_credential_chirho(
        &root_chirho,
        &owner_b_chirho.principal_chirho,
        "owner-resource-policy-b-secret",
    )
    .unwrap();
    deploy_empty_app_for_owner_chirho(
        &root_chirho,
        "ownerbudgetapp",
        &owner_a_chirho.principal_chirho,
    );
    deploy_empty_app_for_owner_chirho(
        &root_chirho,
        "otherbudgetapp",
        &owner_b_chirho.principal_chirho,
    );
    let (kind_a_chirho, id_a_chirho) = owner_path_parts_chirho(&owner_a_chirho.principal_chirho);
    let (kind_b_chirho, id_b_chirho) = owner_path_parts_chirho(&owner_b_chirho.principal_chirho);
    let path_a_chirho =
        format!("/resource-policy-chirho/{kind_a_chirho}/{id_a_chirho}/ownerbudgetapp");
    let path_b_for_a_app_chirho =
        format!("/resource-policy-chirho/{kind_b_chirho}/{id_b_chirho}/ownerbudgetapp");
    let auth_a_chirho = format!("Bearer {}", owner_a_login_chirho.token_chirho);
    let auth_b_chirho = format!("Bearer {}", owner_b_login_chirho.token_chirho);
    let headers_a_chirho = [
        ("authorization", auth_a_chirho.as_str()),
        ("content-type", "application/x-www-form-urlencoded"),
    ];
    let headers_b_chirho = [
        ("authorization", auth_b_chirho.as_str()),
        ("content-type", "application/x-www-form-urlencoded"),
    ];
    let policy_one_json_chirho = resource_policy_input_json_chirho(
        "owner_write_chirho",
        3,
        Some(60_000),
        false,
        resource_chirho::ResourceOverageChirho::FailClosedChirho,
    );
    let preview_one_body_chirho = resource_policy_form_chirho(&[
        ("expected_previous_chirho", String::new()),
        ("policy_json_chirho", policy_one_json_chirho.clone()),
    ]);

    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let missing_auth_apply_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/apply-chirho"),
            &[("content-type", "application/x-www-form-urlencoded")],
            b"not-a-valid-form-before-auth",
        );
        assert_eq!(missing_auth_apply_chirho.status_chirho, 401);
        assert!(
            resource_chirho::load_resource_policy_records_chirho(&root_chirho)
                .unwrap()
                .is_empty()
        );

        let wrong_token_show_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &path_a_chirho,
            &[("authorization", auth_b_chirho.as_str())],
            &[],
        );
        assert_eq!(wrong_token_show_chirho.status_chirho, 403);

        let cross_owner_apply_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_b_for_a_app_chirho}/apply-chirho"),
            &headers_b_chirho,
            &preview_one_body_chirho,
        );
        assert_eq!(cross_owner_apply_chirho.status_chirho, 404);
        assert!(
            resource_chirho::load_resource_policy_records_chirho(&root_chirho)
                .unwrap()
                .is_empty()
        );
        assert!(resource_chirho::current_resource_policy_hash_chirho(
            &root_chirho,
            "ownerbudgetapp"
        )
        .unwrap()
        .is_none());

        let show_empty_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &path_a_chirho,
            &headers_a_chirho,
            &[],
        );
        assert_eq!(show_empty_chirho.status_chirho, 200);
        let show_empty_text_chirho = http_body_text_chirho(&show_empty_chirho);
        assert!(show_empty_text_chirho.contains("No current resource policy"));

        let objects_before_preview_chirho = count_files_chirho(&root_chirho.join("objects-chirho"));
        let preview_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/preview-chirho"),
            &headers_a_chirho,
            &preview_one_body_chirho,
        );
        assert_eq!(preview_chirho.status_chirho, 200);
        let preview_text_chirho = http_body_text_chirho(&preview_chirho);
        assert!(preview_text_chirho.contains("data-resource-policy-author-chirho=\"preview\""));
        assert!(preview_text_chirho.contains("This preview has not stored a policy object"));
        assert_eq!(
            count_files_chirho(&root_chirho.join("objects-chirho")),
            objects_before_preview_chirho
        );
        assert!(
            resource_chirho::load_resource_policy_records_chirho(&root_chirho)
                .unwrap()
                .is_empty()
        );
        assert!(resource_chirho::current_resource_policy_hash_chirho(
            &root_chirho,
            "ownerbudgetapp"
        )
        .unwrap()
        .is_none());

        let reviewed_hash_chirho =
            hidden_input_value_chirho(&preview_text_chirho, "reviewed_policy_hash_chirho");
        let policy_at_ms_chirho =
            hidden_input_value_chirho(&preview_text_chirho, "policy_at_ms_chirho");
        let apply_one_body_chirho = resource_policy_form_chirho(&[
            ("expected_previous_chirho", String::new()),
            ("reviewed_policy_hash_chirho", reviewed_hash_chirho.clone()),
            ("policy_at_ms_chirho", policy_at_ms_chirho.clone()),
            ("policy_json_chirho", policy_one_json_chirho.clone()),
        ]);
        let apply_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/apply-chirho"),
            &headers_a_chirho,
            &apply_one_body_chirho,
        );
        assert_eq!(apply_chirho.status_chirho, 200);
        let apply_text_chirho = http_body_text_chirho(&apply_chirho);
        assert!(apply_text_chirho.contains("data-resource-policy-author-chirho=\"applied\""));
        let current_hash_chirho =
            resource_chirho::current_resource_policy_hash_chirho(&root_chirho, "ownerbudgetapp")
                .unwrap()
                .unwrap();
        assert_eq!(current_hash_chirho.0, reviewed_hash_chirho);
        assert_eq!(
            resource_chirho::load_resource_policy_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            resource_chirho::verify_resource_policies_chirho(&root_chirho).unwrap(),
            1
        );

        let policy_two_json_chirho = resource_policy_input_json_chirho(
            "owner_write_chirho",
            5,
            Some(60_000),
            false,
            resource_chirho::ResourceOverageChirho::RouteChirho {
                route_chirho: "soft-overage".to_string(),
                forward_request_body_chirho: false,
            },
        );
        let preview_two_body_chirho = resource_policy_form_chirho(&[
            ("expected_previous_chirho", current_hash_chirho.0.clone()),
            ("policy_json_chirho", policy_two_json_chirho.clone()),
        ]);
        let preview_two_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/preview-chirho"),
            &headers_a_chirho,
            &preview_two_body_chirho,
        );
        assert_eq!(preview_two_chirho.status_chirho, 200);
        let preview_two_text_chirho = http_body_text_chirho(&preview_two_chirho);
        let reviewed_two_hash_chirho =
            hidden_input_value_chirho(&preview_two_text_chirho, "reviewed_policy_hash_chirho");
        let policy_two_at_ms_chirho =
            hidden_input_value_chirho(&preview_two_text_chirho, "policy_at_ms_chirho");
        let stale_apply_body_chirho = resource_policy_form_chirho(&[
            ("expected_previous_chirho", current_hash_chirho.0.clone()),
            (
                "reviewed_policy_hash_chirho",
                reviewed_two_hash_chirho.clone(),
            ),
            ("policy_at_ms_chirho", policy_two_at_ms_chirho),
            ("policy_json_chirho", policy_two_json_chirho.clone()),
        ]);
        let missing_expected_apply_body_chirho = resource_policy_form_chirho(&[
            ("expected_previous_chirho", String::new()),
            (
                "reviewed_policy_hash_chirho",
                reviewed_two_hash_chirho.clone(),
            ),
            (
                "policy_at_ms_chirho",
                hidden_input_value_chirho(&preview_two_text_chirho, "policy_at_ms_chirho"),
            ),
            ("policy_json_chirho", policy_two_json_chirho.clone()),
        ]);
        let missing_expected_apply_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/apply-chirho"),
            &headers_a_chirho,
            &missing_expected_apply_body_chirho,
        );
        assert_eq!(missing_expected_apply_chirho.status_chirho, 409);
        assert_eq!(
            resource_chirho::current_resource_policy_hash_chirho(&root_chirho, "ownerbudgetapp")
                .unwrap()
                .unwrap(),
            current_hash_chirho
        );
        assert_eq!(
            resource_chirho::load_resource_policy_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            1
        );
        let direct_policy_json_chirho = resource_policy_input_json_chirho(
            "owner_write_chirho",
            7,
            Some(60_000),
            false,
            resource_chirho::ResourceOverageChirho::FailClosedChirho,
        );
        let direct_input_chirho: resource_chirho::ResourcePolicyInputChirho =
            serde_json::from_str(&direct_policy_json_chirho).unwrap();
        let (direct_hash_chirho, _direct_policy_chirho, _direct_record_chirho) =
            resource_chirho::set_resource_policy_from_input_chirho(
                &root_chirho,
                "ownerbudgetapp",
                &owner_a_chirho.principal_chirho,
                direct_input_chirho,
            )
            .unwrap();
        assert_eq!(
            resource_chirho::load_resource_policy_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            2
        );
        let stale_apply_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/apply-chirho"),
            &headers_a_chirho,
            &stale_apply_body_chirho,
        );
        assert_eq!(stale_apply_chirho.status_chirho, 409);
        assert_eq!(
            resource_chirho::current_resource_policy_hash_chirho(&root_chirho, "ownerbudgetapp")
                .unwrap()
                .unwrap(),
            direct_hash_chirho
        );
        assert_eq!(
            resource_chirho::load_resource_policy_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            2
        );

        let risky_policy_json_chirho = resource_policy_input_json_chirho(
            "owner_write_chirho",
            11,
            None,
            true,
            resource_chirho::ResourceOverageChirho::FailClosedChirho,
        );
        let risky_preview_body_chirho = resource_policy_form_chirho(&[
            ("expected_previous_chirho", direct_hash_chirho.0.clone()),
            ("policy_json_chirho", risky_policy_json_chirho),
        ]);
        let risky_preview_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/preview-chirho"),
            &headers_a_chirho,
            &risky_preview_body_chirho,
        );
        assert_eq!(risky_preview_chirho.status_chirho, 200);
        let risky_preview_text_chirho = http_body_text_chirho(&risky_preview_chirho);
        assert!(risky_preview_text_chirho
            .contains("data-resource-policy-warning-chirho=\"anonymous-cumulative-failclosed\""));
        assert!(risky_preview_text_chirho.contains("permanently exhaust the shared bucket"));

        let invalid_policy_body_chirho = resource_policy_form_chirho(&[
            ("expected_previous_chirho", direct_hash_chirho.0.clone()),
            (
                "policy_json_chirho",
                "{\"meters_chirho\":[],\"actions_chirho\":[]}".to_string(),
            ),
        ]);
        let invalid_preview_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("{path_a_chirho}/preview-chirho"),
            &headers_a_chirho,
            &invalid_policy_body_chirho,
        );
        assert_eq!(invalid_preview_chirho.status_chirho, 400);
        assert_eq!(
            resource_chirho::current_resource_policy_hash_chirho(&root_chirho, "ownerbudgetapp")
                .unwrap()
                .unwrap(),
            direct_hash_chirho
        );

        let records_chirho =
            resource_chirho::load_resource_policy_records_chirho(&root_chirho).unwrap();
        let mut bad_records_chirho = records_chirho.clone();
        bad_records_chirho[0].sig_chirho = "00".repeat(64);
        write_jsonl_chirho(
            &root_chirho.join("resource-policy-records-chirho.jsonl"),
            &bad_records_chirho,
        );
        let tampered_show_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "GET",
            &path_a_chirho,
            &headers_a_chirho,
            &[],
        );
        assert_eq!(tampered_show_chirho.status_chirho, 400);
        let tampered_show_text_chirho = http_body_text_chirho(&tampered_show_chirho);
        assert!(!tampered_show_text_chirho.contains("resource policy applied"));
        assert!(!tampered_show_text_chirho.contains("Current reviewed policy"));
        write_jsonl_chirho(
            &root_chirho.join("resource-policy-records-chirho.jsonl"),
            &records_chirho,
        );

        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn resource_policy_http_authoring_routes_are_generic_chirho() {
    let route_segment_chirho = include_str!("../../resource_policy_web_chirho.rs");
    assert!(
        !route_segment_chirho
            .to_ascii_lowercase()
            .contains("perffection"),
        "resource-policy authoring routes must stay generic"
    );
}
