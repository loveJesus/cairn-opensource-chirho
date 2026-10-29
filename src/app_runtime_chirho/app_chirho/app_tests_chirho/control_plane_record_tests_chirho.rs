// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

#[test]
fn owner_gates_redeploy_and_undeploy_chirho() {
    let root_chirho = tmp_root_chirho();
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
    let dag_a_chirho = fake_dag_chirho(&root_chirho, b"dag a");
    let dag_b_chirho = fake_dag_chirho(&root_chirho, b"dag b");

    deploy_app_chirho(
        &root_chirho,
        "myapp",
        dag_a_chirho.clone(),
        &owner_a_chirho.principal_chirho,
    )
    .unwrap();
    assert_eq!(
        refs_chirho::load_refs_chirho(&root_chirho)
            .unwrap()
            .branches_chirho
            .get("app/myapp"),
        Some(&dag_a_chirho)
    );
    assert_eq!(
        app_owner_chirho(&root_chirho, "myapp").unwrap(),
        Some(owner_a_chirho.principal_chirho.clone())
    );

    assert!(deploy_app_chirho(
        &root_chirho,
        "myapp",
        dag_b_chirho.clone(),
        &owner_b_chirho.principal_chirho,
    )
    .is_err());
    assert!(undeploy_app_chirho(&root_chirho, "myapp", &owner_b_chirho.principal_chirho).is_err());

    deploy_app_chirho(
        &root_chirho,
        "myapp",
        dag_b_chirho.clone(),
        &owner_a_chirho.principal_chirho,
    )
    .unwrap();
    let status_chirho = app_status_chirho(&root_chirho, "myapp").unwrap();
    assert!(status_chirho.active_chirho);
    assert_eq!(status_chirho.dag_chirho, Some(dag_b_chirho));
    assert_eq!(status_chirho.records_chirho, 2);

    assert!(undeploy_app_chirho(&root_chirho, "myapp", &owner_a_chirho.principal_chirho).unwrap());
    assert!(!undeploy_app_chirho(&root_chirho, "myapp", &owner_a_chirho.principal_chirho).unwrap());
    assert!(deploy_app_chirho(
        &root_chirho,
        "myapp",
        dag_a_chirho.clone(),
        &owner_b_chirho.principal_chirho,
    )
    .is_err());
    assert_eq!(verify_apps_chirho(&root_chirho).unwrap(), 3);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn verified_app_owner_rejects_tampered_last_record_chirho() {
    let root_chirho = tmp_root_chirho();
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
    let dag_chirho = fake_dag_chirho(&root_chirho, b"tamper dag");
    let mut app_record_chirho = deploy_app_chirho(
        &root_chirho,
        "tamper-app",
        dag_chirho,
        &owner_a_chirho.principal_chirho,
    )
    .unwrap();
    assert_eq!(
        verified_app_owner_chirho(&root_chirho, "tamper-app").unwrap(),
        Some(owner_a_chirho.principal_chirho.clone())
    );

    app_record_chirho.owner_principal_chirho = owner_b_chirho.principal_chirho.clone();
    write_jsonl_chirho(&app_records_path_chirho(&root_chirho), &[app_record_chirho]);

    assert_eq!(
        app_owner_chirho(&root_chirho, "tamper-app").unwrap(),
        Some(owner_b_chirho.principal_chirho.clone())
    );
    let error_chirho = verified_app_owner_chirho(&root_chirho, "tamper-app")
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("app record 0 signature invalid"));
    let redeploy_error_chirho = deploy_app_chirho(
        &root_chirho,
        "tamper-app",
        fake_dag_chirho(&root_chirho, b"tamper redeploy dag"),
        &owner_b_chirho.principal_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(redeploy_error_chirho.contains("app record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn raw_app_owner_reads_have_no_production_callers_chirho() {
    let raw_reads_chirho = production_source_lines_matching_chirho("app_chirho::app_owner_chirho(");
    assert_eq!(
        raw_reads_chirho,
        Vec::<(String, usize, String)>::new(),
        "production app owner consumers must use verified_app_owner_chirho or verified status helpers"
    );
}

#[test]
fn app_control_plane_raw_reads_stay_centralized_chirho() {
    let raw_ref_reads_chirho = production_source_lines_chirho()
        .into_iter()
        .filter(|(_file_chirho, _line_chirho, text_chirho)| {
            // The bare literals are scanned too, not only the call forms. Binding "app/" to a
            // named const and using the const is a one-line, innocent-looking way to own a private
            // copy of the app-ref grammar while leaving this guard green -- which makes the guard
            // read stronger than it is. Catching the literal itself closes that exit.
            text_chirho.contains("\"app/\"")
                || text_chirho.contains("\"app-route/\"")
                || text_chirho.contains("strip_prefix(\"app/\")")
                || text_chirho.contains("format!(\"app/")
                || text_chirho.contains("\"app-route/")
                || text_chirho.contains("format!(\"app-route/")
        })
        .collect::<Vec<_>>();
    for (file_chirho, _line_chirho, text_chirho) in &raw_ref_reads_chirho {
        let allowed_chirho = file_chirho == "src/app_runtime_chirho/app_chirho.rs"
            || file_chirho
                == "crates/runtime-chirho/cairn-model-app-chirho/src/app_policy_chirho.rs"
            || file_chirho
                == "src/app_runtime_chirho/app_chirho/head_protocol_chirho/app_head_transition_chirho.rs"
            || file_chirho
                == "crates/runtime-chirho/cairn-app-control-chirho/src/lib.rs"
            || (file_chirho
                == "crates/runtime-chirho/cairn-app-control-chirho/src/app_head_removal_chirho.rs"
                && text_chirho == "format!(\"app/{app_chirho}\")")
            || (file_chirho
                == "crates/runtime-chirho/cairn-app-control-chirho/src/app_route_head_removal_chirho.rs"
                && text_chirho == "format!(\"app-route/{app_chirho}/{route_chirho}\")")
            || (file_chirho
                == "crates/cairn-cli-chirho/src/cli_helpers_chirho/reporting_chirho/status_cli_chirho.rs"
                && text_chirho == "let route_chirho = format!(\"app/{name_chirho}\");")
            || (file_chirho
                == "crates/cairn-serve-runtime-chirho/src/serve_chirho/app_web_chirho/app_state_web_chirho.rs"
                && matches!(
                    text_chirho.as_str(),
                    "let subject_prefix_chirho = format!(\"app/{app_chirho}/\");"
                        | "let expected_prefix_chirho = format!(\"app/{app_chirho}/\");"
                ))
            || (file_chirho == "crates/services-chirho/cairn-learner-handover-chirho/src/lib.rs"
                && text_chirho
                    == "let branch_chirho = \"app-route/contact/contact-list\".to_string();")
            // G1 tenant-root placement invariant: `cairn-tenant-chirho` is a SUPPORT crate and
            // cannot depend on the root crate, so it cannot call `app_branch_ref_name_chirho` and
            // must own the prefix constant. Allowlisted for the CONST DECLARATION ONLY -- any other
            // raw app-ref handling in that file still fails this guard. Found by adversarial review
            // of cef62aaf, which caught the const binding evading the four call-form needles above.
            || (file_chirho
                == "crates/support-chirho/cairn-tenant-chirho/src/single_customer_app_chirho.rs"
                && text_chirho == "pub const CUSTOMER_APP_REF_PREFIX_CHIRHO: &str = \"app/\";")
            // Shadow ref-snapshot NAME validation (pre-commitment (c)): a pure string check on
            // ref names deciding which branch families may cross replication — reads no
            // control-plane log. Committed in 8d4a63a; allowlisted by the lead (perf-gate pass).
            || (file_chirho
                == "crates/services-chirho/cairn-replication-chirho/src/ref_snapshot_chirho.rs"
                && matches!(
                    text_chirho.as_str(),
                    "if let Some(app_chirho) = name_chirho.strip_prefix(\"app/\") {"
                        | "if let Some(rest_chirho) = name_chirho.strip_prefix(\"app-route/\") {"
                ));
        assert!(
            allowed_chirho,
            "raw app-control-plane ref read escaped verified helpers: {file_chirho}: {text_chirho}"
        );
    }

    let raw_policy_loads_chirho =
        production_source_lines_matching_chirho("app_chirho::load_app_input_policy_records_chirho");
    for (file_chirho, _line_chirho, text_chirho) in &raw_policy_loads_chirho {
        let allowed_chirho = matches!(
            file_chirho.as_str(),
            "src/privacy_compliance_chirho/compliance_evidence_chirho/source_snapshots_chirho.rs"
                | "src/privacy_compliance_chirho/data_rights_chirho.rs"
        );
        assert!(
            allowed_chirho,
            "raw app input policy loads must stay export/evidence-only: {file_chirho}: {text_chirho}"
        );
    }
}

#[test]
fn app_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"app dag");
    let route_dag_chirho = fake_dag_chirho(&root_chirho, b"route dag");
    let app_record_chirho = deploy_app_chirho(
        &root_chirho,
        "myapp",
        app_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let route_record_chirho = deploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "contact",
        route_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let policy_record_chirho = set_app_input_policy_chirho(
        &root_chirho,
        "myapp",
        Some("contact"),
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/myapp/contact".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    let app_response_policy_record_chirho = set_app_response_policy_chirho(
        &root_chirho,
        "myapp",
        &owner_chirho.principal_chirho,
        "text/plain",
    )
    .unwrap();
    let response_policy_record_chirho = set_app_route_response_policy_chirho(
        &root_chirho,
        "myapp",
        "contact",
        &owner_chirho.principal_chirho,
        "text/html",
    )
    .unwrap();
    assert_eq!(app_record_chirho.schema_chirho, APP_RECORD_V2_SCHEMA_CHIRHO);
    assert_eq!(
        route_record_chirho.schema_chirho,
        APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO
    );
    assert_eq!(
        verified_app_route_request_body_policy_chirho(
            &root_chirho,
            "myapp",
            "contact",
            &owner_chirho.principal_chirho,
            route_record_chirho.dag_chirho.as_ref().unwrap(),
        )
        .unwrap(),
        None,
        "legacy direct route deploy must retain accept-body-by-absence semantics"
    );
    assert_eq!(
        policy_record_chirho.schema_chirho,
        APP_INPUT_POLICY_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(
        app_response_policy_record_chirho.schema_chirho,
        APP_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(
        response_policy_record_chirho.schema_chirho,
        APP_ROUTE_RESPONSE_POLICY_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(verify_apps_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_app_routes_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_app_input_policies_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        verify_app_response_policies_chirho(&root_chirho).unwrap(),
        1
    );
    assert_eq!(
        verify_app_route_response_policies_chirho(&root_chirho).unwrap(),
        1
    );

    let mut bad_app_chirho = app_record_chirho.clone();
    bad_app_chirho.schema_chirho = "app-record-v3-chirho".to_string();
    write_jsonl_chirho(&app_records_path_chirho(&root_chirho), &[bad_app_chirho]);
    let app_error_chirho = verify_apps_chirho(&root_chirho).unwrap_err().to_string();
    assert!(app_error_chirho.contains("unsupported app record schema"));
    write_jsonl_chirho(
        &app_records_path_chirho(&root_chirho),
        std::slice::from_ref(&app_record_chirho),
    );

    let mut bad_route_chirho = route_record_chirho.clone();
    bad_route_chirho.schema_chirho = "app-route-record-v3-chirho".to_string();
    write_jsonl_chirho(
        &app_route_records_path_chirho(&root_chirho),
        &[bad_route_chirho],
    );
    let route_error_chirho = verify_app_routes_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(route_error_chirho.contains("unsupported app route record schema"));
    write_jsonl_chirho(
        &app_route_records_path_chirho(&root_chirho),
        std::slice::from_ref(&route_record_chirho),
    );

    let mut tampered_route_policy_chirho = route_record_chirho.clone();
    tampered_route_policy_chirho.request_body_policy_chirho =
        Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho);
    write_jsonl_chirho(
        &app_route_records_path_chirho(&root_chirho),
        &[tampered_route_policy_chirho],
    );
    let route_policy_error_chirho = verify_app_routes_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(route_policy_error_chirho.contains("signature invalid"));
    write_jsonl_chirho(
        &app_route_records_path_chirho(&root_chirho),
        std::slice::from_ref(&route_record_chirho),
    );

    let mut bad_policy_chirho = policy_record_chirho.clone();
    bad_policy_chirho.schema_chirho = "app-input-policy-record-v2-chirho".to_string();
    write_jsonl_chirho(
        &app_input_policy_records_path_chirho(&root_chirho),
        &[bad_policy_chirho],
    );
    let policy_error_chirho = verify_app_input_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(policy_error_chirho.contains("unsupported app input policy record schema"));

    let mut bad_app_response_policy_chirho = app_response_policy_record_chirho.clone();
    bad_app_response_policy_chirho.schema_chirho =
        "app-response-policy-record-v2-chirho".to_string();
    write_jsonl_chirho(
        &app_response_policy_records_path_chirho(&root_chirho),
        &[bad_app_response_policy_chirho],
    );
    let app_response_policy_error_chirho = verify_app_response_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        app_response_policy_error_chirho.contains("unsupported app response policy record schema")
    );

    let mut bad_response_policy_chirho = response_policy_record_chirho.clone();
    bad_response_policy_chirho.schema_chirho =
        "app-route-response-policy-record-v2-chirho".to_string();
    write_jsonl_chirho(
        &app_route_response_policy_records_path_chirho(&root_chirho),
        &[bad_response_policy_chirho],
    );
    let response_policy_error_chirho = verify_app_route_response_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(response_policy_error_chirho
        .contains("unsupported app route response policy record schema"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn app_input_policy_rejects_unreviewed_safe_metadata_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let dag_chirho = fake_dag_chirho(&root_chirho, b"safe metadata app");
    deploy_app_chirho(
        &root_chirho,
        "myapp",
        dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    let error_chirho = set_app_input_policy_chirho(
        &root_chirho,
        "myapp",
        None,
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/myapp/contact".to_string(),
            safe_metadata_chirho: vec![AppPrivateInputSafeMetadataChirho {
                key_chirho: "prayer_chirho".to_string(),
                allowed_values_chirho: vec!["prayer_chirho".to_string()],
            }],
        },
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("unsupported private input safe metadata key 'prayer_chirho'"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn app_response_policy_is_allowlisted_signed_and_latest_wins_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"app dag");
    deploy_app_chirho(
        &root_chirho,
        "myapp",
        app_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    assert!(app_response_content_type_chirho(
        &root_chirho,
        "myapp",
        &owner_chirho.principal_chirho
    )
    .unwrap()
    .is_none());
    let first_chirho = set_app_response_policy_chirho(
        &root_chirho,
        "myapp",
        &owner_chirho.principal_chirho,
        "TEXT/HTML",
    )
    .unwrap();
    assert_eq!(
        first_chirho.response_content_type_chirho,
        "text/html; charset=utf-8"
    );
    set_app_response_policy_chirho(
        &root_chirho,
        "myapp",
        &owner_chirho.principal_chirho,
        "application/json",
    )
    .unwrap();
    assert_eq!(
        app_response_content_type_chirho(&root_chirho, "myapp", &owner_chirho.principal_chirho)
            .unwrap()
            .as_deref(),
        Some("application/json; charset=utf-8")
    );
    assert!(set_app_response_policy_chirho(
        &root_chirho,
        "myapp",
        &owner_chirho.principal_chirho,
        "text/javascript"
    )
    .is_err());

    let mut records_chirho = load_app_response_policy_records_chirho(&root_chirho).unwrap();
    records_chirho[1].response_content_type_chirho = "text/html; charset=utf-8".to_string();
    write_jsonl_chirho(
        &app_response_policy_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let sig_error_chirho = verify_app_response_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(sig_error_chirho.contains("signature invalid"));

    records_chirho[1] =
        resign_app_response_policy_record_for_test_chirho(&root_chirho, records_chirho[1].clone());
    records_chirho[1].response_content_type_chirho = "text/html".to_string();
    records_chirho[1] =
        resign_app_response_policy_record_for_test_chirho(&root_chirho, records_chirho[1].clone());
    write_jsonl_chirho(
        &app_response_policy_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let canonical_error_chirho = verify_app_response_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(canonical_error_chirho.contains("not canonical"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn route_response_policy_is_allowlisted_signed_and_latest_wins_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"app dag");
    let route_dag_chirho = fake_dag_chirho(&root_chirho, b"route dag");
    deploy_app_chirho(
        &root_chirho,
        "myapp",
        app_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    deploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "preview",
        route_dag_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    assert!(app_route_response_content_type_chirho(
        &root_chirho,
        "myapp",
        "preview",
        &owner_chirho.principal_chirho
    )
    .unwrap()
    .is_none());
    let first_chirho = set_app_route_response_policy_chirho(
        &root_chirho,
        "myapp",
        "preview",
        &owner_chirho.principal_chirho,
        "TEXT/HTML",
    )
    .unwrap();
    assert_eq!(
        first_chirho.response_content_type_chirho,
        "text/html; charset=utf-8"
    );
    set_app_route_response_policy_chirho(
        &root_chirho,
        "myapp",
        "preview",
        &owner_chirho.principal_chirho,
        "application/json",
    )
    .unwrap();
    assert_eq!(
        app_route_response_content_type_chirho(
            &root_chirho,
            "myapp",
            "preview",
            &owner_chirho.principal_chirho
        )
        .unwrap()
        .as_deref(),
        Some("application/json; charset=utf-8")
    );
    assert!(set_app_route_response_policy_chirho(
        &root_chirho,
        "myapp",
        "preview",
        &owner_chirho.principal_chirho,
        "text/javascript"
    )
    .is_err());

    let mut records_chirho = load_app_route_response_policy_records_chirho(&root_chirho).unwrap();
    records_chirho[1].response_content_type_chirho = "text/html; charset=utf-8".to_string();
    write_jsonl_chirho(
        &app_route_response_policy_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let sig_error_chirho = verify_app_route_response_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(sig_error_chirho.contains("signature invalid"));

    records_chirho[1] = resign_app_route_response_policy_record_for_test_chirho(
        &root_chirho,
        records_chirho[1].clone(),
    );
    records_chirho[1].response_content_type_chirho = "text/html".to_string();
    records_chirho[1] = resign_app_route_response_policy_record_for_test_chirho(
        &root_chirho,
        records_chirho[1].clone(),
    );
    write_jsonl_chirho(
        &app_route_response_policy_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let canonical_error_chirho = verify_app_route_response_policies_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(canonical_error_chirho.contains("not canonical"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_route_record_and_signed_message_bytes_stay_identical_chirho() {
    let record_chirho = AppRouteRecordChirho {
        seq_chirho: 7,
        schema_chirho: APP_ROUTE_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "legacy-app".to_string(),
        route_chirho: "status".to_string(),
        owner_principal_chirho: "owner/legacy".to_string(),
        dag_chirho: Some(HashChirho("a".repeat(64))),
        action_chirho: AppRouteActionChirho::DeployRouteChirho,
        request_body_policy_chirho: None,
        at_ms_chirho: 11,
        previous_chirho: None,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "legacy-signature".to_string(),
    };
    // The serde storage-JSON layout freeze (exact serialized key order/omission) was demoted to the
    // advisory structure report as a field-order text-proxy; the canonical signed-message-bytes
    // stability engine claim (so legacy signatures keep verifying) stays RED here.
    assert_eq!(
        String::from_utf8(app_route_record_message_chirho(&record_chirho).unwrap()).unwrap(),
        format!(
            "{{\"seq_chirho\":7,\"schema_chirho\":\"app-route-record-v1-chirho\",\"app_chirho\":\"legacy-app\",\"route_chirho\":\"status\",\"owner_principal_chirho\":\"owner/legacy\",\"dag_chirho\":\"{}\",\"action_chirho\":\"DeployRouteChirho\",\"at_ms_chirho\":11}}",
            "a".repeat(64)
        )
    );
}

// unreviewed_route_deploy_defaults_to_legacy_accept_body_absence_chirho was demoted to the advisory
// structure report (serde skip-if-None omission + dev-path-None serialization shape) as a
// source-text proxy in cairn-source-scan-chirho::source_scan_chirho::structure_report_chirho.

#[test]
fn legacy_app_records_without_schema_still_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let app_dag_chirho = fake_dag_chirho(&root_chirho, b"app dag");
    let route_dag_chirho = fake_dag_chirho(&root_chirho, b"route dag");
    let mut app_record_chirho = deploy_app_chirho(
        &root_chirho,
        "myapp",
        app_dag_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let mut route_record_chirho = deploy_app_route_chirho(
        &root_chirho,
        "myapp",
        "contact",
        route_dag_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let mut policy_record_chirho = set_app_input_policy_chirho(
        &root_chirho,
        "myapp",
        Some("contact"),
        &owner_chirho.principal_chirho,
        AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/myapp/contact".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_record_chirho.schema_chirho.clear();
    app_record_chirho.previous_chirho = None;
    app_record_chirho.transition_id_chirho.clear();
    app_record_chirho.prepared_writer_fence_epoch_chirho = None;
    route_record_chirho.schema_chirho.clear();
    route_record_chirho.previous_chirho = None;
    route_record_chirho.transition_id_chirho.clear();
    route_record_chirho.prepared_writer_fence_epoch_chirho = None;
    policy_record_chirho.schema_chirho.clear();
    let app_record_chirho = resign_app_record_for_test_chirho(&root_chirho, app_record_chirho);
    let route_record_chirho =
        resign_app_route_record_for_test_chirho(&root_chirho, route_record_chirho);
    let policy_record_chirho =
        resign_app_input_policy_record_for_test_chirho(&root_chirho, policy_record_chirho);
    write_jsonl_chirho(&app_records_path_chirho(&root_chirho), &[app_record_chirho]);
    write_jsonl_chirho(
        &app_route_records_path_chirho(&root_chirho),
        &[route_record_chirho],
    );
    write_jsonl_chirho(
        &app_input_policy_records_path_chirho(&root_chirho),
        &[policy_record_chirho],
    );
    refs_chirho::set_branch_chirho(&root_chirho, "app/myapp", app_dag_chirho).unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        "app-route/myapp/contact",
        route_dag_chirho.clone(),
    )
    .unwrap();

    for path_chirho in [
        app_records_path_chirho(&root_chirho),
        app_route_records_path_chirho(&root_chirho),
        app_input_policy_records_path_chirho(&root_chirho),
    ] {
        assert!(!std::fs::read_to_string(path_chirho)
            .unwrap()
            .contains("schema_chirho"));
    }
    assert_eq!(verify_apps_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_app_routes_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_app_input_policies_chirho(&root_chirho).unwrap(), 1);
    assert!(load_app_records_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
    assert!(load_app_route_records_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
    assert!(load_app_input_policy_records_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
    assert_eq!(
        resolve_app_route_chirho(
            &root_chirho,
            &refs_chirho::load_refs_chirho(&root_chirho).unwrap(),
            "myapp",
            "contact",
            &owner_chirho.principal_chirho,
        )
        .unwrap(),
        route_dag_chirho
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
