// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn app_and_route_names_reject_empty_slash_and_whitespace_chirho() {
    validate_app_name_chirho("tree-template-landing").unwrap();
    validate_route_name_chirho("build-chirho").unwrap();
    assert!(validate_app_name_chirho("").is_err());
    assert!(validate_app_name_chirho("bad/name").is_err());
    assert!(validate_app_name_chirho("bad name").is_err());
    assert!(validate_route_name_chirho("").is_err());
    assert!(validate_route_name_chirho("bad/name").is_err());
    assert!(validate_route_name_chirho("bad name").is_err());
}

#[test]
fn response_content_type_normalizes_known_payload_types_chirho() {
    assert_eq!(
        normalize_app_response_content_type_chirho("text/html").unwrap(),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        normalize_app_response_content_type_chirho(" Application/JSON; Charset=UTF-8 ").unwrap(),
        "application/json; charset=utf-8"
    );
    assert!(normalize_app_response_content_type_chirho("text/css").is_err());
    assert!(normalize_app_response_content_type_chirho("text/html\r\nx: y").is_err());
}

#[test]
fn static_asset_name_accepts_safe_cosmetic_names_chirho() {
    validate_app_static_asset_name_chirho("site-chirho.css").unwrap();
    validate_app_static_asset_name_chirho("shell_v2-chirho.css").unwrap();
    assert!(validate_app_static_asset_name_chirho("").is_err());
    assert!(validate_app_static_asset_name_chirho(" ../site.css").is_err());
    assert!(validate_app_static_asset_name_chirho("../site.css").is_err());
    assert!(validate_app_static_asset_name_chirho("bad/name.css").is_err());
    assert!(validate_app_static_asset_name_chirho(".").is_err());
    assert!(validate_app_static_asset_name_chirho("..").is_err());
}

#[test]
fn static_asset_content_type_normalizes_reviewed_types_chirho() {
    assert_eq!(
        normalize_app_static_asset_content_type_chirho("text/css").unwrap(),
        APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(
        normalize_app_static_asset_content_type_chirho(" TEXT/CSS; CHARSET=UTF-8 ").unwrap(),
        APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(
        normalize_app_static_asset_content_type_chirho(" IMAGE/PNG ").unwrap(),
        APP_STATIC_ASSET_PNG_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(
        normalize_app_static_asset_content_type_chirho("image/jpeg").unwrap(),
        APP_STATIC_ASSET_JPEG_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(
        normalize_app_static_asset_content_type_chirho("application/pdf").unwrap(),
        APP_STATIC_ASSET_PDF_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(
        normalize_app_static_asset_content_type_chirho("font/woff2").unwrap(),
        APP_STATIC_ASSET_WOFF2_CONTENT_TYPE_CHIRHO
    );
    assert_eq!(
        normalize_app_static_asset_content_type_chirho("application/font-woff").unwrap(),
        APP_STATIC_ASSET_WOFF_CONTENT_TYPE_CHIRHO
    );
    assert!(normalize_app_static_asset_content_type_chirho("text/html").is_err());
    assert!(normalize_app_static_asset_content_type_chirho("image/svg+xml").is_err());
    assert!(normalize_app_static_asset_content_type_chirho("text/css\r\nx: y").is_err());
}

#[test]
fn base_app_control_records_omit_empty_schema_chirho() {
    let hash_chirho =
        HashChirho("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string());
    let app_record_chirho = AppRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        app_chirho: "example-chirho".to_string(),
        owner_principal_chirho: "owner/example-chirho".to_string(),
        dag_chirho: Some(hash_chirho.clone()),
        action_chirho: AppActionChirho::DeployChirho,
        at_ms_chirho: 1,
        previous_chirho: None,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "sig-chirho".to_string(),
    };
    let route_record_chirho = AppRouteRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        app_chirho: "example-chirho".to_string(),
        route_chirho: "build-chirho".to_string(),
        owner_principal_chirho: "owner/example-chirho".to_string(),
        dag_chirho: Some(hash_chirho),
        action_chirho: AppRouteActionChirho::DeployRouteChirho,
        request_body_policy_chirho: None,
        at_ms_chirho: 1,
        previous_chirho: None,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "sig-chirho".to_string(),
    };
    let input_policy_chirho = AppInputPolicyRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        app_chirho: "example-chirho".to_string(),
        route_chirho: None,
        owner_principal_chirho: "owner/example-chirho".to_string(),
        mode_chirho: AppInputModeChirho::PlainChirho,
        request_body_policy_chirho: None,
        at_ms_chirho: 1,
        sig_chirho: "sig-chirho".to_string(),
    };
    let response_policy_chirho = AppResponsePolicyRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        app_chirho: "example-chirho".to_string(),
        owner_principal_chirho: "owner/example-chirho".to_string(),
        response_content_type_chirho: "text/html; charset=utf-8".to_string(),
        at_ms_chirho: 1,
        sig_chirho: "sig-chirho".to_string(),
    };
    let route_response_policy_chirho = AppRouteResponsePolicyRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        app_chirho: "example-chirho".to_string(),
        route_chirho: "build-chirho".to_string(),
        owner_principal_chirho: "owner/example-chirho".to_string(),
        response_content_type_chirho: "text/html; charset=utf-8".to_string(),
        at_ms_chirho: 1,
        sig_chirho: "sig-chirho".to_string(),
    };

    for value_chirho in [
        serde_json::to_value(app_record_chirho).unwrap(),
        serde_json::to_value(route_record_chirho).unwrap(),
        serde_json::to_value(input_policy_chirho).unwrap(),
        serde_json::to_value(response_policy_chirho).unwrap(),
        serde_json::to_value(route_response_policy_chirho).unwrap(),
    ] {
        assert!(value_chirho.get("schema_chirho").is_none());
        assert!(value_chirho.get("undo_plan_bindings_chirho").is_none());
    }
}

#[test]
fn client_owner_binding_record_omits_empty_schema_chirho() {
    let record_chirho = ClientOwnerBindingRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        user_principal_chirho: "user/example-chirho".to_string(),
        owner_principal_chirho: "owner/example-chirho".to_string(),
        status_chirho: CLIENT_OWNER_BINDING_ACTIVE_STATUS_CHIRHO.to_string(),
        at_ms_chirho: 1,
        sig_chirho: "sig-chirho".to_string(),
    };
    let value_chirho = serde_json::to_value(record_chirho).unwrap();
    assert!(value_chirho.get("schema_chirho").is_none());
}

#[test]
fn template_app_deploy_record_omits_optional_usage_seq_chirho() {
    let hash_chirho =
        HashChirho("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
    let record_chirho = TemplateAppDeployRecordChirho {
        seq_chirho: 0,
        schema_chirho: TEMPLATE_APP_DEPLOY_RECORD_SCHEMA_CHIRHO.to_string(),
        user_principal_chirho: "user/example-chirho".to_string(),
        owner_principal_chirho: "owner/example-chirho".to_string(),
        template_id_chirho: "landing-v1-chirho".to_string(),
        app_chirho: "client-example-chirho".to_string(),
        display_slug_chirho: "example-chirho".to_string(),
        root_dag_chirho: hash_chirho.clone(),
        params_chirho: hash_chirho.clone(),
        request_payload_chirho: hash_chirho.clone(),
        idempotency_key_hash_chirho: hash_chirho,
        resource_usage_seq_chirho: None,
        at_ms_chirho: 1,
        sig_chirho: "sig-chirho".to_string(),
    };
    let value_chirho = serde_json::to_value(record_chirho).unwrap();
    assert!(value_chirho.get("resource_usage_seq_chirho").is_none());
}

#[test]
fn app_deploy_manifest_defaults_schema_and_report_omits_legacy_empty_schema_chirho() {
    let hash_chirho =
        HashChirho("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string());
    let manifest_json_chirho = serde_json::json!({
        "app_chirho": "example-chirho",
        "owner_chirho": "owner/example-chirho",
        "root_chirho": {
            "kind_chirho": "dag-chirho",
            "hash_chirho": hash_chirho
        }
    });
    let manifest_chirho: AppDeployManifestChirho =
        serde_json::from_value(manifest_json_chirho).unwrap();
    assert_eq!(
        manifest_chirho.schema_chirho,
        APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO
    );
    assert_eq!(manifest_chirho.request_body_policy_chirho, None);
    assert!(serde_json::to_value(&manifest_chirho)
        .unwrap()
        .get("request_body_policy_chirho")
        .is_none());

    let report_chirho = AppDeployManifestReportChirho {
        schema_chirho: String::new(),
        app_chirho: "example-chirho".to_string(),
        owner_chirho: "owner/example-chirho".to_string(),
        request_access_policy_chirho: None,
        root_dag_chirho: None,
        request_body_policy_chirho: None,
        response_content_type_chirho: None,
        routes_chirho: Vec::new(),
        runtime_packages_chirho: Vec::new(),
    };
    let value_chirho = serde_json::to_value(report_chirho).unwrap();
    assert!(value_chirho.get("schema_chirho").is_none());

    let legacy_route_json_chirho = serde_json::json!({
        "route_chirho": "status-chirho",
        "source_chirho": {
            "kind_chirho": "dag-chirho",
            "hash_chirho": hash_chirho,
        }
    });
    let mut route_chirho: AppDeployRouteManifestChirho =
        serde_json::from_value(legacy_route_json_chirho).unwrap();
    assert_eq!(route_chirho.request_body_policy_chirho, None);
    assert!(serde_json::to_value(&route_chirho)
        .unwrap()
        .get("request_body_policy_chirho")
        .is_none());
    route_chirho.request_body_policy_chirho = Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho);
    assert_eq!(
        serde_json::to_value(route_chirho).unwrap()["request_body_policy_chirho"]["kind_chirho"],
        "no-body-chirho"
    );
}

#[test]
fn legacy_input_policy_record_keeps_exact_signed_message_bytes_chirho() {
    let legacy_record_json_chirho = r#"{"seq_chirho":7,"schema_chirho":"app-input-policy-record-v1-chirho","app_chirho":"legacy-app-chirho","route_chirho":null,"owner_principal_chirho":"owner/legacy-chirho","mode_chirho":{"kind_chirho":"plain-chirho"},"at_ms_chirho":42,"sig_chirho":"legacy-signature-chirho"}"#;
    let record_chirho: AppInputPolicyRecordChirho =
        serde_json::from_str(legacy_record_json_chirho).unwrap();
    assert_eq!(record_chirho.request_body_policy_chirho, None);

    let message_chirho = app_input_policy_record_signed_message_chirho(&record_chirho).unwrap();
    assert_eq!(
        String::from_utf8(message_chirho).unwrap(),
        r#"{"seq_chirho":7,"schema_chirho":"app-input-policy-record-v1-chirho","app_chirho":"legacy-app-chirho","route_chirho":null,"owner_principal_chirho":"owner/legacy-chirho","mode_chirho":{"kind_chirho":"plain-chirho"},"at_ms_chirho":42}"#
    );
}

#[test]
fn app_source_manifest_defaults_schema_and_deploy_target_chirho() {
    let hash_chirho =
        HashChirho("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string());
    let manifest_json_chirho = serde_json::json!({
        "app_chirho": "source-app-chirho",
        "owner_chirho": "owner/source-chirho",
        "nodes_chirho": [{
            "id_chirho": "render_chirho",
            "name_chirho": "render_chirho",
            "source_chirho": {
                "kind_chirho": "stored-node-chirho",
                "hash_chirho": hash_chirho
            }
        }],
        "deploy_chirho": {}
    });

    let manifest_chirho: AppSourceManifestChirho =
        serde_json::from_value(manifest_json_chirho).unwrap();
    assert_eq!(
        manifest_chirho.schema_chirho,
        APP_SOURCE_MANIFEST_SCHEMA_CHIRHO
    );
    assert_eq!(manifest_chirho.nodes_chirho[0].fuel_chirho, 1_000_000);
    assert_eq!(
        manifest_chirho.deploy_chirho.target_chirho,
        AppSourceDeployTargetChirho::LocalDeployChirho
    );

    let builtin_node_chirho = AppSourceNodeManifestChirho {
        id_chirho: "blessed_chirho".to_string(),
        name_chirho: "blessed_chirho".to_string(),
        entry_chirho: Some("node_chirho".to_string()),
        fuel_chirho: 0,
        capabilities_chirho: vec!["write-store:orders-chirho".to_string()],
        source_chirho: AppSourceNodeSourceChirho::BuiltinNodeTemplateChirho {
            template_chirho: APP_SOURCE_BUILTIN_NODE_TEMPLATE_CHIRHO.to_string(),
        },
    };
    let builtin_value_chirho = serde_json::to_value(builtin_node_chirho).unwrap();
    assert_eq!(
        builtin_value_chirho["source_chirho"]["kind_chirho"],
        "builtin-node-template-chirho"
    );
    assert_eq!(
        builtin_value_chirho["source_chirho"]["template_chirho"],
        APP_SOURCE_BUILTIN_NODE_TEMPLATE_CHIRHO
    );
}

#[test]
fn app_source_reports_omit_legacy_empty_schema_chirho() {
    let hash_chirho =
        HashChirho("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string());
    let deploy_report_chirho = AppSourceDeployReportChirho {
        schema_chirho: String::new(),
        unreviewed_dev_chirho: false,
        app_chirho: "source-app-chirho".to_string(),
        owner_chirho: "owner/source-chirho".to_string(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        deploy_chirho: None,
        package_chirho: None,
        undo_plan_bindings_chirho: None,
        target_chirho: AppSourceDeployTargetReportChirho::LocalDeployChirho,
    };
    let candidate_report_chirho = AppSourceCandidateReportChirho {
        schema_chirho: String::new(),
        source_manifest_chirho: None,
        app_chirho: "source-app-chirho".to_string(),
        owner_chirho: "owner/source-chirho".to_string(),
        request_access_policy_chirho: None,
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        undo_plan_bindings_chirho: None,
        root_dag_chirho: hash_chirho,
        input_mode_chirho: None,
        request_body_policy_chirho: None,
        response_content_type_chirho: None,
        routes_chirho: Vec::new(),
    };

    for value_chirho in [
        serde_json::to_value(deploy_report_chirho).unwrap(),
        serde_json::to_value(candidate_report_chirho).unwrap(),
    ] {
        assert!(value_chirho.get("schema_chirho").is_none());
    }
}

#[test]
fn app_source_review_report_omits_legacy_empty_schema_chirho() {
    let root_hash_chirho =
        HashChirho("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
    let candidate_report_chirho = AppSourceCandidateReportChirho {
        schema_chirho: String::new(),
        source_manifest_chirho: None,
        app_chirho: "source-app-chirho".to_string(),
        owner_chirho: "owner/source-chirho".to_string(),
        request_access_policy_chirho: None,
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        undo_plan_bindings_chirho: None,
        root_dag_chirho: root_hash_chirho.clone(),
        input_mode_chirho: None,
        request_body_policy_chirho: None,
        response_content_type_chirho: None,
        routes_chirho: Vec::new(),
    };
    let review_report_chirho = AppSourceReviewReportChirho {
        schema_chirho: String::new(),
        source_review_report_chirho: None,
        candidate_chirho: candidate_report_chirho,
        review_chirho: ReviewSurfaceDiffChirho {
            app_chirho: "source-app-chirho".to_string(),
            live_chirho: None,
            candidate_chirho: root_hash_chirho,
            price_book_chirho: None,
            live_node_count_chirho: 0,
            candidate_node_count_chirho: 0,
            live_edge_count_chirho: 0,
            candidate_edge_count_chirho: 0,
            added_nodes_chirho: Vec::new(),
            removed_nodes_chirho: Vec::new(),
            added_capabilities_chirho: Vec::new(),
            removed_capabilities_chirho: Vec::new(),
            live_paid_effects_chirho: Vec::new(),
            candidate_paid_effects_chirho: Vec::new(),
            live_cost_token_chirho: 0,
            candidate_cost_token_chirho: 0,
            cost_delta_token_chirho: 0,
            warnings_chirho: Vec::new(),
        },
        non_authoritative_chirho: true,
    };
    let value_chirho = serde_json::to_value(review_report_chirho).unwrap();
    assert!(value_chirho.get("schema_chirho").is_none());
    assert!(value_chirho.get("source_review_report_chirho").is_none());
    assert_eq!(
        value_chirho["candidate_chirho"]["schema_chirho"],
        serde_json::Value::Null
    );
}

#[test]
fn private_blob_ref_mode_omits_empty_safe_metadata_chirho() {
    let mode_chirho = AppInputModeChirho::PrivateBlobRefChirho {
        subject_chirho: "app/example/private-input".to_string(),
        safe_metadata_chirho: Vec::new(),
    };
    let value_chirho = serde_json::to_value(mode_chirho).unwrap();
    assert_eq!(
        value_chirho["kind_chirho"],
        serde_json::Value::String("private-blob-ref-chirho".to_string())
    );
    assert_eq!(
        value_chirho["subject_chirho"],
        serde_json::Value::String("app/example/private-input".to_string())
    );
    assert!(value_chirho.get("safe_metadata_chirho").is_none());
}

#[test]
fn private_input_safe_metadata_policy_is_value_allowlisted_chirho() {
    let policy_chirho = AppPrivateInputSafeMetadataChirho {
        key_chirho: APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO.to_string(),
        allowed_values_chirho: vec!["visit_chirho".to_string(), "prayer_chirho".to_string()],
    };
    validate_app_private_input_safe_metadata_chirho(std::slice::from_ref(&policy_chirho)).unwrap();
    assert!(app_private_input_safe_metadata_value_allowed_chirho(
        &[policy_chirho],
        APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO,
        "prayer_chirho"
    ));

    assert!(validate_app_private_input_safe_metadata_chirho(&[
        AppPrivateInputSafeMetadataChirho {
            key_chirho: "prayer_chirho".to_string(),
            allowed_values_chirho: vec!["prayer_chirho".to_string()],
        }
    ])
    .is_err());
    assert!(validate_app_private_input_safe_metadata_chirho(&[
        AppPrivateInputSafeMetadataChirho {
            key_chirho: APP_PRIVATE_INPUT_REQUEST_KIND_METADATA_KEY_CHIRHO.to_string(),
            allowed_values_chirho: vec!["johnsmith_chirho".repeat(5)],
        }
    ])
    .is_err());
}
