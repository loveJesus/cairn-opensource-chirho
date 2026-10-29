// For God so loved the world, that He gave His only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::{
    app_chirho, app_manifest_chirho, app_source_manifest_chirho, identity_chirho, store_chirho,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-app-source-manifest-integration-{nanos_chirho}-{n_chirho}"
    ))
}

#[test]
fn source_manifest_builds_and_deploys_contact_route_chirho() {
    let root_chirho = tmp_root_chirho();
    let artifact_dir_chirho = root_chirho.join("artifacts");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let artifact_chirho = artifact_dir_chirho.join("upcase-chirho.wat");
    std::fs::write(
        &artifact_chirho,
        include_str!("../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let params_value_chirho = serde_json::json!({"business_name_chirho":"Source Cafe"});
    let params_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &params_value_chirho).unwrap();
    let manifest_chirho = app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "contact".to_string(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: vec![app_source_manifest_chirho::AppSourceNodeManifestChirho {
            id_chirho: "contact_node".to_string(),
            name_chirho: "contact_form_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: Vec::new(),
            source_chirho: app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho.clone(),
            },
        }],
        dags_chirho: vec![app_source_manifest_chirho::AppSourceDagManifestChirho {
            id_chirho: "contact_dag".to_string(),
            nodes_chirho: vec!["contact_node".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: vec![app_source_manifest_chirho::AppSourceModuleManifestChirho {
            id_chirho: "contact_module".to_string(),
            dag_chirho: "contact_dag".to_string(),
            name_chirho: "contact_form_chirho".to_string(),
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "request_chirho".to_string(),
                    node_chirho: "contact_node".to_string(),
                    node_port_chirho: "in".to_string(),
                },
            ],
            output_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "response_chirho".to_string(),
                    node_chirho: "contact_node".to_string(),
                    node_port_chirho: "out".to_string(),
                },
            ],
            route_labels_chirho: vec!["contact-chirho".to_string()],
            metadata_chirho: BTreeMap::new(),
            subscription_views_chirho: Vec::new(),
        }],
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "contact_module".to_string(),
                },
            ),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: Some(app_manifest_chirho::AppDeployParamsManifestChirho {
                hash_chirho: params_hash_chirho,
                required_chirho: true,
            }),
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let report_chirho = app_source_manifest_chirho::deploy_app_source_manifest_chirho(
        &root_chirho,
        Path::new("."),
        &manifest_chirho,
    )
    .unwrap();
    let deploy_report_chirho = report_chirho.deploy_chirho.as_ref().unwrap();
    assert_eq!(
        report_chirho.schema_chirho,
        app_source_manifest_chirho::APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(
        deploy_report_chirho.schema_chirho,
        app_manifest_chirho::APP_DEPLOY_MANIFEST_REPORT_SCHEMA_CHIRHO
    );
    app_source_manifest_chirho::validate_app_source_deploy_report_schema_chirho(&report_chirho)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&report_chirho).unwrap()["schema_chirho"],
        app_source_manifest_chirho::APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO
    );
    let mut legacy_report_chirho = report_chirho.clone();
    legacy_report_chirho.schema_chirho.clear();
    legacy_report_chirho
        .deploy_chirho
        .as_mut()
        .unwrap()
        .schema_chirho
        .clear();
    app_source_manifest_chirho::validate_app_source_deploy_report_schema_chirho(
        &legacy_report_chirho,
    )
    .unwrap();
    let legacy_report_json_chirho = serde_json::to_string(&legacy_report_chirho).unwrap();
    assert!(!legacy_report_json_chirho.contains("schema_chirho"));
    let legacy_report_roundtrip_chirho: app_source_manifest_chirho::AppSourceDeployReportChirho =
        serde_json::from_str(&legacy_report_json_chirho).unwrap();
    assert!(legacy_report_roundtrip_chirho.schema_chirho.is_empty());
    assert!(legacy_report_roundtrip_chirho
        .deploy_chirho
        .as_ref()
        .unwrap()
        .schema_chirho
        .is_empty());
    let mut bad_report_chirho = report_chirho.clone();
    bad_report_chirho.schema_chirho = "app-source-deploy-report-v9-chirho".to_string();
    let error_chirho = app_source_manifest_chirho::validate_app_source_deploy_report_schema_chirho(
        &bad_report_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("unsupported app source deploy report schema"));
    let mut bad_nested_report_chirho = report_chirho.clone();
    bad_nested_report_chirho
        .deploy_chirho
        .as_mut()
        .unwrap()
        .schema_chirho = "app-deploy-manifest-report-v9-chirho".to_string();
    let error_chirho = app_source_manifest_chirho::validate_app_source_deploy_report_schema_chirho(
        &bad_nested_report_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("unsupported app deploy manifest report schema"));
    assert_eq!(report_chirho.nodes_chirho.len(), 1);
    assert_eq!(report_chirho.dags_chirho.len(), 1);
    assert_eq!(report_chirho.modules_chirho.len(), 1);
    assert_eq!(
        deploy_report_chirho.root_dag_chirho,
        Some(report_chirho.modules_chirho[0].dag_chirho.clone())
    );
    let status_chirho = app_chirho::app_status_chirho(&root_chirho, "contact").unwrap();
    assert!(status_chirho.active_chirho);
    assert_eq!(
        status_chirho.dag_chirho,
        Some(report_chirho.modules_chirho[0].dag_chirho.clone())
    );
    assert_eq!(
        app_chirho::app_params_chirho(&root_chirho, "contact", None, &owner_chirho)
            .unwrap()
            .unwrap()
            .value_chirho,
        params_value_chirho
    );

    let mut unreviewed_manifest_chirho = manifest_chirho.clone();
    unreviewed_manifest_chirho.app_chirho = "contact-dev".to_string();
    unreviewed_manifest_chirho.deploy_chirho.routes_chirho = vec![
        app_source_manifest_chirho::AppSourceDeployRouteManifestChirho {
            route_chirho: "preview".to_string(),
            source_chirho:
                app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "contact_module".to_string(),
                },
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
            request_body_policy_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            key_access_chirho: None,
        },
    ];
    let unreviewed_report_chirho =
        app_source_manifest_chirho::deploy_app_source_manifest_unreviewed_dev_chirho(
            &root_chirho,
            Path::new("."),
            &unreviewed_manifest_chirho,
        )
        .unwrap();
    assert!(unreviewed_report_chirho.unreviewed_dev_chirho);
    let app_records_chirho = app_chirho::load_app_records_chirho(&root_chirho).unwrap();
    assert!(matches!(
        app_records_chirho.last().unwrap().action_chirho,
        app_chirho::AppActionChirho::DeployUnreviewedDevChirho
    ));
    let route_records_chirho = app_chirho::load_app_route_records_chirho(&root_chirho).unwrap();
    assert!(route_records_chirho.iter().any(|record_chirho| {
        record_chirho.app_chirho == "contact-dev"
            && record_chirho.route_chirho == "preview"
            && matches!(
                record_chirho.action_chirho,
                app_chirho::AppRouteActionChirho::DeployRouteUnreviewedDevChirho
            )
    }));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_path_deploy_accepts_owner_override_chirho() {
    let root_chirho = tmp_root_chirho();
    let artifact_dir_chirho = root_chirho.join("artifacts");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let artifact_chirho = artifact_dir_chirho.join("upcase-chirho.wat");
    std::fs::write(
        &artifact_chirho,
        include_str!("../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "owner-override-app".to_string(),
        owner_chirho: "owner/not-created-placeholder-chirho".to_string(),
        nodes_chirho: vec![app_source_manifest_chirho::AppSourceNodeManifestChirho {
            id_chirho: "contact_node".to_string(),
            name_chirho: "contact_form_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: Vec::new(),
            source_chirho: app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                path_chirho: PathBuf::from("upcase-chirho.wat"),
            },
        }],
        dags_chirho: vec![app_source_manifest_chirho::AppSourceDagManifestChirho {
            id_chirho: "contact_dag".to_string(),
            nodes_chirho: vec!["contact_node".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: vec![app_source_manifest_chirho::AppSourceModuleManifestChirho {
            id_chirho: "contact_module".to_string(),
            dag_chirho: "contact_dag".to_string(),
            name_chirho: "contact_form_chirho".to_string(),
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "request_chirho".to_string(),
                    node_chirho: "contact_node".to_string(),
                    node_port_chirho: "in".to_string(),
                },
            ],
            output_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "response_chirho".to_string(),
                    node_chirho: "contact_node".to_string(),
                    node_port_chirho: "out".to_string(),
                },
            ],
            route_labels_chirho: vec!["contact-chirho".to_string()],
            metadata_chirho: BTreeMap::new(),
            subscription_views_chirho: Vec::new(),
        }],
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "contact_module".to_string(),
                },
            ),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let manifest_path_chirho = artifact_dir_chirho.join("source-manifest-chirho.json");
    std::fs::write(
        &manifest_path_chirho,
        serde_json::to_vec_pretty(&manifest_chirho).unwrap(),
    )
    .unwrap();

    let report_chirho =
        app_source_manifest_chirho::deploy_app_source_manifest_from_path_for_owner_chirho(
            &root_chirho,
            &manifest_path_chirho,
            &owner_chirho,
        )
        .unwrap();

    assert_eq!(report_chirho.owner_chirho, owner_chirho);
    assert_eq!(
        app_chirho::verified_app_owner_chirho(&root_chirho, "owner-override-app")
            .unwrap()
            .as_deref(),
        Some(report_chirho.owner_chirho.as_str())
    );
    let status_chirho = app_chirho::app_status_chirho(&root_chirho, "owner-override-app").unwrap();
    assert_eq!(
        status_chirho.owner_principal_chirho.as_deref(),
        Some(report_chirho.owner_chirho.as_str())
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
