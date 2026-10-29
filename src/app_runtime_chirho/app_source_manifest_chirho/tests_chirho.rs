// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Tests for app_source_manifest_chirho (split out to keep the module under the line cap).

use super::*;
use crate::model_chirho::{NodeDefChirho, BUILTIN_PHI_ENTRY_CHIRHO};
use crate::{app_chirho, cas_chirho, effect_chirho, identity_chirho, refs_chirho, review_chirho};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "request_access_policy_tests_chirho.rs"]
mod request_access_policy_tests_chirho;

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let process_id_chirho = std::process::id();
    std::env::temp_dir().join(format!(
        "cairn-app-source-manifest-test-{process_id_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

#[test]
fn cargo_example_artifact_tracks_cargo_target_dir_chirho() {
    let base_chirho = Path::new("/workspace/examples-chirho");
    let declared_chirho =
        Path::new("../target/wasm32-unknown-unknown/debug/examples/guest_chirho.wasm");
    let target_dir_chirho = Path::new("/isolated/cargo-target-chirho");
    assert_eq!(
        cargo_example_artifact_path_chirho(
            base_chirho,
            declared_chirho,
            "wasm32-unknown-unknown",
            Some(target_dir_chirho),
        )
        .unwrap(),
        target_dir_chirho.join("wasm32-unknown-unknown/debug/examples/guest_chirho.wasm")
    );
    assert_eq!(
        cargo_example_artifact_path_chirho(
            base_chirho,
            declared_chirho,
            "wasm32-unknown-unknown",
            None,
        )
        .unwrap(),
        base_chirho.join(declared_chirho)
    );
}

fn assert_source_candidate_left_no_authoritative_surface_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
) {
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_name_chirho).unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.records_chirho, 0);
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho).unwrap();
    assert!(!refs_chirho
        .branches_chirho
        .contains_key(&format!("app/{app_name_chirho}")));
    let route_prefix_chirho = format!("app-route/{app_name_chirho}/");
    assert!(!refs_chirho
        .branches_chirho
        .keys()
        .any(|branch_chirho| branch_chirho.starts_with(&route_prefix_chirho)));
    assert!(!root_chirho
        .join("app-input-policy-records-chirho.jsonl")
        .exists());
    assert!(!root_chirho.join("effects-chirho").exists());
    assert!(
        effect_chirho::load_volatile_effect_records_chirho(root_chirho)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn path_loader_rejects_projection_manifest_v2_before_permissive_v1_use_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let manifest_path_chirho = root_chirho.join("projection-manifest-v2-chirho.json");
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: "app-source-manifest-v2-chirho".to_string(),
        app_chirho: "projection-app-chirho".to_string(),
        owner_chirho: "owner/projection-chirho".to_string(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    std::fs::write(
        &manifest_path_chirho,
        serde_json::to_vec(&manifest_chirho).unwrap(),
    )
    .unwrap();
    let error_chirho = load_app_source_manifest_from_path_chirho(&manifest_path_chirho)
        .expect_err("production path loader must remain v1-only until packet 4");
    assert!(error_chirho
        .to_string()
        .contains("unsupported app source manifest schema 'app-source-manifest-v2-chirho'"));
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

#[test]
fn legacy_source_route_manifest_omits_request_body_policy_chirho() {
    let route_chirho = AppSourceDeployRouteManifestChirho {
        route_chirho: "status".to_string(),
        source_chirho: AppSourceDeploySourceChirho::StoredDagChirho {
            hash_chirho: HashChirho("a".repeat(64)),
        },
        input_mode_chirho: None,
        request_body_policy_chirho: None,
        response_content_type_chirho: None,
        params_chirho: None,
        key_access_chirho: None,
    };
    let value_chirho = serde_json::to_value(&route_chirho).unwrap();
    assert!(value_chirho.get("request_body_policy_chirho").is_none());
    let roundtrip_chirho: AppSourceDeployRouteManifestChirho =
        serde_json::from_value(value_chirho).unwrap();
    assert_eq!(roundtrip_chirho.request_body_policy_chirho, None);
}

#[test]
fn source_manifest_lowers_builtin_phi_node_chirho() {
    let root_chirho = tmp_root_chirho();
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "phi-app".to_string(),
        owner_chirho: "owner/phi-chirho".to_string(),
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "merge_node".to_string(),
            name_chirho: "merge_choice_chirho".to_string(),
            entry_chirho: None,
            fuel_chirho: 0,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::BuiltinPhiChirho {
                input_ports_chirho: vec!["left_chirho".to_string(), "right_chirho".to_string()],
                output_port_chirho: "chosen_chirho".to_string(),
            },
        }],
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let artifacts_chirho = build_app_source_manifest_artifacts_chirho(
        &root_chirho,
        Path::new("."),
        &manifest_chirho,
        None,
    )
    .unwrap();
    let node_hash_chirho = &artifacts_chirho.node_reports_chirho[0].node_chirho;
    let node_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(&root_chirho, node_hash_chirho).unwrap();
    assert!(node_chirho.is_builtin_phi_chirho());
    assert_eq!(node_chirho.entry_chirho, BUILTIN_PHI_ENTRY_CHIRHO);
    assert_eq!(
        node_chirho
            .inputs_chirho
            .iter()
            .map(|port_chirho| port_chirho.name_chirho.as_str())
            .collect::<Vec<_>>(),
        vec!["left_chirho", "right_chirho"]
    );
    assert_eq!(node_chirho.outputs_chirho[0].name_chirho, "chosen_chirho");

    let mut bad_manifest_chirho = manifest_chirho.clone();
    if let AppSourceNodeSourceChirho::BuiltinPhiChirho {
        input_ports_chirho, ..
    } = &mut bad_manifest_chirho.nodes_chirho[0].source_chirho
    {
        input_ports_chirho.push("left_chirho".to_string());
    }
    let error_chirho = match build_app_source_manifest_artifacts_chirho(
        &root_chirho,
        Path::new("."),
        &bad_manifest_chirho,
        None,
    ) {
        Ok(_) => panic!("duplicate phi ports should fail"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(error_chirho.contains("duplicate builtin phi input port"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_lowers_builtin_node_template_chirho() {
    let root_chirho = tmp_root_chirho();
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "builtin-template-app".to_string(),
        owner_chirho: "owner/builtin-template-chirho".to_string(),
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "save_node".to_string(),
            name_chirho: "save_node_chirho".to_string(),
            entry_chirho: Some("node_chirho".to_string()),
            fuel_chirho: 0,
            capabilities_chirho: vec!["write-store:orders-chirho".to_string()],
            source_chirho: AppSourceNodeSourceChirho::BuiltinNodeTemplateChirho {
                template_chirho: APP_SOURCE_BUILTIN_NODE_TEMPLATE_CHIRHO.to_string(),
            },
        }],
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let artifacts_chirho = build_app_source_manifest_artifacts_chirho(
        &root_chirho,
        Path::new("."),
        &manifest_chirho,
        None,
    )
    .unwrap();
    let node_hash_chirho = &artifacts_chirho.node_reports_chirho[0].node_chirho;
    let node_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(&root_chirho, node_hash_chirho).unwrap();
    let impl_bytes_chirho =
        cas_chirho::get_chirho(&root_chirho, &node_chirho.impl_wasm_chirho).unwrap();
    assert_eq!(
        impl_bytes_chirho,
        include_bytes!("../../../examples-chirho/node-template-chirho.wat")
    );
    assert_eq!(node_chirho.entry_chirho, "node_chirho");
    assert_eq!(node_chirho.fuel_limit_chirho, 0);
    assert_eq!(node_chirho.capabilities_chirho.len(), 1);

    let mut bad_manifest_chirho = manifest_chirho.clone();
    bad_manifest_chirho.nodes_chirho[0].source_chirho =
        AppSourceNodeSourceChirho::BuiltinNodeTemplateChirho {
            template_chirho: "unknown-template-chirho".to_string(),
        };
    let error_chirho = match build_app_source_manifest_artifacts_chirho(
        &root_chirho,
        Path::new("."),
        &bad_manifest_chirho,
        None,
    ) {
        Ok(_) => panic!("unknown builtin node template should fail"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(error_chirho.contains("unsupported builtin node template"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_deploys_static_asset_records_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let css_path_chirho = root_chirho.join("site-chirho.css");
    std::fs::write(&css_path_chirho, b".shell-chirho { color: #245c4b; }\n").unwrap();
    let png_path_chirho = root_chirho.join("logo-chirho.png");
    let png_bytes_chirho = b"\x89PNG\r\n\x1a\nasset-source-proof-chirho";
    std::fs::write(&png_path_chirho, png_bytes_chirho).unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let root_dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "asset-source-app-chirho".to_string(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: vec![
            AppSourceAssetManifestChirho {
                name_chirho: "site-chirho.css".to_string(),
                content_type_chirho: "text/css".to_string(),
                source_chirho: AppSourceAssetSourceChirho::PathChirho {
                    path_chirho: css_path_chirho.clone(),
                },
            },
            AppSourceAssetManifestChirho {
                name_chirho: "logo-chirho.png".to_string(),
                content_type_chirho: "image/png".to_string(),
                source_chirho: AppSourceAssetSourceChirho::PathChirho {
                    path_chirho: png_path_chirho.clone(),
                },
            },
        ],
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::StoredDagChirho {
                hash_chirho: root_dag_chirho,
            }),
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
            response_content_type_chirho: Some("text/html".to_string()),
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let report_chirho =
        deploy_app_source_manifest_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    assert_eq!(report_chirho.assets_chirho.len(), 2);
    assert_eq!(
        app_chirho::verify_app_static_assets_chirho(&root_chirho).unwrap(),
        2
    );
    let css_selection_chirho = app_chirho::app_static_asset_by_name_chirho(
        &root_chirho,
        "asset-source-app-chirho",
        "site-chirho.css",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        app_chirho::app_static_asset_bytes_chirho(&root_chirho, &css_selection_chirho).unwrap(),
        b".shell-chirho { color: #245c4b; }\n"
    );
    let png_selection_chirho = app_chirho::app_static_asset_by_name_chirho(
        &root_chirho,
        "asset-source-app-chirho",
        "logo-chirho.png",
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        png_selection_chirho.record_chirho.content_type_chirho,
        "image/png"
    );
    assert_eq!(
        app_chirho::app_static_asset_bytes_chirho(&root_chirho, &png_selection_chirho).unwrap(),
        png_bytes_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_policy_only_deploy_omits_empty_undo_plan_bindings_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "policy-only-source-chirho",
        dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "policy-only-source-chirho".to_string(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: None,
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let report_chirho =
        deploy_app_source_manifest_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    assert!(report_chirho.undo_plan_bindings_chirho.is_none());
    validate_app_source_deploy_report_schema_chirho(&report_chirho).unwrap();
    assert_eq!(
        app_chirho::app_input_mode_chirho(
            &root_chirho,
            "policy-only-source-chirho",
            None,
            &owner_chirho
        )
        .unwrap(),
        app_chirho::AppInputModeChirho::PlainChirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_installs_package_target_chirho() {
    let src_root_chirho = tmp_root_chirho();
    let dst_root_chirho = tmp_root_chirho();
    let artifact_dir_chirho = src_root_chirho.join("artifacts");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let artifact_chirho = artifact_dir_chirho.join("upcase-chirho.wat");
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &dst_root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "contact-pkg".to_string(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "contact_node".to_string(),
            name_chirho: "contact_form_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho.clone(),
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "contact_dag".to_string(),
            nodes_chirho: vec!["contact_node".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: vec![AppSourceModuleManifestChirho {
            id_chirho: "contact_module".to_string(),
            dag_chirho: "contact_dag".to_string(),
            name_chirho: "contact_form_chirho".to_string(),
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![AppSourceModuleBindingManifestChirho {
                public_name_chirho: "request_chirho".to_string(),
                node_chirho: "contact_node".to_string(),
                node_port_chirho: "in".to_string(),
            }],
            output_bindings_chirho: vec![AppSourceModuleBindingManifestChirho {
                public_name_chirho: "response_chirho".to_string(),
                node_chirho: "contact_node".to_string(),
                node_port_chirho: "out".to_string(),
            }],
            route_labels_chirho: vec!["contact-chirho".to_string()],
            metadata_chirho: BTreeMap::new(),
            subscription_views_chirho: Vec::new(),
        }],
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::ModuleIdChirho {
                id_chirho: "contact_module".to_string(),
            }),
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                subject_chirho: "app/contact-pkg/root".to_string(),
                safe_metadata_chirho: Vec::new(),
            }),
            response_content_type_chirho: Some("text/html".to_string()),
            params_chirho: None,
            routes_chirho: vec![AppSourceDeployRouteManifestChirho {
                route_chirho: "submit".to_string(),
                source_chirho: AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "contact_module".to_string(),
                },
                input_mode_chirho: Some(app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
                    subject_chirho: "app/contact-pkg/submit".to_string(),
                    safe_metadata_chirho: Vec::new(),
                }),
                request_body_policy_chirho: None,
                response_content_type_chirho: Some("text/html".to_string()),
                params_chirho: None,
                key_access_chirho: None,
            }],
            runtime_packages_chirho: vec![AppSourceRuntimePackageManifestChirho {
                module_chirho: AppSourceModuleRefChirho::ModuleIdChirho {
                    id_chirho: "contact_module".to_string(),
                },
                profile_chirho: "browser-chirho".to_string(),
            }],
            target_chirho: AppSourceDeployTargetChirho::LocalInstallChirho {
                root_chirho: dst_root_chirho.clone(),
            },
        },
    };

    let report_chirho =
        deploy_app_source_manifest_chirho(&src_root_chirho, Path::new("."), &manifest_chirho)
            .unwrap();
    assert!(report_chirho.deploy_chirho.is_none());
    let package_report_chirho = report_chirho.package_chirho.as_ref().unwrap();
    let undo_plan_bindings_chirho = report_chirho.undo_plan_bindings_chirho.as_ref().unwrap();
    assert_eq!(undo_plan_bindings_chirho.len(), 1);
    assert!(cas_chirho::get_chirho(
        &dst_root_chirho,
        &undo_plan_bindings_chirho[0].plan_cas_chirho
    )
    .is_ok());
    assert_eq!(package_report_chirho.app_chirho, "contact-pkg");
    assert_eq!(package_report_chirho.owner_chirho, owner_chirho);
    assert_eq!(
        package_report_chirho.dag_chirho,
        report_chirho.modules_chirho[0].dag_chirho
    );
    assert!(package_report_chirho.objects_chirho >= 3);
    assert_eq!(package_report_chirho.runtime_packages_chirho.len(), 1);
    match &report_chirho.target_chirho {
        AppSourceDeployTargetReportChirho::LocalInstallChirho {
            root_chirho,
            objects_installed_chirho,
        } => {
            assert_eq!(root_chirho, &dst_root_chirho);
            assert_eq!(
                *objects_installed_chirho,
                package_report_chirho.objects_chirho
            );
        }
        other_chirho => panic!("unexpected target report: {other_chirho:?}"),
    }
    let dst_status_chirho = app_chirho::app_status_chirho(&dst_root_chirho, "contact-pkg").unwrap();
    assert!(dst_status_chirho.active_chirho);
    assert_eq!(
        dst_status_chirho.dag_chirho,
        Some(report_chirho.modules_chirho[0].dag_chirho.clone())
    );
    assert_eq!(
        dst_status_chirho.routes_chirho.get("submit"),
        Some(&report_chirho.modules_chirho[0].dag_chirho)
    );
    assert_eq!(
        app_chirho::app_input_mode_chirho(&dst_root_chirho, "contact-pkg", None, &owner_chirho)
            .unwrap(),
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact-pkg/root".to_string(),
            safe_metadata_chirho: Vec::new(),
        }
    );
    assert_eq!(
        app_chirho::app_response_content_type_chirho(
            &dst_root_chirho,
            "contact-pkg",
            &owner_chirho
        )
        .unwrap()
        .as_deref(),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        app_chirho::app_input_mode_chirho(
            &dst_root_chirho,
            "contact-pkg",
            Some("submit"),
            &owner_chirho
        )
        .unwrap(),
        app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact-pkg/submit".to_string(),
            safe_metadata_chirho: Vec::new(),
        }
    );
    assert_eq!(
        app_chirho::app_route_response_content_type_chirho(
            &dst_root_chirho,
            "contact-pkg",
            "submit",
            &owner_chirho
        )
        .unwrap()
        .as_deref(),
        Some("text/html; charset=utf-8")
    );
    let _dag_chirho: crate::model_chirho::DagChirho = store_chirho::get_object_chirho(
        &dst_root_chirho,
        &report_chirho.modules_chirho[0].dag_chirho,
    )
    .unwrap();
    let runtime_package_chirho = runtime_profile_chirho::validate_stored_runtime_package_chirho(
        &dst_root_chirho,
        &package_report_chirho.runtime_packages_chirho[0],
    )
    .unwrap();
    assert_eq!(
        runtime_package_chirho.profile_chirho,
        runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho
    );
    assert_eq!(
        runtime_package_chirho.module_chirho,
        report_chirho.modules_chirho[0].module_chirho
    );
    let src_status_chirho = app_chirho::app_status_chirho(&src_root_chirho, "contact-pkg").unwrap();
    assert!(!src_status_chirho.active_chirho);
    let _ = std::fs::remove_dir_all(&src_root_chirho);
    let _ = std::fs::remove_dir_all(&dst_root_chirho);
}

#[test]
fn source_effectful_package_carries_verified_bindings_and_installs_chirho() {
    let source_chirho = tmp_root_chirho();
    let target_chirho = tmp_root_chirho();
    let artifact_chirho = source_chirho.join("effectful-package-chirho.wat");
    std::fs::create_dir_all(&source_chirho).unwrap();
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &target_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "effectful-package-chirho".to_string(),
        owner_chirho,
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "writer_chirho".to_string(),
            name_chirho: "writer_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: vec![
                "write-store:effectful-package/submissions-chirho".to_string()
            ],
            source_chirho: AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho,
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "writer_dag_chirho".to_string(),
            nodes_chirho: vec!["writer_chirho".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::DagIdChirho {
                id_chirho: "writer_dag_chirho".to_string(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalInstallChirho {
                root_chirho: target_chirho.clone(),
            },
        },
    };

    let report_chirho =
        deploy_app_source_manifest_chirho(&source_chirho, Path::new("."), &manifest_chirho)
            .unwrap();
    let bindings_chirho = report_chirho.undo_plan_bindings_chirho.as_ref().unwrap();
    assert_eq!(bindings_chirho.len(), 1);
    assert!(cas_chirho::get_chirho(&target_chirho, &bindings_chirho[0].plan_cas_chirho).is_ok());
    assert!(
        app_chirho::app_status_chirho(&target_chirho, "effectful-package-chirho")
            .unwrap()
            .active_chirho
    );

    let _ = std::fs::remove_dir_all(&source_chirho);
    let _ = std::fs::remove_dir_all(&target_chirho);
}

#[test]
fn source_candidate_builds_checked_in_agent_manifest_without_refs_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-source-manifest-chirho.example.json");

    let report_chirho = build_app_source_candidate_from_path_for_owner_chirho(
        &root_chirho,
        &manifest_chirho,
        &owner_chirho,
    )
    .unwrap();

    assert_eq!(
        report_chirho.schema_chirho,
        APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO
    );
    validate_app_source_candidate_report_schema_chirho(&report_chirho).unwrap();
    assert_eq!(report_chirho.app_chirho, "agent-demo");
    assert_eq!(report_chirho.owner_chirho, owner_chirho);
    assert_eq!(report_chirho.nodes_chirho.len(), 1);
    assert_eq!(report_chirho.dags_chirho.len(), 1);
    assert_eq!(report_chirho.modules_chirho.len(), 1);
    assert_eq!(
        report_chirho.root_dag_chirho,
        report_chirho.modules_chirho[0].dag_chirho
    );
    assert!(matches!(
        report_chirho.input_mode_chirho,
        Some(app_chirho::AppInputModeChirho::PlainChirho)
    ));

    assert_source_candidate_left_no_authoritative_surface_chirho(&root_chirho, "agent-demo");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_review_binds_manifest_hashes_and_is_repeatable_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_path_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-source-manifest-chirho.example.json");
    let raw_manifest_bytes_chirho = std::fs::read(&manifest_path_chirho).unwrap();
    let raw_manifest_hash_chirho = cas_chirho::hash_chirho(&raw_manifest_bytes_chirho);
    let (_base_chirho, mut effective_manifest_chirho) =
        load_app_source_manifest_from_path_chirho(&manifest_path_chirho).unwrap();
    effective_manifest_chirho.owner_chirho = owner_chirho.clone();
    let effective_manifest_hash_chirho =
        store_chirho::hash_object_chirho(&effective_manifest_chirho).unwrap();

    let first_report_chirho = build_app_source_review_from_path_for_owner_chirho(
        &root_chirho,
        &manifest_path_chirho,
        &owner_chirho,
    )
    .unwrap();
    let second_report_chirho = build_app_source_review_from_path_for_owner_chirho(
        &root_chirho,
        &manifest_path_chirho,
        &owner_chirho,
    )
    .unwrap();

    assert_eq!(first_report_chirho, second_report_chirho);
    let source_review_report_hash_chirho = first_report_chirho
        .source_review_report_chirho
        .as_ref()
        .unwrap();
    assert_eq!(
        source_review_report_hash_chirho,
        second_report_chirho
            .source_review_report_chirho
            .as_ref()
            .unwrap()
    );
    assert_eq!(
        hash_app_source_review_report_chirho(&first_report_chirho).unwrap(),
        *source_review_report_hash_chirho
    );
    let stored_review_report_chirho: AppSourceReviewReportChirho =
        store_chirho::get_object_chirho(&root_chirho, source_review_report_hash_chirho).unwrap();
    assert!(stored_review_report_chirho
        .source_review_report_chirho
        .is_none());
    assert_eq!(
        stored_review_report_chirho,
        canonical_app_source_review_report_chirho(&first_report_chirho)
    );
    let source_manifest_chirho = first_report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_ref()
        .unwrap();
    assert_eq!(
        source_manifest_chirho.effective_manifest_hash_chirho,
        effective_manifest_hash_chirho
    );
    assert_eq!(
        source_manifest_chirho.raw_manifest_hash_chirho,
        Some(raw_manifest_hash_chirho)
    );
    assert_eq!(
        cas_chirho::get_chirho(
            &root_chirho,
            source_manifest_chirho
                .raw_manifest_hash_chirho
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        raw_manifest_bytes_chirho
    );
    let stored_manifest_chirho: AppSourceManifestChirho = store_chirho::get_object_chirho(
        &root_chirho,
        &source_manifest_chirho.effective_manifest_hash_chirho,
    )
    .unwrap();
    assert_eq!(stored_manifest_chirho, effective_manifest_chirho);
    let manifest_base_chirho = manifest_path_chirho.parent().unwrap();
    let rebuilt_candidate_chirho = build_app_source_candidate_chirho(
        &root_chirho,
        manifest_base_chirho,
        &stored_manifest_chirho,
    )
    .unwrap();
    assert_eq!(
        rebuilt_candidate_chirho.root_dag_chirho,
        first_report_chirho.candidate_chirho.root_dag_chirho
    );
    let rebuilt_source_chirho = rebuilt_candidate_chirho
        .source_manifest_chirho
        .as_ref()
        .unwrap();
    assert_eq!(
        rebuilt_source_chirho.effective_manifest_hash_chirho,
        source_manifest_chirho.effective_manifest_hash_chirho
    );
    assert!(rebuilt_source_chirho.raw_manifest_hash_chirho.is_none());
    assert_eq!(
        first_report_chirho.review_chirho.candidate_chirho,
        first_report_chirho.candidate_chirho.root_dag_chirho
    );

    let mut legacy_candidate_chirho = first_report_chirho.candidate_chirho.clone();
    legacy_candidate_chirho.source_manifest_chirho = None;
    validate_app_source_candidate_report_schema_chirho(&legacy_candidate_chirho).unwrap();
    let mut legacy_review_chirho = first_report_chirho.clone();
    legacy_review_chirho.source_review_report_chirho = None;
    legacy_review_chirho.candidate_chirho.source_manifest_chirho = None;
    validate_app_source_review_report_schema_chirho(&legacy_review_chirho).unwrap();
    assert_source_candidate_left_no_authoritative_surface_chirho(&root_chirho, "agent-demo");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_review_from_bytes_with_base_matches_path_flow_chirho() {
    // The bytes+base entry point (used by the credits-demo LocalPhaseB smoke to review the
    // in-process tree-build emit without touching checked-in source) must single-source the exact
    // candidate+review the path flow produces on identical bytes, base, owner, and root, while
    // hashing the supplied RAW bytes and resolving assets against the explicit app-root base.
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_path_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-source-manifest-chirho.example.json");
    let manifest_bytes_chirho = std::fs::read(&manifest_path_chirho).unwrap();
    let base_chirho = manifest_path_chirho.parent().unwrap();

    let path_report_chirho = build_app_source_review_from_path_for_owner_chirho(
        &root_chirho,
        &manifest_path_chirho,
        &owner_chirho,
    )
    .unwrap();
    let bytes_report_chirho = build_app_source_review_from_bytes_with_base_for_owner_chirho(
        &root_chirho,
        &manifest_bytes_chirho,
        base_chirho,
        &owner_chirho,
    )
    .unwrap();

    assert_eq!(path_report_chirho, bytes_report_chirho);
    let source_manifest_chirho = bytes_report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_ref()
        .unwrap();
    assert_eq!(
        source_manifest_chirho.raw_manifest_hash_chirho,
        Some(cas_chirho::hash_chirho(&manifest_bytes_chirho))
    );
    assert_ne!(
        source_manifest_chirho
            .raw_manifest_hash_chirho
            .as_ref()
            .unwrap(),
        &source_manifest_chirho.effective_manifest_hash_chirho,
        "owner substitution must make the effective object hash differ from the raw emit hash"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_candidate_surfaces_bad_caps_and_promotes_reviewed_hash_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-source-manifest-chirho.example.json");
    let bad_manifest_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-overcap-source-manifest-chirho.example.json");

    let safe_report_chirho = build_app_source_candidate_from_path_for_owner_chirho(
        &root_chirho,
        &manifest_chirho,
        &owner_chirho,
    )
    .unwrap();
    let bad_report_chirho = build_app_source_candidate_from_path_for_owner_chirho(
        &root_chirho,
        &bad_manifest_chirho,
        &owner_chirho,
    )
    .unwrap();
    assert_source_candidate_left_no_authoritative_surface_chirho(
        &root_chirho,
        &bad_report_chirho.app_chirho,
    );
    let bad_diff_chirho = review_chirho::review_current_app_candidate_chirho(
        &root_chirho,
        &bad_report_chirho.app_chirho,
        bad_report_chirho.root_dag_chirho.clone(),
    )
    .unwrap();
    assert!(bad_diff_chirho
        .added_capabilities_chirho
        .iter()
        .any(|cap_chirho| cap_chirho == "WriteStoreChirho(prefix=agent-demo-overcap-chirho)"));
    assert_eq!(bad_diff_chirho.candidate_cost_token_chirho, 0);
    assert!(review_chirho::promote_candidate_chirho(
        &root_chirho,
        &bad_report_chirho.app_chirho,
        &owner_chirho,
        bad_report_chirho.root_dag_chirho.clone(),
        false,
        false,
    )
    .unwrap_err()
    .to_string()
    .contains("candidate adds capabilities"));
    let bad_status_chirho =
        app_chirho::app_status_chirho(&root_chirho, &bad_report_chirho.app_chirho).unwrap();
    assert!(!bad_status_chirho.active_chirho);

    let promoted_chirho = review_chirho::promote_candidate_chirho(
        &root_chirho,
        &safe_report_chirho.app_chirho,
        &owner_chirho,
        safe_report_chirho.root_dag_chirho.clone(),
        false,
        false,
    )
    .unwrap();
    assert_eq!(
        promoted_chirho.candidate_chirho,
        safe_report_chirho.root_dag_chirho
    );
    assert_eq!(
        promoted_chirho.diff_chirho.candidate_chirho,
        safe_report_chirho.root_dag_chirho
    );
    let status_chirho =
        app_chirho::app_status_chirho(&root_chirho, &safe_report_chirho.app_chirho).unwrap();
    assert!(status_chirho.active_chirho);
    assert_eq!(
        status_chirho.dag_chirho,
        Some(safe_report_chirho.root_dag_chirho)
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_review_surfaces_bad_caps_without_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let bad_manifest_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-overcap-source-manifest-chirho.example.json");

    let report_chirho = build_app_source_review_from_path_for_owner_chirho(
        &root_chirho,
        &bad_manifest_chirho,
        &owner_chirho,
    )
    .unwrap();

    validate_app_source_review_report_schema_chirho(&report_chirho).unwrap();
    assert_eq!(
        report_chirho.schema_chirho,
        APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO
    );
    assert!(report_chirho.non_authoritative_chirho);
    assert_eq!(
        report_chirho.candidate_chirho.app_chirho,
        "agent-demo-overcap"
    );
    assert_eq!(
        report_chirho.review_chirho.candidate_chirho,
        report_chirho.candidate_chirho.root_dag_chirho
    );
    assert!(report_chirho
        .review_chirho
        .added_capabilities_chirho
        .iter()
        .any(|cap_chirho| cap_chirho == "WriteStoreChirho(prefix=agent-demo-overcap-chirho)"));
    assert_source_candidate_left_no_authoritative_surface_chirho(
        &root_chirho,
        &report_chirho.candidate_chirho.app_chirho,
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_review_safe_manifest_is_no_cap_no_cost_and_non_authoritative_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples-chirho/agent-authored-backend-source-manifest-chirho.example.json");

    let report_chirho = build_app_source_review_from_path_for_owner_chirho(
        &root_chirho,
        &manifest_chirho,
        &owner_chirho,
    )
    .unwrap();

    assert!(report_chirho.non_authoritative_chirho);
    assert_eq!(report_chirho.candidate_chirho.app_chirho, "agent-demo");
    assert!(report_chirho
        .review_chirho
        .added_capabilities_chirho
        .is_empty());
    assert_eq!(report_chirho.review_chirho.cost_delta_token_chirho, 0);
    assert!(report_chirho
        .review_chirho
        .candidate_paid_effects_chirho
        .is_empty());
    assert_eq!(
        report_chirho.review_chirho.candidate_chirho,
        report_chirho.candidate_chirho.root_dag_chirho
    );
    assert_source_candidate_left_no_authoritative_surface_chirho(&root_chirho, "agent-demo");
    let promoted_chirho = review_chirho::promote_candidate_chirho(
        &root_chirho,
        &report_chirho.candidate_chirho.app_chirho,
        &owner_chirho,
        report_chirho.review_chirho.candidate_chirho.clone(),
        false,
        false,
    )
    .unwrap();
    assert_eq!(
        promoted_chirho.candidate_chirho,
        report_chirho.candidate_chirho.root_dag_chirho
    );
    assert_eq!(
        promoted_chirho.diff_chirho.candidate_chirho,
        report_chirho.review_chirho.candidate_chirho
    );
    let status_chirho =
        app_chirho::app_status_chirho(&root_chirho, &report_chirho.candidate_chirho.app_chirho)
            .unwrap();
    assert_eq!(
        status_chirho.dag_chirho,
        Some(report_chirho.candidate_chirho.root_dag_chirho)
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_review_surfaces_paid_cost_without_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let artifact_dir_chirho = root_chirho.join("artifacts");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let artifact_chirho = artifact_dir_chirho.join("paid-candidate-chirho.wat");
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "agent-paid-candidate".to_string(),
        owner_chirho,
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "agent_paid_node".to_string(),
            name_chirho: "agent_paid_node_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: vec!["paid:llm_chirho:user/demo".to_string()],
            source_chirho: AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho,
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "agent_paid_dag".to_string(),
            nodes_chirho: vec!["agent_paid_node".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::DagIdChirho {
                id_chirho: "agent_paid_dag".to_string(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    assert!(report_chirho.non_authoritative_chirho);
    let source_manifest_chirho = report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_ref()
        .unwrap();
    assert_eq!(
        source_manifest_chirho.effective_manifest_hash_chirho,
        store_chirho::hash_object_chirho(&manifest_chirho).unwrap()
    );
    assert!(source_manifest_chirho.raw_manifest_hash_chirho.is_none());
    assert_source_candidate_left_no_authoritative_surface_chirho(
        &root_chirho,
        &report_chirho.candidate_chirho.app_chirho,
    );
    let diff_chirho = &report_chirho.review_chirho;
    assert!(diff_chirho
        .added_capabilities_chirho
        .iter()
        .any(|cap_chirho| cap_chirho == "PaidEffectChirho(effect=llm_chirho,caller=user/demo)"));
    assert_eq!(diff_chirho.cost_delta_token_chirho, 100);
    assert_eq!(diff_chirho.candidate_paid_effects_chirho.len(), 1);
    assert_eq!(
        diff_chirho.candidate_paid_effects_chirho[0].effect_chirho,
        "llm_chirho"
    );
    assert_eq!(
        diff_chirho.candidate_paid_effects_chirho[0].source_chirho,
        "registered-effect"
    );
    assert_eq!(
        diff_chirho.candidate_paid_effects_chirho[0].total_cost_token_chirho,
        100
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_rejects_unknown_node_before_deploy_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "contact".to_string(),
        owner_chirho,
        nodes_chirho: Vec::new(),
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "contact_dag".to_string(),
            nodes_chirho: vec!["missing".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::DagIdChirho {
                id_chirho: "contact_dag".to_string(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let err_chirho =
        deploy_app_source_manifest_chirho(&root_chirho, Path::new("."), &manifest_chirho)
            .unwrap_err()
            .to_string();
    assert!(err_chirho.contains("unknown node id"));
    let status_chirho = app_chirho::app_status_chirho(&root_chirho, "contact").unwrap();
    assert!(!status_chirho.active_chirho);
    assert!(status_chirho.dag_chirho.is_none());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn source_manifest_builds_effect_capable_node_chirho() {
    let root_chirho = tmp_root_chirho();
    let artifact_dir_chirho = root_chirho.join("artifacts");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let artifact_chirho = artifact_dir_chirho.join("passthrough-chirho.wat");
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "contact-effect".to_string(),
        owner_chirho,
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "store_contact".to_string(),
            name_chirho: "store_contact_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: vec!["write-store:contacts-chirho/latest".to_string()],
            source_chirho: AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho,
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "contact_effect_dag".to_string(),
            nodes_chirho: vec!["store_contact".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::DagIdChirho {
                id_chirho: "contact_effect_dag".to_string(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let report_chirho =
        deploy_app_source_manifest_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    assert_eq!(report_chirho.nodes_chirho.len(), 1);
    let node_def_chirho: NodeDefChirho =
        store_chirho::get_object_chirho(&root_chirho, &report_chirho.nodes_chirho[0].node_chirho)
            .unwrap();
    assert!(matches!(
        node_def_chirho.capabilities_chirho.as_slice(),
        [crate::model_chirho::CapabilityChirho::WriteStoreChirho { prefix_chirho }]
            if prefix_chirho == "contacts-chirho/latest"
    ));
    assert_eq!(
        node_def_chirho.effect_contract_set_chirho,
        Some(
            cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho(
                &cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho(),
            )
            .unwrap()
        )
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn direct_deploy_refuses_stored_pre_v2_effect_node_chirho() {
    let root_chirho = tmp_root_chirho();
    let legacy_node_chirho = NodeDefChirho {
        name_chirho: "legacy-effect-node-chirho".into(),
        capabilities_chirho: vec![crate::model_chirho::CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "legacy-records-chirho".into(),
        }],
        ..Default::default()
    };
    let legacy_node_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &legacy_node_chirho).unwrap();
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "legacy-direct-deploy-chirho".into(),
        owner_chirho: "owner/legacy-direct-deploy-chirho".into(),
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "legacy_node_chirho".into(),
            name_chirho: "legacy_node_chirho".into(),
            entry_chirho: None,
            fuel_chirho: 0,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::StoredNodeChirho {
                hash_chirho: legacy_node_hash_chirho,
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "legacy_dag_chirho".into(),
            nodes_chirho: vec!["legacy_node_chirho".into()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::DagIdChirho {
                id_chirho: "legacy_dag_chirho".into(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };

    let error_chirho =
        deploy_app_source_manifest_chirho(&root_chirho, Path::new("."), &manifest_chirho)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("does not name the current verified contract set"));
    assert_source_candidate_left_no_authoritative_surface_chirho(
        &root_chirho,
        &manifest_chirho.app_chirho,
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
