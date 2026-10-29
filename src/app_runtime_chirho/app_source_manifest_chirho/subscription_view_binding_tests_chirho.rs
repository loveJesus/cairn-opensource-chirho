// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Security regressions for reviewed subscription-view declaration binding.

use super::*;
use crate::{app_chirho, identity_chirho, review_chirho};
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
        "cairn-subscription-view-binding-test-{nanos_chirho}-{n_chirho}"
    ))
}

fn dependency_chirho(
    module_input_chirho: &str,
    group_chirho: SubscriptionViewDependencyGroupChirho,
) -> SubscriptionViewDependencyChirho {
    SubscriptionViewDependencyChirho {
        module_input_chirho: module_input_chirho.to_string(),
        group_chirho,
    }
}

fn subscription_manifest_chirho(owner_chirho: &str) -> AppSourceManifestChirho {
    AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: "reviewed-subscription-app-chirho".to_string(),
        owner_chirho: owner_chirho.to_string(),
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "render_node_chirho".to_string(),
            name_chirho: "render_node_chirho".to_string(),
            entry_chirho: None,
            fuel_chirho: 0,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::BuiltinPhiChirho {
                input_ports_chirho: vec!["ledger_chirho".to_string(), "holds_chirho".to_string()],
                output_port_chirho: "rendered_chirho".to_string(),
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "render_dag_chirho".to_string(),
            nodes_chirho: vec!["render_node_chirho".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: vec![AppSourceModuleManifestChirho {
            id_chirho: "render_module_chirho".to_string(),
            dag_chirho: "render_dag_chirho".to_string(),
            name_chirho: "render_module_chirho".to_string(),
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![
                AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "ledger_chirho".to_string(),
                    node_chirho: "render_node_chirho".to_string(),
                    node_port_chirho: "ledger_chirho".to_string(),
                },
                AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "holds_chirho".to_string(),
                    node_chirho: "render_node_chirho".to_string(),
                    node_port_chirho: "holds_chirho".to_string(),
                },
            ],
            output_bindings_chirho: vec![AppSourceModuleBindingManifestChirho {
                public_name_chirho: "rendered_chirho".to_string(),
                node_chirho: "render_node_chirho".to_string(),
                node_port_chirho: "rendered_chirho".to_string(),
            }],
            route_labels_chirho: vec!["summary-chirho".to_string()],
            metadata_chirho: BTreeMap::new(),
            subscription_views_chirho: vec![
                SubscriptionViewDeclarationChirho {
                    view_chirho: "owner-root-summary-chirho".to_string(),
                    scope_chirho: SubscriptionViewScopeChirho::AppRootChirho,
                    authorization_chirho: SubscriptionViewAuthorizationChirho::OwnerOnlyChirho,
                    dependencies_chirho: vec![dependency_chirho(
                        "ledger_chirho",
                        SubscriptionViewDependencyGroupChirho::LedgerChirho,
                    )],
                },
                SubscriptionViewDeclarationChirho {
                    view_chirho: "owner-route-summary-chirho".to_string(),
                    scope_chirho: SubscriptionViewScopeChirho::RouteChirho {
                        route_chirho: "summary-chirho".to_string(),
                    },
                    authorization_chirho: SubscriptionViewAuthorizationChirho::OwnerOnlyChirho,
                    dependencies_chirho: vec![dependency_chirho(
                        "holds_chirho",
                        SubscriptionViewDependencyGroupChirho::HoldsChirho,
                    )],
                },
            ],
        }],
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::ModuleIdChirho {
                id_chirho: "render_module_chirho".to_string(),
            }),
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
            response_content_type_chirho: Some("text/html".to_string()),
            params_chirho: None,
            routes_chirho: vec![AppSourceDeployRouteManifestChirho {
                route_chirho: "summary-chirho".to_string(),
                source_chirho: AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "render_module_chirho".to_string(),
                },
                input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
                request_body_policy_chirho: None,
                response_content_type_chirho: Some("text/html".to_string()),
                params_chirho: None,
                key_access_chirho: None,
            }],
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    }
}

#[test]
fn legacy_manifest_without_views_keeps_bytes_and_effective_hash_chirho() {
    let mut manifest_chirho = subscription_manifest_chirho("owner/legacy-chirho");
    manifest_chirho.modules_chirho[0]
        .subscription_views_chirho
        .clear();
    let bytes_chirho = serde_json::to_vec(&manifest_chirho).unwrap();
    assert!(!String::from_utf8_lossy(&bytes_chirho).contains("subscription_views_chirho"));
    let reparsed_chirho: AppSourceManifestChirho = serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(serde_json::to_vec(&reparsed_chirho).unwrap(), bytes_chirho);
    assert_eq!(
        store_chirho::hash_object_chirho(&manifest_chirho)
            .unwrap()
            .0,
        "4be113b0a5c599997a49e6b456c059c81db3a0380a84a363b78a9300eeeb5ea8"
    );
}

#[test]
fn stored_effective_manifest_loader_rejects_projection_v2_schema_chirho() {
    let root_chirho = tmp_root_chirho();
    let mut manifest_chirho = subscription_manifest_chirho("owner/projection-v2-chirho");
    manifest_chirho.schema_chirho = "app-source-manifest-v2-chirho".to_string();
    let manifest_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &manifest_chirho)
        .expect("store inert v2-shaped downgrade fixture");
    let error_chirho = cairn_subscription_view_review_chirho::SubscriptionViewReviewEvidencePortChirho::load_effective_manifest_chirho(
        &RootSubscriptionViewReviewPortChirho(&root_chirho),
        &manifest_hash_chirho,
    )
    .expect_err("stored-hash source-manifest readers must remain v1-only until packet 4");
    assert!(error_chirho
        .to_string()
        .contains("unsupported app source manifest schema 'app-source-manifest-v2-chirho'"));
    std::fs::remove_dir_all(&root_chirho).unwrap();
}

#[test]
fn reviewed_declarations_bind_manifest_candidate_cas_and_scope_chirho() {
    let root_chirho = tmp_root_chirho();
    let manifest_chirho = subscription_manifest_chirho("owner/reviewed-subscription-chirho");
    let report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    validate_app_source_review_declaration_binding_chirho(&root_chirho, &report_chirho).unwrap();
    let module_chirho = &report_chirho.candidate_chirho.modules_chirho[0];
    assert_eq!(module_chirho.subscription_views_chirho.len(), 2);
    for declaration_chirho in &module_chirho.subscription_views_chirho {
        let stored_chirho: SubscriptionViewDeclarationChirho =
            store_chirho::get_object_chirho(&root_chirho, &declaration_chirho.declaration_chirho)
                .unwrap();
        assert_eq!(
            stored_chirho,
            declaration_chirho.reviewed_declaration_chirho()
        );
    }

    let mut dropped_report_chirho = report_chirho.clone();
    dropped_report_chirho.candidate_chirho.modules_chirho[0]
        .subscription_views_chirho
        .clear();
    assert!(validate_app_source_review_declaration_binding_chirho(
        &root_chirho,
        &dropped_report_chirho,
    )
    .unwrap_err()
    .to_string()
    .contains("do not match effective source manifest"));

    let mut tampered_fields_chirho = report_chirho.clone();
    tampered_fields_chirho.candidate_chirho.modules_chirho[0].subscription_views_chirho[0]
        .dependencies_chirho[0]
        .group_chirho = SubscriptionViewDependencyGroupChirho::BillingChirho;
    assert!(validate_app_source_review_declaration_binding_chirho(
        &root_chirho,
        &tampered_fields_chirho,
    )
    .unwrap_err()
    .to_string()
    .contains("do not match effective source manifest"));

    let mut changed_manifest_chirho = manifest_chirho.clone();
    changed_manifest_chirho.modules_chirho[0].subscription_views_chirho[0].dependencies_chirho[0]
        .group_chirho = SubscriptionViewDependencyGroupChirho::BillingChirho;
    let changed_report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &changed_manifest_chirho)
            .unwrap();
    assert_ne!(
        report_chirho
            .candidate_chirho
            .source_manifest_chirho
            .as_ref()
            .unwrap()
            .effective_manifest_hash_chirho,
        changed_report_chirho
            .candidate_chirho
            .source_manifest_chirho
            .as_ref()
            .unwrap()
            .effective_manifest_hash_chirho
    );
    assert_ne!(
        hash_app_source_review_report_chirho(&report_chirho).unwrap(),
        hash_app_source_review_report_chirho(&changed_report_chirho).unwrap()
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn invalid_subscription_view_shapes_fail_before_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let base_chirho = subscription_manifest_chirho("owner/invalid-subscription-chirho");
    let mut cases_chirho = Vec::new();

    let mut empty_chirho = base_chirho.clone();
    empty_chirho.modules_chirho[0].subscription_views_chirho[0]
        .dependencies_chirho
        .clear();
    cases_chirho.push((empty_chirho, "needs at least one dependency"));

    let mut unknown_input_chirho = base_chirho.clone();
    unknown_input_chirho.modules_chirho[0].subscription_views_chirho[0].dependencies_chirho[0]
        .module_input_chirho = "private-row-chirho".to_string();
    cases_chirho.push((unknown_input_chirho, "is not a module input binding"));

    let mut duplicate_input_chirho = base_chirho.clone();
    duplicate_input_chirho.modules_chirho[0].subscription_views_chirho[0]
        .dependencies_chirho
        .push(dependency_chirho(
            "ledger_chirho",
            SubscriptionViewDependencyGroupChirho::BillingChirho,
        ));
    cases_chirho.push((duplicate_input_chirho, "repeats module input"));

    let mut duplicate_group_chirho = base_chirho.clone();
    duplicate_group_chirho.modules_chirho[0].subscription_views_chirho[0]
        .dependencies_chirho
        .push(dependency_chirho(
            "holds_chirho",
            SubscriptionViewDependencyGroupChirho::LedgerChirho,
        ));
    cases_chirho.push((duplicate_group_chirho, "repeats dependency group"));

    let mut duplicate_view_chirho = base_chirho.clone();
    duplicate_view_chirho.modules_chirho[0].subscription_views_chirho[1].view_chirho =
        duplicate_view_chirho.modules_chirho[0].subscription_views_chirho[0]
            .view_chirho
            .clone();
    cases_chirho.push((duplicate_view_chirho, "duplicate subscription view id"));

    let mut invalid_view_id_chirho = base_chirho.clone();
    invalid_view_id_chirho.modules_chirho[0].subscription_views_chirho[0].view_chirho =
        "bad view/chirho".to_string();
    cases_chirho.push((invalid_view_id_chirho, "must contain only ASCII"));

    let mut missing_route_chirho = base_chirho.clone();
    missing_route_chirho.modules_chirho[0].subscription_views_chirho[1].scope_chirho =
        SubscriptionViewScopeChirho::RouteChirho {
            route_chirho: "missing-chirho".to_string(),
        };
    cases_chirho.push((
        missing_route_chirho,
        "route 'missing-chirho' does not exist",
    ));

    for (manifest_chirho, expected_chirho) in cases_chirho {
        let error_chirho =
            build_app_source_candidate_chirho(&root_chirho, Path::new("."), &manifest_chirho)
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains(expected_chirho), "{error_chirho}");
        let status_chirho =
            app_chirho::app_status_chirho(&root_chirho, &manifest_chirho.app_chirho).unwrap();
        assert!(!status_chirho.active_chirho);
        assert_eq!(status_chirho.records_chirho, 0);
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn route_scope_must_resolve_to_the_declaring_module_dag_chirho() {
    let root_chirho = tmp_root_chirho();
    let other_dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let mut manifest_chirho = subscription_manifest_chirho("owner/route-mismatch-chirho");
    manifest_chirho.deploy_chirho.routes_chirho[0].source_chirho =
        AppSourceDeploySourceChirho::StoredDagChirho {
            hash_chirho: other_dag_chirho,
        };
    let error_chirho =
        build_app_source_candidate_chirho(&root_chirho, Path::new("."), &manifest_chirho)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("does not resolve to module DAG"));

    let mut root_mismatch_chirho = subscription_manifest_chirho("owner/root-mismatch-chirho");
    root_mismatch_chirho.deploy_chirho.root_chirho =
        Some(AppSourceDeploySourceChirho::StoredDagChirho {
            hash_chirho: store_chirho::put_object_chirho(
                &root_chirho,
                &crate::model_chirho::DagChirho {
                    nodes_chirho: Vec::new(),
                    edges_chirho: Vec::new(),
                },
            )
            .unwrap(),
        });
    let root_error_chirho =
        build_app_source_candidate_chirho(&root_chirho, Path::new("."), &root_mismatch_chirho)
            .unwrap_err()
            .to_string();
    assert!(root_error_chirho.contains("app-root scope does not match module DAG"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn direct_governance_promote_rejects_mismatched_manifest_before_append_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = subscription_manifest_chirho(&owner_chirho);
    let report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();

    let mut unrelated_manifest_chirho = manifest_chirho.clone();
    unrelated_manifest_chirho.modules_chirho[0]
        .subscription_views_chirho
        .clear();
    let unrelated_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &unrelated_manifest_chirho).unwrap();
    let mut forged_report_chirho = report_chirho.clone();
    forged_report_chirho.source_review_report_chirho = None;
    forged_report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_mut()
        .unwrap()
        .effective_manifest_hash_chirho = unrelated_hash_chirho;
    let forged_hash_chirho =
        put_app_source_review_report_chirho(&root_chirho, &forged_report_chirho).unwrap();

    let error_chirho = review_chirho::promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        &report_chirho.candidate_chirho.app_chirho,
        &owner_chirho,
        report_chirho.candidate_chirho.root_dag_chirho.clone(),
        false,
        false,
        Some(forged_hash_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("do not match effective source manifest"));
    assert_eq!(
        review_chirho::verify_review_records_chirho(&root_chirho).unwrap(),
        0
    );
    let status_chirho =
        app_chirho::app_status_chirho(&root_chirho, &report_chirho.candidate_chirho.app_chirho)
            .unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.records_chirho, 0);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn direct_governance_promote_rejects_deploy_selection_mismatch_before_append_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = subscription_manifest_chirho(&owner_chirho);
    let report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();

    let unrelated_dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let mut mismatched_manifest_chirho = manifest_chirho.clone();
    mismatched_manifest_chirho.deploy_chirho.routes_chirho[0].source_chirho =
        AppSourceDeploySourceChirho::StoredDagChirho {
            hash_chirho: unrelated_dag_chirho,
        };
    let mismatched_manifest_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &mismatched_manifest_chirho).unwrap();
    let mut forged_report_chirho = report_chirho.clone();
    forged_report_chirho.source_review_report_chirho = None;
    forged_report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_mut()
        .unwrap()
        .effective_manifest_hash_chirho = mismatched_manifest_hash_chirho;
    let forged_hash_chirho =
        put_app_source_review_report_chirho(&root_chirho, &forged_report_chirho).unwrap();

    let error_chirho = review_chirho::promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        &report_chirho.candidate_chirho.app_chirho,
        &owner_chirho,
        report_chirho.candidate_chirho.root_dag_chirho.clone(),
        false,
        false,
        Some(forged_hash_chirho),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("route 'summary-chirho' does not resolve to module DAG"),
        "{error_chirho}"
    );
    assert_eq!(
        review_chirho::verify_review_records_chirho(&root_chirho).unwrap(),
        0
    );
    let status_chirho =
        app_chirho::app_status_chirho(&root_chirho, &report_chirho.candidate_chirho.app_chirho)
            .unwrap();
    assert!(!status_chirho.active_chirho);
    assert_eq!(status_chirho.records_chirho, 0);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn composition_deploy_cannot_authorize_module_nested_declaration_chirho() {
    let root_chirho = tmp_root_chirho();
    let manifest_chirho = subscription_manifest_chirho("owner/composition-chirho");
    let report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    let mut composition_manifest_chirho = manifest_chirho;
    composition_manifest_chirho.deploy_chirho.root_chirho =
        Some(AppSourceDeploySourceChirho::StoredCompositionChirho {
            hash_chirho: HashChirho("f".repeat(64)),
        });
    let composition_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &composition_manifest_chirho).unwrap();
    let mut forged_report_chirho = report_chirho;
    forged_report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .as_mut()
        .unwrap()
        .effective_manifest_hash_chirho = composition_hash_chirho;

    let error_chirho =
        validate_app_source_review_declaration_binding_chirho(&root_chirho, &forged_report_chirho)
            .unwrap_err()
            .to_string();
    assert!(
        error_chirho.contains(
            "composition-sourced deploy cannot authorize a module-nested subscription view"
        ),
        "{error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn direct_governance_promote_signs_exact_reviewed_declarations_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let manifest_chirho = subscription_manifest_chirho(&owner_chirho);
    let report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    let source_review_hash_chirho = report_chirho
        .source_review_report_chirho
        .as_ref()
        .unwrap()
        .clone();
    let record_chirho = review_chirho::promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        &report_chirho.candidate_chirho.app_chirho,
        &owner_chirho,
        report_chirho.candidate_chirho.root_dag_chirho.clone(),
        false,
        false,
        Some(source_review_hash_chirho.clone()),
    )
    .unwrap();
    assert_eq!(
        record_chirho.source_review_report_chirho,
        Some(source_review_hash_chirho)
    );
    assert_eq!(
        review_chirho::verify_review_records_chirho(&root_chirho).unwrap(),
        1
    );
    validate_app_source_review_declaration_binding_chirho(&root_chirho, &report_chirho).unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}
