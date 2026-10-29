// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{app_chirho, app_source_manifest_chirho, identity_chirho, review_chirho};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-cli-review-fast-path-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

fn build_source_review_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> (
    HashChirho,
    HashChirho,
    app_source_manifest_chirho::AppSourceReviewReportChirho,
) {
    let artifact_chirho = root_chirho.join(format!("{app_chirho}-node.wat"));
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let input_mode_chirho = app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
        subject_chirho: format!("app/{app_chirho}/input"),
        safe_metadata_chirho: Vec::new(),
    };
    let route_chirho = "preview-chirho";
    let manifest_chirho = app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_chirho: owner_chirho.to_string(),
        nodes_chirho: vec![app_source_manifest_chirho::AppSourceNodeManifestChirho {
            id_chirho: "review_node".to_string(),
            name_chirho: "review_node_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: Vec::new(),
            source_chirho: app_source_manifest_chirho::AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho,
            },
        }],
        contract_refs_chirho: Vec::new(),
        dags_chirho: vec![app_source_manifest_chirho::AppSourceDagManifestChirho {
            id_chirho: "review_dag".to_string(),
            nodes_chirho: vec!["review_node".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: vec![app_source_manifest_chirho::AppSourceModuleManifestChirho {
            id_chirho: "review_module".to_string(),
            dag_chirho: "review_dag".to_string(),
            name_chirho: "review_module_chirho".to_string(),
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "request_chirho".to_string(),
                    node_chirho: "review_node".to_string(),
                    node_port_chirho: "in".to_string(),
                },
            ],
            output_bindings_chirho: vec![
                app_source_manifest_chirho::AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "response_chirho".to_string(),
                    node_chirho: "review_node".to_string(),
                    node_port_chirho: "out".to_string(),
                },
            ],
            route_labels_chirho: vec![route_chirho.to_string()],
            metadata_chirho: std::collections::BTreeMap::new(),
            subscription_views_chirho: Vec::new(),
        }],
        assets_chirho: Vec::new(),
        deploy_chirho: app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "review_module".to_string(),
                },
            ),
            input_mode_chirho: Some(input_mode_chirho.clone()),
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![
                app_source_manifest_chirho::AppSourceDeployRouteManifestChirho {
                    route_chirho: route_chirho.to_string(),
                    source_chirho:
                        app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                            id_chirho: "review_module".to_string(),
                        },
                    input_mode_chirho: Some(input_mode_chirho),
                    request_body_policy_chirho: None,
                    response_content_type_chirho: None,
                    params_chirho: None,
                    key_access_chirho: None,
                },
            ],
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let report_chirho = app_source_manifest_chirho::build_app_source_review_chirho(
        root_chirho,
        root_chirho,
        &manifest_chirho,
    )
    .unwrap();
    (
        report_chirho.source_review_report_chirho.clone().unwrap(),
        report_chirho.candidate_chirho.root_dag_chirho.clone(),
        report_chirho,
    )
}

#[test]
fn review_promote_cli_reject_record_does_not_unlock_exact_current_fast_path_chirho() {
    let root_chirho = temp_root_chirho("reject-record");
    let owner_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner-cli-review-secret",
    )
    .unwrap();
    let app_chirho = "cli-review-fast-path-app-chirho";
    let (_initial_report_hash_chirho, _initial_candidate_chirho, install_report_chirho) =
        build_source_review_chirho(&root_chirho, app_chirho, &owner_chirho.principal_chirho);
    app_source_manifest_chirho::install_reviewed_app_source_report_chirho(
        &root_chirho,
        &owner_chirho.principal_chirho,
        &install_report_chirho,
    )
    .unwrap();
    let (source_review_report_chirho, candidate_chirho, _current_report_chirho) =
        build_source_review_chirho(&root_chirho, app_chirho, &owner_chirho.principal_chirho);
    review_chirho::reject_candidate_with_source_review_report_chirho(
        &root_chirho,
        app_chirho,
        &owner_chirho.principal_chirho,
        candidate_chirho.clone(),
        "reject evidence must not authorize CLI retry fast path",
        Some(source_review_report_chirho.clone()),
    )
    .unwrap();

    let output_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-chirho"))
        .args([
            "--root",
            root_chirho.to_str().unwrap(),
            "review-promote",
            "--app",
            app_chirho,
            "--owner",
            &owner_chirho.principal_chirho,
            "--candidate",
            &candidate_chirho.0,
            "--source-review-report",
            &source_review_report_chirho.0,
        ])
        .output()
        .unwrap();
    assert!(
        output_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(stdout_chirho.contains("review #1 promoted"));
    assert!(!stdout_chirho.contains("already promoted"));

    let records_chirho = review_chirho::load_review_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 2);
    assert!(matches!(
        records_chirho[0].decision_chirho,
        review_chirho::ReviewDecisionChirho::RejectChirho
    ));
    assert!(matches!(
        records_chirho[1].decision_chirho,
        review_chirho::ReviewDecisionChirho::PromoteChirho
    ));
    assert_eq!(
        records_chirho[1].source_review_report_chirho.as_ref(),
        Some(&source_review_report_chirho)
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}
