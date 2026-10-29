// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Security regressions for exact-evidence Subscribe witnesses.

use super::*;
use cairn_chirho::app_chirho;
use cairn_chirho::app_source_manifest_chirho::{
    build_app_source_review_chirho, AppSourceDagManifestChirho, AppSourceDeployManifestChirho,
    AppSourceDeployRouteManifestChirho, AppSourceDeploySourceChirho, AppSourceDeployTargetChirho,
    AppSourceManifestChirho, AppSourceModuleBindingManifestChirho, AppSourceModuleManifestChirho,
    AppSourceNodeManifestChirho, AppSourceNodeSourceChirho, SubscriptionViewDeclarationChirho,
    SubscriptionViewDependencyChirho, SubscriptionViewDependencyGroupChirho,
    APP_SOURCE_MANIFEST_SCHEMA_CHIRHO,
};
use cairn_chirho::identity_chirho::{self, PrincipalKindChirho};
use cairn_chirho::model_chirho::{DagChirho, HashChirho};
use cairn_chirho::{refs_chirho, review_chirho, store_chirho};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const APP_CHIRHO: &str = "subscription-witness-app-chirho";
pub(super) const ROOT_VIEW_CHIRHO: &str = "owner-root-summary-chirho";
pub(super) const ROUTE_VIEW_CHIRHO: &str = "owner-route-summary-chirho";
pub(super) const ROUTE_CHIRHO: &str = "summary-chirho";

pub(super) struct WitnessFixtureChirho {
    pub(super) root_chirho: PathBuf,
    pub(super) owner_chirho: String,
    pub(super) manifest_chirho: AppSourceManifestChirho,
    pub(super) app_dag_chirho: HashChirho,
}

pub(super) fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-subscription-control-plane-{nanos_chirho}-{n_chirho}"
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

pub(super) fn subscription_manifest_chirho(owner_chirho: &str) -> AppSourceManifestChirho {
    AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: APP_CHIRHO.to_string(),
        owner_chirho: owner_chirho.to_string(),
        nodes_chirho: vec![AppSourceNodeManifestChirho {
            id_chirho: "render-node-chirho".to_string(),
            name_chirho: "render-node-chirho".to_string(),
            entry_chirho: None,
            fuel_chirho: 0,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::BuiltinPhiChirho {
                input_ports_chirho: vec!["ledger-chirho".to_string(), "holds-chirho".to_string()],
                output_port_chirho: "rendered-chirho".to_string(),
            },
        }],
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "render-dag-chirho".to_string(),
            nodes_chirho: vec!["render-node-chirho".to_string()],
            edges_chirho: Vec::new(),
        }],
        modules_chirho: vec![AppSourceModuleManifestChirho {
            id_chirho: "render-module-chirho".to_string(),
            dag_chirho: "render-dag-chirho".to_string(),
            name_chirho: "render-module-chirho".to_string(),
            version_chirho: "v1".to_string(),
            previous_module_chirho: None,
            input_bindings_chirho: vec![
                AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "ledger-chirho".to_string(),
                    node_chirho: "render-node-chirho".to_string(),
                    node_port_chirho: "ledger-chirho".to_string(),
                },
                AppSourceModuleBindingManifestChirho {
                    public_name_chirho: "holds-chirho".to_string(),
                    node_chirho: "render-node-chirho".to_string(),
                    node_port_chirho: "holds-chirho".to_string(),
                },
            ],
            output_bindings_chirho: vec![AppSourceModuleBindingManifestChirho {
                public_name_chirho: "rendered-chirho".to_string(),
                node_chirho: "render-node-chirho".to_string(),
                node_port_chirho: "rendered-chirho".to_string(),
            }],
            route_labels_chirho: vec![ROUTE_CHIRHO.to_string()],
            metadata_chirho: BTreeMap::new(),
            subscription_views_chirho: vec![
                SubscriptionViewDeclarationChirho {
                    view_chirho: ROOT_VIEW_CHIRHO.to_string(),
                    scope_chirho: SubscriptionViewScopeChirho::AppRootChirho,
                    authorization_chirho: SubscriptionViewAuthorizationChirho::OwnerOnlyChirho,
                    dependencies_chirho: vec![dependency_chirho(
                        "ledger-chirho",
                        SubscriptionViewDependencyGroupChirho::LedgerChirho,
                    )],
                },
                SubscriptionViewDeclarationChirho {
                    view_chirho: ROUTE_VIEW_CHIRHO.to_string(),
                    scope_chirho: SubscriptionViewScopeChirho::RouteChirho {
                        route_chirho: ROUTE_CHIRHO.to_string(),
                    },
                    authorization_chirho: SubscriptionViewAuthorizationChirho::OwnerOnlyChirho,
                    dependencies_chirho: vec![dependency_chirho(
                        "holds-chirho",
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
                id_chirho: "render-module-chirho".to_string(),
            }),
            input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
            response_content_type_chirho: Some("text/html".to_string()),
            params_chirho: None,
            routes_chirho: vec![AppSourceDeployRouteManifestChirho {
                route_chirho: ROUTE_CHIRHO.to_string(),
                source_chirho: AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "render-module-chirho".to_string(),
                },
                input_mode_chirho: Some(app_chirho::AppInputModeChirho::PlainChirho),
                response_content_type_chirho: Some("text/html".to_string()),
                params_chirho: None,
                request_body_policy_chirho: None,
                key_access_chirho: None,
            }],
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    }
}

pub(super) fn promote_manifest_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    manifest_chirho: &AppSourceManifestChirho,
) -> HashChirho {
    let report_chirho =
        build_app_source_review_chirho(root_chirho, Path::new("."), manifest_chirho).unwrap();
    let source_review_report_chirho = report_chirho.source_review_report_chirho.clone().unwrap();
    let app_dag_chirho = report_chirho.candidate_chirho.root_dag_chirho.clone();
    review_chirho::promote_candidate_with_source_review_report_chirho(
        root_chirho,
        APP_CHIRHO,
        owner_chirho,
        app_dag_chirho.clone(),
        false,
        false,
        Some(source_review_report_chirho),
    )
    .unwrap();
    let route_dag_chirho = report_chirho
        .candidate_chirho
        .routes_chirho
        .iter()
        .find(|route_chirho| route_chirho.route_chirho == ROUTE_CHIRHO)
        .unwrap()
        .dag_chirho
        .clone();
    app_chirho::deploy_app_route_chirho(
        root_chirho,
        APP_CHIRHO,
        ROUTE_CHIRHO,
        route_dag_chirho,
        owner_chirho,
    )
    .unwrap();
    app_dag_chirho
}

pub(super) fn seed_fixture_chirho() -> WitnessFixtureChirho {
    let root_chirho = tmp_root_chirho();
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let manifest_chirho = subscription_manifest_chirho(&owner_chirho);
    let app_dag_chirho = promote_manifest_chirho(&root_chirho, &owner_chirho, &manifest_chirho);
    WitnessFixtureChirho {
        root_chirho,
        owner_chirho,
        manifest_chirho,
        app_dag_chirho,
    }
}

pub(super) fn verified_witness_chirho(
    outcome_chirho: SubscriptionControlPlaneWitnessOutcomeChirho,
) -> Box<VerifiedSubscriptionControlPlaneWitnessChirho> {
    match outcome_chirho {
        SubscriptionControlPlaneWitnessOutcomeChirho::VerifiedChirho(witness_chirho) => {
            witness_chirho
        }
        SubscriptionControlPlaneWitnessOutcomeChirho::ResnapshotRequiredChirho => {
            panic!("expected verified current-control-plane witness")
        }
    }
}

fn derived_digests_chirho(
    witness_chirho: &VerifiedSubscriptionControlPlaneWitnessChirho,
) -> Box<SubscriptionBindingDigestsChirho> {
    match derive_subscription_binding_digests_chirho(witness_chirho) {
        SubscriptionBindingDigestOutcomeChirho::DerivedChirho(digests_chirho) => digests_chirho,
        SubscriptionBindingDigestOutcomeChirho::ResnapshotRequiredChirho => {
            panic!("expected derived subscription binding digests")
        }
    }
}

fn assert_resnapshot_chirho(outcome_chirho: SubscriptionControlPlaneWitnessOutcomeChirho) {
    assert!(matches!(
        outcome_chirho,
        SubscriptionControlPlaneWitnessOutcomeChirho::ResnapshotRequiredChirho
    ));
}

pub(super) fn snapshot_tree_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk_chirho(
        root_chirho: &Path,
        current_chirho: &Path,
        snapshot_chirho: &mut BTreeMap<PathBuf, Vec<u8>>,
    ) {
        let mut entries_chirho = std::fs::read_dir(current_chirho)
            .unwrap()
            .map(|entry_chirho| entry_chirho.unwrap().path())
            .collect::<Vec<_>>();
        entries_chirho.sort();
        for path_chirho in entries_chirho {
            if path_chirho.is_dir() {
                walk_chirho(root_chirho, &path_chirho, snapshot_chirho);
            } else {
                snapshot_chirho.insert(
                    path_chirho.strip_prefix(root_chirho).unwrap().to_path_buf(),
                    std::fs::read(path_chirho).unwrap(),
                );
            }
        }
    }

    let mut snapshot_chirho = BTreeMap::new();
    walk_chirho(root_chirho, root_chirho, &mut snapshot_chirho);
    snapshot_chirho
}

fn tamper_last_signature_chirho(path_chirho: &Path) {
    let mut text_chirho = std::fs::read_to_string(path_chirho).unwrap();
    let marker_chirho = "\"sig_chirho\":\"";
    let marker_start_chirho = text_chirho.rfind(marker_chirho).unwrap();
    let sig_start_chirho = marker_start_chirho + marker_chirho.len();
    let replacement_chirho = if &text_chirho[sig_start_chirho..sig_start_chirho + 1] == "0" {
        "1"
    } else {
        "0"
    };
    text_chirho.replace_range(sig_start_chirho..sig_start_chirho + 1, replacement_chirho);
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn remove_app_transition_receipt_chirho(root_chirho: &Path) {
    let transition_id_chirho = app_chirho::verified_app_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .rev()
        .find(|record_chirho| record_chirho.app_chirho == APP_CHIRHO)
        .unwrap()
        .transition_id_chirho;
    assert!(!transition_id_chirho.is_empty());
    let mut reflog_chirho = refs_chirho::reflog_chirho(root_chirho).unwrap();
    let before_chirho = reflog_chirho.len();
    reflog_chirho.retain(|entry_chirho| entry_chirho.transition_id_chirho != transition_id_chirho);
    assert_eq!(reflog_chirho.len() + 1, before_chirho);
    let mut text_chirho = String::new();
    for entry_chirho in reflog_chirho {
        text_chirho.push_str(&serde_json::to_string(&entry_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(refs_chirho::reflog_path_chirho(root_chirho), text_chirho).unwrap();
}

fn remove_route_transition_receipt_chirho(root_chirho: &Path) {
    let transition_id_chirho = app_chirho::verified_app_route_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == APP_CHIRHO && record_chirho.route_chirho == ROUTE_CHIRHO
        })
        .unwrap()
        .transition_id_chirho;
    assert!(!transition_id_chirho.is_empty());
    let mut reflog_chirho = refs_chirho::reflog_chirho(root_chirho).unwrap();
    let before_chirho = reflog_chirho.len();
    reflog_chirho.retain(|entry_chirho| entry_chirho.transition_id_chirho != transition_id_chirho);
    assert_eq!(reflog_chirho.len() + 1, before_chirho);
    let text_chirho = reflog_chirho
        .into_iter()
        .map(|entry_chirho| serde_json::to_string(&entry_chirho).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(refs_chirho::reflog_path_chirho(root_chirho), text_chirho).unwrap();
}

#[test]
fn root_and_route_witnesses_mint_from_exact_current_evidence_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let root_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    assert!(root_witness_chirho.route_record_chirho.is_none());
    assert_eq!(
        root_witness_chirho.declaration_chirho.view_chirho,
        ROOT_VIEW_CHIRHO
    );
    assert_eq!(
        root_witness_chirho.app_record_chirho.seq_chirho,
        root_witness_chirho
            .review_record_chirho
            .app_record_seq_chirho
            .unwrap()
    );

    let route_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::RouteChirho {
                route_chirho: ROUTE_CHIRHO.to_string(),
            },
            ROUTE_VIEW_CHIRHO,
        ));
    assert_eq!(
        route_witness_chirho
            .route_record_chirho
            .as_ref()
            .unwrap()
            .route_chirho,
        ROUTE_CHIRHO
    );
    assert_eq!(
        route_witness_chirho.declaration_chirho.view_chirho,
        ROUTE_VIEW_CHIRHO
    );
    let root_digests_chirho = derived_digests_chirho(&root_witness_chirho);
    let route_digests_chirho = derived_digests_chirho(&route_witness_chirho);
    assert!(!root_digests_chirho.subscription_generation_matches_chirho(&route_digests_chirho));
    assert!(!root_digests_chirho.authorization_binding_matches_chirho(&route_digests_chirho));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn unreceipted_current_app_returns_generic_resnapshot_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    remove_app_transition_receipt_chirho(&fixture_chirho.root_chirho);
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn unreceipted_current_route_returns_generic_resnapshot_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    remove_route_transition_receipt_chirho(&fixture_chirho.root_chirho);
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::RouteChirho {
            route_chirho: ROUTE_CHIRHO.to_string(),
        },
        ROUTE_VIEW_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn witness_mint_is_deterministic_and_byte_unchanged_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let first_chirho = verified_witness_chirho(current_subscription_control_plane_witness_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
    ));
    let second_chirho = verified_witness_chirho(current_subscription_control_plane_witness_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
    ));
    assert_eq!(
        first_chirho.app_record_chirho.seq_chirho,
        second_chirho.app_record_chirho.seq_chirho
    );
    assert_eq!(
        first_chirho.review_record_chirho.seq_chirho,
        second_chirho.review_record_chirho.seq_chirho
    );
    assert_eq!(
        first_chirho.source_review_report_hash_chirho,
        second_chirho.source_review_report_hash_chirho
    );
    assert_eq!(
        first_chirho.declaration_chirho.declaration_chirho,
        second_chirho.declaration_chirho.declaration_chirho
    );
    let first_digests_chirho = derived_digests_chirho(&first_chirho);
    let second_digests_chirho = derived_digests_chirho(&second_chirho);
    assert!(first_digests_chirho.subscription_generation_matches_chirho(&second_digests_chirho));
    assert!(first_digests_chirho.control_plane_evidence_matches_chirho(&second_digests_chirho));
    assert!(first_digests_chirho.authorization_binding_matches_chirho(&second_digests_chirho));
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn all_validation_failures_share_one_resnapshot_outcome_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &fixture_chirho.root_chirho,
        "owner/not-current-chirho",
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
    ));
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        "missing-view-chirho",
    ));
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::RouteChirho {
            route_chirho: "missing-route-chirho".to_string(),
        },
        ROUTE_VIEW_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);

    for log_chirho in [
        "app-records-chirho.jsonl",
        "app-route-records-chirho.jsonl",
        "review-records-chirho.jsonl",
    ] {
        let tampered_fixture_chirho = seed_fixture_chirho();
        tamper_last_signature_chirho(&tampered_fixture_chirho.root_chirho.join(log_chirho));
        assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
            &tampered_fixture_chirho.root_chirho,
            &tampered_fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::RouteChirho {
                route_chirho: ROUTE_CHIRHO.to_string(),
            },
            ROUTE_VIEW_CHIRHO,
        ));
        let _ = std::fs::remove_dir_all(tampered_fixture_chirho.root_chirho);
    }
}

#[test]
fn reviewed_ref_rollback_mints_current_historical_evidence_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let original_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    let original_digests_chirho = derived_digests_chirho(&original_witness_chirho);
    let mut replacement_manifest_chirho = fixture_chirho.manifest_chirho.clone();
    replacement_manifest_chirho.nodes_chirho[0].name_chirho =
        "replacement-render-node-chirho".to_string();
    let replacement_dag_chirho = promote_manifest_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        &replacement_manifest_chirho,
    );
    assert_ne!(replacement_dag_chirho, fixture_chirho.app_dag_chirho);
    let replacement_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    let replacement_digests_chirho = derived_digests_chirho(&replacement_witness_chirho);
    assert!(!original_digests_chirho
        .subscription_generation_matches_chirho(&replacement_digests_chirho));
    assert!(
        !original_digests_chirho.authorization_binding_matches_chirho(&replacement_digests_chirho)
    );
    refs_chirho::set_branch_chirho(
        &fixture_chirho.root_chirho,
        &format!("app/{APP_CHIRHO}"),
        fixture_chirho.app_dag_chirho.clone(),
    )
    .unwrap();

    let witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    assert_eq!(
        witness_chirho.app_record_chirho.dag_chirho.as_ref(),
        Some(&fixture_chirho.app_dag_chirho)
    );
    assert_eq!(
        witness_chirho.review_record_chirho.candidate_chirho,
        fixture_chirho.app_dag_chirho
    );
    let rollback_digests_chirho = derived_digests_chirho(&witness_chirho);
    assert!(
        original_digests_chirho.subscription_generation_matches_chirho(&rollback_digests_chirho)
    );
    assert!(original_digests_chirho.control_plane_evidence_matches_chirho(&rollback_digests_chirho));
    assert!(original_digests_chirho.authorization_binding_matches_chirho(&rollback_digests_chirho));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn reviewed_declaration_change_rotates_generation_without_dag_change_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let original_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    let original_digests_chirho = derived_digests_chirho(&original_witness_chirho);
    let mut changed_manifest_chirho = fixture_chirho.manifest_chirho.clone();
    changed_manifest_chirho.modules_chirho[0].subscription_views_chirho[0].dependencies_chirho =
        vec![dependency_chirho(
            "holds-chirho",
            SubscriptionViewDependencyGroupChirho::HoldsChirho,
        )];
    let unchanged_dag_chirho = promote_manifest_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        &changed_manifest_chirho,
    );
    assert_eq!(unchanged_dag_chirho, fixture_chirho.app_dag_chirho);

    let changed_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    let changed_digests_chirho = derived_digests_chirho(&changed_witness_chirho);
    assert!(
        !original_digests_chirho.subscription_generation_matches_chirho(&changed_digests_chirho)
    );
    assert!(!original_digests_chirho.authorization_binding_matches_chirho(&changed_digests_chirho));
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn byte_identical_repromote_keeps_generation_and_rotates_exact_evidence_chirho() {
    let fixture_chirho = seed_fixture_chirho();
    let original_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    let original_digests_chirho = derived_digests_chirho(&original_witness_chirho);
    let same_dag_chirho = promote_manifest_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.owner_chirho,
        &fixture_chirho.manifest_chirho,
    );
    assert_eq!(same_dag_chirho, fixture_chirho.app_dag_chirho);

    let repromoted_witness_chirho =
        verified_witness_chirho(current_subscription_control_plane_witness_chirho(
            &fixture_chirho.root_chirho,
            &fixture_chirho.owner_chirho,
            APP_CHIRHO,
            &SubscriptionViewTargetChirho::AppRootChirho,
            ROOT_VIEW_CHIRHO,
        ));
    let repromoted_digests_chirho = derived_digests_chirho(&repromoted_witness_chirho);
    assert!(
        original_digests_chirho.subscription_generation_matches_chirho(&repromoted_digests_chirho)
    );
    assert!(
        !original_digests_chirho.control_plane_evidence_matches_chirho(&repromoted_digests_chirho)
    );
    assert!(
        !original_digests_chirho.authorization_binding_matches_chirho(&repromoted_digests_chirho)
    );
    let _ = std::fs::remove_dir_all(fixture_chirho.root_chirho);
}

#[test]
fn stale_reviewed_promote_cannot_mint_for_current_unreviewed_deploy_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap()
            .principal_chirho;
    let direct_dag_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(
        &root_chirho,
        APP_CHIRHO,
        direct_dag_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    let reviewed_dag_chirho = promote_manifest_chirho(
        &root_chirho,
        &owner_chirho,
        &subscription_manifest_chirho(&owner_chirho),
    );
    assert_ne!(reviewed_dag_chirho, direct_dag_chirho);
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &format!("app/{APP_CHIRHO}"),
        direct_dag_chirho,
    )
    .unwrap();

    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &root_chirho,
        &owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn undeploy_route_removal_and_empty_roots_fail_closed_chirho() {
    let route_fixture_chirho = seed_fixture_chirho();
    app_chirho::undeploy_app_route_chirho(
        &route_fixture_chirho.root_chirho,
        APP_CHIRHO,
        ROUTE_CHIRHO,
        &route_fixture_chirho.owner_chirho,
    )
    .unwrap();
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &route_fixture_chirho.root_chirho,
        &route_fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::RouteChirho {
            route_chirho: ROUTE_CHIRHO.to_string(),
        },
        ROUTE_VIEW_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(route_fixture_chirho.root_chirho);

    let app_fixture_chirho = seed_fixture_chirho();
    app_chirho::undeploy_app_chirho(
        &app_fixture_chirho.root_chirho,
        APP_CHIRHO,
        &app_fixture_chirho.owner_chirho,
    )
    .unwrap();
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &app_fixture_chirho.root_chirho,
        &app_fixture_chirho.owner_chirho,
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(app_fixture_chirho.root_chirho);

    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    assert_resnapshot_chirho(current_subscription_control_plane_witness_chirho(
        &root_chirho,
        "owner/absent-chirho",
        APP_CHIRHO,
        &SubscriptionViewTargetChirho::AppRootChirho,
        ROOT_VIEW_CHIRHO,
    ));
    let _ = std::fs::remove_dir_all(root_chirho);
}
