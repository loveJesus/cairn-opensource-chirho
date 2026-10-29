// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Stored source reviews of a one-node, one-route private-input app, in variants a re-promotion test can tell apart: its
//! assets, its node (which moves the root DAG), and its root response type.

use super::*;

/// What may differ between two reviews of the same app.
pub(super) struct ReviewFixtureVariantChirho {
    /// Each asset's name and bytes, all `text/css`.
    pub(super) assets_chirho: Vec<(&'static str, Vec<u8>)>,
    /// The node's fuel limit. A different value is a different node, so a different root and route DAG.
    pub(super) node_fuel_chirho: u64,
    pub(super) root_response_content_type_chirho: Option<&'static str>,
}

impl ReviewFixtureVariantChirho {
    pub(super) fn one_asset_chirho(asset_bytes_chirho: &[u8]) -> Self {
        ReviewFixtureVariantChirho {
            assets_chirho: vec![("reviewed-source-chirho.css", asset_bytes_chirho.to_vec())],
            node_fuel_chirho: 1_000_000,
            root_response_content_type_chirho: None,
        }
    }
}

pub(super) fn build_private_review_report_for_owner_chirho(
    root_chirho: &std::path::Path,
    app_name_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    subject_chirho: &str,
) -> (
    HashChirho,
    HashChirho,
    app_source_manifest_chirho::AppSourceReviewReportChirho,
) {
    build_private_review_report_for_owner_with_asset_chirho(
        root_chirho,
        app_name_chirho,
        route_chirho,
        owner_chirho,
        subject_chirho,
        b".reviewed-source-chirho{color:#123456}\n",
    )
}

/// The same review, with the bytes of its one asset (`reviewed-source-chirho.css`) chosen by the caller: a second
/// review with other bytes under the SAME name is a re-promotion that changes an asset and keeps its name.
pub(super) fn build_private_review_report_for_owner_with_asset_chirho(
    root_chirho: &std::path::Path,
    app_name_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    subject_chirho: &str,
    asset_bytes_chirho: &[u8],
) -> (
    HashChirho,
    HashChirho,
    app_source_manifest_chirho::AppSourceReviewReportChirho,
) {
    build_private_review_report_variant_chirho(
        root_chirho,
        app_name_chirho,
        route_chirho,
        owner_chirho,
        subject_chirho,
        &ReviewFixtureVariantChirho::one_asset_chirho(asset_bytes_chirho),
    )
}

/// Returns (stored review report hash, candidate root DAG, the review report).
pub(super) fn build_private_review_report_variant_chirho(
    root_chirho: &std::path::Path,
    app_name_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    subject_chirho: &str,
    variant_chirho: &ReviewFixtureVariantChirho,
) -> (
    HashChirho,
    HashChirho,
    app_source_manifest_chirho::AppSourceReviewReportChirho,
) {
    let artifact_chirho = root_chirho.join(format!("{app_name_chirho}-node.wat"));
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let private_mode_chirho = app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
        subject_chirho: subject_chirho.to_string(),
        safe_metadata_chirho: Vec::new(),
    };
    let route_manifest_chirho = app_source_manifest_chirho::AppSourceDeployRouteManifestChirho {
        route_chirho: route_chirho.to_string(),
        source_chirho: app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
            id_chirho: "review_module".to_string(),
        },
        input_mode_chirho: Some(private_mode_chirho.clone()),
        request_body_policy_chirho: None,
        response_content_type_chirho: None,
        params_chirho: None,
        key_access_chirho: None,
    };
    let assets_chirho = variant_chirho
        .assets_chirho
        .iter()
        .map(|(name_chirho, bytes_chirho)| {
            app_source_manifest_chirho::AppSourceAssetManifestChirho {
                name_chirho: name_chirho.to_string(),
                content_type_chirho: "text/css".to_string(),
                source_chirho:
                    app_source_manifest_chirho::AppSourceAssetSourceChirho::StoredAssetChirho {
                        hash_chirho: cas_chirho::add_chirho(root_chirho, bytes_chirho).unwrap(),
                        byte_len_chirho: bytes_chirho.len() as u64,
                    },
            }
        })
        .collect();
    let manifest_chirho = app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_name_chirho.to_string(),
        owner_chirho: owner_chirho.to_string(),
        nodes_chirho: vec![app_source_manifest_chirho::AppSourceNodeManifestChirho {
            id_chirho: "review_node".to_string(),
            name_chirho: "review_node_chirho".to_string(),
            entry_chirho: Some("upcase_chirho".to_string()),
            fuel_chirho: variant_chirho.node_fuel_chirho,
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
        assets_chirho,
        deploy_chirho: app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                app_source_manifest_chirho::AppSourceDeploySourceChirho::ModuleIdChirho {
                    id_chirho: "review_module".to_string(),
                },
            ),
            input_mode_chirho: Some(private_mode_chirho.clone()),
            response_content_type_chirho: variant_chirho
                .root_response_content_type_chirho
                .map(str::to_string),
            params_chirho: None,
            routes_chirho: vec![route_manifest_chirho],
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
