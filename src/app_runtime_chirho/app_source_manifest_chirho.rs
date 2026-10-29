// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Builds, stages, and deploys source app manifests over existing authoring primitives.

use crate::model_chirho::{HashChirho, NodeDefChirho, PortChirho};
use crate::{
    app_chirho, app_manifest_chirho, cas_chirho, dag_author_chirho, dag_module_chirho,
    publish_chirho, review_chirho, runtime_profile_chirho, store_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_subscription_view_review_chirho as subscription_view_review_chirho;
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionAuthorityPortChirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub use cairn_model_app_chirho::{
    lower_app_source_deploy_manifest_chirho, resolve_app_source_hash_id_chirho,
    resolve_app_source_path_chirho, reviewed_app_source_deploy_manifest_chirho,
    validate_app_source_candidate_report_schema_chirho,
    validate_app_source_deploy_report_schema_chirho, validate_app_source_id_chirho,
    validate_builtin_phi_ports_chirho, AppSourceAssetManifestChirho, AppSourceAssetReportChirho,
    AppSourceAssetSourceChirho, AppSourceCandidateReportChirho,
    AppSourceCandidateRouteReportChirho, AppSourceDagEdgeManifestChirho,
    AppSourceDagManifestChirho, AppSourceDagReportChirho, AppSourceDeployManifestChirho,
    AppSourceDeployReportChirho, AppSourceDeployRouteManifestChirho, AppSourceDeploySourceChirho,
    AppSourceDeployTargetChirho, AppSourceDeployTargetReportChirho, AppSourceManifestChirho,
    AppSourceManifestEvidenceChirho, AppSourceModuleBindingManifestChirho,
    AppSourceModuleManifestChirho, AppSourceModuleRefChirho, AppSourceModuleReportChirho,
    AppSourceNodeManifestChirho, AppSourceNodeReportChirho, AppSourceNodeSourceChirho,
    AppSourcePackageReportChirho, AppSourceReviewReportChirho,
    AppSourceRuntimePackageManifestChirho, AppSourceUndoPlanBindingChirho,
    SubscriptionViewAuthorizationChirho, SubscriptionViewDeclarationChirho,
    SubscriptionViewDeclarationReportChirho, SubscriptionViewDependencyChirho,
    SubscriptionViewDependencyGroupChirho, SubscriptionViewScopeChirho,
    APP_SOURCE_BUILTIN_NODE_TEMPLATE_CHIRHO, APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO,
    APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO, APP_SOURCE_MANIFEST_SCHEMA_CHIRHO,
    APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO,
};
pub use cairn_review_policy_chirho::{
    canonical_app_source_review_report_chirho, validate_app_source_review_report_schema_chirho,
};

const BUILTIN_NODE_TEMPLATE_WAT_CHIRHO: &[u8] =
    include_bytes!("../../examples-chirho/node-template-chirho.wat");

// Projection workflow packet 3 keeps every permissive v1 DTO reader schema-gated at its boundary.
fn require_app_source_manifest_v1_chirho(
    manifest_chirho: AppSourceManifestChirho,
) -> Result<AppSourceManifestChirho> {
    if manifest_chirho.schema_chirho != APP_SOURCE_MANIFEST_SCHEMA_CHIRHO {
        bail!(
            "unsupported app source manifest schema '{}'",
            manifest_chirho.schema_chirho
        );
    }
    Ok(manifest_chirho)
}

#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
#[path = "app_source_manifest_chirho/review_test_hooks_tests_chirho.rs"]
mod review_test_hooks_tests_chirho;

#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub use review_test_hooks_tests_chirho::set_reviewed_asset_install_fail_after_for_test_chirho;
#[path = "app_source_manifest_chirho/prepared_inputs_chirho.rs"]
mod prepared_inputs_chirho;
#[cfg(test)]
#[path = "app_source_manifest_chirho/prepared_inputs_tests_chirho.rs"]
mod prepared_inputs_tests_chirho;
#[cfg(test)]
use prepared_inputs_chirho::cargo_example_artifact_path_chirho;
pub use prepared_inputs_chirho::{
    preflight_app_source_manifest_inputs_chirho,
    preflight_app_source_manifest_inputs_with_captured_node_artifacts_chirho,
    AppSourceCapturedNodeArtifactChirho, AppSourcePreparedInputsChirho,
};
use prepared_inputs_chirho::{
    read_bounded_bytes_chirho, run_cargo_example_build_chirho,
    MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO, MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO,
    MAX_APP_SOURCE_STATIC_ASSET_BYTES_CHIRHO,
};

#[path = "app_source_manifest_chirho/reviewed_install_chirho.rs"]
mod reviewed_install_chirho;
pub use reviewed_install_chirho::{
    install_reviewed_app_source_report_chirho,
    install_reviewed_app_source_report_with_head_transition_authority_chirho,
    reviewed_app_source_install_report_current_chirho, ReviewedAppSourceAssetInstallEvidenceChirho,
    ReviewedAppSourceInstallReportChirho, ReviewedAppSourceRouteInstallEvidenceChirho,
};
#[path = "app_source_manifest_chirho/reviewed_surface_restore_chirho.rs"]
mod reviewed_surface_restore_chirho;
pub use reviewed_surface_restore_chirho::promote_then_install_reviewed_source_chirho;
#[path = "app_source_manifest_chirho/subscription_view_binding_chirho.rs"]
mod subscription_view_binding_chirho;
pub use subscription_view_binding_chirho::validate_app_source_review_declaration_binding_chirho;
use subscription_view_binding_chirho::RootSubscriptionViewReviewPortChirho;
#[path = "app_source_manifest_chirho/undo_plan_binding_chirho.rs"]
mod undo_plan_binding_chirho;
use undo_plan_binding_chirho::{
    bind_new_descriptor_v2_node_chirho, derive_and_store_app_source_undo_plan_bindings_chirho,
    validate_descriptor_v2_node_chirho, verify_new_app_source_candidate_descriptor_v2_chirho,
};
pub use undo_plan_binding_chirho::{
    load_verified_app_source_undo_plan_reviews_chirho, VerifiedAppSourceUndoDoorReviewChirho,
    VerifiedAppSourceUndoPlanReviewChirho, VerifiedAppSourceUndoStepReviewChirho,
};
pub(crate) use undo_plan_binding_chirho::{
    load_verified_app_source_undo_plans_chirho, verify_descriptor_v2_deployment_chirho,
    VerifiedAppSourceUndoPlanChirho,
};

fn reviewed_asset_install_should_fail_chirho(installed_chirho: usize) -> bool {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    {
        review_test_hooks_tests_chirho::reviewed_asset_install_should_fail_chirho(installed_chirho)
    }
    #[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
    {
        let _ = installed_chirho;
        false
    }
}

pub fn deploy_app_source_manifest_from_path_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
) -> Result<AppSourceDeployReportChirho> {
    let (base_chirho, manifest_chirho) =
        load_app_source_manifest_from_path_chirho(manifest_path_chirho)?;
    deploy_app_source_manifest_with_review_label_chirho(
        root_chirho,
        &base_chirho,
        &manifest_chirho,
        false,
    )
}

pub fn load_app_source_review_report_for_promotion_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
    owner_chirho: &str,
    source_review_report_chirho: &HashChirho,
    candidate_chirho: Option<&HashChirho>,
) -> Result<AppSourceReviewReportChirho> {
    let report_chirho: AppSourceReviewReportChirho =
        store_chirho::get_object_chirho(root_chirho, source_review_report_chirho)?;
    validate_app_source_review_report_schema_chirho(&report_chirho)?;
    let canonical_hash_chirho = hash_app_source_review_report_chirho(&report_chirho)?;
    if canonical_hash_chirho != *source_review_report_chirho {
        bail!(
            "source review report hash mismatch: requested {}, canonical {}",
            source_review_report_chirho.0,
            canonical_hash_chirho.0
        );
    }
    validate_reviewed_source_report_for_promotion_chirho(
        root_chirho,
        app_name_chirho,
        owner_chirho,
        &report_chirho,
        candidate_chirho,
    )?;
    Ok(report_chirho)
}

pub fn rollback_reviewed_app_source_report_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<(bool, usize, usize)> {
    let app_name_chirho = &report_chirho.candidate_chirho.app_chirho;
    let mut removed_routes_chirho = 0usize;
    let mut removed_assets_chirho = 0usize;
    for asset_chirho in &report_chirho.candidate_chirho.assets_chirho {
        if app_chirho::remove_app_static_asset_chirho(
            root_chirho,
            app_name_chirho,
            owner_chirho,
            &asset_chirho.name_chirho,
        )? {
            removed_assets_chirho += 1;
        }
    }
    for route_chirho in &report_chirho.candidate_chirho.routes_chirho {
        if app_chirho::undeploy_app_route_chirho(
            root_chirho,
            app_name_chirho,
            &route_chirho.route_chirho,
            owner_chirho,
        )? {
            removed_routes_chirho += 1;
        }
    }
    let removed_app_chirho =
        app_chirho::undeploy_app_chirho(root_chirho, app_name_chirho, owner_chirho)?;
    Ok((
        removed_app_chirho,
        removed_routes_chirho,
        removed_assets_chirho,
    ))
}

pub fn deploy_app_source_manifest_from_path_unreviewed_dev_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
) -> Result<AppSourceDeployReportChirho> {
    let (base_chirho, manifest_chirho) =
        load_app_source_manifest_from_path_chirho(manifest_path_chirho)?;
    deploy_app_source_manifest_with_review_label_chirho(
        root_chirho,
        &base_chirho,
        &manifest_chirho,
        true,
    )
}

pub fn deploy_app_source_manifest_from_path_for_owner_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
    owner_chirho: &str,
) -> Result<AppSourceDeployReportChirho> {
    let (base_chirho, mut manifest_chirho) =
        load_app_source_manifest_from_path_chirho(manifest_path_chirho)?;
    manifest_chirho.owner_chirho = owner_chirho.to_string();
    deploy_app_source_manifest_with_review_label_chirho(
        root_chirho,
        &base_chirho,
        &manifest_chirho,
        false,
    )
}

pub fn deploy_app_source_manifest_from_path_for_owner_unreviewed_dev_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
    owner_chirho: &str,
) -> Result<AppSourceDeployReportChirho> {
    let (base_chirho, mut manifest_chirho) =
        load_app_source_manifest_from_path_chirho(manifest_path_chirho)?;
    manifest_chirho.owner_chirho = owner_chirho.to_string();
    deploy_app_source_manifest_with_review_label_chirho(
        root_chirho,
        &base_chirho,
        &manifest_chirho,
        true,
    )
}

pub fn build_app_source_candidate_from_path_for_owner_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
    owner_chirho: &str,
) -> Result<AppSourceCandidateReportChirho> {
    let (base_chirho, mut manifest_chirho, raw_manifest_hash_chirho) =
        load_app_source_manifest_with_raw_hash_from_path_chirho(
            manifest_path_chirho,
            Some(root_chirho),
        )?;
    manifest_chirho.owner_chirho = owner_chirho.to_string();
    build_app_source_candidate_with_manifest_evidence_chirho(
        root_chirho,
        &base_chirho,
        &manifest_chirho,
        Some(raw_manifest_hash_chirho),
        None,
    )
}

pub fn build_app_source_candidate_from_path_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
) -> Result<AppSourceCandidateReportChirho> {
    let (base_chirho, manifest_chirho, raw_manifest_hash_chirho) =
        load_app_source_manifest_with_raw_hash_from_path_chirho(
            manifest_path_chirho,
            Some(root_chirho),
        )?;
    build_app_source_candidate_with_manifest_evidence_chirho(
        root_chirho,
        &base_chirho,
        &manifest_chirho,
        Some(raw_manifest_hash_chirho),
        None,
    )
}

pub fn build_app_source_review_from_path_for_owner_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
    owner_chirho: &str,
) -> Result<AppSourceReviewReportChirho> {
    let candidate_chirho = build_app_source_candidate_from_path_for_owner_chirho(
        root_chirho,
        manifest_path_chirho,
        owner_chirho,
    )?;
    review_app_source_candidate_chirho(root_chirho, candidate_chirho)
}

pub fn build_app_source_review_from_path_chirho(
    root_chirho: &Path,
    manifest_path_chirho: &Path,
) -> Result<AppSourceReviewReportChirho> {
    let candidate_chirho =
        build_app_source_candidate_from_path_chirho(root_chirho, manifest_path_chirho)?;
    review_app_source_candidate_chirho(root_chirho, candidate_chirho)
}

/// Review an in-memory emitted manifest against an EXPLICIT app-root base, without writing anything
/// into the (possibly checked-in, shared-tree) app source. The exact `manifest_bytes_chirho` (the
/// `tree-build-chirho emit` stdout, before any owner substitution) are bound and stored as the RAW
/// manifest hash; asset/wasm sources resolve against `app_root_base_chirho` (NOT a temp
/// `manifest.parent()`); the reviewed owner is substituted, and the effective (post-substitution)
/// manifest object hash is recorded distinctly. Single-sources the inner candidate+review logic with
/// the path flow via `build_app_source_candidate_with_manifest_evidence_chirho` +
/// `review_app_source_candidate_chirho`, so the two entry points cannot drift.
pub fn build_app_source_review_from_bytes_with_base_for_owner_chirho(
    root_chirho: &Path,
    manifest_bytes_chirho: &[u8],
    app_root_base_chirho: &Path,
    owner_chirho: &str,
) -> Result<AppSourceReviewReportChirho> {
    if manifest_bytes_chirho.len() as u64 > MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO {
        bail!(
            "app source manifest bytes exceed the {} byte bound",
            MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO
        );
    }
    let raw_manifest_hash_chirho = cas_chirho::add_chirho(root_chirho, manifest_bytes_chirho)?;
    let manifest_text_chirho = std::str::from_utf8(manifest_bytes_chirho)
        .context("emitted app source manifest bytes were not valid UTF-8")?;
    let mut manifest_chirho =
        require_app_source_manifest_v1_chirho(serde_json::from_str(manifest_text_chirho)?)?;
    manifest_chirho.owner_chirho = owner_chirho.to_string();
    let candidate_chirho = build_app_source_candidate_with_manifest_evidence_chirho(
        root_chirho,
        app_root_base_chirho,
        &manifest_chirho,
        Some(raw_manifest_hash_chirho),
        None,
    )?;
    review_app_source_candidate_chirho(root_chirho, candidate_chirho)
}

/// The PREPARED-INPUT variant of the review build (#6090): identical law, except every path-backed
/// asset/artifact input comes from the preflight-prepared byte set — the write phase performs ZERO
/// filesystem reads for them, structurally closing the preflight→write TOCTOU for this flow.
pub fn build_app_source_review_from_prepared_bytes_for_owner_chirho(
    root_chirho: &Path,
    manifest_bytes_chirho: &[u8],
    app_root_base_chirho: &Path,
    owner_chirho: &str,
    prepared_chirho: &AppSourcePreparedInputsChirho,
) -> Result<AppSourceReviewReportChirho> {
    // #6102: the prepared set must have been built for EXACTLY these bytes/base — verified
    // BEFORE any root write (including the manifest cas_add below).
    prepared_chirho.verify_binding_chirho(manifest_bytes_chirho, app_root_base_chirho)?;
    if manifest_bytes_chirho.len() as u64 > MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO {
        bail!(
            "app source manifest bytes exceed the {} byte bound",
            MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO
        );
    }
    let raw_manifest_hash_chirho = cas_chirho::add_chirho(root_chirho, manifest_bytes_chirho)?;
    let manifest_text_chirho = std::str::from_utf8(manifest_bytes_chirho)
        .context("emitted app source manifest bytes were not valid UTF-8")?;
    let mut manifest_chirho =
        require_app_source_manifest_v1_chirho(serde_json::from_str(manifest_text_chirho)?)?;
    manifest_chirho.owner_chirho = owner_chirho.to_string();
    let candidate_chirho = build_app_source_candidate_with_manifest_evidence_chirho(
        root_chirho,
        app_root_base_chirho,
        &manifest_chirho,
        Some(raw_manifest_hash_chirho),
        Some(prepared_chirho),
    )?;
    review_app_source_candidate_chirho(root_chirho, candidate_chirho)
}

pub fn build_app_source_review_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
) -> Result<AppSourceReviewReportChirho> {
    let candidate_chirho =
        build_app_source_candidate_chirho(root_chirho, base_chirho, manifest_chirho)?;
    review_app_source_candidate_chirho(root_chirho, candidate_chirho)
}

pub fn review_app_source_candidate_chirho(
    root_chirho: &Path,
    candidate_chirho: AppSourceCandidateReportChirho,
) -> Result<AppSourceReviewReportChirho> {
    verify_new_app_source_candidate_descriptor_v2_chirho(root_chirho, &candidate_chirho)?;
    let review_chirho = review_chirho::review_current_app_candidate_chirho(
        root_chirho,
        &candidate_chirho.app_chirho,
        candidate_chirho.root_dag_chirho.clone(),
    )?;
    let mut report_chirho = AppSourceReviewReportChirho {
        schema_chirho: APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO.to_string(),
        source_review_report_chirho: None,
        candidate_chirho,
        review_chirho,
        non_authoritative_chirho: true,
    };
    report_chirho.source_review_report_chirho = Some(put_app_source_review_report_chirho(
        root_chirho,
        &report_chirho,
    )?);
    Ok(report_chirho)
}

pub fn hash_app_source_review_report_chirho(
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(
        &cairn_review_policy_chirho::canonical_app_source_review_report_chirho(report_chirho),
    )
}

pub fn put_app_source_review_report_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<HashChirho> {
    store_chirho::put_object_chirho(
        root_chirho,
        &canonical_app_source_review_report_chirho(report_chirho),
    )
}

pub fn build_app_source_candidate_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
) -> Result<AppSourceCandidateReportChirho> {
    build_app_source_candidate_with_manifest_evidence_chirho(
        root_chirho,
        base_chirho,
        manifest_chirho,
        None,
        None,
    )
}

fn build_app_source_candidate_with_manifest_evidence_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
    raw_manifest_hash_chirho: Option<HashChirho>,
    prepared_chirho: Option<&AppSourcePreparedInputsChirho>,
) -> Result<AppSourceCandidateReportChirho> {
    let artifacts_chirho = build_app_source_manifest_artifacts_chirho(
        root_chirho,
        base_chirho,
        manifest_chirho,
        prepared_chirho,
    )?;
    let app_manifest_chirho = lower_app_source_deploy_manifest_chirho(
        manifest_chirho,
        &artifacts_chirho.dag_hashes_chirho,
        &artifacts_chirho.module_hashes_chirho,
    )?;
    let root_source_chirho = app_manifest_chirho
        .root_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("source manifest candidate needs a root_chirho"))?;
    let root_dag_chirho = dag_for_deploy_source_chirho(root_chirho, root_source_chirho)?;
    let routes_chirho = app_manifest_chirho
        .routes_chirho
        .iter()
        .map(|route_chirho| {
            Ok(AppSourceCandidateRouteReportChirho {
                route_chirho: route_chirho.route_chirho.clone(),
                dag_chirho: dag_for_deploy_source_chirho(root_chirho, &route_chirho.source_chirho)?,
                input_mode_chirho: route_chirho.input_mode_chirho.clone(),
                request_body_policy_chirho: route_chirho.request_body_policy_chirho.clone(),
                key_access_chirho: route_chirho.key_access_chirho.clone(),
                response_content_type_chirho: route_chirho.response_content_type_chirho.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut executable_dags_chirho = BTreeSet::from([root_dag_chirho.clone()]);
    executable_dags_chirho.extend(
        routes_chirho
            .iter()
            .map(|route_chirho| route_chirho.dag_chirho.clone()),
    );
    let undo_plan_bindings_chirho = derive_and_store_app_source_undo_plan_bindings_chirho(
        root_chirho,
        &executable_dags_chirho,
    )?;
    let candidate_chirho = AppSourceCandidateReportChirho {
        schema_chirho: APP_SOURCE_CANDIDATE_REPORT_SCHEMA_CHIRHO.to_string(),
        source_manifest_chirho: Some(AppSourceManifestEvidenceChirho {
            effective_manifest_hash_chirho: store_chirho::put_object_chirho(
                root_chirho,
                manifest_chirho,
            )?,
            raw_manifest_hash_chirho,
        }),
        app_chirho: manifest_chirho.app_chirho.clone(),
        owner_chirho: manifest_chirho.owner_chirho.clone(),
        request_access_policy_chirho: app_manifest_chirho.request_access_policy_chirho,
        nodes_chirho: artifacts_chirho.node_reports_chirho,
        dags_chirho: artifacts_chirho.dag_reports_chirho,
        modules_chirho: artifacts_chirho.module_reports_chirho,
        assets_chirho: artifacts_chirho.asset_reports_chirho,
        contract_refs_chirho: manifest_chirho.contract_refs_chirho.clone(),
        undo_plan_bindings_chirho: Some(undo_plan_bindings_chirho),
        root_dag_chirho,
        input_mode_chirho: app_manifest_chirho.input_mode_chirho,
        request_body_policy_chirho: app_manifest_chirho.request_body_policy_chirho,
        response_content_type_chirho: app_manifest_chirho.response_content_type_chirho,
        routes_chirho,
    };
    subscription_view_review_chirho::validate_candidate_subscription_view_scopes_chirho(
        &candidate_chirho,
    )?;
    verify_new_app_source_candidate_descriptor_v2_chirho(root_chirho, &candidate_chirho)?;
    Ok(candidate_chirho)
}

pub fn load_app_source_manifest_from_path_chirho(
    manifest_path_chirho: &Path,
) -> Result<(PathBuf, AppSourceManifestChirho)> {
    let (base_chirho, manifest_chirho, _raw_manifest_hash_chirho) =
        load_app_source_manifest_with_raw_hash_from_path_chirho(manifest_path_chirho, None)?;
    Ok((base_chirho, manifest_chirho))
}

fn load_app_source_manifest_with_raw_hash_from_path_chirho(
    manifest_path_chirho: &Path,
    raw_store_root_chirho: Option<&Path>,
) -> Result<(PathBuf, AppSourceManifestChirho, HashChirho)> {
    let manifest_bytes_chirho = read_bounded_bytes_chirho(
        manifest_path_chirho,
        "app source manifest",
        MAX_APP_SOURCE_MANIFEST_BYTES_CHIRHO,
    )?;
    let raw_manifest_hash_chirho = match raw_store_root_chirho {
        Some(root_chirho) => cas_chirho::add_chirho(root_chirho, &manifest_bytes_chirho)?,
        None => cas_chirho::hash_chirho(&manifest_bytes_chirho),
    };
    let manifest_text_chirho = String::from_utf8(manifest_bytes_chirho).with_context(|| {
        format!(
            "app source manifest {} was not valid UTF-8",
            manifest_path_chirho.display()
        )
    })?;
    let manifest_chirho =
        require_app_source_manifest_v1_chirho(serde_json::from_str(&manifest_text_chirho)?)?;
    let base_chirho = manifest_path_chirho
        .parent()
        .filter(|path_chirho| !path_chirho.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok((
        base_chirho.to_path_buf(),
        manifest_chirho,
        raw_manifest_hash_chirho,
    ))
}

pub fn deploy_app_source_manifest_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
) -> Result<AppSourceDeployReportChirho> {
    deploy_app_source_manifest_with_review_label_chirho(
        root_chirho,
        base_chirho,
        manifest_chirho,
        false,
    )
}

pub fn deploy_app_source_manifest_unreviewed_dev_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
) -> Result<AppSourceDeployReportChirho> {
    deploy_app_source_manifest_with_review_label_chirho(
        root_chirho,
        base_chirho,
        manifest_chirho,
        true,
    )
}

fn deploy_app_source_manifest_with_review_label_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
    unreviewed_dev_chirho: bool,
) -> Result<AppSourceDeployReportChirho> {
    let artifacts_chirho = build_app_source_manifest_artifacts_chirho(
        root_chirho,
        base_chirho,
        manifest_chirho,
        None,
    )?;
    let app_manifest_chirho = lower_app_source_deploy_manifest_chirho(
        manifest_chirho,
        &artifacts_chirho.dag_hashes_chirho,
        &artifacts_chirho.module_hashes_chirho,
    )?;
    subscription_view_review_chirho::validate_deploy_subscription_view_scopes_chirho(
        &app_manifest_chirho,
        &artifacts_chirho.module_reports_chirho,
        |source_chirho| dag_for_deploy_source_chirho(root_chirho, source_chirho),
    )?;
    let mut executable_dags_chirho = BTreeSet::new();
    if let Some(root_source_chirho) = &app_manifest_chirho.root_chirho {
        executable_dags_chirho.insert(dag_for_deploy_source_chirho(
            root_chirho,
            root_source_chirho,
        )?);
    }
    for route_chirho in &app_manifest_chirho.routes_chirho {
        executable_dags_chirho.insert(dag_for_deploy_source_chirho(
            root_chirho,
            &route_chirho.source_chirho,
        )?);
    }
    let undo_plan_bindings_chirho = if executable_dags_chirho.is_empty() {
        None
    } else {
        Some(derive_and_store_app_source_undo_plan_bindings_chirho(
            root_chirho,
            &executable_dags_chirho,
        )?)
    };
    let (deploy_report_chirho, package_report_chirho, target_report_chirho) =
        match &manifest_chirho.deploy_chirho.target_chirho {
            AppSourceDeployTargetChirho::LocalDeployChirho => {
                let deploy_report_chirho = match &undo_plan_bindings_chirho {
                    Some(bindings_chirho) => {
                        app_manifest_chirho::deploy_app_manifest_with_descriptor_v2_bindings_chirho(
                            root_chirho,
                            &app_manifest_chirho,
                            bindings_chirho,
                            unreviewed_dev_chirho,
                        )?
                    }
                    None if unreviewed_dev_chirho => {
                        app_manifest_chirho::deploy_app_manifest_unreviewed_dev_chirho(
                            root_chirho,
                            &app_manifest_chirho,
                        )?
                    }
                    None => app_manifest_chirho::deploy_app_manifest_chirho(
                        root_chirho,
                        &app_manifest_chirho,
                    )?,
                };
                deploy_source_assets_chirho(
                    root_chirho,
                    &manifest_chirho.app_chirho,
                    &manifest_chirho.owner_chirho,
                    &artifacts_chirho.asset_reports_chirho,
                )?;
                (
                    Some(deploy_report_chirho),
                    None,
                    AppSourceDeployTargetReportChirho::LocalDeployChirho,
                )
            }
            AppSourceDeployTargetChirho::LocalInstallChirho {
                root_chirho: target_root_chirho,
            } => {
                if !artifacts_chirho.asset_reports_chirho.is_empty() {
                    bail!("app source assets are only supported for local-deploy-chirho in v1");
                }
                let (package_chirho, package_report_chirho) = build_source_publish_package_chirho(
                    root_chirho,
                    &app_manifest_chirho,
                    undo_plan_bindings_chirho
                        .as_deref()
                        .context("source package has no executable DAG undo-plan bindings")?,
                )?;
                let target_root_chirho =
                    resolve_app_source_path_chirho(base_chirho, target_root_chirho);
                let objects_installed_chirho =
                    publish_chirho::install_package_chirho(&target_root_chirho, &package_chirho)?;
                (
                    None,
                    Some(package_report_chirho),
                    AppSourceDeployTargetReportChirho::LocalInstallChirho {
                        root_chirho: target_root_chirho,
                        objects_installed_chirho,
                    },
                )
            }
            AppSourceDeployTargetChirho::HttpPublishChirho {
                server_chirho,
                token_chirho,
            } => {
                if !artifacts_chirho.asset_reports_chirho.is_empty() {
                    bail!("app source assets are only supported for local-deploy-chirho in v1");
                }
                let (package_chirho, package_report_chirho) = build_source_publish_package_chirho(
                    root_chirho,
                    &app_manifest_chirho,
                    undo_plan_bindings_chirho
                        .as_deref()
                        .context("source package has no executable DAG undo-plan bindings")?,
                )?;
                let body_chirho = serde_json::to_string(&package_chirho)?;
                let url_chirho = format!("{}/publish-chirho", server_chirho.trim_end_matches('/'));
                let mut request_chirho =
                    ureq::post(&url_chirho).set("content-type", "application/json");
                if let Some(token_val_chirho) = token_chirho {
                    request_chirho =
                        request_chirho.set("authorization", &format!("Bearer {token_val_chirho}"));
                }
                let response_chirho = request_chirho
                    .send_string(&body_chirho)
                    .map_err(|e_chirho| anyhow!("publish failed: {e_chirho}"))?;
                let status_chirho = response_chirho.status();
                let body_chirho = response_chirho.into_string().unwrap_or_default();
                (
                    None,
                    Some(package_report_chirho),
                    AppSourceDeployTargetReportChirho::HttpPublishChirho {
                        server_chirho: server_chirho.clone(),
                        status_chirho,
                        response_chirho: body_chirho,
                    },
                )
            }
        };

    Ok(AppSourceDeployReportChirho {
        schema_chirho: APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO.to_string(),
        unreviewed_dev_chirho,
        app_chirho: manifest_chirho.app_chirho.clone(),
        owner_chirho: manifest_chirho.owner_chirho.clone(),
        nodes_chirho: artifacts_chirho.node_reports_chirho,
        dags_chirho: artifacts_chirho.dag_reports_chirho,
        modules_chirho: artifacts_chirho.module_reports_chirho,
        assets_chirho: artifacts_chirho.asset_reports_chirho,
        deploy_chirho: deploy_report_chirho,
        package_chirho: package_report_chirho,
        undo_plan_bindings_chirho,
        target_chirho: target_report_chirho,
    })
}

struct AppSourceBuildArtifactsChirho {
    dag_hashes_chirho: BTreeMap<String, HashChirho>,
    module_hashes_chirho: BTreeMap<String, HashChirho>,
    node_reports_chirho: Vec<AppSourceNodeReportChirho>,
    dag_reports_chirho: Vec<AppSourceDagReportChirho>,
    module_reports_chirho: Vec<AppSourceModuleReportChirho>,
    asset_reports_chirho: Vec<AppSourceAssetReportChirho>,
}

fn build_app_source_manifest_artifacts_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    manifest_chirho: &AppSourceManifestChirho,
    prepared_chirho: Option<&AppSourcePreparedInputsChirho>,
) -> Result<AppSourceBuildArtifactsChirho> {
    if manifest_chirho.schema_chirho != APP_SOURCE_MANIFEST_SCHEMA_CHIRHO {
        bail!(
            "unsupported app source manifest schema '{}'",
            manifest_chirho.schema_chirho
        );
    }

    let mut node_ids_chirho = BTreeSet::new();
    for node_chirho in &manifest_chirho.nodes_chirho {
        validate_app_source_id_chirho("node id", &node_chirho.id_chirho)?;
        if !node_ids_chirho.insert(node_chirho.id_chirho.clone()) {
            bail!("duplicate node id '{}'", node_chirho.id_chirho);
        }
    }
    let mut dag_ids_chirho = BTreeSet::new();
    for dag_chirho in &manifest_chirho.dags_chirho {
        validate_app_source_id_chirho("dag id", &dag_chirho.id_chirho)?;
        if !dag_ids_chirho.insert(dag_chirho.id_chirho.clone()) {
            bail!("duplicate dag id '{}'", dag_chirho.id_chirho);
        }
    }
    let mut module_ids_chirho = BTreeSet::new();
    for module_chirho in &manifest_chirho.modules_chirho {
        validate_app_source_id_chirho("module id", &module_chirho.id_chirho)?;
        if !module_ids_chirho.insert(module_chirho.id_chirho.clone()) {
            bail!("duplicate module id '{}'", module_chirho.id_chirho);
        }
    }
    let mut asset_names_chirho = BTreeSet::new();
    for asset_chirho in &manifest_chirho.assets_chirho {
        app_chirho::validate_app_static_asset_name_chirho(&asset_chirho.name_chirho)?;
        if !asset_names_chirho.insert(asset_chirho.name_chirho.clone()) {
            bail!("duplicate asset name '{}'", asset_chirho.name_chirho);
        }
        app_chirho::normalize_app_static_asset_content_type_chirho(
            &asset_chirho.content_type_chirho,
        )?;
    }

    let mut node_hashes_chirho = BTreeMap::new();
    let mut node_reports_chirho = Vec::new();
    for node_chirho in &manifest_chirho.nodes_chirho {
        let node_hash_chirho =
            build_source_node_chirho(root_chirho, base_chirho, node_chirho, prepared_chirho)?;
        node_hashes_chirho.insert(node_chirho.id_chirho.clone(), node_hash_chirho.clone());
        node_reports_chirho.push(AppSourceNodeReportChirho {
            id_chirho: node_chirho.id_chirho.clone(),
            node_chirho: node_hash_chirho,
        });
    }

    let mut dag_hashes_chirho = BTreeMap::new();
    let mut dag_reports_chirho = Vec::new();
    for dag_chirho in &manifest_chirho.dags_chirho {
        let dag_hash_chirho =
            build_source_dag_chirho(root_chirho, dag_chirho, &node_hashes_chirho)?;
        dag_hashes_chirho.insert(dag_chirho.id_chirho.clone(), dag_hash_chirho.clone());
        dag_reports_chirho.push(AppSourceDagReportChirho {
            id_chirho: dag_chirho.id_chirho.clone(),
            dag_chirho: dag_hash_chirho,
        });
    }

    let mut module_hashes_chirho = BTreeMap::new();
    let mut module_reports_chirho = Vec::new();
    let mut subscription_view_ids_chirho = BTreeSet::new();
    for module_chirho in &manifest_chirho.modules_chirho {
        let (module_obj_chirho, module_hash_chirho) = build_source_module_chirho(
            root_chirho,
            module_chirho,
            &dag_hashes_chirho,
            &node_hashes_chirho,
        )?;
        module_hashes_chirho.insert(module_chirho.id_chirho.clone(), module_hash_chirho.clone());
        module_reports_chirho.push(AppSourceModuleReportChirho {
            id_chirho: module_chirho.id_chirho.clone(),
            module_chirho: module_hash_chirho,
            dag_chirho: module_obj_chirho.dag_chirho,
            subscription_views_chirho:
                subscription_view_review_chirho::build_subscription_view_reports_chirho(
                    &RootSubscriptionViewReviewPortChirho(root_chirho),
                    module_chirho,
                    &mut subscription_view_ids_chirho,
                )?,
        });
    }
    let mut asset_reports_chirho = Vec::new();
    for asset_chirho in &manifest_chirho.assets_chirho {
        asset_reports_chirho.push(build_source_asset_chirho(
            root_chirho,
            base_chirho,
            asset_chirho,
            prepared_chirho,
        )?);
    }
    Ok(AppSourceBuildArtifactsChirho {
        dag_hashes_chirho,
        module_hashes_chirho,
        node_reports_chirho,
        dag_reports_chirho,
        module_reports_chirho,
        asset_reports_chirho,
    })
}

fn build_source_publish_package_chirho(
    root_chirho: &Path,
    manifest_chirho: &app_manifest_chirho::AppDeployManifestChirho,
    undo_plan_bindings_chirho: &[AppSourceUndoPlanBindingChirho],
) -> Result<(
    publish_chirho::PublishPackageChirho,
    AppSourcePackageReportChirho,
)> {
    let root_dag_chirho = match &manifest_chirho.root_chirho {
        Some(source_chirho) => dag_for_deploy_source_chirho(root_chirho, source_chirho)?,
        None => bail!("source manifest package targets require a root DAG/module/composition"),
    };
    let runtime_packages_chirho = manifest_chirho
        .runtime_packages_chirho
        .iter()
        .map(|runtime_package_chirho| {
            let profile_chirho = runtime_profile_chirho::parse_runtime_profile_kind_chirho(
                &runtime_package_chirho.profile_chirho,
            )?;
            let (_package_chirho, package_hash_chirho) =
                runtime_profile_chirho::build_runtime_package_chirho(
                    root_chirho,
                    &runtime_package_chirho.module_chirho,
                    profile_chirho,
                )?;
            Ok(package_hash_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    let routes_chirho = manifest_chirho
        .routes_chirho
        .iter()
        .map(|route_chirho| {
            Ok(publish_chirho::PublishRouteChirho {
                route_chirho: route_chirho.route_chirho.clone(),
                dag_chirho: dag_for_deploy_source_chirho(root_chirho, &route_chirho.source_chirho)?
                    .0,
                input_mode_chirho: route_chirho.input_mode_chirho.clone(),
                request_body_policy_chirho: route_chirho.request_body_policy_chirho.clone(),
                response_content_type_chirho: route_chirho.response_content_type_chirho.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut package_chirho = publish_chirho::build_package_with_routes_and_runtime_chirho(
        publish_chirho::PublishPackageWithRoutesAndRuntimeInputChirho {
            root_chirho,
            name_chirho: &manifest_chirho.app_chirho,
            dag_chirho: &root_dag_chirho,
            owner_chirho: &manifest_chirho.owner_chirho,
            input_mode_chirho: manifest_chirho.input_mode_chirho.clone(),
            response_content_type_chirho: manifest_chirho.response_content_type_chirho.clone(),
            routes_chirho: &routes_chirho,
            runtime_packages_chirho: &runtime_packages_chirho,
        },
    )?;
    publish_chirho::attach_descriptor_v2_bindings_chirho(
        root_chirho,
        &mut package_chirho,
        undo_plan_bindings_chirho,
    )?;
    let package_report_chirho = AppSourcePackageReportChirho {
        package_hash_chirho: store_chirho::hash_object_chirho(&package_chirho)?,
        app_chirho: package_chirho.name_chirho.clone(),
        owner_chirho: package_chirho.owner_chirho.clone(),
        dag_chirho: root_dag_chirho,
        runtime_packages_chirho,
        objects_chirho: package_chirho.objects_chirho.len(),
    };
    Ok((package_chirho, package_report_chirho))
}

fn dag_for_deploy_source_chirho(
    root_chirho: &Path,
    source_chirho: &app_manifest_chirho::AppDeployDagSourceChirho,
) -> Result<HashChirho> {
    match source_chirho {
        app_manifest_chirho::AppDeployDagSourceChirho::DagChirho { hash_chirho } => {
            let _dag_chirho: crate::model_chirho::DagChirho =
                store_chirho::get_object_chirho(root_chirho, hash_chirho)?;
            Ok(hash_chirho.clone())
        }
        app_manifest_chirho::AppDeployDagSourceChirho::ModuleChirho { hash_chirho } => {
            let module_chirho =
                dag_module_chirho::validate_stored_dag_module_chirho(root_chirho, hash_chirho)?;
            Ok(module_chirho.dag_chirho)
        }
        app_manifest_chirho::AppDeployDagSourceChirho::CompositionChirho { hash_chirho } => {
            let composition_chirho =
                dag_module_chirho::validate_stored_dag_module_composition_chirho(
                    root_chirho,
                    hash_chirho,
                )?;
            Ok(composition_chirho.composed_dag_chirho)
        }
    }
}

fn validate_reviewed_source_report_for_promotion_chirho(
    root_chirho: &Path,
    app_name_chirho: &str,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
    candidate_chirho: Option<&HashChirho>,
) -> Result<()> {
    verify_new_app_source_candidate_descriptor_v2_chirho(
        root_chirho,
        &report_chirho.candidate_chirho,
    )?;
    validate_app_source_review_declaration_binding_chirho(root_chirho, report_chirho)?;
    subscription_view_review_chirho::validate_reviewed_source_report_request_chirho(
        app_name_chirho,
        owner_chirho,
        report_chirho,
        candidate_chirho,
    )?;
    for asset_chirho in &report_chirho.candidate_chirho.assets_chirho {
        validate_reviewed_source_asset_chirho(root_chirho, asset_chirho)?;
    }
    let bindings_chirho = report_chirho
        .candidate_chirho
        .undo_plan_bindings_chirho
        .as_deref()
        .context("reviewed descriptor-v2 source report has no undo-plan bindings")?;
    app_manifest_chirho::validate_app_deploy_manifest_with_descriptor_v2_bindings_chirho(
        root_chirho,
        &reviewed_app_source_deploy_manifest_chirho(owner_chirho, report_chirho),
        bindings_chirho,
    )
}

fn validate_reviewed_source_asset_chirho(
    root_chirho: &Path,
    asset_chirho: &AppSourceAssetReportChirho,
) -> Result<()> {
    app_chirho::validate_app_static_asset_name_chirho(&asset_chirho.name_chirho)?;
    let content_type_chirho = app_chirho::normalize_app_static_asset_content_type_chirho(
        &asset_chirho.content_type_chirho,
    )?;
    if content_type_chirho != asset_chirho.content_type_chirho {
        bail!(
            "reviewed app static asset '{}' content type is not canonical",
            asset_chirho.name_chirho
        );
    }
    let bytes_chirho = cas_chirho::get_chirho(root_chirho, &asset_chirho.asset_chirho)?;
    if bytes_chirho.len() as u64 != asset_chirho.byte_len_chirho {
        bail!(
            "reviewed app static asset '{}' declared byte_len_chirho {} but CAS has {} bytes",
            asset_chirho.asset_chirho.0,
            asset_chirho.byte_len_chirho,
            bytes_chirho.len()
        );
    }
    Ok(())
}

fn deploy_reviewed_app_manifest_chirho(
    root_chirho: &Path,
    manifest_chirho: &app_manifest_chirho::AppDeployManifestChirho,
    bindings_chirho: &[AppSourceUndoPlanBindingChirho],
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
) -> Result<app_manifest_chirho::AppDeployManifestReportChirho> {
    if manifest_chirho.root_chirho.is_none() && manifest_chirho.routes_chirho.is_empty() {
        return app_manifest_chirho::deploy_app_manifest_chirho(root_chirho, manifest_chirho);
    }
    if let Some(authority_chirho) = authority_chirho {
        app_manifest_chirho::deploy_app_manifest_with_descriptor_v2_bindings_and_head_transition_authority_chirho(
            root_chirho,
            manifest_chirho,
            bindings_chirho,
            authority_chirho,
        )
    } else {
        app_manifest_chirho::deploy_app_manifest_with_descriptor_v2_bindings_chirho(
            root_chirho,
            manifest_chirho,
            bindings_chirho,
            false,
        )
    }
}

fn deploy_source_assets_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    assets_chirho: &[AppSourceAssetReportChirho],
) -> Result<()> {
    for (installed_chirho, asset_chirho) in assets_chirho.iter().enumerate() {
        if reviewed_asset_install_should_fail_chirho(installed_chirho) {
            bail!("injected reviewed asset install failure for test");
        }
        if let Some(selection_chirho) = app_chirho::app_static_asset_by_name_chirho(
            root_chirho,
            app_chirho,
            &asset_chirho.name_chirho,
        )? {
            if selection_chirho.record_chirho.asset_chirho == asset_chirho.asset_chirho
                && selection_chirho.record_chirho.content_type_chirho
                    == asset_chirho.content_type_chirho
                && selection_chirho.record_chirho.byte_len_chirho == asset_chirho.byte_len_chirho
            {
                continue;
            }
        }
        app_chirho::set_app_static_asset_hash_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            &asset_chirho.name_chirho,
            asset_chirho.asset_chirho.clone(),
            &asset_chirho.content_type_chirho,
            asset_chirho.byte_len_chirho,
        )?;
    }
    Ok(())
}

fn build_source_asset_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    asset_chirho: &AppSourceAssetManifestChirho,
    prepared_chirho: Option<&AppSourcePreparedInputsChirho>,
) -> Result<AppSourceAssetReportChirho> {
    let content_type_chirho = app_chirho::normalize_app_static_asset_content_type_chirho(
        &asset_chirho.content_type_chirho,
    )?;
    app_chirho::validate_app_static_asset_name_chirho(&asset_chirho.name_chirho)?;
    let (asset_hash_chirho, byte_len_chirho) = match &asset_chirho.source_chirho {
        AppSourceAssetSourceChirho::PathChirho { path_chirho } => {
            let asset_path_chirho = resolve_app_source_path_chirho(base_chirho, path_chirho);
            let bytes_chirho = match prepared_chirho {
                // Prepared flow (#6090): consume the preflight-read bytes — ZERO filesystem
                // reads here; an input outside the prepared set REFUSES.
                Some(prepared_chirho) => prepared_chirho
                    .get_chirho(&asset_path_chirho)
                    .ok_or_else(|| {
                        anyhow!(
                            "app static asset '{}' is not in the prepared input set",
                            path_chirho.display()
                        )
                    })?
                    .to_vec(),
                None => read_bounded_bytes_chirho(
                    &asset_path_chirho,
                    "app static asset",
                    MAX_APP_SOURCE_STATIC_ASSET_BYTES_CHIRHO,
                )?,
            };
            let asset_hash_chirho = cas_chirho::add_chirho(root_chirho, &bytes_chirho)?;
            (asset_hash_chirho, bytes_chirho.len() as u64)
        }
        AppSourceAssetSourceChirho::StoredAssetChirho {
            hash_chirho,
            byte_len_chirho,
        } => {
            let bytes_chirho = cas_chirho::get_chirho(root_chirho, hash_chirho)?;
            if bytes_chirho.len() as u64 != *byte_len_chirho {
                bail!(
                    "stored app static asset '{}' declared byte_len_chirho {} but CAS has {} bytes",
                    hash_chirho.0,
                    byte_len_chirho,
                    bytes_chirho.len()
                );
            }
            (hash_chirho.clone(), *byte_len_chirho)
        }
    };
    Ok(AppSourceAssetReportChirho {
        name_chirho: asset_chirho.name_chirho.clone(),
        asset_chirho: asset_hash_chirho,
        content_type_chirho,
        byte_len_chirho,
    })
}

fn build_source_node_chirho(
    root_chirho: &Path,
    base_chirho: &Path,
    node_chirho: &AppSourceNodeManifestChirho,
    prepared_chirho: Option<&AppSourcePreparedInputsChirho>,
) -> Result<HashChirho> {
    match &node_chirho.source_chirho {
        AppSourceNodeSourceChirho::StoredNodeChirho { hash_chirho } => {
            let node_def_chirho: NodeDefChirho =
                store_chirho::get_object_chirho(root_chirho, hash_chirho)?;
            validate_descriptor_v2_node_chirho(&node_def_chirho)?;
            Ok(hash_chirho.clone())
        }
        AppSourceNodeSourceChirho::BuiltinNodeTemplateChirho { template_chirho } => {
            if template_chirho != APP_SOURCE_BUILTIN_NODE_TEMPLATE_CHIRHO {
                bail!("unsupported builtin node template '{}'", template_chirho);
            }
            let entry_chirho = node_chirho
                .entry_chirho
                .as_deref()
                .unwrap_or(&node_chirho.name_chirho);
            let (_node_def_chirho, node_hash_chirho) = build_descriptor_v2_bytes_node_def_chirho(
                root_chirho,
                &node_chirho.name_chirho,
                BUILTIN_NODE_TEMPLATE_WAT_CHIRHO,
                entry_chirho,
                node_chirho.fuel_chirho,
                &node_chirho.capabilities_chirho,
            )?;
            Ok(node_hash_chirho)
        }
        AppSourceNodeSourceChirho::PathChirho { path_chirho } => {
            let wasm_path_chirho = resolve_app_source_path_chirho(base_chirho, path_chirho);
            let bytes_chirho = match prepared_chirho {
                Some(prepared_chirho) => prepared_chirho
                    .get_chirho(&wasm_path_chirho)
                    .ok_or_else(|| {
                        anyhow!(
                            "node artifact '{}' is not in the prepared input set",
                            path_chirho.display()
                        )
                    })?
                    .to_vec(),
                None => read_bounded_bytes_chirho(
                    &wasm_path_chirho,
                    "node artifact",
                    MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO,
                )?,
            };
            let entry_chirho = node_chirho
                .entry_chirho
                .as_deref()
                .unwrap_or(&node_chirho.name_chirho);
            let (_node_def_chirho, node_hash_chirho) = build_descriptor_v2_bytes_node_def_chirho(
                root_chirho,
                &node_chirho.name_chirho,
                &bytes_chirho,
                entry_chirho,
                node_chirho.fuel_chirho,
                &node_chirho.capabilities_chirho,
            )?;
            Ok(node_hash_chirho)
        }
        AppSourceNodeSourceChirho::CargoExampleChirho {
            package_chirho,
            example_chirho,
            features_chirho,
            manifest_path_chirho,
            target_chirho,
            artifact_path_chirho,
        } => {
            let bytes_chirho = match prepared_chirho {
                // Prepared flow (#6098-1): the artifact was PREBUILT and captured at read-only
                // preflight — consume those exact bytes; ZERO cargo runs or filesystem reads
                // here, so nothing can change between preflight and write.
                Some(prepared_chirho) => {
                    let artifact_key_chirho =
                        resolve_app_source_path_chirho(base_chirho, artifact_path_chirho);
                    prepared_chirho
                        .get_chirho(&artifact_key_chirho)
                        .ok_or_else(|| {
                            anyhow!(
                                "cargo example artifact for '{}' is not in the prepared input set",
                                example_chirho
                            )
                        })?
                        .to_vec()
                }
                None => {
                    let artifact_chirho = run_cargo_example_build_chirho(
                        base_chirho,
                        package_chirho,
                        example_chirho,
                        features_chirho,
                        manifest_path_chirho.as_deref(),
                        target_chirho.as_deref().unwrap_or("wasm32-unknown-unknown"),
                        artifact_path_chirho,
                    )?;
                    read_bounded_bytes_chirho(
                        &artifact_chirho,
                        "cargo example artifact",
                        MAX_APP_SOURCE_NODE_ARTIFACT_BYTES_CHIRHO,
                    )?
                }
            };
            let entry_chirho = node_chirho
                .entry_chirho
                .as_deref()
                .unwrap_or(&node_chirho.name_chirho);
            let (_node_def_chirho, node_hash_chirho) = build_descriptor_v2_bytes_node_def_chirho(
                root_chirho,
                &node_chirho.name_chirho,
                &bytes_chirho,
                entry_chirho,
                node_chirho.fuel_chirho,
                &node_chirho.capabilities_chirho,
            )?;
            Ok(node_hash_chirho)
        }
        AppSourceNodeSourceChirho::BuiltinPhiChirho {
            input_ports_chirho,
            output_port_chirho,
        } => {
            if !node_chirho.capabilities_chirho.is_empty() {
                bail!(
                    "builtin phi node '{}' cannot declare capabilities",
                    node_chirho.name_chirho
                );
            }
            if let Some(entry_chirho) = &node_chirho.entry_chirho {
                if entry_chirho != crate::model_chirho::BUILTIN_PHI_ENTRY_CHIRHO {
                    bail!(
                        "builtin phi node '{}' must use entry '{}'",
                        node_chirho.name_chirho,
                        crate::model_chirho::BUILTIN_PHI_ENTRY_CHIRHO
                    );
                }
            }
            validate_builtin_phi_ports_chirho(input_ports_chirho, output_port_chirho)?;
            let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes")?;
            let node_def_chirho = crate::model_chirho::builtin_phi_node_def_chirho(
                &node_chirho.name_chirho,
                input_ports_chirho,
                output_port_chirho,
                schema_hash_chirho,
            );
            validate_descriptor_v2_node_chirho(&node_def_chirho)?;
            store_chirho::put_object_chirho(root_chirho, &node_def_chirho)
        }
    }
}

pub fn build_bytes_node_def_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    wasm_chirho: &[u8],
    entry_chirho: &str,
    fuel_chirho: u64,
    capabilities_chirho: &[String],
) -> Result<(NodeDefChirho, HashChirho)> {
    let node_chirho = assemble_bytes_node_def_chirho(
        root_chirho,
        name_chirho,
        wasm_chirho,
        entry_chirho,
        fuel_chirho,
        capabilities_chirho,
    )?;
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho)?;
    Ok((node_chirho, node_hash_chirho))
}

fn build_descriptor_v2_bytes_node_def_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    wasm_chirho: &[u8],
    entry_chirho: &str,
    fuel_chirho: u64,
    capabilities_chirho: &[String],
) -> Result<(NodeDefChirho, HashChirho)> {
    let mut node_chirho = assemble_bytes_node_def_chirho(
        root_chirho,
        name_chirho,
        wasm_chirho,
        entry_chirho,
        fuel_chirho,
        capabilities_chirho,
    )?;
    bind_new_descriptor_v2_node_chirho(&mut node_chirho)?;
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho)?;
    Ok((node_chirho, node_hash_chirho))
}

fn assemble_bytes_node_def_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    wasm_chirho: &[u8],
    entry_chirho: &str,
    fuel_chirho: u64,
    capabilities_chirho: &[String],
) -> Result<NodeDefChirho> {
    let impl_hash_chirho = cas_chirho::add_chirho(root_chirho, wasm_chirho)?;
    let schema_hash_chirho = cas_chirho::add_chirho(root_chirho, b"bytes")?;
    let capabilities_chirho =
        crate::capability_spec_chirho::parse_capabilities_chirho(capabilities_chirho)?;
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: impl_hash_chirho,
        entry_chirho: entry_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho,
        fuel_limit_chirho: fuel_chirho,
        ..Default::default()
    };
    Ok(node_chirho)
}

fn build_source_dag_chirho(
    root_chirho: &Path,
    dag_chirho: &AppSourceDagManifestChirho,
    node_hashes_chirho: &BTreeMap<String, HashChirho>,
) -> Result<HashChirho> {
    let nodes_chirho = dag_chirho
        .nodes_chirho
        .iter()
        .map(|node_chirho| {
            resolve_app_source_hash_id_chirho("node", node_hashes_chirho, node_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    let edges_chirho = dag_chirho
        .edges_chirho
        .iter()
        .map(|edge_chirho| {
            Ok(dag_author_chirho::DagBuildEdgeInputChirho {
                from_node_chirho: resolve_app_source_hash_id_chirho(
                    "edge source node",
                    node_hashes_chirho,
                    &edge_chirho.from_node_chirho,
                )?,
                from_port_chirho: edge_chirho.from_port_chirho.clone(),
                to_node_chirho: resolve_app_source_hash_id_chirho(
                    "edge target node",
                    node_hashes_chirho,
                    &edge_chirho.to_node_chirho,
                )?,
                to_port_chirho: edge_chirho.to_port_chirho.clone(),
                privacy_chirho: edge_chirho.privacy_chirho.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let (_dag_obj_chirho, dag_hash_chirho) = dag_author_chirho::build_dag_chirho(
        root_chirho,
        dag_author_chirho::DagBuildInputChirho {
            nodes_chirho,
            edges_chirho,
        },
    )?;
    Ok(dag_hash_chirho)
}

fn build_source_module_chirho(
    root_chirho: &Path,
    module_chirho: &AppSourceModuleManifestChirho,
    dag_hashes_chirho: &BTreeMap<String, HashChirho>,
    node_hashes_chirho: &BTreeMap<String, HashChirho>,
) -> Result<(crate::model_chirho::DagModuleChirho, HashChirho)> {
    let input_bindings_chirho = module_chirho
        .input_bindings_chirho
        .iter()
        .map(|binding_chirho| source_module_binding_chirho(binding_chirho, node_hashes_chirho))
        .collect::<Result<Vec<_>>>()?;
    let output_bindings_chirho = module_chirho
        .output_bindings_chirho
        .iter()
        .map(|binding_chirho| source_module_binding_chirho(binding_chirho, node_hashes_chirho))
        .collect::<Result<Vec<_>>>()?;
    dag_module_chirho::build_dag_module_chirho(
        root_chirho,
        dag_module_chirho::DagModuleBuildInputChirho {
            name_chirho: module_chirho.name_chirho.clone(),
            dag_chirho: resolve_app_source_hash_id_chirho(
                "dag",
                dag_hashes_chirho,
                &module_chirho.dag_chirho,
            )?,
            version_chirho: module_chirho.version_chirho.clone(),
            previous_module_chirho: module_chirho.previous_module_chirho.clone(),
            input_bindings_chirho,
            output_bindings_chirho,
            route_labels_chirho: module_chirho.route_labels_chirho.clone(),
            metadata_chirho: module_chirho.metadata_chirho.clone(),
        },
    )
}

fn source_module_binding_chirho(
    binding_chirho: &AppSourceModuleBindingManifestChirho,
    node_hashes_chirho: &BTreeMap<String, HashChirho>,
) -> Result<dag_module_chirho::DagModuleBindingInputChirho> {
    Ok(dag_module_chirho::DagModuleBindingInputChirho {
        public_name_chirho: binding_chirho.public_name_chirho.clone(),
        node_chirho: resolve_app_source_hash_id_chirho(
            "binding node",
            node_hashes_chirho,
            &binding_chirho.node_chirho,
        )?,
        node_port_chirho: binding_chirho.node_port_chirho.clone(),
    })
}

#[cfg(test)]
#[path = "app_source_manifest_chirho/phi_tree_end_to_end_tests_chirho.rs"]
mod phi_tree_end_to_end_tests_chirho;
#[cfg(test)]
#[path = "app_source_manifest_chirho/subscription_view_binding_tests_chirho.rs"]
mod subscription_view_binding_tests_chirho;
#[cfg(test)]
#[path = "app_source_manifest_chirho/tests_chirho.rs"]
mod tests_chirho;
#[cfg(test)]
#[path = "app_source_manifest_chirho/undo_plan_binding_tests_chirho.rs"]
mod undo_plan_binding_tests_chirho;
