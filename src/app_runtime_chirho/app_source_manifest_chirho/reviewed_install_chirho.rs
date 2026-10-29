// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Reviewed source app installation parity over existing signed app surfaces.
//!
//! A later rejection does not revoke an already-completed promotion; revocation is
//! rollback/undeploy moving refs, while review records gate promotion attempts.
//!
//! An install that fails puts back the surface it found (`reviewed_surface_restore_chirho`): nothing for a first
//! install, the live prior version for a re-promotion. It used to remove the whole app, which darkened a live app
//! (PFE #25681).

use super::reviewed_surface_restore_chirho::{
    capture_app_live_surface_chirho, restore_after_failure_chirho,
};
use super::{
    deploy_reviewed_app_manifest_chirho, deploy_source_assets_chirho,
    validate_reviewed_source_report_for_promotion_chirho,
};
use crate::app_chirho;
use crate::model_chirho::HashChirho;
use anyhow::{anyhow, bail, Result};
use cairn_model_app_chirho::{
    reviewed_app_source_deploy_manifest_chirho, AppSourceAssetReportChirho,
    AppSourceReviewReportChirho,
};
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionAuthorityPortChirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedAppSourceRouteInstallEvidenceChirho {
    pub route_chirho: String,
    pub dag_chirho: HashChirho,
    pub route_record_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedAppSourceAssetInstallEvidenceChirho {
    pub name_chirho: String,
    pub asset_chirho: HashChirho,
    pub content_type_chirho: String,
    pub byte_len_chirho: u64,
    pub static_asset_record_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewedAppSourceInstallReportChirho {
    pub route_count_chirho: usize,
    pub asset_count_chirho: usize,
    pub routes_chirho: Vec<ReviewedAppSourceRouteInstallEvidenceChirho>,
    pub assets_chirho: Vec<ReviewedAppSourceAssetInstallEvidenceChirho>,
    pub already_current_chirho: bool,
}

pub fn install_reviewed_app_source_report_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<ReviewedAppSourceInstallReportChirho> {
    install_reviewed_app_source_report_with_authority_chirho(
        root_chirho,
        owner_chirho,
        report_chirho,
        None,
    )
}

pub fn install_reviewed_app_source_report_with_head_transition_authority_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<ReviewedAppSourceInstallReportChirho> {
    install_reviewed_app_source_report_with_authority_chirho(
        root_chirho,
        owner_chirho,
        report_chirho,
        Some(authority_chirho),
    )
}

fn install_reviewed_app_source_report_with_authority_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
) -> Result<ReviewedAppSourceInstallReportChirho> {
    let app_name_chirho = &report_chirho.candidate_chirho.app_chirho;
    validate_reviewed_source_report_for_promotion_chirho(
        root_chirho,
        app_name_chirho,
        owner_chirho,
        report_chirho,
        Some(&report_chirho.candidate_chirho.root_dag_chirho),
    )?;
    if let Some(report_chirho) =
        reviewed_app_source_install_report_if_current_chirho(root_chirho, report_chirho)?
    {
        return Ok(report_chirho);
    }
    // Everything below writes, so any failure puts back what this install found.
    let found_chirho = capture_app_live_surface_chirho(root_chirho, app_name_chirho)?;
    install_reviewed_app_source_writes_chirho(
        root_chirho,
        owner_chirho,
        report_chirho,
        authority_chirho,
    )
    .map_err(|failure_chirho| {
        restore_after_failure_chirho(
            root_chirho,
            &found_chirho,
            authority_chirho,
            failure_chirho,
            "the surface this install found",
        )
    })
}

fn install_reviewed_app_source_writes_chirho(
    root_chirho: &Path,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
) -> Result<ReviewedAppSourceInstallReportChirho> {
    let app_name_chirho = &report_chirho.candidate_chirho.app_chirho;
    if reviewed_app_source_required_surface_present_chirho(root_chirho, report_chirho)? {
        prune_unreviewed_source_surface_chirho(
            root_chirho,
            app_name_chirho,
            owner_chirho,
            report_chirho,
        )?;
        return reviewed_app_source_install_report_chirho(root_chirho, report_chirho, false);
    }
    let mut deploy_manifest_chirho =
        reviewed_app_source_deploy_manifest_chirho(owner_chirho, report_chirho);
    if reviewed_app_root_current_chirho(root_chirho, report_chirho)? {
        deploy_manifest_chirho.root_chirho = None;
    }
    let mut deployed_dags_chirho = report_chirho
        .candidate_chirho
        .routes_chirho
        .iter()
        .map(|route_chirho| route_chirho.dag_chirho.clone())
        .collect::<BTreeSet<_>>();
    if deploy_manifest_chirho.root_chirho.is_some() {
        deployed_dags_chirho.insert(report_chirho.candidate_chirho.root_dag_chirho.clone());
    }
    let deployed_bindings_chirho = report_chirho
        .candidate_chirho
        .undo_plan_bindings_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("reviewed descriptor-v2 source report has no undo-plan bindings"))?
        .iter()
        .filter(|binding_chirho| deployed_dags_chirho.contains(&binding_chirho.dag_chirho))
        .cloned()
        .collect::<Vec<_>>();
    deploy_reviewed_app_manifest_chirho(
        root_chirho,
        &deploy_manifest_chirho,
        &deployed_bindings_chirho,
        authority_chirho,
    )?;
    deploy_source_assets_chirho(
        root_chirho,
        app_name_chirho,
        owner_chirho,
        &report_chirho.candidate_chirho.assets_chirho,
    )?;
    prune_unreviewed_source_surface_chirho(
        root_chirho,
        app_name_chirho,
        owner_chirho,
        report_chirho,
    )?;
    reviewed_app_source_install_report_chirho(root_chirho, report_chirho, false)
}

/// Each name's active static asset record for `app_chirho`, as serving selects it (`app_static_asset_by_name_chirho`):
/// the NEWEST record per name decides, and a newer removal hides every older record. An older record must never
/// overwrite a newer one, which made a re-promotion that changed an asset's bytes under an unchanged name fail
/// against the record it had just replaced (PFE #25681, CAIRN #25683).
pub(super) fn active_app_static_asset_records_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<BTreeMap<String, app_chirho::AppStaticAssetRecordChirho>> {
    let mut active_chirho = BTreeMap::new();
    let mut decided_chirho = BTreeSet::new();
    for record_chirho in app_chirho::verified_app_static_asset_records_chirho(root_chirho)?
        .into_iter()
        .rev()
    {
        if record_chirho.app_chirho != app_chirho
            || !decided_chirho.insert(record_chirho.name_chirho.clone())
        {
            continue;
        }
        if !record_chirho.removed_chirho {
            active_chirho.insert(record_chirho.name_chirho.clone(), record_chirho);
        }
    }
    Ok(active_chirho)
}

pub fn reviewed_app_source_install_report_current_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<Option<ReviewedAppSourceInstallReportChirho>> {
    reviewed_app_source_install_report_if_current_chirho(root_chirho, report_chirho)
}

fn reviewed_route_map_chirho(
    report_chirho: &AppSourceReviewReportChirho,
) -> BTreeMap<String, HashChirho> {
    report_chirho
        .candidate_chirho
        .routes_chirho
        .iter()
        .map(|route_chirho| {
            (
                route_chirho.route_chirho.clone(),
                route_chirho.dag_chirho.clone(),
            )
        })
        .collect()
}

fn reviewed_asset_map_chirho(
    report_chirho: &AppSourceReviewReportChirho,
) -> BTreeMap<String, AppSourceAssetReportChirho> {
    report_chirho
        .candidate_chirho
        .assets_chirho
        .iter()
        .map(|asset_chirho| (asset_chirho.name_chirho.clone(), asset_chirho.clone()))
        .collect()
}

fn reviewed_app_source_install_report_if_current_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<Option<ReviewedAppSourceInstallReportChirho>> {
    match reviewed_app_source_install_report_chirho(root_chirho, report_chirho, true) {
        Ok(report_chirho) => Ok(Some(report_chirho)),
        Err(_) => Ok(None),
    }
}

fn reviewed_app_source_install_report_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
    already_current_chirho: bool,
) -> Result<ReviewedAppSourceInstallReportChirho> {
    let app_name_chirho = &report_chirho.candidate_chirho.app_chirho;
    let owner_chirho = &report_chirho.candidate_chirho.owner_chirho;
    let reviewed_routes_chirho = reviewed_route_map_chirho(report_chirho);
    let reviewed_assets_chirho = reviewed_asset_map_chirho(report_chirho);
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_name_chirho)?;
    if !status_chirho.active_chirho
        || status_chirho.dag_chirho.as_ref()
            != Some(&report_chirho.candidate_chirho.root_dag_chirho)
    {
        bail!("reviewed app source promotion did not install reviewed app root");
    }
    if status_chirho.routes_chirho != reviewed_routes_chirho {
        bail!("reviewed app source promotion active route set differs from reviewed report");
    }
    verify_reviewed_input_and_response_policies_chirho(root_chirho, report_chirho)?;

    let route_records_chirho = app_chirho::verified_app_route_records_chirho(root_chirho)?;
    let mut route_evidence_chirho = Vec::new();
    for (route_chirho, dag_chirho) in &reviewed_routes_chirho {
        let record_chirho = route_records_chirho
            .iter()
            .rev()
            .find(|record_chirho| {
                record_chirho.app_chirho == *app_name_chirho
                    && record_chirho.route_chirho == *route_chirho
                    && record_chirho.owner_principal_chirho == *owner_chirho
                    && record_chirho.dag_chirho.as_ref() == Some(dag_chirho)
                    && matches!(
                        record_chirho.action_chirho,
                        app_chirho::AppRouteActionChirho::DeployRouteChirho
                            | app_chirho::AppRouteActionChirho::DeployRouteUnreviewedDevChirho
                    )
            })
            .ok_or_else(|| anyhow!("reviewed route '{route_chirho}' lacks signed route record"))?;
        route_evidence_chirho.push(ReviewedAppSourceRouteInstallEvidenceChirho {
            route_chirho: route_chirho.clone(),
            dag_chirho: dag_chirho.clone(),
            route_record_seq_chirho: record_chirho.seq_chirho,
        });
    }

    let active_assets_chirho =
        active_app_static_asset_records_chirho(root_chirho, app_name_chirho)?;
    let active_asset_names_chirho: BTreeSet<String> =
        active_assets_chirho.keys().cloned().collect();
    let reviewed_asset_names_chirho: BTreeSet<String> =
        reviewed_assets_chirho.keys().cloned().collect();
    if active_asset_names_chirho != reviewed_asset_names_chirho {
        bail!("reviewed app source promotion active asset set differs from reviewed report");
    }
    let mut asset_evidence_chirho = Vec::new();
    for (name_chirho, asset_chirho) in &reviewed_assets_chirho {
        let record_chirho = active_assets_chirho.get(name_chirho).ok_or_else(|| {
            anyhow!("reviewed static asset '{name_chirho}' lacks signed asset record")
        })?;
        if record_chirho.asset_chirho != asset_chirho.asset_chirho
            || record_chirho.content_type_chirho != asset_chirho.content_type_chirho
            || record_chirho.byte_len_chirho != asset_chirho.byte_len_chirho
            || record_chirho.owner_principal_chirho != *owner_chirho
        {
            bail!(
                "reviewed static asset '{name_chirho}' signed record differs from reviewed report"
            );
        }
        asset_evidence_chirho.push(ReviewedAppSourceAssetInstallEvidenceChirho {
            name_chirho: name_chirho.clone(),
            asset_chirho: record_chirho.asset_chirho.clone(),
            content_type_chirho: record_chirho.content_type_chirho.clone(),
            byte_len_chirho: record_chirho.byte_len_chirho,
            static_asset_record_seq_chirho: record_chirho.seq_chirho,
        });
    }

    Ok(ReviewedAppSourceInstallReportChirho {
        route_count_chirho: route_evidence_chirho.len(),
        asset_count_chirho: asset_evidence_chirho.len(),
        routes_chirho: route_evidence_chirho,
        assets_chirho: asset_evidence_chirho,
        already_current_chirho,
    })
}

fn reviewed_app_source_required_surface_present_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<bool> {
    let app_name_chirho = &report_chirho.candidate_chirho.app_chirho;
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_name_chirho)?;
    if !status_chirho.active_chirho
        || status_chirho.dag_chirho.as_ref()
            != Some(&report_chirho.candidate_chirho.root_dag_chirho)
    {
        return Ok(false);
    }
    for route_chirho in &report_chirho.candidate_chirho.routes_chirho {
        if status_chirho.routes_chirho.get(&route_chirho.route_chirho)
            != Some(&route_chirho.dag_chirho)
        {
            return Ok(false);
        }
    }
    if verify_reviewed_input_and_response_policies_chirho(root_chirho, report_chirho).is_err() {
        return Ok(false);
    }
    for asset_chirho in &report_chirho.candidate_chirho.assets_chirho {
        let Some(selection_chirho) = app_chirho::app_static_asset_by_name_chirho(
            root_chirho,
            app_name_chirho,
            &asset_chirho.name_chirho,
        )?
        else {
            return Ok(false);
        };
        if selection_chirho.record_chirho.asset_chirho != asset_chirho.asset_chirho
            || selection_chirho.record_chirho.content_type_chirho
                != asset_chirho.content_type_chirho
            || selection_chirho.record_chirho.byte_len_chirho != asset_chirho.byte_len_chirho
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn reviewed_app_root_current_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<bool> {
    let status_chirho =
        app_chirho::app_status_chirho(root_chirho, &report_chirho.candidate_chirho.app_chirho)?;
    Ok(status_chirho.active_chirho
        && status_chirho.owner_principal_chirho.as_deref()
            == Some(report_chirho.candidate_chirho.owner_chirho.as_str())
        && status_chirho.dag_chirho.as_ref()
            == Some(&report_chirho.candidate_chirho.root_dag_chirho))
}

fn verify_reviewed_input_and_response_policies_chirho(
    root_chirho: &Path,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<()> {
    let app_name_chirho = &report_chirho.candidate_chirho.app_chirho;
    let owner_chirho = &report_chirho.candidate_chirho.owner_chirho;
    let active_routes_chirho =
        app_chirho::app_status_chirho(root_chirho, app_name_chirho)?.routes_chirho;
    if let Some(policy_chirho) = &report_chirho.candidate_chirho.request_access_policy_chirho {
        if app_chirho::app_request_access_policy_chirho(root_chirho, app_name_chirho)?
            != *policy_chirho
        {
            bail!(
                "reviewed app source promotion request access policy differs from reviewed report"
            );
        }
    }
    if let Some(mode_chirho) = &report_chirho.candidate_chirho.input_mode_chirho {
        if app_chirho::app_input_mode_chirho(root_chirho, app_name_chirho, None, owner_chirho)?
            != *mode_chirho
        {
            bail!("reviewed app source promotion root input policy differs from reviewed report");
        }
    }
    if let Some(content_type_chirho) = &report_chirho.candidate_chirho.response_content_type_chirho
    {
        if app_chirho::app_response_content_type_chirho(root_chirho, app_name_chirho, owner_chirho)?
            .as_deref()
            != Some(content_type_chirho.as_str())
        {
            bail!(
                "reviewed app source promotion root response policy differs from reviewed report"
            );
        }
    }
    for route_chirho in &report_chirho.candidate_chirho.routes_chirho {
        let active_dag_chirho = active_routes_chirho
            .get(&route_chirho.route_chirho)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "reviewed app source promotion route '{}' is not active",
                    route_chirho.route_chirho
                )
            })?;
        if app_chirho::verified_app_route_request_body_policy_chirho(
            root_chirho,
            app_name_chirho,
            &route_chirho.route_chirho,
            owner_chirho,
            &active_dag_chirho,
        )? != route_chirho.request_body_policy_chirho
        {
            bail!(
                "reviewed app source promotion route '{}' request-body policy differs from reviewed report",
                route_chirho.route_chirho
            );
        }
        if let Some(mode_chirho) = &route_chirho.input_mode_chirho {
            if app_chirho::app_input_mode_chirho(
                root_chirho,
                app_name_chirho,
                Some(&route_chirho.route_chirho),
                owner_chirho,
            )? != *mode_chirho
            {
                bail!(
                    "reviewed app source promotion route '{}' input policy differs from reviewed report",
                    route_chirho.route_chirho
                );
            }
        }
        if let Some(content_type_chirho) = &route_chirho.response_content_type_chirho {
            if app_chirho::app_route_response_content_type_chirho(
                root_chirho,
                app_name_chirho,
                &route_chirho.route_chirho,
                owner_chirho,
            )?
            .as_deref()
                != Some(content_type_chirho.as_str())
            {
                bail!(
                    "reviewed app source promotion route '{}' response policy differs from reviewed report",
                    route_chirho.route_chirho
                );
            }
        }
    }
    Ok(())
}

fn prune_unreviewed_source_surface_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    report_chirho: &AppSourceReviewReportChirho,
) -> Result<()> {
    let reviewed_routes_chirho: BTreeSet<String> = report_chirho
        .candidate_chirho
        .routes_chirho
        .iter()
        .map(|route_chirho| route_chirho.route_chirho.clone())
        .collect();
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_chirho)?;
    for route_chirho in status_chirho.routes_chirho.keys() {
        if !reviewed_routes_chirho.contains(route_chirho) {
            app_chirho::undeploy_app_route_chirho(
                root_chirho,
                app_chirho,
                route_chirho,
                owner_chirho,
            )?;
        }
    }

    let reviewed_assets_chirho: BTreeSet<String> = report_chirho
        .candidate_chirho
        .assets_chirho
        .iter()
        .map(|asset_chirho| asset_chirho.name_chirho.clone())
        .collect();
    for asset_name_chirho in
        active_app_static_asset_records_chirho(root_chirho, app_chirho)?.into_keys()
    {
        if !reviewed_assets_chirho.contains(&asset_name_chirho) {
            app_chirho::remove_app_static_asset_chirho(
                root_chirho,
                app_chirho,
                owner_chirho,
                &asset_name_chirho,
            )?;
        }
    }
    Ok(())
}
