// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Captures the live surface one reviewed app serves, and puts it back when a promotion or its install fails, so a
//! failed re-promotion leaves the prior version serving instead of darkening the app (PFE #25681, CAIRN #25683).
//!
//! The surface is what serving reads:
//! - the active root;
//! - each active route, with its request-body policy;
//! - the effective input mode and response type of the root and of each route;
//! - the request access policy;
//! - every active static asset.
//!
//! A getter that refuses is captured as that refusal, because serving refuses the same way. It is never read as
//! absence.
//!
//! Restoring writes only what differs, through the signed writers the install itself uses, then captures again and
//! requires the two to be equal. What cannot be put back is reported by name, never discarded:
//! - an input policy that turned private stays private (M141's one-way rule);
//! - a response type or input policy the prior version never had cannot be cleared, because those logs have no
//!   "unset" record.
//!
//! An app with no active root serves nothing, so for it only the root, the routes and the assets are compared. That
//! is what a failed FIRST install must undo, as the old teardown did.
//!
//! Limit: nothing else may write the same app between the capture and the restore. The owner's review-promote is the
//! only writer of a reviewed app's surface.
//!
//! Workflow: the review-promote DAG in
//! `spec-chirho/tasklists-chirho/26-10-01_19-40-tasklist-r7_first_light_product_phase-chirho.md` (HELD section).

use super::reviewed_install_chirho::{
    active_app_static_asset_records_chirho, install_reviewed_app_source_report_chirho,
    ReviewedAppSourceInstallReportChirho,
};
use super::AppSourceReviewReportChirho;
use crate::app_chirho;
use crate::model_chirho::HashChirho;
use anyhow::{anyhow, Result};
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionAuthorityPortChirho;
use std::collections::BTreeMap;
use std::path::Path;

/// What serving meets when it asks for one part of the surface: a value, or the refusal it would get.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SurfaceViewChirho<ValueChirho> {
    ValueChirho(ValueChirho),
    RefusedChirho(String),
}

impl<ValueChirho> SurfaceViewChirho<ValueChirho> {
    fn of_chirho(result_chirho: Result<ValueChirho>) -> Self {
        match result_chirho {
            Ok(value_chirho) => Self::ValueChirho(value_chirho),
            Err(error_chirho) => Self::RefusedChirho(format!("{error_chirho:#}")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AppLiveRouteSurfaceChirho {
    dag_chirho: HashChirho,
    request_body_policy_chirho:
        SurfaceViewChirho<Option<app_chirho::AppRouteRequestBodyPolicyChirho>>,
    input_mode_chirho: SurfaceViewChirho<app_chirho::AppInputModeChirho>,
    response_content_type_chirho: SurfaceViewChirho<Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AppLiveAssetSurfaceChirho {
    asset_chirho: HashChirho,
    content_type_chirho: String,
    byte_len_chirho: u64,
}

/// Constructed ONLY by `capture_app_live_surface_chirho`, from the app's verified records: its fields are private, so no
/// caller can hand a restore a DAG that was not live. That is what keeps the restore's low-level deploys a prior-live
/// door rather than an ungated one (`app_deployment_callers_stay_classified_and_exact_chirho`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AppLiveSurfaceChirho {
    app_chirho: String,
    /// The app's verified owner. None when the app has never had one, which leaves only absence to restore.
    owner_chirho: Option<String>,
    /// The active root DAG. None when the app is not active.
    root_dag_chirho: Option<HashChirho>,
    request_access_policy_chirho: SurfaceViewChirho<app_chirho::AppRequestAccessPolicyChirho>,
    root_input_mode_chirho: SurfaceViewChirho<app_chirho::AppInputModeChirho>,
    root_request_body_policy_chirho:
        SurfaceViewChirho<Option<app_chirho::AppRouteRequestBodyPolicyChirho>>,
    root_response_content_type_chirho: SurfaceViewChirho<Option<String>>,
    routes_chirho: BTreeMap<String, AppLiveRouteSurfaceChirho>,
    assets_chirho: BTreeMap<String, AppLiveAssetSurfaceChirho>,
}

/// What a restore did: nothing differed, or it wrote and the result verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SurfaceRestoreOutcomeChirho {
    UnchangedChirho,
    RestoredChirho,
}

/// The view of every owner-scoped part of an app that has no signed owner: serving refuses it.
fn no_owner_view_chirho<ValueChirho>() -> SurfaceViewChirho<ValueChirho> {
    SurfaceViewChirho::RefusedChirho("the app has no signed owner".to_string())
}

pub(super) fn capture_app_live_surface_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<AppLiveSurfaceChirho> {
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_chirho)?;
    let assets_chirho = active_app_static_asset_records_chirho(root_chirho, app_chirho)?
        .into_iter()
        .map(|(name_chirho, record_chirho)| {
            (
                name_chirho,
                AppLiveAssetSurfaceChirho {
                    asset_chirho: record_chirho.asset_chirho,
                    content_type_chirho: record_chirho.content_type_chirho,
                    byte_len_chirho: record_chirho.byte_len_chirho,
                },
            )
        })
        .collect();
    let root_dag_chirho = status_chirho
        .active_chirho
        .then(|| status_chirho.dag_chirho.clone())
        .flatten();
    let Some(owner_chirho) = status_chirho.owner_principal_chirho.clone() else {
        return Ok(AppLiveSurfaceChirho {
            app_chirho: app_chirho.to_string(),
            owner_chirho: None,
            root_dag_chirho,
            request_access_policy_chirho: no_owner_view_chirho(),
            root_input_mode_chirho: no_owner_view_chirho(),
            root_request_body_policy_chirho: no_owner_view_chirho(),
            root_response_content_type_chirho: no_owner_view_chirho(),
            routes_chirho: status_chirho
                .routes_chirho
                .into_iter()
                .map(|(route_chirho, dag_chirho)| {
                    (
                        route_chirho,
                        AppLiveRouteSurfaceChirho {
                            dag_chirho,
                            request_body_policy_chirho: no_owner_view_chirho(),
                            input_mode_chirho: no_owner_view_chirho(),
                            response_content_type_chirho: no_owner_view_chirho(),
                        },
                    )
                })
                .collect(),
            assets_chirho,
        });
    };
    let mut routes_chirho = BTreeMap::new();
    for (route_chirho, dag_chirho) in &status_chirho.routes_chirho {
        routes_chirho.insert(
            route_chirho.clone(),
            AppLiveRouteSurfaceChirho {
                dag_chirho: dag_chirho.clone(),
                request_body_policy_chirho: SurfaceViewChirho::of_chirho(
                    app_chirho::verified_app_route_request_body_policy_chirho(
                        root_chirho,
                        app_chirho,
                        route_chirho,
                        &owner_chirho,
                        dag_chirho,
                    ),
                ),
                input_mode_chirho: SurfaceViewChirho::of_chirho(app_chirho::app_input_mode_chirho(
                    root_chirho,
                    app_chirho,
                    Some(route_chirho),
                    &owner_chirho,
                )),
                response_content_type_chirho: SurfaceViewChirho::of_chirho(
                    app_chirho::app_route_response_content_type_chirho(
                        root_chirho,
                        app_chirho,
                        route_chirho,
                        &owner_chirho,
                    ),
                ),
            },
        );
    }
    Ok(AppLiveSurfaceChirho {
        app_chirho: app_chirho.to_string(),
        request_access_policy_chirho: SurfaceViewChirho::of_chirho(
            app_chirho::app_request_access_policy_chirho(root_chirho, app_chirho),
        ),
        root_input_mode_chirho: SurfaceViewChirho::of_chirho(app_chirho::app_input_mode_chirho(
            root_chirho,
            app_chirho,
            None,
            &owner_chirho,
        )),
        root_request_body_policy_chirho: SurfaceViewChirho::of_chirho(
            app_chirho::app_root_request_body_policy_chirho(root_chirho, app_chirho, &owner_chirho),
        ),
        root_response_content_type_chirho: SurfaceViewChirho::of_chirho(
            app_chirho::app_response_content_type_chirho(root_chirho, app_chirho, &owner_chirho),
        ),
        owner_chirho: Some(owner_chirho),
        root_dag_chirho,
        routes_chirho,
        assets_chirho,
    })
}

/// Every part where `current` does not serve what `prior` served, by name. Empty means equal for serving.
fn app_live_surface_differences_chirho(
    prior_chirho: &AppLiveSurfaceChirho,
    current_chirho: &AppLiveSurfaceChirho,
) -> Vec<String> {
    let mut differences_chirho = Vec::new();
    if prior_chirho.root_dag_chirho != current_chirho.root_dag_chirho {
        differences_chirho.push("the active root".to_string());
    }
    if prior_chirho.assets_chirho != current_chirho.assets_chirho {
        differences_chirho.push("the active static assets".to_string());
    }
    if prior_chirho.root_dag_chirho.is_none() {
        // An app that is not active serves nothing: only leftover routes matter, as the old teardown removed them.
        if prior_chirho
            .routes_chirho
            .keys()
            .ne(current_chirho.routes_chirho.keys())
            || prior_chirho
                .routes_chirho
                .iter()
                .zip(&current_chirho.routes_chirho)
                .any(|((_, prior_route_chirho), (_, current_route_chirho))| {
                    prior_route_chirho.dag_chirho != current_route_chirho.dag_chirho
                })
        {
            differences_chirho.push("the active routes".to_string());
        }
        return differences_chirho;
    }
    if prior_chirho.owner_chirho != current_chirho.owner_chirho {
        differences_chirho.push("the owner".to_string());
    }
    let root_parts_chirho = [
        (
            prior_chirho.request_access_policy_chirho
                != current_chirho.request_access_policy_chirho,
            "the request access policy",
        ),
        (
            prior_chirho.root_input_mode_chirho != current_chirho.root_input_mode_chirho,
            "the root input policy",
        ),
        (
            prior_chirho.root_request_body_policy_chirho
                != current_chirho.root_request_body_policy_chirho,
            "the root request-body policy",
        ),
        (
            prior_chirho.root_response_content_type_chirho
                != current_chirho.root_response_content_type_chirho,
            "the root response type",
        ),
    ];
    for (differs_chirho, part_chirho) in root_parts_chirho {
        if differs_chirho {
            differences_chirho.push(part_chirho.to_string());
        }
    }
    for route_chirho in current_chirho.routes_chirho.keys() {
        if !prior_chirho.routes_chirho.contains_key(route_chirho) {
            differences_chirho.push(format!("route '{route_chirho}' (not served before)"));
        }
    }
    for (route_chirho, prior_route_chirho) in &prior_chirho.routes_chirho {
        match current_chirho.routes_chirho.get(route_chirho) {
            None => differences_chirho.push(format!("route '{route_chirho}' (no longer served)")),
            Some(current_route_chirho) if current_route_chirho != prior_route_chirho => {
                differences_chirho.push(format!("route '{route_chirho}'"))
            }
            Some(_) => {}
        }
    }
    differences_chirho
}

/// Put back `prior_chirho`, writing only what differs, then require the result to serve exactly what it served.
fn restore_app_live_surface_chirho(
    root_chirho: &Path,
    prior_chirho: &AppLiveSurfaceChirho,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
) -> Result<SurfaceRestoreOutcomeChirho> {
    let app_chirho = prior_chirho.app_chirho.as_str();
    let current_chirho = capture_app_live_surface_chirho(root_chirho, app_chirho)?;
    if app_live_surface_differences_chirho(prior_chirho, &current_chirho).is_empty() {
        return Ok(SurfaceRestoreOutcomeChirho::UnchangedChirho);
    }
    let Some(owner_chirho) = prior_chirho
        .owner_chirho
        .clone()
        .or_else(|| current_chirho.owner_chirho.clone())
    else {
        return Err(anyhow!(
            "app '{app_chirho}' differs from its prior surface but has no signed owner to write as"
        ));
    };
    let mut writer_chirho = SurfaceWriterChirho {
        root_chirho,
        app_chirho,
        owner_chirho: &owner_chirho,
        authority_chirho,
        failures_chirho: Vec::new(),
    };
    match &prior_chirho.root_dag_chirho {
        Some(prior_root_chirho) => writer_chirho.put_back_live_version_chirho(
            prior_chirho,
            &current_chirho,
            prior_root_chirho,
        ),
        None => writer_chirho.take_down_to_prior_chirho(prior_chirho, &current_chirho),
    }
    let after_chirho = capture_app_live_surface_chirho(root_chirho, app_chirho)?;
    let remaining_chirho = app_live_surface_differences_chirho(prior_chirho, &after_chirho);
    if remaining_chirho.is_empty() {
        return Ok(SurfaceRestoreOutcomeChirho::RestoredChirho);
    }
    Err(anyhow!(
        "app '{app_chirho}' still differs from its prior surface in: {}{}",
        remaining_chirho.join(", "),
        if writer_chirho.failures_chirho.is_empty() {
            String::new()
        } else {
            format!(
                " (writes that failed: {})",
                writer_chirho.failures_chirho.join("; ")
            )
        }
    ))
}

/// The error to return when `failure_chirho` happened after `prior_chirho` was captured. It puts the prior surface
/// back first, and says whether that worked. If nothing had changed, the failure is returned exactly as it was.
pub(super) fn restore_after_failure_chirho(
    root_chirho: &Path,
    prior_chirho: &AppLiveSurfaceChirho,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
    failure_chirho: anyhow::Error,
    what_chirho: &str,
) -> anyhow::Error {
    match restore_app_live_surface_chirho(root_chirho, prior_chirho, authority_chirho) {
        Ok(SurfaceRestoreOutcomeChirho::UnchangedChirho) => failure_chirho,
        Ok(SurfaceRestoreOutcomeChirho::RestoredChirho) => {
            anyhow!("{failure_chirho:#}; {what_chirho} was put back and verified")
        }
        Err(restore_error_chirho) => anyhow!(
            "{failure_chirho:#}; PUTTING BACK {what_chirho} FAILED, so app '{}' may not serve its prior version: {restore_error_chirho:#}",
            prior_chirho.app_chirho
        ),
    }
}

/// Promote, then install the reviewed surface. If either step fails, the app's live surface from before the promotion
/// is put back, and the failure says whether that worked. The owner's web route and the CLI both promote through here,
/// so neither can discard a failed restore again (it was `let _` in both, PFE #25681).
///
/// The promotion's signed review record stays when the install fails; the app then serves its prior version.
pub fn promote_then_install_reviewed_source_chirho<RecordChirho>(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    report_chirho: Option<&AppSourceReviewReportChirho>,
    promote_chirho: impl FnOnce() -> Result<RecordChirho>,
) -> Result<(RecordChirho, Option<ReviewedAppSourceInstallReportChirho>)> {
    const WHAT_CHIRHO: &str = "the app's live surface from before the promotion";
    let prior_chirho = capture_app_live_surface_chirho(root_chirho, app_chirho)?;
    let record_chirho = promote_chirho().map_err(|failure_chirho| {
        restore_after_failure_chirho(
            root_chirho,
            &prior_chirho,
            None,
            failure_chirho,
            WHAT_CHIRHO,
        )
    })?;
    let install_chirho = match report_chirho {
        None => None,
        Some(report_chirho) => Some(
            install_reviewed_app_source_report_chirho(root_chirho, owner_chirho, report_chirho)
                .map_err(|failure_chirho| {
                    restore_after_failure_chirho(
                        root_chirho,
                        &prior_chirho,
                        None,
                        failure_chirho,
                        WHAT_CHIRHO,
                    )
                })?,
        ),
    };
    Ok((record_chirho, install_chirho))
}

/// The signed writes of one restore. A failed write is recorded and the restore goes on, so one refusal cannot leave
/// the rest unrestored; the closing capture decides the outcome.
struct SurfaceWriterChirho<'a> {
    root_chirho: &'a Path,
    app_chirho: &'a str,
    owner_chirho: &'a str,
    authority_chirho: Option<&'a dyn HeadTransitionAuthorityPortChirho>,
    failures_chirho: Vec<String>,
}

impl SurfaceWriterChirho<'_> {
    fn attempt_chirho<OutputChirho>(
        &mut self,
        step_chirho: &str,
        result_chirho: Result<OutputChirho>,
    ) {
        if let Err(error_chirho) = result_chirho {
            self.failures_chirho
                .push(format!("{step_chirho}: {error_chirho:#}"));
        }
    }

    /// The prior version was live: put its root, routes, policies and assets back.
    fn put_back_live_version_chirho(
        &mut self,
        prior_chirho: &AppLiveSurfaceChirho,
        current_chirho: &AppLiveSurfaceChirho,
        prior_root_chirho: &HashChirho,
    ) {
        let (root_chirho, app_chirho, owner_chirho) =
            (self.root_chirho, self.app_chirho, self.owner_chirho);
        if current_chirho.root_dag_chirho.as_ref() != Some(prior_root_chirho) {
            let deployed_chirho = match self.authority_chirho {
                Some(authority_chirho) => {
                    app_chirho::deploy_app_with_head_transition_authority_chirho(
                        root_chirho,
                        app_chirho,
                        prior_root_chirho.clone(),
                        owner_chirho,
                        authority_chirho,
                    )
                }
                None => app_chirho::deploy_app_chirho(
                    root_chirho,
                    app_chirho,
                    prior_root_chirho.clone(),
                    owner_chirho,
                ),
            };
            self.attempt_chirho("redeploy the prior root", deployed_chirho);
        }
        for route_chirho in current_chirho.routes_chirho.keys() {
            if !prior_chirho.routes_chirho.contains_key(route_chirho) {
                let undeployed_chirho = app_chirho::undeploy_app_route_chirho(
                    root_chirho,
                    app_chirho,
                    route_chirho,
                    owner_chirho,
                );
                self.attempt_chirho(
                    &format!("withdraw route '{route_chirho}'"),
                    undeployed_chirho,
                );
            }
        }
        for (route_chirho, prior_route_chirho) in &prior_chirho.routes_chirho {
            let current_route_chirho = current_chirho.routes_chirho.get(route_chirho);
            let deployment_differs_chirho =
                current_route_chirho.is_none_or(|current_route_chirho| {
                    current_route_chirho.dag_chirho != prior_route_chirho.dag_chirho
                        || current_route_chirho.request_body_policy_chirho
                            != prior_route_chirho.request_body_policy_chirho
                });
            if deployment_differs_chirho {
                self.redeploy_route_chirho(route_chirho, prior_route_chirho);
            }
            if current_route_chirho
                .map(|current_route_chirho| &current_route_chirho.input_mode_chirho)
                != Some(&prior_route_chirho.input_mode_chirho)
            {
                self.put_back_input_mode_chirho(
                    Some(route_chirho),
                    &prior_route_chirho.input_mode_chirho,
                    None,
                );
            }
            if current_route_chirho
                .map(|current_route_chirho| &current_route_chirho.response_content_type_chirho)
                != Some(&prior_route_chirho.response_content_type_chirho)
            {
                self.put_back_response_type_chirho(
                    Some(route_chirho),
                    &prior_route_chirho.response_content_type_chirho,
                );
            }
        }
        if current_chirho.request_access_policy_chirho != prior_chirho.request_access_policy_chirho
        {
            match &prior_chirho.request_access_policy_chirho {
                SurfaceViewChirho::ValueChirho(policy_chirho) => {
                    let set_chirho = app_chirho::set_app_request_access_policy_chirho(
                        root_chirho,
                        app_chirho,
                        owner_chirho,
                        prior_root_chirho.clone(),
                        policy_chirho.clone(),
                    );
                    self.attempt_chirho("put back the request access policy", set_chirho);
                }
                SurfaceViewChirho::RefusedChirho(_) => self.failures_chirho.push(
                    "the prior request access policy was a refusal, which cannot be written"
                        .to_string(),
                ),
            }
        }
        if current_chirho.root_input_mode_chirho != prior_chirho.root_input_mode_chirho
            || current_chirho.root_request_body_policy_chirho
                != prior_chirho.root_request_body_policy_chirho
        {
            self.put_back_input_mode_chirho(
                None,
                &prior_chirho.root_input_mode_chirho,
                Some(&prior_chirho.root_request_body_policy_chirho),
            );
        }
        if current_chirho.root_response_content_type_chirho
            != prior_chirho.root_response_content_type_chirho
        {
            self.put_back_response_type_chirho(
                None,
                &prior_chirho.root_response_content_type_chirho,
            );
        }
        self.put_back_assets_chirho(prior_chirho, current_chirho);
    }

    /// The prior version was not live: withdraw what the failed step added, as the first-install teardown did.
    fn take_down_to_prior_chirho(
        &mut self,
        prior_chirho: &AppLiveSurfaceChirho,
        current_chirho: &AppLiveSurfaceChirho,
    ) {
        let (root_chirho, app_chirho, owner_chirho) =
            (self.root_chirho, self.app_chirho, self.owner_chirho);
        self.put_back_assets_chirho(prior_chirho, current_chirho);
        for route_chirho in current_chirho.routes_chirho.keys() {
            if !prior_chirho.routes_chirho.contains_key(route_chirho) {
                let undeployed_chirho = app_chirho::undeploy_app_route_chirho(
                    root_chirho,
                    app_chirho,
                    route_chirho,
                    owner_chirho,
                );
                self.attempt_chirho(
                    &format!("withdraw route '{route_chirho}'"),
                    undeployed_chirho,
                );
            }
        }
        if current_chirho.root_dag_chirho.is_some() {
            let undeployed_chirho =
                app_chirho::undeploy_app_chirho(root_chirho, app_chirho, owner_chirho);
            self.attempt_chirho("withdraw the root", undeployed_chirho);
        }
    }

    fn redeploy_route_chirho(
        &mut self,
        route_chirho: &str,
        prior_route_chirho: &AppLiveRouteSurfaceChirho,
    ) {
        let SurfaceViewChirho::ValueChirho(body_policy_chirho) =
            &prior_route_chirho.request_body_policy_chirho
        else {
            self.failures_chirho.push(format!(
                "route '{route_chirho}': its prior request-body policy was a refusal, which cannot be written"
            ));
            return;
        };
        let deployed_chirho = match self.authority_chirho {
            Some(authority_chirho) => {
                app_chirho::deploy_app_route_with_request_body_policy_and_head_transition_authority_chirho(
                    self.root_chirho,
                    self.app_chirho,
                    route_chirho,
                    prior_route_chirho.dag_chirho.clone(),
                    self.owner_chirho,
                    body_policy_chirho.clone(),
                    authority_chirho,
                )
            }
            None => app_chirho::deploy_app_route_with_request_body_policy_chirho(
                self.root_chirho,
                self.app_chirho,
                route_chirho,
                prior_route_chirho.dag_chirho.clone(),
                self.owner_chirho,
                body_policy_chirho.clone(),
                false,
            ),
        };
        self.attempt_chirho(&format!("redeploy route '{route_chirho}'"), deployed_chirho);
    }

    /// `root_body_policy_chirho` is Some only for the root surface, whose body policy rides on its input policy record.
    fn put_back_input_mode_chirho(
        &mut self,
        route_chirho: Option<&str>,
        prior_mode_chirho: &SurfaceViewChirho<app_chirho::AppInputModeChirho>,
        root_body_policy_chirho: Option<
            &SurfaceViewChirho<Option<app_chirho::AppRouteRequestBodyPolicyChirho>>,
        >,
    ) {
        let surface_chirho = route_chirho.map_or_else(
            || "the root".to_string(),
            |route_chirho| format!("route '{route_chirho}'"),
        );
        let SurfaceViewChirho::ValueChirho(mode_chirho) = prior_mode_chirho else {
            self.failures_chirho.push(format!(
                "{surface_chirho}: it had no input policy before, and an input policy cannot be cleared"
            ));
            return;
        };
        let set_chirho = match root_body_policy_chirho {
            Some(SurfaceViewChirho::ValueChirho(Some(body_policy_chirho))) => {
                app_chirho::set_app_root_input_policy_with_request_body_policy_chirho(
                    self.root_chirho,
                    self.app_chirho,
                    self.owner_chirho,
                    mode_chirho.clone(),
                    body_policy_chirho.clone(),
                )
            }
            _ => app_chirho::set_app_input_policy_chirho(
                self.root_chirho,
                self.app_chirho,
                route_chirho,
                self.owner_chirho,
                mode_chirho.clone(),
            ),
        };
        self.attempt_chirho(
            &format!("put back the input policy of {surface_chirho}"),
            set_chirho,
        );
    }

    fn put_back_response_type_chirho(
        &mut self,
        route_chirho: Option<&str>,
        prior_type_chirho: &SurfaceViewChirho<Option<String>>,
    ) {
        let surface_chirho = route_chirho.map_or_else(
            || "the root".to_string(),
            |route_chirho| format!("route '{route_chirho}'"),
        );
        let SurfaceViewChirho::ValueChirho(Some(content_type_chirho)) = prior_type_chirho else {
            self.failures_chirho.push(format!(
                "{surface_chirho}: it had no response type before, and a response type cannot be cleared"
            ));
            return;
        };
        let set_chirho = match route_chirho {
            Some(route_chirho) => app_chirho::set_app_route_response_policy_chirho(
                self.root_chirho,
                self.app_chirho,
                route_chirho,
                self.owner_chirho,
                content_type_chirho,
            )
            .map(|_| ()),
            None => app_chirho::set_app_response_policy_chirho(
                self.root_chirho,
                self.app_chirho,
                self.owner_chirho,
                content_type_chirho,
            )
            .map(|_| ()),
        };
        self.attempt_chirho(
            &format!("put back the response type of {surface_chirho}"),
            set_chirho,
        );
    }

    fn put_back_assets_chirho(
        &mut self,
        prior_chirho: &AppLiveSurfaceChirho,
        current_chirho: &AppLiveSurfaceChirho,
    ) {
        let (root_chirho, app_chirho, owner_chirho) =
            (self.root_chirho, self.app_chirho, self.owner_chirho);
        for name_chirho in current_chirho.assets_chirho.keys() {
            if !prior_chirho.assets_chirho.contains_key(name_chirho) {
                let removed_chirho = app_chirho::remove_app_static_asset_chirho(
                    root_chirho,
                    app_chirho,
                    owner_chirho,
                    name_chirho,
                );
                self.attempt_chirho(&format!("withdraw asset '{name_chirho}'"), removed_chirho);
            }
        }
        for (name_chirho, prior_asset_chirho) in &prior_chirho.assets_chirho {
            if current_chirho.assets_chirho.get(name_chirho) != Some(prior_asset_chirho) {
                let set_chirho = app_chirho::set_app_static_asset_hash_chirho(
                    root_chirho,
                    app_chirho,
                    owner_chirho,
                    name_chirho,
                    prior_asset_chirho.asset_chirho.clone(),
                    &prior_asset_chirho.content_type_chirho,
                    prior_asset_chirho.byte_len_chirho,
                );
                self.attempt_chirho(&format!("put back asset '{name_chirho}'"), set_chirho);
            }
        }
    }
}
