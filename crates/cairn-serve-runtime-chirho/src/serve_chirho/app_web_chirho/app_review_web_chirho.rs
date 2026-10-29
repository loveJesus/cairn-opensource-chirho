// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::app_state_web_chirho::{app_state_action_error_response_chirho, app_state_url_chirho};
use super::{escape_html_chirho, parse_review_hash_chirho, AppStateChirho};
use axum::{
    extract::{Form, Path as AxPath, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{app_source_manifest_chirho, review_chirho};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppReviewPromoteRequestChirho {
    pub(super) candidate_chirho: String,
    pub(super) source_review_report_chirho: String,
    #[serde(default)]
    pub(super) accept_capability_escalation_chirho: bool,
    #[serde(default)]
    pub(super) accept_cost_increase_chirho: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppReviewRollbackRequestChirho {
    pub(super) source_review_report_chirho: String,
}

pub(super) async fn app_review_promote_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho, app_chirho)): AxPath<(String, String, String)>,
    Form(req_chirho): Form<AppReviewPromoteRequestChirho>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    if let Some(response_chirho) = state_chirho
        .runtime_chirho
        .require_owner_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    match promote_reviewed_app_candidate_html_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        &principal_chirho,
        &kind_chirho,
        &id_chirho,
        &app_chirho,
        req_chirho,
    ) {
        Ok(html_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html_chirho,
        )
            .into_response(),
        Err(e_chirho) => app_state_action_error_response_chirho(e_chirho),
    }
}

pub(super) async fn app_review_rollback_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho, app_chirho)): AxPath<(String, String, String)>,
    Form(req_chirho): Form<AppReviewRollbackRequestChirho>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    if let Some(response_chirho) = state_chirho
        .runtime_chirho
        .require_owner_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    match rollback_reviewed_app_candidate_html_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        &principal_chirho,
        &kind_chirho,
        &id_chirho,
        &app_chirho,
        req_chirho,
    ) {
        Ok(html_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html_chirho,
        )
            .into_response(),
        Err(e_chirho) => app_state_action_error_response_chirho(e_chirho),
    }
}

fn load_owner_source_review_report_chirho(
    root_chirho: &std::path::Path,
    app_name_chirho: &str,
    owner_chirho: &str,
    source_review_report_chirho: &HashChirho,
    candidate_chirho: Option<&HashChirho>,
) -> anyhow::Result<app_source_manifest_chirho::AppSourceReviewReportChirho> {
    app_source_manifest_chirho::load_app_source_review_report_for_promotion_chirho(
        root_chirho,
        app_name_chirho,
        owner_chirho,
        source_review_report_chirho,
        candidate_chirho,
    )
}

fn promote_reviewed_app_candidate_html_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_name_chirho: &str,
    req_chirho: AppReviewPromoteRequestChirho,
) -> anyhow::Result<String> {
    let candidate_chirho =
        parse_review_hash_chirho("candidate_chirho", &req_chirho.candidate_chirho)?;
    let source_review_report_chirho = parse_review_hash_chirho(
        "source_review_report_chirho",
        &req_chirho.source_review_report_chirho,
    )?;
    let report_chirho = load_owner_source_review_report_chirho(
        root_chirho,
        app_name_chirho,
        owner_chirho,
        &source_review_report_chirho,
        Some(&candidate_chirho),
    )?;
    if let Some(install_report_chirho) =
        app_source_manifest_chirho::reviewed_app_source_install_report_current_chirho(
            root_chirho,
            &report_chirho,
        )?
    {
        if let Some(record_chirho) = review_chirho::latest_promoted_source_review_record_chirho(
            root_chirho,
            app_name_chirho,
            owner_chirho,
            &candidate_chirho,
            &source_review_report_chirho,
        )? {
            return Ok(format!(
                "<section data-app-review-promote-chirho=\"ok\"><h1>review already promoted</h1><p>app <code>{}</code> candidate <code>{}</code> source-review <code>{}</code> review #{} route(s) {} asset(s) {}</p><p><a href=\"{}\">app state</a></p></section>",
                escape_html_chirho(app_name_chirho),
                escape_html_chirho(&candidate_chirho.0),
                escape_html_chirho(&source_review_report_chirho.0),
                record_chirho.seq_chirho,
                install_report_chirho.route_count_chirho,
                install_report_chirho.asset_count_chirho,
                escape_html_chirho(&app_state_url_chirho(kind_chirho, id_chirho, app_name_chirho)),
            ));
        }
    }
    // A failed promote or install puts the app's prior live surface back, and the error says whether that worked.
    let (record_chirho, install_report_chirho) =
        app_source_manifest_chirho::promote_then_install_reviewed_source_chirho(
            root_chirho,
            app_name_chirho,
            owner_chirho,
            Some(&report_chirho),
            || {
                review_chirho::promote_candidate_with_review_evidence_chirho(
                    root_chirho,
                    review_chirho::PromoteCandidateReviewEvidenceInputChirho {
                        app_chirho: app_name_chirho,
                        owner_principal_chirho: owner_chirho,
                        candidate_chirho: candidate_chirho.clone(),
                        accept_capability_escalation_chirho: req_chirho
                            .accept_capability_escalation_chirho,
                        accept_cost_increase_chirho: req_chirho.accept_cost_increase_chirho,
                        require_review_policy_envelope_chirho: false,
                        source_evidence_chirho: review_chirho::ReviewSourceEvidenceChirho {
                            source_review_report_chirho: Some(source_review_report_chirho.clone()),
                            source_manifest_chirho: None,
                        },
                    },
                )
            },
        )?;
    let install_report_chirho = install_report_chirho
        .ok_or_else(|| anyhow::anyhow!("a reviewed promotion with a source review installs it"))?;
    Ok(format!(
        "<section data-app-review-promote-chirho=\"ok\"><h1>review promoted</h1><p>app <code>{}</code> candidate <code>{}</code> source-review <code>{}</code> review #{} route(s) {} asset(s) {}</p><p><a href=\"{}\">app state</a></p></section>",
        escape_html_chirho(app_name_chirho),
        escape_html_chirho(&candidate_chirho.0),
        escape_html_chirho(&source_review_report_chirho.0),
        record_chirho.seq_chirho,
        install_report_chirho.route_count_chirho,
        install_report_chirho.asset_count_chirho,
        escape_html_chirho(&app_state_url_chirho(kind_chirho, id_chirho, app_name_chirho)),
    ))
}

fn rollback_reviewed_app_candidate_html_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_name_chirho: &str,
    req_chirho: AppReviewRollbackRequestChirho,
) -> anyhow::Result<String> {
    let source_review_report_chirho = parse_review_hash_chirho(
        "source_review_report_chirho",
        &req_chirho.source_review_report_chirho,
    )?;
    let report_chirho = load_owner_source_review_report_chirho(
        root_chirho,
        app_name_chirho,
        owner_chirho,
        &source_review_report_chirho,
        None,
    )?;
    let (removed_app_chirho, removed_routes_chirho, removed_assets_chirho) =
        app_source_manifest_chirho::rollback_reviewed_app_source_report_chirho(
            root_chirho,
            owner_chirho,
            &report_chirho,
        )?;
    Ok(format!(
        "<section data-app-review-rollback-chirho=\"ok\"><h1>review rollback</h1><p>app <code>{}</code> source-review <code>{}</code> removed_app={} removed_route(s) {} removed_asset(s) {}</p><p><a href=\"{}\">app state</a></p></section>",
        escape_html_chirho(app_name_chirho),
        escape_html_chirho(&source_review_report_chirho.0),
        removed_app_chirho,
        removed_routes_chirho,
        removed_assets_chirho,
        escape_html_chirho(&app_state_url_chirho(kind_chirho, id_chirho, app_name_chirho)),
    ))
}
