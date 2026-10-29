// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::{
    escape_html_chirho, support_html_head_chirho, support_html_tail_chirho, AppStateChirho,
};
use axum::{
    extract::{Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_chirho::app_build_request_chirho;

#[derive(Clone, Debug, Default)]
struct AppBuildRequestAuthorRequestChirho {
    idempotency_key_chirho: String,
    owner_goal_chirho: String,
    requested_modules_chirho: Vec<String>,
    notes_chirho: String,
}

pub(super) async fn app_build_request_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho, app_chirho)): AxPath<(String, String, String)>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    if let Some(response_chirho) = state_chirho
        .runtime_chirho
        .require_owner_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    match app_build_request_list_html_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        &principal_chirho,
        &kind_chirho,
        &id_chirho,
        &app_chirho,
    ) {
        Ok(html_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html_chirho,
        )
            .into_response(),
        Err(e_chirho) => app_build_request_action_error_response_chirho(e_chirho),
    }
}

pub(super) async fn app_build_request_preview_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho, app_chirho)): AxPath<(String, String, String)>,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    if let Some(response_chirho) = state_chirho
        .runtime_chirho
        .require_owner_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    let req_chirho = match parse_app_build_request_author_request_chirho(request_chirho).await {
        Ok(req_chirho) => req_chirho,
        Err(e_chirho) => return app_build_request_action_error_response_chirho(e_chirho),
    };
    let input_chirho = app_build_request_input_from_author_request_chirho(
        &principal_chirho,
        &app_chirho,
        req_chirho,
    );
    match app_build_request_chirho::preview_app_build_request_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        input_chirho,
    ) {
        Ok(preview_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            app_build_request_preview_html_chirho(
                &kind_chirho,
                &id_chirho,
                &app_chirho,
                &preview_chirho,
            ),
        )
            .into_response(),
        Err(e_chirho) => app_build_request_action_error_response_chirho(e_chirho),
    }
}

pub(super) async fn app_build_request_create_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho, app_chirho)): AxPath<(String, String, String)>,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    if let Some(response_chirho) = state_chirho
        .runtime_chirho
        .require_owner_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    let req_chirho = match parse_app_build_request_author_request_chirho(request_chirho).await {
        Ok(req_chirho) => req_chirho,
        Err(e_chirho) => return app_build_request_action_error_response_chirho(e_chirho),
    };
    let input_chirho = app_build_request_input_from_author_request_chirho(
        &principal_chirho,
        &app_chirho,
        req_chirho,
    );
    match app_build_request_chirho::create_app_build_request_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        input_chirho,
    ) {
        Ok(record_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            app_build_request_record_html_chirho(
                &kind_chirho,
                &id_chirho,
                &app_chirho,
                &record_chirho,
            ),
        )
            .into_response(),
        Err(e_chirho) => app_build_request_action_error_response_chirho(e_chirho),
    }
}

fn app_build_request_input_from_author_request_chirho(
    owner_principal_chirho: &str,
    app_chirho: &str,
    req_chirho: AppBuildRequestAuthorRequestChirho,
) -> app_build_request_chirho::AppBuildRequestInputChirho {
    app_build_request_chirho::AppBuildRequestInputChirho {
        owner_principal_chirho: owner_principal_chirho.to_string(),
        app_chirho: app_chirho.to_string(),
        idempotency_key_chirho: req_chirho.idempotency_key_chirho,
        owner_goal_chirho: req_chirho.owner_goal_chirho,
        requested_modules_chirho: req_chirho.requested_modules_chirho,
        notes_chirho: req_chirho.notes_chirho,
    }
}

fn app_build_request_action_error_response_chirho(error_chirho: anyhow::Error) -> Response {
    let message_chirho = error_chirho.to_string();
    let status_chirho = if message_chirho.contains("idempotency key conflict") {
        StatusCode::CONFLICT
    } else if message_chirho.contains("not found for owner")
        || message_chirho.contains("has no owner")
        || message_chirho.contains("owner does not match")
    {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        status_chirho,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "{}<h1>app build request error</h1><pre>{}</pre>{}",
            support_html_head_chirho("app build request error"),
            escape_html_chirho(&message_chirho),
            support_html_tail_chirho()
        ),
    )
        .into_response()
}

async fn parse_app_build_request_author_request_chirho(
    request_chirho: axum::http::Request<axum::body::Body>,
) -> anyhow::Result<AppBuildRequestAuthorRequestChirho> {
    const MAX_APP_BUILD_REQUEST_FORM_BYTES_CHIRHO: usize = 128 * 1024;
    let bytes_chirho = axum::body::to_bytes(
        request_chirho.into_body(),
        MAX_APP_BUILD_REQUEST_FORM_BYTES_CHIRHO + 1,
    )
    .await
    .map_err(|_| anyhow::anyhow!("read app build request form body failed"))?;
    if bytes_chirho.len() > MAX_APP_BUILD_REQUEST_FORM_BYTES_CHIRHO {
        anyhow::bail!("app build request form body too large");
    }
    let mut req_chirho = AppBuildRequestAuthorRequestChirho::default();
    for (key_chirho, value_chirho) in url::form_urlencoded::parse(&bytes_chirho) {
        match key_chirho.as_ref() {
            "idempotency_key_chirho" => {
                req_chirho.idempotency_key_chirho = value_chirho.into_owned()
            }
            "owner_goal_chirho" => req_chirho.owner_goal_chirho = value_chirho.into_owned(),
            "module_chirho" | "requested_module_chirho" => req_chirho
                .requested_modules_chirho
                .push(value_chirho.into_owned()),
            "notes_chirho" => req_chirho.notes_chirho = value_chirho.into_owned(),
            _ => {}
        }
    }
    Ok(req_chirho)
}

fn app_build_request_module_list_chirho(modules_chirho: &[String]) -> String {
    modules_chirho
        .iter()
        .map(|module_chirho| format!("<code>{}</code>", escape_html_chirho(module_chirho)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn app_build_request_private_ref_marker_chirho(
    record_chirho: &app_build_request_chirho::AppBuildRequestRecordChirho,
) -> String {
    let hash_chirho = &record_chirho.request_private_ref_chirho.ciphertext_chirho.0;
    hash_chirho[..hash_chirho.len().min(16)].to_string()
}

fn app_build_request_resource_seq_label_chirho(
    record_chirho: &app_build_request_chirho::AppBuildRequestRecordChirho,
) -> String {
    record_chirho
        .resource_usage_seq_chirho
        .map(|seq_chirho| seq_chirho.to_string())
        .unwrap_or_else(|| "(none)".to_string())
}

fn app_build_request_preview_html_chirho(
    _kind_chirho: &str,
    _id_chirho: &str,
    app_chirho: &str,
    preview_chirho: &app_build_request_chirho::AppBuildRequestPreviewChirho,
) -> String {
    format!(
        "{}<section data-app-build-request-chirho=\"preview\"><h1>app build request preview</h1><p>app <code>{}</code> existing_app={} no_store={} candidate_request_cost_token={}</p><p>payload <code>{}</code> idempotency <code>{}</code></p><p>modules {}</p><p><a href=\".\">build requests</a></p></section>{}",
        support_html_head_chirho("app build request preview"),
        escape_html_chirho(app_chirho),
        preview_chirho.existing_app_chirho,
        preview_chirho.no_store_chirho,
        preview_chirho.candidate_request_cost_token_chirho,
        escape_html_chirho(&preview_chirho.request_payload_hash_chirho.0),
        escape_html_chirho(&preview_chirho.idempotency_key_hash_chirho.0),
        app_build_request_module_list_chirho(&preview_chirho.requested_module_ids_chirho),
        support_html_tail_chirho(),
    )
}

fn app_build_request_record_html_chirho(
    _kind_chirho: &str,
    _id_chirho: &str,
    app_chirho: &str,
    record_chirho: &app_build_request_chirho::AppBuildRequestRecordChirho,
) -> String {
    format!(
        "{}<section data-app-build-request-chirho=\"created\"><h1>app build request created</h1><p>seq #{} app <code>{}</code> status <code>{}</code></p><p>private-ref-marker <code>{}</code> payload <code>{}</code> idempotency <code>{}</code> resource-usage-seq <code>{}</code></p><p>modules {}</p><p><a href=\".\">build requests</a></p></section>{}",
        support_html_head_chirho("app build request created"),
        record_chirho.seq_chirho,
        escape_html_chirho(app_chirho),
        escape_html_chirho(&record_chirho.status_chirho),
        escape_html_chirho(&app_build_request_private_ref_marker_chirho(record_chirho)),
        escape_html_chirho(&record_chirho.request_payload_hash_chirho.0),
        escape_html_chirho(&record_chirho.idempotency_key_hash_chirho.0),
        escape_html_chirho(&app_build_request_resource_seq_label_chirho(record_chirho)),
        app_build_request_module_list_chirho(&record_chirho.requested_module_ids_chirho),
        support_html_tail_chirho(),
    )
}

fn app_build_request_list_html_chirho(
    root_chirho: &std::path::Path,
    owner_principal_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_chirho: &str,
) -> anyhow::Result<String> {
    let records_chirho = app_build_request_chirho::owner_app_build_request_records_chirho(
        root_chirho,
        owner_principal_chirho,
        app_chirho,
    )?;
    let mut html_chirho = format!(
        "{}<section data-app-build-request-chirho=\"list\"><h1>app build requests</h1><p>app <code>{}</code> safe request rows {}</p>",
        support_html_head_chirho("app build requests"),
        escape_html_chirho(app_chirho),
        records_chirho.len(),
    );
    if records_chirho.is_empty() {
        html_chirho.push_str("<p>No app build requests recorded for this app.</p>");
    } else {
        html_chirho.push_str("<ol>");
        for record_chirho in &records_chirho {
            html_chirho.push_str(&format!(
                "<li data-app-build-request-row-chirho=\"{}\">seq #{} status <code>{}</code> private-ref-marker <code>{}</code> payload <code>{}</code> resource-usage-seq <code>{}</code> modules {}</li>",
                record_chirho.seq_chirho,
                record_chirho.seq_chirho,
                escape_html_chirho(&record_chirho.status_chirho),
                escape_html_chirho(&app_build_request_private_ref_marker_chirho(record_chirho)),
                escape_html_chirho(&record_chirho.request_payload_hash_chirho.0),
                escape_html_chirho(&app_build_request_resource_seq_label_chirho(record_chirho)),
                app_build_request_module_list_chirho(&record_chirho.requested_module_ids_chirho),
            ));
        }
        html_chirho.push_str("</ol>");
    }
    let _ = (kind_chirho, id_chirho, app_chirho);
    html_chirho.push_str(&format!("</section>{}", support_html_tail_chirho(),));
    Ok(html_chirho)
}
