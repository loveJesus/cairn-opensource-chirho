// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::{
    ensure_owner_controls_app_chirho, escape_html_chirho, parse_review_hash_chirho,
    support_html_head_chirho, support_html_tail_chirho, AppStateChirho,
};
use axum::{
    extract::{Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{app_chirho, resource_chirho};
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
struct ResourcePolicyAuthorRequestChirho {
    #[serde(default)]
    policy_json_chirho: String,
    #[serde(default)]
    expected_previous_chirho: String,
    #[serde(default)]
    reviewed_policy_hash_chirho: String,
    #[serde(default)]
    policy_at_ms_chirho: u64,
}

pub(super) async fn resource_policy_get_chirho(
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
    match resource_policy_show_html_chirho(
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
        Err(e_chirho) => resource_policy_action_error_response_chirho(e_chirho),
    }
}

pub(super) async fn resource_policy_preview_post_chirho(
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
    let req_chirho = match parse_resource_policy_author_request_chirho(request_chirho).await {
        Ok(req_chirho) => req_chirho,
        Err(e_chirho) => return resource_policy_action_error_response_chirho(e_chirho),
    };
    match resource_policy_preview_html_chirho(
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
        Err(e_chirho) => resource_policy_action_error_response_chirho(e_chirho),
    }
}

pub(super) async fn resource_policy_apply_post_chirho(
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
    let req_chirho = match parse_resource_policy_author_request_chirho(request_chirho).await {
        Ok(req_chirho) => req_chirho,
        Err(e_chirho) => return resource_policy_action_error_response_chirho(e_chirho),
    };
    match resource_policy_apply_html_chirho(
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
        Err(e_chirho) => resource_policy_action_error_response_chirho(e_chirho),
    }
}

fn current_ms_for_http_chirho() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn optional_resource_policy_hash_value_chirho(hash_chirho: &Option<HashChirho>) -> String {
    hash_chirho
        .as_ref()
        .map(|hash_chirho| hash_chirho.0.clone())
        .unwrap_or_default()
}

fn parse_optional_resource_policy_hash_chirho(
    label_chirho: &str,
    value_chirho: &str,
) -> anyhow::Result<Option<HashChirho>> {
    let trimmed_chirho = value_chirho.trim();
    if trimmed_chirho.is_empty() || trimmed_chirho == "(none)" {
        return Ok(None);
    }
    parse_review_hash_chirho(label_chirho, trimmed_chirho).map(Some)
}

fn resource_policy_action_error_response_chirho(error_chirho: anyhow::Error) -> Response {
    let message_chirho = error_chirho.to_string();
    let status_chirho = if message_chirho.contains("expected previous hash mismatch") {
        StatusCode::CONFLICT
    } else if message_chirho.contains("does not control")
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
            "{}<h1>resource policy error</h1><pre>{}</pre>{}",
            support_html_head_chirho("resource policy error"),
            escape_html_chirho(&message_chirho),
            support_html_tail_chirho()
        ),
    )
        .into_response()
}

async fn parse_resource_policy_author_request_chirho(
    request_chirho: axum::http::Request<axum::body::Body>,
) -> anyhow::Result<ResourcePolicyAuthorRequestChirho> {
    const MAX_RESOURCE_POLICY_FORM_BYTES_CHIRHO: usize = 128 * 1024;
    let bytes_chirho = axum::body::to_bytes(
        request_chirho.into_body(),
        MAX_RESOURCE_POLICY_FORM_BYTES_CHIRHO + 1,
    )
    .await
    .map_err(|_| anyhow::anyhow!("read resource policy form body failed"))?;
    if bytes_chirho.len() > MAX_RESOURCE_POLICY_FORM_BYTES_CHIRHO {
        anyhow::bail!("resource policy form body too large");
    }
    let mut req_chirho = ResourcePolicyAuthorRequestChirho::default();
    for (key_chirho, value_chirho) in url::form_urlencoded::parse(&bytes_chirho) {
        match key_chirho.as_ref() {
            "policy_json_chirho" => req_chirho.policy_json_chirho = value_chirho.into_owned(),
            "expected_previous_chirho" => {
                req_chirho.expected_previous_chirho = value_chirho.into_owned()
            }
            "reviewed_policy_hash_chirho" => {
                req_chirho.reviewed_policy_hash_chirho = value_chirho.into_owned()
            }
            "policy_at_ms_chirho" => {
                req_chirho.policy_at_ms_chirho = value_chirho
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("policy_at_ms_chirho must be a u64"))?
            }
            _ => {}
        }
    }
    Ok(req_chirho)
}

fn resource_policy_input_from_json_chirho(
    req_chirho: &ResourcePolicyAuthorRequestChirho,
) -> anyhow::Result<resource_chirho::ResourcePolicyInputChirho> {
    if req_chirho.policy_json_chirho.trim().is_empty() {
        anyhow::bail!("policy_json_chirho is required");
    }
    serde_json::from_str(&req_chirho.policy_json_chirho)
        .map_err(|e_chirho| anyhow::anyhow!("policy_json_chirho is invalid JSON: {e_chirho}"))
}

fn resource_policy_input_from_policy_chirho(
    policy_chirho: &resource_chirho::AppResourcePolicyChirho,
) -> resource_chirho::ResourcePolicyInputChirho {
    resource_chirho::ResourcePolicyInputChirho {
        meters_chirho: policy_chirho.meters_chirho.clone(),
        actions_chirho: policy_chirho.actions_chirho.clone(),
    }
}

fn verify_resource_policy_authoring_surface_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
) -> anyhow::Result<Option<(HashChirho, resource_chirho::AppResourcePolicyChirho)>> {
    resource_chirho::verify_resource_policy_unsets_chirho(root_chirho)?;
    let current_chirho = resource_chirho::current_resource_policy_chirho(root_chirho, app_chirho)?;
    if let Some((hash_chirho, _policy_chirho)) = &current_chirho {
        let records_chirho =
            resource_chirho::resource_policy_history_chirho(root_chirho, app_chirho)?;
        if !records_chirho
            .iter()
            .any(|record_chirho| record_chirho.resource_policy_chirho == *hash_chirho)
        {
            anyhow::bail!("current resource policy is not backed by signed policy evidence");
        }
    }
    Ok(current_chirho)
}

fn ensure_resource_policy_owner_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    app_chirho: &str,
) -> anyhow::Result<()> {
    app_chirho::validate_app_name_chirho(app_chirho)?;
    ensure_owner_controls_app_chirho(root_chirho, owner_chirho, app_chirho)
}

fn resource_policy_url_chirho(kind_chirho: &str, id_chirho: &str, app_chirho: &str) -> String {
    format!("/resource-policy-chirho/{kind_chirho}/{id_chirho}/{app_chirho}")
}

fn resource_policy_overage_label_chirho(
    overage_chirho: &resource_chirho::ResourceOverageChirho,
) -> String {
    match overage_chirho {
        resource_chirho::ResourceOverageChirho::FailClosedChirho => "FailClosedChirho".to_string(),
        resource_chirho::ResourceOverageChirho::RouteChirho {
            route_chirho,
            forward_request_body_chirho,
        } => format!(
            "RouteChirho route={} forward_request_body_chirho={}",
            route_chirho, forward_request_body_chirho
        ),
    }
}

fn resource_policy_charges_label_chirho(
    charges_chirho: &[resource_chirho::ResourceChargeChirho],
) -> String {
    charges_chirho
        .iter()
        .map(|charge_chirho| {
            format!(
                "{}:{}",
                charge_chirho.resource_chirho, charge_chirho.amount_chirho
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn resource_policy_warning_html_chirho(
    policy_chirho: &resource_chirho::AppResourcePolicyChirho,
) -> String {
    let charged_anonymous_resources_chirho: std::collections::BTreeSet<String> = policy_chirho
        .actions_chirho
        .iter()
        .filter(|action_chirho| action_chirho.allow_anonymous_chirho)
        .flat_map(|action_chirho| {
            action_chirho
                .charges_chirho
                .iter()
                .map(|charge_chirho| charge_chirho.resource_chirho.clone())
        })
        .collect();
    let risky_cumulative_failclosed_chirho =
        policy_chirho.meters_chirho.iter().any(|meter_chirho| {
            charged_anonymous_resources_chirho.contains(&meter_chirho.resource_chirho)
                && meter_chirho.window_ms_chirho.is_none()
                && matches!(
                    meter_chirho.overage_chirho,
                    resource_chirho::ResourceOverageChirho::FailClosedChirho
                )
        });
    if risky_cumulative_failclosed_chirho {
        "<p class=\"err\" data-resource-policy-warning-chirho=\"anonymous-cumulative-failclosed\">Warning: anonymous traffic charged against a cumulative FailClosed meter can permanently exhaust the shared bucket. Prefer a recovering window_ms_chirho or a deliberate non-public policy.</p>\n".to_string()
    } else {
        "<p data-resource-policy-warning-chirho=\"none\">Windowed meters recover after window_ms_chirho; meters without window_ms_chirho are cumulative lifetime budgets.</p>\n".to_string()
    }
}

fn resource_policy_summary_html_chirho(
    policy_hash_chirho: &HashChirho,
    policy_chirho: &resource_chirho::AppResourcePolicyChirho,
) -> String {
    let mut html_chirho = String::new();
    html_chirho.push_str(&format!(
        "<p>policy hash <code>{}</code> | previous <code>{}</code> | at_ms {}</p>\n",
        escape_html_chirho(&policy_hash_chirho.0),
        escape_html_chirho(
            &policy_chirho
                .previous_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.clone())
                .unwrap_or_else(|| "(none)".to_string())
        ),
        policy_chirho.at_ms_chirho
    ));
    html_chirho.push_str(&resource_policy_warning_html_chirho(policy_chirho));
    html_chirho.push_str("<h2>Meters</h2>\n<table><thead><tr><th>resource</th><th>unit</th><th>stack</th><th>per-user</th><th>app</th><th>window_ms</th><th>overage</th></tr></thead><tbody>\n");
    for meter_chirho in &policy_chirho.meters_chirho {
        html_chirho.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape_html_chirho(&meter_chirho.resource_chirho),
            escape_html_chirho(&meter_chirho.unit_chirho),
            meter_chirho.stack_chirho.as_deref().map(escape_html_chirho).unwrap_or_else(|| "(none)".to_string()),
            meter_chirho.per_user_limit_chirho.map(|v_chirho| v_chirho.to_string()).unwrap_or_else(|| "(none)".to_string()),
            meter_chirho.app_limit_chirho.map(|v_chirho| v_chirho.to_string()).unwrap_or_else(|| "(none)".to_string()),
            meter_chirho.window_ms_chirho.map(|v_chirho| v_chirho.to_string()).unwrap_or_else(|| "(none)".to_string()),
            escape_html_chirho(&resource_policy_overage_label_chirho(&meter_chirho.overage_chirho)),
        ));
    }
    html_chirho.push_str("</tbody></table>\n<h2>Actions</h2>\n<table><thead><tr><th>section</th><th>action</th><th>effect</th><th>anonymous</th><th>charges</th></tr></thead><tbody>\n");
    for action_chirho in &policy_chirho.actions_chirho {
        html_chirho.push_str(&format!(
            "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            escape_html_chirho(&action_chirho.section_chirho),
            escape_html_chirho(&action_chirho.action_chirho),
            action_chirho.effect_chirho.as_deref().map(escape_html_chirho).unwrap_or_else(|| "(none)".to_string()),
            action_chirho.allow_anonymous_chirho,
            escape_html_chirho(&resource_policy_charges_label_chirho(&action_chirho.charges_chirho)),
        ));
    }
    html_chirho.push_str("</tbody></table>\n");
    html_chirho
}

fn resource_policy_show_html_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_chirho: &str,
) -> anyhow::Result<String> {
    ensure_resource_policy_owner_chirho(root_chirho, owner_chirho, app_chirho)?;
    let current_chirho = verify_resource_policy_authoring_surface_chirho(root_chirho, app_chirho)?;
    let base_url_chirho = resource_policy_url_chirho(kind_chirho, id_chirho, app_chirho);
    let current_hash_chirho = current_chirho
        .as_ref()
        .map(|(hash_chirho, _policy_chirho)| hash_chirho.clone());
    let policy_input_json_chirho = match &current_chirho {
        Some((_hash_chirho, policy_chirho)) => {
            serde_json::to_string_pretty(&resource_policy_input_from_policy_chirho(policy_chirho))?
        }
        None => "{\n  \"meters_chirho\": [],\n  \"actions_chirho\": []\n}".to_string(),
    };
    let mut html_chirho = format!(
        "{}<section data-resource-policy-author-chirho=\"show\"><h1>resource policy</h1><p>app <code>{}</code> owner <code>{}</code></p>",
        support_html_head_chirho("resource policy"),
        escape_html_chirho(app_chirho),
        escape_html_chirho(owner_chirho),
    );
    match &current_chirho {
        Some((hash_chirho, policy_chirho)) => {
            html_chirho.push_str("<h2>Current reviewed policy</h2>\n");
            html_chirho.push_str(&resource_policy_summary_html_chirho(
                hash_chirho,
                policy_chirho,
            ));
            html_chirho.push_str(&format!(
                "<p>rollback ref: <code>resource-policy/{}</code> current <code>{}</code></p>\n",
                escape_html_chirho(app_chirho),
                escape_html_chirho(&hash_chirho.0),
            ));
        }
        None => html_chirho.push_str("<p>No current resource policy.</p>\n"),
    }
    html_chirho.push_str(&format!(
        "<h2>Preview a policy</h2>\n<form method=\"post\" action=\"{}/preview-chirho\"><input type=\"hidden\" name=\"expected_previous_chirho\" value=\"{}\"><label>ResourcePolicyInputChirho JSON<textarea name=\"policy_json_chirho\" rows=\"18\" cols=\"100\">{}</textarea></label><button type=\"submit\">Preview reviewed policy</button></form>",
        escape_html_chirho(&base_url_chirho),
        escape_html_chirho(&optional_resource_policy_hash_value_chirho(&current_hash_chirho)),
        escape_html_chirho(&policy_input_json_chirho),
    ));
    html_chirho.push_str("</section>");
    html_chirho.push_str(support_html_tail_chirho());
    Ok(html_chirho)
}

fn resource_policy_preview_html_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_chirho: &str,
    req_chirho: ResourcePolicyAuthorRequestChirho,
) -> anyhow::Result<String> {
    ensure_resource_policy_owner_chirho(root_chirho, owner_chirho, app_chirho)?;
    let current_chirho = verify_resource_policy_authoring_surface_chirho(root_chirho, app_chirho)?;
    let expected_previous_chirho = parse_optional_resource_policy_hash_chirho(
        "expected_previous_chirho",
        &req_chirho.expected_previous_chirho,
    )?;
    let current_hash_chirho = current_chirho
        .as_ref()
        .map(|(hash_chirho, _policy_chirho)| hash_chirho.clone());
    if current_hash_chirho != expected_previous_chirho {
        anyhow::bail!("resource policy expected previous hash mismatch");
    }
    let input_chirho = resource_policy_input_from_json_chirho(&req_chirho)?;
    let policy_at_ms_chirho = current_ms_for_http_chirho();
    let (policy_hash_chirho, policy_chirho) =
        resource_chirho::preview_resource_policy_from_input_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            input_chirho,
            policy_at_ms_chirho,
        )?;
    let base_url_chirho = resource_policy_url_chirho(kind_chirho, id_chirho, app_chirho);
    let mut html_chirho = format!(
        "{}<section data-resource-policy-author-chirho=\"preview\"><h1>resource policy preview</h1><p>app <code>{}</code> owner <code>{}</code></p>",
        support_html_head_chirho("resource policy preview"),
        escape_html_chirho(app_chirho),
        escape_html_chirho(owner_chirho),
    );
    html_chirho.push_str(&resource_policy_summary_html_chirho(
        &policy_hash_chirho,
        &policy_chirho,
    ));
    html_chirho.push_str("<p>This preview has not stored a policy object, moved a ref, or appended a signed policy record.</p>\n");
    html_chirho.push_str(&format!(
        "<form method=\"post\" action=\"{}/apply-chirho\"><input type=\"hidden\" name=\"expected_previous_chirho\" value=\"{}\"><input type=\"hidden\" name=\"reviewed_policy_hash_chirho\" value=\"{}\"><input type=\"hidden\" name=\"policy_at_ms_chirho\" value=\"{}\"><textarea hidden name=\"policy_json_chirho\">{}</textarea><button type=\"submit\">Apply exact reviewed policy</button></form>",
        escape_html_chirho(&base_url_chirho),
        escape_html_chirho(&optional_resource_policy_hash_value_chirho(&expected_previous_chirho)),
        escape_html_chirho(&policy_hash_chirho.0),
        policy_chirho.at_ms_chirho,
        escape_html_chirho(&req_chirho.policy_json_chirho),
    ));
    html_chirho.push_str(&format!(
        "<p><a href=\"{}\">back to resource policy</a></p>",
        escape_html_chirho(&base_url_chirho)
    ));
    html_chirho.push_str("</section>");
    html_chirho.push_str(support_html_tail_chirho());
    Ok(html_chirho)
}

fn resource_policy_apply_html_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_chirho: &str,
    req_chirho: ResourcePolicyAuthorRequestChirho,
) -> anyhow::Result<String> {
    ensure_resource_policy_owner_chirho(root_chirho, owner_chirho, app_chirho)?;
    let current_chirho = verify_resource_policy_authoring_surface_chirho(root_chirho, app_chirho)?;
    let expected_previous_chirho = parse_optional_resource_policy_hash_chirho(
        "expected_previous_chirho",
        &req_chirho.expected_previous_chirho,
    )?;
    let current_hash_chirho = current_chirho
        .as_ref()
        .map(|(hash_chirho, _policy_chirho)| hash_chirho.clone());
    if current_hash_chirho != expected_previous_chirho {
        anyhow::bail!("resource policy expected previous hash mismatch");
    }
    let reviewed_policy_hash_chirho = parse_review_hash_chirho(
        "reviewed_policy_hash_chirho",
        req_chirho.reviewed_policy_hash_chirho.trim(),
    )?;
    if req_chirho.policy_at_ms_chirho == 0 {
        anyhow::bail!("policy_at_ms_chirho is required");
    }
    let input_chirho = resource_policy_input_from_json_chirho(&req_chirho)?;
    let (hash_chirho, policy_chirho, record_chirho) =
        resource_chirho::set_resource_policy_from_input_checked_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            input_chirho,
            expected_previous_chirho.clone(),
            reviewed_policy_hash_chirho,
            req_chirho.policy_at_ms_chirho,
        )?;
    let base_url_chirho = resource_policy_url_chirho(kind_chirho, id_chirho, app_chirho);
    let mut html_chirho = format!(
        "{}<section data-resource-policy-author-chirho=\"applied\"><h1>resource policy applied</h1><p>app <code>{}</code> owner <code>{}</code> record #{} policy <code>{}</code></p>",
        support_html_head_chirho("resource policy applied"),
        escape_html_chirho(app_chirho),
        escape_html_chirho(owner_chirho),
        record_chirho.seq_chirho,
        escape_html_chirho(&hash_chirho.0),
    );
    html_chirho.push_str(&resource_policy_summary_html_chirho(
        &hash_chirho,
        &policy_chirho,
    ));
    html_chirho.push_str(&format!(
        "<p>rollback ref: <code>resource-policy/{}</code> previous <code>{}</code></p><p><a href=\"{}\">resource policy</a></p>",
        escape_html_chirho(app_chirho),
        escape_html_chirho(
            &expected_previous_chirho
                .as_ref()
                .map(|hash_chirho| hash_chirho.0.clone())
                .unwrap_or_else(|| "(none)".to_string())
        ),
        escape_html_chirho(&base_url_chirho),
    ));
    html_chirho.push_str("</section>");
    html_chirho.push_str(support_html_tail_chirho());
    Ok(html_chirho)
}
