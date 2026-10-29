// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::{
    ensure_owner_controls_app_chirho, escape_html_chirho, redirect_chirho,
    support_html_head_chirho, support_html_tail_chirho, AppStateChirho,
};
use axum::{
    extract::{Form, Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_chirho::{app_chirho, privacy_chirho, query_chirho, versioned_chirho};
use serde::Deserialize;

#[derive(Clone, Debug)]
struct AppStatePrivateBlobRefChirho {
    subject_chirho: String,
    blob_chirho: privacy_chirho::PrivateBlobRefChirho,
}
#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppStateRollbackRequestChirho {
    pub(super) to_chirho: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct AppStateRevealRequestChirho {
    pub(super) key_chirho: String,
}

pub(super) async fn app_state_get_chirho(
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
    match app_state_html_chirho(
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
        Err(e_chirho) => app_state_action_error_response_chirho(e_chirho),
    }
}

pub(super) async fn app_state_rollback_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho, app_chirho)): AxPath<(String, String, String)>,
    Form(req_chirho): Form<AppStateRollbackRequestChirho>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    if let Some(response_chirho) = state_chirho
        .runtime_chirho
        .require_owner_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    match rollback_app_state_view_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        &principal_chirho,
        &app_chirho,
        req_chirho.to_chirho,
    ) {
        Ok(_) => redirect_chirho(&app_state_url_chirho(&kind_chirho, &id_chirho, &app_chirho)),
        Err(e_chirho) => app_state_action_error_response_chirho(e_chirho),
    }
}

pub(super) async fn app_state_reveal_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    AxPath((kind_chirho, id_chirho, app_chirho)): AxPath<(String, String, String)>,
    Form(req_chirho): Form<AppStateRevealRequestChirho>,
) -> Response {
    let principal_chirho = format!("{kind_chirho}/{id_chirho}");
    if let Some(response_chirho) = state_chirho
        .runtime_chirho
        .require_owner_session_chirho(&headers_chirho, &principal_chirho)
    {
        return response_chirho;
    }
    match app_state_reveal_html_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        &principal_chirho,
        &kind_chirho,
        &id_chirho,
        &app_chirho,
        &req_chirho.key_chirho,
    ) {
        Ok(html_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html_chirho,
        )
            .into_response(),
        Err(e_chirho) => app_state_action_error_response_chirho(e_chirho),
    }
}

pub(super) fn rollback_app_state_view_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    app_chirho: &str,
    to_chirho: u64,
) -> anyhow::Result<()> {
    ensure_owner_controls_app_chirho(root_chirho, owner_chirho, app_chirho)?;
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )?;
    let current_view_chirho = store_chirho.current_view_chirho()?;
    if to_chirho > current_view_chirho {
        anyhow::bail!("cannot roll app state forward from v{current_view_chirho} to v{to_chirho}");
    }
    store_chirho.rollback_to_chirho(to_chirho)?;
    drop(store_chirho);
    // Incremental rollback: refresh applies only the changed-key delta between the projection cursor
    // and the rolled-back view (O(delta)), landing byte-identical to the old full project_chirho.
    query_chirho::refresh_incremental_chirho(root_chirho)?;
    Ok(())
}

fn app_state_html_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_chirho: &str,
) -> anyhow::Result<String> {
    ensure_owner_controls_app_chirho(root_chirho, owner_chirho, app_chirho)?;
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )?;
    let current_view_chirho = store_chirho.current_view_chirho()?;
    let rows_chirho = safe_app_state_rows_chirho(&store_chirho, app_chirho)?;
    let rollback_one_chirho = current_view_chirho.saturating_sub(1);
    let rollback_button_chirho = if current_view_chirho > 0 {
        format!(
            "<form method=\"post\" action=\"{}/rollback-chirho\"><input type=\"hidden\" name=\"to_chirho\" value=\"{}\"><button type=\"submit\">Rollback one version</button></form>",
            app_state_url_chirho(kind_chirho, id_chirho, app_chirho),
            rollback_one_chirho
        )
    } else {
        String::new()
    };
    let mut rows_html_chirho = String::new();
    for (key_chirho, value_chirho) in rows_chirho {
        let value_text_chirho = String::from_utf8_lossy(&value_chirho);
        let reveal_form_chirho = if app_state_private_blob_ref_for_app_row_chirho(
            root_chirho,
            app_chirho,
            &value_chirho,
        )
        .is_ok()
        {
            format!(
                "<form method=\"post\" action=\"{}/reveal-chirho\"><input type=\"hidden\" name=\"key_chirho\" value=\"{}\"><button type=\"submit\">Reveal private body</button></form>",
                app_state_url_chirho(kind_chirho, id_chirho, app_chirho),
                escape_html_chirho(&key_chirho)
            )
        } else {
            String::new()
        };
        rows_html_chirho.push_str(&format!(
            "<li><code>{}</code>{}<pre>{}</pre></li>\n",
            escape_html_chirho(&key_chirho),
            reveal_form_chirho,
            escape_html_chirho(&value_text_chirho)
        ));
    }
    if rows_html_chirho.is_empty() {
        rows_html_chirho.push_str("<li>(no safe app rows at this view)</li>\n");
    }
    Ok(format!(
        "{}<p><a href=\"/\">home</a></p>\n<h1>app state: {}</h1>\n\
<p>owner <code>{}</code></p>\n<p>current store view: <code>v{}</code></p>\n\
<p>This prototype rollback moves the whole versioned store view, then rebuilds the disposable query projection. It is not a prefix-only transaction.</p>\n\
{}\
<form method=\"post\" action=\"{}/rollback-chirho\"><label>rollback to version <input name=\"to_chirho\" type=\"number\" min=\"0\" max=\"{}\" value=\"{}\"></label><button type=\"submit\">Rollback</button></form>\n\
<h2>Safe app rows</h2>\n<ul>\n{}</ul>\n{}",
        support_html_head_chirho("app state"),
        escape_html_chirho(app_chirho),
        escape_html_chirho(owner_chirho),
        current_view_chirho,
        rollback_button_chirho,
        app_state_url_chirho(kind_chirho, id_chirho, app_chirho),
        current_view_chirho,
        rollback_one_chirho,
        rows_html_chirho,
        support_html_tail_chirho()
    ))
}

pub(super) fn app_state_reveal_html_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    kind_chirho: &str,
    id_chirho: &str,
    app_chirho: &str,
    key_chirho: &str,
) -> anyhow::Result<String> {
    ensure_owner_controls_app_chirho(root_chirho, owner_chirho, app_chirho)?;
    if !safe_app_state_key_chirho(app_chirho, key_chirho) {
        anyhow::bail!("app-state reveal key must be inside a safe app-state prefix");
    }
    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )?;
    let Some(value_chirho) = store_chirho.get_chirho(key_chirho)? else {
        anyhow::bail!("safe app row '{key_chirho}' not found at current view");
    };
    let contact_blob_chirho =
        app_state_private_blob_ref_for_app_row_chirho(root_chirho, app_chirho, &value_chirho)?;
    let plaintext_chirho =
        privacy_chirho::load_private_blob_chirho(root_chirho, &contact_blob_chirho.blob_chirho)?;
    privacy_chirho::append_privacy_access_record_chirho(
        root_chirho,
        &contact_blob_chirho.subject_chirho,
        owner_chirho,
        app_chirho,
        key_chirho,
        app_state_reveal_purpose_chirho(app_chirho),
        &contact_blob_chirho.blob_chirho,
    )?;
    let plaintext_text_chirho = String::from_utf8_lossy(&plaintext_chirho);
    Ok(format!(
        "{}<p><a href=\"{}\">app state</a></p>\n<h1>governed private blob reveal</h1>\n\
<p>owner <code>{}</code></p>\n<p>app <code>{}</code></p>\n<p>row <code>{}</code></p>\n\
<p>subject <code>{}</code></p>\n\
<p>This page is owner-session gated and decrypts the private blob only for inspection. The plaintext is not written back to the app state row.</p>\n\
<pre>{}</pre>\n{}",
        support_html_head_chirho("private contact reveal"),
        app_state_url_chirho(kind_chirho, id_chirho, app_chirho),
        escape_html_chirho(owner_chirho),
        escape_html_chirho(app_chirho),
        escape_html_chirho(key_chirho),
        escape_html_chirho(&contact_blob_chirho.subject_chirho),
        escape_html_chirho(&plaintext_text_chirho),
        support_html_tail_chirho()
    ))
}

fn safe_app_state_rows_chirho(
    store_chirho: &versioned_chirho::VersionedStoreChirho,
    app_chirho: &str,
) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    Ok(store_chirho
        .current_entries_chirho()?
        .into_iter()
        .filter(|(key_chirho, _value_chirho)| safe_app_state_key_chirho(app_chirho, key_chirho))
        .collect())
}

fn app_state_private_blob_ref_for_app_row_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    value_chirho: &[u8],
) -> anyhow::Result<AppStatePrivateBlobRefChirho> {
    let private_ref_chirho = app_state_private_blob_ref_from_row_chirho(root_chirho, value_chirho)?;
    ensure_private_ref_subject_matches_app_chirho(app_chirho, &private_ref_chirho.subject_chirho)?;
    Ok(private_ref_chirho)
}

fn ensure_private_ref_subject_matches_app_chirho(
    app_chirho: &str,
    subject_chirho: &str,
) -> anyhow::Result<()> {
    app_chirho::validate_app_name_chirho(app_chirho)?;
    let expected_prefix_chirho = format!("app/{app_chirho}/");
    if !subject_chirho.starts_with(&expected_prefix_chirho) {
        anyhow::bail!(
            "safe app row private blob subject '{subject_chirho}' is not scoped under {expected_prefix_chirho}"
        );
    }
    Ok(())
}

/// A row sealed by the F4 write door carries the inner safe-envelope labels in its bounded safe
/// metadata, so the reveal path reads the INNER person blob straight from the metadata and never
/// needs to unseal the outer envelope. Bounding happened at seal time; every check below (subject
/// validation, blob parse, privacy-log coverage, row-subject binding) still runs unchanged on the
/// inner ref. Owner-gated unseal of an OPAQUE sealed row is S4's surface, not this shim.
fn inner_safe_envelope_from_sealed_row_chirho(value_chirho: &[u8]) -> Option<serde_json::Value> {
    let sealed_chirho =
        match cairn_chirho::store_seal_chirho::detect_sealed_store_value_chirho(value_chirho) {
            Ok(cairn_chirho::store_seal_chirho::StoreValueViewChirho::SealedChirho(
                sealed_chirho,
            )) => sealed_chirho,
            _ => return None,
        };
    let mut inner_chirho = serde_json::Map::new();
    for field_chirho in ["schema_chirho", "subject_chirho"] {
        inner_chirho.insert(
            field_chirho.to_string(),
            serde_json::Value::String(
                sealed_chirho
                    .safe_metadata_chirho
                    .get(field_chirho)?
                    .clone(),
            ),
        );
    }
    let blob_chirho: serde_json::Value =
        serde_json::from_str(sealed_chirho.safe_metadata_chirho.get("blob_chirho")?).ok()?;
    inner_chirho.insert("blob_chirho".to_string(), blob_chirho);
    Some(serde_json::Value::Object(inner_chirho))
}

fn app_state_private_blob_ref_from_row_chirho(
    root_chirho: &std::path::Path,
    value_chirho: &[u8],
) -> anyhow::Result<AppStatePrivateBlobRefChirho> {
    if let Some(inner_chirho) = inner_safe_envelope_from_sealed_row_chirho(value_chirho) {
        return app_state_private_blob_ref_from_safe_envelope_chirho(root_chirho, inner_chirho);
    }
    let value_chirho: serde_json::Value = serde_json::from_slice(value_chirho)?;
    app_state_private_blob_ref_from_safe_envelope_chirho(root_chirho, value_chirho)
}

fn app_state_private_blob_ref_from_safe_envelope_chirho(
    root_chirho: &std::path::Path,
    value_chirho: serde_json::Value,
) -> anyhow::Result<AppStatePrivateBlobRefChirho> {
    let schema_chirho = value_chirho
        .get("schema_chirho")
        .and_then(|schema_chirho| schema_chirho.as_str())
        .unwrap_or_default();
    match schema_chirho {
        "app-private-input-ref-v1-chirho"
        | "contact-record-v1-chirho"
        | "perffection-intake-record-v1-chirho" => {
            let subject_chirho = value_chirho
                .get("subject_chirho")
                .and_then(|subject_chirho| subject_chirho.as_str())
                .ok_or_else(|| anyhow::anyhow!("safe app row has no subject_chirho"))?;
            privacy_chirho::validate_privacy_subject_chirho(subject_chirho)?;
            let blob_chirho = value_chirho
                .get("blob_chirho")
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("safe app row has no private blob ref"))?;
            let blob_chirho: privacy_chirho::PrivateBlobRefChirho =
                serde_json::from_value(blob_chirho)?;
            privacy_chirho::verify_private_blob_ref_subject_chirho(
                root_chirho,
                "safe app row",
                &blob_chirho,
                subject_chirho,
            )?;
            Ok(AppStatePrivateBlobRefChirho {
                subject_chirho: subject_chirho.to_string(),
                blob_chirho,
            })
        }
        _ => anyhow::bail!("safe app row schema cannot be revealed: '{schema_chirho}'"),
    }
}

fn safe_app_state_key_chirho(app_chirho: &str, key_chirho: &str) -> bool {
    (app_chirho == "contact" && contact_store_key_chirho(key_chirho))
        || (app_chirho == "perffection" && perffection_intake_store_key_chirho(key_chirho))
        || app_prefixed_store_key_chirho(app_chirho, key_chirho)
}

pub(super) fn contact_store_key_chirho(key_chirho: &str) -> bool {
    key_chirho == "contacts-chirho"
        || key_chirho
            .strip_prefix("contacts-chirho")
            .is_some_and(|rest_chirho| rest_chirho.starts_with('/'))
}

fn perffection_intake_store_key_chirho(key_chirho: &str) -> bool {
    key_chirho == "perffection-intake-chirho"
        || key_chirho
            .strip_prefix("perffection-intake-chirho")
            .is_some_and(|rest_chirho| rest_chirho.starts_with('/'))
}

fn app_prefixed_store_key_chirho(app_chirho: &str, key_chirho: &str) -> bool {
    if app_chirho::validate_app_name_chirho(app_chirho).is_err() {
        return false;
    }
    key_chirho == app_chirho
        || key_chirho
            .strip_prefix(app_chirho)
            .is_some_and(|rest_chirho| rest_chirho.starts_with('-') || rest_chirho.starts_with('/'))
}

fn app_state_reveal_purpose_chirho(app_chirho: &str) -> &'static str {
    if app_chirho == "contact" {
        "owner-contact-reveal-chirho"
    } else {
        "owner-app-state-reveal-chirho"
    }
}

pub(super) fn app_state_url_chirho(kind_chirho: &str, id_chirho: &str, app_chirho: &str) -> String {
    format!("/app-state-chirho/{kind_chirho}/{id_chirho}/{app_chirho}")
}

pub(super) fn app_state_action_error_response_chirho(error_chirho: anyhow::Error) -> Response {
    let message_chirho = error_chirho.to_string();
    let status_chirho =
        if message_chirho.contains("does not control") || message_chirho.contains("has no owner") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        };
    (
        status_chirho,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "{}<h1>app state error</h1><pre>{}</pre>{}",
            support_html_head_chirho("app state error"),
            escape_html_chirho(&message_chirho),
            support_html_tail_chirho()
        ),
    )
        .into_response()
}
