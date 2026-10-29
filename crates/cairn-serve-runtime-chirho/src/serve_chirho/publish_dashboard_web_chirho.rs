// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Admin dashboard and publish HTTP routes.

use super::{bearer_token_chirho, escape_html_chirho, AppStateChirho};
use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cairn_chirho::{
    app_chirho, blessed_chirho, identity_chirho, publish_chirho, refs_chirho, versioned_chirho,
};

/// GET /dashboard-chirho - an admin-gated (no JS) observability overview: deployed apps, the
/// signed blessed-effect set, the store view, and the recent ref timeline.
pub(super) async fn dashboard_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
) -> Response {
    if let Some(response_chirho) =
        require_admin_dashboard_auth_chirho(&headers_chirho, &state_chirho.publish_token_chirho)
    {
        return response_chirho;
    }
    match dashboard_html_chirho(state_chirho.runtime_chirho.root_path_chirho()) {
        Ok(html_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html_chirho,
        )
            .into_response(),
        Err(error_chirho) => dashboard_error_response_chirho(
            StatusCode::BAD_REQUEST,
            "dashboard verification failed",
            &error_chirho.to_string(),
        ),
    }
}

fn require_admin_dashboard_auth_chirho(
    headers_chirho: &HeaderMap,
    publish_token_chirho: &str,
) -> Option<Response> {
    if publish_token_chirho.trim().is_empty() {
        return Some(dashboard_error_response_chirho(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin dashboard disabled",
            "configure a non-empty admin bearer token before viewing global diagnostics",
        ));
    }
    let Some(token_chirho) = bearer_token_chirho(headers_chirho) else {
        return Some(dashboard_error_response_chirho(
            StatusCode::UNAUTHORIZED,
            "admin bearer required",
            "provide a Bearer token to view global diagnostics",
        ));
    };
    if token_chirho != publish_token_chirho {
        return Some(dashboard_error_response_chirho(
            StatusCode::FORBIDDEN,
            "admin bearer invalid",
            "the supplied Bearer token is not authorized for global diagnostics",
        ));
    }
    None
}

fn dashboard_error_response_chirho(
    status_chirho: StatusCode,
    title_chirho: &str,
    message_chirho: &str,
) -> Response {
    (
        status_chirho,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<!doctype html>\n<meta charset=\"utf-8\">\n<title>cairn-chirho dashboard</title>\n<body>\n<h1>{}</h1>\n<p>{}</p>\n</body>\n",
            escape_html_chirho(title_chirho),
            escape_html_chirho(message_chirho)
        ),
    )
        .into_response()
}

fn dashboard_html_chirho(root_chirho: &std::path::Path) -> Result<String> {
    let mut html_chirho = String::from(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>cairn-chirho dashboard</title>\n<body>\n<h1>cairn-chirho — dashboard</h1>\n",
    );

    html_chirho.push_str("<h2>Apps</h2>\n<ul>\n");
    let apps_chirho = app_chirho::verified_deployed_apps_chirho(root_chirho)?;
    if apps_chirho.is_empty() {
        html_chirho.push_str("<li>(none)</li>\n");
    }
    for app_chirho in &apps_chirho {
        let Some(dag_chirho) = &app_chirho.dag_chirho else {
            continue;
        };
        let owner_chirho = app_chirho
            .owner_principal_chirho
            .as_deref()
            .unwrap_or("(unowned)");
        let name_chirho = &app_chirho.app_chirho;
        let hash_chirho = &dag_chirho.0;
        html_chirho.push_str(&format!(
            "<li><code>{}</code> &rarr; {} owner={} (<a href=\"/app-chirho/{name_chirho}\">/app-chirho/{name_chirho}</a>)</li>\n",
            escape_html_chirho(name_chirho),
            &hash_chirho[..hash_chirho.len().min(16)],
            escape_html_chirho(owner_chirho)
        ));
    }
    html_chirho.push_str("</ul>\n");

    let identity_count_chirho = identity_chirho::verify_identities_chirho(root_chirho)?;
    html_chirho.push_str(&format!(
        "<h2>Identities</h2>\n<p>{identity_count_chirho} verified principal record(s); <a href=\"/auth-chirho/register-chirho\">register</a></p>\n"
    ));

    html_chirho.push_str("<h2>Blessed effects</h2>\n<ul>\n");
    if let Ok(registry_chirho) = blessed_chirho::signed_registry_chirho(root_chirho) {
        for kind_chirho in &registry_chirho.kinds_chirho {
            html_chirho.push_str(&format!("<li>{}</li>\n", escape_html_chirho(kind_chirho)));
        }
        html_chirho.push_str(&format!(
            "</ul>\n<p>registry signature: {}</p>\n",
            if blessed_chirho::verify_registry_chirho(&registry_chirho) {
                "VALID"
            } else {
                "INVALID"
            }
        ));
    } else {
        html_chirho.push_str("</ul>\n");
    }

    let versioned_path_chirho = root_chirho.join("versioned-chirho.redb");
    if versioned_path_chirho.exists() {
        if let Ok(store_chirho) =
            versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho)
        {
            if let Ok(view_chirho) = store_chirho.current_view_chirho() {
                html_chirho.push_str(&format!(
                    "<h2>Store</h2>\n<p>current view: v{view_chirho}</p>\n"
                ));
            }
        }
    }

    html_chirho.push_str("<h2>Timeline (recent ref changes)</h2>\n<ul>\n");
    if let Ok(reflog_chirho) = refs_chirho::reflog_chirho(root_chirho) {
        for entry_chirho in reflog_chirho.iter().rev().take(20) {
            html_chirho.push_str(&format!(
                "<li><code>{}</code> &rarr; {} ({})</li>\n",
                escape_html_chirho(&entry_chirho.branch_chirho),
                &entry_chirho.to_chirho.0[..entry_chirho.to_chirho.0.len().min(12)],
                escape_html_chirho(&entry_chirho.reason_chirho)
            ));
        }
    }
    html_chirho.push_str("</ul>\n</body>\n");
    Ok(html_chirho)
}

/// POST /publish-chirho - install a dagapp package (admin token or owner session Bearer auth).
pub(super) async fn publish_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    Json(package_chirho): Json<publish_chirho::PublishPackageChirho>,
) -> Response {
    if let Some(response_chirho) = require_publish_auth_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        &headers_chirho,
        &package_chirho,
        &state_chirho.publish_token_chirho,
    ) {
        return response_chirho;
    }
    match publish_chirho::install_package_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        &package_chirho,
    ) {
        Ok(count_chirho) => (
            StatusCode::OK,
            format!(
                "published '{}' ({count_chirho} objects) -> /app-chirho/{}\n",
                package_chirho.name_chirho, package_chirho.name_chirho
            ),
        )
            .into_response(),
        Err(e_chirho) => (StatusCode::BAD_REQUEST, format!("error: {e_chirho}\n")).into_response(),
    }
}

pub(super) fn require_publish_auth_chirho(
    root_chirho: &std::path::Path,
    headers_chirho: &HeaderMap,
    package_chirho: &publish_chirho::PublishPackageChirho,
    publish_token_chirho: &str,
) -> Option<Response> {
    let token_chirho = match bearer_token_chirho(headers_chirho) {
        Some(token_chirho) => token_chirho,
        None => {
            return Some(
                (
                    StatusCode::UNAUTHORIZED,
                    "unauthorized: Bearer token required\n",
                )
                    .into_response(),
            )
        }
    };
    if !publish_token_chirho.is_empty() && token_chirho == publish_token_chirho {
        return None;
    }
    if package_chirho.owner_chirho.trim().is_empty() {
        return Some(
            (StatusCode::BAD_REQUEST, "error: owner_chirho is required\n").into_response(),
        );
    }
    match identity_chirho::validate_session_token_chirho(
        root_chirho,
        &package_chirho.owner_chirho,
        token_chirho,
    ) {
        // AUTHORITY BEFORE DURABLE WRITE. The session was validated against
        // `package_chirho.owner_chirho`, so that principal IS the authenticated caller on this
        // branch. Its authoritative kind is checked HERE, before `install_package_chirho`, because
        // the equivalent check inside `deploy_app_chirho` refuses the same request only AFTER every
        // declared object is durably in CAS — measured at d79da456: a user-kind session publishing
        // a valid package got 400 "app owner must be an owner principal" with both objects written
        // and no rollback.
        //
        // KIND LOOKUP ONLY, deliberately NOT `require_owner_session_chirho`: that helper first
        // re-validates the session from headers through the cookie path, while this route has
        // already validated a BEARER against the package owner. Re-validating through the other
        // credential path would refuse valid publish bearers.
        //
        // The configured publish-token branch above returns before reaching here and is unchanged.
        // The late `deploy_app_chirho` check is left in place as defence in depth.
        Ok(Some(_session_chirho)) => {
            // THE VERIFIED authority fact, applied before install_package_chirho.
            //
            // Deliberately app_chirho::ensure_owner_principal_chirho and NOT a raw
            // find_identity_chirho lookup. The raw path reads load_identities_chirho, which checks
            // the schema string only — no signature, no dense sequence. A user row edited to
            // `owner` WITHOUT RE-SIGNING passes the raw read while session validation still
            // succeeds on the unchanged public key, so a raw early check would admit the CAS write
            // and leave the refusal to the verified late gate. That is the exact ordering defect
            // this gate exists to close, reintroduced one layer up.
            //
            // This is the SAME check the late deploy path performs, over the same cached verified
            // map, so it is genuinely the authority fact moved earlier rather than a weaker
            // approximation of it.
            match app_chirho::ensure_owner_principal_chirho(
                root_chirho,
                &package_chirho.owner_chirho,
            ) {
                Ok(()) => None,
                Err(error_chirho) => Some(
                    (
                        StatusCode::FORBIDDEN,
                        format!("unauthorized: {error_chirho}\n"),
                    )
                        .into_response(),
                ),
            }
        }
        Ok(None) => Some(
            (
                StatusCode::FORBIDDEN,
                "unauthorized: invalid owner session\n",
            )
                .into_response(),
        ),
        // Before authentication: the caller's own guess reached the session check, so the answer is a
        // fixed identity; a typed resource exhaustion answers 503.
        Err(e_chirho) => Some(super::public_error_chirho::public_error_response_chirho(
            "publish-session-chirho",
            super::public_error_chirho::classify_non_dag_chirho(
                &e_chirho,
                StatusCode::BAD_REQUEST,
                "session-check-failed-chirho",
            ),
            headers_chirho,
            None,
        )),
    }
}
