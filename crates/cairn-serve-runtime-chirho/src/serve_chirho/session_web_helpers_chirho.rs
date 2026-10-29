// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

pub(super) fn redirect_chirho(location_chirho: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(LOCATION, location_chirho.to_string())],
        "",
    )
        .into_response()
}

pub(super) fn support_html_head_chirho(title_chirho: &str) -> String {
    format!(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{}</title>\n<style>body{{font:14px/1.45 system-ui,-apple-system,sans-serif;margin:1.5rem;max-width:76rem}}table{{border-collapse:collapse;width:100%;margin:.75rem 0 1.5rem}}th,td{{border-bottom:1px solid #ddd;text-align:left;padding:.45rem;vertical-align:top}}code,pre{{font-family:ui-monospace,SFMono-Regular,monospace}}pre{{white-space:pre-wrap;background:#f6f6f6;padding:.75rem;overflow:auto}}form{{margin:.35rem 0}}label{{display:inline-grid;gap:.25rem;margin-right:.6rem}}input,select,textarea,button{{font:inherit}}textarea{{min-width:28rem;max-width:100%}}.actions{{display:grid;gap:.75rem;max-width:46rem}}.err{{color:#b91c1c}}</style>\n<body>\n",
        escape_html_chirho(title_chirho)
    )
}

pub(super) fn support_html_tail_chirho() -> &'static str {
    "</body>\n"
}

pub(super) const AUTH_SESSION_COOKIE_CHIRHO: &str = "cairn_session_chirho";

pub(super) fn parse_review_hash_chirho(
    label_chirho: &str,
    value_chirho: &str,
) -> anyhow::Result<HashChirho> {
    if value_chirho.len() != 64
        || !value_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit())
    {
        anyhow::bail!("{label_chirho} must be a 64-character hex hash");
    }
    Ok(HashChirho(value_chirho.to_string()))
}

pub(super) fn require_principal_session_chirho(
    root_chirho: &std::path::Path,
    headers_chirho: &HeaderMap,
    principal_chirho: &str,
) -> Option<Response> {
    let token_chirho = match session_token_for_principal_chirho(headers_chirho, principal_chirho) {
        Some(token_chirho) => token_chirho,
        None => {
            return Some((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"ok_chirho": false, "error_chirho": "Authorization Bearer token or cairn_session_chirho cookie required"})),
            )
                .into_response())
        }
    };
    match identity_chirho::validate_session_token_chirho(root_chirho, principal_chirho, &token_chirho) {
        Ok(Some(_session_chirho)) => None,
        Ok(None) => Some((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"ok_chirho": false, "error_chirho": "invalid or expired wallet token"})),
        )
            .into_response()),
        // Before authentication, so a fixed identity in this road's JSON; a resource exhaustion is 503.
        Err(e_chirho) => Some(super::public_error_chirho::public_error_response_chirho(
            "principal-session-chirho",
            super::public_error_chirho::classify_non_dag_chirho(
                &e_chirho,
                StatusCode::BAD_REQUEST,
                "session-check-failed-chirho",
            ),
            headers_chirho,
            Some("application/json"),
        )),
    }
}

pub(super) fn session_token_for_principal_chirho(
    headers_chirho: &HeaderMap,
    principal_chirho: &str,
) -> Option<String> {
    bearer_token_chirho(headers_chirho)
        .map(str::to_string)
        .or_else(|| browser_session_cookie_token_chirho(headers_chirho, principal_chirho))
}

pub(super) fn bearer_token_chirho(headers_chirho: &HeaderMap) -> Option<&str> {
    headers_chirho
        .get(AUTHORIZATION)
        .and_then(|value_chirho| value_chirho.to_str().ok())
        .and_then(|value_chirho| {
            let mut parts_chirho = value_chirho.trim().splitn(2, char::is_whitespace);
            let scheme_chirho = parts_chirho.next()?;
            let token_chirho = parts_chirho.next()?.trim();
            scheme_chirho
                .eq_ignore_ascii_case("Bearer")
                .then_some(token_chirho)
        })
        .filter(|token_chirho| !token_chirho.is_empty())
}

pub(super) fn browser_session_cookie_token_chirho(
    headers_chirho: &HeaderMap,
    principal_chirho: &str,
) -> Option<String> {
    let cookie_header_chirho = headers_chirho.get(COOKIE)?.to_str().ok()?;
    for pair_chirho in cookie_header_chirho.split(';') {
        let pair_chirho = pair_chirho.trim();
        let Some(value_chirho) = pair_chirho.strip_prefix(AUTH_SESSION_COOKIE_CHIRHO) else {
            continue;
        };
        let Some(value_chirho) = value_chirho.strip_prefix('=') else {
            continue;
        };
        let Some((cookie_principal_chirho, token_chirho)) = value_chirho.split_once(':') else {
            continue;
        };
        if cookie_principal_chirho == principal_chirho && !token_chirho.trim().is_empty() {
            return Some(token_chirho.to_string());
        }
    }
    None
}

pub(super) fn request_context_error_status_chirho(error_chirho: &anyhow::Error) -> StatusCode {
    if error_chirho
        .downcast_ref::<oauth_chirho::RateLimitExceededChirho>()
        .is_some()
    {
        StatusCode::TOO_MANY_REQUESTS
    } else if error_chirho
        .downcast_ref::<oauth_chirho::UseWindowCatchingUpChirho>()
        .is_some()
    {
        // Transient: the use window's rebuilt index is on its way after a clock step back (brick 4a-2).
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::FORBIDDEN
    }
}
