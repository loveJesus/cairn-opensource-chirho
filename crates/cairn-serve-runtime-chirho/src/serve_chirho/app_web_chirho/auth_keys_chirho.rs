// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! `GET /auth-chirho/keys-chirho` and `POST /auth-chirho/key-revoke-chirho`: the signed-in owner lists her own keys and
//! revokes one by its key id (brick 4b-2).
//!
//! - The principal comes from her browser session cookie, never from the path or the body.
//! - The engine looks a key id up only among her own unexpired keys, so another owner's id, an expired key's id and a
//!   malformed id are one refusal, `no-such-key-chirho`.
//! - JSON for the list and for a JSON revoke. A revoke may also come from a no-script form (K3): its answer is a 303
//!   back to the form's page with a fragment the page reveals by `:target`. Every refusal is a fixed token, never
//!   engine prose, and every answer is `private, no-store`.
//! - CSRF, as for the other owner POSTs: the session cookie is `SameSite=Lax`, so a cross-site page's POST carries no
//!   cookie. No owner POST has a separate origin check (measured 2026-10-03). A revoke also needs the key id, which only
//!   the owner's own list returns and a cross-site page cannot read.
//!
//! Workflow: the owner's keys, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
//! (4b-2, as built), and the form revoke, `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`
//! (K3).

use super::app_session_chirho::{
    browser_session_cookie_pair_chirho, safe_auth_redirect_target_chirho,
};
use super::auth_credential_change_chirho::{
    fragment_redirect_chirho, no_session_response_chirho, refusal_response_chirho,
};
use super::auth_wallet_chirho::{
    auth_body_bytes_chirho, auth_request_format_chirho, AuthRequestFormatChirho,
};
use super::AppStateChirho;
use axum::extract::State;
use axum::http::header::{HeaderValue, CACHE_CONTROL};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cairn_chirho::{identity_chirho, oauth_chirho};
use serde::Deserialize;
use std::path::Path;

pub const KEYS_ROUTE_CHIRHO: &str = "/auth-chirho/keys-chirho";
pub const KEY_REVOKE_ROUTE_CHIRHO: &str = "/auth-chirho/key-revoke-chirho";
const NO_SESSION_TOKEN_CHIRHO: &str = "no-session-chirho";
const REQUEST_INVALID_TOKEN_CHIRHO: &str = "request-invalid-chirho";
const NO_SUCH_KEY_TOKEN_CHIRHO: &str = "no-such-key-chirho";
/// The road refused for a reason that is not hers to fix (a log that failed verification, a store error).
const KEYS_FAILED_TOKEN_CHIRHO: &str = "keys-failed-chirho";
/// A form revoke's success, a repeat included: the fragment `#notice-key-ended-chirho`.
const KEY_ENDED_NOTICE_CHIRHO: &str = "notice-key-ended-chirho";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRevokeRequestChirho {
    key_id_chirho: String,
}

/// Every answer of these routes is private to the signed-in owner, so the engine forbids storing it itself, whatever the
/// edge adds (PFE #26030): the key list is private data on a GET.
fn private_answer_chirho(mut response_chirho: Response) -> Response {
    response_chirho
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response_chirho
}

fn private_json_chirho(status_chirho: StatusCode, body_chirho: serde_json::Value) -> Response {
    private_answer_chirho((status_chirho, Json(body_chirho)).into_response())
}

fn refusal_chirho(status_chirho: StatusCode, token_chirho: &str) -> Response {
    private_json_chirho(
        status_chirho,
        serde_json::json!({"ok_chirho": false, "error_chirho": token_chirho}),
    )
}

/// The principal of a live browser session cookie; `None` for a missing, malformed, expired or revoked one. K4 Part
/// 3's connection road reads its principal through this too.
pub(super) fn cookie_principal_chirho(
    root_chirho: &Path,
    headers_chirho: &HeaderMap,
) -> Option<String> {
    let (principal_chirho, token_chirho) =
        browser_session_cookie_pair_chirho(headers_chirho).ok()??;
    matches!(
        identity_chirho::validate_session_token_chirho(
            root_chirho,
            &principal_chirho,
            &token_chirho
        ),
        Ok(Some(_))
    )
    .then_some(principal_chirho)
}

/// `GET /auth-chirho/keys-chirho`: the signed-in owner's own unexpired keys, oldest first, each marked live or not.
pub(super) async fn auth_keys_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
) -> Response {
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    let Some(principal_chirho) = cookie_principal_chirho(&root_chirho, &headers_chirho) else {
        return refusal_chirho(StatusCode::UNAUTHORIZED, NO_SESSION_TOKEN_CHIRHO);
    };
    match super::auth_blocking_chirho::run_blocking_auth_chirho(move || {
        oauth_chirho::list_own_keys_chirho(&root_chirho, &principal_chirho)
    })
    .await
    {
        Ok(keys_chirho) => private_json_chirho(
            StatusCode::OK,
            serde_json::json!({"ok_chirho": true, "keys_chirho": keys_chirho}),
        ),
        Err(error_chirho) => {
            eprintln!("the owner's key list refused: {error_chirho:#}");
            refusal_chirho(StatusCode::INTERNAL_SERVER_ERROR, KEYS_FAILED_TOKEN_CHIRHO)
        }
    }
}

/// `POST /auth-chirho/key-revoke-chirho` with `{"key_id_chirho": …}`: revoke one of the signed-in owner's own keys. A
/// repeat answers the same success; any id that is not one of her own unexpired keys answers `no-such-key-chirho`. A
/// form-encoded request takes the form road instead (K3); every other request keeps this JSON road byte for byte.
pub(super) async fn auth_key_revoke_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    if auth_request_format_chirho(&headers_chirho) == AuthRequestFormatChirho::FormChirho {
        return private_answer_chirho(
            form_key_revoke_chirho(state_chirho, headers_chirho, request_chirho).await,
        );
    }
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    let Some(principal_chirho) = cookie_principal_chirho(&root_chirho, &headers_chirho) else {
        return refusal_chirho(StatusCode::UNAUTHORIZED, NO_SESSION_TOKEN_CHIRHO);
    };
    let Ok(bytes_chirho) = auth_body_bytes_chirho(request_chirho).await else {
        return refusal_chirho(StatusCode::BAD_REQUEST, REQUEST_INVALID_TOKEN_CHIRHO);
    };
    let Ok(body_chirho) = serde_json::from_slice::<KeyRevokeRequestChirho>(&bytes_chirho) else {
        return refusal_chirho(StatusCode::BAD_REQUEST, REQUEST_INVALID_TOKEN_CHIRHO);
    };
    match super::auth_blocking_chirho::run_blocking_auth_chirho(move || {
        oauth_chirho::revoke_own_key_chirho(
            &root_chirho,
            &principal_chirho,
            &body_chirho.key_id_chirho,
        )
    })
    .await
    {
        Ok(()) => private_json_chirho(StatusCode::OK, serde_json::json!({"ok_chirho": true})),
        Err(error_chirho)
            if error_chirho
                .downcast_ref::<oauth_chirho::UnknownScopedKeyChirho>()
                .is_some() =>
        {
            refusal_chirho(StatusCode::NOT_FOUND, NO_SUCH_KEY_TOKEN_CHIRHO)
        }
        Err(error_chirho) => {
            eprintln!("the owner's key revoke refused: {error_chirho:#}");
            refusal_chirho(StatusCode::INTERNAL_SERVER_ERROR, KEYS_FAILED_TOKEN_CHIRHO)
        }
    }
}

/// The form revoke (K3): `key_id_chirho` and `redirect_chirho`, other fields ignored, the principal the cookie's.
/// - The redirect passes credential-change's own check, `safe_auth_redirect_target_chirho`: anything else becomes `/`,
///   and any fragment it carries is dropped.
/// - Success, a repeat included: 303 to `<redirect>#notice-key-ended-chirho`.
/// - Refusals: `#refusal-no-such-key-chirho` for any id that is not one of her own unexpired keys (unknown, another
///   owner's, expired, malformed or empty), `#refusal-request-invalid-chirho` for an unreadable body or no
///   `key_id_chirho`, and `#refusal-keys-failed-chirho` for a log or store failure.
/// - No session: credential-change's 303 to the login page's `#refusal-no-session-chirho`, before the body is read.
async fn form_key_revoke_chirho(
    state_chirho: AppStateChirho,
    headers_chirho: HeaderMap,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let form_chirho = AuthRequestFormatChirho::FormChirho;
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    let Some(principal_chirho) = cookie_principal_chirho(&root_chirho, &headers_chirho) else {
        return no_session_response_chirho(form_chirho);
    };
    let Ok(bytes_chirho) = auth_body_bytes_chirho(request_chirho).await else {
        return refusal_response_chirho(
            form_chirho,
            StatusCode::BAD_REQUEST,
            REQUEST_INVALID_TOKEN_CHIRHO,
            None,
        );
    };
    let mut key_id_chirho = None;
    let mut redirect_chirho = None;
    for (field_chirho, value_chirho) in url::form_urlencoded::parse(&bytes_chirho) {
        match field_chirho.as_ref() {
            "key_id_chirho" => key_id_chirho = Some(value_chirho.into_owned()),
            "redirect_chirho" => redirect_chirho = Some(value_chirho.into_owned()),
            _ => {}
        }
    }
    let target_chirho = redirect_chirho
        .as_deref()
        .and_then(safe_auth_redirect_target_chirho);
    let Some(key_id_chirho) = key_id_chirho else {
        return refusal_response_chirho(
            form_chirho,
            StatusCode::BAD_REQUEST,
            REQUEST_INVALID_TOKEN_CHIRHO,
            target_chirho.as_deref(),
        );
    };
    let refusal_token_chirho =
        match super::auth_blocking_chirho::run_blocking_auth_chirho(move || {
            oauth_chirho::revoke_own_key_chirho(&root_chirho, &principal_chirho, &key_id_chirho)
        })
        .await
        {
            Ok(()) => {
                return fragment_redirect_chirho(target_chirho.as_deref(), KEY_ENDED_NOTICE_CHIRHO)
            }
            Err(error_chirho)
                if error_chirho
                    .downcast_ref::<oauth_chirho::UnknownScopedKeyChirho>()
                    .is_some() =>
            {
                NO_SUCH_KEY_TOKEN_CHIRHO
            }
            Err(error_chirho) => {
                eprintln!("the owner's form key revoke refused: {error_chirho:#}");
                KEYS_FAILED_TOKEN_CHIRHO
            }
        };
    refusal_response_chirho(
        form_chirho,
        StatusCode::BAD_REQUEST,
        refusal_token_chirho,
        target_chirho.as_deref(),
    )
}
