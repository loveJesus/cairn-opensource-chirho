// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16
//! `POST /auth-chirho/credential-change-chirho`: the signed-in viewer replaces her own credential.
//! The principal comes from her browser session cookie — never from the body — and the act is the
//! engine's self-service change (`identity_chirho::change_identity_credential_for_session_chirho`):
//! prove the current credential under a per-session guess budget (five failed proofs revoke the
//! session), floor the new one, revoke every live session first, replace, sign a plaintext-free
//! record with her as the actor. Accepted → the cookie is cleared and she is sent to the login page
//! ("signed out everywhere, sign in again"; no auto-session — that would be a second act). Refused
//! → a fixed token, never a secret and never engine prose, carried to `redirect_chirho` as the URL
//! FRAGMENT `#refusal-<token>` for a browser form (a served GET hands the page's DAG only context,
//! headers, and body — the query never reaches it, PFE #21928 — while a fragment never leaves the
//! browser, needs no script, and reaches no log; the page pre-renders the refusals and reveals one
//! by `:target`), or as `error_chirho` for a JSON caller, so the product page owns the customer's
//! words. One refusal is special: when the guess budget is spent, the engine revokes THIS session in
//! the same act, so that refusal clears the cookie and goes to the LOGIN page (not `redirect_chirho`)
//! — a revoked session could not open her own page, only meet a bare 403 there (PFE gpt #22471).
//! Part of `spec-chirho/workflows-chirho/identity-auth-chirho/self-service-credential-change-chirho.md`.

use super::app_session_chirho::{
    browser_session_cookie_pair_chirho, safe_auth_redirect_target_chirho,
};
use super::auth_wallet_chirho::{
    auth_body_bytes_chirho, auth_request_format_chirho, AuthRequestFormatChirho,
};
use super::{redirect_chirho, AppStateChirho};
use axum::extract::State;
use axum::http::header::{HeaderValue, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cairn_chirho::identity_chirho;
use serde::Deserialize;

pub const CREDENTIAL_CHANGE_ROUTE_CHIRHO: &str = "/auth-chirho/credential-change-chirho";
const LOGIN_ROUTE_CHIRHO: &str = "/auth-chirho/login-chirho";
/// The road refused for a reason that is not hers to fix (a log that failed verification, a
/// store error): a token so the page can say "try again later" without echoing the engine.
const ENGINE_REFUSED_TOKEN_CHIRHO: &str = "credential-change-failed-chirho";
const NO_SESSION_TOKEN_CHIRHO: &str = "no-session-chirho";
/// A spent per-session guess budget: the engine revoked the session in the same act, so this road
/// clears the dead cookie and lands her on the public login instead of a page her revoked session
/// can no longer open (the bare-403 return-path defect, PFE gpt #22471). Must byte-match
/// `identity_chirho::CredentialChangeRefusalChirho::token_chirho()` for this variant.
const CREDENTIAL_GUESS_EXHAUSTED_TOKEN_CHIRHO: &str = "credential-guess-exhausted-chirho";
pub(super) const CLEAR_SESSION_COOKIE_CHIRHO: &str =
    "cairn_session_chirho=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure";

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialChangeRequestChirho {
    #[serde(default)]
    credential_chirho: String,
    #[serde(default)]
    new_credential_chirho: String,
    #[serde(default)]
    redirect_chirho: Option<String>,
}

pub(super) async fn auth_credential_change_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let format_chirho = auth_request_format_chirho(&headers_chirho);
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho();

    // The session names the principal. A missing, malformed, expired, or revoked session is one
    // refusal, before the body is read.
    // Bind BOTH the principal and the session token: the engine keys the per-session guess budget
    // on this token, and revokes THIS session (not the account) when the budget is spent.
    let (principal_chirho, session_token_chirho) =
        match browser_session_cookie_pair_chirho(&headers_chirho) {
            Ok(Some((principal_chirho, token_chirho))) => {
                match identity_chirho::validate_session_token_chirho(
                    root_chirho,
                    &principal_chirho,
                    &token_chirho,
                ) {
                    Ok(Some(_session_chirho)) => (principal_chirho, token_chirho),
                    _ => return no_session_response_chirho(format_chirho),
                }
            }
            _ => return no_session_response_chirho(format_chirho),
        };

    let request_chirho = match parse_request_chirho(format_chirho, request_chirho).await {
        Ok(request_chirho) => request_chirho,
        Err(_error_chirho) => {
            return refusal_response_chirho(
                format_chirho,
                StatusCode::BAD_REQUEST,
                "request-invalid-chirho",
                None,
            )
        }
    };
    let redirect_target_chirho = request_chirho
        .redirect_chirho
        .as_deref()
        .and_then(safe_auth_redirect_target_chirho);

    // The credential change tests the current credential (Argon2id) and appends: off the async workers.
    let change_root_chirho = root_chirho.to_path_buf();
    let change_principal_chirho = principal_chirho.clone();
    let change_session_chirho = session_token_chirho.clone();
    let current_credential_chirho = request_chirho.credential_chirho.clone();
    let new_credential_chirho = request_chirho.new_credential_chirho.clone();
    match super::auth_blocking_chirho::run_blocking_auth_chirho(move || {
        identity_chirho::change_identity_credential_for_session_chirho(
            &change_root_chirho,
            &change_principal_chirho,
            &change_session_chirho,
            &current_credential_chirho,
            &new_credential_chirho,
        )
    })
    .await
    {
        Ok(report_chirho) => {
            let mut response_chirho = match format_chirho {
                AuthRequestFormatChirho::FormChirho => redirect_chirho(LOGIN_ROUTE_CHIRHO),
                AuthRequestFormatChirho::JsonChirho => (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "ok_chirho": true,
                        "revoked_session_count_chirho": report_chirho.record_chirho.revoked_session_count_chirho,
                        "reset_seq_chirho": report_chirho.record_chirho.seq_chirho,
                        "signed_out_everywhere_chirho": true,
                    })),
                )
                    .into_response(),
            };
            response_chirho.headers_mut().insert(
                SET_COOKIE,
                HeaderValue::from_static(CLEAR_SESSION_COOKIE_CHIRHO),
            );
            response_chirho
        }
        Err(error_chirho) => {
            let refusal_token_chirho =
                identity_chirho::credential_change_refusal_token_chirho(&error_chirho);
            // A spent guess budget revoked THIS session in the same act. Sending her to her own
            // page (the default refusal target) would meet a bare 403 there — no page, no sentence,
            // no way in — because her session is now dead. So clear the cookie and land her on the
            // public login, exactly as the accepted change does (PFE gpt #22471).
            if refusal_token_chirho == Some(CREDENTIAL_GUESS_EXHAUSTED_TOKEN_CHIRHO) {
                return session_revoked_login_response_chirho(format_chirho);
            }
            let (status_chirho, token_chirho) = match refusal_token_chirho {
                Some("credential-mismatch-chirho") => {
                    (StatusCode::UNAUTHORIZED, "credential-mismatch-chirho")
                }
                Some("credential-too-weak-chirho") => {
                    (StatusCode::BAD_REQUEST, "credential-too-weak-chirho")
                }
                Some(other_chirho) => (StatusCode::BAD_REQUEST, other_chirho),
                None => {
                    eprintln!("credential change refused by the engine: {error_chirho:#}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ENGINE_REFUSED_TOKEN_CHIRHO,
                    )
                }
            };
            refusal_response_chirho(
                format_chirho,
                status_chirho,
                token_chirho,
                redirect_target_chirho.as_deref(),
            )
        }
    }
}

async fn parse_request_chirho(
    format_chirho: AuthRequestFormatChirho,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> anyhow::Result<CredentialChangeRequestChirho> {
    let bytes_chirho = auth_body_bytes_chirho(request_chirho).await?;
    Ok(match format_chirho {
        AuthRequestFormatChirho::JsonChirho => serde_json::from_slice(&bytes_chirho)?,
        AuthRequestFormatChirho::FormChirho => {
            let mut request_chirho = CredentialChangeRequestChirho::default();
            for (key_chirho, value_chirho) in url::form_urlencoded::parse(&bytes_chirho) {
                match key_chirho.as_ref() {
                    "credential_chirho" => {
                        request_chirho.credential_chirho = value_chirho.into_owned()
                    }
                    "new_credential_chirho" => {
                        request_chirho.new_credential_chirho = value_chirho.into_owned()
                    }
                    "redirect_chirho" => {
                        request_chirho.redirect_chirho = Some(value_chirho.into_owned())
                    }
                    _ => {}
                }
            }
            request_chirho
        }
    })
}

pub(super) fn no_session_response_chirho(format_chirho: AuthRequestFormatChirho) -> Response {
    match format_chirho {
        // A browser without a session belongs on the login page; the token rides along so the
        // page can say why.
        AuthRequestFormatChirho::FormChirho => redirect_chirho(&format!(
            "{LOGIN_ROUTE_CHIRHO}#refusal-{NO_SESSION_TOKEN_CHIRHO}"
        )),
        AuthRequestFormatChirho::JsonChirho => refusal_response_chirho(
            format_chirho,
            StatusCode::UNAUTHORIZED,
            NO_SESSION_TOKEN_CHIRHO,
            None,
        ),
    }
}

/// The engine revoked THIS session mid-request (its guess budget is spent). Like the accepted
/// change, clear the dead cookie and send a browser to the public login with a fragment saying why;
/// a JSON caller gets the token as `error_chirho`, a 429, and the same cookie clear. Never her own
/// page: her revoked session would meet a bare 403 there, with no page and no way in (PFE gpt #22471).
fn session_revoked_login_response_chirho(format_chirho: AuthRequestFormatChirho) -> Response {
    let mut response_chirho = match format_chirho {
        AuthRequestFormatChirho::FormChirho => redirect_chirho(&format!(
            "{LOGIN_ROUTE_CHIRHO}#refusal-{CREDENTIAL_GUESS_EXHAUSTED_TOKEN_CHIRHO}"
        )),
        AuthRequestFormatChirho::JsonChirho => (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "ok_chirho": false,
                "error_chirho": CREDENTIAL_GUESS_EXHAUSTED_TOKEN_CHIRHO,
            })),
        )
            .into_response(),
    };
    response_chirho.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(CLEAR_SESSION_COOKIE_CHIRHO),
    );
    response_chirho
}

/// A 303 to a form's own page (`/` when it named none) carrying `#<fragment>`; any fragment the target carried is
/// dropped. The page pre-renders each fragment and reveals one by `:target`, so no script is needed.
pub(super) fn fragment_redirect_chirho(
    redirect_target_chirho: Option<&str>,
    fragment_chirho: &str,
) -> Response {
    let target_chirho = redirect_target_chirho.unwrap_or("/");
    let target_chirho = target_chirho.split('#').next().unwrap_or("/");
    redirect_chirho(&format!("{target_chirho}#{fragment_chirho}"))
}

/// A browser form is sent back to its own page with the token as the fragment `#refusal-<token>`
/// (never the secret, never engine prose; any fragment the target carried is dropped); a JSON
/// caller gets the token as `error_chirho`. The anonymous recover road answers through this carrier too.
pub(super) fn refusal_response_chirho(
    format_chirho: AuthRequestFormatChirho,
    status_chirho: StatusCode,
    token_chirho: &str,
    redirect_target_chirho: Option<&str>,
) -> Response {
    match format_chirho {
        AuthRequestFormatChirho::FormChirho => {
            fragment_redirect_chirho(redirect_target_chirho, &format!("refusal-{token_chirho}"))
        }
        AuthRequestFormatChirho::JsonChirho => (
            status_chirho,
            Json(serde_json::json!({ "ok_chirho": false, "error_chirho": token_chirho })),
        )
            .into_response(),
    }
}
