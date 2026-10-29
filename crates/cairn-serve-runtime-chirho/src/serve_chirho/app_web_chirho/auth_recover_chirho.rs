// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! `POST /auth-chirho/recover-chirho`: someone holding an emailed setup or recovery code sets her password. The road is
//! anonymous, so the principal comes from the body.
//!
//! The order is the approved design's (`spec-chirho/workflows-chirho/identity-auth-chirho/self-service-recovery-code-
//! chirho.md`, "R2b, the served road"):
//! 1. parse;
//! 2. the confirmation compare, then the floor (both write nothing and charge nothing);
//! 3. the per-source gate's early check: 4a-1's success limit and R12's failure limit. The authoritative check is the
//!    gate's admission inside the blocking task, which reserves a failure slot before the work (R12). A setup creates
//!    no session, so a success is never charged (PFE ruling (a)); the uniform refusal keeps its failure slot;
//! 4. to 6. the engine: the `recover-chirho` limiter through the attempts window view, the redemption, and one attempt
//!    row per outcome (`identity_chirho::redeem_recovery_code_with_public_limit_outcome_chirho`), with the source's
//!    charge in the same blocking task (R12).
//!
//! A browser form is answered by a 303: on success to the login page with `#notice-password-set-chirho`, the session
//! cookie cleared; on a refusal to its own local page with `#refusal-<token>`, a foreign target becoming `/`. A JSON
//! caller gets `{"ok_chirho": true}` or `{"ok_chirho": false, "error_chirho": <token>}`. Every rate limit answers ONE
//! token, `rate-limited-chirho` (429 and `Retry-After` for JSON), whichever fired. The uniform refusal answers 400, as
//! login's does (PFE ruling (b)). An internal failure answers 500, with one of two tokens by where it stopped against
//! the one commit point (R13, PFE #26146, #26147): `credential-not-set-chirho` before it, where the password is not set
//! and the code still works, and `recovery-failed-chirho` at or after it, where the change may have applied.

use super::auth_credential_change_chirho::{refusal_response_chirho, CLEAR_SESSION_COOKIE_CHIRHO};
use super::auth_wallet_chirho::{
    auth_body_bytes_chirho, auth_request_format_chirho, AuthRequestFormatChirho,
};
use super::{redirect_chirho, AppStateChirho};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{HeaderValue, RETRY_AFTER, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cairn_chirho::identity_chirho;
use serde::Deserialize;

pub const RECOVER_ROUTE_CHIRHO: &str = "/auth-chirho/recover-chirho";
/// Where a browser goes once her password is set: the sign-in page, which reveals its "password set" notice.
const PASSWORD_SET_LOCATION_CHIRHO: &str = "/auth-chirho/login-chirho#notice-password-set-chirho";
const REQUEST_INVALID_TOKEN_CHIRHO: &str = "request-invalid-chirho";
const CONFIRMATION_MISMATCH_TOKEN_CHIRHO: &str = "credential-confirmation-mismatch-chirho";
/// ONE token for both rate limits, the source's and the principal's, so the answer never says which fired.
const RATE_LIMITED_TOKEN_CHIRHO: &str = "rate-limited-chirho";
/// The engine failed at or after the commit point: "your change may have applied; sign in with the new password
/// first".
const RECOVERY_FAILED_TOKEN_CHIRHO: &str = "recovery-failed-chirho";
/// The engine failed BEFORE the commit point: "your password was not set; your code still works". Sessions may already
/// have been revoked, so it never says "nothing changed" (R13).
const CREDENTIAL_NOT_SET_TOKEN_CHIRHO: &str = "credential-not-set-chirho";

/// The road's five fields. A JSON body with any other field refuses; a form's other keys are ignored, as the
/// credential-change road's are.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverRequestChirho {
    #[serde(default)]
    principal_chirho: String,
    #[serde(default)]
    recovery_code_chirho: String,
    #[serde(default)]
    new_credential_chirho: String,
    #[serde(default)]
    new_credential_confirm_chirho: Option<String>,
    #[serde(default)]
    redirect_chirho: Option<String>,
}

pub(super) async fn auth_recover_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    let format_chirho = auth_request_format_chirho(&headers_chirho);
    // 1. Parse. The principal keys the attempt row, so an empty one is a malformed request, never a guess.
    let request_chirho = match parse_request_chirho(format_chirho, request_chirho).await {
        Ok(request_chirho) if !request_chirho.principal_chirho.trim().is_empty() => request_chirho,
        _ => {
            return recover_refusal_chirho(
                format_chirho,
                StatusCode::BAD_REQUEST,
                REQUEST_INVALID_TOKEN_CHIRHO,
                None,
            )
        }
    };
    let redirect_target_chirho = request_chirho
        .redirect_chirho
        .as_deref()
        .and_then(super::app_session_chirho::safe_auth_redirect_target_chirho);
    let target_chirho = redirect_target_chirho.as_deref();

    // 2. The floor step: the confirmation compare, then the floor. Both write nothing and charge nothing.
    if request_chirho
        .new_credential_confirm_chirho
        .as_deref()
        .is_some_and(|confirm_chirho| confirm_chirho != request_chirho.new_credential_chirho)
    {
        return recover_refusal_chirho(
            format_chirho,
            StatusCode::BAD_REQUEST,
            CONFIRMATION_MISMATCH_TOKEN_CHIRHO,
            target_chirho,
        );
    }
    if !identity_chirho::credential_meets_floor_chirho(&request_chirho.new_credential_chirho) {
        return recover_refusal_chirho(
            format_chirho,
            StatusCode::BAD_REQUEST,
            identity_chirho::RecoveryCodeRefusalChirho::CredentialTooWeakChirho.token_chirho(),
            target_chirho,
        );
    }

    // 3. The per-source gate, before any work: both limits are checked. A success is never charged (ruling (a)).
    let source_chirho = match state_chirho.sign_in_gate_chirho.check_source_chirho(
        connect_info_chirho.map(|ConnectInfo(peer_chirho)| peer_chirho),
        &headers_chirho,
        identity_chirho::AUTH_ENDPOINT_RECOVER_CHIRHO,
    ) {
        Ok(source_chirho) => source_chirho,
        // Before any engine work, so nothing can be set. The gate returns rate refusals only, which map first; the
        // flag would matter only for another error, and before any work "not set" is true by construction.
        Err(error_chirho) => {
            return engine_refusal_chirho(format_chirho, error_chirho, true, target_chirho)
        }
    };

    // 4. to 6. The engine's limiter, redemption and attempt row (Argon2id, a locked key write, appends): off the async
    // workers, as login's work is.
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    let principal_chirho = request_chirho.principal_chirho.clone();
    let code_chirho = request_chirho.recovery_code_chirho.clone();
    let new_credential_chirho = request_chirho.new_credential_chirho.clone();
    // R12: metered in the blocking task, as login's. A setup creates no session, so a success charges nothing (ruling
    // (a)); the uniform refusal, which records a failed row, keeps its failure slot.
    let meter_chirho = state_chirho.sign_in_gate_chirho.meter_chirho(
        source_chirho,
        identity_chirho::AUTH_ENDPOINT_RECOVER_CHIRHO,
        super::sign_in_gate_chirho::SignInChargesChirho::FailuresOnlyChirho,
    );
    match super::auth_blocking_chirho::run_blocking_public_auth_chirho(meter_chirho, move || {
        identity_chirho::redeem_recovery_code_with_public_limit_outcome_chirho(
            &root_chirho,
            &principal_chirho,
            &code_chirho,
            &new_credential_chirho,
        )
    })
    .await
    {
        Ok(_report_chirho) => password_set_response_chirho(format_chirho),
        Err(refusal_chirho) => engine_refusal_chirho(
            format_chirho,
            refusal_chirho.error_chirho,
            refusal_chirho.credential_unchanged_chirho,
            target_chirho,
        ),
    }
}

async fn parse_request_chirho(
    format_chirho: AuthRequestFormatChirho,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> anyhow::Result<RecoverRequestChirho> {
    let bytes_chirho = auth_body_bytes_chirho(request_chirho).await?;
    Ok(match format_chirho {
        AuthRequestFormatChirho::JsonChirho => serde_json::from_slice(&bytes_chirho)?,
        AuthRequestFormatChirho::FormChirho => {
            let mut request_chirho = RecoverRequestChirho::default();
            for (key_chirho, value_chirho) in url::form_urlencoded::parse(&bytes_chirho) {
                let value_chirho = value_chirho.into_owned();
                match key_chirho.as_ref() {
                    "principal_chirho" => request_chirho.principal_chirho = value_chirho,
                    "recovery_code_chirho" => request_chirho.recovery_code_chirho = value_chirho,
                    "new_credential_chirho" => request_chirho.new_credential_chirho = value_chirho,
                    "new_credential_confirm_chirho" => {
                        request_chirho.new_credential_confirm_chirho = Some(value_chirho)
                    }
                    "redirect_chirho" => request_chirho.redirect_chirho = Some(value_chirho),
                    _ => {}
                }
            }
            request_chirho
        }
    })
}

/// Her password is set and every session of hers is revoked: a browser goes to the sign-in page's notice, and any
/// session cookie it held is cleared.
fn password_set_response_chirho(format_chirho: AuthRequestFormatChirho) -> Response {
    let mut response_chirho = match format_chirho {
        AuthRequestFormatChirho::FormChirho => redirect_chirho(PASSWORD_SET_LOCATION_CHIRHO),
        AuthRequestFormatChirho::JsonChirho => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok_chirho": true })),
        )
            .into_response(),
    };
    response_chirho.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(CLEAR_SESSION_COOKIE_CHIRHO),
    );
    response_chirho
}

/// An engine or gate error, mapped to its ONE public token: a rate limit (any of them), the redemption's own refusal
/// (the floor, or the uniform refusal), or an internal failure, whose chain goes to the journal only. That failure is
/// `credential-not-set-chirho` when it is KNOWN to have stopped before the commit point, and otherwise
/// `recovery-failed-chirho`, so an unknown phase reads as "may have applied" (R13).
fn engine_refusal_chirho(
    format_chirho: AuthRequestFormatChirho,
    error_chirho: anyhow::Error,
    credential_unchanged_chirho: bool,
    target_chirho: Option<&str>,
) -> Response {
    if identity_chirho::is_auth_rate_limit_error_chirho(&error_chirho) {
        return recover_refusal_chirho(
            format_chirho,
            StatusCode::TOO_MANY_REQUESTS,
            RATE_LIMITED_TOKEN_CHIRHO,
            target_chirho,
        );
    }
    match identity_chirho::recovery_code_refusal_token_chirho(&error_chirho) {
        Some(token_chirho) => recover_refusal_chirho(
            format_chirho,
            StatusCode::BAD_REQUEST,
            token_chirho,
            target_chirho,
        ),
        None => {
            eprintln!("recovery refused by the engine: {error_chirho:#}");
            let token_chirho = if credential_unchanged_chirho {
                CREDENTIAL_NOT_SET_TOKEN_CHIRHO
            } else {
                RECOVERY_FAILED_TOKEN_CHIRHO
            };
            recover_refusal_chirho(
                format_chirho,
                StatusCode::INTERNAL_SERVER_ERROR,
                token_chirho,
                target_chirho,
            )
        }
    }
}

/// The credential-change road's carrier, plus `Retry-After` on a JSON rate refusal, from the one constant every sign-in
/// rate refusal uses (agy #25938).
fn recover_refusal_chirho(
    format_chirho: AuthRequestFormatChirho,
    status_chirho: StatusCode,
    token_chirho: &str,
    target_chirho: Option<&str>,
) -> Response {
    let mut response_chirho =
        refusal_response_chirho(format_chirho, status_chirho, token_chirho, target_chirho);
    if status_chirho == StatusCode::TOO_MANY_REQUESTS
        && matches!(format_chirho, AuthRequestFormatChirho::JsonChirho)
    {
        response_chirho.headers_mut().insert(
            RETRY_AFTER,
            HeaderValue::from(identity_chirho::AUTH_RATE_LIMIT_RETRY_AFTER_SECS_CHIRHO),
        );
    }
    response_chirho
}
