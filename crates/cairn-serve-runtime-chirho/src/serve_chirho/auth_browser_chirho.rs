// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use axum::{extract::State, http::StatusCode, response::IntoResponse, response::Response, Json};
use cairn_chirho::identity_chirho;

// Workflow: spec-chirho/workflows-chirho/identity-auth-chirho/public-registration-gate-chirho.md
/// The canonical login page, the same bytes for any query. It carries no target: the connection form signs her in
/// through its own page (`/auth-chirho/connection-sign-in-chirho`, PFE unit 330), so one page owns connection sign-in.
pub(super) async fn auth_login_get_chirho() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        identity_chirho::auth_login_html_chirho(),
    )
        .into_response()
}

// Workflow: spec-chirho/workflows-chirho/identity-auth-chirho/public-registration-gate-chirho.md
pub(super) async fn auth_register_get_chirho(
    State(state_chirho): State<super::AppStateChirho>,
) -> Response {
    if let Some(response_chirho) =
        super::auth_wallet_chirho::public_registration_disabled_response_chirho(
            &state_chirho,
            super::auth_wallet_chirho::AuthRequestFormatChirho::FormChirho,
        )
    {
        return response_chirho;
    }
    match identity_chirho::issue_auth_human_check_challenge_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
    ) {
        Ok(challenge_chirho) => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            identity_chirho::auth_register_html_chirho(&challenge_chirho),
        )
            .into_response(),
        Err(e_chirho) => super::auth_wallet_chirho::auth_failure_response_chirho(
            super::auth_wallet_chirho::AuthRequestFormatChirho::FormChirho,
            "auth-human-check-issue-chirho",
            &e_chirho,
            "auth human-check challenge unavailable",
        ),
    }
}

// Workflow: spec-chirho/workflows-chirho/identity-auth-chirho/public-registration-gate-chirho.md
pub(super) async fn auth_human_check_get_chirho(
    State(state_chirho): State<super::AppStateChirho>,
) -> Response {
    if let Some(response_chirho) =
        super::auth_wallet_chirho::public_registration_disabled_response_chirho(
            &state_chirho,
            super::auth_wallet_chirho::AuthRequestFormatChirho::JsonChirho,
        )
    {
        return response_chirho;
    }
    match identity_chirho::issue_auth_human_check_challenge_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
    ) {
        Ok(challenge_chirho) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "ok_chirho": true,
                "question_chirho": challenge_chirho.question_chirho,
                "human_check_token_chirho": challenge_chirho.token_chirho,
            })),
        )
            .into_response(),
        Err(e_chirho) => super::auth_wallet_chirho::auth_failure_response_chirho(
            super::auth_wallet_chirho::AuthRequestFormatChirho::JsonChirho,
            "auth-human-check-issue-chirho",
            &e_chirho,
            "auth human-check challenge unavailable",
        ),
    }
}
