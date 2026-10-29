// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! `GET /auth-chirho/connection-sign-in-chirho?redirect_chirho=<target>` (PFE unit 330, #27196): the connection form's
//! own sign-in page, where a signed-out Create link and a failed sign-in that carried the form's target come back to.
//!
//! - **What it is.** The sign-in form, posting to the login road with the target as its hidden field, and a notice for
//!   each refusal that can bring her here, shown by CSS `:target` alone. It reads no session, no connection client and
//!   no opening: the page is a function of its query.
//! - **The road's gate and guard.** Closed, it answers the road's fixed 503. Every answer carries the road's guard
//!   headers, its redirects and the framework's 405 included.
//! - **Exactly one accepted target.** The query is one `redirect_chirho` that `accepted_return_target_chirho` accepts
//!   exactly as received, and no other field. Anything else is a 303 to the bare canonical login page.
//! - **Through the edges as it is.** The beta and apex edges divert only the exact canonical login path to the branded
//!   page and pass the rest of `/auth-chirho/*` to the tenant, so this page needs no edge change.
//!
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (the connection
//! sign-in page).

use super::connection_pages_chirho::ConnectionSignInPageChirho;
use super::{
    accepted_return_target_chirho, answer_chirho, canonical_login_redirect_chirho, page_chirho,
    AppStateChirho, ConnectionAnswerPageChirho, REDIRECT_FIELD_CHIRHO,
};
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;

/// The page for the one accepted target in its query, or a 303 to the canonical login page.
pub(super) async fn connection_sign_in_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    RawQuery(query_chirho): RawQuery,
) -> Response {
    if !state_chirho.connection_issuance_enabled_chirho {
        return answer_chirho(ConnectionAnswerPageChirho::DisabledChirho);
    }
    let Some(target_chirho) = query_chirho.as_deref().and_then(sign_in_target_chirho) else {
        return canonical_login_redirect_chirho();
    };
    match (ConnectionSignInPageChirho {
        target_chirho: &target_chirho,
    })
    .render_chirho()
    {
        Ok(html_chirho) => page_chirho(StatusCode::OK, html_chirho),
        Err(error_chirho) => {
            eprintln!("the connection sign-in page could not be built: {error_chirho:#}");
            answer_chirho(ConnectionAnswerPageChirho::FailedChirho)
        }
    }
}

/// The page's query: exactly one `redirect_chirho`, the connection form's own accepted target, and no other field.
fn sign_in_target_chirho(query_chirho: &str) -> Option<String> {
    let mut target_chirho = None;
    for (field_chirho, value_chirho) in url::form_urlencoded::parse(query_chirho.as_bytes()) {
        if field_chirho != REDIRECT_FIELD_CHIRHO || target_chirho.is_some() {
            return None;
        }
        target_chirho = Some(value_chirho.into_owned());
    }
    accepted_return_target_chirho(&target_chirho?)
}
