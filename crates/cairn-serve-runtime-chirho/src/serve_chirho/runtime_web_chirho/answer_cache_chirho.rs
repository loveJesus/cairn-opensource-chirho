// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Every answer leaves with `Cache-Control: private, no-store` unless its handler marked it public by design, so no
//! browser or shared cache may keep a private answer, whatever header the answer carried.
//!
//! - **One outermost layer.** `finalize_answer_cache_chirho` wraps the whole router, the fallback and the framework's own
//!   refusals included, so a route nobody remembered to mark is private by default.
//! - **Public is a typed marker, never a header.** A handler passes an answer through `public_answer_chirho`, and the
//!   layer then keeps whatever caching that handler set. A `Cache-Control` header alone is no permission: on an
//!   unmarked answer the layer replaces it (PFE #26536).
//! - **The reviewed public answers** are the static assets, the static scripts and demo pages, the runtime package
//!   artifacts, the public API descriptors, and a public app's answer to an anonymous GET
//!   (`public_app_answer_if_anonymous_chirho`). A source guard pins every caller of both.
//!
//! Workflow: connected tools K2, `spec-chirho/workflows-chirho/served-request-admission-chirho/answer-cache-finalization-chirho.md`.

use super::AppStateChirho;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Response;
use cairn_chirho::app_chirho;

/// The caching every answer not marked public leaves with.
pub(crate) const PRIVATE_ANSWER_CACHE_CONTROL_CHIRHO: &str = "private, no-store";

/// The marker an answer that is public by design carries; the finalization layer then keeps its own caching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicAnswerChirho;

/// `response_chirho`, marked public by design. Only the reviewed public answers call this, each directly, so the
/// source guard that counts its callers sees every one.
pub(crate) fn public_answer_chirho(mut response_chirho: Response) -> Response {
    response_chirho.extensions_mut().insert(PublicAnswerChirho);
    response_chirho
}

/// The router's outermost layer: an answer not marked public leaves with `private, no-store`, replacing any
/// `Cache-Control` it carried. A marked answer keeps its handler's own caching.
pub(crate) async fn finalize_answer_cache_chirho(mut response_chirho: Response) -> Response {
    if response_chirho
        .extensions()
        .get::<PublicAnswerChirho>()
        .is_none()
    {
        response_chirho.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static(PRIVATE_ANSWER_CACHE_CONTROL_CHIRHO),
        );
    }
    response_chirho
}

/// A public app's successful answer to an anonymous GET is public, as it was before this layer: it carries no
/// `Cache-Control`, so its caching stays exactly as today. It is NOT public if the request carried any credential
/// (an `Authorization` or `Cookie` header, valid or not), if the app admits signed-in viewers only or its policy cannot
/// be read, if the answer is not a success, or if the answer sets a cookie.
pub(crate) fn public_app_answer_if_anonymous_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    app_name_chirho: &str,
    response_chirho: Response,
) -> Response {
    if headers_chirho.contains_key(AUTHORIZATION)
        || headers_chirho.contains_key(COOKIE)
        || !response_chirho.status().is_success()
        || response_chirho.headers().contains_key(SET_COOKIE)
    {
        return response_chirho;
    }
    match state_chirho
        .runtime_chirho
        .app_request_access_policy_chirho(app_name_chirho)
    {
        Ok(app_chirho::AppRequestAccessPolicyChirho::PublicChirho) => {
            public_answer_chirho(response_chirho)
        }
        _ => response_chirho,
    }
}

#[cfg(test)]
#[path = "answer_cache_chirho/tests_chirho.rs"]
mod tests_chirho;
