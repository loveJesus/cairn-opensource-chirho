// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! `GET` and `POST /auth-chirho/connection-new-chirho` (K4 Part 3): the signed-in owner creates a connection, a limited
//! key for one tool, from an engine-rendered form, and sees its key once.
//!
//! - **Default-off.** With `connection_issuance_enabled_chirho` (the TOML's) closed, both routes answer a fixed 503
//!   before reading the session or the body.
//! - **The principal is the cookie's**, and her password is entered again. Signed out, the GET sends her to this road's
//!   own sign-in page with the form as its target; the POST refuses before reading its body.
//! - **The connection sign-in page** (`GET /auth-chirho/connection-sign-in-chirho`, PFE unit 330, #27196): the sign-in
//!   form for exactly one accepted target, behind this road's gate and guard, with a notice for each refusal that can
//!   bring her back. A failed sign-in that carried that target returns to it, from both refusal exits, while the road is
//!   open. One strict validator (`accepted_return_target_chirho`) decides the page and that retention, and accepts a
//!   target only exactly as received. The canonical login page carries no target.
//! - **Form-encoded only, parsed strictly.** The engine half (`oauth_chirho::issue_connection_key_served_chirho`) checks
//!   the client and the actions, runs the token road's pre-check, and issues through Part 2's connection door, metered
//!   by R12's source gate as the token road is.
//! - **One disclosure.** The bearer is in the body of the POST's own 200 answer and nowhere else. Every answer at this
//!   route carries `private, no-store`, a CSP with `frame-ancestors 'none'` and `script-src 'none'`, `nosniff`,
//!   `no-referrer` and `X-Frame-Options: DENY`: the handlers' answers and the framework's own, such as the 405 another
//!   method gets (PFE #26814). The guard is a layer on this route's method router, so no other page is touched.
//! - **The answers.** An ordinary refusal is a 303 to the form with `#refusal-<token>`, the closed gate a direct 503,
//!   and a failure at or after the session's append, or an engine failure, a direct 500 page with its token. A task the
//!   blocking pool did not complete answers uncertain: it may have stopped after the key (PFE #26813).
//! - **Selection by app** (Account Create brick 1, PFE #26824): the GET takes exactly one of `client_id_chirho` or
//!   `app_chirho`, and at most one `return_chirho`; a repeat, a mix or an unknown field refuses. Signed out, a well-formed
//!   query goes to the sign-in page as its canonical target, and no connection client or opening is resolved; the cookie
//!   is read as before. Signed in, the engine resolves the app to exactly one verified connection client.
//! - **The return path** is navigation data: a named route of the client's app, kept only as it arrived (the shared
//!   redirect check must keep it byte for byte; nothing is trimmed or repaired, PFE #26837), carried as the form's hidden
//!   field, checked again by the engine against the POST's verified client, and shown as an ordinary escaped link on the
//!   one-time page.
//! - **CSRF** rests on the `SameSite=Lax` session cookie and the password entered again: the measured boundary, not a
//!   claim that no other page can supply a password.
//!
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (Part 3's placement,
//! as decided).

use super::app_session_chirho::safe_auth_redirect_target_chirho;
use super::auth_blocking_chirho::{
    run_blocking_auth_chirho, run_blocking_public_auth_chirho, SignInWorkIncompleteChirho,
};
use super::auth_credential_change_chirho::{fragment_redirect_chirho, no_session_response_chirho};
use super::auth_keys_chirho::cookie_principal_chirho;
use super::auth_wallet_chirho::{
    auth_body_bytes_chirho, auth_request_format_chirho, AuthRequestFormatChirho,
};
use super::sign_in_gate_chirho::SignInChargesChirho;
use super::AppStateChirho;
use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::header::{
    HeaderValue, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use cairn_chirho::{identity_chirho, oauth_chirho};
use oauth_chirho::{
    ConnectionSelectorChirho, ConnectionServedOutcomeChirho, ConnectionServedRefusalChirho,
};

#[path = "connection_pages_chirho/connection_pages_chirho.rs"]
mod connection_pages_chirho;
use connection_pages_chirho::{
    ConnectionAnswerPageChirho, ConnectionCreatedPageChirho, ConnectionFormPageChirho,
};

#[path = "auth_connection_sign_in_chirho.rs"]
mod sign_in_chirho;

pub(super) const CONNECTION_NEW_ROUTE_CHIRHO: &str = "/auth-chirho/connection-new-chirho";
/// The road's own sign-in page (PFE unit 330), which the edges pass to the tenant as they pass the rest of the road.
const CONNECTION_SIGN_IN_ROUTE_CHIRHO: &str = "/auth-chirho/connection-sign-in-chirho";
/// The canonical login route, as the login road registers it.
const LOGIN_ROUTE_CHIRHO: &str = "/auth-chirho/login-chirho";
const CLIENT_ID_FIELD_CHIRHO: &str = "client_id_chirho";
/// The GET's other selector: an app, which must resolve to exactly one connection client.
const APP_FIELD_CHIRHO: &str = "app_chirho";
/// The optional return path, through the login page and the form to the one-time page's link.
const RETURN_FIELD_CHIRHO: &str = "return_chirho";
const ACTION_FIELD_CHIRHO: &str = "action_chirho";
const CREDENTIAL_FIELD_CHIRHO: &str = "credential_chirho";
/// The sign-in page's target field, which the login road honors after a success and keeps across a refusal.
const REDIRECT_FIELD_CHIRHO: &str = "redirect_chirho";
/// The most actions one POST may name: the form offers one app's opened actions, a handful.
const MAX_ACTIONS_CHIRHO: usize = 32;
/// The longest action name a POST may carry.
const MAX_ACTION_BYTES_CHIRHO: usize = 128;
const NO_SESSION_FRAGMENT_CHIRHO: &str = "refusal-no-session-chirho";
const REQUEST_INVALID_TOKEN_CHIRHO: &str = "request-invalid-chirho";
const CREDENTIAL_MISMATCH_TOKEN_CHIRHO: &str = "credential-mismatch-chirho";
const RATE_LIMITED_TOKEN_CHIRHO: &str = "rate-limited-chirho";
const SLOTS_FULL_TOKEN_CHIRHO: &str = "connection-slots-full-chirho";
/// Nothing loads from anywhere, nothing runs, no page may frame these, and a form posts only to this origin.
const CONTENT_SECURITY_POLICY_CHIRHO: &str = "default-src 'none'; style-src 'unsafe-inline'; \
     form-action 'self'; frame-ancestors 'none'; base-uri 'none'; script-src 'none'";

/// The road's routes, merged into the served router: the form's GET and POST, and its sign-in page's GET (PFE unit 330).
/// The guard wraps each whole method router, its 405 for any other method included, and `layer` rather than
/// `route_layer`, which would skip that 405 (PFE #26814).
pub(super) fn connection_new_routes_chirho() -> Router<AppStateChirho> {
    Router::new()
        .route(
            CONNECTION_NEW_ROUTE_CHIRHO,
            get(connection_new_get_chirho)
                .post(connection_new_post_chirho)
                .layer(axum::middleware::map_response(guarded_chirho)),
        )
        .route(
            CONNECTION_SIGN_IN_ROUTE_CHIRHO,
            get(sign_in_chirho::connection_sign_in_get_chirho)
                .layer(axum::middleware::map_response(guarded_chirho)),
        )
}

/// The headers every answer at this route carries, whatever its status and whoever made it: never stored, never
/// framed, never sniffed, never sent on as a referrer, and nothing loads or runs in it. It adds headers only, so a
/// status, an `Allow` header and a body pass through unchanged.
async fn guarded_chirho(mut response_chirho: Response) -> Response {
    let headers_chirho = response_chirho.headers_mut();
    headers_chirho.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers_chirho.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY_CHIRHO),
    );
    headers_chirho.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers_chirho.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers_chirho.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response_chirho
}

fn page_chirho(status_chirho: StatusCode, html_chirho: String) -> Response {
    (
        status_chirho,
        [(CONTENT_TYPE, "text/html; charset=utf-8")],
        html_chirho,
    )
        .into_response()
}

fn answer_chirho(answer_page_chirho: ConnectionAnswerPageChirho) -> Response {
    page_chirho(
        answer_page_chirho.status_chirho(),
        answer_page_chirho.render_chirho(),
    )
}

/// A client id as the engine mints one (`next_client_id_chirho`): `client/` and sixteen lowercase hex digits. Only such
/// an id enters a URL this road builds.
fn client_id_well_formed_chirho(value_chirho: &str) -> bool {
    value_chirho
        .strip_prefix("client/")
        .is_some_and(|hex_chirho| {
            hex_chirho.len() == 16
                && hex_chirho
                    .bytes()
                    .all(|byte_chirho| matches!(byte_chirho, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// The form's own URL: the selector, then the return path when there is one, in that order, encoded by the serializer.
/// It is the only target the login page carries, and where a refusal sends the browser back.
fn form_target_chirho(
    selector_chirho: &ConnectionSelectorChirho,
    return_chirho: Option<&str>,
) -> String {
    let mut query_chirho = url::form_urlencoded::Serializer::new(String::new());
    match selector_chirho {
        ConnectionSelectorChirho::ClientChirho(client_id_chirho) => {
            query_chirho.append_pair(CLIENT_ID_FIELD_CHIRHO, client_id_chirho)
        }
        ConnectionSelectorChirho::AppChirho(app_chirho) => {
            query_chirho.append_pair(APP_FIELD_CHIRHO, app_chirho)
        }
    };
    if let Some(return_chirho) = return_chirho {
        query_chirho.append_pair(RETURN_FIELD_CHIRHO, return_chirho);
    }
    format!("{CONNECTION_NEW_ROUTE_CHIRHO}?{}", query_chirho.finish())
}

/// The GET's query, closed (Account Create brick 1): one selector, and the return path when there is one.
struct ConnectionQueryChirho {
    selector_chirho: ConnectionSelectorChirho,
    return_chirho: Option<String>,
}

impl ConnectionQueryChirho {
    fn target_chirho(&self) -> String {
        form_target_chirho(&self.selector_chirho, self.return_chirho.as_deref())
    }
}

/// A return path as it arrived, decoded, kept only when the redirect check every auth road uses keeps it byte for byte:
/// that check trims, and a value it would change is refused, never repaired (PFE #26837). Its shape is the engine's.
fn return_kept_as_received_chirho(return_chirho: &str) -> bool {
    safe_auth_redirect_target_chirho(return_chirho).as_deref() == Some(return_chirho)
        && oauth_chirho::connection_return_path_well_formed_chirho(return_chirho)
}

/// The GET's query: exactly one of a well-formed `client_id_chirho` or `app_chirho`, and at most one `return_chirho`
/// kept as received, which an app selector must name a route of. `None` for a missing, repeated, mixed, unknown or
/// malformed field. A client id's own app is checked once the engine knows it.
fn connection_query_chirho(query_chirho: &str) -> Option<ConnectionQueryChirho> {
    let (mut client_id_chirho, mut app_chirho, mut return_chirho) = (None, None, None);
    for (field_chirho, value_chirho) in url::form_urlencoded::parse(query_chirho.as_bytes()) {
        let slot_chirho = match field_chirho.as_ref() {
            CLIENT_ID_FIELD_CHIRHO => &mut client_id_chirho,
            APP_FIELD_CHIRHO => &mut app_chirho,
            RETURN_FIELD_CHIRHO => &mut return_chirho,
            _ => return None,
        };
        if slot_chirho.is_some() {
            return None;
        }
        *slot_chirho = Some(value_chirho.into_owned());
    }
    let selector_chirho = match (client_id_chirho, app_chirho) {
        (Some(client_id_chirho), None) if client_id_well_formed_chirho(&client_id_chirho) => {
            ConnectionSelectorChirho::ClientChirho(client_id_chirho)
        }
        (None, Some(app_chirho))
            if oauth_chirho::connection_app_selector_well_formed_chirho(&app_chirho) =>
        {
            ConnectionSelectorChirho::AppChirho(app_chirho)
        }
        _ => return None,
    };
    if let Some(return_chirho) = &return_chirho {
        let for_app_chirho = match &selector_chirho {
            ConnectionSelectorChirho::AppChirho(app_chirho) => {
                oauth_chirho::connection_return_path_for_app_chirho(app_chirho, return_chirho)
            }
            ConnectionSelectorChirho::ClientChirho(_client_id_chirho) => true,
        };
        if !(return_kept_as_received_chirho(return_chirho) && for_app_chirho) {
            return None;
        }
    }
    Some(ConnectionQueryChirho {
        selector_chirho,
        return_chirho,
    })
}

/// The one target the sign-in page and refusal retention accept: this form's own canonical target for a well-formed
/// query, passing the redirect check every auth road uses, and exactly as received. That check trims, and its trimmed
/// value is never the one compared: a target with whitespace or a control character before or after it refuses rather
/// than being repaired (PFE #27196). Anything else is `None`.
pub(super) fn accepted_return_target_chirho(value_chirho: &str) -> Option<String> {
    safe_auth_redirect_target_chirho(value_chirho)?;
    let query_chirho = value_chirho
        .strip_prefix(CONNECTION_NEW_ROUTE_CHIRHO)?
        .strip_prefix('?')?;
    let canonical_chirho = connection_query_chirho(query_chirho)?.target_chirho();
    (canonical_chirho == value_chirho).then_some(canonical_chirho)
}

/// A 303 to the bare canonical login page, where the sign-in page sends any visit it does not render.
fn canonical_login_redirect_chirho() -> Response {
    super::redirect_chirho(LOGIN_ROUTE_CHIRHO)
}

/// The sign-in page's URL for an accepted target, with the fragment that shows one of its notices.
fn sign_in_location_chirho(target_chirho: &str, fragment_chirho: &str) -> String {
    let query_chirho = url::form_urlencoded::Serializer::new(String::new())
        .append_pair(REDIRECT_FIELD_CHIRHO, target_chirho)
        .finish();
    format!("{CONNECTION_SIGN_IN_ROUTE_CHIRHO}?{query_chirho}#{fragment_chirho}")
}

/// Where a refused form sign-in goes back to (PFE unit 330, #27196). While the road is open, a sign-in whose one
/// `redirect_chirho` is this form's accepted target returns to the sign-in page with that target and the refusal's
/// token. `None` for anything else, which keeps the login road's fixed answer. A failure never goes to the target itself.
pub(super) fn sign_in_refusal_location_chirho(
    open_chirho: bool,
    redirect_chirho: Option<&str>,
    token_chirho: &str,
) -> Option<String> {
    if !open_chirho {
        return None;
    }
    let target_chirho = accepted_return_target_chirho(redirect_chirho?)?;
    Some(sign_in_location_chirho(
        &target_chirho,
        &format!("refusal-{token_chirho}"),
    ))
}

/// A signed-out GET: to the sign-in page, carrying this form's canonical target, when the query is well formed; to the
/// canonical login page when it is not. It resolves no connection client and no opening.
fn signed_out_get_chirho(query_chirho: Option<&ConnectionQueryChirho>) -> Response {
    let location_chirho = match query_chirho {
        Some(query_chirho) => {
            sign_in_location_chirho(&query_chirho.target_chirho(), NO_SESSION_FRAGMENT_CHIRHO)
        }
        None => format!("{LOGIN_ROUTE_CHIRHO}#{NO_SESSION_FRAGMENT_CHIRHO}"),
    };
    super::redirect_chirho(&location_chirho)
}

/// An ordinary refusal: a 303 back to the form's own target, or to the bare route, with the fixed token.
fn refused_chirho(target_chirho: Option<String>, token_chirho: &str) -> Response {
    let target_chirho = target_chirho.unwrap_or_else(|| CONNECTION_NEW_ROUTE_CHIRHO.to_string());
    fragment_redirect_chirho(Some(&target_chirho), &format!("refusal-{token_chirho}"))
}

/// The form target for a POST's well-formed client id and the return path it carried.
fn client_target_chirho(client_id_chirho: &str, return_chirho: Option<&str>) -> String {
    form_target_chirho(
        &ConnectionSelectorChirho::ClientChirho(client_id_chirho.to_string()),
        return_chirho,
    )
}

/// `GET /auth-chirho/connection-new-chirho?client_id_chirho=<id>` or `?app_chirho=<app>`, each with an optional
/// `return_chirho`: the form for the signed-in owner.
async fn connection_new_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    RawQuery(query_chirho): RawQuery,
) -> Response {
    connection_form_answer_chirho(state_chirho, headers_chirho, query_chirho).await
}

async fn connection_form_answer_chirho(
    state_chirho: AppStateChirho,
    headers_chirho: HeaderMap,
    query_chirho: Option<String>,
) -> Response {
    if !state_chirho.connection_issuance_enabled_chirho {
        return answer_chirho(ConnectionAnswerPageChirho::DisabledChirho);
    }
    let query_chirho = query_chirho.as_deref().and_then(connection_query_chirho);
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    if cookie_principal_chirho(&root_chirho, &headers_chirho).is_none() {
        return signed_out_get_chirho(query_chirho.as_ref());
    }
    let Some(query_chirho) = query_chirho else {
        return answer_chirho(ConnectionAnswerPageChirho::RequestInvalidChirho);
    };
    let selector_chirho = query_chirho.selector_chirho.clone();
    let choices_chirho = run_blocking_auth_chirho(move || {
        oauth_chirho::connection_form_choices_chirho(&root_chirho, &selector_chirho)
    })
    .await;
    match choices_chirho {
        // A return path names a route of the client's own app, now that the engine has verified which app that is.
        Ok(Some(choices_chirho))
            if query_chirho
                .return_chirho
                .as_deref()
                .is_some_and(|return_chirho| {
                    !oauth_chirho::connection_return_path_for_app_chirho(
                        &choices_chirho.app_chirho,
                        return_chirho,
                    )
                }) =>
        {
            answer_chirho(ConnectionAnswerPageChirho::RequestInvalidChirho)
        }
        Ok(Some(choices_chirho)) => match (ConnectionFormPageChirho {
            client_id_chirho: &choices_chirho.client_id_chirho,
            app_chirho: &choices_chirho.app_chirho,
            actions_chirho: &choices_chirho.actions_chirho,
            return_chirho: query_chirho.return_chirho.as_deref(),
        })
        .render_chirho()
        {
            Ok(html_chirho) => page_chirho(StatusCode::OK, html_chirho),
            Err(error_chirho) => {
                eprintln!("the connection form could not be built: {error_chirho:#}");
                answer_chirho(ConnectionAnswerPageChirho::FailedChirho)
            }
        },
        Ok(None) => answer_chirho(ConnectionAnswerPageChirho::RequestInvalidChirho),
        Err(error_chirho) => {
            eprintln!("the connection form refused: {error_chirho:#}");
            answer_chirho(ConnectionAnswerPageChirho::FailedChirho)
        }
    }
}

/// The POST's form, parsed strictly.
struct ConnectionNewFormChirho {
    client_id_chirho: String,
    actions_chirho: Vec<String>,
    credential_chirho: String,
    return_chirho: Option<String>,
}

/// Exactly one well-formed client id, one or more distinct bounded actions, exactly one non-empty credential, at most
/// one return path kept as received, and no other field. A refusal carries the client id when it was well formed, so
/// its 303 can go back to that form. The engine checks the return path against the client's app.
fn parse_form_chirho(bytes_chirho: &[u8]) -> Result<ConnectionNewFormChirho, Option<String>> {
    let mut client_id_chirho: Option<String> = None;
    let mut actions_chirho: Vec<String> = Vec::new();
    let mut credential_chirho: Option<String> = None;
    let mut return_chirho: Option<String> = None;
    let mut invalid_chirho = false;
    for (field_chirho, value_chirho) in url::form_urlencoded::parse(bytes_chirho) {
        match field_chirho.as_ref() {
            CLIENT_ID_FIELD_CHIRHO if client_id_chirho.is_none() => {
                client_id_chirho = Some(value_chirho.into_owned());
            }
            ACTION_FIELD_CHIRHO
                if actions_chirho.len() < MAX_ACTIONS_CHIRHO
                    && value_chirho.len() <= MAX_ACTION_BYTES_CHIRHO
                    && !actions_chirho
                        .iter()
                        .any(|action_chirho| action_chirho == value_chirho.as_ref()) =>
            {
                actions_chirho.push(value_chirho.into_owned());
            }
            CREDENTIAL_FIELD_CHIRHO if credential_chirho.is_none() => {
                credential_chirho = Some(value_chirho.into_owned());
            }
            RETURN_FIELD_CHIRHO
                if return_chirho.is_none() && return_kept_as_received_chirho(&value_chirho) =>
            {
                return_chirho = Some(value_chirho.into_owned());
            }
            _ => invalid_chirho = true,
        }
    }
    let client_id_chirho =
        client_id_chirho.filter(|id_chirho| client_id_well_formed_chirho(id_chirho));
    match (client_id_chirho, credential_chirho) {
        (Some(client_id_chirho), Some(credential_chirho))
            if !invalid_chirho && !actions_chirho.is_empty() && !credential_chirho.is_empty() =>
        {
            Ok(ConnectionNewFormChirho {
                client_id_chirho,
                actions_chirho,
                credential_chirho,
                return_chirho,
            })
        }
        (client_id_chirho, _credential_chirho) => Err(client_id_chirho),
    }
}

/// `POST /auth-chirho/connection-new-chirho`: create a connection and show its key once.
async fn connection_new_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    headers_chirho: HeaderMap,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    connection_created_answer_chirho(
        state_chirho,
        headers_chirho,
        connect_info_chirho,
        request_chirho,
    )
    .await
}

async fn connection_created_answer_chirho(
    state_chirho: AppStateChirho,
    headers_chirho: HeaderMap,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    request_chirho: axum::http::Request<axum::body::Body>,
) -> Response {
    if !state_chirho.connection_issuance_enabled_chirho {
        return answer_chirho(ConnectionAnswerPageChirho::DisabledChirho);
    }
    let root_chirho = state_chirho.runtime_chirho.root_path_chirho().to_path_buf();
    let Some(principal_chirho) = cookie_principal_chirho(&root_chirho, &headers_chirho) else {
        return no_session_response_chirho(AuthRequestFormatChirho::FormChirho);
    };
    if auth_request_format_chirho(&headers_chirho) != AuthRequestFormatChirho::FormChirho {
        return refused_chirho(None, REQUEST_INVALID_TOKEN_CHIRHO);
    }
    let Ok(bytes_chirho) = auth_body_bytes_chirho(request_chirho).await else {
        return refused_chirho(None, REQUEST_INVALID_TOKEN_CHIRHO);
    };
    let form_chirho = match parse_form_chirho(&bytes_chirho) {
        Ok(form_chirho) => form_chirho,
        Err(client_id_chirho) => {
            return refused_chirho(
                client_id_chirho
                    .map(|client_id_chirho| client_target_chirho(&client_id_chirho, None)),
                REQUEST_INVALID_TOKEN_CHIRHO,
            )
        }
    };
    // A refusal keeps the return path only once the engine has checked it against the client's app: after the credential
    // and slot refusals, which only its door gives. A rate refusal may come from the source meter before the engine
    // runs, so it, a request-invalid refusal and any refusal before the engine go back without it.
    let checked_target_chirho = client_target_chirho(
        &form_chirho.client_id_chirho,
        form_chirho.return_chirho.as_deref(),
    );
    let unchecked_target_chirho = client_target_chirho(&form_chirho.client_id_chirho, None);
    // A connection's creation is a sign-in: the source's limits first, before any credential work, as the token road.
    let sign_in_gate_chirho = state_chirho.sign_in_gate_chirho.clone();
    let Ok(source_chirho) = sign_in_gate_chirho.check_source_chirho(
        connect_info_chirho.map(|ConnectInfo(peer_chirho)| peer_chirho),
        &headers_chirho,
        identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
    ) else {
        return refused_chirho(Some(unchecked_target_chirho), RATE_LIMITED_TOKEN_CHIRHO);
    };
    let velocity_chirho = sign_in_gate_chirho.velocity_chirho();
    let meter_chirho = sign_in_gate_chirho.meter_chirho(
        source_chirho,
        identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
        SignInChargesChirho::SuccessesAndFailuresChirho,
    );
    let return_chirho = form_chirho.return_chirho.clone();
    let outcome_chirho = run_blocking_public_auth_chirho(meter_chirho, move || {
        oauth_chirho::issue_connection_key_served_chirho(
            &root_chirho,
            &oauth_chirho::ConnectionServedRequestChirho {
                principal_chirho: &principal_chirho,
                credential_chirho: &form_chirho.credential_chirho,
                client_id_chirho: &form_chirho.client_id_chirho,
                actions_chirho: &form_chirho.actions_chirho,
                return_chirho: form_chirho.return_chirho.as_deref(),
            },
            &velocity_chirho,
        )
        .inspect(|_outcome_chirho| after_issue_seam_chirho::run_chirho(&principal_chirho))
    })
    .await;
    match outcome_chirho {
        Ok(ConnectionServedOutcomeChirho::CreatedChirho(issue_chirho)) => {
            one_time_answer_chirho(&issue_chirho, return_chirho.as_deref())
        }
        Ok(ConnectionServedOutcomeChirho::UncertainChirho { cause_chirho }) => {
            eprintln!("a connection's creation is uncertain: {cause_chirho}");
            answer_chirho(ConnectionAnswerPageChirho::UncertainChirho)
        }
        Err(refusal_chirho)
            if refusal_chirho
                .error_chirho
                .downcast_ref::<SignInWorkIncompleteChirho>()
                .is_some() =>
        {
            // The task stopped where nothing reports, possibly after the key's append, so the answer is not known
            // (PFE #26813). Closed permits ran no work and stay below, as failed.
            eprintln!(
                "a connection's creation did not complete: {:#}",
                refusal_chirho.error_chirho
            );
            answer_chirho(ConnectionAnswerPageChirho::UncertainChirho)
        }
        Err(refusal_chirho) => match ConnectionServedRefusalChirho::of_chirho(&refusal_chirho) {
            ConnectionServedRefusalChirho::RequestInvalidChirho => {
                refused_chirho(Some(unchecked_target_chirho), REQUEST_INVALID_TOKEN_CHIRHO)
            }
            ConnectionServedRefusalChirho::CredentialMismatchChirho => refused_chirho(
                Some(checked_target_chirho),
                CREDENTIAL_MISMATCH_TOKEN_CHIRHO,
            ),
            ConnectionServedRefusalChirho::RateLimitedChirho => {
                refused_chirho(Some(unchecked_target_chirho), RATE_LIMITED_TOKEN_CHIRHO)
            }
            ConnectionServedRefusalChirho::SlotsFullChirho => {
                refused_chirho(Some(checked_target_chirho), SLOTS_FULL_TOKEN_CHIRHO)
            }
            ConnectionServedRefusalChirho::NotCreatedChirho => {
                eprintln!(
                    "a connection was not created: {:#}",
                    refusal_chirho.error_chirho
                );
                answer_chirho(ConnectionAnswerPageChirho::NotCreatedChirho)
            }
            ConnectionServedRefusalChirho::UncertainChirho => {
                eprintln!(
                    "a connection's creation is uncertain: {:#}",
                    refusal_chirho.error_chirho
                );
                answer_chirho(ConnectionAnswerPageChirho::UncertainChirho)
            }
            ConnectionServedRefusalChirho::FailedChirho => {
                eprintln!(
                    "a connection's creation failed before any write: {:#}",
                    refusal_chirho.error_chirho
                );
                answer_chirho(ConnectionAnswerPageChirho::FailedChirho)
            }
        },
    }
}

/// The created connection's one-time page, with its link back to the app when the form carried a return path. A page
/// that cannot be built answers uncertain, without the bearer: the connection exists, and its key was not shown (PFE
/// #26801).
fn one_time_answer_chirho(
    issue_chirho: &oauth_chirho::ScopedTokenIssueChirho,
    return_chirho: Option<&str>,
) -> Response {
    let actions_chirho: Vec<String> = issue_chirho
        .record_chirho
        .limited_grants_chirho
        .as_ref()
        .map(|grants_chirho| {
            grants_chirho
                .actions_chirho
                .iter()
                .map(|grant_chirho| grant_chirho.action_chirho.clone())
                .collect()
        })
        .unwrap_or_default();
    let page_chirho_result =
        one_time_page_hook_chirho::checked_chirho(&issue_chirho.record_chirho.principal_chirho)
            .and_then(|()| {
                ConnectionCreatedPageChirho {
                    app_chirho: &issue_chirho.record_chirho.app_chirho,
                    actions_chirho: &actions_chirho,
                    bearer_chirho: &issue_chirho.token_chirho,
                    return_chirho,
                }
                .render_chirho()
            });
    match page_chirho_result {
        Ok(html_chirho) => page_chirho(StatusCode::OK, html_chirho),
        Err(error_chirho) => {
            eprintln!("a connection's one-time page could not be built: {error_chirho:#}");
            answer_chirho(ConnectionAnswerPageChirho::UncertainChirho)
        }
    }
}

/// Test-only: fail the one-time page for one principal, so the arms reach the seam after a created key over the real
/// road. Outside tests it always passes.
pub(super) mod one_time_page_hook_chirho {
    #[cfg(test)]
    static FAIL_FOR_PRINCIPAL_CHIRHO: std::sync::Mutex<Option<String>> =
        std::sync::Mutex::new(None);

    #[cfg(test)]
    pub(in crate::serve_chirho) fn fail_for_principal_chirho(principal_chirho: Option<&str>) {
        *FAIL_FOR_PRINCIPAL_CHIRHO
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            principal_chirho.map(str::to_string);
    }

    pub(super) fn checked_chirho(_principal_chirho: &str) -> anyhow::Result<()> {
        #[cfg(test)]
        if FAIL_FOR_PRINCIPAL_CHIRHO
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_deref()
            == Some(_principal_chirho)
        {
            anyhow::bail!("the one-time page hook failed this page");
        }
        Ok(())
    }
}

/// Test-only: panic one principal's issuance task right after the issuer returns, inside the production road's blocking
/// closure, so the arms reach a task that fails after a real key append (PFE #26813). Outside tests it does nothing.
pub(super) mod after_issue_seam_chirho {
    #[cfg(test)]
    static PANIC_FOR_PRINCIPAL_CHIRHO: std::sync::Mutex<Option<String>> =
        std::sync::Mutex::new(None);

    #[cfg(test)]
    pub(in crate::serve_chirho) fn panic_for_principal_chirho(principal_chirho: Option<&str>) {
        *PANIC_FOR_PRINCIPAL_CHIRHO
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            principal_chirho.map(str::to_string);
    }

    pub(super) fn run_chirho(_principal_chirho: &str) {
        #[cfg(test)]
        let armed_chirho = PANIC_FOR_PRINCIPAL_CHIRHO
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_deref()
            == Some(_principal_chirho);
        #[cfg(test)]
        assert!(
            !armed_chirho,
            "the after-issue seam panicked this issuance task"
        );
    }
}

#[cfg(test)]
#[path = "auth_connection_new_tests_chirho.rs"]
mod auth_connection_new_tests_chirho;
