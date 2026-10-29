// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Served app HTTP route execution and signed domain-binding fallback.

use super::{
    admit_served_dag_request_chirho, await_owned_served_work_chirho,
    ensure_customer_write_tenant_root_chirho, served_request_rejected_response_chirho,
    try_run_served_input_with_context_chirho,
    write_relay_chirho::{
        caller_key_carrier_chirho::{
            self, CallerKeyCarrierRefusalChirho, REFUSAL_CALLER_KEY_INVALID_CHIRHO,
            REFUSAL_WRITE_UNAVAILABLE_CHIRHO,
        },
        dispatch_before_app_selection_chirho, local_pre_body_route_policy_applies_chirho,
        unconverted_elected_entrypoint_response_chirho, RelayedRequestMarkerChirho,
        ServedWriteBeforeSelectionChirho,
    },
    AppStateChirho,
};
use anyhow::Result;
#[cfg(test)]
use axum::body::Bytes;
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, OriginalUri, Path as AxPath, State},
    http::{
        header::{CONTENT_TYPE, HOST},
        HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri,
    },
    response::{IntoResponse, Response},
};
use cairn_chirho::model_chirho::RequestContextChirho;
use cairn_chirho::{app_chirho, domain_binding_chirho};
use cairn_write_relay_chirho::{CallerIdempotencyKeyChirho, CallerOperationBindingChirho};
use cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho;

pub(super) type DomainBindingRecordChirho = domain_binding_chirho::DomainBindingRecordChirho;
const MAX_SERVED_APP_REQUEST_BODY_BYTES_CHIRHO: usize = 2 * 1024 * 1024;
// The FIRST LINE of a served app-execution refusal body: its refusal identity. On the app route the lines after it
// carry the trusted observation's knowledge, attempt and scope (public_error_chirho); the elected-era pure-read road
// still answers this line alone. No body carries the underlying error text. Exported so smokes pin the identity line.
pub const APP_EXECUTION_REFUSAL_BODY_CHIRHO: &str = "error: CairnAppExecutionRefusedChirho\n";
pub const APP_AUTHENTICATION_REQUIRED_BODY_CHIRHO: &str = "authentication required\n";

pub(super) fn app_execution_refusal_log_line_chirho(error_chirho: &anyhow::Error) -> String {
    cairn_chirho::dag_chirho::refusal_chirho::dag_execution_refusal_log_line_chirho(error_chirho)
}

pub(super) fn verified_domain_bindings_for_root_chirho(
    root_chirho: &std::path::Path,
) -> Result<Vec<DomainBindingRecordChirho>> {
    domain_binding_chirho::verified_domain_bindings_chirho(root_chirho)
}

pub(super) async fn app_route_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath((name_chirho, route_chirho)): AxPath<(String, String)>,
    OriginalUri(uri_chirho): OriginalUri,
) -> Response {
    let response_chirho = run_and_finish_app_http_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &name_chirho,
        Some(&route_chirho),
        Method::GET,
        uri_chirho,
        Vec::new(),
        None,
    )
    .await;
    // K2: a public app's success to an anonymous GET stays public; every other answer is private.
    super::answer_cache_chirho::public_app_answer_if_anonymous_chirho(
        &state_chirho,
        &headers_chirho,
        &name_chirho,
        response_chirho,
    )
}

/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/served-request-admission-workflow-chirho.md`.
pub(super) async fn app_route_post_request_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath((name_chirho, route_chirho)): AxPath<(String, String)>,
    request_chirho: Request<Body>,
) -> Response {
    if local_pre_body_route_policy_applies_chirho(&state_chirho) {
        if let Some(response_chirho) = pre_body_request_access_refusal_chirho(
            &state_chirho,
            &headers_chirho,
            &name_chirho,
            Some(&route_chirho),
        ) {
            return response_chirho;
        }
        if direct_route_rejects_request_body_chirho(&state_chirho, &name_chirho, &route_chirho) {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
    }
    let uri_chirho = request_chirho.uri().clone();
    let body_chirho = match read_served_app_request_body_chirho(request_chirho).await {
        Ok(body_chirho) => body_chirho,
        Err(response_chirho) => return response_chirho,
    };
    run_and_finish_app_http_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &name_chirho,
        Some(&route_chirho),
        Method::POST,
        uri_chirho,
        body_chirho,
        None,
    )
    .await
}

#[cfg(test)]
pub(super) async fn app_route_post_chirho(
    state_chirho: State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    path_chirho: AxPath<(String, String)>,
    body_chirho: Bytes,
) -> Response {
    app_route_post_request_chirho(
        state_chirho,
        connect_info_chirho,
        headers_chirho,
        path_chirho,
        Request::new(Body::from(body_chirho)),
    )
    .await
}

/// Map the request path under a matched binding prefix onto a served app route:
/// the prefix itself (or trailing slash) means the binding's default surface, one extra
/// path segment names an app route, and deeper paths are not servable in v1.
pub(super) fn binding_route_for_path_chirho(
    prefix_chirho: &str,
    path_chirho: &str,
) -> Option<Option<String>> {
    let remainder_chirho = if prefix_chirho == "/" {
        path_chirho.strip_prefix('/')?
    } else {
        let rest_chirho = path_chirho.strip_prefix(prefix_chirho)?;
        rest_chirho.strip_prefix('/').unwrap_or(rest_chirho)
    };
    let trimmed_chirho = remainder_chirho.trim_end_matches('/');
    if trimmed_chirho.is_empty() {
        return Some(None);
    }
    if trimmed_chirho.contains('/') {
        return None;
    }
    Some(Some(trimmed_chirho.to_string()))
}

/// Fallback for requests no explicit route matched: when domain routing is enabled, resolve
/// (Host, path) through the signed binding table and dispatch into the bound app's existing
/// gated serve path; otherwise (or when unbound) answer the legacy 404. Binding verification
/// failures answer 503 without detail — fail closed, never route on an unverified table.
pub(super) async fn domain_binding_fallback_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    request_chirho: Request<Body>,
) -> Response {
    let method_chirho = request_chirho.method().clone();
    let headers_chirho = request_chirho.headers().clone();
    let uri_chirho = request_chirho.uri().clone();
    let path_chirho = request_chirho.uri().path().to_string();
    if !state_chirho.domain_routing_enabled_chirho {
        return StatusCode::NOT_FOUND.into_response();
    }
    if method_chirho != Method::GET && method_chirho != Method::POST {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(host_chirho) = headers_chirho
        .get(HOST)
        .and_then(|h_chirho| h_chirho.to_str().ok())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(response_chirho) = unconverted_elected_entrypoint_response_chirho(&state_chirho) {
        return response_chirho;
    }
    let records_chirho = match state_chirho
        .runtime_chirho
        .verified_domain_bindings_chirho()
    {
        Ok(records_chirho) => records_chirho,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "domain routing unavailable",
            )
                .into_response()
        }
    };
    let Some(binding_chirho) = domain_binding_chirho::resolve_domain_binding_chirho(
        &records_chirho,
        host_chirho,
        &path_chirho,
    ) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(route_slot_chirho) =
        binding_route_for_path_chirho(&binding_chirho.path_prefix_chirho, &path_chirho)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let route_chirho = match route_slot_chirho {
        Some(route_chirho) => Some(route_chirho),
        None => binding_chirho.route_base_chirho.clone(),
    };
    if let Some(response_chirho) = pre_body_request_access_refusal_chirho(
        &state_chirho,
        &headers_chirho,
        &binding_chirho.app_chirho,
        route_chirho.as_deref(),
    ) {
        return response_chirho;
    }
    let input_chirho = if method_chirho == Method::POST {
        let rejects_request_body_chirho = match route_chirho.as_deref() {
            Some(route_chirho) => direct_route_rejects_request_body_chirho(
                &state_chirho,
                &binding_chirho.app_chirho,
                route_chirho,
            ),
            None => match direct_app_rejects_request_body_chirho(
                &state_chirho,
                &binding_chirho.app_chirho,
            ) {
                Ok(rejects_request_body_chirho) => rejects_request_body_chirho,
                Err(error_chirho) => {
                    return app_selection_error_response_chirho(error_chirho, &headers_chirho)
                }
            },
        };
        if rejects_request_body_chirho {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        match read_served_app_request_body_chirho(request_chirho).await {
            Ok(body_chirho) => body_chirho,
            Err(response_chirho) => return response_chirho,
        }
    } else {
        Vec::new()
    };
    run_and_finish_app_http_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &binding_chirho.app_chirho,
        route_chirho.as_deref(),
        method_chirho,
        uri_chirho,
        input_chirho,
        None,
    )
    .await
}

/// Resolve a deployed app name or app route -> its `DagChirho` ref and run it.
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/served-request-admission-workflow-chirho.md`.
pub(super) async fn run_app_http_with_method_for_served_request_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    headers_chirho: &HeaderMap,
    name_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: Method,
    input_chirho: Vec<u8>,
) -> Response {
    let uri_chirho = direct_app_uri_chirho(name_chirho, route_chirho);
    run_and_finish_app_http_chirho(
        state_chirho,
        peer_chirho,
        headers_chirho,
        name_chirho,
        route_chirho,
        method_chirho,
        uri_chirho,
        input_chirho,
        None,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "relay reentry carries one complete verified HTTP request and process-local marker"
)]
pub(super) async fn run_app_http_with_method_for_relay_reentry_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    name_chirho: &str,
    route_chirho: &str,
    method_chirho: Method,
    uri_chirho: Uri,
    input_chirho: Vec<u8>,
    marker_chirho: &RelayedRequestMarkerChirho,
) -> Response {
    run_and_finish_app_http_chirho(
        state_chirho,
        None,
        headers_chirho,
        name_chirho,
        Some(route_chirho),
        method_chirho,
        uri_chirho,
        input_chirho,
        Some(marker_chirho),
    )
    .await
}

/// The COMPLETE public refusal bodies the served-LLM card dispatch returns — refusal identity only,
/// never underlying detail. Exported so a negative test pins the exact identity, mirroring the relay.
pub(super) const SERVED_LLM_LOCAL_AUTHORITY_UNAVAILABLE_BODY_CHIRHO: &str =
    "error: ServedLlmLocalAuthorityUnavailableChirho\n";
pub(super) const SERVED_LLM_CALLER_KEY_REQUIRED_BODY_CHIRHO: &str =
    "error: ServedLlmCallerKeyRequiredChirho\n";
pub(super) const SERVED_LLM_CALLER_KEY_INVALID_BODY_CHIRHO: &str =
    "error: ServedLlmCallerKeyInvalidChirho\n";
pub(super) const SERVED_LLM_CALLER_KEY_DUPLICATE_BODY_CHIRHO: &str =
    "error: ServedLlmCallerKeyDuplicateChirho\n";
pub(super) const SERVED_LLM_RENDER_NOT_PURE_BODY_CHIRHO: &str =
    "error: ServedLlmRenderNotPureChirho\n";

/// The outcome of scoping one HTTP request against the ONE composed served-LLM card surface.
/// Anything that is not the composed app plus an eligible surface (render root GET | paid route POST)
/// returns `NotServedCardChirho`, so it falls through to the UNCHANGED credits/relay dispatch.
enum LlmServedCardAdmissionChirho {
    NotServedCardChirho,
    /// The served paid route is refused because local write authority is not live (deposed /
    /// transferring / not-warm) or the single composition is busy. `reason_chirho` is the specific
    /// write-path/contention identity, captured for the server log; the public wire stays no-detail.
    LocalAuthorityUnavailableChirho {
        reason_chirho: String,
    },
    /// The paid POST's caller key could not be read by the shared carrier; refused before any run.
    CallerKeyRefusedChirho(CallerKeyCarrierRefusalChirho),
    /// The paid POST's method and URI could not bind a caller operation; refused before any run.
    OperationInvalidChirho,
    RenderRootChirho,
    PaidRouteChirho {
        caller_key_chirho: CallerIdempotencyKeyChirho,
        operation_chirho: CallerOperationBindingChirho,
        /// The body without the carrier field when the key came from a form.
        business_body_chirho: Option<Vec<u8>>,
    },
}

/// Route-scoped, live-authority-gated, caller-key-validated admission for the ONE composed served
/// card. It admits only the composed app's render root under GET/HEAD (no caller key), and the
/// composed app's single paid route under POST (live local authority plus a present, valid, unique
/// caller key). Every other app, route, or method returns `NotServedCardChirho`, so there is never a
/// blanket `Some(composition)` exemption and the credits relay path is untouched.
fn admit_llm_served_card_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    name_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: &Method,
    uri_chirho: &Uri,
    body_chirho: &[u8],
) -> LlmServedCardAdmissionChirho {
    let Some((served_app_chirho, paid_route_chirho)) =
        state_chirho.runtime_chirho.llm_served_card_surface_chirho()
    else {
        return LlmServedCardAdmissionChirho::NotServedCardChirho;
    };
    if name_chirho != served_app_chirho {
        return LlmServedCardAdmissionChirho::NotServedCardChirho;
    }
    // Render root: the composed app's root (no route) under a read method. Pure render, no money, no
    // caller key, no write-authority gate.
    if route_chirho.is_none() && matches!(*method_chirho, Method::GET | Method::HEAD) {
        return LlmServedCardAdmissionChirho::RenderRootChirho;
    }
    // Paid route: the composed app's single route under POST. This is the money/effect path.
    if method_chirho == Method::POST && route_chirho == Some(paid_route_chirho) {
        // Live-authority gate FIRST: derive it from the resident actor's current append authority,
        // capturing the specific refusal reason (never `is_ok`-discarding it) for the server log.
        match state_chirho
            .runtime_chirho
            .probe_llm_served_local_authority_chirho()
        {
            Some(Ok(())) => {}
            Some(Err(reason_chirho)) => {
                return LlmServedCardAdmissionChirho::LocalAuthorityUnavailableChirho {
                    reason_chirho: format!("{reason_chirho:#}"),
                }
            }
            None => {
                return LlmServedCardAdmissionChirho::LocalAuthorityUnavailableChirho {
                    reason_chirho: "no served-LLM composition is injected".to_string(),
                }
            }
        }
        // The key comes from the form's field or the header, through the one shared reader.
        let reading_chirho =
            match caller_key_carrier_chirho::read_caller_key_chirho(headers_chirho, body_chirho) {
                Ok(reading_chirho) => reading_chirho,
                Err(refusal_chirho) => {
                    return LlmServedCardAdmissionChirho::CallerKeyRefusedChirho(refusal_chirho)
                }
            };
        return match CallerOperationBindingChirho::new_chirho(
            method_chirho.as_str(),
            uri_chirho.to_string(),
        ) {
            Ok(operation_chirho) => LlmServedCardAdmissionChirho::PaidRouteChirho {
                caller_key_chirho: reading_chirho.caller_key_chirho,
                operation_chirho,
                business_body_chirho: reading_chirho.business_body_chirho,
            },
            Err(_error_chirho) => LlmServedCardAdmissionChirho::OperationInvalidChirho,
        };
    }
    // The composed app, but not an eligible served surface (e.g. POST to the render root, or GET the
    // paid route): fall through to the unchanged dispatch, preserving the original behavior.
    LlmServedCardAdmissionChirho::NotServedCardChirho
}

fn llm_served_admission_refusal_response_chirho(
    status_chirho: StatusCode,
    body_chirho: &'static str,
) -> Response {
    (status_chirho, body_chirho).into_response()
}

/// A served-card refusal before any run: the browser's 303 with `token_chirho` for a form submission, and
/// the card's own named refusal for every other caller.
fn served_card_refusal_response_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    app_chirho: &str,
    token_chirho: &'static str,
    status_chirho: StatusCode,
    body_chirho: &'static str,
) -> Response {
    if !caller_key_carrier_chirho::is_browser_form_submission_chirho(headers_chirho) {
        return llm_served_admission_refusal_response_chirho(status_chirho, body_chirho);
    }
    state_chirho
        .runtime_chirho
        .browser_form_refusal_on_app_chirho(headers_chirho, app_chirho, token_chirho)
}

/// The card's named body for each way the carrier can refuse a key: absent, repeated, or invalid.
fn served_card_caller_key_refusal_body_chirho(
    refusal_chirho: CallerKeyCarrierRefusalChirho,
) -> &'static str {
    use CallerKeyCarrierRefusalChirho as RefusalChirho;
    match refusal_chirho {
        RefusalChirho::HeaderMissingChirho
        | RefusalChirho::FieldMissingChirho
        | RefusalChirho::FieldEmptyChirho => SERVED_LLM_CALLER_KEY_REQUIRED_BODY_CHIRHO,
        RefusalChirho::HeaderDuplicateChirho | RefusalChirho::FieldDuplicateChirho => {
            SERVED_LLM_CALLER_KEY_DUPLICATE_BODY_CHIRHO
        }
        RefusalChirho::HeaderInvalidChirho
        | RefusalChirho::FieldInvalidChirho
        | RefusalChirho::HeaderFieldMismatchChirho
        | RefusalChirho::MultipartNotYetCarriedChirho => SERVED_LLM_CALLER_KEY_INVALID_BODY_CHIRHO,
    }
}

/// The one road every app-route entry takes: run the request through the app-route core, then finish
/// the answer for the browser. The core keeps its name because the HA1/HA2 ordering guards read it.
#[allow(
    clippy::too_many_arguments,
    reason = "the internal serve boundary carries one complete HTTP request and optional relay marker"
)]
async fn run_and_finish_app_http_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    headers_chirho: &HeaderMap,
    name_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: Method,
    uri_chirho: Uri,
    input_chirho: Vec<u8>,
    reentry_chirho: Option<&RelayedRequestMarkerChirho>,
) -> Response {
    let response_chirho = run_app_http_with_method_for_served_request_and_uri_chirho(
        state_chirho,
        peer_chirho,
        headers_chirho,
        name_chirho,
        route_chirho,
        method_chirho,
        uri_chirho,
        input_chirho,
        reentry_chirho,
    )
    .await;
    finish_answer_for_browser_chirho(
        state_chirho,
        name_chirho,
        reentry_chirho.is_some(),
        response_chirho,
    )
    .await
}

/// The last step of every app answer: browser caller keys go into the page at the node that answers the
/// browser. A relayed re-entry answers the source, so its signed answer keeps the empty placeholders, as
/// recorded outcomes do: every answer, a replay included, gets fresh keys.
pub(super) async fn finish_answer_for_browser_chirho(
    state_chirho: &AppStateChirho,
    app_chirho: &str,
    relayed_reentry_chirho: bool,
    response_chirho: Response,
) -> Response {
    if relayed_reentry_chirho
        || !caller_key_carrier_chirho::answer_is_html_chirho(&response_chirho)
        || !issues_browser_caller_keys_chirho(state_chirho, app_chirho)
    {
        return response_chirho;
    }
    caller_key_carrier_chirho::issue_caller_keys_into_answer_chirho(response_chirho).await
}

/// Whether this root fills the empty caller-key placeholders in an app's pages: every app on an elected
/// root, and on a local root only the composed served-LLM card's app, whose paid POST needs a key. Other
/// local-root pages keep their placeholders empty, and their readers drop the field (PFE's contract).
fn issues_browser_caller_keys_chirho(state_chirho: &AppStateChirho, app_chirho: &str) -> bool {
    matches!(
        state_chirho.runtime_chirho.writer_authority_era_chirho(),
        Ok(WriterAuthorityEraChirho::ElectedChirho)
    ) || state_chirho
        .runtime_chirho
        .llm_served_card_surface_chirho()
        .is_some_and(|(served_app_chirho, _paid_route_chirho)| served_app_chirho == app_chirho)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the internal serve boundary carries one complete HTTP request and optional relay marker"
)]
async fn run_app_http_with_method_for_served_request_and_uri_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    headers_chirho: &HeaderMap,
    name_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: Method,
    uri_chirho: Uri,
    input_chirho: Vec<u8>,
    reentry_chirho: Option<&RelayedRequestMarkerChirho>,
) -> Response {
    if super::write_relay_chirho::pure_app_read_chirho::applies_chirho(
        state_chirho,
        name_chirho,
        route_chirho,
        &method_chirho,
    ) {
        return super::write_relay_chirho::pure_app_read_chirho::run_chirho(
            state_chirho,
            super::write_relay_chirho::pure_app_read_chirho::PureAppReadRequestChirho {
                peer_chirho,
                headers_chirho,
                app_chirho: name_chirho,
                route_chirho: route_chirho.expect("pure named route"),
                uri_chirho: &uri_chirho,
                reentry_chirho,
                method_chirho: &method_chirho,
                body_chirho: input_chirho,
            },
        )
        .await;
    }
    let local_pre_body_policy_chirho = local_pre_body_route_policy_applies_chirho(state_chirho);
    let defer_scoped_token_use_chirho = !local_pre_body_policy_chirho;
    let (mut context_chirho, prepared_context_chirho, key_binding_chirho) =
        if defer_scoped_token_use_chirho {
            match state_chirho
                .runtime_chirho
                .prepare_app_request_context_chirho(headers_chirho, name_chirho, route_chirho)
            {
                Ok(prepared_chirho) => {
                    let key_binding_chirho = prepared_chirho.key_binding_chirho().cloned();
                    (
                        prepared_chirho.context_chirho().cloned(),
                        Some(prepared_chirho),
                        key_binding_chirho,
                    )
                }
                Err(e_chirho) => {
                    return super::public_error_chirho::public_error_response_chirho(
                        "app-request-context-chirho",
                        super::public_error_chirho::classify_request_context_chirho(&e_chirho),
                        headers_chirho,
                        None,
                    )
                }
            }
        } else {
            match state_chirho
                .runtime_chirho
                .request_context_for_app_route_chirho(headers_chirho, name_chirho, route_chirho)
            {
                Ok(route_context_chirho) => (
                    route_context_chirho.context_chirho,
                    None,
                    route_context_chirho.key_binding_chirho,
                ),
                Err(e_chirho) => {
                    return super::public_error_chirho::public_error_response_chirho(
                        "app-request-context-chirho",
                        super::public_error_chirho::classify_request_context_chirho(&e_chirho),
                        headers_chirho,
                        None,
                    )
                }
            }
        };
    if local_pre_body_policy_chirho {
        if let Some(response_chirho) = request_access_refusal_for_context_chirho(
            state_chirho,
            headers_chirho,
            name_chirho,
            context_chirho.as_ref(),
        ) {
            return response_chirho;
        }
    }
    let admission_result_chirho = if let Some(reentry_chirho) = reentry_chirho {
        reentry_chirho
            .take_ingress_chirho()
            .and_then(|ingress_chirho| {
                state_chirho
                    .served_request_abuse_gate_chirho
                    .promote_ingress_chirho(
                        ingress_chirho,
                        context_chirho
                            .as_ref()
                            .map(|context_chirho| context_chirho.user_principal_chirho.as_str()),
                    )
            })
    } else {
        admit_served_dag_request_chirho(
            state_chirho,
            peer_chirho,
            headers_chirho,
            context_chirho.as_ref(),
            input_chirho.len(),
        )
    };
    let admission_chirho = match admission_result_chirho {
        Ok(admission_chirho) => admission_chirho,
        Err(_error_chirho) => {
            // The route asked for, as declared: a JSON route answers its refusal in JSON (R13 Part 8). A lookup that
            // fails declares nothing, so the refusal falls back to the request's Accept.
            let declared_chirho = state_chirho
                .runtime_chirho
                .app_route_http_response_content_type_chirho(
                    name_chirho,
                    route_chirho,
                    context_chirho.as_ref(),
                )
                .ok()
                .flatten();
            return served_request_rejected_response_chirho(
                state_chirho,
                headers_chirho,
                declared_chirho.as_deref(),
            );
        }
    };
    // Served-LLM card dispatch (GAP 2): route-scoped, live-authority-gated, caller-key-validated
    // admission for the ONE composed served card. Anything else — including every unrelated app and
    // route — returns `NotServedCardChirho` and keeps the credits/relay route selection below.
    // F1 adds signed ingress evidence and detached permit custody without changing writer authority.
    let (caller_key_op_chirho, business_body_chirho, served_render_root_chirho): (
        Option<(CallerIdempotencyKeyChirho, CallerOperationBindingChirho)>,
        Option<Vec<u8>>,
        bool,
    ) = match admit_llm_served_card_chirho(
        state_chirho,
        headers_chirho,
        name_chirho,
        route_chirho,
        &method_chirho,
        &uri_chirho,
        &input_chirho,
    ) {
        LlmServedCardAdmissionChirho::NotServedCardChirho => {
            let dispatch_chirho = if reentry_chirho.is_some() {
                dispatch_before_app_selection_chirho(
                    state_chirho,
                    headers_chirho,
                    name_chirho,
                    route_chirho,
                    &method_chirho,
                    &uri_chirho,
                    &input_chirho,
                    reentry_chirho,
                    None,
                )
                .await
            } else {
                super::write_relay_chirho::dispatch_origin_with_custody_chirho(
                    state_chirho,
                    super::write_relay_chirho::RelayOriginRequestChirho {
                        headers_chirho,
                        app_chirho: name_chirho,
                        route_chirho,
                        method_chirho: &method_chirho,
                        uri_chirho: &uri_chirho,
                        body_chirho: &input_chirho,
                    },
                    admission_chirho.ingress_assertion_chirho(),
                    admission_chirho.retain_for_dispatch_chirho(),
                )
                .await
            };
            match dispatch_chirho {
                // The relay's verdict carries the body the run must see, the carrier field removed;
                // dropping it here would run the raw form (gpt #28889).
                ServedWriteBeforeSelectionChirho::ContinueChirho(Some(caller_operation_chirho)) => {
                    let (caller_key_chirho, operation_chirho, business_body_chirho) =
                        caller_operation_chirho.into_parts_chirho();
                    (
                        Some((caller_key_chirho, operation_chirho)),
                        business_body_chirho,
                        false,
                    )
                }
                ServedWriteBeforeSelectionChirho::ContinueChirho(None) => (None, None, false),
                ServedWriteBeforeSelectionChirho::RespondChirho(response_chirho) => {
                    return response_chirho
                }
            }
        }
        LlmServedCardAdmissionChirho::LocalAuthorityUnavailableChirho { reason_chirho } => {
            // Capture the specific write-path/contention reason to the server log; the public
            // wire stays the fixed no-detail identity (never leak the internal refusal type).
            eprintln!(
                "served-LLM paid route refused: {} ({reason_chirho})",
                SERVED_LLM_LOCAL_AUTHORITY_UNAVAILABLE_BODY_CHIRHO.trim()
            );
            return served_card_refusal_response_chirho(
                state_chirho,
                headers_chirho,
                name_chirho,
                REFUSAL_WRITE_UNAVAILABLE_CHIRHO,
                StatusCode::SERVICE_UNAVAILABLE,
                SERVED_LLM_LOCAL_AUTHORITY_UNAVAILABLE_BODY_CHIRHO,
            );
        }
        LlmServedCardAdmissionChirho::CallerKeyRefusedChirho(refusal_chirho) => {
            eprintln!(
                "served-LLM paid route refused before any run: caller key ({refusal_chirho:?})"
            );
            return served_card_refusal_response_chirho(
                state_chirho,
                headers_chirho,
                name_chirho,
                REFUSAL_CALLER_KEY_INVALID_CHIRHO,
                StatusCode::BAD_REQUEST,
                served_card_caller_key_refusal_body_chirho(refusal_chirho),
            );
        }
        LlmServedCardAdmissionChirho::OperationInvalidChirho => {
            return served_card_refusal_response_chirho(
                state_chirho,
                headers_chirho,
                name_chirho,
                REFUSAL_CALLER_KEY_INVALID_CHIRHO,
                StatusCode::BAD_REQUEST,
                SERVED_LLM_CALLER_KEY_INVALID_BODY_CHIRHO,
            );
        }
        LlmServedCardAdmissionChirho::RenderRootChirho => (None, None, true),
        LlmServedCardAdmissionChirho::PaidRouteChirho {
            caller_key_chirho,
            operation_chirho,
            business_body_chirho,
        } => (
            Some((caller_key_chirho, operation_chirho)),
            business_body_chirho,
            false,
        ),
    };
    if !local_pre_body_policy_chirho {
        if let Some(response_chirho) = request_access_refusal_for_context_chirho(
            state_chirho,
            headers_chirho,
            name_chirho,
            context_chirho.as_ref(),
        ) {
            return response_chirho;
        }
    }
    if let Some(prepared_context_chirho) = prepared_context_chirho {
        context_chirho = match state_chirho
            .runtime_chirho
            .commit_prepared_app_request_context_chirho(prepared_context_chirho)
        {
            Ok(context_chirho) => context_chirho,
            Err(e_chirho) => {
                return super::public_error_chirho::public_error_response_chirho(
                    "app-request-context-chirho",
                    super::public_error_chirho::classify_request_context_chirho(&e_chirho),
                    headers_chirho,
                    None,
                )
            }
        };
    }
    // The final recheck before execution: it closes a policy change between the pre-body check and here
    // (final_named_route_policy_recheck_closes_preflight_ref_change_chirho). It charges nothing.
    if method_chirho == Method::POST
        && route_chirho.is_some_and(|route_chirho| {
            direct_route_rejects_request_body_chirho(state_chirho, name_chirho, route_chirho)
        })
    {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    #[cfg(test)]
    super::public_error_chirho::hold_points_chirho::reach_for_root_chirho(
        super::public_error_chirho::hold_points_chirho::HoldPointChirho::BeforeAppRefsReadChirho,
        state_chirho.runtime_chirho.root_path_chirho(),
    );
    let refs_val_chirho = match state_chirho.runtime_chirho.load_refs_chirho() {
        Ok(refs_chirho) => refs_chirho,
        Err(error_chirho) => {
            // Before any DAG run: a typed resource cause answers 503, anything else this site's fixed 500.
            let failure_chirho = super::public_error_chirho::classify_pre_run_chirho(
                &error_chirho,
                StatusCode::INTERNAL_SERVER_ERROR,
                "served-request-internal-error-chirho",
            );
            return super::public_error_chirho::public_error_response_chirho(
                "app-refs-load-chirho",
                failure_chirho,
                headers_chirho,
                None,
            );
        }
    };
    let selection_chirho = match route_chirho {
        Some(route_chirho) => state_chirho
            .runtime_chirho
            .select_app_route_dag_direct_chirho(
                &refs_val_chirho,
                name_chirho,
                route_chirho,
                context_chirho.as_ref(),
            ),
        None => state_chirho
            .runtime_chirho
            .select_app_dag_with_resource_gate_chirho(
                &refs_val_chirho,
                name_chirho,
                context_chirho.as_ref(),
            ),
    };
    let selection_chirho = match selection_chirho {
        Ok(selection_chirho) => selection_chirho,
        Err(error_chirho) => {
            return app_selection_error_response_chirho(error_chirho, headers_chirho)
        }
    };
    // A limited key was admitted against one route and DAG; the request must still be running exactly those. A
    // resource-policy reroute or a redeploy between the gate and here refuses it, before the input is sealed or the DAG
    // runs. (By here the key's use is recorded, and a reroute's usage row may exist.)
    if let Some(binding_chirho) = &key_binding_chirho {
        if selection_chirho.route_chirho.as_deref() != Some(binding_chirho.route_chirho.as_str())
            || selection_chirho.dag_chirho != binding_chirho.dag_chirho
        {
            return key_route_changed_response_chirho(headers_chirho);
        }
    }
    // KEYLESS GET PURITY (item 1 / Finding 5): the served render root was admitted from URL coordinates
    // only. The FINAL selected DAG (after any resource-gate reroute or a signed redeployment of these
    // same coordinates) must be capability-free Tier-1 PURE WASM before it executes with NO caller key.
    // REUSE the public-run guard, which rejects BOTH declared capabilities AND native specs (a native
    // node would otherwise bypass a capability-only check). Validate here, before DAG input, CAS, run,
    // or any effect — a keyless render must never run an effect or native DAG wearing a GET URL. Fail
    // closed on load error too.
    if served_render_root_chirho {
        if let Err(purity_error_chirho) = state_chirho
            .runtime_chirho
            .ensure_public_run_dag_is_pure_wasm_chirho(&selection_chirho.dag_chirho)
        {
            eprintln!(
                "served-LLM render root refused: {} ({purity_error_chirho:#})",
                SERVED_LLM_RENDER_NOT_PURE_BODY_CHIRHO.trim()
            );
            return llm_served_admission_refusal_response_chirho(
                StatusCode::FORBIDDEN,
                SERVED_LLM_RENDER_NOT_PURE_BODY_CHIRHO,
            );
        }
    }
    // A resource-gate usage row may already exist when rerouting selects this policy.
    // The final ceiling still runs before DAG input, CAS, run, or privacy persistence.
    let final_no_body_chirho =
        method_chirho == Method::POST && !selection_chirho.accepts_request_body_chirho();
    if final_no_body_chirho {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if let Err(e_chirho) = ensure_customer_write_tenant_root_chirho(
        state_chirho,
        &selection_chirho.dag_chirho,
        "/app-chirho",
    ) {
        // An operator configuration refusal: the visitor learns only that the app cannot write here.
        let failure_chirho = super::public_error_chirho::classify_pre_run_chirho(
            &e_chirho,
            StatusCode::FORBIDDEN,
            "app-write-not-available-chirho",
        );
        return super::public_error_chirho::public_error_response_chirho(
            "app-write-tenant-chirho",
            failure_chirho,
            headers_chirho,
            None,
        );
    }
    let response_content_type_chirho = match state_chirho
        .runtime_chirho
        .app_route_http_response_content_type_chirho(
            name_chirho,
            selection_chirho.route_chirho.as_deref(),
            context_chirho.as_ref(),
        ) {
        Ok(response_content_type_chirho) => response_content_type_chirho,
        Err(e_chirho) => {
            let failure_chirho = super::public_error_chirho::classify_pre_run_chirho(
                &e_chirho,
                StatusCode::BAD_REQUEST,
                "app-response-policy-unavailable-chirho",
            );
            return super::public_error_chirho::public_error_response_chirho(
                "app-response-policy-chirho",
                failure_chirho,
                headers_chirho,
                None,
            );
        }
    };
    // Parsed BEFORE the run: once a run has landed a write, the answer is the saved result, never a refusal.
    let response_content_type_header_chirho = match response_content_type_chirho
        .as_deref()
        .map(HeaderValue::from_str)
        .transpose()
    {
        Ok(header_chirho) => header_chirho,
        Err(e_chirho) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("error: invalid response content type: {e_chirho}\n"),
            )
                .into_response()
        }
    };
    let selected_input_chirho = if selection_chirho.discard_request_body_chirho
        || !selection_chirho.accepts_request_body_chirho()
    {
        Vec::new()
    } else if let Some(business_body_chirho) = business_body_chirho {
        // The caller key came from the form's field, read before any run. The run sees the body without
        // it, so the raw key never reaches the DAG business input or its sealed input record; only the
        // key's digest rides run identity, by design (gpt #28889).
        business_body_chirho
    } else {
        input_chirho
    };
    let dag_input_chirho = match state_chirho.runtime_chirho.app_http_dag_input_value_chirho(
        name_chirho,
        selection_chirho.route_chirho.as_deref(),
        context_chirho.as_ref(),
        headers_chirho,
        selected_input_chirho,
    ) {
        Ok(input_chirho) => input_chirho,
        Err(e_chirho) => {
            return super::public_error_chirho::public_error_response_chirho(
                "app-input-chirho",
                super::public_error_chirho::classify_app_input_chirho(&e_chirho),
                headers_chirho,
                response_content_type_chirho.as_deref(),
            )
        }
    };

    // The run, then its after-write refresh, inside ONE detached task that owns the admission: a handler that is
    // cancelled mid-request drops only its own future, so the in-flight permit is released when this work ends, not
    // before. Both go to the blocking pool, so neither holds an async worker (served-overload (ii);
    // spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md).
    // A signed-out request's private values join the app owner's container (C5 2a).
    let declared_attribution_chirho = match super::anonymous_app_attribution_chirho(
        state_chirho,
        name_chirho,
        context_chirho.as_ref(),
    ) {
        Ok(declared_chirho) => declared_chirho,
        Err(e_chirho) => {
            return super::public_error_chirho::public_error_response_chirho(
                "app-owner-chirho",
                super::public_error_chirho::classify_pre_run_chirho(
                    &e_chirho,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "app-owner-unverified-chirho",
                ),
                headers_chirho,
                response_content_type_chirho.as_deref(),
            )
        }
    };
    let run_state_chirho = state_chirho.clone();
    let run_dag_chirho = selection_chirho.dag_chirho.clone();
    let run_outcome_chirho = await_owned_served_work_chirho(tokio::spawn(async move {
        let payload_chirho = try_run_served_input_with_context_chirho(
            &run_state_chirho,
            &admission_chirho,
            &run_dag_chirho.0,
            dag_input_chirho,
            context_chirho.as_ref(),
            caller_key_op_chirho
                .as_ref()
                .map(|(caller_key_chirho, operation_chirho)| (caller_key_chirho, operation_chirho)),
            declared_attribution_chirho,
        )
        .await?;
        // The run returned Ok, so any write it made has LANDED: from here the answer is the saved result, with no
        // early return. The query projection is derived and no served road reads it (the served Query effect
        // refuses as legacy; served projection reads go through the CF4 port), so a refresh that fails here is
        // only logged. It heals at the next successful refresh: any later write-road request, this request's own
        // identical retry included (PFE #25858; CAIRN #25867). The detail carries filesystem paths, so it goes to
        // the server log only (agy #25855 (d)).
        if let Err(e_chirho) = run_state_chirho
            .runtime_chirho
            .refresh_query_projection_after_write_chirho(&run_dag_chirho)
            .await
        {
            eprintln!("cairn-chirho: query projection refresh after a write failed: {e_chirho:#}");
        }
        drop(admission_chirho);
        Ok::<_, anyhow::Error>(payload_chirho)
    }))
    .await;
    match run_outcome_chirho {
        Ok(payload_chirho) => {
            let mut response_headers_chirho = HeaderMap::new();
            if let (Some(response_content_type_chirho), Some(value_chirho)) = (
                response_content_type_chirho,
                response_content_type_header_chirho,
            ) {
                response_headers_chirho.insert(CONTENT_TYPE, value_chirho);
                state_chirho
                    .runtime_chirho
                    .apply_app_route_response_security_headers_chirho(
                        name_chirho,
                        &payload_chirho,
                        &mut response_headers_chirho,
                        &response_content_type_chirho,
                    );
            }
            if selection_chirho.unreviewed_dev_chirho {
                response_headers_chirho.insert(
                    HeaderName::from_static(app_chirho::APP_UNREVIEWED_DEV_HEADER_CHIRHO),
                    HeaderValue::from_static(app_chirho::APP_UNREVIEWED_DEV_HEADER_VALUE_CHIRHO),
                );
            }
            (StatusCode::OK, response_headers_chirho, payload_chirho).into_response()
        }
        Err(error_chirho) => {
            eprintln!("{}", app_execution_refusal_log_line_chirho(&error_chirho));
            super::public_error_chirho::public_error_response_chirho(
                "app-execution-chirho",
                super::public_error_chirho::classify_execution_chirho(&error_chirho),
                headers_chirho,
                response_content_type_chirho.as_deref(),
            )
        }
    }
}

fn direct_app_uri_chirho(name_chirho: &str, route_chirho: Option<&str>) -> Uri {
    let path_chirho = match route_chirho {
        Some(route_chirho) => format!("/app-chirho/{name_chirho}/{route_chirho}"),
        None => format!("/app-chirho/{name_chirho}"),
    };
    path_chirho
        .parse()
        .expect("validated app and route names always form a relative URI")
}

#[cfg(test)]
pub(super) fn run_app_http_with_method_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    headers_chirho: &HeaderMap,
    name_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: Method,
    input_chirho: Vec<u8>,
) -> Response {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the provider-free app test runtime must build")
        .block_on(run_app_http_with_method_for_served_request_chirho(
            state_chirho,
            peer_chirho,
            headers_chirho,
            name_chirho,
            route_chirho,
            method_chirho,
            input_chirho,
        ))
}

#[cfg(test)]
pub(super) fn run_app_http_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    headers_chirho: &HeaderMap,
    name_chirho: &str,
    route_chirho: Option<&str>,
    input_chirho: Vec<u8>,
) -> Response {
    let method_chirho = if input_chirho.is_empty() {
        Method::GET
    } else {
        Method::POST
    };
    run_app_http_with_method_chirho(
        state_chirho,
        peer_chirho,
        headers_chirho,
        name_chirho,
        route_chirho,
        method_chirho,
        input_chirho,
    )
}

#[cfg(test)]
mod execution_refusal_tests_chirho {
    use super::*;

    #[test]
    fn execution_refusal_log_is_fixed_and_contains_no_error_detail_chirho() {
        let error_chirho = anyhow::anyhow!("/private/app-execution-detail-needle-chirho");
        let line_chirho = app_execution_refusal_log_line_chirho(&error_chirho);
        assert_eq!(
            line_chirho,
            "CairnAppExecutionRefusalChirho:attempt_ordinal_chirho=unclassified-chirho:identity_chirho=DagExecutionUnclassifiedRefusedChirho:knowledge_chirho=unknown-chirho:prior_identity_chirho=none-chirho"
        );
        assert!(!line_chirho.contains("/private/app-execution-detail-needle-chirho"));
    }
}

/// True unless the route's verified policy accepts a body. An `Err` — an unknown route, a forged ref, a tampered
/// record — is a generic denial on purpose: a served route must not reveal route or policy details
/// (`assert_served_control_plane_attack_blocked_chirho`). The CALLER is never resolved here, so a caller's own
/// credential refusal (an exhausted or invalid bearer) surfaces at execution with its real status and reason, and
/// this check charges nothing (PFE #25731, CAIRN #25732).
fn direct_route_rejects_request_body_chirho(
    state_chirho: &AppStateChirho,
    app_chirho: &str,
    route_chirho: &str,
) -> bool {
    !matches!(
        state_chirho
            .runtime_chirho
            .direct_app_route_accepts_request_body_chirho(app_chirho, route_chirho),
        Ok(true)
    )
}

pub(super) fn direct_app_rejects_request_body_chirho(
    state_chirho: &AppStateChirho,
    app_chirho: &str,
) -> Result<bool> {
    state_chirho
        .runtime_chirho
        .direct_app_accepts_request_body_chirho(app_chirho)
        .map(|accepts_request_body_chirho| !accepts_request_body_chirho)
}

/// App selection's public answer: the selection's fixed identity and status, never the requested name or
/// the error text; a typed resource cause answers 503 (PFE #26430, #26451).
pub(super) fn app_selection_error_response_chirho(
    error_chirho: anyhow::Error,
    headers_chirho: &HeaderMap,
) -> Response {
    super::public_error_chirho::public_error_response_chirho(
        "app-selection-chirho",
        super::public_error_chirho::classify_selection_chirho(&error_chirho),
        headers_chirho,
        None,
    )
}

/// The fixed refusal for a limited key whose admitted route or DAG is no longer the one selected (K1).
fn key_route_changed_response_chirho(headers_chirho: &HeaderMap) -> Response {
    super::public_error_chirho::public_error_response_chirho(
        "app-key-route-recheck-chirho",
        super::public_error_chirho::PublicFailureChirho::FixedRefusalChirho {
            status_chirho: StatusCode::CONFLICT,
            identity_chirho: "key-route-changed-chirho",
        },
        headers_chirho,
        None,
    )
}

/// Admit authenticated-only apps before POST body collection. Prepared scoped-token validation is
/// non-consuming; the shared execution boundary remains the only place that commits token use. A bearer is admitted
/// for `route_chirho` (or the app root) through the key gate, so a key the route does not admit refuses here too.
pub(super) fn pre_body_request_access_refusal_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    app_name_chirho: &str,
    route_chirho: Option<&str>,
) -> Option<Response> {
    let policy_chirho = match state_chirho
        .runtime_chirho
        .app_request_access_policy_chirho(app_name_chirho)
    {
        Ok(policy_chirho) => policy_chirho,
        Err(error_chirho) => {
            return Some(request_access_policy_error_response_chirho(
                error_chirho,
                headers_chirho,
            ))
        }
    };
    if !matches!(
        policy_chirho,
        app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho
    ) {
        return None;
    }
    match state_chirho.runtime_chirho.prepare_app_request_context_chirho(
        headers_chirho,
        app_name_chirho,
        route_chirho,
    ) {
        Ok(prepared_chirho) if prepared_chirho.context_chirho().is_some() => None,
        Ok(_) => Some(authentication_required_response_chirho()),
        // A key the gate does not admit gets its own fixed answer; any other failure stays the plain 401.
        Err(error_chirho) => Some(
            match error_chirho.chain().find_map(|cause_chirho| {
                cause_chirho.downcast_ref::<cairn_chirho::capability_key_grant_chirho::KeyRouteRefusalChirho>()
            }) {
                Some(_) => super::public_error_chirho::public_error_response_chirho(
                    "app-request-context-chirho",
                    super::public_error_chirho::classify_request_context_chirho(&error_chirho),
                    headers_chirho,
                    None,
                ),
                None => authentication_required_response_chirho(),
            },
        ),
    }
}

/// Whether an app's signed-in-only policy admits a request with this context. Every entry that runs an app DAG asks it:
/// the app road, the app root, the domain fallback, SSR, `/invoke-chirho` and `/ws-chirho` (K1's alternate entries).
pub(super) enum RequestAccessDecisionChirho {
    AllowedChirho,
    SignInRequiredChirho,
    PolicyErrorChirho(anyhow::Error),
}

pub(super) fn request_access_decision_chirho(
    state_chirho: &AppStateChirho,
    app_name_chirho: &str,
    context_chirho: Option<&RequestContextChirho>,
) -> RequestAccessDecisionChirho {
    match state_chirho
        .runtime_chirho
        .app_request_access_policy_chirho(app_name_chirho)
    {
        Ok(app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho)
            if context_chirho.is_none() =>
        {
            RequestAccessDecisionChirho::SignInRequiredChirho
        }
        Ok(_) => RequestAccessDecisionChirho::AllowedChirho,
        Err(error_chirho) => RequestAccessDecisionChirho::PolicyErrorChirho(error_chirho),
    }
}

/// The access decision as an HTTP answer: `None` when admitted.
pub(super) fn request_access_refusal_for_context_chirho(
    state_chirho: &AppStateChirho,
    headers_chirho: &HeaderMap,
    app_name_chirho: &str,
    context_chirho: Option<&RequestContextChirho>,
) -> Option<Response> {
    match request_access_decision_chirho(state_chirho, app_name_chirho, context_chirho) {
        RequestAccessDecisionChirho::AllowedChirho => None,
        RequestAccessDecisionChirho::SignInRequiredChirho => {
            Some(authentication_required_response_chirho())
        }
        RequestAccessDecisionChirho::PolicyErrorChirho(error_chirho) => Some(
            request_access_policy_error_response_chirho(error_chirho, headers_chirho),
        ),
    }
}

fn authentication_required_response_chirho() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        APP_AUTHENTICATION_REQUIRED_BODY_CHIRHO,
    )
        .into_response()
}

/// The request-access policy's failure answer (PFE #26466): an unknown app is selection's 404, as before; a typed
/// resource exhaustion is the pre-run 503; any other failure is a fixed internal error, 500, with no capacity or retry
/// claim. Only the typed witness reaches the server log, never the error's chain.
fn request_access_policy_error_response_chirho(
    error_chirho: anyhow::Error,
    headers_chirho: &HeaderMap,
) -> Response {
    if error_chirho.to_string().starts_with("no deployed app") {
        return app_selection_error_response_chirho(error_chirho, headers_chirho);
    }
    super::public_error_chirho::public_error_response_chirho(
        "app-request-access-chirho",
        super::public_error_chirho::classify_pre_run_chirho(
            &error_chirho,
            StatusCode::INTERNAL_SERVER_ERROR,
            "served-request-internal-error-chirho",
        ),
        headers_chirho,
        None,
    )
}

pub(super) async fn read_served_app_request_body_chirho(
    request_chirho: Request<Body>,
) -> Result<Vec<u8>, Response> {
    to_bytes(
        request_chirho.into_body(),
        MAX_SERVED_APP_REQUEST_BODY_BYTES_CHIRHO,
    )
    .await
    .map(|bytes_chirho| bytes_chirho.to_vec())
    .map_err(|_error_chirho| StatusCode::PAYLOAD_TOO_LARGE.into_response())
}

const APP_ROUTE_HTML_CSP_BASE_CHIRHO: &str = "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'";
pub(super) const APP_ROUTE_HTML_CSP_CHIRHO: &str = "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'; style-src 'self' 'unsafe-inline'; img-src 'none'; font-src 'none'";

#[derive(Default)]
struct AppRouteAssetCspNeedsChirho {
    has_css_chirho: bool,
    has_image_chirho: bool,
    has_font_chirho: bool,
}

fn app_route_asset_csp_needs_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
) -> AppRouteAssetCspNeedsChirho {
    let mut needs_chirho = AppRouteAssetCspNeedsChirho::default();
    // The CACHED verified view: verified once per change to the asset log, not per response.
    // Re-verifying here re-hashed every asset blob ever registered on every HTML response
    // (bounded-growth census app A2: 1.41 MB per anonymous view on cax11, growing with each
    // release). A log that does not verify still yields no asset allowances.
    let Ok(records_chirho) = app_chirho::verified_app_static_asset_records_chirho(root_chirho)
    else {
        return needs_chirho;
    };
    for record_chirho in records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
    {
        match record_chirho.content_type_chirho.as_str() {
            app_chirho::APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO => {
                needs_chirho.has_css_chirho = true;
            }
            app_chirho::APP_STATIC_ASSET_PNG_CONTENT_TYPE_CHIRHO
            | app_chirho::APP_STATIC_ASSET_JPEG_CONTENT_TYPE_CHIRHO => {
                needs_chirho.has_image_chirho = true;
            }
            app_chirho::APP_STATIC_ASSET_WOFF_CONTENT_TYPE_CHIRHO
            | app_chirho::APP_STATIC_ASSET_WOFF2_CONTENT_TYPE_CHIRHO => {
                needs_chirho.has_font_chirho = true;
            }
            _ => {}
        }
    }
    needs_chirho
}

pub(super) fn app_html_payload_has_inline_style_chirho(payload_chirho: &[u8]) -> bool {
    let html_chirho = String::from_utf8_lossy(payload_chirho).to_ascii_lowercase();
    html_chirho.contains("<style") || html_chirho.contains("style=")
}

/// Part of `spec-chirho/workflows-chirho/template-style-authoring-compiler-chirho.md`.
/// HTML route CSP is derived from verified static-asset records, not from ad hoc URLs.
fn app_route_html_csp_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    payload_chirho: &[u8],
) -> String {
    let needs_chirho = app_route_asset_csp_needs_chirho(root_chirho, app_chirho);
    let mut csp_chirho = String::from(APP_ROUTE_HTML_CSP_BASE_CHIRHO);
    if needs_chirho.has_css_chirho && !app_html_payload_has_inline_style_chirho(payload_chirho) {
        csp_chirho.push_str("; style-src 'self'");
    } else {
        csp_chirho.push_str("; style-src 'self' 'unsafe-inline'");
    }
    csp_chirho.push_str(if needs_chirho.has_image_chirho {
        "; img-src 'self'"
    } else {
        "; img-src 'none'"
    });
    csp_chirho.push_str(if needs_chirho.has_font_chirho {
        "; font-src 'self'"
    } else {
        "; font-src 'none'"
    });
    csp_chirho
}

pub(super) fn apply_app_route_response_security_headers_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    payload_chirho: &[u8],
    headers_chirho: &mut HeaderMap,
    response_content_type_chirho: &str,
) {
    headers_chirho.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    if response_content_type_chirho.starts_with("text/html") {
        let csp_chirho = app_route_html_csp_chirho(root_chirho, app_chirho, payload_chirho);
        if let Ok(csp_chirho) = HeaderValue::from_str(&csp_chirho) {
            headers_chirho.insert(
                HeaderName::from_static("content-security-policy"),
                csp_chirho,
            );
        }
    }
}

pub(super) fn app_route_http_response_content_type_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    context_chirho: Option<&RequestContextChirho>,
) -> Result<Option<String>> {
    let owner_principal_chirho = match context_chirho {
        Some(context_chirho) => context_chirho.owner_principal_chirho.clone(),
        None => app_chirho::verified_app_owner_chirho(root_chirho, app_chirho)?
            .ok_or_else(|| anyhow::anyhow!("app '{app_chirho}' has no signed owner record"))?,
    };
    let Some(route_chirho) = route_chirho else {
        return app_chirho::app_response_content_type_chirho(
            root_chirho,
            app_chirho,
            &owner_principal_chirho,
        );
    };
    app_chirho::app_route_response_content_type_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        &owner_principal_chirho,
    )
}
