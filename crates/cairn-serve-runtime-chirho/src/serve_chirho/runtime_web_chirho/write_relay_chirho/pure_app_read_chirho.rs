// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/pure-app-read-chirho.md`.

use super::super::served_request_rejected_response_chirho;
use super::{
    app_http_chirho, dispatch_before_app_selection_chirho, AppStateChirho,
    RelayedRequestMarkerChirho, RequestRefusalChirho, ServedWriteBeforeSelectionChirho,
    TenantIdChirho, CREDITS_APP_CHIRHO,
};
use axum::{
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE},
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    },
    response::{IntoResponse, Response},
};
use cairn_chirho::app_chirho;
use cairn_pure_executor_chirho::PureDagOutcomeChirho;
use cairn_write_relay_chirho::{RelayExecutionKnowledgeChirho, RelayRefusalIdentityChirho};
use cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho;
use rand::RngCore;

pub(in crate::serve_chirho) struct PureAppReadRequestChirho<'a> {
    pub peer_chirho: Option<std::net::SocketAddr>,
    pub headers_chirho: &'a HeaderMap,
    pub app_chirho: &'a str,
    pub route_chirho: &'a str,
    pub uri_chirho: &'a Uri,
    pub reentry_chirho: Option<&'a RelayedRequestMarkerChirho>,
    pub method_chirho: &'a Method,
    pub body_chirho: Vec<u8>,
}

pub(in crate::serve_chirho) fn is_transient_app_candidate_chirho(
    app_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: &Method,
) -> bool {
    matches!(*method_chirho, Method::GET | Method::POST)
        && route_chirho.is_some()
        && app_chirho != CREDITS_APP_CHIRHO
}

pub(in crate::serve_chirho) fn applies_chirho(
    state_chirho: &AppStateChirho,
    app_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: &Method,
) -> bool {
    routes_to_transient_executor_chirho(
        app_chirho,
        route_chirho,
        method_chirho,
        state_chirho.runtime_chirho.llm_served_card_surface_chirho(),
        &state_chirho.tenant_chirho,
    ) && !matches!(
        state_chirho.runtime_chirho.writer_authority_era_chirho(),
        Ok(WriterAuthorityEraChirho::LocalChirho)
    )
}

fn routes_to_transient_executor_chirho(
    app_chirho: &str,
    route_chirho: Option<&str>,
    method_chirho: &Method,
    served_card_surface_chirho: Option<(&str, &str)>,
    tenant_chirho: &TenantIdChirho,
) -> bool {
    is_transient_app_candidate_chirho(app_chirho, route_chirho, method_chirho)
        // Platform POSTs retain their existing context and unconverted-dispatch checks until C4.
        && (*method_chirho != Method::POST
            || matches!(tenant_chirho, TenantIdChirho::TenantChirho(_)))
        // The explicitly composed paid POST has its own live-authority and caller-key admission.
        // Only that exact surface stays there; composition never exempts the rest of its app.
        && !served_card_surface_chirho.is_some_and(|(served_app_chirho, paid_route_chirho)| {
            *method_chirho == Method::POST
                && app_chirho == served_app_chirho
                && route_chirho == Some(paid_route_chirho)
        })
}

fn unconverted_chirho(refusal_chirho: &RequestRefusalChirho<'_>) -> Response {
    refusal_chirho.answer_chirho(
        RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
        RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
    )
}

fn execution_refused_chirho(error_chirho: anyhow::Error) -> Response {
    eprintln!(
        "{}",
        app_http_chirho::app_execution_refusal_log_line_chirho(&error_chirho)
    );
    (
        StatusCode::BAD_REQUEST,
        app_http_chirho::APP_EXECUTION_REFUSAL_BODY_CHIRHO,
    )
        .into_response()
}

pub(in crate::serve_chirho) async fn run_chirho(
    state_chirho: &AppStateChirho,
    request_chirho: PureAppReadRequestChirho<'_>,
) -> Response {
    let mut response_chirho = run_inner_chirho(state_chirho, request_chirho).await;
    response_chirho
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response_chirho
}

async fn run_inner_chirho(
    state_chirho: &AppStateChirho,
    request_chirho: PureAppReadRequestChirho<'_>,
) -> Response {
    let PureAppReadRequestChirho {
        peer_chirho,
        headers_chirho,
        app_chirho,
        route_chirho,
        uri_chirho,
        reentry_chirho,
        method_chirho,
        body_chirho,
    } = request_chirho;
    let refusal_chirho = RequestRefusalChirho::new_chirho(
        state_chirho,
        headers_chirho,
        app_chirho,
        method_chirho,
        reentry_chirho.is_some(),
    );
    if (*method_chirho == Method::GET && !body_chirho.is_empty())
        || headers_chirho.contains_key(AUTHORIZATION)
        || super::direct_app_route_from_uri_chirho(uri_chirho)
            != Some((app_chirho.to_string(), route_chirho.to_string()))
    {
        return unconverted_chirho(&refusal_chirho);
    }
    let ingress_result_chirho = if let Some(reentry_chirho) = reentry_chirho {
        reentry_chirho.take_ingress_chirho()
    } else {
        state_chirho
            .served_request_abuse_gate_chirho
            .admit_ingress_chirho(
                state_chirho.inflight_chirho.clone(),
                peer_chirho,
                headers_chirho,
                body_chirho.len(),
            )
    };
    let ingress_chirho = match ingress_result_chirho {
        Ok(ingress_chirho) => ingress_chirho,
        Err(_) => {
            return served_request_rejected_response_chirho(state_chirho, headers_chirho, None)
        }
    };
    // Admit and forward before looking at follower refs or sessions. Never fall back on refusal.
    let dispatch_chirho = if reentry_chirho.is_some() {
        dispatch_before_app_selection_chirho(
            state_chirho,
            headers_chirho,
            app_chirho,
            Some(route_chirho),
            method_chirho,
            uri_chirho,
            &body_chirho,
            reentry_chirho,
            None,
        )
        .await
    } else {
        let mut dispatch_headers_chirho = headers_chirho.clone();
        // GET execution is transient, so this key is transport correlation, never a durable
        // idempotency claim. Do not generate or replace a key for any write or supplied key.
        if *method_chirho == Method::GET
            && !dispatch_headers_chirho.contains_key(super::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO)
        {
            let mut nonce_chirho = [0_u8; 32];
            if rand::rngs::OsRng.try_fill_bytes(&mut nonce_chirho).is_err() {
                return unconverted_chirho(&refusal_chirho);
            }
            let key_chirho = format!("pure-read-{}-chirho", blake3::hash(&nonce_chirho).to_hex());
            let Ok(value_chirho) = HeaderValue::from_str(&key_chirho) else {
                return unconverted_chirho(&refusal_chirho);
            };
            dispatch_headers_chirho
                .insert(super::CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO, value_chirho);
        }
        super::dispatch_origin_with_custody_chirho(
            state_chirho,
            super::RelayOriginRequestChirho {
                headers_chirho: &dispatch_headers_chirho,
                app_chirho,
                route_chirho: Some(route_chirho),
                method_chirho,
                uri_chirho,
                body_chirho: &body_chirho,
            },
            ingress_chirho.ingress_assertion_chirho(),
            ingress_chirho.retain_for_dispatch_chirho(),
        )
        .await
    };
    let body_chirho = match dispatch_chirho {
        ServedWriteBeforeSelectionChirho::RespondChirho(response_chirho) => return response_chirho,
        ServedWriteBeforeSelectionChirho::ContinueChirho(Some(operation_chirho)) => {
            operation_chirho
                .into_parts_chirho()
                .2
                .unwrap_or(body_chirho)
        }
        ServedWriteBeforeSelectionChirho::ContinueChirho(None) => {
            return unconverted_chirho(&refusal_chirho)
        }
    };
    let Some(authority_chirho) = state_chirho.local_read_authority_chirho.as_deref() else {
        return refusal_chirho.answer_chirho(
            RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        );
    };
    let witness_chirho = match authority_chirho.begin_local_read_chirho() {
        Ok(witness_chirho) => witness_chirho,
        Err(error_chirho) => {
            return refusal_chirho.answer_chirho(
                error_chirho.identity_chirho(),
                error_chirho.execution_knowledge_chirho(),
            )
        }
    };
    let prepared_chirho = match state_chirho
        .runtime_chirho
        .prepare_app_request_context_chirho(headers_chirho, app_chirho, Some(route_chirho))
    {
        Ok(prepared_chirho) => prepared_chirho,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                app_http_chirho::APP_AUTHENTICATION_REQUIRED_BODY_CHIRHO,
            )
                .into_response()
        }
    };
    let context_chirho = prepared_chirho.context_chirho();
    match state_chirho
        .runtime_chirho
        .app_request_access_policy_chirho(app_chirho)
    {
        Ok(app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho)
            if context_chirho.is_none() =>
        {
            return (
                StatusCode::UNAUTHORIZED,
                app_http_chirho::APP_AUTHENTICATION_REQUIRED_BODY_CHIRHO,
            )
                .into_response()
        }
        Ok(_) => {}
        Err(error_chirho) => return execution_refused_chirho(error_chirho),
    }
    if *method_chirho == Method::POST {
        match state_chirho
            .runtime_chirho
            .direct_app_route_accepts_request_body_chirho(app_chirho, route_chirho)
        {
            Ok(true) => {}
            Ok(false) => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
            Err(error_chirho) => return execution_refused_chirho(error_chirho),
        }
    }
    let declared_chirho = match state_chirho
        .runtime_chirho
        .app_route_http_response_content_type_chirho(app_chirho, Some(route_chirho), context_chirho)
    {
        Ok(declared_chirho) => declared_chirho,
        Err(error_chirho) => return execution_refused_chirho(error_chirho),
    };
    let content_type_chirho = match declared_chirho
        .as_deref()
        .map(HeaderValue::from_str)
        .transpose()
    {
        Ok(value_chirho) => value_chirho,
        Err(error_chirho) => return execution_refused_chirho(error_chirho.into()),
    };
    let admission_chirho = match state_chirho
        .served_request_abuse_gate_chirho
        .promote_ingress_chirho(
            ingress_chirho,
            context_chirho.map(|context_chirho| context_chirho.user_principal_chirho.as_str()),
        ) {
        Ok(admission_chirho) => admission_chirho,
        Err(_) => {
            return served_request_rejected_response_chirho(
                state_chirho,
                headers_chirho,
                declared_chirho.as_deref(),
            )
        }
    };
    let refs_chirho = match state_chirho.runtime_chirho.load_refs_chirho() {
        Ok(refs_chirho) => refs_chirho,
        Err(error_chirho) => return execution_refused_chirho(error_chirho),
    };
    let selection_chirho = match state_chirho.runtime_chirho.select_pure_app_route_chirho(
        &refs_chirho,
        app_chirho,
        route_chirho,
        context_chirho,
    ) {
        Ok(Some(selection_chirho)) => selection_chirho,
        Ok(None) => return unconverted_chirho(&refusal_chirho),
        Err(error_chirho) => return execution_refused_chirho(error_chirho),
    };
    let input_chirho = if *method_chirho == Method::POST {
        state_chirho.runtime_chirho.pure_app_body_input_chirho(
            app_chirho,
            route_chirho,
            context_chirho,
            body_chirho,
        )
    } else {
        state_chirho
            .runtime_chirho
            .pure_app_read_input_chirho(app_chirho, route_chirho, context_chirho, headers_chirho)
            .map(Some)
    };
    let input_chirho = match input_chirho {
        Ok(Some(input_chirho)) => input_chirho,
        Ok(None) => return unconverted_chirho(&refusal_chirho),
        Err(error_chirho) => return execution_refused_chirho(error_chirho),
    };
    let runtime_chirho = state_chirho.runtime_chirho.clone();
    let authority_chirho = state_chirho
        .local_read_authority_chirho
        .clone()
        .expect("read authority");
    let execution_witness_chirho = witness_chirho.clone();
    let dag_hash_chirho = selection_chirho.dag_chirho.clone();
    // Custody survives a cancelled HTTP future: a hash/compile/run holds its admission until done.
    let outcome_chirho = tokio::task::spawn_blocking(move || {
        let _admission_chirho = admission_chirho;
        authority_chirho
            .confirm_local_read_chirho(&execution_witness_chirho)
            .map_err(anyhow::Error::from)?;
        let outcome_chirho =
            runtime_chirho.execute_pure_app_read_chirho(&dag_hash_chirho, &input_chirho)?;
        Ok::<_, anyhow::Error>(outcome_chirho)
    })
    .await;
    let payload_chirho = match outcome_chirho {
        Ok(Ok(PureDagOutcomeChirho::PayloadChirho { bytes_chirho, .. })) => bytes_chirho,
        Ok(Ok(_)) => return unconverted_chirho(&refusal_chirho),
        Ok(Err(error_chirho)) => {
            if let Some(error_chirho) = error_chirho
                .downcast_ref::<cairn_write_relay_chirho::ServedWriteRelayFailureChirho>(
            ) {
                return refusal_chirho.answer_chirho(
                    error_chirho.identity_chirho(),
                    error_chirho.execution_knowledge_chirho(),
                );
            }
            return execution_refused_chirho(error_chirho);
        }
        Err(error_chirho) => return execution_refused_chirho(error_chirho.into()),
    };
    let mut response_headers_chirho = HeaderMap::new();
    if let (Some(value_chirho), Some(declared_chirho)) = (content_type_chirho, declared_chirho) {
        response_headers_chirho.insert(CONTENT_TYPE, value_chirho);
        state_chirho
            .runtime_chirho
            .apply_app_route_response_security_headers_chirho(
                app_chirho,
                &payload_chirho,
                &mut response_headers_chirho,
                &declared_chirho,
            );
    }
    if selection_chirho.unreviewed_dev_chirho {
        response_headers_chirho.insert(
            HeaderName::from_static(app_chirho::APP_UNREVIEWED_DEV_HEADER_CHIRHO),
            HeaderValue::from_static(app_chirho::APP_UNREVIEWED_DEV_HEADER_VALUE_CHIRHO),
        );
    }
    if let Err(error_chirho) = state_chirho
        .local_read_authority_chirho
        .as_deref()
        .expect("read authority")
        .confirm_local_read_chirho(&witness_chirho)
    {
        return refusal_chirho.answer_chirho(
            error_chirho.identity_chirho(),
            error_chirho.execution_knowledge_chirho(),
        );
    }
    (StatusCode::OK, response_headers_chirho, payload_chirho).into_response()
}

#[cfg(test)]
#[path = "pure_app_read_chirho/tests_chirho.rs"]
mod tests_chirho;
