// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Server-side app rendering route for deployed Cairn apps.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`
//! section 3.5.

use super::{
    admit_served_dag_request_chirho, await_owned_served_work_chirho,
    ensure_customer_write_tenant_root_chirho, public_error_chirho,
    served_request_rejected_response_chirho, try_run_served_with_context_chirho,
    write_relay_chirho::relay_named_refusal_response_chirho, AppStateChirho,
};
use axum::{
    extract::{ConnectInfo, Path as AxPath, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_chirho::onboarding_chirho;
use cairn_tenant_chirho::tenant_chirho::TenantIdChirho;
use cairn_write_relay_chirho::{
    RelayExecutionKnowledgeChirho, RelayRefusalIdentityChirho,
    ServedLocalReadAuthorityWitnessChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho;

enum SsrReadAuthorityChirho {
    LocalChirho,
    ElectedChirho(ServedLocalReadAuthorityWitnessChirho),
}

type SsrReadRefusalChirho = (RelayRefusalIdentityChirho, RelayExecutionKnowledgeChirho);

pub(super) async fn ssr_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath(name_chirho): AxPath<String>,
) -> Response {
    let context_chirho = match state_chirho
        .runtime_chirho
        .request_context_for_app_chirho(&headers_chirho, &name_chirho)
    {
        Ok(context_chirho) => context_chirho,
        // The same typed statuses as the app road: a rate limit is 429 here too, no longer 403.
        Err(e_chirho) => {
            return public_error_chirho::public_error_response_chirho(
                "ssr-request-context-chirho",
                public_error_chirho::classify_request_context_chirho(&e_chirho),
                &headers_chirho,
                None,
            )
        }
    };
    // The app's signed-in-only policy, as on the app road (K1: alternate entries enforce it too).
    if let Some(response_chirho) = super::request_access_refusal_for_context_chirho(
        &state_chirho,
        &headers_chirho,
        &name_chirho,
        context_chirho.as_ref(),
    ) {
        return response_chirho;
    }
    let admission_chirho = match admit_served_dag_request_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        context_chirho.as_ref(),
        0,
    ) {
        Ok(admission_chirho) => admission_chirho,
        // A rendered page declares no JSON, so only Accept asks for it (R13 Part 8).
        Err(_error_chirho) => {
            return served_request_rejected_response_chirho(&state_chirho, &headers_chirho, None)
        }
    };
    let read_authority_chirho = match begin_ssr_read_authority_chirho(&state_chirho) {
        Ok(read_authority_chirho) => read_authority_chirho,
        Err((identity_chirho, execution_knowledge_chirho)) => {
            return relay_named_refusal_response_chirho(identity_chirho, execution_knowledge_chirho)
        }
    };
    let refs_val_chirho = match state_chirho.runtime_chirho.load_refs_chirho() {
        Ok(refs_chirho) => refs_chirho,
        Err(error_chirho) => {
            return public_error_chirho::public_error_response_chirho(
                "ssr-refs-load-chirho",
                public_error_chirho::classify_pre_run_chirho(
                    &error_chirho,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "served-request-internal-error-chirho",
                ),
                &headers_chirho,
                None,
            )
        }
    };
    let selection_result_chirho = match &read_authority_chirho {
        SsrReadAuthorityChirho::LocalChirho => state_chirho
            .runtime_chirho
            .select_app_dag_with_resource_gate_chirho(
                &refs_val_chirho,
                &name_chirho,
                context_chirho.as_ref(),
            )
            .map(Some),
        SsrReadAuthorityChirho::ElectedChirho(_) => state_chirho
            .runtime_chirho
            .select_app_dag_without_resource_usage_chirho(&refs_val_chirho, &name_chirho),
    };
    let selection_chirho = match selection_result_chirho {
        Ok(Some(selection_chirho)) => selection_chirho,
        Ok(None) => {
            return relay_named_refusal_response_chirho(
                RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
            )
        }
        Err(e_chirho) => {
            return public_error_chirho::public_error_response_chirho(
                "ssr-selection-chirho",
                public_error_chirho::classify_selection_chirho(&e_chirho),
                &headers_chirho,
                None,
            )
        }
    };
    if let Err(e_chirho) = ensure_customer_write_tenant_root_chirho(
        &state_chirho,
        &selection_chirho.dag_chirho,
        "/ssr-chirho",
    ) {
        return public_error_chirho::public_error_response_chirho(
            "ssr-write-tenant-chirho",
            public_error_chirho::classify_pre_run_chirho(
                &e_chirho,
                StatusCode::FORBIDDEN,
                "app-write-not-available-chirho",
            ),
            &headers_chirho,
            None,
        );
    }
    if let Some(response_chirho) = elected_ssr_selected_dag_refusal_chirho(
        &state_chirho,
        &read_authority_chirho,
        &selection_chirho.dag_chirho,
    ) {
        return response_chirho;
    }
    let dag_input_chirho = match state_chirho.runtime_chirho.app_dag_input_chirho(
        &name_chirho,
        selection_chirho.route_chirho.as_deref(),
        context_chirho.as_ref(),
        Vec::new(),
    ) {
        Ok(input_chirho) => input_chirho,
        Err(e_chirho) => {
            return public_error_chirho::public_error_response_chirho(
                "ssr-input-chirho",
                public_error_chirho::classify_app_input_chirho(&e_chirho),
                &headers_chirho,
                None,
            )
        }
    };
    if let Some(response_chirho) =
        confirm_ssr_read_authority_chirho(&state_chirho, &read_authority_chirho)
    {
        return response_chirho;
    }
    // The run inside a detached task that owns the admission, so a cancelled handler cannot release the in-flight
    // permit while the run still executes (served-overload (ii);
    // spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md).
    #[cfg(test)]
    public_error_chirho::hold_points_chirho::reach_chirho(
        public_error_chirho::hold_points_chirho::HoldPointChirho::BeforeSsrRunChirho,
    );
    // A signed-out request's private values join the app owner's container (C5 2a).
    let declared_attribution_chirho = match super::anonymous_app_attribution_chirho(
        &state_chirho,
        &name_chirho,
        context_chirho.as_ref(),
    ) {
        Ok(declared_chirho) => declared_chirho,
        Err(e_chirho) => {
            return public_error_chirho::public_error_response_chirho(
                "ssr-owner-chirho",
                public_error_chirho::classify_pre_run_chirho(
                    &e_chirho,
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "app-owner-unverified-chirho",
                ),
                &headers_chirho,
                None,
            )
        }
    };
    let run_state_chirho = state_chirho.clone();
    let run_dag_hex_chirho = selection_chirho.dag_chirho.0.clone();
    let run_outcome_chirho = await_owned_served_work_chirho(tokio::spawn(async move {
        let outcome_chirho = try_run_served_with_context_chirho(
            &run_state_chirho,
            &admission_chirho,
            &run_dag_hex_chirho,
            &dag_input_chirho,
            context_chirho.as_ref(),
            declared_attribution_chirho,
        )
        .await;
        drop(admission_chirho);
        outcome_chirho
    }))
    .await;
    match run_outcome_chirho {
        Ok(payload_chirho) => {
            if let Some(response_chirho) =
                confirm_ssr_read_authority_chirho(&state_chirho, &read_authority_chirho)
            {
                return response_chirho;
            }
            (
                [(CONTENT_TYPE, "text/html; charset=utf-8")],
                state_chirho.runtime_chirho.html_lower_chirho(
                    &payload_chirho,
                    &name_chirho,
                    &selection_chirho.dag_chirho.0,
                ),
            )
                .into_response()
        }
        // The run's own refusal, with its trusted observation; a resource failure here is never 503.
        Err(e_chirho) => public_error_chirho::public_error_response_chirho(
            "ssr-execution-chirho",
            public_error_chirho::classify_execution_chirho(&e_chirho),
            &headers_chirho,
            None,
        ),
    }
}

fn begin_ssr_read_authority_chirho(
    state_chirho: &AppStateChirho,
) -> Result<SsrReadAuthorityChirho, SsrReadRefusalChirho> {
    let era_chirho = state_chirho
        .runtime_chirho
        .writer_authority_era_chirho()
        .map_err(|_error_chirho| {
            (
                RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho,
                RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
            )
        })?;
    if era_chirho == WriterAuthorityEraChirho::LocalChirho {
        return Ok(SsrReadAuthorityChirho::LocalChirho);
    }
    if !matches!(state_chirho.tenant_chirho, TenantIdChirho::TenantChirho(_)) {
        return Err((
            RelayRefusalIdentityChirho::RelayPlatformRootIdentityUnavailableChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        ));
    }
    let Some(authority_chirho) = state_chirho.local_read_authority_chirho.as_deref() else {
        return Err((
            RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        ));
    };
    authority_chirho
        .begin_local_read_chirho()
        .map(SsrReadAuthorityChirho::ElectedChirho)
        .map_err(|error_chirho| {
            (
                error_chirho.identity_chirho(),
                error_chirho.execution_knowledge_chirho(),
            )
        })
}

fn elected_ssr_selected_dag_refusal_chirho(
    state_chirho: &AppStateChirho,
    read_authority_chirho: &SsrReadAuthorityChirho,
    dag_chirho: &cairn_chirho::model_chirho::HashChirho,
) -> Option<Response> {
    if matches!(read_authority_chirho, SsrReadAuthorityChirho::LocalChirho) {
        return None;
    }
    if matches!(
        state_chirho
            .runtime_chirho
            .dag_is_elected_ssr_read_only_chirho(dag_chirho),
        Ok(true)
    ) {
        return None;
    }
    Some(relay_named_refusal_response_chirho(
        RelayRefusalIdentityChirho::RelayMutationFamilyUnconvertedChirho,
        RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
    ))
}

fn confirm_ssr_read_authority_chirho(
    state_chirho: &AppStateChirho,
    read_authority_chirho: &SsrReadAuthorityChirho,
) -> Option<Response> {
    let SsrReadAuthorityChirho::ElectedChirho(witness_chirho) = read_authority_chirho else {
        return None;
    };
    let Some(authority_chirho) = state_chirho.local_read_authority_chirho.as_deref() else {
        return Some(relay_named_refusal_response_chirho(
            RelayRefusalIdentityChirho::RelayLocalAuthorityUnavailableChirho,
            RelayExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        ));
    };
    authority_chirho
        .confirm_local_read_chirho(witness_chirho)
        .err()
        .map(|error_chirho| {
            relay_named_refusal_response_chirho(
                error_chirho.identity_chirho(),
                error_chirho.execution_knowledge_chirho(),
            )
        })
}

/// Server-side lowering of the browser render effect (DESIGN §17): wrap the DAG's body payload
/// in an HTML document. Client-side, the same view would be applied via `dom_patch`.
pub(super) fn html_lower_chirho(
    root_chirho: &std::path::Path,
    body_chirho: &[u8],
    app_chirho: &str,
    _app_ref_chirho: &str,
) -> String {
    format!(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>cairn-chirho</title>\n<body>\n{}\n{}\n</body>\n",
        String::from_utf8_lossy(body_chirho),
        onboarding_chirho::onboarding_kit_html_chirho(root_chirho, app_chirho)
    )
}

#[cfg(test)]
#[path = "ssr_web_chirho/tests_chirho.rs"]
mod tests_chirho;
