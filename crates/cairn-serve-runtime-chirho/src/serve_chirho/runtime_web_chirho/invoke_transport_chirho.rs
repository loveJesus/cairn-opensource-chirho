// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Legacy invoke JSON transport and websocket bridge.

use super::write_relay_chirho::unconverted_elected_entrypoint_response_chirho;
use super::{
    admit_served_dag_request_chirho, await_owned_served_work_chirho,
    ensure_customer_write_tenant_root_chirho,
    public_error_chirho::{self, PublicFailureChirho},
    served_request_rejected_response_chirho, try_run_served_with_context_and_caller_key_chirho,
    AppStateChirho, ServedDagAdmissionChirho,
};
use anyhow::{anyhow, Result};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cairn_chirho::model_chirho::RequestContextChirho;
use cairn_write_relay_chirho::{CallerIdempotencyKeyChirho, CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO};
use serde::{Deserialize, Serialize};

/// The client->server wire envelope for POST and WebSocket invoke.
///
/// POST carries its logical-operation key in `cairn-idempotency-key-chirho`. A WebSocket can carry
/// multiple operations, so its handshake headers cannot safely supply one shared key; elected
/// WebSocket forwarding remains `LeaderOnlyUntilConvertedChirho` until a per-message contract is
/// reviewed.
#[derive(Deserialize)]
pub(super) struct WireRequestChirho {
    pub(super) target_chirho: String,
    #[serde(default)]
    pub(super) payload_chirho: String,
    #[serde(default)]
    pub(super) base_version_chirho: Option<u64>,
}

/// The server->client delta: the new authoritative version + the DAG output.
#[derive(Serialize)]
struct WireResponseChirho {
    ok_chirho: bool,
    version_chirho: u64,
    payload_chirho: String,
}

fn store_current_view_chirho(state_chirho: &AppStateChirho) -> Result<u64> {
    state_chirho.runtime_chirho.current_view_chirho()
}

/// The outcome of the serialized invoke critical section.
enum InvokeOutcomeChirho {
    OkChirho {
        version_chirho: u64,
        payload_chirho: Vec<u8>,
    },
    ConflictChirho {
        version_chirho: u64,
    },
    /// A refusal, classified at the stage that refused it: no error text and no requested name travel.
    RefusedChirho {
        site_chirho: &'static str,
        failure_chirho: PublicFailureChirho,
    },
}

/// The invoke transport speaks JSON (R13 Part 8): every refusal it answers is JSON.
const INVOKE_CONTENT_TYPE_CHIRHO: &str = "application/json";

/// The serialized critical section: resolve the app, check `base_version`, run the DAG, read the
/// new version. The Tokio mailbox remains held while a provider-composed run awaits its owned
/// blocking task, preserving the race-free base-version check and linear version chain. The
/// provider's standard mutex is acquired and released only inside that blocking task.
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/served-request-admission-workflow-chirho.md`.
async fn invoke_critical_chirho(
    state_chirho: &AppStateChirho,
    admission_chirho: &ServedDagAdmissionChirho,
    req_chirho: &WireRequestChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    caller_idempotency_key_chirho: Option<&CallerIdempotencyKeyChirho>,
) -> InvokeOutcomeChirho {
    let refs_val_chirho = match state_chirho.runtime_chirho.load_refs_chirho() {
        Ok(r_chirho) => r_chirho,
        Err(e_chirho) => {
            return InvokeOutcomeChirho::RefusedChirho {
                site_chirho: "invoke-refs-load-chirho",
                failure_chirho: public_error_chirho::classify_pre_run_chirho(
                    &e_chirho,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "served-request-internal-error-chirho",
                ),
            }
        }
    };
    let before_chirho = match store_current_view_chirho(state_chirho) {
        Ok(v_chirho) => v_chirho,
        Err(e_chirho) => {
            return InvokeOutcomeChirho::RefusedChirho {
                site_chirho: "invoke-current-view-chirho",
                failure_chirho: public_error_chirho::classify_pre_run_chirho(
                    &e_chirho,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "served-request-internal-error-chirho",
                ),
            }
        }
    };
    if let Some(base_chirho) = req_chirho.base_version_chirho {
        if base_chirho != before_chirho {
            return InvokeOutcomeChirho::ConflictChirho {
                version_chirho: before_chirho,
            };
        }
    }
    let selection_chirho = match state_chirho
        .runtime_chirho
        .select_app_dag_with_resource_gate_chirho(
            &refs_val_chirho,
            &req_chirho.target_chirho,
            request_context_chirho,
        ) {
        Ok(selection_chirho) => selection_chirho,
        Err(e_chirho) => {
            return InvokeOutcomeChirho::RefusedChirho {
                site_chirho: "invoke-selection-chirho",
                failure_chirho: public_error_chirho::classify_selection_chirho(&e_chirho),
            }
        }
    };
    if let Err(e_chirho) = ensure_customer_write_tenant_root_chirho(
        state_chirho,
        &selection_chirho.dag_chirho,
        "/invoke-chirho",
    ) {
        return InvokeOutcomeChirho::RefusedChirho {
            site_chirho: "invoke-write-tenant-chirho",
            failure_chirho: public_error_chirho::classify_pre_run_chirho(
                &e_chirho,
                StatusCode::FORBIDDEN,
                "app-write-not-available-chirho",
            ),
        };
    }
    let selected_input_chirho = if selection_chirho.discard_request_body_chirho
        || !selection_chirho.accepts_request_body_chirho()
    {
        Vec::new()
    } else {
        req_chirho.payload_chirho.as_bytes().to_vec()
    };
    let dag_input_chirho = match state_chirho.runtime_chirho.app_dag_input_chirho(
        &req_chirho.target_chirho,
        selection_chirho.route_chirho.as_deref(),
        request_context_chirho,
        selected_input_chirho,
    ) {
        Ok(input_chirho) => input_chirho,
        Err(e_chirho) => {
            return InvokeOutcomeChirho::RefusedChirho {
                site_chirho: "invoke-input-chirho",
                failure_chirho: public_error_chirho::classify_app_input_chirho(&e_chirho),
            }
        }
    };
    // A signed-out request's private values join the app owner's container (C5 2a).
    let declared_attribution_chirho = match super::anonymous_app_attribution_chirho(
        state_chirho,
        &req_chirho.target_chirho,
        request_context_chirho,
    ) {
        Ok(declared_chirho) => declared_chirho,
        Err(e_chirho) => {
            return InvokeOutcomeChirho::RefusedChirho {
                site_chirho: "invoke-owner-chirho",
                failure_chirho: public_error_chirho::classify_pre_run_chirho(
                    &e_chirho,
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "app-owner-unverified-chirho",
                ),
            }
        }
    };
    match try_run_served_with_context_and_caller_key_chirho(
        state_chirho,
        admission_chirho,
        &selection_chirho.dag_chirho.0,
        &dag_input_chirho,
        request_context_chirho,
        caller_idempotency_key_chirho,
        declared_attribution_chirho,
    )
    .await
    {
        Ok(payload_chirho) => {
            #[cfg(test)]
            state_chirho
                .runtime_chirho
                .wait_at_invoke_after_run_hold_chirho()
                .await;
            let after_chirho = store_current_view_chirho(state_chirho).unwrap_or(before_chirho);
            InvokeOutcomeChirho::OkChirho {
                version_chirho: after_chirho,
                payload_chirho,
            }
        }
        Err(e_chirho) => InvokeOutcomeChirho::RefusedChirho {
            site_chirho: "invoke-execution-chirho",
            failure_chirho: public_error_chirho::classify_execution_chirho(&e_chirho),
        },
    }
}

/// Run one invoke critical section, which owns its request's admission, under the per-store mailbox in a DETACHED task
/// that owns the mailbox guard too. The mailbox spans the WHOLE section, its run and its final version observation (the
/// provider std mutex does not), and a handler or WebSocket message task that is cancelled mid-section releases neither
/// the in-flight permit nor the mailbox before the section ends. The section is a future that has not started: it
/// begins only inside the owning task, after the mailbox is held.
///
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.
async fn run_owned_invoke_section_chirho(
    state_chirho: AppStateChirho,
    section_chirho: impl std::future::Future<Output = InvokeOutcomeChirho> + Send + 'static,
) -> InvokeOutcomeChirho {
    await_owned_served_work_chirho(tokio::spawn(async move {
        let mailbox_chirho = state_chirho.invoke_lock_chirho.lock().await;
        let outcome_chirho = section_chirho.await;
        drop(mailbox_chirho);
        outcome_chirho
    }))
    .await
}

/// POST /invoke-chirho — bounded backpressure (load-shed past the limit with 429), then serialize
/// the critical section through the per-store mailbox lock, then map to a delta. v1 realization of
/// the per-ref mailbox (one store-ref; per-ref mpsc tasks are a later refinement).
pub(super) async fn invoke_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    Json(req_chirho): Json<WireRequestChirho>,
) -> Response {
    let context_chirho = match state_chirho
        .runtime_chirho
        .request_context_for_app_chirho(&headers_chirho, &req_chirho.target_chirho)
    {
        Ok(context_chirho) => context_chirho,
        Err(e_chirho) => {
            return public_error_chirho::public_error_response_chirho(
                "invoke-request-context-chirho",
                public_error_chirho::classify_request_context_chirho(&e_chirho),
                &headers_chirho,
                Some(INVOKE_CONTENT_TYPE_CHIRHO),
            )
        }
    };
    // The app's signed-in-only policy, as on the app road (K1: alternate entries enforce it too).
    if let Some(response_chirho) = super::request_access_refusal_for_context_chirho(
        &state_chirho,
        &headers_chirho,
        &req_chirho.target_chirho,
        context_chirho.as_ref(),
    ) {
        return response_chirho;
    }
    let admission_chirho = match admit_served_dag_request_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        context_chirho.as_ref(),
        req_chirho.payload_chirho.len(),
    ) {
        Ok(admission_chirho) => admission_chirho,
        // The invoke transport speaks JSON and has no page to fall back to (R13 Part 8).
        Err(_error_chirho) => {
            return served_request_rejected_response_chirho(
                &state_chirho,
                &headers_chirho,
                Some(INVOKE_CONTENT_TYPE_CHIRHO),
            )
        }
    };
    if let Some(response_chirho) = unconverted_elected_entrypoint_response_chirho(&state_chirho) {
        return response_chirho;
    }
    let caller_idempotency_key_chirho =
        match caller_idempotency_key_from_post_headers_chirho(&headers_chirho) {
            Ok(caller_idempotency_key_chirho) => caller_idempotency_key_chirho,
            Err(error_chirho) => {
                return (StatusCode::BAD_REQUEST, format!("error: {error_chirho}\n"))
                    .into_response()
            }
        };
    let section_state_chirho = state_chirho.clone();
    let outcome_chirho = run_owned_invoke_section_chirho(state_chirho.clone(), async move {
        let outcome_chirho = invoke_critical_chirho(
            &section_state_chirho,
            &admission_chirho,
            &req_chirho,
            context_chirho.as_ref(),
            caller_idempotency_key_chirho.as_ref(),
        )
        .await;
        drop(admission_chirho);
        outcome_chirho
    })
    .await;
    match outcome_chirho {
        InvokeOutcomeChirho::OkChirho {
            version_chirho,
            payload_chirho,
        } => Json(WireResponseChirho {
            ok_chirho: true,
            version_chirho,
            payload_chirho: String::from_utf8_lossy(&payload_chirho).to_string(),
        })
        .into_response(),
        InvokeOutcomeChirho::ConflictChirho { version_chirho } => (
            StatusCode::CONFLICT,
            Json(WireResponseChirho {
                ok_chirho: false,
                version_chirho,
                payload_chirho: "base_version conflict".to_string(),
            }),
        )
            .into_response(),
        InvokeOutcomeChirho::RefusedChirho {
            site_chirho,
            failure_chirho,
        } => public_error_chirho::public_error_response_chirho(
            site_chirho,
            failure_chirho,
            &headers_chirho,
            Some(INVOKE_CONTENT_TYPE_CHIRHO),
        ),
    }
}

/// Run a JSON wire request through the serialized critical section and serialize the delta. Shared
/// by the WS transport (the POST handler maps the same outcomes to HTTP status codes instead).
pub(super) async fn process_invoke_json_with_headers_chirho(
    state_chirho: &AppStateChirho,
    text_chirho: &str,
    headers_chirho: Option<&HeaderMap>,
    peer_chirho: Option<std::net::SocketAddr>,
) -> String {
    let resp_chirho = match serde_json::from_str::<WireRequestChirho>(text_chirho) {
        // The parser's text can quote the frame back, so the answer names the refusal alone.
        Err(_e_chirho) => WireResponseChirho {
            ok_chirho: false,
            version_chirho: 0,
            payload_chirho: "bad request: invalid-wire-request-chirho".to_string(),
        },
        Ok(req_chirho) => {
            let context_chirho = match headers_chirho {
                Some(headers_chirho) => match state_chirho
                    .runtime_chirho
                    .request_context_for_app_chirho(headers_chirho, &req_chirho.target_chirho)
                {
                    Ok(context_chirho) => context_chirho,
                    Err(e_chirho) => {
                        let failure_chirho =
                            public_error_chirho::classify_request_context_chirho(&e_chirho);
                        eprintln!(
                            "{}",
                            public_error_chirho::witness_line_chirho(
                                "invoke-ws-request-context-chirho",
                                failure_chirho
                            )
                        );
                        let prefix_chirho = if matches!(
                            failure_chirho,
                            PublicFailureChirho::FixedRefusalChirho {
                                status_chirho: StatusCode::TOO_MANY_REQUESTS,
                                ..
                            }
                        ) {
                            "rate-limited"
                        } else {
                            "unauthorized"
                        };
                        return serde_json::to_string(&WireResponseChirho {
                            ok_chirho: false,
                            version_chirho: 0,
                            payload_chirho: format!(
                                "{prefix_chirho}: {}",
                                public_error_chirho::public_summary_chirho(failure_chirho)
                            ),
                        })
                        .unwrap_or_else(|_| "{\"ok_chirho\":false}".to_string());
                    }
                },
                None => None,
            };
            // The app's signed-in-only policy, per message, as on the app road (K1: alternate entries enforce it too).
            // An unknown app falls through to the selection's own answer, as before.
            match super::request_access_decision_chirho(
                state_chirho,
                &req_chirho.target_chirho,
                context_chirho.as_ref(),
            ) {
                super::RequestAccessDecisionChirho::AllowedChirho => {}
                super::RequestAccessDecisionChirho::SignInRequiredChirho => {
                    return serde_json::to_string(&WireResponseChirho {
                        ok_chirho: false,
                        version_chirho: 0,
                        payload_chirho: "unauthorized: authentication required".to_string(),
                    })
                    .unwrap_or_else(|_| "{\"ok_chirho\":false}".to_string());
                }
                super::RequestAccessDecisionChirho::PolicyErrorChirho(error_chirho)
                    if error_chirho.to_string().starts_with("no deployed app") => {}
                super::RequestAccessDecisionChirho::PolicyErrorChirho(_) => {
                    return serde_json::to_string(&WireResponseChirho {
                        ok_chirho: false,
                        version_chirho: 0,
                        payload_chirho: "error: request access policy unavailable".to_string(),
                    })
                    .unwrap_or_else(|_| "{\"ok_chirho\":false}".to_string());
                }
            }
            let admission_headers_chirho = headers_chirho.cloned().unwrap_or_default();
            let admission_chirho = match admit_served_dag_request_chirho(
                state_chirho,
                peer_chirho,
                &admission_headers_chirho,
                context_chirho.as_ref(),
                req_chirho.payload_chirho.len(),
            ) {
                Ok(admission_chirho) => admission_chirho,
                Err(_error_chirho) => {
                    return serde_json::to_string(&WireResponseChirho {
                        ok_chirho: false,
                        version_chirho: 0,
                        payload_chirho: "served request unavailable".to_string(),
                    })
                    .unwrap_or_else(|_| "{\"ok_chirho\":false}".to_string())
                }
            };
            if unconverted_elected_entrypoint_response_chirho(state_chirho).is_some() {
                return serde_json::to_string(&WireResponseChirho {
                    ok_chirho: false,
                    version_chirho: 0,
                    payload_chirho: "error: RelayMutationFamilyUnconvertedChirho".to_string(),
                })
                .unwrap_or_else(|_| "{\"ok_chirho\":false}".to_string());
            }
            let section_state_chirho = state_chirho.clone();
            let outcome_chirho =
                run_owned_invoke_section_chirho(state_chirho.clone(), async move {
                    let outcome_chirho = invoke_critical_chirho(
                        &section_state_chirho,
                        &admission_chirho,
                        &req_chirho,
                        context_chirho.as_ref(),
                        None,
                    )
                    .await;
                    drop(admission_chirho);
                    outcome_chirho
                })
                .await;
            match outcome_chirho {
                InvokeOutcomeChirho::OkChirho {
                    version_chirho,
                    payload_chirho,
                } => WireResponseChirho {
                    ok_chirho: true,
                    version_chirho,
                    payload_chirho: String::from_utf8_lossy(&payload_chirho).to_string(),
                },
                InvokeOutcomeChirho::ConflictChirho { version_chirho } => WireResponseChirho {
                    ok_chirho: false,
                    version_chirho,
                    payload_chirho: "base_version conflict".to_string(),
                },
                InvokeOutcomeChirho::RefusedChirho {
                    site_chirho,
                    failure_chirho,
                } => {
                    eprintln!(
                        "{}",
                        public_error_chirho::witness_line_chirho(site_chirho, failure_chirho)
                    );
                    WireResponseChirho {
                        ok_chirho: false,
                        version_chirho: 0,
                        payload_chirho: public_error_chirho::public_summary_chirho(failure_chirho),
                    }
                }
            }
        }
    };
    serde_json::to_string(&resp_chirho).unwrap_or_else(|_| "{\"ok_chirho\":false}".to_string())
}

fn caller_idempotency_key_from_post_headers_chirho(
    headers_chirho: &HeaderMap,
) -> Result<Option<CallerIdempotencyKeyChirho>> {
    let Some(value_chirho) = headers_chirho.get(CALLER_IDEMPOTENCY_KEY_HEADER_CHIRHO) else {
        return Ok(None);
    };
    let raw_chirho = value_chirho.to_str().map_err(|_| {
        anyhow!("RelayCallerKeyInvalidChirho: caller idempotency header is not visible ASCII")
    })?;
    CallerIdempotencyKeyChirho::new_chirho(raw_chirho.to_string())
        .map(Some)
        .map_err(|error_chirho| anyhow!(error_chirho))
}

/// GET /ws-chirho — upgrade to a WebSocket. Each text message is a wire request; the delta is
/// pushed back over the persistent socket. The JS transport prefers this and downgrades to
/// form-POST (/invoke-chirho) when WebSockets are unavailable.
pub(super) async fn ws_upgrade_chirho(
    ws_chirho: WebSocketUpgrade,
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
) -> Response {
    ws_chirho.on_upgrade(move |socket_chirho| {
        handle_ws_chirho(
            socket_chirho,
            state_chirho,
            headers_chirho,
            connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        )
    })
}

async fn handle_ws_chirho(
    mut socket_chirho: WebSocket,
    state_chirho: AppStateChirho,
    headers_chirho: HeaderMap,
    peer_chirho: Option<std::net::SocketAddr>,
) {
    while let Some(Ok(msg_chirho)) = socket_chirho.recv().await {
        if let Message::Text(text_chirho) = msg_chirho {
            let resp_chirho = process_invoke_json_with_headers_chirho(
                &state_chirho,
                &text_chirho,
                Some(&headers_chirho),
                peer_chirho,
            )
            .await;
            if socket_chirho
                .send(Message::Text(resp_chirho))
                .await
                .is_err()
            {
                break;
            }
        }
    }
}
