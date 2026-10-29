// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Public pure-WASM DAG run and unreviewed preview routes, each admitted and executed off the async workers.

use super::{
    admit_served_dag_request_chirho, outcome_of_owned_work_chirho, parse_content_hash_chirho,
    public_error_chirho, run_on_blocking_pool_chirho, served_request_rejected_response_chirho,
    try_run_chirho, write_relay_chirho::unconverted_elected_entrypoint_response_chirho,
    AppStateChirho,
};
use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path as AxPath, State},
    http::{header::CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_app_preview_chirho::{
    PREVIEW_UNREVIEWED_HEADER_CHIRHO, PREVIEW_UNREVIEWED_HEADER_VALUE_CHIRHO,
};
use cairn_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho};
use cairn_chirho::{native_worker_chirho, store_chirho};

/// The public run's policy refusals, typed so the answer names the refusal without the node's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PublicRunRefusalChirho {
    CapabilityBearingNodeChirho {
        node_name_chirho: String,
        capability_count_chirho: usize,
    },
    NativeProgramNodeChirho {
        node_name_chirho: String,
    },
}

impl std::fmt::Display for PublicRunRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityBearingNodeChirho {
                node_name_chirho,
                capability_count_chirho,
            } => write!(
                f,
                "public /run-chirho only accepts capability-free DAGs; node '{node_name_chirho}' declares {capability_count_chirho} capability item(s)"
            ),
            Self::NativeProgramNodeChirho { node_name_chirho } => write!(
                f,
                "public /run-chirho only accepts Tier-1 WASM DAGs; node '{node_name_chirho}' points at a native program"
            ),
        }
    }
}

impl std::error::Error for PublicRunRefusalChirho {}

impl PublicRunRefusalChirho {
    /// The fixed public identity of this refusal, shared with the preview's.
    pub(crate) fn identity_chirho(&self) -> &'static str {
        match self {
            Self::CapabilityBearingNodeChirho { .. } => {
                public_error_chirho::CAPABILITY_FREE_DAG_REQUIRED_IDENTITY_CHIRHO
            }
            Self::NativeProgramNodeChirho { .. } => {
                public_error_chirho::WASM_DAG_REQUIRED_IDENTITY_CHIRHO
            }
        }
    }
}

pub(super) async fn run_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath(dag_hex_chirho): AxPath<String>,
) -> Response {
    run_dag_http_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &dag_hex_chirho,
        Vec::new(),
    )
    .await
}

pub(super) async fn run_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath(dag_hex_chirho): AxPath<String>,
    body_chirho: Bytes,
) -> Response {
    run_dag_http_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &dag_hex_chirho,
        body_chirho.to_vec(),
    )
    .await
}

async fn run_dag_http_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    headers_chirho: &HeaderMap,
    dag_hex_chirho: &str,
    input_chirho: Vec<u8>,
) -> Response {
    let admission_chirho = match admit_served_dag_request_chirho(
        state_chirho,
        peer_chirho,
        headers_chirho,
        None,
        input_chirho.len(),
    ) {
        Ok(admission_chirho) => admission_chirho,
        // A public run answers the DAG's own bytes and declares no type, so only Accept asks for JSON (R13 Part 8).
        Err(_error_chirho) => {
            return served_request_rejected_response_chirho(state_chirho, headers_chirho, None)
        }
    };
    if let Some(response_chirho) = unconverted_elected_entrypoint_response_chirho(state_chirho) {
        return response_chirho;
    }
    let dag_hash_chirho = match parse_content_hash_chirho(dag_hex_chirho, "dag_chirho") {
        Ok(hash_chirho) => hash_chirho,
        Err(e_chirho) => {
            return (StatusCode::BAD_REQUEST, format!("error: {e_chirho}\n")).into_response()
        }
    };
    if let Err(e_chirho) = state_chirho
        .runtime_chirho
        .ensure_public_run_dag_is_pure_wasm_chirho(&dag_hash_chirho)
    {
        return public_error_chirho::public_error_response_chirho(
            "public-run-check-chirho",
            public_error_chirho::classify_public_run_check_chirho(&e_chirho),
            headers_chirho,
            None,
        );
    }
    // The run on the blocking pool, in a closure that owns the admission: a started blocking task cannot be aborted, so
    // the in-flight permit is released exactly when the run ends (served-overload (ii);
    // spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md).
    let run_state_chirho = state_chirho.clone();
    let run_outcome_chirho = outcome_of_owned_work_chirho(
        run_on_blocking_pool_chirho(move || {
            let outcome_chirho = try_run_chirho(
                &run_state_chirho,
                &admission_chirho,
                &dag_hash_chirho.0,
                &input_chirho,
            );
            drop(admission_chirho);
            outcome_chirho
        })
        .await,
    );
    match run_outcome_chirho {
        Ok(payload_chirho) => (StatusCode::OK, payload_chirho).into_response(),
        // The run's own refusal, with its trusted observation; a resource failure here is never 503.
        Err(e_chirho) => public_error_chirho::public_error_response_chirho(
            "public-run-execution-chirho",
            public_error_chirho::classify_execution_chirho(&e_chirho),
            headers_chirho,
            None,
        ),
    }
}

pub(super) fn ensure_public_run_dag_is_pure_wasm_chirho(
    root_chirho: &std::path::Path,
    dag_hash_chirho: &HashChirho,
) -> Result<()> {
    let dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, dag_hash_chirho)?;
    for node_hash_chirho in &dag_chirho.nodes_chirho {
        let node_chirho: NodeDefChirho =
            store_chirho::get_object_chirho(root_chirho, node_hash_chirho)?;
        if !node_chirho.capabilities_chirho.is_empty() {
            return Err(PublicRunRefusalChirho::CapabilityBearingNodeChirho {
                node_name_chirho: node_chirho.name_chirho.clone(),
                capability_count_chirho: node_chirho.capabilities_chirho.len(),
            }
            .into());
        }
        if native_worker_chirho::native_node_spec_from_impl_chirho(&node_chirho.impl_wasm_chirho)
            .is_some()
        {
            return Err(PublicRunRefusalChirho::NativeProgramNodeChirho {
                node_name_chirho: node_chirho.name_chirho.clone(),
            }
            .into());
        }
    }
    Ok(())
}

pub(super) async fn preview_get_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath(dag_hex_chirho): AxPath<String>,
) -> Response {
    preview_dag_http_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &dag_hex_chirho,
        Vec::new(),
    )
    .await
}

pub(super) async fn preview_post_chirho(
    State(state_chirho): State<AppStateChirho>,
    connect_info_chirho: Option<ConnectInfo<std::net::SocketAddr>>,
    headers_chirho: HeaderMap,
    AxPath(dag_hex_chirho): AxPath<String>,
    body_chirho: Bytes,
) -> Response {
    preview_dag_http_chirho(
        &state_chirho,
        connect_info_chirho.map(|connect_info_chirho| connect_info_chirho.0),
        &headers_chirho,
        &dag_hex_chirho,
        body_chirho.to_vec(),
    )
    .await
}

/// The unreviewed preview. It persists nothing (no run intent, cache entry or input object: its executor is the pure
/// `cairn_app_preview_chirho` one), but it executes WASM in this process, so it takes the same in-memory admission as a
/// served run and executes on the blocking pool with that admission owned by the closure (served-overload (ii), PFE
/// b8be185 (b)). Admission here is backpressure only, never a durable record.
async fn preview_dag_http_chirho(
    state_chirho: &AppStateChirho,
    peer_chirho: Option<std::net::SocketAddr>,
    request_headers_chirho: &HeaderMap,
    dag_hex_chirho: &str,
    input_chirho: Vec<u8>,
) -> Response {
    let admission_chirho = match admit_served_dag_request_chirho(
        state_chirho,
        peer_chirho,
        request_headers_chirho,
        None,
        input_chirho.len(),
    ) {
        Ok(admission_chirho) => admission_chirho,
        Err(_error_chirho) => {
            return served_request_rejected_response_chirho(
                state_chirho,
                request_headers_chirho,
                None,
            )
        }
    };
    let dag_hash_chirho = match parse_content_hash_chirho(dag_hex_chirho, "dag_chirho") {
        Ok(hash_chirho) => hash_chirho,
        Err(e_chirho) => {
            return (
                StatusCode::BAD_REQUEST,
                preview_headers_chirho(),
                format!("error: {e_chirho}\n"),
            )
                .into_response();
        }
    };

    let preview_state_chirho = state_chirho.clone();
    let preview_outcome_chirho = outcome_of_owned_work_chirho(
        run_on_blocking_pool_chirho(move || {
            let outcome_chirho = preview_state_chirho
                .runtime_chirho
                .preview_dag_payload_chirho(&dag_hash_chirho, &input_chirho);
            drop(admission_chirho);
            outcome_chirho
        })
        .await,
    );
    match preview_outcome_chirho {
        Ok(payload_chirho) => {
            let mut headers_chirho = preview_headers_chirho();
            headers_chirho.insert(
                HeaderName::from_static("x-content-type-options"),
                HeaderValue::from_static("nosniff"),
            );

            let payload_str_chirho = String::from_utf8_lossy(&payload_chirho).to_ascii_lowercase();
            let is_html_chirho = payload_str_chirho.trim_start().starts_with("<!doctype")
                || payload_str_chirho.trim_start().starts_with("<html");

            if is_html_chirho {
                headers_chirho.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                headers_chirho.insert(
                    HeaderName::from_static("content-security-policy"),
                    HeaderValue::from_static(super::app_http_chirho::APP_ROUTE_HTML_CSP_CHIRHO),
                );
            }

            (StatusCode::OK, headers_chirho, payload_chirho).into_response()
        }
        // The preview persists nothing and runs only zero-capability WASM, and a later node can fail after an
        // earlier one ran in memory, so its failures have no pre-run class: a typed policy refusal names itself, and
        // anything else is one fixed refusal. The unreviewed-preview header stays on every answer.
        Err(e_chirho) => {
            let mut response_chirho = public_error_chirho::public_error_response_chirho(
                "preview-chirho",
                public_error_chirho::classify_preview_chirho(&e_chirho),
                request_headers_chirho,
                None,
            );
            response_chirho
                .headers_mut()
                .extend(preview_headers_chirho());
            response_chirho
        }
    }
}

pub(super) fn preview_dag_payload_for_root_chirho(
    root_chirho: &std::path::Path,
    dag_hash_chirho: &HashChirho,
    input_chirho: &[u8],
) -> Result<Vec<u8>> {
    cairn_app_preview_chirho::preview_dag_payload_chirho(root_chirho, dag_hash_chirho, input_chirho)
}

fn preview_headers_chirho() -> HeaderMap {
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        HeaderName::from_static(PREVIEW_UNREVIEWED_HEADER_CHIRHO),
        HeaderValue::from_static(PREVIEW_UNREVIEWED_HEADER_VALUE_CHIRHO),
    );
    headers_chirho
}
