// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The source-side HTTP server: an axum `Router` generic over any `ReplicationSourceChirho`, serving
//! immutable objects by hash and ONLY allowlisted public logs — the allowlist is re-asserted here at
//! the wire boundary so a hostile replica can never name the source's signing key. It depends on the
//! port only (never localfs, never a head-mutation crate) and moves no head.

use crate::{
    bearer_header_matches_chirho, is_valid_object_hash_chirho, REPLICATION_LOG_BY_NAME_PATH_CHIRHO,
    REPLICATION_OBJECTS_LIST_PATH_CHIRHO, REPLICATION_OBJECT_BY_HASH_PATH_CHIRHO,
};
use axum::{
    extract::{Path as AxPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_replication_chirho::{is_replicable_log_name_chirho, ReplicationSourceChirho};
use std::sync::Arc;

/// Shared handler state: the read-only source behind the port, and an optional bearer token gating
/// WHO may pull at all (the allowlist gates WHAT may leave regardless of auth).
#[derive(Clone)]
pub struct ReplicationServerStateChirho {
    source_chirho: Arc<dyn ReplicationSourceChirho + Send + Sync>,
    bearer_token_chirho: Option<Arc<String>>,
}

/// Build the replication router over a source. `bearer_token_chirho` is `None` for an unauthenticated
/// (trusted-network / loopback) server, or `Some(token)` to require `Authorization: Bearer <token>`.
pub fn replication_router_chirho(
    source_chirho: Arc<dyn ReplicationSourceChirho + Send + Sync>,
    bearer_token_chirho: Option<String>,
) -> Router {
    let state_chirho = ReplicationServerStateChirho {
        source_chirho,
        bearer_token_chirho: bearer_token_chirho.map(Arc::new),
    };
    Router::new()
        .route(
            REPLICATION_OBJECTS_LIST_PATH_CHIRHO,
            get(list_objects_chirho),
        )
        .route(
            REPLICATION_OBJECT_BY_HASH_PATH_CHIRHO,
            get(get_object_chirho),
        )
        .route(REPLICATION_LOG_BY_NAME_PATH_CHIRHO, get(get_log_chirho))
        .with_state(state_chirho)
}

/// Serve a router on an already-bound std listener, blocking the calling thread. A composition root
/// (or a test) binds the address it wants — including `127.0.0.1:0` for an ephemeral port — and runs
/// this on its own thread. Kept here so the replication crate owns its transport without pulling the
/// forbidden serve-runtime.
pub fn serve_router_blocking_chirho(
    listener_chirho: std::net::TcpListener,
    router_chirho: Router,
) -> anyhow::Result<()> {
    listener_chirho.set_nonblocking(true)?;
    let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime_chirho.block_on(async move {
        let tokio_listener_chirho = tokio::net::TcpListener::from_std(listener_chirho)?;
        axum::serve(tokio_listener_chirho, router_chirho).await?;
        Ok::<(), anyhow::Error>(())
    })
}

/// Enforce the optional bearer token in constant time. `Ok(())` when no token is configured.
fn check_bearer_chirho(
    state_chirho: &ReplicationServerStateChirho,
    headers_chirho: &HeaderMap,
) -> Result<(), StatusCode> {
    let Some(expected_chirho) = &state_chirho.bearer_token_chirho else {
        return Ok(());
    };
    if bearer_header_matches_chirho(
        expected_chirho,
        headers_chirho
            .get(header::AUTHORIZATION)
            .and_then(|value_chirho| value_chirho.to_str().ok()),
    ) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn octet_stream_chirho(bytes_chirho: Vec<u8>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes_chirho,
    )
        .into_response()
}

async fn list_objects_chirho(
    State(state_chirho): State<ReplicationServerStateChirho>,
    headers_chirho: HeaderMap,
) -> Response {
    if let Err(code_chirho) = check_bearer_chirho(&state_chirho, &headers_chirho) {
        return code_chirho.into_response();
    }
    match state_chirho.source_chirho.list_object_addrs_chirho() {
        Ok(addrs_chirho) => {
            let hexes_chirho: Vec<String> = addrs_chirho
                .into_iter()
                .map(|h_chirho| h_chirho.0)
                .collect();
            Json(hexes_chirho).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_object_chirho(
    State(state_chirho): State<ReplicationServerStateChirho>,
    headers_chirho: HeaderMap,
    AxPath(hash_chirho): AxPath<String>,
) -> Response {
    if let Err(code_chirho) = check_bearer_chirho(&state_chirho, &headers_chirho) {
        return code_chirho.into_response();
    }
    // Validate the address shape before any store touch — a route param is never a path or a key.
    if !is_valid_object_hash_chirho(&hash_chirho) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state_chirho
        .source_chirho
        .fetch_object_chirho(&HashChirho(hash_chirho))
    {
        Ok(Some(bytes_chirho)) => octet_stream_chirho(bytes_chirho),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_log_chirho(
    State(state_chirho): State<ReplicationServerStateChirho>,
    headers_chirho: HeaderMap,
    AxPath(name_chirho): AxPath<String>,
) -> Response {
    if let Err(code_chirho) = check_bearer_chirho(&state_chirho, &headers_chirho) {
        return code_chirho.into_response();
    }
    // SERVER-SIDE allowlist: only the anchor log + Ring-A family logs may leave. The signing key,
    // refs, and every private file are refused here at the wire — never reaching the store call.
    if !is_replicable_log_name_chirho(&name_chirho) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state_chirho
        .source_chirho
        .fetch_named_log_chirho(&name_chirho)
    {
        Ok(Some(bytes_chirho)) => octet_stream_chirho(bytes_chirho),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
