// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The holder's two private-mesh endpoints: a leader posts one custody or erasure frame and gets back the signed receipt, or one fixed refusal name.
//!
//! Each body is bounded by its frame's own wire limit before it is read. The admission runs on the
//! blocking pool because it fsyncs. A refusal of the frame answers 409; the holder failing answers 503,
//! and the leader retries the same frame. Neither answer carries a key, subject or path.

use crate::holder_chirho::KeyCustodyHolderChirho;
use crate::refusal_chirho::{HolderRefusalChirho, HolderRefusalIdentityChirho};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use cairn_key_custody_chirho::{ERASURE_WIRE_MAX_BYTES_CHIRHO, KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO};
use std::sync::Arc;

pub const KEY_CUSTODY_CUSTODY_PATH_CHIRHO: &str = "/key-custody-chirho/v1/custody";
pub const KEY_CUSTODY_ERASURE_PATH_CHIRHO: &str = "/key-custody-chirho/v1/erasure";

/// The holder's router. Serve it on the private mesh only, beside the ledger mirror's.
pub fn key_custody_router_chirho(holder_chirho: Arc<KeyCustodyHolderChirho>) -> Router {
    Router::new()
        .route(
            KEY_CUSTODY_CUSTODY_PATH_CHIRHO,
            post(custody_handler_chirho)
                .layer(DefaultBodyLimit::max(KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO)),
        )
        .route(
            KEY_CUSTODY_ERASURE_PATH_CHIRHO,
            post(erasure_handler_chirho)
                .layer(DefaultBodyLimit::max(ERASURE_WIRE_MAX_BYTES_CHIRHO)),
        )
        .with_state(holder_chirho)
}

async fn custody_handler_chirho(
    State(holder_chirho): State<Arc<KeyCustodyHolderChirho>>,
    body_chirho: Bytes,
) -> Response {
    answer_chirho(
        tokio::task::spawn_blocking(move || holder_chirho.admit_custody_chirho(&body_chirho)).await,
    )
}

async fn erasure_handler_chirho(
    State(holder_chirho): State<Arc<KeyCustodyHolderChirho>>,
    body_chirho: Bytes,
) -> Response {
    answer_chirho(
        tokio::task::spawn_blocking(move || holder_chirho.admit_erasure_chirho(&body_chirho)).await,
    )
}

fn answer_chirho(
    outcome_chirho: Result<Result<Vec<u8>, HolderRefusalChirho>, tokio::task::JoinError>,
) -> Response {
    let refusal_chirho = match outcome_chirho {
        Ok(Ok(receipt_chirho)) => {
            return (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                receipt_chirho,
            )
                .into_response();
        }
        Ok(Err(refusal_chirho)) => refusal_chirho,
        Err(_) => HolderRefusalIdentityChirho::HolderAdmissionInterruptedChirho.into(),
    };
    let identity_chirho = refusal_chirho.wire_identity_chirho();
    eprintln!("KeyCustodyHolderRefusalChirho {identity_chirho}");
    let status_chirho = if refusal_chirho.is_internal_chirho() {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::CONFLICT
    };
    (status_chirho, identity_chirho).into_response()
}
