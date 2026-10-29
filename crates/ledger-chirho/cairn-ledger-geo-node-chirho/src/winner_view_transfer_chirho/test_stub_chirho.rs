// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Signed transport test endpoint for held-sender evidence.
//!
//! The endpoint keeps the production canonical parser, peer/roster/signature/term/lease verifier,
//! and response signer. It substitutes only actor dispatch with one configured result. Therefore
//! it proves what the real held sender emits; it does not prove that a real winner actor would
//! return `PreparingChirho`, retained `AcceptedChirho`, or `ActorStateChangedChirho` after a term
//! rollover.

use super::*;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use cairn_writer_elector_http_chirho::serve_router_blocking_with_shutdown_chirho;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrderingChirho};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Gd7WinnerViewTransferTestDispatchChirho {
    StatusChirho(Box<ResidentGd7WinnerHandoffStatusChirho>),
    ActorStateChangedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Gd7WinnerViewTransferTestObservationChirho {
    pub operation_chirho: Gd7WinnerViewTransferOperationChirho,
    pub expected_raft_term_chirho: u64,
    pub sender_node_chirho: String,
}

struct Gd7WinnerViewTransferTestStateChirho {
    service_chirho: Gd7WinnerViewTransferServiceChirho,
    dispatch_chirho: Gd7WinnerViewTransferTestDispatchChirho,
    observations_chirho: Arc<Mutex<Vec<Gd7WinnerViewTransferTestObservationChirho>>>,
}

pub(crate) struct Gd7WinnerViewTransferTestEndpointChirho {
    base_url_chirho: String,
    observations_chirho: Arc<Mutex<Vec<Gd7WinnerViewTransferTestObservationChirho>>>,
    stop_chirho: Arc<AtomicBool>,
    server_thread_chirho: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Gd7WinnerViewTransferTestEndpointChirho {
    pub(crate) fn spawn_chirho(
        node_sign_root_chirho: &Path,
        group_chirho: &ConsistencyGroupIdChirho,
        winner_node_chirho: NodeIdChirho,
        held_node_chirho: NodeIdChirho,
        elector_chirho: Arc<RaftWriterElectorChirho>,
        dispatch_chirho: Gd7WinnerViewTransferTestDispatchChirho,
    ) -> anyhow::Result<Self> {
        let service_chirho = Gd7WinnerViewTransferServiceChirho::open_chirho(
            node_sign_root_chirho,
            group_chirho,
            winner_node_chirho,
            held_node_chirho,
            elector_chirho,
        )?;
        let listener_chirho = TcpListener::bind("127.0.0.1:0")?;
        let address_chirho = listener_chirho.local_addr()?;
        let observations_chirho = Arc::new(Mutex::new(Vec::new()));
        let state_chirho = Arc::new(Gd7WinnerViewTransferTestStateChirho {
            service_chirho,
            dispatch_chirho,
            observations_chirho: Arc::clone(&observations_chirho),
        });
        let router_chirho = Router::new()
            .route(
                GD7_WINNER_VIEW_TRANSFER_PATH_CHIRHO,
                post(post_winner_view_transfer_test_chirho),
            )
            .layer(DefaultBodyLimit::max(
                MAX_GD7_WINNER_VIEW_TRANSFER_REQUEST_BYTES_CHIRHO,
            ))
            .with_state(state_chirho);
        let stop_chirho = Arc::new(AtomicBool::new(false));
        let server_stop_chirho = Arc::clone(&stop_chirho);
        let server_thread_chirho = std::thread::Builder::new()
            .name("gd7-winner-view-transfer-test-endpoint-chirho".to_owned())
            .spawn(move || {
                serve_router_blocking_with_shutdown_chirho(
                    listener_chirho,
                    router_chirho,
                    server_stop_chirho,
                )
            })?;
        Ok(Self {
            base_url_chirho: format!("http://{address_chirho}"),
            observations_chirho,
            stop_chirho,
            server_thread_chirho: Some(server_thread_chirho),
        })
    }

    pub(crate) fn base_url_chirho(&self) -> &str {
        &self.base_url_chirho
    }

    pub(crate) fn observations_chirho(&self) -> Vec<Gd7WinnerViewTransferTestObservationChirho> {
        self.observations_chirho
            .lock()
            .expect("signed test endpoint observation lock remains available")
            .clone()
    }

    pub(crate) fn close_chirho(&mut self) -> anyhow::Result<()> {
        self.stop_chirho.store(true, AtomicOrderingChirho::Release);
        let server_thread_chirho = self
            .server_thread_chirho
            .take()
            .ok_or_else(|| anyhow!("signed test endpoint is already closed"))?;
        server_thread_chirho
            .join()
            .map_err(|_panic_chirho| anyhow!("signed test endpoint panicked"))?
    }
}

impl Drop for Gd7WinnerViewTransferTestEndpointChirho {
    fn drop(&mut self) {
        self.stop_chirho.store(true, AtomicOrderingChirho::Release);
        if let Some(server_thread_chirho) = self.server_thread_chirho.take() {
            let _join_result_chirho = server_thread_chirho.join();
        }
    }
}

async fn post_winner_view_transfer_test_chirho(
    State(state_chirho): State<Arc<Gd7WinnerViewTransferTestStateChirho>>,
    body_chirho: Bytes,
) -> Response {
    let request_digest_chirho = digest_bytes_chirho(&body_chirho);
    let request_chirho = match parse_canonical_bounded_chirho::<Gd7WinnerViewTransferRequestChirho>(
        &body_chirho,
        MAX_GD7_WINNER_VIEW_TRANSFER_REQUEST_BYTES_CHIRHO,
    ) {
        Ok(request_chirho) => request_chirho,
        Err(_error_chirho) => {
            return signed_test_response_chirho(
                &state_chirho.service_chirho,
                &request_digest_chirho,
                state_chirho
                    .service_chirho
                    .state_chirho
                    .elector_chirho
                    .current_leadership_chirho()
                    .term_chirho,
                Gd7WinnerViewTransferResultChirho::RefusedChirho {
                    code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho,
                },
            )
        }
    };
    state_chirho
        .observations_chirho
        .lock()
        .expect("signed test endpoint observation lock remains available")
        .push(Gd7WinnerViewTransferTestObservationChirho {
            operation_chirho: request_chirho.operation_chirho.clone(),
            expected_raft_term_chirho: request_chirho.expected_raft_term_chirho,
            sender_node_chirho: request_chirho.sender_node_chirho.clone(),
        });
    let leadership_chirho = match state_chirho
        .service_chirho
        .verify_request_chirho(&request_chirho)
    {
        Ok(leadership_chirho) => leadership_chirho,
        Err(code_chirho) => {
            return signed_test_response_chirho(
                &state_chirho.service_chirho,
                &request_digest_chirho,
                state_chirho
                    .service_chirho
                    .state_chirho
                    .elector_chirho
                    .current_leadership_chirho()
                    .term_chirho,
                Gd7WinnerViewTransferResultChirho::RefusedChirho { code_chirho },
            )
        }
    };
    let result_chirho = match (
        &request_chirho.operation_chirho,
        &state_chirho.dispatch_chirho,
    ) {
        (
            Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho {
                attempt_digest_chirho,
            },
            Gd7WinnerViewTransferTestDispatchChirho::StatusChirho(status_chirho),
        ) if status_chirho.attempt_digest_chirho == *attempt_digest_chirho => {
            Gd7WinnerViewTransferResultChirho::HandoffStatusChirho {
                status_chirho: status_chirho.clone(),
            }
        }
        (
            Gd7WinnerViewTransferOperationChirho::HandoffStatusChirho { .. },
            Gd7WinnerViewTransferTestDispatchChirho::ActorStateChangedChirho,
        )
        | (Gd7WinnerViewTransferOperationChirho::BeginHandoffChirho { .. }, _) => {
            Gd7WinnerViewTransferResultChirho::RefusedChirho {
                code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::ActorStateChangedChirho,
            }
        }
        _ => Gd7WinnerViewTransferResultChirho::RefusedChirho {
            code_chirho: Gd7WinnerViewTransferRefusalCodeChirho::InvalidRequestChirho,
        },
    };
    signed_test_response_chirho(
        &state_chirho.service_chirho,
        &request_digest_chirho,
        leadership_chirho.term_chirho,
        result_chirho,
    )
}

fn signed_test_response_chirho(
    service_chirho: &Gd7WinnerViewTransferServiceChirho,
    request_digest_chirho: &str,
    raft_term_chirho: u64,
    result_chirho: Gd7WinnerViewTransferResultChirho,
) -> Response {
    match service_chirho.signed_response_chirho(
        request_digest_chirho,
        raft_term_chirho,
        result_chirho,
        &[],
    ) {
        Ok(frame_chirho) => (StatusCode::OK, frame_chirho).into_response(),
        Err(_error_chirho) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
