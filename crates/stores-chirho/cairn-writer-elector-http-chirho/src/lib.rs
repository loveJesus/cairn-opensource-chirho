// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! HTTP transport for P4 writer-election Raft messages (slice 3b). One axum endpoint per node accepts a
//! POSTed encoded Raft message, feeds it to that node's elector via the bytes-only `step_encoded_chirho`
//! API, and returns the node's encoded outbound messages as `(target_raft_id, bytes)` pairs; a ureq
//! client POSTs a message to a peer and reads that reply. The transport moves BYTES only — it depends on
//! neither raft nor prost. The consensus is proven in the elector crate; this carries its messages over
//! real sockets, mirroring the P3 replication transport. It is election-only and mints no fence.

pub mod cluster_file_config_chirho;
pub mod cluster_node_chirho;
pub mod driver_chirho;
pub mod membership_control_chirho;
pub mod tenant_migration_capacity_config_chirho;

#[cfg(test)]
mod leader_info_wire_tests_chirho;

#[cfg(test)]
mod cluster_file_config_no_mint_tests_chirho;

use anyhow::{anyhow, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
// Re-exported, not merely imported: `lease_tier_chirho` is a PUBLIC field of `LeaderInfoChirho`, so a
// caller that matches on it must be able to name its type without depending on the elector crate.
pub use cairn_writer_elector_chirho::elector_port_chirho::LeaseTierChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use driver_chirho::{RaftDriverChirho, RAFT_FIRE_PATH_CHIRHO};
use std::future::IntoFuture;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The route a peer POSTs an encoded Raft message to.
pub const RAFT_MESSAGE_PATH_CHIRHO: &str = "/raft-message-chirho";

/// Hard cap on a single Raft message / message-batch response. Election messages are small; this is a
/// generous safety backstop so neither the server (inbound body) nor the client (response) can be made
/// to buffer an attacker-sized payload (OOM). Snapshots — the only large Raft messages — are rejected
/// by the election-only elector anyway.
pub const MAX_RAFT_MESSAGE_BYTES_CHIRHO: usize = 512 * 1024;

/// Maximum time a stopped server gives already accepted requests to finish before their connections
/// are canceled. Election/control handlers are intentionally bounded and short; this deadline keeps a
/// client that withholds an HTTP request body from holding a rolling restart indefinitely.
pub const GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT_CHIRHO: Duration = Duration::from_secs(1);

const SHUTDOWN_STOP_POLL_INTERVAL_CHIRHO: Duration = Duration::from_millis(25);
const RUNTIME_SHUTDOWN_TIMEOUT_CHIRHO: Duration = Duration::from_millis(100);

/// Build the Raft-message router over one node's elector, capping the inbound body size.
pub fn raft_message_router_chirho(elector_chirho: Arc<RaftWriterElectorChirho>) -> Router {
    Router::new()
        .route(
            RAFT_MESSAGE_PATH_CHIRHO,
            post(post_raft_message_handler_chirho),
        )
        .layer(DefaultBodyLimit::max(MAX_RAFT_MESSAGE_BYTES_CHIRHO))
        .with_state(elector_chirho)
}

/// Build the fire-and-forget Raft router over one node's DRIVER: a POST to `RAFT_FIRE_PATH_CHIRHO` is
/// stepped and its replies are pumped onward by the driver, and the response is a bare ack (no routed
/// body) — the production peer-to-peer path. The inbound body size is capped like the request/response
/// endpoint.
pub fn raft_fire_router_chirho(driver_chirho: Arc<RaftDriverChirho>) -> Router {
    Router::new()
        .route(RAFT_FIRE_PATH_CHIRHO, post(post_raft_fire_handler_chirho))
        .route(LEADER_DISCOVERY_PATH_CHIRHO, get(get_leader_handler_chirho))
        .layer(DefaultBodyLimit::max(MAX_RAFT_MESSAGE_BYTES_CHIRHO))
        .with_state(driver_chirho)
}

async fn post_raft_fire_handler_chirho(
    State(driver_chirho): State<Arc<RaftDriverChirho>>,
    body_chirho: Bytes,
) -> StatusCode {
    match driver_chirho.step_and_pump_chirho(&body_chirho) {
        // Accepted: the message stepped and any replies were pumped fire-and-forget. No routed body.
        Ok(()) => StatusCode::OK,
        // A forged/tampered/malformed message is a bad request; it is never stepped and nothing advances.
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

/// The route a client GETs to discover the current elected writer (master) for this node's group.
pub const LEADER_DISCOVERY_PATH_CHIRHO: &str = "/leader-chirho";

/// The leader-discovery answer: who the current elected writer is for the queried node's group, whether
/// the answering node is itself that leader, the Raft term, and whether the leader holds a valid lease.
/// Bounded, non-identifying fields (node pubkeys + counters) — safe to serve.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LeaderInfoChirho {
    /// The elected leader's node id (ed25519 pubkey hex), or `None` if no leader is known right now.
    pub leader_node_id_chirho: Option<String>,
    /// Whether the node that answered is itself the current leader.
    pub is_local_leader_chirho: bool,
    pub term_chirho: u64,
    /// How much of the leader's lease REMAINS, in milliseconds, or `None` for "expired".
    ///
    /// A duration, never a boolean and never an instant. A boolean would be stale-by-construction —
    /// true when it left this node, with no way for the receiver to price the delay. An instant would
    /// be worse: monotonic clocks have per-process origins, so comparing a sender's instant against a
    /// receiver's clock type-checks and yields plausible garbage. The receiver must convert this on
    /// arrival with `lease_deadline_from_remaining_chirho`, which subtracts a transit budget and
    /// treats absent or exhausted as EXPIRED.
    pub lease_remaining_millis_chirho: Option<u64>,
    /// WHICH validity predicate the answering node runs. **Observability metadata — NOT validity.**
    ///
    /// **What it is for:** `lease_remaining_millis_chirho` is `None` both when a tier-1 lease has
    /// EXPIRED and when the answering node has no monotonic lease at all — tiers 2 and 3 can never
    /// populate it. The tier disambiguates those two readings of a `None`. That is its entire purpose.
    ///
    /// **What it CANNOT do, and must never be read as doing:** it does not report whether the
    /// predicate currently passes. It is derived from configuration alone, so an UNWARMED tier-2
    /// leader and a warmed one send identical bytes — `TickWarmupChirho` with `remaining = None` in
    /// both cases. **A receiver that treated that pair as valid would authorize an unwarmed leader.**
    /// Pinned by `unwarmed_and_warmed_tier_two_leaders_send_byte_identical_responses_chirho`, which
    /// drives this handler and destructures the complete response, so a new field cannot slip past it.
    ///
    /// **Only the duration is authority-relevant.** `lease_deadline_from_remaining_chirho` takes no
    /// tier; non-monotonic tiers remain non-authoritative on this wire.
    ///
    /// **Additive, `#[serde(default)]`, and the default is the fail-closed one.** Nodes on the
    /// previous format carry no tier at all; those decode to `UnknownChirho`, which a receiver must
    /// treat as NOT lease-valid. Defaulting to any real tier would invent a claim the answering node
    /// never made — and every other variant licenses more trust than silence deserves.
    #[serde(default)]
    pub lease_tier_chirho: LeaseTierChirho,
}

async fn get_leader_handler_chirho(
    State(driver_chirho): State<Arc<RaftDriverChirho>>,
) -> Json<LeaderInfoChirho> {
    let leadership_chirho = driver_chirho.elector_chirho().current_leadership_chirho();
    Json(LeaderInfoChirho {
        leader_node_id_chirho: leadership_chirho
            .leader_id_chirho
            .map(|node_chirho| node_chirho.0),
        is_local_leader_chirho: leadership_chirho.is_leader_chirho,
        term_chirho: leadership_chirho.term_chirho,
        lease_remaining_millis_chirho: driver_chirho
            .elector_chirho()
            .current_lease_remaining_millis_chirho(),
        lease_tier_chirho: driver_chirho.elector_chirho().lease_tier_chirho(),
    })
}

/// Client: ask the node at `base_url_chirho` who the current elected writer (master) is for its group.
pub fn discover_leader_chirho(
    agent_chirho: &ureq::Agent,
    base_url_chirho: &str,
) -> Result<LeaderInfoChirho> {
    let url_chirho = format!(
        "{}{}",
        base_url_chirho.trim_end_matches('/'),
        LEADER_DISCOVERY_PATH_CHIRHO
    );
    let response_chirho = agent_chirho
        .get(&url_chirho)
        .call()
        .map_err(|e_chirho| anyhow!("discover leader at {url_chirho}: {e_chirho}"))?;
    let mut buf_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take(MAX_RAFT_MESSAGE_BYTES_CHIRHO as u64 + 1)
        .read_to_end(&mut buf_chirho)
        .map_err(|e_chirho| anyhow!("read leader info from {url_chirho}: {e_chirho}"))?;
    serde_json::from_slice::<LeaderInfoChirho>(&buf_chirho)
        .map_err(|e_chirho| anyhow!("decode leader info from {url_chirho}: {e_chirho}"))
}

/// Serve a Raft-message router on an already-bound std listener, blocking the calling thread. A caller
/// binds the address it wants (including `127.0.0.1:0` for an ephemeral port) and runs this on its own
/// thread.
pub fn serve_router_blocking_chirho(
    listener_chirho: std::net::TcpListener,
    router_chirho: Router,
) -> Result<()> {
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

async fn wait_for_stop_chirho(stop_chirho: Arc<AtomicBool>) {
    while !stop_chirho.load(Ordering::Relaxed) {
        tokio::time::sleep(SHUTDOWN_STOP_POLL_INTERVAL_CHIRHO).await;
    }
}

/// Serve a router on `listener_chirho` until `stop_chirho` is set, then stop accepting and give
/// in-flight requests a fixed graceful drain. Any connections still open at the deadline are canceled
/// before this function returns, so a withheld request body cannot hold a rolling restart forever.
pub fn serve_router_blocking_with_shutdown_chirho(
    listener_chirho: std::net::TcpListener,
    router_chirho: Router,
    stop_chirho: Arc<AtomicBool>,
) -> Result<()> {
    listener_chirho.set_nonblocking(true)?;
    let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let serve_result_chirho = runtime_chirho.block_on(async move {
        let tokio_listener_chirho = tokio::net::TcpListener::from_std(listener_chirho)?;
        let (start_graceful_tx_chirho, start_graceful_rx_chirho) =
            tokio::sync::oneshot::channel::<()>();
        let serve_chirho = axum::serve(tokio_listener_chirho, router_chirho)
            .with_graceful_shutdown(async move {
                let _ = start_graceful_rx_chirho.await;
            })
            .into_future();
        tokio::pin!(serve_chirho);

        tokio::select! {
            result_chirho = &mut serve_chirho => {
                result_chirho?;
            }
            () = wait_for_stop_chirho(stop_chirho) => {
                let _ = start_graceful_tx_chirho.send(());
                if let Ok(result_chirho) = tokio::time::timeout(
                    GRACEFUL_SHUTDOWN_DRAIN_TIMEOUT_CHIRHO,
                    &mut serve_chirho,
                ).await {
                    result_chirho?;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    runtime_chirho.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT_CHIRHO);
    serve_result_chirho
}

/// POST one encoded Raft message to a peer's `base_url_chirho` and return the peer's encoded outbound
/// messages as `(target_raft_id, bytes)` pairs to route next.
pub fn post_raft_message_chirho(
    agent_chirho: &ureq::Agent,
    base_url_chirho: &str,
    message_bytes_chirho: &[u8],
) -> Result<Vec<(u64, Vec<u8>)>> {
    let url_chirho = format!(
        "{}{}",
        base_url_chirho.trim_end_matches('/'),
        RAFT_MESSAGE_PATH_CHIRHO
    );
    let response_chirho = agent_chirho
        .post(&url_chirho)
        .send_bytes(message_bytes_chirho)
        .map_err(|e_chirho| anyhow!("post raft message to {url_chirho}: {e_chirho}"))?;
    // Bound the response so a hostile/MITM peer cannot OOM the initiator: read one byte past the cap and
    // reject if exceeded, then parse the (target_raft_id, bytes) pairs.
    let mut buf_chirho = Vec::new();
    response_chirho
        .into_reader()
        .take(MAX_RAFT_MESSAGE_BYTES_CHIRHO as u64 + 1)
        .read_to_end(&mut buf_chirho)
        .map_err(|e_chirho| anyhow!("read raft message response from {url_chirho}: {e_chirho}"))?;
    if buf_chirho.len() > MAX_RAFT_MESSAGE_BYTES_CHIRHO {
        return Err(anyhow!(
            "raft message response from {url_chirho} exceeds the {MAX_RAFT_MESSAGE_BYTES_CHIRHO}-byte cap"
        ));
    }
    serde_json::from_slice::<Vec<(u64, Vec<u8>)>>(&buf_chirho)
        .map_err(|e_chirho| anyhow!("decode raft message response from {url_chirho}: {e_chirho}"))
}

async fn post_raft_message_handler_chirho(
    State(elector_chirho): State<Arc<RaftWriterElectorChirho>>,
    body_chirho: Bytes,
) -> Response {
    match elector_chirho.step_encoded_chirho(&body_chirho) {
        Ok(outbound_chirho) => Json(outbound_chirho).into_response(),
        // A malformed message is a bad request; it never crashes the node or advances anything.
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}
