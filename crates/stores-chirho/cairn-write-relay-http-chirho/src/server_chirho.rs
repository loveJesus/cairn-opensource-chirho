// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::SERVED_WRITE_RELAY_PATH_CHIRHO;
use anyhow::{bail, Result};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use cairn_write_relay_chirho::{
    decode_and_authenticate_served_write_relay_request_chirho,
    AuthenticatedServedWriteRelayRequestChirho, PreparedServedWriteRelayResponseV1Chirho,
    RelayDestinationExecutionPortChirho, RelayDestinationResponseChirho,
    RelayRefusalIdentityChirho, RelayRosterChirho, ServedWriteRelayResponseInputChirho,
    VerifiedServedWriteRelayRequestChirho, RELAY_REQUEST_WIRE_MAX_BYTES_CHIRHO,
};
use cairn_writer_elector_chirho::monotonic_clock_chirho::{
    lease_deadline_from_remaining_chirho, lease_deadline_is_live_chirho, MonotonicClockChirho,
};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub trait RelayResponseSignerChirho: Send + Sync {
    fn sign_digest_chirho(&self, digest_chirho: &[u8; 32]) -> Result<(String, String)>;
}

pub struct ExistingKeyRelayResponseSignerChirho {
    root_chirho: PathBuf,
    expected_node_id_chirho: String,
}

impl ExistingKeyRelayResponseSignerChirho {
    pub fn new_chirho(root_chirho: &Path, expected_node_id_chirho: String) -> Result<Self> {
        let current_chirho =
            cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)?;
        if current_chirho != expected_node_id_chirho {
            bail!("relay response signer root does not match the configured node identity");
        }
        Ok(Self {
            root_chirho: root_chirho.to_path_buf(),
            expected_node_id_chirho,
        })
    }
}

impl RelayResponseSignerChirho for ExistingKeyRelayResponseSignerChirho {
    fn sign_digest_chirho(&self, digest_chirho: &[u8; 32]) -> Result<(String, String)> {
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                &self.root_chirho,
                digest_chirho,
            )?;
        if possession_chirho.key_id_chirho() != self.expected_node_id_chirho {
            bail!("relay response signer identity changed");
        }
        Ok((
            possession_chirho.key_id_chirho().to_string(),
            possession_chirho.into_signature_hex_chirho(),
        ))
    }
}

#[derive(Clone)]
pub struct RelayServerStateChirho {
    group_digest_chirho: String,
    node_id_chirho: String,
    roster_chirho: Arc<RelayRosterChirho>,
    leadership_chirho: Arc<dyn crate::FixedGroupLeadershipViewChirho>,
    clock_chirho: Arc<dyn MonotonicClockChirho>,
    transit_budget_millis_chirho: NonZeroU64,
    signer_chirho: Arc<dyn RelayResponseSignerChirho>,
    execution_chirho: Arc<dyn RelayDestinationExecutionPortChirho>,
}

pub struct RelayServerConfigChirho {
    pub group_digest_chirho: String,
    pub node_id_chirho: String,
    pub roster_chirho: Arc<RelayRosterChirho>,
    pub leadership_chirho: Arc<dyn crate::FixedGroupLeadershipViewChirho>,
    pub clock_chirho: Arc<dyn MonotonicClockChirho>,
    pub transit_budget_millis_chirho: NonZeroU64,
    pub signer_chirho: Arc<dyn RelayResponseSignerChirho>,
    pub execution_chirho: Arc<dyn RelayDestinationExecutionPortChirho>,
}

impl RelayServerStateChirho {
    pub fn new_chirho(config_chirho: RelayServerConfigChirho) -> Result<Self> {
        if !crate::directory_chirho::valid_group_digest_chirho(&config_chirho.group_digest_chirho) {
            bail!("relay server group digest must be canonical lowercase BLAKE3 hex");
        }
        if !config_chirho
            .roster_chirho
            .contains_chirho(&config_chirho.node_id_chirho)
        {
            bail!("relay server node must belong to the exact active roster");
        }
        Ok(Self {
            group_digest_chirho: config_chirho.group_digest_chirho,
            node_id_chirho: config_chirho.node_id_chirho,
            roster_chirho: config_chirho.roster_chirho,
            leadership_chirho: config_chirho.leadership_chirho,
            clock_chirho: config_chirho.clock_chirho,
            transit_budget_millis_chirho: config_chirho.transit_budget_millis_chirho,
            signer_chirho: config_chirho.signer_chirho,
            execution_chirho: config_chirho.execution_chirho,
        })
    }
}

pub fn relay_router_chirho(state_chirho: RelayServerStateChirho) -> Router {
    Router::new()
        .route(SERVED_WRITE_RELAY_PATH_CHIRHO, post(relay_handler_chirho))
        .layer(DefaultBodyLimit::max(RELAY_REQUEST_WIRE_MAX_BYTES_CHIRHO))
        .with_state(state_chirho)
}

pub fn serve_relay_router_blocking_chirho(
    listener_chirho: std::net::TcpListener,
    router_chirho: Router,
) -> Result<()> {
    listener_chirho.set_nonblocking(true)?;
    let runtime_chirho = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime_chirho.block_on(async move {
        let listener_chirho = tokio::net::TcpListener::from_std(listener_chirho)?;
        axum::serve(listener_chirho, router_chirho).await?;
        Ok::<(), anyhow::Error>(())
    })
}

async fn relay_handler_chirho(
    State(state_chirho): State<RelayServerStateChirho>,
    body_chirho: Bytes,
) -> Response {
    let authenticated_chirho = match decode_and_authenticate_served_write_relay_request_chirho(
        &body_chirho,
        &state_chirho.roster_chirho,
    ) {
        Ok(authenticated_chirho) => authenticated_chirho,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let leadership_chirho = state_chirho.leadership_chirho.current_leadership_chirho();
    let verified_chirho = match authenticated_chirho.bind_destination_chirho(
        &state_chirho.group_digest_chirho,
        &state_chirho.node_id_chirho,
        &state_chirho.roster_chirho,
    ) {
        Ok(verified_chirho) => verified_chirho,
        Err(error_chirho)
            if error_chirho.identity_chirho()
                == RelayRefusalIdentityChirho::RelayConsistencyGroupMismatchChirho
                && authenticated_chirho.target_node_id_chirho() == state_chirho.node_id_chirho =>
        {
            return signed_authenticated_refusal_chirho(
                &state_chirho,
                &authenticated_chirho,
                error_chirho.identity_chirho(),
                leadership_chirho.term_chirho,
            )
            .unwrap_or_else(|| StatusCode::SERVICE_UNAVAILABLE.into_response())
        }
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let response_chirho = if leadership_chirho.term_chirho != verified_chirho.expected_term_chirho()
        || !leadership_chirho.is_leader_chirho
        || leadership_chirho
            .leader_id_chirho
            .as_ref()
            .map(|node_chirho| node_chirho.0.as_str())
            != Some(state_chirho.node_id_chirho.as_str())
    {
        RelayDestinationResponseChirho::relay_refusal_chirho(
            RelayRefusalIdentityChirho::RelayOwnerTermChangedChirho,
        )
    } else if !leadership_chirho.lease_valid_chirho
        || !lease_deadline_is_live_chirho(
            state_chirho.clock_chirho.as_ref(),
            lease_deadline_from_remaining_chirho(
                state_chirho.clock_chirho.as_ref(),
                Some(verified_chirho.relay_budget_remaining_millis_chirho()),
                state_chirho.transit_budget_millis_chirho,
            ),
        )
    {
        RelayDestinationResponseChirho::relay_refusal_chirho(
            RelayRefusalIdentityChirho::RelayLeaseExpiredChirho,
        )
    } else {
        state_chirho
            .execution_chirho
            .execute_verified_chirho(&verified_chirho)
            .await
    };
    signed_response_chirho(
        &state_chirho,
        &verified_chirho,
        leadership_chirho.term_chirho,
        response_chirho,
    )
    .unwrap_or_else(|| StatusCode::SERVICE_UNAVAILABLE.into_response())
}

fn signed_authenticated_refusal_chirho(
    state_chirho: &RelayServerStateChirho,
    request_chirho: &AuthenticatedServedWriteRelayRequestChirho,
    identity_chirho: RelayRefusalIdentityChirho,
    actual_term_chirho: u64,
) -> Option<Response> {
    signed_response_for_binding_chirho(
        state_chirho,
        request_chirho.request_digest_chirho(),
        &request_chirho
            .caller_idempotency_key_chirho()
            .digest_hex_chirho(),
        &state_chirho.group_digest_chirho,
        actual_term_chirho,
        RelayDestinationResponseChirho::relay_refusal_chirho(identity_chirho),
    )
}

fn signed_response_chirho(
    state_chirho: &RelayServerStateChirho,
    request_chirho: &VerifiedServedWriteRelayRequestChirho,
    actual_term_chirho: u64,
    response_chirho: RelayDestinationResponseChirho,
) -> Option<Response> {
    signed_response_for_binding_chirho(
        state_chirho,
        request_chirho.request_digest_chirho(),
        &request_chirho
            .caller_idempotency_key_chirho()
            .digest_hex_chirho(),
        request_chirho.consistency_group_digest_chirho(),
        actual_term_chirho,
        response_chirho,
    )
}

fn signed_response_for_binding_chirho(
    state_chirho: &RelayServerStateChirho,
    request_digest_chirho: &str,
    caller_key_digest_chirho: &str,
    consistency_group_digest_chirho: &str,
    actual_term_chirho: u64,
    response_chirho: RelayDestinationResponseChirho,
) -> Option<Response> {
    let (outcome_class_chirho, outcome_identity_chirho, status_chirho, headers_chirho, body_chirho) =
        response_chirho.into_parts_chirho();
    let prepared_chirho =
        PreparedServedWriteRelayResponseV1Chirho::new_chirho(ServedWriteRelayResponseInputChirho {
            request_digest_chirho: request_digest_chirho.to_string(),
            caller_idempotency_key_digest_chirho: caller_key_digest_chirho.to_string(),
            responder_node_id_chirho: state_chirho.node_id_chirho.clone(),
            consistency_group_digest_chirho: consistency_group_digest_chirho.to_string(),
            actual_term_chirho,
            outcome_class_chirho,
            outcome_identity_chirho,
            status_chirho,
            end_to_end_headers_chirho: headers_chirho,
            body_chirho,
        })
        .ok()?;
    let (key_id_chirho, signature_chirho) = state_chirho
        .signer_chirho
        .sign_digest_chirho(&prepared_chirho.signing_digest_chirho())
        .ok()?;
    if key_id_chirho != state_chirho.node_id_chirho {
        return None;
    }
    let wire_chirho = prepared_chirho
        .into_signed_chirho(signature_chirho)
        .ok()?
        .to_wire_bytes_chirho()
        .ok()?;
    Some(
        (
            [(header::CONTENT_TYPE, "application/octet-stream")],
            wire_chirho,
        )
            .into_response(),
    )
}
