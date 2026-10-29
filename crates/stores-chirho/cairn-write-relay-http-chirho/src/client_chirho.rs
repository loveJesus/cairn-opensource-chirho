// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::{FixedRelayDirectoryChirho, SERVED_WRITE_RELAY_PATH_CHIRHO};
use cairn_write_relay_chirho::{
    PreparedServedWriteRelayAttemptChirho, RelayTransportFailureChirho,
    ServedWriteRelayFailureChirho, ServedWriteRelayFutureChirho, ServedWriteRelayPortChirho,
    RELAY_RESPONSE_WIRE_MAX_BYTES_CHIRHO,
};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy)]
pub struct RelayHttpTimeoutsChirho {
    pub connect_chirho: Duration,
    pub read_chirho: Duration,
    pub write_chirho: Duration,
    pub overall_chirho: Duration,
}

impl Default for RelayHttpTimeoutsChirho {
    fn default() -> Self {
        Self {
            connect_chirho: Duration::from_millis(750),
            read_chirho: Duration::from_secs(5),
            write_chirho: Duration::from_secs(5),
            overall_chirho: Duration::from_secs(8),
        }
    }
}

pub struct HttpServedWriteRelayPortChirho {
    directory_chirho: Arc<FixedRelayDirectoryChirho>,
    roster_chirho: Arc<cairn_write_relay_chirho::RelayRosterChirho>,
    agent_chirho: ureq::Agent,
}

impl HttpServedWriteRelayPortChirho {
    pub fn new_chirho(
        directory_chirho: Arc<FixedRelayDirectoryChirho>,
        roster_chirho: Arc<cairn_write_relay_chirho::RelayRosterChirho>,
        timeouts_chirho: RelayHttpTimeoutsChirho,
    ) -> Self {
        let agent_chirho = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(0)
            .max_idle_connections(0)
            .timeout_connect(timeouts_chirho.connect_chirho)
            .timeout_read(timeouts_chirho.read_chirho)
            .timeout_write(timeouts_chirho.write_chirho)
            .timeout(timeouts_chirho.overall_chirho)
            .build();
        Self {
            directory_chirho,
            roster_chirho,
            agent_chirho,
        }
    }

    fn relay_blocking_chirho(
        directory_chirho: Arc<FixedRelayDirectoryChirho>,
        roster_chirho: Arc<cairn_write_relay_chirho::RelayRosterChirho>,
        agent_chirho: ureq::Agent,
        attempt_chirho: PreparedServedWriteRelayAttemptChirho,
    ) -> Result<Vec<u8>, ServedWriteRelayFailureChirho> {
        let owner_chirho = directory_chirho.resolve_chirho(&attempt_chirho, &agent_chirho)?;
        if !directory_chirho.resolution_is_live_chirho(&owner_chirho) {
            return Err(
                cairn_write_relay_chirho::RelayContractErrorChirho::lease_expired_chirho().into(),
            );
        }
        let url_chirho = format!(
            "{}{}",
            owner_chirho.base_url_chirho(),
            SERVED_WRITE_RELAY_PATH_CHIRHO
        );
        let response_chirho = match agent_chirho
            .post(&url_chirho)
            .set("content-type", "application/octet-stream")
            .send_bytes(attempt_chirho.signed_request_wire_chirho())
        {
            Ok(response_chirho) => response_chirho,
            Err(ureq::Error::Transport(error_chirho))
                if error_chirho.kind() == ureq::ErrorKind::ConnectionFailed =>
            {
                return Err(
                    RelayTransportFailureChirho::owner_unavailable_before_send_chirho().into(),
                )
            }
            Err(_) => {
                return Err(
                    RelayTransportFailureChirho::outcome_ambiguous_after_transmission_chirho()
                        .into(),
                )
            }
        };
        if response_chirho.status() != 200 {
            return Err(
                RelayTransportFailureChirho::response_unavailable_after_execution_chirho().into(),
            );
        }
        let mut wire_chirho = Vec::new();
        response_chirho
            .into_reader()
            .take(RELAY_RESPONSE_WIRE_MAX_BYTES_CHIRHO as u64 + 1)
            .read_to_end(&mut wire_chirho)
            .map_err(|_| {
                RelayTransportFailureChirho::response_unavailable_after_execution_chirho()
            })?;
        if wire_chirho.len() > RELAY_RESPONSE_WIRE_MAX_BYTES_CHIRHO {
            return Err(
                RelayTransportFailureChirho::response_unavailable_after_execution_chirho().into(),
            );
        }
        attempt_chirho.verify_response_chirho(&wire_chirho, &roster_chirho)?;
        Ok(wire_chirho)
    }
}

impl ServedWriteRelayPortChirho for HttpServedWriteRelayPortChirho {
    fn relay_one_hop_chirho<'a>(
        &'a self,
        attempt_chirho: &'a PreparedServedWriteRelayAttemptChirho,
    ) -> ServedWriteRelayFutureChirho<'a> {
        let directory_chirho = Arc::clone(&self.directory_chirho);
        let roster_chirho = Arc::clone(&self.roster_chirho);
        let agent_chirho = self.agent_chirho.clone();
        let attempt_chirho = attempt_chirho.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                Self::relay_blocking_chirho(
                    directory_chirho,
                    roster_chirho,
                    agent_chirho,
                    attempt_chirho,
                )
            })
            .await
            .unwrap_or_else(|_| {
                Err(
                    RelayTransportFailureChirho::outcome_ambiguous_after_transmission_chirho()
                        .into(),
                )
            })
        })
    }
}
