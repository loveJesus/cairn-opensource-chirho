// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The replica-side client: `HttpReplicationSourceChirho` implements the read-only
//! `ReplicationSourceChirho` port by issuing blocking `ureq` GETs to a source server. It does ZERO
//! verification — it just fetches bytes; the existing `receive_objects_chirho` receiver hash-verifies
//! every object and the fold verify binds the logs. A `404` means the source does not have it (`None`);
//! any other non-2xx (including a `403` allowlist refusal) is an error, so a tampered/hostile response
//! never masquerades as an absent object.

use crate::{log_by_name_url_chirho, object_by_hash_url_chirho, objects_list_url_chirho};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{StoreErrorChirho, StoreResultChirho};
use cairn_replication_chirho::ReplicationSourceChirho;
use std::io::Read;
use std::time::Duration;

/// Hard cap on any single response body the client will buffer. A compromised or MITM'd source must
/// not be able to OOM-crash the replica with an unbounded/huge body; a body larger than this is a
/// transport error, never silently truncated. Content-addressed objects and Ring-A logs are far
/// smaller than this in practice, so it is a safety backstop, not a functional limit.
pub const MAX_REPLICATION_BODY_BYTES_CHIRHO: u64 = 256 * 1024 * 1024;

/// A read-only replication source that speaks to a `cairn-replication-http` server over the network.
pub struct HttpReplicationSourceChirho {
    base_url_chirho: String,
    bearer_token_chirho: Option<String>,
    agent_chirho: ureq::Agent,
}

impl HttpReplicationSourceChirho {
    /// `base_url_chirho` is the server origin, e.g. `http://127.0.0.1:8080`. `bearer_token_chirho` is
    /// sent as `Authorization: Bearer <token>` when the server requires it.
    pub fn new_chirho(
        base_url_chirho: impl Into<String>,
        bearer_token_chirho: Option<String>,
    ) -> Self {
        let agent_chirho = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            // A replication source answers directly; a redirect is never legitimate. Not following one
            // denies a hostile/MITM'd source an SSRF lever on the replica and keeps the bearer token
            // from being replayed to a redirect target.
            .redirects(0)
            .build();
        Self {
            base_url_chirho: base_url_chirho.into(),
            bearer_token_chirho,
            agent_chirho,
        }
    }

    /// Read a response body into memory, refusing anything past the cap so a hostile source cannot OOM
    /// the replica. Reads one byte beyond the cap to tell "exactly at cap" from "over".
    fn read_capped_body_chirho(
        url_chirho: &str,
        response_chirho: ureq::Response,
    ) -> StoreResultChirho<Vec<u8>> {
        // Only a 200 carries a body we trust. With redirects disabled, ureq surfaces a 3xx as an Ok
        // response, so a hostile source's redirect must not be read as an empty/absent object here.
        if response_chirho.status() != 200 {
            return Err(store_err_chirho(
                url_chirho,
                anyhow::anyhow!(
                    "replication source returned unexpected status {}",
                    response_chirho.status()
                ),
            ));
        }
        let mut buf_chirho = Vec::new();
        response_chirho
            .into_reader()
            .take(MAX_REPLICATION_BODY_BYTES_CHIRHO + 1)
            .read_to_end(&mut buf_chirho)
            .map_err(|e_chirho| store_err_chirho(url_chirho, e_chirho.into()))?;
        if buf_chirho.len() as u64 > MAX_REPLICATION_BODY_BYTES_CHIRHO {
            return Err(store_err_chirho(
                url_chirho,
                anyhow::anyhow!("response body exceeds the replication body-size cap"),
            ));
        }
        Ok(buf_chirho)
    }

    fn request_chirho(&self, url_chirho: &str) -> ureq::Request {
        let request_chirho = self.agent_chirho.get(url_chirho);
        match &self.bearer_token_chirho {
            Some(token_chirho) => {
                request_chirho.set("Authorization", &format!("Bearer {token_chirho}"))
            }
            None => request_chirho,
        }
    }

    /// GET bytes; a `404` is `None`; any other non-2xx (transport error, `403`, `500`) is an error.
    fn get_optional_bytes_chirho(&self, url_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        match self.request_chirho(url_chirho).call() {
            Ok(response_chirho) => Ok(Some(Self::read_capped_body_chirho(
                url_chirho,
                response_chirho,
            )?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e_chirho) => Err(store_err_chirho(url_chirho, e_chirho.into())),
        }
    }
}

impl ReplicationSourceChirho for HttpReplicationSourceChirho {
    fn list_object_addrs_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        let url_chirho = objects_list_url_chirho(&self.base_url_chirho);
        match self.request_chirho(&url_chirho).call() {
            Ok(response_chirho) => {
                // Cap the body (a hostile source must not OOM the replica), then parse the hash array.
                let body_chirho = Self::read_capped_body_chirho(&url_chirho, response_chirho)?;
                let hexes_chirho: Vec<String> = serde_json::from_slice(&body_chirho)
                    .map_err(|e_chirho| store_err_chirho(&url_chirho, e_chirho.into()))?;
                Ok(hexes_chirho.into_iter().map(HashChirho).collect())
            }
            Err(e_chirho) => Err(store_err_chirho(&url_chirho, e_chirho.into())),
        }
    }

    fn fetch_object_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        self.get_optional_bytes_chirho(&object_by_hash_url_chirho(
            &self.base_url_chirho,
            &addr_chirho.0,
        ))
    }

    fn fetch_named_log_chirho(&self, name_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        self.get_optional_bytes_chirho(&log_by_name_url_chirho(&self.base_url_chirho, name_chirho))
    }
}

fn store_err_chirho(url_chirho: &str, err_chirho: anyhow::Error) -> StoreErrorChirho {
    StoreErrorChirho::from(err_chirho.context(format!("replication http GET {url_chirho}")))
}
