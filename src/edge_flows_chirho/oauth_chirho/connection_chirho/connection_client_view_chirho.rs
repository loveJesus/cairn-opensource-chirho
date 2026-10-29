// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The connection client log as an incremental verified view, so a lookup finds a connection client in memory, O(1)
//! warm, and never scans the store's history on a bearer road (PFE #26751: bounded lookups for the new authority).
//!
//! - **The fold** verifies each row once: its dense sequence, its own schema, the root's signature over it, and that
//!   no earlier row holds its client id. Registration already checked the app's verified owner under the root's
//!   append lock, and the root's signature binds it. The full verifier, `verify_connection_clients_chirho`, rechecks
//!   the owner on the cold paths (verify commands, compliance, export).
//! - **Faults refuse.** A log that cannot be examined, a row that fails, and a changed key each refuse a lookup. Only
//!   a genuine absence is "no connection clients".
//! - **Each app's clients, summarized** (Account Create brick 1, PFE #26824): the same fold records an app's first
//!   connection client by its id, and a second turns the app's entry into "several" for good, since clients are
//!   append-only. So a selection by app name is O(1) warm and never scans the history, and it can only ever answer
//!   none, exactly one, or several: it never picks a first, a latest or a default.

use super::super::{client_message_chirho, now_ms_chirho, OauthClientRecordChirho};
use super::{connection_clients_path_chirho, CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO};
use anyhow::{bail, Result};
use cairn_signer_chirho::signer_chirho;
use cairn_verified_prefix_view_chirho::{
    log_missing_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho, ViewRulesChirho,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The verified log, folded: every connection client by its id, and each app's clients summarized.
#[derive(Default)]
pub(crate) struct ConnectionClientIndexChirho {
    by_id_chirho: HashMap<String, OauthClientRecordChirho>,
    by_app_chirho: HashMap<String, AppConnectionClientChirho>,
}

/// An app's connection clients, as the verified view knows them: none, exactly one (by its id), or several.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppConnectionClientChirho {
    NoneChirho,
    OneChirho(String),
    SeveralChirho,
}

static CONNECTION_CLIENT_REGISTRY_CHIRHO: RegistryChirho<ConnectionClientIndexChirho> =
    RegistryChirho::new_chirho();

const CONNECTION_CLIENT_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const CONNECTION_CLIENT_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const CONNECTION_CLIENT_SLOT_CAP_CHIRHO: usize = 8192;

fn connection_client_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: CONNECTION_CLIENT_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: CONNECTION_CLIENT_SLOT_CAP_CHIRHO,
    }
}

struct ConnectionClientLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
    pubkey_chirho: String,
    verifier_id_chirho: String,
}

impl ConnectionClientLogChirho {
    fn new_chirho(root_chirho: &Path, pubkey_chirho: &str) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: connection_clients_path_chirho(root_chirho),
            verifier_id_chirho: format!("oauth-connection-clients-v1-chirho:{pubkey_chirho}"),
            pubkey_chirho: pubkey_chirho.to_string(),
        }
    }
}

impl PrefixLogChirho for ConnectionClientLogChirho {
    type RecordChirho = OauthClientRecordChirho;
    type IndexChirho = ConnectionClientIndexChirho;
    type JobLogChirho = ConnectionClientLogChirho;

    fn job_log_chirho(&self) -> ConnectionClientLogChirho {
        ConnectionClientLogChirho::new_chirho(&self.root_chirho, &self.pubkey_chirho)
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The fold verifies signatures, so the id names the key: a changed key verifies every row again.
    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_id_chirho
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<ConnectionClientIndexChirho> {
        &CONNECTION_CLIENT_REGISTRY_CHIRHO
    }

    fn parse_chirho(&self, line_chirho: &str) -> Result<OauthClientRecordChirho> {
        Ok(serde_json::from_str(line_chirho)?)
    }

    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut ConnectionClientIndexChirho,
        record_chirho: OauthClientRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        #[cfg(test)]
        super::super::token_view_metrics_chirho::note_connection_client_fold_chirho();
        if record_chirho.seq_chirho != expected_seq_chirho {
            bail!(
                "oauth connection client seq gap at index {expected_seq_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho != CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO {
            bail!(
                "oauth connection client {} has schema '{}'",
                record_chirho.seq_chirho,
                record_chirho.schema_chirho
            );
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &self.pubkey_chirho,
            &client_message_chirho(&record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "oauth connection client {} signature invalid",
                record_chirho.client_id_chirho
            );
        }
        if index_chirho
            .by_id_chirho
            .contains_key(&record_chirho.client_id_chirho)
        {
            bail!(
                "oauth connection client '{}' is written twice",
                record_chirho.client_id_chirho
            );
        }
        index_chirho
            .by_app_chirho
            .entry(record_chirho.app_chirho.clone())
            .and_modify(|clients_chirho| *clients_chirho = AppConnectionClientChirho::SeveralChirho)
            .or_insert_with(|| {
                AppConnectionClientChirho::OneChirho(record_chirho.client_id_chirho.clone())
            });
        index_chirho
            .by_id_chirho
            .insert(record_chirho.client_id_chirho.clone(), record_chirho);
        Ok(())
    }
}

/// The connection client `client_id_chirho`, from the verified view: O(1) warm. `None` for a genuine absence of the log
/// or of the id; any fault refuses.
pub(crate) fn connection_client_by_id_chirho(
    root_chirho: &Path,
    client_id_chirho: &str,
) -> Result<Option<OauthClientRecordChirho>> {
    if log_missing_chirho(
        &CONNECTION_CLIENT_REGISTRY_CHIRHO,
        &connection_clients_path_chirho(root_chirho),
    )? {
        return Ok(None);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let (found_chirho, _status_chirho) = with_current_view_chirho(
        &ConnectionClientLogChirho::new_chirho(root_chirho, &pubkey_chirho),
        &connection_client_view_rules_chirho(),
        now_ms_chirho,
        |index_chirho, _now_ms_chirho| {
            index_chirho
                .and_then(|index_chirho| index_chirho.by_id_chirho.get(client_id_chirho).cloned())
        },
    )?;
    Ok(found_chirho)
}

/// The connection clients of `app_chirho`, from the verified view: O(1) warm (Account Create brick 1). `NoneChirho` for a
/// genuine absence of the log or of the app; any fault refuses, so a fault never reads as no client.
pub(crate) fn connection_client_for_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<AppConnectionClientChirho> {
    if log_missing_chirho(
        &CONNECTION_CLIENT_REGISTRY_CHIRHO,
        &connection_clients_path_chirho(root_chirho),
    )? {
        return Ok(AppConnectionClientChirho::NoneChirho);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let (found_chirho, _status_chirho) = with_current_view_chirho(
        &ConnectionClientLogChirho::new_chirho(root_chirho, &pubkey_chirho),
        &connection_client_view_rules_chirho(),
        now_ms_chirho,
        |index_chirho, _now_ms_chirho| {
            index_chirho
                .and_then(|index_chirho| index_chirho.by_app_chirho.get(app_chirho).cloned())
        },
    )?;
    Ok(found_chirho.unwrap_or(AppConnectionClientChirho::NoneChirho))
}
