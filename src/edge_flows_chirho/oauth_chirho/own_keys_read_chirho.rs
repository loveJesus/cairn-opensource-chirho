// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The owner's keys as a blessed read (K3): a node holding `read-store:own-keys-chirho/` in a signed-in app's route
//! reads the signed-in viewer's own key list, so a no-script page can render it with a Disconnect form per live key.
//!
//! - **Only a browser session reads.** The viewer is the host's request context, never the request. A run with no
//!   context, or a request authenticated by any key, is refused; a principal the request claims is only checked for
//!   agreement. A browser session's context carries `BROWSER_SESSION_CLIENT_ID_CHIRHO`, which no key's can: a key's
//!   client id is its registered client's, and every client id is generated as `client/<hex>`.
//! - **The exact prefix, read only.** This road answers only on `own-keys-chirho/` exactly; every other store road
//!   refuses the prefix, and no write may address it.
//! - **Two states.** `available-chirho` carries her rows, possibly none. `unavailable-chirho` carries a reason and no
//!   rows, for a key or session log that fails verification, a store failure, or a key log the engine cannot examine
//!   (a link, a directory, a pipe, an examination error: the shared absence rule, `log_missing_chirho`); those are never
//!   an empty list. Her rows come from both stores (K4), so either store's fault answers unavailable
//!   (`connection_management_tests_chirho.rs`, the faulted-log arm).
//! - **Her rows are the JSON list's rows** (`list_own_keys_chirho`): never the key, its hash, its seq or its session.
//! - **Private to her.** The answer's private subject is her principal, the subject of her own private request
//!   plane, so it never rests in public CAS and her page can render it beside her private request.
//!
//! Workflow: the owner's keys page (K3),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`.

use super::key_listing_chirho::{list_own_keys_chirho, ScopedKeyRowChirho};
use crate::model_chirho::RequestContextChirho;
use anyhow::{anyhow, bail, Context, Result};
use cairn_capability_chirho::capability_key_grant_chirho::OWN_KEYS_CAPABILITY_PREFIX_CHIRHO;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The client id a browser session's request context carries. No key's context can carry it: a key's client id is
/// its registered client's, and every client id is generated as `client/<hex>`.
pub const BROWSER_SESSION_CLIENT_ID_CHIRHO: &str = "browser-session-chirho";
pub const OWN_KEYS_READ_REQUEST_SCHEMA_CHIRHO: &str = "own-keys-read-request-v1-chirho";
pub const OWN_KEYS_READ_SCHEMA_CHIRHO: &str = "own-keys-read-v1-chirho";
/// The one reason an unavailable answer gives.
pub const OWN_KEYS_UNAVAILABLE_REASON_CHIRHO: &str = "keys-unavailable-chirho";
const MAX_OWN_KEYS_REQUEST_BYTES_CHIRHO: usize = 4 * 1024;

/// Strict except for the two fields the served plain-input path injects into every JSON object body
/// (`user_principal_chirho`, `app_params_chirho`); the read is scoped by the verified session context, never by the
/// claimed principal, which is only checked for agreement.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnKeysReadRequestChirho {
    pub schema_chirho: String,
    #[serde(default)]
    pub user_principal_chirho: Option<String>,
    #[serde(default)]
    pub app_params_chirho: Option<serde_json::Value>,
}

/// The answer: `{"schema_chirho", "state_chirho": "available-chirho", "keys_chirho": [...]}` or
/// `{"schema_chirho", "state_chirho": "unavailable-chirho", "reason_chirho"}`, with no `keys_chirho` at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OwnKeysReadChirho {
    pub schema_chirho: String,
    #[serde(flatten)]
    pub state_chirho: OwnKeysStateChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state_chirho")]
pub enum OwnKeysStateChirho {
    /// Her own unexpired keys, oldest first; empty only when she has none.
    #[serde(rename = "available-chirho")]
    AvailableChirho {
        keys_chirho: Vec<ScopedKeyRowChirho>,
    },
    /// Her records failed verification or a store read; never an empty list. A log the engine cannot examine is not yet
    /// caught here (see the module doc).
    #[serde(rename = "unavailable-chirho")]
    UnavailableChirho { reason_chirho: String },
}

/// What the read hands the effect layer: the answer's bytes and the subject it rests under.
#[derive(Debug)]
pub struct OwnKeysReadOutputChirho {
    pub response_chirho: Vec<u8>,
    pub private_subject_chirho: String,
}

/// A request is the owner's-keys read when its schema says so; any other bytes are not, and fall to the store roads,
/// which refuse this road's prefix.
pub fn decode_own_keys_read_request_chirho(
    request_bytes_chirho: &[u8],
) -> Result<Option<OwnKeysReadRequestChirho>> {
    if request_bytes_chirho.len() > MAX_OWN_KEYS_REQUEST_BYTES_CHIRHO {
        return Ok(None);
    }
    let Ok(value_chirho) = serde_json::from_slice::<serde_json::Value>(request_bytes_chirho) else {
        return Ok(None);
    };
    if value_chirho
        .get("schema_chirho")
        .and_then(|schema_chirho| schema_chirho.as_str())
        != Some(OWN_KEYS_READ_REQUEST_SCHEMA_CHIRHO)
    {
        return Ok(None);
    }
    serde_json::from_value(value_chirho)
        .map(Some)
        .context("decode OwnKeysReadRequestChirho")
}

/// Whether a store capability prefix is in this road's namespace, which no other store road may read or write.
pub fn reserved_own_keys_prefix_chirho(capability_prefix_chirho: &str) -> bool {
    capability_prefix_chirho.starts_with(OWN_KEYS_CAPABILITY_PREFIX_CHIRHO)
}

/// The viewer this read answers for: a browser session's host-derived principal, through the exact prefix.
fn browser_viewer_chirho<'context_chirho>(
    capability_prefix_chirho: &str,
    request_chirho: &OwnKeysReadRequestChirho,
    request_context_chirho: Option<&'context_chirho RequestContextChirho>,
) -> Result<&'context_chirho str> {
    if capability_prefix_chirho != OWN_KEYS_CAPABILITY_PREFIX_CHIRHO {
        bail!(
            "the owner's keys are read only through the exact capability prefix '{OWN_KEYS_CAPABILITY_PREFIX_CHIRHO}'"
        );
    }
    let context_chirho = request_context_chirho
        .ok_or_else(|| anyhow!("the owner's keys need a signed-in browser session"))?;
    if context_chirho.client_id_chirho != BROWSER_SESSION_CLIENT_ID_CHIRHO
        || context_chirho.key_limit_chirho.is_some()
    {
        bail!("the owner's keys are read only by a browser session, never by a key");
    }
    let principal_chirho = context_chirho.user_principal_chirho.as_str();
    if principal_chirho.trim().is_empty() {
        bail!("the owner's keys need the host's signed-in principal");
    }
    if request_chirho
        .user_principal_chirho
        .as_deref()
        .is_some_and(|claimed_chirho| claimed_chirho != principal_chirho)
    {
        bail!("the request claims a principal that is not the signed-in viewer");
    }
    Ok(principal_chirho)
}

/// Read the signed-in viewer's own key list. A refusal fails the run; a list that cannot be read is the
/// `unavailable-chirho` answer.
pub fn run_own_keys_read_chirho(
    root_chirho: &Path,
    capability_prefix_chirho: &str,
    request_chirho: &OwnKeysReadRequestChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<OwnKeysReadOutputChirho> {
    let principal_chirho = browser_viewer_chirho(
        capability_prefix_chirho,
        request_chirho,
        request_context_chirho,
    )?;
    let state_chirho = match list_own_keys_chirho(root_chirho, principal_chirho) {
        Ok(keys_chirho) => OwnKeysStateChirho::AvailableChirho { keys_chirho },
        Err(error_chirho) => {
            eprintln!("the owner's key list read answered unavailable: {error_chirho:#}");
            OwnKeysStateChirho::UnavailableChirho {
                reason_chirho: OWN_KEYS_UNAVAILABLE_REASON_CHIRHO.to_string(),
            }
        }
    };
    let answer_chirho = OwnKeysReadChirho {
        schema_chirho: OWN_KEYS_READ_SCHEMA_CHIRHO.to_string(),
        state_chirho,
    };
    Ok(OwnKeysReadOutputChirho {
        response_chirho: serde_json::to_vec(&answer_chirho)?,
        private_subject_chirho: principal_chirho.to_string(),
    })
}

/// The subject the answer rests under, for the effect layer's resolution: the same checks, the same principal.
pub fn own_keys_response_subject_chirho(
    capability_prefix_chirho: &str,
    request_chirho: &OwnKeysReadRequestChirho,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<String> {
    browser_viewer_chirho(
        capability_prefix_chirho,
        request_chirho,
        request_context_chirho,
    )
    .map(str::to_string)
}
