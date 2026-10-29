// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! An owner's own keys (brick 4b-2): each named by an opaque key id, listed for its owner alone, revoked by that id
//! through the session revocation door, and counted toward the issuance cap only while it is live.
//!
//! - **The key id** is the key's stored token hash put through blake3's derive-key mode under its own context, cut to 16
//!   bytes of hex. It is stable, recomputed from the verified record (no new durable form), and tells nothing about the
//!   key, its hash, or how many keys the root has issued.
//! - **A key is live** while it is unexpired and its session is live (4b-1's predicate), so a revoked session or a reset
//!   credential ends it on its next request.
//! - **The list** is the viewer's own unexpired keys from the token view's per-principal index, oldest first, each
//!   marked live or not: O(log n + those keys), never the principal's history. It never shows the key, its hash, its
//!   seq, its session, or another principal's row. A limited key's row shows its actions, read from its grant set
//!   once that set verifies against its signed digest, never its internal marker and digest scopes (K3).
//! - **The revoke** looks the id up ONLY among the viewer's own unexpired keys. So another principal's id, an expired
//!   key's id and a malformed id are one refusal, reached by the same lookups and touching no shared state. A found key
//!   has its session revoked through the revocation door, so a repeat answers the same and appends nothing.
//! - **The cap** (4a-2b) counts the principal's LIVE rate-limited keys, so revoking a key, or resetting the credential,
//!   frees its slot at once (PFE #26022). Its cost is bounded by the issuance rate times the key lifetime, never by
//!   history.
//!
//! Workflow: the owner's keys, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
//! (4b-2, as built).

use super::{
    now_ms_chirho, token_view_chirho, ScopedTokenRateLimitChirho, ScopedTokenRecordChirho,
};
use crate::identity_chirho;
use anyhow::{anyhow, Result};
use cairn_capability_chirho::capability_key_grant_chirho::{
    scopes_mark_limited_key_chirho, verify_limited_key_grants_chirho,
};
use cairn_signer_chirho::signer_chirho;
use serde::Serialize;
use std::fmt;
use std::path::Path;

/// The key id's blake3 derive-key context: a domain of its own, so the id is never the plain hash of anything.
const SCOPED_KEY_ID_CONTEXT_CHIRHO: &str = "cairn-scoped-key-id-v1-chirho";
const KEY_REVOKE_ACTOR_CHIRHO: &str = "owner-key-chirho";
const KEY_REVOKE_REASON_CHIRHO: &str = "owner-key-revoke-chirho";

/// An owner's handle for one key: blake3 in derive-key mode under its own context, over the key's stored token hash,
/// first 16 bytes in hex.
pub fn scoped_key_id_chirho(token_hash_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new_derive_key(SCOPED_KEY_ID_CONTEXT_CHIRHO);
    hasher_chirho.update(token_hash_chirho.as_bytes());
    hasher_chirho.finalize().as_bytes()[..16]
        .iter()
        .map(|byte_chirho| format!("{byte_chirho:02x}"))
        .collect()
}

/// One row of an owner's key list: what the owner may see of a key. Never the key, its hash, its seq or its session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScopedKeyRowChirho {
    pub key_id_chirho: String,
    pub app_chirho: String,
    /// A legacy key's scopes, or a limited key's actions (K3).
    pub scopes_chirho: Vec<String>,
    pub issued_ms_chirho: u64,
    pub expires_ms_chirho: u64,
    /// The policy the key was issued with; `None` for an operator's key without one.
    pub rate_limit_chirho: Option<ScopedTokenRateLimitChirho>,
    /// Unexpired and its session live. False once its session is revoked or its credential reset; it is listed until
    /// it expires, so the owner sees it ended rather than vanish.
    pub live_chirho: bool,
}

/// The one refusal for an id that does not name one of the viewer's own unexpired keys: another principal's id, an
/// expired key's id, a malformed id and an id that never existed all read as this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownScopedKeyChirho;

impl fmt::Display for UnknownScopedKeyChirho {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no such key")
    }
}

impl std::error::Error for UnknownScopedKeyChirho {}

/// The viewer's own unexpired keys at `now_ms_chirho`, oldest first, each with whether it is live.
fn own_keys_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    principal_chirho: &str,
    now_ms_chirho: u64,
) -> Result<Vec<(ScopedTokenRecordChirho, bool)>> {
    token_view_chirho::unexpired_keys_chirho(
        root_chirho,
        pubkey_chirho,
        principal_chirho,
        now_ms_chirho,
    )?
    .into_iter()
    .map(|key_chirho| {
        let live_chirho = identity_chirho::key_session_live_chirho(
            root_chirho,
            pubkey_chirho,
            principal_chirho,
            key_chirho.session_seq_chirho,
            now_ms_chirho,
        )?;
        Ok((key_chirho, live_chirho))
    })
    .collect()
}

/// The viewer's own unexpired keys, for their key list (brick 4b-2).
pub fn list_own_keys_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<Vec<ScopedKeyRowChirho>> {
    list_own_keys_at_chirho(root_chirho, principal_chirho, now_ms_chirho())
}

/// The key list at `now_ms_chirho`, as `list_own_keys_chirho` reads it with the real clock.
pub(super) fn list_own_keys_at_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    now_ms_chirho: u64,
) -> Result<Vec<ScopedKeyRowChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    own_keys_chirho(root_chirho, &pubkey_chirho, principal_chirho, now_ms_chirho)?
        .into_iter()
        .map(|(key_chirho, live_chirho)| {
            let scopes_chirho = shown_scopes_chirho(&key_chirho)?;
            Ok(ScopedKeyRowChirho {
                key_id_chirho: scoped_key_id_chirho(&key_chirho.token_hash_chirho),
                app_chirho: key_chirho.app_chirho,
                scopes_chirho,
                issued_ms_chirho: key_chirho.issued_ms_chirho,
                expires_ms_chirho: key_chirho.expires_ms_chirho,
                rate_limit_chirho: key_chirho.rate_limit_chirho,
                live_chirho,
            })
        })
        .collect()
}

/// What a row shows as a key's scopes: a legacy key's own, or a limited key's actions (K3). A limited key's grant set
/// rides beside its signed record, bound by the digest in its signed scopes, so it is shown only once it verifies; a
/// grant set that is missing or does not verify fails the list, as any record that fails verification does.
fn shown_scopes_chirho(key_chirho: &ScopedTokenRecordChirho) -> Result<Vec<String>> {
    if !scopes_mark_limited_key_chirho(&key_chirho.scopes_chirho) {
        return Ok(key_chirho.scopes_chirho.clone());
    }
    let grants_chirho = key_chirho
        .limited_grants_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("a limited key's record carries no grant set"))?;
    verify_limited_key_grants_chirho(
        &key_chirho.scopes_chirho,
        &key_chirho.app_chirho,
        grants_chirho,
    )?;
    Ok(grants_chirho
        .actions_chirho
        .iter()
        .map(|grant_chirho| grant_chirho.action_chirho.clone())
        .collect())
}

/// Revoke one of the viewer's own keys by its key id (brick 4b-2). The id is looked up ONLY among the viewer's own
/// unexpired keys, and anything else refuses with `UnknownScopedKeyChirho`. A found key's session is revoked through the
/// revocation door, so revoking twice answers the same and appends one record.
pub fn revoke_own_key_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    key_id_chirho: &str,
) -> Result<()> {
    revoke_own_key_at_chirho(
        root_chirho,
        principal_chirho,
        key_id_chirho,
        now_ms_chirho(),
    )
}

/// The revoke at `now_ms_chirho`, as `revoke_own_key_chirho` runs it with the real clock.
pub(super) fn revoke_own_key_at_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    key_id_chirho: &str,
    now_ms_chirho: u64,
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let Some(key_chirho) = token_view_chirho::unexpired_keys_chirho(
        root_chirho,
        &pubkey_chirho,
        principal_chirho,
        now_ms_chirho,
    )?
    .into_iter()
    .find(|key_chirho| {
        identity_chirho::constant_time_string_eq_chirho(
            &scoped_key_id_chirho(&key_chirho.token_hash_chirho),
            key_id_chirho,
        )
    }) else {
        return Err(UnknownScopedKeyChirho.into());
    };
    identity_chirho::revoke_session_by_seq_chirho(
        root_chirho,
        principal_chirho,
        key_chirho.session_seq_chirho,
        KEY_REVOKE_ACTOR_CHIRHO,
        KEY_REVOKE_REASON_CHIRHO,
    )?;
    Ok(())
}

/// The daily limit's population (K4 Part 3): the issue instants of the principal's connection-store keys expiring at or
/// after `expiring_from_ms_chirho`, ended ones included. It is read under the root append lock beside the cap's count,
/// so no issuance lands between it and the append it decides.
pub(super) fn connection_issue_instants_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    expiring_from_ms_chirho: u64,
) -> Result<Vec<u64>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    token_view_chirho::connection_key_issue_instants_chirho(
        root_chirho,
        &pubkey_chirho,
        principal_chirho,
        expiring_from_ms_chirho,
    )
}

/// The issuance cap's count (4a-2b; live keys only since 4b-2): the principal's rate-limited keys that are live at
/// `now_ms_chirho`. A key whose session was revoked, or whose credential was reset, holds no slot. It runs under the
/// token log's append lock; revocations append under the same lock, so they cannot race it, and a concurrent reset can
/// only make the count high, never low.
pub(super) fn live_rate_limited_keys_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    now_ms_chirho: u64,
) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut live_chirho = 0;
    for key_chirho in token_view_chirho::unexpired_keys_chirho(
        root_chirho,
        &pubkey_chirho,
        principal_chirho,
        now_ms_chirho,
    )? {
        if key_chirho.rate_limit_chirho.is_some()
            && identity_chirho::key_session_live_chirho(
                root_chirho,
                &pubkey_chirho,
                principal_chirho,
                key_chirho.session_seq_chirho,
                now_ms_chirho,
            )?
        {
            live_chirho += 1;
        }
    }
    Ok(live_chirho)
}
