// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4's connection token and use logs: a connection client's keys and their uses, signed by the root under their own
//! schemas in logs no engine before K4 reads, so a rollback can neither see nor honour a connection key.
//!
//! - **Their own namespace.** Each log's sequences run densely from 0, apart from the legacy logs', so both stores hold
//!   a seq 0. A use names its key by that key's seq in its OWN store's token log; nothing resolves across stores.
//! - **Only limited keys.** A connection client exists only for an app opened to limited keys, so every key here is a
//!   limited key whose grant set verifies against its signed digest, issued through a client of this store
//!   (`verify_key_store_chirho`, in the full record check every view and verifier runs).
//! - **One store per key.** A key hash in both token logs refuses every lookup and this verifier.
//!
//! Design: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (Part 1's carrier).

use super::super::{
    load_scoped_tokens_chirho, token_use_view_chirho, token_view_chirho,
    verify_scoped_token_record_chirho, ScopedTokenRecordChirho, ScopedTokenUseRecordChirho,
};
use super::{require_exact_schema_chirho, KeyStoreChirho};
use crate::identity_chirho;
use anyhow::{bail, Result};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_signer_chirho::signer_chirho;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The connection token log's schema. It is part of the signed message, so a row signed under it cannot verify as a
/// legacy key, nor a legacy row as a connection key.
pub(crate) const CONNECTION_TOKEN_RECORD_SCHEMA_CHIRHO: &str = "connection-token-record-v1-chirho";
/// The connection use log's schema, likewise part of the signed message.
pub(crate) const CONNECTION_TOKEN_USE_RECORD_SCHEMA_CHIRHO: &str =
    "connection-token-use-record-v1-chirho";

pub(crate) fn connection_tokens_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("connection-tokens-chirho.jsonl")
}

pub(crate) fn connection_token_uses_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("connection-token-uses-chirho.jsonl")
}

/// One line of the connection token log: the ONE parser its loader and its view share.
pub(crate) fn parse_connection_token_line_chirho(
    line_chirho: &str,
) -> Result<ScopedTokenRecordChirho> {
    let record_chirho: ScopedTokenRecordChirho = serde_json::from_str(line_chirho)?;
    require_exact_schema_chirho(
        &record_chirho.schema_chirho,
        CONNECTION_TOKEN_RECORD_SCHEMA_CHIRHO,
        "connection token record",
    )?;
    Ok(record_chirho)
}

/// One line of the connection use log: the ONE parser its loader and its view share.
pub(crate) fn parse_connection_token_use_line_chirho(
    line_chirho: &str,
) -> Result<ScopedTokenUseRecordChirho> {
    let record_chirho: ScopedTokenUseRecordChirho = serde_json::from_str(line_chirho)?;
    require_exact_schema_chirho(
        &record_chirho.schema_chirho,
        CONNECTION_TOKEN_USE_RECORD_SCHEMA_CHIRHO,
        "connection token use record",
    )?;
    Ok(record_chirho)
}

/// The connection store's keys, as written. Only a genuine absence is an empty list; a log that cannot be examined
/// refuses, and so does a row of any other schema.
pub fn load_connection_tokens_chirho(root_chirho: &Path) -> Result<Vec<ScopedTokenRecordChirho>> {
    #[cfg(test)]
    super::super::token_view_metrics_chirho::note_connection_log_read_chirho();
    let Some(text_chirho) = read_log_text_chirho(&connection_tokens_path_chirho(root_chirho))?
    else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(parse_connection_token_line_chirho(line_chirho)?);
    }
    Ok(records_chirho)
}

/// The connection store's uses, as written, read as the key loader reads.
pub fn load_connection_token_uses_chirho(
    root_chirho: &Path,
) -> Result<Vec<ScopedTokenUseRecordChirho>> {
    #[cfg(test)]
    super::super::token_view_metrics_chirho::note_connection_log_read_chirho();
    let Some(text_chirho) = read_log_text_chirho(&connection_token_uses_path_chirho(root_chirho))?
    else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(parse_connection_token_use_line_chirho(line_chirho)?);
    }
    Ok(records_chirho)
}

/// Verify the connection token log: every session (as the legacy verifier does), dense sequences from 0, every key's
/// full record check, and no key hash the legacy token log also holds. Returns how many keys it holds.
pub fn verify_connection_tokens_chirho(root_chirho: &Path) -> Result<usize> {
    identity_chirho::verify_sessions_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_connection_tokens_chirho(root_chirho)?;
    let legacy_hashes_chirho: HashSet<String> = load_scoped_tokens_chirho(root_chirho)?
        .into_iter()
        .map(|record_chirho| record_chirho.token_hash_chirho)
        .collect();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "connection token seq gap at index {index_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if legacy_hashes_chirho.contains(&record_chirho.token_hash_chirho) {
            bail!(
                "TokenInBothStoresChirho: connection token {} has a key hash the legacy token log also holds",
                record_chirho.seq_chirho
            );
        }
        verify_scoped_token_record_chirho(root_chirho, &pubkey_chirho, record_chirho)?;
    }
    Ok(records_chirho.len())
}

/// Verify the connection use log against the connection token log ALONE: each use names its key by its seq in this
/// store, so the legacy token log is never consulted. Returns how many uses it holds.
pub fn verify_connection_token_uses_chirho(root_chirho: &Path) -> Result<usize> {
    verify_connection_tokens_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    token_use_view_chirho::verify_uses_in_namespace_chirho(
        &pubkey_chirho,
        &load_connection_tokens_chirho(root_chirho)?,
        &load_connection_token_uses_chirho(root_chirho)?,
    )
}

/// Whether the connection token log holds a key with this hash, read from its verified view, O(1) warm: for the
/// run-intent resume, which refuses a connection key's run by the limited-key rule rather than as an unknown key.
pub fn connection_token_hash_recorded_chirho(
    root_chirho: &Path,
    token_hash_chirho: &str,
) -> Result<bool> {
    token_view_chirho::store_holds_hash_chirho(
        root_chirho,
        KeyStoreChirho::ConnectionChirho,
        token_hash_chirho,
    )
}
