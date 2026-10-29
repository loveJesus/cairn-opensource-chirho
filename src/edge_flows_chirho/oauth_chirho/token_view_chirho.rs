// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The scoped-token logs as incremental, verified views (brick 4a-2): each token is checked ONCE, when folded, so a
//! bearer request finds its token in memory instead of re-reading the token, client, identity and session logs.
//!
//! - **One view per store (K4).** The legacy token log and the connection token log each have their own view, registry
//!   and verifier id, and fold with the same checks. A lookup by hash reads both stores and refuses a hash in both; a
//!   lookup by seq reads one store, since each store numbers its keys from 0; a principal's keys come from both.
//! - **The fold** runs the full verifier's per-record check (`verify_scoped_token_record_chirho`: client, app,
//!   identity, session times, policy, signature) and verifies the token's OWN session (its key proof and the
//!   instance signature). A token and everything it references are append-only, so its verdict is fixed once checked.
//! - **A full pass** (the first build, the hourly integrity pass, a write-access fallback) also verifies EVERY session
//!   first, as the full verifier `verify_scoped_tokens_chirho` does on every call. So a tampered session that no token
//!   references is still found within the hour, and the view is dropped, fail-closed (agy #25928, ruling (a)).
//! - **No per-request re-check of the token's own record.** The view serves the verified original from memory, so a
//!   re-check would verify the same bytes against the same key and could never refuse; a changed key is a changed
//!   verifier id, which verifies every token again on the next call. (The design's "fresh check" is dropped on this
//!   measurement; see the brick 4 design's as-built note.)
//! - **Cost:** a token's fold reads the client and identity logs, O(C + I) once per token, and finds its session in
//!   brick 4b's session index, O(1); a full pass also verifies every session, O(S), and is in the background except
//!   on a first load.
//! - **Locks:** the append-log lock (where a caller holds it), then the token-use view's slot, then this view's slot,
//!   then the session index's slot (this view's fold reads it). The client and identity logs are read through their
//!   loaders, never through a view slot.

use super::connection_chirho::parse_connection_token_line_chirho;
use super::{
    now_ms_chirho, parse_scoped_token_line_chirho, verify_scoped_token_record_chirho,
    KeyStoreChirho, ScopedTokenRecordChirho,
};
use crate::identity_chirho;
use anyhow::{anyhow, bail, Result};
use cairn_signer_chirho::signer_chirho;
use cairn_verified_prefix_view_chirho::{
    log_missing_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho, ViewRulesChirho,
};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// The verified token log, folded: every token by seq, the seqs of each token hash, and each principal's and each app's
/// keys by (expiry, seq). The owner's key list and the issuance cap read a principal's unexpired keys from it (brick
/// 4b-2), and an app's opt-in to limited keys reads that app's (K1), each O(log n + those keys), never the history.
#[derive(Default)]
pub(super) struct TokenIndexChirho {
    records_chirho: Vec<ScopedTokenRecordChirho>,
    seqs_by_hash_chirho: HashMap<String, Vec<u64>>,
    keys_by_principal_chirho: HashMap<String, BTreeSet<(u64, u64)>>,
    keys_by_app_chirho: HashMap<String, BTreeSet<(u64, u64)>>,
}

static TOKEN_REGISTRY_CHIRHO: RegistryChirho<TokenIndexChirho> = RegistryChirho::new_chirho();
static CONNECTION_TOKEN_REGISTRY_CHIRHO: RegistryChirho<TokenIndexChirho> =
    RegistryChirho::new_chirho();

fn registry_for_store_chirho(
    store_chirho: KeyStoreChirho,
) -> &'static RegistryChirho<TokenIndexChirho> {
    match store_chirho {
        KeyStoreChirho::LegacyChirho => &TOKEN_REGISTRY_CHIRHO,
        KeyStoreChirho::ConnectionChirho => &CONNECTION_TOKEN_REGISTRY_CHIRHO,
    }
}

const TOKEN_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const TOKEN_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const TOKEN_SLOT_CAP_CHIRHO: usize = 8192;

fn token_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: TOKEN_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: TOKEN_SLOT_CAP_CHIRHO,
    }
}

struct TokenLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
    pubkey_chirho: String,
    verifier_id_chirho: String,
    store_chirho: KeyStoreChirho,
}

impl TokenLogChirho {
    fn new_chirho(root_chirho: &Path, pubkey_chirho: &str, store_chirho: KeyStoreChirho) -> Self {
        let verifier_id_chirho = match store_chirho {
            KeyStoreChirho::LegacyChirho => format!("scoped-tokens-v1-chirho:{pubkey_chirho}"),
            KeyStoreChirho::ConnectionChirho => {
                format!("connection-tokens-v1-chirho:{pubkey_chirho}")
            }
        };
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: store_chirho.tokens_path_chirho(root_chirho),
            verifier_id_chirho,
            pubkey_chirho: pubkey_chirho.to_string(),
            store_chirho,
        }
    }
}

impl PrefixLogChirho for TokenLogChirho {
    type RecordChirho = ScopedTokenRecordChirho;
    type IndexChirho = TokenIndexChirho;
    type JobLogChirho = TokenLogChirho;

    fn job_log_chirho(&self) -> TokenLogChirho {
        TokenLogChirho::new_chirho(&self.root_chirho, &self.pubkey_chirho, self.store_chirho)
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The fold verifies signatures, so the id names the key: a changed key verifies every record again.
    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_id_chirho
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<TokenIndexChirho> {
        registry_for_store_chirho(self.store_chirho)
    }

    /// The store's loader's parse, which refuses any other store's schema.
    fn parse_chirho(&self, line_chirho: &str) -> Result<ScopedTokenRecordChirho> {
        match self.store_chirho {
            KeyStoreChirho::LegacyChirho => parse_scoped_token_line_chirho(line_chirho),
            KeyStoreChirho::ConnectionChirho => parse_connection_token_line_chirho(line_chirho),
        }
    }

    /// The full verifier's checks for one token, in its order, plus the token's own session verified. A full pass
    /// (it starts at seq 0) first verifies every session, as the full verifier does.
    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut TokenIndexChirho,
        record_chirho: ScopedTokenRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        if expected_seq_chirho == 0 {
            identity_chirho::verify_sessions_chirho(&self.root_chirho)?;
        }
        if record_chirho.seq_chirho != expected_seq_chirho {
            bail!(
                "scoped token seq gap at index {expected_seq_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        verify_scoped_token_record_chirho(&self.root_chirho, &self.pubkey_chirho, &record_chirho)?;
        identity_chirho::verified_session_for_token_chirho(
            &self.root_chirho,
            &self.pubkey_chirho,
            &record_chirho.principal_chirho,
            record_chirho.session_seq_chirho,
        )?
        .ok_or_else(|| {
            anyhow!(
                "scoped token {} references missing session",
                record_chirho.seq_chirho
            )
        })?;
        index_chirho
            .seqs_by_hash_chirho
            .entry(record_chirho.token_hash_chirho.clone())
            .or_default()
            .push(record_chirho.seq_chirho);
        index_chirho
            .keys_by_principal_chirho
            .entry(record_chirho.principal_chirho.clone())
            .or_default()
            .insert((record_chirho.expires_ms_chirho, record_chirho.seq_chirho));
        index_chirho
            .keys_by_app_chirho
            .entry(record_chirho.app_chirho.clone())
            .or_default()
            .insert((record_chirho.expires_ms_chirho, record_chirho.seq_chirho));
        index_chirho.records_chirho.push(record_chirho);
        Ok(())
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        match self.store_chirho {
            KeyStoreChirho::LegacyChirho => "cairn-scoped-token-view-job-chirho",
            KeyStoreChirho::ConnectionChirho => "cairn-connection-token-view-job-chirho",
        }
    }
}

/// Bring one store's token view current and read it; the closure only copies out. A missing log reads as no index.
/// `pubkey_chirho` is the instance key the caller already loaded: every oauth log is signed by it.
fn with_token_index_chirho<T>(
    root_chirho: &Path,
    pubkey_chirho: &str,
    store_chirho: KeyStoreChirho,
    read_chirho: impl FnOnce(Option<&TokenIndexChirho>) -> T,
) -> Result<T> {
    if log_missing_chirho(
        registry_for_store_chirho(store_chirho),
        &store_chirho.tokens_path_chirho(root_chirho),
    )? {
        return Ok(read_chirho(None));
    }
    let (value_chirho, _status_chirho) = with_current_view_chirho(
        &TokenLogChirho::new_chirho(root_chirho, pubkey_chirho, store_chirho),
        &token_view_rules_chirho(),
        now_ms_chirho,
        |index_chirho, _now_ms_chirho| read_chirho(index_chirho),
    )?;
    Ok(value_chirho)
}

/// The latest verified token whose hash is `token_hash_chirho` and which passes `accept_chirho`, as today's
/// newest-first scan picks it, from whichever store holds it. The map finds the hash's records; the constant-time
/// compare is kept as today's. No engine issues one key into both stores, so a hash in both refuses (K4).
pub(super) fn latest_token_with_hash_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    token_hash_chirho: &str,
    accept_chirho: impl Fn(&ScopedTokenRecordChirho) -> bool,
) -> Result<Option<ScopedTokenRecordChirho>> {
    let mut stores_holding_chirho = 0;
    let mut latest_chirho = None;
    for store_chirho in KeyStoreChirho::ALL_CHIRHO {
        let (held_chirho, found_chirho) =
            with_token_index_chirho(root_chirho, pubkey_chirho, store_chirho, |index_chirho| {
                let Some(index_chirho) = index_chirho else {
                    return (false, None);
                };
                let Some(seqs_chirho) = index_chirho.seqs_by_hash_chirho.get(token_hash_chirho)
                else {
                    return (false, None);
                };
                let found_chirho = seqs_chirho
                    .iter()
                    .rev()
                    .map(|seq_chirho| &index_chirho.records_chirho[*seq_chirho as usize])
                    .find(|record_chirho| {
                        identity_chirho::constant_time_string_eq_chirho(
                            &record_chirho.token_hash_chirho,
                            token_hash_chirho,
                        ) && accept_chirho(record_chirho)
                    })
                    .cloned();
                (true, found_chirho)
            })?;
        if held_chirho {
            stores_holding_chirho += 1;
        }
        latest_chirho = latest_chirho.or(found_chirho);
    }
    if stores_holding_chirho > 1 {
        bail!(
            "TokenInBothStoresChirho: a key hash is in both the legacy and the connection token log; no engine issues \
             one key into both"
        );
    }
    Ok(latest_chirho)
}

/// Whether one store's verified view holds a key with this hash.
pub(super) fn store_holds_hash_chirho(
    root_chirho: &Path,
    store_chirho: KeyStoreChirho,
    token_hash_chirho: &str,
) -> Result<bool> {
    if log_missing_chirho(
        registry_for_store_chirho(store_chirho),
        &store_chirho.tokens_path_chirho(root_chirho),
    )? {
        return Ok(false);
    }
    with_token_index_chirho(
        root_chirho,
        &signer_chirho::pubkey_hex_chirho(root_chirho)?,
        store_chirho,
        |index_chirho| {
            index_chirho.is_some_and(|index_chirho| {
                index_chirho
                    .seqs_by_hash_chirho
                    .contains_key(token_hash_chirho)
            })
        },
    )
}

/// The verified token at `seq_chirho` in `store_chirho`'s OWN numbering, for a use, which names its key within its
/// store (K4): both stores hold a seq 0.
pub(super) fn token_by_seq_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    store_chirho: KeyStoreChirho,
    seq_chirho: u64,
) -> Result<Option<ScopedTokenRecordChirho>> {
    with_token_index_chirho(root_chirho, pubkey_chirho, store_chirho, |index_chirho| {
        index_chirho?
            .records_chirho
            .get(seq_chirho as usize)
            .cloned()
    })
}

/// One index set's keys still unexpired at `now_ms_chirho`, oldest first (a key is live through its expiry instant).
fn unexpired_from_chirho(
    index_chirho: &TokenIndexChirho,
    keys_chirho: Option<&BTreeSet<(u64, u64)>>,
    now_ms_chirho: u64,
) -> Vec<ScopedTokenRecordChirho> {
    keys_chirho.map_or_else(Vec::new, |keys_chirho| {
        keys_chirho
            .range((now_ms_chirho, 0)..)
            .map(|(_, seq_chirho)| index_chirho.records_chirho[*seq_chirho as usize].clone())
            .collect()
    })
}

/// The principal's keys still unexpired at `now_ms_chirho`, from BOTH stores, oldest first (a tie puts the legacy
/// store's first): what the owner's key list shows and the issuance cap counts from (brick 4b-2; K4). The closures only
/// copy out.
pub(super) fn unexpired_keys_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    principal_chirho: &str,
    now_ms_chirho: u64,
) -> Result<Vec<ScopedTokenRecordChirho>> {
    let mut keys_chirho = Vec::new();
    for store_chirho in KeyStoreChirho::ALL_CHIRHO {
        keys_chirho.extend(with_token_index_chirho(
            root_chirho,
            pubkey_chirho,
            store_chirho,
            |index_chirho| {
                index_chirho.map_or_else(Vec::new, |index_chirho| {
                    unexpired_from_chirho(
                        index_chirho,
                        index_chirho.keys_by_principal_chirho.get(principal_chirho),
                        now_ms_chirho,
                    )
                })
            },
        )?);
    }
    keys_chirho.sort_by_key(|key_chirho| {
        (
            key_chirho.expires_ms_chirho,
            KeyStoreChirho::of_token_chirho(key_chirho) == KeyStoreChirho::ConnectionChirho,
            key_chirho.seq_chirho,
        )
    });
    Ok(keys_chirho)
}

/// The issue instants of the principal's connection-store keys that expire at or after `expiring_from_ms_chirho`, ended
/// keys and keys dated after now included: the population K4 Part 3's daily limit decides over. Every issuer gives a
/// key its session's positive lifetime, so a key issued at or after an instant also expires after it, and this read
/// from the daily window's start holds every key the window can count. O(log n + the principal's connection keys
/// unexpired at `expiring_from_ms_chirho`), never the history. The closure only copies out.
pub(super) fn connection_key_issue_instants_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    principal_chirho: &str,
    expiring_from_ms_chirho: u64,
) -> Result<Vec<u64>> {
    with_token_index_chirho(
        root_chirho,
        pubkey_chirho,
        KeyStoreChirho::ConnectionChirho,
        |index_chirho| {
            index_chirho
                .and_then(|index_chirho| {
                    let keys_chirho = index_chirho
                        .keys_by_principal_chirho
                        .get(principal_chirho)?;
                    Some(
                        keys_chirho
                            .range((expiring_from_ms_chirho, 0)..)
                            .map(|(_expires_ms_chirho, seq_chirho)| {
                                #[cfg(test)]
                                super::token_view_metrics_chirho::note_daily_entry_chirho();
                                index_chirho.records_chirho[*seq_chirho as usize].issued_ms_chirho
                            })
                            .collect(),
                    )
                })
                .unwrap_or_default()
        },
    )
}

/// The app's keys still unexpired at `now_ms_chirho` in the LEGACY store, oldest first, for retiring an app's legacy
/// keys when it opts in to limited keys (K1). Only the legacy store can hold a legacy key: every connection key is a
/// limited key (K4). The closure only copies out.
pub(super) fn unexpired_keys_for_app_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    app_chirho: &str,
    now_ms_chirho: u64,
) -> Result<Vec<ScopedTokenRecordChirho>> {
    with_token_index_chirho(
        root_chirho,
        pubkey_chirho,
        KeyStoreChirho::LegacyChirho,
        |index_chirho| {
            index_chirho.map_or_else(Vec::new, |index_chirho| {
                unexpired_from_chirho(
                    index_chirho,
                    index_chirho.keys_by_app_chirho.get(app_chirho),
                    now_ms_chirho,
                )
            })
        },
    )
}

/// Build the root's token views now, both stores, so the first bearer requests find them ready.
pub(super) fn warm_scoped_token_view_chirho(root_chirho: &Path) -> Result<()> {
    for store_chirho in KeyStoreChirho::ALL_CHIRHO {
        if log_missing_chirho(
            registry_for_store_chirho(store_chirho),
            &store_chirho.tokens_path_chirho(root_chirho),
        )? {
            continue;
        }
        with_token_index_chirho(
            root_chirho,
            &signer_chirho::pubkey_hex_chirho(root_chirho)?,
            store_chirho,
            |_| (),
        )?;
    }
    Ok(())
}
