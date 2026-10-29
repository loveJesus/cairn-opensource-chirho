// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4's connection stores: a client of an app opened to limited keys lives in a log no older engine reads, so a
//! rollback cannot mint for it. Registration picks the store, and rechecks the app's mode and owner, under the root's
//! append lock, the same lock the opt-in takes, so the two never interleave. Its keys and their uses follow it into
//! their own logs (`connection_tokens_chirho.rs`).
//!
//! - **A record names its store by its signed schema.** Each store's reads refuse any other schema, so a client or key
//!   read from a store always names that store, and the store travels with the record wherever it goes.
//!
//! Design and measured evidence: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md`
//! (Part 1). Build record: `spec-chirho/tasklists-chirho/26-10-09_05-45-tasklist-k4_connection_carrier-chirho.md`.

use super::{
    client_message_chirho, clients_path_chirho, load_clients_chirho, next_client_id_chirho,
    now_ms_chirho, scoped_token_uses_path_chirho, scoped_tokens_path_chirho,
    OauthClientRecordChirho, ScopedTokenRecordChirho, OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO,
    SCOPED_TOKEN_RECORD_SCHEMA_CHIRHO, SCOPED_TOKEN_USE_RECORD_SCHEMA_CHIRHO,
};
use crate::{app_chirho, identity_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Result};
use cairn_capability_chirho::capability_key_grant_chirho::{
    scopes_mark_limited_key_chirho, verify_limited_key_grants_chirho,
};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};

#[path = "connection_client_view_chirho.rs"]
mod connection_client_view_chirho;
#[path = "connection_tokens_chirho.rs"]
mod connection_tokens_chirho;
pub use connection_tokens_chirho::{
    connection_token_hash_recorded_chirho, load_connection_token_uses_chirho,
    load_connection_tokens_chirho, verify_connection_token_uses_chirho,
    verify_connection_tokens_chirho,
};
pub(crate) use connection_tokens_chirho::{
    connection_token_uses_path_chirho, connection_tokens_path_chirho,
    parse_connection_token_line_chirho, parse_connection_token_use_line_chirho,
    CONNECTION_TOKEN_RECORD_SCHEMA_CHIRHO, CONNECTION_TOKEN_USE_RECORD_SCHEMA_CHIRHO,
};
#[path = "connection_issuance_chirho.rs"]
mod connection_issuance_chirho;
pub(in crate::oauth_chirho) use connection_issuance_chirho::issue_connection_key_at_chirho;
#[cfg(test)]
pub(in crate::oauth_chirho) use connection_issuance_chirho::{
    connection_issuance_window_start_chirho, daily_limit_admits_chirho,
    CONNECTION_ISSUANCE_WINDOW_MS_CHIRHO,
};
pub use connection_issuance_chirho::{
    ConnectionDailyLimitReachedChirho, ConnectionIssueFaultChirho,
    CONNECTION_ISSUANCES_PER_DAY_CHIRHO,
};

#[path = "connection_served_chirho.rs"]
mod connection_served_chirho;
#[cfg(test)]
pub(in crate::oauth_chirho) use connection_served_chirho::issue_connection_key_served_at_chirho;
pub use connection_served_chirho::{
    connection_app_selector_well_formed_chirho, connection_form_choices_chirho,
    connection_return_path_for_app_chirho, connection_return_path_well_formed_chirho,
    issue_connection_key_served_chirho, ConnectionFormChoicesChirho, ConnectionSelectorChirho,
    ConnectionServedOutcomeChirho, ConnectionServedRefusalChirho, ConnectionServedRequestChirho,
    CONNECTION_APP_SELECTOR_MAX_BYTES_CHIRHO, CONNECTION_RETURN_MAX_BYTES_CHIRHO,
};

/// The connection client log's schema. A row signed under it cannot verify as a legacy client, nor a legacy row as a
/// connection client: the schema is part of the signed message.
pub(super) const CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO: &str =
    "oauth-connection-client-record-v1-chirho";

/// Which store a client, and so its keys and their uses, lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStoreChirho {
    /// The logs every engine reads: an app that opens nothing, exactly as before.
    LegacyChirho,
    /// The successor-only logs: an app opened to limited keys (K4).
    ConnectionChirho,
}

impl KeyStoreChirho {
    /// Both stores, legacy first: the order a lookup across both reads them in.
    pub const ALL_CHIRHO: [KeyStoreChirho; 2] = [
        KeyStoreChirho::LegacyChirho,
        KeyStoreChirho::ConnectionChirho,
    ];

    /// The store a client record lives in, read from its signed schema.
    pub fn of_client_chirho(client_chirho: &OauthClientRecordChirho) -> Self {
        if client_chirho.schema_chirho == CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO {
            Self::ConnectionChirho
        } else {
            Self::LegacyChirho
        }
    }

    /// The store a key record lives in, read from its signed schema.
    pub fn of_token_chirho(record_chirho: &ScopedTokenRecordChirho) -> Self {
        if record_chirho.schema_chirho == CONNECTION_TOKEN_RECORD_SCHEMA_CHIRHO {
            Self::ConnectionChirho
        } else {
            Self::LegacyChirho
        }
    }

    /// The other store: the one a rate decision also counts, since a rate budget belongs to its key, not to a store.
    pub(crate) fn other_chirho(self) -> Self {
        match self {
            Self::LegacyChirho => Self::ConnectionChirho,
            Self::ConnectionChirho => Self::LegacyChirho,
        }
    }

    pub(crate) fn tokens_path_chirho(self, root_chirho: &Path) -> PathBuf {
        match self {
            Self::LegacyChirho => scoped_tokens_path_chirho(root_chirho),
            Self::ConnectionChirho => connection_tokens_path_chirho(root_chirho),
        }
    }

    pub(crate) fn token_schema_chirho(self) -> &'static str {
        match self {
            Self::LegacyChirho => SCOPED_TOKEN_RECORD_SCHEMA_CHIRHO,
            Self::ConnectionChirho => CONNECTION_TOKEN_RECORD_SCHEMA_CHIRHO,
        }
    }

    pub(crate) fn uses_path_chirho(self, root_chirho: &Path) -> PathBuf {
        match self {
            Self::LegacyChirho => scoped_token_uses_path_chirho(root_chirho),
            Self::ConnectionChirho => connection_token_uses_path_chirho(root_chirho),
        }
    }

    pub(crate) fn use_schema_chirho(self) -> &'static str {
        match self {
            Self::LegacyChirho => SCOPED_TOKEN_USE_RECORD_SCHEMA_CHIRHO,
            Self::ConnectionChirho => CONNECTION_TOKEN_USE_RECORD_SCHEMA_CHIRHO,
        }
    }
}

pub(super) fn connection_clients_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("oauth-connection-clients-chirho.jsonl")
}

/// A successor-only log's schema check: exactly `expected_chirho`. Unlike the legacy logs, these logs never held a row
/// without a schema, so an empty schema refuses too.
fn require_exact_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    if schema_chirho != expected_chirho {
        bail!("unsupported {label_chirho} schema '{schema_chirho}'");
    }
    Ok(())
}

/// What a key's store requires of it, beside the full record check: its client lives in the key's own store, and a
/// connection key is a limited key whose grant set verifies against its signed digest. A legacy-log key naming a
/// connection client would fail an older engine's whole token log; a connection key naming a legacy client, or holding
/// anything but a limited grant, was never issued.
pub(super) fn verify_key_store_chirho(
    client_chirho: &OauthClientRecordChirho,
    record_chirho: &ScopedTokenRecordChirho,
) -> Result<()> {
    let store_chirho = KeyStoreChirho::of_token_chirho(record_chirho);
    if KeyStoreChirho::of_client_chirho(client_chirho) != store_chirho {
        bail!(
            "scoped token {} and its client '{}' live in different stores",
            record_chirho.seq_chirho,
            record_chirho.client_id_chirho
        );
    }
    if store_chirho == KeyStoreChirho::ConnectionChirho {
        if !scopes_mark_limited_key_chirho(&record_chirho.scopes_chirho) {
            bail!(
                "connection token {} is not a limited key",
                record_chirho.seq_chirho
            );
        }
        let grants_chirho = record_chirho
            .limited_grants_chirho
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "connection token {} carries no grant set",
                    record_chirho.seq_chirho
                )
            })?;
        verify_limited_key_grants_chirho(
            &record_chirho.scopes_chirho,
            &record_chirho.app_chirho,
            grants_chirho,
        )?;
    }
    Ok(())
}

/// Register a client for `app_chirho` in the store its mode selects, as one section under the root's append lock:
/// - an app opened to limited keys takes only its verified owner (another Owner refuses), into the connection store;
/// - an app that opens nothing takes an Owner principal into the legacy store, exactly as before, so operator and
///   recovery registration stay as they were.
///
/// An app whose mode cannot be known refuses; it is never taken for an app that opens nothing.
pub fn register_client_in_store_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<(OauthClientRecordChirho, KeyStoreChirho)> {
    if app_chirho.trim().is_empty() {
        bail!("app_chirho is required");
    }
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let store_chirho = if app_chirho::app_key_authority_record_chirho(root_chirho, app_chirho)?
            .is_some()
        {
            app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
            KeyStoreChirho::ConnectionChirho
        } else {
            let owner_chirho =
                identity_chirho::find_identity_chirho(root_chirho, owner_principal_chirho)?
                    .ok_or_else(|| anyhow!("unknown owner principal '{owner_principal_chirho}'"))?;
            if owner_chirho.kind_chirho != identity_chirho::PrincipalKindChirho::OwnerChirho {
                bail!("oauth client owner must be an owner principal");
            }
            KeyStoreChirho::LegacyChirho
        };
        let (path_chirho, schema_chirho) = match store_chirho {
            KeyStoreChirho::LegacyChirho => (
                clients_path_chirho(root_chirho),
                OAUTH_CLIENT_RECORD_SCHEMA_CHIRHO,
            ),
            KeyStoreChirho::ConnectionChirho => (
                connection_clients_path_chirho(root_chirho),
                CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO,
            ),
        };
        run_registration_hold_chirho()?;
        let seq_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        let mut record_chirho = OauthClientRecordChirho {
            seq_chirho,
            schema_chirho: schema_chirho.to_string(),
            client_id_chirho: next_client_id_chirho(root_chirho)?,
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &client_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            seq_chirho,
            &record_chirho,
        )?;
        Ok((record_chirho, store_chirho))
    })
}

/// K4's opening precondition, for the caller that holds the root's append lock (the opt-in): an app's INITIAL opening
/// refuses while the legacy store holds any client of that app, since an older engine would still mint unrestricted
/// keys for it. It runs before any retirement or authority append, so a refused opening changes nothing. An app that
/// already opened is not re-judged here.
pub(crate) fn refuse_initial_opening_with_legacy_client_under_append_lock_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<()> {
    if app_chirho::app_key_authority_record_chirho(root_chirho, app_chirho)?.is_some() {
        return Ok(());
    }
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    if K1_ERA_OPENING_CHIRHO.with(std::cell::Cell::get) {
        return Ok(());
    }
    if let Some(client_chirho) = load_clients_chirho(root_chirho)?
        .into_iter()
        .find(|client_chirho| client_chirho.app_chirho == app_chirho)
    {
        bail!(
            "OpeningWithLegacyClientChirho: app '{app_chirho}' has a client in the legacy store ('{}'), which an older \
             engine would still mint unrestricted keys for; an app with a legacy client cannot open to limited keys",
            client_chirho.client_id_chirho
        );
    }
    Ok(())
}

/// Test-only: one step a locked section runs on this thread (registration's or issuance's), taken once.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
type HoldSlotChirho = std::cell::RefCell<Option<Box<dyn FnOnce() -> Result<()>>>>;

#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
thread_local! {
    static K1_ERA_OPENING_CHIRHO: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REGISTRATION_HOLD_CHIRHO: HoldSlotChirho = const { std::cell::RefCell::new(None) };
    static ISSUANCE_HOLD_CHIRHO: HoldSlotChirho = const { std::cell::RefCell::new(None) };
}

/// Test-only: build a root as the K1 engine wrote it, before K4's opening precondition, by running `build_chirho` with
/// that precondition off on this thread. It exists so K1's retirement and rollback arms can still construct a legacy
/// key for an app that later opens; no other caller may use it.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub fn with_k1_era_opening_chirho<T>(build_chirho: impl FnOnce() -> T) -> T {
    K1_ERA_OPENING_CHIRHO.with(|flag_chirho| flag_chirho.set(true));
    let built_chirho = build_chirho();
    K1_ERA_OPENING_CHIRHO.with(|flag_chirho| flag_chirho.set(false));
    built_chirho
}

/// Test-only: a step the next registration on this thread runs inside its locked section, after its store is chosen and
/// before its row is written, so a racing opening meets the lock.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub fn set_registration_hold_chirho(hold_chirho: impl FnOnce() -> Result<()> + 'static) {
    REGISTRATION_HOLD_CHIRHO
        .with(|slot_chirho| *slot_chirho.borrow_mut() = Some(Box::new(hold_chirho)));
}

fn run_registration_hold_chirho() -> Result<()> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    if let Some(hold_chirho) =
        REGISTRATION_HOLD_CHIRHO.with(|slot_chirho| slot_chirho.borrow_mut().take())
    {
        return hold_chirho();
    }
    Ok(())
}

/// Test-only: a step the next issuance on this thread runs inside its locked section, after its daily limit (a
/// connection's, K4 Part 3) and its cap are decided and before its key is written, so a racing issuance meets the lock
/// with this one's decision already made.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub fn set_issuance_hold_chirho(hold_chirho: impl FnOnce() -> Result<()> + 'static) {
    ISSUANCE_HOLD_CHIRHO
        .with(|slot_chirho| *slot_chirho.borrow_mut() = Some(Box::new(hold_chirho)));
}

pub(super) fn run_issuance_hold_chirho() -> Result<()> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    if let Some(hold_chirho) =
        ISSUANCE_HOLD_CHIRHO.with(|slot_chirho| slot_chirho.borrow_mut().take())
    {
        return hold_chirho();
    }
    Ok(())
}

/// The connection store's clients, as written. Only a genuine absence is an empty list; a log that cannot be examined
/// refuses, and so does a row of any other schema.
pub fn load_connection_clients_chirho(root_chirho: &Path) -> Result<Vec<OauthClientRecordChirho>> {
    // The same counter as the legacy store's, so an arm that bounds client reads on a road sees both stores.
    #[cfg(test)]
    super::token_view_metrics_chirho::note_client_read_chirho();
    let Some(text_chirho) = read_log_text_chirho(&connection_clients_path_chirho(root_chirho))?
    else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: OauthClientRecordChirho = serde_json::from_str(line_chirho)?;
        require_exact_schema_chirho(
            &record_chirho.schema_chirho,
            CONNECTION_CLIENT_RECORD_SCHEMA_CHIRHO,
            "oauth connection client record",
        )?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

/// The client `client_id_chirho` and the store it lives in. No engine writes one client to both stores, so a client in
/// both refuses rather than choosing one.
pub fn find_client_in_store_chirho(
    root_chirho: &Path,
    client_id_chirho: &str,
) -> Result<Option<(OauthClientRecordChirho, KeyStoreChirho)>> {
    let legacy_chirho = load_clients_chirho(root_chirho)?
        .into_iter()
        .find(|record_chirho| record_chirho.client_id_chirho == client_id_chirho);
    // The connection store through its verified view: O(1) warm, never a scan of its history on a bearer road.
    let connection_chirho = connection_client_view_chirho::connection_client_by_id_chirho(
        root_chirho,
        client_id_chirho,
    )?;
    match (legacy_chirho, connection_chirho) {
        (Some(_), Some(_)) => bail!(
            "ClientInBothStoresChirho: oauth client '{client_id_chirho}' is in both the legacy and the connection store"
        ),
        (Some(record_chirho), None) => Ok(Some((record_chirho, KeyStoreChirho::LegacyChirho))),
        (None, Some(record_chirho)) => Ok(Some((record_chirho, KeyStoreChirho::ConnectionChirho))),
        (None, None) => Ok(None),
    }
}

/// Verify the connection client log: dense sequences from 0, its own schema, an Owner principal, the app's verified
/// owner, the root's signature, and no client id the legacy store also holds. Returns how many clients it holds.
pub fn verify_connection_clients_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_connection_clients_chirho(root_chirho)?;
    let legacy_chirho = load_clients_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "oauth connection client seq gap at index {index_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if legacy_chirho.iter().any(|legacy_record_chirho| {
            legacy_record_chirho.client_id_chirho == record_chirho.client_id_chirho
        }) {
            bail!(
                "ClientInBothStoresChirho: oauth client '{}' is in both the legacy and the connection store",
                record_chirho.client_id_chirho
            );
        }
        app_chirho::ensure_app_owner_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &client_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "oauth connection client {} signature invalid",
                record_chirho.client_id_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

#[cfg(test)]
#[path = "tests_chirho/connection_fixture_chirho.rs"]
mod connection_fixture_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_client_tests_chirho.rs"]
mod connection_client_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_opening_tests_chirho.rs"]
mod connection_opening_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_token_tests_chirho.rs"]
mod connection_token_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_management_tests_chirho.rs"]
mod connection_management_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_growth_tests_chirho.rs"]
mod connection_growth_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_lifetime_tests_chirho.rs"]
mod connection_lifetime_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_issuance_tests_chirho.rs"]
mod connection_issuance_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_daily_limit_tests_chirho.rs"]
mod connection_daily_limit_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_served_tests_chirho.rs"]
mod connection_served_tests_chirho;

#[cfg(test)]
#[path = "tests_chirho/connection_app_selection_tests_chirho.rs"]
mod connection_app_selection_tests_chirho;
