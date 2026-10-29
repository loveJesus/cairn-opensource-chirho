// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! An app's signed opening of named routes to limited keys, kept in its own dense root-signed log and read through an
//! incremental verified view, so a key request finds its app's latest record in memory.
//!
//! - **Its own log, never the route record.** Engines before limited keys verify a route record's signature over the
//!   fields they know and refuse the whole route log on the first mismatch, so a new signed route field would take every
//!   app down on a rollback. They never open this file, so a rollback leaves every route serving as it did.
//! - **The latest record per app is authoritative, and limited mode is sticky.** Any record for an app puts it in
//!   limited-key mode: legacy keys are refused on every entry. A later record that opens nothing keeps it limited; no
//!   record ever returns an app to legacy keys.
//! - **Each opening names the exact DAG it was reviewed with.** A route whose current DAG is another one is closed to
//!   keys until a reviewed deploy opens it again.
//! - **Cost:** a key request reads one app's latest record from the view, O(1) warm. An append by any app is folded once:
//!   the view verifies only the records appended since its last call (the verified-prefix contract), so another app's
//!   redeploys add their own records' verification once, never a re-verification of the history per request.
//!
//! Workflow: limited-key authority (K1),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.

use super::{
    ensure_app_owner_chirho, load_counted_serialized_jsonl_chirho, now_ms_chirho,
    validate_app_name_chirho, validate_route_name_chirho, verify_record_sig_chirho,
    AppKeyAuthorityRecordChirho, AppKeyAuthorityRouteChirho, DagChirho,
    APP_KEY_AUTHORITY_RECORD_SCHEMA_CHIRHO,
};
use crate::{seqlog_chirho, store_chirho};
use anyhow::{bail, Result};
use cairn_model_app_chirho::{
    app_key_authority_record_signed_message_chirho, validate_key_action_name_chirho,
};
use cairn_signer_chirho::signer_chirho;
use cairn_verified_prefix_view_chirho::{
    log_missing_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho, ViewRulesChirho,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The log's path under the root.
pub fn app_key_authority_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-key-authority-chirho.jsonl")
}

/// The verified log, folded: each app's latest record.
#[derive(Default)]
pub(crate) struct KeyAuthorityIndexChirho {
    latest_by_app_chirho: HashMap<String, AppKeyAuthorityRecordChirho>,
}

static KEY_AUTHORITY_REGISTRY_CHIRHO: RegistryChirho<KeyAuthorityIndexChirho> =
    RegistryChirho::new_chirho();

#[cfg(test)]
thread_local! {
    /// Records this thread's calls folded, for the growth arm: a warm read folds none, an append is folded once.
    static KEY_AUTHORITY_FOLDS_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many key-authority records this thread has folded so far.
#[cfg(test)]
pub(crate) fn key_authority_folds_chirho() -> u64 {
    KEY_AUTHORITY_FOLDS_CHIRHO.with(std::cell::Cell::get)
}

const KEY_AUTHORITY_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const KEY_AUTHORITY_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const KEY_AUTHORITY_SLOT_CAP_CHIRHO: usize = 8192;

fn key_authority_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: KEY_AUTHORITY_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: KEY_AUTHORITY_SLOT_CAP_CHIRHO,
    }
}

struct KeyAuthorityLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
    pubkey_chirho: String,
    verifier_id_chirho: String,
}

impl KeyAuthorityLogChirho {
    fn new_chirho(root_chirho: &Path, pubkey_chirho: &str) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: app_key_authority_records_path_chirho(root_chirho),
            verifier_id_chirho: format!("app-key-authority-v1-chirho:{pubkey_chirho}"),
            pubkey_chirho: pubkey_chirho.to_string(),
        }
    }
}

impl PrefixLogChirho for KeyAuthorityLogChirho {
    type RecordChirho = AppKeyAuthorityRecordChirho;
    type IndexChirho = KeyAuthorityIndexChirho;
    type JobLogChirho = KeyAuthorityLogChirho;

    fn job_log_chirho(&self) -> KeyAuthorityLogChirho {
        KeyAuthorityLogChirho::new_chirho(&self.root_chirho, &self.pubkey_chirho)
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The fold verifies signatures, so the id names the key: a changed key verifies every record again.
    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_id_chirho
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<KeyAuthorityIndexChirho> {
        &KEY_AUTHORITY_REGISTRY_CHIRHO
    }

    fn parse_chirho(&self, line_chirho: &str) -> Result<AppKeyAuthorityRecordChirho> {
        Ok(serde_json::from_str(line_chirho)?)
    }

    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut KeyAuthorityIndexChirho,
        record_chirho: AppKeyAuthorityRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        #[cfg(test)]
        KEY_AUTHORITY_FOLDS_CHIRHO.with(|folds_chirho| folds_chirho.set(folds_chirho.get() + 1));
        if record_chirho.seq_chirho != expected_seq_chirho {
            bail!(
                "app key-authority seq gap at index {expected_seq_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho != APP_KEY_AUTHORITY_RECORD_SCHEMA_CHIRHO {
            bail!(
                "app key-authority record {} has an unknown schema",
                record_chirho.seq_chirho
            );
        }
        validate_opened_routes_chirho(&self.root_chirho, &record_chirho.routes_chirho)?;
        // The app's owner was checked when the record was appended, and the signature proves this engine appended it.
        // The fold reads no other log, so the view never depends on the app records and costs O(1) per record.
        let message_chirho = app_key_authority_record_signed_message_chirho(&record_chirho)?;
        if !verify_record_sig_chirho(
            &self.pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "app key-authority record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        index_chirho
            .latest_by_app_chirho
            .insert(record_chirho.app_chirho.clone(), record_chirho);
        Ok(())
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-app-key-authority-view-job-chirho"
    }
}

/// A record's routes: named validly, strictly sorted by route (so each route once), each action a valid action name,
/// each resource list strictly sorted, and each DAG present in the store. Shared by the append and the fold.
fn validate_opened_routes_chirho(
    root_chirho: &Path,
    routes_chirho: &[AppKeyAuthorityRouteChirho],
) -> Result<()> {
    for (i_chirho, route_chirho) in routes_chirho.iter().enumerate() {
        validate_route_name_chirho(&route_chirho.route_chirho)?;
        validate_key_action_name_chirho(&route_chirho.action_chirho)?;
        if i_chirho > 0 && routes_chirho[i_chirho - 1].route_chirho >= route_chirho.route_chirho {
            bail!("app key-authority routes must be strictly sorted by route");
        }
        if route_chirho
            .resources_chirho
            .windows(2)
            .any(|pair_chirho| pair_chirho[0] >= pair_chirho[1])
        {
            bail!(
                "the route '{}' must list its resources strictly sorted",
                route_chirho.route_chirho
            );
        }
        let _dag_chirho: DagChirho =
            store_chirho::get_object_chirho(root_chirho, &route_chirho.dag_chirho)?;
    }
    Ok(())
}

/// Append `app_chirho`'s whole key authority at this deploy. The caller has checked each route's eligibility; this
/// checks the record's own shape and the app's owner, then signs and appends under the root-wide append lock.
pub fn append_app_key_authority_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    routes_chirho: Vec<AppKeyAuthorityRouteChirho>,
) -> Result<AppKeyAuthorityRecordChirho> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        append_app_key_authority_record_under_append_lock_chirho(
            root_chirho,
            app_chirho,
            owner_principal_chirho,
            routes_chirho,
        )
    })
}

/// The same append for a caller that already holds the root-wide append lock: the opt-in retires the app's legacy
/// keys and records its opening in one locked section, so no legacy key can land between them.
pub fn append_app_key_authority_record_under_append_lock_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    routes_chirho: Vec<AppKeyAuthorityRouteChirho>,
) -> Result<AppKeyAuthorityRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    validate_opened_routes_chirho(root_chirho, &routes_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let path_chirho = app_key_authority_records_path_chirho(root_chirho);
    // An existing log must be a regular file before anything is appended to it, and a log seen present must still be
    // there: a vanished log is never restarted from its first record.
    log_missing_chirho(&KEY_AUTHORITY_REGISTRY_CHIRHO, &path_chirho)?;
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = AppKeyAuthorityRecordChirho {
            seq_chirho,
            schema_chirho: APP_KEY_AUTHORITY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            routes_chirho: routes_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = app_key_authority_record_signed_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

/// Every record in the log, in order and unverified: the compliance pack's read, which it verifies with
/// `verify_app_key_authority_records_chirho`. Only a log that is truly absent reads as empty.
pub fn load_app_key_authority_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppKeyAuthorityRecordChirho>> {
    let path_chirho = app_key_authority_records_path_chirho(root_chirho);
    if log_missing_chirho(&KEY_AUTHORITY_REGISTRY_CHIRHO, &path_chirho)? {
        return Ok(Vec::new());
    }
    load_counted_serialized_jsonl_chirho(&path_chirho)
}

/// The whole log verified from its first record by the same fold the view runs: the compliance pack's verifier. Returns
/// how many records verified. An empty log verifies without reading the root's key.
pub fn verify_app_key_authority_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_key_authority_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let log_chirho = KeyAuthorityLogChirho::new_chirho(root_chirho, &pubkey_chirho);
    let mut index_chirho = KeyAuthorityIndexChirho::default();
    let count_chirho = records_chirho.len();
    for (seq_chirho, record_chirho) in records_chirho.into_iter().enumerate() {
        log_chirho.verify_and_fold_chirho(&mut index_chirho, record_chirho, seq_chirho as u64)?;
    }
    Ok(count_chirho)
}

/// The app's latest verified key-authority record, or `None` when the app has never opened a route to limited keys
/// (legacy mode). A log that fails verification, or that cannot be examined or is not a regular file, is an error,
/// never `None`: an app whose mode cannot be known is not assumed to be in legacy mode.
pub fn app_key_authority_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<AppKeyAuthorityRecordChirho>> {
    if log_missing_chirho(
        &KEY_AUTHORITY_REGISTRY_CHIRHO,
        &app_key_authority_records_path_chirho(root_chirho),
    )? {
        return Ok(None);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let (record_chirho, _status_chirho) = with_current_view_chirho(
        &KeyAuthorityLogChirho::new_chirho(root_chirho, &pubkey_chirho),
        &key_authority_view_rules_chirho(),
        now_ms_chirho,
        |index_chirho, _now_ms_chirho| {
            index_chirho
                .and_then(|index_chirho| index_chirho.latest_by_app_chirho.get(app_chirho).cloned())
        },
    )?;
    Ok(record_chirho)
}
