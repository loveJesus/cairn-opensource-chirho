// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The scoped-token use log as an incremental, verified window (brick 4a-2): a bearer request's rate decision reads a
//! few buckets, and its in-lock check verifies only the uses appended since the last call, where it re-verified every
//! token, every session and every use (quadratically) on every request (census row 2; PFE part 7).
//!
//! - **The fold** runs the full verifier's checks for one use, in its order: its seq; its token, from the token view;
//!   that the use matches the token; the token's policy; the use's rate AT ITS OWN TIME against the uses before it
//!   (one count of the use window, where the full verifier replays every earlier use); its signature.
//! - **The decision** is today's `filter().count()`, exactly: see `cairn_auth_attempt_window_chirho::use_window_chirho`.
//! - **The window:** uses are pruned below `high water - ceiling - tolerance`. A step back of the clock beyond the
//!   tolerance rebuilds the index in the background while the current one serves (the sign-in window's rule).
//! - **The door never appends a use it cannot decide exactly.** Unlike the sign-in log, this log's own verifier checks
//!   every record's rate against all the records before it, so a use admitted from pruned history could be one the
//!   verifier refuses for good: every later bearer request would then fail. So after such a step back the door
//!   refuses with `UseWindowCatchingUpChirho` (HTTP 503) for a key whose window reaches below the retained history,
//!   until the rebuilt index swaps in.
//! - **One edge, stated:** a use another writer appended with a window reaching below the retained history (only a
//!   legacy over-ceiling token, which this binary refuses at use, or a skewed second writer) has its rate checked
//!   against the retained uses only when folded incrementally. Every door decides exactly, so such a record is valid
//!   unless written with write access, and the hourly integrity pass, which folds from scratch, checks it exactly.
//! - **The append door** (`decide_and_append_use_chirho`) brings this view current under the append-log lock BEFORE
//!   the seqlog's recovery and refuses unless both counts agree (the S1 and S3 store rule), so the decision and the
//!   record are one act (charter property 2). The clock is read inside the view's lock, so uses are recorded in time
//!   order and a concurrent caller never looks like a step back.
//! - **Locks:** the append-log lock, then this view's slot, then the token view's slot.
//! - **One use log per store (K4).** A connection key's uses go to the connection use log, each naming its key by seq
//!   in the CONNECTION token log, so both stores hold a seq 0 and nothing resolves across them. The door refuses a key
//!   that is not the verified key at its seq in its own store, so a misnamed use never reaches a log. A rate budget
//!   belongs to its key (app, principal, device, window), not to a store: the door counts both stores' uses at one
//!   instant, and each log's own verifier, counting only its own, is then satisfied too.

use super::connection_chirho::parse_connection_token_use_line_chirho;
use super::token_view_chirho::{token_by_seq_chirho, warm_scoped_token_view_chirho};
use super::{
    now_ms_chirho, parse_scoped_token_use_line_chirho, scoped_token_use_matches_rate_key_chirho,
    scoped_token_use_message_chirho, validate_rate_limit_policy_chirho,
    verify_scoped_token_use_matches_chirho, KeyStoreChirho, RateLimitExceededChirho,
    ScopedTokenRateLimitChirho, ScopedTokenRecordChirho, ScopedTokenUseRecordChirho,
    UseWindowCatchingUpChirho, TOKEN_RATE_WINDOW_CEILING_MS_CHIRHO,
};
use crate::seqlog_chirho;
use anyhow::{anyhow, bail, Result};
use cairn_auth_attempt_window_chirho::use_window_chirho::{
    UseRateKeyChirho, UseRecordChirho, UseWindowIndexChirho,
};
use cairn_signer_chirho::signer_chirho;
use cairn_verified_prefix_view_chirho::{
    log_missing_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho, ViewRulesChirho,
};
use std::path::{Path, PathBuf};

/// How far the clock may step back and still decide exactly; a larger step rebuilds the index in the background.
pub(super) const USE_WINDOW_TOLERANCE_MS_CHIRHO: u64 = TOKEN_RATE_WINDOW_CEILING_MS_CHIRHO;
/// History kept behind the latest decision: one ceiling window plus the tolerance.
const USE_WINDOW_HORIZON_MS_CHIRHO: u64 =
    TOKEN_RATE_WINDOW_CEILING_MS_CHIRHO + USE_WINDOW_TOLERANCE_MS_CHIRHO;
const USE_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const USE_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const USE_SLOT_CAP_CHIRHO: usize = 8192;

static USE_REGISTRY_CHIRHO: RegistryChirho<UseWindowIndexChirho> = RegistryChirho::new_chirho();
static CONNECTION_USE_REGISTRY_CHIRHO: RegistryChirho<UseWindowIndexChirho> =
    RegistryChirho::new_chirho();

fn use_registry_for_store_chirho(
    store_chirho: KeyStoreChirho,
) -> &'static RegistryChirho<UseWindowIndexChirho> {
    match store_chirho {
        KeyStoreChirho::LegacyChirho => &USE_REGISTRY_CHIRHO,
        KeyStoreChirho::ConnectionChirho => &CONNECTION_USE_REGISTRY_CHIRHO,
    }
}

fn use_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: USE_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: USE_SLOT_CAP_CHIRHO,
    }
}

impl UseRecordChirho for ScopedTokenUseRecordChirho {
    fn app_chirho(&self) -> &str {
        &self.app_chirho
    }
    fn principal_chirho(&self) -> &str {
        &self.principal_chirho
    }
    fn device_chirho(&self) -> Option<&str> {
        self.device_id_chirho.as_deref()
    }
    fn at_ms_chirho(&self) -> u64 {
        self.at_ms_chirho
    }
}

/// The rate key a token's policy decides by, as the full verifier's predicate reads it: the TOKEN's app and
/// principal, and its policy's device and window.
fn rate_key_chirho<'key_chirho>(
    token_chirho: &'key_chirho ScopedTokenRecordChirho,
    rate_limit_chirho: &'key_chirho ScopedTokenRateLimitChirho,
) -> UseRateKeyChirho<'key_chirho> {
    UseRateKeyChirho {
        app_chirho: &token_chirho.app_chirho,
        principal_chirho: &token_chirho.principal_chirho,
        device_chirho: rate_limit_chirho.device_id_chirho.as_deref(),
        window_ms_chirho: rate_limit_chirho.window_ms_chirho,
    }
}

struct UseLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
    pubkey_chirho: String,
    verifier_id_chirho: String,
    store_chirho: KeyStoreChirho,
}

impl UseLogChirho {
    fn new_chirho(root_chirho: &Path, pubkey_chirho: String, store_chirho: KeyStoreChirho) -> Self {
        let verifier_id_chirho = match store_chirho {
            KeyStoreChirho::LegacyChirho => format!("scoped-token-uses-v1-chirho:{pubkey_chirho}"),
            KeyStoreChirho::ConnectionChirho => {
                format!("connection-token-uses-v1-chirho:{pubkey_chirho}")
            }
        };
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: store_chirho.uses_path_chirho(root_chirho),
            verifier_id_chirho,
            pubkey_chirho,
            store_chirho,
        }
    }
}

impl PrefixLogChirho for UseLogChirho {
    type RecordChirho = ScopedTokenUseRecordChirho;
    type IndexChirho = UseWindowIndexChirho;
    type JobLogChirho = UseLogChirho;

    fn job_log_chirho(&self) -> UseLogChirho {
        UseLogChirho::new_chirho(
            &self.root_chirho,
            self.pubkey_chirho.clone(),
            self.store_chirho,
        )
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_id_chirho
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<UseWindowIndexChirho> {
        use_registry_for_store_chirho(self.store_chirho)
    }

    /// The store's loader's parse, which refuses any other store's schema.
    fn parse_chirho(&self, line_chirho: &str) -> Result<ScopedTokenUseRecordChirho> {
        match self.store_chirho {
            KeyStoreChirho::LegacyChirho => parse_scoped_token_use_line_chirho(line_chirho),
            KeyStoreChirho::ConnectionChirho => parse_connection_token_use_line_chirho(line_chirho),
        }
    }

    /// The full verifier's checks for one use, in its order, with the rate counted from the use window.
    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut UseWindowIndexChirho,
        record_chirho: ScopedTokenUseRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        if record_chirho.seq_chirho != expected_seq_chirho {
            bail!(
                "scoped token use seq gap at index {expected_seq_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        let token_chirho = token_by_seq_chirho(
            &self.root_chirho,
            &self.pubkey_chirho,
            self.store_chirho,
            record_chirho.scoped_token_seq_chirho,
        )?
        .ok_or_else(|| {
            anyhow!(
                "scoped token use {} references missing token {}",
                record_chirho.seq_chirho,
                record_chirho.scoped_token_seq_chirho
            )
        })?;
        verify_scoped_token_use_matches_chirho(&record_chirho, &token_chirho)?;
        let rate_limit_chirho = token_chirho.rate_limit_chirho.as_ref().ok_or_else(|| {
            anyhow!(
                "scoped token use {} references an unlimited token",
                record_chirho.seq_chirho
            )
        })?;
        validate_rate_limit_policy_chirho(rate_limit_chirho)?;
        if index_chirho.count_chirho(
            &rate_key_chirho(&token_chirho, rate_limit_chirho),
            record_chirho.at_ms_chirho,
        ) >= rate_limit_chirho.max_invokes_chirho
        {
            bail!(
                "scoped token use {} exceeds rate limit for '{}' on app '{}'",
                record_chirho.seq_chirho,
                record_chirho.principal_chirho,
                record_chirho.app_chirho
            );
        }
        let message_chirho = scoped_token_use_message_chirho(&record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &self.pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "scoped token use {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        index_chirho.fold_chirho(&record_chirho);
        #[cfg(test)]
        super::token_view_metrics_chirho::note_use_fold_chirho();
        Ok(())
    }

    fn needs_rebuild_chirho(
        &self,
        index_chirho: &UseWindowIndexChirho,
        now_ms_chirho: u64,
    ) -> bool {
        index_chirho.needs_rebuild_chirho(now_ms_chirho, USE_WINDOW_TOLERANCE_MS_CHIRHO)
    }

    fn after_update_chirho(&self, index_chirho: &mut UseWindowIndexChirho, now_ms_chirho: u64) {
        index_chirho.advance_chirho(now_ms_chirho, USE_WINDOW_HORIZON_MS_CHIRHO);
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        match self.store_chirho {
            KeyStoreChirho::LegacyChirho => "cairn-scoped-token-use-view-job-chirho",
            KeyStoreChirho::ConnectionChirho => "cairn-connection-token-use-view-job-chirho",
        }
    }
}

/// THE APPEND DOOR: decide a token's rate and record the use, as one act under the append-log lock. The view is
/// brought current first (verifying only new uses), refusing on a complete bad line still in the log; then the
/// seqlog's recovery may repair a torn tail, and the two counts must agree. `clock_chirho` is read inside the view's
/// lock and stamps the record.
/// Workflow: the bearer-road DAG, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4a-2a, as built).
pub(super) fn decide_and_append_use_chirho(
    root_chirho: &Path,
    token_chirho: &ScopedTokenRecordChirho,
    rate_limit_chirho: &ScopedTokenRateLimitChirho,
    clock_chirho: impl FnOnce() -> u64,
) -> Result<ScopedTokenUseRecordChirho> {
    // K4: a key's uses go to its OWN store's use log, where its seq names it.
    let store_chirho = KeyStoreChirho::of_token_chirho(token_chirho);
    let path_chirho = store_chirho.uses_path_chirho(root_chirho);
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
        // The use names its key by seq within its store, so the key must be the verified key at that seq there. A key
        // that is not refuses here, before any row, rather than poisoning the log's view for every later request.
        if token_by_seq_chirho(
            root_chirho,
            &pubkey_chirho,
            store_chirho,
            token_chirho.seq_chirho,
        )?
        .as_ref()
            != Some(token_chirho)
        {
            bail!(
                "UseNamesAnotherKeyChirho: the key is not the verified key at its seq in its own store; no use is \
                 recorded"
            );
        }
        let key_chirho = rate_key_chirho(token_chirho, rate_limit_chirho);
        let ((own_chirho, now_ms_chirho), status_chirho) = with_current_view_chirho(
            &UseLogChirho::new_chirho(root_chirho, pubkey_chirho.clone(), store_chirho),
            &use_view_rules_chirho(),
            clock_chirho,
            |index_chirho, now_ms_chirho| {
                (
                    exact_count_now_chirho(index_chirho, &key_chirho, now_ms_chirho),
                    now_ms_chirho,
                )
            },
        )?;
        // The budget belongs to the rate key, not to a store: the other store's uses count too, at the same instant.
        let other_chirho = other_store_count_chirho(
            root_chirho,
            &pubkey_chirho,
            store_chirho.other_chirho(),
            &key_chirho,
            now_ms_chirho,
        )?;
        let seq_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        if seq_chirho != status_chirho.verified_records_chirho {
            bail!(
                "scoped-token use log holds {seq_chirho} records by recovery but {} verified records; refusing to \
                 append",
                status_chirho.verified_records_chirho
            );
        }
        if now_ms_chirho < token_chirho.issued_ms_chirho
            || now_ms_chirho > token_chirho.expires_ms_chirho
        {
            bail!("cannot record use for scoped token outside its lifetime");
        }
        let (Some(own_chirho), Some(other_chirho)) = (own_chirho, other_chirho) else {
            return Err(UseWindowCatchingUpChirho.into());
        };
        if own_chirho + other_chirho >= rate_limit_chirho.max_invokes_chirho {
            return Err(RateLimitExceededChirho {
                principal_chirho: token_chirho.principal_chirho.clone(),
                app_chirho: token_chirho.app_chirho.clone(),
                device_id_chirho: rate_limit_chirho.device_id_chirho.clone(),
                window_ms_chirho: rate_limit_chirho.window_ms_chirho,
                max_invokes_chirho: rate_limit_chirho.max_invokes_chirho,
            }
            .into());
        }
        let mut record_chirho = ScopedTokenUseRecordChirho {
            seq_chirho,
            schema_chirho: store_chirho.use_schema_chirho().to_string(),
            scoped_token_seq_chirho: token_chirho.seq_chirho,
            principal_chirho: token_chirho.principal_chirho.clone(),
            client_id_chirho: token_chirho.client_id_chirho.clone(),
            app_chirho: token_chirho.app_chirho.clone(),
            token_hash_chirho: token_chirho.token_hash_chirho.clone(),
            device_id_chirho: rate_limit_chirho.device_id_chirho.clone(),
            window_ms_chirho: rate_limit_chirho.window_ms_chirho,
            max_invokes_chirho: rate_limit_chirho.max_invokes_chirho,
            at_ms_chirho: now_ms_chirho,
            sig_chirho: String::new(),
        };
        let message_chirho = scoped_token_use_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

/// A store's exact count under `key_chirho` at `now_ms_chirho`: 0 for no log, `None` while its window catches up.
fn exact_count_now_chirho(
    index_chirho: Option<&UseWindowIndexChirho>,
    key_chirho: &UseRateKeyChirho<'_>,
    now_ms_chirho: u64,
) -> Option<u64> {
    match index_chirho {
        None => Some(0),
        Some(index_chirho) => index_chirho.exact_count_chirho(key_chirho, now_ms_chirho),
    }
}

/// The other store's uses under `key_chirho` at the door's instant, from its own verified view. Its log is only read:
/// the door appends to its own store's log alone.
fn other_store_count_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    store_chirho: KeyStoreChirho,
    key_chirho: &UseRateKeyChirho<'_>,
    now_ms_chirho: u64,
) -> Result<Option<u64>> {
    if log_missing_chirho(
        use_registry_for_store_chirho(store_chirho),
        &store_chirho.uses_path_chirho(root_chirho),
    )? {
        return Ok(Some(0));
    }
    let (count_chirho, _status_chirho) = with_current_view_chirho(
        &UseLogChirho::new_chirho(root_chirho, pubkey_chirho.to_string(), store_chirho),
        &use_view_rules_chirho(),
        || now_ms_chirho,
        |index_chirho, now_ms_chirho| {
            exact_count_now_chirho(index_chirho, key_chirho, now_ms_chirho)
        },
    )?;
    Ok(count_chirho)
}

/// Verify a use log against ITS OWN store's token log (K4: each store's uses name keys by that store's seq): dense
/// sequences from 0, each use's key and policy, its rate at its own time against the uses before it in this log, and
/// the root's signature. Returns how many uses it holds. The full verifiers of both stores share it.
pub(super) fn verify_uses_in_namespace_chirho(
    pubkey_chirho: &str,
    tokens_chirho: &[ScopedTokenRecordChirho],
    records_chirho: &[ScopedTokenUseRecordChirho],
) -> Result<usize> {
    let mut previous_chirho: Vec<&ScopedTokenUseRecordChirho> = Vec::new();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "scoped token use seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        let token_chirho = tokens_chirho
            .get(record_chirho.scoped_token_seq_chirho as usize)
            .ok_or_else(|| {
                anyhow!(
                    "scoped token use {} references missing token {}",
                    record_chirho.seq_chirho,
                    record_chirho.scoped_token_seq_chirho
                )
            })?;
        verify_scoped_token_use_matches_chirho(record_chirho, token_chirho)?;
        let rate_limit_chirho = token_chirho.rate_limit_chirho.as_ref().ok_or_else(|| {
            anyhow!(
                "scoped token use {} references an unlimited token",
                record_chirho.seq_chirho
            )
        })?;
        validate_rate_limit_policy_chirho(rate_limit_chirho)?;
        if previous_chirho
            .iter()
            .filter(|prior_chirho| {
                scoped_token_use_matches_rate_key_chirho(
                    prior_chirho,
                    token_chirho,
                    rate_limit_chirho,
                    record_chirho.at_ms_chirho,
                )
            })
            .count() as u64
            >= rate_limit_chirho.max_invokes_chirho
        {
            bail!(
                "scoped token use {} exceeds rate limit for '{}' on app '{}'",
                record_chirho.seq_chirho,
                record_chirho.principal_chirho,
                record_chirho.app_chirho
            );
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &scoped_token_use_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "scoped token use {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        previous_chirho.push(record_chirho);
    }
    Ok(records_chirho.len())
}

/// Build the root's token and use views now, so the first bearer requests find them ready.
pub fn warm_scoped_token_views_chirho(root_chirho: &Path) -> Result<()> {
    warm_scoped_token_view_chirho(root_chirho)?;
    for store_chirho in KeyStoreChirho::ALL_CHIRHO {
        if log_missing_chirho(
            use_registry_for_store_chirho(store_chirho),
            &store_chirho.uses_path_chirho(root_chirho),
        )? {
            continue;
        }
        with_current_view_chirho(
            &UseLogChirho::new_chirho(
                root_chirho,
                signer_chirho::pubkey_hex_chirho(root_chirho)?,
                store_chirho,
            ),
            &use_view_rules_chirho(),
            now_ms_chirho,
            |_index_chirho, _now_ms_chirho| (),
        )?;
    }
    Ok(())
}

/// Warm the root's token and use views on their own thread: the serve runtime calls this after it binds, as it warms
/// the S1 and S3 views. A failure is not fatal: bearer requests refuse on their own until the logs verify. The line
/// it prints names no token, principal or path.
/// Workflow: the bearer-road DAG, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4a-2a, as built).
pub fn spawn_scoped_token_views_warm_up_chirho(root_chirho: &Path) {
    let root_chirho = root_chirho.to_path_buf();
    let spawned_chirho = std::thread::Builder::new()
        .name("cairn-scoped-token-views-warm-chirho".to_string())
        .spawn(move || {
            if warm_scoped_token_views_chirho(&root_chirho).is_err() {
                eprintln!(
                    "cairn-chirho: the scoped-token logs did not verify at startup; bearer requests refuse until \
                     they do (oauth-verify shows why)"
                );
            }
        });
    if spawned_chirho.is_err() {
        eprintln!(
            "cairn-chirho: the scoped-token views' warm-up did not start; the first bearer request builds them"
        );
    }
}
