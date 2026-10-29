// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Keeps an incremental, verified, in-process view of an append-only auth-attempt log, so a rate-limit decision
//! verifies only the records appended since the last call instead of the whole history.
//!
//! Contract (spec-chirho/tasklists-chirho/26-10-01_16-40-tasklist-signin_cost_engine_fix-chirho.md, bricks 2 and 2b;
//! reviewed by agy #25624/#25640, claude2 #25625-#25641 and PFE #1257; measured against the bounded-auth-history
//! charter, spec-chirho/workflows-chirho/identity-auth-chirho/bounded-auth-history-chirho.md). The generic half (the
//! verified prefix, the write-access fallbacks, the integrity pass, the slots and locks) lives in
//! `cairn-verified-prefix-view-chirho`, extracted from here unchanged; the window half lives here:
//! - **Today's decision, exactly, while the clock is at most `regression_tolerance` behind the latest time this
//!   view has decided at.** A key's failures count when `at_ms >= now - window` and they come after the key's
//!   latest success. The view keeps each key's failures SINCE its last success, folded in file order from verified
//!   bytes only, and prunes at `now - window - tolerance`, so a step back of up to the tolerance needs no scan.
//! - **A step back further than that** starts a background INDEX REBUILD. Until it swaps in, the index keeps
//!   serving: new failures always count, and failures pruned before the step may go uncounted for the rebuild's
//!   duration (claude2 #25639: briefly permissive beats a sign-in outage for a clock glitch).
//! - **The hourly INTEGRITY PASS** re-verifies the verified prefix in the background; a failure drops the view.
//! - **The clock is read inside the root's lock,** so calls are ordered by time and a concurrent caller never looks
//!   like a step back.
//! - **Threat boundary:** an in-place edit of an already verified record that keeps the anchor line, and either
//!   grows the file or keeps its length and timestamps, is not DETECTED until the next integrity pass (due hourly,
//!   started by the next call after that); decisions meanwhile still use the verified original. Such an edit needs
//!   write access to the log, and with write access deleting the log is cheaper and already accepted.
//! - **Successes** (brick 4a, the sign-in velocity limit): each (principal hash, endpoint) key's successes inside a
//!   separate success window, never discounted, summed by the caller over the endpoints that create a session.
//!   Only a valid credential makes a success, so a flood of guesses cannot grow that map.
//! - **Not bounded here:** disk growth (records retire in brick 3).
//!
//! Workflow: the sign-in check DAG in `spec-chirho/workflows-chirho/identity-auth-chirho/bounded-auth-history-chirho.md`.

use anyhow::Result;
use cairn_verified_prefix_view_chirho::{
    with_current_view_chirho, PrefixLogChirho, RegistryChirho, UpdateStatusChirho, ViewRulesChirho,
};
use std::borrow::Borrow;
use std::marker::PhantomData;
use std::path::Path;

mod index_chirho;
use index_chirho::AuthIndexChirho;
/// The use window (brick 4a-2): scoped-token uses counted by rate key, never discounted, for the bearer rate limit.
pub mod use_window_chirho;

#[cfg(test)]
pub use cairn_verified_prefix_view_chirho::{
    hold_background_jobs_before_open_chirho, hold_background_jobs_chirho,
    join_background_job_chirho, JobHoldChirho,
};
pub use cairn_verified_prefix_view_chirho::{
    BackgroundJobChirho, BackgroundOutcomeChirho, FallbackCauseChirho, PathTakenChirho,
};

/// What the view needs from one verified record.
pub trait AttemptRecordChirho {
    fn principal_hash_chirho(&self) -> &str;
    fn endpoint_chirho(&self) -> &str;
    fn is_success_chirho(&self) -> bool;
    fn at_ms_chirho(&self) -> u64;
}

/// One append-only attempt log: where it lives, how a line parses, and how one record verifies. The parser and
/// verifier must be the same functions the log's full verification uses. Background jobs run on a clone.
pub trait AttemptLogChirho: Clone + Send + 'static {
    type RecordChirho: AttemptRecordChirho;
    fn path_chirho(&self) -> &Path;
    /// Names the verification key. When it changes, every record is verified again.
    fn verifier_id_chirho(&self) -> &str;
    /// Parse one non-blank line, without its line ending.
    fn parse_chirho(&self, line_chirho: &str) -> Result<Self::RecordChirho>;
    /// Verify a parsed record as the log's `expected_seq_chirho`-th record (0-based): its sequence number, its
    /// fields and its signature.
    fn verify_chirho(
        &self,
        record_chirho: &Self::RecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()>;
}

/// The window rule, how far the clock may step back and still decide exactly, and how often the whole log is
/// re-verified. Memory holds the keys failing within `window + regression_tolerance`, which a rotating-names flood
/// fills, so the tolerance stays at the window (claude2 #25639).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowRulesChirho {
    pub window_ms_chirho: u64,
    pub regression_tolerance_ms_chirho: u64,
    pub full_verify_every_ms_chirho: u64,
    /// Successes count when `at_ms >= now - success_window`, and are never discounted (the sign-in velocity limit,
    /// brick 4a). Pruned at `now - success_window - tolerance`, so a step back within the tolerance stays exact.
    pub success_window_ms_chirho: u64,
}

/// The view after a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewStatusChirho {
    pub verified_records_chirho: u64,
    /// Keys with a failure still retained: the view's memory, bounded by recent activity.
    pub tracked_keys_chirho: usize,
    pub path_chirho: PathTakenChirho,
    pub started_chirho: Option<BackgroundJobChirho>,
}

/// A key's failure count for the rate-limit decision, and the view status that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowDecisionChirho {
    pub recent_failures_chirho: u64,
    pub status_chirho: ViewStatusChirho,
}

/// A key's failures and a principal's successes, both for one rate-limit decision, and the view status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptCountsChirho {
    pub recent_failures_chirho: u64,
    pub recent_successes_chirho: u64,
    pub status_chirho: ViewStatusChirho,
}

/// The failures of one (principal hash, endpoint) key that count at the clock's `now`.
pub fn recent_failures_chirho<L: AttemptLogChirho>(
    log_chirho: &L,
    rules_chirho: &WindowRulesChirho,
    principal_hash_chirho: &str,
    endpoint_chirho: &str,
    clock_chirho: impl FnOnce() -> u64,
) -> Result<WindowDecisionChirho> {
    let counts_chirho = recent_attempts_chirho(
        log_chirho,
        rules_chirho,
        principal_hash_chirho,
        endpoint_chirho,
        &[],
        clock_chirho,
    )?;
    Ok(WindowDecisionChirho {
        recent_failures_chirho: counts_chirho.recent_failures_chirho,
        status_chirho: counts_chirho.status_chirho,
    })
}

/// One view update, two counts: the (principal hash, endpoint) key's failures in the failure window after its last
/// success, and the principal's successes in the success window summed over `success_endpoints_chirho`.
pub fn recent_attempts_chirho<L: AttemptLogChirho>(
    log_chirho: &L,
    rules_chirho: &WindowRulesChirho,
    principal_hash_chirho: &str,
    endpoint_chirho: &str,
    success_endpoints_chirho: &[&str],
    clock_chirho: impl FnOnce() -> u64,
) -> Result<AttemptCountsChirho> {
    let ((recent_failures_chirho, recent_successes_chirho, tracked_keys_chirho), update_chirho) =
        with_current_view_chirho(
            &AuthWindowLogChirho::borrowed_chirho(log_chirho, rules_chirho),
            &view_rules_chirho(rules_chirho),
            clock_chirho,
            |index_chirho, now_ms_chirho| {
                let failure_start_chirho =
                    now_ms_chirho.saturating_sub(rules_chirho.window_ms_chirho);
                let success_start_chirho =
                    now_ms_chirho.saturating_sub(rules_chirho.success_window_ms_chirho);
                index_chirho.map_or((0, 0, 0), |index_chirho| {
                    (
                        index_chirho.recent_failures_chirho(
                            principal_hash_chirho,
                            endpoint_chirho,
                            failure_start_chirho,
                        ),
                        index_chirho.recent_successes_chirho(
                            principal_hash_chirho,
                            success_endpoints_chirho,
                            success_start_chirho,
                        ),
                        index_chirho.tracked_keys_chirho(),
                    )
                })
            },
        )?;
    Ok(AttemptCountsChirho {
        recent_failures_chirho,
        recent_successes_chirho,
        status_chirho: view_status_chirho(update_chirho, tracked_keys_chirho),
    })
}

/// Bring the view up to date, verifying only what was appended where possible. The append path calls this inside
/// its file lock, where today's code verified the whole log; the serve runtime calls it at startup to warm the view.
pub fn verify_current_chirho<L: AttemptLogChirho>(
    log_chirho: &L,
    rules_chirho: &WindowRulesChirho,
    clock_chirho: impl FnOnce() -> u64,
) -> Result<ViewStatusChirho> {
    let (tracked_keys_chirho, update_chirho) = with_current_view_chirho(
        &AuthWindowLogChirho::borrowed_chirho(log_chirho, rules_chirho),
        &view_rules_chirho(rules_chirho),
        clock_chirho,
        |index_chirho, _now_ms_chirho| index_chirho.map_or(0, AuthIndexChirho::tracked_keys_chirho),
    )?;
    Ok(view_status_chirho(update_chirho, tracked_keys_chirho))
}

fn view_status_chirho(
    update_chirho: UpdateStatusChirho,
    tracked_keys_chirho: usize,
) -> ViewStatusChirho {
    ViewStatusChirho {
        verified_records_chirho: update_chirho.verified_records_chirho,
        tracked_keys_chirho,
        path_chirho: update_chirho.path_chirho,
        started_chirho: update_chirho.started_chirho,
    }
}

/// Enough for every root one process serves; eviction only costs the evicted root one full verification.
#[cfg(not(any(test, feature = "test-hooks-chirho")))]
const SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other, so path assertions
// stay deterministic. Eviction itself is tested directly in cairn-verified-prefix-view-chirho.
#[cfg(any(test, feature = "test-hooks-chirho"))]
const SLOT_CAP_CHIRHO: usize = 8192;

fn view_rules_chirho(rules_chirho: &WindowRulesChirho) -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: rules_chirho.full_verify_every_ms_chirho,
        slot_cap_chirho: SLOT_CAP_CHIRHO,
    }
}

/// The auth-attempt views, one slot per root log.
static AUTH_REGISTRY_CHIRHO: RegistryChirho<AuthIndexChirho> = RegistryChirho::new_chirho();

/// An attempt log plus its window rules, as the engine's log type. A call holds the caller's own log (`&L`), so
/// the request's verification runs on the caller's instance; a background job holds an owned clone (`L`).
struct AuthWindowLogChirho<H, L> {
    log_chirho: H,
    rules_chirho: WindowRulesChirho,
    log_type_chirho: PhantomData<fn() -> L>,
}

impl<'a, L: AttemptLogChirho> AuthWindowLogChirho<&'a L, L> {
    fn borrowed_chirho(log_chirho: &'a L, rules_chirho: &WindowRulesChirho) -> Self {
        Self {
            log_chirho,
            rules_chirho: *rules_chirho,
            log_type_chirho: PhantomData,
        }
    }
}

impl<H: Borrow<L>, L: AttemptLogChirho> PrefixLogChirho for AuthWindowLogChirho<H, L> {
    type RecordChirho = L::RecordChirho;
    type IndexChirho = AuthIndexChirho;
    type JobLogChirho = AuthWindowLogChirho<L, L>;

    fn job_log_chirho(&self) -> AuthWindowLogChirho<L, L> {
        AuthWindowLogChirho {
            log_chirho: self.log_chirho.borrow().clone(),
            rules_chirho: self.rules_chirho,
            log_type_chirho: PhantomData,
        }
    }

    fn path_chirho(&self) -> &Path {
        self.log_chirho.borrow().path_chirho()
    }

    fn verifier_id_chirho(&self) -> &str {
        self.log_chirho.borrow().verifier_id_chirho()
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<AuthIndexChirho> {
        &AUTH_REGISTRY_CHIRHO
    }

    fn parse_chirho(&self, line_chirho: &str) -> Result<Self::RecordChirho> {
        self.log_chirho.borrow().parse_chirho(line_chirho)
    }

    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut AuthIndexChirho,
        record_chirho: Self::RecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        self.log_chirho
            .borrow()
            .verify_chirho(&record_chirho, expected_seq_chirho)?;
        index_chirho.fold_chirho(&record_chirho);
        Ok(())
    }

    /// A clock more than the tolerance behind the latest time seen needs the index rebuilt, since pruning already
    /// used that later time.
    fn needs_rebuild_chirho(&self, index_chirho: &AuthIndexChirho, now_ms_chirho: u64) -> bool {
        now_ms_chirho
            < index_chirho
                .high_water_ms_chirho
                .saturating_sub(self.rules_chirho.regression_tolerance_ms_chirho)
    }

    /// Move the high-water mark, then keep one tolerance behind this call's window, for a later step back.
    fn after_update_chirho(&self, index_chirho: &mut AuthIndexChirho, now_ms_chirho: u64) {
        index_chirho.high_water_ms_chirho = index_chirho.high_water_ms_chirho.max(now_ms_chirho);
        index_chirho.prune_chirho(
            now_ms_chirho.saturating_sub(
                self.rules_chirho.window_ms_chirho
                    + self.rules_chirho.regression_tolerance_ms_chirho,
            ),
            now_ms_chirho.saturating_sub(
                self.rules_chirho.success_window_ms_chirho
                    + self.rules_chirho.regression_tolerance_ms_chirho,
            ),
        );
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-auth-window-job-chirho"
    }
}

#[cfg(test)]
mod test_log_chirho;

#[cfg(test)]
mod equivalence_tests_chirho;

#[cfg(test)]
mod fallback_tests_chirho;

#[cfg(test)]
mod background_tests_chirho;
