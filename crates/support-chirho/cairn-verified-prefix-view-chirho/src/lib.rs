// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Keeps an incremental, verified, in-process view of an append-only signed JSONL log, so a hot operation verifies
//! only the records appended since the last call instead of the whole history.
//!
//! Extracted from the sign-in rate limiter (bricks 2 and 2b, spec-chirho/tasklists-chirho/
//! 26-10-01_16-40-tasklist-signin_cost_engine_fix-chirho.md); the generic half of its contract, unchanged:
//! - **Only new bytes are verified per call.** The same file (device and inode), at least as long as the verified
//!   prefix, with the last verified line's bytes unchanged, is read from the end of that prefix only. A second
//!   writer (another process, an operator command) is covered the same way: its appends arrive as new bytes.
//! - **Everything else verifies the whole log again, on the call:** the first call (a user may warm it at
//!   startup), a different verification key, a new inode, a shrink below the verified prefix, a same-length change
//!   in place, or a changed anchor line. Those are first loads or write-access events.
//! - **Any error drops the view,** so the next call verifies everything again and refuses while the bad record is
//!   there. A half-folded index is never reused.
//! - **The INTEGRITY PASS runs in the background** at the rules' interval, never on a call and never under the
//!   appenders' file lock: it re-verifies the verified prefix and must reproduce the view's record count and
//!   anchor. A failure drops the view. A log type may also ask for a background INDEX REBUILD; the current index
//!   keeps serving until the rebuilt one swaps in. At most one background job runs per log.
//! - **A final line without its newline** counts when it parses, as `str::lines` would count it. Otherwise it is
//!   left for a later call: a write still in flight, or a torn tail that seqlog recovery truncates.
//! - **Threat boundary:** an in-place edit of an already verified record that keeps the anchor line, and either
//!   grows the file or keeps its length and timestamps, is not DETECTED until the next integrity pass; reads
//!   meanwhile still use the verified original. Such an edit needs write access to the log.
//! - **Locks:** a short process-wide lock finds the log's slot; the slot's own mutex then covers the stat, the
//!   delta verification, the fold, the log type's bookkeeping and the caller's read. An appender takes its file lock
//!   first and this mutex second, never the reverse. The callbacks run under the mutex and must never re-enter the
//!   slot they run under. A fold MAY read ANOTHER log type's view, along an acyclic order that log type documents:
//!   the run-intent view reads the private-value and blob views (agy #25851), and neither of those calls back. A
//!   background job reads the file without any lock and takes the slot's mutex only to apply its result.
//!
//! Users: the sign-in rate limiter (cairn-auth-attempt-window-chirho), the privacy blob log's subject lookup
//! (`src/privacy_compliance_chirho/privacy_chirho/blob_view_chirho.rs`), the private-value index
//! (`src/app_authoring_chirho/dag_private_value_chirho/value_view_chirho.rs`) and the run-intent admission view
//! (`src/execution_runtime_chirho/effect_chirho/run_intent_chirho/admission_view_chirho.rs`). Design:
//! spec-chirho/workflows-chirho/perf-chirho/execution-checkpoint-brick-design-chirho.md.

use anyhow::{Context, Result};
use cairn_durable_chirho::log_path_chirho::{
    classify_log_path_chirho, open_log_no_follow_chirho, LogPathChirho,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

mod background_chirho;
#[cfg(feature = "dev-lifecycle-custody-chirho")]
mod lifecycle_custody_chirho;
mod view_chirho;

pub use background_chirho::BackgroundOutcomeChirho;
#[cfg(any(test, feature = "test-hooks-chirho"))]
pub use background_chirho::{
    hold_background_jobs_before_open_chirho, hold_background_jobs_chirho,
    join_background_job_chirho, JobHoldChirho,
};
#[cfg(feature = "dev-lifecycle-custody-chirho")]
pub use lifecycle_custody_chirho::active_background_jobs_chirho;
use view_chirho::{fallback_cause_chirho, file_stamp_chirho, ingest_chirho, ViewChirho};

/// One append-only signed log and the index its hot operations read. A call verifies on the caller's own instance;
/// only a background job, which runs on its own thread, gets an owned copy.
pub trait PrefixLogChirho {
    type RecordChirho;
    type IndexChirho: Default + Send + 'static;
    /// The owned copy a background job runs on: usually a clone of the log.
    type JobLogChirho: PrefixLogChirho<IndexChirho = Self::IndexChirho> + Send + 'static;
    fn job_log_chirho(&self) -> Self::JobLogChirho;
    fn path_chirho(&self) -> &Path;
    /// Names the verification key. When it changes, every record is verified again.
    fn verifier_id_chirho(&self) -> &str;
    /// Where this log type's views live: one `static RegistryChirho` per index type.
    fn registry_chirho(&self) -> &'static RegistryChirho<Self::IndexChirho>;
    /// Parse one non-blank line, without its line ending.
    fn parse_chirho(&self, line_chirho: &str) -> Result<Self::RecordChirho>;
    /// Verify a parsed record as the log's `expected_seq_chirho`-th record (0-based) against the index of every
    /// record before it, then fold it in. The checks must be the ones the log's full verification runs. On an error
    /// the index may be partly changed: the engine then drops the whole view, so it is never reused.
    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut Self::IndexChirho,
        record_chirho: Self::RecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()>;
    /// Asked after each update, before `after_update_chirho`: must the index be rebuilt from the whole log at
    /// `now_ms_chirho`, in the background while the current index keeps serving? Default: never.
    fn needs_rebuild_chirho(&self, _index_chirho: &Self::IndexChirho, _now_ms_chirho: u64) -> bool {
        false
    }
    /// Runs under the slot's lock after every update, and on a rebuilt index at the time its rebuild was asked for:
    /// bookkeeping such as pruning. Default: nothing.
    fn after_update_chirho(&self, _index_chirho: &mut Self::IndexChirho, _now_ms_chirho: u64) {}
    /// The background job thread's name, so a thread listing says whose view it is.
    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-prefix-view-job-chirho"
    }
}

/// How often the whole verified prefix is re-verified in the background, and how many logs of one type keep a view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewRulesChirho {
    pub full_verify_every_ms_chirho: u64,
    /// Eviction only costs the evicted log one full verification on its next call.
    pub slot_cap_chirho: usize,
}

/// Why a call verified the whole log again, on the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackCauseChirho {
    FirstLoadChirho,
    VerifierChangedChirho,
    IdentityChangedChirho,
    ShrunkChirho,
    RewrittenInPlaceChirho,
    AnchorChangedChirho,
}

/// The path a call took. Tests assert it, so an equivalence check cannot pass by quietly verifying everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathTakenChirho {
    MissingLogChirho,
    UnchangedChirho,
    IncrementalChirho {
        folded_chirho: u64,
    },
    FullFromFallbackChirho {
        cause_chirho: FallbackCauseChirho,
        verified_chirho: u64,
    },
}

/// Work a call started in the background, off the call's path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundJobChirho {
    /// Re-verify every record of the verified prefix. A failure drops the view.
    IntegrityPassChirho,
    /// The log type asked for its index to be rebuilt from the whole log: keep serving the current one, then swap.
    IndexRebuildChirho,
}

/// What one update did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateStatusChirho {
    pub verified_records_chirho: u64,
    pub path_chirho: PathTakenChirho,
    pub started_chirho: Option<BackgroundJobChirho>,
}

/// The slots of one log type's views, each with the tick of its last use. Declare one per index type:
/// `static REGISTRY_CHIRHO: RegistryChirho<MyIndexChirho> = RegistryChirho::new_chirho();`
pub struct RegistryChirho<I> {
    slots_chirho: OnceLock<Mutex<SlotsChirho<I>>>,
}

impl<I> RegistryChirho<I> {
    pub const fn new_chirho() -> Self {
        Self {
            slots_chirho: OnceLock::new(),
        }
    }
}

impl<I> Default for RegistryChirho<I> {
    fn default() -> Self {
        Self::new_chirho()
    }
}

pub(crate) type SlotChirho<I> = Arc<Mutex<SlotStateChirho<I>>>;

/// One log's slot: its current view, and whether the log was ever found present.
pub(crate) struct SlotStateChirho<I> {
    pub(crate) view_chirho: Option<ViewChirho<I>>,
    /// Kept through faults and through a dropped view, so a log seen present that later reads as missing refuses
    /// rather than becoming empty. It lives as long as the slot: a bounded registry entry in this process. A fresh
    /// process, or a slot evicted and made again, starts without it, so this is not durable completeness.
    pub(crate) seen_present_chirho: bool,
}

impl<I> SlotStateChirho<I> {
    pub(crate) fn empty_chirho() -> Self {
        Self {
            view_chirho: None,
            seen_present_chirho: false,
        }
    }
}

struct SlotsChirho<I> {
    entries_chirho: HashMap<PathBuf, (SlotChirho<I>, u64)>,
    tick_chirho: u64,
}

/// Bring the log's view up to date, verifying only what was appended where possible, start any background job that
/// is due, then let `read_chirho` read the index under the same lock. `read_chirho` receives `None` when the log is
/// missing (an empty log) and the time the clock gave inside the lock. It must not call back into this crate.
pub fn with_current_view_chirho<L: PrefixLogChirho, T>(
    log_chirho: &L,
    rules_chirho: &ViewRulesChirho,
    clock_chirho: impl FnOnce() -> u64,
    read_chirho: impl FnOnce(Option<&L::IndexChirho>, u64) -> T,
) -> Result<(T, UpdateStatusChirho)> {
    let slot_chirho = slot_for_chirho(
        log_chirho.registry_chirho(),
        log_chirho.path_chirho(),
        rules_chirho.slot_cap_chirho,
    );
    let mut slot_state_chirho = lock_slot_chirho(&slot_chirho);
    let slot_state_chirho = &mut *slot_state_chirho;
    // Read inside the lock: updates are then ordered by time, and a concurrent caller is never a step back.
    let now_ms_chirho = clock_chirho();
    let status_chirho = update_view_chirho(
        &slot_chirho,
        &mut slot_state_chirho.view_chirho,
        &mut slot_state_chirho.seen_present_chirho,
        log_chirho,
        rules_chirho,
        now_ms_chirho,
    )?;
    let value_chirho = read_chirho(
        slot_state_chirho
            .view_chirho
            .as_ref()
            .map(|current_chirho| &current_chirho.index_chirho),
        now_ms_chirho,
    );
    Ok((value_chirho, status_chirho))
}

/// Whether a view's log is genuinely missing, so its caller may answer "no records" without loading anything, not even
/// the root's key: only a NotFound for a log this registry never saw present. A log seen present that is now missing
/// refuses, as do a link, a directory, a pipe and every examination error. A log present now is not missing, and the
/// view itself then opens it.
pub fn log_missing_chirho<I>(
    registry_chirho: &RegistryChirho<I>,
    path_chirho: &Path,
) -> Result<bool> {
    match classify_log_path_chirho(path_chirho)
        .with_context(|| format!("examine {}", path_chirho.display()))?
    {
        LogPathChirho::PresentChirho(_) => Ok(false),
        LogPathChirho::AbsentChirho if seen_present_chirho(registry_chirho, path_chirho) => {
            Err(seen_present_now_missing_chirho(path_chirho))
        }
        LogPathChirho::AbsentChirho => Ok(true),
    }
}

/// Whether this registry's slot for the path ever found its log present. The map lock is held only for the lookup.
fn seen_present_chirho<I>(registry_chirho: &RegistryChirho<I>, path_chirho: &Path) -> bool {
    let Some(slots_lock_chirho) = registry_chirho.slots_chirho.get() else {
        return false;
    };
    // Nothing in this short section can leave the map half-changed, so a poisoned lock still holds a valid map.
    let slot_chirho = slots_lock_chirho
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entries_chirho
        .get(path_chirho)
        .map(|(slot_chirho, _)| Arc::clone(slot_chirho));
    slot_chirho.is_some_and(|slot_chirho| lock_slot_chirho(&slot_chirho).seen_present_chirho)
}

/// The refusal for a log seen present that now reads as missing.
fn seen_present_now_missing_chirho(path_chirho: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} was present and is now missing: a log seen present is refused, never read as empty",
        path_chirho.display()
    )
}

/// Drop the log's view, if it has one, so the next call verifies the whole log again. For a fault the log type
/// finds OUTSIDE the fold, in a per-call check against state the fold does not track: the next call then refuses
/// as a first load would, for every caller. A background job in flight finds its view replaced and changes nothing.
pub fn drop_view_chirho<L: PrefixLogChirho>(log_chirho: &L) {
    let Some(slots_lock_chirho) = log_chirho.registry_chirho().slots_chirho.get() else {
        return;
    };
    // Nothing in this short section can leave the map half-changed, so a poisoned lock still holds a valid map.
    let slot_chirho = slots_lock_chirho
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entries_chirho
        .get(log_chirho.path_chirho())
        .map(|(slot_chirho, _)| Arc::clone(slot_chirho));
    if let Some(slot_chirho) = slot_chirho {
        lock_slot_chirho(&slot_chirho).view_chirho = None;
    }
}

/// The log's slot, created on first use. This lock is held only for the map lookup.
fn slot_for_chirho<I>(
    registry_chirho: &RegistryChirho<I>,
    path_chirho: &Path,
    cap_chirho: usize,
) -> SlotChirho<I> {
    // Nothing in this short section can leave the map half-changed, so a poisoned lock still holds a valid map.
    let mut slots_chirho = registry_chirho
        .slots_chirho
        .get_or_init(|| {
            Mutex::new(SlotsChirho {
                entries_chirho: HashMap::new(),
                tick_chirho: 0,
            })
        })
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    slots_chirho.tick_chirho = slots_chirho.tick_chirho.wrapping_add(1);
    let tick_chirho = slots_chirho.tick_chirho;
    if let Some((slot_chirho, last_tick_chirho)) = slots_chirho.entries_chirho.get_mut(path_chirho)
    {
        *last_tick_chirho = tick_chirho;
        return Arc::clone(slot_chirho);
    }
    evict_to_fit_chirho(&mut slots_chirho.entries_chirho, cap_chirho, path_chirho);
    let slot_chirho: SlotChirho<I> = Arc::new(Mutex::new(SlotStateChirho::empty_chirho()));
    slots_chirho.entries_chirho.insert(
        path_chirho.to_path_buf(),
        (Arc::clone(&slot_chirho), tick_chirho),
    );
    slot_chirho
}

/// A poisoned slot means a panic interrupted an update. Its view is dropped, so this call verifies the whole log,
/// and the poison is cleared, so later calls are incremental again. Whether the log was seen present is kept.
pub(crate) fn lock_slot_chirho<I>(
    slot_chirho: &SlotChirho<I>,
) -> MutexGuard<'_, SlotStateChirho<I>> {
    slot_chirho.lock().unwrap_or_else(|poisoned_chirho| {
        slot_chirho.clear_poison();
        let mut slot_state_chirho = poisoned_chirho.into_inner();
        slot_state_chirho.view_chirho = None;
        slot_state_chirho
    })
}

/// Evict least-recently-used slots until `incoming_chirho` fits within `cap_chirho`.
fn evict_to_fit_chirho<I>(
    entries_chirho: &mut HashMap<PathBuf, (SlotChirho<I>, u64)>,
    cap_chirho: usize,
    incoming_chirho: &Path,
) {
    while !entries_chirho.contains_key(incoming_chirho) && entries_chirho.len() >= cap_chirho {
        let victim_chirho = entries_chirho
            .iter()
            .min_by_key(|(_, (_, last_tick_chirho))| *last_tick_chirho)
            .map(|(path_chirho, _)| path_chirho.clone());
        match victim_chirho {
            Some(victim_chirho) => {
                entries_chirho.remove(&victim_chirho);
            }
            None => break,
        }
    }
}

/// Bring the view up to date with the log, then start any background job that is due. Any error drops the view,
/// so the next call verifies everything again.
fn update_view_chirho<L: PrefixLogChirho>(
    slot_chirho: &SlotChirho<L::IndexChirho>,
    view_chirho: &mut Option<ViewChirho<L::IndexChirho>>,
    seen_present_chirho: &mut bool,
    log_chirho: &L,
    rules_chirho: &ViewRulesChirho,
    now_ms_chirho: u64,
) -> Result<UpdateStatusChirho> {
    match update_view_inner_chirho(
        view_chirho,
        seen_present_chirho,
        log_chirho,
        rules_chirho,
        now_ms_chirho,
    ) {
        Ok((mut status_chirho, job_chirho)) => {
            status_chirho.started_chirho = job_chirho.and_then(|request_chirho| {
                background_chirho::start_background_job_chirho(
                    slot_chirho,
                    view_chirho,
                    log_chirho,
                    request_chirho,
                )
            });
            Ok(status_chirho)
        }
        Err(error_chirho) => {
            *view_chirho = None;
            Err(error_chirho)
        }
    }
}

fn update_view_inner_chirho<L: PrefixLogChirho>(
    view_chirho: &mut Option<ViewChirho<L::IndexChirho>>,
    seen_present_chirho: &mut bool,
    log_chirho: &L,
    rules_chirho: &ViewRulesChirho,
    now_ms_chirho: u64,
) -> Result<(
    UpdateStatusChirho,
    Option<background_chirho::JobRequestChirho>,
)> {
    let path_chirho = log_chirho.path_chirho();
    // No-follow and non-blocking: a link, a directory, a pipe or a permission error refuses, and a pipe is never
    // waited on. Only a genuine absence is a missing log.
    let opened_chirho = open_log_no_follow_chirho(path_chirho)
        .with_context(|| format!("open {}", path_chirho.display()))?;
    let Some(mut file_chirho) = opened_chirho else {
        if *seen_present_chirho {
            return Err(seen_present_now_missing_chirho(path_chirho));
        }
        // A log never seen present and missing now is an empty log. A view built later starts from a first load.
        *view_chirho = None;
        let status_chirho = UpdateStatusChirho {
            verified_records_chirho: 0,
            path_chirho: PathTakenChirho::MissingLogChirho,
            started_chirho: None,
        };
        return Ok((status_chirho, None));
    };
    *seen_present_chirho = true;
    // Stat the open handle, so the stamp describes the same file the reads below see.
    let stamp_chirho = file_stamp_chirho(
        &file_chirho
            .metadata()
            .with_context(|| format!("stat {}", path_chirho.display()))?,
    );
    let fallback_chirho = match view_chirho.as_ref() {
        None => Some(FallbackCauseChirho::FirstLoadChirho),
        Some(current_chirho) => {
            fallback_cause_chirho(current_chirho, log_chirho, &stamp_chirho, &mut file_chirho)?
        }
    };
    let path_taken_chirho = match fallback_chirho {
        None => {
            let current_chirho = view_chirho
                .as_mut()
                .expect("no fallback means a view exists");
            if stamp_chirho == current_chirho.stamp_chirho {
                PathTakenChirho::UnchangedChirho
            } else {
                let before_chirho = current_chirho.record_count_chirho;
                ingest_chirho(
                    log_chirho,
                    &mut file_chirho,
                    current_chirho,
                    stamp_chirho.len_chirho,
                )?;
                current_chirho.stamp_chirho = stamp_chirho;
                PathTakenChirho::IncrementalChirho {
                    folded_chirho: current_chirho.record_count_chirho - before_chirho,
                }
            }
        }
        Some(cause_chirho) => {
            let mut fresh_chirho = ViewChirho::<L::IndexChirho>::empty_chirho(
                log_chirho.verifier_id_chirho(),
                stamp_chirho,
                now_ms_chirho,
            );
            ingest_chirho(
                log_chirho,
                &mut file_chirho,
                &mut fresh_chirho,
                stamp_chirho.len_chirho,
            )?;
            let verified_chirho = fresh_chirho.record_count_chirho;
            *view_chirho = Some(fresh_chirho);
            PathTakenChirho::FullFromFallbackChirho {
                cause_chirho,
                verified_chirho,
            }
        }
    };
    let current_chirho = view_chirho.as_mut().expect("a view exists after an update");
    // Decided before the log type's bookkeeping moves, so its rebuild rule sees the index as it stood.
    let job_chirho =
        background_chirho::due_job_chirho(current_chirho, log_chirho, rules_chirho, now_ms_chirho);
    log_chirho.after_update_chirho(&mut current_chirho.index_chirho, now_ms_chirho);
    let status_chirho = UpdateStatusChirho {
        verified_records_chirho: current_chirho.record_count_chirho,
        path_chirho: path_taken_chirho,
        started_chirho: None,
    };
    Ok((status_chirho, job_chirho))
}

#[cfg(test)]
mod eviction_tests_chirho;
