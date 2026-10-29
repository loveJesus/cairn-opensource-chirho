// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Runs a view's two background jobs off the request path, at most one per log: the INTEGRITY PASS (re-verify the
//! verified prefix; a failure drops the view) and the INDEX REBUILD the log type asks for (rebuild from the whole
//! log, keep serving meanwhile, then swap).

use crate::view_chirho::{file_stamp_chirho, ingest_chirho, ViewChirho};
use crate::{lock_slot_chirho, BackgroundJobChirho, PrefixLogChirho, SlotChirho, ViewRulesChirho};
use anyhow::Result;
use cairn_durable_chirho::log_path_chirho::open_log_no_follow_chirho;
use std::sync::Arc;
use std::thread::JoinHandle;

/// How a background job ended. Production threads are detached; tests join them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundOutcomeChirho {
    /// Every record of the verified prefix verified again, with the same count and anchor.
    IntegrityConfirmedChirho { verified_chirho: u64 },
    /// A fresh index built from the whole log replaced the serving one.
    IndexSwappedChirho { verified_chirho: u64 },
    /// A record failed to verify, or the verified prefix changed: the view was dropped, so the next call verifies
    /// everything again and refuses while the bad record is there.
    RefusedChirho,
    /// The log could not be read as the same file, or the view was replaced meanwhile: nothing changed, and a later
    /// call may start the job again.
    AbandonedChirho,
}

/// What a job needs from the view as it stood when the job was started.
pub(crate) struct JobRequestChirho {
    kind_chirho: BackgroundJobChirho,
    view_id_chirho: u64,
    started_ms_chirho: u64,
    dev_ino_chirho: (u64, u64),
    verified_len_chirho: u64,
    record_count_chirho: u64,
    anchor_chirho: Option<(u64, Vec<u8>)>,
}

/// The job this call should start, if any, marked in flight on the view. Called after the update and before the log
/// type's bookkeeping, so its rebuild rule sees the index as it stood before this call; otherwise the integrity pass
/// is due once `full_verify_every_ms_chirho` has passed since the last full verification.
pub(crate) fn due_job_chirho<L: PrefixLogChirho>(
    view_chirho: &mut ViewChirho<L::IndexChirho>,
    log_chirho: &L,
    rules_chirho: &ViewRulesChirho,
    now_ms_chirho: u64,
) -> Option<JobRequestChirho> {
    if view_chirho.job_in_flight_chirho.is_some() {
        return None;
    }
    let kind_chirho = if log_chirho.needs_rebuild_chirho(&view_chirho.index_chirho, now_ms_chirho) {
        BackgroundJobChirho::IndexRebuildChirho
    } else if now_ms_chirho.saturating_sub(view_chirho.last_full_ms_chirho)
        >= rules_chirho.full_verify_every_ms_chirho
    {
        BackgroundJobChirho::IntegrityPassChirho
    } else {
        return None;
    };
    view_chirho.job_in_flight_chirho = Some(kind_chirho);
    Some(JobRequestChirho {
        kind_chirho,
        view_id_chirho: view_chirho.view_id_chirho,
        started_ms_chirho: now_ms_chirho,
        dev_ino_chirho: (
            view_chirho.stamp_chirho.dev_chirho,
            view_chirho.stamp_chirho.ino_chirho,
        ),
        verified_len_chirho: view_chirho.verified_len_chirho,
        record_count_chirho: view_chirho.record_count_chirho,
        anchor_chirho: view_chirho.anchor_chirho.clone(),
    })
}

/// Start the job on its own thread. If no thread can be started, the job is cleared so a later call may retry.
pub(crate) fn start_background_job_chirho<L: PrefixLogChirho>(
    slot_chirho: &SlotChirho<L::IndexChirho>,
    view_chirho: &mut Option<ViewChirho<L::IndexChirho>>,
    log_chirho: &L,
    request_chirho: JobRequestChirho,
) -> Option<BackgroundJobChirho> {
    let kind_chirho = request_chirho.kind_chirho;
    let slot_for_job_chirho = Arc::clone(slot_chirho);
    let log_for_job_chirho = log_chirho.job_log_chirho();
    #[cfg(feature = "dev-lifecycle-custody-chirho")]
    let custody_chirho =
        crate::lifecycle_custody_chirho::ActiveBackgroundJobGuardChirho::begin_chirho();
    let spawned_chirho = std::thread::Builder::new()
        .name(log_chirho.job_thread_name_chirho().to_string())
        .spawn(move || {
            // Acquired before spawn, and owned by the closure even if spawn fails. A child that
            // has not started yet is still counted; the token outlives all file and slot work.
            #[cfg(feature = "dev-lifecycle-custody-chirho")]
            let _custody_chirho = custody_chirho;
            run_job_chirho(&slot_for_job_chirho, &log_for_job_chirho, request_chirho)
        });
    match spawned_chirho {
        Ok(handle_chirho) => {
            keep_handle_chirho(log_chirho.path_chirho(), handle_chirho);
            Some(kind_chirho)
        }
        Err(_) => {
            if let Some(current_chirho) = view_chirho.as_mut() {
                current_chirho.job_in_flight_chirho = None;
            }
            None
        }
    }
}

fn run_job_chirho<L: PrefixLogChirho>(
    slot_chirho: &SlotChirho<L::IndexChirho>,
    log_chirho: &L,
    request_chirho: JobRequestChirho,
) -> BackgroundOutcomeChirho {
    // The file work runs WITHOUT the slot's lock; only the result is applied under it.
    let result_chirho = match request_chirho.kind_chirho {
        BackgroundJobChirho::IntegrityPassChirho => {
            reverify_prefix_chirho(log_chirho, &request_chirho).map(|verified_chirho| {
                verified_chirho.map(|verified_chirho| (verified_chirho, None))
            })
        }
        BackgroundJobChirho::IndexRebuildChirho => {
            rebuild_index_chirho(log_chirho, &request_chirho).map(|fresh_chirho| {
                fresh_chirho
                    .map(|fresh_chirho| (fresh_chirho.record_count_chirho, Some(fresh_chirho)))
            })
        }
    };
    wait_at_test_hold_chirho(log_chirho.path_chirho());
    let mut slot_state_chirho = lock_slot_chirho(slot_chirho);
    let view_chirho = &mut slot_state_chirho.view_chirho;
    // A job read the file for one view; if that view was replaced meanwhile, the job's result is stale.
    let still_current_chirho = view_chirho.as_ref().is_some_and(|current_chirho| {
        current_chirho.view_id_chirho == request_chirho.view_id_chirho
    });
    if !still_current_chirho {
        return BackgroundOutcomeChirho::AbandonedChirho;
    }
    match result_chirho {
        Err(_) => {
            *view_chirho = None;
            BackgroundOutcomeChirho::RefusedChirho
        }
        Ok(None) => {
            if let Some(current_chirho) = view_chirho.as_mut() {
                current_chirho.job_in_flight_chirho = None;
            }
            BackgroundOutcomeChirho::AbandonedChirho
        }
        Ok(Some((verified_chirho, Some(fresh_chirho)))) => {
            *view_chirho = Some(fresh_chirho);
            BackgroundOutcomeChirho::IndexSwappedChirho { verified_chirho }
        }
        Ok(Some((verified_chirho, None))) => {
            if let Some(current_chirho) = view_chirho.as_mut() {
                current_chirho.job_in_flight_chirho = None;
                current_chirho.last_full_ms_chirho = current_chirho
                    .last_full_ms_chirho
                    .max(request_chirho.started_ms_chirho);
            }
            BackgroundOutcomeChirho::IntegrityConfirmedChirho { verified_chirho }
        }
    }
}

/// `Ok(None)` when the log cannot be read as the same file (the next call's own checks deal with that);
/// `Err` when a record fails or the prefix no longer reproduces the count and anchor the view holds.
fn reverify_prefix_chirho<L: PrefixLogChirho>(
    log_chirho: &L,
    request_chirho: &JobRequestChirho,
) -> Result<Option<u64>> {
    wait_before_job_open_chirho(log_chirho.path_chirho());
    // No-follow and non-blocking, so a job never waits on a pipe; whatever cannot be opened is the next call's to refuse.
    let Ok(Some(mut file_chirho)) = open_log_no_follow_chirho(log_chirho.path_chirho()) else {
        return Ok(None);
    };
    let Ok(metadata_chirho) = file_chirho.metadata() else {
        return Ok(None);
    };
    let stamp_chirho = file_stamp_chirho(&metadata_chirho);
    if (stamp_chirho.dev_chirho, stamp_chirho.ino_chirho) != request_chirho.dev_ino_chirho
        || stamp_chirho.len_chirho < request_chirho.verified_len_chirho
    {
        return Ok(None);
    }
    let mut scratch_chirho = ViewChirho::<L::IndexChirho>::empty_chirho(
        log_chirho.verifier_id_chirho(),
        stamp_chirho,
        request_chirho.started_ms_chirho,
    );
    ingest_chirho(
        log_chirho,
        &mut file_chirho,
        &mut scratch_chirho,
        request_chirho.verified_len_chirho,
    )?;
    if scratch_chirho.verified_len_chirho != request_chirho.verified_len_chirho
        || scratch_chirho.record_count_chirho != request_chirho.record_count_chirho
        || scratch_chirho.anchor_chirho != request_chirho.anchor_chirho
    {
        anyhow::bail!(
            "the verified prefix no longer reproduces the view's record count and anchor"
        );
    }
    Ok(Some(scratch_chirho.record_count_chirho))
}

/// A fresh view from the whole log, with the log type's bookkeeping applied at the time the rebuild was asked for.
/// `Ok(None)` when the log cannot be read; `Err` when a record fails to verify.
fn rebuild_index_chirho<L: PrefixLogChirho>(
    log_chirho: &L,
    request_chirho: &JobRequestChirho,
) -> Result<Option<ViewChirho<L::IndexChirho>>> {
    wait_before_job_open_chirho(log_chirho.path_chirho());
    let Ok(Some(mut file_chirho)) = open_log_no_follow_chirho(log_chirho.path_chirho()) else {
        return Ok(None);
    };
    let Ok(metadata_chirho) = file_chirho.metadata() else {
        return Ok(None);
    };
    let stamp_chirho = file_stamp_chirho(&metadata_chirho);
    let mut fresh_chirho = ViewChirho::<L::IndexChirho>::empty_chirho(
        log_chirho.verifier_id_chirho(),
        stamp_chirho,
        request_chirho.started_ms_chirho,
    );
    ingest_chirho(
        log_chirho,
        &mut file_chirho,
        &mut fresh_chirho,
        stamp_chirho.len_chirho,
    )?;
    log_chirho.after_update_chirho(
        &mut fresh_chirho.index_chirho,
        request_chirho.started_ms_chirho,
    );
    Ok(Some(fresh_chirho))
}

#[cfg(not(any(test, feature = "test-hooks-chirho")))]
fn keep_handle_chirho(
    _path_chirho: &std::path::Path,
    handle_chirho: JoinHandle<BackgroundOutcomeChirho>,
) {
    // Detached: the job applies its own result.
    drop(handle_chirho);
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
fn job_handles_chirho() -> &'static std::sync::Mutex<
    std::collections::HashMap<std::path::PathBuf, JoinHandle<BackgroundOutcomeChirho>>,
> {
    static HANDLES_CHIRHO: std::sync::OnceLock<
        std::sync::Mutex<
            std::collections::HashMap<std::path::PathBuf, JoinHandle<BackgroundOutcomeChirho>>,
        >,
    > = std::sync::OnceLock::new();
    HANDLES_CHIRHO.get_or_init(Default::default)
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
fn keep_handle_chirho(
    path_chirho: &std::path::Path,
    handle_chirho: JoinHandle<BackgroundOutcomeChirho>,
) {
    job_handles_chirho()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path_chirho.to_path_buf(), handle_chirho);
}

/// Test hook: wait for the last background job started for this log, and return how it ended.
#[cfg(any(test, feature = "test-hooks-chirho"))]
pub fn join_background_job_chirho(
    path_chirho: &std::path::Path,
) -> Option<BackgroundOutcomeChirho> {
    let handle_chirho = job_handles_chirho()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(path_chirho)?;
    handle_chirho.join().ok()
}

#[cfg(not(any(test, feature = "test-hooks-chirho")))]
fn wait_at_test_hold_chirho(_path_chirho: &std::path::Path) {}

#[cfg(not(any(test, feature = "test-hooks-chirho")))]
fn wait_before_job_open_chirho(_path_chirho: &std::path::Path) {}

/// Where a test hold stops a job: just before it opens the log, or after its file work and before it applies a result.
#[cfg(any(test, feature = "test-hooks-chirho"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum HoldStageChirho {
    BeforeOpenChirho,
    AfterFileWorkChirho,
}

/// One test hold: a held job reports that it has finished its file work, then waits to be released.
#[cfg(any(test, feature = "test-hooks-chirho"))]
#[derive(Default)]
struct HoldGateChirho {
    /// (a job is waiting here, the hold was released)
    state_chirho: std::sync::Mutex<(bool, bool)>,
    signal_chirho: std::sync::Condvar,
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
type HoldKeyChirho = (std::path::PathBuf, HoldStageChirho);

#[cfg(any(test, feature = "test-hooks-chirho"))]
fn hold_gates_chirho(
) -> &'static std::sync::Mutex<std::collections::HashMap<HoldKeyChirho, Arc<HoldGateChirho>>> {
    static GATES_CHIRHO: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<HoldKeyChirho, Arc<HoldGateChirho>>>,
    > = std::sync::OnceLock::new();
    GATES_CHIRHO.get_or_init(Default::default)
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
fn wait_at_test_hold_chirho(path_chirho: &std::path::Path) {
    wait_at_stage_chirho(path_chirho, HoldStageChirho::AfterFileWorkChirho);
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
fn wait_before_job_open_chirho(path_chirho: &std::path::Path) {
    wait_at_stage_chirho(path_chirho, HoldStageChirho::BeforeOpenChirho);
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
fn wait_at_stage_chirho(path_chirho: &std::path::Path, stage_chirho: HoldStageChirho) {
    let gate_chirho = hold_gates_chirho()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&(path_chirho.to_path_buf(), stage_chirho))
        .cloned();
    if let Some(gate_chirho) = gate_chirho {
        let mut state_chirho = gate_chirho
            .state_chirho
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state_chirho.0 = true;
        gate_chirho.signal_chirho.notify_all();
        while !state_chirho.1 {
            state_chirho = gate_chirho
                .signal_chirho
                .wait(state_chirho)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Test hook: hold this log's background jobs after their file work and before they apply their result, so a test
/// can change the view in between. Dropping the hold releases them.
#[cfg(any(test, feature = "test-hooks-chirho"))]
pub struct JobHoldChirho {
    key_chirho: HoldKeyChirho,
    gate_chirho: Arc<HoldGateChirho>,
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
pub fn hold_background_jobs_chirho(path_chirho: &std::path::Path) -> JobHoldChirho {
    hold_at_stage_chirho(path_chirho, HoldStageChirho::AfterFileWorkChirho)
}

/// Test hook: hold this log's background jobs just before they open the log, so a test can swap the path first.
#[cfg(any(test, feature = "test-hooks-chirho"))]
pub fn hold_background_jobs_before_open_chirho(path_chirho: &std::path::Path) -> JobHoldChirho {
    hold_at_stage_chirho(path_chirho, HoldStageChirho::BeforeOpenChirho)
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
fn hold_at_stage_chirho(
    path_chirho: &std::path::Path,
    stage_chirho: HoldStageChirho,
) -> JobHoldChirho {
    let gate_chirho = Arc::new(HoldGateChirho::default());
    let key_chirho = (path_chirho.to_path_buf(), stage_chirho);
    hold_gates_chirho()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key_chirho.clone(), Arc::clone(&gate_chirho));
    JobHoldChirho {
        key_chirho,
        gate_chirho,
    }
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
impl JobHoldChirho {
    /// Block until a job has finished reading the log and is waiting to apply its result.
    pub fn wait_until_held_chirho(&self) {
        let mut state_chirho = self
            .gate_chirho
            .state_chirho
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state_chirho.0 {
            state_chirho = self
                .gate_chirho
                .signal_chirho
                .wait(state_chirho)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
impl Drop for JobHoldChirho {
    fn drop(&mut self) {
        hold_gates_chirho()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key_chirho);
        let mut state_chirho = self
            .gate_chirho
            .state_chirho
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state_chirho.1 = true;
        self.gate_chirho.signal_chirho.notify_all();
    }
}
