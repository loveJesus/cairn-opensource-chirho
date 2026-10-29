// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The run-intent log as an incremental, verified view (checkpoint brick S3), so a run's admission verifies only the
//! records appended since the last call instead of the whole log on every request.
//!
//! Design: `spec-chirho/workflows-chirho/perf-chirho/execution-checkpoint-brick-design-chirho.md`, section S3; agy's
//! money-grade ruling #25851, option (a).
//! - **Each record is verified once, when it is folded,** with the operator verifier's own per-record checks and its
//!   transition check against this view's run map, in log order (`record_verify_chirho`, shared, so the two cannot
//!   drift apart).
//! - **The run being admitted is re-verified FRESH on every admission** (and on every resume): its latest record's
//!   request value, context hash, DAG object and signature. It is the only run whose effect can run.
//! - **What option (a) gives up, by ruling:** a change to an UNRELATED run's request value, blob or key file after its
//!   record was folded no longer refuses the next admission at once. The hourly integrity pass re-verifies the whole
//!   prefix; a failure drops the view, and every admission then refuses until the log verifies again.
//! - **Locks (agy #25851, acyclic):** the append-log lock, then this view's slot, then the private-value and
//!   private-blob views' slots, which the fold reads through; neither of those ever calls into this view. This is the
//!   one engine user whose fold reads ANOTHER log type's view. The engine's rule is about the SAME slot: a callback
//!   must never re-enter the slot it runs under.
//! - **The store rule (S1's):** an append brings this view current under the append-log lock BEFORE the seqlog's
//!   recovery and refuses unless both counts agree, so an append refuses exactly when an admission would.
//! - **A missing log reads the signing key never:** an empty root answers "no records" without creating a key, as the
//!   operator verifier's early return does.

use super::record_verify_chirho::{
    verify_run_intent_record_chirho, verify_run_intent_transition_chirho,
};
use super::{run_intent_records_path_chirho, unfinished_status_chirho, RunIntentRecordChirho};
use crate::dag_private_value_chirho::PrivateDagValueSubjectResolverChirho;
use crate::model_chirho::HashChirho;
use anyhow::{Context, Result};
use cairn_signer_chirho::signer_chirho;
use cairn_verified_prefix_view_chirho::{
    log_missing_chirho, with_current_view_chirho, PrefixLogChirho, RegistryChirho,
    UpdateStatusChirho, ViewRulesChirho,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The verified run-intent log, folded: each run's latest record, and the request contexts each caller key is bound
/// to.
#[derive(Default)]
pub(super) struct RunIntentIndexChirho {
    record_count_chirho: u64,
    latest_by_run_chirho: HashMap<HashChirho, RunIntentRecordChirho>,
    contexts_by_caller_key_chirho: HashMap<HashChirho, BTreeSet<HashChirho>>,
}

/// Every root's run-intent view, one slot per log.
static RUN_INTENT_REGISTRY_CHIRHO: RegistryChirho<RunIntentIndexChirho> =
    RegistryChirho::new_chirho();

/// The verified prefix is re-verified in the background at this interval: option (a)'s integrity pass.
const RUN_INTENT_FULL_VERIFY_EVERY_MS_CHIRHO: u64 = 60 * 60 * 1000;

#[cfg(not(any(test, feature = "serve-runtime-test-hooks-chirho")))]
const RUN_INTENT_SLOT_CAP_CHIRHO: usize = 32;
// Parallel tests each use their own root; a large cap keeps them from evicting each other.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
const RUN_INTENT_SLOT_CAP_CHIRHO: usize = 8192;

pub(super) fn run_intent_view_rules_chirho() -> ViewRulesChirho {
    ViewRulesChirho {
        full_verify_every_ms_chirho: RUN_INTENT_FULL_VERIFY_EVERY_MS_CHIRHO,
        slot_cap_chirho: RUN_INTENT_SLOT_CAP_CHIRHO,
    }
}

pub(super) fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

/// The log, with the key its records are signed by and one private-value resolver for one pass: a call's delta, or a
/// background job's whole prefix.
struct RunIntentLogChirho {
    root_chirho: PathBuf,
    path_chirho: PathBuf,
    pubkey_chirho: String,
    verifier_id_chirho: String,
    private_values_chirho: RefCell<PrivateDagValueSubjectResolverChirho>,
}

impl RunIntentLogChirho {
    fn new_chirho(root_chirho: &Path, pubkey_chirho: String) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            path_chirho: run_intent_records_path_chirho(root_chirho),
            // v2: the rules gained `aborted-chirho` (the reader brick, agy #25907).
            verifier_id_chirho: format!("run-intent-records-v2-chirho:{pubkey_chirho}"),
            pubkey_chirho,
            private_values_chirho: RefCell::new(PrivateDagValueSubjectResolverChirho::new_chirho(
                root_chirho,
            )),
        }
    }
}

impl PrefixLogChirho for RunIntentLogChirho {
    type RecordChirho = RunIntentRecordChirho;
    type IndexChirho = RunIntentIndexChirho;
    type JobLogChirho = RunIntentLogChirho;

    /// A fresh resolver for the job's pass: one resolver per pass, never across passes.
    fn job_log_chirho(&self) -> RunIntentLogChirho {
        RunIntentLogChirho::new_chirho(&self.root_chirho, self.pubkey_chirho.clone())
    }

    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }

    /// The fold verifies signatures, so the id names the key: a changed key verifies every record again.
    fn verifier_id_chirho(&self) -> &str {
        &self.verifier_id_chirho
    }

    fn registry_chirho(&self) -> &'static RegistryChirho<RunIntentIndexChirho> {
        &RUN_INTENT_REGISTRY_CHIRHO
    }

    /// The operator loader's parse, with its message.
    fn parse_chirho(&self, line_chirho: &str) -> Result<RunIntentRecordChirho> {
        serde_json::from_str(line_chirho).context("decode run intent record")
    }

    /// The operator verifier's checks for one record, in its order: the per-record checks, then the transition from
    /// the run's previous status.
    fn verify_and_fold_chirho(
        &self,
        index_chirho: &mut RunIntentIndexChirho,
        record_chirho: RunIntentRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        verify_run_intent_record_chirho(
            &self.root_chirho,
            &self.pubkey_chirho,
            &mut self.private_values_chirho.borrow_mut(),
            expected_seq_chirho as usize,
            &record_chirho,
        )?;
        let previous_status_chirho = index_chirho
            .latest_by_run_chirho
            .get(&record_chirho.run_chirho)
            .map(|latest_chirho| latest_chirho.status_chirho.clone());
        verify_run_intent_transition_chirho(&record_chirho, previous_status_chirho.as_deref())?;
        if let Some(caller_key_chirho) = &record_chirho.caller_idempotency_key_digest_chirho {
            index_chirho
                .contexts_by_caller_key_chirho
                .entry(caller_key_chirho.clone())
                .or_default()
                .insert(record_chirho.idempotency_context_hash_chirho.clone());
        }
        index_chirho
            .latest_by_run_chirho
            .insert(record_chirho.run_chirho.clone(), record_chirho);
        index_chirho.record_count_chirho += 1;
        Ok(())
    }

    fn job_thread_name_chirho(&self) -> &'static str {
        "cairn-run-intent-view-job-chirho"
    }
}

/// Bring the root's view current and read it under its slot lock; the closure only copies out, and must not call back
/// into the engine. A missing log reads as no index, and its signing key is never read or created.
fn with_index_chirho<T>(
    root_chirho: &Path,
    read_chirho: impl FnOnce(Option<&RunIntentIndexChirho>) -> T,
) -> Result<T> {
    with_index_rules_chirho(
        root_chirho,
        &run_intent_view_rules_chirho(),
        now_ms_chirho,
        read_chirho,
    )
    .map(|(value_chirho, _status_chirho)| value_chirho)
}

/// `with_index_chirho` with its rules and clock given, and the view's update status returned: the tests' door to the
/// integrity pass and its interval, as S1's blob view has.
pub(super) fn with_index_rules_chirho<T>(
    root_chirho: &Path,
    rules_chirho: &ViewRulesChirho,
    clock_chirho: impl FnOnce() -> u64,
    read_chirho: impl FnOnce(Option<&RunIntentIndexChirho>) -> T,
) -> Result<(T, Option<UpdateStatusChirho>)> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    run_intent_view_metrics_chirho::note_read_chirho();
    if log_missing_chirho(
        &RUN_INTENT_REGISTRY_CHIRHO,
        &run_intent_records_path_chirho(root_chirho),
    )? {
        return Ok((read_chirho(None), None));
    }
    let log_chirho =
        RunIntentLogChirho::new_chirho(root_chirho, signer_chirho::pubkey_hex_chirho(root_chirho)?);
    let (value_chirho, status_chirho) = with_current_view_chirho(
        &log_chirho,
        rules_chirho,
        clock_chirho,
        |index_chirho, _now_ms_chirho| read_chirho(index_chirho),
    )?;
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    run_intent_view_metrics_chirho::note_update_chirho(&status_chirho);
    Ok((value_chirho, Some(status_chirho)))
}

/// What an admission learns from the view, under the append-log lock: the run's latest record (not yet re-verified)
/// and whether the caller key is already bound to different request evidence.
pub(super) struct AdmissionLookupChirho {
    pub(super) latest_chirho: Option<RunIntentRecordChirho>,
    pub(super) caller_key_collides_chirho: bool,
}

/// The admission's read: the run's latest record, and whether its caller key is bound to any OTHER request context.
/// The caller holds the append-log lock, so the view is exactly the log: nothing decides from a snapshot taken
/// outside it.
pub(super) fn admission_lookup_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
    caller_key_chirho: Option<&HashChirho>,
    context_chirho: &HashChirho,
) -> Result<AdmissionLookupChirho> {
    with_index_chirho(root_chirho, |index_chirho| {
        let Some(index_chirho) = index_chirho else {
            return AdmissionLookupChirho {
                latest_chirho: None,
                caller_key_collides_chirho: false,
            };
        };
        AdmissionLookupChirho {
            latest_chirho: index_chirho.latest_by_run_chirho.get(run_chirho).cloned(),
            caller_key_collides_chirho: caller_key_chirho
                .and_then(|caller_key_chirho| {
                    index_chirho
                        .contexts_by_caller_key_chirho
                        .get(caller_key_chirho)
                })
                .is_some_and(|contexts_chirho| {
                    contexts_chirho
                        .iter()
                        .any(|bound_chirho| bound_chirho != context_chirho)
                }),
        }
    })
}

/// The run's latest record, from the view: a resume's read, under the append-log lock.
pub(super) fn latest_record_for_run_chirho(
    root_chirho: &Path,
    run_chirho: &HashChirho,
) -> Result<Option<RunIntentRecordChirho>> {
    with_index_chirho(root_chirho, |index_chirho| {
        index_chirho
            .and_then(|index_chirho| index_chirho.latest_by_run_chirho.get(run_chirho).cloned())
    })
}

/// Re-verify one record fresh, with today's per-record checks and a new resolver: option (a)'s check on the run being
/// admitted or resumed, the only run whose effect can run.
pub(super) fn reverify_fresh_chirho(
    root_chirho: &Path,
    record_chirho: &RunIntentRecordChirho,
) -> Result<()> {
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    run_intent_view_metrics_chirho::note_fresh_reverify_chirho();
    let mut private_values_chirho = PrivateDagValueSubjectResolverChirho::new_chirho(root_chirho);
    verify_run_intent_record_chirho(
        root_chirho,
        &signer_chirho::pubkey_hex_chirho(root_chirho)?,
        &mut private_values_chirho,
        record_chirho.seq_chirho as usize,
        record_chirho,
    )
}

/// The startup resume's input, under the append-log lock: how many records the log holds, and the latest record of
/// every unfinished run, in run-id order (the order the whole-log pass used).
pub(super) fn unfinished_runs_chirho(
    root_chirho: &Path,
) -> Result<(usize, Vec<RunIntentRecordChirho>)> {
    with_index_chirho(root_chirho, |index_chirho| {
        let Some(index_chirho) = index_chirho else {
            return (0, Vec::new());
        };
        let unfinished_chirho: BTreeMap<&HashChirho, &RunIntentRecordChirho> = index_chirho
            .latest_by_run_chirho
            .iter()
            .filter(|(_run_chirho, latest_chirho)| {
                unfinished_status_chirho(&latest_chirho.status_chirho)
            })
            .collect();
        (
            index_chirho.record_count_chirho as usize,
            unfinished_chirho.into_values().cloned().collect(),
        )
    })
}

/// Bring the view current and return how many records it holds: the append path's gate, run under the append-log
/// lock before the seqlog's recovery, so an append refuses exactly when an admission would.
pub(super) fn current_run_intent_record_count_chirho(root_chirho: &Path) -> Result<u64> {
    with_index_chirho(root_chirho, |index_chirho| {
        index_chirho.map_or(0, |index_chirho| index_chirho.record_count_chirho)
    })
}

/// Build the root's run-intent view now, so the first admissions find it ready; for the serve runtime's warm-up thread.
pub fn warm_run_intent_view_chirho(root_chirho: &Path) -> Result<()> {
    current_run_intent_record_count_chirho(root_chirho).map(|_| ())
}

/// Warm the root's run-intent view on its own thread: the serve runtime calls this after it binds, beside the blob and
/// value views' warm-ups, so restart time does not grow with the log (agy's (a') ruling for S1). Until it is built, an
/// admission builds it itself: correct, only slower. A failure is not fatal: admissions refuse on their own until the
/// log verifies. The line it prints names no record, run or subject.
pub fn spawn_run_intent_view_warm_up_chirho(root_chirho: &Path) {
    let root_chirho = root_chirho.to_path_buf();
    let spawned_chirho = std::thread::Builder::new()
        .name("cairn-run-intent-view-warm-chirho".to_string())
        .spawn(move || {
            if warm_run_intent_view_chirho(&root_chirho).is_err() {
                eprintln!(
                    "cairn-chirho: the run-intent log did not verify at startup; admissions refuse until it does \
                     (verify shows why)"
                );
            }
        });
    if spawned_chirho.is_err() {
        eprintln!("cairn-chirho: the run-intent view warm-up did not start; the first admission builds it");
    }
}

/// What the run-intent road did on the calling thread, for the growth arms. In the `serve-runtime-test-hooks-chirho`
/// family. Thread-local, so parallel tests with their own roots never perturb one another; the background integrity
/// pass runs on its own thread and is not counted.
#[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
pub mod run_intent_view_metrics_chirho {
    use cairn_verified_prefix_view_chirho::{PathTakenChirho, UpdateStatusChirho};
    use std::cell::Cell;

    /// One thread's run-intent-road work since the last reset.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct RunIntentRoadCountsChirho {
        /// Reads of the view: admissions, resumes and append gates.
        pub reads_chirho: u64,
        /// Whole-log verifications: the view built from the whole log.
        pub full_log_loads_chirho: u64,
        /// Records verified and folded: the appended delta, or the whole log on a full build.
        pub records_folded_chirho: u64,
        /// Records re-verified fresh: the run being admitted or resumed.
        pub fresh_reverifies_chirho: u64,
    }

    thread_local! {
        static COUNTS_CHIRHO: Cell<RunIntentRoadCountsChirho> = const {
            Cell::new(RunIntentRoadCountsChirho {
                reads_chirho: 0,
                full_log_loads_chirho: 0,
                records_folded_chirho: 0,
                fresh_reverifies_chirho: 0,
            })
        };
    }

    pub fn reset_chirho() {
        COUNTS_CHIRHO.with(|cell_chirho| cell_chirho.set(RunIntentRoadCountsChirho::default()));
    }

    pub fn counts_chirho() -> RunIntentRoadCountsChirho {
        COUNTS_CHIRHO.with(Cell::get)
    }

    /// Add work counted on another thread, such as a served run's blocking-pool thread, to this thread's counts. The
    /// destructuring is exhaustive, so a new field cannot be left out.
    pub fn absorb_chirho(other_chirho: RunIntentRoadCountsChirho) {
        let RunIntentRoadCountsChirho {
            reads_chirho,
            full_log_loads_chirho,
            records_folded_chirho,
            fresh_reverifies_chirho,
        } = other_chirho;
        change_chirho(|counts_chirho| {
            counts_chirho.reads_chirho += reads_chirho;
            counts_chirho.full_log_loads_chirho += full_log_loads_chirho;
            counts_chirho.records_folded_chirho += records_folded_chirho;
            counts_chirho.fresh_reverifies_chirho += fresh_reverifies_chirho;
        });
    }

    fn change_chirho(change_chirho: impl FnOnce(&mut RunIntentRoadCountsChirho)) {
        COUNTS_CHIRHO.with(|cell_chirho| {
            let mut counts_chirho = cell_chirho.get();
            change_chirho(&mut counts_chirho);
            cell_chirho.set(counts_chirho);
        });
    }

    pub(super) fn note_read_chirho() {
        change_chirho(|counts_chirho| counts_chirho.reads_chirho += 1);
    }

    pub(super) fn note_fresh_reverify_chirho() {
        change_chirho(|counts_chirho| counts_chirho.fresh_reverifies_chirho += 1);
    }

    pub(super) fn note_update_chirho(status_chirho: &UpdateStatusChirho) {
        change_chirho(|counts_chirho| match status_chirho.path_chirho {
            PathTakenChirho::MissingLogChirho | PathTakenChirho::UnchangedChirho => {}
            PathTakenChirho::IncrementalChirho { folded_chirho } => {
                counts_chirho.records_folded_chirho += folded_chirho;
            }
            PathTakenChirho::FullFromFallbackChirho {
                verified_chirho, ..
            } => {
                counts_chirho.full_log_loads_chirho += 1;
                counts_chirho.records_folded_chirho += verified_chirho;
            }
        });
    }
}
