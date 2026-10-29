// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Test-only: carries the growth arms' per-thread road counters across the facade's hop onto the blocking pool, so the
//! arms keep counting a served run's work after it moved off the request's thread.
//!
//! Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.

use cairn_chirho::app_chirho::control_log_load_metrics_chirho as control_loads_chirho;
use cairn_chirho::dag_private_value_chirho::private_value_view_metrics_chirho as value_road_chirho;
use cairn_chirho::effect_chirho::run_intent_chirho::run_intent_view_metrics_chirho as run_intent_road_chirho;
use cairn_chirho::privacy_chirho::private_blob_view_metrics_chirho as blob_road_chirho;
use cairn_core_chirho::refs_chirho::reflog_read_metrics_chirho as reflog_reads_chirho;

/// What one pool task counted, taken on the pool thread and added to the awaiting thread's counts.
pub(crate) struct RoadCarryChirho {
    control_load_count_chirho: u64,
    control_load_logs_chirho: Vec<String>,
    reflog_read_count_chirho: u64,
    blob_chirho: blob_road_chirho::BlobRoadCountsChirho,
    value_chirho: value_road_chirho::ValueRoadCountsChirho,
    run_intent_chirho: run_intent_road_chirho::RunIntentRoadCountsChirho,
}

/// Wrap a pool task: start the pool thread's counters from zero, run the task, then take what it counted.
pub(crate) fn counted_chirho<OutputChirho>(
    task_chirho: impl FnOnce() -> OutputChirho,
) -> impl FnOnce() -> (OutputChirho, RoadCarryChirho) {
    move || {
        control_loads_chirho::reset_chirho();
        reflog_reads_chirho::reset_chirho();
        blob_road_chirho::reset_chirho();
        value_road_chirho::reset_chirho();
        run_intent_road_chirho::reset_chirho();
        let output_chirho = task_chirho();
        let carry_chirho = RoadCarryChirho {
            control_load_count_chirho: control_loads_chirho::count_chirho(),
            control_load_logs_chirho: control_loads_chirho::loaded_logs_chirho(),
            reflog_read_count_chirho: reflog_reads_chirho::count_chirho(),
            blob_chirho: blob_road_chirho::counts_chirho(),
            value_chirho: value_road_chirho::counts_chirho(),
            run_intent_chirho: run_intent_road_chirho::counts_chirho(),
        };
        (output_chirho, carry_chirho)
    }
}

/// On the awaiting thread: add the pool task's counts to this thread's, and hand back its output.
pub(crate) fn absorbed_chirho<OutputChirho>(
    (output_chirho, carry_chirho): (OutputChirho, RoadCarryChirho),
) -> OutputChirho {
    let RoadCarryChirho {
        control_load_count_chirho,
        control_load_logs_chirho,
        reflog_read_count_chirho,
        blob_chirho,
        value_chirho,
        run_intent_chirho,
    } = carry_chirho;
    control_loads_chirho::absorb_chirho(control_load_count_chirho, control_load_logs_chirho);
    reflog_reads_chirho::absorb_chirho(reflog_read_count_chirho);
    blob_road_chirho::absorb_chirho(blob_chirho);
    value_road_chirho::absorb_chirho(value_chirho);
    run_intent_road_chirho::absorb_chirho(run_intent_chirho);
    output_chirho
}
