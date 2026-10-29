// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Root-side glue binding the pure `cairn-usage-checkpoint-chirho` core to this crate's usage loader, meter/decision policy, and durable writer.

use super::*;

// The pure O(window) aggregate core lives in its own model-crate-only crate; the root keeps only the
// thin glue that feeds it this crate's full-scan loader (`load_resource_usage_chirho`), the metering
// and decision functions from `resource_policy_chirho`, and the durable writer. Path stability: every
// `usage_checkpoint_chirho::` reference in `resource_chirho` and its tests resolves here unchanged.
pub(super) use cairn_usage_checkpoint_chirho::UsageAggregateChirho;

// `usage_checkpoint_path_chirho` and the `fold_record_chirho` / `decide_from_aggregate_chirho`
// wrappers are reached only by this module's tests now that the crate owns the internal
// fold/decide/persist calls; `#[cfg(test)]` keeps a non-test build free of unused-item warnings while
// leaving the `usage_checkpoint_chirho::` test paths byte-stable.
#[cfg(test)]
pub(super) use cairn_usage_checkpoint_chirho::usage_checkpoint_path_chirho;

/// Fold one appended usage record into the aggregate, resolving each charge's meter through
/// `resource_policy_chirho::meter_for_chirho`.
#[cfg(test)]
pub(super) fn fold_record_chirho(
    aggregate_chirho: &mut UsageAggregateChirho,
    record_chirho: &ResourceUsageRecordChirho,
    policy_chirho: &AppResourcePolicyChirho,
) {
    cairn_usage_checkpoint_chirho::fold_record_chirho(
        aggregate_chirho,
        record_chirho,
        policy_chirho,
        resource_policy_chirho::meter_for_chirho,
    );
}

/// Decide a request from the O(window) aggregate, reusing `resource_policy_chirho`'s meter lookup and
/// production `decide_resource_usage_chirho` so the outcome is byte-identical to the full scan.
#[cfg(test)]
pub(super) fn decide_from_aggregate_chirho(
    aggregate_chirho: &UsageAggregateChirho,
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    user_chirho: &str,
    charges_chirho: &[ResourceChargeChirho],
    at_ms_chirho: u64,
) -> Result<ResourceDecisionChirho> {
    cairn_usage_checkpoint_chirho::decide_from_aggregate_chirho(
        aggregate_chirho,
        policy_chirho,
        policy_hash_chirho,
        app_chirho,
        user_chirho,
        charges_chirho,
        at_ms_chirho,
        resource_policy_chirho::meter_for_chirho,
        resource_policy_chirho::decide_resource_usage_chirho,
    )
}

/// The regression-safe entry point the gated append calls: warm decisions come from the aggregate, and
/// a detected clock regression falls back to the row-preserving full scan via `load_resource_usage_chirho`.
#[allow(clippy::too_many_arguments)]
pub(super) fn decide_with_regression_guard_chirho(
    root_chirho: &Path,
    aggregate_chirho: &UsageAggregateChirho,
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    user_chirho: &str,
    charges_chirho: &[ResourceChargeChirho],
    at_ms_chirho: u64,
) -> Result<ResourceDecisionChirho> {
    cairn_usage_checkpoint_chirho::decide_with_regression_guard_chirho(
        root_chirho,
        aggregate_chirho,
        policy_chirho,
        policy_hash_chirho,
        app_chirho,
        user_chirho,
        charges_chirho,
        at_ms_chirho,
        super::load_resource_usage_chirho,
        resource_policy_chirho::meter_for_chirho,
        resource_policy_chirho::decide_resource_usage_chirho,
    )
}

/// Load the O(1) checkpoint, or rebuild it once from `load_resource_usage_chirho` on any stale-guard miss.
pub(super) fn load_or_rebuild_chirho(
    root_chirho: &Path,
    usage_log_path_chirho: &Path,
    expected_next_seq_chirho: u64,
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
) -> Result<UsageAggregateChirho> {
    cairn_usage_checkpoint_chirho::load_or_rebuild_chirho(
        root_chirho,
        usage_log_path_chirho,
        expected_next_seq_chirho,
        policy_chirho,
        policy_hash_chirho,
        app_chirho,
        super::load_resource_usage_chirho,
        resource_policy_chirho::meter_for_chirho,
    )
}

/// Fold the appended row into the aggregate and durably rewrite the checkpoint via
/// `crate::durable_chirho::write_file_durable_chirho` (advisory: a failed write self-heals on rebuild).
pub(super) fn fold_and_persist_after_append_chirho(
    usage_log_path_chirho: &Path,
    aggregate_chirho: &mut UsageAggregateChirho,
    record_chirho: &ResourceUsageRecordChirho,
    policy_chirho: &AppResourcePolicyChirho,
) {
    cairn_usage_checkpoint_chirho::fold_and_persist_after_append_chirho(
        usage_log_path_chirho,
        aggregate_chirho,
        record_chirho,
        policy_chirho,
        resource_policy_chirho::meter_for_chirho,
        crate::durable_chirho::write_file_durable_chirho,
    );
}
