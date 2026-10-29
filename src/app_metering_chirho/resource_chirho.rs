// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Stores app-defined resource meters and signed usage-vector records for app-level accounting.

use crate::head_removal_chirho::{
    self, maybe_fail_head_removal_step_chirho as maybe_fail_chirho,
    HeadRemovalStepChirho::{
        AfterBranchRemoveChirho, AfterDomainRecordChirho, AfterRemovalEvidenceChirho,
    },
};
use crate::model_chirho::HashChirho;
use crate::{app_chirho, refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_economic_governance_chirho::resource_policy_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::head_transition_chirho;
use cairn_writer_head_chirho::writer_head_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "resource_chirho/gate1_authority_chirho.rs"]
pub mod gate1_authority_chirho;
#[path = "resource_chirho/policy_head_removal_chirho.rs"]
mod policy_head_removal_chirho;
#[path = "resource_chirho/policy_head_transition_chirho.rs"]
mod policy_head_transition_chirho;
#[path = "resource_chirho/status_read_model_chirho.rs"]
mod status_read_model_chirho;
#[path = "resource_chirho/usage_checkpoint_chirho.rs"]
mod usage_checkpoint_chirho;
pub use crate::economic_model_chirho::{
    append_verified_resource_usage_state_chirho, AppResourcePolicyChirho,
    ResourceActionPolicyChirho, ResourceBalanceRowChirho, ResourceBalanceScopeChirho,
    ResourceBridgeKindChirho, ResourceBridgeRefChirho, ResourceChargeChirho,
    ResourceDecisionChirho, ResourceMeterChirho, ResourceOverageChirho, ResourcePolicyInputChirho,
    ResourcePolicyRecordChirho, ResourcePolicyUnsetRecordChirho, ResourceRollupAxisChirho,
    ResourceRollupRowChirho, ResourceUsageInputChirho, ResourceUsageRecordChirho,
    VerifiedResourcePolicyStateChirho, VerifiedResourcePolicyUnsetStateChirho,
    VerifiedResourceStatesChirho, RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO,
    RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO, RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO,
    RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO,
};
pub use policy_head_removal_chirho::{
    recover_resource_policy_head_removal_chirho, PolicyHeadRemovalRecoveryOutcomeChirho,
};
pub use status_read_model_chirho::{resource_rollup_chirho, resource_status_chirho};

#[derive(Default)]
struct ResourceBridgeEvidenceChirho {
    billing_usage_chirho: Option<Vec<crate::economic_model_chirho::BillingUsageRecordChirho>>,
}

pub(crate) const RESOURCE_POLICY_RECORDS_LOG_CHIRHO: &str = "resource-policy-records-chirho.jsonl";

fn policy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(RESOURCE_POLICY_RECORDS_LOG_CHIRHO)
}

pub(crate) const RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO: &str =
    "resource-policy-unset-records-chirho.jsonl";

fn policy_unset_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO)
}

fn usage_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("resource-usage-chirho.jsonl")
}

fn resource_policy_ref_chirho(app_chirho: &str) -> String {
    format!("resource-policy/{app_chirho}")
}

fn resource_policy_lock_name_chirho(app_chirho: &str) -> String {
    format!("resource-policy/{app_chirho}")
}

fn with_resource_policy_authority_scope_chirho<T, F>(
    root_chirho: &Path,
    app_chirho: &str,
    action_chirho: F,
) -> Result<T>
where
    F: FnOnce(&writer_head_chirho::WriterFenceTokenChirho) -> Result<T>,
{
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &resource_policy_lock_name_chirho(app_chirho),
        || writer_head_chirho::with_gate1_authority_scope_chirho(root_chirho, action_chirho),
    )
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn set_resource_policy_from_input_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    input_chirho: ResourcePolicyInputChirho,
) -> Result<(
    HashChirho,
    AppResourcePolicyChirho,
    ResourcePolicyRecordChirho,
)> {
    set_resource_policy_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        input_chirho.meters_chirho,
        input_chirho.actions_chirho,
    )
}

pub fn preview_resource_policy_from_input_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    input_chirho: ResourcePolicyInputChirho,
    at_ms_chirho: u64,
) -> Result<(HashChirho, AppResourcePolicyChirho)> {
    resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    // ROAD-AWARE: this is the WRITE path, reading the previous hash before appending.
    let previous_chirho = current_resource_policy_hash_chirho(root_chirho, app_chirho)?;
    let policy_chirho = resource_policy_chirho::propose_resource_policy_chirho(
        app_chirho,
        owner_principal_chirho,
        input_chirho.meters_chirho,
        input_chirho.actions_chirho,
        previous_chirho,
        at_ms_chirho,
    )?;
    let hash_chirho = store_chirho::hash_object_chirho(&policy_chirho)?;
    Ok((hash_chirho, policy_chirho))
}

pub fn set_resource_policy_from_input_checked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    input_chirho: ResourcePolicyInputChirho,
    expected_previous_chirho: Option<HashChirho>,
    reviewed_policy_chirho: HashChirho,
    at_ms_chirho: u64,
) -> Result<(
    HashChirho,
    AppResourcePolicyChirho,
    ResourcePolicyRecordChirho,
)> {
    set_resource_policy_chirho_with_expected_chirho(ResourcePolicySetInputChirho {
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        meters_chirho: input_chirho.meters_chirho,
        actions_chirho: input_chirho.actions_chirho,
        expected_previous_chirho: Some(expected_previous_chirho),
        reviewed_policy_chirho: Some(reviewed_policy_chirho),
        at_ms_chirho,
    })
}

pub fn set_resource_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    meters_chirho: Vec<ResourceMeterChirho>,
    actions_chirho: Vec<ResourceActionPolicyChirho>,
) -> Result<(
    HashChirho,
    AppResourcePolicyChirho,
    ResourcePolicyRecordChirho,
)> {
    set_resource_policy_chirho_with_expected_chirho(ResourcePolicySetInputChirho {
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        meters_chirho,
        actions_chirho,
        expected_previous_chirho: None,
        reviewed_policy_chirho: None,
        at_ms_chirho: now_ms_chirho(),
    })
}

struct ResourcePolicySetInputChirho<'a> {
    root_chirho: &'a Path,
    app_chirho: &'a str,
    owner_principal_chirho: &'a str,
    meters_chirho: Vec<ResourceMeterChirho>,
    actions_chirho: Vec<ResourceActionPolicyChirho>,
    expected_previous_chirho: Option<Option<HashChirho>>,
    reviewed_policy_chirho: Option<HashChirho>,
    at_ms_chirho: u64,
}

fn set_resource_policy_chirho_with_expected_chirho(
    input_chirho: ResourcePolicySetInputChirho<'_>,
) -> Result<(
    HashChirho,
    AppResourcePolicyChirho,
    ResourcePolicyRecordChirho,
)> {
    let ResourcePolicySetInputChirho {
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        meters_chirho,
        actions_chirho,
        expected_previous_chirho,
        reviewed_policy_chirho,
        at_ms_chirho,
    } = input_chirho;
    resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |writer_fence_chirho| {
        if policy_head_removal_chirho::policy_removal_recovery_needed_chirho(
            root_chirho,
            app_chirho,
        )? {
            policy_head_removal_chirho::recover_resource_policy_head_removal_unlocked_chirho(
                root_chirho,
                app_chirho,
                writer_fence_chirho,
            )?;
        }
        policy_head_transition_chirho::recover_resource_policy_head_transition_unlocked_chirho(
            root_chirho,
            app_chirho,
            writer_fence_chirho,
        )?;
        // ROAD-AWARE: the writer-fence compare-and-swap against `expected_previous_chirho`.
        let previous_chirho = current_resource_policy_hash_chirho(root_chirho, app_chirho)?;
        if let Some(expected_previous_chirho) = expected_previous_chirho {
            if previous_chirho != expected_previous_chirho {
                bail!("resource policy expected previous hash mismatch");
            }
        }
        let policy_chirho = resource_policy_chirho::propose_resource_policy_chirho(
            app_chirho,
            owner_principal_chirho,
            meters_chirho,
            actions_chirho,
            previous_chirho.clone(),
            at_ms_chirho,
        )?;
        let hash_chirho = store_chirho::hash_object_chirho(&policy_chirho)?;
        if let Some(reviewed_policy_chirho) = reviewed_policy_chirho {
            if hash_chirho != reviewed_policy_chirho {
                bail!("resource policy reviewed hash mismatch");
            }
        }
        let stored_hash_chirho = store_chirho::put_object_chirho(root_chirho, &policy_chirho)?;
        if stored_hash_chirho != hash_chirho {
            bail!("resource policy stored hash mismatch");
        }
        // Floor this set's record at_ms strictly above the latest unset event, mirroring the unset
        // side's floor above the latest set: otherwise a same-millisecond or clock-regressed set can
        // complete (ref moved, receipt minted) while the last-event rule still ranks a prior unset
        // ahead of it, wedging the app's reads and further writes behind a receipt that claims Applied.
        let min_at_ms_chirho =
            verified_resource_states_with_options_chirho(root_chirho, true, false)?
                .policy_unset_records_chirho
                .values()
                .rev()
                .find(|state_chirho| state_chirho.app_chirho == app_chirho)
                .map(|state_chirho| state_chirho.at_ms_chirho + 1)
                .unwrap_or(0);
        let record_chirho = gate1_authority_chirho::append_resource_policy_record_unlocked_chirho(
            root_chirho,
            writer_fence_chirho,
            app_chirho,
            owner_principal_chirho,
            hash_chirho.clone(),
            previous_chirho,
            min_at_ms_chirho,
        )?;
        let roundtrip_chirho = load_resource_policy_records_chirho(root_chirho)?
            .into_iter()
            .find(|row_chirho| row_chirho.seq_chirho == record_chirho.seq_chirho)
            .ok_or_else(|| {
                anyhow!("new resource policy record did not round-trip at its signed sequence")
            })?;
        if roundtrip_chirho != record_chirho {
            bail!("new resource policy record diverges from its physical log row");
        }
        let prepared_chirho =
            policy_head_transition_chirho::prepared_from_verified_policy_record_chirho(
                root_chirho,
                &record_chirho,
            )?;
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            root_chirho,
            &prepared_chirho,
            writer_fence_chirho,
        )?;
        Ok((hash_chirho, policy_chirho, record_chirho))
    })
}

pub fn unset_resource_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<Option<ResourcePolicyUnsetRecordChirho>> {
    resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |writer_fence_chirho| {
        policy_head_transition_chirho::recover_resource_policy_head_transition_unlocked_chirho(
            root_chirho,
            app_chirho,
            writer_fence_chirho,
        )?;
        policy_head_removal_chirho::unset_resource_policy_head_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_principal_chirho,
            writer_fence_chirho,
        )
    })
}

/// The raw ref head, receipt-gated both ways.
///
/// Absence is checked as deliberately as presence -- a missing head must be RECEIPTED absent, not
/// merely absent, or a removed policy and a policy that never existed would be indistinguishable.
fn current_resource_policy_hash_receipted_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HashChirho>> {
    let current_chirho = refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&resource_policy_ref_chirho(app_chirho))
        .cloned();
    match &current_chirho {
        None => {
            policy_head_removal_chirho::verify_receipted_policy_absence_chirho(
                root_chirho,
                app_chirho,
            )?;
        }
        Some(head_chirho) => {
            policy_head_transition_chirho::require_selected_policy_head_chirho(
                root_chirho,
                app_chirho,
                head_chirho,
            )?;
        }
    }
    Ok(current_chirho)
}

/// The current resource policy hash: probe, then the receipted head. One road, one read.
///
/// **Writers came through a separate road-aware door until CF6 wave-1, and the reason expired with
/// the road.** The split existed because a writer must run on whichever road is ACTIVE -- a
/// transition you cannot write during is not a transition -- so routing writes through a probe that
/// refuses flipped roots would have broken writes on exactly the roots the probe exists to notice.
/// Wave-1 deleted the second road and its only writer, so a root carrying that branch is no longer
/// mid-transition; it is ambiguous, and refusing a WRITE on it is at least as right as refusing a
/// read. The doors merged rather than one being kept as a synonym.
pub fn current_resource_policy_hash_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HashChirho>> {
    resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho(
        root_chirho,
    )?;
    current_resource_policy_hash_receipted_chirho(root_chirho, app_chirho)
}

pub fn current_resource_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<(HashChirho, AppResourcePolicyChirho)>> {
    let Some(hash_chirho) = current_resource_policy_hash_chirho(root_chirho, app_chirho)? else {
        return Ok(None);
    };
    let policy_chirho: AppResourcePolicyChirho =
        store_chirho::get_object_chirho(root_chirho, &hash_chirho)?;
    resource_policy_chirho::validate_resource_policy_chirho(&policy_chirho)?;
    if policy_chirho.app_chirho != app_chirho {
        bail!(
            "resource policy ref for app '{app_chirho}' points at policy for '{}'",
            policy_chirho.app_chirho
        );
    }
    Ok(Some((hash_chirho, policy_chirho)))
}

pub fn resource_policy_history_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Vec<ResourcePolicyRecordChirho>> {
    resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    Ok(load_resource_policy_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
        .collect())
}

pub fn load_resource_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ResourcePolicyRecordChirho>> {
    let records_chirho: Vec<ResourcePolicyRecordChirho> =
        load_jsonl_chirho(&policy_records_path_chirho(root_chirho))?;
    for record_chirho in &records_chirho {
        let schema_chirho = record_chirho.schema_chirho.as_str();
        if !schema_chirho.is_empty()
            && schema_chirho != RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO
            && schema_chirho != RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO
        {
            bail!(
                "resource policy record {} has unsupported schema '{schema_chirho}'",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

pub fn load_resource_policy_unset_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ResourcePolicyUnsetRecordChirho>> {
    let records_chirho: Vec<ResourcePolicyUnsetRecordChirho> =
        load_jsonl_chirho(&policy_unset_records_path_chirho(root_chirho))?;
    for record_chirho in &records_chirho {
        validate_resource_record_schema_chirho(
            &record_chirho.schema_chirho,
            RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO,
            "resource policy unset record",
            record_chirho.seq_chirho,
        )?;
    }
    Ok(records_chirho)
}

pub fn load_resource_usage_chirho(root_chirho: &Path) -> Result<Vec<ResourceUsageRecordChirho>> {
    let records_chirho: Vec<ResourceUsageRecordChirho> =
        load_jsonl_chirho(&usage_records_path_chirho(root_chirho))?;
    for record_chirho in &records_chirho {
        validate_resource_record_schema_chirho(
            &record_chirho.schema_chirho,
            RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO,
            "resource usage record",
            record_chirho.seq_chirho,
        )?;
    }
    note_usage_full_load_chirho(records_chirho.len() as u64);
    Ok(records_chirho)
}

// F3 count-based scaling-guard hooks: the whole-usage-log reads the pre-checkpoint gated append paid
// on every request. `note_usage_full_load_chirho` counts EVERY whole-file read of
// `resource-usage-chirho.jsonl` — both the typed `load_resource_usage_chirho` and the physical-line
// `resource_usage_lines_chirho` reader that the Gate-1 envelope's tail lookups used to funnel through
// — so a warm gated append must trigger ZERO of them. `note_usage_tail_bytes_chirho` counts the bytes
// the bounded backward-seek tail reader touches, proving the replacement is O(last-line length) — a
// small per-op constant, never the whole history. `#[cfg(test)]` so production pays nothing; no-op
// stand-ins keep the call sites compiling in release builds.
#[cfg(test)]
thread_local! {
    static USAGE_FULL_LOAD_COUNT_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static USAGE_ROWS_LOADED_COUNT_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static USAGE_TAIL_BYTES_READ_COUNT_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_usage_full_load_chirho(rows_chirho: u64) {
    USAGE_FULL_LOAD_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
    USAGE_ROWS_LOADED_COUNT_CHIRHO
        .with(|count_chirho| count_chirho.set(count_chirho.get() + rows_chirho));
}

#[cfg(not(test))]
#[inline(always)]
fn note_usage_full_load_chirho(_rows_chirho: u64) {}

#[cfg(test)]
fn note_usage_tail_bytes_chirho(bytes_chirho: u64) {
    USAGE_TAIL_BYTES_READ_COUNT_CHIRHO
        .with(|count_chirho| count_chirho.set(count_chirho.get() + bytes_chirho));
}

#[cfg(not(test))]
#[inline(always)]
fn note_usage_tail_bytes_chirho(_bytes_chirho: u64) {}

#[cfg(test)]
fn reset_usage_load_counts_chirho() {
    USAGE_FULL_LOAD_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(0));
    USAGE_ROWS_LOADED_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(0));
    USAGE_TAIL_BYTES_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.set(0));
}

#[cfg(test)]
fn usage_full_load_count_chirho() -> u64 {
    USAGE_FULL_LOAD_COUNT_CHIRHO.with(|count_chirho| count_chirho.get())
}

#[cfg(test)]
fn usage_rows_loaded_count_chirho() -> u64 {
    USAGE_ROWS_LOADED_COUNT_CHIRHO.with(|count_chirho| count_chirho.get())
}

#[cfg(test)]
fn usage_tail_bytes_read_count_chirho() -> u64 {
    USAGE_TAIL_BYTES_READ_COUNT_CHIRHO.with(|count_chirho| count_chirho.get())
}

pub fn record_resource_usage_chirho(
    root_chirho: &Path,
    input_chirho: ResourceUsageInputChirho,
) -> Result<ResourceUsageRecordChirho> {
    resource_policy_chirho::validate_app_name_chirho(&input_chirho.app_chirho)?;
    resource_policy_chirho::validate_principal_label_chirho(
        "user_chirho",
        &input_chirho.user_chirho,
    )?;
    let actor_value_chirho = input_chirho
        .actor_chirho
        .clone()
        .unwrap_or_else(|| input_chirho.user_chirho.clone());
    resource_policy_chirho::validate_principal_label_chirho("actor_chirho", &actor_value_chirho)?;
    resource_policy_chirho::validate_plain_id_chirho(
        "section_chirho",
        &input_chirho.section_chirho,
    )?;
    resource_policy_chirho::validate_plain_id_chirho("action_chirho", &input_chirho.action_chirho)?;
    if let Some(effect_chirho) = &input_chirho.effect_chirho {
        resource_policy_chirho::validate_plain_id_chirho("effect_chirho", effect_chirho)?;
    }
    if let Some(run_chirho) = &input_chirho.run_chirho {
        if run_chirho.0.trim().is_empty() {
            bail!("run_chirho must not be empty");
        }
    }
    let mut bridge_evidence_chirho = ResourceBridgeEvidenceChirho::default();
    validate_resource_bridges_chirho(
        root_chirho,
        &input_chirho.app_chirho,
        &input_chirho.user_chirho,
        input_chirho.effect_chirho.as_deref(),
        input_chirho.run_chirho.as_ref(),
        &input_chirho.bridges_chirho,
        &mut bridge_evidence_chirho,
    )?;

    writer_head_chirho::with_gate1_authority_scope_chirho(root_chirho, |writer_fence_chirho| {
        gate1_authority_chirho::append_resource_usage_unlocked_chirho(
            root_chirho,
            writer_fence_chirho,
            input_chirho,
            actor_value_chirho,
        )
    })
}

pub fn verify_resource_policies_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(
        verified_resource_states_with_options_chirho(root_chirho, false, false)?
            .policy_record_count_chirho,
    )
}

/// Load the old-road policy records only after every one of their signatures verifies, so callers
/// that select a head from this list can trust the row bytes (mirrors the billing precedent's
/// `verified_billing_policy_records_old_road_chirho`). A forged or tampered row fails closed here
/// before any read gate or recovery trusts it.
pub(super) fn verified_resource_policy_records_old_road_chirho(
    root_chirho: &Path,
) -> Result<Vec<ResourcePolicyRecordChirho>> {
    let records_chirho = load_resource_policy_records_chirho(root_chirho)?;
    verified_resource_states_from_records_chirho(
        root_chirho,
        false,
        false,
        &records_chirho,
        &[],
        &[],
    )?;
    Ok(records_chirho)
}

pub fn verify_resource_policy_unsets_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(
        verified_resource_states_with_options_chirho(root_chirho, true, false)?
            .policy_unset_record_count_chirho,
    )
}

pub fn verify_resource_usage_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(
        verified_resource_states_with_options_chirho(root_chirho, false, true)?
            .usage_record_count_chirho,
    )
}

pub fn verified_resource_states_chirho(root_chirho: &Path) -> Result<VerifiedResourceStatesChirho> {
    verified_resource_states_with_options_chirho(root_chirho, true, true)
}

fn verified_resource_states_with_options_chirho(
    root_chirho: &Path,
    include_unsets_chirho: bool,
    include_usage_chirho: bool,
) -> Result<VerifiedResourceStatesChirho> {
    let records_chirho = load_resource_policy_records_chirho(root_chirho)?;
    let unset_records_chirho = load_resource_policy_unset_records_chirho(root_chirho)?;
    // Load the (per-request-growing) usage log only when this call actually verifies usage. Callers
    // that only want policy/unset state — the hot policy-head read on every gated append among them —
    // pass `include_usage_chirho = false`, and `verified_resource_states_from_records_chirho` ignores
    // the usage slice in that case, so loading it was pure O(n) waste on the append path.
    let usage_records_chirho = if include_usage_chirho {
        load_resource_usage_chirho(root_chirho)?
    } else {
        Vec::new()
    };
    verified_resource_states_from_records_chirho(
        root_chirho,
        include_unsets_chirho,
        include_usage_chirho,
        &records_chirho,
        &unset_records_chirho,
        &usage_records_chirho,
    )
}

fn verified_resource_states_from_records_chirho(
    root_chirho: &Path,
    include_unsets_chirho: bool,
    include_usage_chirho: bool,
    records_chirho: &[ResourcePolicyRecordChirho],
    unset_records_chirho: &[ResourcePolicyUnsetRecordChirho],
    usage_records_chirho: &[ResourceUsageRecordChirho],
) -> Result<VerifiedResourceStatesChirho> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut states_chirho = VerifiedResourceStatesChirho {
        policy_record_count_chirho: records_chirho.len(),
        ..VerifiedResourceStatesChirho::default()
    };
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "resource policy seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        resource_policy_chirho::validate_app_name_chirho(&record_chirho.app_chirho)?;
        app_chirho::ensure_app_owner_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let policy_chirho: AppResourcePolicyChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.resource_policy_chirho)?;
        resource_policy_chirho::validate_resource_policy_chirho(&policy_chirho)?;
        if policy_chirho.app_chirho != record_chirho.app_chirho {
            bail!(
                "resource policy record {} app mismatch",
                record_chirho.seq_chirho
            );
        }
        if policy_chirho.owner_principal_chirho != record_chirho.owner_principal_chirho {
            bail!(
                "resource policy record {} owner mismatch",
                record_chirho.seq_chirho
            );
        }
        if policy_chirho.previous_chirho != record_chirho.previous_chirho {
            bail!(
                "resource policy record {} previous hash mismatch",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = resource_policy_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "resource policy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        states_chirho.policy_records_chirho.insert(
            record_chirho.seq_chirho,
            VerifiedResourcePolicyStateChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
                resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
                previous_chirho: record_chirho.previous_chirho.clone(),
                at_ms_chirho: record_chirho.at_ms_chirho,
            },
        );
    }

    if include_unsets_chirho {
        let policy_hashes_chirho: BTreeSet<(String, HashChirho)> = records_chirho
            .iter()
            .map(|record_chirho| {
                (
                    record_chirho.app_chirho.clone(),
                    record_chirho.resource_policy_chirho.clone(),
                )
            })
            .collect();
        states_chirho.policy_unset_record_count_chirho = unset_records_chirho.len();
        for (i_chirho, record_chirho) in unset_records_chirho.iter().enumerate() {
            if record_chirho.seq_chirho != i_chirho as u64 {
                bail!(
                    "resource policy unset seq gap at index {i_chirho}: entry seq is {}",
                    record_chirho.seq_chirho
                );
            }
            resource_policy_chirho::validate_app_name_chirho(&record_chirho.app_chirho)?;
            app_chirho::ensure_app_owner_chirho(
                root_chirho,
                &record_chirho.app_chirho,
                &record_chirho.owner_principal_chirho,
            )?;
            if !policy_hashes_chirho.contains(&(
                record_chirho.app_chirho.clone(),
                record_chirho.previous_chirho.clone(),
            )) {
                bail!(
                    "resource policy unset record {} points at unknown previous policy",
                    record_chirho.seq_chirho
                );
            }
            let policy_chirho: AppResourcePolicyChirho =
                store_chirho::get_object_chirho(root_chirho, &record_chirho.previous_chirho)?;
            resource_policy_chirho::validate_resource_policy_chirho(&policy_chirho)?;
            if policy_chirho.app_chirho != record_chirho.app_chirho {
                bail!(
                    "resource policy unset record {} app mismatch",
                    record_chirho.seq_chirho
                );
            }
            if policy_chirho.owner_principal_chirho != record_chirho.owner_principal_chirho {
                bail!(
                    "resource policy unset record {} owner mismatch",
                    record_chirho.seq_chirho
                );
            }
            let message_chirho = resource_policy_unset_record_message_chirho(record_chirho)?;
            if !signer_chirho::verify_with_pubkey_chirho(
                &pubkey_chirho,
                &message_chirho,
                &record_chirho.sig_chirho,
            )? {
                bail!(
                    "resource policy unset record {} signature invalid",
                    record_chirho.seq_chirho
                );
            }
            states_chirho.policy_unset_records_chirho.insert(
                record_chirho.seq_chirho,
                VerifiedResourcePolicyUnsetStateChirho {
                    app_chirho: record_chirho.app_chirho.clone(),
                    owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
                    previous_chirho: record_chirho.previous_chirho.clone(),
                    at_ms_chirho: record_chirho.at_ms_chirho,
                },
            );
        }
    }

    if include_usage_chirho {
        states_chirho.usage_record_count_chirho = usage_records_chirho.len();
        let mut bridge_evidence_chirho = ResourceBridgeEvidenceChirho::default();
        for (i_chirho, record_chirho) in usage_records_chirho.iter().enumerate() {
            if record_chirho.seq_chirho != i_chirho as u64 {
                bail!(
                    "resource usage seq gap at index {i_chirho}: entry seq is {}",
                    record_chirho.seq_chirho
                );
            }
            resource_policy_chirho::validate_resource_usage_record_chirho(record_chirho)?;
            let policy_chirho: AppResourcePolicyChirho = store_chirho::get_object_chirho(
                root_chirho,
                &record_chirho.resource_policy_chirho,
            )?;
            resource_policy_chirho::validate_resource_policy_chirho(&policy_chirho)?;
            if policy_chirho.app_chirho != record_chirho.app_chirho {
                bail!(
                    "resource usage record {} app mismatch",
                    record_chirho.seq_chirho
                );
            }
            let action_policy_chirho = resource_policy_chirho::find_action_policy_chirho(
                &policy_chirho,
                &record_chirho.section_chirho,
                &record_chirho.action_chirho,
                record_chirho.effect_chirho.as_deref(),
            )?;
            if action_policy_chirho.charges_chirho != record_chirho.charges_chirho {
                bail!(
                    "resource usage record {} charge vector does not match policy action",
                    record_chirho.seq_chirho
                );
            }
            let expected_chirho = resource_policy_chirho::decide_resource_usage_chirho(
                &policy_chirho,
                &record_chirho.resource_policy_chirho,
                &usage_records_chirho[..i_chirho],
                &record_chirho.app_chirho,
                &record_chirho.user_chirho,
                &record_chirho.charges_chirho,
                record_chirho.at_ms_chirho,
            )?;
            if expected_chirho != record_chirho.decision_chirho {
                bail!(
                    "resource usage record {} decision mismatch",
                    record_chirho.seq_chirho
                );
            }
            validate_resource_bridges_chirho(
                root_chirho,
                &record_chirho.app_chirho,
                &record_chirho.user_chirho,
                record_chirho.effect_chirho.as_deref(),
                record_chirho.run_chirho.as_ref(),
                &record_chirho.bridges_chirho,
                &mut bridge_evidence_chirho,
            )?;
            let message_chirho = resource_usage_record_message_chirho(record_chirho)?;
            if !signer_chirho::verify_with_pubkey_chirho(
                &pubkey_chirho,
                &message_chirho,
                &record_chirho.sig_chirho,
            )? {
                bail!(
                    "resource usage record {} signature invalid",
                    record_chirho.seq_chirho
                );
            }
            append_verified_resource_usage_state_chirho(&mut states_chirho, record_chirho)?;
        }
    }

    Ok(states_chirho)
}

fn validate_resource_bridges_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    user_chirho: &str,
    effect_chirho: Option<&str>,
    run_chirho: Option<&HashChirho>,
    bridges_chirho: &[ResourceBridgeRefChirho],
    bridge_evidence_chirho: &mut ResourceBridgeEvidenceChirho,
) -> Result<()> {
    let mut seen_chirho = BTreeSet::new();
    for bridge_chirho in bridges_chirho {
        if !seen_chirho.insert((bridge_chirho.kind_chirho, bridge_chirho.seq_chirho)) {
            bail!(
                "duplicate resource bridge {:?}:{}",
                bridge_chirho.kind_chirho,
                bridge_chirho.seq_chirho
            );
        }
        match bridge_chirho.kind_chirho {
            ResourceBridgeKindChirho::BillingUsageChirho => validate_billing_bridge_chirho(
                root_chirho,
                app_chirho,
                user_chirho,
                effect_chirho,
                run_chirho,
                bridge_chirho.seq_chirho,
                bridge_evidence_chirho,
            )?,
            ResourceBridgeKindChirho::ExternalUsageChirho => {
                bail!("legacy external-usage resource bridges are unavailable after CF6")
            }
            ResourceBridgeKindChirho::ProviderInvoiceChirho => {}
        }
    }
    Ok(())
}

fn billing_bridge_records_chirho<'a>(
    root_chirho: &Path,
    bridge_evidence_chirho: &'a mut ResourceBridgeEvidenceChirho,
) -> Result<&'a [crate::economic_model_chirho::BillingUsageRecordChirho]> {
    if bridge_evidence_chirho.billing_usage_chirho.is_none() {
        crate::legacy_billing_evidence_chirho::verify_billing_usage_single_road_chirho(
            root_chirho,
        )?;
        bridge_evidence_chirho.billing_usage_chirho =
            Some(crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(root_chirho)?);
    }
    Ok(bridge_evidence_chirho
        .billing_usage_chirho
        .as_deref()
        .unwrap_or(&[]))
}

fn validate_billing_bridge_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    user_chirho: &str,
    effect_chirho: Option<&str>,
    run_chirho: Option<&HashChirho>,
    seq_chirho: u64,
    bridge_evidence_chirho: &mut ResourceBridgeEvidenceChirho,
) -> Result<()> {
    let records_chirho = billing_bridge_records_chirho(root_chirho, bridge_evidence_chirho)?;
    let Some(record_chirho) = records_chirho.get(seq_chirho as usize) else {
        bail!("resource bridge points at missing billing usage #{seq_chirho}");
    };
    if record_chirho.seq_chirho != seq_chirho {
        bail!("billing usage bridge seq mismatch at index {seq_chirho}");
    }
    if record_chirho.app_chirho != app_chirho {
        bail!("billing usage bridge app mismatch for #{seq_chirho}");
    }
    if record_chirho.caller_chirho != user_chirho
        && record_chirho.billing_tags_chirho.user_id_chirho.as_deref() != Some(user_chirho)
    {
        bail!("billing usage bridge user mismatch for #{seq_chirho}");
    }
    if effect_chirho.is_some_and(|effect_chirho| effect_chirho != record_chirho.effect_chirho) {
        bail!("billing usage bridge effect mismatch for #{seq_chirho}");
    }
    if let Some(run_chirho) = run_chirho {
        if record_chirho.billing_tags_chirho.run_id_chirho.as_ref() != Some(run_chirho) {
            bail!("billing usage bridge run mismatch for #{seq_chirho}");
        }
    }
    Ok(())
}

fn append_resource_policy_record_old_road_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    resource_policy_chirho: HashChirho,
    previous_chirho: Option<HashChirho>,
    prepared_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
    min_at_ms_chirho: u64,
) -> Result<ResourcePolicyRecordChirho> {
    let path_chirho = policy_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = ResourcePolicyRecordChirho {
            seq_chirho,
            schema_chirho: RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            resource_policy_chirho: resource_policy_chirho.clone(),
            previous_chirho: previous_chirho.clone(),
            at_ms_chirho: now_ms_chirho().max(min_at_ms_chirho),
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho),
            sig_chirho: String::new(),
        };
        record_chirho.transition_id_chirho =
            policy_head_transition_chirho::derive_policy_record_transition_id_chirho(
                root_chirho,
                &record_chirho,
            )?;
        let message_chirho = resource_policy_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn append_resource_policy_unset_record_old_road_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    previous_chirho: HashChirho,
    min_at_ms_chirho: u64,
) -> Result<ResourcePolicyUnsetRecordChirho> {
    let path_chirho = policy_unset_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        resource_policy_unset_record_for_seq_chirho(
            seq_chirho,
            app_chirho,
            owner_principal_chirho,
            previous_chirho.clone(),
            root_chirho,
            min_at_ms_chirho,
        )
    })
}

fn append_resource_usage_old_road_unlocked_chirho(
    root_chirho: &Path,
    input_chirho: ResourceUsageInputChirho,
    actor_value_chirho: String,
) -> Result<ResourceUsageRecordChirho> {
    let path_chirho = usage_records_path_chirho(root_chirho);
    let seq_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
    let (policy_hash_chirho, policy_chirho) =
        current_resource_policy_chirho(root_chirho, &input_chirho.app_chirho)?
            .ok_or_else(|| anyhow!("app '{}' has no resource policy", input_chirho.app_chirho))?;
    let action_policy_chirho = resource_policy_chirho::find_action_policy_chirho(
        &policy_chirho,
        &input_chirho.section_chirho,
        &input_chirho.action_chirho,
        input_chirho.effect_chirho.as_deref(),
    )?;
    let charges_chirho = action_policy_chirho.charges_chirho.clone();
    // O(1) windowed aggregate replaces the whole-log load plus O(n) quota aggregation the gated
    // append used to pay on every request. `load_or_rebuild_chirho` reads the durable checkpoint and
    // rebuilds it from a single full scan only on a stale-guard miss (log grew/shrank out of band, or
    // the enforced policy changed); a warm request stays O(window). The decision is computed back
    // through `decide_resource_usage_chirho`, so the outcome is byte-identical to the full scan.
    let mut aggregate_chirho = usage_checkpoint_chirho::load_or_rebuild_chirho(
        root_chirho,
        &path_chirho,
        seq_chirho,
        &policy_chirho,
        &policy_hash_chirho,
        &input_chirho.app_chirho,
    )?;
    let decision_at_ms_chirho = now_ms_chirho();
    // Regression-safe decision: a warm request decides from the O(window) aggregate, but if the wall
    // clock (`decision_at_ms_chirho`) has regressed below the aggregate's high-water mark the decision
    // is taken from the row-preserving full scan instead, so a pruned-but-still-in-window prior cannot
    // silently under-count `used` and fail OPEN on this money gate.
    let decision_chirho = usage_checkpoint_chirho::decide_with_regression_guard_chirho(
        root_chirho,
        &aggregate_chirho,
        &policy_chirho,
        &policy_hash_chirho,
        &input_chirho.app_chirho,
        &input_chirho.user_chirho,
        &charges_chirho,
        decision_at_ms_chirho,
    )?;
    let mut record_chirho = ResourceUsageRecordChirho {
        seq_chirho,
        schema_chirho: RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: input_chirho.app_chirho,
        user_chirho: input_chirho.user_chirho,
        actor_chirho: actor_value_chirho,
        section_chirho: input_chirho.section_chirho,
        action_chirho: input_chirho.action_chirho,
        effect_chirho: input_chirho.effect_chirho,
        run_chirho: input_chirho.run_chirho,
        resource_policy_chirho: policy_hash_chirho,
        charges_chirho,
        bridges_chirho: input_chirho.bridges_chirho,
        decision_chirho,
        at_ms_chirho: decision_at_ms_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = resource_usage_record_message_chirho(&record_chirho)?;
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
        &path_chirho,
        seq_chirho,
        &record_chirho,
    )?;
    // Behind-never-ahead (same law as F1): the line above is durably committed, so now fold the new
    // row into the aggregate and durably rewrite the checkpoint. It is advisory — a failed rewrite is
    // swallowed and self-heals via rebuild on the next append, never turning a committed usage row
    // (and its Gate-1 receipt) into a retryable error.
    usage_checkpoint_chirho::fold_and_persist_after_append_chirho(
        &path_chirho,
        &mut aggregate_chirho,
        &record_chirho,
        &policy_chirho,
    );
    Ok(record_chirho)
}

fn resource_policy_unset_record_for_seq_chirho(
    seq_chirho: u64,
    app_chirho: &str,
    owner_principal_chirho: &str,
    previous_chirho: HashChirho,
    root_chirho: &Path,
    min_at_ms_chirho: u64,
) -> Result<ResourcePolicyUnsetRecordChirho> {
    let mut record_chirho = ResourcePolicyUnsetRecordChirho {
        seq_chirho,
        schema_chirho: RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        previous_chirho: previous_chirho.clone(),
        // A fresh unset must strictly out-order the latest set event, or a same-millisecond
        // tie would let the set-wins rule read a completed receipted removal as still set.
        at_ms_chirho: now_ms_chirho().max(min_at_ms_chirho),
        sig_chirho: String::new(),
    };
    let message_chirho = resource_policy_unset_record_message_chirho(&record_chirho)?;
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    Ok(record_chirho)
}

fn load_jsonl_chirho<T: for<'de> Deserialize<'de>>(path_chirho: &Path) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(records_chirho)
}

fn validate_resource_record_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
    seq_chirho: u64,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("{label_chirho} {seq_chirho} has unsupported schema '{schema_chirho}'");
    }
    Ok(())
}

fn nonempty_schema_chirho(schema_chirho: &str) -> Option<&str> {
    (!schema_chirho.is_empty()).then_some(schema_chirho)
}

fn resource_policy_record_message_chirho(
    record_chirho: &ResourcePolicyRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct ResourcePolicyRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        resource_policy_chirho: &'a HashChirho,
        previous_chirho: &'a Option<HashChirho>,
        at_ms_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        transition_id_chirho: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prepared_writer_fence_epoch_chirho: Option<u64>,
    }
    Ok(serde_json::to_vec(&ResourcePolicyRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        resource_policy_chirho: &record_chirho.resource_policy_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
        transition_id_chirho: nonempty_schema_chirho(&record_chirho.transition_id_chirho),
        prepared_writer_fence_epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho,
    })?)
}

fn resource_policy_unset_record_message_chirho(
    record_chirho: &ResourcePolicyUnsetRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct ResourcePolicyUnsetRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        previous_chirho: &'a HashChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(
        &ResourcePolicyUnsetRecordMessageChirho {
            seq_chirho: record_chirho.seq_chirho,
            schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
            app_chirho: &record_chirho.app_chirho,
            owner_principal_chirho: &record_chirho.owner_principal_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?)
}

fn resource_usage_record_message_chirho(
    record_chirho: &ResourceUsageRecordChirho,
) -> Result<Vec<u8>> {
    if record_chirho.schema_chirho.is_empty() && record_chirho.bridges_chirho.is_empty() {
        return legacy_resource_usage_record_message_chirho(record_chirho);
    }
    #[derive(Serialize)]
    struct ResourceUsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        user_chirho: &'a str,
        actor_chirho: &'a str,
        section_chirho: &'a str,
        action_chirho: &'a str,
        effect_chirho: &'a Option<String>,
        run_chirho: &'a Option<HashChirho>,
        resource_policy_chirho: &'a HashChirho,
        charges_chirho: &'a [ResourceChargeChirho],
        bridges_chirho: &'a [ResourceBridgeRefChirho],
        decision_chirho: &'a ResourceDecisionChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&ResourceUsageRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        user_chirho: &record_chirho.user_chirho,
        actor_chirho: &record_chirho.actor_chirho,
        section_chirho: &record_chirho.section_chirho,
        action_chirho: &record_chirho.action_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        run_chirho: &record_chirho.run_chirho,
        resource_policy_chirho: &record_chirho.resource_policy_chirho,
        charges_chirho: &record_chirho.charges_chirho,
        bridges_chirho: &record_chirho.bridges_chirho,
        decision_chirho: &record_chirho.decision_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn legacy_resource_usage_record_message_chirho(
    record_chirho: &ResourceUsageRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct ResourceUsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        app_chirho: &'a str,
        user_chirho: &'a str,
        actor_chirho: &'a str,
        section_chirho: &'a str,
        action_chirho: &'a str,
        effect_chirho: &'a Option<String>,
        run_chirho: &'a Option<HashChirho>,
        resource_policy_chirho: &'a HashChirho,
        charges_chirho: &'a [ResourceChargeChirho],
        decision_chirho: &'a ResourceDecisionChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&ResourceUsageRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        app_chirho: &record_chirho.app_chirho,
        user_chirho: &record_chirho.user_chirho,
        actor_chirho: &record_chirho.actor_chirho,
        section_chirho: &record_chirho.section_chirho,
        action_chirho: &record_chirho.action_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        run_chirho: &record_chirho.run_chirho,
        resource_policy_chirho: &record_chirho.resource_policy_chirho,
        charges_chirho: &record_chirho.charges_chirho,
        decision_chirho: &record_chirho.decision_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

#[cfg(test)]
#[path = "resource_chirho/tests_chirho.rs"]
mod tests_chirho;

#[cfg(test)]
#[path = "resource_chirho/usage_checkpoint_tests_chirho.rs"]
mod usage_checkpoint_tests_chirho;

#[cfg(test)]
#[path = "resource_chirho/gate1_dual_write_tests_chirho.rs"]
mod gate1_dual_write_tests_chirho;

#[cfg(test)]
#[path = "resource_chirho/ha2_policy_head_removal_tests_chirho.rs"]
mod ha2_policy_head_removal_tests_chirho;

#[cfg(test)]
#[path = "resource_chirho/ha2_policy_head_transition_tests_chirho.rs"]
mod ha2_policy_head_transition_tests_chirho;
