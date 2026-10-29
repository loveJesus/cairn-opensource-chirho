// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reads and AUTHENTICATES the historical signed billing evidence — usage records, compensations,
//! and the policy-record chain — so that reading it outlives the deletion of `economic_flows_chirho`.
//!
//! The money-integrity core lifted out of `billing_chirho` by CF6-D2 brick (a2-3). Road-agnostic by
//! construction: the verification cores take records AND ledger entries as parameters, so the
//! Gate-1 road selection stays behind in the spine and dies with it.
//!
//! # THE ROAD-BLIND READERS ARE A DESIGNED OMISSION, NOT A FORGOTTEN PROBE
//!
//! `load_billing_usage_chirho` and `load_billing_policy_records_chirho` do NOT call
//! [`crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho`], and
//! that is deliberate. They are readers: on a flipped root they answer from the JSONL while an
//! authority stream may be the real evidence. The same asymmetry is documented on the ledger side,
//! and for the same reason — **a subject export must be able to READ a damaged or superseded log in
//! order to DISCLOSE it, while verification is what asserts the log is whole.** A probe on the
//! reader would refuse the disclosure the export exists to make.
//!
//! The gate belongs on the VERIFY entry points, which assert wholeness and therefore must know which
//! road is authoritative. Written down because the next reader cannot otherwise tell a designed
//! omission from an oversight — which is precisely why the ledger module carries the same paragraph.
//! (Raised at pre-review by claude_chirho, #7686.)
//!
//! # What did NOT come with it, and why
//!
//! `billing_rollup_chirho` looks road-free and is not: it calls `verify_billing_usage_chirho`, a
//! three-line wrapper over the Gate-1 dispatcher, so it reaches the road selection in three hops.
//! Moving it here would make this module — whose whole purpose is to outlive the spine — depend on
//! the spine. It moves with the rebase instead, once there is a single-road billing verify for its
//! call to land on.
//!
//! Pinned by `legacy_billing_characterization_tests_chirho` (13 arms, mutation-proven 9/9 before the
//! move). Those arms live outside `src/economic_flows_chirho` on purpose: billing's own test module
//! is inside the delete scope, so its money pins protect this move and then die.
//!
//! **Reaches `cairn_signer_chirho` directly, not root's `effect_chirho`** (2026-07-26), matching
//! [`legacy_ledger_evidence_chirho`], whose header already stated the reason: those verification and
//! signing functions are one-line delegates to exactly these. Going through the delegate made this
//! module depend on `src/execution_runtime_chirho` for crypto that does not live there -- an accident
//! of where a re-export sits, not a real dependency. Removing it took the whole production
//! legacy_evidence -> execution_runtime edge to zero, which is what breaks that pillar cycle.

use crate::economic_model_chirho::billing_contract_chirho::{
    compensation_record_message_chirho, policy_record_message_chirho, usage_record_message_chirho,
    validate_app_name_chirho, validate_compensation_record_chirho, validate_policy_chirho,
    validate_usage_record_chirho, verify_billing_policy_record_schema_chirho,
    verify_billing_record_schema_chirho, verify_compensation_matches_usage_chirho,
};
use crate::economic_model_chirho::billing_postings_chirho::{
    compensation_postings_for_usage_chirho, verify_cache_hit_usage_postings_chirho,
    verify_credit_hold_usage_chirho, verify_nway_usage_postings_chirho,
};
use crate::economic_model_chirho::{
    append_verified_billing_compensation_state_chirho, append_verified_billing_usage_state_chirho,
    AppBillingPolicyChirho, AssetChirho, BillingCompensationRecordChirho,
    BillingPolicyRecordChirho, BillingRollupAxisChirho, BillingRollupRowChirho,
    BillingUsageRecordChirho, LedgerEntryChirho, VerifiedBillingStatesChirho,
    BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO, BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
};
use crate::model_chirho::HashChirho;
use crate::{app_chirho, refs_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::head_transition_chirho::HEAD_TRANSITION_ID_PREFIX_CHIRHO;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The on-disk name of the policy-record evidence log.
///
/// Moved with `policy_records_path_chirho`: an evidence file's NAME belongs with the readers that
/// resolve it, not with the writers that happen to share the module today.
pub(crate) const BILLING_POLICY_RECORDS_LOG_CHIRHO: &str = "billing-policy-records-chirho.jsonl";

pub(crate) fn policy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(BILLING_POLICY_RECORDS_LOG_CHIRHO)
}

pub(crate) fn usage_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("billing-usage-chirho.jsonl")
}

pub fn load_billing_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<BillingPolicyRecordChirho>> {
    let path_chirho = policy_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: BillingPolicyRecordChirho = serde_json::from_str(line_chirho)?;
        verify_billing_policy_record_schema_chirho(&record_chirho.schema_chirho)?;
        verify_billing_policy_record_transition_shape_chirho(&record_chirho)?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn load_billing_usage_chirho(root_chirho: &Path) -> Result<Vec<BillingUsageRecordChirho>> {
    let path_chirho = usage_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: BillingUsageRecordChirho = serde_json::from_str(line_chirho)?;
        verify_billing_record_schema_chirho(
            &record_chirho.schema_chirho,
            BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
            "billing usage record",
        )?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn billing_policy_history_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Vec<BillingPolicyRecordChirho>> {
    validate_app_name_chirho(app_chirho)?;
    Ok(load_billing_policy_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
        .collect())
}

pub(crate) fn verify_billing_policy_record_transition_shape_chirho(
    record_chirho: &BillingPolicyRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho == BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO {
        if !record_chirho
            .transition_id_chirho
            .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO)
            || record_chirho.prepared_writer_fence_epoch_chirho == Some(0)
            || record_chirho.prepared_writer_fence_epoch_chirho.is_none()
        {
            bail!("billing policy v2 record has incomplete head transition evidence");
        }
    } else if !record_chirho.transition_id_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho.is_some()
    {
        bail!("legacy billing policy record must not carry head transition evidence");
    }
    Ok(())
}

pub(crate) fn verify_billing_policy_records_from_records_chirho(
    root_chirho: &Path,
    records_chirho: &[BillingPolicyRecordChirho],
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "billing policy seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        verify_billing_policy_record_schema_chirho(&record_chirho.schema_chirho)?;
        verify_billing_policy_record_transition_shape_chirho(record_chirho)?;
        validate_app_name_chirho(&record_chirho.app_chirho)?;
        app_chirho::ensure_app_owner_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let policy_chirho: AppBillingPolicyChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.billing_policy_chirho)?;
        validate_policy_chirho(&policy_chirho)?;
        if policy_chirho.app_chirho != record_chirho.app_chirho {
            bail!(
                "billing policy record {} app mismatch",
                record_chirho.seq_chirho
            );
        }
        if policy_chirho.owner_principal_chirho != record_chirho.owner_principal_chirho {
            bail!(
                "billing policy record {} owner mismatch",
                record_chirho.seq_chirho
            );
        }
        if policy_chirho.previous_chirho != record_chirho.previous_chirho {
            bail!(
                "billing policy record {} previous hash mismatch",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = policy_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "billing policy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

pub(crate) fn verified_billing_policy_records_old_road_chirho(
    root_chirho: &Path,
) -> Result<Vec<BillingPolicyRecordChirho>> {
    let records_chirho = load_billing_policy_records_chirho(root_chirho)?;
    verify_billing_policy_records_from_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho)
}

pub(crate) fn append_verified_billing_usage_states_from_records_chirho(
    root_chirho: &Path,
    states_chirho: &mut VerifiedBillingStatesChirho,
    records_chirho: &[BillingUsageRecordChirho],
    ledger_entries_chirho: &[LedgerEntryChirho],
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    states_chirho.usage_record_count_chirho = records_chirho.len();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "billing usage seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_usage_record_chirho(record_chirho)?;
        if record_chirho.ledger_seq_chirho as usize >= ledger_entries_chirho.len() {
            bail!(
                "billing usage record {} points at missing ledger entry {}",
                record_chirho.seq_chirho,
                record_chirho.ledger_seq_chirho
            );
        }
        let ledger_entry_chirho = &ledger_entries_chirho[record_chirho.ledger_seq_chirho as usize];
        if let Some(hold_chirho) = &record_chirho.credit_hold_chirho {
            verify_credit_hold_usage_chirho(
                record_chirho,
                hold_chirho,
                ledger_entry_chirho,
                ledger_entries_chirho,
            )?;
        } else {
            let has_debit_chirho =
                ledger_entry_chirho
                    .postings_chirho
                    .iter()
                    .any(|posting_chirho| {
                        posting_chirho.account_chirho == record_chirho.payer_chirho
                            && posting_chirho.asset_chirho == AssetChirho::TokenChirho
                            && posting_chirho.amount_chirho == -record_chirho.price_chirho
                    });
            if !has_debit_chirho {
                bail!(
                    "billing usage record {} missing payer debit in ledger entry {}",
                    record_chirho.seq_chirho,
                    record_chirho.ledger_seq_chirho
                );
            }
        }
        if record_chirho.nway_settlement_chirho {
            verify_nway_usage_postings_chirho(record_chirho, ledger_entry_chirho)?;
        } else if record_chirho.cache_hit_chirho {
            verify_cache_hit_usage_postings_chirho(record_chirho, ledger_entry_chirho)?;
        } else {
            let has_credit_chirho =
                ledger_entry_chirho
                    .postings_chirho
                    .iter()
                    .any(|posting_chirho| {
                        posting_chirho.account_chirho == record_chirho.provider_chirho
                            && posting_chirho.asset_chirho == AssetChirho::TokenChirho
                            && posting_chirho.amount_chirho == record_chirho.price_chirho
                    });
            if !has_credit_chirho {
                bail!(
                    "billing usage record {} does not match ledger entry {}",
                    record_chirho.seq_chirho,
                    record_chirho.ledger_seq_chirho
                );
            }
        }
        if ledger_entry_chirho.billing_tags_chirho != record_chirho.billing_tags_chirho {
            bail!(
                "billing usage record {} tags do not match ledger entry {}",
                record_chirho.seq_chirho,
                record_chirho.ledger_seq_chirho
            );
        }
        let _price_book_chirho: crate::effect_pricing_chirho::PriceBookChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.price_book_chirho)?;
        if let Some(policy_hash_chirho) = &record_chirho.billing_policy_chirho {
            let _policy_chirho: AppBillingPolicyChirho =
                store_chirho::get_object_chirho(root_chirho, policy_hash_chirho)?;
        }
        let message_chirho = usage_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "billing usage record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        append_verified_billing_usage_state_chirho(states_chirho, record_chirho)?;
    }
    Ok(())
}

pub(crate) fn append_verified_billing_compensation_states_from_records_chirho(
    root_chirho: &Path,
    states_chirho: &mut VerifiedBillingStatesChirho,
    usage_records_chirho: &[BillingUsageRecordChirho],
    records_chirho: &[BillingCompensationRecordChirho],
    ledger_entries_chirho: &[LedgerEntryChirho],
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    states_chirho.compensation_record_count_chirho = records_chirho.len();
    let mut seen_usage_chirho = BTreeSet::new();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "billing compensation seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !seen_usage_chirho.insert(record_chirho.original_usage_seq_chirho) {
            bail!(
                "billing usage {} has more than one compensation",
                record_chirho.original_usage_seq_chirho
            );
        }
        validate_compensation_record_chirho(record_chirho)?;
        let usage_chirho = usage_records_chirho
            .get(record_chirho.original_usage_seq_chirho as usize)
            .ok_or_else(|| {
                anyhow!(
                    "billing compensation {} points at missing usage {}",
                    record_chirho.seq_chirho,
                    record_chirho.original_usage_seq_chirho
                )
            })?;
        verify_compensation_matches_usage_chirho(record_chirho, usage_chirho)?;
        let entry_chirho = ledger_entries_chirho
            .get(record_chirho.ledger_seq_chirho as usize)
            .ok_or_else(|| {
                anyhow!(
                    "billing compensation {} points at missing ledger entry {}",
                    record_chirho.seq_chirho,
                    record_chirho.ledger_seq_chirho
                )
            })?;
        let expected_postings_chirho = compensation_postings_for_usage_chirho(usage_chirho);
        if entry_chirho.postings_chirho != expected_postings_chirho {
            bail!(
                "billing compensation {} ledger entry {} postings do not compensate usage {}",
                record_chirho.seq_chirho,
                record_chirho.ledger_seq_chirho,
                record_chirho.original_usage_seq_chirho
            );
        }
        if entry_chirho.billing_tags_chirho != usage_chirho.billing_tags_chirho
            || record_chirho.billing_tags_chirho != usage_chirho.billing_tags_chirho
        {
            bail!(
                "billing compensation {} tags do not match original usage",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = compensation_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "billing compensation record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        let usage_state_chirho = states_chirho
            .usage_records_chirho
            .get(&record_chirho.original_usage_seq_chirho)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "billing compensation {} points at missing usage {}",
                    record_chirho.seq_chirho,
                    record_chirho.original_usage_seq_chirho
                )
            })?;
        append_verified_billing_compensation_state_chirho(
            states_chirho,
            record_chirho,
            &usage_state_chirho,
        )?;
    }
    Ok(())
}

pub(crate) fn append_verified_billing_usage_states_chirho(
    root_chirho: &Path,
    states_chirho: &mut VerifiedBillingStatesChirho,
) -> Result<()> {
    let records_chirho = load_billing_usage_chirho(root_chirho)?;
    let ledger_entries_chirho =
        crate::legacy_ledger_evidence_chirho::verified_entries_old_road_chirho(root_chirho)?;
    append_verified_billing_usage_states_from_records_chirho(
        root_chirho,
        states_chirho,
        &records_chirho,
        &ledger_entries_chirho,
    )
}

pub(crate) fn append_verified_billing_compensation_states_chirho(
    root_chirho: &Path,
    states_chirho: &mut VerifiedBillingStatesChirho,
) -> Result<()> {
    let records_chirho =
        crate::legacy_evidence_readers_chirho::load_billing_compensations_chirho(root_chirho)?;
    let usage_records_chirho = load_billing_usage_chirho(root_chirho)?;
    let ledger_entries_chirho =
        crate::legacy_ledger_evidence_chirho::verified_entries_old_road_chirho(root_chirho)?;
    append_verified_billing_compensation_states_from_records_chirho(
        root_chirho,
        states_chirho,
        &usage_records_chirho,
        &records_chirho,
        &ledger_entries_chirho,
    )
}

pub(crate) fn rollup_key_chirho(
    record_chirho: &BillingUsageRecordChirho,
    axis_chirho: BillingRollupAxisChirho,
) -> String {
    match axis_chirho {
        BillingRollupAxisChirho::UserChirho => record_chirho
            .billing_tags_chirho
            .user_id_chirho
            .clone()
            .unwrap_or_else(|| record_chirho.caller_chirho.clone()),
        BillingRollupAxisChirho::AppChirho => record_chirho
            .billing_tags_chirho
            .app_id_chirho
            .clone()
            .unwrap_or_else(|| record_chirho.app_chirho.clone()),
        BillingRollupAxisChirho::RunChirho => record_chirho
            .billing_tags_chirho
            .run_id_chirho
            .as_ref()
            .map(|hash_chirho| hash_chirho.0.clone())
            .unwrap_or_else(|| "(none)".to_string()),
        BillingRollupAxisChirho::EffectChirho => record_chirho
            .billing_tags_chirho
            .effect_id_chirho
            .clone()
            .unwrap_or_else(|| record_chirho.effect_chirho.clone()),
    }
}

pub fn billing_rollup_chirho(
    root_chirho: &Path,
    axis_chirho: BillingRollupAxisChirho,
) -> Result<Vec<BillingRollupRowChirho>> {
    verify_billing_usage_single_road_chirho(root_chirho)?;
    let mut rows_chirho: BTreeMap<String, BillingRollupRowChirho> = BTreeMap::new();
    for record_chirho in load_billing_usage_chirho(root_chirho)? {
        let key_chirho = rollup_key_chirho(&record_chirho, axis_chirho);
        let row_chirho = rows_chirho
            .entry(key_chirho.clone())
            .or_insert(BillingRollupRowChirho {
                key_chirho,
                usage_count_chirho: 0,
                amount_chirho: 0,
            });
        row_chirho.usage_count_chirho += 1;
        row_chirho.amount_chirho = row_chirho
            .amount_chirho
            .checked_add(record_chirho.price_chirho)
            .ok_or_else(|| anyhow!("billing rollup overflow"))?;
    }
    Ok(rows_chirho.into_values().collect())
}

/// The three verified billing reads for consumers that must outlive the spine: probe, then old road.
///
/// Named `single_road` because that is the ASSUMPTION, and
/// [`crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho`] is
/// what enforces it rather than leaving it hoped-for. Same shape as the ledger side's
/// `verified_entries_single_road_chirho`, applied three times because billing has three families.
///
/// The READERS above deliberately carry no probe — see this module's header. The gate belongs here,
/// on the calls that assert wholeness and therefore must know which road is authoritative.
pub fn verify_billing_policies_single_road_chirho(root_chirho: &Path) -> Result<usize> {
    crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho(
        root_chirho,
    )?;
    Ok(verified_billing_policy_records_old_road_chirho(root_chirho)?.len())
}

/// See [`verify_billing_policies_single_road_chirho`].
pub fn verify_billing_usage_single_road_chirho(root_chirho: &Path) -> Result<usize> {
    crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho(
        root_chirho,
    )?;
    let mut states_chirho = VerifiedBillingStatesChirho::default();
    append_verified_billing_usage_states_chirho(root_chirho, &mut states_chirho)?;
    Ok(states_chirho.usage_record_count_chirho)
}

/// See [`verify_billing_policies_single_road_chirho`].
///
/// **THE USAGE APPEND IS LOAD-BEARING AND MUST COME FIRST.** A compensation record names the usage
/// record it reverses, and the compensation binder resolves that name against the usage states this
/// call populates — so without it every compensation refuses with "points at missing usage 0". The
/// first draft of this function dropped it, and SEVEN of the spine's own tests went red; the 13-arm
/// acceptance pin did not catch it, because its only compensation arm drives an EMPTY root, where
/// zero is the right answer either way. Do not "simplify" this to the compensation append alone.
pub fn verify_billing_compensations_single_road_chirho(root_chirho: &Path) -> Result<usize> {
    crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho(
        root_chirho,
    )?;
    let mut states_chirho = VerifiedBillingStatesChirho::default();
    append_verified_billing_usage_states_chirho(root_chirho, &mut states_chirho)?;
    append_verified_billing_compensation_states_chirho(root_chirho, &mut states_chirho)?;
    Ok(states_chirho.compensation_record_count_chirho)
}

pub(crate) fn billing_ref_chirho(app_chirho: &str) -> String {
    format!("billing/{app_chirho}")
}

pub(crate) fn billing_policy_ref_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HashChirho>> {
    Ok(refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&billing_ref_chirho(app_chirho))
        .cloned())
}

pub(crate) fn require_applied_billing_policy_record_chirho(
    root_chirho: &Path,
    record_chirho: &BillingPolicyRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho == BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO {
        let prepared_chirho =
            prepared_from_verified_billing_policy_record_chirho(root_chirho, record_chirho)?;
        if !cairn_writer_head_chirho::head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("selected billing policy v2 record has no valid Applied receipt");
        }
    }
    Ok(())
}

pub(crate) fn prepared_from_verified_billing_policy_record_chirho(
    root_chirho: &Path,
    record_chirho: &BillingPolicyRecordChirho,
) -> Result<cairn_writer_head_chirho::head_transition_chirho::PreparedHeadTransitionChirho> {
    if record_chirho.schema_chirho != BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO {
        bail!("only verified billing policy v2 rows can become prepared head transitions");
    }
    let prepared_epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| {
            anyhow!("verified billing policy v2 row is missing its prepared fence epoch")
        })?;
    let prepared_fence_chirho =
        cairn_writer_head_chirho::writer_head_chirho::WriterFenceTokenChirho {
            group_chirho:
                cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho(
                    root_chirho,
                )?,
            epoch_chirho: prepared_epoch_chirho,
            issued_at_ms_chirho: 0,
        };
    let operation_bytes_chirho = billing_policy_transition_operation_bytes_chirho(record_chirho)?;
    let branch_chirho = billing_ref_chirho(&record_chirho.app_chirho);
    let identity_chirho =
        cairn_writer_head_chirho::head_transition_chirho::HeadTransitionIdentityInputChirho {
            family_log_chirho: BILLING_POLICY_RECORDS_LOG_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            branch_chirho: &branch_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            next_chirho: &record_chirho.billing_policy_chirho,
            reason_chirho: BILLING_POLICY_HEAD_REASON_CHIRHO,
            operation_bytes_chirho: &operation_bytes_chirho,
            prepared_fence_chirho: &prepared_fence_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        };
    cairn_writer_head_chirho::head_transition_chirho::bind_caller_verified_head_transition_chirho(
        &identity_chirho,
        &record_chirho.transition_id_chirho,
        &serde_json::to_vec(record_chirho)?,
    )
}

pub(crate) fn billing_policy_transition_operation_bytes_chirho(
    record_chirho: &BillingPolicyRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct BillingPolicyTransitionOperationChirho<'a> {
        schema_chirho: &'static str,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
    }
    Ok(serde_json::to_vec(
        &BillingPolicyTransitionOperationChirho {
            schema_chirho: BILLING_POLICY_TRANSITION_OPERATION_SCHEMA_CHIRHO,
            app_chirho: &record_chirho.app_chirho,
            owner_principal_chirho: &record_chirho.owner_principal_chirho,
        },
    )?)
}

const BILLING_POLICY_HEAD_REASON_CHIRHO: &str = "billing-policy";
const BILLING_POLICY_TRANSITION_OPERATION_SCHEMA_CHIRHO: &str =
    "billing-policy-transition-operation-v1-chirho";

/// The OLD-ROAD half of the current-policy selection, lifted out of the two-road dispatcher.
///
/// Verify the whole signed history FIRST, then let the ref select from it — that order is the point,
/// and it is pinned behaviourally by
/// `a_tampered_policy_row_the_ref_does_not_select_still_refuses_chirho`. Under select-then-verify a
/// tampered row elsewhere in the history would go unnoticed.
///
/// **No probe here, deliberately.** This is the road-specific half; the probe belongs on the public
/// entry points below, which is what makes their answer single-road. The two-road dispatcher in the
/// spine calls this for its own inactive branch and dies with the spine.
pub(crate) fn selected_current_billing_policy_record_old_road_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<BillingPolicyRecordChirho>> {
    let records_chirho = verified_billing_policy_records_old_road_chirho(root_chirho)?;
    let Some(selected_hash_chirho) = billing_policy_ref_head_chirho(root_chirho, app_chirho)?
    else {
        return Ok(None);
    };
    let selected_chirho = records_chirho
        .iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.billing_policy_chirho == selected_hash_chirho
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!("billing ref for app '{app_chirho}' does not select verified signed history")
        })?;
    require_applied_billing_policy_record_chirho(root_chirho, &selected_chirho)?;
    Ok(Some(selected_chirho))
}

/// The app's current billing policy hash for consumers that must outlive the spine: probe, then the
/// old road.
///
/// **The WRITE path must NOT come through here.** `set_billing_policy_with_caps_chirho` reads the
/// previous hash before appending, and a writer has to run on whichever road is ACTIVE — routing it
/// through a probe that refuses flipped roots would break writes on exactly the roots the probe
/// exists to notice. The spine keeps calling its two-road dispatcher directly for that.
pub fn current_billing_policy_hash_single_road_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<crate::model_chirho::HashChirho>> {
    validate_app_name_chirho(app_chirho)?;
    crate::legacy_single_road_probe_chirho::refuse_if_gate1_authority_branch_present_chirho(
        root_chirho,
    )?;
    Ok(
        selected_current_billing_policy_record_old_road_chirho(root_chirho, app_chirho)?
            .map(|record_chirho| record_chirho.billing_policy_chirho),
    )
}

/// See [`current_billing_policy_hash_single_road_chirho`]; resolves the hash to its policy object.
pub fn current_billing_policy_single_road_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<(crate::model_chirho::HashChirho, AppBillingPolicyChirho)>> {
    let Some(hash_chirho) =
        current_billing_policy_hash_single_road_chirho(root_chirho, app_chirho)?
    else {
        return Ok(None);
    };
    let policy_chirho: AppBillingPolicyChirho =
        store_chirho::get_object_chirho(root_chirho, &hash_chirho)?;
    validate_policy_chirho(&policy_chirho)?;
    if policy_chirho.app_chirho != app_chirho {
        bail!(
            "billing policy ref for app '{app_chirho}' points at policy for '{}'",
            policy_chirho.app_chirho
        );
    }
    Ok(Some((hash_chirho, policy_chirho)))
}
