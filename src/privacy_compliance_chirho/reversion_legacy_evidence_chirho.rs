// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only legacy reversion evidence: the record types, JSONL loads, and schema validators
//! retained for historical subject-export/compliance evidence after the legacy reversion engine
//! deletes at CF6 wave-1 (map carve-out 2; the engine's successor is the effect-commit
//! substrate). Slice 1 of the 0a extraction: the read substrate; the reversion-family verifier
//! follows in slice 2. No writer, no execution, no ledger dependency lives here.

use crate::model_chirho::{CapabilityChirho, CompensationKindChirho, HashChirho};
use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const ROLLBACK_EVENT_RECORD_SCHEMA_CHIRHO: &str = "rollback-event-record-v1-chirho";
pub const COMPENSATION_RECORD_SCHEMA_CHIRHO: &str = "compensation-record-v1-chirho";
pub const MANUAL_REMEDIATION_RECORD_SCHEMA_CHIRHO: &str = "manual-remediation-record-v1-chirho";
pub const COMPENSATION_EXECUTION_RECORD_SCHEMA_CHIRHO: &str =
    "compensation-execution-record-v1-chirho";
pub const ROLLBACK_COMPLETION_RECORD_SCHEMA_CHIRHO: &str = "rollback-completion-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependentEffectReferenceChirho {
    pub run_chirho: HashChirho,
    pub effect_seq_chirho: u64,
    pub original_effect_chirho: HashChirho,
    pub capability_chirho: CapabilityChirho,
    pub request_chirho: HashChirho,
    pub response_chirho: Option<HashChirho>,
    pub compensation_kind_chirho: CompensationKindChirho,
    pub budget_cost_token_chirho: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEventChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub branch_chirho: String,
    pub from_chirho: HashChirho,
    pub to_chirho: HashChirho,
    pub actor_chirho: String,
    pub grant_id_chirho: String,
    pub provenance_index_chirho: HashChirho,
    pub consumed_states_chirho: Vec<HashChirho>,
    pub dependent_effects_chirho: Vec<DependentEffectReferenceChirho>,
    pub plan_cost_token_chirho: i64,
    pub reason_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompensationStatusChirho {
    RecordedChirho {
        action_chirho: String,
    },
    PartialChirho {
        unsupported_aspects_chirho: Vec<String>,
    },
    PendingManualChirho {
        task_chirho: String,
    },
    NotApplicableChirho {
        reason_chirho: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompensationRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub rollback_event_chirho: HashChirho,
    pub original_run_chirho: HashChirho,
    pub original_effect_seq_chirho: u64,
    pub original_effect_chirho: HashChirho,
    pub idem_key_chirho: HashChirho,
    pub capability_chirho: CapabilityChirho,
    pub request_chirho: HashChirho,
    pub response_chirho: Option<HashChirho>,
    pub compensation_kind_chirho: CompensationKindChirho,
    pub status_chirho: CompensationStatusChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualRemediationResolutionChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub compensation_seq_chirho: u64,
    pub compensation_idem_key_chirho: HashChirho,
    pub operator_chirho: String,
    pub note_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompensationExecutionStatusChirho {
    IntentChirho {
        request_chirho: HashChirho,
    },
    SucceededChirho {
        effect_hash_chirho: HashChirho,
    },
    DedupedChirho {
        effect_hash_chirho: HashChirho,
    },
    FailedManualChirho {
        error_chirho: String,
        task_chirho: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompensationExecutionRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub compensation_seq_chirho: u64,
    pub compensation_idem_key_chirho: HashChirho,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub status_chirho: CompensationExecutionStatusChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackCompletionRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub rollback_event_chirho: HashChirho,
    pub resolved_compensations_chirho: Vec<u64>,
    pub unresolved_compensations_chirho: Vec<u64>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub fn rollback_events_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("rollback-events-chirho.jsonl")
}

pub fn compensations_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("compensations-chirho.jsonl")
}

pub fn manual_resolutions_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("manual-remediations-chirho.jsonl")
}

pub fn compensation_executions_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("compensation-executions-chirho.jsonl")
}

pub fn rollback_completions_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("rollback-completions-chirho.jsonl")
}

pub fn load_rollback_events_chirho(root_chirho: &Path) -> Result<Vec<RollbackEventChirho>> {
    let records_chirho =
        load_jsonl_chirho(&rollback_events_path_chirho(root_chirho), "rollback event")?;
    for record_chirho in &records_chirho {
        validate_rollback_event_schema_chirho(record_chirho)?;
    }
    Ok(records_chirho)
}

pub fn load_compensation_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<CompensationRecordChirho>> {
    let records_chirho = load_jsonl_chirho(
        &compensations_path_chirho(root_chirho),
        "compensation record",
    )?;
    for record_chirho in &records_chirho {
        validate_compensation_record_schema_chirho(record_chirho)?;
    }
    Ok(records_chirho)
}

pub fn load_manual_remediation_resolutions_chirho(
    root_chirho: &Path,
) -> Result<Vec<ManualRemediationResolutionChirho>> {
    let records_chirho = load_jsonl_chirho(
        &manual_resolutions_path_chirho(root_chirho),
        "manual remediation resolution",
    )?;
    for record_chirho in &records_chirho {
        validate_manual_remediation_schema_chirho(record_chirho)?;
    }
    Ok(records_chirho)
}

pub fn load_compensation_executions_chirho(
    root_chirho: &Path,
) -> Result<Vec<CompensationExecutionRecordChirho>> {
    let records_chirho = load_jsonl_chirho(
        &compensation_executions_path_chirho(root_chirho),
        "compensation execution",
    )?;
    for record_chirho in &records_chirho {
        validate_compensation_execution_schema_chirho(record_chirho)?;
    }
    Ok(records_chirho)
}

pub fn load_rollback_completions_chirho(
    root_chirho: &Path,
) -> Result<Vec<RollbackCompletionRecordChirho>> {
    let records_chirho = load_jsonl_chirho(
        &rollback_completions_path_chirho(root_chirho),
        "rollback completion",
    )?;
    for record_chirho in &records_chirho {
        validate_rollback_completion_schema_chirho(record_chirho)?;
    }
    Ok(records_chirho)
}

pub fn validate_rollback_event_schema_chirho(record_chirho: &RollbackEventChirho) -> Result<()> {
    validate_reversion_schema_chirho(
        "rollback event",
        &record_chirho.schema_chirho,
        ROLLBACK_EVENT_RECORD_SCHEMA_CHIRHO,
    )
}

pub fn validate_compensation_record_schema_chirho(
    record_chirho: &CompensationRecordChirho,
) -> Result<()> {
    validate_reversion_schema_chirho(
        "compensation record",
        &record_chirho.schema_chirho,
        COMPENSATION_RECORD_SCHEMA_CHIRHO,
    )
}

pub fn validate_manual_remediation_schema_chirho(
    record_chirho: &ManualRemediationResolutionChirho,
) -> Result<()> {
    validate_reversion_schema_chirho(
        "manual remediation record",
        &record_chirho.schema_chirho,
        MANUAL_REMEDIATION_RECORD_SCHEMA_CHIRHO,
    )
}

pub fn validate_compensation_execution_schema_chirho(
    record_chirho: &CompensationExecutionRecordChirho,
) -> Result<()> {
    validate_reversion_schema_chirho(
        "compensation execution record",
        &record_chirho.schema_chirho,
        COMPENSATION_EXECUTION_RECORD_SCHEMA_CHIRHO,
    )
}

pub fn validate_rollback_completion_schema_chirho(
    record_chirho: &RollbackCompletionRecordChirho,
) -> Result<()> {
    validate_reversion_schema_chirho(
        "rollback completion record",
        &record_chirho.schema_chirho,
        ROLLBACK_COMPLETION_RECORD_SCHEMA_CHIRHO,
    )
}

fn validate_reversion_schema_chirho(
    label_chirho: &str,
    schema_chirho: &str,
    expected_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("{label_chirho} has unsupported schema '{schema_chirho}'");
    }
    Ok(())
}

pub(crate) fn load_jsonl_chirho<T: DeserializeOwned>(
    path_chirho: &Path,
    label_chirho: &str,
) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        let line_chirho = line_chirho.trim();
        if line_chirho.is_empty() {
            continue;
        }
        out_chirho.push(
            serde_json::from_str(line_chirho)
                .with_context(|| format!("decode {label_chirho} JSONL line"))?,
        );
    }
    Ok(out_chirho)
}

// ===== Slice 2: the retained read-only verify family. The wave-1 deletion removed the mutation
// engine and its legacy-ledger count wrapper; every dependency below is a kept evidence surface.

use crate::{
    attenuation_chirho, cache_chirho, cas_chirho, effect_chirho, refs_chirho, store_chirho,
};
use anyhow::anyhow;
use cairn_signer_chirho::signer_chirho;
use std::collections::{BTreeMap, BTreeSet};

pub const ROLLBACK_REASON_CHIRHO: &str = "causal-rollback";

/// The ledger-free reversion-family verification counts (slice-2 shape): the five evidence
/// families verified for signatures, seq density, cross-links, grant budgets, and reflog moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReversionEvidenceVerificationChirho {
    pub rollback_events_chirho: usize,
    pub compensations_chirho: usize,
    pub compensation_executions_chirho: usize,
    pub manual_resolutions_chirho: usize,
    pub rollback_completions_chirho: usize,
}

/// The consume-once identity of a compensation: the committed effect INSTANCE  (CF5-R2).
#[derive(serde::Serialize)]
struct CompensationIdemPayloadChirho<'a> {
    original_run_chirho: &'a HashChirho,
    original_effect_seq_chirho: u64,
    original_effect_chirho: &'a HashChirho,
}

pub fn verify_reversion_evidence_chirho(
    root_chirho: &Path,
) -> Result<ReversionEvidenceVerificationChirho> {
    attenuation_chirho::verify_grants_chirho(root_chirho)?;
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let grants_chirho = attenuation_chirho::load_grants_chirho(root_chirho)?;
    let events_chirho = load_rollback_events_chirho(root_chirho)?;
    let compensations_chirho = load_compensation_records_chirho(root_chirho)?;
    let executions_chirho = load_compensation_executions_chirho(root_chirho)?;
    let manual_resolutions_chirho = load_manual_remediation_resolutions_chirho(root_chirho)?;
    let completions_chirho = load_rollback_completions_chirho(root_chirho)?;
    let reflog_chirho = refs_chirho::reflog_chirho(root_chirho)?;

    let mut event_by_hash_chirho = BTreeMap::new();
    let mut grant_counts_chirho: BTreeMap<String, u64> = BTreeMap::new();
    let mut grant_costs_chirho: BTreeMap<String, i64> = BTreeMap::new();
    for (i_chirho, event_chirho) in events_chirho.iter().enumerate() {
        if event_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "rollback event seq gap at index {i_chirho}: entry seq is {}",
                event_chirho.seq_chirho
            );
        }
        if event_chirho.plan_cost_token_chirho
            != event_chirho.dependent_effects_chirho.iter().try_fold(
                0_i64,
                |sum_chirho, effect_chirho| {
                    sum_chirho
                        .checked_add(effect_chirho.budget_cost_token_chirho)
                        .ok_or_else(|| anyhow!("rollback event budget cost overflow"))
                },
            )?
        {
            bail!(
                "rollback event {} plan cost mismatch",
                event_chirho.seq_chirho
            );
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &rollback_event_message_chirho(event_chirho)?,
            &event_chirho.sig_chirho,
        )? {
            bail!(
                "rollback event {} signature invalid",
                event_chirho.seq_chirho
            );
        }
        validate_event_grant_chirho(
            event_chirho,
            &grants_chirho,
            &mut grant_counts_chirho,
            &mut grant_costs_chirho,
        )?;
        if !reflog_chirho.iter().any(|entry_chirho| {
            entry_chirho.branch_chirho == event_chirho.branch_chirho
                && entry_chirho.from_chirho.as_ref() == Some(&event_chirho.from_chirho)
                && entry_chirho.to_chirho == event_chirho.to_chirho
                && entry_chirho.reason_chirho == ROLLBACK_REASON_CHIRHO
        }) {
            bail!(
                "rollback event {} has no matching reflog move",
                event_chirho.seq_chirho
            );
        }
        let event_hash_chirho = store_chirho::hash_object_chirho(event_chirho)?;
        event_by_hash_chirho.insert(event_hash_chirho, event_chirho.clone());
    }

    // CF5-R2 duplicate-K guard: no committed effect instance may carry two compensation records.
    let mut seen_compensation_keys_chirho: std::collections::HashSet<(
        HashChirho,
        u64,
        HashChirho,
    )> = std::collections::HashSet::new();
    for (i_chirho, record_chirho) in compensations_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "compensation seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &compensation_record_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "compensation record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        let event_chirho = event_by_hash_chirho
            .get(&record_chirho.rollback_event_chirho)
            .ok_or_else(|| {
                anyhow!(
                    "compensation record {} points at missing rollback event",
                    record_chirho.seq_chirho
                )
            })?;
        let dependent_chirho = event_chirho
            .dependent_effects_chirho
            .iter()
            .find(|effect_chirho| {
                effect_chirho.original_effect_chirho == record_chirho.original_effect_chirho
                    && effect_chirho.run_chirho == record_chirho.original_run_chirho
                    && effect_chirho.effect_seq_chirho == record_chirho.original_effect_seq_chirho
            })
            .ok_or_else(|| {
                anyhow!(
                    "compensation record {} is not in rollback event plan",
                    record_chirho.seq_chirho
                )
            })?;
        if record_chirho.idem_key_chirho
            != compensation_idem_key_chirho(
                &record_chirho.original_run_chirho,
                record_chirho.original_effect_seq_chirho,
                &record_chirho.original_effect_chirho,
            )?
        {
            bail!(
                "compensation record {} idempotency key mismatch",
                record_chirho.seq_chirho
            );
        }
        // CF5-R2: at most ONE compensation intent per committed effect INSTANCE K, across ALL
        // rollback events/history — so a tampered or legacy store carrying two compensations for one
        // K fails closed here, complementing the creation-time dedup.
        if !seen_compensation_keys_chirho.insert((
            record_chirho.original_run_chirho.clone(),
            record_chirho.original_effect_seq_chirho,
            record_chirho.original_effect_chirho.clone(),
        )) {
            bail!(
                "compensation record {} double-compensates a committed effect already \
                 compensated by another record (one intent per effect, ever)",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.capability_chirho != dependent_chirho.capability_chirho
            || record_chirho.request_chirho != dependent_chirho.request_chirho
            || record_chirho.response_chirho != dependent_chirho.response_chirho
            || record_chirho.compensation_kind_chirho != dependent_chirho.compensation_kind_chirho
        {
            bail!(
                "compensation record {} does not match planned effect",
                record_chirho.seq_chirho
            );
        }
        validate_status_matches_kind_chirho(
            &record_chirho.status_chirho,
            &record_chirho.compensation_kind_chirho,
        )?;
        verify_original_effect_hash_chirho(root_chirho, record_chirho)?;
    }

    verify_manual_resolutions_chirho(
        &pubkey_chirho,
        &compensations_chirho,
        &manual_resolutions_chirho,
    )?;
    verify_compensation_executions_chirho(
        root_chirho,
        &pubkey_chirho,
        &compensations_chirho,
        &executions_chirho,
    )?;
    verify_rollback_completions_chirho(
        &pubkey_chirho,
        &events_chirho,
        &compensations_chirho,
        &executions_chirho,
        &manual_resolutions_chirho,
        &completions_chirho,
    )?;
    Ok(ReversionEvidenceVerificationChirho {
        rollback_events_chirho: events_chirho.len(),
        compensations_chirho: compensations_chirho.len(),
        compensation_executions_chirho: executions_chirho.len(),
        manual_resolutions_chirho: manual_resolutions_chirho.len(),
        rollback_completions_chirho: completions_chirho.len(),
    })
}

fn validate_event_grant_chirho(
    event_chirho: &RollbackEventChirho,
    grants_chirho: &[attenuation_chirho::CapabilityGrantRecordChirho],
    grant_counts_chirho: &mut BTreeMap<String, u64>,
    grant_costs_chirho: &mut BTreeMap<String, i64>,
) -> Result<()> {
    let grant_chirho = grants_chirho
        .iter()
        .find(|grant_chirho| grant_chirho.grant_id_chirho == event_chirho.grant_id_chirho)
        .ok_or_else(|| anyhow!("rollback event references missing grant"))?;
    if grant_chirho.grantee_chirho != event_chirho.actor_chirho {
        bail!("rollback event actor is not grant grantee");
    }
    let CapabilityChirho::CausalReversionChirho { branch_chirho } = &grant_chirho.capability_chirho
    else {
        bail!("rollback event grant is not a CausalReversionChirho grant");
    };
    if branch_chirho != &event_chirho.branch_chirho {
        bail!("rollback event grant branch mismatch");
    }
    if let Some(expires_at_ms_chirho) = grant_chirho.limits_chirho.expires_at_ms_chirho {
        if event_chirho.at_ms_chirho > expires_at_ms_chirho {
            bail!("rollback event used an expired grant");
        }
    }
    let count_chirho = grant_counts_chirho
        .entry(event_chirho.grant_id_chirho.clone())
        .or_insert(0);
    if let Some(max_invokes_chirho) = grant_chirho.limits_chirho.max_invokes_chirho {
        if *count_chirho >= max_invokes_chirho {
            bail!("rollback event exceeds grant max_invokes_chirho");
        }
    }
    *count_chirho += 1;
    let cost_chirho = grant_costs_chirho
        .entry(event_chirho.grant_id_chirho.clone())
        .or_insert(0);
    *cost_chirho = cost_chirho
        .checked_add(event_chirho.plan_cost_token_chirho)
        .ok_or_else(|| anyhow!("rollback event grant cost overflow"))?;
    if let Some(budget_token_chirho) = grant_chirho.limits_chirho.budget_token_chirho {
        if *cost_chirho > budget_token_chirho {
            bail!("rollback event exceeds grant budget_token_chirho");
        }
    }
    Ok(())
}

fn validate_status_matches_kind_chirho(
    status_chirho: &CompensationStatusChirho,
    kind_chirho: &CompensationKindChirho,
) -> Result<()> {
    match (status_chirho, kind_chirho) {
        (
            CompensationStatusChirho::RecordedChirho { action_chirho },
            CompensationKindChirho::FullInverseChirho
            | CompensationKindChirho::CorrectiveForwardChirho,
        ) if !action_chirho.trim().is_empty() => Ok(()),
        (
            CompensationStatusChirho::PartialChirho {
                unsupported_aspects_chirho: status_aspects_chirho,
            },
            CompensationKindChirho::PartialChirho {
                unsupported_aspects_chirho: kind_aspects_chirho,
            },
        ) if status_aspects_chirho == kind_aspects_chirho => Ok(()),
        (
            CompensationStatusChirho::PendingManualChirho { task_chirho },
            CompensationKindChirho::ManualRemediationChirho { .. },
        ) if !task_chirho.trim().is_empty() => Ok(()),
        (
            CompensationStatusChirho::NotApplicableChirho {
                reason_chirho: status_reason_chirho,
            },
            CompensationKindChirho::NotApplicableChirho {
                reason_chirho: kind_reason_chirho,
            },
        ) if status_reason_chirho == kind_reason_chirho => Ok(()),
        _ => bail!("compensation status does not match compensation kind"),
    }
}

fn verify_original_effect_hash_chirho(
    root_chirho: &Path,
    record_chirho: &CompensationRecordChirho,
) -> Result<()> {
    let result_chirho =
        cache_chirho::load_sealed_result_chirho(root_chirho, &record_chirho.original_run_chirho)?
            .ok_or_else(|| anyhow!("compensation original run is missing"))?;
    let effect_chirho = result_chirho
        .effects_chirho
        .iter()
        .find(|effect_chirho| effect_chirho.seq_chirho == record_chirho.original_effect_seq_chirho)
        .ok_or_else(|| anyhow!("compensation original effect is missing"))?;
    effect_chirho::verify_effect_chirho(root_chirho, effect_chirho)?;
    if store_chirho::hash_object_chirho(effect_chirho)? != record_chirho.original_effect_chirho {
        bail!("compensation original effect hash mismatch");
    }
    Ok(())
}

fn verify_manual_resolutions_chirho(
    pubkey_chirho: &str,
    compensations_chirho: &[CompensationRecordChirho],
    resolutions_chirho: &[ManualRemediationResolutionChirho],
) -> Result<()> {
    let mut seen_chirho = BTreeSet::new();
    for (i_chirho, resolution_chirho) in resolutions_chirho.iter().enumerate() {
        if resolution_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "manual remediation resolution seq gap at index {i_chirho}: entry seq is {}",
                resolution_chirho.seq_chirho
            );
        }
        if !seen_chirho.insert(resolution_chirho.compensation_seq_chirho) {
            bail!("manual remediation compensation resolved more than once");
        }
        validate_actor_label_chirho("operator_chirho", &resolution_chirho.operator_chirho)?;
        if resolution_chirho.note_chirho.trim().is_empty() {
            bail!("manual remediation resolution note_chirho is required");
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &manual_resolution_message_chirho(resolution_chirho)?,
            &resolution_chirho.sig_chirho,
        )? {
            bail!(
                "manual remediation resolution {} signature invalid",
                resolution_chirho.seq_chirho
            );
        }
        let compensation_chirho = compensations_chirho
            .iter()
            .find(|record_chirho| {
                record_chirho.seq_chirho == resolution_chirho.compensation_seq_chirho
            })
            .ok_or_else(|| {
                anyhow!("manual remediation resolution points at missing compensation")
            })?;
        if !matches!(
            compensation_chirho.status_chirho,
            CompensationStatusChirho::PendingManualChirho { .. }
        ) {
            bail!("manual remediation resolution points at non-manual compensation");
        }
        if resolution_chirho.compensation_idem_key_chirho != compensation_chirho.idem_key_chirho {
            bail!("manual remediation resolution idem key mismatch");
        }
    }
    Ok(())
}

fn verify_compensation_executions_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    compensations_chirho: &[CompensationRecordChirho],
    executions_chirho: &[CompensationExecutionRecordChirho],
) -> Result<()> {
    for (i_chirho, execution_chirho) in executions_chirho.iter().enumerate() {
        if execution_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "compensation execution seq gap at index {i_chirho}: entry seq is {}",
                execution_chirho.seq_chirho
            );
        }
        validate_actor_label_chirho("effect_chirho", &execution_chirho.effect_chirho)?;
        validate_actor_label_chirho("caller_chirho", &execution_chirho.caller_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &compensation_execution_message_chirho(execution_chirho)?,
            &execution_chirho.sig_chirho,
        )? {
            bail!(
                "compensation execution {} signature invalid",
                execution_chirho.seq_chirho
            );
        }
        let compensation_chirho = compensations_chirho
            .iter()
            .find(|record_chirho| {
                record_chirho.seq_chirho == execution_chirho.compensation_seq_chirho
            })
            .ok_or_else(|| anyhow!("compensation execution points at missing compensation"))?;
        if execution_chirho.compensation_idem_key_chirho != compensation_chirho.idem_key_chirho {
            bail!("compensation execution idem key mismatch");
        }
        match &execution_chirho.status_chirho {
            CompensationExecutionStatusChirho::IntentChirho { request_chirho } => {
                cas_chirho::get_chirho(root_chirho, request_chirho).with_context(|| {
                    format!("compensation execution intent request {}", request_chirho.0)
                })?;
            }
            CompensationExecutionStatusChirho::SucceededChirho { effect_hash_chirho }
            | CompensationExecutionStatusChirho::DedupedChirho { effect_hash_chirho } => {
                let effect_record_chirho = effect_chirho::load_effect_chirho(
                    root_chirho,
                    &execution_chirho.compensation_idem_key_chirho,
                )?
                .ok_or_else(|| anyhow!("successful compensation effect is missing"))?;
                if store_chirho::hash_object_chirho(&effect_record_chirho)? != *effect_hash_chirho {
                    bail!("compensation execution effect hash mismatch");
                }
                match &effect_record_chirho.capability_chirho {
                    CapabilityChirho::PaidEffectChirho {
                        effect_chirho,
                        caller_chirho,
                    } if effect_chirho == &execution_chirho.effect_chirho
                        && caller_chirho == &execution_chirho.caller_chirho => {}
                    _ => bail!("compensation execution effect capability mismatch"),
                }
            }
            CompensationExecutionStatusChirho::FailedManualChirho {
                error_chirho,
                task_chirho,
            } => {
                if error_chirho.trim().is_empty() || task_chirho.trim().is_empty() {
                    bail!("failed compensation execution must record error and task");
                }
            }
        }
    }
    Ok(())
}

fn verify_rollback_completions_chirho(
    pubkey_chirho: &str,
    events_chirho: &[RollbackEventChirho],
    compensations_chirho: &[CompensationRecordChirho],
    executions_chirho: &[CompensationExecutionRecordChirho],
    resolutions_chirho: &[ManualRemediationResolutionChirho],
    completions_chirho: &[RollbackCompletionRecordChirho],
) -> Result<()> {
    let event_hashes_chirho = events_chirho
        .iter()
        .map(store_chirho::hash_object_chirho)
        .collect::<Result<BTreeSet<_>>>()?;
    let mut seen_chirho = BTreeSet::new();
    for (i_chirho, completion_chirho) in completions_chirho.iter().enumerate() {
        if completion_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "rollback completion seq gap at index {i_chirho}: entry seq is {}",
                completion_chirho.seq_chirho
            );
        }
        if !seen_chirho.insert(completion_chirho.rollback_event_chirho.clone()) {
            bail!("rollback event completed more than once");
        }
        if !event_hashes_chirho.contains(&completion_chirho.rollback_event_chirho) {
            bail!("rollback completion points at missing rollback event");
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            pubkey_chirho,
            &rollback_completion_message_chirho(completion_chirho)?,
            &completion_chirho.sig_chirho,
        )? {
            bail!(
                "rollback completion {} signature invalid",
                completion_chirho.seq_chirho
            );
        }
        let (resolved_chirho, unresolved_chirho) = fold_rollback_completion_chirho(
            &completion_chirho.rollback_event_chirho,
            compensations_chirho,
            executions_chirho,
            resolutions_chirho,
        );
        if completion_chirho.resolved_compensations_chirho != resolved_chirho
            || completion_chirho.unresolved_compensations_chirho != unresolved_chirho
        {
            bail!("rollback completion resolved/unresolved fold mismatch");
        }
    }
    Ok(())
}

pub(crate) fn rollback_event_message_chirho(event_chirho: &RollbackEventChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = event_chirho.clone();
    signed_chirho.sig_chirho.clear();
    serde_json::to_vec(&signed_chirho).context("encode rollback event message")
}

pub(crate) fn compensation_record_message_chirho(
    record_chirho: &CompensationRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    serde_json::to_vec(&signed_chirho).context("encode compensation record message")
}

pub(crate) fn manual_resolution_message_chirho(
    record_chirho: &ManualRemediationResolutionChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    serde_json::to_vec(&signed_chirho).context("encode manual remediation resolution message")
}

pub(crate) fn compensation_idem_key_chirho(
    original_run_chirho: &HashChirho,
    original_effect_seq_chirho: u64,
    original_effect_chirho: &HashChirho,
) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(&CompensationIdemPayloadChirho {
        original_run_chirho,
        original_effect_seq_chirho,
        original_effect_chirho,
    })
}

pub(crate) fn successful_execution_for_compensation_chirho<'a>(
    executions_chirho: &'a [CompensationExecutionRecordChirho],
    compensation_chirho: &CompensationRecordChirho,
) -> Option<&'a CompensationExecutionRecordChirho> {
    executions_chirho.iter().find(|record_chirho| {
        record_chirho.compensation_seq_chirho == compensation_chirho.seq_chirho
            && record_chirho.compensation_idem_key_chirho == compensation_chirho.idem_key_chirho
            && compensation_execution_succeeded_chirho(&record_chirho.status_chirho)
    })
}

#[cfg(test)]
#[path = "reversion_legacy_evidence_tests_chirho.rs"]
mod tests_chirho;

pub(crate) fn compensation_execution_succeeded_chirho(
    status_chirho: &CompensationExecutionStatusChirho,
) -> bool {
    matches!(
        status_chirho,
        CompensationExecutionStatusChirho::SucceededChirho { .. }
            | CompensationExecutionStatusChirho::DedupedChirho { .. }
    )
}

pub(crate) fn fold_rollback_completion_chirho(
    rollback_event_chirho: &HashChirho,
    compensations_chirho: &[CompensationRecordChirho],
    executions_chirho: &[CompensationExecutionRecordChirho],
    resolutions_chirho: &[ManualRemediationResolutionChirho],
) -> (Vec<u64>, Vec<u64>) {
    let mut resolved_chirho = Vec::new();
    let mut unresolved_chirho = Vec::new();
    for compensation_chirho in compensations_chirho
        .iter()
        .filter(|record_chirho| &record_chirho.rollback_event_chirho == rollback_event_chirho)
    {
        if compensation_resolved_chirho(compensation_chirho, executions_chirho, resolutions_chirho)
        {
            resolved_chirho.push(compensation_chirho.seq_chirho);
        } else {
            unresolved_chirho.push(compensation_chirho.seq_chirho);
        }
    }
    (resolved_chirho, unresolved_chirho)
}

fn compensation_resolved_chirho(
    compensation_chirho: &CompensationRecordChirho,
    executions_chirho: &[CompensationExecutionRecordChirho],
    resolutions_chirho: &[ManualRemediationResolutionChirho],
) -> bool {
    match compensation_chirho.status_chirho {
        CompensationStatusChirho::RecordedChirho { .. } => {
            successful_execution_for_compensation_chirho(executions_chirho, compensation_chirho)
                .is_some()
        }
        CompensationStatusChirho::PartialChirho { .. } => false,
        CompensationStatusChirho::PendingManualChirho { .. } => {
            resolutions_chirho.iter().any(|record_chirho| {
                record_chirho.compensation_seq_chirho == compensation_chirho.seq_chirho
                    && record_chirho.compensation_idem_key_chirho
                        == compensation_chirho.idem_key_chirho
            })
        }
        CompensationStatusChirho::NotApplicableChirho { .. } => true,
    }
}

pub(crate) fn compensation_execution_message_chirho(
    record_chirho: &CompensationExecutionRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    serde_json::to_vec(&signed_chirho).context("encode compensation execution message")
}

pub(crate) fn rollback_completion_message_chirho(
    record_chirho: &RollbackCompletionRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    serde_json::to_vec(&signed_chirho).context("encode rollback completion message")
}

pub(crate) fn validate_actor_label_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty() || value_chirho.chars().any(char::is_whitespace) {
        bail!("{name_chirho} must be nonempty and contain no whitespace");
    }
    Ok(())
}
