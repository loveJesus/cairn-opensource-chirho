// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Typed agent reports: concise ledes, evidence refs, content-addressed bodies, and signed report logs.

use crate::model_chirho::HashChirho;
use crate::{cas_chirho, seqlog_chirho, store_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub use cairn_model_agent_report_chirho::{
    AgentReportCategoryChirho, AgentReportChirho, AgentReportEvidenceKindChirho,
    AgentReportEvidenceRefChirho, AgentReportLedeChirho, AgentReportPriorityChirho,
    AgentReportRecordChirho, AgentRequestedActionChirho, AgentRequestedActionKindChirho,
};

const AGENT_REPORT_RECORD_SCHEMA_CHIRHO: &str = "agent-report-record-v1-chirho";
const AGENT_REPORT_BUDGET_GRANT_RECORD_SCHEMA_CHIRHO: &str =
    "agent-report-budget-grant-record-v1-chirho";
const AGENT_REPORT_CHARGE_RECORD_SCHEMA_CHIRHO: &str = "agent-report-charge-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportBudgetGrantRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub agent_principal_chirho: String,
    pub granted_by_chirho: String,
    pub amount_token_chirho: i64,
    pub reason_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportPriorityReviewChirho {
    pub requested_priority_chirho: AgentReportPriorityChirho,
    pub effective_priority_chirho: AgentReportPriorityChirho,
    pub reviewer_principal_chirho: String,
    pub downgraded_chirho: bool,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportChargeRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub report_seq_chirho: u64,
    pub report_chirho: HashChirho,
    pub producer_principal_chirho: String,
    pub requested_priority_chirho: AgentReportPriorityChirho,
    pub effective_priority_chirho: AgentReportPriorityChirho,
    pub cost_token_chirho: i64,
    pub remaining_budget_token_chirho: i64,
    pub priority_review_chirho: AgentReportPriorityReviewChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentReportBudgetGrantInputChirho {
    pub agent_principal_chirho: String,
    pub granted_by_chirho: String,
    pub amount_token_chirho: i64,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentReportBudgetBalanceChirho {
    pub agent_principal_chirho: String,
    pub granted_token_chirho: i64,
    pub spent_token_chirho: i64,
    pub remaining_token_chirho: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentReportInputChirho {
    pub producer_principal_chirho: String,
    pub category_chirho: AgentReportCategoryChirho,
    pub priority_chirho: AgentReportPriorityChirho,
    pub happened_chirho: String,
    pub affected_chirho: String,
    pub why_matters_chirho: String,
    pub evidence_refs_chirho: Vec<AgentReportEvidenceRefChirho>,
    pub related_run_ids_chirho: Vec<HashChirho>,
    pub related_effect_ids_chirho: Vec<String>,
    pub requested_action_chirho: Option<AgentRequestedActionChirho>,
}

pub fn emit_agent_report_chirho(
    root_chirho: &Path,
    input_chirho: AgentReportInputChirho,
) -> Result<AgentReportRecordChirho> {
    let report_chirho = AgentReportChirho {
        lede_chirho: AgentReportLedeChirho {
            happened_chirho: trim_checked_chirho(input_chirho.happened_chirho),
            affected_chirho: trim_checked_chirho(input_chirho.affected_chirho),
            why_matters_chirho: trim_checked_chirho(input_chirho.why_matters_chirho),
        },
        category_chirho: input_chirho.category_chirho,
        priority_chirho: input_chirho.priority_chirho,
        evidence_refs_chirho: input_chirho.evidence_refs_chirho,
        producer_principal_chirho: trim_checked_chirho(input_chirho.producer_principal_chirho),
        related_run_ids_chirho: input_chirho.related_run_ids_chirho,
        related_effect_ids_chirho: input_chirho.related_effect_ids_chirho,
        requested_action_chirho: input_chirho.requested_action_chirho,
        created_at_ms_chirho: now_ms_chirho(),
    };
    validate_agent_report_chirho(root_chirho, &report_chirho)?;
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let balance_chirho = agent_report_budget_balance_unlocked_chirho(
            root_chirho,
            &report_chirho.producer_principal_chirho,
        )?;
        let cost_token_chirho = agent_report_cost_token_chirho(&report_chirho);
        if balance_chirho.remaining_token_chirho < cost_token_chirho {
            bail!(
                "agent report budget exhausted for {}: remaining {}, cost {}",
                report_chirho.producer_principal_chirho,
                balance_chirho.remaining_token_chirho,
                cost_token_chirho
            );
        }
        let report_hash_chirho = store_chirho::put_object_chirho(root_chirho, &report_chirho)?;
        let report_seq_chirho = jsonl_len_chirho(&agent_report_records_path_chirho(root_chirho))?;
        let mut record_chirho = AgentReportRecordChirho {
            schema_chirho: AGENT_REPORT_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: report_seq_chirho,
            report_chirho: report_hash_chirho.clone(),
            producer_principal_chirho: report_chirho.producer_principal_chirho.clone(),
            category_chirho: report_chirho.category_chirho.clone(),
            priority_chirho: report_chirho.priority_chirho.clone(),
            evidence_count_chirho: report_chirho.evidence_refs_chirho.len(),
            at_ms_chirho: report_chirho.created_at_ms_chirho,
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &agent_report_record_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &agent_report_records_path_chirho(root_chirho),
            record_chirho.seq_chirho,
            &record_chirho,
        )?;

        let priority_review_chirho = review_agent_report_priority_chirho(&report_chirho);
        let mut charge_chirho = AgentReportChargeRecordChirho {
            schema_chirho: AGENT_REPORT_CHARGE_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: jsonl_len_chirho(&agent_report_charges_path_chirho(root_chirho))?,
            report_seq_chirho,
            report_chirho: report_hash_chirho,
            producer_principal_chirho: report_chirho.producer_principal_chirho.clone(),
            requested_priority_chirho: report_chirho.priority_chirho.clone(),
            effective_priority_chirho: priority_review_chirho.effective_priority_chirho.clone(),
            cost_token_chirho,
            remaining_budget_token_chirho: balance_chirho
                .remaining_token_chirho
                .checked_sub(cost_token_chirho)
                .ok_or_else(|| anyhow!("agent report budget underflow"))?,
            priority_review_chirho,
            at_ms_chirho: report_chirho.created_at_ms_chirho,
            sig_chirho: String::new(),
        };
        charge_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &agent_report_charge_message_chirho(&charge_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &agent_report_charges_path_chirho(root_chirho),
            charge_chirho.seq_chirho,
            &charge_chirho,
        )?;
        Ok(record_chirho)
    })
}

pub fn load_agent_report_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AgentReportRecordChirho>> {
    let path_chirho = agent_report_records_path_chirho(root_chirho);
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
        records_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(records_chirho)
}

pub fn load_agent_report_chirho(
    root_chirho: &Path,
    report_chirho: &HashChirho,
) -> Result<AgentReportChirho> {
    store_chirho::get_object_chirho(root_chirho, report_chirho)
}

pub fn grant_agent_report_budget_chirho(
    root_chirho: &Path,
    input_chirho: AgentReportBudgetGrantInputChirho,
) -> Result<AgentReportBudgetGrantRecordChirho> {
    validate_principal_chirho(&input_chirho.agent_principal_chirho)?;
    validate_principal_chirho(&input_chirho.granted_by_chirho)?;
    if input_chirho.amount_token_chirho <= 0 {
        bail!("agent report budget grant amount must be positive");
    }
    validate_safe_text_chirho(
        "agent report budget grant reason",
        &input_chirho.reason_chirho,
        240,
    )?;
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let mut record_chirho = AgentReportBudgetGrantRecordChirho {
            schema_chirho: AGENT_REPORT_BUDGET_GRANT_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: jsonl_len_chirho(&agent_report_budget_grants_path_chirho(root_chirho))?,
            agent_principal_chirho: input_chirho.agent_principal_chirho.clone(),
            granted_by_chirho: input_chirho.granted_by_chirho.clone(),
            amount_token_chirho: input_chirho.amount_token_chirho,
            reason_chirho: input_chirho.reason_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &agent_report_budget_grant_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &agent_report_budget_grants_path_chirho(root_chirho),
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

pub fn load_agent_report_budget_grants_chirho(
    root_chirho: &Path,
) -> Result<Vec<AgentReportBudgetGrantRecordChirho>> {
    load_jsonl_chirho(&agent_report_budget_grants_path_chirho(root_chirho))
}

pub fn load_agent_report_charge_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AgentReportChargeRecordChirho>> {
    load_jsonl_chirho(&agent_report_charges_path_chirho(root_chirho))
}

pub fn agent_report_budget_balance_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
) -> Result<AgentReportBudgetBalanceChirho> {
    validate_principal_chirho(agent_principal_chirho)?;
    agent_report_budget_balance_unlocked_chirho(root_chirho, agent_principal_chirho)
}

pub fn agent_report_charge_by_report_seq_chirho(
    root_chirho: &Path,
) -> Result<BTreeMap<u64, AgentReportChargeRecordChirho>> {
    let mut out_chirho = BTreeMap::new();
    for charge_chirho in load_agent_report_charge_records_chirho(root_chirho)? {
        if out_chirho
            .insert(charge_chirho.report_seq_chirho, charge_chirho)
            .is_some()
        {
            bail!("duplicate agent report charge for one report seq");
        }
    }
    Ok(out_chirho)
}

pub fn verify_agent_report_records_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_agent_report_records_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "agent report seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        verify_agent_report_record_schema_chirho(
            &record_chirho.schema_chirho,
            AGENT_REPORT_RECORD_SCHEMA_CHIRHO,
            "agent report record",
        )?;
        let report_chirho = load_agent_report_chirho(root_chirho, &record_chirho.report_chirho)?;
        validate_agent_report_chirho(root_chirho, &report_chirho)?;
        let expected_hash_chirho = store_chirho::hash_object_chirho(&report_chirho)?;
        if expected_hash_chirho != record_chirho.report_chirho {
            bail!(
                "agent report record {} points at a non-canonical report hash",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.producer_principal_chirho != report_chirho.producer_principal_chirho
            || record_chirho.category_chirho != report_chirho.category_chirho
            || record_chirho.priority_chirho != report_chirho.priority_chirho
            || record_chirho.evidence_count_chirho != report_chirho.evidence_refs_chirho.len()
            || record_chirho.at_ms_chirho != report_chirho.created_at_ms_chirho
        {
            bail!(
                "agent report record {} summary does not match report body",
                record_chirho.seq_chirho
            );
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &agent_report_record_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "agent report record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

pub fn verify_agent_report_accounting_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let budget_grants_chirho = load_agent_report_budget_grants_chirho(root_chirho)?;
    let mut grants_by_agent_chirho: BTreeMap<String, i64> = BTreeMap::new();
    for (i_chirho, grant_chirho) in budget_grants_chirho.iter().enumerate() {
        if grant_chirho.seq_chirho != i_chirho as u64 {
            bail!("agent report budget grant seq gap at index {i_chirho}");
        }
        verify_agent_report_record_schema_chirho(
            &grant_chirho.schema_chirho,
            AGENT_REPORT_BUDGET_GRANT_RECORD_SCHEMA_CHIRHO,
            "agent report budget grant record",
        )?;
        validate_principal_chirho(&grant_chirho.agent_principal_chirho)?;
        validate_principal_chirho(&grant_chirho.granted_by_chirho)?;
        if grant_chirho.amount_token_chirho <= 0 {
            bail!("agent report budget grant amount must be positive");
        }
        validate_safe_text_chirho(
            "agent report budget grant reason",
            &grant_chirho.reason_chirho,
            240,
        )?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &agent_report_budget_grant_message_chirho(grant_chirho)?,
            &grant_chirho.sig_chirho,
        )? {
            bail!(
                "agent report budget grant {} signature invalid",
                grant_chirho.seq_chirho
            );
        }
        let total_chirho = grants_by_agent_chirho
            .entry(grant_chirho.agent_principal_chirho.clone())
            .or_insert(0);
        *total_chirho = total_chirho
            .checked_add(grant_chirho.amount_token_chirho)
            .ok_or_else(|| anyhow!("agent report budget grant overflow"))?;
    }

    let report_records_chirho = load_agent_report_records_chirho(root_chirho)?;
    let mut reports_by_seq_chirho = BTreeMap::new();
    for record_chirho in &report_records_chirho {
        let report_chirho = load_agent_report_chirho(root_chirho, &record_chirho.report_chirho)?;
        reports_by_seq_chirho.insert(record_chirho.seq_chirho, (record_chirho, report_chirho));
    }

    let charges_chirho = load_agent_report_charge_records_chirho(root_chirho)?;
    let mut spent_by_agent_chirho: BTreeMap<String, i64> = BTreeMap::new();
    let mut charged_reports_chirho = BTreeSet::new();
    for (i_chirho, charge_chirho) in charges_chirho.iter().enumerate() {
        if charge_chirho.seq_chirho != i_chirho as u64 {
            bail!("agent report charge seq gap at index {i_chirho}");
        }
        verify_agent_report_record_schema_chirho(
            &charge_chirho.schema_chirho,
            AGENT_REPORT_CHARGE_RECORD_SCHEMA_CHIRHO,
            "agent report charge record",
        )?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &agent_report_charge_message_chirho(charge_chirho)?,
            &charge_chirho.sig_chirho,
        )? {
            bail!(
                "agent report charge {} signature invalid",
                charge_chirho.seq_chirho
            );
        }
        let (record_chirho, report_chirho) = reports_by_seq_chirho
            .get(&charge_chirho.report_seq_chirho)
            .ok_or_else(|| anyhow!("agent report charge references unknown report seq"))?;
        if !charged_reports_chirho.insert(charge_chirho.report_seq_chirho) {
            bail!("duplicate agent report charge for one report seq");
        }
        let expected_review_chirho = review_agent_report_priority_chirho(report_chirho);
        let expected_cost_chirho = agent_report_cost_token_chirho(report_chirho);
        if charge_chirho.report_chirho != record_chirho.report_chirho
            || charge_chirho.producer_principal_chirho != record_chirho.producer_principal_chirho
            || charge_chirho.requested_priority_chirho != report_chirho.priority_chirho
            || charge_chirho.effective_priority_chirho
                != expected_review_chirho.effective_priority_chirho
            || charge_chirho.priority_review_chirho != expected_review_chirho
            || charge_chirho.cost_token_chirho != expected_cost_chirho
            || charge_chirho.at_ms_chirho != record_chirho.at_ms_chirho
        {
            bail!(
                "agent report charge {} does not match report/review/cost",
                charge_chirho.seq_chirho
            );
        }
        let spent_chirho = spent_by_agent_chirho
            .entry(charge_chirho.producer_principal_chirho.clone())
            .or_insert(0);
        *spent_chirho = spent_chirho
            .checked_add(charge_chirho.cost_token_chirho)
            .ok_or_else(|| anyhow!("agent report spend overflow"))?;
        let granted_chirho = grants_by_agent_chirho
            .get(&charge_chirho.producer_principal_chirho)
            .copied()
            .unwrap_or(0);
        let expected_remaining_chirho = granted_chirho
            .checked_sub(*spent_chirho)
            .ok_or_else(|| anyhow!("agent report budget underflow"))?;
        if expected_remaining_chirho != charge_chirho.remaining_budget_token_chirho {
            bail!(
                "agent report charge {} remaining budget mismatch",
                charge_chirho.seq_chirho
            );
        }
        if expected_remaining_chirho < 0 {
            bail!(
                "agent report charge {} overspends report budget",
                charge_chirho.seq_chirho
            );
        }
    }
    if charged_reports_chirho.len() != report_records_chirho.len() {
        bail!("agent report accounting must charge every report exactly once");
    }
    Ok(charges_chirho.len())
}

pub fn parse_agent_report_category_chirho(raw_chirho: &str) -> Result<AgentReportCategoryChirho> {
    match raw_chirho.trim() {
        "informational" | "informational-chirho" => {
            Ok(AgentReportCategoryChirho::InformationalChirho)
        }
        "decisional" | "decisional-chirho" => Ok(AgentReportCategoryChirho::DecisionalChirho),
        other_chirho => bail!("unknown agent report category '{other_chirho}'"),
    }
}

pub fn parse_agent_report_priority_chirho(raw_chirho: &str) -> Result<AgentReportPriorityChirho> {
    match raw_chirho.trim() {
        "low" | "low-chirho" => Ok(AgentReportPriorityChirho::LowChirho),
        "normal" | "normal-chirho" => Ok(AgentReportPriorityChirho::NormalChirho),
        "high" | "high-chirho" => Ok(AgentReportPriorityChirho::HighChirho),
        "critical" | "critical-chirho" => Ok(AgentReportPriorityChirho::CriticalChirho),
        other_chirho => bail!("unknown agent report priority '{other_chirho}'"),
    }
}

pub fn parse_agent_report_evidence_ref_chirho(
    raw_chirho: &str,
) -> Result<AgentReportEvidenceRefChirho> {
    let (kind_chirho, ref_chirho) = raw_chirho
        .split_once(':')
        .ok_or_else(|| anyhow!("evidence must be kind:ref"))?;
    Ok(AgentReportEvidenceRefChirho {
        kind_chirho: parse_evidence_kind_chirho(kind_chirho)?,
        ref_chirho: ref_chirho.trim().to_string(),
    })
}

pub fn parse_agent_requested_action_chirho(raw_chirho: &str) -> Result<AgentRequestedActionChirho> {
    let mut parts_chirho = raw_chirho.splitn(3, ':');
    let kind_chirho = parts_chirho
        .next()
        .ok_or_else(|| anyhow!("requested action must be kind:target:reason"))?;
    let target_chirho = parts_chirho
        .next()
        .ok_or_else(|| anyhow!("requested action must include target"))?;
    let reason_chirho = parts_chirho
        .next()
        .ok_or_else(|| anyhow!("requested action must include reason"))?;
    Ok(AgentRequestedActionChirho {
        kind_chirho: parse_requested_action_kind_chirho(kind_chirho)?,
        target_chirho: target_chirho.trim().to_string(),
        reason_chirho: reason_chirho.trim().to_string(),
    })
}

pub fn category_label_chirho(category_chirho: &AgentReportCategoryChirho) -> &'static str {
    match category_chirho {
        AgentReportCategoryChirho::InformationalChirho => "informational-chirho",
        AgentReportCategoryChirho::DecisionalChirho => "decisional-chirho",
    }
}

pub fn priority_label_chirho(priority_chirho: &AgentReportPriorityChirho) -> &'static str {
    match priority_chirho {
        AgentReportPriorityChirho::LowChirho => "low-chirho",
        AgentReportPriorityChirho::NormalChirho => "normal-chirho",
        AgentReportPriorityChirho::HighChirho => "high-chirho",
        AgentReportPriorityChirho::CriticalChirho => "critical-chirho",
    }
}

pub fn review_agent_report_priority_chirho(
    report_chirho: &AgentReportChirho,
) -> AgentReportPriorityReviewChirho {
    let ceiling_chirho = inferred_priority_ceiling_chirho(report_chirho);
    let effective_priority_chirho =
        min_priority_chirho(&report_chirho.priority_chirho, &ceiling_chirho);
    let downgraded_chirho = effective_priority_chirho != report_chirho.priority_chirho;
    let reason_chirho = if downgraded_chirho {
        format!(
            "requested {} exceeded deterministic reviewer ceiling {} for current evidence/action structure",
            priority_label_chirho(&report_chirho.priority_chirho),
            priority_label_chirho(&effective_priority_chirho)
        )
    } else {
        "requested priority accepted by deterministic reviewer".to_string()
    };
    AgentReportPriorityReviewChirho {
        requested_priority_chirho: report_chirho.priority_chirho.clone(),
        effective_priority_chirho,
        reviewer_principal_chirho: "system/agent-report-priority-reviewer-chirho".to_string(),
        downgraded_chirho,
        reason_chirho,
    }
}

pub fn agent_report_cost_token_chirho(report_chirho: &AgentReportChirho) -> i64 {
    match &report_chirho.priority_chirho {
        AgentReportPriorityChirho::LowChirho => 1,
        AgentReportPriorityChirho::NormalChirho => 2,
        AgentReportPriorityChirho::HighChirho => 4,
        AgentReportPriorityChirho::CriticalChirho => 8,
    }
}

fn agent_report_budget_balance_unlocked_chirho(
    root_chirho: &Path,
    agent_principal_chirho: &str,
) -> Result<AgentReportBudgetBalanceChirho> {
    let mut granted_token_chirho = 0_i64;
    for grant_chirho in load_agent_report_budget_grants_chirho(root_chirho)? {
        if grant_chirho.agent_principal_chirho == agent_principal_chirho {
            granted_token_chirho = granted_token_chirho
                .checked_add(grant_chirho.amount_token_chirho)
                .ok_or_else(|| anyhow!("agent report budget grant overflow"))?;
        }
    }
    let mut spent_token_chirho = 0_i64;
    for charge_chirho in load_agent_report_charge_records_chirho(root_chirho)? {
        if charge_chirho.producer_principal_chirho == agent_principal_chirho {
            spent_token_chirho = spent_token_chirho
                .checked_add(charge_chirho.cost_token_chirho)
                .ok_or_else(|| anyhow!("agent report spend overflow"))?;
        }
    }
    Ok(AgentReportBudgetBalanceChirho {
        agent_principal_chirho: agent_principal_chirho.to_string(),
        granted_token_chirho,
        spent_token_chirho,
        remaining_token_chirho: granted_token_chirho
            .checked_sub(spent_token_chirho)
            .ok_or_else(|| anyhow!("agent report budget underflow"))?,
    })
}

fn inferred_priority_ceiling_chirho(
    report_chirho: &AgentReportChirho,
) -> AgentReportPriorityChirho {
    if matches!(
        report_chirho.category_chirho,
        AgentReportCategoryChirho::DecisionalChirho
    ) && report_chirho.requested_action_chirho.is_some()
        && report_chirho.evidence_refs_chirho.len() >= 2
        && (!report_chirho.related_effect_ids_chirho.is_empty()
            || report_chirho.related_run_ids_chirho.len() >= 2)
    {
        return AgentReportPriorityChirho::CriticalChirho;
    }
    if (matches!(
        report_chirho.category_chirho,
        AgentReportCategoryChirho::DecisionalChirho
    ) && report_chirho.requested_action_chirho.is_some())
        || report_chirho.evidence_refs_chirho.len() >= 2
        || !report_chirho.related_effect_ids_chirho.is_empty()
    {
        return AgentReportPriorityChirho::HighChirho;
    }
    AgentReportPriorityChirho::NormalChirho
}

fn min_priority_chirho(
    left_chirho: &AgentReportPriorityChirho,
    right_chirho: &AgentReportPriorityChirho,
) -> AgentReportPriorityChirho {
    if priority_rank_chirho(left_chirho) <= priority_rank_chirho(right_chirho) {
        left_chirho.clone()
    } else {
        right_chirho.clone()
    }
}

pub fn priority_rank_chirho(priority_chirho: &AgentReportPriorityChirho) -> u8 {
    match priority_chirho {
        AgentReportPriorityChirho::LowChirho => 0,
        AgentReportPriorityChirho::NormalChirho => 1,
        AgentReportPriorityChirho::HighChirho => 2,
        AgentReportPriorityChirho::CriticalChirho => 3,
    }
}

fn validate_agent_report_chirho(
    root_chirho: &Path,
    report_chirho: &AgentReportChirho,
) -> Result<()> {
    validate_principal_chirho(&report_chirho.producer_principal_chirho)?;
    validate_lede_chirho(&report_chirho.lede_chirho)?;
    if report_chirho.evidence_refs_chirho.is_empty() {
        bail!("agent report must include at least one evidence ref");
    }
    let mut evidence_seen_chirho = BTreeSet::new();
    for evidence_chirho in &report_chirho.evidence_refs_chirho {
        validate_evidence_ref_chirho(root_chirho, evidence_chirho)?;
        if !evidence_seen_chirho.insert((
            evidence_kind_label_chirho(&evidence_chirho.kind_chirho),
            evidence_chirho.ref_chirho.clone(),
        )) {
            bail!("duplicate agent report evidence ref");
        }
    }
    for run_chirho in &report_chirho.related_run_ids_chirho {
        validate_hash_like_chirho("related run id", &run_chirho.0)?;
        require_cas_object_chirho(root_chirho, "related run id", run_chirho)?;
    }
    let mut effect_seen_chirho = BTreeSet::new();
    for effect_chirho in &report_chirho.related_effect_ids_chirho {
        validate_safe_text_chirho("related effect id", effect_chirho, 160)?;
        if !effect_seen_chirho.insert(effect_chirho) {
            bail!("duplicate related effect id");
        }
    }
    if let Some(action_chirho) = &report_chirho.requested_action_chirho {
        validate_requested_action_chirho(action_chirho)?;
    }
    Ok(())
}

fn validate_lede_chirho(lede_chirho: &AgentReportLedeChirho) -> Result<()> {
    validate_safe_text_chirho("what happened", &lede_chirho.happened_chirho, 240)?;
    validate_safe_text_chirho("what was affected", &lede_chirho.affected_chirho, 240)?;
    validate_safe_text_chirho("why it matters", &lede_chirho.why_matters_chirho, 240)?;
    for (label_chirho, value_chirho) in [
        ("what happened", &lede_chirho.happened_chirho),
        ("what was affected", &lede_chirho.affected_chirho),
        ("why it matters", &lede_chirho.why_matters_chirho),
    ] {
        if weak_lede_phrase_chirho(value_chirho) {
            bail!("agent report lede field '{label_chirho}' is too weak");
        }
    }
    let total_words_chirho = lede_chirho.happened_chirho.split_whitespace().count()
        + lede_chirho.affected_chirho.split_whitespace().count()
        + lede_chirho.why_matters_chirho.split_whitespace().count();
    if total_words_chirho < 9 {
        bail!("agent report lede must state what happened, what was affected, and why it matters");
    }
    Ok(())
}

fn validate_evidence_ref_chirho(
    root_chirho: &Path,
    evidence_chirho: &AgentReportEvidenceRefChirho,
) -> Result<()> {
    validate_safe_text_chirho("evidence ref", &evidence_chirho.ref_chirho, 260)?;
    match evidence_chirho.kind_chirho {
        AgentReportEvidenceKindChirho::ObjectChirho | AgentReportEvidenceKindChirho::RunChirho => {
            validate_hash_like_chirho("evidence hash", &evidence_chirho.ref_chirho)?;
            require_cas_object_chirho(
                root_chirho,
                "evidence hash",
                &HashChirho(evidence_chirho.ref_chirho.clone()),
            )
        }
        AgentReportEvidenceKindChirho::LogChirho | AgentReportEvidenceKindChirho::EffectChirho => {
            Ok(())
        }
    }
}

fn validate_requested_action_chirho(action_chirho: &AgentRequestedActionChirho) -> Result<()> {
    validate_safe_text_chirho("requested action target", &action_chirho.target_chirho, 200)?;
    validate_safe_text_chirho("requested action reason", &action_chirho.reason_chirho, 280)?;
    Ok(())
}

fn validate_principal_chirho(principal_chirho: &str) -> Result<()> {
    validate_safe_text_chirho("producer principal", principal_chirho, 160)?;
    if principal_chirho.chars().any(char::is_whitespace) || !principal_chirho.contains('/') {
        bail!("producer principal must be a path-like principal such as agent/name-chirho");
    }
    Ok(())
}

fn validate_safe_text_chirho(
    label_chirho: &str,
    value_chirho: &str,
    max_chars_chirho: usize,
) -> Result<()> {
    let trimmed_chirho = value_chirho.trim();
    if trimmed_chirho.is_empty() {
        bail!("{label_chirho} must not be empty");
    }
    if trimmed_chirho != value_chirho {
        bail!("{label_chirho} must not have leading or trailing whitespace");
    }
    if value_chirho.chars().any(char::is_control) {
        bail!("{label_chirho} must not contain control characters");
    }
    if value_chirho.chars().count() > max_chars_chirho {
        bail!("{label_chirho} is too long");
    }
    Ok(())
}

fn validate_hash_like_chirho(label_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.len() != 64
        || !value_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit())
    {
        bail!("{label_chirho} must be a 64-character hex content hash");
    }
    Ok(())
}

fn require_cas_object_chirho(
    root_chirho: &Path,
    label_chirho: &str,
    hash_chirho: &HashChirho,
) -> Result<()> {
    cas_chirho::get_chirho(root_chirho, hash_chirho).with_context(|| {
        format!(
            "{label_chirho} {} does not resolve in the content-addressed store",
            hash_chirho.0
        )
    })?;
    Ok(())
}

fn weak_lede_phrase_chirho(value_chirho: &str) -> bool {
    let lowered_chirho = value_chirho.trim().to_ascii_lowercase();
    matches!(
        lowered_chirho.as_str(),
        "working on it"
            | "still working"
            | "in progress"
            | "progress update"
            | "no update"
            | "no blockers"
            | "looking into it"
            | "checking"
            | "continuing"
    )
}

fn parse_evidence_kind_chirho(raw_chirho: &str) -> Result<AgentReportEvidenceKindChirho> {
    match raw_chirho.trim() {
        "object" | "object-chirho" => Ok(AgentReportEvidenceKindChirho::ObjectChirho),
        "log" | "log-chirho" => Ok(AgentReportEvidenceKindChirho::LogChirho),
        "run" | "run-chirho" => Ok(AgentReportEvidenceKindChirho::RunChirho),
        "effect" | "effect-chirho" => Ok(AgentReportEvidenceKindChirho::EffectChirho),
        other_chirho => bail!("unknown agent report evidence kind '{other_chirho}'"),
    }
}

fn parse_requested_action_kind_chirho(raw_chirho: &str) -> Result<AgentRequestedActionKindChirho> {
    match raw_chirho.trim() {
        "grant" | "grant-chirho" => Ok(AgentRequestedActionKindChirho::GrantChirho),
        "narrow" | "narrow-chirho" => Ok(AgentRequestedActionKindChirho::NarrowChirho),
        "revoke" | "revoke-chirho" => Ok(AgentRequestedActionKindChirho::RevokeChirho),
        "budget-change" | "budget-change-chirho" => {
            Ok(AgentRequestedActionKindChirho::BudgetChangeChirho)
        }
        "scope-change" | "scope-change-chirho" => {
            Ok(AgentRequestedActionKindChirho::ScopeChangeChirho)
        }
        "parameter-change" | "parameter-change-chirho" => {
            Ok(AgentRequestedActionKindChirho::ParameterChangeChirho)
        }
        other_chirho => bail!("unknown requested action kind '{other_chirho}'"),
    }
}

fn evidence_kind_label_chirho(kind_chirho: &AgentReportEvidenceKindChirho) -> &'static str {
    match kind_chirho {
        AgentReportEvidenceKindChirho::ObjectChirho => "object-chirho",
        AgentReportEvidenceKindChirho::LogChirho => "log-chirho",
        AgentReportEvidenceKindChirho::RunChirho => "run-chirho",
        AgentReportEvidenceKindChirho::EffectChirho => "effect-chirho",
    }
}

fn trim_checked_chirho(value_chirho: String) -> String {
    value_chirho.trim().to_string()
}

fn agent_report_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("agent-reports-chirho.jsonl")
}

fn agent_report_budget_grants_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("agent-report-budgets-chirho.jsonl")
}

fn agent_report_charges_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("agent-report-charges-chirho.jsonl")
}

fn agent_report_record_message_chirho(record_chirho: &AgentReportRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn agent_report_budget_grant_message_chirho(
    record_chirho: &AgentReportBudgetGrantRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn agent_report_charge_message_chirho(
    record_chirho: &AgentReportChargeRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn verify_agent_report_record_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("unsupported {label_chirho} schema '{schema_chirho}'");
    }
    Ok(())
}

fn load_jsonl_chirho<T: for<'de> Deserialize<'de>>(path_chirho: &Path) -> Result<Vec<T>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        out_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(out_chirho)
}

fn jsonl_len_chirho(path_chirho: &Path) -> Result<u64> {
    if !path_chirho.exists() {
        return Ok(0);
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .count() as u64)
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!(
            "cairn-agent-report-test-{label_chirho}-{n_chirho}-{}",
            now_ms_chirho()
        ))
    }

    fn evidence_hash_chirho(root_chirho: &Path, label_chirho: &str) -> HashChirho {
        cas_chirho::add_chirho(root_chirho, label_chirho.as_bytes()).unwrap()
    }

    fn grant_budget_chirho(root_chirho: &Path, amount_token_chirho: i64) {
        grant_agent_report_budget_chirho(
            root_chirho,
            AgentReportBudgetGrantInputChirho {
                agent_principal_chirho: "agent/codex-chirho".to_string(),
                granted_by_chirho: "owner/newsroom-chirho".to_string(),
                amount_token_chirho,
                reason_chirho: "Test report budget grant".to_string(),
            },
        )
        .unwrap();
    }

    fn valid_input_chirho(root_chirho: &Path) -> AgentReportInputChirho {
        let run_chirho = evidence_hash_chirho(root_chirho, "run-evidence-chirho");
        AgentReportInputChirho {
            producer_principal_chirho: "agent/codex-chirho".to_string(),
            category_chirho: AgentReportCategoryChirho::DecisionalChirho,
            priority_chirho: AgentReportPriorityChirho::HighChirho,
            happened_chirho: "M32.1 report validation rejected weak agent updates".to_string(),
            affected_chirho: "Agent oversight records and future news-center queues".to_string(),
            why_matters_chirho:
                "Operators get evidence-backed items instead of raw transcript noise".to_string(),
            evidence_refs_chirho: vec![AgentReportEvidenceRefChirho {
                kind_chirho: AgentReportEvidenceKindChirho::RunChirho,
                ref_chirho: run_chirho.0.clone(),
            }],
            related_run_ids_chirho: vec![run_chirho],
            related_effect_ids_chirho: vec!["effect-seq:7".to_string()],
            requested_action_chirho: Some(AgentRequestedActionChirho {
                kind_chirho: AgentRequestedActionKindChirho::NarrowChirho,
                target_chirho: "agent/codex-chirho/support-issue/*".to_string(),
                reason_chirho: "Limit follow-up writes until owner approval lands".to_string(),
            }),
        }
    }

    fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, rows_chirho: &[T]) {
        let mut text_chirho = String::new();
        for row_chirho in rows_chirho {
            text_chirho.push_str(&serde_json::to_string(row_chirho).unwrap());
            text_chirho.push('\n');
        }
        std::fs::write(path_chirho, text_chirho).unwrap();
    }

    #[test]
    fn valid_agent_report_is_content_addressed_logged_and_verified_chirho() {
        let root_chirho = temp_root_chirho("valid");
        grant_budget_chirho(&root_chirho, 8);
        let record_chirho =
            emit_agent_report_chirho(&root_chirho, valid_input_chirho(&root_chirho)).unwrap();
        assert_eq!(record_chirho.seq_chirho, 0);
        assert_eq!(record_chirho.evidence_count_chirho, 1);

        let report_chirho =
            load_agent_report_chirho(&root_chirho, &record_chirho.report_chirho).unwrap();
        assert_eq!(
            report_chirho.producer_principal_chirho,
            "agent/codex-chirho"
        );
        assert_eq!(
            store_chirho::hash_object_chirho(&report_chirho).unwrap(),
            record_chirho.report_chirho
        );
        assert_eq!(verify_agent_report_records_chirho(&root_chirho).unwrap(), 1);
        assert_eq!(
            verify_agent_report_accounting_chirho(&root_chirho).unwrap(),
            1
        );
        assert_eq!(
            agent_report_budget_balance_chirho(&root_chirho, "agent/codex-chirho")
                .unwrap()
                .remaining_token_chirho,
            4
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn agent_report_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
        let root_chirho = temp_root_chirho("schema-report");
        grant_budget_chirho(&root_chirho, 8);
        emit_agent_report_chirho(&root_chirho, valid_input_chirho(&root_chirho)).unwrap();
        let reports_chirho = load_agent_report_records_chirho(&root_chirho).unwrap();
        let grants_chirho = load_agent_report_budget_grants_chirho(&root_chirho).unwrap();
        let charges_chirho = load_agent_report_charge_records_chirho(&root_chirho).unwrap();
        assert_eq!(
            reports_chirho[0].schema_chirho,
            AGENT_REPORT_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            grants_chirho[0].schema_chirho,
            AGENT_REPORT_BUDGET_GRANT_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            charges_chirho[0].schema_chirho,
            AGENT_REPORT_CHARGE_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(verify_agent_report_records_chirho(&root_chirho).unwrap(), 1);
        assert_eq!(
            verify_agent_report_accounting_chirho(&root_chirho).unwrap(),
            1
        );

        let mut bad_reports_chirho = reports_chirho;
        bad_reports_chirho[0].schema_chirho = "agent-report-record-v9-chirho".to_string();
        write_jsonl_chirho(
            &agent_report_records_path_chirho(&root_chirho),
            &bad_reports_chirho,
        );
        let error_chirho = verify_agent_report_records_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported agent report record schema"));
        let _ = std::fs::remove_dir_all(&root_chirho);

        let root_chirho = temp_root_chirho("schema-grant");
        grant_budget_chirho(&root_chirho, 8);
        let mut bad_grants_chirho = load_agent_report_budget_grants_chirho(&root_chirho).unwrap();
        bad_grants_chirho[0].schema_chirho =
            "agent-report-budget-grant-record-v9-chirho".to_string();
        write_jsonl_chirho(
            &agent_report_budget_grants_path_chirho(&root_chirho),
            &bad_grants_chirho,
        );
        let error_chirho = verify_agent_report_accounting_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported agent report budget grant record schema"));
        let _ = std::fs::remove_dir_all(&root_chirho);

        let root_chirho = temp_root_chirho("schema-charge");
        grant_budget_chirho(&root_chirho, 8);
        emit_agent_report_chirho(&root_chirho, valid_input_chirho(&root_chirho)).unwrap();
        let mut bad_charges_chirho = load_agent_report_charge_records_chirho(&root_chirho).unwrap();
        bad_charges_chirho[0].schema_chirho = "agent-report-charge-record-v9-chirho".to_string();
        write_jsonl_chirho(
            &agent_report_charges_path_chirho(&root_chirho),
            &bad_charges_chirho,
        );
        let error_chirho = verify_agent_report_accounting_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported agent report charge record schema"));
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn legacy_agent_report_records_without_schema_still_verify_chirho() {
        let root_chirho = temp_root_chirho("legacy-schema");
        grant_budget_chirho(&root_chirho, 8);
        emit_agent_report_chirho(&root_chirho, valid_input_chirho(&root_chirho)).unwrap();

        let mut reports_chirho = load_agent_report_records_chirho(&root_chirho).unwrap();
        reports_chirho[0].schema_chirho.clear();
        reports_chirho[0].sig_chirho.clear();
        reports_chirho[0].sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &agent_report_record_message_chirho(&reports_chirho[0]).unwrap(),
        )
        .unwrap();
        write_jsonl_chirho(
            &agent_report_records_path_chirho(&root_chirho),
            &reports_chirho,
        );

        let mut grants_chirho = load_agent_report_budget_grants_chirho(&root_chirho).unwrap();
        grants_chirho[0].schema_chirho.clear();
        grants_chirho[0].sig_chirho.clear();
        grants_chirho[0].sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &agent_report_budget_grant_message_chirho(&grants_chirho[0]).unwrap(),
        )
        .unwrap();
        write_jsonl_chirho(
            &agent_report_budget_grants_path_chirho(&root_chirho),
            &grants_chirho,
        );

        let mut charges_chirho = load_agent_report_charge_records_chirho(&root_chirho).unwrap();
        charges_chirho[0].schema_chirho.clear();
        charges_chirho[0].sig_chirho.clear();
        charges_chirho[0].sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &agent_report_charge_message_chirho(&charges_chirho[0]).unwrap(),
        )
        .unwrap();
        write_jsonl_chirho(
            &agent_report_charges_path_chirho(&root_chirho),
            &charges_chirho,
        );

        for path_chirho in [
            agent_report_records_path_chirho(&root_chirho),
            agent_report_budget_grants_path_chirho(&root_chirho),
            agent_report_charges_path_chirho(&root_chirho),
        ] {
            let text_chirho = std::fs::read_to_string(path_chirho).unwrap();
            assert!(!text_chirho.contains("schema_chirho"));
        }
        assert_eq!(verify_agent_report_records_chirho(&root_chirho).unwrap(), 1);
        assert_eq!(
            verify_agent_report_accounting_chirho(&root_chirho).unwrap(),
            1
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn weak_lede_or_missing_evidence_is_refused_chirho() {
        let root_chirho = temp_root_chirho("weak");
        grant_budget_chirho(&root_chirho, 8);
        let mut input_chirho = valid_input_chirho(&root_chirho);
        input_chirho.happened_chirho = "working on it".to_string();
        assert!(emit_agent_report_chirho(&root_chirho, input_chirho).is_err());

        let mut input_chirho = valid_input_chirho(&root_chirho);
        input_chirho.evidence_refs_chirho.clear();
        assert!(emit_agent_report_chirho(&root_chirho, input_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn unresolved_content_evidence_is_refused_chirho() {
        let root_chirho = temp_root_chirho("missing-evidence");
        grant_budget_chirho(&root_chirho, 8);
        let mut input_chirho = valid_input_chirho(&root_chirho);
        input_chirho.evidence_refs_chirho[0].ref_chirho = format!("{:064x}", 7);
        assert!(emit_agent_report_chirho(&root_chirho, input_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn tampered_agent_report_log_is_rejected_chirho() {
        let root_chirho = temp_root_chirho("tamper");
        grant_budget_chirho(&root_chirho, 8);
        emit_agent_report_chirho(&root_chirho, valid_input_chirho(&root_chirho)).unwrap();
        let path_chirho = agent_report_records_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        std::fs::write(
            &path_chirho,
            text_chirho.replace("agent/codex-chirho", "agent/forged-chirho"),
        )
        .unwrap();
        assert!(verify_agent_report_records_chirho(&root_chirho).is_err());
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn report_budget_throttles_over_reporting_chirho() {
        let root_chirho = temp_root_chirho("budget");
        grant_budget_chirho(&root_chirho, 4);
        emit_agent_report_chirho(&root_chirho, valid_input_chirho(&root_chirho)).unwrap();
        assert!(emit_agent_report_chirho(&root_chirho, valid_input_chirho(&root_chirho)).is_err());
        assert_eq!(
            load_agent_report_records_chirho(&root_chirho)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            verify_agent_report_accounting_chirho(&root_chirho).unwrap(),
            1
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn priority_review_downgrades_overclaimed_priority_chirho() {
        let root_chirho = temp_root_chirho("priority");
        grant_budget_chirho(&root_chirho, 8);
        let mut input_chirho = valid_input_chirho(&root_chirho);
        input_chirho.priority_chirho = AgentReportPriorityChirho::CriticalChirho;
        input_chirho.related_effect_ids_chirho.clear();
        let record_chirho = emit_agent_report_chirho(&root_chirho, input_chirho).unwrap();
        let charge_chirho = agent_report_charge_by_report_seq_chirho(&root_chirho)
            .unwrap()
            .remove(&record_chirho.seq_chirho)
            .unwrap();
        assert_eq!(
            charge_chirho.requested_priority_chirho,
            AgentReportPriorityChirho::CriticalChirho
        );
        assert_eq!(
            charge_chirho.effective_priority_chirho,
            AgentReportPriorityChirho::HighChirho
        );
        assert!(charge_chirho.priority_review_chirho.downgraded_chirho);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
