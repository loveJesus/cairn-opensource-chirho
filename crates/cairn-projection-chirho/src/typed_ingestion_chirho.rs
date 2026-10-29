// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Ring A typed-ingestion parity for Gate 1 shadow recovery evidence.

use crate::projection_chirho::{
    materialize_live_byte_baseline_chirho, static_surface_manifest_chirho,
    verify_cas_dependencies_in_value_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::clsd_chirho::{clsd_digest_chirho, ProjectionStateChirho};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::{
    BillingCompensationRecordChirho, BillingPolicyRecordChirho, BillingUsageRecordChirho,
    CreditHoldRecordChirho, LedgerEntryChirho, ResourcePolicyRecordChirho,
    ResourcePolicyUnsetRecordChirho, ResourceUsageRecordChirho,
    BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO, BILLING_POLICY_RECORD_SCHEMA_CHIRHO,
    BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO, BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
    CREDIT_HOLD_RECORD_SCHEMA_CHIRHO, LEDGER_ENTRY_SCHEMA_CHIRHO,
    RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO, RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO,
    RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO, RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO,
};
use cairn_model_gate1_chirho::{Gate1LogAnchorRecordChirho, GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO};
use cairn_model_review_chirho::{
    ReviewPolicyEnvelopeRecordChirho, REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const TYPED_INGESTION_PARITY_REPORT_SCHEMA_CHIRHO: &str =
    "typed-ingestion-parity-report-v2-chirho";

type ParserChirho = fn(&str) -> Result<String>;

#[derive(Clone, Copy)]
struct TypedSurfaceChirho {
    name_chirho: &'static str,
    parser_chirho: ParserChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedIngestionParityReportChirho {
    pub schema_chirho: String,
    pub typed_surface_count_chirho: usize,
    pub static_surface_manifest_count_chirho: usize,
    pub checked_line_count_chirho: usize,
    pub typed_surface_names_chirho: Vec<String>,
    pub typed_clsd_digest_chirho: String,
    pub live_clsd_digest_chirho: String,
    pub typed_recover_clsd_digest_chirho: String,
    pub byte_baseline_clsd_digest_chirho: String,
    pub clsd_digests_match_chirho: bool,
}

pub fn typed_ingestion_parity_report_chirho(
    root_chirho: &Path,
) -> Result<TypedIngestionParityReportChirho> {
    let (typed_state_chirho, checked_line_count_chirho) =
        materialize_typed_recover_chirho(root_chirho)?;
    let byte_baseline_state_chirho = materialize_live_byte_baseline_chirho(root_chirho)?;
    let typed_digest_chirho = clsd_digest_chirho(&typed_state_chirho);
    let byte_baseline_digest_chirho = clsd_digest_chirho(&byte_baseline_state_chirho);

    Ok(TypedIngestionParityReportChirho {
        schema_chirho: TYPED_INGESTION_PARITY_REPORT_SCHEMA_CHIRHO.to_string(),
        typed_surface_count_chirho: ring_a_typed_surfaces_chirho().len(),
        static_surface_manifest_count_chirho: static_surface_manifest_chirho().len(),
        checked_line_count_chirho,
        typed_surface_names_chirho: ring_a_typed_surfaces_chirho()
            .iter()
            .map(|surface_chirho| surface_chirho.name_chirho.to_string())
            .collect(),
        typed_clsd_digest_chirho: typed_digest_chirho.0.clone(),
        live_clsd_digest_chirho: byte_baseline_digest_chirho.0.clone(),
        typed_recover_clsd_digest_chirho: typed_digest_chirho.0.clone(),
        byte_baseline_clsd_digest_chirho: byte_baseline_digest_chirho.0.clone(),
        clsd_digests_match_chirho: typed_digest_chirho == byte_baseline_digest_chirho,
    })
}

pub fn verify_typed_ingestion_parity_chirho(
    root_chirho: &Path,
) -> Result<TypedIngestionParityReportChirho> {
    let report_chirho = typed_ingestion_parity_report_chirho(root_chirho)?;
    if !report_chirho.clsd_digests_match_chirho {
        bail!(
            "typed-ingestion parity CLSD mismatch: typed={} live={}",
            report_chirho.typed_clsd_digest_chirho,
            report_chirho.live_clsd_digest_chirho
        );
    }
    Ok(report_chirho)
}

/// Typed-recover projection view for Gate 1 typed-ingestion parity.
///
/// This is the typed mechanism side of the report. The independent comparator remains
/// `materialize_live_byte_baseline_chirho`/`materialize_live_chirho`, which hashes physical log
/// bytes rather than canonical typed records.
pub fn materialize_typed_recover_chirho(
    root_chirho: &Path,
) -> Result<(ProjectionStateChirho, usize)> {
    materialize_typed_ingestion_chirho(root_chirho)
}

/// Typed-ingestion materializer retained for existing callers; its role is the same typed-recover
/// mechanism exported through `materialize_typed_recover_chirho`.
pub fn materialize_typed_ingestion_chirho(
    root_chirho: &Path,
) -> Result<(ProjectionStateChirho, usize)> {
    let mut state_chirho = ProjectionStateChirho::default();
    let mut checked_line_count_chirho = 0usize;

    for filename_chirho in static_surface_manifest_chirho() {
        let path_chirho = root_chirho.join(filename_chirho);
        if !path_chirho.exists() {
            continue;
        }

        let content_chirho = fs::read_to_string(&path_chirho)
            .with_context(|| format!("read manifest log file {}", path_chirho.display()))?;
        let parser_chirho = typed_surface_by_name_chirho(filename_chirho);

        let mut line_idx_chirho = 0usize;
        for line_chirho in content_chirho.lines() {
            if line_chirho.trim().is_empty() {
                continue;
            }

            let canonical_line_chirho = if let Some(surface_chirho) = parser_chirho {
                (surface_chirho.parser_chirho)(line_chirho).with_context(|| {
                    format!(
                        "typed ingestion parse failed for {} line {}",
                        filename_chirho, line_idx_chirho
                    )
                })?
            } else {
                line_chirho.trim().to_string()
            };

            let value_chirho =
                serde_json::from_str::<Value>(&canonical_line_chirho).with_context(|| {
                    format!(
                        "parse manifest log file {} line {} as JSON",
                        filename_chirho, line_idx_chirho
                    )
                })?;
            verify_cas_dependencies_in_value_chirho(
                root_chirho,
                filename_chirho,
                line_idx_chirho,
                &value_chirho,
            )?;

            let line_hash_chirho = HashChirho(
                blake3::hash(canonical_line_chirho.as_bytes())
                    .to_hex()
                    .to_string(),
            );
            state_chirho.insert_chirho(
                *filename_chirho,
                line_idx_chirho.to_string(),
                line_hash_chirho,
            );
            checked_line_count_chirho += 1;
            line_idx_chirho += 1;
        }
    }

    Ok((state_chirho, checked_line_count_chirho))
}

pub fn typed_ledger_entries_chirho(root_chirho: &Path) -> Result<Vec<LedgerEntryChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "ledger-chirho.jsonl",
        "ledger",
        parse_ledger_entry_chirho,
        "LedgerEntryChirho",
    )
}

pub fn typed_ledger_entries_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<LedgerEntryChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "ledger-chirho.jsonl",
        "ledger",
        parse_ledger_entry_chirho,
        "LedgerEntryChirho",
        line_count_chirho,
    )
}

pub fn typed_billing_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<BillingPolicyRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "billing-policy-records-chirho.jsonl",
        "billing policy",
        parse_billing_policy_record_chirho,
        "BillingPolicyRecordChirho",
    )
}

pub fn typed_billing_policy_records_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<BillingPolicyRecordChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "billing-policy-records-chirho.jsonl",
        "billing policy",
        parse_billing_policy_record_chirho,
        "BillingPolicyRecordChirho",
        line_count_chirho,
    )
}

pub fn typed_billing_usage_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<BillingUsageRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "billing-usage-chirho.jsonl",
        "billing usage",
        parse_billing_usage_record_chirho,
        "BillingUsageRecordChirho",
    )
}

pub fn typed_billing_usage_records_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<BillingUsageRecordChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "billing-usage-chirho.jsonl",
        "billing usage",
        parse_billing_usage_record_chirho,
        "BillingUsageRecordChirho",
        line_count_chirho,
    )
}

pub fn typed_billing_compensation_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<BillingCompensationRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "billing-compensations-chirho.jsonl",
        "billing compensation",
        parse_billing_compensation_record_chirho,
        "BillingCompensationRecordChirho",
    )
}

pub fn typed_billing_compensation_records_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<BillingCompensationRecordChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "billing-compensations-chirho.jsonl",
        "billing compensation",
        parse_billing_compensation_record_chirho,
        "BillingCompensationRecordChirho",
        line_count_chirho,
    )
}

pub fn typed_credit_hold_records_chirho(root_chirho: &Path) -> Result<Vec<CreditHoldRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "credit-holds-chirho.jsonl",
        "hold",
        parse_credit_hold_record_chirho,
        "CreditHoldRecordChirho",
    )
}

pub fn typed_credit_hold_records_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<CreditHoldRecordChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "credit-holds-chirho.jsonl",
        "hold",
        parse_credit_hold_record_chirho,
        "CreditHoldRecordChirho",
        line_count_chirho,
    )
}

pub fn typed_resource_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ResourcePolicyRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "resource-policy-records-chirho.jsonl",
        "resource policy",
        parse_resource_policy_record_chirho,
        "ResourcePolicyRecordChirho",
    )
}

pub fn typed_resource_policy_records_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<ResourcePolicyRecordChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "resource-policy-records-chirho.jsonl",
        "resource policy",
        parse_resource_policy_record_chirho,
        "ResourcePolicyRecordChirho",
        line_count_chirho,
    )
}

pub fn typed_resource_policy_unset_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ResourcePolicyUnsetRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "resource-policy-unset-records-chirho.jsonl",
        "resource policy unset",
        parse_resource_policy_unset_record_chirho,
        "ResourcePolicyUnsetRecordChirho",
    )
}

pub fn typed_resource_policy_unset_records_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<ResourcePolicyUnsetRecordChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "resource-policy-unset-records-chirho.jsonl",
        "resource policy unset",
        parse_resource_policy_unset_record_chirho,
        "ResourcePolicyUnsetRecordChirho",
        line_count_chirho,
    )
}

pub fn typed_resource_usage_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ResourceUsageRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "resource-usage-chirho.jsonl",
        "resource usage",
        parse_resource_usage_record_chirho,
        "ResourceUsageRecordChirho",
    )
}

pub fn typed_resource_usage_records_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<ResourceUsageRecordChirho>> {
    typed_records_from_file_prefix_chirho(
        root_chirho,
        "resource-usage-chirho.jsonl",
        "resource usage",
        parse_resource_usage_record_chirho,
        "ResourceUsageRecordChirho",
        line_count_chirho,
    )
}

pub fn typed_gate1_log_anchor_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1LogAnchorRecordChirho>> {
    typed_records_from_file_chirho(
        root_chirho,
        "gate1-log-anchors-chirho.jsonl",
        "gate1 log anchor",
        parse_gate1_log_anchor_record_chirho,
        "Gate1LogAnchorRecordChirho",
    )
}

fn typed_records_from_file_chirho<TChirho>(
    root_chirho: &Path,
    filename_chirho: &str,
    label_chirho: &str,
    parse_chirho: ParserChirho,
    type_label_chirho: &str,
) -> Result<Vec<TChirho>>
where
    TChirho: DeserializeOwned,
{
    let path_chirho = root_chirho.join(filename_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }

    let content_chirho = fs::read_to_string(&path_chirho).with_context(|| {
        format!(
            "read typed {label_chirho} log file {}",
            path_chirho.display()
        )
    })?;
    let mut records_chirho = Vec::new();
    let mut line_idx_chirho = 0usize;
    for line_chirho in content_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let canonical_line_chirho = parse_chirho(line_chirho).with_context(|| {
            format!(
                "typed ingestion parse failed for {} line {}",
                filename_chirho, line_idx_chirho
            )
        })?;
        let value_chirho =
            serde_json::from_str::<Value>(&canonical_line_chirho).with_context(|| {
                format!(
                    "parse typed {label_chirho} log file {} line {} as JSON",
                    filename_chirho, line_idx_chirho
                )
            })?;
        verify_cas_dependencies_in_value_chirho(
            root_chirho,
            filename_chirho,
            line_idx_chirho,
            &value_chirho,
        )?;
        let record_chirho =
            serde_json::from_str::<TChirho>(&canonical_line_chirho).with_context(|| {
                format!(
                    "parse canonical typed {label_chirho} line {} into {}",
                    line_idx_chirho, type_label_chirho
                )
            })?;
        records_chirho.push(record_chirho);
        line_idx_chirho += 1;
    }

    Ok(records_chirho)
}

fn typed_records_from_file_prefix_chirho<TChirho>(
    root_chirho: &Path,
    filename_chirho: &str,
    label_chirho: &str,
    parse_chirho: ParserChirho,
    type_label_chirho: &str,
    line_count_chirho: u64,
) -> Result<Vec<TChirho>>
where
    TChirho: DeserializeOwned,
{
    let path_chirho = root_chirho.join(filename_chirho);
    let prefix_lines_chirho =
        raw_nonempty_jsonl_prefix_lines_chirho(&path_chirho, line_count_chirho)?;
    let mut records_chirho = Vec::with_capacity(prefix_lines_chirho.len());
    for (line_idx_chirho, line_chirho) in prefix_lines_chirho.iter().enumerate() {
        let canonical_line_chirho = parse_chirho(line_chirho).with_context(|| {
            format!(
                "typed ingestion parse failed for {} line {}",
                filename_chirho, line_idx_chirho
            )
        })?;
        let value_chirho =
            serde_json::from_str::<Value>(&canonical_line_chirho).with_context(|| {
                format!(
                    "parse typed {label_chirho} log file {} line {} as JSON",
                    filename_chirho, line_idx_chirho
                )
            })?;
        verify_cas_dependencies_in_value_chirho(
            root_chirho,
            filename_chirho,
            line_idx_chirho,
            &value_chirho,
        )?;
        let record_chirho =
            serde_json::from_str::<TChirho>(&canonical_line_chirho).with_context(|| {
                format!(
                    "parse canonical typed {label_chirho} line {} into {}",
                    line_idx_chirho, type_label_chirho
                )
            })?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

fn raw_nonempty_jsonl_prefix_lines_chirho(
    path_chirho: &Path,
    line_count_chirho: u64,
) -> Result<Vec<String>> {
    let count_chirho = usize::try_from(line_count_chirho)
        .map_err(|_| anyhow!("typed prefix line count does not fit usize"))?;
    if !path_chirho.exists() {
        if count_chirho == 0 {
            return Ok(Vec::new());
        }
        bail!(
            "typed prefix requested {} rows from missing log {}",
            count_chirho,
            path_chirho.display()
        );
    }
    let bytes_chirho =
        fs::read(path_chirho).with_context(|| format!("read {}", path_chirho.display()))?;
    let lines_chirho = bytes_chirho
        .split(|byte_chirho| *byte_chirho == b'\n')
        .filter(|line_chirho| {
            !line_chirho
                .iter()
                .all(|byte_chirho| byte_chirho.is_ascii_whitespace())
        })
        .collect::<Vec<_>>();
    if count_chirho > lines_chirho.len() {
        bail!(
            "typed prefix requested {} rows from {} with only {} nonempty rows",
            count_chirho,
            path_chirho.display(),
            lines_chirho.len()
        );
    }
    lines_chirho
        .into_iter()
        .take(count_chirho)
        .map(|line_chirho| {
            std::str::from_utf8(line_chirho)
                .map(str::to_string)
                .with_context(|| {
                    format!(
                        "typed prefix line in {} is not UTF-8",
                        path_chirho.display()
                    )
                })
        })
        .collect()
}

pub fn typed_ingestion_surface_count_chirho() -> usize {
    ring_a_typed_surfaces_chirho().len()
}

fn ring_a_typed_surfaces_chirho() -> &'static [TypedSurfaceChirho] {
    &[
        TypedSurfaceChirho {
            name_chirho: "ledger-chirho.jsonl",
            parser_chirho: parse_ledger_entry_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "billing-policy-records-chirho.jsonl",
            parser_chirho: parse_billing_policy_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "billing-usage-chirho.jsonl",
            parser_chirho: parse_billing_usage_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "billing-compensations-chirho.jsonl",
            parser_chirho: parse_billing_compensation_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "credit-holds-chirho.jsonl",
            parser_chirho: parse_credit_hold_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "resource-policy-records-chirho.jsonl",
            parser_chirho: parse_resource_policy_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "resource-policy-unset-records-chirho.jsonl",
            parser_chirho: parse_resource_policy_unset_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "resource-usage-chirho.jsonl",
            parser_chirho: parse_resource_usage_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "review-policy-envelopes-chirho.jsonl",
            parser_chirho: parse_review_policy_envelope_record_chirho,
        },
        TypedSurfaceChirho {
            name_chirho: "gate1-log-anchors-chirho.jsonl",
            parser_chirho: parse_gate1_log_anchor_record_chirho,
        },
    ]
}

fn typed_surface_by_name_chirho(name_chirho: &str) -> Option<&'static TypedSurfaceChirho> {
    ring_a_typed_surfaces_chirho()
        .iter()
        .find(|surface_chirho| surface_chirho.name_chirho == name_chirho)
}

fn parse_ledger_entry_chirho(line_chirho: &str) -> Result<String> {
    parse_typed_record_chirho::<LedgerEntryChirho>(
        "ledger-chirho.jsonl",
        line_chirho,
        LEDGER_ENTRY_SCHEMA_CHIRHO,
    )
}

fn parse_billing_policy_record_chirho(line_chirho: &str) -> Result<String> {
    let surface_chirho = "billing-policy-records-chirho.jsonl";
    let original_value_chirho = serde_json::from_str::<Value>(line_chirho)
        .with_context(|| format!("typed ingestion JSON parse failed for {surface_chirho}"))?;
    match original_value_chirho.get("schema_chirho") {
        None => {}
        Some(Value::String(schema_chirho))
            if schema_chirho.is_empty()
                || schema_chirho == BILLING_POLICY_RECORD_SCHEMA_CHIRHO
                || schema_chirho == BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO => {}
        Some(Value::String(schema_chirho)) => bail!(
            "typed ingestion {surface_chirho} unsupported schema_chirho '{schema_chirho}', expected '{BILLING_POLICY_RECORD_SCHEMA_CHIRHO}', '{BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO}', or legacy empty schema"
        ),
        Some(_) => bail!("typed ingestion {surface_chirho} schema_chirho must be a string"),
    }
    let record_chirho = serde_json::from_str::<BillingPolicyRecordChirho>(line_chirho)
        .with_context(|| format!("typed ingestion DTO parse failed for {surface_chirho}"))?;
    let canonical_line_chirho = serde_json::to_string(&record_chirho).with_context(|| {
        format!("typed ingestion canonical serialize failed for {surface_chirho}")
    })?;
    if canonical_line_chirho != line_chirho {
        bail!(
            "{}",
            byte_mismatch_diagnostic_chirho(surface_chirho, line_chirho, &canonical_line_chirho)
        );
    }
    Ok(canonical_line_chirho)
}

fn parse_billing_usage_record_chirho(line_chirho: &str) -> Result<String> {
    parse_typed_record_chirho::<BillingUsageRecordChirho>(
        "billing-usage-chirho.jsonl",
        line_chirho,
        BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
    )
}

fn parse_billing_compensation_record_chirho(line_chirho: &str) -> Result<String> {
    parse_typed_record_chirho::<BillingCompensationRecordChirho>(
        "billing-compensations-chirho.jsonl",
        line_chirho,
        BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO,
    )
}

fn parse_credit_hold_record_chirho(line_chirho: &str) -> Result<String> {
    parse_typed_record_chirho::<CreditHoldRecordChirho>(
        "credit-holds-chirho.jsonl",
        line_chirho,
        CREDIT_HOLD_RECORD_SCHEMA_CHIRHO,
    )
}

fn parse_resource_policy_record_chirho(line_chirho: &str) -> Result<String> {
    let surface_chirho = "resource-policy-records-chirho.jsonl";
    let original_value_chirho = serde_json::from_str::<Value>(line_chirho)
        .with_context(|| format!("typed ingestion JSON parse failed for {surface_chirho}"))?;
    match original_value_chirho.get("schema_chirho") {
        None => {}
        Some(Value::String(schema_chirho))
            if schema_chirho.is_empty()
                || schema_chirho == RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO
                || schema_chirho == RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO => {}
        Some(Value::String(schema_chirho)) => bail!(
            "typed ingestion {surface_chirho} unsupported schema_chirho '{schema_chirho}', expected '{RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO}', '{RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO}', or legacy empty schema"
        ),
        Some(_) => bail!("typed ingestion {surface_chirho} schema_chirho must be a string"),
    }
    let record_chirho = serde_json::from_str::<ResourcePolicyRecordChirho>(line_chirho)
        .with_context(|| format!("typed ingestion DTO parse failed for {surface_chirho}"))?;
    let canonical_line_chirho = serde_json::to_string(&record_chirho).with_context(|| {
        format!("typed ingestion canonical serialize failed for {surface_chirho}")
    })?;
    if canonical_line_chirho != line_chirho {
        bail!(
            "{}",
            byte_mismatch_diagnostic_chirho(surface_chirho, line_chirho, &canonical_line_chirho)
        );
    }
    Ok(canonical_line_chirho)
}

fn parse_resource_policy_unset_record_chirho(line_chirho: &str) -> Result<String> {
    parse_typed_record_chirho::<ResourcePolicyUnsetRecordChirho>(
        "resource-policy-unset-records-chirho.jsonl",
        line_chirho,
        RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO,
    )
}

fn parse_resource_usage_record_chirho(line_chirho: &str) -> Result<String> {
    parse_typed_record_chirho::<ResourceUsageRecordChirho>(
        "resource-usage-chirho.jsonl",
        line_chirho,
        RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO,
    )
}

fn parse_review_policy_envelope_record_chirho(line_chirho: &str) -> Result<String> {
    parse_typed_record_chirho::<ReviewPolicyEnvelopeRecordChirho>(
        "review-policy-envelopes-chirho.jsonl",
        line_chirho,
        REVIEW_POLICY_ENVELOPE_SCHEMA_CHIRHO,
    )
}

fn parse_gate1_log_anchor_record_chirho(line_chirho: &str) -> Result<String> {
    let surface_chirho = "gate1-log-anchors-chirho.jsonl";
    let original_value_chirho = serde_json::from_str::<Value>(line_chirho)
        .with_context(|| format!("typed ingestion JSON parse failed for {surface_chirho}"))?;
    match original_value_chirho.get("schema_chirho") {
        Some(Value::String(schema_chirho))
            if schema_chirho == GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO => {}
        Some(Value::String(schema_chirho)) => bail!(
            "typed ingestion {surface_chirho} unsupported schema_chirho '{schema_chirho}', expected '{GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO}'"
        ),
        Some(_) => bail!("typed ingestion {surface_chirho} schema_chirho must be a string"),
        None => bail!("typed ingestion {surface_chirho} schema_chirho is required"),
    }
    let record_chirho = serde_json::from_str::<Gate1LogAnchorRecordChirho>(line_chirho)
        .with_context(|| format!("typed ingestion DTO parse failed for {surface_chirho}"))?;
    let canonical_line_chirho = serde_json::to_string(&record_chirho).with_context(|| {
        format!("typed ingestion canonical serialize failed for {surface_chirho}")
    })?;

    if canonical_line_chirho != line_chirho {
        bail!(
            "{}",
            byte_mismatch_diagnostic_chirho(surface_chirho, line_chirho, &canonical_line_chirho)
        );
    }

    Ok(canonical_line_chirho)
}

fn parse_typed_record_chirho<TChirho>(
    surface_chirho: &str,
    line_chirho: &str,
    expected_schema_chirho: &str,
) -> Result<String>
where
    TChirho: DeserializeOwned + Serialize,
{
    let original_value_chirho = serde_json::from_str::<Value>(line_chirho)
        .with_context(|| format!("typed ingestion JSON parse failed for {surface_chirho}"))?;
    validate_schema_chirho(
        surface_chirho,
        expected_schema_chirho,
        &original_value_chirho,
    )?;

    let record_chirho = serde_json::from_str::<TChirho>(line_chirho)
        .with_context(|| format!("typed ingestion DTO parse failed for {surface_chirho}"))?;
    let canonical_line_chirho = serde_json::to_string(&record_chirho).with_context(|| {
        format!("typed ingestion canonical serialize failed for {surface_chirho}")
    })?;

    if canonical_line_chirho != line_chirho {
        bail!(
            "{}",
            byte_mismatch_diagnostic_chirho(surface_chirho, line_chirho, &canonical_line_chirho)
        );
    }

    Ok(canonical_line_chirho)
}

fn validate_schema_chirho(
    surface_chirho: &str,
    expected_schema_chirho: &str,
    value_chirho: &Value,
) -> Result<()> {
    match value_chirho.get("schema_chirho") {
        None => Ok(()),
        Some(Value::String(schema_chirho))
            if schema_chirho.is_empty() || schema_chirho == expected_schema_chirho =>
        {
            Ok(())
        }
        Some(Value::String(schema_chirho)) => bail!(
            "typed ingestion {surface_chirho} unsupported schema_chirho '{schema_chirho}', expected '{expected_schema_chirho}' or legacy empty schema"
        ),
        Some(_) => bail!("typed ingestion {surface_chirho} schema_chirho must be a string"),
    }
}

fn byte_mismatch_diagnostic_chirho(
    surface_chirho: &str,
    original_chirho: &str,
    canonical_chirho: &str,
) -> String {
    let mut parts_chirho = vec![format!(
        "typed ingestion byte mismatch for {surface_chirho}"
    )];

    if let (Ok(original_value_chirho), Ok(canonical_value_chirho)) = (
        serde_json::from_str::<Value>(original_chirho),
        serde_json::from_str::<Value>(canonical_chirho),
    ) {
        if let (Some(original_object_chirho), Some(canonical_object_chirho)) = (
            original_value_chirho.as_object(),
            canonical_value_chirho.as_object(),
        ) {
            let original_keys_chirho = original_object_chirho
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            let canonical_keys_chirho = canonical_object_chirho
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            let unknown_keys_chirho = original_keys_chirho
                .difference(&canonical_keys_chirho)
                .cloned()
                .collect::<Vec<_>>();
            let missing_keys_chirho = canonical_keys_chirho
                .difference(&original_keys_chirho)
                .cloned()
                .collect::<Vec<_>>();

            if !unknown_keys_chirho.is_empty() {
                parts_chirho.push(format!("unknown keys {:?}", unknown_keys_chirho));
            }
            if !missing_keys_chirho.is_empty() {
                parts_chirho.push(format!("missing keys {:?}", missing_keys_chirho));
            }
        }
    }

    if let (Ok(original_order_chirho), Ok(canonical_order_chirho)) = (
        top_level_key_order_chirho(original_chirho),
        top_level_key_order_chirho(canonical_chirho),
    ) {
        for (original_key_chirho, canonical_key_chirho) in original_order_chirho
            .iter()
            .zip(canonical_order_chirho.iter())
        {
            if original_key_chirho != canonical_key_chirho {
                parts_chirho.push(format!(
                    "first key order mismatch original='{original_key_chirho}' canonical='{canonical_key_chirho}'"
                ));
                break;
            }
        }
    }

    parts_chirho.join("; ")
}

fn top_level_key_order_chirho(line_chirho: &str) -> Result<Vec<String>> {
    let chars_chirho = line_chirho.chars().collect::<Vec<_>>();
    let mut idx_chirho = skip_ws_chirho(&chars_chirho, 0);
    if chars_chirho.get(idx_chirho) != Some(&'{') {
        bail!("top-level JSON value is not an object");
    }
    idx_chirho += 1;

    let mut keys_chirho = Vec::new();
    loop {
        idx_chirho = skip_ws_chirho(&chars_chirho, idx_chirho);
        match chars_chirho.get(idx_chirho) {
            Some('}') => return Ok(keys_chirho),
            Some('"') => {}
            Some(other_chirho) => bail!("expected object key, found '{other_chirho}'"),
            None => bail!("unterminated object"),
        }

        let (key_chirho, next_idx_chirho) = parse_json_string_chirho(&chars_chirho, idx_chirho)?;
        keys_chirho.push(key_chirho);
        idx_chirho = skip_ws_chirho(&chars_chirho, next_idx_chirho);
        if chars_chirho.get(idx_chirho) != Some(&':') {
            bail!("expected ':' after object key");
        }
        idx_chirho = skip_json_value_chirho(&chars_chirho, idx_chirho + 1)?;
        idx_chirho = skip_ws_chirho(&chars_chirho, idx_chirho);
        match chars_chirho.get(idx_chirho) {
            Some(',') => idx_chirho += 1,
            Some('}') => return Ok(keys_chirho),
            Some(other_chirho) => bail!("expected ',' or '}}', found '{other_chirho}'"),
            None => bail!("unterminated object"),
        }
    }
}

fn skip_ws_chirho(chars_chirho: &[char], mut idx_chirho: usize) -> usize {
    while chars_chirho
        .get(idx_chirho)
        .is_some_and(|c_chirho| c_chirho.is_whitespace())
    {
        idx_chirho += 1;
    }
    idx_chirho
}

fn parse_json_string_chirho(chars_chirho: &[char], start_chirho: usize) -> Result<(String, usize)> {
    if chars_chirho.get(start_chirho) != Some(&'"') {
        bail!("expected JSON string");
    }
    let mut out_chirho = String::new();
    let mut idx_chirho = start_chirho + 1;
    while let Some(c_chirho) = chars_chirho.get(idx_chirho).copied() {
        match c_chirho {
            '"' => return Ok((out_chirho, idx_chirho + 1)),
            '\\' => {
                let escaped_chirho = chars_chirho
                    .get(idx_chirho + 1)
                    .copied()
                    .ok_or_else(|| anyhow!("unterminated escape"))?;
                out_chirho.push(escaped_chirho);
                idx_chirho += 2;
            }
            other_chirho => {
                out_chirho.push(other_chirho);
                idx_chirho += 1;
            }
        }
    }
    bail!("unterminated JSON string")
}

fn skip_json_value_chirho(chars_chirho: &[char], start_chirho: usize) -> Result<usize> {
    let mut idx_chirho = skip_ws_chirho(chars_chirho, start_chirho);
    if chars_chirho.get(idx_chirho) == Some(&'"') {
        let (_, next_idx_chirho) = parse_json_string_chirho(chars_chirho, idx_chirho)?;
        return Ok(next_idx_chirho);
    }

    let mut object_depth_chirho = 0usize;
    let mut array_depth_chirho = 0usize;
    while let Some(c_chirho) = chars_chirho.get(idx_chirho).copied() {
        match c_chirho {
            '"' => {
                let (_, next_idx_chirho) = parse_json_string_chirho(chars_chirho, idx_chirho)?;
                idx_chirho = next_idx_chirho;
                continue;
            }
            '{' => object_depth_chirho += 1,
            '}' => {
                if object_depth_chirho == 0 && array_depth_chirho == 0 {
                    return Ok(idx_chirho);
                }
                object_depth_chirho = object_depth_chirho
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("object depth underflow"))?;
            }
            '[' => array_depth_chirho += 1,
            ']' => {
                array_depth_chirho = array_depth_chirho
                    .checked_sub(1)
                    .ok_or_else(|| anyhow!("array depth underflow"))?;
            }
            ',' if object_depth_chirho == 0 && array_depth_chirho == 0 => return Ok(idx_chirho),
            _ => {}
        }
        idx_chirho += 1;
    }
    Ok(idx_chirho)
}

#[cfg(test)]
mod tests_chirho {
    include!("typed_ingestion_tests_chirho.rs");
}
