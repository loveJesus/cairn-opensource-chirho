// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure Gate 1 authority-log oracle fold over already verified authority records.
//!
//! The authority-log service crate owns root-signature verification. This lower crate deliberately
//! re-checks only structural facts available inside the DTOs: record digest chain, dense authority
//! sequence, family-line digest, and dense per-family sequence. The first non-comparison recovery
//! entrypoint must add an explicit verified-records witness minted by the authority-log loader.

use crate::gate1_state_digest_chirho::{
    gate1_ring_a_semantic_state_digests_for_prefix_chirho, gate1_semantic_group_for_family_chirho,
    gate1_semantic_group_specs_chirho, GATE1_BILLING_GROUP_CHIRHO, GATE1_HOLDS_GROUP_CHIRHO,
    GATE1_LEDGER_GROUP_CHIRHO, GATE1_RESOURCES_GROUP_CHIRHO,
};
use crate::semantic_billing_chirho::{
    billing_semantic_projection_state_chirho, billing_semantic_state_from_typed_records_chirho,
};
use crate::semantic_holds_chirho::{
    hold_semantic_projection_state_chirho, hold_semantic_state_from_typed_records_chirho,
};
use crate::semantic_parity_chirho::{
    ledger_semantic_projection_state_chirho, ledger_semantic_state_from_typed_entries_chirho,
};
use crate::semantic_resources_chirho::{
    resource_semantic_projection_state_chirho, resource_semantic_state_from_typed_records_chirho,
};
use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::clsd_chirho::clsd_digest_chirho;
use cairn_model_economic_chirho::{
    BillingCompensationRecordChirho, BillingPolicyRecordChirho, BillingUsageRecordChirho,
    CreditHoldRecordChirho, LedgerEntryChirho, ResourcePolicyRecordChirho,
    ResourcePolicyUnsetRecordChirho, ResourceUsageRecordChirho, LEDGER_ENTRY_SCHEMA_V2_CHIRHO,
};
use cairn_model_gate1_chirho::{
    gate1_authority_family_line_digest_chirho, gate1_authority_record_digest_chirho,
    validate_gate1_authority_record_chirho, Gate1AuthorityLogRecordChirho,
    GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO, GATE1_BILLING_POLICIES_FAMILY_CHIRHO,
    GATE1_BILLING_USAGE_FAMILY_CHIRHO, GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
    GATE1_LEDGER_FAMILY_CHIRHO, GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
    GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO, GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const GATE1_ORACLE_REPORT_SCHEMA_CHIRHO: &str = "gate1-oracle-report-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1OracleFamilyCutChirho {
    pub family_chirho: String,
    pub line_count_chirho: u64,
    pub prefix_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1OracleFamilyStatusChirho {
    pub family_chirho: String,
    pub old_road_line_count_chirho: u64,
    pub authority_line_count_chirho: u64,
    pub counts_match_chirho: bool,
    pub old_road_prefix_digest_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_road_tail_family_line_digest_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_tail_family_line_digest_chirho: Option<String>,
    pub watermark_matches_old_road_tail_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1OracleGroupDigestChirho {
    pub group_chirho: String,
    pub authority_record_count_chirho: u64,
    pub authority_clsd_digest_chirho: String,
    pub old_road_clsd_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1OracleReportChirho {
    pub schema_chirho: &'static str,
    pub family_statuses_chirho: Vec<Gate1OracleFamilyStatusChirho>,
    pub group_digests_chirho: Vec<Gate1OracleGroupDigestChirho>,
    pub authority_ledger_entry_count_chirho: Option<u64>,
    pub findings_chirho: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Gate1AuthorityTypedStreamsChirho {
    touched_groups_chirho: BTreeSet<String>,
    family_tail_digests_chirho: BTreeMap<String, Option<String>>,
    pub ledger_entries_chirho: Vec<LedgerEntryChirho>,
    pub credit_holds_chirho: Vec<CreditHoldRecordChirho>,
    pub resource_policies_chirho: Vec<ResourcePolicyRecordChirho>,
    pub resource_policy_unsets_chirho: Vec<ResourcePolicyUnsetRecordChirho>,
    pub resource_usage_chirho: Vec<ResourceUsageRecordChirho>,
    pub billing_policies_chirho: Vec<BillingPolicyRecordChirho>,
    pub billing_usage_chirho: Vec<BillingUsageRecordChirho>,
    pub billing_compensations_chirho: Vec<BillingCompensationRecordChirho>,
}

impl Gate1AuthorityTypedStreamsChirho {
    pub fn touched_groups_chirho(&self) -> &BTreeSet<String> {
        &self.touched_groups_chirho
    }

    pub fn family_count_chirho(&self, family_chirho: &str) -> u64 {
        match family_chirho {
            GATE1_LEDGER_FAMILY_CHIRHO => self.ledger_entries_chirho.len() as u64,
            GATE1_CREDIT_HOLDS_FAMILY_CHIRHO => self.credit_holds_chirho.len() as u64,
            GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO => self.resource_policies_chirho.len() as u64,
            GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO => {
                self.resource_policy_unsets_chirho.len() as u64
            }
            GATE1_RESOURCE_USAGE_FAMILY_CHIRHO => self.resource_usage_chirho.len() as u64,
            GATE1_BILLING_POLICIES_FAMILY_CHIRHO => self.billing_policies_chirho.len() as u64,
            GATE1_BILLING_USAGE_FAMILY_CHIRHO => self.billing_usage_chirho.len() as u64,
            GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO => {
                self.billing_compensations_chirho.len() as u64
            }
            _ => 0,
        }
    }

    pub fn family_tail_digest_chirho(&self, family_chirho: &str) -> Option<String> {
        self.family_tail_digests_chirho
            .get(family_chirho)
            .cloned()
            .flatten()
    }

    pub fn group_count_chirho(&self, group_chirho: &str) -> u64 {
        match group_chirho {
            GATE1_LEDGER_GROUP_CHIRHO => self.ledger_entries_chirho.len() as u64,
            GATE1_HOLDS_GROUP_CHIRHO => self.credit_holds_chirho.len() as u64,
            GATE1_RESOURCES_GROUP_CHIRHO => {
                (self.resource_policies_chirho.len()
                    + self.resource_policy_unsets_chirho.len()
                    + self.resource_usage_chirho.len()) as u64
            }
            GATE1_BILLING_GROUP_CHIRHO => {
                (self.billing_policies_chirho.len()
                    + self.billing_usage_chirho.len()
                    + self.billing_compensations_chirho.len()) as u64
            }
            _ => 0,
        }
    }

    pub fn authority_group_digest_chirho(&self, group_chirho: &str) -> Result<String> {
        match group_chirho {
            GATE1_LEDGER_GROUP_CHIRHO => {
                let state_chirho =
                    ledger_semantic_state_from_typed_entries_chirho(&self.ledger_entries_chirho)?;
                Ok(clsd_digest_chirho(&ledger_semantic_projection_state_chirho(&state_chirho)?).0)
            }
            GATE1_HOLDS_GROUP_CHIRHO => {
                let state_chirho =
                    hold_semantic_state_from_typed_records_chirho(&self.credit_holds_chirho)?;
                Ok(clsd_digest_chirho(&hold_semantic_projection_state_chirho(&state_chirho)?).0)
            }
            GATE1_RESOURCES_GROUP_CHIRHO => {
                let state_chirho = resource_semantic_state_from_typed_records_chirho(
                    &self.resource_policies_chirho,
                    &self.resource_policy_unsets_chirho,
                    &self.resource_usage_chirho,
                )?;
                Ok(
                    clsd_digest_chirho(&resource_semantic_projection_state_chirho(&state_chirho)?)
                        .0,
                )
            }
            GATE1_BILLING_GROUP_CHIRHO => {
                let state_chirho = billing_semantic_state_from_typed_records_chirho(
                    &self.billing_policies_chirho,
                    &self.billing_usage_chirho,
                    &self.billing_compensations_chirho,
                )?;
                Ok(clsd_digest_chirho(&billing_semantic_projection_state_chirho(&state_chirho)?).0)
            }
            _ => bail!("unknown Gate 1 semantic group {group_chirho}"),
        }
    }

    fn push_tail_digest_chirho(&mut self, family_chirho: &str, digest_chirho: String) {
        self.family_tail_digests_chirho
            .insert(family_chirho.to_string(), Some(digest_chirho));
    }
}

pub fn gate1_authority_projection_from_verified_records_chirho(
    records_chirho: &[Gate1AuthorityLogRecordChirho],
) -> Result<Gate1AuthorityTypedStreamsChirho> {
    let (projection_chirho, findings_chirho) = fold_authority_records_chirho(records_chirho)?;
    if !findings_chirho.is_empty() {
        bail!("{}", findings_chirho.join("; "));
    }
    Ok(projection_chirho)
}

pub fn gate1_oracle_report_from_verified_records_chirho(
    root_chirho: &Path,
    records_chirho: &[Gate1AuthorityLogRecordChirho],
    family_cuts_chirho: &[Gate1OracleFamilyCutChirho],
) -> Result<Gate1OracleReportChirho> {
    let (projection_chirho, mut findings_chirho) = fold_authority_records_chirho(records_chirho)?;
    let counts_chirho = family_cuts_chirho
        .iter()
        .map(|cut_chirho| {
            (
                cut_chirho.family_chirho.clone(),
                cut_chirho.line_count_chirho,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let old_road_digests_chirho =
        gate1_ring_a_semantic_state_digests_for_prefix_chirho(root_chirho, &counts_chirho)?;

    let mut family_statuses_chirho = Vec::new();
    for cut_chirho in family_cuts_chirho {
        let authority_count_chirho =
            projection_chirho.family_count_chirho(&cut_chirho.family_chirho);
        let old_tail_chirho = old_road_tail_family_line_digest_chirho(
            root_chirho,
            &cut_chirho.family_chirho,
            cut_chirho.line_count_chirho,
        )?;
        let authority_tail_chirho =
            projection_chirho.family_tail_digest_chirho(&cut_chirho.family_chirho);
        let counts_match_chirho = authority_count_chirho == cut_chirho.line_count_chirho;
        let watermark_matches_old_road_tail_chirho =
            counts_match_chirho && authority_tail_chirho == old_tail_chirho;
        if !counts_match_chirho {
            findings_chirho.push(format!(
                "authority family {} count {} does not match old-road cut {}",
                cut_chirho.family_chirho, authority_count_chirho, cut_chirho.line_count_chirho
            ));
        }
        if !watermark_matches_old_road_tail_chirho {
            findings_chirho.push(format!(
                "authority family {} tail digest {:?} does not match old-road tail {:?}",
                cut_chirho.family_chirho, authority_tail_chirho, old_tail_chirho
            ));
        }
        family_statuses_chirho.push(Gate1OracleFamilyStatusChirho {
            family_chirho: cut_chirho.family_chirho.clone(),
            old_road_line_count_chirho: cut_chirho.line_count_chirho,
            authority_line_count_chirho: authority_count_chirho,
            counts_match_chirho,
            old_road_prefix_digest_chirho: cut_chirho.prefix_digest_chirho.clone(),
            old_road_tail_family_line_digest_chirho: old_tail_chirho,
            authority_tail_family_line_digest_chirho: authority_tail_chirho,
            watermark_matches_old_road_tail_chirho,
        });
    }

    let mut group_digests_chirho = Vec::new();
    for spec_chirho in gate1_semantic_group_specs_chirho() {
        let group_chirho = spec_chirho.group_chirho;
        let authority_digest_chirho =
            projection_chirho.authority_group_digest_chirho(group_chirho)?;
        let old_road_digest_chirho = old_road_digests_chirho
            .get(group_chirho)
            .ok_or_else(|| anyhow!("missing old-road digest for Gate 1 group {group_chirho}"))?
            .0
            .clone();
        if authority_digest_chirho != old_road_digest_chirho {
            findings_chirho.push(format!(
                "authority {group_chirho} fold digest {} differs from old-road digest {}",
                authority_digest_chirho, old_road_digest_chirho
            ));
        }
        group_digests_chirho.push(Gate1OracleGroupDigestChirho {
            group_chirho: group_chirho.to_string(),
            authority_record_count_chirho: projection_chirho.group_count_chirho(group_chirho),
            authority_clsd_digest_chirho: authority_digest_chirho,
            old_road_clsd_digest_chirho: old_road_digest_chirho,
        });
    }

    Ok(Gate1OracleReportChirho {
        schema_chirho: GATE1_ORACLE_REPORT_SCHEMA_CHIRHO,
        family_statuses_chirho,
        group_digests_chirho,
        authority_ledger_entry_count_chirho: if projection_chirho.ledger_entries_chirho.is_empty() {
            None
        } else {
            Some(projection_chirho.ledger_entries_chirho.len() as u64)
        },
        findings_chirho,
    })
}

fn fold_authority_records_chirho(
    records_chirho: &[Gate1AuthorityLogRecordChirho],
) -> Result<(Gate1AuthorityTypedStreamsChirho, Vec<String>)> {
    let mut projection_chirho = Gate1AuthorityTypedStreamsChirho::default();
    let mut findings_chirho = Vec::new();
    let mut expected_prev_digest_chirho: Option<String> = None;

    for (idx_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if let Err(error_chirho) = validate_gate1_authority_record_chirho(record_chirho) {
            findings_chirho.push(format!(
                "authority record {} failed structural validation: {error_chirho}",
                idx_chirho
            ));
        }
        if record_chirho.authority_seq_chirho != idx_chirho as u64 {
            findings_chirho.push(format!(
                "authority seq mismatch at index {}: record seq {}",
                idx_chirho, record_chirho.authority_seq_chirho
            ));
        }
        if record_chirho.prev_authority_record_digest_chirho != expected_prev_digest_chirho {
            findings_chirho.push(format!(
                "authority prev digest mismatch at seq {}",
                record_chirho.authority_seq_chirho
            ));
        }
        expected_prev_digest_chirho = Some(gate1_authority_record_digest_chirho(record_chirho)?);

        if let Some(spec_chirho) =
            gate1_semantic_group_for_family_chirho(&record_chirho.family_chirho)
        {
            projection_chirho
                .touched_groups_chirho
                .insert(spec_chirho.group_chirho.to_string());
        } else {
            findings_chirho.push(format!(
                "unknown authority family {} at authority seq {}",
                record_chirho.family_chirho, record_chirho.authority_seq_chirho
            ));
            continue;
        }
        fold_family_line_chirho(record_chirho, &mut projection_chirho, &mut findings_chirho)?;
    }

    Ok((projection_chirho, findings_chirho))
}

fn fold_family_line_chirho(
    record_chirho: &Gate1AuthorityLogRecordChirho,
    projection_chirho: &mut Gate1AuthorityTypedStreamsChirho,
    findings_chirho: &mut Vec<String>,
) -> Result<()> {
    let expected_family_seq_chirho =
        projection_chirho.family_count_chirho(&record_chirho.family_chirho);
    if record_chirho.family_seq_chirho != expected_family_seq_chirho {
        findings_chirho.push(format!(
            "authority family {} seq gap: expected {}, found {}",
            record_chirho.family_chirho,
            expected_family_seq_chirho,
            record_chirho.family_seq_chirho
        ));
        return Ok(());
    }
    let mut accepted_chirho = true;
    match record_chirho.family_chirho.as_str() {
        GATE1_LEDGER_FAMILY_CHIRHO => {
            let entry_chirho: LedgerEntryChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            // J0a: the Gate-1 authority-log projection is authority-INERT for schema-v2. A v2 row
            // (`schema-v2` ⟺ `op_binding` present) is rejected here before it can enter the
            // authoritative ledger stream, matching the root-crate verify gate. J0b activates v2.
            if entry_chirho.schema_chirho == LEDGER_ENTRY_SCHEMA_V2_CHIRHO
                || entry_chirho.op_binding_chirho.is_some()
            {
                return Err(anyhow::anyhow!(
                    "gate1 authority ledger projection rejects schema-v2 row at seq {}: v2 money authority is INACTIVE (J0a authority-inert)",
                    entry_chirho.seq_chirho
                ));
            }
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                entry_chirho.seq_chirho,
                "ledger",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho.ledger_entries_chirho.push(entry_chirho);
            }
        }
        GATE1_CREDIT_HOLDS_FAMILY_CHIRHO => {
            let typed_chirho: CreditHoldRecordChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                typed_chirho.seq_chirho,
                "credit hold",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho.credit_holds_chirho.push(typed_chirho);
            }
        }
        GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO => {
            let typed_chirho: ResourcePolicyRecordChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                typed_chirho.seq_chirho,
                "resource policy",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho
                    .resource_policies_chirho
                    .push(typed_chirho);
            }
        }
        GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO => {
            let typed_chirho: ResourcePolicyUnsetRecordChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                typed_chirho.seq_chirho,
                "resource policy unset",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho
                    .resource_policy_unsets_chirho
                    .push(typed_chirho);
            }
        }
        GATE1_RESOURCE_USAGE_FAMILY_CHIRHO => {
            let typed_chirho: ResourceUsageRecordChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                typed_chirho.seq_chirho,
                "resource usage",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho.resource_usage_chirho.push(typed_chirho);
            }
        }
        GATE1_BILLING_POLICIES_FAMILY_CHIRHO => {
            let typed_chirho: BillingPolicyRecordChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                typed_chirho.seq_chirho,
                "billing policy",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho.billing_policies_chirho.push(typed_chirho);
            }
        }
        GATE1_BILLING_USAGE_FAMILY_CHIRHO => {
            let typed_chirho: BillingUsageRecordChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                typed_chirho.seq_chirho,
                "billing usage",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho.billing_usage_chirho.push(typed_chirho);
            }
        }
        GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO => {
            let typed_chirho: BillingCompensationRecordChirho =
                parse_authority_family_line_chirho(record_chirho)?;
            accepted_chirho = ensure_embedded_family_seq_chirho(
                record_chirho,
                typed_chirho.seq_chirho,
                "billing compensation",
                findings_chirho,
            );
            if accepted_chirho {
                projection_chirho
                    .billing_compensations_chirho
                    .push(typed_chirho);
            }
        }
        _ => {}
    }
    if accepted_chirho {
        projection_chirho.push_tail_digest_chirho(
            &record_chirho.family_chirho,
            record_chirho.family_line_digest_chirho.clone(),
        );
    }
    Ok(())
}

fn parse_authority_family_line_chirho<TChirho: DeserializeOwned>(
    record_chirho: &Gate1AuthorityLogRecordChirho,
) -> Result<TChirho> {
    serde_json::from_str(&record_chirho.family_line_chirho).map_err(Into::into)
}

fn ensure_embedded_family_seq_chirho(
    record_chirho: &Gate1AuthorityLogRecordChirho,
    embedded_seq_chirho: u64,
    label_chirho: &str,
    findings_chirho: &mut Vec<String>,
) -> bool {
    if embedded_seq_chirho != record_chirho.family_seq_chirho {
        findings_chirho.push(format!(
            "authority {label_chirho} family seq {} does not match embedded seq {}",
            record_chirho.family_seq_chirho, embedded_seq_chirho
        ));
        return false;
    }
    true
}

fn old_road_tail_family_line_digest_chirho(
    root_chirho: &Path,
    family_chirho: &str,
    line_count_chirho: u64,
) -> Result<Option<String>> {
    if line_count_chirho == 0 {
        return Ok(None);
    }
    let text_chirho = std::fs::read_to_string(root_chirho.join(family_chirho))
        .with_context(|| format!("read old-road family {family_chirho}"))?;
    let mut seen_chirho = 0u64;
    let mut tail_chirho = None;
    for line_chirho in text_chirho.lines() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.is_empty() {
            continue;
        }
        if seen_chirho >= line_count_chirho {
            break;
        }
        tail_chirho = Some(gate1_authority_family_line_digest_chirho(trimmed_chirho));
        seen_chirho += 1;
    }
    if seen_chirho != line_count_chirho {
        bail!(
            "old-road family {family_chirho} has {seen_chirho} nonempty lines, below cut {line_count_chirho}"
        );
    }
    Ok(tail_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::model_chirho::HashChirho;
    use cairn_model_economic_chirho::{
        AssetChirho, BillingTagsChirho, CreditHoldRecordChirho, CreditHoldStatusChirho,
        MoneyWriterAuthorityContextChirho, OpBindingChirho, OpKindChirho, PostingChirho,
        CREDIT_HOLD_RECORD_SCHEMA_CHIRHO, LEDGER_ENTRY_SCHEMA_CHIRHO,
        LEDGER_ENTRY_SCHEMA_V2_CHIRHO,
    };
    use cairn_model_gate1_chirho::{
        gate1_authority_record_digest_chirho, GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO,
        GATE1_RING_A_ANCHOR_TARGETS_CHIRHO,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cairn-gate1-oracle-{label_chirho}-{nanos_chirho}-{n_chirho}"
        ))
    }

    fn ledger_line_chirho(seq_chirho: u64, amount_chirho: i64) -> String {
        serde_json::to_string(&LedgerEntryChirho {
            seq_chirho,
            schema_chirho: LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
            memo_chirho: format!("oracle-ledger-{seq_chirho}-chirho"),
            postings_chirho: vec![PostingChirho {
                account_chirho: "a-chirho".to_string(),
                asset_chirho: AssetChirho::TokenChirho,
                amount_chirho,
            }],
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: seq_chirho,
            sig_chirho: "sig-chirho".to_string(),
            op_binding_chirho: None,
        })
        .unwrap()
    }

    /// A schema-v2 (op-binding) ledger family line — a shape-valid charge row that J0a keeps
    /// authority-INACTIVE. Used to prove the Gate-1 projection rejects it before it enters the
    /// authoritative `ledger_entries_chirho` stream.
    fn v2_ledger_line_chirho(seq_chirho: u64) -> String {
        serde_json::to_string(&LedgerEntryChirho {
            seq_chirho,
            schema_chirho: LEDGER_ENTRY_SCHEMA_V2_CHIRHO.to_string(),
            memo_chirho: format!("oracle-v2-ledger-{seq_chirho}-chirho"),
            postings_chirho: vec![
                PostingChirho {
                    account_chirho: "a-chirho".to_string(),
                    asset_chirho: AssetChirho::TokenChirho,
                    amount_chirho: -1,
                },
                PostingChirho {
                    account_chirho: "b-chirho".to_string(),
                    asset_chirho: AssetChirho::TokenChirho,
                    amount_chirho: 1,
                },
            ],
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: seq_chirho,
            sig_chirho: "sig-chirho".to_string(),
            op_binding_chirho: Some(OpBindingChirho {
                op_id_chirho: HashChirho("op-id-chirho".to_string()),
                op_digest_chirho: HashChirho("op-digest-chirho".to_string()),
                intent_generation_chirho: 0,
                planned_body_digest_chirho: HashChirho("plan-chirho".to_string()),
                op_kind_chirho: OpKindChirho::ChargeChirho,
                money_writer_authority_context_chirho:
                    MoneyWriterAuthorityContextChirho::LocalFenceV1Chirho {
                        stable_group_id_chirho: HashChirho("group-chirho".to_string()),
                        local_group_digest_chirho: HashChirho("digest-chirho".to_string()),
                        local_epoch_chirho: 1,
                    },
                allowance_refs_chirho: vec![],
                origin_op_ref_chirho: None,
                provider_call_id_chirho: None,
                witness_refs_chirho: vec![],
            }),
        })
        .unwrap()
    }

    fn hold_line_chirho(seq_chirho: u64) -> String {
        serde_json::to_string(&CreditHoldRecordChirho {
            seq_chirho,
            schema_chirho: CREDIT_HOLD_RECORD_SCHEMA_CHIRHO.to_string(),
            hold_id_chirho: format!("oracle-hold-{seq_chirho}-chirho"),
            hold_account_chirho: format!("platform/credit-hold/oracle-hold-{seq_chirho}-chirho"),
            app_chirho: "oracle-app-chirho".to_string(),
            effect_chirho: "oracle-effect-chirho".to_string(),
            caller_chirho: "oracle-caller-chirho".to_string(),
            payer_chirho: "oracle-payer-chirho".to_string(),
            authorized_token_chirho: 7,
            settled_token_chirho: 0,
            released_token_chirho: 0,
            reserve_ledger_seq_chirho: 0,
            settlement_ledger_seq_chirho: None,
            release_ledger_seq_chirho: None,
            status_chirho: CreditHoldStatusChirho::OpenChirho,
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: seq_chirho,
            sig_chirho: "sig-chirho".to_string(),
        })
        .unwrap()
    }

    fn authority_record_for_family_chirho(
        authority_seq_chirho: u64,
        family_chirho: &str,
        family_seq_chirho: u64,
        family_line_chirho: String,
        prev_chirho: Option<String>,
    ) -> Gate1AuthorityLogRecordChirho {
        Gate1AuthorityLogRecordChirho {
            schema_chirho: GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO.to_string(),
            authority_seq_chirho,
            family_chirho: family_chirho.to_string(),
            family_seq_chirho,
            family_line_digest_chirho: gate1_authority_family_line_digest_chirho(
                &family_line_chirho,
            ),
            family_line_chirho,
            prev_authority_record_digest_chirho: prev_chirho,
            writer_fence_epoch_chirho: 1,
            at_ms_chirho: authority_seq_chirho,
            key_id_chirho: "key-chirho".to_string(),
            sig_chirho: "sig-chirho".to_string(),
        }
    }

    fn record_chirho(
        authority_seq_chirho: u64,
        family_seq_chirho: u64,
        family_line_chirho: String,
        prev_chirho: Option<String>,
    ) -> Gate1AuthorityLogRecordChirho {
        authority_record_for_family_chirho(
            authority_seq_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            family_seq_chirho,
            family_line_chirho,
            prev_chirho,
        )
    }

    fn linked_ledger_records_chirho() -> Vec<Gate1AuthorityLogRecordChirho> {
        let first_chirho = record_chirho(0, 0, ledger_line_chirho(0, 7), None);
        let first_digest_chirho = gate1_authority_record_digest_chirho(&first_chirho).unwrap();
        let second_chirho =
            record_chirho(1, 1, ledger_line_chirho(1, -2), Some(first_digest_chirho));
        vec![first_chirho, second_chirho]
    }

    fn cuts_for_ledger_and_hold_counts_chirho(
        ledger_count_chirho: u64,
        ledger_prefix_chirho: &str,
        hold_count_chirho: u64,
        hold_prefix_chirho: &str,
    ) -> Vec<Gate1OracleFamilyCutChirho> {
        GATE1_RING_A_ANCHOR_TARGETS_CHIRHO
            .iter()
            .map(|family_chirho| {
                let (line_count_chirho, prefix_digest_chirho) = match *family_chirho {
                    GATE1_LEDGER_FAMILY_CHIRHO => (ledger_count_chirho, ledger_prefix_chirho),
                    GATE1_CREDIT_HOLDS_FAMILY_CHIRHO => (hold_count_chirho, hold_prefix_chirho),
                    _ => (0, ""),
                };
                Gate1OracleFamilyCutChirho {
                    family_chirho: (*family_chirho).to_string(),
                    line_count_chirho,
                    prefix_digest_chirho: HashChirho(
                        blake3::hash(prefix_digest_chirho.as_bytes())
                            .to_hex()
                            .to_string(),
                    )
                    .0,
                }
            })
            .collect()
    }

    #[test]
    fn oracle_rejects_a_schema_v2_ledger_row_before_it_enters_the_projection_chirho() {
        // A well-linked authority record whose ONLY defect is a schema-v2 ledger family line. The
        // Gate-1 projection must reject it as authority-inactive (J0a) before the v2 row is pushed
        // into `ledger_entries_chirho`. Removing the projection's v2 condition would let this row
        // through, turning this test RED.
        let v2_record_chirho = record_chirho(0, 0, v2_ledger_line_chirho(0), None);
        let error_chirho =
            gate1_authority_projection_from_verified_records_chirho(&[v2_record_chirho])
                .unwrap_err()
                .to_string();
        assert!(
            error_chirho.contains("schema-v2") && error_chirho.contains("INACTIVE"),
            "the Gate-1 ledger projection must reject a v2 row as authority-inactive, got: {error_chirho}"
        );
    }

    #[test]
    fn oracle_rejects_family_line_digest_mismatch_chirho() {
        let mut records_chirho = linked_ledger_records_chirho();
        records_chirho[0].family_line_chirho = ledger_line_chirho(0, 9);
        let error_chirho = gate1_authority_projection_from_verified_records_chirho(&records_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("family_line_digest_chirho mismatch"));
    }

    #[test]
    fn oracle_rejects_authority_seq_gap_chirho() {
        let mut records_chirho = linked_ledger_records_chirho();
        records_chirho[1].authority_seq_chirho = 2;
        let error_chirho = gate1_authority_projection_from_verified_records_chirho(&records_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("authority seq mismatch"));
    }

    #[test]
    fn oracle_rejects_prev_digest_chain_break_chirho() {
        let mut records_chirho = linked_ledger_records_chirho();
        records_chirho[1].prev_authority_record_digest_chirho = None;
        let error_chirho = gate1_authority_projection_from_verified_records_chirho(&records_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("authority prev digest mismatch"));
    }

    #[test]
    fn oracle_rejects_family_seq_gap_chirho() {
        let first_chirho = record_chirho(0, 0, ledger_line_chirho(0, 7), None);
        let first_digest_chirho = gate1_authority_record_digest_chirho(&first_chirho).unwrap();
        let second_chirho =
            record_chirho(1, 2, ledger_line_chirho(2, -2), Some(first_digest_chirho));
        let error_chirho =
            gate1_authority_projection_from_verified_records_chirho(&[first_chirho, second_chirho])
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains("seq gap"));
    }

    #[test]
    fn oracle_rejects_unknown_family_chirho() {
        let mut records_chirho = linked_ledger_records_chirho();
        records_chirho[0].family_chirho = "rogue-family-chirho.jsonl".to_string();
        let error_chirho = gate1_authority_projection_from_verified_records_chirho(&records_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("family_chirho must be a reviewed Ring A family"));
        assert!(error_chirho.contains("unknown authority family"));
    }

    #[test]
    fn oracle_report_names_count_and_tail_mismatch_chirho() {
        let root_chirho = tmp_root_chirho("count-mismatch");
        fs::create_dir_all(&root_chirho).unwrap();
        let records_chirho = linked_ledger_records_chirho();
        fs::write(
            root_chirho.join(GATE1_LEDGER_FAMILY_CHIRHO),
            format!("{}\n", records_chirho[0].family_line_chirho),
        )
        .unwrap();
        let cuts_chirho = GATE1_RING_A_ANCHOR_TARGETS_CHIRHO
            .iter()
            .map(|family_chirho| Gate1OracleFamilyCutChirho {
                family_chirho: (*family_chirho).to_string(),
                line_count_chirho: if *family_chirho == GATE1_LEDGER_FAMILY_CHIRHO {
                    1
                } else {
                    0
                },
                prefix_digest_chirho: HashChirho(blake3::hash(b"prefix").to_hex().to_string()).0,
            })
            .collect::<Vec<_>>();
        let report_chirho = gate1_oracle_report_from_verified_records_chirho(
            &root_chirho,
            &records_chirho,
            &cuts_chirho,
        )
        .unwrap();
        assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
            finding_chirho.contains("count 2 does not match old-road cut 1")
        }));
        assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
            finding_chirho.contains("tail digest") && finding_chirho.contains("does not match")
        }));
        assert_eq!(
            report_chirho.family_statuses_chirho[0].old_road_prefix_digest_chirho,
            HashChirho(blake3::hash(b"prefix").to_hex().to_string()).0
        );
        let _ = fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn oracle_reproduces_legacy_ledger_fold_golden_chirho() {
        let root_chirho = tmp_root_chirho("golden");
        fs::create_dir_all(&root_chirho).unwrap();
        let records_chirho = linked_ledger_records_chirho();
        let old_lines_chirho = records_chirho
            .iter()
            .map(|record_chirho| record_chirho.family_line_chirho.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            root_chirho.join(GATE1_LEDGER_FAMILY_CHIRHO),
            format!("{old_lines_chirho}\n"),
        )
        .unwrap();
        let cuts_chirho = GATE1_RING_A_ANCHOR_TARGETS_CHIRHO
            .iter()
            .map(|family_chirho| Gate1OracleFamilyCutChirho {
                family_chirho: (*family_chirho).to_string(),
                line_count_chirho: if *family_chirho == GATE1_LEDGER_FAMILY_CHIRHO {
                    2
                } else {
                    0
                },
                prefix_digest_chirho: if *family_chirho == GATE1_LEDGER_FAMILY_CHIRHO {
                    HashChirho(
                        blake3::hash(old_lines_chirho.as_bytes())
                            .to_hex()
                            .to_string(),
                    )
                    .0
                } else {
                    HashChirho(blake3::hash(b"").to_hex().to_string()).0
                },
            })
            .collect::<Vec<_>>();
        let report_chirho = gate1_oracle_report_from_verified_records_chirho(
            &root_chirho,
            &records_chirho,
            &cuts_chirho,
        )
        .unwrap();
        assert_eq!(report_chirho.findings_chirho, Vec::<String>::new());
        assert_eq!(report_chirho.group_digests_chirho.len(), 4);
        let ledger_chirho = report_chirho
            .group_digests_chirho
            .iter()
            .find(|digest_chirho| digest_chirho.group_chirho == GATE1_LEDGER_GROUP_CHIRHO)
            .unwrap();
        assert_eq!(
            ledger_chirho.authority_clsd_digest_chirho,
            ledger_chirho.old_road_clsd_digest_chirho
        );
        assert_eq!(
            ledger_chirho.authority_clsd_digest_chirho,
            "a97c8c75a8e56725368cc637ba4027c808b99263dbdf4bbb3312112f22b4f6ef"
        );
        for digest_chirho in &report_chirho.group_digests_chirho {
            assert_eq!(
                digest_chirho.authority_clsd_digest_chirho,
                digest_chirho.old_road_clsd_digest_chirho
            );
        }
        let _ = fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn oracle_emits_explicit_empty_group_digests_chirho() {
        let root_chirho = tmp_root_chirho("empty-groups");
        fs::create_dir_all(&root_chirho).unwrap();
        let records_chirho = linked_ledger_records_chirho();
        let old_lines_chirho = records_chirho
            .iter()
            .map(|record_chirho| record_chirho.family_line_chirho.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(
            root_chirho.join(GATE1_LEDGER_FAMILY_CHIRHO),
            format!("{old_lines_chirho}\n"),
        )
        .unwrap();
        let cuts_chirho = cuts_for_ledger_and_hold_counts_chirho(2, &old_lines_chirho, 0, "");

        let report_chirho = gate1_oracle_report_from_verified_records_chirho(
            &root_chirho,
            &records_chirho,
            &cuts_chirho,
        )
        .unwrap();

        assert_eq!(report_chirho.findings_chirho, Vec::<String>::new());
        assert_eq!(report_chirho.group_digests_chirho.len(), 4);
        for group_chirho in [
            GATE1_LEDGER_GROUP_CHIRHO,
            GATE1_HOLDS_GROUP_CHIRHO,
            GATE1_RESOURCES_GROUP_CHIRHO,
            GATE1_BILLING_GROUP_CHIRHO,
        ] {
            let digest_chirho = report_chirho
                .group_digests_chirho
                .iter()
                .find(|digest_chirho| digest_chirho.group_chirho == group_chirho)
                .unwrap();
            assert_eq!(
                digest_chirho.authority_clsd_digest_chirho,
                digest_chirho.old_road_clsd_digest_chirho,
                "{group_chirho}"
            );
        }
        let holds_chirho = report_chirho
            .group_digests_chirho
            .iter()
            .find(|digest_chirho| digest_chirho.group_chirho == GATE1_HOLDS_GROUP_CHIRHO)
            .unwrap();
        assert_eq!(holds_chirho.authority_record_count_chirho, 0);
        let hold_status_chirho = report_chirho
            .family_statuses_chirho
            .iter()
            .find(|status_chirho| status_chirho.family_chirho == GATE1_CREDIT_HOLDS_FAMILY_CHIRHO)
            .unwrap();
        assert!(hold_status_chirho.counts_match_chirho);
        assert!(hold_status_chirho.watermark_matches_old_road_tail_chirho);
        assert_eq!(
            hold_status_chirho.old_road_tail_family_line_digest_chirho,
            None
        );
        assert_eq!(
            hold_status_chirho.authority_tail_family_line_digest_chirho,
            None
        );
        let _ = fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn oracle_rejects_old_road_nonempty_authority_empty_chirho() {
        let root_chirho = tmp_root_chirho("old-nonempty-authority-empty");
        fs::create_dir_all(&root_chirho).unwrap();
        let records_chirho = linked_ledger_records_chirho();
        let old_lines_chirho = records_chirho
            .iter()
            .map(|record_chirho| record_chirho.family_line_chirho.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let hold_line_chirho = hold_line_chirho(0);
        fs::write(
            root_chirho.join(GATE1_LEDGER_FAMILY_CHIRHO),
            format!("{old_lines_chirho}\n"),
        )
        .unwrap();
        fs::write(
            root_chirho.join(GATE1_CREDIT_HOLDS_FAMILY_CHIRHO),
            format!("{hold_line_chirho}\n"),
        )
        .unwrap();
        let cuts_chirho =
            cuts_for_ledger_and_hold_counts_chirho(2, &old_lines_chirho, 1, &hold_line_chirho);

        let report_chirho = gate1_oracle_report_from_verified_records_chirho(
            &root_chirho,
            &records_chirho,
            &cuts_chirho,
        )
        .unwrap();

        assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
            finding_chirho.contains("credit-holds-chirho.jsonl count 0")
                && finding_chirho.contains("old-road cut 1")
        }));
        assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
            finding_chirho.contains("authority holds-chirho fold digest")
                && finding_chirho.contains("differs from old-road digest")
        }));
        let holds_chirho = report_chirho
            .group_digests_chirho
            .iter()
            .find(|digest_chirho| digest_chirho.group_chirho == GATE1_HOLDS_GROUP_CHIRHO)
            .unwrap();
        assert_eq!(holds_chirho.authority_record_count_chirho, 0);
        assert_ne!(
            holds_chirho.authority_clsd_digest_chirho,
            holds_chirho.old_road_clsd_digest_chirho
        );
        let _ = fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn oracle_rejects_authority_nonempty_old_road_empty_chirho() {
        let root_chirho = tmp_root_chirho("authority-nonempty-old-empty");
        fs::create_dir_all(&root_chirho).unwrap();
        let hold_line_chirho = hold_line_chirho(0);
        let records_chirho = vec![authority_record_for_family_chirho(
            0,
            GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
            0,
            hold_line_chirho,
            None,
        )];
        let cuts_chirho = cuts_for_ledger_and_hold_counts_chirho(0, "", 0, "");

        let report_chirho = gate1_oracle_report_from_verified_records_chirho(
            &root_chirho,
            &records_chirho,
            &cuts_chirho,
        )
        .unwrap();

        assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
            finding_chirho.contains("credit-holds-chirho.jsonl count 1")
                && finding_chirho.contains("old-road cut 0")
        }));
        assert!(report_chirho.findings_chirho.iter().any(|finding_chirho| {
            finding_chirho.contains("authority holds-chirho fold digest")
                && finding_chirho.contains("differs from old-road digest")
        }));
        let holds_chirho = report_chirho
            .group_digests_chirho
            .iter()
            .find(|digest_chirho| digest_chirho.group_chirho == GATE1_HOLDS_GROUP_CHIRHO)
            .unwrap();
        assert_eq!(holds_chirho.authority_record_count_chirho, 1);
        assert_ne!(
            holds_chirho.authority_clsd_digest_chirho,
            holds_chirho.old_road_clsd_digest_chirho
        );
        let _ = fs::remove_dir_all(root_chirho);
    }
}
