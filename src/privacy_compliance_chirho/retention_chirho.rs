// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Classifies exported data and enforces private-blob retention by crypto-shredding keys.

use crate::{legal_hold_chirho, privacy_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Result};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MS_PER_DAY_CHIRHO: u64 = 24 * 60 * 60 * 1000;
const PRIVACY_RETENTION_RECORDS_LOCK_CHIRHO: &str = "privacy-retention-records-chirho";
const PRIVATE_BLOB_RETENTION_RECORD_SCHEMA_CHIRHO: &str = "private-blob-retention-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataRetentionCategoryChirho {
    PrivateContentEraseOnRequestChirho,
    IdentityAccessAuditChirho,
    ProductConfigAuditChirho,
    SupportRealtimeAuditChirho,
    FinancialLegalHoldChirho,
    LegalHoldAuditChirho,
    SecurityChangeAuditChirho,
    ComplianceControlAuditChirho,
    OperationalAuditChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErasureDispositionChirho {
    CryptoShredPrivateKeyChirho,
    RetainPseudonymousSignedLogChirho,
    RetainFinancialLegalHoldChirho,
    RetainLegalHoldChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRetentionPolicyChirho {
    pub category_chirho: DataRetentionCategoryChirho,
    pub erasure_disposition_chirho: ErasureDispositionChirho,
    pub basis_chirho: String,
    pub note_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBlobRetentionRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub operator_chirho: String,
    pub retention_days_chirho: u32,
    pub cutoff_ms_chirho: u64,
    pub expired_blob_seqs_chirho: Vec<u64>,
    pub target_key_ids_chirho: Vec<String>,
    pub removed_key_ids_chirho: Vec<String>,
    pub held_blob_seqs_chirho: Vec<u64>,
    pub held_key_ids_chirho: Vec<String>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBlobRetentionSweepChirho {
    pub retention_days_chirho: u32,
    pub cutoff_ms_chirho: u64,
    pub expired_blob_seqs_chirho: Vec<u64>,
    pub target_key_ids_chirho: Vec<String>,
    pub removed_key_ids_chirho: Vec<String>,
    pub held_blob_seqs_chirho: Vec<u64>,
    pub held_key_ids_chirho: Vec<String>,
    pub dry_run_chirho: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_chirho: Option<PrivateBlobRetentionRecordChirho>,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn privacy_retention_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-retention-records-chirho.jsonl")
}

pub fn private_blob_retention_policy_chirho() -> DataRetentionPolicyChirho {
    DataRetentionPolicyChirho {
        category_chirho: DataRetentionCategoryChirho::PrivateContentEraseOnRequestChirho,
        erasure_disposition_chirho: ErasureDispositionChirho::CryptoShredPrivateKeyChirho,
        basis_chirho: "data-subject-content".to_string(),
        note_chirho: "Private payload content is retained only while its subject shred key exists."
            .to_string(),
    }
}

pub fn sweep_private_blob_retention_chirho(
    root_chirho: &Path,
    retention_days_chirho: u32,
    operator_chirho: &str,
    dry_run_chirho: bool,
) -> Result<PrivateBlobRetentionSweepChirho> {
    sweep_private_blob_retention_at_chirho(
        root_chirho,
        retention_days_chirho,
        operator_chirho,
        now_ms_chirho(),
        dry_run_chirho,
    )
}

fn sweep_private_blob_retention_at_chirho(
    root_chirho: &Path,
    retention_days_chirho: u32,
    operator_chirho: &str,
    now_ms_chirho: u64,
    dry_run_chirho: bool,
) -> Result<PrivateBlobRetentionSweepChirho> {
    validate_retention_days_chirho(retention_days_chirho)?;
    validate_safe_token_chirho("privacy retention operator", operator_chirho)?;
    let retention_ms_chirho = u64::from(retention_days_chirho)
        .checked_mul(MS_PER_DAY_CHIRHO)
        .ok_or_else(|| anyhow!("retention_days_chirho overflow"))?;
    let cutoff_ms_chirho = now_ms_chirho.saturating_sub(retention_ms_chirho);
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        legal_hold_chirho::SUBJECT_RIGHTS_LOCK_CHIRHO,
        || {
            let key_subjects_chirho =
                privacy_chirho::validate_private_blob_key_namespace_chirho(root_chirho)?;
            let records_chirho = privacy_chirho::load_privacy_blob_records_chirho(root_chirho)?;
            let mut expired_blob_seqs_chirho = Vec::new();
            let mut held_blob_seqs_chirho = Vec::new();
            let mut target_key_ids_chirho = BTreeSet::new();
            let mut held_key_ids_chirho = BTreeSet::new();
            let mut held_subject_cache_chirho: BTreeMap<String, bool> = BTreeMap::new();
            for record_chirho in records_chirho {
                if record_chirho.at_ms_chirho > cutoff_ms_chirho {
                    continue;
                }
                expired_blob_seqs_chirho.push(record_chirho.seq_chirho);
                let key_id_chirho = record_chirho.blob_chirho.key_id_chirho.clone();
                let held_chirho = match held_subject_cache_chirho.get(&record_chirho.subject_chirho)
                {
                    Some(held_chirho) => *held_chirho,
                    None => {
                        let held_chirho =
                            !legal_hold_chirho::active_legal_holds_for_subject_chirho(
                                root_chirho,
                                &record_chirho.subject_chirho,
                            )?
                            .is_empty();
                        held_subject_cache_chirho
                            .insert(record_chirho.subject_chirho.clone(), held_chirho);
                        held_chirho
                    }
                };
                if held_chirho {
                    held_blob_seqs_chirho.push(record_chirho.seq_chirho);
                    held_key_ids_chirho.insert(key_id_chirho);
                } else {
                    target_key_ids_chirho.insert(key_id_chirho);
                }
            }
            let target_key_ids_chirho: Vec<String> = target_key_ids_chirho.into_iter().collect();
            let held_key_ids_chirho: Vec<String> = held_key_ids_chirho.into_iter().collect();
            let mut removed_key_ids_chirho = Vec::new();
            if !dry_run_chirho {
                for key_id_chirho in &target_key_ids_chirho {
                    let subject_chirho =
                        key_subjects_chirho.get(key_id_chirho).ok_or_else(|| {
                            anyhow!("privacy retention key {key_id_chirho} missing subject")
                        })?;
                    if privacy_chirho::erase_private_blob_key_for_subject_chirho(
                        root_chirho,
                        key_id_chirho,
                        subject_chirho,
                    )? {
                        removed_key_ids_chirho.push(key_id_chirho.clone());
                    }
                }
            }
            let record_chirho = if dry_run_chirho
                || (removed_key_ids_chirho.is_empty() && held_key_ids_chirho.is_empty())
            {
                None
            } else {
                Some(append_private_blob_retention_record_chirho(
                    root_chirho,
                    PrivateBlobRetentionAppendInputChirho {
                        operator_chirho: operator_chirho.to_string(),
                        retention_days_chirho,
                        cutoff_ms_chirho,
                        expired_blob_seqs_chirho: expired_blob_seqs_chirho.clone(),
                        target_key_ids_chirho: target_key_ids_chirho.clone(),
                        removed_key_ids_chirho: removed_key_ids_chirho.clone(),
                        held_blob_seqs_chirho: held_blob_seqs_chirho.clone(),
                        held_key_ids_chirho: held_key_ids_chirho.clone(),
                    },
                )?)
            };
            Ok(PrivateBlobRetentionSweepChirho {
                retention_days_chirho,
                cutoff_ms_chirho,
                expired_blob_seqs_chirho,
                target_key_ids_chirho,
                removed_key_ids_chirho,
                held_blob_seqs_chirho,
                held_key_ids_chirho,
                dry_run_chirho,
                record_chirho,
            })
        },
    )
}

pub fn load_private_blob_retention_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivateBlobRetentionRecordChirho>> {
    load_jsonl_chirho(&privacy_retention_records_path_chirho(root_chirho))
}

pub fn verify_private_blob_retention_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_private_blob_retention_records_chirho(root_chirho)?;
    privacy_chirho::validate_private_blob_key_namespace_chirho(root_chirho)?;
    let blob_records_chirho = privacy_chirho::load_privacy_blob_records_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy retention seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_private_blob_retention_record_chirho(record_chirho, &blob_records_chirho)?;
        let message_chirho = private_blob_retention_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "privacy retention record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        for key_id_chirho in &record_chirho.removed_key_ids_chirho {
            if privacy_chirho::private_blob_key_subject_chirho(root_chirho, key_id_chirho)?
                .is_some()
            {
                bail!(
                    "privacy retention record {} key {} is still present",
                    record_chirho.seq_chirho,
                    key_id_chirho
                );
            }
        }
    }
    Ok(records_chirho.len())
}

pub fn signed_log_retention_policy_chirho(source_chirho: &str) -> DataRetentionPolicyChirho {
    if is_financial_source_chirho(source_chirho) {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::FinancialLegalHoldChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainFinancialLegalHoldChirho,
            basis_chirho: "financial-tax-audit-record".to_string(),
            note_chirho:
                "Pseudonymous financial records remain verifiable after private-content erasure."
                    .to_string(),
        };
    }
    if source_chirho.starts_with("legal-holds.") {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::LegalHoldAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainLegalHoldChirho,
            basis_chirho: "case-specific-legal-hold".to_string(),
            note_chirho:
                "Legal-hold records are retained while they govern whether crypto-shred erasure is paused."
                    .to_string(),
        };
    }
    if source_chirho.starts_with("identity.") || source_chirho.starts_with("oauth.") {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::IdentityAccessAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
            basis_chirho: "access-security-audit".to_string(),
            note_chirho:
                "Identity and access metadata is retained as pseudonymous signed audit evidence."
                    .to_string(),
        };
    }
    if is_compliance_control_source_chirho(source_chirho) {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::ComplianceControlAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
            basis_chirho: "compliance-control-evidence".to_string(),
            note_chirho:
                "Signed compliance, residency, and subject-rights control records are retained as control evidence."
                    .to_string(),
        };
    }
    if is_product_config_source_chirho(source_chirho) {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::ProductConfigAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
            basis_chirho: "app-owner-change-history".to_string(),
            note_chirho: "Owner-authored product configuration history is retained as signed change evidence."
                .to_string(),
        };
    }
    if source_chirho.starts_with("support.") || source_chirho.starts_with("realtime.") {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::SupportRealtimeAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
            basis_chirho: "support-realtime-audit".to_string(),
            note_chirho: "Support/realtime signed metadata remains; private payloads are crypto-shredded separately."
                .to_string(),
        };
    }
    if source_chirho.starts_with("review.")
        || source_chirho.starts_with("reversion.")
        || source_chirho.starts_with("agent-authority.")
        || source_chirho.starts_with("attenuation.")
    {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::SecurityChangeAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
            basis_chirho: "security-change-control".to_string(),
            note_chirho:
                "Review, reversion, and agent-authority records are retained as signed change-control evidence."
                    .to_string(),
        };
    }
    if source_chirho.starts_with("agent-reports.") || source_chirho.starts_with("news-center.") {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::OperationalAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
            basis_chirho: "agent-oversight-audit".to_string(),
            note_chirho:
                "Agent oversight records are retained as pseudonymous operational audit evidence."
                    .to_string(),
        };
    }
    if source_chirho.starts_with("crm.") || source_chirho.starts_with("effects.") {
        return DataRetentionPolicyChirho {
            category_chirho: DataRetentionCategoryChirho::OperationalAuditChirho,
            erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
            basis_chirho: "customer-operations-audit".to_string(),
            note_chirho:
                "CRM and effect metadata is retained as pseudonymous operational audit evidence; private payloads are crypto-shredded separately."
                    .to_string(),
        };
    }
    DataRetentionPolicyChirho {
        category_chirho: DataRetentionCategoryChirho::OperationalAuditChirho,
        erasure_disposition_chirho: ErasureDispositionChirho::RetainPseudonymousSignedLogChirho,
        basis_chirho: "operational-audit".to_string(),
        note_chirho:
            "Pseudonymous signed metadata is retained while private payload keys can be shredded."
                .to_string(),
    }
}

fn is_financial_source_chirho(source_chirho: &str) -> bool {
    source_chirho.starts_with("ledger.")
        || source_chirho.starts_with("billing.usage")
        || source_chirho.starts_with("billing.compensations")
        || source_chirho.starts_with("resource.usage")
        || source_chirho.starts_with("external.")
        || source_chirho.starts_with("credit-holds.")
        || source_chirho.starts_with("statements.")
        || source_chirho.starts_with("settlement.")
        || source_chirho.starts_with("promotions.")
        || source_chirho.starts_with("reconciliation.")
}

fn is_compliance_control_source_chirho(source_chirho: &str) -> bool {
    source_chirho.starts_with("privacy.export")
        || source_chirho.starts_with("privacy.backup-key-policies")
        || source_chirho.starts_with("privacy.retention")
        || source_chirho.starts_with("privacy.replica")
        || source_chirho.starts_with("privacy.erasure-propagations")
        || source_chirho.starts_with("data-residency.")
        || source_chirho.starts_with("compliance-evidence.")
        || source_chirho.starts_with("privacy.scan")
}

fn is_product_config_source_chirho(source_chirho: &str) -> bool {
    source_chirho.starts_with("apps.")
        || source_chirho.starts_with("pricebook.")
        || source_chirho.starts_with("billing.policy")
        || source_chirho.starts_with("resource.policy")
        || source_chirho.starts_with("feedback.policy")
        || source_chirho.starts_with("feedback.retention")
        || source_chirho.starts_with("onboarding.")
        || source_chirho.starts_with("knowledge.records")
}

struct PrivateBlobRetentionAppendInputChirho {
    operator_chirho: String,
    retention_days_chirho: u32,
    cutoff_ms_chirho: u64,
    expired_blob_seqs_chirho: Vec<u64>,
    target_key_ids_chirho: Vec<String>,
    removed_key_ids_chirho: Vec<String>,
    held_blob_seqs_chirho: Vec<u64>,
    held_key_ids_chirho: Vec<String>,
}

fn append_private_blob_retention_record_chirho(
    root_chirho: &Path,
    input_chirho: PrivateBlobRetentionAppendInputChirho,
) -> Result<PrivateBlobRetentionRecordChirho> {
    let path_chirho = privacy_retention_records_path_chirho(root_chirho);
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        PRIVACY_RETENTION_RECORDS_LOCK_CHIRHO,
        || {
            let seq_chirho = load_private_blob_retention_records_chirho(root_chirho)?.len() as u64;
            let mut record_chirho = PrivateBlobRetentionRecordChirho {
                schema_chirho: PRIVATE_BLOB_RETENTION_RECORD_SCHEMA_CHIRHO.to_string(),
                seq_chirho,
                operator_chirho: input_chirho.operator_chirho,
                retention_days_chirho: input_chirho.retention_days_chirho,
                cutoff_ms_chirho: input_chirho.cutoff_ms_chirho,
                expired_blob_seqs_chirho: input_chirho.expired_blob_seqs_chirho,
                target_key_ids_chirho: input_chirho.target_key_ids_chirho,
                removed_key_ids_chirho: input_chirho.removed_key_ids_chirho,
                held_blob_seqs_chirho: input_chirho.held_blob_seqs_chirho,
                held_key_ids_chirho: input_chirho.held_key_ids_chirho,
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = private_blob_retention_record_message_chirho(&record_chirho)?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
            seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
                &path_chirho,
                record_chirho.seq_chirho,
                &record_chirho,
            )?;
            Ok(record_chirho)
        },
    )
}

fn validate_private_blob_retention_record_chirho(
    record_chirho: &PrivateBlobRetentionRecordChirho,
    blob_records_chirho: &[privacy_chirho::PrivacyBlobRecordChirho],
) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != PRIVATE_BLOB_RETENTION_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported private blob retention record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    validate_safe_token_chirho("privacy retention operator", &record_chirho.operator_chirho)?;
    validate_retention_days_chirho(record_chirho.retention_days_chirho)?;
    let expired_by_seq_chirho: BTreeMap<u64, &privacy_chirho::PrivacyBlobRecordChirho> =
        blob_records_chirho
            .iter()
            .filter(|blob_chirho| blob_chirho.at_ms_chirho <= record_chirho.cutoff_ms_chirho)
            .map(|blob_chirho| (blob_chirho.seq_chirho, blob_chirho))
            .collect();
    let expired_seq_set_chirho: BTreeSet<u64> = record_chirho
        .expired_blob_seqs_chirho
        .iter()
        .copied()
        .collect();
    if expired_seq_set_chirho.len() != record_chirho.expired_blob_seqs_chirho.len() {
        bail!(
            "privacy retention record {} has duplicate expired blob seqs",
            record_chirho.seq_chirho
        );
    }
    let held_seq_set_chirho: BTreeSet<u64> = record_chirho
        .held_blob_seqs_chirho
        .iter()
        .copied()
        .collect();
    if held_seq_set_chirho.len() != record_chirho.held_blob_seqs_chirho.len() {
        bail!(
            "privacy retention record {} has duplicate held blob seqs",
            record_chirho.seq_chirho
        );
    }
    if !held_seq_set_chirho.is_subset(&expired_seq_set_chirho) {
        bail!(
            "privacy retention record {} has held blob seqs outside expired set",
            record_chirho.seq_chirho
        );
    }
    let mut expected_key_ids_chirho = BTreeSet::new();
    for seq_chirho in &expired_seq_set_chirho {
        let blob_chirho = expired_by_seq_chirho.get(seq_chirho).ok_or_else(|| {
            anyhow!(
                "privacy retention record {} references non-expired blob seq {}",
                record_chirho.seq_chirho,
                seq_chirho
            )
        })?;
        expected_key_ids_chirho.insert(blob_chirho.blob_chirho.key_id_chirho.clone());
    }
    let target_key_ids_chirho: BTreeSet<String> = record_chirho
        .target_key_ids_chirho
        .iter()
        .cloned()
        .collect();
    let held_key_ids_chirho: BTreeSet<String> =
        record_chirho.held_key_ids_chirho.iter().cloned().collect();
    if target_key_ids_chirho.len() != record_chirho.target_key_ids_chirho.len()
        || held_key_ids_chirho.len() != record_chirho.held_key_ids_chirho.len()
    {
        bail!(
            "privacy retention record {} has duplicate key ids",
            record_chirho.seq_chirho
        );
    }
    if !target_key_ids_chirho.is_disjoint(&held_key_ids_chirho) {
        bail!(
            "privacy retention record {} has overlapping target and held key ids",
            record_chirho.seq_chirho
        );
    }
    if target_key_ids_chirho
        .union(&held_key_ids_chirho)
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_key_ids_chirho
    {
        bail!(
            "privacy retention record {} key ids do not match expired blobs",
            record_chirho.seq_chirho
        );
    }
    let removed_key_ids_chirho: BTreeSet<String> = record_chirho
        .removed_key_ids_chirho
        .iter()
        .cloned()
        .collect();
    if removed_key_ids_chirho.len() != record_chirho.removed_key_ids_chirho.len() {
        bail!(
            "privacy retention record {} has duplicate removed key ids",
            record_chirho.seq_chirho
        );
    }
    if !removed_key_ids_chirho.is_subset(&target_key_ids_chirho) {
        bail!(
            "privacy retention record {} removed key ids outside target set",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

fn private_blob_retention_record_message_chirho(
    record_chirho: &PrivateBlobRetentionRecordChirho,
) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn validate_retention_days_chirho(retention_days_chirho: u32) -> Result<()> {
    if retention_days_chirho == 0 {
        bail!("retention_days_chirho must be positive");
    }
    Ok(())
}

fn validate_safe_token_chirho(label_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{label_chirho} must be a short opaque token");
    }
    Ok(())
}

fn load_jsonl_chirho<T>(path_chirho: &Path) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(text_chirho) = read_log_text_chirho(path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut out_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        out_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(out_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let pid_chirho = std::process::id();
        std::env::temp_dir().join(format!(
            "cairn-retention-test-{pid_chirho}-{label_chirho}-{n_chirho}-{}",
            now_ms_chirho()
        ))
    }

    fn write_privacy_blob_records_chirho(
        root_chirho: &Path,
        records_chirho: &[privacy_chirho::PrivacyBlobRecordChirho],
    ) {
        let text_chirho = records_chirho
            .iter()
            .map(|record_chirho| serde_json::to_string(record_chirho).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            root_chirho.join("privacy-blob-records-chirho.jsonl"),
            format!("{text_chirho}\n"),
        )
        .unwrap();
    }

    #[test]
    fn financial_sources_are_legal_hold_chirho() {
        let policy_chirho = signed_log_retention_policy_chirho("ledger.entries-chirho");
        assert_eq!(
            policy_chirho.category_chirho,
            DataRetentionCategoryChirho::FinancialLegalHoldChirho
        );
        assert_eq!(
            policy_chirho.erasure_disposition_chirho,
            ErasureDispositionChirho::RetainFinancialLegalHoldChirho
        );
    }

    #[test]
    fn private_blob_policy_crypto_shreds_chirho() {
        let policy_chirho = private_blob_retention_policy_chirho();
        assert_eq!(
            policy_chirho.erasure_disposition_chirho,
            ErasureDispositionChirho::CryptoShredPrivateKeyChirho
        );
    }

    #[test]
    fn legal_hold_sources_are_case_hold_chirho() {
        let policy_chirho = signed_log_retention_policy_chirho("legal-holds.records-chirho");
        assert_eq!(
            policy_chirho.category_chirho,
            DataRetentionCategoryChirho::LegalHoldAuditChirho
        );
        assert_eq!(
            policy_chirho.erasure_disposition_chirho,
            ErasureDispositionChirho::RetainLegalHoldChirho
        );
    }

    #[test]
    fn agent_oversight_sources_are_explicitly_classified_chirho() {
        let authority_chirho =
            signed_log_retention_policy_chirho("agent-authority.responses-chirho");
        assert_eq!(
            authority_chirho.category_chirho,
            DataRetentionCategoryChirho::SecurityChangeAuditChirho
        );
        let reports_chirho = signed_log_retention_policy_chirho("agent-reports.records-chirho");
        assert_eq!(
            reports_chirho.category_chirho,
            DataRetentionCategoryChirho::OperationalAuditChirho
        );
    }

    #[test]
    fn governance_and_compliance_sources_are_explicitly_classified_chirho() {
        let grants_chirho = signed_log_retention_policy_chirho("attenuation.grants-chirho");
        assert_eq!(
            grants_chirho.category_chirho,
            DataRetentionCategoryChirho::SecurityChangeAuditChirho
        );
        let residency_chirho = signed_log_retention_policy_chirho("data-residency.policies-chirho");
        assert_eq!(
            residency_chirho.category_chirho,
            DataRetentionCategoryChirho::ComplianceControlAuditChirho
        );
        let export_chirho = signed_log_retention_policy_chirho("privacy.export-evidence-chirho");
        assert_eq!(
            export_chirho.category_chirho,
            DataRetentionCategoryChirho::ComplianceControlAuditChirho
        );
        let privacy_retention_chirho =
            signed_log_retention_policy_chirho("privacy.retention-records-chirho");
        assert_eq!(
            privacy_retention_chirho.category_chirho,
            DataRetentionCategoryChirho::ComplianceControlAuditChirho
        );
    }

    #[test]
    fn private_blob_retention_sweep_shreds_expired_keys_chirho() {
        let root_chirho = tmp_root_chirho("sweep");
        let alice_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        let bob_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/bob",
            ),
            "user/bob",
            b"bob",
        )
        .unwrap();
        let future_chirho = now_ms_chirho() + (31 * MS_PER_DAY_CHIRHO);

        let preview_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            future_chirho,
            true,
        )
        .unwrap();
        assert!(preview_chirho.dry_run_chirho);
        assert_eq!(preview_chirho.target_key_ids_chirho.len(), 2);
        assert!(preview_chirho.removed_key_ids_chirho.is_empty());
        assert!(preview_chirho.record_chirho.is_none());
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &alice_chirho).unwrap(),
            b"alice"
        );

        let sweep_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            future_chirho,
            false,
        )
        .unwrap();
        assert_eq!(sweep_chirho.expired_blob_seqs_chirho.len(), 2);
        assert_eq!(sweep_chirho.removed_key_ids_chirho.len(), 2);
        assert!(sweep_chirho.held_key_ids_chirho.is_empty());
        assert!(sweep_chirho.record_chirho.is_some());
        assert!(privacy_chirho::load_private_blob_chirho(&root_chirho, &alice_chirho).is_err());
        assert!(privacy_chirho::load_private_blob_chirho(&root_chirho, &bob_chirho).is_err());
        assert_eq!(
            verify_private_blob_retention_chirho(&root_chirho).unwrap(),
            1
        );

        let second_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            future_chirho,
            false,
        )
        .unwrap();
        assert!(second_chirho.removed_key_ids_chirho.is_empty());
        assert!(second_chirho.record_chirho.is_none());
        assert_eq!(
            verify_private_blob_retention_chirho(&root_chirho).unwrap(),
            1
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn private_blob_retention_fails_on_ambiguous_key_subjects_chirho() {
        let root_chirho = tmp_root_chirho("ambiguous-key");
        let alice_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        let bob_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/bob",
            ),
            "user/bob",
            b"bob",
        )
        .unwrap();
        let mut blob_records_chirho =
            privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
        blob_records_chirho[1].blob_chirho.key_id_chirho = alice_chirho.key_id_chirho.clone();
        write_privacy_blob_records_chirho(&root_chirho, &blob_records_chirho);

        let future_chirho = now_ms_chirho() + (31 * MS_PER_DAY_CHIRHO);
        let dry_run_error_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            future_chirho,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(dry_run_error_chirho.contains("claimed by multiple subjects"));
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &alice_chirho).unwrap(),
            b"alice"
        );
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &bob_chirho).unwrap(),
            b"bob"
        );

        let verify_error_chirho = verify_private_blob_retention_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(verify_error_chirho.contains("claimed by multiple subjects"));

        let destructive_error_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            future_chirho,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(destructive_error_chirho.contains("claimed by multiple subjects"));
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &alice_chirho).unwrap(),
            b"alice"
        );
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &bob_chirho).unwrap(),
            b"bob"
        );
        assert!(load_private_blob_retention_records_chirho(&root_chirho)
            .unwrap()
            .is_empty());

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn private_blob_retention_sweep_honors_legal_holds_chirho() {
        let root_chirho = tmp_root_chirho("hold");
        let held_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/held",
            ),
            "user/held",
            b"held",
        )
        .unwrap();
        let free_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/free",
            ),
            "user/free",
            b"free",
        )
        .unwrap();
        legal_hold_chirho::place_legal_hold_chirho(
            &root_chirho,
            "hold/case-1",
            "user/held",
            "case/privacy",
            "legal-hold",
            "operator/legal",
        )
        .unwrap();
        let future_chirho = now_ms_chirho() + (31 * MS_PER_DAY_CHIRHO);

        let held_sweep_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            future_chirho,
            false,
        )
        .unwrap();
        assert_eq!(held_sweep_chirho.removed_key_ids_chirho.len(), 1);
        assert_eq!(held_sweep_chirho.held_key_ids_chirho.len(), 1);
        assert!(held_sweep_chirho
            .held_key_ids_chirho
            .contains(&held_chirho.key_id_chirho));
        assert!(privacy_chirho::load_private_blob_chirho(&root_chirho, &free_chirho).is_err());
        assert_eq!(
            privacy_chirho::load_private_blob_chirho(&root_chirho, &held_chirho).unwrap(),
            b"held"
        );
        assert_eq!(
            verify_private_blob_retention_chirho(&root_chirho).unwrap(),
            1
        );

        legal_hold_chirho::release_legal_hold_chirho(
            &root_chirho,
            "hold/case-1",
            "case-closed",
            "operator/legal",
        )
        .unwrap();
        let released_sweep_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            future_chirho,
            false,
        )
        .unwrap();
        assert_eq!(released_sweep_chirho.removed_key_ids_chirho.len(), 1);
        assert!(released_sweep_chirho
            .removed_key_ids_chirho
            .contains(&held_chirho.key_id_chirho));
        assert!(released_sweep_chirho.held_key_ids_chirho.is_empty());
        assert!(privacy_chirho::load_private_blob_chirho(&root_chirho, &held_chirho).is_err());
        assert_eq!(
            verify_private_blob_retention_chirho(&root_chirho).unwrap(),
            2
        );
        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn private_blob_retention_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
        let root_chirho = tmp_root_chirho("schema");
        privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        let sweep_chirho = sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            now_ms_chirho() + (31 * MS_PER_DAY_CHIRHO),
            false,
        )
        .unwrap();
        let record_chirho = sweep_chirho.record_chirho.as_ref().unwrap();
        assert_eq!(
            record_chirho.schema_chirho,
            PRIVATE_BLOB_RETENTION_RECORD_SCHEMA_CHIRHO
        );
        let path_chirho = privacy_retention_records_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        assert_eq!(
            text_chirho
                .matches(PRIVATE_BLOB_RETENTION_RECORD_SCHEMA_CHIRHO)
                .count(),
            1
        );

        std::fs::write(
            &path_chirho,
            text_chirho.replace(
                PRIVATE_BLOB_RETENTION_RECORD_SCHEMA_CHIRHO,
                "private-blob-retention-record-v9-chirho",
            ),
        )
        .unwrap();
        let error_chirho = verify_private_blob_retention_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported private blob retention record schema"));

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn legacy_private_blob_retention_records_without_schema_still_verify_chirho() {
        let root_chirho = tmp_root_chirho("legacy-schema");
        privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            now_ms_chirho() + (31 * MS_PER_DAY_CHIRHO),
            false,
        )
        .unwrap();
        let mut records_chirho = load_private_blob_retention_records_chirho(&root_chirho).unwrap();
        for record_chirho in &mut records_chirho {
            record_chirho.schema_chirho.clear();
            record_chirho.sig_chirho.clear();
            record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                &root_chirho,
                &private_blob_retention_record_message_chirho(record_chirho).unwrap(),
            )
            .unwrap();
        }
        let legacy_text_chirho = records_chirho
            .iter()
            .map(|record_chirho| serde_json::to_string(record_chirho).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            privacy_retention_records_path_chirho(&root_chirho),
            format!("{legacy_text_chirho}\n"),
        )
        .unwrap();
        let text_chirho =
            std::fs::read_to_string(privacy_retention_records_path_chirho(&root_chirho)).unwrap();
        assert!(!text_chirho.contains("schema_chirho"));
        assert_eq!(
            verify_private_blob_retention_chirho(&root_chirho).unwrap(),
            1
        );

        let _ = std::fs::remove_dir_all(root_chirho);
    }

    #[test]
    fn private_blob_retention_tamper_is_rejected_chirho() {
        let root_chirho = tmp_root_chirho("tamper");
        let _alice_chirho = privacy_chirho::store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        sweep_private_blob_retention_at_chirho(
            &root_chirho,
            30,
            "operator/privacy",
            now_ms_chirho() + (31 * MS_PER_DAY_CHIRHO),
            false,
        )
        .unwrap();
        assert_eq!(
            verify_private_blob_retention_chirho(&root_chirho).unwrap(),
            1
        );
        let path_chirho = privacy_retention_records_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        std::fs::write(
            &path_chirho,
            text_chirho.replace("operator/privacy", "operator/evil"),
        )
        .unwrap();
        let error_chirho = verify_private_blob_retention_chirho(&root_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("signature invalid"));
        let _ = std::fs::remove_dir_all(root_chirho);
    }
}
