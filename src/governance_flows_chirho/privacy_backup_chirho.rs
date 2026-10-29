// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Records and verifies backup key-material policy plus local replica erasure propagation.

use crate::{privacy_chirho, seqlog_chirho, tenant_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PRIVACY_REPLICA_TARGETS_LOCK_CHIRHO: &str = "privacy-replica-targets-chirho";
const PRIVACY_ERASURE_PROPAGATIONS_LOCK_CHIRHO: &str = "privacy-erasure-propagations-chirho";
const PRIVACY_BACKUP_KEY_POLICIES_LOCK_CHIRHO: &str = "privacy-backup-key-policies-chirho";
const PRIVACY_REPLICA_TARGET_SCHEMA_CHIRHO: &str = "privacy-replica-target-v1-chirho";
const PRIVACY_ERASURE_PROPAGATION_SCHEMA_CHIRHO: &str = "privacy-erasure-propagation-v1-chirho";
const PRIVACY_BACKUP_KEY_POLICY_RECORD_SCHEMA_CHIRHO: &str =
    "privacy-backup-key-policy-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyReplicaTargetChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub replica_chirho: String,
    pub root_chirho: String,
    pub registered_by_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyErasurePropagationRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub source_erasure_seq_chirho: u64,
    pub subject_chirho: String,
    pub replica_chirho: String,
    pub replica_root_chirho: String,
    pub requested_by_chirho: String,
    pub key_ids_chirho: Vec<String>,
    pub removed_key_ids_chirho: Vec<String>,
    pub already_missing_key_ids_chirho: Vec<String>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyBackupKeyPolicyChirho {
    NoDurableKeyMaterialOutsideRegisteredReplicasChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBackupKeyPolicyRecordChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub policy_chirho: PrivacyBackupKeyPolicyChirho,
    pub scope_chirho: String,
    pub max_unregistered_key_material_ttl_ms_chirho: u64,
    pub declared_by_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBackupVerifyReportChirho {
    pub backup_key_policy_records_chirho: usize,
    pub replica_targets_chirho: usize,
    pub erasure_propagation_records_chirho: usize,
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn privacy_replica_targets_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-replica-targets-chirho.jsonl")
}

fn privacy_erasure_propagations_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-erasure-propagations-chirho.jsonl")
}

fn privacy_backup_key_policies_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("privacy-backup-key-policies-chirho.jsonl")
}

pub fn declare_privacy_backup_key_policy_chirho(
    root_chirho: &Path,
    scope_chirho: &str,
    declared_by_chirho: &str,
) -> Result<PrivacyBackupKeyPolicyRecordChirho> {
    validate_safe_token_chirho("privacy backup key policy scope", scope_chirho)?;
    validate_safe_token_chirho("privacy backup key policy declarer", declared_by_chirho)?;
    std::fs::create_dir_all(root_chirho)?;
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        PRIVACY_BACKUP_KEY_POLICIES_LOCK_CHIRHO,
        || {
            let path_chirho = privacy_backup_key_policies_path_chirho(root_chirho);
            let seq_chirho =
                load_privacy_backup_key_policy_records_chirho(root_chirho)?.len() as u64;
            let mut record_chirho = PrivacyBackupKeyPolicyRecordChirho {
                schema_chirho: PRIVACY_BACKUP_KEY_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
                seq_chirho,
                policy_chirho:
                    PrivacyBackupKeyPolicyChirho::NoDurableKeyMaterialOutsideRegisteredReplicasChirho,
                scope_chirho: scope_chirho.to_string(),
                max_unregistered_key_material_ttl_ms_chirho: 0,
                declared_by_chirho: declared_by_chirho.to_string(),
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = privacy_backup_key_policy_message_chirho(&record_chirho)?;
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

pub fn register_privacy_replica_chirho(
    root_chirho: &Path,
    replica_chirho: &str,
    replica_root_chirho: &Path,
    registered_by_chirho: &str,
) -> Result<PrivacyReplicaTargetChirho> {
    validate_safe_token_chirho("privacy replica", replica_chirho)?;
    validate_safe_token_chirho("privacy replica registrar", registered_by_chirho)?;
    std::fs::create_dir_all(root_chirho)?;
    let primary_root_chirho = canonical_dir_chirho(root_chirho)?;
    let replica_root_chirho = canonical_dir_chirho(replica_root_chirho)?;
    validate_replica_root_for_primary_chirho(&primary_root_chirho, &replica_root_chirho)?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, PRIVACY_REPLICA_TARGETS_LOCK_CHIRHO, || {
        let path_chirho = privacy_replica_targets_path_chirho(root_chirho);
        let seq_chirho = load_privacy_replica_targets_chirho(root_chirho)?.len() as u64;
        let mut record_chirho = PrivacyReplicaTargetChirho {
            schema_chirho: PRIVACY_REPLICA_TARGET_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            replica_chirho: replica_chirho.to_string(),
            root_chirho: replica_root_chirho.display().to_string(),
            registered_by_chirho: registered_by_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = privacy_replica_target_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

pub fn propagate_privacy_erasure_to_replica_chirho(
    root_chirho: &Path,
    source_erasure_seq_chirho: u64,
    replica_chirho: &str,
    requested_by_chirho: &str,
) -> Result<PrivacyErasurePropagationRecordChirho> {
    validate_safe_token_chirho("privacy replica", replica_chirho)?;
    validate_safe_token_chirho("privacy erasure propagation requester", requested_by_chirho)?;
    let erasure_chirho = privacy_chirho::load_privacy_erasure_records_chirho(root_chirho)?
        .into_iter()
        .find(|record_chirho| record_chirho.seq_chirho == source_erasure_seq_chirho)
        .ok_or_else(|| anyhow!("privacy erasure record {source_erasure_seq_chirho} not found"))?;
    let target_chirho = latest_verified_replica_target_chirho(root_chirho, replica_chirho)?;
    let primary_root_chirho = canonical_dir_chirho(root_chirho)?;
    let replica_root_chirho = canonical_dir_chirho(&PathBuf::from(&target_chirho.root_chirho))?;
    if replica_root_chirho.display().to_string() != target_chirho.root_chirho {
        bail!(
            "privacy replica '{}' root changed since registration",
            target_chirho.replica_chirho
        );
    }
    validate_replica_root_for_primary_chirho(&primary_root_chirho, &replica_root_chirho)?;
    let mut removed_key_ids_chirho = Vec::new();
    let mut already_missing_key_ids_chirho = Vec::new();
    for key_id_chirho in &erasure_chirho.key_ids_chirho {
        if privacy_chirho::erase_private_blob_key_for_subject_chirho(
            &replica_root_chirho,
            key_id_chirho,
            &erasure_chirho.subject_chirho,
        )? {
            removed_key_ids_chirho.push(key_id_chirho.clone());
        } else {
            already_missing_key_ids_chirho.push(key_id_chirho.clone());
        }
    }
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        PRIVACY_ERASURE_PROPAGATIONS_LOCK_CHIRHO,
        || {
            let path_chirho = privacy_erasure_propagations_path_chirho(root_chirho);
            let seq_chirho =
                load_privacy_erasure_propagation_records_chirho(root_chirho)?.len() as u64;
            let mut record_chirho = PrivacyErasurePropagationRecordChirho {
                schema_chirho: PRIVACY_ERASURE_PROPAGATION_SCHEMA_CHIRHO.to_string(),
                seq_chirho,
                source_erasure_seq_chirho,
                subject_chirho: erasure_chirho.subject_chirho.clone(),
                replica_chirho: replica_chirho.to_string(),
                replica_root_chirho: target_chirho.root_chirho.clone(),
                requested_by_chirho: requested_by_chirho.to_string(),
                key_ids_chirho: erasure_chirho.key_ids_chirho.clone(),
                removed_key_ids_chirho,
                already_missing_key_ids_chirho,
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = privacy_erasure_propagation_message_chirho(&record_chirho)?;
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

pub fn load_privacy_replica_targets_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyReplicaTargetChirho>> {
    load_jsonl_chirho(&privacy_replica_targets_path_chirho(root_chirho))
}

pub fn load_privacy_erasure_propagation_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyErasurePropagationRecordChirho>> {
    load_jsonl_chirho(&privacy_erasure_propagations_path_chirho(root_chirho))
}

pub fn load_privacy_backup_key_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyBackupKeyPolicyRecordChirho>> {
    load_jsonl_chirho(&privacy_backup_key_policies_path_chirho(root_chirho))
}

pub fn verify_privacy_backups_chirho(
    root_chirho: &Path,
) -> Result<PrivacyBackupVerifyReportChirho> {
    let backup_key_policy_records_chirho = verify_privacy_backup_key_policies_chirho(root_chirho)?;
    let target_records_chirho = verify_privacy_replica_targets_chirho(root_chirho)?;
    let propagation_records_chirho = verify_privacy_erasure_propagations_chirho(root_chirho)?;
    let erasures_chirho = privacy_chirho::load_privacy_erasure_records_chirho(root_chirho)?;
    verify_backup_key_policy_covers_erasures_chirho(
        &backup_key_policy_records_chirho,
        &erasures_chirho,
    )?;
    verify_current_replicas_cover_all_erasures_chirho(
        &erasures_chirho,
        &target_records_chirho,
        &propagation_records_chirho,
    )?;
    Ok(PrivacyBackupVerifyReportChirho {
        backup_key_policy_records_chirho: backup_key_policy_records_chirho.len(),
        replica_targets_chirho: target_records_chirho.len(),
        erasure_propagation_records_chirho: propagation_records_chirho.len(),
    })
}

fn verify_privacy_backup_key_policies_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyBackupKeyPolicyRecordChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_privacy_backup_key_policy_records_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy backup key policy seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != PRIVACY_BACKUP_KEY_POLICY_RECORD_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported privacy backup key policy record schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_safe_token_chirho(
            "privacy backup key policy scope",
            &record_chirho.scope_chirho,
        )?;
        validate_safe_token_chirho(
            "privacy backup key policy declarer",
            &record_chirho.declared_by_chirho,
        )?;
        if record_chirho.max_unregistered_key_material_ttl_ms_chirho != 0 {
            bail!(
                "privacy backup key policy {} permits unregistered key material TTL {}ms",
                record_chirho.seq_chirho,
                record_chirho.max_unregistered_key_material_ttl_ms_chirho
            );
        }
        let message_chirho = privacy_backup_key_policy_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "privacy backup key policy {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

fn verify_privacy_replica_targets_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyReplicaTargetChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_privacy_replica_targets_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy replica target seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != PRIVACY_REPLICA_TARGET_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported privacy replica target schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_safe_token_chirho("privacy replica", &record_chirho.replica_chirho)?;
        validate_safe_token_chirho(
            "privacy replica registrar",
            &record_chirho.registered_by_chirho,
        )?;
        let root_path_chirho = PathBuf::from(&record_chirho.root_chirho);
        if !root_path_chirho.is_dir() {
            bail!(
                "privacy replica target '{}' root '{}' is not an existing directory",
                record_chirho.replica_chirho,
                record_chirho.root_chirho
            );
        }
        let primary_root_chirho = canonical_dir_chirho(root_chirho)?;
        let replica_root_chirho = canonical_dir_chirho(&root_path_chirho)?;
        if replica_root_chirho.display().to_string() != record_chirho.root_chirho {
            bail!(
                "privacy replica target '{}' root changed since registration",
                record_chirho.replica_chirho
            );
        }
        validate_replica_root_for_primary_chirho(&primary_root_chirho, &replica_root_chirho)?;
        let message_chirho = privacy_replica_target_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "privacy replica target {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

fn verify_privacy_erasure_propagations_chirho(
    root_chirho: &Path,
) -> Result<Vec<PrivacyErasurePropagationRecordChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let propagation_records_chirho = load_privacy_erasure_propagation_records_chirho(root_chirho)?;
    let erasures_chirho = privacy_chirho::load_privacy_erasure_records_chirho(root_chirho)?;
    let targets_chirho = load_privacy_replica_targets_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in propagation_records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "privacy erasure propagation seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != PRIVACY_ERASURE_PROPAGATION_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported privacy erasure propagation schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_safe_token_chirho("privacy replica", &record_chirho.replica_chirho)?;
        privacy_chirho::validate_privacy_subject_chirho(&record_chirho.subject_chirho)?;
        validate_safe_token_chirho(
            "privacy erasure propagation requester",
            &record_chirho.requested_by_chirho,
        )?;
        let erasure_chirho = erasures_chirho
            .iter()
            .find(|erasure_chirho| {
                erasure_chirho.seq_chirho == record_chirho.source_erasure_seq_chirho
            })
            .ok_or_else(|| {
                anyhow!(
                    "privacy erasure propagation {} references missing erasure {}",
                    record_chirho.seq_chirho,
                    record_chirho.source_erasure_seq_chirho
                )
            })?;
        if erasure_chirho.subject_chirho != record_chirho.subject_chirho
            || erasure_chirho.key_ids_chirho != record_chirho.key_ids_chirho
        {
            bail!(
                "privacy erasure propagation {} does not match source erasure {}",
                record_chirho.seq_chirho,
                record_chirho.source_erasure_seq_chirho
            );
        }
        if record_chirho.removed_key_ids_chirho.len()
            + record_chirho.already_missing_key_ids_chirho.len()
            != record_chirho.key_ids_chirho.len()
        {
            bail!(
                "privacy erasure propagation {} key count mismatch",
                record_chirho.seq_chirho
            );
        }
        if record_chirho
            .removed_key_ids_chirho
            .iter()
            .chain(record_chirho.already_missing_key_ids_chirho.iter())
            .collect::<std::collections::BTreeSet<_>>()
            != record_chirho
                .key_ids_chirho
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
        {
            bail!(
                "privacy erasure propagation {} key classification mismatch",
                record_chirho.seq_chirho
            );
        }
        if !targets_chirho.iter().any(|target_chirho| {
            target_chirho.replica_chirho == record_chirho.replica_chirho
                && target_chirho.root_chirho == record_chirho.replica_root_chirho
        }) {
            bail!(
                "privacy erasure propagation {} references unregistered replica target",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = privacy_erasure_propagation_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "privacy erasure propagation {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        ensure_keys_absent_from_replica_chirho(record_chirho)?;
    }
    Ok(propagation_records_chirho)
}

fn verify_backup_key_policy_covers_erasures_chirho(
    policy_records_chirho: &[PrivacyBackupKeyPolicyRecordChirho],
    erasures_chirho: &[privacy_chirho::PrivacyErasureRecordChirho],
) -> Result<()> {
    for erasure_chirho in erasures_chirho {
        let covered_chirho = policy_records_chirho
            .iter()
            .any(|policy_chirho| policy_chirho.at_ms_chirho <= erasure_chirho.at_ms_chirho);
        if !covered_chirho {
            bail!(
                "privacy erasure {} has no signed backup key-material policy in force",
                erasure_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn verify_current_replicas_cover_all_erasures_chirho(
    erasures_chirho: &[privacy_chirho::PrivacyErasureRecordChirho],
    target_records_chirho: &[PrivacyReplicaTargetChirho],
    propagation_records_chirho: &[PrivacyErasurePropagationRecordChirho],
) -> Result<()> {
    let latest_targets_chirho = latest_targets_chirho(target_records_chirho);
    if latest_targets_chirho.is_empty() {
        return Ok(());
    }
    for erasure_chirho in erasures_chirho {
        for target_chirho in latest_targets_chirho.values() {
            let propagated_chirho = propagation_records_chirho.iter().any(|record_chirho| {
                record_chirho.source_erasure_seq_chirho == erasure_chirho.seq_chirho
                    && record_chirho.replica_chirho == target_chirho.replica_chirho
                    && record_chirho.replica_root_chirho == target_chirho.root_chirho
                    && record_chirho.key_ids_chirho == erasure_chirho.key_ids_chirho
            });
            if !propagated_chirho {
                bail!(
                    "privacy erasure {} has not been propagated to replica '{}'",
                    erasure_chirho.seq_chirho,
                    target_chirho.replica_chirho
                );
            }
        }
    }
    Ok(())
}

fn latest_verified_replica_target_chirho(
    root_chirho: &Path,
    replica_chirho: &str,
) -> Result<PrivacyReplicaTargetChirho> {
    verify_privacy_replica_targets_chirho(root_chirho)?
        .into_iter()
        .rev()
        .find(|target_chirho| target_chirho.replica_chirho == replica_chirho)
        .ok_or_else(|| anyhow!("privacy replica '{replica_chirho}' is not registered"))
}

fn latest_targets_chirho(
    target_records_chirho: &[PrivacyReplicaTargetChirho],
) -> BTreeMap<String, PrivacyReplicaTargetChirho> {
    let mut out_chirho = BTreeMap::new();
    for target_chirho in target_records_chirho {
        out_chirho.insert(target_chirho.replica_chirho.clone(), target_chirho.clone());
    }
    out_chirho
}

fn ensure_keys_absent_from_replica_chirho(
    record_chirho: &PrivacyErasurePropagationRecordChirho,
) -> Result<()> {
    let replica_root_chirho = PathBuf::from(&record_chirho.replica_root_chirho);
    for key_id_chirho in &record_chirho.key_ids_chirho {
        if let Some(subject_chirho) =
            privacy_chirho::private_blob_key_subject_chirho(&replica_root_chirho, key_id_chirho)?
        {
            if subject_chirho == record_chirho.subject_chirho {
                bail!(
                    "privacy erasure propagation {} did not remove key {} from replica '{}'",
                    record_chirho.seq_chirho,
                    key_id_chirho,
                    record_chirho.replica_chirho
                );
            }
            bail!(
                "privacy replica '{}' has key {} for unexpected subject '{}'",
                record_chirho.replica_chirho,
                key_id_chirho,
                subject_chirho
            );
        }
    }
    Ok(())
}

fn canonical_dir_chirho(path_chirho: &Path) -> Result<PathBuf> {
    let canonical_chirho = std::fs::canonicalize(path_chirho)
        .with_context(|| format!("canonicalize {}", path_chirho.display()))?;
    if !canonical_chirho.is_dir() {
        bail!("{} is not a directory", canonical_chirho.display());
    }
    Ok(canonical_chirho)
}

fn validate_replica_root_for_primary_chirho(
    primary_root_chirho: &Path,
    replica_root_chirho: &Path,
) -> Result<()> {
    if primary_root_chirho == replica_root_chirho {
        bail!("privacy backup replica root must not be the primary root");
    }
    let primary_tenant_chirho = tenant_chirho::tenant_id_for_root_chirho(primary_root_chirho)?;
    let replica_tenant_chirho = tenant_chirho::tenant_id_for_root_chirho(replica_root_chirho)?;
    if (!primary_tenant_chirho.is_platform_root_chirho()
        || !replica_tenant_chirho.is_platform_root_chirho())
        && primary_tenant_chirho != replica_tenant_chirho
    {
        bail!("privacy backup replica root must belong to the same tenant as the primary root");
    }
    if replica_tenant_chirho.is_platform_root_chirho()
        && !has_cairn_root_evidence_chirho(replica_root_chirho)
    {
        bail!(
            "privacy backup replica root '{}' is not a recognized cairn root",
            replica_root_chirho.display()
        );
    }
    Ok(())
}

fn has_cairn_root_evidence_chirho(root_chirho: &Path) -> bool {
    root_chirho
        .join(tenant_chirho::TENANT_MARKER_CHIRHO)
        .is_file()
        || root_chirho.join("privacy-keys-chirho").is_dir()
        || root_chirho.join("objects-chirho").is_dir()
        || root_chirho.join("writer-fences-chirho").is_dir()
        || root_chirho.join("gate1-authority-head-chirho").is_dir()
        || root_chirho
            .join("gate1-authority-log-chirho.jsonl")
            .is_file()
        || root_chirho
            .join("privacy-blob-records-chirho.jsonl")
            .is_file()
        || root_chirho.join("head-removals-chirho.jsonl").is_file()
        || root_chirho
            .join("privacy-erasure-records-chirho.jsonl")
            .is_file()
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

fn privacy_replica_target_message_chirho(
    record_chirho: &PrivacyReplicaTargetChirho,
) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn privacy_erasure_propagation_message_chirho(
    record_chirho: &PrivacyErasurePropagationRecordChirho,
) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn privacy_backup_key_policy_message_chirho(
    record_chirho: &PrivacyBackupKeyPolicyRecordChirho,
) -> Result<Vec<u8>> {
    let mut message_chirho = record_chirho.clone();
    message_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&message_chirho)?)
}

fn load_jsonl_chirho<T>(path_chirho: &Path) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
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

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let pid_chirho = std::process::id();
        std::env::temp_dir().join(format!(
            "cairn-privacy-backup-test-{pid_chirho}-{label_chirho}-{n_chirho}-{}",
            now_ms_chirho()
        ))
    }

    fn copy_key_to_replica_chirho(primary_chirho: &Path, replica_chirho: &Path, key_chirho: &str) {
        let from_chirho = primary_chirho
            .join("privacy-keys-chirho")
            .join(format!("{key_chirho}.json"));
        let to_dir_chirho = replica_chirho.join("privacy-keys-chirho");
        std::fs::create_dir_all(&to_dir_chirho).unwrap();
        std::fs::copy(
            from_chirho,
            to_dir_chirho.join(format!("{key_chirho}.json")),
        )
        .unwrap();
    }

    #[test]
    fn erasure_propagates_to_registered_local_replica_chirho() {
        let primary_chirho = tmp_root_chirho("primary");
        let replica_chirho = tmp_root_chirho("replica");
        std::fs::create_dir_all(&replica_chirho).unwrap();
        let alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        let bob_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/bob",
            ),
            "user/bob",
            b"bob",
        )
        .unwrap();
        copy_key_to_replica_chirho(
            &primary_chirho,
            &replica_chirho,
            &alice_blob_chirho.key_id_chirho,
        );
        copy_key_to_replica_chirho(
            &primary_chirho,
            &replica_chirho,
            &bob_blob_chirho.key_id_chirho,
        );
        register_privacy_replica_chirho(
            &primary_chirho,
            "backup/local-a",
            &replica_chirho,
            "operator/privacy",
        )
        .unwrap();
        declare_privacy_backup_key_policy_chirho(
            &primary_chirho,
            "durable-backups-ciphertext-only",
            "operator/privacy",
        )
        .unwrap();
        let erasure_chirho = privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        assert!(verify_privacy_backups_chirho(&primary_chirho).is_err());
        let propagation_chirho = propagate_privacy_erasure_to_replica_chirho(
            &primary_chirho,
            erasure_chirho.seq_chirho,
            "backup/local-a",
            "operator/privacy",
        )
        .unwrap();
        assert_eq!(propagation_chirho.removed_key_ids_chirho.len(), 1);
        assert_eq!(
            privacy_chirho::private_blob_key_subject_chirho(
                &replica_chirho,
                &alice_blob_chirho.key_id_chirho
            )
            .unwrap(),
            None
        );
        assert_eq!(
            privacy_chirho::private_blob_key_subject_chirho(
                &replica_chirho,
                &bob_blob_chirho.key_id_chirho
            )
            .unwrap(),
            Some("user/bob".to_string())
        );
        let report_chirho = verify_privacy_backups_chirho(&primary_chirho).unwrap();
        assert_eq!(report_chirho.replica_targets_chirho, 1);
        assert_eq!(report_chirho.erasure_propagation_records_chirho, 1);
        let _ = std::fs::remove_dir_all(primary_chirho);
        let _ = std::fs::remove_dir_all(replica_chirho);
    }

    #[test]
    fn privacy_backup_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
        let primary_chirho = tmp_root_chirho("primary-schema");
        let replica_chirho = tmp_root_chirho("replica-schema");
        std::fs::create_dir_all(&replica_chirho).unwrap();
        let alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        copy_key_to_replica_chirho(
            &primary_chirho,
            &replica_chirho,
            &alice_blob_chirho.key_id_chirho,
        );
        let target_chirho = register_privacy_replica_chirho(
            &primary_chirho,
            "backup/local-a",
            &replica_chirho,
            "operator/privacy",
        )
        .unwrap();
        let policy_chirho = declare_privacy_backup_key_policy_chirho(
            &primary_chirho,
            "durable-backups-ciphertext-only",
            "operator/privacy",
        )
        .unwrap();
        let erasure_chirho = privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        let propagation_chirho = propagate_privacy_erasure_to_replica_chirho(
            &primary_chirho,
            erasure_chirho.seq_chirho,
            "backup/local-a",
            "operator/privacy",
        )
        .unwrap();
        assert_eq!(
            target_chirho.schema_chirho,
            PRIVACY_REPLICA_TARGET_SCHEMA_CHIRHO
        );
        assert_eq!(
            policy_chirho.schema_chirho,
            PRIVACY_BACKUP_KEY_POLICY_RECORD_SCHEMA_CHIRHO
        );
        assert_eq!(
            propagation_chirho.schema_chirho,
            PRIVACY_ERASURE_PROPAGATION_SCHEMA_CHIRHO
        );

        let policy_path_chirho = privacy_backup_key_policies_path_chirho(&primary_chirho);
        let target_path_chirho = privacy_replica_targets_path_chirho(&primary_chirho);
        let propagation_path_chirho = privacy_erasure_propagations_path_chirho(&primary_chirho);
        let policy_text_chirho = std::fs::read_to_string(&policy_path_chirho).unwrap();
        let target_text_chirho = std::fs::read_to_string(&target_path_chirho).unwrap();
        let propagation_text_chirho = std::fs::read_to_string(&propagation_path_chirho).unwrap();
        assert!(policy_text_chirho.contains(PRIVACY_BACKUP_KEY_POLICY_RECORD_SCHEMA_CHIRHO));
        assert!(target_text_chirho.contains(PRIVACY_REPLICA_TARGET_SCHEMA_CHIRHO));
        assert!(propagation_text_chirho.contains(PRIVACY_ERASURE_PROPAGATION_SCHEMA_CHIRHO));

        std::fs::write(
            &policy_path_chirho,
            policy_text_chirho.replace(
                PRIVACY_BACKUP_KEY_POLICY_RECORD_SCHEMA_CHIRHO,
                "privacy-backup-key-policy-record-v9-chirho",
            ),
        )
        .unwrap();
        let policy_error_chirho = verify_privacy_backups_chirho(&primary_chirho)
            .unwrap_err()
            .to_string();
        assert!(policy_error_chirho.contains("unsupported privacy backup key policy record schema"));

        std::fs::write(&policy_path_chirho, policy_text_chirho).unwrap();
        std::fs::write(
            &target_path_chirho,
            target_text_chirho.replace(
                PRIVACY_REPLICA_TARGET_SCHEMA_CHIRHO,
                "privacy-replica-target-v9-chirho",
            ),
        )
        .unwrap();
        let target_error_chirho = verify_privacy_backups_chirho(&primary_chirho)
            .unwrap_err()
            .to_string();
        assert!(target_error_chirho.contains("unsupported privacy replica target schema"));

        std::fs::write(&target_path_chirho, target_text_chirho).unwrap();
        std::fs::write(
            &propagation_path_chirho,
            propagation_text_chirho.replace(
                PRIVACY_ERASURE_PROPAGATION_SCHEMA_CHIRHO,
                "privacy-erasure-propagation-v9-chirho",
            ),
        )
        .unwrap();
        let propagation_error_chirho = verify_privacy_backups_chirho(&primary_chirho)
            .unwrap_err()
            .to_string();
        assert!(propagation_error_chirho.contains("unsupported privacy erasure propagation schema"));

        let _ = std::fs::remove_dir_all(primary_chirho);
        let _ = std::fs::remove_dir_all(replica_chirho);
    }

    #[test]
    fn legacy_privacy_backup_records_without_schema_still_verify_chirho() {
        let primary_chirho = tmp_root_chirho("primary-legacy");
        let replica_chirho = tmp_root_chirho("replica-legacy");
        std::fs::create_dir_all(&replica_chirho).unwrap();
        let alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        copy_key_to_replica_chirho(
            &primary_chirho,
            &replica_chirho,
            &alice_blob_chirho.key_id_chirho,
        );
        register_privacy_replica_chirho(
            &primary_chirho,
            "backup/local-a",
            &replica_chirho,
            "operator/privacy",
        )
        .unwrap();
        declare_privacy_backup_key_policy_chirho(
            &primary_chirho,
            "durable-backups-ciphertext-only",
            "operator/privacy",
        )
        .unwrap();
        let erasure_chirho = privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        propagate_privacy_erasure_to_replica_chirho(
            &primary_chirho,
            erasure_chirho.seq_chirho,
            "backup/local-a",
            "operator/privacy",
        )
        .unwrap();

        let mut policy_chirho = load_privacy_backup_key_policy_records_chirho(&primary_chirho)
            .unwrap()
            .remove(0);
        policy_chirho.schema_chirho.clear();
        policy_chirho.sig_chirho.clear();
        policy_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &primary_chirho,
            &privacy_backup_key_policy_message_chirho(&policy_chirho).unwrap(),
        )
        .unwrap();
        std::fs::write(
            privacy_backup_key_policies_path_chirho(&primary_chirho),
            format!("{}\n", serde_json::to_string(&policy_chirho).unwrap()),
        )
        .unwrap();

        let mut target_chirho = load_privacy_replica_targets_chirho(&primary_chirho)
            .unwrap()
            .remove(0);
        target_chirho.schema_chirho.clear();
        target_chirho.sig_chirho.clear();
        target_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &primary_chirho,
            &privacy_replica_target_message_chirho(&target_chirho).unwrap(),
        )
        .unwrap();
        std::fs::write(
            privacy_replica_targets_path_chirho(&primary_chirho),
            format!("{}\n", serde_json::to_string(&target_chirho).unwrap()),
        )
        .unwrap();

        let mut propagation_chirho =
            load_privacy_erasure_propagation_records_chirho(&primary_chirho)
                .unwrap()
                .remove(0);
        propagation_chirho.schema_chirho.clear();
        propagation_chirho.sig_chirho.clear();
        propagation_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &primary_chirho,
            &privacy_erasure_propagation_message_chirho(&propagation_chirho).unwrap(),
        )
        .unwrap();
        std::fs::write(
            privacy_erasure_propagations_path_chirho(&primary_chirho),
            format!("{}\n", serde_json::to_string(&propagation_chirho).unwrap()),
        )
        .unwrap();

        let policy_text_chirho =
            std::fs::read_to_string(privacy_backup_key_policies_path_chirho(&primary_chirho))
                .unwrap();
        let target_text_chirho =
            std::fs::read_to_string(privacy_replica_targets_path_chirho(&primary_chirho)).unwrap();
        let propagation_text_chirho =
            std::fs::read_to_string(privacy_erasure_propagations_path_chirho(&primary_chirho))
                .unwrap();
        assert!(!policy_text_chirho.contains("schema_chirho"));
        assert!(!target_text_chirho.contains("schema_chirho"));
        assert!(!propagation_text_chirho.contains("schema_chirho"));
        let report_chirho = verify_privacy_backups_chirho(&primary_chirho).unwrap();
        assert_eq!(report_chirho.backup_key_policy_records_chirho, 1);
        assert_eq!(report_chirho.replica_targets_chirho, 1);
        assert_eq!(report_chirho.erasure_propagation_records_chirho, 1);

        let _ = std::fs::remove_dir_all(primary_chirho);
        let _ = std::fs::remove_dir_all(replica_chirho);
    }

    #[test]
    fn propagation_refuses_subject_mismatched_replica_key_chirho() {
        let primary_chirho = tmp_root_chirho("primary-mismatch");
        let replica_chirho = tmp_root_chirho("replica-mismatch");
        std::fs::create_dir_all(&replica_chirho).unwrap();
        let alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        let wrong_subject_key_chirho = serde_json::json!({
            "subject_chirho": "user/bob",
            "key_hex_chirho": "00".repeat(32),
        });
        let replica_keys_chirho = replica_chirho.join("privacy-keys-chirho");
        std::fs::create_dir_all(&replica_keys_chirho).unwrap();
        std::fs::write(
            replica_keys_chirho.join(format!("{}.json", alice_blob_chirho.key_id_chirho)),
            serde_json::to_vec_pretty(&wrong_subject_key_chirho).unwrap(),
        )
        .unwrap();
        register_privacy_replica_chirho(
            &primary_chirho,
            "backup/local-a",
            &replica_chirho,
            "operator/privacy",
        )
        .unwrap();
        let erasure_chirho = privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        let error_chirho = propagate_privacy_erasure_to_replica_chirho(
            &primary_chirho,
            erasure_chirho.seq_chirho,
            "backup/local-a",
            "operator/privacy",
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("not 'user/alice'"));
        let _ = std::fs::remove_dir_all(primary_chirho);
        let _ = std::fs::remove_dir_all(replica_chirho);
    }

    #[test]
    fn replica_registration_rejects_unrecognized_root_chirho() {
        let primary_chirho = tmp_root_chirho("primary-unrecognized");
        let replica_chirho = tmp_root_chirho("replica-unrecognized");
        std::fs::create_dir_all(&primary_chirho).unwrap();
        std::fs::create_dir_all(&replica_chirho).unwrap();
        let error_chirho = register_privacy_replica_chirho(
            &primary_chirho,
            "backup/local-a",
            &replica_chirho,
            "operator/privacy",
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("not a recognized cairn root"));
        let _ = std::fs::remove_dir_all(primary_chirho);
        let _ = std::fs::remove_dir_all(replica_chirho);
    }

    #[test]
    fn erasure_verify_requires_signed_backup_key_policy_chirho() {
        let primary_chirho = tmp_root_chirho("primary-policy-required");
        let _alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        let error_chirho = verify_privacy_backups_chirho(&primary_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("backup key-material policy"));
        let _ = std::fs::remove_dir_all(primary_chirho);
    }

    #[test]
    fn ciphertext_only_policy_covers_erasure_without_registered_replicas_chirho() {
        let primary_chirho = tmp_root_chirho("primary-ciphertext-only");
        declare_privacy_backup_key_policy_chirho(
            &primary_chirho,
            "durable-backups-ciphertext-only",
            "operator/privacy",
        )
        .unwrap();
        let _alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        let report_chirho = verify_privacy_backups_chirho(&primary_chirho).unwrap();
        assert_eq!(report_chirho.backup_key_policy_records_chirho, 1);
        assert_eq!(report_chirho.replica_targets_chirho, 0);
        assert_eq!(report_chirho.erasure_propagation_records_chirho, 0);
        let _ = std::fs::remove_dir_all(primary_chirho);
    }

    #[test]
    fn backup_key_policy_after_erasure_does_not_retroactively_cover_chirho() {
        let primary_chirho = tmp_root_chirho("primary-policy-late");
        let _alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        declare_privacy_backup_key_policy_chirho(
            &primary_chirho,
            "durable-backups-ciphertext-only",
            "operator/privacy",
        )
        .unwrap();
        let error_chirho = verify_privacy_backups_chirho(&primary_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("no signed backup key-material policy in force"));
        let _ = std::fs::remove_dir_all(primary_chirho);
    }

    #[test]
    fn propagation_is_idempotent_after_first_delete_chirho() {
        let primary_chirho = tmp_root_chirho("primary-idempotent");
        let replica_chirho = tmp_root_chirho("replica-idempotent");
        std::fs::create_dir_all(&replica_chirho).unwrap();
        let alice_blob_chirho = privacy_chirho::store_private_blob_chirho(
            &primary_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/alice",
            ),
            "user/alice",
            b"alice",
        )
        .unwrap();
        copy_key_to_replica_chirho(
            &primary_chirho,
            &replica_chirho,
            &alice_blob_chirho.key_id_chirho,
        );
        register_privacy_replica_chirho(
            &primary_chirho,
            "backup/local-a",
            &replica_chirho,
            "operator/privacy",
        )
        .unwrap();
        declare_privacy_backup_key_policy_chirho(
            &primary_chirho,
            "durable-backups-ciphertext-only",
            "operator/privacy",
        )
        .unwrap();
        let erasure_chirho = privacy_chirho::erase_subject_data_chirho(
            &primary_chirho,
            "user/alice",
            "operator/privacy",
            "gdpr-erasure-request",
        )
        .unwrap();
        let first_chirho = propagate_privacy_erasure_to_replica_chirho(
            &primary_chirho,
            erasure_chirho.seq_chirho,
            "backup/local-a",
            "operator/privacy",
        )
        .unwrap();
        let second_chirho = propagate_privacy_erasure_to_replica_chirho(
            &primary_chirho,
            erasure_chirho.seq_chirho,
            "backup/local-a",
            "operator/privacy",
        )
        .unwrap();
        assert_eq!(first_chirho.removed_key_ids_chirho.len(), 1);
        assert_eq!(second_chirho.removed_key_ids_chirho.len(), 0);
        assert_eq!(second_chirho.already_missing_key_ids_chirho.len(), 1);
        let report_chirho = verify_privacy_backups_chirho(&primary_chirho).unwrap();
        assert_eq!(report_chirho.erasure_propagation_records_chirho, 2);
        let _ = std::fs::remove_dir_all(primary_chirho);
        let _ = std::fs::remove_dir_all(replica_chirho);
    }
}
