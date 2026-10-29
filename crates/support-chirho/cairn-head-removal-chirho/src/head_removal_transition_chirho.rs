// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Signed Prepared/Applied removal recovery over caller-verified domain evidence.

use crate::head_removal_chirho::{self, HeadRemovalKindChirho, HeadRemovalRecordChirho};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::{cas_chirho, model_chirho::HashChirho};
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, verify_writer_fence_for_root_chirho,
    with_head_transition_scope_chirho, WriterFenceTokenChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO: &str = "head-removal-prepared-v2-chirho";
pub const HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO: &str = "head-removal-applied-receipt-v1-chirho";
pub const HEAD_REMOVAL_TRANSITION_ID_PREFIX_CHIRHO: &str =
    "head-removal-transition-blake3-v1-chirho:";
pub const HEAD_REMOVAL_DOMAIN_LINE_DIGEST_PREFIX_CHIRHO: &str =
    "head-removal-domain-line-blake3-v1-chirho:";
pub const HEAD_REMOVAL_PREPARED_LINE_DIGEST_PREFIX_CHIRHO: &str =
    "head-removal-prepared-line-blake3-v1-chirho:";
const HEAD_REMOVAL_REASON_CHIRHO: &str = "head-removal-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadRemovalPreparedRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub transition_id_chirho: String,
    pub branch_chirho: String,
    pub from_chirho: HashChirho,
    pub kind_chirho: HeadRemovalKindChirho,
    pub app_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_chirho: Option<String>,
    pub owner_principal_chirho: String,
    pub domain_log_chirho: String,
    pub domain_seq_chirho: u64,
    pub domain_line_digest_chirho: String,
    pub reason_chirho: String,
    pub writer_fence_group_digest_chirho: String,
    pub prepared_writer_fence_epoch_chirho: u64,
    pub at_ms_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadRemovalAppliedRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub transition_id_chirho: String,
    pub prepared_removal_seq_chirho: u64,
    pub prepared_line_digest_chirho: String,
    pub writer_fence_group_digest_chirho: String,
    pub prepared_writer_fence_epoch_chirho: u64,
    pub applied_writer_fence_epoch_chirho: u64,
    pub applied_at_ms_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

pub struct HeadRemovalPreparedInputChirho<'a> {
    pub branch_chirho: &'a str,
    pub from_chirho: &'a HashChirho,
    pub kind_chirho: HeadRemovalKindChirho,
    pub app_chirho: &'a str,
    pub route_chirho: Option<&'a str>,
    pub owner_principal_chirho: &'a str,
    pub domain_log_chirho: &'a str,
    pub domain_seq_chirho: u64,
    pub prepared_fence_chirho: &'a WriterFenceTokenChirho,
    pub at_ms_chirho: u64,
}

#[derive(Clone)]
pub struct PreparedHeadRemovalChirho {
    transition_id_chirho: String,
    prepared_removal_seq_chirho: u64,
    prepared_line_digest_chirho: String,
    branch_chirho: String,
    from_chirho: HashChirho,
    writer_fence_group_digest_chirho: String,
    prepared_writer_fence_epoch_chirho: u64,
}

impl PreparedHeadRemovalChirho {
    pub fn transition_id_chirho(&self) -> &str {
        &self.transition_id_chirho
    }

    pub fn branch_chirho(&self) -> &str {
        &self.branch_chirho
    }

    pub fn from_chirho(&self) -> &HashChirho {
        &self.from_chirho
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadRemovalRecoveryOutcomeChirho {
    AppliedChirho,
    RepairedAppliedReceiptChirho,
    AlreadyAppliedChirho,
}

#[derive(Clone, Debug)]
pub(crate) enum StoredHeadRemovalLogEntryChirho {
    LegacyV1Chirho(HeadRemovalRecordChirho),
    TransitionChirho(StoredHeadRemovalTransitionEntryChirho),
}

#[derive(Clone, Debug)]
pub(crate) enum StoredHeadRemovalTransitionEntryChirho {
    PreparedV2Chirho(HeadRemovalPreparedRecordChirho),
    AppliedV1Chirho(HeadRemovalAppliedRecordChirho),
}

#[derive(Deserialize)]
struct HeadRemovalSchemaProbeChirho {
    seq_chirho: u64,
    schema_chirho: String,
}

#[derive(Serialize)]
struct HeadRemovalTransitionIdentityChirho<'a> {
    schema_chirho: &'static str,
    prepared_removal_seq_chirho: u64,
    branch_chirho: &'a str,
    from_chirho: &'a HashChirho,
    kind_chirho: &'a HeadRemovalKindChirho,
    app_chirho: &'a str,
    route_chirho: &'a Option<String>,
    owner_principal_chirho: &'a str,
    domain_log_chirho: &'a str,
    domain_seq_chirho: u64,
    domain_line_digest_chirho: &'a str,
    reason_chirho: &'a str,
    writer_fence_group_digest_chirho: &'a str,
    prepared_writer_fence_epoch_chirho: u64,
    at_ms_chirho: u64,
}

pub fn append_caller_verified_prepared_head_removal_unlocked_chirho(
    root_chirho: &Path,
    input_chirho: HeadRemovalPreparedInputChirho<'_>,
    canonical_signed_domain_line_chirho: &[u8],
) -> Result<PreparedHeadRemovalChirho> {
    verify_writer_fence_for_root_chirho(root_chirho, input_chirho.prepared_fence_chirho)
        .map_err(anyhow::Error::new)
        .context("head removal Prepared fence is not current")?;
    validate_prepared_input_chirho(&input_chirho, canonical_signed_domain_line_chirho)?;
    recover_head_removal_log_tail_unlocked_chirho(root_chirho)?;
    verify_head_removal_log_chirho(root_chirho)?;
    ensure_no_unapplied_prepared_for_branch_chirho(root_chirho, input_chirho.branch_chirho)?;
    let current_chirho =
        head_removal_chirho::current_branch_hash_chirho(root_chirho, input_chirho.branch_chirho)?;
    if current_chirho.as_ref() != Some(input_chirho.from_chirho) {
        bail!("head removal Prepared record does not match the current branch head");
    }

    let key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let path_chirho = head_removal_chirho::head_removal_records_path_chirho(root_chirho);
    let domain_line_digest_chirho = prefixed_hash_chirho(
        HEAD_REMOVAL_DOMAIN_LINE_DIGEST_PREFIX_CHIRHO,
        canonical_signed_domain_line_chirho,
    );
    let record_chirho =
        seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
            let writer_fence_group_digest_chirho =
                consistency_group_digest_chirho(&input_chirho.prepared_fence_chirho.group_chirho)?;
            let route_chirho = input_chirho.route_chirho.map(str::to_string);
            let transition_id_chirho = derive_transition_id_chirho(
                seq_chirho,
                &input_chirho,
                &route_chirho,
                &domain_line_digest_chirho,
                &writer_fence_group_digest_chirho,
            )?;
            let mut record_chirho = HeadRemovalPreparedRecordChirho {
                seq_chirho,
                schema_chirho: HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO.to_string(),
                transition_id_chirho,
                branch_chirho: input_chirho.branch_chirho.to_string(),
                from_chirho: input_chirho.from_chirho.clone(),
                kind_chirho: input_chirho.kind_chirho.clone(),
                app_chirho: input_chirho.app_chirho.to_string(),
                route_chirho,
                owner_principal_chirho: input_chirho.owner_principal_chirho.to_string(),
                domain_log_chirho: input_chirho.domain_log_chirho.to_string(),
                domain_seq_chirho: input_chirho.domain_seq_chirho,
                domain_line_digest_chirho: domain_line_digest_chirho.clone(),
                reason_chirho: HEAD_REMOVAL_REASON_CHIRHO.to_string(),
                writer_fence_group_digest_chirho,
                prepared_writer_fence_epoch_chirho: input_chirho.prepared_fence_chirho.epoch_chirho,
                at_ms_chirho: input_chirho.at_ms_chirho,
                key_id_chirho: key_id_chirho.clone(),
                sig_chirho: String::new(),
            };
            record_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
                root_chirho,
                &unsigned_prepared_message_chirho(&record_chirho)?,
            )?;
            if signer_chirho::existing_pubkey_hex_chirho(root_chirho)? != key_id_chirho {
                bail!("head removal root key changed while signing Prepared evidence");
            }
            Ok(record_chirho)
        })?;
    bind_caller_verified_prepared_head_removal_chirho(
        root_chirho,
        &record_chirho,
        canonical_signed_domain_line_chirho,
    )
}

pub fn bind_caller_verified_prepared_head_removal_chirho(
    root_chirho: &Path,
    record_chirho: &HeadRemovalPreparedRecordChirho,
    canonical_signed_domain_line_chirho: &[u8],
) -> Result<PreparedHeadRemovalChirho> {
    if canonical_signed_domain_line_chirho.is_empty() {
        bail!("head removal canonical signed domain line must not be empty");
    }
    verify_prepared_record_chirho(root_chirho, record_chirho)?;
    let domain_line_digest_chirho = prefixed_hash_chirho(
        HEAD_REMOVAL_DOMAIN_LINE_DIGEST_PREFIX_CHIRHO,
        canonical_signed_domain_line_chirho,
    );
    if record_chirho.domain_line_digest_chirho != domain_line_digest_chirho {
        bail!("head removal Prepared record does not bind the caller-verified domain line");
    }
    let input_chirho = HeadRemovalPreparedInputChirho {
        branch_chirho: &record_chirho.branch_chirho,
        from_chirho: &record_chirho.from_chirho,
        kind_chirho: record_chirho.kind_chirho.clone(),
        app_chirho: &record_chirho.app_chirho,
        route_chirho: record_chirho.route_chirho.as_deref(),
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        domain_log_chirho: &record_chirho.domain_log_chirho,
        domain_seq_chirho: record_chirho.domain_seq_chirho,
        prepared_fence_chirho: &WriterFenceTokenChirho {
            group_chirho:
                cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho(
                    root_chirho,
                )?,
            epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho,
            issued_at_ms_chirho: record_chirho.at_ms_chirho,
        },
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    let expected_group_digest_chirho =
        consistency_group_digest_chirho(&input_chirho.prepared_fence_chirho.group_chirho)?;
    if expected_group_digest_chirho != record_chirho.writer_fence_group_digest_chirho {
        bail!("head removal Prepared record belongs to another consistency group");
    }
    let expected_transition_id_chirho = derive_transition_id_chirho(
        record_chirho.seq_chirho,
        &input_chirho,
        &record_chirho.route_chirho,
        &record_chirho.domain_line_digest_chirho,
        &record_chirho.writer_fence_group_digest_chirho,
    )?;
    if expected_transition_id_chirho != record_chirho.transition_id_chirho {
        bail!("head removal transition id does not match the canonical unsigned intent");
    }
    Ok(PreparedHeadRemovalChirho {
        transition_id_chirho: record_chirho.transition_id_chirho.clone(),
        prepared_removal_seq_chirho: record_chirho.seq_chirho,
        prepared_line_digest_chirho: prepared_line_digest_chirho(record_chirho)?,
        branch_chirho: record_chirho.branch_chirho.clone(),
        from_chirho: record_chirho.from_chirho.clone(),
        writer_fence_group_digest_chirho: record_chirho.writer_fence_group_digest_chirho.clone(),
        prepared_writer_fence_epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho,
    })
}

pub fn complete_head_removal_unlocked_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadRemovalChirho,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<HeadRemovalRecoveryOutcomeChirho> {
    verify_applier_fence_chirho(root_chirho, prepared_chirho, applier_fence_chirho)?;
    recover_head_removal_log_tail_unlocked_chirho(root_chirho)?;
    verify_prepared_is_recorded_chirho(root_chirho, prepared_chirho)?;
    if verified_applied_receipt_for_prepared_chirho(root_chirho, prepared_chirho)?.is_some() {
        return Ok(HeadRemovalRecoveryOutcomeChirho::AlreadyAppliedChirho);
    }

    let current_chirho = head_removal_chirho::current_branch_hash_chirho(
        root_chirho,
        &prepared_chirho.branch_chirho,
    )?;
    let outcome_chirho = match current_chirho {
        Some(current_chirho) if current_chirho == prepared_chirho.from_chirho => {
            verify_applier_fence_chirho(root_chirho, prepared_chirho, applier_fence_chirho)?;
            if !head_removal_chirho::remove_branch_if_current_chirho(
                root_chirho,
                &prepared_chirho.branch_chirho,
                &prepared_chirho.from_chirho,
            )? {
                bail!("head removal branch disappeared before the reviewed delete sink");
            }
            HeadRemovalRecoveryOutcomeChirho::AppliedChirho
        }
        None => HeadRemovalRecoveryOutcomeChirho::RepairedAppliedReceiptChirho,
        Some(current_chirho) => bail!(
            "head removal transition '{}' diverges from current branch head {}",
            prepared_chirho.transition_id_chirho,
            current_chirho.0
        ),
    };

    verify_applier_fence_chirho(root_chirho, prepared_chirho, applier_fence_chirho)?;
    let applied_chirho =
        append_applied_receipt_unlocked_chirho(root_chirho, prepared_chirho, applier_fence_chirho)?;
    recover_head_removal_log_tail_unlocked_chirho(root_chirho)?;
    let recorded_chirho =
        verified_applied_receipt_for_prepared_chirho(root_chirho, prepared_chirho)?.ok_or_else(
            || anyhow::anyhow!("head removal Applied receipt missing after completion"),
        )?;
    if recorded_chirho != applied_chirho {
        bail!("head removal recorded Applied receipt differs from completion receipt");
    }
    Ok(outcome_chirho)
}

pub fn recover_head_removal_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadRemovalChirho,
) -> Result<HeadRemovalRecoveryOutcomeChirho> {
    with_head_transition_scope_chirho(root_chirho, |applier_fence_chirho| {
        complete_head_removal_unlocked_chirho(root_chirho, prepared_chirho, applier_fence_chirho)
    })
}

pub fn verified_head_removal_applied_receipt_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadRemovalChirho,
) -> Result<bool> {
    verify_prepared_is_recorded_chirho(root_chirho, prepared_chirho)?;
    Ok(verified_applied_receipt_for_prepared_chirho(root_chirho, prepared_chirho)?.is_some())
}

pub fn pending_head_removal_index_unlocked_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    current_head_chirho: &Option<HashChirho>,
    prepared_chirho: &[PreparedHeadRemovalChirho],
) -> Result<Option<usize>> {
    recover_head_removal_log_tail_unlocked_chirho(root_chirho)?;
    let mut pending_index_chirho = None;
    for (index_chirho, candidate_chirho) in prepared_chirho.iter().enumerate() {
        if candidate_chirho.branch_chirho != branch_chirho {
            continue;
        }
        verify_prepared_is_recorded_chirho(root_chirho, candidate_chirho)?;
        if verified_applied_receipt_for_prepared_chirho(root_chirho, candidate_chirho)?.is_some() {
            continue;
        }
        if current_head_chirho != &Some(candidate_chirho.from_chirho.clone())
            && current_head_chirho.is_some()
        {
            bail!("unapplied head removal diverges from the current branch head");
        }
        if pending_index_chirho.replace(index_chirho).is_some() {
            bail!("multiple unapplied head removals match one branch");
        }
    }
    Ok(pending_index_chirho)
}

pub fn root_signed_prepared_head_removal_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<HeadRemovalPreparedRecordChirho>> {
    let entries_chirho = verified_head_removal_log_entries_chirho(root_chirho)?;
    Ok(entries_chirho
        .into_iter()
        .filter_map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::PreparedV2Chirho(record_chirho),
            ) => Some(record_chirho),
            _ => None,
        })
        .collect())
}

pub fn load_head_removal_evidence_values_chirho(
    root_chirho: &Path,
) -> Result<Vec<serde_json::Value>> {
    load_head_removal_log_entries_chirho(root_chirho)?
        .into_iter()
        .map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::LegacyV1Chirho(record_chirho) => {
                serde_json::to_value(record_chirho).map_err(Into::into)
            }
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::PreparedV2Chirho(record_chirho),
            ) => serde_json::to_value(record_chirho).map_err(Into::into),
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::AppliedV1Chirho(record_chirho),
            ) => serde_json::to_value(record_chirho).map_err(Into::into),
        })
        .collect()
}

pub(crate) fn legacy_head_removal_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<HeadRemovalRecordChirho>> {
    Ok(load_head_removal_log_entries_chirho(root_chirho)?
        .into_iter()
        .filter_map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::LegacyV1Chirho(record_chirho) => Some(record_chirho),
            _ => None,
        })
        .collect())
}

pub(crate) fn verify_head_removal_log_chirho(root_chirho: &Path) -> Result<usize> {
    let entries_chirho = verified_head_removal_log_entries_chirho(root_chirho)?;
    Ok(entries_chirho
        .iter()
        .filter(|entry_chirho| {
            matches!(
                entry_chirho,
                StoredHeadRemovalLogEntryChirho::LegacyV1Chirho(_)
                    | StoredHeadRemovalLogEntryChirho::TransitionChirho(
                        StoredHeadRemovalTransitionEntryChirho::PreparedV2Chirho(_)
                    )
            )
        })
        .count())
}

fn verified_head_removal_log_entries_chirho(
    root_chirho: &Path,
) -> Result<Vec<StoredHeadRemovalLogEntryChirho>> {
    let entries_chirho = load_head_removal_log_entries_chirho(root_chirho)?;
    if entries_chirho.is_empty() {
        return Ok(entries_chirho);
    }
    let root_key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut prepared_chirho = Vec::new();
    let mut applied_chirho = Vec::new();
    for entry_chirho in &entries_chirho {
        match entry_chirho {
            StoredHeadRemovalLogEntryChirho::LegacyV1Chirho(record_chirho) => {
                head_removal_chirho::verify_head_removal_record_signature_with_pubkey_chirho(
                    &root_key_id_chirho,
                    record_chirho,
                )?;
            }
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::PreparedV2Chirho(record_chirho),
            ) => {
                verify_prepared_record_for_root_chirho(
                    root_chirho,
                    &root_key_id_chirho,
                    record_chirho,
                )?;
                prepared_chirho.push(record_chirho);
            }
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::AppliedV1Chirho(record_chirho),
            ) => {
                verify_applied_record_with_pubkey_chirho(&root_key_id_chirho, record_chirho)?;
                applied_chirho.push(record_chirho);
            }
        }
    }
    let mut settled_ids_chirho = BTreeSet::new();
    for receipt_chirho in applied_chirho {
        let mut matching_chirho = Vec::new();
        for prepared_chirho in &prepared_chirho {
            if receipt_chirho.transition_id_chirho == prepared_chirho.transition_id_chirho
                || (receipt_chirho.prepared_removal_seq_chirho == prepared_chirho.seq_chirho
                    && receipt_chirho.prepared_line_digest_chirho
                        == prepared_line_digest_chirho(prepared_chirho)?)
            {
                matching_chirho.push(*prepared_chirho);
            }
        }
        let [prepared_chirho] = matching_chirho.as_slice() else {
            bail!("head removal Applied receipt has missing or ambiguous Prepared evidence");
        };
        verify_applied_against_prepared_record_chirho(receipt_chirho, prepared_chirho)?;
        if !settled_ids_chirho.insert(receipt_chirho.transition_id_chirho.clone()) {
            bail!("head removal transition has duplicate Applied receipts");
        }
    }
    Ok(entries_chirho)
}

fn load_head_removal_log_entries_chirho(
    root_chirho: &Path,
) -> Result<Vec<StoredHeadRemovalLogEntryChirho>> {
    let path_chirho = head_removal_chirho::head_removal_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut entries_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let index_chirho = entries_chirho.len();
        let probe_chirho: HeadRemovalSchemaProbeChirho =
            serde_json::from_str(line_chirho).context("decode head removal schema probe")?;
        if probe_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "head removal seq gap at index {index_chirho}: entry seq is {}",
                probe_chirho.seq_chirho
            );
        }
        let entry_chirho = match probe_chirho.schema_chirho.as_str() {
            head_removal_chirho::HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO => {
                let record_chirho: HeadRemovalRecordChirho = serde_json::from_str(line_chirho)
                    .context("decode legacy head removal record")?;
                head_removal_chirho::verify_head_removal_record_shape_chirho(&record_chirho)?;
                StoredHeadRemovalLogEntryChirho::LegacyV1Chirho(record_chirho)
            }
            HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO => {
                let record_chirho: HeadRemovalPreparedRecordChirho =
                    serde_json::from_str(line_chirho)
                        .context("decode Prepared head removal record")?;
                validate_prepared_record_shape_chirho(&record_chirho)?;
                StoredHeadRemovalLogEntryChirho::TransitionChirho(
                    StoredHeadRemovalTransitionEntryChirho::PreparedV2Chirho(record_chirho),
                )
            }
            HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO => {
                let record_chirho: HeadRemovalAppliedRecordChirho =
                    serde_json::from_str(line_chirho)
                        .context("decode Applied head removal receipt")?;
                validate_applied_record_shape_chirho(&record_chirho)?;
                StoredHeadRemovalLogEntryChirho::TransitionChirho(
                    StoredHeadRemovalTransitionEntryChirho::AppliedV1Chirho(record_chirho),
                )
            }
            schema_chirho => bail!("unsupported head removal log schema '{schema_chirho}'"),
        };
        entries_chirho.push(entry_chirho);
    }
    Ok(entries_chirho)
}

fn append_applied_receipt_unlocked_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadRemovalChirho,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<HeadRemovalAppliedRecordChirho> {
    let key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let path_chirho = head_removal_chirho::head_removal_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = HeadRemovalAppliedRecordChirho {
            seq_chirho,
            schema_chirho: HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO.to_string(),
            transition_id_chirho: prepared_chirho.transition_id_chirho.clone(),
            prepared_removal_seq_chirho: prepared_chirho.prepared_removal_seq_chirho,
            prepared_line_digest_chirho: prepared_chirho.prepared_line_digest_chirho.clone(),
            writer_fence_group_digest_chirho: prepared_chirho
                .writer_fence_group_digest_chirho
                .clone(),
            prepared_writer_fence_epoch_chirho: prepared_chirho.prepared_writer_fence_epoch_chirho,
            applied_writer_fence_epoch_chirho: applier_fence_chirho.epoch_chirho,
            applied_at_ms_chirho: now_ms_chirho(),
            key_id_chirho: key_id_chirho.clone(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
            root_chirho,
            &unsigned_applied_message_chirho(&record_chirho)?,
        )?;
        if signer_chirho::existing_pubkey_hex_chirho(root_chirho)? != key_id_chirho {
            bail!("head removal root key changed while signing Applied evidence");
        }
        Ok(record_chirho)
    })
}

fn verified_applied_receipt_for_prepared_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadRemovalChirho,
) -> Result<Option<HeadRemovalAppliedRecordChirho>> {
    let matching_chirho = verified_head_removal_log_entries_chirho(root_chirho)?
        .into_iter()
        .filter_map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::AppliedV1Chirho(record_chirho),
            ) if record_chirho.transition_id_chirho == prepared_chirho.transition_id_chirho
                || (record_chirho.prepared_removal_seq_chirho
                    == prepared_chirho.prepared_removal_seq_chirho
                    && record_chirho.prepared_line_digest_chirho
                        == prepared_chirho.prepared_line_digest_chirho) =>
            {
                Some(record_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    match matching_chirho.as_slice() {
        [] => Ok(None),
        [receipt_chirho] => {
            verify_applied_against_prepared_witness_chirho(receipt_chirho, prepared_chirho)?;
            Ok(Some(receipt_chirho.clone()))
        }
        _ => bail!("head removal transition has duplicate Applied receipts"),
    }
}

fn verify_prepared_is_recorded_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadRemovalChirho,
) -> Result<()> {
    let matching_chirho = verified_head_removal_log_entries_chirho(root_chirho)?
        .into_iter()
        .filter_map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::PreparedV2Chirho(record_chirho),
            ) if record_chirho.transition_id_chirho == prepared_chirho.transition_id_chirho
                || record_chirho.seq_chirho == prepared_chirho.prepared_removal_seq_chirho =>
            {
                Some(record_chirho)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [record_chirho] = matching_chirho.as_slice() else {
        bail!("head removal Prepared witness has missing or ambiguous persisted evidence");
    };
    if record_chirho.transition_id_chirho != prepared_chirho.transition_id_chirho
        || record_chirho.seq_chirho != prepared_chirho.prepared_removal_seq_chirho
        || prepared_line_digest_chirho(record_chirho)?
            != prepared_chirho.prepared_line_digest_chirho
    {
        bail!("head removal Prepared witness does not match persisted evidence");
    }
    Ok(())
}

fn ensure_no_unapplied_prepared_for_branch_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
) -> Result<()> {
    let entries_chirho = verified_head_removal_log_entries_chirho(root_chirho)?;
    let prepared_chirho = entries_chirho
        .iter()
        .filter_map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::PreparedV2Chirho(record_chirho),
            ) if record_chirho.branch_chirho == branch_chirho => Some(record_chirho),
            _ => None,
        })
        .collect::<Vec<_>>();
    let applied_ids_chirho = entries_chirho
        .iter()
        .filter_map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::AppliedV1Chirho(record_chirho),
            ) => Some(record_chirho.transition_id_chirho.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if prepared_chirho.iter().any(|record_chirho| {
        !applied_ids_chirho.contains(record_chirho.transition_id_chirho.as_str())
    }) {
        bail!("head removal branch already has an unapplied Prepared record");
    }
    Ok(())
}

fn verify_applier_fence_chirho(
    root_chirho: &Path,
    prepared_chirho: &PreparedHeadRemovalChirho,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<()> {
    verify_writer_fence_for_root_chirho(root_chirho, applier_fence_chirho)
        .map_err(anyhow::Error::new)
        .context("head removal applier fence is not current")?;
    let group_digest_chirho = consistency_group_digest_chirho(&applier_fence_chirho.group_chirho)?;
    if group_digest_chirho != prepared_chirho.writer_fence_group_digest_chirho {
        bail!("head removal applier fence belongs to another consistency group");
    }
    if applier_fence_chirho.epoch_chirho < prepared_chirho.prepared_writer_fence_epoch_chirho {
        bail!("head removal applier fence predates the Prepared record");
    }
    Ok(())
}

fn verify_prepared_record_chirho(
    root_chirho: &Path,
    record_chirho: &HeadRemovalPreparedRecordChirho,
) -> Result<()> {
    let root_key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    verify_prepared_record_for_root_chirho(root_chirho, &root_key_id_chirho, record_chirho)
}

fn verify_prepared_record_for_root_chirho(
    root_chirho: &Path,
    root_key_id_chirho: &str,
    record_chirho: &HeadRemovalPreparedRecordChirho,
) -> Result<()> {
    verify_prepared_record_with_pubkey_chirho(root_key_id_chirho, record_chirho)?;
    let expected_group_digest_chirho = consistency_group_digest_chirho(
        &cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho(
            root_chirho,
        )?,
    )?;
    if expected_group_digest_chirho != record_chirho.writer_fence_group_digest_chirho {
        bail!("head removal Prepared record belongs to another consistency group");
    }
    if expected_transition_id_from_record_chirho(record_chirho)?
        != record_chirho.transition_id_chirho
    {
        bail!("head removal transition id does not match the canonical unsigned intent");
    }
    Ok(())
}

fn verify_prepared_record_with_pubkey_chirho(
    root_key_id_chirho: &str,
    record_chirho: &HeadRemovalPreparedRecordChirho,
) -> Result<()> {
    validate_prepared_record_shape_chirho(record_chirho)?;
    if record_chirho.key_id_chirho != root_key_id_chirho {
        bail!("head removal Prepared key is not the root-pinned existing key");
    }
    if !signer_chirho::verify_with_pubkey_chirho(
        root_key_id_chirho,
        &unsigned_prepared_message_chirho(record_chirho)?,
        &record_chirho.sig_chirho,
    )? {
        bail!("head removal Prepared signature invalid");
    }
    Ok(())
}

fn verify_applied_record_with_pubkey_chirho(
    root_key_id_chirho: &str,
    record_chirho: &HeadRemovalAppliedRecordChirho,
) -> Result<()> {
    validate_applied_record_shape_chirho(record_chirho)?;
    if record_chirho.key_id_chirho != root_key_id_chirho {
        bail!("head removal Applied key is not the root-pinned existing key");
    }
    if !signer_chirho::verify_with_pubkey_chirho(
        root_key_id_chirho,
        &unsigned_applied_message_chirho(record_chirho)?,
        &record_chirho.sig_chirho,
    )? {
        bail!("head removal Applied signature invalid");
    }
    Ok(())
}

fn verify_applied_against_prepared_record_chirho(
    applied_chirho: &HeadRemovalAppliedRecordChirho,
    prepared_chirho: &HeadRemovalPreparedRecordChirho,
) -> Result<()> {
    if applied_chirho.transition_id_chirho != prepared_chirho.transition_id_chirho
        || applied_chirho.prepared_removal_seq_chirho != prepared_chirho.seq_chirho
        || applied_chirho.prepared_line_digest_chirho
            != prepared_line_digest_chirho(prepared_chirho)?
        || applied_chirho.writer_fence_group_digest_chirho
            != prepared_chirho.writer_fence_group_digest_chirho
        || applied_chirho.prepared_writer_fence_epoch_chirho
            != prepared_chirho.prepared_writer_fence_epoch_chirho
    {
        bail!("head removal Applied receipt does not match its Prepared record");
    }
    Ok(())
}

fn verify_applied_against_prepared_witness_chirho(
    applied_chirho: &HeadRemovalAppliedRecordChirho,
    prepared_chirho: &PreparedHeadRemovalChirho,
) -> Result<()> {
    if applied_chirho.transition_id_chirho != prepared_chirho.transition_id_chirho
        || applied_chirho.prepared_removal_seq_chirho != prepared_chirho.prepared_removal_seq_chirho
        || applied_chirho.prepared_line_digest_chirho != prepared_chirho.prepared_line_digest_chirho
        || applied_chirho.writer_fence_group_digest_chirho
            != prepared_chirho.writer_fence_group_digest_chirho
        || applied_chirho.prepared_writer_fence_epoch_chirho
            != prepared_chirho.prepared_writer_fence_epoch_chirho
    {
        bail!("head removal Applied receipt does not match the Prepared witness");
    }
    Ok(())
}

fn validate_prepared_input_chirho(
    input_chirho: &HeadRemovalPreparedInputChirho<'_>,
    canonical_signed_domain_line_chirho: &[u8],
) -> Result<()> {
    if canonical_signed_domain_line_chirho.is_empty() {
        bail!("head removal canonical signed domain line must not be empty");
    }
    validate_domain_log_basename_chirho(input_chirho.domain_log_chirho)?;
    if input_chirho.at_ms_chirho == 0 || input_chirho.prepared_fence_chirho.epoch_chirho == 0 {
        bail!("head removal Prepared timestamp and fence epoch must be nonzero");
    }
    validate_labels_chirho(
        input_chirho.branch_chirho,
        input_chirho.app_chirho,
        input_chirho.route_chirho,
        input_chirho.owner_principal_chirho,
    )
}

fn validate_prepared_record_shape_chirho(
    record_chirho: &HeadRemovalPreparedRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO
        || !record_chirho
            .transition_id_chirho
            .starts_with(HEAD_REMOVAL_TRANSITION_ID_PREFIX_CHIRHO)
        || !record_chirho
            .domain_line_digest_chirho
            .starts_with(HEAD_REMOVAL_DOMAIN_LINE_DIGEST_PREFIX_CHIRHO)
        || record_chirho.reason_chirho != HEAD_REMOVAL_REASON_CHIRHO
        || record_chirho.writer_fence_group_digest_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho == 0
        || record_chirho.at_ms_chirho == 0
        || record_chirho.key_id_chirho.is_empty()
        || record_chirho.sig_chirho.is_empty()
    {
        bail!("head removal Prepared record is incomplete");
    }
    validate_domain_log_basename_chirho(&record_chirho.domain_log_chirho)?;
    validate_labels_chirho(
        &record_chirho.branch_chirho,
        &record_chirho.app_chirho,
        record_chirho.route_chirho.as_deref(),
        &record_chirho.owner_principal_chirho,
    )
}

fn validate_applied_record_shape_chirho(
    record_chirho: &HeadRemovalAppliedRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != HEAD_REMOVAL_APPLIED_SCHEMA_CHIRHO
        || !record_chirho
            .transition_id_chirho
            .starts_with(HEAD_REMOVAL_TRANSITION_ID_PREFIX_CHIRHO)
        || !record_chirho
            .prepared_line_digest_chirho
            .starts_with(HEAD_REMOVAL_PREPARED_LINE_DIGEST_PREFIX_CHIRHO)
        || record_chirho.writer_fence_group_digest_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho == 0
        || record_chirho.applied_writer_fence_epoch_chirho
            < record_chirho.prepared_writer_fence_epoch_chirho
        || record_chirho.applied_at_ms_chirho == 0
        || record_chirho.key_id_chirho.is_empty()
        || record_chirho.sig_chirho.is_empty()
    {
        bail!("head removal Applied receipt is incomplete");
    }
    Ok(())
}

fn validate_labels_chirho(
    branch_chirho: &str,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
) -> Result<()> {
    for (label_chirho, value_chirho) in [
        ("branch_chirho", branch_chirho),
        ("app_chirho", app_chirho),
        ("owner_principal_chirho", owner_principal_chirho),
    ] {
        if value_chirho.trim().is_empty() || value_chirho.chars().any(char::is_whitespace) {
            bail!("head removal {label_chirho} must be a non-whitespace token");
        }
    }
    if let Some(route_chirho) = route_chirho {
        if route_chirho.trim().is_empty() || route_chirho.chars().any(char::is_whitespace) {
            bail!("head removal route_chirho must be a non-whitespace token");
        }
    }
    Ok(())
}

fn validate_domain_log_basename_chirho(domain_log_chirho: &str) -> Result<()> {
    let path_chirho = Path::new(domain_log_chirho);
    if path_chirho.components().count() != 1
        || !matches!(path_chirho.components().next(), Some(Component::Normal(_)))
        || !domain_log_chirho.ends_with("-chirho.jsonl")
    {
        bail!("head removal domain log must be a Chirho JSONL basename");
    }
    Ok(())
}

fn derive_transition_id_chirho(
    prepared_removal_seq_chirho: u64,
    input_chirho: &HeadRemovalPreparedInputChirho<'_>,
    route_chirho: &Option<String>,
    domain_line_digest_chirho: &str,
    writer_fence_group_digest_chirho: &str,
) -> Result<String> {
    let message_chirho = serde_json::to_vec(&HeadRemovalTransitionIdentityChirho {
        schema_chirho: HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO,
        prepared_removal_seq_chirho,
        branch_chirho: input_chirho.branch_chirho,
        from_chirho: input_chirho.from_chirho,
        kind_chirho: &input_chirho.kind_chirho,
        app_chirho: input_chirho.app_chirho,
        route_chirho,
        owner_principal_chirho: input_chirho.owner_principal_chirho,
        domain_log_chirho: input_chirho.domain_log_chirho,
        domain_seq_chirho: input_chirho.domain_seq_chirho,
        domain_line_digest_chirho,
        reason_chirho: HEAD_REMOVAL_REASON_CHIRHO,
        writer_fence_group_digest_chirho,
        prepared_writer_fence_epoch_chirho: input_chirho.prepared_fence_chirho.epoch_chirho,
        at_ms_chirho: input_chirho.at_ms_chirho,
    })?;
    Ok(prefixed_hash_chirho(
        HEAD_REMOVAL_TRANSITION_ID_PREFIX_CHIRHO,
        &message_chirho,
    ))
}

fn expected_transition_id_from_record_chirho(
    record_chirho: &HeadRemovalPreparedRecordChirho,
) -> Result<String> {
    let message_chirho = serde_json::to_vec(&HeadRemovalTransitionIdentityChirho {
        schema_chirho: HEAD_REMOVAL_PREPARED_SCHEMA_CHIRHO,
        prepared_removal_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &record_chirho.branch_chirho,
        from_chirho: &record_chirho.from_chirho,
        kind_chirho: &record_chirho.kind_chirho,
        app_chirho: &record_chirho.app_chirho,
        route_chirho: &record_chirho.route_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        domain_log_chirho: &record_chirho.domain_log_chirho,
        domain_seq_chirho: record_chirho.domain_seq_chirho,
        domain_line_digest_chirho: &record_chirho.domain_line_digest_chirho,
        reason_chirho: &record_chirho.reason_chirho,
        writer_fence_group_digest_chirho: &record_chirho.writer_fence_group_digest_chirho,
        prepared_writer_fence_epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?;
    Ok(prefixed_hash_chirho(
        HEAD_REMOVAL_TRANSITION_ID_PREFIX_CHIRHO,
        &message_chirho,
    ))
}

fn prepared_line_digest_chirho(record_chirho: &HeadRemovalPreparedRecordChirho) -> Result<String> {
    Ok(prefixed_hash_chirho(
        HEAD_REMOVAL_PREPARED_LINE_DIGEST_PREFIX_CHIRHO,
        &serde_json::to_vec(record_chirho)?,
    ))
}

fn prefixed_hash_chirho(prefix_chirho: &str, bytes_chirho: &[u8]) -> String {
    let mut message_chirho = Vec::with_capacity(prefix_chirho.len() + 1 + bytes_chirho.len());
    message_chirho.extend_from_slice(prefix_chirho.as_bytes());
    message_chirho.push(0);
    message_chirho.extend_from_slice(bytes_chirho);
    format!(
        "{}{}",
        prefix_chirho,
        cas_chirho::hash_chirho(&message_chirho).0
    )
}

fn unsigned_prepared_message_chirho(
    record_chirho: &HeadRemovalPreparedRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn unsigned_applied_message_chirho(
    record_chirho: &HeadRemovalAppliedRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn recover_head_removal_log_tail_unlocked_chirho(root_chirho: &Path) -> Result<()> {
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(
        &head_removal_chirho::head_removal_records_path_chirho(root_chirho),
    )?;
    Ok(())
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "head_removal_transition_chirho/tests_chirho.rs"]
mod tests_chirho;
