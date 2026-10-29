// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Signed evidence for branch removals.

use anyhow::{bail, Result};
use cairn_core_chirho::{model_chirho::HashChirho, refs_chirho};
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO: &str = "head-removal-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeadRemovalKindChirho {
    AppUndeployChirho,
    AppRouteUndeployChirho,
    ResourcePolicyUnsetChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadRemovalRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub branch_chirho: String,
    pub from_chirho: HashChirho,
    pub kind_chirho: HeadRemovalKindChirho,
    pub app_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_chirho: Option<String>,
    pub owner_principal_chirho: String,
    pub domain_log_chirho: String,
    pub domain_seq_chirho: u64,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub struct HeadRemovalEvidenceInputChirho<'a> {
    pub branch_chirho: &'a str,
    pub from_chirho: &'a HashChirho,
    pub kind_chirho: HeadRemovalKindChirho,
    pub app_chirho: &'a str,
    pub route_chirho: Option<&'a str>,
    pub owner_principal_chirho: &'a str,
    pub domain_log_chirho: &'a str,
    pub domain_seq_chirho: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadRemovalStepChirho {
    AfterDomainRecordChirho,
    AfterRemovalEvidenceChirho,
    AfterBranchRemoveChirho,
}

pub(crate) fn head_removal_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("head-removals-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn current_branch_hash_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
) -> Result<Option<HashChirho>> {
    Ok(refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(branch_chirho)
        .cloned())
}

pub fn append_head_removal_record_unlocked_chirho(
    root_chirho: &Path,
    input_chirho: HeadRemovalEvidenceInputChirho<'_>,
) -> Result<HeadRemovalRecordChirho> {
    validate_head_removal_input_chirho(&input_chirho)?;
    let path_chirho = head_removal_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = HeadRemovalRecordChirho {
            seq_chirho,
            schema_chirho: HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO.to_string(),
            branch_chirho: input_chirho.branch_chirho.to_string(),
            from_chirho: input_chirho.from_chirho.clone(),
            kind_chirho: input_chirho.kind_chirho.clone(),
            app_chirho: input_chirho.app_chirho.to_string(),
            route_chirho: input_chirho.route_chirho.map(str::to_string),
            owner_principal_chirho: input_chirho.owner_principal_chirho.to_string(),
            domain_log_chirho: input_chirho.domain_log_chirho.to_string(),
            domain_seq_chirho: input_chirho.domain_seq_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = head_removal_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

pub fn pending_head_removal_record_chirho(
    root_chirho: &Path,
    input_chirho: HeadRemovalEvidenceInputChirho<'_>,
) -> Result<Option<HeadRemovalRecordChirho>> {
    validate_head_removal_input_chirho(&input_chirho)?;
    let records_chirho = load_head_removal_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(None);
    }
    verify_head_removal_records_chirho(root_chirho)?;
    Ok(records_chirho
        .into_iter()
        .find(|record_chirho| head_removal_record_matches_chirho(record_chirho, &input_chirho)))
}

pub fn remove_branch_after_evidence_chirho(
    root_chirho: &Path,
    record_chirho: &HeadRemovalRecordChirho,
) -> Result<bool> {
    verify_head_removal_record_signature_chirho(root_chirho, record_chirho)?;
    remove_branch_if_current_chirho(
        root_chirho,
        &record_chirho.branch_chirho,
        &record_chirho.from_chirho,
    )
}

pub(crate) fn remove_branch_if_current_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    from_chirho: &HashChirho,
) -> Result<bool> {
    let current_chirho = current_branch_hash_chirho(root_chirho, branch_chirho)?;
    let Some(current_chirho) = current_chirho else {
        return Ok(false);
    };
    if current_chirho != *from_chirho {
        bail!(
            "branch '{}' moved from signed removal head {} to {}; re-derive removal evidence",
            branch_chirho,
            from_chirho.0,
            current_chirho.0
        );
    }
    refs_chirho::remove_branch_chirho(root_chirho, branch_chirho)
}

pub fn load_head_removal_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<HeadRemovalRecordChirho>> {
    crate::head_removal_transition_chirho::legacy_head_removal_records_chirho(root_chirho)
}

pub fn verify_head_removal_records_chirho(root_chirho: &Path) -> Result<usize> {
    crate::head_removal_transition_chirho::verify_head_removal_log_chirho(root_chirho)
}

pub fn maybe_fail_head_removal_step_chirho(
    _root_chirho: &Path,
    _step_chirho: HeadRemovalStepChirho,
) -> Result<()> {
    #[cfg(any(test, feature = "test-hooks-chirho"))]
    {
        let mut failpoints_chirho = HEAD_REMOVAL_FAILPOINT_CHIRHO.lock().unwrap();
        if failpoints_chirho.get(_root_chirho) == Some(&_step_chirho) {
            failpoints_chirho.remove(_root_chirho);
            bail!("injected head removal failure at {_step_chirho:?}");
        }
    }
    Ok(())
}

fn head_removal_record_matches_chirho(
    record_chirho: &HeadRemovalRecordChirho,
    input_chirho: &HeadRemovalEvidenceInputChirho<'_>,
) -> bool {
    record_chirho.branch_chirho == input_chirho.branch_chirho
        && record_chirho.from_chirho == *input_chirho.from_chirho
        && record_chirho.kind_chirho == input_chirho.kind_chirho
        && record_chirho.app_chirho == input_chirho.app_chirho
        && record_chirho.route_chirho.as_deref() == input_chirho.route_chirho
        && record_chirho.owner_principal_chirho == input_chirho.owner_principal_chirho
        && record_chirho.domain_log_chirho == input_chirho.domain_log_chirho
}

fn validate_head_removal_input_chirho(
    input_chirho: &HeadRemovalEvidenceInputChirho<'_>,
) -> Result<()> {
    if input_chirho.branch_chirho.trim().is_empty()
        || input_chirho.branch_chirho.chars().any(char::is_whitespace)
    {
        bail!("head removal branch_chirho must be a non-whitespace token");
    }
    if input_chirho.app_chirho.trim().is_empty()
        || input_chirho.app_chirho.chars().any(char::is_whitespace)
    {
        bail!("head removal app_chirho must be a non-whitespace token");
    }
    if let Some(route_chirho) = input_chirho.route_chirho {
        if route_chirho.trim().is_empty() || route_chirho.chars().any(char::is_whitespace) {
            bail!("head removal route_chirho must be a non-whitespace token");
        }
    }
    if input_chirho.owner_principal_chirho.trim().is_empty()
        || input_chirho
            .owner_principal_chirho
            .chars()
            .any(char::is_whitespace)
    {
        bail!("head removal owner_principal_chirho must be a non-whitespace token");
    }
    if input_chirho.domain_log_chirho.trim().is_empty()
        || !input_chirho.domain_log_chirho.ends_with("-chirho.jsonl")
    {
        bail!("head removal domain_log_chirho must name a Chirho JSONL log");
    }
    Ok(())
}

pub(crate) fn verify_head_removal_record_shape_chirho(
    record_chirho: &HeadRemovalRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != HEAD_REMOVAL_RECORD_SCHEMA_CHIRHO {
        bail!(
            "unsupported head removal record schema '{}' at seq {}",
            record_chirho.schema_chirho,
            record_chirho.seq_chirho
        );
    }
    validate_head_removal_input_chirho(&HeadRemovalEvidenceInputChirho {
        branch_chirho: &record_chirho.branch_chirho,
        from_chirho: &record_chirho.from_chirho,
        kind_chirho: record_chirho.kind_chirho.clone(),
        app_chirho: &record_chirho.app_chirho,
        route_chirho: record_chirho.route_chirho.as_deref(),
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        domain_log_chirho: &record_chirho.domain_log_chirho,
        domain_seq_chirho: record_chirho.domain_seq_chirho,
    })?;
    Ok(())
}

fn verify_head_removal_record_signature_chirho(
    root_chirho: &Path,
    record_chirho: &HeadRemovalRecordChirho,
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    verify_head_removal_record_signature_with_pubkey_chirho(&pubkey_chirho, record_chirho)
}

pub(crate) fn verify_head_removal_record_signature_with_pubkey_chirho(
    pubkey_chirho: &str,
    record_chirho: &HeadRemovalRecordChirho,
) -> Result<()> {
    verify_head_removal_record_shape_chirho(record_chirho)?;
    let message_chirho = head_removal_record_message_chirho(record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "head removal record {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

pub(crate) fn head_removal_record_message_chirho(
    record_chirho: &HeadRemovalRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
static HEAD_REMOVAL_FAILPOINT_CHIRHO: std::sync::Mutex<
    std::collections::BTreeMap<PathBuf, HeadRemovalStepChirho>,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

#[cfg(any(test, feature = "test-hooks-chirho"))]
pub fn set_head_removal_failpoint_chirho(root_chirho: &Path, step_chirho: HeadRemovalStepChirho) {
    HEAD_REMOVAL_FAILPOINT_CHIRHO
        .lock()
        .unwrap()
        .insert(root_chirho.to_path_buf(), step_chirho);
}

#[cfg(test)]
#[path = "head_removal_chirho/tests_chirho.rs"]
mod tests_chirho;
