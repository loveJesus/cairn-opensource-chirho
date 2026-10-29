// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure Gate 1 evidence record models.

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const GATE1_LOG_ANCHORS_FILE_CHIRHO: &str = "gate1-log-anchors-chirho.jsonl";
pub const GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO: &str = "gate1-log-anchor-record-v1-chirho";
pub const GATE1_ANCHOR_HEAD_REPLICATION_RECORD_SCHEMA_CHIRHO: &str =
    "gate1-anchor-head-replication-record-v1-chirho";
pub const GATE1_AUTHORITY_LOG_FILE_CHIRHO: &str = "gate1-authority-log-chirho.jsonl";
pub const GATE1_AUTHORITY_HEAD_DIR_CHIRHO: &str = "gate1-authority-head-chirho";
pub const GATE1_AUTHORITY_HEAD_FILE_CHIRHO: &str = "head-chirho.json";
pub const GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO: &str = "gate1-authority-log-record-v1-chirho";
pub const GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO: &str = "gate1-authority-head-v1-chirho";
pub const GATE1_AUTHORITY_MODE_RECORD_SCHEMA_CHIRHO: &str = "gate1-authority-mode-record-v1-chirho";
pub const GATE1_AUTHORITY_MODE_BRANCH_CHIRHO: &str = "gate1-authority-mode-chirho";
pub const GATE1_AUTHORITY_MODE_OLD_ROAD_CHIRHO: &str = "old-road-chirho";
pub const GATE1_AUTHORITY_MODE_AUTHORITY_LOG_CHIRHO: &str = "authority-log-chirho";
pub const GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO: &str = "gate1-authority-record-v1-chirho:";
pub const GATE1_AUTHORITY_FAMILY_LINE_DIGEST_PREFIX_CHIRHO: &str =
    "gate1-authority-family-line-v1-chirho:";
pub const GATE1_LEDGER_FAMILY_CHIRHO: &str = "ledger-chirho.jsonl";
pub const GATE1_CREDIT_HOLDS_FAMILY_CHIRHO: &str = "credit-holds-chirho.jsonl";
pub const GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO: &str = "resource-policy-records-chirho.jsonl";
pub const GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO: &str =
    "resource-policy-unset-records-chirho.jsonl";
pub const GATE1_RESOURCE_USAGE_FAMILY_CHIRHO: &str = "resource-usage-chirho.jsonl";
pub const GATE1_BILLING_POLICIES_FAMILY_CHIRHO: &str = "billing-policy-records-chirho.jsonl";
pub const GATE1_BILLING_USAGE_FAMILY_CHIRHO: &str = "billing-usage-chirho.jsonl";
pub const GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO: &str = "billing-compensations-chirho.jsonl";

pub const GATE1_RING_A_SEMANTIC_GROUPS_CHIRHO: [&str; 4] = [
    "ledger-chirho",
    "holds-chirho",
    "resources-chirho",
    "billing-chirho",
];

pub const GATE1_RING_A_ANCHOR_TARGETS_CHIRHO: [&str; 8] = [
    GATE1_LEDGER_FAMILY_CHIRHO,
    GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
    GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
    GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
    GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
    GATE1_BILLING_POLICIES_FAMILY_CHIRHO,
    GATE1_BILLING_USAGE_FAMILY_CHIRHO,
    GATE1_BILLING_COMPENSATIONS_FAMILY_CHIRHO,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1LogAnchorRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub family_chirho: String,
    pub line_count_chirho: u64,
    pub prefix_digest_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_digest_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_anchor_hash_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1AnchorHeadReplicationRecordChirho {
    pub schema_chirho: String,
    pub anchor_log_file_chirho: String,
    pub anchor_record_count_chirho: u64,
    pub anchor_prefix_digest_chirho: HashChirho,
    pub physical_target_count_chirho: u64,
    pub semantic_group_count_chirho: u64,
    pub at_ms_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1AuthorityLogRecordChirho {
    pub schema_chirho: String,
    pub authority_seq_chirho: u64,
    pub family_chirho: String,
    pub family_seq_chirho: u64,
    pub family_line_digest_chirho: String,
    pub family_line_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_authority_record_digest_chirho: Option<String>,
    pub writer_fence_epoch_chirho: u64,
    pub at_ms_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1AuthorityHeadChirho {
    pub schema_chirho: String,
    pub authority_log_file_chirho: String,
    pub next_authority_seq_chirho: u64,
    pub authority_log_len_bytes_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_authority_record_digest_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub family_watermarks_chirho: Vec<Gate1AuthorityFamilyWatermarkChirho>,
    pub writer_fence_epoch_chirho: u64,
    pub updated_at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1AuthorityFamilyWatermarkChirho {
    pub family_chirho: String,
    pub next_family_seq_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_family_line_digest_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1AuthorityModeGroupDigestChirho {
    pub group_chirho: String,
    pub live_verified_clsd_digest_chirho: String,
    pub authority_log_clsd_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate1AuthorityModeRecordChirho {
    pub schema_chirho: String,
    pub mode_chirho: String,
    pub checkpoint_status_chirho: String,
    pub checkpoint_report_hash_chirho: HashChirho,
    pub checkpoint_group_digests_chirho: Vec<Gate1AuthorityModeGroupDigestChirho>,
    pub reason_chirho: String,
    pub at_ms_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

pub fn unsigned_gate1_log_anchor_message_chirho(
    record_chirho: &Gate1LogAnchorRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

pub fn canonical_gate1_log_anchor_line_chirho(
    record_chirho: &Gate1LogAnchorRecordChirho,
) -> Result<String> {
    Ok(serde_json::to_string(record_chirho)?)
}

pub fn gate1_anchor_line_hash_chirho(
    record_chirho: &Gate1LogAnchorRecordChirho,
) -> Result<HashChirho> {
    let line_chirho = canonical_gate1_log_anchor_line_chirho(record_chirho)?;
    Ok(HashChirho(
        blake3::hash(line_chirho.as_bytes()).to_hex().to_string(),
    ))
}

pub fn unsigned_gate1_anchor_head_replication_message_chirho(
    record_chirho: &Gate1AnchorHeadReplicationRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

pub fn canonical_gate1_anchor_head_replication_json_chirho(
    record_chirho: &Gate1AnchorHeadReplicationRecordChirho,
) -> Result<String> {
    Ok(serde_json::to_string(record_chirho)?)
}

pub fn canonical_gate1_authority_record_json_chirho(
    record_chirho: &Gate1AuthorityLogRecordChirho,
) -> Result<String> {
    Ok(serde_json::to_string(record_chirho)?)
}

pub fn unsigned_gate1_authority_record_message_chirho(
    record_chirho: &Gate1AuthorityLogRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

pub fn unsigned_gate1_authority_mode_message_chirho(
    record_chirho: &Gate1AuthorityModeRecordChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

pub fn canonical_gate1_authority_mode_json_chirho(
    record_chirho: &Gate1AuthorityModeRecordChirho,
) -> Result<String> {
    Ok(serde_json::to_string(record_chirho)?)
}

pub fn canonical_gate1_authority_head_json_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
) -> Result<String> {
    Ok(serde_json::to_string(head_chirho)?)
}

pub fn prefixed_gate1_digest_for_bytes_chirho(prefix_chirho: &str, bytes_chirho: &[u8]) -> String {
    format!("{}{}", prefix_chirho, blake3::hash(bytes_chirho).to_hex())
}

pub fn gate1_authority_record_digest_chirho(
    record_chirho: &Gate1AuthorityLogRecordChirho,
) -> Result<String> {
    let json_chirho = canonical_gate1_authority_record_json_chirho(record_chirho)?;
    Ok(prefixed_gate1_digest_for_bytes_chirho(
        GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO,
        json_chirho.as_bytes(),
    ))
}

pub fn gate1_authority_family_line_digest_chirho(family_line_chirho: &str) -> String {
    prefixed_gate1_digest_for_bytes_chirho(
        GATE1_AUTHORITY_FAMILY_LINE_DIGEST_PREFIX_CHIRHO,
        family_line_chirho.as_bytes(),
    )
}

pub fn parse_canonical_gate1_authority_record_chirho(
    text_chirho: &str,
) -> Result<Gate1AuthorityLogRecordChirho> {
    let trimmed_chirho = text_chirho.trim();
    let record_chirho: Gate1AuthorityLogRecordChirho = serde_json::from_str(trimmed_chirho)?;
    let canonical_chirho = canonical_gate1_authority_record_json_chirho(&record_chirho)?;
    if canonical_chirho != trimmed_chirho {
        bail!("gate1 authority record canonical byte mismatch");
    }
    validate_gate1_authority_record_chirho(&record_chirho)?;
    Ok(record_chirho)
}

pub fn parse_canonical_gate1_authority_head_chirho(
    text_chirho: &str,
) -> Result<Gate1AuthorityHeadChirho> {
    let trimmed_chirho = text_chirho.trim();
    let head_chirho: Gate1AuthorityHeadChirho = serde_json::from_str(trimmed_chirho)?;
    let canonical_chirho = canonical_gate1_authority_head_json_chirho(&head_chirho)?;
    if canonical_chirho != trimmed_chirho {
        bail!("gate1 authority head canonical byte mismatch");
    }
    validate_gate1_authority_head_chirho(&head_chirho)?;
    Ok(head_chirho)
}

pub fn parse_canonical_gate1_anchor_head_replication_record_chirho(
    text_chirho: &str,
) -> Result<Gate1AnchorHeadReplicationRecordChirho> {
    let trimmed_chirho = text_chirho.trim();
    let record_chirho: Gate1AnchorHeadReplicationRecordChirho =
        serde_json::from_str(trimmed_chirho)?;
    let canonical_chirho = canonical_gate1_anchor_head_replication_json_chirho(&record_chirho)?;
    if canonical_chirho != trimmed_chirho {
        bail!("gate1 anchor head canonical byte mismatch");
    }
    validate_gate1_anchor_head_replication_record_chirho(&record_chirho)?;
    Ok(record_chirho)
}

pub fn validate_gate1_log_anchor_record_chirho(
    record_chirho: &Gate1LogAnchorRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO {
        bail!(
            "gate1 anchor unsupported schema_chirho '{}', expected '{}'",
            record_chirho.schema_chirho,
            GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO
        );
    }
    if record_chirho.family_chirho.trim().is_empty() {
        bail!("gate1 anchor family_chirho must not be empty");
    }
    if !record_chirho.family_chirho.ends_with(".jsonl") {
        bail!("gate1 anchor family_chirho must name a jsonl surface");
    }
    validate_hash_shape_chirho("prefix_digest_chirho", &record_chirho.prefix_digest_chirho)?;
    if let Some(state_digest_chirho) = &record_chirho.state_digest_chirho {
        validate_hash_shape_chirho("state_digest_chirho", state_digest_chirho)?;
    }
    if let Some(prev_anchor_hash_chirho) = &record_chirho.prev_anchor_hash_chirho {
        validate_hash_shape_chirho("prev_anchor_hash_chirho", prev_anchor_hash_chirho)?;
    }
    if record_chirho.key_id_chirho.trim().is_empty() {
        bail!("gate1 anchor key_id_chirho must not be empty");
    }
    if record_chirho.sig_chirho.trim().is_empty() {
        bail!("gate1 anchor sig_chirho must not be empty");
    }
    Ok(())
}

pub fn validate_gate1_anchor_head_replication_record_chirho(
    record_chirho: &Gate1AnchorHeadReplicationRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != GATE1_ANCHOR_HEAD_REPLICATION_RECORD_SCHEMA_CHIRHO {
        bail!(
            "gate1 anchor head unsupported schema_chirho '{}', expected '{}'",
            record_chirho.schema_chirho,
            GATE1_ANCHOR_HEAD_REPLICATION_RECORD_SCHEMA_CHIRHO
        );
    }
    if record_chirho.anchor_log_file_chirho != GATE1_LOG_ANCHORS_FILE_CHIRHO {
        bail!(
            "gate1 anchor head anchor_log_file_chirho must be '{}'",
            GATE1_LOG_ANCHORS_FILE_CHIRHO
        );
    }
    if record_chirho.anchor_record_count_chirho == 0 {
        bail!("gate1 anchor head anchor_record_count_chirho must be positive");
    }
    validate_hash_shape_chirho(
        "anchor_prefix_digest_chirho",
        &record_chirho.anchor_prefix_digest_chirho,
    )?;
    if record_chirho.physical_target_count_chirho != GATE1_RING_A_ANCHOR_TARGETS_CHIRHO.len() as u64
    {
        bail!("gate1 anchor head physical_target_count_chirho must match Ring A targets");
    }
    if record_chirho.semantic_group_count_chirho != GATE1_RING_A_SEMANTIC_GROUPS_CHIRHO.len() as u64
    {
        bail!("gate1 anchor head semantic_group_count_chirho must match Ring A groups");
    }
    if record_chirho.key_id_chirho.trim().is_empty() {
        bail!("gate1 anchor head key_id_chirho must not be empty");
    }
    if record_chirho.sig_chirho.trim().is_empty() {
        bail!("gate1 anchor head sig_chirho must not be empty");
    }
    Ok(())
}

pub fn validate_gate1_authority_record_chirho(
    record_chirho: &Gate1AuthorityLogRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO {
        bail!(
            "gate1 authority unsupported schema_chirho '{}', expected '{}'",
            record_chirho.schema_chirho,
            GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO
        );
    }
    validate_gate1_family_chirho(&record_chirho.family_chirho)?;
    if record_chirho.family_line_chirho.trim().is_empty() {
        bail!("gate1 authority family_line_chirho must not be empty");
    }
    let expected_family_digest_chirho =
        gate1_authority_family_line_digest_chirho(&record_chirho.family_line_chirho);
    if record_chirho.family_line_digest_chirho != expected_family_digest_chirho {
        bail!("gate1 authority family_line_digest_chirho mismatch");
    }
    validate_prefixed_digest_chirho(
        "family_line_digest_chirho",
        &record_chirho.family_line_digest_chirho,
        GATE1_AUTHORITY_FAMILY_LINE_DIGEST_PREFIX_CHIRHO,
    )?;
    if let Some(prev_chirho) = &record_chirho.prev_authority_record_digest_chirho {
        validate_prefixed_digest_chirho(
            "prev_authority_record_digest_chirho",
            prev_chirho,
            GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO,
        )?;
    }
    if record_chirho.writer_fence_epoch_chirho == 0 {
        bail!("gate1 authority writer_fence_epoch_chirho must be positive");
    }
    if record_chirho.key_id_chirho.trim().is_empty() {
        bail!("gate1 authority key_id_chirho must not be empty");
    }
    if record_chirho.sig_chirho.trim().is_empty() {
        bail!("gate1 authority sig_chirho must not be empty");
    }
    Ok(())
}

pub fn validate_gate1_authority_head_chirho(head_chirho: &Gate1AuthorityHeadChirho) -> Result<()> {
    if head_chirho.schema_chirho != GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO {
        bail!(
            "gate1 authority head unsupported schema_chirho '{}', expected '{}'",
            head_chirho.schema_chirho,
            GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO
        );
    }
    if head_chirho.authority_log_file_chirho != GATE1_AUTHORITY_LOG_FILE_CHIRHO {
        bail!(
            "gate1 authority head authority_log_file_chirho must be '{}'",
            GATE1_AUTHORITY_LOG_FILE_CHIRHO
        );
    }
    if let Some(last_chirho) = &head_chirho.last_authority_record_digest_chirho {
        validate_prefixed_digest_chirho(
            "last_authority_record_digest_chirho",
            last_chirho,
            GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO,
        )?;
    }
    if head_chirho.next_authority_seq_chirho == 0
        && head_chirho.last_authority_record_digest_chirho.is_some()
    {
        bail!("gate1 authority head cannot have a last digest at seq zero");
    }
    if head_chirho.next_authority_seq_chirho == 0 && head_chirho.authority_log_len_bytes_chirho != 0
    {
        bail!("gate1 authority head cannot point at log bytes at seq zero");
    }
    if head_chirho.next_authority_seq_chirho > 0
        && head_chirho.last_authority_record_digest_chirho.is_none()
    {
        bail!("gate1 authority head requires last digest when seq is positive");
    }
    if head_chirho.next_authority_seq_chirho > 0 && head_chirho.authority_log_len_bytes_chirho == 0
    {
        bail!("gate1 authority head requires log bytes when seq is positive");
    }
    let mut seen_family_chirho = BTreeSet::new();
    for watermark_chirho in &head_chirho.family_watermarks_chirho {
        validate_gate1_family_chirho(&watermark_chirho.family_chirho)?;
        if !seen_family_chirho.insert(watermark_chirho.family_chirho.clone()) {
            bail!(
                "gate1 authority head has duplicate family watermark '{}'",
                watermark_chirho.family_chirho
            );
        }
        if let Some(last_chirho) = &watermark_chirho.last_family_line_digest_chirho {
            validate_prefixed_digest_chirho(
                "last_family_line_digest_chirho",
                last_chirho,
                GATE1_AUTHORITY_FAMILY_LINE_DIGEST_PREFIX_CHIRHO,
            )?;
        }
        if watermark_chirho.next_family_seq_chirho == 0
            && watermark_chirho.last_family_line_digest_chirho.is_some()
        {
            bail!("gate1 authority family watermark cannot have a last digest at seq zero");
        }
        if watermark_chirho.next_family_seq_chirho > 0
            && watermark_chirho.last_family_line_digest_chirho.is_none()
        {
            bail!("gate1 authority family watermark requires last digest when seq is positive");
        }
    }
    if head_chirho.writer_fence_epoch_chirho == 0 {
        bail!("gate1 authority head writer_fence_epoch_chirho must be positive");
    }
    Ok(())
}

pub fn validate_gate1_authority_mode_record_chirho(
    record_chirho: &Gate1AuthorityModeRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho != GATE1_AUTHORITY_MODE_RECORD_SCHEMA_CHIRHO {
        bail!(
            "gate1 authority mode unsupported schema_chirho '{}', expected '{}'",
            record_chirho.schema_chirho,
            GATE1_AUTHORITY_MODE_RECORD_SCHEMA_CHIRHO
        );
    }
    match record_chirho.mode_chirho.as_str() {
        GATE1_AUTHORITY_MODE_OLD_ROAD_CHIRHO | GATE1_AUTHORITY_MODE_AUTHORITY_LOG_CHIRHO => {}
        other_chirho => bail!("unsupported gate1 authority mode '{other_chirho}'"),
    }
    if record_chirho.checkpoint_status_chirho.trim().is_empty() {
        bail!("gate1 authority mode checkpoint_status_chirho must not be empty");
    }
    validate_hash_shape_chirho(
        "checkpoint_report_hash_chirho",
        &record_chirho.checkpoint_report_hash_chirho,
    )?;
    if record_chirho.mode_chirho == GATE1_AUTHORITY_MODE_AUTHORITY_LOG_CHIRHO
        && record_chirho.checkpoint_group_digests_chirho.len()
            != GATE1_RING_A_SEMANTIC_GROUPS_CHIRHO.len()
    {
        bail!("authority-log mode must bind every Ring-A semantic group digest");
    }
    let mut seen_groups_chirho = BTreeSet::new();
    for digest_chirho in &record_chirho.checkpoint_group_digests_chirho {
        if !seen_groups_chirho.insert(digest_chirho.group_chirho.clone()) {
            bail!(
                "gate1 authority mode duplicated group {}",
                digest_chirho.group_chirho
            );
        }
        if !GATE1_RING_A_SEMANTIC_GROUPS_CHIRHO.contains(&digest_chirho.group_chirho.as_str()) {
            bail!(
                "gate1 authority mode unknown group {}",
                digest_chirho.group_chirho
            );
        }
        validate_hash_shape_chirho(
            "live_verified_clsd_digest_chirho",
            &HashChirho(digest_chirho.live_verified_clsd_digest_chirho.clone()),
        )?;
        validate_hash_shape_chirho(
            "authority_log_clsd_digest_chirho",
            &HashChirho(digest_chirho.authority_log_clsd_digest_chirho.clone()),
        )?;
    }
    if record_chirho.reason_chirho.trim().is_empty() {
        bail!("gate1 authority mode reason_chirho must not be empty");
    }
    if record_chirho.key_id_chirho.trim().is_empty() {
        bail!("gate1 authority mode key_id_chirho must not be empty");
    }
    if record_chirho.sig_chirho.trim().is_empty() {
        bail!("gate1 authority mode sig_chirho must not be empty");
    }
    Ok(())
}

fn validate_hash_shape_chirho(label_chirho: &str, hash_chirho: &HashChirho) -> Result<()> {
    let value_chirho = &hash_chirho.0;
    if value_chirho.len() != 64
        || !value_chirho
            .chars()
            .all(|char_chirho| char_chirho.is_ascii_hexdigit())
    {
        bail!("gate1 anchor {label_chirho} must be 64 hex characters");
    }
    Ok(())
}

fn validate_gate1_family_chirho(family_chirho: &str) -> Result<()> {
    if !GATE1_RING_A_ANCHOR_TARGETS_CHIRHO.contains(&family_chirho) {
        bail!("gate1 authority family_chirho must be a reviewed Ring A family");
    }
    Ok(())
}

fn validate_prefixed_digest_chirho(
    label_chirho: &str,
    digest_chirho: &str,
    prefix_chirho: &str,
) -> Result<()> {
    let Some(hex_chirho) = digest_chirho.strip_prefix(prefix_chirho) else {
        bail!("{label_chirho} must start with '{prefix_chirho}'");
    };
    if hex_chirho.len() != 64
        || !hex_chirho
            .chars()
            .all(|char_chirho| char_chirho.is_ascii_hexdigit())
    {
        bail!("{label_chirho} must end with 64 hex characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn hash_chirho(seed_chirho: char) -> HashChirho {
        HashChirho(seed_chirho.to_string().repeat(64))
    }

    fn anchor_chirho() -> Gate1LogAnchorRecordChirho {
        Gate1LogAnchorRecordChirho {
            schema_chirho: GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: 0,
            family_chirho: GATE1_LEDGER_FAMILY_CHIRHO.to_string(),
            line_count_chirho: 3,
            prefix_digest_chirho: hash_chirho('a'),
            state_digest_chirho: None,
            prev_anchor_hash_chirho: None,
            at_ms_chirho: 123,
            key_id_chirho: "k".repeat(64),
            sig_chirho: "s".repeat(128),
        }
    }

    fn anchor_head_chirho() -> Gate1AnchorHeadReplicationRecordChirho {
        Gate1AnchorHeadReplicationRecordChirho {
            schema_chirho: GATE1_ANCHOR_HEAD_REPLICATION_RECORD_SCHEMA_CHIRHO.to_string(),
            anchor_log_file_chirho: GATE1_LOG_ANCHORS_FILE_CHIRHO.to_string(),
            anchor_record_count_chirho: 10,
            anchor_prefix_digest_chirho: hash_chirho('b'),
            physical_target_count_chirho: GATE1_RING_A_ANCHOR_TARGETS_CHIRHO.len() as u64,
            semantic_group_count_chirho: GATE1_RING_A_SEMANTIC_GROUPS_CHIRHO.len() as u64,
            at_ms_chirho: 456,
            key_id_chirho: "k".repeat(64),
            sig_chirho: "s".repeat(128),
        }
    }

    #[test]
    fn unsigned_anchor_message_clears_signature_only_chirho() {
        let anchor_chirho = anchor_chirho();
        let message_chirho = unsigned_gate1_log_anchor_message_chirho(&anchor_chirho).unwrap();
        let value_chirho: serde_json::Value = serde_json::from_slice(&message_chirho).unwrap();
        assert_eq!(value_chirho["sig_chirho"], "");
        assert_eq!(value_chirho["family_chirho"], GATE1_LEDGER_FAMILY_CHIRHO);
    }

    #[test]
    fn state_digest_none_is_omitted_from_canonical_line_chirho() {
        let line_chirho = canonical_gate1_log_anchor_line_chirho(&anchor_chirho()).unwrap();
        assert!(!line_chirho.contains("state_digest_chirho"));
    }

    #[test]
    fn schema_v1_is_required_from_birth_chirho() {
        let mut anchor_chirho = anchor_chirho();
        anchor_chirho.schema_chirho.clear();
        let error_chirho = validate_gate1_log_anchor_record_chirho(&anchor_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("unsupported schema_chirho"));
    }

    #[test]
    fn unsigned_anchor_head_message_clears_signature_only_chirho() {
        let anchor_head_chirho = anchor_head_chirho();
        let message_chirho =
            unsigned_gate1_anchor_head_replication_message_chirho(&anchor_head_chirho).unwrap();
        let value_chirho: serde_json::Value = serde_json::from_slice(&message_chirho).unwrap();
        assert_eq!(value_chirho["sig_chirho"], "");
        assert_eq!(
            value_chirho["anchor_log_file_chirho"],
            GATE1_LOG_ANCHORS_FILE_CHIRHO
        );
    }

    #[test]
    fn anchor_head_canonical_parse_rejects_unknown_keys_chirho() {
        let json_chirho =
            canonical_gate1_anchor_head_replication_json_chirho(&anchor_head_chirho()).unwrap();
        let with_extra_chirho =
            json_chirho.replace("\"sig_chirho\"", "\"extra_chirho\":true,\"sig_chirho\"");
        let error_chirho =
            parse_canonical_gate1_anchor_head_replication_record_chirho(&with_extra_chirho)
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains("canonical byte mismatch"));
    }

    #[test]
    fn anchor_head_refuses_zero_count_attestations_chirho() {
        let mut record_chirho = anchor_head_chirho();
        record_chirho.anchor_record_count_chirho = 0;
        let error_chirho = validate_gate1_anchor_head_replication_record_chirho(&record_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("must be positive"));
    }

    fn authority_record_chirho() -> Gate1AuthorityLogRecordChirho {
        let family_line_chirho = "{\"seq_chirho\":0,\"amount_chirho\":7}".to_string();
        Gate1AuthorityLogRecordChirho {
            schema_chirho: GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO.to_string(),
            authority_seq_chirho: 0,
            family_chirho: GATE1_LEDGER_FAMILY_CHIRHO.to_string(),
            family_seq_chirho: 0,
            family_line_digest_chirho: gate1_authority_family_line_digest_chirho(
                &family_line_chirho,
            ),
            family_line_chirho,
            prev_authority_record_digest_chirho: None,
            writer_fence_epoch_chirho: 1,
            at_ms_chirho: 999,
            key_id_chirho: "test-authority-key-chirho".to_string(),
            sig_chirho: "test-authority-sig-chirho".to_string(),
        }
    }

    fn authority_head_chirho(
        record_chirho: &Gate1AuthorityLogRecordChirho,
    ) -> Gate1AuthorityHeadChirho {
        Gate1AuthorityHeadChirho {
            schema_chirho: GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO.to_string(),
            authority_log_file_chirho: GATE1_AUTHORITY_LOG_FILE_CHIRHO.to_string(),
            next_authority_seq_chirho: 1,
            authority_log_len_bytes_chirho: 128,
            last_authority_record_digest_chirho: Some(
                gate1_authority_record_digest_chirho(record_chirho).unwrap(),
            ),
            family_watermarks_chirho: vec![Gate1AuthorityFamilyWatermarkChirho {
                family_chirho: record_chirho.family_chirho.clone(),
                next_family_seq_chirho: record_chirho.family_seq_chirho + 1,
                last_family_line_digest_chirho: Some(
                    record_chirho.family_line_digest_chirho.clone(),
                ),
            }],
            writer_fence_epoch_chirho: 1,
            updated_at_ms_chirho: 1000,
        }
    }

    #[test]
    fn authority_record_uses_prefixed_family_digest_chirho() {
        let record_chirho = authority_record_chirho();
        assert!(record_chirho
            .family_line_digest_chirho
            .starts_with(GATE1_AUTHORITY_FAMILY_LINE_DIGEST_PREFIX_CHIRHO));
        assert!(validate_gate1_authority_record_chirho(&record_chirho).is_ok());
    }

    #[test]
    fn authority_record_rejects_bare_or_mismatched_digest_chirho() {
        let mut record_chirho = authority_record_chirho();
        record_chirho.family_line_digest_chirho = "a".repeat(64);
        let error_chirho = validate_gate1_authority_record_chirho(&record_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("family_line_digest_chirho mismatch"));

        let mut chained_chirho = authority_record_chirho();
        chained_chirho.prev_authority_record_digest_chirho = Some(format!(
            "{}{}",
            GATE1_AUTHORITY_FAMILY_LINE_DIGEST_PREFIX_CHIRHO,
            "b".repeat(64)
        ));
        let error_chirho = validate_gate1_authority_record_chirho(&chained_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("prev_authority_record_digest_chirho"));
    }

    #[test]
    fn authority_record_canonical_parse_rejects_unknown_keys_chirho() {
        let json_chirho =
            canonical_gate1_authority_record_json_chirho(&authority_record_chirho()).unwrap();
        let with_extra_chirho =
            json_chirho.replace("\"at_ms_chirho\"", "\"extra_chirho\":true,\"at_ms_chirho\"");
        let error_chirho = parse_canonical_gate1_authority_record_chirho(&with_extra_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("canonical byte mismatch"));
    }

    #[test]
    fn authority_head_requires_prefixed_last_digest_chirho() {
        let record_chirho = authority_record_chirho();
        let mut head_chirho = authority_head_chirho(&record_chirho);
        assert!(validate_gate1_authority_head_chirho(&head_chirho).is_ok());

        head_chirho.last_authority_record_digest_chirho = Some("c".repeat(64));
        let error_chirho = validate_gate1_authority_head_chirho(&head_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("last_authority_record_digest_chirho"));
    }

    #[test]
    fn authority_head_rejects_duplicate_family_watermarks_chirho() {
        let record_chirho = authority_record_chirho();
        let mut head_chirho = authority_head_chirho(&record_chirho);
        head_chirho
            .family_watermarks_chirho
            .push(head_chirho.family_watermarks_chirho[0].clone());

        let error_chirho = validate_gate1_authority_head_chirho(&head_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("duplicate family watermark"));
    }

    #[test]
    fn authority_head_rejects_zero_family_seq_with_digest_chirho() {
        let record_chirho = authority_record_chirho();
        let mut head_chirho = authority_head_chirho(&record_chirho);
        head_chirho.family_watermarks_chirho[0].next_family_seq_chirho = 0;

        let error_chirho = validate_gate1_authority_head_chirho(&head_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("cannot have a last digest at seq zero"));
    }

    #[test]
    fn authority_head_rejects_positive_family_seq_without_digest_chirho() {
        let record_chirho = authority_record_chirho();
        let mut head_chirho = authority_head_chirho(&record_chirho);
        head_chirho.family_watermarks_chirho[0].last_family_line_digest_chirho = None;

        let error_chirho = validate_gate1_authority_head_chirho(&head_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("requires last digest when seq is positive"));
    }
}
