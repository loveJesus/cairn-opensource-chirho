// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Gate 1 append-extension anchors for log-as-authority evidence.

use crate::model_chirho::HashChirho;
use crate::{effect_chirho, seqlog_chirho};
use anyhow::{bail, Context, Result};
use cairn_model_gate1_chirho::{
    canonical_gate1_anchor_head_replication_json_chirho, canonical_gate1_log_anchor_line_chirho,
    gate1_anchor_line_hash_chirho, parse_canonical_gate1_anchor_head_replication_record_chirho,
    unsigned_gate1_anchor_head_replication_message_chirho,
    unsigned_gate1_log_anchor_message_chirho, validate_gate1_anchor_head_replication_record_chirho,
    validate_gate1_log_anchor_record_chirho, Gate1AnchorHeadReplicationRecordChirho,
    Gate1LogAnchorRecordChirho, GATE1_ANCHOR_HEAD_REPLICATION_RECORD_SCHEMA_CHIRHO,
    GATE1_LEDGER_FAMILY_CHIRHO, GATE1_LOG_ANCHORS_FILE_CHIRHO,
    GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO, GATE1_RING_A_ANCHOR_TARGETS_CHIRHO,
    GATE1_RING_A_SEMANTIC_GROUPS_CHIRHO,
};
use cairn_projection_chirho::gate1_state_digest_chirho::{
    gate1_ring_a_semantic_state_digests_for_prefix_chirho, gate1_semantic_group_for_family_chirho,
};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PREFIX_ZERO_BYTES_CHIRHO: [u8; 32] = [0u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedGate1AnchorStateChirho {
    pub anchor_record_count_chirho: usize,
    pub latest_by_family_chirho: BTreeMap<String, VerifiedGate1AnchorRecordChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedGate1AnchorRecordChirho {
    pub record_chirho: Gate1LogAnchorRecordChirho,
    pub anchor_hash_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedGate1AnchorHeadReplicationChirho {
    pub record_chirho: Gate1AnchorHeadReplicationRecordChirho,
    pub current_anchor_record_count_chirho: u64,
    pub current_anchor_prefix_digest_chirho: HashChirho,
    pub unreplicated_tail_count_chirho: u64,
}

pub fn gate1_anchor_log_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO)
}

pub fn gate1_target_log_path_chirho(root_chirho: &Path, family_chirho: &str) -> PathBuf {
    root_chirho.join(family_chirho)
}

pub fn gate1_target_nonempty_line_count_chirho(
    root_chirho: &Path,
    family_chirho: &str,
) -> Result<u64> {
    Ok(
        read_nonempty_jsonl_lines_chirho(&gate1_target_log_path_chirho(root_chirho, family_chirho))?
            .len() as u64,
    )
}

pub fn gate1_target_prefix_digest_chirho(
    root_chirho: &Path,
    family_chirho: &str,
    line_count_chirho: u64,
) -> Result<HashChirho> {
    let lines_chirho = read_nonempty_jsonl_lines_chirho(&gate1_target_log_path_chirho(
        root_chirho,
        family_chirho,
    ))?;
    if line_count_chirho as usize > lines_chirho.len() {
        bail!(
            "gate1 anchor target {} has {} rows, below anchored count {}",
            family_chirho,
            lines_chirho.len(),
            line_count_chirho
        );
    }
    Ok(prefix_digest_for_lines_chirho(
        lines_chirho.iter().take(line_count_chirho as usize),
    ))
}

pub fn gate1_anchor_log_nonempty_line_count_chirho(root_chirho: &Path) -> Result<u64> {
    Ok(read_nonempty_jsonl_lines_chirho(&gate1_anchor_log_path_chirho(root_chirho))?.len() as u64)
}

pub fn gate1_anchor_log_prefix_digest_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<HashChirho> {
    let lines_chirho =
        read_nonempty_jsonl_lines_chirho(&gate1_anchor_log_path_chirho(root_chirho))?;
    if line_count_chirho as usize > lines_chirho.len() {
        bail!(
            "gate1 anchor log current line count {} is below retained external count {}",
            lines_chirho.len(),
            line_count_chirho
        );
    }
    Ok(prefix_digest_for_lines_chirho(
        lines_chirho.iter().take(line_count_chirho as usize),
    ))
}

pub fn append_gate1_ledger_anchor_chirho(root_chirho: &Path) -> Result<Gate1LogAnchorRecordChirho> {
    append_gate1_anchor_for_family_chirho(root_chirho, GATE1_LEDGER_FAMILY_CHIRHO)
}

pub fn append_gate1_ring_a_anchors_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1LogAnchorRecordChirho>> {
    let path_chirho = gate1_anchor_log_path_chirho(root_chirho);
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let anchor_seq_start_chirho =
            seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        let verified_chirho = verify_gate1_anchor_records_chirho(root_chirho)?;
        let counts_chirho = recovered_ring_a_target_counts_chirho(root_chirho)?;
        let state_digests_chirho =
            gate1_ring_a_semantic_state_digests_for_prefix_chirho(root_chirho, &counts_chirho)?;
        let key_id_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
        let mut records_chirho = Vec::with_capacity(GATE1_RING_A_ANCHOR_TARGETS_CHIRHO.len());

        for (idx_chirho, family_chirho) in GATE1_RING_A_ANCHOR_TARGETS_CHIRHO.iter().enumerate() {
            let previous_anchor_hash_chirho = verified_chirho
                .latest_by_family_chirho
                .get(*family_chirho)
                .map(|record_chirho| record_chirho.anchor_hash_chirho.clone());
            let line_count_chirho =
                counts_chirho.get(*family_chirho).copied().ok_or_else(|| {
                    anyhow::anyhow!("missing Ring A anchor count for {family_chirho}")
                })?;
            let prefix_digest_chirho =
                gate1_target_prefix_digest_chirho(root_chirho, family_chirho, line_count_chirho)?;
            let group_chirho =
                gate1_semantic_group_for_family_chirho(family_chirho).ok_or_else(|| {
                    anyhow::anyhow!("missing Ring A semantic group for {family_chirho}")
                })?;
            let state_digest_chirho = state_digests_chirho
                .get(group_chirho.group_chirho)
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing Ring A state digest for {}",
                        group_chirho.group_chirho
                    )
                })?;
            let mut record_chirho = Gate1LogAnchorRecordChirho {
                schema_chirho: GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO.to_string(),
                seq_chirho: anchor_seq_start_chirho + idx_chirho as u64,
                family_chirho: (*family_chirho).to_string(),
                line_count_chirho,
                prefix_digest_chirho,
                state_digest_chirho: Some(state_digest_chirho),
                prev_anchor_hash_chirho: previous_anchor_hash_chirho,
                at_ms_chirho: now_ms_chirho(),
                key_id_chirho: key_id_chirho.clone(),
                sig_chirho: String::new(),
            };
            let message_chirho = unsigned_gate1_log_anchor_message_chirho(&record_chirho)?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
            validate_gate1_log_anchor_record_chirho(&record_chirho)?;
            seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
                &path_chirho,
                record_chirho.seq_chirho,
                &record_chirho,
            )?;
            records_chirho.push(record_chirho);
        }

        Ok(records_chirho)
    })
}

pub fn append_gate1_anchor_for_family_chirho(
    root_chirho: &Path,
    family_chirho: &str,
) -> Result<Gate1LogAnchorRecordChirho> {
    let path_chirho = gate1_anchor_log_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let verified_chirho = verify_gate1_anchor_records_chirho(root_chirho)?;
        let previous_anchor_hash_chirho = verified_chirho
            .latest_by_family_chirho
            .get(family_chirho)
            .map(|record_chirho| record_chirho.anchor_hash_chirho.clone());
        let line_count_chirho =
            gate1_target_nonempty_line_count_chirho(root_chirho, family_chirho)?;
        let prefix_digest_chirho =
            gate1_target_prefix_digest_chirho(root_chirho, family_chirho, line_count_chirho)?;
        let mut record_chirho = Gate1LogAnchorRecordChirho {
            schema_chirho: GATE1_LOG_ANCHOR_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho,
            family_chirho: family_chirho.to_string(),
            line_count_chirho,
            prefix_digest_chirho,
            state_digest_chirho: None,
            prev_anchor_hash_chirho: previous_anchor_hash_chirho,
            at_ms_chirho: now_ms_chirho(),
            key_id_chirho: signer_chirho::pubkey_hex_chirho(root_chirho)?,
            sig_chirho: String::new(),
        };
        let message_chirho = unsigned_gate1_log_anchor_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        validate_gate1_log_anchor_record_chirho(&record_chirho)?;
        Ok(record_chirho)
    })
}

fn recovered_ring_a_target_counts_chirho(root_chirho: &Path) -> Result<BTreeMap<String, u64>> {
    let mut counts_chirho = BTreeMap::new();
    for family_chirho in GATE1_RING_A_ANCHOR_TARGETS_CHIRHO {
        let path_chirho = gate1_target_log_path_chirho(root_chirho, family_chirho);
        let count_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        counts_chirho.insert(family_chirho.to_string(), count_chirho);
    }
    Ok(counts_chirho)
}

pub fn load_gate1_anchor_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1LogAnchorRecordChirho>> {
    let path_chirho = gate1_anchor_log_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = fs::read_to_string(&path_chirho)
        .with_context(|| format!("read gate1 anchor log {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for (line_idx_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: Gate1LogAnchorRecordChirho = serde_json::from_str(line_chirho)
            .with_context(|| format!("parse gate1 anchor line {line_idx_chirho}"))?;
        let canonical_chirho = canonical_gate1_log_anchor_line_chirho(&record_chirho)?;
        if canonical_chirho != line_chirho {
            bail!("gate1 anchor byte mismatch on line {line_idx_chirho}");
        }
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn verify_gate1_anchor_records_chirho(
    root_chirho: &Path,
) -> Result<VerifiedGate1AnchorStateChirho> {
    let records_chirho = load_gate1_anchor_records_chirho(root_chirho)?;
    let expected_key_id_chirho = if records_chirho.is_empty() {
        None
    } else {
        Some(
            effect_chirho::existing_pubkey_hex_chirho(root_chirho)
                .context("gate1 anchor verification requires an existing root signing key")?,
        )
    };
    let mut latest_by_family_chirho: BTreeMap<String, VerifiedGate1AnchorRecordChirho> =
        BTreeMap::new();

    for (idx_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "gate1 anchor seq mismatch at line {}: expected {}, found {}",
                idx_chirho,
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        validate_gate1_log_anchor_record_chirho(record_chirho)?;
        let expected_key_id_chirho = expected_key_id_chirho
            .as_ref()
            .expect("non-empty anchor verification has a root key");
        if record_chirho.key_id_chirho != *expected_key_id_chirho {
            bail!("gate1 anchor key id mismatch at line {idx_chirho}: expected root key");
        }
        let message_chirho = unsigned_gate1_log_anchor_message_chirho(record_chirho)?;
        let sig_ok_chirho = signer_chirho::verify_with_pubkey_chirho(
            expected_key_id_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )?;
        if !sig_ok_chirho {
            bail!("gate1 anchor signature invalid at line {idx_chirho}");
        }
        let expected_prev_chirho = latest_by_family_chirho
            .get(&record_chirho.family_chirho)
            .map(|verified_chirho| verified_chirho.anchor_hash_chirho.clone());
        if record_chirho.prev_anchor_hash_chirho != expected_prev_chirho {
            bail!(
                "gate1 anchor chain broken for {} at line {}",
                record_chirho.family_chirho,
                idx_chirho
            );
        }
        let anchor_hash_chirho = gate1_anchor_line_hash_chirho(record_chirho)?;
        latest_by_family_chirho.insert(
            record_chirho.family_chirho.clone(),
            VerifiedGate1AnchorRecordChirho {
                record_chirho: record_chirho.clone(),
                anchor_hash_chirho,
            },
        );
    }

    Ok(VerifiedGate1AnchorStateChirho {
        anchor_record_count_chirho: records_chirho.len(),
        latest_by_family_chirho,
    })
}

pub fn export_gate1_anchor_head_replication_chirho(
    root_chirho: &Path,
) -> Result<Gate1AnchorHeadReplicationRecordChirho> {
    let verified_chirho = verify_gate1_anchor_records_chirho(root_chirho)?;
    if verified_chirho.anchor_record_count_chirho == 0 {
        bail!("gate1 anchor head export requires a non-empty verified anchor log");
    }
    let anchor_record_count_chirho = verified_chirho.anchor_record_count_chirho as u64;
    let anchor_prefix_digest_chirho =
        gate1_anchor_log_prefix_digest_chirho(root_chirho, anchor_record_count_chirho)?;
    let mut record_chirho = Gate1AnchorHeadReplicationRecordChirho {
        schema_chirho: GATE1_ANCHOR_HEAD_REPLICATION_RECORD_SCHEMA_CHIRHO.to_string(),
        anchor_log_file_chirho: GATE1_LOG_ANCHORS_FILE_CHIRHO.to_string(),
        anchor_record_count_chirho,
        anchor_prefix_digest_chirho,
        physical_target_count_chirho: GATE1_RING_A_ANCHOR_TARGETS_CHIRHO.len() as u64,
        semantic_group_count_chirho: GATE1_RING_A_SEMANTIC_GROUPS_CHIRHO.len() as u64,
        at_ms_chirho: now_ms_chirho(),
        key_id_chirho: effect_chirho::existing_pubkey_hex_chirho(root_chirho)
            .context("gate1 anchor head export requires an existing signing key")?,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_gate1_anchor_head_replication_message_chirho(&record_chirho)?;
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    validate_gate1_anchor_head_replication_record_chirho(&record_chirho)?;
    Ok(record_chirho)
}

pub fn canonical_gate1_anchor_head_replication_text_chirho(
    record_chirho: &Gate1AnchorHeadReplicationRecordChirho,
) -> Result<String> {
    canonical_gate1_anchor_head_replication_json_chirho(record_chirho)
}

pub fn verify_gate1_anchor_head_replication_text_chirho(
    root_chirho: &Path,
    external_text_chirho: &str,
) -> Result<VerifiedGate1AnchorHeadReplicationChirho> {
    let local_verified_chirho = verify_gate1_anchor_records_chirho(root_chirho)
        .context("local gate1 anchor family invalid before external head verify")?;
    let record_chirho =
        parse_canonical_gate1_anchor_head_replication_record_chirho(external_text_chirho)?;
    let current_anchor_record_count_chirho =
        local_verified_chirho.anchor_record_count_chirho as u64;
    if current_anchor_record_count_chirho < record_chirho.anchor_record_count_chirho {
        bail!(
            "gate1 anchor head current anchor count {} is below external retained count {}",
            current_anchor_record_count_chirho,
            record_chirho.anchor_record_count_chirho
        );
    }
    let local_anchor_key_id_chirho = gate1_anchor_shared_key_id_for_prefix_chirho(
        root_chirho,
        record_chirho.anchor_record_count_chirho,
    )?;
    if record_chirho.key_id_chirho != local_anchor_key_id_chirho {
        bail!("gate1 anchor head key id does not match local anchor key");
    }
    let message_chirho = unsigned_gate1_anchor_head_replication_message_chirho(&record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &record_chirho.key_id_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!("gate1 anchor head signature invalid");
    }
    let current_anchor_prefix_digest_chirho = gate1_anchor_log_prefix_digest_chirho(
        root_chirho,
        record_chirho.anchor_record_count_chirho,
    )?;
    if current_anchor_prefix_digest_chirho != record_chirho.anchor_prefix_digest_chirho {
        bail!("gate1 anchor head prefix digest mismatch");
    }
    Ok(VerifiedGate1AnchorHeadReplicationChirho {
        unreplicated_tail_count_chirho: current_anchor_record_count_chirho
            .saturating_sub(record_chirho.anchor_record_count_chirho),
        record_chirho,
        current_anchor_record_count_chirho,
        current_anchor_prefix_digest_chirho,
    })
}

fn gate1_anchor_shared_key_id_for_prefix_chirho(
    root_chirho: &Path,
    line_count_chirho: u64,
) -> Result<String> {
    let records_chirho = load_gate1_anchor_records_chirho(root_chirho)?;
    if line_count_chirho == 0 {
        bail!("gate1 anchor head cannot bind to an empty anchor prefix");
    }
    if line_count_chirho as usize > records_chirho.len() {
        bail!(
            "gate1 anchor log current line count {} is below retained external count {}",
            records_chirho.len(),
            line_count_chirho
        );
    }
    let expected_key_id_chirho = effect_chirho::existing_pubkey_hex_chirho(root_chirho)
        .context("gate1 anchor head prefix verification requires an existing root signing key")?;
    let Some(first_chirho) = records_chirho.first() else {
        bail!("gate1 anchor head cannot bind to an empty anchor log");
    };
    let key_id_chirho = first_chirho.key_id_chirho.clone();
    if key_id_chirho != expected_key_id_chirho {
        bail!("gate1 anchor head key id does not match root signing key");
    }
    for (idx_chirho, record_chirho) in records_chirho
        .iter()
        .take(line_count_chirho as usize)
        .enumerate()
    {
        if record_chirho.key_id_chirho != key_id_chirho {
            bail!("gate1 anchor key id mismatch at line {idx_chirho}");
        }
    }
    Ok(key_id_chirho)
}

fn read_nonempty_jsonl_lines_chirho(path_chirho: &Path) -> Result<Vec<Vec<u8>>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let bytes_chirho = fs::read(path_chirho)
        .with_context(|| format!("read JSONL bytes {}", path_chirho.display()))?;
    Ok(bytes_chirho
        .split(|byte_chirho| *byte_chirho == b'\n')
        .filter(|line_chirho| {
            !line_chirho
                .iter()
                .all(|byte_chirho| byte_chirho.is_ascii_whitespace())
        })
        .map(|line_chirho| line_chirho.to_vec())
        .collect())
}

fn prefix_digest_for_lines_chirho<'a>(
    lines_chirho: impl Iterator<Item = &'a Vec<u8>>,
) -> HashChirho {
    let mut previous_chirho = PREFIX_ZERO_BYTES_CHIRHO;
    for line_chirho in lines_chirho {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(&previous_chirho);
        hasher_chirho.update(line_chirho);
        previous_chirho = *hasher_chirho.finalize().as_bytes();
    }
    HashChirho(hex_from_bytes_chirho(&previous_chirho))
}

fn hex_from_bytes_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        out_chirho.push(HEX_CHIRHO[(byte_chirho >> 4) as usize] as char);
        out_chirho.push(HEX_CHIRHO[(byte_chirho & 0x0f) as usize] as char);
    }
    out_chirho
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}
