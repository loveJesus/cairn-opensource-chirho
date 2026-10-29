// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Appends signed Gate 1 authority envelopes behind the local writer fence.
//!
//! The global authority log is hash-chained and root-signed. For each migrated family F, F's
//! authority projection is a complete prefix of the verified old-road family F after F's successful
//! append/reconcile. The canary fails closed if any family lags or diverges. NO legacy cross-family
//! temporal order is claimed or reconstructed pre-cutover.
//!
//! Backfill is forward-only from verified family lines: the old road writes first, then authority
//! envelopes are appended and the derived head advances record-by-record so an interrupted backfill
//! resumes without gaps or duplicate authority seqs.

use anyhow::{anyhow, bail, Context, Result};
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_model_gate1_chirho::{
    canonical_gate1_authority_head_json_chirho, canonical_gate1_authority_record_json_chirho,
    gate1_authority_family_line_digest_chirho, gate1_authority_record_digest_chirho,
    parse_canonical_gate1_authority_head_chirho, parse_canonical_gate1_authority_record_chirho,
    unsigned_gate1_authority_record_message_chirho, validate_gate1_authority_head_chirho,
    validate_gate1_authority_record_chirho, Gate1AuthorityFamilyWatermarkChirho,
    Gate1AuthorityHeadChirho, Gate1AuthorityLogRecordChirho, GATE1_AUTHORITY_HEAD_DIR_CHIRHO,
    GATE1_AUTHORITY_HEAD_FILE_CHIRHO, GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO,
    GATE1_AUTHORITY_LOG_FILE_CHIRHO, GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO,
};
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_for_root_chirho, verify_writer_fence_chirho, WriterFenceTokenChirho,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate1AuthorityAppendInputChirho<'a> {
    pub family_chirho: &'a str,
    pub family_seq_chirho: u64,
    pub family_line_chirho: &'a str,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate1AuthorityAppendResultChirho {
    pub record_chirho: Gate1AuthorityLogRecordChirho,
    pub record_digest_chirho: String,
    pub head_chirho: Gate1AuthorityHeadChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate1AuthorityFamilyLineChirho {
    pub family_seq_chirho: u64,
    pub family_line_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate1AuthorityFamilyTailChirho {
    pub family_count_chirho: u64,
    pub last_line_chirho: Option<Gate1AuthorityFamilyLineChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Gate1AuthorityBackfillReportChirho {
    pub backfilled_chirho: usize,
    pub head_chirho: Gate1AuthorityHeadChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Gate1AuthorityRepairReportChirho {
    pub truncated_tail_bytes_chirho: u64,
    pub backfill_chirho: Gate1AuthorityBackfillReportChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGate1AuthorityRecordsChirho {
    records_chirho: Vec<Gate1AuthorityLogRecordChirho>,
}

impl VerifiedGate1AuthorityRecordsChirho {
    pub fn records_chirho(&self) -> &[Gate1AuthorityLogRecordChirho] {
        &self.records_chirho
    }

    pub fn len_chirho(&self) -> usize {
        self.records_chirho.len()
    }

    pub fn is_empty_chirho(&self) -> bool {
        self.records_chirho.is_empty()
    }
}

pub fn gate1_authority_log_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(GATE1_AUTHORITY_LOG_FILE_CHIRHO)
}

pub fn gate1_authority_head_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho
        .join(GATE1_AUTHORITY_HEAD_DIR_CHIRHO)
        .join(GATE1_AUTHORITY_HEAD_FILE_CHIRHO)
}

pub fn append_gate1_authority_record_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    input_chirho: Gate1AuthorityAppendInputChirho<'_>,
) -> Result<Gate1AuthorityAppendResultChirho> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        append_gate1_authority_record_unlocked_chirho(root_chirho, token_chirho, input_chirho)
    })
}

/// Append one signed authority envelope while the caller already holds the store append lock.
///
/// This is the reviewed Ring-A dual-write seam: the old road writes first, then the caller invokes
/// this helper without retaking the non-reentrant append lock. Production callsites are
/// source-guarded to reviewed family wrappers.
pub fn append_gate1_authority_record_unlocked_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    input_chirho: Gate1AuthorityAppendInputChirho<'_>,
) -> Result<Gate1AuthorityAppendResultChirho> {
    verify_gate1_authority_writer_fence_chirho(root_chirho, token_chirho)?;
    let head_chirho = read_gate1_authority_head_chirho(root_chirho, token_chirho.epoch_chirho)?;
    validate_append_input_matches_family_watermark_chirho(&head_chirho, &input_chirho)?;
    let record_chirho = signed_gate1_authority_record_chirho(
        root_chirho,
        token_chirho,
        &input_chirho,
        &head_chirho,
    )?;
    seqlog_chirho::append_jsonl_unlocked_chirho(
        &gate1_authority_log_path_chirho(root_chirho),
        &record_chirho,
    )?;
    let record_digest_chirho = gate1_authority_record_digest_chirho(&record_chirho)?;
    let authority_log_len_bytes_chirho = authority_log_len_bytes_chirho(root_chirho)?;
    let next_head_chirho = Gate1AuthorityHeadChirho {
        schema_chirho: GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO.to_string(),
        authority_log_file_chirho: GATE1_AUTHORITY_LOG_FILE_CHIRHO.to_string(),
        next_authority_seq_chirho: record_chirho.authority_seq_chirho + 1,
        authority_log_len_bytes_chirho,
        last_authority_record_digest_chirho: Some(record_digest_chirho.clone()),
        family_watermarks_chirho: updated_family_watermarks_chirho(&head_chirho, &record_chirho)?,
        writer_fence_epoch_chirho: token_chirho.epoch_chirho,
        updated_at_ms_chirho: input_chirho.at_ms_chirho,
    };
    write_gate1_authority_head_chirho(root_chirho, &next_head_chirho)?;
    Ok(Gate1AuthorityAppendResultChirho {
        record_chirho,
        record_digest_chirho,
        head_chirho: next_head_chirho,
    })
}

pub fn recover_gate1_authority_head_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
) -> Result<Gate1AuthorityHeadChirho> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        recover_gate1_authority_head_unlocked_chirho(root_chirho, token_chirho)
    })
}

/// Recover the derived authority head while the caller already holds the store append lock.
pub fn recover_gate1_authority_head_unlocked_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
) -> Result<Gate1AuthorityHeadChirho> {
    verify_gate1_authority_writer_fence_chirho(root_chirho, token_chirho)?;
    let chain_chirho = read_gate1_authority_chain_chirho(root_chirho)?;
    let expected_head_chirho =
        head_from_chain_chirho(root_chirho, token_chirho.epoch_chirho, &chain_chirho)?;
    match read_gate1_authority_head_file_chirho(root_chirho)? {
        Some(head_chirho) if head_matches_chain_chirho(&head_chirho, &expected_head_chirho) => {
            Ok(head_chirho)
        }
        Some(head_chirho)
            if head_matches_chain_except_family_watermarks_chirho(
                &head_chirho,
                &expected_head_chirho,
            ) =>
        {
            write_gate1_authority_head_chirho(root_chirho, &expected_head_chirho)?;
            Ok(expected_head_chirho)
        }
        Some(head_chirho) if head_is_stale_prefix_chirho(&head_chirho, &chain_chirho)? => {
            write_gate1_authority_head_chirho(root_chirho, &expected_head_chirho)?;
            Ok(expected_head_chirho)
        }
        Some(head_chirho) => {
            validate_head_matches_chain_chirho(&head_chirho, &expected_head_chirho)?;
            Ok(head_chirho)
        }
        None => {
            write_gate1_authority_head_chirho(root_chirho, &expected_head_chirho)?;
            Ok(expected_head_chirho)
        }
    }
}

/// Forward-complete the authority log from a verified old-road family prefix.
///
/// The caller must hold the append lock and pass only canonical lines from the already-verified old
/// road. After this returns successfully, the authority log is a complete prefix of `lines_chirho`.
pub fn reconcile_gate1_authority_prefix_unlocked_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    family_chirho: &str,
    lines_chirho: &[Gate1AuthorityFamilyLineChirho],
    at_ms_chirho: u64,
) -> Result<Gate1AuthorityBackfillReportChirho> {
    verify_gate1_authority_writer_fence_chirho(root_chirho, token_chirho)?;
    if authority_log_has_torn_tail_chirho(root_chirho)? {
        return repair_gate1_authority_torn_tail_unlocked_chirho(
            root_chirho,
            token_chirho,
            family_chirho,
            lines_chirho,
            at_ms_chirho,
        )
        .map(|report_chirho| report_chirho.backfill_chirho);
    }
    if let Some(mut head_chirho) = read_gate1_authority_head_file_chirho(root_chirho)? {
        validate_head_log_len_matches_current_chirho(root_chirho, &head_chirho)?;
        validate_head_tail_matches_current_chirho(root_chirho, &head_chirho)?;
        let family_next_seq_chirho = family_next_seq_from_head_chirho(&head_chirho, family_chirho);
        if family_next_seq_chirho == lines_chirho.len() as u64 {
            if validate_family_watermark_matches_old_road_tail_chirho(
                &head_chirho,
                family_chirho,
                lines_chirho.last(),
            )
            .is_err()
            {
                head_chirho =
                    recover_gate1_authority_head_unlocked_chirho(root_chirho, token_chirho)?;
                validate_head_log_len_matches_current_chirho(root_chirho, &head_chirho)?;
                validate_head_tail_matches_current_chirho(root_chirho, &head_chirho)?;
                validate_family_watermark_matches_old_road_tail_chirho(
                    &head_chirho,
                    family_chirho,
                    lines_chirho.last(),
                )?;
            }
            return Ok(Gate1AuthorityBackfillReportChirho {
                backfilled_chirho: 0,
                head_chirho,
            });
        }
        if family_next_seq_chirho > lines_chirho.len() as u64 {
            bail!("gate1 authority log points past verified old-road family prefix");
        }
    } else if authority_log_len_bytes_chirho(root_chirho)? == 0 && lines_chirho.is_empty() {
        return Ok(Gate1AuthorityBackfillReportChirho {
            backfilled_chirho: 0,
            head_chirho: Gate1AuthorityHeadChirho {
                schema_chirho: GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO.to_string(),
                authority_log_file_chirho: GATE1_AUTHORITY_LOG_FILE_CHIRHO.to_string(),
                next_authority_seq_chirho: 0,
                authority_log_len_bytes_chirho: 0,
                last_authority_record_digest_chirho: None,
                family_watermarks_chirho: Vec::new(),
                writer_fence_epoch_chirho: token_chirho.epoch_chirho,
                updated_at_ms_chirho: at_ms_chirho,
            },
        });
    }
    let recovered_head_chirho =
        recover_gate1_authority_head_unlocked_chirho(root_chirho, token_chirho)?;
    let chain_chirho = read_gate1_authority_chain_chirho(root_chirho)?;
    validate_authority_projection_is_family_prefix_chirho(
        &chain_chirho,
        family_chirho,
        lines_chirho,
    )?;
    let current_family_next_chirho =
        family_next_seq_from_head_chirho(&recovered_head_chirho, family_chirho);
    let mut backfilled_chirho = 0usize;
    let mut head_chirho = recovered_head_chirho;
    for line_chirho in lines_chirho
        .iter()
        .skip(current_family_next_chirho as usize)
    {
        let result_chirho = append_gate1_authority_record_unlocked_chirho(
            root_chirho,
            token_chirho,
            Gate1AuthorityAppendInputChirho {
                family_chirho,
                family_seq_chirho: line_chirho.family_seq_chirho,
                family_line_chirho: &line_chirho.family_line_chirho,
                at_ms_chirho,
            },
        )?;
        backfilled_chirho += 1;
        head_chirho = result_chirho.head_chirho;
    }
    Ok(Gate1AuthorityBackfillReportChirho {
        backfilled_chirho,
        head_chirho,
    })
}

/// Cheaply prove a family authority projection is current against a physical old-road tail.
///
/// This is the hot-path check for families that do not already verify every old-road row as part of
/// their own accounting invariant. It never parses or verifies the whole family history; if the
/// watermark is behind, the caller must run the verified-prefix backfill path.
pub fn reconcile_gate1_authority_current_family_tail_unlocked_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    family_chirho: &str,
    tail_chirho: &Gate1AuthorityFamilyTailChirho,
    at_ms_chirho: u64,
) -> Result<Option<Gate1AuthorityBackfillReportChirho>> {
    verify_gate1_authority_writer_fence_chirho(root_chirho, token_chirho)?;
    if authority_log_has_torn_tail_chirho(root_chirho)? {
        return Ok(None);
    }
    if let Some(mut head_chirho) = read_gate1_authority_head_file_chirho(root_chirho)? {
        validate_head_log_len_matches_current_chirho(root_chirho, &head_chirho)?;
        validate_head_tail_matches_current_chirho(root_chirho, &head_chirho)?;
        let family_next_seq_chirho = family_next_seq_from_head_chirho(&head_chirho, family_chirho);
        if family_next_seq_chirho == tail_chirho.family_count_chirho {
            if validate_family_watermark_matches_old_road_tail_chirho(
                &head_chirho,
                family_chirho,
                tail_chirho.last_line_chirho.as_ref(),
            )
            .is_err()
            {
                head_chirho =
                    recover_gate1_authority_head_unlocked_chirho(root_chirho, token_chirho)?;
                validate_head_log_len_matches_current_chirho(root_chirho, &head_chirho)?;
                validate_head_tail_matches_current_chirho(root_chirho, &head_chirho)?;
                validate_family_watermark_matches_old_road_tail_chirho(
                    &head_chirho,
                    family_chirho,
                    tail_chirho.last_line_chirho.as_ref(),
                )?;
            }
            return Ok(Some(Gate1AuthorityBackfillReportChirho {
                backfilled_chirho: 0,
                head_chirho,
            }));
        }
        if family_next_seq_chirho > tail_chirho.family_count_chirho {
            bail!("gate1 authority log points past old-road family tail");
        }
        return Ok(None);
    }
    if authority_log_len_bytes_chirho(root_chirho)? == 0 && tail_chirho.family_count_chirho == 0 {
        return Ok(Some(Gate1AuthorityBackfillReportChirho {
            backfilled_chirho: 0,
            head_chirho: Gate1AuthorityHeadChirho {
                schema_chirho: GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO.to_string(),
                authority_log_file_chirho: GATE1_AUTHORITY_LOG_FILE_CHIRHO.to_string(),
                next_authority_seq_chirho: 0,
                authority_log_len_bytes_chirho: 0,
                last_authority_record_digest_chirho: None,
                family_watermarks_chirho: Vec::new(),
                writer_fence_epoch_chirho: token_chirho.epoch_chirho,
                updated_at_ms_chirho: at_ms_chirho,
            },
        }));
    }
    Ok(None)
}

/// Repair only a torn authority-log tail, then forward-complete from the verified old road.
///
/// Intact complete authority rows are never erased here. If the log already ends at a newline, this
/// refuses so operators cannot use repair as a rewrite tool.
pub fn repair_gate1_authority_torn_tail_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    family_chirho: &str,
    lines_chirho: &[Gate1AuthorityFamilyLineChirho],
    at_ms_chirho: u64,
) -> Result<Gate1AuthorityRepairReportChirho> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        repair_gate1_authority_torn_tail_unlocked_chirho(
            root_chirho,
            token_chirho,
            family_chirho,
            lines_chirho,
            at_ms_chirho,
        )
    })
}

/// Repair a torn authority-log tail while the caller already holds the append lock.
///
/// Intact complete authority rows are never erased here. The caller must have already acquired the
/// same append-lock scope that protects the old-road family snapshot used for forward-completion.
pub fn repair_gate1_authority_torn_tail_unlocked_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    family_chirho: &str,
    lines_chirho: &[Gate1AuthorityFamilyLineChirho],
    at_ms_chirho: u64,
) -> Result<Gate1AuthorityRepairReportChirho> {
    verify_gate1_authority_writer_fence_chirho(root_chirho, token_chirho)?;
    let truncated_tail_bytes_chirho = truncate_torn_authority_tail_unlocked_chirho(root_chirho)?;
    let chain_chirho = read_gate1_authority_chain_chirho(root_chirho)?;
    validate_authority_projection_is_family_prefix_chirho(
        &chain_chirho,
        family_chirho,
        lines_chirho,
    )?;
    let mut head_chirho =
        head_from_chain_chirho(root_chirho, token_chirho.epoch_chirho, &chain_chirho)?;
    write_gate1_authority_head_chirho(root_chirho, &head_chirho)?;
    let mut backfilled_chirho = 0usize;
    let current_family_next_chirho = family_next_seq_from_head_chirho(&head_chirho, family_chirho);
    for line_chirho in lines_chirho
        .iter()
        .skip(current_family_next_chirho as usize)
    {
        let result_chirho = append_gate1_authority_record_unlocked_chirho(
            root_chirho,
            token_chirho,
            Gate1AuthorityAppendInputChirho {
                family_chirho,
                family_seq_chirho: line_chirho.family_seq_chirho,
                family_line_chirho: &line_chirho.family_line_chirho,
                at_ms_chirho,
            },
        )?;
        backfilled_chirho += 1;
        head_chirho = result_chirho.head_chirho;
    }
    Ok(Gate1AuthorityRepairReportChirho {
        truncated_tail_bytes_chirho,
        backfill_chirho: Gate1AuthorityBackfillReportChirho {
            backfilled_chirho,
            head_chirho,
        },
    })
}

pub fn verify_gate1_authority_log_chirho(root_chirho: &Path) -> Result<usize> {
    let chain_chirho = read_gate1_authority_chain_chirho(root_chirho)?;
    if let Some(head_chirho) = read_gate1_authority_head_file_chirho(root_chirho)? {
        let expected_head_chirho = head_from_chain_chirho(
            root_chirho,
            head_chirho.writer_fence_epoch_chirho,
            &chain_chirho,
        )?;
        validate_head_matches_chain_chirho(&head_chirho, &expected_head_chirho)?;
    }
    Ok(chain_chirho.len())
}

pub fn load_gate1_authority_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1AuthorityLogRecordChirho>> {
    read_gate1_authority_chain_chirho(root_chirho)
}

pub fn verified_gate1_authority_records_chirho(
    root_chirho: &Path,
) -> Result<VerifiedGate1AuthorityRecordsChirho> {
    Ok(VerifiedGate1AuthorityRecordsChirho {
        records_chirho: read_gate1_authority_chain_chirho(root_chirho)?,
    })
}

fn read_gate1_authority_head_chirho(
    root_chirho: &Path,
    writer_fence_epoch_chirho: u64,
) -> Result<Gate1AuthorityHeadChirho> {
    if let Some(head_chirho) = read_gate1_authority_head_file_chirho(root_chirho)? {
        validate_head_log_len_matches_current_chirho(root_chirho, &head_chirho)?;
        return Ok(head_chirho);
    }
    let chain_chirho = read_gate1_authority_chain_chirho(root_chirho)?;
    if !chain_chirho.is_empty() {
        bail!("gate1 authority head missing while log exists; run recovery with a writer fence");
    }
    Ok(Gate1AuthorityHeadChirho {
        schema_chirho: GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO.to_string(),
        authority_log_file_chirho: GATE1_AUTHORITY_LOG_FILE_CHIRHO.to_string(),
        next_authority_seq_chirho: 0,
        authority_log_len_bytes_chirho: 0,
        last_authority_record_digest_chirho: None,
        family_watermarks_chirho: Vec::new(),
        writer_fence_epoch_chirho,
        updated_at_ms_chirho: now_ms_chirho(),
    })
}

fn read_gate1_authority_head_file_chirho(
    root_chirho: &Path,
) -> Result<Option<Gate1AuthorityHeadChirho>> {
    let path_chirho = gate1_authority_head_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(None);
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let head_chirho = parse_canonical_gate1_authority_head_chirho(&text_chirho)
        .with_context(|| format!("decode {}", path_chirho.display()))?;
    Ok(Some(head_chirho))
}

fn write_gate1_authority_head_chirho(
    root_chirho: &Path,
    head_chirho: &Gate1AuthorityHeadChirho,
) -> Result<()> {
    validate_gate1_authority_head_chirho(head_chirho)?;
    let text_chirho = canonical_gate1_authority_head_json_chirho(head_chirho)?;
    write_file_durable_chirho(
        &gate1_authority_head_path_chirho(root_chirho),
        text_chirho.as_bytes(),
    )
    .context("write Gate 1 authority head")
}

fn read_gate1_authority_chain_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1AuthorityLogRecordChirho>> {
    let parsed_records_chirho = read_gate1_authority_records_unverified_chirho(root_chirho)?;
    let mut records_chirho = Vec::new();
    let mut previous_digest_chirho: Option<String> = None;
    for (index_chirho, record_chirho) in parsed_records_chirho.into_iter().enumerate() {
        verify_gate1_authority_record_signature_chirho(root_chirho, &record_chirho)
            .with_context(|| format!("verify Gate 1 authority record {}", index_chirho + 1))?;
        if record_chirho.authority_seq_chirho != records_chirho.len() as u64 {
            bail!(
                "gate1 authority seq gap at index {}: entry seq is {}",
                records_chirho.len(),
                record_chirho.authority_seq_chirho
            );
        }
        if record_chirho.prev_authority_record_digest_chirho != previous_digest_chirho {
            bail!(
                "gate1 authority record chain mismatch at seq {}",
                record_chirho.authority_seq_chirho
            );
        }
        previous_digest_chirho = Some(gate1_authority_record_digest_chirho(&record_chirho)?);
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

fn read_gate1_authority_records_unverified_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1AuthorityLogRecordChirho>> {
    let path_chirho = gate1_authority_log_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    if !text_chirho.is_empty() && !text_chirho.as_bytes().ends_with(b"\n") {
        bail!(
            "decode Gate 1 authority record {}: torn Gate 1 authority log tail without newline",
            text_chirho.lines().count()
        );
    }
    let mut records_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            bail!(
                "gate1 authority log contains empty line at record {}",
                index_chirho + 1
            );
        }
        let record_chirho = parse_canonical_gate1_authority_record_chirho(line_chirho)
            .with_context(|| format!("decode Gate 1 authority record {}", index_chirho + 1))?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

fn read_last_gate1_authority_record_chirho(
    root_chirho: &Path,
) -> Result<Option<Gate1AuthorityLogRecordChirho>> {
    let path_chirho = gate1_authority_log_path_chirho(root_chirho);
    let mut file_chirho = match File::open(&path_chirho) {
        Ok(file_chirho) => file_chirho,
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error_chirho) => {
            return Err(error_chirho).with_context(|| format!("open {}", path_chirho.display()));
        }
    };
    let len_chirho = file_chirho
        .metadata()
        .with_context(|| format!("stat {}", path_chirho.display()))?
        .len();
    if len_chirho == 0 {
        return Ok(None);
    }
    file_chirho
        .seek(SeekFrom::End(-1))
        .with_context(|| format!("seek {}", path_chirho.display()))?;
    let mut final_byte_chirho = [0u8; 1];
    file_chirho
        .read_exact(&mut final_byte_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    if final_byte_chirho[0] != b'\n' {
        bail!(
            "decode Gate 1 authority record {}: torn Gate 1 authority log tail without newline",
            len_chirho
        );
    }

    let mut end_chirho = len_chirho - 1;
    let mut chunks_rev_chirho: Vec<Vec<u8>> = Vec::new();
    while end_chirho > 0 {
        let chunk_len_chirho = usize::min(end_chirho as usize, 8192);
        let start_chirho = end_chirho - chunk_len_chirho as u64;
        file_chirho
            .seek(SeekFrom::Start(start_chirho))
            .with_context(|| format!("seek {}", path_chirho.display()))?;
        let mut chunk_chirho = vec![0u8; chunk_len_chirho];
        file_chirho
            .read_exact(&mut chunk_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        if let Some(newline_chirho) = chunk_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
        {
            let mut line_chirho = chunk_chirho[newline_chirho + 1..].to_vec();
            for chunk_chirho in chunks_rev_chirho.iter().rev() {
                line_chirho.extend_from_slice(chunk_chirho);
            }
            return parse_last_gate1_authority_line_chirho(root_chirho, &line_chirho);
        }
        chunks_rev_chirho.push(chunk_chirho);
        end_chirho = start_chirho;
    }

    let mut line_chirho = Vec::new();
    for chunk_chirho in chunks_rev_chirho.iter().rev() {
        line_chirho.extend_from_slice(chunk_chirho);
    }
    parse_last_gate1_authority_line_chirho(root_chirho, &line_chirho)
}

fn parse_last_gate1_authority_line_chirho(
    root_chirho: &Path,
    line_chirho: &[u8],
) -> Result<Option<Gate1AuthorityLogRecordChirho>> {
    let text_chirho = std::str::from_utf8(line_chirho).context("decode Gate 1 authority tail")?;
    if text_chirho.trim().is_empty() {
        bail!("gate1 authority log contains empty final line");
    }
    let record_chirho = parse_canonical_gate1_authority_record_chirho(text_chirho)
        .context("decode Gate 1 authority tail")?;
    verify_gate1_authority_record_signature_chirho(root_chirho, &record_chirho)
        .context("verify Gate 1 authority tail")?;
    Ok(Some(record_chirho))
}

fn signed_gate1_authority_record_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
    input_chirho: &Gate1AuthorityAppendInputChirho<'_>,
    head_chirho: &Gate1AuthorityHeadChirho,
) -> Result<Gate1AuthorityLogRecordChirho> {
    let mut record_chirho = Gate1AuthorityLogRecordChirho {
        schema_chirho: GATE1_AUTHORITY_LOG_RECORD_SCHEMA_CHIRHO.to_string(),
        authority_seq_chirho: head_chirho.next_authority_seq_chirho,
        family_chirho: input_chirho.family_chirho.to_string(),
        family_seq_chirho: input_chirho.family_seq_chirho,
        family_line_digest_chirho: gate1_authority_family_line_digest_chirho(
            input_chirho.family_line_chirho,
        ),
        family_line_chirho: input_chirho.family_line_chirho.to_string(),
        prev_authority_record_digest_chirho: head_chirho
            .last_authority_record_digest_chirho
            .clone(),
        writer_fence_epoch_chirho: token_chirho.epoch_chirho,
        at_ms_chirho: input_chirho.at_ms_chirho,
        key_id_chirho: signer_chirho::pubkey_hex_chirho(root_chirho)?,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_gate1_authority_record_message_chirho(&record_chirho)?;
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
    validate_gate1_authority_record_chirho(&record_chirho)?;
    Ok(record_chirho)
}

fn verify_gate1_authority_record_signature_chirho(
    root_chirho: &Path,
    record_chirho: &Gate1AuthorityLogRecordChirho,
) -> Result<()> {
    let expected_key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    if record_chirho.key_id_chirho != expected_key_id_chirho {
        bail!(
            "gate1 authority record key id mismatch at seq {}",
            record_chirho.authority_seq_chirho
        );
    }
    let message_chirho = unsigned_gate1_authority_record_message_chirho(record_chirho)?;
    if !signer_chirho::verify_with_root_pubkey_chirho(
        root_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "gate1 authority record signature invalid at seq {}",
            record_chirho.authority_seq_chirho
        );
    }
    Ok(())
}

fn authority_log_has_torn_tail_chirho(root_chirho: &Path) -> Result<bool> {
    let path_chirho = gate1_authority_log_path_chirho(root_chirho);
    let mut file_chirho = match File::open(&path_chirho) {
        Ok(file_chirho) => file_chirho,
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error_chirho) => {
            return Err(error_chirho).with_context(|| format!("open {}", path_chirho.display()));
        }
    };
    let len_chirho = file_chirho
        .metadata()
        .with_context(|| format!("stat {}", path_chirho.display()))?
        .len();
    if len_chirho == 0 {
        return Ok(false);
    }
    file_chirho
        .seek(SeekFrom::End(-1))
        .with_context(|| format!("seek {}", path_chirho.display()))?;
    let mut final_byte_chirho = [0u8; 1];
    file_chirho
        .read_exact(&mut final_byte_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(final_byte_chirho[0] != b'\n')
}

fn family_next_seq_from_head_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    family_chirho: &str,
) -> u64 {
    head_chirho
        .family_watermarks_chirho
        .iter()
        .find(|watermark_chirho| watermark_chirho.family_chirho == family_chirho)
        .map(|watermark_chirho| watermark_chirho.next_family_seq_chirho)
        .unwrap_or(0)
}

fn family_watermark_from_head_chirho<'a>(
    head_chirho: &'a Gate1AuthorityHeadChirho,
    family_chirho: &str,
) -> Option<&'a Gate1AuthorityFamilyWatermarkChirho> {
    head_chirho
        .family_watermarks_chirho
        .iter()
        .find(|watermark_chirho| watermark_chirho.family_chirho == family_chirho)
}

fn validate_append_input_matches_family_watermark_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    input_chirho: &Gate1AuthorityAppendInputChirho<'_>,
) -> Result<()> {
    let expected_seq_chirho =
        family_next_seq_from_head_chirho(head_chirho, input_chirho.family_chirho);
    if input_chirho.family_seq_chirho != expected_seq_chirho {
        bail!(
            "gate1 authority family '{}' seq mismatch: input {}, expected {}",
            input_chirho.family_chirho,
            input_chirho.family_seq_chirho,
            expected_seq_chirho
        );
    }
    Ok(())
}

fn validate_family_watermark_matches_old_road_tail_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    family_chirho: &str,
    last_line_chirho: Option<&Gate1AuthorityFamilyLineChirho>,
) -> Result<()> {
    let Some(expected_chirho) = last_line_chirho else {
        match family_watermark_from_head_chirho(head_chirho, family_chirho) {
            None => return Ok(()),
            Some(watermark_chirho) if watermark_chirho.next_family_seq_chirho == 0 => {
                return Ok(());
            }
            _ => {
                bail!("gate1 authority record does not match verified old-road family prefix tail")
            }
        }
    };
    let Some(watermark_chirho) = family_watermark_from_head_chirho(head_chirho, family_chirho)
    else {
        bail!("gate1 authority record does not match verified old-road family prefix tail");
    };
    let expected_digest_chirho =
        gate1_authority_family_line_digest_chirho(&expected_chirho.family_line_chirho);
    if watermark_chirho.next_family_seq_chirho == expected_chirho.family_seq_chirho + 1
        && watermark_chirho.last_family_line_digest_chirho.as_deref()
            == Some(expected_digest_chirho.as_str())
    {
        Ok(())
    } else {
        bail!("gate1 authority record does not match verified old-road family prefix tail");
    }
}

fn family_watermarks_from_chain_chirho(
    records_chirho: &[Gate1AuthorityLogRecordChirho],
) -> Result<Vec<Gate1AuthorityFamilyWatermarkChirho>> {
    let mut by_family_chirho = BTreeMap::<String, Gate1AuthorityFamilyWatermarkChirho>::new();
    for record_chirho in records_chirho {
        let watermark_chirho = by_family_chirho
            .entry(record_chirho.family_chirho.clone())
            .or_insert_with(|| Gate1AuthorityFamilyWatermarkChirho {
                family_chirho: record_chirho.family_chirho.clone(),
                next_family_seq_chirho: 0,
                last_family_line_digest_chirho: None,
            });
        if record_chirho.family_seq_chirho != watermark_chirho.next_family_seq_chirho {
            bail!(
                "gate1 authority family '{}' seq gap: record {}, expected {}",
                record_chirho.family_chirho,
                record_chirho.family_seq_chirho,
                watermark_chirho.next_family_seq_chirho
            );
        }
        watermark_chirho.next_family_seq_chirho = record_chirho.family_seq_chirho + 1;
        watermark_chirho.last_family_line_digest_chirho =
            Some(record_chirho.family_line_digest_chirho.clone());
    }
    Ok(by_family_chirho.into_values().collect())
}

fn updated_family_watermarks_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    record_chirho: &Gate1AuthorityLogRecordChirho,
) -> Result<Vec<Gate1AuthorityFamilyWatermarkChirho>> {
    let mut by_family_chirho = head_chirho
        .family_watermarks_chirho
        .iter()
        .cloned()
        .map(|watermark_chirho| (watermark_chirho.family_chirho.clone(), watermark_chirho))
        .collect::<BTreeMap<_, _>>();
    let watermark_chirho = by_family_chirho
        .entry(record_chirho.family_chirho.clone())
        .or_insert_with(|| Gate1AuthorityFamilyWatermarkChirho {
            family_chirho: record_chirho.family_chirho.clone(),
            next_family_seq_chirho: 0,
            last_family_line_digest_chirho: None,
        });
    if record_chirho.family_seq_chirho != watermark_chirho.next_family_seq_chirho {
        bail!(
            "gate1 authority family '{}' seq mismatch during head update",
            record_chirho.family_chirho
        );
    }
    watermark_chirho.next_family_seq_chirho = record_chirho.family_seq_chirho + 1;
    watermark_chirho.last_family_line_digest_chirho =
        Some(record_chirho.family_line_digest_chirho.clone());
    Ok(by_family_chirho.into_values().collect())
}

fn validate_authority_projection_is_family_prefix_chirho(
    records_chirho: &[Gate1AuthorityLogRecordChirho],
    family_chirho: &str,
    lines_chirho: &[Gate1AuthorityFamilyLineChirho],
) -> Result<()> {
    for (projection_index_chirho, record_chirho) in records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.family_chirho == family_chirho)
        .enumerate()
    {
        if projection_index_chirho >= lines_chirho.len() {
            bail!("gate1 authority log points past verified old-road family prefix");
        }
        let expected_chirho = &lines_chirho[projection_index_chirho];
        if record_chirho.family_chirho != family_chirho
            || record_chirho.family_seq_chirho != expected_chirho.family_seq_chirho
            || record_chirho.family_line_chirho != expected_chirho.family_line_chirho
        {
            bail!(
                "gate1 authority record {} does not match verified old-road family prefix",
                record_chirho.authority_seq_chirho
            );
        }
    }
    Ok(())
}

fn truncate_torn_authority_tail_unlocked_chirho(root_chirho: &Path) -> Result<u64> {
    let path_chirho = gate1_authority_log_path_chirho(root_chirho);
    let bytes_chirho = match std::fs::read(&path_chirho) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => {
            bail!("gate1 authority log has no torn tail to repair")
        }
        Err(error_chirho) => {
            return Err(error_chirho).with_context(|| format!("read {}", path_chirho.display()));
        }
    };
    if bytes_chirho.is_empty() || bytes_chirho.ends_with(b"\n") {
        bail!("gate1 authority log tail is intact; refusing repair overreach");
    }
    let keep_len_chirho = bytes_chirho
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map(|index_chirho| index_chirho + 1)
        .unwrap_or(0);
    let truncated_tail_bytes_chirho = (bytes_chirho.len() - keep_len_chirho) as u64;
    write_file_durable_chirho(&path_chirho, &bytes_chirho[..keep_len_chirho])
        .context("truncate torn Gate 1 authority tail")?;
    Ok(truncated_tail_bytes_chirho)
}

fn head_from_chain_chirho(
    root_chirho: &Path,
    writer_fence_epoch_chirho: u64,
    records_chirho: &[Gate1AuthorityLogRecordChirho],
) -> Result<Gate1AuthorityHeadChirho> {
    let last_authority_record_digest_chirho = records_chirho
        .last()
        .map(gate1_authority_record_digest_chirho)
        .transpose()?;
    Ok(Gate1AuthorityHeadChirho {
        schema_chirho: GATE1_AUTHORITY_HEAD_SCHEMA_CHIRHO.to_string(),
        authority_log_file_chirho: GATE1_AUTHORITY_LOG_FILE_CHIRHO.to_string(),
        next_authority_seq_chirho: records_chirho.len() as u64,
        authority_log_len_bytes_chirho: authority_log_len_bytes_chirho(root_chirho)?,
        last_authority_record_digest_chirho,
        family_watermarks_chirho: family_watermarks_from_chain_chirho(records_chirho)?,
        writer_fence_epoch_chirho,
        updated_at_ms_chirho: now_ms_chirho(),
    })
}

fn validate_head_matches_chain_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    expected_chirho: &Gate1AuthorityHeadChirho,
) -> Result<()> {
    if !head_matches_chain_chirho(head_chirho, expected_chirho) {
        bail!("gate1 authority head does not match log chain");
    }
    Ok(())
}

fn head_matches_chain_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    expected_chirho: &Gate1AuthorityHeadChirho,
) -> bool {
    head_chirho.next_authority_seq_chirho == expected_chirho.next_authority_seq_chirho
        && head_chirho.authority_log_len_bytes_chirho
            == expected_chirho.authority_log_len_bytes_chirho
        && head_chirho.last_authority_record_digest_chirho
            == expected_chirho.last_authority_record_digest_chirho
        && head_chirho.family_watermarks_chirho == expected_chirho.family_watermarks_chirho
}

fn head_matches_chain_except_family_watermarks_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    expected_chirho: &Gate1AuthorityHeadChirho,
) -> bool {
    head_chirho.next_authority_seq_chirho == expected_chirho.next_authority_seq_chirho
        && head_chirho.authority_log_len_bytes_chirho
            == expected_chirho.authority_log_len_bytes_chirho
        && head_chirho.last_authority_record_digest_chirho
            == expected_chirho.last_authority_record_digest_chirho
}

fn head_is_stale_prefix_chirho(
    head_chirho: &Gate1AuthorityHeadChirho,
    records_chirho: &[Gate1AuthorityLogRecordChirho],
) -> Result<bool> {
    let prefix_len_chirho = head_chirho.next_authority_seq_chirho as usize;
    if prefix_len_chirho > records_chirho.len() {
        return Ok(false);
    }
    let expected_digest_chirho = if prefix_len_chirho == 0 {
        None
    } else {
        Some(gate1_authority_record_digest_chirho(
            &records_chirho[prefix_len_chirho - 1],
        )?)
    };
    let expected_len_chirho =
        authority_log_len_for_prefix_chirho(records_chirho, prefix_len_chirho)?;
    Ok(
        head_chirho.last_authority_record_digest_chirho == expected_digest_chirho
            && head_chirho.authority_log_len_bytes_chirho == expected_len_chirho
            && prefix_len_chirho < records_chirho.len(),
    )
}

fn validate_head_log_len_matches_current_chirho(
    root_chirho: &Path,
    head_chirho: &Gate1AuthorityHeadChirho,
) -> Result<()> {
    let current_len_chirho = authority_log_len_bytes_chirho(root_chirho)?;
    if head_chirho.authority_log_len_bytes_chirho != current_len_chirho {
        bail!("stale gate1 authority head; run recovery");
    }
    Ok(())
}

fn validate_head_tail_matches_current_chirho(
    root_chirho: &Path,
    head_chirho: &Gate1AuthorityHeadChirho,
) -> Result<Option<Gate1AuthorityLogRecordChirho>> {
    match read_last_gate1_authority_record_chirho(root_chirho)? {
        None => {
            if head_chirho.next_authority_seq_chirho != 0
                || head_chirho.last_authority_record_digest_chirho.is_some()
                || head_chirho.authority_log_len_bytes_chirho != 0
            {
                bail!("gate1 authority head does not match log tail");
            }
            Ok(None)
        }
        Some(record_chirho) => {
            if head_chirho.next_authority_seq_chirho != record_chirho.authority_seq_chirho + 1 {
                bail!("gate1 authority head does not match log tail");
            }
            let record_digest_chirho = gate1_authority_record_digest_chirho(&record_chirho)?;
            if head_chirho.last_authority_record_digest_chirho.as_deref()
                != Some(record_digest_chirho.as_str())
            {
                bail!("gate1 authority head does not match log tail");
            }
            Ok(Some(record_chirho))
        }
    }
}

fn authority_log_len_bytes_chirho(root_chirho: &Path) -> Result<u64> {
    let path_chirho = gate1_authority_log_path_chirho(root_chirho);
    match std::fs::metadata(&path_chirho) {
        Ok(metadata_chirho) => Ok(metadata_chirho.len()),
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(0),
        Err(error_chirho) => {
            Err(error_chirho).with_context(|| format!("stat {}", path_chirho.display()))
        }
    }
}

fn authority_log_len_for_prefix_chirho(
    records_chirho: &[Gate1AuthorityLogRecordChirho],
    prefix_len_chirho: usize,
) -> Result<u64> {
    let mut len_chirho = 0u64;
    for record_chirho in records_chirho.iter().take(prefix_len_chirho) {
        // This is a stale-head consistency check, not authority sequence assignment.
        len_chirho += canonical_gate1_authority_record_json_chirho(record_chirho)?.len() as u64 + 1;
    }
    Ok(len_chirho)
}

fn verify_gate1_authority_writer_fence_chirho(
    root_chirho: &Path,
    token_chirho: &WriterFenceTokenChirho,
) -> Result<()> {
    let group_chirho = consistency_group_for_root_chirho(root_chirho)?;
    verify_writer_fence_chirho(root_chirho, &group_chirho, token_chirho)
        .map_err(|error_chirho| anyhow!("gate1 authority writer fence rejected: {error_chirho}"))
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests_chirho;
