// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Gate 1 companion authority envelopes for resource Ring-A families.

use super::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use cairn_gate1_authority_log_chirho::authority_log_chirho::{
    append_gate1_authority_record_unlocked_chirho,
    reconcile_gate1_authority_current_family_tail_unlocked_chirho,
    reconcile_gate1_authority_prefix_unlocked_chirho, Gate1AuthorityAppendInputChirho,
    Gate1AuthorityBackfillReportChirho, Gate1AuthorityFamilyLineChirho,
    Gate1AuthorityFamilyTailChirho,
};
use cairn_model_gate1_chirho::{
    GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO, GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
    GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
};

pub(super) fn append_resource_policy_record_unlocked_chirho(
    root_chirho: &Path,
    writer_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
    app_chirho: &str,
    owner_principal_chirho: &str,
    resource_policy_chirho: HashChirho,
    previous_chirho: Option<HashChirho>,
    min_at_ms_chirho: u64,
) -> Result<ResourcePolicyRecordChirho> {
    reconcile_resource_policies_authority_prefix_unlocked_chirho(root_chirho, writer_fence_chirho)?;
    let record_chirho = super::append_resource_policy_record_old_road_unlocked_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        resource_policy_chirho,
        previous_chirho,
        writer_fence_chirho,
        min_at_ms_chirho,
    )?;
    let family_line_chirho =
        resource_policy_line_at_seq_chirho(root_chirho, record_chirho.seq_chirho)?;
    append_gate1_authority_record_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        Gate1AuthorityAppendInputChirho {
            family_chirho: GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            family_line_chirho: &family_line_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?;
    Ok(record_chirho)
}

pub(super) fn append_resource_policy_unset_record_unlocked_chirho(
    root_chirho: &Path,
    writer_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
    app_chirho: &str,
    owner_principal_chirho: &str,
    previous_chirho: HashChirho,
    min_at_ms_chirho: u64,
) -> Result<ResourcePolicyUnsetRecordChirho> {
    reconcile_resource_policy_unsets_authority_prefix_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
    )?;
    let record_chirho = super::append_resource_policy_unset_record_old_road_unlocked_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        previous_chirho,
        min_at_ms_chirho,
    )?;
    let family_line_chirho =
        resource_policy_unset_line_at_seq_chirho(root_chirho, record_chirho.seq_chirho)?;
    append_gate1_authority_record_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        Gate1AuthorityAppendInputChirho {
            family_chirho: GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            family_line_chirho: &family_line_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?;
    Ok(record_chirho)
}

pub(super) fn append_resource_usage_unlocked_chirho(
    root_chirho: &Path,
    writer_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
    input_chirho: ResourceUsageInputChirho,
    actor_value_chirho: String,
) -> Result<ResourceUsageRecordChirho> {
    reconcile_resource_usage_authority_prefix_unlocked_chirho(root_chirho, writer_fence_chirho)?;
    let record_chirho = super::append_resource_usage_old_road_unlocked_chirho(
        root_chirho,
        input_chirho,
        actor_value_chirho,
    )?;
    // F3 Layer 3: the just-appended record IS the log's new tail line, and the old road wrote it as
    // `serde_json::to_string(&record)\n`; re-serializing the in-hand value reproduces those exact
    // bytes (serde_json is deterministic per value) with zero file I/O, replacing a whole-file read of
    // the usage log. `resource_dual_write_binds_exact_old_road_line_bytes_chirho` pins this equality.
    let family_line_chirho = serde_json::to_string(&record_chirho)
        .context("serialize resource usage record for gate1 authority family line")?;
    append_gate1_authority_record_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        Gate1AuthorityAppendInputChirho {
            family_chirho: GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            family_line_chirho: &family_line_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?;
    Ok(record_chirho)
}

pub fn reconcile_resource_policies_authority_prefix_unlocked_chirho(
    root_chirho: &Path,
    writer_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
) -> Result<Gate1AuthorityBackfillReportChirho> {
    let tail_chirho = resource_policy_family_tail_chirho(root_chirho)?;
    if let Some(report_chirho) = reconcile_gate1_authority_current_family_tail_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
        &tail_chirho,
        now_ms_chirho(),
    )? {
        return Ok(report_chirho);
    }
    let lines_chirho = verified_resource_policy_family_lines_chirho(root_chirho)?;
    reconcile_gate1_authority_prefix_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        GATE1_RESOURCE_POLICIES_FAMILY_CHIRHO,
        &lines_chirho,
        now_ms_chirho(),
    )
}

pub fn reconcile_resource_policy_unsets_authority_prefix_unlocked_chirho(
    root_chirho: &Path,
    writer_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
) -> Result<Gate1AuthorityBackfillReportChirho> {
    let tail_chirho = resource_policy_unset_family_tail_chirho(root_chirho)?;
    if let Some(report_chirho) = reconcile_gate1_authority_current_family_tail_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
        &tail_chirho,
        now_ms_chirho(),
    )? {
        return Ok(report_chirho);
    }
    let lines_chirho = verified_resource_policy_unset_family_lines_chirho(root_chirho)?;
    reconcile_gate1_authority_prefix_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        GATE1_RESOURCE_POLICY_UNSETS_FAMILY_CHIRHO,
        &lines_chirho,
        now_ms_chirho(),
    )
}

pub fn reconcile_resource_usage_authority_prefix_unlocked_chirho(
    root_chirho: &Path,
    writer_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
) -> Result<Gate1AuthorityBackfillReportChirho> {
    let tail_chirho = resource_usage_family_tail_chirho(root_chirho)?;
    if let Some(report_chirho) = reconcile_gate1_authority_current_family_tail_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
        &tail_chirho,
        now_ms_chirho(),
    )? {
        return Ok(report_chirho);
    }
    let lines_chirho = verified_resource_usage_family_lines_chirho(root_chirho)?;
    reconcile_gate1_authority_prefix_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
        GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
        &lines_chirho,
        now_ms_chirho(),
    )
}

fn resource_policy_family_tail_chirho(
    root_chirho: &Path,
) -> Result<Gate1AuthorityFamilyTailChirho> {
    let path_chirho = policy_records_path_chirho(root_chirho);
    let family_count_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
    if family_count_chirho == 0 {
        return Ok(Gate1AuthorityFamilyTailChirho {
            family_count_chirho,
            last_line_chirho: None,
        });
    }
    let family_seq_chirho = family_count_chirho - 1;
    let family_line_chirho = resource_policy_line_at_seq_chirho(root_chirho, family_seq_chirho)?;
    let record_chirho = parse_and_verify_resource_policy_tail_line_chirho(
        root_chirho,
        family_seq_chirho,
        &family_line_chirho,
    )?;
    Ok(Gate1AuthorityFamilyTailChirho {
        family_count_chirho,
        last_line_chirho: Some(Gate1AuthorityFamilyLineChirho {
            family_seq_chirho: record_chirho.seq_chirho,
            family_line_chirho,
        }),
    })
}

fn resource_policy_unset_family_tail_chirho(
    root_chirho: &Path,
) -> Result<Gate1AuthorityFamilyTailChirho> {
    let path_chirho = policy_unset_records_path_chirho(root_chirho);
    let family_count_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
    if family_count_chirho == 0 {
        return Ok(Gate1AuthorityFamilyTailChirho {
            family_count_chirho,
            last_line_chirho: None,
        });
    }
    let family_seq_chirho = family_count_chirho - 1;
    let family_line_chirho =
        resource_policy_unset_line_at_seq_chirho(root_chirho, family_seq_chirho)?;
    let record_chirho = parse_and_verify_resource_policy_unset_tail_line_chirho(
        root_chirho,
        family_seq_chirho,
        &family_line_chirho,
    )?;
    Ok(Gate1AuthorityFamilyTailChirho {
        family_count_chirho,
        last_line_chirho: Some(Gate1AuthorityFamilyLineChirho {
            family_seq_chirho: record_chirho.seq_chirho,
            family_line_chirho,
        }),
    })
}

fn resource_usage_family_tail_chirho(root_chirho: &Path) -> Result<Gate1AuthorityFamilyTailChirho> {
    let path_chirho = usage_records_path_chirho(root_chirho);
    let family_count_chirho = seqlog_chirho::recover_jsonl_len_unlocked_chirho(&path_chirho)?;
    if family_count_chirho == 0 {
        return Ok(Gate1AuthorityFamilyTailChirho {
            family_count_chirho,
            last_line_chirho: None,
        });
    }
    let family_seq_chirho = family_count_chirho - 1;
    // F3 Layer 3: fetch the current tail line via a bounded backward seek (O(last-line length))
    // instead of reading the whole usage log. `recover_jsonl_len_unlocked_chirho` above already
    // repaired any torn/newline-less tail, so the fast reader succeeds on the warm path; it falls back
    // to the full physical-line reader only on an edge case it cannot cleanly isolate, keeping
    // behaviour byte-identical. `parse_and_verify_resource_usage_tail_line_chirho` still binds the line
    // to `family_seq_chirho` and its signature, so a wrong tail can never slip through.
    let family_line_chirho = match read_last_usage_line_tail_chirho(&path_chirho)? {
        Some(family_line_chirho) => family_line_chirho,
        None => resource_usage_line_at_seq_chirho(root_chirho, family_seq_chirho)?,
    };
    let record_chirho = parse_and_verify_resource_usage_tail_line_chirho(
        root_chirho,
        family_seq_chirho,
        &family_line_chirho,
    )?;
    Ok(Gate1AuthorityFamilyTailChirho {
        family_count_chirho,
        last_line_chirho: Some(Gate1AuthorityFamilyLineChirho {
            family_seq_chirho: record_chirho.seq_chirho,
            family_line_chirho,
        }),
    })
}

fn verified_resource_policy_family_lines_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1AuthorityFamilyLineChirho>> {
    let lines_chirho = resource_policy_lines_chirho(root_chirho)?;
    let records_chirho = load_resource_policy_records_chirho(root_chirho)?;
    if lines_chirho.len() != records_chirho.len() {
        bail!("resource policy physical lines do not match parsed records");
    }
    let unset_records_chirho = load_resource_policy_unset_records_chirho(root_chirho)?;
    let usage_records_chirho = load_resource_usage_chirho(root_chirho)?;
    verified_resource_states_from_records_chirho(
        root_chirho,
        false,
        false,
        &records_chirho,
        &unset_records_chirho,
        &usage_records_chirho,
    )?;
    records_chirho
        .iter()
        .zip(lines_chirho)
        .enumerate()
        .map(|(index_chirho, (record_chirho, family_line_chirho))| {
            if record_chirho.seq_chirho != index_chirho as u64 {
                bail!(
                    "resource policy seq gap at index {index_chirho}: entry seq is {}",
                    record_chirho.seq_chirho
                );
            }
            Ok(Gate1AuthorityFamilyLineChirho {
                family_seq_chirho: record_chirho.seq_chirho,
                family_line_chirho,
            })
        })
        .collect()
}

fn verified_resource_policy_unset_family_lines_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1AuthorityFamilyLineChirho>> {
    let lines_chirho = resource_policy_unset_lines_chirho(root_chirho)?;
    let records_chirho = load_resource_policy_unset_records_chirho(root_chirho)?;
    if lines_chirho.len() != records_chirho.len() {
        bail!("resource policy unset physical lines do not match parsed records");
    }
    let policy_records_chirho = load_resource_policy_records_chirho(root_chirho)?;
    let usage_records_chirho = load_resource_usage_chirho(root_chirho)?;
    verified_resource_states_from_records_chirho(
        root_chirho,
        true,
        false,
        &policy_records_chirho,
        &records_chirho,
        &usage_records_chirho,
    )?;
    records_chirho
        .iter()
        .zip(lines_chirho)
        .enumerate()
        .map(|(index_chirho, (record_chirho, family_line_chirho))| {
            if record_chirho.seq_chirho != index_chirho as u64 {
                bail!(
                    "resource policy unset seq gap at index {index_chirho}: entry seq is {}",
                    record_chirho.seq_chirho
                );
            }
            Ok(Gate1AuthorityFamilyLineChirho {
                family_seq_chirho: record_chirho.seq_chirho,
                family_line_chirho,
            })
        })
        .collect()
}

fn verified_resource_usage_family_lines_chirho(
    root_chirho: &Path,
) -> Result<Vec<Gate1AuthorityFamilyLineChirho>> {
    let lines_chirho = resource_usage_lines_chirho(root_chirho)?;
    let records_chirho = load_resource_usage_chirho(root_chirho)?;
    if lines_chirho.len() != records_chirho.len() {
        bail!("resource usage physical lines do not match parsed records");
    }
    let policy_records_chirho = load_resource_policy_records_chirho(root_chirho)?;
    let unset_records_chirho = load_resource_policy_unset_records_chirho(root_chirho)?;
    verified_resource_states_from_records_chirho(
        root_chirho,
        false,
        true,
        &policy_records_chirho,
        &unset_records_chirho,
        &records_chirho,
    )?;
    records_chirho
        .iter()
        .zip(lines_chirho)
        .enumerate()
        .map(|(index_chirho, (record_chirho, family_line_chirho))| {
            if record_chirho.seq_chirho != index_chirho as u64 {
                bail!(
                    "resource usage seq gap at index {index_chirho}: entry seq is {}",
                    record_chirho.seq_chirho
                );
            }
            Ok(Gate1AuthorityFamilyLineChirho {
                family_seq_chirho: record_chirho.seq_chirho,
                family_line_chirho,
            })
        })
        .collect()
}

pub(super) fn resource_policy_lines_chirho(root_chirho: &Path) -> Result<Vec<String>> {
    jsonl_lines_chirho(&policy_records_path_chirho(root_chirho))
}

pub(super) fn resource_policy_unset_lines_chirho(root_chirho: &Path) -> Result<Vec<String>> {
    jsonl_lines_chirho(&policy_unset_records_path_chirho(root_chirho))
}

pub(super) fn resource_usage_lines_chirho(root_chirho: &Path) -> Result<Vec<String>> {
    let lines_chirho = jsonl_lines_chirho(&usage_records_path_chirho(root_chirho))?;
    // F3 scaling guard: this is a whole-file `read_to_string` of the (per-request-growing) usage log.
    // A warm gated append must never reach it — the O(1) checkpoint and the bounded tail reader serve
    // the hot path — so the scaling guard counts it exactly like `load_resource_usage_chirho` and
    // asserts a warm append triggers zero such reads. Only the cold rebuild/backfill path lands here.
    super::note_usage_full_load_chirho(lines_chirho.len() as u64);
    Ok(lines_chirho)
}

fn jsonl_lines_chirho(path_chirho: &Path) -> Result<Vec<String>> {
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(str::to_string)
        .collect())
}

pub(super) fn resource_policy_line_at_seq_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
) -> Result<String> {
    resource_policy_lines_chirho(root_chirho)?
        .into_iter()
        .nth(seq_chirho as usize)
        .ok_or_else(|| anyhow!("resource policy physical line {seq_chirho} missing"))
}

pub(super) fn resource_policy_unset_line_at_seq_chirho(
    root_chirho: &Path,
    seq_chirho: u64,
) -> Result<String> {
    resource_policy_unset_lines_chirho(root_chirho)?
        .into_iter()
        .nth(seq_chirho as usize)
        .ok_or_else(|| anyhow!("resource policy unset physical line {seq_chirho} missing"))
}

fn resource_usage_line_at_seq_chirho(root_chirho: &Path, seq_chirho: u64) -> Result<String> {
    resource_usage_lines_chirho(root_chirho)?
        .into_iter()
        .nth(seq_chirho as usize)
        .ok_or_else(|| anyhow!("resource usage physical line {seq_chirho} missing"))
}

/// Backward-seek chunk size for the usage-log tail reader. Exposed so the F3 scaling guard can pin the
/// tail read to at most one chunk (a per-op constant) regardless of usage-log length.
pub(super) const USAGE_TAIL_SCAN_CHUNK_BYTES_CHIRHO: usize = 8192;

/// F3 Layer 3: read the usage log's last physical line in O(last-line length) via a bounded backward
/// seek — the hot-path replacement for a whole-file `read_to_string` + `.nth(count-1)`.
///
/// Byte-identical to `resource_usage_lines_chirho().last()`: it isolates the bytes after the final
/// interior newline and applies the same `str::lines()` view (strip a lone trailing `\r`) and the same
/// `!trim().is_empty()` non-empty filter. It returns `Ok(None)` — never an error — for every case it
/// cannot cleanly resolve to a single non-empty final line (missing file, empty file, a tail lacking
/// the terminal newline, or a whitespace-only final line), so the caller falls back to the full-scan
/// reader and behaviour is unchanged on every edge case. The caller invokes this only after
/// `recover_jsonl_len_unlocked_chirho` has repaired any torn/newline-less tail, so the warm path never
/// falls back. Cost is counted in bytes (`note_usage_tail_bytes_chirho`) to make the O(window) bound
/// executable.
fn read_last_usage_line_tail_chirho(path_chirho: &Path) -> Result<Option<String>> {
    let mut file_chirho = match File::open(path_chirho) {
        Ok(file_chirho) => file_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
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
    // A single trailing `\n` is the final line's terminator (matching `str::lines()`), not a blank
    // line; only a newline-terminated tail is the fast path, so a torn tail defers to the full reader.
    file_chirho
        .seek(SeekFrom::End(-1))
        .with_context(|| format!("seek {}", path_chirho.display()))?;
    let mut final_byte_chirho = [0u8; 1];
    file_chirho
        .read_exact(&mut final_byte_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    super::note_usage_tail_bytes_chirho(1);
    if final_byte_chirho[0] != b'\n' {
        return Ok(None);
    }
    // Scan backward in bounded chunks for the newline before the final line; everything after it (up to
    // the excluded terminal newline) is that line. Cost is the last line length, not the file length.
    let mut end_chirho = len_chirho - 1;
    let mut chunks_rev_chirho: Vec<Vec<u8>> = Vec::new();
    while end_chirho > 0 {
        let chunk_len_chirho = usize::min(end_chirho as usize, USAGE_TAIL_SCAN_CHUNK_BYTES_CHIRHO);
        let start_chirho = end_chirho - chunk_len_chirho as u64;
        file_chirho
            .seek(SeekFrom::Start(start_chirho))
            .with_context(|| format!("seek {}", path_chirho.display()))?;
        let mut chunk_chirho = vec![0u8; chunk_len_chirho];
        file_chirho
            .read_exact(&mut chunk_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        super::note_usage_tail_bytes_chirho(chunk_len_chirho as u64);
        if let Some(newline_chirho) = chunk_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
        {
            let mut line_bytes_chirho = chunk_chirho[newline_chirho + 1..].to_vec();
            for earlier_chirho in chunks_rev_chirho.iter().rev() {
                line_bytes_chirho.extend_from_slice(earlier_chirho);
            }
            return Ok(finalize_usage_tail_line_chirho(&line_bytes_chirho));
        }
        chunks_rev_chirho.push(chunk_chirho);
        end_chirho = start_chirho;
    }
    // No interior newline: the whole content (minus the terminal newline) is the only line.
    let mut line_bytes_chirho = Vec::new();
    for earlier_chirho in chunks_rev_chirho.iter().rev() {
        line_bytes_chirho.extend_from_slice(earlier_chirho);
    }
    Ok(finalize_usage_tail_line_chirho(&line_bytes_chirho))
}

/// Turn isolated final-line bytes into the exact `str::lines()` + `!trim().is_empty()` view: strip a
/// lone trailing `\r` (the `\n` was already excluded) and reject a whitespace-only line (which the
/// filter drops) by returning `None`, so the caller falls back rather than binding a blank family line.
fn finalize_usage_tail_line_chirho(line_bytes_chirho: &[u8]) -> Option<String> {
    let text_chirho = std::str::from_utf8(line_bytes_chirho).ok()?;
    let text_chirho = text_chirho.strip_suffix('\r').unwrap_or(text_chirho);
    if text_chirho.trim().is_empty() {
        return None;
    }
    Some(text_chirho.to_string())
}

fn parse_and_verify_resource_policy_tail_line_chirho(
    root_chirho: &Path,
    expected_seq_chirho: u64,
    family_line_chirho: &str,
) -> Result<ResourcePolicyRecordChirho> {
    let record_chirho: ResourcePolicyRecordChirho = serde_json::from_str(family_line_chirho)?;
    let schema_chirho = record_chirho.schema_chirho.as_str();
    if !schema_chirho.is_empty()
        && schema_chirho != RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO
        && schema_chirho != RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO
    {
        bail!(
            "resource policy record {} has unsupported schema '{schema_chirho}'",
            record_chirho.seq_chirho
        );
    }
    if record_chirho.seq_chirho != expected_seq_chirho {
        bail!(
            "resource policy tail seq mismatch: got {}, expected {}",
            record_chirho.seq_chirho,
            expected_seq_chirho
        );
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let message_chirho = resource_policy_record_message_chirho(&record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "resource policy record {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(record_chirho)
}

fn parse_and_verify_resource_policy_unset_tail_line_chirho(
    root_chirho: &Path,
    expected_seq_chirho: u64,
    family_line_chirho: &str,
) -> Result<ResourcePolicyUnsetRecordChirho> {
    let record_chirho: ResourcePolicyUnsetRecordChirho = serde_json::from_str(family_line_chirho)?;
    validate_resource_record_schema_chirho(
        &record_chirho.schema_chirho,
        RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO,
        "resource policy unset record",
        record_chirho.seq_chirho,
    )?;
    if record_chirho.seq_chirho != expected_seq_chirho {
        bail!(
            "resource policy unset tail seq mismatch: got {}, expected {}",
            record_chirho.seq_chirho,
            expected_seq_chirho
        );
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let message_chirho = resource_policy_unset_record_message_chirho(&record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "resource policy unset record {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(record_chirho)
}

fn parse_and_verify_resource_usage_tail_line_chirho(
    root_chirho: &Path,
    expected_seq_chirho: u64,
    family_line_chirho: &str,
) -> Result<ResourceUsageRecordChirho> {
    let record_chirho: ResourceUsageRecordChirho = serde_json::from_str(family_line_chirho)?;
    resource_policy_chirho::validate_resource_usage_record_chirho(&record_chirho)?;
    if record_chirho.seq_chirho != expected_seq_chirho {
        bail!(
            "resource usage tail seq mismatch: got {}, expected {}",
            record_chirho.seq_chirho,
            expected_seq_chirho
        );
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let message_chirho = resource_usage_record_message_chirho(&record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "resource usage record {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(record_chirho)
}
