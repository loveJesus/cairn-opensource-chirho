// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The central segmented virtual reader: recompose sealed segments plus the active file as one log.
//!
//! This is the single abstraction a family adopts (slice 1B) so its append AND every authoritative
//! reader see the same virtual log. It verifies SEGMENTATION continuity — the signed manifest chain,
//! and each sealed segment's full raw digest, byte length, and record count — then hands back the
//! recomposed records as if the log had never been split. Continuity is MECHANISM evidence only: it
//! proves the bytes are a signed, contiguous, untampered sequence, NOT that they satisfy a family's
//! own record-chain authority (e.g. a money log's prev-digest law); that verification runs on top,
//! on the recomposed records. Reading history is O(total bytes) by nature; only base-seq derivation
//! (used for seq assignment) is O(1) warm. Every byte — sealed segments AND the active file — is
//! read through the storage PORT (sim-driveable, deviation #4): the reader never repairs a torn
//! active tail, it fails closed; repair belongs to the active file's one owner (the adopting
//! journal/family recovery).

use crate::segment_chirho::continuity_chirho::SegmentContinuityPortChirho;
use crate::segment_chirho::manifest_chirho::{
    derive_base_seq_chirho, load_manifest_lines_chirho, segments_dir_has_sealed_files_chirho,
    verify_manifest_chain_chirho,
};
use crate::segment_chirho::note_segment_read_chirho;
use crate::segment_chirho::paths_chirho::SegmentPathsChirho;
use crate::segment_chirho::storage_chirho::SegmentStorageChirho;
use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;

/// Read the active file through the storage port, refusing a torn (non-newline-terminated) tail.
/// Deviation #4: torn-tail REPAIR belongs to the active file's one owner (the adopting journal or
/// family recovery, e.g. via its `LedgerStoragePortChirho`); this reader never mutates, so an
/// unrepaired tail fails closed here instead of being silently accepted or re-repaired. A missing
/// active file is a never-appended log (`None`). A rotation-bounded active keeps this read
/// O(window), never O(total history).
fn read_repaired_active_bytes_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<Option<Vec<u8>>> {
    let Some(bytes_chirho) = storage_chirho.read_all_chirho(&paths_chirho.active_chirho())? else {
        return Ok(None);
    };
    if bytes_chirho
        .last()
        .is_some_and(|byte_chirho| *byte_chirho != b'\n')
    {
        return Err(anyhow!(
            "active file has a torn tail; the owning journal/family must repair it via its own \
             storage port before segmented reads (deviation #4: the reader does not repair)"
        ));
    }
    Ok(Some(bytes_chirho))
}

/// Derive the next global sequence for a segmented log: base seq (warm O(1) via the manifest-head,
/// else cold verify) plus the active file's complete-record count, read through the storage port
/// (torn tail = fail closed; the owner repairs first). The caller holds the append lock.
pub fn segmented_recover_len_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<u64> {
    // derive_base_seq_chirho itself refuses a pending rotation, so a direct call here is guarded too.
    let base_chirho = derive_base_seq_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        expected_identity_digest_chirho,
    )?;
    let active_count_chirho = match read_repaired_active_bytes_chirho(storage_chirho, paths_chirho)?
    {
        Some(bytes_chirho) => bytes_chirho
            .iter()
            .filter(|byte_chirho| **byte_chirho == b'\n')
            .count() as u64,
        None => 0,
    };
    Ok(base_chirho.base_seq_chirho + active_count_chirho)
}

/// Load ONLY the verified sealed history as RAW complete JSONL lines (each without its trailing
/// LF): the signed manifest chain, then per-segment digest + byte-length + line-count checks, in
/// generation order. The ACTIVE file is deliberately NOT read here — an adopting journal that owns
/// active-tail repair (deviation #4) reads/repairs its active itself and recomposes
/// `sealed + clean-active` before replaying; the combined loaders below add the fail-closed active
/// read for shapes with no repair authority. Refuses a pending rotation. An unrotated log (no
/// manifest, no sealed artifacts) has empty sealed history.
pub fn load_sealed_raw_jsonl_lines_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<Vec<String>> {
    paths_chirho.refuse_if_pending_rotation_chirho(storage_chirho)?;
    let lines_chirho = load_manifest_lines_chirho(storage_chirho, paths_chirho)?;
    let mut raw_lines_chirho: Vec<String> = Vec::new();
    if lines_chirho.is_empty() {
        if segments_dir_has_sealed_files_chirho(storage_chirho, paths_chirho)? {
            return Err(anyhow!(
                "sealed segment artifacts exist but the manifest is missing or empty — fail closed"
            ));
        }
        // Legacy single-file log: no sealed history.
    } else {
        let verified_chirho = verify_manifest_chain_chirho(
            port_chirho,
            expected_identity_digest_chirho,
            &lines_chirho,
        )?;
        for entry_chirho in &verified_chirho.entries_chirho {
            let sealed_path_chirho =
                paths_chirho.sealed_segment_chirho(&entry_chirho.segment_digest_chirho);
            let raw_chirho = storage_chirho
                .read_all_chirho(&sealed_path_chirho)?
                .ok_or_else(|| {
                    anyhow!(
                        "read sealed segment gen {} at {}",
                        entry_chirho.generation_chirho,
                        sealed_path_chirho
                    )
                })?;
            note_segment_read_chirho();
            let digest_chirho = blake3::hash(&raw_chirho).to_hex().to_string();
            if digest_chirho != entry_chirho.segment_digest_chirho {
                return Err(anyhow!(
                    "sealed segment gen {} digest mismatch — refusing tampered history",
                    entry_chirho.generation_chirho
                ));
            }
            if raw_chirho.len() as u64 != entry_chirho.byte_len_chirho {
                return Err(anyhow!(
                    "sealed segment gen {} byte length {} != manifest {}",
                    entry_chirho.generation_chirho,
                    raw_chirho.len(),
                    entry_chirho.byte_len_chirho
                ));
            }
            let segment_lines_chirho = complete_jsonl_lines_chirho(&raw_chirho)?;
            if segment_lines_chirho.len() as u64 != entry_chirho.record_count_chirho {
                return Err(anyhow!(
                    "sealed segment gen {} parsed {} records != manifest {}",
                    entry_chirho.generation_chirho,
                    segment_lines_chirho.len(),
                    entry_chirho.record_count_chirho
                ));
            }
            raw_lines_chirho.extend(segment_lines_chirho);
        }
    }
    Ok(raw_lines_chirho)
}

/// Load the whole virtual log as RAW complete JSONL lines: the verified sealed history, then the
/// active tail through the port (torn tail = fail closed — for shapes with no repair authority;
/// the owning journal uses [`load_sealed_raw_jsonl_lines_chirho`] plus its own repaired active).
/// Line 0 is the family's genesis — in the FIRST SEALED SEGMENT once the log has rotated.
pub fn load_segmented_raw_jsonl_lines_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<Vec<String>> {
    let mut raw_lines_chirho = load_sealed_raw_jsonl_lines_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        expected_identity_digest_chirho,
    )?;
    // The active tail rides the same port read + fail-closed torn contract as every read above.
    if let Some(active_bytes_chirho) =
        read_repaired_active_bytes_chirho(storage_chirho, paths_chirho)?
    {
        raw_lines_chirho.extend(complete_jsonl_lines_chirho(&active_bytes_chirho)?);
    }
    Ok(raw_lines_chirho)
}

/// Load the whole virtual log as typed records: the verified raw-line walk, deserialized exactly as
/// a single unsplit log would be. One walk, one verification — the typed shape only adds parsing.
pub fn load_segmented_serialized_jsonl_chirho<T: DeserializeOwned>(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<Vec<T>> {
    load_segmented_raw_jsonl_lines_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        expected_identity_digest_chirho,
    )?
    .iter()
    .map(|line_chirho| serde_json::from_str(line_chirho).map_err(Into::into))
    .collect()
}

/// Split verified segment/active bytes into complete non-empty JSONL lines. No parsing — the
/// caller owns line semantics (serde for the typed loader; strict wire parse for the money journal).
fn complete_jsonl_lines_chirho(bytes_chirho: &[u8]) -> Result<Vec<String>> {
    let text_chirho =
        std::str::from_utf8(bytes_chirho).context("segment bytes are not valid utf-8")?;
    Ok(text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(str::to_owned)
        .collect())
}
