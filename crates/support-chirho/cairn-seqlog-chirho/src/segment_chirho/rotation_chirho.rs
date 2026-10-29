// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Rotation as a crash-recoverable transaction: seal the active file into a signed segment.
//!
//! The active row is already durable before rotation begins, so a rotation failure must NOT turn a
//! committed append into an error (a retry would double-emit money/evidence). Yet the next sequence
//! depends on rotation, so it is not merely advisory either — the next LOCKED recovery finishes or
//! refuses a pending rotation BEFORE returning a sequence. A durable rotation-intent MARKER is written
//! first and deleted last; between them the cuts run in order:
//!   marker -> (A) seal segment file -> (B) write authenticated predecessor object ->
//!   (C) append signed manifest entry + reseed head -> (D) reset active file -> delete marker.
//! The marker carries everything needed to rebuild the manifest entry, and the manifest is the
//! authority recovery consults to learn exactly which cuts already landed. Recovery is idempotent:
//! re-running after completion is a no-op, and any ambiguous state fails closed rather than guessing.
//! The sealed file and predecessor object are content-named, so re-writing identical bytes is
//! idempotent. An index object written before a failed manifest append is unreachable and harmless;
//! a successful manifest append is never allowed to precede its lookup object.

use crate::segment_chirho::continuity_chirho::{
    sign_manifest_entry_chirho, SegmentContinuityPortChirho,
};
use crate::segment_chirho::manifest_chirho::{
    append_signed_manifest_line_chirho, derive_base_seq_chirho, load_manifest_lines_chirho,
    new_segment_manifest_entry_chirho, verify_manifest_chain_chirho, BaseSeqChirho,
    SegmentManifestEntryChirho,
};
use crate::segment_chirho::manifest_head_chirho::reseed_manifest_head_chirho;
use crate::segment_chirho::paths_chirho::SegmentPathsChirho;
use crate::segment_chirho::predecessor_index_chirho::write_predecessor_index_entry_chirho;
use crate::segment_chirho::storage_chirho::SegmentStorageChirho;
use crate::segment_chirho::{final_physical_line_chirho, LogIdentityChirho};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Schema tag for the rotation-intent marker; a wrong tag fails closed rather than being trusted.
const ROTATION_INTENT_SCHEMA_CHIRHO: &str = "segment-rotation-intent-v1-chirho";
pub const MAX_ROTATION_INTENT_BYTES_CHIRHO: u64 = 4 * 1024;

/// The durable rotation-intent marker. Written (and fsynced) FIRST, deleted LAST; while it exists the
/// next locked recovery must finish or refuse the rotation before deriving a sequence. It carries
/// everything needed to rebuild the manifest entry deterministically, so recovery never guesses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationIntentChirho {
    schema_chirho: String,
    log_identity_digest_chirho: String,
    generation_chirho: u64,
    first_seq_chirho: u64,
    last_seq_chirho: u64,
    byte_len_chirho: u64,
    segment_digest_chirho: String,
    final_line_digest_chirho: String,
}

/// Bounded read-only view of a pending rotation marker.
///
/// The marker is not authority; it only classifies which authenticated manifest/active cut must be
/// inspected. Its exact bytes remain part of the caller's retained physical snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadOnlyRotationIntentChirho {
    pub physical_len_chirho: u64,
    pub bytes_digest_chirho: String,
    pub generation_chirho: u64,
    pub first_seq_chirho: u64,
    pub last_seq_chirho: u64,
    pub byte_len_chirho: u64,
    pub segment_digest_chirho: String,
    pub final_line_digest_chirho: String,
}

/// Inspect a pending marker without mutation or a manifest scan. This is the held-cut primitive
/// documented in
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.
pub fn inspect_rotation_intent_read_only_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<Option<ReadOnlyRotationIntentChirho>> {
    let path_chirho = paths_chirho.rotation_marker_chirho();
    let Some(physical_len_chirho) = storage_chirho.object_len_chirho(&path_chirho)? else {
        return Ok(None);
    };
    if physical_len_chirho == 0 || physical_len_chirho > MAX_ROTATION_INTENT_BYTES_CHIRHO {
        return Err(anyhow!(
            "rotation marker length {} exceeds its bounded read contract",
            physical_len_chirho
        ));
    }
    let bytes_chirho = storage_chirho.read_range_chirho(&path_chirho, 0, physical_len_chirho)?;
    let marker_chirho: RotationIntentChirho =
        serde_json::from_slice(&bytes_chirho).context("parse bounded rotation marker")?;
    if serde_json::to_vec(&marker_chirho)? != bytes_chirho {
        return Err(anyhow!("rotation marker is not canonical"));
    }
    if marker_chirho.schema_chirho != ROTATION_INTENT_SCHEMA_CHIRHO
        || marker_chirho.log_identity_digest_chirho != expected_identity_digest_chirho
        || marker_chirho.byte_len_chirho == 0
        || marker_chirho.last_seq_chirho < marker_chirho.first_seq_chirho
        || !is_lower_hex_digest_chirho(&marker_chirho.segment_digest_chirho)
        || !is_lower_hex_digest_chirho(&marker_chirho.final_line_digest_chirho)
    {
        return Err(anyhow!(
            "rotation marker does not satisfy its read-only intrinsic contract"
        ));
    }
    Ok(Some(ReadOnlyRotationIntentChirho {
        physical_len_chirho,
        bytes_digest_chirho: blake3::hash(&bytes_chirho).to_hex().to_string(),
        generation_chirho: marker_chirho.generation_chirho,
        first_seq_chirho: marker_chirho.first_seq_chirho,
        last_seq_chirho: marker_chirho.last_seq_chirho,
        byte_len_chirho: marker_chirho.byte_len_chirho,
        segment_digest_chirho: marker_chirho.segment_digest_chirho,
        final_line_digest_chirho: marker_chirho.final_line_digest_chirho,
    }))
}

/// Outcome of a rotation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotationOutcomeChirho {
    Rotated {
        generation_chirho: u64,
        first_seq_chirho: u64,
        last_seq_chirho: u64,
    },
    NothingToRotate,
}

/// Outcome of a pending-rotation recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotationRecoveryChirho {
    NotPending,
    FinishedReset,
    CompletedForward,
}

/// Seal the current active file into a new signed segment and start a fresh active file.
///
/// The caller holds the append lock. First finishes any pending rotation, then runs the durable cuts.
/// An empty active file is a no-op (`NothingToRotate`).
pub fn rotate_segment_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    identity_chirho: &LogIdentityChirho,
) -> Result<RotationOutcomeChirho> {
    let identity_digest_chirho = identity_chirho.digest_chirho();
    // Never start a new rotation over an in-flight one.
    recover_pending_rotation_chirho(storage_chirho, port_chirho, paths_chirho, identity_chirho)?;

    let base_chirho = derive_base_seq_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        &identity_digest_chirho,
    )?;
    // Deviation #4 (claude2 #4625/#4709): rotation NEVER repairs the active tail — the
    // `SegmentStorageChirho` trait deliberately exposes no truncate, so active-file torn-tail repair
    // stays JOURNAL-owned (the caller repairs via its OWN `LedgerStoragePortChirho` before rotating).
    // We read the active through the PORT and count its COMPLETE JSONL records here; a torn
    // (non-newline-terminated) tail fails CLOSED rather than sealing a partial record — so the whole
    // seal path is port-only and therefore sim-fault-injectable (the RC ii / iii crash-matrix seam).
    let active_bytes_chirho = read_active_bytes_chirho(storage_chirho, paths_chirho)?;
    if active_bytes_chirho
        .last()
        .is_some_and(|last_byte_chirho| *last_byte_chirho != b'\n')
    {
        return Err(anyhow!(
            "active file has a torn tail; the journal must repair it via its LedgerStoragePort \
             before rotation (deviation #4: rotation does not repair)"
        ));
    }
    let active_count_chirho = active_bytes_chirho
        .iter()
        .filter(|byte_chirho| **byte_chirho == b'\n')
        .count() as u64;
    if active_count_chirho == 0 {
        return Ok(RotationOutcomeChirho::NothingToRotate);
    }
    let segment_digest_chirho = blake3::hash(&active_bytes_chirho).to_hex().to_string();
    let final_line_digest_chirho = blake3::hash(final_physical_line_chirho(&active_bytes_chirho))
        .to_hex()
        .to_string();
    let first_seq_chirho = base_chirho.base_seq_chirho;
    let last_seq_chirho = base_chirho.base_seq_chirho + active_count_chirho - 1;
    let generation_chirho = base_chirho.sealed_segment_count_chirho;
    let byte_len_chirho = active_bytes_chirho.len() as u64;

    let marker_chirho = RotationIntentChirho {
        schema_chirho: ROTATION_INTENT_SCHEMA_CHIRHO.to_string(),
        log_identity_digest_chirho: identity_digest_chirho,
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
        byte_len_chirho,
        segment_digest_chirho: segment_digest_chirho.clone(),
        final_line_digest_chirho: final_line_digest_chirho.clone(),
    };
    write_marker_chirho(storage_chirho, paths_chirho, &marker_chirho)?;

    // Cut A — seal (content-named, idempotent).
    write_sealed_segment_chirho(
        storage_chirho,
        paths_chirho,
        &segment_digest_chirho,
        &active_bytes_chirho,
    )?;
    // Cut B — install the authenticated digest-addressed lookup object.
    let entry_chirho = new_segment_manifest_entry_chirho(
        identity_chirho,
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
        byte_len_chirho,
        segment_digest_chirho,
        final_line_digest_chirho,
        base_chirho.last_entry_digest_chirho.clone(),
    );
    let line_chirho = sign_manifest_entry_chirho(port_chirho, &entry_chirho)?;
    let indexed_digest_chirho = write_predecessor_index_entry_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        &line_chirho,
    )?;
    if indexed_digest_chirho != entry_chirho.entry_digest_chirho()? {
        return Err(anyhow!(
            "predecessor index returned a digest different from the manifest entry"
        ));
    }
    // Cut C — append the same signed line to the authoritative manifest, then reseed its advisory
    // head. If this append fails, only an unreachable content-addressed index object remains.
    append_signed_manifest_line_chirho(storage_chirho, paths_chirho, &line_chirho)?;
    let _ = reseed_head_after_entry_chirho(
        storage_chirho,
        paths_chirho,
        &entry_chirho,
        generation_chirho,
    );
    // Cut D — reset the active file to empty.
    reset_active_file_chirho(storage_chirho, paths_chirho)?;
    // Delete the marker last.
    clear_marker_chirho(storage_chirho, paths_chirho)?;

    Ok(RotationOutcomeChirho::Rotated {
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
    })
}

/// Finish or refuse a pending rotation, using the manifest as the authority on how far it got. Safe
/// to call before every sequence derivation; a no-op when no marker exists.
pub fn recover_pending_rotation_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    identity_chirho: &LogIdentityChirho,
) -> Result<RotationRecoveryChirho> {
    if !storage_chirho.exists_chirho(&paths_chirho.rotation_marker_chirho())? {
        return Ok(RotationRecoveryChirho::NotPending);
    }
    let identity_digest_chirho = identity_chirho.digest_chirho();
    let marker_chirho = read_marker_chirho(storage_chirho, paths_chirho)?;
    if marker_chirho.log_identity_digest_chirho != identity_digest_chirho {
        return Err(anyhow!(
            "rotation marker identity does not match this log — fail closed"
        ));
    }
    // The manifest is authoritative: verify it to learn exactly which cuts already landed.
    let lines_chirho = load_manifest_lines_chirho(storage_chirho, paths_chirho)?;
    let verified_chirho =
        verify_manifest_chain_chirho(port_chirho, &identity_digest_chirho, &lines_chirho)?;
    let sealed_count_chirho = verified_chirho.entries_chirho.len() as u64;

    if sealed_count_chirho == marker_chirho.generation_chirho + 1 {
        // The manifest append already landed. Confirm the committed entry matches the marker and
        // ensure its authenticated lookup object exists before finishing the active reset.
        let last_chirho = verified_chirho
            .entries_chirho
            .last()
            .expect("verified manifest with sealed_count > 0 has a last entry");
        if last_chirho.generation_chirho != marker_chirho.generation_chirho
            || last_chirho.segment_digest_chirho != marker_chirho.segment_digest_chirho
            || last_chirho.first_seq_chirho != marker_chirho.first_seq_chirho
            || last_chirho.last_seq_chirho != marker_chirho.last_seq_chirho
        {
            return Err(anyhow!(
                "rotation marker disagrees with the committed manifest entry — fail closed"
            ));
        }
        let last_line_chirho = lines_chirho
            .last()
            .expect("verified manifest with sealed_count > 0 has a signed last line");
        write_predecessor_index_entry_chirho(
            storage_chirho,
            port_chirho,
            paths_chirho,
            last_line_chirho,
        )?;
        finish_cut_c_and_clear_marker_chirho(storage_chirho, paths_chirho, &marker_chirho)?;
        Ok(RotationRecoveryChirho::FinishedReset)
    } else if sealed_count_chirho == marker_chirho.generation_chirho {
        // Cut B has NOT landed; the manifest's next generation is exactly the marker's. Complete it,
        // but only if the active file still holds the exact source bytes the marker sealed.
        if verified_chirho.base_seq_chirho != marker_chirho.first_seq_chirho {
            return Err(anyhow!(
                "rotation marker first_seq {} disagrees with manifest base {} — fail closed",
                marker_chirho.first_seq_chirho,
                verified_chirho.base_seq_chirho
            ));
        }
        let active_bytes_chirho = read_active_bytes_chirho(storage_chirho, paths_chirho)?;
        if blake3::hash(&active_bytes_chirho).to_hex().to_string()
            != marker_chirho.segment_digest_chirho
        {
            return Err(anyhow!(
                "rotation source (active file) no longer matches the marker — fail closed"
            ));
        }
        complete_forward_chirho(
            storage_chirho,
            port_chirho,
            paths_chirho,
            identity_chirho,
            &marker_chirho,
            verified_chirho.last_entry_digest_chirho.clone(),
            &active_bytes_chirho,
        )?;
        Ok(RotationRecoveryChirho::CompletedForward)
    } else {
        Err(anyhow!(
            "rotation marker generation {} is inconsistent with {} sealed segments — fail closed",
            marker_chirho.generation_chirho,
            sealed_count_chirho
        ))
    }
}

/// Cut B is done: reset the active file if it still holds the sealed bytes (else it is already empty),
/// then clear the marker. An active file that is neither the sealed bytes nor empty fails closed.
fn finish_cut_c_and_clear_marker_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    marker_chirho: &RotationIntentChirho,
) -> Result<()> {
    let active_bytes_chirho = read_active_bytes_chirho(storage_chirho, paths_chirho)?;
    if blake3::hash(&active_bytes_chirho).to_hex().to_string()
        == marker_chirho.segment_digest_chirho
    {
        reset_active_file_chirho(storage_chirho, paths_chirho)?;
    } else if !active_bytes_chirho.is_empty() {
        return Err(anyhow!(
            "active file is neither the sealed bytes nor empty during rotation reset — fail closed"
        ));
    }
    clear_marker_chirho(storage_chirho, paths_chirho)
}

/// Cut B has not landed: ensure the sealed file exists, append the manifest entry, reset the active
/// file, and clear the marker. The rebuilt entry is deterministic from the marker plus the manifest's
/// current chain head, so it is byte-identical to the one the interrupted rotation would have written.
fn complete_forward_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    identity_chirho: &LogIdentityChirho,
    marker_chirho: &RotationIntentChirho,
    prev_entry_digest_chirho: Option<String>,
    active_bytes_chirho: &[u8],
) -> Result<()> {
    let sealed_path_chirho =
        paths_chirho.sealed_segment_chirho(&marker_chirho.segment_digest_chirho);
    if storage_chirho.exists_chirho(&sealed_path_chirho)? {
        let existing_chirho = storage_chirho
            .read_all_chirho(&sealed_path_chirho)?
            .ok_or_else(|| anyhow!("read sealed segment {sealed_path_chirho}"))?;
        if blake3::hash(&existing_chirho).to_hex().to_string()
            != marker_chirho.segment_digest_chirho
        {
            return Err(anyhow!(
                "existing sealed file digest mismatch during rotation recovery — fail closed"
            ));
        }
    } else {
        write_sealed_segment_chirho(
            storage_chirho,
            paths_chirho,
            &marker_chirho.segment_digest_chirho,
            active_bytes_chirho,
        )?;
    }
    let entry_chirho = new_segment_manifest_entry_chirho(
        identity_chirho,
        marker_chirho.generation_chirho,
        marker_chirho.first_seq_chirho,
        marker_chirho.last_seq_chirho,
        marker_chirho.byte_len_chirho,
        marker_chirho.segment_digest_chirho.clone(),
        marker_chirho.final_line_digest_chirho.clone(),
        prev_entry_digest_chirho,
    );
    let line_chirho = sign_manifest_entry_chirho(port_chirho, &entry_chirho)?;
    write_predecessor_index_entry_chirho(storage_chirho, port_chirho, paths_chirho, &line_chirho)?;
    append_signed_manifest_line_chirho(storage_chirho, paths_chirho, &line_chirho)?;
    let _ = reseed_head_after_entry_chirho(
        storage_chirho,
        paths_chirho,
        &entry_chirho,
        marker_chirho.generation_chirho,
    );
    reset_active_file_chirho(storage_chirho, paths_chirho)?;
    clear_marker_chirho(storage_chirho, paths_chirho)
}

/// Advisory: re-seed the manifest-head to the post-append state (behind-never-ahead; a failure only
/// costs the next derive a cold scan).
fn reseed_head_after_entry_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    entry_chirho: &SegmentManifestEntryChirho,
    generation_chirho: u64,
) -> Result<()> {
    let base_chirho = BaseSeqChirho {
        base_seq_chirho: entry_chirho.next_first_seq_chirho,
        sealed_segment_count_chirho: generation_chirho + 1,
        last_entry_digest_chirho: Some(entry_chirho.entry_digest_chirho()?),
    };
    reseed_manifest_head_chirho(storage_chirho, paths_chirho, &base_chirho)
}

fn read_active_bytes_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<Vec<u8>> {
    // `read_all_chirho` returns `None` iff the active file is absent, exactly the old
    // `if active.exists() { read } else { empty }`.
    Ok(storage_chirho
        .read_all_chirho(&paths_chirho.active_chirho())?
        .unwrap_or_default())
}

fn reset_active_file_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<()> {
    let active_key_chirho = paths_chirho.active_chirho();
    storage_chirho
        .write_durable_chirho(&active_key_chirho, b"")
        .with_context(|| format!("reset active log {active_key_chirho} to empty"))?;
    // Keep the old F1 head sidecar as an advisory miss. Its byte-length/tail fingerprint binds the
    // pre-reset active bytes, so the empty active cannot satisfy it; the next recover rescans and
    // re-seeds. Retaining this already-invalid object makes room for the new predecessor-index write
    // without increasing the established seven-durable-call rotation ceiling.
    Ok(())
}

fn write_sealed_segment_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    segment_digest_chirho: &str,
    bytes_chirho: &[u8],
) -> Result<()> {
    let sealed_path_chirho = paths_chirho.sealed_segment_chirho(segment_digest_chirho);
    if let Some(parent_chirho) = sealed_path_chirho.parent_chirho() {
        storage_chirho
            .create_dir_all_chirho(&parent_chirho)
            .with_context(|| format!("create segments dir {parent_chirho}"))?;
    }
    storage_chirho
        .write_durable_chirho(&sealed_path_chirho, bytes_chirho)
        .with_context(|| format!("seal segment {sealed_path_chirho}"))
}

fn write_marker_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    marker_chirho: &RotationIntentChirho,
) -> Result<()> {
    let marker_path_chirho = paths_chirho.rotation_marker_chirho();
    if let Some(parent_chirho) = marker_path_chirho.parent_chirho() {
        storage_chirho
            .create_dir_all_chirho(&parent_chirho)
            .with_context(|| format!("create marker dir {parent_chirho}"))?;
    }
    let text_chirho = serde_json::to_string(marker_chirho)
        .with_context(|| format!("encode rotation marker {marker_path_chirho}"))?;
    storage_chirho
        .write_durable_chirho(&marker_path_chirho, text_chirho.as_bytes())
        .with_context(|| format!("write rotation marker {marker_path_chirho}"))
}

fn read_marker_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<RotationIntentChirho> {
    let marker_path_chirho = paths_chirho.rotation_marker_chirho();
    let marker_len_chirho = storage_chirho
        .object_len_chirho(&marker_path_chirho)?
        .ok_or_else(|| anyhow!("read rotation marker {marker_path_chirho}"))?;
    if marker_len_chirho == 0 || marker_len_chirho > MAX_ROTATION_INTENT_BYTES_CHIRHO {
        return Err(anyhow!(
            "rotation marker {marker_path_chirho} exceeds its bounded read contract"
        ));
    }
    let bytes_chirho =
        storage_chirho.read_range_chirho(&marker_path_chirho, 0, marker_len_chirho)?;
    let marker_chirho: RotationIntentChirho = serde_json::from_slice(&bytes_chirho)
        .with_context(|| format!("parse rotation marker {marker_path_chirho}"))?;
    if serde_json::to_vec(&marker_chirho)? != bytes_chirho
        || marker_chirho.schema_chirho != ROTATION_INTENT_SCHEMA_CHIRHO
    {
        return Err(anyhow!(
            "rotation marker has wrong schema or encoding {:?} — fail closed",
            marker_chirho.schema_chirho
        ));
    }
    Ok(marker_chirho)
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .as_bytes()
            .iter()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(byte_chirho))
}

fn clear_marker_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<()> {
    let marker_path_chirho = paths_chirho.rotation_marker_chirho();
    // `remove_chirho` is idempotent (a missing marker is a no-op), matching the old explicit
    // NotFound-is-Ok handling.
    storage_chirho
        .remove_chirho(&marker_path_chirho)
        .with_context(|| format!("clear rotation marker {marker_path_chirho}"))
}

/// A test-only view of the marker file so the crash-matrix tests can construct partial-rotation
/// states directly. Not part of the production surface.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_test_marker_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    identity_chirho: &LogIdentityChirho,
    generation_chirho: u64,
    first_seq_chirho: u64,
    last_seq_chirho: u64,
    byte_len_chirho: u64,
    segment_digest_chirho: &str,
    final_line_digest_chirho: &str,
) -> Result<()> {
    let marker_chirho = RotationIntentChirho {
        schema_chirho: ROTATION_INTENT_SCHEMA_CHIRHO.to_string(),
        log_identity_digest_chirho: identity_chirho.digest_chirho(),
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
        byte_len_chirho,
        segment_digest_chirho: segment_digest_chirho.to_string(),
        final_line_digest_chirho: final_line_digest_chirho.to_string(),
    };
    write_marker_chirho(storage_chirho, paths_chirho, &marker_chirho)
}
