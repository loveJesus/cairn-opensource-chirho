// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! The append-only, signed record of a segmented log's sealed history — one entry per sealed segment.
//!
//! Each entry binds enough to reconstruct and verify the seam: the path-free log identity, the
//! segment's generation and global sequence range, its exact byte length and FULL raw digest (so
//! interior tampering — not just a changed final line — is caught), the prior entry's digest (a hash
//! chain), and the first sequence the NEXT segment must open at. Entries are appended, never
//! rewritten, so the manifest is itself a seqlog-shaped, tamper-evident chain. Verification is
//! authoritative and fail-closed; base-seq derivation is O(1) warm (via the advisory manifest-head)
//! and O(segment-count) cold, and NEVER returns base-0 while sealed artifacts exist.

use crate::segment_chirho::continuity_chirho::{
    verify_manifest_line_chirho, SegmentContinuityPortChirho, SignedSegmentManifestLineChirho,
};
use crate::segment_chirho::manifest_head_chirho::{
    reseed_manifest_head_chirho, try_manifest_head_fast_path_chirho,
};
use crate::segment_chirho::paths_chirho::{SegmentPathsChirho, SEALED_SEGMENT_SUFFIX_CHIRHO};
use crate::segment_chirho::storage_chirho::SegmentStorageChirho;
use crate::segment_chirho::LogIdentityChirho;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Schema tag for a manifest entry. A different value is rejected by `check_intrinsic_chirho`, so an
/// old layout can be safely retired; `deny_unknown_fields` additionally rejects tampered extra keys.
pub const SEGMENT_MANIFEST_ENTRY_SCHEMA_CHIRHO: &str = "segment-manifest-entry-v1-chirho";

/// One sealed segment's immutable record in the manifest. Signed as a whole by the continuity port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentManifestEntryChirho {
    pub schema_chirho: String,
    /// Path-free log identity digest (`LogIdentityChirho::digest_chirho`); identical across a log.
    pub log_identity_digest_chirho: String,
    /// 0-based sealed-segment index; the genesis segment is generation 0.
    pub generation_chirho: u64,
    /// Global sequence of this segment's first record.
    pub first_seq_chirho: u64,
    /// Global sequence of this segment's last record (inclusive).
    pub last_seq_chirho: u64,
    /// Record count; the invariant `last_seq - first_seq + 1` is checked on verify.
    pub record_count_chirho: u64,
    /// Exact sealed segment byte length (the raw file bytes, with line framing).
    pub byte_len_chirho: u64,
    /// blake3 of the FULL raw segment bytes — exact line framing, so any interior edit is caught.
    pub segment_digest_chirho: String,
    /// blake3 of the segment's final physical line — a cheap, redundant seam fact.
    pub final_line_digest_chirho: String,
    /// blake3 of the prior manifest ENTRY's canonical bytes; `None` only for the genesis entry.
    pub prev_entry_digest_chirho: Option<String>,
    /// The global sequence the next segment (or the active file) must open at: `last_seq + 1`.
    pub next_first_seq_chirho: u64,
}

impl SegmentManifestEntryChirho {
    /// blake3 of this entry's canonical bytes — the value the NEXT entry carries as its
    /// `prev_entry_digest_chirho`, forming the manifest's hash chain.
    pub fn entry_digest_chirho(&self) -> Result<String> {
        Ok(blake3::hash(&canonical_manifest_entry_bytes_chirho(self)?)
            .to_hex()
            .to_string())
    }

    /// Structural self-consistency, independent of any neighbour: schema, count arithmetic, the
    /// next-open seam, the non-empty rule, and the genesis rule (generation 0 IFF no prior entry,
    /// opening the log at seq 0).
    pub fn check_intrinsic_chirho(&self) -> Result<()> {
        if self.schema_chirho != SEGMENT_MANIFEST_ENTRY_SCHEMA_CHIRHO {
            return Err(anyhow!(
                "segment manifest entry has wrong schema {:?}",
                self.schema_chirho
            ));
        }
        if self.last_seq_chirho < self.first_seq_chirho {
            return Err(anyhow!(
                "segment manifest entry gen {} has last_seq {} < first_seq {}",
                self.generation_chirho,
                self.last_seq_chirho,
                self.first_seq_chirho
            ));
        }
        let span_chirho = self.last_seq_chirho - self.first_seq_chirho + 1;
        if span_chirho != self.record_count_chirho {
            return Err(anyhow!(
                "segment manifest entry gen {} record_count {} != span {}",
                self.generation_chirho,
                self.record_count_chirho,
                span_chirho
            ));
        }
        if self.next_first_seq_chirho != self.last_seq_chirho + 1 {
            return Err(anyhow!(
                "segment manifest entry gen {} next_first_seq {} != last_seq+1 {}",
                self.generation_chirho,
                self.next_first_seq_chirho,
                self.last_seq_chirho + 1
            ));
        }
        // Genesis rule: generation 0 IFF no prior entry, and it must open the log at seq 0.
        let is_genesis_by_gen_chirho = self.generation_chirho == 0;
        let is_genesis_by_prev_chirho = self.prev_entry_digest_chirho.is_none();
        if is_genesis_by_gen_chirho != is_genesis_by_prev_chirho {
            return Err(anyhow!(
                "segment manifest entry gen {} genesis mismatch: prev_entry_digest present={}",
                self.generation_chirho,
                !is_genesis_by_prev_chirho
            ));
        }
        if is_genesis_by_gen_chirho && self.first_seq_chirho != 0 {
            return Err(anyhow!(
                "genesis segment must open the log at seq 0, not {}",
                self.first_seq_chirho
            ));
        }
        if self.byte_len_chirho == 0 || self.record_count_chirho == 0 {
            return Err(anyhow!(
                "segment manifest entry gen {} seals nothing (bytes {}, records {})",
                self.generation_chirho,
                self.byte_len_chirho,
                self.record_count_chirho
            ));
        }
        Ok(())
    }

    /// Bind this entry's identity to an expected root-pinned identity digest.
    pub fn check_identity_chirho(&self, expected_digest_chirho: &str) -> Result<()> {
        if self.log_identity_digest_chirho != expected_digest_chirho {
            return Err(anyhow!(
                "segment manifest entry gen {} log identity {} != expected {}",
                self.generation_chirho,
                self.log_identity_digest_chirho,
                expected_digest_chirho
            ));
        }
        Ok(())
    }
}

/// Canonical bytes of a manifest entry for hashing and signing: the compact serde-json encoding,
/// identical to what a JSONL line stores (`to_vec == to_string.as_bytes()`), so a stored line and a
/// recomputed entry hash the same value.
pub fn canonical_manifest_entry_bytes_chirho(
    entry_chirho: &SegmentManifestEntryChirho,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(entry_chirho)?)
}

/// Build a well-formed entry for a freshly sealed segment (fills schema, identity, and derived seam
/// fields). The caller guarantees `last_seq >= first_seq`; `check_intrinsic_chirho` re-checks on load.
#[allow(clippy::too_many_arguments)]
pub fn new_segment_manifest_entry_chirho(
    identity_chirho: &LogIdentityChirho,
    generation_chirho: u64,
    first_seq_chirho: u64,
    last_seq_chirho: u64,
    byte_len_chirho: u64,
    segment_digest_chirho: String,
    final_line_digest_chirho: String,
    prev_entry_digest_chirho: Option<String>,
) -> SegmentManifestEntryChirho {
    SegmentManifestEntryChirho {
        schema_chirho: SEGMENT_MANIFEST_ENTRY_SCHEMA_CHIRHO.to_string(),
        log_identity_digest_chirho: identity_chirho.digest_chirho(),
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
        record_count_chirho: last_seq_chirho - first_seq_chirho + 1,
        byte_len_chirho,
        segment_digest_chirho,
        final_line_digest_chirho,
        prev_entry_digest_chirho,
        next_first_seq_chirho: last_seq_chirho + 1,
    }
}

/// A fully verified manifest: the entries in generation order plus the derived base sequence (the
/// global seq the active file's record 0 maps to) and the chain-head digest for the next append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedManifestChirho {
    pub entries_chirho: Vec<SegmentManifestEntryChirho>,
    pub base_seq_chirho: u64,
    pub last_entry_digest_chirho: Option<String>,
}

/// The lean base-sequence result used for seq assignment: the base seq, how many segments are sealed,
/// and the digest the next sealed segment must chain to. Produced warm (checkpoint) or cold (verify).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseSeqChirho {
    pub base_seq_chirho: u64,
    pub sealed_segment_count_chirho: u64,
    pub last_entry_digest_chirho: Option<String>,
}

impl BaseSeqChirho {
    /// The legacy / empty result: no sealed segments, base seq 0 — byte-identical to a single file.
    pub(crate) fn legacy_chirho() -> Self {
        Self {
            base_seq_chirho: 0,
            sealed_segment_count_chirho: 0,
            last_entry_digest_chirho: None,
        }
    }
}

/// Load every signed line of the manifest in order. Assumes a clean manifest tail (rotation recovery
/// repairs a torn tail before this runs); a malformed line fails closed rather than being skipped.
///
/// Mirrors `jsonl_read_chirho::load_serialized_jsonl_chirho` exactly (absent → empty; else parse each
/// non-empty trimmed line), but sources the bytes through storage. It deliberately performs NO
/// torn-tail repair: unlike the active file, a malformed manifest line fails the whole load closed.
pub fn load_manifest_lines_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<Vec<SignedSegmentManifestLineChirho>> {
    let manifest_path_chirho = paths_chirho.manifest_chirho();
    let Some(bytes_chirho) = storage_chirho.read_all_chirho(&manifest_path_chirho)? else {
        return Ok(Vec::new());
    };
    let text_chirho = std::str::from_utf8(&bytes_chirho)
        .with_context(|| format!("read {manifest_path_chirho}"))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| serde_json::from_str(line_chirho).map_err(Into::into))
        .collect()
}

/// Append one signed line to the manifest durably (fsync). The caller holds the append lock and,
/// after the whole transaction commits, re-seeds the advisory manifest-head.
///
/// Routed through the PLAIN durable-append op (`append_durable_chirho`), byte-identical to the prior
/// `append_jsonl_unlocked_chirho` path (`"{json}\n"`, O_APPEND + fsync). This append is torn-able on
/// crash by design; the manifest loader fails closed on a torn tail — it is NEVER atomized here.
pub fn append_signed_manifest_line_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    line_chirho: &SignedSegmentManifestLineChirho,
) -> Result<()> {
    let manifest_path_chirho = paths_chirho.manifest_chirho();
    if let Some(parent_chirho) = manifest_path_chirho.parent_chirho() {
        storage_chirho
            .create_dir_all_chirho(&parent_chirho)
            .with_context(|| format!("create manifest dir {parent_chirho}"))?;
    }
    let line_text_chirho = format!("{}\n", serde_json::to_string(line_chirho)?);
    storage_chirho
        .append_durable_chirho(&manifest_path_chirho, line_text_chirho.as_bytes())
        .with_context(|| format!("append log {manifest_path_chirho}"))
}

/// Verify the full manifest chain against a root-pinned continuity port and expected log identity:
/// every line's signature, each entry's intrinsic shape and identity, dense generations, the
/// prev-entry hash chain, and the checked seq biconditional (`first_seq == prev.last_seq + 1`, which
/// rejects BOTH gaps and overlaps; genesis opens at 0). Any violation fails closed.
pub fn verify_manifest_chain_chirho(
    port_chirho: &dyn SegmentContinuityPortChirho,
    expected_identity_digest_chirho: &str,
    lines_chirho: &[SignedSegmentManifestLineChirho],
) -> Result<VerifiedManifestChirho> {
    crate::segment_chirho::note_manifest_scan_chirho();
    let mut entries_chirho = Vec::with_capacity(lines_chirho.len());
    let mut prev_entry_digest_chirho: Option<String> = None;
    let mut expected_first_seq_chirho: u64 = 0;
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        // Root-pinned signature check → nonconstructible verified token.
        let verified_chirho = verify_manifest_line_chirho(port_chirho, line_chirho)?;
        let entry_chirho = verified_chirho.entry_chirho();
        entry_chirho.check_intrinsic_chirho()?;
        entry_chirho.check_identity_chirho(expected_identity_digest_chirho)?;
        if entry_chirho.generation_chirho != index_chirho as u64 {
            return Err(anyhow!(
                "segment manifest generation {} is out of order at index {}",
                entry_chirho.generation_chirho,
                index_chirho
            ));
        }
        if entry_chirho.prev_entry_digest_chirho != prev_entry_digest_chirho {
            return Err(anyhow!(
                "segment manifest generation {} prev-entry digest breaks the chain",
                entry_chirho.generation_chirho
            ));
        }
        if entry_chirho.first_seq_chirho != expected_first_seq_chirho {
            return Err(anyhow!(
                "segment manifest generation {} first_seq {} != expected {} (gap or overlap)",
                entry_chirho.generation_chirho,
                entry_chirho.first_seq_chirho,
                expected_first_seq_chirho
            ));
        }
        expected_first_seq_chirho = entry_chirho.next_first_seq_chirho;
        prev_entry_digest_chirho = Some(entry_chirho.entry_digest_chirho()?);
        entries_chirho.push(entry_chirho.clone());
    }
    Ok(VerifiedManifestChirho {
        base_seq_chirho: expected_first_seq_chirho,
        last_entry_digest_chirho: prev_entry_digest_chirho,
        entries_chirho,
    })
}

/// Does the sealed-segments directory hold at least one sealed segment file? Used to distinguish a
/// truly legacy (single-file) log from one whose manifest is missing while sealed data still exists.
///
/// `list_dir_chirho` returns direct child regular files (its `is_file` filter matches the original
/// scan) and an empty list for an absent dir, so a child key ending in the sealed suffix is exactly
/// the original "a regular file whose name ends with the suffix".
pub fn segments_dir_has_sealed_files_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
) -> Result<bool> {
    let dir_chirho = paths_chirho.segments_dir_chirho();
    for child_chirho in storage_chirho.list_dir_chirho(&dir_chirho)? {
        if child_chirho
            .as_str_chirho()
            .ends_with(SEALED_SEGMENT_SUFFIX_CHIRHO)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Derive the base sequence for a segmented log: the global seq the active file's record 0 maps to.
///
/// Warm O(1): the advisory manifest-head, trusted only when the manifest file is byte-unchanged.
/// Cold O(segment-count): full manifest scan + verify, then re-seed the head. Safety asymmetry — a
/// MISSING or empty manifest is legacy (base 0) ONLY when zero sealed artifacts exist; artifacts
/// present with no readable manifest fail closed, NEVER base-0 (which would reuse sequences).
pub fn derive_base_seq_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<BaseSeqChirho> {
    // Fail closed if a rotation is mid-flight: the base sequence is minted here, and a warm hit would
    // otherwise trust a base derived while the active file still holds sealed-but-unreset records.
    paths_chirho.refuse_if_pending_rotation_chirho(storage_chirho)?;
    if let Some(base_chirho) = try_manifest_head_fast_path_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        expected_identity_digest_chirho,
    )? {
        return Ok(base_chirho);
    }
    let manifest_path_chirho = paths_chirho.manifest_chirho();
    let has_artifacts_chirho = segments_dir_has_sealed_files_chirho(storage_chirho, paths_chirho)?;
    let lines_chirho = if storage_chirho.exists_chirho(&manifest_path_chirho)? {
        load_manifest_lines_chirho(storage_chirho, paths_chirho)?
    } else {
        Vec::new()
    };
    if lines_chirho.is_empty() {
        if has_artifacts_chirho {
            return Err(anyhow!(
                "sealed segment artifacts exist but segment manifest {} is missing or empty — \
                 refusing base-0 (would reuse sequences)",
                manifest_path_chirho
            ));
        }
        return Ok(BaseSeqChirho::legacy_chirho());
    }
    let verified_chirho =
        verify_manifest_chain_chirho(port_chirho, expected_identity_digest_chirho, &lines_chirho)?;
    let base_chirho = BaseSeqChirho {
        base_seq_chirho: verified_chirho.base_seq_chirho,
        sealed_segment_count_chirho: verified_chirho.entries_chirho.len() as u64,
        last_entry_digest_chirho: verified_chirho.last_entry_digest_chirho.clone(),
    };
    // Advisory re-seed (behind-never-ahead): a failure only costs the next derive another scan.
    let _ = reseed_manifest_head_chirho(storage_chirho, paths_chirho, &base_chirho);
    Ok(base_chirho)
}
