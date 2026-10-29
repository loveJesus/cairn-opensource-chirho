// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! O(1) advisory checkpoint for a segment manifest: warm base-seq derivation without a manifest scan.
//!
//! Mirrors the F1 seqlog-head idea one level up. It proves in O(1) that the MANIFEST file's tail is
//! unchanged (byte length + last-line hash), then locates the manifest's final physical line and —
//! R2, the money-adoption precondition — derives the base from THAT line only after verifying its
//! signature, intrinsic shape, and pinned log identity against the injected root-pinned continuity
//! key. Trust flows from the signed tail line, never from the sidecar: the sidecar is unsigned and
//! attacker-writable, so a forged one could otherwise regress `base_seq` and cause silent sequence
//! reuse at write time. The sidecar's recorded base/count/chain-head are HINTS only, cross-checked
//! against the signed line (any disagreement is a miss). It is ADVISORY: any miss (missing, torn,
//! stale, ahead, tail-mismatched, unparsable/unsigned/foreign tail, or a missing manifest) returns
//! `None` so the caller falls back to the authoritative manifest scan+verify (or the fail-closed
//! artifact check). Like the F1 sidecar it can only ever LAG the manifest, never lead it. The warm
//! path applies the SAME per-line acceptance the cold path does, so it can never accept a tail the
//! cold path would reject; the one unclosed residual is manifest TRUNCATION to a genuine earlier
//! signed line (an external-monotonic-floor concern, the same class as whole-root rollback).
//!
//! (DRY note: the tail-fingerprint primitive below intentionally duplicates the F1 sidecar's; a
//! behaviour-preserving extraction into one shared helper is a deferred follow-up, kept out of this
//! slice to avoid editing the money-adjacent F1 path while the fleet is mid-flight.)

use crate::segment_chirho::continuity_chirho::{
    verify_manifest_line_chirho, SegmentContinuityPortChirho, SignedSegmentManifestLineChirho,
};
use crate::segment_chirho::manifest_chirho::{BaseSeqChirho, SegmentManifestEntryChirho};
use crate::segment_chirho::paths_chirho::SegmentPathsChirho;
use crate::segment_chirho::storage_chirho::{SegmentPathChirho, SegmentStorageChirho};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Schema tag for the manifest-head sidecar; any other value is a miss, so a layout can be retired.
const MANIFEST_HEAD_SCHEMA_CHIRHO: &str = "segment-manifest-head-v1-chirho";
/// Hard cap on the advisory manifest-head sidecar before allocation.
pub const MAX_MANIFEST_HEAD_BYTES_CHIRHO: u64 = 4 * 1024;
/// Hard cap on one authenticated manifest line inspected without the advisory head.
pub const MAX_AUTHENTICATED_MANIFEST_TAIL_LINE_BYTES_CHIRHO: usize = 4 * 1024;
/// Hard cap on an unacknowledged torn manifest suffix retained by read-only inspection.
pub const MAX_AUTHENTICATED_MANIFEST_TORN_BYTES_CHIRHO: usize = 4 * 1024;
const MAX_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO: usize =
    (MAX_AUTHENTICATED_MANIFEST_TAIL_LINE_BYTES_CHIRHO * 2) + 3;
const INITIAL_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO: usize = 1024;

/// The durable manifest-head checkpoint: enough to prove the manifest tail is unchanged, plus the
/// warm values (base seq, sealed count, chain-head digest) trusted once that proof holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentManifestHeadChirho {
    schema_chirho: String,
    manifest_byte_len_chirho: u64,
    last_line_len_chirho: u64,
    last_line_blake3_chirho: String,
    sealed_segment_count_chirho: u64,
    base_seq_chirho: u64,
    last_entry_digest_chirho: Option<String>,
}

/// Direct, bounded verification of the final complete signed manifest line.
///
/// This proof does not trust or require the advisory manifest-head sidecar. A bounded trailing torn
/// append is retained in the snapshot but excluded from the authenticated clean cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedManifestTailSnapshotChirho {
    pub manifest_physical_len_chirho: u64,
    pub manifest_clean_len_chirho: u64,
    pub torn_suffix_len_chirho: u64,
    pub torn_suffix_digest_chirho: Option<String>,
    pub base_chirho: BaseSeqChirho,
    pub entry_chirho: SegmentManifestEntryChirho,
}

/// Bounded bytes from an interrupted first manifest append.
///
/// These bytes are not authority. A held reader may retain them only long enough to prove they are
/// an exact prefix of the signed generation-zero line already installed in the authenticated
/// predecessor index while the rotation marker and bounded active-cut coordinates remain present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntirelyTornManifestTailSnapshotChirho {
    pub manifest_physical_len_chirho: u64,
    pub bytes_digest_chirho: String,
    pub bytes_chirho: Vec<u8>,
}

/// Direct bounded manifest-tail observation for a held, writer-locked recovery cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadOnlyManifestTailSnapshotChirho {
    AuthenticatedChirho(AuthenticatedManifestTailSnapshotChirho),
    EntirelyTornChirho(EntirelyTornManifestTailSnapshotChirho),
}

/// Inspect the final complete manifest line directly, in O(1) lifetime-history cost.
///
/// `None` means the manifest is absent or empty. Malformed, oversized, unsigned, foreign, or
/// entirely torn content is a hard refusal.
pub fn inspect_authenticated_manifest_tail_read_only_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<Option<AuthenticatedManifestTailSnapshotChirho>> {
    match inspect_manifest_tail_for_held_cut_read_only_chirho(
        storage_chirho,
        port_chirho,
        paths_chirho,
        expected_identity_digest_chirho,
    )? {
        None => Ok(None),
        Some(ReadOnlyManifestTailSnapshotChirho::AuthenticatedChirho(snapshot_chirho)) => {
            Ok(Some(snapshot_chirho))
        }
        Some(ReadOnlyManifestTailSnapshotChirho::EntirelyTornChirho(_)) => {
            Err(anyhow!("manifest has no bounded complete signed tail line"))
        }
    }
}

/// Inspect the manifest tail for a writer-locked held recovery cut.
///
/// Unlike the general authenticated-tail reader, this exposes a bounded entirely torn first append
/// as non-authoritative evidence. The held reader must prove that evidence against the rotation
/// marker, active file length plus signed final line, and authenticated predecessor index before
/// deriving a cut.
pub fn inspect_manifest_tail_for_held_cut_read_only_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<Option<ReadOnlyManifestTailSnapshotChirho>> {
    let manifest_path_chirho = paths_chirho.manifest_chirho();
    let Some(physical_len_chirho) = storage_chirho.object_len_chirho(&manifest_path_chirho)? else {
        return Ok(None);
    };
    if physical_len_chirho == 0 {
        return Ok(None);
    }
    let mut requested_chirho = INITIAL_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO
        .min(MAX_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO);
    loop {
        let read_len_chirho = physical_len_chirho.min(requested_chirho as u64);
        let start_chirho = physical_len_chirho - read_len_chirho;
        let bytes_chirho = storage_chirho.read_range_chirho(
            &manifest_path_chirho,
            start_chirho,
            read_len_chirho,
        )?;
        let Some(last_lf_chirho) = bytes_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
        else {
            if start_chirho == 0
                && physical_len_chirho <= MAX_AUTHENTICATED_MANIFEST_TORN_BYTES_CHIRHO as u64
            {
                return Ok(Some(
                    ReadOnlyManifestTailSnapshotChirho::EntirelyTornChirho(
                        EntirelyTornManifestTailSnapshotChirho {
                            manifest_physical_len_chirho: physical_len_chirho,
                            bytes_digest_chirho: blake3::hash(&bytes_chirho).to_hex().to_string(),
                            bytes_chirho,
                        },
                    ),
                ));
            }
            if requested_chirho == MAX_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO {
                return Err(anyhow!("manifest has no bounded complete signed tail line"));
            }
            requested_chirho = requested_chirho
                .saturating_mul(2)
                .min(MAX_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO);
            continue;
        };
        let torn_chirho = &bytes_chirho[last_lf_chirho + 1..];
        if torn_chirho.len() > MAX_AUTHENTICATED_MANIFEST_TORN_BYTES_CHIRHO {
            return Err(anyhow!(
                "manifest torn suffix exceeds {} bytes",
                MAX_AUTHENTICATED_MANIFEST_TORN_BYTES_CHIRHO
            ));
        }
        let line_start_chirho = bytes_chirho[..last_lf_chirho]
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
            .map(|position_chirho| position_chirho + 1);
        let line_start_chirho = match line_start_chirho {
            Some(line_start_chirho) => line_start_chirho,
            None if start_chirho == 0 => 0,
            None if requested_chirho == MAX_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO => {
                return Err(anyhow!(
                    "manifest tail line exceeds {} bytes",
                    MAX_AUTHENTICATED_MANIFEST_TAIL_LINE_BYTES_CHIRHO
                ));
            }
            None => {
                requested_chirho = requested_chirho
                    .saturating_mul(2)
                    .min(MAX_AUTHENTICATED_MANIFEST_TAIL_WINDOW_BYTES_CHIRHO);
                continue;
            }
        };
        let physical_line_chirho = &bytes_chirho[line_start_chirho..=last_lf_chirho];
        if physical_line_chirho.len() > MAX_AUTHENTICATED_MANIFEST_TAIL_LINE_BYTES_CHIRHO + 1 {
            return Err(anyhow!(
                "manifest tail line exceeds {} bytes",
                MAX_AUTHENTICATED_MANIFEST_TAIL_LINE_BYTES_CHIRHO
            ));
        }
        let Some((entry_chirho, entry_digest_chirho)) = authenticated_entry_from_tail_line_chirho(
            port_chirho,
            physical_line_chirho,
            expected_identity_digest_chirho,
        )?
        else {
            return Err(anyhow!(
                "manifest final complete line is not an authenticated entry"
            ));
        };
        return Ok(Some(
            ReadOnlyManifestTailSnapshotChirho::AuthenticatedChirho(
                AuthenticatedManifestTailSnapshotChirho {
                    manifest_physical_len_chirho: physical_len_chirho,
                    manifest_clean_len_chirho: start_chirho + last_lf_chirho as u64 + 1,
                    torn_suffix_len_chirho: torn_chirho.len() as u64,
                    torn_suffix_digest_chirho: (!torn_chirho.is_empty())
                        .then(|| blake3::hash(torn_chirho).to_hex().to_string()),
                    base_chirho: BaseSeqChirho {
                        base_seq_chirho: entry_chirho.next_first_seq_chirho,
                        sealed_segment_count_chirho: entry_chirho.generation_chirho + 1,
                        last_entry_digest_chirho: Some(entry_digest_chirho),
                    },
                    entry_chirho,
                },
            ),
        ));
    }
}

/// Warm O(1) base-seq: return the base sequence only when the manifest file is present, its tail is
/// byte-for-byte the tail this checkpoint was minted for, AND the signed tail line the fingerprint
/// locates verifies against the root-pinned continuity key. A present checkpoint over a MISSING
/// manifest is never trusted (the caller then runs the fail-closed artifact check). Any miss returns
/// `None`.
///
/// R2: the returned base/count/chain-head come from the SIGNED tail line, never from the unsigned
/// sidecar (which a filesystem attacker could forge to regress `base_seq` → silent seq reuse). The
/// fingerprint proves the manifest is unchanged and locates its last physical line; this path then
/// verifies that line's signature, intrinsic shape, and pinned identity — the same per-line acceptance
/// the cold path applies — and cross-checks the sidecar's copies against it (any disagreement is a
/// miss, and the cold path re-derives and self-heals the sidecar). Still one line, one verify → O(1).
pub fn try_manifest_head_fast_path_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    expected_identity_digest_chirho: &str,
) -> Result<Option<BaseSeqChirho>> {
    let manifest_path_chirho = paths_chirho.manifest_chirho();
    // Any metadata failure (a missing manifest included) is an advisory miss, never an error.
    let current_len_chirho = match storage_chirho.object_len_chirho(&manifest_path_chirho) {
        Ok(Some(len_chirho)) => len_chirho,
        _ => return Ok(None),
    };
    // An empty manifest carries no warm base; fall through so the caller resolves legacy vs artifacts.
    if current_len_chirho == 0 {
        return Ok(None);
    }
    let head_path_chirho = paths_chirho.manifest_head_chirho();
    // The sidecar is advisory: any metadata/read failure (absent and oversized included) is a miss.
    let head_len_chirho = match storage_chirho.object_len_chirho(&head_path_chirho) {
        Ok(Some(length_chirho)) if length_chirho <= MAX_MANIFEST_HEAD_BYTES_CHIRHO => length_chirho,
        _ => return Ok(None),
    };
    let head_bytes_chirho =
        match storage_chirho.read_range_chirho(&head_path_chirho, 0, head_len_chirho) {
            Ok(bytes_chirho) => bytes_chirho,
            _ => return Ok(None),
        };
    let head_chirho: SegmentManifestHeadChirho = match serde_json::from_slice(&head_bytes_chirho) {
        Ok(head_chirho) => head_chirho,
        Err(_) => return Ok(None),
    };
    if head_chirho.schema_chirho != MANIFEST_HEAD_SCHEMA_CHIRHO {
        return Ok(None);
    }
    if current_len_chirho != head_chirho.manifest_byte_len_chirho {
        return Ok(None);
    }
    if head_chirho.last_line_len_chirho == 0
        || head_chirho.last_line_len_chirho > current_len_chirho
    {
        return Ok(None);
    }
    // Read the exact tail bytes the fingerprint covers ONCE: hash them to prove the manifest is
    // unchanged, then (R2) parse the SAME bytes as the signed line that trust actually flows from.
    let tail_bytes_chirho = read_tail_bytes_chirho(
        storage_chirho,
        &manifest_path_chirho,
        current_len_chirho,
        head_chirho.last_line_len_chirho,
    )?;
    if blake3::hash(&tail_bytes_chirho).to_hex().to_string() != head_chirho.last_line_blake3_chirho
    {
        return Ok(None);
    }
    // R2: derive the base from the SIGNED tail line, applying the cold path's per-line acceptance.
    let Some(signed_base_chirho) = signed_base_from_tail_line_chirho(
        port_chirho,
        &tail_bytes_chirho,
        expected_identity_digest_chirho,
    )?
    else {
        return Ok(None);
    };
    // The sidecar is a locator only: its money fields must agree with the signed line or it is a
    // miss (the cold path then re-derives authoritatively and re-seeds a correct sidecar).
    if head_chirho.base_seq_chirho != signed_base_chirho.base_seq_chirho
        || head_chirho.sealed_segment_count_chirho != signed_base_chirho.sealed_segment_count_chirho
        || head_chirho.last_entry_digest_chirho != signed_base_chirho.last_entry_digest_chirho
    {
        return Ok(None);
    }
    Ok(Some(signed_base_chirho))
}

/// Parse the manifest's final physical line, verify it against the root-pinned continuity key, and
/// derive the authoritative base from the SIGNED entry. Returns `None` for a line that does not parse,
/// fails the signature/intrinsic/identity checks, or is otherwise not a tail the cold path would
/// accept — the caller then falls through to the fail-closed cold derive. O(1): one line, one verify;
/// it performs no full manifest scan and reads no sealed segment.
fn signed_base_from_tail_line_chirho(
    port_chirho: &dyn SegmentContinuityPortChirho,
    tail_bytes_chirho: &[u8],
    expected_identity_digest_chirho: &str,
) -> Result<Option<BaseSeqChirho>> {
    let Some((entry_chirho, entry_digest_chirho)) = authenticated_entry_from_tail_line_chirho(
        port_chirho,
        tail_bytes_chirho,
        expected_identity_digest_chirho,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(BaseSeqChirho {
        base_seq_chirho: entry_chirho.next_first_seq_chirho,
        sealed_segment_count_chirho: entry_chirho.generation_chirho + 1,
        last_entry_digest_chirho: Some(entry_digest_chirho),
    }))
}

fn authenticated_entry_from_tail_line_chirho(
    port_chirho: &dyn SegmentContinuityPortChirho,
    tail_bytes_chirho: &[u8],
    expected_identity_digest_chirho: &str,
) -> Result<Option<(SegmentManifestEntryChirho, String)>> {
    let line_bytes_chirho = tail_bytes_chirho
        .strip_suffix(b"\n")
        .unwrap_or(tail_bytes_chirho);
    let line_chirho: SignedSegmentManifestLineChirho =
        match serde_json::from_slice(line_bytes_chirho) {
            Ok(line_chirho) => line_chirho,
            Err(_) => return Ok(None),
        };
    let verified_chirho = match verify_manifest_line_chirho(port_chirho, &line_chirho) {
        Ok(verified_chirho) => verified_chirho,
        Err(_) => return Ok(None),
    };
    let entry_chirho = verified_chirho.entry_chirho();
    // Same per-line acceptance the cold path applies (shape + pinned identity); the multi-line chain
    // is the residual trusted from a prior cold verify, exactly like the F1 fast-open covered prefix.
    if entry_chirho.check_intrinsic_chirho().is_err()
        || entry_chirho
            .check_identity_chirho(expected_identity_digest_chirho)
            .is_err()
    {
        return Ok(None);
    }
    let entry_digest_chirho = entry_chirho.entry_digest_chirho()?;
    Ok(Some((entry_chirho.clone(), entry_digest_chirho)))
}

/// Re-seed the checkpoint from the manifest's current durable state and the freshly derived base.
///
/// Call only after the manifest line is written and fsynced (so the checkpoint can only LAG), and
/// only with a base that was just verified (cold path) or just committed (rotation). The write is a
/// durable temp+rename, so a crash mid-write leaves the previous (behind) sidecar or none.
pub fn reseed_manifest_head_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    paths_chirho: &SegmentPathsChirho,
    base_chirho: &BaseSeqChirho,
) -> Result<()> {
    let manifest_path_chirho = paths_chirho.manifest_chirho();
    let fingerprint_chirho =
        manifest_tail_fingerprint_chirho(storage_chirho, &manifest_path_chirho)?;
    let head_chirho = SegmentManifestHeadChirho {
        schema_chirho: MANIFEST_HEAD_SCHEMA_CHIRHO.to_string(),
        manifest_byte_len_chirho: fingerprint_chirho.byte_len_chirho,
        last_line_len_chirho: fingerprint_chirho.last_line_len_chirho,
        last_line_blake3_chirho: fingerprint_chirho.last_line_blake3_chirho,
        sealed_segment_count_chirho: base_chirho.sealed_segment_count_chirho,
        base_seq_chirho: base_chirho.base_seq_chirho,
        last_entry_digest_chirho: base_chirho.last_entry_digest_chirho.clone(),
    };
    let head_path_chirho = paths_chirho.manifest_head_chirho();
    let text_chirho = serde_json::to_string(&head_chirho)
        .with_context(|| format!("encode manifest head {head_path_chirho}"))?;
    storage_chirho
        .write_durable_chirho(&head_path_chirho, text_chirho.as_bytes())
        .with_context(|| format!("write manifest head {head_path_chirho}"))
}

struct ManifestTailFingerprintChirho {
    byte_len_chirho: u64,
    last_line_len_chirho: u64,
    last_line_blake3_chirho: String,
}

fn manifest_tail_fingerprint_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    path_chirho: &SegmentPathChirho,
) -> Result<ManifestTailFingerprintChirho> {
    let byte_len_chirho = storage_chirho
        .object_len_chirho(path_chirho)?
        .ok_or_else(|| anyhow!("manifest {path_chirho} vanished during tail fingerprint"))?;
    if byte_len_chirho == 0 {
        return Ok(ManifestTailFingerprintChirho {
            byte_len_chirho: 0,
            last_line_len_chirho: 0,
            last_line_blake3_chirho: blake3::hash(b"").to_hex().to_string(),
        });
    }
    let last_line_start_chirho =
        last_line_start_chirho(storage_chirho, path_chirho, byte_len_chirho)?;
    let last_line_len_chirho = byte_len_chirho - last_line_start_chirho;
    let buf_chirho = storage_chirho.read_range_chirho(
        path_chirho,
        last_line_start_chirho,
        last_line_len_chirho,
    )?;
    Ok(ManifestTailFingerprintChirho {
        byte_len_chirho,
        last_line_len_chirho,
        last_line_blake3_chirho: blake3::hash(&buf_chirho).to_hex().to_string(),
    })
}

/// Start offset of the final physical line, scanning backwards in bounded 8 KiB chunks (cost = last
/// line length, not file length).
fn last_line_start_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    path_chirho: &SegmentPathChirho,
    byte_len_chirho: u64,
) -> Result<u64> {
    let final_byte_chirho =
        storage_chirho.read_range_chirho(path_chirho, byte_len_chirho - 1, 1)?;
    let mut end_chirho = if final_byte_chirho[0] == b'\n' {
        byte_len_chirho - 1
    } else {
        byte_len_chirho
    };
    while end_chirho > 0 {
        let chunk_len_chirho = usize::min(end_chirho as usize, 8192);
        let start_chirho = end_chirho - chunk_len_chirho as u64;
        let chunk_chirho =
            storage_chirho.read_range_chirho(path_chirho, start_chirho, chunk_len_chirho as u64)?;
        if let Some(newline_chirho) = chunk_chirho
            .iter()
            .rposition(|byte_chirho| *byte_chirho == b'\n')
        {
            return Ok(start_chirho + newline_chirho as u64 + 1);
        }
        end_chirho = start_chirho;
    }
    Ok(0)
}

/// The final `tail_len_chirho` bytes of the file; the caller guarantees `tail_len <= byte_len`. The
/// warm path hashes these for the fingerprint check AND parses them as the signed tail line (R2).
fn read_tail_bytes_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    path_chirho: &SegmentPathChirho,
    byte_len_chirho: u64,
    tail_len_chirho: u64,
) -> Result<Vec<u8>> {
    storage_chirho.read_range_chirho(
        path_chirho,
        byte_len_chirho - tail_len_chirho,
        tail_len_chirho,
    )
}
