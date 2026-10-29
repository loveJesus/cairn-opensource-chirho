// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! READ-ONLY recomposed line stream for a (possibly rotated) journal — the same sealed-history +
//! clean-prefix-active recomposition the verified open replays, with ZERO writes: no rotation
//! recovery (a pending marker REFUSES — `derive_base_seq_chirho` guards it at the mint point),
//! no torn-tail repair (the torn suffix is simply excluded). This function carries NO trust by
//! itself: callers that need verified bytes must BIND the returned lines to a verified open —
//! e.g. the read-model's chain-bound extraction digest walk (genesis digest → prev-binding →
//! verified tail-line digest), which refuses any divergence between this read and the proven
//! chain.

use crate::journal_chirho::{JournalErrorChirho, JournalPortsChirho};
use crate::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;

/// Read the journal's recomposed raw lines (sealed segments first, then the active clean prefix).
/// Read-only; see the module doc for the trust contract.
pub fn read_recomposed_journal_lines_chirho(
    ports_chirho: JournalPortsChirho<'_>,
    path_chirho: &StoragePathChirho,
    cluster_chirho: &ClusterIdChirho,
) -> Result<Vec<String>, JournalErrorChirho> {
    let segment_storage_chirho =
        crate::segment_adapter_chirho::SegmentStorageOverLedgerPortChirho::new_chirho(
            ports_chirho.storage_chirho,
        );
    let segment_continuity_chirho =
        crate::segment_adapter_chirho::SegmentContinuityOverLedgerSignerPortChirho::new_chirho(
            ports_chirho.signer_chirho,
        );
    let segment_paths_chirho =
        cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho::new_chirho(
            path_chirho.key_chirho(),
        );
    let log_identity_chirho = cairn_seqlog_chirho::segment_chirho::LogIdentityChirho::new_chirho(
        format!("cairn-ledger:{}", cluster_chirho.0),
    );
    // Pending rotations refuse INSIDE the base-seq derivation (read-only law: recovery writes,
    // so it belongs to the journal's own open, never to a read path).
    let base_chirho = cairn_seqlog_chirho::segment_chirho::manifest_chirho::derive_base_seq_chirho(
        &segment_storage_chirho,
        &segment_continuity_chirho,
        &segment_paths_chirho,
        &log_identity_chirho.digest_chirho(),
    )
    .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
        detail_chirho: format!("read-only segment base-seq derivation failed: {error_chirho}"),
    })?;
    let sealed_lines_chirho = if base_chirho.base_seq_chirho == 0 {
        Vec::new()
    } else {
        let sealed_chirho =
            cairn_seqlog_chirho::segment_chirho::reader_chirho::load_sealed_raw_jsonl_lines_chirho(
                &segment_storage_chirho,
                &segment_continuity_chirho,
                &segment_paths_chirho,
                &log_identity_chirho.digest_chirho(),
            )
            .map_err(|error_chirho| JournalErrorChirho::ChainChirho {
                detail_chirho: format!("read-only sealed segment walk failed: {error_chirho}"),
            })?;
        if sealed_chirho.len() as u64 != base_chirho.base_seq_chirho {
            return Err(JournalErrorChirho::ChainChirho {
                detail_chirho: format!(
                    "sealed walk returned {} lines but the manifest base seq is {} — refusing \
                     divergent sealed history",
                    sealed_chirho.len(),
                    base_chirho.base_seq_chirho
                ),
            });
        }
        sealed_chirho
    };
    let bytes_chirho = ports_chirho
        .storage_chirho
        .read_all_chirho(path_chirho)
        .map_err(|error_chirho| JournalErrorChirho::StorageChirho {
            detail_chirho: format!("active read failed: {error_chirho}"),
        })?
        .ok_or_else(|| JournalErrorChirho::StorageChirho {
            detail_chirho: "journal object missing".to_owned(),
        })?;
    // The clean prefix ends at the last LF; the torn suffix is EXCLUDED, never repaired here.
    let clean_len_chirho = bytes_chirho
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map(|index_chirho| index_chirho + 1)
        .unwrap_or(0);
    let text_chirho = std::str::from_utf8(&bytes_chirho[..clean_len_chirho]).map_err(|_| {
        JournalErrorChirho::ChainChirho {
            detail_chirho: "journal prefix is not UTF-8".to_owned(),
        }
    })?;
    if base_chirho.base_seq_chirho == 0 && clean_len_chirho == 0 {
        return Err(JournalErrorChirho::ChainChirho {
            detail_chirho: "journal has no clean genesis line".to_owned(),
        });
    }
    let mut lines_chirho = sealed_lines_chirho;
    lines_chirho.extend(
        text_chirho
            .lines()
            .filter(|line_chirho| !line_chirho.trim().is_empty())
            .map(str::to_owned),
    );
    Ok(lines_chirho)
}
