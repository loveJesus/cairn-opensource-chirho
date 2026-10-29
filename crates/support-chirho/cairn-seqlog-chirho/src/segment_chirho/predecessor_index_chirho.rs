// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Authenticated O(1)-expected lookup for one signed segment-manifest entry by entry digest.
//!
//! Rotation writes this immutable object before appending the same signed line to the manifest. A
//! crash before the manifest append can therefore leave only an unreachable content-addressed
//! object; the unsafe inverse state (committed manifest entry without its lookup object) is never a
//! successful rotation cut. Readers verify canonical bytes, the digest-addressed coordinate, the
//! root-pinned signature, intrinsic entry laws, and the expected log identity before returning.

use crate::segment_chirho::continuity_chirho::{
    verify_manifest_line_chirho, SegmentContinuityPortChirho, SignedSegmentManifestLineChirho,
};
use crate::segment_chirho::paths_chirho::SegmentPathsChirho;
use crate::segment_chirho::storage_chirho::SegmentStorageChirho;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// The immutable sidecar's schema. Existing manifest and sealed-segment wire bytes remain unchanged.
pub const SEGMENT_PREDECESSOR_INDEX_SCHEMA_CHIRHO: &str =
    "segment-predecessor-index-entry-v1-chirho";
/// Hard allocation/read ceiling for one index object.
pub const MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO: u64 = 64 * 1024;
const BLAKE3_HEX_DIGEST_BYTES_CHIRHO: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentPredecessorIndexObjectChirho {
    schema_chirho: String,
    manifest_entry_digest_chirho: String,
    signed_manifest_line_chirho: SignedSegmentManifestLineChirho,
}

fn is_canonical_blake3_digest_chirho(digest_chirho: &str) -> bool {
    digest_chirho.len() == BLAKE3_HEX_DIGEST_BYTES_CHIRHO
        && digest_chirho
            .as_bytes()
            .iter()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(byte_chirho))
}

fn validate_digest_chirho(digest_chirho: &str) -> Result<()> {
    if !is_canonical_blake3_digest_chirho(digest_chirho) {
        return Err(anyhow!(
            "segment predecessor index digest is not canonical lowercase blake3 hex"
        ));
    }
    Ok(())
}

fn canonical_object_bytes_chirho(
    object_chirho: &SegmentPredecessorIndexObjectChirho,
) -> Result<Vec<u8>> {
    serde_json::to_vec(object_chirho).context("encode segment predecessor index object")
}

fn decode_verified_object_chirho(
    bytes_chirho: &[u8],
    port_chirho: &dyn SegmentContinuityPortChirho,
    requested_digest_chirho: &str,
    expected_identity_digest_chirho: &str,
) -> Result<SignedSegmentManifestLineChirho> {
    if bytes_chirho.len() as u64 > MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO {
        return Err(anyhow!(
            "segment predecessor index object exceeds {} bytes",
            MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO
        ));
    }
    let object_chirho: SegmentPredecessorIndexObjectChirho =
        serde_json::from_slice(bytes_chirho).context("parse segment predecessor index object")?;
    if canonical_object_bytes_chirho(&object_chirho)? != bytes_chirho {
        return Err(anyhow!(
            "segment predecessor index object is not canonical JSON"
        ));
    }
    if object_chirho.schema_chirho != SEGMENT_PREDECESSOR_INDEX_SCHEMA_CHIRHO {
        return Err(anyhow!(
            "segment predecessor index object has wrong schema {:?}",
            object_chirho.schema_chirho
        ));
    }
    if object_chirho.manifest_entry_digest_chirho != requested_digest_chirho {
        return Err(anyhow!(
            "segment predecessor index coordinate does not match requested digest"
        ));
    }
    let verified_chirho =
        verify_manifest_line_chirho(port_chirho, &object_chirho.signed_manifest_line_chirho)
            .context("verify segment predecessor index signature")?;
    let entry_chirho = verified_chirho.entry_chirho();
    entry_chirho.check_intrinsic_chirho()?;
    entry_chirho.check_identity_chirho(expected_identity_digest_chirho)?;
    if entry_chirho.entry_digest_chirho()? != requested_digest_chirho {
        return Err(anyhow!(
            "segment predecessor index path digest does not name its signed entry"
        ));
    }
    Ok(object_chirho.signed_manifest_line_chirho)
}

/// Durably install one signed entry under its canonical entry digest.
///
/// Existing identical bytes are accepted idempotently. Existing different bytes at the same digest
/// fail closed rather than being overwritten.
pub fn write_predecessor_index_entry_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    line_chirho: &SignedSegmentManifestLineChirho,
) -> Result<String> {
    let verified_chirho = verify_manifest_line_chirho(port_chirho, line_chirho)
        .context("verify predecessor entry before durable write")?;
    let entry_chirho = verified_chirho.entry_chirho();
    entry_chirho.check_intrinsic_chirho()?;
    let entry_digest_chirho = entry_chirho.entry_digest_chirho()?;
    validate_digest_chirho(&entry_digest_chirho)?;
    let object_chirho = SegmentPredecessorIndexObjectChirho {
        schema_chirho: SEGMENT_PREDECESSOR_INDEX_SCHEMA_CHIRHO.to_owned(),
        manifest_entry_digest_chirho: entry_digest_chirho.clone(),
        signed_manifest_line_chirho: line_chirho.clone(),
    };
    let bytes_chirho = canonical_object_bytes_chirho(&object_chirho)?;
    if bytes_chirho.len() as u64 > MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO {
        return Err(anyhow!(
            "segment predecessor index object would exceed {} bytes",
            MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO
        ));
    }
    let path_chirho = paths_chirho.predecessor_index_entry_chirho(&entry_digest_chirho);
    if let Some(existing_len_chirho) = storage_chirho.object_len_chirho(&path_chirho)? {
        if existing_len_chirho > MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO {
            return Err(anyhow!(
                "existing segment predecessor index object exceeds the byte ceiling"
            ));
        }
        let existing_chirho =
            storage_chirho.read_range_chirho(&path_chirho, 0, existing_len_chirho)?;
        let existing_line_chirho = decode_verified_object_chirho(
            &existing_chirho,
            port_chirho,
            &entry_digest_chirho,
            &entry_chirho.log_identity_digest_chirho,
        )?;
        if existing_line_chirho != *line_chirho || existing_chirho != bytes_chirho {
            return Err(anyhow!(
                "segment predecessor index digest already names different bytes"
            ));
        }
        return Ok(entry_digest_chirho);
    }
    if let Some(parent_chirho) = path_chirho.parent_chirho() {
        storage_chirho
            .create_dir_all_chirho(&parent_chirho)
            .with_context(|| format!("create predecessor index dir {parent_chirho}"))?;
    }
    storage_chirho
        .write_durable_chirho(&path_chirho, &bytes_chirho)
        .with_context(|| format!("write predecessor index entry {path_chirho}"))?;
    Ok(entry_digest_chirho)
}

/// Resolve and authenticate one manifest entry by digest with one length lookup and one exact read.
pub fn load_predecessor_index_entry_chirho(
    storage_chirho: &dyn SegmentStorageChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    paths_chirho: &SegmentPathsChirho,
    requested_digest_chirho: &str,
    expected_identity_digest_chirho: &str,
) -> Result<SignedSegmentManifestLineChirho> {
    validate_digest_chirho(requested_digest_chirho)?;
    let path_chirho = paths_chirho.predecessor_index_entry_chirho(requested_digest_chirho);
    let len_chirho = storage_chirho
        .object_len_chirho(&path_chirho)?
        .ok_or_else(|| anyhow!("segment predecessor index entry is missing"))?;
    if len_chirho == 0 || len_chirho > MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO {
        return Err(anyhow!(
            "segment predecessor index object length {len_chirho} is outside 1..={}",
            MAX_SEGMENT_PREDECESSOR_INDEX_BYTES_CHIRHO
        ));
    }
    let bytes_chirho = storage_chirho
        .read_range_chirho(&path_chirho, 0, len_chirho)
        .with_context(|| format!("read predecessor index entry {path_chirho}"))?;
    decode_verified_object_chirho(
        &bytes_chirho,
        port_chirho,
        requested_digest_chirho,
        expected_identity_digest_chirho,
    )
}
