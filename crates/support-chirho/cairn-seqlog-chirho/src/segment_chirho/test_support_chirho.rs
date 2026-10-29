// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Shared segment-test fixtures: the deterministic continuity port, synthetic seal/record
//! builders, and the active/manifest seeders every segment test module reuses.

//! Synthetic-family regression for the segmented-log foundation (RC4 slice 1A). All tests drive a
//! test continuity port (a root-pinned keyed-blake3 MAC) and synthetic records — there is no
//! production rotation caller. Grows increment by increment: Inc 1 pins identity + entry shape +
//! the injected signing boundary and its nonconstructible verified token.

use super::continuity_chirho::{
    sign_manifest_entry_chirho, SegmentContinuityPortChirho, SegmentSignatureChirho,
};
use super::manifest_chirho::{
    append_signed_manifest_line_chirho, new_segment_manifest_entry_chirho,
    SegmentManifestEntryChirho,
};
use super::paths_chirho::SegmentPathsChirho;
use super::storage_chirho::FsSegmentStorageChirho;
use super::LogIdentityChirho;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A test continuity port: a keyed-blake3 MAC over the canonical entry bytes. The key is the
/// root-pinned trust (held inside the port); verification recomputes and compares. This models a real
/// injected signer (a family would use ed25519) without adding a crypto dependency to seqlog.
pub(crate) struct TestContinuityPortChirho {
    key_chirho: [u8; 32],
    key_id_chirho: String,
}

impl TestContinuityPortChirho {
    pub(crate) fn new_chirho() -> Self {
        Self::with_key_chirho(
            b"cairn-segment-test-continuity-key-chirho",
            "test-key-1-chirho",
        )
    }

    pub(crate) fn with_key_chirho(seed_chirho: &[u8], key_id_chirho: &str) -> Self {
        Self {
            key_chirho: *blake3::hash(seed_chirho).as_bytes(),
            key_id_chirho: key_id_chirho.to_string(),
        }
    }
}

impl SegmentContinuityPortChirho for TestContinuityPortChirho {
    fn sign_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
    ) -> Result<SegmentSignatureChirho> {
        Ok(SegmentSignatureChirho(
            blake3::keyed_hash(&self.key_chirho, canonical_bytes_chirho)
                .to_hex()
                .to_string(),
        ))
    }

    fn verify_canonical_chirho(
        &self,
        canonical_bytes_chirho: &[u8],
        signature_chirho: &SegmentSignatureChirho,
    ) -> Result<()> {
        let expected_chirho = blake3::keyed_hash(&self.key_chirho, canonical_bytes_chirho)
            .to_hex()
            .to_string();
        if expected_chirho == signature_chirho.0 {
            Ok(())
        } else {
            Err(anyhow!("test continuity signature mismatch"))
        }
    }

    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }
}

pub(crate) fn sample_genesis_entry_chirho(
    identity_chirho: &LogIdentityChirho,
) -> SegmentManifestEntryChirho {
    new_segment_manifest_entry_chirho(
        identity_chirho,
        0,
        0,
        1,
        24,
        blake3::hash(b"seg-bytes-chirho").to_hex().to_string(),
        blake3::hash(b"last-line-chirho").to_hex().to_string(),
        None,
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SegTestRecordChirho {
    pub(crate) seq_chirho: u64,
    pub(crate) value_chirho: u64,
}

pub(crate) fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-segment-test-{nanos_chirho}-{n_chirho}"))
}

pub(crate) fn placeholder_digest_chirho(tag_chirho: &str) -> String {
    blake3::hash(tag_chirho.as_bytes()).to_hex().to_string()
}

/// The final physical line (record plus its trailing newline) of a raw segment body.
pub(crate) fn final_physical_line_chirho(raw_chirho: &[u8]) -> &[u8] {
    let trimmed_chirho = raw_chirho.strip_suffix(b"\n").unwrap_or(raw_chirho);
    let start_chirho = trimmed_chirho
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map(|position_chirho| position_chirho + 1)
        .unwrap_or(0);
    &raw_chirho[start_chirho..]
}

/// Write a synthetic sealed segment to disk and append its signed manifest entry — exactly the state
/// a real rotation leaves, without a production rotation caller. Returns the new entry's digest so
/// the next call can chain to it.
pub(crate) fn seal_synthetic_segment_chirho(
    paths_chirho: &SegmentPathsChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    identity_chirho: &LogIdentityChirho,
    generation_chirho: u64,
    first_seq_chirho: u64,
    count_chirho: u64,
    prev_entry_digest_chirho: Option<String>,
) -> String {
    let mut body_chirho = String::new();
    for offset_chirho in 0..count_chirho {
        body_chirho.push_str(
            &serde_json::to_string(&SegTestRecordChirho {
                seq_chirho: first_seq_chirho + offset_chirho,
                value_chirho: 1000 + first_seq_chirho + offset_chirho,
            })
            .unwrap(),
        );
        body_chirho.push('\n');
    }
    let raw_chirho = body_chirho.as_bytes();
    let segment_digest_chirho = blake3::hash(raw_chirho).to_hex().to_string();
    let final_line_digest_chirho = blake3::hash(final_physical_line_chirho(raw_chirho))
        .to_hex()
        .to_string();
    let sealed_path_chirho = paths_chirho.sealed_segment_chirho(&segment_digest_chirho);
    std::fs::create_dir_all(
        Path::new(sealed_path_chirho.as_str_chirho())
            .parent()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(sealed_path_chirho.as_str_chirho(), raw_chirho).unwrap();
    let last_seq_chirho = first_seq_chirho + count_chirho - 1;
    let entry_chirho = new_segment_manifest_entry_chirho(
        identity_chirho,
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
        raw_chirho.len() as u64,
        segment_digest_chirho,
        final_line_digest_chirho,
        prev_entry_digest_chirho,
    );
    let line_chirho = sign_manifest_entry_chirho(port_chirho, &entry_chirho).unwrap();
    let storage_chirho = FsSegmentStorageChirho;
    append_signed_manifest_line_chirho(&storage_chirho, paths_chirho, &line_chirho).unwrap();
    entry_chirho.entry_digest_chirho().unwrap()
}

pub(crate) fn write_active_records_chirho(
    paths_chirho: &SegmentPathsChirho,
    first_seq_chirho: u64,
    count_chirho: u64,
) {
    let mut body_chirho = String::new();
    for offset_chirho in 0..count_chirho {
        body_chirho.push_str(
            &serde_json::to_string(&SegTestRecordChirho {
                seq_chirho: first_seq_chirho + offset_chirho,
                value_chirho: 1000 + first_seq_chirho + offset_chirho,
            })
            .unwrap(),
        );
        body_chirho.push('\n');
    }
    std::fs::create_dir_all(
        Path::new(paths_chirho.active_chirho().as_str_chirho())
            .parent()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(paths_chirho.active_chirho().as_str_chirho(), body_chirho).unwrap();
}

/// Bulk-write `segment_count_chirho` valid, chained, signed manifest lines (each sealing one record,
/// so base seq == segment count) WITHOUT the sealed files — enough to prove warm base-seq derivation
/// touches neither the manifest body nor any segment, at any history length.
pub(crate) fn seed_manifest_lines_chirho(
    paths_chirho: &SegmentPathsChirho,
    port_chirho: &dyn SegmentContinuityPortChirho,
    identity_chirho: &LogIdentityChirho,
    segment_count_chirho: u64,
) {
    let mut body_chirho = String::new();
    let mut prev_digest_chirho: Option<String> = None;
    for generation_chirho in 0..segment_count_chirho {
        let entry_chirho = new_segment_manifest_entry_chirho(
            identity_chirho,
            generation_chirho,
            generation_chirho,
            generation_chirho,
            8,
            placeholder_digest_chirho(&format!("seg-{generation_chirho}-chirho")),
            placeholder_digest_chirho(&format!("line-{generation_chirho}-chirho")),
            prev_digest_chirho.clone(),
        );
        let line_chirho = sign_manifest_entry_chirho(port_chirho, &entry_chirho).unwrap();
        body_chirho.push_str(&serde_json::to_string(&line_chirho).unwrap());
        body_chirho.push('\n');
        prev_digest_chirho = Some(entry_chirho.entry_digest_chirho().unwrap());
    }
    let manifest_path_chirho = paths_chirho.manifest_chirho();
    std::fs::create_dir_all(
        Path::new(manifest_path_chirho.as_str_chirho())
            .parent()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(manifest_path_chirho.as_str_chirho(), body_chirho).unwrap();
}
