// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Synthetic-family regression for the segmented-log foundation (RC4 slice 1A). All tests drive a
//! test continuity port (a root-pinned keyed-blake3 MAC) and synthetic records — there is no
//! production rotation caller. Grows increment by increment: Inc 1 pins identity + entry shape +
//! the injected signing boundary and its nonconstructible verified token.

use super::continuity_chirho::sign_manifest_entry_chirho;
use super::manifest_chirho::{
    derive_base_seq_chirho, new_segment_manifest_entry_chirho, segments_dir_has_sealed_files_chirho,
};
use super::manifest_head_chirho::try_manifest_head_fast_path_chirho;
use super::paths_chirho::{SegmentPathsChirho, SEALED_SEGMENT_SUFFIX_CHIRHO};
use super::predecessor_index_chirho::load_predecessor_index_entry_chirho;
use super::reader_chirho::{load_segmented_serialized_jsonl_chirho, segmented_recover_len_chirho};
use super::rotation_chirho::{
    recover_pending_rotation_chirho, rotate_segment_chirho, write_test_marker_chirho,
    RotationOutcomeChirho, RotationRecoveryChirho,
};
use super::storage_chirho::{FsSegmentStorageChirho, SegmentPathChirho, SegmentStorageChirho};
use super::{
    manifest_scan_count_chirho, reset_segment_counts_chirho, segment_read_count_chirho,
    LogIdentityChirho,
};
use anyhow::{anyhow, Result};
use std::path::Path;

/// A test continuity port: a keyed-blake3 MAC over the canonical entry bytes. The key is the
/// root-pinned trust (held inside the port); verification recomputes and compares. This models a real
use super::test_support_chirho::*;

struct ManifestAppendRefusalStorageChirho {
    manifest_path_chirho: SegmentPathChirho,
}

impl SegmentStorageChirho for ManifestAppendRefusalStorageChirho {
    fn read_all_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<Vec<u8>>> {
        FsSegmentStorageChirho.read_all_chirho(path_chirho)
    }

    fn object_len_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<Option<u64>> {
        FsSegmentStorageChirho.object_len_chirho(path_chirho)
    }

    fn read_range_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> Result<Vec<u8>> {
        FsSegmentStorageChirho.read_range_chirho(path_chirho, offset_chirho, len_chirho)
    }

    fn write_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        FsSegmentStorageChirho.write_durable_chirho(path_chirho, bytes_chirho)
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &SegmentPathChirho,
        bytes_chirho: &[u8],
    ) -> Result<()> {
        if path_chirho == &self.manifest_path_chirho {
            return Err(anyhow!("injected manifest append refusal chirho"));
        }
        FsSegmentStorageChirho.append_durable_chirho(path_chirho, bytes_chirho)
    }

    fn rename_chirho(
        &self,
        from_chirho: &SegmentPathChirho,
        to_chirho: &SegmentPathChirho,
    ) -> Result<()> {
        FsSegmentStorageChirho.rename_chirho(from_chirho, to_chirho)
    }

    fn remove_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<()> {
        FsSegmentStorageChirho.remove_chirho(path_chirho)
    }

    fn list_dir_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<Vec<SegmentPathChirho>> {
        FsSegmentStorageChirho.list_dir_chirho(dir_chirho)
    }

    fn exists_chirho(&self, path_chirho: &SegmentPathChirho) -> Result<bool> {
        FsSegmentStorageChirho.exists_chirho(path_chirho)
    }

    fn create_dir_all_chirho(&self, dir_chirho: &SegmentPathChirho) -> Result<()> {
        FsSegmentStorageChirho.create_dir_all_chirho(dir_chirho)
    }
}

#[test]
fn segmented_load_recomposes_sealed_plus_active_as_if_whole_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("recompose-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:recompose-chirho");

    // Sealed seg0 holds seq 0..3, seg1 holds seq 3..5, and the active file holds seq 5..7.
    let d0_chirho =
        seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    seal_synthetic_segment_chirho(
        &paths_chirho,
        &port_chirho,
        &identity_chirho,
        1,
        3,
        2,
        Some(d0_chirho),
    );
    write_active_records_chirho(&paths_chirho, 5, 2);

    let loaded_chirho: Vec<SegTestRecordChirho> = load_segmented_serialized_jsonl_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    let expected_chirho: Vec<SegTestRecordChirho> = (0..7)
        .map(|seq_chirho| SegTestRecordChirho {
            seq_chirho,
            value_chirho: 1000 + seq_chirho,
        })
        .collect();
    assert_eq!(loaded_chirho, expected_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn segmented_load_legacy_active_only_matches_single_file_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("legacy-load-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:legacy-load-chirho");
    write_active_records_chirho(&paths_chirho, 0, 4);

    let segmented_chirho: Vec<SegTestRecordChirho> = load_segmented_serialized_jsonl_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    let single_chirho: Vec<SegTestRecordChirho> =
        crate::jsonl_read_chirho::load_serialized_jsonl_chirho(Path::new(
            paths_chirho.active_chirho().as_str_chirho(),
        ))
        .unwrap();
    assert_eq!(segmented_chirho, single_chirho);
    assert_eq!(segmented_chirho.len(), 4);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn segmented_load_fails_closed_on_tampered_sealed_segment_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("tamper-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:tamper-chirho");
    seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);

    // Overwrite the sealed file with same-length but different bytes; the manifest still names it by
    // its original digest, so the reader's content re-hash no longer matches.
    let sealed_file_chirho = std::fs::read_dir(paths_chirho.segments_dir_chirho().as_str_chirho())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original_chirho = std::fs::read(&sealed_file_chirho).unwrap();
    let mut tampered_chirho = original_chirho.clone();
    let midpoint_chirho = tampered_chirho.len() / 2;
    tampered_chirho[midpoint_chirho] ^= 0x20;
    std::fs::write(&sealed_file_chirho, &tampered_chirho).unwrap();
    assert_eq!(
        std::fs::read(&sealed_file_chirho).unwrap().len(),
        original_chirho.len()
    );

    let error_chirho = load_segmented_serialized_jsonl_chirho::<SegTestRecordChirho>(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .expect_err("a tampered sealed segment must fail closed");
    assert!(error_chirho.to_string().contains("digest mismatch"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn segmented_load_fails_closed_on_missing_sealed_file_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("missing-seg-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:missing-seg-chirho");
    seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);

    // Delete the sealed data while keeping its manifest entry: history is unreadable, fail closed.
    let sealed_file_chirho = std::fs::read_dir(paths_chirho.segments_dir_chirho().as_str_chirho())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(&sealed_file_chirho).unwrap();

    let error_chirho = load_segmented_serialized_jsonl_chirho::<SegTestRecordChirho>(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .expect_err("a missing sealed segment must fail closed");
    assert!(error_chirho.to_string().contains("read sealed segment"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn segmented_recover_len_spans_segments_and_active_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("recover-len-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:recover-len-chirho");

    let d0_chirho =
        seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    seal_synthetic_segment_chirho(
        &paths_chirho,
        &port_chirho,
        &identity_chirho,
        1,
        3,
        2,
        Some(d0_chirho),
    );
    write_active_records_chirho(&paths_chirho, 5, 2);

    let len_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        segmented_recover_len_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
    })
    .unwrap();
    // base 5 (3 + 2 sealed) + 2 active records = next global seq 7.
    assert_eq!(len_chirho, 7);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn warm_base_seq_derivation_is_independent_of_segment_count_chirho() {
    fn seed_then_measure_warm_chirho(segment_count_chirho: u64) -> (u64, u64) {
        let root_chirho = tmp_root_chirho();
        std::fs::create_dir_all(&root_chirho).unwrap();
        let active_chirho = root_chirho.join("scaling-chirho.jsonl");
        let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
        let storage_chirho = FsSegmentStorageChirho;
        let port_chirho = TestContinuityPortChirho::new_chirho();
        let identity_chirho = LogIdentityChirho::new_chirho("ledger:scaling-chirho");
        seed_manifest_lines_chirho(
            &paths_chirho,
            &port_chirho,
            &identity_chirho,
            segment_count_chirho,
        );

        // One cold derive verifies the chain and seeds the manifest-head checkpoint.
        let cold_chirho = derive_base_seq_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
        .unwrap();
        assert_eq!(cold_chirho.base_seq_chirho, segment_count_chirho);

        // Measure the WARM derive: it must touch neither the manifest body nor any segment.
        reset_segment_counts_chirho();
        let warm_chirho = derive_base_seq_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
        .unwrap();
        assert_eq!(warm_chirho.base_seq_chirho, segment_count_chirho);
        let counts_chirho = (manifest_scan_count_chirho(), segment_read_count_chirho());
        let _ = std::fs::remove_dir_all(&root_chirho);
        counts_chirho
    }

    let small_chirho = seed_then_measure_warm_chirho(2);
    let large_chirho = seed_then_measure_warm_chirho(2000);
    assert_eq!(
        small_chirho,
        (0, 0),
        "warm derive at 2 segments must scan nothing"
    );
    assert_eq!(
        large_chirho,
        (0, 0),
        "warm derive at 2000 segments must scan nothing"
    );
    assert_eq!(
        small_chirho, large_chirho,
        "warm base-seq work must not grow with segment count"
    );
}

#[test]
fn cold_base_seq_derivation_scans_then_warm_is_zero_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("cold-warm-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:cold-warm-chirho");
    seed_manifest_lines_chirho(&paths_chirho, &port_chirho, &identity_chirho, 8);

    // Cold: exactly one full manifest scan proves the counter is live (not vacuously zero).
    reset_segment_counts_chirho();
    let cold_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(cold_chirho.base_seq_chirho, 8);
    assert_eq!(
        manifest_scan_count_chirho(),
        1,
        "a cold derive must perform exactly one manifest scan"
    );

    // Warm: the re-seeded head makes the next derive O(1) — zero scans, zero segment reads.
    reset_segment_counts_chirho();
    let warm_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(warm_chirho.base_seq_chirho, 8);
    assert_eq!(manifest_scan_count_chirho(), 0, "warm derive must not scan");
    assert_eq!(
        segment_read_count_chirho(),
        0,
        "warm derive must not read segments"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ============================================================================================
// R2 — the money-adoption precondition: the warm base flows from the SIGNED tail line, never the
// unsigned, attacker-writable sidecar. A forged sidecar cannot regress base_seq (silent seq reuse),
// and the warm path applies the cold path's per-line acceptance (signature + identity).
// ============================================================================================

#[test]
fn r2_forged_sidecar_base_seq_cannot_regress_the_warm_base_chirho() {
    // The manifest-head sidecar is unsigned and attacker-writable. A forged sidecar that preserves
    // the tail fingerprint but REGRESSES base_seq must never be trusted — trust flows only from the
    // signed tail line, so the derive returns the SIGNED base (5), not the forged one (0). Pre-R2 the
    // warm path trusted the sidecar and returned 0, reusing already-sealed sequences at the next
    // append (a silent double-spend-class hazard).
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("forged-head-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:forged-head-chirho");

    let digest0_chirho =
        seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    seal_synthetic_segment_chirho(
        &paths_chirho,
        &port_chirho,
        &identity_chirho,
        1,
        3,
        2,
        Some(digest0_chirho),
    );

    // One cold derive seeds a correct sidecar (base 5). The next derive would be warm.
    let cold_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(cold_chirho.base_seq_chirho, 5);

    // Forge the on-disk sidecar: keep every fingerprint field (so the O(1) tail check still passes),
    // but regress base_seq to 0 — exactly the silent-seq-reuse attack.
    let head_path_chirho = paths_chirho.manifest_head_chirho();
    let mut head_json_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(head_path_chirho.as_str_chirho()).unwrap()).unwrap();
    assert_eq!(head_json_chirho["base_seq_chirho"], serde_json::json!(5));
    head_json_chirho["base_seq_chirho"] = serde_json::json!(0);
    std::fs::write(
        head_path_chirho.as_str_chirho(),
        serde_json::to_vec(&head_json_chirho).unwrap(),
    )
    .unwrap();

    // The warm fast path itself rejects the forged sidecar (its money field disagrees with the
    // signed tail line), so it is a miss …
    let warm_chirho = try_manifest_head_fast_path_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert!(
        warm_chirho.is_none(),
        "a forged sidecar disagreeing with the signed line must be a warm miss"
    );
    // … and the cold re-derive returns the SIGNED base, never the forged regression.
    let derived_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(
        derived_chirho.base_seq_chirho, 5,
        "a forged sidecar base_seq must never regress the signed base (would reuse sequences)"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Refit the on-disk manifest-head sidecar so its fingerprint matches the CURRENT (post-tamper)
/// manifest tail while carrying attacker-chosen money fields — the exact capability a filesystem
/// attacker has over the unsigned sidecar. Reuses the real sidecar's schema string.
fn refit_forged_sidecar_chirho(
    paths_chirho: &SegmentPathsChirho,
    base_seq_chirho: u64,
    sealed_segment_count_chirho: u64,
    last_entry_digest_chirho: Option<String>,
) {
    let manifest_bytes_chirho =
        std::fs::read(paths_chirho.manifest_chirho().as_str_chirho()).unwrap();
    let byte_len_chirho = manifest_bytes_chirho.len() as u64;
    let last_line_chirho = final_physical_line_chirho(&manifest_bytes_chirho);
    let last_line_len_chirho = last_line_chirho.len() as u64;
    let last_line_blake3_chirho = blake3::hash(last_line_chirho).to_hex().to_string();
    let head_path_chirho = paths_chirho.manifest_head_chirho();
    let mut head_json_chirho: serde_json::Value =
        serde_json::from_slice(&std::fs::read(head_path_chirho.as_str_chirho()).unwrap()).unwrap();
    head_json_chirho["manifest_byte_len_chirho"] = serde_json::json!(byte_len_chirho);
    head_json_chirho["last_line_len_chirho"] = serde_json::json!(last_line_len_chirho);
    head_json_chirho["last_line_blake3_chirho"] = serde_json::json!(last_line_blake3_chirho);
    head_json_chirho["base_seq_chirho"] = serde_json::json!(base_seq_chirho);
    head_json_chirho["sealed_segment_count_chirho"] =
        serde_json::json!(sealed_segment_count_chirho);
    head_json_chirho["last_entry_digest_chirho"] = match last_entry_digest_chirho {
        Some(digest_chirho) => serde_json::json!(digest_chirho),
        None => serde_json::Value::Null,
    };
    std::fs::write(
        head_path_chirho.as_str_chirho(),
        serde_json::to_vec(&head_json_chirho).unwrap(),
    )
    .unwrap();
}

#[test]
fn r2_warm_path_rejects_a_wrong_key_signed_tail_line_chirho() {
    // A filesystem attacker replaces the manifest with an intrinsically-valid but REGRESSED entry
    // signed by the WRONG key, then refits the unsigned sidecar to match. The warm-path signature
    // check makes it a miss (returns None); without that check the sidecar cross-check would pass and
    // the warm derive would return the regressed base 1, bypassing the cold verify. End to end the
    // derive fails closed.
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("wrong-key-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let good_port_chirho = TestContinuityPortChirho::new_chirho();
    let evil_port_chirho =
        TestContinuityPortChirho::with_key_chirho(b"attacker-key-chirho", "evil-key-chirho");
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:wrong-key-chirho");

    // Genuine single sealed segment (base 3), seeding a correct sidecar.
    seal_synthetic_segment_chirho(
        &paths_chirho,
        &good_port_chirho,
        &identity_chirho,
        0,
        0,
        3,
        None,
    );
    let cold_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &good_port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(cold_chirho.base_seq_chirho, 3);

    // Replace the whole manifest with a regressed gen-0 entry (first_seq 0, count 1 → base 1) signed
    // by the WRONG key, and refit the sidecar to it.
    let regressed_entry_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        0,
        0,
        0,
        24,
        placeholder_digest_chirho("evil-seg-chirho"),
        placeholder_digest_chirho("evil-line-chirho"),
        None,
    );
    let evil_line_chirho =
        sign_manifest_entry_chirho(&evil_port_chirho, &regressed_entry_chirho).unwrap();
    std::fs::write(
        paths_chirho.manifest_chirho().as_str_chirho(),
        format!("{}\n", serde_json::to_string(&evil_line_chirho).unwrap()),
    )
    .unwrap();
    refit_forged_sidecar_chirho(
        &paths_chirho,
        1,
        1,
        Some(regressed_entry_chirho.entry_digest_chirho().unwrap()),
    );

    // The warm path rejects the wrong-key tail (signature check) …
    let warm_chirho = try_manifest_head_fast_path_chirho(
        &storage_chirho,
        &good_port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert!(
        warm_chirho.is_none(),
        "the warm path must reject a wrong-key-signed tail line"
    );
    // … and end to end the derive fails closed, never authorizing the regressed base.
    let result_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &good_port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    );
    assert!(
        result_chirho.is_err(),
        "a wrong-key-signed tail line must fail closed, not authorize a regressed base"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn r2_warm_path_rejects_a_foreign_log_tail_line_chirho() {
    // Cross-log splice: a genuinely-signed line from a DIFFERENT log (sharing the continuity key)
    // with a lower base is written as this log's manifest tail, sidecar refit to match. The signature
    // passes (same key), so only the pinned-identity check catches it. Without that check the warm
    // derive would return the foreign base 1, bypassing cold.
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("foreign-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_a_chirho = LogIdentityChirho::new_chirho("ledger:log-a-chirho");
    let identity_b_chirho = LogIdentityChirho::new_chirho("ledger:log-b-chirho");

    seal_synthetic_segment_chirho(
        &paths_chirho,
        &port_chirho,
        &identity_a_chirho,
        0,
        0,
        3,
        None,
    );
    let cold_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_a_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(cold_chirho.base_seq_chirho, 3);

    // A foreign (log B) genuinely-signed gen-0 entry with a regressed base (count 1 → base 1).
    let foreign_entry_chirho = new_segment_manifest_entry_chirho(
        &identity_b_chirho,
        0,
        0,
        0,
        24,
        placeholder_digest_chirho("b-seg-chirho"),
        placeholder_digest_chirho("b-line-chirho"),
        None,
    );
    let foreign_line_chirho =
        sign_manifest_entry_chirho(&port_chirho, &foreign_entry_chirho).unwrap();
    std::fs::write(
        paths_chirho.manifest_chirho().as_str_chirho(),
        format!("{}\n", serde_json::to_string(&foreign_line_chirho).unwrap()),
    )
    .unwrap();
    refit_forged_sidecar_chirho(
        &paths_chirho,
        1,
        1,
        Some(foreign_entry_chirho.entry_digest_chirho().unwrap()),
    );

    // The warm path rejects the foreign tail (pinned-identity check) …
    let warm_chirho = try_manifest_head_fast_path_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_a_chirho.digest_chirho(),
    )
    .unwrap();
    assert!(
        warm_chirho.is_none(),
        "the warm path must reject a foreign-log tail line under the pinned identity"
    );
    // … and end to end the derive fails closed, never authorizing the foreign base.
    let result_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_a_chirho.digest_chirho(),
    );
    assert!(
        result_chirho.is_err(),
        "a foreign-log tail line must fail closed, not authorize a regressed base"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ============================================================================================
// Increment 4 — rotation as a recoverable transaction: happy path + the full B4 crash matrix.
// ============================================================================================

/// The raw JSONL bytes a segment of `count_chirho` records starting at `first_seq_chirho` would hold.
fn active_bytes_for_records_chirho(first_seq_chirho: u64, count_chirho: u64) -> Vec<u8> {
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
    body_chirho.into_bytes()
}

/// (full segment digest, final-line digest) for raw segment bytes — the two seam facts a marker binds.
fn segment_digests_chirho(bytes_chirho: &[u8]) -> (String, String) {
    (
        blake3::hash(bytes_chirho).to_hex().to_string(),
        blake3::hash(super::final_physical_line_chirho(bytes_chirho))
            .to_hex()
            .to_string(),
    )
}

#[test]
fn rotation_seals_active_resets_and_continues_seq_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("rotate-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:rotate-chirho");

    write_active_records_chirho(&paths_chirho, 0, 3);
    let outcome_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        rotate_segment_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(
        outcome_chirho,
        RotationOutcomeChirho::Rotated {
            generation_chirho: 0,
            first_seq_chirho: 0,
            last_seq_chirho: 2,
        }
    );
    assert!(std::fs::read(&active_chirho).unwrap().is_empty());
    assert!(!Path::new(paths_chirho.rotation_marker_chirho().as_str_chirho()).exists());

    let len_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        segmented_recover_len_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
    })
    .unwrap();
    assert_eq!(len_chirho, 3);

    // A new record lands at the continuing global seq 3; the virtual log is then 4 records.
    write_active_records_chirho(&paths_chirho, 3, 1);
    let loaded_chirho: Vec<SegTestRecordChirho> = load_segmented_serialized_jsonl_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    let expected_chirho: Vec<SegTestRecordChirho> = (0..4)
        .map(|seq_chirho| SegTestRecordChirho {
            seq_chirho,
            value_chirho: 1000 + seq_chirho,
        })
        .collect();
    assert_eq!(loaded_chirho, expected_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn predecessor_index_lands_before_manifest_and_tamper_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("predecessor-order-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:predecessor-order-chirho");
    write_active_records_chirho(&paths_chirho, 0, 3);

    let refusal_chirho = ManifestAppendRefusalStorageChirho {
        manifest_path_chirho: paths_chirho.manifest_chirho(),
    };
    let error_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        rotate_segment_chirho(
            &refusal_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .expect_err("manifest refusal must interrupt rotation");
    assert!(format!("{error_chirho:#}").contains("injected manifest append refusal"));
    assert!(!Path::new(paths_chirho.manifest_chirho().as_str_chirho()).exists());

    let bytes_chirho = active_bytes_for_records_chirho(0, 3);
    let (segment_digest_chirho, final_digest_chirho) = segment_digests_chirho(&bytes_chirho);
    let entry_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        0,
        0,
        2,
        bytes_chirho.len() as u64,
        segment_digest_chirho,
        final_digest_chirho,
        None,
    );
    let entry_digest_chirho = entry_chirho.entry_digest_chirho().unwrap();
    let indexed_chirho = load_predecessor_index_entry_chirho(
        &FsSegmentStorageChirho,
        &port_chirho,
        &paths_chirho,
        &entry_digest_chirho,
        &identity_chirho.digest_chirho(),
    )
    .expect("the authenticated lookup must land before manifest append");
    assert_eq!(indexed_chirho.entry_chirho, entry_chirho);

    crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &FsSegmentStorageChirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    let index_path_chirho = paths_chirho.predecessor_index_entry_chirho(&entry_digest_chirho);
    let mut tampered_chirho = std::fs::read(index_path_chirho.as_str_chirho()).unwrap();
    let signature_chirho = indexed_chirho.signature_chirho.0;
    let signature_offset_chirho = tampered_chirho
        .windows(signature_chirho.len())
        .position(|window_chirho| window_chirho == signature_chirho.as_bytes())
        .unwrap();
    tampered_chirho[signature_offset_chirho] = if tampered_chirho[signature_offset_chirho] == b'a' {
        b'b'
    } else {
        b'a'
    };
    std::fs::write(index_path_chirho.as_str_chirho(), tampered_chirho).unwrap();
    let tamper_error_chirho = load_predecessor_index_entry_chirho(
        &FsSegmentStorageChirho,
        &port_chirho,
        &paths_chirho,
        &entry_digest_chirho,
        &identity_chirho.digest_chirho(),
    )
    .expect_err("a tampered digest-addressed lookup must fail closed");
    assert!(format!("{tamper_error_chirho:#}").contains("signature mismatch"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_keeps_stale_active_head_as_a_safe_miss_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("stale-head-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:stale-head-chirho");
    write_active_records_chirho(&paths_chirho, 0, 3);
    assert_eq!(
        crate::seqlog_chirho::recover_jsonl_len_unlocked_chirho(&active_chirho).unwrap(),
        3
    );
    let head_path_chirho = crate::seqlog_head_chirho::seqlog_head_path_chirho(&active_chirho);
    assert!(head_path_chirho.exists());

    crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        rotate_segment_chirho(
            &FsSegmentStorageChirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert!(
        head_path_chirho.exists(),
        "rotation preserves the advisory sidecar"
    );
    assert_eq!(
        crate::seqlog_chirho::recover_jsonl_len_unlocked_chirho(&active_chirho).unwrap(),
        0,
        "the old length/tail binding must miss after the active reset"
    );
    assert_eq!(
        segmented_recover_len_chirho(
            &FsSegmentStorageChirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
        .unwrap(),
        3
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_of_empty_active_is_nothing_to_rotate_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("empty-rotate-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:empty-rotate-chirho");

    let outcome_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        rotate_segment_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(outcome_chirho, RotationOutcomeChirho::NothingToRotate);
    assert!(!Path::new(paths_chirho.rotation_marker_chirho().as_str_chirho()).exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn recover_pending_rotation_is_noop_without_marker_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("no-marker-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:no-marker-chirho");

    let recovery_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(recovery_chirho, RotationRecoveryChirho::NotPending);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_recovery_w0_marker_only_completes_forward_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("w0-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:w0-chirho");

    // Crash after the marker, before sealing: active full, no sealed file, no manifest.
    write_active_records_chirho(&paths_chirho, 0, 3);
    let bytes_chirho = active_bytes_for_records_chirho(0, 3);
    let (digest_chirho, final_digest_chirho) = segment_digests_chirho(&bytes_chirho);
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        bytes_chirho.len() as u64,
        &digest_chirho,
        &final_digest_chirho,
    )
    .unwrap();

    let recovery_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(recovery_chirho, RotationRecoveryChirho::CompletedForward);
    assert!(!Path::new(paths_chirho.rotation_marker_chirho().as_str_chirho()).exists());
    assert!(std::fs::read(&active_chirho).unwrap().is_empty());

    let loaded_chirho: Vec<SegTestRecordChirho> = load_segmented_serialized_jsonl_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(loaded_chirho.len(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_recovery_w1_sealed_no_manifest_completes_forward_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("w1-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:w1-chirho");

    // Crash after sealing, before the manifest: active full, sealed file present, no manifest.
    write_active_records_chirho(&paths_chirho, 0, 3);
    let bytes_chirho = active_bytes_for_records_chirho(0, 3);
    let (digest_chirho, final_digest_chirho) = segment_digests_chirho(&bytes_chirho);
    let sealed_path_chirho = paths_chirho.sealed_segment_chirho(&digest_chirho);
    std::fs::create_dir_all(
        Path::new(sealed_path_chirho.as_str_chirho())
            .parent()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(sealed_path_chirho.as_str_chirho(), &bytes_chirho).unwrap();
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        bytes_chirho.len() as u64,
        &digest_chirho,
        &final_digest_chirho,
    )
    .unwrap();

    let recovery_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(recovery_chirho, RotationRecoveryChirho::CompletedForward);
    assert!(!Path::new(paths_chirho.rotation_marker_chirho().as_str_chirho()).exists());
    assert!(std::fs::read(&active_chirho).unwrap().is_empty());
    let loaded_chirho: Vec<SegTestRecordChirho> = load_segmented_serialized_jsonl_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(loaded_chirho.len(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_recovery_w2_manifest_done_active_full_resets_no_dup_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("w2-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:w2-chirho");

    // Crash after the manifest, before resetting the active file: the sealed segment is committed
    // AND the active file still holds those same records — the "duplicate visible data" hazard.
    seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    let bytes_chirho = active_bytes_for_records_chirho(0, 3);
    std::fs::write(&active_chirho, &bytes_chirho).unwrap();
    let (digest_chirho, final_digest_chirho) = segment_digests_chirho(&bytes_chirho);
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        bytes_chirho.len() as u64,
        &digest_chirho,
        &final_digest_chirho,
    )
    .unwrap();

    let recovery_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(recovery_chirho, RotationRecoveryChirho::FinishedReset);
    assert!(!Path::new(paths_chirho.rotation_marker_chirho().as_str_chirho()).exists());
    assert!(std::fs::read(&active_chirho).unwrap().is_empty());

    // No seq duplication: base 3 (the one sealed segment) + active 0 = next seq 3, not 6.
    let len_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        segmented_recover_len_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
    })
    .unwrap();
    assert_eq!(len_chirho, 3);
    let loaded_chirho: Vec<SegTestRecordChirho> = load_segmented_serialized_jsonl_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(loaded_chirho.len(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_recovery_w3_manifest_done_active_empty_clears_marker_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("w3-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:w3-chirho");

    // Crash after resetting the active file, before deleting the marker: everything committed.
    seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    std::fs::write(&active_chirho, b"").unwrap();
    let bytes_chirho = active_bytes_for_records_chirho(0, 3);
    let (digest_chirho, final_digest_chirho) = segment_digests_chirho(&bytes_chirho);
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        bytes_chirho.len() as u64,
        &digest_chirho,
        &final_digest_chirho,
    )
    .unwrap();

    let recovery_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(recovery_chirho, RotationRecoveryChirho::FinishedReset);
    assert!(!Path::new(paths_chirho.rotation_marker_chirho().as_str_chirho()).exists());
    let len_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        segmented_recover_len_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
    })
    .unwrap();
    assert_eq!(len_chirho, 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_recovery_fails_closed_when_source_lost_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("lost-source-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:lost-source-chirho");

    // Marker + no manifest (so recovery would complete forward) but the active file does NOT hold the
    // bytes the marker sealed — the source is gone, so recovery must refuse rather than fabricate.
    write_active_records_chirho(&paths_chirho, 0, 3);
    let wrong_digest_chirho = blake3::hash(b"a-different-source-chirho")
        .to_hex()
        .to_string();
    let wrong_final_chirho = blake3::hash(b"a-different-final-chirho")
        .to_hex()
        .to_string();
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        999,
        &wrong_digest_chirho,
        &wrong_final_chirho,
    )
    .unwrap();

    let error_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .expect_err("a lost rotation source must fail closed");
    assert!(error_chirho
        .to_string()
        .contains("no longer matches the marker"));
    // Recovery refused before mutating anything, so the marker is still present.
    assert!(Path::new(paths_chirho.rotation_marker_chirho().as_str_chirho()).exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn rotation_recovery_is_idempotent_on_repeat_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("idempotent-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:idempotent-chirho");

    // A W1 state (sealed + marker, no manifest, active full).
    write_active_records_chirho(&paths_chirho, 0, 3);
    let bytes_chirho = active_bytes_for_records_chirho(0, 3);
    let (digest_chirho, final_digest_chirho) = segment_digests_chirho(&bytes_chirho);
    let sealed_path_chirho = paths_chirho.sealed_segment_chirho(&digest_chirho);
    std::fs::create_dir_all(
        Path::new(sealed_path_chirho.as_str_chirho())
            .parent()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(sealed_path_chirho.as_str_chirho(), &bytes_chirho).unwrap();
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        bytes_chirho.len() as u64,
        &digest_chirho,
        &final_digest_chirho,
    )
    .unwrap();

    let first_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(first_chirho, RotationRecoveryChirho::CompletedForward);
    // Re-running recovery is a no-op — the marker is gone and nothing is added or duplicated.
    let second_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    assert_eq!(second_chirho, RotationRecoveryChirho::NotPending);
    let len_chirho = crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        segmented_recover_len_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho.digest_chirho(),
        )
    })
    .unwrap();
    assert_eq!(len_chirho, 3);
    let loaded_chirho: Vec<SegTestRecordChirho> = load_segmented_serialized_jsonl_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(loaded_chirho.len(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// R1 (second-seat review fold): the base sequence is minted in derive_base_seq_chirho, so the
// pending-rotation refusal must live THERE — otherwise a 1B adopter calling it directly bypasses the
// W2 double-count defense and could assign duplicate seqs mid-rotation.
#[test]
fn derive_base_seq_refuses_pending_rotation_marker_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("r1-guard-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:r1-guard-chirho");

    // A committed segment plus a mid-flight rotation marker (a W2-shaped state): a DIRECT
    // derive_base_seq_chirho must fail closed rather than mint a base while the active file still
    // holds records already sealed into the segment.
    seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    let bytes_chirho = active_bytes_for_records_chirho(0, 3);
    std::fs::write(&active_chirho, &bytes_chirho).unwrap();
    let (digest_chirho, final_digest_chirho) = segment_digests_chirho(&bytes_chirho);
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        bytes_chirho.len() as u64,
        &digest_chirho,
        &final_digest_chirho,
    )
    .unwrap();

    let error_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .expect_err("a direct derive_base_seq must refuse a pending rotation");
    assert!(error_chirho.to_string().contains("pending rotation"));

    // After recovery clears the marker, derivation succeeds at base 3 — no duplication.
    crate::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        recover_pending_rotation_chirho(
            &storage_chirho,
            &port_chirho,
            &paths_chirho,
            &identity_chirho,
        )
    })
    .unwrap();
    let base_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(base_chirho.base_seq_chirho, 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ================================================================================================
// Coordinate injectivity: `SegmentPathChirho` is the storage/authority coordinate that feeds the
// money-relevant base-seq derivation, so the `&Path`→key conversion must be INJECTIVE and
// FAIL-CLOSED on non-UTF-8 — never a lossy `to_string_lossy` that aliases distinct paths to one key.
// ================================================================================================

/// RED (a): two DISTINCT invalid-UTF-8 root paths BOTH fail closed, so they cannot alias to one key.
#[cfg(unix)]
#[test]
fn distinct_non_utf8_roots_both_fail_closed_no_alias_chirho() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Two DISTINCT invalid-UTF-8 byte sequences that `to_string_lossy` would BOTH collapse to the
    // same "\u{FFFD}\u{FFFD}" key — the exact aliasing an injective coordinate must forbid.
    let path_a_chirho = Path::new(OsStr::from_bytes(&[0xff, 0xfe]));
    let path_b_chirho = Path::new(OsStr::from_bytes(&[0xfe, 0xff]));
    assert_ne!(
        path_a_chirho, path_b_chirho,
        "the two byte paths are genuinely distinct"
    );

    // Both are REFUSED, so there is no key for either to alias. Load-bearing: before the fix each
    // produced Ok(SegmentPathChirho("\u{FFFD}\u{FFFD}")) — equal keys ⇒ silent artifact aliasing.
    assert!(SegmentPathChirho::from_path_chirho(path_a_chirho).is_err());
    assert!(SegmentPathChirho::from_path_chirho(path_b_chirho).is_err());
}

/// RED (b): a UTF-8 root round-trips EXACTLY — behavior preserved, no lossy drift on the keys the
/// money path actually uses. (Passes before AND after the fix; it pins byte-identical UTF-8 keys.)
#[test]
fn utf8_path_round_trips_exactly_no_lossy_drift_chirho() {
    for path_str_chirho in [
        "/tmp/plain-chirho.jsonl",
        "/tmp/caf\u{00e9}-chirho/seg.jsonl",
    ] {
        let key_chirho = SegmentPathChirho::from_path_chirho(Path::new(path_str_chirho)).unwrap();
        assert_eq!(key_chirho.as_str_chirho(), path_str_chirho);
    }
    // The derived child keys keep the exact prior on-disk layout: append the suffix, join with "/".
    let paths_chirho = SegmentPathsChirho::new_chirho("/tmp/log-chirho.jsonl");
    assert_eq!(
        paths_chirho.active_chirho().as_str_chirho(),
        "/tmp/log-chirho.jsonl"
    );
    assert_eq!(
        paths_chirho.manifest_chirho().as_str_chirho(),
        "/tmp/log-chirho.jsonl.segment-manifest-chirho"
    );
    assert_eq!(
        paths_chirho.sealed_segment_chirho("abc123").as_str_chirho(),
        "/tmp/log-chirho.jsonl.segments-chirho/abc123.seg-chirho"
    );
    assert_eq!(
        paths_chirho
            .predecessor_index_entry_chirho("abc123")
            .as_str_chirho(),
        "/tmp/log-chirho.jsonl.segment-predecessors-chirho/ab/c1/abc123.predecessor-chirho"
    );
}

/// RED (c): a non-UTF-8 FILE in the sealed-segments dir makes `segments_dir_has_sealed_files_chirho`
/// fail CLOSED, never SILENTLY COERCE it to a lossy replacement-character key and suffix-match that.
/// Coercing would guess about a sealed-segment store it cannot read; failing closed is the only sound
/// answer at this base-seq boundary. (The DIRECT seq-reuse link is RED (a)'s injectivity: aliasing
/// distinct segments to one key can UNDER-count sealed segments ⇒ base too low ⇒ reuse. A coerced
/// phantom OVER-counts, which this specific empty-manifest branch already fail-closes — the same root
/// defect either way: a non-injective/coerced coordinate at base-seq derivation.)
#[cfg(unix)]
#[test]
fn segments_dir_non_utf8_file_fails_closed_not_phantom_hit_chirho() {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStrExt;

    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("nonutf8-seal-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;

    // Materialize the real sealed-segments dir, then drop a file whose NAME is invalid UTF-8 followed
    // by the sealed suffix. Under the OLD `to_string_lossy` conversion, list_dir coerced the name to
    // "\u{FFFD}\u{FFFD}.seg-chirho", whose `.ends_with(".seg-chirho")` PHANTOM-hits → Ok(true).
    let segments_dir_chirho = paths_chirho.segments_dir_chirho();
    std::fs::create_dir_all(segments_dir_chirho.as_str_chirho()).unwrap();
    let mut file_name_chirho = OsString::new();
    file_name_chirho.push(OsStr::from_bytes(&[0xff, 0xfe]));
    file_name_chirho.push(SEALED_SEGMENT_SUFFIX_CHIRHO);
    let non_utf8_file_chirho =
        Path::new(segments_dir_chirho.as_str_chirho()).join(&file_name_chirho);

    match std::fs::write(&non_utf8_file_chirho, b"synthetic-sealed-bytes-chirho") {
        Ok(()) => {
            // A filesystem that stores the non-UTF-8 name (e.g. Linux ext4 — where cairn runs): the
            // FULL money-relevant scan fails CLOSED, never a lossy phantom "has sealed files" hit.
            // Load-bearing: before the fix `list_dir_chirho` lossily coerced the entry and this
            // returned Ok(true), flipping derive_base_seq's fail-closed branch.
            let result_chirho =
                segments_dir_has_sealed_files_chirho(&storage_chirho, &paths_chirho);
            assert!(
                result_chirho.is_err(),
                "a non-UTF-8 sealed-dir entry must fail closed, not phantom-match as a sealed file"
            );
        }
        Err(_) => {
            // Some filesystems (e.g. macOS APFS) reject a non-UTF-8 filename at the OS with EILSEQ, so
            // the hazardous entry cannot exist there. Assert the SAME defense at its source: the exact
            // path `read_dir` WOULD yield for such a child fails the injective conversion that
            // `list_dir_chirho` relies on. Load-bearing: before the fix this conversion returned
            // Ok(lossy) — the value `list_dir_chirho` would then suffix-match as a phantom sealed file.
            assert!(
                SegmentPathChirho::from_path_chirho(&non_utf8_file_chirho).is_err(),
                "the non-UTF-8 sealed-dir entry path must fail the injective conversion, not coerce"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&root_chirho);
}
