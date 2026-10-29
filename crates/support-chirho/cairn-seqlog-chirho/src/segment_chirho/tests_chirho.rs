// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Synthetic-family regression for the segmented-log foundation (RC4 slice 1A). All tests drive a
//! test continuity port (a root-pinned keyed-blake3 MAC) and synthetic records — there is no
//! production rotation caller. Grows increment by increment: Inc 1 pins identity + entry shape +
//! the injected signing boundary and its nonconstructible verified token.

use super::continuity_chirho::{sign_manifest_entry_chirho, verify_manifest_line_chirho};
use super::manifest_chirho::{
    derive_base_seq_chirho, new_segment_manifest_entry_chirho, verify_manifest_chain_chirho,
    SEGMENT_MANIFEST_ENTRY_SCHEMA_CHIRHO,
};
use super::manifest_head_chirho::{
    inspect_authenticated_manifest_tail_read_only_chirho,
    inspect_manifest_tail_for_held_cut_read_only_chirho, ReadOnlyManifestTailSnapshotChirho,
};
use super::paths_chirho::SegmentPathsChirho;
use super::rotation_chirho::{
    inspect_rotation_intent_read_only_chirho, write_test_marker_chirho,
    MAX_ROTATION_INTENT_BYTES_CHIRHO,
};
use super::storage_chirho::{FsSegmentStorageChirho, SegmentStorageChirho};
use super::LogIdentityChirho;
use std::io::Write;
use std::path::Path;

/// A test continuity port: a keyed-blake3 MAC over the canonical entry bytes. The key is the
/// root-pinned trust (held inside the port); verification recomputes and compares. This models a real
use super::test_support_chirho::*;

#[test]
fn identity_digest_is_stable_and_domain_separated_chirho() {
    let a1_chirho = LogIdentityChirho::new_chirho("ledger:tenant-a:v1-chirho");
    let a2_chirho = LogIdentityChirho::new_chirho("ledger:tenant-a:v1-chirho");
    let b_chirho = LogIdentityChirho::new_chirho("ledger:tenant-b:v1-chirho");
    assert_eq!(a1_chirho.digest_chirho(), a2_chirho.digest_chirho());
    assert_ne!(a1_chirho.digest_chirho(), b_chirho.digest_chirho());
    // Domain-separated: NOT the bare blake3 of the id, so it can't collide with another blake3 use.
    assert_ne!(
        a1_chirho.digest_chirho(),
        blake3::hash(b"ledger:tenant-a:v1-chirho")
            .to_hex()
            .to_string()
    );
}

#[test]
fn sign_then_verify_roundtrips_and_mints_token_chirho() {
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:tenant-a:v1-chirho");
    let entry_chirho = sample_genesis_entry_chirho(&identity_chirho);
    let line_chirho = sign_manifest_entry_chirho(&port_chirho, &entry_chirho).unwrap();
    assert_eq!(line_chirho.key_id_chirho, "test-key-1-chirho");
    let verified_chirho = verify_manifest_line_chirho(&port_chirho, &line_chirho).unwrap();
    assert_eq!(verified_chirho.entry_chirho(), &entry_chirho);
}

#[test]
fn verify_rejects_tampered_entry_chirho() {
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:tenant-a:v1-chirho");
    let entry_chirho = sample_genesis_entry_chirho(&identity_chirho);
    let mut line_chirho = sign_manifest_entry_chirho(&port_chirho, &entry_chirho).unwrap();
    // The signature was over the ORIGINAL canonical bytes; mutating any field must fail verification.
    line_chirho.entry_chirho.last_seq_chirho = 99;
    let error_chirho = verify_manifest_line_chirho(&port_chirho, &line_chirho)
        .expect_err("tampered entry must not verify");
    assert!(error_chirho.to_string().contains("signature mismatch"));
}

#[test]
fn embedded_key_id_never_selects_trust_chirho() {
    // Two ports share a key id but hold DIFFERENT root-pinned keys; a line signed by one must not
    // verify under the other, proving the embedded key_id is never consulted to pick a verifying key.
    let signer_chirho =
        TestContinuityPortChirho::with_key_chirho(b"key-alpha-chirho", "shared-id-chirho");
    let verifier_chirho =
        TestContinuityPortChirho::with_key_chirho(b"key-beta-chirho", "shared-id-chirho");
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:tenant-a:v1-chirho");
    let entry_chirho = sample_genesis_entry_chirho(&identity_chirho);
    let line_chirho = sign_manifest_entry_chirho(&signer_chirho, &entry_chirho).unwrap();
    assert_eq!(line_chirho.key_id_chirho, "shared-id-chirho");
    verify_manifest_line_chirho(&verifier_chirho, &line_chirho)
        .expect_err("same key_id but a different pinned key must fail closed");
}

#[test]
fn entry_intrinsic_checks_catch_bad_shapes_chirho() {
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:tenant-a:v1-chirho");
    let good_chirho = sample_genesis_entry_chirho(&identity_chirho);
    good_chirho.check_intrinsic_chirho().unwrap();
    good_chirho
        .check_identity_chirho(&identity_chirho.digest_chirho())
        .unwrap();
    assert_eq!(
        good_chirho.schema_chirho,
        SEGMENT_MANIFEST_ENTRY_SCHEMA_CHIRHO
    );

    // record_count != span.
    let mut bad_count_chirho = good_chirho.clone();
    bad_count_chirho.record_count_chirho = 5;
    assert!(bad_count_chirho.check_intrinsic_chirho().is_err());

    // Genesis must open the log at seq 0.
    let mut bad_genesis_chirho = good_chirho.clone();
    bad_genesis_chirho.first_seq_chirho = 4;
    bad_genesis_chirho.last_seq_chirho = 4;
    bad_genesis_chirho.record_count_chirho = 1;
    bad_genesis_chirho.next_first_seq_chirho = 5;
    assert!(bad_genesis_chirho.check_intrinsic_chirho().is_err());

    // Generation 0 with a prior digest is not a valid genesis.
    let mut bad_prev_chirho = good_chirho.clone();
    bad_prev_chirho.prev_entry_digest_chirho = Some("deadbeef-chirho".to_string());
    assert!(bad_prev_chirho.check_intrinsic_chirho().is_err());

    // A wrong schema tag is rejected.
    let mut bad_schema_chirho = good_chirho.clone();
    bad_schema_chirho.schema_chirho = "wrong-chirho".to_string();
    assert!(bad_schema_chirho.check_intrinsic_chirho().is_err());

    // Identity binding is root-pinned to the expected digest.
    let other_chirho = LogIdentityChirho::new_chirho("ledger:tenant-b:v1-chirho");
    assert!(good_chirho
        .check_identity_chirho(&other_chirho.digest_chirho())
        .is_err());
}

// ============================================================================================
// Increment 2 — the append-only manifest file, its O(1) advisory head, and fail-closed base-seq.
// ============================================================================================

#[test]
fn base_seq_legacy_zero_when_no_manifest_and_no_artifacts_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("legacy-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:legacy-chirho");

    let base_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(base_chirho.base_seq_chirho, 0);
    assert_eq!(base_chirho.sealed_segment_count_chirho, 0);
    assert_eq!(base_chirho.last_entry_digest_chirho, None);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn base_seq_from_two_sealed_segments_cold_then_warm_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("two-seg-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:two-seg-chirho");

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

    // Cold derive (no checkpoint yet): verify the chain, base = 3 + 2 = 5.
    let cold_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(cold_chirho.base_seq_chirho, 5);
    assert_eq!(cold_chirho.sealed_segment_count_chirho, 2);
    assert!(cold_chirho.last_entry_digest_chirho.is_some());

    // Warm derive (checkpoint now seeded): same result, byte-for-byte.
    let warm_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(warm_chirho, cold_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn bounded_authenticated_manifest_tail_retains_torn_suffix_without_head_trust_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("bounded-manifest-tail-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:bounded-manifest-tail-chirho");
    seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    std::fs::write(
        paths_chirho.manifest_head_chirho().as_str_chirho(),
        b"stale",
    )
    .unwrap();
    let clean_chirho = inspect_authenticated_manifest_tail_read_only_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(clean_chirho.entry_chirho.generation_chirho, 0);
    assert_eq!(clean_chirho.torn_suffix_len_chirho, 0);

    std::fs::OpenOptions::new()
        .append(true)
        .open(paths_chirho.manifest_chirho().as_str_chirho())
        .unwrap()
        .write_all(b"{\"partial_chirho\":")
        .unwrap();
    let torn_chirho = inspect_authenticated_manifest_tail_read_only_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(torn_chirho.entry_chirho, clean_chirho.entry_chirho);
    assert_eq!(
        torn_chirho.torn_suffix_len_chirho,
        b"{\"partial_chirho\":".len() as u64
    );
    assert!(torn_chirho.torn_suffix_digest_chirho.is_some());
    let _cleanup_chirho = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn entirely_torn_first_manifest_line_is_exposed_only_to_held_classification_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("entirely-torn-first-manifest-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:entirely-torn-first-chirho");
    let torn_chirho = b"{\"partial_chirho\":";
    std::fs::write(paths_chirho.manifest_chirho().as_str_chirho(), torn_chirho).unwrap();

    assert!(inspect_authenticated_manifest_tail_read_only_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .is_err());
    let held_chirho = inspect_manifest_tail_for_held_cut_read_only_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap()
    .unwrap();
    let ReadOnlyManifestTailSnapshotChirho::EntirelyTornChirho(held_chirho) = held_chirho else {
        panic!("entirely torn first line must remain non-authoritative held evidence");
    };
    assert_eq!(held_chirho.bytes_chirho, torn_chirho);
    let _cleanup_chirho = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn bounded_rotation_marker_inspection_refuses_oversized_state_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("bounded-rotation-marker-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:bounded-rotation-marker-chirho");
    let segment_digest_chirho = placeholder_digest_chirho("bounded-segment-chirho");
    let line_digest_chirho = placeholder_digest_chirho("bounded-line-chirho");
    write_test_marker_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho,
        0,
        0,
        2,
        64,
        &segment_digest_chirho,
        &line_digest_chirho,
    )
    .unwrap();
    let marker_chirho = inspect_rotation_intent_read_only_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(marker_chirho.last_seq_chirho, 2);

    storage_chirho
        .write_durable_chirho(
            &paths_chirho.rotation_marker_chirho(),
            &vec![b'x'; MAX_ROTATION_INTENT_BYTES_CHIRHO as usize + 1],
        )
        .unwrap();
    assert!(inspect_rotation_intent_read_only_chirho(
        &storage_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .is_err());
    let _cleanup_chirho = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn base_seq_fails_closed_when_manifest_missing_but_artifacts_present_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("orphan-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:orphan-chirho");

    seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);

    // Lose the manifest (and any head) but keep the sealed segment artifact on disk.
    std::fs::remove_file(paths_chirho.manifest_chirho().as_str_chirho()).unwrap();
    let _ = std::fs::remove_file(paths_chirho.manifest_head_chirho().as_str_chirho());
    assert!(Path::new(paths_chirho.segments_dir_chirho().as_str_chirho()).exists());

    let error_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .expect_err("artifacts without a manifest must fail closed, never base-0");
    assert!(error_chirho.to_string().contains("refusing base-0"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn manifest_chain_rejects_seq_gap_chirho() {
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:gap-chirho");
    let entry0_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        0,
        0,
        2,
        24,
        placeholder_digest_chirho("s0-chirho"),
        placeholder_digest_chirho("l0-chirho"),
        None,
    );
    // gen1 must open at 3 (entry0.next_first_seq); opening at 5 leaves a gap.
    let entry1_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        1,
        5,
        6,
        24,
        placeholder_digest_chirho("s1-chirho"),
        placeholder_digest_chirho("l1-chirho"),
        Some(entry0_chirho.entry_digest_chirho().unwrap()),
    );
    let lines_chirho = vec![
        sign_manifest_entry_chirho(&port_chirho, &entry0_chirho).unwrap(),
        sign_manifest_entry_chirho(&port_chirho, &entry1_chirho).unwrap(),
    ];
    let error_chirho = verify_manifest_chain_chirho(
        &port_chirho,
        &identity_chirho.digest_chirho(),
        &lines_chirho,
    )
    .expect_err("a seq gap must fail closed");
    assert!(error_chirho.to_string().contains("gap or overlap"));
}

#[test]
fn manifest_chain_rejects_seq_overlap_chirho() {
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:overlap-chirho");
    let entry0_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        0,
        0,
        2,
        24,
        placeholder_digest_chirho("s0-chirho"),
        placeholder_digest_chirho("l0-chirho"),
        None,
    );
    // gen1 opening at 2 re-covers entry0's last seq (expected 3) — an overlap.
    let entry1_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        1,
        2,
        3,
        24,
        placeholder_digest_chirho("s1-chirho"),
        placeholder_digest_chirho("l1-chirho"),
        Some(entry0_chirho.entry_digest_chirho().unwrap()),
    );
    let lines_chirho = vec![
        sign_manifest_entry_chirho(&port_chirho, &entry0_chirho).unwrap(),
        sign_manifest_entry_chirho(&port_chirho, &entry1_chirho).unwrap(),
    ];
    let error_chirho = verify_manifest_chain_chirho(
        &port_chirho,
        &identity_chirho.digest_chirho(),
        &lines_chirho,
    )
    .expect_err("a seq overlap must fail closed");
    assert!(error_chirho.to_string().contains("gap or overlap"));
}

#[test]
fn manifest_chain_rejects_broken_prev_digest_chirho() {
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:prevchain-chirho");
    let entry0_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        0,
        0,
        2,
        24,
        placeholder_digest_chirho("s0-chirho"),
        placeholder_digest_chirho("l0-chirho"),
        None,
    );
    // Correct seq seam, but the prev-entry digest points nowhere in the chain.
    let entry1_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        1,
        3,
        4,
        24,
        placeholder_digest_chirho("s1-chirho"),
        placeholder_digest_chirho("l1-chirho"),
        Some(placeholder_digest_chirho("not-the-real-prev-chirho")),
    );
    let lines_chirho = vec![
        sign_manifest_entry_chirho(&port_chirho, &entry0_chirho).unwrap(),
        sign_manifest_entry_chirho(&port_chirho, &entry1_chirho).unwrap(),
    ];
    let error_chirho = verify_manifest_chain_chirho(
        &port_chirho,
        &identity_chirho.digest_chirho(),
        &lines_chirho,
    )
    .expect_err("a broken prev-entry digest must fail closed");
    assert!(error_chirho.to_string().contains("breaks the chain"));
}

#[test]
fn manifest_chain_rejects_nondense_generation_chirho() {
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:dense-chirho");
    let entry0_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        0,
        0,
        2,
        24,
        placeholder_digest_chirho("s0-chirho"),
        placeholder_digest_chirho("l0-chirho"),
        None,
    );
    // A jump to generation 5 at index 1 is not a dense sequence.
    let entry1_chirho = new_segment_manifest_entry_chirho(
        &identity_chirho,
        5,
        3,
        4,
        24,
        placeholder_digest_chirho("s1-chirho"),
        placeholder_digest_chirho("l1-chirho"),
        Some(entry0_chirho.entry_digest_chirho().unwrap()),
    );
    let lines_chirho = vec![
        sign_manifest_entry_chirho(&port_chirho, &entry0_chirho).unwrap(),
        sign_manifest_entry_chirho(&port_chirho, &entry1_chirho).unwrap(),
    ];
    let error_chirho = verify_manifest_chain_chirho(
        &port_chirho,
        &identity_chirho.digest_chirho(),
        &lines_chirho,
    )
    .expect_err("a non-dense generation must fail closed");
    assert!(error_chirho.to_string().contains("out of order"));
}

#[test]
fn manifest_chain_rejects_cross_log_identity_replay_chirho() {
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_a_chirho = LogIdentityChirho::new_chirho("ledger:log-a-chirho");
    let identity_b_chirho = LogIdentityChirho::new_chirho("ledger:log-b-chirho");
    let entry_chirho = new_segment_manifest_entry_chirho(
        &identity_a_chirho,
        0,
        0,
        2,
        24,
        placeholder_digest_chirho("s-chirho"),
        placeholder_digest_chirho("l-chirho"),
        None,
    );
    let lines_chirho = vec![sign_manifest_entry_chirho(&port_chirho, &entry_chirho).unwrap()];
    // The very same signed bytes must not verify as belonging to a different log.
    let error_chirho = verify_manifest_chain_chirho(
        &port_chirho,
        &identity_b_chirho.digest_chirho(),
        &lines_chirho,
    )
    .expect_err("bytes bound to log A must not verify as log B");
    assert!(error_chirho.to_string().contains("log identity"));
    // Sanity: the same lines DO verify against their true log identity.
    verify_manifest_chain_chirho(
        &port_chirho,
        &identity_a_chirho.digest_chirho(),
        &lines_chirho,
    )
    .unwrap();
}

#[test]
fn warm_manifest_head_ignored_when_manifest_tail_changes_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join("tail-invalidate-chirho.jsonl");
    let paths_chirho = SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap());
    let storage_chirho = FsSegmentStorageChirho;
    let port_chirho = TestContinuityPortChirho::new_chirho();
    let identity_chirho = LogIdentityChirho::new_chirho("ledger:tail-invalidate-chirho");

    let d0_chirho =
        seal_synthetic_segment_chirho(&paths_chirho, &port_chirho, &identity_chirho, 0, 0, 3, None);
    let d1_chirho = seal_synthetic_segment_chirho(
        &paths_chirho,
        &port_chirho,
        &identity_chirho,
        1,
        3,
        2,
        Some(d0_chirho),
    );
    // Seed the checkpoint at base 5 / 2 segments.
    let seeded_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(seeded_chirho.base_seq_chirho, 5);

    // Append a 3rd sealed segment WITHOUT re-seeding the head; the manifest tail now differs.
    seal_synthetic_segment_chirho(
        &paths_chirho,
        &port_chirho,
        &identity_chirho,
        2,
        5,
        4,
        Some(d1_chirho),
    );
    // The stale checkpoint (byte length of the 2-segment manifest) must be rejected, and the cold
    // verify must derive base 9 (3 + 2 + 4) across all three segments.
    let refreshed_chirho = derive_base_seq_chirho(
        &storage_chirho,
        &port_chirho,
        &paths_chirho,
        &identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(refreshed_chirho.base_seq_chirho, 9);
    assert_eq!(refreshed_chirho.sealed_segment_count_chirho, 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// ============================================================================================
// Increment 3 — the central segmented virtual reader and the O(1)-warm base-seq scaling guard.
