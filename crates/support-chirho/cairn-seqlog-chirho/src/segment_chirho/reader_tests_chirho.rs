// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Reader torn-tail contract tests (deviation #4): the segmented reader reads the active file only
//! through the storage port and FAILS CLOSED on a torn tail — repair belongs to the owning journal.
//! Self-contained fixtures (first stone of the segment tests split; the big suite stays in
//! `tests_chirho.rs` until the 3c split).

use crate::segment_chirho::continuity_chirho::{
    SegmentContinuityPortChirho, SegmentSignatureChirho,
};
use crate::segment_chirho::paths_chirho::SegmentPathsChirho;
use crate::segment_chirho::reader_chirho::{
    load_segmented_serialized_jsonl_chirho, segmented_recover_len_chirho,
};
use crate::segment_chirho::storage_chirho::FsSegmentStorageChirho;
use crate::segment_chirho::LogIdentityChirho;
use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// A continuity port these legacy-branch tests must never exercise: zero sealed segments means no
/// manifest verification, so any call is a broken assumption and fails loudly (and closed).
struct NeverSignContinuityPortChirho;

impl SegmentContinuityPortChirho for NeverSignContinuityPortChirho {
    fn sign_canonical_chirho(
        &self,
        _canonical_bytes_chirho: &[u8],
    ) -> Result<SegmentSignatureChirho> {
        Err(anyhow!("reader tests must not sign"))
    }

    fn verify_canonical_chirho(
        &self,
        _canonical_bytes_chirho: &[u8],
        _signature_chirho: &SegmentSignatureChirho,
    ) -> Result<()> {
        Err(anyhow!("reader tests must not verify"))
    }

    fn key_id_chirho(&self) -> String {
        "reader-tests-never-chirho".to_string()
    }
}

fn tmp_root_chirho(tag_chirho: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cairn-seqlog-reader-tests-{}-{}",
        tag_chirho,
        std::process::id()
    ))
}

struct FixtureChirho {
    root_chirho: PathBuf,
    paths_chirho: SegmentPathsChirho,
    identity_chirho: LogIdentityChirho,
}

fn fixture_chirho(tag_chirho: &str) -> FixtureChirho {
    let root_chirho = tmp_root_chirho(tag_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    let active_chirho = root_chirho.join(format!("{tag_chirho}-chirho.jsonl"));
    FixtureChirho {
        paths_chirho: SegmentPathsChirho::new_chirho(active_chirho.to_str().unwrap()),
        identity_chirho: LogIdentityChirho::new_chirho(format!("ledger:reader-{tag_chirho}")),
        root_chirho,
    }
}

#[test]
fn recover_len_fails_closed_on_torn_active_tail_chirho() {
    let fixture_chirho = fixture_chirho("recover-torn");
    // A torn tail whose final line is even valid JSON: the missing trailing LF alone must refuse.
    std::fs::write(
        fixture_chirho.paths_chirho.active_chirho().as_str_chirho(),
        b"{\"v\":1}\n{\"v\":2}",
    )
    .unwrap();
    let error_chirho =
        crate::seqlog_chirho::with_append_log_lock_chirho(&fixture_chirho.root_chirho, || {
            segmented_recover_len_chirho(
                &FsSegmentStorageChirho,
                &NeverSignContinuityPortChirho,
                &fixture_chirho.paths_chirho,
                &fixture_chirho.identity_chirho.digest_chirho(),
            )
        })
        .expect_err("a torn active tail must fail closed at recover-len");
    assert!(error_chirho.to_string().contains("torn tail"));
    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn recover_len_counts_clean_active_and_missing_as_zero_chirho() {
    let fixture_chirho = fixture_chirho("recover-clean");
    // Missing active = never-appended log = zero records.
    let missing_chirho =
        crate::seqlog_chirho::with_append_log_lock_chirho(&fixture_chirho.root_chirho, || {
            segmented_recover_len_chirho(
                &FsSegmentStorageChirho,
                &NeverSignContinuityPortChirho,
                &fixture_chirho.paths_chirho,
                &fixture_chirho.identity_chirho.digest_chirho(),
            )
        })
        .unwrap();
    assert_eq!(missing_chirho, 0);
    std::fs::write(
        fixture_chirho.paths_chirho.active_chirho().as_str_chirho(),
        b"{\"v\":1}\n{\"v\":2}\n",
    )
    .unwrap();
    let clean_chirho =
        crate::seqlog_chirho::with_append_log_lock_chirho(&fixture_chirho.root_chirho, || {
            segmented_recover_len_chirho(
                &FsSegmentStorageChirho,
                &NeverSignContinuityPortChirho,
                &fixture_chirho.paths_chirho,
                &fixture_chirho.identity_chirho.digest_chirho(),
            )
        })
        .unwrap();
    assert_eq!(clean_chirho, 2);
    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn load_segmented_fails_closed_on_torn_active_tail_chirho() {
    let fixture_chirho = fixture_chirho("load-torn");
    // The old fs loader would have ACCEPTED this valid-JSON-but-unterminated tail line; the port
    // reader refuses the ambiguous tail outright.
    std::fs::write(
        fixture_chirho.paths_chirho.active_chirho().as_str_chirho(),
        b"{\"v\":1}\n{\"v\":2}",
    )
    .unwrap();
    let error_chirho = load_segmented_serialized_jsonl_chirho::<serde_json::Value>(
        &FsSegmentStorageChirho,
        &NeverSignContinuityPortChirho,
        &fixture_chirho.paths_chirho,
        &fixture_chirho.identity_chirho.digest_chirho(),
    )
    .expect_err("a torn active tail must fail closed at segmented load");
    assert!(error_chirho.to_string().contains("torn tail"));
    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn raw_lines_are_byte_exact_and_fail_closed_on_torn_chirho() {
    // The raw-line walk must return the EXACT stored line text (the money journal re-verifies
    // stored-line digests/sigs over these bytes — a serde round-trip would launder byte-identity),
    // and it rides the same fail-closed torn contract.
    let fixture_chirho = fixture_chirho("raw-lines");
    let line_a_chirho = "{\"v\":1,\"note\":\"  spacing kept \"}";
    let line_b_chirho = "{\"v\":2}";
    std::fs::write(
        fixture_chirho.paths_chirho.active_chirho().as_str_chirho(),
        format!("{line_a_chirho}\n{line_b_chirho}\n"),
    )
    .unwrap();
    let raw_chirho = crate::segment_chirho::reader_chirho::load_segmented_raw_jsonl_lines_chirho(
        &FsSegmentStorageChirho,
        &NeverSignContinuityPortChirho,
        &fixture_chirho.paths_chirho,
        &fixture_chirho.identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(
        raw_chirho,
        vec![line_a_chirho.to_owned(), line_b_chirho.to_owned()]
    );
    std::fs::write(
        fixture_chirho.paths_chirho.active_chirho().as_str_chirho(),
        format!("{line_a_chirho}\n{line_b_chirho}"),
    )
    .unwrap();
    let error_chirho = crate::segment_chirho::reader_chirho::load_segmented_raw_jsonl_lines_chirho(
        &FsSegmentStorageChirho,
        &NeverSignContinuityPortChirho,
        &fixture_chirho.paths_chirho,
        &fixture_chirho.identity_chirho.digest_chirho(),
    )
    .expect_err("a torn active tail must fail closed at the raw-line walk");
    assert!(error_chirho.to_string().contains("torn tail"));
    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}

#[test]
fn load_segmented_reads_clean_and_missing_active_chirho() {
    let fixture_chirho = fixture_chirho("load-clean");
    let missing_chirho = load_segmented_serialized_jsonl_chirho::<serde_json::Value>(
        &FsSegmentStorageChirho,
        &NeverSignContinuityPortChirho,
        &fixture_chirho.paths_chirho,
        &fixture_chirho.identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert!(missing_chirho.is_empty());
    std::fs::write(
        fixture_chirho.paths_chirho.active_chirho().as_str_chirho(),
        b"{\"v\":1}\n{\"v\":2}\n",
    )
    .unwrap();
    let loaded_chirho = load_segmented_serialized_jsonl_chirho::<serde_json::Value>(
        &FsSegmentStorageChirho,
        &NeverSignContinuityPortChirho,
        &fixture_chirho.paths_chirho,
        &fixture_chirho.identity_chirho.digest_chirho(),
    )
    .unwrap();
    assert_eq!(loaded_chirho.len(), 2);
    let _ = std::fs::remove_dir_all(&fixture_chirho.root_chirho);
}
