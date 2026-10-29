// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::journal_chirho::{ExpectedLedgerGenesisChirho, LedgerJournalChirho};
use crate::journal_tests_chirho::{mint_request_chirho, transfer_request_chirho, HarnessChirho};
use crate::losing_suffix_chirho::{
    ExpectedLosingTailFloorChirho, FrozenLosingJournalReaderChirho, LosingSuffixCoordinateChirho,
    LosingSuffixJournalIdentityChirho, LosingSuffixPageRequestChirho, LosingSuffixReaderChirho,
    VerifiedLosingTailFloorRelationChirho,
};
use crate::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;
use cairn_seqlog_chirho::segment_chirho::LogIdentityChirho;

#[derive(serde::Serialize)]
struct TestRotationIntentChirho {
    schema_chirho: String,
    log_identity_digest_chirho: String,
    generation_chirho: u64,
    first_seq_chirho: u64,
    last_seq_chirho: u64,
    byte_len_chirho: u64,
    segment_digest_chirho: String,
    final_line_digest_chirho: String,
}

fn create_with_expected_genesis_chirho(
    harness_chirho: &HarnessChirho,
) -> (LedgerJournalChirho<'_>, ExpectedLedgerGenesisChirho) {
    let prepared_chirho = LedgerJournalChirho::prepare_genesis_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let expected_chirho = ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
        prepared_chirho.canonical_line_chirho(),
        prepared_chirho.digest_chirho().clone(),
    )
    .unwrap();
    let journal_chirho = LedgerJournalChirho::create_prepared_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        prepared_chirho,
    )
    .unwrap();
    (journal_chirho, expected_chirho)
}

fn floor_from_journal_chirho(
    journal_chirho: &LedgerJournalChirho<'_>,
) -> ExpectedLosingTailFloorChirho {
    let tail_chirho = journal_chirho.verified_losing_tail_chirho();
    ExpectedLosingTailFloorChirho::new_chirho(
        tail_chirho.coordinate_chirho().seq_chirho(),
        tail_chirho
            .coordinate_chirho()
            .record_digest_chirho()
            .clone(),
        journal_chirho.tail_hlc_chirho().clone(),
        tail_chirho.record_epoch_chirho(),
    )
}

fn rotation_marker_chirho(
    harness_chirho: &HarnessChirho,
    active_bytes_chirho: &[u8],
    generation_chirho: u64,
    first_seq_chirho: u64,
    last_seq_chirho: u64,
) -> (StoragePathChirho, Vec<u8>) {
    let body_end_chirho = active_bytes_chirho
        .len()
        .checked_sub(1)
        .expect("active rotation bytes are non-empty");
    assert_eq!(active_bytes_chirho[body_end_chirho], b'\n');
    let line_start_chirho = active_bytes_chirho[..body_end_chirho]
        .iter()
        .rposition(|byte_chirho| *byte_chirho == b'\n')
        .map(|position_chirho| position_chirho + 1)
        .unwrap_or(0);
    let final_physical_line_chirho = &active_bytes_chirho[line_start_chirho..];
    let identity_chirho = LogIdentityChirho::new_chirho(format!(
        "cairn-ledger:{}",
        harness_chirho.cluster_chirho().0
    ));
    let marker_chirho = serde_json::to_vec(&TestRotationIntentChirho {
        schema_chirho: "segment-rotation-intent-v1-chirho".to_owned(),
        log_identity_digest_chirho: identity_chirho.digest_chirho(),
        generation_chirho,
        first_seq_chirho,
        last_seq_chirho,
        byte_len_chirho: active_bytes_chirho.len() as u64,
        segment_digest_chirho: blake3::hash(active_bytes_chirho).to_hex().to_string(),
        final_line_digest_chirho: blake3::hash(final_physical_line_chirho)
            .to_hex()
            .to_string(),
    })
    .unwrap();
    let marker_path_chirho = StoragePathChirho::new_chirho(
        SegmentPathsChirho::new_chirho(harness_chirho.path_chirho().key_chirho())
            .rotation_marker_chirho()
            .as_str_chirho(),
    );
    (marker_path_chirho, marker_chirho)
}

fn traversal_delta_chirho(before_chirho: [usize; 5], after_chirho: [usize; 5]) -> [usize; 5] {
    std::array::from_fn(|index_chirho| after_chirho[index_chirho] - before_chirho[index_chirho])
}

#[test]
fn frozen_reader_ignores_legacy_head_checkpoint_and_accepts_exact_canary_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut journal_chirho, expected_chirho) =
        create_with_expected_genesis_chirho(&harness_chirho);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-exact-chirho",
        ))
        .unwrap();
    let floor_chirho = floor_from_journal_chirho(&journal_chirho);
    let expected_tail_chirho = journal_chirho.verified_losing_tail_chirho();
    drop(journal_chirho);

    let obsolete_checkpoint_path_chirho = StoragePathChirho::new_chirho(format!(
        "{}.head-checkpoint-chirho",
        harness_chirho.path_chirho().key_chirho()
    ));
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &obsolete_checkpoint_path_chirho,
            b"{\"obsolete_and_malformed_chirho\":true",
        )
        .unwrap();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    let reader_chirho = FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .unwrap();

    assert_eq!(
        reader_chirho.floor_relation_chirho(),
        VerifiedLosingTailFloorRelationChirho::ExactCanaryChirho
    );
    assert_eq!(
        reader_chirho.verified_losing_tail_chirho(),
        expected_tail_chirho
    );
    let page_chirho = reader_chirho
        .read_verified_losing_suffix_page_chirho(&LosingSuffixPageRequestChirho::new_chirho(
            LosingSuffixJournalIdentityChirho::new_chirho(expected_chirho.digest_chirho().clone()),
            LosingSuffixCoordinateChirho::new_chirho(
                expected_tail_chirho.coordinate_chirho().seq_chirho(),
                expected_tail_chirho
                    .coordinate_chirho()
                    .record_digest_chirho()
                    .clone(),
            ),
            LosingSuffixCoordinateChirho::new_chirho(0, expected_chirho.digest_chirho().clone()),
            8,
            64 * 1024,
        ))
        .unwrap();
    assert_eq!(page_chirho.records_newest_first_chirho().len(), 1);
    assert!(page_chirho.reached_anchor_chirho());
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "held cut derivation must not repair or rewrite any durable object"
    );
}

#[test]
fn frozen_reader_refuses_a_signed_tail_rolled_back_below_the_canary_floor_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut journal_chirho, expected_chirho) =
        create_with_expected_genesis_chirho(&harness_chirho);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-rollback-first-chirho",
        ))
        .unwrap();
    let first_cut_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    journal_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            10,
            "frozen-rollback-floor-chirho",
        ))
        .unwrap();
    let floor_chirho = floor_from_journal_chirho(&journal_chirho);
    drop(journal_chirho);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &first_cut_bytes_chirho)
        .unwrap();

    assert!(FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .is_err());
}

#[test]
fn frozen_reader_accepts_exactly_one_committed_record_ahead_and_refuses_two_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut journal_chirho, expected_chirho) =
        create_with_expected_genesis_chirho(&harness_chirho);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-floor-chirho",
        ))
        .unwrap();
    let floor_chirho = floor_from_journal_chirho(&journal_chirho);
    journal_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            10,
            "frozen-one-ahead-chirho",
        ))
        .unwrap();
    {
        let reader_chirho = FrozenLosingJournalReaderChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &expected_chirho,
            &floor_chirho,
        )
        .unwrap();
        assert_eq!(
            reader_chirho.floor_relation_chirho(),
            VerifiedLosingTailFloorRelationChirho::OneCommittedRecordAheadChirho
        );
    }
    journal_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            10,
            "frozen-two-ahead-chirho",
        ))
        .unwrap();
    drop(journal_chirho);

    assert!(FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .is_err());
}

#[test]
fn frozen_reader_accepts_one_epoch_advancing_record_with_exact_canary_anchor_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut journal_chirho, expected_chirho) =
        create_with_expected_genesis_chirho(&harness_chirho);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-epoch-floor-chirho",
        ))
        .unwrap();
    let floor_chirho = floor_from_journal_chirho(&journal_chirho);
    journal_chirho.advance_epoch_chirho(2).unwrap();
    journal_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            10,
            "frozen-epoch-one-ahead-chirho",
        ))
        .unwrap();
    drop(journal_chirho);

    let reader_chirho = FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .unwrap();
    assert_eq!(
        reader_chirho.floor_relation_chirho(),
        VerifiedLosingTailFloorRelationChirho::OneCommittedRecordAheadChirho
    );
    assert_eq!(
        reader_chirho
            .verified_losing_tail_chirho()
            .record_epoch_chirho(),
        2
    );
}

#[test]
fn frozen_reader_retains_bounded_torn_suffix_and_detects_later_mutation_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut journal_chirho, expected_chirho) =
        create_with_expected_genesis_chirho(&harness_chirho);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-torn-chirho",
        ))
        .unwrap();
    let floor_chirho = floor_from_journal_chirho(&journal_chirho);
    drop(journal_chirho);
    harness_chirho
        .storage_chirho
        .append_durable_chirho(&harness_chirho.path_chirho(), b"{\"torn_chirho\":")
        .unwrap();
    let reader_chirho = FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .unwrap();
    reader_chirho
        .revalidate_current_losing_tail_chirho()
        .unwrap();

    harness_chirho
        .storage_chirho
        .append_durable_chirho(&harness_chirho.path_chirho(), b"x")
        .unwrap();
    assert!(reader_chirho
        .revalidate_current_losing_tail_chirho()
        .is_err());
}

#[test]
fn frozen_reader_classifies_pre_and_post_manifest_rotation_without_repair_chirho() {
    let pre_harness_chirho = HarnessChirho::new_chirho();
    let (mut pre_journal_chirho, pre_expected_chirho) =
        create_with_expected_genesis_chirho(&pre_harness_chirho);
    pre_journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-pre-rotation-chirho",
        ))
        .unwrap();
    let pre_floor_chirho = floor_from_journal_chirho(&pre_journal_chirho);
    let pre_tail_seq_chirho = pre_journal_chirho.tail_seq_chirho();
    let pre_active_bytes_chirho = pre_harness_chirho
        .storage_chirho
        .read_all_chirho(&pre_harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    drop(pre_journal_chirho);
    let (pre_marker_path_chirho, pre_marker_chirho) = rotation_marker_chirho(
        &pre_harness_chirho,
        &pre_active_bytes_chirho,
        0,
        0,
        pre_tail_seq_chirho,
    );
    pre_harness_chirho
        .storage_chirho
        .atomic_write_chirho(&pre_marker_path_chirho, &pre_marker_chirho)
        .unwrap();
    FrozenLosingJournalReaderChirho::open_chirho(
        pre_harness_chirho.ports_chirho(),
        pre_harness_chirho.path_chirho(),
        &pre_expected_chirho,
        &pre_floor_chirho,
    )
    .unwrap();

    let post_harness_chirho = HarnessChirho::new_chirho();
    let (mut post_journal_chirho, post_expected_chirho) =
        create_with_expected_genesis_chirho(&post_harness_chirho);
    post_journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-post-rotation-chirho",
        ))
        .unwrap();
    let post_floor_chirho = floor_from_journal_chirho(&post_journal_chirho);
    let post_tail_seq_chirho = post_journal_chirho.tail_seq_chirho();
    let post_active_bytes_chirho = post_harness_chirho
        .storage_chirho
        .read_all_chirho(&post_harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    post_journal_chirho.rotate_chirho().unwrap();
    drop(post_journal_chirho);
    let (post_marker_path_chirho, post_marker_chirho) = rotation_marker_chirho(
        &post_harness_chirho,
        &post_active_bytes_chirho,
        0,
        0,
        post_tail_seq_chirho,
    );
    post_harness_chirho
        .storage_chirho
        .atomic_write_chirho(&post_marker_path_chirho, &post_marker_chirho)
        .unwrap();
    FrozenLosingJournalReaderChirho::open_chirho(
        post_harness_chirho.ports_chirho(),
        post_harness_chirho.path_chirho(),
        &post_expected_chirho,
        &post_floor_chirho,
    )
    .unwrap();
}

#[test]
fn frozen_reader_recovers_torn_first_manifest_append_only_as_authenticated_prefix_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (mut journal_chirho, expected_chirho) =
        create_with_expected_genesis_chirho(&harness_chirho);
    journal_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "frozen-torn-first-manifest-chirho",
        ))
        .unwrap();
    let floor_chirho = floor_from_journal_chirho(&journal_chirho);
    let tail_seq_chirho = journal_chirho.tail_seq_chirho();
    let active_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&harness_chirho.path_chirho())
        .unwrap()
        .unwrap();
    journal_chirho.rotate_chirho().unwrap();
    drop(journal_chirho);

    let segment_paths_chirho =
        SegmentPathsChirho::new_chirho(harness_chirho.path_chirho().key_chirho());
    let manifest_path_chirho =
        StoragePathChirho::new_chirho(segment_paths_chirho.manifest_chirho().as_str_chirho());
    let manifest_bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&manifest_path_chirho)
        .unwrap()
        .unwrap();
    assert_eq!(manifest_bytes_chirho.last(), Some(&b'\n'));
    let torn_len_chirho = manifest_bytes_chirho.len() / 2;
    assert!(torn_len_chirho > 0);
    let torn_manifest_chirho = manifest_bytes_chirho[..torn_len_chirho].to_vec();
    assert!(!torn_manifest_chirho.contains(&b'\n'));

    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&harness_chirho.path_chirho(), &active_bytes_chirho)
        .unwrap();
    let (marker_path_chirho, marker_chirho) =
        rotation_marker_chirho(&harness_chirho, &active_bytes_chirho, 0, 0, tail_seq_chirho);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&marker_path_chirho, &marker_chirho)
        .unwrap();
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&manifest_path_chirho, &torn_manifest_chirho)
        .unwrap();

    let reader_chirho = FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .unwrap();
    reader_chirho
        .revalidate_current_losing_tail_chirho()
        .unwrap();

    let mut forged_torn_manifest_chirho = torn_manifest_chirho.clone();
    forged_torn_manifest_chirho[0] ^= 1;
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&manifest_path_chirho, &forged_torn_manifest_chirho)
        .unwrap();
    assert!(reader_chirho
        .revalidate_current_losing_tail_chirho()
        .is_err());
    assert!(FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .is_err());

    let (_overflow_marker_path_chirho, overflow_marker_chirho) =
        rotation_marker_chirho(&harness_chirho, &active_bytes_chirho, 0, 0, u64::MAX);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&marker_path_chirho, &overflow_marker_chirho)
        .unwrap();
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&manifest_path_chirho, &torn_manifest_chirho)
        .unwrap();
    assert!(FrozenLosingJournalReaderChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &expected_chirho,
        &floor_chirho,
    )
    .is_err());
}

#[test]
fn frozen_reader_open_cost_is_independent_of_lifetime_record_count_chirho() {
    fn derive_cost_chirho(record_count_chirho: usize) -> ([usize; 5], [usize; 6]) {
        let harness_chirho = HarnessChirho::new_chirho();
        let (mut journal_chirho, expected_chirho) =
            create_with_expected_genesis_chirho(&harness_chirho);
        journal_chirho
            .append_chirho(mint_request_chirho(
                "issuer-chirho",
                1_000,
                "frozen-cost-seed-chirho",
            ))
            .unwrap();
        for index_chirho in 1..record_count_chirho {
            journal_chirho
                .append_chirho(transfer_request_chirho(
                    "issuer-chirho",
                    if index_chirho % 2 == 0 {
                        "alice-chirho"
                    } else {
                        "bob-chirho"
                    },
                    1,
                    &format!("frozen-cost-{index_chirho}-chirho"),
                ))
                .unwrap();
        }
        let floor_chirho = floor_from_journal_chirho(&journal_chirho);
        drop(journal_chirho);
        let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
        let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
        FrozenLosingJournalReaderChirho::open_chirho(
            harness_chirho.ports_chirho(),
            harness_chirho.path_chirho(),
            &expected_chirho,
            &floor_chirho,
        )
        .unwrap();
        (
            traversal_delta_chirho(
                reads_before_chirho,
                harness_chirho.storage_chirho.traversal_read_counts_chirho(),
            ),
            std::array::from_fn(|index_chirho| {
                harness_chirho.storage_chirho.storage_write_counts_chirho()[index_chirho]
                    - writes_before_chirho[index_chirho]
            }),
        )
    }

    let small_chirho = derive_cost_chirho(2);
    let large_chirho = derive_cost_chirho(512);
    assert_eq!(small_chirho, large_chirho);
    assert_eq!(large_chirho.0[2], 0, "no whole-object read");
    assert_eq!(large_chirho.0[3], 0, "no storage listing");
    assert_eq!(large_chirho.1, [0; 6], "no durable writes or repairs");
}
