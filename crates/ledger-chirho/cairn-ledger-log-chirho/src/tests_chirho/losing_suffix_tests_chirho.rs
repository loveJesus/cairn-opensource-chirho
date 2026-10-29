// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::journal_chirho::{
    AppendLegRequestChirho, AppendRequestBoundDimensionChirho, AppendRequestChirho,
    JournalErrorChirho, LedgerJournalChirho, MAX_APPEND_REQUEST_BYTES_CHIRHO,
    MAX_APPEND_REQUEST_LEGS_CHIRHO,
};
use crate::journal_tests_chirho::{mint_request_chirho, transfer_request_chirho, HarnessChirho};
use crate::losing_suffix_chirho::{
    LosingSuffixCoordinateChirho, LosingSuffixIdentityFieldChirho,
    LosingSuffixJournalIdentityChirho, LosingSuffixPageLimitChirho, LosingSuffixPageRequestChirho,
    LosingSuffixReadErrorChirho, MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO,
    MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO, MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
};
use crate::ports_chirho::{LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, HlcChirho, LedgerLegChirho, LedgerOpChirho, LedgerRecordChirho,
    LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    LEDGER_FORMAT_VERSION_V1_CHIRHO, LEDGER_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_seqlog_chirho::segment_chirho::paths_chirho::SegmentPathsChirho;

fn request_at_current_genesis_chirho(
    engine_chirho: &LedgerJournalChirho<'_>,
    max_records_chirho: usize,
    max_bytes_chirho: usize,
) -> LosingSuffixPageRequestChirho {
    let tail_digest_chirho = engine_chirho.tail_chirho().1.clone();
    LosingSuffixPageRequestChirho::new_chirho(
        LosingSuffixJournalIdentityChirho::new_chirho(tail_digest_chirho.clone()),
        LosingSuffixCoordinateChirho::new_chirho(0, tail_digest_chirho.clone()),
        LosingSuffixCoordinateChirho::new_chirho(0, tail_digest_chirho),
        max_records_chirho,
        max_bytes_chirho,
    )
}

fn request_for_suffix_chirho(
    engine_chirho: &LedgerJournalChirho<'_>,
    genesis_digest_chirho: &DigestChirho,
    anchor_seq_chirho: u64,
    anchor_digest_chirho: &DigestChirho,
    max_records_chirho: usize,
    max_bytes_chirho: usize,
) -> LosingSuffixPageRequestChirho {
    LosingSuffixPageRequestChirho::new_chirho(
        LosingSuffixJournalIdentityChirho::new_chirho(genesis_digest_chirho.clone()),
        LosingSuffixCoordinateChirho::new_chirho(
            engine_chirho.tail_chirho().0,
            engine_chirho.tail_chirho().1.clone(),
        ),
        LosingSuffixCoordinateChirho::new_chirho(anchor_seq_chirho, anchor_digest_chirho.clone()),
        max_records_chirho,
        max_bytes_chirho,
    )
}

#[test]
fn verified_losing_tail_uses_last_committed_epoch_not_advanced_lease_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "verified-losing-tail-chirho",
        ))
        .unwrap();
    let committed_tail_chirho = engine_chirho.verified_losing_tail_chirho();
    engine_chirho.advance_epoch_chirho(2).unwrap();
    let lease_advanced_tail_chirho = engine_chirho.verified_losing_tail_chirho();

    assert_eq!(committed_tail_chirho.record_epoch_chirho(), 1);
    assert_eq!(lease_advanced_tail_chirho, committed_tail_chirho);
    assert_eq!(
        lease_advanced_tail_chirho
            .identity_chirho()
            .genesis_digest_chirho(),
        engine_chirho.genesis_digest_chirho()
    );
    assert_eq!(
        lease_advanced_tail_chirho.coordinate_chirho().seq_chirho(),
        engine_chirho.tail_seq_chirho()
    );
    assert_eq!(
        lease_advanced_tail_chirho
            .coordinate_chirho()
            .record_digest_chirho(),
        engine_chirho.tail_line_digest_chirho()
    );
}

#[test]
fn append_refuses_oversized_request_bytes_before_clone_sign_or_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            1_000,
            "bounded-request-seed-chirho",
        ))
        .unwrap();
    let mut oversized_request_chirho =
        transfer_request_chirho("issuer-chirho", "alice-chirho", 1, "placeholder-chirho");
    oversized_request_chirho.idempotency_key_chirho =
        "x".repeat(MAX_APPEND_REQUEST_BYTES_CHIRHO + 1);
    let tail_before_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    let signer_calls_before_chirho = harness_chirho.signer_chirho.sign_calls_chirho();
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    assert_eq!(
        engine_chirho.append_chirho(oversized_request_chirho),
        Err(JournalErrorChirho::AppendRequestBoundsChirho {
            dimension_chirho: AppendRequestBoundDimensionChirho::EncodedBytesChirho,
            observed_at_least_chirho: MAX_APPEND_REQUEST_BYTES_CHIRHO + 1,
            maximum_chirho: MAX_APPEND_REQUEST_BYTES_CHIRHO,
        })
    );
    assert_eq!(
        harness_chirho.signer_chirho.sign_calls_chirho(),
        signer_calls_before_chirho,
        "the oversized borrowed request must not reach signing"
    );
    assert_eq!(
        harness_chirho.storage_chirho.traversal_read_counts_chirho(),
        reads_before_chirho,
        "the oversized borrowed request must perform zero storage reads"
    );
    assert_eq!(engine_chirho.tail_chirho().0, tail_before_chirho.0);
    assert_eq!(engine_chirho.tail_chirho().1, &tail_before_chirho.1);
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "the oversized borrowed request must perform zero storage writes"
    );
}

#[test]
fn append_refuses_json_escape_expansion_before_clone_sign_or_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            1_000,
            "escaped-request-seed-chirho",
        ))
        .unwrap();
    let mut escaped_request_chirho =
        transfer_request_chirho("issuer-chirho", "alice-chirho", 1, "placeholder-chirho");
    escaped_request_chirho.idempotency_key_chirho =
        "\"".repeat((MAX_APPEND_REQUEST_BYTES_CHIRHO / 2) + 1);
    assert!(
        escaped_request_chirho.idempotency_key_chirho.len() < MAX_APPEND_REQUEST_BYTES_CHIRHO,
        "the twin must pass the raw borrowed-string precheck"
    );
    assert!(
        serde_json::to_vec(&escaped_request_chirho).unwrap().len()
            > MAX_APPEND_REQUEST_BYTES_CHIRHO,
        "JSON escaping, rather than raw string length, must cross the encoded-byte limit"
    );

    let tail_before_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    let signer_calls_before_chirho = harness_chirho.signer_chirho.sign_calls_chirho();
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    assert_eq!(
        engine_chirho.append_chirho(escaped_request_chirho),
        Err(JournalErrorChirho::AppendRequestBoundsChirho {
            dimension_chirho: AppendRequestBoundDimensionChirho::EncodedBytesChirho,
            observed_at_least_chirho: MAX_APPEND_REQUEST_BYTES_CHIRHO + 1,
            maximum_chirho: MAX_APPEND_REQUEST_BYTES_CHIRHO,
        })
    );
    assert_eq!(
        harness_chirho.signer_chirho.sign_calls_chirho(),
        signer_calls_before_chirho,
        "the encoded-byte refusal must happen before signing"
    );
    assert_eq!(
        harness_chirho.storage_chirho.traversal_read_counts_chirho(),
        reads_before_chirho,
        "the encoded-byte refusal must perform zero storage reads"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "the encoded-byte refusal must perform zero storage writes"
    );
    assert_eq!(engine_chirho.tail_chirho().0, tail_before_chirho.0);
    assert_eq!(engine_chirho.tail_chirho().1, &tail_before_chirho.1);
}

#[test]
fn append_refuses_over_leg_limit_before_duplicate_fold_sign_or_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let duplicate_key_chirho = "bounded-record-seed-chirho";
    engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            1_000,
            duplicate_key_chirho,
        ))
        .unwrap();

    let pair_chirho =
        transfer_request_chirho("issuer-chirho", "alice-chirho", 1, "unused-chirho").legs_chirho;
    let mut over_limit_request_chirho =
        transfer_request_chirho("issuer-chirho", "alice-chirho", 1, duplicate_key_chirho);
    over_limit_request_chirho.legs_chirho.clear();
    while over_limit_request_chirho.legs_chirho.len() < MAX_APPEND_REQUEST_LEGS_CHIRHO + 1 {
        over_limit_request_chirho
            .legs_chirho
            .extend(pair_chirho.iter().cloned());
    }
    over_limit_request_chirho
        .legs_chirho
        .truncate(MAX_APPEND_REQUEST_LEGS_CHIRHO + 1);

    let tail_before_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    let signer_calls_before_chirho = harness_chirho.signer_chirho.sign_calls_chirho();
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    assert_eq!(
        engine_chirho.append_chirho(over_limit_request_chirho),
        Err(JournalErrorChirho::AppendRequestBoundsChirho {
            dimension_chirho: AppendRequestBoundDimensionChirho::LegsChirho,
            observed_at_least_chirho: MAX_APPEND_REQUEST_LEGS_CHIRHO + 1,
            maximum_chirho: MAX_APPEND_REQUEST_LEGS_CHIRHO,
        }),
        "the leg-count refusal must win even over an existing duplicate key"
    );
    assert_eq!(
        harness_chirho.signer_chirho.sign_calls_chirho(),
        signer_calls_before_chirho,
        "the over-limit request must not reach signing"
    );
    assert_eq!(
        harness_chirho.storage_chirho.traversal_read_counts_chirho(),
        reads_before_chirho,
        "the over-limit request must perform zero storage reads"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "the over-limit request must perform zero storage writes"
    );
    assert_eq!(engine_chirho.tail_chirho().0, tail_before_chirho.0);
    assert_eq!(engine_chirho.tail_chirho().1, &tail_before_chirho.1);
}

#[test]
fn persisted_v1_record_above_new_request_limits_still_opens_chirho() {
    const PAIR_COUNT_CHIRHO: u64 = 200;

    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let mint_chirho = engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            1_000,
            "persisted-v1-seed-chirho",
        ))
        .unwrap();
    drop(engine_chirho);

    let mut legs_chirho = Vec::with_capacity((PAIR_COUNT_CHIRHO * 2) as usize);
    for pair_chirho in 1..=PAIR_COUNT_CHIRHO {
        legs_chirho.push(LedgerLegChirho {
            account_chirho: cairn_ledger_model_chirho::LogIdChirho::new_chirho(
                "issuer-chirho",
                "money-chirho",
            ),
            kind_policy_ref_chirho: cairn_ledger_model_chirho::ids_chirho::AssetKindRefChirho(
                cairn_ledger_model_chirho::ids_chirho::DigestChirho(
                    "policy-money-v1-chirho".into(),
                ),
            ),
            delta_chirho: LegDeltaChirho::DebitChirho,
            amount_chirho: 1,
            post_chirho: LegPostStateChirho {
                credits_total_chirho: 1_000,
                debits_total_chirho: pair_chirho,
                held_chirho: 0,
            },
            counterpart_chirho: None,
        });
        legs_chirho.push(LedgerLegChirho {
            account_chirho: cairn_ledger_model_chirho::LogIdChirho::new_chirho(
                "alice-chirho",
                "money-chirho",
            ),
            kind_policy_ref_chirho: cairn_ledger_model_chirho::ids_chirho::AssetKindRefChirho(
                cairn_ledger_model_chirho::ids_chirho::DigestChirho(
                    "policy-money-v1-chirho".into(),
                ),
            ),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 1,
            post_chirho: LegPostStateChirho {
                credits_total_chirho: pair_chirho,
                debits_total_chirho: 0,
                held_chirho: 0,
            },
            counterpart_chirho: None,
        });
    }
    let corresponding_request_chirho = AppendRequestChirho {
        op_chirho: LedgerOpChirho::TransferChirho,
        legs_chirho: legs_chirho
            .iter()
            .map(|leg_chirho| AppendLegRequestChirho {
                account_chirho: leg_chirho.account_chirho.clone(),
                kind_policy_ref_chirho: leg_chirho.kind_policy_ref_chirho.clone(),
                delta_chirho: leg_chirho.delta_chirho.clone(),
                amount_chirho: leg_chirho.amount_chirho,
                counterpart_chirho: leg_chirho.counterpart_chirho.clone(),
            })
            .collect(),
        idempotency_key_chirho: "persisted-v1-wide-transfer-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "issuer-chirho".to_owned(),
        },
    };
    let corresponding_request_bytes_chirho =
        serde_json::to_vec(&corresponding_request_chirho).unwrap();
    let mut record_chirho = LedgerRecordChirho {
        schema_chirho: LEDGER_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        format_version_chirho: LEDGER_FORMAT_VERSION_V1_CHIRHO,
        seq_chirho: mint_chirho.seq_chirho + 1,
        prev_chirho: mint_chirho.record_digest_chirho,
        epoch_chirho: 1,
        hlc_chirho: HlcChirho {
            physical_ms_chirho: 1_001,
            logical_chirho: 0,
        },
        legs_chirho,
        op_chirho: LedgerOpChirho::TransferChirho,
        idempotency_key_chirho: "persisted-v1-wide-transfer-chirho".to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::CauserChirho {
            principal_chirho: "issuer-chirho".to_owned(),
        },
        anchor_chirho: None,
        sig_chirho: String::new(),
        key_id_chirho: harness_chirho.signer_chirho.key_id_chirho(),
    };
    let signed_content_chirho = ledger_record_signed_content_line_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho = harness_chirho
        .signer_chirho
        .sign_chirho(&signed_content_chirho)
        .unwrap();
    let line_chirho = canonical_ledger_record_line_chirho(&record_chirho).unwrap();
    assert!(
        record_chirho.legs_chirho.len() > MAX_APPEND_REQUEST_LEGS_CHIRHO,
        "the persisted-v1 compatibility twin must exceed the new request leg policy"
    );
    assert!(
        line_chirho.len() > MAX_APPEND_REQUEST_BYTES_CHIRHO,
        "the persisted-v1 compatibility twin must itself remain a wide stored record"
    );
    assert!(
        corresponding_request_bytes_chirho.len() > MAX_APPEND_REQUEST_BYTES_CHIRHO,
        "the corresponding new append request must exceed the actual request-byte policy"
    );
    harness_chirho
        .storage_chirho
        .append_durable_chirho(
            &harness_chirho.path_chirho(),
            format!("{line_chirho}\n").as_bytes(),
        )
        .unwrap();

    let reopened_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        &harness_chirho.cluster_chirho(),
    )
    .expect("existing valid ledger-record-v1 bytes remain readable above new request limits");
    assert_eq!(reopened_chirho.tail_seq_chirho(), record_chirho.seq_chirho);
    assert_eq!(
        reopened_chirho
            .head_state_chirho(&cairn_ledger_model_chirho::LogIdChirho::new_chirho(
                "alice-chirho",
                "money-chirho",
            ))
            .unwrap()
            .credits_total_chirho,
        PAIR_COUNT_CHIRHO
    );
}

#[test]
fn losing_suffix_page_limits_are_nonzero_and_capped_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();

    let zero_records_chirho =
        request_at_current_genesis_chirho(&engine_chirho, 0, MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO);
    assert_eq!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&zero_records_chirho),
        Err(LosingSuffixReadErrorChirho::InvalidPageLimitChirho {
            limit_chirho: LosingSuffixPageLimitChirho::RecordsChirho,
            requested_chirho: 0,
            maximum_chirho: MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        })
    );

    let over_records_chirho = request_at_current_genesis_chirho(
        &engine_chirho,
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO + 1,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    assert_eq!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&over_records_chirho),
        Err(LosingSuffixReadErrorChirho::InvalidPageLimitChirho {
            limit_chirho: LosingSuffixPageLimitChirho::RecordsChirho,
            requested_chirho: MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO + 1,
            maximum_chirho: MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        })
    );

    let zero_bytes_chirho =
        request_at_current_genesis_chirho(&engine_chirho, MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO, 0);
    assert_eq!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&zero_bytes_chirho),
        Err(LosingSuffixReadErrorChirho::InvalidPageLimitChirho {
            limit_chirho: LosingSuffixPageLimitChirho::BytesChirho,
            requested_chirho: 0,
            maximum_chirho: MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
        })
    );

    let over_bytes_chirho = request_at_current_genesis_chirho(
        &engine_chirho,
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO + 1,
    );
    assert_eq!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&over_bytes_chirho),
        Err(LosingSuffixReadErrorChirho::InvalidPageLimitChirho {
            limit_chirho: LosingSuffixPageLimitChirho::BytesChirho,
            requested_chirho: MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO + 1,
            maximum_chirho: MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
        })
    );
}

#[test]
fn losing_suffix_identity_inputs_are_fixed_work_before_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let invalid_digest_chirho = DigestChirho("not-a-blake3-digest-chirho".to_owned());
    let digest_request_chirho = LosingSuffixPageRequestChirho::new_chirho(
        LosingSuffixJournalIdentityChirho::new_chirho(invalid_digest_chirho.clone()),
        LosingSuffixCoordinateChirho::new_chirho(0, invalid_digest_chirho.clone()),
        LosingSuffixCoordinateChirho::new_chirho(0, invalid_digest_chirho.clone()),
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    assert_eq!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&digest_request_chirho),
        Err(LosingSuffixReadErrorChirho::InvalidIdentityFieldChirho {
            field_chirho: LosingSuffixIdentityFieldChirho::GenesisDigestChirho,
            observed_bytes_chirho: invalid_digest_chirho.0.len(),
        })
    );
    assert_eq!(
        harness_chirho.storage_chirho.traversal_read_counts_chirho(),
        reads_before_chirho,
        "malformed digest text must refuse before any storage operation"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "malformed digest text must perform zero storage writes"
    );
}

#[test]
fn losing_suffix_pages_cross_two_segments_without_manifest_scan_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let genesis_digest_chirho = engine_chirho.tail_chirho().1.clone();
    let anchor_chirho = engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            1_000,
            "suffix-mint-chirho",
        ))
        .unwrap();
    let seq2_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            300,
            "suffix-seq2-chirho",
        ))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "alice-chirho",
            "bob-chirho",
            50,
            "suffix-seq3-chirho",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            20,
            "suffix-seq4-chirho",
        ))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "alice-chirho",
            "issuer-chirho",
            10,
            "suffix-seq5-chirho",
        ))
        .unwrap();

    let request_chirho = request_for_suffix_chirho(
        &engine_chirho,
        &genesis_digest_chirho,
        anchor_chirho.seq_chirho,
        &anchor_chirho.record_digest_chirho,
        2,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    let reads_before_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    let writes_before_chirho = harness_chirho.storage_chirho.storage_write_counts_chirho();
    let first_page_chirho = engine_chirho
        .read_verified_losing_suffix_page_chirho(&request_chirho)
        .unwrap();
    assert_eq!(
        first_page_chirho
            .records_newest_first_chirho()
            .iter()
            .map(|record_chirho| record_chirho.seq_chirho)
            .collect::<Vec<_>>(),
        vec![5, 4]
    );
    assert!(!first_page_chirho.reached_anchor_chirho());
    let cursor_chirho = first_page_chirho.next_cursor_chirho().unwrap().clone();
    let cursor_bytes_chirho = cursor_chirho.encode_durable_chirho().unwrap();
    assert!(cursor_bytes_chirho.len() <= MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO);
    let decoded_cursor_chirho = engine_chirho
        .decode_verified_losing_suffix_cursor_chirho(&cursor_bytes_chirho)
        .unwrap();
    assert_eq!(
        decoded_cursor_chirho.encode_durable_chirho().unwrap(),
        cursor_bytes_chirho,
        "durable cursor bytes must round-trip canonically"
    );

    let second_page_chirho = engine_chirho
        .read_verified_losing_suffix_page_chirho(
            &request_chirho
                .clone()
                .with_cursor_chirho(decoded_cursor_chirho),
        )
        .unwrap();
    assert_eq!(
        second_page_chirho
            .records_newest_first_chirho()
            .iter()
            .map(|record_chirho| record_chirho.seq_chirho)
            .collect::<Vec<_>>(),
        vec![3, 2]
    );
    assert_eq!(
        second_page_chirho.records_newest_first_chirho()[1].prev_chirho,
        anchor_chirho.record_digest_chirho
    );
    assert!(second_page_chirho.reached_anchor_chirho());
    assert!(second_page_chirho.next_cursor_chirho().is_none());
    let reads_after_chirho = harness_chirho.storage_chirho.traversal_read_counts_chirho();
    assert_eq!(
        reads_after_chirho[2], reads_before_chirho[2],
        "reverse pages must never full-read the manifest or any segment"
    );
    assert_eq!(
        reads_after_chirho[3], reads_before_chirho[3],
        "reverse pages must never list storage"
    );
    assert_eq!(
        reads_after_chirho[4], reads_before_chirho[4],
        "reverse pages need no existence scan"
    );
    assert_eq!(
        harness_chirho.storage_chirho.storage_write_counts_chirho(),
        writes_before_chirho,
        "reverse pages and durable cursor minting must not mutate storage"
    );
    assert_eq!(seq2_chirho.seq_chirho, 2);
}

#[test]
fn losing_suffix_cursor_and_byte_cap_fail_closed_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let genesis_digest_chirho = engine_chirho.tail_chirho().1.clone();
    let anchor_chirho = engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "cursor-mint-chirho",
        ))
        .unwrap();
    let seq2_chirho = engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            10,
            "cursor-seq2-chirho",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            10,
            "cursor-seq3-chirho",
        ))
        .unwrap();
    let request_chirho = request_for_suffix_chirho(
        &engine_chirho,
        &genesis_digest_chirho,
        anchor_chirho.seq_chirho,
        &anchor_chirho.record_digest_chirho,
        1,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    let page_chirho = engine_chirho
        .read_verified_losing_suffix_page_chirho(&request_chirho)
        .unwrap();
    let wrong_anchor_request_chirho = request_for_suffix_chirho(
        &engine_chirho,
        &genesis_digest_chirho,
        0,
        &genesis_digest_chirho,
        1,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    )
    .with_cursor_chirho(page_chirho.next_cursor_chirho().unwrap().clone());
    assert_eq!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&wrong_anchor_request_chirho),
        Err(LosingSuffixReadErrorChirho::CursorContinuityMismatchChirho)
    );
    let mut tampered_chirho = page_chirho
        .next_cursor_chirho()
        .unwrap()
        .encode_durable_chirho()
        .unwrap();
    let offset_chirho = tampered_chirho
        .windows(seq2_chirho.record_digest_chirho.0.len())
        .position(|window_chirho| window_chirho == seq2_chirho.record_digest_chirho.0.as_bytes())
        .unwrap();
    tampered_chirho[offset_chirho] = if tampered_chirho[offset_chirho] == b'a' {
        b'b'
    } else {
        b'a'
    };
    assert_eq!(
        engine_chirho.decode_verified_losing_suffix_cursor_chirho(&tampered_chirho),
        Err(LosingSuffixReadErrorChirho::CursorSignatureInvalidChirho)
    );

    let mut noncanonical_chirho = page_chirho
        .next_cursor_chirho()
        .unwrap()
        .encode_durable_chirho()
        .unwrap();
    noncanonical_chirho.push(b' ');
    assert_eq!(
        engine_chirho.decode_verified_losing_suffix_cursor_chirho(&noncanonical_chirho),
        Err(LosingSuffixReadErrorChirho::CursorNonCanonicalChirho)
    );
    let oversized_chirho = vec![b'x'; MAX_LOSING_SUFFIX_CURSOR_BYTES_CHIRHO + 1];
    assert!(matches!(
        engine_chirho.decode_verified_losing_suffix_cursor_chirho(&oversized_chirho),
        Err(LosingSuffixReadErrorChirho::CursorBytesTooLargeChirho { .. })
    ));

    let tiny_request_chirho = request_for_suffix_chirho(
        &engine_chirho,
        &genesis_digest_chirho,
        anchor_chirho.seq_chirho,
        &anchor_chirho.record_digest_chirho,
        1,
        1,
    );
    assert!(matches!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&tiny_request_chirho),
        Err(LosingSuffixReadErrorChirho::RecordExceedsPageBytesChirho { .. })
    ));

    let wrong_anchor_digest_chirho =
        DigestChirho(blake3::hash(b"wrong-anchor-chirho").to_hex().to_string());
    let wrong_anchor_chirho = request_for_suffix_chirho(
        &engine_chirho,
        &genesis_digest_chirho,
        anchor_chirho.seq_chirho,
        &wrong_anchor_digest_chirho,
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    assert_eq!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&wrong_anchor_chirho),
        Err(LosingSuffixReadErrorChirho::AnchorDigestMismatchChirho)
    );
}

#[test]
fn losing_suffix_refuses_tampered_predecessor_index_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.ports_chirho(),
        harness_chirho.path_chirho(),
        harness_chirho.cluster_chirho(),
        1,
    )
    .unwrap();
    let genesis_digest_chirho = engine_chirho.tail_chirho().1.clone();
    let anchor_chirho = engine_chirho
        .append_chirho(mint_request_chirho(
            "issuer-chirho",
            100,
            "index-mint-chirho",
        ))
        .unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "alice-chirho",
            10,
            "index-seq2-chirho",
        ))
        .unwrap();
    engine_chirho.rotate_chirho().unwrap();
    engine_chirho
        .append_chirho(transfer_request_chirho(
            "issuer-chirho",
            "bob-chirho",
            10,
            "index-seq3-chirho",
        ))
        .unwrap();

    let manifest_digest_chirho = engine_chirho
        .manifest_tail_entry_digest_for_test_chirho()
        .unwrap()
        .to_owned();
    let index_path_chirho =
        SegmentPathsChirho::new_chirho(harness_chirho.path_chirho().key_chirho())
            .predecessor_index_entry_chirho(&manifest_digest_chirho);
    let storage_path_chirho = StoragePathChirho::new_chirho(index_path_chirho.as_str_chirho());
    let mut bytes_chirho = harness_chirho
        .storage_chirho
        .read_all_chirho(&storage_path_chirho)
        .unwrap()
        .unwrap();
    let digest_offset_chirho = bytes_chirho
        .windows(manifest_digest_chirho.len())
        .position(|window_chirho| window_chirho == manifest_digest_chirho.as_bytes())
        .unwrap();
    bytes_chirho[digest_offset_chirho] = if bytes_chirho[digest_offset_chirho] == b'a' {
        b'b'
    } else {
        b'a'
    };
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&storage_path_chirho, &bytes_chirho)
        .unwrap();

    let request_chirho = request_for_suffix_chirho(
        &engine_chirho,
        &genesis_digest_chirho,
        anchor_chirho.seq_chirho,
        &anchor_chirho.record_digest_chirho,
        MAX_LOSING_SUFFIX_PAGE_RECORDS_CHIRHO,
        MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO,
    );
    assert!(matches!(
        engine_chirho.read_verified_losing_suffix_page_chirho(&request_chirho),
        Err(LosingSuffixReadErrorChirho::PredecessorIndexChirho { .. })
    ));
}
