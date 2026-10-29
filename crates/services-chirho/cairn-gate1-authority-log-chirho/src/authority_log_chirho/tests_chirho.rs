// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use cairn_model_gate1_chirho::{
    canonical_gate1_authority_head_json_chirho, canonical_gate1_authority_record_json_chirho,
    gate1_authority_family_line_digest_chirho, gate1_authority_record_digest_chirho,
    Gate1AuthorityFamilyWatermarkChirho, GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO,
    GATE1_BILLING_USAGE_FAMILY_CHIRHO, GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
    GATE1_LEDGER_FAMILY_CHIRHO, GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
};
use cairn_writer_head_chirho::writer_head_chirho::issue_writer_fence_for_root_chirho;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-gate1-authority-{label_chirho}-{}-{nanos_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    root_chirho
}

fn input_chirho(seq_chirho: u64) -> Gate1AuthorityAppendInputChirho<'static> {
    input_for_family_chirho(GATE1_LEDGER_FAMILY_CHIRHO, seq_chirho)
}

fn input_for_family_chirho(
    family_chirho: &'static str,
    seq_chirho: u64,
) -> Gate1AuthorityAppendInputChirho<'static> {
    let line_chirho = match seq_chirho {
        0 => "{\"seq_chirho\":0,\"amount_chirho\":7}",
        1 => "{\"seq_chirho\":1,\"amount_chirho\":9}",
        _ => "{\"seq_chirho\":2,\"amount_chirho\":11}",
    };
    Gate1AuthorityAppendInputChirho {
        family_chirho,
        family_seq_chirho: seq_chirho,
        family_line_chirho: line_chirho,
        at_ms_chirho: 1_000 + seq_chirho,
    }
}

fn family_lines_chirho(count_chirho: u64) -> Vec<Gate1AuthorityFamilyLineChirho> {
    family_lines_for_family_chirho(GATE1_LEDGER_FAMILY_CHIRHO, count_chirho)
}

fn family_lines_for_family_chirho(
    family_chirho: &'static str,
    count_chirho: u64,
) -> Vec<Gate1AuthorityFamilyLineChirho> {
    (0..count_chirho)
        .map(|seq_chirho| {
            let input_chirho = input_for_family_chirho(family_chirho, seq_chirho);
            Gate1AuthorityFamilyLineChirho {
                family_seq_chirho: input_chirho.family_seq_chirho,
                family_line_chirho: input_chirho.family_line_chirho.to_string(),
            }
        })
        .collect()
}

fn rewrite_head_chirho(root_chirho: &std::path::Path, head_chirho: &Gate1AuthorityHeadChirho) {
    write_file_durable_chirho(
        &gate1_authority_head_path_chirho(root_chirho),
        canonical_gate1_authority_head_json_chirho(head_chirho)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
}

fn truncate_trailing_newline_chirho(root_chirho: &std::path::Path) {
    let path_chirho = gate1_authority_log_path_chirho(root_chirho);
    let file_chirho = std::fs::OpenOptions::new()
        .write(true)
        .open(&path_chirho)
        .unwrap();
    let len_chirho = file_chirho.metadata().unwrap().len();
    file_chirho.set_len(len_chirho - 1).unwrap();
}

fn assert_torn_tail_error_chirho(error_chirho: &str) {
    assert!(error_chirho.contains("torn Gate 1 authority log tail without newline"));
}

#[test]
fn authority_append_assigns_persisted_sequence_and_chain_chirho() {
    let root_chirho = temp_root_chirho("chain");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let first_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    let second_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(1)).unwrap();

    assert_eq!(first_chirho.record_chirho.authority_seq_chirho, 0);
    assert_eq!(second_chirho.record_chirho.authority_seq_chirho, 1);
    assert_eq!(
        second_chirho
            .record_chirho
            .prev_authority_record_digest_chirho
            .as_deref(),
        Some(first_chirho.record_digest_chirho.as_str())
    );
    assert!(first_chirho
        .record_digest_chirho
        .starts_with(GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO));
    assert_eq!(second_chirho.head_chirho.next_authority_seq_chirho, 2);
    assert_eq!(
        second_chirho
            .head_chirho
            .family_watermarks_chirho
            .iter()
            .find(|watermark_chirho| watermark_chirho.family_chirho == GATE1_LEDGER_FAMILY_CHIRHO)
            .map(|watermark_chirho| watermark_chirho.next_family_seq_chirho),
        Some(2)
    );
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 2);
}

#[test]
fn authority_records_are_signed_and_tamper_fails_closed_chirho() {
    let root_chirho = temp_root_chirho("signed-tamper");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    let mut records_chirho = load_gate1_authority_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 1);
    assert!(!records_chirho[0].key_id_chirho.is_empty());
    assert!(!records_chirho[0].sig_chirho.is_empty());

    records_chirho[0].sig_chirho = "00".repeat(64);
    std::fs::write(
        gate1_authority_log_path_chirho(&root_chirho),
        format!(
            "{}\n",
            canonical_gate1_authority_record_json_chirho(&records_chirho[0]).unwrap()
        ),
    )
    .unwrap();

    let error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("verify Gate 1 authority record"));
}

#[test]
fn authority_record_foreign_key_id_and_signature_fail_closed_chirho() {
    let root_chirho = temp_root_chirho("foreign-key");
    let foreign_root_chirho = temp_root_chirho("foreign-key-other");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let result_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();

    let mut forged_chirho = result_chirho.record_chirho;
    forged_chirho.key_id_chirho = signer_chirho::pubkey_hex_chirho(&foreign_root_chirho).unwrap();
    forged_chirho.sig_chirho.clear();
    let message_chirho = unsigned_gate1_authority_record_message_chirho(&forged_chirho).unwrap();
    forged_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&foreign_root_chirho, &message_chirho).unwrap();
    std::fs::write(
        gate1_authority_log_path_chirho(&root_chirho),
        format!(
            "{}\n",
            canonical_gate1_authority_record_json_chirho(&forged_chirho).unwrap()
        ),
    )
    .unwrap();

    let error_chirho = verify_gate1_authority_log_chirho(&root_chirho).unwrap_err();
    let error_text_chirho = format!("{error_chirho:#}");
    assert!(
        error_text_chirho.contains("key id mismatch"),
        "{error_text_chirho}"
    );
}

#[test]
fn stale_writer_token_is_rejected_chirho() {
    let root_chirho = temp_root_chirho("stale");
    let old_token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let _new_token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let error_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &old_token_chirho, input_chirho(0))
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("StaleWriterFenceChirho"));
    assert!(!gate1_authority_log_path_chirho(&root_chirho).exists());
}

#[test]
fn corrupt_head_fails_closed_chirho() {
    let root_chirho = temp_root_chirho("corrupt-head");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    std::fs::write(gate1_authority_head_path_chirho(&root_chirho), b"{not-json").unwrap();

    let error_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(1))
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("decode"));
}

#[test]
fn recovery_advances_stale_head_from_valid_log_prefix_chirho() {
    let root_chirho = temp_root_chirho("stale-head");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let first_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(1)).unwrap();

    rewrite_head_chirho(&root_chirho, &first_chirho.head_chirho);

    let recovered_chirho =
        recover_gate1_authority_head_chirho(&root_chirho, &token_chirho).unwrap();
    assert_eq!(recovered_chirho.next_authority_seq_chirho, 2);
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 2);
}

#[test]
fn backfill_forward_completes_and_resumes_without_gaps_chirho() {
    let root_chirho = temp_root_chirho("backfill");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_chirho(3);

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        let partial_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho[..2],
            3_000,
        )?;
        assert_eq!(partial_chirho.backfilled_chirho, 2);
        let resumed_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            4_000,
        )?;
        assert_eq!(resumed_chirho.backfilled_chirho, 1);
        Ok(())
    })
    .unwrap();

    let records_chirho = load_gate1_authority_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(
        records_chirho
            .iter()
            .map(|record_chirho| record_chirho.authority_seq_chirho)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 3);
}

#[test]
fn interleaved_family_reconcile_uses_projection_prefixes_chirho() {
    let root_chirho = temp_root_chirho("interleaved");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let ledger_lines_chirho = family_lines_chirho(2);
    let hold_lines_chirho = family_lines_for_family_chirho(GATE1_CREDIT_HOLDS_FAMILY_CHIRHO, 1);

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        let ledger_report_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &ledger_lines_chirho,
            3_000,
        )?;
        assert_eq!(ledger_report_chirho.backfilled_chirho, 2);
        let hold_report_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
            &hold_lines_chirho,
            4_000,
        )?;
        assert_eq!(hold_report_chirho.backfilled_chirho, 1);
        let ledger_current_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &ledger_lines_chirho,
            5_000,
        )?;
        assert_eq!(ledger_current_chirho.backfilled_chirho, 0);
        Ok(())
    })
    .unwrap();

    let records_chirho = load_gate1_authority_records_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 3);
    assert_eq!(records_chirho[0].family_chirho, GATE1_LEDGER_FAMILY_CHIRHO);
    assert_eq!(records_chirho[1].family_chirho, GATE1_LEDGER_FAMILY_CHIRHO);
    assert_eq!(
        records_chirho[2].family_chirho,
        GATE1_CREDIT_HOLDS_FAMILY_CHIRHO
    );
    let head_chirho = read_gate1_authority_head_file_chirho(&root_chirho)
        .unwrap()
        .unwrap();
    assert_eq!(
        head_chirho
            .family_watermarks_chirho
            .iter()
            .find(|watermark_chirho| watermark_chirho.family_chirho == GATE1_LEDGER_FAMILY_CHIRHO)
            .map(|watermark_chirho| watermark_chirho.next_family_seq_chirho),
        Some(2)
    );
    assert_eq!(
        head_chirho
            .family_watermarks_chirho
            .iter()
            .find(|watermark_chirho| {
                watermark_chirho.family_chirho == GATE1_CREDIT_HOLDS_FAMILY_CHIRHO
            })
            .map(|watermark_chirho| watermark_chirho.next_family_seq_chirho),
        Some(1)
    );
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 3);
}

#[test]
fn current_prefix_reconcile_uses_head_tail_not_full_chain_chirho() {
    let root_chirho = temp_root_chirho("current-prefix-fast");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_chirho(3);

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            3_000,
        )?;
        Ok(())
    })
    .unwrap();
    let mut records_chirho = load_gate1_authority_records_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "00".repeat(64);
    std::fs::write(
        gate1_authority_log_path_chirho(&root_chirho),
        records_chirho
            .iter()
            .map(canonical_gate1_authority_record_json_chirho)
            .collect::<Result<Vec<_>>>()
            .unwrap()
            .join("\n")
            + "\n",
    )
    .unwrap();

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        let report_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            4_000,
        )?;
        assert_eq!(report_chirho.backfilled_chirho, 0);
        Ok(())
    })
    .unwrap();
    let verify_error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(verify_error_chirho.contains("verify Gate 1 authority record 1"));
}

#[test]
fn fabricated_family_watermark_head_fails_verify_and_recovers_chirho() {
    let root_chirho = temp_root_chirho("fabricated-watermark");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let first_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    let mut forged_head_chirho = first_chirho.head_chirho.clone();
    forged_head_chirho.family_watermarks_chirho = vec![Gate1AuthorityFamilyWatermarkChirho {
        family_chirho: GATE1_CREDIT_HOLDS_FAMILY_CHIRHO.to_string(),
        next_family_seq_chirho: 1,
        last_family_line_digest_chirho: Some(gate1_authority_family_line_digest_chirho(
            input_for_family_chirho(GATE1_CREDIT_HOLDS_FAMILY_CHIRHO, 0).family_line_chirho,
        )),
    }];
    rewrite_head_chirho(&root_chirho, &forged_head_chirho);

    let error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("gate1 authority head does not match log chain"));

    let recovered_chirho =
        recover_gate1_authority_head_chirho(&root_chirho, &token_chirho).unwrap();
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        recovered_chirho
            .family_watermarks_chirho
            .iter()
            .find(|watermark_chirho| watermark_chirho.family_chirho == GATE1_LEDGER_FAMILY_CHIRHO)
            .map(|watermark_chirho| watermark_chirho.next_family_seq_chirho),
        Some(1)
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn current_prefix_reconcile_does_not_parse_full_authority_log_chirho() {
    let root_chirho = temp_root_chirho("current-prefix-no-full-parse");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_chirho(3);

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            3_000,
        )?;
        Ok(())
    })
    .unwrap();
    let path_chirho = gate1_authority_log_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let mut physical_lines_chirho = text_chirho.lines().map(str::to_string).collect::<Vec<_>>();
    physical_lines_chirho[1] = "x".repeat(physical_lines_chirho[1].len());
    std::fs::write(&path_chirho, physical_lines_chirho.join("\n") + "\n").unwrap();

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        let report_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            4_000,
        )?;
        assert_eq!(report_chirho.backfilled_chirho, 0);
        Ok(())
    })
    .unwrap();
    let verify_error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(verify_error_chirho.contains("decode Gate 1 authority record 2"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn current_family_tail_reconcile_does_not_parse_full_authority_log_chirho() {
    let root_chirho = temp_root_chirho("current-family-tail-no-full-parse");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_for_family_chirho(GATE1_CREDIT_HOLDS_FAMILY_CHIRHO, 3);

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
            &lines_chirho,
            3_000,
        )?;
        Ok(())
    })
    .unwrap();
    let path_chirho = gate1_authority_log_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let mut physical_lines_chirho = text_chirho.lines().map(str::to_string).collect::<Vec<_>>();
    physical_lines_chirho[1] = "x".repeat(physical_lines_chirho[1].len());
    std::fs::write(&path_chirho, physical_lines_chirho.join("\n") + "\n").unwrap();
    let tail_chirho = Gate1AuthorityFamilyTailChirho {
        family_count_chirho: lines_chirho.len() as u64,
        last_line_chirho: lines_chirho.last().cloned(),
    };

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        let report_chirho = reconcile_gate1_authority_current_family_tail_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
            &tail_chirho,
            4_000,
        )?
        .expect("current family tail should not require full backfill");
        assert_eq!(report_chirho.backfilled_chirho, 0);
        Ok(())
    })
    .unwrap();
    let verify_error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(verify_error_chirho.contains("decode Gate 1 authority record 2"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn current_prefix_reconcile_rejects_head_tail_mismatch_chirho() {
    let root_chirho = temp_root_chirho("head-tail-mismatch");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let first_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    let mut second_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(1)).unwrap();
    second_chirho
        .head_chirho
        .last_authority_record_digest_chirho = Some(first_chirho.record_digest_chirho);
    rewrite_head_chirho(&root_chirho, &second_chirho.head_chirho);

    let error_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &family_lines_chirho(2),
            3_000,
        )
    })
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("gate1 authority head does not match log tail"));
}

#[test]
fn current_prefix_reconcile_rejects_wrong_expected_tail_chirho() {
    let root_chirho = temp_root_chirho("wrong-expected-tail");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_chirho(2);
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            3_000,
        )?;
        Ok(())
    })
    .unwrap();

    let mut wrong_lines_chirho = lines_chirho.clone();
    wrong_lines_chirho[1].family_line_chirho =
        "{\"seq_chirho\":1,\"amount_chirho\":99}".to_string();
    let error_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &wrong_lines_chirho,
            4_000,
        )
    })
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("verified old-road family prefix tail"));
}

#[test]
fn append_refuses_stale_head_until_recovery_chirho() {
    let root_chirho = temp_root_chirho("stale-head-append");
    let first_token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let first_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &first_token_chirho, input_chirho(0))
            .unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &first_token_chirho, input_chirho(1))
        .unwrap();
    rewrite_head_chirho(&root_chirho, &first_chirho.head_chirho);

    let new_token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let log_len_before_chirho = std::fs::metadata(gate1_authority_log_path_chirho(&root_chirho))
        .unwrap()
        .len();
    let error_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &new_token_chirho, input_chirho(2))
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("stale gate1 authority head; run recovery"));
    assert_eq!(
        std::fs::metadata(gate1_authority_log_path_chirho(&root_chirho))
            .unwrap()
            .len(),
        log_len_before_chirho
    );
    assert_eq!(
        load_gate1_authority_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        2
    );

    let recovered_chirho =
        recover_gate1_authority_head_chirho(&root_chirho, &new_token_chirho).unwrap();
    assert_eq!(recovered_chirho.next_authority_seq_chirho, 2);
    let third_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &new_token_chirho, input_chirho(2))
            .unwrap();
    assert_eq!(third_chirho.record_chirho.authority_seq_chirho, 2);
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 3);
}

#[test]
fn torn_partial_tail_fails_closed_until_g1_3_repair_chirho() {
    let root_chirho = temp_root_chirho("torn-tail");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    let mut log_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(gate1_authority_log_path_chirho(&root_chirho))
        .unwrap();
    log_chirho.write_all(b"{\"schema_chirho\"").unwrap();
    drop(log_chirho);

    let load_error_chirho = load_gate1_authority_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert_torn_tail_error_chirho(&load_error_chirho);
    let verify_error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert_torn_tail_error_chirho(&verify_error_chirho);
    let recover_error_chirho = recover_gate1_authority_head_chirho(&root_chirho, &token_chirho)
        .unwrap_err()
        .to_string();
    assert_torn_tail_error_chirho(&recover_error_chirho);
}

#[test]
fn complete_json_tail_without_newline_fails_closed_until_g1_3_repair_chirho() {
    let root_chirho = temp_root_chirho("complete-json-no-newline");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(1)).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(2)).unwrap();
    truncate_trailing_newline_chirho(&root_chirho);

    let load_error_chirho = load_gate1_authority_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert_torn_tail_error_chirho(&load_error_chirho);
    let verify_error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert_torn_tail_error_chirho(&verify_error_chirho);
    let recover_error_chirho = recover_gate1_authority_head_chirho(&root_chirho, &token_chirho)
        .unwrap_err()
        .to_string();
    assert_torn_tail_error_chirho(&recover_error_chirho);
}

#[test]
fn repair_truncates_only_torn_tail_then_forward_completes_chirho() {
    let root_chirho = temp_root_chirho("repair-torn-tail");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_chirho(3);
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho[..2],
            2_000,
        )
        .map(|_| ())
    })
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(gate1_authority_log_path_chirho(&root_chirho))
        .unwrap()
        .write_all(b"{\"schema_chirho\"")
        .unwrap();

    let report_chirho = repair_gate1_authority_torn_tail_chirho(
        &root_chirho,
        &token_chirho,
        GATE1_LEDGER_FAMILY_CHIRHO,
        &lines_chirho,
        5_000,
    )
    .unwrap();
    assert!(report_chirho.truncated_tail_bytes_chirho > 0);
    assert_eq!(report_chirho.backfill_chirho.backfilled_chirho, 1);
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 3);
}

#[test]
fn reconcile_repairs_real_partial_authority_write_then_resumes_chirho() {
    let root_chirho = temp_root_chirho("real-partial-repair");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_chirho(3);
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho[..2],
            2_000,
        )
        .map(|_| ())
    })
    .unwrap();

    let head_chirho = read_gate1_authority_head_file_chirho(&root_chirho)
        .unwrap()
        .unwrap();
    let third_input_chirho = input_chirho(2);
    let partial_record_chirho = signed_gate1_authority_record_chirho(
        &root_chirho,
        &token_chirho,
        &third_input_chirho,
        &head_chirho,
    )
    .unwrap();
    let partial_json_chirho =
        canonical_gate1_authority_record_json_chirho(&partial_record_chirho).unwrap();
    let partial_bytes_chirho = partial_json_chirho.as_bytes();
    std::fs::OpenOptions::new()
        .append(true)
        .open(gate1_authority_log_path_chirho(&root_chirho))
        .unwrap()
        .write_all(&partial_bytes_chirho[..partial_bytes_chirho.len() / 2])
        .unwrap();

    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        let report_chirho = reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            5_000,
        )?;
        assert_eq!(report_chirho.backfilled_chirho, 1);
        Ok(())
    })
    .unwrap();

    let records_chirho = load_gate1_authority_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        records_chirho
            .iter()
            .map(|record_chirho| record_chirho.authority_seq_chirho)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(
        records_chirho
            .iter()
            .map(|record_chirho| record_chirho.family_seq_chirho)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 3);
}

#[test]
fn repair_refuses_to_truncate_intact_complete_tail_chirho() {
    let root_chirho = temp_root_chirho("repair-overreach");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let lines_chirho = family_lines_chirho(1);
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        reconcile_gate1_authority_prefix_unlocked_chirho(
            &root_chirho,
            &token_chirho,
            GATE1_LEDGER_FAMILY_CHIRHO,
            &lines_chirho,
            2_000,
        )
        .map(|_| ())
    })
    .unwrap();

    let error_chirho = repair_gate1_authority_torn_tail_chirho(
        &root_chirho,
        &token_chirho,
        GATE1_LEDGER_FAMILY_CHIRHO,
        &lines_chirho,
        5_000,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("intact"));
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 1);
}

#[test]
fn recovery_rejects_stale_prefix_head_with_wrong_len_chirho() {
    let root_chirho = temp_root_chirho("stale-prefix-wrong-len");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let mut first_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0))
            .unwrap()
            .head_chirho;
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(1)).unwrap();
    first_chirho.authority_log_len_bytes_chirho += 1;
    rewrite_head_chirho(&root_chirho, &first_chirho);

    let error_chirho = recover_gate1_authority_head_chirho(&root_chirho, &token_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("does not match log chain"));
}

#[test]
fn verify_rejects_current_head_with_len_drift_chirho() {
    let root_chirho = temp_root_chirho("current-head-len-drift");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let mut head_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0))
            .unwrap()
            .head_chirho;
    head_chirho.authority_log_len_bytes_chirho += 1;
    rewrite_head_chirho(&root_chirho, &head_chirho);

    let error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("does not match log chain"));
}

#[test]
fn recovery_with_stale_writer_fence_token_rejects_chirho() {
    let root_chirho = temp_root_chirho("stale-recover-token");
    let old_token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let _new_token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let error_chirho = recover_gate1_authority_head_chirho(&root_chirho, &old_token_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("StaleWriterFenceChirho"));
}

#[test]
fn empty_authority_log_lines_fail_closed_chirho() {
    let root_chirho = temp_root_chirho("empty-line");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(gate1_authority_log_path_chirho(&root_chirho))
        .unwrap()
        .write_all(b"\n")
        .unwrap();

    let error_chirho = verify_gate1_authority_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("empty line"));
}

#[test]
fn recovery_refuses_head_that_points_past_log_chirho() {
    let root_chirho = temp_root_chirho("past-head");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let mut first_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0))
            .unwrap()
            .head_chirho;
    first_chirho.next_authority_seq_chirho = 7;
    rewrite_head_chirho(&root_chirho, &first_chirho);

    let error_chirho = recover_gate1_authority_head_chirho(&root_chirho, &token_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("does not match log chain"));
}

#[test]
fn concurrent_appends_get_distinct_authority_sequences_chirho() {
    let root_chirho = Arc::new(temp_root_chirho("concurrent"));
    let token_chirho = Arc::new(issue_writer_fence_for_root_chirho(&root_chirho).unwrap());
    let barrier_chirho = Arc::new(Barrier::new(4));
    let families_chirho = [
        GATE1_LEDGER_FAMILY_CHIRHO,
        GATE1_CREDIT_HOLDS_FAMILY_CHIRHO,
        GATE1_BILLING_USAGE_FAMILY_CHIRHO,
        GATE1_RESOURCE_USAGE_FAMILY_CHIRHO,
    ];
    let mut handles_chirho = Vec::new();
    for family_chirho in families_chirho {
        let root_chirho = Arc::clone(&root_chirho);
        let token_chirho = Arc::clone(&token_chirho);
        let barrier_chirho = Arc::clone(&barrier_chirho);
        handles_chirho.push(thread::spawn(move || {
            barrier_chirho.wait();
            append_gate1_authority_record_chirho(
                &root_chirho,
                &token_chirho,
                input_for_family_chirho(family_chirho, 0),
            )
            .unwrap()
            .record_chirho
            .authority_seq_chirho
        }));
    }
    let mut seqs_chirho = handles_chirho
        .into_iter()
        .map(|handle_chirho| handle_chirho.join().unwrap())
        .collect::<Vec<_>>();
    seqs_chirho.sort_unstable();
    assert_eq!(seqs_chirho, vec![0, 1, 2, 3]);
    assert_eq!(verify_gate1_authority_log_chirho(&root_chirho).unwrap(), 4);
}

#[test]
fn record_digest_changes_when_family_line_changes_chirho() {
    let root_chirho = temp_root_chirho("digest");
    let token_chirho = issue_writer_fence_for_root_chirho(&root_chirho).unwrap();
    let result_chirho =
        append_gate1_authority_record_chirho(&root_chirho, &token_chirho, input_chirho(0)).unwrap();
    let mut changed_chirho = result_chirho.record_chirho.clone();
    changed_chirho.family_line_chirho = "{\"seq_chirho\":0,\"amount_chirho\":8}".to_string();
    changed_chirho.family_line_digest_chirho =
        gate1_authority_family_line_digest_chirho(&changed_chirho.family_line_chirho);
    assert_ne!(
        gate1_authority_record_digest_chirho(&changed_chirho).unwrap(),
        result_chirho.record_digest_chirho
    );
}
