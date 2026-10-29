// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_core_chirho::{cas_chirho, refs_chirho};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-head-removal-transition-test-{}-{n_chirho}",
        now_ms_chirho()
    ))
}

fn seed_existing_key_chirho(root_chirho: &Path) {
    signer_chirho::sign_message_chirho(root_chirho, b"head removal test key seed").unwrap();
}

fn target_chirho(root_chirho: &Path, label_chirho: &[u8]) -> HashChirho {
    cas_chirho::add_chirho(root_chirho, label_chirho).unwrap()
}

fn domain_line_chirho(domain_seq_chirho: u64, branch_chirho: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "seq_chirho": domain_seq_chirho,
        "schema_chirho": "synthetic-removal-domain-v1-chirho",
        "branch_chirho": branch_chirho,
        "sig_chirho": "caller-verified-synthetic-signature-chirho"
    }))
    .unwrap()
}

fn prepare_chirho(
    root_chirho: &Path,
    branch_chirho: &str,
    from_chirho: &HashChirho,
    domain_seq_chirho: u64,
) -> (PreparedHeadRemovalChirho, WriterFenceTokenChirho, Vec<u8>) {
    let domain_line_chirho = domain_line_chirho(domain_seq_chirho, branch_chirho);
    let (prepared_chirho, fence_chirho) =
        with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
            let prepared_chirho = append_caller_verified_prepared_head_removal_unlocked_chirho(
                root_chirho,
                HeadRemovalPreparedInputChirho {
                    branch_chirho,
                    from_chirho,
                    kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
                    app_chirho: "syntheticapp",
                    route_chirho: None,
                    owner_principal_chirho: "owner/abcdefabcdefabcd",
                    domain_log_chirho: "synthetic-domain-records-chirho.jsonl",
                    domain_seq_chirho,
                    prepared_fence_chirho: fence_chirho,
                    at_ms_chirho: 1_000 + domain_seq_chirho,
                },
                &domain_line_chirho,
            )?;
            Ok((prepared_chirho, fence_chirho.clone()))
        })
        .unwrap();
    (prepared_chirho, fence_chirho, domain_line_chirho)
}

fn branch_target_chirho(root_chirho: &Path, branch_chirho: &str) -> Option<HashChirho> {
    refs_chirho::load_refs_chirho(root_chirho)
        .unwrap()
        .branches_chirho
        .get(branch_chirho)
        .cloned()
}

fn applied_records_chirho(root_chirho: &Path) -> Vec<HeadRemovalAppliedRecordChirho> {
    load_head_removal_log_entries_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter_map(|entry_chirho| match entry_chirho {
            StoredHeadRemovalLogEntryChirho::TransitionChirho(
                StoredHeadRemovalTransitionEntryChirho::AppliedV1Chirho(record_chirho),
            ) => Some(record_chirho),
            _ => None,
        })
        .collect()
}

#[test]
fn prepared_removal_recovers_delete_and_records_applied_once_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"prepared removal target");
    let branch_chirho = "app/synthetic-prepared";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    let (prepared_chirho, _, _) = prepare_chirho(&root_chirho, branch_chirho, &from_chirho, 0);

    assert_eq!(
        recover_head_removal_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadRemovalRecoveryOutcomeChirho::AppliedChirho
    );
    assert_eq!(branch_target_chirho(&root_chirho, branch_chirho), None);
    assert!(verified_head_removal_applied_receipt_chirho(&root_chirho, &prepared_chirho).unwrap());
    let applied_chirho = applied_records_chirho(&root_chirho);
    assert_eq!(applied_chirho.len(), 1);
    assert!(
        applied_chirho[0].applied_writer_fence_epoch_chirho
            > applied_chirho[0].prepared_writer_fence_epoch_chirho
    );
    assert_eq!(
        recover_head_removal_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadRemovalRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(applied_records_chirho(&root_chirho).len(), 1);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn clean_apply_records_the_prepared_epoch_truthfully_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"clean removal target");
    let branch_chirho = "app/clean-removal";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
        let domain_line_chirho = domain_line_chirho(10, branch_chirho);
        let prepared_chirho = append_caller_verified_prepared_head_removal_unlocked_chirho(
            &root_chirho,
            HeadRemovalPreparedInputChirho {
                branch_chirho,
                from_chirho: &from_chirho,
                kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
                app_chirho: "syntheticapp",
                route_chirho: None,
                owner_principal_chirho: "owner/abcdefabcdefabcd",
                domain_log_chirho: "synthetic-domain-records-chirho.jsonl",
                domain_seq_chirho: 10,
                prepared_fence_chirho: fence_chirho,
                at_ms_chirho: 1_010,
            },
            &domain_line_chirho,
        )?;
        assert_eq!(
            complete_head_removal_unlocked_chirho(&root_chirho, &prepared_chirho, fence_chirho,)?,
            HeadRemovalRecoveryOutcomeChirho::AppliedChirho
        );
        Ok(())
    })
    .unwrap();
    let applied_chirho = applied_records_chirho(&root_chirho);
    assert_eq!(applied_chirho.len(), 1);
    assert_eq!(
        applied_chirho[0].applied_writer_fence_epoch_chirho,
        applied_chirho[0].prepared_writer_fence_epoch_chirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn applied_receipt_prevents_recreated_same_head_from_stale_delete_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"stale delete target");
    let branch_chirho = "app/stale-delete";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    let (prepared_chirho, _, _) = prepare_chirho(&root_chirho, branch_chirho, &from_chirho, 1);
    recover_head_removal_chirho(&root_chirho, &prepared_chirho).unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();

    assert_eq!(
        recover_head_removal_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadRemovalRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        branch_target_chirho(&root_chirho, branch_chirho),
        Some(from_chirho)
    );
    assert_eq!(applied_records_chirho(&root_chirho).len(), 1);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn divergent_current_head_fails_closed_without_delete_or_receipt_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"divergent from");
    let other_chirho = target_chirho(&root_chirho, b"divergent other");
    let branch_chirho = "app/divergent";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    let (prepared_chirho, _, _) = prepare_chirho(&root_chirho, branch_chirho, &from_chirho, 2);
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, other_chirho.clone()).unwrap();

    let error_chirho = recover_head_removal_chirho(&root_chirho, &prepared_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("diverges"), "{error_chirho}");
    assert_eq!(
        branch_target_chirho(&root_chirho, branch_chirho),
        Some(other_chirho)
    );
    assert!(applied_records_chirho(&root_chirho).is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn absent_branch_repairs_one_applied_receipt_after_torn_tail_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"absent branch target");
    let branch_chirho = "app/absent-repair";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    let (prepared_chirho, _, _) = prepare_chirho(&root_chirho, branch_chirho, &from_chirho, 3);
    refs_chirho::remove_branch_chirho(&root_chirho, branch_chirho).unwrap();
    let path_chirho = head_removal_chirho::head_removal_records_path_chirho(&root_chirho);
    let mut file_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(&path_chirho)
        .unwrap();
    file_chirho.write_all(b"{\"seq_chirho\":1").unwrap();
    file_chirho.sync_all().unwrap();

    assert_eq!(
        recover_head_removal_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadRemovalRecoveryOutcomeChirho::RepairedAppliedReceiptChirho
    );
    assert_eq!(applied_records_chirho(&root_chirho).len(), 1);
    assert_eq!(
        recover_head_removal_chirho(&root_chirho, &prepared_chirho).unwrap(),
        HeadRemovalRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(applied_records_chirho(&root_chirho).len(), 1);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn stale_preparer_cannot_delete_or_append_after_newer_fence_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"stale fence target");
    let branch_chirho = "app/stale-fence";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    let (prepared_chirho, stale_fence_chirho, _) =
        prepare_chirho(&root_chirho, branch_chirho, &from_chirho, 4);
    with_head_transition_scope_chirho(&root_chirho, |_| Ok(())).unwrap();

    let error_chirho =
        complete_head_removal_unlocked_chirho(&root_chirho, &prepared_chirho, &stale_fence_chirho)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("not current"), "{error_chirho}");
    assert_eq!(
        branch_target_chirho(&root_chirho, branch_chirho),
        Some(from_chirho)
    );
    assert!(applied_records_chirho(&root_chirho).is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn same_branch_rejects_second_pending_while_other_branch_is_independent_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let first_chirho = target_chirho(&root_chirho, b"first pending target");
    let second_chirho = target_chirho(&root_chirho, b"second pending target");
    refs_chirho::set_branch_chirho(&root_chirho, "app/first", first_chirho.clone()).unwrap();
    refs_chirho::set_branch_chirho(&root_chirho, "app/second", second_chirho.clone()).unwrap();
    let (first_prepared_chirho, _, _) = prepare_chirho(&root_chirho, "app/first", &first_chirho, 5);

    let same_branch_result_chirho =
        with_head_transition_scope_chirho(&root_chirho, |fence_chirho| {
            append_caller_verified_prepared_head_removal_unlocked_chirho(
                &root_chirho,
                HeadRemovalPreparedInputChirho {
                    branch_chirho: "app/first",
                    from_chirho: &first_chirho,
                    kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
                    app_chirho: "syntheticapp",
                    route_chirho: None,
                    owner_principal_chirho: "owner/abcdefabcdefabcd",
                    domain_log_chirho: "synthetic-domain-records-chirho.jsonl",
                    domain_seq_chirho: 6,
                    prepared_fence_chirho: fence_chirho,
                    at_ms_chirho: 1_006,
                },
                &domain_line_chirho(6, "app/first"),
            )
        });
    let same_branch_error_chirho = match same_branch_result_chirho {
        Ok(_) => panic!("same branch unexpectedly accepted a second pending removal"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(same_branch_error_chirho.contains("already has an unapplied"));

    let (second_prepared_chirho, _, _) =
        prepare_chirho(&root_chirho, "app/second", &second_chirho, 7);
    assert_eq!(
        recover_head_removal_chirho(&root_chirho, &first_prepared_chirho).unwrap(),
        HeadRemovalRecoveryOutcomeChirho::AppliedChirho
    );
    assert_eq!(
        recover_head_removal_chirho(&root_chirho, &second_prepared_chirho).unwrap(),
        HeadRemovalRecoveryOutcomeChirho::AppliedChirho
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn caller_verified_domain_binding_and_persisted_signatures_fail_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"domain binding target");
    let branch_chirho = "app/domain-binding";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    let (_, _, expected_domain_line_chirho) =
        prepare_chirho(&root_chirho, branch_chirho, &from_chirho, 8);
    let record_chirho = root_signed_prepared_head_removal_records_chirho(&root_chirho)
        .unwrap()
        .pop()
        .unwrap();
    let binding_result_chirho = bind_caller_verified_prepared_head_removal_chirho(
        &root_chirho,
        &record_chirho,
        b"different verified domain line",
    );
    let error_chirho = match binding_result_chirho {
        Ok(_) => panic!("different domain line unexpectedly bound Prepared removal"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(error_chirho.contains("does not bind"), "{error_chirho}");
    bind_caller_verified_prepared_head_removal_chirho(
        &root_chirho,
        &record_chirho,
        &expected_domain_line_chirho,
    )
    .unwrap();

    let path_chirho = head_removal_chirho::head_removal_records_path_chirho(&root_chirho);
    let mut tampered_chirho = record_chirho;
    tampered_chirho.transition_id_chirho.push('0');
    std::fs::write(
        &path_chirho,
        format!("{}\n", serde_json::to_string(&tampered_chirho).unwrap()),
    )
    .unwrap();
    let tamper_error_chirho = verify_head_removal_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        tamper_error_chirho.contains("signature invalid"),
        "{tamper_error_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn duplicate_valid_applied_receipt_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    seed_existing_key_chirho(&root_chirho);
    let from_chirho = target_chirho(&root_chirho, b"duplicate receipt target");
    let branch_chirho = "app/duplicate-receipt";
    refs_chirho::set_branch_chirho(&root_chirho, branch_chirho, from_chirho.clone()).unwrap();
    let (prepared_chirho, _, _) = prepare_chirho(&root_chirho, branch_chirho, &from_chirho, 9);
    recover_head_removal_chirho(&root_chirho, &prepared_chirho).unwrap();
    let receipt_chirho = applied_records_chirho(&root_chirho).pop().unwrap();
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        let path_chirho = head_removal_chirho::head_removal_records_path_chirho(&root_chirho);
        seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
            let mut duplicate_chirho = receipt_chirho.clone();
            duplicate_chirho.seq_chirho = seq_chirho;
            duplicate_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
                &root_chirho,
                &unsigned_applied_message_chirho(&duplicate_chirho)?,
            )?;
            Ok(duplicate_chirho)
        })
    })
    .unwrap();

    let error_chirho = verify_head_removal_log_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("duplicate Applied"), "{error_chirho}");

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_v1_rows_remain_visible_and_never_become_prepared_candidates_chirho() {
    let root_chirho = tmp_root_chirho();
    let from_chirho = target_chirho(&root_chirho, b"legacy removal target");
    refs_chirho::set_branch_chirho(&root_chirho, "app/legacy", from_chirho.clone()).unwrap();
    seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        head_removal_chirho::append_head_removal_record_unlocked_chirho(
            &root_chirho,
            head_removal_chirho::HeadRemovalEvidenceInputChirho {
                branch_chirho: "app/legacy",
                from_chirho: &from_chirho,
                kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
                app_chirho: "legacyapp",
                route_chirho: None,
                owner_principal_chirho: "owner/abcdefabcdefabcd",
                domain_log_chirho: "app-records-chirho.jsonl",
                domain_seq_chirho: 0,
            },
        )
        .map(|_| ())
    })
    .unwrap();

    assert_eq!(
        head_removal_chirho::load_head_removal_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(verify_head_removal_log_chirho(&root_chirho).unwrap(), 1);
    assert!(
        root_signed_prepared_head_removal_records_chirho(&root_chirho)
            .unwrap()
            .is_empty()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
