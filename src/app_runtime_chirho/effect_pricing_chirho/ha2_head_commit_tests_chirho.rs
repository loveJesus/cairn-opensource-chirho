// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use std::sync::{Arc, Barrier};
use std::thread;

fn append_pending_price_book_v2_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    price_chirho: i64,
) -> (
    HashChirho,
    PriceBookRecordChirho,
    PreparedHeadTransitionChirho,
    WriterFenceTokenChirho,
) {
    let mut output_chirho = None;
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        let previous_chirho = current_price_book_hash_chirho(root_chirho, app_chirho)?;
        let book_chirho = pricebook_policy_chirho::propose_price_book_chirho(
            app_chirho,
            owner_chirho,
            Some(price_chirho),
            BTreeMap::new(),
            0,
            previous_chirho.clone(),
            now_ms_chirho(),
        )?;
        let hash_chirho = store_chirho::put_object_chirho(root_chirho, &book_chirho)?;
        let record_chirho = append_price_record_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            hash_chirho.clone(),
            previous_chirho,
            fence_chirho,
        )?;
        let records_chirho = verified_price_book_records_chirho(root_chirho)?;
        let prepared_chirho = prepared_from_verified_price_book_record_chirho(
            root_chirho,
            records_chirho.last().unwrap(),
        )?;
        output_chirho = Some((
            hash_chirho,
            record_chirho,
            prepared_chirho,
            fence_chirho.clone(),
        ));
        Ok(())
    })
    .unwrap();
    output_chirho.unwrap()
}

fn append_legacy_price_book_v1_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    price_chirho: i64,
) -> (HashChirho, PriceBookRecordChirho) {
    let book_chirho = pricebook_policy_chirho::propose_price_book_chirho(
        app_chirho,
        owner_chirho,
        Some(price_chirho),
        BTreeMap::new(),
        0,
        None,
        now_ms_chirho(),
    )
    .unwrap();
    let hash_chirho = store_chirho::put_object_chirho(root_chirho, &book_chirho).unwrap();
    let record_chirho = seqlog_chirho::append_serialized_jsonl_chirho(
        root_chirho,
        &price_records_path_chirho(root_chirho),
        |seq_chirho| {
            let mut record_chirho = PriceBookRecordChirho {
                seq_chirho,
                schema_chirho: PRICE_BOOK_RECORD_SCHEMA_CHIRHO.to_string(),
                app_chirho: app_chirho.to_string(),
                owner_principal_chirho: owner_chirho.to_string(),
                price_book_chirho: hash_chirho.clone(),
                previous_chirho: None,
                at_ms_chirho: now_ms_chirho(),
                transition_id_chirho: String::new(),
                prepared_writer_fence_epoch_chirho: None,
                sig_chirho: String::new(),
            };
            record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                root_chirho,
                &price_record_message_chirho(&record_chirho)?,
            )?;
            Ok(record_chirho)
        },
    )
    .unwrap();
    (hash_chirho, record_chirho)
}

fn pricebook_transition_receipts_chirho(
    root_chirho: &Path,
) -> Vec<refs_chirho::ReflogEntryChirho> {
    refs_chirho::reflog_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|entry_chirho| {
            entry_chirho.schema_chirho
                == head_transition_chirho::HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO
                && entry_chirho.family_log_chirho == PRICE_BOOK_RECORDS_LOG_CHIRHO
        })
        .collect()
}

#[test]
fn pricebook_concurrent_writers_chain_linearly_chirho() {
    let root_chirho = Arc::new(tmp_root_chirho());
    let owner_chirho = Arc::new(deploy_owned_app_chirho(root_chirho.as_ref(), "chainprice"));
    let barrier_chirho = Arc::new(Barrier::new(6));
    let mut handles_chirho = Vec::new();
    for index_chirho in 0..6 {
        let root_chirho = Arc::clone(&root_chirho);
        let owner_chirho = Arc::clone(&owner_chirho);
        let barrier_chirho = Arc::clone(&barrier_chirho);
        handles_chirho.push(thread::spawn(move || {
            barrier_chirho.wait();
            set_price_book_chirho(
                root_chirho.as_ref(),
                "chainprice",
                &owner_chirho,
                Some(100 + index_chirho as i64),
                BTreeMap::new(),
                0,
            )
            .map(|(hash_chirho, _book_chirho, _record_chirho)| hash_chirho)
        }));
    }
    for handle_chirho in handles_chirho {
        handle_chirho.join().unwrap().unwrap();
    }

    let records_chirho = price_book_history_chirho(root_chirho.as_ref(), "chainprice").unwrap();
    assert_eq!(records_chirho.len(), 6);
    let mut previous_chirho = None;
    for record_chirho in &records_chirho {
        assert_eq!(record_chirho.previous_chirho, previous_chirho);
        previous_chirho = Some(record_chirho.price_book_chirho.clone());
    }
    assert_eq!(
        current_price_book_hash_chirho(root_chirho.as_ref(), "chainprice").unwrap(),
        previous_chirho
    );
    assert_eq!(verify_price_books_chirho(root_chirho.as_ref()).unwrap(), 6);
    assert_eq!(pricebook_transition_receipts_chirho(root_chirho.as_ref()).len(), 6);

    let _ = std::fs::remove_dir_all(&*root_chirho);
}

#[test]
fn pricebook_clean_v2_apply_records_same_epoch_receipt_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "cleanv2price");
    let (_hash_chirho, _book_chirho, record_chirho) = set_price_book_chirho(
        &root_chirho,
        "cleanv2price",
        &owner_chirho,
        Some(10),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    assert_eq!(
        record_chirho.schema_chirho,
        PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO
    );
    assert!(record_chirho
        .transition_id_chirho
        .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO));
    let receipts_chirho = pricebook_transition_receipts_chirho(&root_chirho);
    assert_eq!(receipts_chirho.len(), 1);
    assert_eq!(
        receipts_chirho[0].prepared_writer_fence_epoch_chirho,
        record_chirho.prepared_writer_fence_epoch_chirho
    );
    assert_eq!(
        receipts_chirho[0].applied_writer_fence_epoch_chirho,
        record_chirho.prepared_writer_fence_epoch_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_crash_before_ref_recovers_with_later_epoch_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "beforerefprice");
    let (hash_chirho, record_chirho, _prepared_chirho, _stale_fence_chirho) =
        append_pending_price_book_v2_chirho(
            &root_chirho,
            "beforerefprice",
            &owner_chirho,
            10,
        );
    assert_eq!(
        recover_price_book_head_chirho(&root_chirho, "beforerefprice").unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, "beforerefprice").unwrap(),
        Some(hash_chirho)
    );
    let receipts_chirho = pricebook_transition_receipts_chirho(&root_chirho);
    assert_eq!(receipts_chirho.len(), 1);
    assert!(
        receipts_chirho[0]
            .applied_writer_fence_epoch_chirho
            .unwrap()
            > record_chirho
                .prepared_writer_fence_epoch_chirho
                .unwrap()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_crash_after_ref_repairs_receipt_exactly_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "afterrefprice");
    let (hash_chirho, _record_chirho, _prepared_chirho, _stale_fence_chirho) =
        append_pending_price_book_v2_chirho(
            &root_chirho,
            "afterrefprice",
            &owner_chirho,
            11,
        );
    let mut refs_state_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    refs_state_chirho
        .branches_chirho
        .insert(pricebook_ref_chirho("afterrefprice"), hash_chirho.clone());
    refs_chirho::save_refs_chirho(&root_chirho, &refs_state_chirho).unwrap();

    let error_chirho = current_price_book_hash_chirho(&root_chirho, "afterrefprice")
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("no valid Applied receipt"),
        "{error_chirho}"
    );
    assert_eq!(
        recover_price_book_head_chirho(&root_chirho, "afterrefprice").unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho)
    );
    assert_eq!(
        recover_price_book_head_chirho(&root_chirho, "afterrefprice").unwrap(),
        None
    );
    assert_eq!(pricebook_transition_receipts_chirho(&root_chirho).len(), 1);
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, "afterrefprice").unwrap(),
        Some(hash_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_recovery_precedes_new_append_and_binds_recovered_head_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "recoverfirstprice");
    let (recovered_hash_chirho, _record_chirho, _prepared_chirho, _stale_fence_chirho) =
        append_pending_price_book_v2_chirho(
            &root_chirho,
            "recoverfirstprice",
            &owner_chirho,
            12,
        );
    let (_next_hash_chirho, _book_chirho, next_record_chirho) = set_price_book_chirho(
        &root_chirho,
        "recoverfirstprice",
        &owner_chirho,
        Some(13),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    assert_eq!(
        next_record_chirho.previous_chirho,
        Some(recovered_hash_chirho)
    );
    assert_eq!(verify_price_books_chirho(&root_chirho).unwrap(), 2);
    assert_eq!(pricebook_transition_receipts_chirho(&root_chirho).len(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_receipt_prevents_rollback_resurrection_and_next_write_uses_rollback_head_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "rollbackprice");
    let (first_chirho, _first_book_chirho, _first_record_chirho) = set_price_book_chirho(
        &root_chirho,
        "rollbackprice",
        &owner_chirho,
        Some(14),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    let (_second_chirho, _second_book_chirho, second_record_chirho) = set_price_book_chirho(
        &root_chirho,
        "rollbackprice",
        &owner_chirho,
        Some(15),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    refs_chirho::rollback_chirho(
        &root_chirho,
        &pricebook_ref_chirho("rollbackprice"),
        first_chirho.clone(),
    )
    .unwrap();
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    assert_eq!(
        recover_price_book_head_chirho(&root_chirho, "rollbackprice").unwrap(),
        None
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    let verified_records_chirho = verified_price_book_records_chirho(&root_chirho).unwrap();
    let settled_prepared_chirho = prepared_from_verified_price_book_record_chirho(
        &root_chirho,
        &verified_records_chirho[second_record_chirho.seq_chirho as usize],
    )
    .unwrap();
    assert_eq!(
        writer_head_chirho::with_head_transition_scope_chirho(
            &root_chirho,
            |fence_chirho| {
                head_transition_chirho::complete_head_transition_unlocked_chirho(
                    &root_chirho,
                    &settled_prepared_chirho,
                    fence_chirho,
                )
            },
        )
        .unwrap(),
        HeadTransitionRecoveryOutcomeChirho::AlreadyAppliedChirho
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    let (_third_chirho, _third_book_chirho, third_record_chirho) = set_price_book_chirho(
        &root_chirho,
        "rollbackprice",
        &owner_chirho,
        Some(16),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    assert_eq!(third_record_chirho.previous_chirho, Some(first_chirho));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_stale_preparer_cannot_complete_after_recovery_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "zombieprice");
    let (_hash_chirho, _record_chirho, prepared_chirho, stale_fence_chirho) =
        append_pending_price_book_v2_chirho(&root_chirho, "zombieprice", &owner_chirho, 17);
    recover_price_book_head_chirho(&root_chirho, "zombieprice").unwrap();
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    let reflog_before_chirho = std::fs::read(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap();
    let error_chirho = seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || {
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            &root_chirho,
            &prepared_chirho,
            &stale_fence_chirho,
        )
    })
    .unwrap_err();
    assert!(format!("{error_chirho:#}").contains("StaleWriterFenceChirho"));
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    assert_eq!(
        std::fs::read(refs_chirho::reflog_path_chirho(&root_chirho)).unwrap(),
        reflog_before_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_v1_history_never_becomes_recovery_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "legacyrecoverprice");
    let (legacy_hash_chirho, _legacy_record_chirho) = append_legacy_price_book_v1_chirho(
        &root_chirho,
        "legacyrecoverprice",
        &owner_chirho,
        18,
    );
    assert_eq!(verify_price_books_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        recover_price_book_head_chirho(&root_chirho, "legacyrecoverprice").unwrap(),
        None
    );
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, "legacyrecoverprice").unwrap(),
        None
    );

    refs_chirho::set_branch_chirho(
        &root_chirho,
        &pricebook_ref_chirho("legacyrecoverprice"),
        legacy_hash_chirho.clone(),
    )
    .unwrap();
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, "legacyrecoverprice").unwrap(),
        Some(legacy_hash_chirho.clone())
    );
    let (_next_chirho, _book_chirho, v2_record_chirho) = set_price_book_chirho(
        &root_chirho,
        "legacyrecoverprice",
        &owner_chirho,
        Some(19),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    assert_eq!(v2_record_chirho.previous_chirho, Some(legacy_hash_chirho));
    assert_eq!(verify_price_books_chirho(&root_chirho).unwrap(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_v2_signature_binds_transition_id_and_prepared_epoch_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "signedv2price");
    set_price_book_chirho(
        &root_chirho,
        "signedv2price",
        &owner_chirho,
        Some(20),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    let original_chirho = load_price_book_records_chirho(&root_chirho).unwrap();
    let mut tampered_id_chirho = original_chirho.clone();
    tampered_id_chirho[0].transition_id_chirho =
        format!("{HEAD_TRANSITION_ID_PREFIX_CHIRHO}{}", "2".repeat(64));
    write_jsonl_chirho(
        &price_records_path_chirho(&root_chirho),
        &tampered_id_chirho,
    );
    assert!(verify_price_books_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("signature invalid"));

    let mut tampered_epoch_chirho = original_chirho.clone();
    tampered_epoch_chirho[0].prepared_writer_fence_epoch_chirho = Some(
        tampered_epoch_chirho[0]
            .prepared_writer_fence_epoch_chirho
            .unwrap()
            + 1,
    );
    write_jsonl_chirho(
        &price_records_path_chirho(&root_chirho),
        &tampered_epoch_chirho,
    );
    assert!(verify_price_books_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("signature invalid"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_recovery_rejects_resigned_transition_from_another_group_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "wronggroupprice");
    set_price_book_chirho(
        &root_chirho,
        "wronggroupprice",
        &owner_chirho,
        Some(21),
        BTreeMap::new(),
        0,
    )
    .unwrap();
    let mut records_chirho = load_price_book_records_chirho(&root_chirho).unwrap();
    let wrong_fence_chirho = WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "wrong-group-chirho".to_string(),
        },
        epoch_chirho: records_chirho[0]
            .prepared_writer_fence_epoch_chirho
            .unwrap(),
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho =
        price_book_transition_operation_bytes_chirho(&records_chirho[0]).unwrap();
    let branch_chirho = pricebook_ref_chirho("wronggroupprice");
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: PRICE_BOOK_RECORDS_LOG_CHIRHO,
        family_seq_chirho: records_chirho[0].seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &records_chirho[0].previous_chirho,
        next_chirho: &records_chirho[0].price_book_chirho,
        reason_chirho: PRICE_BOOK_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &wrong_fence_chirho,
        at_ms_chirho: records_chirho[0].at_ms_chirho,
    };
    records_chirho[0].transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho).unwrap();
    let wrong_group_record_chirho = records_chirho.remove(0);
    records_chirho.push(resign_price_record_for_test_chirho(
        &root_chirho,
        wrong_group_record_chirho,
    ));
    write_jsonl_chirho(&price_records_path_chirho(&root_chirho), &records_chirho);
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    assert!(recover_price_book_head_chirho(&root_chirho, "wronggroupprice")
        .unwrap_err()
        .to_string()
        .contains("transition id does not match"));
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn pricebook_multiple_unapplied_v2_rows_fail_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "ambiguousprice");
    append_pending_price_book_v2_chirho(&root_chirho, "ambiguousprice", &owner_chirho, 22);
    append_pending_price_book_v2_chirho(&root_chirho, "ambiguousprice", &owner_chirho, 23);
    assert!(recover_price_book_head_chirho(&root_chirho, "ambiguousprice")
        .unwrap_err()
        .to_string()
        .contains("multiple unapplied"));
    assert_eq!(
        current_price_book_hash_chirho(&root_chirho, "ambiguousprice").unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
