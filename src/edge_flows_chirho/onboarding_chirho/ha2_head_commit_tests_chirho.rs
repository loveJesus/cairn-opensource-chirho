// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use std::sync::{Arc, Barrier};
use std::thread;

pub(super) fn append_pending_onboarding_v2_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    title_chirho: &str,
) -> (
    HashChirho,
    OnboardingRecordChirho,
    PreparedHeadTransitionChirho,
    WriterFenceTokenChirho,
) {
    let mut output_chirho = None;
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        let previous_chirho = current_onboarding_hash_chirho(root_chirho, app_chirho)?;
        let guide_chirho = OnboardingGuideChirho {
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_chirho.to_string(),
            title_chirho: title_chirho.to_string(),
            steps_chirho: vec![parse_onboarding_step_spec_chirho("Start=Follow the guide")?],
            previous_chirho: previous_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
        };
        validate_onboarding_guide_chirho(&guide_chirho)?;
        let hash_chirho = store_chirho::put_object_chirho(root_chirho, &guide_chirho)?;
        let record_chirho = append_onboarding_record_unlocked_chirho(
            root_chirho,
            app_chirho,
            owner_chirho,
            hash_chirho.clone(),
            previous_chirho,
            fence_chirho,
        )?;
        let records_chirho = verified_onboarding_records_chirho(root_chirho)?;
        let prepared_chirho = prepared_from_verified_onboarding_record_chirho(
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

fn append_legacy_onboarding_v1_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> (HashChirho, OnboardingRecordChirho) {
    let guide_chirho = OnboardingGuideChirho {
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_chirho.to_string(),
        title_chirho: "Legacy guide".to_string(),
        steps_chirho: vec![parse_onboarding_step_spec_chirho("Start=Legacy body").unwrap()],
        previous_chirho: None,
        at_ms_chirho: now_ms_chirho(),
    };
    validate_onboarding_guide_chirho(&guide_chirho).unwrap();
    let hash_chirho = store_chirho::put_object_chirho(root_chirho, &guide_chirho).unwrap();
    let record_chirho = seqlog_chirho::append_serialized_jsonl_chirho(
        root_chirho,
        &onboarding_records_path_chirho(root_chirho),
        |seq_chirho| {
            let mut record_chirho = OnboardingRecordChirho {
                seq_chirho,
                schema_chirho: ONBOARDING_RECORD_SCHEMA_CHIRHO.to_string(),
                app_chirho: app_chirho.to_string(),
                owner_principal_chirho: owner_chirho.to_string(),
                guide_chirho: hash_chirho.clone(),
                previous_chirho: None,
                at_ms_chirho: now_ms_chirho(),
                transition_id_chirho: String::new(),
                prepared_writer_fence_epoch_chirho: None,
                sig_chirho: String::new(),
            };
            record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                root_chirho,
                &onboarding_record_message_chirho(&record_chirho)?,
            )?;
            Ok(record_chirho)
        },
    )
    .unwrap();
    (hash_chirho, record_chirho)
}

fn onboarding_transition_receipts_chirho(
    root_chirho: &Path,
) -> Vec<refs_chirho::ReflogEntryChirho> {
    refs_chirho::reflog_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|entry_chirho| {
            entry_chirho.schema_chirho
                == head_transition_chirho::HEAD_TRANSITION_RECEIPT_SCHEMA_CHIRHO
                && entry_chirho.family_log_chirho == ONBOARDING_RECORDS_LOG_CHIRHO
        })
        .collect()
}

#[test]
fn onboarding_concurrent_writers_chain_linearly_chirho() {
    let root_chirho = Arc::new(tmp_root_chirho());
    let owner_chirho = Arc::new(deploy_owned_app_chirho(root_chirho.as_ref(), "chainguide"));
    let barrier_chirho = Arc::new(Barrier::new(6));
    let mut handles_chirho = Vec::new();
    for index_chirho in 0..6 {
        let root_chirho = Arc::clone(&root_chirho);
        let owner_chirho = Arc::clone(&owner_chirho);
        let barrier_chirho = Arc::clone(&barrier_chirho);
        handles_chirho.push(thread::spawn(move || {
            barrier_chirho.wait();
            set_onboarding_guide_chirho(
                root_chirho.as_ref(),
                "chainguide",
                &owner_chirho,
                &format!("Guide {index_chirho}"),
                vec![parse_onboarding_step_spec_chirho(&format!(
                    "Step {index_chirho}=Body"
                ))
                .unwrap()],
            )
            .map(|(hash_chirho, _guide_chirho, _record_chirho)| hash_chirho)
        }));
    }
    for handle_chirho in handles_chirho {
        handle_chirho.join().unwrap().unwrap();
    }

    let records_chirho = onboarding_history_chirho(root_chirho.as_ref(), "chainguide").unwrap();
    assert_eq!(records_chirho.len(), 6);
    let mut previous_chirho = None;
    for record_chirho in &records_chirho {
        assert_eq!(record_chirho.previous_chirho, previous_chirho);
        previous_chirho = Some(record_chirho.guide_chirho.clone());
    }
    assert_eq!(
        current_onboarding_hash_chirho(root_chirho.as_ref(), "chainguide").unwrap(),
        previous_chirho
    );
    assert_eq!(verify_onboarding_chirho(root_chirho.as_ref()).unwrap(), 6);
    assert_eq!(
        onboarding_transition_receipts_chirho(root_chirho.as_ref()).len(),
        6
    );

    let _ = std::fs::remove_dir_all(&*root_chirho);
}

#[test]
fn onboarding_crash_before_ref_recovers_with_later_epoch_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "beforerefguide");
    let (hash_chirho, record_chirho, _prepared_chirho, _stale_fence_chirho) =
        append_pending_onboarding_v2_chirho(
            &root_chirho,
            "beforerefguide",
            &owner_chirho,
            "Pending guide",
        );
    assert_eq!(
        recover_onboarding_head_chirho(&root_chirho, "beforerefguide").unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::AppliedChirho)
    );
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "beforerefguide").unwrap(),
        Some(hash_chirho)
    );
    let receipts_chirho = onboarding_transition_receipts_chirho(&root_chirho);
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
fn onboarding_crash_after_ref_repairs_receipt_exactly_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "afterrefguide");
    let (hash_chirho, _record_chirho, _prepared_chirho, _stale_fence_chirho) =
        append_pending_onboarding_v2_chirho(
            &root_chirho,
            "afterrefguide",
            &owner_chirho,
            "Pending guide",
        );
    let mut refs_state_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    refs_state_chirho
        .branches_chirho
        .insert(onboarding_ref_chirho("afterrefguide"), hash_chirho.clone());
    refs_chirho::save_refs_chirho(&root_chirho, &refs_state_chirho).unwrap();

    let error_chirho = current_onboarding_hash_chirho(&root_chirho, "afterrefguide")
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("no valid Applied receipt"),
        "{error_chirho}"
    );
    assert_eq!(
        recover_onboarding_head_chirho(&root_chirho, "afterrefguide").unwrap(),
        Some(HeadTransitionRecoveryOutcomeChirho::RepairedReflogChirho)
    );
    assert_eq!(
        recover_onboarding_head_chirho(&root_chirho, "afterrefguide").unwrap(),
        None
    );
    assert_eq!(onboarding_transition_receipts_chirho(&root_chirho).len(), 1);
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "afterrefguide").unwrap(),
        Some(hash_chirho)
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn onboarding_recovery_precedes_new_append_and_binds_recovered_head_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "recoverfirstguide");
    let (recovered_hash_chirho, _record_chirho, _prepared_chirho, _stale_fence_chirho) =
        append_pending_onboarding_v2_chirho(
            &root_chirho,
            "recoverfirstguide",
            &owner_chirho,
            "Pending guide",
        );
    let (_next_hash_chirho, _guide_chirho, next_record_chirho) = set_onboarding_guide_chirho(
        &root_chirho,
        "recoverfirstguide",
        &owner_chirho,
        "Next guide",
        vec![parse_onboarding_step_spec_chirho("Next=Updated body").unwrap()],
    )
    .unwrap();
    assert_eq!(
        next_record_chirho.previous_chirho,
        Some(recovered_hash_chirho)
    );
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 2);
    assert_eq!(onboarding_transition_receipts_chirho(&root_chirho).len(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn onboarding_receipt_prevents_rollback_resurrection_and_next_write_uses_rollback_head_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "rollbackguide");
    let (first_chirho, _first_guide_chirho, _first_record_chirho) =
        set_onboarding_guide_chirho(
            &root_chirho,
            "rollbackguide",
            &owner_chirho,
            "Guide A",
            vec![parse_onboarding_step_spec_chirho("A=First").unwrap()],
        )
        .unwrap();
    let (_second_chirho, _second_guide_chirho, second_record_chirho) =
        set_onboarding_guide_chirho(
            &root_chirho,
            "rollbackguide",
            &owner_chirho,
            "Guide B",
            vec![parse_onboarding_step_spec_chirho("B=Second").unwrap()],
        )
        .unwrap();
    refs_chirho::rollback_chirho(
        &root_chirho,
        &onboarding_ref_chirho("rollbackguide"),
        first_chirho.clone(),
    )
    .unwrap();
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    assert_eq!(
        recover_onboarding_head_chirho(&root_chirho, "rollbackguide").unwrap(),
        None
    );
    assert_eq!(
        std::fs::read(root_chirho.join("refs-chirho.json")).unwrap(),
        refs_before_chirho
    );
    let verified_records_chirho = verified_onboarding_records_chirho(&root_chirho).unwrap();
    let settled_prepared_chirho = prepared_from_verified_onboarding_record_chirho(
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
    let (_third_chirho, _third_guide_chirho, third_record_chirho) =
        set_onboarding_guide_chirho(
            &root_chirho,
            "rollbackguide",
            &owner_chirho,
            "Guide C",
            vec![parse_onboarding_step_spec_chirho("C=Third").unwrap()],
        )
        .unwrap();
    assert_eq!(third_record_chirho.previous_chirho, Some(first_chirho));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn onboarding_stale_preparer_cannot_complete_after_recovery_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "zombieguide");
    let (_hash_chirho, _record_chirho, prepared_chirho, stale_fence_chirho) =
        append_pending_onboarding_v2_chirho(
            &root_chirho,
            "zombieguide",
            &owner_chirho,
            "Pending guide",
        );
    recover_onboarding_head_chirho(&root_chirho, "zombieguide").unwrap();
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
fn onboarding_v1_history_never_becomes_recovery_authority_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "legacyrecoverguide");
    let (legacy_hash_chirho, _legacy_record_chirho) = append_legacy_onboarding_v1_chirho(
        &root_chirho,
        "legacyrecoverguide",
        &owner_chirho,
    );
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        recover_onboarding_head_chirho(&root_chirho, "legacyrecoverguide").unwrap(),
        None
    );
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "legacyrecoverguide").unwrap(),
        None
    );

    refs_chirho::set_branch_chirho(
        &root_chirho,
        &onboarding_ref_chirho("legacyrecoverguide"),
        legacy_hash_chirho.clone(),
    )
    .unwrap();
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "legacyrecoverguide").unwrap(),
        Some(legacy_hash_chirho.clone())
    );
    let (_next_chirho, _guide_chirho, v2_record_chirho) = set_onboarding_guide_chirho(
        &root_chirho,
        "legacyrecoverguide",
        &owner_chirho,
        "Current guide",
        vec![parse_onboarding_step_spec_chirho("Start=Current body").unwrap()],
    )
    .unwrap();
    assert_eq!(v2_record_chirho.previous_chirho, Some(legacy_hash_chirho));
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn onboarding_v2_signature_binds_transition_id_and_prepared_epoch_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "signedv2guide");
    set_onboarding_guide_chirho(
        &root_chirho,
        "signedv2guide",
        &owner_chirho,
        "Signed guide",
        vec![parse_onboarding_step_spec_chirho("Start=Signed body").unwrap()],
    )
    .unwrap();
    let original_chirho = load_onboarding_records_chirho(&root_chirho).unwrap();
    let mut tampered_id_chirho = original_chirho.clone();
    tampered_id_chirho[0].transition_id_chirho =
        format!("{HEAD_TRANSITION_ID_PREFIX_CHIRHO}{}", "2".repeat(64));
    write_jsonl_chirho(
        &onboarding_records_path_chirho(&root_chirho),
        &tampered_id_chirho,
    );
    assert!(verify_onboarding_chirho(&root_chirho)
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
        &onboarding_records_path_chirho(&root_chirho),
        &tampered_epoch_chirho,
    );
    assert!(verify_onboarding_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("signature invalid"));
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn onboarding_recovery_rejects_resigned_transition_from_another_group_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "wronggroupguide");
    set_onboarding_guide_chirho(
        &root_chirho,
        "wronggroupguide",
        &owner_chirho,
        "Wrong group guide",
        vec![parse_onboarding_step_spec_chirho("Start=Wrong group body").unwrap()],
    )
    .unwrap();
    let mut records_chirho = load_onboarding_records_chirho(&root_chirho).unwrap();
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
        onboarding_transition_operation_bytes_chirho(&records_chirho[0]).unwrap();
    let branch_chirho = onboarding_ref_chirho("wronggroupguide");
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: ONBOARDING_RECORDS_LOG_CHIRHO,
        family_seq_chirho: records_chirho[0].seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &records_chirho[0].previous_chirho,
        next_chirho: &records_chirho[0].guide_chirho,
        reason_chirho: ONBOARDING_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &wrong_fence_chirho,
        at_ms_chirho: records_chirho[0].at_ms_chirho,
    };
    records_chirho[0].transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho).unwrap();
    let wrong_group_record_chirho = records_chirho.remove(0);
    records_chirho.push(resign_onboarding_record_for_test_chirho(
        &root_chirho,
        wrong_group_record_chirho,
    ));
    write_jsonl_chirho(
        &onboarding_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let refs_before_chirho = std::fs::read(root_chirho.join("refs-chirho.json")).unwrap();
    assert!(recover_onboarding_head_chirho(&root_chirho, "wronggroupguide")
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
fn onboarding_multiple_unapplied_v2_rows_fail_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "ambiguousguide");
    append_pending_onboarding_v2_chirho(
        &root_chirho,
        "ambiguousguide",
        &owner_chirho,
        "Guide A",
    );
    append_pending_onboarding_v2_chirho(
        &root_chirho,
        "ambiguousguide",
        &owner_chirho,
        "Guide B",
    );
    assert!(recover_onboarding_head_chirho(&root_chirho, "ambiguousguide")
        .unwrap_err()
        .to_string()
        .contains("multiple unapplied"));
    assert_eq!(
        current_onboarding_hash_chirho(&root_chirho, "ambiguousguide").unwrap(),
        None
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
