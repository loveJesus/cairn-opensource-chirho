// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn compensation_preview_is_read_only_across_executable_superseded_and_replay_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho.clone());
    let key_chirho = evidence_key_chirho();
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');
    let effect_key_chirho = hash_chirho('e');
    let compensation_key_chirho = hash_chirho('c');
    let new_ref_chirho = private_chirho.insert_blob_chirho(&subject_chirho, b"new-value");
    let request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: new_ref_chirho,
        },
    );
    let request_bytes_chirho = canonical_request_bytes_chirho(&request_chirho).unwrap();
    let forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &request_bytes_chirho,
    )
    .unwrap();
    let originals_chirho = original_effects_chirho(
        &effect_key_chirho,
        &request_bytes_chirho,
        &forward_chirho.receipt_bytes_chirho,
    );

    let state_before_chirho = (
        database_chirho.rows_chirho.clone(),
        database_chirho.forward_decisions_chirho.clone(),
        database_chirho.compensation_receipts_chirho.clone(),
        database_chirho.compensation_by_original_chirho.clone(),
    );
    events_chirho.borrow_mut().clear();
    assert_eq!(
        preview_reversible_postgres_compensation_chirho(
            &mut database_chirho,
            &originals_chirho,
            &key_chirho,
            &effect_key_chirho,
        )
        .unwrap(),
        PostgresCompensationPreviewChirho::ExecutableChirho
    );
    assert_eq!(
        (
            database_chirho.rows_chirho.clone(),
            database_chirho.forward_decisions_chirho.clone(),
            database_chirho.compensation_receipts_chirho.clone(),
            database_chirho.compensation_by_original_chirho.clone(),
        ),
        state_before_chirho
    );
    assert!(!events_chirho.borrow().iter().any(|event_chirho| matches!(
        *event_chirho,
        LawEventChirho::UPSERT_ROW_CHIRHO
            | LawEventChirho::DELETE_ROW_CHIRHO
            | LawEventChirho::INSERT_FORWARD_CHIRHO
            | LawEventChirho::INSERT_COMPENSATION_CHIRHO
            | LawEventChirho::COMMIT_CHIRHO
    )));
    assert_eq!(
        query_reversible_postgres_compensation_by_key_chirho(
            &mut database_chirho,
            &originals_chirho,
            &key_chirho,
            &compensation_key_chirho,
            &effect_key_chirho,
        )
        .unwrap(),
        PostgresCompensationQueryResultChirho::InDoubtChirho
    );

    database_chirho.set_row_chirho(&subject_chirho, &row_key_chirho, b"newer-world-state");
    let state_before_chirho = (
        database_chirho.rows_chirho.clone(),
        database_chirho.forward_decisions_chirho.clone(),
        database_chirho.compensation_receipts_chirho.clone(),
        database_chirho.compensation_by_original_chirho.clone(),
    );
    assert!(matches!(
        preview_reversible_postgres_compensation_chirho(
            &mut database_chirho,
            &originals_chirho,
            &key_chirho,
            &effect_key_chirho,
        )
        .unwrap(),
        PostgresCompensationPreviewChirho::MustNotExecuteChirho { .. }
    ));
    assert_eq!(
        (
            database_chirho.rows_chirho.clone(),
            database_chirho.forward_decisions_chirho.clone(),
            database_chirho.compensation_receipts_chirho.clone(),
            database_chirho.compensation_by_original_chirho.clone(),
        ),
        state_before_chirho
    );

    let compensation_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &originals_chirho,
        &key_chirho,
        &compensation_key_chirho,
        &effect_key_chirho,
    )
    .unwrap();
    let state_before_chirho = (
        database_chirho.rows_chirho.clone(),
        database_chirho.forward_decisions_chirho.clone(),
        database_chirho.compensation_receipts_chirho.clone(),
        database_chirho.compensation_by_original_chirho.clone(),
    );
    assert_eq!(
        preview_reversible_postgres_compensation_chirho(
            &mut database_chirho,
            &originals_chirho,
            &key_chirho,
            &effect_key_chirho,
        )
        .unwrap(),
        PostgresCompensationPreviewChirho::CompletedReplayChirho {
            receipt_chirho: compensation_chirho.receipt_chirho.clone(),
            receipt_bytes_chirho: compensation_chirho.receipt_bytes_chirho.clone(),
        }
    );
    assert_eq!(
        query_reversible_postgres_compensation_by_key_chirho(
            &mut database_chirho,
            &originals_chirho,
            &key_chirho,
            &compensation_key_chirho,
            &effect_key_chirho,
        )
        .unwrap(),
        PostgresCompensationQueryResultChirho::CommittedChirho {
            receipt_chirho: compensation_chirho.receipt_chirho.clone(),
            receipt_bytes_chirho: compensation_chirho.receipt_bytes_chirho.clone(),
        }
    );
    assert_eq!(
        (
            database_chirho.rows_chirho.clone(),
            database_chirho.forward_decisions_chirho.clone(),
            database_chirho.compensation_receipts_chirho.clone(),
            database_chirho.compensation_by_original_chirho.clone(),
        ),
        state_before_chirho
    );
}

#[test]
fn compensation_restores_update_replays_and_refuses_second_key_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho.clone());
    let key_chirho = evidence_key_chirho();
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');
    let effect_key_chirho = hash_chirho('e');
    let compensation_key_chirho = hash_chirho('c');
    database_chirho.set_row_chirho(&subject_chirho, &row_key_chirho, b"old-value");
    let new_ref_chirho = private_chirho.insert_blob_chirho(&subject_chirho, b"new-value");
    let request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: row_fingerprint_chirho(
                &key_chirho,
                &subject_chirho,
                &row_key_chirho,
                b"old-value",
            ),
        },
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: new_ref_chirho,
        },
    );
    let request_bytes_chirho = canonical_request_bytes_chirho(&request_chirho).unwrap();
    let forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &request_bytes_chirho,
    )
    .unwrap();
    let originals_chirho = original_effects_chirho(
        &effect_key_chirho,
        &request_bytes_chirho,
        &forward_chirho.receipt_bytes_chirho,
    );
    events_chirho.borrow_mut().clear();

    let compensation_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &originals_chirho,
        &key_chirho,
        &compensation_key_chirho,
        &effect_key_chirho,
    )
    .unwrap();
    assert_eq!(
        compensation_chirho.receipt_chirho.outcome_chirho,
        PostgresCompensationOutcomeChirho::RestoredChirho {
            restored_state_chirho: forward_chirho.receipt_chirho.before_state_chirho.clone(),
        }
    );
    assert_eq!(
        database_chirho.row_chirho(&subject_chirho, &row_key_chirho),
        Some(b"old-value".as_slice())
    );
    let mutation_count_chirho =
        event_count_chirho(&events_chirho.borrow(), LawEventChirho::UPSERT_ROW_CHIRHO);
    let commit_count_chirho =
        event_count_chirho(&events_chirho.borrow(), LawEventChirho::COMMIT_CHIRHO);

    let replay_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &originals_chirho,
        &key_chirho,
        &compensation_key_chirho,
        &effect_key_chirho,
    )
    .unwrap();
    assert!(replay_chirho.replayed_chirho);
    assert_eq!(
        replay_chirho.receipt_bytes_chirho,
        compensation_chirho.receipt_bytes_chirho
    );
    assert_eq!(
        event_count_chirho(&events_chirho.borrow(), LawEventChirho::UPSERT_ROW_CHIRHO),
        mutation_count_chirho
    );
    assert_eq!(
        event_count_chirho(&events_chirho.borrow(), LawEventChirho::COMMIT_CHIRHO),
        commit_count_chirho
    );
    assert_eq!(
        compensate_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &originals_chirho,
            &key_chirho,
            &hash_chirho('d'),
            &effect_key_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::CompensationAlreadyRecordedChirho)
    );
}

#[test]
fn compensation_restores_deleted_row_and_deletes_created_row_chirho() {
    let key_chirho = evidence_key_chirho();
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');

    let delete_events_chirho = EventLedgerChirho::default();
    let mut delete_database_chirho = FakeDatabaseChirho::new_chirho(delete_events_chirho.clone());
    let mut delete_private_chirho = FakePrivateEvidenceChirho::new_chirho(delete_events_chirho);
    delete_database_chirho.set_row_chirho(&subject_chirho, &row_key_chirho, b"delete-me");
    let delete_request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: row_fingerprint_chirho(
                &key_chirho,
                &subject_chirho,
                &row_key_chirho,
                b"delete-me",
            ),
        },
        DesiredPostgresStateChirho::AbsentChirho,
    );
    let delete_request_bytes_chirho =
        canonical_request_bytes_chirho(&delete_request_chirho).unwrap();
    let delete_effect_chirho = hash_chirho('e');
    let delete_forward_chirho = apply_reversible_postgres_chirho(
        &mut delete_database_chirho,
        &mut delete_private_chirho,
        &key_chirho,
        &delete_effect_chirho,
        &delete_request_bytes_chirho,
    )
    .unwrap();
    assert!(delete_database_chirho
        .row_chirho(&subject_chirho, &row_key_chirho)
        .is_none());
    compensate_reversible_postgres_chirho(
        &mut delete_database_chirho,
        &mut delete_private_chirho,
        &original_effects_chirho(
            &delete_effect_chirho,
            &delete_request_bytes_chirho,
            &delete_forward_chirho.receipt_bytes_chirho,
        ),
        &key_chirho,
        &hash_chirho('c'),
        &delete_effect_chirho,
    )
    .unwrap();
    assert_eq!(
        delete_database_chirho.row_chirho(&subject_chirho, &row_key_chirho),
        Some(b"delete-me".as_slice())
    );

    let create_events_chirho = EventLedgerChirho::default();
    let mut create_database_chirho = FakeDatabaseChirho::new_chirho(create_events_chirho.clone());
    let mut create_private_chirho = FakePrivateEvidenceChirho::new_chirho(create_events_chirho);
    let create_ref_chirho = create_private_chirho.insert_blob_chirho(&subject_chirho, b"create-me");
    let create_request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: create_ref_chirho,
        },
    );
    let create_request_bytes_chirho =
        canonical_request_bytes_chirho(&create_request_chirho).unwrap();
    let create_effect_chirho = hash_chirho('f');
    let create_forward_chirho = apply_reversible_postgres_chirho(
        &mut create_database_chirho,
        &mut create_private_chirho,
        &key_chirho,
        &create_effect_chirho,
        &create_request_bytes_chirho,
    )
    .unwrap();
    compensate_reversible_postgres_chirho(
        &mut create_database_chirho,
        &mut create_private_chirho,
        &original_effects_chirho(
            &create_effect_chirho,
            &create_request_bytes_chirho,
            &create_forward_chirho.receipt_bytes_chirho,
        ),
        &key_chirho,
        &hash_chirho('9'),
        &create_effect_chirho,
    )
    .unwrap();
    assert!(create_database_chirho
        .row_chirho(&subject_chirho, &row_key_chirho)
        .is_none());
}

#[test]
fn superseded_compensation_is_durable_and_never_blind_restores_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho.clone());
    let key_chirho = evidence_key_chirho();
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');
    let effect_key_chirho = hash_chirho('e');
    let compensation_key_chirho = hash_chirho('c');
    let new_ref_chirho = private_chirho.insert_blob_chirho(&subject_chirho, b"new-value");
    let request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: new_ref_chirho,
        },
    );
    let request_bytes_chirho = canonical_request_bytes_chirho(&request_chirho).unwrap();
    let forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &request_bytes_chirho,
    )
    .unwrap();
    let originals_chirho = original_effects_chirho(
        &effect_key_chirho,
        &request_bytes_chirho,
        &forward_chirho.receipt_bytes_chirho,
    );
    database_chirho.set_row_chirho(&subject_chirho, &row_key_chirho, b"newer-world-state");

    let superseded_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &originals_chirho,
        &key_chirho,
        &compensation_key_chirho,
        &effect_key_chirho,
    )
    .unwrap();
    assert!(matches!(
        superseded_chirho.receipt_chirho.outcome_chirho,
        PostgresCompensationOutcomeChirho::SupersededChirho { .. }
    ));
    assert_eq!(
        database_chirho.row_chirho(&subject_chirho, &row_key_chirho),
        Some(b"newer-world-state".as_slice())
    );

    database_chirho.set_row_chirho(&subject_chirho, &row_key_chirho, b"later-world-state");
    let replay_chirho = compensate_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &originals_chirho,
        &key_chirho,
        &compensation_key_chirho,
        &effect_key_chirho,
    )
    .unwrap();
    assert!(replay_chirho.replayed_chirho);
    assert_eq!(
        replay_chirho.receipt_bytes_chirho,
        superseded_chirho.receipt_bytes_chirho
    );
    assert_eq!(
        database_chirho.row_chirho(&subject_chirho, &row_key_chirho),
        Some(b"later-world-state".as_slice())
    );
}

#[test]
fn receipt_mac_original_binding_and_before_image_tamper_fail_closed_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho);
    let key_chirho = evidence_key_chirho();
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');
    let effect_key_chirho = hash_chirho('e');
    database_chirho.set_row_chirho(&subject_chirho, &row_key_chirho, b"old-value");
    let new_ref_chirho = private_chirho.insert_blob_chirho(&subject_chirho, b"new-value");
    let request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: row_fingerprint_chirho(
                &key_chirho,
                &subject_chirho,
                &row_key_chirho,
                b"old-value",
            ),
        },
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: new_ref_chirho,
        },
    );
    let request_bytes_chirho = canonical_request_bytes_chirho(&request_chirho).unwrap();
    apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &request_bytes_chirho,
    )
    .unwrap();

    let coordinate_chirho = effect_coordinate_chirho(&effect_key_chirho);
    let row_chirho = database_chirho
        .forward_decisions_chirho
        .get_mut(coordinate_chirho.effect_intent_key_chirho())
        .unwrap();
    let mut decision_chirho =
        parse_canonical_committed_decision_chirho(&row_chirho.decision_bytes_chirho).unwrap();
    decision_chirho.receipt_mac_chirho = hash_chirho('0');
    row_chirho.decision_bytes_chirho =
        canonical_committed_decision_bytes_chirho(&decision_chirho).unwrap();
    assert!(matches!(
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &key_chirho,
            &effect_key_chirho,
            &request_bytes_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::StoredEvidenceInvalidChirho { .. })
    ));

    // Restore the authenticated row by re-applying its canonical MAC through a fresh fixture.
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho);
    database_chirho.set_row_chirho(&subject_chirho, &row_key_chirho, b"old-value");
    let new_ref_chirho = private_chirho.insert_blob_chirho(&subject_chirho, b"new-value");
    let bound_request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: row_fingerprint_chirho(
                &key_chirho,
                &subject_chirho,
                &row_key_chirho,
                b"old-value",
            ),
        },
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: new_ref_chirho,
        },
    );
    let request_bytes_chirho = canonical_request_bytes_chirho(&bound_request_chirho).unwrap();
    let forward_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &request_bytes_chirho,
    )
    .unwrap();
    let before_ref_chirho = forward_chirho
        .receipt_chirho
        .before_image_ref_chirho
        .clone()
        .unwrap();
    private_chirho.tamper_blob_chirho(&before_ref_chirho, b"forged-before-image");
    let originals_chirho = original_effects_chirho(
        &effect_key_chirho,
        &request_bytes_chirho,
        &forward_chirho.receipt_bytes_chirho,
    );
    assert_eq!(
        compensate_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &originals_chirho,
            &key_chirho,
            &hash_chirho('c'),
            &effect_key_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::BeforeImageMismatchChirho)
    );
    assert_eq!(
        database_chirho.row_chirho(&subject_chirho, &row_key_chirho),
        Some(b"new-value".as_slice())
    );

    let mut wrong_originals_chirho = originals_chirho;
    wrong_originals_chirho
        .effects_chirho
        .get_mut(&effect_key_chirho)
        .unwrap()
        .request_bytes_chirho = canonical_request_bytes_chirho(&build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::AbsentChirho,
    ))
    .unwrap();
    assert!(matches!(
        compensate_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &wrong_originals_chirho,
            &key_chirho,
            &hash_chirho('d'),
            &effect_key_chirho,
        ),
        Err(ReversiblePostgresErrorChirho::OriginalEffectBindingInvalidChirho { .. })
    ));
}
