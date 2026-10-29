// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn forward_create_replays_and_conflicting_request_refuses_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho.clone());
    let key_chirho = evidence_key_chirho();
    let effect_key_chirho = hash_chirho('e');
    let subject_chirho = hash_chirho('a');
    let value_ref_chirho = private_chirho.insert_blob_chirho(&subject_chirho, b"created-value");
    let request_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho { value_ref_chirho },
    );
    let request_bytes_chirho = canonical_request_bytes_chirho(&request_chirho).unwrap();

    let first_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &request_bytes_chirho,
    )
    .unwrap();
    assert!(!first_chirho.replayed_chirho);
    assert_eq!(
        database_chirho.row_chirho(
            &request_chirho.subject_chirho,
            &request_chirho.row_key_chirho
        ),
        Some(b"created-value".as_slice())
    );

    let replay_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &effect_key_chirho,
        &request_bytes_chirho,
    )
    .unwrap();
    assert!(replay_chirho.replayed_chirho);
    assert_eq!(
        replay_chirho.receipt_bytes_chirho,
        first_chirho.receipt_bytes_chirho
    );
    let events_snapshot_chirho = events_chirho.borrow().clone();
    assert_eq!(
        event_count_chirho(
            &events_snapshot_chirho,
            LawEventChirho::INSERT_FORWARD_CHIRHO
        ),
        1
    );
    assert_eq!(
        event_count_chirho(&events_snapshot_chirho, LawEventChirho::COMMIT_CHIRHO),
        1
    );

    let conflicting_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::AbsentChirho,
    );
    assert_eq!(
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &key_chirho,
            &effect_key_chirho,
            &canonical_request_bytes_chirho(&conflicting_chirho).unwrap(),
        ),
        Err(ReversiblePostgresErrorChirho::IdempotencyConflictChirho)
    );
}

#[test]
fn forward_update_stores_before_image_before_mutation_and_commit_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho.clone());
    let key_chirho = evidence_key_chirho();
    let subject_chirho = hash_chirho('a');
    let row_key_chirho = hash_chirho('b');
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
    events_chirho.borrow_mut().clear();

    let result_chirho = apply_reversible_postgres_chirho(
        &mut database_chirho,
        &mut private_chirho,
        &key_chirho,
        &hash_chirho('e'),
        &canonical_request_bytes_chirho(&request_chirho).unwrap(),
    )
    .unwrap();
    assert_eq!(
        database_chirho.row_chirho(&subject_chirho, &row_key_chirho),
        Some(b"new-value".as_slice())
    );
    let before_ref_chirho = result_chirho
        .receipt_chirho
        .before_image_ref_chirho
        .expect("update receipt carries before-image ref");
    assert_eq!(
        private_chirho
            .load_subject_blob_chirho(&subject_chirho, &before_ref_chirho)
            .unwrap()
            .as_slice_chirho(),
        b"old-value"
    );

    let events_snapshot_chirho = events_chirho.borrow().clone();
    assert!(
        event_position_chirho(&events_snapshot_chirho, LawEventChirho::LOAD_PRIVATE_CHIRHO)
            < event_position_chirho(&events_snapshot_chirho, LawEventChirho::BEGIN_CHIRHO)
    );
    assert!(
        event_position_chirho(
            &events_snapshot_chirho,
            LawEventChirho::STORE_PRIVATE_CHIRHO
        ) < event_position_chirho(&events_snapshot_chirho, LawEventChirho::UPSERT_ROW_CHIRHO)
    );
    assert!(
        event_position_chirho(
            &events_snapshot_chirho,
            LawEventChirho::STORE_PRIVATE_CHIRHO
        ) < event_position_chirho(&events_snapshot_chirho, LawEventChirho::COMMIT_CHIRHO)
    );
}

#[test]
fn subject_and_expected_state_mismatches_leave_database_unchanged_chirho() {
    let events_chirho = EventLedgerChirho::default();
    let mut database_chirho = FakeDatabaseChirho::new_chirho(events_chirho.clone());
    let mut private_chirho = FakePrivateEvidenceChirho::new_chirho(events_chirho.clone());
    let key_chirho = evidence_key_chirho();
    let wrong_subject_ref_chirho =
        private_chirho.insert_blob_chirho(&hash_chirho('9'), b"private-value");
    let subject_mismatch_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::AbsentChirho,
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: wrong_subject_ref_chirho,
        },
    );
    assert_eq!(
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &key_chirho,
            &hash_chirho('e'),
            &canonical_request_bytes_chirho(&subject_mismatch_chirho).unwrap(),
        ),
        Err(ReversiblePostgresErrorChirho::PrivateEvidenceChirho(
            PrivateEvidencePortErrorChirho::SubjectMismatchChirho
        ))
    );
    assert!(database_chirho.rows_chirho.is_empty());
    assert!(!events_chirho
        .borrow()
        .contains(&LawEventChirho::BEGIN_CHIRHO));

    let valid_ref_chirho = private_chirho.insert_blob_chirho(&hash_chirho('a'), b"private-value");
    let expected_mismatch_chirho = build_request_chirho(
        ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: hash_chirho('f'),
        },
        DesiredPostgresStateChirho::PresentChirho {
            value_ref_chirho: valid_ref_chirho,
        },
    );
    assert!(matches!(
        apply_reversible_postgres_chirho(
            &mut database_chirho,
            &mut private_chirho,
            &key_chirho,
            &hash_chirho('d'),
            &canonical_request_bytes_chirho(&expected_mismatch_chirho).unwrap(),
        ),
        Err(ReversiblePostgresErrorChirho::ExpectedBeforeMismatchChirho { .. })
    ));
    assert!(database_chirho.rows_chirho.is_empty());
    assert!(database_chirho.forward_decisions_chirho.is_empty());
    assert!(!events_chirho
        .borrow()
        .contains(&LawEventChirho::STORE_PRIVATE_CHIRHO));
}
