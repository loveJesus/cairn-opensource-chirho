// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

#[test]
fn private_key_file_is_written_0600_and_durable_chirho() {
    // The key that un-shreds a private blob must be written as durably (fsync'd) and as tightly
    // scoped (0600) as the ciphertext and record it accompanies. fsync itself is not observable
    // from userspace, so this pins the durable-write path's OBSERVABLE contract: after
    // store_private_blob_chirho the key file exists at its keyed path, is a 0600 regular file, and
    // the blob round-trips through that on-disk key. The reviewer confirms write_private_key_file_
    // chirho calls sync_all + fsync_dir_chirho (see its body).
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private key durability",
    )
    .unwrap();

    let key_file_path_chirho = key_path_chirho(&root_chirho, &blob_chirho.key_id_chirho);
    let metadata_chirho = std::fs::metadata(&key_file_path_chirho).unwrap();
    assert!(
        metadata_chirho.is_file(),
        "the shred key file must exist after store_private_blob_chirho"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            metadata_chirho.permissions().mode() & 0o777,
            0o600,
            "the shred key file must stay owner-only 0600"
        );
    }
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &blob_chirho).unwrap(),
        b"alice private key durability"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_blob_round_trips_then_shreds_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("anon"),
        "anon",
        b"private feedback text",
    )
    .unwrap();
    let ciphertext_chirho =
        cas_chirho::get_chirho(&root_chirho, &blob_chirho.ciphertext_chirho).unwrap();
    assert_ne!(ciphertext_chirho, b"private feedback text");
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &blob_chirho).unwrap(),
        b"private feedback text"
    );
    assert_eq!(erase_subject_keys_chirho(&root_chirho, "anon").unwrap(), 1);
    assert!(load_private_blob_chirho(&root_chirho, &blob_chirho).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_access_records_are_signed_and_plaintext_free_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "app/contact/inbox",
        ),
        "app/contact/inbox",
        b"send reply to alice@example.com",
    )
    .unwrap();
    append_privacy_access_record_chirho(
        &root_chirho,
        "app/contact/inbox",
        "owner/abc123",
        "contact",
        "contacts-chirho/submission-001",
        "owner-contact-reveal-chirho",
        &blob_chirho,
    )
    .unwrap();

    let report_chirho = verify_privacy_logs_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.blob_records_chirho, 1);
    assert_eq!(report_chirho.erasure_records_chirho, 0);
    assert_eq!(report_chirho.access_records_chirho, 1);
    let access_log_chirho =
        std::fs::read_to_string(privacy_access_records_path_chirho(&root_chirho)).unwrap();
    assert!(!access_log_chirho.contains("alice@example.com"));
    assert_eq!(
        export_subject_data_chirho(&root_chirho, "app/contact/inbox", false)
            .unwrap()
            .access_records_chirho
            .len(),
        1
    );
    assert_eq!(
        export_subject_data_chirho(&root_chirho, "owner/abc123", false)
            .unwrap()
            .access_records_chirho
            .len(),
        1
    );

    let mut record_chirho = load_privacy_access_records_chirho(&root_chirho)
        .unwrap()
        .remove(0);
    record_chirho.purpose_chirho = "tampered-purpose-chirho".to_string();
    std::fs::write(
        privacy_access_records_path_chirho(&root_chirho),
        format!("{}\n", serde_json::to_string(&record_chirho).unwrap()),
    )
    .unwrap();
    let verify_error_chirho = verify_privacy_logs_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(verify_error_chirho.contains("privacy access record 0 signature invalid"));
    let export_error_chirho = export_subject_data_chirho(&root_chirho, "app/contact/inbox", false)
        .unwrap_err()
        .to_string();
    assert!(export_error_chirho.contains("privacy access record 0 signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_blob_key_subject_bindings_fail_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    let bob_blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/bob"),
        "user/bob",
        b"bob private",
    )
    .unwrap();
    let mut blob_records_chirho = load_privacy_blob_records_chirho(&root_chirho).unwrap();
    blob_records_chirho[1].blob_chirho.key_id_chirho = alice_blob_chirho.key_id_chirho.clone();
    blob_records_chirho[1].sig_chirho.clear();
    blob_records_chirho[1].sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &privacy_blob_record_message_chirho(&blob_records_chirho[1]).unwrap(),
    )
    .unwrap();
    write_jsonl_records_chirho(
        &privacy_blob_records_path_chirho(&root_chirho),
        &blob_records_chirho,
    );

    let erase_error_chirho =
        erase_subject_data_chirho(&root_chirho, "user/alice", "owner/admin", "gdpr-erasure")
            .unwrap_err()
            .to_string();
    assert!(
        erase_error_chirho.contains("belongs to subject 'user/alice'")
            || erase_error_chirho.contains("claimed by multiple subjects")
    );
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &alice_blob_chirho).unwrap(),
        b"alice private"
    );
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &bob_blob_chirho).unwrap(),
        b"bob private"
    );
    assert!(load_privacy_erasure_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    let verify_error_chirho = verify_privacy_logs_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        verify_error_chirho.contains("belongs to subject 'user/alice'")
            || verify_error_chirho.contains("claimed by multiple subjects")
    );
    let export_error_chirho = export_subject_data_chirho(&root_chirho, "user/alice", false)
        .unwrap_err()
        .to_string();
    assert!(
        export_error_chirho.contains("belongs to subject 'user/alice'")
            || export_error_chirho.contains("claimed by multiple subjects")
    );
    let _ = std::fs::remove_dir_all(&root_chirho);

    let root_chirho = tmp_root_chirho();
    let alice_blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    let access_error_chirho = append_privacy_access_record_chirho(
        &root_chirho,
        "user/bob",
        "owner/admin",
        "contact",
        "contacts-chirho/submission-001",
        "owner-contact-reveal-chirho",
        &alice_blob_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(access_error_chirho.contains("belongs to subject 'user/alice'"));
    assert_eq!(
        verify_privacy_logs_chirho(&root_chirho)
            .unwrap()
            .access_records_chirho,
        0
    );
    let _ = std::fs::remove_dir_all(&root_chirho);

    let root_chirho = tmp_root_chirho();
    let alice_blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    append_privacy_access_record_chirho(
        &root_chirho,
        "user/alice",
        "owner/admin",
        "contact",
        "contacts-chirho/submission-001",
        "owner-contact-reveal-chirho",
        &alice_blob_chirho,
    )
    .unwrap();
    let mut access_records_chirho = load_privacy_access_records_chirho(&root_chirho).unwrap();
    access_records_chirho[0].subject_chirho = "user/bob".to_string();
    access_records_chirho[0].sig_chirho.clear();
    access_records_chirho[0].sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &privacy_access_record_message_chirho(&access_records_chirho[0]).unwrap(),
    )
    .unwrap();
    write_jsonl_records_chirho(
        &privacy_access_records_path_chirho(&root_chirho),
        &access_records_chirho,
    );
    let verify_error_chirho = verify_privacy_logs_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(verify_error_chirho.contains("belongs to subject 'user/alice'"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    let access_record_chirho = append_privacy_access_record_chirho(
        &root_chirho,
        "user/alice",
        "owner/abc123",
        "contact",
        "contacts-chirho/submission-001",
        "owner-contact-reveal-chirho",
        &blob_chirho,
    )
    .unwrap();
    let erasure_record_chirho = erase_subject_data_chirho(
        &root_chirho,
        "user/alice",
        "owner/admin",
        "gdpr-erasure-request",
    )
    .unwrap();
    let blob_record_chirho = load_privacy_blob_records_chirho(&root_chirho)
        .unwrap()
        .remove(0);
    assert_eq!(
        blob_record_chirho.schema_chirho,
        PRIVACY_BLOB_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(
        erasure_record_chirho.schema_chirho,
        PRIVACY_ERASURE_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(
        access_record_chirho.schema_chirho,
        PRIVACY_ACCESS_RECORD_SCHEMA_CHIRHO
    );

    let blob_path_chirho = privacy_blob_records_path_chirho(&root_chirho);
    let erasure_path_chirho = privacy_erasure_records_path_chirho(&root_chirho);
    let access_path_chirho = privacy_access_records_path_chirho(&root_chirho);
    let blob_text_chirho = std::fs::read_to_string(&blob_path_chirho).unwrap();
    let erasure_text_chirho = std::fs::read_to_string(&erasure_path_chirho).unwrap();
    let access_text_chirho = std::fs::read_to_string(&access_path_chirho).unwrap();
    assert!(blob_text_chirho.contains(PRIVACY_BLOB_RECORD_SCHEMA_CHIRHO));
    assert!(erasure_text_chirho.contains(PRIVACY_ERASURE_RECORD_SCHEMA_CHIRHO));
    assert!(access_text_chirho.contains(PRIVACY_ACCESS_RECORD_SCHEMA_CHIRHO));

    std::fs::write(
        &blob_path_chirho,
        blob_text_chirho.replace(
            PRIVACY_BLOB_RECORD_SCHEMA_CHIRHO,
            "privacy-blob-record-v9-chirho",
        ),
    )
    .unwrap();
    let blob_error_chirho = verify_privacy_logs_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(blob_error_chirho.contains("unsupported privacy blob record schema"));

    std::fs::write(&blob_path_chirho, blob_text_chirho).unwrap();
    std::fs::write(
        &erasure_path_chirho,
        erasure_text_chirho.replace(
            PRIVACY_ERASURE_RECORD_SCHEMA_CHIRHO,
            "privacy-erasure-record-v9-chirho",
        ),
    )
    .unwrap();
    let erasure_error_chirho = verify_privacy_logs_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(erasure_error_chirho.contains("unsupported privacy erasure record schema"));

    std::fs::write(&erasure_path_chirho, erasure_text_chirho).unwrap();
    std::fs::write(
        &access_path_chirho,
        access_text_chirho.replace(
            PRIVACY_ACCESS_RECORD_SCHEMA_CHIRHO,
            "privacy-access-record-v9-chirho",
        ),
    )
    .unwrap();
    let access_error_chirho = verify_privacy_logs_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(access_error_chirho.contains("unsupported privacy access record schema"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_blob_ref_requires_privacy_log_coverage_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    std::fs::remove_file(privacy_blob_records_path_chirho(&root_chirho)).unwrap();

    let error_chirho = verify_private_blob_ref_chirho(&root_chirho, &blob_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("not represented in the privacy blob log"));
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &blob_chirho).unwrap(),
        b"alice private"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_blob_records_require_ciphertext_presence_chirho() {
    let root_chirho = tmp_root_chirho();
    store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    let mut records_chirho = load_privacy_blob_records_chirho(&root_chirho).unwrap();
    records_chirho[0].blob_chirho.ciphertext_chirho = HashChirho("0".repeat(64));
    records_chirho[0].sig_chirho.clear();
    records_chirho[0].sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &privacy_blob_record_message_chirho(&records_chirho[0]).unwrap(),
    )
    .unwrap();
    write_jsonl_records_chirho(
        &privacy_blob_records_path_chirho(&root_chirho),
        &records_chirho,
    );

    let error_chirho = verify_privacy_logs_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("private ciphertext"));
    assert!(error_chirho.contains("missing"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_privacy_records_without_schema_still_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    append_privacy_access_record_chirho(
        &root_chirho,
        "user/alice",
        "owner/abc123",
        "contact",
        "contacts-chirho/submission-001",
        "owner-contact-reveal-chirho",
        &blob_chirho,
    )
    .unwrap();
    erase_subject_data_chirho(
        &root_chirho,
        "user/alice",
        "owner/admin",
        "gdpr-erasure-request",
    )
    .unwrap();

    let mut blob_record_chirho = load_privacy_blob_records_chirho(&root_chirho)
        .unwrap()
        .remove(0);
    blob_record_chirho.schema_chirho.clear();
    blob_record_chirho.sig_chirho.clear();
    blob_record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &privacy_blob_record_message_chirho(&blob_record_chirho).unwrap(),
    )
    .unwrap();
    std::fs::write(
        privacy_blob_records_path_chirho(&root_chirho),
        format!("{}\n", serde_json::to_string(&blob_record_chirho).unwrap()),
    )
    .unwrap();

    let mut erasure_record_chirho = load_privacy_erasure_records_chirho(&root_chirho)
        .unwrap()
        .remove(0);
    erasure_record_chirho.schema_chirho.clear();
    erasure_record_chirho.sig_chirho.clear();
    erasure_record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &privacy_erasure_record_message_chirho(&erasure_record_chirho).unwrap(),
    )
    .unwrap();
    std::fs::write(
        privacy_erasure_records_path_chirho(&root_chirho),
        format!(
            "{}\n",
            serde_json::to_string(&erasure_record_chirho).unwrap()
        ),
    )
    .unwrap();

    let mut access_record_chirho = load_privacy_access_records_chirho(&root_chirho)
        .unwrap()
        .remove(0);
    access_record_chirho.schema_chirho.clear();
    access_record_chirho.sig_chirho.clear();
    access_record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &privacy_access_record_message_chirho(&access_record_chirho).unwrap(),
    )
    .unwrap();
    std::fs::write(
        privacy_access_records_path_chirho(&root_chirho),
        format!(
            "{}\n",
            serde_json::to_string(&access_record_chirho).unwrap()
        ),
    )
    .unwrap();

    let blob_text_chirho =
        std::fs::read_to_string(privacy_blob_records_path_chirho(&root_chirho)).unwrap();
    let erasure_text_chirho =
        std::fs::read_to_string(privacy_erasure_records_path_chirho(&root_chirho)).unwrap();
    let access_text_chirho =
        std::fs::read_to_string(privacy_access_records_path_chirho(&root_chirho)).unwrap();
    assert!(!blob_text_chirho.contains("schema_chirho"));
    assert!(!erasure_text_chirho.contains("schema_chirho"));
    assert!(!access_text_chirho.contains("schema_chirho"));
    let report_chirho = verify_privacy_logs_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.blob_records_chirho, 1);
    assert_eq!(report_chirho.erasure_records_chirho, 1);
    assert_eq!(report_chirho.access_records_chirho, 1);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_blob_key_can_be_erased_by_key_id_chirho() {
    let root_chirho = tmp_root_chirho();
    let blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("anon"),
        "anon",
        b"private feedback text",
    )
    .unwrap();
    let other_blob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("anon"),
        "anon",
        b"younger private feedback",
    )
    .unwrap();
    assert!(erase_private_blob_key_chirho(&root_chirho, &blob_chirho.key_id_chirho).unwrap());
    assert!(!erase_private_blob_key_chirho(&root_chirho, &blob_chirho.key_id_chirho).unwrap());
    assert!(load_private_blob_chirho(&root_chirho, &blob_chirho).is_err());
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &other_blob_chirho).unwrap(),
        b"younger private feedback"
    );
    assert!(erase_private_blob_key_chirho(&root_chirho, "../bad").is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn private_blob_subject_must_be_opaque_token_chirho() {
    let root_chirho = tmp_root_chirho();
    assert!(store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "alice@example.com"
        ),
        "alice@example.com",
        b"secret"
    )
    .is_err());
    assert!(store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/abcdef0123456789"
        ),
        "user/abcdef0123456789",
        b"secret"
    )
    .is_ok());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_blob_index_is_signed_and_contains_no_plaintext_chirho() {
    let root_chirho = tmp_root_chirho();
    let first_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"private feedback text",
    )
    .unwrap();
    let second_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"second private text",
    )
    .unwrap();
    let other_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/bob"),
        "user/bob",
        b"bob private text",
    )
    .unwrap();

    let report_chirho = verify_privacy_logs_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.blob_records_chirho, 3);
    assert_eq!(report_chirho.erasure_records_chirho, 0);
    let log_chirho =
        std::fs::read_to_string(privacy_blob_records_path_chirho(&root_chirho)).unwrap();
    assert!(!log_chirho.contains("private feedback text"));
    assert!(!log_chirho.contains("second private text"));
    assert!(log_chirho.contains(&first_chirho.ciphertext_chirho.0));
    assert!(log_chirho.contains(&second_chirho.ciphertext_chirho.0));
    assert!(log_chirho.contains(&other_chirho.ciphertext_chirho.0));

    let export_chirho = export_subject_data_chirho(&root_chirho, "user/alice", true).unwrap();
    assert_eq!(export_chirho.private_blobs_chirho.len(), 2);
    let payloads_chirho: Vec<Vec<u8>> = export_chirho
        .private_blobs_chirho
        .iter()
        .map(|item_chirho| {
            general_purpose::STANDARD
                .decode(item_chirho.plaintext_base64_chirho.as_ref().unwrap())
                .unwrap()
        })
        .collect();
    assert!(payloads_chirho.contains(&b"private feedback text".to_vec()));
    assert!(payloads_chirho.contains(&b"second private text".to_vec()));

    let mut records_chirho = load_privacy_blob_records_chirho(&root_chirho).unwrap();
    records_chirho[0].bytes_chirho += 1;
    write_jsonl_records_chirho(
        &privacy_blob_records_path_chirho(&root_chirho),
        &records_chirho,
    );
    let export_error_chirho = export_subject_data_chirho(&root_chirho, "user/alice", true)
        .unwrap_err()
        .to_string();
    assert!(export_error_chirho.contains("privacy blob record 0 signature invalid"));
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &first_chirho).unwrap(),
        b"private feedback text"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn subject_erasure_records_signed_shred_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    let bob_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/bob"),
        "user/bob",
        b"bob private",
    )
    .unwrap();

    assert_eq!(
        subject_private_key_ids_chirho(&root_chirho, "user/alice")
            .unwrap()
            .len(),
        1
    );
    let record_chirho = erase_subject_data_chirho(
        &root_chirho,
        "user/alice",
        "owner/admin",
        "gdpr-erasure-request",
    )
    .unwrap();
    assert_eq!(record_chirho.removed_keys_chirho, 1);
    assert_eq!(
        record_chirho.key_ids_chirho,
        vec![alice_chirho.key_id_chirho.clone()]
    );
    assert!(load_private_blob_chirho(&root_chirho, &alice_chirho).is_err());
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &bob_chirho).unwrap(),
        b"bob private"
    );

    let report_chirho = verify_privacy_logs_chirho(&root_chirho).unwrap();
    assert_eq!(report_chirho.blob_records_chirho, 2);
    assert_eq!(report_chirho.erasure_records_chirho, 1);
    let export_chirho = export_subject_data_chirho(&root_chirho, "user/alice", true).unwrap();
    assert_eq!(export_chirho.private_blobs_chirho.len(), 1);
    assert!(export_chirho.private_blobs_chirho[0]
        .plaintext_base64_chirho
        .is_none());
    assert!(export_chirho.private_blobs_chirho[0]
        .unavailable_reason_chirho
        .as_deref()
        .unwrap_or("")
        .contains("read"));
    assert_eq!(export_chirho.erasures_chirho.len(), 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn active_legal_hold_blocks_subject_erasure_chirho() {
    let root_chirho = tmp_root_chirho();
    let alice_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/alice"),
        "user/alice",
        b"alice private",
    )
    .unwrap();
    crate::legal_hold_chirho::place_legal_hold_chirho(
        &root_chirho,
        "hold/case-1",
        "user/alice",
        "case/privacy-1",
        "litigation",
        "operator/legal",
    )
    .unwrap();
    let error_chirho = erase_subject_data_chirho(
        &root_chirho,
        "user/alice",
        "operator/privacy",
        "gdpr-erasure-request",
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("active legal hold"));
    assert_eq!(
        load_private_blob_chirho(&root_chirho, &alice_chirho).unwrap(),
        b"alice private"
    );
    crate::legal_hold_chirho::release_legal_hold_chirho(
        &root_chirho,
        "hold/case-1",
        "case-closed",
        "operator/legal",
    )
    .unwrap();
    erase_subject_data_chirho(
        &root_chirho,
        "user/alice",
        "operator/privacy",
        "gdpr-erasure-request",
    )
    .unwrap();
    assert!(load_private_blob_chirho(&root_chirho, &alice_chirho).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}
