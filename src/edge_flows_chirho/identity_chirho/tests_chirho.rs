// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-identity-test-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, rows_chirho: &[T]) {
    if let Some(parent_chirho) = path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho).unwrap();
    }
    let mut text_chirho = String::new();
    for row_chirho in rows_chirho {
        text_chirho.push_str(&serde_json::to_string(row_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn resign_identity_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: IdentityRecordChirho,
) -> IdentityRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

fn resign_session_record_for_test_chirho(
    root_chirho: &Path,
    mut session_chirho: IdentitySessionChirho,
) -> IdentitySessionChirho {
    let key_record_chirho =
        load_identity_key_record_chirho(root_chirho, &session_chirho.principal_chirho).unwrap();
    let signing_key_chirho = signing_key_from_identity_key_chirho(&key_record_chirho).unwrap();
    session_chirho.proof_chirho.clear();
    session_chirho.sig_chirho.clear();
    session_chirho.proof_chirho = hex_encode_chirho(
        &signing_key_chirho
            .sign(&session_proof_message_chirho(&session_chirho).unwrap())
            .to_bytes(),
    );
    session_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &session_message_chirho(&session_chirho).unwrap(),
    )
    .unwrap();
    session_chirho
}

fn resign_session_revocation_record_for_test_chirho(
    root_chirho: &Path,
    mut revocation_chirho: IdentitySessionRevocationRecordChirho,
) -> IdentitySessionRevocationRecordChirho {
    revocation_chirho.sig_chirho.clear();
    revocation_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &session_revocation_message_chirho(&revocation_chirho).unwrap(),
    )
    .unwrap();
    revocation_chirho
}

#[test]
fn register_user_binds_one_wallet_without_legacy_ledger_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    assert!(identity_chirho.principal_chirho.starts_with("user/"));
    assert_eq!(
        identity_chirho.wallet_chirho,
        identity_chirho.principal_chirho
    );
    assert_eq!(verify_identities_chirho(&root_chirho).unwrap(), 1);
    let login_chirho =
        login_identity_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();
    assert_eq!(
        login_chirho.session_chirho.principal_chirho,
        identity_chirho.principal_chirho
    );
    assert_ne!(
        login_chirho.session_chirho.token_hash_chirho,
        login_chirho.token_chirho
    );
    assert_eq!(verify_sessions_chirho(&root_chirho).unwrap(), 1);
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    assert!(
        validate_session_token_chirho(&root_chirho, &identity_chirho.principal_chirho, "bad")
            .unwrap()
            .is_none()
    );
    assert!(!root_chirho.join("ledger-chirho.jsonl").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn session_revocation_invalidates_only_target_session_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::OwnerChirho,
        "owner-session-secret",
    )
    .unwrap();
    let login_a_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "owner-session-secret",
    )
    .unwrap();
    let login_b_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "owner-session-secret",
    )
    .unwrap();

    assert_eq!(verify_sessions_chirho(&root_chirho).unwrap(), 2);
    assert_eq!(verify_session_revocations_chirho(&root_chirho).unwrap(), 0);
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_a_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_b_chirho.token_chirho
    )
    .unwrap()
    .is_some());

    let revocation_chirho = revoke_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_a_chirho.token_chirho,
        "owner-session-chirho",
        "owner-logout-chirho",
    )
    .unwrap();
    assert_eq!(
        revocation_chirho.session_seq_chirho,
        login_a_chirho.session_chirho.seq_chirho
    );
    assert_eq!(verify_session_revocations_chirho(&root_chirho).unwrap(), 1);
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_a_chirho.token_chirho
    )
    .unwrap()
    .is_none());
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_b_chirho.token_chirho
    )
    .unwrap()
    .is_some());

    let repeated_chirho = revoke_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_a_chirho.token_chirho,
        "owner-session-chirho",
        "owner-logout-chirho",
    )
    .unwrap();
    assert_eq!(repeated_chirho.seq_chirho, revocation_chirho.seq_chirho);
    assert_eq!(verify_session_revocations_chirho(&root_chirho).unwrap(), 1);

    let revocation_json_chirho =
        std::fs::read_to_string(session_revocations_path_chirho(&root_chirho)).unwrap();
    assert!(!revocation_json_chirho.contains(&login_a_chirho.token_chirho));
    assert!(!revocation_json_chirho.contains(&login_b_chirho.token_chirho));
    assert!(revocation_json_chirho.contains(&login_a_chirho.session_chirho.token_hash_chirho));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn session_revocation_verify_catches_tamper_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "tamper-session-secret",
    )
    .unwrap();
    let login_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "tamper-session-secret",
    )
    .unwrap();
    let revocation_chirho = revoke_session_by_seq_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        login_chirho.session_chirho.seq_chirho,
        "operator-cli-chirho",
        "operator-revoke-chirho",
    )
    .unwrap();
    assert_eq!(verify_session_revocations_chirho(&root_chirho).unwrap(), 1);

    let mut tampered_chirho = revocation_chirho.clone();
    tampered_chirho.reason_chirho = "different-reason-chirho".to_string();
    write_jsonl_chirho(
        &session_revocations_path_chirho(&root_chirho),
        &[tampered_chirho],
    );
    let error_chirho = verify_session_revocations_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("identity session revocation 0 signature invalid"));
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_chirho.token_chirho
    )
    .is_err());

    let mut missing_chirho = revocation_chirho.clone();
    missing_chirho.session_seq_chirho = 999;
    missing_chirho = resign_session_revocation_record_for_test_chirho(&root_chirho, missing_chirho);
    write_jsonl_chirho(
        &session_revocations_path_chirho(&root_chirho),
        &[missing_chirho],
    );
    let error_chirho = verify_session_revocations_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("references missing session 999"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn identity_records_are_schema_tagged_and_unknown_schemas_fail_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let login_chirho =
        login_identity_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();

    assert_eq!(identity_chirho.schema_chirho, IDENTITY_RECORD_SCHEMA_CHIRHO);
    assert_eq!(
        login_chirho.session_chirho.schema_chirho,
        IDENTITY_SESSION_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(verify_identities_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_sessions_chirho(&root_chirho).unwrap(), 1);

    let mut bad_identity_chirho = identity_chirho.clone();
    bad_identity_chirho.schema_chirho = "identity-record-v9-chirho".to_string();
    write_jsonl_chirho(
        &identities_path_chirho(&root_chirho),
        &[bad_identity_chirho],
    );
    let error_chirho = verify_identities_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported identity record schema"));
    write_jsonl_chirho(
        &identities_path_chirho(&root_chirho),
        std::slice::from_ref(&identity_chirho),
    );

    let mut bad_session_chirho = login_chirho.session_chirho.clone();
    bad_session_chirho.schema_chirho = "identity-session-record-v9-chirho".to_string();
    write_jsonl_chirho(&sessions_path_chirho(&root_chirho), &[bad_session_chirho]);
    let error_chirho = verify_sessions_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported identity session record schema"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_identity_records_without_schema_still_verify_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let login_chirho =
        login_identity_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();

    let mut identity_records_chirho = load_identities_chirho(&root_chirho).unwrap();
    for record_chirho in &mut identity_records_chirho {
        record_chirho.schema_chirho.clear();
        *record_chirho =
            resign_identity_record_for_test_chirho(&root_chirho, record_chirho.clone());
    }
    write_jsonl_chirho(
        &identities_path_chirho(&root_chirho),
        &identity_records_chirho,
    );

    let mut sessions_chirho = load_sessions_chirho(&root_chirho).unwrap();
    for session_chirho in &mut sessions_chirho {
        session_chirho.schema_chirho.clear();
        *session_chirho =
            resign_session_record_for_test_chirho(&root_chirho, session_chirho.clone());
    }
    write_jsonl_chirho(&sessions_path_chirho(&root_chirho), &sessions_chirho);

    for path_chirho in [
        identities_path_chirho(&root_chirho),
        sessions_path_chirho(&root_chirho),
    ] {
        assert!(!std::fs::read_to_string(path_chirho)
            .unwrap()
            .contains("schema_chirho"));
    }
    assert_eq!(verify_identities_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(verify_sessions_chirho(&root_chirho).unwrap(), 1);
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    assert!(load_identities_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));
    assert!(load_sessions_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|session_chirho| session_chirho.schema_chirho.is_empty()));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn parallel_identity_sessions_get_contiguous_signed_sequences_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let mut threads_chirho = Vec::new();
    for _ in 0..32 {
        let root_chirho = root_chirho.clone();
        let principal_chirho = identity_chirho.principal_chirho.clone();
        threads_chirho.push(thread::spawn(move || {
            login_identity_chirho(&root_chirho, &principal_chirho).unwrap();
        }));
    }
    for thread_chirho in threads_chirho {
        thread_chirho.join().unwrap();
    }
    let sessions_chirho = load_sessions_chirho(&root_chirho).unwrap();
    assert_eq!(sessions_chirho.len(), 32);
    for (i_chirho, session_chirho) in sessions_chirho.iter().enumerate() {
        assert_eq!(session_chirho.seq_chirho, i_chirho as u64);
    }
    assert_eq!(verify_sessions_chirho(&root_chirho).unwrap(), 32);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn register_owner_uses_owner_namespace_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho).unwrap();
    assert!(identity_chirho.principal_chirho.starts_with("owner/"));
    assert!(!root_chirho.join("ledger-chirho.jsonl").exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn credential_login_requires_the_registered_secret_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "correct-horse-battery",
    )
    .unwrap();
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "wrong-horse"
    )
    .is_err());
    let login_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "correct-horse-battery",
    )
    .unwrap();
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn credential_set_adds_argon2id_to_existing_credentialless_identity_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho).unwrap();
    let before_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(before_chirho.credentialless_keys_chirho, 1);
    assert_eq!(before_chirho.argon2id_credentials_chirho, 0);

    set_identity_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "new-owner-secret",
    )
    .unwrap();

    let after_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(after_chirho.credentialless_keys_chirho, 0);
    assert_eq!(after_chirho.argon2id_credentials_chirho, 1);
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "wrong-owner-secret"
    )
    .is_err());
    let login_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "new-owner-secret",
    )
    .unwrap();
    assert!(validate_session_token_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        &login_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    assert_eq!(verify_identities_chirho(&root_chirho).unwrap(), 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn credential_set_rejects_existing_or_short_credentials_chirho() {
    let root_chirho = tmp_root_chirho();
    let credentialless_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho).unwrap();
    let credentialed_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::OwnerChirho,
        "existing-secret",
    )
    .unwrap();
    assert!(set_identity_credential_chirho(
        &root_chirho,
        &credentialless_chirho.principal_chirho,
        "short"
    )
    .unwrap_err()
    .to_string()
    .contains(IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO));
    assert!(set_identity_credential_chirho(
        &root_chirho,
        &credentialed_chirho.principal_chirho,
        "replacement-secret",
    )
    .unwrap_err()
    .to_string()
    .contains("already has an HTTP credential"));
    assert!(set_identity_credential_chirho(
        &root_chirho,
        "owner/missing-chirho",
        "missing-owner-secret",
    )
    .unwrap_err()
    .to_string()
    .contains("unknown principal"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn credentials_use_argon2id_and_legacy_blake3_still_verifies_chirho() {
    let root_chirho = tmp_root_chirho();
    let credential_chirho = "correct-horse-battery";
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap();
    let mut key_record_chirho =
        load_identity_key_record_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();
    let hash_chirho = key_record_chirho
        .credential_hash_chirho
        .as_deref()
        .expect("credential hash");
    assert!(hash_chirho.starts_with(CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO));
    assert!(!hash_chirho.contains(credential_chirho));
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        credential_chirho
    )
    .is_ok());

    let salt_chirho = key_record_chirho
        .credential_salt_chirho
        .as_deref()
        .expect("credential salt")
        .to_string();
    key_record_chirho.credential_hash_chirho = Some(legacy_credential_hash_blake3_chirho(
        &salt_chirho,
        credential_chirho,
    ));
    write_identity_key_record_chirho(&root_chirho, &key_record_chirho).unwrap();
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        credential_chirho
    )
    .is_ok());
    let upgraded_chirho =
        load_identity_key_record_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();
    assert!(upgraded_chirho
        .credential_hash_chirho
        .as_deref()
        .unwrap()
        .starts_with(CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO));
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        "wrong-horse"
    )
    .is_err());
    let mut bad_param_chirho = upgraded_chirho.clone();
    bad_param_chirho.credential_hash_chirho = Some(format!(
        "{CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO}$m999999999$t2$p1${}",
        "00".repeat(ARGON2_OUTPUT_LEN_CHIRHO)
    ));
    write_identity_key_record_chirho(&root_chirho, &bad_param_chirho).unwrap();
    let error_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        credential_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(error_chirho.contains("memory param exceeds supported bound"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn credential_inventory_reports_legacy_without_leaking_chirho() {
    let root_chirho = tmp_root_chirho();
    let credential_chirho = "m195-correct-horse";
    let secret_key_needle_chirho = "11".repeat(32);
    let email_principal_needle_chirho = "legacy-m195@example.com";
    let extra_principal_needle_chirho = "extra-m195@example.com";
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap();
    let owner_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho).unwrap();

    let mut key_record_chirho =
        load_identity_key_record_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();
    let salt_chirho = key_record_chirho
        .credential_salt_chirho
        .as_deref()
        .expect("credential salt")
        .to_string();
    key_record_chirho.credential_hash_chirho = Some(legacy_credential_hash_blake3_chirho(
        &salt_chirho,
        credential_chirho,
    ));
    write_identity_key_record_chirho(&root_chirho, &key_record_chirho).unwrap();

    write_identity_key_record_chirho(
        &root_chirho,
        &IdentityKeyChirho {
            principal_chirho: extra_principal_needle_chirho.to_string(),
            secret_key_chirho: secret_key_needle_chirho.clone(),
            credential_salt_chirho: Some("extra-salt-chirho".to_string()),
            credential_hash_chirho: Some("f".repeat(64)),
            credential_generation_chirho: 0,
            recovery_code_salt_chirho: None,
            recovery_code_hash_chirho: None,
            recovery_code_expires_ms_chirho: None,
        },
    )
    .unwrap();

    let inventory_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(
        inventory_chirho.schema_chirho,
        IDENTITY_CREDENTIAL_INVENTORY_SCHEMA_CHIRHO
    );
    assert_eq!(inventory_chirho.identity_records_chirho, 2);
    assert_eq!(inventory_chirho.key_files_chirho, 3);
    assert_eq!(inventory_chirho.argon2id_credentials_chirho, 0);
    assert_eq!(inventory_chirho.legacy_blake3_credentials_chirho, 1);
    assert_eq!(inventory_chirho.credentialless_keys_chirho, 1);
    assert_eq!(inventory_chirho.extra_key_files_chirho, 1);
    assert!(!inventory_chirho.legacy_rotation_ready_chirho);
    assert_eq!(inventory_chirho.legacy_principal_hashes_chirho.len(), 1);
    assert_eq!(inventory_chirho.extra_key_principal_hashes_chirho.len(), 1);

    let json_chirho = serde_json::to_string_pretty(&inventory_chirho).unwrap();
    assert!(!json_chirho.contains(credential_chirho));
    assert!(!json_chirho.contains(&identity_chirho.principal_chirho));
    assert!(!json_chirho.contains(&owner_chirho.principal_chirho));
    assert!(!json_chirho.contains(email_principal_needle_chirho));
    assert!(!json_chirho.contains(extra_principal_needle_chirho));
    assert!(!json_chirho.contains(&secret_key_needle_chirho));
    assert!(!json_chirho.contains(&salt_chirho));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn credential_inventory_is_ready_after_legacy_auto_upgrade_chirho() {
    let root_chirho = tmp_root_chirho();
    let credential_chirho = "m195-correct-horse";
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap();
    let mut key_record_chirho =
        load_identity_key_record_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();
    let salt_chirho = key_record_chirho
        .credential_salt_chirho
        .as_deref()
        .expect("credential salt")
        .to_string();
    key_record_chirho.credential_hash_chirho = Some(legacy_credential_hash_blake3_chirho(
        &salt_chirho,
        credential_chirho,
    ));
    write_identity_key_record_chirho(&root_chirho, &key_record_chirho).unwrap();

    let before_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(before_chirho.legacy_blake3_credentials_chirho, 1);
    assert_eq!(before_chirho.argon2id_credentials_chirho, 0);
    assert!(!before_chirho.legacy_rotation_ready_chirho);

    login_identity_with_credential_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        credential_chirho,
    )
    .unwrap();
    let after_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(after_chirho.legacy_blake3_credentials_chirho, 0);
    assert_eq!(after_chirho.argon2id_credentials_chirho, 1);
    assert_eq!(after_chirho.invalid_key_files_chirho, 0);
    assert_eq!(after_chirho.missing_key_files_chirho, 0);
    assert_eq!(after_chirho.extra_key_files_chirho, 0);
    assert!(after_chirho.legacy_rotation_ready_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn identity_registration_checks_key_dir_before_identity_append_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        identity_keys_dir_chirho(&root_chirho),
        b"blocked-key-dir-chirho",
    )
    .unwrap();

    let error_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "m208-registration-secret",
    )
    .unwrap_err()
    .to_string();
    assert!(!error_chirho.is_empty());
    assert_eq!(load_identities_chirho(&root_chirho).unwrap().len(), 0);
    assert!(!auth_attempts_path_chirho(&root_chirho).exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn public_auth_attempts_limit_verify_and_stay_secret_safe_chirho() {
    let root_chirho = tmp_root_chirho();
    let credential_chirho = "correct-horse-battery";
    let wrong_credential_chirho = "wrong-horse";
    let attempted_email_principal_chirho = "victim-m193@example.com";
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap();

    for _ in 0..2 {
        assert!(login_identity_with_public_auth_limit_chirho(
            &root_chirho,
            &identity_chirho.principal_chirho,
            wrong_credential_chirho,
            &SignInVelocityChirho::default()
        )
        .is_err());
    }
    assert!(login_identity_with_public_auth_limit_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        credential_chirho,
        &SignInVelocityChirho::default()
    )
    .is_ok());
    assert_eq!(verify_sessions_chirho(&root_chirho).unwrap(), 1);

    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
        assert!(login_identity_with_public_auth_limit_chirho(
            &root_chirho,
            &identity_chirho.principal_chirho,
            wrong_credential_chirho,
            &SignInVelocityChirho::default()
        )
        .is_err());
    }
    assert!(login_identity_with_public_auth_limit_chirho(
        &root_chirho,
        attempted_email_principal_chirho,
        wrong_credential_chirho,
        &SignInVelocityChirho::default()
    )
    .is_err());
    assert_eq!(
        verify_auth_attempts_chirho(&root_chirho).unwrap(),
        4 + PUBLIC_AUTH_MAX_FAILURES_CHIRHO as usize
    );
    let attempts_text_chirho =
        std::fs::read_to_string(auth_attempts_path_chirho(&root_chirho)).unwrap();
    assert!(!attempts_text_chirho.contains(credential_chirho));
    assert!(!attempts_text_chirho.contains(wrong_credential_chirho));
    assert!(!attempts_text_chirho.contains(attempted_email_principal_chirho));

    let mut key_record_chirho =
        load_identity_key_record_chirho(&root_chirho, &identity_chirho.principal_chirho).unwrap();
    key_record_chirho.credential_hash_chirho = Some(format!(
        "{CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO}$m999999999$t2$p1${}",
        "00".repeat(ARGON2_OUTPUT_LEN_CHIRHO)
    ));
    write_identity_key_record_chirho(&root_chirho, &key_record_chirho).unwrap();
    let limited_error_chirho = login_identity_with_public_auth_limit_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        credential_chirho,
        &SignInVelocityChirho::default(),
    )
    .unwrap_err();
    assert!(is_auth_rate_limit_error_chirho(&limited_error_chirho));
    assert!(limited_error_chirho
        .to_string()
        .contains("credential auth rate limit exceeded"));
    assert_eq!(verify_sessions_chirho(&root_chirho).unwrap(), 1);

    let mut attempts_chirho = load_auth_attempts_chirho(&root_chirho).unwrap();
    attempts_chirho[0].outcome_chirho = IdentityAuthAttemptOutcomeChirho::SuccessChirho;
    write_jsonl_chirho(&auth_attempts_path_chirho(&root_chirho), &attempts_chirho);
    let tamper_error_chirho = login_identity_with_public_auth_limit_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
        credential_chirho,
        &SignInVelocityChirho::default(),
    )
    .unwrap_err()
    .to_string();
    assert!(tamper_error_chirho.contains("identity auth attempt 0 signature invalid"));
    assert_eq!(load_sessions_chirho(&root_chirho).unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn auth_hash_comparisons_stay_constant_time_chirho() {
    let root_chirho = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for path_chirho in [
        "src/edge_flows_chirho/identity_chirho.rs",
        "src/edge_flows_chirho/oauth_chirho.rs",
    ] {
        let source_chirho = std::fs::read_to_string(root_chirho.join(path_chirho)).unwrap();
        for needle_chirho in [
            format!(
                "{} {} {}",
                "actual_hash_chirho", "!=", "expected_hash_chirho"
            ),
            format!(
                "{} {} {}",
                "token_hash_chirho", "!=", "expected_token_hash_chirho"
            ),
            format!(
                "{} {} {}",
                "token_hash_chirho", "!=", "expected_hash_chirho"
            ),
            format!(
                "{} {} {}",
                "token_hash_chirho", "!=", "token_chirho.token_hash_chirho"
            ),
        ] {
            assert!(
                !source_chirho.contains(&needle_chirho),
                "{path_chirho} must use constant_time_string_eq_chirho for auth hash compares: {needle_chirho}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn identity_key_file_is_private_chirho() {
    use std::os::unix::fs::PermissionsExt;

    let root_chirho = tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let dir_mode_chirho = std::fs::metadata(identity_keys_dir_chirho(&root_chirho))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let key_mode_chirho = std::fs::metadata(identity_key_path_chirho(
        &root_chirho,
        &identity_chirho.principal_chirho,
    ))
    .unwrap()
    .permissions()
    .mode()
        & 0o777;
    assert_eq!(dir_mode_chirho, 0o700);
    assert_eq!(key_mode_chirho, 0o600);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// #6048/#6049 mutation: a tampered record SIGNATURE (schema/principal/count preserved) must
/// refuse through the ONE verified loader — the raw loader would false-PASS this.
#[test]
fn load_verified_identities_refuses_signature_tamper_chirho() {
    let root_chirho = tmp_root_chirho();
    let record_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    assert_eq!(
        load_verified_identities_chirho(&root_chirho).unwrap().len(),
        1
    );

    let path_chirho = identities_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let sig_chirho = &record_chirho.sig_chirho;
    let flipped_first_chirho = if sig_chirho.starts_with('0') {
        "1"
    } else {
        "0"
    };
    let tampered_sig_chirho = format!("{flipped_first_chirho}{}", &sig_chirho[1..]);
    let tampered_chirho = text_chirho.replace(sig_chirho.as_str(), tampered_sig_chirho.as_str());
    assert_ne!(text_chirho, tampered_chirho);
    std::fs::write(&path_chirho, tampered_chirho).unwrap();

    // The RAW loader still parses (the false-green the verified loader exists to close)...
    assert_eq!(load_identities_chirho(&root_chirho).unwrap().len(), 1);
    // ...while the verified loader refuses on the flipped signature.
    let error_chirho = load_verified_identities_chirho(&root_chirho).unwrap_err();
    assert!(error_chirho.to_string().contains("signature invalid"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_session_carrying_a_superseded_generation_is_unusable_even_when_the_reset_never_revoked_it_chirho(
) {
    // The login-generation race (gpt #22338 / claude2 #22339): login takes no credential lock, so
    // it can append its session AFTER a reset's revocation enumeration — that session is NOT
    // revoked. The fix binds the session's generation to the PROVED snapshot (a single read; there
    // is no second load that a racing reset could bump), so such a session carries the OLD
    // generation and validation rejects it. This reconstructs the raced artifact deterministically
    // and shows the discriminator's "unusable session" outcome; the negative control shows the hole
    // the fix closes (a session stamped with the POST-reset generation would validate). It pins
    // ONLY that validation rejects a stale generation — that login binds to the proved generation
    // is a single-variable data-flow fact in login_identity_internal_chirho, established by
    // reading, not by this arm.
    let root_chirho = tmp_root_chirho();
    let user_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = user_chirho.principal_chirho;
    let login_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    assert!(
        validate_session_token_chirho(&root_chirho, &principal_chirho, &login_chirho.token_chirho)
            .unwrap()
            .is_some(),
        "positive control: the session is live at its own generation before the reset"
    );

    // A reset bumps the key generation (0 -> 1) and revokes the pre-reset session.
    reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
        &principal_chirho,
        "test-generation-race-reset-chirho",
    )
    .unwrap();

    // Reconstruct the RACED session: appended after the reset's enumeration (so UNREVOKED), with a
    // fresh token, live expiry, and a valid signature — the only thing that can reject it is its
    // generation. The fix stamps it with the PROVED generation (0).
    let raced_token_chirho = "raced-after-reset-token-value";
    let mut sessions_chirho = load_sessions_chirho(&root_chirho).unwrap();
    let mut raced_chirho = login_chirho.session_chirho.clone();
    raced_chirho.seq_chirho = sessions_chirho.len() as u64;
    raced_chirho.token_hash_chirho = token_hash_chirho(raced_token_chirho);
    raced_chirho.credential_generation_chirho = 0;
    raced_chirho.issued_ms_chirho = now_ms_chirho();
    raced_chirho.expires_ms_chirho = now_ms_chirho() + 60_000;
    raced_chirho = resign_session_record_for_test_chirho(&root_chirho, raced_chirho);
    sessions_chirho.push(raced_chirho);
    write_jsonl_chirho(&sessions_path_chirho(&root_chirho), &sessions_chirho);
    assert!(
        validate_session_token_chirho(&root_chirho, &principal_chirho, raced_token_chirho)
            .unwrap()
            .is_none(),
        "a live, unrevoked, correctly signed session with a superseded generation is unusable"
    );

    // The hole the fix closes: the SAME session stamped with the POST-reset generation (1) — what
    // a second load after the reset produced (the R1 defect) — validates. So the generation VALUE
    // is decisive, and binding it to the proved snapshot is what makes the raced session unusable.
    let mut sessions_chirho = load_sessions_chirho(&root_chirho).unwrap();
    for session_chirho in &mut sessions_chirho {
        if session_chirho.token_hash_chirho == token_hash_chirho(raced_token_chirho) {
            session_chirho.credential_generation_chirho = 1;
            *session_chirho =
                resign_session_record_for_test_chirho(&root_chirho, session_chirho.clone());
        }
    }
    write_jsonl_chirho(&sessions_path_chirho(&root_chirho), &sessions_chirho);
    assert!(
        validate_session_token_chirho(&root_chirho, &principal_chirho, raced_token_chirho)
            .unwrap()
            .is_some(),
        "negative control: the identical session at the current generation is otherwise valid"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn login_and_reset_compose_without_deadlock_and_login_refuses_the_old_credential_chirho() {
    // A concurrency-composition smoke test, NOT the serialization proof (gpt, relayed #22350): login
    // now takes the principal credential lock that reset also takes, so this confirms the two do not
    // DEADLOCK under contention and that a login which runs against a completed reset refuses the old
    // credential. It does NOT reliably exercise the interleaving — a worker first scheduled after the
    // reset releases the lock passes without racing anything — so it is not evidence that the lock
    // serialized a concurrent attempt. The SERIALIZATION itself is structural: login and reset take
    // the same named lock (`credential_lock_name_chirho`), so mutual exclusion is the lock's
    // contract, verified by reading both call sites. The generation-check fail-safe is proven
    // behaviorally by `a_session_carrying_a_superseded_generation_is_unusable_...` above.
    let root_chirho = tmp_root_chirho();
    let user_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = user_chirho.principal_chirho;

    let handle_chirho = seqlog_chirho::with_named_lock_chirho(
        &root_chirho,
        &credential_lock_name_chirho(&principal_chirho),
        || {
            let root_for_thread_chirho = root_chirho.clone();
            let principal_for_thread_chirho = principal_chirho.clone();
            // Spawned INSIDE the held lock, so the login always blocks before its proof.
            let handle_chirho = std::thread::spawn(move || {
                login_identity_with_credential_chirho(
                    &root_for_thread_chirho,
                    &principal_for_thread_chirho,
                    "first-secret-value",
                )
            });
            reset_identity_credential_locked_chirho(
                &root_chirho,
                &principal_chirho,
                "second-secret-value",
                &principal_chirho,
                "test-login-race-reset-chirho",
                CredentialReplacementCauseChirho::OperatorResetChirho,
            )?;
            Ok::<_, anyhow::Error>(handle_chirho)
        },
    )
    .unwrap();

    let raced_login_chirho = handle_chirho.join().unwrap();
    assert!(
        raced_login_chirho.is_err(),
        "a login racing a reset proves the old credential against the reset record and refuses"
    );
    assert!(
        login_identity_with_credential_chirho(
            &root_chirho,
            &principal_chirho,
            "first-secret-value"
        )
        .is_err(),
        "the old credential no longer logs in after the reset"
    );
    assert!(
        login_identity_with_credential_chirho(
            &root_chirho,
            &principal_chirho,
            "second-secret-value"
        )
        .is_ok(),
        "the new credential logs in"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[path = "public_auth_refusal_tests_chirho.rs"]
mod public_auth_refusal_tests_chirho;
#[path = "sign_in_velocity_tests_chirho.rs"]
mod sign_in_velocity_tests_chirho;
