// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Arms for the operator credential reset: what a reset must refuse, revoke, replace, and record.
//!
//! Each arm names the refusal or effect it pins, and the migration path if it reds: a reset that
//! stops revoking would leave the "prior session refused" arm red — that is a regression, not a
//! retarget; a reset that starts accepting a credentialless principal reds the identity arm — the
//! two commands were kept disjoint on purpose.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn reset_tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-credential-reset-test-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

fn refusal_of_chirho(error_chirho: &anyhow::Error) -> Option<IdentityCredentialResetRefusalChirho> {
    error_chirho
        .downcast_ref::<IdentityCredentialResetRefusalChirho>()
        .cloned()
}

#[test]
fn reset_revokes_live_sessions_then_replaces_the_credential_and_records_it_chirho() {
    let root_chirho = reset_tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    // Two live sessions under the old credential, one of them already revoked by the operator.
    let session_a_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    let session_b_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    revoke_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &session_b_chirho.token_chirho,
        "operator-cli-chirho",
        "pre-reset-revoke-chirho",
    )
    .unwrap();
    assert!(
        validate_session_token_chirho(
            &root_chirho,
            &principal_chirho,
            &session_a_chirho.token_chirho
        )
        .unwrap()
        .is_some(),
        "positive control: session A is live before the reset"
    );

    let report_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
        "operator-cli-chirho",
        "invitee-lost-password-chirho",
    )
    .unwrap();

    // Revocation: exactly the ONE session that was still live is revoked by the reset.
    assert_eq!(
        report_chirho.revoked_session_seqs_chirho,
        vec![session_a_chirho.session_chirho.seq_chirho]
    );
    assert_eq!(report_chirho.record_chirho.revoked_session_count_chirho, 1);
    assert!(
        validate_session_token_chirho(
            &root_chirho,
            &principal_chirho,
            &session_a_chirho.token_chirho
        )
        .unwrap()
        .is_none(),
        "the prior session must be refused after the reset"
    );
    let reset_revocations_chirho = load_session_revocations_chirho(&root_chirho)
        .unwrap()
        .into_iter()
        .filter(|revocation_chirho| {
            revocation_chirho.reason_chirho == CREDENTIAL_RESET_SESSION_REVOCATION_REASON_CHIRHO
        })
        .count();
    assert_eq!(
        reset_revocations_chirho, 1,
        "one signed revocation carries the reset reason"
    );
    assert_eq!(verify_session_revocations_chirho(&root_chirho).unwrap(), 2);

    // Replacement: the old credential is refused, the new one is accepted, and the new session
    // is live -- the reset revoked the past, not the future.
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value"
    )
    .is_err());
    let session_c_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
    )
    .unwrap();
    assert!(validate_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &session_c_chirho.token_chirho
    )
    .unwrap()
    .is_some());

    // Record: signed, verified, schema-tagged, and carrying nothing that authenticates.
    assert_eq!(verify_credential_resets_chirho(&root_chirho).unwrap(), 1);
    let records_chirho = load_credential_resets_chirho(&root_chirho).unwrap();
    assert_eq!(records_chirho.len(), 1);
    assert_eq!(records_chirho[0], report_chirho.record_chirho);
    assert_eq!(
        records_chirho[0].schema_chirho,
        IDENTITY_CREDENTIAL_RESET_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(
        records_chirho[0].reason_chirho,
        "invitee-lost-password-chirho"
    );
    let log_text_chirho =
        std::fs::read_to_string(root_chirho.join("identity-credential-resets-chirho.jsonl"))
            .unwrap();
    for needle_chirho in ["first-secret-value", "second-secret-value"] {
        assert!(
            !log_text_chirho.contains(needle_chirho),
            "the reset log must not carry a credential value"
        );
    }
    let key_text_chirho =
        std::fs::read_to_string(identity_key_path_chirho(&root_chirho, &principal_chirho)).unwrap();
    let key_record_chirho: serde_json::Value = serde_json::from_str(&key_text_chirho).unwrap();
    let stored_hash_chirho = key_record_chirho["credential_hash_chirho"]
        .as_str()
        .unwrap();
    assert!(
        !log_text_chirho.contains(stored_hash_chirho),
        "the reset log must not carry the stored credential hash either; it carries a digest of it"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reset_refuses_a_credentialless_principal_by_its_own_identity_and_changes_nothing_chirho() {
    let root_chirho = reset_tmp_root_chirho();
    let identity_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    let key_before_chirho =
        std::fs::read(identity_key_path_chirho(&root_chirho, &principal_chirho)).unwrap();
    let error_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "replacement-secret",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap_err();
    assert_eq!(
        refusal_of_chirho(&error_chirho),
        Some(IdentityCredentialResetRefusalChirho::CredentiallessPrincipalChirho),
        "the refusal must be the credentialless identity, not unknown-principal: {error_chirho}"
    );
    assert!(error_chirho.to_string().contains("identity-credential-set"));
    let key_after_chirho =
        std::fs::read(identity_key_path_chirho(&root_chirho, &principal_chirho)).unwrap();
    assert_eq!(
        key_before_chirho, key_after_chirho,
        "a refused reset leaves the key record untouched"
    );
    assert!(load_credential_resets_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    // And the set road still works for exactly this principal, so the two commands are disjoint.
    set_identity_credential_chirho(&root_chirho, &principal_chirho, "replacement-secret").unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reset_refuses_an_unknown_principal_and_a_short_credential_before_revoking_anything_chirho() {
    let root_chirho = reset_tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    let session_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();

    let unknown_chirho = reset_identity_credential_chirho(
        &root_chirho,
        "user/0000000000000000",
        "replacement-secret",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap_err();
    assert_eq!(
        refusal_of_chirho(&unknown_chirho),
        Some(IdentityCredentialResetRefusalChirho::UnknownPrincipalChirho)
    );

    let short_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "short",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap_err();
    assert_eq!(
        refusal_of_chirho(&short_chirho),
        Some(IdentityCredentialResetRefusalChirho::CredentialBelowFloorChirho)
    );

    // Neither refusal revoked the live session or replaced the credential.
    assert!(validate_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &session_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    assert!(load_session_revocations_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value"
    )
    .is_ok());
    assert!(load_credential_resets_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reset_fails_closed_on_a_tampered_identity_log_before_touching_sessions_or_keys_chirho() {
    let root_chirho = reset_tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    let session_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    // Tamper: append a well-formed but unsigned identity row. The verified loader must refuse
    // the whole log, and the reset must refuse with it, having done nothing.
    let log_path_chirho = root_chirho.join("identities-chirho.jsonl");
    let mut forged_chirho = identity_chirho.clone();
    forged_chirho.seq_chirho += 1;
    forged_chirho.principal_chirho = "user/ffffffffffffffff".to_string();
    forged_chirho.sig_chirho = "00".repeat(64);
    let mut text_chirho = std::fs::read_to_string(&log_path_chirho).unwrap();
    text_chirho.push_str(&serde_json::to_string(&forged_chirho).unwrap());
    text_chirho.push('\n');
    std::fs::write(&log_path_chirho, text_chirho).unwrap();
    let key_before_chirho =
        std::fs::read(identity_key_path_chirho(&root_chirho, &principal_chirho)).unwrap();

    let error_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "replacement-secret",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap_err();
    assert!(
        error_chirho.to_string().contains("signature invalid"),
        "the refusal must be the identity-log verification failure, got: {error_chirho}"
    );
    assert_eq!(
        refusal_of_chirho(&error_chirho),
        None,
        "not one of the typed reset refusals"
    );
    assert_eq!(
        key_before_chirho,
        std::fs::read(identity_key_path_chirho(&root_chirho, &principal_chirho)).unwrap()
    );
    assert!(load_session_revocations_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(load_credential_resets_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    // The session is still live: nothing was revoked on a log nobody could verify.
    let _ = session_chirho;
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reset_record_verification_refuses_a_tampered_or_reordered_log_chirho() {
    let root_chirho = reset_tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    for credential_chirho in ["second-secret-value", "third-secret-value"] {
        reset_identity_credential_chirho(
            &root_chirho,
            &principal_chirho,
            credential_chirho,
            "operator-cli-chirho",
            "operator-reset-chirho",
        )
        .unwrap();
    }
    assert_eq!(verify_credential_resets_chirho(&root_chirho).unwrap(), 2);
    let path_chirho = root_chirho.join("identity-credential-resets-chirho.jsonl");
    let original_chirho = std::fs::read_to_string(&path_chirho).unwrap();

    // Tamper the count in the second record: the signature no longer covers the bytes.
    let tampered_chirho = original_chirho.replacen(
        "\"revoked_session_count_chirho\":0",
        "\"revoked_session_count_chirho\":7",
        2,
    );
    assert_ne!(
        tampered_chirho, original_chirho,
        "the plant must change the bytes"
    );
    std::fs::write(&path_chirho, &tampered_chirho).unwrap();
    assert!(verify_credential_resets_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("signature invalid"));

    // Reorder: drop the first record so seqs are no longer dense from zero.
    let mut lines_chirho: Vec<&str> = original_chirho.lines().collect();
    lines_chirho.remove(0);
    std::fs::write(&path_chirho, format!("{}\n", lines_chirho.join("\n"))).unwrap();
    assert!(verify_credential_resets_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("seq gap"));

    std::fs::write(&path_chirho, &original_chirho).unwrap();
    assert_eq!(
        verify_credential_resets_chirho(&root_chirho).unwrap(),
        2,
        "restore control"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn session_listing_reports_live_expired_and_revoked_from_verified_records_only_chirho() {
    let root_chirho = reset_tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    let other_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let live_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    let revoked_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    revoke_session_token_chirho(
        &root_chirho,
        &principal_chirho,
        &revoked_chirho.token_chirho,
        "operator-cli-chirho",
        "operator-revoke-chirho",
    )
    .unwrap();
    // A session of ANOTHER principal must not appear in this principal's listing.
    login_identity_chirho(&root_chirho, &other_chirho.principal_chirho).unwrap();

    let rows_chirho = list_principal_sessions_chirho(&root_chirho, &principal_chirho).unwrap();
    assert_eq!(rows_chirho.len(), 2);
    assert_eq!(
        rows_chirho[0].seq_chirho,
        live_chirho.session_chirho.seq_chirho
    );
    assert_eq!(
        rows_chirho[0].state_chirho,
        IdentitySessionStateChirho::LiveChirho
    );
    assert_eq!(
        rows_chirho[1].seq_chirho,
        revoked_chirho.session_chirho.seq_chirho
    );
    assert_eq!(
        rows_chirho[1].state_chirho,
        IdentitySessionStateChirho::RevokedChirho
    );

    // A reset flips the live row to revoked without touching the count.
    reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap();
    let rows_chirho = list_principal_sessions_chirho(&root_chirho, &principal_chirho).unwrap();
    assert_eq!(rows_chirho.len(), 2);
    assert!(rows_chirho
        .iter()
        .all(|row_chirho| row_chirho.state_chirho == IdentitySessionStateChirho::RevokedChirho));

    // A tampered session row fails the listing closed rather than being shown or skipped.
    let path_chirho = root_chirho.join("identity-sessions-chirho.jsonl");
    let original_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let tampered_chirho =
        original_chirho.replacen("\"expires_ms_chirho\":", "\"expires_ms_chirho\":9", 1);
    assert_ne!(
        tampered_chirho, original_chirho,
        "the plant must change the bytes"
    );
    std::fs::write(&path_chirho, &tampered_chirho).unwrap();
    assert!(list_principal_sessions_chirho(&root_chirho, &principal_chirho).is_err());
    std::fs::write(&path_chirho, &original_chirho).unwrap();
    assert_eq!(
        list_principal_sessions_chirho(&root_chirho, &principal_chirho)
            .unwrap()
            .len(),
        2,
        "restore control"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn listing_and_reset_fail_closed_on_a_row_whose_principal_field_was_tampered_chirho() {
    // F1 shape: a row routed on an UNVERIFIED principal field would be silently excluded from both
    // principals' views. Both consumers must verify before they route.
    let root_chirho = reset_tmp_root_chirho();
    let victim_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let bystander_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let live_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &victim_chirho.principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    let path_chirho = root_chirho.join("identity-sessions-chirho.jsonl");
    let original_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let tampered_chirho = original_chirho.replacen(
        &format!(
            "\"principal_chirho\":\"{}\"",
            victim_chirho.principal_chirho
        ),
        &format!(
            "\"principal_chirho\":\"{}\"",
            bystander_chirho.principal_chirho
        ),
        1,
    );
    assert_ne!(
        tampered_chirho, original_chirho,
        "the plant must change the bytes"
    );
    std::fs::write(&path_chirho, &tampered_chirho).unwrap();

    // Listing for EITHER principal refuses; neither silently shows or hides the row.
    assert!(list_principal_sessions_chirho(&root_chirho, &victim_chirho.principal_chirho).is_err());
    assert!(
        list_principal_sessions_chirho(&root_chirho, &bystander_chirho.principal_chirho).is_err()
    );
    // The reset refuses too, before touching anything.
    let error_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &victim_chirho.principal_chirho,
        "second-secret-value",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap_err();
    assert!(
        error_chirho.to_string().contains("signature invalid")
            || error_chirho.to_string().contains("session"),
        "expected the session-log verification refusal, got: {error_chirho}"
    );
    assert!(load_session_revocations_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(load_credential_resets_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &victim_chirho.principal_chirho,
        "first-secret-value"
    )
    .is_ok());

    std::fs::write(&path_chirho, &original_chirho).unwrap();
    let rows_chirho =
        list_principal_sessions_chirho(&root_chirho, &victim_chirho.principal_chirho).unwrap();
    assert_eq!(rows_chirho.len(), 1, "restore control");
    assert_eq!(
        rows_chirho[0].seq_chirho,
        live_chirho.session_chirho.seq_chirho
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn reset_does_not_trust_a_forged_revocation_row_to_skip_a_live_session_chirho() {
    // F3 shape: an unsigned revocation row that names a live session must not make the reset skip
    // that session. The verified load refuses the log; the reset refuses with it.
    let root_chirho = reset_tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    let live_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    let forged_chirho = IdentitySessionRevocationRecordChirho {
        seq_chirho: 0,
        schema_chirho: String::new(),
        principal_chirho: principal_chirho.clone(),
        session_seq_chirho: live_chirho.session_chirho.seq_chirho,
        token_hash_chirho: live_chirho.session_chirho.token_hash_chirho.clone(),
        actor_chirho: "forger-chirho".to_string(),
        reason_chirho: "forged-chirho".to_string(),
        at_ms_chirho: 1,
        sig_chirho: "00".repeat(64),
    };
    let path_chirho = root_chirho.join("identity-session-revocations-chirho.jsonl");
    std::fs::write(
        &path_chirho,
        format!("{}\n", serde_json::to_string(&forged_chirho).unwrap()),
    )
    .unwrap();

    let error_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap_err();
    assert!(
        error_chirho.to_string().contains("signature invalid")
            || error_chirho.to_string().contains("revocation"),
        "expected the revocation-log verification refusal, got: {error_chirho}"
    );
    // Nothing replaced: the old credential still logs in, no reset record exists.
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value"
    )
    .is_ok());
    assert!(load_credential_resets_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    // Same forged log, the listing refuses rather than showing the session as revoked.
    assert!(list_principal_sessions_chirho(&root_chirho, &principal_chirho).is_err());
    std::fs::remove_file(&path_chirho).unwrap();
    assert_eq!(
        list_principal_sessions_chirho(&root_chirho, &principal_chirho).unwrap()[0].state_chirho,
        IdentitySessionStateChirho::LiveChirho,
        "restore control"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[cfg(unix)]
#[test]
fn reset_revokes_before_it_replaces_measured_by_obstructing_the_key_write_chirho() {
    // Denying sibling creation stops the atomic key write before rename. Revocations must already
    // be recorded while the prior complete key remains usable. This does not cover later sync errors
    // or an interruption inside the revocation loop.
    let mut fixture_chirho = super::key_write_tests_chirho::KeyWriteRootChirho::new_chirho();
    let root_chirho = fixture_chirho.path_chirho.clone();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        "first-secret-value",
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.clone();
    let live_chirho = login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value",
    )
    .unwrap();
    let key_path_chirho = identity_key_path_chirho(&root_chirho, &principal_chirho);
    let key_before_chirho = std::fs::read(&key_path_chirho).unwrap();
    fixture_chirho.obstruct_key_directory_chirho();

    let result_chirho = reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
        "operator-cli-chirho",
        "operator-reset-chirho",
    );
    fixture_chirho.restore_key_directory_chirho().unwrap();
    let error_chirho = result_chirho.expect_err(
        "reset succeeded despite the sibling-creation obstruction: check the writer and retarget \
         the failure fixture without relaxing the revoke-before-replace assertion",
    );
    assert_eq!(
        error_chirho
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::PermissionDenied),
        "the refusal must be the obstructed key write, got: {error_chirho}"
    );
    // Revoke-first: the interruption left the live session ALREADY revoked ...
    assert!(
        validate_session_token_chirho(&root_chirho, &principal_chirho, &live_chirho.token_chirho)
            .unwrap()
            .is_none(),
        "revoke-before-replace: the live session must be revoked even though the write failed"
    );
    assert_eq!(verify_session_revocations_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(std::fs::read(&key_path_chirho).unwrap(), key_before_chirho);
    // ... the old credential is still in force (nothing replaced), and no reset record exists.
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value"
    )
    .is_ok());
    assert!(load_credential_resets_chirho(&root_chirho)
        .unwrap()
        .is_empty());

    // Removing the obstruction permits the same reset and preserves signed-log verification.
    reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value",
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap();
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "second-secret-value"
    )
    .is_ok());
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        "first-secret-value"
    )
    .is_err());
    assert_eq!(verify_credential_resets_chirho(&root_chirho).unwrap(), 1);
}

#[test]
fn credential_floor_message_states_the_shared_floor_number_chirho() {
    // F6: the number is shared, but the message carries its own copy of it. Raising the floor
    // without this guard would refuse a remote user's 8-character credential while telling them
    // "at least 8". The two must not drift.
    assert!(
        IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO
            .contains(&IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO.to_string()),
        "the floor message must state the shared floor: {IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO} vs {IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO}"
    );
    assert!(!credential_meets_floor_chirho(
        &"x".repeat(IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO - 1)
    ));
    assert!(credential_meets_floor_chirho(
        &"x".repeat(IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO)
    ));
    assert!(
        !credential_meets_floor_chirho(&format!(
            " {} ",
            "x".repeat(IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO - 1)
        )),
        "the floor counts trimmed characters, as every site did before it was shared"
    );
}
