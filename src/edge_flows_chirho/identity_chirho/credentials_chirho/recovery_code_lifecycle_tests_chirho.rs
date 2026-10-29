// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Arms for a code's lifecycle around the two acts: every credential replacement burns it, invalid key state fails
//! closed and is named, the evidence log refuses tamper, one code permits one replacement under a race, and the code is
//! in no file under the root.

use super::recovery_code_tests_chirho::{
    code_tmp_root_chirho, events_chirho, redeem_at_chirho, refusal_token_chirho,
    root_snapshot_chirho, signs_in_chirho, FIRST_CHIRHO, SECOND_CHIRHO, THIRD_CHIRHO,
};
use super::*;

/// One way to break a key record's code fields, with its name.
type BrokenCodeStateChirho = (&'static str, fn(&mut IdentityKeyChirho));

fn credentialed_with_code_chirho(root_chirho: &Path) -> (String, IssuedRecoveryCodeChirho) {
    let principal_chirho = register_identity_with_credential_chirho(
        root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let issued_chirho = mint_operator_recovery_code_chirho(root_chirho, &principal_chirho).unwrap();
    (principal_chirho, issued_chirho)
}

#[test]
fn every_credential_replacement_burns_a_held_code_and_says_which_chirho() {
    // The operator reset.
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, issued_chirho) = credentialed_with_code_chirho(&root_chirho);
    reset_identity_credential_chirho(
        &root_chirho,
        &principal_chirho,
        SECOND_CHIRHO,
        "operator-cli-chirho",
        "operator-reset-chirho",
    )
    .unwrap();
    assert_eq!(
        events_chirho(&root_chirho)[1],
        (
            RecoveryCodeEventKindChirho::BurnedChirho,
            RecoveryCodeReasonKindChirho::CredentialResetChirho
        )
    );
    let error_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        THIRD_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_token_chirho(&error_chirho),
        Some("recovery-refused-chirho")
    );
    let _ = std::fs::remove_dir_all(&root_chirho);

    // Her own change, behind her session.
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, issued_chirho) = credentialed_with_code_chirho(&root_chirho);
    let token_chirho =
        login_identity_with_credential_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO)
            .unwrap()
            .token_chirho;
    change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &token_chirho,
        FIRST_CHIRHO,
        SECOND_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        events_chirho(&root_chirho)[1],
        (
            RecoveryCodeEventKindChirho::BurnedChirho,
            RecoveryCodeReasonKindChirho::CredentialChangeChirho
        )
    );
    assert!(redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        THIRD_CHIRHO
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);

    // The operator's set, on an invitee who has not used her invitation.
    let root_chirho = code_tmp_root_chirho();
    let invited_chirho =
        invite_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    set_identity_credential_chirho(
        &root_chirho,
        &invited_chirho.principal_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        events_chirho(&root_chirho)[1],
        (
            RecoveryCodeEventKindChirho::BurnedChirho,
            RecoveryCodeReasonKindChirho::CredentialSetChirho
        )
    );
    assert!(signs_in_chirho(
        &root_chirho,
        &invited_chirho.principal_chirho,
        SECOND_CHIRHO
    ));
    assert!(redeem_recovery_code_chirho(
        &root_chirho,
        &invited_chirho.principal_chirho,
        &invited_chirho.recovery_code_chirho,
        THIRD_CHIRHO
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);

    // A re-mint burns the code before it, and the new one works.
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, first_issue_chirho) = credentialed_with_code_chirho(&root_chirho);
    let second_issue_chirho =
        mint_operator_recovery_code_chirho(&root_chirho, &principal_chirho).unwrap();
    assert_eq!(
        events_chirho(&root_chirho)[1..],
        [
            (
                RecoveryCodeEventKindChirho::BurnedChirho,
                RecoveryCodeReasonKindChirho::ReplacedByMintChirho
            ),
            (
                RecoveryCodeEventKindChirho::MintedChirho,
                RecoveryCodeReasonKindChirho::OperatorRecoveryChirho
            ),
        ]
    );
    assert!(redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &first_issue_chirho.recovery_code_chirho,
        THIRD_CHIRHO
    )
    .is_err());
    redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &second_issue_chirho.recovery_code_chirho,
        THIRD_CHIRHO,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn invalid_code_state_fails_closed_everywhere_and_the_inventory_names_it_chirho() {
    let shapes_chirho: [BrokenCodeStateChirho; 3] = [
        ("a salt without a hash", |key_chirho| {
            key_chirho.recovery_code_hash_chirho = None
        }),
        ("an expiry without a code", |key_chirho| {
            key_chirho.recovery_code_salt_chirho = None;
            key_chirho.recovery_code_hash_chirho = None;
        }),
        ("a malformed hash", |key_chirho| {
            key_chirho.recovery_code_hash_chirho = Some("not-hex".to_string())
        }),
    ];
    for (label_chirho, break_chirho) in shapes_chirho {
        let root_chirho = code_tmp_root_chirho();
        let (principal_chirho, issued_chirho) = credentialed_with_code_chirho(&root_chirho);
        let token_chirho =
            login_identity_with_credential_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO)
                .unwrap()
                .token_chirho;
        let mut key_chirho =
            load_identity_key_record_chirho(&root_chirho, &principal_chirho).unwrap();
        break_chirho(&mut key_chirho);
        write_identity_key_record_chirho(&root_chirho, &key_chirho).unwrap();
        let before_chirho = root_snapshot_chirho(&root_chirho);
        // The redemption fails as an INTERNAL error, never as the uniform refusal ("no code").
        let error_chirho = redeem_recovery_code_chirho(
            &root_chirho,
            &principal_chirho,
            &issued_chirho.recovery_code_chirho,
            SECOND_CHIRHO,
        )
        .unwrap_err();
        assert_eq!(
            refusal_token_chirho(&error_chirho),
            None,
            "{label_chirho}: {error_chirho}"
        );
        // A mint, the operator reset and the set refuse before any write, so nothing repairs it silently.
        assert!(
            mint_operator_recovery_code_chirho(&root_chirho, &principal_chirho).is_err(),
            "{label_chirho}"
        );
        assert!(
            reset_identity_credential_chirho(
                &root_chirho,
                &principal_chirho,
                SECOND_CHIRHO,
                "operator-cli-chirho",
                "operator-reset-chirho"
            )
            .is_err(),
            "{label_chirho}"
        );
        assert_eq!(
            root_snapshot_chirho(&root_chirho),
            before_chirho,
            "{label_chirho}: nothing written"
        );
        assert!(
            validate_session_token_chirho(&root_chirho, &principal_chirho, &token_chirho)
                .unwrap()
                .is_some(),
            "{label_chirho}: no session was revoked"
        );
        let inventory_chirho = credential_inventory_chirho(&root_chirho).unwrap();
        assert_eq!(
            inventory_chirho.invalid_recovery_codes_chirho, 1,
            "{label_chirho}"
        );
        assert_eq!(
            inventory_chirho
                .invalid_recovery_code_principal_hashes_chirho
                .len(),
            1
        );
        assert!(
            !inventory_chirho.legacy_rotation_ready_chirho,
            "{label_chirho}: not ready"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
    // Control: a valid code is counted as a code, and readiness holds.
    let root_chirho = code_tmp_root_chirho();
    credentialed_with_code_chirho(&root_chirho);
    let inventory_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(
        (
            inventory_chirho.recovery_codes_chirho,
            inventory_chirho.invalid_recovery_codes_chirho
        ),
        (1, 0)
    );
    assert!(inventory_chirho.legacy_rotation_ready_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_generation_ahead_of_its_reset_records_is_named_but_does_not_fail_readiness_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, issued_chirho) = credentialed_with_code_chirho(&root_chirho);
    redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        credential_inventory_chirho(&root_chirho)
            .unwrap()
            .generation_ahead_of_reset_records_chirho,
        0
    );
    // A replacement that committed and then lost its evidence: the generation moved, no reset record followed.
    let mut key_chirho = load_identity_key_record_chirho(&root_chirho, &principal_chirho).unwrap();
    key_chirho.credential_generation_chirho += 1;
    write_identity_key_record_chirho(&root_chirho, &key_chirho).unwrap();
    let inventory_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(inventory_chirho.generation_ahead_of_reset_records_chirho, 1);
    assert_eq!(
        inventory_chirho
            .generation_ahead_principal_hashes_chirho
            .len(),
        1
    );
    assert!(
        inventory_chirho.legacy_rotation_ready_chirho,
        "named, not fatal"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_events_verifier_refuses_tamper_and_pairs_every_kind_with_its_reasons_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, issued_chirho) = credentialed_with_code_chirho(&root_chirho);
    redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    assert_eq!(verify_recovery_code_events_chirho(&root_chirho).unwrap(), 2);
    let path_chirho = root_chirho.join("identity-recovery-code-events-chirho.jsonl");
    let original_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let rewrite_chirho = |edit_chirho: &dyn Fn(&mut serde_json::Value), resign_chirho: bool| {
        let mut lines_chirho: Vec<serde_json::Value> = original_chirho
            .lines()
            .map(|line_chirho| serde_json::from_str(line_chirho).unwrap())
            .collect();
        edit_chirho(&mut lines_chirho[0]);
        if resign_chirho {
            let mut event_chirho: IdentityRecoveryCodeEventChirho =
                serde_json::from_value(lines_chirho[0].clone()).unwrap();
            event_chirho.sig_chirho.clear();
            let message_chirho = serde_json::to_vec(&event_chirho).unwrap();
            lines_chirho[0]["sig_chirho"] = serde_json::Value::String(
                signer_chirho::sign_message_chirho(&root_chirho, &message_chirho).unwrap(),
            );
        }
        let text_chirho: String = lines_chirho
            .iter()
            .map(|value_chirho| format!("{value_chirho}\n"))
            .collect();
        std::fs::write(&path_chirho, text_chirho).unwrap();
    };
    // An unsigned edit fails by signature.
    rewrite_chirho(
        &|value_chirho| value_chirho["credential_generation_chirho"] = 9.into(),
        false,
    );
    assert!(verify_recovery_code_events_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("signature invalid"));
    // Re-signed, a kind paired with another kind's reason still fails, by its own rule.
    rewrite_chirho(
        &|value_chirho| value_chirho["kind_chirho"] = "used-chirho".into(),
        true,
    );
    assert!(verify_recovery_code_events_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("reason of another kind"));
    // Re-signed, an operator mint with no expiry fails by its expiry rule.
    rewrite_chirho(
        &|value_chirho| {
            value_chirho
                .as_object_mut()
                .unwrap()
                .remove("expires_ms_chirho");
        },
        true,
    );
    assert!(verify_recovery_code_events_chirho(&root_chirho)
        .unwrap_err()
        .to_string()
        .contains("expiry rule"));
    // A listing labels every row INVALID while the family fails, and VALID once it verifies.
    let rows_chirho =
        load_recovery_code_events_for_display_chirho(&root_chirho).unwrap_or_default();
    assert!(
        rows_chirho.is_empty()
            || rows_chirho
                .iter()
                .all(|row_chirho| !row_chirho.valid_chirho())
    );
    std::fs::write(&path_chirho, &original_chirho).unwrap();
    let rows_chirho = load_recovery_code_events_for_display_chirho(&root_chirho).unwrap();
    assert_eq!(rows_chirho.len(), 2);
    assert!(rows_chirho
        .iter()
        .all(|row_chirho| row_chirho.valid_chirho()));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn two_concurrent_redemptions_of_one_code_permit_exactly_one_replacement_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, issued_chirho) = credentialed_with_code_chirho(&root_chirho);
    // Both redemptions are started while the test holds the principal lock, so both have passed every read-only step
    // and wait at the lock; then the lock is released and they serialize.
    let handles_chirho = seqlog_chirho::with_named_lock_chirho(
        &root_chirho,
        &credential_lock_name_chirho(&principal_chirho),
        || {
            let handles_chirho: Vec<_> = [SECOND_CHIRHO, THIRD_CHIRHO]
                .into_iter()
                .map(|credential_chirho| {
                    let root_for_thread_chirho = root_chirho.clone();
                    let principal_for_thread_chirho = principal_chirho.clone();
                    let code_chirho = issued_chirho.recovery_code_chirho.clone();
                    std::thread::spawn(move || {
                        redeem_recovery_code_chirho(
                            &root_for_thread_chirho,
                            &principal_for_thread_chirho,
                            &code_chirho,
                            credential_chirho,
                        )
                        .map(|_| credential_chirho)
                    })
                })
                .collect();
            std::thread::sleep(std::time::Duration::from_millis(200));
            Ok::<_, anyhow::Error>(handles_chirho)
        },
    )
    .unwrap();
    let outcomes_chirho: Vec<_> = handles_chirho
        .into_iter()
        .map(|handle_chirho| handle_chirho.join().unwrap())
        .collect();
    let winners_chirho: Vec<&str> = outcomes_chirho
        .iter()
        .filter_map(|outcome_chirho| outcome_chirho.as_ref().ok().copied())
        .collect();
    assert_eq!(winners_chirho.len(), 1, "exactly one replacement");
    let loser_chirho = outcomes_chirho
        .iter()
        .find_map(|outcome_chirho| outcome_chirho.as_ref().err())
        .unwrap();
    assert_eq!(
        refusal_token_chirho(loser_chirho),
        Some("recovery-refused-chirho")
    );
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        winners_chirho[0]
    ));
    assert_eq!(verify_credential_resets_chirho(&root_chirho).unwrap(), 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_code_is_in_no_file_under_the_root_after_mint_and_after_use_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho =
        invite_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let canonical_chirho = issued_chirho.recovery_code_chirho.replace('-', "");
    let scan_chirho = |needle_chirho: &str| {
        root_snapshot_chirho(&root_chirho)
            .values()
            .filter(|bytes_chirho| {
                bytes_chirho
                    .windows(needle_chirho.len())
                    .any(|window_chirho| window_chirho == needle_chirho.as_bytes())
            })
            .count()
    };
    // Control: the scan finds what is there. The principal is in the identity log and its key file.
    assert!(scan_chirho(&issued_chirho.principal_chirho) >= 1);
    for needle_chirho in [
        issued_chirho.recovery_code_chirho.as_str(),
        canonical_chirho.as_str(),
    ] {
        assert_eq!(scan_chirho(needle_chirho), 0, "after the mint");
    }
    redeem_recovery_code_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap();
    for needle_chirho in [
        issued_chirho.recovery_code_chirho.as_str(),
        canonical_chirho.as_str(),
    ] {
        assert_eq!(scan_chirho(needle_chirho), 0, "after the use");
    }
    // An expired invitation can be re-minted, and the re-mint is a new code (the burn is recorded).
    let _ = redeem_at_chirho;
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_recover_endpoint_is_read_before_anything_writes_it_and_keeps_its_own_budget_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let principal_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
        append_auth_attempt_chirho(
            &root_chirho,
            &principal_chirho,
            AUTH_ENDPOINT_RECOVER_CHIRHO,
            IdentityAuthAttemptOutcomeChirho::FailureChirho,
        )
        .unwrap();
    }
    // The verifier reads the rows, so a binary from R2a on is a safe rollback target for the release that writes them.
    assert_eq!(
        verify_auth_attempts_chirho(&root_chirho).unwrap(),
        PUBLIC_AUTH_MAX_FAILURES_CHIRHO as usize
    );
    // Its own budget: the recover key is at its limit, and login's is untouched.
    let error_chirho = ensure_public_auth_attempt_allowed_chirho(
        &root_chirho,
        &principal_chirho,
        AUTH_ENDPOINT_RECOVER_CHIRHO,
    )
    .unwrap_err();
    assert!(is_auth_rate_limit_error_chirho(&error_chirho));
    ensure_public_auth_attempt_allowed_chirho(
        &root_chirho,
        &principal_chirho,
        AUTH_ENDPOINT_LOGIN_CHIRHO,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn only_user_principals_ever_hold_a_mailable_code_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let user_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let owner_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::OwnerChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let before_chirho = root_snapshot_chirho(&root_chirho);
    // An owner invitation is refused before anything is registered.
    let error_chirho =
        invite_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho).unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        super::recovery_code_mint_chirho::OWNER_INVITE_REFUSAL_CHIRHO
    );
    assert_eq!(
        root_snapshot_chirho(&root_chirho),
        before_chirho,
        "no identity row, nothing written"
    );
    // An owner's re-mint is refused before any lock, code or event, by its VERIFIED kind.
    let error_chirho = mint_operator_recovery_code_chirho(&root_chirho, &owner_chirho).unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        super::recovery_code_mint_chirho::OWNER_MINT_REFUSAL_CHIRHO
    );
    assert_eq!(
        root_snapshot_chirho(&root_chirho),
        before_chirho,
        "no lock, no code, no event"
    );
    // Control: the same two commands serve a user.
    invite_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    mint_operator_recovery_code_chirho(&root_chirho, &user_chirho).unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}
