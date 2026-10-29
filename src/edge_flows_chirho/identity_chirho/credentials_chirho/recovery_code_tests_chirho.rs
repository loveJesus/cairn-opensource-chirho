// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Arms for R2a's code and its two acts: the operator's mint (the invitation, and the re-mint) and the redemption.
//! Each refusal arm asserts its IDENTITY and that the whole root is byte-unchanged, so a refusal that wrote anything,
//! a lock file for a stranger's string included, fails by name.
//! Migration paths: an arm that reds because a refusal now writes something is a regression (refusals write nothing
//! in R2a; R2b's served road adds one attempt row, in its own arms). An arm that reds because the lifetime moved is a
//! retarget only with L.J.'s word, since the constant is the lifetime's one source (PFE #26035).

use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn code_tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-recovery-code-test-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

pub(super) const FIRST_CHIRHO: &str = "first-credential-value";
pub(super) const SECOND_CHIRHO: &str = "second-credential-value";
pub(super) const THIRD_CHIRHO: &str = "third-credential-value";

/// Every file under the root with its bytes: a refusal must leave this exactly as it was.
pub(super) fn root_snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out_chirho = BTreeMap::new();
    let mut stack_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = stack_chirho.pop() {
        let Ok(entries_chirho) = std::fs::read_dir(&dir_chirho) else {
            continue;
        };
        for entry_chirho in entries_chirho.flatten() {
            let path_chirho = entry_chirho.path();
            if path_chirho.is_dir() {
                stack_chirho.push(path_chirho);
            } else {
                out_chirho.insert(
                    path_chirho.clone(),
                    std::fs::read(&path_chirho).unwrap_or_default(),
                );
            }
        }
    }
    out_chirho
}

/// The files a step created, changed or removed, by comparing two snapshots.
pub(super) fn refusal_writes_chirho(
    before_chirho: &BTreeMap<PathBuf, Vec<u8>>,
    after_chirho: &BTreeMap<PathBuf, Vec<u8>>,
) -> Vec<PathBuf> {
    let mut paths_chirho: Vec<PathBuf> = after_chirho
        .iter()
        .filter(|(path_chirho, bytes_chirho)| {
            before_chirho.get(*path_chirho) != Some(*bytes_chirho)
        })
        .map(|(path_chirho, _)| path_chirho.clone())
        .collect();
    paths_chirho.extend(
        before_chirho
            .keys()
            .filter(|path_chirho| !after_chirho.contains_key(*path_chirho))
            .cloned(),
    );
    paths_chirho
}

pub(super) fn signs_in_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
) -> bool {
    login_identity_with_credential_chirho(root_chirho, principal_chirho, credential_chirho).is_ok()
}

pub(super) fn refusal_token_chirho(error_chirho: &anyhow::Error) -> Option<&'static str> {
    recovery_code_refusal_token_chirho(error_chirho)
}

pub(super) fn events_chirho(
    root_chirho: &Path,
) -> Vec<(RecoveryCodeEventKindChirho, RecoveryCodeReasonKindChirho)> {
    verify_recovery_code_events_chirho(root_chirho).unwrap();
    load_recovery_code_events_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .map(|event_chirho| (event_chirho.kind_chirho, event_chirho.reason_kind_chirho))
        .collect()
}

pub(super) fn redeem_at_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    code_chirho: &str,
    credential_chirho: &str,
    now_ms_chirho: u64,
) -> Result<IdentityCredentialResetReportChirho> {
    super::recovery_code_redeem_chirho::redeem_recovery_code_at_chirho(
        root_chirho,
        principal_chirho,
        code_chirho,
        credential_chirho,
        now_ms_chirho,
    )
}

#[test]
fn a_code_is_24_canonical_symbols_in_six_groups_normalized_the_same_at_mint_and_at_use_chirho() {
    let fresh_chirho = fresh_recovery_code_chirho(None).unwrap();
    let display_chirho = &fresh_chirho.display_chirho;
    let groups_chirho: Vec<&str> = display_chirho.split('-').collect();
    assert_eq!(groups_chirho.len(), 6, "{display_chirho}");
    for group_chirho in &groups_chirho {
        assert_eq!(group_chirho.len(), 4);
        assert!(group_chirho
            .bytes()
            .all(|byte_chirho| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&byte_chirho)));
    }
    let canonical_chirho = groups_chirho.concat();
    assert_eq!(
        normalize_recovery_code_chirho(display_chirho).as_deref(),
        Some(canonical_chirho.as_str())
    );
    // What she might type back: lower case, spaces, no dashes, and the decode aliases.
    let typed_chirho = format!(" {} ", canonical_chirho.to_lowercase());
    assert_eq!(
        normalize_recovery_code_chirho(&typed_chirho).as_deref(),
        Some(canonical_chirho.as_str())
    );
    assert_eq!(
        normalize_recovery_code_chirho("o1lI-0000-0000-0000-0000-0000").as_deref(),
        Some("011100000000000000000000")
    );
    // What cannot be a code.
    for refused_chirho in [
        "U000-0000-0000-0000-0000-0000",
        "0000-0000-0000-0000-0000-000",
        "0000-0000-0000-0000-0000-00000",
        "0000-0000-0000-0000-0000-000\u{e9}",
        &"0".repeat(65),
        "",
    ] {
        assert_eq!(
            normalize_recovery_code_chirho(refused_chirho),
            None,
            "{refused_chirho:?}"
        );
    }
    // The stored form holds the hash, never the code.
    let stored_chirho = &fresh_chirho.stored_chirho;
    assert_eq!(
        recovery_code_hash_chirho(&stored_chirho.salt_chirho, &canonical_chirho).unwrap(),
        stored_chirho.hash_chirho
    );
    assert!(!stored_chirho.hash_chirho.contains(&canonical_chirho));
}

#[test]
fn the_hash_is_salted_and_domain_separated_chirho() {
    let code_chirho = "0123456789ABCDEFGHJKMNPQ";
    let salt_a_chirho = "00".repeat(16);
    let salt_b_chirho = "11".repeat(16);
    let hash_a_chirho = recovery_code_hash_chirho(&salt_a_chirho, code_chirho).unwrap();
    assert_ne!(
        hash_a_chirho,
        recovery_code_hash_chirho(&salt_b_chirho, code_chirho).unwrap()
    );
    let mut plain_chirho = blake3::Hasher::new();
    plain_chirho.update(&[0_u8; 16]);
    plain_chirho.update(code_chirho.as_bytes());
    assert_ne!(
        hash_a_chirho,
        plain_chirho.finalize().to_hex().to_string(),
        "the hash has its own domain"
    );
    assert!(
        recovery_code_hash_chirho("00", code_chirho).is_err(),
        "a short salt is refused"
    );
    assert!(
        recovery_code_hash_chirho(&salt_a_chirho, "0123").is_err(),
        "a short code is refused"
    );
}

#[test]
fn an_invitation_sets_the_first_credential_once_and_the_code_then_refuses_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho =
        invite_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let principal_chirho = issued_chirho.principal_chirho.clone();
    assert!(principal_chirho.starts_with("user/"));
    let key_chirho = load_identity_key_record_chirho(&root_chirho, &principal_chirho).unwrap();
    assert!(
        key_chirho.credential_hash_chirho.is_none(),
        "an invitee has no credential yet"
    );
    assert_eq!(
        key_chirho.recovery_code_expires_ms_chirho,
        Some(issued_chirho.expires_ms_chirho)
    );
    let minted_chirho = load_recovery_code_events_chirho(&root_chirho).unwrap();
    assert_eq!(
        (
            minted_chirho[0].kind_chirho,
            minted_chirho[0].reason_kind_chirho,
            minted_chirho[0].expires_ms_chirho
        ),
        (
            RecoveryCodeEventKindChirho::MintedChirho,
            RecoveryCodeReasonKindChirho::OperatorInvitationChirho,
            Some(issued_chirho.expires_ms_chirho)
        )
    );
    // `--json` prints exactly these three fields (PFE #26035, item 3).
    let json_chirho = serde_json::to_value(&issued_chirho).unwrap();
    let mut keys_chirho: Vec<&String> = json_chirho.as_object().unwrap().keys().collect();
    keys_chirho.sort();
    assert_eq!(
        keys_chirho,
        [
            "expires_ms_chirho",
            "principal_chirho",
            "recovery_code_chirho"
        ]
    );

    let report_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        report_chirho.record_chirho.reason_chirho,
        INVITATION_CODE_RESET_REASON_CHIRHO
    );
    assert_eq!(report_chirho.record_chirho.actor_chirho, principal_chirho);
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        FIRST_CHIRHO
    ));
    let key_chirho = load_identity_key_record_chirho(&root_chirho, &principal_chirho).unwrap();
    assert_eq!(
        stored_recovery_code_chirho(&key_chirho).unwrap(),
        None,
        "the code is consumed"
    );
    assert_eq!(key_chirho.credential_generation_chirho, 1);
    let events_after_chirho = load_recovery_code_events_chirho(&root_chirho).unwrap();
    assert_eq!(
        (
            events_after_chirho[1].kind_chirho,
            events_after_chirho[1].reason_kind_chirho
        ),
        (
            RecoveryCodeEventKindChirho::UsedChirho,
            RecoveryCodeReasonKindChirho::CodeUseChirho
        )
    );
    assert_eq!(
        events_after_chirho[1].code_state_digest_chirho, minted_chirho[0].code_state_digest_chirho,
        "the use names the code its mint named"
    );
    let error_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_token_chirho(&error_chirho),
        Some("recovery-refused-chirho")
    );
    assert!(
        signs_in_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO),
        "the second try changed nothing"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_redemption_is_the_reset_act_sessions_first_and_the_generation_bumped_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let principal_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let tokens_chirho: Vec<String> = (0..2)
        .map(|_| {
            login_identity_with_credential_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO)
                .unwrap()
                .token_chirho
        })
        .collect();
    let issued_chirho =
        mint_operator_recovery_code_chirho(&root_chirho, &principal_chirho).unwrap();
    assert_eq!(
        events_chirho(&root_chirho),
        [(
            RecoveryCodeEventKindChirho::MintedChirho,
            RecoveryCodeReasonKindChirho::OperatorRecoveryChirho
        )]
    );
    let report_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        report_chirho.record_chirho.reason_chirho,
        RECOVERY_CODE_RESET_REASON_CHIRHO
    );
    assert_eq!(
        report_chirho.revoked_session_seqs_chirho.len(),
        2,
        "both live sessions revoked first"
    );
    for token_chirho in &tokens_chirho {
        assert!(
            validate_session_token_chirho(&root_chirho, &principal_chirho, token_chirho)
                .unwrap()
                .is_none()
        );
    }
    assert!(!signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        FIRST_CHIRHO
    ));
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        SECOND_CHIRHO
    ));
    assert_eq!(
        load_identity_key_record_chirho(&root_chirho, &principal_chirho)
            .unwrap()
            .credential_generation_chirho,
        1
    );
    assert_eq!(verify_credential_resets_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        events_chirho(&root_chirho)[1],
        (
            RecoveryCodeEventKindChirho::UsedChirho,
            RecoveryCodeReasonKindChirho::CodeUseChirho
        )
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn every_operator_code_expires_one_lifetime_after_its_mint_and_is_live_at_the_instant_chirho() {
    let root_chirho = code_tmp_root_chirho();
    // A CREDENTIALED principal's operator code expires too (PFE #26035, item 2).
    let principal_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let before_ms_chirho = now_ms_chirho();
    let issued_chirho =
        mint_operator_recovery_code_chirho(&root_chirho, &principal_chirho).unwrap();
    let after_ms_chirho = now_ms_chirho();
    assert!(
        issued_chirho.expires_ms_chirho
            >= before_ms_chirho + RECOVERY_CODE_OPERATOR_LIFETIME_MS_CHIRHO
            && issued_chirho.expires_ms_chirho
                <= after_ms_chirho + RECOVERY_CODE_OPERATOR_LIFETIME_MS_CHIRHO,
        "one lifetime after the mint"
    );
    let expires_chirho = issued_chirho.expires_ms_chirho;
    // One millisecond past the expiry: the uniform refusal, and nothing written.
    let before_chirho = root_snapshot_chirho(&root_chirho);
    let error_chirho = redeem_at_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
        expires_chirho + 1,
    )
    .unwrap_err();
    assert_eq!(
        refusal_token_chirho(&error_chirho),
        Some("recovery-refused-chirho")
    );
    assert_eq!(
        root_snapshot_chirho(&root_chirho),
        before_chirho,
        "an expired code writes nothing"
    );
    // At the expiry instant itself the code is still live, as a key and a session are.
    redeem_at_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
        expires_chirho,
    )
    .unwrap();
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        SECOND_CHIRHO
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn one_uniform_refusal_with_the_same_common_work_and_nothing_written_on_every_branch_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let with_code_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let without_code_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let burned_chirho =
        mint_operator_recovery_code_chirho(&root_chirho, &with_code_chirho).unwrap();
    let live_chirho = mint_operator_recovery_code_chirho(&root_chirho, &with_code_chirho).unwrap();
    let wrong_chirho = "0000-0000-0000-0000-0000-0000";
    let now_chirho = now_ms_chirho();
    let branches_chirho: [(&str, &str, &str, u64); 6] = [
        (
            "an unknown principal",
            "user/0123456789abcdef",
            live_chirho.recovery_code_chirho.as_str(),
            now_chirho,
        ),
        (
            "a principal with no code",
            &without_code_chirho,
            live_chirho.recovery_code_chirho.as_str(),
            now_chirho,
        ),
        (
            "a malformed code",
            &with_code_chirho,
            "not a code at all",
            now_chirho,
        ),
        ("a wrong code", &with_code_chirho, wrong_chirho, now_chirho),
        (
            "a burned code",
            &with_code_chirho,
            burned_chirho.recovery_code_chirho.as_str(),
            now_chirho,
        ),
        (
            "an expired code",
            &with_code_chirho,
            live_chirho.recovery_code_chirho.as_str(),
            live_chirho.expires_ms_chirho + 1,
        ),
    ];
    for (label_chirho, principal_chirho, code_chirho, at_ms_chirho) in branches_chirho {
        let before_chirho = root_snapshot_chirho(&root_chirho);
        recovery_code_hash_metrics_chirho::take_chirho();
        let error_chirho = redeem_at_chirho(
            &root_chirho,
            principal_chirho,
            code_chirho,
            SECOND_CHIRHO,
            at_ms_chirho,
        )
        .unwrap_err();
        assert_eq!(
            refusal_token_chirho(&error_chirho),
            Some("recovery-refused-chirho"),
            "{label_chirho}"
        );
        assert_eq!(
            error_chirho.to_string(),
            "recovery-refused-chirho",
            "{label_chirho}: one value, no detail"
        );
        assert_eq!(
            recovery_code_hash_metrics_chirho::take_chirho(),
            1,
            "{label_chirho}: the same one code hash"
        );
        // A refusal may create the named lock of a principal that EXISTS, once, and nothing else (revision 2: a lock
        // is created only for a principal that exists). For a string a stranger chose it creates nothing at all.
        let writes_chirho =
            refusal_writes_chirho(&before_chirho, &root_snapshot_chirho(&root_chirho));
        if label_chirho == "an unknown principal" {
            assert!(
                writes_chirho.is_empty(),
                "{label_chirho}: wrote {writes_chirho:?}"
            );
        } else {
            assert!(
                writes_chirho.len() <= 1
                    && writes_chirho.iter().all(|path_chirho| {
                        path_chirho.parent() == Some(root_chirho.join("locks-chirho").as_path())
                            && !before_chirho.contains_key(path_chirho)
                    }),
                "{label_chirho}: only its own lock may appear: {writes_chirho:?}"
            );
        }
    }
    // The live code still redeems after all of that.
    redeem_recovery_code_chirho(
        &root_chirho,
        &with_code_chirho,
        &live_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_floor_comes_first_and_says_nothing_about_the_principal_or_the_code_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho =
        invite_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let short_chirho = "fourteen-chars";
    for (label_chirho, principal_chirho) in [
        ("an unknown principal", "user/0123456789abcdef"),
        ("the invitee", issued_chirho.principal_chirho.as_str()),
    ] {
        let before_chirho = root_snapshot_chirho(&root_chirho);
        recovery_code_hash_metrics_chirho::take_chirho();
        let error_chirho = redeem_recovery_code_chirho(
            &root_chirho,
            principal_chirho,
            &issued_chirho.recovery_code_chirho,
            short_chirho,
        )
        .unwrap_err();
        assert_eq!(
            refusal_token_chirho(&error_chirho),
            Some("credential-too-weak-chirho"),
            "{label_chirho}"
        );
        assert_eq!(
            recovery_code_hash_metrics_chirho::take_chirho(),
            0,
            "{label_chirho}: before any code work"
        );
        assert_eq!(
            root_snapshot_chirho(&root_chirho),
            before_chirho,
            "{label_chirho}: nothing written"
        );
    }
    redeem_recovery_code_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}
