// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Brick 4b-1's arms for the bearer road: a key lives exactly as long as its session (PFE's finding 1), its expiry is its
//! session's (PFE #26013, item 4), and a warm cookie or bearer check does no history-sized work.

use super::*;
use identity_chirho::PrincipalKindChirho;
use std::sync::atomic::AtomicU64;

const APP_CHIRHO: &str = "alpha";
const SECRET_CHIRHO: &str = "key-liveness-secret-chirho";
const NEW_SECRET_CHIRHO: &str = "key-liveness-new-secret-chirho";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-key-liveness-{label_chirho}-{}-{n_chirho}-{}",
        std::process::id(),
        now_ms_chirho()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// A root with an owner and one client, for the app `APP_CHIRHO`.
struct FixtureChirho {
    root_chirho: PathBuf,
    client_chirho: OauthClientRecordChirho,
}

fn fixture_chirho(label_chirho: &str) -> FixtureChirho {
    let root_chirho = tmp_root_chirho(label_chirho);
    let owner_chirho =
        identity_chirho::register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
            .unwrap();
    let client_chirho =
        register_client_chirho(&root_chirho, APP_CHIRHO, &owner_chirho.principal_chirho).unwrap();
    FixtureChirho {
        root_chirho,
        client_chirho,
    }
}

fn user_chirho(fixture_chirho: &FixtureChirho) -> String {
    identity_chirho::register_identity_chirho(
        &fixture_chirho.root_chirho,
        PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho
}

/// A key for `principal_chirho`, from a fresh operator sign-in.
fn key_chirho(fixture_chirho: &FixtureChirho, principal_chirho: &str) -> ScopedTokenIssueChirho {
    let login_chirho =
        identity_chirho::login_identity_chirho(&fixture_chirho.root_chirho, principal_chirho)
            .unwrap();
    issue_scoped_token_after_login_chirho(
        &fixture_chirho.root_chirho,
        fixture_chirho.client_chirho.clone(),
        login_chirho,
        vec!["invoke_chirho".to_string()],
        None,
    )
    .unwrap()
}

/// What the app route's bearer check answers for this key now.
fn bearer_chirho(
    fixture_chirho: &FixtureChirho,
    token_chirho: &str,
) -> Option<ScopedTokenRecordChirho> {
    validate_scoped_token_for_app_chirho(&fixture_chirho.root_chirho, APP_CHIRHO, token_chirho)
        .unwrap()
}

/// FINDING 1, FIRST HALF: revoking the session a key was issued from ends that key, and nothing else. The principal's
/// second key (from another sign-in) and another principal's key keep working, on the app road and the client road, and
/// the ended key refuses exactly as an unknown key does: both read as no key, which the app route answers with its one
/// refusal.
///
/// MIGRATION PATH: the revoked key still answering is PFE's finding 1 back; another key refusing is an outage.
#[test]
fn revoking_a_keys_session_ends_that_key_and_no_other_chirho() {
    let fixture_chirho = fixture_chirho("revoke");
    let alice_chirho = user_chirho(&fixture_chirho);
    let bob_chirho = user_chirho(&fixture_chirho);
    let first_chirho = key_chirho(&fixture_chirho, &alice_chirho);
    let second_chirho = key_chirho(&fixture_chirho, &alice_chirho);
    let bobs_chirho = key_chirho(&fixture_chirho, &bob_chirho);
    for key_chirho in [&first_chirho, &second_chirho, &bobs_chirho] {
        assert_eq!(
            bearer_chirho(&fixture_chirho, &key_chirho.token_chirho),
            Some(key_chirho.record_chirho.clone()),
            "the control: every key answers before the revocation"
        );
    }
    identity_chirho::revoke_session_by_seq_chirho(
        &fixture_chirho.root_chirho,
        &alice_chirho,
        first_chirho.record_chirho.session_seq_chirho,
        "operator-chirho",
        "finding 1 arm",
    )
    .unwrap();
    assert_eq!(
        bearer_chirho(&fixture_chirho, &first_chirho.token_chirho),
        None,
        "the revoked session's key ends"
    );
    assert_eq!(
        bearer_chirho(&fixture_chirho, &first_chirho.token_chirho),
        bearer_chirho(&fixture_chirho, "not-a-key-chirho"),
        "and refuses exactly as an unknown key does"
    );
    assert_eq!(
        bearer_chirho(&fixture_chirho, &second_chirho.token_chirho),
        Some(second_chirho.record_chirho.clone())
    );
    assert_eq!(
        bearer_chirho(&fixture_chirho, &bobs_chirho.token_chirho),
        Some(bobs_chirho.record_chirho.clone())
    );
    let client_id_chirho = &fixture_chirho.client_chirho.client_id_chirho;
    assert!(validate_scoped_token_chirho(
        &fixture_chirho.root_chirho,
        client_id_chirho,
        &first_chirho.token_chirho
    )
    .unwrap()
    .is_none());
    assert!(validate_scoped_token_chirho(
        &fixture_chirho.root_chirho,
        client_id_chirho,
        &second_chirho.token_chirho
    )
    .unwrap()
    .is_some());
}

/// FINDING 1, THE RESET: a credential reset ends every key of that principal (each key's session is revoked, and its
/// credential generation is stale), while another principal's key keeps working, and a key issued afterwards with the
/// new credential works.
///
/// MIGRATION PATH: a key surviving the reset is PFE's finding 1 back; the fresh key refusing means the predicate read a
/// generation the reset did not write.
#[test]
fn a_credential_reset_ends_every_key_of_that_principal_and_no_other_chirho() {
    let fixture_chirho = fixture_chirho("reset");
    let root_chirho = &fixture_chirho.root_chirho;
    let client_id_chirho = fixture_chirho.client_chirho.client_id_chirho.clone();
    let principal_with_credential_chirho = || {
        identity_chirho::register_identity_with_credential_chirho(
            root_chirho,
            PrincipalKindChirho::UserChirho,
            SECRET_CHIRHO,
        )
        .unwrap()
        .principal_chirho
    };
    let alice_chirho = principal_with_credential_chirho();
    let bob_chirho = principal_with_credential_chirho();
    let issue_chirho = |principal_chirho: &str, secret_chirho: &str| {
        issue_scoped_token_chirho(
            root_chirho,
            principal_chirho,
            secret_chirho,
            &client_id_chirho,
            vec!["invoke_chirho".to_string()],
        )
        .unwrap()
    };
    let alices_chirho = [
        issue_chirho(&alice_chirho, SECRET_CHIRHO),
        issue_chirho(&alice_chirho, SECRET_CHIRHO),
    ];
    let bobs_chirho = issue_chirho(&bob_chirho, SECRET_CHIRHO);
    for key_chirho in alices_chirho.iter().chain([&bobs_chirho]) {
        assert!(bearer_chirho(&fixture_chirho, &key_chirho.token_chirho).is_some());
    }
    identity_chirho::reset_identity_credential_chirho(
        root_chirho,
        &alice_chirho,
        NEW_SECRET_CHIRHO,
        "operator-chirho",
        "finding 1 arm",
    )
    .unwrap();
    for key_chirho in &alices_chirho {
        assert_eq!(
            bearer_chirho(&fixture_chirho, &key_chirho.token_chirho),
            None,
            "the reset ends every key of that principal"
        );
    }
    assert_eq!(
        bearer_chirho(&fixture_chirho, &bobs_chirho.token_chirho),
        Some(bobs_chirho.record_chirho.clone()),
        "and no other principal's"
    );
    let fresh_chirho = issue_chirho(&alice_chirho, NEW_SECRET_CHIRHO);
    assert_eq!(
        bearer_chirho(&fixture_chirho, &fresh_chirho.token_chirho),
        Some(fresh_chirho.record_chirho.clone()),
        "a key issued with the new credential works"
    );
}

/// PFE #26013 ITEM 4, RULED (a): a key's session expires no earlier than the key, so a key never dies before the expiry
/// it was issued with. A key issued with lifetime L has a session with the same issue and expiry instants, and the key
/// answers at exactly its expiry and refuses one millisecond later, on the bearer check and on the session question the
/// check asks.
///
/// MIGRATION PATH: the key refusing at its own expiry means the session's expiry test is stricter than the key's.
#[test]
fn a_keys_expiry_is_its_sessions_and_it_lives_until_exactly_that_instant_chirho() {
    let fixture_chirho = fixture_chirho("expiry");
    let root_chirho = &fixture_chirho.root_chirho;
    let alice_chirho = user_chirho(&fixture_chirho);
    let key_chirho = key_chirho(&fixture_chirho, &alice_chirho);
    let record_chirho = &key_chirho.record_chirho;
    let lifetime_chirho = record_chirho.expires_ms_chirho - record_chirho.issued_ms_chirho;
    assert!(lifetime_chirho > 0);
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho).unwrap();
    let session_chirho = identity_chirho::verified_session_for_token_chirho(
        root_chirho,
        &pubkey_chirho,
        &alice_chirho,
        record_chirho.session_seq_chirho,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        (
            session_chirho.issued_ms_chirho,
            session_chirho.expires_ms_chirho
        ),
        (
            record_chirho.issued_ms_chirho,
            record_chirho.expires_ms_chirho
        ),
        "the key's session is issued and expires with the key"
    );
    assert!(session_chirho.expires_ms_chirho - session_chirho.issued_ms_chirho >= lifetime_chirho);
    let at_chirho = |now_ms_chirho: u64| {
        validate_scoped_token_for_app_at_chirho(
            root_chirho,
            APP_CHIRHO,
            &key_chirho.token_chirho,
            now_ms_chirho,
        )
        .unwrap()
    };
    let session_live_at_chirho = |now_ms_chirho: u64| {
        identity_chirho::key_session_live_chirho(
            root_chirho,
            &pubkey_chirho,
            &alice_chirho,
            record_chirho.session_seq_chirho,
            now_ms_chirho,
        )
        .unwrap()
    };
    assert_eq!(
        at_chirho(record_chirho.expires_ms_chirho),
        Some(record_chirho.clone()),
        "the key is live at exactly its expiry"
    );
    assert!(session_live_at_chirho(record_chirho.expires_ms_chirho));
    assert_eq!(
        at_chirho(record_chirho.expires_ms_chirho + 1),
        None,
        "and not one millisecond later"
    );
    assert!(!session_live_at_chirho(record_chirho.expires_ms_chirho + 1));
}

/// (session records parsed, revocation records parsed, whole session-log loads, token records checked) on this thread.
fn work_chirho() -> (u64, u64, u64, u64) {
    let (sessions_chirho, revocations_chirho) =
        identity_chirho::session_read_metrics_chirho::parses_chirho();
    (
        sessions_chirho,
        revocations_chirho,
        identity_chirho::session_read_metrics_chirho::count_chirho(),
        token_view_metrics_chirho::counts_chirho().0,
    )
}

fn delta_chirho(
    after_chirho: (u64, u64, u64, u64),
    before_chirho: (u64, u64, u64, u64),
) -> (u64, u64, u64, u64) {
    (
        after_chirho.0 - before_chirho.0,
        after_chirho.1 - before_chirho.1,
        after_chirho.2 - before_chirho.2,
        after_chirho.3 - before_chirho.3,
    )
}

/// THE GROWTH ARM for the cookie and bearer checks: the growth gate's covered rows for the session log on the anonymous
/// view and the app route name it. At 1, 10 and 100 past sessions, each revoked, a warm cookie check and a warm bearer
/// check parse no session record and no revocation record, load the session log whole zero times, and check no token.
/// The controls: the cold checks before them did parse records on this thread, and a direct load of each log is counted.
///
/// MIGRATION PATH: a nonzero warm count is a request whose cost grows with every sign-in or revocation the root has seen.
#[test]
fn a_warm_cookie_or_bearer_check_parses_no_session_or_revocation_record_at_any_history_chirho() {
    let mut per_history_chirho = Vec::new();
    for history_chirho in [1u64, 10, 100] {
        let fixture_chirho = fixture_chirho("growth");
        let root_chirho = &fixture_chirho.root_chirho;
        let alice_chirho = user_chirho(&fixture_chirho);
        for _ in 0..history_chirho {
            let login_chirho =
                identity_chirho::login_identity_chirho(root_chirho, &alice_chirho).unwrap();
            identity_chirho::revoke_session_token_chirho(
                root_chirho,
                &alice_chirho,
                &login_chirho.token_chirho,
                "operator-chirho",
                "growth arm",
            )
            .unwrap();
        }
        let cookie_chirho =
            identity_chirho::login_identity_chirho(root_chirho, &alice_chirho).unwrap();
        let key_chirho = key_chirho(&fixture_chirho, &alice_chirho);
        let check_chirho = || {
            assert!(identity_chirho::validate_session_token_chirho(
                root_chirho,
                &alice_chirho,
                &cookie_chirho.token_chirho
            )
            .unwrap()
            .is_some());
            assert!(bearer_chirho(&fixture_chirho, &key_chirho.token_chirho).is_some());
        };
        let cold_before_chirho = work_chirho();
        check_chirho();
        let cold_chirho = delta_chirho(work_chirho(), cold_before_chirho);
        assert!(
            cold_chirho.0 > 0,
            "the control: the cold checks parsed sessions on this thread: {cold_chirho:?}"
        );
        let warm_before_chirho = work_chirho();
        check_chirho();
        per_history_chirho.push(delta_chirho(work_chirho(), warm_before_chirho));
        let (sessions_before_chirho, revocations_before_chirho, _, _) = work_chirho();
        identity_chirho::load_sessions_chirho(root_chirho).unwrap();
        identity_chirho::load_session_revocations_chirho(root_chirho).unwrap();
        let (sessions_after_chirho, revocations_after_chirho, _, _) = work_chirho();
        assert_eq!(
            (
                sessions_after_chirho - sessions_before_chirho,
                revocations_after_chirho - revocations_before_chirho
            ),
            (history_chirho + 2, history_chirho),
            "the control: a direct load of each log is counted record by record"
        );
    }
    assert_eq!(
        per_history_chirho,
        vec![(0, 0, 0, 0); 3],
        "a warm cookie or bearer check parses no session or revocation record at 1, 10 or 100 past sessions"
    );
}

/// The four logs the session road's repair sets aside together, each with its seqlog sidecar (measured for PFE #26020):
/// every scoped-token record names its session and every use names its token, so the token logs must go with the
/// session logs or the token view refuses for good.
const REPAIR_LOGS_CHIRHO: [&str; 4] = [
    "identity-sessions-chirho.jsonl",
    "identity-session-revocations-chirho.jsonl",
    "scoped-tokens-chirho.jsonl",
    "scoped-token-uses-chirho.jsonl",
];

/// Move `names_chirho` and their `.head-chirho` sidecars out of `root_chirho`, as the runbook's Step 9 does.
fn set_aside_chirho(root_chirho: &Path, names_chirho: &[&str]) {
    let aside_chirho = tmp_root_chirho("set-aside");
    for name_chirho in names_chirho {
        for suffix_chirho in ["", ".head-chirho"] {
            let file_chirho = format!("{name_chirho}{suffix_chirho}");
            if root_chirho.join(&file_chirho).exists() {
                std::fs::rename(
                    root_chirho.join(&file_chirho),
                    aside_chirho.join(&file_chirho),
                )
                .unwrap();
            }
        }
    }
}

/// A copy of `root_chirho` at a new path, whose views were never built: what a restarted service sees.
fn restarted_root_chirho(root_chirho: &Path) -> PathBuf {
    fn copy_dir_chirho(from_chirho: &Path, to_chirho: &Path) {
        std::fs::create_dir_all(to_chirho).unwrap();
        for entry_chirho in std::fs::read_dir(from_chirho).unwrap() {
            let entry_chirho = entry_chirho.unwrap();
            let target_chirho = to_chirho.join(entry_chirho.file_name());
            if entry_chirho.file_type().unwrap().is_dir() {
                copy_dir_chirho(&entry_chirho.path(), &target_chirho);
            } else {
                std::fs::copy(entry_chirho.path(), &target_chirho).unwrap();
            }
        }
    }
    let copy_chirho = tmp_root_chirho("restarted");
    copy_dir_chirho(root_chirho, &copy_chirho);
    copy_chirho
}

fn rate_limit_chirho() -> ScopedTokenRateLimitChirho {
    ScopedTokenRateLimitChirho {
        window_ms_chirho: 60_000,
        max_invokes_chirho: 50,
        device_id_chirho: None,
    }
}

/// A rate-limited key for `principal_chirho` with one recorded use, so all four repair logs hold records.
fn key_with_use_chirho(
    fixture_chirho: &FixtureChirho,
    principal_chirho: &str,
) -> ScopedTokenIssueChirho {
    let login_chirho =
        identity_chirho::login_identity_chirho(&fixture_chirho.root_chirho, principal_chirho)
            .unwrap();
    let issue_chirho = issue_scoped_token_after_login_chirho(
        &fixture_chirho.root_chirho,
        fixture_chirho.client_chirho.clone(),
        login_chirho,
        vec!["invoke_chirho".to_string()],
        Some(rate_limit_chirho()),
    )
    .unwrap();
    record_scoped_token_use_chirho(&fixture_chirho.root_chirho, &issue_chirho.record_chirho)
        .unwrap()
        .unwrap();
    issue_chirho
}

/// THE REPAIR PATH for the widened fail-closed (PFE #26020, the runbook's Step 9). A complete session record that fails
/// verification refuses every cookie and bearer check. Setting aside the four logs together (sessions, revocations,
/// scoped tokens and their uses, each with its sidecar) and restarting recovers every road: the old cookie and key read
/// as unknown, a new sign-in works, new keys issue (the cap included) and answer, and today's full verifiers accept the
/// new logs. The two NEVERs are measured too: with only the revocation log set aside a revoked session lives again, and
/// with only the session log set aside a restarted service refuses every bearer check and every capped key issuance.
///
/// MIGRATION PATH: a road still refused after the four logs move means another log references sessions or keys; add it
/// to `REPAIR_LOGS_CHIRHO` and to the runbook's Step 9.
#[test]
fn the_repair_path_sets_aside_four_logs_together_and_every_road_recovers_chirho() {
    // THE REPAIR.
    let repair_fixture_chirho = fixture_chirho("repair");
    let root_chirho = &repair_fixture_chirho.root_chirho;
    let alice_chirho = user_chirho(&repair_fixture_chirho);
    let old_cookie_chirho =
        identity_chirho::login_identity_chirho(root_chirho, &alice_chirho).unwrap();
    let revoked_chirho =
        identity_chirho::login_identity_chirho(root_chirho, &alice_chirho).unwrap();
    identity_chirho::revoke_session_token_chirho(
        root_chirho,
        &alice_chirho,
        &revoked_chirho.token_chirho,
        "operator-chirho",
        "repair arm",
    )
    .unwrap();
    let old_key_chirho = key_with_use_chirho(&repair_fixture_chirho, &alice_chirho);
    let mut forged_chirho = old_cookie_chirho.session_chirho.clone();
    forged_chirho.seq_chirho = identity_chirho::load_sessions_chirho(root_chirho)
        .unwrap()
        .len() as u64;
    let mut sessions_file_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(root_chirho.join(REPAIR_LOGS_CHIRHO[0]))
        .unwrap();
    use std::io::Write as _;
    writeln!(
        sessions_file_chirho,
        "{}",
        serde_json::to_string(&forged_chirho).unwrap()
    )
    .unwrap();
    drop(sessions_file_chirho);
    assert!(
        identity_chirho::validate_session_token_chirho(
            root_chirho,
            &alice_chirho,
            &old_cookie_chirho.token_chirho
        )
        .is_err(),
        "the control: a complete bad session record refuses the cookie road"
    );
    set_aside_chirho(root_chirho, &REPAIR_LOGS_CHIRHO);
    let repaired_chirho = FixtureChirho {
        root_chirho: restarted_root_chirho(root_chirho),
        client_chirho: repair_fixture_chirho.client_chirho.clone(),
    };
    let repaired_root_chirho = &repaired_chirho.root_chirho;
    assert_eq!(
        identity_chirho::validate_session_token_chirho(
            repaired_root_chirho,
            &alice_chirho,
            &old_cookie_chirho.token_chirho
        )
        .unwrap(),
        None,
        "the old cookie reads as no session"
    );
    assert_eq!(
        bearer_chirho(&repaired_chirho, &old_key_chirho.token_chirho),
        None,
        "the old key reads as unknown"
    );
    let new_cookie_chirho =
        identity_chirho::login_identity_chirho(repaired_root_chirho, &alice_chirho).unwrap();
    assert!(identity_chirho::validate_session_token_chirho(
        repaired_root_chirho,
        &alice_chirho,
        &new_cookie_chirho.token_chirho
    )
    .unwrap()
    .is_some());
    let new_key_chirho = key_with_use_chirho(&repaired_chirho, &alice_chirho);
    assert_eq!(
        bearer_chirho(&repaired_chirho, &new_key_chirho.token_chirho),
        Some(new_key_chirho.record_chirho.clone()),
        "a new key issues through the cap and answers"
    );
    identity_chirho::verify_sessions_chirho(repaired_root_chirho).unwrap();
    identity_chirho::verify_session_revocations_chirho(repaired_root_chirho).unwrap();
    verify_scoped_token_uses_chirho(repaired_root_chirho).unwrap();

    // NEVER ONLY THE REVOCATION LOG: the revoked session lives again.
    let revocations_only_chirho = fixture_chirho("repair-revocations-only");
    let root_chirho = &revocations_only_chirho.root_chirho;
    let alice_chirho = user_chirho(&revocations_only_chirho);
    let revoked_chirho =
        identity_chirho::login_identity_chirho(root_chirho, &alice_chirho).unwrap();
    identity_chirho::revoke_session_token_chirho(
        root_chirho,
        &alice_chirho,
        &revoked_chirho.token_chirho,
        "operator-chirho",
        "repair arm",
    )
    .unwrap();
    set_aside_chirho(root_chirho, &[REPAIR_LOGS_CHIRHO[1]]);
    assert!(
        identity_chirho::validate_session_token_chirho(
            &restarted_root_chirho(root_chirho),
            &alice_chirho,
            &revoked_chirho.token_chirho
        )
        .unwrap()
        .is_some(),
        "with only the revocation log set aside, a revoked session lives again: NEVER do this"
    );

    // NEVER ONLY THE SESSION LOG: a restarted service refuses every bearer check and every capped key issuance.
    let sessions_only_chirho = fixture_chirho("repair-sessions-only");
    let alice_chirho = user_chirho(&sessions_only_chirho);
    let key_chirho = key_with_use_chirho(&sessions_only_chirho, &alice_chirho);
    set_aside_chirho(&sessions_only_chirho.root_chirho, &[REPAIR_LOGS_CHIRHO[0]]);
    let restarted_chirho = FixtureChirho {
        root_chirho: restarted_root_chirho(&sessions_only_chirho.root_chirho),
        client_chirho: sessions_only_chirho.client_chirho.clone(),
    };
    let refusal_chirho = validate_scoped_token_for_app_chirho(
        &restarted_chirho.root_chirho,
        APP_CHIRHO,
        &key_chirho.token_chirho,
    )
    .unwrap_err();
    assert!(
        format!("{refusal_chirho:#}").contains("references missing session"),
        "with only the session log set aside, the token view refuses: {refusal_chirho:#}"
    );
    let login_chirho =
        identity_chirho::login_identity_chirho(&restarted_chirho.root_chirho, &alice_chirho)
            .unwrap();
    assert!(
        issue_scoped_token_after_login_chirho(
            &restarted_chirho.root_chirho,
            restarted_chirho.client_chirho.clone(),
            login_chirho,
            vec!["invoke_chirho".to_string()],
            Some(rate_limit_chirho()),
        )
        .is_err(),
        "and no capped key can issue until the token logs follow"
    );
}
