// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Arms for the self-service credential change: what her own change must prove, refuse, revoke,
//! replace, and record. Each refusal arm asserts the failure's IDENTITY (its token) and that
//! nothing else moved; the success arm pins the ordering through the reset's own record. F1 (the
//! proof and the mutation are one critical section) is proven by a deterministic race the lock
//! serialises; F2 (the guess budget is per session and exhaustion revokes the session, never
//! touching login) is proven both ways.
//! Migration paths: an arm that reds because a refusal now writes a record is a regression
//! (refusals write nothing except the one failed-proof row named here); an arm that reds because a
//! token spelling changed is a retarget only if the product catalog moved with it.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn change_tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-credential-change-test-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

const OLD_SECRET_CHIRHO: &str = "first-secret-value";
const NEW_SECRET_CHIRHO: &str = "second-secret-value";

/// One credentialed user with two live sessions; returns (principal, session tokens).
fn world_chirho(root_chirho: &Path) -> (String, Vec<String>) {
    let identity_chirho = register_identity_with_credential_chirho(
        root_chirho,
        PrincipalKindChirho::UserChirho,
        OLD_SECRET_CHIRHO,
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho;
    let tokens_chirho = (0..2)
        .map(|_| {
            login_identity_with_credential_chirho(root_chirho, &principal_chirho, OLD_SECRET_CHIRHO)
                .unwrap()
                .token_chirho
        })
        .collect::<Vec<_>>();
    for token_chirho in &tokens_chirho {
        assert!(
            validate_session_token_chirho(root_chirho, &principal_chirho, token_chirho)
                .unwrap()
                .is_some(),
            "positive control: the session is live before the change"
        );
    }
    (principal_chirho, tokens_chirho)
}

/// Everything a refusal must leave untouched: reset records, revocations, the SHARED auth-attempt
/// log (this road must write ZERO of those now), this road's own failed-proof log, and whether the
/// sessions are still live.
fn untouched_snapshot_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    tokens_chirho: &[String],
) -> (usize, usize, usize, usize, bool) {
    let live_chirho = tokens_chirho.iter().all(|token_chirho| {
        validate_session_token_chirho(root_chirho, principal_chirho, token_chirho)
            .unwrap()
            .is_some()
    });
    (
        verify_credential_resets_chirho(root_chirho).unwrap(),
        verify_session_revocations_chirho(root_chirho).unwrap(),
        load_auth_attempts_chirho(root_chirho).unwrap().len(),
        verify_credential_change_attempts_chirho(root_chirho).unwrap(),
        live_chirho,
    )
}

#[test]
fn a_mismatched_current_credential_refuses_by_token_records_one_failed_proof_and_changes_nothing_chirho(
) {
    let root_chirho = change_tmp_root_chirho();
    let (principal_chirho, tokens_chirho) = world_chirho(&root_chirho);
    let before_chirho = untouched_snapshot_chirho(&root_chirho, &principal_chirho, &tokens_chirho);
    let error_chirho = change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &tokens_chirho[0],
        "not-the-secret-value",
        NEW_SECRET_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        credential_change_refusal_token_chirho(&error_chirho),
        Some("credential-mismatch-chirho")
    );
    let after_chirho = untouched_snapshot_chirho(&root_chirho, &principal_chirho, &tokens_chirho);
    assert_eq!(
        after_chirho,
        (
            before_chirho.0,
            before_chirho.1,
            before_chirho.2,
            before_chirho.3 + 1,
            true
        ),
        "no reset, no revocation, ZERO auth-attempt rows, exactly one failed-proof row, sessions live"
    );
    assert!(
        login_identity_with_credential_chirho(&root_chirho, &principal_chirho, OLD_SECRET_CHIRHO)
            .is_ok(),
        "the old credential is still the credential"
    );
    assert!(login_identity_with_credential_chirho(
        &root_chirho,
        &principal_chirho,
        NEW_SECRET_CHIRHO
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_replacement_below_the_floor_refuses_by_token_and_writes_nothing_at_all_chirho() {
    let root_chirho = change_tmp_root_chirho();
    let (principal_chirho, tokens_chirho) = world_chirho(&root_chirho);
    let before_chirho = untouched_snapshot_chirho(&root_chirho, &principal_chirho, &tokens_chirho);
    let error_chirho = change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &tokens_chirho[0],
        OLD_SECRET_CHIRHO,
        "short",
    )
    .unwrap_err();
    assert_eq!(
        credential_change_refusal_token_chirho(&error_chirho),
        Some("credential-too-weak-chirho")
    );
    assert_eq!(
        untouched_snapshot_chirho(&root_chirho, &principal_chirho, &tokens_chirho),
        before_chirho,
        "a floor refusal is not a guess: not even a failed-proof row is written"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_change_revokes_every_live_session_first_replaces_the_credential_bumps_the_generation_and_records_her_chirho(
) {
    let root_chirho = change_tmp_root_chirho();
    let (principal_chirho, tokens_chirho) = world_chirho(&root_chirho);
    let report_chirho = change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &tokens_chirho[0],
        OLD_SECRET_CHIRHO,
        NEW_SECRET_CHIRHO,
    )
    .expect("her change is accepted");
    assert_eq!(report_chirho.revoked_session_seqs_chirho.len(), 2);
    assert_eq!(report_chirho.record_chirho.revoked_session_count_chirho, 2);
    assert_eq!(
        report_chirho.record_chirho.actor_chirho, principal_chirho,
        "she is the actor of her own change"
    );
    assert_eq!(
        report_chirho.record_chirho.reason_chirho,
        SELF_SERVICE_CREDENTIAL_CHANGE_REASON_CHIRHO
    );
    for token_chirho in &tokens_chirho {
        assert!(
            validate_session_token_chirho(&root_chirho, &principal_chirho, token_chirho)
                .unwrap()
                .is_none(),
            "every pre-change session is dead"
        );
    }
    assert!(
        login_identity_with_credential_chirho(&root_chirho, &principal_chirho, OLD_SECRET_CHIRHO)
            .is_err(),
        "the old credential refuses"
    );
    let new_login_chirho =
        login_identity_with_credential_chirho(&root_chirho, &principal_chirho, NEW_SECRET_CHIRHO)
            .expect("the new credential logs in");
    assert!(
        validate_session_token_chirho(
            &root_chirho,
            &principal_chirho,
            &new_login_chirho.token_chirho
        )
        .unwrap()
        .is_some(),
        "a session issued AFTER the change (new generation) is valid"
    );
    assert_eq!(verify_credential_resets_chirho(&root_chirho).unwrap(), 1);
    let record_chirho = &load_credential_resets_chirho(&root_chirho).unwrap()[0];
    assert_eq!(record_chirho, &report_chirho.record_chirho);
    let serialized_chirho = serde_json::to_string(record_chirho).unwrap();
    assert!(
        !serialized_chirho.contains(OLD_SECRET_CHIRHO)
            && !serialized_chirho.contains(NEW_SECRET_CHIRHO),
        "the record carries neither credential"
    );
    // The change road writes ZERO auth-attempt rows (it left the shared login limiter entirely).
    assert_eq!(load_auth_attempts_chirho(&root_chirho).unwrap().len(), 0);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_fifth_failed_proof_revokes_the_session_and_refuses_as_guess_exhausted_chirho() {
    let root_chirho = change_tmp_root_chirho();
    let (principal_chirho, tokens_chirho) = world_chirho(&root_chirho);
    // The first four wrong proofs are plain mismatches and the session stays live.
    for _ in 0..CREDENTIAL_CHANGE_SESSION_MAX_FAILURES_CHIRHO - 1 {
        let error_chirho = change_identity_credential_for_session_chirho(
            &root_chirho,
            &principal_chirho,
            &tokens_chirho[0],
            "not-the-secret-value",
            NEW_SECRET_CHIRHO,
        )
        .unwrap_err();
        assert_eq!(
            credential_change_refusal_token_chirho(&error_chirho),
            Some("credential-mismatch-chirho")
        );
    }
    assert!(
        validate_session_token_chirho(&root_chirho, &principal_chirho, &tokens_chirho[0])
            .unwrap()
            .is_some(),
        "four failures do not yet revoke the session"
    );
    // The FIFTH failed proof spends the budget: it revokes the session AND refuses as
    // guess-exhausted, NOT as one more mismatch. That distinct identity is what lets the served road
    // send her to the login page (a revoked session cannot open her own page) instead of a bare 403.
    let fifth_chirho = change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &tokens_chirho[0],
        "not-the-secret-value",
        NEW_SECRET_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        credential_change_refusal_token_chirho(&fifth_chirho),
        Some("credential-guess-exhausted-chirho"),
        "the budget-spending proof refuses as exhausted, not as another mismatch"
    );
    // The fifth failure revoked session 0; it is dead now.
    assert!(
        validate_session_token_chirho(&root_chirho, &principal_chirho, &tokens_chirho[0])
            .unwrap()
            .is_none(),
        "the exhausted session is revoked"
    );
    // The SECOND session is untouched: its own budget, and it is still live.
    assert!(
        validate_session_token_chirho(&root_chirho, &principal_chirho, &tokens_chirho[1])
            .unwrap()
            .is_some(),
        "a different session keeps its own budget and its own life"
    );
    // A sixth attempt from the (now dead) session — even with the CORRECT credential — is refused as
    // guess-exhausted too: the same identity, so the served road always clears the cookie and lands
    // her on login.
    let sixth_chirho = change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &tokens_chirho[0],
        OLD_SECRET_CHIRHO,
        NEW_SECRET_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        credential_change_refusal_token_chirho(&sixth_chirho),
        Some("credential-guess-exhausted-chirho")
    );
    // The owner's LOGIN is untouched by the change door's exhaustion: the right password still
    // signs in (the budgets are separate — no family, no shared bucket).
    assert!(
        login_identity_with_public_auth_limit_chirho(
            &root_chirho,
            &principal_chirho,
            OLD_SECRET_CHIRHO,
            &SignInVelocityChirho::default()
        )
        .is_ok(),
        "exhausting the change door does not lock the owner out of login"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn the_second_session_can_still_change_after_the_first_exhausts_its_budget_chirho() {
    let root_chirho = change_tmp_root_chirho();
    let (principal_chirho, tokens_chirho) = world_chirho(&root_chirho);
    for _ in 0..CREDENTIAL_CHANGE_SESSION_MAX_FAILURES_CHIRHO {
        let _ = change_identity_credential_for_session_chirho(
            &root_chirho,
            &principal_chirho,
            &tokens_chirho[0],
            "not-the-secret-value",
            NEW_SECRET_CHIRHO,
        );
    }
    // Session 1 (never guessed) proves the current credential and changes it successfully.
    change_identity_credential_for_session_chirho(
        &root_chirho,
        &principal_chirho,
        &tokens_chirho[1],
        OLD_SECRET_CHIRHO,
        NEW_SECRET_CHIRHO,
    )
    .expect("a session with budget left changes the credential");
    assert!(
        login_identity_with_credential_chirho(&root_chirho, &principal_chirho, NEW_SECRET_CHIRHO)
            .is_ok(),
        "the new credential is in force"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_stale_proof_cannot_authorize_a_later_change_the_lock_binds_the_proof_to_current_state_chirho()
{
    // F1, deterministic (no sleeps): the lock is the barrier. The main thread takes the credential
    // lock, THEN spawns a second change that blocks on it, then replaces the credential from under
    // the lock, then releases. When the second change finally runs, it verifies the OLD credential
    // against the NOW-CURRENT record and must refuse — the proof is bound to current state, not to
    // the record as it stood when the request arrived.
    let root_chirho = change_tmp_root_chirho();
    let (principal_chirho, tokens_chirho) = world_chirho(&root_chirho);
    const RACED_SECRET_CHIRHO: &str = "raced-new-secret-value";
    const WINNER_SECRET_CHIRHO: &str = "winner-new-secret-value";

    let handle_chirho = seqlog_chirho::with_named_lock_chirho(
        &root_chirho,
        &credential_lock_name_chirho(&principal_chirho),
        || {
            let root_for_thread_chirho = root_chirho.clone();
            let principal_for_thread_chirho = principal_chirho.clone();
            let token_for_thread_chirho = tokens_chirho[1].clone();
            let handle_chirho = std::thread::spawn(move || {
                change_identity_credential_for_session_chirho(
                    &root_for_thread_chirho,
                    &principal_for_thread_chirho,
                    &token_for_thread_chirho,
                    OLD_SECRET_CHIRHO,
                    RACED_SECRET_CHIRHO,
                )
            });
            // Replace the credential while we hold the lock (the locked reset takes no lock itself).
            reset_identity_credential_locked_chirho(
                &root_chirho,
                &principal_chirho,
                WINNER_SECRET_CHIRHO,
                &principal_chirho,
                SELF_SERVICE_CREDENTIAL_CHANGE_REASON_CHIRHO,
                CredentialReplacementCauseChirho::SelfServiceChangeChirho,
            )?;
            Ok::<_, anyhow::Error>(handle_chirho)
        },
    )
    .unwrap();

    let raced_result_chirho = handle_chirho.join().unwrap();
    let error_chirho = raced_result_chirho.expect_err("the raced change must refuse");
    assert_eq!(
        credential_change_refusal_token_chirho(&error_chirho),
        Some("credential-mismatch-chirho"),
        "the stale proof of the old credential does not authorize a change against the new state"
    );
    assert!(
        login_identity_with_credential_chirho(
            &root_chirho,
            &principal_chirho,
            WINNER_SECRET_CHIRHO
        )
        .is_ok(),
        "the winner's credential is in force"
    );
    assert!(
        login_identity_with_credential_chirho(&root_chirho, &principal_chirho, RACED_SECRET_CHIRHO)
            .is_err(),
        "the raced credential was never written"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn an_engine_error_carries_no_customer_token_chirho() {
    let error_chirho = anyhow::anyhow!("identity log failed verification");
    assert_eq!(credential_change_refusal_token_chirho(&error_chirho), None);
}
