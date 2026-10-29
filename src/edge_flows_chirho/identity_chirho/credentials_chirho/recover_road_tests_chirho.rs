// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! R2b's engine arms: the anonymous road's limiter and attempt rows around R2a's redemption
//! (`redeem_recovery_code_with_public_limit_chirho`), and its growth arm. Each refusal asserts its identity, and a
//! limiter refusal also asserts the root is byte-unchanged, so a refusal that did any work fails by name.
//! Migration paths: an arm that reds because the limit moved from five failures is a retarget only with a ruling (the
//! constant is login's, shared by design); one that reds because a refusal now writes is a regression.
//!
//! R13's arms (PFE #26146, #26147), at the end: where an internal failure stopped against the one commit point. Each
//! asserts the flag the served road maps to its token AND the fact the token's words claim. Before the commit point:
//! the credential unchanged and the SAME code redeeming afterwards. At or after it: the change may have applied. A
//! fixture that changes a file's mode first proves the mode took effect, so an arm cannot pass as root by accident.

use super::recovery_code_redeem_chirho::{
    act_phase_chirho, lock_failure_phase_chirho, RedemptionFailureChirho, RedemptionPhaseChirho,
};
use super::recovery_code_tests_chirho::{
    code_tmp_root_chirho, refusal_writes_chirho, root_snapshot_chirho, signs_in_chirho,
    FIRST_CHIRHO, SECOND_CHIRHO,
};
use super::*;

/// The `recover-chirho` attempt rows for one principal, in order: what the limiter and the audit read.
fn recover_rows_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Vec<IdentityAuthAttemptOutcomeChirho> {
    let digest_chirho = auth_attempt_principal_hash_chirho(principal_chirho);
    load_auth_attempts_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|row_chirho| {
            row_chirho.endpoint_chirho == AUTH_ENDPOINT_RECOVER_CHIRHO
                && row_chirho.principal_hash_chirho == digest_chirho
        })
        .map(|row_chirho| row_chirho.outcome_chirho)
        .collect()
}

fn invited_chirho(root_chirho: &Path) -> IssuedRecoveryCodeChirho {
    invite_identity_chirho(root_chirho, PrincipalKindChirho::UserChirho).unwrap()
}

/// A wrong code typed for a principal: refused with the uniform refusal.
fn wrong_code_chirho(root_chirho: &Path, principal_chirho: &str) -> anyhow::Error {
    redeem_recovery_code_with_public_limit_chirho(
        root_chirho,
        principal_chirho,
        "0000-0000-0000-0000-0000-0000",
        FIRST_CHIRHO,
    )
    .unwrap_err()
}

fn is_uniform_refusal_chirho(error_chirho: &anyhow::Error) -> bool {
    error_chirho.downcast_ref::<RecoveryCodeRefusalChirho>()
        == Some(&RecoveryCodeRefusalChirho::RecoveryRefusedChirho)
}

/// The rate refusal R2b's served road answers `rate-limited-chirho` for: the principal's failed attempts.
fn is_failure_limit_chirho(error_chirho: &anyhow::Error) -> bool {
    error_chirho
        .downcast_ref::<AuthRateLimitExceededChirho>()
        .is_some_and(|limit_chirho| {
            limit_chirho.reason_chirho == AuthRateLimitReasonChirho::FailedAttemptsChirho
                && limit_chirho.endpoint_chirho == AUTH_ENDPOINT_RECOVER_CHIRHO
        })
}

/// Whole control-plane log loads on this thread (the identity log among them), from the verified-view cache's metrics.
fn full_log_loads_chirho() -> u64 {
    cairn_verified_view_cache_chirho::test_metrics_chirho::snapshot_chirho().full_log_loads_chirho
}

#[test]
fn one_failure_row_for_the_uniform_refusal_and_one_success_row_for_the_act_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho
    )));
    assert_eq!(
        recover_rows_chirho(&root_chirho, &issued_chirho.principal_chirho),
        vec![IdentityAuthAttemptOutcomeChirho::FailureChirho]
    );
    redeem_recovery_code_with_public_limit_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        recover_rows_chirho(&root_chirho, &issued_chirho.principal_chirho),
        vec![
            IdentityAuthAttemptOutcomeChirho::FailureChirho,
            IdentityAuthAttemptOutcomeChirho::SuccessChirho
        ]
    );
    // The road's rows are its own: nothing was written under login's endpoint.
    assert!(load_auth_attempts_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|row_chirho| row_chirho.endpoint_chirho == AUTH_ENDPOINT_RECOVER_CHIRHO));
}

#[test]
fn an_invented_principal_gets_the_same_refusal_and_the_same_one_row_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let _issued_chirho = invited_chirho(&root_chirho);
    let invented_chirho = "user/0123456789abcdef";
    assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
        &root_chirho,
        invented_chirho
    )));
    assert_eq!(
        recover_rows_chirho(&root_chirho, invented_chirho),
        vec![IdentityAuthAttemptOutcomeChirho::FailureChirho]
    );
}

#[test]
fn the_floor_refusal_writes_nothing_and_charges_nothing_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let before_chirho = root_snapshot_chirho(&root_chirho);
    let error_chirho = redeem_recovery_code_with_public_limit_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &issued_chirho.recovery_code_chirho,
        "fourteen-chars",
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.downcast_ref::<RecoveryCodeRefusalChirho>(),
        Some(&RecoveryCodeRefusalChirho::CredentialTooWeakChirho)
    );
    assert_eq!(
        refusal_writes_chirho(&before_chirho, &root_snapshot_chirho(&root_chirho)),
        Vec::<PathBuf>::new()
    );
}

/// Five failures refuse the sixth BEFORE any work, even with the right code: no row, no lock, no key write, and the
/// same refusal for a real principal and an invented one.
#[test]
fn five_failures_refuse_the_sixth_before_any_work_for_real_and_invented_alike_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let invented_chirho = "user/0123456789abcdef";
    for principal_chirho in [issued_chirho.principal_chirho.as_str(), invented_chirho] {
        for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
            assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
                &root_chirho,
                principal_chirho
            )));
        }
    }
    let before_chirho = root_snapshot_chirho(&root_chirho);
    let real_chirho = redeem_recovery_code_with_public_limit_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap_err();
    let invented_error_chirho = wrong_code_chirho(&root_chirho, invented_chirho);
    assert!(
        is_failure_limit_chirho(&real_chirho),
        "the real principal: {real_chirho:#}"
    );
    assert!(
        is_failure_limit_chirho(&invented_error_chirho),
        "the invented one: {invented_error_chirho:#}"
    );
    assert_eq!(
        refusal_writes_chirho(&before_chirho, &root_snapshot_chirho(&root_chirho)),
        Vec::<PathBuf>::new()
    );
    assert_eq!(
        recover_rows_chirho(&root_chirho, &issued_chirho.principal_chirho).len() as u64,
        PUBLIC_AUTH_MAX_FAILURES_CHIRHO
    );
}

/// The limiter counts failures after the principal's latest success on this road, as login's does.
#[test]
fn a_success_clears_the_failure_count_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO - 1 {
        wrong_code_chirho(&root_chirho, &issued_chirho.principal_chirho);
    }
    redeem_recovery_code_with_public_limit_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap();
    let again_chirho =
        mint_operator_recovery_code_chirho(&root_chirho, &issued_chirho.principal_chirho).unwrap();
    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
        assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
            &root_chirho,
            &issued_chirho.principal_chirho
        )));
    }
    let limited_chirho = redeem_recovery_code_with_public_limit_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &again_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap_err();
    assert!(
        is_failure_limit_chirho(&limited_chirho),
        "{limited_chirho:#}"
    );
}

/// The road keeps its own budget (decision 8), in both directions: five failed sign-ins leave recover open, and five
/// failed recovers leave sign-in open, so neither door can lock the owner out of the other.
#[test]
fn the_recover_budget_is_its_own_apart_from_logins_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let velocity_chirho = SignInVelocityChirho::default();
    let set_up_chirho = |issued_chirho: &IssuedRecoveryCodeChirho| {
        redeem_recovery_code_with_public_limit_chirho(
            &root_chirho,
            &issued_chirho.principal_chirho,
            &issued_chirho.recovery_code_chirho,
            FIRST_CHIRHO,
        )
        .unwrap();
    };
    // A: failed sign-ins do not limit recover.
    let a_chirho = invited_chirho(&root_chirho);
    set_up_chirho(&a_chirho);
    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
        login_identity_with_public_auth_limit_chirho(
            &root_chirho,
            &a_chirho.principal_chirho,
            "a-wrong-credential-value",
            &velocity_chirho,
        )
        .unwrap_err();
    }
    let a_again_chirho =
        mint_operator_recovery_code_chirho(&root_chirho, &a_chirho.principal_chirho).unwrap();
    redeem_recovery_code_with_public_limit_chirho(
        &root_chirho,
        &a_chirho.principal_chirho,
        &a_again_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    // B: failed recovers do not limit sign-in.
    let b_chirho = invited_chirho(&root_chirho);
    set_up_chirho(&b_chirho);
    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
        assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
            &root_chirho,
            &b_chirho.principal_chirho
        )));
    }
    assert!(is_failure_limit_chirho(&wrong_code_chirho(
        &root_chirho,
        &b_chirho.principal_chirho
    )));
    login_identity_with_public_auth_limit_chirho(
        &root_chirho,
        &b_chirho.principal_chirho,
        FIRST_CHIRHO,
        &velocity_chirho,
    )
    .unwrap();
}

/// The recover road's growth arm (the growth gate names it): at 1, 10 and 100 sessions, clients and identities, a warm
/// REFUSED attempt loads no identity log (its existence check reads the cached verified map) and parses neither the
/// session log nor the client log, and a successful one parses no client log. The gate
/// reaches the client log from this road only through the shared prefix-view engine's generic fold (the token view's,
/// whose fold reads clients), which this road never folds. A success genuinely verifies the principal's sessions
/// (R2a's stated cost, a Debt row), so only the refused attempt is held to zero session parses.
#[test]
fn a_warm_recover_reads_no_identity_or_client_log_and_a_refused_one_no_session_log_at_any_history_chirho(
) {
    let mut per_history_chirho = Vec::new();
    for history_chirho in [1usize, 10, 100] {
        let root_chirho = code_tmp_root_chirho();
        let owner_chirho =
            register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho).unwrap();
        let other_chirho =
            register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
        for n_chirho in 0..history_chirho {
            register_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
            login_identity_chirho(&root_chirho, &other_chirho.principal_chirho).unwrap();
            crate::oauth_chirho::register_client_chirho(
                &root_chirho,
                &format!("app-{n_chirho}"),
                &owner_chirho.principal_chirho,
            )
            .unwrap();
        }
        let issued_chirho = invited_chirho(&root_chirho);
        // The first refusal builds the attempt view; the second is the warm one measured.
        wrong_code_chirho(&root_chirho, &issued_chirho.principal_chirho);
        let sessions_chirho = session_read_metrics_chirho::count_chirho();
        let clients_chirho = crate::oauth_chirho::token_view_metrics_chirho::client_reads_chirho();
        let loads_chirho = full_log_loads_chirho();
        wrong_code_chirho(&root_chirho, &issued_chirho.principal_chirho);
        let refused_chirho = (
            full_log_loads_chirho() - loads_chirho,
            session_read_metrics_chirho::count_chirho() - sessions_chirho,
            crate::oauth_chirho::token_view_metrics_chirho::client_reads_chirho() - clients_chirho,
        );
        let clients_chirho = crate::oauth_chirho::token_view_metrics_chirho::client_reads_chirho();
        redeem_recovery_code_with_public_limit_chirho(
            &root_chirho,
            &issued_chirho.principal_chirho,
            &issued_chirho.recovery_code_chirho,
            FIRST_CHIRHO,
        )
        .unwrap();
        per_history_chirho.push((
            refused_chirho,
            crate::oauth_chirho::token_view_metrics_chirho::client_reads_chirho() - clients_chirho,
        ));
        // The control: the counters see a direct load on this thread.
        let loads_chirho = full_log_loads_chirho();
        load_identities_chirho(&root_chirho).unwrap();
        assert_eq!(
            full_log_loads_chirho(),
            loads_chirho + 1,
            "the identity-load counter is live"
        );
        let sessions_chirho = session_read_metrics_chirho::count_chirho();
        let clients_chirho = crate::oauth_chirho::token_view_metrics_chirho::client_reads_chirho();
        load_sessions_chirho(&root_chirho).unwrap();
        crate::oauth_chirho::load_clients_chirho(&root_chirho).unwrap();
        assert_eq!(
            session_read_metrics_chirho::count_chirho(),
            sessions_chirho + 1
        );
        assert_eq!(
            crate::oauth_chirho::token_view_metrics_chirho::client_reads_chirho(),
            clients_chirho + 1
        );
    }
    assert_eq!(
        per_history_chirho,
        vec![((0, 0, 0), 0); 3],
        "((identity loads, session parses, client parses) per warm refusal, client parses per success) at 1, 10 and 100"
    );
}

// ---------------------------------------------------------------- R13: the phase of an internal failure

fn outcome_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    code_chirho: &str,
    credential_chirho: &str,
) -> std::result::Result<IdentityCredentialResetReportChirho, PublicAuthRefusalChirho> {
    redeem_recovery_code_with_public_limit_outcome_chirho(
        root_chirho,
        principal_chirho,
        code_chirho,
        credential_chirho,
    )
}

/// The code still held in the key record: not consumed.
fn code_held_chirho(root_chirho: &Path, principal_chirho: &str) -> bool {
    stored_recovery_code_chirho(
        &load_identity_key_record_chirho(root_chirho, principal_chirho).unwrap(),
    )
    .unwrap()
    .is_some()
}

#[cfg(unix)]
fn set_mode_chirho(path_chirho: &Path, mode_chirho: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(mode_chirho)).unwrap();
}

/// PFE's arm (e), the honesty limit itself: a recovering user with two live sessions, a failure injected AFTER the
/// revocations, at the salt and hash step. The flag says not set; both sessions are ended (so "nothing changed" would
/// be false); the old password still signs in; the code is not consumed; and the SAME code then redeems.
#[test]
fn a_failure_after_the_revocations_is_not_set_ends_the_sessions_and_leaves_the_code_working_chirho()
{
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
    credential_fault_points_chirho::arm_chirho(
        credential_fault_points_chirho::CredentialFaultPointChirho::SaltAndHashChirho,
    );
    let refusal_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap_err();
    assert!(
        format!("{:#}", refusal_chirho.error_chirho)
            .contains("injected fault at SaltAndHashChirho"),
        "the fault point fired, not another failure: {:#}",
        refusal_chirho.error_chirho
    );
    assert!(
        refusal_chirho.credential_unchanged_chirho,
        "a failure before the commit point is known not set"
    );
    assert!(
        !refusal_chirho.failure_recorded_chirho,
        "an internal failure records no failed row"
    );
    for token_chirho in &tokens_chirho {
        assert!(
            validate_session_token_chirho(&root_chirho, &principal_chirho, token_chirho)
                .unwrap()
                .is_none(),
            "revocation ran before the failure, so the sessions are ended: the copy must not say nothing changed"
        );
    }
    assert!(
        code_held_chirho(&root_chirho, &principal_chirho),
        "the code is not consumed"
    );
    assert!(
        signs_in_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO),
        "the password was not set"
    );
    assert!(!signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        SECOND_CHIRHO
    ));
    outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    assert!(
        signs_in_chirho(&root_chirho, &principal_chirho, SECOND_CHIRHO),
        "the same code redeemed"
    );
    assert!(!code_held_chirho(&root_chirho, &principal_chirho));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// After the commit point (PFE's arm (c), at the engine): a failure at the read-back proof, after a write that
/// succeeded. The flag says not known; the new password IS set and the code IS consumed, so "may have applied" is
/// the true answer.
#[test]
fn a_failure_after_the_write_may_have_applied_and_the_new_password_is_set_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let principal_chirho = issued_chirho.principal_chirho.clone();
    credential_fault_points_chirho::arm_chirho(
        credential_fault_points_chirho::CredentialFaultPointChirho::ReadBackChirho,
    );
    let refusal_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap_err();
    assert!(
        format!("{:#}", refusal_chirho.error_chirho).contains("injected fault at ReadBackChirho"),
        "the fault point fired: {:#}",
        refusal_chirho.error_chirho
    );
    assert!(
        !refusal_chirho.credential_unchanged_chirho,
        "after the write, the change may have applied"
    );
    assert!(
        signs_in_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO),
        "the credential IS set"
    );
    let again_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap_err();
    assert!(
        is_uniform_refusal_chirho(&again_chirho.error_chirho),
        "the code IS consumed"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Inside the lock, before the code is compared: PFE's measured case, a key record the service cannot read. Not set,
/// and once the record is readable again the SAME code redeems.
#[cfg(unix)]
#[test]
fn an_unreadable_key_record_is_not_set_and_the_same_code_redeems_once_it_is_readable_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let principal_chirho = issued_chirho.principal_chirho.clone();
    let key_path_chirho = identity_key_path_chirho(&root_chirho, &principal_chirho);
    set_mode_chirho(&key_path_chirho, 0o000);
    assert!(
        std::fs::read(&key_path_chirho).is_err(),
        "the mode did not take effect: run this arm as a non-root user"
    );
    let refusal_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap_err();
    assert!(
        refusal_chirho.credential_unchanged_chirho,
        "{:#}",
        refusal_chirho.error_chirho
    );
    assert!(!refusal_chirho.failure_recorded_chirho);
    set_mode_chirho(&key_path_chirho, 0o600);
    outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap();
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        FIRST_CHIRHO
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The write ITSELF fails (the keys folder read-only, so the temp file cannot be made): its error is never claimed as
/// not set, since a write's error can follow its rename. Here it did not, so afterwards the same code still redeems:
/// "may have applied" is the conservative answer, not a false one.
#[cfg(unix)]
#[test]
fn a_failed_key_record_write_is_not_claimed_as_not_set_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let principal_chirho = issued_chirho.principal_chirho.clone();
    let keys_chirho = identity_key_path_chirho(&root_chirho, &principal_chirho)
        .parent()
        .unwrap()
        .to_path_buf();
    set_mode_chirho(&keys_chirho, 0o555);
    assert!(
        std::fs::write(keys_chirho.join("probe-chirho"), b"x").is_err(),
        "the mode did not take effect: run this arm as a non-root user"
    );
    let refusal_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap_err();
    assert!(
        !refusal_chirho.credential_unchanged_chirho,
        "the write's own error may have applied: {:#}",
        refusal_chirho.error_chirho
    );
    set_mode_chirho(&keys_chirho, 0o755);
    assert!(code_held_chirho(&root_chirho, &principal_chirho));
    outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The uniform refusal's failure row cannot be appended (the attempts log read-only). The refusal set nothing, so it is
/// not set, and nothing was recorded. The control proves the limiter still READS that log, so the failure is the
/// append's and not the limiter's.
#[cfg(unix)]
#[test]
fn a_failure_row_that_cannot_be_appended_after_the_uniform_refusal_is_not_set_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let principal_chirho = issued_chirho.principal_chirho.clone();
    assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
        &root_chirho,
        &principal_chirho
    )));
    let log_chirho = auth_attempts_path_chirho(&root_chirho);
    set_mode_chirho(&log_chirho, 0o444);
    assert!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log_chirho)
            .is_err(),
        "the mode did not take effect: run this arm as a non-root user"
    );
    ensure_public_auth_attempt_allowed_chirho(
        &root_chirho,
        &principal_chirho,
        AUTH_ENDPOINT_RECOVER_CHIRHO,
    )
    .expect("the control: the limiter still reads a read-only log");
    let refusal_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        "0000-0000-0000-0000-0000-0000",
        FIRST_CHIRHO,
    )
    .unwrap_err();
    assert!(
        !is_uniform_refusal_chirho(&refusal_chirho.error_chirho),
        "the append's failure, not the refusal itself"
    );
    assert!(
        refusal_chirho.credential_unchanged_chirho,
        "{:#}",
        refusal_chirho.error_chirho
    );
    assert!(!refusal_chirho.failure_recorded_chirho);
    set_mode_chirho(&log_chirho, 0o600);
    assert_eq!(
        recover_rows_chirho(&root_chirho, &principal_chirho),
        vec![IdentityAuthAttemptOutcomeChirho::FailureChirho],
        "only the first refusal's row exists"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// After the commit point, in the outcome: the success row cannot be appended (the attempts log read-only). The
/// credential IS set, so the flag stays "may have applied", and the new password signs in.
#[cfg(unix)]
#[test]
fn a_success_row_that_cannot_be_appended_may_have_applied_and_the_password_is_set_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let principal_chirho = issued_chirho.principal_chirho.clone();
    assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
        &root_chirho,
        &principal_chirho
    )));
    let log_chirho = auth_attempts_path_chirho(&root_chirho);
    set_mode_chirho(&log_chirho, 0o444);
    assert!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log_chirho)
            .is_err(),
        "the mode did not take effect: run this arm as a non-root user"
    );
    let outcome_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    );
    set_mode_chirho(&log_chirho, 0o600);
    let refusal_chirho = outcome_chirho.expect_err("the success row could not be appended");
    assert!(
        !refusal_chirho.credential_unchanged_chirho,
        "{:#}",
        refusal_chirho.error_chirho
    );
    assert!(
        !code_held_chirho(&root_chirho, &principal_chirho),
        "the code IS consumed"
    );
    assert!(
        signs_in_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO),
        "the credential IS set"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The limiter's own failure (the attempts log unreadable): nothing was compared, so not set, and the code is held.
#[cfg(unix)]
#[test]
fn a_limiter_that_cannot_read_its_log_is_not_set_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let principal_chirho = issued_chirho.principal_chirho.clone();
    assert!(is_uniform_refusal_chirho(&wrong_code_chirho(
        &root_chirho,
        &principal_chirho
    )));
    let log_chirho = auth_attempts_path_chirho(&root_chirho);
    set_mode_chirho(&log_chirho, 0o000);
    assert!(
        std::fs::read(&log_chirho).is_err(),
        "the mode did not take effect: run this arm as a non-root user"
    );
    let outcome_chirho = outcome_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    );
    set_mode_chirho(&log_chirho, 0o600);
    let refusal_chirho = outcome_chirho.expect_err("the limiter could not read its log");
    assert!(
        !is_failure_limit_chirho(&refusal_chirho.error_chirho),
        "an internal failure, not a rate refusal"
    );
    assert!(
        refusal_chirho.credential_unchanged_chirho,
        "{:#}",
        refusal_chirho.error_chirho
    );
    assert!(!refusal_chirho.failure_recorded_chirho);
    assert!(
        code_held_chirho(&root_chirho, &principal_chirho),
        "nothing was compared or consumed"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Before the lock: an identity log that fails verification. Not set, and no failed row.
#[test]
fn an_identity_log_that_fails_verification_is_not_set_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let issued_chirho = invited_chirho(&root_chirho);
    let log_chirho = identities_path_chirho(&root_chirho);
    let mut text_chirho = std::fs::read_to_string(&log_chirho).unwrap();
    let mut forged_chirho: serde_json::Value =
        serde_json::from_str(text_chirho.lines().next().unwrap()).unwrap();
    forged_chirho["seq_chirho"] = serde_json::json!(text_chirho.lines().count());
    forged_chirho["principal_chirho"] = serde_json::json!("user/ffffffffffffffff");
    forged_chirho["sig_chirho"] = serde_json::json!("00".repeat(64));
    text_chirho.push_str(&forged_chirho.to_string());
    text_chirho.push('\n');
    std::fs::write(&log_chirho, text_chirho).unwrap();
    let refusal_chirho = outcome_chirho(
        &root_chirho,
        &issued_chirho.principal_chirho,
        &issued_chirho.recovery_code_chirho,
        FIRST_CHIRHO,
    )
    .unwrap_err();
    assert!(
        !is_uniform_refusal_chirho(&refusal_chirho.error_chirho),
        "an internal failure, not the uniform refusal"
    );
    assert!(
        refusal_chirho.credential_unchanged_chirho,
        "{:#}",
        refusal_chirho.error_chirho
    );
    assert!(!refusal_chirho.failure_recorded_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The principal lock's own failure: before the act ran, nothing was set. After it ran, only the unlock can fail, and
/// it is returned IN PLACE OF the act's outcome, so a success, or a failure at or after the commit point, may have
/// applied, while a failure before the commit point stays not set.
#[test]
fn a_failure_of_the_lock_itself_is_not_set_only_when_the_act_did_not_set_it_chirho() {
    assert_eq!(
        lock_failure_phase_chirho(None),
        RedemptionPhaseChirho::CredentialUnchangedChirho
    );
    assert_eq!(
        lock_failure_phase_chirho(Some(RedemptionPhaseChirho::MayHaveAppliedChirho)),
        RedemptionPhaseChirho::MayHaveAppliedChirho,
        "an unlock that fails after a success must not read as not set"
    );
    assert_eq!(
        lock_failure_phase_chirho(Some(RedemptionPhaseChirho::CredentialUnchangedChirho)),
        RedemptionPhaseChirho::CredentialUnchangedChirho
    );
    // The act's own phase, which the lock's failure reads: a success under the lock HAS applied.
    assert_eq!(
        act_phase_chirho::<()>(&Ok(())),
        RedemptionPhaseChirho::MayHaveAppliedChirho,
        "a success under the lock has applied, so a later unlock failure must not read as not set"
    );
    for phase_chirho in [
        RedemptionPhaseChirho::CredentialUnchangedChirho,
        RedemptionPhaseChirho::MayHaveAppliedChirho,
    ] {
        let failure_chirho: std::result::Result<(), RedemptionFailureChirho> =
            Err(RedemptionFailureChirho {
                error_chirho: anyhow::anyhow!("a failure"),
                phase_chirho,
            });
        assert_eq!(act_phase_chirho(&failure_chirho), phase_chirho);
    }
}
