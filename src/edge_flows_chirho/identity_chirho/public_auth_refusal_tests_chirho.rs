// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! R12's contract between the engine and the served failure limit: a public auth road's refusal says it RECORDED a
//! failure exactly when it appended one failed attempt row. Pinned on login, token and recover for every kind of
//! refusal each road gives, including one no HTTP request reaches (the engine's own floor check on recover).

use super::*;
use crate::oauth_chirho;

const SECRET_CHIRHO: &str = "refusal-arm-secret-chirho";
const WRONG_CHIRHO: &str = "refusal-arm-wrong-chirho";
const NEW_VALUE_CHIRHO: &str = "refusal-arm-new-value";
const WRONG_CODE_CHIRHO: &str = "0000-0000-0000-0000-0000-0000";

fn failure_rows_chirho(root_chirho: &Path) -> usize {
    load_auth_attempts_chirho(root_chirho)
        .unwrap()
        .iter()
        .filter(|row_chirho| {
            row_chirho.outcome_chirho == IdentityAuthAttemptOutcomeChirho::FailureChirho
        })
        .count()
}

/// Run one attempt that must be refused, and check its flag against the failed rows it appended: one when it says
/// recorded, none when it does not.
fn assert_refusal_chirho<OutputChirho>(
    root_chirho: &Path,
    what_chirho: &str,
    recorded_chirho: bool,
    attempt_chirho: impl FnOnce() -> std::result::Result<OutputChirho, PublicAuthRefusalChirho>,
) -> anyhow::Error {
    let before_chirho = failure_rows_chirho(root_chirho);
    let refusal_chirho = match attempt_chirho() {
        Ok(_) => panic!("{what_chirho}: expected a refusal"),
        Err(refusal_chirho) => refusal_chirho,
    };
    assert_eq!(
        refusal_chirho.failure_recorded_chirho, recorded_chirho,
        "{what_chirho}: {:#}",
        refusal_chirho.error_chirho
    );
    assert_eq!(
        failure_rows_chirho(root_chirho),
        before_chirho + usize::from(recorded_chirho),
        "{what_chirho}: the flag says exactly whether a failed row was appended"
    );
    refusal_chirho.error_chirho
}

/// Login: a refused credential records one failed row; a refusal by the principal's own limit records nothing.
#[test]
fn login_records_a_failure_only_for_a_refused_credential_chirho() {
    let root_chirho = tmp_root_chirho();
    let principal_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let one_per_hour_chirho = SignInVelocityChirho {
        principal_successes_per_hour_chirho: 1,
    };
    let login_chirho = |credential_chirho: &str| {
        login_identity_with_public_auth_limit_outcome_chirho(
            &root_chirho,
            &principal_chirho,
            credential_chirho,
            AUTH_ENDPOINT_LOGIN_CHIRHO,
            &one_per_hour_chirho,
        )
    };
    assert_refusal_chirho(&root_chirho, "a wrong credential", true, || {
        login_chirho(WRONG_CHIRHO)
    });
    login_chirho(SECRET_CHIRHO)
        .map_err(|refusal_chirho| refusal_chirho.error_chirho)
        .expect("the hour's one sign-in");
    let limited_chirho = assert_refusal_chirho(
        &root_chirho,
        "past the principal's own limit",
        false,
        || login_chirho(SECRET_CHIRHO),
    );
    assert!(
        is_auth_rate_limit_error_chirho(&limited_chirho),
        "{limited_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Token: the policy and client checks come before the sign-in and the live-key cap after a proved credential, so
/// none of them records; only a refused credential does.
#[test]
fn the_token_road_records_a_failure_only_for_a_refused_credential_chirho() {
    let root_chirho = tmp_root_chirho();
    let principal_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let owner_chirho =
        register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho).unwrap();
    let client_id_chirho = oauth_chirho::register_client_chirho(
        &root_chirho,
        "refusal-arm-app",
        &owner_chirho.principal_chirho,
    )
    .unwrap()
    .client_id_chirho;
    let velocity_chirho = SignInVelocityChirho {
        principal_successes_per_hour_chirho: 1_000,
    };
    let issue_chirho =
        |credential_chirho: &str,
         client_chirho: &str,
         rate_limit_chirho: Option<oauth_chirho::ScopedTokenRateLimitChirho>| {
            oauth_chirho::issue_scoped_token_with_public_auth_limit_outcome_chirho(
                &root_chirho,
                &principal_chirho,
                credential_chirho,
                client_chirho,
                vec!["invoke_chirho".to_string()],
                rate_limit_chirho,
                &velocity_chirho,
            )
        };
    assert_refusal_chirho(&root_chirho, "an unknown client", false, || {
        issue_chirho(SECRET_CHIRHO, "client/unknown-chirho", None)
    });
    let above_chirho = oauth_chirho::ScopedTokenRateLimitChirho {
        window_ms_chirho: 7_200_000,
        max_invokes_chirho: 10,
        device_id_chirho: None,
    };
    assert_refusal_chirho(&root_chirho, "a policy above the ceiling", false, || {
        issue_chirho(SECRET_CHIRHO, &client_id_chirho, Some(above_chirho))
    });
    assert_refusal_chirho(&root_chirho, "a wrong credential", true, || {
        issue_chirho(WRONG_CHIRHO, &client_id_chirho, None)
    });
    for _ in 0..oauth_chirho::LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO {
        issue_chirho(SECRET_CHIRHO, &client_id_chirho, None)
            .map_err(|refusal_chirho| refusal_chirho.error_chirho)
            .expect("under the live-key cap");
    }
    let capped_chirho = assert_refusal_chirho(&root_chirho, "past the live-key cap", false, || {
        issue_chirho(SECRET_CHIRHO, &client_id_chirho, None)
    });
    assert!(
        capped_chirho
            .downcast_ref::<oauth_chirho::ScopedTokenCapReachedChirho>()
            .is_some(),
        "{capped_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Recover: the engine's own floor check and a refusal by the principal's limiter record nothing; the uniform refusal
/// records one failed row each time, for an invented principal and a real one alike.
#[test]
fn recover_records_a_failure_only_for_the_uniform_refusal_chirho() {
    let root_chirho = tmp_root_chirho();
    let invited_chirho =
        invite_identity_chirho(&root_chirho, PrincipalKindChirho::UserChirho).unwrap();
    let redeem_chirho = |principal_chirho: &str, code_chirho: &str, new_chirho: &str| {
        redeem_recovery_code_with_public_limit_outcome_chirho(
            &root_chirho,
            principal_chirho,
            code_chirho,
            new_chirho,
        )
    };
    assert_refusal_chirho(
        &root_chirho,
        "a weak new password, at the engine's floor",
        false,
        || {
            redeem_chirho(
                &invited_chirho.principal_chirho,
                &invited_chirho.recovery_code_chirho,
                "short",
            )
        },
    );
    assert_refusal_chirho(&root_chirho, "an invented principal", true, || {
        redeem_chirho("user/0123456789abcdef", WRONG_CODE_CHIRHO, NEW_VALUE_CHIRHO)
    });
    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
        assert_refusal_chirho(&root_chirho, "a wrong code", true, || {
            redeem_chirho(
                &invited_chirho.principal_chirho,
                WRONG_CODE_CHIRHO,
                NEW_VALUE_CHIRHO,
            )
        });
    }
    let limited_chirho =
        assert_refusal_chirho(&root_chirho, "past the principal's limiter", false, || {
            redeem_chirho(
                &invited_chirho.principal_chirho,
                &invited_chirho.recovery_code_chirho,
                NEW_VALUE_CHIRHO,
            )
        });
    assert!(
        is_auth_rate_limit_error_chirho(&limited_chirho),
        "{limited_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
