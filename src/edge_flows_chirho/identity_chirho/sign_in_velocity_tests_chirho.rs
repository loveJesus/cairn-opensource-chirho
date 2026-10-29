// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! THE SIGN-IN VELOCITY LIMIT for one principal (brick 4a; PFE #25922, agy #25924): past it, every attempt is refused
//! BEFORE its credential is checked, identically for a right and a wrong password; a wrong password never counts as a
//! sign-in; and login and scoped-token issue share one count.

use super::super::credentials_chirho::credential_verification_metrics_chirho as verifications_chirho;
use super::*;

const SECRET_CHIRHO: &str = "velocity-arm-secret-chirho";
const WRONG_CHIRHO: &str = "velocity-arm-wrong-chirho";

fn velocity_chirho(per_hour_chirho: u64) -> SignInVelocityChirho {
    SignInVelocityChirho {
        principal_successes_per_hour_chirho: per_hour_chirho,
    }
}

fn sign_in_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    endpoint_chirho: &str,
    velocity_chirho: &SignInVelocityChirho,
) -> Result<IdentityLoginResultChirho> {
    login_identity_with_public_auth_limit_for_endpoint_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
        endpoint_chirho,
        velocity_chirho,
    )
}

fn assert_velocity_refusal_chirho(refusal_chirho: &anyhow::Error) {
    assert!(
        is_auth_rate_limit_error_chirho(refusal_chirho),
        "{refusal_chirho:#}"
    );
    assert_eq!(
        refusal_chirho
            .downcast_ref::<AuthRateLimitExceededChirho>()
            .map(|limit_chirho| limit_chirho.reason_chirho),
        Some(AuthRateLimitReasonChirho::PrincipalSignInsChirho),
        "{refusal_chirho:#}"
    );
}

/// THE NO-ORACLE ARM: past the limit, a right and a wrong password get the same refusal, and neither costs a
/// credential check, an attempt record or a session.
///
/// MIGRATION PATH: a credential verified, an attempt recorded, or two different refusals means the check moved after
/// verification, where "rate-limited" would tell an attacker their guess was right.
#[test]
fn past_the_limit_a_right_and_a_wrong_password_are_refused_alike_before_any_credential_work_chirho()
{
    let root_chirho = tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.as_str();
    let limit_chirho = velocity_chirho(3);
    for _ in 0..3 {
        sign_in_chirho(
            &root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            AUTH_ENDPOINT_LOGIN_CHIRHO,
            &limit_chirho,
        )
        .expect("under the limit, the right password signs in");
    }
    let attempts_before_chirho = load_auth_attempts_chirho(&root_chirho).unwrap().len();
    let sessions_before_chirho = load_sessions_chirho(&root_chirho).unwrap().len();
    let verifications_before_chirho = verifications_chirho::count_chirho();

    let right_chirho = sign_in_chirho(
        &root_chirho,
        principal_chirho,
        SECRET_CHIRHO,
        AUTH_ENDPOINT_LOGIN_CHIRHO,
        &limit_chirho,
    )
    .expect_err("the fourth sign-in in the hour is refused");
    let wrong_chirho = sign_in_chirho(
        &root_chirho,
        principal_chirho,
        WRONG_CHIRHO,
        AUTH_ENDPOINT_LOGIN_CHIRHO,
        &limit_chirho,
    )
    .expect_err("a wrong password is refused too");
    assert_velocity_refusal_chirho(&right_chirho);
    assert_velocity_refusal_chirho(&wrong_chirho);
    assert_eq!(
        format!("{right_chirho:#}"),
        format!("{wrong_chirho:#}"),
        "one refusal for a right and a wrong password"
    );
    assert_eq!(
        verifications_chirho::count_chirho(),
        verifications_before_chirho,
        "no credential was verified"
    );
    assert_eq!(
        load_auth_attempts_chirho(&root_chirho).unwrap().len(),
        attempts_before_chirho
    );
    assert_eq!(
        load_sessions_chirho(&root_chirho).unwrap().len(),
        sessions_before_chirho
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Only a successful sign-in counts: wrong passwords (fewer than the failure lockout's five) leave the count alone.
#[test]
fn a_wrong_password_never_counts_as_a_sign_in_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.as_str();
    let limit_chirho = velocity_chirho(3);
    for _ in 0..2 {
        sign_in_chirho(
            &root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            AUTH_ENDPOINT_LOGIN_CHIRHO,
            &limit_chirho,
        )
        .unwrap();
    }
    for _ in 0..PUBLIC_AUTH_MAX_FAILURES_CHIRHO - 1 {
        let refusal_chirho = sign_in_chirho(
            &root_chirho,
            principal_chirho,
            WRONG_CHIRHO,
            AUTH_ENDPOINT_LOGIN_CHIRHO,
            &limit_chirho,
        )
        .expect_err("a wrong password is refused");
        assert!(
            !is_auth_rate_limit_error_chirho(&refusal_chirho),
            "{refusal_chirho:#}"
        );
    }
    sign_in_chirho(
        &root_chirho,
        principal_chirho,
        SECRET_CHIRHO,
        AUTH_ENDPOINT_LOGIN_CHIRHO,
        &limit_chirho,
    )
    .expect("the third success: the wrong passwords did not count");
    assert_velocity_refusal_chirho(
        &sign_in_chirho(
            &root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            AUTH_ENDPOINT_LOGIN_CHIRHO,
            &limit_chirho,
        )
        .expect_err("the fourth success is refused"),
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A scoped-token issue is a sign-in too: both endpoints create a session, so they share one count.
#[test]
fn login_and_token_issue_share_one_count_chirho() {
    let root_chirho = tmp_root_chirho();
    let identity_chirho = register_identity_with_credential_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap();
    let principal_chirho = identity_chirho.principal_chirho.as_str();
    let limit_chirho = velocity_chirho(3);
    for endpoint_chirho in [
        AUTH_ENDPOINT_LOGIN_CHIRHO,
        AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
        AUTH_ENDPOINT_LOGIN_CHIRHO,
    ] {
        sign_in_chirho(
            &root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            endpoint_chirho,
            &limit_chirho,
        )
        .unwrap();
    }
    for endpoint_chirho in SESSION_CREATING_AUTH_ENDPOINTS_CHIRHO {
        assert_velocity_refusal_chirho(
            &sign_in_chirho(
                &root_chirho,
                principal_chirho,
                SECRET_CHIRHO,
                endpoint_chirho,
                &limit_chirho,
            )
            .expect_err("the fourth sign-in, on either endpoint, is refused"),
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}
