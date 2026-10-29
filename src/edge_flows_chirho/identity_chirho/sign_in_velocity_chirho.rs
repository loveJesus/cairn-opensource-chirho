// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The sign-in velocity limit (brick 4a): a principal's successful sign-ins per hour, counted across login and
//! scoped-token issue and refused BEFORE the credential is checked, with the failure lockout's own refusal.
//!
//! Workflow: the sign-in check DAG in `spec-chirho/workflows-chirho/identity-auth-chirho/bounded-auth-history-chirho.md`.

use super::{
    auth_attempt_principal_hash_chirho, recent_auth_attempts_chirho, AuthRateLimitExceededChirho,
    AUTH_ENDPOINT_LOGIN_CHIRHO, AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
    PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO, PUBLIC_AUTH_MAX_FAILURES_CHIRHO,
};
use anyhow::{bail, Result};
use std::path::Path;

/// The endpoints whose success creates a session: the ones the sign-in velocity limit counts (brick 4a).
pub const SESSION_CREATING_AUTH_ENDPOINTS_CHIRHO: [&str; 2] = [
    AUTH_ENDPOINT_LOGIN_CHIRHO,
    AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
];
/// Successful sign-ins count toward the velocity limit for one hour (PFE #25922, agy #25924).
pub const SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO: u64 = 60 * 60 * 1000;
/// The default successful sign-ins per principal per hour; the host TOML may set another.
pub const SIGN_IN_PRINCIPAL_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO: u64 = 10;
/// The default successful sign-ins per network source per hour; the host TOML may set another.
pub const SIGN_IN_SOURCE_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO: u64 = 60;
/// The default FAILED attempts per network source per failure window (15 minutes), ONE budget across login, token and
/// recover (R12; PFE #26065, sized #26068); the host TOML may set another. A church Wi-Fi onboarding 30 people who each
/// fail twice never meets it, and one source's appended rows stay bounded at 400 an hour.
pub const SIGN_IN_SOURCE_FAILURES_PER_WINDOW_DEFAULT_CHIRHO: u64 = 100;
/// The ONE `Retry-After` every sign-in rate refusal carries, whichever limit refused: the failure window, so a
/// refusal never tells which limit fired (agy #25938, the constant, final).
pub const AUTH_RATE_LIMIT_RETRY_AFTER_SECS_CHIRHO: u64 =
    PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO / 1000;

/// The sign-in velocity limit for one principal (brick 4a): its successful sign-ins per hour, set from the host TOML.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignInVelocityChirho {
    pub principal_successes_per_hour_chirho: u64,
}

impl Default for SignInVelocityChirho {
    fn default() -> Self {
        Self {
            principal_successes_per_hour_chirho:
                SIGN_IN_PRINCIPAL_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO,
        }
    }
}

/// Which limit refused, for the server's own log only. Every reason renders as ONE public response, through the one
/// `is_auth_rate_limit_error_chirho` predicate, so a caller never learns which limit fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthRateLimitReasonChirho {
    FailedAttemptsChirho,
    PrincipalSignInsChirho,
    SourceSignInsChirho,
    /// A network source's failed attempts across login, token and recover (R12's per-source failure limit).
    SourceFailuresChirho,
}

/// The sign-in road's pre-check, BEFORE the credential is verified, from ONE view update: the key's failures (today's
/// rule), then the principal's successful sign-ins in the last hour over the session-creating endpoints (brick 4a).
/// Either refusal is the same error type, so the served response is identical whichever fired, and identical for a
/// right and a wrong password: no credential work has been done yet, so the refusal cannot be a password oracle
/// (PFE #25922, agy #25924). Concurrent sign-ins of one principal may each pass before any lands, so the limit can be
/// exceeded by at most the sign-ins in flight at once, which the blocking-auth permit cap bounds.
///
/// Workflow: the sign-in check DAG in `spec-chirho/workflows-chirho/identity-auth-chirho/bounded-auth-history-chirho.md`.
pub(super) fn ensure_public_sign_in_allowed_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    endpoint_chirho: &str,
    velocity_chirho: &SignInVelocityChirho,
) -> Result<()> {
    if !SESSION_CREATING_AUTH_ENDPOINTS_CHIRHO.contains(&endpoint_chirho) {
        bail!("unsupported sign-in endpoint '{endpoint_chirho}'");
    }
    if principal_chirho.trim().is_empty() {
        bail!("principal_chirho is required");
    }
    let principal_hash_chirho = auth_attempt_principal_hash_chirho(principal_chirho);
    let (recent_failures_chirho, recent_successes_chirho) =
        recent_auth_attempts_chirho(root_chirho, &principal_hash_chirho, endpoint_chirho)?;
    if recent_failures_chirho >= PUBLIC_AUTH_MAX_FAILURES_CHIRHO {
        return Err(AuthRateLimitExceededChirho {
            principal_hash_chirho,
            endpoint_chirho: endpoint_chirho.to_string(),
            window_ms_chirho: PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
            max_failures_chirho: PUBLIC_AUTH_MAX_FAILURES_CHIRHO,
            reason_chirho: AuthRateLimitReasonChirho::FailedAttemptsChirho,
        }
        .into());
    }
    if recent_successes_chirho >= velocity_chirho.principal_successes_per_hour_chirho {
        return Err(AuthRateLimitExceededChirho {
            principal_hash_chirho,
            endpoint_chirho: endpoint_chirho.to_string(),
            window_ms_chirho: SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
            max_failures_chirho: velocity_chirho.principal_successes_per_hour_chirho,
            reason_chirho: AuthRateLimitReasonChirho::PrincipalSignInsChirho,
        }
        .into());
    }
    Ok(())
}
