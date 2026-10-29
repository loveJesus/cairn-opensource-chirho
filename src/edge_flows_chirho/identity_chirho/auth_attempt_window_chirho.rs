// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Reads the auth-attempt log through the incremental window view, with ONE parser and ONE per-record verifier
//! shared by the loader, the full verification and the view.
//!
//! Workflow: the sign-in check DAG in `spec-chirho/workflows-chirho/identity-auth-chirho/bounded-auth-history-chirho.md`.

use super::{
    auth_attempt_message_chirho, auth_attempts_path_chirho, now_ms_chirho,
    validate_auth_attempt_record_chirho, verify_identity_record_schema_chirho,
    IdentityAuthAttemptOutcomeChirho, IdentityAuthAttemptRecordChirho,
    IDENTITY_AUTH_ATTEMPT_RECORD_SCHEMA_CHIRHO, PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
    SESSION_CREATING_AUTH_ENDPOINTS_CHIRHO, SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
};
use anyhow::{bail, Result};
use cairn_auth_attempt_window_chirho::{
    recent_attempts_chirho, recent_failures_chirho, verify_current_chirho, AttemptLogChirho,
    AttemptRecordChirho, WindowRulesChirho,
};
use cairn_durable_chirho::log_path_chirho::{classify_log_path_chirho, LogPathChirho};
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};

/// The public failure window; a step back of the clock by up to one more window still decides exactly (a larger one
/// rebuilds the index in the background); and a background integrity pass over the whole log at least hourly, the
/// bound on how long an in-place edit of an already verified record can go undetected.
const AUTH_ATTEMPT_WINDOW_RULES_CHIRHO: WindowRulesChirho = WindowRulesChirho {
    window_ms_chirho: PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
    regression_tolerance_ms_chirho: PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO,
    full_verify_every_ms_chirho: 60 * 60 * 1000,
    success_window_ms_chirho: SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
};

/// Parse one line of the auth-attempt log, schema included.
pub(super) fn parse_auth_attempt_line_chirho(
    line_chirho: &str,
) -> Result<IdentityAuthAttemptRecordChirho> {
    let record_chirho: IdentityAuthAttemptRecordChirho = serde_json::from_str(line_chirho)?;
    verify_identity_record_schema_chirho(
        &record_chirho.schema_chirho,
        IDENTITY_AUTH_ATTEMPT_RECORD_SCHEMA_CHIRHO,
        "identity auth attempt record",
    )?;
    Ok(record_chirho)
}

/// Verify one record as the log's `expected_seq_chirho`-th: its seq, its fields, and its signature under the root key.
pub(super) fn verify_auth_attempt_record_chirho(
    pubkey_chirho: &str,
    record_chirho: &IdentityAuthAttemptRecordChirho,
    expected_seq_chirho: u64,
) -> Result<()> {
    #[cfg(test)]
    AUTH_ATTEMPT_VERIFICATIONS_CHIRHO.with(|count_chirho| count_chirho.set(count_chirho.get() + 1));
    if record_chirho.seq_chirho != expected_seq_chirho {
        bail!(
            "identity auth attempt seq gap at index {expected_seq_chirho}: entry seq is {}",
            record_chirho.seq_chirho
        );
    }
    validate_auth_attempt_record_chirho(record_chirho)?;
    let message_chirho = auth_attempt_message_chirho(record_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        pubkey_chirho,
        &message_chirho,
        &record_chirho.sig_chirho,
    )? {
        bail!(
            "identity auth attempt {} signature invalid",
            record_chirho.seq_chirho
        );
    }
    Ok(())
}

impl AttemptRecordChirho for IdentityAuthAttemptRecordChirho {
    fn principal_hash_chirho(&self) -> &str {
        &self.principal_hash_chirho
    }
    fn endpoint_chirho(&self) -> &str {
        &self.endpoint_chirho
    }
    fn is_success_chirho(&self) -> bool {
        self.outcome_chirho == IdentityAuthAttemptOutcomeChirho::SuccessChirho
    }
    fn at_ms_chirho(&self) -> u64 {
        self.at_ms_chirho
    }
}

/// The root's auth-attempt log as the window view reads it. The root's public key names the verifier, so a key
/// change verifies every record again. Background jobs run on a clone.
#[derive(Clone)]
struct AuthAttemptLogChirho {
    path_chirho: PathBuf,
    pubkey_chirho: String,
}

impl AttemptLogChirho for AuthAttemptLogChirho {
    type RecordChirho = IdentityAuthAttemptRecordChirho;
    fn path_chirho(&self) -> &Path {
        &self.path_chirho
    }
    fn verifier_id_chirho(&self) -> &str {
        &self.pubkey_chirho
    }
    fn parse_chirho(&self, line_chirho: &str) -> Result<IdentityAuthAttemptRecordChirho> {
        parse_auth_attempt_line_chirho(line_chirho)
    }
    fn verify_chirho(
        &self,
        record_chirho: &IdentityAuthAttemptRecordChirho,
        expected_seq_chirho: u64,
    ) -> Result<()> {
        verify_auth_attempt_record_chirho(&self.pubkey_chirho, record_chirho, expected_seq_chirho)
    }
}

fn auth_attempt_log_chirho(root_chirho: &Path) -> Result<AuthAttemptLogChirho> {
    // As the full verification does, resolve the root key before reading the log.
    Ok(AuthAttemptLogChirho {
        path_chirho: auth_attempts_path_chirho(root_chirho),
        pubkey_chirho: signer_chirho::pubkey_hex_chirho(root_chirho)?,
    })
}

/// The failures today's full scan would count for this (principal hash, endpoint), verifying only the records
/// appended since the last call.
pub(super) fn recent_auth_failures_chirho(
    root_chirho: &Path,
    principal_hash_chirho: &str,
    endpoint_chirho: &str,
) -> Result<u64> {
    let log_chirho = auth_attempt_log_chirho(root_chirho)?;
    Ok(recent_failures_chirho(
        &log_chirho,
        &AUTH_ATTEMPT_WINDOW_RULES_CHIRHO,
        principal_hash_chirho,
        endpoint_chirho,
        now_ms_chirho,
    )?
    .recent_failures_chirho)
}

/// The sign-in pre-check's two counts from ONE view update: today's failures for this (principal hash, endpoint), and
/// the principal's successful sign-ins in the last hour over the session-creating endpoints (brick 4a).
pub(super) fn recent_auth_attempts_chirho(
    root_chirho: &Path,
    principal_hash_chirho: &str,
    endpoint_chirho: &str,
) -> Result<(u64, u64)> {
    let log_chirho = auth_attempt_log_chirho(root_chirho)?;
    let counts_chirho = recent_attempts_chirho(
        &log_chirho,
        &AUTH_ATTEMPT_WINDOW_RULES_CHIRHO,
        principal_hash_chirho,
        endpoint_chirho,
        &SESSION_CREATING_AUTH_ENDPOINTS_CHIRHO,
        now_ms_chirho,
    )?;
    Ok((
        counts_chirho.recent_failures_chirho,
        counts_chirho.recent_successes_chirho,
    ))
}

/// The auth-attempt log verifies, reading only what was appended since the last call (the whole log is re-verified
/// in the background at least hourly). Returns the verified record count. Per-attempt paths use this; audits and
/// exports keep the full `verify_auth_attempts_chirho`.
pub fn verify_auth_attempts_current_chirho(root_chirho: &Path) -> Result<u64> {
    let log_chirho = auth_attempt_log_chirho(root_chirho)?;
    Ok(verify_current_chirho(
        &log_chirho,
        &AUTH_ATTEMPT_WINDOW_RULES_CHIRHO,
        now_ms_chirho,
    )?
    .verified_records_chirho)
}

/// Build the view at process start, so a process's first load (proportional to the whole log) lands on startup
/// rather than on a sign-in. Read-only: it reads the existing root key and never creates one, and a missing log is
/// left for the first check. The key is derived exactly as the sign-in checks derive it, so they find the view
/// already built for their key.
pub fn warm_auth_attempt_view_chirho(root_chirho: &Path) -> Result<u64> {
    let path_chirho = auth_attempts_path_chirho(root_chirho);
    // Absent is left for the first check; a log that cannot be examined is reported, and sign-ins refuse on their own.
    if let LogPathChirho::AbsentChirho = classify_log_path_chirho(&path_chirho)? {
        return Ok(0);
    }
    let log_chirho = AuthAttemptLogChirho {
        path_chirho,
        pubkey_chirho: signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)?,
    };
    Ok(verify_current_chirho(
        &log_chirho,
        &AUTH_ATTEMPT_WINDOW_RULES_CHIRHO,
        now_ms_chirho,
    )?
    .verified_records_chirho)
}

#[cfg(test)]
thread_local! {
    /// Records verified on this thread: the wiring arm's scaling counter.
    pub(super) static AUTH_ATTEMPT_VERIFICATIONS_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
