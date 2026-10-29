// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Registers principals, binds identity wallets, and manages authentication evidence.

use crate::{cas_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use cairn_signer_chirho::signer_chirho;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "identity_chirho/auth_attempt_window_chirho.rs"]
mod auth_attempt_window_chirho;
/// The credential families (R2a's placement, PFE #26036): set, hash and inventory, change and reset as its children.
#[path = "identity_chirho/credentials_chirho/credentials_chirho.rs"]
mod credentials_chirho;
#[path = "identity_chirho/sign_in_velocity_chirho.rs"]
mod sign_in_velocity_chirho;
use sign_in_velocity_chirho::ensure_public_sign_in_allowed_chirho;
pub use sign_in_velocity_chirho::{
    AuthRateLimitReasonChirho, SignInVelocityChirho, AUTH_RATE_LIMIT_RETRY_AFTER_SECS_CHIRHO,
    SESSION_CREATING_AUTH_ENDPOINTS_CHIRHO, SIGN_IN_PRINCIPAL_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO,
    SIGN_IN_SOURCE_FAILURES_PER_WINDOW_DEFAULT_CHIRHO,
    SIGN_IN_SOURCE_SUCCESSES_PER_HOUR_DEFAULT_CHIRHO, SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO,
};
/// Registration under a principal named by a reviewed input (the test-kind geo seed only; C1 A3).
#[path = "identity_chirho/reviewed_principal_chirho.rs"]
mod reviewed_principal_chirho;
pub use reviewed_principal_chirho::{
    precheck_reviewed_principal_chirho, register_identity_with_reviewed_principal_chirho,
};
/// How many times this thread loaded the whole session log (brick 4a-2), and how many session and revocation RECORDS it
/// parsed (brick 4b), for the growth arms: a warm sign-in, cookie check or bearer check parses none.
#[cfg(test)]
pub(crate) mod session_read_metrics_chirho {
    use std::cell::Cell;

    thread_local! {
        static READS_CHIRHO: Cell<u64> = const { Cell::new(0) };
        static SESSION_PARSES_CHIRHO: Cell<u64> = const { Cell::new(0) };
        static REVOCATION_PARSES_CHIRHO: Cell<u64> = const { Cell::new(0) };
        static KEY_RECORD_READS_CHIRHO: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn note_chirho() {
        READS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    pub(crate) fn count_chirho() -> u64 {
        READS_CHIRHO.with(Cell::get)
    }

    pub(crate) fn note_session_parse_chirho() {
        SESSION_PARSES_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    pub(crate) fn note_revocation_parse_chirho() {
        REVOCATION_PARSES_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    /// One principal key record read by the liveness predicate: once per unexpired session it checks (K4 Part 2's churn
    /// witness counts the rows a cap decision reads).
    pub(crate) fn note_key_record_read_chirho() {
        KEY_RECORD_READS_CHIRHO.with(|cell_chirho| cell_chirho.set(cell_chirho.get() + 1));
    }

    /// Key records the liveness predicate read on this thread so far.
    pub(crate) fn key_record_reads_chirho() -> u64 {
        KEY_RECORD_READS_CHIRHO.with(Cell::get)
    }

    /// (session records, revocation records) this thread parsed so far.
    pub(crate) fn parses_chirho() -> (u64, u64) {
        (
            SESSION_PARSES_CHIRHO.with(Cell::get),
            REVOCATION_PARSES_CHIRHO.with(Cell::get),
        )
    }
}
/// The session road (brick 4b): its records, logs, cookie validation and revocation.
#[path = "identity_chirho/sessions_chirho/sessions_chirho.rs"]
mod sessions_chirho;
#[path = "identity_chirho/web_auth_chirho.rs"]
mod web_auth_chirho;
use auth_attempt_window_chirho::{
    parse_auth_attempt_line_chirho, recent_auth_attempts_chirho, recent_auth_failures_chirho,
    verify_auth_attempt_record_chirho,
};
pub use auth_attempt_window_chirho::{
    verify_auth_attempts_current_chirho, warm_auth_attempt_view_chirho,
};
pub use cairn_model_identity_chirho::{IdentityRecordChirho, PrincipalKindChirho};
use credentials_chirho::credential_lock_name_chirho;
pub use credentials_chirho::{
    change_identity_credential_for_session_chirho, credential_change_refusal_token_chirho,
    load_verified_credential_change_attempts_chirho, verify_credential_change_attempts_chirho,
    CredentialChangeRefusalChirho, IdentityCredentialChangeAttemptChirho,
    CREDENTIAL_CHANGE_SESSION_MAX_FAILURES_CHIRHO,
    CREDENTIAL_GUESS_EXHAUSTED_REVOCATION_REASON_CHIRHO,
    SELF_SERVICE_CREDENTIAL_CHANGE_REASON_CHIRHO,
};
pub(crate) use credentials_chirho::{constant_time_string_eq_chirho, CredentialMismatchChirho};
use credentials_chirho::{
    credential_hash_chirho, upgrade_legacy_identity_credential_locked_chirho,
    verify_identity_credential_chirho,
};
pub use credentials_chirho::{
    credential_inventory_chirho, identity_inventory_principal_hash_chirho,
    set_identity_credential_chirho, IdentityCredentialInventoryChirho,
    IDENTITY_CREDENTIAL_INVENTORY_SCHEMA_CHIRHO,
};
/// R2: the recovery and setup code (revision 3 of `self-service-recovery-code-chirho.md`).
pub use credentials_chirho::{
    invite_identity_chirho, load_recovery_code_events_chirho,
    load_recovery_code_events_for_display_chirho, mint_operator_recovery_code_chirho,
    recovery_code_refusal_token_chirho, redeem_recovery_code_chirho,
    redeem_recovery_code_with_public_limit_chirho,
    redeem_recovery_code_with_public_limit_outcome_chirho, verify_recovery_code_events_chirho,
    IdentityRecoveryCodeEventChirho, IssuedRecoveryCodeChirho, RecoveryCodeEventDisplayRowChirho,
    RecoveryCodeEventKindChirho, RecoveryCodeReasonKindChirho, RecoveryCodeRefusalChirho,
    IDENTITY_RECOVERY_CODE_EVENT_SCHEMA_CHIRHO, INVITATION_CODE_RESET_REASON_CHIRHO,
    RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO, RECOVERY_CODE_OPERATOR_LIFETIME_MS_CHIRHO,
    RECOVERY_CODE_RESET_REASON_CHIRHO,
};
#[cfg(test)]
use credentials_chirho::{
    legacy_credential_hash_blake3_chirho, ARGON2_OUTPUT_LEN_CHIRHO,
    CREDENTIAL_HASH_ARGON2ID_V1_CHIRHO,
};
pub use credentials_chirho::{
    load_credential_resets_chirho, reset_identity_credential_chirho,
    verify_credential_resets_chirho, IdentityCredentialResetRecordChirho,
    IdentityCredentialResetRefusalChirho, IdentityCredentialResetReportChirho,
    CREDENTIAL_RESET_SESSION_REVOCATION_REASON_CHIRHO,
    IDENTITY_CREDENTIAL_RESET_RECORD_SCHEMA_CHIRHO,
};
#[cfg(test)]
use credentials_chirho::{
    reset_identity_credential_locked_chirho, CredentialReplacementCauseChirho,
};
pub(crate) use sessions_chirho::with_connection_session_door_chirho;
use sessions_chirho::*;
#[cfg(test)]
pub(crate) use sessions_chirho::{
    connection_issue_locks_held_chirho, set_connection_proved_hold_chirho,
};
pub use sessions_chirho::{
    key_session_live_chirho, list_principal_sessions_chirho, load_session_revocations_chirho,
    load_sessions_chirho, load_verified_session_revocations_chirho, load_verified_sessions_chirho,
    revoke_session_by_seq_chirho, revoke_session_by_seq_under_append_lock_chirho,
    revoke_session_token_chirho, spawn_session_views_warm_up_chirho, validate_session_token_chirho,
    verified_session_for_token_chirho, verify_session_revocations_chirho, verify_sessions_chirho,
    warm_session_views_chirho, IdentitySessionChirho, IdentitySessionRevocationRecordChirho,
    IdentitySessionStateChirho, IdentitySessionStatusChirho, BROWSER_SESSION_LIFETIME_MS_CHIRHO,
    CONNECTION_SESSION_LIFETIME_MS_CHIRHO,
};
pub use web_auth_chirho::{
    auth_login_html_chirho, auth_register_html_chirho, issue_auth_human_check_challenge_chirho,
    public_registration_token_matches_chirho, verify_auth_human_check_chirho,
    AuthHumanCheckChallengeChirho, AuthHumanCheckRefusalChirho,
};

const IDENTITY_RECORD_SCHEMA_CHIRHO: &str = "identity-record-v1-chirho";
const IDENTITY_AUTH_ATTEMPT_RECORD_SCHEMA_CHIRHO: &str = "identity-auth-attempt-record-v1-chirho";
pub const PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO: u64 = 15 * 60 * 1000;
pub const PUBLIC_AUTH_MAX_FAILURES_CHIRHO: u64 = 5;
pub const AUTH_ENDPOINT_LOGIN_CHIRHO: &str = "login-chirho";
pub const AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO: &str = "token-chirho";
pub const AUTH_ENDPOINT_REGISTER_CHIRHO: &str = "register-chirho";
/// R2b's recover road (`POST /auth-chirho/recover-chirho`), with its own failure budget. The verifier reads it from
/// R2a on, BEFORE anything writes it, so the release that first writes recover rows can always roll back to one
/// that reads them: an older verifier refuses the whole attempts log on a value it does not know.
pub const AUTH_ENDPOINT_RECOVER_CHIRHO: &str = "recover-chirho";
const PUBLIC_REGISTRATION_ATTEMPT_PRINCIPAL_CHIRHO: &str = "public-registration-chirho";
/// The credential floor shared by every road that chooses a credential: registration, credential set, credential
/// reset, R1's self-service change and the served registration road (R2's recover road joins by calling the same
/// function). ONE definition: a floor raised here raises everywhere, and the refusal text travels with it so the
/// copies cannot drift apart.
///
/// L.J. settled it on 2026-10-04 ("yes do the password thing", relayed in PFE #26041): 15 characters, as NIST SP
/// 800-63B-4 asks when a password is the only factor. A character is a Unicode code point counted after trim, as NIST
/// counts one: `chars().count()`, never `len()`, so "ééééé" is 5 characters, not 10 bytes. The floor judges only a NEW
/// credential. Sign-in never asks it, and neither does the legacy hash upgrade, so an existing shorter password keeps
/// signing in.
pub const IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO: usize = 15;
pub const IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO: &str =
    "credential_chirho must be at least 15 characters";
pub fn credential_meets_floor_chirho(credential_chirho: &str) -> bool {
    credential_chirho.trim().chars().count() >= IDENTITY_CREDENTIAL_MIN_CHARS_CHIRHO
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityLoginResultChirho {
    pub session_chirho: IdentitySessionChirho,
    pub token_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityAuthAttemptOutcomeChirho {
    SuccessChirho,
    FailureChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityAuthAttemptRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub principal_hash_chirho: String,
    pub endpoint_chirho: String,
    pub outcome_chirho: IdentityAuthAttemptOutcomeChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// A public auth road's refusal, with whether it RECORDED a failed attempt row (R12). The served roads charge a network
/// source's failure budget exactly when one was recorded: never for a parse, floor, policy or rate refusal (they record
/// none) and never for a success. The plain functions return `error_chirho` alone, unchanged.
///
/// `credential_unchanged_chirho` is true only where the refusal is KNOWN to have stopped before a credential-setting
/// road's one commit point, so the credential and any code are untouched (R13, PFE #26146, #26147). False means not
/// known: the Set-up road then answers "may have applied", the conservative reading.
#[derive(Debug)]
pub struct PublicAuthRefusalChirho {
    pub error_chirho: anyhow::Error,
    pub failure_recorded_chirho: bool,
    pub credential_unchanged_chirho: bool,
}

impl PublicAuthRefusalChirho {
    /// A refusal that recorded no attempt row.
    pub fn not_recorded_chirho(error_chirho: anyhow::Error) -> Self {
        Self {
            error_chirho,
            failure_recorded_chirho: false,
            credential_unchanged_chirho: false,
        }
    }

    /// A refusal whose failed attempt row was recorded.
    pub fn recorded_chirho(error_chirho: anyhow::Error) -> Self {
        Self {
            error_chirho,
            failure_recorded_chirho: true,
            credential_unchanged_chirho: false,
        }
    }

    /// A refusal that recorded no attempt row and stopped before the commit point: the credential and any code are
    /// untouched (R13).
    pub fn not_recorded_unchanged_chirho(error_chirho: anyhow::Error) -> Self {
        Self {
            error_chirho,
            failure_recorded_chirho: false,
            credential_unchanged_chirho: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthRateLimitExceededChirho {
    pub principal_hash_chirho: String,
    pub endpoint_chirho: String,
    pub window_ms_chirho: u64,
    /// The limit that refused: failures for `FailedAttemptsChirho`, successful sign-ins otherwise.
    pub max_failures_chirho: u64,
    pub reason_chirho: AuthRateLimitReasonChirho,
}

impl std::fmt::Display for AuthRateLimitExceededChirho {
    fn fmt(&self, f_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let counted_chirho = match self.reason_chirho {
            AuthRateLimitReasonChirho::FailedAttemptsChirho => "failed attempts",
            AuthRateLimitReasonChirho::PrincipalSignInsChirho => "successful sign-ins",
            AuthRateLimitReasonChirho::SourceSignInsChirho => "successful sign-ins from one source",
            AuthRateLimitReasonChirho::SourceFailuresChirho => "failed attempts from one source",
        };
        write!(
            f_chirho,
            "credential auth rate limit exceeded for principal hash '{}' endpoint '{}' (max {} {counted_chirho} in {} ms)",
            self.principal_hash_chirho,
            self.endpoint_chirho,
            self.max_failures_chirho,
            self.window_ms_chirho
        )
    }
}

impl std::error::Error for AuthRateLimitExceededChirho {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityKeyChirho {
    principal_chirho: String,
    secret_key_chirho: String,
    #[serde(default)]
    credential_salt_chirho: Option<String>,
    #[serde(default)]
    credential_hash_chirho: Option<String>,
    /// Bumped by every credential SET and RESET; a session is valid only while it carries the
    /// generation current at its issue. A legacy record has no field and reads as 0, and a record
    /// that has never been reset serializes no field (skip-if-0), so old key files are byte-identical.
    #[serde(default, skip_serializing_if = "is_zero_generation_chirho")]
    credential_generation_chirho: u64,
    /// R2's recovery or setup code, stored only as a salted hash (`credentials_chirho/recovery_code_chirho.rs`). Both
    /// halves or neither, and an expiry only beside a code: anything else is invalid key state, which fails closed.
    /// Absent fields serialize to nothing, so a key file with no code is byte-identical to one written before R2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_code_salt_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_code_hash_chirho: Option<String>,
    /// Every OPERATOR-minted code carries one (PFE #26035); only R2c's self-service code will have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_code_expires_ms_chirho: Option<u64>,
}

fn is_zero_generation_chirho(generation_chirho: &u64) -> bool {
    *generation_chirho == 0
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRegisterRequestChirho {
    #[serde(default = "default_kind_chirho")]
    pub kind_chirho: String,
    #[serde(default)]
    pub credential_chirho: String,
    #[serde(default)]
    pub registration_token_chirho: Option<String>,
    #[serde(default)]
    pub human_check_chirho: Option<String>,
    #[serde(default)]
    pub human_check_token_chirho: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthLoginRequestChirho {
    #[serde(default)]
    pub principal_chirho: String,
    #[serde(default)]
    pub credential_chirho: String,
    #[serde(default)]
    pub redirect_chirho: Option<String>,
}

fn default_kind_chirho() -> String {
    "user".to_string()
}

fn identities_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identities-chirho.jsonl")
}

fn auth_attempts_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identity-auth-attempts-chirho.jsonl")
}

fn identity_keys_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identity-keys-chirho")
}

fn identity_key_path_chirho(root_chirho: &Path, principal_chirho: &str) -> PathBuf {
    let safe_chirho = principal_chirho.replace('/', "__");
    identity_keys_dir_chirho(root_chirho).join(format!("{safe_chirho}.json"))
}

fn identity_key_file_count_chirho(root_chirho: &Path) -> Result<usize> {
    let dir_chirho = identity_keys_dir_chirho(root_chirho);
    if !dir_chirho.exists() {
        return Ok(0);
    }
    let mut count_chirho = 0;
    for entry_chirho in
        std::fs::read_dir(&dir_chirho).with_context(|| format!("read {}", dir_chirho.display()))?
    {
        if entry_chirho?.path().is_file() {
            count_chirho += 1;
        }
    }
    Ok(count_chirho)
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

pub fn register_identity_chirho(
    root_chirho: &Path,
    kind_chirho: PrincipalKindChirho,
) -> Result<IdentityRecordChirho> {
    register_identity_internal_chirho(
        root_chirho,
        kind_chirho,
        None,
        PrincipalSourceChirho::DrawnChirho,
    )
}

pub fn register_identity_with_credential_chirho(
    root_chirho: &Path,
    kind_chirho: PrincipalKindChirho,
    credential_chirho: &str,
) -> Result<IdentityRecordChirho> {
    if !credential_meets_floor_chirho(credential_chirho) {
        bail!("{IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO}");
    }
    register_identity_internal_chirho(
        root_chirho,
        kind_chirho,
        Some(credential_chirho),
        PrincipalSourceChirho::DrawnChirho,
    )
}

/// Where a new identity's principal comes from: drawn at random, or named by a reviewed input
/// (`reviewed_principal_chirho`, the test-kind geo seed only).
#[derive(Clone, Copy)]
enum PrincipalSourceChirho<'principal_chirho> {
    DrawnChirho,
    ReviewedChirho(&'principal_chirho str),
}

fn register_identity_internal_chirho(
    root_chirho: &Path,
    kind_chirho: PrincipalKindChirho,
    credential_chirho: Option<&str>,
    principal_source_chirho: PrincipalSourceChirho<'_>,
) -> Result<IdentityRecordChirho> {
    create_identity_keys_dir_chirho(root_chirho)?;
    let signing_key_chirho = SigningKey::generate(&mut OsRng);
    let path_chirho = identities_path_chirho(root_chirho);
    let record_chirho =
        seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
            let principal_chirho = match principal_source_chirho {
                PrincipalSourceChirho::DrawnChirho => {
                    next_principal_chirho(root_chirho, &kind_chirho)?
                }
                PrincipalSourceChirho::ReviewedChirho(principal_chirho) => {
                    reviewed_principal_chirho::claim_reviewed_principal_chirho(
                        root_chirho,
                        principal_chirho,
                    )?
                }
            };
            let wallet_chirho = principal_chirho.clone();
            let mut record_chirho = IdentityRecordChirho {
                seq_chirho,
                schema_chirho: IDENTITY_RECORD_SCHEMA_CHIRHO.to_string(),
                principal_chirho,
                kind_chirho: kind_chirho.clone(),
                wallet_chirho,
                pubkey_chirho: hex_encode_chirho(&signing_key_chirho.verifying_key().to_bytes()),
                at_ms_chirho: now_ms_chirho(),
                sig_chirho: String::new(),
            };
            let message_chirho = record_message_chirho(&record_chirho)?;
            record_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
            Ok(record_chirho)
        })?;
    store_identity_key_chirho(
        root_chirho,
        &record_chirho.principal_chirho,
        &signing_key_chirho,
        credential_chirho,
    )?;
    Ok(record_chirho)
}

pub fn login_identity_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<IdentityLoginResultChirho> {
    login_identity_internal_chirho(root_chirho, principal_chirho, None)
}

pub fn login_identity_with_credential_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
) -> Result<IdentityLoginResultChirho> {
    if credential_chirho.is_empty() {
        bail!("credential_chirho is required");
    }
    login_identity_internal_chirho(root_chirho, principal_chirho, Some(credential_chirho))
}

pub fn login_identity_with_public_auth_limit_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    velocity_chirho: &SignInVelocityChirho,
) -> Result<IdentityLoginResultChirho> {
    login_identity_with_public_auth_limit_for_endpoint_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
        AUTH_ENDPOINT_LOGIN_CHIRHO,
        velocity_chirho,
    )
}

pub fn login_identity_with_public_auth_limit_for_endpoint_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    endpoint_chirho: &str,
    velocity_chirho: &SignInVelocityChirho,
) -> Result<IdentityLoginResultChirho> {
    login_identity_with_public_auth_limit_outcome_chirho(
        root_chirho,
        principal_chirho,
        credential_chirho,
        endpoint_chirho,
        velocity_chirho,
    )
    .map_err(|refusal_chirho| refusal_chirho.error_chirho)
}

/// The same sign-in, saying whether a refusal RECORDED a failed attempt row, for the served roads' per-source failure
/// limit (R12): a rate or validation refusal records none, and a refused credential records exactly one.
pub fn login_identity_with_public_auth_limit_outcome_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    endpoint_chirho: &str,
    velocity_chirho: &SignInVelocityChirho,
) -> std::result::Result<IdentityLoginResultChirho, PublicAuthRefusalChirho> {
    ensure_public_sign_in_allowed_chirho(
        root_chirho,
        principal_chirho,
        endpoint_chirho,
        velocity_chirho,
    )
    .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
    match login_identity_with_credential_chirho(root_chirho, principal_chirho, credential_chirho) {
        Ok(login_chirho) => {
            append_auth_attempt_chirho(
                root_chirho,
                principal_chirho,
                endpoint_chirho,
                IdentityAuthAttemptOutcomeChirho::SuccessChirho,
            )
            .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
            Ok(login_chirho)
        }
        Err(e_chirho) => {
            append_auth_attempt_chirho(
                root_chirho,
                principal_chirho,
                endpoint_chirho,
                IdentityAuthAttemptOutcomeChirho::FailureChirho,
            )
            .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
            Err(PublicAuthRefusalChirho::recorded_chirho(e_chirho))
        }
    }
}

/// K4 Part 3's served connection road: the scoped-token endpoint's pre-check, run as the token road runs it, before
/// the credential is checked.
pub(crate) fn ensure_scoped_token_sign_in_allowed_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    velocity_chirho: &SignInVelocityChirho,
) -> Result<()> {
    ensure_public_sign_in_allowed_chirho(
        root_chirho,
        principal_chirho,
        AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
        velocity_chirho,
    )
}

/// K4 Part 3's served connection road: one attempt row under the scoped-token endpoint, `token-chirho`, which every
/// engine down to R15 verifies. The road appends a failure for a refused credential and a success for a created
/// connection, and nothing else.
pub(crate) fn append_scoped_token_attempt_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    outcome_chirho: IdentityAuthAttemptOutcomeChirho,
) -> Result<()> {
    append_auth_attempt_chirho(
        root_chirho,
        principal_chirho,
        AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO,
        outcome_chirho,
    )
    .map(|_record_chirho| ())
}

pub fn is_auth_rate_limit_error_chirho(e_chirho: &anyhow::Error) -> bool {
    e_chirho
        .downcast_ref::<AuthRateLimitExceededChirho>()
        .is_some()
}

pub fn append_public_registration_attempt_chirho(
    root_chirho: &Path,
    outcome_chirho: IdentityAuthAttemptOutcomeChirho,
) -> Result<IdentityAuthAttemptRecordChirho> {
    append_auth_attempt_chirho(
        root_chirho,
        PUBLIC_REGISTRATION_ATTEMPT_PRINCIPAL_CHIRHO,
        AUTH_ENDPOINT_REGISTER_CHIRHO,
        outcome_chirho,
    )
}

pub fn ensure_public_registration_attempt_allowed_chirho(root_chirho: &Path) -> Result<()> {
    ensure_public_auth_attempt_allowed_chirho(
        root_chirho,
        PUBLIC_REGISTRATION_ATTEMPT_PRINCIPAL_CHIRHO,
        AUTH_ENDPOINT_REGISTER_CHIRHO,
    )
}

fn login_identity_internal_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: Option<&str>,
) -> Result<IdentityLoginResultChirho> {
    let identity_chirho = find_identity_chirho(root_chirho, principal_chirho)?
        .ok_or_else(|| anyhow!("unknown principal '{principal_chirho}'"))?;
    // Proof and session issue are ONE critical section under the principal credential lock — the
    // same lock reset/set/change take. The login road had the proof-then-mutate shape the change
    // road fixed (claude2 #22007 F1, gpt #22338): without the lock, a reset could land between the
    // credential proof and the session append, and the session (stamped from a later read) would
    // inherit the reset's new generation and validate, surviving a reset meant to end it. Under the
    // lock a login that races a reset proves against the CURRENT record (an old credential then
    // refuses) and any session it issues is seen by a later reset's revocation enumeration; the
    // generation is stamped from the proved snapshot and kept as defense in depth. The append below
    // takes the append-log lock while this credential lock is held — the same order reset uses, so
    // there is no lock-order inversion.
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &credential_lock_name_chirho(principal_chirho),
        || {
            let key_record_chirho =
                prove_credential_locked_chirho(root_chirho, principal_chirho, credential_chirho)?;
            #[cfg(test)]
            login_lock_probe_tests_chirho::observe_login_chirho(
                login_lock_probe_tests_chirho::LoginProbePointChirho::ProofChirho,
            )?;
            let issued_ms_chirho = now_ms_chirho();
            let token_chirho = random_token_chirho();
            let session_chirho = seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
                append_session_row_unlocked_chirho(
                    root_chirho,
                    principal_chirho,
                    &identity_chirho,
                    &key_record_chirho,
                    SessionLifetimeChirho::BrowserChirho,
                    issued_ms_chirho,
                    token_hash_chirho(&token_chirho),
                )
            })?;
            #[cfg(test)]
            login_lock_probe_tests_chirho::observe_login_chirho(
                login_lock_probe_tests_chirho::LoginProbePointChirho::AppendedChirho,
            )?;
            Ok(IdentityLoginResultChirho {
                session_chirho,
                token_chirho,
            })
        },
    )
}

/// The principal's key record with `credential_chirho` proved against it, for a caller that holds the principal's
/// credential lock, so the proof and what the caller then writes are one critical section. A legacy hash is re-hashed
/// to argon2id inline under that same lock (never a second acquire), only while the on-disk record is still the proved
/// legacy one. `None` proves nothing: the operator's login. The record returned is the proved snapshot, whose credential
/// generation a new session is stamped with.
fn prove_credential_locked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: Option<&str>,
) -> Result<IdentityKeyChirho> {
    let key_record_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho)?;
    if let Some(credential_chirho) = credential_chirho {
        let is_legacy_chirho =
            verify_identity_credential_chirho(&key_record_chirho, credential_chirho)?;
        if is_legacy_chirho {
            upgrade_legacy_identity_credential_locked_chirho(
                root_chirho,
                principal_chirho,
                credential_chirho,
            )?;
        }
    }
    Ok(key_record_chirho)
}

pub fn load_identities_chirho(root_chirho: &Path) -> Result<Vec<IdentityRecordChirho>> {
    // Counted as one full-log load so the verified-view cache's warm-request "zero full reads"
    // invariant is observable at this leaf: the served owner gate must never re-read this log warm.
    #[cfg(all(test, feature = "prototype-full-chirho"))]
    crate::app_chirho::verified_view_cache_chirho::test_metrics_chirho::note_full_log_load_chirho();
    #[cfg(all(
        any(test, feature = "serve-runtime-test-hooks-chirho"),
        feature = "prototype-full-chirho"
    ))]
    crate::app_chirho::control_log_load_metrics_chirho::note_load_chirho(&identities_path_chirho(
        root_chirho,
    ));
    let path_chirho = identities_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: IdentityRecordChirho = serde_json::from_str(line_chirho)?;
        verify_identity_record_schema_chirho(
            &record_chirho.schema_chirho,
            IDENTITY_RECORD_SCHEMA_CHIRHO,
            "identity record",
        )?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

pub fn load_auth_attempts_chirho(
    root_chirho: &Path,
) -> Result<Vec<IdentityAuthAttemptRecordChirho>> {
    let path_chirho = auth_attempts_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(parse_auth_attempt_line_chirho(line_chirho)?);
    }
    Ok(records_chirho)
}

pub fn find_identity_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<Option<IdentityRecordChirho>> {
    Ok(load_identities_chirho(root_chirho)?
        .into_iter()
        .find(|record_chirho| record_chirho.principal_chirho == principal_chirho))
}

/// The verified (principal -> kind) map, cached per root fingerprint: O(1) warm, rebuilt (every record verified) only
/// when a fingerprint file such as the identity log changes. Two readers take it so that neither does history-sized
/// work per request: the served owner-principal gate, and R2b's anonymous recover road for its existence check.
///
/// `pub` so the served owner gate can take its kind from the VERIFIED map rather than a raw
/// `find_identity_chirho`. The gate deliberately consumes the MAP and not
/// `ensure_owner_principal_chirho`: that wrapper's two `bail!` messages differ from each other and
/// one interpolates the principal name, so propagating them would change the gate's status class and
/// widen an existence oracle. Taking the map keeps every response byte the gate already emits.
pub fn verified_identity_kind_map_arc_chirho(
    root_chirho: &Path,
) -> Result<std::sync::Arc<std::collections::BTreeMap<String, PrincipalKindChirho>>> {
    cairn_verified_view_cache_chirho::cached_identity_kind_map_chirho(root_chirho, || {
        let mut map_chirho = std::collections::BTreeMap::new();
        for record_chirho in load_verified_identities_chirho(root_chirho)? {
            map_chirho
                .entry(record_chirho.principal_chirho)
                .or_insert(record_chirho.kind_chirho);
        }
        Ok(map_chirho)
    })
}

/// Load + VERIFY the identity log in ONE parse — dense seq and EVERY record signature against the
/// root pubkey — and return the verified records. This is the single identity verification law:
/// a consumer that needs verified records must take them from HERE; a verify-then-raw-reload pair
/// would be a TOCTOU and would hand the second load a false verified-label (#6048/#6049).
pub fn load_verified_identities_chirho(root_chirho: &Path) -> Result<Vec<IdentityRecordChirho>> {
    let records_chirho = load_identities_chirho(root_chirho)?;
    // An empty identity log needs no key and must not mint one. This verification law is reached by
    // read-only paths (e.g. the publication door's occupancy check, via an app owner's identity
    // kind), so an empty or keyless root must not create/chmod/name-lock a signing key. Non-empty
    // records were signed, so a key already exists to verify against.
    if records_chirho.is_empty() {
        return Ok(records_chirho);
    }
    // Read the EXISTING public key only: verifying identity signatures never needs the private key,
    // and `pubkey_hex_chirho` -> `load_or_create_signing_key_chirho` would create/chmod/name-lock it
    // on a read path. Fail closed on a missing/corrupt authority. Registration itself still mints its
    // key at signing time via `sign_message_chirho`, not here.
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "identity seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "identity entry {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho)
}

/// First consumer of [`load_verified_identities_chirho`] — the count contract for existing
/// verify/inventory callers is unchanged.
pub fn verify_identities_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_identities_chirho(root_chirho)?.len())
}

/// The FULL verification of the auth-attempt log, every record. Audits and exports use it; the per-attempt paths use
/// `verify_auth_attempts_current_chirho`, which reads only new records and runs this same check at least hourly.
pub fn verify_auth_attempts_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_auth_attempts_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        verify_auth_attempt_record_chirho(&pubkey_chirho, record_chirho, i_chirho as u64)?;
    }
    Ok(records_chirho.len())
}

/// Keep this emitted `user|owner/<16 lowerhex>` shape aligned with the H3 account-owner grammar
/// in cairn-config and the dependency-light credits-demo viewer check.
fn next_principal_chirho(root_chirho: &Path, kind_chirho: &PrincipalKindChirho) -> Result<String> {
    let existing_chirho = load_identities_chirho(root_chirho)?;
    for _ in 0..16 {
        let mut seed_chirho = [0_u8; 16];
        OsRng.fill_bytes(&mut seed_chirho);
        let hash_chirho = cas_chirho::hash_chirho(&seed_chirho).0;
        let id_chirho = hash_chirho[..16].to_string();
        if !id_chirho
            .bytes()
            .any(|byte_chirho| byte_chirho.is_ascii_alphabetic())
        {
            continue;
        }
        let principal_chirho = format!("{}/{}", kind_chirho.prefix_chirho(), id_chirho);
        if !existing_chirho
            .iter()
            .any(|record_chirho| record_chirho.principal_chirho == principal_chirho)
        {
            return Ok(principal_chirho);
        }
    }
    bail!("could not allocate unique principal id")
}

fn create_identity_keys_dir_chirho(root_chirho: &Path) -> Result<()> {
    let dir_chirho = identity_keys_dir_chirho(root_chirho);
    std::fs::create_dir_all(&dir_chirho)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir_chirho, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn store_identity_key_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    key_chirho: &SigningKey,
    credential_chirho: Option<&str>,
) -> Result<()> {
    create_identity_keys_dir_chirho(root_chirho)?;
    let credential_pair_chirho = match credential_chirho {
        Some(credential_chirho) => {
            let salt_chirho = random_salt_chirho();
            let hash_chirho = credential_hash_chirho(&salt_chirho, credential_chirho)?;
            Some((salt_chirho, hash_chirho))
        }
        None => None,
    };
    let record_chirho = IdentityKeyChirho {
        principal_chirho: principal_chirho.to_string(),
        secret_key_chirho: hex_encode_chirho(&key_chirho.to_bytes()),
        credential_salt_chirho: credential_pair_chirho
            .as_ref()
            .map(|(salt_chirho, _)| salt_chirho.clone()),
        credential_hash_chirho: credential_pair_chirho
            .as_ref()
            .map(|(_, hash_chirho)| hash_chirho.clone()),
        credential_generation_chirho: 0,
        recovery_code_salt_chirho: None,
        recovery_code_hash_chirho: None,
        recovery_code_expires_ms_chirho: None,
    };
    write_identity_key_record_chirho(root_chirho, &record_chirho)?;
    Ok(())
}

/// Atomically replace the complete key record without truncating its signing secret.
/// Workflow: spec-chirho/workflows-chirho/identity-auth-chirho/identity-key-replacement-chirho.md.
/// A parent-sync error after rename can leave the replacement visible; Err is not a rollback.
fn write_identity_key_record_chirho(
    root_chirho: &Path,
    record_chirho: &IdentityKeyChirho,
) -> Result<()> {
    let path_chirho = identity_key_path_chirho(root_chirho, &record_chirho.principal_chirho);
    let bytes_chirho = serde_json::to_vec_pretty(record_chirho)?;
    cairn_durable_chirho::write_file_durable_with_mode_chirho(&path_chirho, &bytes_chirho, 0o600)?;
    Ok(())
}

fn load_identity_key_record_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<IdentityKeyChirho> {
    let path_chirho = identity_key_path_chirho(root_chirho, principal_chirho);
    let bytes_chirho = std::fs::read(&path_chirho)
        .with_context(|| format!("read local identity key {}", path_chirho.display()))?;
    let record_chirho: IdentityKeyChirho = serde_json::from_slice(&bytes_chirho)
        .with_context(|| format!("decode local identity key {}", path_chirho.display()))?;
    if record_chirho.principal_chirho != principal_chirho {
        bail!("local identity key principal mismatch for '{principal_chirho}'");
    }
    Ok(record_chirho)
}

fn signing_key_from_identity_key_chirho(record_chirho: &IdentityKeyChirho) -> Result<SigningKey> {
    let secret_bytes_chirho = hex_decode_chirho(&record_chirho.secret_key_chirho)?;
    let secret_chirho: [u8; 32] = secret_bytes_chirho
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("local identity key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&secret_chirho))
}

fn record_message_chirho(record_chirho: &IdentityRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn auth_attempt_message_chirho(record_chirho: &IdentityAuthAttemptRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

fn nonempty_schema_chirho(schema_chirho: &str) -> Option<&str> {
    (!schema_chirho.is_empty()).then_some(schema_chirho)
}

fn verify_identity_record_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("unsupported {label_chirho} schema '{schema_chirho}'");
    }
    Ok(())
}

fn validate_auth_attempt_endpoint_chirho(endpoint_chirho: &str) -> Result<()> {
    if endpoint_chirho != AUTH_ENDPOINT_LOGIN_CHIRHO
        && endpoint_chirho != AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO
        && endpoint_chirho != AUTH_ENDPOINT_REGISTER_CHIRHO
        && endpoint_chirho != AUTH_ENDPOINT_RECOVER_CHIRHO
    {
        bail!("unsupported identity auth endpoint '{endpoint_chirho}'");
    }
    Ok(())
}

fn validate_auth_attempt_record_chirho(
    record_chirho: &IdentityAuthAttemptRecordChirho,
) -> Result<()> {
    if record_chirho.principal_hash_chirho.len() != 64
        || !record_chirho
            .principal_hash_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit())
    {
        bail!("identity auth attempt principal hash is invalid");
    }
    validate_auth_attempt_endpoint_chirho(&record_chirho.endpoint_chirho)
}

fn auth_attempt_principal_hash_chirho(principal_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(b"cairn-chirho/identity-auth-attempt-principal/v1");
    hasher_chirho.update(principal_chirho.as_bytes());
    hex_encode_chirho(hasher_chirho.finalize().as_bytes())
}

fn append_auth_attempt_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    endpoint_chirho: &str,
    outcome_chirho: IdentityAuthAttemptOutcomeChirho,
) -> Result<IdentityAuthAttemptRecordChirho> {
    validate_auth_attempt_endpoint_chirho(endpoint_chirho)?;
    if principal_chirho.trim().is_empty() {
        bail!("principal_chirho is required");
    }
    let principal_hash_chirho = auth_attempt_principal_hash_chirho(principal_chirho);
    let path_chirho = auth_attempts_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        // Under the append lock, then the view's lock (never the reverse). The new record reaches the view only as
        // file bytes, on a later call.
        verify_auth_attempts_current_chirho(root_chirho)?;
        let mut record_chirho = IdentityAuthAttemptRecordChirho {
            seq_chirho,
            schema_chirho: IDENTITY_AUTH_ATTEMPT_RECORD_SCHEMA_CHIRHO.to_string(),
            principal_hash_chirho: principal_hash_chirho.clone(),
            endpoint_chirho: endpoint_chirho.to_string(),
            outcome_chirho: outcome_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = auth_attempt_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

/// Failures are counted per (principal, endpoint) key: every road keeps its own budget. The self-service credential
/// change once shared login's; that sharing let a change-door attacker lock the owner out of login, so it was
/// withdrawn (claude2 #22277), and the change door counts its own guesses per session in its own log.
fn ensure_public_auth_attempt_allowed_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    endpoint_chirho: &str,
) -> Result<()> {
    validate_auth_attempt_endpoint_chirho(endpoint_chirho)?;
    if principal_chirho.trim().is_empty() {
        bail!("principal_chirho is required");
    }
    let principal_hash_chirho = auth_attempt_principal_hash_chirho(principal_chirho);
    // Failures for this key at or after `now - window`, after the key's latest success: today's rule, from a view
    // that verifies only records appended since the last call.
    let recent_failures_chirho =
        recent_auth_failures_chirho(root_chirho, &principal_hash_chirho, endpoint_chirho)?;
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
    Ok(())
}

fn random_token_chirho() -> String {
    let mut token_bytes_chirho = [0_u8; 32];
    OsRng.fill_bytes(&mut token_bytes_chirho);
    hex_encode_chirho(&token_bytes_chirho)
}

fn random_salt_chirho() -> String {
    let mut salt_bytes_chirho = [0_u8; 16];
    OsRng.fill_bytes(&mut salt_bytes_chirho);
    hex_encode_chirho(&salt_bytes_chirho)
}

fn token_hash_chirho(token_chirho: &str) -> String {
    cas_chirho::hash_chirho(token_chirho.as_bytes()).0
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for b_chirho in bytes_chirho {
        out_chirho.push(HEX_CHIRHO[(b_chirho >> 4) as usize] as char);
        out_chirho.push(HEX_CHIRHO[(b_chirho & 0x0f) as usize] as char);
    }
    out_chirho
}

fn hex_decode_chirho(hex_chirho: &str) -> Result<Vec<u8>> {
    if !hex_chirho.len().is_multiple_of(2) {
        bail!("odd-length hex string");
    }
    (0..hex_chirho.len())
        .step_by(2)
        .map(|i_chirho| {
            u8::from_str_radix(&hex_chirho[i_chirho..i_chirho + 2], 16)
                .map_err(|e_chirho| anyhow!("bad hex: {e_chirho}"))
        })
        .collect()
}

fn escape_html_chirho(value_chirho: &str) -> String {
    value_chirho
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
#[path = "identity_chirho/auth_attempt_window_tests_chirho.rs"]
mod auth_attempt_window_tests_chirho;
#[cfg(all(test, unix))]
#[path = "identity_chirho/key_write_tests_chirho.rs"]
mod key_write_tests_chirho;
#[cfg(test)]
#[path = "identity_chirho/login_lock_probe_tests_chirho.rs"]
mod login_lock_probe_tests_chirho;
#[cfg(test)]
#[path = "identity_chirho/tests_chirho.rs"]
mod tests_chirho;
