// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Self-service credential change: the operator reset performed by the principal herself, behind
//! her own session, after proving the credential she is replacing.
//!
//! The act is exactly `reset_identity_credential_chirho` (revoke every live session FIRST, then
//! replace, then a signed plaintext-free record) with `actor_chirho` = the principal. Two
//! authority properties this road adds over the bare operator reset, both found in review
//! (claude2 #22007 F1/F2, gpt #21941 D1):
//!
//! - **F1, the proof and the mutation are ONE critical section.** The CURRENT credential is
//!   verified INSIDE `identity-credential-set/<principal>`, the same lock the reset takes, so a
//!   proof cannot go stale between the check and the replacement. Verifying outside the lock (as
//!   the first cut did) let an attacker who holds a live session and the current credential race
//!   the owner's change and land a replacement authorized by a credential that was already gone.
//! - **F2, the guess budget is PER SESSION, not shared with login.** Five failed proofs from one
//!   session cookie REVOKE that session (`credential-guess-exhausted-chirho`) rather than throttle
//!   it — terminating a stolen-cookie holder's access instead of merely slowing it, and never
//!   letting failures here spend the owner's login budget. A fresh session (re-login, which proves
//!   the password) starts a fresh budget. The count lives in its own signed log keyed by the
//!   session's token hash, so this road touches neither the shared auth-attempt limiter nor the
//!   credential-guess family it used to share (both withdrawn).
//!
//! Every refusal here happens before any credential write: a mismatch records one failed-proof row
//! for the session and nothing else; a replacement below the floor records nothing at all. Typed
//! refusals, never prose, so the product page owns the customer's words. Part of
//! `spec-chirho/workflows-chirho/identity-auth-chirho/self-service-credential-change-chirho.md`.

use super::*;
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;

/// The reason the session revocation carries when a session exhausts its guess budget.
pub const CREDENTIAL_GUESS_EXHAUSTED_REVOCATION_REASON_CHIRHO: &str =
    "credential-guess-exhausted-chirho";
/// The reason the reset record and the reset's own revoked sessions carry.
pub const SELF_SERVICE_CREDENTIAL_CHANGE_REASON_CHIRHO: &str =
    "self-service-credential-change-chirho";
/// Failed current-credential proofs one session may make before it is revoked. A lifetime budget,
/// not a window: a live session can only reach this door while it is live, and exhaustion ends it.
pub const CREDENTIAL_CHANGE_SESSION_MAX_FAILURES_CHIRHO: u64 = 5;
const CREDENTIAL_CHANGE_ATTEMPT_RECORD_SCHEMA_CHIRHO: &str =
    "identity-credential-change-attempt-record-v1-chirho";

/// One signed, plaintext-free record of a failed current-credential proof by a session, keyed by
/// the session's token hash (never the token, never either credential). The per-session budget
/// counts these; the log joins the identity family's verification and the JSONL inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCredentialChangeAttemptChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub principal_hash_chirho: String,
    pub session_hash_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// Fixed refusal tokens a product surface maps to sentences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialChangeRefusalChirho {
    CredentialMismatchChirho,
    CredentialTooWeakChirho,
    /// The session spent its per-session guess budget and was revoked in the same act. This is NOT
    /// throttling: the session is gone, so the served road must clear the dead cookie and send her
    /// to the PUBLIC login, never back to a page her revoked session can no longer open (that is
    /// the bare-403 return-path defect this identity fixes, PFE gpt #22471). On this road a spent
    /// budget was the only "rate-limited" state there ever was, so it replaces it here outright.
    CredentialGuessExhaustedChirho,
}

impl CredentialChangeRefusalChirho {
    pub fn token_chirho(self) -> &'static str {
        match self {
            Self::CredentialMismatchChirho => "credential-mismatch-chirho",
            Self::CredentialTooWeakChirho => "credential-too-weak-chirho",
            Self::CredentialGuessExhaustedChirho => "credential-guess-exhausted-chirho",
        }
    }
}

impl std::fmt::Display for CredentialChangeRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token_chirho())
    }
}

impl std::error::Error for CredentialChangeRefusalChirho {}

/// The token for any error this road returns: its own refusals by identity; anything else is an
/// engine error with no customer token. A spent per-session guess budget refuses AS
/// `CredentialGuessExhaustedChirho` (not the shared auth limiter's error), so no downcast is needed.
pub fn credential_change_refusal_token_chirho(
    error_chirho: &anyhow::Error,
) -> Option<&'static str> {
    error_chirho
        .downcast_ref::<CredentialChangeRefusalChirho>()
        .map(|refusal_chirho| refusal_chirho.token_chirho())
}

fn credential_change_attempts_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identity-credential-change-attempts-chirho.jsonl")
}

fn credential_change_attempt_message_chirho(
    record_chirho: &IdentityCredentialChangeAttemptChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

/// Load + VERIFY the change-attempt log in one parse: dense seq and every signature against the
/// root pubkey. A consumer that needs verified rows takes them from here; the load is O(rows in
/// this log), which is the same shape as the auth-attempt log and joins the M250 windowed /
/// retirement treatment before any public activation — but this log is session-gated (only a
/// signed-in caller reaches the door), so it is not the anonymous flood surface.
pub fn verify_credential_change_attempts_chirho(root_chirho: &Path) -> Result<usize> {
    load_verified_credential_change_attempts_chirho(root_chirho)
        .map(|records_chirho| records_chirho.len())
}

pub fn load_verified_credential_change_attempts_chirho(
    root_chirho: &Path,
) -> Result<Vec<IdentityCredentialChangeAttemptChirho>> {
    let path_chirho = credential_change_attempts_path_chirho(root_chirho);
    // The log is read first, so a genuinely absent one loads no key; one that cannot be examined refuses.
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut records_chirho = Vec::new();
    for (i_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: IdentityCredentialChangeAttemptChirho =
            serde_json::from_str(line_chirho)?;
        verify_identity_record_schema_chirho(
            &record_chirho.schema_chirho,
            CREDENTIAL_CHANGE_ATTEMPT_RECORD_SCHEMA_CHIRHO,
            "identity credential change attempt record",
        )?;
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "identity credential change attempt seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = credential_change_attempt_message_chirho(&record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "identity credential change attempt {} signature invalid",
                record_chirho.seq_chirho
            );
        }
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

/// Count a session's failed current-credential proofs. Verifies the whole log first, so a tampered
/// row fails the count closed rather than under- or over-counting a security budget.
fn count_credential_change_failures_for_session_chirho(
    root_chirho: &Path,
    session_hash_chirho: &str,
) -> Result<u64> {
    Ok(
        load_verified_credential_change_attempts_chirho(root_chirho)?
            .into_iter()
            .filter(|record_chirho| record_chirho.session_hash_chirho == session_hash_chirho)
            .count() as u64,
    )
}

fn append_credential_change_failure_chirho(
    root_chirho: &Path,
    principal_hash_chirho: &str,
    session_hash_chirho: &str,
) -> Result<()> {
    let path_chirho = credential_change_attempts_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        verify_credential_change_attempts_chirho(root_chirho)?;
        let mut record_chirho = IdentityCredentialChangeAttemptChirho {
            seq_chirho,
            schema_chirho: CREDENTIAL_CHANGE_ATTEMPT_RECORD_SCHEMA_CHIRHO.to_string(),
            principal_hash_chirho: principal_hash_chirho.to_string(),
            session_hash_chirho: session_hash_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = credential_change_attempt_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })?;
    Ok(())
}

/// Change the principal's own credential, from the session identified by `session_token_chirho`.
/// The whole flow runs INSIDE the principal's credential lock so the proof and the replacement are
/// one critical section (F1): per-session budget → verify the CURRENT credential (a mismatch
/// records one failed-proof row and, at the fifth, revokes this session) → floor on the
/// replacement (below-floor writes nothing) → the reset act (revoke every live session first,
/// replace, signed record with actor = principal). The caller must have established that
/// `principal_chirho` is `session_token_chirho`'s principal; this function never reads the
/// principal from a request body.
pub fn change_identity_credential_for_session_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    session_token_chirho: &str,
    current_credential_chirho: &str,
    new_credential_chirho: &str,
) -> Result<IdentityCredentialResetReportChirho> {
    let session_hash_chirho = token_hash_chirho(session_token_chirho);
    let principal_hash_chirho = auth_attempt_principal_hash_chirho(principal_chirho);
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &credential_lock_name_chirho(principal_chirho),
        || {
            let prior_failures_chirho = count_credential_change_failures_for_session_chirho(
                root_chirho,
                &session_hash_chirho,
            )?;
            if prior_failures_chirho >= CREDENTIAL_CHANGE_SESSION_MAX_FAILURES_CHIRHO {
                // Already exhausted: make sure the session is dead (idempotent) and refuse.
                revoke_session_token_chirho(
                    root_chirho,
                    principal_chirho,
                    session_token_chirho,
                    principal_chirho,
                    CREDENTIAL_GUESS_EXHAUSTED_REVOCATION_REASON_CHIRHO,
                )?;
                return Err(anyhow::Error::new(
                    CredentialChangeRefusalChirho::CredentialGuessExhaustedChirho,
                ));
            }
            let key_record_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho)?;
            if verify_identity_credential_chirho(&key_record_chirho, current_credential_chirho)
                .is_err()
            {
                append_credential_change_failure_chirho(
                    root_chirho,
                    &principal_hash_chirho,
                    &session_hash_chirho,
                )?;
                if prior_failures_chirho + 1 >= CREDENTIAL_CHANGE_SESSION_MAX_FAILURES_CHIRHO {
                    revoke_session_token_chirho(
                        root_chirho,
                        principal_chirho,
                        session_token_chirho,
                        principal_chirho,
                        CREDENTIAL_GUESS_EXHAUSTED_REVOCATION_REASON_CHIRHO,
                    )?;
                    // This failed proof spent the budget and revoked the session in the same act, so
                    // she must be sent to the public login, not back to a page her dead session can
                    // no longer open. Return the exhaustion identity, not another mismatch: the
                    // mismatch fragment is the answer only while the session survives (PFE gpt #22471).
                    return Err(anyhow::Error::new(
                        CredentialChangeRefusalChirho::CredentialGuessExhaustedChirho,
                    ));
                }
                return Err(anyhow::Error::new(
                    CredentialChangeRefusalChirho::CredentialMismatchChirho,
                ));
            }
            if !credential_meets_floor_chirho(new_credential_chirho) {
                return Err(anyhow::Error::new(
                    CredentialChangeRefusalChirho::CredentialTooWeakChirho,
                ));
            }
            reset_identity_credential_locked_chirho(
                root_chirho,
                principal_chirho,
                new_credential_chirho,
                principal_chirho,
                SELF_SERVICE_CREDENTIAL_CHANGE_REASON_CHIRHO,
                CredentialReplacementCauseChirho::SelfServiceChangeChirho,
            )
        },
    )
}
