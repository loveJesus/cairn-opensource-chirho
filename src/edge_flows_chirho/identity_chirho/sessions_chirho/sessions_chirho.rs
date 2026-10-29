// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The session road: identity sessions and their revocations, their two logs, the verified session index and
//! revocation set over them (brick 4b), the one liveness predicate the cookie and bearer roads share, and revoking.

use super::*;
use cairn_durable_chirho::log_path_chirho::{classify_log_path_chirho, LogPathChirho};
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;

#[path = "session_listing_chirho.rs"]
mod session_listing_chirho;
pub use session_listing_chirho::{
    list_principal_sessions_chirho, IdentitySessionStateChirho, IdentitySessionStatusChirho,
};
#[path = "revocation_view_chirho.rs"]
mod revocation_view_chirho;
#[path = "session_issue_chirho.rs"]
mod session_issue_chirho;
#[path = "session_view_chirho.rs"]
mod session_view_chirho;
pub(crate) use session_issue_chirho::with_connection_session_door_chirho;
pub(super) use session_issue_chirho::{append_session_row_unlocked_chirho, SessionLifetimeChirho};
#[cfg(test)]
pub(crate) use session_issue_chirho::{
    connection_issue_locks_held_chirho, set_connection_proved_hold_chirho,
};
pub use session_issue_chirho::{
    BROWSER_SESSION_LIFETIME_MS_CHIRHO, CONNECTION_SESSION_LIFETIME_MS_CHIRHO,
};
#[cfg(test)]
#[path = "session_views_tests_chirho.rs"]
mod session_views_tests_chirho;

pub(super) const IDENTITY_SESSION_RECORD_SCHEMA_CHIRHO: &str = "identity-session-record-v1-chirho";

pub(super) const IDENTITY_SESSION_REVOCATION_RECORD_SCHEMA_CHIRHO: &str =
    "identity-session-revocation-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySessionChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub principal_chirho: String,
    pub token_hash_chirho: String,
    /// The key record's `credential_generation_chirho` at the moment this session was issued.
    /// Session validation requires it still equal the current one, so a login that verified a
    /// credential a reset then replaced dies at commit rather than by session enumeration.
    #[serde(default, skip_serializing_if = "is_zero_generation_chirho")]
    pub credential_generation_chirho: u64,
    pub proof_chirho: String,
    pub issued_ms_chirho: u64,
    pub expires_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySessionRevocationRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub principal_chirho: String,
    pub session_seq_chirho: u64,
    pub token_hash_chirho: String,
    pub actor_chirho: String,
    pub reason_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub(super) fn sessions_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identity-sessions-chirho.jsonl")
}

pub(super) fn session_revocations_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identity-session-revocations-chirho.jsonl")
}

pub fn load_sessions_chirho(root_chirho: &Path) -> Result<Vec<IdentitySessionChirho>> {
    #[cfg(test)]
    session_read_metrics_chirho::note_chirho();
    let path_chirho = sessions_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut sessions_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        sessions_chirho.push(parse_session_line_chirho(line_chirho)?);
    }
    Ok(sessions_chirho)
}

/// One session line, parsed as the loader and the session index both parse it: the record, then its schema.
fn parse_session_line_chirho(line_chirho: &str) -> Result<IdentitySessionChirho> {
    #[cfg(test)]
    session_read_metrics_chirho::note_session_parse_chirho();
    let session_chirho: IdentitySessionChirho = serde_json::from_str(line_chirho)?;
    verify_identity_record_schema_chirho(
        &session_chirho.schema_chirho,
        IDENTITY_SESSION_RECORD_SCHEMA_CHIRHO,
        "identity session record",
    )?;
    Ok(session_chirho)
}

pub fn load_session_revocations_chirho(
    root_chirho: &Path,
) -> Result<Vec<IdentitySessionRevocationRecordChirho>> {
    let path_chirho = session_revocations_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut revocations_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        revocations_chirho.push(parse_session_revocation_line_chirho(line_chirho)?);
    }
    Ok(revocations_chirho)
}

/// One revocation line, parsed as the loader and the revocation set both parse it: the record, then its schema.
fn parse_session_revocation_line_chirho(
    line_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    #[cfg(test)]
    session_read_metrics_chirho::note_revocation_parse_chirho();
    let revocation_chirho: IdentitySessionRevocationRecordChirho =
        serde_json::from_str(line_chirho)?;
    verify_identity_record_schema_chirho(
        &revocation_chirho.schema_chirho,
        IDENTITY_SESSION_REVOCATION_RECORD_SCHEMA_CHIRHO,
        "identity session revocation record",
    )?;
    Ok(revocation_chirho)
}

/// Load + VERIFY the session log in ONE parse — dense seq and every record signature — and return
/// the verified records. Consumers that route on a session field (principal, seq) must take rows
/// from HERE, so a tampered field cannot exclude a row from the verification that would have
/// caught it. Same law as [`load_verified_identities_chirho`].
pub fn load_verified_sessions_chirho(root_chirho: &Path) -> Result<Vec<IdentitySessionChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let sessions_chirho = load_sessions_chirho(root_chirho)?;
    for (i_chirho, session_chirho) in sessions_chirho.iter().enumerate() {
        if session_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "identity session seq gap at index {i_chirho}: entry seq is {}",
                session_chirho.seq_chirho
            );
        }
        verify_session_record_chirho(root_chirho, &pubkey_chirho, session_chirho)?;
    }
    Ok(sessions_chirho)
}

/// The session a scoped token was issued from, VERIFIED: found by principal and seq in the session index, whose fold
/// verified it (the identity's key proof and the instance signature). The scoped-token view checks each token's own
/// session this way when it folds the token (brick 4a-2); since brick 4b the lookup no longer parses the session log.
pub fn verified_session_for_token_chirho(
    root_chirho: &Path,
    instance_pubkey_chirho: &str,
    principal_chirho: &str,
    session_seq_chirho: u64,
) -> Result<Option<IdentitySessionChirho>> {
    session_view_chirho::session_by_seq_chirho(
        root_chirho,
        instance_pubkey_chirho,
        principal_chirho,
        session_seq_chirho,
    )
}

pub fn verify_sessions_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_sessions_chirho(root_chirho)?.len())
}

/// Load + VERIFY the revocation log in ONE parse and return the verified records, so a decision
/// that a session is already revoked rests on a row somebody signed.
pub fn load_verified_session_revocations_chirho(
    root_chirho: &Path,
) -> Result<Vec<IdentitySessionRevocationRecordChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let sessions_chirho = load_sessions_chirho(root_chirho)?;
    let revocations_chirho = load_session_revocations_chirho(root_chirho)?;
    for (i_chirho, revocation_chirho) in revocations_chirho.iter().enumerate() {
        if revocation_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "identity session revocation seq gap at index {i_chirho}: entry seq is {}",
                revocation_chirho.seq_chirho
            );
        }
        verify_session_revocation_record_chirho(
            root_chirho,
            &pubkey_chirho,
            |revocation_chirho| {
                Ok(sessions_chirho
                    .iter()
                    .find(|session_chirho| {
                        session_chirho.principal_chirho == revocation_chirho.principal_chirho
                            && session_chirho.seq_chirho == revocation_chirho.session_seq_chirho
                            && session_chirho.token_hash_chirho
                                == revocation_chirho.token_hash_chirho
                    })
                    .cloned())
            },
            revocation_chirho,
        )?;
    }
    Ok(revocations_chirho)
}

pub fn verify_session_revocations_chirho(root_chirho: &Path) -> Result<usize> {
    Ok(load_verified_session_revocations_chirho(root_chirho)?.len())
}

pub fn validate_session_token_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    token_chirho: &str,
) -> Result<Option<IdentitySessionChirho>> {
    validate_session_token_at_chirho(root_chirho, principal_chirho, token_chirho, now_ms_chirho())
}

/// The cookie check at `now_ms_chirho` (brick 4b): the newest verified session of this principal with this token's hash,
/// from the session index, then `session_live_chirho`. Today's scan selected that row by its unverified fields and then
/// verified it; the index holds verified sessions only, and picks the same row.
/// Workflow: the cookie and bearer roads, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4b, as built).
fn validate_session_token_at_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    token_chirho: &str,
    now_ms_chirho: u64,
) -> Result<Option<IdentitySessionChirho>> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let Some(session_chirho) = session_view_chirho::session_by_token_hash_chirho(
        root_chirho,
        &pubkey_chirho,
        principal_chirho,
        &token_hash_chirho(token_chirho),
    )?
    else {
        return Ok(None);
    };
    Ok(
        session_live_chirho(root_chirho, &pubkey_chirho, &session_chirho, now_ms_chirho)?
            .then_some(session_chirho),
    )
}

/// THE ONE LIVENESS PREDICATE (brick 4b): a session is live at `now_ms_chirho` while it is unexpired, its credential
/// generation is still the identity key record's, and it is not revoked. The cookie road asks it of its session and the
/// bearer road of its key's session, so a key lives exactly as long as its session: revoking the session, or resetting
/// the credential, ends the key.
/// Workflow: the cookie and bearer roads, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4b, as built).
fn session_live_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    session_chirho: &IdentitySessionChirho,
    now_ms_chirho: u64,
) -> Result<bool> {
    if session_chirho.expires_ms_chirho < now_ms_chirho {
        return Ok(false);
    }
    // A session outlives its credential generation: a reset after issue makes it stale by
    // construction, closing the login-racing-a-reset window without serializing login. This is
    // one extra key-record read per check (O(1), a single principal's file, not a log scan), on
    // the road every authenticated request runs.
    #[cfg(test)]
    super::session_read_metrics_chirho::note_key_record_read_chirho();
    let key_record_chirho =
        load_identity_key_record_chirho(root_chirho, &session_chirho.principal_chirho)?;
    if session_chirho.credential_generation_chirho != key_record_chirho.credential_generation_chirho
    {
        return Ok(false);
    }
    Ok(!session_is_revoked_chirho(
        root_chirho,
        pubkey_chirho,
        session_chirho,
    )?)
}

/// Whether the session a key was issued from is live at `now_ms_chirho` (brick 4b): the session index finds it by
/// principal and seq, then `session_live_chirho` decides. A key whose session is missing is not live. The bearer road
/// asks this on every request, so a key refuses as soon as its session is revoked or its credential reset.
/// Workflow: the cookie and bearer roads, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4b, as built).
pub fn key_session_live_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    principal_chirho: &str,
    session_seq_chirho: u64,
    now_ms_chirho: u64,
) -> Result<bool> {
    match session_view_chirho::session_by_seq_chirho(
        root_chirho,
        pubkey_chirho,
        principal_chirho,
        session_seq_chirho,
    )? {
        Some(session_chirho) => {
            session_live_chirho(root_chirho, pubkey_chirho, &session_chirho, now_ms_chirho)
        }
        None => Ok(false),
    }
}

/// Build the root's session index and revocation set now, so the first cookie and bearer requests find them ready. It
/// loads the instance key pair through the custody-checked loader, which creates and changes nothing and derives the
/// same public key the requests derive, so the views it builds are the ones they read. A root with no session log has
/// nothing to warm.
pub fn warm_session_views_chirho(root_chirho: &Path) -> Result<()> {
    // Absent is left for the first request; a log that cannot be examined is reported, and requests refuse on their own.
    if let LogPathChirho::AbsentChirho =
        classify_log_path_chirho(&sessions_path_chirho(root_chirho))?
    {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)?;
    session_view_chirho::warm_session_index_chirho(root_chirho, &pubkey_chirho)?;
    revocation_view_chirho::warm_revocation_set_chirho(root_chirho, &pubkey_chirho)
}

/// Warm the root's session views on their own thread: the serve runtime calls this after it binds, as it warms the
/// token views. A failure is not fatal: cookie and bearer requests refuse on their own until the logs verify. The line it
/// prints names no session, principal or path.
/// Workflow: the cookie and bearer roads, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4b, as built).
pub fn spawn_session_views_warm_up_chirho(root_chirho: &Path) {
    let root_chirho = root_chirho.to_path_buf();
    let spawned_chirho = std::thread::Builder::new()
        .name("cairn-session-views-warm-chirho".to_string())
        .spawn(move || {
            if warm_session_views_chirho(&root_chirho).is_err() {
                eprintln!(
                    "cairn-chirho: the session logs did not verify at startup; cookie and bearer requests refuse \
                     until they do (identity-sessions-verify and identity-session-revocations-verify show why)"
                );
            }
        });
    if spawned_chirho.is_err() {
        eprintln!(
            "cairn-chirho: the session views' warm-up did not start; the first cookie or bearer request builds them"
        );
    }
}

pub fn revoke_session_token_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    token_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    if token_chirho.trim().is_empty() {
        bail!("session token is required");
    }
    let token_hash_chirho = token_hash_chirho(token_chirho);
    revoke_session_token_hash_chirho(
        root_chirho,
        principal_chirho,
        &token_hash_chirho,
        actor_chirho,
        reason_chirho,
    )
}

pub fn revoke_session_by_seq_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    session_seq_chirho: u64,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    let session_chirho =
        find_verified_session_by_seq_chirho(root_chirho, principal_chirho, session_seq_chirho)?
            .ok_or_else(|| {
                anyhow!(
            "identity session {session_seq_chirho} not found for principal '{principal_chirho}'"
        )
            })?;
    append_session_revocation_chirho(root_chirho, &session_chirho, actor_chirho, reason_chirho)
}

/// `revoke_session_by_seq_chirho` for a caller that already holds the root-wide append-log lock, so a revocation and
/// the caller's own append land in one locked section (the limited-key opt-in, K1).
pub fn revoke_session_by_seq_under_append_lock_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    session_seq_chirho: u64,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    let session_chirho =
        find_verified_session_by_seq_chirho(root_chirho, principal_chirho, session_seq_chirho)?
            .ok_or_else(|| {
                anyhow!(
            "identity session {session_seq_chirho} not found for principal '{principal_chirho}'"
        )
            })?;
    validate_session_revocation_actor_chirho(actor_chirho)?;
    validate_session_revocation_reason_chirho(reason_chirho)?;
    revocation_view_chirho::revoke_under_append_lock_chirho(
        root_chirho,
        &session_chirho,
        actor_chirho,
        reason_chirho,
    )
}

pub(super) fn revoke_session_token_hash_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    token_hash_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    validate_session_token_hash_chirho(token_hash_chirho)?;
    let session_chirho = find_verified_session_by_token_hash_chirho(
        root_chirho,
        principal_chirho,
        token_hash_chirho,
    )?
    .ok_or_else(|| {
        anyhow!("identity session token not found for principal '{principal_chirho}'")
    })?;
    append_session_revocation_chirho(root_chirho, &session_chirho, actor_chirho, reason_chirho)
}

/// Revoke `session_chirho` through the revocation set's append door (brick 4b): one record per session, decided under the
/// append-log lock, so a repeat, even a concurrent one, answers the first record and appends nothing.
/// Workflow: the cookie and bearer roads, `spec-chirho/workflows-chirho/identity-auth-chirho/auth-wave-brick4-design-chirho.md`
/// (4b, as built).
pub(super) fn append_session_revocation_chirho(
    root_chirho: &Path,
    session_chirho: &IdentitySessionChirho,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentitySessionRevocationRecordChirho> {
    validate_session_revocation_actor_chirho(actor_chirho)?;
    validate_session_revocation_reason_chirho(reason_chirho)?;
    revocation_view_chirho::revoke_through_door_chirho(
        root_chirho,
        session_chirho,
        actor_chirho,
        reason_chirho,
    )
}

pub(super) fn find_verified_session_by_token_hash_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    token_hash_chirho: &str,
) -> Result<Option<IdentitySessionChirho>> {
    validate_session_token_hash_chirho(token_hash_chirho)?;
    session_view_chirho::session_by_token_hash_chirho(
        root_chirho,
        &signer_chirho::pubkey_hex_chirho(root_chirho)?,
        principal_chirho,
        token_hash_chirho,
    )
}

pub(super) fn find_verified_session_by_seq_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    session_seq_chirho: u64,
) -> Result<Option<IdentitySessionChirho>> {
    session_view_chirho::session_by_seq_chirho(
        root_chirho,
        &signer_chirho::pubkey_hex_chirho(root_chirho)?,
        principal_chirho,
        session_seq_chirho,
    )
}

/// Whether `session_chirho` is revoked: one lookup in the verified revocation set (brick 4b), where today verified the
/// whole revocation log and then scanned it again.
pub(super) fn session_is_revoked_chirho(
    root_chirho: &Path,
    pubkey_chirho: &str,
    session_chirho: &IdentitySessionChirho,
) -> Result<bool> {
    revocation_view_chirho::session_revoked_chirho(root_chirho, pubkey_chirho, session_chirho)
}

pub(super) fn session_message_chirho(session_chirho: &IdentitySessionChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = session_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

pub(super) fn session_revocation_message_chirho(
    revocation_chirho: &IdentitySessionRevocationRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = revocation_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

#[derive(Serialize)]
pub(super) struct SessionProofPayloadChirho<'a> {
    seq_chirho: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema_chirho: Option<&'a str>,
    principal_chirho: &'a str,
    token_hash_chirho: &'a str,
    issued_ms_chirho: u64,
    expires_ms_chirho: u64,
}

pub(super) fn session_proof_message_chirho(
    session_chirho: &IdentitySessionChirho,
) -> Result<Vec<u8>> {
    let payload_chirho = SessionProofPayloadChirho {
        seq_chirho: session_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&session_chirho.schema_chirho),
        principal_chirho: &session_chirho.principal_chirho,
        token_hash_chirho: &session_chirho.token_hash_chirho,
        issued_ms_chirho: session_chirho.issued_ms_chirho,
        expires_ms_chirho: session_chirho.expires_ms_chirho,
    };
    Ok(serde_json::to_vec(&payload_chirho)?)
}

pub(super) fn validate_session_token_hash_chirho(token_hash_chirho: &str) -> Result<()> {
    if token_hash_chirho.len() != 64
        || !token_hash_chirho
            .chars()
            .all(|c_chirho| c_chirho.is_ascii_hexdigit())
    {
        bail!("identity session token hash is invalid");
    }
    Ok(())
}

pub(super) fn validate_session_revocation_actor_chirho(actor_chirho: &str) -> Result<()> {
    let actor_chirho = actor_chirho.trim();
    if actor_chirho.is_empty() {
        bail!("session revocation actor_chirho is required");
    }
    if actor_chirho.len() > 128 {
        bail!("session revocation actor_chirho is too long");
    }
    if !actor_chirho
        .chars()
        .all(|c_chirho| c_chirho.is_ascii_alphanumeric() || matches!(c_chirho, '/' | '_' | '-'))
    {
        bail!("session revocation actor_chirho has unsupported characters");
    }
    Ok(())
}

pub(super) fn validate_session_revocation_reason_chirho(reason_chirho: &str) -> Result<()> {
    let reason_chirho = reason_chirho.trim();
    if reason_chirho.is_empty() {
        bail!("session revocation reason_chirho is required");
    }
    if reason_chirho.len() > 256 {
        bail!("session revocation reason_chirho is too long");
    }
    if reason_chirho
        .chars()
        .any(|c_chirho| c_chirho.is_control() && c_chirho != '\n' && c_chirho != '\t')
    {
        bail!("session revocation reason_chirho has unsupported control characters");
    }
    Ok(())
}

/// One revocation record's checks. `find_session_chirho` finds its target session by principal, seq and token hash:
/// the full verifier searches the whole session log, and the revocation set asks the session index (brick 4b).
pub(super) fn verify_session_revocation_record_chirho(
    root_chirho: &Path,
    instance_pubkey_chirho: &str,
    find_session_chirho: impl FnOnce(
        &IdentitySessionRevocationRecordChirho,
    ) -> Result<Option<IdentitySessionChirho>>,
    revocation_chirho: &IdentitySessionRevocationRecordChirho,
) -> Result<()> {
    validate_session_token_hash_chirho(&revocation_chirho.token_hash_chirho)?;
    validate_session_revocation_actor_chirho(&revocation_chirho.actor_chirho)?;
    validate_session_revocation_reason_chirho(&revocation_chirho.reason_chirho)?;
    let session_chirho = find_session_chirho(revocation_chirho)?.ok_or_else(|| {
        anyhow!(
            "identity session revocation {} references missing session {} for principal '{}'",
            revocation_chirho.seq_chirho,
            revocation_chirho.session_seq_chirho,
            revocation_chirho.principal_chirho
        )
    })?;
    verify_session_record_chirho(root_chirho, instance_pubkey_chirho, &session_chirho)?;
    if revocation_chirho.at_ms_chirho < session_chirho.issued_ms_chirho {
        bail!(
            "identity session revocation {} predates target session {}",
            revocation_chirho.seq_chirho,
            revocation_chirho.session_seq_chirho
        );
    }
    let message_chirho = session_revocation_message_chirho(revocation_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        instance_pubkey_chirho,
        &message_chirho,
        &revocation_chirho.sig_chirho,
    )? {
        bail!(
            "identity session revocation {} signature invalid",
            revocation_chirho.seq_chirho
        );
    }
    Ok(())
}

pub(super) fn verify_session_record_chirho(
    root_chirho: &Path,
    instance_pubkey_chirho: &str,
    session_chirho: &IdentitySessionChirho,
) -> Result<()> {
    let identity_chirho = find_identity_chirho(root_chirho, &session_chirho.principal_chirho)?
        .ok_or_else(|| {
            anyhow!(
                "session references unknown principal '{}'",
                session_chirho.principal_chirho
            )
        })?;
    let proof_message_chirho = session_proof_message_chirho(session_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        &identity_chirho.pubkey_chirho,
        &proof_message_chirho,
        &session_chirho.proof_chirho,
    )? {
        bail!(
            "identity session {} local key proof invalid",
            session_chirho.seq_chirho
        );
    }
    let message_chirho = session_message_chirho(session_chirho)?;
    if !signer_chirho::verify_with_pubkey_chirho(
        instance_pubkey_chirho,
        &message_chirho,
        &session_chirho.sig_chirho,
    )? {
        bail!(
            "identity session {} signature invalid",
            session_chirho.seq_chirho
        );
    }
    Ok(())
}
