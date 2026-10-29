// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Issuing a session: every session row is written by one signer, with a lifetime fixed by its kind (a browser's 24
//! hours, a connection's 30 days), and a connection's issuer appends its session through a door that opens only inside
//! its own locked decision, so a refused issuance writes no session (K4 Part 2).
//!
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (Part 2, as built).

use super::*;

/// A browser session's life: a login's session, and so a legacy-store key's, which is issued from one.
pub const BROWSER_SESSION_LIFETIME_MS_CHIRHO: u64 = 24 * 60 * 60 * 1000;

/// A connection's life (K4 Part 2): the session a connection-store key is issued from, and so the key. It is fixed at
/// issuance and never renewed.
pub const CONNECTION_SESSION_LIFETIME_MS_CHIRHO: u64 = 30 * BROWSER_SESSION_LIFETIME_MS_CHIRHO;

/// Which life a new session gets. A closed choice: no caller supplies a duration, so no road can lengthen one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::identity_chirho) enum SessionLifetimeChirho {
    BrowserChirho,
    ConnectionChirho,
}

impl SessionLifetimeChirho {
    fn ms_chirho(self) -> u64 {
        match self {
            Self::BrowserChirho => BROWSER_SESSION_LIFETIME_MS_CHIRHO,
            Self::ConnectionChirho => CONNECTION_SESSION_LIFETIME_MS_CHIRHO,
        }
    }
}

/// Append one session row for a proved principal, by a caller that holds the root append lock. The row is stamped with
/// the proved key record's credential generation and signed twice: by the principal's identity key (its proof, checked
/// against the identity's public key before anything is written) and by the root's signer. Every session is written
/// here; a browser login and a connection's issuance differ only in `lifetime_chirho`, and in what becomes of the token
/// behind `token_hash_chirho`.
pub(in crate::identity_chirho) fn append_session_row_unlocked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    identity_chirho: &IdentityRecordChirho,
    key_record_chirho: &IdentityKeyChirho,
    lifetime_chirho: SessionLifetimeChirho,
    issued_ms_chirho: u64,
    token_hash_chirho: String,
) -> Result<IdentitySessionChirho> {
    let signing_key_chirho = signing_key_from_identity_key_chirho(key_record_chirho)?;
    let expires_ms_chirho = issued_ms_chirho + lifetime_chirho.ms_chirho();
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(
        &sessions_path_chirho(root_chirho),
        |seq_chirho| {
            let mut session_chirho = IdentitySessionChirho {
                seq_chirho,
                schema_chirho: IDENTITY_SESSION_RECORD_SCHEMA_CHIRHO.to_string(),
                principal_chirho: principal_chirho.to_string(),
                token_hash_chirho,
                credential_generation_chirho: key_record_chirho.credential_generation_chirho,
                proof_chirho: String::new(),
                issued_ms_chirho,
                expires_ms_chirho,
                sig_chirho: String::new(),
            };
            let proof_message_chirho = session_proof_message_chirho(&session_chirho)?;
            session_chirho.proof_chirho =
                hex_encode_chirho(&signing_key_chirho.sign(&proof_message_chirho).to_bytes());
            if !signer_chirho::verify_with_pubkey_chirho(
                &identity_chirho.pubkey_chirho,
                &proof_message_chirho,
                &session_chirho.proof_chirho,
            )? {
                bail!("local identity key did not verify for '{principal_chirho}'");
            }
            let message_chirho = session_message_chirho(&session_chirho)?;
            session_chirho.sig_chirho =
                signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
            Ok(session_chirho)
        },
    )
}

/// The door a connection's issuer appends its session through (K4 Part 2). It exists only inside
/// `with_connection_session_door_chirho`, after the credential is proved and while both locks are held, and appending
/// consumes it, so one decision appends at most one session.
pub(crate) struct ConnectionSessionDoorChirho<'door_chirho> {
    root_chirho: &'door_chirho Path,
    principal_chirho: &'door_chirho str,
    identity_chirho: &'door_chirho IdentityRecordChirho,
    key_record_chirho: &'door_chirho IdentityKeyChirho,
}

impl ConnectionSessionDoorChirho<'_> {
    /// The principal whose credential was proved.
    pub(crate) fn principal_chirho(&self) -> &str {
        self.principal_chirho
    }

    /// Append the connection's session, issued at `issued_ms_chirho` for the connection's 30 days and stamped with the
    /// proved credential generation. Its token is made, hashed into the row and dropped here: nobody ever holds it, so
    /// it cannot be returned, installed as a cookie, logged, or presented as a browser session.
    pub(crate) fn append_session_chirho(
        self,
        issued_ms_chirho: u64,
    ) -> Result<IdentitySessionChirho> {
        append_session_row_unlocked_chirho(
            self.root_chirho,
            self.principal_chirho,
            self.identity_chirho,
            self.key_record_chirho,
            SessionLifetimeChirho::ConnectionChirho,
            issued_ms_chirho,
            token_hash_chirho(&random_token_chirho()),
        )
    }
}

/// Test-only: one step an issuance runs on this thread, taken once.
#[cfg(test)]
type ProvedHoldSlotChirho = std::cell::RefCell<Option<Box<dyn FnOnce() -> Result<()>>>>;

#[cfg(test)]
thread_local! {
    static PROVED_HOLD_CHIRHO: ProvedHoldSlotChirho = const { std::cell::RefCell::new(None) };
}

/// Test-only: a step the next connection issuance on this thread runs just after its credential is proved, while it
/// holds the credential lock and before it takes the append lock, so a racing reset meets the credential lock there.
#[cfg(test)]
pub(crate) fn set_connection_proved_hold_chirho(
    hold_chirho: impl FnOnce() -> Result<()> + 'static,
) {
    PROVED_HOLD_CHIRHO.with(|slot_chirho| *slot_chirho.borrow_mut() = Some(Box::new(hold_chirho)));
}

/// Test-only: whether the named lock `name_chirho` is held right now, by a non-blocking try on its lock file: no timing,
/// the login probe's technique (`login_lock_probe_tests_chirho.rs`). The file is the one seqlog's named lock takes,
/// `locks-chirho/<blake3(name)>.lock`.
#[cfg(test)]
fn named_lock_held_chirho(root_chirho: &Path, name_chirho: &str) -> Result<bool> {
    let path_chirho = root_chirho.join("locks-chirho").join(format!(
        "{}.lock",
        blake3::hash(name_chirho.as_bytes()).to_hex()
    ));
    let file_chirho = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path_chirho)?;
    match file_chirho.try_lock() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(error_chirho) => Err(anyhow!("nonblocking lock probe: {error_chirho}")),
    }
}

/// Test-only: whether `principal_chirho`'s credential lock and the root append lock are held right now. An issuance's
/// hold calls this on its own thread, so the answer is which locks the issuance holds at that step. The append lock's
/// name is seqlog's (`with_append_log_lock_chirho`).
#[cfg(test)]
pub(crate) fn connection_issue_locks_held_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<(bool, bool)> {
    Ok((
        named_lock_held_chirho(root_chirho, &credential_lock_name_chirho(principal_chirho))?,
        named_lock_held_chirho(root_chirho, "append-log-chirho")?,
    ))
}

fn run_connection_proved_hold_chirho() -> Result<()> {
    #[cfg(test)]
    if let Some(hold_chirho) =
        PROVED_HOLD_CHIRHO.with(|slot_chirho| slot_chirho.borrow_mut().take())
    {
        return hold_chirho();
    }
    Ok(())
}

/// The identity half of a connection key's issuance (K4 Part 2), deciding before creating. It proves
/// `credential_chirho` while holding the principal's credential lock, so the argon2 work stays outside the root append
/// lock. It keeps that lock, takes the root append lock, and runs `decide_chirho` there with the door to the
/// connection's session. So the caller decides its cap before its session or key is appended, and a refusal appends
/// neither. The root is not otherwise untouched: the proof may re-hash a legacy credential, as every sign-in does. A
/// credential reset takes the same credential lock, so it lands either before the proof (the old credential then
/// refuses) or after the writes (and ends what they issued), never between them. The lock order is login's and
/// reset's: the credential lock, then the append lock.
/// Workflow: the connection issuance DAG, `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md`
/// (Part 2, as built).
pub(crate) fn with_connection_session_door_chirho<T>(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    decide_chirho: impl FnOnce(ConnectionSessionDoorChirho<'_>) -> Result<T>,
) -> Result<T> {
    if credential_chirho.is_empty() {
        bail!("credential_chirho is required");
    }
    let identity_chirho = find_identity_chirho(root_chirho, principal_chirho)?
        .ok_or_else(|| anyhow!("unknown principal '{principal_chirho}'"))?;
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &credential_lock_name_chirho(principal_chirho),
        || {
            let key_record_chirho = prove_credential_locked_chirho(
                root_chirho,
                principal_chirho,
                Some(credential_chirho),
            )?;
            run_connection_proved_hold_chirho()?;
            seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
                decide_chirho(ConnectionSessionDoorChirho {
                    root_chirho,
                    principal_chirho,
                    identity_chirho: &identity_chirho,
                    key_record_chirho: &key_record_chirho,
                })
            })
        },
    )
}
