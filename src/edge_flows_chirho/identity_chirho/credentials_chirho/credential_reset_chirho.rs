// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Operator credential reset: replace a credentialed principal's HTTP credential AFTER revoking every
//! live session it could still authorize, and leave a signed, plaintext-free reset record.
//!
//! `set_identity_credential_chirho` deliberately refuses a principal that already holds a credential,
//! which left a lost password with one road only: a new principal, which orphans everything keyed by
//! the old principal digest. This module is the missing road. Its ordering is the contract:
//!
//! 1. the principal is taken from the VERIFIED identity log (a log that fails verification refuses
//!    the reset rather than trusting a raw row);
//! 2. the key record must ALREADY carry a credential — a credentialless principal is refused with its
//!    own identity and pointed at `identity-credential-set`, so the two commands never overlap;
//! 3. every unexpired session of the principal is revoked FIRST (signed, append-only, idempotent);
//! 4. only then is the credential replaced and re-verified by reload;
//! 5. a signed reset record is appended to its own log, carrying counts and a digest of the stored
//!    hash — never the credential, never the hash itself.
//!
//! A failure before key rename leaves the complete old key and any completed session revocations.
//! After rename, the new credential can be visible even if parent sync or the reset-log append
//! fails. Key replacement and the evidence append are not one atomic transaction.

use super::*;
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;
use std::collections::HashSet;

pub const IDENTITY_CREDENTIAL_RESET_RECORD_SCHEMA_CHIRHO: &str =
    "identity-credential-reset-record-v1-chirho";
pub const CREDENTIAL_RESET_SESSION_REVOCATION_REASON_CHIRHO: &str = "credential-reset-chirho";
const CREDENTIAL_RESET_LOCK_PREFIX_CHIRHO: &str = "identity-credential-set";
const CREDENTIAL_RESET_DIGEST_DOMAIN_CHIRHO: &[u8] = b"cairn-identity-credential-reset-v1-chirho";

/// Signed evidence that a reset happened, with nothing in it that could authenticate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCredentialResetRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub principal_chirho: String,
    pub actor_chirho: String,
    pub reason_chirho: String,
    /// Sessions revoked by THIS reset. Sessions already revoked or expired are not counted.
    pub revoked_session_count_chirho: u64,
    /// Domain-separated blake3 of the newly stored salt and hash. Binds the record to the key file
    /// state without carrying either value.
    pub credential_state_digest_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

/// What the operator gets back; the CLI prints hashes, never principals or values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCredentialResetReportChirho {
    pub record_chirho: IdentityCredentialResetRecordChirho,
    pub revoked_session_seqs_chirho: Vec<u64>,
}

/// Refusals a caller must be able to tell apart: the road to take differs for each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityCredentialResetRefusalChirho {
    /// The principal is absent from the verified identity log.
    UnknownPrincipalChirho,
    /// The principal exists but holds no HTTP credential; `identity-credential-set` is the road.
    CredentiallessPrincipalChirho,
    /// The replacement credential is below the floor shared with registration and set.
    CredentialBelowFloorChirho,
}

impl std::fmt::Display for IdentityCredentialResetRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPrincipalChirho => {
                f.write_str("credential reset refused: unknown principal in the verified identity log")
            }
            Self::CredentiallessPrincipalChirho => f.write_str(
                "credential reset refused: principal has no HTTP credential; use identity-credential-set",
            ),
            Self::CredentialBelowFloorChirho => {
                write!(f, "credential reset refused: {IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO}")
            }
        }
    }
}

impl std::error::Error for IdentityCredentialResetRefusalChirho {}

fn credential_resets_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identity-credential-resets-chirho.jsonl")
}

/// The named lock that serializes every writer of one principal's key record: operator set,
/// operator reset, the self-service credential change (which proves the CURRENT credential inside
/// it), and the legacy-hash upgrade. A proof taken outside this lock is stale by construction, so
/// callers that must bind a proof to a mutation take the lock ONCE and do both within it.
pub(in crate::identity_chirho) fn credential_lock_name_chirho(principal_chirho: &str) -> String {
    format!("{CREDENTIAL_RESET_LOCK_PREFIX_CHIRHO}/{principal_chirho}")
}

pub fn reset_identity_credential_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
) -> Result<IdentityCredentialResetReportChirho> {
    // Same lock family as `set_identity_credential_chirho`, so a set and a reset on one principal
    // serialize instead of interleaving their read-modify-write of the key record.
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &credential_lock_name_chirho(principal_chirho),
        || {
            reset_identity_credential_locked_chirho(
                root_chirho,
                principal_chirho,
                credential_chirho,
                actor_chirho,
                reason_chirho,
                CredentialReplacementCauseChirho::OperatorResetChirho,
            )
        },
    )
}

/// Why a credential is replaced. It names the event the replacement appends when the key record held a recovery or
/// setup code (R2): a redemption USES the code, and every other replacement BURNS it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::identity_chirho) enum CredentialReplacementCauseChirho {
    OperatorResetChirho,
    SelfServiceChangeChirho,
    CodeRedeemedChirho,
}

impl CredentialReplacementCauseChirho {
    fn code_event_reason_chirho(self) -> RecoveryCodeReasonKindChirho {
        match self {
            Self::OperatorResetChirho => RecoveryCodeReasonKindChirho::CredentialResetChirho,
            Self::SelfServiceChangeChirho => RecoveryCodeReasonKindChirho::CredentialChangeChirho,
            Self::CodeRedeemedChirho => RecoveryCodeReasonKindChirho::CodeUseChirho,
        }
    }
}

pub(in crate::identity_chirho) fn reset_identity_credential_locked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    credential_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
    cause_chirho: CredentialReplacementCauseChirho,
) -> Result<IdentityCredentialResetReportChirho> {
    validate_session_revocation_actor_chirho(actor_chirho)?;
    validate_session_revocation_reason_chirho(reason_chirho)?;
    // The floor is checked BEFORE the identity-log lookup on purpose: a below-floor credential
    // refuses without revealing whether the principal exists. Keep this order.
    if !credential_meets_floor_chirho(credential_chirho) {
        return Err(IdentityCredentialResetRefusalChirho::CredentialBelowFloorChirho.into());
    }
    // Verified, not raw: a forged or torn identity log refuses the whole operation here, before any
    // revocation or key write, instead of resetting a principal nobody signed for.
    let known_chirho = load_verified_identities_chirho(root_chirho)?
        .into_iter()
        .any(|record_chirho| record_chirho.principal_chirho == principal_chirho);
    if !known_chirho {
        return Err(IdentityCredentialResetRefusalChirho::UnknownPrincipalChirho.into());
    }
    let key_record_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho)?;
    if key_record_chirho.credential_salt_chirho.is_none()
        || key_record_chirho.credential_hash_chirho.is_none()
    {
        return Err(IdentityCredentialResetRefusalChirho::CredentiallessPrincipalChirho.into());
    }
    replace_credential_locked_chirho(
        root_chirho,
        principal_chirho,
        key_record_chirho,
        credential_chirho,
        actor_chirho,
        reason_chirho,
        cause_chirho,
    )
}

/// Steps 3 to 6 of the reset, shared with R2's redemption once its own authority (the code) is established, all under
/// the principal lock its caller holds: revoke every live session FIRST, then ONE key-record replacement (the new
/// credential, any recovery code cleared, the generation bumped), then the signed reset record, then the code's event
/// when the key record held one. It is the preparation, then the commit; the redemption calls the two apart, to know
/// on which side of the commit point a failure fell (R13).
pub(in crate::identity_chirho) fn replace_credential_locked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    key_record_chirho: IdentityKeyChirho,
    credential_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
    cause_chirho: CredentialReplacementCauseChirho,
) -> Result<IdentityCredentialResetReportChirho> {
    let prepared_chirho = prepare_credential_replacement_locked_chirho(
        root_chirho,
        principal_chirho,
        key_record_chirho,
        credential_chirho,
        actor_chirho,
        reason_chirho,
        cause_chirho,
    )?;
    commit_credential_replacement_locked_chirho(
        root_chirho,
        principal_chirho,
        prepared_chirho,
        credential_chirho,
        actor_chirho,
        reason_chirho,
        cause_chirho,
    )
}

/// A replacement once prepared, under the principal lock: every live session revoked, and the new credential hashed into
/// the key record IN MEMORY with the code cleared there. Only the revocations are on disk, so a failure up to here
/// leaves the credential and any code untouched (R13): the same code still works.
pub(in crate::identity_chirho) struct PreparedCredentialReplacementChirho {
    key_record_chirho: IdentityKeyChirho,
    held_code_chirho: Option<StoredRecoveryCodeChirho>,
    revoked_session_seqs_chirho: Vec<u64>,
    salt_chirho: String,
    hash_chirho: String,
}

/// Steps 3 and 4's preparation: the checks, the revocations, then the new credential's salt and hash, with the key
/// record changed in memory only.
pub(in crate::identity_chirho) fn prepare_credential_replacement_locked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    mut key_record_chirho: IdentityKeyChirho,
    credential_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
    cause_chirho: CredentialReplacementCauseChirho,
) -> Result<PreparedCredentialReplacementChirho> {
    validate_session_revocation_actor_chirho(actor_chirho)?;
    validate_session_revocation_reason_chirho(reason_chirho)?;
    // A malformed code state fails the replacement before any mutation: invalid key state is never cleared silently.
    let held_code_chirho = stored_recovery_code_chirho(&key_record_chirho)?;
    if cause_chirho == CredentialReplacementCauseChirho::CodeRedeemedChirho
        && held_code_chirho.is_none()
    {
        bail!("a redemption must replace a key record that holds the code it verified");
    }

    // Step 3: revoke first. Both logs are loaded and VERIFIED once, before the loop: the
    // "already revoked, skip" decision rests on a signed row, and a session row whose principal
    // field was tampered fails the whole reset instead of being filtered past its own check.
    // Each append is signed and idempotent; an already-revoked session is not counted, and an
    // expired one is skipped because it can no longer authenticate.
    let now_ms_chirho = now_ms_chirho();
    let mut revoked_session_seqs_chirho = Vec::new();
    let revoked_keys_chirho: HashSet<(String, u64, String)> =
        load_verified_session_revocations_chirho(root_chirho)?
            .into_iter()
            .map(|revocation_chirho| {
                (
                    revocation_chirho.principal_chirho,
                    revocation_chirho.session_seq_chirho,
                    revocation_chirho.token_hash_chirho,
                )
            })
            .collect();
    for session_chirho in load_verified_sessions_chirho(root_chirho)? {
        if session_chirho.principal_chirho != principal_chirho
            || session_chirho.expires_ms_chirho < now_ms_chirho
        {
            continue;
        }
        let already_chirho = revoked_keys_chirho.contains(&(
            session_chirho.principal_chirho.clone(),
            session_chirho.seq_chirho,
            session_chirho.token_hash_chirho.clone(),
        ));
        if already_chirho {
            continue;
        }
        revoke_session_by_seq_chirho(
            root_chirho,
            principal_chirho,
            session_chirho.seq_chirho,
            actor_chirho,
            CREDENTIAL_RESET_SESSION_REVOCATION_REASON_CHIRHO,
        )?;
        revoked_session_seqs_chirho.push(session_chirho.seq_chirho);
    }

    // Step 4: replace, then prove the replacement by reloading the key record from disk. The
    // verifier may itself rewrite a legacy record on success, so the bytes compared against what
    // was written are reloaded AFTER verification, not before it — a freshly written hash is never
    // legacy today, and the order keeps that from ever mattering.
    #[cfg(test)]
    credential_fault_points_chirho::fail_if_armed_chirho(
        credential_fault_points_chirho::CredentialFaultPointChirho::SaltAndHashChirho,
    )?;
    let salt_chirho = random_salt_chirho();
    let hash_chirho = credential_hash_chirho(&salt_chirho, credential_chirho)?;
    key_record_chirho.credential_salt_chirho = Some(salt_chirho.clone());
    key_record_chirho.credential_hash_chirho = Some(hash_chirho.clone());
    // A reset invalidates every session authorized by the OLD credential: bump the generation so a
    // session that raced the enumeration above (issued under the old generation) fails validation.
    key_record_chirho.credential_generation_chirho = key_record_chirho
        .credential_generation_chirho
        .saturating_add(1);
    // The code is the OTHER authenticator: every credential replacement clears it in the SAME write (R2, invariant 2),
    // so a redemption consumes its code at the one commit point that sets the credential.
    key_record_chirho.recovery_code_salt_chirho = None;
    key_record_chirho.recovery_code_hash_chirho = None;
    key_record_chirho.recovery_code_expires_ms_chirho = None;
    Ok(PreparedCredentialReplacementChirho {
        key_record_chirho,
        held_code_chirho,
        revoked_session_seqs_chirho,
        salt_chirho,
        hash_chirho,
    })
}

/// The ONE commit point, the key-record write that sets the credential and clears the code together, then what follows
/// it: the read-back proof, the signed reset record, the code's event. An error from the write itself may follow its
/// rename, so it, and everything after it, may have applied.
pub(in crate::identity_chirho) fn commit_credential_replacement_locked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    prepared_chirho: PreparedCredentialReplacementChirho,
    credential_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
    cause_chirho: CredentialReplacementCauseChirho,
) -> Result<IdentityCredentialResetReportChirho> {
    let PreparedCredentialReplacementChirho {
        key_record_chirho,
        held_code_chirho,
        revoked_session_seqs_chirho,
        salt_chirho,
        hash_chirho,
    } = prepared_chirho;
    write_identity_key_record_chirho(root_chirho, &key_record_chirho)?;
    #[cfg(test)]
    credential_fault_points_chirho::fail_if_armed_chirho(
        credential_fault_points_chirho::CredentialFaultPointChirho::ReadBackChirho,
    )?;
    let reloaded_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho)?;
    verify_identity_credential_chirho(&reloaded_chirho, credential_chirho)?;
    let settled_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho)?;
    if settled_chirho.credential_salt_chirho.as_deref() != Some(salt_chirho.as_str())
        || settled_chirho.credential_hash_chirho.as_deref() != Some(hash_chirho.as_str())
        || stored_recovery_code_chirho(&settled_chirho)?.is_some()
    {
        bail!("credential reset wrote a key record that does not read back as written");
    }

    // Step 5: the signed record. Written after the replacement so that its existence means the
    // credential was replaced. A failure between replacement and this append can leave a replaced
    // credential without a reset record. A retry performs a new reset; it cannot reconstruct the
    // missing event or its original revoked-session count.
    let record_chirho = append_credential_reset_record_chirho(
        root_chirho,
        principal_chirho,
        actor_chirho,
        reason_chirho,
        revoked_session_seqs_chirho.len() as u64,
        &credential_state_digest_chirho(&salt_chirho, &hash_chirho),
    )?;
    // Step 6: the code's event, after the reset record: a use for a redemption, a burn for every other replacement. A
    // failure here leaves the code cleared and the reset recorded, without the event; nothing can revive the code.
    if let Some(held_chirho) = held_code_chirho {
        append_recovery_code_event_chirho(
            root_chirho,
            principal_chirho,
            cause_chirho.code_event_reason_chirho(),
            actor_chirho,
            &held_chirho,
            settled_chirho.credential_generation_chirho,
        )?;
    }
    Ok(IdentityCredentialResetReportChirho {
        record_chirho,
        revoked_session_seqs_chirho,
    })
}

fn credential_state_digest_chirho(salt_chirho: &str, hash_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(CREDENTIAL_RESET_DIGEST_DOMAIN_CHIRHO);
    hasher_chirho.update(&(salt_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(salt_chirho.as_bytes());
    hasher_chirho.update(&(hash_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(hash_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

fn append_credential_reset_record_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    actor_chirho: &str,
    reason_chirho: &str,
    revoked_session_count_chirho: u64,
    credential_state_digest_chirho: &str,
) -> Result<IdentityCredentialResetRecordChirho> {
    let path_chirho = credential_resets_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        verify_credential_resets_chirho(root_chirho)?;
        let mut record_chirho = IdentityCredentialResetRecordChirho {
            seq_chirho,
            schema_chirho: IDENTITY_CREDENTIAL_RESET_RECORD_SCHEMA_CHIRHO.to_string(),
            principal_chirho: principal_chirho.to_string(),
            actor_chirho: actor_chirho.to_string(),
            reason_chirho: reason_chirho.to_string(),
            revoked_session_count_chirho,
            credential_state_digest_chirho: credential_state_digest_chirho.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = credential_reset_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn credential_reset_message_chirho(
    record_chirho: &IdentityCredentialResetRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

pub fn load_credential_resets_chirho(
    root_chirho: &Path,
) -> Result<Vec<IdentityCredentialResetRecordChirho>> {
    let path_chirho = credential_resets_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho: IdentityCredentialResetRecordChirho = serde_json::from_str(line_chirho)?;
        verify_identity_record_schema_chirho(
            &record_chirho.schema_chirho,
            IDENTITY_CREDENTIAL_RESET_RECORD_SCHEMA_CHIRHO,
            "identity credential reset record",
        )?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

/// Dense seqs and every signature under the root pubkey; the count is the verified length.
pub fn verify_credential_resets_chirho(root_chirho: &Path) -> Result<usize> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let records_chirho = load_credential_resets_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "identity credential reset seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = credential_reset_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "identity credential reset entry {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

/// Test-only fault points on the two sides of the commit point (R13, PFE #26147). A point armed on this thread fails
/// once, then disarms itself. No fixture can make these two steps fail by itself: the salt and hash take no input a
/// test controls, and the read-back follows a write that has just succeeded.
#[cfg(test)]
pub(super) mod credential_fault_points_chirho {
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::identity_chirho) enum CredentialFaultPointChirho {
        /// After every revocation, before the new credential's salt and hash: before the commit point.
        SaltAndHashChirho,
        /// After the key-record write, at the read-back proof: after the commit point.
        ReadBackChirho,
    }

    thread_local! {
        static ARMED_CHIRHO: Cell<Option<CredentialFaultPointChirho>> = const { Cell::new(None) };
    }

    pub(in crate::identity_chirho) fn arm_chirho(point_chirho: CredentialFaultPointChirho) {
        ARMED_CHIRHO.with(|armed_chirho| armed_chirho.set(Some(point_chirho)));
    }

    pub(in crate::identity_chirho) fn fail_if_armed_chirho(
        point_chirho: CredentialFaultPointChirho,
    ) -> anyhow::Result<()> {
        if ARMED_CHIRHO.with(|armed_chirho| armed_chirho.get()) == Some(point_chirho) {
            ARMED_CHIRHO.with(|armed_chirho| armed_chirho.set(None));
            anyhow::bail!("injected fault at {point_chirho:?}");
        }
        Ok(())
    }
}
