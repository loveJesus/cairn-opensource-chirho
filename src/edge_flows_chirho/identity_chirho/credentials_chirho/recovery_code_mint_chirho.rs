// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! The operator's mints: the invitation (a new credentialless principal and its setup code, in one act) and the re-mint
//! for an existing principal. Every operator mint expires one lifetime after it is made, and burns any code before it.
//!
//! Design: `spec-chirho/workflows-chirho/identity-auth-chirho/self-service-recovery-code-chirho.md`, revision 3, items 1
//! and 2 (PFE #26035: every OPERATOR mint expires; `--json` on both commands).

use super::*;

/// The operator's fixed actor name on mint events; an operator command holds no principal of its own.
pub const RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO: &str = "operator-cli-chirho";

/// The refusals for an owner principal, each with its own words, so an operator reads which command refused and what
/// to use instead.
pub const OWNER_INVITE_REFUSAL_CHIRHO: &str =
    "identity-invite refused: only user principals hold a mailable code; \
     register an owner with identity-register --credential-file";
pub const OWNER_MINT_REFUSAL_CHIRHO: &str =
    "identity-recovery-code-mint refused: only user principals hold a mailable \
     code; reset an owner with identity-credential-reset";

/// What the operator is shown ONCE, on stdout: the principal, the code and its expiry. `--json` prints exactly these
/// three fields. Nothing here is stored: the code exists only in this value until the command prints it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IssuedRecoveryCodeChirho {
    pub principal_chirho: String,
    pub recovery_code_chirho: String,
    pub expires_ms_chirho: u64,
}

/// `identity-invite`: register a credentialless principal and mint its setup code. Two steps, not one transaction: if
/// the mint fails after the registration, the principal exists with no code, and `identity-recovery-code-mint` mints
/// one; nothing can sign in as it meanwhile, because it holds no credential.
pub fn invite_identity_chirho(
    root_chirho: &Path,
    kind_chirho: PrincipalKindChirho,
) -> Result<IssuedRecoveryCodeChirho> {
    // Only USER principals ever hold a mailable code (PFE's ruling, #26061), refused before anything is registered. An
    // emailed code must never set the credential of an owner, an operator-level authority. The flag stays, so the
    // operator's command line says what it makes.
    if kind_chirho != PrincipalKindChirho::UserChirho {
        bail!("{OWNER_INVITE_REFUSAL_CHIRHO}");
    }
    let principal_chirho = register_identity_chirho(root_chirho, kind_chirho)?.principal_chirho;
    mint_operator_recovery_code_chirho(root_chirho, &principal_chirho)
}

/// `identity-recovery-code-mint`: mint a fresh code for an existing principal, burning any code before it. For a
/// credentialless principal it is the invitation again; for a credentialed one it is an operator recovery code. Both
/// expire one lifetime after the mint.
pub fn mint_operator_recovery_code_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Result<IssuedRecoveryCodeChirho> {
    // The principal must exist on the VERIFIED identity log before any lock is taken for it. A log that fails
    // verification refuses the mint; a raw row is never trusted for an authority act.
    let Some(record_chirho) = load_verified_identities_chirho(root_chirho)?
        .into_iter()
        .find(|record_chirho| record_chirho.principal_chirho == principal_chirho)
    else {
        bail!("recovery code mint refused: unknown principal in the verified identity log");
    };
    // Only USER principals ever hold a mailable code (#26061), judged by the VERIFIED record's kind, never by the
    // name's prefix, and refused before any lock. An owner is reset with identity-credential-reset from a mode-600 file.
    if record_chirho.kind_chirho != PrincipalKindChirho::UserChirho {
        bail!("{OWNER_MINT_REFUSAL_CHIRHO}");
    }
    let expires_ms_chirho = now_ms_chirho()
        .checked_add(RECOVERY_CODE_OPERATOR_LIFETIME_MS_CHIRHO)
        .ok_or_else(|| anyhow!("the recovery code's expiry overflows"))?;
    seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &credential_lock_name_chirho(principal_chirho),
        || {
            let mut key_record_chirho =
                load_identity_key_record_chirho(root_chirho, principal_chirho)?;
            // A malformed code state refuses the mint instead of being overwritten: invalid key state is never repaired
            // silently.
            let previous_chirho = stored_recovery_code_chirho(&key_record_chirho)?;
            let credentialed_chirho = key_record_chirho.credential_hash_chirho.is_some();
            let fresh_chirho = fresh_recovery_code_chirho(Some(expires_ms_chirho))?;
            key_record_chirho.recovery_code_salt_chirho =
                Some(fresh_chirho.stored_chirho.salt_chirho.clone());
            key_record_chirho.recovery_code_hash_chirho =
                Some(fresh_chirho.stored_chirho.hash_chirho.clone());
            key_record_chirho.recovery_code_expires_ms_chirho = Some(expires_ms_chirho);
            write_identity_key_record_chirho(root_chirho, &key_record_chirho)?;
            let settled_chirho = load_identity_key_record_chirho(root_chirho, principal_chirho)?;
            if stored_recovery_code_chirho(&settled_chirho)?.as_ref()
                != Some(&fresh_chirho.stored_chirho)
            {
                bail!(
                    "the recovery code mint wrote a key record that does not read back as written"
                );
            }
            // The evidence follows the write, so its existence means the write happened. A failure between them leaves a
            // live code without its event; the credential inventory names that gap rather than inferring it.
            if let Some(previous_chirho) = previous_chirho {
                append_recovery_code_event_chirho(
                    root_chirho,
                    principal_chirho,
                    RecoveryCodeReasonKindChirho::ReplacedByMintChirho,
                    RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO,
                    &previous_chirho,
                    settled_chirho.credential_generation_chirho,
                )?;
            }
            append_recovery_code_event_chirho(
                root_chirho,
                principal_chirho,
                if credentialed_chirho {
                    RecoveryCodeReasonKindChirho::OperatorRecoveryChirho
                } else {
                    RecoveryCodeReasonKindChirho::OperatorInvitationChirho
                },
                RECOVERY_CODE_OPERATOR_ACTOR_CHIRHO,
                &fresh_chirho.stored_chirho,
                settled_chirho.credential_generation_chirho,
            )?;
            Ok(IssuedRecoveryCodeChirho {
                principal_chirho: principal_chirho.to_string(),
                recovery_code_chirho: fresh_chirho.display_chirho,
                expires_ms_chirho,
            })
        },
    )
}
