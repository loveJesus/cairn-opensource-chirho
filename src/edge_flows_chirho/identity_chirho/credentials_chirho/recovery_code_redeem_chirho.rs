// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Redeeming a recovery or setup code: ONE act, under the principal lock, in which the code sets the credential it
//! authorizes. It is the reset act with the code as its proof, so it serves an invited principal (no credential yet)
//! and a recovering one alike.
//!
//! Design: `spec-chirho/workflows-chirho/identity-auth-chirho/self-service-recovery-code-chirho.md`, revision 3, item 3,
//! and revision 2's transaction contract and invariants 4 to 6. What a caller may learn is two things: the new
//! credential is below the floor, or ONE uniform refusal for everything about the principal and the code.

use super::*;

/// The anonymous road's refusals. Anything else this act returns is an internal error with no customer token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryCodeRefusalChirho {
    /// The new credential is below the floor. Checked first: nothing is written, and nothing is said about the principal
    /// or the code.
    CredentialTooWeakChirho,
    /// ONE value for an unknown principal, no code, a malformed code, a wrong code, a used or burned code, and an
    /// expired code. Every one of those branches runs the same one code hash first.
    RecoveryRefusedChirho,
}

impl RecoveryCodeRefusalChirho {
    pub fn token_chirho(self) -> &'static str {
        match self {
            Self::CredentialTooWeakChirho => "credential-too-weak-chirho",
            Self::RecoveryRefusedChirho => "recovery-refused-chirho",
        }
    }
}

impl std::fmt::Display for RecoveryCodeRefusalChirho {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token_chirho())
    }
}

impl std::error::Error for RecoveryCodeRefusalChirho {}

pub fn recovery_code_refusal_token_chirho(error_chirho: &anyhow::Error) -> Option<&'static str> {
    error_chirho
        .downcast_ref::<RecoveryCodeRefusalChirho>()
        .map(|refusal_chirho| refusal_chirho.token_chirho())
}

/// The reset record's reason for a redemption: a credentialed principal recovered, or an invited one set her first
/// credential. A closed pair, fixed here.
pub const RECOVERY_CODE_RESET_REASON_CHIRHO: &str = "recovery-code-chirho";
pub const INVITATION_CODE_RESET_REASON_CHIRHO: &str = "invitation-code-chirho";

/// A code, a salt and a hash that no mint ever produces, used on every refusing branch that has nothing real to work
/// on, so each branch does the same work. The salt is all zero bytes; a minted salt comes from `OsRng`.
const DUMMY_CODE_CHIRHO: &str = "000000000000000000000000";
const DUMMY_SALT_CHIRHO: &str = "00000000000000000000000000000000";
const DUMMY_HASH_CHIRHO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// A fixed key record, decoded in place of a key file when the principal is unknown (revision 2, invariant 6).
const DUMMY_KEY_RECORD_JSON_CHIRHO: &str =
    r#"{"principal_chirho":"user/0000000000000000","secret_key_chirho":"00"}"#;

/// The common work, then the one refusal: one hash and one constant-time compare against a fixed hash. Bounded, not
/// constant-time: the arm proves only that this work runs on every refusing branch (revision 2, invariant 6).
fn refuse_after_common_work_chirho(
    salt_hex_chirho: &str,
    normalized_chirho: Option<&str>,
) -> anyhow::Error {
    if let Ok(hash_chirho) = recovery_code_hash_chirho(
        salt_hex_chirho,
        normalized_chirho.unwrap_or(DUMMY_CODE_CHIRHO),
    ) {
        let _ = constant_time_string_eq_chirho(&hash_chirho, DUMMY_HASH_CHIRHO);
    }
    RecoveryCodeRefusalChirho::RecoveryRefusedChirho.into()
}

/// Set her credential with a code she was given or saved. On success she signs in with the new credential.
pub fn redeem_recovery_code_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    typed_code_chirho: &str,
    new_credential_chirho: &str,
) -> Result<IdentityCredentialResetReportChirho> {
    redeem_recovery_code_at_chirho(
        root_chirho,
        principal_chirho,
        typed_code_chirho,
        new_credential_chirho,
        now_ms_chirho(),
    )
}

/// The anonymous road's engine part (R2b): the floor, then the `recover-chirho` limiter through the attempts WINDOW VIEW
/// (never the whole log), then the redemption, then ONE attempt row for the outcome, keyed by the principal digest,
/// known or not: a failure for the uniform refusal, a success for the act. No row is written for a floor or limiter
/// refusal, so a rate limit behaves the same for a real principal and an invented one. The served road runs the
/// confirmation compare and the per-source gate before this.
///
/// Design: `self-service-recovery-code-chirho.md`, "R2b, the served road".
pub fn redeem_recovery_code_with_public_limit_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    typed_code_chirho: &str,
    new_credential_chirho: &str,
) -> Result<IdentityCredentialResetReportChirho> {
    redeem_recovery_code_with_public_limit_outcome_chirho(
        root_chirho,
        principal_chirho,
        typed_code_chirho,
        new_credential_chirho,
    )
    .map_err(|refusal_chirho| refusal_chirho.error_chirho)
}

/// The same act, saying whether a refusal RECORDED a failed attempt row, for the served road's per-source failure limit
/// (R12): only the uniform refusal records one. It also says whether a failure stopped BEFORE the commit point, so the
/// served road answers "your password was not set; your code still works" exactly when that is true (R13).
pub fn redeem_recovery_code_with_public_limit_outcome_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    typed_code_chirho: &str,
    new_credential_chirho: &str,
) -> std::result::Result<IdentityCredentialResetReportChirho, PublicAuthRefusalChirho> {
    if !credential_meets_floor_chirho(new_credential_chirho) {
        return Err(PublicAuthRefusalChirho::not_recorded_chirho(
            RecoveryCodeRefusalChirho::CredentialTooWeakChirho.into(),
        ));
    }
    // A rate refusal, or the window view's own failure: nothing was compared, and nothing was set.
    ensure_public_auth_attempt_allowed_chirho(
        root_chirho,
        principal_chirho,
        AUTH_ENDPOINT_RECOVER_CHIRHO,
    )
    .map_err(PublicAuthRefusalChirho::not_recorded_unchanged_chirho)?;
    match redeem_recovery_code_phased_at_chirho(
        root_chirho,
        principal_chirho,
        typed_code_chirho,
        new_credential_chirho,
        now_ms_chirho(),
    ) {
        Ok(report_chirho) => {
            // The credential IS set: a success row that fails to append cannot make it unset.
            append_auth_attempt_chirho(
                root_chirho,
                principal_chirho,
                AUTH_ENDPOINT_RECOVER_CHIRHO,
                IdentityAuthAttemptOutcomeChirho::SuccessChirho,
            )
            .map_err(PublicAuthRefusalChirho::not_recorded_chirho)?;
            Ok(report_chirho)
        }
        Err(failure_chirho) => {
            if failure_chirho
                .error_chirho
                .downcast_ref::<RecoveryCodeRefusalChirho>()
                == Some(&RecoveryCodeRefusalChirho::RecoveryRefusedChirho)
            {
                // The uniform refusal set nothing, and a failure row that fails to append does not change that.
                append_auth_attempt_chirho(
                    root_chirho,
                    principal_chirho,
                    AUTH_ENDPOINT_RECOVER_CHIRHO,
                    IdentityAuthAttemptOutcomeChirho::FailureChirho,
                )
                .map_err(PublicAuthRefusalChirho::not_recorded_unchanged_chirho)?;
                return Err(PublicAuthRefusalChirho::recorded_chirho(
                    failure_chirho.error_chirho,
                ));
            }
            Err(match failure_chirho.phase_chirho {
                RedemptionPhaseChirho::CredentialUnchangedChirho => {
                    PublicAuthRefusalChirho::not_recorded_unchanged_chirho(
                        failure_chirho.error_chirho,
                    )
                }
                RedemptionPhaseChirho::MayHaveAppliedChirho => {
                    PublicAuthRefusalChirho::not_recorded_chirho(failure_chirho.error_chirho)
                }
            })
        }
    }
}

/// Where a failed redemption stopped, against its ONE commit point: the key-record write that sets the credential and
/// clears the code together (R13, PFE #26146, #26147).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RedemptionPhaseChirho {
    /// Before the write: the credential and the code are untouched, so the same code still works. Sessions may already
    /// be revoked, since revocation runs first, so "nothing changed" is NOT what this says.
    CredentialUnchangedChirho,
    /// The write itself, whose error can follow its rename, or anything after it: the credential may be set and the code
    /// consumed.
    MayHaveAppliedChirho,
}

/// A failed redemption, and where it stopped.
pub(super) struct RedemptionFailureChirho {
    pub(super) error_chirho: anyhow::Error,
    pub(super) phase_chirho: RedemptionPhaseChirho,
}

fn unchanged_chirho(error_chirho: anyhow::Error) -> RedemptionFailureChirho {
    RedemptionFailureChirho {
        error_chirho,
        phase_chirho: RedemptionPhaseChirho::CredentialUnchangedChirho,
    }
}

fn may_have_applied_chirho(error_chirho: anyhow::Error) -> RedemptionFailureChirho {
    RedemptionFailureChirho {
        error_chirho,
        phase_chirho: RedemptionPhaseChirho::MayHaveAppliedChirho,
    }
}

/// The phase of the act's own outcome under the lock: a success has applied, and a failure carries its phase.
pub(super) fn act_phase_chirho<T>(
    outcome_chirho: &std::result::Result<T, RedemptionFailureChirho>,
) -> RedemptionPhaseChirho {
    match outcome_chirho {
        Ok(_) => RedemptionPhaseChirho::MayHaveAppliedChirho,
        Err(failure_chirho) => failure_chirho.phase_chirho,
    }
}

/// What a failure of the principal lock ITSELF means. Opening or taking it fails before the act runs (`None`), so nothing
/// was set. Once the act has run, only the unlock can fail, and the lock then returns that error IN PLACE OF the act's
/// outcome, a success included, so the act's own phase decides: a success, or a failure at or after the commit point,
/// may have applied.
pub(super) fn lock_failure_phase_chirho(
    action_phase_chirho: Option<RedemptionPhaseChirho>,
) -> RedemptionPhaseChirho {
    action_phase_chirho.unwrap_or(RedemptionPhaseChirho::CredentialUnchangedChirho)
}

pub(super) fn redeem_recovery_code_at_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    typed_code_chirho: &str,
    new_credential_chirho: &str,
    now_ms_chirho: u64,
) -> Result<IdentityCredentialResetReportChirho> {
    redeem_recovery_code_phased_at_chirho(
        root_chirho,
        principal_chirho,
        typed_code_chirho,
        new_credential_chirho,
        now_ms_chirho,
    )
    .map_err(|failure_chirho| failure_chirho.error_chirho)
}

/// The redemption, saying on which side of the commit point a failure fell (R13).
pub(super) fn redeem_recovery_code_phased_at_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    typed_code_chirho: &str,
    new_credential_chirho: &str,
    now_ms_chirho: u64,
) -> std::result::Result<IdentityCredentialResetReportChirho, RedemptionFailureChirho> {
    // 1. The floor FIRST: below it nothing is written and nothing is learned about the principal or the code.
    if !credential_meets_floor_chirho(new_credential_chirho) {
        return Err(unchanged_chirho(
            RecoveryCodeRefusalChirho::CredentialTooWeakChirho.into(),
        ));
    }
    // 2. What she typed, normalized and bounded. A malformed code still runs the common work below.
    let normalized_chirho = normalize_recovery_code_chirho(typed_code_chirho);
    // 3. Existence on the VERIFIED identity log, read-only and BEFORE any lock, so no lock file is ever created for a
    //    string a stranger chose. A log that fails verification refuses as an internal error, never as "unknown".
    //    It reads the verified kind map, cached per root fingerprint (R2b's measurement, PFE #26058): verifying the
    //    whole log on every anonymous attempt cost 9.6 times a refused sign-in at 6,000 identities.
    let known_chirho = verified_identity_kind_map_arc_chirho(root_chirho)
        .map_err(unchanged_chirho)?
        .contains_key(principal_chirho);
    if !known_chirho {
        let _ = serde_json::from_str::<IdentityKeyChirho>(DUMMY_KEY_RECORD_JSON_CHIRHO);
        return Err(unchanged_chirho(refuse_after_common_work_chirho(
            DUMMY_SALT_CHIRHO,
            normalized_chirho.as_deref(),
        )));
    }
    // 4. Under the principal lock. The act reports its own phase, because an unlock that fails AFTER it reaches this
    //    function in place of the act's outcome (`lock_failure_phase_chirho`).
    let mut action_phase_chirho = None;
    let locked_chirho = seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &credential_lock_name_chirho(principal_chirho),
        || {
            let outcome_chirho = redeem_locked_chirho(
                root_chirho,
                principal_chirho,
                normalized_chirho.as_deref(),
                new_credential_chirho,
                now_ms_chirho,
            );
            action_phase_chirho = Some(act_phase_chirho(&outcome_chirho));
            Ok(outcome_chirho)
        },
    );
    match locked_chirho {
        Ok(outcome_chirho) => outcome_chirho,
        Err(lock_error_chirho) => Err(RedemptionFailureChirho {
            error_chirho: lock_error_chirho,
            phase_chirho: lock_failure_phase_chirho(action_phase_chirho),
        }),
    }
}

/// Step 4, under the principal lock, against the CURRENT key state: the code, its expiry, then the one replacement,
/// prepared (before the commit point) and then committed.
fn redeem_locked_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    normalized_chirho: Option<&str>,
    new_credential_chirho: &str,
    now_ms_chirho: u64,
) -> std::result::Result<IdentityCredentialResetReportChirho, RedemptionFailureChirho> {
    let key_record_chirho =
        load_identity_key_record_chirho(root_chirho, principal_chirho).map_err(unchanged_chirho)?;
    // Invalid code state fails closed as an internal error: never "no code".
    let Some(stored_chirho) =
        stored_recovery_code_chirho(&key_record_chirho).map_err(unchanged_chirho)?
    else {
        return Err(unchanged_chirho(refuse_after_common_work_chirho(
            DUMMY_SALT_CHIRHO,
            normalized_chirho,
        )));
    };
    let Some(normalized_chirho) = normalized_chirho else {
        return Err(unchanged_chirho(refuse_after_common_work_chirho(
            &stored_chirho.salt_chirho,
            None,
        )));
    };
    let computed_chirho = recovery_code_hash_chirho(&stored_chirho.salt_chirho, normalized_chirho)
        .map_err(unchanged_chirho)?;
    let matches_chirho =
        constant_time_string_eq_chirho(&computed_chirho, &stored_chirho.hash_chirho);
    if !matches_chirho || !stored_chirho.live_at_chirho(now_ms_chirho) {
        return Err(unchanged_chirho(
            RecoveryCodeRefusalChirho::RecoveryRefusedChirho.into(),
        ));
    }
    // 5. The act: revoke every live session FIRST, then ONE key-record replacement (the new credential, the code
    //    cleared, the generation bumped), then the signed reset record and the `used-chirho` event. The preparation
    //    ends before the key-record write; the commit is that write and everything after it.
    let reason_chirho = if key_record_chirho.credential_hash_chirho.is_some() {
        RECOVERY_CODE_RESET_REASON_CHIRHO
    } else {
        INVITATION_CODE_RESET_REASON_CHIRHO
    };
    let prepared_chirho = prepare_credential_replacement_locked_chirho(
        root_chirho,
        principal_chirho,
        key_record_chirho,
        new_credential_chirho,
        principal_chirho,
        reason_chirho,
        CredentialReplacementCauseChirho::CodeRedeemedChirho,
    )
    .map_err(unchanged_chirho)?;
    commit_credential_replacement_locked_chirho(
        root_chirho,
        principal_chirho,
        prepared_chirho,
        new_credential_chirho,
        principal_chirho,
        reason_chirho,
        CredentialReplacementCauseChirho::CodeRedeemedChirho,
    )
    .map_err(may_have_applied_chirho)
}
