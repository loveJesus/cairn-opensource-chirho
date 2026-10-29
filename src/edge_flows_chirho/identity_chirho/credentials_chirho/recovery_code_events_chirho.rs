// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! The recovery code's evidence: one signed, plaintext-free event per mint, use and burn, in a closed vocabulary, in its
//! own append-only log. Never the code, never its hash: a digest of the stored state joins a use or a burn to its mint.
//!
//! Its growth is bounded by code lifecycle events (an operator mint, her use, a credential replacement that clears a
//! code), never by requests, so an append verifies the whole log first, as the reset log's does.

use super::*;
use cairn_seqlog_chirho::jsonl_read_chirho::read_log_text_chirho;

pub const IDENTITY_RECOVERY_CODE_EVENT_SCHEMA_CHIRHO: &str =
    "identity-recovery-code-event-v1-chirho";

/// What happened to a code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryCodeEventKindChirho {
    #[serde(rename = "minted-chirho")]
    MintedChirho,
    #[serde(rename = "used-chirho")]
    UsedChirho,
    #[serde(rename = "burned-chirho")]
    BurnedChirho,
}

/// Why it happened: a closed vocabulary from day one. The privacy class is chosen by the field's NAME, so a free-text
/// reason here would be a high-risk finding. Each reason belongs to exactly one kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryCodeReasonKindChirho {
    /// Minted by the operator for a credentialless principal: the invitation.
    #[serde(rename = "operator-invitation-chirho")]
    OperatorInvitationChirho,
    /// Minted by the operator for a credentialed principal.
    #[serde(rename = "operator-recovery-chirho")]
    OperatorRecoveryChirho,
    /// Minted by herself behind her password (R2c). It never expires.
    #[serde(rename = "self-service-mint-chirho")]
    SelfServiceMintChirho,
    /// Redeemed on the recover road: the code set her credential.
    #[serde(rename = "code-use-chirho")]
    CodeUseChirho,
    /// Burned by a newer mint.
    #[serde(rename = "replaced-by-mint-chirho")]
    ReplacedByMintChirho,
    /// Burned by the operator's credential set.
    #[serde(rename = "credential-set-chirho")]
    CredentialSetChirho,
    /// Burned by the operator's credential reset.
    #[serde(rename = "credential-reset-chirho")]
    CredentialResetChirho,
    /// Burned by her own credential change.
    #[serde(rename = "credential-change-chirho")]
    CredentialChangeChirho,
}

impl RecoveryCodeReasonKindChirho {
    pub fn event_kind_chirho(self) -> RecoveryCodeEventKindChirho {
        match self {
            Self::OperatorInvitationChirho
            | Self::OperatorRecoveryChirho
            | Self::SelfServiceMintChirho => RecoveryCodeEventKindChirho::MintedChirho,
            Self::CodeUseChirho => RecoveryCodeEventKindChirho::UsedChirho,
            Self::ReplacedByMintChirho
            | Self::CredentialSetChirho
            | Self::CredentialResetChirho
            | Self::CredentialChangeChirho => RecoveryCodeEventKindChirho::BurnedChirho,
        }
    }

    /// An operator mint always expires (PFE #26035); her own mint never does; a use or a burn carries no expiry.
    fn expiry_rule_chirho(self) -> Option<bool> {
        match self {
            Self::OperatorInvitationChirho | Self::OperatorRecoveryChirho => Some(true),
            Self::SelfServiceMintChirho => Some(false),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRecoveryCodeEventChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub principal_chirho: String,
    pub kind_chirho: RecoveryCodeEventKindChirho,
    pub reason_kind_chirho: RecoveryCodeReasonKindChirho,
    /// The operator's fixed actor name, or the principal herself.
    pub actor_chirho: String,
    pub code_state_digest_chirho: String,
    /// A minted operator code's expiry; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_ms_chirho: Option<u64>,
    pub credential_generation_chirho: u64,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

fn recovery_code_events_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("identity-recovery-code-events-chirho.jsonl")
}

fn recovery_code_event_message_chirho(
    event_chirho: &IdentityRecoveryCodeEventChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = event_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

/// One event's own rules, apart from its signature and seq: the schema, the kind its reason belongs to, and the expiry
/// rule its reason sets.
fn check_recovery_code_event_shape_chirho(
    event_chirho: &IdentityRecoveryCodeEventChirho,
) -> Result<()> {
    verify_identity_record_schema_chirho(
        &event_chirho.schema_chirho,
        IDENTITY_RECOVERY_CODE_EVENT_SCHEMA_CHIRHO,
        "identity recovery code event",
    )?;
    if event_chirho.reason_kind_chirho.event_kind_chirho() != event_chirho.kind_chirho {
        bail!(
            "identity recovery code event {} pairs its kind with a reason of another kind",
            event_chirho.seq_chirho
        );
    }
    let expiry_ok_chirho = match event_chirho.reason_kind_chirho.expiry_rule_chirho() {
        Some(true) => event_chirho.expires_ms_chirho.is_some(),
        Some(false) | None => event_chirho.expires_ms_chirho.is_none(),
    };
    if !expiry_ok_chirho {
        bail!(
            "identity recovery code event {} breaks its reason's expiry rule",
            event_chirho.seq_chirho
        );
    }
    Ok(())
}

pub fn load_recovery_code_events_chirho(
    root_chirho: &Path,
) -> Result<Vec<IdentityRecoveryCodeEventChirho>> {
    let path_chirho = recovery_code_events_path_chirho(root_chirho);
    let Some(text_chirho) = read_log_text_chirho(&path_chirho)? else {
        return Ok(Vec::new());
    };
    let mut events_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let event_chirho: IdentityRecoveryCodeEventChirho = serde_json::from_str(line_chirho)?;
        check_recovery_code_event_shape_chirho(&event_chirho)?;
        events_chirho.push(event_chirho);
    }
    Ok(events_chirho)
}

/// Authoritative: every event parses, has its shape, sits at its seq and carries a valid signature by the root's EXISTING
/// key. A read never creates a key: with no key, an empty log verifies as empty and a non-empty one refuses.
pub fn verify_recovery_code_events_chirho(root_chirho: &Path) -> Result<usize> {
    let events_chirho = load_recovery_code_events_chirho(root_chirho)?;
    if events_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::existing_keypair_pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, event_chirho) in events_chirho.iter().enumerate() {
        if event_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "identity recovery code event seq gap at index {i_chirho}: entry seq is {}",
                event_chirho.seq_chirho
            );
        }
        let message_chirho = recovery_code_event_message_chirho(event_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &event_chirho.sig_chirho,
        )? {
            bail!(
                "identity recovery code event {} signature invalid",
                event_chirho.seq_chirho
            );
        }
    }
    Ok(events_chirho.len())
}

/// One listed row: the event, or the line that failed to decode, with its VALID or INVALID label.
pub type RecoveryCodeEventDisplayRowChirho =
    cairn_display_chirho::DisplayRecordChirho<IdentityRecoveryCodeEventChirho>;

/// For listing: every row, labelled VALID or INVALID by the shared display loader. Each row inherits the authoritative
/// verifier's error, so a listing never shows as valid a row the verifier would refuse.
pub fn load_recovery_code_events_for_display_chirho(
    root_chirho: &Path,
) -> Result<Vec<RecoveryCodeEventDisplayRowChirho>> {
    let family_error_chirho = verify_recovery_code_events_chirho(root_chirho)
        .err()
        .map(|error_chirho| error_chirho.to_string());
    cairn_display_chirho::load_jsonl_for_display_chirho(
        &recovery_code_events_path_chirho(root_chirho),
        "identity recovery code event",
        family_error_chirho.as_deref(),
        |event_chirho: &IdentityRecoveryCodeEventChirho| event_chirho.seq_chirho,
    )
}

/// Append one signed event after verifying the whole log, under the log's own append lock.
pub(super) fn append_recovery_code_event_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    reason_kind_chirho: RecoveryCodeReasonKindChirho,
    actor_chirho: &str,
    stored_chirho: &StoredRecoveryCodeChirho,
    credential_generation_chirho: u64,
) -> Result<IdentityRecoveryCodeEventChirho> {
    let expires_ms_chirho = match reason_kind_chirho.expiry_rule_chirho() {
        Some(true) => Some(
            stored_chirho
                .expires_ms_chirho
                .ok_or_else(|| anyhow!("an operator recovery code must carry an expiry"))?,
        ),
        Some(false) | None => None,
    };
    let path_chirho = recovery_code_events_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        verify_recovery_code_events_chirho(root_chirho)?;
        let mut event_chirho = IdentityRecoveryCodeEventChirho {
            seq_chirho,
            schema_chirho: IDENTITY_RECOVERY_CODE_EVENT_SCHEMA_CHIRHO.to_string(),
            principal_chirho: principal_chirho.to_string(),
            kind_chirho: reason_kind_chirho.event_kind_chirho(),
            reason_kind_chirho,
            actor_chirho: actor_chirho.to_string(),
            code_state_digest_chirho: stored_chirho.state_digest_chirho(),
            expires_ms_chirho,
            credential_generation_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = recovery_code_event_message_chirho(&event_chirho)?;
        event_chirho.sig_chirho = signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(event_chirho)
    })
}
