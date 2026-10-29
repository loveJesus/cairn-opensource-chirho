// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Canonical root-signed Gate 1 cursor minting and generic current-authorization resume validation.

#[cfg(test)]
#[path = "cursor_tests_chirho.rs"]
mod cursor_tests_chirho;

use super::digests_chirho::{
    constant_time_digest_matches_chirho, root_identity_digest_from_public_key_chirho,
    SubscriptionCursorDigestComponentsChirho,
};
use super::{
    current_subscription_control_plane_witness_chirho, derive_subscription_binding_digests_chirho,
    SubscriptionBindingDigestOutcomeChirho, SubscriptionControlPlaneWitnessOutcomeChirho,
    SubscriptionViewTargetChirho, VerifiedSubscriptionControlPlaneWitnessChirho,
};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use cairn_gate1_authority_log_chirho::authority_log_chirho::verified_gate1_authority_records_chirho;
use cairn_model_gate1_chirho::{
    gate1_authority_record_digest_chirho, Gate1AuthorityLogRecordChirho,
    GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use cairn_subscribe_chirho::{Gate1AuthorityCursorChirho, SubscriptionIdChirho};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SUBSCRIPTION_CURSOR_SCHEMA_CHIRHO: &str = "subscribe-gate1-cursor-v1-chirho";
const GATE1_AUTHORITY_SOURCE_KIND_CHIRHO: &str = "gate1-authority-log-chirho";
const SUBSCRIPTION_CURSOR_TTL_MS_CHIRHO: u64 = 15 * 60 * 1_000;
const SUBSCRIPTION_CURSOR_MAX_ENCODED_BYTES_CHIRHO: usize = 4_096;

/// Opaque wire text can be read for transport but not constructed or debug-rendered by callers.
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::OpaqueSubscriptionCursorTokenChirho;
/// let _token_chirho = OpaqueSubscriptionCursorTokenChirho(String::new());
/// ```
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::OpaqueSubscriptionCursorTokenChirho;
/// fn print_token_chirho(token_chirho: &OpaqueSubscriptionCursorTokenChirho) {
///     println!("{token_chirho:?}");
/// }
/// ```
pub struct OpaqueSubscriptionCursorTokenChirho(String);

impl OpaqueSubscriptionCursorTokenChirho {
    pub fn as_str_chirho(&self) -> &str {
        &self.0
    }
}

pub enum SubscriptionCursorMintOutcomeChirho {
    MintedChirho(OpaqueSubscriptionCursorTokenChirho),
    ResnapshotRequiredChirho,
}

pub enum SubscriptionCursorResumeOutcomeChirho {
    ValidatedChirho(Box<ValidatedSubscriptionCursorChirho>),
    ResnapshotRequiredChirho,
}

/// Validated state cannot be constructed or rendered outside the validator.
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::ValidatedSubscriptionCursorChirho;
/// let _validated_chirho = ValidatedSubscriptionCursorChirho {};
/// ```
///
/// ```compile_fail
/// use cairn_subscription_control_plane_chirho::ValidatedSubscriptionCursorChirho;
/// fn print_validated_chirho(validated_chirho: &ValidatedSubscriptionCursorChirho) {
///     println!("{validated_chirho:?}");
/// }
/// ```
pub struct ValidatedSubscriptionCursorChirho {
    subscription_id_chirho: u64,
    next_source_seq_chirho: u64,
}

impl ValidatedSubscriptionCursorChirho {
    pub fn subscription_id_matches_chirho(
        &self,
        subscription_id_chirho: SubscriptionIdChirho,
    ) -> bool {
        constant_time_eq::constant_time_eq(
            &self.subscription_id_chirho.to_be_bytes(),
            &subscription_id_chirho.value_chirho().to_be_bytes(),
        )
    }

    pub fn cursor_chirho(&self) -> Gate1AuthorityCursorChirho {
        Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: self.next_source_seq_chirho,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedSubscriptionCursorEnvelopeChirho {
    schema_chirho: String,
    source_kind_chirho: String,
    root_identity_digest_chirho: cairn_chirho::model_chirho::HashChirho,
    next_source_seq_chirho: u64,
    previous_record_digest_chirho: Option<String>,
    subscription_id_chirho: u64,
    subscription_generation_chirho: cairn_chirho::model_chirho::HashChirho,
    view_id_digest_chirho: cairn_chirho::model_chirho::HashChirho,
    dependency_set_digest_chirho: cairn_chirho::model_chirho::HashChirho,
    authorization_binding_digest_chirho: cairn_chirho::model_chirho::HashChirho,
    issued_at_ms_chirho: u64,
    expires_at_ms_chirho: u64,
    key_id_chirho: String,
    sig_chirho: String,
}

pub(super) trait Gate1CursorSourceChirho {
    fn verified_records_chirho(
        &mut self,
        root_chirho: &Path,
    ) -> Result<Vec<Gate1AuthorityLogRecordChirho>>;
}

struct RootGate1CursorSourceChirho;

pub(super) struct SubscriptionResumeContextChirho<'a> {
    pub(super) authenticated_principal_chirho: &'a str,
    pub(super) app_chirho: &'a str,
    pub(super) target_chirho: &'a SubscriptionViewTargetChirho,
    pub(super) view_chirho: &'a str,
    pub(super) now_ms_chirho: u64,
}

impl Gate1CursorSourceChirho for RootGate1CursorSourceChirho {
    fn verified_records_chirho(
        &mut self,
        root_chirho: &Path,
    ) -> Result<Vec<Gate1AuthorityLogRecordChirho>> {
        Ok(verified_gate1_authority_records_chirho(root_chirho)?
            .records_chirho()
            .to_vec())
    }
}

pub fn mint_gate1_subscription_cursor_chirho(
    root_chirho: &Path,
    witness_chirho: &VerifiedSubscriptionControlPlaneWitnessChirho,
    subscription_id_chirho: SubscriptionIdChirho,
    cursor_chirho: Gate1AuthorityCursorChirho,
    issued_at_ms_chirho: u64,
) -> SubscriptionCursorMintOutcomeChirho {
    let mut source_chirho = RootGate1CursorSourceChirho;
    match try_mint_gate1_subscription_cursor_chirho(
        root_chirho,
        witness_chirho,
        subscription_id_chirho,
        cursor_chirho,
        issued_at_ms_chirho,
        &mut source_chirho,
    ) {
        Ok(token_chirho) => SubscriptionCursorMintOutcomeChirho::MintedChirho(token_chirho),
        Err(_) => SubscriptionCursorMintOutcomeChirho::ResnapshotRequiredChirho,
    }
}

pub fn resume_gate1_subscription_cursor_chirho(
    root_chirho: &Path,
    token_chirho: &OpaqueSubscriptionCursorTokenChirho,
    authenticated_principal_chirho: &str,
    app_chirho: &str,
    target_chirho: &SubscriptionViewTargetChirho,
    view_chirho: &str,
    now_ms_chirho: u64,
) -> SubscriptionCursorResumeOutcomeChirho {
    let mut source_chirho = RootGate1CursorSourceChirho;
    let context_chirho = SubscriptionResumeContextChirho {
        authenticated_principal_chirho,
        app_chirho,
        target_chirho,
        view_chirho,
        now_ms_chirho,
    };
    match try_resume_gate1_subscription_cursor_chirho(
        root_chirho,
        token_chirho,
        &context_chirho,
        &mut source_chirho,
    ) {
        Ok(cursor_chirho) => {
            SubscriptionCursorResumeOutcomeChirho::ValidatedChirho(Box::new(cursor_chirho))
        }
        Err(_) => SubscriptionCursorResumeOutcomeChirho::ResnapshotRequiredChirho,
    }
}

pub(super) fn try_mint_gate1_subscription_cursor_chirho(
    root_chirho: &Path,
    witness_chirho: &VerifiedSubscriptionControlPlaneWitnessChirho,
    subscription_id_chirho: SubscriptionIdChirho,
    cursor_chirho: Gate1AuthorityCursorChirho,
    issued_at_ms_chirho: u64,
    source_chirho: &mut dyn Gate1CursorSourceChirho,
) -> Result<OpaqueSubscriptionCursorTokenChirho> {
    let digests_chirho = match derive_subscription_binding_digests_chirho(witness_chirho) {
        SubscriptionBindingDigestOutcomeChirho::DerivedChirho(digests_chirho) => digests_chirho,
        SubscriptionBindingDigestOutcomeChirho::ResnapshotRequiredChirho => {
            bail!("current authorization digests are unavailable")
        }
    };
    let components_chirho = digests_chirho.cursor_components_chirho();
    let key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let current_root_identity_chirho = root_identity_digest_from_public_key_chirho(&key_id_chirho)?;
    if !constant_time_digest_matches_chirho(
        &components_chirho.root_identity_digest_chirho,
        &current_root_identity_chirho,
    ) {
        bail!("current root identity does not match verified witness");
    }
    let records_chirho = source_chirho.verified_records_chirho(root_chirho)?;
    let previous_record_digest_chirho =
        previous_record_digest_at_cut_chirho(&records_chirho, cursor_chirho)?;
    let expires_at_ms_chirho = issued_at_ms_chirho
        .checked_add(SUBSCRIPTION_CURSOR_TTL_MS_CHIRHO)
        .ok_or_else(|| anyhow!("cursor expiry overflows"))?;
    let mut envelope_chirho = SignedSubscriptionCursorEnvelopeChirho {
        schema_chirho: SUBSCRIPTION_CURSOR_SCHEMA_CHIRHO.to_string(),
        source_kind_chirho: GATE1_AUTHORITY_SOURCE_KIND_CHIRHO.to_string(),
        root_identity_digest_chirho: components_chirho.root_identity_digest_chirho,
        next_source_seq_chirho: cursor_chirho.next_authority_seq_chirho,
        previous_record_digest_chirho,
        subscription_id_chirho: subscription_id_chirho.value_chirho(),
        subscription_generation_chirho: components_chirho.subscription_generation_chirho,
        view_id_digest_chirho: components_chirho.view_identity_digest_chirho,
        dependency_set_digest_chirho: components_chirho.dependency_set_digest_chirho,
        authorization_binding_digest_chirho: components_chirho.authorization_binding_digest_chirho,
        issued_at_ms_chirho,
        expires_at_ms_chirho,
        key_id_chirho: key_id_chirho.clone(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = unsigned_cursor_message_chirho(&envelope_chirho)?;
    envelope_chirho.sig_chirho =
        signer_chirho::sign_message_with_existing_key_chirho(root_chirho, &unsigned_chirho)?;
    let key_after_sign_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    if !constant_time_eq::constant_time_eq(
        key_id_chirho.as_bytes(),
        key_after_sign_chirho.as_bytes(),
    ) || !signer_chirho::verify_with_root_pubkey_chirho(
        root_chirho,
        &unsigned_chirho,
        &envelope_chirho.sig_chirho,
    )? {
        bail!("cursor signing root changed");
    }
    encode_cursor_chirho(&envelope_chirho)
}

pub(super) fn try_resume_gate1_subscription_cursor_chirho(
    root_chirho: &Path,
    token_chirho: &OpaqueSubscriptionCursorTokenChirho,
    context_chirho: &SubscriptionResumeContextChirho<'_>,
    source_chirho: &mut dyn Gate1CursorSourceChirho,
) -> Result<ValidatedSubscriptionCursorChirho> {
    let envelope_chirho = decode_cursor_chirho(token_chirho)?;
    let expected_key_id_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    if !constant_time_eq::constant_time_eq(
        envelope_chirho.key_id_chirho.as_bytes(),
        expected_key_id_chirho.as_bytes(),
    ) {
        bail!("cursor root key does not match");
    }
    let unsigned_chirho = unsigned_cursor_message_chirho(&envelope_chirho)?;
    if !signer_chirho::verify_with_root_pubkey_chirho(
        root_chirho,
        &unsigned_chirho,
        &envelope_chirho.sig_chirho,
    )? {
        bail!("cursor signature is invalid");
    }
    let expected_expiry_chirho = envelope_chirho
        .issued_at_ms_chirho
        .checked_add(SUBSCRIPTION_CURSOR_TTL_MS_CHIRHO)
        .ok_or_else(|| anyhow!("cursor expiry overflows"))?;
    if envelope_chirho.expires_at_ms_chirho != expected_expiry_chirho
        || envelope_chirho.issued_at_ms_chirho > context_chirho.now_ms_chirho
        || context_chirho.now_ms_chirho >= envelope_chirho.expires_at_ms_chirho
    {
        bail!("cursor validity window is unavailable");
    }
    let witness_chirho = match current_subscription_control_plane_witness_chirho(
        root_chirho,
        context_chirho.authenticated_principal_chirho,
        context_chirho.app_chirho,
        context_chirho.target_chirho,
        context_chirho.view_chirho,
    ) {
        SubscriptionControlPlaneWitnessOutcomeChirho::VerifiedChirho(witness_chirho) => {
            witness_chirho
        }
        SubscriptionControlPlaneWitnessOutcomeChirho::ResnapshotRequiredChirho => {
            bail!("current authorization is unavailable")
        }
    };
    let current_digests_chirho = match derive_subscription_binding_digests_chirho(&witness_chirho) {
        SubscriptionBindingDigestOutcomeChirho::DerivedChirho(digests_chirho) => digests_chirho,
        SubscriptionBindingDigestOutcomeChirho::ResnapshotRequiredChirho => {
            bail!("current authorization digests are unavailable")
        }
    };
    let current_chirho = current_digests_chirho.cursor_components_chirho();
    validate_current_binding_chirho(&envelope_chirho, &current_chirho)?;

    let records_chirho = source_chirho.verified_records_chirho(root_chirho)?;
    let current_previous_digest_chirho = previous_record_digest_at_cut_chirho(
        &records_chirho,
        Gate1AuthorityCursorChirho {
            next_authority_seq_chirho: envelope_chirho.next_source_seq_chirho,
        },
    )?;
    if !optional_digest_matches_chirho(
        envelope_chirho.previous_record_digest_chirho.as_deref(),
        current_previous_digest_chirho.as_deref(),
    ) {
        bail!("cursor source prefix is unavailable");
    }

    Ok(ValidatedSubscriptionCursorChirho {
        subscription_id_chirho: envelope_chirho.subscription_id_chirho,
        next_source_seq_chirho: envelope_chirho.next_source_seq_chirho,
    })
}

fn validate_current_binding_chirho(
    envelope_chirho: &SignedSubscriptionCursorEnvelopeChirho,
    current_chirho: &SubscriptionCursorDigestComponentsChirho,
) -> Result<()> {
    for (cursor_digest_chirho, current_digest_chirho) in [
        (
            &envelope_chirho.root_identity_digest_chirho,
            &current_chirho.root_identity_digest_chirho,
        ),
        (
            &envelope_chirho.view_id_digest_chirho,
            &current_chirho.view_identity_digest_chirho,
        ),
        (
            &envelope_chirho.dependency_set_digest_chirho,
            &current_chirho.dependency_set_digest_chirho,
        ),
        (
            &envelope_chirho.subscription_generation_chirho,
            &current_chirho.subscription_generation_chirho,
        ),
        (
            &envelope_chirho.authorization_binding_digest_chirho,
            &current_chirho.authorization_binding_digest_chirho,
        ),
    ] {
        if !constant_time_digest_matches_chirho(cursor_digest_chirho, current_digest_chirho) {
            bail!("current cursor binding is unavailable");
        }
    }
    Ok(())
}

fn previous_record_digest_at_cut_chirho(
    records_chirho: &[Gate1AuthorityLogRecordChirho],
    cursor_chirho: Gate1AuthorityCursorChirho,
) -> Result<Option<String>> {
    let record_count_chirho = u64::try_from(records_chirho.len())?;
    if cursor_chirho.next_authority_seq_chirho > record_count_chirho {
        bail!("cursor is beyond the verified authority tail");
    }
    if cursor_chirho.next_authority_seq_chirho == 0 {
        return Ok(None);
    }
    let previous_index_chirho = usize::try_from(cursor_chirho.next_authority_seq_chirho - 1)?;
    Ok(Some(gate1_authority_record_digest_chirho(
        &records_chirho[previous_index_chirho],
    )?))
}

fn optional_digest_matches_chirho(left_chirho: Option<&str>, right_chirho: Option<&str>) -> bool {
    match (left_chirho, right_chirho) {
        (None, None) => true,
        (Some(left_chirho), Some(right_chirho)) => {
            constant_time_eq::constant_time_eq(left_chirho.as_bytes(), right_chirho.as_bytes())
        }
        _ => false,
    }
}

fn unsigned_cursor_message_chirho(
    envelope_chirho: &SignedSubscriptionCursorEnvelopeChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = envelope_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn encode_cursor_chirho(
    envelope_chirho: &SignedSubscriptionCursorEnvelopeChirho,
) -> Result<OpaqueSubscriptionCursorTokenChirho> {
    let canonical_chirho = serde_json::to_vec(envelope_chirho)?;
    let encoded_chirho = URL_SAFE_NO_PAD.encode(canonical_chirho);
    if encoded_chirho.len() > SUBSCRIPTION_CURSOR_MAX_ENCODED_BYTES_CHIRHO {
        bail!("cursor token exceeds encoded limit");
    }
    Ok(OpaqueSubscriptionCursorTokenChirho(encoded_chirho))
}

fn decode_cursor_chirho(
    token_chirho: &OpaqueSubscriptionCursorTokenChirho,
) -> Result<SignedSubscriptionCursorEnvelopeChirho> {
    if token_chirho.0.is_empty()
        || token_chirho.0.len() > SUBSCRIPTION_CURSOR_MAX_ENCODED_BYTES_CHIRHO
    {
        bail!("cursor token size is unavailable");
    }
    let decoded_chirho = URL_SAFE_NO_PAD.decode(token_chirho.0.as_bytes())?;
    if URL_SAFE_NO_PAD.encode(&decoded_chirho) != token_chirho.0 {
        bail!("cursor token encoding is noncanonical");
    }
    let envelope_chirho: SignedSubscriptionCursorEnvelopeChirho =
        serde_json::from_slice(&decoded_chirho)?;
    if serde_json::to_vec(&envelope_chirho)? != decoded_chirho {
        bail!("cursor JSON is noncanonical");
    }
    validate_cursor_shape_chirho(&envelope_chirho)?;
    Ok(envelope_chirho)
}

fn validate_cursor_shape_chirho(
    envelope_chirho: &SignedSubscriptionCursorEnvelopeChirho,
) -> Result<()> {
    if envelope_chirho.schema_chirho != SUBSCRIPTION_CURSOR_SCHEMA_CHIRHO
        || envelope_chirho.source_kind_chirho != GATE1_AUTHORITY_SOURCE_KIND_CHIRHO
        || !is_lower_hex_chirho(&envelope_chirho.root_identity_digest_chirho.0, 64)
        || !is_lower_hex_chirho(&envelope_chirho.subscription_generation_chirho.0, 64)
        || !is_lower_hex_chirho(&envelope_chirho.view_id_digest_chirho.0, 64)
        || !is_lower_hex_chirho(&envelope_chirho.dependency_set_digest_chirho.0, 64)
        || !is_lower_hex_chirho(&envelope_chirho.authorization_binding_digest_chirho.0, 64)
        || !is_lower_hex_chirho(&envelope_chirho.key_id_chirho, 64)
        || !is_lower_hex_chirho(&envelope_chirho.sig_chirho, 128)
        || !valid_previous_digest_shape_chirho(
            envelope_chirho.next_source_seq_chirho,
            envelope_chirho.previous_record_digest_chirho.as_deref(),
        )
    {
        bail!("cursor field shape is unavailable");
    }
    Ok(())
}

fn valid_previous_digest_shape_chirho(next_seq_chirho: u64, digest_chirho: Option<&str>) -> bool {
    match (next_seq_chirho, digest_chirho) {
        (0, None) => true,
        (0, Some(_)) | (_, None) => false,
        (_, Some(digest_chirho)) => digest_chirho
            .strip_prefix(GATE1_AUTHORITY_RECORD_DIGEST_PREFIX_CHIRHO)
            .is_some_and(|hex_chirho| is_lower_hex_chirho(hex_chirho, 64)),
    }
}

fn is_lower_hex_chirho(value_chirho: &str, expected_len_chirho: usize) -> bool {
    value_chirho.len() == expected_len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
