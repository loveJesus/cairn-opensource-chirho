// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Role-bound Ed25519 ledger signers loaded only from secret-store refs.

use crate::reconciliation_chirho::Gd7LedgerRecordVerifierPortChirho;
use anyhow::{bail, Result};
use cairn_config_chirho::config_chirho::{
    LedgerHostConfigChirho, LedgerHostHeldVerifierPinsConfigChirho,
    LedgerHostSignerRefsConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
    LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO, LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
};
use cairn_effect_commit_chirho::intent_chirho::{
    EffectIntentSignerPortChirho, EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_chirho::minimal_warrant_chirho::MINIMAL_EFFECT_WARRANT_SCHEMA_V1_CHIRHO;
use cairn_effect_commit_chirho::terminal_chirho::{
    EffectTerminalSignerPortChirho, EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO,
};
use cairn_kind_registry_chirho::record_chirho::KIND_REGISTRY_SCHEMA_V1_CHIRHO;
use cairn_ledger_log_chirho::checkpoint_chirho::HEAD_CHECKPOINT_SCHEMA_V1_CHIRHO;
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    LEDGER_GENESIS_SCHEMA_V1_CHIRHO, LEDGER_RECORD_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_read_model_chirho::feeder_chirho::FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO;
use cairn_ledger_read_model_chirho::heartbeat_chirho::SOURCE_HEARTBEAT_SCHEMA_V1_CHIRHO;
use cairn_ledger_read_model_chirho::merge_feeder_chirho::MERGE_FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO;
use cairn_ledger_read_model_chirho::registry_chirho::PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO;
use cairn_ledger_read_model_chirho::source_registry_chirho::SOURCE_REGISTRY_RECORD_SCHEMA_V1_CHIRHO;
use cairn_secret_chirho::secret_chirho::{
    resolve_secret_ref_chirho, secret_ref_chirho, SecretRefChirho,
};
use cairn_seqlog_chirho::segment_chirho::manifest_chirho::SEGMENT_MANIFEST_ENTRY_SCHEMA_CHIRHO;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::error::Error;
use std::fmt;
use std::path::Path;
use zeroize::Zeroize;

pub mod control_plane_law_chirho;

const SCHEMA_PREFIX_CHIRHO: &str = r#"{"schema_chirho":""#;

/// The six non-substitutable runtime signing authorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LedgerSignerRoleChirho {
    JournalChirho,
    ConfigChirho,
    FeederChirho,
    KindRootChirho,
    EffectIntentChirho,
    EffectTerminalChirho,
}

impl LedgerSignerRoleChirho {
    fn label_chirho(self) -> &'static str {
        match self {
            Self::JournalChirho => "journal-chirho",
            Self::ConfigChirho => "config-chirho",
            Self::FeederChirho => "feeder-chirho",
            Self::KindRootChirho => "kind-root-chirho",
            Self::EffectIntentChirho => "effect-intent-chirho",
            Self::EffectTerminalChirho => "effect-terminal-chirho",
        }
    }

    fn allows_schema_chirho(self, schema_chirho: &str) -> bool {
        match self {
            Self::JournalChirho => matches!(
                schema_chirho,
                LEDGER_GENESIS_SCHEMA_V1_CHIRHO
                    | LEDGER_RECORD_SCHEMA_V1_CHIRHO
                    | HEAD_CHECKPOINT_SCHEMA_V1_CHIRHO
                    | SEGMENT_MANIFEST_ENTRY_SCHEMA_CHIRHO
            ),
            Self::ConfigChirho => matches!(
                schema_chirho,
                PROJECTION_REGISTRY_RECORD_SCHEMA_V1_CHIRHO
                    | SOURCE_REGISTRY_RECORD_SCHEMA_V1_CHIRHO
            ),
            Self::FeederChirho => matches!(
                schema_chirho,
                FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO
                    | MERGE_FOLLOW_RECEIPT_SCHEMA_V1_CHIRHO
                    | SOURCE_HEARTBEAT_SCHEMA_V1_CHIRHO
            ),
            Self::KindRootChirho => schema_chirho == KIND_REGISTRY_SCHEMA_V1_CHIRHO,
            // The minimal warrant is admitted under the SAME role as the intent it is derived
            // from, deliberately: it is signed by the authority that signs intents, it is a strict
            // PROJECTION of one (never new authority), and it asserts strictly less. Admitting it
            // here rather than minting a role keeps the warrant inside the intent's trust boundary.
            Self::EffectIntentChirho => matches!(
                schema_chirho,
                EFFECT_INTENT_SCHEMA_V1_CHIRHO | MINIMAL_EFFECT_WARRANT_SCHEMA_V1_CHIRHO
            ),
            Self::EffectTerminalChirho => schema_chirho == EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO,
        }
    }
}

impl fmt::Display for LedgerSignerRoleChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.label_chirho())
    }
}

/// Typed, value-redacted signer loading and admission failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostLedgerSignerRefusalChirho {
    SecretUnavailableChirho {
        role_chirho: LedgerSignerRoleChirho,
        secret_name_chirho: String,
    },
    SecretLengthChirho {
        role_chirho: LedgerSignerRoleChirho,
        secret_name_chirho: String,
        actual_bytes_chirho: usize,
    },
    AllZeroSecretChirho {
        role_chirho: LedgerSignerRoleChirho,
        secret_name_chirho: String,
    },
    DuplicateSecretNameChirho {
        first_role_chirho: LedgerSignerRoleChirho,
        second_role_chirho: LedgerSignerRoleChirho,
    },
    DuplicateIdentityChirho {
        first_role_chirho: LedgerSignerRoleChirho,
        second_role_chirho: LedgerSignerRoleChirho,
    },
    MessageRoleMismatchChirho {
        role_chirho: LedgerSignerRoleChirho,
    },
    VerificationOnlyChirho {
        role_chirho: LedgerSignerRoleChirho,
    },
}

impl fmt::Display for HostLedgerSignerRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretUnavailableChirho {
                role_chirho,
                secret_name_chirho,
            } => write!(
                formatter_chirho,
                "{role_chirho} secret {secret_name_chirho} is unavailable"
            ),
            Self::SecretLengthChirho {
                role_chirho,
                secret_name_chirho,
                actual_bytes_chirho,
            } => write!(
                formatter_chirho,
                "{role_chirho} secret {secret_name_chirho} must be exactly 32 bytes; found {actual_bytes_chirho}"
            ),
            Self::AllZeroSecretChirho {
                role_chirho,
                secret_name_chirho,
            } => write!(
                formatter_chirho,
                "{role_chirho} secret {secret_name_chirho} must not be all zero"
            ),
            Self::DuplicateSecretNameChirho {
                first_role_chirho,
                second_role_chirho,
            } => write!(
                formatter_chirho,
                "{first_role_chirho} and {second_role_chirho} must use distinct secret names"
            ),
            Self::DuplicateIdentityChirho {
                first_role_chirho,
                second_role_chirho,
            } => write!(
                formatter_chirho,
                "{first_role_chirho} and {second_role_chirho} must derive distinct identities"
            ),
            Self::MessageRoleMismatchChirho { role_chirho } => write!(
                formatter_chirho,
                "canonical message class is not admitted for {role_chirho}"
            ),
            Self::VerificationOnlyChirho { role_chirho } => {
                write!(formatter_chirho, "{role_chirho} key is verification-only")
            }
        }
    }
}

impl Error for HostLedgerSignerRefusalChirho {}

/// The six secret-store coordinates selected by verified host configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostLedgerSignerSecretRefsChirho {
    pub journal_chirho: SecretRefChirho,
    pub config_chirho: SecretRefChirho,
    pub feeder_chirho: SecretRefChirho,
    pub kind_root_chirho: SecretRefChirho,
    pub effect_intent_chirho: SecretRefChirho,
    pub effect_terminal_chirho: SecretRefChirho,
}

/// Convert the already-validated config names into secret-store coordinates. Values are never
/// accepted in configuration and no lookup happens during conversion.
pub fn host_ledger_signer_refs_from_config_chirho(
    config_chirho: &LedgerHostSignerRefsConfigChirho,
) -> Result<HostLedgerSignerSecretRefsChirho> {
    Ok(HostLedgerSignerSecretRefsChirho {
        journal_chirho: secret_ref_chirho(&config_chirho.journal_chirho)?,
        config_chirho: secret_ref_chirho(&config_chirho.config_chirho)?,
        feeder_chirho: secret_ref_chirho(&config_chirho.feeder_chirho)?,
        kind_root_chirho: secret_ref_chirho(&config_chirho.kind_root_chirho)?,
        effect_intent_chirho: secret_ref_chirho(&config_chirho.effect_intent_chirho)?,
        effect_terminal_chirho: secret_ref_chirho(&config_chirho.effect_terminal_chirho)?,
    })
}

/// One signer whose key and accepted canonical message classes are bound to one role.
pub struct RoleBoundLedgerSignerChirho {
    role_chirho: LedgerSignerRoleChirho,
    secret_name_chirho: String,
    signing_key_chirho: SigningKey,
    verifying_key_chirho: VerifyingKey,
}

/// Public-only verifier preserving the same role/schema and key-label boundaries as a runtime
/// signer. It can satisfy read APIs that share `LedgerSignerPortChirho`, but signing always refuses.
pub(crate) struct RoleBoundLedgerVerifierChirho {
    role_chirho: LedgerSignerRoleChirho,
    key_id_chirho: String,
    verifying_key_chirho: VerifyingKey,
}

impl RoleBoundLedgerVerifierChirho {
    pub(crate) fn new_chirho(
        role_chirho: LedgerSignerRoleChirho,
        secret_name_chirho: &str,
        verifying_key_hex_chirho: &str,
    ) -> Result<Self> {
        if secret_name_chirho.is_empty() || secret_name_chirho.len() > 128 {
            bail!("held ledger verifier secret-name label is invalid");
        }
        let verifying_key_bytes_chirho = hex_decode_key_chirho(verifying_key_hex_chirho)
            .ok_or_else(|| {
                anyhow::anyhow!("held ledger verifier key is not canonical lower hex")
            })?;
        if verifying_key_bytes_chirho
            .iter()
            .all(|byte_chirho| *byte_chirho == 0)
        {
            bail!("held ledger verifier key must not be all zero");
        }
        let verifying_key_chirho = VerifyingKey::from_bytes(&verifying_key_bytes_chirho)
            .map_err(|_error_chirho| anyhow::anyhow!("held ledger verifier key is invalid"))?;
        Ok(Self {
            role_chirho,
            key_id_chirho: format!("{role_chirho}:{secret_name_chirho}"),
            verifying_key_chirho,
        })
    }

    fn admits_message_chirho(&self, signed_content_line_chirho: &str) -> bool {
        canonical_schema_chirho(signed_content_line_chirho)
            .is_some_and(|schema_chirho| self.role_chirho.allows_schema_chirho(schema_chirho))
    }
}

impl LedgerSignerPortChirho for RoleBoundLedgerVerifierChirho {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> Result<String> {
        Err(HostLedgerSignerRefusalChirho::VerificationOnlyChirho {
            role_chirho: self.role_chirho,
        }
        .into())
    }

    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        if !self.admits_message_chirho(signed_content_line_chirho) {
            return false;
        }
        let Some(signature_bytes_chirho) = hex_decode_signature_chirho(sig_chirho) else {
            return false;
        };
        self.verifying_key_chirho
            .verify(
                signed_content_line_chirho.as_bytes(),
                &Signature::from_bytes(&signature_bytes_chirho),
            )
            .is_ok()
    }
}

impl Gd7LedgerRecordVerifierPortChirho for RoleBoundLedgerVerifierChirho {
    fn key_id_chirho(&self) -> String {
        LedgerSignerPortChirho::key_id_chirho(self)
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        LedgerSignerPortChirho::verify_chirho(self, signed_content_line_chirho, sig_chirho)
    }
}

impl EffectIntentSignerPortChirho for RoleBoundLedgerVerifierChirho {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> Result<String> {
        Err(HostLedgerSignerRefusalChirho::VerificationOnlyChirho {
            role_chirho: self.role_chirho,
        }
        .into())
    }

    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        LedgerSignerPortChirho::verify_chirho(self, signed_content_line_chirho, sig_chirho)
    }
}

impl EffectTerminalSignerPortChirho for RoleBoundLedgerVerifierChirho {
    fn sign_chirho(&self, _signed_content_line_chirho: &str) -> Result<String> {
        Err(HostLedgerSignerRefusalChirho::VerificationOnlyChirho {
            role_chirho: self.role_chirho,
        }
        .into())
    }

    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        LedgerSignerPortChirho::verify_chirho(self, signed_content_line_chirho, sig_chirho)
    }
}

/// The only ledger roots admitted to a held GD7 process.
pub(crate) struct HostLedgerHeldVerifiersChirho {
    pub(crate) journal_chirho: RoleBoundLedgerVerifierChirho,
    pub(crate) effect_intent_chirho: Option<RoleBoundLedgerVerifierChirho>,
    pub(crate) effect_terminal_chirho: Option<RoleBoundLedgerVerifierChirho>,
}

impl HostLedgerHeldVerifiersChirho {
    pub(crate) fn from_config_chirho(
        signer_refs_chirho: &LedgerHostSignerRefsConfigChirho,
        pins_chirho: &LedgerHostHeldVerifierPinsConfigChirho,
    ) -> Result<Self> {
        let (effect_intent_chirho, effect_terminal_chirho) = match (
            pins_chirho
                .effect_intent_verifying_key_hex_chirho
                .as_deref(),
            pins_chirho
                .effect_terminal_verifying_key_hex_chirho
                .as_deref(),
        ) {
            (None, None) => (None, None),
            (Some(effect_intent_pin_chirho), Some(effect_terminal_pin_chirho)) => (
                Some(RoleBoundLedgerVerifierChirho::new_chirho(
                    LedgerSignerRoleChirho::EffectIntentChirho,
                    &signer_refs_chirho.effect_intent_chirho,
                    effect_intent_pin_chirho,
                )?),
                Some(RoleBoundLedgerVerifierChirho::new_chirho(
                    LedgerSignerRoleChirho::EffectTerminalChirho,
                    &signer_refs_chirho.effect_terminal_chirho,
                    effect_terminal_pin_chirho,
                )?),
            ),
            _ => {
                bail!(
                    "held live ledger verifier pins require both effect-intent and effect-terminal roots"
                );
            }
        };
        let verifiers_chirho = Self {
            journal_chirho: RoleBoundLedgerVerifierChirho::new_chirho(
                LedgerSignerRoleChirho::JournalChirho,
                &signer_refs_chirho.journal_chirho,
                &pins_chirho.journal_verifying_key_hex_chirho,
            )?,
            effect_intent_chirho,
            effect_terminal_chirho,
        };
        if let (Some(effect_intent_chirho), Some(effect_terminal_chirho)) = (
            &verifiers_chirho.effect_intent_chirho,
            &verifiers_chirho.effect_terminal_chirho,
        ) {
            if verifiers_chirho.journal_chirho.verifying_key_chirho
                == effect_intent_chirho.verifying_key_chirho
                || verifiers_chirho.journal_chirho.verifying_key_chirho
                    == effect_terminal_chirho.verifying_key_chirho
                || effect_intent_chirho.verifying_key_chirho
                    == effect_terminal_chirho.verifying_key_chirho
            {
                bail!("held ledger verifier roots must be pairwise distinct");
            }
        }
        Ok(verifiers_chirho)
    }

    pub(crate) fn verify_control_key_separation_chirho(
        &self,
        control_key_hex_chirho: &str,
    ) -> Result<()> {
        let control_key_bytes_chirho = hex_decode_key_chirho(control_key_hex_chirho)
            .ok_or_else(|| anyhow::anyhow!("GD7 control key is not canonical lower hex"))?;
        if self.journal_chirho.verifying_key_chirho.as_bytes() == &control_key_bytes_chirho
            || self
                .effect_intent_chirho
                .as_ref()
                .is_some_and(|verifier_chirho| {
                    verifier_chirho.verifying_key_chirho.as_bytes() == &control_key_bytes_chirho
                })
            || self
                .effect_terminal_chirho
                .as_ref()
                .is_some_and(|verifier_chirho| {
                    verifier_chirho.verifying_key_chirho.as_bytes() == &control_key_bytes_chirho
                })
        {
            bail!("held ledger verifier root must be distinct from every GD7 control key");
        }
        Ok(())
    }
}

/// Build the role-bound journal verifier admitted by one already validated, custody-checked host
/// config, while proving that root remains distinct from the selected GD7 control key.
///
/// The caller owns the existing config-custody check. This constructor deliberately returns an
/// opaque verifier so a downstream geo composition cannot reconstruct the role label, select a
/// trust root from a node id, or gain access to the other held verifier roles.
pub fn configured_held_gd7_journal_verifier_chirho(
    config_chirho: &LedgerHostConfigChirho,
    selected_control_key_hex_chirho: &str,
) -> Result<impl Gd7LedgerRecordVerifierPortChirho> {
    config_chirho.validate_chirho()?;
    let pins_chirho = config_chirho
        .held_verifier_pins_chirho
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("held GD7 journal verifier requires public verifier pins")
        })?;
    let verifiers_chirho = HostLedgerHeldVerifiersChirho::from_config_chirho(
        &config_chirho.signer_secrets_chirho,
        pins_chirho,
    )?;
    verifiers_chirho.verify_control_key_separation_chirho(selected_control_key_hex_chirho)?;
    Ok(verifiers_chirho.journal_chirho)
}

/// Build the public-only journal verifier for a resident geo node after proving the selected secret
/// and public held-verifier pin name the same key. No signing capability leaves this function.
pub fn configured_resident_gd7_journal_verifier_chirho(
    root_chirho: &Path,
    config_chirho: &LedgerHostConfigChirho,
    selected_control_key_hex_chirho: &str,
) -> Result<impl Gd7LedgerRecordVerifierPortChirho> {
    config_chirho.validate_chirho()?;
    let pins_chirho = config_chirho
        .held_verifier_pins_chirho
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("resident F1 mirror requires public journal verifier pins")
        })?;
    let signer_refs_chirho =
        host_ledger_signer_refs_from_config_chirho(&config_chirho.signer_secrets_chirho)?;
    let signer_chirho = RoleBoundLedgerSignerChirho::load_chirho(
        root_chirho,
        &signer_refs_chirho.journal_chirho,
        LedgerSignerRoleChirho::JournalChirho,
    )?;
    let pinned_key_bytes_chirho =
        hex_decode_key_chirho(&pins_chirho.journal_verifying_key_hex_chirho)
            .ok_or_else(|| anyhow::anyhow!("resident journal verifier pin is invalid"))?;
    if signer_chirho.verifying_key_bytes_chirho() != &pinned_key_bytes_chirho {
        bail!("ResidentJournalSignerPinMismatchChirho");
    }
    let verifier_chirho = RoleBoundLedgerVerifierChirho::new_chirho(
        LedgerSignerRoleChirho::JournalChirho,
        &config_chirho.signer_secrets_chirho.journal_chirho,
        &pins_chirho.journal_verifying_key_hex_chirho,
    )?;
    let control_key_bytes_chirho = hex_decode_key_chirho(selected_control_key_hex_chirho)
        .ok_or_else(|| anyhow::anyhow!("GD7 control key is not canonical lower hex"))?;
    if verifier_chirho.verifying_key_chirho.as_bytes() == &control_key_bytes_chirho {
        bail!("resident journal verifier root must be distinct from GD7 control key");
    }
    Ok(verifier_chirho)
}

impl fmt::Debug for RoleBoundLedgerSignerChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho
            .debug_struct("RoleBoundLedgerSignerChirho")
            .field("role_chirho", &self.role_chirho)
            .field("secret_name_chirho", &self.secret_name_chirho)
            .field("key_material_chirho", &"<redacted-chirho>")
            .finish()
    }
}

impl RoleBoundLedgerSignerChirho {
    fn load_chirho(
        root_chirho: &Path,
        secret_ref_chirho: &SecretRefChirho,
        role_chirho: LedgerSignerRoleChirho,
    ) -> Result<Self> {
        let secret_name_chirho = secret_ref_chirho.name_chirho.clone();
        let secret_value_chirho = resolve_secret_ref_chirho(root_chirho, secret_ref_chirho)
            .map_err(
                |_error_chirho| HostLedgerSignerRefusalChirho::SecretUnavailableChirho {
                    role_chirho,
                    secret_name_chirho: secret_name_chirho.clone(),
                },
            )?;
        if secret_value_chirho.as_bytes_chirho().len() != 32 {
            return Err(HostLedgerSignerRefusalChirho::SecretLengthChirho {
                role_chirho,
                secret_name_chirho,
                actual_bytes_chirho: secret_value_chirho.as_bytes_chirho().len(),
            }
            .into());
        }
        if secret_value_chirho
            .as_bytes_chirho()
            .iter()
            .all(|byte_chirho| *byte_chirho == 0)
        {
            return Err(HostLedgerSignerRefusalChirho::AllZeroSecretChirho {
                role_chirho,
                secret_name_chirho,
            }
            .into());
        }
        let mut seed_chirho = [0_u8; 32];
        seed_chirho.copy_from_slice(secret_value_chirho.as_bytes_chirho());
        let signing_key_chirho = SigningKey::from_bytes(&seed_chirho);
        seed_chirho.zeroize();
        let verifying_key_chirho = signing_key_chirho.verifying_key();
        Ok(Self {
            role_chirho,
            secret_name_chirho,
            signing_key_chirho,
            verifying_key_chirho,
        })
    }

    pub fn role_chirho(&self) -> LedgerSignerRoleChirho {
        self.role_chirho
    }

    pub fn secret_name_chirho(&self) -> &str {
        &self.secret_name_chirho
    }

    fn verifying_key_bytes_chirho(&self) -> &[u8; 32] {
        self.verifying_key_chirho.as_bytes()
    }

    fn admits_message_chirho(&self, signed_content_line_chirho: &str) -> bool {
        canonical_schema_chirho(signed_content_line_chirho)
            .is_some_and(|schema_chirho| self.role_chirho.allows_schema_chirho(schema_chirho))
    }

    fn sign_bound_message_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        if !self.admits_message_chirho(signed_content_line_chirho) {
            return Err(HostLedgerSignerRefusalChirho::MessageRoleMismatchChirho {
                role_chirho: self.role_chirho,
            }
            .into());
        }
        Ok(hex_encode_chirho(
            &self
                .signing_key_chirho
                .sign(signed_content_line_chirho.as_bytes())
                .to_bytes(),
        ))
    }

    fn verify_bound_message_chirho(
        &self,
        signed_content_line_chirho: &str,
        sig_chirho: &str,
    ) -> bool {
        if !self.admits_message_chirho(signed_content_line_chirho) {
            return false;
        }
        let Some(signature_bytes_chirho) = hex_decode_signature_chirho(sig_chirho) else {
            return false;
        };
        self.verifying_key_chirho
            .verify(
                signed_content_line_chirho.as_bytes(),
                &Signature::from_bytes(&signature_bytes_chirho),
            )
            .is_ok()
    }

    fn key_label_chirho(&self) -> String {
        format!("{}:{}", self.role_chirho, self.secret_name_chirho)
    }
}

impl LedgerSignerPortChirho for RoleBoundLedgerSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        self.sign_bound_message_chirho(signed_content_line_chirho)
    }

    fn key_id_chirho(&self) -> String {
        self.key_label_chirho()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bound_message_chirho(signed_content_line_chirho, sig_chirho)
    }
}

impl Gd7LedgerRecordVerifierPortChirho for RoleBoundLedgerSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_label_chirho()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bound_message_chirho(signed_content_line_chirho, sig_chirho)
    }
}

impl EffectIntentSignerPortChirho for RoleBoundLedgerSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        self.sign_bound_message_chirho(signed_content_line_chirho)
    }

    fn key_id_chirho(&self) -> String {
        self.key_label_chirho()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bound_message_chirho(signed_content_line_chirho, sig_chirho)
    }
}

impl EffectTerminalSignerPortChirho for RoleBoundLedgerSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        self.sign_bound_message_chirho(signed_content_line_chirho)
    }

    fn key_id_chirho(&self) -> String {
        self.key_label_chirho()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.verify_bound_message_chirho(signed_content_line_chirho, sig_chirho)
    }
}

/// The loaded, pairwise-distinct signer set. Loading is read-only and never generates a key.
///
/// **To a crate other than this one, holding a `HostLedgerSignersChirho` proves that
/// `load_existing_chirho` produced it.** The six fields are `pub(crate)` and are read from outside
/// only through the per-role accessors below, each of which hands back a shared borrow and nothing
/// more. So no other crate can write a struct literal for this type, assign a field on an owned
/// value, or take a `&mut` to one role: the sole way out-of-crate code obtains a set is to call the
/// loader, which reads all six secrets from ONE root and refuses duplicate names and duplicate
/// identities before returning. That closes the splice — taking five roles from one root's set and
/// one role from a DIFFERENT root's — for every consumer that reads a `&HostLedgerSignersChirho` as
/// a custody proof (see `cairn-ledger-regenesis-chirho`'s `issuer_chirho`).
///
/// **The residual, stated so nobody writes a stronger claim than the code carries:** the fields stay
/// `pub(crate)`, so a module INSIDE `cairn-ledger-host-chirho` could still overwrite one role on a
/// set it already loaded. Within this crate the defence therefore remains the module boundary — the
/// one exported authoring road builds the set itself and the derivations that consume it are
/// `pub(crate)`. Sealing the fields module-private would close that too, at 63 further in-crate read
/// sites; it was measured and deliberately left, because the compiled defect this seal answers was
/// an OUTSIDE crate re-assembling the type.
///
/// The two doctests below are the executable record of the closure. They are `compile_fail`, and a
/// doctest compiles as its own crate, so each asserts that the named route is rejected across the
/// crate boundary — the same two routes that COMPILED before this seal.
///
/// **MIGRATION PATH — read this before "fixing" a red here.** If either fence starts FAILING (that
/// is, the snippet COMPILES again), the seal has been undone: someone has widened a field back to
/// `pub`, or added a public constructor / `&mut` accessor / owned-field getter that lets an outside
/// crate assemble a set from parts. That is a money-authority regression, not a doc drift — restore
/// the seal rather than relaxing the fence. If instead a fence fails because the snippet no longer
/// names a real field, the type was renamed: retarget the snippet at the new field WITHOUT weakening
/// what it asks.
///
/// Re-assembly by struct literal, splicing one role in from a second root's loaded set:
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::HostLedgerSignersChirho;
/// fn splice_chirho(
///     first_chirho: HostLedgerSignersChirho,
///     second_chirho: HostLedgerSignersChirho,
/// ) -> HostLedgerSignersChirho {
///     HostLedgerSignersChirho {
///         journal_chirho: first_chirho.journal_chirho,
///         config_chirho: first_chirho.config_chirho,
///         feeder_chirho: first_chirho.feeder_chirho,
///         kind_root_chirho: second_chirho.kind_root_chirho,
///         effect_intent_chirho: first_chirho.effect_intent_chirho,
///         effect_terminal_chirho: first_chirho.effect_terminal_chirho,
///     }
/// }
/// ```
///
/// Field assignment on an owned value is the same defect without a literal, and it is asked
/// SEPARATELY because the two need different fixes: `#[non_exhaustive]` would block the literal
/// above and leave this one open, which is why sealing — not an attribute — is the real remedy.
///
/// ```compile_fail
/// use cairn_ledger_host_chirho::HostLedgerSignersChirho;
/// fn overwrite_chirho(
///     mut first_chirho: HostLedgerSignersChirho,
///     second_chirho: HostLedgerSignersChirho,
/// ) -> HostLedgerSignersChirho {
///     first_chirho.kind_root_chirho = second_chirho.kind_root_chirho;
///     first_chirho
/// }
/// ```
#[derive(Debug)]
pub struct HostLedgerSignersChirho {
    pub(crate) journal_chirho: RoleBoundLedgerSignerChirho,
    pub(crate) config_chirho: RoleBoundLedgerSignerChirho,
    pub(crate) feeder_chirho: RoleBoundLedgerSignerChirho,
    pub(crate) kind_root_chirho: RoleBoundLedgerSignerChirho,
    pub(crate) effect_intent_chirho: RoleBoundLedgerSignerChirho,
    pub(crate) effect_terminal_chirho: RoleBoundLedgerSignerChirho,
}

impl HostLedgerSignersChirho {
    /// Load and bind all six runtime signer roles from explicit secret refs.
    ///
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
    pub fn load_existing_chirho(
        root_chirho: &Path,
        refs_chirho: &HostLedgerSignerSecretRefsChirho,
    ) -> Result<Self> {
        refuse_duplicate_names_chirho(refs_chirho)?;
        let signers_chirho = Self {
            journal_chirho: RoleBoundLedgerSignerChirho::load_chirho(
                root_chirho,
                &refs_chirho.journal_chirho,
                LedgerSignerRoleChirho::JournalChirho,
            )?,
            config_chirho: RoleBoundLedgerSignerChirho::load_chirho(
                root_chirho,
                &refs_chirho.config_chirho,
                LedgerSignerRoleChirho::ConfigChirho,
            )?,
            feeder_chirho: RoleBoundLedgerSignerChirho::load_chirho(
                root_chirho,
                &refs_chirho.feeder_chirho,
                LedgerSignerRoleChirho::FeederChirho,
            )?,
            kind_root_chirho: RoleBoundLedgerSignerChirho::load_chirho(
                root_chirho,
                &refs_chirho.kind_root_chirho,
                LedgerSignerRoleChirho::KindRootChirho,
            )?,
            effect_intent_chirho: RoleBoundLedgerSignerChirho::load_chirho(
                root_chirho,
                &refs_chirho.effect_intent_chirho,
                LedgerSignerRoleChirho::EffectIntentChirho,
            )?,
            effect_terminal_chirho: RoleBoundLedgerSignerChirho::load_chirho(
                root_chirho,
                &refs_chirho.effect_terminal_chirho,
                LedgerSignerRoleChirho::EffectTerminalChirho,
            )?,
        };
        refuse_duplicate_identities_chirho(&signers_chirho)?;
        Ok(signers_chirho)
    }

    /// Derive a journal-only schema-v3 config for a synthetic shared-journal topology from this
    /// already custody-bound signer set.
    ///
    /// The caller supplies only the CHOICE to take this branch. No caller-selected verifier value
    /// crosses into this crate: this method requires the config's six signer names to identify this
    /// exact loaded set, derives the public half from the journal signer held here, and returns that
    /// public value only inside the validated config. Production configs, pre-pinned configs, and
    /// v3/v4 inputs refuse. Effect verifier pins remain absent.
    pub fn author_test_kind_shared_journal_config_chirho(
        &self,
        config_chirho: &LedgerHostConfigChirho,
    ) -> Result<LedgerHostConfigChirho> {
        config_chirho.validate_chirho()?;
        if config_chirho.test_kind_chirho.is_none() {
            bail!("shared journal verifier authoring requires a test-kind config");
        }
        if !matches!(
            config_chirho.schema_chirho.as_str(),
            LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO | LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO
        ) || config_chirho.held_verifier_pins_chirho.is_some()
        {
            bail!("shared journal verifier authoring requires one unpinned v1/v2 config");
        }
        let signer_refs_chirho = &config_chirho.signer_secrets_chirho;
        let loaded_names_chirho = [
            self.journal_chirho.secret_name_chirho(),
            self.config_chirho.secret_name_chirho(),
            self.feeder_chirho.secret_name_chirho(),
            self.kind_root_chirho.secret_name_chirho(),
            self.effect_intent_chirho.secret_name_chirho(),
            self.effect_terminal_chirho.secret_name_chirho(),
        ];
        let configured_names_chirho = [
            signer_refs_chirho.journal_chirho.as_str(),
            signer_refs_chirho.config_chirho.as_str(),
            signer_refs_chirho.feeder_chirho.as_str(),
            signer_refs_chirho.kind_root_chirho.as_str(),
            signer_refs_chirho.effect_intent_chirho.as_str(),
            signer_refs_chirho.effect_terminal_chirho.as_str(),
        ];
        if loaded_names_chirho != configured_names_chirho {
            bail!("shared journal verifier authoring signer set does not bind the config");
        }

        let mut authored_chirho = config_chirho.clone();
        authored_chirho.schema_chirho = LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO.to_owned();
        authored_chirho.held_verifier_pins_chirho = Some(LedgerHostHeldVerifierPinsConfigChirho {
            journal_verifying_key_hex_chirho: hex_encode_chirho(
                self.journal_chirho.verifying_key_bytes_chirho(),
            ),
            effect_intent_verifying_key_hex_chirho: None,
            effect_terminal_verifying_key_hex_chirho: None,
        });
        authored_chirho.validate_chirho()?;
        Ok(authored_chirho)
    }

    /// Borrow the journal-role signer. A shared borrow is the whole of the read surface this type
    /// offers a foreign crate: it hands back no owned signer, no `&mut`, and no key bytes — the
    /// signer's own key material stays private to this module behind its port impls.
    pub fn journal_signer_chirho(&self) -> &RoleBoundLedgerSignerChirho {
        &self.journal_chirho
    }

    /// Borrow the config-role signer. Same shared-borrow-only surface as `journal_signer_chirho`.
    pub fn config_signer_chirho(&self) -> &RoleBoundLedgerSignerChirho {
        &self.config_chirho
    }

    /// Borrow the feeder-role signer. Same shared-borrow-only surface as `journal_signer_chirho`.
    pub fn feeder_signer_chirho(&self) -> &RoleBoundLedgerSignerChirho {
        &self.feeder_chirho
    }

    /// Borrow the kind-root-role signer. Same shared-borrow-only surface as `journal_signer_chirho`.
    pub fn kind_root_signer_chirho(&self) -> &RoleBoundLedgerSignerChirho {
        &self.kind_root_chirho
    }

    /// Borrow the effect-intent-role signer. Same shared-borrow-only surface as
    /// `journal_signer_chirho`.
    pub fn effect_intent_signer_chirho(&self) -> &RoleBoundLedgerSignerChirho {
        &self.effect_intent_chirho
    }

    /// Borrow the effect-terminal-role signer. Same shared-borrow-only surface as
    /// `journal_signer_chirho`.
    pub fn effect_terminal_signer_chirho(&self) -> &RoleBoundLedgerSignerChirho {
        &self.effect_terminal_chirho
    }

    /// Return the runtime role that already owns a candidate secret name. The candidate value is
    /// never resolved here; H3 uses this before create to keep its offline seventh key distinct.
    pub fn matching_secret_name_role_chirho(
        &self,
        candidate_name_chirho: &str,
    ) -> Option<LedgerSignerRoleChirho> {
        self.signers_by_role_chirho()
            .into_iter()
            .find_map(|(role_chirho, signer_chirho)| {
                (signer_chirho.secret_name_chirho() == candidate_name_chirho).then_some(role_chirho)
            })
    }

    /// Return the runtime role that already owns a candidate Ed25519 identity. No runtime public
    /// key bytes leave this boundary; H3 supplies its candidate and receives only the role label.
    pub fn matching_verifying_identity_role_chirho(
        &self,
        candidate_identity_chirho: &[u8; 32],
    ) -> Option<LedgerSignerRoleChirho> {
        self.signers_by_role_chirho()
            .into_iter()
            .find_map(|(role_chirho, signer_chirho)| {
                (signer_chirho.verifying_key_bytes_chirho() == candidate_identity_chirho)
                    .then_some(role_chirho)
            })
    }

    fn signers_by_role_chirho(
        &self,
    ) -> [(LedgerSignerRoleChirho, &RoleBoundLedgerSignerChirho); 6] {
        [
            (LedgerSignerRoleChirho::JournalChirho, &self.journal_chirho),
            (LedgerSignerRoleChirho::ConfigChirho, &self.config_chirho),
            (LedgerSignerRoleChirho::FeederChirho, &self.feeder_chirho),
            (
                LedgerSignerRoleChirho::KindRootChirho,
                &self.kind_root_chirho,
            ),
            (
                LedgerSignerRoleChirho::EffectIntentChirho,
                &self.effect_intent_chirho,
            ),
            (
                LedgerSignerRoleChirho::EffectTerminalChirho,
                &self.effect_terminal_chirho,
            ),
        ]
    }
}

fn refuse_duplicate_names_chirho(refs_chirho: &HostLedgerSignerSecretRefsChirho) -> Result<()> {
    let refs_by_role_chirho = [
        (
            LedgerSignerRoleChirho::JournalChirho,
            &refs_chirho.journal_chirho,
        ),
        (
            LedgerSignerRoleChirho::ConfigChirho,
            &refs_chirho.config_chirho,
        ),
        (
            LedgerSignerRoleChirho::FeederChirho,
            &refs_chirho.feeder_chirho,
        ),
        (
            LedgerSignerRoleChirho::KindRootChirho,
            &refs_chirho.kind_root_chirho,
        ),
        (
            LedgerSignerRoleChirho::EffectIntentChirho,
            &refs_chirho.effect_intent_chirho,
        ),
        (
            LedgerSignerRoleChirho::EffectTerminalChirho,
            &refs_chirho.effect_terminal_chirho,
        ),
    ];
    for (index_chirho, (first_role_chirho, first_ref_chirho)) in
        refs_by_role_chirho.iter().enumerate()
    {
        for (second_role_chirho, second_ref_chirho) in &refs_by_role_chirho[index_chirho + 1..] {
            if first_ref_chirho.name_chirho == second_ref_chirho.name_chirho {
                return Err(HostLedgerSignerRefusalChirho::DuplicateSecretNameChirho {
                    first_role_chirho: *first_role_chirho,
                    second_role_chirho: *second_role_chirho,
                }
                .into());
            }
        }
    }
    Ok(())
}

fn refuse_duplicate_identities_chirho(signers_chirho: &HostLedgerSignersChirho) -> Result<()> {
    let signers_by_role_chirho = [
        (
            LedgerSignerRoleChirho::JournalChirho,
            &signers_chirho.journal_chirho,
        ),
        (
            LedgerSignerRoleChirho::ConfigChirho,
            &signers_chirho.config_chirho,
        ),
        (
            LedgerSignerRoleChirho::FeederChirho,
            &signers_chirho.feeder_chirho,
        ),
        (
            LedgerSignerRoleChirho::KindRootChirho,
            &signers_chirho.kind_root_chirho,
        ),
        (
            LedgerSignerRoleChirho::EffectIntentChirho,
            &signers_chirho.effect_intent_chirho,
        ),
        (
            LedgerSignerRoleChirho::EffectTerminalChirho,
            &signers_chirho.effect_terminal_chirho,
        ),
    ];
    for (index_chirho, (first_role_chirho, first_signer_chirho)) in
        signers_by_role_chirho.iter().enumerate()
    {
        for (second_role_chirho, second_signer_chirho) in
            &signers_by_role_chirho[index_chirho + 1..]
        {
            if first_signer_chirho.verifying_key_bytes_chirho()
                == second_signer_chirho.verifying_key_bytes_chirho()
            {
                return Err(HostLedgerSignerRefusalChirho::DuplicateIdentityChirho {
                    first_role_chirho: *first_role_chirho,
                    second_role_chirho: *second_role_chirho,
                }
                .into());
            }
        }
    }
    Ok(())
}

fn canonical_schema_chirho(signed_content_line_chirho: &str) -> Option<&str> {
    let remainder_chirho = signed_content_line_chirho.strip_prefix(SCHEMA_PREFIX_CHIRHO)?;
    let closing_quote_chirho = remainder_chirho.find('"')?;
    let schema_chirho = &remainder_chirho[..closing_quote_chirho];
    (!schema_chirho.is_empty()
        && schema_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase() || byte_chirho.is_ascii_digit() || byte_chirho == b'-'
        }))
    .then_some(schema_chirho)
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write;
        write!(&mut encoded_chirho, "{byte_chirho:02x}").expect("writing to String cannot fail");
    }
    encoded_chirho
}

fn hex_decode_signature_chirho(encoded_chirho: &str) -> Option<[u8; 64]> {
    if encoded_chirho.len() != 128 || !encoded_chirho.is_ascii() {
        return None;
    }
    let mut decoded_chirho = [0_u8; 64];
    for (index_chirho, byte_chirho) in decoded_chirho.iter_mut().enumerate() {
        let start_chirho = index_chirho * 2;
        *byte_chirho =
            u8::from_str_radix(&encoded_chirho[start_chirho..start_chirho + 2], 16).ok()?;
    }
    Some(decoded_chirho)
}

fn hex_decode_key_chirho(encoded_chirho: &str) -> Option<[u8; 32]> {
    if encoded_chirho.len() != 64
        || !encoded_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
    {
        return None;
    }
    let mut decoded_chirho = [0_u8; 32];
    for (index_chirho, byte_chirho) in decoded_chirho.iter_mut().enumerate() {
        let start_chirho = index_chirho * 2;
        *byte_chirho =
            u8::from_str_radix(&encoded_chirho[start_chirho..start_chirho + 2], 16).ok()?;
    }
    Some(decoded_chirho)
}

#[cfg(test)]
mod verifier_tests_chirho {
    use super::*;
    use cairn_config_chirho::config_chirho::{
        LedgerHostIssuerPinConfigChirho, LedgerHostMemberConfigChirho,
        LedgerHostProjectionRouteConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
    };
    use cairn_secret_chirho::secret_chirho::set_secret_chirho;

    fn held_gd7_verifier_config_chirho(
        journal_key_hex_chirho: String,
        intent_key_hex_chirho: String,
        terminal_key_hex_chirho: String,
    ) -> LedgerHostConfigChirho {
        LedgerHostConfigChirho {
            schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO.to_owned(),
            storage_namespace_chirho: "ledger-storage-chirho".to_owned(),
            monitor_evidence_namespace_chirho: "monitor-evidence-chirho".to_owned(),
            monitor_evidence_path_chirho: "cycles/conservation-chirho.jsonl".to_owned(),
            money_group_id_chirho: "money-group-chirho".to_owned(),
            cluster_id_chirho: "cluster-chirho".to_owned(),
            journal_path_chirho: "journals-chirho/money-chirho.jsonl".to_owned(),
            local_epoch_chirho: 1,
            members_chirho: vec![LedgerHostMemberConfigChirho {
                owner_chirho: "owner-chirho".to_owned(),
                kind_id_chirho: "credits-chirho".to_owned(),
            }],
            kind_registry_path_chirho: "registries-chirho/kinds-chirho.jsonl".to_owned(),
            kind_registry_id_chirho: "kind-registry-chirho".to_owned(),
            kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
                principal_chirho: "kind-issuer-chirho".to_owned(),
                verifying_key_hex_chirho: hex_encode_chirho(
                    SigningKey::from_bytes(&[0x59; 32])
                        .verifying_key()
                        .as_bytes(),
                ),
            },
            activation_authority_chirho: None,
            projection_registry_path_chirho: "registries-chirho/projections-chirho.jsonl"
                .to_owned(),
            projection_registry_id_chirho: "projection-registry-chirho".to_owned(),
            source_registry_path_chirho: "registries-chirho/sources-chirho.jsonl".to_owned(),
            source_registry_id_chirho: "source-registry-chirho".to_owned(),
            projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
                projection_name_chirho: "account-net-chirho".to_owned(),
                head_path_chirho: "projection-heads-chirho/account-net-chirho.json".to_owned(),
            }],
            signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
                journal_chirho: "shared-winner-journal-secret-chirho".to_owned(),
                config_chirho: "config-secret-chirho".to_owned(),
                feeder_chirho: "feeder-secret-chirho".to_owned(),
                kind_root_chirho: "kind-root-secret-chirho".to_owned(),
                effect_intent_chirho: "effect-intent-secret-chirho".to_owned(),
                effect_terminal_chirho: "effect-terminal-secret-chirho".to_owned(),
            },
            migration_destination_authority_chirho: None,
            held_verifier_pins_chirho: Some(LedgerHostHeldVerifierPinsConfigChirho {
                journal_verifying_key_hex_chirho: journal_key_hex_chirho,
                effect_intent_verifying_key_hex_chirho: Some(intent_key_hex_chirho),
                effect_terminal_verifying_key_hex_chirho: Some(terminal_key_hex_chirho),
            }),
            monitor_cadence_ms_chirho: 5_000,
            postgres_effect_chirho: None,
            control_plane_chirho: None,
            test_kind_chirho: None,
            adopt_migrated_root_chirho: false,
        }
    }

    #[test]
    fn public_only_verifier_preserves_role_and_refuses_signing_chirho() {
        let signing_key_chirho = SigningKey::from_bytes(&[0x5a; 32]);
        let public_key_hex_chirho =
            hex_encode_chirho(signing_key_chirho.verifying_key().as_bytes());
        let journal_verifier_chirho = RoleBoundLedgerVerifierChirho::new_chirho(
            LedgerSignerRoleChirho::JournalChirho,
            "journal-secret-chirho",
            &public_key_hex_chirho,
        )
        .unwrap();
        let kind_verifier_chirho = RoleBoundLedgerVerifierChirho::new_chirho(
            LedgerSignerRoleChirho::KindRootChirho,
            "kind-secret-chirho",
            &public_key_hex_chirho,
        )
        .unwrap();
        let journal_content_chirho =
            format!(r#"{{"schema_chirho":"{LEDGER_RECORD_SCHEMA_V1_CHIRHO}"}}"#);
        let signature_chirho = hex_encode_chirho(
            &signing_key_chirho
                .sign(journal_content_chirho.as_bytes())
                .to_bytes(),
        );

        assert!(LedgerSignerPortChirho::verify_chirho(
            &journal_verifier_chirho,
            &journal_content_chirho,
            &signature_chirho
        ));
        assert!(!LedgerSignerPortChirho::verify_chirho(
            &kind_verifier_chirho,
            &journal_content_chirho,
            &signature_chirho
        ));
        assert!(LedgerSignerPortChirho::sign_chirho(
            &journal_verifier_chirho,
            &journal_content_chirho
        )
        .unwrap_err()
        .to_string()
        .contains("verification-only"));
        assert_eq!(
            LedgerSignerPortChirho::key_id_chirho(&journal_verifier_chirho),
            "journal-chirho:journal-secret-chirho"
        );
    }

    #[test]
    fn held_verifier_set_preserves_v3_and_builds_v4_public_roles_chirho() {
        let signer_refs_chirho = LedgerHostSignerRefsConfigChirho {
            journal_chirho: "journal-secret-chirho".to_string(),
            config_chirho: "config-secret-chirho".to_string(),
            feeder_chirho: "feeder-secret-chirho".to_string(),
            kind_root_chirho: "kind-root-secret-chirho".to_string(),
            effect_intent_chirho: "effect-intent-secret-chirho".to_string(),
            effect_terminal_chirho: "effect-terminal-secret-chirho".to_string(),
        };
        let journal_signing_key_chirho = SigningKey::from_bytes(&[0x5a; 32]);
        let intent_signing_key_chirho = SigningKey::from_bytes(&[0x5b; 32]);
        let terminal_signing_key_chirho = SigningKey::from_bytes(&[0x5c; 32]);
        let journal_key_hex_chirho =
            hex_encode_chirho(journal_signing_key_chirho.verifying_key().as_bytes());
        let intent_key_hex_chirho =
            hex_encode_chirho(intent_signing_key_chirho.verifying_key().as_bytes());
        let terminal_key_hex_chirho =
            hex_encode_chirho(terminal_signing_key_chirho.verifying_key().as_bytes());

        let historical_verifiers_chirho = HostLedgerHeldVerifiersChirho::from_config_chirho(
            &signer_refs_chirho,
            &LedgerHostHeldVerifierPinsConfigChirho {
                journal_verifying_key_hex_chirho: journal_key_hex_chirho.clone(),
                effect_intent_verifying_key_hex_chirho: None,
                effect_terminal_verifying_key_hex_chirho: None,
            },
        )
        .unwrap();
        assert!(historical_verifiers_chirho.effect_intent_chirho.is_none());
        assert!(historical_verifiers_chirho.effect_terminal_chirho.is_none());

        let live_verifiers_chirho = HostLedgerHeldVerifiersChirho::from_config_chirho(
            &signer_refs_chirho,
            &LedgerHostHeldVerifierPinsConfigChirho {
                journal_verifying_key_hex_chirho: journal_key_hex_chirho.clone(),
                effect_intent_verifying_key_hex_chirho: Some(intent_key_hex_chirho.clone()),
                effect_terminal_verifying_key_hex_chirho: Some(terminal_key_hex_chirho.clone()),
            },
        )
        .unwrap();
        let intent_verifier_chirho = live_verifiers_chirho.effect_intent_chirho.as_ref().unwrap();
        let terminal_verifier_chirho = live_verifiers_chirho
            .effect_terminal_chirho
            .as_ref()
            .unwrap();
        let intent_content_chirho =
            format!(r#"{{"schema_chirho":"{EFFECT_INTENT_SCHEMA_V1_CHIRHO}"}}"#);
        let terminal_content_chirho =
            format!(r#"{{"schema_chirho":"{EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO}"}}"#);
        let intent_signature_chirho = hex_encode_chirho(
            &intent_signing_key_chirho
                .sign(intent_content_chirho.as_bytes())
                .to_bytes(),
        );
        let terminal_signature_chirho = hex_encode_chirho(
            &terminal_signing_key_chirho
                .sign(terminal_content_chirho.as_bytes())
                .to_bytes(),
        );

        assert!(EffectIntentSignerPortChirho::verify_chirho(
            intent_verifier_chirho,
            &intent_content_chirho,
            &intent_signature_chirho
        ));
        assert!(EffectTerminalSignerPortChirho::verify_chirho(
            terminal_verifier_chirho,
            &terminal_content_chirho,
            &terminal_signature_chirho
        ));
        assert!(!EffectIntentSignerPortChirho::verify_chirho(
            intent_verifier_chirho,
            &terminal_content_chirho,
            &terminal_signature_chirho
        ));
        assert!(!EffectTerminalSignerPortChirho::verify_chirho(
            terminal_verifier_chirho,
            &intent_content_chirho,
            &intent_signature_chirho
        ));
        assert!(EffectIntentSignerPortChirho::sign_chirho(
            intent_verifier_chirho,
            &intent_content_chirho
        )
        .unwrap_err()
        .to_string()
        .contains("verification-only"));
        assert!(EffectTerminalSignerPortChirho::sign_chirho(
            terminal_verifier_chirho,
            &terminal_content_chirho
        )
        .unwrap_err()
        .to_string()
        .contains("verification-only"));
        assert_eq!(
            EffectIntentSignerPortChirho::key_id_chirho(intent_verifier_chirho),
            "effect-intent-chirho:effect-intent-secret-chirho"
        );
        assert_eq!(
            EffectTerminalSignerPortChirho::key_id_chirho(terminal_verifier_chirho),
            "effect-terminal-chirho:effect-terminal-secret-chirho"
        );
        assert!(live_verifiers_chirho
            .verify_control_key_separation_chirho(&hex_encode_chirho(
                SigningKey::from_bytes(&[0x5d; 32])
                    .verifying_key()
                    .to_bytes()
                    .as_slice(),
            ))
            .is_ok());
        assert!(live_verifiers_chirho
            .verify_control_key_separation_chirho(&journal_key_hex_chirho)
            .unwrap_err()
            .to_string()
            .contains("distinct from every GD7 control key"));
        assert!(live_verifiers_chirho
            .verify_control_key_separation_chirho(&intent_key_hex_chirho)
            .is_err());
        assert!(live_verifiers_chirho
            .verify_control_key_separation_chirho(&terminal_key_hex_chirho)
            .is_err());

        assert!(HostLedgerHeldVerifiersChirho::from_config_chirho(
            &signer_refs_chirho,
            &LedgerHostHeldVerifierPinsConfigChirho {
                journal_verifying_key_hex_chirho: journal_key_hex_chirho,
                effect_intent_verifying_key_hex_chirho: Some(intent_key_hex_chirho.clone()),
                effect_terminal_verifying_key_hex_chirho: Some(intent_key_hex_chirho),
            },
        )
        .err()
        .unwrap()
        .to_string()
        .contains("pairwise distinct"));
    }

    #[test]
    fn configured_gd7_journal_verifier_preserves_role_label_and_control_separation_chirho() {
        let journal_signing_key_chirho = SigningKey::from_bytes(&[0x5a; 32]);
        let journal_key_hex_chirho =
            hex_encode_chirho(journal_signing_key_chirho.verifying_key().as_bytes());
        let intent_key_hex_chirho = hex_encode_chirho(
            SigningKey::from_bytes(&[0x5b; 32])
                .verifying_key()
                .as_bytes(),
        );
        let terminal_key_hex_chirho = hex_encode_chirho(
            SigningKey::from_bytes(&[0x5c; 32])
                .verifying_key()
                .as_bytes(),
        );
        let config_chirho = held_gd7_verifier_config_chirho(
            journal_key_hex_chirho.clone(),
            intent_key_hex_chirho,
            terminal_key_hex_chirho,
        );
        let distinct_control_key_hex_chirho = hex_encode_chirho(
            SigningKey::from_bytes(&[0x5d; 32])
                .verifying_key()
                .as_bytes(),
        );

        let verifier_chirho = configured_held_gd7_journal_verifier_chirho(
            &config_chirho,
            &distinct_control_key_hex_chirho,
        )
        .expect("valid config yields one opaque journal verifier");
        assert_eq!(
            Gd7LedgerRecordVerifierPortChirho::key_id_chirho(&verifier_chirho),
            "journal-chirho:shared-winner-journal-secret-chirho"
        );
        let signed_record_content_chirho =
            format!(r#"{{"schema_chirho":"{LEDGER_RECORD_SCHEMA_V1_CHIRHO}"}}"#);
        let signature_chirho = hex_encode_chirho(
            &journal_signing_key_chirho
                .sign(signed_record_content_chirho.as_bytes())
                .to_bytes(),
        );
        assert!(Gd7LedgerRecordVerifierPortChirho::verify_chirho(
            &verifier_chirho,
            &signed_record_content_chirho,
            &signature_chirho,
        ));
        assert!(configured_held_gd7_journal_verifier_chirho(
            &config_chirho,
            &journal_key_hex_chirho,
        )
        .err()
        .expect("the selected control key must not equal the configured journal root")
        .to_string()
        .contains("distinct from every GD7 control key"));
    }

    #[test]
    fn resident_journal_verifier_refuses_a_public_pin_that_differs_from_the_secret_chirho() {
        let root_chirho = crate::tests_chirho::temp_root_chirho("resident-journal-verifier-chirho");
        let journal_seed_chirho = [0x5a; 32];
        set_secret_chirho(
            &root_chirho,
            "shared-winner-journal-secret-chirho",
            &journal_seed_chirho,
        )
        .expect("install resident journal secret");
        let journal_key_hex_chirho = hex_encode_chirho(
            SigningKey::from_bytes(&journal_seed_chirho)
                .verifying_key()
                .as_bytes(),
        );
        let distinct_control_key_hex_chirho = hex_encode_chirho(
            SigningKey::from_bytes(&[0x5d; 32])
                .verifying_key()
                .as_bytes(),
        );
        let mut config_chirho = held_gd7_verifier_config_chirho(
            journal_key_hex_chirho,
            hex_encode_chirho(
                SigningKey::from_bytes(&[0x5b; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            hex_encode_chirho(
                SigningKey::from_bytes(&[0x5c; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
        );
        let verifier_chirho = configured_resident_gd7_journal_verifier_chirho(
            &root_chirho,
            &config_chirho,
            &distinct_control_key_hex_chirho,
        )
        .expect("matching secret and public pin yield only a verifier");
        assert_eq!(
            Gd7LedgerRecordVerifierPortChirho::key_id_chirho(&verifier_chirho),
            "journal-chirho:shared-winner-journal-secret-chirho"
        );

        config_chirho
            .held_verifier_pins_chirho
            .as_mut()
            .expect("fixture has held pins")
            .journal_verifying_key_hex_chirho = hex_encode_chirho(
            SigningKey::from_bytes(&[0x6a; 32])
                .verifying_key()
                .as_bytes(),
        );
        assert!(configured_resident_gd7_journal_verifier_chirho(
            &root_chirho,
            &config_chirho,
            &distinct_control_key_hex_chirho,
        )
        .err()
        .expect("mismatched pin must refuse at startup")
        .to_string()
        .contains("ResidentJournalSignerPinMismatchChirho"));
        std::fs::remove_dir_all(&root_chirho).expect("remove resident signer root");
    }
}
