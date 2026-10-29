// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Canonical signed CF3 terminal outcomes and their one-coordinate law.
//!
//! One original effect intent has exactly one terminal coordinate. The coordinate derives only
//! from the verified intent ref; provider evidence, result identity, and disposition deliberately
//! do not fork it. A journal can therefore detect conflicting terminal observations at one key.
//!
//! # RECORDED CONTENT DECISION: this line needs no narrowing (measured, not inherited)
//!
//! The intent side was narrowed to a minimal signed warrant because its full line carried
//! unvalidated free `String`s (an account owner and an attribution principal) into a permanent,
//! content-addressed store. The same question was then asked of THIS object, at the bytes, field by
//! field against `EffectTerminalOutcomeChirho` and its body validator:
//!
//! - `schema_chirho` — refused unless byte-equal to one constant. An enum of one.
//! - `intent_ref_chirho`, `provider_evidence_ref_chirho` — refused unless 64 lower-hex. Digests.
//! - `disposition_chirho` — a two-variant tagged enum; its only payload, `result_ref_chirho`, is
//!   refused unless 64 lower-hex.
//!
//! Those four carry no free text and no identifier, so the terminal outcome is ALREADY minimal:
//! there is nothing to project away, and publishing it whole is the decision, not an oversight.
//! **A `MinimalEffectTerminalOutcomeChirho` would be a rename of this struct.**
//!
//! Two fields sit outside that list and are NOT digests — `sig_chirho` and `key_id_chirho`. They
//! were length-bounded only, so this object could carry an email-shaped or multi-word key label to
//! disk. They now answer to the money log's own bounded-identifier law (control characters,
//! whitespace, `@`), applied at the cap this object declares rather than the record cap, because a
//! detached signature is legitimately longer than an account name. They stay verbatim rather than
//! becoming digests: a key id is an audit label meant to be read, and a signature must be the exact
//! bytes or it cannot verify. That is the same resolution the warrant's `kind_id_chirho` took.

use anyhow::Result;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_ledger_model_chirho::wire_chirho::validate_ledger_bounded_label_chirho;
use serde::{Deserialize, Serialize};

pub const EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO: &str = "effect-terminal-outcome-v1-chirho";
pub const EFFECT_TERMINAL_KEY_PREFIX_CHIRHO: &str = "cf3-terminal-v1-chirho:";
const EFFECT_TERMINAL_OUTCOME_REF_DOMAIN_CHIRHO: &[u8] =
    b"cairn-effect-terminal-outcome-ref-v1-chirho";
const MAX_EFFECT_TERMINAL_LABEL_BYTES_CHIRHO: usize = 256;

/// A provider observation may close only one of these two states. Transport errors and ambiguous
/// observations have no variant here: they leave the original Hold in doubt for fsck to query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum EffectTerminalDispositionChirho {
    #[serde(rename = "committed-chirho")]
    CommittedChirho { result_ref_chirho: DigestChirho },
    #[serde(rename = "definite-no-effect-chirho")]
    DefiniteNoEffectChirho,
}

/// Signed evidence that one original intent reached one closed provider state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectTerminalOutcomeChirho {
    pub schema_chirho: String,
    pub intent_ref_chirho: DigestChirho,
    pub provider_evidence_ref_chirho: DigestChirho,
    pub disposition_chirho: EffectTerminalDispositionChirho,
    pub sig_chirho: String,
    pub key_id_chirho: String,
}

/// Terminal signing is a distinct injected authority. The carried key id is only an audit label;
/// callers never select trust through it.
pub trait EffectTerminalSignerPortChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String>;
    fn key_id_chirho(&self) -> String;
    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectTerminalWireErrorChirho {
    MalformedChirho {
        detail_chirho: String,
    },
    NonCanonicalBytesChirho,
    UnsupportedSchemaChirho,
    InvalidCoordinateChirho {
        field_chirho: &'static str,
    },
    /// The money log's BOUNDED-IDENTIFIER law refused a free string, with the reason preserved.
    UnboundedIdentifierChirho {
        field_chirho: &'static str,
        reason_chirho: String,
    },
    EmptySignatureChirho,
    EmptyKeyIdChirho,
    SignerChirho {
        detail_chirho: String,
    },
    SignatureUnverifiedChirho,
}

impl std::fmt::Display for EffectTerminalWireErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "malformed effect terminal outcome: {detail_chirho}"
                )
            }
            Self::NonCanonicalBytesChirho => {
                formatter_chirho.write_str("effect terminal outcome bytes are not canonical")
            }
            Self::UnsupportedSchemaChirho => {
                formatter_chirho.write_str("unsupported effect terminal outcome schema")
            }
            Self::InvalidCoordinateChirho { field_chirho } => write!(
                formatter_chirho,
                "invalid effect terminal outcome coordinate: {field_chirho}"
            ),
            Self::UnboundedIdentifierChirho {
                field_chirho,
                reason_chirho,
            } => write!(
                formatter_chirho,
                "effect terminal outcome identifier is unbounded: {field_chirho}: {reason_chirho}"
            ),
            Self::EmptySignatureChirho => {
                formatter_chirho.write_str("effect terminal outcome signature is empty")
            }
            Self::EmptyKeyIdChirho => {
                formatter_chirho.write_str("effect terminal outcome key id is empty")
            }
            Self::SignerChirho { detail_chirho } => write!(
                formatter_chirho,
                "effect terminal outcome signer failed: {detail_chirho}"
            ),
            Self::SignatureUnverifiedChirho => {
                formatter_chirho.write_str("effect terminal outcome signature does not verify")
            }
        }
    }
}

impl std::error::Error for EffectTerminalWireErrorChirho {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectTerminalKeyErrorChirho {
    NotReservedChirho,
    MalformedReservedChirho,
}

impl std::fmt::Display for EffectTerminalKeyErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReservedChirho => {
                formatter_chirho.write_str("key is outside the CF3 terminal namespace")
            }
            Self::MalformedReservedChirho => {
                formatter_chirho.write_str("reserved CF3 terminal key is malformed")
            }
        }
    }
}

impl std::error::Error for EffectTerminalKeyErrorChirho {}

/// A canonical, root-verified outcome paired with both derived identities. Fields stay private so
/// callers cannot construct terminal authority by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEffectTerminalOutcomeChirho {
    outcome_chirho: EffectTerminalOutcomeChirho,
    outcome_ref_chirho: DigestChirho,
    terminal_key_chirho: String,
}

impl VerifiedEffectTerminalOutcomeChirho {
    pub fn outcome_chirho(&self) -> &EffectTerminalOutcomeChirho {
        &self.outcome_chirho
    }

    pub fn outcome_ref_chirho(&self) -> &DigestChirho {
        &self.outcome_ref_chirho
    }

    pub fn terminal_key_chirho(&self) -> &str {
        &self.terminal_key_chirho
    }

    pub fn into_outcome_chirho(self) -> EffectTerminalOutcomeChirho {
        self.outcome_chirho
    }
}

/// Sign-then-attach. Caller-carried signature and key labels are discarded before signing.
pub fn sign_effect_terminal_outcome_chirho(
    mut outcome_chirho: EffectTerminalOutcomeChirho,
    signer_chirho: &dyn EffectTerminalSignerPortChirho,
) -> Result<EffectTerminalOutcomeChirho, EffectTerminalWireErrorChirho> {
    outcome_chirho.sig_chirho.clear();
    outcome_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    validate_effect_terminal_outcome_body_chirho(&outcome_chirho)?;
    if outcome_chirho.key_id_chirho.is_empty()
        || outcome_chirho.key_id_chirho.len() > MAX_EFFECT_TERMINAL_LABEL_BYTES_CHIRHO
    {
        return Err(EffectTerminalWireErrorChirho::EmptyKeyIdChirho);
    }
    let signed_content_chirho =
        effect_terminal_outcome_signed_content_line_chirho(&outcome_chirho)?;
    outcome_chirho.sig_chirho =
        signer_chirho
            .sign_chirho(&signed_content_chirho)
            .map_err(|error_chirho| EffectTerminalWireErrorChirho::SignerChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
    if outcome_chirho.sig_chirho.is_empty()
        || outcome_chirho.sig_chirho.len() > MAX_EFFECT_TERMINAL_LABEL_BYTES_CHIRHO
    {
        return Err(EffectTerminalWireErrorChirho::EmptySignatureChirho);
    }
    Ok(outcome_chirho)
}

pub fn canonical_effect_terminal_outcome_line_chirho(
    outcome_chirho: &EffectTerminalOutcomeChirho,
) -> Result<String, EffectTerminalWireErrorChirho> {
    validate_effect_terminal_outcome_body_chirho(outcome_chirho)?;
    if outcome_chirho.sig_chirho.is_empty()
        || outcome_chirho.sig_chirho.len() > MAX_EFFECT_TERMINAL_LABEL_BYTES_CHIRHO
    {
        return Err(EffectTerminalWireErrorChirho::EmptySignatureChirho);
    }
    if outcome_chirho.key_id_chirho.is_empty()
        || outcome_chirho.key_id_chirho.len() > MAX_EFFECT_TERMINAL_LABEL_BYTES_CHIRHO
    {
        return Err(EffectTerminalWireErrorChirho::EmptyKeyIdChirho);
    }
    serde_json::to_string(outcome_chirho).map_err(|error_chirho| {
        EffectTerminalWireErrorChirho::MalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

/// Canonical signable bytes: the exact outcome with only its detached signature blanked.
pub fn effect_terminal_outcome_signed_content_line_chirho(
    outcome_chirho: &EffectTerminalOutcomeChirho,
) -> Result<String, EffectTerminalWireErrorChirho> {
    validate_effect_terminal_outcome_body_chirho(outcome_chirho)?;
    let mut unsigned_chirho = outcome_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    serde_json::to_string(&unsigned_chirho).map_err(|error_chirho| {
        EffectTerminalWireErrorChirho::MalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

/// Strict parse plus exact reserialization. Alternate JSON spellings never share authority.
pub fn parse_canonical_effect_terminal_outcome_line_chirho(
    line_chirho: &str,
) -> Result<EffectTerminalOutcomeChirho, EffectTerminalWireErrorChirho> {
    let outcome_chirho: EffectTerminalOutcomeChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            EffectTerminalWireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    if canonical_effect_terminal_outcome_line_chirho(&outcome_chirho)?.as_bytes()
        != line_chirho.as_bytes()
    {
        return Err(EffectTerminalWireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(outcome_chirho)
}

pub fn verify_effect_terminal_outcome_line_chirho(
    line_chirho: &str,
    verifier_chirho: &dyn EffectTerminalSignerPortChirho,
) -> Result<VerifiedEffectTerminalOutcomeChirho, EffectTerminalWireErrorChirho> {
    let outcome_chirho = parse_canonical_effect_terminal_outcome_line_chirho(line_chirho)?;
    let signed_content_chirho =
        effect_terminal_outcome_signed_content_line_chirho(&outcome_chirho)?;
    if !verifier_chirho.verify_chirho(&signed_content_chirho, &outcome_chirho.sig_chirho) {
        return Err(EffectTerminalWireErrorChirho::SignatureUnverifiedChirho);
    }
    let outcome_ref_chirho = effect_terminal_outcome_ref_chirho(&outcome_chirho)?;
    let terminal_key_chirho = effect_terminal_key_chirho(&outcome_chirho.intent_ref_chirho)
        .map_err(|_| EffectTerminalWireErrorChirho::InvalidCoordinateChirho {
            field_chirho: "intent_ref_chirho",
        })?;
    Ok(VerifiedEffectTerminalOutcomeChirho {
        outcome_chirho,
        outcome_ref_chirho,
        terminal_key_chirho,
    })
}

/// Content identity binds the full terminal fact while excluding only the detached signature.
pub fn effect_terminal_outcome_ref_chirho(
    outcome_chirho: &EffectTerminalOutcomeChirho,
) -> Result<DigestChirho, EffectTerminalWireErrorChirho> {
    let signed_content_chirho = effect_terminal_outcome_signed_content_line_chirho(outcome_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(EFFECT_TERMINAL_OUTCOME_REF_DOMAIN_CHIRHO);
    hasher_chirho.update(&(signed_content_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(signed_content_chirho.as_bytes());
    Ok(DigestChirho(hasher_chirho.finalize().to_hex().to_string()))
}

/// One terminal coordinate per original intent. Evidence and disposition never enter this key.
pub fn effect_terminal_key_chirho(
    intent_ref_chirho: &DigestChirho,
) -> Result<String, EffectTerminalKeyErrorChirho> {
    if !is_lower_hex_digest_chirho(&intent_ref_chirho.0) {
        return Err(EffectTerminalKeyErrorChirho::MalformedReservedChirho);
    }
    Ok(format!(
        "{EFFECT_TERMINAL_KEY_PREFIX_CHIRHO}{}",
        intent_ref_chirho.0
    ))
}

pub fn is_reserved_effect_terminal_key_chirho(key_chirho: &str) -> bool {
    key_chirho.starts_with(EFFECT_TERMINAL_KEY_PREFIX_CHIRHO)
}

pub fn parse_effect_terminal_key_chirho(
    key_chirho: &str,
) -> Result<DigestChirho, EffectTerminalKeyErrorChirho> {
    let Some(digest_chirho) = key_chirho.strip_prefix(EFFECT_TERMINAL_KEY_PREFIX_CHIRHO) else {
        return Err(EffectTerminalKeyErrorChirho::NotReservedChirho);
    };
    if !is_lower_hex_digest_chirho(digest_chirho) {
        return Err(EffectTerminalKeyErrorChirho::MalformedReservedChirho);
    }
    Ok(DigestChirho(digest_chirho.to_owned()))
}

fn validate_effect_terminal_outcome_body_chirho(
    outcome_chirho: &EffectTerminalOutcomeChirho,
) -> Result<(), EffectTerminalWireErrorChirho> {
    if outcome_chirho.schema_chirho != EFFECT_TERMINAL_OUTCOME_SCHEMA_V1_CHIRHO {
        return Err(EffectTerminalWireErrorChirho::UnsupportedSchemaChirho);
    }
    for (field_chirho, digest_chirho) in [
        ("intent_ref_chirho", &outcome_chirho.intent_ref_chirho.0),
        (
            "provider_evidence_ref_chirho",
            &outcome_chirho.provider_evidence_ref_chirho.0,
        ),
    ] {
        if !is_lower_hex_digest_chirho(digest_chirho) {
            return Err(EffectTerminalWireErrorChirho::InvalidCoordinateChirho { field_chirho });
        }
    }
    if let EffectTerminalDispositionChirho::CommittedChirho { result_ref_chirho } =
        &outcome_chirho.disposition_chirho
    {
        if !is_lower_hex_digest_chirho(&result_ref_chirho.0) {
            return Err(EffectTerminalWireErrorChirho::InvalidCoordinateChirho {
                field_chirho: "disposition_chirho.result_ref_chirho",
            });
        }
    }
    // The two remaining free strings on this object (see the module header's content decision) get
    // the money log's own shape law under this object's declared cap. Emptiness stays with the
    // dedicated refusals that already own it.
    for (field_chirho, value_chirho) in [
        ("key_id_chirho", &outcome_chirho.key_id_chirho),
        ("sig_chirho", &outcome_chirho.sig_chirho),
    ] {
        if value_chirho.is_empty() {
            continue;
        }
        validate_ledger_bounded_label_chirho(
            field_chirho,
            value_chirho,
            MAX_EFFECT_TERMINAL_LABEL_BYTES_CHIRHO,
        )
        .map_err(|error_chirho| {
            EffectTerminalWireErrorChirho::UnboundedIdentifierChirho {
                field_chirho,
                reason_chirho: crate::intent_chirho::unbounded_reason_chirho(&error_chirho),
            }
        })?;
    }
    Ok(())
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
}
