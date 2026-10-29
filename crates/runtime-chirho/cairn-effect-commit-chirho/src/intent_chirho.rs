// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Canonical signed CF3 effect intent and its reserved journal key.
//!
//! The journal door, not ledger admission, owns the namespace law. Generic append refuses every
//! key beginning with [`EFFECT_INTENT_KEY_PREFIX_CHIRHO`], including malformed tails. The dedicated
//! path verifies these canonical bytes against an injected root and recomputes the key before it
//! invokes the ordinary admission path. The frozen ledger record therefore needs no new field.

use anyhow::Result;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, HlcChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    validate_ledger_bounded_label_chirho, WireErrorChirho, MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
};
use cairn_undo_plan_chirho::plan_chirho::UndoDoorKeyChirho;
use serde::{Deserialize, Serialize};

pub const EFFECT_INTENT_SCHEMA_V1_CHIRHO: &str = "effect-intent-v1-chirho";
pub const EFFECT_INTENT_KEY_PREFIX_CHIRHO: &str = "cf3-intent-v1-chirho:";
pub const EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO: &str = "cf3-compensation-v1-chirho:";
const EFFECT_INTENT_KEY_DOMAIN_CHIRHO: &[u8] = b"cairn-effect-intent-key-v1-chirho";
const EFFECT_COMPENSATION_KEY_DOMAIN_CHIRHO: &[u8] = b"cairn-effect-compensation-key-v1-chirho";
const MAX_EFFECT_INTENT_EVIDENCE_REFS_CHIRHO: usize = 64;
const MAX_EFFECT_INTENT_LABEL_BYTES_CHIRHO: usize = 256;

/// The engine-issued journal cut that makes intent age authoritative.
///
/// Re-stamping a request necessarily changes this signed content and therefore changes K. A
/// same-K replay always names the original cut and HLC whose age the journal can verify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIntentJournalCutChirho {
    pub journal_genesis_digest_chirho: DigestChirho,
    pub tail_seq_chirho: u64,
    pub tail_record_digest_chirho: DigestChirho,
    pub tail_hlc_chirho: HlcChirho,
}

/// One engine-authored effect intent.
///
/// Request bytes cannot choose attribution, door authority, price, reversion policy, or the
/// journal cut. The caller supplies this fully-derived shape to the injected signer only after
/// resolving those coordinates from verified runtime evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIntentChirho {
    pub schema_chirho: String,
    pub journal_cut_chirho: EffectIntentJournalCutChirho,
    pub contract_set_digest_chirho: DigestChirho,
    pub door_chirho: UndoDoorKeyChirho,
    pub reversion_contract_digest_chirho: DigestChirho,
    pub request_ref_chirho: DigestChirho,
    pub request_context_ref_chirho: DigestChirho,
    pub evidence_refs_chirho: Vec<DigestChirho>,
    pub resolved_price_chirho: AssetOpChirho,
    /// Exact account whose spendable balance funds the reservation. The composition root derives
    /// it from verified billing context; the journal door never accepts a caller-selected payer.
    pub payer_account_chirho: AccountIdChirho,
    pub effect_step_chirho: u32,
    pub attribution_chirho: AttributionChirho,
    /// Present only for a compensation intent and bound to the ORIGINAL forward-effect K. The
    /// reviewed reversion-contract digest above remains the disposition authority; this field is
    /// only the one-compensation-per-original relation, not a second disposition taxonomy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_effect_key_chirho: Option<String>,
    pub sig_chirho: String,
    pub key_id_chirho: String,
}

/// Intent signing is an injected authority. A distinct instance must back this family; the
/// self-declared key id remains a label and never selects trust.
pub trait EffectIntentSignerPortChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String>;
    fn key_id_chirho(&self) -> String;
    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectIntentWireErrorChirho {
    MalformedChirho {
        detail_chirho: String,
    },
    NonCanonicalBytesChirho,
    UnsupportedSchemaChirho,
    InvalidCoordinateChirho {
        field_chirho: &'static str,
    },
    /// The money log's own BOUNDED-IDENTIFIER law refused a free string. Carries the field AND the
    /// reason: collapsing the causes of a refusal into one nameless variant costs a diagnosis, and
    /// this family already paid for that once.
    UnboundedIdentifierChirho {
        field_chirho: &'static str,
        reason_chirho: String,
    },
    EvidenceOrderChirho,
    FixedPriceRoundingChirho,
    EmptySignatureChirho,
    EmptyKeyIdChirho,
    SignerChirho {
        detail_chirho: String,
    },
    SignatureUnverifiedChirho,
}

impl std::fmt::Display for EffectIntentWireErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedChirho { detail_chirho } => {
                write!(formatter_chirho, "malformed effect intent: {detail_chirho}")
            }
            Self::NonCanonicalBytesChirho => {
                write!(formatter_chirho, "effect intent bytes are not canonical")
            }
            Self::UnsupportedSchemaChirho => {
                write!(formatter_chirho, "unsupported effect intent schema")
            }
            Self::InvalidCoordinateChirho { field_chirho } => {
                write!(
                    formatter_chirho,
                    "invalid effect intent coordinate: {field_chirho}"
                )
            }
            Self::UnboundedIdentifierChirho {
                field_chirho,
                reason_chirho,
            } => {
                write!(
                    formatter_chirho,
                    "effect intent identifier is unbounded: {field_chirho}: {reason_chirho}"
                )
            }
            Self::EvidenceOrderChirho => {
                write!(
                    formatter_chirho,
                    "effect evidence refs must be strictly sorted and unique"
                )
            }
            Self::FixedPriceRoundingChirho => {
                write!(
                    formatter_chirho,
                    "resolved effect price must use exact rounding"
                )
            }
            Self::EmptySignatureChirho => {
                write!(formatter_chirho, "effect intent signature is empty")
            }
            Self::EmptyKeyIdChirho => write!(formatter_chirho, "effect intent key id is empty"),
            Self::SignerChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect intent signer failed: {detail_chirho}"
                )
            }
            Self::SignatureUnverifiedChirho => {
                write!(formatter_chirho, "effect intent signature does not verify")
            }
        }
    }
}

impl std::error::Error for EffectIntentWireErrorChirho {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectIntentKeyErrorChirho {
    NotReservedChirho,
    MalformedReservedChirho,
}

impl std::fmt::Display for EffectIntentKeyErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReservedChirho => {
                write!(formatter_chirho, "key is outside the CF3 intent namespace")
            }
            Self::MalformedReservedChirho => {
                write!(formatter_chirho, "reserved CF3 intent key is malformed")
            }
        }
    }
}

impl std::error::Error for EffectIntentKeyErrorChirho {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCompensationKeyErrorChirho {
    NotReservedChirho,
    MalformedReservedChirho,
    InvalidOriginalEffectKeyChirho,
}

impl std::fmt::Display for EffectCompensationKeyErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReservedChirho => {
                write!(
                    formatter_chirho,
                    "key is outside the CF3 compensation namespace"
                )
            }
            Self::MalformedReservedChirho => {
                write!(
                    formatter_chirho,
                    "reserved CF3 compensation key is malformed"
                )
            }
            Self::InvalidOriginalEffectKeyChirho => {
                write!(
                    formatter_chirho,
                    "original effect key is not a verified CF3 coordinate"
                )
            }
        }
    }
}

impl std::error::Error for EffectCompensationKeyErrorChirho {}

/// A canonical, root-verified intent paired with its recomputed reserved key. Fields stay private
/// so a caller cannot construct verification evidence by hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEffectIntentChirho {
    intent_chirho: EffectIntentChirho,
    key_chirho: String,
}

impl VerifiedEffectIntentChirho {
    pub fn intent_chirho(&self) -> &EffectIntentChirho {
        &self.intent_chirho
    }

    pub fn key_chirho(&self) -> &str {
        &self.key_chirho
    }

    pub fn into_intent_chirho(self) -> EffectIntentChirho {
        self.intent_chirho
    }
}

/// Sign-then-attach. Any caller-carried signature or key label is discarded before signing.
pub fn sign_effect_intent_chirho(
    mut intent_chirho: EffectIntentChirho,
    signer_chirho: &dyn EffectIntentSignerPortChirho,
) -> Result<EffectIntentChirho, EffectIntentWireErrorChirho> {
    intent_chirho.sig_chirho.clear();
    intent_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    validate_effect_intent_body_chirho(&intent_chirho)?;
    if intent_chirho.key_id_chirho.is_empty()
        || intent_chirho.key_id_chirho.len() > MAX_EFFECT_INTENT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptyKeyIdChirho);
    }
    let signed_content_chirho = effect_intent_signed_content_line_chirho(&intent_chirho)?;
    intent_chirho.sig_chirho =
        signer_chirho
            .sign_chirho(&signed_content_chirho)
            .map_err(|error_chirho| EffectIntentWireErrorChirho::SignerChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
    if intent_chirho.sig_chirho.is_empty()
        || intent_chirho.sig_chirho.len() > MAX_EFFECT_INTENT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptySignatureChirho);
    }
    Ok(intent_chirho)
}

/// Emit the one canonical signed intent line (without a trailing LF).
pub fn canonical_effect_intent_line_chirho(
    intent_chirho: &EffectIntentChirho,
) -> Result<String, EffectIntentWireErrorChirho> {
    validate_effect_intent_body_chirho(intent_chirho)?;
    if intent_chirho.sig_chirho.is_empty()
        || intent_chirho.sig_chirho.len() > MAX_EFFECT_INTENT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptySignatureChirho);
    }
    if intent_chirho.key_id_chirho.is_empty()
        || intent_chirho.key_id_chirho.len() > MAX_EFFECT_INTENT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptyKeyIdChirho);
    }
    serde_json::to_string(intent_chirho).map_err(|error_chirho| {
        EffectIntentWireErrorChirho::MalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

/// Canonical signable bytes: the exact intent with only the detached signature blanked.
pub fn effect_intent_signed_content_line_chirho(
    intent_chirho: &EffectIntentChirho,
) -> Result<String, EffectIntentWireErrorChirho> {
    validate_effect_intent_body_chirho(intent_chirho)?;
    let mut unsigned_chirho = intent_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    serde_json::to_string(&unsigned_chirho).map_err(|error_chirho| {
        EffectIntentWireErrorChirho::MalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

/// Strict parse plus exact reserialization. Whitespace, reorder, unknown/duplicate fields, or
/// trailing bytes produce a different content identity and therefore refuse.
pub fn parse_canonical_effect_intent_line_chirho(
    line_chirho: &str,
) -> Result<EffectIntentChirho, EffectIntentWireErrorChirho> {
    let intent_chirho: EffectIntentChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            EffectIntentWireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    if canonical_effect_intent_line_chirho(&intent_chirho)?.as_bytes() != line_chirho.as_bytes() {
        return Err(EffectIntentWireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(intent_chirho)
}

/// Verify canonical bytes against the injected root, then derive K from the verified signed
/// content. Trust never comes from the record's self-declared key label.
pub fn verify_effect_intent_line_chirho(
    line_chirho: &str,
    verifier_chirho: &dyn EffectIntentSignerPortChirho,
) -> Result<VerifiedEffectIntentChirho, EffectIntentWireErrorChirho> {
    let intent_chirho = parse_canonical_effect_intent_line_chirho(line_chirho)?;
    let signed_content_chirho = effect_intent_signed_content_line_chirho(&intent_chirho)?;
    if !verifier_chirho.verify_chirho(&signed_content_chirho, &intent_chirho.sig_chirho) {
        return Err(EffectIntentWireErrorChirho::SignatureUnverifiedChirho);
    }
    let key_chirho = effect_intent_key_chirho(&intent_chirho)?;
    Ok(VerifiedEffectIntentChirho {
        intent_chirho,
        key_chirho,
    })
}

/// The intent ref is a domain-separated digest of the FULL signable content. The detached
/// signature is deliberately excluded, so resigning identical authority content cannot fork K.
pub fn effect_intent_ref_chirho(
    intent_chirho: &EffectIntentChirho,
) -> Result<DigestChirho, EffectIntentWireErrorChirho> {
    let signed_content_chirho = effect_intent_signed_content_line_chirho(intent_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(EFFECT_INTENT_KEY_DOMAIN_CHIRHO);
    hasher_chirho.update(&(signed_content_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(signed_content_chirho.as_bytes());
    Ok(DigestChirho(hasher_chirho.finalize().to_hex().to_string()))
}

pub fn effect_intent_key_chirho(
    intent_chirho: &EffectIntentChirho,
) -> Result<String, EffectIntentWireErrorChirho> {
    Ok(format!(
        "{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{}",
        effect_intent_ref_chirho(intent_chirho)?.0
    ))
}

/// Namespace recognition is intentionally prefix-only across forward and compensation intents.
/// The generic journal door rejects malformed reserved tails too; parsing is exclusively each
/// dedicated verified path's responsibility.
pub fn is_reserved_effect_intent_key_chirho(key_chirho: &str) -> bool {
    key_chirho.starts_with(EFFECT_INTENT_KEY_PREFIX_CHIRHO)
        || is_reserved_effect_compensation_key_chirho(key_chirho)
}

pub fn parse_effect_intent_key_chirho(
    key_chirho: &str,
) -> Result<DigestChirho, EffectIntentKeyErrorChirho> {
    let Some(digest_chirho) = key_chirho.strip_prefix(EFFECT_INTENT_KEY_PREFIX_CHIRHO) else {
        return Err(EffectIntentKeyErrorChirho::NotReservedChirho);
    };
    if !is_lower_hex_digest_chirho(digest_chirho) {
        return Err(EffectIntentKeyErrorChirho::MalformedReservedChirho);
    }
    Ok(DigestChirho(digest_chirho.to_owned()))
}

/// One compensation coordinate per ORIGINAL committed effect K. Rollback event, plan, evidence,
/// request, and cut are deliberately excluded so a second rollback cannot mint a second inverse.
pub fn effect_compensation_key_chirho(
    original_effect_key_chirho: &str,
) -> Result<String, EffectCompensationKeyErrorChirho> {
    validate_original_effect_key_chirho(original_effect_key_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(EFFECT_COMPENSATION_KEY_DOMAIN_CHIRHO);
    hasher_chirho.update(&(original_effect_key_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(original_effect_key_chirho.as_bytes());
    Ok(format!(
        "{EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO}{}",
        hasher_chirho.finalize().to_hex()
    ))
}

/// Prefix-only recognition lets every generic door reject malformed reserved tails too.
pub fn is_reserved_effect_compensation_key_chirho(key_chirho: &str) -> bool {
    key_chirho.starts_with(EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO)
}

pub fn parse_effect_compensation_key_chirho(
    key_chirho: &str,
) -> Result<DigestChirho, EffectCompensationKeyErrorChirho> {
    let Some(digest_chirho) = key_chirho.strip_prefix(EFFECT_COMPENSATION_KEY_PREFIX_CHIRHO) else {
        return Err(EffectCompensationKeyErrorChirho::NotReservedChirho);
    };
    if !is_lower_hex_digest_chirho(digest_chirho) {
        return Err(EffectCompensationKeyErrorChirho::MalformedReservedChirho);
    }
    Ok(DigestChirho(digest_chirho.to_owned()))
}

fn validate_original_effect_key_chirho(
    key_chirho: &str,
) -> Result<(), EffectCompensationKeyErrorChirho> {
    if parse_effect_intent_key_chirho(key_chirho).is_ok()
        || parse_effect_compensation_key_chirho(key_chirho).is_ok()
    {
        return Ok(());
    }
    Err(EffectCompensationKeyErrorChirho::InvalidOriginalEffectKeyChirho)
}

fn validate_effect_intent_body_chirho(
    intent_chirho: &EffectIntentChirho,
) -> Result<(), EffectIntentWireErrorChirho> {
    if intent_chirho.schema_chirho != EFFECT_INTENT_SCHEMA_V1_CHIRHO {
        return Err(EffectIntentWireErrorChirho::UnsupportedSchemaChirho);
    }
    for (field_chirho, digest_chirho) in [
        (
            "journal_cut.journal_genesis_digest_chirho",
            &intent_chirho
                .journal_cut_chirho
                .journal_genesis_digest_chirho
                .0,
        ),
        (
            "journal_cut.tail_record_digest_chirho",
            &intent_chirho.journal_cut_chirho.tail_record_digest_chirho.0,
        ),
        (
            "contract_set_digest_chirho",
            &intent_chirho.contract_set_digest_chirho.0,
        ),
        (
            "door.effect_node_chirho",
            &intent_chirho.door_chirho.effect_node_chirho.0,
        ),
        (
            "door.capability_fingerprint_chirho",
            &intent_chirho.door_chirho.capability_fingerprint_chirho.0,
        ),
        (
            "reversion_contract_digest_chirho",
            &intent_chirho.reversion_contract_digest_chirho.0,
        ),
        ("request_ref_chirho", &intent_chirho.request_ref_chirho.0),
        (
            "request_context_ref_chirho",
            &intent_chirho.request_context_ref_chirho.0,
        ),
    ] {
        if !is_lower_hex_digest_chirho(digest_chirho) {
            return Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho { field_chirho });
        }
    }
    if intent_chirho.evidence_refs_chirho.len() > MAX_EFFECT_INTENT_EVIDENCE_REFS_CHIRHO
        || intent_chirho
            .evidence_refs_chirho
            .iter()
            .any(|digest_chirho| !is_lower_hex_digest_chirho(&digest_chirho.0))
    {
        return Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho {
            field_chirho: "evidence_refs_chirho",
        });
    }
    if intent_chirho
        .evidence_refs_chirho
        .windows(2)
        .any(|pair_chirho| pair_chirho[0] >= pair_chirho[1])
    {
        return Err(EffectIntentWireErrorChirho::EvidenceOrderChirho);
    }
    if intent_chirho.resolved_price_chirho.rounding_chirho != RoundingChirho::ExactChirho {
        return Err(EffectIntentWireErrorChirho::FixedPriceRoundingChirho);
    }
    if intent_chirho.payer_account_chirho.kind_id_chirho
        != intent_chirho.resolved_price_chirho.kind_id_chirho
    {
        return Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho {
            field_chirho: "payer_account_chirho.kind_id_chirho",
        });
    }
    if let Some(original_effect_key_chirho) = &intent_chirho.original_effect_key_chirho {
        validate_original_effect_key_chirho(original_effect_key_chirho).map_err(|_| {
            EffectIntentWireErrorChirho::InvalidCoordinateChirho {
                field_chirho: "original_effect_key_chirho",
            }
        })?;
    }
    validate_effect_intent_identifier_law_chirho(intent_chirho)?;
    Ok(())
}

/// The money log's OWN bounded-identifier law, applied at the intent door.
///
/// # Why here, and why it is not a new law
///
/// These exact strings become `account_chirho` and `attribution.principal_chirho` on a ledger
/// record, where `validate_bounded_identifier_chirho` has always refused control characters,
/// whitespace ("free-text shape") and `@` ("email shape"). The intent path applied NO shape law, so
/// the same value the money log refuses could be signed, canonically emitted, and — because a
/// warrant is published BEFORE the append it warrants — left permanently in an immutable,
/// content-addressed store by an intent the ledger was always going to reject.
///
/// Applying it here refuses strictly EARLIER something that must fail later anyway. It is not a new
/// restriction on what can be recorded: an intent that fails this check could never have become a
/// record. It is the removal of a window in which such an intent's identifiers reach disk.
///
/// This is also what closes the CF3 evidence site. That store retains the FULL canonical intent line
/// deliberately — `reconcile_in_doubt_chirho` reloads it, re-verifies it, and hands the rebuilt
/// `VerifiedEffectIntentChirho` to `query_by_key_chirho` to close an in-doubt Hold, so a minimal
/// projection cannot stand in for it there. The line stays whole; what changes is that it can no
/// longer carry a shape the money log itself would refuse.
fn validate_effect_intent_identifier_law_chirho(
    intent_chirho: &EffectIntentChirho,
) -> Result<(), EffectIntentWireErrorChirho> {
    let AccountIdChirho {
        owner_chirho,
        kind_id_chirho,
    } = &intent_chirho.payer_account_chirho;
    bounded_intent_identifier_chirho(
        "payer_account_chirho.owner_chirho",
        owner_chirho,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    bounded_intent_identifier_chirho(
        "payer_account_chirho.kind_id_chirho",
        &kind_id_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    bounded_intent_identifier_chirho(
        "resolved_price_chirho.kind_id_chirho",
        &intent_chirho.resolved_price_chirho.kind_id_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    // EXHAUSTIVE match (no `_`): a new attribution variant carrying a string has to be classified
    // here to compile, the same idiom the record wire law uses.
    match &intent_chirho.attribution_chirho {
        AttributionChirho::CauserChirho { principal_chirho } => bounded_intent_identifier_chirho(
            "attribution_chirho.principal_chirho",
            principal_chirho,
            MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
        )?,
        AttributionChirho::PlatformChirho => {}
        AttributionChirho::PolicyChirho { policy_ref_chirho } => bounded_intent_identifier_chirho(
            "attribution_chirho.policy_ref_chirho",
            &policy_ref_chirho.0,
            MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
        )?,
    }
    // Signature and key label are the remaining free strings that reach disk verbatim. The key id
    // is an audit label and stays readable; the detached signature is opaque but is still bytes we
    // persist, so it answers to the same shape law under this object's own wider cap.
    //
    // EMPTINESS is deliberately NOT this law's business. The signing flow validates an intent whose
    // signature is cleared and whose key label is not yet set — refusing empty here would make a
    // lawful intent unsignable, and the dedicated `EmptySignatureChirho` / `EmptyKeyIdChirho`
    // refusals already own that case with a precise name.
    for (field_chirho, value_chirho) in [
        ("key_id_chirho", &intent_chirho.key_id_chirho),
        ("sig_chirho", &intent_chirho.sig_chirho),
    ] {
        if !value_chirho.is_empty() {
            bounded_intent_identifier_chirho(
                field_chirho,
                value_chirho,
                MAX_EFFECT_INTENT_LABEL_BYTES_CHIRHO,
            )?;
        }
    }
    Ok(())
}

/// Adapt the ledger's refusal into this family's typed error, preserving the REASON.
fn bounded_intent_identifier_chirho(
    field_chirho: &'static str,
    value_chirho: &str,
    max_bytes_chirho: usize,
) -> Result<(), EffectIntentWireErrorChirho> {
    validate_ledger_bounded_label_chirho(field_chirho, value_chirho, max_bytes_chirho).map_err(
        |error_chirho| EffectIntentWireErrorChirho::UnboundedIdentifierChirho {
            field_chirho,
            reason_chirho: unbounded_reason_chirho(&error_chirho),
        },
    )
}

/// The ledger law's REASON, carried across the crate boundary rather than collapsed. Shared by the
/// three CF3 wire objects that apply the law, so there is one adapter and not three copies.
pub(crate) fn unbounded_reason_chirho(error_chirho: &WireErrorChirho) -> String {
    match error_chirho {
        WireErrorChirho::UnboundedIdentifierChirho { reason_chirho, .. } => {
            (*reason_chirho).to_owned()
        }
        other_chirho => format!("{other_chirho:?}"),
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
}
