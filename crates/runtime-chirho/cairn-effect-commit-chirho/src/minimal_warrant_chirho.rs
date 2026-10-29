// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The minimal signed effect warrant: the reducer-consumed coordinates of an intent, and nothing
//! identifying.
//!
//! # Why this exists
//!
//! The full canonical intent line carries `payer_account_chirho.owner_chirho` and
//! `AttributionChirho::CauserChirho.principal_chirho`, both unvalidated `String`s. Nothing on the
//! intent path applies a shape law to them — `parse_canonical_effect_intent_line_chirho` is serde
//! plus a canonical-bytes check — while the ledger RECORD path refuses whitespace ("free-text
//! shape") and `@` ("email shape") through `validate_bounded_identifier_chirho`. So publishing the
//! full line put content in a projection that the money log itself would reject, permanently, in an
//! immutable content-addressed store.
//!
//! # What replaces it, and why it is EQUIVALENT rather than weaker
//!
//! Measured at `reducer_chirho.rs:598-626` and `ensure_hold_binding_chirho`, the reducer consumes
//! the two identifying fields ONLY to compare them for equality against the corresponding fields of
//! a losing record it already holds and has already verified. An equality test does not need the
//! value — it needs a binding. So this object carries domain-separated, length-framed digests
//! (`LogIdChirho::digest_chirho`, `AttributionChirho::binding_digest_chirho`) and the reducer
//! recomputes them from the record's own fields. Same verdict on every input; no principal and no
//! account owner ever reach the projection.
//!
//! Everything else the reducer consumes is already a non-identifying coordinate — sequence numbers,
//! digests, a step index, a money amount, a policy ref — and is carried as-is.
//! `original_effect_key_chirho` is carried verbatim because it is a CONSTRAINED coordinate
//! (`validate_original_effect_key_chirho` admits only `cf3-intent-v1-chirho:<digest>` or
//! `cf3-compensation-v1-chirho:<digest>`), and carrying it preserves the reducer's own re-derivation
//! of the control saga id rather than making it trust a value we derived.
//!
//! # Ordering is unchanged
//!
//! A warrant is still published BEFORE the append it warrants, and is still inert without a journal
//! record: every reader resolves its ref from a record it already found. This object narrows WHAT is
//! published, not WHEN.

use crate::intent_chirho::{
    effect_intent_ref_chirho, EffectIntentChirho, EffectIntentSignerPortChirho,
    EffectIntentWireErrorChirho,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_ledger_model_chirho::wire_chirho::{
    validate_ledger_bounded_label_chirho, MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
};
use serde::{Deserialize, Serialize};

pub const MINIMAL_EFFECT_WARRANT_SCHEMA_V1_CHIRHO: &str = "cf3-minimal-effect-warrant-v1-chirho";
const MINIMAL_EFFECT_WARRANT_REF_DOMAIN_CHIRHO: &[u8] =
    b"cairn-minimal-effect-warrant-ref-v1-chirho";
const MAX_MINIMAL_WARRANT_LABEL_BYTES_CHIRHO: usize = 512;

/// One signed warrant: the intent's reducer-consumed coordinates, bound to its authoritative ref.
///
/// EVERY field here is either a content digest, a sequence coordinate, a bounded numeric, or a
/// constrained prefixed key. Adding an identifying field would defeat the object's whole purpose —
/// the `deny_unknown_fields` plus the exhaustive signed-content walk make that a deliberate act.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimalEffectWarrantChirho {
    pub schema_chirho: String,
    /// The authoritative intent this warrant stands for. Recomputed by the reducer from the record.
    pub intent_ref_chirho: DigestChirho,
    /// Journal-cut coordinates: genesis equality plus the predecessor binding.
    pub journal_genesis_digest_chirho: DigestChirho,
    pub tail_seq_chirho: u64,
    pub tail_record_digest_chirho: DigestChirho,
    /// Constrained prefixed key; absent for a forward effect. Never free text.
    pub original_effect_key_chirho: Option<String>,
    /// Content digest of the reversion contract; flows into the plan obligation.
    pub reversion_contract_digest_chirho: DigestChirho,
    pub effect_step_chirho: u32,
    pub amount_chirho: u64,
    /// The STABLE asset-kind id, carried in the clear. It is the ONE plain string here, and it is
    /// not identifying: an asset kind is a low-cardinality label shared by every account of that
    /// kind (the `request_kind_chirho` shape the private-data rule names as safe metadata), never a
    /// principal. The terminal record-law check compares it against `leg.account.kind_id_chirho`,
    /// so a binding digest would buy nothing and cost auditability.
    pub kind_id_chirho: AssetKindIdChirho,
    pub kind_policy_ref_chirho: AssetKindRefChirho,
    /// BINDING, not value: `LogIdChirho::digest_chirho` of the payer account.
    pub payer_account_binding_chirho: String,
    /// BINDING, not value: `AttributionChirho::binding_digest_chirho`.
    pub attribution_binding_chirho: String,
    pub sig_chirho: String,
    pub key_id_chirho: String,
}

/// Project a verified intent down to its warrant. This is the ONLY constructor from an intent, so
/// the narrowing happens in exactly one place.
pub fn minimal_warrant_from_intent_chirho(
    intent_chirho: &EffectIntentChirho,
) -> Result<MinimalEffectWarrantChirho, EffectIntentWireErrorChirho> {
    // The ONE plain string that rides the warrant answers to the money log's own law, HERE, at the
    // single narrowing point — so "an asset kind is safe metadata" is enforced rather than asserted.
    //
    // FIRST, deliberately: the intent door applies the same law to `resolved_price_chirho
    // .kind_id_chirho` under ITS OWN field name, and computing the ref below would run that check.
    // Checking here first means this constructor's refusal names `kind_id_chirho` — the warrant's
    // field — so an arm aimed at the warrant's law cannot be satisfied by the intent's law firing
    // instead. Two independent gates, and each one is provable on its own.
    bounded_warrant_label_chirho(
        "kind_id_chirho",
        &intent_chirho.resolved_price_chirho.kind_id_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    let intent_ref_chirho = effect_intent_ref_chirho(intent_chirho)?;
    Ok(MinimalEffectWarrantChirho {
        schema_chirho: MINIMAL_EFFECT_WARRANT_SCHEMA_V1_CHIRHO.to_owned(),
        intent_ref_chirho,
        journal_genesis_digest_chirho: intent_chirho
            .journal_cut_chirho
            .journal_genesis_digest_chirho
            .clone(),
        tail_seq_chirho: intent_chirho.journal_cut_chirho.tail_seq_chirho,
        tail_record_digest_chirho: intent_chirho
            .journal_cut_chirho
            .tail_record_digest_chirho
            .clone(),
        original_effect_key_chirho: intent_chirho.original_effect_key_chirho.clone(),
        reversion_contract_digest_chirho: intent_chirho.reversion_contract_digest_chirho.clone(),
        effect_step_chirho: intent_chirho.effect_step_chirho,
        amount_chirho: intent_chirho.resolved_price_chirho.amount_chirho,
        kind_id_chirho: intent_chirho.resolved_price_chirho.kind_id_chirho.clone(),
        kind_policy_ref_chirho: intent_chirho
            .resolved_price_chirho
            .kind_policy_ref_chirho
            .clone(),
        payer_account_binding_chirho: intent_chirho.payer_account_chirho.digest_chirho(),
        attribution_binding_chirho: intent_chirho.attribution_chirho.binding_digest_chirho(),
        sig_chirho: String::new(),
        key_id_chirho: String::new(),
    })
}

/// Content identity of a warrant, excluding only the detached signature.
pub fn minimal_warrant_ref_chirho(
    warrant_chirho: &MinimalEffectWarrantChirho,
) -> Result<DigestChirho, EffectIntentWireErrorChirho> {
    let signed_content_chirho = minimal_warrant_signed_content_line_chirho(warrant_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(MINIMAL_EFFECT_WARRANT_REF_DOMAIN_CHIRHO);
    hasher_chirho.update(&(signed_content_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(signed_content_chirho.as_bytes());
    Ok(DigestChirho(hasher_chirho.finalize().to_hex().to_string()))
}

pub fn minimal_warrant_signed_content_line_chirho(
    warrant_chirho: &MinimalEffectWarrantChirho,
) -> Result<String, EffectIntentWireErrorChirho> {
    validate_minimal_warrant_body_chirho(warrant_chirho)?;
    let mut unsigned_chirho = warrant_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    serde_json::to_string(&unsigned_chirho).map_err(|error_chirho| {
        EffectIntentWireErrorChirho::MalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

pub fn canonical_minimal_warrant_line_chirho(
    warrant_chirho: &MinimalEffectWarrantChirho,
) -> Result<String, EffectIntentWireErrorChirho> {
    validate_minimal_warrant_body_chirho(warrant_chirho)?;
    if warrant_chirho.sig_chirho.is_empty()
        || warrant_chirho.sig_chirho.len() > MAX_MINIMAL_WARRANT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptySignatureChirho);
    }
    if warrant_chirho.key_id_chirho.is_empty()
        || warrant_chirho.key_id_chirho.len() > MAX_MINIMAL_WARRANT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptyKeyIdChirho);
    }
    serde_json::to_string(warrant_chirho).map_err(|error_chirho| {
        EffectIntentWireErrorChirho::MalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

pub fn parse_canonical_minimal_warrant_line_chirho(
    line_chirho: &str,
) -> Result<MinimalEffectWarrantChirho, EffectIntentWireErrorChirho> {
    let warrant_chirho: MinimalEffectWarrantChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            EffectIntentWireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    if canonical_minimal_warrant_line_chirho(&warrant_chirho)?.as_bytes() != line_chirho.as_bytes()
    {
        return Err(EffectIntentWireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(warrant_chirho)
}

/// Every field is a bounded, non-identifying coordinate. This walk is what keeps that true: a future
/// field that is free text has to pass through here to ship.
fn validate_minimal_warrant_body_chirho(
    warrant_chirho: &MinimalEffectWarrantChirho,
) -> Result<(), EffectIntentWireErrorChirho> {
    // EXHAUSTIVE destructure (no `..`): adding a wire field without classifying it here is a
    // COMPILE error, so an identifying field cannot slip into the projection unreviewed.
    let MinimalEffectWarrantChirho {
        schema_chirho,
        intent_ref_chirho,
        journal_genesis_digest_chirho,
        tail_seq_chirho: _tail_seq_chirho,
        tail_record_digest_chirho,
        original_effect_key_chirho,
        reversion_contract_digest_chirho,
        effect_step_chirho: _effect_step_chirho,
        amount_chirho: _amount_chirho,
        kind_id_chirho,
        kind_policy_ref_chirho,
        payer_account_binding_chirho,
        attribution_binding_chirho,
        sig_chirho,
        key_id_chirho,
    } = warrant_chirho;
    if schema_chirho != MINIMAL_EFFECT_WARRANT_SCHEMA_V1_CHIRHO {
        return Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho {
            field_chirho: "schema_chirho",
        });
    }
    for (field_chirho, digest_chirho) in [
        ("intent_ref_chirho", &intent_ref_chirho.0),
        (
            "journal_genesis_digest_chirho",
            &journal_genesis_digest_chirho.0,
        ),
        ("tail_record_digest_chirho", &tail_record_digest_chirho.0),
        (
            "reversion_contract_digest_chirho",
            &reversion_contract_digest_chirho.0,
        ),
        ("kind_policy_ref_chirho", &kind_policy_ref_chirho.0 .0),
        ("payer_account_binding_chirho", payer_account_binding_chirho),
        ("attribution_binding_chirho", attribution_binding_chirho),
    ] {
        if !is_lower_hex_digest_chirho(digest_chirho) {
            return Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho { field_chirho });
        }
    }
    // THE LAW, not a length bound: an asset kind is a low-cardinality label, and the check that says
    // so is the money log's own — control characters, whitespace (free-text shape) and '@' (email
    // shape) are refused, at the identifier cap the record path uses for `leg.account.kind_id`.
    bounded_warrant_label_chirho(
        "kind_id_chirho",
        &kind_id_chirho.0,
        MAX_LEDGER_IDENTIFIER_BYTES_CHIRHO,
    )?;
    // The signature and key label reach disk verbatim inside this line; they answer to the same
    // shape law under this object's own wider cap. A hex or base64 signature satisfies it.
    // EMPTINESS is deliberately left to the dedicated `EmptyKeyIdChirho` / `EmptySignatureChirho`
    // refusals that already own it — a signing path legitimately walks through here with the
    // signature cleared, and shadowing a precise refusal with a general one is how a diagnosis gets
    // lost.
    for (field_chirho, value_chirho) in
        [("key_id_chirho", key_id_chirho), ("sig_chirho", sig_chirho)]
    {
        if !value_chirho.is_empty() {
            bounded_warrant_label_chirho(
                field_chirho,
                value_chirho,
                MAX_MINIMAL_WARRANT_LABEL_BYTES_CHIRHO,
            )?;
        }
    }
    if let Some(original_effect_key_chirho) = original_effect_key_chirho {
        if crate::intent_chirho::parse_effect_intent_key_chirho(original_effect_key_chirho).is_err()
            && crate::intent_chirho::parse_effect_compensation_key_chirho(
                original_effect_key_chirho,
            )
            .is_err()
        {
            return Err(EffectIntentWireErrorChirho::InvalidCoordinateChirho {
                field_chirho: "original_effect_key_chirho",
            });
        }
    }
    Ok(())
}

/// Apply the money log's bounded-identifier law to a warrant string, preserving the REASON.
fn bounded_warrant_label_chirho(
    field_chirho: &'static str,
    value_chirho: &str,
    max_bytes_chirho: usize,
) -> Result<(), EffectIntentWireErrorChirho> {
    validate_ledger_bounded_label_chirho(field_chirho, value_chirho, max_bytes_chirho).map_err(
        |error_chirho| EffectIntentWireErrorChirho::UnboundedIdentifierChirho {
            field_chirho,
            reason_chirho: crate::intent_chirho::unbounded_reason_chirho(&error_chirho),
        },
    )
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
}

/// Sign-then-attach, mirroring the intent door. Caller-carried signature and key labels are
/// discarded before signing, so a caller cannot smuggle bytes past the signature.
pub fn sign_minimal_warrant_chirho(
    mut warrant_chirho: MinimalEffectWarrantChirho,
    signer_chirho: &dyn EffectIntentSignerPortChirho,
) -> Result<MinimalEffectWarrantChirho, EffectIntentWireErrorChirho> {
    warrant_chirho.sig_chirho.clear();
    warrant_chirho.key_id_chirho = signer_chirho.key_id_chirho();
    validate_minimal_warrant_body_chirho(&warrant_chirho)?;
    if warrant_chirho.key_id_chirho.is_empty()
        || warrant_chirho.key_id_chirho.len() > MAX_MINIMAL_WARRANT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptyKeyIdChirho);
    }
    let signed_content_chirho = minimal_warrant_signed_content_line_chirho(&warrant_chirho)?;
    warrant_chirho.sig_chirho =
        signer_chirho
            .sign_chirho(&signed_content_chirho)
            .map_err(|error_chirho| EffectIntentWireErrorChirho::SignerChirho {
                detail_chirho: error_chirho.to_string(),
            })?;
    if warrant_chirho.sig_chirho.is_empty()
        || warrant_chirho.sig_chirho.len() > MAX_MINIMAL_WARRANT_LABEL_BYTES_CHIRHO
    {
        return Err(EffectIntentWireErrorChirho::EmptySignatureChirho);
    }
    Ok(warrant_chirho)
}

/// Parse, verify the signature, and hand back the warrant. Same verification SHAPE as the intent
/// door it replaces: canonical bytes, then a signature over the signed content.
pub fn verify_minimal_warrant_line_chirho(
    line_chirho: &str,
    verifier_chirho: &dyn EffectIntentSignerPortChirho,
) -> Result<MinimalEffectWarrantChirho, EffectIntentWireErrorChirho> {
    let warrant_chirho = parse_canonical_minimal_warrant_line_chirho(line_chirho)?;
    let signed_content_chirho = minimal_warrant_signed_content_line_chirho(&warrant_chirho)?;
    if !verifier_chirho.verify_chirho(&signed_content_chirho, &warrant_chirho.sig_chirho) {
        return Err(EffectIntentWireErrorChirho::SignatureUnverifiedChirho);
    }
    Ok(warrant_chirho)
}
