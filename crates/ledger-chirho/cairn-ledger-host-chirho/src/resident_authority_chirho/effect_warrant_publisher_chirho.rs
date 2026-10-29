// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Publish one signed effect WARRANT to the bounded public projection before its money append.
//!
//! A WARRANT ASSERTS ONLY THAT A SIGNED INTENT OR TERMINAL OUTCOME EXISTS. It is never a commit
//! receipt, and no reader may treat its presence as proof that the journal appended anything —
//! see the consumption contract on
//! [`cairn_effect_commit_ledger_chirho::public_evidence_chirho`].
//!
//! Publishing BEFORE the append is deliberate and composes the same order as the CF3 commit
//! coordinator (`cairn-effect-commit-chirho/src/coordinator_chirho.rs`, "never a settlement
//! without its warrant"). The accepted residue of a crash between the two is an ORPHAN warrant
//! that nothing can look up, because every production reader keys its lookup by a ref taken from a
//! record it already found in the journal. The REFUSED state is the reverse: a committed
//! losing-suffix record whose warrant is missing, which GD7 reconciliation cannot compensate at
//! all until recovery runs. Orphan warrants are inert; warrantless settlements are not.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use cairn_effect_commit_chirho::intent_chirho::{
    effect_intent_ref_chirho, verify_effect_intent_line_chirho, EffectIntentSignerPortChirho,
};
use cairn_effect_commit_chirho::minimal_warrant_chirho::{
    canonical_minimal_warrant_line_chirho, minimal_warrant_from_intent_chirho,
    sign_minimal_warrant_chirho,
};
use cairn_effect_commit_chirho::terminal_chirho::{
    verify_effect_terminal_outcome_line_chirho, EffectTerminalSignerPortChirho,
};
use cairn_effect_commit_ledger_chirho::public_evidence_chirho::{
    PublicEffectEvidenceKindChirho, PublicEffectEvidenceRefusalChirho,
    RootPublicEffectEvidenceStoreChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use std::error::Error;
use std::fmt;
use std::path::Path;

/// Why one effect warrant could not be published ahead of its append.
///
/// Every variant refuses the append that would have followed. The reasons stay DISTINCT because a
/// caller must be able to tell a malformed or unsigned line from a coordinate that already binds
/// different bytes; collapsing them would report a forged warrant as a storage fault.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum ResidentEffectWarrantRefusalChirho {
    /// The canonical intent line did not parse, verify, or yield a content ref.
    InvalidIntentWarrantChirho,
    /// The canonical terminal outcome line did not parse, verify, or yield a content ref.
    InvalidTerminalWarrantChirho,
    /// The coordinate already binds DIFFERENT bytes. Warrants are immutable and never rewritten.
    ImmutableCollisionChirho,
    /// The canonical line exceeds the projection's fixed byte bound.
    OversizedWarrantChirho,
    /// The derived content ref is not a well-formed projection coordinate.
    InvalidCoordinateChirho,
    /// The minimal warrant could not be signed at this boundary.
    ///
    /// Distinct from an invalid intent: the intent verified, but no signing authority produced a
    /// warrant. A verify-only root reaches here and REFUSES rather than publishing unsigned bytes.
    ///
    /// The detail is carried because "could not sign" has several causes -- a verification-only
    /// root, an empty key id, a warrant body failing its own coordinate law -- and collapsing them
    /// would hide which one on a money path.
    UnsignableWarrantChirho { detail_chirho: String },
    /// The projection could not be read or written.
    UnavailableChirho { detail_chirho: String },
}

impl fmt::Display for ResidentEffectWarrantRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIntentWarrantChirho => {
                formatter_chirho.write_str("effect intent warrant did not verify")
            }
            Self::InvalidTerminalWarrantChirho => {
                formatter_chirho.write_str("effect terminal warrant did not verify")
            }
            Self::ImmutableCollisionChirho => {
                formatter_chirho.write_str("effect warrant coordinate binds different bytes")
            }
            Self::OversizedWarrantChirho => {
                formatter_chirho.write_str("effect warrant exceeds its fixed bound")
            }
            Self::InvalidCoordinateChirho => {
                formatter_chirho.write_str("effect warrant coordinate is invalid")
            }
            Self::UnsignableWarrantChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect warrant could not be signed: {detail_chirho}"
                )
            }
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "effect warrant projection is unavailable: {detail_chirho}"
                )
            }
        }
    }
}

impl Error for ResidentEffectWarrantRefusalChirho {}

/// Verify the canonical intent line and publish it at its own content ref, before any append.
///
/// The coordinate is recomputed here from the verified content rather than taken from a caller, so
/// the published coordinate is BY CONSTRUCTION the one the GD7 plan reducer recomputes and
/// compares. An unverifiable line refuses without publishing and without appending.
pub(crate) fn publish_effect_intent_warrant_chirho(
    canonical_root_chirho: &Path,
    canonical_intent_line_chirho: &str,
    verifier_chirho: &dyn EffectIntentSignerPortChirho,
) -> Result<DigestChirho, ResidentEffectWarrantRefusalChirho> {
    let verified_chirho =
        verify_effect_intent_line_chirho(canonical_intent_line_chirho, verifier_chirho).map_err(
            |_error_chirho| ResidentEffectWarrantRefusalChirho::InvalidIntentWarrantChirho,
        )?;
    let intent_ref_chirho = effect_intent_ref_chirho(verified_chirho.intent_chirho())
        .map_err(|_error_chirho| ResidentEffectWarrantRefusalChirho::InvalidIntentWarrantChirho)?;
    // NARROWED HERE, and only here. The published bytes are the MINIMAL warrant, never the intent
    // line: the intent's payer-account owner and causer principal are unvalidated Strings that no
    // intent-path law constrains, and this projection has no privacy or GC custody. The warrant
    // carries their domain-separated BINDINGS instead, which is what the reducer's equality checks
    // actually consume. The coordinate stays the intent ref, so the reducer's lookup is unchanged.
    let warrant_chirho = minimal_warrant_from_intent_chirho(verified_chirho.intent_chirho())
        .map_err(|_error_chirho| ResidentEffectWarrantRefusalChirho::InvalidIntentWarrantChirho)?;
    let signed_warrant_chirho = sign_minimal_warrant_chirho(warrant_chirho, verifier_chirho)
        .map_err(
            |error_chirho| ResidentEffectWarrantRefusalChirho::UnsignableWarrantChirho {
                detail_chirho: format!("{error_chirho:?}"),
            },
        )?;
    let warrant_line_chirho = canonical_minimal_warrant_line_chirho(&signed_warrant_chirho)
        .map_err(|_error_chirho| ResidentEffectWarrantRefusalChirho::InvalidIntentWarrantChirho)?;
    store_warrant_chirho(
        canonical_root_chirho,
        PublicEffectEvidenceKindChirho::WarrantChirho,
        &intent_ref_chirho,
        &warrant_line_chirho,
    )?;
    Ok(intent_ref_chirho)
}

/// Verify the canonical terminal outcome line and publish it at its own content ref.
///
/// Same order and same reasoning as the intent warrant: the outcome is a signed FACT about the
/// effect, published before the terminal money append so no settlement lands without it.
pub(crate) fn publish_effect_terminal_warrant_chirho(
    canonical_root_chirho: &Path,
    canonical_terminal_line_chirho: &str,
    verifier_chirho: &dyn EffectTerminalSignerPortChirho,
) -> Result<DigestChirho, ResidentEffectWarrantRefusalChirho> {
    let verified_chirho =
        verify_effect_terminal_outcome_line_chirho(canonical_terminal_line_chirho, verifier_chirho)
            .map_err(|_error_chirho| {
                ResidentEffectWarrantRefusalChirho::InvalidTerminalWarrantChirho
            })?;
    let outcome_ref_chirho = verified_chirho.outcome_ref_chirho().clone();
    store_warrant_chirho(
        canonical_root_chirho,
        PublicEffectEvidenceKindChirho::TerminalChirho,
        &outcome_ref_chirho,
        canonical_terminal_line_chirho,
    )?;
    Ok(outcome_ref_chirho)
}

/// Immutable store-or-match. Identical bytes at the same coordinate are idempotent, so a retried
/// append republishes the same warrant without a second write and without a second journal effect.
fn store_warrant_chirho(
    canonical_root_chirho: &Path,
    kind_chirho: PublicEffectEvidenceKindChirho,
    coordinate_chirho: &DigestChirho,
    canonical_line_chirho: &str,
) -> Result<(), ResidentEffectWarrantRefusalChirho> {
    RootPublicEffectEvidenceStoreChirho::new_chirho(canonical_root_chirho)
        .store_line_chirho(
            kind_chirho,
            &coordinate_chirho.0,
            canonical_line_chirho.as_bytes(),
        )
        .map_err(warrant_refusal_chirho)
}

fn warrant_refusal_chirho(
    error_chirho: PublicEffectEvidenceRefusalChirho,
) -> ResidentEffectWarrantRefusalChirho {
    match error_chirho {
        PublicEffectEvidenceRefusalChirho::InvalidCoordinateChirho => {
            ResidentEffectWarrantRefusalChirho::InvalidCoordinateChirho
        }
        PublicEffectEvidenceRefusalChirho::OversizedLineChirho => {
            ResidentEffectWarrantRefusalChirho::OversizedWarrantChirho
        }
        PublicEffectEvidenceRefusalChirho::ImmutableCollisionChirho => {
            ResidentEffectWarrantRefusalChirho::ImmutableCollisionChirho
        }
        PublicEffectEvidenceRefusalChirho::UnavailableChirho { detail_chirho } => {
            ResidentEffectWarrantRefusalChirho::UnavailableChirho { detail_chirho }
        }
    }
}
