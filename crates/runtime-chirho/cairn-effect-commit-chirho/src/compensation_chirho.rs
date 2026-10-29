// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! CF3 compensation authorization and the one-coordinate lineage law.
//!
//! This substrate is dormant until CF5 P2 supplies the real authorization view and custody root.
//! The view derives lineage facts from verified evidence; app/caller bytes carry no depth or
//! breaker switch. The leaf validates those facts before it can mint an opaque journal-door token.

use crate::intent_chirho::{
    effect_compensation_key_chirho, effect_intent_ref_chirho, parse_effect_compensation_key_chirho,
    verify_effect_intent_line_chirho, EffectIntentSignerPortChirho, VerifiedEffectIntentChirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompensationBreakerVerdictChirho {
    PermittedChirho,
    TrippedChirho { detail_chirho: String },
}

/// Facts derived by the injected authority from the verified original effect, reviewed undo plan,
/// lineage evidence, and durable breaker state. The candidate intent carries none of these knobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompensationAuthorizationFactsChirho {
    original_effect_key_chirho: String,
    lineage_root_key_chirho: String,
    next_depth_chirho: u16,
    max_depth_chirho: u16,
    breaker_verdict_chirho: CompensationBreakerVerdictChirho,
}

impl CompensationAuthorizationFactsChirho {
    pub fn new_chirho(
        original_effect_key_chirho: String,
        lineage_root_key_chirho: String,
        next_depth_chirho: u16,
        max_depth_chirho: u16,
        breaker_verdict_chirho: CompensationBreakerVerdictChirho,
    ) -> Self {
        Self {
            original_effect_key_chirho,
            lineage_root_key_chirho,
            next_depth_chirho,
            max_depth_chirho,
            breaker_verdict_chirho,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompensationAuthorizationViewErrorChirho {
    UnavailableChirho { detail_chirho: String },
    RefusedChirho { detail_chirho: String },
}

impl std::fmt::Display for CompensationAuthorizationViewErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnavailableChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "compensation authority unavailable: {detail_chirho}"
                )
            }
            Self::RefusedChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "compensation authority refused: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for CompensationAuthorizationViewErrorChirho {}

pub trait CompensationAuthorizationViewChirho {
    fn derive_chirho(
        &self,
        candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompensationPendingReasonChirho {
    DepthExceededChirho {
        next_depth_chirho: u16,
        max_depth_chirho: u16,
    },
    CircuitBreakerTrippedChirho {
        detail_chirho: String,
    },
}

/// Typed fail-closed result. The reviewed undo plan retains the remediation obligation while no
/// Hold, provider call, or money append is permitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompensationPendingManualChirho {
    pub original_effect_key_chirho: String,
    pub lineage_root_key_chirho: String,
    pub reason_chirho: CompensationPendingReasonChirho,
}

/// Opaque capability proving the exact signed compensation intent passed lineage, depth, and
/// breaker authorization. Public accessors expose coordinates but construction remains private.
/// This capability does not bind a winner term today. Current-term authority is derived inside
/// the resident actor command operation and checked separately by the sink fence; the historical
/// term on a GD7 obligation is never substituted for that live authority coordinate.
///
/// Any winner-term coordinate bound into this capability must be the current elected term at
/// authorization time, never the historical reconciliation term carried by a GD7 losing-effect
/// obligation. They are different coordinates. Binding the historical term here would make the
/// sink fence refuse every legitimate compensation while its safety arms remain green.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEffectCompensationChirho {
    intent_ref_chirho: DigestChirho,
    compensation_key_chirho: String,
    control_saga_id_chirho: DigestChirho,
    original_effect_key_chirho: String,
    lineage_root_key_chirho: String,
    next_depth_chirho: u16,
    max_depth_chirho: u16,
}

impl VerifiedEffectCompensationChirho {
    pub fn intent_ref_chirho(&self) -> &DigestChirho {
        &self.intent_ref_chirho
    }

    pub fn compensation_key_chirho(&self) -> &str {
        &self.compensation_key_chirho
    }

    pub fn control_saga_id_chirho(&self) -> &DigestChirho {
        &self.control_saga_id_chirho
    }

    pub fn original_effect_key_chirho(&self) -> &str {
        &self.original_effect_key_chirho
    }

    pub fn lineage_root_key_chirho(&self) -> &str {
        &self.lineage_root_key_chirho
    }

    pub fn next_depth_chirho(&self) -> u16 {
        self.next_depth_chirho
    }

    pub fn max_depth_chirho(&self) -> u16 {
        self.max_depth_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCompensationAuthorizationOutcomeChirho {
    AuthorizedChirho(VerifiedEffectCompensationChirho),
    PendingManualChirho(CompensationPendingManualChirho),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCompensationAuthorizationErrorChirho {
    IntentChirho { detail_chirho: String },
    MissingOriginalEffectKeyChirho,
    AuthorityChirho { detail_chirho: String },
    FactBindingChirho { detail_chirho: String },
}

impl std::fmt::Display for EffectCompensationAuthorizationErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntentChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "compensation intent refused: {detail_chirho}"
                )
            }
            Self::MissingOriginalEffectKeyChirho => {
                write!(
                    formatter_chirho,
                    "compensation intent lacks its original effect K"
                )
            }
            Self::AuthorityChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "compensation authority failed: {detail_chirho}"
                )
            }
            Self::FactBindingChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "compensation authorization facts diverge: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for EffectCompensationAuthorizationErrorChirho {}

/// Verify one signed compensation candidate and mint its opaque door token only after the
/// injected authority's lineage facts pass binding, depth, and breaker checks.
pub fn authorize_effect_compensation_chirho(
    canonical_intent_line_chirho: &str,
    intent_verifier_chirho: &dyn EffectIntentSignerPortChirho,
    authorization_view_chirho: &dyn CompensationAuthorizationViewChirho,
) -> Result<EffectCompensationAuthorizationOutcomeChirho, EffectCompensationAuthorizationErrorChirho>
{
    let verified_intent_chirho =
        verify_effect_intent_line_chirho(canonical_intent_line_chirho, intent_verifier_chirho)
            .map_err(
                |error_chirho| EffectCompensationAuthorizationErrorChirho::IntentChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )?;
    let original_effect_key_chirho = verified_intent_chirho
        .intent_chirho()
        .original_effect_key_chirho
        .as_ref()
        .ok_or(EffectCompensationAuthorizationErrorChirho::MissingOriginalEffectKeyChirho)?
        .clone();
    let facts_chirho = authorization_view_chirho
        .derive_chirho(&verified_intent_chirho)
        .map_err(
            |error_chirho| EffectCompensationAuthorizationErrorChirho::AuthorityChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
    if facts_chirho.original_effect_key_chirho != original_effect_key_chirho {
        return Err(
            EffectCompensationAuthorizationErrorChirho::FactBindingChirho {
                detail_chirho: "authority returned a different original effect K".to_owned(),
            },
        );
    }
    effect_compensation_key_chirho(&facts_chirho.lineage_root_key_chirho).map_err(|_| {
        EffectCompensationAuthorizationErrorChirho::FactBindingChirho {
            detail_chirho: "authority returned a malformed lineage root K".to_owned(),
        }
    })?;
    if facts_chirho.next_depth_chirho == 0 || facts_chirho.max_depth_chirho == 0 {
        return Err(
            EffectCompensationAuthorizationErrorChirho::FactBindingChirho {
                detail_chirho: "authority returned a zero compensation depth bound".to_owned(),
            },
        );
    }
    if facts_chirho.next_depth_chirho > facts_chirho.max_depth_chirho {
        return Ok(
            EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(
                CompensationPendingManualChirho {
                    original_effect_key_chirho,
                    lineage_root_key_chirho: facts_chirho.lineage_root_key_chirho,
                    reason_chirho: CompensationPendingReasonChirho::DepthExceededChirho {
                        next_depth_chirho: facts_chirho.next_depth_chirho,
                        max_depth_chirho: facts_chirho.max_depth_chirho,
                    },
                },
            ),
        );
    }
    if let CompensationBreakerVerdictChirho::TrippedChirho { detail_chirho } =
        facts_chirho.breaker_verdict_chirho
    {
        return Ok(
            EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(
                CompensationPendingManualChirho {
                    original_effect_key_chirho,
                    lineage_root_key_chirho: facts_chirho.lineage_root_key_chirho,
                    reason_chirho: CompensationPendingReasonChirho::CircuitBreakerTrippedChirho {
                        detail_chirho,
                    },
                },
            ),
        );
    }

    let intent_ref_chirho = effect_intent_ref_chirho(verified_intent_chirho.intent_chirho())
        .map_err(
            |error_chirho| EffectCompensationAuthorizationErrorChirho::IntentChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
    let compensation_key_chirho = effect_compensation_key_chirho(&original_effect_key_chirho)
        .map_err(
            |error_chirho| EffectCompensationAuthorizationErrorChirho::IntentChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
    let control_saga_id_chirho = parse_effect_compensation_key_chirho(&compensation_key_chirho)
        .map_err(
            |error_chirho| EffectCompensationAuthorizationErrorChirho::IntentChirho {
                detail_chirho: error_chirho.to_string(),
            },
        )?;
    Ok(
        EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(
            VerifiedEffectCompensationChirho {
                intent_ref_chirho,
                compensation_key_chirho,
                control_saga_id_chirho,
                original_effect_key_chirho,
                lineage_root_key_chirho: facts_chirho.lineage_root_key_chirho,
                next_depth_chirho: facts_chirho.next_depth_chirho,
                max_depth_chirho: facts_chirho.max_depth_chirho,
            },
        ),
    )
}
