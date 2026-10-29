// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! CF3 provider adapter for the reversible PostgreSQL decision engine.

use crate::crypto_chirho::AdapterEvidenceKeyChirho;
use crate::engine_chirho::{
    apply_reversible_postgres_chirho, compensate_reversible_postgres_chirho,
    query_reversible_postgres_by_key_chirho, query_reversible_postgres_compensation_by_key_chirho,
    PostgresCompensationQueryResultChirho, PostgresForwardQueryResultChirho,
    ReversiblePostgresErrorChirho,
};
use crate::model_chirho::ReversiblePostgresEffectCoordinateChirho;
use crate::ports_chirho::{
    PostgresOriginalEffectEvidencePortChirho, PostgresPrivateEvidencePortChirho,
    ReversiblePostgresDatabasePortChirho,
};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    BlessedEffectProviderPortChirho, EffectProviderEvidenceBytesChirho,
    EffectProviderObservationChirho, EffectProviderPortErrorChirho,
};
use cairn_effect_commit_chirho::intent_chirho::VerifiedEffectIntentChirho;
use cairn_effect_commit_chirho::intent_chirho::{
    effect_compensation_key_chirho, parse_effect_compensation_key_chirho,
    parse_effect_intent_key_chirho,
};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;

const POSTGRES_PROVIDER_RESULT_REF_DOMAIN_CHIRHO: &[u8] =
    b"cairn-postgres-effect-provider-result-ref-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostgresRequestEvidenceErrorChirho {
    MissingChirho,
    UnavailableChirho { detail_chirho: String },
}

impl std::fmt::Display for PostgresRequestEvidenceErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingChirho => {
                formatter_chirho.write_str("reversible-Postgres request evidence is missing")
            }
            Self::UnavailableChirho { detail_chirho } => write!(
                formatter_chirho,
                "reversible-Postgres request evidence unavailable: {detail_chirho}"
            ),
        }
    }
}

impl std::error::Error for PostgresRequestEvidenceErrorChirho {}

/// The root resolves content-addressed request bytes; the provider independently re-hashes them
/// against the signed intent before the P1 engine parses or acts on the request.
pub trait PostgresRequestEvidencePortChirho {
    fn load_request_bytes_chirho(
        &self,
        request_ref_chirho: &DigestChirho,
    ) -> Result<Vec<u8>, PostgresRequestEvidenceErrorChirho>;
}

pub struct ReversiblePostgresProviderChirho<
    'provider_chirho,
    DatabaseChirho,
    PrivateChirho,
    RequestsChirho,
> {
    database_chirho: &'provider_chirho mut DatabaseChirho,
    private_evidence_chirho: &'provider_chirho mut PrivateChirho,
    request_evidence_chirho: &'provider_chirho RequestsChirho,
    original_effects_chirho: Option<&'provider_chirho dyn PostgresOriginalEffectEvidencePortChirho>,
    evidence_key_chirho: &'provider_chirho AdapterEvidenceKeyChirho,
}

impl<'provider_chirho, DatabaseChirho, PrivateChirho, RequestsChirho>
    ReversiblePostgresProviderChirho<
        'provider_chirho,
        DatabaseChirho,
        PrivateChirho,
        RequestsChirho,
    >
{
    pub fn new_chirho(
        database_chirho: &'provider_chirho mut DatabaseChirho,
        private_evidence_chirho: &'provider_chirho mut PrivateChirho,
        request_evidence_chirho: &'provider_chirho RequestsChirho,
        evidence_key_chirho: &'provider_chirho AdapterEvidenceKeyChirho,
    ) -> Self {
        Self {
            database_chirho,
            private_evidence_chirho,
            request_evidence_chirho,
            original_effects_chirho: None,
            evidence_key_chirho,
        }
    }

    pub fn new_with_compensation_chirho(
        database_chirho: &'provider_chirho mut DatabaseChirho,
        private_evidence_chirho: &'provider_chirho mut PrivateChirho,
        request_evidence_chirho: &'provider_chirho RequestsChirho,
        original_effects_chirho: &'provider_chirho dyn PostgresOriginalEffectEvidencePortChirho,
        evidence_key_chirho: &'provider_chirho AdapterEvidenceKeyChirho,
    ) -> Self {
        Self {
            database_chirho,
            private_evidence_chirho,
            request_evidence_chirho,
            original_effects_chirho: Some(original_effects_chirho),
            evidence_key_chirho,
        }
    }
}

impl<DatabaseChirho, PrivateChirho, RequestsChirho> BlessedEffectProviderPortChirho
    for ReversiblePostgresProviderChirho<'_, DatabaseChirho, PrivateChirho, RequestsChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
    PrivateChirho: PostgresPrivateEvidencePortChirho,
    RequestsChirho: PostgresRequestEvidencePortChirho,
{
    fn execute_or_replay_chirho(
        &mut self,
        intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        if let Some(original_effect_key_chirho) = intent_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .as_deref()
        {
            let (compensation_idem_key_chirho, original_effect_idem_key_chirho) =
                compensation_coordinates_chirho(original_effect_key_chirho)?;
            let original_effects_chirho = self.original_effects_chirho.ok_or_else(|| {
                EffectProviderPortErrorChirho::InvalidResponseChirho {
                    detail_chirho: "compensation intent reached a forward-only PostgreSQL provider"
                        .to_owned(),
                }
            })?;
            let result_chirho = compensate_reversible_postgres_chirho(
                self.database_chirho,
                self.private_evidence_chirho,
                original_effects_chirho,
                self.evidence_key_chirho,
                &compensation_idem_key_chirho,
                &original_effect_idem_key_chirho,
            )
            .map_err(engine_provider_error_chirho)?;
            return committed_observation_chirho(result_chirho.receipt_bytes_chirho);
        }
        let coordinate_chirho =
            ReversiblePostgresEffectCoordinateChirho::from_verified_intent_chirho(intent_chirho)
                .map_err(invalid_provider_error_chirho)?;
        let request_bytes_chirho = self
            .request_evidence_chirho
            .load_request_bytes_chirho(&intent_chirho.intent_chirho().request_ref_chirho)
            .map_err(request_evidence_error_chirho)?;
        verify_request_ref_chirho(intent_chirho, &request_bytes_chirho)?;
        let result_chirho = apply_reversible_postgres_chirho(
            self.database_chirho,
            self.private_evidence_chirho,
            self.evidence_key_chirho,
            &coordinate_chirho,
            &request_bytes_chirho,
        )
        .map_err(engine_provider_error_chirho)?;
        committed_observation_chirho(result_chirho.decision_bytes_chirho)
    }

    fn query_by_key_chirho(
        &mut self,
        intent_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
        if let Some(original_effect_key_chirho) = intent_chirho
            .intent_chirho()
            .original_effect_key_chirho
            .as_deref()
        {
            let (compensation_idem_key_chirho, original_effect_idem_key_chirho) =
                compensation_coordinates_chirho(original_effect_key_chirho)?;
            let original_effects_chirho = self.original_effects_chirho.ok_or_else(|| {
                EffectProviderPortErrorChirho::InvalidResponseChirho {
                    detail_chirho: "compensation intent reached a forward-only PostgreSQL provider"
                        .to_owned(),
                }
            })?;
            return match query_reversible_postgres_compensation_by_key_chirho(
                self.database_chirho,
                original_effects_chirho,
                self.evidence_key_chirho,
                &compensation_idem_key_chirho,
                &original_effect_idem_key_chirho,
            )
            .map_err(engine_provider_error_chirho)?
            {
                PostgresCompensationQueryResultChirho::CommittedChirho {
                    receipt_bytes_chirho,
                    ..
                } => committed_observation_chirho(receipt_bytes_chirho),
                PostgresCompensationQueryResultChirho::InDoubtChirho => {
                    Ok(EffectProviderObservationChirho::InDoubtChirho)
                }
            };
        }
        let coordinate_chirho =
            ReversiblePostgresEffectCoordinateChirho::from_verified_intent_chirho(intent_chirho)
                .map_err(invalid_provider_error_chirho)?;
        match query_reversible_postgres_by_key_chirho(
            self.database_chirho,
            self.evidence_key_chirho,
            &coordinate_chirho,
        )
        .map_err(engine_provider_error_chirho)?
        {
            PostgresForwardQueryResultChirho::CommittedChirho {
                decision_bytes_chirho,
                ..
            } => committed_observation_chirho(decision_bytes_chirho),
            PostgresForwardQueryResultChirho::DefiniteNoEffectChirho {
                witness_bytes_chirho,
                ..
            } => Ok(EffectProviderObservationChirho::DefiniteNoEffectChirho {
                evidence_chirho: provider_evidence_chirho(witness_bytes_chirho)?,
            }),
        }
    }
}

fn compensation_coordinates_chirho(
    original_effect_key_chirho: &str,
) -> Result<(HashChirho, HashChirho), EffectProviderPortErrorChirho> {
    let original_effect_idem_key_chirho =
        parse_effect_intent_key_chirho(original_effect_key_chirho)
            .map_err(invalid_provider_error_chirho)?;
    let compensation_key_chirho = effect_compensation_key_chirho(original_effect_key_chirho)
        .map_err(invalid_provider_error_chirho)?;
    let compensation_idem_key_chirho =
        parse_effect_compensation_key_chirho(&compensation_key_chirho)
            .map_err(invalid_provider_error_chirho)?;
    Ok((
        HashChirho(compensation_idem_key_chirho.0),
        HashChirho(original_effect_idem_key_chirho.0),
    ))
}

fn verify_request_ref_chirho(
    intent_chirho: &VerifiedEffectIntentChirho,
    request_bytes_chirho: &[u8],
) -> Result<(), EffectProviderPortErrorChirho> {
    let actual_chirho = blake3::hash(request_bytes_chirho).to_hex().to_string();
    if actual_chirho != intent_chirho.intent_chirho().request_ref_chirho.0 {
        return Err(EffectProviderPortErrorChirho::InvalidResponseChirho {
            detail_chirho: "resolved request bytes do not match the signed request ref".to_string(),
        });
    }
    Ok(())
}

fn committed_observation_chirho(
    decision_bytes_chirho: Vec<u8>,
) -> Result<EffectProviderObservationChirho, EffectProviderPortErrorChirho> {
    let result_ref_chirho = postgres_provider_result_ref_chirho(&decision_bytes_chirho);
    Ok(EffectProviderObservationChirho::CommittedChirho {
        result_ref_chirho,
        evidence_chirho: provider_evidence_chirho(decision_bytes_chirho)?,
    })
}

pub fn postgres_provider_result_ref_chirho(decision_bytes_chirho: &[u8]) -> DigestChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(POSTGRES_PROVIDER_RESULT_REF_DOMAIN_CHIRHO);
    hasher_chirho.update(&(decision_bytes_chirho.len() as u64).to_be_bytes());
    hasher_chirho.update(decision_bytes_chirho);
    DigestChirho(hasher_chirho.finalize().to_hex().to_string())
}

fn provider_evidence_chirho(
    bytes_chirho: Vec<u8>,
) -> Result<EffectProviderEvidenceBytesChirho, EffectProviderPortErrorChirho> {
    EffectProviderEvidenceBytesChirho::new_chirho(bytes_chirho).map_err(|error_chirho| {
        EffectProviderPortErrorChirho::InvalidResponseChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

fn request_evidence_error_chirho(
    error_chirho: PostgresRequestEvidenceErrorChirho,
) -> EffectProviderPortErrorChirho {
    match error_chirho {
        PostgresRequestEvidenceErrorChirho::MissingChirho => {
            EffectProviderPortErrorChirho::InvalidResponseChirho {
                detail_chirho: error_chirho.to_string(),
            }
        }
        PostgresRequestEvidenceErrorChirho::UnavailableChirho { .. } => {
            EffectProviderPortErrorChirho::UnavailableChirho {
                detail_chirho: error_chirho.to_string(),
            }
        }
    }
}

fn engine_provider_error_chirho(
    error_chirho: ReversiblePostgresErrorChirho,
) -> EffectProviderPortErrorChirho {
    match error_chirho {
        ReversiblePostgresErrorChirho::DatabaseChirho(_)
        | ReversiblePostgresErrorChirho::PrivateEvidenceChirho(_)
        | ReversiblePostgresErrorChirho::OriginalEffectEvidenceChirho(_) => {
            EffectProviderPortErrorChirho::UnavailableChirho {
                detail_chirho:
                    "reversible-Postgres provider could not establish a terminal observation"
                        .to_string(),
            }
        }
        error_chirho => invalid_provider_error_chirho(error_chirho),
    }
}

fn invalid_provider_error_chirho(
    error_chirho: impl std::fmt::Display,
) -> EffectProviderPortErrorChirho {
    EffectProviderPortErrorChirho::InvalidResponseChirho {
        detail_chirho: error_chirho.to_string(),
    }
}
