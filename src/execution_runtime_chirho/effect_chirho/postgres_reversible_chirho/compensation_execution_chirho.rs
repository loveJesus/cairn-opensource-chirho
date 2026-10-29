// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Verified current-plan compensation execution over the existing CF3 terminal spine.

use super::compensation_authority_chirho::{
    CurrentPostgresCompensationPreviewVerdictChirho, VerifiedCurrentUndoPlanAuthorityChirho,
    VerifiedCurrentUndoPlanAuthorityErrorChirho,
};
use super::evidence_chirho::{
    RootEffectCommitEvidenceChirho, RootPostgresOriginalEffectEvidenceChirho,
    RootPostgresPrivateEvidenceChirho, RootPostgresRequestEvidenceChirho,
};
use super::LocalPostgresEffectCompositionChirho;
use crate::model_chirho::HashChirho;
use cairn_effect_commit_chirho::compensation_chirho::{
    authorize_effect_compensation_chirho, CompensationAuthorizationFactsChirho,
    CompensationAuthorizationViewChirho, CompensationAuthorizationViewErrorChirho,
    CompensationBreakerVerdictChirho, EffectCompensationAuthorizationOutcomeChirho,
};
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitCoordinatorChirho, EffectCommitCoordinatorErrorChirho,
    EffectCommitJournalAuthorityRefusalIdentityChirho, EffectCommitRunResultChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    canonical_effect_intent_line_chirho, effect_intent_ref_chirho, parse_effect_intent_key_chirho,
    sign_effect_intent_chirho, EffectIntentChirho, VerifiedEffectIntentChirho,
    EFFECT_INTENT_SCHEMA_V1_CHIRHO,
};
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalDispositionChirho;
use cairn_ledger_model_chirho::asset_op_chirho::{AssetOpChirho, RoundingChirho};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_postgres_effect_chirho::ports_chirho::ReversiblePostgresDatabasePortChirho;
use cairn_postgres_effect_chirho::ReversiblePostgresProviderChirho;
use cairn_undo_plan_chirho::contract_chirho::POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const CURRENT_COMPENSATION_EXECUTION_SCHEMA_CHIRHO: &str =
    "current-postgres-compensation-execution-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPostgresCompensationExecutionChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub original_effect_key_chirho: HashChirho,
    pub compensation_intent_ref_chirho: DigestChirho,
    pub terminal_outcome_ref_chirho: DigestChirho,
    pub disposition_chirho: EffectTerminalDispositionChirho,
    pub provider_restored_chirho: bool,
}

struct CurrentCompensationAuthorizationViewChirho {
    expected_intent_chirho: EffectIntentChirho,
    expected_intent_ref_chirho: DigestChirho,
    original_effect_key_chirho: String,
    max_depth_chirho: u16,
    durable_bindings_chirho: BTreeMap<String, DigestChirho>,
}

impl CompensationAuthorizationViewChirho for CurrentCompensationAuthorizationViewChirho {
    fn derive_chirho(
        &self,
        candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<CompensationAuthorizationFactsChirho, CompensationAuthorizationViewErrorChirho>
    {
        if candidate_chirho.intent_chirho() != &self.expected_intent_chirho
            || effect_intent_ref_chirho(candidate_chirho.intent_chirho()).map_err(
                |error_chirho| CompensationAuthorizationViewErrorChirho::RefusedChirho {
                    detail_chirho: error_chirho.to_string(),
                },
            )? != self.expected_intent_ref_chirho
        {
            return Err(CompensationAuthorizationViewErrorChirho::RefusedChirho {
                detail_chirho: "signed compensation candidate diverges from verified authority"
                    .to_owned(),
            });
        }
        let breaker_verdict_chirho = match self
            .durable_bindings_chirho
            .get(&self.original_effect_key_chirho)
        {
            Some(existing_chirho) if existing_chirho != &self.expected_intent_ref_chirho => {
                CompensationBreakerVerdictChirho::TrippedChirho {
                    detail_chirho:
                        "original effect already binds another signed compensation intent"
                            .to_owned(),
                }
            }
            _ => CompensationBreakerVerdictChirho::PermittedChirho,
        };
        Ok(CompensationAuthorizationFactsChirho::new_chirho(
            self.original_effect_key_chirho.clone(),
            self.original_effect_key_chirho.clone(),
            1,
            self.max_depth_chirho,
            breaker_verdict_chirho,
        ))
    }
}

impl<DatabaseChirho> LocalPostgresEffectCompositionChirho<'_, DatabaseChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
{
    /// Execute the one current-plan compensation. Preview, authorization, targeted crash query,
    /// provider transaction, terminal append, and the final authenticated provider outcome all
    /// occur while the host retains its one provider mutex.
    /// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
    pub fn execute_current_compensation_chirho(
        &mut self,
        authority_chirho: &VerifiedCurrentUndoPlanAuthorityChirho,
    ) -> Result<
        CurrentPostgresCompensationExecutionChirho,
        VerifiedCurrentUndoPlanAuthorityErrorChirho,
    > {
        if authority_chirho.root_chirho() != self.root_chirho {
            return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::StaleAuthorityChirho);
        }
        let preview_chirho = self.preview_current_compensation_chirho(authority_chirho)?;
        if matches!(
            preview_chirho.verdict_chirho,
            CurrentPostgresCompensationPreviewVerdictChirho::MustNotExecuteChirho
        ) {
            return Err(
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationPendingManualChirho,
            );
        }

        let effect_evidence_chirho = RootEffectCommitEvidenceChirho::new_chirho(&self.root_chirho);
        let original_intent_chirho = effect_evidence_chirho
            .load_verified_intent_chirho(
                &preview_chirho.intent_ref_chirho,
                self.intent_signer_chirho,
            )
            .map_err(|_| {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho
            })?;
        let original_key_chirho = original_intent_chirho.key_chirho().to_owned();
        let original_digest_chirho =
            parse_effect_intent_key_chirho(&original_key_chirho).map_err(|_| {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho
            })?;
        if original_digest_chirho.0 != preview_chirho.original_effect_key_chirho.0 {
            return Err(
                VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho,
            );
        }

        let (candidate_line_chirho, candidate_chirho) = match effect_evidence_chirho
            .load_verified_compensation_intent_line_chirho(
                &original_key_chirho,
                self.intent_signer_chirho,
            )
            .map_err(|_| {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::ExistingCompensationBindingRefusedChirho
            })? {
            Some(existing_chirho) => existing_chirho,
            None => {
                let unsigned_chirho = self.derive_current_compensation_intent_chirho(
                    authority_chirho,
                    &preview_chirho,
                    &original_intent_chirho,
                    &original_key_chirho,
                )?;
                let signed_chirho = sign_effect_intent_chirho(
                    unsigned_chirho,
                    self.intent_signer_chirho,
                )
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
                })?;
                let line_chirho = canonical_effect_intent_line_chirho(&signed_chirho).map_err(
                    |_| {
                        VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
                    },
                )?;
                let verified_chirho = cairn_effect_commit_chirho::intent_chirho::verify_effect_intent_line_chirho(
                    &line_chirho,
                    self.intent_signer_chirho,
                )
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
                })?;
                (line_chirho, verified_chirho)
            }
        };
        self.validate_compensation_candidate_chirho(
            authority_chirho,
            &preview_chirho,
            &original_intent_chirho,
            &candidate_chirho,
        )?;
        let candidate_ref_chirho = effect_intent_ref_chirho(candidate_chirho.intent_chirho())
            .map_err(|_| {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
            })?;
        let authorization_view_chirho = CurrentCompensationAuthorizationViewChirho {
            expected_intent_chirho: candidate_chirho.intent_chirho().clone(),
            expected_intent_ref_chirho: candidate_ref_chirho.clone(),
            original_effect_key_chirho: original_key_chirho.clone(),
            max_depth_chirho: authority_chirho.max_depth_chirho(),
            durable_bindings_chirho: self.durable_compensation_bindings_chirho()?,
        };
        let authorization_chirho = match authorize_effect_compensation_chirho(
            &candidate_line_chirho,
            self.intent_signer_chirho,
            &authorization_view_chirho,
        )
        .map_err(|_| {
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
        })? {
            EffectCompensationAuthorizationOutcomeChirho::AuthorizedChirho(token_chirho) => {
                token_chirho
            }
            EffectCompensationAuthorizationOutcomeChirho::PendingManualChirho(_) => {
                return Err(
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationPendingManualChirho,
                );
            }
        };

        let original_evidence_chirho = RootPostgresOriginalEffectEvidenceChirho::new_chirho(
            &self.root_chirho,
            preview_chirho.intent_ref_chirho.clone(),
            preview_chirho.terminal_outcome_ref_chirho.clone(),
            self.intent_signer_chirho,
            self.terminal_signer_chirho,
        );
        let request_evidence_chirho =
            RootPostgresRequestEvidenceChirho::new_chirho(&self.root_chirho);
        let mut private_evidence_chirho =
            RootPostgresPrivateEvidenceChirho::new_chirho(&self.root_chirho);
        let mut effect_evidence_chirho =
            RootEffectCommitEvidenceChirho::new_chirho(&self.root_chirho);
        let state_chirho = self
            .journal_chirho
            .receipt_by_intent_ref_chirho(&candidate_ref_chirho)
            .map_err(|_| {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationTerminalRefusedChirho
            })?;
        let mut provider_chirho = ReversiblePostgresProviderChirho::new_with_compensation_chirho(
            &mut *self.database_chirho,
            &mut private_evidence_chirho,
            &request_evidence_chirho,
            &original_evidence_chirho,
            &self.evidence_key_chirho,
        );
        let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut effect_evidence_chirho,
            &mut *self.journal_chirho,
            self.intent_signer_chirho,
            self.terminal_signer_chirho,
        );
        let run_chirho = if state_chirho
            .as_ref()
            .is_some_and(|state_chirho| state_chirho.terminal_outcome_ref_chirho.is_none())
        {
            coordinator_chirho
                .reconcile_in_doubt_chirho(candidate_ref_chirho.clone())
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationTerminalRefusedChirho
                })?
        } else {
            coordinator_chirho
                .execute_compensation_chirho(&candidate_line_chirho, authorization_chirho)
                .map_err(map_compensation_execution_refusal_chirho)?
        };
        let (terminal_outcome_ref_chirho, disposition_chirho) = match run_chirho {
            EffectCommitRunResultChirho::TerminalChirho {
                outcome_ref_chirho,
                disposition_chirho,
                ..
            } => (outcome_ref_chirho, disposition_chirho),
            EffectCommitRunResultChirho::InDoubtChirho { .. } => {
                return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationInDoubtChirho);
            }
        };
        let completed_chirho = self.preview_current_compensation_chirho(authority_chirho)?;
        let provider_restored_chirho = match completed_chirho.verdict_chirho {
            CurrentPostgresCompensationPreviewVerdictChirho::CompletedReplayChirho {
                provider_restored_chirho,
            } => provider_restored_chirho,
            _ => {
                return Err(
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationTerminalRefusedChirho,
                );
            }
        };
        Ok(CurrentPostgresCompensationExecutionChirho {
            schema_chirho: CURRENT_COMPENSATION_EXECUTION_SCHEMA_CHIRHO.to_owned(),
            app_chirho: authority_chirho.app_chirho().to_owned(),
            original_effect_key_chirho: preview_chirho.original_effect_key_chirho,
            compensation_intent_ref_chirho: candidate_ref_chirho,
            terminal_outcome_ref_chirho,
            disposition_chirho,
            provider_restored_chirho,
        })
    }

    fn derive_current_compensation_intent_chirho(
        &self,
        authority_chirho: &VerifiedCurrentUndoPlanAuthorityChirho,
        preview_chirho: &super::compensation_authority_chirho::CurrentPostgresCompensationPreviewChirho,
        original_intent_chirho: &VerifiedEffectIntentChirho,
        original_key_chirho: &str,
    ) -> Result<EffectIntentChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho> {
        let price_chirho = crate::effect_pricing_chirho::resolve_price_chirho(
            &self.root_chirho,
            authority_chirho.app_chirho(),
            POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
        )
        .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho)?;
        let amount_chirho = u64::try_from(price_chirho.price_chirho)
            .ok()
            .filter(|amount_chirho| *amount_chirho > 0)
            .ok_or(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho)?;
        let continuation_chirho = self
            .journal_chirho
            .current_continuation_chirho(&self.billing_kind_chirho)
            .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho)?
            .filter(|continuation_chirho| continuation_chirho.settlement_owner_present_chirho)
            .ok_or(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho)?;
        let original_chirho = original_intent_chirho.intent_chirho();
        let mut evidence_refs_chirho = BTreeSet::new();
        evidence_refs_chirho.insert(DigestChirho(price_chirho.price_book_chirho.0));
        evidence_refs_chirho.insert(preview_chirho.intent_ref_chirho.clone());
        evidence_refs_chirho.insert(preview_chirho.terminal_outcome_ref_chirho.clone());
        Ok(EffectIntentChirho {
            schema_chirho: EFFECT_INTENT_SCHEMA_V1_CHIRHO.to_owned(),
            journal_cut_chirho: self
                .journal_chirho
                .effect_intent_cut_chirho()
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
                })?,
            contract_set_digest_chirho: DigestChirho(
                authority_chirho.contract_set_digest_chirho().0.clone(),
            ),
            door_chirho: authority_chirho.door_chirho().clone(),
            reversion_contract_digest_chirho: DigestChirho(
                authority_chirho.contract_digest_chirho().0.clone(),
            ),
            request_ref_chirho: original_chirho.request_ref_chirho.clone(),
            request_context_ref_chirho: original_chirho.request_context_ref_chirho.clone(),
            evidence_refs_chirho: evidence_refs_chirho.into_iter().collect(),
            resolved_price_chirho: AssetOpChirho {
                amount_chirho,
                kind_id_chirho: self.billing_kind_chirho.clone(),
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                rounding_chirho: RoundingChirho::ExactChirho,
            },
            payer_account_chirho: original_chirho.payer_account_chirho.clone(),
            effect_step_chirho: original_chirho.effect_step_chirho.checked_add(1).ok_or(
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho,
            )?,
            attribution_chirho: original_chirho.attribution_chirho.clone(),
            original_effect_key_chirho: Some(original_key_chirho.to_owned()),
            sig_chirho: String::new(),
            key_id_chirho: String::new(),
        })
    }

    fn validate_compensation_candidate_chirho(
        &self,
        authority_chirho: &VerifiedCurrentUndoPlanAuthorityChirho,
        preview_chirho: &super::compensation_authority_chirho::CurrentPostgresCompensationPreviewChirho,
        original_intent_chirho: &VerifiedEffectIntentChirho,
        candidate_chirho: &VerifiedEffectIntentChirho,
    ) -> Result<(), VerifiedCurrentUndoPlanAuthorityErrorChirho> {
        let original_chirho = original_intent_chirho.intent_chirho();
        let candidate_chirho = candidate_chirho.intent_chirho();
        let expected_step_chirho = original_chirho.effect_step_chirho.checked_add(1).ok_or(
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho,
        )?;
        if candidate_chirho.original_effect_key_chirho.as_deref()
            != Some(original_intent_chirho.key_chirho())
            || candidate_chirho.contract_set_digest_chirho.0
                != authority_chirho.contract_set_digest_chirho().0
            || candidate_chirho.door_chirho != *authority_chirho.door_chirho()
            || candidate_chirho.reversion_contract_digest_chirho.0
                != authority_chirho.contract_digest_chirho().0
            || candidate_chirho.request_ref_chirho != original_chirho.request_ref_chirho
            || candidate_chirho.request_context_ref_chirho
                != original_chirho.request_context_ref_chirho
            || candidate_chirho.payer_account_chirho != original_chirho.payer_account_chirho
            || candidate_chirho.attribution_chirho != original_chirho.attribution_chirho
            || candidate_chirho.effect_step_chirho != expected_step_chirho
            || candidate_chirho.resolved_price_chirho.amount_chirho == 0
            || candidate_chirho.resolved_price_chirho.kind_id_chirho != self.billing_kind_chirho
            || candidate_chirho.resolved_price_chirho.rounding_chirho != RoundingChirho::ExactChirho
            || !candidate_chirho
                .evidence_refs_chirho
                .contains(&preview_chirho.intent_ref_chirho)
            || !candidate_chirho
                .evidence_refs_chirho
                .contains(&preview_chirho.terminal_outcome_ref_chirho)
            || candidate_chirho
                .journal_cut_chirho
                .journal_genesis_digest_chirho
                != self
                    .journal_chirho
                    .effect_intent_cut_chirho()
                    .map_err(|_| {
                        VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
                    })?
                    .journal_genesis_digest_chirho
        {
            return Err(
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho,
            );
        }
        Ok(())
    }

    fn durable_compensation_bindings_chirho(
        &self,
    ) -> Result<BTreeMap<String, DigestChirho>, VerifiedCurrentUndoPlanAuthorityErrorChirho> {
        let evidence_chirho = RootEffectCommitEvidenceChirho::new_chirho(&self.root_chirho);
        let mut bindings_chirho = BTreeMap::new();
        for entry_chirho in self
            .journal_chirho
            .verified_effect_receipt_inventory_chirho()
            .map_err(|_| {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
            })?
            .into_iter()
            .filter(|entry_chirho| entry_chirho.control_saga_id_chirho.is_some())
        {
            let intent_chirho = evidence_chirho
                .load_verified_intent_chirho(
                    &entry_chirho.intent_ref_chirho,
                    self.intent_signer_chirho,
                )
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho
                })?;
            let original_chirho = intent_chirho
                .intent_chirho()
                .original_effect_key_chirho
                .clone()
                .ok_or(
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho,
                )?;
            if bindings_chirho
                .insert(original_chirho, entry_chirho.intent_ref_chirho)
                .is_some()
            {
                return Err(
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho,
                );
            }
        }
        Ok(bindings_chirho)
    }
}

fn map_compensation_execution_refusal_chirho(
    error_chirho: EffectCommitCoordinatorErrorChirho,
) -> VerifiedCurrentUndoPlanAuthorityErrorChirho {
    match error_chirho {
        EffectCommitCoordinatorErrorChirho::JournalAuthorityRefusedChirho {
            identity_chirho,
            ..
        } => match identity_chirho {
            EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermNoAcceptedWinnerChirho => {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho
            }
            EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermStaleWinnerChirho => {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermStaleWinnerRefusedChirho
            }
            EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermUnseenWinnerChirho => {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermUnseenWinnerRefusedChirho
            }
            EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho => {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionOrdinaryTermInputsUnavailableChirho
            }
            EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceChirho => {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionOrdinaryTermAcceptanceRefusedChirho
            }
        },
        EffectCommitCoordinatorErrorChirho::JournalCommittedEvidencePendingChirho { .. } => {
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionCommittedEvidencePendingChirho
        }
        _ => VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionRefusedChirho,
    }
}

#[cfg(test)]
#[path = "compensation_execution_tests_chirho.rs"]
mod compensation_execution_tests_chirho;
