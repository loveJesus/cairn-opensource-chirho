// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Opaque current-plan authority and read-only compensation preview for CF7 Brick C.

use super::evidence_chirho::{
    RootEffectCommitEvidenceChirho, RootPostgresOriginalEffectEvidenceChirho,
};
use super::LocalPostgresEffectCompositionChirho;
use crate::app_source_manifest_chirho::{
    load_app_source_review_report_for_promotion_chirho, load_verified_app_source_undo_plans_chirho,
    VerifiedAppSourceUndoPlanChirho,
};
use crate::model_chirho::HashChirho;
use crate::{app_chirho, review_chirho};
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalDispositionChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_postgres_effect_chirho::ports_chirho::ReversiblePostgresDatabasePortChirho;
use cairn_postgres_effect_chirho::{
    preview_reversible_postgres_compensation_chirho, PostgresCompensationOutcomeChirho,
    PostgresCompensationPreviewChirho, ReversiblePostgresEffectCoordinateChirho,
};
use cairn_undo_plan_chirho::canonical_chirho::reversion_contract_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::{
    EffectDoorSelectorChirho, POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
};
use cairn_undo_plan_chirho::plan_chirho::{UndoDoorKeyChirho, UndoPlanEffectDoorChirho};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const CURRENT_COMPENSATION_PREVIEW_SCHEMA_CHIRHO: &str =
    "current-postgres-compensation-preview-v1-chirho";
const POSTGRES_REVERSIBLE_CONTRACT_KEY_CHIRHO: &str = "postgres-reversible-chirho";

/// This token is intentionally non-Clone, non-Debug, non-Serialize, and non-Default. Its sole
/// production mint below re-verifies the complete current promotion and exact undo-plan bytes.
pub struct VerifiedCurrentUndoPlanAuthorityChirho {
    root_chirho: PathBuf,
    app_chirho: String,
    owner_chirho: String,
    source_review_report_chirho: HashChirho,
    plan_digest_chirho: HashChirho,
    contract_set_digest_chirho: HashChirho,
    max_depth_chirho: u16,
    door_chirho: UndoDoorKeyChirho,
    contract_digest_chirho: HashChirho,
}

impl VerifiedCurrentUndoPlanAuthorityChirho {
    pub(super) fn root_chirho(&self) -> &Path {
        &self.root_chirho
    }

    pub(super) fn app_chirho(&self) -> &str {
        &self.app_chirho
    }

    pub(super) fn contract_set_digest_chirho(&self) -> &HashChirho {
        &self.contract_set_digest_chirho
    }

    pub(super) fn max_depth_chirho(&self) -> u16 {
        self.max_depth_chirho
    }

    pub(super) fn door_chirho(&self) -> &UndoDoorKeyChirho {
        &self.door_chirho
    }

    pub(super) fn contract_digest_chirho(&self) -> &HashChirho {
        &self.contract_digest_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum CurrentPostgresCompensationPreviewVerdictChirho {
    #[serde(rename = "executable-chirho")]
    ExecutableChirho,
    #[serde(rename = "must-not-execute-chirho")]
    MustNotExecuteChirho,
    #[serde(rename = "completed-replay-chirho")]
    CompletedReplayChirho { provider_restored_chirho: bool },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPostgresCompensationPreviewChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub source_review_report_chirho: HashChirho,
    pub plan_digest_chirho: HashChirho,
    pub original_effect_key_chirho: HashChirho,
    pub intent_ref_chirho: DigestChirho,
    pub terminal_outcome_ref_chirho: DigestChirho,
    pub verdict_chirho: CurrentPostgresCompensationPreviewVerdictChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedCurrentUndoPlanAuthorityErrorChirho {
    CurrentAppRefusedChirho,
    CurrentPromotionRefusedChirho,
    CurrentPlanRefusedChirho,
    NoEligiblePlanEffectChirho,
    MultipleEligiblePlanEffectsChirho,
    StaleAuthorityChirho,
    NoEligibleJournalEffectChirho,
    MultipleEligibleJournalEffectsChirho,
    OriginalEffectEvidenceRefusedChirho,
    ProviderPreviewRefusedChirho,
    CurrentPriceRefusedChirho,
    ExistingCompensationBindingRefusedChirho,
    CompensationAuthorizationRefusedChirho,
    CompensationPendingManualChirho,
    CompensationInDoubtChirho,
    CompensationTerminalRefusedChirho,
    CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho,
    CompensationExecutionSinkTermStaleWinnerRefusedChirho,
    CompensationExecutionSinkTermUnseenWinnerRefusedChirho,
    CompensationExecutionOrdinaryTermInputsUnavailableChirho,
    CompensationExecutionOrdinaryTermAcceptanceRefusedChirho,
    CompensationExecutionCommittedEvidencePendingChirho,
    CompensationExecutionRefusedChirho,
}

impl std::fmt::Display for VerifiedCurrentUndoPlanAuthorityErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label_chirho = match self {
            Self::CurrentAppRefusedChirho => "current app state refused compensation authority",
            Self::CurrentPromotionRefusedChirho => {
                "current promoted source review refused compensation authority"
            }
            Self::CurrentPlanRefusedChirho => {
                "current exact undo plan refused compensation authority"
            }
            Self::NoEligiblePlanEffectChirho => {
                "current undo plan has no eligible reversible-PostgreSQL effect"
            }
            Self::MultipleEligiblePlanEffectsChirho => {
                "current undo plan has multiple eligible reversible-PostgreSQL effects"
            }
            Self::StaleAuthorityChirho => "verified current undo-plan authority is stale",
            Self::NoEligibleJournalEffectChirho => {
                "verified journal has no eligible terminalized forward effect"
            }
            Self::MultipleEligibleJournalEffectsChirho => {
                "verified journal has multiple eligible terminalized forward effects"
            }
            Self::OriginalEffectEvidenceRefusedChirho => {
                "signed original effect evidence refused compensation preview"
            }
            Self::ProviderPreviewRefusedChirho => {
                "reversible-PostgreSQL provider refused compensation preview"
            }
            Self::CurrentPriceRefusedChirho => {
                "current signed PostgreSQL compensation price refused"
            }
            Self::ExistingCompensationBindingRefusedChirho => {
                "existing signed compensation binding refused"
            }
            Self::CompensationAuthorizationRefusedChirho => {
                "verified compensation authorization refused"
            }
            Self::CompensationPendingManualChirho => {
                "verified compensation remains pending manual disposition"
            }
            Self::CompensationInDoubtChirho => {
                "verified compensation provider outcome remains in-doubt"
            }
            Self::CompensationTerminalRefusedChirho => "verified compensation terminal refused",
            Self::CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho => {
                "compensation execution found no accepted sink winner term"
            }
            Self::CompensationExecutionSinkTermStaleWinnerRefusedChirho => {
                "compensation execution supplied a stale sink winner term"
            }
            Self::CompensationExecutionSinkTermUnseenWinnerRefusedChirho => {
                "compensation execution supplied an unseen sink winner term"
            }
            Self::CompensationExecutionOrdinaryTermInputsUnavailableChirho => {
                "compensation execution ordinary-term acceptance inputs are unavailable"
            }
            Self::CompensationExecutionOrdinaryTermAcceptanceRefusedChirho => {
                "compensation execution ordinary-term two-holder acceptance refused"
            }
            Self::CompensationExecutionCommittedEvidencePendingChirho => {
                "compensation execution committed while authority evidence remains pending"
            }
            Self::CompensationExecutionRefusedChirho => "compensation execution refused",
        };
        formatter_chirho.write_str(label_chirho)
    }
}

impl std::error::Error for VerifiedCurrentUndoPlanAuthorityErrorChirho {}

struct EligiblePlanEffectChirho {
    plan_digest_chirho: HashChirho,
    contract_set_digest_chirho: HashChirho,
    max_depth_chirho: u16,
    door_chirho: UndoPlanEffectDoorChirho,
    contract_digest_chirho: HashChirho,
}

struct EligibleJournalEffectChirho {
    original_effect_key_chirho: HashChirho,
    intent_ref_chirho: DigestChirho,
    terminal_outcome_ref_chirho: DigestChirho,
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
pub fn mint_verified_current_undo_plan_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> Result<VerifiedCurrentUndoPlanAuthorityChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho> {
    let status_chirho = app_chirho::app_status_chirho(root_chirho, app_chirho)
        .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentAppRefusedChirho)?;
    let current_dag_chirho = status_chirho
        .dag_chirho
        .as_ref()
        .filter(|_| status_chirho.active_chirho)
        .ok_or(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentAppRefusedChirho)?;
    if status_chirho.owner_principal_chirho.as_deref() != Some(owner_chirho) {
        return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentAppRefusedChirho);
    }

    let promotion_chirho = review_chirho::verified_review_records_chirho(root_chirho)
        .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho)?
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.owner_principal_chirho == owner_chirho
                && record_chirho.candidate_chirho == *current_dag_chirho
                && record_chirho.source_review_report_chirho.is_some()
                && matches!(
                    record_chirho.decision_chirho,
                    review_chirho::ReviewDecisionChirho::PromoteChirho
                )
        })
        .ok_or(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho)?;
    let source_review_report_chirho = promotion_chirho
        .source_review_report_chirho
        .ok_or(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho)?;
    let report_chirho = load_app_source_review_report_for_promotion_chirho(
        root_chirho,
        app_chirho,
        owner_chirho,
        &source_review_report_chirho,
        Some(current_dag_chirho),
    )
    .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho)?;
    if candidate_routes_chirho(&report_chirho.candidate_chirho.routes_chirho)?
        != status_chirho.routes_chirho
    {
        return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho);
    }

    let plans_chirho =
        load_verified_app_source_undo_plans_chirho(root_chirho, &report_chirho.candidate_chirho)
            .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPlanRefusedChirho)?;
    let mut eligible_chirho = plans_chirho
        .iter()
        .flat_map(eligible_postgres_effects_chirho)
        .collect::<Result<Vec<_>, _>>()?;
    let eligible_chirho = match eligible_chirho.len() {
        0 => {
            return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::NoEligiblePlanEffectChirho);
        }
        1 => eligible_chirho
            .pop()
            .expect("one eligible plan effect exists"),
        _ => {
            return Err(
                VerifiedCurrentUndoPlanAuthorityErrorChirho::MultipleEligiblePlanEffectsChirho,
            );
        }
    };
    Ok(VerifiedCurrentUndoPlanAuthorityChirho {
        root_chirho: root_chirho.to_path_buf(),
        app_chirho: app_chirho.to_owned(),
        owner_chirho: owner_chirho.to_owned(),
        source_review_report_chirho,
        plan_digest_chirho: eligible_chirho.plan_digest_chirho,
        contract_set_digest_chirho: eligible_chirho.contract_set_digest_chirho,
        max_depth_chirho: eligible_chirho.max_depth_chirho,
        door_chirho: eligible_chirho.door_chirho.door_chirho,
        contract_digest_chirho: eligible_chirho.contract_digest_chirho,
    })
}

impl<DatabaseChirho> LocalPostgresEffectCompositionChirho<'_, DatabaseChirho>
where
    DatabaseChirho: ReversiblePostgresDatabasePortChirho,
{
    pub fn preview_current_compensation_chirho(
        &mut self,
        authority_chirho: &VerifiedCurrentUndoPlanAuthorityChirho,
    ) -> Result<CurrentPostgresCompensationPreviewChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho>
    {
        if self.root_chirho != authority_chirho.root_chirho {
            return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::StaleAuthorityChirho);
        }
        let current_chirho = mint_verified_current_undo_plan_authority_chirho(
            &self.root_chirho,
            &authority_chirho.app_chirho,
            &authority_chirho.owner_chirho,
        )
        .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::StaleAuthorityChirho)?;
        if !same_authority_chirho(authority_chirho, &current_chirho) {
            return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::StaleAuthorityChirho);
        }
        let selected_chirho = self.select_eligible_journal_effect_chirho(authority_chirho)?;
        let original_evidence_chirho = RootPostgresOriginalEffectEvidenceChirho::new_chirho(
            &self.root_chirho,
            selected_chirho.intent_ref_chirho.clone(),
            selected_chirho.terminal_outcome_ref_chirho.clone(),
            self.intent_signer_chirho,
            self.terminal_signer_chirho,
        );
        let preview_chirho = preview_reversible_postgres_compensation_chirho(
            &mut *self.database_chirho,
            &original_evidence_chirho,
            &self.evidence_key_chirho,
            &selected_chirho.original_effect_key_chirho,
        )
        .map_err(|_| VerifiedCurrentUndoPlanAuthorityErrorChirho::ProviderPreviewRefusedChirho)?;
        let verdict_chirho = match preview_chirho {
            PostgresCompensationPreviewChirho::ExecutableChirho => {
                CurrentPostgresCompensationPreviewVerdictChirho::ExecutableChirho
            }
            PostgresCompensationPreviewChirho::MustNotExecuteChirho { .. } => {
                CurrentPostgresCompensationPreviewVerdictChirho::MustNotExecuteChirho
            }
            PostgresCompensationPreviewChirho::CompletedReplayChirho { receipt_chirho, .. } => {
                CurrentPostgresCompensationPreviewVerdictChirho::CompletedReplayChirho {
                    provider_restored_chirho: matches!(
                        receipt_chirho.outcome_chirho,
                        PostgresCompensationOutcomeChirho::RestoredChirho { .. }
                    ),
                }
            }
        };
        Ok(CurrentPostgresCompensationPreviewChirho {
            schema_chirho: CURRENT_COMPENSATION_PREVIEW_SCHEMA_CHIRHO.to_owned(),
            app_chirho: authority_chirho.app_chirho.clone(),
            source_review_report_chirho: authority_chirho.source_review_report_chirho.clone(),
            plan_digest_chirho: authority_chirho.plan_digest_chirho.clone(),
            original_effect_key_chirho: selected_chirho.original_effect_key_chirho,
            intent_ref_chirho: selected_chirho.intent_ref_chirho,
            terminal_outcome_ref_chirho: selected_chirho.terminal_outcome_ref_chirho,
            verdict_chirho,
        })
    }

    fn select_eligible_journal_effect_chirho(
        &self,
        authority_chirho: &VerifiedCurrentUndoPlanAuthorityChirho,
    ) -> Result<EligibleJournalEffectChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho> {
        let effect_evidence_chirho = RootEffectCommitEvidenceChirho::new_chirho(&self.root_chirho);
        let mut eligible_chirho = Vec::new();
        for entry_chirho in self
            .journal_chirho
            .verified_effect_receipt_inventory_chirho()
            .map_err(|_| {
                VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho
            })?
        {
            if entry_chirho.control_saga_id_chirho.is_some() {
                continue;
            }
            let Some(terminal_outcome_ref_chirho) = entry_chirho.terminal_outcome_ref_chirho else {
                continue;
            };
            let intent_chirho = effect_evidence_chirho
                .load_verified_intent_chirho(
                    &entry_chirho.intent_ref_chirho,
                    self.intent_signer_chirho,
                )
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho
                })?;
            if intent_chirho
                .intent_chirho()
                .original_effect_key_chirho
                .is_some()
                || intent_chirho.intent_chirho().door_chirho != authority_chirho.door_chirho
                || intent_chirho.intent_chirho().contract_set_digest_chirho.0
                    != authority_chirho.contract_set_digest_chirho.0
                || intent_chirho
                    .intent_chirho()
                    .reversion_contract_digest_chirho
                    .0
                    != authority_chirho.contract_digest_chirho.0
            {
                continue;
            }
            let terminal_chirho = effect_evidence_chirho
                .load_verified_terminal_chirho(
                    &terminal_outcome_ref_chirho,
                    self.terminal_signer_chirho,
                )
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho
                })?;
            if terminal_chirho.outcome_chirho().intent_ref_chirho != entry_chirho.intent_ref_chirho
                || !matches!(
                    terminal_chirho.outcome_chirho().disposition_chirho,
                    EffectTerminalDispositionChirho::CommittedChirho { .. }
                )
            {
                continue;
            }
            let coordinate_chirho =
                ReversiblePostgresEffectCoordinateChirho::from_verified_intent_chirho(
                    &intent_chirho,
                )
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho
                })?;
            eligible_chirho.push(EligibleJournalEffectChirho {
                original_effect_key_chirho: coordinate_chirho.effect_idem_key_chirho().clone(),
                intent_ref_chirho: entry_chirho.intent_ref_chirho,
                terminal_outcome_ref_chirho,
            });
        }
        match eligible_chirho.len() {
            0 => Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::NoEligibleJournalEffectChirho),
            1 => Ok(eligible_chirho
                .pop()
                .expect("one eligible journal effect exists")),
            _ => Err(
                VerifiedCurrentUndoPlanAuthorityErrorChirho::MultipleEligibleJournalEffectsChirho,
            ),
        }
    }
}

fn candidate_routes_chirho(
    routes_chirho: &[crate::app_source_manifest_chirho::AppSourceCandidateRouteReportChirho],
) -> Result<BTreeMap<String, HashChirho>, VerifiedCurrentUndoPlanAuthorityErrorChirho> {
    let mut mapped_chirho = BTreeMap::new();
    for route_chirho in routes_chirho {
        if mapped_chirho
            .insert(
                route_chirho.route_chirho.clone(),
                route_chirho.dag_chirho.clone(),
            )
            .is_some()
        {
            return Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho);
        }
    }
    Ok(mapped_chirho)
}

fn eligible_postgres_effects_chirho(
    verified_chirho: &VerifiedAppSourceUndoPlanChirho,
) -> impl Iterator<
    Item = Result<EligiblePlanEffectChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho>,
> + '_ {
    verified_chirho
        .plan_chirho
        .effect_doors_chirho
        .iter()
        .filter(|door_chirho| is_postgres_reversible_door_chirho(door_chirho))
        .map(|door_chirho| {
            Ok(EligiblePlanEffectChirho {
                plan_digest_chirho: verified_chirho.binding_chirho.plan_digest_chirho.clone(),
                contract_set_digest_chirho: verified_chirho
                    .binding_chirho
                    .contract_set_digest_chirho
                    .clone(),
                max_depth_chirho: verified_chirho.plan_chirho.max_depth_chirho,
                door_chirho: door_chirho.clone(),
                contract_digest_chirho: reversion_contract_digest_chirho(
                    &door_chirho.contract_chirho,
                )
                .map_err(|_| {
                    VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPlanRefusedChirho
                })?,
            })
        })
}

fn is_postgres_reversible_door_chirho(door_chirho: &UndoPlanEffectDoorChirho) -> bool {
    door_chirho.contract_chirho.contract_key_chirho.0 == POSTGRES_REVERSIBLE_CONTRACT_KEY_CHIRHO
        && matches!(
            &door_chirho.contract_chirho.effect_selector_chirho,
            EffectDoorSelectorChirho::PaidEffectChirho { effect_chirho }
                if effect_chirho == POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO
        )
}

fn same_authority_chirho(
    left_chirho: &VerifiedCurrentUndoPlanAuthorityChirho,
    right_chirho: &VerifiedCurrentUndoPlanAuthorityChirho,
) -> bool {
    left_chirho.root_chirho == right_chirho.root_chirho
        && left_chirho.app_chirho == right_chirho.app_chirho
        && left_chirho.owner_chirho == right_chirho.owner_chirho
        && left_chirho.source_review_report_chirho == right_chirho.source_review_report_chirho
        && left_chirho.plan_digest_chirho == right_chirho.plan_digest_chirho
        && left_chirho.contract_set_digest_chirho == right_chirho.contract_set_digest_chirho
        && left_chirho.max_depth_chirho == right_chirho.max_depth_chirho
        && left_chirho.door_chirho == right_chirho.door_chirho
        && left_chirho.contract_digest_chirho == right_chirho.contract_digest_chirho
}

#[cfg(test)]
#[path = "compensation_authority_tests_chirho.rs"]
mod compensation_authority_tests_chirho;
#[cfg(test)]
pub(super) use compensation_authority_tests_chirho::promoted_postgres_app_chirho;
