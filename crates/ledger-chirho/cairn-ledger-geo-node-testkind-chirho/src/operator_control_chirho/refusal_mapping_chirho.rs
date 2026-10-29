// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Fixed, non-secret CF7 operator refusal identities.
//!
//! Typed causes become unit labels only. Embedded details, paths, principals, intent coordinates,
//! and the surrounding `anyhow` display chain never cross the test-kind wire.

use super::TestkindCf7OperatorRefusalChirho;
use cairn_serve_runtime_chirho::{
    LedgerHostPostgresEffectRefusalChirho, PostgresReversibleActivationErrorChirho,
    ReviewedCurrentPostgresCompensationRefusalChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho,
};

pub(super) fn map_reviewed_execution_refusal_chirho(
    error_chirho: anyhow::Error,
) -> TestkindCf7OperatorRefusalChirho {
    match error_chirho.downcast_ref::<ReviewedCurrentPostgresCompensationRefusalChirho>() {
        Some(ReviewedCurrentPostgresCompensationRefusalChirho::PreviewChangedChirho) => {
            TestkindCf7OperatorRefusalChirho::ReviewedPreviewChangedChirho
        }
        Some(ReviewedCurrentPostgresCompensationRefusalChirho::PreviewNotExecutableChirho) => {
            TestkindCf7OperatorRefusalChirho::ReviewedPreviewNotExecutableChirho
        }
        Some(ReviewedCurrentPostgresCompensationRefusalChirho::ReplayNotCompletedChirho)
        | Some(ReviewedCurrentPostgresCompensationRefusalChirho::ReplayExecutionChangedChirho)
        | None => map_current_compensation_refusal_chirho(&error_chirho)
            .unwrap_or(TestkindCf7OperatorRefusalChirho::ExecutionRefusedChirho),
    }
}

pub(super) fn map_reviewed_replay_refusal_chirho(
    error_chirho: anyhow::Error,
) -> TestkindCf7OperatorRefusalChirho {
    match error_chirho.downcast_ref::<ReviewedCurrentPostgresCompensationRefusalChirho>() {
        Some(ReviewedCurrentPostgresCompensationRefusalChirho::ReplayNotCompletedChirho) => {
            TestkindCf7OperatorRefusalChirho::ReplayNotCompletedChirho
        }
        Some(ReviewedCurrentPostgresCompensationRefusalChirho::ReplayExecutionChangedChirho) => {
            TestkindCf7OperatorRefusalChirho::ReplayExecutionChangedChirho
        }
        Some(ReviewedCurrentPostgresCompensationRefusalChirho::PreviewChangedChirho)
        | Some(ReviewedCurrentPostgresCompensationRefusalChirho::PreviewNotExecutableChirho)
        | None => map_current_compensation_refusal_chirho(&error_chirho)
            .unwrap_or(TestkindCf7OperatorRefusalChirho::ReplayRefusedChirho),
    }
}

pub(super) fn map_preview_refusal_chirho(
    error_chirho: anyhow::Error,
) -> TestkindCf7OperatorRefusalChirho {
    map_current_compensation_refusal_chirho(&error_chirho)
        .unwrap_or(TestkindCf7OperatorRefusalChirho::PreviewRefusedChirho)
}

pub(super) fn map_current_compensation_refusal_chirho(
    error_chirho: &anyhow::Error,
) -> Option<TestkindCf7OperatorRefusalChirho> {
    if let Some(refusal_chirho) =
        error_chirho.downcast_ref::<VerifiedCurrentUndoPlanAuthorityErrorChirho>()
    {
        return Some(match refusal_chirho {
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentAppRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationCurrentAppRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationCurrentPromotionRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPlanRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationCurrentPlanRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::NoEligiblePlanEffectChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationNoEligiblePlanEffectChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::MultipleEligiblePlanEffectsChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationMultipleEligiblePlanEffectsChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::StaleAuthorityChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationStaleAuthorityChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::NoEligibleJournalEffectChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationNoEligibleJournalEffectChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::MultipleEligibleJournalEffectsChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationMultipleEligibleJournalEffectsChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::OriginalEffectEvidenceRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationOriginalEffectEvidenceRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::ProviderPreviewRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationProviderPreviewRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPriceRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationCurrentPriceRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::ExistingCompensationBindingRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExistingBindingRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationAuthorizationRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationAuthorizationRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationPendingManualChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationPendingManualChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationInDoubtChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationInDoubtChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationTerminalRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationTerminalRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermStaleWinnerRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExecutionSinkTermStaleWinnerRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermUnseenWinnerRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExecutionSinkTermUnseenWinnerRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionOrdinaryTermInputsUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExecutionOrdinaryTermInputsUnavailableChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionOrdinaryTermAcceptanceRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExecutionOrdinaryTermAcceptanceRefusedChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionCommittedEvidencePendingChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExecutionCommittedEvidencePendingChirho
            }
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionRefusedChirho => {
                TestkindCf7OperatorRefusalChirho::CompensationExecutionRefusedChirho
            }
        });
    }
    if let Some(refusal_chirho) =
        error_chirho.downcast_ref::<LedgerHostPostgresEffectRefusalChirho>()
    {
        return Some(match refusal_chirho {
            LedgerHostPostgresEffectRefusalChirho::PostgresEffectConfigUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresEffectConfigUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::ConnectionSecretUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresConnectionSecretUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::ConnectionOutsideLocalPhaseBChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresConnectionOutsideLocalPhaseBChirho
            }
            LedgerHostPostgresEffectRefusalChirho::ConnectionUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresConnectionUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::DatabaseSchemaUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresDatabaseSchemaUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::AdapterCustodyUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresAdapterCustodyUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::BillingKindUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresBillingKindUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::ProjectionRouteUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresProjectionRouteUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::ProjectionFeedUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresProjectionFeedUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::ProviderLockUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresProviderLockUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::BlockingDispatchUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresBlockingDispatchUnavailableChirho
            }
            LedgerHostPostgresEffectRefusalChirho::ForeignRootChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresForeignRootChirho
            }
        });
    }
    error_chirho
        .downcast_ref::<PostgresReversibleActivationErrorChirho>()
        .map(|refusal_chirho| match refusal_chirho {
            PostgresReversibleActivationErrorChirho::ContractLawRefusedChirho { .. } => {
                TestkindCf7OperatorRefusalChirho::PostgresContractLawRefusedChirho
            }
            PostgresReversibleActivationErrorChirho::CompositionUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresCompositionUnavailableChirho
            }
            PostgresReversibleActivationErrorChirho::VerifiedContextUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresVerifiedContextUnavailableChirho
            }
            PostgresReversibleActivationErrorChirho::InvocationScopeUnavailableChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresInvocationScopeUnavailableChirho
            }
            PostgresReversibleActivationErrorChirho::BootstrapRefusedChirho { .. } => {
                TestkindCf7OperatorRefusalChirho::PostgresBootstrapRefusedChirho
            }
            PostgresReversibleActivationErrorChirho::CustodyUnavailableChirho { .. } => {
                TestkindCf7OperatorRefusalChirho::PostgresCustodyUnavailableChirho
            }
            PostgresReversibleActivationErrorChirho::MoneyPolicyRefusedChirho { .. } => {
                TestkindCf7OperatorRefusalChirho::PostgresMoneyPolicyRefusedChirho
            }
            PostgresReversibleActivationErrorChirho::InvocationObligationConflictChirho => {
                TestkindCf7OperatorRefusalChirho::PostgresInvocationObligationConflictChirho
            }
            PostgresReversibleActivationErrorChirho::InDoubtChirho { .. } => {
                TestkindCf7OperatorRefusalChirho::PostgresProviderOutcomeInDoubtChirho
            }
        })
}
