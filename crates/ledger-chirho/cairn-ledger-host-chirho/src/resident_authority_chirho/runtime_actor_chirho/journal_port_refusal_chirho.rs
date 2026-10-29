// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exhaustive resident-authority conversion into the neutral effect-journal port.

use super::*;
use crate::reconciliation_chirho::sink_term_fence_chirho::SinkTermFenceRefusalChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitJournalAuthorityRefusalIdentityChirho,
    EffectCommitJournalCommittedEvidenceIdentityChirho,
    EffectCommitJournalResidentRefusalIdentityChirho, MAX_EFFECT_COMMIT_RECEIPT_INVENTORY_CHIRHO,
};

pub(super) fn effect_receipt_chirho(
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
) -> EffectCommitJournalReceiptChirho {
    EffectCommitJournalReceiptChirho {
        seq_chirho: receipt_chirho.append_chirho.seq_chirho,
        record_digest_chirho: receipt_chirho.append_chirho.record_digest_chirho.clone(),
        hlc_chirho: receipt_chirho.append_chirho.hlc_chirho.clone(),
    }
}

pub(super) fn bounded_inventory_chirho<EntryChirho>(
    inventory_chirho: Vec<EntryChirho>,
) -> ResidentEffectJournalResultChirho<Vec<EntryChirho>> {
    if inventory_chirho.len() > MAX_EFFECT_COMMIT_RECEIPT_INVENTORY_CHIRHO {
        return Err(resident_refused_chirho(
            EffectCommitJournalResidentRefusalIdentityChirho::InventoryBoundChirho,
            "effect journal inventory exceeds the fixed composition bound",
        ));
    }
    Ok(inventory_chirho)
}

pub(super) fn resident_refusal_chirho(
    error_chirho: ResidentLedgerAuthorityRefusalChirho,
) -> EffectCommitJournalPortErrorChirho {
    match error_chirho {
        ResidentLedgerAuthorityRefusalChirho::MirrorCommittedEvidencePendingChirho {
            receipt_chirho,
            detail_chirho,
        } => committed_pending_chirho(
            &effect_receipt_chirho(&receipt_chirho),
            EffectCommitJournalCommittedEvidenceIdentityChirho::MirrorAppendEvidencePendingChirho,
            detail_chirho,
        ),
        ResidentLedgerAuthorityRefusalChirho::CompensationFenceRefusedChirho {
            reason_chirho,
        } => {
            let identity_chirho = match reason_chirho {
                SinkTermFenceRefusalChirho::NoAcceptedWinnerTermChirho { .. } => {
                    EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermNoAcceptedWinnerChirho
                }
                SinkTermFenceRefusalChirho::StaleWinnerTermChirho { .. } => {
                    EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermStaleWinnerChirho
                }
                SinkTermFenceRefusalChirho::UnseenWinnerTermChirho { .. } => {
                    EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermUnseenWinnerChirho
                }
            };
            authority_refused_chirho(
                identity_chirho,
                format!("resident compensation sink fence refused: {reason_chirho:?}"),
            )
        }
        ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceRefusedChirho {
            detail_chirho,
        } => authority_refused_chirho(
            EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceChirho,
            format!(
                "resident ordinary-election sink-term acceptance was refused: {detail_chirho}"
            ),
        ),
        ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho => authority_refused_chirho(
            EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
            "resident ordinary-election sink-term acceptance inputs are unavailable".to_owned(),
        ),
        error_chirho @ (
            ResidentLedgerAuthorityRefusalChirho::RootGroupMismatchChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::StorageOutsideSelectedRootChirho
            | ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::LocalGenerationChangedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::StableNamespaceRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::ResidentIdentityRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::ResidentIdentityKindMismatchChirho
            | ResidentLedgerAuthorityRefusalChirho::ResidentIdentityChangedChirho
            | ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::EffectWarrantPublicationRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::ResidentLeaseRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::ExpectedGenesisRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::OpeningMembershipEpochMismatchChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::ExistingJournalWithoutVerifiedPendingIdentityChirho
            | ResidentLedgerAuthorityRefusalChirho::PendingJournalNotPristineChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::JournalCompositionRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::ResidentGenesisMismatchChirho
            | ResidentLedgerAuthorityRefusalChirho::JournalMutationRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::MembershipMutationRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldInspectionRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::Gd7CompensationLaneRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::Gd7PostCutExtensionRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::LawfulSinkTermAdvanceRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::ActivationIntentRefusedChirho
            | ResidentLedgerAuthorityRefusalChirho::ActivationStatementRefusedChirho
            | ResidentLedgerAuthorityRefusalChirho::ActivationSignatureRefusedChirho
            | ResidentLedgerAuthorityRefusalChirho::ActivationReceiptRefusedChirho
        ) => resident_refused_chirho(
            EffectCommitJournalResidentRefusalIdentityChirho::AuthorityCompositionOtherChirho,
            &error_chirho.to_string(),
        ),
        // Split out of the residual above on 2026-08-17. Three hosted windows showed node loss and
        // region loss failing at `prepare_resident_mutation_chirho` with one unattributable identity;
        // these are the groups a loss drill can plausibly be sitting in, so they now say which.
        ResidentLedgerAuthorityRefusalChirho::Gd7ReconciliationHoldActiveChirho
        | ResidentLedgerAuthorityRefusalChirho::Gd7OrdinaryWritesWithheldChirho => {
            resident_refused_chirho(
                EffectCommitJournalResidentRefusalIdentityChirho::Gd7HoldOrWithheldChirho,
                &error_chirho.to_string(),
            )
        }
        // Split out of the residual on 2026-08-18. A missing current mirror holder was arriving as
        // `AuthorityCompositionOtherChirho` -- the unattributable envelope the mirror identity work
        // existed to remove -- because resident-path refusals never pass through the adapter mapping
        // that carries `MirrorRefusedChirho`.
        ResidentLedgerAuthorityRefusalChirho::MirrorPrepareRefusedChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::MirrorReconciliationRefusedChirho { .. } => {
            resident_refused_chirho(
                EffectCommitJournalResidentRefusalIdentityChirho::MirrorPrepareOrReconciliationChirho,
                &error_chirho.to_string(),
            )
        }
        ResidentLedgerAuthorityRefusalChirho::TestkindLossWitnessExemptLaneRefusedChirho => {
            resident_refused_chirho(
                EffectCommitJournalResidentRefusalIdentityChirho::TestkindExemptLaneChirho,
                &error_chirho.to_string(),
            )
        }
        ResidentLedgerAuthorityRefusalChirho::TenantMigrationSourceFenceActiveChirho => {
            resident_refused_chirho(
                EffectCommitJournalResidentRefusalIdentityChirho::TenantMigrationFenceChirho,
                &error_chirho.to_string(),
            )
        }
        ResidentLedgerAuthorityRefusalChirho::WriterFenceRefusedChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::FenceTermMismatchChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::JournalAheadOfFenceChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfFenceChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::JournalAheadOfDurableFenceStateChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfDurableFenceStateChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfJournalChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::JournalAheadOfPublishedRaftTermChirho { .. }
        | ResidentLedgerAuthorityRefusalChirho::MembershipAheadOfPublishedRaftTermChirho { .. } => {
            resident_refused_chirho(
                EffectCommitJournalResidentRefusalIdentityChirho::FenceOrContinuityChirho,
                &error_chirho.to_string(),
            )
        }
    }
}

pub(super) fn resident_refused_chirho(
    identity_chirho: EffectCommitJournalResidentRefusalIdentityChirho,
    detail_chirho: &str,
) -> EffectCommitJournalPortErrorChirho {
    EffectCommitJournalPortErrorChirho::ResidentRefusedChirho {
        identity_chirho,
        detail_chirho: detail_chirho.to_owned(),
    }
}

fn authority_refused_chirho(
    identity_chirho: EffectCommitJournalAuthorityRefusalIdentityChirho,
    detail_chirho: String,
) -> EffectCommitJournalPortErrorChirho {
    EffectCommitJournalPortErrorChirho::AuthorityRefusedChirho {
        identity_chirho,
        detail_chirho,
    }
}

pub(super) fn refused_chirho(detail_chirho: &str) -> EffectCommitJournalPortErrorChirho {
    EffectCommitJournalPortErrorChirho::RefusedChirho {
        detail_chirho: detail_chirho.to_owned(),
    }
}

pub(super) fn unavailable_chirho(detail_chirho: &str) -> EffectCommitJournalPortErrorChirho {
    EffectCommitJournalPortErrorChirho::UnavailableChirho {
        detail_chirho: detail_chirho.to_owned(),
    }
}

pub(super) fn committed_pending_chirho(
    receipt_chirho: &EffectCommitJournalReceiptChirho,
    identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
    detail_chirho: impl Into<String>,
) -> EffectCommitJournalPortErrorChirho {
    EffectCommitJournalPortErrorChirho::CommittedEvidencePendingChirho {
        receipt_chirho: receipt_chirho.clone(),
        identity_chirho,
        detail_chirho: detail_chirho.into(),
    }
}
