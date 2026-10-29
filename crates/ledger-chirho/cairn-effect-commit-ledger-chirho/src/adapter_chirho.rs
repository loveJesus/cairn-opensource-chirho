// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Logic-free implementation of the CF3 coordinator's journal port over one real ledger journal.

use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitContinuationViewChirho, EffectCommitJournalMirrorRefusalIdentityChirho,
    EffectCommitJournalPortChirho, EffectCommitJournalPortErrorChirho,
    EffectCommitJournalReceiptChirho, EffectCommitJournalViewPortChirho,
    EffectIntentJournalStateChirho, VerifiedEffectReceiptInventoryEntryChirho,
    MAX_EFFECT_COMMIT_RECEIPT_INVENTORY_CHIRHO,
};
use cairn_effect_commit_chirho::intent_chirho::EffectIntentSignerPortChirho;
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalSignerPortChirho;
use cairn_ledger_log_chirho::journal_chirho::{
    AppendReceiptChirho, JournalErrorChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::EffectCompensationJournalErrorChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};

/// The write-integration twin of `cairn-ledger-composition-chirho`'s read composition.
///
/// This adapter owns no defaults, policy resolution, provider ordering, or receipt law. It only
/// supplies the two injected verification roots to the journal's dedicated doors and translates
/// their typed result into the leaf coordinator's narrow port vocabulary.
pub struct LedgerEffectCommitAdapterChirho<'adapter_chirho, 'ports_chirho> {
    journal_chirho: &'adapter_chirho mut LedgerJournalChirho<'ports_chirho>,
    intent_verifier_chirho: &'adapter_chirho dyn EffectIntentSignerPortChirho,
    terminal_verifier_chirho: &'adapter_chirho dyn EffectTerminalSignerPortChirho,
}

impl<'adapter_chirho, 'ports_chirho>
    LedgerEffectCommitAdapterChirho<'adapter_chirho, 'ports_chirho>
{
    pub fn new_chirho(
        journal_chirho: &'adapter_chirho mut LedgerJournalChirho<'ports_chirho>,
        intent_verifier_chirho: &'adapter_chirho dyn EffectIntentSignerPortChirho,
        terminal_verifier_chirho: &'adapter_chirho dyn EffectTerminalSignerPortChirho,
    ) -> Self {
        Self {
            journal_chirho,
            intent_verifier_chirho,
            terminal_verifier_chirho,
        }
    }
}

impl EffectCommitJournalPortChirho for LedgerEffectCommitAdapterChirho<'_, '_> {
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.journal_chirho
            .append_effect_intent_chirho(canonical_intent_line_chirho, self.intent_verifier_chirho)
            .map(receipt_chirho)
            .map_err(port_error_chirho)
    }

    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    fn append_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.journal_chirho
            .append_effect_compensation_chirho(
                canonical_intent_line_chirho,
                self.intent_verifier_chirho,
                authorization_chirho,
            )
            .map(receipt_chirho)
            .map_err(compensation_port_error_chirho)
    }

    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf3-effect-commit-second-seat-chirho.md`.
    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.journal_chirho
            .append_effect_terminal_chirho(
                canonical_intent_line_chirho,
                self.intent_verifier_chirho,
                canonical_terminal_line_chirho,
                self.terminal_verifier_chirho,
            )
            .map(receipt_chirho)
            .map_err(port_error_chirho)
    }

    fn active_hold_intent_refs_chirho(
        &self,
    ) -> Result<Vec<DigestChirho>, EffectCommitJournalPortErrorChirho> {
        let refs_chirho = self.journal_chirho.active_effect_intent_refs_chirho();
        if refs_chirho.len() > MAX_EFFECT_COMMIT_RECEIPT_INVENTORY_CHIRHO {
            return Err(EffectCommitJournalPortErrorChirho::RefusedChirho {
                detail_chirho: "active effect Hold inventory exceeds the bounded composition limit"
                    .to_owned(),
            });
        }
        Ok(refs_chirho)
    }

    fn receipt_by_intent_ref_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<EffectIntentJournalStateChirho>, EffectCommitJournalPortErrorChirho> {
        Ok(self
            .journal_chirho
            .effect_intent_journal_state_chirho(intent_ref_chirho))
    }
}

impl EffectCommitJournalViewPortChirho for LedgerEffectCommitAdapterChirho<'_, '_> {
    fn effect_intent_cut_chirho(
        &self,
    ) -> Result<
        cairn_effect_commit_chirho::intent_chirho::EffectIntentJournalCutChirho,
        EffectCommitJournalPortErrorChirho,
    > {
        Ok(self.journal_chirho.effect_intent_cut_chirho())
    }

    fn current_continuation_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Result<Option<EffectCommitContinuationViewChirho>, EffectCommitJournalPortErrorChirho>
    {
        Ok(self
            .journal_chirho
            .current_continuation_chirho(kind_id_chirho)
            .map(|continuation_chirho| EffectCommitContinuationViewChirho {
                kind_id_chirho: continuation_chirho.policy_chirho.kind_id_chirho,
                kind_policy_ref_chirho: continuation_chirho.kind_policy_ref_chirho,
                settlement_owner_present_chirho: continuation_chirho
                    .policy_chirho
                    .settlement_owner_chirho
                    .is_some(),
            }))
    }

    fn verified_effect_receipt_inventory_chirho(
        &self,
    ) -> Result<Vec<VerifiedEffectReceiptInventoryEntryChirho>, EffectCommitJournalPortErrorChirho>
    {
        let inventory_chirho = self
            .journal_chirho
            .verified_effect_receipt_inventory_chirho();
        if inventory_chirho.len() > MAX_EFFECT_COMMIT_RECEIPT_INVENTORY_CHIRHO {
            return Err(EffectCommitJournalPortErrorChirho::RefusedChirho {
                detail_chirho: "effect receipt inventory exceeds the bounded composition limit"
                    .to_owned(),
            });
        }
        Ok(inventory_chirho)
    }
}

fn receipt_chirho(receipt_chirho: AppendReceiptChirho) -> EffectCommitJournalReceiptChirho {
    EffectCommitJournalReceiptChirho {
        seq_chirho: receipt_chirho.seq_chirho,
        record_digest_chirho: receipt_chirho.record_digest_chirho,
        hlc_chirho: receipt_chirho.hlc_chirho,
    }
}

fn port_error_chirho(error_chirho: JournalErrorChirho) -> EffectCommitJournalPortErrorChirho {
    let detail_chirho = format!("{error_chirho:?}");
    match error_chirho {
        JournalErrorChirho::EffectTerminalConflictChirho { .. } => {
            EffectCommitJournalPortErrorChirho::ConflictChirho { detail_chirho }
        }
        JournalErrorChirho::StorageChirho { .. } | JournalErrorChirho::SignerChirho { .. } => {
            EffectCommitJournalPortErrorChirho::UnavailableChirho { detail_chirho }
        }
        // The MIRROR family is reported separately from the generic refusal. Collapsing these three
        // into `RefusedChirho` alongside thirteen unrelated errors is what made the node-loss and
        // region-loss drills undiagnosable: both surfaced as a bare `current-envelope-refused-chirho`
        // with no observed witness outcome, and a lawful mirror refusal was indistinguishable from a
        // stale intent or an invalid tail signature.
        JournalErrorChirho::MirrorPrepareRefusedChirho { .. } => {
            EffectCommitJournalPortErrorChirho::MirrorRefusedChirho {
                identity_chirho:
                    EffectCommitJournalMirrorRefusalIdentityChirho::PrepareRefusedChirho,
                detail_chirho,
            }
        }
        JournalErrorChirho::MirrorReconciliationRefusedChirho { .. } => {
            EffectCommitJournalPortErrorChirho::MirrorRefusedChirho {
                identity_chirho:
                    EffectCommitJournalMirrorRefusalIdentityChirho::ReconciliationRefusedChirho,
                detail_chirho,
            }
        }
        JournalErrorChirho::MirrorCommittedEvidencePendingChirho { .. } => {
            EffectCommitJournalPortErrorChirho::MirrorRefusedChirho {
                identity_chirho:
                    EffectCommitJournalMirrorRefusalIdentityChirho::CommittedEvidencePendingChirho,
                detail_chirho,
            }
        }
        JournalErrorChirho::WireChirho { .. }
        | JournalErrorChirho::AppendRequestBoundsChirho { .. }
        | JournalErrorChirho::AppendRequestPreflightChirho { .. }
        | JournalErrorChirho::ChainChirho { .. }
        | JournalErrorChirho::TornTailChirho
        | JournalErrorChirho::ReadOnlyRecoveryRequiredChirho { .. }
        | JournalErrorChirho::ReadOnlyExactCheckpointRequiredChirho
        | JournalErrorChirho::ReadOnlyExactCheckpointTailRefusedChirho { .. }
        | JournalErrorChirho::TailSignatureInvalidChirho
        | JournalErrorChirho::AdmissionChirho { .. }
        | JournalErrorChirho::EffectIntentChirho { .. }
        | JournalErrorChirho::EffectTerminalChirho { .. }
        | JournalErrorChirho::StaleIntentChirho { .. }
        | JournalErrorChirho::StaleEffectTerminalChirho { .. } => {
            EffectCommitJournalPortErrorChirho::RefusedChirho { detail_chirho }
        }
    }
}

fn compensation_port_error_chirho(
    error_chirho: EffectCompensationJournalErrorChirho,
) -> EffectCommitJournalPortErrorChirho {
    match error_chirho {
        EffectCompensationJournalErrorChirho::IntentConflictChirho { .. } => {
            EffectCommitJournalPortErrorChirho::ConflictChirho {
                detail_chirho: error_chirho.to_string(),
            }
        }
        EffectCompensationJournalErrorChirho::JournalChirho(error_chirho) => {
            port_error_chirho(error_chirho)
        }
    }
}
