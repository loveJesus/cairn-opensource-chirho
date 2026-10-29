// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Real-journal compensation storms and every compensation-specific durable cut.

use crate::test_support_chirho::*;
use crate::LedgerEffectCommitAdapterChirho;
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitCoordinatorChirho, EffectCommitCoordinatorErrorChirho,
    EffectCommitJournalPortChirho, EffectCommitJournalPortErrorChirho,
    EffectCommitJournalReceiptChirho, EffectCommitRunResultChirho, EffectIntentJournalStateChirho,
};
use cairn_effect_commit_chirho::intent_chirho::EFFECT_INTENT_KEY_PREFIX_CHIRHO;
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalDispositionChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;

#[test]
fn compensation_evidence_failure_precedes_hold_and_provider_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let original_key_chirho = original_effect_key_chirho();
    let (_, intent_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_key_chirho,
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let first_token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let retry_token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = committed_provider_chirho();
    let mut evidence_chirho = MemoryEvidenceChirho {
        fail_compensation_create_once_chirho: true,
        ..MemoryEvidenceChirho::default()
    };

    {
        let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut evidence_chirho,
            &mut adapter_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        assert!(matches!(
            coordinator_chirho.execute_compensation_chirho(&intent_line_chirho, first_token_chirho),
            Err(EffectCommitCoordinatorErrorChirho::EvidenceChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 2);
    assert_eq!(provider_chirho.execute_calls_chirho, 0);
    assert!(evidence_chirho.intent_lines_chirho.is_empty());
    assert!(evidence_chirho.compensation_intent_lines_chirho.is_empty());

    execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &intent_line_chirho,
        retry_token_chirho,
    )
    .unwrap();
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_settled_once_chirho(&journal_chirho);
}

#[test]
fn compensation_token_cannot_be_worn_by_another_signed_intent_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let original_key_chirho = original_effect_key_chirho();
    let (_, first_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_key_chirho,
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let (_, other_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_key_chirho,
        DigestChirho(DIGEST_D_CHIRHO.to_owned()),
    );
    let first_token_chirho =
        authorized_compensation_chirho(&first_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = committed_provider_chirho();
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    let error_chirho = execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &other_line_chirho,
        first_token_chirho,
    )
    .unwrap_err();
    assert!(matches!(
        error_chirho,
        EffectCommitCoordinatorErrorChirho::CompensationChirho { .. }
    ));
    assert_eq!(journal_chirho.tail_chirho().0, 2);
    assert_eq!(provider_chirho.execute_calls_chirho, 0);
    assert!(evidence_chirho.intent_lines_chirho.is_empty());
    assert!(evidence_chirho.compensation_intent_lines_chirho.is_empty());
}

#[test]
fn compensation_evidence_cut_before_hold_reloads_exact_line_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_effect_key_chirho(),
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let first_token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let retry_token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = committed_provider_chirho();
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    {
        let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut cut_chirho = CompensationHoldCutChirho {
            inner_chirho: &mut adapter_chirho,
            fail_next_chirho: true,
        };
        let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut evidence_chirho,
            &mut cut_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        assert!(matches!(
            coordinator_chirho.execute_compensation_chirho(&intent_line_chirho, first_token_chirho),
            Err(EffectCommitCoordinatorErrorChirho::JournalChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 2);
    assert_eq!(provider_chirho.execute_calls_chirho, 0);
    assert_eq!(evidence_chirho.intent_lines_chirho.len(), 1);
    assert_eq!(evidence_chirho.compensation_intent_lines_chirho.len(), 1);

    execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &intent_line_chirho,
        retry_token_chirho,
    )
    .unwrap();
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_settled_once_chirho(&journal_chirho);
}

#[test]
fn competing_compensation_intents_conflict_before_second_money_or_provider_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let original_key_chirho = original_effect_key_chirho();
    let (_, first_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_key_chirho,
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let (_, competing_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_key_chirho,
        DigestChirho(DIGEST_D_CHIRHO.to_owned()),
    );
    let first_token_chirho =
        authorized_compensation_chirho(&first_line_chirho, &harness_chirho.intent_root_chirho);
    let competing_token_chirho =
        authorized_compensation_chirho(&competing_line_chirho, &harness_chirho.intent_root_chirho);
    assert_eq!(
        first_token_chirho.compensation_key_chirho(),
        competing_token_chirho.compensation_key_chirho()
    );
    let mut provider_chirho = committed_provider_chirho();
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &first_line_chirho,
        first_token_chirho,
    )
    .unwrap();
    let tail_after_first_chirho = journal_chirho.tail_chirho().0;
    let error_chirho = execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &competing_line_chirho,
        competing_token_chirho,
    )
    .unwrap_err();
    assert!(matches!(
        error_chirho,
        EffectCommitCoordinatorErrorChirho::CompensationIntentEvidenceConflictChirho { .. }
    ));
    assert_eq!(journal_chirho.tail_chirho().0, tail_after_first_chirho);
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_eq!(evidence_chirho.compensation_intent_lines_chirho.len(), 1);
    assert_settled_once_chirho(&journal_chirho);
}

#[test]
fn compensation_transport_ambiguity_queries_same_key_and_settles_once_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_effect_key_chirho(),
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::transport_error_chirho(),
        ProviderReplyChirho::committed_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    let result_chirho = execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &intent_line_chirho,
        token_chirho,
    )
    .unwrap();
    assert!(matches!(
        result_chirho,
        EffectCommitRunResultChirho::TerminalChirho {
            disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho { .. },
            ..
        }
    ));
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_eq!(provider_chirho.query_calls_chirho, 1);
    assert_settled_once_chirho(&journal_chirho);
}

#[test]
fn compensation_provider_evidence_cut_fsck_settles_once_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_effect_key_chirho(),
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = committed_provider_chirho();
    let mut evidence_chirho = MemoryEvidenceChirho {
        fail_provider_store_once_chirho: true,
        ..MemoryEvidenceChirho::default()
    };

    let error_chirho = execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &intent_line_chirho,
        token_chirho,
    )
    .unwrap_err();
    assert!(matches!(
        error_chirho,
        EffectCommitCoordinatorErrorChirho::EvidenceChirho { .. }
    ));
    assert_eq!(journal_chirho.tail_chirho().0, 3);
    assert!(evidence_chirho.provider_bytes_chirho.is_empty());

    drop(journal_chirho);
    let mut recovered_chirho = harness_chirho.reopen_chirho();
    reconcile_chirho(
        &harness_chirho,
        &mut recovered_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
    );
    assert_eq!(recovered_chirho.tail_chirho().0, 4);
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_eq!(provider_chirho.query_calls_chirho, 1);
    assert_settled_once_chirho(&recovered_chirho);
}

#[test]
fn compensation_definite_no_effect_releases_without_meter_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_effect_key_chirho(),
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::transport_error_chirho(),
        ProviderReplyChirho::definite_no_effect_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &intent_line_chirho,
        token_chirho,
    )
    .unwrap();
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    let payer_chirho = journal_chirho
        .head_state_chirho(&account_chirho("payer-chirho"))
        .unwrap();
    assert_eq!(payer_chirho.credits_total_chirho, 100);
    assert_eq!(payer_chirho.debits_total_chirho, 0);
    assert_eq!(payer_chirho.held_chirho, 0);
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_eq!(provider_chirho.query_calls_chirho, 1);
    assert!(journal_chirho.active_effect_intent_refs_chirho().is_empty());
    assert!(journal_chirho
        .head_state_chirho(&account_chirho("platform-chirho"))
        .is_none());
}

#[test]
fn compensation_terminal_evidence_cut_fsck_settles_once_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_effect_key_chirho(),
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = committed_provider_chirho();
    let mut evidence_chirho = MemoryEvidenceChirho {
        fail_terminal_store_once_chirho: true,
        ..MemoryEvidenceChirho::default()
    };
    let error_chirho = execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &intent_line_chirho,
        token_chirho,
    )
    .unwrap_err();
    assert!(matches!(
        error_chirho,
        EffectCommitCoordinatorErrorChirho::EvidenceChirho { .. }
    ));
    assert_eq!(journal_chirho.tail_chirho().0, 3);

    drop(journal_chirho);
    let mut recovered_chirho = harness_chirho.reopen_chirho();
    reconcile_chirho(
        &harness_chirho,
        &mut recovered_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
    );
    assert_eq!(recovered_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&recovered_chirho);
}

#[test]
fn compensation_terminal_ack_loss_retries_without_second_meter_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) = signed_compensation_intent_line_chirho(
        &journal_chirho,
        &harness_chirho.intent_root_chirho,
        &original_effect_key_chirho(),
        DigestChirho(DIGEST_E_CHIRHO.to_owned()),
    );
    let first_token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let retry_token_chirho =
        authorized_compensation_chirho(&intent_line_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = committed_provider_chirho();
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    {
        let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut ack_loss_chirho = CompensationTerminalAckLossChirho {
            inner_chirho: &mut adapter_chirho,
            fail_next_chirho: true,
        };
        let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut evidence_chirho,
            &mut ack_loss_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        assert!(matches!(
            coordinator_chirho.execute_compensation_chirho(&intent_line_chirho, first_token_chirho),
            Err(EffectCommitCoordinatorErrorChirho::JournalChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&journal_chirho);

    execute_compensation_chirho(
        &harness_chirho,
        &mut journal_chirho,
        &mut provider_chirho,
        &mut evidence_chirho,
        &intent_line_chirho,
        retry_token_chirho,
    )
    .unwrap();
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_eq!(provider_chirho.execute_calls_chirho, 2);
    assert_settled_once_chirho(&journal_chirho);
}

fn original_effect_key_chirho() -> String {
    format!("{EFFECT_INTENT_KEY_PREFIX_CHIRHO}{DIGEST_A_CHIRHO}")
}

fn committed_provider_chirho() -> ScriptedProviderChirho {
    ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::committed_chirho(),
        ProviderReplyChirho::committed_chirho(),
    )
}

fn execute_compensation_chirho(
    harness_chirho: &IntegrationHarnessChirho,
    journal_chirho: &mut cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho<'_>,
    provider_chirho: &mut ScriptedProviderChirho,
    evidence_chirho: &mut MemoryEvidenceChirho,
    intent_line_chirho: &str,
    token_chirho: VerifiedEffectCompensationChirho,
) -> Result<EffectCommitRunResultChirho, EffectCommitCoordinatorErrorChirho> {
    let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
        journal_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
        provider_chirho,
        evidence_chirho,
        &mut adapter_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    coordinator_chirho.execute_compensation_chirho(intent_line_chirho, token_chirho)
}

fn reconcile_chirho(
    harness_chirho: &IntegrationHarnessChirho,
    journal_chirho: &mut cairn_ledger_log_chirho::journal_chirho::LedgerJournalChirho<'_>,
    provider_chirho: &mut ScriptedProviderChirho,
    evidence_chirho: &mut MemoryEvidenceChirho,
) {
    let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
        journal_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
        provider_chirho,
        evidence_chirho,
        &mut adapter_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    let results_chirho = coordinator_chirho.reconcile_all_in_doubt_chirho().unwrap();
    assert_eq!(results_chirho.len(), 1);
    assert!(matches!(
        &results_chirho[0],
        EffectCommitRunResultChirho::TerminalChirho { .. }
    ));
}

struct CompensationHoldCutChirho<'port_chirho> {
    inner_chirho: &'port_chirho mut dyn EffectCommitJournalPortChirho,
    fail_next_chirho: bool,
}

struct CompensationTerminalAckLossChirho<'port_chirho> {
    inner_chirho: &'port_chirho mut dyn EffectCommitJournalPortChirho,
    fail_next_chirho: bool,
}

macro_rules! delegate_read_methods_chirho {
    () => {
        fn active_hold_intent_refs_chirho(
            &self,
        ) -> Result<Vec<DigestChirho>, EffectCommitJournalPortErrorChirho> {
            self.inner_chirho.active_hold_intent_refs_chirho()
        }

        fn receipt_by_intent_ref_chirho(
            &self,
            intent_ref_chirho: &DigestChirho,
        ) -> Result<Option<EffectIntentJournalStateChirho>, EffectCommitJournalPortErrorChirho> {
            self.inner_chirho
                .receipt_by_intent_ref_chirho(intent_ref_chirho)
        }
    };
}

impl EffectCommitJournalPortChirho for CompensationHoldCutChirho<'_> {
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.inner_chirho
            .append_hold_chirho(canonical_intent_line_chirho)
    }

    fn append_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        if self.fail_next_chirho {
            self.fail_next_chirho = false;
            return Err(EffectCommitJournalPortErrorChirho::UnavailableChirho {
                detail_chirho: "injected compensation Hold cut".to_owned(),
            });
        }
        self.inner_chirho
            .append_compensation_hold_chirho(canonical_intent_line_chirho, authorization_chirho)
    }

    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.inner_chirho
            .append_terminal_chirho(canonical_intent_line_chirho, canonical_terminal_line_chirho)
    }

    delegate_read_methods_chirho!();
}

impl EffectCommitJournalPortChirho for CompensationTerminalAckLossChirho<'_> {
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.inner_chirho
            .append_hold_chirho(canonical_intent_line_chirho)
    }

    fn append_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.inner_chirho
            .append_compensation_hold_chirho(canonical_intent_line_chirho, authorization_chirho)
    }

    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        let receipt_chirho = self
            .inner_chirho
            .append_terminal_chirho(canonical_intent_line_chirho, canonical_terminal_line_chirho)?;
        if self.fail_next_chirho {
            self.fail_next_chirho = false;
            return Err(EffectCommitJournalPortErrorChirho::UnavailableChirho {
                detail_chirho: "injected compensation terminal acknowledgement loss".to_owned(),
            });
        }
        Ok(receipt_chirho)
    }

    delegate_read_methods_chirho!();
}
