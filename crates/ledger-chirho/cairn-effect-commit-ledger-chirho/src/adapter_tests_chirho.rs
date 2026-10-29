// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Real-journal CF3 composition: exactly-once meter, in-doubt fsck, definite-no-effect release,
//! terminal-ack ambiguity, and verified reopen at every durable cut exercised here.

use crate::test_support_chirho::*;
use crate::LedgerEffectCommitAdapterChirho;
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    verify_effect_cache_hit_chirho, EffectCacheHitCandidateChirho,
    EffectCacheHitVerifierPortChirho, EffectCommitCoordinatorChirho,
    EffectCommitCoordinatorErrorChirho, EffectCommitJournalPortChirho,
    EffectCommitJournalPortErrorChirho, EffectCommitJournalReceiptChirho,
    EffectCommitRunResultChirho, EffectIntentJournalStateChirho,
};
use cairn_effect_commit_chirho::intent_chirho::{
    effect_intent_ref_chirho, VerifiedEffectIntentChirho,
};
use cairn_effect_commit_chirho::terminal_chirho::EffectTerminalDispositionChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;

#[test]
fn committed_effect_and_meter_are_exactly_once_across_retry_and_reopen_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (intent_chirho, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::committed_chirho(),
        ProviderReplyChirho::committed_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    let (first_terminal_receipt_chirho, first_outcome_ref_chirho) = {
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
        let first_chirho = coordinator_chirho
            .execute_chirho(&intent_line_chirho)
            .unwrap();
        let (first_hold_receipt_chirho, first_terminal_receipt_chirho, first_outcome_ref_chirho) =
            terminal_result_chirho(first_chirho);
        assert_eq!(first_hold_receipt_chirho.seq_chirho, 3);
        assert_eq!(first_terminal_receipt_chirho.seq_chirho, 4);

        let retry_chirho = coordinator_chirho
            .execute_chirho(&intent_line_chirho)
            .unwrap();
        let (_, retry_terminal_receipt_chirho, retry_outcome_ref_chirho) =
            terminal_result_chirho(retry_chirho);
        assert_eq!(retry_terminal_receipt_chirho, first_terminal_receipt_chirho);
        assert_eq!(retry_outcome_ref_chirho, first_outcome_ref_chirho);
        (first_terminal_receipt_chirho, first_outcome_ref_chirho)
    };

    assert_eq!(provider_chirho.execute_calls_chirho, 2);
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&journal_chirho);
    assert!(journal_chirho.active_effect_intent_refs_chirho().is_empty());
    let state_chirho = journal_chirho
        .effect_intent_journal_state_chirho(&intent_ref_chirho)
        .unwrap();
    assert_eq!(state_chirho.receipt_chirho, first_terminal_receipt_chirho);
    assert_eq!(
        state_chirho.terminal_outcome_ref_chirho,
        Some(first_outcome_ref_chirho)
    );
    assert_eq!(evidence_chirho.intent_lines_chirho.len(), 1);
    assert_eq!(evidence_chirho.provider_bytes_chirho.len(), 1);
    assert_eq!(evidence_chirho.terminal_lines_chirho.len(), 1);

    drop(journal_chirho);
    let reopened_chirho = harness_chirho.reopen_chirho();
    assert_eq!(reopened_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&reopened_chirho);
    assert_eq!(
        reopened_chirho
            .effect_intent_journal_state_chirho(&intent_ref_chirho)
            .unwrap()
            .receipt_chirho,
        first_terminal_receipt_chirho
    );
}

struct IntegrationCacheVerifierChirho;

impl EffectCacheHitVerifierPortChirho for IntegrationCacheVerifierChirho {
    fn verify_chirho(
        &self,
        intent_chirho: &VerifiedEffectIntentChirho,
        result_ref_chirho: &DigestChirho,
        evidence_bytes_chirho: &[u8],
    ) -> bool {
        intent_chirho.intent_chirho().request_ref_chirho == DigestChirho(DIGEST_E_CHIRHO.to_owned())
            && result_ref_chirho == &DigestChirho(DIGEST_B_CHIRHO.to_owned())
            && evidence_bytes_chirho == b"verified-cache-hit-evidence-chirho"
    }
}

fn cache_candidate_chirho() -> EffectCacheHitCandidateChirho {
    EffectCacheHitCandidateChirho::new_chirho(
        DigestChirho(DIGEST_B_CHIRHO.to_owned()),
        b"verified-cache-hit-evidence-chirho".to_vec(),
    )
    .unwrap()
}

#[test]
fn verified_cache_hit_meters_once_without_provider_io_on_real_journal_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let first_cache_hit_chirho = verify_effect_cache_hit_chirho(
        &intent_line_chirho,
        &harness_chirho.intent_root_chirho,
        cache_candidate_chirho(),
        &IntegrationCacheVerifierChirho,
    )
    .unwrap();
    let retry_cache_hit_chirho = verify_effect_cache_hit_chirho(
        &intent_line_chirho,
        &harness_chirho.intent_root_chirho,
        cache_candidate_chirho(),
        &IntegrationCacheVerifierChirho,
    )
    .unwrap();
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::committed_chirho(),
        ProviderReplyChirho::committed_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

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
        let first_chirho = coordinator_chirho
            .execute_verified_cache_hit_chirho(&intent_line_chirho, first_cache_hit_chirho)
            .unwrap();
        assert!(matches!(
            first_chirho,
            EffectCommitRunResultChirho::TerminalChirho {
                disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho { .. },
                ..
            }
        ));
        let retry_chirho = coordinator_chirho
            .execute_verified_cache_hit_chirho(&intent_line_chirho, retry_cache_hit_chirho)
            .unwrap();
        assert!(matches!(
            retry_chirho,
            EffectCommitRunResultChirho::TerminalChirho { .. }
        ));
    }

    assert_eq!(provider_chirho.execute_calls_chirho, 0);
    assert_eq!(provider_chirho.query_calls_chirho, 0);
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&journal_chirho);
    assert_eq!(evidence_chirho.intent_lines_chirho.len(), 1);
    assert_eq!(evidence_chirho.provider_bytes_chirho.len(), 1);
    assert_eq!(evidence_chirho.terminal_lines_chirho.len(), 1);

    drop(journal_chirho);
    let reopened_chirho = harness_chirho.reopen_chirho();
    assert_eq!(reopened_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&reopened_chirho);
}

#[test]
fn transport_ambiguity_queries_committed_and_terminalizes_once_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::transport_error_chirho(),
        ProviderReplyChirho::committed_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
        &mut journal_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    let result_chirho = EffectCommitCoordinatorChirho::new_chirho(
        &mut provider_chirho,
        &mut evidence_chirho,
        &mut adapter_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    )
    .execute_chirho(&intent_line_chirho)
    .unwrap();
    assert!(matches!(
        result_chirho,
        EffectCommitRunResultChirho::TerminalChirho {
            disposition_chirho: EffectTerminalDispositionChirho::CommittedChirho { .. },
            ..
        }
    ));
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_eq!(provider_chirho.query_calls_chirho, 1);
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&journal_chirho);
}

#[test]
fn unresolved_transport_ambiguity_survives_crash_then_fsck_terminalizes_once_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (intent_chirho, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let intent_ref_chirho = effect_intent_ref_chirho(&intent_chirho).unwrap();
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::transport_error_chirho(),
        ProviderReplyChirho::transport_error_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

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
            coordinator_chirho.execute_chirho(&intent_line_chirho),
            Ok(EffectCommitRunResultChirho::InDoubtChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 3);
    assert_eq!(
        journal_chirho.active_effect_intent_refs_chirho(),
        vec![intent_ref_chirho.clone()]
    );
    provider_chirho.query_reply_chirho = ProviderReplyChirho::committed_chirho();

    drop(journal_chirho);
    let mut recovered_chirho = harness_chirho.reopen_chirho();
    {
        let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut recovered_chirho,
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
        let recovered_results_chirho = coordinator_chirho.reconcile_all_in_doubt_chirho().unwrap();
        assert_eq!(recovered_results_chirho.len(), 1);
        assert!(matches!(
            &recovered_results_chirho[0],
            EffectCommitRunResultChirho::TerminalChirho { .. }
        ));
        assert!(coordinator_chirho
            .reconcile_all_in_doubt_chirho()
            .unwrap()
            .is_empty());
    }
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_eq!(provider_chirho.query_calls_chirho, 2);
    assert_eq!(recovered_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&recovered_chirho);
    assert!(recovered_chirho
        .active_effect_intent_refs_chirho()
        .is_empty());
}

#[test]
fn definite_no_effect_releases_real_hold_without_metering_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::transport_error_chirho(),
        ProviderReplyChirho::definite_no_effect_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();
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
        let result_chirho = coordinator_chirho
            .execute_chirho(&intent_line_chirho)
            .unwrap();
        assert!(matches!(
            result_chirho,
            EffectCommitRunResultChirho::TerminalChirho {
                disposition_chirho: EffectTerminalDispositionChirho::DefiniteNoEffectChirho,
                ..
            }
        ));
    }
    let payer_chirho = journal_chirho
        .head_state_chirho(&account_chirho("payer-chirho"))
        .unwrap();
    assert_eq!(payer_chirho.held_chirho, 0);
    assert_eq!(payer_chirho.debits_total_chirho, 0);
    assert!(journal_chirho
        .head_state_chirho(&account_chirho("platform-chirho"))
        .is_none());
    assert!(journal_chirho.active_effect_intent_refs_chirho().is_empty());
    assert_eq!(provider_chirho.execute_calls_chirho, 1);
    assert_eq!(provider_chirho.query_calls_chirho, 1);
}

#[test]
fn terminal_ack_loss_retries_same_committed_meter_without_second_append_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::committed_chirho(),
        ProviderReplyChirho::committed_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    {
        let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut ack_loss_chirho = TerminalAckLossChirho {
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
            coordinator_chirho.execute_chirho(&intent_line_chirho),
            Err(EffectCommitCoordinatorErrorChirho::JournalChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&journal_chirho);

    let tail_after_ambiguous_ack_chirho = journal_chirho.tail_chirho().0;
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
            coordinator_chirho.execute_chirho(&intent_line_chirho),
            Ok(EffectCommitRunResultChirho::TerminalChirho { .. })
        ));
    }
    assert_eq!(
        journal_chirho.tail_chirho().0,
        tail_after_ambiguous_ack_chirho
    );
    assert_settled_once_chirho(&journal_chirho);

    drop(journal_chirho);
    let reopened_chirho = harness_chirho.reopen_chirho();
    assert_eq!(reopened_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&reopened_chirho);
}

#[test]
fn intent_evidence_cut_before_hold_retries_without_orphaning_money_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::committed_chirho(),
        ProviderReplyChirho::committed_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho::default();

    {
        let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut hold_cut_chirho = HoldPreAppendCutChirho {
            inner_chirho: &mut adapter_chirho,
            fail_next_chirho: true,
        };
        let mut coordinator_chirho = EffectCommitCoordinatorChirho::new_chirho(
            &mut provider_chirho,
            &mut evidence_chirho,
            &mut hold_cut_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        assert!(matches!(
            coordinator_chirho.execute_chirho(&intent_line_chirho),
            Err(EffectCommitCoordinatorErrorChirho::JournalChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 2);
    assert_eq!(evidence_chirho.intent_lines_chirho.len(), 1);
    assert_eq!(provider_chirho.execute_calls_chirho, 0);

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
            coordinator_chirho.execute_chirho(&intent_line_chirho),
            Ok(EffectCommitRunResultChirho::TerminalChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&journal_chirho);
}

#[test]
fn terminal_evidence_cut_before_money_is_recovered_by_fsck_chirho() {
    let harness_chirho = IntegrationHarnessChirho::new_chirho();
    let mut journal_chirho = harness_chirho.funded_journal_chirho();
    let (_, intent_line_chirho) =
        signed_intent_line_chirho(&journal_chirho, &harness_chirho.intent_root_chirho);
    let mut provider_chirho = ScriptedProviderChirho::new_chirho(
        ProviderReplyChirho::committed_chirho(),
        ProviderReplyChirho::committed_chirho(),
    );
    let mut evidence_chirho = MemoryEvidenceChirho {
        fail_terminal_store_once_chirho: true,
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
            coordinator_chirho.execute_chirho(&intent_line_chirho),
            Err(EffectCommitCoordinatorErrorChirho::EvidenceChirho { .. })
        ));
    }
    assert_eq!(journal_chirho.tail_chirho().0, 3);
    assert_eq!(evidence_chirho.provider_bytes_chirho.len(), 1);
    assert!(evidence_chirho.terminal_lines_chirho.is_empty());
    assert_eq!(journal_chirho.active_effect_intent_refs_chirho().len(), 1);

    drop(journal_chirho);
    let mut recovered_chirho = harness_chirho.reopen_chirho();
    {
        let mut adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut recovered_chirho,
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
        let results_chirho = coordinator_chirho.reconcile_all_in_doubt_chirho().unwrap();
        assert_eq!(results_chirho.len(), 1);
        assert!(matches!(
            &results_chirho[0],
            EffectCommitRunResultChirho::TerminalChirho { .. }
        ));
    }
    assert_eq!(recovered_chirho.tail_chirho().0, 4);
    assert_settled_once_chirho(&recovered_chirho);
    assert_eq!(evidence_chirho.terminal_lines_chirho.len(), 1);
}

#[test]
fn integration_crate_dependency_direction_stays_downward_chirho() {
    let manifest_chirho = include_str!("../Cargo.toml");
    assert!(manifest_chirho.contains("cairn-effect-commit-chirho"));
    assert!(manifest_chirho.contains("cairn-ledger-log-chirho"));
    assert!(!manifest_chirho.contains("cairn-ledger-read-model-chirho"));
}

fn terminal_result_chirho(
    result_chirho: EffectCommitRunResultChirho,
) -> (
    EffectCommitJournalReceiptChirho,
    EffectCommitJournalReceiptChirho,
    DigestChirho,
) {
    match result_chirho {
        EffectCommitRunResultChirho::TerminalChirho {
            hold_receipt_chirho,
            terminal_receipt_chirho,
            outcome_ref_chirho,
            ..
        } => (
            hold_receipt_chirho,
            terminal_receipt_chirho,
            outcome_ref_chirho,
        ),
        EffectCommitRunResultChirho::InDoubtChirho { .. } => {
            panic!("expected terminal coordinator result")
        }
    }
}

struct TerminalAckLossChirho<'port_chirho> {
    inner_chirho: &'port_chirho mut dyn EffectCommitJournalPortChirho,
    fail_next_chirho: bool,
}

struct HoldPreAppendCutChirho<'port_chirho> {
    inner_chirho: &'port_chirho mut dyn EffectCommitJournalPortChirho,
    fail_next_chirho: bool,
}

impl EffectCommitJournalPortChirho for HoldPreAppendCutChirho<'_> {
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        if self.fail_next_chirho {
            self.fail_next_chirho = false;
            return Err(EffectCommitJournalPortErrorChirho::UnavailableChirho {
                detail_chirho: "injected cut before Hold append".to_owned(),
            });
        }
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
                detail_chirho: "injected cut before compensation Hold append".to_owned(),
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
}

impl EffectCommitJournalPortChirho for TerminalAckLossChirho<'_> {
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
                detail_chirho: "injected terminal acknowledgement loss".to_owned(),
            });
        }
        Ok(receipt_chirho)
    }

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
}
