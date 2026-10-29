// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::tests_chirho::{
    postgres_node_chirho, request_bytes_chirho, run_scoped_postgres_node_chirho,
    setup_context_chirho, tmp_root_chirho, JournalHarnessChirho, MemoryPostgresDatabaseChirho,
    ScopedPostgresNodeInputsChirho, APP_PRICE_POLICY_CHIRHO, MONEY_KIND_CHIRHO,
};
use super::*;
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitContinuationViewChirho, EffectCommitJournalPortChirho,
    EffectCommitJournalPortErrorChirho, EffectCommitJournalReceiptChirho,
    EffectCommitJournalViewPortChirho, EffectIntentJournalStateChirho,
    VerifiedEffectReceiptInventoryEntryChirho,
};
use cairn_effect_commit_chirho::intent_chirho::EffectIntentJournalCutChirho;
use cairn_effect_commit_ledger_chirho::LedgerEffectCommitAdapterChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, DigestChirho};
use std::sync::{Arc, Mutex};

struct TerminalCommittedEvidenceJournalChirho<'adapter_chirho, 'ports_chirho> {
    delegate_chirho: LedgerEffectCommitAdapterChirho<'adapter_chirho, 'ports_chirho>,
    identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
}

impl EffectCommitJournalPortChirho for TerminalCommittedEvidenceJournalChirho<'_, '_> {
    fn append_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.delegate_chirho
            .append_hold_chirho(canonical_intent_line_chirho)
    }

    fn append_compensation_hold_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        authorization_chirho: &VerifiedEffectCompensationChirho,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.delegate_chirho
            .append_compensation_hold_chirho(canonical_intent_line_chirho, authorization_chirho)
    }

    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        let receipt_chirho = self
            .delegate_chirho
            .append_terminal_chirho(canonical_intent_line_chirho, canonical_terminal_line_chirho)?;
        Err(
            EffectCommitJournalPortErrorChirho::CommittedEvidencePendingChirho {
                receipt_chirho,
                identity_chirho: self.identity_chirho,
                detail_chirho: "/private/committed-evidence-origin-needle-chirho".to_owned(),
            },
        )
    }

    fn active_hold_intent_refs_chirho(
        &self,
    ) -> Result<Vec<DigestChirho>, EffectCommitJournalPortErrorChirho> {
        self.delegate_chirho.active_hold_intent_refs_chirho()
    }

    fn receipt_by_intent_ref_chirho(
        &self,
        intent_ref_chirho: &DigestChirho,
    ) -> Result<Option<EffectIntentJournalStateChirho>, EffectCommitJournalPortErrorChirho> {
        self.delegate_chirho
            .receipt_by_intent_ref_chirho(intent_ref_chirho)
    }
}

impl EffectCommitJournalViewPortChirho for TerminalCommittedEvidenceJournalChirho<'_, '_> {
    fn effect_intent_cut_chirho(
        &self,
    ) -> Result<EffectIntentJournalCutChirho, EffectCommitJournalPortErrorChirho> {
        self.delegate_chirho.effect_intent_cut_chirho()
    }

    fn current_continuation_chirho(
        &self,
        kind_id_chirho: &AssetKindIdChirho,
    ) -> Result<Option<EffectCommitContinuationViewChirho>, EffectCommitJournalPortErrorChirho>
    {
        self.delegate_chirho
            .current_continuation_chirho(kind_id_chirho)
    }

    fn verified_effect_receipt_inventory_chirho(
        &self,
    ) -> Result<Vec<VerifiedEffectReceiptInventoryEntryChirho>, EffectCommitJournalPortErrorChirho>
    {
        self.delegate_chirho
            .verified_effect_receipt_inventory_chirho()
    }
}

#[test]
fn committed_evidence_origin_reaches_the_detail_free_leader_log_chirho() {
    let root_chirho = tmp_root_chirho();
    let context_chirho = setup_context_chirho(&root_chirho);
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let node_chirho = postgres_node_chirho();
    let node_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (request_bytes_chirho, _subject_chirho, _row_key_chirho) =
        request_bytes_chirho(&root_chirho);
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut database_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let run_chirho = HashChirho("8".repeat(64));
    let captured_lines_chirho = Arc::new(Mutex::new(Vec::new()));
    let origin_identity_chirho =
        EffectCommitJournalCommittedEvidenceIdentityChirho::JournalDenseTailTransitionEvidencePendingChirho;

    let error_chirho = {
        let journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut pending_journal_chirho = TerminalCommittedEvidenceJournalChirho {
            delegate_chirho: journal_adapter_chirho,
            identity_chirho: origin_identity_chirho,
        };
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut pending_journal_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        )
        .unwrap()
        .with_committed_evidence_log_capture_chirho(Arc::clone(&captured_lines_chirho));
        run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            false,
            &mut runtime_chirho,
        )
        .expect_err("the terminal receipt fixture returns committed evidence pending")
    };
    assert!(error_chirho.chain().any(|cause_chirho| cause_chirho
        .downcast_ref::<EffectCommitCoordinatorErrorChirho>()
        .is_some_and(|error_chirho| matches!(
            error_chirho,
            EffectCommitCoordinatorErrorChirho::JournalCommittedEvidencePendingChirho {
                identity_chirho,
                ..
            } if *identity_chirho == origin_identity_chirho
        ))));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert_eq!(
        *captured_lines_chirho
            .lock()
            .expect("read committed-evidence origin capture"),
        vec![format!(
            "CairnResidentCommittedEvidencePendingChirho:identity_chirho={}",
            origin_identity_chirho.as_str_chirho()
        )]
    );
    assert!(!captured_lines_chirho
        .lock()
        .expect("read detail-free committed-evidence capture")
        .iter()
        .any(|line_chirho| line_chirho.contains("/private/")));
    let _ = std::fs::remove_dir_all(root_chirho);
}
