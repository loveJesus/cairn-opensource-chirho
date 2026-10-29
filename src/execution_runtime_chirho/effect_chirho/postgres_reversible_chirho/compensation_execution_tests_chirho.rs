// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::super::compensation_authority_chirho::{
    mint_verified_current_undo_plan_authority_chirho, promoted_postgres_app_chirho,
};
use super::super::tests_chirho::{
    run_scoped_postgres_node_chirho, JournalHarnessChirho, MemoryPostgresDatabaseChirho,
    ScopedPostgresNodeInputsChirho, APP_PRICE_POLICY_CHIRHO, MONEY_KIND_CHIRHO,
    SETTLEMENT_OWNER_CHIRHO,
};
use super::*;
use crate::identity_chirho;
use crate::model_chirho::{DagChirho, HashChirho, NodeDefChirho, RequestContextChirho};
use cairn_effect_commit_chirho::compensation_chirho::VerifiedEffectCompensationChirho;
use cairn_effect_commit_chirho::coordinator_chirho::{
    EffectCommitContinuationViewChirho, EffectCommitJournalCommittedEvidenceIdentityChirho,
    EffectCommitJournalPortChirho, EffectCommitJournalPortErrorChirho,
    EffectCommitJournalReceiptChirho, EffectCommitJournalViewPortChirho,
    EffectIntentJournalStateChirho, VerifiedEffectReceiptInventoryEntryChirho,
};
use cairn_effect_commit_chirho::intent_chirho::EffectIntentJournalCutChirho;
use cairn_effect_commit_ledger_chirho::LedgerEffectCommitAdapterChirho;
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_postgres_effect_chirho::{
    canonical_request_bytes_chirho, DesiredPostgresStateChirho, ExpectedPostgresStateChirho,
    ReversiblePostgresRequestChirho,
};

struct SiteCRefusingJournalChirho<'adapter_chirho, 'ports_chirho> {
    delegate_chirho: LedgerEffectCommitAdapterChirho<'adapter_chirho, 'ports_chirho>,
    next_compensation_refusal_chirho: Option<EffectCommitJournalPortErrorChirho>,
}

impl EffectCommitJournalPortChirho for SiteCRefusingJournalChirho<'_, '_> {
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
        if let Some(refusal_chirho) = self.next_compensation_refusal_chirho.take() {
            return Err(refusal_chirho);
        }
        self.delegate_chirho
            .append_compensation_hold_chirho(canonical_intent_line_chirho, authorization_chirho)
    }

    fn append_terminal_chirho(
        &mut self,
        canonical_intent_line_chirho: &str,
        canonical_terminal_line_chirho: &str,
    ) -> Result<EffectCommitJournalReceiptChirho, EffectCommitJournalPortErrorChirho> {
        self.delegate_chirho
            .append_terminal_chirho(canonical_intent_line_chirho, canonical_terminal_line_chirho)
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

impl EffectCommitJournalViewPortChirho for SiteCRefusingJournalChirho<'_, '_> {
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
fn site_c_maps_only_fixed_authority_identity_and_keeps_committed_pending_distinct_chirho() {
    let planted_private_detail_chirho = "/private/site-c-detail-needle-chirho";
    let cases_chirho = [
        (
            EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermNoAcceptedWinnerChirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermNoAcceptedWinnerRefusedChirho,
        ),
        (
            EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermStaleWinnerChirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermStaleWinnerRefusedChirho,
        ),
        (
            EffectCommitJournalAuthorityRefusalIdentityChirho::SinkTermUnseenWinnerChirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermUnseenWinnerRefusedChirho,
        ),
        (
            EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionOrdinaryTermInputsUnavailableChirho,
        ),
        (
            EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceChirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionOrdinaryTermAcceptanceRefusedChirho,
        ),
    ];
    for (identity_chirho, expected_chirho) in cases_chirho {
        let observed_chirho = map_compensation_execution_refusal_chirho(
            EffectCommitCoordinatorErrorChirho::JournalAuthorityRefusedChirho {
                identity_chirho,
                detail_chirho: planted_private_detail_chirho.to_owned(),
            },
        );
        assert_eq!(observed_chirho, expected_chirho);
        assert!(
            !observed_chirho
                .to_string()
                .contains(planted_private_detail_chirho),
            "Site C must inspect only the typed identity and discard private local detail"
        );
    }

    let committed_pending_chirho = map_compensation_execution_refusal_chirho(
        EffectCommitCoordinatorErrorChirho::JournalCommittedEvidencePendingChirho {
            receipt_chirho: EffectCommitJournalReceiptChirho {
                seq_chirho: 7,
                record_digest_chirho: DigestChirho("a".repeat(64)),
                hlc_chirho: HlcChirho {
                    physical_ms_chirho: 11,
                    logical_chirho: 2,
                },
            },
            identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho::CanaryPersistenceEvidencePendingChirho,
            detail_chirho: planted_private_detail_chirho.to_owned(),
        },
    );
    assert_eq!(
        committed_pending_chirho,
        VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionCommittedEvidencePendingChirho
    );
    assert_ne!(
        committed_pending_chirho,
        VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionRefusedChirho,
        "a half-landed committed effect must never look like a plain retryable refusal"
    );

    assert_eq!(
        map_compensation_execution_refusal_chirho(
            EffectCommitCoordinatorErrorChirho::IntentChirho {
                detail_chirho: planted_private_detail_chirho.to_owned(),
            }
        ),
        VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionRefusedChirho,
        "unclassified Site C causes remain fail-closed behind one fixed generic label"
    );
}

#[test]
fn operator_execute_queries_committed_compensation_and_replays_without_refund_chirho() {
    let app_chirho = "execute-current-compensation";
    let (root_chirho, owner_chirho, price_book_chirho) =
        promoted_postgres_app_chirho(app_chirho, 1);
    let user_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let status_chirho = crate::app_chirho::app_status_chirho(&root_chirho, app_chirho).unwrap();
    let dag_chirho: DagChirho = crate::store_chirho::get_object_chirho(
        &root_chirho,
        status_chirho.dag_chirho.as_ref().unwrap(),
    )
    .unwrap();
    let node_hash_chirho = dag_chirho.nodes_chirho[0].clone();
    let node_chirho: NodeDefChirho =
        crate::store_chirho::get_object_chirho(&root_chirho, &node_hash_chirho).unwrap();
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        super::super::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let subject_chirho = HashChirho("a".repeat(64));
    let row_key_chirho = HashChirho("b".repeat(64));
    let value_ref_chirho = crate::privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            &subject_chirho.0,
        ),
        &subject_chirho.0,
        b"compensation-new-value-chirho",
    )
    .unwrap();
    let request_bytes_chirho = canonical_request_bytes_chirho(&ReversiblePostgresRequestChirho {
        schema_chirho: "reversible-postgres-request-v1-chirho".to_owned(),
        subject_chirho: subject_chirho.clone(),
        row_key_chirho: row_key_chirho.clone(),
        expected_before_chirho: ExpectedPostgresStateChirho::AbsentChirho,
        desired_chirho: DesiredPostgresStateChirho::PresentChirho { value_ref_chirho },
    })
    .unwrap();
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: user_chirho.clone(),
        app_chirho: app_chirho.to_owned(),
        owner_principal_chirho: owner_chirho.clone(),
        client_id_chirho: "compensation-client-chirho".to_owned(),
        token_hash_chirho: "compensation-token-chirho".to_owned(),
        price_book_chirho: Some(price_book_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let authority_chirho =
        mint_verified_current_undo_plan_authority_chirho(&root_chirho, app_chirho, &owner_chirho)
            .unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&user_chirho);
    let mut journal_chirho = harness_chirho.funded_journal_chirho(&user_chirho);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut database_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let run_chirho = HashChirho("9".repeat(64));
    let (closed_chirho, replayed_chirho) = {
        let mut journal_adapter_chirho = SiteCRefusingJournalChirho {
            delegate_chirho: LedgerEffectCommitAdapterChirho::new_chirho(
                &mut journal_chirho,
                &harness_chirho.intent_root_chirho,
                &harness_chirho.terminal_root_chirho,
            ),
            next_compensation_refusal_chirho: Some(
                EffectCommitJournalPortErrorChirho::AuthorityRefusedChirho {
                    identity_chirho: EffectCommitJournalAuthorityRefusalIdentityChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
                    detail_chirho: "/private/site-c-runtime-needle-chirho".to_owned(),
                },
            ),
        };
        let mut runtime_chirho = super::super::LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &APP_PRICE_POLICY_CHIRHO,
            AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
        )
        .unwrap();
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
        .unwrap();
        assert_eq!(
            runtime_chirho
                .database_chirho
                .row_bytes_chirho(&subject_chirho, &row_key_chirho),
            Some(b"compensation-new-value-chirho".as_slice())
        );
        let site_c_refusal_chirho = runtime_chirho
            .execute_current_compensation_chirho(&authority_chirho)
            .expect_err("the planted journal authority refusal must stop before provider work");
        assert_eq!(
            site_c_refusal_chirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionOrdinaryTermInputsUnavailableChirho
        );
        assert_ne!(
            site_c_refusal_chirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationExecutionSinkTermUnseenWinnerRefusedChirho,
            "acceptance-not-attempted must not collapse into the old unseen-term refusal"
        );
        assert_ne!(
            site_c_refusal_chirho,
            VerifiedCurrentUndoPlanAuthorityErrorChirho::CompensationTerminalRefusedChirho,
            "Site C must not restore the old one-label flattening"
        );
        assert_eq!(
            runtime_chirho
                .database_chirho
                .row_bytes_chirho(&subject_chirho, &row_key_chirho),
            Some(b"compensation-new-value-chirho".as_slice()),
            "diagnostic classification must not execute or retry provider compensation"
        );
        assert_eq!(
            runtime_chirho.database_chirho.compensation_count_chirho(),
            0
        );
        runtime_chirho.database_chirho.lose_next_commit_ack_chirho();
        let closed_chirho = runtime_chirho
            .execute_current_compensation_chirho(&authority_chirho)
            .unwrap();
        assert!(matches!(
            closed_chirho.disposition_chirho,
            EffectTerminalDispositionChirho::CommittedChirho { .. }
        ));
        assert!(closed_chirho.provider_restored_chirho);
        assert_eq!(
            runtime_chirho
                .database_chirho
                .row_bytes_chirho(&subject_chirho, &row_key_chirho),
            None
        );
        assert_eq!(
            runtime_chirho.database_chirho.compensation_count_chirho(),
            1
        );
        assert!(runtime_chirho
            .journal_chirho
            .active_hold_intent_refs_chirho()
            .unwrap()
            .is_empty());
        let replayed_chirho = runtime_chirho
            .execute_current_compensation_chirho(&authority_chirho)
            .unwrap();
        assert_eq!(
            closed_chirho.compensation_intent_ref_chirho,
            replayed_chirho.compensation_intent_ref_chirho
        );
        assert_eq!(
            closed_chirho.terminal_outcome_ref_chirho,
            replayed_chirho.terminal_outcome_ref_chirho
        );
        assert_eq!(
            runtime_chirho.database_chirho.compensation_count_chirho(),
            1
        );
        (closed_chirho, replayed_chirho)
    };
    assert_eq!(closed_chirho, replayed_chirho);
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 4);
    assert!(journal_chirho.active_holds_chirho().is_empty());
    let payer_chirho = journal_chirho
        .head_states_chirho()
        .get(&LogIdChirho::new_chirho(
            user_chirho.clone(),
            MONEY_KIND_CHIRHO,
        ))
        .unwrap();
    assert_eq!(payer_chirho.debits_total_chirho, 20);
    assert_eq!(payer_chirho.held_chirho, 0);
    let settlement_chirho = journal_chirho
        .head_states_chirho()
        .get(&LogIdChirho::new_chirho(
            SETTLEMENT_OWNER_CHIRHO,
            MONEY_KIND_CHIRHO,
        ))
        .unwrap();
    assert_eq!(settlement_chirho.credits_total_chirho, 20);
    std::fs::remove_dir_all(root_chirho).unwrap();
}
