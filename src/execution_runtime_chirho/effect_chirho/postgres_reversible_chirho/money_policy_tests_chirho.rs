// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;

struct MutableMoneyPolicyChirho {
    price_book_chirho: HashChirho,
    billing_policy_chirho: HashChirho,
    payer_mode_chirho: Cell<PostgresReversiblePayerModeChirho>,
}

impl PostgresReversibleMoneyPolicyPortChirho for MutableMoneyPolicyChirho {
    fn resolve_money_policy_chirho(
        &self,
        _root_chirho: &Path,
        _request_context_chirho: &RequestContextChirho,
        _effect_chirho: &str,
    ) -> anyhow::Result<PostgresReversibleMoneyPolicyChirho> {
        PostgresReversibleMoneyPolicyChirho::new_chirho(
            self.price_book_chirho.clone(),
            Some(self.billing_policy_chirho.clone()),
            17,
            self.payer_mode_chirho.get(),
        )
    }
}

#[test]
fn user_pays_adapter_refuses_policy_context_before_intent_or_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let mut context_chirho = setup_context_chirho(&root_chirho);
    context_chirho.billing_policy_chirho = Some(HashChirho("c".repeat(64)));
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let node_chirho = postgres_node_chirho();
    let node_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (request_bytes_chirho, _, _) = request_bytes_chirho(&root_chirho);
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.user_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.user_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut database_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let run_chirho = HashChirho("7".repeat(64));

    let error_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
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
        .unwrap_err()
    };

    assert!(matches!(
        error_chirho.downcast_ref::<PostgresReversibleActivationErrorChirho>(),
        Some(PostgresReversibleActivationErrorChirho::MoneyPolicyRefusedChirho { .. })
    ));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho);
    assert_eq!(database_chirho.committed_transactions_chirho, 0);
    assert!(!root_chirho.join("effect-commit-evidence-chirho").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn same_invocation_refuses_when_live_policy_changes_only_the_payer_chirho() {
    let root_chirho = tmp_root_chirho();
    let mut context_chirho = setup_context_chirho(&root_chirho);
    let policy_ref_chirho = HashChirho("c".repeat(64));
    context_chirho.billing_policy_chirho = Some(policy_ref_chirho.clone());
    let money_policy_chirho = MutableMoneyPolicyChirho {
        price_book_chirho: context_chirho.price_book_chirho.clone().unwrap(),
        billing_policy_chirho: policy_ref_chirho,
        payer_mode_chirho: Cell::new(PostgresReversiblePayerModeChirho::PolicyOwnerPaysChirho),
    };
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let node_chirho = postgres_node_chirho();
    let node_hash_chirho =
        crate::store_chirho::put_object_chirho(&root_chirho, &node_chirho).unwrap();
    let (request_bytes_chirho, _, _) = request_bytes_chirho(&root_chirho);
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&context_chirho.owner_principal_chirho);
    let mut journal_chirho =
        harness_chirho.funded_journal_chirho(&context_chirho.owner_principal_chirho);
    harness_chirho.clock_chirho.now_ms_chirho.set(1_300);
    let initial_tail_chirho = journal_chirho.tail_seq_chirho();
    let mut database_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let run_chirho = HashChirho("8".repeat(64));

    let second_error_chirho = {
        let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
            &mut journal_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
        );
        let mut runtime_chirho = LocalPostgresEffectCompositionChirho::open_chirho(
            &root_chirho,
            &mut journal_adapter_chirho,
            &mut database_chirho,
            &harness_chirho.intent_root_chirho,
            &harness_chirho.terminal_root_chirho,
            &money_policy_chirho,
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
        money_policy_chirho
            .payer_mode_chirho
            .set(PostgresReversiblePayerModeChirho::PolicyUserPaysChirho);
        run_scoped_postgres_node_chirho(
            &ScopedPostgresNodeInputsChirho {
                root_chirho: &root_chirho,
                node_chirho: &node_chirho,
                node_hash_chirho: &node_hash_chirho,
                input_hash_chirho: &input_hash_chirho,
                context_chirho: &context_chirho,
                run_chirho: &run_chirho,
            },
            true,
            &mut runtime_chirho,
        )
        .unwrap_err()
    };

    assert!(matches!(
        second_error_chirho.downcast_ref::<PostgresReversibleActivationErrorChirho>(),
        Some(PostgresReversibleActivationErrorChirho::InvocationObligationConflictChirho)
    ));
    assert_eq!(journal_chirho.tail_seq_chirho(), initial_tail_chirho + 2);
    assert_eq!(database_chirho.committed_transactions_chirho, 1);
    let _ = std::fs::remove_dir_all(root_chirho);
}
