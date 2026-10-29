// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn only_committed_terminals_attempt_refeed_and_feed_failure_stays_nonterminal_chirho() {
    let committed_calls_chirho = Cell::new(0_u32);
    refeed_committed_terminal_chirho(
        &EffectTerminalDispositionChirho::CommittedChirho {
            result_ref_chirho: DigestChirho("11".repeat(32)),
        },
        || {
            committed_calls_chirho.set(committed_calls_chirho.get() + 1);
            Err(LedgerHostPostgresEffectRefusalChirho::ProjectionFeedUnavailableChirho.into())
        },
    );
    assert_eq!(committed_calls_chirho.get(), 1);

    let no_effect_calls_chirho = Cell::new(0_u32);
    refeed_committed_terminal_chirho(
        &EffectTerminalDispositionChirho::DefiniteNoEffectChirho,
        || {
            no_effect_calls_chirho.set(no_effect_calls_chirho.get() + 1);
            Ok(())
        },
    );
    assert_eq!(no_effect_calls_chirho.get(), 0);
}

#[test]
fn feed_refusal_does_not_skip_later_configured_routes_chirho() {
    let visited_chirho = RefCell::new(Vec::new());
    let error_chirho = feed_every_configured_route_chirho([1_u8, 2, 3], |route_chirho| {
        visited_chirho.borrow_mut().push(route_chirho);
        if route_chirho == 2 {
            anyhow::bail!("injected middle-route feed refusal");
        }
        Ok(())
    })
    .unwrap_err();

    assert_eq!(*visited_chirho.borrow(), [1, 2, 3]);
    assert_eq!(
        error_chirho.downcast_ref::<LedgerHostPostgresEffectRefusalChirho>(),
        Some(&LedgerHostPostgresEffectRefusalChirho::ProjectionFeedUnavailableChirho)
    );
}

struct ReviewedCompensationFakePortChirho {
    preview_chirho: CurrentPostgresCompensationPreviewChirho,
    execution_chirho: CurrentPostgresCompensationExecutionChirho,
    execute_count_chirho: Arc<AtomicUsize>,
}

impl PostgresReversibleRuntimePortChirho for ReviewedCompensationFakePortChirho {
    fn execute_chirho(
        &mut self,
        _execution_chirho: PostgresReversibleExecutionChirho<'_>,
    ) -> Result<Vec<u8>> {
        anyhow::bail!("reviewed compensation fake has no ordinary effect door")
    }
}

impl LedgerHostPostgresEffectPortChirho for ReviewedCompensationFakePortChirho {
    // This fake exists for the COMPENSATION lifecycle. It refuses migration activation rather than
    // pretending: an arm that reached activation through a compensation fake would be measuring the
    // fake, not the seam.
    fn activate_current_tenant_migration_target_chirho(
        &mut self,
        _target_root_chirho: &std::path::Path,
    ) -> std::result::Result<
        cairn_ledger_host_chirho::ResidentTenantMigrationTargetActivatedStatusChirho,
        cairn_ledger_host_chirho::ResidentTenantMigrationOperationRefusalChirho,
    > {
        Err(cairn_ledger_host_chirho::ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho)
    }

    // Same refusal, same reason: a compensation fake that FENCED a source would be installing a
    // real append barrier from a fixture that models none of it.
    fn begin_current_tenant_migration_source_fence_chirho(
        &mut self,
        _target_root_chirho: &std::path::Path,
        _destination_chirho: cairn_ledger_host_chirho::TenantMigrationDestinationRecordChirho,
        _writer_adoption_chirho: Option<
            cairn_ledger_host_chirho::TenantMigrationWriterAdoptionRecordChirho,
        >,
    ) -> std::result::Result<
        cairn_ledger_host_chirho::ResidentTenantMigrationSourceFenceStatusChirho,
        cairn_ledger_host_chirho::ResidentTenantMigrationOperationRefusalChirho,
    > {
        Err(cairn_ledger_host_chirho::ResidentTenantMigrationOperationRefusalChirho::ActorUnavailableChirho)
    }

    fn runtime_port_chirho(&mut self) -> &mut dyn PostgresReversibleRuntimePortChirho {
        self
    }

    fn preview_current_compensation_chirho(
        &mut self,
        _root_chirho: &Path,
        _app_chirho: &str,
        _owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationPreviewChirho> {
        Ok(self.preview_chirho.clone())
    }

    fn execute_current_compensation_chirho(
        &mut self,
        _root_chirho: &Path,
        _app_chirho: &str,
        _owner_chirho: &str,
    ) -> Result<CurrentPostgresCompensationExecutionChirho> {
        self.execute_count_chirho.fetch_add(1, Ordering::SeqCst);
        Ok(self.execution_chirho.clone())
    }

    fn execute_current_testkind_loss_witness_chirho(
        &mut self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        Err(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)
    }

    fn execute_sustained_testkind_loss_witness_chirho(
        &mut self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        Err(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)
    }

    fn execute_deposed_sink_testkind_loss_witness_chirho(
        &mut self,
        _phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    ) -> std::result::Result<
        ResidentTestkindLossWitnessOutcomeChirho,
        ResidentTestkindLossWitnessRefusalChirho,
    > {
        Err(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)
    }
}

fn reviewed_preview_chirho(
    verdict_chirho: serde_json::Value,
) -> CurrentPostgresCompensationPreviewChirho {
    serde_json::from_value(serde_json::json!({
        "schema_chirho": "current-postgres-compensation-preview-v1-chirho",
        "app_chirho": "credits-demo-chirho",
        "source_review_report_chirho": "11".repeat(32),
        "plan_digest_chirho": "22".repeat(32),
        "original_effect_key_chirho": "33".repeat(32),
        "intent_ref_chirho": "44".repeat(32),
        "terminal_outcome_ref_chirho": "55".repeat(32),
        "verdict_chirho": verdict_chirho
    }))
    .unwrap()
}

fn reviewed_execution_chirho() -> CurrentPostgresCompensationExecutionChirho {
    serde_json::from_value(serde_json::json!({
        "schema_chirho": "current-postgres-compensation-execution-v1-chirho",
        "app_chirho": "credits-demo-chirho",
        "original_effect_key_chirho": "33".repeat(32),
        "compensation_intent_ref_chirho": "66".repeat(32),
        "terminal_outcome_ref_chirho": "77".repeat(32),
        "disposition_chirho": {
            "kind_chirho": "committed-chirho",
            "result_ref_chirho": "88".repeat(32)
        },
        "provider_restored_chirho": true
    }))
    .unwrap()
}

fn reviewed_runtime_chirho(
    preview_chirho: CurrentPostgresCompensationPreviewChirho,
    execution_chirho: CurrentPostgresCompensationExecutionChirho,
    execute_count_chirho: Arc<AtomicUsize>,
) -> SharedLedgerHostPostgresEffectRuntimeChirho {
    SharedLedgerHostPostgresEffectRuntimeChirho {
        inner_chirho: Arc::new(Mutex::new(Box::new(ReviewedCompensationFakePortChirho {
            preview_chirho,
            execution_chirho,
            execute_count_chirho,
        }))),
    }
}

#[test]
fn reviewed_execute_requires_the_exact_executable_preview_before_mutation_chirho() {
    let preview_chirho = reviewed_preview_chirho(serde_json::json!({
        "kind_chirho": "executable-chirho"
    }));
    let execution_chirho = reviewed_execution_chirho();
    let execute_count_chirho = Arc::new(AtomicUsize::new(0));
    let runtime_chirho = reviewed_runtime_chirho(
        preview_chirho.clone(),
        execution_chirho.clone(),
        Arc::clone(&execute_count_chirho),
    );
    let mut stale_preview_chirho = preview_chirho.clone();
    stale_preview_chirho.plan_digest_chirho.0 = "aa".repeat(32);
    let refusal_chirho = execute_reviewed_current_ledger_host_postgres_compensation_chirho(
        &runtime_chirho,
        Path::new("/root-chirho"),
        "credits-demo-chirho",
        "user/0123456789abcdef",
        &stale_preview_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<ReviewedCurrentPostgresCompensationRefusalChirho>(),
        Some(&ReviewedCurrentPostgresCompensationRefusalChirho::PreviewChangedChirho)
    );
    assert_eq!(execute_count_chirho.load(Ordering::SeqCst), 0);

    assert_eq!(
        execute_reviewed_current_ledger_host_postgres_compensation_chirho(
            &runtime_chirho,
            Path::new("/root-chirho"),
            "credits-demo-chirho",
            "user/0123456789abcdef",
            &preview_chirho,
        )
        .unwrap(),
        execution_chirho
    );
    assert_eq!(execute_count_chirho.load(Ordering::SeqCst), 1);
}

#[test]
fn replay_verb_cannot_be_the_first_execution_and_reuses_exact_evidence_chirho() {
    let executable_preview_chirho = reviewed_preview_chirho(serde_json::json!({
        "kind_chirho": "executable-chirho"
    }));
    let expected_execution_chirho = reviewed_execution_chirho();
    let execute_count_chirho = Arc::new(AtomicUsize::new(0));
    let not_completed_runtime_chirho = reviewed_runtime_chirho(
        executable_preview_chirho,
        expected_execution_chirho.clone(),
        Arc::clone(&execute_count_chirho),
    );
    let refusal_chirho = replay_completed_current_ledger_host_postgres_compensation_chirho(
        &not_completed_runtime_chirho,
        Path::new("/root-chirho"),
        "credits-demo-chirho",
        "user/0123456789abcdef",
        &expected_execution_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho.downcast_ref::<ReviewedCurrentPostgresCompensationRefusalChirho>(),
        Some(&ReviewedCurrentPostgresCompensationRefusalChirho::ReplayNotCompletedChirho)
    );
    assert_eq!(execute_count_chirho.load(Ordering::SeqCst), 0);

    let completed_preview_chirho = reviewed_preview_chirho(serde_json::json!({
        "kind_chirho": "completed-replay-chirho",
        "provider_restored_chirho": true
    }));
    let completed_runtime_chirho = reviewed_runtime_chirho(
        completed_preview_chirho,
        expected_execution_chirho.clone(),
        Arc::clone(&execute_count_chirho),
    );
    assert_eq!(
        replay_completed_current_ledger_host_postgres_compensation_chirho(
            &completed_runtime_chirho,
            Path::new("/root-chirho"),
            "credits-demo-chirho",
            "user/0123456789abcdef",
            &expected_execution_chirho,
        )
        .unwrap(),
        expected_execution_chirho
    );
    assert_eq!(execute_count_chirho.load(Ordering::SeqCst), 1);
}
