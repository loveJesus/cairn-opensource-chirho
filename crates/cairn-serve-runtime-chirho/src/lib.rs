// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

#![allow(clippy::enum_variant_names)]

//! Served HTTP runtime adapter for cairn-chirho applications.

mod serve_chirho;

#[cfg(feature = "dev-transient-review-fixture-chirho")]
pub use serve_chirho::{
    prepare_transient_review_server_chirho, PreparedTransientReviewServerChirho,
};

pub use cairn_chirho::effect_chirho::postgres_reversible_chirho::{
    CurrentPostgresCompensationExecutionChirho, CurrentPostgresCompensationPreviewChirho,
    CurrentPostgresCompensationPreviewVerdictChirho, EffectTerminalDispositionChirho,
    PostgresReversibleActivationErrorChirho, VerifiedCurrentUndoPlanAuthorityErrorChirho,
};
pub use serve_chirho::APP_EXECUTION_REFUSAL_BODY_CHIRHO;
pub use serve_chirho::{
    activate_current_ledger_host_tenant_migration_target_chirho,
    begin_current_ledger_host_tenant_migration_source_fence_chirho,
    execute_current_ledger_host_postgres_compensation_chirho,
    execute_current_ledger_host_testkind_loss_witness_chirho,
    execute_deposed_sink_ledger_host_testkind_loss_witness_chirho,
    execute_reviewed_current_ledger_host_postgres_compensation_chirho,
    execute_sustained_ledger_host_testkind_loss_witness_chirho,
    open_shared_ledger_host_postgres_effect_runtime_chirho,
    open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho,
    open_shared_llm_served_composition_with_resident_journal_chirho,
    parse_ledger_conservation_cycle_row_chirho, parse_local_phase_b_connection_config_chirho,
    preflight_ledger_host_postgres_effect_runtime_chirho,
    preview_current_ledger_host_postgres_compensation_chirho,
    replay_completed_current_ledger_host_postgres_compensation_chirho, serve_chirho,
    serve_quiet_chirho, serve_quiet_with_registration_token_chirho,
    serve_with_configured_ledger_host_chirho, serve_with_configured_request_limits_chirho,
    serve_with_domain_routing_chirho, serve_with_projection_read_port_chirho,
    serve_with_registration_token_and_limits_chirho, serve_with_registration_token_chirho,
    ConfiguredLedgerHostRuntimePortsChirho, ErasurePropagationSinkChirho,
    LedgerConservationCycleOutcomeChirho, LedgerConservationCycleRowChirho,
    LedgerConservationCycleWireRefusalChirho, LedgerConservationHeadEvidenceChirho,
    LedgerConservationIncidentEvidenceChirho, LedgerConservationRefusalCodeChirho,
    LedgerHostPostgresEffectRefusalChirho, LedgerHostProjectionReadPortChirho,
    LedgerHostRuntimeRefusalChirho, LedgerSubstrateBalancesChirho,
    LlmServedCompositionRefusalChirho, OpenSharedLlmServedCompositionParamsChirho,
    ReviewedCurrentPostgresCompensationRefusalChirho, ServeAuthTokensChirho,
    ServedLlmCardSurfaceChirho, ServedRequestAbuseLimitsChirho,
    ServedWriteRelayDestinationSlotChirho, SharedLedgerHostPostgresEffectRuntimeChirho,
    SharedLlmServedCompositionChirho, LEDGER_CONSERVATION_CYCLE_SCHEMA_V1_CHIRHO,
    SERVED_LLM_COMPOSITION_BUSY_REFUSAL_CHIRHO, SERVED_LLM_DEV_ROOT_MISMATCH_REFUSAL_CHIRHO,
};

/// The dev-only served-LLM loopback entry (a2b). Compiled only under `dev-llm-served-chirho`; the
/// authoritative runtime gate is `CAIRN_DEV_LLM_SERVED_CHIRHO=1` plus the test-kind-only handle.
#[cfg(feature = "dev-llm-served-chirho")]
pub use serve_chirho::{
    serve_with_dev_llm_served_composition_chirho,
    serve_with_dev_llm_served_composition_until_chirho,
};
