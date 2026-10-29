// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! M2.1 — the HTTP entrypoint: request -> server DAG -> payload.
//!
//! An axum router over a cairn root. Routes:
//!   - `GET  /healthz-chirho`     -> liveness (`"ok\n"` body); `/healthz` stays as a compatibility alias.
//!   - `GET|POST /run-chirho/:dag_chirho` -> load a stored capability-free Tier-1 WASM
//!     `DagChirho`, run it (POST body = input), return the payload bytes as the HTTP response body.
//!   - `GET|POST /app-chirho/:name_chirho` -> resolve a deployed app (the `app/<name>` ref,
//!     or a resource-routed `app-route/<name>/<route>` ref) and run its DagChirho.
//!   - `GET /ssr-chirho/:name_chirho` -> run a deployed app through its signed input policy
//!     and serve its payload wrapped in an HTML document.
//!   - `POST /invoke-chirho` and `GET /ws-chirho` -> legacy wire transport for app targets;
//!     payloads honor the same signed app input policy as `/app-chirho`.
//!   - `GET /realtime-chirho/:session_chirho/ws-chirho` -> authenticated realtime session stream.
//!   - `GET /runtime-package-chirho/:package_chirho/...` -> validated runtime-package artifacts.
//!   - `GET /app-assets-chirho/:app_chirho/...` -> verified same-origin app static assets.
//!   - `GET /auth-chirho/human-check-chirho`, `GET|POST /auth-chirho/register-chirho`, `GET|POST /auth-chirho/login-chirho`,
//!     `POST /auth-chirho/token-chirho`, `POST /auth-chirho/:kind_chirho/:id_chirho/session-revoke-chirho`,
//!     `POST /auth-chirho/credential-change-chirho` (the signed-in viewer's own credential change:
//!     revoke every session, replace, signed record, typed refusal tokens), `GET /auth-chirho/keys-chirho` and
//!     `POST /auth-chirho/key-revoke-chirho` (the signed-in owner's own keys, listed and revoked by key id), and
//!     registration, login, token, and session-revocation routes -> identity/auth.
//!   - `GET|POST /app-state-chirho/:kind_chirho/:id_chirho/:app_chirho/...` -> owner-gated app state rollback and reveal actions.
//!   - `POST /app-review-chirho/:kind_chirho/:id_chirho/:app_chirho/...` -> owner-gated reviewed app promote/rollback.
//!   - `GET|POST /app-build-request-chirho/:kind_chirho/:id_chirho/:app_chirho/...` -> owner-gated private app-build request preview/create.
//!   - `GET|POST /resource-policy-chirho/:kind_chirho/:id_chirho/:app_chirho/...` -> owner-gated resource-policy review/apply.
//!
//! Route names are part of the Chirho contract: every public static segment is `-chirho`
//! suffixed, every dynamic segment is `_chirho` suffixed, except `/` and legacy `/healthz`.
//!
//! The DAG runs through the same cached/effect-logged executor as the CLI, so a re-hit is
//! served from cache where safe; live read effects re-execute.
//!
use anyhow::Result;
use axum::{
    extract::connect_info::IntoMakeServiceWithConnectInfo,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION, RETRY_AFTER},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use cairn_chirho::model_chirho::{HashChirho, RequestContextChirho};
use cairn_chirho::{app_chirho, identity_chirho, oauth_chirho, tenant_chirho};
use cairn_write_relay_chirho::{
    CallerIdempotencyKeyChirho, CallerOperationBindingChirho, ServedLocalReadAuthorityPortChirho,
    ServedWriteDispatchPortChirho,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[path = "serve_chirho/runtime_web_chirho/answer_cache_chirho.rs"]
mod answer_cache_chirho;
#[path = "serve_chirho/app_web_chirho/app_assets_chirho.rs"]
mod app_assets_chirho;
#[path = "serve_chirho/app_web_chirho/app_build_request_web_chirho.rs"]
mod app_build_request_web_chirho;
#[path = "serve_chirho/runtime_web_chirho/app_http_chirho.rs"]
mod app_http_chirho;
#[path = "serve_chirho/app_web_chirho/app_review_web_chirho.rs"]
mod app_review_web_chirho;
#[path = "serve_chirho/app_web_chirho/app_root_chirho.rs"]
mod app_root_chirho;
#[path = "serve_chirho/app_web_chirho/app_session_chirho.rs"]
mod app_session_chirho;
#[path = "serve_chirho/app_web_chirho/app_state_web_chirho.rs"]
mod app_state_web_chirho;
#[path = "serve_chirho/runtime_web_chirho/request_admission_chirho/auth_blocking_chirho.rs"]
mod auth_blocking_chirho;
#[path = "serve_chirho/auth_browser_chirho.rs"]
mod auth_browser_chirho;
#[path = "serve_chirho/app_web_chirho/auth_connection_new_chirho.rs"]
mod auth_connection_new_chirho;
#[path = "serve_chirho/app_web_chirho/auth_credential_change_chirho.rs"]
mod auth_credential_change_chirho;
#[path = "serve_chirho/app_web_chirho/auth_keys_chirho.rs"]
mod auth_keys_chirho;
#[path = "serve_chirho/app_web_chirho/auth_recover_chirho.rs"]
mod auth_recover_chirho;
#[path = "serve_chirho/auth_wallet_chirho.rs"]
mod auth_wallet_chirho;
#[path = "serve_chirho/app_web_chirho/erasure_propagation_chirho/sink_chirho.rs"]
mod erasure_propagation_sink_chirho;
pub use erasure_propagation_sink_chirho::ErasurePropagationSinkChirho;
#[path = "serve_chirho/runtime_web_chirho/invoke_transport_chirho.rs"]
mod invoke_transport_chirho;
#[path = "serve_chirho/ledger_host_runtime_chirho.rs"]
mod ledger_host_runtime_chirho;
pub use ledger_host_runtime_chirho::ConfiguredLedgerHostRuntimePortsChirho;
#[path = "serve_chirho/llm_served_runtime_chirho.rs"]
mod llm_served_runtime_chirho;
#[path = "serve_chirho/runtime_web_chirho/public_error_chirho/public_error_chirho.rs"]
mod public_error_chirho;
#[path = "serve_chirho/public_routes_chirho.rs"]
mod public_routes_chirho;
#[path = "serve_chirho/runtime_web_chirho/public_run_chirho.rs"]
mod public_run_chirho;
#[path = "serve_chirho/publish_dashboard_web_chirho.rs"]
mod publish_dashboard_web_chirho;
#[path = "serve_chirho/runtime_web_chirho/realtime_ws_chirho.rs"]
mod realtime_ws_chirho;
#[path = "serve_chirho/resource_gate_chirho.rs"]
mod resource_gate_chirho;
#[path = "serve_chirho/resource_policy_web_chirho.rs"]
mod resource_policy_web_chirho;
#[path = "serve_chirho/runtime_ports_chirho.rs"]
mod runtime_ports_chirho;
#[path = "serve_chirho/runtime_lifecycle_chirho/startup_chirho.rs"]
mod runtime_startup_chirho;
#[path = "serve_chirho/runtime_lifecycle_chirho/state_chirho.rs"]
mod runtime_state_chirho;
#[path = "serve_chirho/runtime_web_chirho/request_admission_chirho/served_request_abuse_gate_chirho.rs"]
mod served_request_abuse_gate_chirho;
#[path = "serve_chirho/runtime_web_chirho/request_admission_chirho/served_request_limits_chirho.rs"]
mod served_request_limits_chirho;
#[path = "serve_chirho/session_web_helpers_chirho.rs"]
mod session_web_helpers_chirho;
#[path = "serve_chirho/runtime_web_chirho/request_admission_chirho/sign_in_gate_chirho.rs"]
mod sign_in_gate_chirho;
use runtime_startup_chirho::serve_with_options_until_chirho;
#[cfg(feature = "dev-transient-review-fixture-chirho")]
pub use runtime_startup_chirho::{
    prepare_transient_review_server_chirho, PreparedTransientReviewServerChirho,
};
#[cfg(test)]
use runtime_startup_chirho::{
    resume_projection_run_intents_for_startup_posture_chirho,
    runtime_router_for_root_with_effect_runtime_after_resume_chirho,
};
#[cfg(test)]
use runtime_state_chirho::SERVED_REQUEST_UNAVAILABLE_JSON_CHIRHO;
use runtime_state_chirho::{
    accept_names_json_chirho, admit_served_dag_request_chirho,
    app_state_for_runtime_root_with_effect_runtime_chirho, media_type_is_json_chirho,
    served_request_rejected_response_chirho,
};
#[path = "serve_chirho/runtime_web_chirho/ssr_web_chirho.rs"]
mod ssr_web_chirho;
#[path = "serve_chirho/runtime_web_chirho/write_relay_chirho.rs"]
mod write_relay_chirho;
use app_assets_chirho::{app_asset_by_hash_get_chirho, app_asset_by_name_get_chirho};
use app_build_request_web_chirho::{
    app_build_request_create_post_chirho, app_build_request_get_chirho,
    app_build_request_preview_post_chirho,
};
pub use app_http_chirho::APP_EXECUTION_REFUSAL_BODY_CHIRHO;
use app_http_chirho::{
    app_route_get_chirho, app_route_post_request_chirho, app_selection_error_response_chirho,
    direct_app_rejects_request_body_chirho, domain_binding_fallback_chirho,
    pre_body_request_access_refusal_chirho, read_served_app_request_body_chirho,
    request_access_decision_chirho, request_access_refusal_for_context_chirho,
    run_app_http_with_method_for_served_request_chirho, RequestAccessDecisionChirho,
};
use app_review_web_chirho::{app_review_promote_post_chirho, app_review_rollback_post_chirho};
#[cfg(test)]
use app_root_chirho::app_post_chirho;
use app_root_chirho::{app_get_chirho, app_post_request_chirho};
use app_session_chirho::{
    app_dag_input_chirho, app_http_dag_input_value_chirho, auth_browser_redirect_path_chirho,
    auth_logout_get_chirho, auth_session_cookie_header_chirho,
    commit_prepared_app_request_context_chirho, prepare_app_request_context_chirho,
    request_context_for_app_chirho, request_context_for_app_route_chirho,
    AppRouteRequestContextChirho, PreparedAppRequestContextChirho,
};
use app_state_web_chirho::{
    app_state_get_chirho, app_state_reveal_post_chirho, app_state_rollback_post_chirho,
};
use auth_browser_chirho::{
    auth_human_check_get_chirho, auth_login_get_chirho, auth_register_get_chirho,
};
use auth_wallet_chirho::{
    auth_login_post_chirho, auth_register_post_chirho, auth_session_revoke_post_chirho,
    auth_token_post_chirho,
};
use invoke_transport_chirho::{invoke_chirho, ws_upgrade_chirho};
pub use ledger_host_runtime_chirho::parse_local_phase_b_connection_config_chirho;
pub use ledger_host_runtime_chirho::{
    activate_current_ledger_host_tenant_migration_target_chirho,
    begin_current_ledger_host_tenant_migration_source_fence_chirho,
    execute_current_ledger_host_postgres_compensation_chirho,
    execute_current_ledger_host_testkind_loss_witness_chirho,
    execute_deposed_sink_ledger_host_testkind_loss_witness_chirho,
    execute_reviewed_current_ledger_host_postgres_compensation_chirho,
    execute_sustained_ledger_host_testkind_loss_witness_chirho,
    open_shared_ledger_host_postgres_effect_runtime_chirho,
    open_shared_ledger_host_postgres_effect_runtime_with_resident_journal_chirho,
    parse_ledger_conservation_cycle_row_chirho,
    preflight_ledger_host_postgres_effect_runtime_chirho,
    preview_current_ledger_host_postgres_compensation_chirho,
    replay_completed_current_ledger_host_postgres_compensation_chirho,
    LedgerConservationCycleOutcomeChirho, LedgerConservationCycleRowChirho,
    LedgerConservationCycleWireRefusalChirho, LedgerConservationHeadEvidenceChirho,
    LedgerConservationIncidentEvidenceChirho, LedgerConservationRefusalCodeChirho,
    LedgerHostPostgresEffectRefusalChirho, LedgerHostProjectionReadPortChirho,
    LedgerHostRuntimeRefusalChirho, LedgerSubstrateBalancesChirho,
    ReviewedCurrentPostgresCompensationRefusalChirho, SharedLedgerHostPostgresEffectRuntimeChirho,
    LEDGER_CONSERVATION_CYCLE_SCHEMA_V1_CHIRHO,
};
use ledger_host_runtime_chirho::{
    ConfiguredLedgerHostServeOptionsChirho, FixedLedgerConservationAlarmChirho,
    LedgerMonitorRuntimeChirho, TokioLedgerMonitorCadenceWaitChirho,
};
pub use llm_served_runtime_chirho::{
    open_shared_llm_served_composition_with_resident_journal_chirho,
    LlmServedCompositionRefusalChirho, OpenSharedLlmServedCompositionParamsChirho,
    ServedLlmCardSurfaceChirho, SharedLlmServedCompositionChirho,
    SERVED_LLM_COMPOSITION_BUSY_REFUSAL_CHIRHO, SERVED_LLM_DEV_ROOT_MISMATCH_REFUSAL_CHIRHO,
};
use public_routes_chirho::{
    app_descriptor_get_chirho, app_docs_get_chirho, app_mcp_get_chirho, client_demo_chirho,
    contact_demo_chirho, healthz_chirho, host_js_chirho, htmx_lite_js_chirho, index_chirho,
    perffection_intake_demo_chirho, platform_mcp_get_chirho, runtime_package_demo_chirho,
    runtime_package_executable_get_chirho, runtime_package_host_js_chirho,
    runtime_package_manifest_get_chirho, wasm_demo_chirho,
};
use public_run_chirho::{preview_get_chirho, preview_post_chirho, run_get_chirho, run_post_chirho};
use publish_dashboard_web_chirho::{dashboard_chirho, publish_post_chirho};
use realtime_ws_chirho::realtime_ws_upgrade_chirho;
use resource_gate_chirho::{
    select_app_dag_with_resource_gate_chirho, select_app_dag_without_resource_usage_chirho,
    select_app_route_dag_direct_chirho,
};
use resource_policy_web_chirho::{
    resource_policy_apply_post_chirho, resource_policy_get_chirho,
    resource_policy_preview_post_chirho,
};
use runtime_ports_chirho::{
    await_owned_served_work_chirho, outcome_of_owned_work_chirho,
    resume_unfinished_run_intents_for_served_effect_runtime_chirho, run_on_blocking_pool_chirho,
    ServedRuntimeRootChirho,
};
use served_request_abuse_gate_chirho::{ServedDagAdmissionChirho, ServedRequestAbuseGateChirho};
pub use served_request_limits_chirho::ServedRequestAbuseLimitsChirho;
use session_web_helpers_chirho::*;
use sign_in_gate_chirho::SignInGateChirho;
use ssr_web_chirho::ssr_get_chirho;
pub use write_relay_chirho::ServedWriteRelayDestinationSlotChirho;

#[derive(Clone)]
struct AppStateChirho {
    runtime_chirho: Arc<ServedRuntimeRootChirho>,
    tenant_chirho: tenant_chirho::TenantIdChirho,
    /// Per-store mailbox lock: serializes mutating invokes so the version chain is linear and
    /// base_version is race-free. (v1: one store-ref; per-ref mpsc mailboxes are a later refinement.)
    invoke_lock_chirho: Arc<tokio::sync::Mutex<()>>,
    /// Bounded in-flight permits — backpressure (load-shed with 429 past the limit).
    inflight_chirho: Arc<tokio::sync::Semaphore>,
    /// Process-local rolling admission for every served DAG path that can persist run intent.
    served_request_abuse_gate_chirho: Arc<ServedRequestAbuseGateChirho>,
    /// The sign-in velocity gate (brick 4a): the principal's limit for the durable pre-check, and the process-local
    /// per-source limit on successful sign-ins.
    sign_in_gate_chirho: Arc<SignInGateChirho>,
    /// Admin Bearer token accepted by POST /publish-chirho and GET /dashboard-chirho.
    /// Empty disables admin-token auth; publish can still use a matching owner session.
    publish_token_chirho: Arc<String>,
    /// Outer token required before any public registration challenge or write path.
    /// Empty disables public registration without touching root state.
    registration_token_chirho: Arc<String>,
    /// K4 Part 3's connection issuance road: false (the default) answers 503 on both of its routes before reading the
    /// session or the body.
    connection_issuance_enabled_chirho: bool,
    /// When true, unmatched requests resolve through the signed domain-binding table
    /// (host + path -> app route) before 404ing; false preserves the exact legacy 404.
    domain_routing_enabled_chirho: bool,
    /// Optional elected-era forwarding decision. Legacy and uncomposed entrypoints remain exact.
    write_dispatch_chirho: Option<Arc<dyn ServedWriteDispatchPortChirho>>,
    /// Local-owner pre/post witness for capability-bounded elected-era reads; never relays.
    local_read_authority_chirho: Option<Arc<dyn ServedLocalReadAuthorityPortChirho>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfiguredServeStartupPostureChirho {
    RecoverRunIntentsAndMonitorChirho,
    RelayOnlyFollowerChirho,
}

struct ServeOptionsChirho {
    inflight_limit_chirho: usize,
    auth_tokens_chirho: ServeAuthTokensChirho,
    announce_chirho: bool,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
    projection_read_chirho: Option<
        Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>,
    >,
    postgres_effect_chirho: Option<SharedLedgerHostPostgresEffectRuntimeChirho>,
    /// Dev-only served-LLM composition (loopback + env-fenced). `None` on every production path.
    llm_served_chirho: Option<SharedLlmServedCompositionChirho>,
    ledger_monitor_chirho: Option<LedgerMonitorRuntimeChirho>,
    write_dispatch_chirho: Option<Arc<dyn ServedWriteDispatchPortChirho>>,
    local_read_authority_chirho: Option<Arc<dyn ServedLocalReadAuthorityPortChirho>>,
    write_destination_slot_chirho: Option<ServedWriteRelayDestinationSlotChirho>,
    startup_posture_chirho: ConfiguredServeStartupPostureChirho,
}

/// Process-level HTTP auth settings carried together through configured serve entrypoints: the publish and
/// registration tokens, and the connection issuance gate (K4 Part 3), which is off unless the configured road opens it.
#[derive(Clone, Debug, Default)]
pub struct ServeAuthTokensChirho {
    publish_token_chirho: String,
    registration_token_chirho: String,
    connection_issuance_enabled_chirho: bool,
}

impl ServeAuthTokensChirho {
    pub fn new_chirho(publish_token_chirho: String, registration_token_chirho: String) -> Self {
        Self {
            publish_token_chirho,
            registration_token_chirho,
            connection_issuance_enabled_chirho: false,
        }
    }

    /// The same settings with the connection issuance road open or closed, as the TOML's
    /// `connection_issuance_enabled_chirho` says. Closed, both of its routes answer 503 before reading anything.
    pub fn with_connection_issuance_enabled_chirho(mut self, enabled_chirho: bool) -> Self {
        self.connection_issuance_enabled_chirho = enabled_chirho;
        self
    }
}

struct RuntimeAppStateOptionsChirho {
    inflight_limit_chirho: usize,
    auth_tokens_chirho: ServeAuthTokensChirho,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
    projection_read_chirho: Option<
        Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>,
    >,
    postgres_effect_chirho: Option<SharedLedgerHostPostgresEffectRuntimeChirho>,
    llm_served_chirho: Option<SharedLlmServedCompositionChirho>,
    write_dispatch_chirho: Option<Arc<dyn ServedWriteDispatchPortChirho>>,
    local_read_authority_chirho: Option<Arc<dyn ServedLocalReadAuthorityPortChirho>>,
    write_destination_slot_chirho: Option<ServedWriteRelayDestinationSlotChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResourceGateSelectionChirho {
    dag_chirho: HashChirho,
    route_chirho: Option<String>,
    discard_request_body_chirho: bool,
    request_body_policy_chirho: Option<app_chirho::AppRouteRequestBodyPolicyChirho>,
    unreviewed_dev_chirho: bool,
}

impl ResourceGateSelectionChirho {
    fn accepts_request_body_chirho(&self) -> bool {
        self.request_body_policy_chirho
            .as_ref()
            .is_none_or(app_chirho::AppRouteRequestBodyPolicyChirho::accepts_request_body_chirho)
    }
}

const REQUEST_RESOURCE_SECTION_CHIRHO: &str = "request-chirho";
const REQUEST_RESOURCE_ACTION_CHIRHO: &str = "default-chirho";

/// Start the HTTP server on `127.0.0.1:port` over the given cairn root.
pub async fn serve_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
) -> Result<()> {
    serve_with_announcement_chirho(
        root_chirho,
        port_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        String::new(),
        true,
        ServedRequestAbuseLimitsChirho::default(),
    )
    .await
}

pub async fn serve_with_registration_token_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
) -> Result<()> {
    serve_with_announcement_chirho(
        root_chirho,
        port_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        registration_token_chirho,
        true,
        ServedRequestAbuseLimitsChirho::default(),
    )
    .await
}

/// The CLI `serve` road with its served-request limits: the same composition as
/// `serve_with_registration_token_chirho`, which passes the defaults. Its flags set the two sign-in rates (brick 4a).
pub async fn serve_with_registration_token_and_limits_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
) -> Result<()> {
    serve_with_announcement_chirho(
        root_chirho,
        port_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        registration_token_chirho,
        true,
        served_request_limits_chirho,
    )
    .await
}

/// Start the HTTP server without writing the listen banner to stdout.
pub async fn serve_quiet_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
) -> Result<()> {
    serve_with_announcement_chirho(
        root_chirho,
        port_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        String::new(),
        false,
        ServedRequestAbuseLimitsChirho::default(),
    )
    .await
}

pub async fn serve_quiet_with_registration_token_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
) -> Result<()> {
    serve_with_announcement_chirho(
        root_chirho,
        port_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        registration_token_chirho,
        false,
        ServedRequestAbuseLimitsChirho::default(),
    )
    .await
}

/// Start the server with signed domain-binding routing enabled (host + path -> app route for
/// requests no explicit route matches). The flag comes from `domain_routing_enabled_chirho`
/// in `cairn-chirho.toml`; every other serve entry point keeps it off.
pub async fn serve_with_domain_routing_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
) -> Result<()> {
    serve_with_options_chirho(
        root_chirho,
        port_chirho,
        ServeOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho: ServeAuthTokensChirho::new_chirho(
                publish_token_chirho,
                registration_token_chirho,
            ),
            announce_chirho: true,
            domain_routing_enabled_chirho: true,
            served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            ledger_monitor_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
            startup_posture_chirho:
                ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        },
    )
    .await
}

async fn serve_with_announcement_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
    announce_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
) -> Result<()> {
    serve_with_options_chirho(
        root_chirho,
        port_chirho,
        ServeOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho: ServeAuthTokensChirho::new_chirho(
                publish_token_chirho,
                registration_token_chirho,
            ),
            announce_chirho,
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho,
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            ledger_monitor_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
            startup_posture_chirho:
                ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        },
    )
    .await
}

/// Start the configured runtime with the shared served-DAG admission limits. The limits are
/// process-local and reset only when an operator restarts the process.
pub async fn serve_with_configured_request_limits_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
) -> Result<()> {
    serve_with_configured_ledger_host_chirho(
        root_chirho,
        port_chirho,
        inflight_limit_chirho,
        ServeAuthTokensChirho::new_chirho(publish_token_chirho, registration_token_chirho),
        domain_routing_enabled_chirho,
        served_request_limits_chirho,
        ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho(),
    )
    .await
}

/// Start the configured runtime with an optional already-preflighted ledger host. The concrete
/// host remains available to the lifecycle owner for the H2 monitor loop; only its projection
/// read capability is injected into app execution.
pub async fn serve_with_configured_ledger_host_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    auth_tokens_chirho: ServeAuthTokensChirho,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
    runtime_ports_chirho: ConfiguredLedgerHostRuntimePortsChirho,
) -> Result<()> {
    let ConfiguredLedgerHostRuntimePortsChirho {
        ledger_host_chirho,
        postgres_effect_chirho,
        process_stop_chirho,
        write_dispatch_chirho,
        local_read_authority_chirho,
        write_destination_slot_chirho,
        startup_posture_chirho,
    } = runtime_ports_chirho;
    if startup_posture_chirho == ConfiguredServeStartupPostureChirho::RelayOnlyFollowerChirho {
        if postgres_effect_chirho.is_some()
            || write_dispatch_chirho.is_none()
            || local_read_authority_chirho.is_none()
            || write_destination_slot_chirho.is_none()
        {
            anyhow::bail!("RelayOnlyFollowerStartupCompositionInvalidChirho");
        }
        let era_chirho =
            cairn_writer_head_chirho::writer_head_chirho::writer_authority_era_chirho(root_chirho)?;
        if era_chirho
            != cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho::ElectedChirho
        {
            anyhow::bail!("RelayOnlyFollowerRequiresElectedRootChirho");
        }
    }
    serve_with_configured_ledger_host_and_monitor_ports_until_chirho(
        root_chirho,
        port_chirho,
        ConfiguredLedgerHostServeOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho,
            domain_routing_enabled_chirho,
            served_request_limits_chirho,
            ledger_host_chirho,
            postgres_effect_chirho,
            monitor_wait_chirho: Arc::new(TokioLedgerMonitorCadenceWaitChirho),
            monitor_alarm_chirho: Arc::new(FixedLedgerConservationAlarmChirho),
            write_dispatch_chirho,
            local_read_authority_chirho,
            write_destination_slot_chirho,
            startup_posture_chirho,
        },
        process_stop_chirho,
    )
    .await
}

async fn serve_with_configured_ledger_host_and_monitor_ports_until_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    options_chirho: ConfiguredLedgerHostServeOptionsChirho,
    stop_chirho: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let ConfiguredLedgerHostServeOptionsChirho {
        inflight_limit_chirho,
        auth_tokens_chirho,
        domain_routing_enabled_chirho,
        served_request_limits_chirho,
        ledger_host_chirho,
        postgres_effect_chirho,
        monitor_wait_chirho,
        monitor_alarm_chirho,
        write_dispatch_chirho,
        local_read_authority_chirho,
        write_destination_slot_chirho,
        startup_posture_chirho,
    } = options_chirho;
    let projection_read_chirho = ledger_host_chirho.as_ref().map(|host_chirho| {
        projection_read_port_for_effect_posture_chirho(
            host_chirho.clone(),
            postgres_effect_chirho.as_ref(),
        )
    });
    let ledger_monitor_chirho = match startup_posture_chirho {
        ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho => {
            ledger_host_chirho.map(|host_chirho| LedgerMonitorRuntimeChirho {
                host_chirho,
                wait_chirho: monitor_wait_chirho,
                alarm_chirho: monitor_alarm_chirho,
            })
        }
        ConfiguredServeStartupPostureChirho::RelayOnlyFollowerChirho => None,
    };
    serve_with_options_until_chirho(
        root_chirho,
        port_chirho,
        ServeOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho,
            announce_chirho: true,
            domain_routing_enabled_chirho,
            served_request_limits_chirho,
            projection_read_chirho,
            postgres_effect_chirho,
            llm_served_chirho: None,
            ledger_monitor_chirho,
            write_dispatch_chirho,
            local_read_authority_chirho,
            write_destination_slot_chirho,
            startup_posture_chirho,
        },
        stop_chirho,
    )
    .await
}

fn projection_read_port_for_effect_posture_chirho(
    host_chirho: Arc<LedgerHostProjectionReadPortChirho>,
    postgres_effect_chirho: Option<&SharedLedgerHostPostgresEffectRuntimeChirho>,
) -> Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>
{
    if postgres_effect_chirho.is_some() {
        ledger_host_runtime_chirho::effect_host_projection_read_port_chirho(host_chirho)
    } else {
        host_chirho
    }
}

/// Start a served runtime with one explicit CF4 published-projection read authority. Existing
/// serve entrypoints remain uncomposed and retain Brick 2's typed Query refusal.
pub async fn serve_with_projection_read_port_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    projection_read_chirho: Arc<
        dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
) -> Result<()> {
    serve_with_options_chirho(
        root_chirho,
        port_chirho,
        ServeOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho: ServeAuthTokensChirho::new_chirho(
                publish_token_chirho,
                String::new(),
            ),
            announce_chirho: true,
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
            projection_read_chirho: Some(projection_read_chirho),
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            ledger_monitor_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
            startup_posture_chirho:
                ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        },
    )
    .await
}

/// Dev-only loopback entry that serves with an injected served-LLM composition (a2b). The
/// composition can only be built through the test-kind door, and this entry additionally requires
/// the runtime env fence `CAIRN_DEV_LLM_SERVED_CHIRHO=1`; the `dev-llm-served-chirho` cargo feature
/// keeps it out of production builds entirely. The listener binds loopback only, exactly like every
/// other serve entry, so a non-loopback listener never gains the dev composition.
#[cfg(feature = "dev-llm-served-chirho")]
pub async fn serve_with_dev_llm_served_composition_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
    llm_served_chirho: SharedLlmServedCompositionChirho,
) -> Result<()> {
    serve_with_dev_llm_served_composition_until_chirho(
        root_chirho,
        port_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        registration_token_chirho,
        llm_served_chirho,
        None,
    )
    .await
}

/// The same dev-only loopback entry, but with a graceful-shutdown stop signal so a test can serve,
/// drive one HTTP request, then stop the server (which drops the composition and its resident
/// handle, releasing the exclusive ledger lock) before reading the substrate balances.
#[cfg(feature = "dev-llm-served-chirho")]
pub async fn serve_with_dev_llm_served_composition_until_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
    llm_served_chirho: SharedLlmServedCompositionChirho,
    stop_chirho: Option<Arc<AtomicBool>>,
) -> Result<()> {
    if std::env::var("CAIRN_DEV_LLM_SERVED_CHIRHO").ok().as_deref() != Some("1") {
        anyhow::bail!(
            "dev served-LLM composition refused: set CAIRN_DEV_LLM_SERVED_CHIRHO=1 to enable it"
        );
    }
    // GAP-1 startup fence: authoritatively bind the served root to the injected composition and
    // require a test-kind config BEFORE startup recovery, router build, or listener bind. The env
    // opt-in plus composition presence above is deliberately NOT the whole fence.
    llm_served_chirho.verify_dev_startup_eligibility_chirho(root_chirho)?;
    serve_with_options_until_chirho(
        root_chirho,
        port_chirho,
        ServeOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho: ServeAuthTokensChirho::new_chirho(
                publish_token_chirho,
                registration_token_chirho,
            ),
            announce_chirho: true,
            domain_routing_enabled_chirho: false,
            served_request_limits_chirho: ServedRequestAbuseLimitsChirho::default(),
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: Some(llm_served_chirho),
            ledger_monitor_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
            startup_posture_chirho:
                ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho,
        },
        stop_chirho,
    )
    .await
}

async fn serve_with_options_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    options_chirho: ServeOptionsChirho,
) -> Result<()> {
    serve_with_options_until_chirho(root_chirho, port_chirho, options_chirho, None).await
}

/// Whose container an app run's private values join when its request carries no signed-in context: the
/// app's verified owner, with no actor. A signed-in request declares nothing (its context decides), and an
/// app with no verified owner declares nothing either, so any private store such a run attempts refuses.
fn anonymous_app_attribution_chirho(
    state_chirho: &AppStateChirho,
    app_chirho: &str,
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Option<cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho>> {
    if request_context_chirho.is_some() {
        return Ok(None);
    }
    let Some(owner_principal_chirho) = app_chirho::verified_app_owner_chirho(
        state_chirho.runtime_chirho.root_path_chirho(),
        app_chirho,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(
        cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho::app_container_chirho(
            &owner_principal_chirho,
            None,
        )?,
    ))
}

/// A public run belongs to no app, so it declares no owner: a private store in one refuses.
fn try_run_chirho(
    state_chirho: &AppStateChirho,
    admission_chirho: &ServedDagAdmissionChirho,
    dag_hex_chirho: &str,
    input_chirho: &[u8],
) -> Result<Vec<u8>> {
    try_run_with_context_chirho(
        state_chirho,
        admission_chirho,
        dag_hex_chirho,
        input_chirho,
        None,
        None,
    )
}

fn try_run_with_context_chirho(
    state_chirho: &AppStateChirho,
    _admission_chirho: &ServedDagAdmissionChirho,
    dag_hex_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    declared_attribution_chirho: Option<
        &cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho,
    >,
) -> Result<Vec<u8>> {
    state_chirho.runtime_chirho.run_dag_with_intent_chirho(
        &HashChirho(dag_hex_chirho.to_string()),
        input_chirho,
        request_context_chirho,
        declared_attribution_chirho,
    )
}

async fn try_run_served_with_context_chirho(
    state_chirho: &AppStateChirho,
    _admission_chirho: &ServedDagAdmissionChirho,
    dag_hex_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    declared_attribution_chirho: Option<cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho>,
) -> Result<Vec<u8>> {
    try_run_served_with_context_and_caller_key_chirho(
        state_chirho,
        _admission_chirho,
        dag_hex_chirho,
        input_chirho,
        request_context_chirho,
        None,
        declared_attribution_chirho,
    )
    .await
}

/// Workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md`.
async fn try_run_served_with_context_and_caller_key_chirho(
    state_chirho: &AppStateChirho,
    _admission_chirho: &ServedDagAdmissionChirho,
    dag_hex_chirho: &str,
    input_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
    caller_key_chirho: Option<&CallerIdempotencyKeyChirho>,
    declared_attribution_chirho: Option<cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho>,
) -> Result<Vec<u8>> {
    state_chirho
        .runtime_chirho
        .run_dag_with_intent_for_served_request_and_caller_key_chirho(
            HashChirho(dag_hex_chirho.to_string()),
            input_chirho.to_vec(),
            request_context_chirho.cloned(),
            caller_key_chirho.cloned(),
            declared_attribution_chirho,
        )
        .await
}

async fn try_run_served_input_with_context_chirho(
    state_chirho: &AppStateChirho,
    admission_chirho: &ServedDagAdmissionChirho,
    dag_hex_chirho: &str,
    input_chirho: cairn_chirho::dag_chirho::DagInputValueChirho,
    request_context_chirho: Option<&RequestContextChirho>,
    caller_operation_chirho: Option<(&CallerIdempotencyKeyChirho, &CallerOperationBindingChirho)>,
    declared_attribution_chirho: Option<cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho>,
) -> Result<Vec<u8>> {
    match input_chirho {
        cairn_chirho::dag_chirho::DagInputValueChirho::PublicBytesChirho(bytes_chirho) => {
            match caller_operation_chirho {
                Some((caller_key_chirho, operation_chirho)) => {
                    state_chirho
                        .runtime_chirho
                        .run_dag_with_intent_for_served_caller_operation_chirho(
                            HashChirho(dag_hex_chirho.to_string()),
                            bytes_chirho,
                            request_context_chirho.cloned(),
                            caller_key_chirho.clone(),
                            operation_chirho.clone(),
                            declared_attribution_chirho,
                        )
                        .await
                }
                None => {
                    try_run_served_with_context_and_caller_key_chirho(
                        state_chirho,
                        admission_chirho,
                        dag_hex_chirho,
                        &bytes_chirho,
                        request_context_chirho,
                        None,
                        declared_attribution_chirho,
                    )
                    .await
                }
            }
        }
        cairn_chirho::dag_chirho::DagInputValueChirho::PrivateBytesChirho {
            subject_chirho,
            bytes_chirho,
        } => match caller_operation_chirho {
            Some((caller_key_chirho, operation_chirho)) => {
                state_chirho
                    .runtime_chirho
                    .run_dag_with_private_input_intent_for_served_caller_operation_chirho(
                        HashChirho(dag_hex_chirho.to_string()),
                        runtime_ports_chirho::ServedPrivateInputChirho {
                            subject_chirho,
                            bytes_chirho,
                        },
                        request_context_chirho.cloned(),
                        caller_key_chirho.clone(),
                        operation_chirho.clone(),
                        declared_attribution_chirho,
                    )
                    .await
            }
            None => {
                state_chirho
                    .runtime_chirho
                    .run_dag_with_private_input_intent_for_served_request_chirho(
                        HashChirho(dag_hex_chirho.to_string()),
                        runtime_ports_chirho::ServedPrivateInputChirho {
                            subject_chirho,
                            bytes_chirho,
                        },
                        request_context_chirho.cloned(),
                        None,
                        declared_attribution_chirho,
                    )
                    .await
            }
        },
    }
}

fn ensure_customer_write_tenant_root_chirho(
    state_chirho: &AppStateChirho,
    dag_chirho: &HashChirho,
    surface_chirho: &str,
) -> Result<()> {
    if !matches!(
        state_chirho.tenant_chirho,
        tenant_chirho::TenantIdChirho::PlatformRootChirho
    ) {
        return Ok(());
    }
    if !state_chirho
        .runtime_chirho
        .dag_has_write_store_chirho(dag_chirho)?
    {
        return Ok(());
    }
    anyhow::bail!(
        "customer WriteStoreChirho execution for {surface_chirho} requires an explicit tenant root; PlatformRootChirho is operator/dev only for pure/read app execution; restart with --tenant <tenant-id>"
    );
}

fn parse_content_hash_chirho(value_chirho: &str, label_chirho: &str) -> Result<HashChirho> {
    if value_chirho.len() != 64
        || !value_chirho
            .chars()
            .all(|ch_chirho| ch_chirho.is_ascii_hexdigit())
    {
        anyhow::bail!("{label_chirho} must be a 64-character hex content hash");
    }
    Ok(HashChirho(value_chirho.to_string()))
}

fn escape_html_chirho(value_chirho: &str) -> String {
    value_chirho
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn require_owner_session_chirho(
    root_chirho: &std::path::Path,
    headers_chirho: &HeaderMap,
    principal_chirho: &str,
) -> Option<Response> {
    if let Some(response_chirho) =
        require_principal_session_chirho(root_chirho, headers_chirho, principal_chirho)
    {
        return Some(response_chirho);
    }
    // The kind comes from the VERIFIED, cached identity map — not `find_identity_chirho`, which
    // reads `load_identities_chirho` and checks the schema string only. A user row edited to
    // `OwnerChirho` WITHOUT re-signing passed that raw read and was byte-equivalent to a real owner,
    // executed against the real promote route; this gate has twelve production callers.
    //
    // Only the DATA SOURCE changes. Every response arm below is byte-identical to the raw version,
    // deliberately: `ensure_owner_principal_chirho` is NOT used here because its two `bail!`
    // messages differ from each other and one interpolates the principal name, so propagating them
    // would move the reachable non-owner response from 403 -> 400. The unknown-principal body
    // becomes an existence oracle only if the session-to-principal binding above is removed.
    // Collapsing the unknown/non-owner bodies is the right privacy change and is a SEPARATE one,
    // with its own byte-identity arm.
    //
    // Verification loads the identity log as a whole and fails on the first sequence or signature
    // error. Therefore a row that EXISTS but fails verification does not take the `None` arm: the
    // map load returns `Err`, and this gate returns its global 400 error arm. The ordinary
    // non-owner and genuinely absent cases still retain their existing 403 response bodies.
    // The unknown-principal body is currently unreachable on the measured roads because the
    // session-to-principal binding runs first; the composition mutation proves that removing that
    // binding would make the body an existence oracle. Privacy collapse remains a separate,
    // scheduled change rather than part of this authority repair.
    //
    // Cost: none. The helper goes through `verified_view_cache_chirho::cached_identity_kind_map`,
    // so the warm served path keeps its zero-full-log-read invariant (M250).
    match app_chirho::verified_identity_kind_map_arc_chirho(root_chirho) {
        Ok(kind_map_chirho) => match kind_map_chirho.get(principal_chirho) {
            Some(kind_chirho) if *kind_chirho == identity_chirho::PrincipalKindChirho::OwnerChirho => None,
            Some(_kind_chirho) => Some((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"ok_chirho": false, "error_chirho": "support console requires an owner principal"})),
            )
                .into_response()),
            None => Some((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({"ok_chirho": false, "error_chirho": "unknown owner principal"})),
            )
                .into_response()),
        },
        Err(e_chirho) => Some((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok_chirho": false, "error_chirho": e_chirho.to_string()})),
        )
            .into_response()),
    }
}

fn ensure_owner_controls_app_chirho(
    root_chirho: &std::path::Path,
    owner_chirho: &str,
    app_chirho: &str,
) -> anyhow::Result<()> {
    let app_owner_chirho = app_chirho::verified_app_owner_chirho(root_chirho, app_chirho)?
        .ok_or_else(|| anyhow::anyhow!("app '{app_chirho}' has no owner"))?;
    if app_owner_chirho != owner_chirho {
        anyhow::bail!("owner '{owner_chirho}' does not control app '{app_chirho}'");
    }
    Ok(())
}

#[cfg(test)]
use app_http_chirho::{app_route_post_chirho, run_app_http_chirho};

#[cfg(test)]
#[path = "serve_chirho/tests_chirho/helpers_chirho/runtime_state_helpers_tests_chirho.rs"]
mod runtime_state_helpers_chirho;
#[cfg(test)]
use runtime_state_helpers_chirho::{
    app_state_for_runtime_root_chirho, runtime_router_for_root_chirho,
    runtime_router_for_root_with_projection_read_chirho,
};

#[cfg(test)]
#[path = "serve_chirho/app_state_tenant_context_tests_chirho.rs"]
mod app_state_tenant_context_tests_chirho;

#[cfg(test)]
#[path = "serve_chirho/tests_chirho.rs"]
mod tests_chirho;
