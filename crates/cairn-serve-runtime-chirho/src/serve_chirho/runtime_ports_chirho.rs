// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Private served-runtime root facade for the HA1 serve-through-ports migration.

#[path = "runtime_ports_chirho/pure_read_chirho.rs"]
mod pure_read_chirho;
#[path = "runtime_ports_chirho/request_input_chirho.rs"]
mod request_input_chirho;

#[cfg(test)]
#[path = "runtime_ports_chirho/served_run_hold_chirho.rs"]
pub(crate) mod served_run_hold_chirho;

#[cfg(test)]
#[path = "runtime_ports_chirho/road_count_carry_chirho.rs"]
mod road_count_carry_chirho;

use anyhow::Result;
use axum::http::HeaderMap;
use axum::response::Response;
use cairn_chirho::model_chirho::{
    CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, RefsChirho, RequestContextChirho,
};
use cairn_chirho::privacy_chirho::PrivateBlobAttributionChirho;
use cairn_chirho::{query_chirho, refs_chirho, store_chirho, versioned_chirho};
use cairn_write_relay_chirho::{CallerIdempotencyKeyChirho, CallerOperationBindingChirho};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{
    ledger_host_runtime_chirho::{
        LedgerHostPostgresEffectRefusalChirho, SharedLedgerHostPostgresEffectRuntimeChirho,
    },
    llm_served_runtime_chirho::SharedLlmServedCompositionChirho,
    ResourceGateSelectionChirho,
};

type AppStaticAssetSelectionChirho = super::app_assets_chirho::AppStaticAssetSelectionChirho;
type PublicAppDescriptorChirho = super::public_routes_chirho::AppDescriptorChirho;
type PublicRuntimePackageChirho = super::public_routes_chirho::RuntimePackageChirho;

/// The served facade's one hop onto the blocking pool, for the roads served-overload (ii) changed: provider sections,
/// served runs, the after-write refresh, the public run and preview. (The elected pure-read owner executor in
/// `pure_app_read_chirho` spawns its own blocking task.) In test builds the hop also carries the growth arms' per-thread
/// road counters from the pool thread back to the awaiting thread, so those arms keep counting work that executes there.
///
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.
pub(super) async fn run_on_blocking_pool_chirho<OutputChirho>(
    task_chirho: impl FnOnce() -> OutputChirho + Send + 'static,
) -> std::result::Result<OutputChirho, tokio::task::JoinError>
where
    OutputChirho: Send + 'static,
{
    #[cfg(test)]
    let task_chirho = road_count_carry_chirho::counted_chirho(task_chirho);
    let joined_chirho = tokio::task::spawn_blocking(task_chirho).await;
    #[cfg(test)]
    let joined_chirho = joined_chirho.map(road_count_carry_chirho::absorbed_chirho);
    joined_chirho
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/cf7-read-composition-design-chirho.md`.
async fn spawn_blocking_provider_task_chirho<OutputChirho>(
    task_chirho: impl FnOnce() -> Result<OutputChirho> + Send + 'static,
) -> Result<OutputChirho>
where
    OutputChirho: Send + 'static,
{
    run_on_blocking_pool_chirho(task_chirho)
        .await
        .map_err(|_join_error_chirho| {
            LedgerHostPostgresEffectRefusalChirho::BlockingDispatchUnavailableChirho
        })?
}

/// A served run on the blocking pool in EVERY configuration, so its synchronous work never holds an async worker. A
/// Postgres configuration keeps its existing refusal identity for a blocking task that cannot complete.
///
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.
async fn spawn_blocking_served_run_chirho<OutputChirho>(
    postgres_configured_chirho: bool,
    task_chirho: impl FnOnce() -> Result<OutputChirho> + Send + 'static,
) -> Result<OutputChirho>
where
    OutputChirho: Send + 'static,
{
    if postgres_configured_chirho {
        return spawn_blocking_provider_task_chirho(task_chirho).await;
    }
    outcome_of_owned_work_chirho(run_on_blocking_pool_chirho(task_chirho).await)
}

/// The outcome of served work that ran in its own task: a blocking closure, or a detached task, that owns the request's
/// admission. A panic in the work unwinds the waiting request exactly as it did when the work ran inline, so no answer
/// claims that work which may have started was refused or had no effect: its result is unknown, and the caller's key
/// and the run intent's replay binding stay the way to learn it. Nothing aborts this work, so only a runtime shutdown
/// can cancel it, and that tears the waiting request down with it.
///
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.
pub(super) fn outcome_of_owned_work_chirho<OutputChirho>(
    joined_chirho: std::result::Result<OutputChirho, tokio::task::JoinError>,
) -> OutputChirho {
    match joined_chirho {
        Ok(output_chirho) => output_chirho,
        Err(join_error_chirho) => match join_error_chirho.try_into_panic() {
            Ok(panic_chirho) => std::panic::resume_unwind(panic_chirho),
            Err(_cancelled_chirho) => panic!("served work was cancelled by its runtime's shutdown"),
        },
    }
}

/// Await a DETACHED task that owns served work, with the outcome rule above.
///
/// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.
pub(super) async fn await_owned_served_work_chirho<OutputChirho>(
    work_chirho: tokio::task::JoinHandle<OutputChirho>,
) -> OutputChirho {
    outcome_of_owned_work_chirho(work_chirho.await)
}

/// A served private request body and the subject it is stored under, which always travel together.
pub(super) struct ServedPrivateInputChirho {
    pub(super) subject_chirho: String,
    pub(super) bytes_chirho: Vec<u8>,
}

pub(super) async fn resume_unfinished_run_intents_for_served_effect_runtime_chirho(
    root_chirho: PathBuf,
    projection_read_chirho: Option<
        Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>,
    >,
    postgres_effect_chirho: SharedLedgerHostPostgresEffectRuntimeChirho,
) -> Result<cairn_chirho::effect_chirho::run_intent_chirho::RunIntentResumeReportChirho> {
    spawn_blocking_provider_task_chirho(move || {
        postgres_effect_chirho.with_runtime_chirho(|provider_chirho| {
            let runtime_ports_chirho = cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                projection_read_chirho: projection_read_chirho.as_deref(),
                postgres_reversible_chirho: Some(provider_chirho),
                // Served-LLM dev composition not yet wired into serve; the next brick composes it
                // behind a dev config. `None` keeps the served card refusing pre-effect (resendable).
                llm_served_chirho: None,
                // A resume takes no declaration: startup cannot know any one run's owner.
                private_attribution_chirho: None,
            };
            cairn_chirho::effect_chirho::run_intent_chirho::resume_unfinished_run_intents_with_effect_runtime_chirho(
                &root_chirho,
                runtime_ports_chirho,
            )
        })
    })
    .await
}

#[derive(Clone)]
pub(super) struct ServedRuntimeRootChirho {
    root_chirho: PathBuf,
    projection_read_chirho: Option<
        Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>,
    >,
    postgres_effect_chirho: Option<SharedLedgerHostPostgresEffectRuntimeChirho>,
    /// Dev-only served-LLM composition (loopback + env-fenced). `None` on every production path.
    llm_served_chirho: Option<SharedLlmServedCompositionChirho>,
}

impl ServedRuntimeRootChirho {
    #[cfg(test)]
    pub(super) fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            projection_read_chirho: None,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
        }
    }

    pub(super) fn with_effect_runtime_chirho(
        root_chirho: &Path,
        projection_read_chirho: Option<
            Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>,
        >,
        postgres_effect_chirho: Option<SharedLedgerHostPostgresEffectRuntimeChirho>,
        llm_served_chirho: Option<SharedLlmServedCompositionChirho>,
    ) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
            projection_read_chirho,
            postgres_effect_chirho,
            llm_served_chirho,
        }
    }

    /// Transitional migration scaffold while served routes move to narrower facade methods.
    pub(super) fn root_path_chirho(&self) -> &Path {
        &self.root_chirho
    }

    /// The named app route's after-write refresh, on the blocking pool: it rebuilds the derived query projection when
    /// the DAG has a write store. A failure, a panic included, comes back as an error for the caller to log: the write
    /// it follows has already landed, so it must never become the request's answer.
    ///
    /// Workflow: `spec-chirho/workflows-chirho/served-request-admission-chirho/off-worker-runs-design-chirho.md`.
    pub(super) async fn refresh_query_projection_after_write_chirho(
        &self,
        dag_chirho: &HashChirho,
    ) -> Result<()> {
        let runtime_chirho = self.clone();
        let dag_chirho = dag_chirho.clone();
        run_on_blocking_pool_chirho(move || {
            #[cfg(test)]
            served_run_hold_chirho::wait_if_armed_chirho(
                &runtime_chirho.root_chirho,
                served_run_hold_chirho::HoldSiteChirho::RefreshChirho,
            )?;
            if !runtime_chirho.dag_has_write_store_chirho(&dag_chirho)? {
                return Ok(());
            }
            runtime_chirho.project_query_projection_chirho()
        })
        .await
        .unwrap_or_else(|_join_error_chirho| {
            Err(anyhow::anyhow!("the after-write refresh did not complete"))
        })
    }

    /// Test-only: park the invoke critical section after its run, without blocking the worker it runs on.
    #[cfg(test)]
    pub(super) async fn wait_at_invoke_after_run_hold_chirho(&self) {
        served_run_hold_chirho::wait_if_armed_async_chirho(
            &self.root_chirho,
            served_run_hold_chirho::HoldSiteChirho::InvokeAfterRunChirho,
        )
        .await
        .expect("the invoke hold parks or panics; it has no failure to inject");
    }

    pub(super) fn load_refs_chirho(&self) -> Result<RefsChirho> {
        refs_chirho::load_refs_chirho(&self.root_chirho)
    }

    pub(super) fn writer_authority_era_chirho(
        &self,
    ) -> Result<cairn_writer_head_chirho::writer_head_chirho::WriterAuthorityEraChirho> {
        cairn_writer_head_chirho::writer_head_chirho::writer_authority_era_chirho(&self.root_chirho)
    }

    /// The one composed served-LLM card surface (app name, single paid route) when a dev served-LLM
    /// composition is injected on this root; `None` on every ordinary runtime, so the served
    /// dispatch only activates for the app the operator explicitly composed.
    pub(super) fn llm_served_card_surface_chirho(&self) -> Option<(&str, &str)> {
        self.llm_served_chirho.as_ref().map(|composition_chirho| {
            (
                composition_chirho.served_app_chirho(),
                composition_chirho.paid_route_chirho(),
            )
        })
    }

    /// GAP-2 live-authority readiness for the served paid route: `Some(Ok)` only when a composition
    /// is present AND the resident actor's LIVE local append authority acquires (then drops) cleanly;
    /// `Some(Err(reason))` carries the specific write-path/contention refusal so the dispatch can LOG
    /// it (not discard it via `is_ok`) while returning a no-detail public body; `None` when no
    /// composition is injected. This is the CURRENT authority path, not a static era or binding check.
    pub(super) fn probe_llm_served_local_authority_chirho(&self) -> Option<Result<()>> {
        self.llm_served_chirho
            .as_ref()
            .map(|composition_chirho| composition_chirho.probe_local_authority_live_chirho())
    }

    // Keyless GET purity for the served render root reuses `ensure_public_run_dag_is_pure_wasm_chirho`
    // (below), which rejects declared capabilities AND native specs. The earlier capability-only
    // `ensure_served_render_dag_pure_chirho` was removed (Finding 5): a native node would have bypassed
    // it, and one Tier-1 pure-WASM guard is the single source of truth.

    pub(super) fn current_view_chirho(&self) -> Result<u64> {
        versioned_chirho::VersionedStoreChirho::open_chirho(
            &self.root_chirho.join("versioned-chirho.redb"),
        )?
        .current_view_chirho()
    }

    pub(super) fn require_owner_session_chirho(
        &self,
        headers_chirho: &HeaderMap,
        principal_chirho: &str,
    ) -> Option<Response> {
        super::require_owner_session_chirho(&self.root_chirho, headers_chirho, principal_chirho)
    }

    pub(super) fn require_principal_session_chirho(
        &self,
        headers_chirho: &HeaderMap,
        principal_chirho: &str,
    ) -> Option<Response> {
        super::require_principal_session_chirho(&self.root_chirho, headers_chirho, principal_chirho)
    }

    pub(super) fn verified_domain_bindings_chirho(
        &self,
    ) -> Result<Vec<super::app_http_chirho::DomainBindingRecordChirho>> {
        super::app_http_chirho::verified_domain_bindings_for_root_chirho(&self.root_chirho)
    }

    pub(super) fn request_context_for_app_chirho(
        &self,
        headers_chirho: &HeaderMap,
        app_name_chirho: &str,
    ) -> Result<Option<RequestContextChirho>> {
        super::request_context_for_app_chirho(&self.root_chirho, headers_chirho, app_name_chirho)
    }

    /// The app road's request context for `route_chirho` (or the app root), with a limited key's binding.
    pub(super) fn request_context_for_app_route_chirho(
        &self,
        headers_chirho: &HeaderMap,
        app_name_chirho: &str,
        route_chirho: Option<&str>,
    ) -> Result<super::AppRouteRequestContextChirho> {
        super::request_context_for_app_route_chirho(
            &self.root_chirho,
            headers_chirho,
            app_name_chirho,
            route_chirho,
        )
    }

    pub(super) fn app_request_access_policy_chirho(
        &self,
        app_name_chirho: &str,
    ) -> Result<cairn_chirho::app_chirho::AppRequestAccessPolicyChirho> {
        #[cfg(test)]
        super::public_error_chirho::hold_points_chirho::reach_chirho(
            super::public_error_chirho::hold_points_chirho::HoldPointChirho::BeforeRequestAccessPolicyReadChirho,
        );
        cairn_chirho::app_chirho::app_request_access_policy_chirho(
            &self.root_chirho,
            app_name_chirho,
        )
    }

    pub(super) fn prepare_app_request_context_chirho(
        &self,
        headers_chirho: &HeaderMap,
        app_name_chirho: &str,
        route_chirho: Option<&str>,
    ) -> Result<super::PreparedAppRequestContextChirho> {
        super::prepare_app_request_context_chirho(
            &self.root_chirho,
            headers_chirho,
            app_name_chirho,
            route_chirho,
        )
    }

    pub(super) fn commit_prepared_app_request_context_chirho(
        &self,
        prepared_chirho: super::PreparedAppRequestContextChirho,
    ) -> Result<Option<RequestContextChirho>> {
        super::commit_prepared_app_request_context_chirho(&self.root_chirho, prepared_chirho)
    }

    pub(super) fn select_app_dag_with_resource_gate_chirho(
        &self,
        refs_chirho: &RefsChirho,
        app_name_chirho: &str,
        request_context_chirho: Option<&RequestContextChirho>,
    ) -> Result<ResourceGateSelectionChirho> {
        super::select_app_dag_with_resource_gate_chirho(
            &self.root_chirho,
            refs_chirho,
            app_name_chirho,
            request_context_chirho,
        )
    }

    pub(super) fn select_app_dag_without_resource_usage_chirho(
        &self,
        refs_chirho: &RefsChirho,
        app_name_chirho: &str,
    ) -> Result<Option<ResourceGateSelectionChirho>> {
        super::select_app_dag_without_resource_usage_chirho(
            &self.root_chirho,
            refs_chirho,
            app_name_chirho,
        )
    }

    pub(super) fn select_app_route_dag_direct_chirho(
        &self,
        refs_chirho: &RefsChirho,
        app_name_chirho: &str,
        route_chirho: &str,
        request_context_chirho: Option<&RequestContextChirho>,
    ) -> Result<ResourceGateSelectionChirho> {
        super::select_app_route_dag_direct_chirho(
            &self.root_chirho,
            refs_chirho,
            app_name_chirho,
            route_chirho,
            request_context_chirho,
        )
    }

    /// Whether the route's verified request-body policy accepts a body, read from the APP'S verified owner. It never
    /// resolves the caller: this check runs before the body is read and again just before execution, and resolving
    /// the caller here charged a scoped bearer once per check, three uses per POST (PFE #25731, CAIRN #25732). The
    /// caller is resolved, and charged once, by the execution itself.
    pub(super) fn direct_app_route_accepts_request_body_chirho(
        &self,
        app_name_chirho: &str,
        route_chirho: &str,
    ) -> Result<bool> {
        let owner_principal_chirho = cairn_chirho::app_chirho::verified_app_owner_chirho(
            &self.root_chirho,
            app_name_chirho,
        )?
        .ok_or_else(|| anyhow::anyhow!("no deployed app '{app_name_chirho}'"))?;
        let refs_chirho = self.load_refs_chirho()?;
        let dag_chirho = cairn_chirho::app_chirho::resolve_app_route_chirho(
            &self.root_chirho,
            &refs_chirho,
            app_name_chirho,
            route_chirho,
            &owner_principal_chirho,
        )?;
        Ok(cairn_chirho::app_chirho::verified_app_route_request_body_policy_chirho(
            &self.root_chirho,
            app_name_chirho,
            route_chirho,
            &owner_principal_chirho,
            &dag_chirho,
        )?
        .as_ref()
        .is_none_or(
            cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::accepts_request_body_chirho,
        ))
    }

    /// Whether a refused browser form may land on `route_chirho` (PFE #29303, #29320), read from the APP'S
    /// verified records:
    /// - the route table declares the route;
    /// - its signed body policy is exactly `NoBodyChirho`, so a GET of it carries no body (a route with no
    ///   policy accepts a body by default);
    /// - the answer type its served GET would carry is exactly `APP_RESPONSE_HTML_CONTENT_TYPE_CHIRHO`,
    ///   never a prefix match.
    ///
    /// Anything else, a failed read included, is not a landing, and the browser goes to the app's home.
    /// Like the body-policy check, it never resolves the caller.
    ///
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/serve-write-forwarding-design-chirho.md` (7.1).
    pub(super) fn direct_app_route_is_refusal_landing_chirho(
        &self,
        app_name_chirho: &str,
        route_chirho: &str,
    ) -> bool {
        self.direct_app_route_refusal_landing_chirho(app_name_chirho, route_chirho)
            .unwrap_or(false)
    }

    /// The 303 a refused browser form on `app_name_chirho` gets, naming `token_chirho`: back to the
    /// Referer's page when it is a landing (`direct_app_route_is_refusal_landing_chirho`), else the app's
    /// home. It is the one door both the served card's pre-run refusals and the relay's refusal answer
    /// use, so neither can choose a landing any other way.
    pub(super) fn browser_form_refusal_on_app_chirho(
        &self,
        headers_chirho: &HeaderMap,
        app_name_chirho: &str,
        token_chirho: &str,
    ) -> Response {
        super::write_relay_chirho::caller_key_carrier_chirho::browser_form_refusal_response_chirho(
            headers_chirho,
            app_name_chirho,
            |route_chirho| {
                self.direct_app_route_is_refusal_landing_chirho(app_name_chirho, route_chirho)
            },
            token_chirho,
        )
    }

    fn direct_app_route_refusal_landing_chirho(
        &self,
        app_name_chirho: &str,
        route_chirho: &str,
    ) -> Result<bool> {
        let Some(owner_principal_chirho) = cairn_chirho::app_chirho::verified_app_owner_chirho(
            &self.root_chirho,
            app_name_chirho,
        )?
        else {
            return Ok(false);
        };
        let refs_chirho = self.load_refs_chirho()?;
        let dag_chirho = cairn_chirho::app_chirho::resolve_app_route_chirho(
            &self.root_chirho,
            &refs_chirho,
            app_name_chirho,
            route_chirho,
            &owner_principal_chirho,
        )?;
        let bodyless_chirho = matches!(
            cairn_chirho::app_chirho::verified_app_route_request_body_policy_chirho(
                &self.root_chirho,
                app_name_chirho,
                route_chirho,
                &owner_principal_chirho,
                &dag_chirho,
            )?,
            Some(cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho)
        );
        if !bodyless_chirho {
            return Ok(false);
        }
        Ok(self
            .app_route_http_response_content_type_chirho(app_name_chirho, Some(route_chirho), None)?
            .as_deref()
            == Some(cairn_model_app_chirho::APP_RESPONSE_HTML_CONTENT_TYPE_CHIRHO))
    }

    pub(super) fn direct_app_accepts_request_body_chirho(
        &self,
        app_name_chirho: &str,
    ) -> Result<bool> {
        let refs_chirho = self.load_refs_chirho()?;
        let resolved_chirho = cairn_chirho::app_chirho::resolve_app_dag_chirho(
            &self.root_chirho,
            &refs_chirho,
            app_name_chirho,
        )?;
        Ok(cairn_chirho::app_chirho::app_root_request_body_policy_chirho(
            &self.root_chirho,
            app_name_chirho,
            &resolved_chirho.owner_principal_chirho,
        )?
        .as_ref()
        .is_none_or(
            cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::accepts_request_body_chirho,
        ))
    }

    pub(super) fn app_dag_input_chirho(
        &self,
        app_chirho: &str,
        route_chirho: Option<&str>,
        context_chirho: Option<&RequestContextChirho>,
        input_chirho: Vec<u8>,
    ) -> Result<Vec<u8>> {
        super::app_dag_input_chirho(
            &self.root_chirho,
            app_chirho,
            route_chirho,
            context_chirho,
            input_chirho,
        )
    }

    pub(super) fn app_http_dag_input_value_chirho(
        &self,
        app_chirho: &str,
        route_chirho: Option<&str>,
        context_chirho: Option<&RequestContextChirho>,
        headers_chirho: &HeaderMap,
        input_chirho: Vec<u8>,
    ) -> Result<cairn_chirho::dag_chirho::DagInputValueChirho> {
        super::app_http_dag_input_value_chirho(
            &self.root_chirho,
            app_chirho,
            route_chirho,
            context_chirho,
            headers_chirho,
            input_chirho,
        )
    }

    pub(super) fn app_route_http_response_content_type_chirho(
        &self,
        app_chirho: &str,
        route_chirho: Option<&str>,
        context_chirho: Option<&RequestContextChirho>,
    ) -> Result<Option<String>> {
        super::app_http_chirho::app_route_http_response_content_type_chirho(
            &self.root_chirho,
            app_chirho,
            route_chirho,
            context_chirho,
        )
    }

    pub(super) fn apply_app_route_response_security_headers_chirho(
        &self,
        app_chirho: &str,
        payload_chirho: &[u8],
        headers_chirho: &mut HeaderMap,
        response_content_type_chirho: &str,
    ) {
        super::app_http_chirho::apply_app_route_response_security_headers_chirho(
            &self.root_chirho,
            app_chirho,
            payload_chirho,
            headers_chirho,
            response_content_type_chirho,
        );
    }

    /// Bring the query read model up to date after a served write — **incrementally**
    /// (`refresh_incremental_chirho`): apply only the changed-key delta since the projection's
    /// cursor rather than rebuilding the whole table, so a served write costs O(delta), not
    /// O(all rows). Opens its own versioned-store handle; the write's handle is already dropped by
    /// the time this runs (same open-own-handle pattern the prior full `project_chirho` used here).
    pub(super) fn project_query_projection_chirho(&self) -> Result<()> {
        query_chirho::refresh_incremental_chirho(&self.root_chirho).map(|_rows_chirho| ())
    }

    pub(super) fn html_lower_chirho(
        &self,
        body_chirho: &[u8],
        app_chirho: &str,
        app_ref_chirho: &str,
    ) -> String {
        super::ssr_web_chirho::html_lower_chirho(
            &self.root_chirho,
            body_chirho,
            app_chirho,
            app_ref_chirho,
        )
    }

    pub(super) fn ensure_public_run_dag_is_pure_wasm_chirho(
        &self,
        dag_hash_chirho: &HashChirho,
    ) -> Result<()> {
        super::public_run_chirho::ensure_public_run_dag_is_pure_wasm_chirho(
            &self.root_chirho,
            dag_hash_chirho,
        )
    }

    pub(super) fn preview_dag_payload_chirho(
        &self,
        dag_hash_chirho: &HashChirho,
        input_chirho: &[u8],
    ) -> Result<Vec<u8>> {
        #[cfg(test)]
        served_run_hold_chirho::wait_if_armed_chirho(
            &self.root_chirho,
            served_run_hold_chirho::HoldSiteChirho::RunChirho,
        )?;
        super::public_run_chirho::preview_dag_payload_for_root_chirho(
            &self.root_chirho,
            dag_hash_chirho,
            input_chirho,
        )
    }

    pub(super) fn validate_public_runtime_package_chirho(
        &self,
        package_hash_chirho: &HashChirho,
    ) -> Result<PublicRuntimePackageChirho> {
        super::public_routes_chirho::validate_public_runtime_package_for_root_chirho(
            &self.root_chirho,
            package_hash_chirho,
        )
    }

    pub(super) fn public_runtime_package_executable_bytes_chirho(
        &self,
        package_chirho: &PublicRuntimePackageChirho,
    ) -> Result<Vec<u8>> {
        super::public_routes_chirho::public_runtime_package_executable_bytes_for_root_chirho(
            &self.root_chirho,
            package_chirho,
        )
    }

    pub(super) fn public_app_descriptor_chirho(
        &self,
        app_chirho: &str,
    ) -> Result<Option<PublicAppDescriptorChirho>> {
        super::public_routes_chirho::public_app_descriptor_for_root_chirho(
            &self.root_chirho,
            app_chirho,
        )
    }

    pub(super) fn app_static_asset_by_name_chirho(
        &self,
        app_chirho: &str,
        name_chirho: &str,
    ) -> Result<Option<AppStaticAssetSelectionChirho>> {
        super::app_assets_chirho::app_static_asset_by_name_for_root_chirho(
            &self.root_chirho,
            app_chirho,
            name_chirho,
        )
    }

    pub(super) fn app_static_asset_by_hash_chirho(
        &self,
        app_chirho: &str,
        asset_chirho: &HashChirho,
    ) -> Result<Option<AppStaticAssetSelectionChirho>> {
        super::app_assets_chirho::app_static_asset_by_hash_for_root_chirho(
            &self.root_chirho,
            app_chirho,
            asset_chirho,
        )
    }

    pub(super) fn app_static_asset_bytes_chirho(
        &self,
        selection_chirho: &AppStaticAssetSelectionChirho,
    ) -> Result<Vec<u8>> {
        super::app_assets_chirho::app_static_asset_bytes_for_root_chirho(
            &self.root_chirho,
            selection_chirho,
        )
    }

    /// `declared_attribution_chirho` is whose container a run with no request context puts its private
    /// values in: the app owner, for an anonymous app request. With neither, a private store refuses.
    pub(super) fn run_dag_with_intent_chirho(
        &self,
        dag_chirho: &HashChirho,
        input_chirho: &[u8],
        context_chirho: Option<&RequestContextChirho>,
        declared_attribution_chirho: Option<&PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        self.run_dag_with_optional_caller_key_chirho(
            dag_chirho,
            input_chirho,
            context_chirho,
            None,
            None,
            declared_attribution_chirho,
        )
    }

    fn run_dag_with_optional_caller_key_chirho(
        &self,
        dag_chirho: &HashChirho,
        input_chirho: &[u8],
        context_chirho: Option<&RequestContextChirho>,
        caller_key_chirho: Option<&CallerIdempotencyKeyChirho>,
        caller_operation_chirho: Option<&CallerOperationBindingChirho>,
        declared_attribution_chirho: Option<&PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        #[cfg(test)]
        served_run_hold_chirho::wait_if_armed_chirho(
            &self.root_chirho,
            served_run_hold_chirho::HoldSiteChirho::RunChirho,
        )?;
        if caller_operation_chirho.is_some() && caller_key_chirho.is_none() {
            anyhow::bail!("served caller operation requires a caller key");
        }
        // Dev served-LLM lane: build the composition fresh inside its Mutex and wire it as the
        // `llm_served` effect port. The dev composition is its own lane (postgres absent); fail
        // closed if both are set rather than silently dropping one.
        if let Some(llm_served_chirho) = &self.llm_served_chirho {
            if self.postgres_effect_chirho.is_some() {
                anyhow::bail!(
                    "dev served-LLM lane does not compose with the postgres effect runtime"
                );
            }
            return llm_served_chirho.with_composition_chirho(|llm_runtime_chirho| {
                let runtime_ports_chirho =
                    cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                        projection_read_chirho: self.projection_read_chirho.as_deref(),
                        postgres_reversible_chirho: None,
                        llm_served_chirho: Some(llm_runtime_chirho),
                        private_attribution_chirho: declared_attribution_chirho,
                    };
                let report_chirho = match (caller_key_chirho, caller_operation_chirho) {
                    (Some(caller_key_chirho), Some(caller_operation_chirho)) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_and_caller_operation_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        input_chirho,
                        context_chirho,
                        runtime_ports_chirho,
                        caller_key_chirho,
                        caller_operation_chirho,
                    )?,
                    (Some(caller_key_chirho), None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_and_caller_key_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        input_chirho,
                        context_chirho,
                        runtime_ports_chirho,
                        caller_key_chirho,
                    )?,
                    (None, None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        input_chirho,
                        context_chirho,
                        runtime_ports_chirho,
                    )?,
                    (None, Some(_caller_operation_chirho)) => unreachable!("validated above"),
                };
                Ok(report_chirho.payload_chirho)
            });
        }
        match &self.postgres_effect_chirho {
            Some(postgres_effect_chirho) => postgres_effect_chirho.with_runtime_chirho(
                |provider_chirho| {
                    let runtime_ports_chirho =
                        cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                            projection_read_chirho: self.projection_read_chirho.as_deref(),
                            postgres_reversible_chirho: Some(provider_chirho),
                            llm_served_chirho: None,
                            private_attribution_chirho: declared_attribution_chirho,
                        };
                    match (caller_key_chirho, caller_operation_chirho) {
                        (Some(caller_key_chirho), Some(caller_operation_chirho)) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_and_caller_operation_chirho(
                            &self.root_chirho,
                            dag_chirho,
                            input_chirho,
                            context_chirho,
                            runtime_ports_chirho,
                            caller_key_chirho,
                            caller_operation_chirho,
                        ),
                        (Some(caller_key_chirho), None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_and_caller_key_chirho(
                            &self.root_chirho,
                            dag_chirho,
                            input_chirho,
                            context_chirho,
                            runtime_ports_chirho,
                            caller_key_chirho,
                        ),
                        (None, None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_chirho(
                            &self.root_chirho,
                            dag_chirho,
                            input_chirho,
                            context_chirho,
                            runtime_ports_chirho,
                        ),
                        (None, Some(_caller_operation_chirho)) => unreachable!("validated above"),
                    }
                },
            ),
            None => {
                let projection_read_chirho = self.projection_read_chirho.as_deref();
                let plain_ports_chirho = || cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                    projection_read_chirho,
                    postgres_reversible_chirho: None,
                    llm_served_chirho: None,
                    private_attribution_chirho: declared_attribution_chirho,
                };
                match (caller_key_chirho, caller_operation_chirho) {
                    (Some(caller_key_chirho), Some(caller_operation_chirho)) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_and_caller_operation_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        input_chirho,
                        context_chirho,
                        cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                            projection_read_chirho,
                            postgres_reversible_chirho: None,
                            llm_served_chirho: None,
                            private_attribution_chirho: declared_attribution_chirho,
                        },
                        caller_key_chirho,
                        caller_operation_chirho,
                    ),
                    (Some(caller_key_chirho), None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_and_caller_key_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        input_chirho,
                        context_chirho,
                        plain_ports_chirho(),
                        caller_key_chirho,
                    ),
                    (None, None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        input_chirho,
                        context_chirho,
                        plain_ports_chirho(),
                    ),
                    (None, Some(_caller_operation_chirho)) => unreachable!("validated above"),
                }
            }
        }
        .map(|report_chirho| report_chirho.payload_chirho)
    }

    pub(super) async fn run_dag_with_intent_for_served_request_and_caller_key_chirho(
        &self,
        dag_chirho: HashChirho,
        input_chirho: Vec<u8>,
        context_chirho: Option<RequestContextChirho>,
        caller_key_chirho: Option<CallerIdempotencyKeyChirho>,
        declared_attribution_chirho: Option<PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        self.run_dag_with_intent_for_served_request_optional_caller_key_chirho(
            dag_chirho,
            input_chirho,
            context_chirho,
            caller_key_chirho,
            None,
            declared_attribution_chirho,
        )
        .await
    }

    pub(super) async fn run_dag_with_intent_for_served_caller_operation_chirho(
        &self,
        dag_chirho: HashChirho,
        input_chirho: Vec<u8>,
        context_chirho: Option<RequestContextChirho>,
        caller_key_chirho: CallerIdempotencyKeyChirho,
        caller_operation_chirho: CallerOperationBindingChirho,
        declared_attribution_chirho: Option<PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        self.run_dag_with_intent_for_served_request_optional_caller_key_chirho(
            dag_chirho,
            input_chirho,
            context_chirho,
            Some(caller_key_chirho),
            Some(caller_operation_chirho),
            declared_attribution_chirho,
        )
        .await
    }

    async fn run_dag_with_intent_for_served_request_optional_caller_key_chirho(
        &self,
        dag_chirho: HashChirho,
        input_chirho: Vec<u8>,
        context_chirho: Option<RequestContextChirho>,
        caller_key_chirho: Option<CallerIdempotencyKeyChirho>,
        caller_operation_chirho: Option<CallerOperationBindingChirho>,
        declared_attribution_chirho: Option<PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        let runtime_chirho = self.clone();
        spawn_blocking_served_run_chirho(self.postgres_effect_chirho.is_some(), move || {
            runtime_chirho.run_dag_with_optional_caller_key_chirho(
                &dag_chirho,
                &input_chirho,
                context_chirho.as_ref(),
                caller_key_chirho.as_ref(),
                caller_operation_chirho.as_ref(),
                declared_attribution_chirho.as_ref(),
            )
        })
        .await
    }

    fn run_dag_with_private_input_intent_optional_caller_key_chirho(
        &self,
        dag_chirho: &HashChirho,
        private_input_chirho: &ServedPrivateInputChirho,
        context_chirho: Option<&RequestContextChirho>,
        caller_key_chirho: Option<&CallerIdempotencyKeyChirho>,
        caller_operation_chirho: Option<&CallerOperationBindingChirho>,
        declared_attribution_chirho: Option<&PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        let subject_chirho = private_input_chirho.subject_chirho.as_str();
        let bytes_chirho = private_input_chirho.bytes_chirho.as_slice();
        #[cfg(test)]
        served_run_hold_chirho::wait_if_armed_chirho(
            &self.root_chirho,
            served_run_hold_chirho::HoldSiteChirho::RunChirho,
        )?;
        if caller_operation_chirho.is_some() && caller_key_chirho.is_none() {
            anyhow::bail!("served caller operation requires a caller key");
        }
        // Dev served-LLM lane (private input): the served-LLM card runs here. Build the composition
        // fresh inside its Mutex and wire it as the `llm_served` effect port. Fail closed if the
        // postgres runtime is also present rather than silently dropping one.
        if let Some(llm_served_chirho) = &self.llm_served_chirho {
            if self.postgres_effect_chirho.is_some() {
                anyhow::bail!(
                    "dev served-LLM lane does not compose with the postgres effect runtime"
                );
            }
            return llm_served_chirho.with_composition_chirho(|llm_runtime_chirho| {
                let runtime_ports_chirho =
                    cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                        projection_read_chirho: self.projection_read_chirho.as_deref(),
                        postgres_reversible_chirho: None,
                        llm_served_chirho: Some(llm_runtime_chirho),
                        private_attribution_chirho: declared_attribution_chirho,
                    };
                let report_chirho = match (caller_key_chirho, caller_operation_chirho) {
                    (Some(caller_key_chirho), Some(caller_operation_chirho)) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_and_caller_operation_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        subject_chirho,
                        bytes_chirho,
                        context_chirho,
                        runtime_ports_chirho,
                        caller_key_chirho,
                        caller_operation_chirho,
                    )?,
                    (Some(caller_key_chirho), None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_and_caller_key_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        subject_chirho,
                        bytes_chirho,
                        context_chirho,
                        runtime_ports_chirho,
                        caller_key_chirho,
                    )?,
                    (None, None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        subject_chirho,
                        bytes_chirho,
                        context_chirho,
                        runtime_ports_chirho,
                    )?,
                    (None, Some(_caller_operation_chirho)) => unreachable!("validated above"),
                };
                Ok(report_chirho.payload_chirho)
            });
        }
        match &self.postgres_effect_chirho {
            Some(postgres_effect_chirho) => postgres_effect_chirho.with_runtime_chirho(
                |provider_chirho| {
                    let runtime_ports_chirho =
                        cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                            projection_read_chirho: self.projection_read_chirho.as_deref(),
                            postgres_reversible_chirho: Some(provider_chirho),
                            llm_served_chirho: None,
                            private_attribution_chirho: declared_attribution_chirho,
                        };
                    match (caller_key_chirho, caller_operation_chirho) {
                        (Some(caller_key_chirho), Some(caller_operation_chirho)) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_and_caller_operation_chirho(
                            &self.root_chirho,
                            dag_chirho,
                            subject_chirho,
                            bytes_chirho,
                            context_chirho,
                            runtime_ports_chirho,
                            caller_key_chirho,
                            caller_operation_chirho,
                        ),
                        (Some(caller_key_chirho), None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_and_caller_key_chirho(
                            &self.root_chirho,
                            dag_chirho,
                            subject_chirho,
                            bytes_chirho,
                            context_chirho,
                            runtime_ports_chirho,
                            caller_key_chirho,
                        ),
                        (None, None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho(
                            &self.root_chirho,
                            dag_chirho,
                            subject_chirho,
                            bytes_chirho,
                            context_chirho,
                            runtime_ports_chirho,
                        ),
                        (None, Some(_caller_operation_chirho)) => unreachable!("validated above"),
                    }
                },
            ),
            None => {
                let projection_read_chirho = self.projection_read_chirho.as_deref();
                let plain_ports_chirho = || cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                    projection_read_chirho,
                    postgres_reversible_chirho: None,
                    llm_served_chirho: None,
                    private_attribution_chirho: declared_attribution_chirho,
                };
                match (caller_key_chirho, caller_operation_chirho) {
                    (Some(caller_key_chirho), Some(caller_operation_chirho)) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_and_caller_operation_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        subject_chirho,
                        bytes_chirho,
                        context_chirho,
                        cairn_chirho::effect_chirho::DagEffectRuntimePortsChirho {
                            projection_read_chirho,
                            postgres_reversible_chirho: None,
                            llm_served_chirho: None,
                            private_attribution_chirho: declared_attribution_chirho,
                        },
                        caller_key_chirho,
                        caller_operation_chirho,
                    ),
                    (Some(caller_key_chirho), None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_and_caller_key_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        subject_chirho,
                        bytes_chirho,
                        context_chirho,
                        plain_ports_chirho(),
                        caller_key_chirho,
                    ),
                    (None, None) => cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho(
                        &self.root_chirho,
                        dag_chirho,
                        subject_chirho,
                        bytes_chirho,
                        context_chirho,
                        plain_ports_chirho(),
                    ),
                    (None, Some(_caller_operation_chirho)) => unreachable!("validated above"),
                }
            }
        }
        .map(|report_chirho| report_chirho.payload_chirho)
    }

    pub(super) async fn run_dag_with_private_input_intent_for_served_request_chirho(
        &self,
        dag_chirho: HashChirho,
        private_input_chirho: ServedPrivateInputChirho,
        context_chirho: Option<RequestContextChirho>,
        caller_key_chirho: Option<CallerIdempotencyKeyChirho>,
        declared_attribution_chirho: Option<PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        self.run_dag_with_private_input_intent_for_served_request_optional_caller_operation_chirho(
            dag_chirho,
            private_input_chirho,
            context_chirho,
            caller_key_chirho,
            None,
            declared_attribution_chirho,
        )
        .await
    }

    pub(super) async fn run_dag_with_private_input_intent_for_served_caller_operation_chirho(
        &self,
        dag_chirho: HashChirho,
        private_input_chirho: ServedPrivateInputChirho,
        context_chirho: Option<RequestContextChirho>,
        caller_key_chirho: CallerIdempotencyKeyChirho,
        caller_operation_chirho: CallerOperationBindingChirho,
        declared_attribution_chirho: Option<PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        self.run_dag_with_private_input_intent_for_served_request_optional_caller_operation_chirho(
            dag_chirho,
            private_input_chirho,
            context_chirho,
            Some(caller_key_chirho),
            Some(caller_operation_chirho),
            declared_attribution_chirho,
        )
        .await
    }

    async fn run_dag_with_private_input_intent_for_served_request_optional_caller_operation_chirho(
        &self,
        dag_chirho: HashChirho,
        private_input_chirho: ServedPrivateInputChirho,
        context_chirho: Option<RequestContextChirho>,
        caller_key_chirho: Option<CallerIdempotencyKeyChirho>,
        caller_operation_chirho: Option<CallerOperationBindingChirho>,
        declared_attribution_chirho: Option<PrivateBlobAttributionChirho>,
    ) -> Result<Vec<u8>> {
        let runtime_chirho = self.clone();
        spawn_blocking_served_run_chirho(self.postgres_effect_chirho.is_some(), move || {
            runtime_chirho.run_dag_with_private_input_intent_optional_caller_key_chirho(
                &dag_chirho,
                &private_input_chirho,
                context_chirho.as_ref(),
                caller_key_chirho.as_ref(),
                caller_operation_chirho.as_ref(),
                declared_attribution_chirho.as_ref(),
            )
        })
        .await
    }

    pub(super) fn dag_has_write_store_chirho(&self, dag_hash_chirho: &HashChirho) -> Result<bool> {
        let dag_chirho: DagChirho =
            store_chirho::get_object_chirho(&self.root_chirho, dag_hash_chirho)?;
        for node_hash_chirho in dag_chirho.nodes_chirho {
            let node_chirho: NodeDefChirho =
                store_chirho::get_object_chirho(&self.root_chirho, &node_hash_chirho)?;
            if node_chirho
                .capabilities_chirho
                .iter()
                .any(|capability_chirho| {
                    matches!(capability_chirho, CapabilityChirho::WriteStoreChirho { .. })
                })
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The first elected SSR conversion admits only pure nodes and the two capabilities used by a
    /// bounded authenticated projection read. Every other capability remains on the named
    /// unconverted path, even when it appears on an HTTP GET surface.
    pub(super) fn dag_is_elected_ssr_read_only_chirho(
        &self,
        dag_hash_chirho: &HashChirho,
    ) -> Result<bool> {
        let dag_chirho: DagChirho =
            store_chirho::get_object_chirho(&self.root_chirho, dag_hash_chirho)?;
        for node_hash_chirho in dag_chirho.nodes_chirho {
            let node_chirho: NodeDefChirho =
                store_chirho::get_object_chirho(&self.root_chirho, &node_hash_chirho)?;
            if node_chirho
                .capabilities_chirho
                .iter()
                .any(|capability_chirho| {
                    !matches!(
                        capability_chirho,
                        CapabilityChirho::QueryChirho { .. }
                            | CapabilityChirho::UserIdentityChirho { .. }
                    )
                })
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
