// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Constructs the real router and owns HTTP startup and shutdown.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/transient-review-fixture-chirho/lifecycle-source-chirho.md`.

use super::*;

#[cfg(feature = "dev-transient-review-fixture-chirho")]
#[path = "fixture_chirho.rs"]
mod fixture_chirho;
#[cfg(feature = "dev-transient-review-fixture-chirho")]
pub use fixture_chirho::{
    prepare_transient_review_server_chirho, PreparedTransientReviewServerChirho,
};

struct PreparedHttpRuntimeChirho {
    state_chirho: AppStateChirho,
    relay_only_chirho: bool,
    announce_chirho: bool,
    monitor_chirho: Option<LedgerMonitorRuntimeChirho>,
}

async fn prepare_http_runtime_chirho(
    root_chirho: &std::path::Path,
    options_chirho: ServeOptionsChirho,
) -> Result<PreparedHttpRuntimeChirho> {
    let ServeOptionsChirho {
        inflight_limit_chirho,
        auth_tokens_chirho,
        announce_chirho,
        domain_routing_enabled_chirho,
        served_request_limits_chirho,
        projection_read_chirho,
        postgres_effect_chirho,
        llm_served_chirho,
        ledger_monitor_chirho,
        write_dispatch_chirho,
        local_read_authority_chirho,
        write_destination_slot_chirho,
        startup_posture_chirho,
    } = options_chirho;
    match postgres_effect_chirho.as_ref() {
        Some(postgres_effect_chirho) => {
            let _resume_report_chirho =
                resume_unfinished_run_intents_for_served_effect_runtime_chirho(
                    root_chirho.to_path_buf(),
                    projection_read_chirho.clone(),
                    postgres_effect_chirho.clone(),
                )
                .await?;
        }
        None => resume_projection_run_intents_for_startup_posture_chirho(
            root_chirho,
            projection_read_chirho.as_deref(),
            startup_posture_chirho,
        )?,
    }
    let state_chirho = app_state_for_runtime_root_with_effect_runtime_chirho(
        root_chirho,
        RuntimeAppStateOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho,
            domain_routing_enabled_chirho,
            served_request_limits_chirho,
            projection_read_chirho,
            postgres_effect_chirho,
            llm_served_chirho,
            write_dispatch_chirho,
            local_read_authority_chirho,
            write_destination_slot_chirho,
        },
    )?;
    Ok(PreparedHttpRuntimeChirho {
        state_chirho,
        relay_only_chirho: startup_posture_chirho
            == ConfiguredServeStartupPostureChirho::RelayOnlyFollowerChirho,
        announce_chirho,
        monitor_chirho: ledger_monitor_chirho,
    })
}

pub(super) async fn serve_with_options_until_chirho(
    root_chirho: &std::path::Path,
    port_chirho: u16,
    options_chirho: ServeOptionsChirho,
    stop_chirho: Option<Arc<AtomicBool>>,
) -> Result<()> {
    if stop_chirho
        .as_ref()
        .is_some_and(|stop_chirho| stop_chirho.load(Ordering::Acquire))
    {
        return Ok(());
    }
    let prepared_chirho = prepare_http_runtime_chirho(root_chirho, options_chirho).await?;
    let app_chirho = router_for_state_chirho(
        prepared_chirho.state_chirho,
        prepared_chirho.relay_only_chirho,
    )?;
    if stop_chirho
        .as_ref()
        .is_some_and(|stop_chirho| stop_chirho.load(Ordering::Acquire))
    {
        return Ok(());
    }
    auth_blocking_chirho::warm_sign_in_view_chirho(root_chirho).await;
    let addr_chirho = std::net::SocketAddr::from(([127, 0, 0, 1], port_chirho));
    let listener_chirho = tokio::net::TcpListener::bind(addr_chirho).await?;
    spawn_runtime_views_warm_up_chirho(root_chirho);
    let _monitor_task_chirho = prepared_chirho
        .monitor_chirho
        .map(LedgerMonitorRuntimeChirho::spawn_chirho);
    if prepared_chirho.announce_chirho {
        println!("cairn-chirho serving on http://{addr_chirho}");
    }
    let service_chirho: IntoMakeServiceWithConnectInfo<_, std::net::SocketAddr> =
        app_chirho.into_make_service_with_connect_info();
    let server_chirho = axum::serve(listener_chirho, service_chirho);
    match stop_chirho {
        Some(stop_chirho) => {
            server_chirho
                .with_graceful_shutdown(wait_for_serve_stop_chirho(stop_chirho))
                .await?;
        }
        None => server_chirho.await?,
    }
    Ok(())
}

fn spawn_runtime_views_warm_up_chirho(root_chirho: &std::path::Path) {
    cairn_chirho::privacy_chirho::spawn_private_blob_view_warm_up_chirho(root_chirho);
    cairn_chirho::dag_private_value_chirho::spawn_private_value_view_warm_up_chirho(root_chirho);
    cairn_chirho::effect_chirho::run_intent_chirho::spawn_run_intent_view_warm_up_chirho(
        root_chirho,
    );
    cairn_chirho::identity_chirho::spawn_session_views_warm_up_chirho(root_chirho);
    cairn_chirho::oauth_chirho::spawn_scoped_token_views_warm_up_chirho(root_chirho);
}

pub(super) fn resume_projection_run_intents_for_startup_posture_chirho(
    root_chirho: &std::path::Path,
    projection_read_chirho: Option<
        &dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho,
    >,
    startup_posture_chirho: ConfiguredServeStartupPostureChirho,
) -> Result<()> {
    if startup_posture_chirho
        == ConfiguredServeStartupPostureChirho::RecoverRunIntentsAndMonitorChirho
    {
        let _resume_report_chirho = cairn_chirho::effect_chirho::run_intent_chirho::resume_unfinished_run_intents_with_projection_read_chirho(
            root_chirho,
            projection_read_chirho,
        )?;
    }
    Ok(())
}

async fn wait_for_serve_stop_chirho(stop_chirho: Arc<AtomicBool>) {
    while !stop_chirho.load(Ordering::Acquire) {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
pub(super) fn runtime_router_for_root_with_effect_runtime_after_resume_chirho(
    root_chirho: &std::path::Path,
    options_chirho: RuntimeAppStateOptionsChirho,
    relay_only_follower_chirho: bool,
) -> Result<Router> {
    let state_chirho =
        app_state_for_runtime_root_with_effect_runtime_chirho(root_chirho, options_chirho)?;
    router_for_state_chirho(state_chirho, relay_only_follower_chirho)
}

fn router_for_state_chirho(
    state_chirho: AppStateChirho,
    relay_only_follower_chirho: bool,
) -> Result<Router> {
    debug_assert!(state_chirho.tenant_chirho.validate().is_ok());
    let app_chirho = Router::new()
        .route("/", get(index_chirho))
        .route("/healthz-chirho", get(healthz_chirho))
        .route("/healthz", get(healthz_chirho))
        .route(
            "/run-chirho/:dag_chirho",
            get(run_get_chirho).post(run_post_chirho),
        )
        .route(
            "/preview-chirho/:dag_chirho",
            get(preview_get_chirho).post(preview_post_chirho),
        )
        .route(
            "/app-chirho/:name_chirho",
            get(app_get_chirho).post(app_post_request_chirho),
        )
        .route(
            "/app-chirho/:name_chirho/",
            get(app_get_chirho).post(app_post_request_chirho),
        )
        .route(
            "/app-chirho/:name_chirho/:route_chirho",
            get(app_route_get_chirho).post(app_route_post_request_chirho),
        )
        .route(
            "/app-assets-chirho/:app_chirho/by-name-chirho/:name_chirho",
            get(app_asset_by_name_get_chirho),
        )
        .route(
            "/app-assets-chirho/:app_chirho/by-hash-chirho/:hash_chirho/:name_chirho",
            get(app_asset_by_hash_get_chirho),
        )
        .route(
            "/app-descriptor-chirho/:app_chirho",
            get(app_descriptor_get_chirho),
        )
        .route("/app-docs-chirho/:app_chirho", get(app_docs_get_chirho))
        .route("/app-mcp-chirho/:app_chirho", get(app_mcp_get_chirho))
        .route("/platform-mcp-chirho", get(platform_mcp_get_chirho))
        .route("/ssr-chirho/:name_chirho", get(ssr_get_chirho))
        .route("/invoke-chirho", post(invoke_chirho))
        .route("/host-chirho.js", get(host_js_chirho))
        .route(
            "/runtime-package-host-chirho.js",
            get(runtime_package_host_js_chirho),
        )
        .route("/wasm-demo-chirho", get(wasm_demo_chirho))
        .route("/client-demo-chirho", get(client_demo_chirho))
        .route("/htmx-lite-chirho.js", get(htmx_lite_js_chirho))
        .route("/contact-demo-chirho", get(contact_demo_chirho))
        .route(
            "/perffection-intake-demo-chirho",
            get(perffection_intake_demo_chirho),
        )
        .route(
            "/runtime-package-demo-chirho/:package_chirho",
            get(runtime_package_demo_chirho),
        )
        .route(
            "/runtime-package-chirho/:package_chirho/manifest-chirho",
            get(runtime_package_manifest_get_chirho),
        )
        .route(
            "/runtime-package-chirho/:package_chirho/executable-chirho",
            get(runtime_package_executable_get_chirho),
        )
        .route("/ws-chirho", get(ws_upgrade_chirho))
        .route(
            "/realtime-chirho/:session_chirho/ws-chirho",
            get(realtime_ws_upgrade_chirho),
        )
        .route("/dashboard-chirho", get(dashboard_chirho))
        .route(
            "/auth-chirho/register-chirho",
            get(auth_register_get_chirho).post(auth_register_post_chirho),
        )
        .route(
            "/auth-chirho/human-check-chirho",
            get(auth_human_check_get_chirho),
        )
        .route(
            "/auth-chirho/login-chirho",
            get(auth_login_get_chirho).post(auth_login_post_chirho),
        )
        .route("/auth-chirho/logout-chirho", get(auth_logout_get_chirho))
        .route(
            auth_credential_change_chirho::CREDENTIAL_CHANGE_ROUTE_CHIRHO,
            post(auth_credential_change_chirho::auth_credential_change_post_chirho),
        )
        .route(
            auth_keys_chirho::KEYS_ROUTE_CHIRHO,
            get(auth_keys_chirho::auth_keys_get_chirho),
        )
        .route(
            auth_keys_chirho::KEY_REVOKE_ROUTE_CHIRHO,
            post(auth_keys_chirho::auth_key_revoke_post_chirho),
        )
        .route(
            auth_recover_chirho::RECOVER_ROUTE_CHIRHO,
            post(auth_recover_chirho::auth_recover_post_chirho),
        )
        .merge(auth_connection_new_chirho::connection_new_routes_chirho())
        .route("/auth-chirho/token-chirho", post(auth_token_post_chirho))
        .route(
            "/auth-chirho/:kind_chirho/:id_chirho/session-revoke-chirho",
            post(auth_session_revoke_post_chirho),
        )
        .route(
            "/app-state-chirho/:kind_chirho/:id_chirho/:app_chirho",
            get(app_state_get_chirho),
        )
        .route(
            "/app-state-chirho/:kind_chirho/:id_chirho/:app_chirho/rollback-chirho",
            post(app_state_rollback_post_chirho),
        )
        .route(
            "/app-state-chirho/:kind_chirho/:id_chirho/:app_chirho/reveal-chirho",
            post(app_state_reveal_post_chirho),
        )
        .route(
            "/app-review-chirho/:kind_chirho/:id_chirho/:app_chirho/promote-chirho",
            post(app_review_promote_post_chirho),
        )
        .route(
            "/app-review-chirho/:kind_chirho/:id_chirho/:app_chirho/rollback-chirho",
            post(app_review_rollback_post_chirho),
        )
        .route(
            "/app-build-request-chirho/:kind_chirho/:id_chirho/:app_chirho",
            get(app_build_request_get_chirho),
        )
        .route(
            "/app-build-request-chirho/:kind_chirho/:id_chirho/:app_chirho/preview-chirho",
            post(app_build_request_preview_post_chirho),
        )
        .route(
            "/app-build-request-chirho/:kind_chirho/:id_chirho/:app_chirho/create-chirho",
            post(app_build_request_create_post_chirho),
        )
        .route(
            "/resource-policy-chirho/:kind_chirho/:id_chirho/:app_chirho",
            get(resource_policy_get_chirho),
        )
        .route(
            "/resource-policy-chirho/:kind_chirho/:id_chirho/:app_chirho/preview-chirho",
            post(resource_policy_preview_post_chirho),
        )
        .route(
            "/resource-policy-chirho/:kind_chirho/:id_chirho/:app_chirho/apply-chirho",
            post(resource_policy_apply_post_chirho),
        )
        .route("/publish-chirho", post(publish_post_chirho))
        .fallback(domain_binding_fallback_chirho)
        .with_state(state_chirho);
    let app_chirho = if relay_only_follower_chirho {
        app_chirho.layer(axum::middleware::from_fn(
            write_relay_chirho::relay_only_follower_route_guard_chirho,
        ))
    } else {
        app_chirho
    };
    // K2, outermost: every answer not marked public leaves private, no-store, the fallback's, the follower guard's and
    // the framework's own refusals included.
    Ok(app_chirho.layer(axum::middleware::map_response(
        answer_cache_chirho::finalize_answer_cache_chirho,
    )))
}
