// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The served runtime's test-only routers and states: the production composition with test-chosen tokens, limits and
//! projection read, for the arms that drive the router or a handler directly. Moved out of `serve_chirho.rs`
//! unchanged, so the production root module carries no test scaffolding.

use super::*;

pub(super) fn runtime_router_for_root_chirho(
    root_chirho: &std::path::Path,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
) -> Result<Router> {
    runtime_router_for_root_with_projection_read_chirho(
        root_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        registration_token_chirho,
        domain_routing_enabled_chirho,
        served_request_limits_chirho,
        None,
    )
}

pub(super) fn runtime_router_for_root_with_projection_read_chirho(
    root_chirho: &std::path::Path,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    registration_token_chirho: String,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
    projection_read_chirho: Option<
        Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>,
    >,
) -> Result<Router> {
    let _resume_report_chirho = cairn_chirho::effect_chirho::run_intent_chirho::resume_unfinished_run_intents_with_projection_read_chirho(
        root_chirho,
        projection_read_chirho.as_deref(),
    )?;
    runtime_router_for_root_with_effect_runtime_after_resume_chirho(
        root_chirho,
        RuntimeAppStateOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho: ServeAuthTokensChirho::new_chirho(
                publish_token_chirho,
                registration_token_chirho,
            ),
            domain_routing_enabled_chirho,
            served_request_limits_chirho,
            projection_read_chirho,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
        },
        false,
    )
}

pub(super) fn app_state_for_runtime_root_chirho(
    root_chirho: &std::path::Path,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
) -> Result<AppStateChirho> {
    app_state_for_runtime_root_with_projection_read_chirho(
        root_chirho,
        inflight_limit_chirho,
        publish_token_chirho,
        domain_routing_enabled_chirho,
        served_request_limits_chirho,
        None,
    )
}

fn app_state_for_runtime_root_with_projection_read_chirho(
    root_chirho: &std::path::Path,
    inflight_limit_chirho: usize,
    publish_token_chirho: String,
    domain_routing_enabled_chirho: bool,
    served_request_limits_chirho: ServedRequestAbuseLimitsChirho,
    projection_read_chirho: Option<
        Arc<dyn cairn_chirho::effect_chirho::projection_read_chirho::PublishedProjectionReadPortChirho>,
    >,
) -> Result<AppStateChirho> {
    app_state_for_runtime_root_with_effect_runtime_chirho(
        root_chirho,
        RuntimeAppStateOptionsChirho {
            inflight_limit_chirho,
            auth_tokens_chirho: ServeAuthTokensChirho::new_chirho(
                publish_token_chirho,
                String::new(),
            ),
            domain_routing_enabled_chirho,
            served_request_limits_chirho,
            projection_read_chirho,
            postgres_effect_chirho: None,
            llm_served_chirho: None,
            write_dispatch_chirho: None,
            local_read_authority_chirho: None,
            write_destination_slot_chirho: None,
        },
    )
}
