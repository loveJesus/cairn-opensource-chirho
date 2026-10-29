// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::app_http_chirho::APP_ROUTE_HTML_CSP_CHIRHO;
use super::app_review_web_chirho::{
    app_review_promote_post_chirho, app_review_rollback_post_chirho, AppReviewPromoteRequestChirho,
    AppReviewRollbackRequestChirho,
};
use super::app_state_web_chirho::{
    app_state_reveal_html_chirho, contact_store_key_chirho, rollback_app_state_view_chirho,
    AppStateRevealRequestChirho, AppStateRollbackRequestChirho,
};
use super::*;
use axum::body::Bytes;
use axum::extract::{Path as AxPath, State};
use axum::Form;
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_chirho::model_chirho::{CapabilityChirho, DagChirho, NodeDefChirho};
use cairn_chirho::{
    app_build_request_chirho, app_source_manifest_chirho, cas_chirho, dag_chirho,
    domain_binding_chirho, effect_pricing_chirho, privacy_chirho, query_chirho, refs_chirho,
    resource_chirho, review_chirho, store_chirho, versioned_chirho,
};

#[path = "tests_chirho/helpers_chirho/runtime_fixture_helpers_tests_chirho.rs"]
mod runtime_fixture_helpers_chirho;
use runtime_fixture_helpers_chirho::*;
#[path = "tests_chirho/helpers_chirho/review_fixture_helpers_tests_chirho.rs"]
mod review_fixture_helpers_chirho;
use review_fixture_helpers_chirho::*;

async fn assert_fixed_app_execution_http_refusal_chirho(
    response_chirho: axum::response::Response,
    detail_needle_chirho: &str,
) -> Vec<u8> {
    let status_chirho = response_chirho.status();
    let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
        .await
        .unwrap();
    let text_chirho = String::from_utf8_lossy(&body_chirho);
    assert_eq!(status_chirho, StatusCode::BAD_REQUEST, "{text_chirho}");
    assert!(
        crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
            &text_chirho
        )
        .is_some(),
        "the body is exactly one fixed execution refusal: {text_chirho}"
    );
    assert!(!text_chirho.contains("legacy money road"), "{text_chirho}");
    assert!(!text_chirho.contains(detail_needle_chirho), "{text_chirho}");
    body_chirho.to_vec()
}

#[path = "tests_chirho/helpers_chirho/http_smoke_helpers_tests_chirho.rs"]
mod http_smoke_helpers_chirho;
use http_smoke_helpers_chirho::*;

#[path = "tests_chirho/helpers_chirho/control_plane_helpers_tests_chirho.rs"]
mod control_plane_helpers_chirho;
use control_plane_helpers_chirho::*;

#[path = "tests_chirho/helpers_chirho/privacy_assert_helpers_tests_chirho.rs"]
mod privacy_assert_helpers_chirho;
use privacy_assert_helpers_chirho::*;

#[path = "tests_chirho/public_runtime_tests_chirho.rs"]
mod public_runtime_tests_chirho;

#[path = "tests_chirho/app_route_tests_chirho.rs"]
mod app_route_tests_chirho;
#[path = "tests_chirho/auth_blocking_tests_chirho.rs"]
mod auth_blocking_tests_chirho;

#[path = "tests_chirho/request_access_chirho/request_access_policy_tests_chirho.rs"]
mod request_access_policy_tests_chirho;
#[path = "tests_chirho/request_access_chirho/unexaminable_key_log_tests_chirho.rs"]
mod unexaminable_key_log_tests_chirho;
#[path = "tests_chirho/request_access_chirho/unexaminable_log_tests_chirho.rs"]
mod unexaminable_log_tests_chirho;
#[path = "tests_chirho/request_access_chirho/unexaminable_memory_tests_chirho.rs"]
mod unexaminable_memory_tests_chirho;

#[path = "tests_chirho/runtime_transport_tests_chirho.rs"]
mod runtime_transport_tests_chirho;

#[path = "tests_chirho/projection_read_runtime_tests_chirho.rs"]
mod projection_read_runtime_tests_chirho;

#[path = "tests_chirho/ledger_host_runtime_tests_chirho.rs"]
mod ledger_host_runtime_tests_chirho;

#[path = "tests_chirho/realtime_ws_tests_chirho.rs"]
mod realtime_ws_tests_chirho;

#[path = "tests_chirho/growth_arms_chirho/anonymous_html_view_growth_tests_chirho.rs"]
mod anonymous_html_view_growth_tests_chirho;
#[path = "tests_chirho/request_access_chirho/answer_cache_http_tests_chirho.rs"]
mod answer_cache_http_tests_chirho;
#[path = "tests_chirho/request_access_chirho/answer_cache_refusal_http_tests_chirho.rs"]
mod answer_cache_refusal_http_tests_chirho;
#[path = "tests_chirho/growth_arms_chirho/app_route_concurrency_tests_chirho.rs"]
mod app_route_concurrency_tests_chirho;
#[path = "tests_chirho/growth_arms_chirho/app_route_fixture_chirho.rs"]
mod app_route_fixture_chirho;
#[path = "tests_chirho/growth_arms_chirho/app_route_growth_tests_chirho.rs"]
mod app_route_growth_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_disconnect_http_tests_chirho.rs"]
mod connection_disconnect_http_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_new_http_tests_chirho.rs"]
mod connection_new_http_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_new_limits_http_tests_chirho.rs"]
mod connection_new_limits_http_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_new_output_tests_chirho.rs"]
mod connection_new_output_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_new_rollback_tests_chirho.rs"]
mod connection_new_rollback_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_new_selection_http_tests_chirho.rs"]
mod connection_new_selection_http_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_real_rollback_tests_chirho.rs"]
mod connection_real_rollback_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_rollback_tests_chirho.rs"]
mod connection_rollback_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/connection_sign_in_http_tests_chirho.rs"]
mod connection_sign_in_http_tests_chirho;
#[path = "tests_chirho/growth_arms_chirho/late_replay_tests_chirho.rs"]
mod late_replay_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/limited_key_fixture_chirho.rs"]
mod limited_key_fixture_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/limited_key_http_tests_chirho.rs"]
mod limited_key_http_tests_chirho;
#[path = "tests_chirho/request_access_chirho/limited_keys_chirho/limited_key_rollback_tests_chirho.rs"]
mod limited_key_rollback_tests_chirho;
#[path = "tests_chirho/request_access_chirho/own_keys_chirho/own_keys_fixture_chirho.rs"]
mod own_keys_fixture_chirho;
#[path = "tests_chirho/request_access_chirho/own_keys_chirho/own_keys_form_http_tests_chirho.rs"]
mod own_keys_form_http_tests_chirho;
#[path = "tests_chirho/request_access_chirho/own_keys_chirho/own_keys_page_http_tests_chirho.rs"]
mod own_keys_page_http_tests_chirho;
#[path = "tests_chirho/route_contract_tests_chirho.rs"]
mod route_contract_tests_chirho;
#[path = "tests_chirho/scoped_token_metering_tests_chirho.rs"]
mod scoped_token_metering_tests_chirho;

#[path = "tests_chirho/request_access_chirho/auth_wallet_tests_chirho.rs"]
mod auth_wallet_tests_chirho;

#[path = "tests_chirho/request_access_chirho/credential_change_tests_chirho.rs"]
mod credential_change_tests_chirho;

#[path = "tests_chirho/request_access_chirho/owner_keys_http_tests_chirho.rs"]
mod owner_keys_http_tests_chirho;

#[path = "tests_chirho/request_access_chirho/recover_http_tests_chirho.rs"]
mod recover_http_tests_chirho;

#[path = "tests_chirho/request_access_chirho/public_error_boundary_tests_chirho.rs"]
mod public_error_boundary_tests_chirho;
#[path = "tests_chirho/request_access_chirho/served_refusal_http_tests_chirho.rs"]
mod served_refusal_http_tests_chirho;

#[path = "tests_chirho/request_access_chirho/sign_in_velocity_http_tests_chirho.rs"]
mod sign_in_velocity_http_tests_chirho;

#[path = "tests_chirho/app_state_review_chirho/mod_tests_chirho.rs"]
mod app_state_review_tests_chirho;

#[path = "tests_chirho/app_review_fast_path_tests_chirho.rs"]
mod app_review_fast_path_tests_chirho;

#[path = "tests_chirho/publish_dashboard_tests_chirho.rs"]
mod publish_dashboard_tests_chirho;

#[path = "tests_chirho/resource_policy_chirho/resource_policy_authoring_tests_chirho.rs"]
mod resource_policy_authoring_tests_chirho;
#[path = "tests_chirho/resource_policy_chirho/resource_policy_gate_tests_chirho.rs"]
mod resource_policy_gate_tests_chirho;

#[path = "tests_chirho/billing_runtime_tests_chirho.rs"]
mod billing_runtime_tests_chirho;

#[path = "tests_chirho/contact_flow_chirho/source_manifest_tests_chirho.rs"]
mod source_manifest_tests_chirho;

#[path = "tests_chirho/contact_flow_chirho/app_route_write_query_tests_chirho.rs"]
mod app_route_write_query_tests_chirho;

#[path = "tests_chirho/contact_flow_chirho/contact_persistence_tests_chirho.rs"]
mod contact_persistence_tests_chirho;

#[path = "tests_chirho/contact_flow_chirho/app_build_request_tests_chirho.rs"]
mod app_build_request_tests_chirho;

#[path = "tests_chirho/publication_two_root_tests_chirho.rs"]
mod publication_two_root_tests_chirho;

#[path = "tests_chirho/request_access_chirho/served_offworker_tests_chirho.rs"]
mod served_offworker_tests_chirho;

#[path = "tests_chirho/request_access_chirho/served_offworker_edge_tests_chirho.rs"]
mod served_offworker_edge_tests_chirho;
