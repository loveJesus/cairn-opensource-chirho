// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn app_html_inline_style_detector_catches_style_blocks_and_attrs_chirho() {
    assert!(app_http_chirho::app_html_payload_has_inline_style_chirho(
        b"<STYLE>.x{color:red}</STYLE>"
    ));
    assert!(app_http_chirho::app_html_payload_has_inline_style_chirho(
        b"<div STYLE=\"color:red\">x</div>"
    ));
    assert!(!app_http_chirho::app_html_payload_has_inline_style_chirho(
        b"<link rel=\"stylesheet\" href=\"/app-assets-chirho/app/style.css\">"
    ));
}

#[test]
fn index_routes_are_chirho_suffixed_chirho() {
    let html_chirho = public_routes_chirho::index_html_chirho();

    assert!(html_chirho.contains("/healthz-chirho"));
    assert!(!html_chirho.contains("href=\"/healthz\""));
    assert!(!html_chirho.contains("/owner-console-chirho/"));
}

#[test]
fn registered_routes_are_chirho_suffixed_chirho() {
    let source_chirho = include_str!("../runtime_lifecycle_chirho/startup_chirho.rs");
    let routes_chirho: Vec<&str> = source_chirho
        .match_indices(".route(\"")
        .filter_map(|(start_chirho, _)| {
            let route_start_chirho = start_chirho + ".route(\"".len();
            let rest_chirho = &source_chirho[route_start_chirho..];
            let route_end_chirho = rest_chirho.find('"')?;
            Some(&rest_chirho[..route_end_chirho])
        })
        .collect();

    assert!(!routes_chirho.is_empty());
    for route_chirho in routes_chirho {
        assert!(
            route_is_chirho_suffixed_chirho(route_chirho),
            "route is missing Chirho suffixing: {route_chirho}"
        );
    }
}

/// Serve startup recovers unfinished run intents: the startup road calls the posture's recovery, and the posture's
/// recovery calls the engine's. Corrected 2026-10-09 (K4 Part 3): the needle used to be the `.as_deref()` call that only
/// a test-only router helper still made, so it passed on test code after production's call changed shape. That helper
/// now lives in `runtime_state_helpers_tests_chirho.rs`, and both needles name production's calls.
#[test]
fn serve_startup_calls_run_intent_recovery_chirho() {
    let serve_source_chirho = include_str!("../runtime_lifecycle_chirho/startup_chirho.rs");
    let compact_source_chirho = serve_source_chirho.split_whitespace().collect::<String>();
    assert!(compact_source_chirho.contains(
        "resume_projection_run_intents_for_startup_posture_chirho(root_chirho,projection_read_chirho.as_deref(),startup_posture_chirho,)?"
    ));
    assert!(compact_source_chirho.contains(
        "resume_unfinished_run_intents_with_projection_read_chirho(root_chirho,projection_read_chirho,)?"
    ));
}

fn route_is_chirho_suffixed_chirho(route_chirho: &str) -> bool {
    if matches!(route_chirho, "/" | "/healthz") {
        return true;
    }

    route_chirho
        .split('/')
        .filter(|segment_chirho| !segment_chirho.is_empty())
        .all(|segment_chirho| {
            if let Some(param_chirho) = segment_chirho.strip_prefix(':') {
                param_chirho.ends_with("_chirho")
            } else {
                segment_chirho.contains("-chirho")
            }
        })
}

#[test]
fn bearer_token_parses_only_nonempty_bearer_chirho() {
    let mut headers_chirho = HeaderMap::new();
    assert_eq!(bearer_token_chirho(&headers_chirho), None);

    headers_chirho.insert(AUTHORIZATION, "bearer wallet-token".parse().unwrap());
    assert_eq!(bearer_token_chirho(&headers_chirho), Some("wallet-token"));

    headers_chirho.insert(AUTHORIZATION, "Basic wallet-token".parse().unwrap());
    assert_eq!(bearer_token_chirho(&headers_chirho), None);

    headers_chirho.insert(AUTHORIZATION, "Bearer    ".parse().unwrap());
    assert_eq!(bearer_token_chirho(&headers_chirho), None);
}

#[test]
fn named_no_body_route_rejects_before_body_read_or_admission_chirho() {
    let root_chirho = temp_root_chirho("no-body-direct");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "bodygate",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        "bodygate",
        "status",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho,
    );
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);
    let oversized_body_chirho = Bytes::from(vec![b'x'; 2 * 1024 * 1024 + 1]);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let response_chirho = runtime_chirho.block_on(app_route_post_chirho(
        State(state_chirho),
        None,
        HeaderMap::new(),
        AxPath(("bodygate".to_string(), "status".to_string())),
        oversized_body_chirho,
    ));

    assert_eq!(response_chirho.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(runtime_tree_snapshot_chirho(&root_chirho), before_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn final_named_route_policy_recheck_closes_preflight_ref_change_chirho() {
    let root_chirho = temp_root_chirho("no-body-final-recheck");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "bodyrace",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        "bodyrace",
        "status",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::AcceptBodyChirho,
    );
    let state_chirho = app_state_for_root_chirho(&root_chirho);
    assert!(state_chirho
        .runtime_chirho
        .direct_app_route_accepts_request_body_chirho("bodyrace", "status")
        .unwrap());
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "bodyrace",
        Some("status"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
    let accepted_chirho = app_http_chirho::run_app_http_with_method_chirho(
        &state_chirho,
        None,
        &HeaderMap::new(),
        "bodyrace",
        Some("status"),
        axum::http::Method::POST,
        b"accepted".to_vec(),
    );
    assert_eq!(accepted_chirho.status(), StatusCode::OK);

    deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
        &root_chirho,
        "bodyrace",
        "status",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
        cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho::NoBodyChirho,
    );
    let before_chirho = runtime_tree_snapshot_chirho(&root_chirho);
    let response_chirho = app_http_chirho::run_app_http_with_method_chirho(
        &state_chirho,
        None,
        &HeaderMap::new(),
        "bodyrace",
        Some("status"),
        axum::http::Method::POST,
        b"must not reach the DAG".to_vec(),
    );

    assert_eq!(response_chirho.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(runtime_tree_snapshot_chirho(&root_chirho), before_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}
