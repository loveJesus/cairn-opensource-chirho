// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! R13 Part 8 (PFE #26153, #26154): the served request gate's ONE refusal. Every 429 from the gate carries ONE
//! Retry-After, the rolling window's whole seconds rounded up, and one generic body. The body is JSON when the route
//! declares a JSON response, or when the request's Accept names `application/json`, and always on the invoke
//! transport; otherwise it is plain text. The same request answers the same bytes whichever limit fired, so nothing in
//! the answer says which.

use super::sign_in_velocity_http_tests_chirho::with_limited_server_chirho;
use super::*;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path as AxPath, State};

const JSON_BODY_CHIRHO: &str =
    r#"{"ok_chirho":false,"error_chirho":"served-request-unavailable-chirho"}"#;
const TEXT_BODY_CHIRHO: &[u8] = b"served request unavailable\n";
const ZERO_DAG_CHIRHO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One route's case: its name, method, path, Accept and body, and whether its refusal must be JSON.
type RefusalCaseChirho<'a> = (&'a str, &'a str, &'a str, Option<&'a str>, &'a [u8], bool);

/// One request per source is admitted, and its second is refused by the per-source limit.
fn refusal_limits_chirho(window_ms_chirho: u64) -> ServedRequestAbuseLimitsChirho {
    ServedRequestAbuseLimitsChirho {
        window_ms_chirho,
        actor_max_requests_chirho: 1,
        ..ServedRequestAbuseLimitsChirho::default()
    }
}

/// Two upcase apps: `refusal-page` declares no response type, and `refusal-json` declares `application/json`.
fn deploy_refusal_apps_chirho(root_chirho: &std::path::Path) {
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    for app_chirho in ["refusal-page", "refusal-json"] {
        deploy_transform_app_for_owner_chirho(
            root_chirho,
            app_chirho,
            &owner_chirho,
            include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
            "upcase_chirho",
        );
        set_plain_app_input_policy_for_test_chirho(root_chirho, app_chirho, &owner_chirho);
    }
    cairn_chirho::app_chirho::set_app_response_policy_chirho(
        root_chirho,
        "refusal-json",
        &owner_chirho,
        "application/json",
    )
    .unwrap();
}

fn request_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    source_chirho: &str,
    accept_chirho: Option<&str>,
    body_chirho: &[u8],
) -> HttpSmokeResponseChirho {
    let mut headers_chirho = vec![
        ("x-forwarded-for", source_chirho),
        ("content-type", "application/json"),
    ];
    if let Some(accept_chirho) = accept_chirho {
        headers_chirho.push(("accept", accept_chirho));
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        method_chirho,
        path_chirho,
        &headers_chirho,
        body_chirho,
    )
}

/// A gate refusal: 429, the one Retry-After, and the one body, JSON or plain text.
fn assert_refusal_chirho(
    response_chirho: &HttpSmokeResponseChirho,
    json_chirho: bool,
    retry_after_chirho: &str,
    case_chirho: &str,
) {
    assert_eq!(response_chirho.status_chirho, 429, "{case_chirho}");
    assert_eq!(
        response_chirho
            .headers_chirho
            .get("retry-after")
            .map(String::as_str),
        Some(retry_after_chirho),
        "{case_chirho}: the one Retry-After"
    );
    let content_type_chirho = response_chirho
        .headers_chirho
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    if json_chirho {
        assert_eq!(content_type_chirho, "application/json", "{case_chirho}");
        assert_eq!(
            response_chirho.body_chirho,
            JSON_BODY_CHIRHO.as_bytes(),
            "{case_chirho}"
        );
        let parsed_chirho: serde_json::Value =
            serde_json::from_slice(&response_chirho.body_chirho).unwrap();
        assert_eq!(
            parsed_chirho["error_chirho"],
            "served-request-unavailable-chirho"
        );
    } else {
        assert!(
            content_type_chirho.starts_with("text/plain"),
            "{case_chirho}: {content_type_chirho}"
        );
        assert_eq!(
            response_chirho.body_chirho, TEXT_BODY_CHIRHO,
            "{case_chirho}"
        );
    }
}

/// Every route that reaches the gate, each from its own source: the first request is admitted, the second refused. The
/// declared-type branch is the JSON app asked with `*/*`; the invoke transport answers JSON even to a page's Accept.
#[test]
fn every_gate_refusal_carries_one_retry_after_and_speaks_json_only_when_asked_or_declared_chirho() {
    with_limited_server_chirho(
        "served-refusal-format",
        refusal_limits_chirho(60_000),
        |root_chirho, addr_chirho| {
            deploy_refusal_apps_chirho(root_chirho);
            let run_path_chirho = format!("/run-chirho/{ZERO_DAG_CHIRHO}");
            // Preview reaches the gate since served-overload (ii): it executes WASM in this process, so it is bounded.
            let preview_path_chirho = format!("/preview-chirho/{ZERO_DAG_CHIRHO}");
            let invoke_body_chirho = br#"{"target_chirho":"refusal-page","payload_chirho":"x"}"#;
            let cases_chirho: [RefusalCaseChirho; 12] = [
                (
                    "app page, JSON asked",
                    "POST",
                    "/app-chirho/refusal-page",
                    Some("application/json"),
                    b"x",
                    true,
                ),
                (
                    "app page, page asked",
                    "POST",
                    "/app-chirho/refusal-page",
                    Some("text/html"),
                    b"x",
                    false,
                ),
                (
                    "app page, nothing asked",
                    "POST",
                    "/app-chirho/refusal-page",
                    None,
                    b"x",
                    false,
                ),
                (
                    "JSON app, anything asked",
                    "POST",
                    "/app-chirho/refusal-json",
                    Some("*/*"),
                    b"x",
                    true,
                ),
                (
                    "JSON app, page asked",
                    "POST",
                    "/app-chirho/refusal-json",
                    Some("text/html"),
                    b"x",
                    true,
                ),
                (
                    "public run, JSON asked",
                    "POST",
                    &run_path_chirho,
                    Some("application/json"),
                    b"x",
                    true,
                ),
                (
                    "public run, nothing asked",
                    "POST",
                    &run_path_chirho,
                    None,
                    b"x",
                    false,
                ),
                (
                    "preview, JSON asked",
                    "POST",
                    &preview_path_chirho,
                    Some("application/json"),
                    b"x",
                    true,
                ),
                (
                    "preview, nothing asked",
                    "POST",
                    &preview_path_chirho,
                    None,
                    b"x",
                    false,
                ),
                (
                    "rendered page, JSON asked",
                    "GET",
                    "/ssr-chirho/refusal-page",
                    Some("application/json"),
                    b"",
                    true,
                ),
                (
                    "rendered page, page asked",
                    "GET",
                    "/ssr-chirho/refusal-page",
                    Some("text/html"),
                    b"",
                    false,
                ),
                (
                    "invoke, page asked",
                    "POST",
                    "/invoke-chirho",
                    Some("text/html"),
                    invoke_body_chirho,
                    true,
                ),
            ];
            for (
                index_chirho,
                (case_chirho, method_chirho, path_chirho, accept_chirho, body_chirho, json_chirho),
            ) in cases_chirho.iter().enumerate()
            {
                let source_chirho = format!("198.51.100.{}", index_chirho + 1);
                let first_chirho = request_chirho(
                    addr_chirho,
                    method_chirho,
                    path_chirho,
                    &source_chirho,
                    *accept_chirho,
                    body_chirho,
                );
                assert_ne!(
                    first_chirho.status_chirho, 429,
                    "{case_chirho}: the first request is admitted"
                );
                let refused_chirho = request_chirho(
                    addr_chirho,
                    method_chirho,
                    path_chirho,
                    &source_chirho,
                    *accept_chirho,
                    body_chirho,
                );
                assert_refusal_chirho(&refused_chirho, *json_chirho, "60", case_chirho);
            }
        },
    );
}

/// A window that is not a whole number of seconds rounds UP: 1.5 seconds answers Retry-After 2.
#[test]
fn a_refusal_retry_after_is_the_configured_window_rounded_up_chirho() {
    with_limited_server_chirho(
        "served-refusal-window",
        refusal_limits_chirho(1_500),
        |root_chirho, addr_chirho| {
            deploy_refusal_apps_chirho(root_chirho);
            let path_chirho = "/app-chirho/refusal-page";
            let source_chirho = "198.51.100.77";
            let first_chirho =
                request_chirho(addr_chirho, "POST", path_chirho, source_chirho, None, b"x");
            assert_ne!(first_chirho.status_chirho, 429);
            let refused_chirho =
                request_chirho(addr_chirho, "POST", path_chirho, source_chirho, None, b"x");
            assert_refusal_chirho(&refused_chirho, false, "2", "a 1.5 s window");
        },
    );
}

/// The gate's Retry-After itself, at several windows.
#[test]
fn the_gate_retry_after_is_the_rolling_window_in_whole_seconds_rounded_up_chirho() {
    for (window_ms_chirho, want_chirho) in
        [(1, 1), (1_000, 1), (1_001, 2), (1_500, 2), (60_000, 60)]
    {
        let gate_chirho =
            ServedRequestAbuseGateChirho::new_chirho(ServedRequestAbuseLimitsChirho {
                window_ms_chirho,
                ..ServedRequestAbuseLimitsChirho::default()
            })
            .unwrap();
        assert_eq!(
            gate_chirho.retry_after_secs_chirho(),
            want_chirho,
            "window {window_ms_chirho} ms"
        );
    }
}

/// The SAME request answers the SAME bytes whichever limit fired: the per-source limit, the global limit, and the
/// in-flight cap. Each fixture leaves only its own reason possible:
/// - the per-source refusal comes while the global count is 1 of 2;
/// - the global refusal comes on a third source's FIRST request, after two admissions fill the count;
/// - the in-flight refusal comes on a fresh gate with no permit at all.
#[test]
fn a_refusal_is_the_same_bytes_whichever_limit_fired_chirho() {
    let root_chirho = temp_root_chirho("served-refusal-same-bytes");
    deploy_refusal_apps_chirho(&root_chirho);
    let mut state_chirho = app_state_for_root_chirho(&root_chirho);
    state_chirho.served_request_abuse_gate_chirho = Arc::new(
        ServedRequestAbuseGateChirho::new_chirho(ServedRequestAbuseLimitsChirho {
            window_ms_chirho: 60_000,
            actor_max_requests_chirho: 1,
            global_max_requests_chirho: 2,
            ..ServedRequestAbuseLimitsChirho::default()
        })
        .unwrap(),
    );
    let mut no_permit_chirho = state_chirho.clone();
    no_permit_chirho.served_request_abuse_gate_chirho =
        Arc::new(ServedRequestAbuseGateChirho::new_chirho(refusal_limits_chirho(60_000)).unwrap());
    no_permit_chirho.inflight_chirho = Arc::new(tokio::sync::Semaphore::new(0));
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let post_chirho = |state_chirho: AppStateChirho, last_octet_chirho: u8| {
            let mut headers_chirho = HeaderMap::new();
            headers_chirho.insert(ACCEPT, HeaderValue::from_static("application/json"));
            app_post_chirho(
                State(state_chirho),
                Some(ConnectInfo(std::net::SocketAddr::from((
                    [203, 0, 113, last_octet_chirho],
                    40_000,
                )))),
                headers_chirho,
                AxPath("refusal-page".to_string()),
                Bytes::from_static(b"x"),
            )
        };
        assert_eq!(
            post_chirho(state_chirho.clone(), 1).await.status(),
            StatusCode::OK
        );
        let per_source_chirho = post_chirho(state_chirho.clone(), 1).await;
        assert_eq!(
            post_chirho(state_chirho.clone(), 2).await.status(),
            StatusCode::OK,
            "the global count was not full at the per-source refusal"
        );
        let global_chirho = post_chirho(state_chirho.clone(), 3).await;
        let in_flight_chirho = post_chirho(no_permit_chirho, 4).await;
        let mut seen_chirho = Vec::new();
        for (reason_chirho, response_chirho) in [
            ("per source", per_source_chirho),
            ("global", global_chirho),
            ("in flight", in_flight_chirho),
        ] {
            assert_eq!(
                response_chirho.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "{reason_chirho}"
            );
            let mut headers_chirho: Vec<(String, Vec<u8>)> = response_chirho
                .headers()
                .iter()
                .map(|(name_chirho, value_chirho)| {
                    (name_chirho.to_string(), value_chirho.as_bytes().to_vec())
                })
                .collect();
            headers_chirho.sort();
            let body_chirho = axum::body::to_bytes(response_chirho.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(
                &body_chirho[..],
                JSON_BODY_CHIRHO.as_bytes(),
                "{reason_chirho}"
            );
            seen_chirho.push((reason_chirho, headers_chirho, body_chirho.to_vec()));
        }
        for (reason_chirho, headers_chirho, body_chirho) in &seen_chirho[1..] {
            assert_eq!(
                (headers_chirho, body_chirho),
                (&seen_chirho[0].1, &seen_chirho[0].2),
                "the {reason_chirho} refusal differs from the per-source one"
            );
        }
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Accept names JSON only as a media range of its own with a nonzero q. A wildcard is not a request for JSON; the
/// route's declared type covers that case.
#[test]
fn accept_names_json_only_as_its_own_media_range_with_a_nonzero_q_chirho() {
    let headers_chirho = |values_chirho: &[&str]| {
        let mut headers_chirho = HeaderMap::new();
        for value_chirho in values_chirho {
            headers_chirho.append(ACCEPT, HeaderValue::from_str(value_chirho).unwrap());
        }
        headers_chirho
    };
    for (values_chirho, want_chirho) in [
        (vec!["application/json"], true),
        (vec!["text/html, application/json;q=0.9"], true),
        (vec!["Application/JSON"], true),
        (vec!["text/html", "application/json"], true),
        (vec!["application/json;q=0"], false),
        (vec!["application/json ; q = 0.0"], false),
        (vec!["*/*"], false),
        (vec!["application/*"], false),
        (vec!["application/json-patch+json"], false),
        (vec![], false),
    ] {
        assert_eq!(
            accept_names_json_chirho(&headers_chirho(&values_chirho)),
            want_chirho,
            "{values_chirho:?}"
        );
    }
    assert!(media_type_is_json_chirho("application/json; charset=utf-8"));
    assert!(!media_type_is_json_chirho("text/html; charset=utf-8"));
}
