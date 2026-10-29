// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K2's refusal witnesses (PFE #26656): through the real router on a real port, the framework's and the engine's own
//! refusals each leave with their status and exactly `private, no-store`, and the layer keeps what each must carry: the
//! served gate's Retry-After and body, and an execution refusal's knowledge, attempt and scope.
//! Workflow: connected tools K2,
//! `spec-chirho/workflows-chirho/served-request-admission-chirho/answer-cache-finalization-chirho.md`.

use super::sign_in_velocity_http_tests_chirho::with_limited_server_chirho;
use super::*;

const PRIVATE_CHIRHO: &str = "private, no-store";
const PAGE_APP_CHIRHO: &str = "k2-refusal-page";
const TRAP_APP_CHIRHO: &str = "k2-refusal-trap";
/// The served gate's window, so its Retry-After is known: whole seconds, rounded up.
const WINDOW_MS_CHIRHO: u64 = 60_000;

/// A guest whose run traps: the engine refuses the run after trying it.
const TRAP_WAT_CHIRHO: &str = r#"(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))
  (func (export "alloc_chirho") (param $len i32) (result i32)
    (local $p i32)
    global.get $heap_chirho
    local.set $p
    global.get $heap_chirho
    local.get $len
    i32.add
    global.set $heap_chirho
    local.get $p)
  (func (export "trap_chirho") (param $ptr i32) (param $len i32) (result i64)
    unreachable))
"#;

/// A plain upcase app, and an app whose guest traps.
fn deploy_refusal_witness_apps_chirho(root_chirho: &std::path::Path) {
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        root_chirho,
        PAGE_APP_CHIRHO,
        &owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(root_chirho, PAGE_APP_CHIRHO, &owner_chirho);
    deploy_transform_app_for_owner_chirho(
        root_chirho,
        TRAP_APP_CHIRHO,
        &owner_chirho,
        TRAP_WAT_CHIRHO,
        "trap_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(root_chirho, TRAP_APP_CHIRHO, &owner_chirho);
}

/// One request from its own source, so only the limit a witness means to reach can fire.
fn from_source_chirho(
    addr_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    source_chirho: &str,
    content_type_chirho: &str,
    body_chirho: &[u8],
) -> HttpSmokeResponseChirho {
    http_request_for_smoke_chirho(
        addr_chirho,
        method_chirho,
        path_chirho,
        &[
            ("x-forwarded-for", source_chirho),
            ("content-type", content_type_chirho),
        ],
        body_chirho,
    )
}

fn assert_private_chirho(
    response_chirho: &HttpSmokeResponseChirho,
    status_chirho: u16,
    what_chirho: &str,
) {
    assert_eq!(
        response_chirho.status_chirho,
        status_chirho,
        "{what_chirho}: {}",
        http_body_text_chirho(response_chirho)
    );
    assert_eq!(
        response_chirho
            .headers_chirho
            .get("cache-control")
            .map(String::as_str),
        Some(PRIVATE_CHIRHO),
        "{what_chirho} must leave private, no-store"
    );
}

/// THE REFUSAL WITNESSES. On a served root whose gate admits one request per source in a 60-second window:
/// - the token road's typed JSON extractor refuses an unreadable body: 400, private;
/// - the app road refuses a body over its limit: 413, private;
/// - the gate refuses a source's second request: 429, private, with its one Retry-After ("60") and its one body intact;
/// - a guest that traps is an execution refusal: 400, private, its body still one of the fixed bodies, with its
///   knowledge, attempt and scope lines intact.
///
/// Each runs beside its control, a request the same road answers (a readable token body, a small app body, the
/// source's first request, the plain app's run), so each refusal is the road's own and not the fixture's.
///
/// MIGRATION PATH: a refusal without `private, no-store` means the layer missed that exit; a 429 without Retry-After or
/// with another body, or an execution refusal whose lines changed, means the layer rewrote more than Cache-Control.
#[test]
fn every_refusal_exit_leaves_private_and_keeps_what_it_carries_chirho() {
    with_limited_server_chirho(
        "k2-refusal-witnesses",
        ServedRequestAbuseLimitsChirho {
            window_ms_chirho: WINDOW_MS_CHIRHO,
            actor_max_requests_chirho: 1,
            ..ServedRequestAbuseLimitsChirho::default()
        },
        |root_chirho, addr_chirho| {
            deploy_refusal_witness_apps_chirho(root_chirho);
            let page_chirho = format!("/app-chirho/{PAGE_APP_CHIRHO}");
            let trap_chirho = format!("/app-chirho/{TRAP_APP_CHIRHO}");

            // The framework's extractor: an unreadable JSON body to the token road.
            let extractor_chirho = from_source_chirho(
                addr_chirho,
                "POST",
                "/auth-chirho/token-chirho",
                "198.51.100.1",
                "application/json",
                b"this is not json",
            );
            assert_private_chirho(&extractor_chirho, 400, "an extractor refusal");

            // The body limit, beside its control.
            let control_chirho = from_source_chirho(
                addr_chirho,
                "POST",
                &page_chirho,
                "198.51.100.2",
                "text/plain",
                b"small",
            );
            assert_private_chirho(&control_chirho, 200, "the body limit's control");
            let oversized_chirho = vec![b'x'; 2 * 1024 * 1024 + 1];
            let too_large_chirho = from_source_chirho(
                addr_chirho,
                "POST",
                &page_chirho,
                "198.51.100.3",
                "text/plain",
                &oversized_chirho,
            );
            assert_private_chirho(&too_large_chirho, 413, "a body over the limit");

            // The served gate: one source's first request is answered, its second refused.
            let first_chirho = from_source_chirho(
                addr_chirho,
                "POST",
                &page_chirho,
                "198.51.100.4",
                "text/plain",
                b"first",
            );
            assert_private_chirho(&first_chirho, 200, "the gate's control");
            let gated_chirho = from_source_chirho(
                addr_chirho,
                "POST",
                &page_chirho,
                "198.51.100.4",
                "text/plain",
                b"second",
            );
            assert_private_chirho(&gated_chirho, 429, "the gate's refusal");
            assert_eq!(
                gated_chirho
                    .headers_chirho
                    .get("retry-after")
                    .map(String::as_str),
                Some("60"),
                "the gate's one Retry-After, kept"
            );
            assert_eq!(
                gated_chirho.body_chirho, b"served request unavailable\n",
                "the gate's one body, kept"
            );

            // A trusted execution refusal: the trapping guest's run.
            let refused_chirho = from_source_chirho(
                addr_chirho,
                "POST",
                &trap_chirho,
                "198.51.100.5",
                "text/plain",
                b"run",
            );
            assert_private_chirho(&refused_chirho, 400, "an execution refusal");
            let refused_text_chirho = http_body_text_chirho(&refused_chirho);
            assert!(
                crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(
                    &refused_text_chirho
                )
                .is_some(),
                "the execution refusal keeps one of its fixed bodies: {refused_text_chirho}"
            );
            for line_chirho in ["knowledge: ", "attempt: ", "scope: "] {
                assert!(
                    refused_text_chirho.contains(line_chirho),
                    "the execution refusal keeps its {line_chirho:?} line"
                );
            }
        },
    );
}
