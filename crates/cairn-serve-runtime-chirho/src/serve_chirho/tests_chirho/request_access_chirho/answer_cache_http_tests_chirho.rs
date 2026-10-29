// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K2's direct-engine matrix: through the real router on a real port, every private answer leaves with exactly
//! `private, no-store` and every public-by-design answer keeps what its handler set. Every row asserts its expected
//! status first, so it means what it names. The private rows cover F5's shape on a signed-in app (the page, the root, the
//! save, a review POST, and the page by a limited key: PFE #26589), a signed-in app's JSON answer with its content type,
//! refusal, framework and fallback answers, SSR and invoke, the auth, token-bearing and owner routes, and a public app
//! read with a session, a valid bearer, a made-up bearer, by POST and through its redirect. The public rows are the
//! landing page, a static script, the platform and app descriptors, a demo page, and a public app's anonymous GET. The
//! asset answers are pinned by `tests/app_static_assets_chirho.rs` through the same router, and the framework's and
//! engine's own refusal exits by `answer_cache_refusal_http_tests_chirho.rs`.
//! Workflow: connected tools K2,
//! `spec-chirho/workflows-chirho/served-request-admission-chirho/answer-cache-finalization-chirho.md`.

use super::app_route_fixture_chirho::write_request_chirho;
use super::limited_key_fixture_chirho::*;
use super::*;

const PRIVATE_CHIRHO: &str = "private, no-store";
const PUBLIC_APP_CHIRHO: &str = "k2-public";
const PUBLIC_JSON_APP_CHIRHO: &str = "k2-public-json";
const PROTECTED_JSON_APP_CHIRHO: &str = "k2-protected-json";
const REVIEW_ROUTE_CHIRHO: &str = "review";

/// One row: what was sent, and the status and `Cache-Control` the engine answered.
struct AnswerChirho {
    label_chirho: String,
    status_chirho: u16,
    cache_chirho: Option<String>,
    content_type_chirho: Option<String>,
}

fn answer_chirho(
    addr_chirho: &str,
    label_chirho: &str,
    method_chirho: &str,
    path_chirho: &str,
    headers_chirho: &[(&str, &str)],
    body_chirho: &[u8],
) -> AnswerChirho {
    let response_chirho = http_request_for_smoke_chirho(
        addr_chirho,
        method_chirho,
        path_chirho,
        headers_chirho,
        body_chirho,
    );
    AnswerChirho {
        label_chirho: label_chirho.to_string(),
        status_chirho: response_chirho.status_chirho,
        cache_chirho: response_chirho.headers_chirho.get("cache-control").cloned(),
        content_type_chirho: response_chirho.headers_chirho.get("content-type").cloned(),
    }
}

fn header_value_chirho(headers_chirho: &HeaderMap, name_chirho: axum::http::HeaderName) -> String {
    headers_chirho
        .get(name_chirho)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// The keyed app (signed-in only, opened to limited keys) with a review route beside its save, two public upcase apps
/// (the plain one with a client), and a signed-in-only upcase app answering JSON.
fn matrix_tenant_chirho() -> (KeyedTenantChirho, String) {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k2-matrix", OpeningsChirho::PAGE_CHIRHO, 2);
    // A review POST: the save's module under its own route name, as a product's review step would be.
    tenant_chirho.deploy_chirho(OpeningsChirho::PAGE_CHIRHO, |manifest_chirho| {
        let mut review_chirho = route_entry_chirho(manifest_chirho, SAVE_ROUTE_CHIRHO).clone();
        review_chirho["route_chirho"] = serde_json::Value::from(REVIEW_ROUTE_CHIRHO);
        manifest_chirho["deploy_chirho"]["routes_chirho"]
            .as_array_mut()
            .unwrap()
            .push(review_chirho);
    });
    let protected_dag_chirho = deploy_transform_app_for_owner_chirho(
        &tenant_chirho.root_chirho,
        PROTECTED_JSON_APP_CHIRHO,
        &tenant_chirho.owner_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    set_plain_app_input_policy_for_test_chirho(
        &tenant_chirho.root_chirho,
        PROTECTED_JSON_APP_CHIRHO,
        &tenant_chirho.owner_chirho,
    );
    cairn_chirho::app_chirho::set_app_response_policy_chirho(
        &tenant_chirho.root_chirho,
        PROTECTED_JSON_APP_CHIRHO,
        &tenant_chirho.owner_chirho,
        "application/json",
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_request_access_policy_chirho(
        &tenant_chirho.root_chirho,
        PROTECTED_JSON_APP_CHIRHO,
        &tenant_chirho.owner_chirho,
        protected_dag_chirho,
        cairn_chirho::app_chirho::AppRequestAccessPolicyChirho::AuthenticatedChirho,
    )
    .unwrap();
    for app_chirho in [PUBLIC_APP_CHIRHO, PUBLIC_JSON_APP_CHIRHO] {
        deploy_transform_app_for_owner_chirho(
            &tenant_chirho.root_chirho,
            app_chirho,
            &tenant_chirho.owner_chirho,
            include_str!("../../../../../../examples-chirho/upcase-chirho.wat"),
            "upcase_chirho",
        );
        set_plain_app_input_policy_for_test_chirho(
            &tenant_chirho.root_chirho,
            app_chirho,
            &tenant_chirho.owner_chirho,
        );
    }
    cairn_chirho::app_chirho::set_app_response_policy_chirho(
        &tenant_chirho.root_chirho,
        PUBLIC_JSON_APP_CHIRHO,
        &tenant_chirho.owner_chirho,
        "application/json",
    )
    .unwrap();
    let public_client_chirho = oauth_chirho::register_client_chirho(
        &tenant_chirho.root_chirho,
        PUBLIC_APP_CHIRHO,
        &tenant_chirho.owner_chirho,
    )
    .unwrap()
    .client_id_chirho;
    (tenant_chirho, public_client_chirho)
}

#[test]
fn every_private_answer_leaves_private_no_store_and_public_answers_keep_their_own_chirho() {
    let (tenant_chirho, public_client_chirho) = matrix_tenant_chirho();
    let cookie_chirho = header_value_chirho(&tenant_chirho.cookie_chirho(0), COOKIE);
    let read_key_chirho = header_value_chirho(
        &tenant_chirho.limited_bearer_chirho(0, &[PAGE_READ_CHIRHO]),
        AUTHORIZATION,
    );
    let (principal_chirho, credential_chirho) = tenant_chirho.user_chirho(1);
    // A valid key on the public app, so its GET succeeds and the credential is the only reason it stays private.
    let public_key_chirho = format!(
        "Bearer {}",
        oauth_chirho::issue_scoped_token_with_rate_limit_chirho(
            &tenant_chirho.root_chirho,
            principal_chirho,
            credential_chirho,
            &public_client_chirho,
            Vec::new(),
            Some(oauth_chirho::ScopedTokenRateLimitChirho {
                window_ms_chirho: 60_000,
                max_invokes_chirho: oauth_chirho::TOKEN_RATE_MAX_INVOKES_CEILING_CHIRHO,
                device_id_chirho: None,
            }),
        )
        .unwrap()
        .token_chirho
    );
    let login_form_chirho = format!(
        "principal_chirho={}&credential_chirho={}",
        principal_chirho.replace('/', "%2F"),
        credential_chirho
    );
    let login_json_chirho = serde_json::json!({
        "principal_chirho": principal_chirho,
        "credential_chirho": credential_chirho,
    })
    .to_string();
    let token_request_chirho = serde_json::json!({
        "principal_chirho": principal_chirho,
        "credential_chirho": credential_chirho,
        "client_id_chirho": public_client_chirho,
        "scopes_chirho": [],
    })
    .to_string();
    let save_chirho = write_request_chirho(None, "k2 matrix page");
    let invoke_chirho =
        serde_json::json!({"target_chirho": KEYED_APP_CHIRHO, "payload_chirho": ""}).to_string();
    let json_chirho = ("content-type", "application/json");
    let form_chirho = ("content-type", "application/x-www-form-urlencoded");
    let preview_path_chirho = format!("/preview-chirho/{}", "0".repeat(64));

    with_successor_served_chirho(&tenant_chirho.root_chirho, |addr_chirho| {
        let cookie_header_chirho = ("cookie", cookie_chirho.as_str());
        let bearer_header_chirho = ("authorization", read_key_chirho.as_str());
        let private_chirho = vec![
            // F5's shape on a signed-in app: the page, the root, the save, a review POST, and the page by a limited key.
            answer_chirho(
                addr_chirho,
                "page by session",
                "GET",
                "/app-chirho/keyedapp/view",
                &[cookie_header_chirho],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "root by session",
                "GET",
                "/app-chirho/keyedapp/",
                &[cookie_header_chirho],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "save by session",
                "POST",
                "/app-chirho/keyedapp/save",
                &[cookie_header_chirho],
                save_chirho.as_bytes(),
            ),
            answer_chirho(
                addr_chirho,
                "review by session",
                "POST",
                &format!("/app-chirho/keyedapp/{REVIEW_ROUTE_CHIRHO}"),
                &[cookie_header_chirho],
                save_chirho.as_bytes(),
            ),
            answer_chirho(
                addr_chirho,
                "page by limited key",
                "GET",
                "/app-chirho/keyedapp/view",
                &[bearer_header_chirho],
                b"",
            ),
            // A signed-in app's JSON answer.
            answer_chirho(
                addr_chirho,
                "protected json app by session",
                "GET",
                &format!("/app-chirho/{PROTECTED_JSON_APP_CHIRHO}/"),
                &[cookie_header_chirho],
                b"",
            ),
            // Refusals.
            answer_chirho(
                addr_chirho,
                "anonymous on a signed-in app",
                "GET",
                "/app-chirho/keyedapp/view",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "read key on the save",
                "POST",
                "/app-chirho/keyedapp/save",
                &[bearer_header_chirho],
                save_chirho.as_bytes(),
            ),
            answer_chirho(
                addr_chirho,
                "unknown app",
                "GET",
                "/app-chirho/no-such-app-chirho/view",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "unknown descriptor",
                "GET",
                "/app-descriptor-chirho/no-such-app-chirho",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "preview refusal",
                "GET",
                &preview_path_chirho,
                &[],
                b"",
            ),
            // The framework's own and the fallback's.
            answer_chirho(
                addr_chirho,
                "method not allowed",
                "DELETE",
                "/healthz-chirho",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "fallback",
                "GET",
                "/no-such-path-chirho",
                &[],
                b"",
            ),
            // Alternate entries.
            answer_chirho(
                addr_chirho,
                "ssr by session",
                "GET",
                "/ssr-chirho/keyedapp",
                &[cookie_header_chirho],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "invoke by session",
                "POST",
                "/invoke-chirho",
                &[cookie_header_chirho, json_chirho],
                invoke_chirho.as_bytes(),
            ),
            // Auth and owner routes, the token-bearing answers included.
            answer_chirho(
                addr_chirho,
                "login page",
                "GET",
                "/auth-chirho/login-chirho",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "form login",
                "POST",
                "/auth-chirho/login-chirho",
                &[form_chirho],
                login_form_chirho.as_bytes(),
            ),
            answer_chirho(
                addr_chirho,
                "json login with its token",
                "POST",
                "/auth-chirho/login-chirho",
                &[json_chirho],
                login_json_chirho.as_bytes(),
            ),
            answer_chirho(
                addr_chirho,
                "token road with its key",
                "POST",
                "/auth-chirho/token-chirho",
                &[json_chirho],
                token_request_chirho.as_bytes(),
            ),
            answer_chirho(
                addr_chirho,
                "owner key list",
                "GET",
                "/auth-chirho/keys-chirho",
                &[cookie_header_chirho],
                b"",
            ),
            answer_chirho(addr_chirho, "health", "GET", "/healthz-chirho", &[], b""),
            // A public app, but not to an anonymous GET.
            answer_chirho(
                addr_chirho,
                "public app by session",
                "GET",
                "/app-chirho/k2-public/",
                &[cookie_header_chirho],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "public app with a valid bearer",
                "GET",
                "/app-chirho/k2-public/",
                &[("authorization", public_key_chirho.as_str())],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "public app with a made-up bearer",
                "GET",
                "/app-chirho/k2-public/",
                &[("authorization", "Bearer not-a-key-chirho")],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "public app by anonymous POST",
                "POST",
                "/app-chirho/k2-public/",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "public app redirect",
                "GET",
                "/app-chirho/k2-public",
                &[],
                b"",
            ),
        ];
        let public_chirho = vec![
            answer_chirho(addr_chirho, "landing page", "GET", "/", &[], b""),
            answer_chirho(
                addr_chirho,
                "host script",
                "GET",
                "/host-chirho.js",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "platform mcp",
                "GET",
                "/platform-mcp-chirho",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "app descriptor",
                "GET",
                "/app-descriptor-chirho/k2-public",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "app docs",
                "GET",
                "/app-docs-chirho/k2-public",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "app mcp",
                "GET",
                "/app-mcp-chirho/k2-public",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "contact demo page",
                "GET",
                "/contact-demo-chirho",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "public app anonymous GET",
                "GET",
                "/app-chirho/k2-public/",
                &[],
                b"",
            ),
            answer_chirho(
                addr_chirho,
                "public json app anonymous GET",
                "GET",
                "/app-chirho/k2-public-json/",
                &[],
                b"",
            ),
        ];
        // Every row's expected status, judged before its header: a row means something only if it reached what it
        // names. Every row has one, and every expectation names a row, so none can be skipped or relabelled.
        let expected_chirho: std::collections::BTreeMap<&str, u16> =
            std::collections::BTreeMap::from([
                ("page by session", 200),
                ("root by session", 200),
                ("save by session", 200),
                ("review by session", 200),
                ("page by limited key", 200),
                ("protected json app by session", 200),
                ("anonymous on a signed-in app", 401),
                ("read key on the save", 403),
                ("unknown app", 400),
                ("unknown descriptor", 404),
                ("preview refusal", 400),
                ("method not allowed", 405),
                ("fallback", 404),
                ("ssr by session", 200),
                ("invoke by session", 200),
                ("login page", 200),
                ("form login", 303),
                ("json login with its token", 200),
                ("token road with its key", 200),
                ("owner key list", 200),
                ("health", 200),
                ("public app by session", 200),
                ("public app with a valid bearer", 200),
                ("public app with a made-up bearer", 403),
                ("public app by anonymous POST", 200),
                ("public app redirect", 308),
                ("landing page", 200),
                ("host script", 200),
                ("platform mcp", 200),
                ("app descriptor", 200),
                ("app docs", 200),
                ("app mcp", 200),
                ("contact demo page", 200),
                ("public app anonymous GET", 200),
                ("public json app anonymous GET", 200),
            ]);
        let mut status_faults_chirho: Vec<String> = Vec::new();
        for row_chirho in private_chirho.iter().chain(public_chirho.iter()) {
            match expected_chirho.get(row_chirho.label_chirho.as_str()) {
                Some(expected_status_chirho)
                    if *expected_status_chirho == row_chirho.status_chirho => {}
                expected_status_chirho => status_faults_chirho.push(format!(
                    "{}: expected {expected_status_chirho:?}, answered {}",
                    row_chirho.label_chirho, row_chirho.status_chirho
                )),
            }
        }
        let labels_chirho: std::collections::BTreeSet<&str> = private_chirho
            .iter()
            .chain(public_chirho.iter())
            .map(|row_chirho| row_chirho.label_chirho.as_str())
            .collect();
        for label_chirho in expected_chirho.keys() {
            if !labels_chirho.contains(label_chirho) {
                status_faults_chirho.push(format!("{label_chirho}: no such row"));
            }
        }
        assert!(status_faults_chirho.is_empty(), "{status_faults_chirho:#?}");
        // A signed-in app's JSON answer says it is JSON.
        let protected_json_chirho = private_chirho
            .iter()
            .find(|row_chirho| row_chirho.label_chirho == "protected json app by session")
            .unwrap();
        assert!(
            protected_json_chirho
                .content_type_chirho
                .as_deref()
                .is_some_and(
                    |content_type_chirho| content_type_chirho.starts_with("application/json")
                ),
            "the protected JSON answer's content type: {:?}",
            protected_json_chirho.content_type_chirho
        );
        for row_chirho in &private_chirho {
            assert_eq!(
                row_chirho.cache_chirho.as_deref(),
                Some(PRIVATE_CHIRHO),
                "{} ({}) must leave private, no-store",
                row_chirho.label_chirho,
                row_chirho.status_chirho
            );
        }
        // Each public row's handler sets no caching of its own, so it leaves with none, as before this layer.
        for row_chirho in &public_chirho {
            assert_eq!(
                row_chirho.cache_chirho, None,
                "{} keeps its handler's caching",
                row_chirho.label_chirho
            );
        }
    });
}

/// A public app's successful anonymous answer that sets a cookie is not public: the cookie is somebody's state, so the
/// answer leaves `private, no-store`. The control is the same answer without the cookie, which the rule marks public
/// and the layer leaves with no `Cache-Control` at all, as before K2. No row of the served matrix sets a cookie on an
/// anonymous GET, so this arm is what pins the condition.
///
/// MIGRATION PATH: the cookie answer keeping no `Cache-Control` means the rule lost its `Set-Cookie` condition; the
/// control gaining one means the public app is no longer read as public, and this arm proves nothing until it is.
#[test]
fn a_public_apps_anonymous_answer_that_sets_a_cookie_leaves_private_chirho() {
    use crate::serve_chirho::answer_cache_chirho::{
        finalize_answer_cache_chirho, public_app_answer_if_anonymous_chirho,
    };
    use axum::response::IntoResponse;
    let (tenant_chirho, _) = matrix_tenant_chirho();
    let state_chirho = tenant_chirho.state_chirho();
    let answer_chirho = |sets_cookie_chirho: bool| {
        let mut response_chirho = (StatusCode::OK, "a public page").into_response();
        if sets_cookie_chirho {
            response_chirho.headers_mut().insert(
                axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_static("seen_chirho=1; Path=/"),
            );
        }
        let marked_chirho = public_app_answer_if_anonymous_chirho(
            &state_chirho,
            &HeaderMap::new(),
            PUBLIC_APP_CHIRHO,
            response_chirho,
        );
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(finalize_answer_cache_chirho(marked_chirho))
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .map(|value_chirho| value_chirho.to_str().unwrap().to_string())
    };
    assert_eq!(
        answer_chirho(false),
        None,
        "the control: marked public, no Cache-Control"
    );
    assert_eq!(answer_chirho(true).as_deref(), Some(PRIVATE_CHIRHO));
}
