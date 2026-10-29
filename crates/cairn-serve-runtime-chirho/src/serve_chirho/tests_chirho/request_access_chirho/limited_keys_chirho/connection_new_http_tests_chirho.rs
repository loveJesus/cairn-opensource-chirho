// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3's served road over a real local server, through the configured road `up` composes (PFE #26801): the gate,
//! the signed-out GET and its sign-in page's target, the form's shape over raw HTTP and its one-time disclosure, every
//! answer's headers, the framework's own included, and the refusals with the attempt rows each appends. These arms are
//! raw HTTP, not a browser; the JavaScript-disabled browser run is separate (PFE #26814).
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (Part 3's placement,
//! as decided).

use super::limited_key_fixture_chirho::*;
use super::*;
use axum::http::header::COOKIE;
use std::io::{Read, Write};
use std::path::Path;

pub(super) const CONNECTION_NEW_PATH_CHIRHO: &str = "/auth-chirho/connection-new-chirho";
const LOGIN_PATH_CHIRHO: &str = "/auth-chirho/login-chirho";
const SIGN_IN_PATH_CHIRHO: &str = "/auth-chirho/connection-sign-in-chirho";
const ATTEMPTS_LOG_CHIRHO: &str = "identity-auth-attempts-chirho.jsonl";
const CONNECTION_TOKENS_LOG_CHIRHO: &str = "connection-tokens-chirho.jsonl";

/// The configured road (`up`'s composition) serving `root_chirho` with the connection gate `open_chirho`, its sign-in
/// velocity raised past what these arms measure, while `probe_chirho` runs.
pub(super) fn with_connection_road_chirho<T>(
    root_chirho: &Path,
    open_chirho: bool,
    probe_chirho: impl FnOnce(&str) -> T,
) -> T {
    with_connection_road_limits_chirho(
        root_chirho,
        open_chirho,
        ServedRequestAbuseLimitsChirho {
            sign_in_principal_successes_per_hour_chirho: 100,
            ..ServedRequestAbuseLimitsChirho::default()
        },
        probe_chirho,
    )
}

/// The configured road serving `root_chirho` with the connection gate `open_chirho` and the request limits
/// `limits_chirho`, while `probe_chirho` runs.
pub(super) fn with_connection_road_limits_chirho<T>(
    root_chirho: &Path,
    open_chirho: bool,
    limits_chirho: ServedRequestAbuseLimitsChirho,
    probe_chirho: impl FnOnce(&str) -> T,
) -> T {
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.to_path_buf();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_with_configured_ledger_host_chirho(
                &root_for_server_chirho,
                port_chirho,
                8,
                ServeAuthTokensChirho::new_chirho(String::new(), String::new())
                    .with_connection_issuance_enabled_chirho(open_chirho),
                false,
                limits_chirho,
                ConfiguredLedgerHostRuntimePortsChirho::uncomposed_chirho(),
            )
            .await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let result_chirho = probe_chirho(&addr_chirho);
        server_chirho.abort();
        result_chirho
    })
}

/// User `index_chirho`'s browser session cookie, signed in through the engine with no attempt row.
pub(super) fn cookie_value_chirho(
    tenant_chirho: &KeyedTenantChirho,
    index_chirho: usize,
) -> String {
    tenant_chirho
        .cookie_chirho(index_chirho)
        .get(COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// A form body: the client id, each action, and the credential, encoded as a browser encodes a form.
pub(super) fn form_body_chirho(
    client_id_chirho: &str,
    actions_chirho: &[&str],
    credential_chirho: &str,
) -> String {
    let mut form_chirho = url::form_urlencoded::Serializer::new(String::new());
    form_chirho.append_pair("client_id_chirho", client_id_chirho);
    for action_chirho in actions_chirho {
        form_chirho.append_pair("action_chirho", action_chirho);
    }
    form_chirho.append_pair("credential_chirho", credential_chirho);
    form_chirho.finish()
}

/// A form-encoded POST to the road, with the cookie when one is given.
pub(super) fn post_form_chirho(
    addr_chirho: &str,
    cookie_chirho: Option<&str>,
    body_chirho: &str,
) -> HttpSmokeResponseChirho {
    let mut headers_chirho = vec![("content-type", "application/x-www-form-urlencoded")];
    if let Some(cookie_chirho) = cookie_chirho {
        headers_chirho.push(("cookie", cookie_chirho));
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        CONNECTION_NEW_PATH_CHIRHO,
        &headers_chirho,
        body_chirho.as_bytes(),
    )
}

pub(super) fn get_chirho(
    addr_chirho: &str,
    path_chirho: &str,
    cookie_chirho: Option<&str>,
) -> HttpSmokeResponseChirho {
    let headers_chirho: Vec<(&str, &str)> = cookie_chirho
        .map(|cookie_chirho| ("cookie", cookie_chirho))
        .into_iter()
        .collect();
    http_request_for_smoke_chirho(addr_chirho, "GET", path_chirho, &headers_chirho, b"")
}

pub(super) fn location_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    response_chirho
        .headers_chirho
        .get("location")
        .cloned()
        .unwrap_or_default()
}

/// The form's own URL for `client_id_chirho`, as the road builds it.
pub(super) fn form_target_chirho(client_id_chirho: &str) -> String {
    format!(
        "{CONNECTION_NEW_PATH_CHIRHO}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id_chirho", client_id_chirho)
            .finish()
    )
}

/// EVERY ANSWER OF BOTH ROUTES CARRIES THE GUARD HEADERS: never stored, never framed, never sniffed, never a referrer,
/// and nothing loads or runs in it.
pub(super) fn assert_guarded_chirho(response_chirho: &HttpSmokeResponseChirho) {
    let headers_chirho = &response_chirho.headers_chirho;
    let header_chirho = |name_chirho: &str| headers_chirho.get(name_chirho).map(String::as_str);
    assert_eq!(
        header_chirho("cache-control"),
        Some("private, no-store"),
        "{headers_chirho:?}"
    );
    let policy_chirho = header_chirho("content-security-policy").unwrap_or_default();
    for directive_chirho in [
        "default-src 'none'",
        "script-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'none'",
    ] {
        assert!(
            policy_chirho.contains(directive_chirho),
            "{directive_chirho} in {policy_chirho}"
        );
    }
    assert_eq!(header_chirho("x-content-type-options"), Some("nosniff"));
    assert_eq!(header_chirho("referrer-policy"), Some("no-referrer"));
    assert_eq!(header_chirho("x-frame-options"), Some("DENY"));
}

/// Every file under `root_chirho` that holds `needle_chirho`.
pub(super) fn files_holding_chirho(
    root_chirho: &Path,
    needle_chirho: &str,
) -> Vec<std::path::PathBuf> {
    let mut found_chirho = Vec::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = pending_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap() {
            let path_chirho = entry_chirho.unwrap().path();
            if path_chirho.is_dir() {
                pending_chirho.push(path_chirho);
            } else if std::fs::read(&path_chirho)
                .unwrap_or_default()
                .windows(needle_chirho.len())
                .any(|window_chirho| window_chirho == needle_chirho.as_bytes())
            {
                found_chirho.push(path_chirho);
            }
        }
    }
    found_chirho
}

/// The attempt rows on disk as (endpoint, outcome).
pub(super) fn attempt_rows_chirho(
    root_chirho: &Path,
) -> Vec<(String, identity_chirho::IdentityAuthAttemptOutcomeChirho)> {
    identity_chirho::load_auth_attempts_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .map(|record_chirho| (record_chirho.endpoint_chirho, record_chirho.outcome_chirho))
        .collect()
}

pub(super) fn lines_chirho(root_chirho: &Path, name_chirho: &str) -> usize {
    std::fs::read_to_string(root_chirho.join(name_chirho))
        .map(|text_chirho| text_chirho.lines().count())
        .unwrap_or(0)
}

/// A POST whose declared body never arrives, read with a deadline: `Some` answer means the road answered without
/// reading its body; `None`, that it was still waiting for it when the deadline passed.
pub(super) fn answer_without_its_body_chirho(
    addr_chirho: &str,
    headers_chirho: &[(&str, &str)],
    deadline_chirho: std::time::Duration,
) -> Option<u16> {
    let mut stream_chirho = std::net::TcpStream::connect(addr_chirho).unwrap();
    stream_chirho
        .set_read_timeout(Some(deadline_chirho))
        .unwrap();
    let mut request_chirho = format!(
        "POST {CONNECTION_NEW_PATH_CHIRHO} HTTP/1.1\r\nhost: {addr_chirho}\r\nconnection: close\r\ncontent-length: 4096\r\n"
    );
    for (name_chirho, value_chirho) in headers_chirho {
        request_chirho.push_str(&format!("{name_chirho}: {value_chirho}\r\n"));
    }
    request_chirho.push_str("\r\n");
    stream_chirho.write_all(request_chirho.as_bytes()).unwrap();
    let mut answer_chirho = Vec::new();
    let mut buffer_chirho = [0_u8; 4096];
    while !http_request_complete_chirho(&answer_chirho) {
        match stream_chirho.read(&mut buffer_chirho) {
            Ok(0) => break,
            Ok(read_chirho) => answer_chirho.extend_from_slice(&buffer_chirho[..read_chirho]),
            Err(_timed_out_chirho) => return None,
        }
    }
    String::from_utf8_lossy(&answer_chirho)
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// THE CLOSED GATE ANSWERS 503 BEFORE ANYTHING IS READ, AND THE BODY IS NEVER POLLED: closed, the form's GET and a valid
/// POST with a live cookie each answer the fixed 503 with every guard header, and nothing is appended. A POST whose
/// declared body never arrives is answered at once, closed, and signed out with the gate open; the control, open with a
/// live cookie, waits for its body.
#[test]
fn the_closed_gate_answers_before_anything_is_read_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-closed", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = &tenant_chirho.root_chirho;
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let (_principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let body_chirho = form_body_chirho(
        &tenant_chirho.client_id_chirho,
        &[PAGE_READ_CHIRHO],
        secret_chirho,
    );
    let written_chirho = || {
        (
            lines_chirho(root_chirho, CONNECTION_TOKENS_LOG_CHIRHO),
            lines_chirho(root_chirho, ATTEMPTS_LOG_CHIRHO),
        )
    };
    let before_chirho = written_chirho();
    with_connection_road_chirho(root_chirho, false, |addr_chirho| {
        for response_chirho in [
            get_chirho(
                addr_chirho,
                &form_target_chirho(&tenant_chirho.client_id_chirho),
                Some(&cookie_chirho),
            ),
            post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho),
            post_form_chirho(addr_chirho, None, "not a form at all"),
        ] {
            assert_eq!(response_chirho.status_chirho, 503);
            assert!(http_body_text_chirho(&response_chirho)
                .contains("id=\"connection-issuance-disabled-chirho\""));
            assert_guarded_chirho(&response_chirho);
        }
        let short_chirho = std::time::Duration::from_secs(10);
        assert_eq!(
            answer_without_its_body_chirho(
                addr_chirho,
                &[
                    ("cookie", &cookie_chirho),
                    ("content-type", "application/x-www-form-urlencoded")
                ],
                short_chirho
            ),
            Some(503),
            "closed, the road answers without reading its body"
        );
    });
    assert_eq!(
        written_chirho(),
        before_chirho,
        "the closed gate appends nothing"
    );
    with_connection_road_chirho(root_chirho, true, |addr_chirho| {
        assert_eq!(
            answer_without_its_body_chirho(
                addr_chirho,
                &[("content-type", "application/x-www-form-urlencoded")],
                std::time::Duration::from_secs(10)
            ),
            Some(303),
            "signed out, the POST refuses without reading its body"
        );
        assert_eq!(
            answer_without_its_body_chirho(
                addr_chirho,
                &[
                    ("cookie", &cookie_chirho),
                    ("content-type", "application/x-www-form-urlencoded")
                ],
                std::time::Duration::from_secs(2)
            ),
            None,
            "the control: open and signed in, the road waits for the body it reads"
        );
    });
}

/// THE FRAMEWORK'S OWN ANSWERS AT THIS ROUTE CARRY THE GUARD (PFE #26814): PUT, OPTIONS, DELETE and PATCH get the
/// framework's 405, its `Allow` naming GET, HEAD and POST and its body empty, and every guard header, with the gate
/// closed and open. Beside them, the controls: the handlers' own answers to GET, HEAD and POST at the same route carry
/// the same headers. A guard only the handlers applied passes the controls and fails the 405s.
#[test]
fn the_framework_answers_at_this_route_carry_the_guard_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-methods", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = &tenant_chirho.root_chirho;
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let target_chirho = form_target_chirho(&tenant_chirho.client_id_chirho);
    let request_chirho = |addr_chirho: &str, method_chirho: &str| {
        http_request_for_smoke_chirho(
            addr_chirho,
            method_chirho,
            &target_chirho,
            &[
                ("cookie", &cookie_chirho),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            b"",
        )
    };
    for open_chirho in [false, true] {
        with_connection_road_chirho(root_chirho, open_chirho, |addr_chirho| {
            for method_chirho in ["PUT", "OPTIONS", "DELETE", "PATCH"] {
                let response_chirho = request_chirho(addr_chirho, method_chirho);
                assert_eq!(
                    response_chirho.status_chirho, 405,
                    "{method_chirho}, open {open_chirho}"
                );
                let mut allowed_chirho: Vec<&str> = response_chirho
                    .headers_chirho
                    .get("allow")
                    .map(|allow_chirho| allow_chirho.split(',').map(str::trim).collect())
                    .unwrap_or_default();
                allowed_chirho.sort_unstable();
                assert_eq!(allowed_chirho, ["GET", "HEAD", "POST"], "{method_chirho}");
                assert!(
                    response_chirho.body_chirho.is_empty(),
                    "{method_chirho}: the framework's empty body passes through"
                );
                assert_guarded_chirho(&response_chirho);
            }
            for method_chirho in ["GET", "HEAD", "POST"] {
                let response_chirho = request_chirho(addr_chirho, method_chirho);
                assert_ne!(
                    response_chirho.status_chirho, 405,
                    "{method_chirho}: a handler answers"
                );
                assert_guarded_chirho(&response_chirho);
            }
        });
    }
}

/// SIGNED OUT, THE GET GOES TO THE ROAD'S SIGN-IN PAGE WITH THE FORM AS ITS TARGET (PFE unit 330): the 303 carries the
/// engine-built target, holding only the client id; the sign-in page carries exactly that target as a hidden field, and
/// a sign-in through it lands on the form. The page takes no other target: a foreign, malformed, extended or repeated one
/// is a 303 to the canonical login page, which carries no target at all, and a malformed client id gets no target.
#[test]
fn a_signed_out_get_returns_through_the_login_to_the_form_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-return", OpeningsChirho::PAGE_CHIRHO, 1);
    let client_id_chirho = tenant_chirho.client_id_chirho.clone();
    let target_chirho = form_target_chirho(&client_id_chirho);
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    with_connection_road_chirho(&tenant_chirho.root_chirho, true, |addr_chirho| {
        let signed_out_chirho = get_chirho(addr_chirho, &target_chirho, None);
        assert_eq!(signed_out_chirho.status_chirho, 303);
        assert_guarded_chirho(&signed_out_chirho);
        let sign_in_url_chirho = location_chirho(&signed_out_chirho);
        let redirect_query_chirho = |value_chirho: &str| {
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("redirect_chirho", value_chirho)
                .finish()
        };
        let encoded_target_chirho = |value_chirho: &str| {
            format!(
                "{SIGN_IN_PATH_CHIRHO}?{}",
                redirect_query_chirho(value_chirho)
            )
        };
        assert_eq!(
            sign_in_url_chirho,
            format!(
                "{}#refusal-no-session-chirho",
                encoded_target_chirho(&target_chirho)
            )
        );

        let sign_in_page_chirho = get_chirho(
            addr_chirho,
            sign_in_url_chirho.split('#').next().unwrap(),
            None,
        );
        assert_eq!(sign_in_page_chirho.status_chirho, 200);
        assert_eq!(
            field_values_chirho(
                &http_body_text_chirho(&sign_in_page_chirho),
                "redirect_chirho"
            ),
            std::slice::from_ref(&target_chirho)
        );

        for foreign_chirho in [
            "//evil.example/path".to_string(),
            "https://evil.example/".to_string(),
            "/other-chirho".to_string(),
            format!("{target_chirho}&extra_chirho=1"),
            "/\\evil.example".to_string(),
            format!("{target_chirho}\r\nx"),
            form_target_chirho("client/ABCDEF0123456789"),
            form_target_chirho("client/0123"),
        ] {
            let refused_chirho =
                get_chirho(addr_chirho, &encoded_target_chirho(&foreign_chirho), None);
            assert_eq!(
                (
                    refused_chirho.status_chirho,
                    location_chirho(&refused_chirho)
                ),
                (303, LOGIN_PATH_CHIRHO.to_string()),
                "{foreign_chirho:?}"
            );
        }
        let twice_chirho = format!(
            "{}&redirect_chirho=%2F",
            encoded_target_chirho(&target_chirho)
        );
        assert_eq!(
            location_chirho(&get_chirho(addr_chirho, &twice_chirho, None)),
            LOGIN_PATH_CHIRHO
        );
        let plain_chirho = http_body_text_chirho(&get_chirho(addr_chirho, LOGIN_PATH_CHIRHO, None));
        assert_eq!(
            http_body_text_chirho(&get_chirho(
                addr_chirho,
                &format!(
                    "{LOGIN_PATH_CHIRHO}?{}",
                    redirect_query_chirho(&target_chirho)
                ),
                None
            )),
            plain_chirho,
            "the canonical login page carries no target, even the form's own"
        );

        let malformed_chirho = get_chirho(addr_chirho, &form_target_chirho("client/XYZ"), None);
        assert_eq!(
            location_chirho(&malformed_chirho),
            format!("{LOGIN_PATH_CHIRHO}#refusal-no-session-chirho")
        );

        let login_body_chirho = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("redirect_chirho", &target_chirho)
            .append_pair("principal_chirho", principal_chirho)
            .append_pair("credential_chirho", secret_chirho)
            .finish();
        let signed_in_chirho = http_request_for_smoke_chirho(
            addr_chirho,
            "POST",
            LOGIN_PATH_CHIRHO,
            &[("content-type", "application/x-www-form-urlencoded")],
            login_body_chirho.as_bytes(),
        );
        assert_eq!(
            (
                signed_in_chirho.status_chirho,
                location_chirho(&signed_in_chirho)
            ),
            (303, target_chirho.clone())
        );
        let cookie_chirho = signed_in_chirho
            .headers_chirho
            .get("set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let form_chirho = get_chirho(addr_chirho, &target_chirho, Some(&cookie_chirho));
        assert_eq!(form_chirho.status_chirho, 200);
        assert!(http_body_text_chirho(&form_chirho)
            .contains("<form method=\"post\" action=\"/auth-chirho/connection-new-chirho\">"));
    });
}

/// The value of `name="<field>"`'s `value="..."` attributes in `page_chirho`, in order: the no-script reading of a form.
pub(super) fn field_values_chirho(page_chirho: &str, field_chirho: &str) -> Vec<String> {
    let marker_chirho = format!("name=\"{field_chirho}\" value=\"");
    page_chirho
        .match_indices(&marker_chirho)
        .map(|(at_chirho, _)| {
            let rest_chirho = &page_chirho[at_chirho + marker_chirho.len()..];
            rest_chirho[..rest_chirho.find('"').unwrap()].to_string()
        })
        .collect()
}

/// THE FORM'S SHAPE OVER RAW HTTP, AND THE KEY SHOWN ONCE: the form's fields are read from the served HTML and posted
/// form-encoded, as a form submission carries them. It is raw HTTP, not a browser (PFE #26814): no browser parses the
/// page, keeps the cookie or submits the form here. The answer's body shows the bearer exactly once; no header carries
/// it; it admits the granted action and not the other. A planted needle is found under the root, and neither the bearer
/// nor the password is.
#[test]
fn the_form_over_raw_http_shows_the_key_once_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("k4p3-form", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = &tenant_chirho.root_chirho;
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let (_principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let bearer_chirho = with_connection_road_chirho(root_chirho, true, |addr_chirho| {
        let form_chirho = get_chirho(
            addr_chirho,
            &form_target_chirho(&tenant_chirho.client_id_chirho),
            Some(&cookie_chirho),
        );
        assert_eq!(form_chirho.status_chirho, 200);
        assert_guarded_chirho(&form_chirho);
        assert_eq!(
            form_chirho
                .headers_chirho
                .get("content-type")
                .map(String::as_str),
            Some("text/html; charset=utf-8")
        );
        let page_chirho = http_body_text_chirho(&form_chirho);
        assert!(!page_chirho.to_ascii_lowercase().contains("<script"));
        assert!(page_chirho
            .contains("<form method=\"post\" action=\"/auth-chirho/connection-new-chirho\">"));
        assert!(
            page_chirho.contains("name=\"credential_chirho\" autocomplete=\"current-password\"")
        );
        let client_ids_chirho = field_values_chirho(&page_chirho, "client_id_chirho");
        let mut actions_chirho = field_values_chirho(&page_chirho, "action_chirho");
        assert_eq!(
            client_ids_chirho,
            vec![tenant_chirho.client_id_chirho.clone()]
        );
        actions_chirho.sort();
        assert_eq!(
            actions_chirho,
            vec![PAGE_READ_CHIRHO.to_string(), PAGE_SAVE_CHIRHO.to_string()]
        );

        // What a form submission carries: the hidden field, the one box she ticked (read), and the password.
        let created_chirho = post_form_chirho(
            addr_chirho,
            Some(&cookie_chirho),
            &form_body_chirho(&client_ids_chirho[0], &[PAGE_READ_CHIRHO], secret_chirho),
        );
        assert_eq!(
            created_chirho.status_chirho,
            200,
            "{}",
            http_body_text_chirho(&created_chirho)
        );
        assert_guarded_chirho(&created_chirho);
        let page_chirho = http_body_text_chirho(&created_chirho);
        let start_chirho = page_chirho.find("<code>").unwrap() + "<code>".len();
        let bearer_chirho = page_chirho
            [start_chirho..start_chirho + page_chirho[start_chirho..].find("</code>").unwrap()]
            .to_string();
        assert!(bearer_chirho.len() > 20, "{bearer_chirho}");
        assert_eq!(
            page_chirho.matches(&bearer_chirho).count(),
            1,
            "the bearer once in the body"
        );
        for (name_chirho, value_chirho) in &created_chirho.headers_chirho {
            assert!(
                !value_chirho.contains(&bearer_chirho),
                "the bearer in the header {name_chirho}"
            );
        }
        let authorization_chirho = format!("Bearer {bearer_chirho}");
        let view_chirho = http_request_for_smoke_chirho(
            addr_chirho,
            "GET",
            &keyed_path_for_http_chirho(VIEW_ROUTE_CHIRHO),
            &[("authorization", &authorization_chirho)],
            b"",
        );
        assert_eq!(view_chirho.status_chirho, 200, "the granted action answers");
        let save_chirho = http_request_for_smoke_chirho(
            addr_chirho,
            "POST",
            &keyed_path_for_http_chirho(SAVE_ROUTE_CHIRHO),
            &[("authorization", &authorization_chirho)],
            super::app_route_fixture_chirho::write_request_chirho(None, "not granted").as_bytes(),
        );
        assert_eq!(
            save_chirho.status_chirho, 403,
            "the action not chosen is refused"
        );
        bearer_chirho
    });
    let control_chirho = "planted-control-needle-k4p3-chirho";
    std::fs::write(
        root_chirho.join("planted-control-chirho.txt"),
        control_chirho,
    )
    .unwrap();
    assert_eq!(
        files_holding_chirho(root_chirho, control_chirho).len(),
        1,
        "the scan finds what is there"
    );
    assert!(
        files_holding_chirho(root_chirho, &bearer_chirho).is_empty(),
        "no stored copy of the bearer"
    );
    assert!(
        files_holding_chirho(root_chirho, secret_chirho).is_empty(),
        "no stored copy of the password"
    );
}

pub(super) fn keyed_path_for_http_chirho(route_chirho: &str) -> String {
    format!("/app-chirho/{KEYED_APP_CHIRHO}/{route_chirho}")
}

/// THE REFUSALS: each answers its fixed 303 with every guard header, and none appends a session or a key. Only the wrong
/// password appends an attempt row, one failure under `token-chirho`: a non-form body, an unknown field, a repeated
/// action or credential, no action, an empty credential, a malformed or unknown client id, and an action the app does
/// not open append none.
#[test]
fn the_refusals_answer_their_tokens_and_append_no_key_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("k4p3-refusals", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = &tenant_chirho.root_chirho;
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let (_principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let client_id_chirho = tenant_chirho.client_id_chirho.clone();
    let target_chirho = form_target_chirho(&client_id_chirho);
    let keys_before_chirho = lines_chirho(root_chirho, CONNECTION_TOKENS_LOG_CHIRHO);
    with_connection_road_chirho(root_chirho, true, |addr_chirho| {
        let json_chirho = http_request_for_smoke_chirho(
            addr_chirho,
            "POST",
            CONNECTION_NEW_PATH_CHIRHO,
            &[
                ("content-type", "application/json"),
                ("cookie", &cookie_chirho),
            ],
            br#"{"client_id_chirho":"x"}"#,
        );
        assert_eq!(
            (json_chirho.status_chirho, location_chirho(&json_chirho)),
            (
                303,
                format!("{CONNECTION_NEW_PATH_CHIRHO}#refusal-request-invalid-chirho")
            )
        );
        assert_guarded_chirho(&json_chirho);
        let invalid_chirho = format!("{target_chirho}#refusal-request-invalid-chirho");
        for (body_chirho, expected_chirho) in [
            (
                format!(
                    "{}&extra_chirho=1",
                    form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], secret_chirho)
                ),
                invalid_chirho.clone(),
            ),
            (
                form_body_chirho(
                    &client_id_chirho,
                    &[PAGE_READ_CHIRHO, PAGE_READ_CHIRHO],
                    secret_chirho,
                ),
                invalid_chirho.clone(),
            ),
            (
                format!(
                    "{}&credential_chirho=again",
                    form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], secret_chirho)
                ),
                invalid_chirho.clone(),
            ),
            (
                form_body_chirho(&client_id_chirho, &[], secret_chirho),
                invalid_chirho.clone(),
            ),
            (
                form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], ""),
                invalid_chirho.clone(),
            ),
            (
                form_body_chirho("client/XYZ", &[PAGE_READ_CHIRHO], secret_chirho),
                format!("{CONNECTION_NEW_PATH_CHIRHO}#refusal-request-invalid-chirho"),
            ),
            (
                form_body_chirho(
                    "client/0000000000000000",
                    &[PAGE_READ_CHIRHO],
                    secret_chirho,
                ),
                format!(
                    "{}#refusal-request-invalid-chirho",
                    form_target_chirho("client/0000000000000000")
                ),
            ),
            (
                form_body_chirho(&client_id_chirho, &["page-admin-chirho"], secret_chirho),
                invalid_chirho.clone(),
            ),
        ] {
            let refused_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &body_chirho);
            assert_eq!(
                (
                    refused_chirho.status_chirho,
                    location_chirho(&refused_chirho)
                ),
                (303, expected_chirho),
                "{body_chirho}"
            );
            assert_guarded_chirho(&refused_chirho);
        }
        assert!(
            attempt_rows_chirho(root_chirho).is_empty(),
            "no request refusal appends an attempt row"
        );

        let mismatch_chirho = post_form_chirho(
            addr_chirho,
            Some(&cookie_chirho),
            &form_body_chirho(
                &client_id_chirho,
                &[PAGE_READ_CHIRHO],
                "not-the-secret-chirho",
            ),
        );
        assert_eq!(
            (
                mismatch_chirho.status_chirho,
                location_chirho(&mismatch_chirho)
            ),
            (
                303,
                format!("{target_chirho}#refusal-credential-mismatch-chirho")
            )
        );
        assert_guarded_chirho(&mismatch_chirho);
        assert_eq!(
            attempt_rows_chirho(root_chirho),
            vec![(
                identity_chirho::AUTH_ENDPOINT_SCOPED_TOKEN_CHIRHO.to_string(),
                identity_chirho::IdentityAuthAttemptOutcomeChirho::FailureChirho
            )]
        );

        let signed_out_chirho = post_form_chirho(
            addr_chirho,
            None,
            &form_body_chirho(&client_id_chirho, &[PAGE_READ_CHIRHO], secret_chirho),
        );
        assert_eq!(
            (
                signed_out_chirho.status_chirho,
                location_chirho(&signed_out_chirho)
            ),
            (
                303,
                format!("{LOGIN_PATH_CHIRHO}#refusal-no-session-chirho")
            )
        );
        assert!(!location_chirho(&signed_out_chirho).contains(secret_chirho));
        assert_guarded_chirho(&signed_out_chirho);

        let no_client_chirho = get_chirho(
            addr_chirho,
            CONNECTION_NEW_PATH_CHIRHO,
            Some(&cookie_chirho),
        );
        assert_eq!(no_client_chirho.status_chirho, 400);
        assert!(http_body_text_chirho(&no_client_chirho).contains("id=\"request-invalid-chirho\""));
        assert_guarded_chirho(&no_client_chirho);
        let unknown_client_chirho = get_chirho(
            addr_chirho,
            &form_target_chirho("client/0000000000000000"),
            Some(&cookie_chirho),
        );
        assert_eq!(unknown_client_chirho.status_chirho, 400);
        assert_guarded_chirho(&unknown_client_chirho);
    });
    assert_eq!(
        lines_chirho(root_chirho, CONNECTION_TOKENS_LOG_CHIRHO),
        keys_before_chirho,
        "no refusal appends a key"
    );
}
