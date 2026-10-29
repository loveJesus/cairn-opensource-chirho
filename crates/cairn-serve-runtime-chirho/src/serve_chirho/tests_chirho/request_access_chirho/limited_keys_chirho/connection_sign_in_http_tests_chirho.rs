// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The connection sign-in page (PFE unit 330, #27196) over a real local server, through the configured road `up`
//! composes. A signed-out Create link goes to its own sign-in page, which carries the form's accepted target and a
//! notice for each refusal that can bring her back to it. A failed sign-in keeps that target at both refusal exits. A
//! repeated target field is malformed before any credential work. Every other sign-in answers as before. Raw HTTP, not
//! a browser; the JavaScript-disabled browser run is separate.
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (the connection
//! sign-in page).

use super::connection_new_http_tests_chirho::{
    assert_guarded_chirho, attempt_rows_chirho, field_values_chirho, get_chirho, lines_chirho,
    location_chirho, with_connection_road_chirho, with_connection_road_limits_chirho,
    CONNECTION_NEW_PATH_CHIRHO,
};
use super::limited_key_fixture_chirho::*;
use super::*;
use std::path::Path;

const SIGN_IN_PATH_CHIRHO: &str = "/auth-chirho/connection-sign-in-chirho";
const LOGIN_PATH_CHIRHO: &str = "/auth-chirho/login-chirho";
const SESSIONS_LOG_CHIRHO: &str = "identity-sessions-chirho.jsonl";
const WRONG_SECRET_CHIRHO: &str = "not-her-secret-chirho";
/// The notices the page carries, each by the fragment that shows it.
const NOTICES_CHIRHO: [&str; 3] = [
    "refusal-no-session-chirho",
    "refusal-invalid-credential-chirho",
    "refusal-auth-rate-limited-chirho",
];

/// The form's canonical target for the keyed app, with its view route as the return path, as the road builds it.
fn app_target_chirho() -> String {
    format!(
        "{CONNECTION_NEW_PATH_CHIRHO}?{}",
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("app_chirho", KEYED_APP_CHIRHO)
            .append_pair(
                "return_chirho",
                &format!("/app-chirho/{KEYED_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}")
            )
            .finish()
    )
}

/// `value_chirho` as the one `redirect_chirho` field of a query, encoded by the serializer.
fn redirect_query_chirho(value_chirho: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("redirect_chirho", value_chirho)
        .finish()
}

/// The sign-in page's URL carrying `target_chirho`, as the road builds it, without a fragment.
fn sign_in_url_chirho(target_chirho: &str) -> String {
    format!(
        "{SIGN_IN_PATH_CHIRHO}?{}",
        redirect_query_chirho(target_chirho)
    )
}

/// A form POST to the login road, its fields in the order given.
fn sign_in_post_chirho(
    addr_chirho: &str,
    fields_chirho: &[(&str, &str)],
) -> HttpSmokeResponseChirho {
    let mut body_chirho = url::form_urlencoded::Serializer::new(String::new());
    for (field_chirho, value_chirho) in fields_chirho {
        body_chirho.append_pair(field_chirho, value_chirho);
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        LOGIN_PATH_CHIRHO,
        &[("content-type", "application/x-www-form-urlencoded")],
        body_chirho.finish().as_bytes(),
    )
}

/// What a sign-in may append: its attempt rows and its sessions.
fn sign_in_written_chirho(root_chirho: &Path) -> (usize, usize) {
    (
        attempt_rows_chirho(root_chirho).len(),
        lines_chirho(root_chirho, SESSIONS_LOG_CHIRHO),
    )
}

fn session_cookie_chirho(response_chirho: &HttpSmokeResponseChirho) -> String {
    response_chirho
        .headers_chirho
        .get("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// A SIGNED-OUT CREATE LINK SIGNS IN THROUGH ITS OWN PAGE: signed out, the app's canonical target goes to the connection
/// sign-in page with the no-session notice's fragment. That page carries exactly the target as its hidden field, posts
/// to the login road, carries the three notices its refusals can show, and has every guard header, for GET and for
/// HEAD. A sign-in through it lands on the form. The canonical login page carries no target at all, this one included:
/// it is shed (PFE unit 330), so one page owns connection sign-in.
#[test]
fn a_signed_out_create_link_signs_in_through_its_own_page_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("u330-journey", OpeningsChirho::PAGE_CHIRHO, 1);
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let target_chirho = app_target_chirho();
    with_connection_road_chirho(&tenant_chirho.root_chirho, true, |addr_chirho| {
        let signed_out_chirho = get_chirho(addr_chirho, &target_chirho, None);
        assert_eq!(signed_out_chirho.status_chirho, 303);
        assert_guarded_chirho(&signed_out_chirho);
        assert_eq!(
            location_chirho(&signed_out_chirho),
            format!(
                "{}#refusal-no-session-chirho",
                sign_in_url_chirho(&target_chirho)
            )
        );

        let page_chirho = get_chirho(addr_chirho, &sign_in_url_chirho(&target_chirho), None);
        assert_eq!(page_chirho.status_chirho, 200);
        assert_guarded_chirho(&page_chirho);
        let text_chirho = http_body_text_chirho(&page_chirho);
        assert_eq!(
            field_values_chirho(&text_chirho, "redirect_chirho"),
            [target_chirho.replace('&', "&amp;")],
            "{text_chirho}"
        );
        assert!(
            text_chirho.contains(&format!(
                "<form method=\"post\" action=\"{LOGIN_PATH_CHIRHO}\">"
            )),
            "{text_chirho}"
        );
        for notice_chirho in NOTICES_CHIRHO {
            assert!(
                text_chirho.contains(&format!("id=\"{notice_chirho}\"")),
                "{notice_chirho}: {text_chirho}"
            );
        }
        let head_chirho = http_request_for_smoke_chirho(
            addr_chirho,
            "HEAD",
            &sign_in_url_chirho(&target_chirho),
            &[],
            b"",
        );
        assert_eq!(head_chirho.status_chirho, 200);
        assert!(head_chirho.body_chirho.is_empty());
        assert_guarded_chirho(&head_chirho);

        let plain_chirho = http_body_text_chirho(&get_chirho(addr_chirho, LOGIN_PATH_CHIRHO, None));
        assert!(field_values_chirho(&plain_chirho, "redirect_chirho").is_empty());
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
            "the canonical login page sheds the connection target"
        );

        let signed_in_chirho = sign_in_post_chirho(
            addr_chirho,
            &[
                ("redirect_chirho", &target_chirho),
                ("principal_chirho", principal_chirho),
                ("credential_chirho", secret_chirho),
            ],
        );
        assert_eq!(
            (
                signed_in_chirho.status_chirho,
                location_chirho(&signed_in_chirho)
            ),
            (303, target_chirho.clone())
        );
        let form_chirho = get_chirho(
            addr_chirho,
            &target_chirho,
            Some(&session_cookie_chirho(&signed_in_chirho)),
        );
        assert_eq!(form_chirho.status_chirho, 200);
        assert_eq!(
            field_values_chirho(&http_body_text_chirho(&form_chirho), "client_id_chirho"),
            std::slice::from_ref(&tenant_chirho.client_id_chirho)
        );
    });
}

/// A WRONG PASSWORD COMES BACK TO THE SIGN-IN PAGE WITH ITS TARGET: a refused sign-in carrying the form's accepted
/// target returns to the connection sign-in page with that target and the invalid-credential notice's fragment. An
/// unknown principal gets the same bytes, so the refusal still tells no one whether the name exists. No session is
/// appended, and the right password then lands on the form's target.
#[test]
fn a_wrong_password_comes_back_to_the_sign_in_page_with_its_target_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("u330-wrong", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let target_chirho = app_target_chirho();
    let invalid_chirho = format!(
        "{}#refusal-invalid-credential-chirho",
        sign_in_url_chirho(&target_chirho)
    );
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let sessions_chirho = sign_in_written_chirho(&root_chirho).1;
        for principal_chirho in [principal_chirho, "nobody-by-this-name-chirho"] {
            let wrong_chirho = sign_in_post_chirho(
                addr_chirho,
                &[
                    ("redirect_chirho", &target_chirho),
                    ("principal_chirho", principal_chirho),
                    ("credential_chirho", WRONG_SECRET_CHIRHO),
                ],
            );
            assert_eq!(
                (wrong_chirho.status_chirho, location_chirho(&wrong_chirho)),
                (303, invalid_chirho.clone()),
                "{principal_chirho}"
            );
            assert!(!wrong_chirho.headers_chirho.contains_key("set-cookie"));
        }
        assert_eq!(sign_in_written_chirho(&root_chirho).1, sessions_chirho);
        let right_chirho = sign_in_post_chirho(
            addr_chirho,
            &[
                ("redirect_chirho", &target_chirho),
                ("principal_chirho", principal_chirho),
                ("credential_chirho", secret_chirho),
            ],
        );
        assert_eq!(
            (right_chirho.status_chirho, location_chirho(&right_chirho)),
            (303, target_chirho.clone())
        );
    });
}

/// BOTH RATE EXITS KEEP THE ACCEPTED TARGET, AND ONLY IT. The early exit: with the source's failure budget at one, a
/// second sign-in from that source, with the right password, is refused at the handler's check before any credential
/// work (it appends no attempt row and no session) and returns to the sign-in page with its target and the rate
/// notice's fragment; an ordinary target refused there goes to the canonical login page. The blocking exit: with the
/// default budget, a fresh principal's own failure limit refuses inside the blocking task, and keeps the target too.
#[test]
fn both_rate_exits_keep_only_the_accepted_target_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("u330-rates", OpeningsChirho::PAGE_CHIRHO, 2);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let target_chirho = app_target_chirho();
    let invalid_chirho = format!(
        "{}#refusal-invalid-credential-chirho",
        sign_in_url_chirho(&target_chirho)
    );
    let rate_chirho = format!(
        "{}#refusal-auth-rate-limited-chirho",
        sign_in_url_chirho(&target_chirho)
    );
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let one_failure_chirho = ServedRequestAbuseLimitsChirho {
        sign_in_principal_successes_per_hour_chirho: 100,
        sign_in_source_failures_per_window_chirho: 1,
        ..ServedRequestAbuseLimitsChirho::default()
    };
    with_connection_road_limits_chirho(&root_chirho, true, one_failure_chirho, |addr_chirho| {
        let wrong_chirho = sign_in_post_chirho(
            addr_chirho,
            &[
                ("redirect_chirho", &target_chirho),
                ("principal_chirho", principal_chirho),
                ("credential_chirho", WRONG_SECRET_CHIRHO),
            ],
        );
        assert_eq!(location_chirho(&wrong_chirho), invalid_chirho);
        let written_chirho = sign_in_written_chirho(&root_chirho);
        let early_chirho = sign_in_post_chirho(
            addr_chirho,
            &[
                ("redirect_chirho", &target_chirho),
                ("principal_chirho", principal_chirho),
                ("credential_chirho", secret_chirho),
            ],
        );
        assert_eq!(
            (early_chirho.status_chirho, location_chirho(&early_chirho)),
            (303, rate_chirho.clone())
        );
        assert_eq!(
            sign_in_written_chirho(&root_chirho),
            written_chirho,
            "the early exit runs before any credential work"
        );
        let ordinary_chirho = sign_in_post_chirho(
            addr_chirho,
            &[
                (
                    "redirect_chirho",
                    &format!("/app-chirho/{KEYED_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}"),
                ),
                ("principal_chirho", principal_chirho),
                ("credential_chirho", secret_chirho),
            ],
        );
        assert_eq!(
            location_chirho(&ordinary_chirho),
            format!("{LOGIN_PATH_CHIRHO}#refusal-auth-rate-limited-chirho")
        );
    });
    let (fresh_principal_chirho, _fresh_secret_chirho) = tenant_chirho.user_chirho(1);
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let mut refused_chirho = None;
        for _attempt_chirho in 0..12 {
            let wrong_chirho = sign_in_post_chirho(
                addr_chirho,
                &[
                    ("redirect_chirho", &target_chirho),
                    ("principal_chirho", fresh_principal_chirho),
                    ("credential_chirho", WRONG_SECRET_CHIRHO),
                ],
            );
            let location_chirho = location_chirho(&wrong_chirho);
            if location_chirho != invalid_chirho {
                refused_chirho = Some(location_chirho);
                break;
            }
        }
        assert_eq!(
            refused_chirho.as_deref(),
            Some(rate_chirho.as_str()),
            "the principal's limit refuses inside the task, and keeps the target"
        );
    });
}

/// A REPEATED TARGET FIELD IS MALFORMED, BEFORE ANY CREDENTIAL WORK: two `redirect_chirho` fields (equal, or the
/// accepted target beside a hostile one in either order) refuse through the existing malformed-request answer, the same
/// bytes a body too large to read gets, with the right password and with a wrong one. Nothing is appended: no attempt
/// row and no session. The honest single field, the control, signs in. Only `redirect_chirho` is narrowed: a repeated
/// principal or credential field keeps today's last-one-wins, a recorded residual (PFE #27203), not exercised here.
#[test]
fn a_repeated_target_field_is_malformed_before_any_credential_work_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("u330-repeat", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let target_chirho = app_target_chirho();
    let hostile_chirho = "/app-chirho/chosen-by-caller-chirho";
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let unreadable_chirho = http_request_for_smoke_chirho(
            addr_chirho,
            "POST",
            LOGIN_PATH_CHIRHO,
            &[("content-type", "application/x-www-form-urlencoded")],
            &vec![b'a'; 17 * 1024],
        );
        assert_eq!(unreadable_chirho.status_chirho, 400);
        let written_chirho = sign_in_written_chirho(&root_chirho);
        for (first_chirho, second_chirho) in [
            (target_chirho.as_str(), target_chirho.as_str()),
            (target_chirho.as_str(), hostile_chirho),
            (hostile_chirho, target_chirho.as_str()),
        ] {
            for credential_chirho in [secret_chirho, WRONG_SECRET_CHIRHO] {
                let repeated_chirho = sign_in_post_chirho(
                    addr_chirho,
                    &[
                        ("redirect_chirho", first_chirho),
                        ("principal_chirho", principal_chirho),
                        ("credential_chirho", credential_chirho),
                        ("redirect_chirho", second_chirho),
                    ],
                );
                let case_chirho = format!("{first_chirho} then {second_chirho}");
                assert_eq!(
                    repeated_chirho.status_chirho,
                    400,
                    "{case_chirho}: answered {}",
                    location_chirho(&repeated_chirho)
                );
                assert_eq!(
                    repeated_chirho.body_chirho, unreadable_chirho.body_chirho,
                    "{case_chirho}: the existing malformed-request answer"
                );
                for header_chirho in ["location", "set-cookie"] {
                    assert!(
                        !repeated_chirho.headers_chirho.contains_key(header_chirho),
                        "{case_chirho}: {header_chirho}"
                    );
                }
            }
        }
        assert_eq!(
            sign_in_written_chirho(&root_chirho),
            written_chirho,
            "no attempt row and no session"
        );
        let honest_chirho = sign_in_post_chirho(
            addr_chirho,
            &[
                ("redirect_chirho", &target_chirho),
                ("principal_chirho", principal_chirho),
                ("credential_chirho", secret_chirho),
            ],
        );
        assert_eq!(
            (honest_chirho.status_chirho, location_chirho(&honest_chirho)),
            (303, target_chirho.clone())
        );
        assert_eq!(sign_in_written_chirho(&root_chirho).1, written_chirho.1 + 1);
    });
}

/// THE SIGN-IN PAGE RENDERS ONLY ITS ONE ACCEPTED TARGET. Anything else is a 303 to the bare canonical login page, with
/// every guard header, for GET and for HEAD: no query, an empty one, an empty target, another origin, another
/// same-origin page, the form's bare route, a non-canonical encoding, the target with whitespace before or after it, a
/// repeated target, an extra field and another field name. Other methods get the framework's 405, its `Allow` naming GET
/// and HEAD, with the guard. Closed, the page answers the road's 503, guarded.
#[test]
fn the_sign_in_page_renders_only_its_one_accepted_target_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("u330-page", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let target_chirho = app_target_chirho();
    let page_url_chirho = sign_in_url_chirho(&target_chirho);
    let refused_chirho = [
        SIGN_IN_PATH_CHIRHO.to_string(),
        format!("{SIGN_IN_PATH_CHIRHO}?"),
        format!("{SIGN_IN_PATH_CHIRHO}?redirect_chirho="),
        sign_in_url_chirho("https://evil.example/"),
        sign_in_url_chirho(&format!("//evil.example{target_chirho}")),
        sign_in_url_chirho(&format!(
            "/app-chirho/{KEYED_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}"
        )),
        sign_in_url_chirho(CONNECTION_NEW_PATH_CHIRHO),
        sign_in_url_chirho(&target_chirho.replace("%2F", "/")),
        sign_in_url_chirho(&format!(" {target_chirho}")),
        sign_in_url_chirho(&format!("{target_chirho}\n")),
        format!(
            "{page_url_chirho}&{}",
            redirect_query_chirho(&target_chirho)
        ),
        format!("{page_url_chirho}&redirect_chirho=%2F"),
        format!("{page_url_chirho}&extra_chirho=1"),
        format!(
            "{SIGN_IN_PATH_CHIRHO}?{}",
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("return_chirho", &target_chirho)
                .finish()
        ),
    ];
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        for url_chirho in &refused_chirho {
            for method_chirho in ["GET", "HEAD"] {
                let response_chirho =
                    http_request_for_smoke_chirho(addr_chirho, method_chirho, url_chirho, &[], b"");
                assert_eq!(
                    (
                        response_chirho.status_chirho,
                        location_chirho(&response_chirho)
                    ),
                    (303, LOGIN_PATH_CHIRHO.to_string()),
                    "{method_chirho} {url_chirho:?}"
                );
                assert_guarded_chirho(&response_chirho);
            }
        }
    });
    for open_chirho in [true, false] {
        with_connection_road_chirho(&root_chirho, open_chirho, |addr_chirho| {
            for method_chirho in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
                let response_chirho = http_request_for_smoke_chirho(
                    addr_chirho,
                    method_chirho,
                    &page_url_chirho,
                    &[("content-type", "application/x-www-form-urlencoded")],
                    b"",
                );
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
                assert_eq!(allowed_chirho, ["GET", "HEAD"], "{method_chirho}");
                assert!(response_chirho.body_chirho.is_empty(), "{method_chirho}");
                assert_guarded_chirho(&response_chirho);
            }
        });
    }
    with_connection_road_chirho(&root_chirho, false, |addr_chirho| {
        for method_chirho in ["GET", "HEAD"] {
            let response_chirho = http_request_for_smoke_chirho(
                addr_chirho,
                method_chirho,
                &page_url_chirho,
                &[],
                b"",
            );
            assert_eq!(response_chirho.status_chirho, 503, "{method_chirho}");
            assert_guarded_chirho(&response_chirho);
        }
        assert!(
            http_body_text_chirho(&get_chirho(addr_chirho, &page_url_chirho, None))
                .contains("id=\"connection-issuance-disabled-chirho\"")
        );
    });
}

/// EVERY OTHER SIGN-IN ANSWERS AS BEFORE. With the road open, a refused sign-in carrying no target, an ordinary page, a
/// foreign origin, a non-canonical encoding of the form's target, or that target with whitespace before it goes to the
/// canonical login page with its fixed token; an ordinary target still steers a success. With the road closed, even
/// the form's accepted target is not kept: the closed road's sign-in answers as it did before the sign-in page existed.
/// Three principals keep each one under its own failure limit (five), so every refusal here is a credential refusal.
#[test]
fn every_other_sign_in_answers_as_before_chirho() {
    let tenant_chirho =
        KeyedTenantChirho::new_chirho("u330-ordinary", OpeningsChirho::PAGE_CHIRHO, 3);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let target_chirho = app_target_chirho();
    let view_chirho = format!("/app-chirho/{KEYED_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}");
    let invalid_chirho = format!("{LOGIN_PATH_CHIRHO}#refusal-invalid-credential-chirho");
    let refused_with_chirho =
        |addr_chirho: &str, index_chirho: usize, target_chirho: Option<&str>| {
            let mut fields_chirho = vec![
                (
                    "principal_chirho",
                    tenant_chirho.user_chirho(index_chirho).0,
                ),
                ("credential_chirho", WRONG_SECRET_CHIRHO),
            ];
            if let Some(target_chirho) = target_chirho {
                fields_chirho.push(("redirect_chirho", target_chirho));
            }
            location_chirho(&sign_in_post_chirho(addr_chirho, &fields_chirho))
        };
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        assert_eq!(refused_with_chirho(addr_chirho, 0, None), invalid_chirho);
        for ordinary_chirho in [
            view_chirho.clone(),
            "https://evil.example/".to_string(),
            target_chirho.replace("%2F", "/"),
            format!(" {target_chirho}"),
        ] {
            assert_eq!(
                refused_with_chirho(addr_chirho, 0, Some(&ordinary_chirho)),
                invalid_chirho,
                "{ordinary_chirho:?}"
            );
        }
        let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(1);
        let steered_chirho = sign_in_post_chirho(
            addr_chirho,
            &[
                ("principal_chirho", principal_chirho),
                ("credential_chirho", secret_chirho),
                ("redirect_chirho", &view_chirho),
            ],
        );
        assert_eq!(
            (
                steered_chirho.status_chirho,
                location_chirho(&steered_chirho)
            ),
            (303, view_chirho.clone())
        );
    });
    with_connection_road_chirho(&root_chirho, false, |addr_chirho| {
        assert_eq!(
            refused_with_chirho(addr_chirho, 2, Some(&target_chirho)),
            invalid_chirho,
            "closed, the road keeps no target"
        );
    });
}
