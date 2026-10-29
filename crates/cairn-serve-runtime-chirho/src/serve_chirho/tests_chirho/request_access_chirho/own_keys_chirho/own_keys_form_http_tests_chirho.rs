// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K3's served form revoke over a real local server: `POST /auth-chirho/key-revoke-chirho` from a no-script form answers
//! a 303 back to the form's page with a fragment the page reveals by `:target`, ends exactly her key, refuses every id
//! that is not hers with one answer, keeps a hostile redirect on this origin, and is never cached.
//! Workflow: the owner's keys page (K3),
//! `spec-chirho/workflows-chirho/identity-auth-chirho/own-keys-page-chirho.md`.

use super::*;
use std::path::Path;

const SECRET_CHIRHO: &str = "own-keys-form-secret";
const PAGE_CHIRHO: &str = "/app-chirho/accountapp/account";

fn cookie_chirho(root_chirho: &Path, principal_chirho: &str) -> String {
    let login_chirho =
        identity_chirho::login_identity_chirho(root_chirho, principal_chirho).unwrap();
    format!(
        "cairn_session_chirho={}:{}",
        login_chirho.session_chirho.principal_chirho, login_chirho.token_chirho
    )
}

/// A form body with the fields given, in order.
fn form_chirho(fields_chirho: &[(&str, &str)]) -> Vec<u8> {
    let mut serializer_chirho = url::form_urlencoded::Serializer::new(String::new());
    for (name_chirho, value_chirho) in fields_chirho {
        serializer_chirho.append_pair(name_chirho, value_chirho);
    }
    serializer_chirho.finish().into_bytes()
}

fn revoke_chirho(
    addr_chirho: &str,
    cookie_chirho: Option<&str>,
    body_chirho: &[u8],
) -> HttpSmokeResponseChirho {
    let mut headers_chirho: Vec<(&str, &str)> =
        vec![("content-type", "application/x-www-form-urlencoded")];
    if let Some(cookie_chirho) = cookie_chirho {
        headers_chirho.push(("cookie", cookie_chirho));
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/key-revoke-chirho",
        &headers_chirho,
        body_chirho,
    )
}

/// A form answer: a 303 to exactly `location_chirho`, never cached.
fn assert_see_other_chirho(
    response_chirho: &HttpSmokeResponseChirho,
    location_chirho: &str,
    what_chirho: &str,
) {
    assert_eq!(response_chirho.status_chirho, 303, "{what_chirho}");
    assert_eq!(
        response_chirho
            .headers_chirho
            .get("location")
            .map(String::as_str),
        Some(location_chirho),
        "{what_chirho}"
    );
    assert_eq!(
        response_chirho
            .headers_chirho
            .get("cache-control")
            .map(String::as_str),
        Some("private, no-store"),
        "{what_chirho}: never cached"
    );
}

/// THE FORM REVOKE. Alice ends her first key from a form: 303 to her page's `#notice-key-ended-chirho`, the key then
/// refuses while her second key and Bob's keep working, and a repeat answers the same. Bob naming her key, an unknown
/// id, a malformed id and an empty id all answer `#refusal-no-such-key-chirho` and end nothing. A form without a key
/// id answers `#refusal-request-invalid-chirho` on her page, an unreadable (oversized) body the same on `/`, and no
/// session the login page's `#refusal-no-session-chirho`. A redirect off this origin, or one with a backslash or a
/// control character, becomes `/`; a fragment the page carried is dropped. Other fields are ignored. A JSON caller
/// keeps today's JSON answer.
///
/// MIGRATION PATH: a different answer for Bob's id than for an unknown one is an existence oracle; a Location off
/// this origin is an open redirect; a revoked key still answering means the revoke missed its session.
#[test]
fn the_form_revoke_answers_by_fragment_and_ends_only_her_key_chirho() {
    let root_chirho = temp_root_chirho("own-keys-form-revoke");
    let register_chirho = || {
        identity_chirho::register_identity_with_credential_chirho(
            &root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            SECRET_CHIRHO,
        )
        .unwrap()
        .principal_chirho
    };
    let alice_chirho = register_chirho();
    let bob_chirho = register_chirho();
    let client_chirho =
        oauth_chirho::register_client_chirho(&root_chirho, "alpha", &alice_chirho).unwrap();
    let issue_chirho = |principal_chirho: &str| {
        oauth_chirho::issue_scoped_token_chirho(
            &root_chirho,
            principal_chirho,
            SECRET_CHIRHO,
            &client_chirho.client_id_chirho,
            vec!["invoke_chirho".to_string()],
        )
        .unwrap()
    };
    let alices_chirho = [issue_chirho(&alice_chirho), issue_chirho(&alice_chirho)];
    let bobs_chirho = issue_chirho(&bob_chirho);
    let alice_cookie_chirho = cookie_chirho(&root_chirho, &alice_chirho);
    let bob_cookie_chirho = cookie_chirho(&root_chirho, &bob_chirho);
    let key_id_chirho = |issue_chirho: &oauth_chirho::ScopedTokenIssueChirho| {
        oauth_chirho::scoped_key_id_chirho(&issue_chirho.record_chirho.token_hash_chirho)
    };
    let works_chirho = |issue_chirho: &oauth_chirho::ScopedTokenIssueChirho| {
        oauth_chirho::validate_scoped_token_for_app_chirho(
            &root_chirho,
            "alpha",
            &issue_chirho.token_chirho,
        )
        .unwrap()
        .is_some()
    };
    let notice_chirho = format!("{PAGE_CHIRHO}#notice-key-ended-chirho");
    let no_such_chirho = format!("{PAGE_CHIRHO}#refusal-no-such-key-chirho");
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let alice_form_chirho = |fields_chirho: &[(&str, &str)]| {
            revoke_chirho(
                &addr_chirho,
                Some(&alice_cookie_chirho),
                &form_chirho(fields_chirho),
            )
        };

        // Not hers: one answer for Bob's naming of her key, an unknown, a malformed and an empty id; nothing ends.
        let alices_second_chirho = key_id_chirho(&alices_chirho[1]);
        let unknown_chirho = "0".repeat(32);
        for (what_chirho, id_chirho) in [
            ("her key, named by bob", alices_second_chirho.as_str()),
            ("an unknown id", unknown_chirho.as_str()),
            ("a malformed id", "zz"),
            ("an empty id", ""),
        ] {
            let response_chirho = revoke_chirho(
                &addr_chirho,
                Some(&bob_cookie_chirho),
                &form_chirho(&[
                    ("key_id_chirho", id_chirho),
                    ("redirect_chirho", PAGE_CHIRHO),
                ]),
            );
            assert_see_other_chirho(&response_chirho, &no_such_chirho, what_chirho);
        }
        assert!(
            alices_chirho.iter().all(&works_chirho) && works_chirho(&bobs_chirho),
            "no refused form ended a key"
        );

        // Hers: it ends exactly her key, and a repeat answers the same.
        let first_id_chirho = key_id_chirho(&alices_chirho[0]);
        for what_chirho in ["the revoke", "a repeat"] {
            let response_chirho = alice_form_chirho(&[
                ("key_id_chirho", first_id_chirho.as_str()),
                ("redirect_chirho", PAGE_CHIRHO),
            ]);
            assert_see_other_chirho(&response_chirho, &notice_chirho, what_chirho);
            assert!(response_chirho.body_chirho.is_empty(), "{what_chirho}");
        }
        assert!(!works_chirho(&alices_chirho[0]), "the revoked key refuses");
        assert!(
            works_chirho(&alices_chirho[1]) && works_chirho(&bobs_chirho),
            "and no other key"
        );

        // A form without a key id, an unreadable body, and no session.
        assert_see_other_chirho(
            &alice_form_chirho(&[("redirect_chirho", PAGE_CHIRHO)]),
            &format!("{PAGE_CHIRHO}#refusal-request-invalid-chirho"),
            "no key id",
        );
        let oversized_chirho = form_chirho(&[
            ("key_id_chirho", first_id_chirho.as_str()),
            ("redirect_chirho", PAGE_CHIRHO),
            ("padding_chirho", &"x".repeat(17 * 1024)),
        ]);
        assert_see_other_chirho(
            &revoke_chirho(&addr_chirho, Some(&alice_cookie_chirho), &oversized_chirho),
            "/#refusal-request-invalid-chirho",
            "an unreadable body",
        );
        assert_see_other_chirho(
            &revoke_chirho(
                &addr_chirho,
                None,
                &form_chirho(&[
                    ("key_id_chirho", alices_second_chirho.as_str()),
                    ("redirect_chirho", PAGE_CHIRHO),
                ]),
            ),
            "/auth-chirho/login-chirho#refusal-no-session-chirho",
            "no session",
        );
        assert!(
            works_chirho(&alices_chirho[1]),
            "a sessionless form ended nothing"
        );

        // The redirect stays on this origin; a carried fragment is dropped; no redirect at all is `/`.
        for (redirect_chirho, location_chirho) in [
            ("//evil.example/x", "/#refusal-no-such-key-chirho"),
            ("https://evil.example/x", "/#refusal-no-such-key-chirho"),
            ("/a\\b", "/#refusal-no-such-key-chirho"),
            ("/a\u{7}b", "/#refusal-no-such-key-chirho"),
            ("javascript:alert(1)", "/#refusal-no-such-key-chirho"),
            (
                "/ok?x=1#her-own-fragment",
                "/ok?x=1#refusal-no-such-key-chirho",
            ),
        ] {
            assert_see_other_chirho(
                &alice_form_chirho(&[
                    ("key_id_chirho", unknown_chirho.as_str()),
                    ("redirect_chirho", redirect_chirho),
                ]),
                location_chirho,
                redirect_chirho,
            );
        }
        assert_see_other_chirho(
            &alice_form_chirho(&[("key_id_chirho", unknown_chirho.as_str())]),
            "/#refusal-no-such-key-chirho",
            "no redirect",
        );

        // A JSON caller keeps today's answer: the form road did not take it.
        let json_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/key-revoke-chirho",
            &[
                ("content-type", "application/json"),
                ("cookie", &bob_cookie_chirho),
            ],
            serde_json::json!({ "key_id_chirho": unknown_chirho })
                .to_string()
                .as_bytes(),
        );
        assert_eq!(json_chirho.status_chirho, 404);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&http_body_text_chirho(&json_chirho))
                .unwrap(),
            serde_json::json!({ "ok_chirho": false, "error_chirho": "no-such-key-chirho" })
        );

        // Other fields are ignored: her second key ends from a form that carries one more.
        assert_see_other_chirho(
            &alice_form_chirho(&[
                ("key_id_chirho", alices_second_chirho.as_str()),
                ("redirect_chirho", "/elsewhere-chirho"),
                ("unrelated_chirho", "1"),
            ]),
            "/elsewhere-chirho#notice-key-ended-chirho",
            "other fields ignored",
        );
        assert!(!works_chirho(&alices_chirho[1]) && works_chirho(&bobs_chirho));
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A log the revoke cannot read answers `#refusal-keys-failed-chirho`, not `no-such-key`: a failure is never read as
/// "that is not your key".
///
/// MIGRATION PATH: `no-such-key` here would tell her a key she can see in her list is not hers.
#[test]
fn the_form_revoke_says_keys_failed_when_her_keys_cannot_be_read_chirho() {
    let root_chirho = temp_root_chirho("own-keys-form-keys-failed");
    let alice_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let client_chirho =
        oauth_chirho::register_client_chirho(&root_chirho, "alpha", &alice_chirho).unwrap();
    let issue_chirho = oauth_chirho::issue_scoped_token_chirho(
        &root_chirho,
        &alice_chirho,
        SECRET_CHIRHO,
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let alice_cookie_chirho = cookie_chirho(&root_chirho, &alice_chirho);
    // Her key's signed record no longer matches its signature.
    let log_chirho = root_chirho.join("scoped-tokens-chirho.jsonl");
    let text_chirho = std::fs::read_to_string(&log_chirho).unwrap();
    let mut lines_chirho: Vec<String> = text_chirho.lines().map(str::to_string).collect();
    let mut last_chirho: serde_json::Value =
        serde_json::from_str(lines_chirho.last().unwrap()).unwrap();
    last_chirho["scopes_chirho"] = serde_json::json!(["invoke_chirho", "admin_chirho"]);
    *lines_chirho.last_mut().unwrap() = last_chirho.to_string();
    std::fs::write(&log_chirho, format!("{}\n", lines_chirho.join("\n"))).unwrap();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let response_chirho = revoke_chirho(
            &addr_chirho,
            Some(&alice_cookie_chirho),
            &form_chirho(&[
                (
                    "key_id_chirho",
                    &oauth_chirho::scoped_key_id_chirho(
                        &issue_chirho.record_chirho.token_hash_chirho,
                    ),
                ),
                ("redirect_chirho", PAGE_CHIRHO),
            ]),
        );
        assert_see_other_chirho(
            &response_chirho,
            &format!("{PAGE_CHIRHO}#refusal-keys-failed-chirho"),
            "a log that cannot be read",
        );
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}
