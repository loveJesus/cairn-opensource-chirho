// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16
//! Served arms for `POST /auth-chirho/credential-change-chirho` over a real local server: the
//! session names the principal; every refusal is a fixed token carried to the form's own page
//! (never a secret, never engine prose); on success the pre-change cookie no longer serves, the
//! old credential refuses at login, the new one signs in, and nothing else in the root moved.

use super::*;

const OLD_SECRET_CHIRHO: &str = "served-first-secret-value";
const NEW_SECRET_CHIRHO: &str = "served-second-secret-value";
const ACCOUNT_PAGE_CHIRHO: &str = "/app-chirho/perffection-workspace/account-chirho";

fn form_headers_chirho() -> [(&'static str, &'static str); 1] {
    [("content-type", "application/x-www-form-urlencoded")]
}

/// Log in through the served form and return the `cairn_session_chirho=…` cookie pair.
fn served_login_cookie_chirho(
    addr_chirho: &str,
    principal_chirho: &str,
    secret_chirho: &str,
) -> Option<String> {
    let body_chirho =
        format!("principal_chirho={principal_chirho}&credential_chirho={secret_chirho}");
    let response_chirho = http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/login-chirho",
        &form_headers_chirho(),
        body_chirho.as_bytes(),
    );
    if response_chirho.status_chirho != 303 {
        return None;
    }
    response_chirho
        .headers_chirho
        .get("set-cookie")
        .map(|cookie_chirho| cookie_chirho.split(';').next().unwrap().to_string())
}

fn change_chirho(
    addr_chirho: &str,
    cookie_chirho: Option<&str>,
    current_chirho: &str,
    new_chirho: &str,
    redirect_chirho: &str,
) -> HttpSmokeResponseChirho {
    let body_chirho = format!(
        "credential_chirho={current_chirho}&new_credential_chirho={new_chirho}&redirect_chirho={}",
        url::form_urlencoded::byte_serialize(redirect_chirho.as_bytes()).collect::<String>()
    );
    let mut headers_chirho: Vec<(&str, &str)> =
        vec![("content-type", "application/x-www-form-urlencoded")];
    if let Some(cookie_chirho) = cookie_chirho {
        headers_chirho.push(("cookie", cookie_chirho));
    }
    http_request_for_smoke_chirho(
        addr_chirho,
        "POST",
        "/auth-chirho/credential-change-chirho",
        &headers_chirho,
        body_chirho.as_bytes(),
    )
}

#[test]
fn served_credential_change_refuses_by_token_and_then_changes_her_credential_chirho() {
    let root_chirho = temp_root_chirho("served-credential-change");
    // An OWNER, not a User: this arm exercises the credential-change ROAD, which is identical for
    // any credentialed principal, and the serve crate cannot reach cairn-chirho's #[cfg(test)]
    // configured-User mint. When the cohort-1 User-registration ceiling law lands, a generic User
    // mint is refused; the change road is kind-agnostic, so an owner keeps this test faithful.
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        OLD_SECRET_CHIRHO,
    )
    .unwrap();
    let principal_chirho = user_chirho.principal_chirho.clone();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let needles_chirho = [OLD_SECRET_CHIRHO, NEW_SECRET_CHIRHO];

        // 1. No session: sent to the login page with the token; nothing read from the body.
        let no_session_chirho = change_chirho(
            &addr_chirho,
            None,
            OLD_SECRET_CHIRHO,
            NEW_SECRET_CHIRHO,
            ACCOUNT_PAGE_CHIRHO,
        );
        assert_eq!(no_session_chirho.status_chirho, 303);
        assert_eq!(
            no_session_chirho.headers_chirho.get("location").unwrap(),
            "/auth-chirho/login-chirho#refusal-no-session-chirho"
        );

        let cookie_chirho =
            served_login_cookie_chirho(&addr_chirho, &principal_chirho, OLD_SECRET_CHIRHO)
                .expect("the old credential signs in");
        let second_cookie_chirho =
            served_login_cookie_chirho(&addr_chirho, &principal_chirho, OLD_SECRET_CHIRHO)
                .expect("a second live session");
        let resets_before_chirho =
            identity_chirho::verify_credential_resets_chirho(&root_chirho).unwrap();

        // 2. Wrong current credential: back to her page with the token, 303, no secret anywhere.
        let mismatch_chirho = change_chirho(
            &addr_chirho,
            Some(&cookie_chirho),
            "served-not-the-secret",
            NEW_SECRET_CHIRHO,
            ACCOUNT_PAGE_CHIRHO,
        );
        assert_eq!(mismatch_chirho.status_chirho, 303);
        assert_eq!(
            mismatch_chirho.headers_chirho.get("location").unwrap(),
            &format!("{ACCOUNT_PAGE_CHIRHO}#refusal-credential-mismatch-chirho")
        );
        assert_no_contact_pii_chirho(
            "credential mismatch response",
            &mismatch_chirho.body_chirho,
            &needles_chirho,
        );
        assert!(
            !mismatch_chirho.headers_chirho.contains_key("set-cookie"),
            "a refusal leaves the session"
        );

        // 3. Too weak: the same shape with its own token; nothing written.
        let weak_chirho = change_chirho(
            &addr_chirho,
            Some(&cookie_chirho),
            OLD_SECRET_CHIRHO,
            "short",
            ACCOUNT_PAGE_CHIRHO,
        );
        assert_eq!(weak_chirho.status_chirho, 303);
        assert_eq!(
            weak_chirho.headers_chirho.get("location").unwrap(),
            &format!("{ACCOUNT_PAGE_CHIRHO}#refusal-credential-too-weak-chirho")
        );
        assert_eq!(
            identity_chirho::verify_credential_resets_chirho(&root_chirho).unwrap(),
            resets_before_chirho
        );

        // 4. A foreign redirect target is not followed: the token lands on "/".
        let foreign_chirho = change_chirho(
            &addr_chirho,
            Some(&cookie_chirho),
            "served-not-the-secret",
            NEW_SECRET_CHIRHO,
            "https://evil.example/steal",
        );
        assert_eq!(
            foreign_chirho.headers_chirho.get("location").unwrap(),
            "/#refusal-credential-mismatch-chirho"
        );

        // 5. Accepted: cookie cleared, sent to login; BOTH pre-change sessions are dead; the old
        //    credential refuses at the served login; the new one signs in.
        let accepted_chirho = change_chirho(
            &addr_chirho,
            Some(&cookie_chirho),
            OLD_SECRET_CHIRHO,
            NEW_SECRET_CHIRHO,
            ACCOUNT_PAGE_CHIRHO,
        );
        assert_eq!(accepted_chirho.status_chirho, 303);
        assert_eq!(
            accepted_chirho.headers_chirho.get("location").unwrap(),
            "/auth-chirho/login-chirho"
        );
        let clear_chirho = accepted_chirho
            .headers_chirho
            .get("set-cookie")
            .expect("the session cookie is cleared");
        assert!(
            clear_chirho.contains("cairn_session_chirho=;") && clear_chirho.contains("Max-Age=0")
        );
        assert_no_contact_pii_chirho(
            "credential change response",
            &accepted_chirho.body_chirho,
            &needles_chirho,
        );
        for dead_chirho in [&cookie_chirho, &second_cookie_chirho] {
            let (principal_in_cookie_chirho, token_chirho) = dead_chirho
                .trim_start_matches("cairn_session_chirho=")
                .split_once(':')
                .unwrap();
            assert_eq!(principal_in_cookie_chirho, principal_chirho);
            assert!(
                identity_chirho::validate_session_token_chirho(
                    &root_chirho,
                    &principal_chirho,
                    token_chirho
                )
                .unwrap()
                .is_none(),
                "every pre-change session is revoked"
            );
            // And the dead cookie cannot use this door again: it is a no-session refusal now.
            let again_chirho = change_chirho(
                &addr_chirho,
                Some(dead_chirho),
                NEW_SECRET_CHIRHO,
                OLD_SECRET_CHIRHO,
                ACCOUNT_PAGE_CHIRHO,
            );
            assert_eq!(
                again_chirho.headers_chirho.get("location").unwrap(),
                "/auth-chirho/login-chirho#refusal-no-session-chirho"
            );
        }
        assert!(
            served_login_cookie_chirho(&addr_chirho, &principal_chirho, OLD_SECRET_CHIRHO)
                .is_none(),
            "the old credential refuses at the served login"
        );
        assert!(
            served_login_cookie_chirho(&addr_chirho, &principal_chirho, NEW_SECRET_CHIRHO)
                .is_some(),
            "the new credential signs in"
        );
        assert_eq!(
            identity_chirho::verify_credential_resets_chirho(&root_chirho).unwrap(),
            resets_before_chirho + 1
        );
        let record_chirho = identity_chirho::load_credential_resets_chirho(&root_chirho)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(record_chirho.actor_chirho, principal_chirho);
        assert_eq!(record_chirho.revoked_session_count_chirho, 2);

        // 6. The JSON shape carries the token as error_chirho and no prose.
        let json_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/auth-chirho/credential-change-chirho",
            &[("content-type", "application/json")],
            br#"{"credential_chirho":"x","new_credential_chirho":"y"}"#,
        );
        assert_eq!(json_chirho.status_chirho, 401);
        assert_eq!(
            http_body_text_chirho(&json_chirho).trim(),
            r#"{"error_chirho":"no-session-chirho","ok_chirho":false}"#
        );

        server_chirho.abort();
    });
    // Nothing in the root ever held either secret in the clear.
    assert_path_tree_has_no_contact_pii_chirho(
        &root_chirho,
        "credential change root surfaces",
        &[OLD_SECRET_CHIRHO, NEW_SECRET_CHIRHO],
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// R1 return-path (PFE gpt #22471): the proof that spends the session's guess budget revokes the
/// session in the same act, so the browser's automatic GET of `redirect_chirho` (her Account page)
/// would meet a bare 403 — no page, no sentence, no way in. The exhausting POST must instead clear
/// the dead cookie and 303 to the PUBLIC login with the exhaustion token, exactly as the accepted
/// change does. Mismatches 1-4 are unchanged; the revoked cookie is a clean no-session redirect after.
#[test]
fn served_fifth_mismatch_clears_the_cookie_and_lands_on_login_not_a_dead_account_page_chirho() {
    let root_chirho = temp_root_chirho("served-credential-change-exhaustion");
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        OLD_SECRET_CHIRHO,
    )
    .unwrap();
    let principal_chirho = user_chirho.principal_chirho.clone();
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let needles_chirho = [OLD_SECRET_CHIRHO, NEW_SECRET_CHIRHO];

        let cookie_chirho =
            served_login_cookie_chirho(&addr_chirho, &principal_chirho, OLD_SECRET_CHIRHO)
                .expect("the credential signs in");

        // Mismatches 1-4: each is a plain mismatch back to her own page, session intact.
        for _ in 0..4 {
            let mismatch_chirho = change_chirho(
                &addr_chirho,
                Some(&cookie_chirho),
                "served-not-the-secret",
                NEW_SECRET_CHIRHO,
                ACCOUNT_PAGE_CHIRHO,
            );
            assert_eq!(mismatch_chirho.status_chirho, 303);
            assert_eq!(
                mismatch_chirho.headers_chirho.get("location").unwrap(),
                &format!("{ACCOUNT_PAGE_CHIRHO}#refusal-credential-mismatch-chirho")
            );
            assert!(
                !mismatch_chirho.headers_chirho.contains_key("set-cookie"),
                "a plain mismatch leaves the session"
            );
        }

        // The FIFTH proof spends the budget: clear the dead cookie and land on the PUBLIC login with
        // the exhaustion token, never back on the Account page her revoked session cannot open.
        let fifth_chirho = change_chirho(
            &addr_chirho,
            Some(&cookie_chirho),
            "served-not-the-secret",
            NEW_SECRET_CHIRHO,
            ACCOUNT_PAGE_CHIRHO,
        );
        assert_eq!(fifth_chirho.status_chirho, 303);
        assert_eq!(
            fifth_chirho.headers_chirho.get("location").unwrap(),
            "/auth-chirho/login-chirho#refusal-credential-guess-exhausted-chirho",
            "the exhausting proof lands on login, never the dead Account page"
        );
        let clear_chirho = fifth_chirho
            .headers_chirho
            .get("set-cookie")
            .expect("the dead session cookie is cleared");
        assert!(
            clear_chirho.contains("cairn_session_chirho=;") && clear_chirho.contains("Max-Age=0"),
            "the exhausting proof clears the cookie"
        );
        assert_no_contact_pii_chirho(
            "exhaustion response",
            &fifth_chirho.body_chirho,
            &needles_chirho,
        );

        // The session is dead: the same (revoked) cookie is now a clean no-session redirect to
        // login, not a stranded 403.
        let after_chirho = change_chirho(
            &addr_chirho,
            Some(&cookie_chirho),
            OLD_SECRET_CHIRHO,
            NEW_SECRET_CHIRHO,
            ACCOUNT_PAGE_CHIRHO,
        );
        assert_eq!(
            after_chirho.headers_chirho.get("location").unwrap(),
            "/auth-chirho/login-chirho#refusal-no-session-chirho",
            "the revoked cookie no longer opens the change door"
        );

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}
