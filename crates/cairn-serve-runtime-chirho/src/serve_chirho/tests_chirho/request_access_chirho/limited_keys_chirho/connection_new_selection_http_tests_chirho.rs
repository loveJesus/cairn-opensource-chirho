// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Account Create brick 1 over a real local server, through the configured road `up` composes (PFE #26824, #26837):
//! selection by app through the sign-in page to the form, the one-time page's link back, wrong, missing, malformed and
//! ambiguous apps, hostile return paths at the GET and at the POST before anything is appended, and a refused POST that
//! keeps its return path. Raw HTTP, not a browser; the JavaScript-disabled browser run is separate.
//! Workflow: `spec-chirho/workflows-chirho/identity-auth-chirho/connection-keys-k4-design-chirho.md` (Account Create
//! brick 1).

use super::connection_new_http_tests_chirho::{
    assert_guarded_chirho, attempt_rows_chirho, cookie_value_chirho, get_chirho, lines_chirho,
    location_chirho, post_form_chirho, with_connection_road_chirho, CONNECTION_NEW_PATH_CHIRHO,
};
use super::limited_key_fixture_chirho::*;
use super::*;
use std::path::Path;

const LOGIN_PATH_CHIRHO: &str = "/auth-chirho/login-chirho";
const SIGN_IN_PATH_CHIRHO: &str = "/auth-chirho/connection-sign-in-chirho";

/// The form's canonical target for an app, and its return path when there is one, as the road builds it.
fn app_target_chirho(app_chirho: &str, return_chirho: Option<&str>) -> String {
    let mut query_chirho = url::form_urlencoded::Serializer::new(String::new());
    query_chirho.append_pair("app_chirho", app_chirho);
    if let Some(return_chirho) = return_chirho {
        query_chirho.append_pair("return_chirho", return_chirho);
    }
    format!("{CONNECTION_NEW_PATH_CHIRHO}?{}", query_chirho.finish())
}

/// The form's canonical target for a client id, and its return path when there is one.
fn client_target_chirho(client_id_chirho: &str, return_chirho: Option<&str>) -> String {
    let mut query_chirho = url::form_urlencoded::Serializer::new(String::new());
    query_chirho.append_pair("client_id_chirho", client_id_chirho);
    if let Some(return_chirho) = return_chirho {
        query_chirho.append_pair("return_chirho", return_chirho);
    }
    format!("{CONNECTION_NEW_PATH_CHIRHO}?{}", query_chirho.finish())
}

/// A POST body: the client id, one action, the credential, and a return path when there is one.
fn body_chirho(
    client_id_chirho: &str,
    credential_chirho: &str,
    return_chirho: Option<&str>,
) -> String {
    let mut body_chirho = url::form_urlencoded::Serializer::new(String::new());
    body_chirho
        .append_pair("client_id_chirho", client_id_chirho)
        .append_pair("action_chirho", PAGE_READ_CHIRHO)
        .append_pair("credential_chirho", credential_chirho);
    if let Some(return_chirho) = return_chirho {
        body_chirho.append_pair("return_chirho", return_chirho);
    }
    body_chirho.finish()
}

fn request_invalid_page_chirho(response_chirho: &HttpSmokeResponseChirho) -> bool {
    response_chirho.status_chirho == 400
        && http_body_text_chirho(response_chirho).contains("id=\"request-invalid-chirho\"")
}

/// What the road has appended: attempt rows, connection keys and sessions.
fn written_chirho(root_chirho: &Path) -> (usize, usize, usize) {
    (
        attempt_rows_chirho(root_chirho).len(),
        lines_chirho(root_chirho, "connection-tokens-chirho.jsonl"),
        lines_chirho(root_chirho, "identity-sessions-chirho.jsonl"),
    )
}

fn view_return_chirho() -> String {
    format!("/app-chirho/{KEYED_APP_CHIRHO}/{VIEW_ROUTE_CHIRHO}")
}

/// AN APP SELECTION GOES THROUGH THE SIGN-IN PAGE TO THE FORM, AND THE ONE-TIME PAGE LINKS BACK: signed out, the app's
/// canonical target, return path included, goes to the road's sign-in page (PFE unit 330), which carries it as its
/// hidden field; the login's own POST returns to it; the form names the app's one connection client and carries the
/// return path; the creation's
/// one-time page shows the key once and an ordinary link to the return path. Following that link is a GET of the app's
/// route: it shows no key, and creates nothing.
#[test]
fn an_app_selection_goes_through_login_and_links_back_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("b1-journey", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let (principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let return_chirho = view_return_chirho();
    let target_chirho = app_target_chirho(KEYED_APP_CHIRHO, Some(&return_chirho));
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let signed_out_chirho = get_chirho(addr_chirho, &target_chirho, None);
        assert_eq!(signed_out_chirho.status_chirho, 303);
        assert_guarded_chirho(&signed_out_chirho);
        let sign_in_url_chirho = location_chirho(&signed_out_chirho);
        assert_eq!(
            sign_in_url_chirho,
            format!(
                "{SIGN_IN_PATH_CHIRHO}?{}#refusal-no-session-chirho",
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("redirect_chirho", &target_chirho)
                    .finish()
            )
        );
        let sign_in_page_chirho = http_body_text_chirho(&get_chirho(
            addr_chirho,
            sign_in_url_chirho.split('#').next().unwrap(),
            None,
        ));
        assert!(
            sign_in_page_chirho.contains(&format!(
                "<input type=\"hidden\" name=\"redirect_chirho\" value=\"{}\">",
                target_chirho.replace('&', "&amp;")
            )),
            "{sign_in_page_chirho}"
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
        assert_guarded_chirho(&form_chirho);
        let form_page_chirho = http_body_text_chirho(&form_chirho);
        assert!(form_page_chirho.contains(&format!(
            "<input type=\"hidden\" name=\"client_id_chirho\" value=\"{}\">",
            tenant_chirho.client_id_chirho
        )));
        assert!(form_page_chirho.contains(&format!(
            "<input type=\"hidden\" name=\"return_chirho\" value=\"{return_chirho}\">"
        )));

        let created_chirho = post_form_chirho(
            addr_chirho,
            Some(&cookie_chirho),
            &body_chirho(
                &tenant_chirho.client_id_chirho,
                secret_chirho,
                Some(&return_chirho),
            ),
        );
        assert_eq!(created_chirho.status_chirho, 200);
        assert_guarded_chirho(&created_chirho);
        let created_page_chirho = http_body_text_chirho(&created_chirho);
        let start_chirho = created_page_chirho.find("<code>").expect("the key") + "<code>".len();
        let bearer_chirho = &created_page_chirho[start_chirho
            ..start_chirho + created_page_chirho[start_chirho..].find("</code>").unwrap()];
        assert_eq!(created_page_chirho.matches(bearer_chirho).count(), 1);
        assert_eq!(created_page_chirho.matches("href=").count(), 1);
        assert!(created_page_chirho.contains(&format!("<a href=\"{return_chirho}\">")));

        let followed_chirho = get_chirho(addr_chirho, &return_chirho, Some(&cookie_chirho));
        assert!(!http_body_text_chirho(&followed_chirho).contains(bearer_chirho));
        assert_eq!(
            oauth_chirho::list_own_keys_chirho(&root_chirho, principal_chirho)
                .unwrap()
                .iter()
                .filter(|row_chirho| row_chirho.live_chirho)
                .count(),
            1,
            "following the link created nothing"
        );
    });
}

/// A WRONG, MISSING, MALFORMED OR AMBIGUOUS APP ANSWERS REQUEST-INVALID: signed in, an app nobody deployed, an empty or
/// malformed name, two selectors, a repeated or an unknown field each answer the request-invalid page; signed out, they
/// go to the login page with no target. The app's one client is the control; a second connection client for the same
/// app makes it ambiguous, never the first or the latest, while the explicit client id still reaches its form.
#[test]
fn a_wrong_missing_malformed_or_ambiguous_app_answers_request_invalid_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("b1-invalid", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let client_chirho = client_target_chirho(&tenant_chirho.client_id_chirho, None);
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let app_chirho = app_target_chirho(KEYED_APP_CHIRHO, None);
        assert_eq!(
            get_chirho(addr_chirho, &app_chirho, Some(&cookie_chirho)).status_chirho,
            200
        );
        for invalid_chirho in [
            app_target_chirho("nosuchapp", None),
            format!("{CONNECTION_NEW_PATH_CHIRHO}?app_chirho="),
            app_target_chirho("keyed/app", None),
            format!(
                "{app_chirho}&client_id_chirho={}",
                tenant_chirho.client_id_chirho.replace('/', "%2F")
            ),
            format!("{app_chirho}&app_chirho={KEYED_APP_CHIRHO}"),
            format!("{app_chirho}&other_chirho=1"),
        ] {
            let answer_chirho = get_chirho(addr_chirho, &invalid_chirho, Some(&cookie_chirho));
            assert!(
                request_invalid_page_chirho(&answer_chirho),
                "{invalid_chirho}"
            );
            assert_guarded_chirho(&answer_chirho);
        }
        let signed_out_chirho =
            get_chirho(addr_chirho, &format!("{app_chirho}&other_chirho=1"), None);
        assert_eq!(
            location_chirho(&signed_out_chirho),
            format!("{LOGIN_PATH_CHIRHO}#refusal-no-session-chirho")
        );

        oauth_chirho::register_client_chirho(
            &root_chirho,
            KEYED_APP_CHIRHO,
            &tenant_chirho.owner_chirho,
        )
        .unwrap();
        assert!(
            request_invalid_page_chirho(&get_chirho(
                addr_chirho,
                &app_chirho,
                Some(&cookie_chirho)
            )),
            "two connection clients for the app: ambiguous"
        );
        assert_eq!(
            get_chirho(addr_chirho, &client_chirho, Some(&cookie_chirho)).status_chirho,
            200,
            "the explicit client id still reaches its form"
        );
    });
}

/// HOSTILE RETURN PATHS REFUSE AT THE GET AND AT THE POST, BEFORE ANYTHING IS APPENDED (PFE #26837): another app's
/// route, a dot segment, a value the shared redirect check would trim, a query, a fragment, an encoded slash or dot, a
/// backslash or another origin, written plainly or query-encoded. Signed in, each GET answers request-invalid; signed
/// out, it goes to the login page with no target. Each POST answers a refusal back to the client's form without the
/// return, and appends no attempt row, key or session. The good return is the control at both.
#[test]
fn hostile_returns_refuse_at_get_and_post_before_any_append_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("b1-hostile", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let (_principal_chirho, secret_chirho) = tenant_chirho.user_chirho(0);
    let client_id_chirho = tenant_chirho.client_id_chirho.clone();
    let good_chirho = view_return_chirho();
    let other_app_chirho = format!("/app-chirho/other-app/{VIEW_ROUTE_CHIRHO}");
    let hostile_chirho = [
        other_app_chirho.clone(),
        format!("/app-chirho/{KEYED_APP_CHIRHO}/.."),
        format!("/app-chirho/{KEYED_APP_CHIRHO}/."),
        format!("/app-chirho/../{VIEW_ROUTE_CHIRHO}"),
        format!(" {good_chirho}"),
        format!("{good_chirho} "),
        format!("{good_chirho}?x=1"),
        format!("{good_chirho}#top"),
        format!("/app-chirho/{KEYED_APP_CHIRHO}/%2E%2E"),
        format!("/app-chirho/{KEYED_APP_CHIRHO}/vi%2Few"),
        format!("/app-chirho/{KEYED_APP_CHIRHO}/vi\\ew"),
        format!("//evil.example{good_chirho}"),
        format!("https://evil.example{good_chirho}"),
        format!("{good_chirho}/"),
    ];
    // The same refusals arriving query-encoded: decoded once, then refused as they arrived.
    let encoded_chirho = [
        format!("app_chirho={KEYED_APP_CHIRHO}&return_chirho=%2Fapp-chirho%2F{KEYED_APP_CHIRHO}%2F%2E%2E"),
        format!("app_chirho={KEYED_APP_CHIRHO}&return_chirho=%20%2Fapp-chirho%2F{KEYED_APP_CHIRHO}%2Fview"),
        format!("app_chirho={KEYED_APP_CHIRHO}&return_chirho=%2Fapp-chirho%2F{KEYED_APP_CHIRHO}%2Fview%3Fx%3D1"),
    ];
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let good_form_chirho = get_chirho(
            addr_chirho,
            &app_target_chirho(KEYED_APP_CHIRHO, Some(&good_chirho)),
            Some(&cookie_chirho),
        );
        assert_eq!(good_form_chirho.status_chirho, 200, "the GET's control");
        for return_chirho in &hostile_chirho {
            for target_chirho in [
                app_target_chirho(KEYED_APP_CHIRHO, Some(return_chirho)),
                client_target_chirho(&client_id_chirho, Some(return_chirho)),
            ] {
                let answer_chirho = get_chirho(addr_chirho, &target_chirho, Some(&cookie_chirho));
                assert!(
                    request_invalid_page_chirho(&answer_chirho),
                    "{target_chirho}"
                );
                if return_chirho != &other_app_chirho || target_chirho.contains("app_chirho=") {
                    assert_eq!(
                        location_chirho(&get_chirho(addr_chirho, &target_chirho, None)),
                        format!("{LOGIN_PATH_CHIRHO}#refusal-no-session-chirho"),
                        "signed out, no target: {target_chirho}"
                    );
                }
            }
        }
        for raw_chirho in &encoded_chirho {
            let target_chirho = format!("{CONNECTION_NEW_PATH_CHIRHO}?{raw_chirho}");
            assert!(
                request_invalid_page_chirho(&get_chirho(
                    addr_chirho,
                    &target_chirho,
                    Some(&cookie_chirho)
                )),
                "{target_chirho}"
            );
        }

        let before_chirho = written_chirho(&root_chirho);
        let refused_target_chirho = format!(
            "{}#refusal-request-invalid-chirho",
            client_target_chirho(&client_id_chirho, None)
        );
        for return_chirho in &hostile_chirho {
            let refused_chirho = post_form_chirho(
                addr_chirho,
                Some(&cookie_chirho),
                &body_chirho(&client_id_chirho, secret_chirho, Some(return_chirho)),
            );
            assert_eq!(
                (
                    refused_chirho.status_chirho,
                    location_chirho(&refused_chirho)
                ),
                (303, refused_target_chirho.clone()),
                "{return_chirho:?}"
            );
            assert_guarded_chirho(&refused_chirho);
        }
        for raw_chirho in [
            format!("client_id_chirho={}&action_chirho={PAGE_READ_CHIRHO}&credential_chirho={secret_chirho}&return_chirho=%2Fapp-chirho%2F{KEYED_APP_CHIRHO}%2F%2E%2E", client_id_chirho.replace('/', "%2F")),
            format!("client_id_chirho={}&action_chirho={PAGE_READ_CHIRHO}&credential_chirho={secret_chirho}&return_chirho=+%2Fapp-chirho%2F{KEYED_APP_CHIRHO}%2Fview", client_id_chirho.replace('/', "%2F")),
        ] {
            let refused_chirho = post_form_chirho(addr_chirho, Some(&cookie_chirho), &raw_chirho);
            assert_eq!(
                (refused_chirho.status_chirho, location_chirho(&refused_chirho)),
                (303, refused_target_chirho.clone()),
                "{raw_chirho}"
            );
        }
        assert_eq!(
            written_chirho(&root_chirho),
            before_chirho,
            "no hostile return appends an attempt row, a key or a session"
        );
        let created_chirho = post_form_chirho(
            addr_chirho,
            Some(&cookie_chirho),
            &body_chirho(&client_id_chirho, secret_chirho, Some(&good_chirho)),
        );
        assert_eq!(created_chirho.status_chirho, 200, "the POST's control");
        let (attempts_chirho, keys_chirho, sessions_chirho) = written_chirho(&root_chirho);
        assert_eq!(
            (attempts_chirho, keys_chirho, sessions_chirho),
            (
                before_chirho.0 + 1,
                before_chirho.1 + 1,
                before_chirho.2 + 1
            )
        );
    });
}

/// A REFUSED POST KEEPS ITS RETURN PATH: a wrong password answers the credential refusal back to the client's form with
/// the return path kept, and that form carries it again.
#[test]
fn a_refused_post_keeps_its_return_chirho() {
    let tenant_chirho = KeyedTenantChirho::new_chirho("b1-keep", OpeningsChirho::PAGE_CHIRHO, 1);
    let root_chirho = tenant_chirho.root_chirho.clone();
    let cookie_chirho = cookie_value_chirho(&tenant_chirho, 0);
    let client_id_chirho = tenant_chirho.client_id_chirho.clone();
    let return_chirho = view_return_chirho();
    with_connection_road_chirho(&root_chirho, true, |addr_chirho| {
        let refused_chirho = post_form_chirho(
            addr_chirho,
            Some(&cookie_chirho),
            &body_chirho(
                &client_id_chirho,
                "not-the-password-chirho",
                Some(&return_chirho),
            ),
        );
        let target_chirho = client_target_chirho(&client_id_chirho, Some(&return_chirho));
        assert_eq!(
            (
                refused_chirho.status_chirho,
                location_chirho(&refused_chirho)
            ),
            (
                303,
                format!("{target_chirho}#refusal-credential-mismatch-chirho")
            )
        );
        let form_chirho = get_chirho(addr_chirho, &target_chirho, Some(&cookie_chirho));
        assert_eq!(form_chirho.status_chirho, 200);
        assert!(http_body_text_chirho(&form_chirho).contains(&format!(
            "<input type=\"hidden\" name=\"return_chirho\" value=\"{return_chirho}\">"
        )));
    });
}
