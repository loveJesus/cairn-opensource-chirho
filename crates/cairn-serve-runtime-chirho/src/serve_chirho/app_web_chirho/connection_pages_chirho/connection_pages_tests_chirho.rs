// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The connection pages' fill (K4 Part 3): every template fills completely, holds no script, escapes what enters it,
//! never re-reads a value as a placeholder, and the one-time page holds the bearer exactly once. With a return path
//! (Account Create brick 1) the form carries it as a hidden field, and the one-time page as its one ordinary link. The
//! sign-in page (PFE unit 330) carries its target escaped, and each of its notices as a refusal.

use super::*;

const BEARER_CHIRHO: &str = "ck_live_bearer_for_the_page_arm_chirho";
const RETURN_CHIRHO: &str = "/app-chirho/connected/view";

fn actions_chirho() -> Vec<String> {
    vec![
        "page-read-chirho".to_string(),
        "page-save-chirho".to_string(),
    ]
}

/// EVERY PAGE FILLS COMPLETELY AND HOLDS NO SCRIPT: no placeholder is left in any page, and no template or the shared
/// style carries a script element, an event handler, or a reference to anything outside the page. With a return path,
/// the form carries it as its hidden field, and the one-time page holds exactly one link, that path; with it set aside,
/// that page holds no other reference.
#[test]
fn every_page_fills_completely_and_holds_no_script_chirho() {
    let actions_chirho = actions_chirho();
    let mut pages_chirho = vec![
        ConnectionFormPageChirho {
            client_id_chirho: "client/0123456789abcdef",
            app_chirho: "connected",
            actions_chirho: &actions_chirho,
            return_chirho: None,
        }
        .render_chirho()
        .unwrap(),
        ConnectionCreatedPageChirho {
            app_chirho: "connected",
            actions_chirho: &actions_chirho,
            bearer_chirho: BEARER_CHIRHO,
            return_chirho: None,
        }
        .render_chirho()
        .unwrap(),
        ConnectionFormPageChirho {
            client_id_chirho: "client/0123456789abcdef",
            app_chirho: "connected",
            actions_chirho: &actions_chirho,
            return_chirho: Some(RETURN_CHIRHO),
        }
        .render_chirho()
        .unwrap(),
    ];
    let linked_chirho = ConnectionCreatedPageChirho {
        app_chirho: "connected",
        actions_chirho: &actions_chirho,
        bearer_chirho: BEARER_CHIRHO,
        return_chirho: Some(RETURN_CHIRHO),
    }
    .render_chirho()
    .unwrap();
    assert!(pages_chirho[2].contains(&format!(
        "<input type=\"hidden\" name=\"return_chirho\" value=\"{RETURN_CHIRHO}\">"
    )));
    assert_eq!(
        linked_chirho.matches("href=").count(),
        1,
        "the one-time page's one link is its return"
    );
    assert!(linked_chirho.contains(&format!("<a href=\"{RETURN_CHIRHO}\">")));
    pages_chirho.push(linked_chirho.replacen(&format!("href=\"{RETURN_CHIRHO}\""), "", 1));
    for answer_chirho in [
        ConnectionAnswerPageChirho::DisabledChirho,
        ConnectionAnswerPageChirho::RequestInvalidChirho,
        ConnectionAnswerPageChirho::NotCreatedChirho,
        ConnectionAnswerPageChirho::UncertainChirho,
        ConnectionAnswerPageChirho::FailedChirho,
    ] {
        let page_chirho = answer_chirho.render_chirho();
        assert!(page_chirho.contains(&format!("id=\"{}\"", answer_chirho.token_chirho())));
        pages_chirho.push(page_chirho);
    }
    let sign_in_chirho = ConnectionSignInPageChirho {
        target_chirho: "/auth-chirho/connection-new-chirho?app_chirho=connected",
    }
    .render_chirho()
    .unwrap();
    for notice_chirho in [
        "refusal-no-session-chirho",
        "refusal-invalid-credential-chirho",
        "refusal-auth-rate-limited-chirho",
    ] {
        assert!(
            sign_in_chirho.contains(&format!("id=\"{notice_chirho}\" class=\"refusal\"")),
            "{notice_chirho}: the shared style shows a refusal only at its :target"
        );
    }
    pages_chirho.push(sign_in_chirho);
    for page_chirho in &pages_chirho {
        assert!(
            !page_chirho.contains("{{") && !page_chirho.contains("}}"),
            "{page_chirho}"
        );
        let lowered_chirho = page_chirho.to_ascii_lowercase();
        for forbidden_chirho in [
            "<script",
            "javascript:",
            " onload",
            " onclick",
            " onerror",
            "src=",
            "href=",
            "@import",
            "url(",
        ] {
            assert!(
                !lowered_chirho.contains(forbidden_chirho),
                "{forbidden_chirho} in {page_chirho}"
            );
        }
    }
}

/// THE ONE-TIME PAGE HOLDS THE BEARER EXACTLY ONCE, and the form and the answers never.
#[test]
fn the_bearer_is_on_the_one_time_page_exactly_once_chirho() {
    let actions_chirho = actions_chirho();
    for return_chirho in [None, Some(RETURN_CHIRHO)] {
        let created_chirho = ConnectionCreatedPageChirho {
            app_chirho: "connected",
            actions_chirho: &actions_chirho,
            bearer_chirho: BEARER_CHIRHO,
            return_chirho,
        }
        .render_chirho()
        .unwrap();
        assert_eq!(
            created_chirho.matches(BEARER_CHIRHO).count(),
            1,
            "{return_chirho:?}"
        );
        assert!(created_chirho.contains("page-read-chirho, page-save-chirho"));
    }
}

/// WHAT ENTERS IS ESCAPED, AND A VALUE IS NEVER READ AS A PLACEHOLDER: an app name, a client id, an action and a return
/// path carrying markup reach the page escaped, in the hidden field and in the link alike, and an app name spelling a
/// placeholder stays text.
#[test]
fn values_are_escaped_and_never_read_as_placeholders_chirho() {
    let hostile_chirho = "<b onmouseover=\"x\">{{bearer_chirho}}</b>&'";
    let actions_chirho = vec![hostile_chirho.to_string()];
    let form_chirho = ConnectionFormPageChirho {
        client_id_chirho: hostile_chirho,
        app_chirho: hostile_chirho,
        actions_chirho: &actions_chirho,
        return_chirho: Some(hostile_chirho),
    }
    .render_chirho()
    .unwrap();
    assert!(!form_chirho.contains("<b onmouseover"));
    assert!(form_chirho
        .contains("&lt;b onmouseover=&quot;x&quot;&gt;{{bearer_chirho}}&lt;/b&gt;&amp;&#39;"));
    let created_chirho = ConnectionCreatedPageChirho {
        app_chirho: hostile_chirho,
        actions_chirho: &actions_chirho,
        bearer_chirho: BEARER_CHIRHO,
        return_chirho: Some(hostile_chirho),
    }
    .render_chirho()
    .unwrap();
    assert_eq!(
        created_chirho.matches(BEARER_CHIRHO).count(),
        1,
        "a placeholder spelled inside a value is not filled"
    );
    let escaped_chirho = "&lt;b onmouseover=&quot;x&quot;&gt;{{bearer_chirho}}&lt;/b&gt;&amp;&#39;";
    assert!(!created_chirho.contains("<b onmouseover"));
    assert!(form_chirho.contains(&format!(
        "<input type=\"hidden\" name=\"return_chirho\" value=\"{escaped_chirho}\">"
    )));
    assert!(created_chirho.contains(&format!(
        "<a href=\"{escaped_chirho}\">Back to {escaped_chirho}</a>"
    )));
    let sign_in_chirho = ConnectionSignInPageChirho {
        target_chirho: hostile_chirho,
    }
    .render_chirho()
    .unwrap();
    assert!(!sign_in_chirho.contains("<b onmouseover"));
    assert!(sign_in_chirho.contains(&format!(
        "<input type=\"hidden\" name=\"redirect_chirho\" value=\"{escaped_chirho}\">"
    )));
}

/// THE FILL REFUSES WHAT IT CANNOT FILL, naming the placeholder and never a value.
#[test]
fn the_fill_refuses_an_unknown_or_unclosed_placeholder_chirho() {
    let unknown_chirho = fill_chirho(
        "a {{missing_chirho}} b",
        &[("present_chirho", "secret-value")],
    )
    .unwrap_err();
    assert!(format!("{unknown_chirho:#}").contains("missing_chirho"));
    assert!(!format!("{unknown_chirho:#}").contains("secret-value"));
    assert!(fill_chirho("a {{open", &[]).is_err());
    assert_eq!(
        fill_chirho("no placeholders", &[]).unwrap(),
        "no placeholders"
    );
}
