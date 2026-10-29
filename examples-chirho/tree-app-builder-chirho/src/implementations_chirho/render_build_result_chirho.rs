// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render the "your app is live" result page from the blessed deploy door's receipt — the final pure
//! node of the app-builder dag. JS-free; every dynamic string (the live URL, the app name) is routed
//! through the kit's escaper, so the page is safe by construction whatever the deploy returned. Pure:
//! same receipt in, same page out, so its run is cached.
//! Part of the `view_build_chirho` dag.

use crate::types_chirho::deploy_response_v1_chirho::DeployResponseV1Chirho;
use cairn_node_templating_chirho::{
    card_chirho, escape_attr_chirho, escape_html_chirho, page_chirho, topbar_chirho,
    HtmlPartialV1Chirho, PageChirho,
};

/// in deploy_response: DeployResponseV1Chirho -> out page: HtmlPartialV1Chirho
pub fn render_build_result_chirho(response_chirho: &DeployResponseV1Chirho) -> HtmlPartialV1Chirho {
    let app_chirho = response_chirho.app_chirho.trim();
    let url_chirho = response_chirho.url_chirho.trim();

    // The live-link block: a real link when the door returned a URL, plain text otherwise (no broken
    // empty link). The href is attribute-escaped and the visible URL is HTML-escaped.
    let live_link_chirho = if url_chirho.is_empty() {
        "<p class=\"muted-chirho\">Your app has been deployed.</p>".to_string()
    } else {
        format!(
            "<p>Your app is live at <a href=\"{href_chirho}\">{shown_chirho}</a>.</p>",
            href_chirho = escape_attr_chirho(url_chirho),
            shown_chirho = escape_html_chirho(url_chirho),
        )
    };

    let app_line_chirho = if app_chirho.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"muted-chirho small-chirho\">App: {app_chirho}</p>",
            app_chirho = escape_html_chirho(app_chirho),
        )
    };

    let body_chirho = format!(
        "{topbar_chirho}<section class=\"container-chirho center-chirho stack-chirho\">{card_chirho}</section>",
        topbar_chirho = topbar_chirho("App builder", ""),
        card_chirho = card_chirho(&format!(
            "<h1>Your app is ready.</h1>{live_link_chirho}{app_line_chirho}\
<p class=\"muted-chirho small-chirho\">Heads up: submitting another description builds a brand-new \
app each time &mdash; there is no chosen address or re-edit yet, so keep this link to return to \
what you just built.</p>"
        )),
    );

    HtmlPartialV1Chirho::new_chirho(page_chirho(&PageChirho {
        title_chirho: "Your app is ready",
        body_html_chirho: &body_chirho,
        head_extra_chirho: "",
        htmx_chirho: false,
    }))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn sample_response_chirho() -> DeployResponseV1Chirho {
        DeployResponseV1Chirho {
            schema_chirho: "template-app-deploy-response-v1-chirho".to_string(),
            app_chirho: "riverbend-roasters".to_string(),
            url_chirho: "/app-chirho/riverbend-roasters/landing-chirho".to_string(),
            owner_principal_chirho: "owner/abc".to_string(),
            user_principal_chirho: "owner/abc".to_string(),
            template_id_chirho: "landing-v1-chirho".to_string(),
            display_slug_chirho: "riverbend-roasters".to_string(),
            params_chirho: "blake3-of-params".to_string(),
            deploy_record_seq_chirho: 1,
        }
    }

    #[test]
    fn shows_the_live_url_and_app_chirho() {
        let page_chirho = render_build_result_chirho(&sample_response_chirho());
        let html_chirho = &page_chirho.html_chirho;
        assert!(html_chirho.starts_with("<!doctype html>"));
        // It is a JS-free page (htmx not loaded).
        assert!(!html_chirho.contains("htmx"));
        // The live URL shows, as a link.
        assert!(html_chirho.contains("/app-chirho/riverbend-roasters/landing-chirho"));
        assert!(html_chirho.contains("href="));
        // The app name shows.
        assert!(html_chirho.contains("riverbend-roasters"));
        // Honest copy about fresh-app-per-submission.
        assert!(html_chirho.contains("brand-new"));
    }

    #[test]
    fn escapes_a_hostile_url_chirho() {
        // A deploy URL carrying markup must not break out of the link.
        let mut response_chirho = sample_response_chirho();
        response_chirho.url_chirho = "/x\"><script>alert(1)</script>".to_string();
        let page_chirho = render_build_result_chirho(&response_chirho);
        let html_chirho = &page_chirho.html_chirho;
        // The raw script tag must not appear unescaped.
        assert!(!html_chirho.contains("<script>alert(1)</script>"));
        // The escaped form does appear (in the visible text).
        assert!(html_chirho.contains("&lt;script&gt;"));
    }

    #[test]
    fn escapes_a_hostile_app_name_chirho() {
        let mut response_chirho = sample_response_chirho();
        response_chirho.app_chirho = "<b>evil</b>".to_string();
        let page_chirho = render_build_result_chirho(&response_chirho);
        assert!(!page_chirho.html_chirho.contains("<b>evil</b>"));
    }

    #[test]
    fn handles_an_empty_url_without_a_broken_link_chirho() {
        let mut response_chirho = sample_response_chirho();
        response_chirho.url_chirho = String::new();
        let page_chirho = render_build_result_chirho(&response_chirho);
        let html_chirho = &page_chirho.html_chirho;
        // No empty anchor; a plain "deployed" line instead.
        assert!(html_chirho.contains("has been deployed"));
        assert!(!html_chirho.contains("href=\"\""));
    }
}
