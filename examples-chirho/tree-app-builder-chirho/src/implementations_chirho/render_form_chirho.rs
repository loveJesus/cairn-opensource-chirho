// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render the JS-free "describe your app" landing form — the pure root node of the form dag. It is a
//! static page (a heading, a helper line, and a single textarea + submit) that POSTs the typed
//! business description to the build route; it ignores the request content (the form is the same for
//! everyone) but takes the http request per the surface convention. JS-free: no `<script>`, htmx not
//! loaded. Pure: same input in, same page out, so its run is cached.
//! Part of the `view_form_chirho` dag.

use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;
use cairn_node_templating_chirho::{
    button_chirho, card_chirho, escape_attr_chirho, page_chirho, topbar_chirho,
    HtmlPartialV1Chirho, PageChirho,
};

/// Where the form POSTs: the named build route the app manifest exposes for the build dag. Stated
/// once (DRY) so the action and the manifest route stay in lock-step.
pub const BUILD_ROUTE_ACTION_CHIRHO: &str = "/app-chirho/tree-app-builder/build-chirho";

/// The form control name the typed description is submitted under. A later serve step must map the
/// POST body to `http_request_v1.description_chirho`, so the name is stated once here.
pub const DESCRIPTION_FIELD_NAME_CHIRHO: &str = "description_chirho";

/// The placeholder shown in the empty description box — a plain hint, not pinned prose.
const DESCRIPTION_PLACEHOLDER_CHIRHO: &str =
    "e.g. A small-batch coffee roaster on Main Street with a cozy cafe and weekly single-origin beans.";

/// How many rows tall the description box renders.
const DESCRIPTION_ROWS_CHIRHO: u32 = 6;

/// in request: HttpRequestV1Chirho (ignored; static form) -> out page: HtmlPartialV1Chirho
pub fn render_form_chirho(_request_chirho: &HttpRequestV1Chirho) -> HtmlPartialV1Chirho {
    // A static form. The action/method and the field name are fixed safe ASCII constants; the only
    // free text (the placeholder) is attribute-escaped, exactly like the result render node escapes
    // every dynamic string it emits.
    let form_chirho = format!(
        "<form method=\"post\" action=\"{action_chirho}\" class=\"stack-chirho\">\
<label class=\"field-chirho\"><span class=\"label-chirho\">Your business description</span>\
<textarea class=\"input-chirho\" name=\"{field_chirho}\" rows=\"{rows_chirho}\" \
placeholder=\"{placeholder_chirho}\" required></textarea></label>{submit_chirho}</form>",
        action_chirho = escape_attr_chirho(BUILD_ROUTE_ACTION_CHIRHO),
        field_chirho = escape_attr_chirho(DESCRIPTION_FIELD_NAME_CHIRHO),
        rows_chirho = DESCRIPTION_ROWS_CHIRHO,
        placeholder_chirho = escape_attr_chirho(DESCRIPTION_PLACEHOLDER_CHIRHO),
        submit_chirho = button_chirho("Build my app", true),
    );

    let body_chirho = format!(
        "{topbar_chirho}<section class=\"container-chirho center-chirho stack-chirho\">{card_chirho}</section>",
        topbar_chirho = topbar_chirho("App builder", ""),
        card_chirho = card_chirho(&format!(
            "<h1>Describe your app.</h1>\
<p class=\"muted-chirho\">Tell us about your business in a sentence or two and we will build you a \
landing page. Submit to start the build.</p>{form_chirho}"
        )),
    );

    HtmlPartialV1Chirho::new_chirho(page_chirho(&PageChirho {
        title_chirho: "Describe your app",
        body_html_chirho: &body_chirho,
        head_extra_chirho: "",
        htmx_chirho: false,
    }))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn sample_request_chirho() -> HttpRequestV1Chirho {
        HttpRequestV1Chirho {
            path_chirho: "/".to_string(),
            user_principal_chirho: Some("owner/abc".to_string()),
            description_chirho: String::new(),
        }
    }

    #[test]
    fn renders_a_js_free_post_form_to_the_build_route_chirho() {
        let page_chirho = render_form_chirho(&sample_request_chirho());
        let html_chirho = &page_chirho.html_chirho;
        assert!(html_chirho.starts_with("<!doctype html>"));
        // The form POSTs to the build route.
        assert!(html_chirho.contains("method=\"post\""));
        assert!(html_chirho.contains("action=\"/app-chirho/tree-app-builder/build-chirho\""));
        // A description textarea, named so a later serve step can map it to description_chirho.
        assert!(html_chirho.contains("<textarea"));
        assert!(html_chirho.contains("name=\"description_chirho\""));
        // A submit button to start the build.
        assert!(html_chirho.contains("type=\"submit\""));
        assert!(html_chirho.contains("Build my app"));
    }

    #[test]
    fn the_page_is_js_free_chirho() {
        let page_chirho = render_form_chirho(&sample_request_chirho());
        let html_chirho = &page_chirho.html_chirho;
        // No script of any kind, and htmx is not loaded.
        assert!(!html_chirho.contains("<script"));
        assert!(!html_chirho.contains("htmx"));
    }

    #[test]
    fn ignores_the_request_content_so_the_form_is_static_chirho() {
        // Whatever the incoming request carries, the rendered form is identical (it is static).
        let mut loud_request_chirho = sample_request_chirho();
        loud_request_chirho.description_chirho = "PRIOR DESCRIPTION SHOULD NOT APPEAR".to_string();
        loud_request_chirho.path_chirho = "/something-else".to_string();
        let from_loud_chirho = render_form_chirho(&loud_request_chirho).html_chirho;
        let from_blank_chirho = render_form_chirho(&sample_request_chirho()).html_chirho;
        assert_eq!(from_loud_chirho, from_blank_chirho);
        assert!(!from_loud_chirho.contains("PRIOR DESCRIPTION SHOULD NOT APPEAR"));
    }
}
