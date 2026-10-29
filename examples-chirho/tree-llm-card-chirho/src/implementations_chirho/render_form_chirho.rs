// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Render the JS-free "describe your business" landing form — the pure root node of the served-LLM
//! card app. It is a static page (a heading, a helper line, one textarea + submit) that POSTs the
//! typed business description to the draft route; it ignores the request content (the form is the
//! same for everyone) but takes the HTTP request per the surface convention. JS-free: no `<script>`,
//! htmx not loaded. Pure: same input in, same page out, so its run is cached.

use crate::implementations_chirho::build_llm_request_chirho::idempotency_key_hidden_field_chirho;
use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;
use cairn_node_templating_chirho::{
    button_chirho, card_chirho, escape_attr_chirho, page_chirho, topbar_chirho,
    HtmlPartialV1Chirho, PageChirho,
};

/// The deployed app name. Stated once so the form action, the deploy, and the served POST all use
/// the same name.
pub const APP_NAME_CHIRHO: &str = "served-llm-card-e2e-chirho";

/// The named POST route that runs the served-LLM draft DAG.
pub const DRAFT_ROUTE_CHIRHO: &str = "draft-chirho";

/// The form control name the typed description is submitted under.
pub const DESCRIPTION_FIELD_NAME_CHIRHO: &str = "description_chirho";

/// The placeholder shown in the empty description box — a plain hint, not pinned prose.
const DESCRIPTION_PLACEHOLDER_CHIRHO: &str =
    "e.g. A small-batch coffee roaster on Main Street with a cozy cafe and weekly single-origin beans.";

/// How many rows tall the description box renders.
const DESCRIPTION_ROWS_CHIRHO: u32 = 6;

/// The route the form POSTs to: the named draft route this app exposes. Built once (DRY) so the
/// action and the deployed route stay in lock-step.
pub fn draft_route_action_chirho() -> String {
    format!("/app-chirho/{APP_NAME_CHIRHO}/{DRAFT_ROUTE_CHIRHO}")
}

/// The JS-free draft form: the empty caller-key placeholder (the serve engine fills it with a fresh key
/// after the render), the description textarea, and a submit button. Shared by
/// the GET render root and the result card's "draft again" retry form so both carry a caller key.
pub fn draft_form_html_chirho(submit_label_chirho: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{action_chirho}\" class=\"stack-chirho\">\
{idempotency_key_field_chirho}\
<label class=\"field-chirho\"><span class=\"label-chirho\">Your business description</span>\
<textarea class=\"input-chirho\" name=\"{field_chirho}\" rows=\"{rows_chirho}\" \
placeholder=\"{placeholder_chirho}\" required></textarea></label>{submit_chirho}</form>",
        action_chirho = escape_attr_chirho(&draft_route_action_chirho()),
        idempotency_key_field_chirho = idempotency_key_hidden_field_chirho(),
        field_chirho = escape_attr_chirho(DESCRIPTION_FIELD_NAME_CHIRHO),
        rows_chirho = DESCRIPTION_ROWS_CHIRHO,
        placeholder_chirho = escape_attr_chirho(DESCRIPTION_PLACEHOLDER_CHIRHO),
        submit_chirho = button_chirho(submit_label_chirho, true),
    )
}

/// in request: HttpRequestV1Chirho (ignored; static form) -> out page: HtmlPartialV1Chirho
pub fn render_form_chirho(_request_chirho: &HttpRequestV1Chirho) -> HtmlPartialV1Chirho {
    // A static form. The action/method and the field name are fixed safe ASCII constants; the only
    // free text (the placeholder) is attribute-escaped, exactly like a result render node escapes
    // every dynamic string it emits.
    let form_chirho = draft_form_html_chirho("Draft my landing page");

    let body_chirho = format!(
        "{topbar_chirho}<section class=\"container-chirho center-chirho stack-chirho\">{card_chirho}</section>",
        topbar_chirho = topbar_chirho("Served-LLM card", ""),
        card_chirho = card_chirho(&format!(
            "<h1>Describe your business.</h1>\
<p class=\"muted-chirho\">Tell us about your business in a sentence or two and the served draft \
model will write you a landing page. Submit to draft it.</p>{form_chirho}"
        )),
    );

    HtmlPartialV1Chirho::new_chirho(page_chirho(&PageChirho {
        title_chirho: "Describe your business",
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
            user_principal_chirho: Some("user/abc".to_string()),
            description_chirho: String::new(),
        }
    }

    #[test]
    fn renders_a_js_free_post_form_to_the_draft_route_chirho() {
        let page_chirho = render_form_chirho(&sample_request_chirho());
        let html_chirho = &page_chirho.html_chirho;
        assert!(html_chirho.starts_with("<!doctype html>"));
        assert!(html_chirho.contains("method=\"post\""));
        assert!(
            html_chirho.contains("action=\"/app-chirho/served-llm-card-e2e-chirho/draft-chirho\"")
        );
        assert!(html_chirho.contains("<textarea"));
        assert!(html_chirho.contains("name=\"description_chirho\""));
        assert!(html_chirho.contains("type=\"submit\""));
    }

    #[test]
    fn the_page_is_js_free_chirho() {
        let page_chirho = render_form_chirho(&sample_request_chirho());
        let html_chirho = &page_chirho.html_chirho;
        assert!(!html_chirho.contains("<script"));
        assert!(!html_chirho.contains("htmx"));
    }

    #[test]
    fn ignores_the_request_content_so_the_form_is_static_chirho() {
        let mut loud_request_chirho = sample_request_chirho();
        loud_request_chirho.description_chirho = "PRIOR DESCRIPTION SHOULD NOT APPEAR".to_string();
        loud_request_chirho.path_chirho = "/something-else".to_string();
        let from_loud_chirho = render_form_chirho(&loud_request_chirho).html_chirho;
        let from_blank_chirho = render_form_chirho(&sample_request_chirho()).html_chirho;
        assert_eq!(from_loud_chirho, from_blank_chirho);
        assert!(!from_loud_chirho.contains("PRIOR DESCRIPTION SHOULD NOT APPEAR"));
    }
}
