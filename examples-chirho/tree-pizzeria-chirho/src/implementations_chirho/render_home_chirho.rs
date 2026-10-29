// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render Rosa's pizzeria home page (pure; ignores the request — a fully static page, so its run is
//! computed once and served from cache thereafter). Built on the shared cairn UI kit.

use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;
use cairn_node_templating_chirho::{
    link_button_chirho, page_chirho, topbar_chirho, HtmlPartialV1Chirho, PageChirho,
};

/// in request: HttpRequestV1Chirho (ignored) -> out page: HtmlPartialV1Chirho
pub fn render_home_chirho(_request_chirho: &HttpRequestV1Chirho) -> HtmlPartialV1Chirho {
    let body_chirho = format!(
        "{}<section class=\"container-chirho center-chirho stack-chirho\">\
<h1>Rosa's Pizzeria</h1>\
<p class=\"muted-chirho\">Wood-fired pizza, made fresh in your neighborhood.</p>\
<div class=\"row-chirho\" style=\"justify-content:center\">{} {}</div>\
</section>",
        topbar_chirho("Rosa's Pizzeria", ""),
        link_button_chirho("menu-chirho", "See the menu"),
        link_button_chirho("order-chirho", "Place an order"),
    );
    HtmlPartialV1Chirho::new_chirho(page_chirho(&PageChirho {
        title_chirho: "Rosa's Pizzeria",
        body_html_chirho: &body_chirho,
        head_extra_chirho: "",
        htmx_chirho: false,
    }))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn renders_a_warm_static_home_chirho() {
        let page_chirho = render_home_chirho(&HttpRequestV1Chirho::default());
        assert!(page_chirho.html_chirho.contains("Rosa's Pizzeria"));
        assert!(page_chirho.html_chirho.contains("See the menu"));
    }
}
