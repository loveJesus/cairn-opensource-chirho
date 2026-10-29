// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render the Honeyhill Bakery landing page — the shop's front door, built on the shared cairn UI
//! kit (`cairn-node-templating-chirho`). Pure: ignores the request, so its run is computed once and
//! served from cache. Part of the `view_home_chirho` dag.

use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;
use cairn_node_templating_chirho::{
    card_chirho, escape_html_chirho, link_button_chirho, page_chirho, topbar_chirho,
    HtmlPartialV1Chirho, PageChirho,
};

/// The shop's name, kept in one place so the brand reads the same everywhere on the page.
const BRAND_CHIRHO: &str = "Honeyhill Bakery";
/// Where to find the shop (shown in the hero and the footer).
const NEIGHBORHOOD_CHIRHO: &str = "Maple & 5th, Riverbend";
/// When the ovens are warm (a single source of truth for the hours line).
const HOURS_CHIRHO: &str = "Tue–Sun, 7am–2pm";

/// in request: HttpRequestV1Chirho (ignored) -> out page: HtmlPartialV1Chirho (the full landing page)
pub fn render_home_chirho(_request_chirho: &HttpRequestV1Chirho) -> HtmlPartialV1Chirho {
    let nav_chirho = format!(
        "{} {}",
        link_button_chirho("#menu-chirho", "Menu"),
        link_button_chirho("#visit-chirho", "Visit"),
    );

    // Dynamic text routed through the kit's escaper, so the page is safe by construction even though
    // these values happen to be static today.
    let hero_chirho = format!(
        "<section class=\"container-chirho center-chirho stack-chirho\">\
<h1>Fresh sourdough, every morning.</h1>\
<p class=\"muted-chirho\">{brand_chirho} is your neighborhood bakery on {neighborhood_chirho} \
&mdash; long-fermented loaves, butter-laminated croissants, and a cinnamon roll worth setting an \
alarm for. Pulled from the oven before the coffee&rsquo;s even brewed.</p>\
<div class=\"row-chirho\" style=\"justify-content:center\">\
<a class=\"btn-chirho btn-primary-chirho\" href=\"#menu-chirho\">See today&rsquo;s bakes</a>\
<a class=\"btn-chirho\" href=\"#visit-chirho\">Plan a visit</a>\
</div></section>",
        brand_chirho = escape_html_chirho(BRAND_CHIRHO),
        neighborhood_chirho = escape_html_chirho(NEIGHBORHOOD_CHIRHO),
    );

    let menu_chirho = format!(
        "<section id=\"menu-chirho\" class=\"container-chirho\"><div class=\"grid-chirho\">{}{}{}</div></section>",
        card_chirho(
            "<h3>Country Sourdough</h3><p class=\"muted-chirho\">A 36-hour rise, a crackling \
mahogany crust, and an open, custardy crumb. Milled-wheat blend, sea salt, time. <strong>$8 a \
loaf.</strong></p>"
        ),
        card_chirho(
            "<h3>Butter Croissants</h3><p class=\"muted-chirho\">Folded by hand through 27 layers \
of European butter, baked until they shatter when you bite. Plain, almond, or pain au chocolat. \
<strong>$4 each.</strong></p>"
        ),
        card_chirho(
            "<h3>Honeyhill Cinnamon Rolls</h3><p class=\"muted-chirho\">Soft, gooey, and finished \
with a brown-butter glaze and a drizzle of local wildflower honey. They sell out by nine. \
<strong>$5 each.</strong></p>"
        ),
    );

    let visit_chirho = format!(
        "<section id=\"visit-chirho\" class=\"container-chirho center-chirho stack-chirho\">\
<h2>Come say hello</h2>\
<p class=\"muted-chirho\">Find us at {neighborhood_chirho}. Open {hours_chirho} &mdash; or until \
the shelves are bare, whichever comes first. Pre-orders for whole cakes are always welcome.</p>\
</section>",
        neighborhood_chirho = escape_html_chirho(NEIGHBORHOOD_CHIRHO),
        hours_chirho = escape_html_chirho(HOURS_CHIRHO),
    );

    let footer_chirho = format!(
        "<footer class=\"container-chirho muted-chirho small-chirho center-chirho\">\
<p>{brand_chirho} &middot; {neighborhood_chirho} &middot; baked fresh daily</p></footer>",
        brand_chirho = escape_html_chirho(BRAND_CHIRHO),
        neighborhood_chirho = escape_html_chirho(NEIGHBORHOOD_CHIRHO),
    );

    let body_chirho = format!(
        "{}{hero_chirho}{menu_chirho}{visit_chirho}{footer_chirho}",
        topbar_chirho(BRAND_CHIRHO, &nav_chirho)
    );

    HtmlPartialV1Chirho::new_chirho(page_chirho(&PageChirho {
        title_chirho: "Honeyhill Bakery — fresh sourdough & pastries on Maple & 5th",
        body_html_chirho: &body_chirho,
        head_extra_chirho: "",
        htmx_chirho: false,
    }))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn landing_has_brand_and_menu_cta_chirho() {
        let page_chirho = render_home_chirho(&HttpRequestV1Chirho::default());
        assert!(page_chirho.html_chirho.contains("Honeyhill Bakery"));
        assert!(page_chirho.html_chirho.contains("href=\"#menu-chirho\""));
        assert!(page_chirho.html_chirho.starts_with("<!doctype html>"));
    }

    #[test]
    fn landing_lists_the_signature_bakes_chirho() {
        let page_chirho = render_home_chirho(&HttpRequestV1Chirho::default());
        assert!(page_chirho.html_chirho.contains("Country Sourdough"));
        assert!(page_chirho.html_chirho.contains("Butter Croissants"));
        assert!(page_chirho.html_chirho.contains("Cinnamon Rolls"));
    }

    #[test]
    fn landing_shows_hours_and_neighborhood_chirho() {
        let page_chirho = render_home_chirho(&HttpRequestV1Chirho::default());
        // `&` is escaped by the kit; the literal en-dash passes through unchanged.
        assert!(page_chirho
            .html_chirho
            .contains("Maple &amp; 5th, Riverbend"));
        assert!(page_chirho
            .html_chirho
            .contains("Tue\u{2013}Sun, 7am\u{2013}2pm"));
    }
}
