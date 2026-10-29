// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render the Fernwell & Frond landing page — the shop's front door, built on the shared cairn UI
//! kit (`cairn-node-templating-chirho`). Pure: ignores the request, so its run is computed once and
//! served from cache. Part of the `view_home_chirho` dag.

use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;
use cairn_node_templating_chirho::{
    card_chirho, escape_html_chirho, link_button_chirho, page_chirho, topbar_chirho,
    HtmlPartialV1Chirho, PageChirho,
};

/// The shop's name, kept in one place so the brand reads the same everywhere on the page.
const BRAND_CHIRHO: &str = "Fernwell & Frond";
/// Where to find the greenhouse (shown in the hero, the visit section, and the footer).
const NEIGHBORHOOD_CHIRHO: &str = "112 Willow Court, Greenmarket District";
/// When the greenhouse doors are open (a single source of truth for the hours line).
const HOURS_CHIRHO: &str = "Wed–Mon, 9am–6pm";

/// in request: HttpRequestV1Chirho (ignored) -> out page: HtmlPartialV1Chirho (the full landing page)
pub fn render_home_chirho(_request_chirho: &HttpRequestV1Chirho) -> HtmlPartialV1Chirho {
    let nav_chirho = format!(
        "{} {} {}",
        link_button_chirho("#plants-chirho", "Plants"),
        link_button_chirho("#care-chirho", "Care"),
        link_button_chirho("#visit-chirho", "Visit"),
    );

    // Dynamic text routed through the kit's escaper, so the page is safe by construction even though
    // these values happen to be static today.
    let hero_chirho = format!(
        "<section class=\"container-chirho center-chirho stack-chirho\">\
<h1>Grow something that stays.</h1>\
<p class=\"muted-chirho\">{brand_chirho} is a small greenhouse and nursery on \
{neighborhood_chirho} &mdash; rare aroids, hardy succulents, and starter herbs, each one \
hand-potted and labeled with the light and water it actually wants. We&rsquo;d rather sell you \
one plant that thrives than three that sulk.</p>\
<div class=\"row-chirho\" style=\"justify-content:center\">\
<a class=\"btn-chirho btn-primary-chirho\" href=\"#plants-chirho\">Meet this week&rsquo;s plants</a>\
<a class=\"btn-chirho\" href=\"#visit-chirho\">Plan a visit</a>\
</div></section>",
        brand_chirho = escape_html_chirho(BRAND_CHIRHO),
        neighborhood_chirho = escape_html_chirho(NEIGHBORHOOD_CHIRHO),
    );

    let plants_chirho = format!(
        "<section id=\"plants-chirho\" class=\"container-chirho\"><div class=\"grid-chirho\">{}{}{}</div></section>",
        card_chirho(
            "<h3>Monstera deliciosa</h3><p class=\"muted-chirho\">The split-leaf classic, grown \
from a stocky mother plant so the fenestrations come early. Loves bright indirect light; let the \
top two inches dry between drinks. <strong>$28, in a 6&quot; nursery pot.</strong></p>"
        ),
        card_chirho(
            "<h3>Haworthia &lsquo;Zebra&rsquo;</h3><p class=\"muted-chirho\">A tidy, forgiving \
succulent with banded white stripes &mdash; happy on a sunny sill and content if you forget it \
for a fortnight. Water deeply, then leave it be. <strong>$12.</strong></p>"
        ),
        card_chirho(
            "<h3>Sweet Basil starts</h3><p class=\"muted-chirho\">Cutting-grown Genovese basil, \
already bushy and ready for your kitchen window. Six hours of sun and a weekly soak keeps the \
pesto coming all season. <strong>$6 a pot, 3 for $15.</strong></p>"
        ),
    );

    let care_chirho = format!(
        "<section id=\"care-chirho\" class=\"container-chirho center-chirho stack-chirho\">\
<h2>Plants are easier than you think</h2>\
<p class=\"muted-chirho\">Every plant leaves the shop with a {brand_chirho} care card: light, \
water, and one honest warning about how to kill it. Bring a leaf or a photo of a struggling \
plant and we&rsquo;ll repot or diagnose it on the bench, free &mdash; no purchase needed.</p>\
</section>",
        brand_chirho = escape_html_chirho(BRAND_CHIRHO),
    );

    let visit_chirho = format!(
        "<section id=\"visit-chirho\" class=\"container-chirho center-chirho stack-chirho\">\
<h2>Come wander the benches</h2>\
<p class=\"muted-chirho\">Find the greenhouse at {neighborhood_chirho}. Open {hours_chirho} &mdash; \
closed Tuesdays so the plants get a quiet day. Local delivery on Saturdays; ask about holds for \
the rare shelf.</p>\
</section>",
        neighborhood_chirho = escape_html_chirho(NEIGHBORHOOD_CHIRHO),
        hours_chirho = escape_html_chirho(HOURS_CHIRHO),
    );

    let footer_chirho = format!(
        "<footer class=\"container-chirho muted-chirho small-chirho center-chirho\">\
<p>{brand_chirho} &middot; {neighborhood_chirho} &middot; potted with care</p></footer>",
        brand_chirho = escape_html_chirho(BRAND_CHIRHO),
        neighborhood_chirho = escape_html_chirho(NEIGHBORHOOD_CHIRHO),
    );

    let body_chirho = format!(
        "{}{hero_chirho}{plants_chirho}{care_chirho}{visit_chirho}{footer_chirho}",
        topbar_chirho(BRAND_CHIRHO, &nav_chirho)
    );

    HtmlPartialV1Chirho::new_chirho(page_chirho(&PageChirho {
        title_chirho: "Fernwell & Frond — a neighborhood plant shop & nursery on Willow Court",
        body_html_chirho: &body_chirho,
        head_extra_chirho: "",
        htmx_chirho: false,
    }))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn landing_has_brand_and_plants_cta_chirho() {
        let page_chirho = render_home_chirho(&HttpRequestV1Chirho::default());
        assert!(page_chirho.html_chirho.contains("Fernwell &amp; Frond"));
        assert!(page_chirho.html_chirho.contains("href=\"#plants-chirho\""));
        assert!(page_chirho.html_chirho.starts_with("<!doctype html>"));
    }

    #[test]
    fn landing_lists_the_featured_plants_chirho() {
        let page_chirho = render_home_chirho(&HttpRequestV1Chirho::default());
        assert!(page_chirho.html_chirho.contains("Monstera deliciosa"));
        assert!(page_chirho.html_chirho.contains("Haworthia"));
        assert!(page_chirho.html_chirho.contains("Sweet Basil"));
    }

    #[test]
    fn landing_shows_hours_and_neighborhood_chirho() {
        let page_chirho = render_home_chirho(&HttpRequestV1Chirho::default());
        // `&` is escaped by the kit; the literal en-dash passes through unchanged.
        assert!(page_chirho
            .html_chirho
            .contains("112 Willow Court, Greenmarket District"));
        assert!(page_chirho
            .html_chirho
            .contains("Wed\u{2013}Mon, 9am\u{2013}6pm"));
    }
}
