// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Dep-light, npm-free HTML templating + UI kit for cairn app render nodes.
//!
//! One correct HTML escape (security), the shared HTML-partial type, a page shell, reusable
//! components, and a Tailwind-lite utility CSS — so every cairn app renders safe, consistent,
//! good-looking HTML without copy-pasting escaping or styles into each guest.

mod components_chirho;
mod escape_chirho;
mod html_chirho;
mod layout_chirho;
mod ui_css_chirho;

pub use components_chirho::{
    alert_chirho, button_chirho, card_chirho, field_chirho, link_button_chirho, text_input_chirho,
    textarea_chirho, topbar_chirho, AlertKindChirho,
};
pub use escape_chirho::{escape_attr_chirho, escape_html_chirho};
pub use html_chirho::HtmlPartialV1Chirho;
pub use layout_chirho::{page_chirho, simple_page_chirho, PageChirho};
pub use ui_css_chirho::UI_CSS_CHIRHO;
