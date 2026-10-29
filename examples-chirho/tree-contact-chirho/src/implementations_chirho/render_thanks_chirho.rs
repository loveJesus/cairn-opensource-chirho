// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render the warm thank-you partial for a clean message (pure; escapes via the shared UI kit).

use crate::types_chirho::message_v1_chirho::MessageV1Chirho;
use cairn_node_templating_chirho::{escape_html_chirho, HtmlPartialV1Chirho};

/// in clean_message: MessageV1Chirho -> out page: HtmlPartialV1Chirho
pub fn render_thanks_chirho(clean_message_chirho: &MessageV1Chirho) -> HtmlPartialV1Chirho {
    let name_chirho = escape_html_chirho(&clean_message_chirho.name_chirho);
    HtmlPartialV1Chirho::new_chirho(format!(
        "<section class=\"thanks-chirho\"><h2>Thank you, {name_chirho}!</h2><p>Your message is safely received.</p></section>"
    ))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn renders_escaped_warmth_chirho() {
        let page_chirho = render_thanks_chirho(&MessageV1Chirho {
            name_chirho: "Rosa <3".to_string(),
            body_chirho: "ciao".to_string(),
        });
        assert!(page_chirho.html_chirho.contains("Thank you, Rosa &lt;3!"));
        assert!(!page_chirho.html_chirho.contains("<3"));
    }
}
