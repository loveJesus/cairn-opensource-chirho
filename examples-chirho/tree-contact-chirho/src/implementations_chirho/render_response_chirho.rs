// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Render the response partial from a validation outcome (pure). v0 inlines the branch choice the
//! authored tree expresses as a phi merge; on success it defers to the pure render_thanks node.
//! Escapes via the shared UI kit.

use crate::implementations_chirho::render_thanks_chirho::render_thanks_chirho;
use crate::types_chirho::validation_outcome_v1_chirho::ValidationOutcomeV1Chirho;
use cairn_node_templating_chirho::{escape_html_chirho, HtmlPartialV1Chirho};

/// in outcome: ValidationOutcomeV1Chirho -> out page: HtmlPartialV1Chirho
pub fn render_response_chirho(outcome_chirho: &ValidationOutcomeV1Chirho) -> HtmlPartialV1Chirho {
    match (&outcome_chirho.ok_chirho, &outcome_chirho.message_chirho) {
        (true, Some(message_chirho)) => render_thanks_chirho(message_chirho),
        _ => {
            let reason_chirho = outcome_chirho
                .error_chirho
                .as_deref()
                .unwrap_or("something was not right with that message");
            HtmlPartialV1Chirho::new_chirho(format!(
                "<section class=\"oops-chirho\"><p>Sorry — {}.</p></section>",
                escape_html_chirho(reason_chirho)
            ))
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::types_chirho::message_v1_chirho::MessageV1Chirho;

    #[test]
    fn renders_thanks_on_ok_and_kind_error_otherwise_chirho() {
        let ok_chirho = render_response_chirho(&ValidationOutcomeV1Chirho {
            ok_chirho: true,
            message_chirho: Some(MessageV1Chirho {
                name_chirho: "Rosa".to_string(),
                body_chirho: "ciao".to_string(),
            }),
            error_chirho: None,
        });
        assert!(ok_chirho.html_chirho.contains("Thank you, Rosa!"));

        let err_chirho = render_response_chirho(&ValidationOutcomeV1Chirho {
            ok_chirho: false,
            message_chirho: None,
            error_chirho: Some("please tell us your name".to_string()),
        });
        assert!(err_chirho.html_chirho.contains("please tell us your name"));
        assert!(!err_chirho.html_chirho.contains("Thank you"));
    }
}
