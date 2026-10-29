// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Phase 4: render the effect output into the served-LLM card page. The effect returns EITHER an
//! `llm-response-v1-chirho` success (the sealed draft) OR an `llm-refusal-v1-chirho` typed refusal, so
//! this node DISCRIMINATES on `schema_chirho` (Finding 4): a success shows the drafted content; a
//! typed refusal shows its fixed, secret-free message as an honest refusal (NEVER an amount); anything
//! else (malformed bytes, an unknown schema, a response with no completion) shows an honest error, not
//! a fake "draft is ready". Every branch carries the "draft again" retry form (one
//! empty caller-key placeholder), so the engine issues the retry its own key and the user can
//! always retry. PURE: same bytes in, same HTML out, so the run is cached. It reads ONLY the completion
//! text / refusal message; the plaintext-free evidence beside it (hashes, counts) is never shown. On a
//! success its input is the sealed viewer-subject response, so its output inherits that subject and is
//! sealed too; a typed refusal carries no PII (public), so the refusal card is public.

use crate::implementations_chirho::render_form_chirho::draft_form_html_chirho;
use cairn_node_templating_chirho::{
    card_chirho, escape_attr_chirho, page_chirho, topbar_chirho, HtmlPartialV1Chirho, PageChirho,
};

/// The effect's success schema tag (mirror of `cairn_llm_served_effect_chirho::LLM_RESPONSE_SCHEMA_CHIRHO`).
const LLM_RESPONSE_SCHEMA_CHIRHO: &str = "llm-response-v1-chirho";

/// The effect's typed-refusal schema tag (mirror of `cairn_llm_served_effect_chirho::LLM_REFUSAL_SCHEMA_CHIRHO`).
const LLM_REFUSAL_SCHEMA_CHIRHO: &str = "llm-refusal-v1-chirho";

/// in response: the effect output JSON (`llm-response-v1-chirho` OR `llm-refusal-v1-chirho`) -> out
/// page: HtmlPartialV1Chirho (the drafted card, or an honest refusal / error card).
pub fn render_card_chirho(response_bytes_chirho: &[u8]) -> HtmlPartialV1Chirho {
    let Ok(value_chirho) = serde_json::from_slice::<serde_json::Value>(response_bytes_chirho)
    else {
        // Malformed output must never render as an empty success.
        return honest_error_card_chirho();
    };
    let schema_chirho = value_chirho
        .get("schema_chirho")
        .and_then(|field_chirho| field_chirho.as_str())
        .unwrap_or_default();
    match schema_chirho {
        LLM_RESPONSE_SCHEMA_CHIRHO => match value_chirho
            .get("completion_chirho")
            .and_then(|field_chirho| field_chirho.as_str())
        {
            Some(completion_chirho) => render_success_card_chirho(completion_chirho),
            // A success schema with no completion string is malformed, not an empty success.
            None => honest_error_card_chirho(),
        },
        LLM_REFUSAL_SCHEMA_CHIRHO => {
            // The typed refusal carries a fixed, secret-free message and NO amount. Show it honestly.
            let message_chirho = value_chirho
                .get("message_chirho")
                .and_then(|field_chirho| field_chirho.as_str())
                .unwrap_or("the draft was refused");
            render_refusal_card_chirho(message_chirho)
        }
        // Unknown / absent schema: an honest error, never a fabricated success.
        _ => honest_error_card_chirho(),
    }
}

/// The success card: the drafted content (escaped) plus the "draft again" retry form.
fn render_success_card_chirho(completion_chirho: &str) -> HtmlPartialV1Chirho {
    served_card_page_chirho(
        "Your draft",
        "Your draft is ready.",
        &format!(
            "<pre class=\"input-chirho\">{completion_chirho}</pre>",
            completion_chirho = escape_attr_chirho(completion_chirho)
        ),
        "Draft another",
    )
}

/// The refusal card: an honest heading and the refusal's fixed message (escaped, never an amount),
/// plus a retry form so the customer can try again.
fn render_refusal_card_chirho(message_chirho: &str) -> HtmlPartialV1Chirho {
    served_card_page_chirho(
        "Draft not ready",
        "We could not draft your page.",
        &format!(
            "<p class=\"muted-chirho\">{message_chirho}</p>",
            message_chirho = escape_attr_chirho(message_chirho)
        ),
        "Try again",
    )
}

/// The honest-error card for malformed / unexpected effect output: never a fake success.
fn honest_error_card_chirho() -> HtmlPartialV1Chirho {
    served_card_page_chirho(
        "Draft not ready",
        "We could not draft your page.",
        "<p class=\"muted-chirho\">The drafting service returned an unexpected result. Start blank and try again.</p>",
        "Try again",
    )
}

/// Shared page frame for every served card (success, refusal, error): topbar + a card carrying the
/// fixed heading, the branch-specific inner HTML, and the "draft again" retry form. The retry form
/// emits the empty caller-key placeholder once, so the engine issues the retry its own key.
/// The heading and inner HTML are fixed/escaped, so model output can never inject markup.
fn served_card_page_chirho(
    title_chirho: &str,
    heading_chirho: &str,
    inner_html_chirho: &str,
    retry_label_chirho: &str,
) -> HtmlPartialV1Chirho {
    let body_chirho = format!(
        "{topbar_chirho}<section class=\"container-chirho center-chirho stack-chirho\">{card_chirho}</section>",
        topbar_chirho = topbar_chirho("Served-LLM card", ""),
        card_chirho = card_chirho(&format!(
            "<h1>{heading_chirho}</h1>{inner_html_chirho}{form_chirho}",
            form_chirho = draft_form_html_chirho(retry_label_chirho),
        )),
    );
    HtmlPartialV1Chirho::new_chirho(page_chirho(&PageChirho {
        title_chirho,
        body_html_chirho: &body_chirho,
        head_extra_chirho: "",
        htmx_chirho: false,
    }))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::implementations_chirho::build_llm_request_chirho::FORM_CALLER_KEY_PLACEHOLDER_CHIRHO;

    fn response_bytes_chirho(completion_chirho: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_chirho": "llm-response-v1-chirho",
            "completion_chirho": completion_chirho,
            "tokens_in_chirho": 10,
            "tokens_out_chirho": 20,
            "model_chirho": "stub",
            "evidence_chirho": {},
        }))
        .unwrap()
    }

    fn refusal_bytes_chirho(refusal_code_chirho: &str, message_chirho: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema_chirho": "llm-refusal-v1-chirho",
            "refusal_code_chirho": refusal_code_chirho,
            "message_chirho": message_chirho,
        }))
        .unwrap()
    }

    #[test]
    fn renders_the_completion_and_a_retry_form_with_the_placeholder_chirho() {
        let page_chirho =
            render_card_chirho(&response_bytes_chirho("Zzyzx Bakery draft body")).html_chirho;
        assert!(page_chirho.starts_with("<!doctype html>"));
        assert!(page_chirho.contains("Your draft is ready."));
        assert!(page_chirho.contains("Zzyzx Bakery draft body"));
        // The retry form carries the empty caller-key placeholder once (the engine fills it).
        assert_eq!(
            page_chirho
                .matches(FORM_CALLER_KEY_PLACEHOLDER_CHIRHO)
                .count(),
            1,
            "the card's retry form must emit the empty caller-key placeholder exactly once"
        );
        assert!(page_chirho.contains("method=\"post\""));
        assert!(!page_chirho.contains("<script"));
    }

    #[test]
    fn a_typed_refusal_renders_honestly_not_a_fake_success_chirho() {
        let page_chirho = render_card_chirho(&refusal_bytes_chirho(
            "insufficient-credit-chirho",
            "not enough credit for a draft",
        ))
        .html_chirho;
        assert!(page_chirho.starts_with("<!doctype html>"));
        // Honest refusal: the fixed message shows, the success heading does NOT.
        assert!(page_chirho.contains("not enough credit for a draft"));
        assert!(
            !page_chirho.contains("Your draft is ready."),
            "a typed refusal must never render the success heading"
        );
        // A refusal still offers a retry form carrying the empty caller-key placeholder once, so the
        // engine issues the retry a fresh key and its POST is never refused for a missing one.
        assert_eq!(
            page_chirho
                .matches(FORM_CALLER_KEY_PLACEHOLDER_CHIRHO)
                .count(),
            1,
            "the refusal card's retry form must emit the empty caller-key placeholder exactly once"
        );
        assert!(page_chirho.contains("method=\"post\""));
    }

    #[test]
    fn malformed_output_renders_an_honest_error_not_empty_success_chirho() {
        let page_chirho = render_card_chirho(b"this is not json").html_chirho;
        assert!(!page_chirho.contains("Your draft is ready."));
        assert!(page_chirho.contains("We could not draft your page."));
        assert_eq!(
            page_chirho
                .matches(FORM_CALLER_KEY_PLACEHOLDER_CHIRHO)
                .count(),
            1,
            "even the error card carries one retry-form placeholder so the engine issues a key"
        );
    }

    #[test]
    fn a_success_schema_with_no_completion_is_an_honest_error_chirho() {
        let no_completion_chirho = serde_json::to_vec(&serde_json::json!({
            "schema_chirho": "llm-response-v1-chirho",
        }))
        .unwrap();
        let page_chirho = render_card_chirho(&no_completion_chirho).html_chirho;
        assert!(
            !page_chirho.contains("Your draft is ready."),
            "a response schema with no completion must not fake a success"
        );
        assert!(page_chirho.contains("We could not draft your page."));
    }
}
