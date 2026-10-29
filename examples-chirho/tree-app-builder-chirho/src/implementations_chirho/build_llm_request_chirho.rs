// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Build the bounded LLM request from the incoming business description — the first pure node of the
//! app-builder dag. It assembles the proven content-generator instruction plus the user's
//! description and pins the hard budget (token ceiling + max price per token) the blessed `llm` door
//! enforces. Fails closed on a missing/blank description (so a GET to the build route or an empty
//! submission yields no real LLM request, hence no provider call and no spend). Pure: same
//! description in, same result out, so its run is cached.
//! Part of the `view_build_chirho` dag.

use crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;
use crate::types_chirho::llm_request_v1_chirho::LlmRequestV1Chirho;

/// The token budget the request asks the LLM door for. Kept here as a named constant so the value is
/// stated once (DRY) and matches the budget the blessed `llm` card declares.
pub const MAX_TOKENS_CHIRHO: u64 = 800;

/// The max price-per-token ceiling the request asks the LLM door for. Stated once; matches the
/// blessed `llm` card's `max_price_per_token_chirho`.
pub const MAX_PRICE_PER_TOKEN_CHIRHO: i64 = 5;

/// The fixed content-generator instruction, shared with the proven `tree-template-landing` slice.
/// It constrains the model to emit ONLY a single-line JSON object with exactly the keys the vetted
/// landing template renders from, so `validate_build_params_chirho` can strict-validate the result.
const GENERATOR_INSTRUCTION_CHIRHO: &str = "You are a website content generator. Output ONLY one compact JSON object on a single line, no prose/markdown/code fences. Use exactly these string keys: business_name_chirho, tagline_chirho, contact_chirho, and features_chirho (array of 2 to 4 objects each having exactly title_chirho and body_chirho). Business description: ";

/// in request: HttpRequestV1Chirho (reads the business description) -> out llm_request: LlmRequestV1Chirho.
/// `Ok` only when a non-blank description is present; `Err(reason)` on a missing/blank/whitespace-only
/// description, so the guest fails closed before the blessed `llm` door (no LLM request, no spend).
pub fn build_llm_request_chirho(
    request_chirho: &HttpRequestV1Chirho,
) -> Result<LlmRequestV1Chirho, String> {
    // Fail closed on no real description (a GET to the build route, or a blank/whitespace submission):
    // there is nothing to generate from, so we emit no LLM request and the door never fires.
    if request_chirho.description_chirho.trim().is_empty() {
        return Err("blank-description-chirho".to_string());
    }
    Ok(LlmRequestV1Chirho {
        prompt_chirho: format!(
            "{GENERATOR_INSTRUCTION_CHIRHO}{description_chirho}",
            description_chirho = request_chirho.description_chirho
        ),
        max_tokens_chirho: MAX_TOKENS_CHIRHO,
        max_price_per_token_chirho: MAX_PRICE_PER_TOKEN_CHIRHO,
    })
}

/// Parse the build route's wire body into the typed request accepted by `build_llm_request_chirho`.
/// Plain-mode tests pass JSON; the private browser route passes the raw form body so it never lands
/// in plaintext CAS before this first pure transform.
pub fn http_request_from_wire_bytes_chirho(input_chirho: &[u8]) -> HttpRequestV1Chirho {
    if let Ok(request_chirho) = serde_json::from_slice::<HttpRequestV1Chirho>(input_chirho) {
        return request_chirho;
    }
    let Ok(text_chirho) = std::str::from_utf8(input_chirho) else {
        return HttpRequestV1Chirho::default();
    };
    let mut request_chirho = HttpRequestV1Chirho::default();
    for pair_chirho in text_chirho.split('&') {
        let mut parts_chirho = pair_chirho.splitn(2, '=');
        let key_chirho = form_component_decode_chirho(parts_chirho.next().unwrap_or(""));
        let value_chirho = form_component_decode_chirho(parts_chirho.next().unwrap_or(""));
        if key_chirho == "description_chirho" {
            request_chirho.description_chirho = value_chirho;
        } else if key_chirho == "path_chirho" {
            request_chirho.path_chirho = value_chirho;
        }
    }
    request_chirho
}

fn form_component_decode_chirho(raw_chirho: &str) -> String {
    let bytes_chirho = raw_chirho.as_bytes();
    let mut out_chirho = Vec::with_capacity(bytes_chirho.len());
    let mut index_chirho = 0usize;
    while index_chirho < bytes_chirho.len() {
        match bytes_chirho[index_chirho] {
            b'+' => {
                out_chirho.push(b' ');
                index_chirho += 1;
            }
            b'%' if index_chirho + 2 < bytes_chirho.len() => {
                let hi_chirho = hex_value_chirho(bytes_chirho[index_chirho + 1]);
                let lo_chirho = hex_value_chirho(bytes_chirho[index_chirho + 2]);
                if let (Some(hi_chirho), Some(lo_chirho)) = (hi_chirho, lo_chirho) {
                    out_chirho.push((hi_chirho << 4) | lo_chirho);
                    index_chirho += 3;
                } else {
                    out_chirho.push(bytes_chirho[index_chirho]);
                    index_chirho += 1;
                }
            }
            byte_chirho => {
                out_chirho.push(byte_chirho);
                index_chirho += 1;
            }
        }
    }
    String::from_utf8_lossy(&out_chirho).into_owned()
}

fn hex_value_chirho(byte_chirho: u8) -> Option<u8> {
    match byte_chirho {
        b'0'..=b'9' => Some(byte_chirho - b'0'),
        b'a'..=b'f' => Some(byte_chirho - b'a' + 10),
        b'A'..=b'F' => Some(byte_chirho - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn request_carries_the_description_and_the_budget_chirho() {
        let request_chirho = HttpRequestV1Chirho {
            path_chirho: "/build-chirho".to_string(),
            user_principal_chirho: Some("owner/abc".to_string()),
            description_chirho: "A small-batch coffee roaster on Main Street.".to_string(),
        };
        let llm_request_chirho = build_llm_request_chirho(&request_chirho).unwrap();
        // The user's description is included verbatim in the prompt.
        assert!(llm_request_chirho
            .prompt_chirho
            .contains("A small-batch coffee roaster on Main Street."));
        // The generator instruction (which pins the exact JSON keys) is present.
        assert!(llm_request_chirho
            .prompt_chirho
            .contains("You are a website content generator."));
        assert!(llm_request_chirho
            .prompt_chirho
            .contains("business_name_chirho"));
        // The hard budget is pinned to the named constants.
        assert_eq!(llm_request_chirho.max_tokens_chirho, MAX_TOKENS_CHIRHO);
        assert_eq!(
            llm_request_chirho.max_price_per_token_chirho,
            MAX_PRICE_PER_TOKEN_CHIRHO
        );
    }

    #[test]
    fn the_description_is_appended_after_the_instruction_chirho() {
        let request_chirho = HttpRequestV1Chirho {
            description_chirho: "UNIQUE_MARKER_DESCRIPTION".to_string(),
            ..Default::default()
        };
        let llm_request_chirho = build_llm_request_chirho(&request_chirho).unwrap();
        // The instruction ends with "Business description: " and the description follows it.
        assert!(llm_request_chirho
            .prompt_chirho
            .ends_with("Business description: UNIQUE_MARKER_DESCRIPTION"));
    }

    #[test]
    fn fails_closed_on_a_missing_description_chirho() {
        // A request with no description (e.g. a GET to the build route) yields no LLM request.
        let request_chirho = HttpRequestV1Chirho::default();
        assert!(build_llm_request_chirho(&request_chirho).is_err());
    }

    #[test]
    fn fails_closed_on_a_blank_or_whitespace_description_chirho() {
        // An empty submission.
        let blank_chirho = HttpRequestV1Chirho {
            description_chirho: String::new(),
            ..Default::default()
        };
        assert!(build_llm_request_chirho(&blank_chirho).is_err());
        // A whitespace-only submission.
        let whitespace_chirho = HttpRequestV1Chirho {
            description_chirho: "   \t\n ".to_string(),
            ..Default::default()
        };
        assert!(build_llm_request_chirho(&whitespace_chirho).is_err());
    }

    #[test]
    fn parses_private_form_encoded_browser_body_chirho() {
        let request_chirho = http_request_from_wire_bytes_chirho(
            b"description_chirho=A+bookstore+with+poetry%20nights&ignored_chirho=value",
        );
        assert_eq!(
            request_chirho.description_chirho,
            "A bookstore with poetry nights"
        );
        let llm_request_chirho = build_llm_request_chirho(&request_chirho).unwrap();
        assert!(llm_request_chirho
            .prompt_chirho
            .contains("A bookstore with poetry nights"));
    }
}
