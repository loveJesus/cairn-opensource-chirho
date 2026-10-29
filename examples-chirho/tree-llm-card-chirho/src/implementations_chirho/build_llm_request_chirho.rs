// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Phase 3: turn the draft form's `application/x-www-form-urlencoded` submission into the
//! `llm-request-v1-chirho` the paid effect consumes. PURE: same body in, same request out. It reads
//! ONLY the business-description field and forms the prompt from that alone; the caller idempotency
//! key (a hidden form field) is deliberately NOT read into the request, so the key never reaches the
//! prompt (a left-in key would ride the prompt and completion and shift the request's content). The
//! key is the serve dispatch's idempotency coordinate, extracted separately before persistence.

use crate::types_chirho::llm_request_v1_chirho::LlmRequestV1Chirho;

/// The form control the business description is submitted under (mirror of
/// `render_form_chirho::DESCRIPTION_FIELD_NAME_CHIRHO`).
pub const DESCRIPTION_FIELD_NAME_CHIRHO: &str = "description_chirho";

/// The hidden form control the issued caller idempotency key rides in. Named here so the render
/// form (which emits it), the serve dispatch (which extracts it for idempotency), and this node
/// (which drops it from the prompt) all agree; a browser form cannot set a request header, so the key
/// travels in the body. The contracted wire name is `idempotency_key_chirho` (#24124/#24243).
pub const IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO: &str = "idempotency_key_chirho";

/// The exact empty placeholder the render nodes emit once per POST form. The serve engine fills each one
/// with its own fresh caller key after the render (the browser caller-key carrier), so the render node
/// stays pure and cacheable while each served page carries distinct keys. Mirror of the serve crate's
/// `FORM_CALLER_KEY_PLACEHOLDER_CHIRHO`; the bytes are load-bearing.
pub const FORM_CALLER_KEY_PLACEHOLDER_CHIRHO: &str =
    "<input type=\"hidden\" name=\"idempotency_key_chirho\" value=\"\">";

/// The hidden caller-key form field the render nodes emit: the contract's empty placeholder.
pub fn idempotency_key_hidden_field_chirho() -> String {
    FORM_CALLER_KEY_PLACEHOLDER_CHIRHO.to_string()
}

/// in body: url-encoded form bytes -> out request: `llm-request-v1-chirho` JSON bytes.
pub fn build_llm_request_chirho(body_chirho: &[u8]) -> Vec<u8> {
    let body_chirho = String::from_utf8_lossy(body_chirho);
    let description_chirho =
        urlencoded_field_value_chirho(&body_chirho, DESCRIPTION_FIELD_NAME_CHIRHO)
            .unwrap_or_default();
    let request_chirho = LlmRequestV1Chirho::from_description_chirho(&description_chirho);
    serde_json::to_vec(&request_chirho).expect("serialize llm-request-v1-chirho")
}

/// Return the percent-decoded value of the FIRST occurrence of `field_chirho` in a url-encoded body,
/// or `None` if absent. Field names in this app are plain ASCII, so the key is matched decoded too.
fn urlencoded_field_value_chirho(body_chirho: &str, field_chirho: &str) -> Option<String> {
    for pair_chirho in body_chirho.split('&') {
        let mut parts_chirho = pair_chirho.splitn(2, '=');
        let key_chirho = parts_chirho.next().unwrap_or_default();
        if percent_decode_chirho(key_chirho) == field_chirho {
            return Some(percent_decode_chirho(
                parts_chirho.next().unwrap_or_default(),
            ));
        }
    }
    None
}

/// Minimal `application/x-www-form-urlencoded` value decoder: `+` -> space and `%XX` -> byte, with a
/// malformed `%` left literal. Lossy UTF-8 at the end, matching a browser form submission.
fn percent_decode_chirho(input_chirho: &str) -> String {
    let bytes_chirho = input_chirho.as_bytes();
    let mut out_chirho = Vec::with_capacity(bytes_chirho.len());
    let mut index_chirho = 0;
    while index_chirho < bytes_chirho.len() {
        match bytes_chirho[index_chirho] {
            b'+' => {
                out_chirho.push(b' ');
                index_chirho += 1;
            }
            b'%' if index_chirho + 2 < bytes_chirho.len() => {
                match (
                    hex_nibble_chirho(bytes_chirho[index_chirho + 1]),
                    hex_nibble_chirho(bytes_chirho[index_chirho + 2]),
                ) {
                    (Some(high_chirho), Some(low_chirho)) => {
                        out_chirho.push(high_chirho * 16 + low_chirho);
                        index_chirho += 3;
                    }
                    _ => {
                        out_chirho.push(b'%');
                        index_chirho += 1;
                    }
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

fn hex_nibble_chirho(byte_chirho: u8) -> Option<u8> {
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
    use crate::types_chirho::llm_request_v1_chirho::{
        LLM_REQUEST_SCHEMA_CHIRHO, LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO,
    };

    #[test]
    fn builds_the_request_from_the_description_field_only_chirho() {
        let body_chirho = format!(
            "{IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO}=render-key-123-chirho&\
             {DESCRIPTION_FIELD_NAME_CHIRHO}=A+cozy+cafe+on+Main+St."
        );
        let request_chirho: LlmRequestV1Chirho =
            serde_json::from_slice(&build_llm_request_chirho(body_chirho.as_bytes())).unwrap();
        assert_eq!(request_chirho.schema_chirho, LLM_REQUEST_SCHEMA_CHIRHO);
        assert_eq!(
            request_chirho.response_format_chirho,
            LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO
        );
        assert_eq!(
            request_chirho.user_chirho,
            "Business name: A cozy cafe on Main St."
        );
    }

    #[test]
    fn the_caller_key_never_reaches_the_prompt_chirho() {
        let body_chirho = format!(
            "{DESCRIPTION_FIELD_NAME_CHIRHO}=Zzyzx+Bakery&\
             {IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO}=secret-render-key-chirho"
        );
        let request_bytes_chirho = build_llm_request_chirho(body_chirho.as_bytes());
        let rendered_chirho = String::from_utf8_lossy(&request_bytes_chirho);
        assert!(
            rendered_chirho.contains("Zzyzx Bakery"),
            "the description must reach the prompt"
        );
        assert!(
            !rendered_chirho.contains("secret-render-key-chirho")
                && !rendered_chirho.contains(IDEMPOTENCY_KEY_FIELD_NAME_CHIRHO),
            "the caller key must never reach the request/prompt"
        );
    }

    #[test]
    fn percent_encoded_description_is_decoded_chirho() {
        let body_chirho = format!("{DESCRIPTION_FIELD_NAME_CHIRHO}=Bread%20%26%20cakes%2C%20daily");
        let request_chirho: LlmRequestV1Chirho =
            serde_json::from_slice(&build_llm_request_chirho(body_chirho.as_bytes())).unwrap();
        assert_eq!(
            request_chirho.user_chirho,
            "Business name: Bread & cakes, daily"
        );
    }
}
