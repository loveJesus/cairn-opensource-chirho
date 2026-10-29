// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the prompt role (bytes ABI). Parses the HttpRequestV1Chirho, calls the pure
//! impl (build_llm_request_chirho), and serializes the bounded LlmRequestV1Chirho the blessed `llm`
//! door consumes.
//!
//! Fail-closed convention: the impl returns `Err` when there is no real description (a GET to the
//! build route, or a blank/whitespace-only submission). In that case this guest emits the SDK's
//! non-request error envelope (`{"error_chirho":"json-chirho"}`) instead of an LLM request. That
//! envelope is NOT a valid bounded `LlmRequestV1Chirho`: it carries no `max_tokens_chirho` or
//! `max_price_per_token_chirho`, and the blessed app-scoped `llm` door requires both (it fails closed
//! with "app-scoped llm_chirho request must include max_tokens_chirho and max_price_per_token_chirho"
//! when they are absent), so the door rejects it before any provider call - no LLM spend happens on a
//! blank/missing description.

use tree_app_builder_chirho::implementations_chirho::build_llm_request_chirho::{
    build_llm_request_chirho as build_llm_request_impl_fn_chirho,
    http_request_from_wire_bytes_chirho,
};

fn prompt_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let request_chirho = http_request_from_wire_bytes_chirho(input_chirho);
    match build_llm_request_impl_fn_chirho(&request_chirho) {
        Ok(llm_request_chirho) => serde_json::to_vec(&llm_request_chirho)
            .unwrap_or_else(|_e_chirho| cairn_node_sdk_chirho::json_error_bytes_chirho()),
        // Blank/missing description -> the SDK error envelope, which is not a valid LLM request; the
        // blessed `llm` door's request decode / budget validation rejects it (fail closed, no spend).
        Err(_reason_chirho) => cairn_node_sdk_chirho::json_error_bytes_chirho(),
    }
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(prompt_chirho, prompt_impl_chirho);
