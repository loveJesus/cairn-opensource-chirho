// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! WASM boundary for the served-LLM card's Phase-3 form-build node. Pure: it turns the draft form's
//! url-encoded submission into the `llm-request-v1-chirho` JSON the paid effect consumes, reading only
//! the business description (never the caller key) over the SDK bytes ABI.

use tree_llm_card_chirho::implementations_chirho::build_llm_request_chirho::build_llm_request_chirho as build_llm_request_impl_fn_chirho;

fn build_llm_request_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    build_llm_request_impl_fn_chirho(input_chirho)
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    build_llm_request_chirho,
    build_llm_request_impl_chirho
);
