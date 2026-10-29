// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! WASM boundary for the served-LLM card form-render node. Pure: it decodes the surface request and
//! returns the static form's HTML bytes over the SDK bytes ABI.

use tree_llm_card_chirho::implementations_chirho::render_form_chirho::render_form_chirho as render_form_impl_fn_chirho;
use tree_llm_card_chirho::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;

fn render_form_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let request_chirho =
        serde_json::from_slice::<HttpRequestV1Chirho>(input_chirho).unwrap_or_default();
    render_form_impl_fn_chirho(&request_chirho).into_bytes_chirho()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(render_form_chirho, render_form_impl_chirho);
