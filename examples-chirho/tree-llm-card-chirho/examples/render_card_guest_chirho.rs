// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! WASM boundary for the served-LLM card's Phase-4 result-render node. Pure: it turns the effect's
//! llm-response-v1-chirho into the drafted card HTML (completion + a retry form carrying the
//! empty caller-key placeholder the engine fills) over the SDK bytes ABI.

use tree_llm_card_chirho::implementations_chirho::render_card_chirho::render_card_chirho as render_card_impl_fn_chirho;

fn render_card_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    render_card_impl_fn_chirho(input_chirho).into_bytes_chirho()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(render_card_chirho, render_card_impl_chirho);
