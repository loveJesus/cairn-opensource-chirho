// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the render_confirmation role (v0, generated-by-hand). It receives the reified
//! `OrderRecordV1Chirho` (the blessed `save_order` node's output is the value it wrote) and emits the
//! htmx confirmation partial as the response body.

use tree_pizzeria_chirho::implementations_chirho::render_confirmation_chirho::render_confirmation_chirho as render_confirmation_impl_fn_chirho;
use tree_pizzeria_chirho::types_chirho::order_v1_chirho::OrderRecordV1Chirho;

fn render_confirmation_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<OrderRecordV1Chirho>(input_chirho) {
        Ok(record_chirho) => render_confirmation_impl_fn_chirho(&record_chirho)
            .html_chirho
            .into_bytes(),
        Err(_error_chirho) => {
            b"<section data-order-chirho=\"rejected\"><p>Sorry &mdash; we could not read your order.</p></section>"
                .to_vec()
        }
    }
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    render_confirmation_chirho,
    render_confirmation_impl_chirho
);
