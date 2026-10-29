// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the render_order_list role (v0): parses the scoped query response (the blessed
//! query node's output) and renders the order-list htmx partial.

use serde::Deserialize;
use tree_pizzeria_chirho::implementations_chirho::render_order_list_chirho::render_order_list_chirho as render_order_list_impl_fn_chirho;
use tree_pizzeria_chirho::types_chirho::order_v1_chirho::OrderRecordV1Chirho;

#[derive(Deserialize)]
struct ScopedQueryResponseChirho {
    #[serde(default)]
    rows_chirho: Vec<QueryRowChirho>,
}

#[derive(Deserialize)]
struct QueryRowChirho {
    #[serde(default)]
    value_chirho: String,
}

fn render_order_list_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let response_chirho = match serde_json::from_slice::<ScopedQueryResponseChirho>(input_chirho) {
        Ok(response_chirho) => response_chirho,
        Err(_error_chirho) => {
            return b"<section data-order-list-chirho=\"error\"><p>Could not load orders.</p></section>"
                .to_vec()
        }
    };
    let orders_chirho: Vec<OrderRecordV1Chirho> = response_chirho
        .rows_chirho
        .iter()
        .filter_map(|row_chirho| {
            serde_json::from_str::<OrderRecordV1Chirho>(&row_chirho.value_chirho).ok()
        })
        .collect();
    render_order_list_impl_fn_chirho(&orders_chirho)
        .html_chirho
        .into_bytes()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    render_order_list_chirho,
    render_order_list_impl_chirho
);
