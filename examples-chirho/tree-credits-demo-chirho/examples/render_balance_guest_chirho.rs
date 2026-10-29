// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Bytes-ABI guest for rendering the typed published-projection balance response.

use credits_demo_chirho::implementations_chirho::render_balance_chirho::{
    render_balance_chirho as render_balance_impl_chirho, render_invalid_balance_transport_chirho,
};
use credits_demo_chirho::types_chirho::published_projection_read_chirho::parse_exact_published_projection_read_chirho;

fn render_balance_guest_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    match parse_exact_published_projection_read_chirho(input_chirho) {
        Ok(response_chirho) => render_balance_impl_chirho(&response_chirho).into_bytes(),
        Err(_error_chirho) => render_invalid_balance_transport_chirho().into_bytes(),
    }
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    render_balance_chirho,
    render_balance_guest_impl_chirho
);
