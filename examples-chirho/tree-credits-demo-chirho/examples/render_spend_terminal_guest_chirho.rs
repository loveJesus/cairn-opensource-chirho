// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Bytes-ABI guest for rendering Descriptor-D's exact terminal response.

use credits_demo_chirho::implementations_chirho::render_spend_terminal_chirho::{
    render_spend_terminal_chirho as render_spend_terminal_impl_chirho,
    render_spend_transport_refusal_chirho,
};
use credits_demo_chirho::types_chirho::postgres_effect_terminal_v1_chirho::parse_exact_postgres_effect_terminal_chirho;

fn render_spend_terminal_guest_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    match parse_exact_postgres_effect_terminal_chirho(input_chirho) {
        Ok(terminal_chirho) => render_spend_terminal_impl_chirho(&terminal_chirho).into_bytes(),
        Err(_error_chirho) => render_spend_transport_refusal_chirho().into_bytes(),
    }
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    render_spend_terminal_chirho,
    render_spend_terminal_guest_impl_chirho
);
