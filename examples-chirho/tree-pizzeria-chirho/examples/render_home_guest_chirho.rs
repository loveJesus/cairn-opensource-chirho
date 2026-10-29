// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the render_home role (v0, generated-by-hand). Ignores the request bytes and
//! emits the static home HTML partial as the response body.

use tree_pizzeria_chirho::implementations_chirho::render_home_chirho::render_home_chirho as render_home_impl_fn_chirho;
use tree_pizzeria_chirho::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;

fn render_home_impl_chirho(_input_chirho: &[u8]) -> Vec<u8> {
    render_home_impl_fn_chirho(&HttpRequestV1Chirho::default())
        .html_chirho
        .into_bytes()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(render_home_chirho, render_home_impl_chirho);
