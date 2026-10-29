// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the render_home role (v0, generated-by-hand). Parses the HttpRequestV1Chirho
//! (ignored by the static landing) and emits the landing-page HTML as the response body, via the
//! pure tree impl + the shared cairn UI kit.

use tree_bakery_chirho::implementations_chirho::render_home_chirho::render_home_chirho as render_home_impl_fn_chirho;
use tree_bakery_chirho::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;

fn render_home_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let request_chirho =
        serde_json::from_slice::<HttpRequestV1Chirho>(input_chirho).unwrap_or_default();
    render_home_impl_fn_chirho(&request_chirho).into_bytes_chirho()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(render_home_chirho, render_home_impl_chirho);
