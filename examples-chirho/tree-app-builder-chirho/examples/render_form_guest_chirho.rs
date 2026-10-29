// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the render_form role (bytes ABI). Parses the HttpRequestV1Chirho the dag
//! surface carries, calls the pure impl, and emits the JS-free "describe your app" form HTML as the
//! response body, via the shared cairn UI kit. The form is static, so the request content is ignored.

use tree_app_builder_chirho::implementations_chirho::render_form_chirho::render_form_chirho as render_form_impl_fn_chirho;
use tree_app_builder_chirho::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho;

fn render_form_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let request_chirho =
        serde_json::from_slice::<HttpRequestV1Chirho>(input_chirho).unwrap_or_default();
    render_form_impl_fn_chirho(&request_chirho).into_bytes_chirho()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(render_form_chirho, render_form_impl_chirho);
