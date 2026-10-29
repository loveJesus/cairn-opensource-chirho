// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the result role (bytes ABI). Parses the DeployResponseV1Chirho the blessed
//! template-deploy door returned, calls the pure impl (render_build_result_chirho), and emits the
//! "your app is live" HTML as the response body, via the shared cairn UI kit.

use tree_app_builder_chirho::implementations_chirho::render_build_result_chirho::render_build_result_chirho as render_build_result_impl_fn_chirho;
use tree_app_builder_chirho::types_chirho::deploy_response_v1_chirho::DeployResponseV1Chirho;

fn result_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let response_chirho =
        serde_json::from_slice::<DeployResponseV1Chirho>(input_chirho).unwrap_or_default();
    render_build_result_impl_fn_chirho(&response_chirho).into_bytes_chirho()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(result_chirho, result_impl_chirho);
