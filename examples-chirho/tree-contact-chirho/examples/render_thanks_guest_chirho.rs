// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Generated-by-hand boundary entry for the render role (v0). Parses the validation outcome stone
//! and emits the response HTML partial as raw bytes (the HTTP body), via the pure tree impl.

use tree_contact_chirho::implementations_chirho::render_response_chirho::render_response_chirho;
use tree_contact_chirho::types_chirho::validation_outcome_v1_chirho::ValidationOutcomeV1Chirho;

fn render_thanks_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let outcome_chirho = match serde_json::from_slice::<ValidationOutcomeV1Chirho>(input_chirho) {
        Ok(outcome_chirho) => outcome_chirho,
        Err(_error_chirho) => {
            return b"<section class=\"oops-chirho\"><p>Sorry \xe2\x80\x94 we could not read that.</p></section>".to_vec()
        }
    };
    render_response_chirho(&outcome_chirho)
        .html_chirho
        .into_bytes()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(render_thanks_chirho, render_thanks_impl_chirho);
