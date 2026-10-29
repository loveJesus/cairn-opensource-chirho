// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Bytes-ABI guest for shaping the bounded spend form into the fixed reversible request.

use credits_demo_chirho::implementations_chirho::build_spend_request_chirho::build_spend_request_chirho as build_spend_request_impl_chirho;
use credits_demo_chirho::types_chirho::form_post_v1_chirho::FormPostV1Chirho;

fn build_spend_request_guest_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let form_chirho = serde_json::from_slice::<FormPostV1Chirho>(input_chirho)
        .expect("spend form must match the bounded schema-chirho");
    build_spend_request_impl_chirho(&form_chirho)
        .expect("spend form must name the fixed item and a canonical concurrency token-chirho")
        .canonical_bytes_chirho()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    build_spend_request_chirho,
    build_spend_request_guest_impl_chirho
);
