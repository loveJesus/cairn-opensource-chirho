// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Bytes-ABI guest for the fixed published-projection balance query.

use credits_demo_chirho::implementations_chirho::build_balance_query_chirho::build_balance_query_chirho as build_balance_query_impl_chirho;

fn build_balance_query_guest_impl_chirho(_input_chirho: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&build_balance_query_impl_chirho())
        .expect("fixed balance query must serialize-chirho")
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    build_balance_query_chirho,
    build_balance_query_guest_impl_chirho
);
