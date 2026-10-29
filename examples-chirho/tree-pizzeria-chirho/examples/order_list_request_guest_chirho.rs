// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Boundary entry for the order_list_request role (v0): emits the scoped query for the orders
//! namespace from the tree's pure implementation. Pure; ignores its input.

use tree_pizzeria_chirho::implementations_chirho::order_list_request_chirho::order_list_request_chirho as order_list_request_impl_fn_chirho;

fn order_list_request_impl_chirho(_input_chirho: &[u8]) -> Vec<u8> {
    order_list_request_impl_fn_chirho().into_bytes()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    order_list_request_chirho,
    order_list_request_impl_chirho
);
