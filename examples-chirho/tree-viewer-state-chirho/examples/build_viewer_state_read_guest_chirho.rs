// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16 (KJV)

use tree_viewer_state_chirho::implementations_chirho::build_viewer_state_read_chirho::build_viewer_state_read_chirho as build_viewer_state_read_impl_chirho;

fn build_viewer_state_read_guest_chirho(_input_chirho: &[u8]) -> Vec<u8> {
    build_viewer_state_read_impl_chirho().to_vec()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    build_viewer_state_read_chirho,
    build_viewer_state_read_guest_chirho
);
