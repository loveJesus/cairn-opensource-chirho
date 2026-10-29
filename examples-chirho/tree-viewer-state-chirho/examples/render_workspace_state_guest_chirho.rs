// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. - John 3:16 (KJV)

use tree_viewer_state_chirho::implementations_chirho::render_workspace_state_chirho::render_workspace_state_chirho as render_workspace_state_impl_chirho;

fn render_workspace_state_guest_chirho(input_chirho: &[u8]) -> Vec<u8> {
    render_workspace_state_impl_chirho(input_chirho).into_bytes_chirho()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    render_workspace_state_chirho,
    render_workspace_state_guest_chirho
);
