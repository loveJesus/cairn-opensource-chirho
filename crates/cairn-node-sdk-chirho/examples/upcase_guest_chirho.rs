// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use std::vec::Vec;

fn upcase_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    input_chirho
        .iter()
        .map(|byte_chirho| {
            if byte_chirho.is_ascii_lowercase() {
                byte_chirho.to_ascii_uppercase()
            } else {
                *byte_chirho
            }
        })
        .collect()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(upcase_chirho, upcase_impl_chirho);
