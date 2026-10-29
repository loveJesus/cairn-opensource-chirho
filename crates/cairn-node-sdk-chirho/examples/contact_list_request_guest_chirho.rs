// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure request shaper for the safe contact-list route.

use std::vec::Vec;

const CONTACT_LIST_QUERY_CHIRHO: &[u8] =
    br#"{"prefix_chirho":"contacts-chirho","limit_chirho":50}"#;

fn contact_list_request_impl_chirho(_input_chirho: &[u8]) -> Vec<u8> {
    CONTACT_LIST_QUERY_CHIRHO.to_vec()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    contact_list_request_chirho,
    contact_list_request_impl_chirho
);

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ScopedQueryRequestChirho {
        prefix_chirho: String,
        limit_chirho: Option<u64>,
    }

    #[test]
    fn contact_list_request_emits_scoped_query_chirho() {
        let out_chirho = contact_list_request_impl_chirho(b"name_chirho=Alice");
        let request_chirho: ScopedQueryRequestChirho = serde_json::from_slice(&out_chirho).unwrap();
        assert_eq!(request_chirho.prefix_chirho, "contacts-chirho");
        assert_eq!(request_chirho.limit_chirho, Some(50));
        let text_chirho = String::from_utf8(out_chirho).unwrap();
        assert!(!text_chirho.contains("Alice"));
        assert!(!text_chirho.contains("alice@example.com"));
    }
}
