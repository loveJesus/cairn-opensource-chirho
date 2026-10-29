// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure request shaper for the safe perffection intake list route.

use std::vec::Vec;

const PERFFECTION_INTAKE_LIST_QUERY_CHIRHO: &[u8] =
    br#"{"prefix_chirho":"perffection-intake-chirho","limit_chirho":50}"#;

fn perffection_intake_list_request_impl_chirho(_input_chirho: &[u8]) -> Vec<u8> {
    PERFFECTION_INTAKE_LIST_QUERY_CHIRHO.to_vec()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    perffection_intake_list_request_chirho,
    perffection_intake_list_request_impl_chirho
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
    fn perffection_intake_list_request_emits_scoped_query_chirho() {
        let out_chirho = perffection_intake_list_request_impl_chirho(b"business_name_chirho=Cakes");
        let request_chirho: ScopedQueryRequestChirho = serde_json::from_slice(&out_chirho).unwrap();
        assert_eq!(request_chirho.prefix_chirho, "perffection-intake-chirho");
        assert_eq!(request_chirho.limit_chirho, Some(50));
        let text_chirho = String::from_utf8(out_chirho).unwrap();
        assert!(!text_chirho.contains("Cakes"));
        assert!(!text_chirho.contains("miriam@example.com"));
    }
}
