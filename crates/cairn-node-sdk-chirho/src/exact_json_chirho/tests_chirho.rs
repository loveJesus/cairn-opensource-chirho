// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use alloc::string::String;

crate::define_exact_json_input_chirho! {
    struct StrictInputChirho {
        required_chirho {
            name_chirho: String,
            enabled_chirho: bool,
        }
        optional_chirho {
            note_chirho: String,
        }
    }
}

#[derive(serde::Serialize)]
struct StrictOutputChirho {
    accepted_chirho: bool,
}

fn handle_chirho(input_chirho: StrictInputChirho) -> StrictOutputChirho {
    StrictOutputChirho {
        accepted_chirho: input_chirho.enabled_chirho && !input_chirho.name_chirho.is_empty(),
    }
}

crate::export_attested_json_node_chirho!(
    strict_entry_chirho,
    StrictInputChirho,
    StrictOutputChirho,
    handle_chirho,
    br#"{"schema_chirho":"input-schema-attestation-v1-chirho","projected_schema_hash_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
);

#[test]
fn generated_input_rejects_missing_unknown_null_and_wrong_types_chirho() {
    let valid_chirho: StrictInputChirho =
        serde_json::from_slice(br#"{"name_chirho":"L.J.","enabled_chirho":true}"#).unwrap();
    assert_eq!(valid_chirho.name_chirho, "L.J.");
    assert_eq!(valid_chirho.note_chirho.as_ref_chirho(), None);
    let present_chirho: StrictInputChirho = serde_json::from_slice(
        br#"{"name_chirho":"L.J.","enabled_chirho":true,"note_chirho":"ready"}"#,
    )
    .unwrap();
    assert_eq!(
        present_chirho
            .note_chirho
            .as_ref_chirho()
            .map(String::as_str),
        Some("ready")
    );
    for bytes_chirho in [
        br#"{"name_chirho":"L.J."}"#.as_slice(),
        br#"{"name_chirho":"L.J.","enabled_chirho":true,"extra_chirho":1}"#.as_slice(),
        br#"{"name_chirho":null,"enabled_chirho":true}"#.as_slice(),
        br#"{"name_chirho":"L.J.","enabled_chirho":true,"note_chirho":null}"#.as_slice(),
        br#"{"name_chirho":"L.J.","enabled_chirho":"true"}"#.as_slice(),
    ] {
        assert!(serde_json::from_slice::<StrictInputChirho>(bytes_chirho).is_err());
    }
}

#[test]
fn attested_export_keeps_the_exact_payload_bytes_chirho() {
    assert_eq!(
        CAIRN_INPUT_SCHEMA_ATTESTATION_BYTES_CHIRHO,
        br#"{"schema_chirho":"input-schema-attestation-v1-chirho","projected_schema_hash_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#
    );
}
