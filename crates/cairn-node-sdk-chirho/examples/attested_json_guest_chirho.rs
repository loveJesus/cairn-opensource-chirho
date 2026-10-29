// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

#![no_std]

extern crate alloc;

use alloc::string::String;
use serde::Serialize;

cairn_node_sdk_chirho::define_exact_json_input_chirho! {
    pub struct AttestedGreetingInputChirho {
        required_chirho {
            pub name_chirho: String,
        }
        optional_chirho {
            pub salutation_chirho: String,
        }
    }
}

#[derive(Serialize)]
pub struct AttestedGreetingOutputChirho {
    pub message_chirho: String,
}

fn handle_greeting_chirho(
    input_chirho: AttestedGreetingInputChirho,
) -> AttestedGreetingOutputChirho {
    let salutation_chirho = input_chirho
        .salutation_chirho
        .into_option_chirho()
        .unwrap_or_else(|| String::from("Hello"));
    AttestedGreetingOutputChirho {
        message_chirho: alloc::format!("{salutation_chirho}, {}", input_chirho.name_chirho),
    }
}

cairn_node_sdk_chirho::export_attested_json_node_chirho!(
    greet_chirho,
    AttestedGreetingInputChirho,
    AttestedGreetingOutputChirho,
    handle_greeting_chirho,
    br#"{"schema_chirho":"input-schema-attestation-v1-chirho","projected_schema_hash_chirho":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
);
