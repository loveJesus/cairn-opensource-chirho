// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Pure htmx renderer for the safe perffection intake submit response.

use serde::Deserialize;
use std::vec::Vec;

#[derive(Deserialize)]
struct PerffectionIntakeRecordViewChirho {
    #[serde(default)]
    status_chirho: String,
}

fn perffection_intake_render_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let record_chirho =
        match serde_json::from_slice::<PerffectionIntakeRecordViewChirho>(input_chirho) {
            Ok(record_chirho) => record_chirho,
            Err(_error_chirho) => return partial_chirho("error", "The intake was not recorded."),
        };
    if record_chirho.status_chirho == "received" {
        partial_chirho(
            "received",
            "Perffection intake received and stored as a private Cairn ref.",
        )
    } else {
        partial_chirho("error", "The intake was not recorded.")
    }
}

fn partial_chirho(state_chirho: &str, message_chirho: &str) -> Vec<u8> {
    format!(
        "<section data-perffection-intake-chirho=\"{state_chirho}\"><p>{message_chirho}</p></section>"
    )
    .into_bytes()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(
    perffection_intake_render_chirho,
    perffection_intake_render_impl_chirho
);
