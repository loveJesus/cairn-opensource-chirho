// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Brick-A guest node #3 (PURE): renders the htmx partial from the SAFE reified contact record. It
//! reads only the record's `status_chirho` (safe metadata) and never echoes any PII — the
//! name/email/message live only in the crypto-shredded private blob, recoverable through the privacy
//! layer, never here.

use serde::Deserialize;
use std::string::String;
use std::vec::Vec;

#[derive(Deserialize)]
struct ContactRecordViewChirho {
    #[serde(default)]
    status_chirho: String,
}

fn contact_render_impl_chirho(input_chirho: &[u8]) -> Vec<u8> {
    let record_chirho = match serde_json::from_slice::<ContactRecordViewChirho>(input_chirho) {
        Ok(record_chirho) => record_chirho,
        Err(_error_chirho) => return partial_chirho("error", "We could not record your message."),
    };
    if record_chirho.status_chirho == "received" {
        partial_chirho(
            "received",
            "Thanks &mdash; your message was received and stored safely.",
        )
    } else {
        partial_chirho("error", "We could not record your message.")
    }
}

/// Build the htmx partial. `state_chirho` is a fixed safe token; `message_chirho` is a trusted
/// literal from this node (no caller/PII input), so it is embedded as-is.
fn partial_chirho(state_chirho: &str, message_chirho: &str) -> Vec<u8> {
    format!("<section data-contact-chirho=\"{state_chirho}\"><p>{message_chirho}</p></section>")
        .into_bytes()
}

cairn_node_sdk_chirho::export_bytes_node_chirho!(contact_render_chirho, contact_render_impl_chirho);
