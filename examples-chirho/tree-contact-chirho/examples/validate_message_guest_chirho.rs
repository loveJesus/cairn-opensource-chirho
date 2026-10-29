// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Generated-by-hand boundary entry for the validate_message role (v0; the toolchain will emit
//! this). Wraps the pure tree implementation. v0 bakes the max_length pin (the authored tree keeps
//! it as a content-in port); pin-threading through the multi-input ABI is T4 tooling work.

use tree_contact_chirho::implementations_chirho::validate_message_chirho::validate_message_chirho as validate_impl_chirho;
use tree_contact_chirho::types_chirho::form_post_v1_chirho::FormPostV1Chirho;
use tree_contact_chirho::types_chirho::validation_outcome_v1_chirho::ValidationOutcomeV1Chirho;

const MAX_LENGTH_PIN_CHIRHO: u32 = 2000;

fn validate_message_entry_chirho(form_chirho: FormPostV1Chirho) -> ValidationOutcomeV1Chirho {
    match validate_impl_chirho(&form_chirho, MAX_LENGTH_PIN_CHIRHO) {
        Ok(message_chirho) => ValidationOutcomeV1Chirho {
            ok_chirho: true,
            message_chirho: Some(message_chirho),
            error_chirho: None,
        },
        Err(reason_chirho) => ValidationOutcomeV1Chirho {
            ok_chirho: false,
            message_chirho: None,
            error_chirho: Some(reason_chirho),
        },
    }
}

cairn_node_sdk_chirho::export_json_node_chirho!(
    validate_message_chirho,
    FormPostV1Chirho,
    ValidationOutcomeV1Chirho,
    validate_message_entry_chirho
);
