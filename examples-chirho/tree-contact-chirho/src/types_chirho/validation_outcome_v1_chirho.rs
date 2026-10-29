// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

use crate::types_chirho::message_v1_chirho::MessageV1Chirho;

/// The boundary outcome of validation: success carries the clean message, failure a kind reason.
/// v0 carries both arms in one stone because the engine has no phi merge yet; the authored tree
/// models validate -> phi -> {render_thanks, render_error}.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationOutcomeV1Chirho {
    pub ok_chirho: bool,
    pub message_chirho: Option<MessageV1Chirho>,
    pub error_chirho: Option<String>,
}
