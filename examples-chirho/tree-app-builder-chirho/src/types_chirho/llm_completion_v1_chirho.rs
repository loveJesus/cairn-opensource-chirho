// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// The raw model completion the LLM door returns: just the text the model produced. The pure
/// `validate_build_params` node is what parses and strict-validates this text into vetted params —
/// the completion itself is untrusted free text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmCompletionV1Chirho {
    #[serde(default)]
    pub text_chirho: String,
}
