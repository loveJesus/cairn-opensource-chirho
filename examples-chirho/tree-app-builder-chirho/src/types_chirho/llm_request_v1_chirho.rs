// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde::{Deserialize, Serialize};

/// The bounded request the LLM door consumes: the assembled prompt plus the hard budget the door
/// enforces (a token ceiling and a max price per token). The pure `build_llm_request` node produces
/// it; the blessed `llm` door reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmRequestV1Chirho {
    #[serde(default)]
    pub prompt_chirho: String,
    #[serde(default)]
    pub max_tokens_chirho: u64,
    #[serde(default)]
    pub max_price_per_token_chirho: i64,
}
