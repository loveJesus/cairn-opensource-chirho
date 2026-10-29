// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The `llm-request-v1-chirho` value the build node emits for the draft route's paid effect. Its
//! serde shape MUST match `cairn_llm_served_effect_chirho::LlmRequestChirho` byte-for-byte (same
//! field names, same `skip_serializing_if` on `max_tokens_chirho`, and that type's `deny_unknown_fields`
//! means this must carry EXACTLY these fields — never a caller key or any other extra), because the
//! effect deserializes this node's output as that type. The guest crate has no dependency on the
//! effect leaf, so the contract is mirrored here and pinned by a test.

use serde::{Deserialize, Serialize};

/// The one request schema tag the served card's effect accepts (mirror of
/// `cairn_llm_served_effect_chirho::LLM_REQUEST_SCHEMA_CHIRHO`).
pub const LLM_REQUEST_SCHEMA_CHIRHO: &str = "llm-request-v1-chirho";

/// The one response format the served card asks for (mirror of
/// `cairn_llm_served_effect_chirho::LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO`).
pub const LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO: &str = "json-object";

/// The fixed system instruction the card sends; it carries no request PII (the business description
/// is the user turn), so it is a plain constant.
pub const DRAFT_SYSTEM_PROMPT_CHIRHO: &str = "You draft a small business landing page.";

/// A `llm-request-v1-chirho` guided brief, serialized to the exact wire shape the effect consumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmRequestV1Chirho {
    pub schema_chirho: String,
    pub system_chirho: String,
    pub user_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens_chirho: Option<u32>,
    pub response_format_chirho: String,
}

impl LlmRequestV1Chirho {
    /// Build the request from the submitted business description ONLY. The system turn is fixed and
    /// the user turn is the labelled brief the card draws its draft from; nothing else (no caller
    /// key) enters the request, so the prompt never carries the idempotency coordinate. The single
    /// description field names the business the page is drafted for.
    pub fn from_description_chirho(description_chirho: &str) -> Self {
        Self {
            schema_chirho: LLM_REQUEST_SCHEMA_CHIRHO.to_string(),
            system_chirho: DRAFT_SYSTEM_PROMPT_CHIRHO.to_string(),
            user_chirho: format!("Business name: {description_chirho}"),
            max_tokens_chirho: None,
            response_format_chirho: LLM_RESPONSE_FORMAT_JSON_OBJECT_CHIRHO.to_string(),
        }
    }
}
