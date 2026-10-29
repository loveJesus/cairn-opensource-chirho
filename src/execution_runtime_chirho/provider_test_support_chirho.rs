// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::model_chirho::HashChirho;

pub(crate) fn current_effect_contract_set_chirho() -> HashChirho {
    cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho(
        &cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho(
        ),
    )
    .expect("canonical descriptor-v2 contract set")
}

pub(crate) fn llm_request_bytes_chirho(prompt_chirho: &str) -> Vec<u8> {
    serde_json::json!({
        "prompt_chirho": prompt_chirho,
        "max_tokens_chirho": 1,
        "max_price_per_token_chirho": 17
    })
    .to_string()
    .into_bytes()
}
