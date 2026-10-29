// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use crate::ledger_chirho::BillingTagsChirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalUsageRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub provider_chirho: String,
    pub model_chirho: String,
    pub effect_chirho: String,
    pub request_chirho: HashChirho,
    pub response_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_private_ref_chirho: Option<PrivateBlobRefChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_private_ref_chirho: Option<PrivateBlobRefChirho>,
    pub prompt_tokens_chirho: u64,
    pub completion_tokens_chirho: u64,
    pub total_tokens_chirho: u64,
    pub latency_ms_chirho: u64,
    pub price_record_seq_chirho: u64,
    pub input_microunits_per_token_chirho: i64,
    pub output_microunits_per_token_chirho: i64,
    pub cost_microunits_chirho: i64,
    pub cost_token_chirho: i64,
    pub ledger_seq_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspense_ledger_seq_chirho: Option<u64>,
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}
