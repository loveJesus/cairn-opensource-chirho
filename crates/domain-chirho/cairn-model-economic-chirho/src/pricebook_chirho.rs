// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PRICE_BOOK_RECORD_SCHEMA_CHIRHO: &str = "price-book-record-v1-chirho";
pub const PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO: &str = "price-book-record-v2-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceBookChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub price_per_request_chirho: Option<i64>,
    pub effect_prices_chirho: BTreeMap<String, i64>,
    pub external_markup_bps_chirho: i64,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceBookRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub price_book_chirho: HashChirho,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PriceSourceChirho {
    EffectChirho,
    RequestChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPriceChirho {
    pub app_chirho: String,
    pub effect_chirho: String,
    pub price_chirho: i64,
    pub price_book_chirho: HashChirho,
    pub source_chirho: PriceSourceChirho,
}
