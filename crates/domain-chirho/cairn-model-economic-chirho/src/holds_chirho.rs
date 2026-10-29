// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure credit-hold record DTOs for Ring A money-log recovery.

use crate::ledger_chirho::BillingTagsChirho;
use serde::{Deserialize, Serialize};

pub const CREDIT_HOLD_RECORD_SCHEMA_CHIRHO: &str = "credit-hold-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditHoldStatusChirho {
    OpenChirho,
    SettledChirho,
    ReleasedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditHoldRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub hold_id_chirho: String,
    pub hold_account_chirho: String,
    pub app_chirho: String,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub authorized_token_chirho: i64,
    pub settled_token_chirho: i64,
    pub released_token_chirho: i64,
    pub reserve_ledger_seq_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_ledger_seq_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_ledger_seq_chirho: Option<u64>,
    pub status_chirho: CreditHoldStatusChirho,
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}
