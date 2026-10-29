// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use crate::op_binding_chirho::OpBindingChirho;
use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

pub const LEDGER_ENTRY_SCHEMA_CHIRHO: &str = "ledger-entry-v1-chirho";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssetChirho {
    CashChirho,
    TokenChirho,
}

/// One leg of a transaction: a signed amount in an asset against an account (+credit / -debit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostingChirho {
    pub account_chirho: String,
    pub asset_chirho: AssetChirho,
    pub amount_chirho: i64,
}

/// Attribution carried by billable ledger and usage records.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingTagsChirho {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_id_chirho: Option<String>,
}

impl BillingTagsChirho {
    pub fn is_empty_chirho(&self) -> bool {
        self.user_id_chirho.is_none()
            && self.app_id_chirho.is_none()
            && self.run_id_chirho.is_none()
            && self.effect_id_chirho.is_none()
    }

    pub fn validate_chirho(&self) -> Result<()> {
        validate_optional_tag_chirho("user_id_chirho", &self.user_id_chirho)?;
        validate_optional_tag_chirho("app_id_chirho", &self.app_id_chirho)?;
        validate_optional_tag_chirho("effect_id_chirho", &self.effect_id_chirho)?;
        if let Some(run_id_chirho) = &self.run_id_chirho {
            if run_id_chirho.0.trim().is_empty() {
                bail!("run_id_chirho tag must not be empty");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceRequirementChirho {
    pub account_chirho: String,
    pub asset_chirho: AssetChirho,
    pub min_balance_chirho: i64,
    pub reason_chirho: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEntryChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub memo_chirho: String,
    pub postings_chirho: Vec<PostingChirho>,
    #[serde(default)]
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
    /// The schema-v2 operation binding. Biconditional with `schema_chirho`: schema-v2 ⟺ `Some`,
    /// v1/legacy ⟺ `None`. `skip_serializing_if` keeps legacy v1 rows byte-identical (the field is
    /// absent on the wire), preserving their exact stored bytes and signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_binding_chirho: Option<OpBindingChirho>,
}

fn validate_optional_tag_chirho(name_chirho: &str, value_chirho: &Option<String>) -> Result<()> {
    if let Some(value_chirho) = value_chirho {
        if value_chirho.trim().is_empty() {
            bail!("{name_chirho} tag must not be empty");
        }
    }
    Ok(())
}
