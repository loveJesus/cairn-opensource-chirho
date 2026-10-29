// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use crate::ledger_chirho::BillingTagsChirho;
use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const BILLING_POLICY_RECORD_SCHEMA_CHIRHO: &str = "billing-policy-record-v1-chirho";
pub const BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO: &str = "billing-policy-record-v2-chirho";
pub const BILLING_USAGE_RECORD_SCHEMA_CHIRHO: &str = "billing-usage-record-v1-chirho";
pub const BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO: &str = "billing-compensation-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BillingOverageChirho {
    FailClosedChirho,
    FallThroughUserPaysChirho,
}

impl BillingOverageChirho {
    pub fn parse_chirho(value_chirho: &str) -> Result<Self> {
        match value_chirho {
            "fail-closed" => Ok(Self::FailClosedChirho),
            "fall-through-user-pays" => Ok(Self::FallThroughUserPaysChirho),
            other_chirho => {
                bail!("unknown overage '{other_chirho}' (use fail-closed|fall-through-user-pays)")
            }
        }
    }

    pub fn label_chirho(&self) -> &'static str {
        match self {
            Self::FailClosedChirho => "fail-closed",
            Self::FallThroughUserPaysChirho => "fall-through-user-pays",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BillingPolicyModeChirho {
    UserPaysChirho,
    AppPaysChirho,
    SubsidyChirho {
        per_user_budget_chirho: i64,
        overage_chirho: BillingOverageChirho,
    },
}

impl BillingPolicyModeChirho {
    pub fn label_chirho(&self) -> String {
        match self {
            Self::UserPaysChirho => "user-pays".to_string(),
            Self::AppPaysChirho => "app-pays".to_string(),
            Self::SubsidyChirho {
                per_user_budget_chirho,
                overage_chirho,
            } => format!(
                "subsidy:{}:{}",
                per_user_budget_chirho,
                overage_chirho.label_chirho()
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBillingPolicyChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub default_chirho: BillingPolicyModeChirho,
    pub effect_overrides_chirho: BTreeMap<String, BillingPolicyModeChirho>,
    #[serde(default)]
    pub spend_caps_chirho: BillingSpendCapsChirho,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingSpendCapsChirho {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_user_cap_chirho: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cap_chirho: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingPolicyRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub billing_policy_chirho: HashChirho,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BillingPayerKindChirho {
    UserChirho,
    AppOwnerChirho,
    SubsidyOwnerChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBillingChirho {
    pub app_chirho: String,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub owner_principal_chirho: String,
    pub payer_chirho: String,
    pub payer_kind_chirho: BillingPayerKindChirho,
    pub price_chirho: i64,
    pub billing_policy_chirho: Option<HashChirho>,
    pub mode_chirho: BillingPolicyModeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingUsageRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub payer_kind_chirho: BillingPayerKindChirho,
    pub provider_chirho: String,
    pub price_chirho: i64,
    pub price_book_chirho: HashChirho,
    pub billing_policy_chirho: Option<HashChirho>,
    pub mode_chirho: BillingPolicyModeChirho,
    pub ledger_seq_chirho: u64,
    #[serde(default)]
    pub cache_hit_chirho: bool,
    #[serde(default)]
    pub nway_settlement_chirho: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_provider_chirho: Option<String>,
    #[serde(default)]
    pub external_cost_token_chirho: i64,
    #[serde(default)]
    pub platform_fee_chirho: i64,
    #[serde(default)]
    pub owner_margin_chirho: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_hold_chirho: Option<BillingCreditHoldChirho>,
    #[serde(default)]
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingCreditHoldChirho {
    pub hold_id_chirho: String,
    pub hold_account_chirho: String,
    pub authorized_token_chirho: i64,
    pub released_token_chirho: i64,
    pub reserve_ledger_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BillingUsageInputChirho {
    pub app_chirho: String,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub payer_kind_chirho: BillingPayerKindChirho,
    pub provider_chirho: String,
    pub price_chirho: i64,
    pub price_book_chirho: HashChirho,
    pub billing_policy_chirho: Option<HashChirho>,
    pub mode_chirho: BillingPolicyModeChirho,
    pub ledger_seq_chirho: u64,
    pub cache_hit_chirho: bool,
    pub nway_settlement_chirho: bool,
    pub external_provider_chirho: Option<String>,
    pub external_cost_token_chirho: i64,
    pub platform_fee_chirho: i64,
    pub owner_margin_chirho: i64,
    pub credit_hold_chirho: Option<BillingCreditHoldChirho>,
    pub billing_tags_chirho: BillingTagsChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingCompensationRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub original_usage_seq_chirho: u64,
    pub ledger_seq_chirho: u64,
    pub app_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub amount_token_chirho: i64,
    pub reason_chirho: String,
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBillingPolicyStateChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub billing_policy_chirho: HashChirho,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBillingUsageRecordStateChirho {
    pub app_chirho: String,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub payer_kind_chirho: BillingPayerKindChirho,
    pub provider_chirho: String,
    pub price_chirho: i64,
    pub price_book_chirho: HashChirho,
    pub billing_policy_chirho: Option<HashChirho>,
    pub mode_chirho: BillingPolicyModeChirho,
    pub ledger_seq_chirho: u64,
    pub cache_hit_chirho: bool,
    pub nway_settlement_chirho: bool,
    pub external_provider_chirho: Option<String>,
    pub external_cost_token_chirho: i64,
    pub platform_fee_chirho: i64,
    pub owner_margin_chirho: i64,
    pub credit_hold_chirho: Option<BillingCreditHoldChirho>,
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBillingCompensationRecordStateChirho {
    pub original_usage_seq_chirho: u64,
    pub ledger_seq_chirho: u64,
    pub app_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub amount_token_chirho: i64,
    pub reason_chirho: String,
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerifiedBillingAppKeyChirho {
    pub app_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerifiedBillingAppUserKeyChirho {
    pub app_chirho: String,
    pub caller_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerifiedBillingAppEffectKeyChirho {
    pub app_chirho: String,
    pub effect_chirho: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBillingAggregateChirho {
    pub usage_count_chirho: u64,
    pub gross_token_chirho: i64,
    pub compensation_count_chirho: u64,
    pub compensation_token_chirho: i64,
    pub net_token_chirho: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedBillingStatesChirho {
    pub policy_record_count_chirho: usize,
    pub usage_record_count_chirho: usize,
    pub compensation_record_count_chirho: usize,
    pub policy_records_chirho: BTreeMap<u64, VerifiedBillingPolicyStateChirho>,
    pub usage_records_chirho: BTreeMap<u64, VerifiedBillingUsageRecordStateChirho>,
    pub compensation_records_chirho: BTreeMap<u64, VerifiedBillingCompensationRecordStateChirho>,
    pub compensated_usage_seqs_chirho: BTreeSet<u64>,
    pub usage_by_app_chirho: BTreeMap<VerifiedBillingAppKeyChirho, VerifiedBillingAggregateChirho>,
    pub usage_by_app_user_chirho:
        BTreeMap<VerifiedBillingAppUserKeyChirho, VerifiedBillingAggregateChirho>,
    pub usage_by_app_effect_chirho:
        BTreeMap<VerifiedBillingAppEffectKeyChirho, VerifiedBillingAggregateChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BillingRollupAxisChirho {
    UserChirho,
    AppChirho,
    RunChirho,
    EffectChirho,
}

pub fn append_verified_billing_policy_state_chirho(
    states_chirho: &mut VerifiedBillingStatesChirho,
    record_chirho: &BillingPolicyRecordChirho,
) {
    states_chirho.policy_records_chirho.insert(
        record_chirho.seq_chirho,
        VerifiedBillingPolicyStateChirho {
            app_chirho: record_chirho.app_chirho.clone(),
            owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
            billing_policy_chirho: record_chirho.billing_policy_chirho.clone(),
            previous_chirho: record_chirho.previous_chirho.clone(),
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    );
}

pub fn append_verified_billing_usage_state_chirho(
    states_chirho: &mut VerifiedBillingStatesChirho,
    record_chirho: &BillingUsageRecordChirho,
) -> Result<()> {
    states_chirho.usage_records_chirho.insert(
        record_chirho.seq_chirho,
        VerifiedBillingUsageRecordStateChirho {
            app_chirho: record_chirho.app_chirho.clone(),
            effect_chirho: record_chirho.effect_chirho.clone(),
            caller_chirho: record_chirho.caller_chirho.clone(),
            payer_chirho: record_chirho.payer_chirho.clone(),
            payer_kind_chirho: record_chirho.payer_kind_chirho.clone(),
            provider_chirho: record_chirho.provider_chirho.clone(),
            price_chirho: record_chirho.price_chirho,
            price_book_chirho: record_chirho.price_book_chirho.clone(),
            billing_policy_chirho: record_chirho.billing_policy_chirho.clone(),
            mode_chirho: record_chirho.mode_chirho.clone(),
            ledger_seq_chirho: record_chirho.ledger_seq_chirho,
            cache_hit_chirho: record_chirho.cache_hit_chirho,
            nway_settlement_chirho: record_chirho.nway_settlement_chirho,
            external_provider_chirho: record_chirho.external_provider_chirho.clone(),
            external_cost_token_chirho: record_chirho.external_cost_token_chirho,
            platform_fee_chirho: record_chirho.platform_fee_chirho,
            owner_margin_chirho: record_chirho.owner_margin_chirho,
            credit_hold_chirho: record_chirho.credit_hold_chirho.clone(),
            billing_tags_chirho: record_chirho.billing_tags_chirho.clone(),
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    );
    add_billing_usage_aggregate_chirho(
        states_chirho
            .usage_by_app_chirho
            .entry(VerifiedBillingAppKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
            })
            .or_default(),
        record_chirho.price_chirho,
    )?;
    add_billing_usage_aggregate_chirho(
        states_chirho
            .usage_by_app_user_chirho
            .entry(VerifiedBillingAppUserKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                caller_chirho: record_chirho.caller_chirho.clone(),
            })
            .or_default(),
        record_chirho.price_chirho,
    )?;
    add_billing_usage_aggregate_chirho(
        states_chirho
            .usage_by_app_effect_chirho
            .entry(VerifiedBillingAppEffectKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                effect_chirho: record_chirho.effect_chirho.clone(),
            })
            .or_default(),
        record_chirho.price_chirho,
    )
}

pub fn append_verified_billing_compensation_state_chirho(
    states_chirho: &mut VerifiedBillingStatesChirho,
    record_chirho: &BillingCompensationRecordChirho,
    usage_chirho: &VerifiedBillingUsageRecordStateChirho,
) -> Result<()> {
    if !states_chirho
        .compensated_usage_seqs_chirho
        .insert(record_chirho.original_usage_seq_chirho)
    {
        bail!(
            "billing usage {} has more than one compensation",
            record_chirho.original_usage_seq_chirho
        );
    }
    states_chirho.compensation_records_chirho.insert(
        record_chirho.seq_chirho,
        VerifiedBillingCompensationRecordStateChirho {
            original_usage_seq_chirho: record_chirho.original_usage_seq_chirho,
            ledger_seq_chirho: record_chirho.ledger_seq_chirho,
            app_chirho: record_chirho.app_chirho.clone(),
            caller_chirho: record_chirho.caller_chirho.clone(),
            payer_chirho: record_chirho.payer_chirho.clone(),
            amount_token_chirho: record_chirho.amount_token_chirho,
            reason_chirho: record_chirho.reason_chirho.clone(),
            billing_tags_chirho: record_chirho.billing_tags_chirho.clone(),
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    );
    add_billing_compensation_aggregate_chirho(
        states_chirho
            .usage_by_app_chirho
            .entry(VerifiedBillingAppKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
            })
            .or_default(),
        record_chirho.amount_token_chirho,
    )?;
    add_billing_compensation_aggregate_chirho(
        states_chirho
            .usage_by_app_user_chirho
            .entry(VerifiedBillingAppUserKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                caller_chirho: record_chirho.caller_chirho.clone(),
            })
            .or_default(),
        record_chirho.amount_token_chirho,
    )?;
    add_billing_compensation_aggregate_chirho(
        states_chirho
            .usage_by_app_effect_chirho
            .entry(VerifiedBillingAppEffectKeyChirho {
                app_chirho: usage_chirho.app_chirho.clone(),
                effect_chirho: usage_chirho.effect_chirho.clone(),
            })
            .or_default(),
        record_chirho.amount_token_chirho,
    )
}

fn add_billing_usage_aggregate_chirho(
    aggregate_chirho: &mut VerifiedBillingAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.usage_count_chirho = aggregate_chirho
        .usage_count_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("billing semantic usage count overflow"))?;
    aggregate_chirho.gross_token_chirho = aggregate_chirho
        .gross_token_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic gross token overflow"))?;
    aggregate_chirho.net_token_chirho = aggregate_chirho
        .net_token_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic net token overflow"))?;
    Ok(())
}

fn add_billing_compensation_aggregate_chirho(
    aggregate_chirho: &mut VerifiedBillingAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.compensation_count_chirho = aggregate_chirho
        .compensation_count_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("billing semantic compensation count overflow"))?;
    aggregate_chirho.compensation_token_chirho = aggregate_chirho
        .compensation_token_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic compensation token overflow"))?;
    aggregate_chirho.net_token_chirho = aggregate_chirho
        .net_token_chirho
        .checked_sub(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic net token underflow"))?;
    Ok(())
}

impl BillingRollupAxisChirho {
    pub fn parse_chirho(value_chirho: &str) -> Result<Self> {
        match value_chirho {
            "user" => Ok(Self::UserChirho),
            "app" => Ok(Self::AppChirho),
            "run" => Ok(Self::RunChirho),
            "effect" => Ok(Self::EffectChirho),
            other_chirho => {
                bail!("unknown billing rollup axis '{other_chirho}' (use user|app|run|effect)")
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingRollupRowChirho {
    pub key_chirho: String,
    pub usage_count_chirho: u64,
    pub amount_chirho: i64,
}
