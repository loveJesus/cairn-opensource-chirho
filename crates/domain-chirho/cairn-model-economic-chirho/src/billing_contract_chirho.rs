// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Billing record validation and canonical signed-message construction.

use crate::billing_chirho::{
    AppBillingPolicyChirho, BillingCompensationRecordChirho, BillingCreditHoldChirho,
    BillingPayerKindChirho, BillingPolicyModeChirho, BillingPolicyRecordChirho,
    BillingSpendCapsChirho, BillingUsageInputChirho, BillingUsageRecordChirho,
    BILLING_POLICY_RECORD_SCHEMA_CHIRHO, BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO,
};
use crate::ledger_chirho;
use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::Serialize;

pub fn validate_app_name_chirho(app_chirho: &str) -> Result<()> {
    if app_chirho.trim().is_empty() {
        bail!("app_chirho is required");
    }
    if app_chirho.contains('/') || app_chirho.chars().any(char::is_whitespace) {
        bail!("app_chirho must not contain slashes or whitespace");
    }
    Ok(())
}

pub fn latest_billing_policy_record_by_seq_chirho(
    records_chirho: &[BillingPolicyRecordChirho],
    app_chirho: &str,
) -> Option<BillingPolicyRecordChirho> {
    records_chirho
        .iter()
        .rev()
        .find(|record_chirho| record_chirho.app_chirho == app_chirho)
        .cloned()
}

pub fn validate_policy_chirho(policy_chirho: &AppBillingPolicyChirho) -> Result<()> {
    validate_app_name_chirho(&policy_chirho.app_chirho)?;
    ensure_owner_principal_name_chirho(&policy_chirho.owner_principal_chirho)?;
    validate_mode_chirho(&policy_chirho.default_chirho)?;
    for (effect_chirho, mode_chirho) in &policy_chirho.effect_overrides_chirho {
        if effect_chirho.trim().is_empty() {
            bail!("effect policy key must not be empty");
        }
        validate_mode_chirho(mode_chirho)?;
    }
    validate_spend_caps_chirho(&policy_chirho.spend_caps_chirho)?;
    Ok(())
}

pub fn validate_spend_caps_chirho(spend_caps_chirho: &BillingSpendCapsChirho) -> Result<()> {
    if matches!(spend_caps_chirho.per_user_cap_chirho, Some(cap_chirho) if cap_chirho < 0) {
        bail!("per_user_cap_chirho must be non-negative");
    }
    if matches!(spend_caps_chirho.app_cap_chirho, Some(cap_chirho) if cap_chirho < 0) {
        bail!("app_cap_chirho must be non-negative");
    }
    Ok(())
}

fn validate_mode_chirho(mode_chirho: &BillingPolicyModeChirho) -> Result<()> {
    if let BillingPolicyModeChirho::SubsidyChirho {
        per_user_budget_chirho,
        ..
    } = mode_chirho
    {
        if *per_user_budget_chirho < 0 {
            bail!("subsidy per_user_budget_chirho must be non-negative");
        }
    }
    Ok(())
}

pub fn validate_usage_input_chirho(input_chirho: &BillingUsageInputChirho) -> Result<()> {
    validate_app_name_chirho(&input_chirho.app_chirho)?;
    if input_chirho.effect_chirho.trim().is_empty() {
        bail!("effect_chirho is required");
    }
    if input_chirho.caller_chirho.trim().is_empty() {
        bail!("caller_chirho is required");
    }
    if input_chirho.payer_chirho.trim().is_empty() {
        bail!("payer_chirho is required");
    }
    if input_chirho.provider_chirho.trim().is_empty() {
        bail!("provider_chirho is required");
    }
    if input_chirho.price_chirho <= 0 {
        bail!("price_chirho must be positive");
    }
    if input_chirho.cache_hit_chirho && input_chirho.nway_settlement_chirho {
        bail!("billing usage cannot be both cache-hit and N-way settlement");
    }
    if input_chirho.external_cost_token_chirho < 0 {
        bail!("external_cost_token_chirho must be non-negative");
    }
    if input_chirho.platform_fee_chirho < 0 {
        bail!("platform_fee_chirho must be non-negative");
    }
    if input_chirho.cache_hit_chirho {
        if is_split_cache_hit_usage_chirho(
            input_chirho.cache_hit_chirho,
            input_chirho.platform_fee_chirho,
            input_chirho.owner_margin_chirho,
        ) {
            validate_cache_hit_split_chirho(
                input_chirho.price_chirho,
                input_chirho.external_provider_chirho.as_ref(),
                input_chirho.external_cost_token_chirho,
                input_chirho.platform_fee_chirho,
                input_chirho.owner_margin_chirho,
            )?;
        } else if input_chirho.external_provider_chirho.is_some()
            || input_chirho.external_cost_token_chirho != 0
        {
            bail!("cache-hit billing usage must not carry external provider cost");
        }
    } else if !input_chirho.nway_settlement_chirho
        && (input_chirho.external_provider_chirho.is_some()
            || input_chirho.external_cost_token_chirho != 0
            || input_chirho.platform_fee_chirho != 0
            || input_chirho.owner_margin_chirho != 0)
    {
        bail!("non-N-way billing usage must not carry N-way settlement amounts");
    }
    if let Some(hold_chirho) = &input_chirho.credit_hold_chirho {
        if !input_chirho.nway_settlement_chirho || input_chirho.cache_hit_chirho {
            bail!("credit hold billing usage must be live N-way settlement");
        }
        validate_credit_hold_chirho(input_chirho.price_chirho, hold_chirho)?;
    }
    input_chirho.billing_tags_chirho.validate_chirho()?;
    if let Some(user_id_chirho) = &input_chirho.billing_tags_chirho.user_id_chirho {
        if user_id_chirho != &input_chirho.caller_chirho {
            bail!("billing user_id_chirho tag must match caller_chirho");
        }
    }
    if let Some(app_id_chirho) = &input_chirho.billing_tags_chirho.app_id_chirho {
        if app_id_chirho != &input_chirho.app_chirho {
            bail!("billing app_id_chirho tag must match app_chirho");
        }
    }
    if let Some(effect_id_chirho) = &input_chirho.billing_tags_chirho.effect_id_chirho {
        if effect_id_chirho != &input_chirho.effect_chirho {
            bail!("billing effect_id_chirho tag must match effect_chirho");
        }
    }
    validate_mode_chirho(&input_chirho.mode_chirho)?;
    Ok(())
}

pub fn validate_usage_record_chirho(record_chirho: &BillingUsageRecordChirho) -> Result<()> {
    validate_usage_input_chirho(&BillingUsageInputChirho {
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
    })
}

pub fn validate_compensation_record_chirho(
    record_chirho: &BillingCompensationRecordChirho,
) -> Result<()> {
    validate_app_name_chirho(&record_chirho.app_chirho)?;
    if record_chirho.caller_chirho.trim().is_empty() {
        bail!("compensation caller_chirho is required");
    }
    if record_chirho.payer_chirho.trim().is_empty() {
        bail!("compensation payer_chirho is required");
    }
    if record_chirho.amount_token_chirho <= 0 {
        bail!("compensation amount_token_chirho must be positive");
    }
    if record_chirho.reason_chirho.trim().is_empty() {
        bail!("compensation reason_chirho is required");
    }
    record_chirho.billing_tags_chirho.validate_chirho()?;
    Ok(())
}

pub fn verify_compensation_matches_usage_chirho(
    record_chirho: &BillingCompensationRecordChirho,
    usage_chirho: &BillingUsageRecordChirho,
) -> Result<()> {
    if record_chirho.app_chirho != usage_chirho.app_chirho
        || record_chirho.caller_chirho != usage_chirho.caller_chirho
        || record_chirho.payer_chirho != usage_chirho.payer_chirho
        || record_chirho.amount_token_chirho != usage_chirho.price_chirho
    {
        bail!(
            "billing compensation {} does not match original usage {}",
            record_chirho.seq_chirho,
            record_chirho.original_usage_seq_chirho
        );
    }
    Ok(())
}

pub fn validate_credit_hold_chirho(
    price_chirho: i64,
    hold_chirho: &BillingCreditHoldChirho,
) -> Result<()> {
    if hold_chirho.hold_id_chirho.trim().is_empty() {
        bail!("credit hold id must not be empty");
    }
    if hold_chirho.hold_account_chirho.trim().is_empty() {
        bail!("credit hold account must not be empty");
    }
    if hold_chirho.authorized_token_chirho <= 0 {
        bail!("credit hold authorized_token_chirho must be positive");
    }
    if hold_chirho.released_token_chirho < 0 {
        bail!("credit hold released_token_chirho must be non-negative");
    }
    let expected_chirho = price_chirho
        .checked_add(hold_chirho.released_token_chirho)
        .ok_or_else(|| anyhow!("credit hold amount overflow"))?;
    if hold_chirho.authorized_token_chirho != expected_chirho {
        bail!(
            "credit hold authorized {} must equal price {} plus release {}",
            hold_chirho.authorized_token_chirho,
            price_chirho,
            hold_chirho.released_token_chirho
        );
    }
    Ok(())
}

pub fn is_split_cache_hit_usage_chirho(
    cache_hit_chirho: bool,
    platform_fee_chirho: i64,
    owner_margin_chirho: i64,
) -> bool {
    cache_hit_chirho && (platform_fee_chirho != 0 || owner_margin_chirho != 0)
}

pub fn validate_cache_hit_split_chirho(
    price_chirho: i64,
    external_provider_chirho: Option<&String>,
    external_cost_token_chirho: i64,
    platform_fee_chirho: i64,
    owner_margin_chirho: i64,
) -> Result<()> {
    if external_provider_chirho.is_some() || external_cost_token_chirho != 0 {
        bail!("cache-hit split must not carry external provider cost");
    }
    if owner_margin_chirho < 0 {
        bail!("cache-hit owner_margin_chirho must be non-negative");
    }
    let total_chirho = platform_fee_chirho
        .checked_add(owner_margin_chirho)
        .ok_or_else(|| anyhow!("cache-hit split overflow"))?;
    if total_chirho != price_chirho {
        bail!(
            "cache-hit split platform fee {} plus owner margin {} must equal price {}",
            platform_fee_chirho,
            owner_margin_chirho,
            price_chirho
        );
    }
    Ok(())
}

fn ensure_owner_principal_name_chirho(owner_principal_chirho: &str) -> Result<()> {
    if !owner_principal_chirho.starts_with("owner/") {
        bail!("app owner must be an owner principal");
    }
    Ok(())
}

fn nonempty_schema_chirho(schema_chirho: &str) -> Option<&str> {
    (!schema_chirho.is_empty()).then_some(schema_chirho)
}

pub fn verify_billing_record_schema_chirho(
    schema_chirho: &str,
    expected_chirho: &str,
    label_chirho: &str,
) -> Result<()> {
    if !schema_chirho.is_empty() && schema_chirho != expected_chirho {
        bail!("unsupported {label_chirho} schema '{schema_chirho}'");
    }
    Ok(())
}

pub fn verify_billing_policy_record_schema_chirho(schema_chirho: &str) -> Result<()> {
    if !schema_chirho.is_empty()
        && schema_chirho != BILLING_POLICY_RECORD_SCHEMA_CHIRHO
        && schema_chirho != BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO
    {
        bail!("unsupported billing policy record schema '{schema_chirho}'");
    }
    Ok(())
}

pub fn policy_record_message_chirho(record_chirho: &BillingPolicyRecordChirho) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct PolicyRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        billing_policy_chirho: &'a HashChirho,
        previous_chirho: &'a Option<HashChirho>,
        at_ms_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        transition_id_chirho: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prepared_writer_fence_epoch_chirho: Option<u64>,
    }
    Ok(serde_json::to_vec(&PolicyRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        billing_policy_chirho: &record_chirho.billing_policy_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
        transition_id_chirho: nonempty_schema_chirho(&record_chirho.transition_id_chirho),
        prepared_writer_fence_epoch_chirho: record_chirho.prepared_writer_fence_epoch_chirho,
    })?)
}

pub fn compensation_record_message_chirho(
    record_chirho: &BillingCompensationRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct CompensationRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        original_usage_seq_chirho: u64,
        ledger_seq_chirho: u64,
        app_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        amount_token_chirho: i64,
        reason_chirho: &'a str,
        billing_tags_chirho: &'a ledger_chirho::BillingTagsChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&CompensationRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        original_usage_seq_chirho: record_chirho.original_usage_seq_chirho,
        ledger_seq_chirho: record_chirho.ledger_seq_chirho,
        app_chirho: &record_chirho.app_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        amount_token_chirho: record_chirho.amount_token_chirho,
        reason_chirho: &record_chirho.reason_chirho,
        billing_tags_chirho: &record_chirho.billing_tags_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

pub fn usage_record_message_chirho(record_chirho: &BillingUsageRecordChirho) -> Result<Vec<u8>> {
    if record_chirho.credit_hold_chirho.is_some() {
        return held_nway_usage_record_message_chirho(record_chirho);
    }
    if record_chirho.nway_settlement_chirho {
        return nway_usage_record_message_chirho(record_chirho);
    }
    if record_chirho.cache_hit_chirho {
        if is_split_cache_hit_usage_chirho(
            record_chirho.cache_hit_chirho,
            record_chirho.platform_fee_chirho,
            record_chirho.owner_margin_chirho,
        ) {
            return split_cache_hit_usage_record_message_chirho(record_chirho);
        }
        return cache_hit_usage_record_message_chirho(record_chirho);
    }
    if record_chirho.billing_tags_chirho.is_empty_chirho() {
        return legacy_usage_record_message_chirho(record_chirho);
    }
    #[derive(Serialize)]
    struct TaggedUsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        payer_kind_chirho: &'a BillingPayerKindChirho,
        provider_chirho: &'a str,
        price_chirho: i64,
        price_book_chirho: &'a HashChirho,
        billing_policy_chirho: &'a Option<HashChirho>,
        mode_chirho: &'a BillingPolicyModeChirho,
        ledger_seq_chirho: u64,
        billing_tags_chirho: &'a ledger_chirho::BillingTagsChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&TaggedUsageRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        payer_kind_chirho: &record_chirho.payer_kind_chirho,
        provider_chirho: &record_chirho.provider_chirho,
        price_chirho: record_chirho.price_chirho,
        price_book_chirho: &record_chirho.price_book_chirho,
        billing_policy_chirho: &record_chirho.billing_policy_chirho,
        mode_chirho: &record_chirho.mode_chirho,
        ledger_seq_chirho: record_chirho.ledger_seq_chirho,
        billing_tags_chirho: &record_chirho.billing_tags_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn held_nway_usage_record_message_chirho(
    record_chirho: &BillingUsageRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct HeldNWayUsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        payer_kind_chirho: &'a BillingPayerKindChirho,
        provider_chirho: &'a str,
        price_chirho: i64,
        price_book_chirho: &'a HashChirho,
        billing_policy_chirho: &'a Option<HashChirho>,
        mode_chirho: &'a BillingPolicyModeChirho,
        ledger_seq_chirho: u64,
        nway_settlement_chirho: bool,
        external_provider_chirho: &'a Option<String>,
        external_cost_token_chirho: i64,
        platform_fee_chirho: i64,
        owner_margin_chirho: i64,
        credit_hold_chirho: &'a Option<BillingCreditHoldChirho>,
        billing_tags_chirho: &'a ledger_chirho::BillingTagsChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&HeldNWayUsageRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        payer_kind_chirho: &record_chirho.payer_kind_chirho,
        provider_chirho: &record_chirho.provider_chirho,
        price_chirho: record_chirho.price_chirho,
        price_book_chirho: &record_chirho.price_book_chirho,
        billing_policy_chirho: &record_chirho.billing_policy_chirho,
        mode_chirho: &record_chirho.mode_chirho,
        ledger_seq_chirho: record_chirho.ledger_seq_chirho,
        nway_settlement_chirho: record_chirho.nway_settlement_chirho,
        external_provider_chirho: &record_chirho.external_provider_chirho,
        external_cost_token_chirho: record_chirho.external_cost_token_chirho,
        platform_fee_chirho: record_chirho.platform_fee_chirho,
        owner_margin_chirho: record_chirho.owner_margin_chirho,
        credit_hold_chirho: &record_chirho.credit_hold_chirho,
        billing_tags_chirho: &record_chirho.billing_tags_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn nway_usage_record_message_chirho(record_chirho: &BillingUsageRecordChirho) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct NWayUsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        payer_kind_chirho: &'a BillingPayerKindChirho,
        provider_chirho: &'a str,
        price_chirho: i64,
        price_book_chirho: &'a HashChirho,
        billing_policy_chirho: &'a Option<HashChirho>,
        mode_chirho: &'a BillingPolicyModeChirho,
        ledger_seq_chirho: u64,
        nway_settlement_chirho: bool,
        external_provider_chirho: &'a Option<String>,
        external_cost_token_chirho: i64,
        platform_fee_chirho: i64,
        owner_margin_chirho: i64,
        billing_tags_chirho: &'a ledger_chirho::BillingTagsChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&NWayUsageRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        payer_kind_chirho: &record_chirho.payer_kind_chirho,
        provider_chirho: &record_chirho.provider_chirho,
        price_chirho: record_chirho.price_chirho,
        price_book_chirho: &record_chirho.price_book_chirho,
        billing_policy_chirho: &record_chirho.billing_policy_chirho,
        mode_chirho: &record_chirho.mode_chirho,
        ledger_seq_chirho: record_chirho.ledger_seq_chirho,
        nway_settlement_chirho: record_chirho.nway_settlement_chirho,
        external_provider_chirho: &record_chirho.external_provider_chirho,
        external_cost_token_chirho: record_chirho.external_cost_token_chirho,
        platform_fee_chirho: record_chirho.platform_fee_chirho,
        owner_margin_chirho: record_chirho.owner_margin_chirho,
        billing_tags_chirho: &record_chirho.billing_tags_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn cache_hit_usage_record_message_chirho(
    record_chirho: &BillingUsageRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct CacheHitUsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        payer_kind_chirho: &'a BillingPayerKindChirho,
        provider_chirho: &'a str,
        price_chirho: i64,
        price_book_chirho: &'a HashChirho,
        billing_policy_chirho: &'a Option<HashChirho>,
        mode_chirho: &'a BillingPolicyModeChirho,
        ledger_seq_chirho: u64,
        cache_hit_chirho: bool,
        billing_tags_chirho: &'a ledger_chirho::BillingTagsChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&CacheHitUsageRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        payer_kind_chirho: &record_chirho.payer_kind_chirho,
        provider_chirho: &record_chirho.provider_chirho,
        price_chirho: record_chirho.price_chirho,
        price_book_chirho: &record_chirho.price_book_chirho,
        billing_policy_chirho: &record_chirho.billing_policy_chirho,
        mode_chirho: &record_chirho.mode_chirho,
        ledger_seq_chirho: record_chirho.ledger_seq_chirho,
        cache_hit_chirho: record_chirho.cache_hit_chirho,
        billing_tags_chirho: &record_chirho.billing_tags_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn split_cache_hit_usage_record_message_chirho(
    record_chirho: &BillingUsageRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct SplitCacheHitUsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        payer_kind_chirho: &'a BillingPayerKindChirho,
        provider_chirho: &'a str,
        price_chirho: i64,
        price_book_chirho: &'a HashChirho,
        billing_policy_chirho: &'a Option<HashChirho>,
        mode_chirho: &'a BillingPolicyModeChirho,
        ledger_seq_chirho: u64,
        cache_hit_chirho: bool,
        external_provider_chirho: &'a Option<String>,
        external_cost_token_chirho: i64,
        platform_fee_chirho: i64,
        owner_margin_chirho: i64,
        billing_tags_chirho: &'a ledger_chirho::BillingTagsChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(
        &SplitCacheHitUsageRecordMessageChirho {
            seq_chirho: record_chirho.seq_chirho,
            schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
            app_chirho: &record_chirho.app_chirho,
            effect_chirho: &record_chirho.effect_chirho,
            caller_chirho: &record_chirho.caller_chirho,
            payer_chirho: &record_chirho.payer_chirho,
            payer_kind_chirho: &record_chirho.payer_kind_chirho,
            provider_chirho: &record_chirho.provider_chirho,
            price_chirho: record_chirho.price_chirho,
            price_book_chirho: &record_chirho.price_book_chirho,
            billing_policy_chirho: &record_chirho.billing_policy_chirho,
            mode_chirho: &record_chirho.mode_chirho,
            ledger_seq_chirho: record_chirho.ledger_seq_chirho,
            cache_hit_chirho: record_chirho.cache_hit_chirho,
            external_provider_chirho: &record_chirho.external_provider_chirho,
            external_cost_token_chirho: record_chirho.external_cost_token_chirho,
            platform_fee_chirho: record_chirho.platform_fee_chirho,
            owner_margin_chirho: record_chirho.owner_margin_chirho,
            billing_tags_chirho: &record_chirho.billing_tags_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?)
}

fn legacy_usage_record_message_chirho(record_chirho: &BillingUsageRecordChirho) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct UsageRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        effect_chirho: &'a str,
        caller_chirho: &'a str,
        payer_chirho: &'a str,
        payer_kind_chirho: &'a BillingPayerKindChirho,
        provider_chirho: &'a str,
        price_chirho: i64,
        price_book_chirho: &'a HashChirho,
        billing_policy_chirho: &'a Option<HashChirho>,
        mode_chirho: &'a BillingPolicyModeChirho,
        ledger_seq_chirho: u64,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&UsageRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        effect_chirho: &record_chirho.effect_chirho,
        caller_chirho: &record_chirho.caller_chirho,
        payer_chirho: &record_chirho.payer_chirho,
        payer_kind_chirho: &record_chirho.payer_kind_chirho,
        provider_chirho: &record_chirho.provider_chirho,
        price_chirho: record_chirho.price_chirho,
        price_book_chirho: &record_chirho.price_book_chirho,
        billing_policy_chirho: &record_chirho.billing_policy_chirho,
        mode_chirho: &record_chirho.mode_chirho,
        ledger_seq_chirho: record_chirho.ledger_seq_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}
