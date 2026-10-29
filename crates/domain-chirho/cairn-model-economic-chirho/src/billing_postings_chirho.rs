// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pure billing posting construction and verified-ledger linkage checks with no I/O.

use crate::billing_chirho::{BillingCreditHoldChirho, BillingUsageRecordChirho};
use crate::billing_contract_chirho::{
    is_split_cache_hit_usage_chirho, validate_cache_hit_split_chirho, validate_credit_hold_chirho,
};
use crate::ledger_chirho;
use anyhow::{anyhow, bail, Result};

pub const PLATFORM_FEE_ACCOUNT_CHIRHO: &str = "platform/fee";
pub const CACHE_HIT_SERVE_FEE_ACCOUNT_CHIRHO: &str = "platform/cache-hit";
pub const PLATFORM_REFUND_LOSS_ACCOUNT_CHIRHO: &str = "platform/refund-loss";

pub fn verify_credit_hold_usage_chirho(
    record_chirho: &BillingUsageRecordChirho,
    hold_chirho: &BillingCreditHoldChirho,
    settlement_entry_chirho: &ledger_chirho::LedgerEntryChirho,
    ledger_entries_chirho: &[ledger_chirho::LedgerEntryChirho],
) -> Result<()> {
    if !record_chirho.nway_settlement_chirho || record_chirho.cache_hit_chirho {
        bail!(
            "billing usage record {} has a credit hold outside live N-way settlement",
            record_chirho.seq_chirho
        );
    }
    validate_credit_hold_chirho(record_chirho.price_chirho, hold_chirho)?;
    let reserve_entry_chirho = ledger_entries_chirho
        .get(hold_chirho.reserve_ledger_seq_chirho as usize)
        .ok_or_else(|| {
            anyhow!(
                "billing usage record {} points at missing hold reserve ledger entry {}",
                record_chirho.seq_chirho,
                hold_chirho.reserve_ledger_seq_chirho
            )
        })?;
    if reserve_entry_chirho.billing_tags_chirho != record_chirho.billing_tags_chirho {
        bail!(
            "billing usage record {} hold reserve tags do not match usage tags",
            record_chirho.seq_chirho
        );
    }
    require_token_posting_chirho(
        reserve_entry_chirho,
        &record_chirho.payer_chirho,
        -hold_chirho.authorized_token_chirho,
    )?;
    require_token_posting_chirho(
        reserve_entry_chirho,
        &hold_chirho.hold_account_chirho,
        hold_chirho.authorized_token_chirho,
    )?;
    require_token_posting_chirho(
        settlement_entry_chirho,
        &hold_chirho.hold_account_chirho,
        -hold_chirho.authorized_token_chirho,
    )?;
    if hold_chirho.released_token_chirho > 0 {
        require_token_posting_chirho(
            settlement_entry_chirho,
            &record_chirho.payer_chirho,
            hold_chirho.released_token_chirho,
        )?;
    }
    Ok(())
}

pub fn verify_cache_hit_usage_postings_chirho(
    record_chirho: &BillingUsageRecordChirho,
    ledger_entry_chirho: &ledger_chirho::LedgerEntryChirho,
) -> Result<()> {
    if is_split_cache_hit_usage_chirho(
        record_chirho.cache_hit_chirho,
        record_chirho.platform_fee_chirho,
        record_chirho.owner_margin_chirho,
    ) {
        validate_cache_hit_split_chirho(
            record_chirho.price_chirho,
            record_chirho.external_provider_chirho.as_ref(),
            record_chirho.external_cost_token_chirho,
            record_chirho.platform_fee_chirho,
            record_chirho.owner_margin_chirho,
        )?;
        if record_chirho.platform_fee_chirho > 0 {
            require_token_posting_chirho(
                ledger_entry_chirho,
                CACHE_HIT_SERVE_FEE_ACCOUNT_CHIRHO,
                record_chirho.platform_fee_chirho,
            )?;
        }
        if record_chirho.owner_margin_chirho > 0 {
            require_token_posting_chirho(
                ledger_entry_chirho,
                &record_chirho.provider_chirho,
                record_chirho.owner_margin_chirho,
            )?;
        }
        return Ok(());
    }
    require_token_posting_chirho(
        ledger_entry_chirho,
        &record_chirho.provider_chirho,
        record_chirho.price_chirho,
    )
}

pub fn compensation_postings_for_usage_chirho(
    usage_chirho: &BillingUsageRecordChirho,
) -> Vec<ledger_chirho::PostingChirho> {
    let mut postings_chirho = Vec::new();
    if usage_chirho.nway_settlement_chirho {
        if usage_chirho.external_cost_token_chirho != 0 {
            postings_chirho.push(ledger_chirho::PostingChirho {
                account_chirho: PLATFORM_REFUND_LOSS_ACCOUNT_CHIRHO.to_string(),
                asset_chirho: ledger_chirho::AssetChirho::TokenChirho,
                amount_chirho: -usage_chirho.external_cost_token_chirho,
            });
        }
        if usage_chirho.platform_fee_chirho != 0 {
            postings_chirho.push(ledger_chirho::PostingChirho {
                account_chirho: PLATFORM_FEE_ACCOUNT_CHIRHO.to_string(),
                asset_chirho: ledger_chirho::AssetChirho::TokenChirho,
                amount_chirho: -usage_chirho.platform_fee_chirho,
            });
        }
        if usage_chirho.owner_margin_chirho != 0 {
            postings_chirho.push(ledger_chirho::PostingChirho {
                account_chirho: usage_chirho.provider_chirho.clone(),
                asset_chirho: ledger_chirho::AssetChirho::TokenChirho,
                amount_chirho: -usage_chirho.owner_margin_chirho,
            });
        }
    } else if is_split_cache_hit_usage_chirho(
        usage_chirho.cache_hit_chirho,
        usage_chirho.platform_fee_chirho,
        usage_chirho.owner_margin_chirho,
    ) {
        if usage_chirho.platform_fee_chirho != 0 {
            postings_chirho.push(ledger_chirho::PostingChirho {
                account_chirho: CACHE_HIT_SERVE_FEE_ACCOUNT_CHIRHO.to_string(),
                asset_chirho: ledger_chirho::AssetChirho::TokenChirho,
                amount_chirho: -usage_chirho.platform_fee_chirho,
            });
        }
        if usage_chirho.owner_margin_chirho != 0 {
            postings_chirho.push(ledger_chirho::PostingChirho {
                account_chirho: usage_chirho.provider_chirho.clone(),
                asset_chirho: ledger_chirho::AssetChirho::TokenChirho,
                amount_chirho: -usage_chirho.owner_margin_chirho,
            });
        }
    } else {
        postings_chirho.push(ledger_chirho::PostingChirho {
            account_chirho: usage_chirho.provider_chirho.clone(),
            asset_chirho: ledger_chirho::AssetChirho::TokenChirho,
            amount_chirho: -usage_chirho.price_chirho,
        });
    }
    postings_chirho.push(ledger_chirho::PostingChirho {
        account_chirho: usage_chirho.payer_chirho.clone(),
        asset_chirho: ledger_chirho::AssetChirho::TokenChirho,
        amount_chirho: usage_chirho.price_chirho,
    });
    postings_chirho
}

pub fn require_token_posting_chirho(
    entry_chirho: &ledger_chirho::LedgerEntryChirho,
    account_chirho: &str,
    amount_chirho: i64,
) -> Result<()> {
    if !entry_chirho.postings_chirho.iter().any(|posting_chirho| {
        posting_chirho.account_chirho == account_chirho
            && posting_chirho.asset_chirho == ledger_chirho::AssetChirho::TokenChirho
            && posting_chirho.amount_chirho == amount_chirho
    }) {
        bail!(
            "ledger entry {} missing token posting {} {}",
            entry_chirho.seq_chirho,
            account_chirho,
            amount_chirho
        );
    }
    Ok(())
}

pub fn verify_nway_usage_postings_chirho(
    record_chirho: &BillingUsageRecordChirho,
    ledger_entry_chirho: &ledger_chirho::LedgerEntryChirho,
) -> Result<()> {
    let expected_sum_chirho = record_chirho
        .external_cost_token_chirho
        .checked_add(record_chirho.platform_fee_chirho)
        .and_then(|amount_chirho| amount_chirho.checked_add(record_chirho.owner_margin_chirho))
        .ok_or_else(|| {
            anyhow!(
                "billing usage record {} N-way sum overflow",
                record_chirho.seq_chirho
            )
        })?;
    if expected_sum_chirho != record_chirho.price_chirho {
        bail!(
            "billing usage record {} N-way legs sum to {}, not price {}",
            record_chirho.seq_chirho,
            expected_sum_chirho,
            record_chirho.price_chirho
        );
    }
    if let Some(external_provider_chirho) = &record_chirho.external_provider_chirho {
        let suspense_account_chirho =
            format!("external_provider_suspense/{external_provider_chirho}");
        let has_suspense_chirho =
            ledger_entry_chirho
                .postings_chirho
                .iter()
                .any(|posting_chirho| {
                    posting_chirho.account_chirho == suspense_account_chirho
                        && posting_chirho.asset_chirho == ledger_chirho::AssetChirho::TokenChirho
                        && posting_chirho.amount_chirho == record_chirho.external_cost_token_chirho
                });
        if !has_suspense_chirho {
            bail!(
                "billing usage record {} missing external suspense leg in ledger entry {}",
                record_chirho.seq_chirho,
                ledger_entry_chirho.seq_chirho
            );
        }
    } else if record_chirho.external_cost_token_chirho != 0 {
        bail!(
            "billing usage record {} has external cost without external provider",
            record_chirho.seq_chirho
        );
    }
    let has_platform_fee_chirho =
        ledger_entry_chirho
            .postings_chirho
            .iter()
            .any(|posting_chirho| {
                posting_chirho.account_chirho == PLATFORM_FEE_ACCOUNT_CHIRHO
                    && posting_chirho.asset_chirho == ledger_chirho::AssetChirho::TokenChirho
                    && posting_chirho.amount_chirho == record_chirho.platform_fee_chirho
            });
    if !has_platform_fee_chirho {
        bail!(
            "billing usage record {} missing platform fee leg in ledger entry {}",
            record_chirho.seq_chirho,
            ledger_entry_chirho.seq_chirho
        );
    }
    let has_owner_margin_chirho =
        ledger_entry_chirho
            .postings_chirho
            .iter()
            .any(|posting_chirho| {
                posting_chirho.account_chirho == record_chirho.provider_chirho
                    && posting_chirho.asset_chirho == ledger_chirho::AssetChirho::TokenChirho
                    && posting_chirho.amount_chirho == record_chirho.owner_margin_chirho
            });
    if !has_owner_margin_chirho {
        bail!(
            "billing usage record {} missing owner margin leg in ledger entry {}",
            record_chirho.seq_chirho,
            ledger_entry_chirho.seq_chirho
        );
    }
    Ok(())
}
