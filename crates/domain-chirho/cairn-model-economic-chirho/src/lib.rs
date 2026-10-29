// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure economic model records and wire contracts for pricebooks, metering, ledger, and billing.
//!
//! This crate owns serializable economic DTOs plus pure validation/canonical-message helpers. It
//! does not read a cairn root, sign records, verify owners, resolve prices, settle ledgers, or
//! perform billing effects.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

mod accounting_chirho;
mod billing_chirho;
pub mod billing_contract_chirho;
pub mod billing_postings_chirho;
mod external_chirho;
mod holds_chirho;
mod ledger_chirho;
pub mod op_binding_chirho;
mod pricebook_chirho;
mod resource_chirho;

pub use accounting_chirho::{
    AccountingAccountKindChirho, AccountingAdapterChirho, AccountingBalanceSheetChirho,
    AccountingChartAccountChirho, AccountingExportChirho, AccountingFinancialViewsChirho,
    AccountingJournalRowChirho, AccountingPeriodCloseChirho, AccountingProfitAndLossChirho,
    AccountingStatementRowChirho, AccountingTaxSummaryChirho, AccountingTaxSummaryRowChirho,
    AccountingTrialBalanceRowChirho, ACCOUNTING_EXPORT_SCHEMA_CHIRHO,
    ACCOUNTING_FINANCIAL_VIEWS_SCHEMA_CHIRHO,
};
pub use billing_chirho::{
    append_verified_billing_compensation_state_chirho, append_verified_billing_policy_state_chirho,
    append_verified_billing_usage_state_chirho, AppBillingPolicyChirho,
    BillingCompensationRecordChirho, BillingCreditHoldChirho, BillingOverageChirho,
    BillingPayerKindChirho, BillingPolicyModeChirho, BillingPolicyRecordChirho,
    BillingRollupAxisChirho, BillingRollupRowChirho, BillingSpendCapsChirho,
    BillingUsageInputChirho, BillingUsageRecordChirho, ResolvedBillingChirho,
    VerifiedBillingAggregateChirho, VerifiedBillingAppEffectKeyChirho, VerifiedBillingAppKeyChirho,
    VerifiedBillingAppUserKeyChirho, VerifiedBillingCompensationRecordStateChirho,
    VerifiedBillingPolicyStateChirho, VerifiedBillingStatesChirho,
    VerifiedBillingUsageRecordStateChirho, BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO,
    BILLING_POLICY_RECORD_SCHEMA_CHIRHO, BILLING_POLICY_RECORD_V2_SCHEMA_CHIRHO,
    BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
};
pub use external_chirho::ExternalUsageRecordChirho;
pub use holds_chirho::{
    CreditHoldRecordChirho, CreditHoldStatusChirho, CREDIT_HOLD_RECORD_SCHEMA_CHIRHO,
};
pub use ledger_chirho::{
    AssetChirho, BalanceRequirementChirho, BillingTagsChirho, LedgerEntryChirho, PostingChirho,
    LEDGER_ENTRY_SCHEMA_CHIRHO,
};
pub use op_binding_chirho::{
    AllowanceRefChirho, MoneyWriterAuthorityContextChirho, OpBindingChirho,
    OpBindingShapeErrorChirho, OpKindChirho, OpKindFieldRequirementsChirho,
    ALLOWANCE_WINDOW_LIFETIME_CHIRHO, LEDGER_ENTRY_SCHEMA_V2_CHIRHO,
};
pub use pricebook_chirho::{
    PriceBookChirho, PriceBookRecordChirho, PriceSourceChirho, ResolvedPriceChirho,
    PRICE_BOOK_RECORD_SCHEMA_CHIRHO, PRICE_BOOK_RECORD_V2_SCHEMA_CHIRHO,
};
pub use resource_chirho::{
    append_verified_resource_usage_state_chirho, AppResourcePolicyChirho,
    ResourceActionPolicyChirho, ResourceBalanceRowChirho, ResourceBalanceScopeChirho,
    ResourceBridgeKindChirho, ResourceBridgeRefChirho, ResourceChargeChirho,
    ResourceDecisionChirho, ResourceMeterChirho, ResourceOverageChirho, ResourcePolicyInputChirho,
    ResourcePolicyRecordChirho, ResourcePolicyUnsetRecordChirho, ResourceRollupAxisChirho,
    ResourceRollupRowChirho, ResourceUsageInputChirho, ResourceUsageRecordChirho,
    VerifiedResourceAppKeyChirho, VerifiedResourcePolicyStateChirho,
    VerifiedResourcePolicyUnsetStateChirho, VerifiedResourceRoutedAggregateChirho,
    VerifiedResourceStatesChirho, VerifiedResourceUsageAggregateChirho,
    VerifiedResourceUsageRecordStateChirho, VerifiedResourceUserKeyChirho,
    RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO, RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO,
    RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO, RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO,
};

#[cfg(test)]
mod tests_chirho;
