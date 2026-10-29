// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use crate::ledger_chirho::AssetChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ACCOUNTING_EXPORT_SCHEMA_CHIRHO: &str = "accounting-export-v1-chirho";
pub const ACCOUNTING_FINANCIAL_VIEWS_SCHEMA_CHIRHO: &str = "accounting-financial-views-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AccountingAccountKindChirho {
    AssetChirho,
    LiabilityChirho,
    EquityChirho,
    RevenueChirho,
    ExpenseChirho,
    UnknownChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountingAdapterChirho {
    QuickBooksChirho,
    XeroChirho,
    NetSuiteChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingChartAccountChirho {
    pub account_chirho: String,
    pub asset_chirho: AssetChirho,
    pub kind_chirho: AccountingAccountKindChirho,
    pub tax_category_chirho: String,
    pub classification_note_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingJournalRowChirho {
    pub entry_seq_chirho: u64,
    pub line_seq_chirho: u64,
    pub at_ms_chirho: u64,
    pub memo_chirho: String,
    pub account_chirho: String,
    pub asset_chirho: AssetChirho,
    pub account_kind_chirho: AccountingAccountKindChirho,
    pub debit_chirho: i64,
    pub credit_chirho: i64,
    pub signed_amount_chirho: i64,
    pub user_id_chirho: Option<String>,
    pub app_id_chirho: Option<String>,
    pub run_id_chirho: Option<String>,
    pub effect_id_chirho: Option<String>,
    pub entry_sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingTrialBalanceRowChirho {
    pub account_chirho: String,
    pub asset_chirho: AssetChirho,
    pub kind_chirho: AccountingAccountKindChirho,
    pub debit_total_chirho: i64,
    pub credit_total_chirho: i64,
    pub net_signed_amount_chirho: i64,
    pub source_line_count_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingPeriodCloseChirho {
    pub ledger_cutoff_chirho: u64,
    pub period_entry_count_chirho: usize,
    pub period_line_count_chirho: usize,
    pub balanced_by_asset_chirho: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingStatementRowChirho {
    pub account_chirho: String,
    pub asset_chirho: AssetChirho,
    pub kind_chirho: AccountingAccountKindChirho,
    pub tax_category_chirho: String,
    pub debit_total_chirho: i64,
    pub credit_total_chirho: i64,
    pub statement_amount_chirho: i64,
    pub source_line_count_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingProfitAndLossChirho {
    pub rows_chirho: Vec<AccountingStatementRowChirho>,
    pub revenue_total_by_asset_chirho: BTreeMap<String, i64>,
    pub expense_total_by_asset_chirho: BTreeMap<String, i64>,
    pub net_income_by_asset_chirho: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingBalanceSheetChirho {
    pub rows_chirho: Vec<AccountingStatementRowChirho>,
    pub asset_total_by_asset_chirho: BTreeMap<String, i64>,
    pub liability_total_by_asset_chirho: BTreeMap<String, i64>,
    pub equity_total_by_asset_chirho: BTreeMap<String, i64>,
    pub current_earnings_by_asset_chirho: BTreeMap<String, i64>,
    pub accounting_equation_delta_by_asset_chirho: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingTaxSummaryRowChirho {
    pub tax_category_chirho: String,
    pub asset_chirho: AssetChirho,
    pub kind_chirho: AccountingAccountKindChirho,
    pub statement_amount_chirho: i64,
    pub source_account_count_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingTaxSummaryChirho {
    pub rows_chirho: Vec<AccountingTaxSummaryRowChirho>,
    pub taxable_revenue_by_asset_chirho: BTreeMap<String, i64>,
    pub deductible_expense_by_asset_chirho: BTreeMap<String, i64>,
    pub scope_note_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingFinancialViewsChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub generated_ms_chirho: u64,
    pub period_start_ms_chirho: u64,
    pub period_end_ms_chirho: u64,
    pub ledger_verified_count_chirho: usize,
    pub ledger_source_digest_chirho: String,
    pub profit_and_loss_chirho: AccountingProfitAndLossChirho,
    pub balance_sheet_chirho: AccountingBalanceSheetChirho,
    pub tax_summary_chirho: AccountingTaxSummaryChirho,
    pub trial_balance_chirho: Vec<AccountingTrialBalanceRowChirho>,
    pub period_close_chirho: AccountingPeriodCloseChirho,
    pub scope_notes_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountingExportChirho {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub generated_ms_chirho: u64,
    pub period_start_ms_chirho: u64,
    pub period_end_ms_chirho: u64,
    pub ledger_verified_count_chirho: usize,
    pub ledger_source_digest_chirho: String,
    pub chart_of_accounts_chirho: Vec<AccountingChartAccountChirho>,
    pub journal_rows_chirho: Vec<AccountingJournalRowChirho>,
    pub trial_balance_chirho: Vec<AccountingTrialBalanceRowChirho>,
    pub profit_and_loss_chirho: AccountingProfitAndLossChirho,
    pub balance_sheet_chirho: AccountingBalanceSheetChirho,
    pub tax_summary_chirho: AccountingTaxSummaryChirho,
    pub period_close_chirho: AccountingPeriodCloseChirho,
    pub scope_notes_chirho: Vec<String>,
}
