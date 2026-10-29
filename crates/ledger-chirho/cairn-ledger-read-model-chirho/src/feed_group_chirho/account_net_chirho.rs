// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Generic account-net projection over a journal's verified head state.
//!
//! This fold is the production home for the CF6/CF7 balance view. It never accepts raw records or
//! storage authority: [`ProjectionFoldPortChirho`] supplies only a verified journal. The money
//! quantity is coded once by converting the verified counters into
//! [`cairn_ledger_model_chirho::account_state_chirho::AccountStateChirho`] and calling its reviewed
//! `net_money_chirho`; money-audit re-exports the same implementation, and this module does not
//! reimplement credits-minus-debits arithmetic.
//!
//! Workflows:
//! - `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`
//! - `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`

use crate::feeder_chirho::{ProjectionFoldPortChirho, VerifiedSourceStateChirho};
use anyhow::{bail, Context, Result};
use cairn_ledger_model_chirho::account_state_chirho::AccountStateChirho;
use cairn_ledger_model_chirho::ids_chirho::{AccountIdChirho, DigestChirho};
use cairn_ledger_model_chirho::projection_json_chirho::{
    canonical_projection_json_bytes_chirho, parse_canonical_projection_json_value_chirho,
};
use cairn_ledger_model_chirho::record_chirho::LegPostStateChirho;
use cairn_ledger_model_chirho::wire_chirho::validate_ledger_account_identifier_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO: &str =
    "ledger-account-net-projection-view-v1-chirho";
pub const ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO: usize = 256;
const ACCOUNT_NET_PROJECTION_FOLD_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-ledger-account-net-projection-fold-v1-chirho";
const ACCOUNT_NET_SOURCE_SCHEMA_DOMAIN_V1_CHIRHO: &[u8] =
    b"cairn-ledger-verified-head-state-source-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountNetProjectionRowChirho {
    pub account_chirho: AccountIdChirho,
    pub account_net_chirho: u64,
}

/// Canonical disposable view bytes. The rows are ordered by the verified journal's BTreeMap
/// account coordinate; the signed follow receipt, not this DTO, binds the source cut.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountNetProjectionViewChirho {
    pub schema_chirho: String,
    pub rows_chirho: Vec<AccountNetProjectionRowChirho>,
}

/// One bounded slice of the verified account-head map.
///
/// Rows remain canonical ascending while the cursor walks from the highest account downward. A
/// caller cannot select the page size, so one invocation allocates at most one fixed page plus one
/// borrowed lookahead entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountNetProjectionPageSliceChirho {
    pub rows_chirho: Vec<AccountNetProjectionRowChirho>,
    pub next_upper_exclusive_account_chirho: Option<AccountIdChirho>,
}

pub fn account_net_projection_fold_ref_chirho() -> DigestChirho {
    DigestChirho(
        blake3::hash(ACCOUNT_NET_PROJECTION_FOLD_DOMAIN_V1_CHIRHO)
            .to_hex()
            .to_string(),
    )
}

pub fn account_net_source_schema_ref_chirho() -> DigestChirho {
    DigestChirho(
        blake3::hash(ACCOUNT_NET_SOURCE_SCHEMA_DOMAIN_V1_CHIRHO)
            .to_hex()
            .to_string(),
    )
}

pub fn canonical_account_net_projection_view_chirho(
    view_chirho: &AccountNetProjectionViewChirho,
) -> Result<Vec<u8>> {
    validate_account_net_projection_view_chirho(view_chirho)?;
    canonical_projection_json_bytes_chirho(view_chirho)
        .context("encode canonical account-net projection view")
}

fn validate_account_net_projection_view_chirho(
    view_chirho: &AccountNetProjectionViewChirho,
) -> Result<()> {
    if view_chirho.schema_chirho != ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO {
        bail!("unsupported account-net projection view schema");
    }
    if !view_chirho
        .rows_chirho
        .windows(2)
        .all(|pair_chirho| pair_chirho[0].account_chirho < pair_chirho[1].account_chirho)
    {
        bail!("account-net projection rows must be strictly ordered and unique");
    }
    if view_chirho.rows_chirho.iter().any(|row_chirho| {
        validate_ledger_account_identifier_chirho(&row_chirho.account_chirho).is_err()
    }) {
        bail!("account-net projection account coordinate violates the ledger wire law");
    }
    Ok(())
}

pub fn parse_canonical_account_net_projection_view_chirho(
    bytes_chirho: &[u8],
) -> Result<AccountNetProjectionViewChirho> {
    let value_chirho = parse_canonical_projection_json_value_chirho(bytes_chirho)
        .context("decode exact-canonical account-net projection view")?;
    let view_chirho: AccountNetProjectionViewChirho =
        serde_json::from_value(value_chirho).context("decode account-net projection view")?;
    validate_account_net_projection_view_chirho(&view_chirho)?;
    Ok(view_chirho)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AccountNetProjectionFoldChirho;

impl ProjectionFoldPortChirho for AccountNetProjectionFoldChirho {
    fn fold_chirho(&self, source_chirho: &VerifiedSourceStateChirho<'_>) -> Result<Vec<u8>> {
        canonical_account_net_projection_view_chirho(&account_net_view_from_verified_heads_chirho(
            source_chirho.journal_chirho.head_states_chirho(),
        )?)
    }
}

pub fn account_net_projection_page_chirho(
    source_chirho: &VerifiedSourceStateChirho<'_>,
    upper_exclusive_chirho: Option<&AccountIdChirho>,
) -> Result<AccountNetProjectionPageSliceChirho> {
    account_net_projection_page_from_verified_heads_chirho(
        source_chirho.journal_chirho.head_states_chirho(),
        upper_exclusive_chirho,
    )
}

fn account_net_view_from_verified_heads_chirho(
    heads_chirho: &BTreeMap<AccountIdChirho, LegPostStateChirho>,
) -> Result<AccountNetProjectionViewChirho> {
    let rows_chirho = heads_chirho
        .iter()
        .map(|(account_chirho, post_chirho)| {
            account_net_projection_row_chirho(account_chirho, post_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AccountNetProjectionViewChirho {
        schema_chirho: ACCOUNT_NET_PROJECTION_VIEW_SCHEMA_V1_CHIRHO.to_owned(),
        rows_chirho,
    })
}

fn account_net_projection_page_from_verified_heads_chirho(
    heads_chirho: &BTreeMap<AccountIdChirho, LegPostStateChirho>,
    upper_exclusive_chirho: Option<&AccountIdChirho>,
) -> Result<AccountNetProjectionPageSliceChirho> {
    let mut entries_chirho = if let Some(upper_exclusive_chirho) = upper_exclusive_chirho {
        heads_chirho
            .range(..upper_exclusive_chirho)
            .rev()
            .take(ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO + 1)
            .collect::<Vec<_>>()
    } else {
        heads_chirho
            .iter()
            .rev()
            .take(ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO + 1)
            .collect::<Vec<_>>()
    };
    let has_more_chirho = entries_chirho.len() > ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO;
    entries_chirho.truncate(ACCOUNT_NET_PROJECTION_PAGE_ROWS_CHIRHO);
    let next_upper_exclusive_account_chirho = has_more_chirho
        .then(|| {
            entries_chirho
                .last()
                .map(|entry_chirho| entry_chirho.0.clone())
        })
        .flatten();
    let mut rows_chirho = entries_chirho
        .into_iter()
        .map(|(account_chirho, post_chirho)| {
            account_net_projection_row_chirho(account_chirho, post_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    rows_chirho.reverse();
    Ok(AccountNetProjectionPageSliceChirho {
        rows_chirho,
        next_upper_exclusive_account_chirho,
    })
}

/// Derive one canonical account-net row from independently verified account-head state.
///
/// This pure conversion is shared by ordinary projection paging and GD7's read-only
/// cross-artifact composition proof. It carries no journal, storage, or mutation authority.
pub fn account_net_projection_row_chirho(
    account_chirho: &AccountIdChirho,
    post_chirho: &LegPostStateChirho,
) -> Result<AccountNetProjectionRowChirho> {
    validate_ledger_account_identifier_chirho(account_chirho).map_err(|error_chirho| {
        anyhow::anyhow!("validate account-net projection account coordinate: {error_chirho:?}")
    })?;
    let state_chirho = AccountStateChirho {
        credits_chirho: post_chirho.credits_total_chirho,
        debits_chirho: post_chirho.debits_total_chirho,
        held_chirho: post_chirho.held_chirho,
    };
    let account_net_chirho = u64::try_from(state_chirho.net_money_chirho())
        .map_err(|_error_chirho| anyhow::anyhow!("verified account net is negative"))?;
    Ok(AccountNetProjectionRowChirho {
        account_chirho: account_chirho.clone(),
        account_net_chirho,
    })
}

#[cfg(test)]
#[path = "account_net_chirho/account_net_tests_chirho.rs"]
mod account_net_tests_chirho;
