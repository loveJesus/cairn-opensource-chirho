// For God so loved the world, that He gave His only begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Gate 1 semantic parity rung 2a: pure ledger semantic state and shadow reducer.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::clsd_chirho::ProjectionStateChirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::{AssetChirho, LedgerEntryChirho};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const LEDGER_SEMANTIC_BALANCES_SURFACE_CHIRHO: &str = "ledger-semantic-balances-chirho";
pub const LEDGER_SEMANTIC_META_SURFACE_CHIRHO: &str = "ledger-semantic-meta-chirho";
pub const LEDGER_SEMANTIC_ENTRY_COUNT_KEY_CHIRHO: &str = "entry-count-chirho";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LedgerBalanceKeyChirho {
    pub account_chirho: String,
    pub asset_chirho: AssetChirho,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSemanticStateChirho {
    pub entry_count_chirho: u64,
    pub balances_chirho: BTreeMap<LedgerBalanceKeyChirho, i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSemanticDiffChirho {
    pub key_chirho: String,
    pub left_chirho: Option<i64>,
    pub right_chirho: Option<i64>,
}

/// Part of `spec-chirho/workflows-chirho/audit-deep-pass-chirho.md`: this reducer is the
/// deterministic shadow road for Gate 1 semantic parity rung 2a.
pub fn ledger_semantic_state_from_typed_entries_chirho(
    entries_chirho: &[LedgerEntryChirho],
) -> Result<LedgerSemanticStateChirho> {
    let mut balances_chirho: BTreeMap<LedgerBalanceKeyChirho, i64> = BTreeMap::new();
    for (idx_chirho, entry_chirho) in entries_chirho.iter().enumerate() {
        if entry_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "ledger semantic parity seq/order mismatch at line {}: entry seq {}",
                idx_chirho,
                entry_chirho.seq_chirho
            );
        }
        for posting_chirho in &entry_chirho.postings_chirho {
            let key_chirho = LedgerBalanceKeyChirho {
                account_chirho: posting_chirho.account_chirho.clone(),
                asset_chirho: posting_chirho.asset_chirho,
            };
            let balance_chirho = balances_chirho.entry(key_chirho).or_insert(0);
            *balance_chirho = balance_chirho
                .checked_add(posting_chirho.amount_chirho)
                .ok_or_else(|| anyhow!("ledger semantic parity balance overflow"))?;
        }
    }
    Ok(LedgerSemanticStateChirho {
        entry_count_chirho: u64::try_from(entries_chirho.len())
            .map_err(|_| anyhow!("ledger entry count does not fit u64"))?,
        balances_chirho,
    })
}

pub fn ledger_semantic_state_from_live_balances_chirho(
    entry_count_chirho: usize,
    balances_chirho: &BTreeMap<(String, AssetChirho), i64>,
) -> Result<LedgerSemanticStateChirho> {
    let mut semantic_balances_chirho = BTreeMap::new();
    for ((account_chirho, asset_chirho), amount_chirho) in balances_chirho {
        semantic_balances_chirho.insert(
            LedgerBalanceKeyChirho {
                account_chirho: account_chirho.clone(),
                asset_chirho: *asset_chirho,
            },
            *amount_chirho,
        );
    }
    Ok(LedgerSemanticStateChirho {
        entry_count_chirho: u64::try_from(entry_count_chirho)
            .map_err(|_| anyhow!("ledger live entry count does not fit u64"))?,
        balances_chirho: semantic_balances_chirho,
    })
}

pub fn ledger_semantic_projection_state_chirho(
    state_chirho: &LedgerSemanticStateChirho,
) -> Result<ProjectionStateChirho> {
    let mut projection_chirho = ProjectionStateChirho::default();
    projection_chirho.insert_chirho(
        LEDGER_SEMANTIC_META_SURFACE_CHIRHO,
        LEDGER_SEMANTIC_ENTRY_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.entry_count_chirho)?,
    );
    for (key_chirho, amount_chirho) in &state_chirho.balances_chirho {
        projection_chirho.insert_chirho(
            LEDGER_SEMANTIC_BALANCES_SURFACE_CHIRHO,
            structural_balance_key_chirho(key_chirho)?,
            semantic_value_hash_chirho(amount_chirho)?,
        );
    }
    Ok(projection_chirho)
}

pub fn ledger_semantic_first_diff_chirho(
    left_chirho: &LedgerSemanticStateChirho,
    right_chirho: &LedgerSemanticStateChirho,
) -> Result<Option<LedgerSemanticDiffChirho>> {
    if left_chirho.entry_count_chirho != right_chirho.entry_count_chirho {
        return Ok(Some(LedgerSemanticDiffChirho {
            key_chirho: LEDGER_SEMANTIC_ENTRY_COUNT_KEY_CHIRHO.to_string(),
            left_chirho: Some(
                i64::try_from(left_chirho.entry_count_chirho)
                    .map_err(|_| anyhow!("left ledger entry count does not fit diff integer"))?,
            ),
            right_chirho: Some(
                i64::try_from(right_chirho.entry_count_chirho)
                    .map_err(|_| anyhow!("right ledger entry count does not fit diff integer"))?,
            ),
        }));
    }

    let mut keys_chirho = BTreeSet::new();
    keys_chirho.extend(left_chirho.balances_chirho.keys().cloned());
    keys_chirho.extend(right_chirho.balances_chirho.keys().cloned());
    for key_chirho in keys_chirho {
        let left_amount_chirho = left_chirho.balances_chirho.get(&key_chirho).copied();
        let right_amount_chirho = right_chirho.balances_chirho.get(&key_chirho).copied();
        if left_amount_chirho != right_amount_chirho {
            return Ok(Some(LedgerSemanticDiffChirho {
                key_chirho: structural_balance_key_chirho(&key_chirho)?,
                left_chirho: left_amount_chirho,
                right_chirho: right_amount_chirho,
            }));
        }
    }
    Ok(None)
}

pub fn structural_balance_key_chirho(key_chirho: &LedgerBalanceKeyChirho) -> Result<String> {
    Ok(serde_json::to_string(key_chirho)?)
}

fn semantic_value_hash_chirho<TChirho: Serialize>(value_chirho: &TChirho) -> Result<HashChirho> {
    Ok(HashChirho(
        blake3::hash(&serde_json::to_vec(value_chirho)?)
            .to_hex()
            .to_string(),
    ))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_model_economic_chirho::{BillingTagsChirho, PostingChirho};

    fn entry_chirho(seq_chirho: u64, postings_chirho: Vec<PostingChirho>) -> LedgerEntryChirho {
        LedgerEntryChirho {
            seq_chirho,
            schema_chirho: cairn_model_economic_chirho::LEDGER_ENTRY_SCHEMA_CHIRHO.to_string(),
            memo_chirho: format!("entry-{seq_chirho}-chirho"),
            postings_chirho,
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: seq_chirho,
            sig_chirho: "a".repeat(128),
            op_binding_chirho: None,
        }
    }

    fn posting_chirho(
        account_chirho: &str,
        asset_chirho: AssetChirho,
        amount_chirho: i64,
    ) -> PostingChirho {
        PostingChirho {
            account_chirho: account_chirho.to_string(),
            asset_chirho,
            amount_chirho,
        }
    }

    #[test]
    fn ledger_semantic_reducer_folds_hand_computable_balances_chirho() {
        let entries_chirho = vec![
            entry_chirho(
                0,
                vec![
                    posting_chirho("alice-chirho", AssetChirho::TokenChirho, -10),
                    posting_chirho("platform-chirho", AssetChirho::TokenChirho, 10),
                ],
            ),
            entry_chirho(
                1,
                vec![
                    posting_chirho("alice-chirho", AssetChirho::CashChirho, 25),
                    posting_chirho("cash-mint-chirho", AssetChirho::CashChirho, -25),
                ],
            ),
        ];

        let state_chirho =
            ledger_semantic_state_from_typed_entries_chirho(&entries_chirho).unwrap();
        assert_eq!(state_chirho.entry_count_chirho, 2);
        assert_eq!(
            state_chirho.balances_chirho[&LedgerBalanceKeyChirho {
                account_chirho: "alice-chirho".to_string(),
                asset_chirho: AssetChirho::TokenChirho,
            }],
            -10
        );
        assert_eq!(
            state_chirho.balances_chirho[&LedgerBalanceKeyChirho {
                account_chirho: "alice-chirho".to_string(),
                asset_chirho: AssetChirho::CashChirho,
            }],
            25
        );
    }

    #[test]
    fn ledger_semantic_reducer_rejects_seq_reorder_chirho() {
        let entries_chirho = vec![entry_chirho(1, Vec::new())];
        let error_chirho = ledger_semantic_state_from_typed_entries_chirho(&entries_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("seq/order mismatch"));
    }

    #[test]
    fn ledger_semantic_reducer_rejects_overflow_chirho() {
        let entries_chirho = vec![entry_chirho(
            0,
            vec![
                posting_chirho("overflow-chirho", AssetChirho::TokenChirho, i64::MAX),
                posting_chirho("overflow-chirho", AssetChirho::TokenChirho, 1),
            ],
        )];
        let error_chirho = ledger_semantic_state_from_typed_entries_chirho(&entries_chirho)
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("overflow"));
    }

    #[test]
    fn ledger_semantic_balance_key_is_structural_not_joined_chirho() {
        let first_chirho = LedgerBalanceKeyChirho {
            account_chirho: "a:b-chirho".to_string(),
            asset_chirho: AssetChirho::TokenChirho,
        };
        let second_chirho = LedgerBalanceKeyChirho {
            account_chirho: "a-chirho".to_string(),
            asset_chirho: AssetChirho::TokenChirho,
        };
        let first_key_chirho = structural_balance_key_chirho(&first_chirho).unwrap();
        let second_key_chirho = structural_balance_key_chirho(&second_chirho).unwrap();
        assert_ne!(first_key_chirho, second_key_chirho);
        assert!(first_key_chirho.contains("account_chirho"));
        assert!(first_key_chirho.contains("asset_chirho"));
    }

    #[test]
    fn ledger_semantic_diff_names_first_divergent_key_chirho() {
        let mut left_chirho = LedgerSemanticStateChirho {
            entry_count_chirho: 1,
            balances_chirho: BTreeMap::new(),
        };
        let mut right_chirho = left_chirho.clone();
        let key_chirho = LedgerBalanceKeyChirho {
            account_chirho: "alice-chirho".to_string(),
            asset_chirho: AssetChirho::TokenChirho,
        };
        left_chirho.balances_chirho.insert(key_chirho.clone(), 10);
        right_chirho.balances_chirho.insert(key_chirho, 9);

        let diff_chirho = ledger_semantic_first_diff_chirho(&left_chirho, &right_chirho).unwrap();
        let diff_chirho = diff_chirho.expect("expected semantic diff");
        assert!(diff_chirho.key_chirho.contains("alice-chirho"));
        assert_eq!(diff_chirho.left_chirho, Some(10));
        assert_eq!(diff_chirho.right_chirho, Some(9));
    }

    #[test]
    fn ledger_semantic_projection_includes_count_and_balances_chirho() {
        let entries_chirho = vec![entry_chirho(
            0,
            vec![posting_chirho("alice-chirho", AssetChirho::TokenChirho, 7)],
        )];
        let state_chirho =
            ledger_semantic_state_from_typed_entries_chirho(&entries_chirho).unwrap();
        let projection_chirho = ledger_semantic_projection_state_chirho(&state_chirho).unwrap();
        assert!(projection_chirho
            .surfaces_chirho
            .contains_key(LEDGER_SEMANTIC_META_SURFACE_CHIRHO));
        assert!(projection_chirho
            .surfaces_chirho
            .contains_key(LEDGER_SEMANTIC_BALANCES_SURFACE_CHIRHO));
    }
}
