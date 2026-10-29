// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Gate 1 semantic parity rung 2b: pure credit-hold lifecycle state and shadow reducer.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::clsd_chirho::ProjectionStateChirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::{
    BillingTagsChirho, CreditHoldRecordChirho, CreditHoldStatusChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const HOLD_SEMANTIC_STATES_SURFACE_CHIRHO: &str = "hold-semantic-states-chirho";
pub const HOLD_SEMANTIC_META_SURFACE_CHIRHO: &str = "hold-semantic-meta-chirho";
pub const HOLD_SEMANTIC_RECORD_COUNT_KEY_CHIRHO: &str = "hold-record-count-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldOpenStateChirho {
    pub hold_account_chirho: String,
    pub app_chirho: String,
    pub effect_chirho: String,
    pub caller_chirho: String,
    pub payer_chirho: String,
    pub authorized_token_chirho: i64,
    pub reserve_ledger_seq_chirho: u64,
    pub billing_tags_chirho: BillingTagsChirho,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldTerminalStateChirho {
    pub status_chirho: CreditHoldStatusChirho,
    pub settled_token_chirho: i64,
    pub released_token_chirho: i64,
    pub settlement_ledger_seq_chirho: Option<u64>,
    pub release_ledger_seq_chirho: Option<u64>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldLifecycleStateChirho {
    pub open_chirho: HoldOpenStateChirho,
    pub terminal_chirho: Option<HoldTerminalStateChirho>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldSemanticStateChirho {
    pub record_count_chirho: u64,
    pub holds_chirho: BTreeMap<String, HoldLifecycleStateChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldSemanticDiffChirho {
    pub key_chirho: String,
    pub left_chirho: Option<String>,
    pub right_chirho: Option<String>,
}

/// Part of `spec-chirho/workflows-chirho/audit-deep-pass-chirho.md`: this reducer is the
/// deterministic shadow road for Gate 1 semantic parity rung 2b.
pub fn hold_semantic_state_from_typed_records_chirho(
    records_chirho: &[CreditHoldRecordChirho],
) -> Result<HoldSemanticStateChirho> {
    let mut holds_chirho: BTreeMap<String, HoldLifecycleStateChirho> = BTreeMap::new();
    for (idx_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "hold semantic parity seq/order mismatch at line {}: record seq {}",
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        validate_common_hold_record_chirho(record_chirho)?;
        match record_chirho.status_chirho {
            CreditHoldStatusChirho::OpenChirho => {
                validate_open_record_chirho(record_chirho)?;
                if holds_chirho.contains_key(&record_chirho.hold_id_chirho) {
                    bail!(
                        "hold semantic parity duplicate open record for {}",
                        record_chirho.hold_id_chirho
                    );
                }
                holds_chirho.insert(
                    record_chirho.hold_id_chirho.clone(),
                    HoldLifecycleStateChirho {
                        open_chirho: open_state_from_record_chirho(record_chirho),
                        terminal_chirho: None,
                    },
                );
            }
            CreditHoldStatusChirho::SettledChirho | CreditHoldStatusChirho::ReleasedChirho => {
                validate_terminal_record_chirho(record_chirho)?;
                let state_chirho = holds_chirho
                    .get_mut(&record_chirho.hold_id_chirho)
                    .ok_or_else(|| {
                        anyhow!(
                            "hold semantic parity terminal before open for {}",
                            record_chirho.hold_id_chirho
                        )
                    })?;
                if state_chirho.terminal_chirho.is_some() {
                    bail!(
                        "hold semantic parity duplicate terminal record for {}",
                        record_chirho.hold_id_chirho
                    );
                }
                validate_terminal_matches_open_chirho(record_chirho, &state_chirho.open_chirho)?;
                state_chirho.terminal_chirho =
                    Some(terminal_state_from_record_chirho(record_chirho));
            }
        }
    }

    Ok(HoldSemanticStateChirho {
        record_count_chirho: u64::try_from(records_chirho.len())
            .map_err(|_| anyhow!("hold record count does not fit u64"))?,
        holds_chirho,
    })
}

pub fn hold_semantic_projection_state_chirho(
    state_chirho: &HoldSemanticStateChirho,
) -> Result<ProjectionStateChirho> {
    let mut projection_chirho = ProjectionStateChirho::default();
    projection_chirho.insert_chirho(
        HOLD_SEMANTIC_META_SURFACE_CHIRHO,
        HOLD_SEMANTIC_RECORD_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.record_count_chirho)?,
    );
    for (hold_id_chirho, state_chirho) in &state_chirho.holds_chirho {
        projection_chirho.insert_chirho(
            HOLD_SEMANTIC_STATES_SURFACE_CHIRHO,
            hold_semantic_state_key_chirho(hold_id_chirho)?,
            semantic_value_hash_chirho(state_chirho)?,
        );
    }
    Ok(projection_chirho)
}

pub fn hold_semantic_first_diff_chirho(
    left_chirho: &HoldSemanticStateChirho,
    right_chirho: &HoldSemanticStateChirho,
) -> Result<Option<HoldSemanticDiffChirho>> {
    if left_chirho.record_count_chirho != right_chirho.record_count_chirho {
        return Ok(Some(HoldSemanticDiffChirho {
            key_chirho: HOLD_SEMANTIC_RECORD_COUNT_KEY_CHIRHO.to_string(),
            left_chirho: Some(left_chirho.record_count_chirho.to_string()),
            right_chirho: Some(right_chirho.record_count_chirho.to_string()),
        }));
    }

    let mut keys_chirho = BTreeSet::new();
    keys_chirho.extend(left_chirho.holds_chirho.keys().cloned());
    keys_chirho.extend(right_chirho.holds_chirho.keys().cloned());
    for key_chirho in keys_chirho {
        let left_state_chirho = left_chirho.holds_chirho.get(&key_chirho);
        let right_state_chirho = right_chirho.holds_chirho.get(&key_chirho);
        if left_state_chirho != right_state_chirho {
            return Ok(Some(HoldSemanticDiffChirho {
                key_chirho: hold_semantic_state_key_chirho(&key_chirho)?,
                left_chirho: optional_state_text_chirho(left_state_chirho)?,
                right_chirho: optional_state_text_chirho(right_state_chirho)?,
            }));
        }
    }
    Ok(None)
}

pub fn hold_semantic_state_key_chirho(hold_id_chirho: &str) -> Result<String> {
    Ok(serde_json::to_string(hold_id_chirho)?)
}

fn optional_state_text_chirho(
    state_chirho: Option<&HoldLifecycleStateChirho>,
) -> Result<Option<String>> {
    Ok(match state_chirho {
        Some(state_chirho) => Some(serde_json::to_string(state_chirho)?),
        None => None,
    })
}

fn semantic_value_hash_chirho<TChirho: Serialize>(value_chirho: &TChirho) -> Result<HashChirho> {
    Ok(HashChirho(
        blake3::hash(&serde_json::to_vec(value_chirho)?)
            .to_hex()
            .to_string(),
    ))
}

fn validate_common_hold_record_chirho(record_chirho: &CreditHoldRecordChirho) -> Result<()> {
    require_nonempty_chirho("hold_id_chirho", &record_chirho.hold_id_chirho)?;
    require_nonempty_chirho("hold_account_chirho", &record_chirho.hold_account_chirho)?;
    require_nonempty_chirho("app_chirho", &record_chirho.app_chirho)?;
    require_nonempty_chirho("effect_chirho", &record_chirho.effect_chirho)?;
    require_nonempty_chirho("caller_chirho", &record_chirho.caller_chirho)?;
    require_nonempty_chirho("payer_chirho", &record_chirho.payer_chirho)?;
    if record_chirho.authorized_token_chirho <= 0 {
        bail!("hold semantic parity authorized_token_chirho must be positive");
    }
    record_chirho.billing_tags_chirho.validate_chirho()?;
    Ok(())
}

fn validate_open_record_chirho(record_chirho: &CreditHoldRecordChirho) -> Result<()> {
    if record_chirho.settled_token_chirho != 0
        || record_chirho.released_token_chirho != 0
        || record_chirho.settlement_ledger_seq_chirho.is_some()
        || record_chirho.release_ledger_seq_chirho.is_some()
    {
        bail!(
            "hold semantic parity open record carries terminal fields for {}",
            record_chirho.hold_id_chirho
        );
    }
    Ok(())
}

fn validate_terminal_record_chirho(record_chirho: &CreditHoldRecordChirho) -> Result<()> {
    if record_chirho.settled_token_chirho < 0 || record_chirho.released_token_chirho < 0 {
        bail!("hold semantic parity terminal amounts must be non-negative");
    }
    let total_chirho = record_chirho
        .settled_token_chirho
        .checked_add(record_chirho.released_token_chirho)
        .ok_or_else(|| anyhow!("hold semantic parity terminal amount overflow"))?;
    if total_chirho != record_chirho.authorized_token_chirho {
        bail!(
            "hold semantic parity terminal amounts settle/release {total_chirho}, not authorized {}",
            record_chirho.authorized_token_chirho
        );
    }

    match record_chirho.status_chirho {
        CreditHoldStatusChirho::OpenChirho => unreachable!("open handled separately"),
        CreditHoldStatusChirho::SettledChirho => {
            if record_chirho.settlement_ledger_seq_chirho.is_none()
                || record_chirho.release_ledger_seq_chirho.is_some()
            {
                bail!(
                    "hold semantic parity settled record has invalid ledger refs for {}",
                    record_chirho.hold_id_chirho
                );
            }
        }
        CreditHoldStatusChirho::ReleasedChirho => {
            if record_chirho.settled_token_chirho != 0
                || record_chirho.release_ledger_seq_chirho.is_none()
                || record_chirho.settlement_ledger_seq_chirho.is_some()
            {
                bail!(
                    "hold semantic parity released record has invalid ledger refs for {}",
                    record_chirho.hold_id_chirho
                );
            }
        }
    }
    Ok(())
}

fn validate_terminal_matches_open_chirho(
    terminal_chirho: &CreditHoldRecordChirho,
    open_chirho: &HoldOpenStateChirho,
) -> Result<()> {
    if terminal_chirho.hold_account_chirho != open_chirho.hold_account_chirho
        || terminal_chirho.app_chirho != open_chirho.app_chirho
        || terminal_chirho.effect_chirho != open_chirho.effect_chirho
        || terminal_chirho.caller_chirho != open_chirho.caller_chirho
        || terminal_chirho.payer_chirho != open_chirho.payer_chirho
        || terminal_chirho.authorized_token_chirho != open_chirho.authorized_token_chirho
        || terminal_chirho.reserve_ledger_seq_chirho != open_chirho.reserve_ledger_seq_chirho
        || terminal_chirho.billing_tags_chirho != open_chirho.billing_tags_chirho
    {
        bail!(
            "hold semantic parity terminal record does not match open record for {}",
            terminal_chirho.hold_id_chirho
        );
    }
    Ok(())
}

fn open_state_from_record_chirho(record_chirho: &CreditHoldRecordChirho) -> HoldOpenStateChirho {
    HoldOpenStateChirho {
        hold_account_chirho: record_chirho.hold_account_chirho.clone(),
        app_chirho: record_chirho.app_chirho.clone(),
        effect_chirho: record_chirho.effect_chirho.clone(),
        caller_chirho: record_chirho.caller_chirho.clone(),
        payer_chirho: record_chirho.payer_chirho.clone(),
        authorized_token_chirho: record_chirho.authorized_token_chirho,
        reserve_ledger_seq_chirho: record_chirho.reserve_ledger_seq_chirho,
        billing_tags_chirho: record_chirho.billing_tags_chirho.clone(),
        at_ms_chirho: record_chirho.at_ms_chirho,
    }
}

fn terminal_state_from_record_chirho(
    record_chirho: &CreditHoldRecordChirho,
) -> HoldTerminalStateChirho {
    HoldTerminalStateChirho {
        status_chirho: record_chirho.status_chirho.clone(),
        settled_token_chirho: record_chirho.settled_token_chirho,
        released_token_chirho: record_chirho.released_token_chirho,
        settlement_ledger_seq_chirho: record_chirho.settlement_ledger_seq_chirho,
        release_ledger_seq_chirho: record_chirho.release_ledger_seq_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    }
}

fn require_nonempty_chirho(field_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty() {
        bail!("hold semantic parity {field_chirho} must not be empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_model_economic_chirho::{BillingTagsChirho, CREDIT_HOLD_RECORD_SCHEMA_CHIRHO};

    fn open_record_chirho(seq_chirho: u64, hold_id_chirho: &str) -> CreditHoldRecordChirho {
        CreditHoldRecordChirho {
            seq_chirho,
            schema_chirho: CREDIT_HOLD_RECORD_SCHEMA_CHIRHO.to_string(),
            hold_id_chirho: hold_id_chirho.to_string(),
            hold_account_chirho: format!("platform/credit-hold/{hold_id_chirho}"),
            app_chirho: "app-chirho".to_string(),
            effect_chirho: "effect-chirho".to_string(),
            caller_chirho: "caller-chirho".to_string(),
            payer_chirho: "payer-chirho".to_string(),
            authorized_token_chirho: 10,
            settled_token_chirho: 0,
            released_token_chirho: 0,
            reserve_ledger_seq_chirho: seq_chirho,
            settlement_ledger_seq_chirho: None,
            release_ledger_seq_chirho: None,
            status_chirho: CreditHoldStatusChirho::OpenChirho,
            billing_tags_chirho: BillingTagsChirho::default(),
            at_ms_chirho: seq_chirho + 10,
            sig_chirho: "a".repeat(128),
        }
    }

    fn settled_record_chirho(
        seq_chirho: u64,
        open_chirho: &CreditHoldRecordChirho,
    ) -> CreditHoldRecordChirho {
        let mut record_chirho = open_chirho.clone();
        record_chirho.seq_chirho = seq_chirho;
        record_chirho.settled_token_chirho = 7;
        record_chirho.released_token_chirho = 3;
        record_chirho.settlement_ledger_seq_chirho = Some(8);
        record_chirho.release_ledger_seq_chirho = None;
        record_chirho.status_chirho = CreditHoldStatusChirho::SettledChirho;
        record_chirho.at_ms_chirho = seq_chirho + 10;
        record_chirho.sig_chirho = "b".repeat(128);
        record_chirho
    }

    fn released_record_chirho(
        seq_chirho: u64,
        open_chirho: &CreditHoldRecordChirho,
    ) -> CreditHoldRecordChirho {
        let mut record_chirho = open_chirho.clone();
        record_chirho.seq_chirho = seq_chirho;
        record_chirho.settled_token_chirho = 0;
        record_chirho.released_token_chirho = open_chirho.authorized_token_chirho;
        record_chirho.settlement_ledger_seq_chirho = None;
        record_chirho.release_ledger_seq_chirho = Some(9);
        record_chirho.status_chirho = CreditHoldStatusChirho::ReleasedChirho;
        record_chirho.at_ms_chirho = seq_chirho + 10;
        record_chirho.sig_chirho = "c".repeat(128);
        record_chirho
    }

    #[test]
    fn hold_semantic_reducer_accepts_open_state_chirho() {
        let state_chirho = hold_semantic_state_from_typed_records_chirho(&[open_record_chirho(
            0,
            "hold-open-chirho",
        )])
        .unwrap();
        assert_eq!(state_chirho.record_count_chirho, 1);
        assert_eq!(state_chirho.holds_chirho.len(), 1);
        assert!(state_chirho.holds_chirho["hold-open-chirho"]
            .terminal_chirho
            .is_none());
    }

    #[test]
    fn hold_semantic_reducer_accepts_released_and_settled_chirho() {
        let open_one_chirho = open_record_chirho(0, "hold-one-chirho");
        let release_one_chirho = released_record_chirho(1, &open_one_chirho);
        let open_two_chirho = open_record_chirho(2, "hold-two-chirho");
        let settle_two_chirho = settled_record_chirho(3, &open_two_chirho);
        let state_chirho = hold_semantic_state_from_typed_records_chirho(&[
            open_one_chirho,
            release_one_chirho,
            open_two_chirho,
            settle_two_chirho,
        ])
        .unwrap();
        assert_eq!(state_chirho.record_count_chirho, 4);
        assert_eq!(
            state_chirho.holds_chirho["hold-one-chirho"]
                .terminal_chirho
                .as_ref()
                .unwrap()
                .status_chirho,
            CreditHoldStatusChirho::ReleasedChirho
        );
        assert_eq!(
            state_chirho.holds_chirho["hold-two-chirho"]
                .terminal_chirho
                .as_ref()
                .unwrap()
                .status_chirho,
            CreditHoldStatusChirho::SettledChirho
        );
    }

    #[test]
    fn hold_semantic_reducer_rejects_terminal_before_open_chirho() {
        let open_chirho = open_record_chirho(1, "hold-order-chirho");
        let mut terminal_chirho = released_record_chirho(0, &open_chirho);
        terminal_chirho.seq_chirho = 0;
        let error_chirho =
            hold_semantic_state_from_typed_records_chirho(&[terminal_chirho, open_chirho])
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains("terminal before open"));
    }

    #[test]
    fn hold_semantic_reducer_rejects_duplicate_terminal_chirho() {
        let open_chirho = open_record_chirho(0, "hold-dup-chirho");
        let first_chirho = released_record_chirho(1, &open_chirho);
        let mut second_chirho = settled_record_chirho(2, &open_chirho);
        second_chirho.authorized_token_chirho = open_chirho.authorized_token_chirho;
        let error_chirho = hold_semantic_state_from_typed_records_chirho(&[
            open_chirho,
            first_chirho,
            second_chirho,
        ])
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("duplicate terminal"));
    }

    #[test]
    fn hold_semantic_reducer_rejects_open_terminal_fields_chirho() {
        let mut open_chirho = open_record_chirho(0, "hold-bad-open-chirho");
        open_chirho.released_token_chirho = 1;
        let error_chirho = hold_semantic_state_from_typed_records_chirho(&[open_chirho])
            .unwrap_err()
            .to_string();
        assert!(error_chirho.contains("open record carries terminal fields"));
    }

    #[test]
    fn hold_semantic_reducer_rejects_terminal_mismatch_chirho() {
        let open_chirho = open_record_chirho(0, "hold-mismatch-chirho");
        let mut terminal_chirho = released_record_chirho(1, &open_chirho);
        terminal_chirho.payer_chirho = "other-payer-chirho".to_string();
        let error_chirho =
            hold_semantic_state_from_typed_records_chirho(&[open_chirho, terminal_chirho])
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains("does not match open"));
    }

    #[test]
    fn hold_semantic_reducer_rejects_terminal_amount_overflow_chirho() {
        let open_chirho = open_record_chirho(0, "hold-overflow-chirho");
        let mut terminal_chirho = settled_record_chirho(1, &open_chirho);
        terminal_chirho.settled_token_chirho = i64::MAX;
        terminal_chirho.released_token_chirho = 1;
        let error_chirho =
            hold_semantic_state_from_typed_records_chirho(&[open_chirho, terminal_chirho])
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains("terminal amount overflow"));
    }

    #[test]
    fn hold_semantic_projection_and_diff_name_hold_chirho() {
        let open_chirho = open_record_chirho(0, "hold-diff-chirho");
        let mut left_chirho =
            hold_semantic_state_from_typed_records_chirho(std::slice::from_ref(&open_chirho))
                .unwrap();
        let mut right_chirho =
            hold_semantic_state_from_typed_records_chirho(std::slice::from_ref(&open_chirho))
                .unwrap();
        right_chirho
            .holds_chirho
            .get_mut("hold-diff-chirho")
            .unwrap()
            .open_chirho
            .authorized_token_chirho += 1;
        let diff_chirho = hold_semantic_first_diff_chirho(&left_chirho, &right_chirho)
            .unwrap()
            .unwrap();
        assert!(diff_chirho.key_chirho.contains("hold-diff-chirho"));
        let projection_chirho = hold_semantic_projection_state_chirho(&left_chirho).unwrap();
        assert!(projection_chirho
            .surfaces_chirho
            .contains_key(HOLD_SEMANTIC_STATES_SURFACE_CHIRHO));
        left_chirho.record_count_chirho += 1;
        let count_diff_chirho = hold_semantic_first_diff_chirho(&left_chirho, &right_chirho)
            .unwrap()
            .unwrap();
        assert_eq!(
            count_diff_chirho.key_chirho,
            HOLD_SEMANTIC_RECORD_COUNT_KEY_CHIRHO
        );
    }
}
