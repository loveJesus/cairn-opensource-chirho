// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Gate 1 semantic parity rung 2e: pure billing policy/usage/compensation state.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::clsd_chirho::ProjectionStateChirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::{
    BillingCompensationRecordChirho, BillingPolicyRecordChirho, BillingUsageRecordChirho,
    VerifiedBillingAggregateChirho, VerifiedBillingAppEffectKeyChirho, VerifiedBillingAppKeyChirho,
    VerifiedBillingAppUserKeyChirho, VerifiedBillingCompensationRecordStateChirho,
    VerifiedBillingPolicyStateChirho, VerifiedBillingStatesChirho,
    VerifiedBillingUsageRecordStateChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const BILLING_SEMANTIC_META_SURFACE_CHIRHO: &str = "billing-semantic-meta-chirho";
pub const BILLING_SEMANTIC_POLICY_COUNT_KEY_CHIRHO: &str = "billing-policy-count-chirho";
pub const BILLING_SEMANTIC_USAGE_COUNT_KEY_CHIRHO: &str = "billing-usage-count-chirho";
pub const BILLING_SEMANTIC_COMPENSATION_COUNT_KEY_CHIRHO: &str =
    "billing-compensation-count-chirho";
pub const BILLING_SEMANTIC_POLICIES_SURFACE_CHIRHO: &str = "billing-semantic-policies-chirho";
pub const BILLING_SEMANTIC_USAGE_RECORDS_SURFACE_CHIRHO: &str =
    "billing-semantic-usage-records-chirho";
pub const BILLING_SEMANTIC_COMPENSATION_RECORDS_SURFACE_CHIRHO: &str =
    "billing-semantic-compensation-records-chirho";
pub const BILLING_SEMANTIC_USAGE_BY_APP_SURFACE_CHIRHO: &str =
    "billing-semantic-usage-by-app-chirho";
pub const BILLING_SEMANTIC_USAGE_BY_APP_USER_SURFACE_CHIRHO: &str =
    "billing-semantic-usage-by-app-user-chirho";
pub const BILLING_SEMANTIC_USAGE_BY_APP_EFFECT_SURFACE_CHIRHO: &str =
    "billing-semantic-usage-by-app-effect-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingSemanticDiffChirho {
    pub key_chirho: String,
    pub left_chirho: Option<String>,
    pub right_chirho: Option<String>,
}

/// Part of `spec-chirho/workflows-chirho/audit-deep-pass-chirho.md`: this reducer is the
/// deterministic shadow road for Gate 1 semantic parity rung 2e.
pub fn billing_semantic_state_from_typed_records_chirho(
    policies_chirho: &[BillingPolicyRecordChirho],
    usages_chirho: &[BillingUsageRecordChirho],
    compensations_chirho: &[BillingCompensationRecordChirho],
) -> Result<VerifiedBillingStatesChirho> {
    let mut state_chirho = VerifiedBillingStatesChirho {
        policy_record_count_chirho: policies_chirho.len(),
        usage_record_count_chirho: usages_chirho.len(),
        compensation_record_count_chirho: compensations_chirho.len(),
        ..VerifiedBillingStatesChirho::default()
    };

    for (idx_chirho, record_chirho) in policies_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "billing semantic parity policy seq/order mismatch at line {}: record seq {}",
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        state_chirho.policy_records_chirho.insert(
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

    for (idx_chirho, record_chirho) in usages_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "billing semantic parity usage seq/order mismatch at line {}: record seq {}",
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        insert_usage_state_chirho(&mut state_chirho, record_chirho)?;
    }

    for (idx_chirho, record_chirho) in compensations_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "billing semantic parity compensation seq/order mismatch at line {}: record seq {}",
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        insert_compensation_state_chirho(&mut state_chirho, record_chirho)?;
    }

    Ok(state_chirho)
}

pub fn billing_semantic_projection_state_chirho(
    state_chirho: &VerifiedBillingStatesChirho,
) -> Result<ProjectionStateChirho> {
    let mut projection_chirho = ProjectionStateChirho::default();
    projection_chirho.insert_chirho(
        BILLING_SEMANTIC_META_SURFACE_CHIRHO,
        BILLING_SEMANTIC_POLICY_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.policy_record_count_chirho)?,
    );
    projection_chirho.insert_chirho(
        BILLING_SEMANTIC_META_SURFACE_CHIRHO,
        BILLING_SEMANTIC_USAGE_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.usage_record_count_chirho)?,
    );
    projection_chirho.insert_chirho(
        BILLING_SEMANTIC_META_SURFACE_CHIRHO,
        BILLING_SEMANTIC_COMPENSATION_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.compensation_record_count_chirho)?,
    );
    insert_map_chirho(
        &mut projection_chirho,
        BILLING_SEMANTIC_POLICIES_SURFACE_CHIRHO,
        &state_chirho.policy_records_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        BILLING_SEMANTIC_USAGE_RECORDS_SURFACE_CHIRHO,
        &state_chirho.usage_records_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        BILLING_SEMANTIC_COMPENSATION_RECORDS_SURFACE_CHIRHO,
        &state_chirho.compensation_records_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        BILLING_SEMANTIC_USAGE_BY_APP_SURFACE_CHIRHO,
        &state_chirho.usage_by_app_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        BILLING_SEMANTIC_USAGE_BY_APP_USER_SURFACE_CHIRHO,
        &state_chirho.usage_by_app_user_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        BILLING_SEMANTIC_USAGE_BY_APP_EFFECT_SURFACE_CHIRHO,
        &state_chirho.usage_by_app_effect_chirho,
    )?;
    Ok(projection_chirho)
}

pub fn billing_semantic_first_diff_chirho(
    left_chirho: &VerifiedBillingStatesChirho,
    right_chirho: &VerifiedBillingStatesChirho,
) -> Result<Option<BillingSemanticDiffChirho>> {
    for (key_chirho, left_chirho, right_chirho) in [
        (
            BILLING_SEMANTIC_POLICY_COUNT_KEY_CHIRHO,
            left_chirho.policy_record_count_chirho.to_string(),
            right_chirho.policy_record_count_chirho.to_string(),
        ),
        (
            BILLING_SEMANTIC_USAGE_COUNT_KEY_CHIRHO,
            left_chirho.usage_record_count_chirho.to_string(),
            right_chirho.usage_record_count_chirho.to_string(),
        ),
        (
            BILLING_SEMANTIC_COMPENSATION_COUNT_KEY_CHIRHO,
            left_chirho.compensation_record_count_chirho.to_string(),
            right_chirho.compensation_record_count_chirho.to_string(),
        ),
    ] {
        if left_chirho != right_chirho {
            return Ok(Some(BillingSemanticDiffChirho {
                key_chirho: key_chirho.to_string(),
                left_chirho: Some(left_chirho),
                right_chirho: Some(right_chirho),
            }));
        }
    }

    for diff_chirho in [
        first_map_diff_chirho(
            BILLING_SEMANTIC_POLICIES_SURFACE_CHIRHO,
            &left_chirho.policy_records_chirho,
            &right_chirho.policy_records_chirho,
        )?,
        first_map_diff_chirho(
            BILLING_SEMANTIC_USAGE_RECORDS_SURFACE_CHIRHO,
            &left_chirho.usage_records_chirho,
            &right_chirho.usage_records_chirho,
        )?,
        first_map_diff_chirho(
            BILLING_SEMANTIC_COMPENSATION_RECORDS_SURFACE_CHIRHO,
            &left_chirho.compensation_records_chirho,
            &right_chirho.compensation_records_chirho,
        )?,
        first_map_diff_chirho(
            BILLING_SEMANTIC_USAGE_BY_APP_SURFACE_CHIRHO,
            &left_chirho.usage_by_app_chirho,
            &right_chirho.usage_by_app_chirho,
        )?,
        first_map_diff_chirho(
            BILLING_SEMANTIC_USAGE_BY_APP_USER_SURFACE_CHIRHO,
            &left_chirho.usage_by_app_user_chirho,
            &right_chirho.usage_by_app_user_chirho,
        )?,
        first_map_diff_chirho(
            BILLING_SEMANTIC_USAGE_BY_APP_EFFECT_SURFACE_CHIRHO,
            &left_chirho.usage_by_app_effect_chirho,
            &right_chirho.usage_by_app_effect_chirho,
        )?,
    ] {
        if diff_chirho.is_some() {
            return Ok(diff_chirho);
        }
    }
    Ok(None)
}

pub fn billing_app_key_chirho(key_chirho: &VerifiedBillingAppKeyChirho) -> Result<String> {
    Ok(serde_json::to_string(key_chirho)?)
}

pub fn billing_app_user_key_chirho(key_chirho: &VerifiedBillingAppUserKeyChirho) -> Result<String> {
    Ok(serde_json::to_string(key_chirho)?)
}

pub fn billing_app_effect_key_chirho(
    key_chirho: &VerifiedBillingAppEffectKeyChirho,
) -> Result<String> {
    Ok(serde_json::to_string(key_chirho)?)
}

fn insert_usage_state_chirho(
    state_chirho: &mut VerifiedBillingStatesChirho,
    record_chirho: &BillingUsageRecordChirho,
) -> Result<()> {
    state_chirho.usage_records_chirho.insert(
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
    add_usage_aggregate_chirho(
        state_chirho
            .usage_by_app_chirho
            .entry(VerifiedBillingAppKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
            })
            .or_default(),
        record_chirho.price_chirho,
    )?;
    add_usage_aggregate_chirho(
        state_chirho
            .usage_by_app_user_chirho
            .entry(VerifiedBillingAppUserKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                caller_chirho: record_chirho.caller_chirho.clone(),
            })
            .or_default(),
        record_chirho.price_chirho,
    )?;
    add_usage_aggregate_chirho(
        state_chirho
            .usage_by_app_effect_chirho
            .entry(VerifiedBillingAppEffectKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                effect_chirho: record_chirho.effect_chirho.clone(),
            })
            .or_default(),
        record_chirho.price_chirho,
    )
}

fn insert_compensation_state_chirho(
    state_chirho: &mut VerifiedBillingStatesChirho,
    record_chirho: &BillingCompensationRecordChirho,
) -> Result<()> {
    if !state_chirho
        .compensated_usage_seqs_chirho
        .insert(record_chirho.original_usage_seq_chirho)
    {
        bail!(
            "billing usage {} has more than one compensation",
            record_chirho.original_usage_seq_chirho
        );
    }
    let usage_chirho = state_chirho
        .usage_records_chirho
        .get(&record_chirho.original_usage_seq_chirho)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "billing compensation {} points at missing usage {}",
                record_chirho.seq_chirho,
                record_chirho.original_usage_seq_chirho
            )
        })?;
    state_chirho.compensation_records_chirho.insert(
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
    add_compensation_aggregate_chirho(
        state_chirho
            .usage_by_app_chirho
            .entry(VerifiedBillingAppKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
            })
            .or_default(),
        record_chirho.amount_token_chirho,
    )?;
    add_compensation_aggregate_chirho(
        state_chirho
            .usage_by_app_user_chirho
            .entry(VerifiedBillingAppUserKeyChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                caller_chirho: record_chirho.caller_chirho.clone(),
            })
            .or_default(),
        record_chirho.amount_token_chirho,
    )?;
    add_compensation_aggregate_chirho(
        state_chirho
            .usage_by_app_effect_chirho
            .entry(VerifiedBillingAppEffectKeyChirho {
                app_chirho: usage_chirho.app_chirho,
                effect_chirho: usage_chirho.effect_chirho,
            })
            .or_default(),
        record_chirho.amount_token_chirho,
    )
}

fn add_usage_aggregate_chirho(
    aggregate_chirho: &mut VerifiedBillingAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.usage_count_chirho = aggregate_chirho
        .usage_count_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("billing semantic parity usage count overflow"))?;
    aggregate_chirho.gross_token_chirho = aggregate_chirho
        .gross_token_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic parity gross token overflow"))?;
    aggregate_chirho.net_token_chirho = aggregate_chirho
        .net_token_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic parity net token overflow"))?;
    Ok(())
}

fn add_compensation_aggregate_chirho(
    aggregate_chirho: &mut VerifiedBillingAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.compensation_count_chirho = aggregate_chirho
        .compensation_count_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("billing semantic parity compensation count overflow"))?;
    aggregate_chirho.compensation_token_chirho = aggregate_chirho
        .compensation_token_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic parity compensation token overflow"))?;
    aggregate_chirho.net_token_chirho = aggregate_chirho
        .net_token_chirho
        .checked_sub(amount_chirho)
        .ok_or_else(|| anyhow!("billing semantic parity net token underflow"))?;
    Ok(())
}

fn insert_map_chirho<KChirho, VChirho>(
    projection_chirho: &mut ProjectionStateChirho,
    surface_chirho: &'static str,
    rows_chirho: &BTreeMap<KChirho, VChirho>,
) -> Result<()>
where
    KChirho: Serialize,
    VChirho: Serialize,
{
    for (key_chirho, value_chirho) in rows_chirho {
        projection_chirho.insert_chirho(
            surface_chirho,
            serde_json::to_string(key_chirho)?,
            semantic_value_hash_chirho(value_chirho)?,
        );
    }
    Ok(())
}

fn first_map_diff_chirho<KChirho, VChirho>(
    surface_chirho: &'static str,
    left_chirho: &BTreeMap<KChirho, VChirho>,
    right_chirho: &BTreeMap<KChirho, VChirho>,
) -> Result<Option<BillingSemanticDiffChirho>>
where
    KChirho: Clone + Ord + Serialize,
    VChirho: PartialEq + Serialize,
{
    let mut keys_chirho = BTreeSet::new();
    keys_chirho.extend(left_chirho.keys().cloned());
    keys_chirho.extend(right_chirho.keys().cloned());
    for key_chirho in keys_chirho {
        let left_value_chirho = left_chirho.get(&key_chirho);
        let right_value_chirho = right_chirho.get(&key_chirho);
        if left_value_chirho != right_value_chirho {
            return Ok(Some(BillingSemanticDiffChirho {
                key_chirho: format!("{surface_chirho}:{}", serde_json::to_string(&key_chirho)?),
                left_chirho: optional_value_text_chirho(left_value_chirho)?,
                right_chirho: optional_value_text_chirho(right_value_chirho)?,
            }));
        }
    }
    Ok(None)
}

fn optional_value_text_chirho<TChirho: Serialize>(
    value_chirho: Option<&TChirho>,
) -> Result<Option<String>> {
    Ok(match value_chirho {
        Some(value_chirho) => Some(serde_json::to_string(value_chirho)?),
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

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_model_economic_chirho::{
        BillingPayerKindChirho, BillingPolicyModeChirho, BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO,
        BILLING_POLICY_RECORD_SCHEMA_CHIRHO, BILLING_USAGE_RECORD_SCHEMA_CHIRHO,
    };

    fn hash_chirho(seed_chirho: char) -> HashChirho {
        HashChirho(seed_chirho.to_string().repeat(64))
    }

    fn policy_chirho(seq_chirho: u64) -> BillingPolicyRecordChirho {
        BillingPolicyRecordChirho {
            seq_chirho,
            schema_chirho: BILLING_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "billapp".to_string(),
            owner_principal_chirho: "owner-chirho".to_string(),
            billing_policy_chirho: hash_chirho('a'),
            previous_chirho: None,
            at_ms_chirho: seq_chirho,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: None,
            sig_chirho: "b".repeat(128),
        }
    }

    fn usage_chirho(
        seq_chirho: u64,
        caller_chirho: &str,
        price_chirho: i64,
    ) -> BillingUsageRecordChirho {
        BillingUsageRecordChirho {
            seq_chirho,
            schema_chirho: BILLING_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: "billapp".to_string(),
            effect_chirho: "effect-chirho".to_string(),
            caller_chirho: caller_chirho.to_string(),
            payer_chirho: caller_chirho.to_string(),
            payer_kind_chirho: BillingPayerKindChirho::UserChirho,
            provider_chirho: "provider-chirho".to_string(),
            price_chirho,
            price_book_chirho: hash_chirho('c'),
            billing_policy_chirho: Some(hash_chirho('a')),
            mode_chirho: BillingPolicyModeChirho::UserPaysChirho,
            ledger_seq_chirho: seq_chirho,
            cache_hit_chirho: false,
            nway_settlement_chirho: false,
            external_provider_chirho: None,
            external_cost_token_chirho: 0,
            platform_fee_chirho: 0,
            owner_margin_chirho: 0,
            credit_hold_chirho: None,
            billing_tags_chirho: Default::default(),
            at_ms_chirho: seq_chirho,
            sig_chirho: "d".repeat(128),
        }
    }

    fn compensation_chirho(
        seq_chirho: u64,
        usage_seq_chirho: u64,
    ) -> BillingCompensationRecordChirho {
        BillingCompensationRecordChirho {
            seq_chirho,
            schema_chirho: BILLING_COMPENSATION_RECORD_SCHEMA_CHIRHO.to_string(),
            original_usage_seq_chirho: usage_seq_chirho,
            ledger_seq_chirho: seq_chirho + 10,
            app_chirho: "billapp".to_string(),
            caller_chirho: "alice-chirho".to_string(),
            payer_chirho: "alice-chirho".to_string(),
            amount_token_chirho: 7,
            reason_chirho: "test refund".to_string(),
            billing_tags_chirho: Default::default(),
            at_ms_chirho: seq_chirho,
            sig_chirho: "e".repeat(128),
        }
    }

    #[test]
    fn billing_semantic_reducer_tracks_net_usage_chirho() {
        let state_chirho = billing_semantic_state_from_typed_records_chirho(
            &[policy_chirho(0)],
            &[usage_chirho(0, "alice-chirho", 17)],
            &[compensation_chirho(0, 0)],
        )
        .unwrap();
        let key_chirho = VerifiedBillingAppUserKeyChirho {
            app_chirho: "billapp".to_string(),
            caller_chirho: "alice-chirho".to_string(),
        };
        let aggregate_chirho = &state_chirho.usage_by_app_user_chirho[&key_chirho];
        assert_eq!(aggregate_chirho.usage_count_chirho, 1);
        assert_eq!(aggregate_chirho.gross_token_chirho, 17);
        assert_eq!(aggregate_chirho.compensation_count_chirho, 1);
        assert_eq!(aggregate_chirho.compensation_token_chirho, 7);
        assert_eq!(aggregate_chirho.net_token_chirho, 10);
    }

    #[test]
    fn billing_semantic_reducer_rejects_reordered_usage_chirho() {
        let error_chirho =
            billing_semantic_state_from_typed_records_chirho(&[], &[usage_chirho(1, "a", 1)], &[])
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains("usage seq/order mismatch"));
    }

    #[test]
    fn billing_semantic_keys_are_structural_not_joined_chirho() {
        let first_chirho = VerifiedBillingAppEffectKeyChirho {
            app_chirho: "app-a-chirho-effect-b-chirho".to_string(),
            effect_chirho: "effect-c-chirho".to_string(),
        };
        let second_chirho = VerifiedBillingAppEffectKeyChirho {
            app_chirho: "app-a-chirho".to_string(),
            effect_chirho: "effect-b-chirho-effect-c-chirho".to_string(),
        };
        let naive_first_chirho =
            format!("{}-{}", first_chirho.app_chirho, first_chirho.effect_chirho);
        let naive_second_chirho = format!(
            "{}-{}",
            second_chirho.app_chirho, second_chirho.effect_chirho
        );
        assert_eq!(naive_first_chirho, naive_second_chirho);
        assert_ne!(
            billing_app_effect_key_chirho(&first_chirho).unwrap(),
            billing_app_effect_key_chirho(&second_chirho).unwrap()
        );
    }
}
