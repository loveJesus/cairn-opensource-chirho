// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Gate 1 semantic parity rung 2d: pure resource policy/usage aggregation state.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::clsd_chirho::ProjectionStateChirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::{
    ResourceDecisionChirho, ResourcePolicyRecordChirho, ResourcePolicyUnsetRecordChirho,
    ResourceUsageRecordChirho, VerifiedResourceAppKeyChirho, VerifiedResourcePolicyStateChirho,
    VerifiedResourcePolicyUnsetStateChirho, VerifiedResourceRoutedAggregateChirho,
    VerifiedResourceStatesChirho, VerifiedResourceUsageAggregateChirho,
    VerifiedResourceUsageRecordStateChirho, VerifiedResourceUserKeyChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RESOURCE_SEMANTIC_META_SURFACE_CHIRHO: &str = "resource-semantic-meta-chirho";
pub const RESOURCE_SEMANTIC_POLICY_COUNT_KEY_CHIRHO: &str = "resource-policy-count-chirho";
pub const RESOURCE_SEMANTIC_UNSET_COUNT_KEY_CHIRHO: &str = "resource-policy-unset-count-chirho";
pub const RESOURCE_SEMANTIC_USAGE_COUNT_KEY_CHIRHO: &str = "resource-usage-count-chirho";
pub const RESOURCE_SEMANTIC_POLICIES_SURFACE_CHIRHO: &str = "resource-semantic-policies-chirho";
pub const RESOURCE_SEMANTIC_UNSETS_SURFACE_CHIRHO: &str = "resource-semantic-unsets-chirho";
pub const RESOURCE_SEMANTIC_USAGE_RECORDS_SURFACE_CHIRHO: &str =
    "resource-semantic-usage-records-chirho";
pub const RESOURCE_SEMANTIC_ALLOWED_BY_USER_SURFACE_CHIRHO: &str =
    "resource-semantic-allowed-by-user-chirho";
pub const RESOURCE_SEMANTIC_ALLOWED_BY_APP_SURFACE_CHIRHO: &str =
    "resource-semantic-allowed-by-app-chirho";
pub const RESOURCE_SEMANTIC_ROUTED_BY_USER_SURFACE_CHIRHO: &str =
    "resource-semantic-routed-by-user-chirho";
pub const RESOURCE_SEMANTIC_ROUTED_BY_APP_SURFACE_CHIRHO: &str =
    "resource-semantic-routed-by-app-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSemanticDiffChirho {
    pub key_chirho: String,
    pub left_chirho: Option<String>,
    pub right_chirho: Option<String>,
}

/// Part of `spec-chirho/workflows-chirho/audit-deep-pass-chirho.md`: this reducer is the
/// deterministic shadow road for Gate 1 semantic parity rung 2d.
pub fn resource_semantic_state_from_typed_records_chirho(
    policies_chirho: &[ResourcePolicyRecordChirho],
    unsets_chirho: &[ResourcePolicyUnsetRecordChirho],
    usage_chirho: &[ResourceUsageRecordChirho],
) -> Result<VerifiedResourceStatesChirho> {
    let mut state_chirho = VerifiedResourceStatesChirho {
        policy_record_count_chirho: policies_chirho.len(),
        policy_unset_record_count_chirho: unsets_chirho.len(),
        usage_record_count_chirho: usage_chirho.len(),
        ..VerifiedResourceStatesChirho::default()
    };

    for (idx_chirho, record_chirho) in policies_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "resource semantic parity policy seq/order mismatch at line {}: record seq {}",
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        state_chirho.policy_records_chirho.insert(
            record_chirho.seq_chirho,
            VerifiedResourcePolicyStateChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
                resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
                previous_chirho: record_chirho.previous_chirho.clone(),
                at_ms_chirho: record_chirho.at_ms_chirho,
            },
        );
    }

    for (idx_chirho, record_chirho) in unsets_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "resource semantic parity policy-unset seq/order mismatch at line {}: record seq {}",
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        state_chirho.policy_unset_records_chirho.insert(
            record_chirho.seq_chirho,
            VerifiedResourcePolicyUnsetStateChirho {
                app_chirho: record_chirho.app_chirho.clone(),
                owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
                previous_chirho: record_chirho.previous_chirho.clone(),
                at_ms_chirho: record_chirho.at_ms_chirho,
            },
        );
    }

    for (idx_chirho, record_chirho) in usage_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != idx_chirho as u64 {
            bail!(
                "resource semantic parity usage seq/order mismatch at line {}: record seq {}",
                idx_chirho,
                record_chirho.seq_chirho
            );
        }
        insert_usage_state_chirho(&mut state_chirho, record_chirho)?;
    }

    Ok(state_chirho)
}

pub fn resource_semantic_projection_state_chirho(
    state_chirho: &VerifiedResourceStatesChirho,
) -> Result<ProjectionStateChirho> {
    let mut projection_chirho = ProjectionStateChirho::default();
    projection_chirho.insert_chirho(
        RESOURCE_SEMANTIC_META_SURFACE_CHIRHO,
        RESOURCE_SEMANTIC_POLICY_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.policy_record_count_chirho)?,
    );
    projection_chirho.insert_chirho(
        RESOURCE_SEMANTIC_META_SURFACE_CHIRHO,
        RESOURCE_SEMANTIC_UNSET_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.policy_unset_record_count_chirho)?,
    );
    projection_chirho.insert_chirho(
        RESOURCE_SEMANTIC_META_SURFACE_CHIRHO,
        RESOURCE_SEMANTIC_USAGE_COUNT_KEY_CHIRHO,
        semantic_value_hash_chirho(&state_chirho.usage_record_count_chirho)?,
    );
    insert_map_chirho(
        &mut projection_chirho,
        RESOURCE_SEMANTIC_POLICIES_SURFACE_CHIRHO,
        &state_chirho.policy_records_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        RESOURCE_SEMANTIC_UNSETS_SURFACE_CHIRHO,
        &state_chirho.policy_unset_records_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        RESOURCE_SEMANTIC_USAGE_RECORDS_SURFACE_CHIRHO,
        &state_chirho.usage_records_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        RESOURCE_SEMANTIC_ALLOWED_BY_USER_SURFACE_CHIRHO,
        &state_chirho.allowed_by_user_resource_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        RESOURCE_SEMANTIC_ALLOWED_BY_APP_SURFACE_CHIRHO,
        &state_chirho.allowed_by_app_resource_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        RESOURCE_SEMANTIC_ROUTED_BY_USER_SURFACE_CHIRHO,
        &state_chirho.routed_by_user_resource_chirho,
    )?;
    insert_map_chirho(
        &mut projection_chirho,
        RESOURCE_SEMANTIC_ROUTED_BY_APP_SURFACE_CHIRHO,
        &state_chirho.routed_by_app_resource_chirho,
    )?;
    Ok(projection_chirho)
}

pub fn resource_semantic_first_diff_chirho(
    left_chirho: &VerifiedResourceStatesChirho,
    right_chirho: &VerifiedResourceStatesChirho,
) -> Result<Option<ResourceSemanticDiffChirho>> {
    for (key_chirho, left_chirho, right_chirho) in [
        (
            RESOURCE_SEMANTIC_POLICY_COUNT_KEY_CHIRHO,
            left_chirho.policy_record_count_chirho.to_string(),
            right_chirho.policy_record_count_chirho.to_string(),
        ),
        (
            RESOURCE_SEMANTIC_UNSET_COUNT_KEY_CHIRHO,
            left_chirho.policy_unset_record_count_chirho.to_string(),
            right_chirho.policy_unset_record_count_chirho.to_string(),
        ),
        (
            RESOURCE_SEMANTIC_USAGE_COUNT_KEY_CHIRHO,
            left_chirho.usage_record_count_chirho.to_string(),
            right_chirho.usage_record_count_chirho.to_string(),
        ),
    ] {
        if left_chirho != right_chirho {
            return Ok(Some(ResourceSemanticDiffChirho {
                key_chirho: key_chirho.to_string(),
                left_chirho: Some(left_chirho),
                right_chirho: Some(right_chirho),
            }));
        }
    }

    if let Some(diff_chirho) = first_map_diff_chirho(
        RESOURCE_SEMANTIC_POLICIES_SURFACE_CHIRHO,
        &left_chirho.policy_records_chirho,
        &right_chirho.policy_records_chirho,
    )? {
        return Ok(Some(diff_chirho));
    }
    if let Some(diff_chirho) = first_map_diff_chirho(
        RESOURCE_SEMANTIC_UNSETS_SURFACE_CHIRHO,
        &left_chirho.policy_unset_records_chirho,
        &right_chirho.policy_unset_records_chirho,
    )? {
        return Ok(Some(diff_chirho));
    }
    if let Some(diff_chirho) = first_map_diff_chirho(
        RESOURCE_SEMANTIC_USAGE_RECORDS_SURFACE_CHIRHO,
        &left_chirho.usage_records_chirho,
        &right_chirho.usage_records_chirho,
    )? {
        return Ok(Some(diff_chirho));
    }
    if let Some(diff_chirho) = first_map_diff_chirho(
        RESOURCE_SEMANTIC_ALLOWED_BY_USER_SURFACE_CHIRHO,
        &left_chirho.allowed_by_user_resource_chirho,
        &right_chirho.allowed_by_user_resource_chirho,
    )? {
        return Ok(Some(diff_chirho));
    }
    if let Some(diff_chirho) = first_map_diff_chirho(
        RESOURCE_SEMANTIC_ALLOWED_BY_APP_SURFACE_CHIRHO,
        &left_chirho.allowed_by_app_resource_chirho,
        &right_chirho.allowed_by_app_resource_chirho,
    )? {
        return Ok(Some(diff_chirho));
    }
    if let Some(diff_chirho) = first_map_diff_chirho(
        RESOURCE_SEMANTIC_ROUTED_BY_USER_SURFACE_CHIRHO,
        &left_chirho.routed_by_user_resource_chirho,
        &right_chirho.routed_by_user_resource_chirho,
    )? {
        return Ok(Some(diff_chirho));
    }
    first_map_diff_chirho(
        RESOURCE_SEMANTIC_ROUTED_BY_APP_SURFACE_CHIRHO,
        &left_chirho.routed_by_app_resource_chirho,
        &right_chirho.routed_by_app_resource_chirho,
    )
}

pub fn resource_user_key_chirho(key_chirho: &VerifiedResourceUserKeyChirho) -> Result<String> {
    Ok(serde_json::to_string(key_chirho)?)
}

pub fn resource_app_key_chirho(key_chirho: &VerifiedResourceAppKeyChirho) -> Result<String> {
    Ok(serde_json::to_string(key_chirho)?)
}

fn insert_usage_state_chirho(
    state_chirho: &mut VerifiedResourceStatesChirho,
    record_chirho: &ResourceUsageRecordChirho,
) -> Result<()> {
    state_chirho.usage_records_chirho.insert(
        record_chirho.seq_chirho,
        VerifiedResourceUsageRecordStateChirho {
            app_chirho: record_chirho.app_chirho.clone(),
            user_chirho: record_chirho.user_chirho.clone(),
            actor_chirho: record_chirho.actor_chirho.clone(),
            section_chirho: record_chirho.section_chirho.clone(),
            action_chirho: record_chirho.action_chirho.clone(),
            effect_chirho: record_chirho.effect_chirho.clone(),
            run_chirho: record_chirho.run_chirho.clone(),
            resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
            charges_chirho: record_chirho.charges_chirho.clone(),
            bridges_chirho: record_chirho.bridges_chirho.clone(),
            decision_chirho: record_chirho.decision_chirho.clone(),
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    );
    match &record_chirho.decision_chirho {
        ResourceDecisionChirho::AllowedChirho => {
            for charge_chirho in &record_chirho.charges_chirho {
                add_allowed_chirho(
                    state_chirho,
                    record_chirho,
                    &charge_chirho.resource_chirho,
                    charge_chirho.amount_chirho,
                )?;
            }
        }
        ResourceDecisionChirho::RoutedChirho {
            resource_chirho, ..
        } => {
            for charge_chirho in &record_chirho.charges_chirho {
                if &charge_chirho.resource_chirho == resource_chirho {
                    add_routed_chirho(
                        state_chirho,
                        record_chirho,
                        resource_chirho,
                        charge_chirho.amount_chirho,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn add_allowed_chirho(
    state_chirho: &mut VerifiedResourceStatesChirho,
    record_chirho: &ResourceUsageRecordChirho,
    resource_chirho: &str,
    amount_chirho: i64,
) -> Result<()> {
    add_usage_aggregate_chirho(
        state_chirho
            .allowed_by_user_resource_chirho
            .entry(user_key_chirho(record_chirho, resource_chirho))
            .or_default(),
        amount_chirho,
    )?;
    add_usage_aggregate_chirho(
        state_chirho
            .allowed_by_app_resource_chirho
            .entry(app_key_chirho(record_chirho, resource_chirho))
            .or_default(),
        amount_chirho,
    )
}

fn add_routed_chirho(
    state_chirho: &mut VerifiedResourceStatesChirho,
    record_chirho: &ResourceUsageRecordChirho,
    resource_chirho: &str,
    amount_chirho: i64,
) -> Result<()> {
    add_routed_aggregate_chirho(
        state_chirho
            .routed_by_user_resource_chirho
            .entry(user_key_chirho(record_chirho, resource_chirho))
            .or_default(),
        amount_chirho,
    )?;
    add_routed_aggregate_chirho(
        state_chirho
            .routed_by_app_resource_chirho
            .entry(app_key_chirho(record_chirho, resource_chirho))
            .or_default(),
        amount_chirho,
    )
}

fn user_key_chirho(
    record_chirho: &ResourceUsageRecordChirho,
    resource_chirho: &str,
) -> VerifiedResourceUserKeyChirho {
    VerifiedResourceUserKeyChirho {
        app_chirho: record_chirho.app_chirho.clone(),
        resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
        user_chirho: record_chirho.user_chirho.clone(),
        resource_chirho: resource_chirho.to_string(),
    }
}

fn app_key_chirho(
    record_chirho: &ResourceUsageRecordChirho,
    resource_chirho: &str,
) -> VerifiedResourceAppKeyChirho {
    VerifiedResourceAppKeyChirho {
        app_chirho: record_chirho.app_chirho.clone(),
        resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
        resource_chirho: resource_chirho.to_string(),
    }
}

fn add_usage_aggregate_chirho(
    aggregate_chirho: &mut VerifiedResourceUsageAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.usage_count_chirho = aggregate_chirho
        .usage_count_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("resource semantic parity usage count overflow"))?;
    aggregate_chirho.amount_chirho = aggregate_chirho
        .amount_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("resource semantic parity usage amount overflow"))?;
    Ok(())
}

fn add_routed_aggregate_chirho(
    aggregate_chirho: &mut VerifiedResourceRoutedAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.routed_attempts_chirho = aggregate_chirho
        .routed_attempts_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("resource semantic parity routed attempts overflow"))?;
    aggregate_chirho.routed_amount_chirho = aggregate_chirho
        .routed_amount_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("resource semantic parity routed amount overflow"))?;
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
) -> Result<Option<ResourceSemanticDiffChirho>>
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
            return Ok(Some(ResourceSemanticDiffChirho {
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
        ResourceBridgeRefChirho, ResourceChargeChirho, ResourceDecisionChirho,
    };

    fn hash_chirho(seed_chirho: char) -> HashChirho {
        HashChirho(seed_chirho.to_string().repeat(64))
    }

    fn usage_chirho(
        seq_chirho: u64,
        user_chirho: &str,
        resource_chirho: &str,
        amount_chirho: i64,
    ) -> ResourceUsageRecordChirho {
        ResourceUsageRecordChirho {
            seq_chirho,
            schema_chirho: cairn_model_economic_chirho::RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO
                .to_string(),
            app_chirho: "app-chirho".to_string(),
            user_chirho: user_chirho.to_string(),
            actor_chirho: user_chirho.to_string(),
            section_chirho: "section-chirho".to_string(),
            action_chirho: "action-chirho".to_string(),
            effect_chirho: None,
            run_chirho: None,
            resource_policy_chirho: hash_chirho('a'),
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: resource_chirho.to_string(),
                amount_chirho,
            }],
            bridges_chirho: Vec::<ResourceBridgeRefChirho>::new(),
            decision_chirho: ResourceDecisionChirho::AllowedChirho,
            at_ms_chirho: seq_chirho,
            sig_chirho: "b".repeat(128),
        }
    }

    #[test]
    fn resource_semantic_reducer_buckets_stored_allowed_decisions_chirho() {
        let state_chirho = resource_semantic_state_from_typed_records_chirho(
            &[],
            &[],
            &[
                usage_chirho(0, "alice-chirho", "tokens-chirho", 2),
                usage_chirho(1, "alice-chirho", "tokens-chirho", 3),
            ],
        )
        .unwrap();
        let key_chirho = VerifiedResourceUserKeyChirho {
            app_chirho: "app-chirho".to_string(),
            resource_policy_chirho: hash_chirho('a'),
            user_chirho: "alice-chirho".to_string(),
            resource_chirho: "tokens-chirho".to_string(),
        };
        let aggregate_chirho = &state_chirho.allowed_by_user_resource_chirho[&key_chirho];
        assert_eq!(aggregate_chirho.usage_count_chirho, 2);
        assert_eq!(aggregate_chirho.amount_chirho, 5);
    }

    #[test]
    fn resource_semantic_reducer_rejects_usage_reorder_chirho() {
        let mut record_chirho = usage_chirho(1, "alice-chirho", "tokens-chirho", 2);
        record_chirho.seq_chirho = 1;
        let error_chirho =
            resource_semantic_state_from_typed_records_chirho(&[], &[], &[record_chirho])
                .unwrap_err()
                .to_string();
        assert!(error_chirho.contains("usage seq/order mismatch"));
    }

    #[test]
    fn resource_semantic_keys_are_structural_not_joined_chirho() {
        let first_chirho = VerifiedResourceUserKeyChirho {
            app_chirho: "a-chirho-b-chirho".to_string(),
            resource_policy_chirho: hash_chirho('c'),
            user_chirho: "c-chirho".to_string(),
            resource_chirho: "e-chirho".to_string(),
        };
        let second_chirho = VerifiedResourceUserKeyChirho {
            app_chirho: "a-chirho".to_string(),
            resource_policy_chirho: hash_chirho('c'),
            user_chirho: "b-chirho-c-chirho".to_string(),
            resource_chirho: "e-chirho".to_string(),
        };
        let naive_first_chirho = format!(
            "{}-{}-{}",
            first_chirho.app_chirho, first_chirho.user_chirho, first_chirho.resource_chirho
        );
        let naive_second_chirho = format!(
            "{}-{}-{}",
            second_chirho.app_chirho, second_chirho.user_chirho, second_chirho.resource_chirho
        );
        assert_eq!(naive_first_chirho, naive_second_chirho);
        assert_ne!(
            resource_user_key_chirho(&first_chirho).unwrap(),
            resource_user_key_chirho(&second_chirho).unwrap()
        );

        let all_first_chirho = VerifiedResourceUserKeyChirho {
            app_chirho: "app-a-chirho-policy-b-chirho".to_string(),
            resource_policy_chirho: HashChirho("policy-c-chirho".to_string()),
            user_chirho: "user-d-chirho".to_string(),
            resource_chirho: "resource-e-chirho".to_string(),
        };
        let all_second_chirho = VerifiedResourceUserKeyChirho {
            app_chirho: "app-a-chirho".to_string(),
            resource_policy_chirho: HashChirho("policy-b-chirho-policy-c-chirho".to_string()),
            user_chirho: "user-d-chirho".to_string(),
            resource_chirho: "resource-e-chirho".to_string(),
        };
        let naive_all_first_chirho = format!(
            "{}-{}-{}-{}",
            all_first_chirho.app_chirho,
            all_first_chirho.resource_policy_chirho.0,
            all_first_chirho.user_chirho,
            all_first_chirho.resource_chirho
        );
        let naive_all_second_chirho = format!(
            "{}-{}-{}-{}",
            all_second_chirho.app_chirho,
            all_second_chirho.resource_policy_chirho.0,
            all_second_chirho.user_chirho,
            all_second_chirho.resource_chirho
        );
        assert_eq!(naive_all_first_chirho, naive_all_second_chirho);
        assert_ne!(
            resource_user_key_chirho(&all_first_chirho).unwrap(),
            resource_user_key_chirho(&all_second_chirho).unwrap()
        );
    }
}
