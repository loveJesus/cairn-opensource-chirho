// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RESOURCE_POLICY_RECORD_SCHEMA_CHIRHO: &str = "resource-policy-record-v1-chirho";
pub const RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO: &str = "resource-policy-record-v2-chirho";
pub const RESOURCE_POLICY_UNSET_RECORD_SCHEMA_CHIRHO: &str =
    "resource-policy-unset-record-v1-chirho";
pub const RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO: &str = "resource-usage-record-v1-chirho";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceOverageChirho {
    #[default]
    FailClosedChirho,
    RouteChirho {
        route_chirho: String,
        #[serde(default)]
        forward_request_body_chirho: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceMeterChirho {
    pub resource_chirho: String,
    pub unit_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_user_limit_chirho: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_limit_chirho: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_ms_chirho: Option<u64>,
    #[serde(default)]
    pub overage_chirho: ResourceOverageChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceChargeChirho {
    pub resource_chirho: String,
    pub amount_chirho: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceActionPolicyChirho {
    pub section_chirho: String,
    pub action_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_chirho: Option<String>,
    #[serde(default)]
    pub allow_anonymous_chirho: bool,
    pub charges_chirho: Vec<ResourceChargeChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePolicyInputChirho {
    pub meters_chirho: Vec<ResourceMeterChirho>,
    pub actions_chirho: Vec<ResourceActionPolicyChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppResourcePolicyChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub meters_chirho: Vec<ResourceMeterChirho>,
    pub actions_chirho: Vec<ResourceActionPolicyChirho>,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePolicyRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub resource_policy_chirho: HashChirho,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePolicyUnsetRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub previous_chirho: HashChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceDecisionChirho {
    AllowedChirho,
    RoutedChirho {
        resource_chirho: String,
        route_chirho: String,
        #[serde(default)]
        forward_request_body_chirho: bool,
        limit_chirho: i64,
        used_chirho: i64,
        attempted_chirho: i64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsageRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub user_chirho: String,
    pub actor_chirho: String,
    pub section_chirho: String,
    pub action_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_chirho: Option<HashChirho>,
    pub resource_policy_chirho: HashChirho,
    pub charges_chirho: Vec<ResourceChargeChirho>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridges_chirho: Vec<ResourceBridgeRefChirho>,
    pub decision_chirho: ResourceDecisionChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ResourceBridgeKindChirho {
    BillingUsageChirho,
    ExternalUsageChirho,
    ProviderInvoiceChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBridgeRefChirho {
    pub kind_chirho: ResourceBridgeKindChirho,
    pub seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceUsageInputChirho {
    pub app_chirho: String,
    pub user_chirho: String,
    pub actor_chirho: Option<String>,
    pub section_chirho: String,
    pub action_chirho: String,
    pub effect_chirho: Option<String>,
    pub run_chirho: Option<HashChirho>,
    pub bridges_chirho: Vec<ResourceBridgeRefChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceRollupAxisChirho {
    AppChirho,
    UserChirho,
    SectionChirho,
    ActionChirho,
    ResourceChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRollupRowChirho {
    pub key_chirho: String,
    pub resource_chirho: String,
    pub unit_chirho: String,
    pub usage_count_chirho: u64,
    pub amount_chirho: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceBalanceScopeChirho {
    AppChirho,
    UserChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBalanceRowChirho {
    pub app_chirho: String,
    pub scope_chirho: ResourceBalanceScopeChirho,
    pub subject_chirho: String,
    pub resource_chirho: String,
    pub unit_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_chirho: Option<String>,
    pub resource_policy_chirho: HashChirho,
    pub limit_chirho: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_ms_chirho: Option<u64>,
    pub used_chirho: i64,
    pub remaining_chirho: i64,
    pub routed_attempts_chirho: u64,
    pub routed_amount_chirho: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_chirho: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedResourcePolicyStateChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub resource_policy_chirho: HashChirho,
    pub previous_chirho: Option<HashChirho>,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedResourcePolicyUnsetStateChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub previous_chirho: HashChirho,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedResourceUsageRecordStateChirho {
    pub app_chirho: String,
    pub user_chirho: String,
    pub actor_chirho: String,
    pub section_chirho: String,
    pub action_chirho: String,
    pub effect_chirho: Option<String>,
    pub run_chirho: Option<HashChirho>,
    pub resource_policy_chirho: HashChirho,
    pub charges_chirho: Vec<ResourceChargeChirho>,
    pub bridges_chirho: Vec<ResourceBridgeRefChirho>,
    pub decision_chirho: ResourceDecisionChirho,
    pub at_ms_chirho: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedResourceUsageAggregateChirho {
    pub usage_count_chirho: u64,
    pub amount_chirho: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedResourceRoutedAggregateChirho {
    pub routed_attempts_chirho: u64,
    pub routed_amount_chirho: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerifiedResourceUserKeyChirho {
    pub app_chirho: String,
    pub resource_policy_chirho: HashChirho,
    pub user_chirho: String,
    pub resource_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VerifiedResourceAppKeyChirho {
    pub app_chirho: String,
    pub resource_policy_chirho: HashChirho,
    pub resource_chirho: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedResourceStatesChirho {
    pub policy_record_count_chirho: usize,
    pub policy_unset_record_count_chirho: usize,
    pub usage_record_count_chirho: usize,
    pub policy_records_chirho: BTreeMap<u64, VerifiedResourcePolicyStateChirho>,
    pub policy_unset_records_chirho: BTreeMap<u64, VerifiedResourcePolicyUnsetStateChirho>,
    pub usage_records_chirho: BTreeMap<u64, VerifiedResourceUsageRecordStateChirho>,
    pub allowed_by_user_resource_chirho:
        BTreeMap<VerifiedResourceUserKeyChirho, VerifiedResourceUsageAggregateChirho>,
    pub allowed_by_app_resource_chirho:
        BTreeMap<VerifiedResourceAppKeyChirho, VerifiedResourceUsageAggregateChirho>,
    pub routed_by_user_resource_chirho:
        BTreeMap<VerifiedResourceUserKeyChirho, VerifiedResourceRoutedAggregateChirho>,
    pub routed_by_app_resource_chirho:
        BTreeMap<VerifiedResourceAppKeyChirho, VerifiedResourceRoutedAggregateChirho>,
}

impl ResourceRollupAxisChirho {
    pub fn parse_chirho(value_chirho: &str) -> Result<Self> {
        match value_chirho {
            "app" => Ok(Self::AppChirho),
            "user" => Ok(Self::UserChirho),
            "section" => Ok(Self::SectionChirho),
            "action" => Ok(Self::ActionChirho),
            "resource" => Ok(Self::ResourceChirho),
            other_chirho => {
                bail!("unknown resource rollup axis '{other_chirho}' (use app|user|section|action|resource)")
            }
        }
    }
}

pub fn append_verified_resource_usage_state_chirho(
    states_chirho: &mut VerifiedResourceStatesChirho,
    record_chirho: &ResourceUsageRecordChirho,
) -> Result<()> {
    states_chirho.usage_records_chirho.insert(
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
                add_resource_usage_aggregate_chirho(
                    states_chirho
                        .allowed_by_user_resource_chirho
                        .entry(VerifiedResourceUserKeyChirho {
                            app_chirho: record_chirho.app_chirho.clone(),
                            resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
                            user_chirho: record_chirho.user_chirho.clone(),
                            resource_chirho: charge_chirho.resource_chirho.clone(),
                        })
                        .or_default(),
                    charge_chirho.amount_chirho,
                )?;
                add_resource_usage_aggregate_chirho(
                    states_chirho
                        .allowed_by_app_resource_chirho
                        .entry(VerifiedResourceAppKeyChirho {
                            app_chirho: record_chirho.app_chirho.clone(),
                            resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
                            resource_chirho: charge_chirho.resource_chirho.clone(),
                        })
                        .or_default(),
                    charge_chirho.amount_chirho,
                )?;
            }
        }
        ResourceDecisionChirho::RoutedChirho {
            resource_chirho, ..
        } => {
            for charge_chirho in &record_chirho.charges_chirho {
                if &charge_chirho.resource_chirho != resource_chirho {
                    continue;
                }
                add_resource_routed_aggregate_chirho(
                    states_chirho
                        .routed_by_user_resource_chirho
                        .entry(VerifiedResourceUserKeyChirho {
                            app_chirho: record_chirho.app_chirho.clone(),
                            resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
                            user_chirho: record_chirho.user_chirho.clone(),
                            resource_chirho: charge_chirho.resource_chirho.clone(),
                        })
                        .or_default(),
                    charge_chirho.amount_chirho,
                )?;
                add_resource_routed_aggregate_chirho(
                    states_chirho
                        .routed_by_app_resource_chirho
                        .entry(VerifiedResourceAppKeyChirho {
                            app_chirho: record_chirho.app_chirho.clone(),
                            resource_policy_chirho: record_chirho.resource_policy_chirho.clone(),
                            resource_chirho: charge_chirho.resource_chirho.clone(),
                        })
                        .or_default(),
                    charge_chirho.amount_chirho,
                )?;
            }
        }
    }
    Ok(())
}

fn add_resource_usage_aggregate_chirho(
    aggregate_chirho: &mut VerifiedResourceUsageAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.usage_count_chirho = aggregate_chirho
        .usage_count_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("resource usage count overflow"))?;
    aggregate_chirho.amount_chirho = aggregate_chirho
        .amount_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("resource usage amount overflow"))?;
    Ok(())
}

fn add_resource_routed_aggregate_chirho(
    aggregate_chirho: &mut VerifiedResourceRoutedAggregateChirho,
    amount_chirho: i64,
) -> Result<()> {
    aggregate_chirho.routed_attempts_chirho = aggregate_chirho
        .routed_attempts_chirho
        .checked_add(1)
        .ok_or_else(|| anyhow!("resource routed attempts overflow"))?;
    aggregate_chirho.routed_amount_chirho = aggregate_chirho
        .routed_amount_chirho
        .checked_add(amount_chirho)
        .ok_or_else(|| anyhow!("resource routed amount overflow"))?;
    Ok(())
}
