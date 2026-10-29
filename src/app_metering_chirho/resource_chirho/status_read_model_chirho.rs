// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Resource rollup/status read models and resource-decision helpers.

use super::{
    load_resource_usage_chirho, now_ms_chirho, AppResourcePolicyChirho, ResourceBalanceRowChirho,
    ResourceBalanceScopeChirho, ResourceDecisionChirho, ResourceMeterChirho, ResourceOverageChirho,
    ResourceRollupAxisChirho, ResourceRollupRowChirho, ResourceUsageRecordChirho,
};
use crate::{model_chirho::HashChirho, refs_chirho, store_chirho};
use anyhow::{anyhow, Result};
use cairn_economic_governance_chirho::resource_policy_chirho;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

struct ResourceBalanceRequestChirho<'a> {
    scope_chirho: ResourceBalanceScopeChirho,
    subject_chirho: &'a str,
    user_chirho: Option<&'a str>,
    limit_chirho: i64,
    at_ms_chirho: u64,
}

pub fn resource_rollup_chirho(
    root_chirho: &Path,
    app_filter_chirho: Option<&str>,
    axis_chirho: ResourceRollupAxisChirho,
) -> Result<Vec<ResourceRollupRowChirho>> {
    if let Some(app_chirho) = app_filter_chirho {
        resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    }
    super::verify_resource_usage_chirho(root_chirho)?;
    let records_chirho = load_resource_usage_chirho(root_chirho)?;
    let mut rows_chirho: BTreeMap<(String, String, String), ResourceRollupRowChirho> =
        BTreeMap::new();
    for record_chirho in records_chirho {
        if app_filter_chirho.is_some_and(|app_chirho| app_chirho != record_chirho.app_chirho) {
            continue;
        }
        if record_chirho.decision_chirho != ResourceDecisionChirho::AllowedChirho {
            continue;
        }
        let policy_chirho: AppResourcePolicyChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.resource_policy_chirho)?;
        for charge_chirho in &record_chirho.charges_chirho {
            let meter_chirho = resource_policy_chirho::meter_for_chirho(
                &policy_chirho,
                &charge_chirho.resource_chirho,
            )?;
            let key_chirho = match axis_chirho {
                ResourceRollupAxisChirho::AppChirho => record_chirho.app_chirho.clone(),
                ResourceRollupAxisChirho::UserChirho => record_chirho.user_chirho.clone(),
                ResourceRollupAxisChirho::SectionChirho => record_chirho.section_chirho.clone(),
                ResourceRollupAxisChirho::ActionChirho => {
                    format!(
                        "{}/{}",
                        record_chirho.section_chirho, record_chirho.action_chirho
                    )
                }
                ResourceRollupAxisChirho::ResourceChirho => charge_chirho.resource_chirho.clone(),
            };
            let row_key_chirho = (
                key_chirho.clone(),
                charge_chirho.resource_chirho.clone(),
                meter_chirho.unit_chirho.clone(),
            );
            let row_chirho =
                rows_chirho
                    .entry(row_key_chirho)
                    .or_insert_with(|| ResourceRollupRowChirho {
                        key_chirho,
                        resource_chirho: charge_chirho.resource_chirho.clone(),
                        unit_chirho: meter_chirho.unit_chirho.clone(),
                        usage_count_chirho: 0,
                        amount_chirho: 0,
                    });
            row_chirho.usage_count_chirho = row_chirho
                .usage_count_chirho
                .checked_add(1)
                .ok_or_else(|| anyhow!("resource rollup usage count overflow"))?;
            row_chirho.amount_chirho = row_chirho
                .amount_chirho
                .checked_add(charge_chirho.amount_chirho)
                .ok_or_else(|| anyhow!("resource rollup amount overflow"))?;
        }
    }
    Ok(rows_chirho.into_values().collect())
}

pub fn resource_status_chirho(
    root_chirho: &Path,
    app_filter_chirho: Option<&str>,
    user_filter_chirho: Option<&str>,
) -> Result<Vec<ResourceBalanceRowChirho>> {
    if let Some(app_chirho) = app_filter_chirho {
        resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    }
    if let Some(user_chirho) = user_filter_chirho {
        resource_policy_chirho::validate_principal_label_chirho("user_chirho", user_chirho)?;
    }
    super::verify_resource_usage_chirho(root_chirho)?;
    let usage_chirho = load_resource_usage_chirho(root_chirho)?;
    let refs_state_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let status_at_ms_chirho = now_ms_chirho();
    let mut rows_chirho = Vec::new();
    for ref_chirho in refs_state_chirho.branches_chirho.keys() {
        let Some(app_chirho) = ref_chirho.strip_prefix("resource-policy/") else {
            continue;
        };
        if app_filter_chirho.is_some_and(|filter_chirho| filter_chirho != app_chirho) {
            continue;
        }
        // Render only the verified-current policy the enforcement path would authorize, not the raw
        // ref object: a forged, resurrected, or superseded ref fails closed here (the gated read
        // errors) rather than showing an unverified head, and a genuinely unset app returns None and
        // contributes no rows. Failing the listing closed on a tampered ref is deliberate for this
        // money-adjacent status surface; graceful per-app skip-with-label would be a separate choice.
        let Some((verified_hash_chirho, policy_chirho)) =
            super::current_resource_policy_chirho(root_chirho, app_chirho)?
        else {
            continue;
        };
        let policy_hash_chirho = &verified_hash_chirho;
        for meter_chirho in &policy_chirho.meters_chirho {
            if let Some(app_limit_chirho) = meter_chirho.app_limit_chirho {
                if user_filter_chirho.is_none() {
                    rows_chirho.push(resource_balance_row_chirho(
                        &usage_chirho,
                        &policy_chirho,
                        policy_hash_chirho,
                        meter_chirho,
                        ResourceBalanceRequestChirho {
                            scope_chirho: ResourceBalanceScopeChirho::AppChirho,
                            subject_chirho: &policy_chirho.app_chirho,
                            user_chirho: None,
                            limit_chirho: app_limit_chirho,
                            at_ms_chirho: status_at_ms_chirho,
                        },
                    )?);
                }
            }
            if let Some(per_user_limit_chirho) = meter_chirho.per_user_limit_chirho {
                let mut users_chirho = BTreeSet::new();
                if let Some(user_chirho) = user_filter_chirho {
                    users_chirho.insert(user_chirho.to_string());
                } else {
                    for record_chirho in &usage_chirho {
                        if record_chirho.app_chirho == policy_chirho.app_chirho
                            && record_chirho.resource_policy_chirho == *policy_hash_chirho
                            && record_chirho.charges_chirho.iter().any(|charge_chirho| {
                                charge_chirho.resource_chirho == meter_chirho.resource_chirho
                            })
                        {
                            users_chirho.insert(record_chirho.user_chirho.clone());
                        }
                    }
                }
                for user_chirho in users_chirho {
                    rows_chirho.push(resource_balance_row_chirho(
                        &usage_chirho,
                        &policy_chirho,
                        policy_hash_chirho,
                        meter_chirho,
                        ResourceBalanceRequestChirho {
                            scope_chirho: ResourceBalanceScopeChirho::UserChirho,
                            subject_chirho: &user_chirho,
                            user_chirho: Some(&user_chirho),
                            limit_chirho: per_user_limit_chirho,
                            at_ms_chirho: status_at_ms_chirho,
                        },
                    )?);
                }
            }
        }
    }
    Ok(rows_chirho)
}

fn resource_balance_row_chirho(
    records_chirho: &[ResourceUsageRecordChirho],
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    meter_chirho: &ResourceMeterChirho,
    request_chirho: ResourceBalanceRequestChirho<'_>,
) -> Result<ResourceBalanceRowChirho> {
    let used_chirho = resource_policy_chirho::used_amount_chirho(
        records_chirho,
        policy_hash_chirho,
        &policy_chirho.app_chirho,
        request_chirho.user_chirho,
        &meter_chirho.resource_chirho,
        meter_chirho.window_ms_chirho,
        request_chirho.at_ms_chirho,
    )?;
    let remaining_chirho = request_chirho
        .limit_chirho
        .checked_sub(used_chirho)
        .ok_or_else(|| anyhow!("resource status used amount exceeds limit"))?;
    let (routed_attempts_chirho, routed_amount_chirho) = routed_summary_chirho(
        records_chirho,
        policy_hash_chirho,
        &policy_chirho.app_chirho,
        request_chirho.user_chirho,
        &meter_chirho.resource_chirho,
    )?;
    Ok(ResourceBalanceRowChirho {
        app_chirho: policy_chirho.app_chirho.clone(),
        scope_chirho: request_chirho.scope_chirho,
        subject_chirho: request_chirho.subject_chirho.to_string(),
        resource_chirho: meter_chirho.resource_chirho.clone(),
        unit_chirho: meter_chirho.unit_chirho.clone(),
        stack_chirho: meter_chirho.stack_chirho.clone(),
        resource_policy_chirho: policy_hash_chirho.clone(),
        limit_chirho: request_chirho.limit_chirho,
        window_ms_chirho: meter_chirho.window_ms_chirho,
        used_chirho,
        remaining_chirho,
        routed_attempts_chirho,
        routed_amount_chirho,
        route_chirho: match &meter_chirho.overage_chirho {
            ResourceOverageChirho::FailClosedChirho => None,
            ResourceOverageChirho::RouteChirho { route_chirho, .. } => Some(route_chirho.clone()),
        },
    })
}

fn routed_summary_chirho(
    records_chirho: &[ResourceUsageRecordChirho],
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    user_chirho: Option<&str>,
    resource_chirho: &str,
) -> Result<(u64, i64)> {
    let mut attempts_chirho = 0_u64;
    let mut amount_chirho = 0_i64;
    for record_chirho in records_chirho {
        if record_chirho.resource_policy_chirho != *policy_hash_chirho
            || record_chirho.app_chirho != app_chirho
        {
            continue;
        }
        if user_chirho.is_some_and(|user_chirho| user_chirho != record_chirho.user_chirho) {
            continue;
        }
        let ResourceDecisionChirho::RoutedChirho {
            resource_chirho: routed_resource_chirho,
            ..
        } = &record_chirho.decision_chirho
        else {
            continue;
        };
        if routed_resource_chirho != resource_chirho {
            continue;
        }
        attempts_chirho = attempts_chirho
            .checked_add(1)
            .ok_or_else(|| anyhow!("resource routed attempts overflow"))?;
        for charge_chirho in &record_chirho.charges_chirho {
            if charge_chirho.resource_chirho == resource_chirho {
                amount_chirho = amount_chirho
                    .checked_add(charge_chirho.amount_chirho)
                    .ok_or_else(|| anyhow!("resource routed amount overflow"))?;
            }
        }
    }
    Ok((attempts_chirho, amount_chirho))
}
