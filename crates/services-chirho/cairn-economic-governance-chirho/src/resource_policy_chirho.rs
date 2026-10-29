// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure resource policy proposal and usage-decision helpers.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_model_economic_chirho::{
    AppResourcePolicyChirho, ResourceActionPolicyChirho, ResourceChargeChirho,
    ResourceDecisionChirho, ResourceMeterChirho, ResourceOverageChirho, ResourceUsageRecordChirho,
    VerifiedResourcePolicyStateChirho, VerifiedResourcePolicyUnsetStateChirho,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn propose_resource_policy_chirho(
    app_chirho: &str,
    owner_principal_chirho: &str,
    meters_chirho: Vec<ResourceMeterChirho>,
    actions_chirho: Vec<ResourceActionPolicyChirho>,
    previous_chirho: Option<HashChirho>,
    at_ms_chirho: u64,
) -> Result<AppResourcePolicyChirho> {
    let policy_chirho = AppResourcePolicyChirho {
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: owner_principal_chirho.to_string(),
        meters_chirho,
        actions_chirho,
        previous_chirho,
        at_ms_chirho,
    };
    validate_resource_policy_chirho(&policy_chirho)?;
    Ok(policy_chirho)
}

pub fn validate_resource_policy_chirho(policy_chirho: &AppResourcePolicyChirho) -> Result<()> {
    validate_app_name_chirho(&policy_chirho.app_chirho)?;
    validate_principal_label_chirho(
        "owner_principal_chirho",
        &policy_chirho.owner_principal_chirho,
    )?;
    if policy_chirho.meters_chirho.is_empty() {
        bail!("resource policy needs at least one meter");
    }
    if policy_chirho.actions_chirho.is_empty() {
        bail!("resource policy needs at least one action");
    }
    let mut meters_chirho = BTreeSet::new();
    for meter_chirho in &policy_chirho.meters_chirho {
        validate_plain_id_chirho("resource_chirho", &meter_chirho.resource_chirho)?;
        validate_plain_id_chirho("unit_chirho", &meter_chirho.unit_chirho)?;
        if let Some(stack_chirho) = &meter_chirho.stack_chirho {
            validate_plain_id_chirho("stack_chirho", stack_chirho)?;
        }
        if !meters_chirho.insert(meter_chirho.resource_chirho.clone()) {
            bail!(
                "duplicate resource meter '{}'",
                meter_chirho.resource_chirho
            );
        }
        if meter_chirho.per_user_limit_chirho.is_none() && meter_chirho.app_limit_chirho.is_none() {
            bail!(
                "resource meter '{}' needs per_user_limit_chirho or app_limit_chirho",
                meter_chirho.resource_chirho
            );
        }
        if let Some(limit_chirho) = meter_chirho.per_user_limit_chirho {
            if limit_chirho <= 0 {
                bail!("per_user_limit_chirho must be positive");
            }
        }
        if let Some(limit_chirho) = meter_chirho.app_limit_chirho {
            if limit_chirho <= 0 {
                bail!("app_limit_chirho must be positive");
            }
        }
        if let Some(window_ms_chirho) = meter_chirho.window_ms_chirho {
            if window_ms_chirho == 0 {
                bail!("window_ms_chirho must be positive");
            }
        }
        if let ResourceOverageChirho::RouteChirho { route_chirho, .. } =
            &meter_chirho.overage_chirho
        {
            validate_plain_id_chirho("route_chirho", route_chirho)?;
        }
    }

    let mut action_keys_chirho = BTreeSet::new();
    for action_chirho in &policy_chirho.actions_chirho {
        validate_plain_id_chirho("section_chirho", &action_chirho.section_chirho)?;
        validate_plain_id_chirho("action_chirho", &action_chirho.action_chirho)?;
        if let Some(effect_chirho) = &action_chirho.effect_chirho {
            validate_plain_id_chirho("effect_chirho", effect_chirho)?;
        }
        let key_chirho = (
            action_chirho.section_chirho.clone(),
            action_chirho.action_chirho.clone(),
            action_chirho.effect_chirho.clone(),
        );
        if !action_keys_chirho.insert(key_chirho) {
            bail!(
                "duplicate resource action '{}/{}'",
                action_chirho.section_chirho,
                action_chirho.action_chirho
            );
        }
        if action_chirho.charges_chirho.is_empty() {
            bail!("resource action needs at least one charge");
        }
        let mut charged_chirho = BTreeSet::new();
        for charge_chirho in &action_chirho.charges_chirho {
            validate_plain_id_chirho("resource_chirho", &charge_chirho.resource_chirho)?;
            if !meters_chirho.contains(&charge_chirho.resource_chirho) {
                bail!(
                    "resource action charges undeclared meter '{}'",
                    charge_chirho.resource_chirho
                );
            }
            if !charged_chirho.insert(charge_chirho.resource_chirho.clone()) {
                bail!(
                    "resource action duplicates charge for '{}'",
                    charge_chirho.resource_chirho
                );
            }
            if charge_chirho.amount_chirho <= 0 {
                bail!("resource charge amount_chirho must be positive");
            }
        }
    }
    Ok(())
}

pub fn validate_resource_usage_record_chirho(
    record_chirho: &ResourceUsageRecordChirho,
) -> Result<()> {
    validate_app_name_chirho(&record_chirho.app_chirho)?;
    validate_principal_label_chirho("user_chirho", &record_chirho.user_chirho)?;
    validate_principal_label_chirho("actor_chirho", &record_chirho.actor_chirho)?;
    validate_plain_id_chirho("section_chirho", &record_chirho.section_chirho)?;
    validate_plain_id_chirho("action_chirho", &record_chirho.action_chirho)?;
    if let Some(effect_chirho) = &record_chirho.effect_chirho {
        validate_plain_id_chirho("effect_chirho", effect_chirho)?;
    }
    if let Some(run_chirho) = &record_chirho.run_chirho {
        if run_chirho.0.trim().is_empty() {
            bail!("run_chirho must not be empty");
        }
    }
    if record_chirho.charges_chirho.is_empty() {
        bail!("resource usage needs at least one planned charge");
    }
    for charge_chirho in &record_chirho.charges_chirho {
        validate_plain_id_chirho("resource_chirho", &charge_chirho.resource_chirho)?;
        if charge_chirho.amount_chirho <= 0 {
            bail!("resource usage charge amount_chirho must be positive");
        }
    }
    if let ResourceDecisionChirho::RoutedChirho {
        resource_chirho,
        route_chirho,
        forward_request_body_chirho: _,
        limit_chirho,
        used_chirho,
        attempted_chirho,
    } = &record_chirho.decision_chirho
    {
        validate_plain_id_chirho("resource_chirho", resource_chirho)?;
        validate_plain_id_chirho("route_chirho", route_chirho)?;
        if *limit_chirho <= 0 {
            bail!("routed resource limit_chirho must be positive");
        }
        if *used_chirho < 0 || *attempted_chirho <= *used_chirho {
            bail!("routed resource usage bounds are invalid");
        }
    }
    Ok(())
}

pub fn decide_resource_usage_chirho(
    policy_chirho: &AppResourcePolicyChirho,
    policy_hash_chirho: &HashChirho,
    prior_chirho: &[ResourceUsageRecordChirho],
    app_chirho: &str,
    user_chirho: &str,
    charges_chirho: &[ResourceChargeChirho],
    at_ms_chirho: u64,
) -> Result<ResourceDecisionChirho> {
    for charge_chirho in charges_chirho {
        let meter_chirho = meter_for_chirho(policy_chirho, &charge_chirho.resource_chirho)?;
        if let Some(per_user_limit_chirho) = meter_chirho.per_user_limit_chirho {
            let used_chirho = used_amount_chirho(
                prior_chirho,
                policy_hash_chirho,
                app_chirho,
                Some(user_chirho),
                &charge_chirho.resource_chirho,
                meter_chirho.window_ms_chirho,
                at_ms_chirho,
            )?;
            let attempted_chirho = used_chirho
                .checked_add(charge_chirho.amount_chirho)
                .ok_or_else(|| anyhow!("resource usage overflow"))?;
            if attempted_chirho > per_user_limit_chirho {
                return overage_decision_chirho(
                    meter_chirho,
                    per_user_limit_chirho,
                    used_chirho,
                    attempted_chirho,
                );
            }
        }
        if let Some(app_limit_chirho) = meter_chirho.app_limit_chirho {
            let used_chirho = used_amount_chirho(
                prior_chirho,
                policy_hash_chirho,
                app_chirho,
                None,
                &charge_chirho.resource_chirho,
                meter_chirho.window_ms_chirho,
                at_ms_chirho,
            )?;
            let attempted_chirho = used_chirho
                .checked_add(charge_chirho.amount_chirho)
                .ok_or_else(|| anyhow!("resource usage overflow"))?;
            if attempted_chirho > app_limit_chirho {
                return overage_decision_chirho(
                    meter_chirho,
                    app_limit_chirho,
                    used_chirho,
                    attempted_chirho,
                );
            }
        }
    }
    Ok(ResourceDecisionChirho::AllowedChirho)
}

pub fn find_action_policy_chirho<'a_chirho>(
    policy_chirho: &'a_chirho AppResourcePolicyChirho,
    section_chirho: &str,
    action_chirho: &str,
    effect_chirho: Option<&str>,
) -> Result<&'a_chirho ResourceActionPolicyChirho> {
    let mut fallback_chirho = None;
    for candidate_chirho in &policy_chirho.actions_chirho {
        if candidate_chirho.section_chirho != section_chirho
            || candidate_chirho.action_chirho != action_chirho
        {
            continue;
        }
        match (&candidate_chirho.effect_chirho, effect_chirho) {
            (Some(candidate_effect_chirho), Some(effect_chirho))
                if candidate_effect_chirho == effect_chirho =>
            {
                return Ok(candidate_chirho);
            }
            (None, _) => fallback_chirho = Some(candidate_chirho),
            _ => {}
        }
    }
    fallback_chirho
        .ok_or_else(|| anyhow!("resource policy has no action '{section_chirho}/{action_chirho}'"))
}

pub fn validate_app_name_chirho(app_chirho: &str) -> Result<()> {
    if app_chirho.trim().is_empty() {
        bail!("app_chirho is required");
    }
    if app_chirho.contains('/') || app_chirho.chars().any(char::is_whitespace) {
        bail!("app_chirho must not contain slashes or whitespace");
    }
    Ok(())
}

pub fn validate_plain_id_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty() {
        bail!("{name_chirho} is required");
    }
    if value_chirho.contains('/') || value_chirho.chars().any(char::is_whitespace) {
        bail!("{name_chirho} must not contain slashes or whitespace");
    }
    Ok(())
}

pub fn validate_principal_label_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty() {
        bail!("{name_chirho} is required");
    }
    if value_chirho.chars().any(char::is_whitespace) {
        bail!("{name_chirho} must not contain whitespace");
    }
    Ok(())
}

fn overage_decision_chirho(
    meter_chirho: &ResourceMeterChirho,
    limit_chirho: i64,
    used_chirho: i64,
    attempted_chirho: i64,
) -> Result<ResourceDecisionChirho> {
    match &meter_chirho.overage_chirho {
        ResourceOverageChirho::FailClosedChirho => bail!(
            "resource '{}' exhausted: used {}, attempted {}, limit {}",
            meter_chirho.resource_chirho,
            used_chirho,
            attempted_chirho,
            limit_chirho
        ),
        ResourceOverageChirho::RouteChirho {
            route_chirho,
            forward_request_body_chirho,
        } => Ok(ResourceDecisionChirho::RoutedChirho {
            resource_chirho: meter_chirho.resource_chirho.clone(),
            route_chirho: route_chirho.clone(),
            forward_request_body_chirho: *forward_request_body_chirho,
            limit_chirho,
            used_chirho,
            attempted_chirho,
        }),
    }
}

pub fn used_amount_chirho(
    records_chirho: &[ResourceUsageRecordChirho],
    policy_hash_chirho: &HashChirho,
    app_chirho: &str,
    user_chirho: Option<&str>,
    resource_chirho: &str,
    window_ms_chirho: Option<u64>,
    at_ms_chirho: u64,
) -> Result<i64> {
    let mut used_chirho = 0_i64;
    for record_chirho in records_chirho {
        if record_chirho.resource_policy_chirho != *policy_hash_chirho
            || record_chirho.app_chirho != app_chirho
            || record_chirho.decision_chirho != ResourceDecisionChirho::AllowedChirho
        {
            continue;
        }
        if let Some(window_ms_chirho) = window_ms_chirho {
            if record_chirho.at_ms_chirho > at_ms_chirho
                || at_ms_chirho - record_chirho.at_ms_chirho >= window_ms_chirho
            {
                continue;
            }
        }
        if user_chirho.is_some_and(|user_chirho| user_chirho != record_chirho.user_chirho) {
            continue;
        }
        for charge_chirho in &record_chirho.charges_chirho {
            if charge_chirho.resource_chirho == resource_chirho {
                used_chirho = used_chirho
                    .checked_add(charge_chirho.amount_chirho)
                    .ok_or_else(|| anyhow!("resource used amount overflow"))?;
            }
        }
    }
    Ok(used_chirho)
}

pub fn meter_for_chirho<'a_chirho>(
    policy_chirho: &'a_chirho AppResourcePolicyChirho,
    resource_chirho: &str,
) -> Result<&'a_chirho ResourceMeterChirho> {
    policy_chirho
        .meters_chirho
        .iter()
        .find(|meter_chirho| meter_chirho.resource_chirho == resource_chirho)
        .ok_or_else(|| anyhow!("resource '{resource_chirho}' is not declared by policy"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LatestPolicyEventChirho<'a_chirho> {
    SetChirho {
        seq_chirho: u64,
        state_chirho: &'a_chirho VerifiedResourcePolicyStateChirho,
    },
    UnsetChirho {
        seq_chirho: u64,
        state_chirho: &'a_chirho VerifiedResourcePolicyUnsetStateChirho,
    },
}

/// The app's latest policy event decides the current policy: a set-record makes its policy
/// current, an unset-record makes it absent. Within one log seq is the order; across the two
/// logs the later record `at_ms_chirho` wins, and an exact tie keeps the set so ambiguity
/// fails toward metering rather than toward an unmetered gate.
pub fn latest_policy_event_chirho<'a_chirho>(
    app_chirho: &str,
    policy_states_chirho: &'a_chirho BTreeMap<u64, VerifiedResourcePolicyStateChirho>,
    unset_states_chirho: &'a_chirho BTreeMap<u64, VerifiedResourcePolicyUnsetStateChirho>,
) -> Option<LatestPolicyEventChirho<'a_chirho>> {
    let latest_set_chirho = policy_states_chirho
        .iter()
        .rev()
        .find(|(_, state_chirho)| state_chirho.app_chirho == app_chirho);
    let latest_unset_chirho = unset_states_chirho
        .iter()
        .rev()
        .find(|(_, state_chirho)| state_chirho.app_chirho == app_chirho);
    match (latest_set_chirho, latest_unset_chirho) {
        (None, None) => None,
        (Some((seq_chirho, state_chirho)), None) => Some(LatestPolicyEventChirho::SetChirho {
            seq_chirho: *seq_chirho,
            state_chirho,
        }),
        (None, Some((seq_chirho, state_chirho))) => Some(LatestPolicyEventChirho::UnsetChirho {
            seq_chirho: *seq_chirho,
            state_chirho,
        }),
        (
            Some((set_seq_chirho, set_state_chirho)),
            Some((unset_seq_chirho, unset_state_chirho)),
        ) => {
            if unset_state_chirho.at_ms_chirho > set_state_chirho.at_ms_chirho {
                Some(LatestPolicyEventChirho::UnsetChirho {
                    seq_chirho: *unset_seq_chirho,
                    state_chirho: unset_state_chirho,
                })
            } else {
                Some(LatestPolicyEventChirho::SetChirho {
                    seq_chirho: *set_seq_chirho,
                    state_chirho: set_state_chirho,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn hash_chirho(byte_chirho: char) -> HashChirho {
        HashChirho(byte_chirho.to_string().repeat(64))
    }

    fn meter_chirho() -> ResourceMeterChirho {
        ResourceMeterChirho {
            resource_chirho: "labs_credit_chirho".to_string(),
            unit_chirho: "credit".to_string(),
            stack_chirho: Some("labs".to_string()),
            per_user_limit_chirho: Some(10),
            app_limit_chirho: Some(30),
            window_ms_chirho: Some(60_000),
            overage_chirho: ResourceOverageChirho::RouteChirho {
                route_chirho: "limit-reached".to_string(),
                forward_request_body_chirho: true,
            },
        }
    }

    fn action_chirho() -> ResourceActionPolicyChirho {
        ResourceActionPolicyChirho {
            section_chirho: "builder".to_string(),
            action_chirho: "submit".to_string(),
            effect_chirho: Some("write_store_chirho".to_string()),
            allow_anonymous_chirho: false,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "labs_credit_chirho".to_string(),
                amount_chirho: 3,
            }],
        }
    }

    fn allowed_usage_chirho(
        seq_chirho: u64,
        user_chirho: &str,
        amount_chirho: i64,
        at_ms_chirho: u64,
    ) -> ResourceUsageRecordChirho {
        ResourceUsageRecordChirho {
            seq_chirho,
            schema_chirho: "resource-usage-record-v1-chirho".to_string(),
            app_chirho: "resourceapp".to_string(),
            user_chirho: user_chirho.to_string(),
            actor_chirho: user_chirho.to_string(),
            section_chirho: "builder".to_string(),
            action_chirho: "submit".to_string(),
            effect_chirho: Some("write_store_chirho".to_string()),
            run_chirho: None,
            resource_policy_chirho: hash_chirho('b'),
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "labs_credit_chirho".to_string(),
                amount_chirho,
            }],
            bridges_chirho: vec![],
            decision_chirho: ResourceDecisionChirho::AllowedChirho,
            at_ms_chirho,
            sig_chirho: "sig".to_string(),
        }
    }

    #[test]
    fn proposed_resource_policy_serialization_stays_stable_chirho() {
        let policy_chirho = propose_resource_policy_chirho(
            "resourceapp",
            "owner/test",
            vec![meter_chirho()],
            vec![action_chirho()],
            Some(hash_chirho('a')),
            1234,
        )
        .unwrap();

        assert_eq!(
            serde_json::to_string(&policy_chirho).unwrap(),
            concat!(
                r#"{"app_chirho":"resourceapp","owner_principal_chirho":"owner/test","#,
                r#""meters_chirho":[{"resource_chirho":"labs_credit_chirho","unit_chirho":"credit","#,
                r#""stack_chirho":"labs","per_user_limit_chirho":10,"app_limit_chirho":30,"#,
                r#""window_ms_chirho":60000,"overage_chirho":{"RouteChirho":{"route_chirho":"limit-reached","#,
                r#""forward_request_body_chirho":true}}}],"#,
                r#""actions_chirho":[{"section_chirho":"builder","action_chirho":"submit","#,
                r#""effect_chirho":"write_store_chirho","allow_anonymous_chirho":false,"#,
                r#""charges_chirho":[{"resource_chirho":"labs_credit_chirho","amount_chirho":3}]}],"#,
                r#""previous_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","at_ms_chirho":1234}"#
            )
        );
    }

    #[test]
    fn resource_usage_decision_routes_and_fails_closed_chirho() {
        let policy_hash_chirho = hash_chirho('b');
        let policy_chirho = propose_resource_policy_chirho(
            "resourceapp",
            "owner/test",
            vec![meter_chirho()],
            vec![action_chirho()],
            Some(hash_chirho('a')),
            1234,
        )
        .unwrap();
        let prior_chirho = vec![allowed_usage_chirho(0, "user/test", 8, 100)];
        let action_policy_chirho = find_action_policy_chirho(
            &policy_chirho,
            "builder",
            "submit",
            Some("write_store_chirho"),
        )
        .unwrap();
        let decision_chirho = decide_resource_usage_chirho(
            &policy_chirho,
            &policy_hash_chirho,
            &prior_chirho,
            "resourceapp",
            "user/test",
            &action_policy_chirho.charges_chirho,
            110,
        )
        .unwrap();
        assert_eq!(
            decision_chirho,
            ResourceDecisionChirho::RoutedChirho {
                resource_chirho: "labs_credit_chirho".to_string(),
                route_chirho: "limit-reached".to_string(),
                forward_request_body_chirho: true,
                limit_chirho: 10,
                used_chirho: 8,
                attempted_chirho: 11,
            }
        );

        let fail_closed_chirho = propose_resource_policy_chirho(
            "resourceapp",
            "owner/test",
            vec![ResourceMeterChirho {
                overage_chirho: ResourceOverageChirho::FailClosedChirho,
                ..meter_chirho()
            }],
            vec![action_chirho()],
            Some(hash_chirho('a')),
            1234,
        )
        .unwrap();
        let error_chirho = decide_resource_usage_chirho(
            &fail_closed_chirho,
            &policy_hash_chirho,
            &prior_chirho,
            "resourceapp",
            "user/test",
            &action_policy_chirho.charges_chirho,
            110,
        )
        .unwrap_err()
        .to_string();
        assert!(error_chirho.contains("resource 'labs_credit_chirho' exhausted"));
    }

    #[test]
    fn resource_validation_stays_fail_closed_chirho() {
        let duplicate_chirho = propose_resource_policy_chirho(
            "resourceapp",
            "owner/test",
            vec![meter_chirho(), meter_chirho()],
            vec![action_chirho()],
            None,
            1,
        )
        .unwrap_err()
        .to_string();
        assert!(duplicate_chirho.contains("duplicate resource meter"));

        let usage_chirho = ResourceUsageRecordChirho {
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "labs_credit_chirho".to_string(),
                amount_chirho: 0,
            }],
            ..allowed_usage_chirho(0, "user/test", 1, 100)
        };
        assert_eq!(
            validate_resource_usage_record_chirho(&usage_chirho)
                .unwrap_err()
                .to_string(),
            "resource usage charge amount_chirho must be positive"
        );
    }

    fn set_state_chirho(
        app_chirho: &str,
        policy_chirho: char,
        at_ms_chirho: u64,
    ) -> VerifiedResourcePolicyStateChirho {
        VerifiedResourcePolicyStateChirho {
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: "owner/test".to_string(),
            resource_policy_chirho: hash_chirho(policy_chirho),
            previous_chirho: None,
            at_ms_chirho,
        }
    }

    fn unset_state_chirho(
        app_chirho: &str,
        previous_chirho: char,
        at_ms_chirho: u64,
    ) -> VerifiedResourcePolicyUnsetStateChirho {
        VerifiedResourcePolicyUnsetStateChirho {
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: "owner/test".to_string(),
            previous_chirho: hash_chirho(previous_chirho),
            at_ms_chirho,
        }
    }

    fn latest_hash_chirho(
        sets_chirho: &BTreeMap<u64, VerifiedResourcePolicyStateChirho>,
        unsets_chirho: &BTreeMap<u64, VerifiedResourcePolicyUnsetStateChirho>,
    ) -> Option<HashChirho> {
        match latest_policy_event_chirho("resourceapp", sets_chirho, unsets_chirho) {
            Some(LatestPolicyEventChirho::SetChirho { state_chirho, .. }) => {
                Some(state_chirho.resource_policy_chirho.clone())
            }
            _ => None,
        }
    }

    #[test]
    fn latest_policy_event_unset_clears_superseded_chain_chirho() {
        let sets_chirho = BTreeMap::from([
            (0, set_state_chirho("resourceapp", 'a', 100)),
            (1, set_state_chirho("resourceapp", 'b', 200)),
        ]);
        let unsets_chirho = BTreeMap::from([(0, unset_state_chirho("resourceapp", 'b', 300))]);
        assert_eq!(latest_hash_chirho(&sets_chirho, &unsets_chirho), None);
    }

    #[test]
    fn latest_policy_event_reset_same_hash_stays_current_chirho() {
        let sets_chirho = BTreeMap::from([
            (0, set_state_chirho("resourceapp", 'a', 100)),
            (1, set_state_chirho("resourceapp", 'a', 300)),
        ]);
        let unsets_chirho = BTreeMap::from([(0, unset_state_chirho("resourceapp", 'a', 200))]);
        assert_eq!(
            latest_hash_chirho(&sets_chirho, &unsets_chirho),
            Some(hash_chirho('a'))
        );
    }

    #[test]
    fn latest_policy_event_tie_keeps_the_set_chirho() {
        let sets_chirho = BTreeMap::from([(0, set_state_chirho("resourceapp", 'a', 100))]);
        let unsets_chirho = BTreeMap::from([(0, unset_state_chirho("resourceapp", 'a', 100))]);
        assert_eq!(
            latest_hash_chirho(&sets_chirho, &unsets_chirho),
            Some(hash_chirho('a'))
        );
    }

    #[test]
    fn latest_policy_event_duplicate_unsets_stay_inert_chirho() {
        let sets_chirho = BTreeMap::from([(0, set_state_chirho("resourceapp", 'a', 100))]);
        let unsets_chirho = BTreeMap::from([
            (0, unset_state_chirho("resourceapp", 'a', 200)),
            (1, unset_state_chirho("resourceapp", 'a', 250)),
        ]);
        assert_eq!(latest_hash_chirho(&sets_chirho, &unsets_chirho), None);
        let resets_chirho = BTreeMap::from([
            (0, set_state_chirho("resourceapp", 'a', 100)),
            (1, set_state_chirho("resourceapp", 'a', 400)),
        ]);
        assert_eq!(
            latest_hash_chirho(&resets_chirho, &unsets_chirho),
            Some(hash_chirho('a'))
        );
    }

    #[test]
    fn latest_policy_event_ignores_other_apps_chirho() {
        let sets_chirho = BTreeMap::from([
            (0, set_state_chirho("resourceapp", 'a', 100)),
            (1, set_state_chirho("otherapp", 'b', 500)),
        ]);
        let unsets_chirho = BTreeMap::from([(0, unset_state_chirho("otherapp", 'b', 600))]);
        assert_eq!(
            latest_hash_chirho(&sets_chirho, &unsets_chirho),
            Some(hash_chirho('a'))
        );
        assert!(latest_policy_event_chirho("neverapp", &sets_chirho, &unsets_chirho).is_none());
    }
}
