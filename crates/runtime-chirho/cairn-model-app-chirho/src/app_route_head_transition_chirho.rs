// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure app-route authority-state identity, transition policy, and verified-history selection.

use crate::{
    AppRouteActionChirho, AppRouteAuthorityStateChirho, AppRouteRecordChirho,
    APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO, APP_ROUTE_RECORD_SCHEMA_CHIRHO,
    APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO,
};
use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::{model_chirho::HashChirho, store_chirho};
use serde::Serialize;

pub fn app_route_action_is_deploy_chirho(action_chirho: &AppRouteActionChirho) -> bool {
    matches!(
        action_chirho,
        AppRouteActionChirho::DeployRouteChirho
            | AppRouteActionChirho::DeployRouteUnreviewedDevChirho
    )
}

pub fn app_route_action_is_unreviewed_dev_chirho(action_chirho: &AppRouteActionChirho) -> bool {
    matches!(
        action_chirho,
        AppRouteActionChirho::DeployRouteUnreviewedDevChirho
    )
}

pub fn validate_app_route_record_schema_chirho(record_chirho: &AppRouteRecordChirho) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != APP_ROUTE_RECORD_SCHEMA_CHIRHO
        && record_chirho.schema_chirho != APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported app route record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

pub fn validate_app_route_record_transition_shape_chirho(
    record_chirho: &AppRouteRecordChirho,
    transition_id_prefix_chirho: &str,
) -> Result<()> {
    if record_chirho.schema_chirho == APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO {
        if !app_route_action_is_deploy_chirho(&record_chirho.action_chirho)
            || record_chirho.dag_chirho.is_none()
        {
            bail!("app route v2 record must be a deploy with a DAG");
        }
        if !record_chirho
            .transition_id_chirho
            .starts_with(transition_id_prefix_chirho)
            || record_chirho.prepared_writer_fence_epoch_chirho == Some(0)
            || record_chirho.prepared_writer_fence_epoch_chirho.is_none()
        {
            bail!("app route v2 record has incomplete head transition evidence");
        }
    } else if record_chirho.previous_chirho.is_some()
        || !record_chirho.transition_id_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho.is_some()
    {
        bail!("legacy app route record must not carry head transition evidence");
    }
    Ok(())
}

pub fn app_route_authority_state_from_record_chirho(
    record_chirho: &AppRouteRecordChirho,
) -> Result<AppRouteAuthorityStateChirho> {
    if !app_route_action_is_deploy_chirho(&record_chirho.action_chirho) {
        bail!("only an app route deploy record defines route authority state");
    }
    Ok(AppRouteAuthorityStateChirho {
        schema_chirho: APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO.to_string(),
        app_chirho: record_chirho.app_chirho.clone(),
        route_chirho: record_chirho.route_chirho.clone(),
        owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
        dag_chirho: record_chirho
            .dag_chirho
            .clone()
            .ok_or_else(|| anyhow!("app route deploy record has no DAG"))?,
        action_chirho: record_chirho.action_chirho.clone(),
        request_body_policy_chirho: record_chirho.request_body_policy_chirho.clone(),
    })
}

pub fn app_route_authority_state_hash_chirho(
    state_chirho: &AppRouteAuthorityStateChirho,
) -> Result<HashChirho> {
    store_chirho::hash_object_chirho(state_chirho)
}

pub fn app_route_ref_target_from_record_chirho(
    record_chirho: &AppRouteRecordChirho,
) -> Result<HashChirho> {
    if record_chirho.schema_chirho == APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO {
        app_route_authority_state_hash_chirho(&app_route_authority_state_from_record_chirho(
            record_chirho,
        )?)
    } else {
        record_chirho
            .dag_chirho
            .clone()
            .ok_or_else(|| anyhow!("legacy app route deploy record has no DAG"))
    }
}

pub fn app_route_head_transition_operation_bytes_chirho(
    record_chirho: &AppRouteRecordChirho,
    state_hash_chirho: &HashChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppRouteHeadTransitionOperationChirho<'a> {
        schema_chirho: &'static str,
        app_chirho: &'a str,
        route_chirho: &'a str,
        owner_principal_chirho: &'a str,
        action_chirho: &'a AppRouteActionChirho,
        dag_chirho: &'a Option<HashChirho>,
        request_body_policy_chirho: &'a Option<crate::AppRouteRequestBodyPolicyChirho>,
        previous_chirho: &'a Option<HashChirho>,
        state_hash_chirho: &'a HashChirho,
    }
    Ok(serde_json::to_vec(
        &AppRouteHeadTransitionOperationChirho {
            schema_chirho: APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO,
            app_chirho: &record_chirho.app_chirho,
            route_chirho: &record_chirho.route_chirho,
            owner_principal_chirho: &record_chirho.owner_principal_chirho,
            action_chirho: &record_chirho.action_chirho,
            dag_chirho: &record_chirho.dag_chirho,
            request_body_policy_chirho: &record_chirho.request_body_policy_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            state_hash_chirho,
        },
    )?)
}

pub fn selected_app_route_record_from_verified_history_chirho<'a>(
    records_chirho: &'a [AppRouteRecordChirho],
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    ref_target_chirho: &HashChirho,
) -> Result<&'a AppRouteRecordChirho> {
    let matching_chirho = records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho == route_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
        })
        .collect::<Vec<_>>();
    let latest_chirho = matching_chirho
        .last()
        .ok_or_else(|| anyhow!("app route '{app_chirho}/{route_chirho}' is not deployed"))?;
    if matches!(
        latest_chirho.action_chirho,
        AppRouteActionChirho::UndeployRouteChirho
    ) {
        bail!("app route '{app_chirho}/{route_chirho}' is not deployed");
    }
    for record_chirho in matching_chirho.into_iter().rev() {
        if app_route_action_is_deploy_chirho(&record_chirho.action_chirho)
            && app_route_ref_target_from_record_chirho(record_chirho)? == *ref_target_chirho
        {
            return Ok(record_chirho);
        }
    }
    bail!(
        "app route '{app_chirho}/{route_chirho}' ref does not match verified signed route history"
    )
}

pub fn app_route_previous_is_verified_chirho(
    records_chirho: &[AppRouteRecordChirho],
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    previous_chirho: &HashChirho,
) -> Result<bool> {
    for record_chirho in records_chirho.iter().filter(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho == route_chirho
            && record_chirho.owner_principal_chirho == owner_principal_chirho
            && app_route_action_is_deploy_chirho(&record_chirho.action_chirho)
    }) {
        if app_route_ref_target_from_record_chirho(record_chirho)? == *previous_chirho {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
#[path = "tests_chirho/app_route_head_transition_tests_chirho.rs"]
mod tests_chirho;
