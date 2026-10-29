// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure app-head transition validation, encoding, and verified-history selection.

use crate::{
    AppActionChirho, AppRecordChirho, ResolvedAppDagChirho, APP_RECORD_SCHEMA_CHIRHO,
    APP_RECORD_V2_SCHEMA_CHIRHO,
};
use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::Serialize;
use std::collections::BTreeSet;

pub fn app_action_is_reviewed_deploy_chirho(action_chirho: &AppActionChirho) -> bool {
    matches!(action_chirho, AppActionChirho::DeployChirho)
}

pub fn app_action_is_unreviewed_dev_chirho(action_chirho: &AppActionChirho) -> bool {
    matches!(action_chirho, AppActionChirho::DeployUnreviewedDevChirho)
}

pub fn app_action_is_deploy_chirho(action_chirho: &AppActionChirho) -> bool {
    app_action_is_reviewed_deploy_chirho(action_chirho)
        || app_action_is_unreviewed_dev_chirho(action_chirho)
}

pub fn validate_app_record_schema_chirho(record_chirho: &AppRecordChirho) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != APP_RECORD_SCHEMA_CHIRHO
        && record_chirho.schema_chirho != APP_RECORD_V2_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported app record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

pub fn validate_app_record_transition_shape_chirho(
    record_chirho: &AppRecordChirho,
    transition_id_prefix_chirho: &str,
) -> Result<()> {
    if record_chirho.schema_chirho == APP_RECORD_V2_SCHEMA_CHIRHO {
        if !app_action_is_deploy_chirho(&record_chirho.action_chirho)
            || record_chirho.dag_chirho.is_none()
        {
            bail!("app v2 record must be a deploy with a DAG");
        }
        if !record_chirho
            .transition_id_chirho
            .starts_with(transition_id_prefix_chirho)
            || record_chirho.prepared_writer_fence_epoch_chirho == Some(0)
            || record_chirho.prepared_writer_fence_epoch_chirho.is_none()
        {
            bail!("app v2 record has incomplete head transition evidence");
        }
    } else if record_chirho.previous_chirho.is_some()
        || !record_chirho.transition_id_chirho.is_empty()
        || record_chirho.prepared_writer_fence_epoch_chirho.is_some()
    {
        bail!("legacy app record must not carry head transition evidence");
    }
    Ok(())
}

pub fn app_head_transition_operation_bytes_chirho(
    record_chirho: &AppRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppHeadTransitionOperationChirho<'a> {
        schema_chirho: &'static str,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        action_chirho: &'a AppActionChirho,
        previous_chirho: &'a Option<HashChirho>,
        next_chirho: &'a Option<HashChirho>,
    }
    Ok(serde_json::to_vec(&AppHeadTransitionOperationChirho {
        schema_chirho: APP_RECORD_V2_SCHEMA_CHIRHO,
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        action_chirho: &record_chirho.action_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &record_chirho.dag_chirho,
    })?)
}

pub fn selected_app_record_from_verified_history_chirho<'a>(
    records_chirho: &'a [AppRecordChirho],
    app_chirho: &str,
    ref_dag_chirho: &HashChirho,
) -> Result<&'a AppRecordChirho> {
    let app_records_chirho = records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
        .collect::<Vec<_>>();
    let latest_chirho = app_records_chirho
        .last()
        .ok_or_else(|| anyhow!("app '{app_chirho}' has no signed owner record"))?;
    if matches!(latest_chirho.action_chirho, AppActionChirho::UndeployChirho) {
        bail!("no deployed app '{app_chirho}'");
    }
    let owner_principal_chirho = &latest_chirho.owner_principal_chirho;
    app_records_chirho
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.owner_principal_chirho == *owner_principal_chirho
                && app_action_is_deploy_chirho(&record_chirho.action_chirho)
                && record_chirho.dag_chirho.as_ref() == Some(ref_dag_chirho)
        })
        .ok_or_else(|| {
            anyhow!("app '{app_chirho}' ref does not match any signed app deploy record")
        })
}

pub fn app_previous_is_verified_chirho(
    records_chirho: &[AppRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
    previous_chirho: &HashChirho,
) -> bool {
    records_chirho.iter().any(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.owner_principal_chirho == owner_principal_chirho
            && app_action_is_deploy_chirho(&record_chirho.action_chirho)
            && record_chirho.dag_chirho.as_ref() == Some(previous_chirho)
    })
}

pub fn resolved_app_dag_from_selected_record_chirho(
    app_chirho: &str,
    record_chirho: &AppRecordChirho,
) -> Result<ResolvedAppDagChirho> {
    let dag_chirho = record_chirho
        .dag_chirho
        .clone()
        .ok_or_else(|| anyhow!("selected app deploy record has no DAG"))?;
    Ok(ResolvedAppDagChirho {
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
        dag_chirho,
        unreviewed_dev_chirho: app_action_is_unreviewed_dev_chirho(&record_chirho.action_chirho),
    })
}

pub fn latest_app_record_for_app_chirho<'a>(
    records_chirho: &'a [AppRecordChirho],
    app_chirho: &str,
) -> Option<&'a AppRecordChirho> {
    records_chirho
        .iter()
        .rev()
        .find(|record_chirho| record_chirho.app_chirho == app_chirho)
}

pub fn verified_app_owner_from_records_chirho(
    records_chirho: &[AppRecordChirho],
    app_chirho: &str,
) -> Option<String> {
    latest_app_record_for_app_chirho(records_chirho, app_chirho)
        .map(|record_chirho| record_chirho.owner_principal_chirho.clone())
}

pub fn app_owner_from_records_chirho(
    records_chirho: &[AppRecordChirho],
    app_chirho: &str,
) -> Option<String> {
    latest_app_record_for_app_chirho(records_chirho, app_chirho)
        .map(|record_chirho| record_chirho.owner_principal_chirho.clone())
}

pub fn app_deploy_dags_from_verified_records_chirho(
    records_chirho: &[AppRecordChirho],
    app_chirho: &str,
) -> BTreeSet<HashChirho> {
    records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && app_action_is_deploy_chirho(&record_chirho.action_chirho)
        })
        .filter_map(|record_chirho| record_chirho.dag_chirho.clone())
        .collect()
}

pub fn app_records_for_app_chirho(
    records_chirho: Vec<AppRecordChirho>,
    app_chirho: &str,
) -> Vec<AppRecordChirho> {
    records_chirho
        .into_iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
        .collect()
}

#[cfg(test)]
#[path = "tests_chirho/app_head_transition_tests_chirho.rs"]
mod tests_chirho;
