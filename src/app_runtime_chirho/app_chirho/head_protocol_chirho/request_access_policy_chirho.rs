// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Signed app-wide request admission policy bound to reviewed root DAGs.
//!
//! Workflow: `spec-chirho/workflows-chirho/viewer-state-authority-chirho/README-chirho.md`.

use super::{
    app_request_access_policy_records_path_chirho, ensure_owner_principal_chirho,
    load_counted_serialized_jsonl_chirho, now_ms_chirho, validate_app_name_chirho,
    verified_app_records_chirho, verified_view_cache_chirho, verify_record_sig_chirho,
    AppActionChirho, AppRequestAccessPolicyChirho, AppRequestAccessPolicyRecordChirho, DagChirho,
    APP_REQUEST_ACCESS_POLICY_RECORD_SCHEMA_CHIRHO,
};
use crate::{refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{bail, Result};
use cairn_model_app_chirho::app_request_access_policy_record_signed_message_chirho;
use cairn_signer_chirho::signer_chirho;
use std::collections::BTreeSet;
use std::path::Path;

pub fn set_app_request_access_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    root_dag_chirho: crate::model_chirho::HashChirho,
    policy_chirho: AppRequestAccessPolicyChirho,
) -> Result<AppRequestAccessPolicyRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    ensure_owner_principal_chirho(root_chirho, owner_principal_chirho)?;
    let _dag_chirho: DagChirho = store_chirho::get_object_chirho(root_chirho, &root_dag_chirho)?;

    validate_app_request_access_policy_transition_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
        &policy_chirho,
    )?;
    let access_records_chirho = verified_app_request_access_policy_records_chirho(root_chirho)?;
    if let Some(existing_chirho) = access_records_chirho.iter().rev().find(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.owner_principal_chirho == owner_principal_chirho
            && record_chirho.root_dag_chirho == root_dag_chirho
            && record_chirho.policy_chirho == policy_chirho
    }) {
        return Ok(existing_chirho.clone());
    }

    let path_chirho = app_request_access_policy_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = AppRequestAccessPolicyRecordChirho {
            seq_chirho,
            schema_chirho: APP_REQUEST_ACCESS_POLICY_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            root_dag_chirho: root_dag_chirho.clone(),
            policy_chirho: policy_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho =
            app_request_access_policy_record_signed_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

pub(crate) fn validate_app_request_access_policy_transition_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    policy_chirho: &AppRequestAccessPolicyChirho,
) -> Result<()> {
    if !matches!(policy_chirho, AppRequestAccessPolicyChirho::PublicChirho) {
        return Ok(());
    }
    let access_records_chirho = verified_app_request_access_policy_records_chirho(root_chirho)?;
    let app_records_chirho = verified_app_records_chirho(root_chirho)?;
    if applied_authenticated_policy_exists_chirho(
        &access_records_chirho,
        &app_records_chirho,
        app_chirho,
        owner_principal_chirho,
    ) {
        bail!(
            "app '{app_chirho}' cannot downgrade to PublicChirho after an applied signed AuthenticatedChirho policy"
        );
    }
    Ok(())
}

pub fn app_request_access_policy_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<AppRequestAccessPolicyChirho> {
    validate_app_name_chirho(app_chirho)?;
    let access_records_chirho = verified_app_request_access_policy_records_chirho(root_chirho)?;
    if !access_records_chirho
        .iter()
        .any(|record_chirho| record_chirho.app_chirho == app_chirho)
    {
        return Ok(AppRequestAccessPolicyChirho::PublicChirho);
    }
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let selected_chirho =
        super::verified_selected_app_record_chirho(root_chirho, &refs_chirho, app_chirho)?;
    let root_dag_chirho = selected_chirho
        .dag_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("selected app deploy record has no DAG"))?;
    let app_records_chirho = verified_app_records_chirho(root_chirho)?;
    Ok(app_request_access_policy_from_verified_records_chirho(
        &access_records_chirho,
        &app_records_chirho,
        app_chirho,
        &selected_chirho.owner_principal_chirho,
        root_dag_chirho,
    ))
}

pub fn load_app_request_access_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppRequestAccessPolicyRecordChirho>> {
    load_counted_serialized_jsonl_chirho(&app_request_access_policy_records_path_chirho(
        root_chirho,
    ))
}

pub fn verify_app_request_access_policies_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_request_access_policy_records_chirho(root_chirho)?;
    verify_app_request_access_policy_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

fn verified_app_request_access_policy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppRequestAccessPolicyRecordChirho>> {
    Ok(
        verified_view_cache_chirho::cached_request_access_policy_records_chirho(
            root_chirho,
            || {
                let records_chirho = load_app_request_access_policy_records_chirho(root_chirho)?;
                verify_app_request_access_policy_records_chirho(root_chirho, &records_chirho)?;
                Ok(records_chirho)
            },
        )?
        .as_ref()
        .clone(),
    )
}

fn verify_app_request_access_policy_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppRequestAccessPolicyRecordChirho],
) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let public_key_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.schema_chirho != APP_REQUEST_ACCESS_POLICY_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported app request access policy record schema '{}'",
                record_chirho.schema_chirho
            );
        }
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!(
                "app request access policy record seq gap at index {index_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_app_name_chirho(&record_chirho.app_chirho)?;
        ensure_owner_principal_chirho(root_chirho, &record_chirho.owner_principal_chirho)?;
        let _dag_chirho: DagChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.root_dag_chirho)?;
        let message_chirho = app_request_access_policy_record_signed_message_chirho(record_chirho)?;
        if !verify_record_sig_chirho(
            &public_key_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "app request access policy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn app_request_access_policy_from_verified_records_chirho(
    access_records_chirho: &[AppRequestAccessPolicyRecordChirho],
    app_records_chirho: &[super::AppRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
    active_root_dag_chirho: &crate::model_chirho::HashChirho,
) -> AppRequestAccessPolicyChirho {
    if applied_authenticated_policy_exists_chirho(
        access_records_chirho,
        app_records_chirho,
        app_chirho,
        owner_principal_chirho,
    ) {
        return AppRequestAccessPolicyChirho::AuthenticatedChirho;
    }
    access_records_chirho
        .iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
                && &record_chirho.root_dag_chirho == active_root_dag_chirho
        })
        .map(|record_chirho| record_chirho.policy_chirho.clone())
        .unwrap_or_default()
}

fn applied_authenticated_policy_exists_chirho(
    access_records_chirho: &[AppRequestAccessPolicyRecordChirho],
    app_records_chirho: &[super::AppRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> bool {
    let applied_dags_chirho = app_records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
                && matches!(
                    record_chirho.action_chirho,
                    AppActionChirho::DeployChirho | AppActionChirho::DeployUnreviewedDevChirho
                )
        })
        .filter_map(|record_chirho| record_chirho.dag_chirho.clone())
        .collect::<BTreeSet<_>>();
    access_records_chirho.iter().any(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.owner_principal_chirho == owner_principal_chirho
            && matches!(
                record_chirho.policy_chirho,
                AppRequestAccessPolicyChirho::AuthenticatedChirho
            )
            && applied_dags_chirho.contains(&record_chirho.root_dag_chirho)
    })
}
