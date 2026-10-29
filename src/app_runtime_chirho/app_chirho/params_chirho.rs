// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Signed app-params records for verified app input injection.

use super::{
    ensure_app_owner_chirho, resolve_app_dag_chirho, resolve_app_route_chirho,
    validate_app_name_chirho, validate_route_name_chirho,
};
use crate::model_chirho::HashChirho;
use crate::{refs_chirho, seqlog_chirho, store_chirho};
use anyhow::{bail, Context, Result};
use cairn_model_app_chirho::{
    app_params_policy_chirho::{
        app_params_record_signed_message_chirho, app_params_selection_from_record_chirho,
        selected_app_params_record_chirho, validate_app_params_record_shape_chirho,
    },
    AppParamsRecordChirho, AppParamsSelectionChirho, APP_PARAMS_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};

pub fn set_app_params_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
    value_chirho: &serde_json::Value,
    required_chirho: bool,
) -> Result<AppParamsRecordChirho> {
    let hash_chirho = store_chirho::put_object_chirho(root_chirho, value_chirho)?;
    set_app_params_hash_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        hash_chirho,
        required_chirho,
    )
}

pub fn set_app_params_hash_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
    params_chirho: HashChirho,
    required_chirho: bool,
) -> Result<AppParamsRecordChirho> {
    validate_app_params_target_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    )?;
    validate_app_params_object_chirho(root_chirho, &params_chirho)?;
    append_app_params_record_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        params_chirho,
        required_chirho,
    )
}

pub fn app_params_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
) -> Result<Option<AppParamsSelectionChirho>> {
    validate_app_name_chirho(app_chirho)?;
    if let Some(route_chirho) = route_chirho {
        validate_route_name_chirho(route_chirho)?;
    }
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let records_chirho = verified_app_params_records_chirho(root_chirho)?;
    let record_chirho = selected_app_params_record_chirho(
        &records_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    );
    let Some(record_chirho) = record_chirho else {
        return Ok(None);
    };
    let value_chirho = load_app_params_value_chirho(root_chirho, &record_chirho.params_chirho)
        .with_context(|| {
            format!(
                "selected app params record {} for app '{}' points at unavailable params {}",
                record_chirho.seq_chirho, app_chirho, record_chirho.params_chirho.0
            )
        })?;
    Ok(Some(app_params_selection_from_record_chirho(
        record_chirho,
        value_chirho,
    )))
}

pub fn verify_app_params_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_params_records_chirho(root_chirho)?;
    verify_app_params_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

pub fn load_app_params_records_chirho(root_chirho: &Path) -> Result<Vec<AppParamsRecordChirho>> {
    super::load_counted_serialized_jsonl_chirho(&app_params_records_path_chirho(root_chirho))
}

fn verified_app_params_records_chirho(root_chirho: &Path) -> Result<Vec<AppParamsRecordChirho>> {
    Ok(
        super::verified_view_cache_chirho::cached_params_records_chirho(root_chirho, || {
            let records_chirho = load_app_params_records_chirho(root_chirho)?;
            verify_app_params_records_chirho(root_chirho, &records_chirho)?;
            Ok(records_chirho)
        })?
        .as_ref()
        .clone(),
    )
}

fn verify_app_params_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppParamsRecordChirho],
) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut owner_check_chirho = super::AppOwnerLoopCheckChirho::new_chirho();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        validate_app_params_record_shape_chirho(
            record_chirho,
            i_chirho,
            APP_PARAMS_RECORD_SCHEMA_CHIRHO,
        )?;
        owner_check_chirho.ensure_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        validate_app_params_object_chirho(root_chirho, &record_chirho.params_chirho).with_context(
            || {
                format!(
                    "app params record {} points at missing params {}",
                    record_chirho.seq_chirho, record_chirho.params_chirho.0
                )
            },
        )?;
        let message_chirho = app_params_record_signed_message_chirho(record_chirho)?;
        if !super::verify_record_sig_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "app params record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn validate_app_params_target_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
) -> Result<()> {
    validate_app_name_chirho(app_chirho)?;
    if let Some(route_chirho) = route_chirho {
        validate_route_name_chirho(route_chirho)?;
    }
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    if let Some(route_chirho) = route_chirho {
        let _route_dag_chirho = resolve_app_route_chirho(
            root_chirho,
            &refs_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
        )?;
    } else {
        let resolved_chirho = resolve_app_dag_chirho(root_chirho, &refs_chirho, app_chirho)?;
        if resolved_chirho.owner_principal_chirho != owner_principal_chirho {
            bail!(
                "app '{app_chirho}' is owned by '{}', not '{owner_principal_chirho}'",
                resolved_chirho.owner_principal_chirho
            );
        }
    }
    Ok(())
}

fn validate_app_params_object_chirho(root_chirho: &Path, params_chirho: &HashChirho) -> Result<()> {
    let _value_chirho = load_app_params_value_chirho(root_chirho, params_chirho)?;
    Ok(())
}

fn load_app_params_value_chirho(
    root_chirho: &Path,
    params_chirho: &HashChirho,
) -> Result<serde_json::Value> {
    store_chirho::get_object_chirho(root_chirho, params_chirho)
}

fn append_app_params_record_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
    params_chirho: HashChirho,
    required_chirho: bool,
) -> Result<AppParamsRecordChirho> {
    let path_chirho = app_params_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = AppParamsRecordChirho {
            seq_chirho,
            schema_chirho: APP_PARAMS_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            route_chirho: route_chirho.map(str::to_string),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            params_chirho: params_chirho.clone(),
            required_chirho,
            at_ms_chirho: super::now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = app_params_record_signed_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn app_params_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-params-records-chirho.jsonl")
}

#[cfg(test)]
#[path = "params_chirho/params_tests_chirho.rs"]
mod params_tests_chirho;
