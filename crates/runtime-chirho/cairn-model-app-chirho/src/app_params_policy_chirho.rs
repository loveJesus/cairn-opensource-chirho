// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure app-params record selection and canonical signed-message encoding.

use crate::{
    validate_app_name_chirho, validate_route_name_chirho, AppParamsRecordChirho,
    AppParamsSelectionChirho,
};
use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::Serialize;

pub fn selected_app_params_record_chirho<'a>(
    records_chirho: &'a [AppParamsRecordChirho],
    app_chirho: &str,
    route_chirho: Option<&str>,
    owner_principal_chirho: &str,
) -> Option<&'a AppParamsRecordChirho> {
    let route_record_chirho = route_chirho.and_then(|route_chirho| {
        records_chirho.iter().rev().find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho.as_deref() == Some(route_chirho)
                && record_chirho.owner_principal_chirho == owner_principal_chirho
        })
    });
    route_record_chirho.or_else(|| {
        records_chirho.iter().rev().find(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho.is_none()
                && record_chirho.owner_principal_chirho == owner_principal_chirho
        })
    })
}

pub fn app_params_selection_from_record_chirho(
    record_chirho: &AppParamsRecordChirho,
    value_chirho: serde_json::Value,
) -> AppParamsSelectionChirho {
    AppParamsSelectionChirho {
        params_chirho: record_chirho.params_chirho.clone(),
        value_chirho,
        required_chirho: record_chirho.required_chirho,
    }
}

pub fn validate_app_params_record_shape_chirho(
    record_chirho: &AppParamsRecordChirho,
    index_chirho: usize,
    expected_schema_chirho: &str,
) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != expected_schema_chirho
    {
        bail!(
            "unsupported app params record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    if record_chirho.seq_chirho != index_chirho as u64 {
        bail!(
            "app params record seq gap at index {index_chirho}: entry seq is {}",
            record_chirho.seq_chirho
        );
    }
    validate_app_name_chirho(&record_chirho.app_chirho)?;
    if let Some(route_chirho) = &record_chirho.route_chirho {
        validate_route_name_chirho(route_chirho)?;
    }
    Ok(())
}

pub fn app_params_record_signed_message_chirho(
    record_chirho: &AppParamsRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppParamsRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        route_chirho: &'a Option<String>,
        owner_principal_chirho: &'a str,
        params_chirho: &'a HashChirho,
        required_chirho: bool,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&AppParamsRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: (!record_chirho.schema_chirho.is_empty())
            .then_some(record_chirho.schema_chirho.as_str()),
        app_chirho: &record_chirho.app_chirho,
        route_chirho: &record_chirho.route_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        params_chirho: &record_chirho.params_chirho,
        required_chirho: record_chirho.required_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}
