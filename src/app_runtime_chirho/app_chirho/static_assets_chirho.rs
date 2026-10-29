// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Signed app static asset records for content-addressed same-origin assets.

use super::{ensure_app_owner_chirho, validate_app_name_chirho};
use crate::model_chirho::HashChirho;
use crate::{cas_chirho, seqlog_chirho};
use anyhow::{bail, Context, Result};
use cairn_model_app_chirho::{
    normalize_app_static_asset_content_type_chirho, validate_app_static_asset_name_chirho,
    AppStaticAssetRecordChirho, AppStaticAssetSelectionChirho,
    APP_STATIC_ASSET_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn app_static_asset_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-static-asset-records-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

struct AppStaticAssetAppendChirho<'a> {
    app_chirho: &'a str,
    owner_principal_chirho: &'a str,
    name_chirho: &'a str,
    asset_chirho: &'a HashChirho,
    content_type_chirho: &'a str,
    byte_len_chirho: u64,
    removed_chirho: bool,
}

pub fn set_app_static_asset_bytes_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    name_chirho: &str,
    content_type_chirho: &str,
    bytes_chirho: &[u8],
) -> Result<AppStaticAssetRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    validate_app_static_asset_name_chirho(name_chirho)?;
    let content_type_chirho = normalize_app_static_asset_content_type_chirho(content_type_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let asset_chirho = cas_chirho::add_chirho(root_chirho, bytes_chirho)?;
    append_app_static_asset_record_chirho(
        root_chirho,
        AppStaticAssetAppendChirho {
            app_chirho,
            owner_principal_chirho,
            name_chirho,
            asset_chirho: &asset_chirho,
            content_type_chirho: &content_type_chirho,
            byte_len_chirho: bytes_chirho.len() as u64,
            removed_chirho: false,
        },
    )
}

pub fn set_app_static_asset_hash_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    name_chirho: &str,
    asset_chirho: HashChirho,
    content_type_chirho: &str,
    byte_len_chirho: u64,
) -> Result<AppStaticAssetRecordChirho> {
    validate_app_name_chirho(app_chirho)?;
    validate_app_static_asset_name_chirho(name_chirho)?;
    let content_type_chirho = normalize_app_static_asset_content_type_chirho(content_type_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let bytes_chirho = cas_chirho::get_chirho(root_chirho, &asset_chirho)?;
    if bytes_chirho.len() as u64 != byte_len_chirho {
        bail!(
            "asset '{}' declared byte_len_chirho {} but CAS has {} bytes",
            asset_chirho.0,
            byte_len_chirho,
            bytes_chirho.len()
        );
    }
    append_app_static_asset_record_chirho(
        root_chirho,
        AppStaticAssetAppendChirho {
            app_chirho,
            owner_principal_chirho,
            name_chirho,
            asset_chirho: &asset_chirho,
            content_type_chirho: &content_type_chirho,
            byte_len_chirho,
            removed_chirho: false,
        },
    )
}

pub fn remove_app_static_asset_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    name_chirho: &str,
) -> Result<bool> {
    validate_app_name_chirho(app_chirho)?;
    validate_app_static_asset_name_chirho(name_chirho)?;
    ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let Some(selection_chirho) =
        app_static_asset_by_name_chirho(root_chirho, app_chirho, name_chirho)?
    else {
        return Ok(false);
    };
    let empty_asset_chirho = cas_chirho::add_chirho(root_chirho, b"")?;
    append_app_static_asset_record_chirho(
        root_chirho,
        AppStaticAssetAppendChirho {
            app_chirho,
            owner_principal_chirho,
            name_chirho,
            asset_chirho: &empty_asset_chirho,
            content_type_chirho: &selection_chirho.record_chirho.content_type_chirho,
            byte_len_chirho: 0,
            removed_chirho: true,
        },
    )?;
    Ok(true)
}

pub fn app_static_asset_by_name_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    name_chirho: &str,
) -> Result<Option<AppStaticAssetSelectionChirho>> {
    validate_app_name_chirho(app_chirho)?;
    validate_app_static_asset_name_chirho(name_chirho)?;
    Ok(verified_app_static_asset_records_chirho(root_chirho)?
        .into_iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.app_chirho == app_chirho && record_chirho.name_chirho == name_chirho
        })
        .and_then(|record_chirho| {
            (!record_chirho.removed_chirho)
                .then_some(AppStaticAssetSelectionChirho { record_chirho })
        }))
}

pub fn app_static_asset_by_hash_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    asset_chirho: &HashChirho,
) -> Result<Option<AppStaticAssetSelectionChirho>> {
    validate_app_name_chirho(app_chirho)?;
    let mut removed_names_chirho = BTreeSet::new();
    for record_chirho in verified_app_static_asset_records_chirho(root_chirho)?
        .into_iter()
        .rev()
    {
        if record_chirho.app_chirho != app_chirho {
            continue;
        }
        if record_chirho.removed_chirho {
            removed_names_chirho.insert(record_chirho.name_chirho);
            continue;
        }
        if removed_names_chirho.contains(&record_chirho.name_chirho) {
            continue;
        }
        if &record_chirho.asset_chirho == asset_chirho {
            return Ok(Some(AppStaticAssetSelectionChirho { record_chirho }));
        }
    }
    Ok(None)
}

pub fn app_static_asset_bytes_chirho(
    root_chirho: &Path,
    selection_chirho: &AppStaticAssetSelectionChirho,
) -> Result<Vec<u8>> {
    let bytes_chirho =
        cas_chirho::get_chirho(root_chirho, &selection_chirho.record_chirho.asset_chirho)?;
    if bytes_chirho.len() as u64 != selection_chirho.record_chirho.byte_len_chirho {
        bail!("app static asset byte length mismatch");
    }
    Ok(bytes_chirho)
}

pub fn load_app_static_asset_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppStaticAssetRecordChirho>> {
    let path_chirho = app_static_asset_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    #[cfg(test)]
    super::verified_view_cache_chirho::test_metrics_chirho::note_full_log_load_chirho();
    #[cfg(any(test, feature = "serve-runtime-test-hooks-chirho"))]
    super::control_log_load_metrics_chirho::note_load_chirho(&path_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho.lines() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho)?);
    }
    Ok(records_chirho)
}

pub fn verify_app_static_assets_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_app_static_asset_records_chirho(root_chirho)?;
    verify_app_static_asset_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

pub fn verified_app_static_asset_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppStaticAssetRecordChirho>> {
    Ok(
        super::verified_view_cache_chirho::cached_static_asset_records_chirho(root_chirho, || {
            let records_chirho = load_app_static_asset_records_chirho(root_chirho)?;
            verify_app_static_asset_records_chirho(root_chirho, &records_chirho)?;
            Ok(records_chirho)
        })?
        .as_ref()
        .clone(),
    )
}

fn verify_app_static_asset_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppStaticAssetRecordChirho],
) -> Result<()> {
    if records_chirho.is_empty() {
        return Ok(());
    }
    let pubkey_chirho = signer_chirho::existing_pubkey_hex_chirho(root_chirho)?;
    let mut owner_check_chirho = super::AppOwnerLoopCheckChirho::new_chirho();
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if !record_chirho.schema_chirho.is_empty()
            && record_chirho.schema_chirho != APP_STATIC_ASSET_RECORD_SCHEMA_CHIRHO
        {
            bail!(
                "unsupported app static asset record schema '{}'",
                record_chirho.schema_chirho
            );
        }
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "app static asset record seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        validate_app_name_chirho(&record_chirho.app_chirho)?;
        validate_app_static_asset_name_chirho(&record_chirho.name_chirho)?;
        let normalized_chirho =
            normalize_app_static_asset_content_type_chirho(&record_chirho.content_type_chirho)?;
        if normalized_chirho != record_chirho.content_type_chirho {
            bail!(
                "app static asset record {} content type is not canonical",
                record_chirho.seq_chirho
            );
        }
        owner_check_chirho.ensure_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let bytes_chirho = cas_chirho::get_chirho(root_chirho, &record_chirho.asset_chirho)
            .with_context(|| {
                format!(
                    "app static asset record {} points at missing CAS object {}",
                    record_chirho.seq_chirho, record_chirho.asset_chirho.0
                )
            })?;
        if bytes_chirho.len() as u64 != record_chirho.byte_len_chirho {
            bail!(
                "app static asset record {} byte length mismatch",
                record_chirho.seq_chirho
            );
        }
        let message_chirho = app_static_asset_record_message_chirho(record_chirho)?;
        if !super::verify_record_sig_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "app static asset record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn append_app_static_asset_record_chirho(
    root_chirho: &Path,
    append_chirho: AppStaticAssetAppendChirho<'_>,
) -> Result<AppStaticAssetRecordChirho> {
    let path_chirho = app_static_asset_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = AppStaticAssetRecordChirho {
            seq_chirho,
            schema_chirho: APP_STATIC_ASSET_RECORD_SCHEMA_CHIRHO.to_string(),
            app_chirho: append_chirho.app_chirho.to_string(),
            owner_principal_chirho: append_chirho.owner_principal_chirho.to_string(),
            name_chirho: append_chirho.name_chirho.to_string(),
            asset_chirho: append_chirho.asset_chirho.clone(),
            content_type_chirho: append_chirho.content_type_chirho.to_string(),
            byte_len_chirho: append_chirho.byte_len_chirho,
            removed_chirho: append_chirho.removed_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = app_static_asset_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn app_static_asset_record_message_chirho(
    record_chirho: &AppStaticAssetRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppStaticAssetRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        name_chirho: &'a str,
        asset_chirho: &'a HashChirho,
        content_type_chirho: &'a str,
        byte_len_chirho: u64,
        #[serde(skip_serializing_if = "is_false_chirho")]
        removed_chirho: bool,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&AppStaticAssetRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: (!record_chirho.schema_chirho.is_empty())
            .then_some(record_chirho.schema_chirho.as_str()),
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        name_chirho: &record_chirho.name_chirho,
        asset_chirho: &record_chirho.asset_chirho,
        content_type_chirho: &record_chirho.content_type_chirho,
        byte_len_chirho: record_chirho.byte_len_chirho,
        removed_chirho: record_chirho.removed_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn is_false_chirho(value_chirho: &bool) -> bool {
    !*value_chirho
}

#[cfg(test)]
use cairn_model_app_chirho::{
    APP_STATIC_ASSET_CSS_CONTENT_TYPE_CHIRHO, APP_STATIC_ASSET_PNG_CONTENT_TYPE_CHIRHO,
};
#[cfg(test)]
#[path = "static_assets_chirho/tests_chirho.rs"]
mod tests_chirho;
