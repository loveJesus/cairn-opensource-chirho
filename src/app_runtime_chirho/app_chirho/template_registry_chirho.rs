// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Signed registry of reviewed template DAGs that narrow app-builder deploy effects may instantiate.

use super::normalize_app_response_content_type_chirho;
use crate::model_chirho::{DagChirho, HashChirho};
use crate::{seqlog_chirho, store_chirho};
use anyhow::{bail, Context, Result};
use cairn_model_app_chirho::{
    TemplateRegistryInputChirho, TemplateRegistryRecordChirho, TemplateRegistryTargetChirho,
    TEMPLATE_REGISTRY_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn register_template_app_template_chirho(
    root_chirho: &Path,
    input_chirho: TemplateRegistryInputChirho,
) -> Result<TemplateRegistryRecordChirho> {
    let target_chirho = validate_template_registry_input_chirho(root_chirho, input_chirho)?;
    let path_chirho = template_registry_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = TemplateRegistryRecordChirho {
            seq_chirho,
            schema_chirho: TEMPLATE_REGISTRY_RECORD_SCHEMA_CHIRHO.to_string(),
            template_id_chirho: target_chirho.template_id_chirho.clone(),
            root_dag_chirho: target_chirho.root_dag_chirho.clone(),
            response_content_type_chirho: target_chirho.response_content_type_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = template_registry_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

pub fn load_template_registry_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<TemplateRegistryRecordChirho>> {
    let path_chirho = template_registry_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| serde_json::from_str(line_chirho).context("decode template registry"))
        .collect()
}

pub fn verify_template_registry_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_template_registry_records_chirho(root_chirho)?;
    verify_template_registry_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

pub fn verified_template_registry_chirho(
    root_chirho: &Path,
) -> Result<BTreeMap<String, TemplateRegistryTargetChirho>> {
    let records_chirho = load_template_registry_records_chirho(root_chirho)?;
    verify_template_registry_records_chirho(root_chirho, &records_chirho)?;
    let mut targets_chirho = BTreeMap::new();
    for record_chirho in records_chirho {
        targets_chirho.insert(
            record_chirho.template_id_chirho.clone(),
            TemplateRegistryTargetChirho {
                template_id_chirho: record_chirho.template_id_chirho,
                root_dag_chirho: record_chirho.root_dag_chirho,
                response_content_type_chirho: record_chirho.response_content_type_chirho,
            },
        );
    }
    Ok(targets_chirho)
}

pub(crate) fn template_target_chirho(
    root_chirho: &Path,
    template_id_chirho: &str,
) -> Result<TemplateRegistryTargetChirho> {
    validate_template_id_chirho(template_id_chirho)?;
    verified_template_registry_chirho(root_chirho)?
        .remove(template_id_chirho)
        .ok_or_else(|| {
            anyhow::anyhow!("template_id_chirho '{template_id_chirho}' is not allowlisted")
        })
}

pub(crate) fn validate_template_id_chirho(template_id_chirho: &str) -> Result<()> {
    validate_short_id_chirho("template_id_chirho", template_id_chirho)
}

fn validate_template_registry_input_chirho(
    root_chirho: &Path,
    input_chirho: TemplateRegistryInputChirho,
) -> Result<TemplateRegistryTargetChirho> {
    validate_template_id_chirho(&input_chirho.template_id_chirho)?;
    let _dag_chirho: DagChirho =
        store_chirho::get_object_chirho(root_chirho, &input_chirho.root_dag_chirho).with_context(
            || {
                format!(
                    "template root DAG {} is not in the store",
                    input_chirho.root_dag_chirho.0
                )
            },
        )?;
    let response_content_type_chirho =
        normalize_app_response_content_type_chirho(&input_chirho.response_content_type_chirho)?;
    Ok(TemplateRegistryTargetChirho {
        template_id_chirho: input_chirho.template_id_chirho,
        root_dag_chirho: input_chirho.root_dag_chirho,
        response_content_type_chirho,
    })
}

fn verify_template_registry_records_chirho(
    root_chirho: &Path,
    records_chirho: &[TemplateRegistryRecordChirho],
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("template registry seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != TEMPLATE_REGISTRY_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported template registry schema '{}'",
                record_chirho.schema_chirho
            );
        }
        validate_template_id_chirho(&record_chirho.template_id_chirho)?;
        let normalized_chirho = normalize_app_response_content_type_chirho(
            &record_chirho.response_content_type_chirho,
        )?;
        if normalized_chirho != record_chirho.response_content_type_chirho {
            bail!("template registry response content type must be normalized");
        }
        let _dag_chirho: DagChirho =
            store_chirho::get_object_chirho(root_chirho, &record_chirho.root_dag_chirho)
                .with_context(|| {
                    format!(
                        "template registry record {} points at missing DAG {}",
                        record_chirho.seq_chirho, record_chirho.root_dag_chirho.0
                    )
                })?;
        let message_chirho = template_registry_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "template registry record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_short_id_chirho(label_chirho: &str, value_chirho: &str) -> Result<()> {
    let value_chirho = value_chirho.trim();
    if value_chirho.is_empty() || value_chirho.len() > 128 {
        bail!("{label_chirho} must be 1..=128 chars");
    }
    if !value_chirho
        .chars()
        .all(|ch_chirho| ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '.'))
    {
        bail!("{label_chirho} contains unsupported characters");
    }
    Ok(())
}

fn template_registry_record_message_chirho(
    record_chirho: &TemplateRegistryRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct TemplateRegistryRecordMessageChirho<'a> {
        seq_chirho: u64,
        schema_chirho: &'a str,
        template_id_chirho: &'a str,
        root_dag_chirho: &'a HashChirho,
        response_content_type_chirho: &'a str,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&TemplateRegistryRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: &record_chirho.schema_chirho,
        template_id_chirho: &record_chirho.template_id_chirho,
        root_dag_chirho: &record_chirho.root_dag_chirho,
        response_content_type_chirho: &record_chirho.response_content_type_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn template_registry_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("template-registry-records-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "template_registry_chirho/tests_chirho.rs"]
mod tests_chirho;
