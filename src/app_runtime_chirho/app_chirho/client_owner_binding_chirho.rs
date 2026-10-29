// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Signed first-build user -> owner bindings for client-owned generated apps.

use crate::{identity_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_model_app_chirho::{
    ClientOwnerBindingRecordChirho, CLIENT_OWNER_BINDING_ACTIVE_STATUS_CHIRHO,
    CLIENT_OWNER_BINDING_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CLIENT_OWNER_BINDING_LOCK_PREFIX_CHIRHO: &str = "client-owner-binding-chirho";

pub fn load_client_owner_binding_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ClientOwnerBindingRecordChirho>> {
    let path_chirho = client_owner_binding_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| {
            serde_json::from_str(line_chirho).context("decode client owner binding record")
        })
        .collect()
}

pub fn verify_client_owner_bindings_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_client_owner_binding_records_chirho(root_chirho)?;
    verify_client_owner_binding_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

pub(crate) fn active_client_owner_binding_for_user_chirho(
    root_chirho: &Path,
    user_principal_chirho: &str,
) -> Result<Option<ClientOwnerBindingRecordChirho>> {
    ensure_principal_kind_chirho(
        root_chirho,
        user_principal_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "user_principal_chirho",
    )?;
    let records_chirho = verified_client_owner_binding_records_chirho(root_chirho)?;
    Ok(records_chirho.into_iter().find(|record_chirho| {
        record_chirho.user_principal_chirho == user_principal_chirho
            && record_chirho.status_chirho == CLIENT_OWNER_BINDING_ACTIVE_STATUS_CHIRHO
    }))
}

pub(crate) fn resolve_or_mint_client_owner_binding_chirho(
    root_chirho: &Path,
    user_principal_chirho: &str,
) -> Result<ClientOwnerBindingRecordChirho> {
    let lock_name_chirho = format!(
        "{CLIENT_OWNER_BINDING_LOCK_PREFIX_CHIRHO}-{}",
        short_principal_hash_chirho(user_principal_chirho)
    );
    seqlog_chirho::with_named_lock_chirho(root_chirho, &lock_name_chirho, || {
        if let Some(record_chirho) =
            active_client_owner_binding_for_user_chirho(root_chirho, user_principal_chirho)?
        {
            return Ok(record_chirho);
        }
        let owner_chirho = identity_chirho::register_identity_chirho(
            root_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
        )?;
        append_client_owner_binding_record_chirho(
            root_chirho,
            user_principal_chirho,
            &owner_chirho.principal_chirho,
        )
    })
}

fn verified_client_owner_binding_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<ClientOwnerBindingRecordChirho>> {
    let records_chirho = load_client_owner_binding_records_chirho(root_chirho)?;
    verify_client_owner_binding_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho)
}

fn verify_client_owner_binding_records_chirho(
    root_chirho: &Path,
    records_chirho: &[ClientOwnerBindingRecordChirho],
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut active_by_user_chirho: BTreeMap<String, String> = BTreeMap::new();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("client owner binding seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != CLIENT_OWNER_BINDING_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported client owner binding schema '{}'",
                record_chirho.schema_chirho
            );
        }
        if record_chirho.status_chirho != CLIENT_OWNER_BINDING_ACTIVE_STATUS_CHIRHO {
            bail!(
                "unsupported client owner binding status '{}'",
                record_chirho.status_chirho
            );
        }
        ensure_principal_kind_chirho(
            root_chirho,
            &record_chirho.user_principal_chirho,
            identity_chirho::PrincipalKindChirho::UserChirho,
            "user_principal_chirho",
        )?;
        ensure_principal_kind_chirho(
            root_chirho,
            &record_chirho.owner_principal_chirho,
            identity_chirho::PrincipalKindChirho::OwnerChirho,
            "owner_principal_chirho",
        )?;
        if active_by_user_chirho
            .insert(
                record_chirho.user_principal_chirho.clone(),
                record_chirho.owner_principal_chirho.clone(),
            )
            .is_some()
        {
            bail!(
                "duplicate active client owner binding for '{}'",
                record_chirho.user_principal_chirho
            );
        }
        let message_chirho = client_owner_binding_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "client owner binding record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn append_client_owner_binding_record_chirho(
    root_chirho: &Path,
    user_principal_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<ClientOwnerBindingRecordChirho> {
    ensure_principal_kind_chirho(
        root_chirho,
        user_principal_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        "user_principal_chirho",
    )?;
    ensure_principal_kind_chirho(
        root_chirho,
        owner_principal_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
        "owner_principal_chirho",
    )?;
    let path_chirho = client_owner_binding_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = ClientOwnerBindingRecordChirho {
            seq_chirho,
            schema_chirho: CLIENT_OWNER_BINDING_RECORD_SCHEMA_CHIRHO.to_string(),
            user_principal_chirho: user_principal_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            status_chirho: CLIENT_OWNER_BINDING_ACTIVE_STATUS_CHIRHO.to_string(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = client_owner_binding_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn ensure_principal_kind_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    expected_chirho: identity_chirho::PrincipalKindChirho,
    label_chirho: &str,
) -> Result<()> {
    let identity_chirho = identity_chirho::find_identity_chirho(root_chirho, principal_chirho)?
        .ok_or_else(|| anyhow!("{label_chirho} '{principal_chirho}' is unknown"))?;
    if identity_chirho.kind_chirho != expected_chirho {
        bail!(
            "{label_chirho} '{}' must be {:?}",
            principal_chirho,
            expected_chirho
        );
    }
    Ok(())
}

fn client_owner_binding_record_message_chirho(
    record_chirho: &ClientOwnerBindingRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct ClientOwnerBindingRecordMessageChirho<'a> {
        seq_chirho: u64,
        schema_chirho: &'a str,
        user_principal_chirho: &'a str,
        owner_principal_chirho: &'a str,
        status_chirho: &'a str,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(
        &ClientOwnerBindingRecordMessageChirho {
            seq_chirho: record_chirho.seq_chirho,
            schema_chirho: &record_chirho.schema_chirho,
            user_principal_chirho: &record_chirho.user_principal_chirho,
            owner_principal_chirho: &record_chirho.owner_principal_chirho,
            status_chirho: &record_chirho.status_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?)
}

fn client_owner_binding_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("client-owner-bindings-chirho.jsonl")
}

fn short_principal_hash_chirho(principal_chirho: &str) -> String {
    crate::cas_chirho::hash_chirho(principal_chirho.as_bytes()).0[..24].to_string()
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "client_owner_binding_chirho/tests_chirho.rs"]
mod tests_chirho;
