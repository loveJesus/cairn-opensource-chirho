// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Host-private NetChirho body persistence helpers.

use super::{NetRequestChirho, NetResponseChirho};
use crate::model_chirho::HashChirho;
use crate::{cas_chirho, privacy_chirho};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use std::collections::BTreeMap;
use std::path::Path;

pub(super) struct NetBodyPersistenceChirho {
    pub request_body_hash_chirho: HashChirho,
    pub response_body_hash_chirho: HashChirho,
    pub request_body_private_ref_chirho: Option<privacy_chirho::PrivateBlobRefChirho>,
    pub response_body_private_ref_chirho: Option<privacy_chirho::PrivateBlobRefChirho>,
    pub body_base64_chirho: String,
}

/// Persist a net request's bodies: privately, under the caller's attribution, when they carry a private
/// subject or host-private headers; otherwise as ordinary CAS node I/O. A private body with no
/// attribution refuses before anything is stored.
/// A private net request's host-only parts: its secret headers, the subject a private body is stored under
/// when its caller names one, and whose container any private body joins.
pub struct PrivateNetPartsChirho<'a> {
    pub headers_chirho: &'a BTreeMap<String, String>,
    pub body_subject_chirho: Option<&'a str>,
    pub attribution_chirho: &'a privacy_chirho::PrivateBlobAttributionChirho,
}

pub(super) fn persist_net_bodies_chirho(
    root_chirho: &Path,
    body_chirho: &[u8],
    response_body_chirho: &[u8],
    private_headers_chirho: &BTreeMap<String, String>,
    private_body_subject_chirho: Option<&str>,
    attribution_chirho: Option<&privacy_chirho::PrivateBlobAttributionChirho>,
) -> Result<NetBodyPersistenceChirho> {
    let request_body_hash_chirho = cas_chirho::hash_chirho(body_chirho);
    let response_body_hash_chirho = cas_chirho::hash_chirho(response_body_chirho);
    let private_subject_chirho = private_net_body_subject_chirho(
        private_body_subject_chirho,
        private_headers_chirho,
        &request_body_hash_chirho,
        attribution_chirho,
    );
    let (request_body_private_ref_chirho, response_body_private_ref_chirho, body_base64_chirho) =
        match private_subject_chirho {
            Some(subject_chirho) => {
                let attribution_chirho = attribution_chirho.ok_or_else(|| {
                    anyhow!("a private net body has no attribution, so it is not stored")
                })?;
                (
                    Some(privacy_chirho::store_private_blob_chirho(
                        root_chirho,
                        attribution_chirho,
                        &subject_chirho,
                        body_chirho,
                    )?),
                    Some(privacy_chirho::store_private_blob_chirho(
                        root_chirho,
                        attribution_chirho,
                        &subject_chirho,
                        response_body_chirho,
                    )?),
                    String::new(),
                )
            }
            None => (None, None, BASE64_CHIRHO.encode(response_body_chirho)),
        };
    if request_body_private_ref_chirho.is_none() {
        cas_chirho::add_chirho(root_chirho, body_chirho)?;
        cas_chirho::add_chirho(root_chirho, response_body_chirho)?;
    }
    Ok(NetBodyPersistenceChirho {
        request_body_hash_chirho,
        response_body_hash_chirho,
        request_body_private_ref_chirho,
        response_body_private_ref_chirho,
        body_base64_chirho,
    })
}

pub fn net_response_body_bytes_chirho(
    root_chirho: &Path,
    response_chirho: &NetResponseChirho,
) -> Result<Vec<u8>> {
    if let Some(response_ref_chirho) = &response_chirho.response_body_private_ref_chirho {
        return privacy_chirho::load_private_blob_chirho(root_chirho, response_ref_chirho);
    }
    BASE64_CHIRHO
        .decode(response_chirho.body_base64_chirho.as_bytes())
        .context("decode NetResponseChirho body_base64_chirho")
}

pub(super) fn private_net_logged_request_bytes_chirho(
    request_bytes_chirho: &[u8],
) -> Result<Vec<u8>> {
    let _request_chirho: NetRequestChirho =
        serde_json::from_slice(request_bytes_chirho).context("decode NetRequestChirho")?;
    let mut value_chirho: serde_json::Value =
        serde_json::from_slice(request_bytes_chirho).context("decode NetRequestChirho")?;
    let object_chirho = value_chirho
        .as_object_mut()
        .ok_or_else(|| anyhow!("NetRequestChirho must be a JSON object"))?;
    object_chirho.remove("body_base64_chirho");
    serde_json::to_vec(&value_chirho).context("encode private NetChirho logged request")
}

pub(super) fn validate_private_net_header_chirho(
    name_chirho: &str,
    value_chirho: &str,
) -> Result<()> {
    let normalized_chirho = name_chirho.trim().to_ascii_lowercase();
    if normalized_chirho.is_empty() {
        bail!("private NetChirho header name is required");
    }
    if normalized_chirho.contains(':')
        || normalized_chirho.contains('\r')
        || normalized_chirho.contains('\n')
        || value_chirho.contains('\r')
        || value_chirho.contains('\n')
    {
        bail!("private NetChirho headers must not contain control separators");
    }
    if value_chirho.trim().is_empty() {
        bail!("private NetChirho header value is required");
    }
    Ok(())
}

pub(super) fn validate_private_net_response_body_chirho(
    body_chirho: &[u8],
    private_headers_chirho: &BTreeMap<String, String>,
) -> Result<()> {
    if private_headers_chirho.is_empty() {
        return Ok(());
    }
    let body_text_chirho = String::from_utf8_lossy(body_chirho);
    for value_chirho in private_headers_chirho.values() {
        let value_chirho = value_chirho.trim();
        if !value_chirho.is_empty() && body_text_chirho.contains(value_chirho) {
            bail!("private NetChirho response reflected a private header value");
        }
        if let Some(token_chirho) = value_chirho.strip_prefix("Bearer ") {
            if !token_chirho.is_empty() && body_text_chirho.contains(token_chirho) {
                bail!("private NetChirho response reflected a private bearer token");
            }
        }
    }
    Ok(())
}

/// The subject a private net body rests under: the caller's explicit subject, or, for host-private
/// headers, a system subject from the body's hash. An account-attributed body's system subject also names
/// the account, so two accounts sending the same body never share one subject (and one erasure).
fn private_net_body_subject_chirho(
    explicit_subject_chirho: Option<&str>,
    private_headers_chirho: &BTreeMap<String, String>,
    request_body_hash_chirho: &HashChirho,
    attribution_chirho: Option<&privacy_chirho::PrivateBlobAttributionChirho>,
) -> Option<String> {
    if let Some(subject_chirho) = explicit_subject_chirho {
        let trimmed_chirho = subject_chirho.trim();
        if !trimmed_chirho.is_empty() {
            return Some(trimmed_chirho.to_string());
        }
    }
    if private_headers_chirho.is_empty() {
        return None;
    }
    let hash_chirho = request_body_hash_chirho.0.get(..16).unwrap_or("unknown");
    match attribution_chirho.map(privacy_chirho::PrivateBlobAttributionChirho::container_chirho) {
        Some(privacy_chirho::BlobContainerChirho::AccountChirho(account_chirho)) => Some(format!(
            "system/net-chirho/{}/{hash_chirho}",
            &account_chirho.as_hex_chirho()[..16]
        )),
        _ => Some(format!("system/net-chirho/{hash_chirho}")),
    }
}
