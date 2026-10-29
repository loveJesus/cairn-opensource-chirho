// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Signed host/path->app domain bindings: the append-only routing table that makes served apps domain-conscious.
//!
//! Records are platform-signed, seq-contiguous JSONL like the other signed families; owner/app
//! authorization for WRITING a binding belongs to the calling surface (CLI/route layer), exactly
//! as with the other record families. Resolution is longest-path-prefix over the latest record
//! per (host, path_prefix), active records only.

use crate::seqlog_chirho;
use anyhow::{bail, Context, Result};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DOMAIN_BINDING_RECORD_SCHEMA_CHIRHO: &str = "domain-binding-record-v1-chirho";
const HOST_MAX_LEN_CHIRHO: usize = 253;
const PATH_PREFIX_MAX_LEN_CHIRHO: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainBindingStatusChirho {
    ActiveChirho,
    RemovedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainBindingRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub owner_principal_chirho: String,
    /// Lowercase DNS host this binding serves (no scheme, port, path, or wildcard).
    pub host_chirho: String,
    /// Path prefix on that host; "/" binds the whole host.
    pub path_prefix_chirho: String,
    pub app_chirho: String,
    /// Optional app route the prefix maps onto; None means the app's default route surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_base_chirho: Option<String>,
    pub status_chirho: DomainBindingStatusChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

pub struct DomainBindingInputChirho {
    pub owner_principal_chirho: String,
    pub host_chirho: String,
    pub path_prefix_chirho: String,
    pub app_chirho: String,
    pub route_base_chirho: Option<String>,
    pub status_chirho: DomainBindingStatusChirho,
}

fn domain_bindings_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("domain-bindings-chirho.jsonl")
}

fn now_ms_chirho() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d_chirho| d_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn jsonl_len_chirho(path_chirho: &Path) -> Result<u64> {
    if !path_chirho.exists() {
        return Ok(0);
    }
    let text_chirho = std::fs::read_to_string(path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    Ok(text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .count() as u64)
}

fn domain_binding_message_chirho(record_chirho: &DomainBindingRecordChirho) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}

/// Host validation: lowercase DNS labels only — rejects schemes, ports, paths, wildcards,
/// uppercase, and malformed labels, so a binding can never smuggle routing syntax.
pub fn validate_binding_host_chirho(host_chirho: &str) -> Result<()> {
    if host_chirho.is_empty() || host_chirho.len() > HOST_MAX_LEN_CHIRHO {
        bail!("binding host must be 1..={HOST_MAX_LEN_CHIRHO} chars");
    }
    if host_chirho != host_chirho.to_ascii_lowercase() {
        bail!("binding host must be lowercase");
    }
    for label_chirho in host_chirho.split('.') {
        if label_chirho.is_empty() || label_chirho.len() > 63 {
            bail!("binding host label must be 1..=63 chars");
        }
        if label_chirho.starts_with('-') || label_chirho.ends_with('-') {
            bail!("binding host label must not start or end with '-'");
        }
        if !label_chirho.chars().all(|c_chirho| {
            c_chirho.is_ascii_lowercase() || c_chirho.is_ascii_digit() || c_chirho == '-'
        }) {
            bail!("binding host may contain only a-z, 0-9, '-', and '.'");
        }
    }
    Ok(())
}

pub fn validate_binding_path_prefix_chirho(path_prefix_chirho: &str) -> Result<()> {
    if !path_prefix_chirho.starts_with('/') {
        bail!("binding path prefix must start with '/'");
    }
    if path_prefix_chirho.len() > PATH_PREFIX_MAX_LEN_CHIRHO {
        bail!("binding path prefix must be <= {PATH_PREFIX_MAX_LEN_CHIRHO} chars");
    }
    if path_prefix_chirho.contains("..")
        || path_prefix_chirho.contains('\\')
        || path_prefix_chirho
            .chars()
            .any(|c_chirho| c_chirho.is_whitespace())
    {
        bail!("binding path prefix must not contain '..', '\\\\', or whitespace");
    }
    if path_prefix_chirho != "/" && path_prefix_chirho.ends_with('/') {
        bail!("binding path prefix must not end with '/' (except the root prefix)");
    }
    Ok(())
}

fn validate_binding_input_chirho(input_chirho: &DomainBindingInputChirho) -> Result<()> {
    if input_chirho.owner_principal_chirho.trim().is_empty() {
        bail!("binding owner principal must not be empty");
    }
    validate_binding_host_chirho(&input_chirho.host_chirho)?;
    validate_binding_path_prefix_chirho(&input_chirho.path_prefix_chirho)?;
    if input_chirho.app_chirho.trim().is_empty() || input_chirho.app_chirho.contains('/') {
        bail!("binding app must be non-empty and contain no '/'");
    }
    if let Some(route_chirho) = &input_chirho.route_base_chirho {
        if route_chirho.trim().is_empty() || route_chirho.contains('/') {
            bail!("binding route base must be non-empty and contain no '/'");
        }
    }
    Ok(())
}

/// Append one signed binding record (active or removal) under the store-wide append lock.
pub fn emit_domain_binding_chirho(
    root_chirho: &Path,
    input_chirho: DomainBindingInputChirho,
) -> Result<DomainBindingRecordChirho> {
    validate_binding_input_chirho(&input_chirho)?;
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        let path_chirho = domain_bindings_path_chirho(root_chirho);
        let mut record_chirho = DomainBindingRecordChirho {
            schema_chirho: DOMAIN_BINDING_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: jsonl_len_chirho(&path_chirho)?,
            owner_principal_chirho: input_chirho.owner_principal_chirho.clone(),
            host_chirho: input_chirho.host_chirho.clone(),
            path_prefix_chirho: input_chirho.path_prefix_chirho.clone(),
            app_chirho: input_chirho.app_chirho.clone(),
            route_base_chirho: input_chirho.route_base_chirho.clone(),
            status_chirho: input_chirho.status_chirho.clone(),
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            root_chirho,
            &domain_binding_message_chirho(&record_chirho)?,
        )?;
        seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
            &path_chirho,
            record_chirho.seq_chirho,
            &record_chirho,
        )?;
        Ok(record_chirho)
    })
}

pub fn load_domain_binding_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<DomainBindingRecordChirho>> {
    let path_chirho = domain_bindings_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    let mut records_chirho = Vec::new();
    for line_chirho in text_chirho
        .lines()
        .filter(|l_chirho| !l_chirho.trim().is_empty())
    {
        records_chirho.push(serde_json::from_str(line_chirho).context("parse domain binding")?);
    }
    Ok(records_chirho)
}

/// Fail-closed verification: seq contiguity, schema pin, field validity, and signature on every
/// record. Authoritative consumers (the serve resolver) must use [`verified_domain_bindings_chirho`].
pub fn verify_domain_binding_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_domain_binding_records_chirho(root_chirho)?;
    if records_chirho.is_empty() {
        return Ok(0);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != i_chirho as u64 {
            bail!(
                "domain binding seq gap at index {i_chirho}: entry seq is {}",
                record_chirho.seq_chirho
            );
        }
        if record_chirho.schema_chirho != DOMAIN_BINDING_RECORD_SCHEMA_CHIRHO {
            bail!(
                "domain binding record {} schema mismatch",
                record_chirho.seq_chirho
            );
        }
        validate_binding_host_chirho(&record_chirho.host_chirho)?;
        validate_binding_path_prefix_chirho(&record_chirho.path_prefix_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &domain_binding_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "domain binding record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(records_chirho.len())
}

/// Load + verify, returning records only when the whole log verifies (fail-closed).
pub fn verified_domain_bindings_chirho(
    root_chirho: &Path,
) -> Result<Vec<DomainBindingRecordChirho>> {
    verify_domain_binding_records_chirho(root_chirho)?;
    load_domain_binding_records_chirho(root_chirho)
}

/// True when `path` is `prefix` itself or sits beneath it on a path-segment boundary, so
/// "/shop" matches "/shop" and "/shop/x" but never "/shopx".
fn prefix_matches_chirho(prefix_chirho: &str, path_chirho: &str) -> bool {
    if prefix_chirho == "/" {
        return path_chirho.starts_with('/');
    }
    path_chirho == prefix_chirho
        || path_chirho
            .strip_prefix(prefix_chirho)
            .is_some_and(|rest_chirho| rest_chirho.starts_with('/'))
}

/// Resolve a request (host, path) against verified records: latest record per
/// (host, path_prefix) wins, removed bindings drop out, and the longest matching prefix is
/// chosen. Returns None when the host/path is unbound (caller falls through to normal routes).
pub fn resolve_domain_binding_chirho<'a_chirho>(
    records_chirho: &'a_chirho [DomainBindingRecordChirho],
    host_chirho: &str,
    path_chirho: &str,
) -> Option<&'a_chirho DomainBindingRecordChirho> {
    let host_lower_chirho = host_chirho.to_ascii_lowercase();
    // Strip a port if present; bindings are host-only by validation.
    let host_only_chirho = host_lower_chirho
        .split_once(':')
        .map(|(h_chirho, _)| h_chirho)
        .unwrap_or(&host_lower_chirho);
    let mut latest_chirho: std::collections::BTreeMap<&str, &DomainBindingRecordChirho> =
        std::collections::BTreeMap::new();
    for record_chirho in records_chirho {
        if record_chirho.host_chirho == host_only_chirho {
            latest_chirho.insert(record_chirho.path_prefix_chirho.as_str(), record_chirho);
        }
    }
    latest_chirho
        .into_values()
        .filter(|record_chirho| {
            record_chirho.status_chirho == DomainBindingStatusChirho::ActiveChirho
        })
        .filter(|record_chirho| {
            prefix_matches_chirho(&record_chirho.path_prefix_chirho, path_chirho)
        })
        .max_by_key(|record_chirho| record_chirho.path_prefix_chirho.len())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_root_chirho(label_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-domain-binding-test-{label_chirho}-{n_chirho}-{}",
            now_ms_chirho()
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn binding_chirho(
        host_chirho: &str,
        prefix_chirho: &str,
        app_chirho: &str,
        status_chirho: DomainBindingStatusChirho,
    ) -> DomainBindingInputChirho {
        DomainBindingInputChirho {
            owner_principal_chirho: "owner/test".to_string(),
            host_chirho: host_chirho.to_string(),
            path_prefix_chirho: prefix_chirho.to_string(),
            app_chirho: app_chirho.to_string(),
            route_base_chirho: None,
            status_chirho,
        }
    }

    #[test]
    fn emit_load_verify_roundtrip_chirho() {
        let root_chirho = temp_root_chirho("roundtrip");
        emit_domain_binding_chirho(
            &root_chirho,
            binding_chirho(
                "cardshop.example",
                "/",
                "cardshop",
                DomainBindingStatusChirho::ActiveChirho,
            ),
        )
        .unwrap();
        emit_domain_binding_chirho(
            &root_chirho,
            binding_chirho(
                "cardshop.example",
                "/api",
                "cardshop-api",
                DomainBindingStatusChirho::ActiveChirho,
            ),
        )
        .unwrap();
        let records_chirho = verified_domain_bindings_chirho(&root_chirho).unwrap();
        assert_eq!(records_chirho.len(), 2);
        assert_eq!(records_chirho[0].seq_chirho, 0);
        assert_eq!(records_chirho[1].seq_chirho, 1);
    }

    #[test]
    fn tampered_binding_log_fails_closed_chirho() {
        let root_chirho = temp_root_chirho("tamper");
        emit_domain_binding_chirho(
            &root_chirho,
            binding_chirho(
                "shop.example",
                "/",
                "shop",
                DomainBindingStatusChirho::ActiveChirho,
            ),
        )
        .unwrap();
        let path_chirho = domain_bindings_path_chirho(&root_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        std::fs::write(&path_chirho, text_chirho.replace("\"shop\"", "\"forged\"")).unwrap();
        assert!(verify_domain_binding_records_chirho(&root_chirho).is_err());
        assert!(verified_domain_bindings_chirho(&root_chirho).is_err());
    }

    #[test]
    fn resolver_longest_prefix_and_boundaries_chirho() {
        let root_chirho = temp_root_chirho("resolve");
        emit_domain_binding_chirho(
            &root_chirho,
            binding_chirho(
                "shop.example",
                "/",
                "site",
                DomainBindingStatusChirho::ActiveChirho,
            ),
        )
        .unwrap();
        emit_domain_binding_chirho(
            &root_chirho,
            binding_chirho(
                "shop.example",
                "/api",
                "api",
                DomainBindingStatusChirho::ActiveChirho,
            ),
        )
        .unwrap();
        let records_chirho = verified_domain_bindings_chirho(&root_chirho).unwrap();
        let pick_chirho = |path_chirho: &str| {
            resolve_domain_binding_chirho(&records_chirho, "SHOP.example:8443", path_chirho)
                .map(|r_chirho| r_chirho.app_chirho.clone())
        };
        assert_eq!(pick_chirho("/api/orders"), Some("api".to_string()));
        assert_eq!(pick_chirho("/api"), Some("api".to_string()));
        assert_eq!(pick_chirho("/apix"), Some("site".to_string()));
        assert_eq!(pick_chirho("/about"), Some("site".to_string()));
        assert!(resolve_domain_binding_chirho(&records_chirho, "other.example", "/").is_none());
    }

    #[test]
    fn removal_unbinds_latest_wins_chirho() {
        let root_chirho = temp_root_chirho("removal");
        emit_domain_binding_chirho(
            &root_chirho,
            binding_chirho(
                "shop.example",
                "/api",
                "api",
                DomainBindingStatusChirho::ActiveChirho,
            ),
        )
        .unwrap();
        emit_domain_binding_chirho(
            &root_chirho,
            binding_chirho(
                "shop.example",
                "/api",
                "api",
                DomainBindingStatusChirho::RemovedChirho,
            ),
        )
        .unwrap();
        let records_chirho = verified_domain_bindings_chirho(&root_chirho).unwrap();
        assert!(resolve_domain_binding_chirho(&records_chirho, "shop.example", "/api/x").is_none());
    }

    #[test]
    fn invalid_host_and_path_rejected_chirho() {
        let root_chirho = temp_root_chirho("invalid");
        for (host_chirho, prefix_chirho) in [
            ("https://shop.example", "/"),
            ("Shop.Example", "/"),
            ("shop.example", "no-slash"),
            ("shop.example", "/has/../traversal"),
            ("shop.example", "/trailing/"),
            ("-bad.example", "/"),
        ] {
            assert!(
                emit_domain_binding_chirho(
                    &root_chirho,
                    binding_chirho(
                        host_chirho,
                        prefix_chirho,
                        "app",
                        DomainBindingStatusChirho::ActiveChirho
                    ),
                )
                .is_err(),
                "expected rejection for host={host_chirho} prefix={prefix_chirho}"
            );
        }
    }
}
