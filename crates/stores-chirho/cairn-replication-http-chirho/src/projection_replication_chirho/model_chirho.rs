// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::is_lower_hex_64_chirho;
use anyhow::{bail, Result};
use cairn_ledger_model_chirho::wire_chirho::validate_ledger_account_identifier_chirho;
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_ledger_read_model_chirho::account_net_chirho::AccountNetProjectionViewChirho;
use cairn_ledger_read_model_chirho::feeder_chirho::{
    follow_receipt_signed_content_chirho, view_bytes_digest_hex_chirho, FollowReceiptChirho,
};
use cairn_ledger_read_model_chirho::parse_canonical_account_net_projection_view_chirho;
use cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};

pub const PROJECTION_REPLICA_MOUNT_SCHEMA_V1_CHIRHO: &str = "projection-replica-mount-v1-chirho";
pub const PROJECTION_REPLICA_PULL_REPORT_SCHEMA_V1_CHIRHO: &str =
    "projection-replica-pull-report-v1-chirho";
const MAX_IDENTITY_LABEL_BYTES_CHIRHO: usize = 256;
const MAX_LOGICAL_PATH_BYTES_CHIRHO: usize = 4 * 1024;
const MAX_INSPECTED_ACCOUNTS_CHIRHO: usize = 16;

/// Exact trust coordinate for one replicated projection.
///
/// The source verifies this before serving and the replica independently verifies it before
/// mounting. A signature alone never turns a valid foreign projection into the configured one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReplicationIdentityChirho {
    pub projection_name_chirho: String,
    pub descriptor_digest_chirho: String,
    pub source_cluster_chirho: String,
    pub source_genesis_digest_chirho: String,
    pub feeder_pubkey_hex_chirho: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReplicationSourceConfigChirho {
    pub source_namespace_root_chirho: PathBuf,
    pub head_path_chirho: String,
    pub listen_addr_chirho: String,
    pub bearer_env_chirho: String,
    pub identity_chirho: ProjectionReplicationIdentityChirho,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReplicaPullConfigChirho {
    pub source_url_chirho: String,
    pub bearer_env_chirho: String,
    pub replica_root_chirho: PathBuf,
    pub identity_chirho: ProjectionReplicationIdentityChirho,
    #[serde(default)]
    pub inspect_accounts_chirho: Vec<LogIdChirho>,
}

/// The single atomic replica commit. The bound view is installed first at its digest path; replacing
/// this file advances both the readable mount and its rollback floor in one durable operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionReplicaMountChirho {
    pub schema_chirho: String,
    pub identity_chirho: ProjectionReplicationIdentityChirho,
    pub mounted_at_unix_chirho: u64,
    pub receipt_chirho: FollowReceiptChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ProjectionReplicaPullDispositionChirho {
    #[serde(rename = "installed-initial-chirho")]
    InstalledInitialChirho,
    #[serde(rename = "advanced-chirho")]
    AdvancedChirho,
    #[serde(rename = "already-current-chirho")]
    AlreadyCurrentChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectionReplicaAccountObservationChirho {
    pub account_chirho: LogIdChirho,
    pub account_net_chirho: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProjectionReplicaPullReportChirho {
    pub schema_chirho: String,
    pub disposition_chirho: ProjectionReplicaPullDispositionChirho,
    pub observed_at_unix_chirho: u64,
    pub source_tail_seq_chirho: u64,
    pub source_tail_line_digest_chirho: String,
    pub view_digest_hex_chirho: String,
    pub view_rows_chirho: u64,
    pub inspected_accounts_chirho: Vec<ProjectionReplicaAccountObservationChirho>,
}

pub(crate) fn validate_identity_chirho(
    identity_chirho: &ProjectionReplicationIdentityChirho,
) -> Result<()> {
    validate_identity_label_chirho(
        "ProjectionReplicaProjectionNameRefusedChirho",
        &identity_chirho.projection_name_chirho,
    )?;
    validate_identity_label_chirho(
        "ProjectionReplicaSourceClusterRefusedChirho",
        &identity_chirho.source_cluster_chirho,
    )?;
    if !is_lower_hex_64_chirho(&identity_chirho.descriptor_digest_chirho) {
        bail!("ProjectionReplicaDescriptorDigestRefusedChirho");
    }
    if !is_lower_hex_64_chirho(&identity_chirho.source_genesis_digest_chirho) {
        bail!("ProjectionReplicaSourceGenesisRefusedChirho");
    }
    if !is_lower_hex_64_chirho(&identity_chirho.feeder_pubkey_hex_chirho) {
        bail!("ProjectionReplicaFeederKeyRefusedChirho");
    }
    Ok(())
}

pub(crate) fn decode_and_verify_receipt_chirho(
    bytes_chirho: &[u8],
    identity_chirho: &ProjectionReplicationIdentityChirho,
) -> Result<FollowReceiptChirho> {
    validate_identity_chirho(identity_chirho)?;
    let receipt_chirho: FollowReceiptChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaReceiptDecodeRefusedChirho"))?;
    let encoded_chirho = serde_json::to_vec(&receipt_chirho)
        .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaReceiptEncodeRefusedChirho"))?;
    if encoded_chirho != bytes_chirho {
        bail!("ProjectionReplicaReceiptCanonicalRefusedChirho");
    }
    if receipt_chirho.projection_name_chirho != identity_chirho.projection_name_chirho {
        bail!("ProjectionReplicaProjectionNameMismatchChirho");
    }
    if receipt_chirho.descriptor_digest_chirho.0 != identity_chirho.descriptor_digest_chirho {
        bail!("ProjectionReplicaDescriptorMismatchChirho");
    }
    if receipt_chirho.source_cluster_chirho != identity_chirho.source_cluster_chirho {
        bail!("ProjectionReplicaSourceClusterMismatchChirho");
    }
    if receipt_chirho.source_genesis_digest_chirho.0 != identity_chirho.source_genesis_digest_chirho
    {
        bail!("ProjectionReplicaSourceGenesisMismatchChirho");
    }
    if !is_lower_hex_64_chirho(&receipt_chirho.source_tail_line_digest_chirho.0) {
        bail!("ProjectionReplicaSourceTailDigestRefusedChirho");
    }
    if !is_lower_hex_64_chirho(&receipt_chirho.view_digest_hex_chirho) {
        bail!("ProjectionReplicaViewDigestRefusedChirho");
    }
    let signed_content_chirho = follow_receipt_signed_content_chirho(&receipt_chirho)
        .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaReceiptSchemaRefusedChirho"))?;
    if !verify_with_pubkey_chirho(
        &identity_chirho.feeder_pubkey_hex_chirho,
        signed_content_chirho.as_bytes(),
        &receipt_chirho.feeder_sig_chirho,
    )
    .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaReceiptSignatureRefusedChirho"))?
    {
        bail!("ProjectionReplicaReceiptSignatureRefusedChirho");
    }
    Ok(receipt_chirho)
}

pub(crate) fn decode_and_verify_view_chirho(
    bytes_chirho: &[u8],
    expected_digest_chirho: &str,
) -> Result<AccountNetProjectionViewChirho> {
    if !is_lower_hex_64_chirho(expected_digest_chirho)
        || view_bytes_digest_hex_chirho(bytes_chirho) != expected_digest_chirho
    {
        bail!("ProjectionReplicaViewDigestMismatchChirho");
    }
    parse_canonical_account_net_projection_view_chirho(bytes_chirho)
        .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaViewCanonicalRefusedChirho"))
}

pub(crate) fn validate_source_config_chirho(
    config_chirho: &ProjectionReplicationSourceConfigChirho,
) -> Result<()> {
    validate_identity_chirho(&config_chirho.identity_chirho)?;
    validate_relative_storage_path_chirho(&config_chirho.head_path_chirho)?;
    if config_chirho.bearer_env_chirho.trim().is_empty() {
        bail!("ProjectionReplicaBearerEnvRefusedChirho");
    }
    let listen_chirho: std::net::SocketAddr = config_chirho
        .listen_addr_chirho
        .parse()
        .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaListenAddressRefusedChirho"))?;
    if !is_private_transport_ip_chirho(listen_chirho.ip()) {
        bail!("ProjectionReplicaPublicBindRefusedChirho");
    }
    Ok(())
}

pub(crate) fn validate_pull_config_chirho(
    config_chirho: &ProjectionReplicaPullConfigChirho,
) -> Result<()> {
    validate_identity_chirho(&config_chirho.identity_chirho)?;
    if config_chirho.bearer_env_chirho.trim().is_empty() {
        bail!("ProjectionReplicaBearerEnvRefusedChirho");
    }
    let source_url_chirho = url::Url::parse(&config_chirho.source_url_chirho)
        .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaSourceUrlRefusedChirho"))?;
    if !matches!(source_url_chirho.scheme(), "http" | "https")
        || !source_url_chirho.username().is_empty()
        || source_url_chirho.password().is_some()
        || source_url_chirho.query().is_some()
        || source_url_chirho.fragment().is_some()
        || source_url_chirho.path() != "/"
    {
        bail!("ProjectionReplicaSourceUrlRefusedChirho");
    }
    let source_ip_chirho = source_url_chirho
        .host_str()
        .and_then(|host_chirho| host_chirho.parse::<IpAddr>().ok())
        .ok_or_else(|| anyhow::anyhow!("ProjectionReplicaSourceAddressRefusedChirho"))?;
    if !is_private_transport_ip_chirho(source_ip_chirho) {
        bail!("ProjectionReplicaSourceAddressRefusedChirho");
    }
    if config_chirho.inspect_accounts_chirho.len() > MAX_INSPECTED_ACCOUNTS_CHIRHO {
        bail!("ProjectionReplicaInspectionPopulationRefusedChirho");
    }
    let mut unique_accounts_chirho = BTreeSet::new();
    for account_chirho in &config_chirho.inspect_accounts_chirho {
        validate_ledger_account_identifier_chirho(account_chirho)
            .map_err(|_error_chirho| anyhow::anyhow!("ProjectionReplicaAccountRefusedChirho"))?;
        if !unique_accounts_chirho.insert(account_chirho.clone()) {
            bail!("ProjectionReplicaInspectionDuplicateRefusedChirho");
        }
    }
    Ok(())
}

pub(crate) fn validate_relative_storage_path_chirho(path_chirho: &str) -> Result<()> {
    if path_chirho.is_empty()
        || path_chirho.len() > MAX_LOGICAL_PATH_BYTES_CHIRHO
        || Path::new(path_chirho).is_absolute()
        || !Path::new(path_chirho)
            .components()
            .all(|component_chirho| matches!(component_chirho, Component::Normal(_)))
    {
        bail!("ProjectionReplicaHeadPathRefusedChirho");
    }
    Ok(())
}

fn validate_identity_label_chirho(refusal_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.is_empty()
        || value_chirho.len() > MAX_IDENTITY_LABEL_BYTES_CHIRHO
        || value_chirho.chars().any(|character_chirho| {
            character_chirho.is_control()
                || character_chirho.is_whitespace()
                || matches!(character_chirho, '/' | '\\' | '@')
        })
    {
        bail!("{refusal_chirho}");
    }
    Ok(())
}

fn is_private_transport_ip_chirho(ip_chirho: IpAddr) -> bool {
    match ip_chirho {
        IpAddr::V4(ip_chirho) => ip_chirho.is_loopback() || ip_chirho.is_private(),
        IpAddr::V6(ip_chirho) => {
            let first_segment_chirho = ip_chirho.segments()[0];
            ip_chirho.is_loopback()
                || first_segment_chirho & 0xfe00 == 0xfc00
                || first_segment_chirho & 0xffc0 == 0xfe80
        }
    }
}
