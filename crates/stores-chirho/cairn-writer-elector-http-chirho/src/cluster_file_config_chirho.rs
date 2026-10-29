// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Shared bounded JSON-file adapter for deployable writer-election nodes.

use crate::cluster_node_chirho::{validate_cluster_tick_interval_chirho, ClusterNodeConfigChirho};
use crate::membership_control_chirho::{
    MembershipControlConfigChirho, MembershipTargetAuthorityChirho, RosterAuthorityConfigChirho,
    TenantPlacementAuthorityConfigChirho,
};
use crate::tenant_migration_capacity_config_chirho::{
    nonzero_lower_hex_coordinate_chirho, parse_tenant_migration_capacity_config_chirho,
    TenantMigrationCapacityFileConfigChirho,
};
pub use crate::tenant_migration_capacity_config_chirho::{
    TenantMigrationCapacityConfigChirho, TenantMigrationCapacityHeadroomConfigChirho,
    TENANT_MIGRATION_CAPACITY_CONFIG_SCHEMA_V2_CHIRHO,
};
use anyhow::{Context, Result};
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Startup configuration is operator-sized, never a growing runtime data surface.
pub const MAX_CLUSTER_NODE_FILE_BYTES_CHIRHO: u64 = 64 * 1024;

/// Runtime-control-free posture and signer-custody material for one node-readiness receipt.
///
/// The signing-root path lets offline authoring verify that the supplied existing node key matches
/// this config. The view deliberately carries no operator token, durable elector handle, peer URLs,
/// or control configuration, so it grants no convergence or election capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterNodeReadinessRoleChirho {
    TenantPlacementServingChirho,
    NoMembershipControlChirho,
    RosterWideControlChirho,
}

pub struct LoadedClusterNodeReadinessConfigChirho {
    pub group_chirho: ConsistencyGroupIdChirho,
    pub local_raft_id_chirho: u64,
    pub voters_chirho: Vec<(u64, String)>,
    pub learners_chirho: Vec<(u64, String)>,
    pub sign_root_chirho: PathBuf,
    pub config_blake3_chirho: String,
    pub roster_authority_configured_chirho: bool,
    pub tenant_placement_configured_chirho: bool,
    pub placement_record_path_chirho: Option<PathBuf>,
    pub placement_pubkey_hex_chirho: Option<String>,
    pub roster_operator_pubkey_hex_chirho: Option<String>,
    pub geo_plan_pubkey_hex_chirho: Option<String>,
    pub role_chirho: ClusterNodeReadinessRoleChirho,
}

/// Attenuated review view for the two custody-separated capacity-expectation signing stages.
///
/// It carries the exact config hash and only the public coordinates needed to verify the resident
/// placement and expectation. It grants no node signing root, operator token, peer transport, or
/// membership-control capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedTenantMigrationCapacityExpectationAuthoringConfigChirho {
    pub config_blake3_chirho: String,
    pub tenant_id_chirho: String,
    pub local_node_id_chirho: String,
    pub placement_record_path_chirho: PathBuf,
    pub evidence_root_chirho: PathBuf,
    pub expectation_record_path_chirho: PathBuf,
    pub expectation_revision_chirho: u64,
    pub placement_pubkey_hex_chirho: String,
    pub roster_operator_pubkey_hex_chirho: String,
    pub geo_plan_pubkey_hex_chirho: String,
    pub topology_grant_pubkey_hex_chirho: String,
}

#[derive(Deserialize)]
struct NodeFileConfigChirho {
    group_chirho: GroupConfigChirho,
    local_raft_id_chirho: u64,
    members_chirho: Vec<MemberConfigChirho>,
    durable_dir_chirho: String,
    sign_root_chirho: String,
    listen_addr_chirho: String,
    tick_ms_chirho: u64,
    #[serde(default)]
    writer_era_activation_authorization_chirho: Option<String>,
    #[serde(default)]
    roster_authority_chirho: Option<RosterAuthorityFileConfigChirho>,
    #[serde(default)]
    membership_control_chirho: Option<MembershipControlFileConfigChirho>,
    #[serde(default)]
    tenant_placement_chirho: Option<TenantPlacementAuthorityFileConfigChirho>,
    #[serde(default)]
    tenant_migration_capacity_chirho: Option<TenantMigrationCapacityFileConfigChirho>,
}

#[derive(Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "snake_case")]
enum GroupConfigChirho {
    Tenant { tenant_id_chirho: String },
    Root { root_path_chirho: String },
}

#[derive(Deserialize)]
struct MemberConfigChirho {
    raft_id_chirho: u64,
    pubkey_chirho: String,
    url_chirho: String,
    learner_chirho: bool,
}

#[derive(Deserialize)]
struct MembershipControlFileConfigChirho {
    operator_token_env_chirho: String,
    #[serde(default)]
    target_authority_chirho: Option<MembershipTargetAuthorityFileConfigChirho>,
    #[serde(default = "default_fixpoint_step_sleep_ms_chirho")]
    fixpoint_step_sleep_ms_chirho: u64,
    #[serde(default = "default_fixpoint_max_steps_chirho")]
    fixpoint_max_steps_chirho: usize,
}

#[derive(Deserialize)]
struct RosterAuthorityFileConfigChirho {
    roster_path_chirho: String,
    roster_head_path_chirho: String,
    operator_pubkey_hex_chirho: String,
    /// WireGuard interface whose live peers must equal this group's signed roster. Omitted ⇒ `wg0`,
    /// so every existing config keeps its exact previous behaviour. This is NOT a trust widening:
    /// the verifier independently requires the named interface to be UP and to carry the SIGNED
    /// local mesh address, and requires its peer set to equal the signed roster — so naming a
    /// different interface cannot admit a mesh the roster does not already describe.
    #[serde(default)]
    relay_interface_chirho: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "snake_case")]
enum MembershipTargetAuthorityFileConfigChirho {
    RosterWide,
    TenantPlacement,
}

#[derive(Deserialize)]
struct TenantPlacementAuthorityFileConfigChirho {
    placement_record_path_chirho: String,
    placement_pubkey_hex_chirho: String,
    geo_plan_pubkey_hex_chirho: String,
}

fn default_fixpoint_step_sleep_ms_chirho() -> u64 {
    200
}

fn default_fixpoint_max_steps_chirho() -> usize {
    32
}

pub struct LoadedClusterNodeConfigChirho {
    pub cluster_chirho: ClusterNodeConfigChirho,
    pub listen_addr_chirho: String,
    /// Digest of the exact bounded bytes parsed into `cluster_chirho`.
    pub config_blake3_chirho: String,
    pub writer_era_activation_authorization_chirho: Option<PathBuf>,
    pub roster_authority_chirho: Option<RosterAuthorityConfigChirho>,
    pub tenant_placement_chirho: Option<TenantPlacementAuthorityConfigChirho>,
    pub tenant_migration_capacity_chirho: Option<TenantMigrationCapacityConfigChirho>,
}

/// Verify custody before an authority-bearing composition reads the cluster file.
///
/// Parsing owns the roster schema. This check owns only the non-symlink, regular-file,
/// private-mode, and selected-root-owner boundary.
pub fn verify_cluster_node_file_config_custody_chirho(
    selected_root_chirho: &Path,
    config_path_chirho: &Path,
) -> Result<()> {
    let root_metadata_chirho = std::fs::symlink_metadata(selected_root_chirho)
        .context("inspect selected root for cluster config custody")?;
    let config_metadata_chirho = cluster_config_metadata_chirho(config_path_chirho)?;
    if !same_owner_chirho(&root_metadata_chirho, &config_metadata_chirho) {
        anyhow::bail!("cluster config owner does not match the selected root owner");
    }
    Ok(())
}

pub fn load_cluster_node_file_config_chirho(
    config_path_chirho: &Path,
) -> Result<LoadedClusterNodeConfigChirho> {
    let bytes_chirho = read_cluster_node_file_bytes_chirho(config_path_chirho)?;
    parse_cluster_node_file_config_chirho(&bytes_chirho)
        .with_context(|| format!("parse cluster config {}", config_path_chirho.display()))
}

pub fn load_cluster_node_readiness_config_chirho(
    config_path_chirho: &Path,
) -> Result<LoadedClusterNodeReadinessConfigChirho> {
    let bytes_chirho = read_cluster_node_file_bytes_chirho(config_path_chirho)?;
    parse_cluster_node_readiness_config_chirho(&bytes_chirho)
        .with_context(|| format!("parse readiness config {}", config_path_chirho.display()))
}

pub fn load_tenant_migration_capacity_expectation_authoring_config_chirho(
    config_path_chirho: &Path,
) -> Result<LoadedTenantMigrationCapacityExpectationAuthoringConfigChirho> {
    let bytes_chirho = read_cluster_node_file_bytes_chirho(config_path_chirho)?;
    let config_blake3_chirho = blake3::hash(&bytes_chirho).to_hex().to_string();
    let file_chirho: NodeFileConfigChirho = serde_json::from_slice(&bytes_chirho)
        .with_context(|| format!("parse cluster config {}", config_path_chirho.display()))?;
    validate_cluster_tick_interval_chirho(Duration::from_millis(file_chirho.tick_ms_chirho))?;
    let tenant_id_chirho = match &file_chirho.group_chirho {
        GroupConfigChirho::Tenant { tenant_id_chirho } => tenant_id_chirho.clone(),
        GroupConfigChirho::Root { .. } => {
            anyhow::bail!("TenantMigrationCapacityTenantGroupRequiredChirho")
        }
    };
    let mut local_members_chirho = file_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| member_chirho.raft_id_chirho == file_chirho.local_raft_id_chirho);
    let local_node_id_chirho = local_members_chirho
        .next()
        .map(|member_chirho| member_chirho.pubkey_chirho.clone())
        .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityLocalMemberMissingChirho"))?;
    if local_members_chirho.next().is_some()
        || !nonzero_lower_hex_coordinate_chirho(&local_node_id_chirho)
    {
        anyhow::bail!("TenantMigrationCapacityLocalMemberRefusedChirho");
    }
    let roster_authority_chirho = file_chirho
        .roster_authority_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityRosterAuthorityMissingChirho"))?;
    let placement_chirho = file_chirho
        .tenant_placement_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityPlacementAuthorityMissingChirho"))?;
    let placement_record_path_chirho =
        PathBuf::from(&placement_chirho.placement_record_path_chirho);
    let placement_pubkey_hex_chirho = placement_chirho.placement_pubkey_hex_chirho.clone();
    let geo_plan_pubkey_hex_chirho = placement_chirho.geo_plan_pubkey_hex_chirho.clone();
    let roster_operator_pubkey_hex_chirho =
        roster_authority_chirho.operator_pubkey_hex_chirho.clone();
    let capacity_chirho = parse_tenant_migration_capacity_config_chirho(
        file_chirho
            .tenant_migration_capacity_chirho
            .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityConfigMissingChirho"))?,
    )?;
    Ok(
        LoadedTenantMigrationCapacityExpectationAuthoringConfigChirho {
            config_blake3_chirho,
            tenant_id_chirho,
            local_node_id_chirho,
            placement_record_path_chirho,
            evidence_root_chirho: capacity_chirho.evidence_root_chirho,
            expectation_record_path_chirho: capacity_chirho.expectation_record_path_chirho,
            expectation_revision_chirho: capacity_chirho.expectation_revision_chirho,
            placement_pubkey_hex_chirho,
            roster_operator_pubkey_hex_chirho,
            geo_plan_pubkey_hex_chirho,
            topology_grant_pubkey_hex_chirho: capacity_chirho.topology_grant_pubkey_hex_chirho,
        },
    )
}

fn read_cluster_node_file_bytes_chirho(config_path_chirho: &Path) -> Result<Vec<u8>> {
    let config_metadata_chirho = cluster_config_metadata_chirho(config_path_chirho)?;
    if config_metadata_chirho.len() > MAX_CLUSTER_NODE_FILE_BYTES_CHIRHO {
        anyhow::bail!(
            "cluster config exceeds the {}-byte limit",
            MAX_CLUSTER_NODE_FILE_BYTES_CHIRHO
        );
    }
    cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        config_path_chirho,
        MAX_CLUSTER_NODE_FILE_BYTES_CHIRHO,
    )
    .with_context(|| {
        format!(
            "read identity-stable cluster config {}",
            config_path_chirho.display()
        )
    })
}

fn cluster_config_metadata_chirho(config_path_chirho: &Path) -> Result<std::fs::Metadata> {
    let config_metadata_chirho = std::fs::symlink_metadata(config_path_chirho)
        .with_context(|| format!("inspect cluster config {}", config_path_chirho.display()))?;
    if config_metadata_chirho.file_type().is_symlink() {
        anyhow::bail!("cluster config must not be a symlink");
    }
    if !config_metadata_chirho.is_file() {
        anyhow::bail!("cluster config must be a regular file");
    }
    if !private_config_mode_chirho(&config_metadata_chirho) {
        anyhow::bail!("cluster config permissions are too broad");
    }
    Ok(config_metadata_chirho)
}

#[cfg(unix)]
fn private_config_mode_chirho(metadata_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata_chirho.permissions().mode() & 0o077 == 0
}

#[cfg(not(unix))]
fn private_config_mode_chirho(_metadata_chirho: &std::fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn same_owner_chirho(left_chirho: &std::fs::Metadata, right_chirho: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left_chirho.uid() == right_chirho.uid()
}

#[cfg(not(unix))]
fn same_owner_chirho(_left_chirho: &std::fs::Metadata, _right_chirho: &std::fs::Metadata) -> bool {
    true
}

pub fn parse_cluster_node_file_config_chirho(
    bytes_chirho: &[u8],
) -> Result<LoadedClusterNodeConfigChirho> {
    let config_blake3_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    let file_chirho: NodeFileConfigChirho = serde_json::from_slice(bytes_chirho)?;
    let tick_interval_chirho = Duration::from_millis(file_chirho.tick_ms_chirho);
    validate_cluster_tick_interval_chirho(tick_interval_chirho)?;
    let group_chirho = match file_chirho.group_chirho {
        GroupConfigChirho::Tenant { tenant_id_chirho } => {
            ConsistencyGroupIdChirho::TenantChirho { tenant_id_chirho }
        }
        GroupConfigChirho::Root { root_path_chirho } => ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: root_path_chirho,
        },
    };
    let voters_chirho = file_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| !member_chirho.learner_chirho)
        .map(|member_chirho| {
            (
                member_chirho.raft_id_chirho,
                NodeIdChirho(member_chirho.pubkey_chirho.clone()),
            )
        })
        .collect();
    let learners_chirho = file_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| member_chirho.learner_chirho)
        .map(|member_chirho| {
            (
                member_chirho.raft_id_chirho,
                NodeIdChirho(member_chirho.pubkey_chirho.clone()),
            )
        })
        .collect();
    let peers_chirho = file_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| member_chirho.raft_id_chirho != file_chirho.local_raft_id_chirho)
        .map(|member_chirho| {
            (
                member_chirho.raft_id_chirho,
                member_chirho.url_chirho.clone(),
            )
        })
        .collect();
    let roster_authority_chirho =
        file_chirho
            .roster_authority_chirho
            .map(|config_chirho| RosterAuthorityConfigChirho {
                roster_path_chirho: PathBuf::from(config_chirho.roster_path_chirho),
                roster_head_path_chirho: PathBuf::from(config_chirho.roster_head_path_chirho),
                operator_pubkey_hex_chirho: config_chirho.operator_pubkey_hex_chirho,
                relay_interface_chirho: config_chirho.relay_interface_chirho.unwrap_or_else(|| {
                    cairn_roster_config_chirho::RELAY_WIREGUARD_INTERFACE_CHIRHO.to_string()
                }),
            });
    let tenant_placement_chirho = file_chirho.tenant_placement_chirho.map(|config_chirho| {
        TenantPlacementAuthorityConfigChirho {
            placement_record_path_chirho: PathBuf::from(config_chirho.placement_record_path_chirho),
            placement_pubkey_hex_chirho: config_chirho.placement_pubkey_hex_chirho,
            geo_plan_pubkey_hex_chirho: config_chirho.geo_plan_pubkey_hex_chirho,
        }
    });
    let tenant_migration_capacity_chirho = file_chirho
        .tenant_migration_capacity_chirho
        .map(parse_tenant_migration_capacity_config_chirho)
        .transpose()?;
    let membership_control_chirho = match file_chirho.membership_control_chirho {
        Some(control_chirho) => {
            let roster_authority_chirho = roster_authority_chirho
                .clone()
                .ok_or_else(|| anyhow::anyhow!("RosterAuthorityConfigUnavailableChirho"))?;
            // Read the node's EXISTING pair and never mint one. Config parse is not a provisioning road: a
            // missing, partial, unsafe or mismatched pair refuses here, with no creation, repair or chmod
            // (#30111, C2/C5 item 8a). keygen stays the one road that creates a node key.
            let actual_local_node_chirho =
                existing_keypair_pubkey_hex_chirho(&PathBuf::from(&file_chirho.sign_root_chirho))
                    .context("read the local node's existing key pair for membership control")?;
            let operator_token_chirho = std::env::var(&control_chirho.operator_token_env_chirho)
                .ok()
                .filter(|token_chirho| !token_chirho.is_empty());
            let target_authority_chirho = match control_chirho.target_authority_chirho {
                Some(MembershipTargetAuthorityFileConfigChirho::RosterWide) => {
                    MembershipTargetAuthorityChirho::RosterWideChirho
                }
                Some(MembershipTargetAuthorityFileConfigChirho::TenantPlacement) => {
                    MembershipTargetAuthorityChirho::TenantPlacementChirho(
                        tenant_placement_chirho.clone().ok_or_else(|| {
                            anyhow::anyhow!("TenantPlacementMembershipConfigUnavailableChirho")
                        })?,
                    )
                }
                None if matches!(&group_chirho, ConsistencyGroupIdChirho::TenantChirho { .. }) => {
                    anyhow::bail!("TenantPlacementMembershipSelectorUnavailableChirho")
                }
                None => MembershipTargetAuthorityChirho::RosterWideChirho,
            };
            Some(MembershipControlConfigChirho {
                roster_authority_chirho,
                local_node_pubkey_hex_chirho: actual_local_node_chirho,
                group_id_chirho: group_chirho.canonical_id_chirho(),
                target_authority_chirho,
                operator_token_chirho,
                fixpoint_step_sleep_chirho: Duration::from_millis(
                    control_chirho.fixpoint_step_sleep_ms_chirho,
                ),
                fixpoint_max_steps_chirho: control_chirho.fixpoint_max_steps_chirho,
            })
        }
        None => None,
    };
    Ok(LoadedClusterNodeConfigChirho {
        cluster_chirho: ClusterNodeConfigChirho {
            group_chirho,
            local_raft_id_chirho: file_chirho.local_raft_id_chirho,
            voters_chirho,
            learners_chirho,
            peers_chirho,
            durable_dir_chirho: PathBuf::from(file_chirho.durable_dir_chirho),
            sign_root_chirho: PathBuf::from(file_chirho.sign_root_chirho),
            tick_interval_chirho,
            membership_control_chirho,
        },
        listen_addr_chirho: file_chirho.listen_addr_chirho,
        config_blake3_chirho,
        writer_era_activation_authorization_chirho: file_chirho
            .writer_era_activation_authorization_chirho
            .map(PathBuf::from),
        roster_authority_chirho,
        tenant_placement_chirho,
        tenant_migration_capacity_chirho,
    })
}

fn parse_cluster_node_readiness_config_chirho(
    bytes_chirho: &[u8],
) -> Result<LoadedClusterNodeReadinessConfigChirho> {
    let config_blake3_chirho = blake3::hash(bytes_chirho).to_hex().to_string();
    let file_chirho: NodeFileConfigChirho = serde_json::from_slice(bytes_chirho)?;
    validate_cluster_tick_interval_chirho(Duration::from_millis(file_chirho.tick_ms_chirho))?;
    let group_chirho = match &file_chirho.group_chirho {
        GroupConfigChirho::Tenant { tenant_id_chirho } => ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: tenant_id_chirho.clone(),
        },
        GroupConfigChirho::Root { root_path_chirho } => ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: root_path_chirho.clone(),
        },
    };
    let role_chirho = match file_chirho.membership_control_chirho.as_ref() {
        Some(control_chirho) => {
            if file_chirho.roster_authority_chirho.is_none() {
                anyhow::bail!("RosterAuthorityConfigUnavailableChirho");
            }
            match control_chirho.target_authority_chirho.as_ref() {
                Some(MembershipTargetAuthorityFileConfigChirho::TenantPlacement) => {
                    if file_chirho.tenant_placement_chirho.is_none() {
                        anyhow::bail!("TenantPlacementMembershipConfigUnavailableChirho");
                    }
                    ClusterNodeReadinessRoleChirho::TenantPlacementServingChirho
                }
                Some(MembershipTargetAuthorityFileConfigChirho::RosterWide) => {
                    ClusterNodeReadinessRoleChirho::RosterWideControlChirho
                }
                None if matches!(&group_chirho, ConsistencyGroupIdChirho::TenantChirho { .. }) => {
                    anyhow::bail!("TenantPlacementMembershipSelectorUnavailableChirho")
                }
                None => ClusterNodeReadinessRoleChirho::RosterWideControlChirho,
            }
        }
        None => ClusterNodeReadinessRoleChirho::NoMembershipControlChirho,
    };
    let voters_chirho = file_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| !member_chirho.learner_chirho)
        .map(|member_chirho| {
            (
                member_chirho.raft_id_chirho,
                member_chirho.pubkey_chirho.clone(),
            )
        })
        .collect();
    let learners_chirho = file_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| member_chirho.learner_chirho)
        .map(|member_chirho| {
            (
                member_chirho.raft_id_chirho,
                member_chirho.pubkey_chirho.clone(),
            )
        })
        .collect();
    let placement_record_path_chirho = file_chirho
        .tenant_placement_chirho
        .as_ref()
        .map(|placement_chirho| PathBuf::from(&placement_chirho.placement_record_path_chirho));
    let placement_pubkey_hex_chirho = file_chirho
        .tenant_placement_chirho
        .as_ref()
        .map(|placement_chirho| placement_chirho.placement_pubkey_hex_chirho.clone());
    let geo_plan_pubkey_hex_chirho = file_chirho
        .tenant_placement_chirho
        .as_ref()
        .map(|placement_chirho| placement_chirho.geo_plan_pubkey_hex_chirho.clone());
    let roster_operator_pubkey_hex_chirho = file_chirho
        .roster_authority_chirho
        .as_ref()
        .map(|roster_chirho| roster_chirho.operator_pubkey_hex_chirho.clone());
    Ok(LoadedClusterNodeReadinessConfigChirho {
        group_chirho,
        local_raft_id_chirho: file_chirho.local_raft_id_chirho,
        voters_chirho,
        learners_chirho,
        sign_root_chirho: PathBuf::from(file_chirho.sign_root_chirho),
        config_blake3_chirho,
        roster_authority_configured_chirho: file_chirho.roster_authority_chirho.is_some(),
        tenant_placement_configured_chirho: file_chirho.tenant_placement_chirho.is_some(),
        placement_record_path_chirho,
        placement_pubkey_hex_chirho,
        roster_operator_pubkey_hex_chirho,
        geo_plan_pubkey_hex_chirho,
        role_chirho,
    })
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn config_bytes_chirho(tick_ms_chirho: u64) -> Vec<u8> {
        format!(
            r#"{{
                "group_chirho": {{"kind_chirho":"root","root_path_chirho":"/tmp/cairn-chirho"}},
                "local_raft_id_chirho": 1,
                "members_chirho": [
                    {{
                        "raft_id_chirho": 1,
                        "pubkey_chirho": "{}",
                        "url_chirho": "http://127.0.0.1:3001",
                        "learner_chirho": false
                    }}
                ],
                "durable_dir_chirho": "/tmp/cairn-raft-chirho",
                "sign_root_chirho": "/tmp/cairn-sign-chirho",
                "listen_addr_chirho": "127.0.0.1:3001",
                "tick_ms_chirho": {tick_ms_chirho}
            }}"#,
            "a".repeat(64)
        )
        .into_bytes()
    }

    fn tenant_migration_capacity_value_chirho() -> serde_json::Value {
        serde_json::json!({
            "schema_chirho": TENANT_MIGRATION_CAPACITY_CONFIG_SCHEMA_V2_CHIRHO,
            "evidence_root_chirho": "/var/lib/cairn-capacity-evidence-chirho",
            "expectation_record_path_chirho": "/etc/cairn-chirho/capacity-expectation-7-chirho.json",
            "expectation_revision_chirho": 7,
            "capacity_registrar_pubkey_hex_chirho": "a".repeat(64),
            "lifecycle_pubkey_hex_chirho": "b".repeat(64),
            "topology_grant_pubkey_hex_chirho": "c".repeat(64),
            "budget_pubkey_hex_chirho": "d".repeat(64),
            "node_measurement_pubkeys_chirho": {
                "e".repeat(64): "f".repeat(64),
            },
            "headroom_chirho": {
                "cpu_millicores_chirho": 500,
                "memory_bytes_chirho": 1_073_741_824_u64,
                "durable_bytes_chirho": 10_737_418_240_u64,
            },
        })
    }

    #[test]
    fn cluster_file_tick_interval_is_bounded_chirho() {
        parse_cluster_node_file_config_chirho(&config_bytes_chirho(50))
            .expect("ordinary election tick is accepted");
        assert!(
            parse_cluster_node_file_config_chirho(&config_bytes_chirho(0))
                .err()
                .expect("zero tick is refused")
                .to_string()
                .contains("between 10 and 1000 milliseconds")
        );
        assert!(
            parse_cluster_node_file_config_chirho(&config_bytes_chirho(1_001))
                .err()
                .expect("oversized tick is refused")
                .to_string()
                .contains("between 10 and 1000 milliseconds")
        );
    }

    #[test]
    fn tenant_migration_capacity_expectation_locator_is_stable_and_fail_closed_chirho() {
        let absent_chirho = parse_cluster_node_file_config_chirho(&config_bytes_chirho(50))
            .expect("legacy cluster config parses without capacity admission");
        assert_eq!(absent_chirho.tenant_migration_capacity_chirho, None);

        let mut value_chirho: serde_json::Value =
            serde_json::from_slice(&config_bytes_chirho(50)).expect("fixture JSON");
        value_chirho["tenant_migration_capacity_chirho"] = tenant_migration_capacity_value_chirho();
        let loaded_chirho = parse_cluster_node_file_config_chirho(
            &serde_json::to_vec(&value_chirho).expect("encode fixture JSON"),
        )
        .expect("stable capacity policy parses")
        .tenant_migration_capacity_chirho
        .expect("capacity admission configured");
        assert_eq!(
            loaded_chirho.expectation_record_path_chirho,
            PathBuf::from("/etc/cairn-chirho/capacity-expectation-7-chirho.json")
        );
        assert_eq!(loaded_chirho.expectation_revision_chirho, 7);
        assert_eq!(loaded_chirho.node_measurement_pubkeys_chirho.len(), 1);

        let mut zero_revision_chirho = value_chirho.clone();
        zero_revision_chirho["tenant_migration_capacity_chirho"]["expectation_revision_chirho"] =
            serde_json::Value::from(0);
        assert_eq!(
            parse_cluster_node_file_config_chirho(
                &serde_json::to_vec(&zero_revision_chirho).expect("encode zero revision fixture"),
            )
            .err()
            .expect("zero expectation revision is refused")
            .to_string(),
            "TenantMigrationCapacityExpectationRevisionRefusedChirho"
        );

        let mut inside_root_chirho = value_chirho.clone();
        inside_root_chirho["tenant_migration_capacity_chirho"]["expectation_record_path_chirho"] =
            serde_json::Value::String(
                "/var/lib/cairn-capacity-evidence-chirho/expectation-chirho.json".to_string(),
            );
        assert_eq!(
            parse_cluster_node_file_config_chirho(
                &serde_json::to_vec(&inside_root_chirho).expect("encode inside-root fixture"),
            )
            .err()
            .expect("inside-root expectation is refused")
            .to_string(),
            "TenantMigrationCapacityExpectationInsideEvidenceRootRefusedChirho"
        );

        let mut legacy_inline_chirho = value_chirho.clone();
        let legacy_capacity_chirho = legacy_inline_chirho["tenant_migration_capacity_chirho"]
            .as_object_mut()
            .expect("capacity object");
        legacy_capacity_chirho.insert(
            "schema_chirho".to_string(),
            serde_json::Value::String("tenant-migration-capacity-config-v1-chirho".to_string()),
        );
        legacy_capacity_chirho.remove("expectation_record_path_chirho");
        legacy_capacity_chirho.remove("expectation_revision_chirho");
        legacy_capacity_chirho.insert(
            "expected_placement_population_digest_chirho".to_string(),
            serde_json::Value::String("1".repeat(64)),
        );
        legacy_capacity_chirho.insert(
            "expected_capacity_load_snapshot_digest_chirho".to_string(),
            serde_json::Value::String("2".repeat(64)),
        );
        assert!(
            parse_cluster_node_file_config_chirho(
                &serde_json::to_vec(&legacy_inline_chirho).expect("encode inline-pin fixture"),
            )
            .is_err(),
            "the self-referential V1 inline pins must not deserialize"
        );

        let mut shared_authority_chirho = value_chirho.clone();
        shared_authority_chirho["tenant_migration_capacity_chirho"]
            ["lifecycle_pubkey_hex_chirho"] = serde_json::Value::String("a".repeat(64));
        assert_eq!(
            parse_cluster_node_file_config_chirho(
                &serde_json::to_vec(&shared_authority_chirho)
                    .expect("encode shared authority fixture"),
            )
            .err()
            .expect("shared authority is refused")
            .to_string(),
            "TenantMigrationCapacityFleetAuthorityRefusedChirho"
        );

        let mut zero_headroom_chirho = value_chirho;
        zero_headroom_chirho["tenant_migration_capacity_chirho"]["headroom_chirho"]
            ["durable_bytes_chirho"] = serde_json::Value::from(0);
        assert_eq!(
            parse_cluster_node_file_config_chirho(
                &serde_json::to_vec(&zero_headroom_chirho).expect("encode zero headroom fixture"),
            )
            .err()
            .expect("zero headroom is refused")
            .to_string(),
            "TenantMigrationCapacityHeadroomRefusedChirho"
        );
    }

    #[test]
    fn omitting_the_relay_interface_keeps_the_previous_wg0_behaviour_chirho() {
        // THE LOAD-BEARING HALF. Every config authored before this field existed must resolve to the
        // exact interface the compiled-in constant named, or this change silently retargets which
        // WireGuard interface a live deployment verifies its signed roster against.
        let mut omitted_chirho: serde_json::Value =
            serde_json::from_slice(&config_bytes_chirho(50)).expect("fixture JSON");
        omitted_chirho["roster_authority_chirho"] = serde_json::json!({
            "roster_path_chirho": "/tmp/roster-chirho.json",
            "roster_head_path_chirho": "/tmp/roster-head-chirho.json",
            "operator_pubkey_hex_chirho": "a".repeat(64),
        });
        let parsed_omitted_chirho = parse_cluster_node_file_config_chirho(
            &serde_json::to_vec(&omitted_chirho).expect("encode fixture JSON"),
        )
        .expect("roster authority without an interface parses");
        assert_eq!(
            parsed_omitted_chirho
                .roster_authority_chirho
                .expect("roster authority present")
                .relay_interface_chirho,
            cairn_roster_config_chirho::RELAY_WIREGUARD_INTERFACE_CHIRHO,
            "an omitted interface must resolve to the previously compiled-in constant"
        );

        // And a supplied interface is carried through verbatim, so a drill can name its own mesh.
        let mut supplied_chirho: serde_json::Value =
            serde_json::from_slice(&config_bytes_chirho(50)).expect("fixture JSON");
        supplied_chirho["roster_authority_chirho"] = serde_json::json!({
            "roster_path_chirho": "/tmp/roster-chirho.json",
            "roster_head_path_chirho": "/tmp/roster-head-chirho.json",
            "operator_pubkey_hex_chirho": "a".repeat(64),
            "relay_interface_chirho": "wg1",
        });
        let parsed_supplied_chirho = parse_cluster_node_file_config_chirho(
            &serde_json::to_vec(&supplied_chirho).expect("encode fixture JSON"),
        )
        .expect("roster authority with an interface parses");
        assert_eq!(
            parsed_supplied_chirho
                .roster_authority_chirho
                .expect("roster authority present")
                .relay_interface_chirho,
            "wg1"
        );
    }

    #[test]
    fn cluster_file_preserves_the_optional_writer_era_activation_path_chirho() {
        let absent_bytes_chirho = config_bytes_chirho(50);
        let absent_chirho = parse_cluster_node_file_config_chirho(&absent_bytes_chirho)
            .expect("ordinary cluster config parses");
        assert_eq!(
            absent_chirho.writer_era_activation_authorization_chirho,
            None
        );
        assert_eq!(
            absent_chirho.config_blake3_chirho,
            blake3::hash(&absent_bytes_chirho).to_hex().to_string()
        );

        let mut value_chirho: serde_json::Value =
            serde_json::from_slice(&config_bytes_chirho(50)).expect("fixture JSON");
        value_chirho["writer_era_activation_authorization_chirho"] =
            serde_json::Value::String("/tmp/writer-era-activation-chirho.json".to_string());
        let present_chirho = parse_cluster_node_file_config_chirho(
            &serde_json::to_vec(&value_chirho).expect("encode fixture JSON"),
        )
        .expect("cluster config with activation path parses");
        assert_eq!(
            present_chirho.writer_era_activation_authorization_chirho,
            Some(PathBuf::from("/tmp/writer-era-activation-chirho.json"))
        );
    }

    #[test]
    fn tenant_membership_selector_and_top_level_placement_fail_closed_at_load_chirho() {
        let sign_temp_chirho = tempfile::tempdir().unwrap();
        let sign_root_chirho = sign_temp_chirho.path().join("node-sign-chirho");
        cairn_signer_chirho::signer_chirho::sign_message_chirho(
            &sign_root_chirho,
            b"provision-node-chirho",
        )
        .unwrap();
        let mut value_chirho: serde_json::Value =
            serde_json::from_slice(&config_bytes_chirho(50)).unwrap();
        value_chirho["group_chirho"] = serde_json::json!({
            "kind_chirho": "tenant",
            "tenant_id_chirho": "selector-test-chirho"
        });
        value_chirho["sign_root_chirho"] =
            serde_json::Value::String(sign_root_chirho.display().to_string());
        value_chirho["membership_control_chirho"] = serde_json::json!({
            "operator_token_env_chirho": "TEST_OPERATOR_TOKEN_CHIRHO",
            "target_authority_chirho": {"kind_chirho": "roster_wide"}
        });
        let missing_roster_chirho = match parse_cluster_node_file_config_chirho(
            &serde_json::to_vec(&value_chirho).unwrap(),
        ) {
            Ok(_loaded_chirho) => panic!("membership control without roster reads must refuse"),
            Err(error_chirho) => error_chirho,
        };
        assert_eq!(
            missing_roster_chirho.to_string(),
            "RosterAuthorityConfigUnavailableChirho"
        );

        value_chirho["roster_authority_chirho"] = serde_json::json!({
            "roster_path_chirho": "/tmp/roster-chirho.jsonl",
            "roster_head_path_chirho": "/tmp/roster-head-chirho.json",
            "operator_pubkey_hex_chirho": "b".repeat(64)
        });
        value_chirho["membership_control_chirho"] = serde_json::json!({
            "operator_token_env_chirho": "TEST_OPERATOR_TOKEN_CHIRHO"
        });
        let missing_selector_chirho = match parse_cluster_node_file_config_chirho(
            &serde_json::to_vec(&value_chirho).unwrap(),
        ) {
            Ok(_loaded_chirho) => panic!("tenant membership without a selector must refuse"),
            Err(error_chirho) => error_chirho,
        };
        assert_eq!(
            missing_selector_chirho.to_string(),
            "TenantPlacementMembershipSelectorUnavailableChirho"
        );

        value_chirho["membership_control_chirho"]["target_authority_chirho"] =
            serde_json::json!({"kind_chirho": "tenant_placement"});
        let missing_placement_chirho = match parse_cluster_node_file_config_chirho(
            &serde_json::to_vec(&value_chirho).unwrap(),
        ) {
            Ok(_loaded_chirho) => {
                panic!("tenant placement selector without top-level config must refuse")
            }
            Err(error_chirho) => error_chirho,
        };
        assert_eq!(
            missing_placement_chirho.to_string(),
            "TenantPlacementMembershipConfigUnavailableChirho"
        );

        value_chirho["tenant_placement_chirho"] = serde_json::json!({
            "placement_record_path_chirho": "/tmp/tenant-placement-chirho.json",
            "placement_pubkey_hex_chirho": "c".repeat(64),
            "geo_plan_pubkey_hex_chirho": "d".repeat(64)
        });
        let loaded_chirho =
            parse_cluster_node_file_config_chirho(&serde_json::to_vec(&value_chirho).unwrap())
                .unwrap();
        assert!(matches!(
            loaded_chirho
                .cluster_chirho
                .membership_control_chirho
                .unwrap()
                .target_authority_chirho,
            MembershipTargetAuthorityChirho::TenantPlacementChirho(_)
        ));
        assert!(loaded_chirho.roster_authority_chirho.is_some());
        assert!(loaded_chirho.tenant_placement_chirho.is_some());

        value_chirho
            .as_object_mut()
            .unwrap()
            .remove("membership_control_chirho");
        let held_read_only_chirho =
            parse_cluster_node_file_config_chirho(&serde_json::to_vec(&value_chirho).unwrap())
                .unwrap();
        assert!(held_read_only_chirho.roster_authority_chirho.is_some());
        assert!(held_read_only_chirho.tenant_placement_chirho.is_some());
        assert!(held_read_only_chirho
            .cluster_chirho
            .membership_control_chirho
            .is_none());
    }

    #[test]
    fn cluster_file_load_refuses_before_unbounded_allocation_chirho() {
        let nonce_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-cluster-config-bound-{}-{nonce_chirho}-chirho.json",
            std::process::id()
        ));
        std::fs::write(
            &path_chirho,
            vec![b' '; MAX_CLUSTER_NODE_FILE_BYTES_CHIRHO as usize + 1],
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path_chirho, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error_chirho = match load_cluster_node_file_config_chirho(&path_chirho) {
            Ok(_loaded_chirho) => panic!("oversized cluster config must be refused"),
            Err(error_chirho) => error_chirho,
        };
        assert!(error_chirho
            .to_string()
            .contains("cluster config exceeds the 65536-byte limit"));

        std::fs::remove_file(path_chirho).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cluster_file_custody_refuses_broad_mode_symlink_and_hard_link_chirho() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let nonce_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-cluster-config-custody-{}-{nonce_chirho}-chirho",
            std::process::id()
        ));
        std::fs::create_dir_all(&root_chirho).unwrap();
        let config_path_chirho = root_chirho.join("node-chirho.json");
        std::fs::write(&config_path_chirho, config_bytes_chirho(50)).unwrap();
        std::fs::set_permissions(&config_path_chirho, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        verify_cluster_node_file_config_custody_chirho(&root_chirho, &config_path_chirho)
            .expect("private same-owner cluster config is accepted");

        std::fs::set_permissions(&config_path_chirho, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(
            verify_cluster_node_file_config_custody_chirho(&root_chirho, &config_path_chirho)
                .unwrap_err()
                .to_string()
                .contains("permissions are too broad")
        );

        std::fs::set_permissions(&config_path_chirho, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let symlink_path_chirho = root_chirho.join("node-link-chirho.json");
        symlink(&config_path_chirho, &symlink_path_chirho).unwrap();
        assert!(
            verify_cluster_node_file_config_custody_chirho(&root_chirho, &symlink_path_chirho)
                .unwrap_err()
                .to_string()
                .contains("must not be a symlink")
        );

        let hard_link_path_chirho = root_chirho.join("node-hard-link-chirho.json");
        std::fs::hard_link(&config_path_chirho, &hard_link_path_chirho).unwrap();
        let hard_link_error_chirho =
            match load_cluster_node_file_config_chirho(&hard_link_path_chirho) {
                Ok(_loaded_chirho) => panic!("a multiply linked authority config must refuse"),
                Err(error_chirho) => error_chirho,
            };
        assert!(
            hard_link_error_chirho
                .to_string()
                .contains("read identity-stable cluster config"),
            "a multiply linked authority config must not be hashed or trusted"
        );

        std::fs::remove_dir_all(root_chirho).unwrap();
    }
}
