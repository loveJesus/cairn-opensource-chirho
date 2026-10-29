// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Stable cluster-config half of capacity-driven tenant migration.
//!
//! The exact cluster-config hash is bound into every placement readiness receipt. Derived placement
//! and load digests therefore cannot live in these bytes: placement population depends on the
//! receipts, which would create a fixed point. The config names only an outside-root expectation
//! record and an operator-authored revision. The independently signed record binds this exact config
//! hash and carries the derived digests.
//!
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use anyhow::Result;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, PathBuf};

pub const TENANT_MIGRATION_CAPACITY_CONFIG_SCHEMA_V2_CHIRHO: &str =
    "tenant-migration-capacity-config-v2-chirho";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TenantMigrationCapacityFileConfigChirho {
    schema_chirho: String,
    evidence_root_chirho: String,
    expectation_record_path_chirho: String,
    expectation_revision_chirho: u64,
    capacity_registrar_pubkey_hex_chirho: String,
    lifecycle_pubkey_hex_chirho: String,
    topology_grant_pubkey_hex_chirho: String,
    budget_pubkey_hex_chirho: String,
    node_measurement_pubkeys_chirho: BTreeMap<String, String>,
    headroom_chirho: TenantMigrationCapacityHeadroomConfigChirho,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TenantMigrationCapacityHeadroomConfigChirho {
    pub cpu_millicores_chirho: u64,
    pub memory_bytes_chirho: u64,
    pub durable_bytes_chirho: u64,
}

/// Stable policy and custody coordinates for one reviewed capacity/load admission generation.
///
/// The expectation locator is not authority. Runtime admission separately verifies the record's two
/// signatures, exact config hash, operator revision, resident placement, and derived evidence pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantMigrationCapacityConfigChirho {
    pub evidence_root_chirho: PathBuf,
    pub expectation_record_path_chirho: PathBuf,
    pub expectation_revision_chirho: u64,
    pub capacity_registrar_pubkey_hex_chirho: String,
    pub lifecycle_pubkey_hex_chirho: String,
    pub topology_grant_pubkey_hex_chirho: String,
    pub budget_pubkey_hex_chirho: String,
    pub node_measurement_pubkeys_chirho: BTreeMap<String, String>,
    pub headroom_chirho: TenantMigrationCapacityHeadroomConfigChirho,
}

pub(crate) fn parse_tenant_migration_capacity_config_chirho(
    config_chirho: TenantMigrationCapacityFileConfigChirho,
) -> Result<TenantMigrationCapacityConfigChirho> {
    if config_chirho.schema_chirho != TENANT_MIGRATION_CAPACITY_CONFIG_SCHEMA_V2_CHIRHO {
        anyhow::bail!("TenantMigrationCapacitySchemaRefusedChirho");
    }
    let evidence_root_chirho = absolute_normal_path_chirho(&config_chirho.evidence_root_chirho)
        .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityEvidenceRootRefusedChirho"))?;
    let expectation_record_path_chirho = absolute_normal_path_chirho(
        &config_chirho.expectation_record_path_chirho,
    )
    .ok_or_else(|| anyhow::anyhow!("TenantMigrationCapacityExpectationPathRefusedChirho"))?;
    if expectation_record_path_chirho.starts_with(&evidence_root_chirho) {
        anyhow::bail!("TenantMigrationCapacityExpectationInsideEvidenceRootRefusedChirho");
    }
    if config_chirho.expectation_revision_chirho == 0 {
        anyhow::bail!("TenantMigrationCapacityExpectationRevisionRefusedChirho");
    }

    let fleet_keys_chirho = [
        &config_chirho.capacity_registrar_pubkey_hex_chirho,
        &config_chirho.lifecycle_pubkey_hex_chirho,
        &config_chirho.topology_grant_pubkey_hex_chirho,
        &config_chirho.budget_pubkey_hex_chirho,
    ];
    if fleet_keys_chirho
        .iter()
        .any(|key_chirho| !nonzero_lower_hex_coordinate_chirho(key_chirho))
        || fleet_keys_chirho.into_iter().collect::<BTreeSet<_>>().len() != 4
    {
        anyhow::bail!("TenantMigrationCapacityFleetAuthorityRefusedChirho");
    }
    if config_chirho.node_measurement_pubkeys_chirho.is_empty() {
        anyhow::bail!("TenantMigrationCapacityNodePopulationRefusedChirho");
    }
    let mut all_keys_chirho = fleet_keys_chirho.into_iter().collect::<BTreeSet<_>>();
    for (node_id_chirho, key_chirho) in &config_chirho.node_measurement_pubkeys_chirho {
        if !nonzero_lower_hex_coordinate_chirho(node_id_chirho)
            || !nonzero_lower_hex_coordinate_chirho(key_chirho)
            || !all_keys_chirho.insert(key_chirho)
        {
            anyhow::bail!("TenantMigrationCapacityNodeAuthorityRefusedChirho");
        }
    }
    if config_chirho.headroom_chirho.cpu_millicores_chirho == 0
        || config_chirho.headroom_chirho.memory_bytes_chirho == 0
        || config_chirho.headroom_chirho.durable_bytes_chirho == 0
    {
        anyhow::bail!("TenantMigrationCapacityHeadroomRefusedChirho");
    }

    Ok(TenantMigrationCapacityConfigChirho {
        evidence_root_chirho,
        expectation_record_path_chirho,
        expectation_revision_chirho: config_chirho.expectation_revision_chirho,
        capacity_registrar_pubkey_hex_chirho: config_chirho.capacity_registrar_pubkey_hex_chirho,
        lifecycle_pubkey_hex_chirho: config_chirho.lifecycle_pubkey_hex_chirho,
        topology_grant_pubkey_hex_chirho: config_chirho.topology_grant_pubkey_hex_chirho,
        budget_pubkey_hex_chirho: config_chirho.budget_pubkey_hex_chirho,
        node_measurement_pubkeys_chirho: config_chirho.node_measurement_pubkeys_chirho,
        headroom_chirho: config_chirho.headroom_chirho,
    })
}

fn absolute_normal_path_chirho(value_chirho: &str) -> Option<PathBuf> {
    let path_chirho = PathBuf::from(value_chirho);
    if !path_chirho.is_absolute()
        || path_chirho.components().any(|component_chirho| {
            matches!(component_chirho, Component::CurDir | Component::ParentDir)
        })
    {
        return None;
    }
    Some(path_chirho)
}

pub(crate) fn nonzero_lower_hex_coordinate_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
        && value_chirho.bytes().any(|byte_chirho| byte_chirho != b'0')
}
