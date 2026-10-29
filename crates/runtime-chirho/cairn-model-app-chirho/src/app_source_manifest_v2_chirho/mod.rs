// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Strict, authority-inert source-manifest v2 DTOs for projection-aware authoring.

use crate::{
    validate_app_name_chirho, validate_app_source_id_chirho, AppSourceAssetManifestChirho,
    AppSourceDagManifestChirho, AppSourceDeployManifestChirho, AppSourceModuleManifestChirho,
    AppSourceNodeSourceChirho,
};
use anyhow::{bail, Context, Result};
use cairn_input_projection_chirho::contract_chirho::{
    validate_node_input_projection_binding_chirho, NodeInputProjectionBindingChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const APP_SOURCE_MANIFEST_V2_SCHEMA_CHIRHO: &str = "app-source-manifest-v2-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSourceManifestV2Chirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_chirho: String,
    pub nodes_chirho: Vec<AppSourceNodeManifestV2Chirho>,
    pub dags_chirho: Vec<AppSourceDagManifestChirho>,
    pub modules_chirho: Vec<AppSourceModuleManifestChirho>,
    pub assets_chirho: Vec<AppSourceAssetManifestChirho>,
    pub contract_refs_chirho: Vec<String>,
    pub deploy_chirho: AppSourceDeployManifestChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSourceNodeManifestV2Chirho {
    pub id_chirho: String,
    pub name_chirho: String,
    pub entry_chirho: Option<String>,
    pub fuel_chirho: u64,
    pub capabilities_chirho: Vec<String>,
    pub source_chirho: AppSourceNodeSourceChirho,
    pub input_contracts_chirho: BTreeMap<String, NodeInputProjectionBindingChirho>,
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn validate_app_source_manifest_v2_chirho(
    manifest_chirho: &AppSourceManifestV2Chirho,
) -> Result<()> {
    if manifest_chirho.schema_chirho != APP_SOURCE_MANIFEST_V2_SCHEMA_CHIRHO {
        bail!("unsupported app source manifest v2 schema");
    }
    validate_app_name_chirho(&manifest_chirho.app_chirho)?;
    if manifest_chirho.owner_chirho.trim().is_empty() {
        bail!("source manifest v2 owner cannot be empty");
    }

    let mut node_ids_chirho = BTreeSet::new();
    for node_chirho in &manifest_chirho.nodes_chirho {
        validate_app_source_id_chirho("source manifest v2 node id", &node_chirho.id_chirho)?;
        if !node_ids_chirho.insert(&node_chirho.id_chirho) {
            bail!("duplicate source manifest v2 node id");
        }
        if node_chirho.fuel_chirho == 0 {
            bail!("source manifest v2 node fuel must be positive");
        }
        for (port_chirho, binding_chirho) in &node_chirho.input_contracts_chirho {
            validate_app_source_id_chirho("source manifest v2 input port", port_chirho)?;
            validate_node_input_projection_binding_chirho(binding_chirho)
                .with_context(|| format!("validate input contract for port {port_chirho}"))?;
        }
    }

    let mut dag_ids_chirho = BTreeSet::new();
    for dag_chirho in &manifest_chirho.dags_chirho {
        validate_app_source_id_chirho("source manifest v2 dag id", &dag_chirho.id_chirho)?;
        if !dag_ids_chirho.insert(&dag_chirho.id_chirho) {
            bail!("duplicate source manifest v2 dag id");
        }
    }
    let mut module_ids_chirho = BTreeSet::new();
    for module_chirho in &manifest_chirho.modules_chirho {
        validate_app_source_id_chirho("source manifest v2 module id", &module_chirho.id_chirho)?;
        if !module_ids_chirho.insert(&module_chirho.id_chirho) {
            bail!("duplicate source manifest v2 module id");
        }
    }
    Ok(())
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn canonical_app_source_manifest_v2_bytes_chirho(
    manifest_chirho: &AppSourceManifestV2Chirho,
) -> Result<Vec<u8>> {
    validate_app_source_manifest_v2_chirho(manifest_chirho)?;
    serde_json::to_vec(manifest_chirho).context("encode canonical app source manifest v2")
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn parse_canonical_app_source_manifest_v2_chirho(
    bytes_chirho: &[u8],
) -> Result<AppSourceManifestV2Chirho> {
    let manifest_chirho: AppSourceManifestV2Chirho =
        serde_json::from_slice(bytes_chirho).context("decode app source manifest v2")?;
    validate_app_source_manifest_v2_chirho(&manifest_chirho)?;
    if serde_json::to_vec(&manifest_chirho)? != bytes_chirho {
        bail!("app source manifest v2 has a byte-canonical mismatch");
    }
    Ok(manifest_chirho)
}

#[cfg(test)]
mod tests_chirho;
