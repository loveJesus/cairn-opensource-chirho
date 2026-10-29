// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Read-only, path-free population projection from one verified tenant-placement record.
//!
//! This is the Rust authority boundary used before Python composes a fleet packet. The projection is
//! conditional on three independently supplied public authority pins. It binds their exact ordered
//! triple by digest so a later consumer can compare that digest against its own trusted inputs; it
//! never treats the record's embedded placement key as self-authentication.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.

use crate::{
    verify_tenant_placement_record_chirho, TenantPlacementRecordChirho,
    TenantPlacementRefusalChirho, TENANT_PLACEMENT_ASSIGNED_NODE_COUNT_CHIRHO,
    TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO, TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO,
};
use cairn_core_chirho::model_chirho::{consistency_group_digest_chirho, ConsistencyGroupIdChirho};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::Read;
use std::path::Path;

pub const TENANT_PLACEMENT_POPULATION_PROJECTION_SCHEMA_V2_CHIRHO: &str =
    "tenant-placement-population-projection-v2-chirho";
pub const TENANT_PLACEMENT_AUTHORITY_PIN_DIGEST_PREFIX_V1_CHIRHO: &str =
    "tenant-placement-authority-pins-sha256-v1-chirho:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TenantPlacementPopulationProjectionChirho {
    pub schema_chirho: String,
    pub record_sha256_chirho: String,
    pub assignment_digest_chirho: String,
    /// Digest of placement, roster-operator, and geo-plan public key ids in that exact order.
    /// The raw public keys are intentionally not emitted.
    pub authority_pin_digest_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub ordered_assigned_node_ids_chirho: Vec<String>,
    /// Per-slot activation incarnation digests in the exact assigned-node order above.
    pub ordered_activation_anchor_digests_chirho: Vec<String>,
    pub held_observer_node_id_chirho: String,
    pub assigned_node_count_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantPlacementPopulationProjectionRefusalChirho {
    StoreUnavailableChirho,
    StoreEntryTypeChirho,
    StoreTooLargeChirho,
    DecodeChirho,
    RecordVerificationChirho(TenantPlacementRefusalChirho),
    AuthorityPinDigestChirho,
    ConsistencyGroupDigestChirho,
    AssignedNodePopulationChirho,
    ActivationAnchorRequiredChirho,
    RenderChirho,
}

impl fmt::Display for TenantPlacementPopulationProjectionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter_chirho, "{self:?}")
    }
}

impl std::error::Error for TenantPlacementPopulationProjectionRefusalChirho {}

pub type TenantPlacementPopulationProjectionResultChirho<ValueChirho> =
    Result<ValueChirho, TenantPlacementPopulationProjectionRefusalChirho>;

pub fn project_tenant_placement_population_bytes_chirho(
    record_bytes_chirho: &[u8],
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> TenantPlacementPopulationProjectionResultChirho<TenantPlacementPopulationProjectionChirho> {
    if record_bytes_chirho.len() as u64 > TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO {
        return Err(TenantPlacementPopulationProjectionRefusalChirho::StoreTooLargeChirho);
    }
    let record_chirho: TenantPlacementRecordChirho = serde_json::from_slice(record_bytes_chirho)
        .map_err(|_error_chirho| TenantPlacementPopulationProjectionRefusalChirho::DecodeChirho)?;
    let verified_chirho = verify_tenant_placement_record_chirho(
        record_chirho,
        expected_placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    )
    .map_err(TenantPlacementPopulationProjectionRefusalChirho::RecordVerificationChirho)?;
    if verified_chirho.record_schema_chirho() != TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO {
        return Err(
            TenantPlacementPopulationProjectionRefusalChirho::ActivationAnchorRequiredChirho,
        );
    }

    let assigned_node_count_chirho = u64::try_from(TENANT_PLACEMENT_ASSIGNED_NODE_COUNT_CHIRHO)
        .map_err(|_error_chirho| {
            TenantPlacementPopulationProjectionRefusalChirho::AssignedNodePopulationChirho
        })?;
    if verified_chirho.assigned_nodes_chirho().len() != TENANT_PLACEMENT_ASSIGNED_NODE_COUNT_CHIRHO
    {
        return Err(TenantPlacementPopulationProjectionRefusalChirho::AssignedNodePopulationChirho);
    }
    let consistency_group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: verified_chirho.intent_chirho().tenant_id_chirho.clone(),
    };
    let consistency_group_digest_chirho =
        consistency_group_digest_chirho(&consistency_group_chirho).map_err(|_error_chirho| {
            TenantPlacementPopulationProjectionRefusalChirho::ConsistencyGroupDigestChirho
        })?;

    Ok(TenantPlacementPopulationProjectionChirho {
        schema_chirho: TENANT_PLACEMENT_POPULATION_PROJECTION_SCHEMA_V2_CHIRHO.to_string(),
        record_sha256_chirho: format!("{:x}", Sha256::digest(record_bytes_chirho)),
        assignment_digest_chirho: verified_chirho.assignment_digest_chirho().to_string(),
        authority_pin_digest_chirho: tenant_placement_authority_pin_digest_chirho(
            expected_placement_key_chirho,
            roster_operator_key_chirho,
            geo_plan_authority_key_chirho,
        )?,
        consistency_group_digest_chirho,
        ordered_assigned_node_ids_chirho: verified_chirho
            .assigned_nodes_chirho()
            .iter()
            .map(|node_chirho| node_chirho.node_id_chirho.clone())
            .collect(),
        ordered_activation_anchor_digests_chirho: verified_chirho
            .serving_readiness_receipts_chirho()
            .iter()
            .map(|receipt_chirho| {
                receipt_chirho
                    .activation_anchor_digest_chirho
                    .clone()
                    .ok_or(
                        TenantPlacementPopulationProjectionRefusalChirho::ActivationAnchorRequiredChirho,
                    )
            })
            .collect::<TenantPlacementPopulationProjectionResultChirho<Vec<_>>>()?,
        held_observer_node_id_chirho: verified_chirho
            .held_observer_node_chirho()
            .node_id_chirho
            .clone(),
        assigned_node_count_chirho,
    })
}

pub fn load_and_project_tenant_placement_population_chirho(
    record_path_chirho: &Path,
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> TenantPlacementPopulationProjectionResultChirho<TenantPlacementPopulationProjectionChirho> {
    let metadata_chirho =
        std::fs::symlink_metadata(record_path_chirho).map_err(|_error_chirho| {
            TenantPlacementPopulationProjectionRefusalChirho::StoreUnavailableChirho
        })?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_file() {
        return Err(TenantPlacementPopulationProjectionRefusalChirho::StoreEntryTypeChirho);
    }
    if metadata_chirho.len() > TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO {
        return Err(TenantPlacementPopulationProjectionRefusalChirho::StoreTooLargeChirho);
    }
    let file_chirho = std::fs::File::open(record_path_chirho).map_err(|_error_chirho| {
        TenantPlacementPopulationProjectionRefusalChirho::StoreUnavailableChirho
    })?;
    let mut record_bytes_chirho = Vec::new();
    file_chirho
        .take(TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO + 1)
        .read_to_end(&mut record_bytes_chirho)
        .map_err(|_error_chirho| {
            TenantPlacementPopulationProjectionRefusalChirho::StoreUnavailableChirho
        })?;
    if record_bytes_chirho.len() as u64 > TENANT_PLACEMENT_RECORD_MAX_BYTES_CHIRHO {
        return Err(TenantPlacementPopulationProjectionRefusalChirho::StoreTooLargeChirho);
    }

    // Hashing, decoding, and verification all consume this one captured byte population.
    project_tenant_placement_population_bytes_chirho(
        &record_bytes_chirho,
        expected_placement_key_chirho,
        roster_operator_key_chirho,
        geo_plan_authority_key_chirho,
    )
}

pub fn render_tenant_placement_population_projection_chirho(
    projection_chirho: &TenantPlacementPopulationProjectionChirho,
) -> TenantPlacementPopulationProjectionResultChirho<String> {
    serde_json::to_string(projection_chirho)
        .map_err(|_error_chirho| TenantPlacementPopulationProjectionRefusalChirho::RenderChirho)
}

/// Recomputable cross-language binding for the exact ordered public-authority pin triple.
///
/// Each component is prefixed by its big-endian u64 byte length before SHA-256. This avoids an
/// ambiguous concatenation and does not require Python to reproduce Rust serialization.
pub fn tenant_placement_authority_pin_digest_chirho(
    expected_placement_key_chirho: &str,
    roster_operator_key_chirho: &str,
    geo_plan_authority_key_chirho: &str,
) -> TenantPlacementPopulationProjectionResultChirho<String> {
    let mut digest_chirho = Sha256::new();
    for component_chirho in [
        TENANT_PLACEMENT_AUTHORITY_PIN_DIGEST_PREFIX_V1_CHIRHO.as_bytes(),
        expected_placement_key_chirho.as_bytes(),
        roster_operator_key_chirho.as_bytes(),
        geo_plan_authority_key_chirho.as_bytes(),
    ] {
        let length_chirho = u64::try_from(component_chirho.len()).map_err(|_error_chirho| {
            TenantPlacementPopulationProjectionRefusalChirho::AuthorityPinDigestChirho
        })?;
        digest_chirho.update(length_chirho.to_be_bytes());
        digest_chirho.update(component_chirho);
    }
    let digest_hex_chirho = format!("{:x}", digest_chirho.finalize());
    Ok(format!(
        "{TENANT_PLACEMENT_AUTHORITY_PIN_DIGEST_PREFIX_V1_CHIRHO}{digest_hex_chirho}"
    ))
}
