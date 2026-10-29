// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Production capacity/load admission for an already-placed tenant migration.
//!
//! The adapter consumes four independent evidence families: the complete signed placement
//! population, registrar-signed capacity, authority-signed lifecycle, and node-signed usage. The
//! target's occupied capacity is the componentwise maximum of derived reservations and observed
//! usage; neither signal can erase the other and no dimension can pay for another.
//!
//! The capacity/lifecycle/usage logs are an unbounded stream rather than a complete population. For
//! one migration they become a bounded OPERATOR-REVIEWED SNAPSHOT: the exact log bytes are hashed and
//! compared with a digest supplied outside this evidence root. A legitimate later report therefore
//! invalidates the snapshot until the operator reviews and reauthors the coordinate. That refusal is
//! intentional. Never "fix" it by deriving the expected digest beside these logs; that would turn
//! deletion/truncation detection into self-certification.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use crate::attestation_stores_chirho::capacity_attestation_store_chirho::{
    NODE_CAPACITY_ATTESTATION_LOG_CHIRHO, NODE_CAPACITY_ATTESTATION_LOG_MAX_BYTES_CHIRHO,
};
use crate::attestation_stores_chirho::lifecycle_transition_store_chirho::{
    NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO, NODE_LIFECYCLE_TRANSITION_LOG_MAX_BYTES_CHIRHO,
};
use crate::attestation_stores_chirho::placement_record_store_chirho::{
    load_verified_placement_population_chirho, PlacementRecordStoreRefusalChirho,
};
use crate::attestation_stores_chirho::usage_measurement_store_chirho::{
    NODE_USAGE_MEASUREMENT_LOG_CHIRHO, NODE_USAGE_MEASUREMENT_LOG_MAX_BYTES_CHIRHO,
};
use crate::control_plane_authorities_chirho::{
    resolve_control_plane_authorities_chirho, ControlPlaneAuthoritiesChirho,
    ControlPlaneAuthorityRefusalChirho,
};
use crate::placement_registry_load_chirho::{
    load_verified_placement_registry_for_admission_chirho, RegistryLoadRefusalChirho,
};
use crate::VerifiedTenantPlacementChirho;
use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::capacity_chirho::reserved_capacity_chirho::PlacedDemandChirho;
use cairn_placement_chirho::placement_registry_chirho::PlacementRefusalChirho;
use cairn_tenant_chirho::capacity_admission_chirho::{
    TenantCapacityAdmissionPortChirho, TenantCapacityAdmissionVerdictChirho,
    TenantCapacityDemandChirho,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const CAPACITY_LOAD_SNAPSHOT_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-capacity-load-snapshot-v1-chirho";
const CAPACITY_ADMISSION_IDENTITY_DOMAIN_V1_CHIRHO: &str =
    "tenant-migration-capacity-admission-identity-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantCapacityAdmissionAdapterRefusalChirho {
    EvidenceRootRefusedChirho,
    AuthorityRefusedChirho,
    EvidenceSnapshotUnavailableChirho,
    EvidenceSnapshotMismatchChirho,
    PlacementPopulationChirho(PlacementRecordStoreRefusalChirho),
    RegistryChirho(RegistryLoadRefusalChirho),
    CurrentTenantMissingChirho,
    CurrentAssignmentChangedChirho,
    CurrentDemandChangedChirho,
    PlacementNamesUnknownNodeChirho,
    TargetNotAssignedChirho,
    TargetEvidenceMissingChirho,
    IdentityEncodeChirho,
}

impl TenantCapacityAdmissionAdapterRefusalChirho {
    fn label_chirho(&self) -> &'static str {
        match self {
            Self::EvidenceRootRefusedChirho => "capacity-evidence-root-refused-chirho",
            Self::AuthorityRefusedChirho => "capacity-authority-refused-chirho",
            Self::EvidenceSnapshotUnavailableChirho => {
                "capacity-evidence-snapshot-unavailable-chirho"
            }
            Self::EvidenceSnapshotMismatchChirho => "capacity-evidence-snapshot-mismatch-chirho",
            Self::PlacementPopulationChirho(_) => "placement-population-refused-chirho",
            Self::RegistryChirho(_) => "capacity-registry-refused-chirho",
            Self::CurrentTenantMissingChirho => "current-tenant-placement-missing-chirho",
            Self::CurrentAssignmentChangedChirho => "current-tenant-assignment-changed-chirho",
            Self::CurrentDemandChangedChirho => "current-tenant-demand-changed-chirho",
            Self::PlacementNamesUnknownNodeChirho => "placement-node-evidence-missing-chirho",
            Self::TargetNotAssignedChirho => "migration-target-not-assigned-chirho",
            Self::TargetEvidenceMissingChirho => "migration-target-evidence-missing-chirho",
            Self::IdentityEncodeChirho => "capacity-admission-identity-refused-chirho",
        }
    }
}

impl From<ControlPlaneAuthorityRefusalChirho> for TenantCapacityAdmissionAdapterRefusalChirho {
    fn from(_refusal_chirho: ControlPlaneAuthorityRefusalChirho) -> Self {
        Self::AuthorityRefusedChirho
    }
}

/// Plain, public-only coordinates needed to verify one placement evidence root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantCapacityEvidenceConfigChirho {
    pub evidence_root_chirho: PathBuf,
    pub expected_placement_population_digest_chirho: String,
    pub expected_capacity_load_snapshot_digest_chirho: String,
    pub placement_pubkey_hex_chirho: String,
    pub roster_operator_pubkey_hex_chirho: String,
    pub geo_plan_pubkey_hex_chirho: String,
    pub capacity_registrar_pubkey_hex_chirho: String,
    pub lifecycle_pubkey_hex_chirho: String,
    pub topology_grant_pubkey_hex_chirho: String,
    pub budget_pubkey_hex_chirho: String,
    pub node_measurement_pubkeys_chirho: BTreeMap<String, String>,
}

/// Production implementation of the dependency-light tenant capacity port.
pub struct VerifiedTenantCapacityAdmissionChirho {
    config_chirho: TenantCapacityEvidenceConfigChirho,
    authorities_chirho: ControlPlaneAuthoritiesChirho,
    current_placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    node_ids_chirho: Vec<String>,
}

impl VerifiedTenantCapacityAdmissionChirho {
    pub fn new_chirho(
        config_chirho: TenantCapacityEvidenceConfigChirho,
        current_placement_chirho: Arc<VerifiedTenantPlacementChirho>,
    ) -> Result<Self, TenantCapacityAdmissionAdapterRefusalChirho> {
        let metadata_chirho = std::fs::symlink_metadata(&config_chirho.evidence_root_chirho)
            .map_err(|_error_chirho| {
                TenantCapacityAdmissionAdapterRefusalChirho::EvidenceRootRefusedChirho
            })?;
        if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
            return Err(TenantCapacityAdmissionAdapterRefusalChirho::EvidenceRootRefusedChirho);
        }
        let authorities_chirho = resolve_control_plane_authorities_chirho(
            &config_chirho.capacity_registrar_pubkey_hex_chirho,
            &config_chirho.lifecycle_pubkey_hex_chirho,
            &config_chirho.topology_grant_pubkey_hex_chirho,
            &config_chirho.budget_pubkey_hex_chirho,
            &config_chirho.node_measurement_pubkeys_chirho,
        )?;
        let node_ids_chirho = config_chirho
            .node_measurement_pubkeys_chirho
            .keys()
            .cloned()
            .collect();
        Ok(Self {
            config_chirho,
            authorities_chirho,
            current_placement_chirho,
            node_ids_chirho,
        })
    }

    fn evaluate_chirho(
        &self,
        target_node_id_chirho: &str,
        demand_chirho: &TenantCapacityDemandChirho,
        headroom_chirho: &TenantCapacityDemandChirho,
    ) -> Result<TenantCapacityAdmissionVerdictChirho, TenantCapacityAdmissionAdapterRefusalChirho>
    {
        let snapshot_before_chirho =
            capacity_load_snapshot_digest_chirho(&self.config_chirho.evidence_root_chirho)?;
        if snapshot_before_chirho
            != self
                .config_chirho
                .expected_capacity_load_snapshot_digest_chirho
        {
            return Err(
                TenantCapacityAdmissionAdapterRefusalChirho::EvidenceSnapshotMismatchChirho,
            );
        }

        let population_chirho = load_verified_placement_population_chirho(
            &self.config_chirho.evidence_root_chirho,
            &self
                .config_chirho
                .expected_placement_population_digest_chirho,
            &self.config_chirho.placement_pubkey_hex_chirho,
            &self.config_chirho.roster_operator_pubkey_hex_chirho,
            &self.config_chirho.geo_plan_pubkey_hex_chirho,
        )
        .map_err(TenantCapacityAdmissionAdapterRefusalChirho::PlacementPopulationChirho)?;
        let current_population_placement_chirho = population_chirho
            .current_chirho()
            .iter()
            .find(|placement_chirho| {
                placement_chirho.intent_chirho().tenant_id_chirho
                    == self
                        .current_placement_chirho
                        .intent_chirho()
                        .tenant_id_chirho
            })
            .ok_or(TenantCapacityAdmissionAdapterRefusalChirho::CurrentTenantMissingChirho)?;
        if current_population_placement_chirho.assignment_digest_chirho()
            != self.current_placement_chirho.assignment_digest_chirho()
        {
            return Err(
                TenantCapacityAdmissionAdapterRefusalChirho::CurrentAssignmentChangedChirho,
            );
        }
        let expected_demand_chirho = demand_from_allocatable_chirho(
            &self.current_placement_chirho.intent_chirho().demand_chirho,
        );
        if &expected_demand_chirho != demand_chirho {
            return Err(TenantCapacityAdmissionAdapterRefusalChirho::CurrentDemandChangedChirho);
        }
        if self
            .current_placement_chirho
            .assigned_node_chirho(target_node_id_chirho)
            .is_none()
        {
            return Err(TenantCapacityAdmissionAdapterRefusalChirho::TargetNotAssignedChirho);
        }

        let mut registry_chirho = load_verified_placement_registry_for_admission_chirho(
            &self.config_chirho.evidence_root_chirho,
            &self.node_ids_chirho,
            self.authorities_chirho.capacity_registrar_chirho(),
            self.authorities_chirho.lifecycle_chirho(),
            &self.authorities_chirho,
        )
        .map_err(TenantCapacityAdmissionAdapterRefusalChirho::RegistryChirho)?;
        for placement_chirho in population_chirho.current_chirho() {
            for node_chirho in placement_chirho.assigned_nodes_chirho() {
                if !self
                    .config_chirho
                    .node_measurement_pubkeys_chirho
                    .contains_key(&node_chirho.node_id_chirho)
                {
                    return Err(
                        TenantCapacityAdmissionAdapterRefusalChirho::PlacementNamesUnknownNodeChirho,
                    );
                }
                registry_chirho.record_placement_chirho(
                    &node_chirho.node_id_chirho,
                    PlacedDemandChirho {
                        placement_id_chirho: placement_chirho
                            .assignment_digest_chirho()
                            .to_string(),
                        demand_chirho: placement_chirho.intent_chirho().demand_chirho,
                    },
                );
            }
        }
        let target_node_chirho = registry_chirho
            .node_chirho(target_node_id_chirho)
            .ok_or(TenantCapacityAdmissionAdapterRefusalChirho::TargetEvidenceMissingChirho)?;
        let headroom_allocatable_chirho = allocatable_from_demand_chirho(headroom_chirho);
        let placement_refusals_chirho = registry_chirho.retained_placement_refusals_chirho(
            target_node_id_chirho,
            &headroom_allocatable_chirho,
        );

        // Re-read the exact bytes after parsing. The stores perform their own identity-stable reads;
        // this second snapshot check makes a replace between the first hash and those reads refuse.
        let snapshot_after_chirho =
            capacity_load_snapshot_digest_chirho(&self.config_chirho.evidence_root_chirho)?;
        if snapshot_after_chirho != snapshot_before_chirho {
            return Err(
                TenantCapacityAdmissionAdapterRefusalChirho::EvidenceSnapshotMismatchChirho,
            );
        }

        let identity_material_chirho = CapacityAdmissionIdentityMaterialChirho {
            schema_chirho: CAPACITY_ADMISSION_IDENTITY_DOMAIN_V1_CHIRHO,
            target_node_id_chirho,
            population_digest_chirho: population_chirho.population_digest_chirho(),
            capacity_load_snapshot_digest_chirho: &snapshot_after_chirho,
            current_assignment_digest_chirho: self
                .current_placement_chirho
                .assignment_digest_chirho(),
            demand_chirho,
            headroom_chirho,
            target_allocatable_chirho: target_node_chirho.allocatable_chirho(),
            target_lifecycle_chirho: format!("{:?}", target_node_chirho.lifecycle_chirho()),
            target_measurement_chirho: target_node_chirho.last_measurement_chirho(),
            target_observed_usage_chirho: target_node_chirho.last_observed_usage_chirho(),
            target_reserved_chirho: registry_chirho.reserved_for_chirho(target_node_id_chirho),
            target_occupied_chirho: registry_chirho
                .effective_occupied_for_chirho(target_node_id_chirho),
            placement_refusals_chirho: &placement_refusals_chirho,
            placement_pubkey_hex_chirho: &self.config_chirho.placement_pubkey_hex_chirho,
            roster_operator_pubkey_hex_chirho: &self
                .config_chirho
                .roster_operator_pubkey_hex_chirho,
            geo_plan_pubkey_hex_chirho: &self.config_chirho.geo_plan_pubkey_hex_chirho,
            capacity_registrar_pubkey_hex_chirho: &self
                .config_chirho
                .capacity_registrar_pubkey_hex_chirho,
            lifecycle_pubkey_hex_chirho: &self.config_chirho.lifecycle_pubkey_hex_chirho,
            topology_grant_pubkey_hex_chirho: &self.config_chirho.topology_grant_pubkey_hex_chirho,
            budget_pubkey_hex_chirho: &self.config_chirho.budget_pubkey_hex_chirho,
            node_measurement_pubkeys_chirho: &self.config_chirho.node_measurement_pubkeys_chirho,
        };
        let identity_bytes_chirho =
            serde_json::to_vec(&identity_material_chirho).map_err(|_error_chirho| {
                TenantCapacityAdmissionAdapterRefusalChirho::IdentityEncodeChirho
            })?;
        let evidence_identity_chirho = blake3::hash(&identity_bytes_chirho).to_hex().to_string();
        let considered_chirho = [
            population_chirho.population_digest_chirho()
                == self
                    .config_chirho
                    .expected_placement_population_digest_chirho,
            snapshot_after_chirho
                == self
                    .config_chirho
                    .expected_capacity_load_snapshot_digest_chirho,
            registry_chirho.node_chirho(target_node_id_chirho).is_some(),
            registry_chirho.placement_count_for_chirho(target_node_id_chirho) > 0,
            target_node_chirho.last_observed_usage_chirho().is_some(),
        ]
        .into_iter()
        .filter(|considered_chirho| *considered_chirho)
        .count();
        Ok(TenantCapacityAdmissionVerdictChirho {
            considered_chirho,
            refusals_chirho: placement_refusals_chirho
                .iter()
                .map(placement_refusal_label_chirho)
                .map(str::to_string)
                .collect(),
            evidence_identity_chirho,
        })
    }
}

impl TenantCapacityAdmissionPortChirho for VerifiedTenantCapacityAdmissionChirho {
    fn admit_target_chirho(
        &self,
        target_node_id_chirho: &str,
        demand_chirho: &TenantCapacityDemandChirho,
        headroom_chirho: &TenantCapacityDemandChirho,
    ) -> TenantCapacityAdmissionVerdictChirho {
        self.evaluate_chirho(target_node_id_chirho, demand_chirho, headroom_chirho)
            .unwrap_or_else(|refusal_chirho| TenantCapacityAdmissionVerdictChirho {
                considered_chirho: 0,
                refusals_chirho: vec![refusal_chirho.label_chirho().to_string()],
                evidence_identity_chirho: failure_identity_chirho(
                    target_node_id_chirho,
                    refusal_chirho.label_chirho(),
                ),
            })
    }
}

#[derive(Serialize)]
struct CapacityAdmissionIdentityMaterialChirho<'material_chirho> {
    schema_chirho: &'static str,
    target_node_id_chirho: &'material_chirho str,
    population_digest_chirho: &'material_chirho str,
    capacity_load_snapshot_digest_chirho: &'material_chirho str,
    current_assignment_digest_chirho: &'material_chirho str,
    demand_chirho: &'material_chirho TenantCapacityDemandChirho,
    headroom_chirho: &'material_chirho TenantCapacityDemandChirho,
    target_allocatable_chirho: &'material_chirho AllocatableCapacityChirho,
    target_lifecycle_chirho: String,
    target_measurement_chirho:
        Option<cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::MeasurementStampChirho>,
    target_observed_usage_chirho: Option<&'material_chirho AllocatableCapacityChirho>,
    target_reserved_chirho: AllocatableCapacityChirho,
    target_occupied_chirho: Option<AllocatableCapacityChirho>,
    placement_refusals_chirho: &'material_chirho [PlacementRefusalChirho],
    placement_pubkey_hex_chirho: &'material_chirho str,
    roster_operator_pubkey_hex_chirho: &'material_chirho str,
    geo_plan_pubkey_hex_chirho: &'material_chirho str,
    capacity_registrar_pubkey_hex_chirho: &'material_chirho str,
    lifecycle_pubkey_hex_chirho: &'material_chirho str,
    topology_grant_pubkey_hex_chirho: &'material_chirho str,
    budget_pubkey_hex_chirho: &'material_chirho str,
    node_measurement_pubkeys_chirho: &'material_chirho BTreeMap<String, String>,
}

fn placement_refusal_label_chirho(refusal_chirho: &PlacementRefusalChirho) -> &'static str {
    match refusal_chirho {
        PlacementRefusalChirho::FrozenByItsOwnEvidenceChirho => {
            "capacity-load-evidence-frozen-chirho"
        }
        PlacementRefusalChirho::UnknownNodeChirho { .. } => {
            "migration-target-evidence-missing-chirho"
        }
        PlacementRefusalChirho::LifecycleClosedChirho { .. } => {
            "migration-target-lifecycle-closed-chirho"
        }
        PlacementRefusalChirho::MeasurementNotFreshChirho { .. } => {
            "capacity-load-offer-not-fresh-chirho"
        }
        PlacementRefusalChirho::CapacityChirho(_) => {
            "migration-target-headroom-insufficient-chirho"
        }
    }
}

fn demand_from_allocatable_chirho(
    capacity_chirho: &AllocatableCapacityChirho,
) -> TenantCapacityDemandChirho {
    TenantCapacityDemandChirho {
        cpu_millicores_chirho: capacity_chirho.cpu_millicores_chirho,
        memory_bytes_chirho: capacity_chirho.memory_bytes_chirho,
        durable_bytes_chirho: capacity_chirho.durable_bytes_chirho,
    }
}

fn allocatable_from_demand_chirho(
    demand_chirho: &TenantCapacityDemandChirho,
) -> AllocatableCapacityChirho {
    AllocatableCapacityChirho {
        cpu_millicores_chirho: demand_chirho.cpu_millicores_chirho,
        memory_bytes_chirho: demand_chirho.memory_bytes_chirho,
        durable_bytes_chirho: demand_chirho.durable_bytes_chirho,
    }
}

fn failure_identity_chirho(target_node_id_chirho: &str, label_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(CAPACITY_ADMISSION_IDENTITY_DOMAIN_V1_CHIRHO.as_bytes());
    hasher_chirho.update(b"\0refused\0");
    hasher_chirho.update(target_node_id_chirho.as_bytes());
    hasher_chirho.update(b"\0");
    hasher_chirho.update(label_chirho.as_bytes());
    hasher_chirho.finalize().to_hex().to_string()
}

/// Digest the exact bounded capacity, lifecycle, and usage log bytes for one admission snapshot.
pub fn capacity_load_snapshot_digest_chirho(
    root_chirho: &Path,
) -> Result<String, TenantCapacityAdmissionAdapterRefusalChirho> {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(CAPACITY_LOAD_SNAPSHOT_DOMAIN_V1_CHIRHO.as_bytes());
    for (name_chirho, max_bytes_chirho) in [
        (
            NODE_CAPACITY_ATTESTATION_LOG_CHIRHO,
            NODE_CAPACITY_ATTESTATION_LOG_MAX_BYTES_CHIRHO,
        ),
        (
            NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO,
            NODE_LIFECYCLE_TRANSITION_LOG_MAX_BYTES_CHIRHO,
        ),
        (
            NODE_USAGE_MEASUREMENT_LOG_CHIRHO,
            NODE_USAGE_MEASUREMENT_LOG_MAX_BYTES_CHIRHO,
        ),
    ] {
        let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
            &root_chirho.join(name_chirho),
            max_bytes_chirho,
        )
        .map_err(|_error_chirho| {
            TenantCapacityAdmissionAdapterRefusalChirho::EvidenceSnapshotUnavailableChirho
        })?;
        hasher_chirho.update(b"\0");
        hasher_chirho.update(name_chirho.as_bytes());
        hasher_chirho.update(b"\0");
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
    }
    Ok(hasher_chirho.finalize().to_hex().to_string())
}

#[cfg(test)]
#[path = "capacity_admission_impl_tests_chirho.rs"]
mod capacity_admission_impl_tests_chirho;
