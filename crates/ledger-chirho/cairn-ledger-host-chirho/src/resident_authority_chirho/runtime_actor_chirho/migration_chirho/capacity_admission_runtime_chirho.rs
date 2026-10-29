// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Actor-owned capacity admission coordinates for tenant migration.
//!
//! The placement implementation lives above this crate. The resident actor retains only the plain
//! port plus the signed tenant demand and operator-reviewed headroom, then derives the target node
//! from the target root's existing keypair. A caller cannot substitute a node id beside the path.
//! Workflow:
//! `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`.

use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_tenant_chirho::capacity_admission_chirho::{
    TenantCapacityAdmissionPortChirho, TenantCapacityAdmissionVerdictChirho,
    TenantCapacityDemandChirho,
};
use std::path::Path;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TenantMigrationCapacityCompositionRefusalChirho {
    ZeroDemandChirho,
    ZeroHeadroomChirho,
    TargetNodeIdentityUnavailableChirho,
    EvidenceIdentityMalformedChirho,
}

/// Fixed capacity policy retained by the resident actor for every begin/recovery/activation check.
#[derive(Clone)]
pub struct TenantMigrationCapacityAdmissionCompositionChirho {
    admission_port_chirho: Arc<dyn TenantCapacityAdmissionPortChirho>,
    demand_chirho: TenantCapacityDemandChirho,
    headroom_chirho: TenantCapacityDemandChirho,
}

impl TenantMigrationCapacityAdmissionCompositionChirho {
    pub fn new_chirho(
        admission_port_chirho: Arc<dyn TenantCapacityAdmissionPortChirho>,
        demand_chirho: TenantCapacityDemandChirho,
        headroom_chirho: TenantCapacityDemandChirho,
    ) -> Result<Self, TenantMigrationCapacityCompositionRefusalChirho> {
        if has_zero_dimension_chirho(demand_chirho) {
            return Err(TenantMigrationCapacityCompositionRefusalChirho::ZeroDemandChirho);
        }
        if has_zero_dimension_chirho(headroom_chirho) {
            return Err(TenantMigrationCapacityCompositionRefusalChirho::ZeroHeadroomChirho);
        }
        Ok(Self {
            admission_port_chirho,
            demand_chirho,
            headroom_chirho,
        })
    }

    pub(crate) fn admit_target_root_chirho(
        &self,
        target_root_chirho: &Path,
    ) -> Result<TenantCapacityAdmissionVerdictChirho, TenantMigrationCapacityCompositionRefusalChirho>
    {
        let target_node_id_chirho = existing_keypair_pubkey_hex_chirho(target_root_chirho)
            .map_err(|_error_chirho| {
                TenantMigrationCapacityCompositionRefusalChirho::TargetNodeIdentityUnavailableChirho
            })?;
        let verdict_chirho = self.admission_port_chirho.admit_target_chirho(
            &target_node_id_chirho,
            &self.demand_chirho,
            &self.headroom_chirho,
        );
        if !is_nonzero_lower_hex_digest_chirho(&verdict_chirho.evidence_identity_chirho) {
            return Err(
                TenantMigrationCapacityCompositionRefusalChirho::EvidenceIdentityMalformedChirho,
            );
        }
        Ok(verdict_chirho)
    }
}

fn has_zero_dimension_chirho(demand_chirho: TenantCapacityDemandChirho) -> bool {
    demand_chirho.cpu_millicores_chirho == 0
        || demand_chirho.memory_bytes_chirho == 0
        || demand_chirho.durable_bytes_chirho == 0
}

fn is_nonzero_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
        && value_chirho.bytes().any(|byte_chirho| byte_chirho != b'0')
}

#[cfg(test)]
pub(crate) use tests_chirho::admitting_test_capacity_composition_chirho;

#[cfg(test)]
mod tests_chirho {
    use super::*;

    struct AdmittingTestCapacityPortChirho;

    impl TenantCapacityAdmissionPortChirho for AdmittingTestCapacityPortChirho {
        fn admit_target_chirho(
            &self,
            _target_node_id_chirho: &str,
            _demand_chirho: &TenantCapacityDemandChirho,
            _headroom_chirho: &TenantCapacityDemandChirho,
        ) -> TenantCapacityAdmissionVerdictChirho {
            TenantCapacityAdmissionVerdictChirho {
                considered_chirho: 1,
                refusals_chirho: Vec::new(),
                evidence_identity_chirho:
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            }
        }
    }

    pub(crate) fn admitting_test_capacity_composition_chirho(
    ) -> TenantMigrationCapacityAdmissionCompositionChirho {
        TenantMigrationCapacityAdmissionCompositionChirho::new_chirho(
            Arc::new(AdmittingTestCapacityPortChirho),
            TenantCapacityDemandChirho {
                cpu_millicores_chirho: 1,
                memory_bytes_chirho: 1,
                durable_bytes_chirho: 1,
            },
            TenantCapacityDemandChirho {
                cpu_millicores_chirho: 1,
                memory_bytes_chirho: 1,
                durable_bytes_chirho: 1,
            },
        )
        .expect("the fixed test capacity composition must be valid")
    }
}
