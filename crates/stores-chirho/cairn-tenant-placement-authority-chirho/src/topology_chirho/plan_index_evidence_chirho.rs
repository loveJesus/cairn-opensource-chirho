// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Verifies every topology-index binding without publishing plan contents or granting authority.

use super::{read_index_chirho, PlanStoreRefusalChirho, TopologyPlanIndexRowChirho};
use cairn_core_chirho::cas_chirho::{read_verified_bounded_chirho, CasReadOutcomeChirho};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_placement_chirho::topology_chirho::plan_hash_chirho::canonical_plan_bytes_chirho;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::DesiredTopologyPlanChirho;
use std::collections::BTreeSet;
use std::path::Path;

/// Evidence verification refuses larger objects; it does not change the plan writer's policy.
pub const TOPOLOGY_PLAN_EVIDENCE_OBJECT_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopologyPlanIndexEvidenceRefusalChirho {
    IndexChirho(PlanStoreRefusalChirho),
    ObjectAbsentChirho,
    ObjectUnreadableChirho,
    ObjectTamperedChirho,
    PlanDecodeChirho,
    CanonicalBindingMismatchChirho,
}

fn read_object_chirho(
    root_chirho: &Path,
    address_chirho: &str,
) -> Result<Vec<u8>, TopologyPlanIndexEvidenceRefusalChirho> {
    match read_verified_bounded_chirho(
        root_chirho,
        &HashChirho(address_chirho.to_owned()),
        TOPOLOGY_PLAN_EVIDENCE_OBJECT_MAX_BYTES_CHIRHO,
    ) {
        CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => Ok(bytes_chirho),
        CasReadOutcomeChirho::AbsentChirho(_error_chirho) => {
            Err(TopologyPlanIndexEvidenceRefusalChirho::ObjectAbsentChirho)
        }
        CasReadOutcomeChirho::UnreadableChirho(_error_chirho) => {
            Err(TopologyPlanIndexEvidenceRefusalChirho::ObjectUnreadableChirho)
        }
        CasReadOutcomeChirho::TamperedChirho { .. } => {
            Err(TopologyPlanIndexEvidenceRefusalChirho::ObjectTamperedChirho)
        }
    }
}

/// Return only the two-address rows after checking both objects and their canonical-plan binding.
///
/// The index remains an unsigned hint: this proves integrity, not grant approval or completeness
/// against a trusted historical head. The bounded index is read once and duplicate bindings share
/// object checks. No key, lock, object, or log is created. Workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/tenant-placement-authority-chirho.md`.
pub fn load_verified_topology_plan_index_chirho(
    root_chirho: &Path,
) -> Result<Vec<TopologyPlanIndexRowChirho>, TopologyPlanIndexEvidenceRefusalChirho> {
    let rows_chirho = read_index_chirho(root_chirho)
        .map_err(TopologyPlanIndexEvidenceRefusalChirho::IndexChirho)?;
    let mut checked_chirho = BTreeSet::new();
    for row_chirho in &rows_chirho {
        if !checked_chirho.insert((
            row_chirho.plan_hash_chirho.as_str(),
            row_chirho.serde_address_chirho.as_str(),
        )) {
            continue;
        }
        let canonical_chirho = read_object_chirho(root_chirho, &row_chirho.plan_hash_chirho)?;
        let encoded_chirho = read_object_chirho(root_chirho, &row_chirho.serde_address_chirho)?;
        let plan_chirho: DesiredTopologyPlanChirho = serde_json::from_slice(&encoded_chirho)
            .map_err(|_error_chirho| TopologyPlanIndexEvidenceRefusalChirho::PlanDecodeChirho)?;
        if canonical_plan_bytes_chirho(&plan_chirho) != canonical_chirho {
            return Err(TopologyPlanIndexEvidenceRefusalChirho::CanonicalBindingMismatchChirho);
        }
    }
    Ok(rows_chirho)
}

/// Count the index rows whose object bindings verify, including legitimate duplicate writes.
pub fn verify_topology_plan_index_chirho(
    root_chirho: &Path,
) -> Result<usize, TopologyPlanIndexEvidenceRefusalChirho> {
    Ok(load_verified_topology_plan_index_chirho(root_chirho)?.len())
}

#[cfg(test)]
#[path = "plan_index_evidence_tests_chirho.rs"]
mod plan_index_evidence_tests_chirho;
