// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Where a desired-state topology plan lives in a root, and the resolver that finds it again.
//!
//! **The obstacle this module exists to get past, stated first because it is the whole design.** A
//! plan's declared digest is `plan_hash_chirho(plan) = hash(canonical_plan_bytes_chirho(plan))` — a
//! hand-written length-prefixed INJECTIVE encoding, deliberately not serde. A CAS address is
//! `hash(serde_json::to_vec(value))`. **They are different digests of the same plan**, so
//! `put_object_chirho(plan)` files it somewhere the declared digest does not name, and a resolver
//! keyed on that digest finds ABSENT every single time. That is why the port has had no implementor.
//!
//! The tempting fix is a DECODER for the canonical encoding, so the canonical bytes could be both the
//! stored object and the parse source. That is the expensive option: a hand-written encoder plus a
//! hand-written decoder is two things that must agree forever, and nothing else in the tree needs a
//! decoder today.
//!
//! So both forms are stored and one indexes the other:
//!
//! ```text
//! add(canonical_plan_bytes(plan))  -> lands at EXACTLY plan_hash, by construction
//! put_object(plan)                 -> lands at the serde address; THIS is what gets parsed
//! append {plan_hash, serde_address} to the index log
//! ```
//!
//! **The index does not have to be trusted, and that is the point.**
//! `verify_topology_plan_reference_chirho` re-hashes whatever a resolver returns and refuses
//! `PlanDigestMismatchChirho` if it differs. So a wrong — or hostile — index row produces a REFUSAL,
//! never an acceptance. The row is a hint; the digest is the proof. That is what makes the pure
//! module's "the re-hash is last and is not optional" load-bearing rather than decorative.
//!
//! **Why the canonical bytes are stored even though nothing ever parses them.** The index log is a
//! DECLARED surface, so self-containment requires every 64-hex token in it to resolve as an object in
//! this root — and `plan_hash` appears in every row. Without that object, every row is a dangling
//! reference and migration refuses. Storing the canonical bytes makes the digest resolve *by
//! construction*, because the address IS their hash. It is also independently checkable without a
//! decoder: verifying bytes hash to their own address needs no parse.
//!
//! Growth: resolution scans the index. Plans are written on topology CHANGE, not per request, so the
//! log is bounded by operator actions rather than by traffic — unlike the usage log next door, which
//! is the one that grows without a ceiling.

use super::plan_reference_chirho::{TopologyPlanResolutionChirho, TopologyPlanResolverPortChirho};
use cairn_core_chirho::cas_chirho::{self, CasReadOutcomeChirho};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::store_chirho::put_object_chirho;
use cairn_placement_chirho::topology_chirho::plan_hash_chirho::{
    canonical_plan_bytes_chirho, plan_hash_chirho,
};
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::DesiredTopologyPlanChirho;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[path = "plan_index_evidence_chirho.rs"]
pub mod plan_index_evidence_chirho;

pub const TOPOLOGY_PLAN_INDEX_LOG_CHIRHO: &str = "topology-plan-index-chirho.jsonl";
pub const TOPOLOGY_PLAN_INDEX_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;

/// One plan's two addresses. Untrusted by construction — see the module header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyPlanIndexRowChirho {
    /// The plan's DECLARED digest, over canonical bytes. Also the address those bytes are stored at.
    pub plan_hash_chirho: String,
    /// Where the serde-encoded plan lives, which is what gets parsed.
    pub serde_address_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlanStoreRefusalChirho {
    StoreUnavailableChirho,
    StoreIdentityUnstableChirho,
    DecodeChirho {
        line_chirho: u64,
    },
    /// The canonical bytes did not land at the plan's declared digest. Checked rather than assumed,
    /// because the whole self-containment argument rests on that identity holding.
    CanonicalBytesNotAtPlanHashChirho {
        declared_chirho: String,
        stored_at_chirho: String,
    },
}

fn index_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO)
}

fn read_index_chirho(
    root_chirho: &Path,
) -> Result<Vec<TopologyPlanIndexRowChirho>, PlanStoreRefusalChirho> {
    let path_chirho = index_path_chirho(root_chirho);
    let bytes_chirho = match cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        TOPOLOGY_PLAN_INDEX_MAX_BYTES_CHIRHO,
    ) {
        Ok(bytes_chirho) => bytes_chirho,
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new())
        }
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::InvalidData => {
            return Err(PlanStoreRefusalChirho::StoreIdentityUnstableChirho)
        }
        Err(_error_chirho) => return Err(PlanStoreRefusalChirho::StoreUnavailableChirho),
    };
    let text_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_error_chirho| PlanStoreRefusalChirho::DecodeChirho { line_chirho: 0 })?;
    let mut rows_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        rows_chirho.push(serde_json::from_str(line_chirho).map_err(|_error_chirho| {
            PlanStoreRefusalChirho::DecodeChirho {
                line_chirho: index_chirho as u64 + 1,
            }
        })?);
    }
    Ok(rows_chirho)
}

/// Store a plan and return its declared digest.
///
/// Idempotent by content address: storing the same plan twice writes the same two objects and appends
/// a duplicate index row, and a duplicate row resolves to the same place.
pub fn store_topology_plan_chirho(
    root_chirho: &Path,
    plan_chirho: &DesiredTopologyPlanChirho,
) -> Result<String, PlanStoreRefusalChirho> {
    let declared_chirho = plan_hash_chirho(plan_chirho).0;

    // The canonical bytes must land at the declared digest. This is the identity the index log's
    // self-containment depends on, so it is VERIFIED rather than assumed.
    let canonical_address_chirho =
        cas_chirho::add_chirho(root_chirho, &canonical_plan_bytes_chirho(plan_chirho))
            .map_err(|_error_chirho| PlanStoreRefusalChirho::StoreUnavailableChirho)?;
    if canonical_address_chirho.0 != declared_chirho {
        return Err(PlanStoreRefusalChirho::CanonicalBytesNotAtPlanHashChirho {
            declared_chirho,
            stored_at_chirho: canonical_address_chirho.0,
        });
    }

    let serde_address_chirho = put_object_chirho(root_chirho, plan_chirho)
        .map_err(|_error_chirho| PlanStoreRefusalChirho::StoreUnavailableChirho)?;

    let row_chirho = TopologyPlanIndexRowChirho {
        plan_hash_chirho: declared_chirho.clone(),
        serde_address_chirho: serde_address_chirho.0,
    };
    let mut line_chirho = serde_json::to_vec(&row_chirho)
        .map_err(|_error_chirho| PlanStoreRefusalChirho::StoreUnavailableChirho)?;
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(&index_path_chirho(root_chirho), &line_chirho)
        .map_err(|_error_chirho| PlanStoreRefusalChirho::StoreUnavailableChirho)?;

    Ok(declared_chirho)
}

/// Resolves plan digests against one root. The production implementor of the pure port.
pub struct RootPlanResolverChirho {
    root_chirho: PathBuf,
}

impl RootPlanResolverChirho {
    pub fn new_chirho(root_chirho: &Path) -> Self {
        Self {
            root_chirho: root_chirho.to_path_buf(),
        }
    }
}

impl TopologyPlanResolverPortChirho for RootPlanResolverChirho {
    fn resolve_plan_chirho(&self, digest_chirho: &str) -> TopologyPlanResolutionChirho {
        // An index that cannot be READ is not an index that says "nothing here". Absent is reserved
        // for a root that genuinely holds no such plan.
        let Ok(rows_chirho) = read_index_chirho(&self.root_chirho) else {
            return TopologyPlanResolutionChirho::UnreadableChirho;
        };
        let Some(row_chirho) = rows_chirho
            .into_iter()
            .find(|row_chirho| row_chirho.plan_hash_chirho == digest_chirho)
        else {
            return TopologyPlanResolutionChirho::AbsentChirho;
        };
        match cas_chirho::read_verified_chirho(
            &self.root_chirho,
            &HashChirho(row_chirho.serde_address_chirho),
        ) {
            CasReadOutcomeChirho::VerifiedChirho(bytes_chirho) => {
                // Verified means the bytes produce their own address. If they then fail to PARSE as a
                // plan they are unreadable, NOT tampered: tampered means the bytes do not produce the
                // address they are filed under, and these do.
                match serde_json::from_slice::<DesiredTopologyPlanChirho>(&bytes_chirho) {
                    Ok(plan_chirho) => {
                        TopologyPlanResolutionChirho::FoundChirho(Box::new(plan_chirho))
                    }
                    Err(_error_chirho) => TopologyPlanResolutionChirho::UnreadableChirho,
                }
            }
            CasReadOutcomeChirho::AbsentChirho(_error_chirho) => {
                TopologyPlanResolutionChirho::AbsentChirho
            }
            CasReadOutcomeChirho::UnreadableChirho(_error_chirho) => {
                TopologyPlanResolutionChirho::UnreadableChirho
            }
            CasReadOutcomeChirho::TamperedChirho { .. } => {
                TopologyPlanResolutionChirho::TamperedChirho
            }
        }
    }
}

#[cfg(test)]
#[path = "plan_store_tests_chirho.rs"]
mod plan_store_tests_chirho;
