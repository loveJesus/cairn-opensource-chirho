// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure host-placement ranking core: typed placement DTOs, hard-constraint/affinity field validation, and deterministic candidate scoring — no store or dag_module I/O.
//!
//! # CF8 current state, measured 2026-08-28
//!
//! The caller-resolved tasklist remains the status authority; this crate-root map mirrors it so an
//! older count cannot compete with the current disposition. The 2026-08-26 ruling against evidence
//! landing `f0abdacbfa08031a10a8667e72869af690b3fb81` first recorded all 17 clauses MET. A measured
//! canonical counterexample later reopened clause 11 and immediate correction
//! `4587f4b0efc0f5f1694595f3043ca8e646fbab0b` closed its fail-open replay. Closure
//! `0c51d45e228f5448db22d1a9e7cfede6990b1fd0` answers the four residuals, so **17 of 17 clauses are
//! MET and CF8 is DONE**. That reclosure preserves the counterexample and first ruling as chronology;
//! it does not erase either one.
//!
//! Clause 6 closed on both conjuncts. Scaling twins prove the per-node scaling relationship using
//! reserved capacity and retained rows without claiming host RSS, allocator residency, or absolute
//! bytes. The hosted ceremony proves the source writable through receipt-bound elected authority
//! before the fence, an attempted fenced-source write refusing with zero effect, byte-identical reads
//! across cutover, and a target write after activation. Its journal handoff is content-bound and
//! admission-enforced. It did not exercise an election, quorum loss, failover, a second-host move, or
//! source retirement. The stop is `TargetActivatedSourceRetainedChirho`; source retention is
//! intentional, and no production-money, public-signup, public-webhook, production-real-user-email,
//! retirement, C4, identity-copying, custody-erasure, or readiness gate moved.
//!
//! The detailed notes below preserve **historical clause chronology**. Any embedded `pending`,
//! `PARTIAL`, `16/17`, `17/17`, `MET`, or "remaining" wording yields to the current state above. It
//! remains here to preserve why each mechanism and caveat exists:
//! A 2026-08-23 cold read found that an older map both miscounted its clauses and called clause 9
//! `PARTIAL` below a `MET` headline after the distinct in-place upgrade had landed. Every identifier
//! still resolved, so `cf8_clause_map_guard_tests_chirho` stayed green over contradictory prose. That
//! is why this map mirrors the caller-resolved tasklist instead of acting as its own status authority.
//!
//! - `capacity_chirho`, `topology_chirho`, `node_lifecycle_chirho`,
//!   `infrastructure_budget_chirho`, and `deploy_evidence_chirho` exist and remain reusable;
//! - **clause 11 is RECLOSED.** Its earlier single-seat money-path ruling did not survive a direct
//!   canonical replay check: the loader routed on an unverified stored budget id and discarded failed
//!   verification, so an altered terminal event vanished while replay returned `Ok` from survivors.
//!   Correction `4587f4b0efc0f5f1694595f3043ca8e646fbab0b` authenticates before routing. Closure
//!   `0c51d45e228f5448db22d1a9e7cfede6990b1fd0` adds immutable signed scalar funding, signed
//!   root/tenant/budget/funding binding, a dense exact-line root chain, a separately custodied atomic
//!   monotone checkpoint, ordered root-wide cross-process locks, read-only fail-closed verification,
//!   and a separately gated operator repair road. The report accepts no caller ceiling or authority
//!   key and carries authenticated-funding provenance. Twenty focused arms pass; GPT separately ran
//!   and restored twelve causal mutants, while registered Agy seat message #18823 records an
//!   independent frozen-byte PASS with no findings. Those are distinct evidence provenances. Scope is
//!   evidence-root tamper and honest concurrency, not signer or coherently compromised dual-custody
//!   authority, and no production-money gate moved;
//! - **clauses 9 and 10 remain MET at mechanism scope.** They and clause 11 were originally ruled by
//!   one seat in one session and share the manual adapter. A mechanism-first reread found that the
//!   adapter still has no production constructor and the other grant consumer explicitly applies
//!   nothing, so the adjacent topology-grant truncation question can mislead an operator report but
//!   cannot machine-authorize a plan today. That question remains routed for independent reread and
//!   clearer mechanism-scope wording; it is not a demonstrated live defect or a Clause 11 blocker.
//!   Clause 10's planner-source authority guard remains
//!   `cf8_planner_authority_guard_tests_chirho`. Clause 9's distinct in-place upgrade path and
//!   ports-only source guard remain its current basis; candidate replacement is a different operation;
//! - clause 7 closes ONE of those three: allocatable capacity is now registrar-signed evidence
//!   ([`capacity_chirho::capacity_attestation_chirho`], verify-only, no `sign_chirho`) and the
//!   registry is GATED on it — `RegisteredNodeChirho`'s allocatable field is private and
//!   `from_verified_capacity_chirho` is the only code path in, and it now yields the ENTRY state
//!   (`ProvisionedChirho`) rather than taking a lifecycle parameter: a grant says how much a node may
//!   offer and nothing about whether it was inspected or joined, and admission is gated on Joined, so
//!   a lifecycle argument would have let a signed capacity figure alone open a node to placements.
//!   A durable adapter in `cairn-tenant-placement-authority-chirho` now persists grants and supplies
//!   the replay protection this crate's stateless verifier documents as the caller's. (Named by crate
//!   rather than by module on purpose: the module's name ends in a token the
//!   `host_ranking_core_does_not_reach_into_data_custody_chirho` guard scans for, and a data-custody
//!   guard erring toward flagging a mere mention is the correct direction for a guard.) It remains
//!   **MET** as of 2026-08-18. It was refused twice that day on a later note's ILLUSTRATION of where a
//!   production caller would live ("the running geo-node"), then ruled once that was measured: the
//!   geo-node has zero references to the placement registry or node capacity, so the illustration names
//!   a component with no role needing it, while the AUDIT's residual is one sentence shared with clauses
//!   9-11 and was satisfied the same way for all four. Historical note on what changed underneath: lifecycle transitions and
//!   node-signed usage reports are now durable too, so a node DOES advance past Provisioned from
//!   evidence and a shipped binary builds the registry from a root. The residual is exactly one thing,
//!   and it is quoted rather than paraphrased: *"nothing in the RUNNING GEO-NODE calls
//!   `load_verified_placement_registry_chirho`"*. What ships is a CLI, so that bar stands unlowered;
//! - clause 8's missing piece — an explicit priced network/egress affinity — is now
//!   [`PlacementAffinityKindChirho::EgressPriceCeilingChirho`], with a measured
//!   `egress_price_micros_per_gib_chirho` on the candidate and a `dag-command` spec producer for
//!   both halves. Mutation-proven: making an UNMEASURED price qualify turns
//!   `an_unmeasured_egress_price_never_earns_the_affinity_chirho` red; and
//! - clause 12's pair is no longer a `#[cfg(test)]` fixture — `cairn-deploy-evidence-verify-chirho`
//!   ships as a binary and the staging script consumes it, so a shipping path now constructs
//!   `DeployEvidenceChirho` and gates on the reviewed pair.
//!
//! Clauses 5, 13 and 14 also closed, outside this crate — `cairn-tenant-chirho`'s three migration
//! verifiers, the A6 bridge/shadow-canary boundary, and the hosted five-drill loss sequence.
//!
//! That distinction protects the architecture rather than diminishing it. Post-CF8 product work may
//! extend the durable tenant-root control plane, but it must not create a second placement model,
//! provider-specific authority in this crate, or app-visible topology machinery.

use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub mod budget_chirho;
pub mod capacity_chirho;
pub mod deploy_evidence_chirho;
pub mod failure_domain_chirho;
pub mod node_lifecycle_chirho;
pub mod placement_registry_chirho;
pub mod topology_chirho;

#[cfg(test)]
#[path = "scaling_twins_tests_chirho.rs"]
mod scaling_twins_tests_chirho;

#[cfg(test)]
#[path = "egress_affinity_tests_chirho.rs"]
mod egress_affinity_tests_chirho;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]

pub enum PlacementHardConstraintChirho {
    RequiredHardwareChirho { hardware_chirho: String },
    RequiredRegionChirho { region_chirho: String },
    DataResidencyRegionChirho { region_chirho: String },
    RequiredFeatureChirho { feature_chirho: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlacementAffinityKindChirho {
    PreviousWarmLocationChirho {
        location_chirho: String,
    },
    ColocateWithModuleChirho {
        module_chirho: HashChirho,
    },
    ColocateWithUserCacheChirho {
        user_chirho: String,
    },
    ColocateWithModelChirho {
        model_chirho: String,
    },
    DataLocalityChirho {
        region_chirho: String,
    },
    PreferredAcceleratorChirho {
        accelerator_chirho: String,
    },
    /// Prefer a candidate whose MEASURED egress price is at or below a ceiling, in micros per GiB.
    ///
    /// CF8 clause 8 keeps network/egress *"a priced affinity ... rather than an unmeasured hard
    /// capacity dimension"*, and both halves of that are load-bearing here. **Priced:** the ceiling
    /// and the candidate's price are explicit currency-per-unit numbers, not an opaque preference, so
    /// a rejection can be explained in the units an operator pays in. **Affinity, never capacity:**
    /// this can only add score, so an expensive node stays ELIGIBLE and merely ranks lower — egress
    /// is a cost to be traded off, not a hard admission limit, and it deliberately has no entry in
    /// [`capacity_chirho::capacity_dominance_chirho::CAPACITY_DIMENSIONS_CHIRHO`].
    ///
    /// An UNMEASURED price never matches: a candidate that has not reported one earns no discount,
    /// because "unmeasured" is exactly the state the clause refuses to let stand in for "cheap".
    EgressPriceCeilingChirho {
        max_micros_per_gib_chirho: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementAffinityChirho {
    pub kind_chirho: PlacementAffinityKindChirho,
    pub weight_chirho: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementDescriptorChirho {
    pub module_chirho: HashChirho,
    pub hard_constraints_chirho: Vec<PlacementHardConstraintChirho>,
    pub affinities_chirho: Vec<PlacementAffinityChirho>,
    pub metadata_chirho: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementCandidateChirho {
    pub candidate_chirho: String,
    pub region_chirho: String,
    pub hardware_chirho: Vec<String>,
    pub features_chirho: Vec<String>,
    pub resident_modules_chirho: Vec<HashChirho>,
    pub user_caches_chirho: Vec<String>,
    pub resident_models_chirho: Vec<String>,
    pub data_regions_chirho: Vec<String>,
    pub accelerators_chirho: Vec<String>,
    /// Measured egress price in micros per GiB, or `None` when this candidate has not reported one.
    ///
    /// Defaulted on deserialize so an older serialized candidate still loads, and `None` is the SAFE
    /// reading: it earns no egress affinity rather than being treated as free.
    #[serde(default)]
    pub egress_price_micros_per_gib_chirho: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementCandidateScoreChirho {
    pub candidate_chirho: String,
    pub eligible_chirho: bool,
    pub score_chirho: i64,
    pub matched_affinities_chirho: Vec<String>,
    pub violations_chirho: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementDecisionChirho {
    pub descriptor_chirho: HashChirho,
    pub module_chirho: HashChirho,
    pub run_chirho: Option<HashChirho>,
    pub candidates_digest_chirho: HashChirho,
    pub selected_candidate_chirho: String,
    pub selected_score_chirho: i64,
    pub rankings_chirho: Vec<PlacementCandidateScoreChirho>,
    pub provenance_parents_chirho: Vec<HashChirho>,
}

/// Validate the store-independent fields of a descriptor (hard constraints, affinity weights/tokens,
/// and metadata keys). The root-side `validate_placement_descriptor_chirho` calls this after it has
/// confirmed the descriptor's module exists in the store, preserving the original check order.
pub fn validate_placement_descriptor_fields_chirho(
    descriptor_chirho: &PlacementDescriptorChirho,
) -> Result<()> {
    for constraint_chirho in &descriptor_chirho.hard_constraints_chirho {
        validate_hard_constraint_chirho(constraint_chirho)?;
    }
    for affinity_chirho in &descriptor_chirho.affinities_chirho {
        validate_affinity_chirho(affinity_chirho)?;
    }
    for key_chirho in descriptor_chirho.metadata_chirho.keys() {
        validate_safe_token_chirho("metadata key", key_chirho)?;
    }
    Ok(())
}

pub fn rank_placement_candidates_chirho(
    descriptor_chirho: &PlacementDescriptorChirho,
    candidates_chirho: &[PlacementCandidateChirho],
) -> Result<Vec<PlacementCandidateScoreChirho>> {
    if candidates_chirho.is_empty() {
        bail!("placement dry-run needs at least one candidate");
    }
    let mut seen_chirho = BTreeSet::new();
    let mut scores_chirho = Vec::new();
    for candidate_chirho in candidates_chirho {
        validate_candidate_chirho(candidate_chirho)?;
        if !seen_chirho.insert(candidate_chirho.candidate_chirho.clone()) {
            bail!(
                "duplicate placement candidate '{}'",
                candidate_chirho.candidate_chirho
            );
        }
        scores_chirho.push(score_candidate_chirho(descriptor_chirho, candidate_chirho)?);
    }
    scores_chirho.sort_by(|left_chirho, right_chirho| {
        match right_chirho
            .eligible_chirho
            .cmp(&left_chirho.eligible_chirho)
        {
            Ordering::Equal => match right_chirho.score_chirho.cmp(&left_chirho.score_chirho) {
                Ordering::Equal => left_chirho
                    .candidate_chirho
                    .cmp(&right_chirho.candidate_chirho),
                ordering_chirho => ordering_chirho,
            },
            ordering_chirho => ordering_chirho,
        }
    });
    Ok(scores_chirho)
}

fn score_candidate_chirho(
    descriptor_chirho: &PlacementDescriptorChirho,
    candidate_chirho: &PlacementCandidateChirho,
) -> Result<PlacementCandidateScoreChirho> {
    let violations_chirho = hard_constraint_violations_chirho(descriptor_chirho, candidate_chirho);
    let mut score_chirho = 0_i64;
    let mut matched_affinities_chirho = Vec::new();
    if violations_chirho.is_empty() {
        for affinity_chirho in &descriptor_chirho.affinities_chirho {
            if affinity_matches_chirho(&affinity_chirho.kind_chirho, candidate_chirho) {
                score_chirho += affinity_chirho.weight_chirho;
                matched_affinities_chirho.push(affinity_label_chirho(&affinity_chirho.kind_chirho));
            }
        }
    }
    Ok(PlacementCandidateScoreChirho {
        candidate_chirho: candidate_chirho.candidate_chirho.clone(),
        eligible_chirho: violations_chirho.is_empty(),
        score_chirho,
        matched_affinities_chirho,
        violations_chirho,
    })
}

fn hard_constraint_violations_chirho(
    descriptor_chirho: &PlacementDescriptorChirho,
    candidate_chirho: &PlacementCandidateChirho,
) -> Vec<String> {
    let mut violations_chirho = Vec::new();
    for constraint_chirho in &descriptor_chirho.hard_constraints_chirho {
        match constraint_chirho {
            PlacementHardConstraintChirho::RequiredHardwareChirho { hardware_chirho } => {
                if !contains_str_chirho(&candidate_chirho.hardware_chirho, hardware_chirho) {
                    violations_chirho.push(format!("missing hardware {hardware_chirho}"));
                }
            }
            PlacementHardConstraintChirho::RequiredRegionChirho { region_chirho } => {
                if candidate_chirho.region_chirho != *region_chirho {
                    violations_chirho
                        .push(format!("wrong region {}", candidate_chirho.region_chirho));
                }
            }
            PlacementHardConstraintChirho::DataResidencyRegionChirho { region_chirho } => {
                if candidate_chirho.region_chirho != *region_chirho {
                    violations_chirho
                        .push(format!("violates data residency region {region_chirho}"));
                }
            }
            PlacementHardConstraintChirho::RequiredFeatureChirho { feature_chirho } => {
                if !contains_str_chirho(&candidate_chirho.features_chirho, feature_chirho) {
                    violations_chirho.push(format!("missing feature {feature_chirho}"));
                }
            }
        }
    }
    violations_chirho
}

fn affinity_matches_chirho(
    affinity_chirho: &PlacementAffinityKindChirho,
    candidate_chirho: &PlacementCandidateChirho,
) -> bool {
    match affinity_chirho {
        PlacementAffinityKindChirho::PreviousWarmLocationChirho { location_chirho } => {
            candidate_chirho.candidate_chirho == *location_chirho
        }
        PlacementAffinityKindChirho::ColocateWithModuleChirho { module_chirho } => candidate_chirho
            .resident_modules_chirho
            .contains(module_chirho),
        PlacementAffinityKindChirho::ColocateWithUserCacheChirho { user_chirho } => {
            contains_str_chirho(&candidate_chirho.user_caches_chirho, user_chirho)
        }
        PlacementAffinityKindChirho::ColocateWithModelChirho { model_chirho } => {
            contains_str_chirho(&candidate_chirho.resident_models_chirho, model_chirho)
        }
        PlacementAffinityKindChirho::DataLocalityChirho { region_chirho } => {
            candidate_chirho.region_chirho == *region_chirho
                || contains_str_chirho(&candidate_chirho.data_regions_chirho, region_chirho)
        }
        PlacementAffinityKindChirho::PreferredAcceleratorChirho { accelerator_chirho } => {
            contains_str_chirho(&candidate_chirho.accelerators_chirho, accelerator_chirho)
                || contains_str_chirho(&candidate_chirho.hardware_chirho, accelerator_chirho)
        }
        // An absent price does NOT match: unmeasured never earns the cheap-egress bonus.
        PlacementAffinityKindChirho::EgressPriceCeilingChirho {
            max_micros_per_gib_chirho,
        } => matches!(
            candidate_chirho.egress_price_micros_per_gib_chirho,
            Some(price_chirho) if price_chirho <= *max_micros_per_gib_chirho
        ),
    }
}

fn affinity_label_chirho(affinity_chirho: &PlacementAffinityKindChirho) -> String {
    match affinity_chirho {
        PlacementAffinityKindChirho::PreviousWarmLocationChirho { location_chirho } => {
            format!("previous-warm-location={location_chirho}")
        }
        PlacementAffinityKindChirho::ColocateWithModuleChirho { module_chirho } => {
            format!("colocate-module={}", module_chirho.0)
        }
        PlacementAffinityKindChirho::ColocateWithUserCacheChirho { user_chirho } => {
            format!("user-cache={user_chirho}")
        }
        PlacementAffinityKindChirho::ColocateWithModelChirho { model_chirho } => {
            format!("model={model_chirho}")
        }
        PlacementAffinityKindChirho::DataLocalityChirho { region_chirho } => {
            format!("data-region={region_chirho}")
        }
        PlacementAffinityKindChirho::PreferredAcceleratorChirho { accelerator_chirho } => {
            format!("accelerator={accelerator_chirho}")
        }
        PlacementAffinityKindChirho::EgressPriceCeilingChirho {
            max_micros_per_gib_chirho,
        } => {
            format!("egress-price-ceiling-micros-per-gib={max_micros_per_gib_chirho}")
        }
    }
}

fn validate_hard_constraint_chirho(
    constraint_chirho: &PlacementHardConstraintChirho,
) -> Result<()> {
    match constraint_chirho {
        PlacementHardConstraintChirho::RequiredHardwareChirho { hardware_chirho } => {
            validate_safe_token_chirho("hardware", hardware_chirho)
        }
        PlacementHardConstraintChirho::RequiredRegionChirho { region_chirho }
        | PlacementHardConstraintChirho::DataResidencyRegionChirho { region_chirho } => {
            validate_safe_token_chirho("region", region_chirho)
        }
        PlacementHardConstraintChirho::RequiredFeatureChirho { feature_chirho } => {
            validate_safe_token_chirho("feature", feature_chirho)
        }
    }
}

fn validate_affinity_chirho(affinity_chirho: &PlacementAffinityChirho) -> Result<()> {
    if affinity_chirho.weight_chirho <= 0 || affinity_chirho.weight_chirho > 1_000_000 {
        bail!("placement affinity weights must be between 1 and 1000000");
    }
    match &affinity_chirho.kind_chirho {
        PlacementAffinityKindChirho::PreviousWarmLocationChirho { location_chirho } => {
            validate_safe_token_chirho("location", location_chirho)
        }
        PlacementAffinityKindChirho::ColocateWithModuleChirho { module_chirho } => {
            validate_safe_token_chirho("module hash", &module_chirho.0)
        }
        PlacementAffinityKindChirho::ColocateWithUserCacheChirho { user_chirho } => {
            validate_safe_token_chirho("user cache", user_chirho)
        }
        PlacementAffinityKindChirho::ColocateWithModelChirho { model_chirho } => {
            validate_safe_token_chirho("model", model_chirho)
        }
        PlacementAffinityKindChirho::DataLocalityChirho { region_chirho } => {
            validate_safe_token_chirho("region", region_chirho)
        }
        PlacementAffinityKindChirho::PreferredAcceleratorChirho { accelerator_chirho } => {
            validate_safe_token_chirho("accelerator", accelerator_chirho)
        }
        PlacementAffinityKindChirho::EgressPriceCeilingChirho {
            max_micros_per_gib_chirho,
        } => {
            if *max_micros_per_gib_chirho == 0 {
                bail!("egress price ceilings must be greater than zero micros per GiB");
            }
            Ok(())
        }
    }
}

fn validate_candidate_chirho(candidate_chirho: &PlacementCandidateChirho) -> Result<()> {
    validate_safe_token_chirho("candidate", &candidate_chirho.candidate_chirho)?;
    validate_safe_token_chirho("region", &candidate_chirho.region_chirho)?;
    validate_tokens_chirho("hardware", &candidate_chirho.hardware_chirho)?;
    validate_tokens_chirho("feature", &candidate_chirho.features_chirho)?;
    validate_tokens_chirho("user cache", &candidate_chirho.user_caches_chirho)?;
    validate_tokens_chirho("model", &candidate_chirho.resident_models_chirho)?;
    validate_tokens_chirho("data region", &candidate_chirho.data_regions_chirho)?;
    validate_tokens_chirho("accelerator", &candidate_chirho.accelerators_chirho)?;
    for module_chirho in &candidate_chirho.resident_modules_chirho {
        validate_safe_token_chirho("resident module", &module_chirho.0)?;
    }
    Ok(())
}

fn validate_tokens_chirho(name_chirho: &str, values_chirho: &[String]) -> Result<()> {
    for value_chirho in values_chirho {
        validate_safe_token_chirho(name_chirho, value_chirho)?;
    }
    Ok(())
}

fn contains_str_chirho(values_chirho: &[String], needle_chirho: &str) -> bool {
    values_chirho
        .iter()
        .any(|value_chirho| value_chirho == needle_chirho)
}

fn validate_safe_token_chirho(name_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
    {
        bail!("{name_chirho} must be a short opaque token");
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    fn candidate_chirho(
        candidate_chirho: &str,
        region_chirho: &str,
        hardware_chirho: &[&str],
    ) -> PlacementCandidateChirho {
        PlacementCandidateChirho {
            candidate_chirho: candidate_chirho.to_string(),
            region_chirho: region_chirho.to_string(),
            hardware_chirho: hardware_chirho
                .iter()
                .map(|value_chirho| value_chirho.to_string())
                .collect(),
            features_chirho: vec!["wasm".to_string()],
            resident_modules_chirho: Vec::new(),
            user_caches_chirho: Vec::new(),
            resident_models_chirho: Vec::new(),
            data_regions_chirho: vec![region_chirho.to_string()],
            accelerators_chirho: hardware_chirho
                .iter()
                .map(|value_chirho| value_chirho.to_string())
                .collect(),
            egress_price_micros_per_gib_chirho: None,
        }
    }

    fn warm_gpu_descriptor_chirho() -> PlacementDescriptorChirho {
        PlacementDescriptorChirho {
            module_chirho: HashChirho("module-ignored-by-rank-chirho".to_string()),
            hard_constraints_chirho: vec![
                PlacementHardConstraintChirho::RequiredRegionChirho {
                    region_chirho: "us-east-chirho".to_string(),
                },
                PlacementHardConstraintChirho::RequiredHardwareChirho {
                    hardware_chirho: "gpu-chirho".to_string(),
                },
            ],
            affinities_chirho: vec![
                PlacementAffinityChirho {
                    kind_chirho: PlacementAffinityKindChirho::PreviousWarmLocationChirho {
                        location_chirho: "worker-a-chirho".to_string(),
                    },
                    weight_chirho: 50,
                },
                PlacementAffinityChirho {
                    kind_chirho: PlacementAffinityKindChirho::ColocateWithUserCacheChirho {
                        user_chirho: "user-7-chirho".to_string(),
                    },
                    weight_chirho: 20,
                },
                PlacementAffinityChirho {
                    kind_chirho: PlacementAffinityKindChirho::PreferredAcceleratorChirho {
                        accelerator_chirho: "gpu-chirho".to_string(),
                    },
                    weight_chirho: 5,
                },
            ],
            metadata_chirho: BTreeMap::new(),
        }
    }

    #[test]
    fn rank_prefers_warm_gpu_user_cache_and_flags_wrong_region_chirho() {
        let descriptor_chirho = warm_gpu_descriptor_chirho();
        let mut worker_a_chirho =
            candidate_chirho("worker-a-chirho", "us-east-chirho", &["gpu-chirho"]);
        worker_a_chirho
            .user_caches_chirho
            .push("user-7-chirho".to_string());
        let worker_b_chirho =
            candidate_chirho("worker-b-chirho", "us-east-chirho", &["gpu-chirho"]);
        let worker_c_chirho =
            candidate_chirho("worker-c-chirho", "eu-west-chirho", &["gpu-chirho"]);

        let rankings_chirho = rank_placement_candidates_chirho(
            &descriptor_chirho,
            &[worker_b_chirho, worker_c_chirho, worker_a_chirho],
        )
        .unwrap();

        assert_eq!(rankings_chirho[0].candidate_chirho, "worker-a-chirho");
        assert_eq!(rankings_chirho[0].score_chirho, 75);
        assert!(rankings_chirho[0].eligible_chirho);
        assert_eq!(rankings_chirho[1].candidate_chirho, "worker-b-chirho");
        assert_eq!(rankings_chirho[1].score_chirho, 5);
        assert_eq!(rankings_chirho[2].candidate_chirho, "worker-c-chirho");
        assert!(!rankings_chirho[2].eligible_chirho);
        assert!(!rankings_chirho[2].violations_chirho.is_empty());
    }

    #[test]
    fn rank_rejects_empty_and_duplicate_candidates_chirho() {
        let descriptor_chirho = warm_gpu_descriptor_chirho();
        assert!(rank_placement_candidates_chirho(&descriptor_chirho, &[]).is_err());
        let worker_chirho = candidate_chirho("worker-a-chirho", "us-east-chirho", &["gpu-chirho"]);
        assert!(rank_placement_candidates_chirho(
            &descriptor_chirho,
            &[worker_chirho.clone(), worker_chirho],
        )
        .is_err());
    }

    #[test]
    fn validate_fields_rejects_out_of_range_affinity_weight_chirho() {
        let mut descriptor_chirho = warm_gpu_descriptor_chirho();
        descriptor_chirho
            .affinities_chirho
            .push(PlacementAffinityChirho {
                kind_chirho: PlacementAffinityKindChirho::DataLocalityChirho {
                    region_chirho: "us-east-chirho".to_string(),
                },
                weight_chirho: 0,
            });
        assert!(validate_placement_descriptor_fields_chirho(&descriptor_chirho).is_err());
    }

    #[test]
    fn validate_fields_rejects_unsafe_metadata_key_chirho() {
        let mut descriptor_chirho = warm_gpu_descriptor_chirho();
        descriptor_chirho
            .metadata_chirho
            .insert("bad key with spaces".to_string(), "value".to_string());
        assert!(validate_placement_descriptor_fields_chirho(&descriptor_chirho).is_err());
    }

    #[test]
    fn validate_fields_accepts_clean_descriptor_chirho() {
        let descriptor_chirho = warm_gpu_descriptor_chirho();
        assert!(validate_placement_descriptor_fields_chirho(&descriptor_chirho).is_ok());
    }
}
