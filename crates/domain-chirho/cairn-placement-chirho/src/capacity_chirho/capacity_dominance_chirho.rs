// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A stronger replacement node is one that DOMINATES in every hard capacity dimension — never one
//! that wins on an opaque score.
//!
//! CF8 acceptance, verbatim: *"a stronger replacement node is defined by numeric dominance across
//! allocatable CPU, memory, and durable bytes, optionally filtered by hardware/features, never by an
//! opaque scalar strength score; network/egress remains a priced affinity for CF8 rather than an
//! unmeasured hard capacity dimension."*
//!
//! Three design commitments follow from that sentence, and each is pinned by a test:
//!
//! 1. **Dominance, not a sum.** Every dimension must be met independently. A candidate with triple
//!    the CPU and one byte too little memory is NOT a replacement. This is what makes the rule
//!    unable to collapse into a score — there is no exchange rate between millicores and bytes, so a
//!    surplus in one dimension can never pay for a deficit in another.
//! 2. **No opaque scalar anywhere in the API.** The refusal type names the failing dimension and
//!    both numbers, so a caller can explain a rejection and an operator can act on it. A function
//!    returning `bool`, or worse a `strength: f64`, would satisfy the arithmetic while losing exactly
//!    the property the criterion is about.
//! 3. **Features FILTER, they do not score.** Hardware/features are set containment — you have the
//!    GPU or you do not. They are deliberately not a fourth number.
//!
//! **A DELIBERATE ABSENCE:** there is no network or egress field in
//! [`AllocatableCapacityChirho`]. The criterion is explicit that network/egress stays a *priced
//! affinity* (see the affinity types in this crate's root) rather than an unmeasured hard capacity
//! dimension — cairn does not measure it, so promoting it to a hard gate would be a number nobody
//! can verify. Adding it here would silently widen the criterion.
//!
//! Pure: no I/O, no store, no authority. Every value is supplied by the caller.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Allocatable capacity in the three HARD dimensions, in the units CF8 names. These are the same
/// units placement demand uses, so a demand and an allocation are directly comparable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocatableCapacityChirho {
    /// CPU, in millicores (1000 = one core).
    pub cpu_millicores_chirho: u64,
    /// Active memory, in bytes.
    pub memory_bytes_chirho: u64,
    /// Durable storage, in bytes.
    pub durable_bytes_chirho: u64,
}

/// The hard dimension a candidate fell short in. Named rather than scored, so a refusal is
/// explainable and actionable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapacityDimensionChirho {
    CpuMillicoresChirho,
    MemoryBytesChirho,
    DurableBytesChirho,
}

impl CapacityDimensionChirho {
    /// The dimension's name and unit, for operator-facing refusal text.
    pub fn label_chirho(&self) -> &'static str {
        match self {
            Self::CpuMillicoresChirho => "cpu-millicores-chirho",
            Self::MemoryBytesChirho => "memory-bytes-chirho",
            Self::DurableBytesChirho => "durable-bytes-chirho",
        }
    }
}

/// One reason a candidate is not a valid replacement. Every variant carries the numbers, so nothing
/// downstream needs to re-derive them — and no caller is tempted to invent a scalar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplacementRefusalChirho {
    /// The candidate offers less than the incumbent in a hard dimension.
    DimensionShortfallChirho {
        dimension_chirho: CapacityDimensionChirho,
        incumbent_chirho: u64,
        candidate_chirho: u64,
    },
    /// A required hardware/feature label the candidate does not carry.
    MissingRequiredFeatureChirho { feature_chirho: String },
}

impl AllocatableCapacityChirho {
    /// This capacity's value in one dimension.
    pub fn in_dimension_chirho(&self, dimension_chirho: CapacityDimensionChirho) -> u64 {
        match dimension_chirho {
            CapacityDimensionChirho::CpuMillicoresChirho => self.cpu_millicores_chirho,
            CapacityDimensionChirho::MemoryBytesChirho => self.memory_bytes_chirho,
            CapacityDimensionChirho::DurableBytesChirho => self.durable_bytes_chirho,
        }
    }
}

/// Every hard dimension, in a fixed order so refusals are deterministic.
pub const CAPACITY_DIMENSIONS_CHIRHO: [CapacityDimensionChirho; 3] = [
    CapacityDimensionChirho::CpuMillicoresChirho,
    CapacityDimensionChirho::MemoryBytesChirho,
    CapacityDimensionChirho::DurableBytesChirho,
];

/// Is `candidate` a valid stronger replacement for `incumbent`?
///
/// Returns every reason it is not, in deterministic order — an empty vector means it dominates.
/// Dominance is `>=` in **all three** dimensions plus containment of `required_features_chirho`;
/// there is deliberately no way to express "better overall".
pub fn replacement_refusals_chirho(
    incumbent_chirho: &AllocatableCapacityChirho,
    candidate_chirho: &AllocatableCapacityChirho,
    incumbent_features_chirho: &BTreeSet<String>,
    candidate_features_chirho: &BTreeSet<String>,
) -> Vec<ReplacementRefusalChirho> {
    let mut refusals_chirho = Vec::new();
    for dimension_chirho in CAPACITY_DIMENSIONS_CHIRHO {
        let incumbent_value_chirho = incumbent_chirho.in_dimension_chirho(dimension_chirho);
        let candidate_value_chirho = candidate_chirho.in_dimension_chirho(dimension_chirho);
        if candidate_value_chirho < incumbent_value_chirho {
            refusals_chirho.push(ReplacementRefusalChirho::DimensionShortfallChirho {
                dimension_chirho,
                incumbent_chirho: incumbent_value_chirho,
                candidate_chirho: candidate_value_chirho,
            });
        }
    }
    // Features filter; they never offset a numeric shortfall.
    for feature_chirho in incumbent_features_chirho {
        if !candidate_features_chirho.contains(feature_chirho) {
            refusals_chirho.push(ReplacementRefusalChirho::MissingRequiredFeatureChirho {
                feature_chirho: feature_chirho.clone(),
            });
        }
    }
    refusals_chirho
}

/// Convenience predicate over [`replacement_refusals_chirho`]. The refusal list stays the primary
/// API precisely because a bare `bool` is where an opaque score starts.
pub fn replacement_dominates_chirho(
    incumbent_chirho: &AllocatableCapacityChirho,
    candidate_chirho: &AllocatableCapacityChirho,
    incumbent_features_chirho: &BTreeSet<String>,
    candidate_features_chirho: &BTreeSet<String>,
) -> bool {
    replacement_refusals_chirho(
        incumbent_chirho,
        candidate_chirho,
        incumbent_features_chirho,
        candidate_features_chirho,
    )
    .is_empty()
}

#[cfg(test)]
#[path = "capacity_dominance_tests_chirho.rs"]
mod capacity_dominance_tests_chirho;
