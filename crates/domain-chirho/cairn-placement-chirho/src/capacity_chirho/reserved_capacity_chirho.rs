// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reserved capacity is DERIVED from placed demands — never reported, never accumulated.
//!
//! CF8 keeps three capacity sources distinct, and this module owns exactly one of them:
//!
//! | source | where it comes from | owned here |
//! |---|---|---|
//! | **allocatable** | signed at node registration | no — it is an input |
//! | **reserved** | *deterministically derived from placed demands in the registry* | **yes** |
//! | **measured usage** | node-signed with HLC and monotone sequence | no — it is an input |
//!
//! Keeping them distinct is the point. A node that *reports* its own reserved figure could drift
//! from, or lie about, what is actually placed on it; deriving it from the registry means reserved
//! is a **function of decisions cairn already made**, recomputable by anyone holding the registry.
//! So this module deliberately offers no way to set a reserved value — only to derive one.
//!
//! Two arithmetic commitments, each pinned by a test:
//!
//! 1. **Saturating, never wrapping.** A hostile or corrupt registry row must not be able to make a
//!    sum wrap to a small number and manufacture free capacity. Saturation fails toward "full",
//!    which refuses admission — the safe direction.
//! 2. **Order-independent.** Reserved must not depend on registry iteration order, or two honest
//!    nodes could derive different figures from the same facts.
//!
//! Admission keeps reservation and measurement distinct, then uses their componentwise maximum as
//! occupied capacity. Adding them would double-count ordinary placement load; trusting only reserved
//! would ignore untracked host load, and trusting only measured usage would discard accepted placement
//! obligations. The maximum fails closed in either direction without collapsing the two sources.
//!
//! Admission then requires **headroom**: free capacity must cover the new demand *plus* a configured
//! margin, per dimension, with the same no-exchange-rate rule as
//! [`super::capacity_dominance_chirho`] — a surplus of memory never pays for a shortage of CPU.
//!
//! Pure: no I/O, no store, no authority, no clock. Freshness and signature checks on the *other* two
//! sources belong to the caller; this module never sees them.

use super::capacity_dominance_chirho::{
    AllocatableCapacityChirho, CapacityDimensionChirho, CAPACITY_DIMENSIONS_CHIRHO,
};
use serde::{Deserialize, Serialize};

/// One placement's reservation on a node, in the same units as allocatable capacity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacedDemandChirho {
    pub placement_id_chirho: String,
    pub demand_chirho: AllocatableCapacityChirho,
}

/// Why a placement cannot be admitted to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionRefusalChirho {
    /// Free capacity does not cover the demand plus the configured headroom in this dimension.
    InsufficientFreeCapacityChirho {
        dimension_chirho: CapacityDimensionChirho,
        /// allocatable − reserved, saturating at zero.
        free_chirho: u64,
        demand_chirho: u64,
        headroom_chirho: u64,
    },
}

/// Sum the placed demands. Saturating so a corrupt registry cannot wrap a dimension into looking
/// empty; order-independent so two holders of the same registry derive the same figure.
pub fn derive_reserved_capacity_chirho(
    placed_chirho: &[PlacedDemandChirho],
) -> AllocatableCapacityChirho {
    placed_chirho.iter().fold(
        AllocatableCapacityChirho {
            cpu_millicores_chirho: 0,
            memory_bytes_chirho: 0,
            durable_bytes_chirho: 0,
        },
        |acc_chirho, placed_chirho| AllocatableCapacityChirho {
            cpu_millicores_chirho: acc_chirho
                .cpu_millicores_chirho
                .saturating_add(placed_chirho.demand_chirho.cpu_millicores_chirho),
            memory_bytes_chirho: acc_chirho
                .memory_bytes_chirho
                .saturating_add(placed_chirho.demand_chirho.memory_bytes_chirho),
            durable_bytes_chirho: acc_chirho
                .durable_bytes_chirho
                .saturating_add(placed_chirho.demand_chirho.durable_bytes_chirho),
        },
    )
}

/// Conservative occupied capacity from the two independent usage signals.
///
/// The values remain separately inspectable; this function only selects the larger value in each
/// dimension for admission arithmetic. A high real measurement therefore cannot be hidden by a low
/// reservation, while an under-reported measurement cannot erase signed placement obligations.
pub fn effective_occupied_capacity_chirho(
    reserved_chirho: &AllocatableCapacityChirho,
    observed_usage_chirho: &AllocatableCapacityChirho,
) -> AllocatableCapacityChirho {
    AllocatableCapacityChirho {
        cpu_millicores_chirho: reserved_chirho
            .cpu_millicores_chirho
            .max(observed_usage_chirho.cpu_millicores_chirho),
        memory_bytes_chirho: reserved_chirho
            .memory_bytes_chirho
            .max(observed_usage_chirho.memory_bytes_chirho),
        durable_bytes_chirho: reserved_chirho
            .durable_bytes_chirho
            .max(observed_usage_chirho.durable_bytes_chirho),
    }
}

/// Free capacity in one dimension: allocatable − reserved, saturating at zero. Over-reservation
/// (reserved above allocatable, which a shrunk node can produce) reads as zero free, not as a huge
/// number — the safe direction.
pub fn free_in_dimension_chirho(
    allocatable_chirho: &AllocatableCapacityChirho,
    reserved_chirho: &AllocatableCapacityChirho,
    dimension_chirho: CapacityDimensionChirho,
) -> u64 {
    allocatable_chirho
        .in_dimension_chirho(dimension_chirho)
        .saturating_sub(reserved_chirho.in_dimension_chirho(dimension_chirho))
}

/// Every reason this demand cannot be admitted; empty means admissible.
///
/// Requires `free >= demand + headroom` in **each** dimension independently. The demand-plus-headroom
/// sum saturates, so an absurd headroom refuses rather than wrapping into acceptance.
pub fn admission_refusals_chirho(
    allocatable_chirho: &AllocatableCapacityChirho,
    reserved_chirho: &AllocatableCapacityChirho,
    demand_chirho: &AllocatableCapacityChirho,
    headroom_chirho: &AllocatableCapacityChirho,
) -> Vec<AdmissionRefusalChirho> {
    let mut refusals_chirho = Vec::new();
    for dimension_chirho in CAPACITY_DIMENSIONS_CHIRHO {
        let free_value_chirho =
            free_in_dimension_chirho(allocatable_chirho, reserved_chirho, dimension_chirho);
        let demand_value_chirho = demand_chirho.in_dimension_chirho(dimension_chirho);
        let headroom_value_chirho = headroom_chirho.in_dimension_chirho(dimension_chirho);
        let required_chirho = demand_value_chirho.saturating_add(headroom_value_chirho);
        if free_value_chirho < required_chirho {
            refusals_chirho.push(AdmissionRefusalChirho::InsufficientFreeCapacityChirho {
                dimension_chirho,
                free_chirho: free_value_chirho,
                demand_chirho: demand_value_chirho,
                headroom_chirho: headroom_value_chirho,
            });
        }
    }
    refusals_chirho
}

#[cfg(test)]
#[path = "reserved_capacity_tests_chirho.rs"]
mod reserved_capacity_tests_chirho;
