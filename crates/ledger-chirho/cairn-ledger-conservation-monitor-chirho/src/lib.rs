// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Pure CF4 conservation checker over complete, verified, head-consistent ledger views.
//!
//! This crate is deliberately a leaf below projection/runtime owners. It has no storage, network,
//! clock, signer, or write capability. A read-only port supplies one complete snapshot whose
//! account rollups, local-supply allocations, and independent issuer-supply aggregates were
//! verified at the same signed checkpoint. The checker either returns bounded CONSERVED evidence
//! or a deterministic incident for the caller to sign, retain, alarm on, and use to halt admission.
//! It never rebalances money and never scans history. CONSERVED does not claim that every settlement
//! completed; settlement liveness and bilateral funding are separate CF2 gates.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

pub mod checker_chirho;
pub mod model_chirho;
pub mod ports_chirho;

pub use checker_chirho::{
    run_conservation_monitor_once_chirho, ConservationGreenEvidenceChirho,
    ConservationIncidentChirho, ConservationIncidentKindChirho, ConservationMonitorFailureChirho,
};
pub use model_chirho::{
    ConservationDomainIdChirho, ConservationHeadCoordinateChirho,
    DomainKindConservationRollupChirho, GlobalKindSupplyChirho,
    HeadConsistentConservationSnapshotChirho,
};
pub use ports_chirho::VerifiedConservationSnapshotPortChirho;

#[cfg(test)]
mod tests_chirho;
