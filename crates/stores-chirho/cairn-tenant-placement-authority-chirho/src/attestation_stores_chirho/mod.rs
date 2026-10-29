// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable stores of signed evidence a node's placement authority is built from.
//!
//! Most stores share one shape: verify the signature, refuse or classify against durable state the
//! stateless verifiers cannot keep, store the intent in the payload CAS at its declared digest, then
//! append. Tenant moves deliberately differ: complete signed move records live in a dedicated bounded
//! control namespace outside the payload commitment, so the carried-surface evidence cannot contain
//! the signed row whose bytes contain that commitment.
//!
//! The original three placement feeds differ in the RULE each applies to its own history:
//!
//! ```text
//! capacity    registrar-signed  replay REFUSED at or below the high-water registration seq
//! lifecycle   authority-signed  replay refused by seq AND a stale view refused by from-state
//! usage       NODE-signed       a stale report is RECORDED and FREEZES -- never refused
//! placement   authority-signed  ANY chain defect refuses the WHOLE POPULATION -- never skipped
//! ```
//!
//! The fourth breaks the capacity store's skip-a-bad-row precedent ON PURPOSE: a skipped placement is
//! a MISSING RESERVATION, and a registry that silently under-counts manufactures free capacity. Its
//! own header carries the argument.
//!
//! The third breaks the pattern deliberately, and its own header explains why refusing there would
//! leave a node that can no longer be seen looking healthy.
//!
//! One growth note, because the identical shape invites the assumption it was considered for all
//! three: capacity rows are per-registration and lifecycle rows are bounded by the state machine, so
//! only the usage log grows without a natural ceiling. Each read is a full scan under a byte cap.

pub mod budget_event_store_chirho;
pub mod capacity_admission_expectation_chirho;
pub mod capacity_attestation_store_chirho;
pub mod lifecycle_transition_store_chirho;
pub mod move_control_store_chirho;
pub mod placement_record_store_chirho;
pub mod tenant_move_store_chirho;
pub mod usage_measurement_store_chirho;
