// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The store side of topology: where a desired-state plan LIVES, and how a signed reference to one is
//! proven to name something real.
//!
//! `plan_reference_chirho` is pure and stays pure — it defines the four-outcome resolver port and the
//! verifier that re-hashes whatever a resolver returns. `plan_store_chirho` is the root-backed half:
//! it writes plans and implements that port, which is exactly the reach the pure module's own header
//! says belongs to an implementor rather than to it.

pub mod grant_store_chirho;
pub mod manual_adapter_chirho;
pub mod plan_authority_report_chirho;
pub mod plan_reference_chirho;
pub mod plan_store_chirho;
