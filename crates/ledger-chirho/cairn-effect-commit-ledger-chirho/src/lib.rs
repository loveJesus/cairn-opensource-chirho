// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The downward-only CF3 write-integration adapter.
//!
//! `cairn-effect-commit-chirho` owns provider/evidence/fsck ordering and its dumb journal trait;
//! `cairn-ledger-log-chirho` owns money admission and durable journal state. This crate joins those
//! two leaves without moving either law or creating an upward dependency.

mod adapter_chirho;
pub mod public_evidence_chirho;

pub use adapter_chirho::LedgerEffectCommitAdapterChirho;

#[cfg(test)]
mod test_support_chirho;

#[cfg(test)]
mod adapter_tests_chirho;

#[cfg(test)]
mod compensation_adapter_tests_chirho;

#[cfg(test)]
mod public_evidence_tests_chirho;
