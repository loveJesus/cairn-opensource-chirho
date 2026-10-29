// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The single account-log engine and the I/O ports it needs (hexagonal: the core owns its ports; the
//! sim adapter and the real adapter implement them).
//!
//! Brick 2.0 defines the three ports (`ports_chirho`) and — in later increments — a TOY log the sim
//! and stateright models exercise, so the proof machinery is validated before the Brick 2.1 money
//! core trusts it. The toy log speaks ONLY through the ports; it never calls fs, clock, or tokio.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

pub mod admission_chirho;
#[cfg(test)]
#[path = "tests_chirho/admission_escrow_tests_chirho.rs"]
mod admission_escrow_tests_chirho;
#[cfg(test)]
#[path = "tests_chirho/admission_tests_chirho.rs"]
mod admission_tests_chirho;
pub use journal_chirho::append_mirror_chirho;
#[cfg(test)]
#[path = "tests_chirho/append_mirror_tests_chirho.rs"]
mod append_mirror_tests_chirho;
pub mod checkpoint_chirho;
pub mod effect_record_fact_chirho;
#[cfg(test)]
#[path = "tests_chirho/effect_record_fact_tests_chirho.rs"]
mod effect_record_fact_tests_chirho;
pub mod epoch_first_record_chirho;
pub mod journal_chirho;
#[cfg(test)]
#[path = "tests_chirho/journal_compensation_tests_chirho.rs"]
mod journal_compensation_tests_chirho;
mod journal_effect_chirho;
#[path = "journal_chirho/verified_prefix_state_chirho.rs"]
pub mod verified_prefix_state_chirho;
pub use cairn_effect_commit_chirho::coordinator_chirho::VerifiedEffectReceiptInventoryEntryChirho;
pub use journal_effect_chirho::EffectCompensationJournalErrorChirho;
#[cfg(test)]
#[path = "tests_chirho/frozen_losing_reader_tests_chirho.rs"]
mod frozen_losing_reader_tests_chirho;
#[cfg(test)]
#[path = "tests_chirho/journal_effect_tests_chirho.rs"]
mod journal_effect_tests_chirho;
#[cfg(test)]
#[path = "tests_chirho/journal_escrow_tests_chirho.rs"]
mod journal_escrow_tests_chirho;
mod journal_fastopen_chirho;
#[cfg(test)]
#[path = "tests_chirho/journal_rotation_tests_chirho.rs"]
mod journal_rotation_tests_chirho;
#[cfg(test)]
#[path = "tests_chirho/journal_tests_chirho.rs"]
mod journal_tests_chirho;
pub mod losing_suffix_chirho;
#[cfg(test)]
#[path = "tests_chirho/losing_suffix_tests_chirho.rs"]
mod losing_suffix_tests_chirho;
pub mod ports_chirho;
#[cfg(test)]
#[path = "tests_chirho/read_only_fastopen_tests_chirho.rs"]
mod read_only_fastopen_tests_chirho;
pub mod recompose_chirho;
#[path = "journal_chirho/recovery_mirror_chirho.rs"]
pub mod recovery_mirror_chirho;
pub mod registry_chirho;
#[cfg(test)]
#[path = "tests_chirho/registry_tests_chirho.rs"]
mod registry_tests_chirho;
pub mod segment_adapter_chirho;
pub mod toy_log_chirho;
#[cfg(test)]
#[path = "journal_chirho/verified_prefix_state_tests_chirho.rs"]
mod verified_prefix_state_tests_chirho;
