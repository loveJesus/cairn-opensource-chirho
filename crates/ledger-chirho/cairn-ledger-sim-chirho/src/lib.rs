// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Deterministic simulation harness for the ledger proof machinery (Brick 2.0).
//!
//! This crate is where the proof machinery validates ITSELF before the Brick 2.1 money core trusts
//! it. It provides:
//!
//! - in-memory adapters for the three ports that inject a fault at EVERY operation — torn write,
//!   crash-between-ops, reorder, delay, clock regression/skew — under a seeded, reproducible schedule
//!   (Inc 2);
//! - a single-threaded deterministic scheduler over virtual time for the runtime port (Inc 2);
//! - eleven stateright models, exhaustive over small N: the epoch fence (A, A-real), rotation
//!   recovery (B, B-seq), credit and folded debit (C), the CF2 family (transfer, settlement, TTL,
//!   lock order), the geo authority sink/election composition (D), and deposed-fork reconciliation
//!   (GD7).
//!
//! The adapters run against the TOY log in `cairn-ledger-log-chirho`; the models are self-contained
//! state machines. Neither touches money code. Dependency direction is model <- log <- sim.
//!
//! **Every model carries a REACHABILITY FLOOR, and that is a crate invariant.** A bounded model that
//! stops exploring stays green on all of its `always` properties, so "every law holds" is worth
//! nothing on its own — the cheapest way to a green proof layer is a state space that goes nowhere.
//! Verified across the whole layer on 2026-07-25: 23 `sometimes` witnesses over all eleven models,
//! every one of them reading state, so none is satisfiable in the initial state. Confirmed by
//! observation on GD7 rather than by reading — planting a collapse reddened both the `sometimes`
//! witness and all seven of that model's mutation tests, since a collapsed space cannot reach the
//! violations they require. **A new model MUST bring at least one state-reading witness**; an
//! `always`-only model can be green while proving nothing.

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

pub mod clock_chirho;
pub mod fault_chirho;
pub mod runtime_chirho;
pub mod storage_chirho;

// Re-export the ports the sim adapters implement and the DTOs they carry, so test targets depend
// only on this harness crate.
pub use cairn_ledger_log_chirho::ports_chirho;
pub use cairn_ledger_model_chirho as model_chirho;

#[cfg(test)]
mod journal_crash_tests_chirho;

#[cfg(test)]
mod toy_log_tests_chirho;

#[cfg(test)]
#[path = "models_chirho/model_a_chirho.rs"]
mod model_a_chirho;

#[cfg(test)]
#[path = "models_chirho/model_a_real_chirho.rs"]
mod model_a_real_chirho;

#[cfg(test)]
#[path = "models_chirho/model_b_chirho.rs"]
mod model_b_chirho;

#[cfg(test)]
#[path = "models_chirho/model_b_seq_chirho.rs"]
mod model_b_seq_chirho;

#[cfg(test)]
#[path = "models_chirho/model_c_chirho.rs"]
mod model_c_chirho;

#[cfg(test)]
#[path = "models_chirho/model_cf2_transfer_chirho.rs"]
mod model_cf2_transfer_chirho;

#[cfg(test)]
#[path = "models_chirho/model_cf2_settlement_chirho.rs"]
mod model_cf2_settlement_chirho;

#[cfg(test)]
#[path = "models_chirho/model_cf2_lockorder_chirho.rs"]
mod model_cf2_lockorder_chirho;

#[cfg(test)]
#[path = "models_chirho/model_cf2_ttl_chirho.rs"]
mod model_cf2_ttl_chirho;

#[cfg(test)]
#[path = "models_chirho/model_d_geo_authority_chirho.rs"]
mod model_d_geo_authority_chirho;

#[cfg(test)]
#[path = "models_chirho/model_gd7_reconciliation_chirho.rs"]
mod model_gd7_reconciliation_chirho;

// Test infra: an in-memory `SegmentStorageChirho` proven byte-for-byte equivalent to the filesystem
// impl (fs≡mem differential over the storage-agnostic seqlog segment machinery). Test-scoped because
// the trait it implements arrives through the `cairn-seqlog-chirho` DEV-dependency. Named
// `*_tests_chirho.rs`: this is a whole-file `#[cfg(test)]`-only module, and the source-scan guard
// classifies such files by that name convention — otherwise its `tmp_root`-dir JSONL fixtures are
// misread as production log surfaces by `production_root_jsonl_log_names_chirho`.
#[cfg(test)]
mod mem_segment_storage_tests_chirho;

// B0 brick 1 (sim-scoped): the `SegmentStorageChirho`-over-`LedgerStoragePortChirho` adapter, proving
// the money-critical `derive_base_seq_chirho` drives identically through the journal's OWN storage port
// (fs ≡ ledger-port differential). Test-scoped for the same DEV-dependency reason; the production
// adapter lands in `cairn-ledger-log-chirho` at brick 2 per the ruled dependency direction. Its own
// JSONL fixture stays test-classified because its tests sit in an inline `#[cfg(test)] mod tests_chirho`
// that the source scan strips, so the file itself does not need the `*_tests_chirho.rs` name.
#[cfg(test)]
mod ledger_port_segment_adapter_chirho;
