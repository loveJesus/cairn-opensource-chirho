// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Lean, wasm-compilable foundation for cairn-chirho: model types, hashes, typed objects, refs,
//! and the storage port traits — the dep-light layer everything else builds on. (Note: cas/store/
//! refs use `std::fs`, which compiles on wasm32 but errors at runtime there; the runtime-portable
//! paths are the new port-driven ones, not these.)

// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]

pub mod cas_chirho;
pub mod clsd_chirho;
/// Reads a stored DAG's declared capabilities. Here rather than in a root pillar because it touches
/// only this crate's own types and store, and has consumers in two root pillars plus the CLI.
pub mod dag_capability_scan_chirho;
pub mod model_chirho;
pub mod object_graph_chirho;
pub mod refs_chirho;
pub mod store_chirho;

/// Brick 1 — the storage port traits (`ContentStoreChirho` + `AuditLogChirho`) that adapter
/// crates implement. A real file in this crate (not a `#[path]` share), pure + wasm-safe.
pub mod ports_chirho;
