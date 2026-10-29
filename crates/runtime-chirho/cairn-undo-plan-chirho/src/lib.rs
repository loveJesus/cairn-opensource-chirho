// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pure, authority-inert static undo-plan contracts and derivation.
//!
//! This crate cannot load a Cairn root, sign a registry, execute an effect, mutate a store, or
//! confer production authority. Tree-build, review, deploy, and runtime activation are later
//! callers of this one canonical model.

#![allow(clippy::enum_variant_names)]

pub mod canonical_chirho;
pub mod contract_chirho;
pub mod derive_chirho;
pub mod framing_chirho;
pub mod plan_chirho;

#[cfg(test)]
mod tests_chirho;
