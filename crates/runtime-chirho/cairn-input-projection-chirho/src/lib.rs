// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Pure, authority-inert input-projection contracts.
//!
//! Packet 2 adds standalone projection mechanics only. Nothing in this crate can load a cairn root,
//! mutate `NodeDefChirho` or `RunKeyChirho`, invoke a runner, or confer runtime authority.

pub mod attestation_chirho;
pub mod contract_chirho;
pub mod coordinate_chirho;
pub mod field_graph_chirho;
pub mod materialize_chirho;
pub mod path_chirho;

#[cfg(test)]
mod tests_chirho;
