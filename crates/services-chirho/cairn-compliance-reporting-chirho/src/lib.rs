// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Compliance and ops reporting: the outward-facing evidence surface, kept out of the privacy vault.
//!
//! This is RD5's W4 destination, organised by CAPABILITY rather than by the pillar each module
//! happened to land in. Vault, crypto-shred and privacy-log stay behind in the root's privacy ring:
//! this crate READS and VERIFIES them to build reports, and must never grow a blob-write path.

pub mod data_residency_chirho;
