// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Offline, local-only operator authoring for signed membership-roster bundles.
//!
//! The signer is intentionally separated from `cairn-roster-config-chirho`: nodes may verify and
//! derive configuration, but they never gain roster-minting custody. Deployment procedures must
//! stage only this crate's output, never this executable or its local signing root.

pub mod roster_authoring_chirho;

#[cfg(test)]
mod roster_authoring_tests_chirho;
