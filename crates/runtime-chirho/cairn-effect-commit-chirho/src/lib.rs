// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Synchronous CF3 effect-commit law.
//!
//! The crate is a focused runtime leaf. It owns no ambient filesystem, network, clock, key, or
//! projection authority. The composition root injects those boundaries; this crate supplies the
//! canonical signed intent whose content identity becomes the reserved ledger idempotency key,
//! the one-coordinate signed terminal outcome, and the synchronous provider/fsck coordinator.

pub mod compensation_chirho;
pub mod coordinator_chirho;
pub mod intent_chirho;
pub mod minimal_warrant_chirho;
pub mod terminal_chirho;

#[cfg(test)]
mod coordinator_tests_chirho;

#[cfg(test)]
mod intent_tests_chirho;

#[cfg(test)]
mod minimal_warrant_tests_chirho;

#[cfg(test)]
mod terminal_tests_chirho;
