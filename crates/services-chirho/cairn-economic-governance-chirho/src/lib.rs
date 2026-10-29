// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Port-driven economic and governance orchestration.
//!
//! This crate is the Phase-2 extraction home for policy/config and governance sequencing. It does
//! not own root-authority implementations such as signing keys, app ownership, ledger mutation, or
//! money-effect execution. Its signing, app-owner, and identity dependencies use narrow ports;
//! caller-specified legacy-ledger postings are intentionally not exposed through this crate.

pub mod billing_policy_chirho;
pub mod ports_chirho;
pub mod pricebook_policy_chirho;
pub mod resource_policy_chirho;
