// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The per-account attribution and freeze record of every private-blob key, written ahead of key creation, so an account's erasure can find every key it ever made.
//!
//! R3 (account close) measured that an account's private data spans many derived subjects, that a seal
//! can succeed before the state row naming it commits, and that a retained request context can mint a
//! new subject after an erasure (gpt #28830). So the inventory cannot be read from committed state, and
//! it cannot be inferred from a leaf subject. Instead, the one key-creation chokepoint appends a signed
//! attribution row (account, subject, key id) to that account's own log BEFORE the key exists, and a
//! freeze stops every later row. An inventory is readable only once the account is frozen, so it cannot
//! grow after it is read, and it is bounded by that one account's rows. Each subject also has ONE owner,
//! claimed by its first key (`subject_owner_chirho`), so erasing any subject in an account's inventory
//! shreds only that account's keys (gpt #28915). Every operation here is
//! `_unlocked`: the caller holds `ACCOUNT_ATTRIBUTION_LOCK_CHIRHO`, whose place in the root's lock order is
//! after the subject-rights and append-log locks and before the blob-record and erasure-record locks.
//! Design: `spec-chirho/workstream-state-chirho/item7-2c-key-custody-and-erasure-design-chirho.md`.

pub mod coordinate_chirho;
pub mod coverage_debt_chirho;
pub mod record_chirho;
pub mod refusal_chirho;
pub mod store_chirho;
pub mod subject_owner_chirho;

#[cfg(test)]
mod tests_chirho;

pub use coordinate_chirho::AccountCoordinateChirho;
pub use coverage_debt_chirho::{
    coverage_debts_unlocked_chirho, CoverageDebtChirho, CoverageDebtRecordChirho,
    COVERAGE_DEBT_RECORD_SCHEMA_V1_CHIRHO,
};
pub use record_chirho::{AccountAttributionRecordChirho, AccountFreezeRecordChirho};
pub use refusal_chirho::{AccountAttributionErrorChirho, AccountAttributionRefusalChirho};
pub use store_chirho::{
    account_attribution_snapshot_unlocked_chirho, account_freeze_unlocked_chirho,
    append_account_attribution_unlocked_chirho, freeze_account_unlocked_chirho,
    frozen_account_inventory_unlocked_chirho, refuse_if_account_frozen_chirho,
    with_account_attribution_lock_chirho, AccountInventoryEntryChirho, AttributionRoleChirho,
    VerifiedAccountFreezeChirho, VerifiedAccountInventoryChirho, VerifiedAccountSnapshotChirho,
    ACCOUNT_ATTRIBUTION_DIR_CHIRHO, ACCOUNT_ATTRIBUTION_LOCK_CHIRHO,
};
pub use subject_owner_chirho::{
    admit_private_key_unlocked_chirho, subject_owner_unlocked_chirho, SubjectOwnerChirho,
    SubjectOwnerRecordChirho, SUBJECT_CLAIM_WITNESS_SCHEMA_V1_CHIRHO,
    SUBJECT_OWNER_RECORD_SCHEMA_V1_CHIRHO,
};
