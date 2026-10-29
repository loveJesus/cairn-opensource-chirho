// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Narrow authenticated transition from a deposed-fork observation to `ObservedHeld`.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::contract_chirho::Gd7ReconciliationSignerPortChirho;
use super::store_chirho::{
    Gd7ObservedHeldOutcomeChirho, Gd7ReconciliationStoreChirho, Gd7ReconciliationStoreRefusalChirho,
};
use super::winner_witness_chirho::AuthenticatedGd7DeposedForkObservationChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;

/// Persist the initial held state from independently authenticated winner and local-tail evidence.
pub fn ensure_authenticated_deposed_fork_observed_held_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    held_signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    observation_chirho: &AuthenticatedGd7DeposedForkObservationChirho,
) -> Result<Gd7ObservedHeldOutcomeChirho, Gd7ReconciliationStoreRefusalChirho> {
    let store_chirho = Gd7ReconciliationStoreChirho::new_authenticated_chirho(
        storage_chirho,
        held_signer_chirho,
        observation_chirho.identity_chirho().clone(),
        observation_chirho
            .winner_fork_witness_chirho()
            .object_digest_chirho()
            .to_owned(),
    )?;
    store_chirho.ensure_observed_held_chirho()
}
