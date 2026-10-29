// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Dormant reversible-PostgreSQL outbound-effect substrate.
//!
//! This leaf owns canonical ref-only wires, keyed evidence coordinates, and narrow ports. It does
//! not register a blessed contract, effect coordinate, price, runtime caller, or database schema.
//! Cairn remains redb/log-first: PostgreSQL is the external world this future effect may mutate.
//! Cairn evidence carries only subject-bound private refs and keyed fingerprints; the target
//! database necessarily holds the plaintext world state it is asked to store.
//!
//! P2 activation precondition: the first runtime caller must source [`AdapterEvidenceKeyChirho`]
//! through Cairn's existing secret-store composition root, register that custody surface with
//! `ops-custody-inventory`, and land the coordinate source guard in the same atomic activation.
//! Neither this dormant leaf nor its future caller may read the key from a bare environment
//! variable or persist it in PostgreSQL.

pub mod crypto_chirho;
pub mod engine_chirho;
pub mod evidence_inventory_chirho;
pub mod model_chirho;
pub mod ports_chirho;
pub mod postgres_driver_chirho;
pub mod provider_chirho;

pub use crypto_chirho::AdapterEvidenceKeyChirho;
pub use engine_chirho::{
    apply_reversible_postgres_chirho, compensate_reversible_postgres_chirho,
    preview_reversible_postgres_compensation_chirho, query_reversible_postgres_by_key_chirho,
    query_reversible_postgres_compensation_by_key_chirho, PostgresCompensationPreviewChirho,
    PostgresCompensationQueryResultChirho, PostgresCompensationResultChirho,
    PostgresForwardQueryResultChirho, PostgresForwardResultChirho, ReversiblePostgresErrorChirho,
};
pub use evidence_inventory_chirho::{
    verified_provider_outcome_inventory_chirho, ProviderOutcomeInventoryChirho,
    ProviderOutcomeInventoryErrorChirho,
};
pub use model_chirho::{
    canonical_absence_witness_bytes_chirho, canonical_committed_decision_bytes_chirho,
    canonical_compensation_receipt_bytes_chirho, canonical_forward_receipt_bytes_chirho,
    canonical_request_bytes_chirho, parse_canonical_absence_witness_chirho,
    parse_canonical_committed_decision_chirho, parse_canonical_compensation_receipt_chirho,
    parse_canonical_forward_receipt_chirho, parse_canonical_request_chirho,
    DesiredPostgresStateChirho, EffectAbsenceDecisionChirho, ExpectedPostgresStateChirho,
    PostgresCompensationOutcomeChirho, PostgresWireErrorChirho,
    ReversiblePostgresAbsenceWitnessChirho, ReversiblePostgresCommittedDecisionChirho,
    ReversiblePostgresCompensationReceiptChirho, ReversiblePostgresEffectCoordinateChirho,
    ReversiblePostgresForwardReceiptChirho, ReversiblePostgresRequestChirho,
};
pub use postgres_driver_chirho::{
    install_reversible_postgres_schema_chirho, PostgresDatabaseChirho, PostgresTransactionChirho,
};
pub use provider_chirho::{
    postgres_provider_result_ref_chirho, PostgresRequestEvidenceErrorChirho,
    PostgresRequestEvidencePortChirho, ReversiblePostgresProviderChirho,
};

#[cfg(test)]
mod engine_tests_chirho;
#[cfg(test)]
mod provider_tests_chirho;
#[cfg(test)]
mod source_guard_tests_chirho;
