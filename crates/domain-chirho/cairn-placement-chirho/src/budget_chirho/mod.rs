// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The prepaid test-credit budget for provisioning, and the signed events that move it.
//!
//! `infrastructure_budget_chirho` is the pure rule: reserve a priced maximum before anything is
//! provisioned, then settle or release exactly once. A settlement may use less than its reservation;
//! the remainder returns implicitly because availability subtracts settled and still-outstanding
//! amounts rather than summing terminal events. An unresolved reservation is not terminal, so no
//! terminal bound applies to it yet. That differs deliberately from the legacy credit-hold substrate,
//! whose terminal amounts must sum to its authorization. `budget_event_attestation_chirho` makes
//! budget movements EVIDENCE instead of calls — a verify-only port with no `sign_chirho`, so a caller
//! cannot author its own spend authority.
//!
//! The split is the same one this crate keeps everywhere: the rule knows no clock, no store and no
//! signature; the attestation knows no rule. Whoever holds both is the durable adapter, and it lives
//! in `cairn-tenant-placement-authority-chirho` rather than here.

pub mod budget_event_attestation_chirho;
pub mod budget_funding_attestation_chirho;
pub mod infrastructure_budget_chirho;
