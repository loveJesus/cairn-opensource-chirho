// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Whether a migration TARGET has room for the root, decided from evidence a caller resolves rather
//! than from numbers this crate can see.
//!
//! CF8 clause 6 asks that "host-capacity/load evidence DRIVES one hosted tenant-root migration". The
//! evidence, its verifiers and the four-clause admission conjunction all already ship, in
//! `cairn-placement-chirho` and its authority store — but nothing on the migration road consulted
//! them, so the clause's first conjunct had no producer. This is the seam that lets it have one.
//!
//! **Why a port rather than a direct call, and it is a dependency fact rather than a taste.**
//! `cairn-tenant-placement-authority-chirho` already depends on THIS crate, so this crate cannot
//! depend on it back. The trait therefore speaks only in plain integers and strings: the implementer
//! lives in the placement authority crate, which already sees both sides, and the composition happens
//! at the migration operation above them. No new dependency edge in either direction.
//!
//! **The refusals are STRINGS on purpose.** The typed refusal enum lives in `cairn-placement-chirho`,
//! which is exactly the crate this one must not name; and the strings are fed to the migration
//! half-failure sanitizer, which is where a capacity refusal naming node ids and evidence coordinates
//! gets filtered before it can reach an operator response.
//!
//! **An implementer must never construct `PreliminaryMigrationHalfFailureChirho`.** That type's
//! fields are private precisely so a caller cannot place raw identifiers into operator output; the
//! conversion happens inside this crate, behind that private constructor, like every other half.
//!
//! **SCOPE, AND IT TRAVELS WITH THE CODE ON PURPOSE.** The gate takes this port as an `Option`, so a
//! caller that passes `None` SKIPS capacity admission entirely and the check still returns `Ok`. That
//! is deliberate for this brick and it means clause 6's "evidence drives" conjunct is NOT yet
//! satisfied by the existence of this file: a port with an optional parameter and a test implementer
//! proves the gate BEHAVIOUR, not that anything on the production migration road consults it. Two
//! things must follow before the conjunct is real — a production implementer that loads signed
//! capacity and usage evidence, and a composition that makes ABSENCE fail closed on that road rather
//! than skip. Until both land, read this module as a seam, never as the clause.
//!
//! Pure: no I/O and no store. The port is injected, so the gate is testable without a placement root
//! and cannot accidentally consult a global registry.

use serde::{Deserialize, Serialize};

/// Allocatable figures in the three hard capacity dimensions.
///
/// Dominance is per-dimension and there is no exchange rate between them — a surplus of memory never
/// pays for a shortage of durable bytes. This type carries the numbers only; the comparison is the
/// implementer's, and it consults the shipped conjunction rather than re-implementing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantCapacityDemandChirho {
    pub cpu_millicores_chirho: u64,
    pub memory_bytes_chirho: u64,
    pub durable_bytes_chirho: u64,
}

/// What a capacity admission decided, with the same anti-vacuity rule the other halves carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantCapacityAdmissionVerdictChirho {
    /// How many admission clauses were actually decided over STORED evidence.
    pub considered_chirho: usize,
    /// Every reason the target was refused; empty means admit. Sanitized downstream, never here.
    pub refusals_chirho: Vec<String>,
    /// A digest over the admission INPUTS — target node, evidence heads, demand, headroom, authority
    /// key ids. Carried so a later brick can persist it as an ordinary request coordinate and
    /// RE-VERIFY it at activation; an admission that is merely observed at begin does not drive
    /// anything. Nothing in this crate consumes it yet, and that is named debt rather than a field
    /// looking for a purpose.
    pub evidence_identity_chirho: String,
}

impl TenantCapacityAdmissionVerdictChirho {
    /// Admitted AND at least one clause actually decided over stored evidence.
    ///
    /// A target that offered no capacity evidence has not been CHECKED, which is a different thing
    /// from having been found sufficient — and it is the reading the obvious implementation gets
    /// wrong, because an empty refusal list looks like a pass. Every other half in this gate carries
    /// this same guard for the same reason.
    /// **WHAT THIS GUARD DOES NOT CATCH, measured by claude_chirho 2026-08-21.** It stops an EMPTY
    /// verdict reading as sufficiency. It cannot stop a verdict that considered its clauses over a
    /// registry nobody populated: `record_placement_chirho` has **zero production callers**, so
    /// reserved capacity derives as zero for every node and the admission arithmetic runs against a
    /// world that looks completely free. That verdict would arrive here with `considered_chirho > 0`
    /// and an empty refusal list — **non-vacuous and wrong**, which is the harder failure to see.
    /// Whoever writes the production implementer owes a population source, not just a loader; this
    /// guard is necessary and is nowhere near sufficient.
    pub fn is_admitted_over_evidence_chirho(&self) -> bool {
        self.refusals_chirho.is_empty() && self.considered_chirho > 0
    }
}

/// Answers whether a target node is admitted to hold a tenant root of this size.
pub trait TenantCapacityAdmissionPortChirho: Send + Sync {
    /// Decide admission for `target_node_id_chirho` against `demand_chirho` plus `headroom_chirho`.
    ///
    /// Implementers load signed capacity and usage evidence and CONSULT the placement registry's
    /// admission conjunction; they do not re-implement it, and they do not decide anything this
    /// crate could have decided from its own inputs.
    fn admit_target_chirho(
        &self,
        target_node_id_chirho: &str,
        demand_chirho: &TenantCapacityDemandChirho,
        headroom_chirho: &TenantCapacityDemandChirho,
    ) -> TenantCapacityAdmissionVerdictChirho;
}

#[cfg(test)]
#[path = "capacity_admission_tests_chirho.rs"]
mod capacity_admission_tests_chirho;
