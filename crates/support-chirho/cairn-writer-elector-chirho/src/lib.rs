// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P4 writer-election port (shadow-mode-first). It answers ONE read-only question — who is the elected
//! writer for a consistency group, and with what term (the future fence epoch) — so the fence-mint seam
//! (`with_issued_writer_fence_for_root_chirho`) can be OBSERVED against the election without changing
//! it. In shadow mode the local fence lock still mints; the elector never mints or commits. A
//! single-node baseline (here) and a raft-rs-backed impl (later) satisfy the same swappable port; the
//! authority cutover that lets the elected leader actually mint is P5, hard-gated and not in this crate.

pub mod durable_store_chirho;
pub mod elector_port_chirho;
mod lease_composition_chirho;
mod local_append_authority_chirho;
pub mod monotonic_clock_chirho;
pub mod raft_elector_chirho;
pub mod raft_wire_chirho;
pub mod shadow_canary_activation_anchor_chirho;
pub mod shadow_canary_chirho;
pub mod shadow_canary_generation_chirho;
pub mod shadow_canary_proof_chirho;

pub use local_append_authority_chirho::{
    LocalActiveHandoffAppendGenerationGuardChirho, LocalAppendAuthorityHandleChirho,
    LocalAppendAuthorityRefusalChirho, LocalAppendHandoffControlHandleChirho,
    LocalAppendHandoffGenerationGuardChirho, LocalAppendHandoffPreparationChirho,
    LocalAppendHandoffReadGenerationChirho, LocalAppendHandoffReadHandleChirho,
    LocalLeadershipGenerationGuardChirho, LocalStartupCoordinatesGuardChirho,
};

#[cfg(test)]
mod tests_chirho;
