// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The full lifecycle composition, driven end to end through DURABLE SIGNED EVIDENCE.
//!
//! CF8 clause 9 asks that *"one manual adapter proves provision/inspect/join/drain/retire … composition,
//! with … no new placement during drain, leadership handoff before exit, and ownership-proven
//! retirement."* Each of those rules is unit-proven in `node_lifecycle_chirho` against in-memory facts.
//! **What was never proven is that they hold when the facts come off disk**, through signed records, in
//! sequence, with each step's state derived from the log rather than handed in.
//!
//! **Naming this honestly matters more than the code.** This is a COMPOSITION PROOF, not a provider
//! adapter. It drives the sequence through the real durable stores and asserts the clause's named
//! properties at each step. It does NOT provision a machine, talk to a provider API, or prove anything
//! about a host — clause 15 explicitly disclaims live provider APIs, and a proof that quietly implied
//! otherwise would be worth less than nothing. What it establishes is that the RULES survive the trip
//! through persistence, which is the half that unit tests structurally cannot reach.
//!
//! The three exit preconditions are the reason this is worth its own module rather than another arm
//! beside the store: they are checked at RETIRE, they are asserted by the signer, and each is
//! independently sufficient to refuse. A proof that only walked the happy path would show the sequence
//! runs and say nothing about the gate at its end.

#[cfg(test)]
#[path = "lifecycle_composition_proof_tests_chirho.rs"]
mod lifecycle_composition_proof_tests_chirho;
