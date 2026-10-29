// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The private-blob key-custody HOLDER (C5 B2): its durable store, the two private-mesh endpoints that admit a leader's custody and erasure frames, and the client a leader calls them with.
//!
//! A holder admits a frame only through the custody contract (`cairn-key-custody-chirho`): the sender
//! must be the current leader of the holder's own joined view, and a custody frame must not be covered
//! by the holder's erasure tombstones. Beyond the contract the holder keeps four durable things, all
//! private: a per-group term high-water no admission may go below, per-subject tombstones written
//! before any key is removed, each key in the root's own key-file bytes beside its binding, and a
//! per-frame erasure record fixed before anything is unlinked. It signs a receipt with the node's
//! existing key only after the state that receipt promises is durable. Composing it into the node is
//! the next brick. The leader's side is in `leader_chirho`: the store of each erasure's propagation
//! requirement and its holders' receipts (B3-a2, B3-a3-i), the engine that carries a requirement to its
//! holders (B3-a3-ii), and the attempt a caller keeps and retries by (B3-a4-i). Design and review:
//! `spec-chirho/workstream-state-chirho/item7-2c-key-custody-and-erasure-design-chirho.md`.

// Every identifier carries the Chirho suffix, so every enum's variants share that postfix by design.
#![allow(clippy::enum_variant_names)]

mod barrier_chirho;
mod holder_chirho;
mod layout_chirho;
mod private_tree_chirho;
mod refusal_chirho;
mod store_chirho;

pub mod client_chirho;
pub mod leader_chirho;
pub mod server_chirho;

#[cfg(test)]
mod tests_chirho;

pub use client_chirho::{KeyCustodyClientChirho, KeyCustodyClientErrorChirho};
pub use holder_chirho::{KeyCustodyHolderChirho, KeyCustodyHolderConfigChirho};
pub use leader_chirho::propagate_chirho::{
    propagate_erasure_requirement_chirho, retry_erasure_propagation_chirho,
    ErasureDeliveryErrorChirho, ErasureHolderOutcomeChirho, ErasureHolderSeamChirho,
    ErasureHoldersChirho, ErasureLeaderAuthorityChirho, ErasurePropagationPacingChirho,
    ErasurePropagationPolicyChirho, ErasurePropagationReportChirho, ErasurePropagationStopChirho,
};
pub use leader_chirho::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
pub use leader_chirho::store_chirho::{
    EarlierErasureChirho, ErasureAttemptChirho, ErasureAttemptIdentityChirho,
    ErasurePropagationStoreChirho, ErasureReceiptRecordedChirho, RecordRequirementRequestChirho,
    RequirementErasureChirho, RequirementStandingChirho, SubjectErasureStatusChirho,
    SubjectPropagationViewChirho, ERASURE_PROPAGATION_MAX_SUBJECT_REQUIREMENTS_CHIRHO,
    ERASURE_PROPAGATION_STORE_DIR_CHIRHO, ERASURE_PROPAGATION_STORE_LOCK_CHIRHO,
    ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO,
};
pub use refusal_chirho::{HolderRefusalChirho, HolderRefusalIdentityChirho};
pub use server_chirho::{
    key_custody_router_chirho, KEY_CUSTODY_CUSTODY_PATH_CHIRHO, KEY_CUSTODY_ERASURE_PATH_CHIRHO,
};
