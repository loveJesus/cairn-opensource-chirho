// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The CF7 §1 COMPOSITION ROOT for the ledger read substrate — one focused leaf that wires
//! journals, the config chains (projection + source registries), feeder roots, publication, and
//! serving into a composable surface. Root `cairn-chirho` later consumes THIS crate (the
//! thin-composition true north); nothing here reaches upward.
//!
//! THE AUTHORITY LAW (#4972b + the P1/CF3 custody ruling): distinct KEY IDENTITIES — the journal
//! root, the CONFIG root (projection + source registries), the FEEDER root, and (when the F3a
//! x-cluster seam is wired) per-money-group SOURCE roots — each an injected
//! `LedgerSignerPortChirho` instance whose signatures never verify under another identity
//! (pairwise-pinned in tests). KEY SOURCING: the crate accepts INJECTED signer instances only —
//! it never reads env, never loads key files, never persists key material; real keys arrive from
//! the secret-store composition path, and the custody tripwire (ops-custody-inventory rows +
//! source guards) rides the first REAL-KEY caller's commit per the dormant-P1 pattern. Until
//! then, every composition here is fake-signer-only by construction.
//!
//! F3a WIRING SEAM (claude #5079): `open_journal_chirho` composes the finality views when
//! present; an UN-wired composition keeps the counterpart row ExplicitlyUnsupported (law v — the
//! seam's absence refuses, never default-opens). Merge-projection composition follows the same
//! seam shape and is an explicitly deferred increment, not an accident.

pub mod composition_chirho;

pub use cairn_ledger_read_model_chirho::serving_chirho::{
    FollowerServeOutcomeChirho, ServeGateRefusalChirho,
};
pub use cairn_ledger_read_model_chirho::{
    FollowerReadRefusalChirho, ProjectionCostClassChirho, ProjectionReadOutcomeChirho,
    ProjectionWatermarkChirho, PublishedProjectionViewChirho,
};
pub use composition_chirho::{
    ComposedProjectionReadChirho, LedgerReadCompositionChirho, LedgerWriteCompositionChirho,
};
