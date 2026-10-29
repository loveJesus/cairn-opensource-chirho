// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A transport-neutral, durable-store-then-receipt mirror contract that never executes effects.
//!
//! A mirror receiver is a FOLLOWER that durably stores an inert, already-sealed closure on behalf of
//! the leader and signs a receipt. It reuses the write-relay template's per-node-key auth, roster
//! binding, term/lease binding, and signed-response spine, but its "execute" step is durable storage
//! plus a receipt — never effect execution and never re-entry into a served request path. Like the
//! relay contract, this crate has no root, filesystem, HTTP, elector, serve, or effect dependency,
//! and none of its verified wrappers grant mutation authority.
//!
//! The one reassembly trap it exists to get right is the INVERTED leadership predicate in
//! `authority_chirho`: the receiver verifies the SENDER is the current leader (never `leader_id ==
//! self`). See that module's header. The roster and leadership halves that predicate reads reach it
//! as ONE value produced by `membership_chirho::join_mirror_view_chirho`, the two-authority JOIN.

mod digest_chirho;

pub mod authority_chirho;
pub mod frame_chirho;
pub mod holder_set_chirho;
pub mod manifest_chirho;
pub mod membership_chirho;
pub mod port_chirho;
pub mod receipt_chirho;
pub mod refusal_chirho;

pub use authority_chirho::{
    verify_mirror_authority_binding_chirho, verify_mirror_finalize_authority_chirho,
    verify_mirror_prepare_authority_chirho, verify_mirror_receiver_elected_leader_chirho,
    AuthorizedMirrorFinalizeChirho, AuthorizedMirrorPrepareChirho, MirrorAuthorityFrameViewChirho,
};
pub use frame_chirho::{
    decode_and_authenticate_mirror_prepare_chirho, decode_and_verify_mirror_finalize_chirho,
    AuthenticatedMirrorPrepareChirho, FinalizeMirrorReceiptFrameInputChirho,
    FinalizeMirrorReceiptFrameV1Chirho, InlineSealedPayloadChirho,
    PrepareMirrorClosureFrameInputChirho, PrepareMirrorClosureFrameV1Chirho,
    PreparedFinalizeMirrorReceiptFrameChirho, PreparedPrepareMirrorClosureFrameChirho,
    VerifiedMirrorFinalizeChirho, VerifiedMirrorPrepareChirho, VerifiedSealedPayloadChirho,
    MIRROR_FINALIZE_FRAME_SCHEMA_V1_CHIRHO, MIRROR_FRAME_WIRE_MAX_BYTES_CHIRHO,
    MIRROR_PREPARE_FRAME_SCHEMA_V1_CHIRHO,
};
pub use holder_set_chirho::{MirrorHolderSetChirho, MirrorResidencyPolicyChirho};
pub use manifest_chirho::{
    KeyCustodyConfirmationChirho, KeyCustodyStatusChirho, LogPrefixBindingChirho,
    MirrorClosureManifestChirho, MirrorClosureManifestInputChirho, MirrorFamilyMemberChirho,
    SignedLedgerRecordMirrorMemberViewChirho, MIRROR_CLOSURE_MANIFEST_SCHEMA_V2_CHIRHO,
    PRIVATE_BLOB_ALG_CHIRHO,
};
pub use membership_chirho::{
    join_mirror_view_chirho, JoinedMirrorViewChirho, MirrorElectionObservationChirho,
    MirrorHolderChirho, MirrorLeadershipViewChirho, MirrorMembershipViewChirho,
};
pub use port_chirho::{
    MirrorHolderFailureChirho, MirrorHolderPortChirho, MirrorTransportFailureChirho,
};
pub use receipt_chirho::{
    decode_and_verify_mirror_receipt_chirho, MirrorDurableCommitClassChirho, MirrorReceiptChirho,
    MirrorReceiptInputChirho, MirrorReceiptStageChirho, PreparedMirrorReceiptChirho,
    VerifiedMirrorReceiptChirho, MIRROR_RECEIPT_SCHEMA_V1_CHIRHO,
    MIRROR_RECEIPT_WIRE_MAX_BYTES_CHIRHO,
};
pub use refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
