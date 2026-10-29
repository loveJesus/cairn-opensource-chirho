// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The transport-neutral contract for copying private-blob keys to placement holders and erasing them there (item 7.2c, C5).
//!
//! A key never travels the data mirror. It travels only here, wrapped to one holder's custody key and
//! bound to one group, membership view, elected term, sending leader, holder and exact blob. A holder
//! admits a custody or erasure frame through the MIRROR's own authority check (the sender is the current
//! leader of the holder's own joined view, never "am I leader"), refuses a key its erasure tombstones
//! already cover, signs a custody receipt only after the key is durably stored, and signs an erasure
//! receipt only after its tombstones are durable and the keys are gone. Custody of a key is confirmed
//! only when both other serving holders signed for exactly that key, and a subject's erasure is complete
//! only when every holder its custody evidence names has closed its share. Design and review findings:
//! `spec-chirho/workstream-state-chirho/item7-2c-key-custody-and-erasure-design-chirho.md`.
//!
//! This crate has no root, filesystem, network, elector-driving or effect dependency; it reads the
//! mirror's joined view and the elector's clock trait only. Refusals carry fixed sentences: no key,
//! subject or ciphertext ever reaches an error.

mod digest_chirho;

pub mod custody_chirho;
pub mod custody_key_chirho;
pub mod erasure_chirho;
pub mod refusal_chirho;

#[cfg(test)]
mod tests_chirho;

pub use custody_chirho::binding_chirho::{subject_digest_hex_chirho, CustodyBindingChirho};
pub use custody_chirho::frame_chirho::{
    authorize_custody_frame_chirho, decode_and_authenticate_custody_frame_chirho,
    AuthenticatedCustodyFrameChirho, AuthorizedCustodyFrameChirho, CustodyFrameV1Chirho,
    OpenedCustodyKeyChirho, PreparedCustodyFrameChirho, CUSTODY_FRAME_SCHEMA_V1_CHIRHO,
    KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO,
};
pub use custody_chirho::receipt_chirho::{
    confirm_key_custody_chirho, decode_and_verify_custody_receipt_chirho,
    CustodyKeyCoordinatesChirho, CustodyReceiptV1Chirho, KeyCustodyConfirmedChirho,
    PreparedCustodyReceiptChirho, VerifiedCustodyReceiptChirho, CUSTODY_RECEIPT_SCHEMA_V1_CHIRHO,
};
pub use custody_chirho::wrap_chirho::{
    seal_wrapped_key_chirho, ShredKeyRecordChirho, WrappedKeyPayloadChirho,
};
pub use custody_key_chirho::{
    CustodyAnnouncementV1Chirho, NodeCustodySecretChirho, PreparedCustodyAnnouncementChirho,
    VerifiedCustodyAnnouncementChirho, CUSTODY_ANNOUNCEMENT_SCHEMA_V1_CHIRHO,
    CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO,
};
pub use digest_chirho::ERASURE_MAX_KEY_IDS_CHIRHO;
pub use erasure_chirho::decommission_chirho::{
    DecommissionAttestationV1Chirho, PreparedDecommissionAttestationChirho,
    VerifiedDecommissionAttestationChirho, DECOMMISSION_ATTESTATION_SCHEMA_V1_CHIRHO,
};
pub use erasure_chirho::frame_chirho::{
    authorize_erasure_frame_chirho, decode_and_authenticate_erasure_frame_chirho,
    AuthenticatedErasureFrameChirho, AuthorizedErasureFrameChirho, ErasureFrameInputChirho,
    ErasureFrameV1Chirho, PreparedErasureFrameChirho, ERASURE_FRAME_SCHEMA_V1_CHIRHO,
    ERASURE_WIRE_MAX_BYTES_CHIRHO,
};
pub use erasure_chirho::propagation_chirho::{
    ErasurePropagationBindingV1Chirho, ErasurePropagationContextChirho,
    ErasurePropagationRefChirho, ErasurePropagationRequirementInputChirho,
    ErasurePropagationRequirementV1Chirho, PreparedErasurePropagationBindingChirho,
    PreparedErasurePropagationRequirementChirho, VerifiedErasurePropagationBindingChirho,
    VerifiedErasurePropagationRequirementChirho, ERASURE_PROPAGATION_BINDING_SCHEMA_V1_CHIRHO,
    ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO, ERASURE_PROPAGATION_MAX_HOLDERS_CHIRHO,
    ERASURE_PROPAGATION_MAX_SUCCEEDS_CHIRHO, ERASURE_PROPAGATION_REQUIREMENT_SCHEMA_V1_CHIRHO,
};
pub use erasure_chirho::receipt_chirho::{
    decode_and_verify_erasure_receipt_chirho, verify_erasure_receipt_answers_frame_chirho,
    ErasureReceiptV1Chirho, PreparedErasureReceiptChirho, VerifiedErasureReceiptChirho,
    ERASURE_RECEIPT_SCHEMA_V1_CHIRHO,
};
pub use erasure_chirho::status_chirho::{
    erasure_status_chirho, ErasureRequirementChirho, ErasureStatusChirho,
};
pub use erasure_chirho::tombstone_chirho::HolderTombstonesChirho;
pub use refusal_chirho::{KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho};
