// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader-signed erasure frame that tells one holder to erase a subject's keys, and the rule that says which stored keys it covers.
//!
//! A frame names its keys two ways, and a holder erases the union: every key id it lists, and every
//! stored key whose subject is the frame's subject and whose blob seq is at or below the frame's
//! `erased_below_blob_seq_chirho`. The id list alone is not enough, because a leader that lost its
//! own key files in a crashed earlier attempt lists nothing on retry (agy R-C5-3); the subject rule
//! alone is not enough either, because without the seq bound a delayed erasure frame would also erase
//! a key for a blob the subject created AFTER the erasure. The bound is EXCLUSIVE, the blob log's length
//! when the subject was erased: blob seqs start at 0, so an inclusive bound could not say that no blob
//! existed yet, and an erasure of an empty log would tombstone the subject's first later blob. The frame is admitted by the mirror's own
//! authority check, exactly like a custody frame: only the current leader of the holder's exact view
//! may erase.

use crate::custody_chirho::binding_chirho::CustodyBindingChirho;
use crate::digest_chirho::{
    decode_hex_32_chirho, key_id_list_chirho, update_digest_field_chirho,
    update_key_ids_field_chirho, update_lease_field_chirho, valid_key_id_list_chirho,
    valid_lower_hex_chirho, validate_signature_hex_chirho, verify_node_signature_chirho,
    DIGEST_HEX_BYTES_CHIRHO, NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use cairn_mirror_chirho::{
    verify_mirror_authority_binding_chirho, JoinedMirrorViewChirho, MirrorAuthorityFrameViewChirho,
};
use cairn_writer_elector_chirho::monotonic_clock_chirho::MonotonicClockChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::num::NonZeroU64;

pub const ERASURE_FRAME_SCHEMA_V1_CHIRHO: &str = "key-erasure-frame-v1-chirho";
/// 4096 listed ids of 32 hex characters each, plus the fixed fields, fits well inside this.
pub const ERASURE_WIRE_MAX_BYTES_CHIRHO: usize = 512 * 1024;
const ERASURE_FRAME_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-erasure-frame-v1-chirho";

/// What a leader asks one holder to erase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureFrameInputChirho {
    pub consistency_group_digest_chirho: String,
    pub membership_view_digest_chirho: String,
    pub elected_term_chirho: u64,
    pub origin_node_id_chirho: String,
    pub holder_node_id_chirho: String,
    pub leader_lease_remaining_millis_chirho: Option<u64>,
    pub subject_digest_chirho: String,
    pub erased_below_blob_seq_chirho: u64,
    pub key_ids_chirho: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureFrameV1Chirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    membership_view_digest_chirho: String,
    elected_term_chirho: u64,
    origin_node_id_chirho: String,
    holder_node_id_chirho: String,
    leader_lease_remaining_millis_chirho: Option<u64>,
    subject_digest_chirho: String,
    erased_below_blob_seq_chirho: u64,
    key_ids_chirho: Vec<String>,
    frame_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedErasureFrameChirho {
    frame_chirho: ErasureFrameV1Chirho,
}

impl PreparedErasureFrameChirho {
    pub fn new_chirho(
        input_chirho: ErasureFrameInputChirho,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let mut frame_chirho = ErasureFrameV1Chirho {
            schema_chirho: ERASURE_FRAME_SCHEMA_V1_CHIRHO.to_string(),
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
            elected_term_chirho: input_chirho.elected_term_chirho,
            origin_node_id_chirho: input_chirho.origin_node_id_chirho,
            holder_node_id_chirho: input_chirho.holder_node_id_chirho,
            leader_lease_remaining_millis_chirho: input_chirho.leader_lease_remaining_millis_chirho,
            subject_digest_chirho: input_chirho.subject_digest_chirho,
            erased_below_blob_seq_chirho: input_chirho.erased_below_blob_seq_chirho,
            key_ids_chirho: key_id_list_chirho(&input_chirho.key_ids_chirho),
            frame_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_erasure_frame_chirho(&frame_chirho)?;
        frame_chirho.frame_digest_chirho = erasure_frame_digest_hex_chirho(&frame_chirho);
        Ok(Self { frame_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.frame_chirho.frame_digest_chirho)
            .expect("a prepared erasure frame always carries a validated digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<ErasureFrameV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::ErasureFrameInvalidChirho,
        )?;
        self.frame_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.frame_chirho)
    }
}

impl ErasureFrameV1Chirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, KeyCustodyErrorChirho> {
        let bytes_chirho = serde_json::to_vec(self).map_err(|_| erasure_wire_invalid_chirho())?;
        if bytes_chirho.len() > ERASURE_WIRE_MAX_BYTES_CHIRHO {
            return Err(erasure_wire_invalid_chirho());
        }
        Ok(bytes_chirho)
    }

    pub fn frame_digest_chirho(&self) -> &str {
        &self.frame_digest_chirho
    }
}

/// An erasure frame whose digest binds its fields and whose sender's node key signed it.
#[derive(Debug)]
pub struct AuthenticatedErasureFrameChirho {
    frame_chirho: ErasureFrameV1Chirho,
}

impl MirrorAuthorityFrameViewChirho for AuthenticatedErasureFrameChirho {
    fn origin_node_id_chirho(&self) -> &str {
        &self.frame_chirho.origin_node_id_chirho
    }

    fn target_node_id_chirho(&self) -> &str {
        &self.frame_chirho.holder_node_id_chirho
    }

    fn consistency_group_digest_chirho(&self) -> &str {
        &self.frame_chirho.consistency_group_digest_chirho
    }

    fn membership_view_digest_chirho(&self) -> &str {
        &self.frame_chirho.membership_view_digest_chirho
    }

    fn expected_term_chirho(&self) -> u64 {
        self.frame_chirho.elected_term_chirho
    }

    fn leader_lease_remaining_millis_chirho(&self) -> Option<u64> {
        self.frame_chirho.leader_lease_remaining_millis_chirho
    }
}

pub fn decode_and_authenticate_erasure_frame_chirho(
    wire_bytes_chirho: &[u8],
) -> Result<AuthenticatedErasureFrameChirho, KeyCustodyErrorChirho> {
    if wire_bytes_chirho.len() > ERASURE_WIRE_MAX_BYTES_CHIRHO {
        return Err(erasure_wire_invalid_chirho());
    }
    let frame_chirho: ErasureFrameV1Chirho =
        serde_json::from_slice(wire_bytes_chirho).map_err(|_| erasure_wire_invalid_chirho())?;
    validate_erasure_frame_chirho(&frame_chirho)?;
    let invalid_chirho = KeyCustodyRefusalIdentityChirho::ErasureFrameInvalidChirho;
    if frame_chirho.frame_digest_chirho != erasure_frame_digest_hex_chirho(&frame_chirho) {
        return Err(refuse_chirho(
            invalid_chirho,
            "the erasure frame digest does not bind its fields",
        ));
    }
    let digest_chirho = decode_hex_32_chirho(&frame_chirho.frame_digest_chirho)
        .ok_or_else(|| refuse_chirho(invalid_chirho, "the erasure frame digest is not 32 bytes"))?;
    verify_node_signature_chirho(
        &frame_chirho.origin_node_id_chirho,
        &digest_chirho,
        &frame_chirho.sig_hex_chirho,
        invalid_chirho,
    )?;
    Ok(AuthenticatedErasureFrameChirho { frame_chirho })
}

/// An erasure this holder must carry out: its sender is the current leader of this holder's exact
/// joined view.
#[derive(Debug)]
pub struct AuthorizedErasureFrameChirho {
    frame_chirho: ErasureFrameV1Chirho,
}

pub fn authorize_erasure_frame_chirho(
    authenticated_chirho: AuthenticatedErasureFrameChirho,
    joined_chirho: &JoinedMirrorViewChirho,
    receiver_node_id_chirho: &str,
    clock_chirho: &dyn MonotonicClockChirho,
    transit_budget_millis_chirho: NonZeroU64,
) -> Result<AuthorizedErasureFrameChirho, KeyCustodyErrorChirho> {
    verify_mirror_authority_binding_chirho(
        &authenticated_chirho,
        joined_chirho,
        receiver_node_id_chirho,
        clock_chirho,
        transit_budget_millis_chirho,
    )
    .map_err(KeyCustodyErrorChirho::from_mirror_authority_chirho)?;
    Ok(AuthorizedErasureFrameChirho {
        frame_chirho: authenticated_chirho.frame_chirho,
    })
}

impl AuthorizedErasureFrameChirho {
    pub fn frame_digest_chirho(&self) -> &str {
        &self.frame_chirho.frame_digest_chirho
    }

    pub fn subject_digest_chirho(&self) -> &str {
        &self.frame_chirho.subject_digest_chirho
    }

    pub fn erased_below_blob_seq_chirho(&self) -> u64 {
        self.frame_chirho.erased_below_blob_seq_chirho
    }

    pub fn key_ids_chirho(&self) -> &[String] {
        &self.frame_chirho.key_ids_chirho
    }

    /// The group whose current leader ordered this erasure; a holder keys its term high-water by it.
    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.frame_chirho.consistency_group_digest_chirho
    }

    /// The elected term the sender led in when it ordered this erasure.
    pub fn elected_term_chirho(&self) -> u64 {
        self.frame_chirho.elected_term_chirho
    }

    pub(crate) fn frame_chirho(&self) -> &ErasureFrameV1Chirho {
        &self.frame_chirho
    }

    /// Whether a key this holder stores under `stored_chirho` must be erased by this frame: its id is
    /// listed, or its subject is the frame's subject and its blob seq is below the erasure's bound.
    pub fn covers_stored_key_chirho(&self, stored_chirho: &CustodyBindingChirho) -> bool {
        self.frame_chirho
            .key_ids_chirho
            .binary_search(&stored_chirho.key_id_chirho)
            .is_ok()
            || (stored_chirho.subject_digest_chirho == self.frame_chirho.subject_digest_chirho
                && stored_chirho.blob_seq_chirho < self.frame_chirho.erased_below_blob_seq_chirho)
    }
}

impl ErasureFrameV1Chirho {
    pub(crate) fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub(crate) fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }

    pub(crate) fn elected_term_chirho(&self) -> u64 {
        self.elected_term_chirho
    }

    pub(crate) fn origin_node_id_chirho(&self) -> &str {
        &self.origin_node_id_chirho
    }

    pub(crate) fn holder_node_id_chirho(&self) -> &str {
        &self.holder_node_id_chirho
    }

    pub(crate) fn subject_digest_chirho(&self) -> &str {
        &self.subject_digest_chirho
    }

    pub(crate) fn erased_below_blob_seq_chirho(&self) -> u64 {
        self.erased_below_blob_seq_chirho
    }

    pub(crate) fn key_ids_chirho(&self) -> &[String] {
        &self.key_ids_chirho
    }
}

/// An erasure frame MAY address its own sender: the elected leader closes its own holder store's share with a
/// frame to itself, through the same admission as any holder (C5 B3-a3, item 14 D1; gpt #30156, agy #30163).
/// Authority still admits only the established leader at the frame's term, to its own target. A custody binding
/// keeps its separate refusal of a leader sending custody to itself.
fn validate_erasure_frame_chirho(
    frame_chirho: &ErasureFrameV1Chirho,
) -> Result<(), KeyCustodyErrorChirho> {
    let in_form_chirho = frame_chirho.schema_chirho == ERASURE_FRAME_SCHEMA_V1_CHIRHO
        && valid_lower_hex_chirho(
            &frame_chirho.consistency_group_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        )
        && valid_lower_hex_chirho(
            &frame_chirho.membership_view_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        )
        && valid_lower_hex_chirho(&frame_chirho.subject_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
        && valid_lower_hex_chirho(
            &frame_chirho.origin_node_id_chirho,
            NODE_ID_HEX_BYTES_CHIRHO,
        )
        && valid_lower_hex_chirho(
            &frame_chirho.holder_node_id_chirho,
            NODE_ID_HEX_BYTES_CHIRHO,
        )
        && frame_chirho.elected_term_chirho != 0
        && valid_key_id_list_chirho(&frame_chirho.key_ids_chirho)
        && (frame_chirho.frame_digest_chirho.is_empty()
            || valid_lower_hex_chirho(&frame_chirho.frame_digest_chirho, DIGEST_HEX_BYTES_CHIRHO));
    if !in_form_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::ErasureFrameInvalidChirho,
            "erasure frame fields are not in form",
        ));
    }
    Ok(())
}

fn erasure_frame_digest_hex_chirho(frame_chirho: &ErasureFrameV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(ERASURE_FRAME_DIGEST_DOMAIN_V1_CHIRHO);
    for (label_chirho, value_chirho) in [
        (&b"schema-chirho"[..], &frame_chirho.schema_chirho),
        (
            &b"consistency-group-chirho"[..],
            &frame_chirho.consistency_group_digest_chirho,
        ),
        (
            &b"membership-view-chirho"[..],
            &frame_chirho.membership_view_digest_chirho,
        ),
        (
            &b"origin-node-chirho"[..],
            &frame_chirho.origin_node_id_chirho,
        ),
        (
            &b"holder-node-chirho"[..],
            &frame_chirho.holder_node_id_chirho,
        ),
        (
            &b"subject-digest-chirho"[..],
            &frame_chirho.subject_digest_chirho,
        ),
    ] {
        update_digest_field_chirho(&mut hasher_chirho, label_chirho, value_chirho.as_bytes());
    }
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"elected-term-chirho",
        &frame_chirho.elected_term_chirho.to_le_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"erased-below-blob-seq-chirho",
        &frame_chirho.erased_below_blob_seq_chirho.to_le_bytes(),
    );
    update_lease_field_chirho(
        &mut hasher_chirho,
        frame_chirho.leader_lease_remaining_millis_chirho,
    );
    update_key_ids_field_chirho(
        &mut hasher_chirho,
        b"key-id-count-chirho",
        frame_chirho.key_ids_chirho.iter(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}

fn erasure_wire_invalid_chirho() -> KeyCustodyErrorChirho {
    refuse_chirho(
        KeyCustodyRefusalIdentityChirho::CustodyWireInvalidChirho,
        "the erasure wire bytes are too large or do not parse",
    )
}
