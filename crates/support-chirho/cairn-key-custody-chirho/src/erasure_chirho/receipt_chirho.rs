// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The holder's signed erasure receipt: every listed key accounted for as removed or already absent, plus the keys the subject rule removed.
//!
//! A holder signs only after its tombstones for the frame are durable and every removed key file is
//! unlinked with its directory fsynced. The listed ids must split exactly into `removed` and
//! `already_absent`; keys found only by the subject rule are reported separately, so the evidence
//! says which keys the leader knew about and which the holder found itself.

use crate::digest_chirho::{
    decode_hex_32_chirho, key_id_list_chirho, update_digest_field_chirho,
    update_key_ids_field_chirho, valid_key_id_list_chirho, valid_lower_hex_chirho,
    validate_signature_hex_chirho, verify_node_signature_chirho, DIGEST_HEX_BYTES_CHIRHO,
    NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::erasure_chirho::frame_chirho::{
    AuthorizedErasureFrameChirho, ErasureFrameV1Chirho, ERASURE_WIRE_MAX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ERASURE_RECEIPT_SCHEMA_V1_CHIRHO: &str = "key-erasure-receipt-v1-chirho";
const ERASURE_RECEIPT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-erasure-receipt-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureReceiptV1Chirho {
    schema_chirho: String,
    erasure_frame_digest_chirho: String,
    consistency_group_digest_chirho: String,
    membership_view_digest_chirho: String,
    elected_term_chirho: u64,
    origin_node_id_chirho: String,
    holder_node_id_chirho: String,
    subject_digest_chirho: String,
    erased_below_blob_seq_chirho: u64,
    removed_key_ids_chirho: Vec<String>,
    already_absent_key_ids_chirho: Vec<String>,
    removed_by_subject_key_ids_chirho: Vec<String>,
    receipt_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedErasureReceiptChirho {
    receipt_chirho: ErasureReceiptV1Chirho,
}

impl PreparedErasureReceiptChirho {
    /// Call only AFTER the tombstones recording this frame are durable and every removed key file is
    /// unlinked with its directory fsynced. `removed` and `already_absent` must split the frame's
    /// listed ids exactly; `removed_by_subject` holds only ids the frame did not list.
    pub fn after_durable_erasure_chirho(
        frame_chirho: &AuthorizedErasureFrameChirho,
        removed_chirho: BTreeSet<String>,
        already_absent_chirho: BTreeSet<String>,
        removed_by_subject_chirho: BTreeSet<String>,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let listed_chirho = frame_chirho
            .key_ids_chirho()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let accounted_chirho = removed_chirho
            .union(&already_absent_chirho)
            .cloned()
            .collect::<BTreeSet<_>>();
        if !removed_chirho.is_disjoint(&already_absent_chirho)
            || accounted_chirho != listed_chirho
            || !removed_by_subject_chirho.is_disjoint(&listed_chirho)
        {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::ErasureReceiptInvalidChirho,
                "the receipt does not split the listed key ids exactly",
            ));
        }
        let frame_body_chirho = frame_chirho.frame_chirho();
        let mut receipt_chirho = ErasureReceiptV1Chirho {
            schema_chirho: ERASURE_RECEIPT_SCHEMA_V1_CHIRHO.to_string(),
            erasure_frame_digest_chirho: frame_chirho.frame_digest_chirho().to_string(),
            consistency_group_digest_chirho: frame_body_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            membership_view_digest_chirho: frame_body_chirho
                .membership_view_digest_chirho()
                .to_string(),
            elected_term_chirho: frame_body_chirho.elected_term_chirho(),
            origin_node_id_chirho: frame_body_chirho.origin_node_id_chirho().to_string(),
            holder_node_id_chirho: frame_body_chirho.holder_node_id_chirho().to_string(),
            subject_digest_chirho: frame_chirho.subject_digest_chirho().to_string(),
            erased_below_blob_seq_chirho: frame_chirho.erased_below_blob_seq_chirho(),
            removed_key_ids_chirho: key_id_list_chirho(&removed_chirho),
            already_absent_key_ids_chirho: key_id_list_chirho(&already_absent_chirho),
            removed_by_subject_key_ids_chirho: key_id_list_chirho(&removed_by_subject_chirho),
            receipt_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        validate_erasure_receipt_chirho(&receipt_chirho)?;
        receipt_chirho.receipt_digest_chirho = erasure_receipt_digest_hex_chirho(&receipt_chirho);
        Ok(Self { receipt_chirho })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.receipt_chirho.receipt_digest_chirho)
            .expect("a prepared erasure receipt always carries its digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<ErasureReceiptV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::ErasureReceiptInvalidChirho,
        )?;
        self.receipt_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.receipt_chirho)
    }
}

impl ErasureReceiptV1Chirho {
    /// The receipt as the bytes a holder answers with, bounded like an erasure frame.
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, KeyCustodyErrorChirho> {
        let bytes_chirho =
            serde_json::to_vec(self).map_err(|_| erasure_receipt_wire_invalid_chirho())?;
        if bytes_chirho.len() > ERASURE_WIRE_MAX_BYTES_CHIRHO {
            return Err(erasure_receipt_wire_invalid_chirho());
        }
        Ok(bytes_chirho)
    }

    /// Accept the receipt only if it is in form, its sets are disjoint, its digest binds its fields,
    /// and its holder's node key signed it.
    pub fn verify_chirho(&self) -> Result<VerifiedErasureReceiptChirho, KeyCustodyErrorChirho> {
        validate_erasure_receipt_chirho(self)?;
        let invalid_chirho = KeyCustodyRefusalIdentityChirho::ErasureReceiptInvalidChirho;
        if self.receipt_digest_chirho != erasure_receipt_digest_hex_chirho(self) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the receipt digest does not bind its fields",
            ));
        }
        let digest_chirho = decode_hex_32_chirho(&self.receipt_digest_chirho)
            .ok_or_else(|| refuse_chirho(invalid_chirho, "receipt digest is not 32 bytes"))?;
        verify_node_signature_chirho(
            &self.holder_node_id_chirho,
            &digest_chirho,
            &self.sig_hex_chirho,
            invalid_chirho,
        )?;
        Ok(VerifiedErasureReceiptChirho {
            receipt_chirho: self.clone(),
        })
    }
}

/// Decode a holder's answer to an erasure frame and verify it; the caller still checks that it answers
/// the frame it sent.
pub fn decode_and_verify_erasure_receipt_chirho(
    wire_bytes_chirho: &[u8],
) -> Result<VerifiedErasureReceiptChirho, KeyCustodyErrorChirho> {
    if wire_bytes_chirho.len() > ERASURE_WIRE_MAX_BYTES_CHIRHO {
        return Err(erasure_receipt_wire_invalid_chirho());
    }
    let receipt_chirho: ErasureReceiptV1Chirho = serde_json::from_slice(wire_bytes_chirho)
        .map_err(|_| erasure_receipt_wire_invalid_chirho())?;
    receipt_chirho.verify_chirho()
}

/// Whether `receipt_chirho` answers exactly the signed `frame_chirho` it was sent for: the frame's digest, every field
/// its holder copies from the frame, the holder the FRAME addresses, and the frame's listed ids split exactly
/// between removed and already absent. Both delivery roads, a peer over HTTP and the leader's own holder in
/// process, accept a receipt only through this one check (C5 B3-a3, item 14 D4; gpt #30156, agy #30163).
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
pub fn verify_erasure_receipt_answers_frame_chirho(
    frame_chirho: &ErasureFrameV1Chirho,
    receipt_chirho: &VerifiedErasureReceiptChirho,
) -> Result<(), KeyCustodyErrorChirho> {
    let receipt_chirho = &receipt_chirho.receipt_chirho;
    let split_chirho = receipt_chirho
        .removed_key_ids_chirho
        .iter()
        .chain(receipt_chirho.already_absent_key_ids_chirho.iter())
        .collect::<BTreeSet<_>>();
    let listed_chirho = frame_chirho
        .key_ids_chirho()
        .iter()
        .collect::<BTreeSet<_>>();
    let answers_chirho = receipt_chirho.erasure_frame_digest_chirho
        == frame_chirho.frame_digest_chirho()
        && receipt_chirho.consistency_group_digest_chirho
            == frame_chirho.consistency_group_digest_chirho()
        && receipt_chirho.membership_view_digest_chirho
            == frame_chirho.membership_view_digest_chirho()
        && receipt_chirho.elected_term_chirho == frame_chirho.elected_term_chirho()
        && receipt_chirho.origin_node_id_chirho == frame_chirho.origin_node_id_chirho()
        && receipt_chirho.holder_node_id_chirho == frame_chirho.holder_node_id_chirho()
        && receipt_chirho.subject_digest_chirho == frame_chirho.subject_digest_chirho()
        && receipt_chirho.erased_below_blob_seq_chirho
            == frame_chirho.erased_below_blob_seq_chirho()
        && split_chirho == listed_chirho;
    if !answers_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::ErasureReceiptNotForFrameChirho,
            "the receipt does not echo the frame it answers",
        ));
    }
    Ok(())
}

/// Test-only: one field of a receipt to change before it is re-digested and re-signed.
#[cfg(test)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub(crate) enum ReceiptFieldChirho {
    FrameDigestChirho(String),
    GroupChirho(String),
    ViewChirho(String),
    TermChirho(u64),
    OriginChirho(String),
    HolderChirho(String),
    SubjectChirho(String),
    BoundChirho(u64),
    ListsChirho {
        removed_chirho: Vec<String>,
        absent_chirho: Vec<String>,
        by_subject_chirho: Vec<String>,
    },
}

#[cfg(test)]
impl ReceiptFieldChirho {
    fn apply_chirho(self, receipt_chirho: &mut ErasureReceiptV1Chirho) {
        match self {
            Self::FrameDigestChirho(value_chirho) => {
                receipt_chirho.erasure_frame_digest_chirho = value_chirho
            }
            Self::GroupChirho(value_chirho) => {
                receipt_chirho.consistency_group_digest_chirho = value_chirho
            }
            Self::ViewChirho(value_chirho) => {
                receipt_chirho.membership_view_digest_chirho = value_chirho
            }
            Self::TermChirho(value_chirho) => receipt_chirho.elected_term_chirho = value_chirho,
            Self::OriginChirho(value_chirho) => receipt_chirho.origin_node_id_chirho = value_chirho,
            Self::HolderChirho(value_chirho) => receipt_chirho.holder_node_id_chirho = value_chirho,
            Self::SubjectChirho(value_chirho) => {
                receipt_chirho.subject_digest_chirho = value_chirho
            }
            Self::BoundChirho(value_chirho) => {
                receipt_chirho.erased_below_blob_seq_chirho = value_chirho
            }
            Self::ListsChirho {
                removed_chirho,
                absent_chirho,
                by_subject_chirho,
            } => {
                receipt_chirho.removed_key_ids_chirho = removed_chirho;
                receipt_chirho.already_absent_key_ids_chirho = absent_chirho;
                receipt_chirho.removed_by_subject_key_ids_chirho = by_subject_chirho;
            }
        }
    }
}

fn erasure_receipt_wire_invalid_chirho() -> KeyCustodyErrorChirho {
    refuse_chirho(
        KeyCustodyRefusalIdentityChirho::CustodyWireInvalidChirho,
        "the erasure receipt wire bytes are too large or do not parse",
    )
}

/// An erasure receipt its holder signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedErasureReceiptChirho {
    receipt_chirho: ErasureReceiptV1Chirho,
}

impl VerifiedErasureReceiptChirho {
    /// The signed receipt itself, as a store keeps it.
    pub fn record_chirho(&self) -> &ErasureReceiptV1Chirho {
        &self.receipt_chirho
    }

    /// Test-only: this receipt with the given fields changed, then re-digested and re-signed by `sign_chirho`, so a
    /// check downstream of signature verification can be exercised alone.
    #[cfg(test)]
    pub(crate) fn resigned_with_chirho(
        &self,
        changes_chirho: Vec<ReceiptFieldChirho>,
        sign_chirho: impl FnOnce(&[u8; 32]) -> String,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let mut receipt_chirho = self.receipt_chirho.clone();
        for change_chirho in changes_chirho {
            change_chirho.apply_chirho(&mut receipt_chirho);
        }
        receipt_chirho.receipt_digest_chirho = erasure_receipt_digest_hex_chirho(&receipt_chirho);
        let digest_chirho = decode_hex_32_chirho(&receipt_chirho.receipt_digest_chirho)
            .expect("a recomputed receipt digest is 32 bytes");
        receipt_chirho.sig_hex_chirho = sign_chirho(&digest_chirho);
        receipt_chirho.verify_chirho()
    }

    /// The erasure frame this receipt answers.
    pub fn erasure_frame_digest_chirho(&self) -> &str {
        &self.receipt_chirho.erasure_frame_digest_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.receipt_chirho.consistency_group_digest_chirho
    }

    pub fn holder_node_id_chirho(&self) -> &str {
        &self.receipt_chirho.holder_node_id_chirho
    }

    pub fn subject_digest_chirho(&self) -> &str {
        &self.receipt_chirho.subject_digest_chirho
    }

    pub fn erased_below_blob_seq_chirho(&self) -> u64 {
        self.receipt_chirho.erased_below_blob_seq_chirho
    }

    pub fn receipt_digest_chirho(&self) -> &str {
        &self.receipt_chirho.receipt_digest_chirho
    }

    /// Every key id this receipt says the holder no longer has: removed, already absent, or removed by
    /// the subject rule.
    pub fn accounted_key_ids_chirho(&self) -> impl Iterator<Item = &String> {
        self.receipt_chirho
            .removed_key_ids_chirho
            .iter()
            .chain(self.receipt_chirho.already_absent_key_ids_chirho.iter())
            .chain(self.receipt_chirho.removed_by_subject_key_ids_chirho.iter())
    }
}

fn validate_erasure_receipt_chirho(
    receipt_chirho: &ErasureReceiptV1Chirho,
) -> Result<(), KeyCustodyErrorChirho> {
    let lists_chirho = [
        &receipt_chirho.removed_key_ids_chirho,
        &receipt_chirho.already_absent_key_ids_chirho,
        &receipt_chirho.removed_by_subject_key_ids_chirho,
    ];
    let mut seen_chirho = BTreeSet::new();
    let disjoint_chirho = lists_chirho
        .iter()
        .flat_map(|list_chirho| list_chirho.iter())
        .all(|key_id_chirho| seen_chirho.insert(key_id_chirho));
    let in_form_chirho = receipt_chirho.schema_chirho == ERASURE_RECEIPT_SCHEMA_V1_CHIRHO
        && [
            &receipt_chirho.erasure_frame_digest_chirho,
            &receipt_chirho.consistency_group_digest_chirho,
            &receipt_chirho.membership_view_digest_chirho,
            &receipt_chirho.subject_digest_chirho,
        ]
        .iter()
        .all(|value_chirho| valid_lower_hex_chirho(value_chirho, DIGEST_HEX_BYTES_CHIRHO))
        && valid_lower_hex_chirho(
            &receipt_chirho.origin_node_id_chirho,
            NODE_ID_HEX_BYTES_CHIRHO,
        )
        && valid_lower_hex_chirho(
            &receipt_chirho.holder_node_id_chirho,
            NODE_ID_HEX_BYTES_CHIRHO,
        )
        && receipt_chirho.elected_term_chirho != 0
        && lists_chirho
            .iter()
            .all(|list_chirho| valid_key_id_list_chirho(list_chirho))
        && disjoint_chirho
        && (receipt_chirho.receipt_digest_chirho.is_empty()
            || valid_lower_hex_chirho(
                &receipt_chirho.receipt_digest_chirho,
                DIGEST_HEX_BYTES_CHIRHO,
            ));
    if !in_form_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::ErasureReceiptInvalidChirho,
            "erasure receipt fields are not in form or its key sets overlap",
        ));
    }
    Ok(())
}

fn erasure_receipt_digest_hex_chirho(receipt_chirho: &ErasureReceiptV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(ERASURE_RECEIPT_DIGEST_DOMAIN_V1_CHIRHO);
    for (label_chirho, value_chirho) in [
        (&b"schema-chirho"[..], &receipt_chirho.schema_chirho),
        (
            &b"erasure-frame-digest-chirho"[..],
            &receipt_chirho.erasure_frame_digest_chirho,
        ),
        (
            &b"consistency-group-chirho"[..],
            &receipt_chirho.consistency_group_digest_chirho,
        ),
        (
            &b"membership-view-chirho"[..],
            &receipt_chirho.membership_view_digest_chirho,
        ),
        (
            &b"origin-node-chirho"[..],
            &receipt_chirho.origin_node_id_chirho,
        ),
        (
            &b"holder-node-chirho"[..],
            &receipt_chirho.holder_node_id_chirho,
        ),
        (
            &b"subject-digest-chirho"[..],
            &receipt_chirho.subject_digest_chirho,
        ),
    ] {
        update_digest_field_chirho(&mut hasher_chirho, label_chirho, value_chirho.as_bytes());
    }
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"elected-term-chirho",
        &receipt_chirho.elected_term_chirho.to_le_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"erased-below-blob-seq-chirho",
        &receipt_chirho.erased_below_blob_seq_chirho.to_le_bytes(),
    );
    update_key_ids_field_chirho(
        &mut hasher_chirho,
        b"removed-count-chirho",
        receipt_chirho.removed_key_ids_chirho.iter(),
    );
    update_key_ids_field_chirho(
        &mut hasher_chirho,
        b"already-absent-count-chirho",
        receipt_chirho.already_absent_key_ids_chirho.iter(),
    );
    update_key_ids_field_chirho(
        &mut hasher_chirho,
        b"removed-by-subject-count-chirho",
        receipt_chirho.removed_by_subject_key_ids_chirho.iter(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}
