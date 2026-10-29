// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Whether a subject's erasure reached every holder that ever held its keys: the requirement, and the status signed receipts and attestations give it.
//!
//! The caller builds the requirement from custody EVIDENCE, never from the leader's local key scan (agy
//! R-C5-3): every key id ever recorded for the subject, every holder that was ever sent custody of one of
//! them, and the current serving peers. A holder's share closes only when its signed erasure receipts for
//! the subject account for every required key id AND carry a blob-seq bound at least the requirement's,
//! so an erasure frame built from a leader's scan that lost its own files cannot report complete. A holder
//! that can no longer answer closes only through a verified decommission attestation, and the status then
//! names it under its own variant. An attestation never closes the share of a holder the caller's current
//! view still places, whatever view it was verified against.

use crate::digest_chirho::{
    valid_lower_hex_chirho, DIGEST_HEX_BYTES_CHIRHO, KEY_ID_HEX_BYTES_CHIRHO,
    NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::erasure_chirho::decommission_chirho::VerifiedDecommissionAttestationChirho;
use crate::erasure_chirho::receipt_chirho::VerifiedErasureReceiptChirho;
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use cairn_mirror_chirho::MirrorMembershipViewChirho;
use std::collections::BTreeSet;

/// Everything one subject's erasure must reach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureRequirementChirho {
    consistency_group_digest_chirho: String,
    subject_digest_chirho: String,
    erased_below_blob_seq_chirho: u64,
    key_ids_chirho: BTreeSet<String>,
    holders_chirho: BTreeSet<String>,
}

impl ErasureRequirementChirho {
    /// `key_ids_chirho` and `holders_chirho` are unions over custody evidence (see the module header).
    /// An empty holder set is refused: it would make every erasure complete by construction.
    pub fn new_chirho(
        consistency_group_digest_chirho: impl Into<String>,
        subject_digest_chirho: impl Into<String>,
        erased_below_blob_seq_chirho: u64,
        key_ids_chirho: BTreeSet<String>,
        holders_chirho: BTreeSet<String>,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let requirement_chirho = Self {
            consistency_group_digest_chirho: consistency_group_digest_chirho.into(),
            subject_digest_chirho: subject_digest_chirho.into(),
            erased_below_blob_seq_chirho,
            key_ids_chirho,
            holders_chirho,
        };
        let in_form_chirho = valid_lower_hex_chirho(
            &requirement_chirho.consistency_group_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        ) && valid_lower_hex_chirho(
            &requirement_chirho.subject_digest_chirho,
            DIGEST_HEX_BYTES_CHIRHO,
        ) && requirement_chirho
            .key_ids_chirho
            .iter()
            .all(|key_id_chirho| valid_lower_hex_chirho(key_id_chirho, KEY_ID_HEX_BYTES_CHIRHO))
            && !requirement_chirho.holders_chirho.is_empty()
            && requirement_chirho
                .holders_chirho
                .iter()
                .all(|holder_chirho| {
                    valid_lower_hex_chirho(holder_chirho, NODE_ID_HEX_BYTES_CHIRHO)
                });
        if !in_form_chirho {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::ErasureRequirementInvalidChirho,
                "the requirement is not in form or names no holder",
            ));
        }
        Ok(requirement_chirho)
    }

    /// Whether this one receipt closes its holder's share by itself: the holder is required, and the receipt
    /// alone passes the status predicate below. A leader stores only such receipts, so storage and status judge a
    /// share the same way (C5 B3-a3, item 14 D5; agy #30163).
    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
    pub fn closes_share_alone_chirho(&self, receipt_chirho: &VerifiedErasureReceiptChirho) -> bool {
        self.holders_chirho
            .contains(receipt_chirho.holder_node_id_chirho())
            && self.closed_by_receipts_chirho(
                receipt_chirho.holder_node_id_chirho(),
                std::slice::from_ref(receipt_chirho),
            )
    }

    /// Whether one holder's receipts close its share: they account for every required key id and one
    /// of them carries a bound at least the requirement's.
    fn closed_by_receipts_chirho(
        &self,
        holder_chirho: &str,
        receipts_chirho: &[VerifiedErasureReceiptChirho],
    ) -> bool {
        let mine_chirho = receipts_chirho
            .iter()
            .filter(|receipt_chirho| {
                receipt_chirho.holder_node_id_chirho() == holder_chirho
                    && receipt_chirho.consistency_group_digest_chirho()
                        == self.consistency_group_digest_chirho
                    && receipt_chirho.subject_digest_chirho() == self.subject_digest_chirho
            })
            .collect::<Vec<_>>();
        let accounted_chirho = mine_chirho
            .iter()
            .flat_map(|receipt_chirho| receipt_chirho.accounted_key_ids_chirho())
            .collect::<BTreeSet<_>>();
        let bound_reached_chirho = mine_chirho.iter().any(|receipt_chirho| {
            receipt_chirho.erased_below_blob_seq_chirho() >= self.erased_below_blob_seq_chirho
        });
        bound_reached_chirho
            && self
                .key_ids_chirho
                .iter()
                .all(|key_id_chirho| accounted_chirho.contains(key_id_chirho))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErasureStatusChirho {
    /// Every required holder signed receipts that close its share.
    ErasureConfirmedByHolderReceiptsChirho,
    /// Every share is closed, but these holders only through a destroyed-media attestation.
    ErasureConfirmedWithDecommissionedHolderAttestationChirho {
        attested_holders_chirho: BTreeSet<String>,
    },
    /// These holders have not closed their share, and the erasure is not complete.
    ErasurePropagationPendingChirho {
        pending_holders_chirho: BTreeSet<String>,
    },
}

impl ErasureStatusChirho {
    pub fn is_complete_chirho(&self) -> bool {
        !matches!(self, Self::ErasurePropagationPendingChirho { .. })
    }
}

/// The erasure's status for its requirement under the caller's CURRENT view, which must be the
/// requirement's own group: a view from another group would let the placement re-check below pass for a
/// holder it simply does not list (agy pin B2-1). Receipts and attestations must already be verified;
/// one from another group or subject counts for nothing, and an attestation for a holder the current
/// view still places counts for nothing.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/key-custody-chirho/erasure-propagation-workflow-chirho.md`.
pub fn erasure_status_chirho(
    requirement_chirho: &ErasureRequirementChirho,
    current_view_chirho: &MirrorMembershipViewChirho,
    receipts_chirho: &[VerifiedErasureReceiptChirho],
    attestations_chirho: &[VerifiedDecommissionAttestationChirho],
) -> Result<ErasureStatusChirho, KeyCustodyErrorChirho> {
    if current_view_chirho.consistency_group_digest_chirho()
        != requirement_chirho.consistency_group_digest_chirho
    {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::ErasureRequirementInvalidChirho,
            "the current view is for another group",
        ));
    }
    let mut attested_holders_chirho = BTreeSet::new();
    let mut pending_holders_chirho = BTreeSet::new();
    for holder_chirho in &requirement_chirho.holders_chirho {
        if requirement_chirho.closed_by_receipts_chirho(holder_chirho, receipts_chirho) {
            continue;
        }
        let attested_chirho = !current_view_chirho.contains_chirho(holder_chirho)
            && attestations_chirho.iter().any(|attestation_chirho| {
                attestation_chirho.decommissioned_holder_node_id_chirho() == holder_chirho
                    && attestation_chirho.consistency_group_digest_chirho()
                        == requirement_chirho.consistency_group_digest_chirho
            });
        if attested_chirho {
            attested_holders_chirho.insert(holder_chirho.clone());
        } else {
            pending_holders_chirho.insert(holder_chirho.clone());
        }
    }
    Ok(if !pending_holders_chirho.is_empty() {
        ErasureStatusChirho::ErasurePropagationPendingChirho {
            pending_holders_chirho,
        }
    } else if !attested_holders_chirho.is_empty() {
        ErasureStatusChirho::ErasureConfirmedWithDecommissionedHolderAttestationChirho {
            attested_holders_chirho,
        }
    } else {
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    })
}
