// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The holder's signed custody receipt, and the leader's confirmation that both other placement holders hold one exact key.
//!
//! A holder signs a receipt only after the opened key record is durably stored. The leader confirms
//! custody for one key only when, under its own CURRENT joined view, it is the elected leader and each
//! of the two other serving holders returned a receipt for exactly that key's binding: same group,
//! view, term, leader, key id, subject, ciphertext and blob seq. The three failure domains come from
//! the mirror's holder selection, which already refuses a non-distinct spread or a residency veto.
//! This is per key; a manifest with several sealed members needs one confirmation per member (R-C5-2b).

use crate::custody_chirho::binding_chirho::CustodyBindingChirho;
use crate::custody_chirho::frame_chirho::OpenedCustodyKeyChirho;
use crate::digest_chirho::{
    decode_hex_32_chirho, update_digest_field_chirho, valid_lower_hex_chirho,
    validate_signature_hex_chirho, verify_node_signature_chirho, DIGEST_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use cairn_mirror_chirho::{
    verify_mirror_receiver_elected_leader_chirho, JoinedMirrorViewChirho, MirrorHolderSetChirho,
};
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CUSTODY_RECEIPT_SCHEMA_V1_CHIRHO: &str = "key-custody-receipt-v1-chirho";
const CUSTODY_RECEIPT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-custody-receipt-v1-chirho";
const CUSTODY_RECEIPT_WIRE_MAX_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyReceiptV1Chirho {
    schema_chirho: String,
    custody_frame_digest_chirho: String,
    binding_chirho: CustodyBindingChirho,
    receipt_digest_chirho: String,
    sig_hex_chirho: String,
}

pub struct PreparedCustodyReceiptChirho {
    receipt_chirho: CustodyReceiptV1Chirho,
}

impl PreparedCustodyReceiptChirho {
    /// Call only AFTER the opened key record is durably stored: the key file written and fsynced and
    /// its directory fsynced. A signed receipt is the holder's promise that the key survives its crash.
    pub fn for_durably_stored_key_chirho(opened_chirho: &OpenedCustodyKeyChirho) -> Self {
        let mut receipt_chirho = CustodyReceiptV1Chirho {
            schema_chirho: CUSTODY_RECEIPT_SCHEMA_V1_CHIRHO.to_string(),
            custody_frame_digest_chirho: opened_chirho.frame_digest_chirho().to_string(),
            binding_chirho: opened_chirho.binding_chirho().clone(),
            receipt_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        receipt_chirho.receipt_digest_chirho = receipt_digest_hex_chirho(&receipt_chirho);
        Self { receipt_chirho }
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        decode_hex_32_chirho(&self.receipt_chirho.receipt_digest_chirho)
            .expect("a prepared custody receipt always carries its digest")
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<CustodyReceiptV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::CustodyReceiptInvalidChirho,
        )?;
        self.receipt_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.receipt_chirho)
    }
}

impl CustodyReceiptV1Chirho {
    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, KeyCustodyErrorChirho> {
        let bytes_chirho = serde_json::to_vec(self).map_err(|_| receipt_wire_invalid_chirho())?;
        if bytes_chirho.len() > CUSTODY_RECEIPT_WIRE_MAX_BYTES_CHIRHO {
            return Err(receipt_wire_invalid_chirho());
        }
        Ok(bytes_chirho)
    }

    /// Accept the receipt only if it is in form, its digest binds its fields, and the bound holder's
    /// node key signed it.
    pub fn verify_chirho(&self) -> Result<VerifiedCustodyReceiptChirho, KeyCustodyErrorChirho> {
        let invalid_chirho = KeyCustodyRefusalIdentityChirho::CustodyReceiptInvalidChirho;
        if self.schema_chirho != CUSTODY_RECEIPT_SCHEMA_V1_CHIRHO
            || !valid_lower_hex_chirho(&self.custody_frame_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
            || !valid_lower_hex_chirho(&self.receipt_digest_chirho, DIGEST_HEX_BYTES_CHIRHO)
        {
            return Err(refuse_chirho(
                invalid_chirho,
                "receipt fields are not in form",
            ));
        }
        self.binding_chirho
            .validate_chirho()
            .map_err(|_| refuse_chirho(invalid_chirho, "receipt binding is not in form"))?;
        if self.receipt_digest_chirho != receipt_digest_hex_chirho(self) {
            return Err(refuse_chirho(
                invalid_chirho,
                "the receipt digest does not bind its fields",
            ));
        }
        let digest_chirho = decode_hex_32_chirho(&self.receipt_digest_chirho)
            .ok_or_else(|| refuse_chirho(invalid_chirho, "receipt digest is not 32 bytes"))?;
        verify_node_signature_chirho(
            &self.binding_chirho.holder_node_id_chirho,
            &digest_chirho,
            &self.sig_hex_chirho,
            invalid_chirho,
        )?;
        Ok(VerifiedCustodyReceiptChirho {
            receipt_chirho: self.clone(),
        })
    }
}

pub fn decode_and_verify_custody_receipt_chirho(
    wire_bytes_chirho: &[u8],
) -> Result<VerifiedCustodyReceiptChirho, KeyCustodyErrorChirho> {
    if wire_bytes_chirho.len() > CUSTODY_RECEIPT_WIRE_MAX_BYTES_CHIRHO {
        return Err(receipt_wire_invalid_chirho());
    }
    let receipt_chirho: CustodyReceiptV1Chirho =
        serde_json::from_slice(wire_bytes_chirho).map_err(|_| receipt_wire_invalid_chirho())?;
    receipt_chirho.verify_chirho()
}

/// A receipt its holder signed over a well-formed binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCustodyReceiptChirho {
    receipt_chirho: CustodyReceiptV1Chirho,
}

impl VerifiedCustodyReceiptChirho {
    pub fn binding_chirho(&self) -> &CustodyBindingChirho {
        &self.receipt_chirho.binding_chirho
    }

    pub fn receipt_digest_chirho(&self) -> &str {
        &self.receipt_chirho.receipt_digest_chirho
    }

    pub fn custody_frame_digest_chirho(&self) -> &str {
        &self.receipt_chirho.custody_frame_digest_chirho
    }
}

/// The key a leader is confirming, by its blob coordinates. Group, view, term and leader come from
/// the leader's own joined view and holder selection, never from a receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyKeyCoordinatesChirho {
    pub key_id_chirho: String,
    pub subject_digest_chirho: String,
    pub ciphertext_addr_chirho: String,
    pub blob_seq_chirho: u64,
}

/// Custody of one key, proven across the placement's three distinct failure domains: the leader's
/// own copy plus a signed durable-store receipt from each other serving holder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCustodyConfirmedChirho {
    consistency_group_digest_chirho: String,
    membership_view_digest_chirho: String,
    elected_term_chirho: u64,
    leader_node_id_chirho: String,
    key_chirho: CustodyKeyCoordinatesChirho,
    holder_receipt_digests_chirho: [String; 2],
    covered_failure_domains_chirho: [FailureDomainChirho; 3],
}

impl KeyCustodyConfirmedChirho {
    pub fn key_chirho(&self) -> &CustodyKeyCoordinatesChirho {
        &self.key_chirho
    }

    pub fn leader_node_id_chirho(&self) -> &str {
        &self.leader_node_id_chirho
    }

    pub fn elected_term_chirho(&self) -> u64 {
        self.elected_term_chirho
    }

    pub fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub fn holder_receipt_digests_chirho(&self) -> &[String; 2] {
        &self.holder_receipt_digests_chirho
    }

    pub fn covered_failure_domains_chirho(&self) -> &[FailureDomainChirho; 3] {
        &self.covered_failure_domains_chirho
    }
}

/// Confirm custody of one key. `holder_set_chirho` must be the selection over `joined_chirho`'s view
/// with this node as leader; every serving holder is checked against the view again here.
pub fn confirm_key_custody_chirho(
    joined_chirho: &JoinedMirrorViewChirho,
    holder_set_chirho: &MirrorHolderSetChirho,
    key_chirho: &CustodyKeyCoordinatesChirho,
    receipts_chirho: &[VerifiedCustodyReceiptChirho],
) -> Result<KeyCustodyConfirmedChirho, KeyCustodyErrorChirho> {
    let view_chirho = joined_chirho.view_chirho();
    let leader_chirho = holder_set_chirho.leader_chirho();
    let term_chirho = joined_chirho.term_chirho();
    verify_mirror_receiver_elected_leader_chirho(
        joined_chirho,
        leader_chirho.node_id_chirho(),
        term_chirho,
    )
    .map_err(KeyCustodyErrorChirho::from_mirror_authority_chirho)?;
    let peers_chirho = holder_set_chirho.mirror_holders_chirho();
    let selected_chirho = [leader_chirho, peers_chirho[0], peers_chirho[1]];
    let selected_nodes_chirho = selected_chirho
        .iter()
        .map(|holder_chirho| holder_chirho.node_id_chirho())
        .collect::<BTreeSet<_>>();
    let view_nodes_chirho = view_chirho
        .holders_chirho()
        .iter()
        .map(|holder_chirho| holder_chirho.node_id_chirho())
        .collect::<BTreeSet<_>>();
    let domains_chirho = selected_chirho
        .iter()
        .map(|holder_chirho| holder_chirho.failure_domain_chirho().clone())
        .collect::<BTreeSet<_>>();
    if selected_nodes_chirho != view_nodes_chirho || domains_chirho.len() != 3 {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyConfirmationIncompleteChirho,
            "the holder selection is not this view's three distinct serving holders",
        ));
    }
    let view_digest_chirho = view_chirho.view_digest_chirho();
    let mut receipt_digests_chirho = Vec::with_capacity(2);
    for peer_chirho in peers_chirho {
        let expected_chirho = CustodyBindingChirho {
            consistency_group_digest_chirho: view_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            membership_view_digest_chirho: view_digest_chirho.clone(),
            elected_term_chirho: term_chirho,
            origin_node_id_chirho: leader_chirho.node_id_chirho().to_string(),
            holder_node_id_chirho: peer_chirho.node_id_chirho().to_string(),
            key_id_chirho: key_chirho.key_id_chirho.clone(),
            subject_digest_chirho: key_chirho.subject_digest_chirho.clone(),
            ciphertext_addr_chirho: key_chirho.ciphertext_addr_chirho.clone(),
            blob_seq_chirho: key_chirho.blob_seq_chirho,
        };
        let receipt_chirho = receipts_chirho
            .iter()
            .find(|receipt_chirho| receipt_chirho.binding_chirho() == &expected_chirho)
            .ok_or_else(|| {
                refuse_chirho(
                    KeyCustodyRefusalIdentityChirho::CustodyConfirmationIncompleteChirho,
                    "a serving holder has no receipt for exactly this key under this view",
                )
            })?;
        receipt_digests_chirho.push(receipt_chirho.receipt_digest_chirho().to_string());
    }
    let mut covered_chirho = domains_chirho.into_iter();
    Ok(KeyCustodyConfirmedChirho {
        consistency_group_digest_chirho: view_chirho.consistency_group_digest_chirho().to_string(),
        membership_view_digest_chirho: view_digest_chirho,
        elected_term_chirho: term_chirho,
        leader_node_id_chirho: leader_chirho.node_id_chirho().to_string(),
        key_chirho: key_chirho.clone(),
        holder_receipt_digests_chirho: [
            receipt_digests_chirho[0].clone(),
            receipt_digests_chirho[1].clone(),
        ],
        covered_failure_domains_chirho: [
            covered_chirho.next().expect("three distinct domains"),
            covered_chirho.next().expect("three distinct domains"),
            covered_chirho.next().expect("three distinct domains"),
        ],
    })
}

fn receipt_digest_hex_chirho(receipt_chirho: &CustodyReceiptV1Chirho) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(CUSTODY_RECEIPT_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"schema-chirho",
        receipt_chirho.schema_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"custody-frame-digest-chirho",
        receipt_chirho.custody_frame_digest_chirho.as_bytes(),
    );
    receipt_chirho
        .binding_chirho
        .update_digest_chirho(&mut hasher_chirho);
    hasher_chirho.finalize().to_hex().to_string()
}

fn receipt_wire_invalid_chirho() -> KeyCustodyErrorChirho {
    refuse_chirho(
        KeyCustodyRefusalIdentityChirho::CustodyWireInvalidChirho,
        "the custody receipt wire bytes are too large or do not parse",
    )
}
