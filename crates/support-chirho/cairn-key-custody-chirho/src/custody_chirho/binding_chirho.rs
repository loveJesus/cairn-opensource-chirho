// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! What one wrapped key is bound to: the group, the exact membership view and term, the sending leader, the holder, and the exact blob.
//!
//! The binding's digest is both the wrap's associated data and the core of the leader-signed frame,
//! so a frame made for one holder, view, term, key, subject, ciphertext or blob record opens and
//! verifies for none other. The mirror's view digest already covers the placement assignment, the
//! applied configuration index, every serving holder and the held observer, so binding it refuses a
//! frame replayed across a re-placement inside one term (agy R-C5-2a). The ciphertext address and
//! blob seq tie custody to one exact blob record, and the blob seq is what lets a holder's erasure
//! tombstone refuse a delayed frame for a blob that existed when the subject was erased (R-C5-4b).

use crate::digest_chirho::{
    update_digest_field_chirho, valid_lower_hex_chirho, DIGEST_HEX_BYTES_CHIRHO,
    KEY_ID_HEX_BYTES_CHIRHO, NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use serde::{Deserialize, Serialize};

const BINDING_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-custody-binding-v1-chirho";
const SUBJECT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-custody-subject-v1-chirho";
const SUBJECT_MAX_BYTES_CHIRHO: usize = 256;

/// The subject's domain-separated digest. It is unsalted on purpose: holders index keys and keep
/// erasure tombstones by it, so it must stay stable across terms, views and tenant moves. The subject
/// is an opaque id that already sits in plain text in the root's signed privacy logs.
pub fn subject_digest_hex_chirho(subject_chirho: &str) -> String {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(SUBJECT_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"subject-chirho",
        subject_chirho.as_bytes(),
    );
    hasher_chirho.finalize().to_hex().to_string()
}

/// The same charset and bound as the root's privacy subjects: a short opaque id.
pub(crate) fn valid_subject_chirho(subject_chirho: &str) -> bool {
    !subject_chirho.trim().is_empty()
        && subject_chirho.len() <= SUBJECT_MAX_BYTES_CHIRHO
        && subject_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | '/' | ':' | '.')
        })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyBindingChirho {
    pub consistency_group_digest_chirho: String,
    pub membership_view_digest_chirho: String,
    pub elected_term_chirho: u64,
    pub origin_node_id_chirho: String,
    pub holder_node_id_chirho: String,
    pub key_id_chirho: String,
    pub subject_digest_chirho: String,
    pub ciphertext_addr_chirho: String,
    pub blob_seq_chirho: u64,
}

impl CustodyBindingChirho {
    pub fn validate_chirho(&self) -> Result<(), KeyCustodyErrorChirho> {
        let digests_in_form_chirho = [
            &self.consistency_group_digest_chirho,
            &self.membership_view_digest_chirho,
            &self.subject_digest_chirho,
            &self.ciphertext_addr_chirho,
        ]
        .iter()
        .all(|value_chirho| valid_lower_hex_chirho(value_chirho, DIGEST_HEX_BYTES_CHIRHO));
        if !digests_in_form_chirho
            || !valid_lower_hex_chirho(&self.origin_node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO)
            || !valid_lower_hex_chirho(&self.holder_node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO)
            || !valid_lower_hex_chirho(&self.key_id_chirho, KEY_ID_HEX_BYTES_CHIRHO)
            || self.elected_term_chirho == 0
        {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyBindingMalformedChirho,
                "binding fields are not in form",
            ));
        }
        if self.origin_node_id_chirho == self.holder_node_id_chirho {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyHolderMismatchChirho,
                "a leader never sends custody to itself",
            ));
        }
        Ok(())
    }

    pub fn digest_chirho(&self) -> [u8; 32] {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(BINDING_DIGEST_DOMAIN_V1_CHIRHO);
        self.update_digest_chirho(&mut hasher_chirho);
        *hasher_chirho.finalize().as_bytes()
    }

    pub(crate) fn update_digest_chirho(&self, hasher_chirho: &mut blake3::Hasher) {
        for (label_chirho, value_chirho) in [
            (
                &b"consistency-group-chirho"[..],
                &self.consistency_group_digest_chirho,
            ),
            (
                &b"membership-view-chirho"[..],
                &self.membership_view_digest_chirho,
            ),
            (&b"origin-node-chirho"[..], &self.origin_node_id_chirho),
            (&b"holder-node-chirho"[..], &self.holder_node_id_chirho),
            (&b"key-id-chirho"[..], &self.key_id_chirho),
            (&b"subject-digest-chirho"[..], &self.subject_digest_chirho),
            (&b"ciphertext-addr-chirho"[..], &self.ciphertext_addr_chirho),
        ] {
            update_digest_field_chirho(hasher_chirho, label_chirho, value_chirho.as_bytes());
        }
        update_digest_field_chirho(
            hasher_chirho,
            b"elected-term-chirho",
            &self.elected_term_chirho.to_le_bytes(),
        );
        update_digest_field_chirho(
            hasher_chirho,
            b"blob-seq-chirho",
            &self.blob_seq_chirho.to_le_bytes(),
        );
    }
}
