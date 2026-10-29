// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The key record as the root stores it, and its wrap to one holder: ephemeral X25519 and XChaCha20-Poly1305 under a derived wrapping key, bound to the custody binding.
//!
//! The record is the root's own key-file shape (`subject_chirho`, `key_hex_chirho`), so a holder
//! stores exactly what the leader stores and a later adoption reads it with the root's own loader.
//! The wrap's associated data is the binding digest, so a frame cannot be re-pointed at another
//! holder, view, term, key or subject without the open failing. Opening also checks that the
//! record's subject is the one the binding names, which an honest seal guarantees and a dishonest
//! leader cannot get around.

use crate::custody_chirho::binding_chirho::{
    subject_digest_hex_chirho, valid_subject_chirho, CustodyBindingChirho,
};
use crate::custody_key_chirho::{
    check_custody_point_chirho, diffie_hellman_bytes_chirho, NodeCustodySecretChirho,
    VerifiedCustodyAnnouncementChirho,
};
use crate::digest_chirho::{
    decode_hex_32_chirho, decode_hex_chirho, hex_chirho, valid_lower_hex_chirho,
    NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::{Zeroize, Zeroizing};

const WRAP_KEY_DERIVATION_CONTEXT_CHIRHO: &str = "cairn-key-custody-wrap-key-v1-chirho";
const WRAP_AAD_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-custody-wrap-aad-v1-chirho";
const NONCE_HEX_BYTES_CHIRHO: usize = 48;
const KEY_HEX_BYTES_CHIRHO: usize = 64;
/// A record is a bounded subject plus 64 hex characters; this caps the sealed bytes we will open.
const RECORD_MAX_BYTES_CHIRHO: usize = 1024;
const AEAD_TAG_BYTES_CHIRHO: usize = 16;

/// One private-blob key in the root's key-file shape. The key is zeroized on drop, never printed and
/// never compared outside tests.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShredKeyRecordChirho {
    subject_chirho: String,
    key_hex_chirho: String,
}

impl Drop for ShredKeyRecordChirho {
    fn drop(&mut self) {
        self.key_hex_chirho.zeroize();
    }
}

impl fmt::Debug for ShredKeyRecordChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str("ShredKeyRecordChirho(..)")
    }
}

impl ShredKeyRecordChirho {
    pub fn new_chirho(
        subject_chirho: impl Into<String>,
        key_hex_chirho: impl Into<String>,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let record_chirho = Self {
            subject_chirho: subject_chirho.into(),
            key_hex_chirho: key_hex_chirho.into(),
        };
        record_chirho.validate_chirho()?;
        Ok(record_chirho)
    }

    fn validate_chirho(&self) -> Result<(), KeyCustodyErrorChirho> {
        if !valid_subject_chirho(&self.subject_chirho)
            || !valid_lower_hex_chirho(&self.key_hex_chirho, KEY_HEX_BYTES_CHIRHO)
        {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho,
                "the subject or the 32-byte key is not in form",
            ));
        }
        Ok(())
    }

    pub fn subject_chirho(&self) -> &str {
        &self.subject_chirho
    }

    pub fn subject_digest_chirho(&self) -> String {
        subject_digest_hex_chirho(&self.subject_chirho)
    }

    /// The exact bytes the root writes for a key file (`serde_json::to_vec_pretty` of the same two
    /// fields), so a holder's stored key is indistinguishable from the leader's.
    pub fn to_key_file_bytes_chirho(&self) -> Result<Zeroizing<Vec<u8>>, KeyCustodyErrorChirho> {
        serde_json::to_vec_pretty(self)
            .map(Zeroizing::new)
            .map_err(|_| {
                refuse_chirho(
                    KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho,
                    "the key record does not serialize",
                )
            })
    }

    /// Read a stored key file back, for a holder that must scan its keys by subject.
    pub fn from_key_file_bytes_chirho(bytes_chirho: &[u8]) -> Result<Self, KeyCustodyErrorChirho> {
        if bytes_chirho.len() > RECORD_MAX_BYTES_CHIRHO {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho,
                "the key file is too large",
            ));
        }
        let record_chirho: Self = serde_json::from_slice(bytes_chirho).map_err(|_| {
            refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho,
                "the key file does not parse",
            )
        })?;
        record_chirho.validate_chirho()?;
        Ok(record_chirho)
    }

    #[cfg(test)]
    pub(crate) fn same_record_chirho(&self, other_chirho: &Self) -> bool {
        self.subject_chirho == other_chirho.subject_chirho
            && self.key_hex_chirho == other_chirho.key_hex_chirho
    }
}

/// A key record sealed to one holder: the sender's ephemeral X25519 public key, the nonce and the
/// ciphertext, all lowercase hex. Nothing in it is secret without the holder's custody secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKeyPayloadChirho {
    pub ephemeral_public_hex_chirho: String,
    pub nonce_hex_chirho: String,
    pub ciphertext_hex_chirho: String,
}

impl WrappedKeyPayloadChirho {
    pub(crate) fn in_form_chirho(&self) -> bool {
        let ciphertext_max_hex_chirho = 2 * (RECORD_MAX_BYTES_CHIRHO + AEAD_TAG_BYTES_CHIRHO);
        valid_lower_hex_chirho(&self.ephemeral_public_hex_chirho, NODE_ID_HEX_BYTES_CHIRHO)
            && valid_lower_hex_chirho(&self.nonce_hex_chirho, NONCE_HEX_BYTES_CHIRHO)
            && self.ciphertext_hex_chirho.len() > 2 * AEAD_TAG_BYTES_CHIRHO
            && self.ciphertext_hex_chirho.len() <= ciphertext_max_hex_chirho
            && valid_lower_hex_chirho(
                &self.ciphertext_hex_chirho,
                self.ciphertext_hex_chirho.len(),
            )
    }
}

/// The wrapping key: BLAKE3 `derive_key` over the shared secret, the ephemeral public key and the
/// holder's custody public key, so it binds both ends of the exchange.
pub(crate) fn wrap_key_chirho(
    shared_chirho: &[u8; 32],
    ephemeral_public_chirho: &[u8; 32],
    holder_public_chirho: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut material_chirho = Zeroizing::new([0_u8; 96]);
    material_chirho[..32].copy_from_slice(shared_chirho);
    material_chirho[32..64].copy_from_slice(ephemeral_public_chirho);
    material_chirho[64..].copy_from_slice(holder_public_chirho);
    Zeroizing::new(blake3::derive_key(
        WRAP_KEY_DERIVATION_CONTEXT_CHIRHO,
        &*material_chirho,
    ))
}

pub(crate) fn wrap_aad_chirho(binding_chirho: &CustodyBindingChirho) -> Vec<u8> {
    let mut aad_chirho = WRAP_AAD_DOMAIN_V1_CHIRHO.to_vec();
    aad_chirho.extend_from_slice(&binding_chirho.digest_chirho());
    aad_chirho
}

/// Seal one key record to the binding's holder. The holder announcement must be the binding's holder
/// and the record's subject must be the binding's subject, so the leader cannot mis-address a key.
pub fn seal_wrapped_key_chirho(
    record_chirho: &ShredKeyRecordChirho,
    holder_chirho: &VerifiedCustodyAnnouncementChirho,
    binding_chirho: &CustodyBindingChirho,
) -> Result<WrappedKeyPayloadChirho, KeyCustodyErrorChirho> {
    binding_chirho.validate_chirho()?;
    if holder_chirho.node_id_chirho() != binding_chirho.holder_node_id_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyHolderMismatchChirho,
            "the custody key announced is not the bound holder's",
        ));
    }
    if record_chirho.subject_digest_chirho() != binding_chirho.subject_digest_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodySubjectMismatchChirho,
            "the record's subject is not the bound subject",
        ));
    }
    let mut ephemeral_secret_chirho = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *ephemeral_secret_chirho);
    let ephemeral_public_chirho = x25519(*ephemeral_secret_chirho, X25519_BASEPOINT_BYTES);
    let shared_chirho = diffie_hellman_bytes_chirho(
        &ephemeral_secret_chirho,
        holder_chirho.custody_public_chirho(),
    )?;
    let wrap_key_value_chirho = wrap_key_chirho(
        &shared_chirho,
        &ephemeral_public_chirho,
        holder_chirho.custody_public_chirho(),
    );
    let mut nonce_chirho = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce_chirho);
    let plaintext_chirho = Zeroizing::new(serde_json::to_vec(record_chirho).map_err(|_| {
        refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho,
            "the key record does not serialize",
        )
    })?);
    let ciphertext_chirho = XChaCha20Poly1305::new(Key::from_slice(&*wrap_key_value_chirho))
        .encrypt(
            XNonce::from_slice(&nonce_chirho),
            Payload {
                msg: &plaintext_chirho,
                aad: &wrap_aad_chirho(binding_chirho),
            },
        )
        .map_err(|_| {
            refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho,
                "the key record could not be sealed",
            )
        })?;
    Ok(WrappedKeyPayloadChirho {
        ephemeral_public_hex_chirho: hex_chirho(&ephemeral_public_chirho),
        nonce_hex_chirho: hex_chirho(&nonce_chirho),
        ciphertext_hex_chirho: hex_chirho(&ciphertext_chirho),
    })
}

/// Open a wrapped key with this holder's custody secret under the binding it was sealed to. Only an
/// authorized frame reaches this (`frame_chirho::AuthorizedCustodyFrameChirho::open_chirho`).
pub(crate) fn open_wrapped_key_chirho(
    payload_chirho: &WrappedKeyPayloadChirho,
    holder_secret_chirho: &NodeCustodySecretChirho,
    binding_chirho: &CustodyBindingChirho,
) -> Result<ShredKeyRecordChirho, KeyCustodyErrorChirho> {
    let unwrap_failed_chirho = KeyCustodyRefusalIdentityChirho::CustodyUnwrapFailedChirho;
    if !payload_chirho.in_form_chirho() {
        return Err(refuse_chirho(
            unwrap_failed_chirho,
            "the wrapped key is not in form",
        ));
    }
    let ephemeral_public_chirho = decode_hex_32_chirho(&payload_chirho.ephemeral_public_hex_chirho)
        .ok_or_else(|| refuse_chirho(unwrap_failed_chirho, "ephemeral key is not 32 bytes"))?;
    check_custody_point_chirho(&ephemeral_public_chirho)?;
    let nonce_chirho = decode_hex_chirho(&payload_chirho.nonce_hex_chirho)
        .ok_or_else(|| refuse_chirho(unwrap_failed_chirho, "nonce is not hex"))?;
    let ciphertext_chirho = decode_hex_chirho(&payload_chirho.ciphertext_hex_chirho)
        .ok_or_else(|| refuse_chirho(unwrap_failed_chirho, "ciphertext is not hex"))?;
    let shared_chirho = holder_secret_chirho.diffie_hellman_chirho(&ephemeral_public_chirho)?;
    let wrap_key_value_chirho = wrap_key_chirho(
        &shared_chirho,
        &ephemeral_public_chirho,
        &holder_secret_chirho.public_bytes_chirho(),
    );
    let plaintext_chirho = Zeroizing::new(
        XChaCha20Poly1305::new(Key::from_slice(&*wrap_key_value_chirho))
            .decrypt(
                XNonce::from_slice(&nonce_chirho),
                Payload {
                    msg: &ciphertext_chirho,
                    aad: &wrap_aad_chirho(binding_chirho),
                },
            )
            .map_err(|_| {
                refuse_chirho(
                    unwrap_failed_chirho,
                    "the wrap does not open under this binding",
                )
            })?,
    );
    let record_chirho: ShredKeyRecordChirho =
        serde_json::from_slice(&plaintext_chirho).map_err(|_| {
            refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho,
                "the opened key record does not parse",
            )
        })?;
    record_chirho.validate_chirho()?;
    if record_chirho.subject_digest_chirho() != binding_chirho.subject_digest_chirho {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodySubjectMismatchChirho,
            "the opened record's subject is not the bound subject",
        ));
    }
    Ok(record_chirho)
}
