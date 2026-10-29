// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Each node's X25519 custody key, derived from its node-control seed, and the signed announcement of its public half.
//!
//! The secret is BLAKE3 `derive_key` of the node-control ed25519 seed under a fixed context, so it
//! needs no new key file, config field or operator step, and it is domain-separated from the signing
//! key (ed25519 expands the same seed with SHA-512). Derivation takes the `SigningKey` itself, never
//! raw 32 bytes, so a caller cannot hand it the node's PUBLIC key by mistake (agy R-C5-1a); and an
//! announcement whose key equals the node id, or equals the key such a mistake would produce, is
//! refused. Because a node id IS the node's public signing key, any peer verifies an announcement
//! from the node id alone; whether that node may hold custody is decided against the joined view.
//!
//! Rotating a node key changes its node id, so it is a holder replacement (C4/B4), not an edit here.

use crate::digest_chirho::{
    decode_hex_32_chirho, hex_chirho, update_digest_field_chirho, valid_lower_hex_chirho,
    validate_signature_hex_chirho, verify_node_signature_chirho, NODE_ID_HEX_BYTES_CHIRHO,
};
use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

pub const CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO: &str = "cairn-key-custody-x25519-v1-chirho";
pub const CUSTODY_ANNOUNCEMENT_SCHEMA_V1_CHIRHO: &str = "key-custody-announcement-v1-chirho";
const ANNOUNCEMENT_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"cairn-key-custody-announcement-v1-chirho";
/// Any fixed scalar: X25519 clamps it to a multiple of the cofactor, so every small-order point maps
/// to all zeros under it, which is how a rejected point is detected.
const POINT_CHECK_SCALAR_CHIRHO: [u8; 32] = [0x55; 32];

/// This node's X25519 custody secret. It is never printed, serialized or compared.
pub struct NodeCustodySecretChirho {
    secret_chirho: Zeroizing<[u8; 32]>,
}

impl NodeCustodySecretChirho {
    /// Derive the custody secret from the node-control signing key's seed.
    pub fn derive_from_node_signing_key_chirho(node_key_chirho: &SigningKey) -> Self {
        let seed_chirho = Zeroizing::new(node_key_chirho.to_bytes());
        Self {
            secret_chirho: Zeroizing::new(blake3::derive_key(
                CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO,
                &*seed_chirho,
            )),
        }
    }

    /// The custody secret from bytes ALREADY derived as
    /// `blake3::derive_key(CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO, node signing-key seed)`, for a holder
    /// whose signing key never leaves its signer (the signer's existing-key derivation). For the same
    /// key it equals `derive_from_node_signing_key_chirho`.
    pub fn from_derived_secret_chirho(derived_chirho: Zeroizing<[u8; 32]>) -> Self {
        Self {
            secret_chirho: derived_chirho,
        }
    }

    pub fn public_bytes_chirho(&self) -> [u8; 32] {
        x25519(*self.secret_chirho, X25519_BASEPOINT_BYTES)
    }

    /// The shared secret with a peer's public key, refused when the peer key is a rejected point.
    pub(crate) fn diffie_hellman_chirho(
        &self,
        peer_public_chirho: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, KeyCustodyErrorChirho> {
        diffie_hellman_bytes_chirho(&self.secret_chirho, peer_public_chirho)
    }
}

impl fmt::Debug for NodeCustodySecretChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str("NodeCustodySecretChirho(..)")
    }
}

/// X25519 of a secret and a peer point, refused if the result is all zeros (a small-order point).
pub(crate) fn diffie_hellman_bytes_chirho(
    secret_chirho: &[u8; 32],
    peer_public_chirho: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, KeyCustodyErrorChirho> {
    let shared_chirho = Zeroizing::new(x25519(*secret_chirho, *peer_public_chirho));
    if shared_chirho.iter().all(|byte_chirho| *byte_chirho == 0) {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyPointRejectedChirho,
            "the shared secret is all zeros",
        ));
    }
    Ok(shared_chirho)
}

/// Refuse a public point that any clamped scalar sends to all zeros.
pub(crate) fn check_custody_point_chirho(
    public_chirho: &[u8; 32],
) -> Result<(), KeyCustodyErrorChirho> {
    if x25519(POINT_CHECK_SCALAR_CHIRHO, *public_chirho)
        .iter()
        .all(|byte_chirho| *byte_chirho == 0)
    {
        return Err(refuse_chirho(
            KeyCustodyRefusalIdentityChirho::CustodyPointRejectedChirho,
            "the custody public key is a small-order point",
        ));
    }
    Ok(())
}

/// A node's signed statement of its custody public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyAnnouncementV1Chirho {
    schema_chirho: String,
    node_id_chirho: String,
    custody_public_hex_chirho: String,
    sig_hex_chirho: String,
}

/// An announcement built from this node's own custody secret, digested but not yet signed. Production
/// signs `signing_digest_chirho` through the node signer, which never hands the node key out.
pub struct PreparedCustodyAnnouncementChirho {
    announcement_chirho: CustodyAnnouncementV1Chirho,
}

impl PreparedCustodyAnnouncementChirho {
    pub fn new_chirho(
        node_id_chirho: impl Into<String>,
        custody_secret_chirho: &NodeCustodySecretChirho,
    ) -> Result<Self, KeyCustodyErrorChirho> {
        let node_id_chirho = node_id_chirho.into();
        if !valid_lower_hex_chirho(&node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO) {
            return Err(refuse_chirho(
                KeyCustodyRefusalIdentityChirho::CustodyAnnouncementInvalidChirho,
                "node id is not canonical hex",
            ));
        }
        Ok(Self {
            announcement_chirho: CustodyAnnouncementV1Chirho {
                schema_chirho: CUSTODY_ANNOUNCEMENT_SCHEMA_V1_CHIRHO.to_string(),
                node_id_chirho,
                custody_public_hex_chirho: hex_chirho(&custody_secret_chirho.public_bytes_chirho()),
                sig_hex_chirho: String::new(),
            },
        })
    }

    pub fn signing_digest_chirho(&self) -> [u8; 32] {
        announcement_digest_chirho(
            &self.announcement_chirho.node_id_chirho,
            &self.announcement_chirho.custody_public_hex_chirho,
        )
    }

    pub fn into_signed_chirho(
        mut self,
        sig_hex_chirho: String,
    ) -> Result<CustodyAnnouncementV1Chirho, KeyCustodyErrorChirho> {
        validate_signature_hex_chirho(
            &sig_hex_chirho,
            KeyCustodyRefusalIdentityChirho::CustodyAnnouncementInvalidChirho,
        )?;
        self.announcement_chirho.sig_hex_chirho = sig_hex_chirho;
        Ok(self.announcement_chirho)
    }
}

/// An announcement whose node signed it and whose key is an accepted point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCustodyAnnouncementChirho {
    node_id_chirho: String,
    custody_public_chirho: [u8; 32],
}

impl VerifiedCustodyAnnouncementChirho {
    pub fn node_id_chirho(&self) -> &str {
        &self.node_id_chirho
    }

    pub fn custody_public_chirho(&self) -> &[u8; 32] {
        &self.custody_public_chirho
    }
}

pub(crate) fn announcement_digest_chirho(
    node_id_chirho: &str,
    custody_public_hex_chirho: &str,
) -> [u8; 32] {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(ANNOUNCEMENT_DIGEST_DOMAIN_V1_CHIRHO);
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"schema-chirho",
        CUSTODY_ANNOUNCEMENT_SCHEMA_V1_CHIRHO.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"node-id-chirho",
        node_id_chirho.as_bytes(),
    );
    update_digest_field_chirho(
        &mut hasher_chirho,
        b"custody-public-chirho",
        custody_public_hex_chirho.as_bytes(),
    );
    *hasher_chirho.finalize().as_bytes()
}

impl CustodyAnnouncementV1Chirho {
    pub fn node_id_chirho(&self) -> &str {
        &self.node_id_chirho
    }

    /// Accept the announcement only if it is in form, its key is an accepted point that is neither
    /// the node id nor the key a derivation from public bytes would give, and its node signed it.
    pub fn verify_chirho(
        &self,
    ) -> Result<VerifiedCustodyAnnouncementChirho, KeyCustodyErrorChirho> {
        let invalid_chirho = KeyCustodyRefusalIdentityChirho::CustodyAnnouncementInvalidChirho;
        if self.schema_chirho != CUSTODY_ANNOUNCEMENT_SCHEMA_V1_CHIRHO
            || !valid_lower_hex_chirho(&self.node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO)
            || !valid_lower_hex_chirho(&self.custody_public_hex_chirho, NODE_ID_HEX_BYTES_CHIRHO)
        {
            return Err(refuse_chirho(
                invalid_chirho,
                "announcement fields are not in form",
            ));
        }
        let custody_public_chirho = decode_hex_32_chirho(&self.custody_public_hex_chirho)
            .ok_or_else(|| refuse_chirho(invalid_chirho, "custody key is not 32 bytes"))?;
        check_custody_point_chirho(&custody_public_chirho)?;
        let node_public_chirho = decode_hex_32_chirho(&self.node_id_chirho)
            .ok_or_else(|| refuse_chirho(invalid_chirho, "node id is not 32 bytes"))?;
        if custody_public_chirho == node_public_chirho {
            return Err(refuse_chirho(
                invalid_chirho,
                "the custody key is the node's signing public key",
            ));
        }
        let derived_from_public_chirho = x25519(
            blake3::derive_key(CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO, &node_public_chirho),
            X25519_BASEPOINT_BYTES,
        );
        if custody_public_chirho == derived_from_public_chirho {
            return Err(refuse_chirho(
                invalid_chirho,
                "the custody key was derived from public bytes, so every peer knows its secret",
            ));
        }
        verify_node_signature_chirho(
            &self.node_id_chirho,
            &announcement_digest_chirho(&self.node_id_chirho, &self.custody_public_hex_chirho),
            &self.sig_hex_chirho,
            invalid_chirho,
        )?;
        Ok(VerifiedCustodyAnnouncementChirho {
            node_id_chirho: self.node_id_chirho.clone(),
            custody_public_chirho,
        })
    }
}
