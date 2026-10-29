// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Domain-separated digest, canonical-hex, and ed25519 primitives shared by the mirror's frames,
//! manifest, and receipt — copied length-prefixed field hashing (the relay's is private) so each
//! caller supplies its OWN domain constant and a mirror frame digest can never collide with a relay
//! envelope digest.

use crate::refusal_chirho::{MirrorContractErrorChirho, MirrorRefusalIdentityChirho};
use ed25519_dalek::{Signature, VerifyingKey};

pub(crate) const NODE_ID_HEX_BYTES_CHIRHO: usize = 64;
pub(crate) const DIGEST_HEX_BYTES_CHIRHO: usize = 64;
pub(crate) const SIGNATURE_HEX_BYTES_CHIRHO: usize = 128;
/// A private-blob key id is a 16-byte blake3-derived id => 32 lowercase hex chars. A value of
/// 64 hex (32 bytes) in the key-id slot is key-material-shaped and refused (defense-in-depth A4).
pub(crate) const KEY_ID_HEX_BYTES_CHIRHO: usize = 32;
/// A private-blob nonce is 24 bytes => 48 lowercase hex chars.
pub(crate) const NONCE_HEX_BYTES_CHIRHO: usize = 48;
/// A MAC hex is a 32-byte blake3 keyed digest => 64 lowercase hex chars.
pub(crate) const MAC_HEX_BYTES_CHIRHO: usize = 64;

/// Append one length-prefixed labelled field to a hasher. The label and value are each length-tagged
/// so no two distinct field layouts can hash the same — the same construction the relay uses, copied
/// because the relay's helper is private.
pub(crate) fn update_digest_field_chirho(
    hasher_chirho: &mut blake3::Hasher,
    label_chirho: &[u8],
    bytes_chirho: &[u8],
) {
    hasher_chirho.update(&(label_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(label_chirho);
    hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(bytes_chirho);
}

pub(crate) fn valid_lower_hex_chirho(value_chirho: &str, exact_len_chirho: usize) -> bool {
    value_chirho.len() == exact_len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

/// Verify an ed25519 signature over a 32-byte digest against a node id that IS the signer's public
/// key (hex). `verify_strict` rejects the small-order / malleable edge cases.
pub(crate) fn verify_node_signature_chirho(
    node_id_chirho: &str,
    digest_hex_chirho: &str,
    sig_hex_chirho: &str,
    identity_chirho: MirrorRefusalIdentityChirho,
) -> Result<(), MirrorContractErrorChirho> {
    let public_key_chirho = decode_hex_32_chirho(node_id_chirho).ok_or_else(|| {
        MirrorContractErrorChirho::new_chirho(
            MirrorRefusalIdentityChirho::MirrorOriginNodeInvalidChirho,
            "mirror signer node id is not a canonical public key",
        )
    })?;
    let digest_chirho = decode_hex_32_chirho(digest_hex_chirho).ok_or_else(|| {
        MirrorContractErrorChirho::new_chirho(identity_chirho, "mirror signed digest is invalid")
    })?;
    let signature_bytes_chirho = decode_hex_chirho(sig_hex_chirho).ok_or_else(|| {
        MirrorContractErrorChirho::new_chirho(identity_chirho, "mirror signature is invalid")
    })?;
    let signature_chirho = Signature::from_slice(&signature_bytes_chirho).map_err(|_| {
        MirrorContractErrorChirho::new_chirho(identity_chirho, "mirror signature is invalid")
    })?;
    let verifying_key_chirho = VerifyingKey::from_bytes(&public_key_chirho).map_err(|_| {
        MirrorContractErrorChirho::new_chirho(identity_chirho, "mirror signer key is invalid")
    })?;
    verifying_key_chirho
        .verify_strict(&digest_chirho, &signature_chirho)
        .map_err(|_| {
            MirrorContractErrorChirho::new_chirho(
                identity_chirho,
                "mirror signature does not verify",
            )
        })
}

pub(crate) fn decode_hex_32_chirho(value_chirho: &str) -> Option<[u8; 32]> {
    decode_hex_chirho(value_chirho)?.try_into().ok()
}

pub(crate) fn decode_hex_chirho(value_chirho: &str) -> Option<Vec<u8>> {
    if !value_chirho.len().is_multiple_of(2) {
        return None;
    }
    value_chirho
        .as_bytes()
        .chunks_exact(2)
        .map(|pair_chirho| {
            let high_chirho = hex_nibble_chirho(pair_chirho[0])?;
            let low_chirho = hex_nibble_chirho(pair_chirho[1])?;
            Some((high_chirho << 4) | low_chirho)
        })
        .collect()
}

fn hex_nibble_chirho(byte_chirho: u8) -> Option<u8> {
    match byte_chirho {
        b'0'..=b'9' => Some(byte_chirho - b'0'),
        b'a'..=b'f' => Some(byte_chirho - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn validate_signature_hex_chirho(
    signature_chirho: &str,
    identity_chirho: MirrorRefusalIdentityChirho,
) -> Result<(), MirrorContractErrorChirho> {
    if !valid_lower_hex_chirho(signature_chirho, SIGNATURE_HEX_BYTES_CHIRHO) {
        return Err(MirrorContractErrorChirho::new_chirho(
            identity_chirho,
            "mirror signature must be canonical lowercase hex",
        ));
    }
    Ok(())
}
