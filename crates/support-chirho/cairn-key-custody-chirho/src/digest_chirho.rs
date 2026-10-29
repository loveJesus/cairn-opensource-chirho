// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Domain-separated field hashing, canonical lowercase hex, key-id set checks and node-signature verification for the custody contract.

use crate::refusal_chirho::{
    refuse_chirho, KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho,
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::BTreeSet;

pub(crate) const NODE_ID_HEX_BYTES_CHIRHO: usize = 64;
pub(crate) const DIGEST_HEX_BYTES_CHIRHO: usize = 64;
/// A private-blob key id is 16 bytes of BLAKE3 output, so 32 lowercase hex characters. A 64-character
/// value in the key-id slot is key-material-shaped, and the exact-length check refuses it.
pub(crate) const KEY_ID_HEX_BYTES_CHIRHO: usize = 32;
pub(crate) const SIGNATURE_HEX_BYTES_CHIRHO: usize = 128;
/// The most key ids one erasure frame or receipt may name.
pub const ERASURE_MAX_KEY_IDS_CHIRHO: usize = 4096;

/// Append one length-prefixed labelled field, so no two distinct field layouts hash the same.
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

/// Bind an optional lease duration the same way the mirror frames do: a presence byte, then the value.
pub(crate) fn update_lease_field_chirho(
    hasher_chirho: &mut blake3::Hasher,
    lease_chirho: Option<u64>,
) {
    match lease_chirho {
        Some(value_chirho) => {
            update_digest_field_chirho(hasher_chirho, b"lease-present-chirho", &[1]);
            update_digest_field_chirho(
                hasher_chirho,
                b"lease-remaining-millis-chirho",
                &value_chirho.to_le_bytes(),
            );
        }
        None => update_digest_field_chirho(hasher_chirho, b"lease-present-chirho", &[0]),
    }
}

/// Bind an ordered set of key ids: its count, then each id.
pub(crate) fn update_key_ids_field_chirho<'a>(
    hasher_chirho: &mut blake3::Hasher,
    label_chirho: &[u8],
    key_ids_chirho: impl ExactSizeIterator<Item = &'a String>,
) {
    update_digest_field_chirho(
        hasher_chirho,
        label_chirho,
        &(key_ids_chirho.len() as u64).to_le_bytes(),
    );
    for key_id_chirho in key_ids_chirho {
        update_digest_field_chirho(hasher_chirho, b"key-id-chirho", key_id_chirho.as_bytes());
    }
}

pub(crate) fn valid_lower_hex_chirho(value_chirho: &str, exact_len_chirho: usize) -> bool {
    value_chirho.len() == exact_len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

/// A wire list of key ids is in form when it is strictly ascending (so sorted and unique), bounded,
/// and every id is a canonical 32-hex key id.
pub(crate) fn valid_key_id_list_chirho(key_ids_chirho: &[String]) -> bool {
    key_ids_chirho.len() <= ERASURE_MAX_KEY_IDS_CHIRHO
        && key_ids_chirho
            .iter()
            .all(|key_id_chirho| valid_lower_hex_chirho(key_id_chirho, KEY_ID_HEX_BYTES_CHIRHO))
        && key_ids_chirho
            .windows(2)
            .all(|pair_chirho| pair_chirho[0] < pair_chirho[1])
}

pub(crate) fn key_id_list_chirho(key_ids_chirho: &BTreeSet<String>) -> Vec<String> {
    key_ids_chirho.iter().cloned().collect()
}

pub(crate) fn hex_chirho(bytes_chirho: &[u8]) -> String {
    const DIGITS_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut out_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        out_chirho.push(DIGITS_CHIRHO[(byte_chirho >> 4) as usize] as char);
        out_chirho.push(DIGITS_CHIRHO[(byte_chirho & 0x0f) as usize] as char);
    }
    out_chirho
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

pub(crate) fn decode_hex_32_chirho(value_chirho: &str) -> Option<[u8; 32]> {
    decode_hex_chirho(value_chirho)?.try_into().ok()
}

fn hex_nibble_chirho(byte_chirho: u8) -> Option<u8> {
    match byte_chirho {
        b'0'..=b'9' => Some(byte_chirho - b'0'),
        b'a'..=b'f' => Some(byte_chirho - b'a' + 10),
        _ => None,
    }
}

/// A signature passed to `into_signed_chirho` must at least be canonical 64-byte hex.
pub(crate) fn validate_signature_hex_chirho(
    sig_hex_chirho: &str,
    identity_chirho: KeyCustodyRefusalIdentityChirho,
) -> Result<(), KeyCustodyErrorChirho> {
    if !valid_lower_hex_chirho(sig_hex_chirho, SIGNATURE_HEX_BYTES_CHIRHO) {
        return Err(refuse_chirho(
            identity_chirho,
            "signature is not canonical hex",
        ));
    }
    Ok(())
}

/// Verify an ed25519 signature over a 32-byte digest against a node id that is the signer's public
/// key. `verify_strict` rejects the small-order and malleable edge cases.
pub(crate) fn verify_node_signature_chirho(
    node_id_chirho: &str,
    digest_chirho: &[u8; 32],
    sig_hex_chirho: &str,
    identity_chirho: KeyCustodyRefusalIdentityChirho,
) -> Result<(), KeyCustodyErrorChirho> {
    if !valid_lower_hex_chirho(node_id_chirho, NODE_ID_HEX_BYTES_CHIRHO)
        || !valid_lower_hex_chirho(sig_hex_chirho, SIGNATURE_HEX_BYTES_CHIRHO)
    {
        return Err(refuse_chirho(
            identity_chirho,
            "signer or signature is not canonical hex",
        ));
    }
    let public_chirho = decode_hex_32_chirho(node_id_chirho)
        .ok_or_else(|| refuse_chirho(identity_chirho, "signer is not a public key"))?;
    let signature_bytes_chirho = decode_hex_chirho(sig_hex_chirho)
        .ok_or_else(|| refuse_chirho(identity_chirho, "signature is not hex"))?;
    let signature_chirho = Signature::from_slice(&signature_bytes_chirho)
        .map_err(|_| refuse_chirho(identity_chirho, "signature is not a signature"))?;
    let verifying_key_chirho = VerifyingKey::from_bytes(&public_chirho)
        .map_err(|_| refuse_chirho(identity_chirho, "signer key is invalid"))?;
    verifying_key_chirho
        .verify_strict(digest_chirho, &signature_chirho)
        .map_err(|_| refuse_chirho(identity_chirho, "signature does not verify"))
}
