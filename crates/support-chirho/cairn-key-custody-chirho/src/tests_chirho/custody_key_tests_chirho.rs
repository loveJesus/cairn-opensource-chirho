// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The custody key: derivation from the node seed, and every way an announcement refuses even when its node signed it.

use super::world_chirho::node_chirho;
use crate::custody_key_chirho::{
    announcement_digest_chirho, CustodyAnnouncementV1Chirho, CUSTODY_ANNOUNCEMENT_SCHEMA_V1_CHIRHO,
    CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO,
};
use crate::digest_chirho::{decode_hex_32_chirho, hex_chirho};
use crate::refusal_chirho::KeyCustodyRefusalIdentityChirho;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// An announcement of any chosen key, properly signed by node `seed_chirho`, so only the check under
/// test can refuse it.
fn signed_announcement_chirho(
    seed_chirho: u8,
    custody_public_hex_chirho: &str,
) -> CustodyAnnouncementV1Chirho {
    let node_chirho = node_chirho(seed_chirho);
    let sig_chirho = node_chirho.sign_chirho(&announcement_digest_chirho(
        &node_chirho.id_chirho,
        custody_public_hex_chirho,
    ));
    serde_json::from_value(serde_json::json!({
        "schema_chirho": CUSTODY_ANNOUNCEMENT_SCHEMA_V1_CHIRHO,
        "node_id_chirho": node_chirho.id_chirho,
        "custody_public_hex_chirho": custody_public_hex_chirho,
        "sig_hex_chirho": sig_chirho,
    }))
    .expect("announcement json")
}

#[test]
fn the_custody_key_comes_from_the_seed_and_is_not_the_node_id_chirho() {
    let node_chirho = node_chirho(1);
    let public_chirho = node_chirho.custody_secret_chirho().public_bytes_chirho();
    assert_eq!(
        public_chirho,
        node_chirho.custody_secret_chirho().public_bytes_chirho()
    );
    assert_ne!(
        public_chirho,
        super::world_chirho::node_chirho(2)
            .custody_secret_chirho()
            .public_bytes_chirho()
    );
    assert_ne!(hex_chirho(&public_chirho), node_chirho.id_chirho);
    let announcement_chirho = node_chirho.announcement_chirho();
    assert_eq!(announcement_chirho.node_id_chirho(), node_chirho.id_chirho);
    assert_eq!(announcement_chirho.custody_public_chirho(), &public_chirho);
}

/// A holder whose signing key never leaves its signer builds the same custody secret from bytes the
/// signer derived, so a frame wrapped to its announced key opens.
#[test]
fn a_custody_secret_from_derived_bytes_equals_the_seed_derivation_chirho() {
    let node_chirho = node_chirho(3);
    let derived_chirho = zeroize::Zeroizing::new(blake3::derive_key(
        CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO,
        &node_chirho.key_chirho.to_bytes(),
    ));
    assert_eq!(
        crate::custody_key_chirho::NodeCustodySecretChirho::from_derived_secret_chirho(
            derived_chirho
        )
        .public_bytes_chirho(),
        node_chirho.custody_secret_chirho().public_bytes_chirho()
    );
}

#[test]
fn an_announcement_with_a_swapped_key_refuses_chirho() {
    let honest_chirho = signed_announcement_chirho(
        1,
        &hex_chirho(&node_chirho(1).custody_secret_chirho().public_bytes_chirho()),
    );
    honest_chirho
        .verify_chirho()
        .expect("the honest announcement verifies");
    let mut value_chirho = serde_json::to_value(&honest_chirho).unwrap();
    value_chirho["custody_public_hex_chirho"] =
        hex_chirho(&node_chirho(2).custody_secret_chirho().public_bytes_chirho()).into();
    let swapped_chirho: CustodyAnnouncementV1Chirho = serde_json::from_value(value_chirho).unwrap();
    let error_chirho = swapped_chirho.verify_chirho().unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyAnnouncementInvalidChirho
    );
    assert_eq!(error_chirho.detail_chirho(), "signature does not verify");
}

#[test]
fn a_small_order_custody_key_refuses_even_when_signed_chirho() {
    let mut order_four_chirho = [0_u8; 32];
    order_four_chirho[0] = 1;
    for point_chirho in [[0_u8; 32], order_four_chirho] {
        let error_chirho = signed_announcement_chirho(1, &hex_chirho(&point_chirho))
            .verify_chirho()
            .unwrap_err();
        assert_eq!(
            error_chirho.identity_chirho(),
            KeyCustodyRefusalIdentityChirho::CustodyPointRejectedChirho
        );
    }
}

#[test]
fn a_custody_key_equal_to_the_node_id_refuses_even_when_signed_chirho() {
    let node_chirho = node_chirho(1);
    let error_chirho = signed_announcement_chirho(1, &node_chirho.id_chirho)
        .verify_chirho()
        .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyAnnouncementInvalidChirho
    );
    assert_eq!(
        error_chirho.detail_chirho(),
        "the custody key is the node's signing public key"
    );
}

#[test]
fn a_custody_key_derived_from_public_bytes_refuses_even_when_signed_chirho() {
    let node_chirho = node_chirho(1);
    let node_public_chirho = decode_hex_32_chirho(&node_chirho.id_chirho).unwrap();
    let mistaken_chirho = x25519(
        blake3::derive_key(CUSTODY_KEY_DERIVATION_CONTEXT_CHIRHO, &node_public_chirho),
        X25519_BASEPOINT_BYTES,
    );
    let error_chirho = signed_announcement_chirho(1, &hex_chirho(&mistaken_chirho))
        .verify_chirho()
        .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyAnnouncementInvalidChirho
    );
    assert_eq!(
        error_chirho.detail_chirho(),
        "the custody key was derived from public bytes, so every peer knows its secret"
    );
}
