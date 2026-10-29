// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The wrap: only the bound holder opens it, only under its exact binding, a dishonest leader is caught at open, and records keep the root's key-file shape.

use super::world_chirho::{
    key_id_chirho, record_chirho, world_chirho, OTHER_SUBJECT_CHIRHO, SUBJECT_CHIRHO,
};
use crate::custody_chirho::binding_chirho::{subject_digest_hex_chirho, CustodyBindingChirho};
use crate::custody_chirho::wrap_chirho::{
    open_wrapped_key_chirho, seal_wrapped_key_chirho, wrap_aad_chirho, wrap_key_chirho,
    ShredKeyRecordChirho, WrappedKeyPayloadChirho,
};
use crate::digest_chirho::hex_chirho;
use crate::refusal_chirho::KeyCustodyRefusalIdentityChirho;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

#[test]
fn a_sealed_key_opens_only_for_its_holder_chirho() {
    let world_chirho = world_chirho();
    let binding_chirho = world_chirho.binding_chirho(
        &world_chirho.peer_one_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
    );
    let record_chirho = record_chirho(SUBJECT_CHIRHO, 0x11);
    let wrapped_chirho = seal_wrapped_key_chirho(
        &record_chirho,
        &world_chirho.peer_one_chirho.announcement_chirho(),
        &binding_chirho,
    )
    .unwrap();
    let opened_chirho = open_wrapped_key_chirho(
        &wrapped_chirho,
        &world_chirho.peer_one_chirho.custody_secret_chirho(),
        &binding_chirho,
    )
    .unwrap();
    assert!(opened_chirho.same_record_chirho(&record_chirho));
    let error_chirho = open_wrapped_key_chirho(
        &wrapped_chirho,
        &world_chirho.peer_two_chirho.custody_secret_chirho(),
        &binding_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyUnwrapFailedChirho
    );
}

/// One edit to a binding, for the every-field arm.
type BindingMutationChirho = Box<dyn Fn(&mut CustodyBindingChirho)>;

#[test]
fn changing_any_bound_field_stops_the_open_chirho() {
    let world_chirho = world_chirho();
    let binding_chirho = world_chirho.binding_chirho(
        &world_chirho.peer_one_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
    );
    let wrapped_chirho = seal_wrapped_key_chirho(
        &record_chirho(SUBJECT_CHIRHO, 0x11),
        &world_chirho.peer_one_chirho.announcement_chirho(),
        &binding_chirho,
    )
    .unwrap();
    let other_node_chirho = world_chirho.peer_two_chirho.id_chirho.clone();
    let mutations_chirho: Vec<(&str, BindingMutationChirho)> = vec![
        (
            "group",
            Box::new(|b_chirho| b_chirho.consistency_group_digest_chirho = "1".repeat(64)),
        ),
        (
            "view",
            Box::new(|b_chirho| b_chirho.membership_view_digest_chirho = "2".repeat(64)),
        ),
        (
            "term",
            Box::new(|b_chirho| b_chirho.elected_term_chirho += 1),
        ),
        (
            "origin",
            Box::new({
                let node_chirho = other_node_chirho.clone();
                move |b_chirho| b_chirho.origin_node_id_chirho = node_chirho.clone()
            }),
        ),
        (
            "holder",
            Box::new(move |b_chirho| b_chirho.holder_node_id_chirho = other_node_chirho.clone()),
        ),
        (
            "key id",
            Box::new(|b_chirho| b_chirho.key_id_chirho = key_id_chirho(2)),
        ),
        (
            "subject",
            Box::new(|b_chirho| {
                b_chirho.subject_digest_chirho = subject_digest_hex_chirho(OTHER_SUBJECT_CHIRHO)
            }),
        ),
        (
            "ciphertext",
            Box::new(|b_chirho| b_chirho.ciphertext_addr_chirho = "3".repeat(64)),
        ),
        (
            "blob seq",
            Box::new(|b_chirho| b_chirho.blob_seq_chirho += 1),
        ),
    ];
    let secret_chirho = world_chirho.peer_one_chirho.custody_secret_chirho();
    for (name_chirho, mutate_chirho) in mutations_chirho {
        let mut changed_chirho = binding_chirho.clone();
        mutate_chirho(&mut changed_chirho);
        let error_chirho =
            open_wrapped_key_chirho(&wrapped_chirho, &secret_chirho, &changed_chirho).unwrap_err();
        assert_eq!(
            error_chirho.identity_chirho(),
            KeyCustodyRefusalIdentityChirho::CustodyUnwrapFailedChirho,
            "{name_chirho}"
        );
    }
}

#[test]
fn the_leader_cannot_seal_to_a_holder_or_subject_the_binding_does_not_name_chirho() {
    let world_chirho = world_chirho();
    let binding_chirho = world_chirho.binding_chirho(
        &world_chirho.peer_one_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
    );
    let wrong_holder_chirho = seal_wrapped_key_chirho(
        &record_chirho(SUBJECT_CHIRHO, 0x11),
        &world_chirho.peer_two_chirho.announcement_chirho(),
        &binding_chirho,
    )
    .unwrap_err();
    assert_eq!(
        wrong_holder_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyHolderMismatchChirho
    );
    let wrong_subject_chirho = seal_wrapped_key_chirho(
        &record_chirho(OTHER_SUBJECT_CHIRHO, 0x11),
        &world_chirho.peer_one_chirho.announcement_chirho(),
        &binding_chirho,
    )
    .unwrap_err();
    assert_eq!(
        wrong_subject_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodySubjectMismatchChirho
    );
}

#[test]
fn a_dishonest_seal_of_another_subject_is_refused_at_open_chirho() {
    // A leader that skips the seal-time check wraps another subject's key under this binding. The wrap
    // itself is valid, so only the open-time subject check can refuse it.
    let world_chirho = world_chirho();
    let binding_chirho = world_chirho.binding_chirho(
        &world_chirho.peer_one_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
    );
    let holder_public_chirho = *world_chirho
        .peer_one_chirho
        .announcement_chirho()
        .custody_public_chirho();
    let ephemeral_secret_chirho = [0x42_u8; 32];
    let ephemeral_public_chirho = x25519(ephemeral_secret_chirho, X25519_BASEPOINT_BYTES);
    let shared_chirho = x25519(ephemeral_secret_chirho, holder_public_chirho);
    let wrap_key_value_chirho = wrap_key_chirho(
        &shared_chirho,
        &ephemeral_public_chirho,
        &holder_public_chirho,
    );
    let nonce_chirho = [7_u8; 24];
    let plaintext_chirho = serde_json::to_vec(&record_chirho(OTHER_SUBJECT_CHIRHO, 0x22)).unwrap();
    let ciphertext_chirho = XChaCha20Poly1305::new(Key::from_slice(&wrap_key_value_chirho[..]))
        .encrypt(
            XNonce::from_slice(&nonce_chirho),
            Payload {
                msg: &plaintext_chirho,
                aad: &wrap_aad_chirho(&binding_chirho),
            },
        )
        .unwrap();
    let wrapped_chirho = WrappedKeyPayloadChirho {
        ephemeral_public_hex_chirho: hex_chirho(&ephemeral_public_chirho),
        nonce_hex_chirho: hex_chirho(&nonce_chirho),
        ciphertext_hex_chirho: hex_chirho(&ciphertext_chirho),
    };
    let error_chirho = open_wrapped_key_chirho(
        &wrapped_chirho,
        &world_chirho.peer_one_chirho.custody_secret_chirho(),
        &binding_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodySubjectMismatchChirho
    );
}

#[test]
fn key_records_refuse_bad_shapes_and_store_in_the_root_format_chirho() {
    for (subject_chirho, key_chirho) in [
        (SUBJECT_CHIRHO, "ab".repeat(31)),
        (SUBJECT_CHIRHO, "AB".repeat(32)),
        ("a subject with spaces", "ab".repeat(32)),
        ("", "ab".repeat(32)),
    ] {
        assert_eq!(
            ShredKeyRecordChirho::new_chirho(subject_chirho, key_chirho)
                .unwrap_err()
                .identity_chirho(),
            KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho
        );
    }
    // The root writes `serde_json::to_vec_pretty` of exactly these two fields, in this order.
    #[derive(serde::Serialize)]
    struct RootShredKeyChirho {
        subject_chirho: String,
        key_hex_chirho: String,
    }
    let record_chirho = record_chirho(SUBJECT_CHIRHO, 0x33);
    let expected_chirho = serde_json::to_vec_pretty(&RootShredKeyChirho {
        subject_chirho: SUBJECT_CHIRHO.to_string(),
        key_hex_chirho: "33".repeat(32),
    })
    .unwrap();
    let bytes_chirho = record_chirho.to_key_file_bytes_chirho().unwrap();
    assert_eq!(&bytes_chirho[..], &expected_chirho[..]);
    assert!(
        ShredKeyRecordChirho::from_key_file_bytes_chirho(&bytes_chirho)
            .unwrap()
            .same_record_chirho(&record_chirho)
    );
    let extra_chirho = br#"{"subject_chirho":"s","key_hex_chirho":"ab","extra_chirho":1}"#;
    assert_eq!(
        ShredKeyRecordChirho::from_key_file_bytes_chirho(extra_chirho)
            .unwrap_err()
            .identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyKeyRecordMalformedChirho
    );
}
