// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Custody receipts, and the leader's confirmation that both other serving holders hold one exact key across three failure domains.

use super::world_chirho::{key_id_chirho, world_chirho, SUBJECT_CHIRHO};
use crate::custody_chirho::binding_chirho::subject_digest_hex_chirho;
use crate::custody_chirho::receipt_chirho::{
    confirm_key_custody_chirho, CustodyKeyCoordinatesChirho, CustodyReceiptV1Chirho,
};
use crate::refusal_chirho::KeyCustodyRefusalIdentityChirho;
use cairn_mirror_chirho::{
    MirrorHolderSetChirho, MirrorRefusalIdentityChirho, MirrorResidencyPolicyChirho,
};
use std::collections::BTreeSet;

/// The coordinates the world's binding uses for key `key_chirho` at blob seq `blob_seq_chirho`.
fn coordinates_chirho(key_chirho: u8, blob_seq_chirho: u64) -> CustodyKeyCoordinatesChirho {
    CustodyKeyCoordinatesChirho {
        key_id_chirho: key_id_chirho(key_chirho),
        subject_digest_chirho: subject_digest_hex_chirho(SUBJECT_CHIRHO),
        ciphertext_addr_chirho: format!("{:064x}", blob_seq_chirho + 7),
        blob_seq_chirho,
    }
}

#[test]
fn a_receipt_verifies_only_when_its_holder_signed_its_exact_fields_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let receipt_chirho =
        world_chirho.custody_receipt_chirho(holder_chirho, &key_id_chirho(1), SUBJECT_CHIRHO, 3);
    assert_eq!(
        receipt_chirho.binding_chirho().holder_node_id_chirho,
        holder_chirho.id_chirho
    );
    // The leader signs a receipt in the holder's name.
    let forged_chirho = world_chirho.signed_custody_receipt_chirho(
        holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        &world_chirho.leader_chirho,
    );
    let error_chirho = forged_chirho.verify_chirho().unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyReceiptInvalidChirho
    );
    assert_eq!(error_chirho.detail_chirho(), "signature does not verify");
    // An honest receipt edited after signing.
    let honest_chirho = world_chirho.signed_custody_receipt_chirho(
        holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        holder_chirho,
    );
    let mut value_chirho = serde_json::to_value(&honest_chirho).unwrap();
    value_chirho["binding_chirho"]["blob_seq_chirho"] = 4.into();
    let edited_chirho: CustodyReceiptV1Chirho = serde_json::from_value(value_chirho).unwrap();
    let error_chirho = edited_chirho.verify_chirho().unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyReceiptInvalidChirho
    );
    assert_eq!(
        error_chirho.detail_chirho(),
        "the receipt digest does not bind its fields"
    );
}

#[test]
fn custody_is_confirmed_only_by_both_peers_for_exactly_this_key_chirho() {
    let world_chirho = world_chirho();
    let holder_set_chirho = MirrorHolderSetChirho::select_chirho(
        world_chirho.joined_chirho.view_chirho(),
        &world_chirho.leader_chirho.id_chirho,
        &MirrorResidencyPolicyChirho::AnyDomainChirho,
    )
    .unwrap();
    let one_chirho = world_chirho.custody_receipt_chirho(
        &world_chirho.peer_one_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
    );
    let two_chirho = world_chirho.custody_receipt_chirho(
        &world_chirho.peer_two_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
    );
    let confirmed_chirho = confirm_key_custody_chirho(
        &world_chirho.joined_chirho,
        &holder_set_chirho,
        &coordinates_chirho(1, 3),
        &[two_chirho.clone(), one_chirho.clone()],
    )
    .unwrap();
    assert_eq!(
        confirmed_chirho.leader_node_id_chirho(),
        world_chirho.leader_chirho.id_chirho
    );
    let domains_chirho = confirmed_chirho
        .covered_failure_domains_chirho()
        .iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(domains_chirho.len(), 3, "three distinct failure domains");
    let digests_chirho = confirmed_chirho
        .holder_receipt_digests_chirho()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        digests_chirho,
        [
            one_chirho.receipt_digest_chirho(),
            two_chirho.receipt_digest_chirho()
        ]
        .into_iter()
        .collect()
    );
    let incomplete_chirho = KeyCustodyRefusalIdentityChirho::CustodyConfirmationIncompleteChirho;
    let confirm_with_chirho = |receipts_chirho: &[_]| {
        confirm_key_custody_chirho(
            &world_chirho.joined_chirho,
            &holder_set_chirho,
            &coordinates_chirho(1, 3),
            receipts_chirho,
        )
        .unwrap_err()
        .identity_chirho()
    };
    // One peer missing; the same peer twice; the other peer holding a different blob of the key.
    assert_eq!(
        confirm_with_chirho(std::slice::from_ref(&one_chirho)),
        incomplete_chirho
    );
    assert_eq!(
        confirm_with_chirho(&[one_chirho.clone(), one_chirho.clone()]),
        incomplete_chirho
    );
    let other_blob_chirho = world_chirho.custody_receipt_chirho(
        &world_chirho.peer_two_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        4,
    );
    assert_eq!(
        confirm_with_chirho(&[one_chirho, other_blob_chirho]),
        incomplete_chirho
    );
}

#[test]
fn only_the_elected_leader_can_confirm_custody_chirho() {
    let world_chirho = world_chirho();
    let follower_set_chirho = MirrorHolderSetChirho::select_chirho(
        world_chirho.joined_chirho.view_chirho(),
        &world_chirho.peer_one_chirho.id_chirho,
        &MirrorResidencyPolicyChirho::AnyDomainChirho,
    )
    .unwrap();
    let error_chirho = confirm_key_custody_chirho(
        &world_chirho.joined_chirho,
        &follower_set_chirho,
        &coordinates_chirho(1, 3),
        &[],
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyAuthorityRefusedChirho
    );
    assert_eq!(
        error_chirho.mirror_identity_chirho(),
        Some(MirrorRefusalIdentityChirho::MirrorSenderNotLeaderChirho)
    );
}
