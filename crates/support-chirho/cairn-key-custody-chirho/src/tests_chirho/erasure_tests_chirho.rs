// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Erasure frames, the subject rule's exclusive bound, receipt accounting, tombstones read back from storage, the leader's frame to its own holder, the largest legal frame and receipt, and a receipt's answer to its frame.

use super::world_chirho::{
    key_id_chirho, world_chirho, NodeChirho, LEASE_MILLIS_CHIRHO, OTHER_SUBJECT_CHIRHO,
    SUBJECT_CHIRHO, TERM_CHIRHO,
};
use crate::custody_chirho::binding_chirho::subject_digest_hex_chirho;
use crate::erasure_chirho::frame_chirho::{
    decode_and_authenticate_erasure_frame_chirho, ErasureFrameInputChirho, ErasureFrameV1Chirho,
    PreparedErasureFrameChirho, ERASURE_WIRE_MAX_BYTES_CHIRHO,
};
use crate::erasure_chirho::receipt_chirho::{
    decode_and_verify_erasure_receipt_chirho, verify_erasure_receipt_answers_frame_chirho,
    PreparedErasureReceiptChirho, ReceiptFieldChirho, VerifiedErasureReceiptChirho,
};
use crate::erasure_chirho::status_chirho::ErasureRequirementChirho;
use crate::erasure_chirho::tombstone_chirho::HolderTombstonesChirho;
use crate::refusal_chirho::KeyCustodyRefusalIdentityChirho;
use crate::ERASURE_MAX_KEY_IDS_CHIRHO;
use cairn_mirror_chirho::MirrorRefusalIdentityChirho;
use std::collections::BTreeSet;

fn set_chirho(numbers_chirho: &[u8]) -> BTreeSet<String> {
    numbers_chirho
        .iter()
        .map(|number_chirho| key_id_chirho(*number_chirho))
        .collect()
}

#[test]
fn only_the_current_leader_can_order_an_erasure_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let from_leader_chirho = world_chirho.erasure_wire_chirho(
        holder_chirho,
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1)],
        &world_chirho.leader_chirho,
    );
    let frame_chirho = world_chirho
        .receive_erasure_chirho(holder_chirho, &from_leader_chirho)
        .unwrap();
    assert_eq!(frame_chirho.key_ids_chirho(), &[key_id_chirho(1)]);
    let from_follower_chirho = world_chirho.erasure_wire_chirho(
        holder_chirho,
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1)],
        &world_chirho.peer_two_chirho,
    );
    let error_chirho = world_chirho
        .receive_erasure_chirho(holder_chirho, &from_follower_chirho)
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

#[test]
fn the_subject_rule_covers_only_blobs_below_the_exclusive_bound_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let frame_chirho = world_chirho
        .receive_erasure_chirho(
            holder_chirho,
            &world_chirho.erasure_wire_chirho(
                holder_chirho,
                SUBJECT_CHIRHO,
                5,
                &[key_id_chirho(1)],
                &world_chirho.leader_chirho,
            ),
        )
        .unwrap();
    let stored_chirho = |key_chirho: u8, subject_chirho: &str, blob_seq_chirho: u64| {
        world_chirho.binding_chirho(
            holder_chirho,
            &key_id_chirho(key_chirho),
            subject_chirho,
            blob_seq_chirho,
        )
    };
    assert!(
        frame_chirho.covers_stored_key_chirho(&stored_chirho(1, OTHER_SUBJECT_CHIRHO, 99)),
        "a listed key"
    );
    assert!(
        frame_chirho.covers_stored_key_chirho(&stored_chirho(2, SUBJECT_CHIRHO, 4)),
        "below the bound"
    );
    assert!(
        !frame_chirho.covers_stored_key_chirho(&stored_chirho(3, SUBJECT_CHIRHO, 5)),
        "at the bound: a later blob"
    );
    assert!(
        !frame_chirho.covers_stored_key_chirho(&stored_chirho(4, OTHER_SUBJECT_CHIRHO, 0)),
        "another subject"
    );
    // An erasure taken over an empty blob log covers none of the subject's later blobs, not even seq 0.
    let empty_log_chirho = world_chirho
        .receive_erasure_chirho(
            holder_chirho,
            &world_chirho.erasure_wire_chirho(
                holder_chirho,
                SUBJECT_CHIRHO,
                0,
                &[],
                &world_chirho.leader_chirho,
            ),
        )
        .unwrap();
    assert!(!empty_log_chirho.covers_stored_key_chirho(&stored_chirho(2, SUBJECT_CHIRHO, 0)));
}

#[test]
fn a_receipt_must_split_the_listed_ids_exactly_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let frame_chirho = world_chirho
        .receive_erasure_chirho(
            holder_chirho,
            &world_chirho.erasure_wire_chirho(
                holder_chirho,
                SUBJECT_CHIRHO,
                5,
                &[key_id_chirho(1), key_id_chirho(2)],
                &world_chirho.leader_chirho,
            ),
        )
        .unwrap();
    let invalid_chirho = KeyCustodyRefusalIdentityChirho::ErasureReceiptInvalidChirho;
    let prepare_chirho = |removed_chirho: &[u8], absent_chirho: &[u8], by_subject_chirho: &[u8]| {
        PreparedErasureReceiptChirho::after_durable_erasure_chirho(
            &frame_chirho,
            set_chirho(removed_chirho),
            set_chirho(absent_chirho),
            set_chirho(by_subject_chirho),
        )
    };
    assert_eq!(
        prepare_chirho(&[1], &[], &[])
            .err()
            .unwrap()
            .identity_chirho(),
        invalid_chirho,
        "k2 unaccounted"
    );
    assert_eq!(
        prepare_chirho(&[1, 2], &[2], &[])
            .err()
            .unwrap()
            .identity_chirho(),
        invalid_chirho,
        "k2 twice"
    );
    assert_eq!(
        prepare_chirho(&[1], &[2], &[2])
            .err()
            .unwrap()
            .identity_chirho(),
        invalid_chirho,
        "listed id in the subject set"
    );
    let prepared_chirho = prepare_chirho(&[1], &[2], &[3]).expect("an exact split prepares");
    let signature_chirho = holder_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
    let receipt_chirho = prepared_chirho
        .into_signed_chirho(signature_chirho)
        .unwrap()
        .verify_chirho()
        .expect("the holder's receipt verifies");
    assert_eq!(
        receipt_chirho
            .accounted_key_ids_chirho()
            .cloned()
            .collect::<BTreeSet<_>>(),
        set_chirho(&[1, 2, 3])
    );
    // The same accounting signed by the leader in the holder's name.
    let prepared_chirho = prepare_chirho(&[1], &[2], &[3]).unwrap();
    let forged_chirho = world_chirho
        .leader_chirho
        .sign_chirho(&prepared_chirho.signing_digest_chirho());
    let error_chirho = prepared_chirho
        .into_signed_chirho(forged_chirho)
        .unwrap()
        .verify_chirho()
        .unwrap_err();
    assert_eq!(error_chirho.identity_chirho(), invalid_chirho);
}

/// A key the holder found under the erased subject but whose blob seq it cannot read is tombstoned by id,
/// so a delayed custody frame for it is refused even when its claimed blob seq is above the bound.
#[test]
fn a_discovered_key_is_tombstoned_whatever_its_blob_seq_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let frame_chirho = world_chirho
        .receive_erasure_chirho(
            holder_chirho,
            &world_chirho.erasure_wire_chirho(
                holder_chirho,
                SUBJECT_CHIRHO,
                5,
                &[key_id_chirho(1)],
                &world_chirho.leader_chirho,
            ),
        )
        .unwrap();
    let mut tombstones_chirho = HolderTombstonesChirho::new_chirho();
    tombstones_chirho.record_erasure_chirho(&frame_chirho);
    let above_bound_chirho =
        world_chirho.binding_chirho(holder_chirho, &key_id_chirho(3), SUBJECT_CHIRHO, 9);
    assert!(
        !tombstones_chirho.covers_chirho(&above_bound_chirho),
        "the bound alone covered it"
    );
    tombstones_chirho.record_discovered_key_ids_chirho(&frame_chirho, [&key_id_chirho(3)]);
    assert!(tombstones_chirho.covers_chirho(&above_bound_chirho));
    // Control: another key above the bound stays admissible.
    assert!(
        !tombstones_chirho.covers_chirho(&world_chirho.binding_chirho(
            holder_chirho,
            &key_id_chirho(4),
            SUBJECT_CHIRHO,
            9
        ))
    );
}

/// The holder answers an erasure frame with these wire bytes (C5 B2): the receipt round-trips, names
/// the frame it answers, and refuses a changed accounted id or oversized bytes. The authorized frame
/// names its own group and term, which the holder's term high-water is keyed by.
#[test]
fn an_erasure_receipt_round_trips_its_wire_and_names_its_frame_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let frame_chirho = world_chirho
        .receive_erasure_chirho(
            holder_chirho,
            &world_chirho.erasure_wire_chirho(
                holder_chirho,
                SUBJECT_CHIRHO,
                5,
                &[key_id_chirho(1)],
                &world_chirho.leader_chirho,
            ),
        )
        .unwrap();
    assert_eq!(
        frame_chirho.consistency_group_digest_chirho(),
        world_chirho.group_chirho()
    );
    assert_eq!(frame_chirho.elected_term_chirho(), TERM_CHIRHO);
    let prepared_chirho = PreparedErasureReceiptChirho::after_durable_erasure_chirho(
        &frame_chirho,
        set_chirho(&[1]),
        set_chirho(&[]),
        set_chirho(&[3]),
    )
    .unwrap();
    let signature_chirho = holder_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
    let wire_chirho = prepared_chirho
        .into_signed_chirho(signature_chirho)
        .unwrap()
        .to_wire_bytes_chirho()
        .unwrap();
    let verified_chirho =
        decode_and_verify_erasure_receipt_chirho(&wire_chirho).expect("the wire receipt verifies");
    assert_eq!(
        verified_chirho.erasure_frame_digest_chirho(),
        frame_chirho.frame_digest_chirho()
    );
    assert_eq!(
        verified_chirho.holder_node_id_chirho(),
        holder_chirho.id_chirho
    );
    let text_chirho = String::from_utf8(wire_chirho).unwrap();
    assert_eq!(text_chirho.matches(&key_id_chirho(3)).count(), 1);
    let tampered_chirho = text_chirho.replacen(&key_id_chirho(3), &key_id_chirho(4), 1);
    assert_eq!(
        decode_and_verify_erasure_receipt_chirho(tampered_chirho.as_bytes())
            .unwrap_err()
            .identity_chirho(),
        KeyCustodyRefusalIdentityChirho::ErasureReceiptInvalidChirho
    );
    let oversized_chirho = vec![b' '; crate::ERASURE_WIRE_MAX_BYTES_CHIRHO + 1];
    assert_eq!(
        decode_and_verify_erasure_receipt_chirho(&oversized_chirho)
            .unwrap_err()
            .identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyWireInvalidChirho
    );
}

#[test]
fn tombstones_survive_storage_and_stored_garbage_refuses_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let frame_chirho = world_chirho
        .receive_erasure_chirho(
            holder_chirho,
            &world_chirho.erasure_wire_chirho(
                holder_chirho,
                SUBJECT_CHIRHO,
                5,
                &[key_id_chirho(1)],
                &world_chirho.leader_chirho,
            ),
        )
        .unwrap();
    let mut tombstones_chirho = HolderTombstonesChirho::new_chirho();
    tombstones_chirho.record_erasure_chirho(&frame_chirho);
    let bytes_chirho = serde_json::to_vec(&tombstones_chirho).unwrap();
    let read_back_chirho: HolderTombstonesChirho = serde_json::from_slice(&bytes_chirho).unwrap();
    read_back_chirho
        .validate_chirho()
        .expect("stored tombstones are in form");
    assert_eq!(read_back_chirho, tombstones_chirho);
    assert!(read_back_chirho.covers_chirho(&world_chirho.binding_chirho(
        holder_chirho,
        &key_id_chirho(2),
        SUBJECT_CHIRHO,
        4
    )));
    let garbage_chirho: HolderTombstonesChirho = serde_json::from_value(serde_json::json!({
        "erased_key_ids_chirho": ["NOT-A-KEY-ID"],
        "erased_subject_bounds_chirho": {},
    }))
    .unwrap();
    assert_eq!(
        garbage_chirho
            .validate_chirho()
            .unwrap_err()
            .identity_chirho(),
        KeyCustodyRefusalIdentityChirho::ErasureFrameInvalidChirho
    );
}

/// The signed frame a leader holds after sending `wire_chirho`.
fn signed_frame_chirho(wire_chirho: &[u8]) -> ErasureFrameV1Chirho {
    serde_json::from_slice(wire_chirho).expect("the frame decodes")
}

/// `count_chirho` distinct, sorted key ids of 32 hex, from `start_chirho` on.
fn wide_ids_chirho(start_chirho: usize, count_chirho: usize) -> BTreeSet<String> {
    (start_chirho..start_chirho + count_chirho)
        .map(|number_chirho| format!("{number_chirho:032x}"))
        .collect()
}

/// A holder's signed, verified receipt for an authorized frame, with `removed` and `absent` splitting its ids.
fn holder_receipt_chirho(
    holder_chirho: &NodeChirho,
    authorized_chirho: &crate::AuthorizedErasureFrameChirho,
    removed_chirho: &[u8],
    absent_chirho: &[u8],
) -> VerifiedErasureReceiptChirho {
    let prepared_chirho = PreparedErasureReceiptChirho::after_durable_erasure_chirho(
        authorized_chirho,
        set_chirho(removed_chirho),
        set_chirho(absent_chirho),
        set_chirho(&[]),
    )
    .expect("the receipt prepares");
    let signature_chirho = holder_chirho.sign_chirho(&prepared_chirho.signing_digest_chirho());
    prepared_chirho
        .into_signed_chirho(signature_chirho)
        .expect("the receipt signs")
        .verify_chirho()
        .expect("the receipt verifies")
}

/// C5 B3-a3, item 14 D1: the elected leader closes its own holder store's share with a frame addressed to itself,
/// through the same admission as any holder, and that receipt closes the share.
#[test]
fn the_leader_admits_a_frame_addressed_to_itself_and_that_receipt_closes_its_share_chirho() {
    let world_chirho = world_chirho();
    let leader_chirho = &world_chirho.leader_chirho;
    let wire_chirho = world_chirho.erasure_wire_chirho(
        leader_chirho,
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1)],
        leader_chirho,
    );
    let authorized_chirho = world_chirho
        .receive_erasure_chirho(leader_chirho, &wire_chirho)
        .expect("the elected leader admits a frame addressed to itself");
    let receipt_chirho = holder_receipt_chirho(leader_chirho, &authorized_chirho, &[1], &[]);
    verify_erasure_receipt_answers_frame_chirho(
        &signed_frame_chirho(&wire_chirho),
        &receipt_chirho,
    )
    .expect("the leader's own receipt answers its frame");
    let requirement_chirho = ErasureRequirementChirho::new_chirho(
        world_chirho.group_chirho(),
        subject_digest_hex_chirho(SUBJECT_CHIRHO),
        5,
        set_chirho(&[1]),
        BTreeSet::from([leader_chirho.id_chirho.clone()]),
    )
    .unwrap();
    assert!(requirement_chirho.closes_share_alone_chirho(&receipt_chirho));
}

/// Dropping the self-address clause lets only the elected leader address itself: a follower's frame to itself
/// still refuses, at authority, by the mirror's leader reason.
#[test]
fn a_follower_frame_addressed_to_itself_is_refused_at_authority_chirho() {
    let world_chirho = world_chirho();
    let follower_chirho = &world_chirho.peer_one_chirho;
    let wire_chirho = world_chirho.erasure_wire_chirho(
        follower_chirho,
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1)],
        follower_chirho,
    );
    let error_chirho = world_chirho
        .receive_erasure_chirho(follower_chirho, &wire_chirho)
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

/// Item 14 D2: a requirement holds at most the frame's id count, so the largest legal frame, with every integer and
/// the lease at their maximum and a real signature, encodes within the wire cap. There is no chunker to need.
#[test]
fn the_largest_legal_frame_encodes_within_the_wire_cap_chirho() {
    let world_chirho = world_chirho();
    let input_chirho = ErasureFrameInputChirho {
        consistency_group_digest_chirho: world_chirho.group_chirho(),
        membership_view_digest_chirho: world_chirho.view_digest_chirho(),
        elected_term_chirho: u64::MAX,
        origin_node_id_chirho: world_chirho.leader_chirho.id_chirho.clone(),
        holder_node_id_chirho: world_chirho.peer_one_chirho.id_chirho.clone(),
        leader_lease_remaining_millis_chirho: Some(u64::MAX),
        subject_digest_chirho: subject_digest_hex_chirho(SUBJECT_CHIRHO),
        erased_below_blob_seq_chirho: u64::MAX,
        key_ids_chirho: wide_ids_chirho(0, ERASURE_MAX_KEY_IDS_CHIRHO),
    };
    let prepared_chirho = PreparedErasureFrameChirho::new_chirho(input_chirho.clone())
        .expect("the largest legal frame prepares");
    let signature_chirho = world_chirho
        .leader_chirho
        .sign_chirho(&prepared_chirho.signing_digest_chirho());
    let wire_chirho = prepared_chirho
        .into_signed_chirho(signature_chirho)
        .unwrap()
        .to_wire_bytes_chirho()
        .expect("the largest legal frame encodes");
    assert!(
        wire_chirho.len() <= ERASURE_WIRE_MAX_BYTES_CHIRHO,
        "{} bytes exceed the cap",
        wire_chirho.len()
    );
    decode_and_authenticate_erasure_frame_chirho(&wire_chirho).expect("and it decodes");
    let one_more_chirho = ErasureFrameInputChirho {
        key_ids_chirho: wide_ids_chirho(0, ERASURE_MAX_KEY_IDS_CHIRHO + 1),
        ..input_chirho
    };
    assert_eq!(
        PreparedErasureFrameChirho::new_chirho(one_more_chirho)
            .err()
            .expect("one id more is no longer a legal frame")
            .identity_chirho(),
        KeyCustodyRefusalIdentityChirho::ErasureFrameInvalidChirho
    );
}

/// Item 14 D2, the receipt side: each of a receipt's three lists may hold the frame cap of ids, disjoint from the
/// others, so the largest receipt that verifies carries three times that. It still encodes within the same cap.
#[test]
fn the_largest_verifiable_receipt_encodes_within_the_wire_cap_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let base_chirho = world_chirho.erasure_receipt_chirho(
        holder_chirho,
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1)],
        &[key_id_chirho(1)],
        &[],
        &[],
    );
    let list_chirho = |start_chirho: usize| {
        wide_ids_chirho(start_chirho, ERASURE_MAX_KEY_IDS_CHIRHO)
            .into_iter()
            .collect::<Vec<_>>()
    };
    let largest_chirho = base_chirho
        .resigned_with_chirho(
            vec![
                ReceiptFieldChirho::TermChirho(u64::MAX),
                ReceiptFieldChirho::BoundChirho(u64::MAX),
                ReceiptFieldChirho::ListsChirho {
                    removed_chirho: list_chirho(0),
                    absent_chirho: list_chirho(ERASURE_MAX_KEY_IDS_CHIRHO),
                    by_subject_chirho: list_chirho(2 * ERASURE_MAX_KEY_IDS_CHIRHO),
                },
            ],
            |digest_chirho| holder_chirho.sign_chirho(digest_chirho),
        )
        .expect("the largest receipt verifies");
    let wire_chirho = largest_chirho
        .record_chirho()
        .to_wire_bytes_chirho()
        .expect("the largest verifiable receipt encodes");
    assert!(
        wire_chirho.len() <= ERASURE_WIRE_MAX_BYTES_CHIRHO,
        "{} bytes exceed the cap",
        wire_chirho.len()
    );
    decode_and_verify_erasure_receipt_chirho(&wire_chirho).expect("and it decodes");
}

/// Item 14 D4 (gpt #30156, agy #30163): a receipt answers only the frame it echoes. Each case changes ONE field and
/// re-signs it validly, so the signature check passes and only the answer check can refuse.
#[test]
fn a_receipt_answers_only_the_frame_it_echoes_field_by_field_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let other_holder_chirho = &world_chirho.peer_two_chirho;
    let wire_chirho = world_chirho.erasure_wire_chirho(
        holder_chirho,
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1), key_id_chirho(2)],
        &world_chirho.leader_chirho,
    );
    let frame_chirho = signed_frame_chirho(&wire_chirho);
    let authorized_chirho = world_chirho
        .receive_erasure_chirho(holder_chirho, &wire_chirho)
        .unwrap();
    let receipt_chirho = holder_receipt_chirho(holder_chirho, &authorized_chirho, &[1], &[2]);
    verify_erasure_receipt_answers_frame_chirho(&frame_chirho, &receipt_chirho)
        .expect("a receipt answers the frame it was built from");
    let other_hex_chirho = "ab".repeat(32);
    let cases_chirho: Vec<(&str, ReceiptFieldChirho, &NodeChirho)> = vec![
        (
            "frame digest",
            ReceiptFieldChirho::FrameDigestChirho(other_hex_chirho.clone()),
            holder_chirho,
        ),
        (
            "group",
            ReceiptFieldChirho::GroupChirho(other_hex_chirho.clone()),
            holder_chirho,
        ),
        (
            "view",
            ReceiptFieldChirho::ViewChirho(other_hex_chirho.clone()),
            holder_chirho,
        ),
        (
            "term",
            ReceiptFieldChirho::TermChirho(TERM_CHIRHO + 1),
            holder_chirho,
        ),
        (
            "origin",
            ReceiptFieldChirho::OriginChirho(other_holder_chirho.id_chirho.clone()),
            holder_chirho,
        ),
        (
            "holder",
            ReceiptFieldChirho::HolderChirho(other_holder_chirho.id_chirho.clone()),
            other_holder_chirho,
        ),
        (
            "subject",
            ReceiptFieldChirho::SubjectChirho(subject_digest_hex_chirho(OTHER_SUBJECT_CHIRHO)),
            holder_chirho,
        ),
        ("bound", ReceiptFieldChirho::BoundChirho(6), holder_chirho),
        (
            "listed split",
            ReceiptFieldChirho::ListsChirho {
                removed_chirho: vec![key_id_chirho(1)],
                absent_chirho: Vec::new(),
                by_subject_chirho: Vec::new(),
            },
            holder_chirho,
        ),
    ];
    for (name_chirho, change_chirho, signer_chirho) in cases_chirho {
        let changed_chirho = receipt_chirho
            .resigned_with_chirho(vec![change_chirho], |digest_chirho| {
                signer_chirho.sign_chirho(digest_chirho)
            })
            .unwrap_or_else(|error_chirho| {
                panic!("{name_chirho}: the changed receipt must still verify: {error_chirho}")
            });
        assert_eq!(
            verify_erasure_receipt_answers_frame_chirho(&frame_chirho, &changed_chirho)
                .err()
                .unwrap_or_else(|| panic!("{name_chirho}: a changed receipt must not answer"))
                .identity_chirho(),
            KeyCustodyRefusalIdentityChirho::ErasureReceiptNotForFrameChirho,
            "{name_chirho}"
        );
    }
    // A genuine receipt for a second frame that differs only in its lease answers that frame, never this one.
    let second_input_chirho = ErasureFrameInputChirho {
        consistency_group_digest_chirho: world_chirho.group_chirho(),
        membership_view_digest_chirho: world_chirho.view_digest_chirho(),
        elected_term_chirho: TERM_CHIRHO,
        origin_node_id_chirho: world_chirho.leader_chirho.id_chirho.clone(),
        holder_node_id_chirho: holder_chirho.id_chirho.clone(),
        leader_lease_remaining_millis_chirho: Some(LEASE_MILLIS_CHIRHO - 1),
        subject_digest_chirho: subject_digest_hex_chirho(SUBJECT_CHIRHO),
        erased_below_blob_seq_chirho: 5,
        key_ids_chirho: set_chirho(&[1, 2]),
    };
    let second_prepared_chirho =
        PreparedErasureFrameChirho::new_chirho(second_input_chirho).unwrap();
    let second_signature_chirho = world_chirho
        .leader_chirho
        .sign_chirho(&second_prepared_chirho.signing_digest_chirho());
    let second_wire_chirho = second_prepared_chirho
        .into_signed_chirho(second_signature_chirho)
        .unwrap()
        .to_wire_bytes_chirho()
        .unwrap();
    let second_authorized_chirho = world_chirho
        .receive_erasure_chirho(holder_chirho, &second_wire_chirho)
        .unwrap();
    let second_receipt_chirho =
        holder_receipt_chirho(holder_chirho, &second_authorized_chirho, &[1], &[2]);
    verify_erasure_receipt_answers_frame_chirho(
        &signed_frame_chirho(&second_wire_chirho),
        &second_receipt_chirho,
    )
    .expect("it answers its own frame");
    assert_eq!(
        verify_erasure_receipt_answers_frame_chirho(&frame_chirho, &second_receipt_chirho)
            .expect_err("a receipt for another frame does not answer this one")
            .identity_chirho(),
        KeyCustodyRefusalIdentityChirho::ErasureReceiptNotForFrameChirho
    );
}
