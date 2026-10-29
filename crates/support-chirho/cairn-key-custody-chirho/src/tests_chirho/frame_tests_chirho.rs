// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The custody frame's three gates: authentication, the mirror's own authority check, and the holder's erasure tombstones.

use super::world_chirho::{
    joined_view_chirho, key_id_chirho, record_chirho, world_chirho, LEASE_MILLIS_CHIRHO,
    OTHER_SUBJECT_CHIRHO, SUBJECT_CHIRHO, TERM_CHIRHO,
};
use crate::custody_chirho::frame_chirho::KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO;
use crate::erasure_chirho::tombstone_chirho::HolderTombstonesChirho;
use crate::refusal_chirho::{KeyCustodyErrorChirho, KeyCustodyRefusalIdentityChirho};
use cairn_mirror_chirho::MirrorRefusalIdentityChirho;

/// The mirror's named reason inside a custody authority refusal.
fn mirror_reason_chirho(error_chirho: KeyCustodyErrorChirho) -> MirrorRefusalIdentityChirho {
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyAuthorityRefusedChirho
    );
    error_chirho
        .mirror_identity_chirho()
        .expect("the mirror names its reason")
}

#[test]
fn the_current_leader_delivers_a_key_its_holder_opens_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let binding_chirho =
        world_chirho.binding_chirho(holder_chirho, &key_id_chirho(1), SUBJECT_CHIRHO, 3);
    let record_chirho = record_chirho(SUBJECT_CHIRHO, 0x44);
    let wire_chirho = world_chirho.custody_wire_chirho(
        &binding_chirho,
        &record_chirho,
        holder_chirho,
        Some(LEASE_MILLIS_CHIRHO),
        &world_chirho.leader_chirho,
    );
    let opened_chirho = world_chirho
        .receive_custody_chirho(
            &world_chirho.joined_chirho,
            holder_chirho,
            &wire_chirho,
            &HolderTombstonesChirho::new_chirho(),
        )
        .unwrap();
    assert_eq!(opened_chirho.binding_chirho(), &binding_chirho);
    assert!(opened_chirho
        .record_chirho()
        .same_record_chirho(&record_chirho));
}

#[test]
fn a_frame_from_a_follower_is_refused_by_the_inverted_predicate_chirho() {
    // peer_two is a rostered serving holder, but not the elected leader.
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let mut binding_chirho =
        world_chirho.binding_chirho(holder_chirho, &key_id_chirho(1), SUBJECT_CHIRHO, 3);
    binding_chirho.origin_node_id_chirho = world_chirho.peer_two_chirho.id_chirho.clone();
    let wire_chirho = world_chirho.custody_wire_chirho(
        &binding_chirho,
        &record_chirho(SUBJECT_CHIRHO, 0x44),
        holder_chirho,
        Some(LEASE_MILLIS_CHIRHO),
        &world_chirho.peer_two_chirho,
    );
    let error_chirho = world_chirho
        .receive_custody_chirho(
            &world_chirho.joined_chirho,
            holder_chirho,
            &wire_chirho,
            &HolderTombstonesChirho::new_chirho(),
        )
        .unwrap_err();
    assert_eq!(
        mirror_reason_chirho(error_chirho),
        MirrorRefusalIdentityChirho::MirrorSenderNotLeaderChirho
    );
}

#[test]
fn a_frame_addressed_to_another_holder_is_refused_chirho() {
    let world_chirho = world_chirho();
    let binding_chirho = world_chirho.binding_chirho(
        &world_chirho.peer_two_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
    );
    let wire_chirho = world_chirho.custody_wire_chirho(
        &binding_chirho,
        &record_chirho(SUBJECT_CHIRHO, 0x44),
        &world_chirho.peer_two_chirho,
        Some(LEASE_MILLIS_CHIRHO),
        &world_chirho.leader_chirho,
    );
    let error_chirho = world_chirho
        .receive_custody_chirho(
            &world_chirho.joined_chirho,
            &world_chirho.peer_one_chirho,
            &wire_chirho,
            &HolderTombstonesChirho::new_chirho(),
        )
        .unwrap_err();
    assert_eq!(
        mirror_reason_chirho(error_chirho),
        MirrorRefusalIdentityChirho::MirrorReceiverUnrosteredChirho
    );
}

#[test]
fn a_frame_from_an_older_term_or_another_view_is_refused_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let refuse_chirho =
        |mutate_chirho: &dyn Fn(&mut crate::CustodyBindingChirho),
         joined_chirho: &cairn_mirror_chirho::JoinedMirrorViewChirho| {
            let mut binding_chirho =
                world_chirho.binding_chirho(holder_chirho, &key_id_chirho(1), SUBJECT_CHIRHO, 3);
            mutate_chirho(&mut binding_chirho);
            let wire_chirho = world_chirho.custody_wire_chirho(
                &binding_chirho,
                &record_chirho(SUBJECT_CHIRHO, 0x44),
                holder_chirho,
                Some(LEASE_MILLIS_CHIRHO),
                &world_chirho.leader_chirho,
            );
            mirror_reason_chirho(
                world_chirho
                    .receive_custody_chirho(
                        joined_chirho,
                        holder_chirho,
                        &wire_chirho,
                        &HolderTombstonesChirho::new_chirho(),
                    )
                    .unwrap_err(),
            )
        };
    assert_eq!(
        refuse_chirho(
            &|b_chirho| b_chirho.elected_term_chirho = TERM_CHIRHO - 1,
            &world_chirho.joined_chirho
        ),
        MirrorRefusalIdentityChirho::MirrorTermInvalidChirho
    );
    assert_eq!(
        refuse_chirho(
            &|b_chirho| b_chirho.membership_view_digest_chirho = "9".repeat(64),
            &world_chirho.joined_chirho
        ),
        MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho
    );
    // The holder has already joined a later term under the same leader, so the frame's view is stale.
    let later_chirho = joined_view_chirho(
        &world_chirho.placement_chirho,
        Some(&world_chirho.leader_chirho.id_chirho),
        TERM_CHIRHO + 1,
    );
    assert_eq!(
        refuse_chirho(&|_| {}, &later_chirho),
        MirrorRefusalIdentityChirho::MirrorMembershipViewMismatchChirho
    );
}

#[test]
fn an_absent_or_spent_leader_lease_is_refused_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let binding_chirho =
        world_chirho.binding_chirho(holder_chirho, &key_id_chirho(1), SUBJECT_CHIRHO, 3);
    for lease_chirho in [None, Some(100)] {
        let wire_chirho = world_chirho.custody_wire_chirho(
            &binding_chirho,
            &record_chirho(SUBJECT_CHIRHO, 0x44),
            holder_chirho,
            lease_chirho,
            &world_chirho.leader_chirho,
        );
        let error_chirho = world_chirho
            .receive_custody_chirho(
                &world_chirho.joined_chirho,
                holder_chirho,
                &wire_chirho,
                &HolderTombstonesChirho::new_chirho(),
            )
            .unwrap_err();
        assert_eq!(
            mirror_reason_chirho(error_chirho),
            MirrorRefusalIdentityChirho::MirrorLeaseExpiredChirho
        );
    }
}

#[test]
fn a_tampered_or_wrongly_signed_frame_is_refused_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let binding_chirho =
        world_chirho.binding_chirho(holder_chirho, &key_id_chirho(1), SUBJECT_CHIRHO, 3);
    let honest_chirho = world_chirho.custody_wire_chirho(
        &binding_chirho,
        &record_chirho(SUBJECT_CHIRHO, 0x44),
        holder_chirho,
        Some(LEASE_MILLIS_CHIRHO),
        &world_chirho.leader_chirho,
    );
    let mut value_chirho: serde_json::Value = serde_json::from_slice(&honest_chirho).unwrap();
    value_chirho["binding_chirho"]["blob_seq_chirho"] = 4.into();
    let tampered_chirho = serde_json::to_vec(&value_chirho).unwrap();
    let error_chirho = world_chirho
        .receive_custody_chirho(
            &world_chirho.joined_chirho,
            holder_chirho,
            &tampered_chirho,
            &HolderTombstonesChirho::new_chirho(),
        )
        .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho
    );
    assert_eq!(
        error_chirho.detail_chirho(),
        "the frame digest does not bind its fields"
    );
    // The leader is named as origin, but another node signed.
    let forged_chirho = world_chirho.custody_wire_chirho(
        &binding_chirho,
        &record_chirho(SUBJECT_CHIRHO, 0x44),
        holder_chirho,
        Some(LEASE_MILLIS_CHIRHO),
        &world_chirho.peer_two_chirho,
    );
    let error_chirho = world_chirho
        .receive_custody_chirho(
            &world_chirho.joined_chirho,
            holder_chirho,
            &forged_chirho,
            &HolderTombstonesChirho::new_chirho(),
        )
        .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyFrameInvalidChirho
    );
    assert_eq!(error_chirho.detail_chirho(), "signature does not verify");
}

#[test]
fn oversized_or_unexpected_wire_is_refused_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let empty_chirho = HolderTombstonesChirho::new_chirho();
    let oversized_chirho = vec![b' '; KEY_CUSTODY_WIRE_MAX_BYTES_CHIRHO + 1];
    let error_chirho = world_chirho
        .receive_custody_chirho(
            &world_chirho.joined_chirho,
            holder_chirho,
            &oversized_chirho,
            &empty_chirho,
        )
        .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyWireInvalidChirho
    );
    let binding_chirho =
        world_chirho.binding_chirho(holder_chirho, &key_id_chirho(1), SUBJECT_CHIRHO, 3);
    let honest_chirho = world_chirho.custody_wire_chirho(
        &binding_chirho,
        &record_chirho(SUBJECT_CHIRHO, 0x44),
        holder_chirho,
        Some(LEASE_MILLIS_CHIRHO),
        &world_chirho.leader_chirho,
    );
    let mut value_chirho: serde_json::Value = serde_json::from_slice(&honest_chirho).unwrap();
    value_chirho["extra_chirho"] = 1.into();
    let error_chirho = world_chirho
        .receive_custody_chirho(
            &world_chirho.joined_chirho,
            holder_chirho,
            &serde_json::to_vec(&value_chirho).unwrap(),
            &empty_chirho,
        )
        .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::CustodyWireInvalidChirho
    );
}

#[test]
fn a_key_or_subject_an_erasure_covers_is_refused_before_it_opens_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    // The leader erased SUBJECT below blob seq 5 on this holder, listing key 1.
    let erasure_chirho = world_chirho
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
    tombstones_chirho.record_erasure_chirho(&erasure_chirho);
    let deliver_chirho = |key_chirho: u8, subject_chirho: &str, blob_seq_chirho: u64| {
        let binding_chirho = world_chirho.binding_chirho(
            holder_chirho,
            &key_id_chirho(key_chirho),
            subject_chirho,
            blob_seq_chirho,
        );
        let wire_chirho = world_chirho.custody_wire_chirho(
            &binding_chirho,
            &record_chirho(subject_chirho, 0x44),
            holder_chirho,
            Some(LEASE_MILLIS_CHIRHO),
            &world_chirho.leader_chirho,
        );
        world_chirho.receive_custody_chirho(
            &world_chirho.joined_chirho,
            holder_chirho,
            &wire_chirho,
            &tombstones_chirho,
        )
    };
    let erased_chirho = KeyCustodyRefusalIdentityChirho::CustodySubjectAlreadyErasedChirho;
    // The listed key, whatever subject or seq a delayed frame claims.
    assert_eq!(
        deliver_chirho(1, OTHER_SUBJECT_CHIRHO, 9)
            .unwrap_err()
            .identity_chirho(),
        erased_chirho
    );
    // A blob the erased subject had when it was erased.
    assert_eq!(
        deliver_chirho(2, SUBJECT_CHIRHO, 4)
            .unwrap_err()
            .identity_chirho(),
        erased_chirho
    );
    // A blob the subject created at or after the bound, and another subject's blob, are custodied.
    deliver_chirho(3, SUBJECT_CHIRHO, 5).expect("a post-erasure blob is custodied");
    deliver_chirho(4, OTHER_SUBJECT_CHIRHO, 0).expect("another subject is custodied");
}
