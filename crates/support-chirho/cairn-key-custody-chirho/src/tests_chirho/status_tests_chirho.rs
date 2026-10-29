// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Erasure completeness: requirements from custody evidence, the retry that lost its local scan, the bound, and destroyed-media attestations that cannot close a placed holder.

use super::world_chirho::{
    joined_view_chirho, key_id_chirho, node_chirho, verified_placement_chirho,
    verified_placement_for_tenant_chirho, world_chirho, WorldChirho, OTHER_SUBJECT_CHIRHO,
    SUBJECT_CHIRHO, TERM_CHIRHO,
};
use crate::custody_chirho::binding_chirho::subject_digest_hex_chirho;
use crate::erasure_chirho::decommission_chirho::{
    attestation_digest_hex_chirho, DecommissionAttestationV1Chirho,
    PreparedDecommissionAttestationChirho, VerifiedDecommissionAttestationChirho,
    DECOMMISSION_ATTESTATION_SCHEMA_V1_CHIRHO,
};
use crate::erasure_chirho::status_chirho::{
    erasure_status_chirho, ErasureRequirementChirho, ErasureStatusChirho,
};
use crate::refusal_chirho::KeyCustodyRefusalIdentityChirho;
use std::collections::BTreeSet;

/// The status, for arms whose view is the requirement's own group.
fn status_chirho(
    requirement_chirho: &ErasureRequirementChirho,
    view_chirho: &cairn_mirror_chirho::MirrorMembershipViewChirho,
    receipts_chirho: &[crate::erasure_chirho::receipt_chirho::VerifiedErasureReceiptChirho],
    attestations_chirho: &[VerifiedDecommissionAttestationChirho],
) -> ErasureStatusChirho {
    erasure_status_chirho(
        requirement_chirho,
        view_chirho,
        receipts_chirho,
        attestations_chirho,
    )
    .expect("the view is the requirement's group")
}

fn requirement_chirho(
    world_chirho: &WorldChirho,
    holders_chirho: &[&str],
    keys_chirho: &[u8],
) -> ErasureRequirementChirho {
    ErasureRequirementChirho::new_chirho(
        world_chirho.group_chirho(),
        subject_digest_hex_chirho(SUBJECT_CHIRHO),
        5,
        keys_chirho
            .iter()
            .map(|key_chirho| key_id_chirho(*key_chirho))
            .collect(),
        holders_chirho
            .iter()
            .map(|holder_chirho| holder_chirho.to_string())
            .collect(),
    )
    .unwrap()
}

fn ids_chirho(keys_chirho: &[u8]) -> Vec<String> {
    keys_chirho
        .iter()
        .map(|key_chirho| key_id_chirho(*key_chirho))
        .collect()
}

fn pending_chirho(holders_chirho: &[&str]) -> ErasureStatusChirho {
    ErasureStatusChirho::ErasurePropagationPendingChirho {
        pending_holders_chirho: holders_chirho
            .iter()
            .map(|holder_chirho| holder_chirho.to_string())
            .collect(),
    }
}

/// The leader attests that `destroyed_chirho` was destroyed, under the world's current view.
fn attestation_chirho(
    world_chirho: &WorldChirho,
    destroyed_chirho: &str,
) -> VerifiedDecommissionAttestationChirho {
    let prepared_chirho = PreparedDecommissionAttestationChirho::new_chirho(
        &world_chirho.joined_chirho,
        &world_chirho.leader_chirho.id_chirho,
        destroyed_chirho,
    )
    .expect("attestation prepares");
    let signature_chirho = world_chirho
        .leader_chirho
        .sign_chirho(&prepared_chirho.signing_digest_chirho());
    prepared_chirho
        .into_signed_chirho(signature_chirho)
        .unwrap()
        .verify_chirho(world_chirho.joined_chirho.view_chirho())
        .expect("attestation verifies")
}

#[test]
fn a_retry_that_never_accounts_for_a_custodied_key_stays_pending_chirho() {
    // agy R-C5-3. The custody evidence says both peers were sent key 1. peer_two closed its share in the
    // first attempt. The retry to peer_one was built from the leader's emptied local scan, so it listed
    // nothing, and its receipt accounts for nothing: the erasure must not report complete.
    let world_chirho = world_chirho();
    let (one_chirho, two_chirho) = (&world_chirho.peer_one_chirho, &world_chirho.peer_two_chirho);
    let requirement_chirho = requirement_chirho(
        &world_chirho,
        &[&one_chirho.id_chirho, &two_chirho.id_chirho],
        &[1],
    );
    let two_closed_chirho = world_chirho.erasure_receipt_chirho(
        two_chirho,
        SUBJECT_CHIRHO,
        5,
        &ids_chirho(&[1]),
        &ids_chirho(&[1]),
        &[],
        &[],
    );
    let one_retry_chirho =
        world_chirho.erasure_receipt_chirho(one_chirho, SUBJECT_CHIRHO, 5, &[], &[], &[], &[]);
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            world_chirho.joined_chirho.view_chirho(),
            &[two_closed_chirho.clone(), one_retry_chirho.clone()],
            &[],
        ),
        pending_chirho(&[&one_chirho.id_chirho])
    );
    // The same retry, once its subject rule found and removed key 1, closes the share.
    let one_found_chirho = world_chirho.erasure_receipt_chirho(
        one_chirho,
        SUBJECT_CHIRHO,
        5,
        &[],
        &[],
        &[],
        &ids_chirho(&[1]),
    );
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            world_chirho.joined_chirho.view_chirho(),
            &[two_closed_chirho, one_retry_chirho, one_found_chirho],
            &[],
        ),
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    );
}

#[test]
fn a_share_closes_only_when_the_bound_reaches_the_requirement_chirho() {
    let world_chirho = world_chirho();
    let one_chirho = &world_chirho.peer_one_chirho;
    let requirement_chirho = requirement_chirho(&world_chirho, &[&one_chirho.id_chirho], &[1]);
    let low_chirho = world_chirho.erasure_receipt_chirho(
        one_chirho,
        SUBJECT_CHIRHO,
        3,
        &ids_chirho(&[1]),
        &ids_chirho(&[1]),
        &[],
        &[],
    );
    let view_chirho = world_chirho.joined_chirho.view_chirho();
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            view_chirho,
            std::slice::from_ref(&low_chirho),
            &[]
        ),
        pending_chirho(&[&one_chirho.id_chirho])
    );
    // A later receipt carries the full bound; together they account for key 1 and reach the bound.
    let full_chirho =
        world_chirho.erasure_receipt_chirho(one_chirho, SUBJECT_CHIRHO, 5, &[], &[], &[], &[]);
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            view_chirho,
            &[low_chirho, full_chirho],
            &[]
        ),
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    );
}

#[test]
fn receipts_for_another_subject_count_for_nothing_chirho() {
    let world_chirho = world_chirho();
    let one_chirho = &world_chirho.peer_one_chirho;
    let requirement_chirho = requirement_chirho(&world_chirho, &[&one_chirho.id_chirho], &[1]);
    let other_chirho = world_chirho.erasure_receipt_chirho(
        one_chirho,
        OTHER_SUBJECT_CHIRHO,
        5,
        &ids_chirho(&[1]),
        &ids_chirho(&[1]),
        &[],
        &[],
    );
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            world_chirho.joined_chirho.view_chirho(),
            &[other_chirho],
            &[]
        ),
        pending_chirho(&[&one_chirho.id_chirho])
    );
}

#[test]
fn a_lost_holder_closes_only_through_an_attestation_and_the_status_says_so_chirho() {
    let world_chirho = world_chirho();
    let (one_chirho, two_chirho) = (&world_chirho.peer_one_chirho, &world_chirho.peer_two_chirho);
    let lost_chirho = node_chirho(9);
    let requirement_chirho = requirement_chirho(
        &world_chirho,
        &[
            &one_chirho.id_chirho,
            &two_chirho.id_chirho,
            &lost_chirho.id_chirho,
        ],
        &[1],
    );
    let receipts_chirho = [
        world_chirho.erasure_receipt_chirho(
            one_chirho,
            SUBJECT_CHIRHO,
            5,
            &ids_chirho(&[1]),
            &[],
            &ids_chirho(&[1]),
            &[],
        ),
        world_chirho.erasure_receipt_chirho(
            two_chirho,
            SUBJECT_CHIRHO,
            5,
            &ids_chirho(&[1]),
            &ids_chirho(&[1]),
            &[],
            &[],
        ),
    ];
    let view_chirho = world_chirho.joined_chirho.view_chirho();
    assert_eq!(
        status_chirho(&requirement_chirho, view_chirho, &receipts_chirho, &[]),
        pending_chirho(&[&lost_chirho.id_chirho])
    );
    let attested_chirho = attestation_chirho(&world_chirho, &lost_chirho.id_chirho);
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            view_chirho,
            &receipts_chirho,
            &[attested_chirho]
        ),
        ErasureStatusChirho::ErasureConfirmedWithDecommissionedHolderAttestationChirho {
            attested_holders_chirho: [lost_chirho.id_chirho.clone()]
                .into_iter()
                .collect::<BTreeSet<_>>(),
        }
    );
}

#[test]
fn an_attestation_cannot_close_a_holder_the_placement_still_names_chirho() {
    let world_chirho = world_chirho();
    let placed_chirho = &world_chirho.peer_one_chirho;
    let still_placed_chirho = KeyCustodyRefusalIdentityChirho::DecommissionHolderStillPlacedChirho;
    // The leader cannot even prepare one for a placed holder.
    let error_chirho = PreparedDecommissionAttestationChirho::new_chirho(
        &world_chirho.joined_chirho,
        &world_chirho.leader_chirho.id_chirho,
        &placed_chirho.id_chirho,
    )
    .err()
    .unwrap();
    assert_eq!(error_chirho.identity_chirho(), still_placed_chirho);
    // agy #28783: peer_two hand-crafts and signs one that names peer_one destroyed, declaring a
    // replacement placement of its own. Its self-declared list passes; the caller's real view refuses it.
    let mut declared_chirho = vec![
        world_chirho.leader_chirho.id_chirho.clone(),
        world_chirho.peer_two_chirho.id_chirho.clone(),
        node_chirho(9).id_chirho,
    ];
    declared_chirho.sort();
    let mut value_chirho = serde_json::json!({
        "schema_chirho": DECOMMISSION_ATTESTATION_SCHEMA_V1_CHIRHO,
        "consistency_group_digest_chirho": world_chirho.group_chirho(),
        "decommissioned_holder_node_id_chirho": placed_chirho.id_chirho,
        "replacement_assignment_digest_chirho": "a".repeat(64),
        "replacement_view_digest_chirho": "b".repeat(64),
        "replacement_serving_holders_chirho": declared_chirho,
        "replacement_held_observer_chirho": world_chirho.placement_chirho.held_observer_node_chirho().node_id_chirho,
        "attested_by_node_id_chirho": world_chirho.peer_two_chirho.id_chirho,
        "elected_term_chirho": TERM_CHIRHO,
        "attestation_digest_chirho": "",
        "sig_hex_chirho": "",
    });
    let unsigned_chirho: DecommissionAttestationV1Chirho =
        serde_json::from_value(value_chirho.clone()).unwrap();
    let digest_chirho = attestation_digest_hex_chirho(&unsigned_chirho);
    let digest_bytes_chirho: [u8; 32] =
        crate::digest_chirho::decode_hex_32_chirho(&digest_chirho).unwrap();
    value_chirho["attestation_digest_chirho"] = digest_chirho.into();
    value_chirho["sig_hex_chirho"] = world_chirho
        .peer_two_chirho
        .sign_chirho(&digest_bytes_chirho)
        .into();
    let forged_chirho: DecommissionAttestationV1Chirho =
        serde_json::from_value(value_chirho).unwrap();
    let error_chirho = forged_chirho
        .verify_chirho(world_chirho.joined_chirho.view_chirho())
        .unwrap_err();
    assert_eq!(error_chirho.identity_chirho(), still_placed_chirho);
    assert_eq!(
        error_chirho.detail_chirho(),
        "the current placement still names this holder"
    );
}

#[test]
fn an_attestation_counts_for_nothing_once_the_holder_is_placed_again_chirho() {
    // An attestation verified while node 9 was out of the placement, then a later view that places it
    // again: at the decision point, the current view wins and node 9 stays pending.
    let world_chirho = world_chirho();
    let returned_chirho = node_chirho(9);
    let attested_chirho = attestation_chirho(&world_chirho, &returned_chirho.id_chirho);
    let observer_chirho = node_chirho(4);
    let placement_chirho = verified_placement_chirho(
        [
            &world_chirho.leader_chirho,
            &world_chirho.peer_one_chirho,
            &returned_chirho,
        ],
        &observer_chirho,
    );
    let later_chirho = joined_view_chirho(
        &placement_chirho,
        Some(&world_chirho.leader_chirho.id_chirho),
        TERM_CHIRHO + 1,
    );
    assert_eq!(
        later_chirho.view_chirho().consistency_group_digest_chirho(),
        world_chirho.group_chirho(),
        "the same group, re-placed"
    );
    let requirement_chirho = requirement_chirho(&world_chirho, &[&returned_chirho.id_chirho], &[1]);
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            later_chirho.view_chirho(),
            &[],
            &[attested_chirho]
        ),
        pending_chirho(&[&returned_chirho.id_chirho])
    );
}

#[test]
fn a_requirement_naming_no_holder_is_refused_chirho() {
    let world_chirho = world_chirho();
    let error_chirho = ErasureRequirementChirho::new_chirho(
        world_chirho.group_chirho(),
        subject_digest_hex_chirho(SUBJECT_CHIRHO),
        5,
        BTreeSet::new(),
        BTreeSet::new(),
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::ErasureRequirementInvalidChirho
    );
}

#[test]
fn a_view_from_another_group_is_refused_chirho() {
    // agy pin B2-1: a view of ANOTHER group does not list this group's holders, so without the group
    // check the placement re-check would pass and an attestation could close a placed holder's share.
    let world_chirho = world_chirho();
    let placed_chirho = &world_chirho.peer_one_chirho;
    let observer_chirho = node_chirho(4);
    let other_placement_chirho = verified_placement_for_tenant_chirho(
        [
            &world_chirho.leader_chirho,
            &world_chirho.peer_two_chirho,
            &node_chirho(9),
        ],
        &observer_chirho,
        "other-fixture-chirho",
    );
    let other_chirho = joined_view_chirho(
        &other_placement_chirho,
        Some(&world_chirho.leader_chirho.id_chirho),
        TERM_CHIRHO,
    );
    assert_ne!(
        other_chirho.view_chirho().consistency_group_digest_chirho(),
        world_chirho.group_chirho(),
        "the control: the other view really is another group"
    );
    // A real attestation of THIS group for peer_one, made while an earlier placement of this group had
    // replaced it. The world's current view places peer_one again, so it must not close the share; the
    // other group's view does not list peer_one, which is exactly what would let it close.
    let replaced_placement_chirho = verified_placement_chirho(
        [
            &world_chirho.leader_chirho,
            &world_chirho.peer_two_chirho,
            &node_chirho(9),
        ],
        &observer_chirho,
    );
    let replaced_chirho = joined_view_chirho(
        &replaced_placement_chirho,
        Some(&world_chirho.leader_chirho.id_chirho),
        TERM_CHIRHO,
    );
    let prepared_chirho = PreparedDecommissionAttestationChirho::new_chirho(
        &replaced_chirho,
        &world_chirho.leader_chirho.id_chirho,
        &placed_chirho.id_chirho,
    )
    .expect("peer_one is outside the replaced placement");
    let signature_chirho = world_chirho
        .leader_chirho
        .sign_chirho(&prepared_chirho.signing_digest_chirho());
    let attestation_chirho = prepared_chirho
        .into_signed_chirho(signature_chirho)
        .unwrap()
        .verify_chirho(replaced_chirho.view_chirho())
        .expect("verified against the view it was made under");
    let requirement_chirho = requirement_chirho(&world_chirho, &[&placed_chirho.id_chirho], &[1]);
    let error_chirho = erasure_status_chirho(
        &requirement_chirho,
        other_chirho.view_chirho(),
        &[],
        &[attestation_chirho],
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.identity_chirho(),
        KeyCustodyRefusalIdentityChirho::ErasureRequirementInvalidChirho
    );
    assert_eq!(
        error_chirho.detail_chirho(),
        "the current view is for another group"
    );
}

/// C5 B3-a3, item 14 D5 (agy #30163): a leader stores only a receipt that closes its holder's share by itself, judged
/// by the status predicate, so storage and status cannot disagree.
#[test]
fn one_receipt_closes_a_share_alone_only_with_the_whole_cut_and_bound_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = &world_chirho.peer_one_chirho;
    let requirement_chirho = requirement_chirho(
        &world_chirho,
        &[
            &world_chirho.peer_one_chirho.id_chirho,
            &world_chirho.peer_two_chirho.id_chirho,
        ],
        &[1, 2],
    );
    let closing_chirho = world_chirho.erasure_receipt_chirho(
        holder_chirho,
        SUBJECT_CHIRHO,
        5,
        &ids_chirho(&[1, 2]),
        &ids_chirho(&[1]),
        &ids_chirho(&[2]),
        &[],
    );
    assert!(requirement_chirho.closes_share_alone_chirho(&closing_chirho));
    assert_eq!(
        status_chirho(
            &requirement_chirho,
            world_chirho.joined_chirho.view_chirho(),
            std::slice::from_ref(&closing_chirho),
            &[],
        ),
        pending_chirho(&[&world_chirho.peer_two_chirho.id_chirho]),
        "status agrees: that share is closed and only the other is pending"
    );
    let short_chirho = world_chirho.erasure_receipt_chirho(
        holder_chirho,
        SUBJECT_CHIRHO,
        5,
        &ids_chirho(&[1]),
        &ids_chirho(&[1]),
        &[],
        &[],
    );
    assert!(!requirement_chirho.closes_share_alone_chirho(&short_chirho));
    let low_bound_chirho = world_chirho.erasure_receipt_chirho(
        holder_chirho,
        SUBJECT_CHIRHO,
        4,
        &ids_chirho(&[1, 2]),
        &ids_chirho(&[1, 2]),
        &[],
        &[],
    );
    assert!(!requirement_chirho.closes_share_alone_chirho(&low_bound_chirho));
    let other_subject_chirho = world_chirho.erasure_receipt_chirho(
        holder_chirho,
        OTHER_SUBJECT_CHIRHO,
        5,
        &ids_chirho(&[1, 2]),
        &ids_chirho(&[1, 2]),
        &[],
        &[],
    );
    assert!(!requirement_chirho.closes_share_alone_chirho(&other_subject_chirho));
    let unnamed_holder_chirho = world_chirho.erasure_receipt_chirho(
        &world_chirho.leader_chirho,
        SUBJECT_CHIRHO,
        5,
        &ids_chirho(&[1, 2]),
        &ids_chirho(&[1, 2]),
        &[],
        &[],
    );
    assert!(
        !requirement_chirho.closes_share_alone_chirho(&unnamed_holder_chirho),
        "a holder the requirement does not name closes nothing"
    );
}
