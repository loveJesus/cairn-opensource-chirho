// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Erasure propagation over real HTTP (C5 B3-a3-ii, item 14 D3 and D4): one fresh frame per open holder, the leader's own holder reached in process, every receipt kept only through the answer check, authority read before every attempt, and one budget bounding the call.

use super::propagation_world_chirho::*;
use super::world_chirho::{key_id_chirho, serve_router_chirho, FIRST_TERM_CHIRHO};
use crate::leader_chirho::propagate_chirho::{
    classify_refusal_chirho, propagate_erasure_requirement_chirho, ErasureDeliveryErrorChirho,
    ErasureHolderOutcomeChirho, ErasureHolderSeamChirho, ErasureLeaderAuthorityChirho,
    ErasurePropagationPacingChirho, ErasurePropagationPolicyChirho, ErasurePropagationStopChirho,
    ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO,
};
use crate::leader_chirho::refusal_chirho::LeaderRefusalIdentityChirho;
use crate::leader_chirho::store_chirho::{
    EarlierErasureChirho, ErasurePropagationStoreChirho, RecordRequirementRequestChirho,
};
use cairn_key_custody_chirho::{ErasurePropagationContextChirho, ErasureStatusChirho};
use cairn_mirror_chirho::join_mirror_view_chirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::MonotonicClockChirho;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

#[test]
fn one_call_closes_every_holder_with_one_fresh_frame_each_and_a_second_call_sends_nothing_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    );
    assert_eq!(report_chirho.stopped_chirho, None);
    assert!(report_chirho
        .holders_chirho
        .values()
        .all(|outcome_chirho| *outcome_chirho == ErasureHolderOutcomeChirho::ClosedChirho));
    let sent_to_chirho = recording_chirho.holders_chirho();
    assert_eq!(
        sent_to_chirho.iter().cloned().collect::<BTreeSet<_>>(),
        world_chirho.holder_ids_chirho(),
        "one frame to each holder, the leader's own included"
    );
    assert_eq!(sent_to_chirho.len(), 3);
    let second_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let again_chirho = world_chirho
        .propagate_chirho(0, &second_chirho, ErasurePropagationPolicyChirho::default())
        .unwrap();
    assert!(
        second_chirho.holders_chirho().is_empty(),
        "a holder whose stored receipts close its share gets no frame"
    );
    assert!(again_chirho
        .holders_chirho
        .values()
        .all(|outcome_chirho| *outcome_chirho == ErasureHolderOutcomeChirho::AlreadyClosedChirho));
}

#[test]
fn a_peer_that_does_not_answer_stays_pending_and_a_later_call_reaches_only_it_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let down_chirho = world_chirho.peer_b_chirho.id_chirho().to_string();
    let mut origins_chirho = world_chirho.peer_origins_chirho.clone();
    origins_chirho.insert(down_chirho.clone(), dead_origin_chirho());
    let seam_chirho = world_chirho.seam_with_chirho(origins_chirho);
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        pending_chirho(&[&down_chirho])
    );
    assert_eq!(
        report_chirho.holders_chirho[&down_chirho],
        ErasureHolderOutcomeChirho::UnansweredChirho { attempts_chirho: 3 }
    );
    assert_eq!(
        recording_chirho
            .holders_chirho()
            .iter()
            .filter(|holder_chirho| **holder_chirho == down_chirho)
            .count(),
        3,
        "bounded attempts"
    );
    let back_chirho = world_chirho.seam_chirho();
    let rerun_chirho = RecordingSeamChirho::passing_chirho(&back_chirho);
    let later_chirho = world_chirho
        .propagate_chirho(0, &rerun_chirho, ErasurePropagationPolicyChirho::default())
        .unwrap();
    assert_eq!(rerun_chirho.holders_chirho(), vec![down_chirho]);
    assert_eq!(
        *later_chirho.attempt_chirho.status_chirho(),
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    );
}

#[test]
fn a_holder_without_a_route_stays_pending_and_is_never_dropped_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let unrouted_chirho = world_chirho.peer_b_chirho.id_chirho().to_string();
    let mut origins_chirho = world_chirho.peer_origins_chirho.clone();
    origins_chirho.remove(&unrouted_chirho);
    let seam_chirho = world_chirho.seam_with_chirho(origins_chirho);
    let report_chirho = world_chirho
        .propagate_chirho(0, &seam_chirho, ErasurePropagationPolicyChirho::default())
        .unwrap();
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        pending_chirho(&[&unrouted_chirho])
    );
    assert_eq!(
        report_chirho.holders_chirho[&unrouted_chirho],
        ErasureHolderOutcomeChirho::RefusedChirho(ErasureDeliveryErrorChirho::NoRouteChirho)
    );
}

#[test]
fn a_node_that_is_not_the_leader_with_a_live_lease_sends_and_stores_nothing_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let seam_chirho = world_chirho.seam_chirho();
    for (name_chirho, leader_chirho, remaining_chirho) in [
        (
            "another leader",
            world_chirho.peer_a_chirho.id_chirho().to_string(),
            Some(LEASE_MILLIS_CHIRHO),
        ),
        (
            "no lease",
            world_chirho.leader_chirho.id_chirho().to_string(),
            None,
        ),
    ] {
        world_chirho.set_leader_view_chirho(&leader_chirho, remaining_chirho);
        let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
        assert_eq!(
            leader_refusal_chirho(world_chirho.propagate_chirho(
                0,
                &recording_chirho,
                ErasurePropagationPolicyChirho::default(),
            )),
            LeaderRefusalIdentityChirho::ErasurePropagationNotLeaderChirho,
            "{name_chirho}"
        );
        assert!(
            recording_chirho.holders_chirho().is_empty(),
            "{name_chirho}: nothing sent"
        );
        assert!(
            !world_chirho.receipts_dir_chirho(0).exists(),
            "{name_chirho}: nothing stored"
        );
    }
}

#[test]
fn deposed_after_the_first_holder_the_call_stops_and_keeps_that_receipt_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let seam_chirho = world_chirho.seam_chirho();
    let other_leader_chirho = world_chirho.peer_a_chirho.id_chirho().to_string();
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.after_chirho = Box::new(|index_chirho| {
        if index_chirho == 0 {
            world_chirho.set_leader_view_chirho(&other_leader_chirho, Some(LEASE_MILLIS_CHIRHO));
        }
    });
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    let first_chirho = recording_chirho.holders_chirho()[0].clone();
    assert_eq!(
        recording_chirho.holders_chirho().len(),
        1,
        "no attempt after deposition"
    );
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::NotLeaderChirho)
    );
    assert_eq!(
        report_chirho.holders_chirho[&first_chirho],
        ErasureHolderOutcomeChirho::ClosedChirho
    );
    let rest_chirho = world_chirho
        .holder_ids_chirho()
        .into_iter()
        .filter(|holder_chirho| *holder_chirho != first_chirho)
        .collect::<Vec<_>>();
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        pending_chirho(&rest_chirho.iter().map(String::as_str).collect::<Vec<_>>()),
        "the first receipt is stored and counts"
    );
}

#[test]
fn a_holder_refusing_this_node_as_its_leader_stops_the_whole_call_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let seam_chirho = world_chirho.seam_chirho();
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.before_chirho =
        Box::new(|_, _| Some(ErasureDeliveryErrorChirho::AuthorityRefusedChirho));
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::DeposedChirho)
    );
    assert_eq!(
        recording_chirho.holders_chirho().len(),
        1,
        "no holder is tried after it"
    );
    assert_eq!(
        report_chirho
            .holders_chirho
            .values()
            .filter(
                |outcome_chirho| **outcome_chirho == ErasureHolderOutcomeChirho::NotReachedChirho
            )
            .count(),
        2
    );
    assert!(!world_chirho.receipts_dir_chirho(0).exists());
}

#[test]
fn an_unbound_or_carried_requirement_refuses_before_anything_is_sent_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), false);
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    assert_eq!(
        leader_refusal_chirho(world_chirho.propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )),
        LeaderRefusalIdentityChirho::ErasurePropagationRequirementUnboundChirho,
        "unbound"
    );
    world_chirho.record_chirho(
        1,
        BTreeMap::from([(0, EarlierErasureChirho::NeverRecordedChirho)]),
        true,
    );
    assert_eq!(
        leader_refusal_chirho(world_chirho.propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )),
        LeaderRefusalIdentityChirho::ErasurePropagationRequirementUnboundChirho,
        "carried by a bound successor, never propagated on its own"
    );
    assert!(recording_chirho.holders_chirho().is_empty());
}

#[test]
fn a_refusal_and_a_receipt_for_another_frame_each_leave_their_holder_pending_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let refusing_chirho = world_chirho.peer_a_chirho.id_chirho().to_string();
    let answering_wrongly_chirho = world_chirho.peer_b_chirho.id_chirho().to_string();
    // A stub for peer A refuses by a fixed name; one for peer B answers with B's genuine receipt for another frame.
    let other_frame_receipt_chirho = {
        let seam_chirho = world_chirho.seam_chirho();
        let to_b_chirho = world_chirho
            .store_chirho
            .sign_erasure_frame_chirho(
                cairn_key_custody_chirho::PreparedErasureFrameChirho::new_chirho(
                    cairn_key_custody_chirho::ErasureFrameInputChirho {
                        consistency_group_digest_chirho: world_chirho
                            .store_chirho
                            .group_digest_chirho()
                            .to_string(),
                        membership_view_digest_chirho: join_mirror_view_chirho(
                            &world_chirho.placement_chirho,
                            world_chirho.leader_view_chirho.as_ref(),
                        )
                        .unwrap()
                        .view_chirho()
                        .view_digest_chirho(),
                        elected_term_chirho: FIRST_TERM_CHIRHO,
                        origin_node_id_chirho: world_chirho.leader_chirho.id_chirho().to_string(),
                        holder_node_id_chirho: answering_wrongly_chirho.clone(),
                        leader_lease_remaining_millis_chirho: Some(LEASE_MILLIS_CHIRHO),
                        subject_digest_chirho: subject_chirho(),
                        erased_below_blob_seq_chirho: BOUND_CHIRHO + 9,
                        key_ids_chirho: [key_id_chirho(1), key_id_chirho(2)].into(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
        seam_chirho
            .deliver_erasure_chirho(
                &answering_wrongly_chirho,
                &to_b_chirho,
                Duration::from_secs(10),
            )
            .expect("B answers its own frame")
            .record_chirho()
            .to_wire_bytes_chirho()
            .unwrap()
    };
    // Each stub reads its request body, so the server never closes a connection with the body unread (see
    // `http_tests_chirho.rs`).
    let stub_chirho = axum::Router::new()
        .route(
            "/refusing-chirho/key-custody-chirho/v1/erasure",
            axum::routing::post(|_body_chirho: axum::body::Bytes| async {
                (
                    axum::http::StatusCode::CONFLICT,
                    "HolderErasureScanTooLargeChirho",
                )
            }),
        )
        .route(
            "/wrong-chirho/key-custody-chirho/v1/erasure",
            axum::routing::post(move |_body_chirho: axum::body::Bytes| {
                let answer_chirho = other_frame_receipt_chirho.clone();
                async move { answer_chirho }
            }),
        );
    let (_stub_runtime_chirho, stub_origin_chirho) = serve_router_chirho(stub_chirho);
    let mut origins_chirho = world_chirho.peer_origins_chirho.clone();
    origins_chirho.insert(
        refusing_chirho.clone(),
        format!("{stub_origin_chirho}/refusing-chirho"),
    );
    origins_chirho.insert(
        answering_wrongly_chirho.clone(),
        format!("{stub_origin_chirho}/wrong-chirho"),
    );
    let seam_chirho = world_chirho.seam_with_chirho(origins_chirho);
    let report_chirho = world_chirho
        .propagate_chirho(0, &seam_chirho, ErasurePropagationPolicyChirho::default())
        .unwrap();
    assert_eq!(
        report_chirho.holders_chirho[&refusing_chirho],
        ErasureHolderOutcomeChirho::RefusedChirho(ErasureDeliveryErrorChirho::RefusedChirho)
    );
    assert_eq!(
        report_chirho.holders_chirho[&answering_wrongly_chirho],
        ErasureHolderOutcomeChirho::RefusedChirho(
            ErasureDeliveryErrorChirho::ReceiptRejectedChirho
        )
    );
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        pending_chirho(&[&refusing_chirho, &answering_wrongly_chirho])
    );
    for holder_chirho in [&refusing_chirho, &answering_wrongly_chirho] {
        assert!(
            !world_chirho
                .receipts_dir_chirho(0)
                .join(holder_chirho)
                .exists(),
            "nothing stored"
        );
    }
}

#[test]
fn a_delivered_receipt_the_store_refuses_does_not_count_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let blocked_chirho = world_chirho.peer_a_chirho.id_chirho().to_string();
    // The holder's receipt directory exists, private, but not writable: the store cannot keep the receipt.
    let blocked_dir_chirho = world_chirho.receipts_dir_chirho(0).join(&blocked_chirho);
    for dir_chirho in [
        world_chirho.receipts_dir_chirho(0),
        blocked_dir_chirho.clone(),
    ] {
        fs::create_dir_all(&dir_chirho).unwrap();
        fs::set_permissions(&dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::set_permissions(&blocked_dir_chirho, fs::Permissions::from_mode(0o500)).unwrap();
    let seam_chirho = world_chirho.seam_chirho();
    let report_chirho = world_chirho
        .propagate_chirho(0, &seam_chirho, ErasurePropagationPolicyChirho::default())
        .unwrap();
    fs::set_permissions(&blocked_dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        report_chirho.holders_chirho[&blocked_chirho],
        ErasureHolderOutcomeChirho::StoreRefusedChirho
    );
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        pending_chirho(&[&blocked_chirho]),
        "status is read back from the store, so a receipt it could not keep does not count"
    );
}

#[test]
fn a_retry_signs_a_fresh_frame_under_a_renewed_lease_and_never_without_one_chirho() {
    // Positive: the first attempt to the first holder goes unanswered and the lease is renewed meanwhile.
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let seam_chirho = world_chirho.seam_chirho();
    let renewed_chirho = 7_000_u64;
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.before_chirho = Box::new(|index_chirho, _| {
        (index_chirho == 0).then(|| {
            world_chirho.set_leader_view_chirho(
                world_chirho.leader_chirho.id_chirho(),
                Some(renewed_chirho),
            );
            ErasureDeliveryErrorChirho::TransportChirho
        })
    });
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    let deliveries_chirho = recording_chirho.deliveries_chirho.borrow().clone();
    assert_eq!(
        deliveries_chirho[0].holder_chirho,
        deliveries_chirho[1].holder_chirho
    );
    // Each frame carries the lease read for it, less the signing reserve; no time passes while it is prepared.
    let reserve_chirho = ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO.as_millis() as u64;
    assert_eq!(
        deliveries_chirho[0].lease_chirho,
        Some(LEASE_MILLIS_CHIRHO - reserve_chirho)
    );
    assert_eq!(
        deliveries_chirho[1].lease_chirho,
        Some(renewed_chirho - reserve_chirho),
        "the retry carries the lease read for it, not the old one and not an invented one"
    );
    assert_ne!(
        deliveries_chirho[0].frame_digest_chirho, deliveries_chirho[1].frame_digest_chirho,
        "the retry is a freshly signed frame"
    );
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    );

    // Negative: the first attempt goes unanswered and the lease is NOT renewed: nothing more is sent.
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let seam_chirho = world_chirho.seam_chirho();
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.before_chirho = Box::new(|index_chirho, _| {
        (index_chirho == 0).then(|| {
            world_chirho.set_leader_view_chirho(world_chirho.leader_chirho.id_chirho(), None);
            ErasureDeliveryErrorChirho::TransportChirho
        })
    });
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    assert_eq!(
        recording_chirho.holders_chirho().len(),
        1,
        "no attempt without a live lease"
    );
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::NotLeaderChirho)
    );
}

#[test]
fn one_budget_bounds_the_call_and_cuts_every_timeout_and_backoff_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    let seam_chirho = world_chirho.seam_chirho();
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.before_chirho =
        Box::new(|_, _| Some(ErasureDeliveryErrorChirho::TransportChirho));
    let started_chirho = world_chirho.clock_chirho.now_millis_chirho();
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho {
                attempts_per_holder_chirho: 3,
                first_backoff_chirho: Duration::from_millis(200),
                request_timeout_chirho: Duration::from_secs(5),
                call_budget_chirho: Duration::from_secs(1),
                ..ErasurePropagationPolicyChirho::default()
            },
        )
        .unwrap();
    // The first holder: 1000, then 800 after a 200 ms pause, then 400 after a 400 ms pause. The second holder:
    // 400, then 200 after a 200 ms pause, then a 200 ms pause cut to what remained, and the budget is spent.
    let timeouts_chirho = recording_chirho
        .deliveries_chirho
        .borrow()
        .iter()
        .map(|delivery_chirho| delivery_chirho.timeout_chirho.as_millis() as u64)
        .collect::<Vec<_>>();
    assert_eq!(timeouts_chirho, vec![1000, 800, 400, 400, 200]);
    assert_eq!(
        world_chirho.clock_chirho.now_millis_chirho() - started_chirho,
        1000,
        "every pause was cut to what remained, so the call took exactly its budget"
    );
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::BudgetSpentChirho)
    );
    assert_eq!(
        report_chirho
            .holders_chirho
            .values()
            .filter(
                |outcome_chirho| **outcome_chirho == ErasureHolderOutcomeChirho::NotReachedChirho
            )
            .count(),
        1,
        "no work starts once the budget is spent"
    );
}

#[test]
fn only_a_deposing_refusal_stops_the_call_and_an_interrupted_admission_is_retried_chirho() {
    for (identity_chirho, expected_chirho) in [
        (
            "HolderStaleTermChirho",
            ErasureDeliveryErrorChirho::AuthorityRefusedChirho,
        ),
        (
            "CustodyAuthorityRefusedChirho:MirrorSenderNotLeaderChirho",
            ErasureDeliveryErrorChirho::AuthorityRefusedChirho,
        ),
        (
            "CustodyAuthorityRefusedChirho:MirrorTermInvalidChirho",
            ErasureDeliveryErrorChirho::AuthorityRefusedChirho,
        ),
        (
            "CustodyAuthorityRefusedChirho:MirrorLeaseExpiredChirho",
            ErasureDeliveryErrorChirho::AuthorityRefusedChirho,
        ),
        (
            "CustodyAuthorityRefusedChirho:MirrorMembershipViewMismatchChirho",
            ErasureDeliveryErrorChirho::RefusedChirho,
        ),
        (
            "HolderAdmissionInterruptedChirho",
            ErasureDeliveryErrorChirho::TransportChirho,
        ),
        (
            "HolderErasureBindingUnverifiableChirho",
            ErasureDeliveryErrorChirho::RefusedChirho,
        ),
        ("", ErasureDeliveryErrorChirho::RefusedChirho),
    ] {
        assert_eq!(
            classify_refusal_chirho(identity_chirho),
            expected_chirho,
            "{identity_chirho:?}"
        );
    }
}

#[test]
fn a_view_of_another_group_refuses_before_anything_is_sent_chirho() {
    let world_chirho = propagation_world_chirho();
    // A store for another group, on the leader's own root, with a bound requirement for all three holders.
    let other_store_chirho = ErasurePropagationStoreChirho::open_chirho(
        &world_chirho.leader_root_chirho,
        ErasurePropagationContextChirho::new_chirho(
            &"22".repeat(32),
            TENANT_CHIRHO,
            INSTANCE_CHIRHO,
            world_chirho.leader_chirho.id_chirho(),
        )
        .expect("context in form"),
    )
    .expect("store opens");
    other_store_chirho
        .record_requirement_chirho(&RecordRequirementRequestChirho {
            subject_digest_chirho: subject_chirho(),
            erasure_seq_chirho: 0,
            erased_below_blob_seq_chirho: BOUND_CHIRHO,
            key_ids_chirho: [key_id_chirho(1), key_id_chirho(2)].into(),
            holders_chirho: world_chirho.holder_ids_chirho(),
            earlier_chirho: BTreeMap::new(),
        })
        .expect("requirement records");
    other_store_chirho
        .record_binding_chirho(&subject_chirho(), 0, &"ab".repeat(32))
        .expect("requirement binds");
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let clock_chirho = world_chirho.clock_chirho.clone();
    let sleep_chirho = move |pause_chirho: Duration| {
        clock_chirho.advance_millis_chirho(pause_chirho.as_millis() as u64);
    };
    let refused_chirho = propagate_erasure_requirement_chirho(
        &other_store_chirho,
        &subject_chirho(),
        0,
        &ErasureLeaderAuthorityChirho {
            placement_chirho: &world_chirho.placement_chirho,
            election_view_chirho: world_chirho.leader_view_chirho.as_ref(),
        },
        &recording_chirho,
        &ErasurePropagationPacingChirho {
            policy_chirho: ErasurePropagationPolicyChirho::default(),
            clock_chirho: world_chirho.clock_chirho.as_ref(),
            sleep_chirho: &sleep_chirho,
        },
    );
    assert_eq!(
        leader_refusal_chirho(refused_chirho),
        LeaderRefusalIdentityChirho::ErasurePropagationViewGroupMismatchChirho
    );
    assert!(recording_chirho.holders_chirho().is_empty(), "nothing sent");
}
