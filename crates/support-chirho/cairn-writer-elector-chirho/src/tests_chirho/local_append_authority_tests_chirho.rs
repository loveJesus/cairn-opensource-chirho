// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Deterministic same-process append-authority tests. These deliberately do not claim exclusion of an
//! unseen remote higher term; they prove only that a locally received transition waits for a held
//! generation guard, blocks new guards with pending priority, and republishes or refuses fail-closed.
//! A roster update is one of those transitions (A6-c).

use crate::elector_port_chirho::NodeIdChirho;
use crate::local_append_authority_chirho::{
    local_append_authority_pair_chirho, LocalAppendAuthorityObservationChirho,
    LocalAppendAuthorityRefusalChirho,
};
use crate::monotonic_clock_chirho::FakeMonotonicClockChirho;
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::{Message, MessageType};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

fn warmed_single_node_chirho(label_chirho: &str) -> Arc<RaftWriterElectorChirho> {
    let node_id_chirho = NodeIdChirho("a".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-local-authority-{label_chirho}-chirho"),
    };
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(node_id_chirho, group_chirho)
            .expect("build local append-authority elector")
            .with_leadership_warmup_lease_chirho(),
    );
    elector_chirho
        .campaign_chirho()
        .expect("single-node elector campaigns");
    for _warmup_tick_chirho in 0..10 {
        elector_chirho.tick_chirho();
    }
    elector_chirho
}

#[test]
fn warm_leadership_and_pending_append_authority_can_coexist_chirho() {
    let elector_chirho = warmed_single_node_chirho("warm-role-pending-authority");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let warm_leadership_chirho = elector_chirho.current_leadership_chirho();
    assert!(warm_leadership_chirho.is_leader_chirho);
    assert!(warm_leadership_chirho.lease_valid_chirho);
    handle_chirho
        .try_acquire_chirho()
        .expect("the completed warm transition initially publishes append authority");

    let pending_transition_chirho = handle_chirho.begin_transition_for_test_chirho();
    let leadership_during_transition_chirho = elector_chirho.current_leadership_chirho();
    assert!(leadership_during_transition_chirho.is_leader_chirho);
    assert!(leadership_during_transition_chirho.lease_valid_chirho);
    assert_eq!(handle_chirho.transition_pending_count_chirho(), 1);
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho)
    ));

    drop(pending_transition_chirho);
    elector_chirho.tick_chirho();
    handle_chirho
        .try_acquire_chirho()
        .expect("the next completed transition republishes append authority");
}

fn assert_observation_refusal_chirho(
    observation_chirho: LocalAppendAuthorityObservationChirho,
    expected_chirho: LocalAppendAuthorityRefusalChirho,
) {
    let (publisher_chirho, handle_chirho) = local_append_authority_pair_chirho(
        ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/tmp/local-authority-refusal-chirho".to_owned(),
        },
        NodeIdChirho("a".repeat(64)),
    );
    publisher_chirho
        .begin_transition_chirho()
        .publish_chirho(observation_chirho);
    let actual_chirho = match handle_chirho.try_acquire_chirho() {
        Ok(_guard_chirho) => panic!("unsafe local append-authority observation was accepted"),
        Err(error_chirho) => error_chirho,
    };
    assert_eq!(actual_chirho, expected_chirho);
}

#[test]
fn fixed_observation_refuses_every_unsafe_authority_field_chirho() {
    let safe_chirho = LocalAppendAuthorityObservationChirho {
        local_is_leader_chirho: true,
        warmup_lease_valid_chirho: true,
        lease_confirmed_millis_chirho: 0,
        local_is_promotable_voter_chirho: true,
        transfer_in_progress_chirho: false,
        published_raft_term_chirho: 7,
    };

    assert_observation_refusal_chirho(
        LocalAppendAuthorityObservationChirho {
            local_is_leader_chirho: false,
            ..safe_chirho
        },
        LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
    );
    assert_observation_refusal_chirho(
        LocalAppendAuthorityObservationChirho {
            warmup_lease_valid_chirho: false,
            ..safe_chirho
        },
        LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho,
    );
    assert_observation_refusal_chirho(
        LocalAppendAuthorityObservationChirho {
            local_is_promotable_voter_chirho: false,
            ..safe_chirho
        },
        LocalAppendAuthorityRefusalChirho::NotPromotableVoterChirho,
    );
    assert_observation_refusal_chirho(
        LocalAppendAuthorityObservationChirho {
            transfer_in_progress_chirho: true,
            ..safe_chirho
        },
        LocalAppendAuthorityRefusalChirho::LeadershipTransferInProgressChirho,
    );
    assert_observation_refusal_chirho(
        LocalAppendAuthorityObservationChirho {
            published_raft_term_chirho: 0,
            ..safe_chirho
        },
        LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho,
    );
    assert_observation_refusal_chirho(
        LocalAppendAuthorityObservationChirho {
            published_raft_term_chirho: u64::from(u32::MAX) + 1,
            ..safe_chirho
        },
        LocalAppendAuthorityRefusalChirho::PublishedRaftTermOutOfRangeChirho,
    );

    let (publisher_chirho, handle_chirho) = local_append_authority_pair_chirho(
        ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/tmp/local-authority-bounds-chirho".to_owned(),
        },
        NodeIdChirho("b".repeat(64)),
    );
    publisher_chirho
        .begin_transition_chirho()
        .publish_chirho(safe_chirho);
    let guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("the complete safe observation is accepted");
    assert_eq!(guard_chirho.published_raft_term_chirho(), 7);
    drop(guard_chirho);

    publisher_chirho.begin_transition_chirho().publish_chirho(
        LocalAppendAuthorityObservationChirho {
            published_raft_term_chirho: u64::from(u32::MAX),
            ..safe_chirho
        },
    );
    let maximum_term_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("the exact writer-fence u32 maximum remains representable");
    assert_eq!(
        maximum_term_guard_chirho.published_raft_term_chirho(),
        u64::from(u32::MAX)
    );
}

#[test]
fn local_append_authority_generation_is_stable_for_the_same_view_chirho() {
    let node_id_chirho = NodeIdChirho("b".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-local-authority-generation-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_chirho(node_id_chirho, group_chirho)
            .expect("build local append-authority elector")
            .with_leadership_warmup_lease_chirho();
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();

    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho)
    ));
    elector_chirho
        .campaign_chirho()
        .expect("single-node elector campaigns");
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
    ));

    for _warmup_tick_chirho in 0..9 {
        elector_chirho.tick_chirho();
    }
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
    ));
    elector_chirho.tick_chirho();

    let first_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("warmed local leader has append authority");
    let first_generation_chirho = first_guard_chirho.process_generation_chirho();
    let first_term_chirho = first_guard_chirho.published_raft_term_chirho();
    assert!(first_generation_chirho > 0);
    assert!((1..=u32::MAX as u64).contains(&first_term_chirho));
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
    ));
    drop(first_guard_chirho);

    elector_chirho.tick_chirho();
    let same_view_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("same leadership view remains admissible");
    assert_eq!(
        same_view_guard_chirho.process_generation_chirho(),
        first_generation_chirho,
        "ordinary same-view heartbeats do not advance the process generation"
    );
    assert_eq!(
        same_view_guard_chirho.published_raft_term_chirho(),
        first_term_chirho
    );
}

#[test]
fn held_guard_delays_higher_term_and_pending_transition_gets_priority_chirho() {
    let elector_chirho = warmed_single_node_chirho("higher-term");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let held_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("warmed local leader has append authority");
    let original_generation_chirho = held_guard_chirho.process_generation_chirho();
    let original_term_chirho = held_guard_chirho.published_raft_term_chirho();

    let mut higher_term_heartbeat_chirho = Message::default();
    higher_term_heartbeat_chirho.set_msg_type(MessageType::MsgHeartbeat);
    higher_term_heartbeat_chirho.from = 2;
    higher_term_heartbeat_chirho.to = 1;
    higher_term_heartbeat_chirho.term = original_term_chirho + 1;

    let (started_sender_chirho, started_receiver_chirho) = mpsc::channel();
    let (done_sender_chirho, done_receiver_chirho) = mpsc::channel();
    let transition_elector_chirho = Arc::clone(&elector_chirho);
    let transition_thread_chirho = thread::spawn(move || {
        started_sender_chirho
            .send(())
            .expect("announce higher-term transition");
        let transition_result_chirho =
            transition_elector_chirho.step_chirho(higher_term_heartbeat_chirho);
        done_sender_chirho
            .send(transition_result_chirho)
            .expect("report higher-term transition");
    });
    started_receiver_chirho
        .recv_timeout(Duration::from_secs(2))
        .expect("transition thread started");

    let pending_deadline_chirho = Instant::now() + Duration::from_secs(2);
    while handle_chirho.transition_pending_count_chirho() == 0
        && Instant::now() < pending_deadline_chirho
    {
        thread::yield_now();
    }
    assert_eq!(handle_chirho.transition_pending_count_chirho(), 1);
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho)
    ));
    assert!(
        matches!(
            done_receiver_chirho.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ),
        "the locally received higher-term transition waits for the held append guard"
    );

    drop(held_guard_chirho);
    done_receiver_chirho
        .recv_timeout(Duration::from_secs(2))
        .expect("higher-term transition completes after guard release")
        .expect("higher-term heartbeat steps cleanly");
    transition_thread_chirho
        .join()
        .expect("higher-term transition thread joins");
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho)
    ));

    elector_chirho
        .campaign_chirho()
        .expect("single-node elector campaigns again");
    for _warmup_tick_chirho in 0..10 {
        elector_chirho.tick_chirho();
    }
    let reelected_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("reelected and rewarmed local leader is admissible");
    assert!(
        reelected_guard_chirho.process_generation_chirho() > original_generation_chirho,
        "a changed leadership tuple advances the process generation"
    );
    assert!(reelected_guard_chirho.published_raft_term_chirho() > original_term_chirho);
}

#[test]
fn multiple_pending_transitions_serialize_behind_one_generation_guard_chirho() {
    let elector_chirho = warmed_single_node_chirho("multiple-pending");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let held_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("warmed local leader has append authority");
    let start_barrier_chirho = Arc::new(Barrier::new(3));
    let mut transition_threads_chirho = Vec::new();
    for _transition_index_chirho in 0..2 {
        let transition_elector_chirho = Arc::clone(&elector_chirho);
        let transition_barrier_chirho = Arc::clone(&start_barrier_chirho);
        transition_threads_chirho.push(thread::spawn(move || {
            transition_barrier_chirho.wait();
            transition_elector_chirho.tick_chirho();
        }));
    }
    start_barrier_chirho.wait();

    let pending_deadline_chirho = Instant::now() + Duration::from_secs(2);
    while handle_chirho.transition_pending_count_chirho() != 2
        && Instant::now() < pending_deadline_chirho
    {
        thread::yield_now();
    }
    assert_eq!(handle_chirho.transition_pending_count_chirho(), 2);
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho)
    ));

    drop(held_guard_chirho);
    for transition_thread_chirho in transition_threads_chirho {
        transition_thread_chirho
            .join()
            .expect("queued local transition joins");
    }
    assert_eq!(handle_chirho.transition_pending_count_chirho(), 0);
    handle_chirho
        .try_acquire_chirho()
        .expect("serialized successful transitions republish authority");
}

#[test]
fn transition_error_and_post_mutation_panic_are_terminal_for_the_elector_chirho() {
    let error_elector_chirho = warmed_single_node_chirho("ordinary-error");
    let error_handle_chirho = error_elector_chirho.local_append_authority_handle_chirho();

    assert!(error_elector_chirho
        .inject_local_append_authority_error_chirho()
        .is_err());
    assert!(matches!(
        error_handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
    ));
    error_elector_chirho.tick_chirho();
    assert!(matches!(
        error_handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
    ));

    let panic_elector_chirho = warmed_single_node_chirho("post-mutation-panic");
    let panic_handle_chirho = panic_elector_chirho.local_append_authority_handle_chirho();
    assert!(panic_elector_chirho
        .inject_local_append_authority_panic_chirho()
        .is_err());
    assert!(matches!(
        panic_handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
    ));
    panic_elector_chirho.tick_chirho();
    assert!(matches!(
        panic_handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
    ));

    let reconstructed_elector_chirho = warmed_single_node_chirho("reconstructed");
    reconstructed_elector_chirho
        .local_append_authority_handle_chirho()
        .try_acquire_chirho()
        .expect("a newly reconstructed elector owns an independent authority pair");
}

#[test]
fn dropping_elector_with_live_guard_does_not_block_and_stale_handle_refuses_chirho() {
    let elector_chirho = warmed_single_node_chirho("owner-drop");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let live_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("warmed local leader has append authority");
    let issued_generation_chirho = live_guard_chirho.process_generation_chirho();

    // The guard borrows only the cloned handle, so dropping the final elector owner while it is live is
    // legal. Teardown must flip the alive bit without waiting on the mutex held by this same thread.
    drop(elector_chirho);
    assert_eq!(
        live_guard_chirho.process_generation_chirho(),
        issued_generation_chirho,
        "an already-issued guard may finish after owner teardown"
    );
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho)
    ));
    drop(live_guard_chirho);

    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::ElectorDroppedChirho)
    ));
}

#[test]
fn exact_handoff_marker_survives_transitions_and_blocks_normal_appends_chirho() {
    let safe_chirho = LocalAppendAuthorityObservationChirho {
        local_is_leader_chirho: true,
        warmup_lease_valid_chirho: true,
        lease_confirmed_millis_chirho: 0,
        local_is_promotable_voter_chirho: true,
        transfer_in_progress_chirho: false,
        published_raft_term_chirho: 11,
    };
    let (publisher_chirho, handle_chirho) = local_append_authority_pair_chirho(
        ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/tmp/local-authority-handoff-chirho".to_owned(),
        },
        NodeIdChirho("c".repeat(64)),
    );
    publisher_chirho
        .begin_transition_chirho()
        .publish_chirho(safe_chirho);
    let handoff_digest_chirho = "d".repeat(64);
    let other_digest_chirho = "e".repeat(64);
    let read_handle_chirho = handle_chirho.handoff_read_handle_chirho();

    read_handle_chirho
        .require_no_active_handoff_chirho()
        .expect("an empty authority slot is observable without mutation authority");

    assert!(matches!(
        handle_chirho.try_prepare_handoff_chirho("NOT-A-DIGEST"),
        Err(LocalAppendAuthorityRefusalChirho::InvalidHandoffIdentityChirho)
    ));
    let preparation_chirho = handle_chirho
        .try_prepare_handoff_chirho(&handoff_digest_chirho)
        .expect("fresh handoff preparation holds the generation gate");
    assert_eq!(
        preparation_chirho.handoff_digest_chirho(),
        handoff_digest_chirho
    );
    assert_eq!(preparation_chirho.published_raft_term_chirho(), 11);
    assert!(preparation_chirho.process_generation_chirho() > 0);
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
    ));

    let active_guard_chirho = preparation_chirho.activate_chirho();
    assert_eq!(
        active_guard_chirho.handoff_digest_chirho(),
        handoff_digest_chirho
    );
    assert_eq!(active_guard_chirho.published_raft_term_chirho(), 11);
    drop(active_guard_chirho);
    assert!(matches!(
        read_handle_chirho.require_no_active_handoff_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
    let read_generation_chirho = handle_chirho
        .try_acquire_handoff_read_chirho(&handoff_digest_chirho)
        .expect("the exact active attempt yields a snapshot-only read witness");
    assert_eq!(
        read_generation_chirho.handoff_digest_chirho(),
        handoff_digest_chirho
    );
    assert_eq!(read_generation_chirho.published_raft_term_chirho(), 11);
    assert!(read_generation_chirho.process_generation_chirho() > 0);
    assert!(matches!(
        handle_chirho.try_acquire_handoff_read_chirho(&other_digest_chirho),
        Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho)
    ));
    warmed_single_node_chirho("other-handoff-group")
        .local_append_authority_handle_chirho()
        .try_acquire_chirho()
        .expect("one group's active handoff cannot freeze another group");
    handle_chirho
        .try_acquire_handoff_chirho(&handoff_digest_chirho)
        .expect("the exact active attempt may revalidate under its generation");
    assert_eq!(
        read_generation_chirho.node_id_chirho(),
        &NodeIdChirho("c".repeat(64)),
        "retaining a read witness must not retain the authority mutex"
    );
    assert!(matches!(
        handle_chirho.try_acquire_handoff_chirho(&other_digest_chirho),
        Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho)
    ));

    publisher_chirho.begin_transition_chirho().publish_chirho(
        LocalAppendAuthorityObservationChirho {
            local_is_leader_chirho: false,
            published_raft_term_chirho: 12,
            ..safe_chirho
        },
    );
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
    assert!(matches!(
        handle_chirho.try_acquire_handoff_chirho(&handoff_digest_chirho),
        Err(LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho)
    ));

    publisher_chirho.begin_transition_chirho().publish_chirho(
        LocalAppendAuthorityObservationChirho {
            published_raft_term_chirho: 13,
            ..safe_chirho
        },
    );
    let resumed_guard_chirho = handle_chirho
        .try_acquire_handoff_chirho(&handoff_digest_chirho)
        .expect("the exact handoff resumes only after safe authority is republished");
    assert_eq!(resumed_guard_chirho.published_raft_term_chirho(), 13);
    drop(resumed_guard_chirho);
    assert!(matches!(
        handle_chirho.try_acquire_handoff_chirho(&other_digest_chirho),
        Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho)
    ));
    handle_chirho
        .try_acquire_handoff_chirho(&handoff_digest_chirho)
        .expect("the exact durable terminal decision reacquires the marker")
        .release_chirho();
    read_handle_chirho
        .require_no_active_handoff_chirho()
        .expect("release makes the shared authority slot observably empty again");
    handle_chirho
        .try_acquire_chirho()
        .expect("normal append authority returns only after exact release");

    handle_chirho
        .restore_handoff_chirho(&handoff_digest_chirho)
        .expect("restart restores one exact active marker");
    handle_chirho
        .restore_handoff_chirho(&handoff_digest_chirho)
        .expect("exact restart replay is idempotent");
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
    handle_chirho
        .try_acquire_handoff_chirho(&handoff_digest_chirho)
        .expect("restored marker reacquires exactly")
        .release_chirho();
}

/// GATE 3 OF THE GD7 COMPENSATION LANE, measured at the layer that owns it (reviewer-authored arm,
/// claude2_chirho, review of `604a98ce`): `try_acquire_active_handoff_append_chirho` admits ONLY
/// the exact active attempt, refuses when no marker is armed at all (the lane can never become an
/// ordinary-append bypass), validates the observation on the same terms as an ordinary
/// acquisition, and its guard leaves the marker exactly as armed — dropping it must NOT release
/// the freeze, which is the no-release property observed behaviorally rather than read off the
/// type.
#[test]
fn active_handoff_append_lane_admits_only_the_exact_active_attempt_chirho() {
    let safe_chirho = LocalAppendAuthorityObservationChirho {
        local_is_leader_chirho: true,
        warmup_lease_valid_chirho: true,
        lease_confirmed_millis_chirho: 0,
        local_is_promotable_voter_chirho: true,
        transfer_in_progress_chirho: false,
        published_raft_term_chirho: 11,
    };
    let (publisher_chirho, handle_chirho) = local_append_authority_pair_chirho(
        ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/tmp/local-authority-compensation-lane-chirho".to_owned(),
        },
        NodeIdChirho("f".repeat(64)),
    );
    publisher_chirho
        .begin_transition_chirho()
        .publish_chirho(safe_chirho);
    let handoff_digest_chirho = "a".repeat(64);
    let other_digest_chirho = "b".repeat(64);

    // NO MARKER ARMED: the lane must refuse rather than degrade into an ordinary acquisition —
    // with no freeze there is nothing to be exempt FROM, and the ordinary path is the lawful one.
    assert!(matches!(
        handle_chirho.try_acquire_active_handoff_append_chirho(&handoff_digest_chirho),
        Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho)
    ));
    // Malformed identity refuses before any state is consulted.
    assert!(matches!(
        handle_chirho.try_acquire_active_handoff_append_chirho("NOT-A-DIGEST"),
        Err(LocalAppendAuthorityRefusalChirho::InvalidHandoffIdentityChirho)
    ));

    handle_chirho
        .try_prepare_handoff_chirho(&handoff_digest_chirho)
        .expect("fresh handoff preparation holds the generation gate")
        .activate_chirho();
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));

    // THE EXACT-ATTEMPT COMPARISON: a different digest — however well-formed — must refuse.
    assert!(matches!(
        handle_chirho.try_acquire_active_handoff_append_chirho(&other_digest_chirho),
        Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho)
    ));

    // The exact attempt admits, and yields the same coordinates an ordinary acquisition would.
    let lane_guard_chirho = handle_chirho
        .try_acquire_active_handoff_append_chirho(&handoff_digest_chirho)
        .expect("the exact active attempt admits the compensation lane");
    assert!(lane_guard_chirho.process_generation_chirho() > 0);
    assert_eq!(lane_guard_chirho.published_raft_term_chirho(), 11);
    // The lane guard holds the authority mutex for its span, exactly like an ordinary guard.
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
    ));

    // DROPPING THE LANE GUARD MUST NOT RELEASE THE MARKER: the lane borrows the freeze and cannot
    // clear it. An `Ok` from the ordinary acquisition here would mean an exempt append ended the
    // handoff freeze it ran under — the one thing this lane must never be able to do.
    drop(lane_guard_chirho);
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));

    // OBSERVATION VALIDATION runs on the same terms as an ordinary acquisition: a deposed local
    // leader cannot use the lane even while naming the exact active attempt.
    publisher_chirho.begin_transition_chirho().publish_chirho(
        LocalAppendAuthorityObservationChirho {
            local_is_leader_chirho: false,
            ..safe_chirho
        },
    );
    assert!(matches!(
        handle_chirho.try_acquire_active_handoff_append_chirho(&handoff_digest_chirho),
        Err(LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho)
    ));
}

fn two_member_roster_chirho() -> Vec<(u64, NodeIdChirho)> {
    vec![
        (1, NodeIdChirho("a".repeat(64))),
        (2, NodeIdChirho("b".repeat(64))),
    ]
}

/// A6-c (gpt #29847): a roster swap is sealed like a Raft transition. A held append guard excludes it,
/// so a recovery effect that revalidated its candidate under that guard commits against the same roster.
#[test]
fn roster_update_waits_for_a_held_guard_and_republishes_after_it_chirho() {
    let elector_chirho = warmed_single_node_chirho("roster-waits");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let held_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("warmed local leader has append authority");

    let (done_sender_chirho, done_receiver_chirho) = mpsc::channel();
    let update_elector_chirho = Arc::clone(&elector_chirho);
    let update_thread_chirho = thread::spawn(move || {
        done_sender_chirho
            .send(update_elector_chirho.update_members_chirho(two_member_roster_chirho()))
            .expect("report the roster update");
    });
    let pending_deadline_chirho = Instant::now() + Duration::from_secs(2);
    while handle_chirho.transition_pending_count_chirho() == 0
        && Instant::now() < pending_deadline_chirho
    {
        thread::yield_now();
    }
    assert_eq!(
        handle_chirho.transition_pending_count_chirho(),
        1,
        "the roster update announces itself as a pending transition"
    );
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::TransitionPendingChirho)
    ));
    assert!(
        matches!(
            done_receiver_chirho.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ),
        "the roster update waits for the held append guard"
    );
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1],
        "the roster is unchanged while the guard is held"
    );

    drop(held_guard_chirho);
    done_receiver_chirho
        .recv_timeout(Duration::from_secs(2))
        .expect("the roster update completes after the guard is released")
        .expect("a valid roster update succeeds");
    update_thread_chirho
        .join()
        .expect("roster update thread joins");
    assert_eq!(elector_chirho.authenticated_member_ids_chirho(), vec![1, 2]);
    assert_eq!(handle_chirho.transition_pending_count_chirho(), 0);
    handle_chirho
        .try_acquire_chirho()
        .expect("the completed roster update republishes usable authority, with no tick");
}

/// Validation runs before admission, so an invalid set refuses at once even behind a held guard, and
/// touches neither the roster nor append authority.
#[test]
fn invalid_roster_refuses_before_the_seal_and_leaves_authority_untouched_chirho() {
    let elector_chirho = warmed_single_node_chirho("roster-invalid");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let held_guard_chirho = handle_chirho
        .try_acquire_chirho()
        .expect("warmed local leader has append authority");

    let (done_sender_chirho, done_receiver_chirho) = mpsc::channel();
    let update_elector_chirho = Arc::clone(&elector_chirho);
    let update_thread_chirho = thread::spawn(move || {
        let duplicate_id_chirho = vec![
            (1, NodeIdChirho("a".repeat(64))),
            (1, NodeIdChirho("b".repeat(64))),
        ];
        done_sender_chirho
            .send(update_elector_chirho.update_members_chirho(duplicate_id_chirho))
            .expect("report the roster refusal");
    });
    let refusal_chirho = done_receiver_chirho
        .recv_timeout(Duration::from_secs(2))
        .expect("an invalid roster refuses without waiting for the held guard")
        .expect_err("a duplicate raft id is refused");
    update_thread_chirho
        .join()
        .expect("roster refusal thread joins");
    assert!(
        refusal_chirho.to_string().contains("appears twice"),
        "{refusal_chirho}"
    );
    assert_eq!(handle_chirho.transition_pending_count_chirho(), 0);
    assert_eq!(elector_chirho.authenticated_member_ids_chirho(), vec![1]);

    drop(held_guard_chirho);
    drop(
        handle_chirho
            .try_acquire_chirho()
            .expect("a refused roster leaves append authority usable"),
    );
    elector_chirho
        .update_members_chirho(elector_chirho.authenticated_members_chirho())
        .expect("control: an unchanged valid set passes through the seal");
    handle_chirho
        .try_acquire_chirho()
        .expect("control: and republishes usable authority");
}

/// gpt #29852: a partial update ends in terminal refusal, never stale success. An exhausted roster
/// generation makes the bump panic after the new set is already in place.
#[test]
fn roster_update_that_panics_after_its_swap_poisons_append_authority_chirho() {
    let elector_chirho = warmed_single_node_chirho("roster-partial");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    drop(
        handle_chirho
            .try_acquire_chirho()
            .expect("starts with usable append authority"),
    );

    elector_chirho.exhaust_roster_generation_for_test_chirho();
    let failure_chirho = elector_chirho
        .update_members_chirho(two_member_roster_chirho())
        .expect_err("an exhausted generation panics inside the seal");
    assert!(
        failure_chirho.to_string().contains("terminally poisoned"),
        "{failure_chirho}"
    );
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1, 2],
        "the new set landed before the panic: the partial update the poison exists for"
    );
    assert_eq!(handle_chirho.transition_pending_count_chirho(), 0);
    assert!(matches!(
        handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
    ));
    elector_chirho.tick_chirho();
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::AuthorityPoisonedChirho)
        ),
        "a later transition cannot revive poisoned authority"
    );
}

/// gpt #29852: a roster update is a non-tick event. A live lease stays usable through it with no tick,
/// and an expired lease stays expired until a real clock tick.
#[test]
fn roster_update_republishes_without_refreshing_the_lease_chirho() {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-local-authority-roster-lease-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("a".repeat(64)),
            group_chirho,
            clock_chirho.clone(),
            500,
            500,
        )
        .expect("build a lease-backed elector");
    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");
    for _warmup_step_chirho in 0..20 {
        clock_chirho.advance_millis_chirho(50);
        elector_chirho.tick_chirho();
    }
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    drop(handle_chirho.try_acquire_chirho().expect("warmed and live"));

    clock_chirho.advance_millis_chirho(100);
    elector_chirho
        .update_members_chirho(two_member_roster_chirho())
        .expect("valid roster update");
    drop(
        handle_chirho
            .try_acquire_chirho()
            .expect("a live lease stays usable through a roster update, with no tick"),
    );

    clock_chirho.advance_millis_chirho(500);
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ),
        "600 ms after the last tick, the 500 ms lease has expired"
    );
    elector_chirho
        .update_members_chirho(vec![(1, NodeIdChirho("a".repeat(64)))])
        .expect("valid roster update");
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ),
        "a roster update is not a heartbeat: the expired lease stays expired"
    );
    elector_chirho.tick_chirho();
    handle_chirho
        .try_acquire_chirho()
        .expect("a clock tick does refresh it, so the refusal above was the expiry");
}

/// gpt #29947: a roster update republishes warmth that elapsed time has earned, but never past the
/// original confirmation's expiry. The 300 ms warm-up is shorter than the 500 ms expiry, so there is a
/// window where the warm-up has passed and the last tick's confirmation is still live.
#[test]
fn roster_update_publishes_elapsed_warmth_but_never_past_the_original_expiry_chirho() {
    let clock_chirho = FakeMonotonicClockChirho::new_chirho();
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-local-authority-roster-warmth-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_single_node_with_monotonic_leadership_lease_chirho(
            NodeIdChirho("a".repeat(64)),
            group_chirho,
            clock_chirho.clone(),
            300,
            500,
        )
        .expect("build a lease-backed elector");
    elector_chirho
        .campaign_chirho()
        .expect("campaign to leader");
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();

    // One clock tick at t=10 starts leadership and confirms it. Nothing has warmed yet.
    clock_chirho.advance_millis_chirho(10);
    elector_chirho.tick_chirho();
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ),
        "the published observation starts unwarmed"
    );

    // t=410, with no tick. 400 ms of leadership is past the warm-up, and the t=10 confirmation is 400
    // ms old, inside its 500 ms expiry. Until something republishes, the cached observation is unwarmed.
    clock_chirho.advance_millis_chirho(400);
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ),
        "with no republish, the cached observation is still unwarmed"
    );
    elector_chirho
        .update_members_chirho(two_member_roster_chirho())
        .expect("valid roster update");
    drop(
        handle_chirho
            .try_acquire_chirho()
            .expect("the republish recomputes the warmth that elapsed time earned"),
    );

    // t=510: the ORIGINAL t=10 confirmation reaches its 500 ms expiry, because nothing extended it.
    clock_chirho.advance_millis_chirho(100);
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ),
        "the original confirmation's expiry still binds"
    );
    elector_chirho
        .update_members_chirho(vec![(1, NodeIdChirho("a".repeat(64)))])
        .expect("valid roster update");
    assert!(
        matches!(
            handle_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::WarmupLeaseInvalidChirho)
        ),
        "a second roster update cannot extend it"
    );
    elector_chirho.tick_chirho();
    handle_chirho
        .try_acquire_chirho()
        .expect("a real clock tick does refresh it, so the refusals above were the expiry");
}
