// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The promotion-exit watcher fires only on sustained warm local leadership after arming, the startup
//! stability window outlasts a doomed winner, and only a relay-only follower is watched.

use crate::promotion_exit_chirho::{
    startup_deadline_chirho, watches_startup_role_chirho, PromotionExitDetectorChirho,
    PromotionExitTimingChirho, PromotionExitWatchChirho, RemoteOwnerStabilityChirho,
    PROMOTION_EXIT_IDENTITY_CHIRHO,
};
use crate::voter_startup_chirho::{
    GeoNonResidentVoterRoleChirho, GeoVoterStartupOwnershipChirho, GeoVoterStartupRoleChirho,
    StartupSettleChirho, StartupStepChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::{LeadershipChirho, NodeIdChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::election_timeout_upper_bound_chirho;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TICK_CHIRHO: Duration = Duration::from_millis(250);

fn local_chirho() -> NodeIdChirho {
    NodeIdChirho("local-chirho".to_owned())
}

fn remote_chirho() -> NodeIdChirho {
    NodeIdChirho("remote-chirho".to_owned())
}

fn warm_local_chirho(term_chirho: u64) -> LeadershipChirho {
    LeadershipChirho {
        is_leader_chirho: true,
        leader_id_chirho: Some(local_chirho()),
        term_chirho,
        lease_valid_chirho: true,
    }
}

fn timing_chirho() -> PromotionExitTimingChirho {
    PromotionExitTimingChirho::from_driver_tick_chirho(TICK_CHIRHO).expect("deployable tick")
}

#[test]
fn watcher_fires_only_after_arming_and_a_full_unbroken_confirmation_chirho() {
    let timing_chirho = timing_chirho();
    let start_chirho = Instant::now();
    let mut detector_chirho = PromotionExitDetectorChirho::new_chirho(start_chirho, timing_chirho);
    let armed_chirho = start_chirho + timing_chirho.arming_chirho;

    // Warm local leadership before arming never counts, however long it lasts.
    assert!(!detector_chirho.observe_chirho(start_chirho, &warm_local_chirho(5), &local_chirho()));
    assert!(!detector_chirho.observe_chirho(
        armed_chirho - Duration::from_millis(1),
        &warm_local_chirho(5),
        &local_chirho()
    ));

    // From arming, the confirmation window must elapse without a break.
    assert!(!detector_chirho.observe_chirho(armed_chirho, &warm_local_chirho(5), &local_chirho()));
    assert!(!detector_chirho.observe_chirho(
        armed_chirho + timing_chirho.confirm_chirho - Duration::from_millis(1),
        &warm_local_chirho(5),
        &local_chirho()
    ));
    assert!(
        detector_chirho.observe_chirho(
            armed_chirho + timing_chirho.confirm_chirho,
            &warm_local_chirho(5),
            &local_chirho()
        ),
        "a full confirmation window of warm local leadership after arming must fire"
    );
}

#[test]
fn any_observation_that_is_not_warm_local_leadership_restarts_the_window_chirho() {
    let timing_chirho = timing_chirho();
    let start_chirho = Instant::now();
    let armed_chirho = start_chirho + timing_chirho.arming_chirho;
    let not_warm_chirho = [
        LeadershipChirho {
            lease_valid_chirho: false,
            ..warm_local_chirho(5)
        },
        LeadershipChirho {
            is_leader_chirho: false,
            ..warm_local_chirho(5)
        },
        LeadershipChirho {
            is_leader_chirho: false,
            leader_id_chirho: Some(remote_chirho()),
            term_chirho: 5,
            lease_valid_chirho: false,
        },
        LeadershipChirho {
            is_leader_chirho: false,
            leader_id_chirho: None,
            term_chirho: 5,
            lease_valid_chirho: false,
        },
    ];
    for break_chirho in not_warm_chirho {
        let mut detector_chirho =
            PromotionExitDetectorChirho::new_chirho(start_chirho, timing_chirho);
        assert!(!detector_chirho.observe_chirho(
            armed_chirho,
            &warm_local_chirho(5),
            &local_chirho()
        ));
        let mid_chirho = armed_chirho + timing_chirho.confirm_chirho / 2;
        assert!(!detector_chirho.observe_chirho(mid_chirho, &break_chirho, &local_chirho()));
        // The original window has now elapsed, but the break restarted it.
        let after_chirho = armed_chirho + timing_chirho.confirm_chirho;
        assert!(
            !detector_chirho.observe_chirho(after_chirho, &warm_local_chirho(5), &local_chirho()),
            "a break of {break_chirho:?} must restart the confirmation window"
        );
        assert!(detector_chirho.observe_chirho(
            after_chirho + timing_chirho.confirm_chirho,
            &warm_local_chirho(5),
            &local_chirho()
        ));
    }
}

#[test]
fn remote_owner_stability_needs_one_owner_at_one_term_for_the_whole_window_chirho() {
    let window_chirho = Duration::from_secs(10);
    let start_chirho = Instant::now();
    let mut stability_chirho = RemoteOwnerStabilityChirho::default();
    assert!(!stability_chirho.observe_chirho(start_chirho, &remote_chirho(), 7, window_chirho));
    assert!(!stability_chirho.observe_chirho(
        start_chirho + window_chirho - Duration::from_millis(1),
        &remote_chirho(),
        7,
        window_chirho
    ));
    assert!(stability_chirho.observe_chirho(
        start_chirho + window_chirho,
        &remote_chirho(),
        7,
        window_chirho
    ));

    // A new term restarts the window, as does a different owner, as does a reset.
    let mut term_change_chirho = RemoteOwnerStabilityChirho::default();
    assert!(!term_change_chirho.observe_chirho(start_chirho, &remote_chirho(), 7, window_chirho));
    assert!(!term_change_chirho.observe_chirho(
        start_chirho + window_chirho,
        &remote_chirho(),
        8,
        window_chirho
    ));
    let mut owner_change_chirho = RemoteOwnerStabilityChirho::default();
    assert!(!owner_change_chirho.observe_chirho(start_chirho, &remote_chirho(), 7, window_chirho));
    assert!(!owner_change_chirho.observe_chirho(
        start_chirho + window_chirho,
        &NodeIdChirho("third-chirho".to_owned()),
        7,
        window_chirho
    ));
    let mut reset_chirho = RemoteOwnerStabilityChirho::default();
    assert!(!reset_chirho.observe_chirho(start_chirho, &remote_chirho(), 7, window_chirho));
    reset_chirho.reset_chirho();
    assert!(!reset_chirho.observe_chirho(
        start_chirho + window_chirho,
        &remote_chirho(),
        7,
        window_chirho
    ));
}

#[test]
fn startup_stability_window_outlasts_a_doomed_winner_and_the_election_after_it_chirho() {
    let timing_chirho = timing_chirho();
    let election_upper_bound_chirho =
        election_timeout_upper_bound_chirho(TICK_CHIRHO).expect("deployable tick");
    // A relay-only winner stays visible for its arming, confirmation and bounded exit, and a
    // follower keeps naming it until that follower's own election timeout fires. The window must
    // STRICTLY exceed that whole visible life, or a starting voter can settle under a winner that
    // is about to leave; the second election timeout in the window is the margin that makes it
    // strict.
    let doomed_visible_life_chirho = timing_chirho.arming_chirho
        + timing_chirho.confirm_chirho
        + timing_chirho.exit_budget_chirho
        + election_upper_bound_chirho;
    assert!(
        timing_chirho.remote_owner_stability_chirho > doomed_visible_life_chirho,
        "stability window {:?} does not outlast a doomed winner's visible life {:?}",
        timing_chirho.remote_owner_stability_chirho,
        doomed_visible_life_chirho
    );
    // It must still leave most of the bounded 30 s startup interval for an election to finish.
    assert!(timing_chirho.remote_owner_stability_chirho < Duration::from_secs(15));
    assert!(PromotionExitTimingChirho::from_driver_tick_chirho(Duration::ZERO).is_err());
}

#[test]
fn only_a_relay_only_follower_runs_the_watcher_chirho() {
    assert!(watches_startup_role_chirho(
        GeoVoterStartupRoleChirho::NonResidentChirho(
            GeoNonResidentVoterRoleChirho::RemoteOwnerChirho
        )
    ));
    assert!(!watches_startup_role_chirho(
        GeoVoterStartupRoleChirho::LocalWarmOwnerChirho
    ));
    assert!(!watches_startup_role_chirho(
        GeoVoterStartupRoleChirho::NonResidentChirho(
            GeoNonResidentVoterRoleChirho::RetiringTransportOnlyChirho
        )
    ));
}

#[test]
fn a_fired_watch_finishes_as_the_fixed_identity_and_releases_the_forced_exit_wait_chirho() {
    // The composition's exit step: a watch that fired must surface the fixed identity, so the
    // process exits non-zero and the supervisor restarts it; a quiet watch must finish cleanly.
    // Either way, finishing marks the stop complete, which is what keeps a fired watcher from
    // forcing an exit the composition already finished.
    let fired_shutdown_chirho = Arc::new(AtomicBool::new(false));
    let fired_chirho = PromotionExitWatchChirho {
        thread_chirho: None,
        fired_chirho: Arc::new(AtomicBool::new(true)),
        shutdown_complete_chirho: Arc::clone(&fired_shutdown_chirho),
    };
    let error_chirho = fired_chirho
        .finish_chirho()
        .expect_err("a fired watch must finish as an error");
    assert!(
        error_chirho
            .to_string()
            .contains(PROMOTION_EXIT_IDENTITY_CHIRHO),
        "the error must carry the fixed identity; got {error_chirho:#}"
    );
    assert!(fired_shutdown_chirho.load(Ordering::Acquire));

    let quiet_shutdown_chirho = Arc::new(AtomicBool::new(false));
    let quiet_chirho = PromotionExitWatchChirho {
        thread_chirho: None,
        fired_chirho: Arc::new(AtomicBool::new(false)),
        shutdown_complete_chirho: Arc::clone(&quiet_shutdown_chirho),
    };
    quiet_chirho
        .finish_chirho()
        .expect("a quiet watch finishes cleanly");
    assert!(quiet_shutdown_chirho.load(Ordering::Acquire));
}

#[test]
fn a_late_settle_gets_its_window_but_startup_grows_by_at_most_one_window_chirho() {
    let window_chirho = Duration::from_secs(14);
    let base_chirho = Instant::now() + Duration::from_secs(30);
    // Nothing settling: the bounded interval is unchanged.
    assert_eq!(
        startup_deadline_chirho(base_chirho, None, window_chirho),
        base_chirho
    );
    // A settle that completes before the deadline needs no extension.
    let early_chirho = base_chirho - Duration::from_secs(20) + window_chirho;
    assert_eq!(
        startup_deadline_chirho(base_chirho, Some(early_chirho), window_chirho),
        base_chirho
    );
    // Claude2's round 2: an owner first seen 5 s before the deadline settles 9 s after it, and
    // the deadline moves to exactly that settle.
    let late_chirho = base_chirho - Duration::from_secs(5) + window_chirho;
    assert_eq!(
        startup_deadline_chirho(base_chirho, Some(late_chirho), window_chirho),
        late_chirho
    );
    // An owner first seen exactly at the deadline can still settle inside the cap.
    let at_cap_chirho = base_chirho + window_chirho;
    assert_eq!(
        startup_deadline_chirho(base_chirho, Some(at_cap_chirho), window_chirho),
        at_cap_chirho
    );
    // An owner first seen AFTER the deadline cannot settle inside the cap, so it gets no extension
    // at all rather than a wait that cannot finish (Agy R-C1-2c).
    let very_late_chirho = base_chirho + Duration::from_secs(3) + window_chirho;
    assert_eq!(
        startup_deadline_chirho(base_chirho, Some(very_late_chirho), window_chirho),
        base_chirho
    );
}

#[test]
fn the_settle_point_follows_the_observed_owner_and_clears_on_reset_chirho() {
    let window_chirho = Duration::from_secs(14);
    let seen_chirho = Instant::now();
    let mut stability_chirho = RemoteOwnerStabilityChirho::default();
    assert_eq!(stability_chirho.settles_at_chirho(window_chirho), None);
    assert!(!stability_chirho.observe_chirho(seen_chirho, &remote_chirho(), 7, window_chirho));
    assert_eq!(
        stability_chirho.settles_at_chirho(window_chirho),
        Some(seen_chirho + window_chirho)
    );
    stability_chirho.reset_chirho();
    assert_eq!(stability_chirho.settles_at_chirho(window_chirho), None);
}

fn remote_owner_view_chirho(owner_chirho: &NodeIdChirho, term_chirho: u64) -> LeadershipChirho {
    LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: Some(owner_chirho.clone()),
        term_chirho,
        lease_valid_chirho: false,
    }
}

#[test]
fn a_late_remote_owner_settles_on_the_poll_its_window_completes_not_expires_chirho() {
    // Agy R-C1-2c, driven through the step: the owner is first seen 5 s before the base deadline,
    // so its window completes 9 s after it. Every poll in between must WAIT, and the poll at the
    // completion must SETTLE, because the step observes before it checks the deadline.
    let window_chirho = Duration::from_secs(14);
    let start_chirho = Instant::now();
    let base_chirho = start_chirho + Duration::from_secs(30);
    let mut settle_chirho = StartupSettleChirho::new_chirho(base_chirho, window_chirho);
    let ownership_chirho = GeoVoterStartupOwnershipChirho::FirstKnownOwnerChirho;
    let first_seen_chirho = base_chirho - Duration::from_secs(5);
    let view_chirho = remote_owner_view_chirho(&remote_chirho(), 9);
    for now_chirho in [
        first_seen_chirho,
        base_chirho,
        base_chirho + Duration::from_secs(1),
        first_seen_chirho + window_chirho - Duration::from_millis(1),
    ] {
        assert_eq!(
            settle_chirho.step_chirho(now_chirho, &view_chirho, &local_chirho(), ownership_chirho),
            StartupStepChirho::WaitChirho,
            "before its window completes the remote owner must wait, not expire"
        );
    }
    assert_eq!(
        settle_chirho.step_chirho(
            first_seen_chirho + window_chirho,
            &view_chirho,
            &local_chirho(),
            ownership_chirho
        ),
        StartupStepChirho::SettledChirho(GeoVoterStartupRoleChirho::NonResidentChirho(
            GeoNonResidentVoterRoleChirho::RemoteOwnerChirho
        )),
        "the poll at which the window completes must settle, not expire"
    );
}

#[test]
fn startup_settles_a_warm_local_owner_at_once_and_expires_without_any_owner_chirho() {
    let window_chirho = Duration::from_secs(14);
    let start_chirho = Instant::now();
    let base_chirho = start_chirho + Duration::from_secs(30);
    let ownership_chirho = GeoVoterStartupOwnershipChirho::FirstKnownOwnerChirho;
    let mut local_settle_chirho = StartupSettleChirho::new_chirho(base_chirho, window_chirho);
    assert_eq!(
        local_settle_chirho.step_chirho(
            start_chirho,
            &warm_local_chirho(4),
            &local_chirho(),
            ownership_chirho
        ),
        StartupStepChirho::SettledChirho(GeoVoterStartupRoleChirho::LocalWarmOwnerChirho)
    );
    let no_leader_chirho = LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: None,
        term_chirho: 4,
        lease_valid_chirho: false,
    };
    let mut empty_settle_chirho = StartupSettleChirho::new_chirho(base_chirho, window_chirho);
    assert_eq!(
        empty_settle_chirho.step_chirho(
            base_chirho - Duration::from_millis(1),
            &no_leader_chirho,
            &local_chirho(),
            ownership_chirho
        ),
        StartupStepChirho::WaitChirho
    );
    assert_eq!(
        empty_settle_chirho.step_chirho(
            base_chirho,
            &no_leader_chirho,
            &local_chirho(),
            ownership_chirho
        ),
        StartupStepChirho::ExpiredChirho
    );
}

#[test]
fn an_owner_change_after_the_deadline_expires_instead_of_waiting_in_vain_chirho() {
    let window_chirho = Duration::from_secs(14);
    let start_chirho = Instant::now();
    let base_chirho = start_chirho + Duration::from_secs(30);
    let ownership_chirho = GeoVoterStartupOwnershipChirho::FirstKnownOwnerChirho;
    let mut settle_chirho = StartupSettleChirho::new_chirho(base_chirho, window_chirho);
    assert_eq!(
        settle_chirho.step_chirho(
            base_chirho - Duration::from_secs(5),
            &remote_owner_view_chirho(&remote_chirho(), 9),
            &local_chirho(),
            ownership_chirho
        ),
        StartupStepChirho::WaitChirho
    );
    // A new owner first seen after the base deadline could not settle inside the cap.
    assert_eq!(
        settle_chirho.step_chirho(
            base_chirho + Duration::from_secs(2),
            &remote_owner_view_chirho(&NodeIdChirho("third-chirho".to_owned()), 10),
            &local_chirho(),
            ownership_chirho
        ),
        StartupStepChirho::ExpiredChirho
    );
}
