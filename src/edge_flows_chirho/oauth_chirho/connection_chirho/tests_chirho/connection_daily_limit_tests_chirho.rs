// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! K4 Part 3's daily-limit arms (PFE #26801, #26804): the connection door admits at most ten connections per principal
//! in any 24 hours, counting ended keys and keys dated after now, and decides it before the cap.
//! - The cap and the daily limit are told apart, across two apps, at the real limit.
//! - The window is closed at both ends: a key issued exactly 24 hours ago still counts, and one millisecond later it
//!   does not. At the 30-day edge an expired key leaves the population the cap and the list read.
//! - A wall clock moved back counts the keys dated after it.
//! - The last daily slot, raced between the served road and the operator road for different apps, admits one, decided
//!   inside the locked section the probe shows held.
//! - SIMULATION, named apart (PFE #26804): adversarial timings over the production boundary function never leave more
//!   than 300 unexpired keys, and an open lower bound would.

use super::super::key_listing_chirho::{
    connection_issue_instants_chirho, list_own_keys_at_chirho, live_rate_limited_keys_chirho,
    revoke_own_key_at_chirho,
};
use super::super::token_view_metrics_chirho::daily_entries_chirho;
use super::super::{
    issue_limited_key_chirho, limited_key_grants_now_chirho, public_default_rate_limit_chirho,
    revoke_own_key_chirho, scoped_key_id_chirho, ScopedTokenCapReachedChirho,
    ScopedTokenIssueChirho, LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO,
};
use super::connection_fixture_chirho::*;
use super::*;
use identity_chirho::{
    PrincipalKindChirho, SignInVelocityChirho, CONNECTION_SESSION_LIFETIME_MS_CHIRHO,
};
use std::sync::mpsc;
use std::time::Duration;

/// The session log, as the identity module names it.
const SESSIONS_CHIRHO: &str = "identity-sessions-chirho.jsonl";
/// A second opened app, for the arms that span apps.
const SECOND_APP_CHIRHO: &str = "connectedtwo";
/// The window, the limit and the lifetime, as the arms use them.
const WINDOW_CHIRHO: u64 = CONNECTION_ISSUANCE_WINDOW_MS_CHIRHO;
const LIMIT_CHIRHO: usize = CONNECTION_ISSUANCES_PER_DAY_CHIRHO;
const CAP_CHIRHO: usize = LIVE_RATE_LIMITED_TOKENS_PER_PRINCIPAL_CHIRHO;

/// A second app, opened before its client registers, and that connection client.
fn second_connection_client_chirho(world_chirho: &TokenWorldChirho) -> OauthClientRecordChirho {
    let root_chirho = &world_chirho.root_chirho;
    let owner_chirho = &world_chirho.connection_client_chirho.owner_principal_chirho;
    let view_chirho = deploy_app_chirho(root_chirho, SECOND_APP_CHIRHO, owner_chirho);
    crate::app_manifest_chirho::open_app_to_limited_keys_chirho(
        root_chirho,
        SECOND_APP_CHIRHO,
        owner_chirho,
        view_opening_chirho(&view_chirho),
    )
    .unwrap();
    let (client_chirho, store_chirho) =
        register_client_in_store_chirho(root_chirho, SECOND_APP_CHIRHO, owner_chirho).unwrap();
    assert_eq!(store_chirho, KeyStoreChirho::ConnectionChirho);
    client_chirho
}

/// A connection for the world's user through `client_chirho`, decided at `at_chirho`.
fn issue_at_chirho(
    world_chirho: &TokenWorldChirho,
    client_chirho: &OauthClientRecordChirho,
    at_chirho: u64,
) -> Result<ScopedTokenIssueChirho> {
    let grants_chirho = limited_key_grants_now_chirho(
        &world_chirho.root_chirho,
        &client_chirho.app_chirho,
        &page_read_chirho(),
    )?;
    issue_connection_key_at_chirho(
        &world_chirho.root_chirho,
        client_chirho,
        &world_chirho.user_chirho,
        SECRET_CHIRHO,
        grants_chirho,
        public_default_rate_limit_chirho(),
        move || at_chirho,
    )
}

/// End `key_chirho` at `at_chirho`, as Disconnect does.
fn end_at_chirho(
    world_chirho: &TokenWorldChirho,
    key_chirho: &ScopedTokenIssueChirho,
    at_chirho: u64,
) {
    revoke_own_key_at_chirho(
        &world_chirho.root_chirho,
        &world_chirho.user_chirho,
        &scoped_key_id_chirho(&key_chirho.record_chirho.token_hash_chirho),
        at_chirho,
    )
    .unwrap();
}

/// Ten connections at `at_chirho`, ended as they go so the cap never refuses: the day's whole allowance.
fn spend_the_day_at_chirho(world_chirho: &TokenWorldChirho, at_chirho: u64) {
    for _ in 0..LIMIT_CHIRHO {
        let key_chirho = issue_at_chirho(
            world_chirho,
            &world_chirho.connection_client_chirho,
            at_chirho,
        )
        .expect("the day has room");
        end_at_chirho(world_chirho, &key_chirho, at_chirho);
    }
}

fn is_daily_refusal_chirho(outcome_chirho: Result<ScopedTokenIssueChirho>) -> bool {
    outcome_chirho
        .unwrap_err()
        .downcast_ref::<ConnectionDailyLimitReachedChirho>()
        .is_some()
}

/// THE CAP AND THE DAY, TOLD APART, ACROSS APPS, at the real limits: with five live connections through one app, a sixth
/// through another app refuses at the cap, the day having room. Ended, they free their slots and not the day: five more
/// fit through the second app, and then, with two of those ended and three slots live, an eleventh through the first
/// app refuses at the day, the cap having room. Neither refusal appends a session or a key. Another principal has her
/// own day.
#[test]
fn the_cap_and_the_daily_limit_are_told_apart_across_apps_chirho() {
    let world_chirho = world_chirho("daily-told-apart");
    let second_chirho = second_connection_client_chirho(&world_chirho);
    let root_chirho = &world_chirho.root_chirho;
    let user_chirho = &world_chirho.user_chirho;
    let mut first_keys_chirho = Vec::new();
    for _ in 0..CAP_CHIRHO {
        first_keys_chirho.push(world_chirho.connection_key_chirho().unwrap());
    }
    let written_chirho = (
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        world_chirho.token_lines_chirho(),
    );
    let cap_refusal_chirho =
        issue_at_chirho(&world_chirho, &second_chirho, now_ms_chirho()).unwrap_err();
    assert!(
        cap_refusal_chirho
            .downcast_ref::<ScopedTokenCapReachedChirho>()
            .is_some(),
        "five live and five issued today: the cap refuses, not the day: {cap_refusal_chirho:#}"
    );
    assert_eq!(
        (
            world_chirho.lines_chirho(SESSIONS_CHIRHO),
            world_chirho.token_lines_chirho()
        ),
        written_chirho
    );

    for key_chirho in &first_keys_chirho {
        revoke_own_key_chirho(
            root_chirho,
            user_chirho,
            &scoped_key_id_chirho(&key_chirho.record_chirho.token_hash_chirho),
        )
        .unwrap();
    }
    let mut second_keys_chirho = Vec::new();
    for _ in 0..CAP_CHIRHO {
        second_keys_chirho
            .push(issue_at_chirho(&world_chirho, &second_chirho, now_ms_chirho()).unwrap());
    }
    for key_chirho in &second_keys_chirho[..2] {
        revoke_own_key_chirho(
            root_chirho,
            user_chirho,
            &scoped_key_id_chirho(&key_chirho.record_chirho.token_hash_chirho),
        )
        .unwrap();
    }
    assert_eq!(
        live_rate_limited_keys_chirho(root_chirho, user_chirho, now_ms_chirho()).unwrap(),
        3
    );
    let written_chirho = (
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        world_chirho.token_lines_chirho(),
    );
    let day_refusal_chirho = world_chirho.connection_key_chirho().unwrap_err();
    assert!(
        day_refusal_chirho
            .downcast_ref::<ConnectionDailyLimitReachedChirho>()
            .is_some(),
        "three live and ten issued today: the day refuses, not the cap: {day_refusal_chirho:#}"
    );
    assert!(format!("{day_refusal_chirho:#}").contains("ended connections count too"));
    assert_eq!(
        (
            world_chirho.lines_chirho(SESSIONS_CHIRHO),
            world_chirho.token_lines_chirho()
        ),
        written_chirho,
        "the day's refusal appends neither a session nor a key"
    );

    let other_user_chirho = identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        PrincipalKindChirho::UserChirho,
        SECRET_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    issue_limited_key_chirho(
        root_chirho,
        &other_user_chirho,
        SECRET_CHIRHO,
        &world_chirho.connection_client_chirho.client_id_chirho,
        &page_read_chirho(),
        None,
    )
    .expect("another principal's day is her own");
}

/// THE WINDOW IS CLOSED AT BOTH ENDS, AND THE 30-DAY EDGE: ten connections at t0 spend the day. Exactly 24 hours later
/// they still count, and the eleventh refuses; one millisecond later they do not, and it fits. The keys of t0 stay in
/// the population the cap and the list read through their expiry instant, and leave it one millisecond after.
#[test]
fn the_daily_window_is_closed_at_both_ends_chirho() {
    let world_chirho = world_chirho("daily-closed");
    let t0_chirho = now_ms_chirho();
    spend_the_day_at_chirho(&world_chirho, t0_chirho);
    let written_chirho = (
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        world_chirho.token_lines_chirho(),
    );
    assert!(is_daily_refusal_chirho(issue_at_chirho(
        &world_chirho,
        &world_chirho.connection_client_chirho,
        t0_chirho + WINDOW_CHIRHO
    )));
    assert_eq!(
        (
            world_chirho.lines_chirho(SESSIONS_CHIRHO),
            world_chirho.token_lines_chirho()
        ),
        written_chirho
    );
    issue_at_chirho(
        &world_chirho,
        &world_chirho.connection_client_chirho,
        t0_chirho + WINDOW_CHIRHO + 1,
    )
    .expect("one millisecond past the window, the day's keys no longer count");

    let expiry_chirho = t0_chirho + CONNECTION_SESSION_LIFETIME_MS_CHIRHO;
    let listed_at_chirho = |at_chirho: u64| {
        list_own_keys_at_chirho(
            &world_chirho.root_chirho,
            &world_chirho.user_chirho,
            at_chirho,
        )
        .unwrap()
        .iter()
        .filter(|row_chirho| row_chirho.issued_ms_chirho == t0_chirho)
        .count()
    };
    assert_eq!(
        listed_at_chirho(expiry_chirho),
        LIMIT_CHIRHO,
        "inclusive at the expiry instant"
    );
    assert_eq!(
        listed_at_chirho(expiry_chirho + 1),
        0,
        "gone one millisecond later"
    );
}

/// A CLOCK MOVED BACK COUNTS THE KEYS DATED AFTER IT: ten connections at t1 spend the day. Decided with the clock
/// moved back, ten days or one millisecond before t1, those keys are dated after now, and they still count, so the next
/// connection refuses. Past t1's window it fits. (The keys are ended at the real clock, after t1: a revocation stamped
/// before its session's issue instant does not verify, so the arm moves only the decision's clock back.)
#[test]
fn a_clock_moved_back_counts_keys_dated_after_now_chirho() {
    let world_chirho = world_chirho("daily-clock-back");
    let t1_chirho = now_ms_chirho();
    spend_the_day_at_chirho(&world_chirho, t1_chirho);
    let written_chirho = (
        world_chirho.lines_chirho(SESSIONS_CHIRHO),
        world_chirho.token_lines_chirho(),
    );
    for back_chirho in [t1_chirho - 10 * WINDOW_CHIRHO, t1_chirho - 1] {
        assert!(
            is_daily_refusal_chirho(issue_at_chirho(
                &world_chirho,
                &world_chirho.connection_client_chirho,
                back_chirho
            )),
            "keys dated after now count"
        );
    }
    assert_eq!(
        (
            world_chirho.lines_chirho(SESSIONS_CHIRHO),
            world_chirho.token_lines_chirho()
        ),
        written_chirho
    );
    issue_at_chirho(
        &world_chirho,
        &world_chirho.connection_client_chirho,
        t1_chirho + WINDOW_CHIRHO + 1,
    )
    .expect("past t1's window the day has room");
}

/// THE LAST DAILY SLOT GOES TO ONE ISSUANCE, IN BOTH ORDERS, ACROSS ROADS AND APPS: with nine of the day's connections
/// issued and four live, one issuance holds the locked section after deciding and before writing, and the probe shows
/// it holding both the credential lock and the append lock. The other, through the other road and the other app, meets
/// those locks and refuses at the day once it can count. A decision taken outside the section would admit both.
#[test]
fn a_race_for_the_last_daily_slot_admits_exactly_one_chirho() {
    for holder_is_served_chirho in [true, false] {
        let world_chirho = world_chirho(if holder_is_served_chirho {
            "daily-race-served-holds"
        } else {
            "daily-race-operator-holds"
        });
        let second_chirho = second_connection_client_chirho(&world_chirho);
        let at_chirho = now_ms_chirho();
        for index_chirho in 0..(LIMIT_CHIRHO - 1) {
            let key_chirho = issue_at_chirho(
                &world_chirho,
                &world_chirho.connection_client_chirho,
                at_chirho,
            )
            .unwrap();
            if index_chirho < LIMIT_CHIRHO - 1 - (CAP_CHIRHO - 1) {
                end_at_chirho(&world_chirho, &key_chirho, at_chirho);
            }
        }
        let root_chirho = &world_chirho.root_chirho;
        assert_eq!(
            live_rate_limited_keys_chirho(root_chirho, &world_chirho.user_chirho, at_chirho)
                .unwrap(),
            CAP_CHIRHO - 1
        );
        type IssueChirho<'world_chirho> = Box<dyn FnOnce() -> Result<()> + Send + 'world_chirho>;
        let served_chirho = |client_chirho: OauthClientRecordChirho| -> IssueChirho<'_> {
            let user_chirho = world_chirho.user_chirho.clone();
            Box::new(move || {
                match issue_connection_key_served_at_chirho(
                    root_chirho,
                    &ConnectionServedRequestChirho {
                        principal_chirho: &user_chirho,
                        credential_chirho: SECRET_CHIRHO,
                        client_id_chirho: &client_chirho.client_id_chirho,
                        actions_chirho: &page_read_chirho(),
                        return_chirho: None,
                    },
                    &SignInVelocityChirho {
                        principal_successes_per_hour_chirho: 100,
                    },
                    move || at_chirho,
                ) {
                    Ok(ConnectionServedOutcomeChirho::CreatedChirho(_)) => Ok(()),
                    Ok(other_chirho) => panic!("not created: {other_chirho:?}"),
                    Err(refusal_chirho) => Err(refusal_chirho.error_chirho),
                }
            })
        };
        let operator_chirho = |client_chirho: OauthClientRecordChirho| -> IssueChirho<'_> {
            let world_ref_chirho = &world_chirho;
            Box::new(move || {
                issue_at_chirho(world_ref_chirho, &client_chirho, at_chirho).map(|_| ())
            })
        };
        let (holder_issue_chirho, waiter_issue_chirho) = if holder_is_served_chirho {
            (
                served_chirho(world_chirho.connection_client_chirho.clone()),
                operator_chirho(second_chirho.clone()),
            )
        } else {
            (
                operator_chirho(world_chirho.connection_client_chirho.clone()),
                served_chirho(second_chirho.clone()),
            )
        };
        let (held_chirho, held_rx_chirho) = mpsc::channel::<(bool, bool)>();
        let (release_chirho, release_rx_chirho) = mpsc::channel::<()>();
        let user_for_probe_chirho = world_chirho.user_chirho.clone();
        let root_for_probe_chirho = root_chirho.clone();
        std::thread::scope(|scope_chirho| {
            let holder_chirho = scope_chirho.spawn(move || {
                set_issuance_hold_chirho(move || {
                    held_chirho
                        .send(
                            identity_chirho::connection_issue_locks_held_chirho(
                                &root_for_probe_chirho,
                                &user_for_probe_chirho,
                            )
                            .unwrap(),
                        )
                        .unwrap();
                    release_rx_chirho.recv().unwrap();
                    Ok(())
                });
                holder_issue_chirho()
            });
            let probe_chirho = held_rx_chirho
                .recv_timeout(Duration::from_secs(60))
                .unwrap();
            assert_eq!(
                probe_chirho,
                (true, true),
                "decided inside the credential and append locks"
            );
            let waiter_chirho = scope_chirho.spawn(waiter_issue_chirho);
            std::thread::sleep(Duration::from_millis(300));
            release_chirho.send(()).unwrap();
            holder_chirho
                .join()
                .unwrap()
                .expect("the holder takes the last daily slot");
            let refusal_chirho = waiter_chirho.join().unwrap().unwrap_err();
            assert!(
                refusal_chirho
                    .downcast_ref::<ConnectionDailyLimitReachedChirho>()
                    .is_some(),
                "{refusal_chirho:#}"
            );
        });
        assert_eq!(world_chirho.token_lines_chirho(), (0, LIMIT_CHIRHO));
        assert_eq!(
            live_rate_limited_keys_chirho(root_chirho, &world_chirho.user_chirho, at_chirho)
                .unwrap(),
            CAP_CHIRHO
        );
    }
}

/// THE DAILY COUNT READS THE WINDOW'S KEYS, NOT THE HISTORY, COUNTED: one principal has ten connections from forty days
/// ago, long expired, and three from now; another has only the three. The day's decision visits exactly the keys that
/// expire at or after the window's start, three for each, cold and warm: the history adds nothing.
#[test]
fn the_daily_count_reads_the_window_not_the_history_chirho() {
    let now_chirho = now_ms_chirho();
    let visited_chirho = |world_chirho: &TokenWorldChirho| {
        let before_chirho = daily_entries_chirho();
        let instants_chirho = connection_issue_instants_chirho(
            &world_chirho.root_chirho,
            &world_chirho.user_chirho,
            connection_issuance_window_start_chirho(now_chirho),
        )
        .unwrap();
        (
            instants_chirho.len(),
            daily_entries_chirho() - before_chirho,
        )
    };
    let mut seen_chirho = Vec::new();
    for (label_chirho, history_chirho) in [
        ("daily-counted-history", true),
        ("daily-counted-fresh", false),
    ] {
        let world_chirho = world_chirho(label_chirho);
        if history_chirho {
            spend_the_day_at_chirho(&world_chirho, now_chirho - 40 * WINDOW_CHIRHO);
        }
        for _ in 0..3 {
            issue_at_chirho(
                &world_chirho,
                &world_chirho.connection_client_chirho,
                now_chirho,
            )
            .unwrap();
        }
        seen_chirho.push((visited_chirho(&world_chirho), visited_chirho(&world_chirho)));
    }
    assert_eq!(
        seen_chirho,
        vec![((3, 3), (3, 3)), ((3, 3), (3, 3))],
        "cold then warm, with and without history"
    );
}

/// The simulation's model of one principal's connection keys: each key's issue instant, every key living the
/// connection's 30 days, unexpired through its expiry instant as the token view reads it.
struct ModelChirho {
    issued_chirho: Vec<u64>,
}

impl ModelChirho {
    /// Try `attempts_chirho` creations at `now_chirho`, each decided by the production function; returns how many it
    /// admitted.
    fn attempt_chirho(
        &mut self,
        now_chirho: u64,
        attempts_chirho: usize,
        admits_chirho: &dyn Fn(&[u64], u64) -> bool,
    ) -> usize {
        let mut admitted_chirho = 0;
        for _ in 0..attempts_chirho {
            if admits_chirho(&self.issued_chirho, now_chirho) {
                self.issued_chirho.push(now_chirho);
                admitted_chirho += 1;
            }
        }
        admitted_chirho
    }

    fn unexpired_at_chirho(&self, now_chirho: u64) -> usize {
        self.issued_chirho
            .iter()
            .filter(|issued_chirho| {
                **issued_chirho + CONNECTION_SESSION_LIFETIME_MS_CHIRHO >= now_chirho
            })
            .count()
    }
}

/// The production decision, as the door makes it.
fn production_admits_chirho(issued_chirho: &[u64], now_chirho: u64) -> bool {
    daily_limit_admits_chirho(issued_chirho.iter().copied(), now_chirho)
}

/// Run `schedule_chirho` (instants, each with how many creations to try) through `admits_chirho`, and return the most
/// unexpired keys seen right after any instant's creations, where that count peaks.
fn peak_unexpired_chirho(
    schedule_chirho: &[(u64, usize)],
    admits_chirho: &dyn Fn(&[u64], u64) -> bool,
) -> usize {
    let mut model_chirho = ModelChirho {
        issued_chirho: Vec::new(),
    };
    let mut peak_chirho = 0;
    for (now_chirho, attempts_chirho) in schedule_chirho {
        model_chirho.attempt_chirho(*now_chirho, *attempts_chirho, admits_chirho);
        peak_chirho = peak_chirho.max(model_chirho.unexpired_at_chirho(*now_chirho));
    }
    peak_chirho
}

/// SIMULATION, NAMED APART FROM THE REAL-ROAD ARMS ABOVE (PFE #26804): over the production boundary function itself,
/// adversarial and pseudo-random timings never leave more than 30 windows' worth, 300, of keys unexpired. The planted
/// control is PFE's counterexample: the same function with an open lower bound admits a batch every exact day and
/// reaches 310, so the checker sees a violation when there is one. A boundary mutant in `daily_limit_admits_chirho` or
/// `connection_issuance_window_start_chirho` fails this arm. A clock moved back admits nothing while the day's keys sit
/// after it.
#[test]
fn simulation_thirty_days_of_adversarial_timing_hold_at_most_three_hundred_chirho() {
    let bound_chirho = 30 * LIMIT_CHIRHO;
    let attempts_chirho = LIMIT_CHIRHO + 1;
    // Away from zero, where the window's start saturates; the zero instant has its own check below.
    let base_chirho = 100 * WINDOW_CHIRHO;
    let exact_days_chirho: Vec<(u64, usize)> = (0..=60)
        .map(|day_chirho| (base_chirho + day_chirho * WINDOW_CHIRHO, attempts_chirho))
        .collect();
    let just_past_chirho: Vec<(u64, usize)> = (0..=60)
        .map(|day_chirho| {
            (
                base_chirho + day_chirho * (WINDOW_CHIRHO + 1),
                attempts_chirho,
            )
        })
        .collect();
    let mut seed_chirho: u64 = 0x2026_1009_c0de_cafe;
    let mut at_chirho = base_chirho;
    let random_chirho: Vec<(u64, usize)> = (0..5_000)
        .map(|_| {
            seed_chirho = seed_chirho
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            at_chirho += (seed_chirho >> 33) % (2 * WINDOW_CHIRHO / 3);
            (at_chirho, 1 + (seed_chirho >> 13) as usize % 4)
        })
        .collect();
    for (name_chirho, schedule_chirho) in [
        ("every exact day", &exact_days_chirho),
        ("one millisecond past each day", &just_past_chirho),
        ("pseudo-random", &random_chirho),
    ] {
        let peak_chirho = peak_unexpired_chirho(schedule_chirho, &production_admits_chirho);
        assert!(
            peak_chirho <= bound_chirho,
            "{name_chirho}: {peak_chirho} unexpired"
        );
    }
    assert_eq!(
        peak_unexpired_chirho(&just_past_chirho, &production_admits_chirho),
        bound_chirho,
        "the bound is reached, so it is the right bound"
    );

    let open_admits_chirho = |issued_chirho: &[u64], now_chirho: u64| {
        let start_chirho = connection_issuance_window_start_chirho(now_chirho);
        issued_chirho
            .iter()
            .filter(|issued_chirho| **issued_chirho > start_chirho)
            .count()
            < LIMIT_CHIRHO
    };
    assert_eq!(
        peak_unexpired_chirho(&exact_days_chirho, &open_admits_chirho),
        bound_chirho + LIMIT_CHIRHO,
        "the planted control: an open lower bound admits 31 days of keys"
    );

    let mut zero_chirho = ModelChirho {
        issued_chirho: Vec::new(),
    };
    assert_eq!(
        zero_chirho.attempt_chirho(0, attempts_chirho, &production_admits_chirho),
        LIMIT_CHIRHO,
        "at the zero instant the saturated window still counts the keys issued at zero"
    );

    let mut model_chirho = ModelChirho {
        issued_chirho: Vec::new(),
    };
    let late_chirho = 60 * WINDOW_CHIRHO;
    assert_eq!(
        model_chirho.attempt_chirho(late_chirho, attempts_chirho, &production_admits_chirho),
        LIMIT_CHIRHO
    );
    for back_chirho in [0, 30 * WINDOW_CHIRHO, late_chirho - 1] {
        assert_eq!(
            model_chirho.attempt_chirho(back_chirho, attempts_chirho, &production_admits_chirho),
            0,
            "a clock moved back to {back_chirho} admits nothing while the day's keys sit after it"
        );
    }
}
