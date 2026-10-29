// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reserve, resolve once, conserve — and survive a recovery that retries the resolution.

use super::*;

const DEADLINE_CHIRHO: u64 = 10_000;

fn budget_chirho() -> InfrastructureBudgetChirho {
    InfrastructureBudgetChirho::new_chirho(1_000_000)
}

#[test]
fn admission_refuses_beyond_the_prepaid_ceiling_before_anything_is_provisioned_chirho() {
    // THE POINT OF RESERVING FIRST. The refusal lands while nothing has been built, so there is
    // nothing to unwind — which is the whole reason the ceiling is checked at reserve time rather
    // than at settle time.
    let mut budget_chirho = budget_chirho();
    budget_chirho
        .reserve_chirho("a-chirho", 600_000, DEADLINE_CHIRHO)
        .expect("first reservation fits");
    assert_eq!(
        budget_chirho.reserve_chirho("b-chirho", 500_000, DEADLINE_CHIRHO),
        Err(BudgetRefusalChirho::ExceedsPrepaidCeilingChirho {
            requested_micros_chirho: 500_000,
            available_micros_chirho: 400_000,
        }),
        "an outstanding reservation must reduce what a later one may claim"
    );
    assert!(budget_chirho.conservation_holds_chirho());
}

#[test]
fn settling_consumes_only_what_was_used_and_frees_the_rest_chirho() {
    let mut budget_chirho = budget_chirho();
    budget_chirho
        .reserve_chirho("a-chirho", 600_000, DEADLINE_CHIRHO)
        .unwrap();
    assert_eq!(budget_chirho.available_micros_chirho(), 400_000);
    assert_eq!(
        budget_chirho.settle_chirho("a-chirho", 250_000).unwrap(),
        BudgetOutcomeChirho::SettledChirho {
            settled_micros_chirho: 250_000
        }
    );
    // The unused 350_000 returns to the budget: reserving a MAXIMUM must not cost the maximum.
    assert_eq!(budget_chirho.available_micros_chirho(), 750_000);
    assert!(budget_chirho.conservation_holds_chirho());
}

#[test]
fn settling_more_than_was_reserved_is_refused_chirho() {
    // Spending credits nobody set aside is exactly what the ceiling exists to prevent, and it would
    // arrive through the settle path rather than the reserve path.
    let mut budget_chirho = budget_chirho();
    budget_chirho
        .reserve_chirho("a-chirho", 100_000, DEADLINE_CHIRHO)
        .unwrap();
    assert_eq!(
        budget_chirho.settle_chirho("a-chirho", 100_001),
        Err(BudgetRefusalChirho::SettlementExceedsReservationChirho {
            reserved_micros_chirho: 100_000,
            settle_micros_chirho: 100_001,
        })
    );
    assert!(budget_chirho.conservation_holds_chirho());
}

#[test]
fn a_failed_provision_releases_the_whole_reservation_chirho() {
    let mut budget_chirho = budget_chirho();
    budget_chirho
        .reserve_chirho("a-chirho", 600_000, DEADLINE_CHIRHO)
        .unwrap();
    assert_eq!(
        budget_chirho.release_chirho("a-chirho").unwrap(),
        BudgetOutcomeChirho::ReleasedChirho {
            released_micros_chirho: 600_000
        }
    );
    assert_eq!(budget_chirho.available_micros_chirho(), 1_000_000);
    assert!(budget_chirho.conservation_holds_chirho());
}

#[test]
fn restart_recovery_re_drives_the_terminal_step_without_double_spending_chirho() {
    // THE IDEMPOTENCY PROPERTY, and the reason it is not an error. A recovering node cannot know
    // whether its resolution landed, so it retries; if a retry errored, a caller would be tempted to
    // resolve differently, which is how a release becomes a second release.
    let mut budget_chirho = budget_chirho();
    budget_chirho
        .reserve_chirho("a-chirho", 400_000, DEADLINE_CHIRHO)
        .unwrap();
    let first_chirho = budget_chirho.release_chirho("a-chirho").unwrap();
    for _recovery_attempt_chirho in 0..5 {
        assert_eq!(
            budget_chirho.release_chirho("a-chirho").unwrap(),
            first_chirho,
            "every recovery retry must return the SAME outcome, not a new release"
        );
    }
    // And a settle arriving after a release must not overwrite it — the resolution is terminal
    // whichever step recovery happens to re-drive.
    assert_eq!(
        budget_chirho.settle_chirho("a-chirho", 123).unwrap(),
        first_chirho,
        "a late settle cannot convert a released reservation into a charge"
    );
    assert_eq!(budget_chirho.available_micros_chirho(), 1_000_000);
    assert!(budget_chirho.conservation_holds_chirho());
}

#[test]
fn re_reserving_the_same_id_does_not_stack_a_second_hold_chirho() {
    let mut budget_chirho = budget_chirho();
    budget_chirho
        .reserve_chirho("a-chirho", 600_000, DEADLINE_CHIRHO)
        .unwrap();
    budget_chirho
        .reserve_chirho("a-chirho", 600_000, DEADLINE_CHIRHO)
        .expect("a retrying caller re-reserving the same intent is idempotent");
    assert_eq!(
        budget_chirho.outstanding_micros_chirho(),
        600_000,
        "two calls for one intent must hold 600_000, not 1_200_000"
    );
    assert!(budget_chirho.conservation_holds_chirho());
}

#[test]
fn a_passed_deadline_releases_rather_than_settles_chirho() {
    // Unproven work is not billable. Erring the other way charges for infrastructure that may not
    // exist, which is the strictly worse mistake.
    let mut budget_chirho = budget_chirho();
    budget_chirho
        .reserve_chirho("a-chirho", 300_000, 5_000)
        .unwrap();
    budget_chirho
        .reserve_chirho("b-chirho", 200_000, 50_000)
        .unwrap();

    assert!(
        budget_chirho.release_expired_chirho(4_999).is_empty(),
        "nothing expires before its deadline"
    );
    let expired_chirho = budget_chirho.release_expired_chirho(5_000);
    assert_eq!(expired_chirho, vec!["a-chirho".to_string()]);
    assert_eq!(
        budget_chirho.outstanding_micros_chirho(),
        200_000,
        "only the expired reservation resolved"
    );
    assert_eq!(
        budget_chirho.settled_micros_chirho(),
        0,
        "a deadline must RELEASE, never settle -- unproven work is not billable"
    );

    // Safe to call repeatedly, which restart recovery does.
    assert!(budget_chirho.release_expired_chirho(9_999).is_empty());
    assert!(budget_chirho.conservation_holds_chirho());
}

#[test]
fn resolving_a_reservation_that_never_existed_is_an_error_not_a_no_op_chirho() {
    // Idempotency is about re-resolving something REAL. Silently accepting an unknown id would hide
    // a caller resolving the wrong reservation entirely.
    let mut budget_chirho = budget_chirho();
    assert_eq!(
        budget_chirho.release_chirho("ghost-chirho"),
        Err(BudgetRefusalChirho::UnknownReservationChirho {
            reservation_id_chirho: "ghost-chirho".to_string(),
        })
    );
    assert_eq!(
        budget_chirho.settle_chirho("ghost-chirho", 1),
        Err(BudgetRefusalChirho::UnknownReservationChirho {
            reservation_id_chirho: "ghost-chirho".to_string(),
        })
    );
}

#[test]
fn conservation_holds_across_a_mixed_lifecycle_chirho() {
    // The whole-system check: many reservations, every resolution path exercised, and the sum still
    // accounts for itself.
    let mut budget_chirho = InfrastructureBudgetChirho::new_chirho(1_000_000);
    budget_chirho
        .reserve_chirho("settle-chirho", 300_000, 9_000)
        .unwrap();
    budget_chirho
        .reserve_chirho("release-chirho", 200_000, 9_000)
        .unwrap();
    budget_chirho
        .reserve_chirho("expire-chirho", 100_000, 1_000)
        .unwrap();
    budget_chirho
        .reserve_chirho("open-chirho", 50_000, 90_000)
        .unwrap();

    budget_chirho
        .settle_chirho("settle-chirho", 120_000)
        .unwrap();
    budget_chirho.release_chirho("release-chirho").unwrap();
    budget_chirho.release_expired_chirho(1_000);

    assert_eq!(budget_chirho.settled_micros_chirho(), 120_000);
    assert_eq!(budget_chirho.outstanding_micros_chirho(), 50_000);
    assert_eq!(
        budget_chirho.available_micros_chirho(),
        1_000_000 - 120_000 - 50_000
    );
    assert!(budget_chirho.conservation_holds_chirho());
}

/// THE CONSERVATION PREDICATE MUST BE ABLE TO SAY NO.
///
/// Measured 2026-08-21 by mutation: replacing `conservation_holds_chirho`'s body with a bare `true`
/// left every suite in the tree GREEN. Every one of its ~17 assertions across this crate, the budget
/// event store, and the budget CLI asserts it TRUE; not one had ever shown it can return FALSE.
///
/// **That matters because it is not only a self-check.** `budget_event_store_chirho.rs:162` fails
/// closed on it — `if !budget_chirho.conservation_holds_chirho()` — and `:320` reports it onto an
/// evidence surface that a CLI arm asserts renders `"conservation_holds_chirho":true`. A predicate
/// that cannot detect a violation would pass that money gate silently AND publish a confident wrong
/// answer, which is the harder failure to see: nothing goes red, and the evidence says it is fine.
///
/// The reachable paths cannot produce these states — `settle_chirho` refuses a settlement above its
/// reservation and `release_chirho` releases the full amount. That is exactly why the fixture builds
/// the violating state DIRECTLY: the predicate's job is to catch a corrupt or mis-migrated budget,
/// and a detector is only worth having if something has shown it discriminating.
#[test]
fn the_conservation_predicate_detects_a_violation_it_did_not_create_chirho() {
    // POSITIVE CONTROL: the same direct construction, conserving, must hold — otherwise this arm
    // would pass against a predicate that simply always says no.
    let mut conserving_chirho = InfrastructureBudgetChirho::new_chirho(1_000_000);
    conserving_chirho.reservations_chirho.insert(
        "honest-chirho".to_string(),
        ReservationChirho {
            reserved_micros_chirho: 100_000,
            deadline_millis_chirho: 0,
            outcome_chirho: Some(BudgetOutcomeChirho::SettledChirho {
                settled_micros_chirho: 40_000,
            }),
        },
    );
    assert!(
        conserving_chirho.conservation_holds_chirho(),
        "a directly-built CONSERVING budget must still hold, or the arm below proves nothing"
    );

    // Settled MORE than was reserved: credits spent that nobody set aside.
    let mut overspent_chirho = InfrastructureBudgetChirho::new_chirho(1_000_000);
    overspent_chirho.reservations_chirho.insert(
        "overspent-chirho".to_string(),
        ReservationChirho {
            reserved_micros_chirho: 100_000,
            deadline_millis_chirho: 0,
            outcome_chirho: Some(BudgetOutcomeChirho::SettledChirho {
                settled_micros_chirho: 100_001,
            }),
        },
    );
    assert!(
        !overspent_chirho.conservation_holds_chirho(),
        "settling ONE micro above the reservation must break conservation — a detector that only \
         catches large violations is not a detector"
    );

    // Released an amount that is not the reservation: a partial refund is not a release.
    let mut short_release_chirho = InfrastructureBudgetChirho::new_chirho(1_000_000);
    short_release_chirho.reservations_chirho.insert(
        "short-release-chirho".to_string(),
        ReservationChirho {
            reserved_micros_chirho: 100_000,
            deadline_millis_chirho: 0,
            outcome_chirho: Some(BudgetOutcomeChirho::ReleasedChirho {
                released_micros_chirho: 99_999,
            }),
        },
    );
    assert!(
        !short_release_chirho.conservation_holds_chirho(),
        "a release must return the WHOLE reservation; a short release silently keeps the difference"
    );
}
