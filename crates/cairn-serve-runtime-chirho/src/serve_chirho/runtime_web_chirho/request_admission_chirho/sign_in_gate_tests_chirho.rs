// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The sign-in gate's per-source limit on its own: only confirmed successes count, the hour slides, the cap evicts
//! and never refuses, and a refusal is the one rate-limit error every sign-in refusal uses.

use super::*;
use std::net::{IpAddr, Ipv4Addr};

const HOUR_MS_CHIRHO: u64 = identity_chirho::SIGN_IN_SUCCESS_WINDOW_MS_CHIRHO;

fn gate_chirho(source_max_chirho: u64, bucket_cap_chirho: usize) -> SignInGateChirho {
    SignInGateChirho::new_chirho(&ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: source_max_chirho,
        actor_bucket_cap_chirho: bucket_cap_chirho,
        ..ServedRequestAbuseLimitsChirho::default()
    })
}

fn peer_chirho(last_octet_chirho: u8) -> Option<SocketAddr> {
    Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet_chirho)),
        443,
    ))
}

fn check_chirho(
    gate_chirho: &SignInGateChirho,
    octet_chirho: u8,
    now_chirho: u64,
) -> Result<SignInSourceChirho> {
    gate_chirho.check_source_at_chirho(
        peer_chirho(octet_chirho),
        &HeaderMap::new(),
        identity_chirho::AUTH_ENDPOINT_LOGIN_CHIRHO,
        now_chirho,
    )
}

/// A source passes until it has `max` successes in the hour; checks alone (attempts that then fail) charge nothing.
#[test]
fn only_confirmed_successes_count_and_the_limit_refuses_chirho() {
    let gate_chirho = gate_chirho(3, 64);
    for _ in 0..10 {
        check_chirho(&gate_chirho, 1, 1_000).expect("an uncharged check never fills the bucket");
    }
    for at_chirho in [1_000, 1_001, 1_002] {
        let source_chirho = check_chirho(&gate_chirho, 1, at_chirho).unwrap();
        gate_chirho.record_success_at_chirho(source_chirho, at_chirho);
    }
    let refusal_chirho = match check_chirho(&gate_chirho, 1, 1_003) {
        Ok(_) => panic!("the fourth sign-in in the hour is refused"),
        Err(refusal_chirho) => refusal_chirho,
    };
    assert!(identity_chirho::is_auth_rate_limit_error_chirho(
        &refusal_chirho
    ));
    assert_eq!(
        refusal_chirho
            .downcast_ref::<identity_chirho::AuthRateLimitExceededChirho>()
            .map(|limit_chirho| limit_chirho.reason_chirho),
        Some(identity_chirho::AuthRateLimitReasonChirho::SourceSignInsChirho)
    );
    check_chirho(&gate_chirho, 2, 1_003).expect("another source is not limited by this one");
}

/// The hour slides: the oldest success leaves the window an hour later, and frees one sign-in.
#[test]
fn the_hour_slides_chirho() {
    let gate_chirho = gate_chirho(2, 64);
    for at_chirho in [0, 10] {
        let source_chirho = check_chirho(&gate_chirho, 7, at_chirho).unwrap();
        gate_chirho.record_success_at_chirho(source_chirho, at_chirho);
    }
    assert!(check_chirho(&gate_chirho, 7, HOUR_MS_CHIRHO - 1).is_err());
    assert!(check_chirho(&gate_chirho, 7, HOUR_MS_CHIRHO + 1).is_ok());
}

/// At the bucket cap the least recently charged source is evicted; a new source is never refused for capacity.
#[test]
fn the_cap_evicts_the_oldest_and_never_refuses_a_new_source_chirho() {
    let gate_chirho = gate_chirho(5, 3);
    for octet_chirho in 1..=10u8 {
        let at_chirho = u64::from(octet_chirho);
        let source_chirho = check_chirho(&gate_chirho, octet_chirho, at_chirho)
            .expect("a new source passes whatever the bucket count");
        gate_chirho.record_success_at_chirho(source_chirho, at_chirho);
        let buckets_chirho = gate_chirho.buckets_chirho.lock().unwrap();
        assert!(buckets_chirho.len() <= 3, "the cap bounds the buckets");
    }
    let buckets_chirho = gate_chirho.buckets_chirho.lock().unwrap();
    for (octet_chirho, kept_chirho) in [(10u8, true), (9, true), (8, true), (7, false), (1, false)]
    {
        let key_chirho =
            served_network_actor_key_chirho(peer_chirho(octet_chirho), &HeaderMap::new());
        assert_eq!(
            buckets_chirho.contains_key(&key_chirho),
            kept_chirho,
            "source {octet_chirho}: the most recently charged are kept"
        );
    }
}

// ---------------------------------------------------------------- R12: the per-source failure limit

const FAILURE_WINDOW_MS_CHIRHO: u64 = identity_chirho::PUBLIC_AUTH_FAILURE_WINDOW_MS_CHIRHO;

fn failure_gate_chirho(failure_max_chirho: u64, bucket_cap_chirho: usize) -> SignInGateChirho {
    SignInGateChirho::new_chirho(&ServedRequestAbuseLimitsChirho {
        sign_in_source_failures_per_window_chirho: failure_max_chirho,
        actor_bucket_cap_chirho: bucket_cap_chirho,
        ..ServedRequestAbuseLimitsChirho::default()
    })
}

fn fail_chirho(gate_chirho: &SignInGateChirho, octet_chirho: u8, at_chirho: u64) {
    let source_chirho = check_chirho(gate_chirho, octet_chirho, at_chirho).unwrap();
    gate_chirho.record_failure_at_chirho(source_chirho, at_chirho);
}

fn refusal_reason_chirho(
    result_chirho: Result<SignInSourceChirho>,
) -> Option<identity_chirho::AuthRateLimitReasonChirho> {
    match result_chirho {
        Ok(_) => None,
        Err(error_chirho) => {
            assert!(
                identity_chirho::is_auth_rate_limit_error_chirho(&error_chirho),
                "the one rate-limit error type"
            );
            error_chirho
                .downcast_ref::<identity_chirho::AuthRateLimitExceededChirho>()
                .map(|limit_chirho| limit_chirho.reason_chirho)
        }
    }
}

/// A source passes until it has `max` RECORDED failures in the window; checks alone charge nothing, and the refusal is
/// the one rate-limit error every sign-in refusal uses, with the failure limit's own reason for the server's log.
#[test]
fn only_recorded_failures_count_and_the_limit_refuses_chirho() {
    let gate_chirho = failure_gate_chirho(3, 64);
    for _ in 0..10 {
        check_chirho(&gate_chirho, 1, 1_000).expect("an uncharged check never fills the bucket");
    }
    for at_chirho in [1_000, 1_001, 1_002] {
        fail_chirho(&gate_chirho, 1, at_chirho);
    }
    assert_eq!(
        refusal_reason_chirho(check_chirho(&gate_chirho, 1, 1_003)),
        Some(identity_chirho::AuthRateLimitReasonChirho::SourceFailuresChirho)
    );
    check_chirho(&gate_chirho, 2, 1_003).expect("another source is not limited by this one");
}

/// The failure window slides: the oldest failure leaves it fifteen minutes later, and frees one attempt.
#[test]
fn the_failure_window_slides_chirho() {
    let gate_chirho = failure_gate_chirho(2, 64);
    fail_chirho(&gate_chirho, 7, 0);
    fail_chirho(&gate_chirho, 7, 10);
    assert!(check_chirho(&gate_chirho, 7, FAILURE_WINDOW_MS_CHIRHO - 1).is_err());
    assert!(check_chirho(&gate_chirho, 7, FAILURE_WINDOW_MS_CHIRHO + 1).is_ok());
}

/// The two budgets are separate: successes never fill the failure budget, and failures never fill the success budget.
#[test]
fn successes_and_failures_are_separate_budgets_chirho() {
    let gate_chirho = SignInGateChirho::new_chirho(&ServedRequestAbuseLimitsChirho {
        sign_in_source_successes_per_hour_chirho: 2,
        sign_in_source_failures_per_window_chirho: 2,
        ..ServedRequestAbuseLimitsChirho::default()
    });
    let source_chirho = check_chirho(&gate_chirho, 3, 0).unwrap();
    gate_chirho.record_success_at_chirho(source_chirho, 0);
    fail_chirho(&gate_chirho, 3, 1);
    check_chirho(&gate_chirho, 3, 2).expect("one of each fills neither budget");
    let source_chirho = check_chirho(&gate_chirho, 3, 2).unwrap();
    gate_chirho.record_success_at_chirho(source_chirho, 2);
    assert_eq!(
        refusal_reason_chirho(check_chirho(&gate_chirho, 3, 3)),
        Some(identity_chirho::AuthRateLimitReasonChirho::SourceSignInsChirho),
        "two successes fill the success budget, not the failure one"
    );
    let other_chirho = failure_gate_chirho(2, 64);
    fail_chirho(&other_chirho, 4, 0);
    fail_chirho(&other_chirho, 4, 1);
    assert_eq!(
        refusal_reason_chirho(check_chirho(&other_chirho, 4, 2)),
        Some(identity_chirho::AuthRateLimitReasonChirho::SourceFailuresChirho)
    );
}

/// At the bucket cap the least recently charged source's failures are evicted; a new failing source is never refused
/// for capacity, and the evicted source starts over.
#[test]
fn the_failure_cap_evicts_the_oldest_and_never_refuses_chirho() {
    let gate_chirho = failure_gate_chirho(1, 2);
    fail_chirho(&gate_chirho, 1, 1);
    assert!(
        check_chirho(&gate_chirho, 1, 2).is_err(),
        "one failure fills a one-failure budget"
    );
    fail_chirho(&gate_chirho, 2, 3);
    fail_chirho(&gate_chirho, 3, 4);
    let buckets_chirho = gate_chirho.failure_buckets_chirho.lock().unwrap();
    assert!(
        buckets_chirho.len() <= 2,
        "the cap bounds the failure buckets"
    );
    drop(buckets_chirho);
    assert!(
        check_chirho(&gate_chirho, 1, 5).is_ok(),
        "the least recently charged source was evicted, so it starts over"
    );
    assert!(
        check_chirho(&gate_chirho, 3, 5).is_err(),
        "the newest source keeps its failure"
    );
}

fn bucket_len_chirho(
    buckets_chirho: &Mutex<HashMap<ServedRequestActorKeyChirho, VecDeque<u64>>>,
    key_chirho: &ServedRequestActorKeyChirho,
) -> usize {
    buckets_chirho
        .lock()
        .unwrap()
        .get(key_chirho)
        .map_or(0, VecDeque::len)
}

/// R12: an admission holds its slot until it settles, so a second attempt from the same source sees it at once; a
/// settle that earned nothing releases it.
#[test]
fn an_admission_holds_its_slot_until_it_settles_chirho() {
    let gate_chirho = failure_gate_chirho(1, 64);
    let key_chirho = check_chirho(&gate_chirho, 5, 1).unwrap().0;
    let held_chirho = gate_chirho
        .admit_at_chirho(
            key_chirho,
            "login-chirho",
            SignInChargesChirho::FailuresOnlyChirho,
            1,
        )
        .expect("the first attempt takes the only slot");
    assert_eq!(
        refusal_reason_chirho(
            gate_chirho
                .admit_at_chirho(
                    key_chirho,
                    "login-chirho",
                    SignInChargesChirho::FailuresOnlyChirho,
                    2
                )
                .map(|_| SignInSourceChirho(key_chirho))
        ),
        Some(identity_chirho::AuthRateLimitReasonChirho::SourceFailuresChirho),
        "a held slot counts before its attempt settles"
    );
    gate_chirho.settle_chirho(key_chirho, held_chirho, false, false);
    gate_chirho
        .admit_at_chirho(
            key_chirho,
            "login-chirho",
            SignInChargesChirho::FailuresOnlyChirho,
            3,
        )
        .expect("a settle that earned nothing frees the slot");
}

/// R12: settling keeps exactly the slot the outcome earned: a success its success slot, a recorded failure its failure
/// slot, anything else nothing; and recover's admission never touches the success budget.
#[test]
fn settling_keeps_exactly_the_slot_the_outcome_earned_chirho() {
    let gate_chirho = gate_chirho(5, 64);
    let both_chirho = SignInChargesChirho::SuccessesAndFailuresChirho;
    let cases_chirho = [
        (1u8, both_chirho, true, false, (1, 0)),
        (2, both_chirho, false, true, (0, 1)),
        (3, both_chirho, false, false, (0, 0)),
        (
            4,
            SignInChargesChirho::FailuresOnlyChirho,
            true,
            false,
            (0, 0),
        ),
        (
            6,
            SignInChargesChirho::FailuresOnlyChirho,
            false,
            true,
            (0, 1),
        ),
    ];
    for (octet_chirho, charges_chirho, succeeded_chirho, recorded_chirho, want_chirho) in
        cases_chirho
    {
        let key_chirho = check_chirho(&gate_chirho, octet_chirho, 10).unwrap().0;
        let admission_chirho = gate_chirho
            .admit_at_chirho(key_chirho, "login-chirho", charges_chirho, 10)
            .unwrap();
        gate_chirho.settle_chirho(
            key_chirho,
            admission_chirho,
            succeeded_chirho,
            recorded_chirho,
        );
        assert_eq!(
            (
                bucket_len_chirho(&gate_chirho.buckets_chirho, &key_chirho),
                bucket_len_chirho(&gate_chirho.failure_buckets_chirho, &key_chirho)
            ),
            want_chirho,
            "source {octet_chirho}: (successes, failures) kept"
        );
    }
}
