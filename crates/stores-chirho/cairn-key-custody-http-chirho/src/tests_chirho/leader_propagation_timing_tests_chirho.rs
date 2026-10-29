// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Erasure propagation's time boundaries (gpt #30241, #30243, #30244): time spent preparing an attempt comes off both the call budget and the lease the frame carries, nothing is signed or sent once either is spent, a slow signing is never sent, and a policy may not exceed the design's limits.

use super::propagation_world_chirho::*;
use crate::leader_chirho::propagate_chirho::{
    ErasureDeliveryErrorChirho, ErasurePropagationPolicyChirho, ErasurePropagationReportChirho,
    ErasurePropagationStopChirho, ERASURE_PROPAGATION_ATTEMPTS_PER_HOLDER_CHIRHO,
    ERASURE_PROPAGATION_CALL_BUDGET_CHIRHO, ERASURE_PROPAGATION_REQUEST_TIMEOUT_CHIRHO,
    ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO,
};
use crate::leader_chirho::refusal_chirho::LeaderRefusalIdentityChirho;
use cairn_key_custody_chirho::ErasureStatusChirho;
use cairn_writer_elector_chirho::monotonic_clock_chirho::MonotonicClockChirho;
use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

const RESERVE_MILLIS_CHIRHO: u64 = ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO.as_millis() as u64;

/// A world with a bound requirement whose leader view charges `read_cost_millis_chirho` per read and reports a lease
/// of `lease_millis_chirho`.
fn timed_world_chirho(
    read_cost_millis_chirho: u64,
    lease_millis_chirho: u64,
) -> PropagationWorldChirho {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), true);
    world_chirho.set_leader_view_chirho(
        world_chirho.leader_chirho.id_chirho(),
        Some(lease_millis_chirho),
    );
    world_chirho
        .leader_view_chirho
        .charge_reads_chirho(world_chirho.clock_chirho.clone(), read_cost_millis_chirho);
    world_chirho
}

fn one_second_budget_chirho() -> ErasurePropagationPolicyChirho {
    ErasurePropagationPolicyChirho {
        call_budget_chirho: Duration::from_secs(1),
        ..ErasurePropagationPolicyChirho::default()
    }
}

#[test]
fn once_a_backoff_spends_the_budget_authority_is_not_read_again_chirho() {
    // Reads cost 100 ms and the budget is 900 ms. The second attempt's 400 ms backoff ends exactly at the budget,
    // so the third attempt stops before it reads authority: the call ends at exactly its budget.
    let world_chirho = timed_world_chirho(100, LEASE_MILLIS_CHIRHO);
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
                call_budget_chirho: Duration::from_millis(900),
                ..ErasurePropagationPolicyChirho::default()
            },
        )
        .unwrap();
    assert_eq!(recording_chirho.holders_chirho().len(), 2);
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::BudgetSpentChirho)
    );
    assert_eq!(
        world_chirho.clock_chirho.now_millis_chirho() - started_chirho,
        900,
        "no read of authority after the budget is spent"
    );
}

/// One call under a pacing clock that is either the world's own (frozen between reads and pauses) or a ticking one,
/// with every delivery recorded at the world clock's reading as it began, and every authority read logged. It
/// returns the call's deadline on that clock, the report, the deliveries and the read times.
fn timed_call_chirho(
    read_cost_millis_chirho: u64,
    tick_millis_chirho: Option<u64>,
    budget_chirho: Duration,
) -> (
    u64,
    ErasurePropagationReportChirho,
    Vec<DeliveryChirho>,
    Vec<u64>,
) {
    let world_chirho = timed_world_chirho(read_cost_millis_chirho, LEASE_MILLIS_CHIRHO);
    let seam_chirho = world_chirho.seam_chirho();
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.before_chirho =
        Box::new(|_, _| Some(ErasureDeliveryErrorChirho::TransportChirho));
    recording_chirho.stamp_clock_chirho = Some(world_chirho.clock_chirho.clone());
    let ticking_chirho = tick_millis_chirho.map(|tick_chirho| TickingClockChirho {
        inner_chirho: world_chirho.clock_chirho.clone(),
        tick_millis_chirho: tick_chirho,
    });
    let pacing_clock_chirho: &dyn MonotonicClockChirho = match &ticking_chirho {
        Some(ticking_chirho) => ticking_chirho,
        None => world_chirho.clock_chirho.as_ref(),
    };
    // The call's own first reading starts its budget: one tick after now on a ticking clock.
    let started_chirho =
        world_chirho.clock_chirho.now_millis_chirho() + tick_millis_chirho.unwrap_or(0);
    let deadline_chirho = started_chirho + budget_chirho.as_millis() as u64;
    let report_chirho = world_chirho
        .propagate_with_clock_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho {
                call_budget_chirho: budget_chirho,
                ..ErasurePropagationPolicyChirho::default()
            },
            pacing_clock_chirho,
        )
        .unwrap();
    let deliveries_chirho = recording_chirho.deliveries_chirho.borrow().clone();
    (
        deadline_chirho,
        report_chirho,
        deliveries_chirho,
        world_chirho.leader_view_chirho.read_times_chirho(),
    )
}

#[test]
fn every_delivery_fits_inside_the_budget_and_the_lease_left_when_it_is_sent_chirho() {
    // Behavior, not a count of clock readings (gpt #30253, #30255): whatever an attempt reads, a frame starts
    // before the call's deadline, its timeout ends by that deadline, and the lease it carries is no more than what
    // remains, at the moment it is sent, of the lease seen at the last authority read before it.
    for (name_chirho, read_cost_chirho, tick_chirho, budget_chirho) in [
        (
            "frozen clock, 300 ms reads, 1 s budget",
            300,
            None,
            Duration::from_secs(1),
        ),
        (
            "frozen clock, 150 ms reads",
            150,
            None,
            Duration::from_secs(30),
        ),
        ("75 ms ticks", 0, Some(75), Duration::from_secs(30)),
        (
            "25 ms ticks and 50 ms reads",
            50,
            Some(25),
            Duration::from_secs(30),
        ),
    ] {
        let (deadline_chirho, _report_chirho, deliveries_chirho, reads_chirho) =
            timed_call_chirho(read_cost_chirho, tick_chirho, budget_chirho);
        assert!(
            !deliveries_chirho.is_empty(),
            "{name_chirho}: control, frames were sent"
        );
        for delivery_chirho in &deliveries_chirho {
            let at_chirho = delivery_chirho.at_millis_chirho.unwrap();
            assert!(
                at_chirho < deadline_chirho,
                "{name_chirho}: a frame started at the deadline"
            );
            assert!(
                delivery_chirho.timeout_chirho
                    <= Duration::from_millis(deadline_chirho - at_chirho),
                "{name_chirho}: a timeout outlasts the budget"
            );
            let last_read_chirho = reads_chirho
                .iter()
                .copied()
                .filter(|read_chirho| *read_chirho <= at_chirho)
                .max()
                .unwrap();
            let left_chirho = (last_read_chirho + LEASE_MILLIS_CHIRHO).saturating_sub(at_chirho);
            assert!(
                delivery_chirho.lease_chirho.unwrap() <= left_chirho,
                "{name_chirho}: a frame carries {} ms at {at_chirho}, but only {left_chirho} ms remain",
                delivery_chirho.lease_chirho.unwrap()
            );
        }
    }
}

#[test]
fn no_authority_read_or_delivery_starts_once_the_budget_is_spent_chirho() {
    // A 25 ms tick against budgets that run out before the authority read, before signing, at the delivery
    // boundary, or after a delivery (gpt #30255, agy #30251). Whatever the budget, no logged authority read and no
    // delivery begins at or after the deadline.
    let (mut sent_chirho, mut spent_chirho) = (0, 0);
    for budget_millis_chirho in [20, 40, 60, 70, 75, 80, 120, 300] {
        let (deadline_chirho, report_chirho, deliveries_chirho, reads_chirho) =
            timed_call_chirho(0, Some(25), Duration::from_millis(budget_millis_chirho));
        for read_chirho in &reads_chirho {
            assert!(
                *read_chirho < deadline_chirho,
                "budget {budget_millis_chirho} ms: a read at the deadline"
            );
        }
        for delivery_chirho in &deliveries_chirho {
            assert!(
                delivery_chirho.at_millis_chirho.unwrap() < deadline_chirho,
                "budget {budget_millis_chirho} ms: a delivery at the deadline"
            );
        }
        sent_chirho += deliveries_chirho.len();
        spent_chirho += usize::from(
            report_chirho.stopped_chirho == Some(ErasurePropagationStopChirho::BudgetSpentChirho),
        );
    }
    assert!(
        sent_chirho > 0 && spent_chirho > 0,
        "control: some budgets sent, some ran out"
    );
}

#[test]
fn no_frame_is_signed_once_its_own_reading_finds_the_budget_spent_chirho() {
    // A sensor in place of a signing hook (gpt #30262). With the leader's synthetic private key removed, any signing
    // fails by name as the call's error, and nothing before signing loads that key. Under a ticking clock the world
    // clock then reads exactly the moment that signing began. Across budgets that run out before the authority
    // read, before signing, or later, a call either stops before signing or begins signing before its deadline.
    let (mut signed_chirho, mut stopped_chirho) = (0, 0);
    for budget_millis_chirho in [20, 40, 60, 70, 75, 80, 120, 300] {
        let world_chirho = timed_world_chirho(0, LEASE_MILLIS_CHIRHO);
        // The signer crate's private key file (cairn-signer-chirho signer_chirho.rs:16), a test-only synthetic key.
        fs::remove_file(
            world_chirho
                .leader_root_chirho
                .join("signing-key-chirho.bin"),
        )
        .unwrap();
        let ticking_chirho = TickingClockChirho {
            inner_chirho: world_chirho.clock_chirho.clone(),
            tick_millis_chirho: 25,
        };
        let deadline_chirho =
            world_chirho.clock_chirho.now_millis_chirho() + 25 + budget_millis_chirho;
        let seam_chirho = world_chirho.seam_chirho();
        let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
        recording_chirho.before_chirho =
            Box::new(|_, _| Some(ErasureDeliveryErrorChirho::TransportChirho));
        match world_chirho.propagate_with_clock_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho {
                call_budget_chirho: Duration::from_millis(budget_millis_chirho),
                ..ErasurePropagationPolicyChirho::default()
            },
            &ticking_chirho,
        ) {
            Ok(report_chirho) => {
                assert_eq!(
                    report_chirho.stopped_chirho,
                    Some(ErasurePropagationStopChirho::BudgetSpentChirho),
                    "budget {budget_millis_chirho} ms"
                );
                stopped_chirho += 1;
            }
            Err(error_chirho) => {
                assert_eq!(
                    error_chirho.leader_identity_chirho(),
                    Some(LeaderRefusalIdentityChirho::LeaderSignerUnavailableChirho),
                    "budget {budget_millis_chirho} ms: the sensor is the only refusal"
                );
                assert!(
                    world_chirho.clock_chirho.now_millis_chirho() < deadline_chirho,
                    "budget {budget_millis_chirho} ms: signing began at or after the deadline"
                );
                signed_chirho += 1;
            }
        }
        assert!(
            recording_chirho.holders_chirho().is_empty(),
            "nothing is sent without a signature"
        );
    }
    assert!(
        signed_chirho > 0 && stopped_chirho > 0,
        "control: the sensor fired, and some budgets stopped before signing"
    );
}

#[test]
fn a_read_that_spends_the_budget_signs_and_sends_nothing_chirho() {
    // The read spends the budget AND the 500 ms lease. Only a budget check between the read and the signing names the
    // budget; without it the lease check would stop the call as lost leadership instead.
    let world_chirho = timed_world_chirho(600, 500);
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let report_chirho = world_chirho
        .propagate_chirho(0, &recording_chirho, one_second_budget_chirho())
        .unwrap();
    assert!(recording_chirho.holders_chirho().is_empty(), "nothing sent");
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::BudgetSpentChirho)
    );
}

#[test]
fn a_lease_that_runs_out_while_an_attempt_is_prepared_stops_the_call_though_the_budget_lives_chirho(
) {
    // Positive: reads of 300 ms leave a 500 ms lease 100 ms to carry once the reserve is taken off.
    let world_chirho = timed_world_chirho(300, 500);
    let seam_chirho = world_chirho.seam_chirho();
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.before_chirho =
        Box::new(|_, _| Some(ErasureDeliveryErrorChirho::RefusedChirho));
    world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    let deliveries_chirho = recording_chirho.deliveries_chirho.borrow().clone();
    assert_eq!(deliveries_chirho.len(), 3, "one frame to each holder");
    assert!(deliveries_chirho
        .iter()
        .all(|delivery_chirho| delivery_chirho.lease_chirho
            == Some(500 - 300 - RESERVE_MILLIS_CHIRHO)));

    // Negative: reads of 450 ms leave nothing after the reserve, with almost all of the call budget unspent.
    let world_chirho = timed_world_chirho(450, 500);
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    assert!(recording_chirho.holders_chirho().is_empty(), "nothing sent");
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::NotLeaderChirho)
    );
}

#[test]
fn a_frame_whose_signing_outlasts_the_reserve_is_never_sent_chirho() {
    // Positive: a clock that ticks 50 ms per reading keeps the signing interval inside the 100 ms reserve, and every
    // holder closes.
    let world_chirho = timed_world_chirho(0, LEASE_MILLIS_CHIRHO);
    let ticking_chirho = TickingClockChirho {
        inner_chirho: world_chirho.clock_chirho.clone(),
        tick_millis_chirho: RESERVE_MILLIS_CHIRHO / 2,
    };
    let seam_chirho = world_chirho.seam_chirho();
    let report_chirho = world_chirho
        .propagate_with_clock_chirho(
            0,
            &seam_chirho,
            ErasurePropagationPolicyChirho::default(),
            &ticking_chirho,
        )
        .unwrap();
    assert_eq!(report_chirho.stopped_chirho, None);
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    );

    // Negative: a tick longer than the reserve makes every signing outlast it, so no frame is sent.
    let world_chirho = timed_world_chirho(0, LEASE_MILLIS_CHIRHO);
    let ticking_chirho = TickingClockChirho {
        inner_chirho: world_chirho.clock_chirho.clone(),
        tick_millis_chirho: RESERVE_MILLIS_CHIRHO + 50,
    };
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let report_chirho = world_chirho
        .propagate_with_clock_chirho(
            0,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
            &ticking_chirho,
        )
        .unwrap();
    assert!(recording_chirho.holders_chirho().is_empty(), "nothing sent");
    assert_eq!(
        report_chirho.stopped_chirho,
        Some(ErasurePropagationStopChirho::SigningOverranChirho)
    );
}

#[test]
fn a_policy_outside_the_design_limits_refuses_before_authority_is_read_chirho() {
    let default_chirho = ErasurePropagationPolicyChirho::default();
    let one_millisecond_chirho = Duration::from_millis(1);
    for (name_chirho, policy_chirho) in [
        (
            "no attempt",
            ErasurePropagationPolicyChirho {
                attempts_per_holder_chirho: 0,
                ..default_chirho
            },
        ),
        (
            "one attempt too many",
            ErasurePropagationPolicyChirho {
                attempts_per_holder_chirho: ERASURE_PROPAGATION_ATTEMPTS_PER_HOLDER_CHIRHO + 1,
                ..default_chirho
            },
        ),
        (
            "no request time",
            ErasurePropagationPolicyChirho {
                request_timeout_chirho: Duration::ZERO,
                ..default_chirho
            },
        ),
        (
            "a longer request timeout",
            ErasurePropagationPolicyChirho {
                request_timeout_chirho: ERASURE_PROPAGATION_REQUEST_TIMEOUT_CHIRHO
                    + one_millisecond_chirho,
                ..default_chirho
            },
        ),
        (
            "no budget",
            ErasurePropagationPolicyChirho {
                call_budget_chirho: Duration::ZERO,
                ..default_chirho
            },
        ),
        (
            "a longer call budget",
            ErasurePropagationPolicyChirho {
                call_budget_chirho: ERASURE_PROPAGATION_CALL_BUDGET_CHIRHO + one_millisecond_chirho,
                ..default_chirho
            },
        ),
        (
            "a smaller signing reserve",
            ErasurePropagationPolicyChirho {
                signing_reserve_chirho: ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO
                    - one_millisecond_chirho,
                ..default_chirho
            },
        ),
    ] {
        // Each read of authority would cost a millisecond, so a refusal after any read would move the clock.
        let world_chirho = timed_world_chirho(1, LEASE_MILLIS_CHIRHO);
        let before_chirho = world_chirho.clock_chirho.now_millis_chirho();
        let seam_chirho = world_chirho.seam_chirho();
        let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
        // The case is named in every failure, including an accepted policy, so a kill names the case it came from.
        let refused_chirho =
            match world_chirho.propagate_chirho(0, &recording_chirho, policy_chirho) {
                Ok(_) => panic!("{name_chirho}: the policy was accepted"),
                Err(error_chirho) => error_chirho.leader_identity_chirho(),
            };
        assert_eq!(
            refused_chirho,
            Some(LeaderRefusalIdentityChirho::ErasurePropagationPolicyOutOfLimitsChirho),
            "{name_chirho}"
        );
        assert_eq!(
            world_chirho.clock_chirho.now_millis_chirho(),
            before_chirho,
            "{name_chirho}: refused before authority was read"
        );
        assert!(
            recording_chirho.holders_chirho().is_empty(),
            "{name_chirho}: nothing sent"
        );
    }
    // Lowering the limits, and raising the reserve, is allowed.
    let world_chirho = timed_world_chirho(0, LEASE_MILLIS_CHIRHO);
    let seam_chirho = world_chirho.seam_chirho();
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &seam_chirho,
            ErasurePropagationPolicyChirho {
                attempts_per_holder_chirho: 1,
                first_backoff_chirho: Duration::from_millis(50),
                request_timeout_chirho: Duration::from_secs(1),
                call_budget_chirho: Duration::from_secs(10),
                signing_reserve_chirho: ERASURE_PROPAGATION_SIGNING_RESERVE_CHIRHO * 2,
            },
        )
        .unwrap();
    assert_eq!(
        *report_chirho.attempt_chirho.status_chirho(),
        ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho
    );
}
