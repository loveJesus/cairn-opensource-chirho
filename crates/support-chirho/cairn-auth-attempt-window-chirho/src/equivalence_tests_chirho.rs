// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proves the view decides exactly as today's full scan whenever the clock is within the tolerance of the latest time
//! seen, serves a pinned, bounded count during a larger step back until its rebuild swaps in, takes the predicted path
//! and background job on every call, verifies only appended records on the request, and keeps memory bounded by the
//! keys failing recently.

use crate::test_log_chirho::{
    full_scan_count_chirho, full_scan_success_count_chirho, verified_by_chirho, RngChirho,
    TestLogChirho, FULL_EVERY_MS_CHIRHO, RULES_CHIRHO, START_MS_CHIRHO, TOLERANCE_MS_CHIRHO,
    WINDOW_MS_CHIRHO,
};
use crate::{
    join_background_job_chirho, recent_attempts_chirho, recent_failures_chirho,
    verify_current_chirho, BackgroundJobChirho, BackgroundOutcomeChirho, FallbackCauseChirho,
    PathTakenChirho, WindowDecisionChirho,
};
use std::collections::BTreeMap;

const PRINCIPALS_CHIRHO: [&str; 4] = ["p0", "p1", "p2", "p3"];
const ENDPOINTS_CHIRHO: [&str; 2] = ["login-chirho", "token-chirho"];
const MINUTE_MS_CHIRHO: u64 = 60_000;

struct ModelRecordChirho {
    principal_chirho: &'static str,
    endpoint_chirho: &'static str,
    success_chirho: bool,
    at_ms_chirho: u64,
    /// The view has dropped this failure (it was older than a call's `now - window - tolerance`).
    pruned_chirho: bool,
}

/// What the view must hold and do, built from the appends and calls alone, never from the view's internals.
#[derive(Default)]
struct ModelChirho {
    records_chirho: Vec<ModelRecordChirho>,
    file_exists_chirho: bool,
    view_chirho: bool,
    high_water_chirho: u64,
    last_full_chirho: u64,
    pending_chirho: u64,
}

impl ModelChirho {
    fn predict_chirho(&self, now_chirho: u64) -> (PathTakenChirho, Option<BackgroundJobChirho>) {
        if !self.file_exists_chirho {
            return (PathTakenChirho::MissingLogChirho, None);
        }
        if !self.view_chirho {
            let path_chirho = PathTakenChirho::FullFromFallbackChirho {
                cause_chirho: FallbackCauseChirho::FirstLoadChirho,
                verified_chirho: self.records_chirho.len() as u64,
            };
            return (path_chirho, None);
        }
        let path_chirho = if self.pending_chirho == 0 {
            PathTakenChirho::UnchangedChirho
        } else {
            PathTakenChirho::IncrementalChirho {
                folded_chirho: self.pending_chirho,
            }
        };
        let job_chirho = if now_chirho < self.high_water_chirho.saturating_sub(TOLERANCE_MS_CHIRHO)
        {
            Some(BackgroundJobChirho::IndexRebuildChirho)
        } else if now_chirho.saturating_sub(self.last_full_chirho) >= FULL_EVERY_MS_CHIRHO {
            Some(BackgroundJobChirho::IntegrityPassChirho)
        } else {
            None
        };
        (path_chirho, job_chirho)
    }

    fn prune_chirho(&mut self, now_chirho: u64) {
        let cutoff_chirho = now_chirho.saturating_sub(WINDOW_MS_CHIRHO + TOLERANCE_MS_CHIRHO);
        for record_chirho in &mut self.records_chirho {
            if !record_chirho.success_chirho && record_chirho.at_ms_chirho < cutoff_chirho {
                record_chirho.pruned_chirho = true;
            }
        }
    }

    fn fresh_view_chirho(&mut self, now_chirho: u64) {
        for record_chirho in &mut self.records_chirho {
            record_chirho.pruned_chirho = false;
        }
        self.view_chirho = true;
        self.high_water_chirho = now_chirho;
        self.last_full_chirho = now_chirho;
    }

    fn observe_chirho(&mut self, now_chirho: u64, path_chirho: PathTakenChirho) {
        match path_chirho {
            PathTakenChirho::MissingLogChirho => {
                self.view_chirho = false;
                self.pending_chirho = 0;
                return;
            }
            PathTakenChirho::FullFromFallbackChirho { .. } => self.fresh_view_chirho(now_chirho),
            PathTakenChirho::UnchangedChirho | PathTakenChirho::IncrementalChirho { .. } => {}
        }
        self.high_water_chirho = self.high_water_chirho.max(now_chirho);
        self.prune_chirho(now_chirho);
        self.pending_chirho = 0;
    }

    /// The job finished (the test joined it): apply what it changed.
    fn apply_job_chirho(&mut self, job_chirho: BackgroundJobChirho, started_chirho: u64) {
        match job_chirho {
            BackgroundJobChirho::IntegrityPassChirho => self.last_full_chirho = started_chirho,
            BackgroundJobChirho::IndexRebuildChirho => {
                self.fresh_view_chirho(started_chirho);
                self.prune_chirho(started_chirho);
            }
        }
    }

    /// Today's rule over the failures the view still holds.
    fn view_count_chirho(
        &self,
        principal_chirho: &str,
        endpoint_chirho: &str,
        now_chirho: u64,
    ) -> u64 {
        let key_chirho = |record_chirho: &&ModelRecordChirho| {
            record_chirho.principal_chirho == principal_chirho
                && record_chirho.endpoint_chirho == endpoint_chirho
        };
        let latest_success_chirho = self
            .records_chirho
            .iter()
            .enumerate()
            .filter(|(_, record_chirho)| key_chirho(record_chirho) && record_chirho.success_chirho)
            .map(|(seq_chirho, _)| seq_chirho)
            .max();
        let window_start_chirho = now_chirho.saturating_sub(WINDOW_MS_CHIRHO);
        self.records_chirho
            .iter()
            .enumerate()
            .filter(|(seq_chirho, record_chirho)| {
                key_chirho(record_chirho)
                    && !record_chirho.success_chirho
                    && !record_chirho.pruned_chirho
                    && record_chirho.at_ms_chirho >= window_start_chirho
                    && latest_success_chirho
                        .is_none_or(|success_chirho| *seq_chirho > success_chirho)
            })
            .count() as u64
    }
}

fn kind_chirho(path_chirho: PathTakenChirho) -> &'static str {
    match path_chirho {
        PathTakenChirho::MissingLogChirho => "missing",
        PathTakenChirho::UnchangedChirho => "unchanged",
        PathTakenChirho::IncrementalChirho { .. } => "incremental",
        PathTakenChirho::FullFromFallbackChirho { .. } => "first-load",
    }
}

/// Every call, on 48 seeded histories of appends (writer clocks near, far ahead of and far behind the reader's),
/// forward steps, backward steps within and beyond the tolerance, pre-checks and in-lock checks:
/// - the path and the background job equal the model's prediction, and the request verifies exactly what that path
///   reads (background jobs verify on their own handle);
/// - the count equals the model's count over what the view still holds, and equals TODAY'S FULL SCAN whenever the
///   clock is within the tolerance of the latest time seen;
/// - during a larger step back the count is never above today's, and the joined rebuild restores exactness.
#[test]
fn decisions_equal_a_full_scan_within_the_tolerance_and_every_path_is_predicted_chirho() {
    let mut kinds_chirho: BTreeMap<&str, u64> = BTreeMap::new();
    for seed_chirho in 1..=48u64 {
        let log_chirho = TestLogChirho::new_chirho(&format!("equivalence-{seed_chirho}"));
        let mut rng_chirho = RngChirho(seed_chirho.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut model_chirho = ModelChirho::default();
        let mut now_chirho = START_MS_CHIRHO;
        for step_chirho in 0..300 {
            let context_chirho = format!("seed {seed_chirho} step {step_chirho}");
            let principal_chirho = PRINCIPALS_CHIRHO[rng_chirho.below_chirho(4) as usize];
            let endpoint_chirho = ENDPOINTS_CHIRHO[rng_chirho.below_chirho(2) as usize];
            let roll_chirho = rng_chirho.below_chirho(100);
            match roll_chirho {
                0..=39 => {
                    let at_ms_chirho = match rng_chirho.below_chirho(20) {
                        0 => now_chirho + rng_chirho.below_chirho(2 * FULL_EVERY_MS_CHIRHO),
                        1 => now_chirho
                            .saturating_sub(rng_chirho.below_chirho(2 * FULL_EVERY_MS_CHIRHO)),
                        _ => (now_chirho + rng_chirho.below_chirho(4 * MINUTE_MS_CHIRHO))
                            .saturating_sub(2 * MINUTE_MS_CHIRHO),
                    };
                    let success_chirho = rng_chirho.below_chirho(5) == 0;
                    log_chirho.append_chirho(
                        model_chirho.records_chirho.len() as u64,
                        principal_chirho,
                        endpoint_chirho,
                        success_chirho,
                        at_ms_chirho,
                    );
                    model_chirho.records_chirho.push(ModelRecordChirho {
                        principal_chirho,
                        endpoint_chirho,
                        success_chirho,
                        at_ms_chirho,
                        pruned_chirho: false,
                    });
                    model_chirho.file_exists_chirho = true;
                    model_chirho.pending_chirho += 1;
                }
                40..=54 => now_chirho += 1 + rng_chirho.below_chirho(MINUTE_MS_CHIRHO),
                55..=59 => {
                    now_chirho +=
                        WINDOW_MS_CHIRHO + rng_chirho.below_chirho(2 * FULL_EVERY_MS_CHIRHO)
                }
                // Backward: within the tolerance, and beyond it.
                60..=64 => now_chirho -= 1 + rng_chirho.below_chirho(TOLERANCE_MS_CHIRHO),
                65..=67 => {
                    now_chirho -=
                        TOLERANCE_MS_CHIRHO + 1 + rng_chirho.below_chirho(3 * FULL_EVERY_MS_CHIRHO)
                }
                _ => {
                    let in_lock_chirho = roll_chirho < 76;
                    let (expected_path_chirho, expected_job_chirho) =
                        model_chirho.predict_chirho(now_chirho);
                    let before_chirho = log_chirho.verified_chirho();
                    let (status_chirho, count_chirho, successes_chirho) = if in_lock_chirho {
                        let status_chirho =
                            verify_current_chirho(&log_chirho, &RULES_CHIRHO, || now_chirho)
                                .unwrap_or_else(|error_chirho| {
                                    panic!("{context_chirho}: {error_chirho:#}")
                                });
                        (status_chirho, None, None)
                    } else {
                        let counts_chirho = recent_attempts_chirho(
                            &log_chirho,
                            &RULES_CHIRHO,
                            principal_chirho,
                            endpoint_chirho,
                            &ENDPOINTS_CHIRHO,
                            || now_chirho,
                        )
                        .unwrap_or_else(|error_chirho| {
                            panic!("{context_chirho}: {error_chirho:#}")
                        });
                        (
                            counts_chirho.status_chirho,
                            Some(counts_chirho.recent_failures_chirho),
                            Some(counts_chirho.recent_successes_chirho),
                        )
                    };
                    assert_eq!(
                        status_chirho.path_chirho, expected_path_chirho,
                        "{context_chirho}: path"
                    );
                    assert_eq!(
                        status_chirho.started_chirho, expected_job_chirho,
                        "{context_chirho}: background job"
                    );
                    assert_eq!(
                        log_chirho.verified_chirho() - before_chirho,
                        verified_by_chirho(expected_path_chirho),
                        "{context_chirho}: records verified on the request"
                    );
                    *kinds_chirho
                        .entry(kind_chirho(expected_path_chirho))
                        .or_default() += 1;
                    model_chirho.observe_chirho(now_chirho, status_chirho.path_chirho);
                    if let Some(count_chirho) = count_chirho {
                        let full_scan_chirho = full_scan_count_chirho(
                            &log_chirho,
                            principal_chirho,
                            endpoint_chirho,
                            now_chirho,
                        )
                        .unwrap();
                        assert_eq!(
                            count_chirho,
                            model_chirho.view_count_chirho(
                                principal_chirho,
                                endpoint_chirho,
                                now_chirho
                            ),
                            "{context_chirho}: count over what the view holds"
                        );
                        if expected_job_chirho == Some(BackgroundJobChirho::IndexRebuildChirho) {
                            assert!(
                                count_chirho <= full_scan_chirho,
                                "{context_chirho}: above today's count"
                            );
                            *kinds_chirho.entry("served-while-rebuilding").or_default() += 1;
                            if count_chirho < full_scan_chirho {
                                *kinds_chirho.entry("served-below-today").or_default() += 1;
                            }
                        } else {
                            assert_eq!(
                                count_chirho, full_scan_chirho,
                                "{context_chirho}: differs from today's full scan"
                            );
                        }
                    }
                    // The success count (brick 4a): exact against today's full scan unless a rebuild started,
                    // and never above it while one runs, the same rule as the failure count above.
                    if let Some(successes_chirho) = successes_chirho {
                        let full_scan_chirho = full_scan_success_count_chirho(
                            &log_chirho,
                            principal_chirho,
                            &ENDPOINTS_CHIRHO,
                            now_chirho,
                        )
                        .unwrap();
                        if expected_job_chirho == Some(BackgroundJobChirho::IndexRebuildChirho) {
                            assert!(
                                successes_chirho <= full_scan_chirho,
                                "{context_chirho}: successes above today's count"
                            );
                        } else {
                            assert_eq!(
                                successes_chirho, full_scan_chirho,
                                "{context_chirho}: successes differ from today's full scan"
                            );
                            if successes_chirho > 0 {
                                *kinds_chirho.entry("successes-compared").or_default() += 1;
                            }
                        }
                    }
                    if let Some(job_chirho) = expected_job_chirho {
                        let outcome_chirho = join_background_job_chirho(&log_chirho.path_chirho)
                            .unwrap_or_else(|| {
                                panic!("{context_chirho}: the started job was not found")
                            });
                        let verified_chirho = model_chirho.records_chirho.len() as u64;
                        let expected_outcome_chirho = match job_chirho {
                            BackgroundJobChirho::IntegrityPassChirho => {
                                *kinds_chirho.entry("integrity-pass").or_default() += 1;
                                BackgroundOutcomeChirho::IntegrityConfirmedChirho {
                                    verified_chirho,
                                }
                            }
                            BackgroundJobChirho::IndexRebuildChirho => {
                                *kinds_chirho.entry("index-rebuild").or_default() += 1;
                                BackgroundOutcomeChirho::IndexSwappedChirho { verified_chirho }
                            }
                        };
                        assert_eq!(
                            outcome_chirho, expected_outcome_chirho,
                            "{context_chirho}: job outcome"
                        );
                        model_chirho.apply_job_chirho(job_chirho, now_chirho);
                    }
                }
            }
        }
    }
    // Positive control: every path, both jobs, and a count genuinely below today's (healed by its rebuild) were
    // reached, so no branch passed vacuously.
    for kind_chirho in [
        "missing",
        "unchanged",
        "incremental",
        "first-load",
        "integrity-pass",
        "index-rebuild",
        "served-while-rebuilding",
        "served-below-today",
        "successes-compared",
    ] {
        assert!(
            kinds_chirho.get(kind_chirho).copied().unwrap_or(0) > 0,
            "the randomized history never reached {kind_chirho}: {kinds_chirho:?}"
        );
    }
}

fn decide_chirho(
    log_chirho: &TestLogChirho,
    now_chirho: u64,
    principal_chirho: &str,
    endpoint_chirho: &str,
    expected_chirho: u64,
) -> WindowDecisionChirho {
    let decision_chirho = recent_failures_chirho(
        log_chirho,
        &RULES_CHIRHO,
        principal_chirho,
        endpoint_chirho,
        || now_chirho,
    )
    .unwrap();
    assert_eq!(
        decision_chirho.recent_failures_chirho, expected_chirho,
        "view count for {principal_chirho}/{endpoint_chirho} at {now_chirho}"
    );
    decision_chirho
}

fn assert_full_scan_chirho(
    log_chirho: &TestLogChirho,
    now_chirho: u64,
    principal_chirho: &str,
    endpoint_chirho: &str,
    expected_chirho: u64,
) {
    assert_eq!(
        full_scan_count_chirho(log_chirho, principal_chirho, endpoint_chirho, now_chirho).unwrap(),
        expected_chirho,
        "fixture: today's full scan counts {expected_chirho} for {principal_chirho}/{endpoint_chirho}"
    );
}

/// The cases PFE named (#1257 C7), each with its expected count spelled out: failures before and after a success
/// for one key; two endpoints for one principal; failure times out of seq order (a writer clock slewed back by less
/// than the window); a step back within the tolerance (exact, no scan); and one beyond it (the index keeps serving,
/// a rebuild starts, and exactness returns when it swaps in).
#[test]
fn review_named_cases_decide_like_a_full_scan_chirho() {
    let log_chirho = TestLogChirho::new_chirho("named-cases");
    let t_chirho = START_MS_CHIRHO;
    let rows_chirho: [(&str, &str, bool, u64); 11] = [
        ("alice", "login-chirho", false, t_chirho),
        ("alice", "login-chirho", false, t_chirho + 1_000),
        ("alice", "login-chirho", true, t_chirho + 2_000),
        ("alice", "login-chirho", false, t_chirho + 3_000),
        ("alice", "login-chirho", false, t_chirho + 4_000),
        ("alice", "token-chirho", false, t_chirho + 5_000),
        ("alice", "token-chirho", false, t_chirho + 6_000),
        ("alice", "token-chirho", false, t_chirho + 7_000),
        ("bob", "login-chirho", false, t_chirho + 8_000),
        (
            "bob",
            "login-chirho",
            false,
            t_chirho + 8_000 - 5 * MINUTE_MS_CHIRHO,
        ),
        ("bob", "login-chirho", false, t_chirho + 9_000),
    ];
    for (seq_chirho, (principal_chirho, endpoint_chirho, success_chirho, at_ms_chirho)) in
        rows_chirho.into_iter().enumerate()
    {
        log_chirho.append_chirho(
            seq_chirho as u64,
            principal_chirho,
            endpoint_chirho,
            success_chirho,
            at_ms_chirho,
        );
    }
    let now_chirho = t_chirho + 10_000;
    // Only the two failures after alice's success count; her token failures never count for login.
    assert_full_scan_chirho(&log_chirho, now_chirho, "alice", "login-chirho", 2);
    decide_chirho(&log_chirho, now_chirho, "alice", "login-chirho", 2);
    assert_full_scan_chirho(&log_chirho, now_chirho, "alice", "token-chirho", 3);
    decide_chirho(&log_chirho, now_chirho, "alice", "token-chirho", 3);
    assert_full_scan_chirho(&log_chirho, now_chirho, "bob", "login-chirho", 3);
    decide_chirho(&log_chirho, now_chirho, "bob", "login-chirho", 3);

    // The slewed failure leaves the window first, though it is not the oldest record.
    let later_chirho = t_chirho + 8_000 - 5 * MINUTE_MS_CHIRHO + WINDOW_MS_CHIRHO + 1;
    assert_full_scan_chirho(&log_chirho, later_chirho, "bob", "login-chirho", 2);
    let decision_chirho = decide_chirho(&log_chirho, later_chirho, "bob", "login-chirho", 2);
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::UnchangedChirho
    );

    // A step back within the tolerance needs the slewed failure again: it was kept, so no scan and no job.
    let earlier_chirho = later_chirho - 2 * MINUTE_MS_CHIRHO;
    assert_full_scan_chirho(&log_chirho, earlier_chirho, "bob", "login-chirho", 3);
    let decision_chirho = decide_chirho(&log_chirho, earlier_chirho, "bob", "login-chirho", 3);
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::UnchangedChirho
    );
    assert_eq!(decision_chirho.status_chirho.started_chirho, None);
    log_chirho.append_chirho(11, "bob", "login-chirho", false, earlier_chirho + 2);
    let decision_chirho = decide_chirho(&log_chirho, earlier_chirho + 3, "bob", "login-chirho", 4);
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::IncrementalChirho { folded_chirho: 1 }
    );

    // A writer with a slow clock recorded a failure two hours "ago"; the view pruned it at once. A step back that
    // far is beyond the tolerance: the current index serves (0, below today's 1) and a rebuild starts; once it swaps
    // in, the count is today's again.
    let two_hours_ago_chirho = earlier_chirho - 2 * FULL_EVERY_MS_CHIRHO;
    log_chirho.append_chirho(12, "carol", "login-chirho", false, two_hours_ago_chirho);
    decide_chirho(&log_chirho, earlier_chirho + 4, "carol", "login-chirho", 0);
    let far_back_chirho = two_hours_ago_chirho + MINUTE_MS_CHIRHO;
    assert_full_scan_chirho(&log_chirho, far_back_chirho, "carol", "login-chirho", 1);
    let decision_chirho = decide_chirho(&log_chirho, far_back_chirho, "carol", "login-chirho", 0);
    assert_eq!(
        decision_chirho.status_chirho.started_chirho,
        Some(BackgroundJobChirho::IndexRebuildChirho)
    );
    assert_eq!(
        join_background_job_chirho(&log_chirho.path_chirho),
        Some(BackgroundOutcomeChirho::IndexSwappedChirho {
            verified_chirho: 13
        })
    );
    let decision_chirho =
        decide_chirho(&log_chirho, far_back_chirho + 1, "carol", "login-chirho", 1);
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::UnchangedChirho
    );
    assert_eq!(decision_chirho.status_chirho.started_chirho, None);
}

/// The scaling guard: after the first load of 2,000 records, each appended record costs the pre-check exactly one
/// verification, and the in-lock check right after it costs none. Bypassing the incremental path turns this red.
#[test]
fn only_appended_records_are_verified_after_the_first_load_chirho() {
    let log_chirho = TestLogChirho::new_chirho("scaling");
    let t_chirho = START_MS_CHIRHO;
    for seq_chirho in 0..2_000u64 {
        let principal_chirho = format!("p{}", seq_chirho % 50);
        log_chirho.append_chirho(
            seq_chirho,
            &principal_chirho,
            "login-chirho",
            seq_chirho % 7 == 0,
            t_chirho + seq_chirho,
        );
    }
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "p1", "login-chirho", || {
            t_chirho + 2_000
        })
        .unwrap();
    assert_eq!(
        decision_chirho.status_chirho.path_chirho,
        PathTakenChirho::FullFromFallbackChirho {
            cause_chirho: FallbackCauseChirho::FirstLoadChirho,
            verified_chirho: 2_000,
        }
    );
    assert_eq!(log_chirho.verified_chirho(), 2_000);
    for step_chirho in 0..100u64 {
        let seq_chirho = 2_000 + step_chirho;
        let now_chirho = t_chirho + 3_000 + step_chirho;
        log_chirho.append_chirho(
            seq_chirho,
            &format!("p{}", seq_chirho % 50),
            "login-chirho",
            false,
            now_chirho,
        );
        let before_chirho = log_chirho.verified_chirho();
        let decision_chirho =
            recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "p1", "login-chirho", || {
                now_chirho
            })
            .unwrap();
        assert_eq!(
            log_chirho.verified_chirho() - before_chirho,
            1,
            "attempt {seq_chirho}: the pre-check verified history again"
        );
        assert_eq!(
            decision_chirho.status_chirho.path_chirho,
            PathTakenChirho::IncrementalChirho { folded_chirho: 1 }
        );
        let before_chirho = log_chirho.verified_chirho();
        let status_chirho =
            verify_current_chirho(&log_chirho, &RULES_CHIRHO, || now_chirho).unwrap();
        assert_eq!(
            log_chirho.verified_chirho() - before_chirho,
            0,
            "attempt {seq_chirho}: the in-lock check verified records it had already seen"
        );
        assert_eq!(status_chirho.path_chirho, PathTakenChirho::UnchangedChirho);
    }
}

/// A rotating-names flood, one new name per second: the view tracks at most the keys failing inside the window plus
/// the tolerance (30 minutes), and none once that has passed them all.
#[test]
fn memory_stays_bounded_by_the_keys_failing_recently_chirho() {
    let log_chirho = TestLogChirho::new_chirho("rotating-names");
    let t_chirho = START_MS_CHIRHO;
    let mut most_tracked_chirho = 0usize;
    for seq_chirho in 0..6_000u64 {
        let now_chirho = t_chirho + seq_chirho * 1_000;
        log_chirho.append_chirho(
            seq_chirho,
            &format!("name-{seq_chirho}"),
            "login-chirho",
            false,
            now_chirho,
        );
        if seq_chirho % 50 == 49 {
            let decision_chirho = recent_failures_chirho(
                &log_chirho,
                &RULES_CHIRHO,
                "name-0",
                "login-chirho",
                || now_chirho,
            )
            .unwrap();
            most_tracked_chirho =
                most_tracked_chirho.max(decision_chirho.status_chirho.tracked_keys_chirho);
            // Joining keeps the hourly integrity passes from piling up behind the test.
            if decision_chirho.status_chirho.started_chirho.is_some() {
                join_background_job_chirho(&log_chirho.path_chirho);
            }
        }
    }
    let bound_chirho = ((WINDOW_MS_CHIRHO + TOLERANCE_MS_CHIRHO) / 1_000 + 1) as usize;
    assert!(
        most_tracked_chirho <= bound_chirho,
        "tracked {most_tracked_chirho} keys; one name per second fits at most {bound_chirho} in 30 minutes"
    );
    assert!(
        most_tracked_chirho + 60 >= bound_chirho,
        "control: the flood must fill the window and tolerance, but only {most_tracked_chirho} keys were tracked"
    );
    let after_chirho = t_chirho + 6_000_000 + WINDOW_MS_CHIRHO + TOLERANCE_MS_CHIRHO + 1;
    let decision_chirho =
        recent_failures_chirho(&log_chirho, &RULES_CHIRHO, "name-0", "login-chirho", || {
            after_chirho
        })
        .unwrap();
    assert_eq!(decision_chirho.status_chirho.tracked_keys_chirho, 0);
    if decision_chirho.status_chirho.started_chirho.is_some() {
        join_background_job_chirho(&log_chirho.path_chirho);
    }
}
