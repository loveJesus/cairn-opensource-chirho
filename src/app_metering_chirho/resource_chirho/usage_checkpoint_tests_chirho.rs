// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! F3 usage-checkpoint tests for resource_chirho: oracle equivalence, clock-regression guard, scaling-guard counters, and sidecar-loss rebuild (split out to keep tests_chirho under the line cap).

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-resource-test-{nanos_chirho}-{n_chirho}"))
}

fn deploy_owned_app_chirho(root_chirho: &Path, app_chirho: &str) -> String {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = crate::cas_chirho::add_chirho(root_chirho, b"node marker").unwrap();
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &crate::model_chirho::DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, dag_chirho, &owner_chirho).unwrap();
    owner_chirho
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

/// Deterministic xorshift so the oracle sweep is seeded and CI-stable (no `rand` dependency).
struct OracleRngChirho {
    state_chirho: u64,
}

impl OracleRngChirho {
    fn new_chirho(seed_chirho: u64) -> Self {
        OracleRngChirho {
            state_chirho: seed_chirho | 1,
        }
    }

    fn next_u64_chirho(&mut self) -> u64 {
        let mut x_chirho = self.state_chirho;
        x_chirho ^= x_chirho << 13;
        x_chirho ^= x_chirho >> 7;
        x_chirho ^= x_chirho << 17;
        self.state_chirho = x_chirho;
        x_chirho
    }

    fn below_chirho(&mut self, bound_chirho: u64) -> u64 {
        self.next_u64_chirho() % bound_chirho
    }
}

fn oracle_policy_chirho() -> AppResourcePolicyChirho {
    AppResourcePolicyChirho {
        app_chirho: "oracleapp".to_string(),
        owner_principal_chirho: "owner/test".to_string(),
        meters_chirho: vec![
            // Windowed, both per-user and app limits: exercises the sliding-window sum and pruning.
            ResourceMeterChirho {
                resource_chirho: "res_windowed_chirho".to_string(),
                unit_chirho: "u".to_string(),
                stack_chirho: None,
                per_user_limit_chirho: Some(3),
                app_limit_chirho: Some(10),
                window_ms_chirho: Some(80),
                overage_chirho: ResourceOverageChirho::RouteChirho {
                    route_chirho: "over".to_string(),
                    forward_request_body_chirho: false,
                },
            },
            // Windowless per-user only: exercises the scalar lifetime total with no app-wide bucket.
            ResourceMeterChirho {
                resource_chirho: "res_lifetime_chirho".to_string(),
                unit_chirho: "u".to_string(),
                stack_chirho: None,
                per_user_limit_chirho: Some(4),
                app_limit_chirho: None,
                window_ms_chirho: None,
                overage_chirho: ResourceOverageChirho::FailClosedChirho,
            },
            // Windowed app-only: exercises the app-wide sentinel row with no per-user bucket.
            ResourceMeterChirho {
                resource_chirho: "res_appwide_chirho".to_string(),
                unit_chirho: "u".to_string(),
                stack_chirho: None,
                per_user_limit_chirho: None,
                app_limit_chirho: Some(5),
                window_ms_chirho: Some(60),
                overage_chirho: ResourceOverageChirho::RouteChirho {
                    route_chirho: "over2".to_string(),
                    forward_request_body_chirho: true,
                },
            },
        ],
        actions_chirho: vec![ResourceActionPolicyChirho {
            section_chirho: "sec".to_string(),
            action_chirho: "act".to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![
                ResourceChargeChirho {
                    resource_chirho: "res_windowed_chirho".to_string(),
                    amount_chirho: 1,
                },
                ResourceChargeChirho {
                    resource_chirho: "res_lifetime_chirho".to_string(),
                    amount_chirho: 1,
                },
                ResourceChargeChirho {
                    resource_chirho: "res_appwide_chirho".to_string(),
                    amount_chirho: 1,
                },
            ],
        }],
        previous_chirho: None,
        at_ms_chirho: 0,
    }
}

fn oracle_usage_row_chirho(
    seq_chirho: u64,
    user_chirho: &str,
    policy_hash_chirho: &HashChirho,
    charges_chirho: &[ResourceChargeChirho],
    decision_chirho: ResourceDecisionChirho,
    at_ms_chirho: u64,
) -> ResourceUsageRecordChirho {
    ResourceUsageRecordChirho {
        seq_chirho,
        schema_chirho: RESOURCE_USAGE_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "oracleapp".to_string(),
        user_chirho: user_chirho.to_string(),
        actor_chirho: user_chirho.to_string(),
        section_chirho: "sec".to_string(),
        action_chirho: "act".to_string(),
        effect_chirho: None,
        run_chirho: None,
        resource_policy_chirho: policy_hash_chirho.clone(),
        charges_chirho: charges_chirho.to_vec(),
        bridges_chirho: Vec::new(),
        decision_chirho,
        at_ms_chirho,
        sig_chirho: String::new(),
    }
}

/// F3 EQUIVALENCE LAW: the checkpoint decision must equal the full-scan decision on every step of a
/// randomized append/decide sequence that crosses window boundaries. This drives the pure aggregate
/// against `decide_resource_usage_chirho` over the growing real prior — decision-for-decision, users
/// interleaving, timestamps advancing past the sliding windows so windowed rows age out — with a
/// mix of windowed/windowless and per-user/app-only meters.
#[test]
fn usage_checkpoint_oracle_matches_full_scan_chirho() {
    let policy_chirho = oracle_policy_chirho();
    let policy_hash_chirho = HashChirho("a".repeat(64));
    let users_chirho = ["user/a", "user/b", "user/c"];
    // Decoupled charge sets so different requests exercise different meters independently: a windowed
    // route, a windowless fail-closed, an app-wide route, and a combined multi-meter charge all
    // appear and must each match the full scan.
    let charge_chirho = |resource_chirho: &str, amount_chirho: i64| ResourceChargeChirho {
        resource_chirho: resource_chirho.to_string(),
        amount_chirho,
    };
    let charge_sets_chirho: Vec<Vec<ResourceChargeChirho>> = vec![
        vec![charge_chirho("res_windowed_chirho", 2)],
        vec![charge_chirho("res_lifetime_chirho", 2)],
        vec![charge_chirho("res_appwide_chirho", 2)],
        vec![
            charge_chirho("res_windowed_chirho", 1),
            charge_chirho("res_lifetime_chirho", 1),
            charge_chirho("res_appwide_chirho", 1),
        ],
    ];

    let mut rng_chirho = OracleRngChirho::new_chirho(0x5eed_1234_abcd_0001);
    let mut prior_chirho: Vec<ResourceUsageRecordChirho> = Vec::new();
    let mut aggregate_chirho = usage_checkpoint_chirho::UsageAggregateChirho::empty_chirho(
        &policy_hash_chirho,
        "oracleapp",
    );
    let mut at_ms_chirho: u64 = 1_000;
    let mut allowed_chirho = 0u64;
    let mut routed_chirho = 0u64;
    let mut fail_closed_chirho = 0u64;

    for step_chirho in 0..600u64 {
        // Non-decreasing time (the realistic wall clock), sometimes jumping a whole window so rows age
        // out and both per-user and app-wide windowed usage must recover.
        at_ms_chirho += rng_chirho.below_chirho(18);
        if rng_chirho.below_chirho(6) == 0 {
            at_ms_chirho += 30 + rng_chirho.below_chirho(60);
        }
        let user_chirho = users_chirho[rng_chirho.below_chirho(users_chirho.len() as u64) as usize];
        let charges_chirho = charge_sets_chirho
            [rng_chirho.below_chirho(charge_sets_chirho.len() as u64) as usize]
            .clone();

        let old_chirho = resource_policy_chirho::decide_resource_usage_chirho(
            &policy_chirho,
            &policy_hash_chirho,
            &prior_chirho,
            "oracleapp",
            user_chirho,
            &charges_chirho,
            at_ms_chirho,
        );
        let new_chirho = usage_checkpoint_chirho::decide_from_aggregate_chirho(
            &aggregate_chirho,
            &policy_chirho,
            &policy_hash_chirho,
            "oracleapp",
            user_chirho,
            &charges_chirho,
            at_ms_chirho,
        );

        match (&old_chirho, &new_chirho) {
            (Ok(old_decision_chirho), Ok(new_decision_chirho)) => {
                assert_eq!(
                    old_decision_chirho, new_decision_chirho,
                    "checkpoint decision diverged at step {step_chirho} (user {user_chirho}, t={at_ms_chirho})"
                );
            }
            (Err(old_error_chirho), Err(new_error_chirho)) => {
                assert_eq!(
                    old_error_chirho.to_string(),
                    new_error_chirho.to_string(),
                    "checkpoint fail-closed message diverged at step {step_chirho}"
                );
            }
            (old_result_chirho, new_result_chirho) => {
                panic!("checkpoint Ok/Err diverged at step {step_chirho}: full-scan {old_result_chirho:?} vs checkpoint {new_result_chirho:?}");
            }
        }

        // Only a produced record (Allowed or Routed) is appended in the real flow; a fail-closed
        // overage bails before the append, so it advances neither the prior nor the aggregate.
        match old_chirho {
            Ok(decision_chirho @ ResourceDecisionChirho::AllowedChirho) => {
                allowed_chirho += 1;
                let record_chirho = oracle_usage_row_chirho(
                    prior_chirho.len() as u64,
                    user_chirho,
                    &policy_hash_chirho,
                    &charges_chirho,
                    decision_chirho,
                    at_ms_chirho,
                );
                usage_checkpoint_chirho::fold_record_chirho(
                    &mut aggregate_chirho,
                    &record_chirho,
                    &policy_chirho,
                );
                prior_chirho.push(record_chirho);
            }
            Ok(decision_chirho) => {
                routed_chirho += 1;
                let record_chirho = oracle_usage_row_chirho(
                    prior_chirho.len() as u64,
                    user_chirho,
                    &policy_hash_chirho,
                    &charges_chirho,
                    decision_chirho,
                    at_ms_chirho,
                );
                usage_checkpoint_chirho::fold_record_chirho(
                    &mut aggregate_chirho,
                    &record_chirho,
                    &policy_chirho,
                );
                prior_chirho.push(record_chirho);
            }
            Err(_) => fail_closed_chirho += 1,
        }
    }

    // The sweep must actually exercise every decision branch under both paths, not trivially Allow or
    // deny everything: allow, windowed routing, and windowless fail-closed all appeared and matched.
    assert!(
        allowed_chirho > 0 && routed_chirho > 0 && fail_closed_chirho > 0,
        "oracle sweep did not exercise all decision branches: allowed={allowed_chirho}, routed={routed_chirho}, fail_closed={fail_closed_chirho}"
    );
}

/// F3 CLOCK-REGRESSION LAW: after the wall clock steps forward past a window and then regresses, the
/// windowed aggregate has pruned a prior row that is still in-window for the regressed decision, so
/// deciding from the aggregate would UNDER-count `used` and fail OPEN. The regression guard must instead
/// decide from the row-preserving full scan and match it exactly. `at_ms` is driven explicitly (no
/// wall-clock sleeps), like the oracle test.
#[test]
fn usage_checkpoint_regression_decides_from_full_scan_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let policy_chirho = oracle_policy_chirho();
    let policy_hash_chirho = HashChirho("b".repeat(64));
    let user_chirho = "user/a";
    // res_windowed_chirho: per-user limit 3, window 80ms, Route on overage.
    let window_ms_chirho: u64 = 80;
    let t0_chirho: u64 = 1_000;
    let windowed_charge_chirho = |amount_chirho: i64| {
        vec![ResourceChargeChirho {
            resource_chirho: "res_windowed_chirho".to_string(),
            amount_chirho,
        }]
    };

    // A prior at t0 that fills the per-user window to the limit, then one at t0 + 2*window whose fold
    // prunes the t0 row out of the aggregate (age 2*window >= window).
    let row_t0_chirho = oracle_usage_row_chirho(
        0,
        user_chirho,
        &policy_hash_chirho,
        &windowed_charge_chirho(3),
        ResourceDecisionChirho::AllowedChirho,
        t0_chirho,
    );
    let row_late_chirho = oracle_usage_row_chirho(
        1,
        user_chirho,
        &policy_hash_chirho,
        &windowed_charge_chirho(1),
        ResourceDecisionChirho::AllowedChirho,
        t0_chirho + 2 * window_ms_chirho,
    );
    // The full scan reads these rows from disk; nothing is ever deleted there.
    write_jsonl_chirho(
        &usage_records_path_chirho(&root_chirho),
        &[row_t0_chirho.clone(), row_late_chirho.clone()],
    );

    let mut aggregate_chirho = usage_checkpoint_chirho::UsageAggregateChirho::empty_chirho(
        &policy_hash_chirho,
        "oracleapp",
    );
    usage_checkpoint_chirho::fold_record_chirho(
        &mut aggregate_chirho,
        &row_t0_chirho,
        &policy_chirho,
    );
    usage_checkpoint_chirho::fold_record_chirho(
        &mut aggregate_chirho,
        &row_late_chirho,
        &policy_chirho,
    );
    assert_eq!(
        aggregate_chirho.max_folded_at_ms_chirho(),
        t0_chirho + 2 * window_ms_chirho,
        "the high-water mark must track the latest folded row"
    );

    // The clock regresses to t0 (below the high-water mark) for a fresh same-resource charge.
    let new_charge_chirho = windowed_charge_chirho(1);

    // Authority: the full scan still sees the t0 row in-window (used=3), so 3+1 > limit 3 -> Routed.
    let full_scan_chirho = resource_policy_chirho::decide_resource_usage_chirho(
        &policy_chirho,
        &policy_hash_chirho,
        &[row_t0_chirho.clone(), row_late_chirho.clone()],
        "oracleapp",
        user_chirho,
        &new_charge_chirho,
        t0_chirho,
    )
    .unwrap();
    assert!(
        matches!(
            full_scan_chirho,
            ResourceDecisionChirho::RoutedChirho { .. }
        ),
        "full scan must route the over-limit charge, got {full_scan_chirho:?}"
    );

    // Pre-fix behavior: the t0 row was pruned, so the bare aggregate under-counts (used=0) -> Allowed.
    // This is the exact fail-OPEN the guard must not reproduce.
    let aggregate_only_chirho = usage_checkpoint_chirho::decide_from_aggregate_chirho(
        &aggregate_chirho,
        &policy_chirho,
        &policy_hash_chirho,
        "oracleapp",
        user_chirho,
        &new_charge_chirho,
        t0_chirho,
    )
    .unwrap();
    assert_eq!(
        aggregate_only_chirho,
        ResourceDecisionChirho::AllowedChirho,
        "sanity: the un-guarded aggregate under-counts and would fail OPEN here"
    );
    assert_ne!(
        aggregate_only_chirho, full_scan_chirho,
        "the hazard must actually diverge, or this test proves nothing"
    );

    // The fix: the guard detects the regression and returns the full-scan decision, exactly.
    let guarded_chirho = usage_checkpoint_chirho::decide_with_regression_guard_chirho(
        &root_chirho,
        &aggregate_chirho,
        &policy_chirho,
        &policy_hash_chirho,
        "oracleapp",
        user_chirho,
        &new_charge_chirho,
        t0_chirho,
    )
    .unwrap();
    assert_eq!(
        guarded_chirho, full_scan_chirho,
        "the regression guard must decide exactly as the full scan"
    );

    // With no regression (`at_ms` at/above the high-water mark) the guard delegates to the aggregate
    // unchanged, so the warm O(window) path is preserved.
    let warm_at_ms_chirho = t0_chirho + 2 * window_ms_chirho + 5;
    let guarded_warm_chirho = usage_checkpoint_chirho::decide_with_regression_guard_chirho(
        &root_chirho,
        &aggregate_chirho,
        &policy_chirho,
        &policy_hash_chirho,
        "oracleapp",
        user_chirho,
        &new_charge_chirho,
        warm_at_ms_chirho,
    )
    .unwrap();
    let aggregate_warm_chirho = usage_checkpoint_chirho::decide_from_aggregate_chirho(
        &aggregate_chirho,
        &policy_chirho,
        &policy_hash_chirho,
        "oracleapp",
        user_chirho,
        &new_charge_chirho,
        warm_at_ms_chirho,
    )
    .unwrap();
    assert_eq!(
        guarded_warm_chirho, aggregate_warm_chirho,
        "with no regression the guard must not change the warm aggregate decision"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn scaling_guard_policy_chirho() -> (Vec<ResourceMeterChirho>, Vec<ResourceActionPolicyChirho>) {
    (
        vec![ResourceMeterChirho {
            resource_chirho: "scaling_credit_chirho".to_string(),
            unit_chirho: "u".to_string(),
            stack_chirho: None,
            // High limits so every seeded request is Allowed and the log actually grows.
            per_user_limit_chirho: Some(100_000_000),
            app_limit_chirho: Some(100_000_000),
            window_ms_chirho: None,
            overage_chirho: ResourceOverageChirho::FailClosedChirho,
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: "sec".to_string(),
            action_chirho: "act".to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "scaling_credit_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
}

fn scaling_usage_input_chirho() -> ResourceUsageInputChirho {
    ResourceUsageInputChirho {
        app_chirho: "scalingapp".to_string(),
        user_chirho: "user/scale".to_string(),
        actor_chirho: None,
        section_chirho: "sec".to_string(),
        action_chirho: "act".to_string(),
        effect_chirho: None,
        run_chirho: None,
        bridges_chirho: Vec::new(),
    }
}

/// Returns `(whole_usage_file_reads, usage_rows_scanned, tail_bytes_read)` for one warm gated append
/// over a history of `seed_count_chirho` prior appends.
fn warm_append_full_load_count_chirho(
    root_chirho: &Path,
    seed_count_chirho: usize,
) -> (u64, u64, u64) {
    for _ in 0..seed_count_chirho {
        let record_chirho = record_resource_usage_chirho(root_chirho, scaling_usage_input_chirho())
            .expect("seeded usage append should be allowed under the high limits");
        assert_eq!(
            record_chirho.decision_chirho,
            ResourceDecisionChirho::AllowedChirho
        );
    }
    reset_usage_load_counts_chirho();
    let measured_chirho = record_resource_usage_chirho(root_chirho, scaling_usage_input_chirho())
        .expect("measured warm usage append should be allowed");
    assert_eq!(
        measured_chirho.decision_chirho,
        ResourceDecisionChirho::AllowedChirho
    );
    (
        usage_full_load_count_chirho(),
        usage_rows_loaded_count_chirho(),
        usage_tail_bytes_read_count_chirho(),
    )
}

/// F3 SCALING GUARD (count-based, never wall-clock): a warm gated append must do ZERO whole-usage-log
/// reads regardless of how much history precedes it, and its one bounded tail read must stay a per-op
/// constant. The pre-checkpoint path loaded the whole `resource-usage-chirho.jsonl` on every request
/// (Θ(N²) over request count). The counter now spans BOTH whole-file readers of the usage log — the
/// typed `load_resource_usage_chirho` AND the physical-line `resource_usage_lines_chirho` reader that
/// the Gate-1 envelope's tail lookups used to funnel through — so the earlier Layer-3 `jsonl_lines`
/// last-line reads are no longer an uncounted blind spot: they were replaced by a bounded backward-seek
/// tail read (:250) and an in-hand re-serialization (:99), and this guard proves both are gone.
#[test]
fn usage_append_full_load_is_independent_of_history_chirho() {
    let small_root_chirho = tmp_root_chirho();
    let small_owner_chirho = deploy_owned_app_chirho(&small_root_chirho, "scalingapp");
    let (meters_chirho, actions_chirho) = scaling_guard_policy_chirho();
    set_resource_policy_chirho(
        &small_root_chirho,
        "scalingapp",
        &small_owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap();
    let (small_full_loads_chirho, small_rows_chirho, small_tail_bytes_chirho) =
        warm_append_full_load_count_chirho(&small_root_chirho, 16);

    let large_root_chirho = tmp_root_chirho();
    let large_owner_chirho = deploy_owned_app_chirho(&large_root_chirho, "scalingapp");
    let (meters_chirho, actions_chirho) = scaling_guard_policy_chirho();
    set_resource_policy_chirho(
        &large_root_chirho,
        "scalingapp",
        &large_owner_chirho,
        meters_chirho,
        actions_chirho,
    )
    .unwrap();
    let (large_full_loads_chirho, large_rows_chirho, large_tail_bytes_chirho) =
        warm_append_full_load_count_chirho(&large_root_chirho, 256);

    assert_eq!(
        small_full_loads_chirho, 0,
        "warm append over a short history still did a full usage-log read"
    );
    assert_eq!(
        large_full_loads_chirho, 0,
        "warm append over a long history did a full usage-log read: per-request work scales with history"
    );
    assert_eq!(
        small_rows_chirho, 0,
        "warm append over a short history scanned usage rows"
    );
    assert_eq!(
        large_rows_chirho, 0,
        "warm append over a long history scanned usage rows: per-request work scales with history"
    );

    // The warm append's only usage-log read is the bounded backward-seek tail read: prove it is a
    // partial read AND a per-op constant (at most one chunk), so per-append cost never scales with
    // history, and that it ran on both histories (the fast reader, not the full-scan fallback).
    let tail_cap_chirho = gate1_authority_chirho::USAGE_TAIL_SCAN_CHUNK_BYTES_CHIRHO as u64 + 1;
    let large_usage_len_chirho = std::fs::metadata(usage_records_path_chirho(&large_root_chirho))
        .unwrap()
        .len();
    assert!(
        large_tail_bytes_chirho > 0
            && large_tail_bytes_chirho <= tail_cap_chirho
            && large_tail_bytes_chirho < large_usage_len_chirho,
        "warm append tail read must touch at most one bounded chunk, not the whole usage log (read {large_tail_bytes_chirho} bytes of a {large_usage_len_chirho}-byte log)"
    );
    assert!(
        small_tail_bytes_chirho > 0 && small_tail_bytes_chirho <= tail_cap_chirho,
        "warm append over a short history must serve the family tail from one bounded tail read (read {small_tail_bytes_chirho} bytes)"
    );

    let _ = std::fs::remove_dir_all(&small_root_chirho);
    let _ = std::fs::remove_dir_all(&large_root_chirho);
}

/// F3 self-heal law: a lost checkpoint sidecar must rebuild once from the full scan and still decide
/// exactly as the full scan would, then return to O(1). A windowless per-user Route meter makes the
/// post-limit decision deterministic, so the rebuilt aggregate is proven correct (Routed), not merely
/// present.
#[test]
fn usage_checkpoint_rebuilds_after_sidecar_loss_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "rebuildapp");
    set_resource_policy_chirho(
        &root_chirho,
        "rebuildapp",
        &owner_chirho,
        vec![ResourceMeterChirho {
            resource_chirho: "credit_chirho".to_string(),
            unit_chirho: "u".to_string(),
            stack_chirho: None,
            per_user_limit_chirho: Some(2),
            app_limit_chirho: Some(1_000),
            window_ms_chirho: None,
            overage_chirho: ResourceOverageChirho::RouteChirho {
                route_chirho: "over".to_string(),
                forward_request_body_chirho: false,
            },
        }],
        vec![ResourceActionPolicyChirho {
            section_chirho: "sec".to_string(),
            action_chirho: "act".to_string(),
            effect_chirho: None,
            allow_anonymous_chirho: true,
            charges_chirho: vec![ResourceChargeChirho {
                resource_chirho: "credit_chirho".to_string(),
                amount_chirho: 1,
            }],
        }],
    )
    .unwrap();

    let input_chirho = || ResourceUsageInputChirho {
        app_chirho: "rebuildapp".to_string(),
        user_chirho: "user/one".to_string(),
        actor_chirho: None,
        section_chirho: "sec".to_string(),
        action_chirho: "act".to_string(),
        effect_chirho: None,
        run_chirho: None,
        bridges_chirho: Vec::new(),
    };
    for _ in 0..2 {
        assert_eq!(
            record_resource_usage_chirho(&root_chirho, input_chirho())
                .unwrap()
                .decision_chirho,
            ResourceDecisionChirho::AllowedChirho
        );
    }

    // Lose the checkpoint sidecar, forcing the next gated append to rebuild from the full scan.
    let checkpoint_path_chirho = usage_checkpoint_chirho::usage_checkpoint_path_chirho(
        &usage_records_path_chirho(&root_chirho),
    );
    assert!(
        checkpoint_path_chirho.exists(),
        "warm appends should have written a checkpoint"
    );
    std::fs::remove_file(&checkpoint_path_chirho).unwrap();

    reset_usage_load_counts_chirho();
    let rebuilt_chirho = record_resource_usage_chirho(&root_chirho, input_chirho()).unwrap();
    assert_eq!(
        rebuilt_chirho.decision_chirho,
        ResourceDecisionChirho::RoutedChirho {
            resource_chirho: "credit_chirho".to_string(),
            route_chirho: "over".to_string(),
            forward_request_body_chirho: false,
            limit_chirho: 2,
            used_chirho: 2,
            attempted_chirho: 3,
        },
        "the rebuilt aggregate must reproduce the full-scan routed decision"
    );
    assert_eq!(
        usage_full_load_count_chirho(),
        1,
        "sidecar loss must trigger exactly one full-scan rebuild"
    );
    assert_eq!(
        usage_rows_loaded_count_chirho(),
        2,
        "rebuild scans the prior rows once"
    );
    assert!(
        checkpoint_path_chirho.exists(),
        "rebuild must re-seed the checkpoint sidecar"
    );

    reset_usage_load_counts_chirho();
    let warm_again_chirho = record_resource_usage_chirho(&root_chirho, input_chirho()).unwrap();
    assert!(matches!(
        warm_again_chirho.decision_chirho,
        ResourceDecisionChirho::RoutedChirho { .. }
    ));
    assert_eq!(
        usage_full_load_count_chirho(),
        0,
        "after the one rebuild the checkpoint is warm again"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
