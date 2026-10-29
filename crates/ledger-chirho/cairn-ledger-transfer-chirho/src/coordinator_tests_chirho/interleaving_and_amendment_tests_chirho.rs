// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Exhaustive interleaving, lock-coordinate, and mid-saga amendment proofs.

use super::*;

/// CF2 acceptance: EVERY interleaving of two single-step sagas at the saga-append grain holds
/// per-kind sum-zero AND spendable >= 0 at EVERY intermediate durable state, and both close
/// Finalized with the golden nets. The crash-budget wrapper IS the step scheduler: one turn =
/// one durable saga record (plus its preceding journal effect), so the schedule space is the
/// full shuffle of the two sagas' 5-record sequences — C(10,5) = 252 schedules, exhaustive.
#[test]
fn every_interleaving_of_two_sagas_conserves_at_every_cut_chirho() {
    fn spendable_floor_holds_chirho(router_chirho: &RouterChirho<'_>) -> bool {
        router_chirho
            .engines_chirho
            .values()
            .flat_map(|engine_chirho| engine_chirho.head_states_chirho().values())
            .all(|post_chirho| {
                i128::from(post_chirho.credits_total_chirho)
                    - i128::from(post_chirho.debits_total_chirho)
                    - i128::from(post_chirho.held_chirho)
                    >= 0
            })
    }
    // Enumerate all bit-schedules: bit = which saga takes the next turn.
    fn schedules_chirho(turns_a_chirho: u32, turns_b_chirho: u32) -> Vec<Vec<u8>> {
        if turns_a_chirho == 0 {
            return vec![vec![1; turns_b_chirho as usize]];
        }
        if turns_b_chirho == 0 {
            return vec![vec![0; turns_a_chirho as usize]];
        }
        let mut out_chirho = Vec::new();
        for (first_chirho, rest_a_chirho, rest_b_chirho) in [
            (0_u8, turns_a_chirho - 1, turns_b_chirho),
            (1, turns_a_chirho, turns_b_chirho - 1),
        ] {
            for mut tail_chirho in schedules_chirho(rest_a_chirho, rest_b_chirho) {
                let mut schedule_chirho = vec![first_chirho];
                schedule_chirho.append(&mut tail_chirho);
                out_chirho.push(schedule_chirho);
            }
        }
        out_chirho
    }
    let all_chirho = schedules_chirho(5, 5);
    assert_eq!(all_chirho.len(), 252, "exhaustive shuffle of 5+5 turns");
    for schedule_chirho in all_chirho {
        let clock_chirho = SharedClockChirho {
            now_ms_chirho: Cell::new(1_000),
        };
        let a_chirho = JournalFixtureChirho::new_chirho(
            "cluster-a-chirho",
            "money-chirho",
            "platform-a-chirho",
        );
        let b_chirho = JournalFixtureChirho::new_chirho(
            "cluster-b-chirho",
            "points-chirho",
            "platform-b-chirho",
        );
        let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
        let sigma_funded_chirho = sigma_chirho(&router_chirho);
        let saga_storage_chirho = MemoryStorageChirho::default();
        let saga_root_chirho = SagaRootSignerChirho;
        // Saga 0: alice money on A. Saga 1: bob points on B. One step each.
        let plan_chirho = |index_chirho: usize| {
            let (fixture_chirho, owner_chirho, amount_chirho, settlement_chirho) =
                if index_chirho == 0 {
                    (&a_chirho, "alice-chirho", 10_u64, "platform-a-chirho")
                } else {
                    (&b_chirho, "bob-chirho", 5, "platform-b-chirho")
                };
            vec![SagaStepPlanChirho {
                cluster_chirho: fixture_chirho.cluster_chirho.clone(),
                owner_chirho: owner_chirho.to_owned(),
                kind_chirho: fixture_chirho.kind_chirho.clone(),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                    fixture_chirho.policy_ref_chirho.clone(),
                )),
                amount_chirho,
                settlement_owner_chirho: settlement_chirho.to_owned(),
            }]
        };
        let tokens_chirho = ["token-il-0-chirho", "token-il-1-chirho"];
        let mut closed_chirho = [false, false];
        for turn_chirho in &schedule_chirho {
            let index_chirho = *turn_chirho as usize;
            if closed_chirho[index_chirho] {
                continue;
            }
            let crash_storage_chirho = CrashStorageChirho {
                inner_chirho: &saga_storage_chirho,
                appends_left_chirho: Cell::new(Some(1)),
            };
            let coordinator_chirho = SagaCoordinatorChirho {
                storage_chirho: &crash_storage_chirho,
                root_chirho: &saga_root_chirho,
                clock_chirho: &clock_chirho,
                path_chirho: saga_path_chirho(),
                saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
            };
            closed_chirho[index_chirho] = coordinator_chirho
                .run_saga_chirho(
                    &mut router_chirho,
                    tokens_chirho[index_chirho],
                    plan_chirho(index_chirho),
                    60_000,
                )
                .is_ok();
            // THE INVARIANT SWEEP — after every single durable turn.
            assert_eq!(
                sigma_chirho(&router_chirho),
                sigma_funded_chirho,
                "sum-zero at every cut (schedule {schedule_chirho:?})"
            );
            assert!(
                spendable_floor_holds_chirho(&router_chirho),
                "spendable floor at every cut (schedule {schedule_chirho:?})"
            );
        }
        // Any residual turns (schedule exhausted early is impossible with 5+5, but close out).
        for index_chirho in 0..2 {
            if !closed_chirho[index_chirho] {
                let coordinator_chirho = SagaCoordinatorChirho {
                    storage_chirho: &saga_storage_chirho,
                    root_chirho: &saga_root_chirho,
                    clock_chirho: &clock_chirho,
                    path_chirho: saga_path_chirho(),
                    saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
                };
                coordinator_chirho
                    .run_saga_chirho(
                        &mut router_chirho,
                        tokens_chirho[index_chirho],
                        plan_chirho(index_chirho),
                        60_000,
                    )
                    .unwrap();
            }
        }
        assert_eq!(sigma_chirho(&router_chirho), sigma_funded_chirho);
        assert_eq!(held_total_chirho(&router_chirho), 0);
        let nets_chirho = nets_snapshot_chirho(&router_chirho);
        assert_eq!(nets_chirho["alice-chirho/money-chirho"], 90);
        assert_eq!(nets_chirho["platform-a-chirho/money-chirho"], 10);
        assert_eq!(nets_chirho["bob-chirho/points-chirho"], 95);
        assert_eq!(nets_chirho["platform-b-chirho/points-chirho"], 5);
    }
}

/// #5042's splice RED: separator-crafted ids must produce DISTINCT lock digests (length-prefix
/// framing), so the total order never tie-breaks by per-saga insertion order.
#[test]
fn lock_digest_refuses_the_separator_splice_chirho() {
    use crate::coordinator_chirho::step_lock_digest_chirho;
    let step_chirho = |cluster_chirho: &str, owner_chirho: &str| SagaStepPlanChirho {
        cluster_chirho: ClusterIdChirho(cluster_chirho.to_owned()),
        owner_chirho: owner_chirho.to_owned(),
        kind_chirho: "money-chirho".into(),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("policy-money-chirho".into())),
        amount_chirho: 1,
        settlement_owner_chirho: "platform-chirho".into(),
    };
    assert_ne!(
        step_lock_digest_chirho(&step_chirho("a/b-chirho", "c-chirho")),
        step_lock_digest_chirho(&step_chirho("a-chirho", "b-chirho/c-chirho")),
        "splice-shaped ids must never share a lock coordinate"
    );
    assert_ne!(
        step_lock_digest_chirho(&step_chirho("ab-chirho", "c-chirho")),
        step_lock_digest_chirho(&step_chirho("a-chirho", "bc-chirho")),
        "boundary shifts must never share a lock coordinate"
    );
    assert_eq!(
        step_lock_digest_chirho(&step_chirho("a-chirho", "b-chirho")),
        step_lock_digest_chirho(&step_chirho("a-chirho", "b-chirho")),
        "the coordinate is deterministic"
    );
}

/// #5127/#5151 a2: an amend superseding the plan's ref BETWEEN the hold and the settle must not
/// strand the hold — the coordinator finalizes under the CURRENT continuation ref and credits the
/// CURRENT settlement owner, not the plan's. The registry override makes the plan ref Superseded
/// (so a coordinator reusing it would refuse), proving the fix uses current-by-stable-kind.
#[test]
fn mid_saga_amend_finalizes_under_current_continuation_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let sigma_funded_chirho = sigma_chirho(&router_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let saga_root_chirho = SagaRootSignerChirho;
    let step_chirho = |amount_chirho: u64| {
        vec![SagaStepPlanChirho {
            cluster_chirho: a_chirho.cluster_chirho.clone(),
            owner_chirho: "alice-chirho".into(),
            kind_chirho: a_chirho.kind_chirho.clone(),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                a_chirho.policy_ref_chirho.clone(),
            )),
            amount_chirho,
            settlement_owner_chirho: "platform-a-chirho".into(),
        }]
    };
    // Crash after the hold, before the decision (intent + held = 2 saga appends).
    let crash_storage_chirho = CrashStorageChirho {
        inner_chirho: &saga_storage_chirho,
        appends_left_chirho: Cell::new(Some(2)),
    };
    SagaCoordinatorChirho {
        storage_chirho: &crash_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    }
    .run_saga_chirho(
        &mut router_chirho,
        "token-amend-fin-chirho",
        step_chirho(10),
        60_000,
    )
    .expect_err("crash before the decision");
    assert!(
        held_total_chirho(&router_chirho) > 0,
        "the hold is live at the cut"
    );
    // THE AMEND: R1 -> R2 with a NEW settlement owner, mid-saga.
    a_chirho.amend_continuation_chirho("policy-money-v2-chirho", "platform-a-v2-chirho");
    // Resume within TTL: finalizes under R2, credits platform-a-v2 (a plan-R1 finalize would
    // refuse — R1 is now Superseded).
    let reports_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    }
    .resume_all_chirho(&mut router_chirho)
    .unwrap();
    assert_eq!(reports_chirho.len(), 1);
    assert_eq!(
        reports_chirho[0].outcome_chirho,
        SagaOutcomeChirho::FinalizedChirho
    );
    let nets_chirho = nets_snapshot_chirho(&router_chirho);
    assert_eq!(
        nets_chirho["platform-a-v2-chirho/money-chirho"], 10,
        "CURRENT owner credited"
    );
    assert!(
        !nets_chirho.contains_key("platform-a-chirho/money-chirho"),
        "the PLAN's settlement owner is never touched"
    );
    assert_eq!(nets_chirho["alice-chirho/money-chirho"], 90);
    assert_eq!(
        sigma_chirho(&router_chirho),
        sigma_funded_chirho,
        "conserved across the amend"
    );
    assert_eq!(held_total_chirho(&router_chirho), 0);
}

/// #5152 a3: the release side has the same strand — a TTL-expiry compensation must release under
/// the CURRENT ref, not the plan's superseded one, or the hold strands forever.
#[test]
fn mid_saga_amend_ttl_releases_under_current_continuation_chirho() {
    let clock_chirho = SharedClockChirho {
        now_ms_chirho: Cell::new(1_000),
    };
    let a_chirho =
        JournalFixtureChirho::new_chirho("cluster-a-chirho", "money-chirho", "platform-a-chirho");
    let b_chirho =
        JournalFixtureChirho::new_chirho("cluster-b-chirho", "points-chirho", "platform-b-chirho");
    let mut router_chirho = funded_router_chirho(&a_chirho, &b_chirho, &clock_chirho);
    let nets_funded_chirho = nets_snapshot_chirho(&router_chirho);
    let sigma_funded_chirho = sigma_chirho(&router_chirho);
    let saga_storage_chirho = MemoryStorageChirho::default();
    let saga_root_chirho = SagaRootSignerChirho;
    let step_chirho = vec![SagaStepPlanChirho {
        cluster_chirho: a_chirho.cluster_chirho.clone(),
        owner_chirho: "alice-chirho".into(),
        kind_chirho: a_chirho.kind_chirho.clone(),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            a_chirho.policy_ref_chirho.clone(),
        )),
        amount_chirho: 10,
        settlement_owner_chirho: "platform-a-chirho".into(),
    }];
    let crash_storage_chirho = CrashStorageChirho {
        inner_chirho: &saga_storage_chirho,
        appends_left_chirho: Cell::new(Some(2)),
    };
    SagaCoordinatorChirho {
        storage_chirho: &crash_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    }
    .run_saga_chirho(
        &mut router_chirho,
        "token-amend-rel-chirho",
        step_chirho,
        500,
    )
    .expect_err("crash before the decision");
    assert!(held_total_chirho(&router_chirho) > 0);
    a_chirho.amend_continuation_chirho("policy-money-v2-chirho", "platform-a-v2-chirho");
    clock_chirho.now_ms_chirho.set(10_000); // past the 1_500 deadline -> abort -> release
    let reports_chirho = SagaCoordinatorChirho {
        storage_chirho: &saga_storage_chirho,
        root_chirho: &saga_root_chirho,
        clock_chirho: &clock_chirho,
        path_chirho: saga_path_chirho(),
        saga_log_id_chirho: SAGA_LOG_ID_CHIRHO.into(),
    }
    .resume_all_chirho(&mut router_chirho)
    .unwrap();
    assert_eq!(reports_chirho.len(), 1);
    assert_eq!(
        reports_chirho[0].outcome_chirho,
        SagaOutcomeChirho::CompensatedChirho,
        "expired TTL compensates under the CURRENT ref (a plan-R1 release would strand)"
    );
    assert_eq!(
        nets_snapshot_chirho(&router_chirho),
        nets_funded_chirho,
        "nothing moved"
    );
    assert_eq!(sigma_chirho(&router_chirho), sigma_funded_chirho);
    assert_eq!(
        held_total_chirho(&router_chirho),
        0,
        "the hold released, never stranded"
    );
}
