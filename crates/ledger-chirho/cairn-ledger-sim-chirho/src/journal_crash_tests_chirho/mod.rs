// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The REAL-engine crash/fault matrix (CF1 acceptance clause 1) + the write/read-amplification
//! measurement (clause 3), driven through the fault-injecting sim storage: a scripted scenario
//! (genesis → mint → transfer → epoch-advance → anchored transfer) is crashed at EVERY mutating
//! cut with EVERY fault kind, then recovered — the recovered state must equal the fold of a clean
//! PREFIX of the scenario (acknowledged ops always survive; a torn final line is repaired away; a
//! fully-durable-but-unacknowledged line may lawfully survive), and the journal must keep working
//! after every recovery. Steady state must cost EXACTLY one durability call per op and ZERO reads.

use crate::fault_chirho::{FaultKindChirho, FaultPlanChirho};
use crate::storage_chirho::SimStorageChirho;
use anyhow::Result;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalErrorChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{
    AttributionChirho, LedgerOpChirho, LegDeltaChirho, LegPostStateChirho,
};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use std::cell::Cell;

const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";

struct StepClockChirho {
    now_ms_chirho: Cell<u64>,
}

impl StepClockChirho {
    fn tick_chirho(&self) {
        self.now_ms_chirho.set(self.now_ms_chirho.get() + 100);
    }
}

impl LedgerClockPortChirho for StepClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

struct FakeSignerChirho;

impl LedgerSignerPortChirho for FakeSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "fake-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "sim-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .map(|expected_chirho| expected_chirho == sig_chirho)
            .unwrap_or(false)
    }
}

struct AllMembersChirho;

impl MembershipViewChirho for AllMembersChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

struct MoneyRegistryChirho;

impl KindRegistryViewChirho for MoneyRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        (policy_ref_chirho.0 .0 == MONEY_POLICY_REF_CHIRHO)
            .then(|| KindPolicyViewChirho {
                kind_id_chirho: MONEY_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: None,
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            })
            .map_or(
                KindResolutionChirho::UnknownChirho,
                KindResolutionChirho::CurrentChirho,
            )
    }
}

struct OpenAuthorityChirho;

impl AuthorityVerifierViewChirho for OpenAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == MINT_EVIDENCE_CHIRHO {
            AuthorityVerdictChirho::VerifiedChirho
        } else {
            AuthorityVerdictChirho::UnverifiedChirho
        }
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

struct ViewsChirho {
    clock_chirho: StepClockChirho,
    signer_chirho: FakeSignerChirho,
    membership_chirho: AllMembersChirho,
    registry_chirho: MoneyRegistryChirho,
    authority_chirho: OpenAuthorityChirho,
}

impl ViewsChirho {
    fn new_chirho() -> Self {
        ViewsChirho {
            clock_chirho: StepClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            signer_chirho: FakeSignerChirho,
            membership_chirho: AllMembersChirho,
            registry_chirho: MoneyRegistryChirho,
            authority_chirho: OpenAuthorityChirho,
        }
    }

    fn ports_chirho<'views_chirho>(
        &'views_chirho self,
        storage_chirho: &'views_chirho SimStorageChirho,
    ) -> JournalPortsChirho<'views_chirho> {
        JournalPortsChirho {
            storage_chirho,
            signer_chirho: &self.signer_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }
}

fn path_chirho() -> StoragePathChirho {
    StoragePathChirho::new_chirho("journals/cluster-sim-chirho.jsonl")
}

fn cluster_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-sim-chirho".into())
}

fn path_n_chirho(n_chirho: u64) -> StoragePathChirho {
    StoragePathChirho::new_chirho(format!("journals/cluster-{n_chirho}-chirho.jsonl"))
}

fn cluster_n_chirho(n_chirho: u64) -> ClusterIdChirho {
    ClusterIdChirho(format!("cluster-{n_chirho}-chirho"))
}

fn sidecar_path_of_chirho(path_chirho: &StoragePathChirho) -> String {
    format!("{}.head-checkpoint-chirho", path_chirho.0)
}

fn account_chirho(owner_chirho: &str) -> AccountIdChirho {
    LogIdChirho::new_chirho(owner_chirho, MONEY_KIND_CHIRHO)
}

fn leg_chirho(
    owner_chirho: &str,
    delta_chirho: LegDeltaChirho,
    amount_chirho: u64,
) -> AppendLegRequestChirho {
    AppendLegRequestChirho {
        account_chirho: account_chirho(owner_chirho),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(MONEY_POLICY_REF_CHIRHO.into())),
        delta_chirho,
        amount_chirho,
        counterpart_chirho: None,
    }
}

fn mint_chirho(amount_chirho: u64, idem_chirho: &str) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(MINT_EVIDENCE_CHIRHO.into()),
        },
        legs_chirho: vec![leg_chirho(
            "issuer-chirho",
            LegDeltaChirho::CreditChirho,
            amount_chirho,
        )],
        idempotency_key_chirho: idem_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn transfer_chirho(to_chirho: &str, amount_chirho: u64, idem_chirho: &str) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::TransferChirho,
        legs_chirho: vec![
            leg_chirho("issuer-chirho", LegDeltaChirho::DebitChirho, amount_chirho),
            leg_chirho(to_chirho, LegDeltaChirho::CreditChirho, amount_chirho),
        ],
        idempotency_key_chirho: idem_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

/// Drive the scripted scenario until it completes or the storage crash-latches. Returns how many
/// appends were ACKNOWLEDGED (an `Ok` receipt returned to the caller). Mutating-op indices:
/// 0 = genesis create, 1 = mint, 2 = transfer→alice, 3 = anchored transfer→bob (epoch 2).
fn drive_scenario_chirho(views_chirho: &ViewsChirho, storage_chirho: &SimStorageChirho) -> u64 {
    let mut acked_chirho = 0;
    let engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    );
    let mut engine_chirho = match engine_chirho {
        Ok(engine_chirho) => engine_chirho,
        Err(_) => return acked_chirho,
    };
    views_chirho.clock_chirho.tick_chirho();
    if engine_chirho
        .append_chirho(mint_chirho(500, "idem-mint-1"))
        .is_err()
    {
        return acked_chirho;
    }
    acked_chirho += 1;
    views_chirho.clock_chirho.tick_chirho();
    if engine_chirho
        .append_chirho(transfer_chirho("alice-chirho", 120, "idem-t-1"))
        .is_err()
    {
        return acked_chirho;
    }
    acked_chirho += 1;
    engine_chirho.advance_epoch_chirho(2).unwrap();
    views_chirho.clock_chirho.tick_chirho();
    if engine_chirho
        .append_chirho(transfer_chirho("bob-chirho", 50, "idem-t-2"))
        .is_err()
    {
        return acked_chirho;
    }
    acked_chirho += 1;
    acked_chirho
}

/// The reference fold: the exact expected state after the first `records` scenario appends.
fn assert_state_chirho(engine_chirho: &LedgerJournalChirho<'_>, records_chirho: u64) {
    let post_chirho = |c_chirho: u64, d_chirho: u64| LegPostStateChirho {
        credits_total_chirho: c_chirho,
        debits_total_chirho: d_chirho,
        held_chirho: 0,
    };
    assert_eq!(engine_chirho.tail_chirho().0, records_chirho);
    let issuer_chirho = engine_chirho.head_state_chirho(&account_chirho("issuer-chirho"));
    let alice_chirho = engine_chirho.head_state_chirho(&account_chirho("alice-chirho"));
    let bob_chirho = engine_chirho.head_state_chirho(&account_chirho("bob-chirho"));
    let supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    match records_chirho {
        0 => {
            assert_eq!(issuer_chirho, None);
            assert_eq!(supply_chirho, 0);
        }
        1 => {
            assert_eq!(issuer_chirho, Some(&post_chirho(500, 0)));
            assert_eq!(alice_chirho, None);
            assert_eq!(supply_chirho, 500);
        }
        2 => {
            assert_eq!(issuer_chirho, Some(&post_chirho(500, 120)));
            assert_eq!(alice_chirho, Some(&post_chirho(120, 0)));
            assert_eq!(supply_chirho, 500);
        }
        3 => {
            assert_eq!(issuer_chirho, Some(&post_chirho(500, 170)));
            assert_eq!(alice_chirho, Some(&post_chirho(120, 0)));
            assert_eq!(bob_chirho, Some(&post_chirho(50, 0)));
            assert_eq!(supply_chirho, 500);
            assert_eq!(engine_chirho.current_epoch_chirho(), 2);
        }
        _ => panic!("scenario has at most 3 appends"),
    }
}

#[test]
fn crash_matrix_every_cut_every_fault_recovers_to_a_clean_prefix_chirho() {
    // The full matrix: 4 mutating cuts × 4 fault shapes. TearWrite{usize::MAX} clamps to the FULL
    // line — durable-but-unacknowledged, the lawful `acked + 1` recovery case.
    let fault_shapes_chirho: Vec<(FaultKindChirho, bool)> = vec![
        (FaultKindChirho::CrashBeforeChirho, false),
        (
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: 1,
            },
            false,
        ),
        (
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: 40,
            },
            false,
        ),
        (
            FaultKindChirho::TearWriteChirho {
                prefix_len_chirho: usize::MAX,
            },
            true,
        ),
    ];
    for op_index_chirho in 0..=3u64 {
        for (fault_chirho, full_line_chirho) in &fault_shapes_chirho {
            let views_chirho = ViewsChirho::new_chirho();
            let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
                op_index_chirho,
                fault_chirho.clone(),
            ));
            let acked_chirho = drive_scenario_chirho(&views_chirho, &storage_chirho);
            assert_eq!(
                acked_chirho,
                op_index_chirho.saturating_sub(1),
                "appends before the faulted cut are acknowledged (op 0 is the genesis create)"
            );
            assert!(storage_chirho.is_crashed_chirho(), "the fault latched");
            // Recover: survived bytes reload into a fresh no-fault adapter.
            let recovered_storage_chirho = SimStorageChirho::restore_chirho(
                storage_chirho.snapshot_chirho(),
                FaultPlanChirho::none_chirho(),
            );
            let recovery_views_chirho = ViewsChirho::new_chirho();
            recovery_views_chirho.clock_chirho.now_ms_chirho.set(9_000);
            let opened_chirho = LedgerJournalChirho::open_chirho(
                recovery_views_chirho.ports_chirho(&recovered_storage_chirho),
                path_chirho(),
                &cluster_chirho(),
            );
            if op_index_chirho == 0 {
                // The GENESIS cut: crash-before leaves no object; a torn genesis has no verified
                // prefix. Both fail TYPED — recreate is the caller's explicit decision.
                match fault_chirho {
                    FaultKindChirho::CrashBeforeChirho => assert!(matches!(
                        opened_chirho,
                        Err(JournalErrorChirho::StorageChirho { .. })
                    )),
                    FaultKindChirho::TearWriteChirho { .. } if !full_line_chirho => {
                        assert!(matches!(
                            opened_chirho,
                            Err(JournalErrorChirho::TornTailChirho)
                        ))
                    }
                    // The full genesis line survived durably: the journal opens at zero records.
                    _ => match opened_chirho {
                        Ok(engine_chirho) => assert_state_chirho(&engine_chirho, 0),
                        Err(error_chirho) => {
                            panic!("full-line genesis must open: {error_chirho:?}")
                        }
                    },
                }
                continue;
            }
            let mut recovered_chirho = opened_chirho.unwrap();
            // The recovery law: acked ops ALWAYS survive; a fully-durable unacknowledged line may
            // lawfully survive too (its caller retries into IdempotencyDuplicate); a partial line
            // is repaired away.
            let expected_records_chirho = if *full_line_chirho {
                acked_chirho + 1
            } else {
                acked_chirho
            };
            assert_state_chirho(&recovered_chirho, expected_records_chirho);
            if !*full_line_chirho && matches!(fault_chirho, FaultKindChirho::TearWriteChirho { .. })
            {
                assert!(
                    recovered_chirho.repaired_torn_tail_bytes_chirho().is_some(),
                    "a partial tear at cut {op_index_chirho} repairs"
                );
            }
            // Continuity: the recovered journal accepts new work after EVERY cut.
            recovery_views_chirho.clock_chirho.tick_chirho();
            let receipt_chirho = recovered_chirho
                .append_chirho(mint_chirho(7, "idem-post-recovery-chirho"))
                .unwrap();
            assert_eq!(receipt_chirho.seq_chirho, expected_records_chirho + 1);
        }
    }
}

#[test]
fn repair_crash_is_idempotent_chirho() {
    // Tear the last append, then CRASH THE REPAIR ITSELF (the truncate is mutating op 0 of the
    // recovery adapter): the journal stays torn, and a second recovery completes the same repair.
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
        3,
        FaultKindChirho::TearWriteChirho {
            prefix_len_chirho: 25,
        },
    ));
    let acked_chirho = drive_scenario_chirho(&views_chirho, &storage_chirho);
    assert_eq!(acked_chirho, 2);
    let torn_snapshot_chirho = storage_chirho.snapshot_chirho();
    // Recovery attempt 1: the repair truncate itself crashes.
    let crashing_repair_chirho = SimStorageChirho::restore_chirho(
        torn_snapshot_chirho.clone(),
        FaultPlanChirho::single_chirho(0, FaultKindChirho::CrashBeforeChirho),
    );
    let views2_chirho = ViewsChirho::new_chirho();
    assert!(matches!(
        LedgerJournalChirho::open_chirho(
            views2_chirho.ports_chirho(&crashing_repair_chirho),
            path_chirho(),
            &cluster_chirho(),
        ),
        Err(JournalErrorChirho::StorageChirho { .. })
    ));
    // The object is UNCHANGED (crash-before truncate) — recovery attempt 2 repairs cleanly.
    let second_chirho = SimStorageChirho::restore_chirho(
        crashing_repair_chirho.snapshot_chirho(),
        FaultPlanChirho::none_chirho(),
    );
    let views3_chirho = ViewsChirho::new_chirho();
    views3_chirho.clock_chirho.now_ms_chirho.set(9_000);
    let recovered_chirho = LedgerJournalChirho::open_chirho(
        views3_chirho.ports_chirho(&second_chirho),
        path_chirho(),
        &cluster_chirho(),
    )
    .unwrap();
    assert!(recovered_chirho.repaired_torn_tail_bytes_chirho().is_some());
    assert_state_chirho(&recovered_chirho, 2);
}

#[test]
fn steady_state_costs_one_durability_call_per_op_and_zero_reads_chirho() {
    // CF1 acceptance clause 3: write amplification == 1 authority sync/op steady-state, and the
    // append path performs ZERO storage reads (the live head-index is the fence's read source —
    // §11.4 delta=0; recovery's one full read is the measured, non-hot-path exception).
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(1_000, "idem-mint-1"))
        .unwrap();
    for index_chirho in 0..10 {
        views_chirho.clock_chirho.tick_chirho();
        engine_chirho
            .append_chirho(transfer_chirho(
                "alice-chirho",
                5,
                &format!("idem-steady-{index_chirho}"),
            ))
            .unwrap();
    }
    let counts_chirho = storage_chirho.operation_counts_chirho();
    assert_eq!(
        counts_chirho.create_durable_calls_chirho, 1,
        "genesis is one exclusive durable create"
    );
    assert_eq!(
        counts_chirho.append_durable_calls_chirho, 11,
        "the 11 steady-state operations use ONE durable append each"
    );
    assert_eq!(
        counts_chirho.durability_call_count_chirho(),
        12,
        "no other durability calls"
    );
    assert_eq!(
        storage_chirho
            .read_operation_counts_chirho()
            .total_read_calls_chirho(),
        0,
        "the append hot path reads NOTHING (live index; §11.4 delta=0)"
    );
    // Recovery is the ONE measured full read.
    drop(engine_chirho);
    let views2_chirho = ViewsChirho::new_chirho();
    views2_chirho.clock_chirho.now_ms_chirho.set(9_000);
    LedgerJournalChirho::open_chirho(
        views2_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    )
    .unwrap();
    let journal_full_reads_chirho = storage_chirho
        .read_trace_chirho()
        .iter()
        .filter(|event_chirho| {
            event_chirho.kind_chirho == crate::storage_chirho::StorageReadKindChirho::FullReadChirho
                && event_chirho.path_chirho == path_chirho().0
        })
        .count();
    assert_eq!(
        journal_full_reads_chirho, 1,
        "a no-sidecar open costs exactly ONE full read of the JOURNAL (the sidecar probe is a \
         separate cheap miss; a checkpointed open range-reads instead, proven in the log crate)"
    );
}

#[test]
fn rotation_crash_matrix_recovers_at_every_cut_chirho() {
    // B0 3c: RC.1 / RC.2 / RC.4 over the REAL money journal — crash BEFORE every one of the
    // rotation's durable mutations, restart, and require the uniform money invariants: reopen
    // SUCCEEDS (the manifest-authoritative marker protocol finishes or refuses the half-cut —
    // never a wedged journal), the logical state is EXACTLY the pre-rotation live state (a
    // rotation is a layout cut; NO crash outcome may lose or duplicate a committed record), and
    // the next append continues the dense chain (no seq reuse, no gap). Which side of the cut a
    // given crash recovers to (nothing-happened vs completed-forward) is the protocol's business;
    // the invariants hold on BOTH.
    // Baseline (fault-free): learn the pre-rotation op count, rotation op count, and live state.
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(1_000, "idem-rcm-mint"))
        .unwrap();
    for index_chirho in 0..2 {
        views_chirho.clock_chirho.tick_chirho();
        engine_chirho
            .append_chirho(transfer_chirho(
                "alice-chirho",
                7,
                &format!("idem-rcm-pre-{index_chirho}"),
            ))
            .unwrap();
    }
    let live_tail_seq_chirho = engine_chirho.tail_chirho().0;
    let live_tail_digest_chirho = engine_chirho.tail_chirho().1.clone();
    let live_supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    let live_issuer_chirho = engine_chirho
        .head_state_chirho(&account_chirho("issuer-chirho"))
        .cloned();
    let live_alice_chirho = engine_chirho
        .head_state_chirho(&account_chirho("alice-chirho"))
        .cloned();
    let pre_ops_chirho = storage_chirho
        .operation_counts_chirho()
        .durability_call_count_chirho();
    engine_chirho.rotate_chirho().unwrap();
    let rotation_ops_chirho = storage_chirho
        .operation_counts_chirho()
        .durability_call_count_chirho()
        - pre_ops_chirho;
    drop(engine_chirho);

    for cut_chirho in 0..rotation_ops_chirho {
        // Fresh deterministic replay of the same scenario, crashing before rotation op `cut`.
        let crash_views_chirho = ViewsChirho::new_chirho();
        let crash_storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
            pre_ops_chirho + cut_chirho,
            FaultKindChirho::CrashBeforeChirho,
        ));
        let mut crash_engine_chirho = LedgerJournalChirho::create_chirho(
            crash_views_chirho.ports_chirho(&crash_storage_chirho),
            path_chirho(),
            cluster_chirho(),
            1,
        )
        .unwrap();
        crash_views_chirho.clock_chirho.tick_chirho();
        crash_engine_chirho
            .append_chirho(mint_chirho(1_000, "idem-rcm-mint"))
            .unwrap();
        for index_chirho in 0..2 {
            crash_views_chirho.clock_chirho.tick_chirho();
            crash_engine_chirho
                .append_chirho(transfer_chirho(
                    "alice-chirho",
                    7,
                    &format!("idem-rcm-pre-{index_chirho}"),
                ))
                .unwrap();
        }
        assert!(
            crash_engine_chirho.rotate_chirho().is_err(),
            "cut {cut_chirho}: the injected crash must surface as a rotation error"
        );
        drop(crash_engine_chirho);
        // Restart the machine: recovery must never wedge and never mis-state money.
        let restart_storage_chirho = SimStorageChirho::restore_chirho(
            crash_storage_chirho.snapshot_chirho(),
            FaultPlanChirho::none_chirho(),
        );
        let restart_views_chirho = ViewsChirho::new_chirho();
        restart_views_chirho.clock_chirho.now_ms_chirho.set(9_000);
        let mut recovered_chirho = LedgerJournalChirho::open_chirho(
            restart_views_chirho.ports_chirho(&restart_storage_chirho),
            path_chirho(),
            &cluster_chirho(),
        )
        .unwrap_or_else(|error_chirho| {
            panic!(
                "cut {cut_chirho}: reopen must recover the crashed rotation, got {error_chirho:?}"
            )
        });
        assert_eq!(
            recovered_chirho.tail_chirho().0,
            live_tail_seq_chirho,
            "cut {cut_chirho}: recovered tail seq"
        );
        assert_eq!(
            recovered_chirho.tail_chirho().1,
            &live_tail_digest_chirho,
            "cut {cut_chirho}: recovered tail digest"
        );
        assert_eq!(
            recovered_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
            live_supply_chirho,
            "cut {cut_chirho}: supply conserved"
        );
        assert_eq!(
            recovered_chirho
                .head_state_chirho(&account_chirho("issuer-chirho"))
                .cloned(),
            live_issuer_chirho,
            "cut {cut_chirho}: issuer head"
        );
        assert_eq!(
            recovered_chirho
                .head_state_chirho(&account_chirho("alice-chirho"))
                .cloned(),
            live_alice_chirho,
            "cut {cut_chirho}: alice head"
        );
        restart_views_chirho.clock_chirho.tick_chirho();
        let receipt_chirho = recovered_chirho
            .append_chirho(transfer_chirho(
                "alice-chirho",
                1,
                &format!("idem-rcm-post-{cut_chirho}"),
            ))
            .unwrap_or_else(|error_chirho| {
                panic!("cut {cut_chirho}: the recovered journal must accept appends, got {error_chirho:?}")
            });
        assert_eq!(
            receipt_chirho.seq_chirho,
            live_tail_seq_chirho + 1,
            "cut {cut_chirho}: dense continuation — no seq reuse, no gap"
        );
    }
}

#[test]
fn rotation_seals_repaired_bytes_after_torn_active_tail_chirho() {
    // Deviation-#4 obligation (ii), the ENFORCER RC: a torn active tail is repaired by the JOURNAL
    // at open (its own port truncate), and a subsequent rotation seals exactly the REPAIRED bytes
    // — never the torn ones. This is only writable because the whole seal path is port-driven.
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(500, "idem-torn-mint"))
        .unwrap();
    drop(engine_chirho);
    // A crash mid-append leaves an unacknowledged torn suffix on the active file.
    let clean_bytes_chirho = storage_chirho
        .read_all_chirho(&path_chirho())
        .unwrap()
        .unwrap();
    storage_chirho
        .append_durable_chirho(&path_chirho(), b"{\"schema_chirho\":\"torn-partial")
        .unwrap();
    // Reopen: the journal repairs its own active through its own port.
    let views2_chirho = ViewsChirho::new_chirho();
    views2_chirho.clock_chirho.now_ms_chirho.set(5_000);
    let mut reopened_chirho = LedgerJournalChirho::open_chirho(
        views2_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    )
    .unwrap();
    assert!(reopened_chirho.repaired_torn_tail_bytes_chirho().is_some());
    // Rotation seals the REPAIRED bytes exactly.
    reopened_chirho.rotate_chirho().unwrap();
    let sealed_dir_chirho = StoragePathChirho(format!("{}.segments-chirho/", path_chirho().0));
    let sealed_files_chirho = storage_chirho.list_chirho(&sealed_dir_chirho).unwrap();
    assert_eq!(sealed_files_chirho.len(), 1, "exactly one sealed segment");
    let sealed_bytes_chirho = storage_chirho
        .read_all_chirho(&sealed_files_chirho[0])
        .unwrap()
        .unwrap();
    assert_eq!(
        sealed_bytes_chirho, clean_bytes_chirho,
        "the sealed segment must hold the REPAIRED active bytes, never the torn suffix"
    );
}

#[test]
fn append_and_rotation_costs_are_independent_of_segment_count_twin_chirho() {
    // CF1 clause 4, the SEGMENTS + MANIFEST scaling twins (M250 law at the segment axis): a
    // journal that has rotated many times must cost EXACTLY the same per append (1 durable call,
    // 0 hot-path reads — appends never touch sealed history) and EXACTLY the same per rotation
    // (the pinned 7 — one manifest APPEND per seal, never an O(segments) manifest rewrite) as a
    // journal with one segment. Growth in sealed history is a storage fact, never a hot-path cost.
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(10_000, "idem-segtwin-mint"))
        .unwrap();
    let mut rotation_costs_chirho: Vec<u64> = Vec::new();
    let mut append_costs_chirho: Vec<(u64, u64)> = Vec::new();
    for round_chirho in 0..5 {
        let before_rotate_chirho = storage_chirho
            .operation_counts_chirho()
            .durability_call_count_chirho();
        engine_chirho.rotate_chirho().unwrap();
        rotation_costs_chirho.push(
            storage_chirho
                .operation_counts_chirho()
                .durability_call_count_chirho()
                - before_rotate_chirho,
        );
        let before_appends_chirho = storage_chirho
            .operation_counts_chirho()
            .durability_call_count_chirho();
        let reads_before_chirho = storage_chirho
            .read_operation_counts_chirho()
            .total_read_calls_chirho();
        for index_chirho in 0..3 {
            views_chirho.clock_chirho.tick_chirho();
            engine_chirho
                .append_chirho(transfer_chirho(
                    "alice-chirho",
                    1,
                    &format!("idem-segtwin-{round_chirho}-{index_chirho}"),
                ))
                .unwrap();
        }
        append_costs_chirho.push((
            storage_chirho
                .operation_counts_chirho()
                .durability_call_count_chirho()
                - before_appends_chirho,
            storage_chirho
                .read_operation_counts_chirho()
                .total_read_calls_chirho()
                - reads_before_chirho,
        ));
    }
    assert_eq!(
        rotation_costs_chirho,
        vec![7, 7, 7, 7, 7],
        "every rotation costs the pinned 7 regardless of how many segments already exist"
    );
    assert_eq!(
        append_costs_chirho,
        vec![(3, 0); 5],
        "appends stay 1 durable / 0 reads regardless of sealed-segment count"
    );
    // And the five-segment journal still REOPENS with exact state equivalence — the manifest-walk
    // recomposition chains across EVERY seam (the multi-segment positive twin of the 3b-iii
    // single-seam equivalence proof).
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    let live_supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    drop(engine_chirho);
    let reopen_views_chirho = ViewsChirho::new_chirho();
    reopen_views_chirho.clock_chirho.now_ms_chirho.set(99_000);
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        reopen_views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    )
    .unwrap();
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho,
        "multi-segment reopen recovers the exact live tail across every seam"
    );
    assert_eq!(
        reopened_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into()),
        live_supply_chirho
    );
}

#[test]
fn rotated_fast_open_is_o_window_never_o_history_chirho() {
    // Clause-4 completion (the promoted fast-path increment): a post-rotation checkpoint makes
    // rotated-journal reopen O(window) — the warm path reads NO sealed segment and never
    // full-reads the journal object; hydrate cost is independent of sealed history.
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(1_000, "idem-fpwin-mint"))
        .unwrap();
    for round_chirho in 0..3 {
        views_chirho.clock_chirho.tick_chirho();
        engine_chirho
            .append_chirho(transfer_chirho(
                "alice-chirho",
                3,
                &format!("idem-fpwin-{round_chirho}"),
            ))
            .unwrap();
        engine_chirho.rotate_chirho().unwrap();
    }
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let live_tail_chirho = (
        engine_chirho.tail_chirho().0,
        engine_chirho.tail_chirho().1.clone(),
    );
    drop(engine_chirho);
    let reads_before_chirho = storage_chirho.read_trace_chirho().len();
    let reopened_chirho = LedgerJournalChirho::open_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    )
    .unwrap();
    assert!(
        reopened_chirho.last_open_was_fast_chirho(),
        "a rotated journal with a post-rotation checkpoint must fast-open"
    );
    assert_eq!(
        (
            reopened_chirho.tail_chirho().0,
            reopened_chirho.tail_chirho().1.clone()
        ),
        live_tail_chirho
    );
    let new_reads_chirho: Vec<_> = storage_chirho
        .read_trace_chirho()
        .into_iter()
        .skip(reads_before_chirho)
        .collect();
    assert!(
        !new_reads_chirho
            .iter()
            .any(|event_chirho| event_chirho.path_chirho.contains(".segments-chirho/")),
        "the warm rotated open must read NO sealed segment (O(window), never O(history))"
    );
    assert!(
        !new_reads_chirho.iter().any(|event_chirho| {
            event_chirho.kind_chirho == crate::storage_chirho::StorageReadKindChirho::FullReadChirho
                && event_chirho.path_chirho == path_chirho().0
        }),
        "the warm rotated open must never full-read the journal object"
    );
}

#[test]
fn rotation_costs_bounded_writes_and_keeps_steady_state_one_durable_per_op_chirho() {
    // CF1 acceptance clause 3, rotation half (RC.5): the rotation boundary costs a BOUNDED number
    // of durability calls (budget ≤ 7 — seal + one manifest append + active reset + marker
    // lifecycle + sidecar removal), never O(segments) or O(history); and the steady-state append
    // law (ONE durable call per op, ZERO hot-path reads) is UNCHANGED on the far side of the seam.
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    let mut engine_chirho = LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(&storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    views_chirho.clock_chirho.tick_chirho();
    engine_chirho
        .append_chirho(mint_chirho(1_000, "idem-rotamp-mint"))
        .unwrap();
    for index_chirho in 0..4 {
        views_chirho.clock_chirho.tick_chirho();
        engine_chirho
            .append_chirho(transfer_chirho(
                "alice-chirho",
                5,
                &format!("idem-rotamp-pre-{index_chirho}"),
            ))
            .unwrap();
    }
    engine_chirho.write_head_checkpoint_chirho().unwrap();
    let before_chirho = storage_chirho
        .operation_counts_chirho()
        .durability_call_count_chirho();

    engine_chirho.rotate_chirho().unwrap();

    let rotation_cost_chirho = storage_chirho
        .operation_counts_chirho()
        .durability_call_count_chirho()
        - before_chirho;
    assert!(
        rotation_cost_chirho <= 7,
        "rotation must cost ≤ 7 durability calls at the boundary, measured {rotation_cost_chirho}"
    );
    // The exact 7: marker write + sealed segment + manifest append + manifest-head locator +
    // active reset + seqlog head-sidecar clear + marker clear. (The journal's own checkpoint
    // sidecar is NOT removed — its base>0 genesis binding self-discards structurally.) A count
    // drift in EITHER direction is a boundary-cost regression to re-derive, not renumber.
    assert_eq!(
        rotation_cost_chirho, 7,
        "rotation boundary cost drifted from the derived 7 durable calls"
    );

    // Steady-state on the far side of the seam: ONE durable call per append, ZERO hot-path reads.
    let appends_before_chirho = storage_chirho
        .operation_counts_chirho()
        .append_durable_calls_chirho;
    let reads_before_chirho = storage_chirho
        .read_operation_counts_chirho()
        .total_read_calls_chirho();
    for index_chirho in 0..3 {
        views_chirho.clock_chirho.tick_chirho();
        engine_chirho
            .append_chirho(transfer_chirho(
                "alice-chirho",
                2,
                &format!("idem-rotamp-post-{index_chirho}"),
            ))
            .unwrap();
    }
    assert_eq!(
        storage_chirho
            .operation_counts_chirho()
            .append_durable_calls_chirho
            - appends_before_chirho,
        3,
        "post-rotation appends stay ONE durable append each"
    );
    assert_eq!(
        storage_chirho
            .read_operation_counts_chirho()
            .total_read_calls_chirho()
            - reads_before_chirho,
        0,
        "the post-rotation append hot path reads NOTHING (live index; §11.4 delta=0)"
    );
}

// --- CF1 acceptance clause 4: the scaling twins (2 vs 2000) ---

/// Twin A — per-append runtime cost is O(1) in the account count. A journal fanning out to 2000
/// distinct accounts costs the SAME per append (one durable call, zero hot-path reads) as one
/// fanning out to 2. The append never scans the growing head-index — the fence reads the LIVE
/// in-memory head, so appends 2 and 2000 are indistinguishable in storage cost (§11.4).
#[test]
fn append_cost_is_o1_in_account_count_twin_chirho() {
    fn fanout_cost_chirho(members_chirho: u64) -> (u64, u64) {
        let views_chirho = ViewsChirho::new_chirho();
        let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
        let mut engine_chirho = LedgerJournalChirho::create_chirho(
            views_chirho.ports_chirho(&storage_chirho),
            path_chirho(),
            cluster_chirho(),
            1,
        )
        .unwrap();
        views_chirho.clock_chirho.tick_chirho();
        engine_chirho
            .append_chirho(mint_chirho(members_chirho + 10, "idem-mint-1"))
            .unwrap();
        for index_chirho in 0..members_chirho {
            views_chirho.clock_chirho.tick_chirho();
            engine_chirho
                .append_chirho(transfer_chirho(
                    &format!("acct-{index_chirho}-chirho"),
                    1,
                    &format!("idem-fan-{index_chirho}"),
                ))
                .unwrap();
        }
        (
            storage_chirho
                .operation_counts_chirho()
                .durability_call_count_chirho(),
            storage_chirho
                .read_operation_counts_chirho()
                .total_read_calls_chirho(),
        )
    }
    let (durable_2_chirho, reads_2_chirho) = fanout_cost_chirho(2);
    let (durable_2000_chirho, reads_2000_chirho) = fanout_cost_chirho(2000);
    // genesis create + mint + one durable append per transfer, and ZERO hot-path reads, at BOTH scales.
    assert_eq!(durable_2_chirho, 1 + 1 + 2);
    assert_eq!(durable_2000_chirho, 1 + 1 + 2000);
    assert_eq!(reads_2_chirho, 0);
    assert_eq!(reads_2000_chirho, 0);
    // The twin: appends-only durable cost == account count at BOTH scales (exactly 1 per append),
    // and the read cost stays flat at zero — no O(accounts) scan crept into the hot path.
    assert_eq!(durable_2_chirho - 2, 2);
    assert_eq!(durable_2000_chirho - 2, 2000);
}

/// Twin B — resident MEMORY is O(active), not O(total journals). N journals are each checkpointed
/// then PASSIVATED (dropped); HYDRATING any one is a verified fast-open that range-reads ONLY that
/// journal's own files — never a scan of the other N−1. So a system holding K resident journals
/// uses O(K) memory regardless of how many exist, and per-hydrate cost is independent of N.
#[test]
fn passivate_hydrate_is_local_and_fast_o_active_twin_chirho() {
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::none_chirho());
    const N_CHIRHO: u64 = 50;
    // Create + checkpoint + passivate (drop) every journal.
    for n_chirho in 0..N_CHIRHO {
        let mut engine_chirho = LedgerJournalChirho::create_chirho(
            views_chirho.ports_chirho(&storage_chirho),
            path_n_chirho(n_chirho),
            cluster_n_chirho(n_chirho),
            1,
        )
        .unwrap();
        views_chirho.clock_chirho.tick_chirho();
        engine_chirho
            .append_chirho(mint_chirho(100, &format!("idem-mint-{n_chirho}")))
            .unwrap();
        engine_chirho.write_head_checkpoint_chirho().unwrap();
        // drop(engine_chirho): passivated. Durable state = journal file + signed sidecar.
    }
    // Hydrate a chosen journal and return (was_fast, reads-touching-OTHER-journals,
    // full-reads-of-THIS-journal, total reads in the hydrate window).
    let hydrate_profile_chirho = |n_chirho: u64| -> (bool, usize, usize, usize) {
        let before_chirho = storage_chirho.read_trace_chirho().len();
        let engine_chirho = LedgerJournalChirho::open_chirho(
            views_chirho.ports_chirho(&storage_chirho),
            path_n_chirho(n_chirho),
            &cluster_n_chirho(n_chirho),
        )
        .unwrap();
        let was_fast_chirho = engine_chirho.last_open_was_fast_chirho();
        drop(engine_chirho); // immediately passivate again — resident set stays O(1).
        let trace_chirho = storage_chirho.read_trace_chirho();
        let window_chirho = &trace_chirho[before_chirho..];
        let own_journal_chirho = path_n_chirho(n_chirho).0;
        let own_sidecar_chirho = sidecar_path_of_chirho(&path_n_chirho(n_chirho));
        let foreign_chirho = window_chirho
            .iter()
            .filter(|event_chirho| {
                // Own files = the journal object, its sidecar, and its whole segment family
                // (manifest/mhead/marker/sealed dir — all prefixed by the journal path).
                !event_chirho.path_chirho.starts_with(&own_journal_chirho)
                    && event_chirho.path_chirho != own_sidecar_chirho
            })
            .count();
        let own_full_reads_chirho = window_chirho
            .iter()
            .filter(|event_chirho| {
                event_chirho.path_chirho == own_journal_chirho
                    && event_chirho.kind_chirho
                        == crate::storage_chirho::StorageReadKindChirho::FullReadChirho
            })
            .count();
        (
            was_fast_chirho,
            foreign_chirho,
            own_full_reads_chirho,
            window_chirho.len(),
        )
    };
    // The LAST journal and the FIRST journal hydrate identically — cost independent of N and of
    // position; each is a fast-open touching ONLY its own files, with NO full read of the journal.
    let (fast_last_chirho, foreign_last_chirho, full_last_chirho, total_last_chirho) =
        hydrate_profile_chirho(N_CHIRHO - 1);
    let (fast_first_chirho, foreign_first_chirho, full_first_chirho, total_first_chirho) =
        hydrate_profile_chirho(0);
    assert!(
        fast_last_chirho && fast_first_chirho,
        "each hydrate is a verified fast-open"
    );
    assert_eq!(
        foreign_last_chirho, 0,
        "a hydrate never reads another journal"
    );
    assert_eq!(foreign_first_chirho, 0);
    assert_eq!(
        full_last_chirho, 0,
        "a checkpointed hydrate never full-reads the journal"
    );
    assert_eq!(full_first_chirho, 0);
    // Per-hydrate read count is IDENTICAL for #49 and #0 — the twin: O(1) in the journal count N.
    assert_eq!(total_last_chirho, total_first_chirho);
}

// --- The sidecar x crash interaction (the fast-open recovery path under faults) ---

/// Drive: genesis(op0) -> mint(op1) -> CHECKPOINT(op2, an atomic_write) -> transfer alice(op3) ->
/// transfer bob(op4), stopping at the first crash-latch. Unlike `drive_scenario_chirho` this writes
/// a signed sidecar mid-run, so recovery can take the verified FAST path. Returns acked appends.
fn drive_checkpointed_scenario_chirho(
    views_chirho: &ViewsChirho,
    storage_chirho: &SimStorageChirho,
) -> u64 {
    let mut acked_chirho = 0;
    let mut engine_chirho = match LedgerJournalChirho::create_chirho(
        views_chirho.ports_chirho(storage_chirho),
        path_chirho(),
        cluster_chirho(),
        1,
    ) {
        Ok(engine_chirho) => engine_chirho,
        Err(_) => return acked_chirho,
    };
    views_chirho.clock_chirho.tick_chirho();
    if engine_chirho
        .append_chirho(mint_chirho(500, "idem-mint-1"))
        .is_err()
    {
        return acked_chirho;
    }
    acked_chirho += 1;
    if engine_chirho.write_head_checkpoint_chirho().is_err() {
        return acked_chirho; // the checkpoint atomic_write crashed (op2)
    }
    views_chirho.clock_chirho.tick_chirho();
    if engine_chirho
        .append_chirho(transfer_chirho("alice-chirho", 120, "idem-t-1"))
        .is_err()
    {
        return acked_chirho;
    }
    acked_chirho += 1;
    // Advance the epoch so bob is the anchored first record of epoch 2 — mirrors the base scenario
    // (so `assert_state_chirho` applies) AND exercises a suffix replay that spans an epoch bump.
    engine_chirho.advance_epoch_chirho(2).unwrap();
    views_chirho.clock_chirho.tick_chirho();
    if engine_chirho
        .append_chirho(transfer_chirho("bob-chirho", 50, "idem-t-2"))
        .is_err()
    {
        return acked_chirho;
    }
    acked_chirho += 1;
    acked_chirho
}

// --- CF1 acceptance clause 1: a SEEDED crash fuzzer (recorded seeds; failing seeds preserved) ---

/// Whether an engine's state is EXACTLY one of the scenario's valid clean prefixes (0..=3 records).
/// A recovery that lands on anything else is a corruption the fuzzer must catch.
fn is_valid_scenario_prefix_chirho(engine_chirho: &LedgerJournalChirho<'_>) -> bool {
    let issuer_chirho = engine_chirho
        .head_state_chirho(&account_chirho("issuer-chirho"))
        .cloned();
    let alice_chirho = engine_chirho
        .head_state_chirho(&account_chirho("alice-chirho"))
        .cloned();
    let bob_chirho = engine_chirho
        .head_state_chirho(&account_chirho("bob-chirho"))
        .cloned();
    let supply_chirho = engine_chirho.supply_chirho(&MONEY_KIND_CHIRHO.into());
    let post_chirho = |c_chirho: u64, d_chirho: u64| LegPostStateChirho {
        credits_total_chirho: c_chirho,
        debits_total_chirho: d_chirho,
        held_chirho: 0,
    };
    match engine_chirho.tail_chirho().0 {
        0 => {
            issuer_chirho.is_none()
                && alice_chirho.is_none()
                && bob_chirho.is_none()
                && supply_chirho == 0
        }
        1 => {
            issuer_chirho == Some(post_chirho(500, 0))
                && alice_chirho.is_none()
                && bob_chirho.is_none()
                && supply_chirho == 500
        }
        2 => {
            issuer_chirho == Some(post_chirho(500, 120))
                && alice_chirho == Some(post_chirho(120, 0))
                && bob_chirho.is_none()
                && supply_chirho == 500
        }
        3 => {
            issuer_chirho == Some(post_chirho(500, 170))
                && alice_chirho == Some(post_chirho(120, 0))
                && bob_chirho == Some(post_chirho(50, 0))
                && supply_chirho == 500
                && engine_chirho.current_epoch_chirho() == 2
        }
        _ => false,
    }
}

/// One seeded trial: a deterministic LCG picks a fault (kind + op index + tear length) to inject into
/// the checkpointed scenario, then recovers and checks the recovery LAW: either the journal fails
/// TYPED (torn genesis), or it recovers to a valid clean prefix AND accepts a following append.
/// Returns true iff the law held for this seed.
fn crash_fuzz_seed_holds_chirho(seed_chirho: u64) -> bool {
    // A tiny LCG (Numerical Recipes constants) — deterministic per seed, no wall-clock/rng.
    let mut state_chirho = seed_chirho
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let mut next_chirho = |bound_chirho: u64| -> u64 {
        state_chirho = state_chirho
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state_chirho >> 33) % bound_chirho
    };
    // op index across the checkpointed scenario's mutating ops (0 genesis create .. 4 bob, plus 5 = "no
    // fault" so some seeds run clean).
    let op_index_chirho = next_chirho(6);
    let fault_chirho = match next_chirho(3) {
        0 => FaultKindChirho::CrashBeforeChirho,
        1 => FaultKindChirho::TearWriteChirho {
            prefix_len_chirho: (next_chirho(60) + 1) as usize,
        },
        _ => FaultKindChirho::TearWriteChirho {
            prefix_len_chirho: usize::MAX,
        },
    };
    let views_chirho = ViewsChirho::new_chirho();
    let storage_chirho = SimStorageChirho::new_chirho(FaultPlanChirho::single_chirho(
        op_index_chirho,
        fault_chirho,
    ));
    drive_checkpointed_scenario_chirho(&views_chirho, &storage_chirho);
    // Recover from whatever survived (a clean no-fault reopen).
    let recovered_storage_chirho = SimStorageChirho::restore_chirho(
        storage_chirho.snapshot_chirho(),
        FaultPlanChirho::none_chirho(),
    );
    let recovery_views_chirho = ViewsChirho::new_chirho();
    recovery_views_chirho.clock_chirho.now_ms_chirho.set(9_000);
    let opened_chirho = LedgerJournalChirho::open_chirho(
        recovery_views_chirho.ports_chirho(&recovered_storage_chirho),
        path_chirho(),
        &cluster_chirho(),
    );
    let mut engine_chirho = match opened_chirho {
        Ok(engine_chirho) => engine_chirho,
        // A typed failure (e.g. a torn GENESIS — op 0) is a lawful outcome, not a corruption.
        Err(JournalErrorChirho::TornTailChirho) | Err(JournalErrorChirho::StorageChirho { .. }) => {
            return true
        }
        Err(_) => return false,
    };
    if !is_valid_scenario_prefix_chirho(&engine_chirho) {
        return false;
    }
    // Continuity: the recovered journal must accept new work (proves it is not wedged).
    let expected_next_chirho = engine_chirho.tail_chirho().0 + 1;
    recovery_views_chirho.clock_chirho.tick_chirho();
    match engine_chirho.append_chirho(mint_chirho(1, "idem-fuzz-post-chirho")) {
        Ok(receipt_chirho) => receipt_chirho.seq_chirho == expected_next_chirho,
        Err(_) => false,
    }
}

#[path = "fuzz_and_admission_tests_chirho.rs"]
mod fuzz_and_admission_tests_chirho;

#[path = "recovery_tests_chirho.rs"]
mod recovery_tests_chirho;
