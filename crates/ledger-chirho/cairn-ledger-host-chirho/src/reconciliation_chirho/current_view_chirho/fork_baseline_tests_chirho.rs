// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::winner_handoff_tests_chirho::{
    durable_commit_chirho, handoff_fixture_for_cut_chirho,
    InstalledAtomicWriteSyncFaultStorageChirho, TestWinnerHandoffSignerChirho,
};
use super::*;
use crate::reconciliation_chirho::{
    Gd7ForkCoordinateChirho, Gd7ReconciliationCheckpointChirho,
    Gd7ReconciliationCheckpointStateChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationPhaseChirho, GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO,
};
use crate::SystemLedgerClockChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, ExpectedLedgerGenesisChirho, JournalPortsChirho,
    LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};

struct ForkBaselineMembershipChirho;

impl MembershipViewChirho for ForkBaselineMembershipChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

struct ForkBaselineKindRegistryChirho;

impl KindRegistryViewChirho for ForkBaselineKindRegistryChirho {
    fn resolve_chirho(&self, _policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        KindResolutionChirho::CurrentChirho(KindPolicyViewChirho {
            kind_id_chirho: AssetKindIdChirho("gd7-fork-baseline-kind-chirho".to_owned()),
            mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                max_supply_chirho: Some(10_000),
            },
            rounding_chirho: RoundingChirho::ExactChirho,
            settlement_owner_chirho: None,
            idempotency_window_chirho: None,
        })
    }
}

struct ForkBaselineAuthorityChirho;

impl AuthorityVerifierViewChirho for ForkBaselineAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::VerifiedChirho
    }
}

fn fork_baseline_append_chirho(index_chirho: usize) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho("5".repeat(64)),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho(
                format!("gd7-fork-baseline-owner-{index_chirho:04}-chirho"),
                "gd7-fork-baseline-kind-chirho",
            ),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho("6".repeat(64))),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 1,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: format!("gd7-fork-baseline-{index_chirho:04}-chirho"),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
    }
}

fn signed_plan_checkpoint_chirho(
    identity_chirho: Gd7ReconciliationIdentityChirho,
    held_signer_chirho: &TestWinnerHandoffSignerChirho,
) -> (String, Gd7ReconciliationCheckpointChirho) {
    let sealed_plan_ref_chirho = "7".repeat(64);
    let mut checkpoint_chirho = Gd7ReconciliationCheckpointChirho {
        schema_chirho: GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
        identity_chirho,
        winner_fork_witness_object_digest_chirho: "8".repeat(64),
        state_chirho: Gd7ReconciliationCheckpointStateChirho {
            phase_chirho: Gd7ReconciliationPhaseChirho::PlanSealedChirho,
            transition_seq_chirho: 2,
            previous_checkpoint_ref_chirho: Some("9".repeat(64)),
            manifest_head_ref_chirho: Some("a".repeat(64)),
            manifest_page_count_chirho: 1,
            manifest_record_count_chirho: 1,
            plan_head_ref_chirho: Some(sealed_plan_ref_chirho.clone()),
            plan_page_count_chirho: 1,
            sealed_plan_ref_chirho: Some(sealed_plan_ref_chirho),
            effect_obligation_count_chirho: 0,
            cursor_object_ref_chirho: None,
            adoption_binding_chirho: None,
        },
        key_id_chirho: Gd7ReconciliationVerifierPortChirho::key_id_chirho(held_signer_chirho),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = serde_json::to_string(&checkpoint_chirho).unwrap();
    checkpoint_chirho.sig_chirho =
        Gd7ReconciliationSignerPortChirho::sign_chirho(held_signer_chirho, &unsigned_chirho)
            .unwrap();
    let bytes_chirho = serde_json::to_vec(&checkpoint_chirho).unwrap();
    (
        blake3::hash(&bytes_chirho).to_hex().to_string(),
        checkpoint_chirho,
    )
}

pub(super) struct ForkBaselineTestContextChirho<'fixture_chirho> {
    pub(super) storage_chirho: &'fixture_chirho InstalledAtomicWriteSyncFaultStorageChirho,
    pub(super) winner_signer_chirho: &'fixture_chirho TestWinnerHandoffSignerChirho,
    pub(super) winner_journal_signer_chirho: &'fixture_chirho TestWinnerHandoffSignerChirho,
    pub(super) held_signer_chirho: &'fixture_chirho TestWinnerHandoffSignerChirho,
    pub(super) store_chirho: &'fixture_chirho Gd7WinnerHandoffStoreChirho<'fixture_chirho>,
    pub(super) winner_journal_chirho: &'fixture_chirho LedgerJournalChirho<'fixture_chirho>,
    pub(super) losing_journal_chirho: &'fixture_chirho LedgerJournalChirho<'fixture_chirho>,
    pub(super) expected_genesis_chirho: &'fixture_chirho ExpectedLedgerGenesisChirho,
    pub(super) journal_ports_chirho: JournalPortsChirho<'fixture_chirho>,
    pub(super) journal_path_chirho: &'fixture_chirho StoragePathChirho,
    pub(super) cluster_chirho: &'fixture_chirho ClusterIdChirho,
    pub(super) plan_checkpoint_ref_chirho: &'fixture_chirho str,
    pub(super) plan_checkpoint_chirho: &'fixture_chirho Gd7ReconciliationCheckpointChirho,
    pub(super) accepted_attempt_digest_chirho: &'fixture_chirho str,
}

#[derive(Clone, Copy)]
pub(super) enum ForkBaselineTailBindingChirho {
    ActualChirho,
    WrongSequenceChirho,
}

pub(super) fn with_fork_baseline_fixture_chirho(
    prefix_account_count_chirho: usize,
    accept_handoff_chirho: bool,
    tail_binding_chirho: ForkBaselineTailBindingChirho,
    test_chirho: impl FnOnce(ForkBaselineTestContextChirho<'_>),
) {
    assert!(prefix_account_count_chirho > 0);
    let storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::new_chirho(false);
    let winner_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("a".repeat(64));
    let winner_journal_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho(
        "journal-chirho:shared-winner-journal-secret-chirho".to_owned(),
    );
    let held_signer_chirho = TestWinnerHandoffSignerChirho::new_chirho("b".repeat(64));
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = ForkBaselineMembershipChirho;
    let kind_registry_chirho = ForkBaselineKindRegistryChirho;
    let authority_chirho = ForkBaselineAuthorityChirho;
    let journal_ports_chirho = || JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &winner_journal_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let journal_path_chirho =
        StoragePathChirho::new_chirho("journals-chirho/gd7-fork-baseline-chirho.jsonl");
    let cluster_chirho = ClusterIdChirho("gd7-fork-baseline-cluster-chirho".to_owned());
    let fork_epoch_chirho = compose_writer_epoch_chirho(6, 0).unwrap();
    let prepared_genesis_chirho = LedgerJournalChirho::prepare_genesis_chirho(
        journal_ports_chirho(),
        cluster_chirho.clone(),
        fork_epoch_chirho,
    )
    .unwrap();
    let expected_genesis_chirho = ExpectedLedgerGenesisChirho::from_verified_identity_chirho(
        prepared_genesis_chirho.canonical_line_chirho(),
        prepared_genesis_chirho.digest_chirho().clone(),
    )
    .unwrap();
    let mut winner_journal_chirho = LedgerJournalChirho::create_prepared_chirho(
        journal_ports_chirho(),
        journal_path_chirho.clone(),
        prepared_genesis_chirho,
    )
    .unwrap();
    let winner_genesis_chirho = winner_journal_chirho.genesis_digest_chirho().0.clone();
    let mut fork_receipt_chirho = None;
    for index_chirho in 0..prefix_account_count_chirho {
        fork_receipt_chirho = Some(
            winner_journal_chirho
                .append_chirho(fork_baseline_append_chirho(index_chirho))
                .unwrap(),
        );
    }
    let fork_receipt_chirho = fork_receipt_chirho.unwrap();
    let losing_storage_chirho = InstalledAtomicWriteSyncFaultStorageChirho::restore_chirho(
        storage_chirho.snapshot_chirho(),
        false,
    );
    let losing_journal_ports_chirho = || JournalPortsChirho {
        storage_chirho: &losing_storage_chirho,
        signer_chirho: &winner_journal_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let mut losing_journal_chirho = LedgerJournalChirho::open_chirho(
        losing_journal_ports_chirho(),
        journal_path_chirho.clone(),
        &cluster_chirho,
    )
    .unwrap();
    losing_journal_chirho
        .append_chirho(fork_baseline_append_chirho(
            prefix_account_count_chirho + 10_000,
        ))
        .unwrap();
    let losing_tail_chirho = losing_journal_chirho.verified_losing_tail_chirho();
    winner_journal_chirho
        .advance_epoch_chirho(compose_writer_epoch_chirho(7, 0).unwrap())
        .unwrap();
    winner_journal_chirho
        .append_chirho(fork_baseline_append_chirho(prefix_account_count_chirho))
        .unwrap();
    let winner_tail_chirho = winner_journal_chirho.verified_losing_tail_chirho();
    let mut winner_tail_coordinate_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: winner_tail_chirho.record_epoch_chirho(),
        seq_chirho: winner_tail_chirho.coordinate_chirho().seq_chirho(),
        record_digest_chirho: winner_tail_chirho
            .coordinate_chirho()
            .record_digest_chirho()
            .0
            .clone(),
    };
    if matches!(
        tail_binding_chirho,
        ForkBaselineTailBindingChirho::WrongSequenceChirho
    ) {
        winner_tail_coordinate_chirho.seq_chirho += 1;
    }
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/tmp/gd7-winner-handoff-chirho".to_owned(),
    };
    let identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: "a".repeat(64),
        held_node_chirho: "b".repeat(64),
        winner_term_chirho: 7,
        losing_term_chirho: 6,
        winner_journal_genesis_digest_chirho: winner_genesis_chirho.clone(),
        winner_journal_tail_chirho: winner_tail_coordinate_chirho,
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: fork_epoch_chirho,
            seq_chirho: fork_receipt_chirho.seq_chirho,
            record_digest_chirho: fork_receipt_chirho.record_digest_chirho.0.clone(),
        },
        losing_journal_genesis_digest_chirho: winner_genesis_chirho.clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: losing_tail_chirho.record_epoch_chirho(),
            seq_chirho: losing_tail_chirho.coordinate_chirho().seq_chirho(),
            record_digest_chirho: losing_tail_chirho
                .coordinate_chirho()
                .record_digest_chirho()
                .0
                .clone(),
        },
    };
    let (plan_checkpoint_ref_chirho, plan_checkpoint_chirho) =
        signed_plan_checkpoint_chirho(identity_chirho.clone(), &held_signer_chirho);
    let (group_digest_chirho, handoff_identity_chirho, challenge_bytes_chirho, inspection_chirho) =
        handoff_fixture_for_cut_chirho(
            plan_checkpoint_ref_chirho.clone(),
            winner_genesis_chirho,
            identity_chirho.winner_journal_tail_chirho.clone(),
        );
    let store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
        &storage_chirho,
        &winner_signer_chirho,
        group_digest_chirho,
        "a".repeat(64),
    )
    .unwrap();
    let preparing_chirho = durable_commit_chirho(
        store_chirho
            .commit_preparing_chirho(
                handoff_identity_chirho,
                &challenge_bytes_chirho,
                inspection_chirho,
                19,
            )
            .unwrap(),
    );
    if accept_handoff_chirho {
        durable_commit_chirho(
            store_chirho
                .commit_accepted_chirho(
                    &preparing_chirho.attempt_digest_chirho,
                    &preparing_chirho.checkpoint_ref_chirho,
                    20,
                )
                .unwrap(),
        );
    }
    test_chirho(ForkBaselineTestContextChirho {
        storage_chirho: &storage_chirho,
        winner_signer_chirho: &winner_signer_chirho,
        winner_journal_signer_chirho: &winner_journal_signer_chirho,
        held_signer_chirho: &held_signer_chirho,
        store_chirho: &store_chirho,
        winner_journal_chirho: &winner_journal_chirho,
        losing_journal_chirho: &losing_journal_chirho,
        expected_genesis_chirho: &expected_genesis_chirho,
        journal_ports_chirho: journal_ports_chirho(),
        journal_path_chirho: &journal_path_chirho,
        cluster_chirho: &cluster_chirho,
        plan_checkpoint_ref_chirho: &plan_checkpoint_ref_chirho,
        plan_checkpoint_chirho: &plan_checkpoint_chirho,
        accepted_attempt_digest_chirho: &preparing_chirho.attempt_digest_chirho,
    });
}

#[test]
fn accepted_handoff_stages_and_reverifies_two_fork_baseline_pages_chirho() {
    with_fork_baseline_fixture_chirho(
        GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO + 1,
        true,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let root_chirho = context_chirho
                .store_chirho
                .stage_accepted_fork_baseline_chirho(
                    context_chirho.plan_checkpoint_ref_chirho,
                    context_chirho.plan_checkpoint_chirho,
                    context_chirho.held_signer_chirho,
                    context_chirho.journal_ports_chirho,
                    context_chirho.journal_path_chirho,
                    context_chirho.cluster_chirho,
                )
                .unwrap();
            assert_eq!(root_chirho.root_chirho().page_count_chirho, 2);
            assert_eq!(
                root_chirho.root_chirho().account_count_chirho,
                u64::try_from(GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO + 1).unwrap()
            );
            let replayed_root_chirho = context_chirho
                .store_chirho
                .stage_accepted_fork_baseline_chirho(
                    context_chirho.plan_checkpoint_ref_chirho,
                    context_chirho.plan_checkpoint_chirho,
                    context_chirho.held_signer_chirho,
                    context_chirho.journal_ports_chirho,
                    context_chirho.journal_path_chirho,
                    context_chirho.cluster_chirho,
                )
                .unwrap();
            assert_eq!(
                replayed_root_chirho.object_digest_chirho(),
                root_chirho.object_digest_chirho(),
                "a lost response must recreate the exact immutable baseline root"
            );
            let baseline_chirho = verify_complete_gd7_fork_baseline_chirho(
                context_chirho.storage_chirho,
                root_chirho.object_digest_chirho(),
                &root_chirho.root_chirho().identity_chirho,
                context_chirho.winner_signer_chirho,
            )
            .unwrap();
            assert_eq!(
                baseline_chirho.head_states_chirho().len(),
                GD7_FORK_BASELINE_PAGE_ROWS_CHIRHO + 1
            );
            assert!(baseline_chirho
                .head_states_chirho()
                .values()
                .all(|post_chirho| post_chirho.credits_total_chirho == 1));

            let first_page_path_chirho = gd7_fork_baseline_page_path_chirho(
                root_chirho
                    .root_chirho()
                    .first_page_ref_chirho
                    .as_deref()
                    .unwrap(),
            )
            .unwrap();
            context_chirho
                .storage_chirho
                .atomic_write_chirho(&first_page_path_chirho, b"{}")
                .unwrap();
            assert!(matches!(
                verify_complete_gd7_fork_baseline_chirho(
                    context_chirho.storage_chirho,
                    root_chirho.object_digest_chirho(),
                    &root_chirho.root_chirho().identity_chirho,
                    context_chirho.winner_signer_chirho,
                ),
                Err(Gd7ForkBaselineRefusalChirho::ObjectDigestMismatchChirho)
            ));
        },
    );
}

#[test]
fn preparing_handoff_refuses_before_opening_the_winner_journal_chirho() {
    with_fork_baseline_fixture_chirho(
        1,
        false,
        ForkBaselineTailBindingChirho::ActualChirho,
        |context_chirho| {
            let missing_path_chirho =
                StoragePathChirho::new_chirho("journals-chirho/must-not-open-chirho.jsonl");
            assert_eq!(
                context_chirho
                    .store_chirho
                    .stage_accepted_fork_baseline_chirho(
                        context_chirho.plan_checkpoint_ref_chirho,
                        context_chirho.plan_checkpoint_chirho,
                        context_chirho.held_signer_chirho,
                        context_chirho.journal_ports_chirho,
                        &missing_path_chirho,
                        context_chirho.cluster_chirho,
                    )
                    .unwrap_err(),
                Gd7WinnerHandoffStoreRefusalChirho::InvalidTransitionChirho,
                "PreparingChirho must win before any source-journal refusal can be observed"
            );
        },
    );
}

#[test]
fn accepted_handoff_refuses_a_false_winner_tail_after_exact_fork_replay_chirho() {
    with_fork_baseline_fixture_chirho(
        1,
        true,
        ForkBaselineTailBindingChirho::WrongSequenceChirho,
        |context_chirho| {
            assert_eq!(
                context_chirho
                    .store_chirho
                    .stage_accepted_fork_baseline_chirho(
                        context_chirho.plan_checkpoint_ref_chirho,
                        context_chirho.plan_checkpoint_chirho,
                        context_chirho.held_signer_chirho,
                        context_chirho.journal_ports_chirho,
                        context_chirho.journal_path_chirho,
                        context_chirho.cluster_chirho,
                    )
                    .unwrap_err(),
                Gd7WinnerHandoffStoreRefusalChirho::ForkBaselineChirho(
                    Gd7ForkBaselineRefusalChirho::InvalidSourceBindingChirho,
                ),
                "a real fork cut with a false accepted tail must reach the outer source-binding refusal"
            );
        },
    );
}
