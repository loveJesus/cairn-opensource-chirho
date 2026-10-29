// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::reconciliation_witness_tests_chirho::{
    digest_chirho, epoch_first_evidence_chirho, open_storage_chirho, ClosedGd7IntentVerifierChirho,
    ClosedGd7TerminalVerifierChirho, FakeGd7ControlSignerChirho, FakeWinnerLedgerSignerChirho,
    FakeWinnerLedgerVerifierOnlyChirho, ObservedTailAuthorityChirho,
    ObservedTailKindRegistryChirho, ObservedTailMembershipChirho,
};
use crate::reconciliation_chirho::{
    drive_authenticated_losing_manifest_page_chirho,
    ensure_authenticated_deposed_fork_observed_held_chirho, gd7_losing_manifest_page_path_chirho,
    gd7_reconciliation_plan_page_path_chirho, Gd7ForkCoordinateChirho,
    Gd7JournalTailCoordinateChirho, Gd7ManifestPageBudgetChirho, Gd7ManifestPageDriveOutcomeChirho,
    Gd7ManifestRefusalChirho, Gd7ObservedHeldOutcomeChirho, Gd7PlanPageDriveOutcomeChirho,
    Gd7PlanRefusalChirho, Gd7ReconciliationIdentityChirho, Gd7ReconciliationPhaseChirho,
    Gd7WinnerWitnessReaderChirho, Gd7WinnerWitnessRefusalChirho, Gd7WinnerWitnessStoreChirho,
};
use crate::resident_authority_chirho::ResidentGd7PlanPortsChirho;
use crate::SystemLedgerClockChirho;
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, JournalPortsChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, ClusterIdChirho, DigestChirho};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::LogIdChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::fs;

#[test]
fn authenticated_observation_drives_restart_stable_bounded_manifest_chirho() {
    let (root_chirho, storage_chirho) =
        open_storage_chirho("gd7-authenticated-deposed-observation-chirho");
    let intent_verifier_chirho = ClosedGd7IntentVerifierChirho;
    let terminal_verifier_chirho = ClosedGd7TerminalVerifierChirho;
    let ledger_signer_chirho = FakeWinnerLedgerSignerChirho::new_chirho(0x56);
    let clock_chirho = SystemLedgerClockChirho;
    let membership_chirho = ObservedTailMembershipChirho;
    let kind_registry_chirho = ObservedTailKindRegistryChirho;
    let authority_chirho = ObservedTailAuthorityChirho;
    let journal_ports_chirho = || JournalPortsChirho {
        storage_chirho: &storage_chirho,
        signer_chirho: &ledger_signer_chirho,
        clock_chirho: &clock_chirho,
        membership_chirho: &membership_chirho,
        kind_registry_chirho: &kind_registry_chirho,
        authority_chirho: &authority_chirho,
    };
    let losing_path_chirho = cairn_ledger_log_chirho::ports_chirho::StoragePathChirho::new_chirho(
        "journals-chirho/deposed-chirho.jsonl",
    );
    let losing_cluster_chirho = ClusterIdChirho("gd7-deposed-cluster-chirho".to_owned());
    let mut losing_journal_chirho = LedgerJournalChirho::create_chirho(
        journal_ports_chirho(),
        losing_path_chirho.clone(),
        losing_cluster_chirho.clone(),
        0,
    )
    .unwrap();
    let losing_genesis_chirho = losing_journal_chirho.genesis_digest_chirho().clone();
    losing_journal_chirho
        .append_chirho(AppendRequestChirho {
            op_chirho: LedgerOpChirho::MintChirho {
                authority_evidence_chirho: DigestChirho(digest_chirho('7')),
            },
            legs_chirho: vec![AppendLegRequestChirho {
                account_chirho: LogIdChirho::new_chirho(
                    "gd7-deposed-owner-chirho",
                    "gd7-observed-kind-chirho",
                ),
                kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(digest_chirho('8'))),
                delta_chirho: LegDeltaChirho::CreditChirho,
                amount_chirho: 10,
                counterpart_chirho: None,
            }],
            idempotency_key_chirho: "gd7-deposed-mint-chirho".to_owned(),
            provenance_chirho: None,
            attribution_chirho: AttributionChirho::PlatformChirho,
        })
        .unwrap();
    for (record_number_chirho, evidence_nibble_chirho) in [(2, '9'), (3, 'a')] {
        losing_journal_chirho
            .append_chirho(AppendRequestChirho {
                op_chirho: LedgerOpChirho::MintChirho {
                    authority_evidence_chirho: DigestChirho(digest_chirho(evidence_nibble_chirho)),
                },
                legs_chirho: vec![AppendLegRequestChirho {
                    account_chirho: LogIdChirho::new_chirho(
                        "gd7-deposed-owner-chirho",
                        "gd7-observed-kind-chirho",
                    ),
                    kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(digest_chirho('8'))),
                    delta_chirho: LegDeltaChirho::CreditChirho,
                    amount_chirho: 10,
                    counterpart_chirho: None,
                }],
                idempotency_key_chirho: format!("gd7-deposed-mint-{record_number_chirho}-chirho"),
                provenance_chirho: None,
                attribution_chirho: AttributionChirho::PlatformChirho,
            })
            .unwrap();
    }
    let verified_losing_tail_chirho = losing_journal_chirho.verified_losing_tail_chirho();

    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "gd7-observed-held-tenant-chirho".to_owned(),
    };
    let mut identity_chirho = Gd7ReconciliationIdentityChirho {
        consistency_group_digest_chirho: consistency_group_digest_chirho(&group_chirho).unwrap(),
        winner_node_chirho: digest_chirho('a'),
        held_node_chirho: digest_chirho('b'),
        winner_term_chirho: 1,
        losing_term_chirho: 0,
        winner_journal_genesis_digest_chirho: losing_genesis_chirho.0.clone(),
        winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(1, 0).unwrap(),
            seq_chirho: 1,
            record_digest_chirho: digest_chirho('3'),
        },
        fork_chirho: Gd7ForkCoordinateChirho {
            epoch_chirho: 0,
            seq_chirho: 0,
            record_digest_chirho: losing_genesis_chirho.0.clone(),
        },
        losing_journal_genesis_digest_chirho: losing_genesis_chirho.0.clone(),
        losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: verified_losing_tail_chirho.record_epoch_chirho(),
            seq_chirho: verified_losing_tail_chirho.coordinate_chirho().seq_chirho(),
            record_digest_chirho: verified_losing_tail_chirho
                .coordinate_chirho()
                .record_digest_chirho()
                .0
                .clone(),
        },
    };
    let winner_control_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.winner_node_chirho.clone(), 0x46);
    let held_control_chirho =
        FakeGd7ControlSignerChirho::new_chirho(identity_chirho.held_node_chirho.clone(), 0x47);
    let resident_plan_ports_chirho = ResidentGd7PlanPortsChirho::new_chirho(
        &storage_chirho,
        &root_chirho,
        &held_control_chirho,
        &ledger_signer_chirho,
        &intent_verifier_chirho,
        &terminal_verifier_chirho,
        None,
    );
    let winner_evidence_chirho = epoch_first_evidence_chirho(
        &ledger_signer_chirho,
        1,
        0,
        0,
        0,
        0,
        &losing_genesis_chirho.0,
    );
    let winner_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
        &storage_chirho,
        &winner_control_chirho,
        &ledger_signer_chirho,
    );
    let winner_index_chirho = winner_store_chirho
        .ensure_winner_first_record_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            identity_chirho.winner_term_chirho,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            &winner_evidence_chirho,
        )
        .unwrap();
    identity_chirho.winner_journal_tail_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: winner_index_chirho
            .index_chirho()
            .first_record_chirho
            .epoch_chirho,
        seq_chirho: winner_index_chirho
            .index_chirho()
            .first_record_chirho
            .seq_chirho,
        record_digest_chirho: winner_index_chirho
            .index_chirho()
            .first_record_digest_chirho
            .clone(),
    };
    let winner_witness_chirho = winner_store_chirho
        .seal_winner_fork_witness_chirho(identity_chirho.clone(), &winner_index_chirho)
        .unwrap();
    let wrong_key_verifier_chirho =
        FakeWinnerLedgerVerifierOnlyChirho::new_chirho("winner-ledger-key-chirho", 0x57);
    assert_eq!(
        Gd7WinnerWitnessReaderChirho::new_chirho(
            &storage_chirho,
            &winner_control_chirho,
            &wrong_key_verifier_chirho,
        )
        .load_authenticated_deposed_fork_observation_chirho(
            &identity_chirho,
            &verified_losing_tail_chirho,
        )
        .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::InvalidLedgerSignatureChirho
    );
    let wrong_label_verifier_chirho =
        FakeWinnerLedgerVerifierOnlyChirho::new_chirho("wrong-ledger-key-chirho", 0x56);
    assert_eq!(
        Gd7WinnerWitnessReaderChirho::new_chirho(
            &storage_chirho,
            &winner_control_chirho,
            &wrong_label_verifier_chirho,
        )
        .load_authenticated_deposed_fork_observation_chirho(
            &identity_chirho,
            &verified_losing_tail_chirho,
        )
        .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::WrongIndexCoordinateChirho
    );
    let winner_ledger_verifier_chirho =
        FakeWinnerLedgerVerifierOnlyChirho::new_chirho("winner-ledger-key-chirho", 0x56);
    let winner_reader_chirho = Gd7WinnerWitnessReaderChirho::new_chirho(
        &storage_chirho,
        &winner_control_chirho,
        &winner_ledger_verifier_chirho,
    );
    let observation_chirho = winner_reader_chirho
        .load_authenticated_deposed_fork_observation_chirho(
            &identity_chirho,
            &verified_losing_tail_chirho,
        )
        .unwrap();
    let installed_chirho = ensure_authenticated_deposed_fork_observed_held_chirho(
        &storage_chirho,
        &held_control_chirho,
        &observation_chirho,
    )
    .unwrap();
    let Gd7ObservedHeldOutcomeChirho::InstalledChirho(installed_chirho) = installed_chirho else {
        panic!("first authenticated observation must install the held checkpoint");
    };
    assert_eq!(
        installed_chirho
            .checkpoint_chirho
            .winner_fork_witness_object_digest_chirho,
        winner_witness_chirho.object_digest_chirho()
    );
    assert!(matches!(
        ensure_authenticated_deposed_fork_observed_held_chirho(
            &storage_chirho,
            &held_control_chirho,
            &observation_chirho,
        )
        .unwrap(),
        Gd7ObservedHeldOutcomeChirho::AlreadyObservedChirho(_)
    ));

    let manifest_budget_chirho =
        Gd7ManifestPageBudgetChirho::new_chirho(1, MAX_LOSING_SUFFIX_PAGE_BYTES_CHIRHO);
    let observed_checkpoint_ref_chirho = installed_chirho.checkpoint_ref_chirho.clone();
    let first_drive_chirho = drive_authenticated_losing_manifest_page_chirho(
        &storage_chirho,
        &held_control_chirho,
        &losing_journal_chirho,
        &observation_chirho,
        &observed_checkpoint_ref_chirho,
        manifest_budget_chirho,
    )
    .unwrap();
    let Gd7ManifestPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: first_checkpoint_chirho,
        manifest_page_chirho: first_page_chirho,
    } = first_drive_chirho
    else {
        panic!("the first bounded manifest page must advance the held checkpoint");
    };
    assert_eq!(
        first_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_chirho()
            .seq_chirho,
        3
    );
    assert_eq!(
        first_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_chirho()
            .idempotency_key_chirho,
        "gd7-deposed-mint-3-chirho"
    );
    assert!(matches!(
        first_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_chirho()
            .op_chirho,
        LedgerOpChirho::MintChirho { .. }
    ));
    assert_eq!(first_page_chirho.page_chirho().page_index_chirho(), 0);
    assert!(first_page_chirho
        .page_chirho()
        .newer_manifest_page_ref_chirho()
        .is_none());
    assert!(!first_page_chirho.page_chirho().reached_anchor_chirho());
    assert_eq!(
        first_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_page_count_chirho,
        1
    );
    assert_eq!(
        first_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_head_ref_chirho
            .as_deref(),
        Some(first_page_chirho.object_digest_chirho())
    );
    assert_eq!(
        first_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_record_count_chirho,
        1
    );
    assert_eq!(
        first_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .effect_obligation_count_chirho,
        0,
        "manifesting preserves evidence but grants no compensation authority"
    );
    assert!(first_checkpoint_chirho
        .checkpoint_chirho
        .state_chirho
        .cursor_object_ref_chirho
        .is_some());
    assert_eq!(
        drive_authenticated_losing_manifest_page_chirho(
            &storage_chirho,
            &held_control_chirho,
            &losing_journal_chirho,
            &observation_chirho,
            &observed_checkpoint_ref_chirho,
            manifest_budget_chirho,
        )
        .unwrap_err(),
        Gd7ManifestRefusalChirho::StaleCheckpointChirho,
        "a lost response must not let an old checkpoint consume the next page"
    );
    assert!(matches!(
        drive_authenticated_losing_manifest_page_chirho(
            &storage_chirho,
            &held_control_chirho,
            &losing_journal_chirho,
            &observation_chirho,
            &first_checkpoint_chirho.checkpoint_ref_chirho,
            manifest_budget_chirho,
        )
        .unwrap(),
        Gd7ManifestPageDriveOutcomeChirho::AwaitingPlanReductionChirho(_)
    ));
    let first_page_path_chirho =
        gd7_losing_manifest_page_path_chirho(first_page_chirho.object_digest_chirho()).unwrap();
    let first_page_bytes_chirho = storage_chirho
        .read_all_chirho(&first_page_path_chirho)
        .unwrap()
        .unwrap();
    let mut tampered_page_bytes_chirho = first_page_bytes_chirho.clone();
    tampered_page_bytes_chirho[0] ^= 1;
    storage_chirho
        .atomic_write_chirho(&first_page_path_chirho, &tampered_page_bytes_chirho)
        .unwrap();
    assert_eq!(
        resident_plan_ports_chirho
            .drive_chirho(
                &observation_chirho,
                &first_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::ManifestChirho(Gd7ManifestRefusalChirho::ObjectDigestMismatchChirho),
        "plan reduction must re-authenticate its exact manifest page"
    );
    storage_chirho
        .atomic_write_chirho(&first_page_path_chirho, &first_page_bytes_chirho)
        .unwrap();
    let first_plan_drive_chirho = resident_plan_ports_chirho
        .drive_chirho(
            &observation_chirho,
            &first_checkpoint_chirho.checkpoint_ref_chirho,
        )
        .unwrap();
    let Gd7PlanPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: first_plan_checkpoint_chirho,
        plan_page_chirho: first_plan_page_chirho,
    } = first_plan_drive_chirho
    else {
        panic!("the first manifest page must reduce into one bounded plan page");
    };
    assert_eq!(first_plan_page_chirho.page_chirho().page_index_chirho(), 0);
    assert!(first_plan_page_chirho
        .page_chirho()
        .obligations_newest_first_chirho()
        .is_empty());
    assert_eq!(
        first_plan_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .plan_page_count_chirho,
        1
    );
    assert_eq!(
        first_plan_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .effect_obligation_count_chirho,
        0
    );

    storage_chirho
        .atomic_write_chirho(&first_page_path_chirho, &tampered_page_bytes_chirho)
        .unwrap();
    assert_eq!(
        drive_authenticated_losing_manifest_page_chirho(
            &storage_chirho,
            &held_control_chirho,
            &losing_journal_chirho,
            &observation_chirho,
            &first_plan_checkpoint_chirho.checkpoint_ref_chirho,
            manifest_budget_chirho,
        )
        .unwrap_err(),
        Gd7ManifestRefusalChirho::ObjectDigestMismatchChirho,
        "manifest continuation must re-authenticate the prior manifest page"
    );
    storage_chirho
        .atomic_write_chirho(&first_page_path_chirho, &first_page_bytes_chirho)
        .unwrap();

    drop(losing_journal_chirho);
    let losing_journal_chirho = LedgerJournalChirho::open_chirho(
        journal_ports_chirho(),
        losing_path_chirho,
        &losing_cluster_chirho,
    )
    .unwrap();
    let second_drive_chirho = drive_authenticated_losing_manifest_page_chirho(
        &storage_chirho,
        &held_control_chirho,
        &losing_journal_chirho,
        &observation_chirho,
        &first_plan_checkpoint_chirho.checkpoint_ref_chirho,
        manifest_budget_chirho,
    )
    .unwrap();
    let Gd7ManifestPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: second_checkpoint_chirho,
        manifest_page_chirho: second_page_chirho,
    } = second_drive_chirho
    else {
        panic!("the reopened journal must resume from the durable manifest cursor");
    };
    assert_eq!(
        second_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_chirho()
            .seq_chirho,
        2
    );
    assert_eq!(second_page_chirho.page_chirho().page_index_chirho(), 1);
    assert_eq!(
        second_page_chirho
            .page_chirho()
            .newer_manifest_page_ref_chirho(),
        Some(first_page_chirho.object_digest_chirho())
    );
    assert_eq!(
        first_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_chirho()
            .prev_chirho
            .0,
        second_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_digest_chirho()
    );

    let first_plan_path_chirho =
        gd7_reconciliation_plan_page_path_chirho(first_plan_page_chirho.object_digest_chirho())
            .unwrap();
    let first_plan_bytes_chirho = storage_chirho
        .read_all_chirho(&first_plan_path_chirho)
        .unwrap()
        .unwrap();
    let mut tampered_plan_bytes_chirho = first_plan_bytes_chirho.clone();
    tampered_plan_bytes_chirho[0] ^= 1;
    storage_chirho
        .atomic_write_chirho(&first_plan_path_chirho, &tampered_plan_bytes_chirho)
        .unwrap();
    assert_eq!(
        resident_plan_ports_chirho
            .drive_chirho(
                &observation_chirho,
                &second_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::ObjectDigestMismatchChirho,
        "cross-page reduction must re-authenticate the prior inductive plan page"
    );
    storage_chirho
        .atomic_write_chirho(&first_plan_path_chirho, &first_plan_bytes_chirho)
        .unwrap();
    let second_plan_drive_chirho = resident_plan_ports_chirho
        .drive_chirho(
            &observation_chirho,
            &second_checkpoint_chirho.checkpoint_ref_chirho,
        )
        .unwrap();
    let Gd7PlanPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: second_plan_checkpoint_chirho,
        plan_page_chirho: second_plan_page_chirho,
    } = second_plan_drive_chirho
    else {
        panic!("the second manifest page must extend the bounded plan chain");
    };
    assert_eq!(second_plan_page_chirho.page_chirho().page_index_chirho(), 1);
    assert_eq!(
        second_plan_page_chirho
            .page_chirho()
            .newer_plan_page_ref_chirho(),
        Some(first_plan_page_chirho.object_digest_chirho())
    );

    let third_drive_chirho = drive_authenticated_losing_manifest_page_chirho(
        &storage_chirho,
        &held_control_chirho,
        &losing_journal_chirho,
        &observation_chirho,
        &second_plan_checkpoint_chirho.checkpoint_ref_chirho,
        manifest_budget_chirho,
    )
    .unwrap();
    let Gd7ManifestPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: final_manifest_checkpoint_chirho,
        manifest_page_chirho: final_page_chirho,
    } = third_drive_chirho
    else {
        panic!("the final bounded manifest page must reach the exact fork anchor");
    };
    assert_eq!(
        final_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_chirho()
            .seq_chirho,
        1
    );
    assert_eq!(final_page_chirho.page_chirho().page_index_chirho(), 2);
    assert_eq!(
        final_page_chirho
            .page_chirho()
            .newer_manifest_page_ref_chirho(),
        Some(second_page_chirho.object_digest_chirho())
    );
    assert_eq!(
        second_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_chirho()
            .prev_chirho
            .0,
        final_page_chirho
            .page_chirho()
            .records_newest_first_chirho()[0]
            .record_digest_chirho()
    );
    assert!(final_page_chirho.page_chirho().reached_anchor_chirho());
    assert_eq!(
        final_manifest_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .phase_chirho,
        Gd7ReconciliationPhaseChirho::ManifestingChirho
    );
    assert_eq!(
        final_manifest_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_page_count_chirho,
        3
    );
    assert_eq!(
        final_manifest_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_head_ref_chirho
            .as_deref(),
        Some(final_page_chirho.object_digest_chirho())
    );
    assert_eq!(
        final_manifest_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .manifest_record_count_chirho,
        3
    );
    assert_eq!(
        final_manifest_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .effect_obligation_count_chirho,
        0
    );
    assert!(final_manifest_checkpoint_chirho
        .checkpoint_chirho
        .state_chirho
        .cursor_object_ref_chirho
        .is_none());
    assert_eq!(
        resident_plan_ports_chirho
            .verify_sealed_chirho(
                &observation_chirho,
                &final_manifest_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::InvalidPhaseChirho,
        "a complete manifest without its sealed plan is not adoption authority"
    );
    let final_plan_drive_chirho = resident_plan_ports_chirho
        .drive_chirho(
            &observation_chirho,
            &final_manifest_checkpoint_chirho.checkpoint_ref_chirho,
        )
        .unwrap();
    let Gd7PlanPageDriveOutcomeChirho::CommittedChirho {
        checkpoint_chirho: sealed_checkpoint_chirho,
        plan_page_chirho: sealed_plan_page_chirho,
    } = final_plan_drive_chirho
    else {
        panic!("the anchor manifest page must seal the inductive plan");
    };
    assert!(sealed_plan_page_chirho
        .page_chirho()
        .reached_anchor_chirho());
    assert_eq!(
        sealed_plan_page_chirho
            .page_chirho()
            .cumulative_manifest_page_count_chirho,
        3
    );
    assert_eq!(
        sealed_plan_page_chirho
            .page_chirho()
            .cumulative_manifest_record_count_chirho,
        3
    );
    assert_eq!(
        sealed_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .phase_chirho,
        Gd7ReconciliationPhaseChirho::PlanSealedChirho
    );
    assert_eq!(
        sealed_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .plan_page_count_chirho,
        3
    );
    assert_eq!(
        sealed_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .sealed_plan_ref_chirho
            .as_deref(),
        Some(sealed_plan_page_chirho.object_digest_chirho())
    );
    assert_eq!(
        sealed_checkpoint_chirho
            .checkpoint_chirho
            .state_chirho
            .effect_obligation_count_chirho,
        0
    );
    let sealed_proof_chirho = resident_plan_ports_chirho
        .verify_sealed_chirho(
            &observation_chirho,
            &sealed_checkpoint_chirho.checkpoint_ref_chirho,
        )
        .unwrap();
    assert_eq!(
        sealed_proof_chirho.checkpoint_ref_chirho(),
        sealed_checkpoint_chirho.checkpoint_ref_chirho
    );
    assert_eq!(
        sealed_proof_chirho.sealed_plan_ref_chirho(),
        sealed_plan_page_chirho.object_digest_chirho()
    );
    assert_eq!(sealed_proof_chirho.winner_term_chirho(), 1);
    assert_eq!(sealed_proof_chirho.plan_page_count_chirho(), 3);
    assert_eq!(sealed_proof_chirho.manifest_record_count_chirho(), 3);
    assert_eq!(sealed_proof_chirho.effect_obligation_count_chirho(), 0);
    let rejecting_losing_verifier_chirho =
        FakeWinnerLedgerVerifierOnlyChirho::new_chirho("rejecting-loser-chirho", 0x57);
    let rejecting_plan_ports_chirho = ResidentGd7PlanPortsChirho::new_chirho(
        &storage_chirho,
        &root_chirho,
        &held_control_chirho,
        &rejecting_losing_verifier_chirho,
        &intent_verifier_chirho,
        &terminal_verifier_chirho,
        None,
    );
    assert_eq!(
        rejecting_plan_ports_chirho
            .verify_sealed_chirho(
                &observation_chirho,
                &sealed_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::InvalidLosingRecordSignatureChirho,
        "whole-plan verification must reverify each manifest record under the losing journal key"
    );
    assert_eq!(
        resident_plan_ports_chirho
            .verify_sealed_chirho(
                &observation_chirho,
                &final_manifest_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::StaleCheckpointChirho
    );

    storage_chirho
        .atomic_write_chirho(&first_plan_path_chirho, &tampered_plan_bytes_chirho)
        .unwrap();
    assert_eq!(
        resident_plan_ports_chirho
            .verify_sealed_chirho(
                &observation_chirho,
                &sealed_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::ObjectDigestMismatchChirho,
        "whole-plan verification must reach and re-authenticate an intermediate page"
    );
    storage_chirho
        .atomic_write_chirho(&first_plan_path_chirho, &first_plan_bytes_chirho)
        .unwrap();
    storage_chirho
        .atomic_write_chirho(&first_page_path_chirho, &tampered_page_bytes_chirho)
        .unwrap();
    assert_eq!(
        resident_plan_ports_chirho
            .verify_sealed_chirho(
                &observation_chirho,
                &sealed_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::ManifestChirho(Gd7ManifestRefusalChirho::ObjectDigestMismatchChirho),
        "whole-plan verification must reach and re-authenticate the linked manifest chain"
    );
    storage_chirho
        .atomic_write_chirho(&first_page_path_chirho, &first_page_bytes_chirho)
        .unwrap();
    assert!(matches!(
        drive_authenticated_losing_manifest_page_chirho(
            &storage_chirho,
            &held_control_chirho,
            &losing_journal_chirho,
            &observation_chirho,
            &sealed_checkpoint_chirho.checkpoint_ref_chirho,
            manifest_budget_chirho,
        )
        .unwrap(),
        Gd7ManifestPageDriveOutcomeChirho::AlreadyAdvancedChirho(_)
    ));
    let sealed_plan_path_chirho =
        gd7_reconciliation_plan_page_path_chirho(sealed_plan_page_chirho.object_digest_chirho())
            .unwrap();
    let sealed_plan_bytes_chirho = storage_chirho
        .read_all_chirho(&sealed_plan_path_chirho)
        .unwrap()
        .unwrap();
    let mut tampered_sealed_plan_bytes_chirho = sealed_plan_bytes_chirho.clone();
    tampered_sealed_plan_bytes_chirho[0] ^= 1;
    storage_chirho
        .atomic_write_chirho(&sealed_plan_path_chirho, &tampered_sealed_plan_bytes_chirho)
        .unwrap();
    assert_eq!(
        resident_plan_ports_chirho
            .drive_chirho(
                &observation_chirho,
                &sealed_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap_err(),
        Gd7PlanRefusalChirho::ObjectDigestMismatchChirho,
        "sealed retries must re-authenticate the exact sealed plan head"
    );
    storage_chirho
        .atomic_write_chirho(&sealed_plan_path_chirho, &sealed_plan_bytes_chirho)
        .unwrap();
    assert!(matches!(
        resident_plan_ports_chirho
            .drive_chirho(
                &observation_chirho,
                &sealed_checkpoint_chirho.checkpoint_ref_chirho,
            )
            .unwrap(),
        Gd7PlanPageDriveOutcomeChirho::AlreadyAdvancedChirho(_)
    ));

    let mut invented_tail_identity_chirho = identity_chirho;
    invented_tail_identity_chirho
        .losing_journal_tail_chirho
        .record_digest_chirho = digest_chirho('e');
    assert_eq!(
        winner_reader_chirho
            .load_authenticated_deposed_fork_observation_chirho(
                &invented_tail_identity_chirho,
                &verified_losing_tail_chirho,
            )
            .unwrap_err(),
        Gd7WinnerWitnessRefusalChirho::WrongLosingTailChirho
    );
    fs::remove_dir_all(root_chirho).unwrap();
}
