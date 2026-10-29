// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::command_dispatch_chirho::ResidentTenantMigrationAdmittedCommandChirho;
use super::super::mailbox_chirho::ResidentEffectJournalCommandChirho;
use super::super::tenant_migration_operation_chirho::unusable_destination_record_chirho;
use super::super::tenant_migration_operation_chirho::{
    ResidentTenantMigrationOperationCommandChirho, ResidentTenantMigrationOperationRefusalChirho,
};
use super::super::winner_handoff_chirho::ResidentGd7WinnerHandoffRuntimeChirho;
use super::{
    require_recovery_adoption_slot_chirho, ResidentAppendBarrierRefusalChirho,
    ResidentAppendBarrierRuntimeChirho,
};
use crate::reconciliation_chirho::{
    gd7_winner_handoff_attempt_digest_chirho, generate_gd7_winner_current_view_challenge_chirho,
    parse_canonical_gd7_winner_current_view_challenge_chirho, ExistingNodeGd7SignerChirho,
    Gd7HeldViewTransferIdentityChirho, Gd7JournalTailCoordinateChirho,
    Gd7ReconciliationSignerPortChirho, Gd7WinnerCurrentViewEvidenceChirho,
    Gd7WinnerCurrentViewInspectionChirho, Gd7WinnerHandoffAttemptIdentityChirho,
    Gd7WinnerHandoffPhaseChirho, Gd7WinnerHandoffStoreChirho, Gd7WinnerViewBundleRootChirho,
    GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO,
    GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO,
};
use crate::tests_chirho::{warm_single_node_elector_chirho, with_bound_resident_fixture_chirho};
use crate::ResidentLedgerAuthorityChirho;
use cairn_ledger_read_model_chirho::account_net_projection_fold_ref_chirho;
use cairn_ledger_tenant_migration_durable_chirho::{
    TenantMigrationCutClaimChirho, TenantMigrationStartupBarrierChirho, TenantMigrationStoreChirho,
};
use cairn_writer_elector_chirho::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::path::PathBuf;
use std::sync::mpsc::sync_channel;

struct Gd7PreparingFixtureChirho {
    attempt_identity_chirho: Gd7WinnerHandoffAttemptIdentityChirho,
    challenge_bytes_chirho: Vec<u8>,
    inspection_chirho: Gd7WinnerCurrentViewInspectionChirho,
}

fn digest_serialized_chirho<ValueChirho: serde::Serialize>(value_chirho: &ValueChirho) -> String {
    blake3::hash(&serde_json::to_vec(value_chirho).expect("serialize test value chirho"))
        .to_hex()
        .to_string()
}

fn gd7_preparing_fixture_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    winner_node_chirho: &NodeIdChirho,
    elector_chirho: &RaftWriterElectorChirho,
    signer_chirho: &ExistingNodeGd7SignerChirho,
) -> Gd7PreparingFixtureChirho {
    let group_digest_chirho = consistency_group_digest_chirho(group_chirho).unwrap();
    let held_node_chirho = NodeIdChirho("b".repeat(64));
    let winner_term_chirho = elector_chirho.leadership_chirho(group_chirho).term_chirho;
    let transfer_identity_chirho = Gd7HeldViewTransferIdentityChirho {
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        reconciliation_checkpoint_ref_chirho: "c".repeat(64),
        winner_node_chirho: winner_node_chirho.0.clone(),
        held_node_chirho: held_node_chirho.0.clone(),
        winner_term_chirho,
    };
    let transfer_identity_digest_chirho = digest_serialized_chirho(&transfer_identity_chirho);
    let issued_challenge_chirho = generate_gd7_winner_current_view_challenge_chirho(
        elector_chirho,
        group_chirho,
        winner_node_chirho,
        &held_node_chirho,
        &transfer_identity_digest_chirho,
    )
    .unwrap();
    let challenge_bytes_chirho = issued_challenge_chirho.canonical_bytes_chirho().unwrap();
    let challenge_chirho =
        parse_canonical_gd7_winner_current_view_challenge_chirho(&challenge_bytes_chirho).unwrap();
    let challenge_digest_chirho = challenge_chirho.digest_chirho().unwrap();
    let source_cut_chirho = Gd7JournalTailCoordinateChirho {
        epoch_chirho: compose_writer_epoch_chirho(winner_term_chirho, 1).unwrap(),
        seq_chirho: 0,
        record_digest_chirho: "e".repeat(64),
    };
    let bundle_root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: group_digest_chirho.clone(),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: "1".repeat(64),
        source_cut_chirho: source_cut_chirho.clone(),
        lowest_page_ref_chirho: None,
        page_count_chirho: 0,
        row_count_chirho: 0,
    };
    let bundle_root_digest_chirho = digest_serialized_chirho(&bundle_root_chirho);
    let mut evidence_chirho = Gd7WinnerCurrentViewEvidenceChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_EVIDENCE_SCHEMA_V1_CHIRHO.to_owned(),
        challenge_digest_chirho: challenge_digest_chirho.clone(),
        consistency_group_digest_chirho: group_digest_chirho,
        winner_node_chirho: winner_node_chirho.0.clone(),
        raft_term_chirho: winner_term_chirho,
        winner_process_generation_chirho: 1,
        winner_journal_genesis_digest_chirho: "1".repeat(64),
        latest_verified_journal_cut_chirho: source_cut_chirho,
        view_bundle_root_chirho: bundle_root_digest_chirho.clone(),
        key_id_chirho: winner_node_chirho.0.clone(),
        sig_chirho: String::new(),
    };
    evidence_chirho.sig_chirho = Gd7ReconciliationSignerPortChirho::sign_chirho(
        signer_chirho,
        std::str::from_utf8(&serde_json::to_vec(&evidence_chirho).unwrap()).unwrap(),
    )
    .unwrap();
    let evidence_digest_chirho = digest_serialized_chirho(&evidence_chirho);
    Gd7PreparingFixtureChirho {
        attempt_identity_chirho: Gd7WinnerHandoffAttemptIdentityChirho {
            held_transfer_identity_chirho: transfer_identity_chirho,
            held_transfer_checkpoint_ref_chirho: "4".repeat(64),
            expected_bundle_root_object_digest_chirho: bundle_root_digest_chirho.clone(),
            challenge_digest_chirho,
        },
        challenge_bytes_chirho,
        inspection_chirho: Gd7WinnerCurrentViewInspectionChirho {
            evidence_object_digest_chirho: evidence_digest_chirho,
            evidence_chirho,
            bundle_root_object_digest_chirho: bundle_root_digest_chirho,
            bundle_root_chirho,
        },
    }
}

fn bind_inspection_generation_chirho(
    inspection_chirho: &mut Gd7WinnerCurrentViewInspectionChirho,
    signer_chirho: &ExistingNodeGd7SignerChirho,
    process_generation_chirho: u64,
) {
    inspection_chirho
        .evidence_chirho
        .winner_process_generation_chirho = process_generation_chirho;
    inspection_chirho.evidence_chirho.sig_chirho.clear();
    inspection_chirho.evidence_chirho.sig_chirho = Gd7ReconciliationSignerPortChirho::sign_chirho(
        signer_chirho,
        std::str::from_utf8(&serde_json::to_vec(&inspection_chirho.evidence_chirho).unwrap())
            .unwrap(),
    )
    .unwrap();
    inspection_chirho.evidence_object_digest_chirho =
        digest_serialized_chirho(&inspection_chirho.evidence_chirho);
}

fn migration_store_chirho<'a>(
    storage_chirho: &'a dyn cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho,
    signer_chirho: &'a ExistingNodeGd7SignerChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
) -> TenantMigrationStoreChirho<'a> {
    TenantMigrationStoreChirho::new_chirho(
        storage_chirho,
        signer_chirho,
        consistency_group_digest_chirho(group_chirho).unwrap(),
        node_chirho.0.clone(),
    )
    .unwrap()
}

fn commit_migration_preparing_chirho(
    store_chirho: &TenantMigrationStoreChirho<'_>,
    group_chirho: &ConsistencyGroupIdChirho,
    attempt_digest_chirho: &str,
) {
    let tenant_id_chirho = match group_chirho {
        ConsistencyGroupIdChirho::TenantChirho { tenant_id_chirho } => tenant_id_chirho.clone(),
        ConsistencyGroupIdChirho::RootPathChirho { .. } => {
            panic!("migration test requires a tenant consistency group")
        }
    };
    store_chirho
        .commit_preparing_test_hook_chirho(
            tenant_id_chirho,
            "resident-authority-cluster-chirho".to_owned(),
            "journals/resident-authority-chirho.jsonl".to_owned(),
            attempt_digest_chirho.to_owned(),
            TenantMigrationCutClaimChirho {
                epoch_chirho: 0,
                seq_chirho: 0,
                record_digest_chirho: "d".repeat(64),
            },
        )
        .unwrap();
}

#[test]
fn active_gd7_owner_refuses_migration_begin_before_durable_or_marker_mutation_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-append-barrier-gd7-preflight",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         _journal_path_chirho,
         _cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
            let control_chirho = broad_chirho.handoff_control_handle_chirho();
            let signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .unwrap();
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .unwrap();
            let migration_store_chirho = migration_store_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                group_chirho,
                node_chirho,
            );
            let mut gd7_fixture_chirho = gd7_preparing_fixture_chirho(
                group_chirho,
                node_chirho,
                &elector_chirho,
                &signer_chirho,
            );
            let gd7_attempt_chirho = gd7_winner_handoff_attempt_digest_chirho(
                &gd7_fixture_chirho.attempt_identity_chirho,
            )
            .unwrap();
            let preparation_chirho = control_chirho
                .try_prepare_handoff_chirho(&gd7_attempt_chirho)
                .unwrap();
            bind_inspection_generation_chirho(
                &mut gd7_fixture_chirho.inspection_chirho,
                &signer_chirho,
                preparation_chirho.process_generation_chirho(),
            );
            let (committed_chirho, durable_chirho) = gd7_store_chirho
                .commit_preparing_chirho(
                    gd7_fixture_chirho.attempt_identity_chirho,
                    &gd7_fixture_chirho.challenge_bytes_chirho,
                    gd7_fixture_chirho.inspection_chirho,
                    preparation_chirho.process_generation_chirho(),
                )
                .unwrap()
                .into_parts_chirho();
            assert!(durable_chirho);
            drop(preparation_chirho.activate_chirho());
            let barrier_chirho = ResidentAppendBarrierRuntimeChirho {
                gd7_chirho:
                    ResidentGd7WinnerHandoffRuntimeChirho::from_durable_active_test_fixture_chirho(
                        crate::reconciliation_chirho::ActiveGd7WinnerHandoffChirho {
                            attempt_digest_chirho: committed_chirho.attempt_digest_chirho,
                            checkpoint_ref_chirho: committed_chirho.checkpoint_ref_chirho,
                            checkpoint_chirho: committed_chirho.checkpoint_chirho,
                        },
                    ),
                migration_chirho: TenantMigrationStartupBarrierChirho::NoneChirho,
                migration_operation_fault_chirho: false,
            };
            assert!(barrier_chirho.any_owner_blocks_mutations_chirho());
            assert!(!barrier_chirho.migration_blocks_mutations_chirho());
            assert!(matches!(
                require_recovery_adoption_slot_chirho(
                    &gd7_store_chirho,
                    Some(&migration_store_chirho),
                    &control_chirho,
                ),
                Err(ResidentAppendBarrierRefusalChirho::Gd7RecoveryOwnerActiveChirho)
            ));

            let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
            let command_chirho =
                ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
                    command_chirho:
                        ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                            target_root_chirho: PathBuf::from("/must-not-open-target-chirho"),
                            // Never reached: the append-barrier owner refuses before the
                            // destination gate runs, which is the ordering this test pins.
                            destination_chirho: Box::new(unusable_destination_record_chirho()),
                            writer_adoption_chirho: None,
                        },
                    reply_chirho: reply_sender_chirho,
                };
            assert!(ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
                command_chirho,
                &barrier_chirho,
            )
            .is_none());
            assert!(matches!(
                reply_receiver_chirho.recv().unwrap(),
                Err(
                    ResidentTenantMigrationOperationRefusalChirho::AnyAppendBarrierOwnerActiveChirho
                )
            ));
            assert!(migration_store_chirho
                .load_current_chirho()
                .unwrap()
                .is_none());
            assert!(control_chirho
                .handoff_read_handle_chirho()
                .try_acquire_handoff_read_chirho(&gd7_attempt_chirho)
                .is_ok());
        },
    );
}

#[test]
fn terminal_gd7_recovery_probe_releases_only_its_observed_marker_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-append-barrier-terminal-recovery",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         _journal_path_chirho,
         _cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
            let control_chirho = broad_chirho.handoff_control_handle_chirho();
            let signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .unwrap();
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .unwrap();
            let migration_store_chirho = migration_store_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                group_chirho,
                node_chirho,
            );
            let mut gd7_fixture_chirho = gd7_preparing_fixture_chirho(
                group_chirho,
                node_chirho,
                &elector_chirho,
                &signer_chirho,
            );
            let gd7_attempt_chirho = gd7_winner_handoff_attempt_digest_chirho(
                &gd7_fixture_chirho.attempt_identity_chirho,
            )
            .unwrap();
            let preparation_chirho = control_chirho
                .try_prepare_handoff_chirho(&gd7_attempt_chirho)
                .unwrap();
            bind_inspection_generation_chirho(
                &mut gd7_fixture_chirho.inspection_chirho,
                &signer_chirho,
                preparation_chirho.process_generation_chirho(),
            );
            let (preparing_chirho, preparing_durable_chirho) = gd7_store_chirho
                .commit_preparing_chirho(
                    gd7_fixture_chirho.attempt_identity_chirho,
                    &gd7_fixture_chirho.challenge_bytes_chirho,
                    gd7_fixture_chirho.inspection_chirho,
                    preparation_chirho.process_generation_chirho(),
                )
                .unwrap()
                .into_parts_chirho();
            assert!(preparing_durable_chirho);
            drop(preparation_chirho.activate_chirho());
            let (_, aborted_durable_chirho) = gd7_store_chirho
                .commit_aborted_chirho(&gd7_attempt_chirho, &preparing_chirho.checkpoint_ref_chirho)
                .unwrap()
                .into_parts_chirho();
            assert!(aborted_durable_chirho);
            assert!(control_chirho
                .handoff_read_handle_chirho()
                .try_acquire_handoff_read_chirho(&gd7_attempt_chirho)
                .is_ok());

            require_recovery_adoption_slot_chirho(
                &gd7_store_chirho,
                Some(&migration_store_chirho),
                &control_chirho,
            )
            .expect("a terminal exact owner is released before recovery staging");
            control_chirho
                .handoff_read_handle_chirho()
                .require_no_active_handoff_chirho()
                .expect("terminal recovery arbitration leaves the shared slot empty");
        },
    );
}

#[test]
fn two_active_durable_owners_refuse_before_any_marker_is_claimed_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-append-barrier-two-active",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
            let control_chirho = broad_chirho.handoff_control_handle_chirho();
            let resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                broad_chirho.clone(),
            )
            .unwrap();
            let signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .unwrap();
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .unwrap();
            let migration_store_chirho = migration_store_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                group_chirho,
                node_chirho,
            );
            let mut gd7_fixture_chirho = gd7_preparing_fixture_chirho(
                group_chirho,
                node_chirho,
                &elector_chirho,
                &signer_chirho,
            );
            let gd7_attempt_chirho = gd7_winner_handoff_attempt_digest_chirho(
                &gd7_fixture_chirho.attempt_identity_chirho,
            )
            .unwrap();
            let preparation_chirho = control_chirho
                .try_prepare_handoff_chirho(&gd7_attempt_chirho)
                .unwrap();
            bind_inspection_generation_chirho(
                &mut gd7_fixture_chirho.inspection_chirho,
                &signer_chirho,
                preparation_chirho.process_generation_chirho(),
            );
            let (_committed_chirho, durable_chirho) = gd7_store_chirho
                .commit_preparing_chirho(
                    gd7_fixture_chirho.attempt_identity_chirho,
                    &gd7_fixture_chirho.challenge_bytes_chirho,
                    gd7_fixture_chirho.inspection_chirho,
                    preparation_chirho.process_generation_chirho(),
                )
                .unwrap()
                .into_parts_chirho();
            assert!(durable_chirho);
            drop(preparation_chirho);
            commit_migration_preparing_chirho(
                &migration_store_chirho,
                group_chirho,
                &"9".repeat(64),
            );

            assert!(matches!(
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_store_chirho,
                    Some(&migration_store_chirho),
                    &control_chirho,
                    &resident_chirho,
                    &broad_chirho,
                ),
                Err(ResidentAppendBarrierRefusalChirho::TwoActiveDurableOwnersChirho)
            ));
            drop(
                broad_chirho.try_acquire_chirho().expect(
                    "two-active refusal occurs before either durable owner claims the slot",
                ),
            );
        },
    );
}

#[test]
fn aborted_gd7_never_releases_the_later_active_migration_marker_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-append-barrier-terminal-foreign",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
            let control_chirho = broad_chirho.handoff_control_handle_chirho();
            let resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                broad_chirho.clone(),
            )
            .unwrap();
            let signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .unwrap();
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .unwrap();
            let migration_store_chirho = migration_store_chirho(
                ports_chirho.storage_chirho,
                &signer_chirho,
                group_chirho,
                node_chirho,
            );
            let mut gd7_fixture_chirho = gd7_preparing_fixture_chirho(
                group_chirho,
                node_chirho,
                &elector_chirho,
                &signer_chirho,
            );
            let gd7_attempt_chirho = gd7_winner_handoff_attempt_digest_chirho(
                &gd7_fixture_chirho.attempt_identity_chirho,
            )
            .unwrap();
            let preparation_chirho = control_chirho
                .try_prepare_handoff_chirho(&gd7_attempt_chirho)
                .unwrap();
            bind_inspection_generation_chirho(
                &mut gd7_fixture_chirho.inspection_chirho,
                &signer_chirho,
                preparation_chirho.process_generation_chirho(),
            );
            let (preparing_chirho, preparing_durable_chirho) = gd7_store_chirho
                .commit_preparing_chirho(
                    gd7_fixture_chirho.attempt_identity_chirho,
                    &gd7_fixture_chirho.challenge_bytes_chirho,
                    gd7_fixture_chirho.inspection_chirho,
                    preparation_chirho.process_generation_chirho(),
                )
                .unwrap()
                .into_parts_chirho();
            assert!(preparing_durable_chirho);
            preparation_chirho.activate_chirho().release_chirho();
            let (aborted_chirho, aborted_durable_chirho) = gd7_store_chirho
                .commit_aborted_chirho(&gd7_attempt_chirho, &preparing_chirho.checkpoint_ref_chirho)
                .unwrap()
                .into_parts_chirho();
            assert!(aborted_durable_chirho);
            assert_eq!(
                aborted_chirho.checkpoint_chirho.phase_chirho,
                Gd7WinnerHandoffPhaseChirho::AbortedChirho
            );

            let migration_attempt_chirho = "9".repeat(64);
            commit_migration_preparing_chirho(
                &migration_store_chirho,
                group_chirho,
                &migration_attempt_chirho,
            );
            drop(
                control_chirho
                    .try_prepare_handoff_chirho(&migration_attempt_chirho)
                    .unwrap()
                    .activate_chirho(),
            );

            let (barrier_chirho, _readiness_chirho) =
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_store_chirho,
                    Some(&migration_store_chirho),
                    &control_chirho,
                    &resident_chirho,
                    &broad_chirho,
                )
                .unwrap();
            assert!(barrier_chirho.migration_blocks_mutations_chirho());
            assert!(barrier_chirho
                .accepted_gd7_attempt_digest_chirho()
                .is_none());
            assert!(control_chirho
                .handoff_read_handle_chirho()
                .try_acquire_handoff_read_chirho(&migration_attempt_chirho)
                .is_ok());
            assert!(matches!(
                control_chirho
                    .handoff_read_handle_chirho()
                    .try_acquire_handoff_read_chirho(&gd7_attempt_chirho),
                Err(LocalAppendAuthorityRefusalChirho::HandoffIdentityMismatchChirho)
            ));
        },
    );
}
