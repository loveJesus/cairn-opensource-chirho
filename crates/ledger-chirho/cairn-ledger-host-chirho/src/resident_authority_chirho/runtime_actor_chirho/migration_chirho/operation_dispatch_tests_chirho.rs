// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::reconciliation_chirho::{
    ExistingNodeGd7SignerChirho, Gd7WinnerHandoffStoreChirho, Gd7WinnerWitnessStoreChirho,
};
use crate::tests_chirho::{
    signer_refs_chirho, warm_single_node_elector_chirho, with_bound_resident_fixture_chirho,
};
use cairn_tenant_chirho::migration_completeness_chirho::{
    preliminary_migration_check_chirho, CompletenessRefusalChirho, CompletenessVerdictChirho,
};
use cairn_tenant_chirho::self_containment_chirho::SelfContainmentVerdictChirho;
use cairn_tenant_chirho::surface_disposition_chirho::{
    verify_surface_dispositions_chirho, DispositionRefusalChirho,
};
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::ShadowCanaryEvidenceStoreChirho;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::command_dispatch_chirho::{
    handle_actor_command_chirho, ResidentTenantMigrationAdmittedCommandChirho,
};
use super::tenant_migration_operation_chirho::{
    destination_record_for_roots_chirho, AcceptingDestinationAuthorityChirho,
    ResidentTenantMigrationOperationCommandChirho, ResidentTenantMigrationOperationOutcomeChirho,
    ResidentTenantMigrationOperationRefusalChirho, ResidentTenantMigrationOperationRuntimeChirho,
};

fn temp_platform_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-tenant-migration-dispatch-{label_chirho}-{nanos_chirho}-{counter_chirho}-chirho"
    ))
}

#[test]
fn target_not_eligible_refusal_retains_each_failed_half_surface_chirho() {
    let completeness_chirho = CompletenessVerdictChirho {
        observed_count_chirho: 1,
        refusals_chirho: vec![CompletenessRefusalChirho::UnknownSurfaceChirho {
            surface_chirho: "unknown-root-surface-chirho".to_owned(),
        }],
        declared_but_absent_chirho: Vec::new(),
    };
    let containment_chirho = SelfContainmentVerdictChirho {
        references_checked_chirho: 1,
        refusals_chirho: Vec::new(),
    };
    let disposition_chirho =
        verify_surface_dispositions_chirho(&["undisposed-root-surface-chirho".to_owned()], None);
    assert_eq!(
        disposition_chirho.refusals_chirho,
        vec![DispositionRefusalChirho::UndisposedSurfaceChirho {
            surface_chirho: "undisposed-root-surface-chirho".to_owned(),
        }]
    );
    let failed_halves_chirho = preliminary_migration_check_chirho(
        &completeness_chirho,
        &containment_chirho,
        &disposition_chirho,
        None,
        None,
    )
    .expect_err("both independently failed halves must remain attributed");
    let refusal_chirho = ResidentTenantMigrationOperationRefusalChirho::TargetNotEligibleChirho {
        failed_halves_chirho,
    };
    let operator_output_chirho = refusal_chirho.to_string();
    assert!(operator_output_chirho
        .contains("completeness-chirho[surfaces_chirho=unknown-root-surface-chirho;"));
    assert!(operator_output_chirho
        .contains("disposition-chirho[surfaces_chirho=undisposed-root-surface-chirho;"));
    assert_eq!(
        ResidentTenantMigrationOperationRefusalChirho::TargetRootUnreadableChirho.to_string(),
        "the target root could not be inspected"
    );
}

#[test]
fn production_actor_dispatch_preserves_begin_recover_activate_and_abort_selection_chirho() {
    with_bound_resident_fixture_chirho(
        "tenant-migration-production-dispatch",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
            let control_chirho = broad_chirho.handoff_control_handle_chirho();
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    broad_chirho.clone(),
                )
                .expect("open bound resident for production dispatch arm");

            let control_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open migration control storage");
            let control_signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .expect("open migration node-control signer");
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &signer_refs_chirho())
                    .expect("open resident signers for production dispatch arm");
            let gd7_winner_store_chirho = Gd7WinnerWitnessStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                &signers_chirho.journal_chirho,
            );
            let gd7_handoff_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .expect("open empty GD7 handoff store");
            let migration_store_chirho = TenantMigrationStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .expect("open tenant migration store");
            let (mut append_barrier_chirho, _readiness_chirho) =
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_handoff_store_chirho,
                    Some(&migration_store_chirho),
                    &control_chirho,
                    &resident_chirho,
                    &broad_chirho,
                )
                .expect("restore empty append barrier");
            let mut migration_runtime_chirho = Some(
                ResidentTenantMigrationOperationRuntimeChirho::new_chirho(
                    root_chirho,
                    ports_chirho.storage_chirho,
                    "ledger-namespace-chirho",
                    TenantLedgerVerificationViewsChirho {
                        signer_chirho: ports_chirho.signer_chirho,
                        clock_chirho: ports_chirho.clock_chirho,
                        membership_chirho: ports_chirho.membership_chirho,
                        kind_registry_chirho: ports_chirho.kind_registry_chirho,
                        authority_chirho: ports_chirho.authority_chirho,
                    },
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    migration_store_chirho,
                    control_chirho.clone(),
                    Some(&AcceptingDestinationAuthorityChirho),
                    Some(admitting_test_capacity_composition_chirho()),
                    None,
                    None,
                    &control_signer_chirho,
                    1,
                )
                .expect("bind production migration runtime"),
            );
            let gd7_plan_ports_chirho = ResidentGd7PlanPortsChirho::new_chirho(
                &control_storage_chirho,
                root_chirho,
                &control_signer_chirho,
                &signers_chirho.journal_chirho,
                &signers_chirho.effect_intent_chirho,
                &signers_chirho.effect_terminal_chirho,
                None,
            );
            let canary_root_chirho = root_chirho.join("migration-dispatch-canary-chirho");
            let _generation_zero_store_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("open canary store for production dispatch arm");
            let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("open generation-aware canary store for production dispatch arm");
            let mut canary_state_chirho = ResidentCanaryStateChirho {
                latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
                    1,
                    "0".repeat(64),
                    1,
                    0,
                    1,
                    group_chirho,
                )
                .expect("construct valid fixture ledger cut"),
                pending_chirho: None,
                sticky_refusal_chirho: None,
            };
            let mut winner_view_state_chirho = ResidentGd7WinnerViewStateChirho::default();
            let mut adoption_state_chirho = ResidentGd7WinnerAdoptionEvidenceStateChirho::default();
            let provider_chirho = RefusingGd7CompensationProviderChirho;

            let target_platform_chirho = temp_platform_root_chirho("target");
            fs::create_dir_all(&target_platform_chirho).unwrap();
            let target_root_chirho = prepare_tenant_root_chirho(
                &target_platform_chirho,
                "resident-authority-tenant-chirho",
            )
            .expect("prepare same-tenant migration target");
            // Stage it the way an operator must: the surfaces the model says travel. The actor now
            // computes eligibility itself, so a target that was merely PREPARED is refused — which
            // is the point of the required-surfaces half, and makes this dispatch arm exercise a
            // target that is genuinely eligible instead of one waved through by an injected check.
            crate::resident_authority_chirho::runtime_actor_chirho::seed_migration_reference_chirho(
                root_chirho,
            );
            crate::resident_authority_chirho::runtime_actor_chirho::stage_migration_target_surfaces_chirho(
                root_chirho,
                &target_root_chirho,
            );
            crate::resident_authority_chirho::runtime_actor_chirho::stage_adopted_writer_identity_chirho(
                &target_root_chirho,
            );
            let (begin_reply_sender_chirho, begin_reply_receiver_chirho) = sync_channel(1);
            let begin_command_chirho =
                ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
                    command_chirho:
                        ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                            target_root_chirho: target_root_chirho.clone(),
                            // Bound to the REAL source binding digest, so this proves the gate
                            // accepts a correct authorization rather than any record at all.
                            destination_chirho: Box::new(destination_record_for_roots_chirho(
                                root_chirho,
                                &target_root_chirho,
                            )),
                            writer_adoption_chirho: None,
                        },
                    reply_chirho: begin_reply_sender_chirho,
                };
            let begin_command_chirho = ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
                begin_command_chirho,
                &append_barrier_chirho,
            )
            .expect("an unowned source admits migration begin");
            assert!(!handle_actor_command_chirho(
                begin_command_chirho,
                &mut resident_chirho,
                &signers_chirho,
                &elector_chirho,
                &gd7_winner_store_chirho,
                &gd7_handoff_store_chirho,
                &broad_chirho,
                &gd7_plan_ports_chirho,
                &None,
                &provider_chirho,
                &canary_store_chirho,
                group_chirho,
                node_chirho,
                &mut canary_state_chirho,
                &mut winner_view_state_chirho,
                &mut append_barrier_chirho,
                &mut migration_runtime_chirho,
                &mut adoption_state_chirho,
            ));
            let begin_outcome_chirho = begin_reply_receiver_chirho
                .recv()
                .expect("production dispatcher returns the begin reply")
                .expect("production dispatcher preserves BeginSourceFence");
            let ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                begin_status_chirho,
            ) = begin_outcome_chirho
            else {
                panic!("production dispatcher must return the requested source-fenced outcome");
            };
            assert!(append_barrier_chirho.migration_blocks_mutations_chirho());

            let (recover_reply_sender_chirho, recover_reply_receiver_chirho) = sync_channel(1);
            let recover_command_chirho =
                ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
                    command_chirho:
                        ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                            target_root_chirho: target_root_chirho.clone(),
                        },
                    reply_chirho: recover_reply_sender_chirho,
                };
            let recover_command_chirho =
                ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
                    recover_command_chirho,
                    &append_barrier_chirho,
                )
                .expect("the active source fence admits recovery");
            assert!(!handle_actor_command_chirho(
                recover_command_chirho,
                &mut resident_chirho,
                &signers_chirho,
                &elector_chirho,
                &gd7_winner_store_chirho,
                &gd7_handoff_store_chirho,
                &broad_chirho,
                &gd7_plan_ports_chirho,
                &None,
                &provider_chirho,
                &canary_store_chirho,
                group_chirho,
                node_chirho,
                &mut canary_state_chirho,
                &mut winner_view_state_chirho,
                &mut append_barrier_chirho,
                &mut migration_runtime_chirho,
                &mut adoption_state_chirho,
            ));
            let recover_outcome_chirho = recover_reply_receiver_chirho
                .recv()
                .expect("production dispatcher returns the recovery reply")
                .expect("production dispatcher preserves RecoverSourceFence");
            let ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                recover_status_chirho,
            ) = recover_outcome_chirho
            else {
                panic!("production dispatcher must return the recovered source-fenced outcome");
            };
            assert_eq!(recover_status_chirho, begin_status_chirho);
            assert!(append_barrier_chirho.migration_blocks_mutations_chirho());

            // ACTIVATION SELECTION, and the absent-namespace case with it. This fixture's target is
            // a bare prepared tenant root: it verifies as a root but carries NO ledger namespace, so
            // activation must refuse at the storage open rather than proceeding on a target that has
            // nothing to verify. Absent is one of the three cases this seam owes; the present-and-
            // wrong case is pinned at the coordinator layer by the fenced-cut arm.
            let (activate_reply_sender_chirho, activate_reply_receiver_chirho) = sync_channel(1);
            let activate_command_chirho =
                ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
                    command_chirho:
                        ResidentTenantMigrationOperationCommandChirho::ActivateTargetChirho {
                            target_root_chirho,
                        },
                    reply_chirho: activate_reply_sender_chirho,
                };
            let activate_command_chirho =
                ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
                    activate_command_chirho,
                    &append_barrier_chirho,
                )
                .expect("the active source fence admits activation");
            assert!(!handle_actor_command_chirho(
                activate_command_chirho,
                &mut resident_chirho,
                &signers_chirho,
                &elector_chirho,
                &gd7_winner_store_chirho,
                &gd7_handoff_store_chirho,
                &broad_chirho,
                &gd7_plan_ports_chirho,
                &None,
                &provider_chirho,
                &canary_store_chirho,
                group_chirho,
                node_chirho,
                &mut canary_state_chirho,
                &mut winner_view_state_chirho,
                &mut append_barrier_chirho,
                &mut migration_runtime_chirho,
                &mut adoption_state_chirho,
            ));
            let activate_outcome_chirho = activate_reply_receiver_chirho
                .recv()
                .expect("production dispatcher returns the activation reply");
            assert!(
                activate_outcome_chirho.is_err(),
                "a target root carrying no ledger namespace must not activate"
            );
            // FAIL-TOWARD-FREEZE: a refused activation leaves the source frozen, never briefly
            // writable. This is the assertion that would catch a refusal path that released first
            // and only then discovered it could not proceed.
            assert!(append_barrier_chirho.migration_blocks_mutations_chirho());

            let (abort_reply_sender_chirho, abort_reply_receiver_chirho) = sync_channel(1);
            let abort_command_chirho =
                ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
                    command_chirho:
                        ResidentTenantMigrationOperationCommandChirho::AbortCurrentChirho,
                    reply_chirho: abort_reply_sender_chirho,
                };
            let abort_command_chirho = ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
                abort_command_chirho,
                &append_barrier_chirho,
            )
            .expect("the active source fence admits exact-current abort");
            assert!(!handle_actor_command_chirho(
                abort_command_chirho,
                &mut resident_chirho,
                &signers_chirho,
                &elector_chirho,
                &gd7_winner_store_chirho,
                &gd7_handoff_store_chirho,
                &broad_chirho,
                &gd7_plan_ports_chirho,
                &None,
                &provider_chirho,
                &canary_store_chirho,
                group_chirho,
                node_chirho,
                &mut canary_state_chirho,
                &mut winner_view_state_chirho,
                &mut append_barrier_chirho,
                &mut migration_runtime_chirho,
                &mut adoption_state_chirho,
            ));
            let abort_outcome_chirho = abort_reply_receiver_chirho
                .recv()
                .expect("production dispatcher returns the abort reply")
                .expect("production dispatcher preserves AbortCurrent");
            let ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(abort_status_chirho) =
                abort_outcome_chirho
            else {
                panic!("production dispatcher must return the requested aborted outcome");
            };
            assert_eq!(
                abort_status_chirho.attempt_digest_chirho,
                begin_status_chirho.attempt_digest_chirho
            );
            assert!(abort_status_chirho.released_owned_marker_chirho);
            assert!(!append_barrier_chirho.migration_blocks_mutations_chirho());
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("exact-current abort restores ordinary append authority"),
            );

            drop(migration_runtime_chirho);
            drop(resident_chirho);
            drop(elector_chirho);
            fs::remove_dir_all(target_platform_chirho).unwrap();
        },
    );
}
