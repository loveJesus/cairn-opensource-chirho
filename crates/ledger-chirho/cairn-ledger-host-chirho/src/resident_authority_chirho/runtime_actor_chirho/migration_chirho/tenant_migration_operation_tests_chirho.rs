// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::reconciliation_chirho::{ExistingNodeGd7SignerChirho, Gd7WinnerHandoffStoreChirho};
use crate::tests_chirho::{warm_single_node_elector_chirho, with_bound_resident_fixture_chirho};
use crate::ResidentLedgerAuthorityChirho;
use cairn_ledger_log_chirho::append_mirror_chirho::{
    LedgerAppendMirrorCandidateChirho, LedgerAppendMirrorPortChirho,
    LedgerAppendMirrorPortErrorChirho, LedgerAppendMirrorTailChirho,
};
use cairn_tenant_chirho::capacity_admission_chirho::{
    TenantCapacityAdmissionPortChirho, TenantCapacityAdmissionVerdictChirho,
    TenantCapacityDemandChirho,
};
use cairn_tenant_chirho::migration_completeness_chirho::PreliminaryMigrationHalfChirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_digest_chirho;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_platform_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cairn-tenant-migration-operation-{label_chirho}-{nanos_chirho}-{counter_chirho}-chirho"
    ))
}

struct MutableIdentityCapacityPortChirho {
    identity_chirho: Arc<Mutex<String>>,
}

impl TenantCapacityAdmissionPortChirho for MutableIdentityCapacityPortChirho {
    fn admit_target_chirho(
        &self,
        _target_node_id_chirho: &str,
        _demand_chirho: &TenantCapacityDemandChirho,
        _headroom_chirho: &TenantCapacityDemandChirho,
    ) -> TenantCapacityAdmissionVerdictChirho {
        TenantCapacityAdmissionVerdictChirho {
            considered_chirho: 1,
            refusals_chirho: Vec::new(),
            evidence_identity_chirho: self.identity_chirho.lock().unwrap().clone(),
        }
    }
}

struct RefusingCapacityPortChirho;

impl TenantCapacityAdmissionPortChirho for RefusingCapacityPortChirho {
    fn admit_target_chirho(
        &self,
        _target_node_id_chirho: &str,
        _demand_chirho: &TenantCapacityDemandChirho,
        _headroom_chirho: &TenantCapacityDemandChirho,
    ) -> TenantCapacityAdmissionVerdictChirho {
        TenantCapacityAdmissionVerdictChirho {
            considered_chirho: 1,
            refusals_chirho: vec!["insufficientheadroomchirho".to_owned()],
            evidence_identity_chirho: "d".repeat(64),
        }
    }
}

struct TogglePendingMirrorPortChirho {
    pending_chirho: Arc<AtomicBool>,
}

impl LedgerAppendMirrorPortChirho for TogglePendingMirrorPortChirho {
    fn require_no_unreconciled_pending_append_chirho(
        &self,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        if self.pending_chirho.load(Ordering::Acquire) {
            return Err(LedgerAppendMirrorPortErrorChirho::new_chirho(
                "LedgerMirrorPendingSourceFenceRefusedChirho",
            ));
        }
        Ok(())
    }

    fn reconcile_before_append_chirho(
        &self,
        _local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        Ok(())
    }

    fn prepare_append_chirho(
        &self,
        _candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        Ok(())
    }

    fn finalize_append_chirho(
        &self,
        _committed_candidate_chirho: &LedgerAppendMirrorCandidateChirho,
    ) -> Result<(), LedgerAppendMirrorPortErrorChirho> {
        Ok(())
    }
}

fn refusing_capacity_composition_chirho() -> TenantMigrationCapacityAdmissionCompositionChirho {
    TenantMigrationCapacityAdmissionCompositionChirho::new_chirho(
        Arc::new(RefusingCapacityPortChirho),
        TenantCapacityDemandChirho {
            cpu_millicores_chirho: 1,
            memory_bytes_chirho: 1,
            durable_bytes_chirho: 1,
        },
        TenantCapacityDemandChirho {
            cpu_millicores_chirho: 1,
            memory_bytes_chirho: 1,
            durable_bytes_chirho: 1,
        },
    )
    .unwrap()
}

fn mutable_identity_capacity_composition_chirho() -> (
    TenantMigrationCapacityAdmissionCompositionChirho,
    Arc<Mutex<String>>,
) {
    let identity_chirho = Arc::new(Mutex::new("a".repeat(64)));
    let composition_chirho = TenantMigrationCapacityAdmissionCompositionChirho::new_chirho(
        Arc::new(MutableIdentityCapacityPortChirho {
            identity_chirho: Arc::clone(&identity_chirho),
        }),
        TenantCapacityDemandChirho {
            cpu_millicores_chirho: 1,
            memory_bytes_chirho: 1,
            durable_bytes_chirho: 1,
        },
        TenantCapacityDemandChirho {
            cpu_millicores_chirho: 1,
            memory_bytes_chirho: 1,
            durable_bytes_chirho: 1,
        },
    )
    .unwrap();
    (composition_chirho, identity_chirho)
}

#[test]
fn crate_private_handle_carries_only_bounded_operation_commands_chirho() {
    let (command_sender_chirho, command_receiver_chirho) = sync_channel(3);
    let handle_chirho = ResidentTenantMigrationOperationHandleChirho {
        command_sender_chirho,
    };
    let target_root_chirho = PathBuf::from("/bounded-target-chirho");
    let actor_chirho = std::thread::spawn(move || {
        let begin_chirho = command_receiver_chirho.recv().unwrap();
        let ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
            command_chirho:
                ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                    target_root_chirho,
                    destination_chirho: _destination_chirho,
                    ..
                },
            reply_chirho,
        } = begin_chirho
        else {
            panic!("first command must be bounded migration begin");
        };
        assert_eq!(target_root_chirho, PathBuf::from("/bounded-target-chirho"));
        // The precheck used to ride ON the command, so this arm could inspect it here. It is
        // now computed inside the actor — the only layer holding the configured namespace and
        // the source root — so there is nothing about it to assert at the mailbox. What this
        // arm still pins is the part that DOES cross: the target path.
        reply_chirho
            .send(Ok(
                ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                    ResidentTenantMigrationSourceFenceStatusChirho {
                        attempt_digest_chirho: "a".repeat(64),
                        checkpoint_ref_chirho: "b".repeat(64),
                        phase_chirho: TenantMigrationPhaseChirho::SourceFencedChirho,
                        marker_activation_generation_chirho: 7,
                    },
                ),
            ))
            .unwrap();

        let recover_chirho = command_receiver_chirho.recv().unwrap();
        let ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
            command_chirho:
                ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                    target_root_chirho,
                },
            reply_chirho,
        } = recover_chirho
        else {
            panic!("second command must be bounded migration recovery");
        };
        assert_eq!(target_root_chirho, PathBuf::from("/bounded-target-chirho"));
        reply_chirho
            .send(Ok(
                ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                    ResidentTenantMigrationSourceFenceStatusChirho {
                        attempt_digest_chirho: "a".repeat(64),
                        checkpoint_ref_chirho: "b".repeat(64),
                        phase_chirho: TenantMigrationPhaseChirho::SourceFencedChirho,
                        marker_activation_generation_chirho: 7,
                    },
                ),
            ))
            .unwrap();

        let activate_chirho = command_receiver_chirho.recv().unwrap();
        let ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
            command_chirho:
                ResidentTenantMigrationOperationCommandChirho::ActivateTargetChirho {
                    target_root_chirho,
                },
            reply_chirho,
        } = activate_chirho
        else {
            panic!("third command must be target activation");
        };
        // Activation carries the target and the same non-authoritative preliminary evidence, and
        // carries NO attempt digest or checkpoint ref — the actor selects the head itself.
        // The command now carries ONLY the target. Eligibility is computed inside the actor,
        // where the configured namespace name is known.
        assert_eq!(target_root_chirho, PathBuf::from("/bounded-target-chirho"));
        reply_chirho
            .send(Ok(
                ResidentTenantMigrationOperationOutcomeChirho::TargetActivatedChirho(
                    ResidentTenantMigrationTargetActivatedStatusChirho {
                        attempt_digest_chirho: "a".repeat(64),
                        checkpoint_ref_chirho: "d".repeat(64),
                        phase_chirho:
                            TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho,
                    },
                ),
            ))
            .unwrap();

        let abort_chirho = command_receiver_chirho.recv().unwrap();
        let ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
            command_chirho: ResidentTenantMigrationOperationCommandChirho::AbortCurrentChirho,
            reply_chirho,
        } = abort_chirho
        else {
            panic!("fourth command must be identity-free exact-current abort");
        };
        reply_chirho
            .send(Ok(
                ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(
                    ResidentTenantMigrationAbortStatusChirho {
                        attempt_digest_chirho: "a".repeat(64),
                        checkpoint_ref_chirho: "c".repeat(64),
                        released_owned_marker_chirho: true,
                    },
                ),
            ))
            .unwrap();
    });

    let begin_chirho = handle_chirho
        .begin_source_fence_chirho(&target_root_chirho, unusable_destination_record_chirho())
        .unwrap();
    assert_eq!(begin_chirho.marker_activation_generation_chirho, 7);
    let recover_chirho = handle_chirho
        .recover_source_fence_chirho(&target_root_chirho)
        .unwrap();
    assert_eq!(recover_chirho, begin_chirho);
    let activated_chirho = handle_chirho
        .activate_target_chirho(&target_root_chirho)
        .unwrap();
    assert_eq!(
        activated_chirho.phase_chirho,
        TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
    );
    // The handle must map the ACTIVATED reply to its own status type. If it accepted a
    // source-fenced reply here it would report activation that never happened.
    assert_eq!(activated_chirho.checkpoint_ref_chirho, "d".repeat(64));
    let aborted_chirho = handle_chirho.abort_current_chirho().unwrap();
    assert!(aborted_chirho.released_owned_marker_chirho);
    actor_chirho.join().unwrap();
}

#[test]
fn actor_owned_operation_refuses_foreign_target_then_recovers_and_aborts_exactly_chirho() {
    with_bound_resident_fixture_chirho(
        "tenant-migration-operation",
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
            .expect("open bound resident for migration operation");
            let control_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open migration control storage");
            let control_signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .expect("open migration node-control signer");
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .expect("open empty GD7 store");
            let migration_store_chirho = TenantMigrationStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .expect("open migration store");
            let (mut append_barrier_chirho, _readiness_chirho) =
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_store_chirho,
                    Some(&migration_store_chirho),
                    &control_chirho,
                    &resident_chirho,
                    &broad_chirho,
                )
                .expect("restore empty append barrier");
            let (capacity_composition_chirho, capacity_identity_chirho) =
                mutable_identity_capacity_composition_chirho();
            let source_mirror_pending_chirho = Arc::new(AtomicBool::new(true));
            let mut runtime_chirho = ResidentTenantMigrationOperationRuntimeChirho::new_chirho(
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
                Some(capacity_composition_chirho),
                Some(Arc::new(TogglePendingMirrorPortChirho {
                    pending_chirho: Arc::clone(&source_mirror_pending_chirho),
                })),
                None,
                &control_signer_chirho,
                1,
            )
            .expect("bind resident tenant migration operation runtime");

            let foreign_platform_chirho = temp_platform_root_chirho("foreign");
            fs::create_dir_all(&foreign_platform_chirho).unwrap();
            let foreign_target_chirho =
                prepare_tenant_root_chirho(&foreign_platform_chirho, "foreign-tenant-chirho")
                    .unwrap();
            stage_adopted_writer_identity_chirho(&foreign_target_chirho);
            let foreign_refusal_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: foreign_target_chirho.clone(),
                        // Correctly authorized for THIS source, so the foreign-target refusal
                        // this test pins still comes from the target check rather than from a
                        // destination gate the test did not intend to exercise.
                        destination_chirho: Box::new(destination_record_for_roots_chirho(
                            root_chirho,
                            &foreign_target_chirho,
                        )),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("foreign tenant target must refuse");
            assert!(matches!(
                &foreign_refusal_chirho,
                ResidentTenantMigrationOperationRefusalChirho::CoordinatorChirho(
                    TenantMigrationCoordinatorRefusalChirho::MigrationContractChirho(
                        TenantMigrationRefusalChirho::TenantMismatchChirho
                    )
                )
            ), "foreign target must retain the tenant-mismatch identity, got {foreign_refusal_chirho:?}");
            assert!(runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .is_none());
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("foreign target refusal leaves append authority available"),
            );

            let target_platform_chirho = temp_platform_root_chirho("target");
            fs::create_dir_all(&target_platform_chirho).unwrap();
            let target_root_chirho = prepare_tenant_root_chirho(
                &target_platform_chirho,
                "resident-authority-tenant-chirho",
            )
            .unwrap();
            cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(&target_root_chirho)
                .expect("the migration target owns an existing node key before admission");
            // Staged the way an operator must, because the actor now computes eligibility from
            // the real roots rather than accepting a precheck the caller built. A merely
            // PREPARED target is refused for missing what the model says travels — which is the
            // whole point of the required-surfaces half.
            seed_migration_reference_chirho(root_chirho);
            stage_migration_target_surfaces_chirho(root_chirho, &target_root_chirho);
            stage_adopted_writer_identity_chirho(&target_root_chirho);
            // TARGET-BINDING ARM at the RESIDENT boundary, not only at the pure verifier. The
            // signed record is valid for the same tenant and source but names another real
            // target. Before the fix this passed destination verification and reached a later
            // gate; it must now refuse by destination identity before any fence or checkpoint.
            let authorized_elsewhere_platform_chirho =
                temp_platform_root_chirho("authorized-elsewhere");
            fs::create_dir_all(&authorized_elsewhere_platform_chirho).unwrap();
            let authorized_elsewhere_root_chirho = prepare_tenant_root_chirho(
                &authorized_elsewhere_platform_chirho,
                "resident-authority-tenant-chirho",
            )
            .unwrap();
            let wrong_target_refusal_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(destination_record_for_roots_chirho(
                            root_chirho,
                            &authorized_elsewhere_root_chirho,
                        )),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("an authorization for another target must refuse");
            assert!(
                matches!(
                    wrong_target_refusal_chirho,
                    ResidentTenantMigrationOperationRefusalChirho::DestinationAuthorityChirho(
                        TenantMigrationDestinationRefusalChirho::DestinationRootBindingChirho
                    )
                ),
                "wrong target must refuse at destination authority, got {wrong_target_refusal_chirho:?}"
            );
            assert!(runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .is_none());
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("a wrong-target authorization leaves append authority available"),
            );
            // GATE ARM: an authorization bound to a source that is not this one must refuse
            // BEFORE any fence begins, and must refuse as an AUTHORIZATION problem rather than
            // as a target or fence problem. Placed before the successful begin so no prior
            // attempt state can mask it.
            let unauthorized_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(unusable_destination_record_chirho()),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("a destination bound to another source must refuse");
            assert!(
                matches!(
                    unauthorized_chirho,
                    ResidentTenantMigrationOperationRefusalChirho::DestinationAuthorityChirho(
                        TenantMigrationDestinationRefusalChirho::TenantIdentityChirho
                            | TenantMigrationDestinationRefusalChirho::SourceRootBindingChirho
                    )
                ),
                "expected a destination authorization refusal, got {unauthorized_chirho:?}"
            );
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("a refused destination must leave append authority available"),
            );

            let configured_capacity_chirho = runtime_chirho.capacity_admission_chirho.take();
            let missing_capacity_refusal_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(destination_record_for_roots_chirho(
                            root_chirho,
                            &target_root_chirho,
                        )),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("a migration actor without capacity/load composition must refuse");
            assert!(matches!(
                missing_capacity_refusal_chirho,
                ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionUnavailableChirho
            ));
            assert!(runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .is_none());
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("missing capacity composition leaves append authority available"),
            );

            runtime_chirho.capacity_admission_chirho = Some(refusing_capacity_composition_chirho());
            let refused_capacity_verdict_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(destination_record_for_roots_chirho(
                            root_chirho,
                            &target_root_chirho,
                        )),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("the production road must consume a refusing capacity verdict");
            let ResidentTenantMigrationOperationRefusalChirho::TargetNotEligibleChirho {
                failed_halves_chirho,
            } = refused_capacity_verdict_chirho
            else {
                panic!(
                    "a refusing verdict must retain the eligibility identity, got \
                     {refused_capacity_verdict_chirho:?}"
                );
            };
            assert_eq!(failed_halves_chirho.len(), 1);
            assert_eq!(
                failed_halves_chirho[0].half_chirho(),
                PreliminaryMigrationHalfChirho::CapacityAdmissionChirho,
                "the sixth half, not a neighbouring eligibility half, must refuse"
            );
            assert!(runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .is_none());
            runtime_chirho.capacity_admission_chirho = configured_capacity_chirho;
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("a refusing capacity verdict leaves append authority available"),
            );

            let pending_mirror_refusal_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(destination_record_for_roots_chirho(
                            root_chirho,
                            &target_root_chirho,
                        )),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("an unreconciled source mirror intent must refuse before fencing");
            assert!(matches!(
                pending_mirror_refusal_chirho,
                ResidentTenantMigrationOperationRefusalChirho::SourceMirrorPendingChirho(_)
            ));
            assert!(runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .is_none());
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("a pending mirror refusal leaves append authority available"),
            );
            source_mirror_pending_chirho.store(false, Ordering::Release);

            let begin_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(destination_record_for_roots_chirho(
                            root_chirho,
                            &target_root_chirho,
                        )),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect("begin source fence");
            let ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                begin_status_chirho,
            ) = begin_chirho
            else {
                panic!("begin must return a source-fenced status");
            };
            assert_eq!(
                begin_status_chirho.phase_chirho,
                TenantMigrationPhaseChirho::SourceFencedChirho
            );
            assert!(append_barrier_chirho.migration_blocks_mutations_chirho());
            assert!(matches!(
                broad_chirho.try_acquire_chirho(),
                Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
            ));

            let active_at_begin_chirho = runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .expect("begin persists the source-fenced migration head");
            let begin_envelope_chirho = parse_operation_authority_chirho(
                active_at_begin_chirho.operation_authority_chirho(),
            )
            .expect("begin persists a canonical v2 operation authority envelope");
            assert_eq!(
                begin_envelope_chirho.capacity_admission_identity_chirho(),
                Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            );

            *capacity_identity_chirho.lock().unwrap() = "b".repeat(64);
            let changed_capacity_refusal_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("recovery must re-verify the exact begin-time capacity identity");
            assert!(matches!(
                changed_capacity_refusal_chirho,
                ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionIdentityChangedChirho
            ));
            let active_after_drift_chirho = runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .expect("capacity identity drift must leave the active head intact");
            assert_eq!(
                active_after_drift_chirho.checkpoint_ref_chirho(),
                active_at_begin_chirho.checkpoint_ref_chirho()
            );
            *capacity_identity_chirho.lock().unwrap() = "a".repeat(64);

            let recover_once_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                    },
                    &mut append_barrier_chirho,
                )
                .expect("recover source fence once");
            let recover_twice_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                    },
                    &mut append_barrier_chirho,
                )
                .expect("recover source fence twice");
            let (
                ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                    recover_once_status_chirho,
                ),
                ResidentTenantMigrationOperationOutcomeChirho::SourceFencedChirho(
                    recover_twice_status_chirho,
                ),
            ) = (recover_once_chirho, recover_twice_chirho)
            else {
                panic!("recovery must return source-fenced statuses");
            };
            assert_eq!(recover_once_status_chirho, begin_status_chirho);
            assert_eq!(recover_twice_status_chirho, begin_status_chirho);
            *capacity_identity_chirho.lock().unwrap() = "c".repeat(64);
            let activation_drift_refusal_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::ActivateTargetChirho {
                        target_root_chirho: target_root_chirho.clone(),
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("activation must re-verify the exact begin-time capacity identity");
            assert!(matches!(
                activation_drift_refusal_chirho,
                ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionIdentityChangedChirho
            ));
            *capacity_identity_chirho.lock().unwrap() = "a".repeat(64);
            let active_chirho = runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .expect("source-fenced durable head remains present");
            assert_eq!(
                active_chirho.checkpoint_ref_chirho(),
                begin_status_chirho.checkpoint_ref_chirho
            );

            let aborted_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::AbortCurrentChirho,
                    &mut append_barrier_chirho,
                )
                .expect("abort exact current source fence");
            let ResidentTenantMigrationOperationOutcomeChirho::AbortedChirho(aborted_status_chirho) =
                aborted_chirho
            else {
                panic!("abort must return an aborted status");
            };
            assert_eq!(
                aborted_status_chirho.attempt_digest_chirho,
                begin_status_chirho.attempt_digest_chirho
            );
            assert!(aborted_status_chirho.released_owned_marker_chirho);
            assert!(!append_barrier_chirho.migration_blocks_mutations_chirho());
            drop(
                broad_chirho
                    .try_acquire_chirho()
                    .expect("exact-current abort restores ordinary append authority"),
            );

            drop(runtime_chirho);
            drop(resident_chirho);
            drop(elector_chirho);
            fs::remove_dir_all(foreign_platform_chirho).unwrap();
            fs::remove_dir_all(target_platform_chirho).unwrap();
            fs::remove_dir_all(authorized_elsewhere_platform_chirho).unwrap();
        },
    );
}

/// A legacy operation authority that predates the capacity pin must REFUSE activation by its own
/// identity, while the legacy record itself stays parseable.
///
/// The two halves are deliberately asserted together. `two_authorities_and_exact_target_binding_are_
/// independently_required_chirho` pins that a completed legacy adoption record REMAINS PARSEABLE —
/// true, and deliberate. The distance from "v1 must remain parseable" to "v1 must remain activatable"
/// is one sentence in a future upgrade-path commit, and the true neighbour is what would make the
/// wrong change feel confirmed. This arm makes the second statement fail out loud.
///
/// If this ever REFUSES with a different identity, the capacity gate moved and the arm should be
/// retargeted at wherever the absent pin is now caught. If it RETURNS Ok, the fail-closed absence
/// case regressed: a migration begun before the capacity pin existed can now be activated without
/// one, and clause 6's "capacity evidence drives the migration" is void on the legacy path.
#[test]
fn legacy_authority_without_capacity_identity_refuses_activation_by_its_own_identity_chirho() {
    with_bound_resident_fixture_chirho(
        "tenant-migration-legacy-capacity-pin",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
            let control_chirho = broad_chirho.handoff_control_handle_chirho();
            let _resident_chirho = ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                root_chirho,
                ports_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
                broad_chirho.clone(),
            )
            .expect("open bound resident for the legacy-capacity-pin arm");
            let control_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open migration control storage");
            let control_signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .expect("open migration node-control signer");
            let gd7_store_chirho = Gd7WinnerHandoffStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .expect("open empty GD7 store");
            let migration_store_chirho = TenantMigrationStoreChirho::new_chirho(
                &control_storage_chirho,
                &control_signer_chirho,
                consistency_group_digest_chirho(group_chirho).unwrap(),
                node_chirho.0.clone(),
            )
            .expect("open migration store");
            let (mut append_barrier_chirho, _readiness_chirho) =
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_store_chirho,
                    Some(&migration_store_chirho),
                    &control_chirho,
                    &_resident_chirho,
                    &broad_chirho,
                )
                .expect("restore empty append barrier");
            let (capacity_composition_chirho, _capacity_identity_chirho) =
                mutable_identity_capacity_composition_chirho();
            let mut runtime_chirho = ResidentTenantMigrationOperationRuntimeChirho::new_chirho(
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
                Some(capacity_composition_chirho),
                None,
                None,
                &control_signer_chirho,
                1,
            )
            .expect("bind the legacy-capacity-pin migration runtime");

            let target_platform_chirho = temp_platform_root_chirho("legacy-capacity-pin");
            fs::create_dir_all(&target_platform_chirho).unwrap();
            let target_root_chirho = prepare_tenant_root_chirho(
                &target_platform_chirho,
                "resident-authority-tenant-chirho",
            )
            .unwrap();
            cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(&target_root_chirho)
                .expect("the migration target owns an existing node key before admission");
            seed_migration_reference_chirho(root_chirho);
            stage_migration_target_surfaces_chirho(root_chirho, &target_root_chirho);
            stage_adopted_writer_identity_chirho(&target_root_chirho);

            runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::BeginSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                        destination_chirho: Box::new(destination_record_for_roots_chirho(
                            root_chirho,
                            &target_root_chirho,
                        )),
                        writer_adoption_chirho: None,
                    },
                    &mut append_barrier_chirho,
                )
                .expect("a capacity-ADMITTING begin must reach the source fence");

            let active_chirho = runtime_chirho
                .store_chirho
                .load_current_chirho()
                .unwrap()
                .expect("begin persists the source-fenced migration head");
            let v2_binding_chirho = active_chirho.operation_authority_chirho().clone();
            assert!(
                parse_operation_authority_chirho(&v2_binding_chirho)
                    .expect("begin persists a canonical v2 envelope")
                    .capacity_admission_identity_chirho()
                    .is_some(),
                "positive control: the arm is only meaningful if begin pinned an identity to remove"
            );

            let legacy_binding_chirho =
                super::super::super::writer_adoption_chirho::legacy_v1_operation_authority_for_test_chirho(
                    &v2_binding_chirho,
                )
                .expect("re-encode the begin authority as a legacy v1 envelope");
            assert_eq!(
                parse_operation_authority_chirho(&legacy_binding_chirho)
                    .expect("completed legacy adoption records remain parseable")
                    .capacity_admission_identity_chirho(),
                None,
                "the legacy half: v1 stays parseable and legitimately carries no capacity identity"
            );

            runtime_chirho
                .store_chirho
                .replace_active_operation_authority_test_hook_chirho(legacy_binding_chirho)
                .expect("seed a correctly signed head carrying the legacy authority");

            let refusal_chirho = runtime_chirho
                .handle_chirho(
                    ResidentTenantMigrationOperationCommandChirho::RecoverSourceFenceChirho {
                        target_root_chirho: target_root_chirho.clone(),
                    },
                    &mut append_barrier_chirho,
                )
                .expect_err("a legacy authority carrying no capacity identity must not activate");
            // Exact variant, deliberately not a catch-all: a permissive fallback that rescued
            // ABSENCE would still refuse a CHANGED identity, so an arm accepting either neighbour
            // would pass over the exact regression this exists to catch.
            assert!(
                matches!(
                    refusal_chirho,
                    ResidentTenantMigrationOperationRefusalChirho::CapacityAdmissionIdentityUnavailableChirho
                ),
                "absence must refuse by ITS OWN identity, got {refusal_chirho:?}"
            );

            let _ = fs::remove_dir_all(&target_platform_chirho);
        },
    );
}
