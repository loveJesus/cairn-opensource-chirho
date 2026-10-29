// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::command_dispatch_chirho::{
    classify_testkind_loss_witness_deposed_sink_result_chirho, handle_actor_command_chirho,
    ResidentTenantMigrationAdmittedCommandChirho,
};
use super::*;
use crate::reconciliation_chirho::{
    ExistingNodeGd7SignerChirho, Gd7WinnerHandoffStoreChirho, Gd7WinnerWitnessStoreChirho,
};
use crate::resident_authority_chirho::testkind_loss_witness_tests_chirho::witness_config_chirho;
use crate::tests_chirho::{
    resident_mint_request_chirho, signer_refs_chirho, warm_single_node_elector_chirho,
    with_bound_resident_fixture_chirho, with_unbound_resident_fixture_chirho, ElectorMeshChirho,
};
use crate::ResidentLedgerBirthPermitChirho;
use cairn_writer_elector_chirho::shadow_canary_chirho::ShadowCanaryEvidenceStoreChirho;
use std::sync::mpsc::sync_channel;

#[test]
fn migration_classifier_refuses_provider_command_by_identity_chirho() {
    let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
    let command_chirho = ResidentEffectJournalCommandChirho::ExecuteGd7CompensationProviderChirho {
        canonical_obligation_digest_chirho: "obligation-chirho".to_owned(),
        action_idempotency_key_chirho: "action-chirho".to_owned(),
        bounded_payload_chirho: b"payload-chirho".to_vec(),
        reply_chirho: reply_sender_chirho,
    };

    assert!(command_chirho
        .refuse_mutation_during_tenant_migration_chirho()
        .is_none());
    assert_eq!(
        reply_receiver_chirho
            .recv()
            .expect("receive migration refusal"),
        Err(Gd7CompensationProviderRefusalChirho::TenantMigrationSourceFenceActiveChirho)
    );
}

#[test]
fn migration_classifier_keeps_bounded_read_transfer_available_chirho() {
    let (reply_sender_chirho, _reply_receiver_chirho) = sync_channel(1);
    let command_chirho = ResidentEffectJournalCommandChirho::ProbeGd7WinnerChirho {
        reply_chirho: reply_sender_chirho,
    };

    assert!(matches!(
        command_chirho.refuse_mutation_during_tenant_migration_chirho(),
        Some(ResidentEffectJournalCommandChirho::ProbeGd7WinnerChirho { .. })
    ));
}

#[test]
fn deposed_sink_classifier_accepts_only_exact_not_local_leader_and_makes_admission_sticky_chirho() {
    with_bound_resident_fixture_chirho(
        "resident-deposed-result-classifier",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let elector_chirho = warm_single_node_elector_chirho(node_chirho, group_chirho);
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    ports_chirho,
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    elector_chirho.local_append_authority_handle_chirho(),
                )
                .expect("the current resident opens for the unexpected-admission control");
            let admitted_receipt_chirho = resident_chirho
                .record_testkind_loss_witness_chirho(resident_mint_request_chirho(
                    1,
                    "deposed-result-admission-control-chirho",
                ))
                .expect("a current resident supplies the real admitted receipt");
            let latest_cut_chirho = ShadowCanaryLedgerCutChirho::new_chirho(
                admitted_receipt_chirho.append_chirho.seq_chirho,
                admitted_receipt_chirho
                    .append_chirho
                    .record_digest_chirho
                    .0
                    .clone(),
                admitted_receipt_chirho
                    .append_chirho
                    .hlc_chirho
                    .physical_ms_chirho,
                admitted_receipt_chirho
                    .append_chirho
                    .hlc_chirho
                    .logical_chirho,
                admitted_receipt_chirho.fence_chirho.epoch_chirho,
                group_chirho,
            )
            .unwrap();
            let state_chirho = || ResidentCanaryStateChirho {
                latest_ledger_cut_chirho: latest_cut_chirho.clone(),
                pending_chirho: None,
                sticky_refusal_chirho: None,
            };

            let mut admitted_state_chirho = state_chirho();
            assert_eq!(
                classify_testkind_loss_witness_deposed_sink_result_chirho(
                    Ok(admitted_receipt_chirho),
                    &mut admitted_state_chirho,
                    ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                ),
                Err(ResidentTestkindLossWitnessRefusalChirho::DeposedSinkUnexpectedAdmissionChirho)
            );
            assert_eq!(
                admitted_state_chirho
                    .sticky_refusal_chirho
                    .as_ref()
                    .expect("unexpected admission makes the actor sticky-refusing")
                    .origin_identity_chirho,
                EffectCommitJournalCommittedEvidenceIdentityChirho::TestkindDeposedSinkAdmissionEvidencePendingChirho,
            );

            let mut exact_state_chirho = state_chirho();
            assert_eq!(
                classify_testkind_loss_witness_deposed_sink_result_chirho(
                    Err(
                        ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                            reason_chirho: LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
                        }
                    ),
                    &mut exact_state_chirho,
                    ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                ),
                Ok(
                    ResidentTestkindLossWitnessOutcomeChirho::DeposedSinkRefusedChirho {
                        phase_chirho: ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                    }
                )
            );
            assert!(exact_state_chirho.sticky_refusal_chirho.is_none());

            let mut neighbour_state_chirho = state_chirho();
            assert_eq!(
                classify_testkind_loss_witness_deposed_sink_result_chirho(
                    Err(
                        ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
                            reason_chirho:
                                LocalAppendAuthorityRefusalChirho::AuthorityUnavailableChirho,
                        }
                    ),
                    &mut neighbour_state_chirho,
                    ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                ),
                Err(ResidentTestkindLossWitnessRefusalChirho::DeposedSinkUnexpectedRefusalChirho)
            );
            assert!(neighbour_state_chirho.sticky_refusal_chirho.is_none());
        },
    );
}

/// The resident-tier arm proves the sink itself. This arm additionally traverses the production
/// dispatcher, so restoring the deposed path's early authority probe must red here while leaving
/// that resident-tier arm green.
#[test]
fn production_dispatch_deposed_loss_witness_reaches_the_final_sink_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-deposed-production-dispatch",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mut config_chirho = witness_config_chirho(true);
            config_chirho.members_chirho[0].owner_chirho =
                "resident-authority-user-chirho".to_owned();
            let static_membership_chirho =
                StaticClusterMembershipChirho::from_config_chirho(0, &config_chirho.members_chirho)
                    .expect("construct the witness membership from the sealed host config");
            let membership_chirho = static_membership_chirho.elected_view_chirho();
            let resident_ports_chirho = || ResidentLedgerLocalPortsChirho {
                storage_chirho: ports_chirho.storage_chirho,
                signer_chirho: ports_chirho.signer_chirho,
                clock_chirho: ports_chirho.clock_chirho,
                membership_chirho: &membership_chirho,
                kind_registry_chirho: ports_chirho.kind_registry_chirho,
                authority_chirho: ports_chirho.authority_chirho,
            };
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, node_chirho);
            let _opening_term_chirho = mesh_chirho.elect_chirho(1, None);
            let local_authority_chirho = mesh_chirho
                .node_chirho(1)
                .local_append_authority_handle_chirho();
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            drop(
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    birth_permit_chirho,
                    resident_ports_chirho(),
                    local_authority_chirho.clone(),
                )
                .expect("bind the witness resident under node 1"),
            );
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    resident_ports_chirho(),
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    local_authority_chirho.clone(),
                )
                .expect("open the witness resident under node 1");
            let loss_witness_plan_chirho = derive_resident_testkind_loss_witness_plan_chirho(
                &config_chirho,
                ports_chirho.kind_registry_chirho,
                ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
                false,
                false,
            )
            .expect("derive the actor-owned test-kind plan");
            resident_chirho
                .record_testkind_loss_witness_chirho(resident_mint_request_chirho(
                    1,
                    "deposed-production-dispatch-funding-control-chirho",
                ))
                .expect("fund the exact payer before the balanced current-writer control");
            let current_receipt_chirho = resident_chirho
                .record_testkind_loss_witness_chirho(
                    loss_witness_plan_chirho
                        .as_ref()
                        .expect("a marked config retains one witness plan")
                        .append_request_chirho(
                            ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                            ResidentTestkindLossWitnessRoleChirho::CurrentWriterChirho,
                        )
                        .expect("derive the sealed current-writer control request"),
                )
                .expect("the current resident admits the exact witness before deposition");

            let control_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open the authority-control storage");
            let control_signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .expect("open the node-control signer");
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &signer_refs_chirho())
                    .expect("load the witness resident signers");
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
            .expect("open the empty handoff store");
            let handoff_control_chirho = local_authority_chirho.handoff_control_handle_chirho();
            let (mut append_barrier_chirho, readiness_chirho) =
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_handoff_store_chirho,
                    None,
                    &handoff_control_chirho,
                    &resident_chirho,
                    &local_authority_chirho,
                )
                .expect("restore the empty append barrier before deposition");
            let gd7_plan_ports_chirho = ResidentGd7PlanPortsChirho::new_chirho(
                &control_storage_chirho,
                root_chirho,
                &control_signer_chirho,
                &signers_chirho.journal_chirho,
                &signers_chirho.effect_intent_chirho,
                &signers_chirho.effect_terminal_chirho,
                None,
            );
            let canary_root_chirho = root_chirho.join("deposed-production-dispatch-canary-chirho");
            let _generation_zero_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("create the dispatch canary store");
            let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("open the dispatch canary generation store");
            let mut canary_state_chirho = ResidentCanaryStateChirho {
                latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
                    current_receipt_chirho.append_chirho.seq_chirho,
                    current_receipt_chirho
                        .append_chirho
                        .record_digest_chirho
                        .0
                        .clone(),
                    current_receipt_chirho
                        .append_chirho
                        .hlc_chirho
                        .physical_ms_chirho,
                    current_receipt_chirho
                        .append_chirho
                        .hlc_chirho
                        .logical_chirho,
                    current_receipt_chirho.fence_chirho.epoch_chirho,
                    group_chirho,
                )
                .expect("bind the fixture canary cut to the resident readiness"),
                pending_chirho: None,
                sticky_refusal_chirho: None,
            };
            let mut winner_view_state_chirho = ResidentGd7WinnerViewStateChirho::default();
            let mut winner_adoption_state_chirho =
                ResidentGd7WinnerAdoptionEvidenceStateChirho::default();
            let mut migration_runtime_chirho = None;
            let provider_chirho = RefusingGd7CompensationProviderChirho;
            assert_eq!(
                readiness_chirho.journal_tail_seq_chirho,
                current_receipt_chirho.append_chirho.seq_chirho,
                "the append barrier must restore over the admitted current-writer control cut",
            );

            let _deposed_term_chirho = mesh_chirho.elect_chirho(2, Some(1));
            let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
            let command_chirho =
                ResidentEffectJournalCommandChirho::TestkindLossWitnessDeposedSinkChirho {
                    phase_chirho: ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                    reply_chirho: reply_sender_chirho,
                };
            let admitted_command_chirho =
                ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
                    command_chirho,
                    &append_barrier_chirho,
                )
                .expect("the empty migration barrier admits the deposed witness command");
            assert!(!handle_actor_command_chirho(
                admitted_command_chirho,
                &mut resident_chirho,
                &signers_chirho,
                mesh_chirho.node_chirho(1),
                &gd7_winner_store_chirho,
                &gd7_handoff_store_chirho,
                &local_authority_chirho,
                &gd7_plan_ports_chirho,
                &loss_witness_plan_chirho,
                &provider_chirho,
                &canary_store_chirho,
                group_chirho,
                node_chirho,
                &mut canary_state_chirho,
                &mut winner_view_state_chirho,
                &mut append_barrier_chirho,
                &mut migration_runtime_chirho,
                &mut winner_adoption_state_chirho,
            ));
            assert_eq!(
                reply_receiver_chirho
                    .recv()
                    .expect("the production dispatcher returns the deposed witness outcome"),
                Ok(
                    ResidentTestkindLossWitnessOutcomeChirho::DeposedSinkRefusedChirho {
                        phase_chirho: ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                    }
                ),
                "only the final sink's exact NotLocalLeader identity may satisfy this arm",
            );
        },
    );
}

/// A2-FULL of the epoch-wedge brick — the ACTOR LOOP refuses a subsequent command.
///
/// The sibling arms in `canary_alignment_tests_chirho` prove the PRECONDITION: a refused append
/// leaves the epoch advanced and the alignment gate then refuses. They stop short of the served
/// path, because they call the resident's append door directly and never enter
/// `prepare_resident_mutation_chirho`. This one closes that gap by driving the real
/// `handle_actor_command_chirho`, which is what the CF8 loss witness actually goes through.
///
/// Sequence, faithful to what a hosted window does:
///   1. a successful witness append establishes the aligned canary cut (its receipt is the only
///      thing that ever moves that cut);
///   2. the resident REOPENS — production's adoption-aligned start, and the point at which no fence
///      token is cached, so the next append will advance the epoch;
///   3. one REFUSED append writes no record and advances the epoch;
///   4. the actor loop is then handed an ordinary current-writer witness command and REFUSES it.
///
/// MIGRATION PATH — CORRECTED 2026-08-17 after an audit measured that the original note was WRONG
/// and would have actively misled whoever landed a fix.
///
/// The original said: red means retarget to `Ok(..)`; a merely CHANGED identity means the wedge
/// moved. **Neither is right here, because `Ok(..)` is unreachable for reasons that are not the
/// defect.** Measured by removing the epoch check and re-running, peeling one wall at a time:
///   * same phase+role as STEP 1 derives the SAME sealed request -> `CurrentAppendRefusedChirho`
///     (an idempotency duplicate, masked today because the canary gate fires first). FIXED above by
///     using a different phase.
///   * one funded unit covers only STEP 1's append -> the STEP 4 append cannot succeed. FIXED above
///     by funding both.
///   * this single-node fixture then reaches `CommittedEvidencePendingChirho`, a mirror-evidence
///     limit of the fixture that has nothing to do with the epoch wedge.
///
/// SO THE CORRECT RETARGET IS: assert the refusal is NOT a canary-alignment identity — that is what
/// closing the wedge means here. Do NOT require `Ok(..)`; that would demand fixing unrelated
/// single-node fixture limits and would make a working fix look failed. And if the identity changes
/// to another CANARY coordinate, the wedge has moved rather than closed — check A3, since a
/// journal-only repair leaves membership ahead.
#[test]
fn the_actor_loop_refuses_a_command_after_one_refused_append_chirho() {
    with_unbound_resident_fixture_chirho(
        "resident-epoch-wedge-actor-loop",
        |root_chirho,
         group_chirho,
         node_chirho,
         ports_chirho,
         journal_path_chirho,
         cluster_id_chirho| {
            let mut config_chirho = witness_config_chirho(true);
            config_chirho.members_chirho[0].owner_chirho =
                "resident-authority-user-chirho".to_owned();
            let static_membership_chirho =
                StaticClusterMembershipChirho::from_config_chirho(0, &config_chirho.members_chirho)
                    .expect("construct the witness membership from the sealed host config");
            let membership_chirho = static_membership_chirho.elected_view_chirho();
            let resident_ports_chirho = || ResidentLedgerLocalPortsChirho {
                storage_chirho: ports_chirho.storage_chirho,
                signer_chirho: ports_chirho.signer_chirho,
                clock_chirho: ports_chirho.clock_chirho,
                membership_chirho: &membership_chirho,
                kind_registry_chirho: ports_chirho.kind_registry_chirho,
                authority_chirho: ports_chirho.authority_chirho,
            };
            let mesh_chirho = ElectorMeshChirho::new_chirho(group_chirho, node_chirho);
            let _opening_term_chirho = mesh_chirho.elect_chirho(1, None);
            let local_authority_chirho = mesh_chirho
                .node_chirho(1)
                .local_append_authority_handle_chirho();
            let birth_permit_chirho = ResidentLedgerBirthPermitChirho::for_test_chirho(
                root_chirho,
                journal_path_chirho.clone(),
                cluster_id_chirho.clone(),
                0,
            );
            drop(
                ResidentLedgerAuthorityChirho::create_bound_preactivation_chirho(
                    birth_permit_chirho,
                    resident_ports_chirho(),
                    local_authority_chirho.clone(),
                )
                .expect("bind the resident"),
            );
            let loss_witness_plan_chirho = derive_resident_testkind_loss_witness_plan_chirho(
                &config_chirho,
                ports_chirho.kind_registry_chirho,
                ResidentTestkindLossWitnessOpenerModeChirho::MandatoryWitnessOrProductionChirho,
                false,
                false,
            )
            .expect("derive the actor-owned test-kind plan");

            // STEP 1 — a successful append establishes the aligned canary cut.
            let current_receipt_chirho = {
                let mut resident_chirho =
                    ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                        root_chirho,
                        resident_ports_chirho(),
                        journal_path_chirho.clone(),
                        cluster_id_chirho.clone(),
                        0,
                        local_authority_chirho.clone(),
                    )
                    .expect("open the resident for the funding append");
                // Fund enough for BOTH witness appends: STEP 1's control append and the STEP 4
                // command. Measured — with only one unit funded, STEP 4 cannot succeed even once the
                // gate passes, so the arm could never reach `Ok(..)` and could not verify any fix.
                resident_chirho
                    .record_testkind_loss_witness_chirho(resident_mint_request_chirho(
                        16,
                        "epoch-wedge-funding-chirho",
                    ))
                    .expect("fund the payer for both witness appends");
                resident_chirho
                    .record_testkind_loss_witness_chirho(
                        loss_witness_plan_chirho
                            .as_ref()
                            .expect("a marked config retains one witness plan")
                            .append_request_chirho(
                                ResidentTestkindLossWitnessPhaseChirho::LeaderLossChirho,
                                ResidentTestkindLossWitnessRoleChirho::CurrentWriterChirho,
                            )
                            .expect("derive the sealed current-writer control request"),
                    )
                    .expect("the aligned control append commits")
            };

            // STEP 2 — REOPEN. No fence token is cached now, so the next append advances the epoch.
            let mut resident_chirho =
                ResidentLedgerAuthorityChirho::open_bound_preactivation_chirho(
                    root_chirho,
                    resident_ports_chirho(),
                    journal_path_chirho.clone(),
                    cluster_id_chirho.clone(),
                    0,
                    local_authority_chirho.clone(),
                )
                .expect("reopen the resident on its existing journal");

            // STEP 3 — one REFUSED append. Writes nothing; advances the epoch.
            let tail_before_chirho = resident_chirho
                .probe_chirho()
                .unwrap()
                .journal_tail_seq_chirho;
            let _refused_chirho = resident_chirho
                .record_testkind_loss_witness_chirho(resident_mint_request_chirho(
                    0,
                    "epoch-wedge-rejected-chirho",
                ))
                .expect_err("a zero-amount mint is refused by admission");
            assert_eq!(
                resident_chirho
                    .probe_chirho()
                    .unwrap()
                    .journal_tail_seq_chirho,
                tail_before_chirho,
                "the refused append must not write a record"
            );

            let control_storage_chirho = FsLedgerStorageChirho::open_existing_chirho(root_chirho)
                .expect("open the authority-control storage");
            let control_signer_chirho =
                ExistingNodeGd7SignerChirho::open_existing_chirho(root_chirho, node_chirho)
                    .expect("open the node-control signer");
            let signers_chirho =
                HostLedgerSignersChirho::load_existing_chirho(root_chirho, &signer_refs_chirho())
                    .expect("load the resident signers");
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
            .expect("open the empty handoff store");
            let handoff_control_chirho = local_authority_chirho.handoff_control_handle_chirho();
            let (mut append_barrier_chirho, _readiness_chirho) =
                ResidentAppendBarrierRuntimeChirho::restore_chirho(
                    &gd7_handoff_store_chirho,
                    None,
                    &handoff_control_chirho,
                    &resident_chirho,
                    &local_authority_chirho,
                )
                .expect("restore the empty append barrier");
            let gd7_plan_ports_chirho = ResidentGd7PlanPortsChirho::new_chirho(
                &control_storage_chirho,
                root_chirho,
                &control_signer_chirho,
                &signers_chirho.journal_chirho,
                &signers_chirho.effect_intent_chirho,
                &signers_chirho.effect_terminal_chirho,
                None,
            );
            let canary_root_chirho = root_chirho.join("epoch-wedge-canary-chirho");
            let _generation_zero_chirho = ShadowCanaryEvidenceStoreChirho::open_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("create the canary store");
            let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
                &canary_root_chirho,
                root_chirho,
                group_chirho.clone(),
                node_chirho.clone(),
            )
            .expect("open the canary generation store");
            // The cut a healthy predecessor left, bound to the COMMITTED receipt from step 1.
            let mut canary_state_chirho = ResidentCanaryStateChirho {
                latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::new_chirho(
                    current_receipt_chirho.append_chirho.seq_chirho,
                    current_receipt_chirho
                        .append_chirho
                        .record_digest_chirho
                        .0
                        .clone(),
                    current_receipt_chirho
                        .append_chirho
                        .hlc_chirho
                        .physical_ms_chirho,
                    current_receipt_chirho
                        .append_chirho
                        .hlc_chirho
                        .logical_chirho,
                    current_receipt_chirho.fence_chirho.epoch_chirho,
                    group_chirho,
                )
                .expect("bind the cut to the committed receipt"),
                pending_chirho: None,
                sticky_refusal_chirho: None,
            };
            let mut winner_view_state_chirho = ResidentGd7WinnerViewStateChirho::default();
            let mut winner_adoption_state_chirho =
                ResidentGd7WinnerAdoptionEvidenceStateChirho::default();
            let mut migration_runtime_chirho = None;
            let provider_chirho = RefusingGd7CompensationProviderChirho;

            // STEP 4 — the actor loop is handed an ordinary current-writer witness command.
            let (reply_sender_chirho, reply_receiver_chirho) = sync_channel(1);
            let command_chirho =
                ResidentEffectJournalCommandChirho::TestkindLossWitnessCurrentChirho {
                    // MUST NOT REPLAY STEP 1's REQUEST. An audit measured that reusing STEP 1's
                    // phase+role derives the SAME sealed request, so the append is an idempotency
                    // duplicate — masked today because the canary gate fires first, but surfacing as
                    // `CurrentAppendRefusedChirho` the moment a fix lets the gate through. That would
                    // make this arm's migration path UNREACHABLE and tell the next builder a working
                    // fix had failed. A different phase keeps the command ordinary and the arm honest.
                    phase_chirho: ResidentTestkindLossWitnessPhaseChirho::NodeLossChirho,
                    reply_chirho: reply_sender_chirho,
                };
            let admitted_command_chirho =
                ResidentTenantMigrationAdmittedCommandChirho::admit_chirho(
                    command_chirho,
                    &append_barrier_chirho,
                )
                .expect("the empty migration barrier admits the witness command");
            assert!(!handle_actor_command_chirho(
                admitted_command_chirho,
                &mut resident_chirho,
                &signers_chirho,
                mesh_chirho.node_chirho(1),
                &gd7_winner_store_chirho,
                &gd7_handoff_store_chirho,
                &local_authority_chirho,
                &gd7_plan_ports_chirho,
                &loss_witness_plan_chirho,
                &provider_chirho,
                &canary_store_chirho,
                group_chirho,
                node_chirho,
                &mut canary_state_chirho,
                &mut winner_view_state_chirho,
                &mut append_barrier_chirho,
                &mut migration_runtime_chirho,
                &mut winner_adoption_state_chirho,
            ));
            let outcome_chirho = reply_receiver_chirho
                .recv()
                .expect("the dispatcher replies to the witness command");
            // RETARGETED 2026-08-17 exactly as this arm's corrected migration path instructed: assert
            // the refusal is NOT a canary-alignment identity. `Ok(..)` is deliberately NOT required —
            // it is unreachable here for measured reasons that are not the defect (a mirror-evidence
            // limit of this single-node fixture), and demanding it would make a working fix look
            // failed. What the removal buys is that the CANARY GATE no longer blocks the command.
            assert!(
                !matches!(
                    outcome_chirho,
                    Err(ResidentTestkindLossWitnessRefusalChirho::CanaryTailSeqRefusedChirho)
                        | Err(ResidentTestkindLossWitnessRefusalChirho::CanaryTailDigestRefusedChirho)
                        | Err(
                            ResidentTestkindLossWitnessRefusalChirho::CanaryConsistencyGroupRefusedChirho
                        )
                        | Err(
                            ResidentTestkindLossWitnessRefusalChirho::EnvelopeReadinessCanaryRefusedChirho
                        )
                ),
                "THE FIX ON THE SERVED PATH: after one refused append the actor loop no longer \
                 refuses at the canary alignment gate. Observed outcome: {outcome_chirho:?}"
            );
        },
    );
}
