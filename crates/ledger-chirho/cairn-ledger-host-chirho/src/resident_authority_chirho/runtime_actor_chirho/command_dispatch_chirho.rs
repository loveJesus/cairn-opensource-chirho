// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

use super::gd7_compensation_composition_chirho::{
    compose_gd7_provider_result_chirho, Gd7CompensationCompositionRefusalChirho,
};
use super::tenant_migration_operation_chirho::{
    ResidentTenantMigrationOperationRefusalChirho, ResidentTenantMigrationOperationRuntimeChirho,
};
use crate::reconciliation_chirho::create_or_load_gd7_obligation_processing_state_chirho;

impl ResidentEffectJournalCommandChirho {
    /// A new migration must never race either existing owner of the shared append-barrier slot.
    /// Recovery and exact-current abort remain admitted because they are the only commands that can
    /// heal or retire an already-owned migration barrier.
    fn refuse_tenant_migration_begin_while_owned_chirho(self) -> Option<Self> {
        match self {
            Self::TenantMigrationOperationChirho {
                command_chirho,
                reply_chirho,
            } if command_chirho.begins_source_fence_chirho() => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    ResidentTenantMigrationOperationRefusalChirho::AnyAppendBarrierOwnerActiveChirho,
                ));
                None
            }
            command_chirho => Some(command_chirho),
        }
    }

    /// Refuse every resident-root or external-effect mutation before dispatch while migration owns
    /// the source fence. This exhaustive match makes a new mailbox variant choose a posture before
    /// it compiles. Bounded reads and derived immutable view-transfer staging remain available for
    /// final target synchronization.
    fn refuse_mutation_during_tenant_migration_chirho(self) -> Option<Self> {
        match self {
            Self::TestkindLossWitnessCurrentChirho { reply_chirho, .. }
            | Self::TestkindLossWitnessSustainedChirho { reply_chirho, .. }
            | Self::TestkindLossWitnessDeposedSinkChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    ResidentTestkindLossWitnessRefusalChirho::AppendBarrierRefusedChirho,
                ));
                None
            }
            Self::AppendHoldChirho { reply_chirho, .. }
            | Self::AppendCompensationHoldChirho { reply_chirho, .. }
            | Self::AppendTerminalChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(unavailable_chirho(
                    "tenant migration source fence blocks resident-root mutation",
                )));
                None
            }
            Self::ExecuteGd7CompensationProviderChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    Gd7CompensationProviderRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::ComposeGd7CompensationChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    Gd7CompensationCompositionRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::AdvanceGd7SinkTermChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    ResidentLedgerAuthorityRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::ReleaseConvergedGd7HoldChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    ResidentLedgerAuthorityRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::CompleteGd7CompensationChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    Gd7CompensationCompletionRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::DriveGd7PlanPageChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    Gd7PlanRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::ImportConvergedCompensationReceiptGd7Chirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    Gd7PlanRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::ObserveGd7DeposedForkChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    ResidentGd7WinnerForkObservationRefusalChirho::TenantMigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::Gd7WinnerHandoffChirho { reply_chirho, .. } => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    ResidentGd7WinnerHandoffRefusalChirho::MigrationSourceFenceActiveChirho,
                ));
                None
            }
            Self::TenantMigrationOperationChirho {
                command_chirho,
                reply_chirho,
            } if command_chirho.begins_source_fence_chirho() => {
                let _reply_result_chirho = reply_chirho.send(Err(
                    ResidentTenantMigrationOperationRefusalChirho::AnyAppendBarrierOwnerActiveChirho,
                ));
                None
            }
            command_chirho @ Self::ActiveHoldIntentRefsChirho { .. }
            | command_chirho @ Self::ReceiptByIntentRefChirho { .. }
            | command_chirho @ Self::EffectIntentCutChirho { .. }
            | command_chirho @ Self::CurrentContinuationChirho { .. }
            | command_chirho @ Self::VerifiedReceiptInventoryChirho { .. }
            | command_chirho @ Self::VerifyGd7SealedPlanChirho { .. }
            | command_chirho @ Self::ConvergeAndCertifyGd7Chirho { .. }
            | command_chirho @ Self::ProbeGd7WinnerChirho { .. }
            | command_chirho @ Self::StageGd7WinnerViewPageChirho { .. }
            | command_chirho @ Self::SealGd7WinnerCurrentViewChirho { .. }
            | command_chirho @ Self::SealGd7WinnerCurrentViewForHeldChirho { .. }
            | command_chirho @ Self::IssueFirstGd7WinnerViewPageGrantChirho { .. }
            | command_chirho @ Self::FetchGrantedGd7WinnerViewPageChirho { .. }
            | command_chirho @ Self::Gd7WinnerAdoptionEvidenceChirho { .. }
            | command_chirho @ Self::TenantMigrationOperationChirho { .. }
            | command_chirho @ Self::ShutdownChirho => Some(command_chirho),
        }
    }
}

/// Opaque command admitted through the current migration posture before dispatch.
///
/// The dispatcher cannot accept a raw mailbox command. Its sole constructor runs the exhaustive
/// mutation classifier against the live append-barrier state first, so provider invocation and
/// processing-state writes are downstream of admission by type rather than by statement order.
pub(super) struct ResidentTenantMigrationAdmittedCommandChirho(ResidentEffectJournalCommandChirho);

impl ResidentTenantMigrationAdmittedCommandChirho {
    pub(super) fn admit_chirho(
        command_chirho: ResidentEffectJournalCommandChirho,
        append_barrier_state_chirho: &ResidentAppendBarrierRuntimeChirho,
    ) -> Option<Self> {
        let command_chirho = if append_barrier_state_chirho.any_owner_blocks_mutations_chirho() {
            command_chirho.refuse_tenant_migration_begin_while_owned_chirho()?
        } else {
            command_chirho
        };
        if append_barrier_state_chirho.migration_blocks_mutations_chirho() {
            command_chirho
                .refuse_mutation_during_tenant_migration_chirho()
                .map(Self)
        } else {
            Some(Self(command_chirho))
        }
    }

    fn into_command_chirho(self) -> ResidentEffectJournalCommandChirho {
        self.0
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the actor loop passes one fixed resident authority bundle without heap indirection"
)]
pub(super) fn handle_actor_command_chirho(
    command_chirho: ResidentTenantMigrationAdmittedCommandChirho,
    resident_chirho: &mut ResidentLedgerAuthorityChirho<'_>,
    signers_chirho: &HostLedgerSignersChirho,
    elector_chirho: &RaftWriterElectorChirho,
    gd7_winner_store_chirho: &Gd7WinnerWitnessStoreChirho<'_>,
    gd7_winner_handoff_store_chirho: &Gd7WinnerHandoffStoreChirho<'_>,
    handoff_local_authority_chirho: &LocalAppendAuthorityHandleChirho,
    gd7_plan_ports_chirho: &ResidentGd7PlanPortsChirho<'_>,
    testkind_loss_witness_plan_chirho: &Option<ResidentTestkindLossWitnessPlanChirho>,
    gd7_compensation_provider_chirho: &dyn Gd7CompensationProviderAdapterChirho,
    canary_store_chirho: &ShadowCanaryGenerationStoreChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
    canary_state_chirho: &mut ResidentCanaryStateChirho,
    winner_view_state_chirho: &mut ResidentGd7WinnerViewStateChirho,
    append_barrier_state_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    tenant_migration_operation_runtime_chirho: &mut Option<
        ResidentTenantMigrationOperationRuntimeChirho<'_>,
    >,
    winner_adoption_evidence_state_chirho: &mut ResidentGd7WinnerAdoptionEvidenceStateChirho,
) -> bool {
    let command_chirho = command_chirho.into_command_chirho();
    match command_chirho {
        ResidentEffectJournalCommandChirho::TestkindLossWitnessCurrentChirho {
            phase_chirho,
            reply_chirho,
        } => {
            let envelope_chirho = ResidentMutationEnvelopeChirho {
                resident_chirho,
                elector_chirho,
                gd7_winner_store_chirho,
                canary_store_chirho,
                group_chirho,
                node_chirho,
                canary_state_chirho,
                append_barrier_state_chirho,
            };
            let result_chirho = execute_testkind_loss_witness_current_chirho(
                envelope_chirho,
                testkind_loss_witness_plan_chirho,
                phase_chirho,
                ResidentTestkindLossWitnessRoleChirho::CurrentWriterChirho,
                ResidentMutationCommandKindChirho::TestkindLossWitnessCurrentChirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::TestkindLossWitnessSustainedChirho {
            phase_chirho,
            reply_chirho,
        } => {
            let envelope_chirho = ResidentMutationEnvelopeChirho {
                resident_chirho,
                elector_chirho,
                gd7_winner_store_chirho,
                canary_store_chirho,
                group_chirho,
                node_chirho,
                canary_state_chirho,
                append_barrier_state_chirho,
            };
            let result_chirho = execute_testkind_loss_witness_current_chirho(
                envelope_chirho,
                testkind_loss_witness_plan_chirho,
                phase_chirho,
                ResidentTestkindLossWitnessRoleChirho::SustainedWriterChirho,
                ResidentMutationCommandKindChirho::TestkindLossWitnessSustainedChirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::TestkindLossWitnessDeposedSinkChirho {
            phase_chirho,
            reply_chirho,
        } => {
            let result_chirho = execute_testkind_loss_witness_deposed_sink_chirho(
                ResidentMutationEnvelopeChirho {
                    resident_chirho,
                    elector_chirho,
                    gd7_winner_store_chirho,
                    canary_store_chirho,
                    group_chirho,
                    node_chirho,
                    canary_state_chirho,
                    append_barrier_state_chirho,
                },
                testkind_loss_witness_plan_chirho,
                phase_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::AppendHoldChirho {
            canonical_intent_line_chirho,
            reply_chirho,
        } => {
            let result_chirho = execute_resident_mutation_chirho(
                ResidentMutationEnvelopeChirho {
                    resident_chirho,
                    elector_chirho,
                    gd7_winner_store_chirho,
                    canary_store_chirho,
                    group_chirho,
                    node_chirho,
                    canary_state_chirho,
                    append_barrier_state_chirho,
                },
                ResidentMutationLaneChirho::OrdinaryChirho,
                ResidentMutationCommandKindChirho::AppendHoldChirho,
                |resident_chirho| {
                    resident_chirho.record_effect_hold_chirho(
                        &canonical_intent_line_chirho,
                        &signers_chirho.effect_intent_chirho,
                    )
                },
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::AppendCompensationHoldChirho {
            canonical_intent_line_chirho,
            authorization_chirho,
            reply_chirho,
        } => {
            let result_chirho = execute_resident_mutation_chirho(
                ResidentMutationEnvelopeChirho {
                    resident_chirho,
                    elector_chirho,
                    gd7_winner_store_chirho,
                    canary_store_chirho,
                    group_chirho,
                    node_chirho,
                    canary_state_chirho,
                    append_barrier_state_chirho,
                },
                ResidentMutationLaneChirho::Gd7CompensationChirho,
                ResidentMutationCommandKindChirho::AppendCompensationHoldChirho,
                |resident_chirho| {
                    resident_chirho.record_effect_compensation_hold_chirho(
                        &canonical_intent_line_chirho,
                        &signers_chirho.effect_intent_chirho,
                        &authorization_chirho,
                    )
                },
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::AdvanceGd7SinkTermChirho {
            observation_chirho,
            adopted_checkpoint_ref_chirho,
            reply_chirho,
        } => {
            // The held signer IS the verifier (supertrait), so one root serves both roles here.
            let result_chirho = resident_chirho.accept_new_winner_term_chirho(
                &observation_chirho,
                &adopted_checkpoint_ref_chirho,
                gd7_plan_ports_chirho.held_verifier_chirho(),
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ReleaseConvergedGd7HoldChirho {
            adopted_checkpoint_ref_chirho,
            convergence_chirho,
            reply_chirho,
        } => {
            let result_chirho = resident_chirho.release_converged_gd7_hold_chirho(
                &adopted_checkpoint_ref_chirho,
                &convergence_chirho,
                gd7_plan_ports_chirho.held_verifier_chirho(),
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::CompleteGd7CompensationChirho {
            mint_identity_digest_chirho,
            obligation_receipt_ref_chirho,
            canonical_obligation_digest_chirho,
            inverse_authority_ref_chirho,
            action_idempotency_key_chirho,
            canonical_intent_line_chirho,
            authorization_chirho,
            reply_chirho,
        } => {
            let result_chirho = complete_gd7_compensation_command_chirho(
                resident_chirho,
                signers_chirho,
                elector_chirho,
                gd7_winner_store_chirho,
                canary_store_chirho,
                group_chirho,
                node_chirho,
                canary_state_chirho,
                append_barrier_state_chirho,
                Gd7CompensationCompletionRequestChirho {
                    mint_identity_digest_chirho: &mint_identity_digest_chirho,
                    obligation_receipt_ref_chirho: &obligation_receipt_ref_chirho,
                    canonical_obligation_digest_chirho: &canonical_obligation_digest_chirho,
                    inverse_authority_ref_chirho: &inverse_authority_ref_chirho,
                    action_idempotency_key_chirho: &action_idempotency_key_chirho,
                    canonical_intent_line_chirho: &canonical_intent_line_chirho,
                    authorization_chirho: &authorization_chirho,
                },
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::AppendTerminalChirho {
            canonical_intent_line_chirho,
            canonical_terminal_line_chirho,
            reply_chirho,
        } => {
            let result_chirho = execute_resident_mutation_chirho(
                ResidentMutationEnvelopeChirho {
                    resident_chirho,
                    elector_chirho,
                    gd7_winner_store_chirho,
                    canary_store_chirho,
                    group_chirho,
                    node_chirho,
                    canary_state_chirho,
                    append_barrier_state_chirho,
                },
                ResidentMutationLaneChirho::OrdinaryChirho,
                ResidentMutationCommandKindChirho::AppendTerminalChirho,
                |resident_chirho| {
                    resident_chirho.record_effect_terminal_chirho(
                        &canonical_intent_line_chirho,
                        &signers_chirho.effect_intent_chirho,
                        &canonical_terminal_line_chirho,
                        &signers_chirho.effect_terminal_chirho,
                    )
                },
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ExecuteGd7CompensationProviderChirho {
            canonical_obligation_digest_chirho,
            action_idempotency_key_chirho,
            bounded_payload_chirho,
            reply_chirho,
        } => {
            let result_chirho = derive_gd7_compensation_provider_idempotency_key_chirho(
                &canonical_obligation_digest_chirho,
                &action_idempotency_key_chirho,
            )
            .and_then(|provider_idempotency_key_chirho| {
                execute_gd7_compensation_provider_chirho(
                    gd7_compensation_provider_chirho,
                    &provider_idempotency_key_chirho,
                    &bounded_payload_chirho,
                )
            });
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ComposeGd7CompensationChirho {
            mint_identity_digest_chirho,
            obligation_receipt_ref_chirho,
            canonical_obligation_digest_chirho,
            inverse_authority_ref_chirho,
            action_idempotency_key_chirho,
            bounded_payload_chirho,
            reply_chirho,
        } => {
            let result_chirho = create_or_load_gd7_obligation_processing_state_chirho(
                resident_chirho.gd7_obligation_processing_storage_chirho(),
                &mint_identity_digest_chirho,
                &obligation_receipt_ref_chirho,
                &canonical_obligation_digest_chirho,
                &inverse_authority_ref_chirho,
                &action_idempotency_key_chirho,
            )
            .map_err(Gd7CompensationCompositionRefusalChirho::ProcessingChirho)
            .and_then(|state_chirho| {
                compose_gd7_provider_result_chirho(
                    resident_chirho.gd7_obligation_processing_storage_chirho(),
                    &state_chirho,
                    gd7_compensation_provider_chirho,
                    &bounded_payload_chirho,
                )
            });
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ActiveHoldIntentRefsChirho { reply_chirho } => {
            let result_chirho = append_barrier_state_chirho
                .read_resident_chirho(
                    resident_chirho,
                    handoff_local_authority_chirho,
                    |resident_chirho, handoff_guard_chirho| {
                        resident_chirho.active_effect_intent_refs_chirho(handoff_guard_chirho)
                    },
                )
                .map_err(resident_refusal_chirho)
                .and_then(bounded_inventory_chirho);
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ReceiptByIntentRefChirho {
            intent_ref_chirho,
            reply_chirho,
        } => {
            let result_chirho = append_barrier_state_chirho
                .read_resident_chirho(
                    resident_chirho,
                    handoff_local_authority_chirho,
                    |resident_chirho, handoff_guard_chirho| {
                        resident_chirho.effect_intent_journal_state_chirho(
                            &intent_ref_chirho,
                            handoff_guard_chirho,
                        )
                    },
                )
                .map_err(resident_refusal_chirho);
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::EffectIntentCutChirho { reply_chirho } => {
            let result_chirho = append_barrier_state_chirho
                .read_resident_chirho(
                    resident_chirho,
                    handoff_local_authority_chirho,
                    |resident_chirho, handoff_guard_chirho| {
                        resident_chirho.effect_intent_cut_chirho(handoff_guard_chirho)
                    },
                )
                .map_err(resident_refusal_chirho);
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::CurrentContinuationChirho {
            kind_id_chirho,
            reply_chirho,
        } => {
            let result_chirho = append_barrier_state_chirho
                .read_resident_chirho(
                    resident_chirho,
                    handoff_local_authority_chirho,
                    |resident_chirho, handoff_guard_chirho| {
                        resident_chirho
                            .current_continuation_chirho(&kind_id_chirho, handoff_guard_chirho)
                    },
                )
                .map_err(resident_refusal_chirho);
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::VerifiedReceiptInventoryChirho { reply_chirho } => {
            let result_chirho = append_barrier_state_chirho
                .read_resident_chirho(
                    resident_chirho,
                    handoff_local_authority_chirho,
                    |resident_chirho, handoff_guard_chirho| {
                        resident_chirho
                            .verified_effect_receipt_inventory_chirho(handoff_guard_chirho)
                    },
                )
                .map_err(resident_refusal_chirho)
                .and_then(bounded_inventory_chirho);
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::DriveGd7PlanPageChirho {
            observation_chirho,
            expected_checkpoint_ref_chirho,
            reply_chirho,
        } => {
            let result_chirho = gd7_plan_ports_chirho
                .drive_chirho(observation_chirho.as_ref(), &expected_checkpoint_ref_chirho);
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::VerifyGd7SealedPlanChirho {
            observation_chirho,
            expected_checkpoint_ref_chirho,
            reply_chirho,
        } => {
            let result_chirho = gd7_plan_ports_chirho
                .verify_sealed_chirho(observation_chirho.as_ref(), &expected_checkpoint_ref_chirho);
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ConvergeAndCertifyGd7Chirho {
            observation_chirho,
            checkpoint_ref_chirho,
            binding_chirho,
            unmeasured_chirho,
            reply_chirho,
        } => {
            let result_chirho = gd7_plan_ports_chirho.converge_and_certify_chirho(
                observation_chirho.as_ref(),
                &checkpoint_ref_chirho,
                binding_chirho,
                unmeasured_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ImportConvergedCompensationReceiptGd7Chirho {
            observation_chirho,
            checkpoint_ref_chirho,
            winner_compensation_record_line_chirho,
            reply_chirho,
        } => {
            let result_chirho = gd7_plan_ports_chirho.import_converged_compensation_receipt_chirho(
                observation_chirho.as_ref(),
                &checkpoint_ref_chirho,
                &winner_compensation_record_line_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ProbeGd7WinnerChirho { reply_chirho } => {
            let _reply_result_chirho = reply_chirho.send(
                append_barrier_state_chirho
                    .probe_resident_chirho(resident_chirho, handoff_local_authority_chirho),
            );
        }
        ResidentEffectJournalCommandChirho::ObserveGd7DeposedForkChirho {
            expected_winner_term_chirho,
            held_node_chirho,
            losing_journal_genesis_digest_chirho,
            losing_journal_tail_chirho,
            cancellation_chirho,
            reply_chirho,
        } => {
            let result_chirho = if cancellation_chirho.load(Ordering::Acquire) {
                Err(ResidentGd7WinnerForkObservationRefusalChirho::ActorReplyTimedOutChirho)
            } else {
                observe_resident_gd7_deposed_fork_chirho(
                    resident_chirho,
                    gd7_winner_store_chirho,
                    expected_winner_term_chirho,
                    &held_node_chirho,
                    &losing_journal_genesis_digest_chirho,
                    &losing_journal_tail_chirho,
                )
            };
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::StageGd7WinnerViewPageChirho {
            expected_stage_index_chirho,
            reply_chirho,
        } => {
            let result_chirho = stage_resident_gd7_winner_view_page_chirho(
                resident_chirho,
                winner_view_state_chirho,
                expected_stage_index_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::SealGd7WinnerCurrentViewChirho {
            challenge_chirho,
            reply_chirho,
        } => {
            let result_chirho = seal_resident_gd7_winner_current_view_chirho(
                resident_chirho,
                winner_view_state_chirho,
                challenge_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::SealGd7WinnerCurrentViewForHeldChirho {
            challenge_chirho,
            held_node_chirho,
            reply_chirho,
        } => {
            let result_chirho = seal_resident_gd7_winner_current_view_for_held_chirho(
                resident_chirho,
                winner_view_state_chirho,
                challenge_chirho,
                &held_node_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::IssueFirstGd7WinnerViewPageGrantChirho {
            held_node_chirho,
            reply_chirho,
        } => {
            let result_chirho = issue_first_resident_gd7_winner_view_page_grant_chirho(
                resident_chirho,
                winner_view_state_chirho,
                &held_node_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::FetchGrantedGd7WinnerViewPageChirho {
            requester_chirho,
            grant_chirho,
            reply_chirho,
        } => {
            let result_chirho = fetch_resident_gd7_winner_view_page_chirho(
                resident_chirho,
                winner_view_state_chirho,
                &requester_chirho,
                grant_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::Gd7WinnerHandoffChirho {
            command_chirho,
            reply_chirho,
        } => {
            let result_chirho = handle_resident_gd7_winner_handoff_chirho(
                command_chirho,
                resident_chirho,
                winner_view_state_chirho,
                append_barrier_state_chirho.gd7_mut_chirho(),
                gd7_winner_handoff_store_chirho,
                handoff_local_authority_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::Gd7WinnerAdoptionEvidenceChirho {
            command_chirho,
            reply_chirho,
        } => {
            let result_chirho = handle_resident_gd7_winner_adoption_evidence_chirho(
                command_chirho,
                resident_chirho,
                append_barrier_state_chirho.gd7_chirho(),
                gd7_winner_handoff_store_chirho,
                winner_adoption_evidence_state_chirho,
            );
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::TenantMigrationOperationChirho {
            command_chirho,
            reply_chirho,
        } => {
            let result_chirho = tenant_migration_operation_runtime_chirho
                .as_mut()
                .ok_or(ResidentTenantMigrationOperationRefusalChirho::ResidentRootIsNotTenantChirho)
                .and_then(|runtime_chirho| {
                    runtime_chirho.handle_chirho(command_chirho, append_barrier_state_chirho)
                });
            let _reply_result_chirho = reply_chirho.send(result_chirho);
        }
        ResidentEffectJournalCommandChirho::ShutdownChirho => return true,
    }
    false
}

fn testkind_loss_witness_commit_chirho(
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
) -> ResidentTestkindLossWitnessCommitChirho {
    ResidentTestkindLossWitnessCommitChirho {
        seq_chirho: receipt_chirho.append_chirho.seq_chirho,
        record_digest_chirho: receipt_chirho.append_chirho.record_digest_chirho.clone(),
        physical_ms_chirho: receipt_chirho.append_chirho.hlc_chirho.physical_ms_chirho,
        logical_chirho: receipt_chirho.append_chirho.hlc_chirho.logical_chirho,
    }
}

fn testkind_loss_witness_envelope_refusal_chirho(
    refusal_chirho: EffectCommitJournalPortErrorChirho,
) -> ResidentTestkindLossWitnessRefusalChirho {
    match refusal_chirho {
        EffectCommitJournalPortErrorChirho::CommittedEvidencePendingChirho { .. } => {
            ResidentTestkindLossWitnessRefusalChirho::CommittedEvidencePendingChirho
        }
        EffectCommitJournalPortErrorChirho::AuthorityRefusedChirho { .. } => {
            ResidentTestkindLossWitnessRefusalChirho::CurrentAuthorityRefusedChirho
        }
        EffectCommitJournalPortErrorChirho::UnavailableChirho { .. } => {
            ResidentTestkindLossWitnessRefusalChirho::AppendBarrierRefusedChirho
        }
        // The mirror family now reports WHICH mirror condition refused. Before this split every one
        // of them arrived here as a generic `RefusedChirho` and left as the single
        // `CurrentEnvelopeRefusedChirho` token, which is what left node loss and region loss
        // unattributable on their first-ever hosted execution.
        EffectCommitJournalPortErrorChirho::MirrorRefusedChirho {
            identity_chirho, ..
        } => match identity_chirho {
            EffectCommitJournalMirrorRefusalIdentityChirho::PrepareRefusedChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeMirrorPrepareRefusedChirho
            }
            EffectCommitJournalMirrorRefusalIdentityChirho::ReconciliationRefusedChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeMirrorReconciliationRefusedChirho
            }
            EffectCommitJournalMirrorRefusalIdentityChirho::CommittedEvidencePendingChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeMirrorEvidencePendingChirho
            }
        },
        // The resident-path family now reports WHICH KIND of condition refused. This is the arm the
        // loss drills actually reach: they fail at `prepare_resident_mutation_chirho`, whose refusals
        // are built in the resident path rather than mapped from a journal error.
        EffectCommitJournalPortErrorChirho::ResidentRefusedChirho {
            identity_chirho, ..
        } => match identity_chirho {
            EffectCommitJournalResidentRefusalIdentityChirho::ReadinessCanaryAlignmentChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeReadinessCanaryRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::CanaryTailSeqChirho => {
                ResidentTestkindLossWitnessRefusalChirho::CanaryTailSeqRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::CanaryTailDigestChirho => {
                ResidentTestkindLossWitnessRefusalChirho::CanaryTailDigestRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::CanaryConsistencyGroupChirho => {
                ResidentTestkindLossWitnessRefusalChirho::CanaryConsistencyGroupRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::Gd7HoldOrWithheldChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeGd7HoldRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::TestkindExemptLaneChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeTestkindLaneRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::TenantMigrationFenceChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeMigrationFenceRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::FenceOrContinuityChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeFenceContinuityRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::InventoryBoundChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeInventoryBoundRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::MirrorPrepareOrReconciliationChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeMirrorPrepareRefusedChirho
            }
            EffectCommitJournalResidentRefusalIdentityChirho::AuthorityCompositionOtherChirho => {
                ResidentTestkindLossWitnessRefusalChirho::EnvelopeAuthorityOtherRefusedChirho
            }
        },
        EffectCommitJournalPortErrorChirho::RefusedChirho { .. }
        | EffectCommitJournalPortErrorChirho::ConflictChirho { .. } => {
            ResidentTestkindLossWitnessRefusalChirho::CurrentEnvelopeRefusedChirho
        }
    }
}

fn retain_testkind_committed_refusal_chirho(
    canary_state_chirho: &mut ResidentCanaryStateChirho,
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
    identity_chirho: EffectCommitJournalCommittedEvidenceIdentityChirho,
    detail_chirho: &'static str,
) {
    let _sticky_refusal_chirho: ResidentEffectJournalResultChirho<()> =
        sticky_committed_refusal_chirho(
            canary_state_chirho,
            effect_receipt_chirho(receipt_chirho),
            identity_chirho,
            detail_chirho,
        );
}

fn refuse_testkind_loss_witness_unexpected_admission_chirho(
    canary_state_chirho: &mut ResidentCanaryStateChirho,
    receipt_chirho: &ResidentLedgerAppendReceiptChirho,
) -> ResidentTestkindLossWitnessRefusalChirho {
    retain_testkind_committed_refusal_chirho(
        canary_state_chirho,
        receipt_chirho,
        EffectCommitJournalCommittedEvidenceIdentityChirho::TestkindDeposedSinkAdmissionEvidencePendingChirho,
        "deposed test-kind resident reached a committed final-sink outcome",
    );
    ResidentTestkindLossWitnessRefusalChirho::DeposedSinkUnexpectedAdmissionChirho
}

/// Commit one witness as the node that currently holds write authority.
///
/// `role_chirho` selects WHICH committing observation this is, and it is not cosmetic: the append
/// key is exactly (phase, role), so the role is what makes a second post-adoption observation a
/// distinct append rather than a duplicate. `command_kind_chirho` must name the same thing in the
/// private log, because a shared label would report a sustained witness as the first one.
fn execute_testkind_loss_witness_current_chirho(
    mut envelope_chirho: ResidentMutationEnvelopeChirho<'_, '_, '_>,
    plan_chirho: &Option<ResidentTestkindLossWitnessPlanChirho>,
    phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
    role_chirho: ResidentTestkindLossWitnessRoleChirho,
    command_kind_chirho: ResidentMutationCommandKindChirho,
) -> std::result::Result<
    ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessRefusalChirho,
> {
    let plan_chirho = plan_chirho
        .as_ref()
        .ok_or(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)?;
    let prepared_chirho = prepare_resident_mutation_chirho(
        &mut envelope_chirho,
        ResidentMutationLaneChirho::OrdinaryChirho,
    )
    .map_err(testkind_loss_witness_envelope_refusal_chirho)?;
    let request_chirho = plan_chirho.append_request_chirho(phase_chirho, role_chirho)?;
    let append_receipt_chirho = match envelope_chirho
        .resident_chirho
        .record_testkind_loss_witness_chirho(request_chirho)
    {
        Ok(receipt_chirho) => receipt_chirho,
        Err(ResidentLedgerAuthorityRefusalChirho::MirrorReconciliationRefusedChirho { .. }) => {
            return Ok(
                ResidentTestkindLossWitnessOutcomeChirho::MirrorReconciliationRefusedChirho {
                    phase_chirho,
                },
            );
        }
        Err(ResidentLedgerAuthorityRefusalChirho::MirrorPrepareRefusedChirho { .. }) => {
            return Ok(
                ResidentTestkindLossWitnessOutcomeChirho::MirrorPrepareRefusedChirho {
                    phase_chirho,
                },
            );
        }
        Err(ResidentLedgerAuthorityRefusalChirho::MirrorCommittedEvidencePendingChirho {
            receipt_chirho,
            ..
        }) => {
            retain_testkind_committed_refusal_chirho(
                envelope_chirho.canary_state_chirho,
                &receipt_chirho,
                EffectCommitJournalCommittedEvidenceIdentityChirho::MirrorAppendEvidencePendingChirho,
                "test-kind current witness mirror evidence remains pending after commit",
            );
            return Err(
                ResidentTestkindLossWitnessRefusalChirho::CommittedEvidencePendingChirho,
            );
        }
        Err(ResidentLedgerAuthorityRefusalChirho::TestkindLossWitnessExemptLaneRefusedChirho) => {
            return Err(
                ResidentTestkindLossWitnessRefusalChirho::MutationExemptionRefusedChirho,
            );
        }
        Err(
            ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::SinkTermCellRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::CompensationFenceRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceRefusedChirho { .. }
            | ResidentLedgerAuthorityRefusalChirho::OrdinaryElectionSinkTermAcceptanceInputsUnavailableChirho,
        ) => {
            return Err(
                ResidentTestkindLossWitnessRefusalChirho::CurrentAuthorityRefusedChirho,
            );
        }
        Err(_refusal_chirho) => {
            return Err(ResidentTestkindLossWitnessRefusalChirho::CurrentAppendRefusedChirho);
        }
    };
    let commit_chirho = testkind_loss_witness_commit_chirho(&append_receipt_chirho);
    complete_resident_mutation_chirho(
        envelope_chirho,
        command_kind_chirho,
        prepared_chirho,
        append_receipt_chirho,
    )
    .map_err(testkind_loss_witness_envelope_refusal_chirho)?;
    Ok(ResidentTestkindLossWitnessOutcomeChirho::CommittedChirho {
        phase_chirho,
        commit_chirho,
    })
}

fn execute_testkind_loss_witness_deposed_sink_chirho(
    envelope_chirho: ResidentMutationEnvelopeChirho<'_, '_, '_>,
    plan_chirho: &Option<ResidentTestkindLossWitnessPlanChirho>,
    phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
) -> std::result::Result<
    ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessRefusalChirho,
> {
    let plan_chirho = plan_chirho
        .as_ref()
        .ok_or(ResidentTestkindLossWitnessRefusalChirho::TestKindConfigRequiredChirho)?;
    if envelope_chirho
        .append_barrier_state_chirho
        .mutation_refusal_detail_chirho()
        .is_some()
    {
        return Err(ResidentTestkindLossWitnessRefusalChirho::AppendBarrierRefusedChirho);
    }
    ensure_canary_ready_chirho(
        envelope_chirho.canary_store_chirho,
        envelope_chirho.canary_state_chirho,
        envelope_chirho.group_chirho,
    )
    .map_err(testkind_loss_witness_envelope_refusal_chirho)?;
    // Deliberately omit only the local-authority probe and its read-derived alignment: either
    // would refuse the deposed actor before the private append funnel can measure the sink gate.
    let request_chirho = plan_chirho.append_request_chirho(
        phase_chirho,
        ResidentTestkindLossWitnessRoleChirho::DeposedSinkChirho,
    )?;
    classify_testkind_loss_witness_deposed_sink_result_chirho(
        envelope_chirho
            .resident_chirho
            .record_testkind_loss_witness_chirho(request_chirho),
        envelope_chirho.canary_state_chirho,
        phase_chirho,
    )
}

pub(super) fn classify_testkind_loss_witness_deposed_sink_result_chirho(
    result_chirho: Result<ResidentLedgerAppendReceiptChirho, ResidentLedgerAuthorityRefusalChirho>,
    canary_state_chirho: &mut ResidentCanaryStateChirho,
    phase_chirho: ResidentTestkindLossWitnessPhaseChirho,
) -> std::result::Result<
    ResidentTestkindLossWitnessOutcomeChirho,
    ResidentTestkindLossWitnessRefusalChirho,
> {
    match result_chirho {
        Err(ResidentLedgerAuthorityRefusalChirho::LocalGenerationRefusedChirho {
            reason_chirho: LocalAppendAuthorityRefusalChirho::NotLocalLeaderChirho,
        }) => {
            Ok(ResidentTestkindLossWitnessOutcomeChirho::DeposedSinkRefusedChirho { phase_chirho })
        }
        Err(ResidentLedgerAuthorityRefusalChirho::TestkindLossWitnessExemptLaneRefusedChirho) => {
            Err(ResidentTestkindLossWitnessRefusalChirho::MutationExemptionRefusedChirho)
        }
        Err(ResidentLedgerAuthorityRefusalChirho::MirrorCommittedEvidencePendingChirho {
            receipt_chirho,
            ..
        }) => Err(refuse_testkind_loss_witness_unexpected_admission_chirho(
            canary_state_chirho,
            &receipt_chirho,
        )),
        Ok(receipt_chirho) => Err(refuse_testkind_loss_witness_unexpected_admission_chirho(
            canary_state_chirho,
            &receipt_chirho,
        )),
        Err(_refusal_chirho) => {
            Err(ResidentTestkindLossWitnessRefusalChirho::DeposedSinkUnexpectedRefusalChirho)
        }
    }
}

/// The five obligation coordinates plus the compensation append inputs for one completion.
///
/// Grouped into a struct because the completion needs both the obligation's identity (to load its
/// durable state) and the append's own inputs, and threading nine bare arguments through the
/// borrow-ordered phases below reads as an invitation to pass them in the wrong order.
pub(super) struct Gd7CompensationCompletionRequestChirho<'request_chirho> {
    pub(super) mint_identity_digest_chirho: &'request_chirho str,
    pub(super) obligation_receipt_ref_chirho: &'request_chirho str,
    pub(super) canonical_obligation_digest_chirho: &'request_chirho str,
    pub(super) inverse_authority_ref_chirho: &'request_chirho str,
    pub(super) action_idempotency_key_chirho: &'request_chirho str,
    pub(super) canonical_intent_line_chirho: &'request_chirho str,
    pub(super) authorization_chirho: &'request_chirho VerifiedEffectCompensationChirho,
}

/// Load, decide, append (only if owed), then finish — in that order, each borrow released before
/// the next is taken.
///
/// The phase split is not a borrow-checker workaround; it is the ordering the money path requires.
/// The decision runs on loaded state BEFORE any durable append, so an obligation that has not
/// reached `ProviderObservedChirho` is refused with nothing written. The append is the FENCED
/// compensation append: when the sink winner-term cell is behind, this is exactly where a term
/// bump strands the obligation, and the lawful D2 advance is what lifts it.
#[allow(
    clippy::too_many_arguments,
    reason = "the actor loop passes one fixed resident authority bundle without heap indirection"
)]
fn complete_gd7_compensation_command_chirho(
    resident_chirho: &mut ResidentLedgerAuthorityChirho<'_>,
    signers_chirho: &HostLedgerSignersChirho,
    elector_chirho: &RaftWriterElectorChirho,
    gd7_winner_store_chirho: &Gd7WinnerWitnessStoreChirho<'_>,
    canary_store_chirho: &ShadowCanaryGenerationStoreChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    node_chirho: &NodeIdChirho,
    canary_state_chirho: &mut ResidentCanaryStateChirho,
    append_barrier_state_chirho: &mut ResidentAppendBarrierRuntimeChirho,
    request_chirho: Gd7CompensationCompletionRequestChirho<'_>,
) -> std::result::Result<Gd7ObligationProcessingStateChirho, Gd7CompensationCompletionRefusalChirho>
{
    let state_chirho = create_or_load_gd7_obligation_processing_state_chirho(
        resident_chirho.gd7_obligation_processing_storage_chirho(),
        request_chirho.mint_identity_digest_chirho,
        request_chirho.obligation_receipt_ref_chirho,
        request_chirho.canonical_obligation_digest_chirho,
        request_chirho.inverse_authority_ref_chirho,
        request_chirho.action_idempotency_key_chirho,
    )
    .map_err(Gd7CompensationCompletionRefusalChirho::ProcessingChirho)?;
    // Pure, and it runs before anything durable happens.
    let plan_chirho = plan_gd7_compensation_completion_chirho(&state_chirho)?;
    let receipt_ref_chirho = match plan_chirho {
        Gd7CompensationCompletionPlanChirho::AppendThenFinishChirho => {
            let receipt_chirho = execute_resident_mutation_chirho(
                ResidentMutationEnvelopeChirho {
                    resident_chirho,
                    elector_chirho,
                    gd7_winner_store_chirho,
                    canary_store_chirho,
                    group_chirho,
                    node_chirho,
                    canary_state_chirho,
                    append_barrier_state_chirho,
                },
                ResidentMutationLaneChirho::Gd7CompensationChirho,
                ResidentMutationCommandKindChirho::CompleteGd7CompensationChirho,
                |resident_chirho| {
                    resident_chirho.record_effect_compensation_hold_chirho(
                        request_chirho.canonical_intent_line_chirho,
                        &signers_chirho.effect_intent_chirho,
                        request_chirho.authorization_chirho,
                    )
                },
            )
            .map_err(|error_chirho| {
                Gd7CompensationCompletionRefusalChirho::JournalAppendRefusedChirho {
                    detail_chirho: format!("{error_chirho:?}"),
                }
            })?;
            // Content-addressed: the exact journal record, never a synthesized label.
            Some(receipt_chirho.record_digest_chirho.0)
        }
        Gd7CompensationCompletionPlanChirho::FinishWithoutAppendChirho => None,
    };
    finish_gd7_compensation_completion_chirho(
        resident_chirho.gd7_obligation_processing_storage_chirho(),
        &state_chirho,
        receipt_ref_chirho.as_deref(),
    )
}

#[cfg(test)]
#[path = "command_dispatch_tests_chirho.rs"]
mod tests_chirho;
